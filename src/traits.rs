//! Stable extension contracts: identity resolution, service classification, export.
//!
//! These are the swappable seams around the eBPF probe core. Each has a trivial default
//! implementation here; environment-specific ones (k8s, a3s-box, OTel) land with the
//! probes.

use crate::model::EnrichedEvent;
use serde::Serialize;
use std::net::IpAddr;

/// Who an event belongs to. Resolved from kernel-side keys (pid / cgroup / netns).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Identity {
    pub agent: Option<String>,
    pub task: Option<String>,
    pub session: Option<String>,
}

/// Maps a kernel event's process/namespace keys to an [`Identity`].
///
/// Implementations: k8s (cgroup→pod), docker, a3s-box (pid/netns→box), bare pid-tree.
pub trait IdentityResolver: Send + Sync {
    fn resolve(&self, pid: u32, cgroup_id: u64, netns: u64) -> Identity;
}

/// Known service providers, identified language-agnostically from TLS SNI / DNS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Provider {
    OpenAi,
    Anthropic,
    Gemini,
    Mistral,
    Cohere,
    XAi,
    DeepSeek,
    Groq,
    Together,
    Perplexity,
    Fireworks,
    OpenRouter,
    AzureOpenAi,
    Bedrock,
    Ollama,
    Other(String),
}

/// Classifies a network destination (SNI hostname and/or peer IP) into a [`Provider`].
pub trait ServiceClassifier: Send + Sync {
    fn classify(&self, sni: Option<&str>, peer: IpAddr) -> Option<Provider>;
}

/// Default classifier: maps well-known provider hostnames from the TLS ClientHello SNI.
///
/// SNI is plaintext today; Encrypted ClientHello (ECH) will eventually hide it, at which
/// point classification must fall back to IP/DNS correlation.
pub struct SniClassifier;

impl ServiceClassifier for SniClassifier {
    fn classify(&self, sni: Option<&str>, _peer: IpAddr) -> Option<Provider> {
        let host = sni?;
        Some(match host {
            h if h.ends_with("openai.azure.com") => Provider::AzureOpenAi,
            h if h.ends_with("openai.com") || h.ends_with("oaiusercontent.com") => Provider::OpenAi,
            h if h.ends_with("anthropic.com") => Provider::Anthropic,
            h if h.ends_with("googleapis.com") => Provider::Gemini,
            h if h.ends_with("mistral.ai") => Provider::Mistral,
            h if h.ends_with("cohere.ai") || h.ends_with("cohere.com") => Provider::Cohere,
            h if h.ends_with("x.ai") => Provider::XAi,
            h if h.ends_with("deepseek.com") => Provider::DeepSeek,
            h if h.ends_with("groq.com") => Provider::Groq,
            h if h.ends_with("together.xyz") || h.ends_with("together.ai") => Provider::Together,
            h if h.ends_with("perplexity.ai") => Provider::Perplexity,
            h if h.ends_with("fireworks.ai") => Provider::Fireworks,
            h if h.ends_with("openrouter.ai") => Provider::OpenRouter,
            h if h.ends_with("amazonaws.com") && h.contains("bedrock") => Provider::Bedrock,
            _ => return None,
        })
    }
}

/// Sink for enriched telemetry. Implementations: OTel (default target), Prometheus, log.
pub trait Exporter: Send + Sync {
    fn export(&self, event: &EnrichedEvent);
    /// Output lines dropped because the write queue was full (slow/stalled consumer). Cumulative.
    fn output_drops(&self) -> u64 {
        0
    }
}

/// Trivial exporter that logs via `tracing`. Useful for bring-up; OTel is the real target.
pub struct LogExporter;

impl Exporter for LogExporter {
    fn export(&self, event: &EnrichedEvent) {
        tracing::info!(?event, "a3s-observer event");
    }
}

/// Exporter that writes each event as one NDJSON line to stdout — consumable by any log
/// pipeline (vector / Loki / jq / files). OTLP is a drop-in via this same trait.
///
/// A dedicated writer thread owns stdout, fed by a bounded queue, so a slow/stalled consumer can
/// never block the caller's event loop — which would stall the 60s report + liveness heartbeat
/// and get the collector killed. When the queue is full, lines are dropped and counted instead.
pub struct JsonExporter {
    tx: std::sync::mpsc::SyncSender<String>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl JsonExporter {
    pub fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<String>(4096);
        std::thread::spawn(move || {
            use std::io::Write;
            let mut out = std::io::stdout().lock();
            while let Ok(line) = rx.recv() {
                let _ = writeln!(out, "{line}");
            }
        });
        Self {
            tx,
            dropped: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }
}

impl Default for JsonExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for JsonExporter {
    fn export(&self, event: &EnrichedEvent) {
        if let Ok(line) = serde_json::to_string(event) {
            // Non-blocking: a full queue means the consumer is slower than collection — drop the
            // line (counted) rather than stall the event loop on a blocking write.
            if self.tx.try_send(line).is_err() {
                self.dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
    fn output_drops(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Default [`IdentityResolver`]: reads `/proc/<pid>` — the process `comm` as the agent
/// label and the parent pid from `stat`. Works on bare hosts; a cgroup→pod resolver for
/// k8s is a future addition. (A short-lived process may exit before resolution; then the
/// agent label is `None`.)
pub struct ProcResolver;

impl IdentityResolver for ProcResolver {
    fn resolve(&self, pid: u32, _cgroup_id: u64, _netns: u64) -> Identity {
        Identity {
            agent: read_comm(pid),
            task: Some(pid.to_string()),
            session: None,
        }
    }
}

/// Parent pid of `pid` via `/proc/<pid>/stat` (0 if unavailable). Userspace process-tree
/// without eBPF CO-RE.
pub fn read_ppid(pid: u32) -> u32 {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .as_deref()
        .and_then(parse_ppid_from_stat)
        .unwrap_or(0)
}

fn read_comm(pid: u32) -> Option<String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

/// Field 4 (ppid) of a `/proc/<pid>/stat` line — robust to `)` / spaces inside the comm.
fn parse_ppid_from_stat(stat: &str) -> Option<u32> {
    let tail = stat.rsplit_once(')')?.1; // drop "pid (comm)"
    tail.split_whitespace().nth(1)?.parse().ok() // remaining = [state, ppid, ...]
}

/// [`IdentityResolver`] for Kubernetes / containers: reads `/proc/<pid>/cgroup` for the
/// pod UID + container id, falling back to the process `comm` on a bare host. Pod *names*
/// need the k8s API (a future enhancement); this gives pod-UID / container-id attribution
/// with zero cluster access.
pub struct KubeResolver;

impl IdentityResolver for KubeResolver {
    fn resolve(&self, pid: u32, _cgroup_id: u64, _netns: u64) -> Identity {
        if let Ok(cg) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
            let k = parse_cgroup(&cg);
            if k.pod_uid.is_some() || k.container_id.is_some() {
                return Identity {
                    agent: k.pod_uid.or_else(|| k.container_id.clone()),
                    task: Some(pid.to_string()),
                    session: k.container_id,
                };
            }
        }
        Identity {
            agent: read_comm(pid), // bare host
            task: Some(pid.to_string()),
            session: None,
        }
    }
}

struct KubeId {
    pod_uid: Option<String>,
    container_id: Option<String>,
}

/// Extract pod UID + (short) container id from a `/proc/<pid>/cgroup` body. Handles the
/// common containerd (`...-pod<uid>.slice/cri-containerd-<64hex>.scope`) and docker
/// (`docker-<64hex>.scope`) layouts; returns `None`s for a non-container cgroup.
fn parse_cgroup(s: &str) -> KubeId {
    let mut pod_uid = None;
    let mut container_id = None;
    for seg in s.split(['/', '.', '-']) {
        if seg.len() == 64 && seg.bytes().all(|b| b.is_ascii_hexdigit()) {
            container_id = Some(seg[..12].to_owned()); // short id
        } else if let Some(uid) = seg.strip_prefix("pod") {
            if uid.len() >= 30 {
                pod_uid = Some(uid.replace('_', "-")); // containerd uses '_' in the UID
            }
        }
    }
    KubeId {
        pod_uid,
        container_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn ppid_parse_handles_parens_in_comm() {
        assert_eq!(parse_ppid_from_stat("7 (bash) S 1 1 0"), Some(1));
        assert_eq!(parse_ppid_from_stat("9 (weird (x) y) R 42 9 0"), Some(42));
        assert_eq!(parse_ppid_from_stat("garbage"), None);
    }

    #[test]
    fn sni_classifier_maps_known_hosts() {
        let c = SniClassifier;
        let ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            c.classify(Some("api.anthropic.com"), ip),
            Some(Provider::Anthropic)
        );
        assert_eq!(
            c.classify(Some("api.openai.com"), ip),
            Some(Provider::OpenAi)
        );
        assert_eq!(
            c.classify(Some("api.mistral.ai"), ip),
            Some(Provider::Mistral)
        );
        assert_eq!(
            c.classify(Some("api.deepseek.com"), ip),
            Some(Provider::DeepSeek)
        );
        assert_eq!(
            c.classify(Some("myorg.openai.azure.com"), ip),
            Some(Provider::AzureOpenAi)
        );
        assert_eq!(
            c.classify(Some("bedrock-runtime.us-east-1.amazonaws.com"), ip),
            Some(Provider::Bedrock)
        );
        assert_eq!(c.classify(Some("example.com"), ip), None);
    }

    #[test]
    fn cgroup_parse_containerd_docker_bare() {
        let cd = "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1a2b3c4d_5e6f_7890_abcd_ef1234567890.slice/cri-containerd-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.scope";
        let k = parse_cgroup(cd);
        assert_eq!(
            k.pod_uid.as_deref(),
            Some("1a2b3c4d-5e6f-7890-abcd-ef1234567890")
        );
        assert_eq!(k.container_id.as_deref(), Some("abcdef012345"));

        let dk = "0::/system.slice/docker-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.scope";
        let k2 = parse_cgroup(dk);
        assert_eq!(k2.container_id.as_deref(), Some("abcdef012345"));
        assert_eq!(k2.pod_uid, None);

        let bare = "0::/user.slice/user-1000.slice/session-3.scope";
        let k3 = parse_cgroup(bare);
        assert!(k3.pod_uid.is_none() && k3.container_id.is_none());
    }
}
