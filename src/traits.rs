//! Stable extension contracts: identity resolution, service classification, export.
//!
//! These are the swappable seams around the eBPF probe core. Each has a trivial default
//! implementation here; environment-specific ones (k8s, a3s-box, OTel) land with the
//! probes.

use crate::model::{AgentEvent, EnrichedEvent};
use crate::workload::WorkloadIdentity;
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

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

    /// Resolve a complete, provider-neutral workload identity when one is available.
    ///
    /// Existing process-only resolvers remain valid and default to no workload attribution.
    /// Implementations must return `None` rather than inventing or partially filling identity.
    fn resolve_workload(
        &self,
        _pid: u32,
        _cgroup_id: u64,
        _netns: u64,
    ) -> Option<WorkloadIdentity> {
        None
    }
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

fn host_is_or_subdomain(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn is_gemini_host(host: &str) -> bool {
    host_is_or_subdomain(host, "generativelanguage.googleapis.com")
        || host_is_or_subdomain(host, "aiplatform.googleapis.com")
        // Vertex AI regional endpoints use `<location>-aiplatform.googleapis.com`.
        || host.ends_with("-aiplatform.googleapis.com")
        || host_is_or_subdomain(host, "cloudaicompanion.googleapis.com")
        || host_is_or_subdomain(host, "geminicloudassist.googleapis.com")
}

impl ServiceClassifier for SniClassifier {
    fn classify(&self, sni: Option<&str>, _peer: IpAddr) -> Option<Provider> {
        let normalized = sni?.trim_end_matches('.').to_ascii_lowercase();
        let host = normalized.as_str();
        Some(match host {
            h if host_is_or_subdomain(h, "openai.azure.com") => Provider::AzureOpenAi,
            h if host_is_or_subdomain(h, "openai.com")
                || host_is_or_subdomain(h, "oaiusercontent.com") =>
            {
                Provider::OpenAi
            }
            h if host_is_or_subdomain(h, "anthropic.com") => Provider::Anthropic,
            h if is_gemini_host(h) => Provider::Gemini,
            h if host_is_or_subdomain(h, "mistral.ai") => Provider::Mistral,
            h if host_is_or_subdomain(h, "cohere.ai") || host_is_or_subdomain(h, "cohere.com") => {
                Provider::Cohere
            }
            h if host_is_or_subdomain(h, "x.ai") => Provider::XAi,
            h if host_is_or_subdomain(h, "deepseek.com") => Provider::DeepSeek,
            h if host_is_or_subdomain(h, "groq.com") => Provider::Groq,
            h if host_is_or_subdomain(h, "together.xyz")
                || host_is_or_subdomain(h, "together.ai") =>
            {
                Provider::Together
            }
            h if host_is_or_subdomain(h, "perplexity.ai") => Provider::Perplexity,
            h if host_is_or_subdomain(h, "fireworks.ai") => Provider::Fireworks,
            h if host_is_or_subdomain(h, "openrouter.ai") => Provider::OpenRouter,
            h if host_is_or_subdomain(h, "amazonaws.com") && h.contains("bedrock") => {
                Provider::Bedrock
            }
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
    fn output_drops_by_kind(&self) -> std::collections::BTreeMap<String, u64> {
        std::collections::BTreeMap::new()
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
/// Lifecycle, ToolExec and ordinary events have separate bounded channels. A writer thread owns
/// stdout and drains them in that priority order.
pub struct JsonExporter {
    tx: std::sync::mpsc::SyncSender<String>,
    exec_tx: std::sync::mpsc::SyncSender<String>,
    lifecycle_tx: std::sync::mpsc::SyncSender<String>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
    dropped_by_kind: std::sync::Arc<Mutex<std::collections::BTreeMap<String, u64>>>,
}

impl JsonExporter {
    pub fn new() -> Self {
        Self::with_limits(4096, 65_536, 16_384)
    }

    fn with_limits(
        ordinary_capacity: usize,
        exec_capacity: usize,
        lifecycle_capacity: usize,
    ) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<String>(ordinary_capacity);
        let (exec_tx, exec_rx) = std::sync::mpsc::sync_channel::<String>(exec_capacity);
        let (lifecycle_tx, lifecycle_rx) =
            std::sync::mpsc::sync_channel::<String>(lifecycle_capacity);
        std::thread::spawn(move || {
            use std::io::Write;
            use std::sync::mpsc::TryRecvError;
            let mut out = std::io::stdout().lock();
            loop {
                match lifecycle_rx.try_recv() {
                    Ok(line) => {
                        let _ = writeln!(out, "{line}");
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => break,
                }
                match exec_rx.try_recv() {
                    Ok(line) => {
                        let _ = writeln!(out, "{line}");
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => break,
                }
                match rx.try_recv() {
                    Ok(line) => {
                        let _ = writeln!(out, "{line}");
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => break,
                }
            }
        });
        Self {
            tx,
            exec_tx,
            lifecycle_tx,
            dropped: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            dropped_by_kind: std::sync::Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        }
    }

    fn record_output_drop(&self, kind: &'static str) {
        self.dropped
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut counts) = self.dropped_by_kind.lock() {
            *counts.entry(kind.to_string()).or_insert(0) += 1;
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
            if matches!(
                event.event,
                AgentEvent::ProcessExit { .. } | AgentEvent::CollectorHeartbeat { .. }
            ) {
                let _ = self.lifecycle_tx.send(line);
                return;
            }
            let (kind, failed) = match &event.event {
                AgentEvent::ToolExec { .. } => ("ToolExec", self.exec_tx.send(line).is_err()),
                AgentEvent::Egress { .. } => ("Egress", self.tx.try_send(line).is_err()),
                AgentEvent::Dns { .. } => ("Dns", self.tx.try_send(line).is_err()),
                AgentEvent::FileAccess { .. } => ("FileAccess", self.tx.try_send(line).is_err()),
                AgentEvent::FileDelete { .. } => ("FileDelete", self.tx.try_send(line).is_err()),
                AgentEvent::LlmCall { .. } => ("LlmCall", self.tx.try_send(line).is_err()),
                AgentEvent::LlmRequestObserved { .. } => {
                    ("LlmRequestObserved", self.tx.try_send(line).is_err())
                }
                AgentEvent::LlmResponseObserved { .. } => {
                    ("LlmResponseObserved", self.tx.try_send(line).is_err())
                }
                AgentEvent::SecurityAction { .. } => {
                    ("SecurityAction", self.tx.try_send(line).is_err())
                }
                AgentEvent::ProcessExit { .. } | AgentEvent::CollectorHeartbeat { .. } => return,
            };
            if failed {
                self.record_output_drop(kind);
            }
        }
    }
    fn output_drops(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn output_drops_by_kind(&self) -> std::collections::BTreeMap<String, u64> {
        self.dropped_by_kind
            .lock()
            .map(|counts| counts.clone())
            .unwrap_or_default()
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

/// [`IdentityResolver`] for Kubernetes / containers: reads `/proc/<pid>/cgroup` once per
/// cgroup identity and caches the parsed pod UID + container id. Bare-host process names are
/// supplied by the collector's kernel `comm` fallback, avoiding another per-event `/proc` read.
/// Pod *names* still come from the AnySentry Kubernetes identity snapshot.
pub struct KubeResolver;

impl IdentityResolver for KubeResolver {
    fn resolve(&self, pid: u32, cgroup_id: u64, _netns: u64) -> Identity {
        let cache_key = (cgroup_id, if cgroup_id == 0 { pid } else { 0 });
        let now = Instant::now();
        let cached = kube_identity_cache().lock().ok().and_then(|mut cache| {
            let cached = cache.get(&cache_key)?;
            if now.duration_since(cached.refreshed_at) <= KUBE_IDENTITY_CACHE_TTL {
                Some(cached.identity.clone())
            } else {
                cache.remove(&cache_key);
                None
            }
        });
        let resolved = cached.or_else(|| {
            let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
            let parsed = parse_cgroup(&cgroup);
            if let Ok(mut cache) = kube_identity_cache().lock() {
                if cache.len() >= KUBE_IDENTITY_CACHE_LIMIT {
                    cache.clear();
                }
                cache.insert(
                    cache_key,
                    CachedKubeId {
                        identity: parsed.clone(),
                        refreshed_at: now,
                    },
                );
            }
            Some(parsed)
        });
        if let Some(kube) = resolved {
            if kube.pod_uid.is_some() || kube.container_id.is_some() {
                return Identity {
                    agent: kube.pod_uid.or_else(|| kube.container_id.clone()),
                    task: Some(pid.to_string()),
                    session: kube.container_id,
                };
            }
        }
        Identity {
            agent: None,
            task: Some(pid.to_string()),
            session: None,
        }
    }
}

const KUBE_IDENTITY_CACHE_LIMIT: usize = 65_536;
const KUBE_IDENTITY_CACHE_TTL: Duration = Duration::from_secs(30);

fn kube_identity_cache() -> &'static Mutex<HashMap<(u64, u32), CachedKubeId>> {
    static CACHE: OnceLock<Mutex<HashMap<(u64, u32), CachedKubeId>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

struct CachedKubeId {
    identity: KubeId,
    refreshed_at: Instant,
}

#[derive(Clone)]
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
        assert_eq!(
            c.classify(Some("generativelanguage.googleapis.com"), ip),
            Some(Provider::Gemini)
        );
        assert_eq!(
            c.classify(Some("us-central1-aiplatform.googleapis.com"), ip),
            Some(Provider::Gemini)
        );
        assert_eq!(
            c.classify(Some("cloudaicompanion.googleapis.com"), ip),
            Some(Provider::Gemini)
        );
        assert_eq!(
            c.classify(Some("GEMINICLOUDASSIST.GOOGLEAPIS.COM."), ip),
            Some(Provider::Gemini)
        );
        assert_eq!(
            c.classify(Some("api.cohere.ai"), ip),
            Some(Provider::Cohere)
        );
        assert_eq!(c.classify(Some("api.x.ai"), ip), Some(Provider::XAi));
        assert_eq!(c.classify(Some("api.groq.com"), ip), Some(Provider::Groq));
        assert_eq!(
            c.classify(Some("api.together.xyz"), ip),
            Some(Provider::Together)
        );
        assert_eq!(
            c.classify(Some("api.perplexity.ai"), ip),
            Some(Provider::Perplexity)
        );
        assert_eq!(
            c.classify(Some("api.fireworks.ai"), ip),
            Some(Provider::Fireworks)
        );
        assert_eq!(
            c.classify(Some("openrouter.ai"), ip),
            Some(Provider::OpenRouter)
        );
        assert_eq!(c.classify(None, ip), None); // no SNI → unclassified
        assert_eq!(c.classify(Some("example.com"), ip), None);
        for non_gemini_google_api in [
            "oauthaccountmanager.googleapis.com",
            "content-autofill.googleapis.com",
            "safebrowsing.googleapis.com",
            "serviceusage.googleapis.com",
        ] {
            assert_eq!(
                c.classify(Some(non_gemini_google_api), ip),
                None,
                "{non_gemini_google_api} must not be classified as Gemini"
            );
        }
        assert_eq!(c.classify(Some("notopenai.com"), ip), None);
        assert_eq!(c.classify(Some("evilopenrouter.ai"), ip), None);
    }

    #[test]
    fn parse_cgroup_extracts_containerd_pod_and_container() {
        // containerd / cri-o systemd layout — pod UID uses '_' which must become '-'.
        let cg = "0::/kubepods.slice/kubepods-besteffort.slice/\
                  kubepods-besteffort-poda1b2c3d4_e5f6_7890_abcd_ef1234567890.slice/\
                  cri-containerd-1111111111111111111111111111111111111111111111111111111111111111.scope\n";
        let k = parse_cgroup(cg);
        assert_eq!(
            k.pod_uid.as_deref(),
            Some("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        );
        assert_eq!(k.container_id.as_deref(), Some("111111111111")); // short id (12)
    }

    #[test]
    fn parse_cgroup_extracts_docker_container_only() {
        let cg = "0::/system.slice/\
                  docker-2222222222222222222222222222222222222222222222222222222222222222.scope\n";
        let k = parse_cgroup(cg);
        assert_eq!(k.container_id.as_deref(), Some("222222222222"));
        assert_eq!(k.pod_uid, None);
    }

    #[test]
    fn parse_cgroup_none_for_bare_host() {
        let k = parse_cgroup("0::/user.slice/user-1000.slice/session-2.scope\n");
        assert!(k.pod_uid.is_none());
        assert!(k.container_id.is_none());
    }

    #[test]
    fn json_exporter_protects_exits_when_ordinary_queue_is_full() {
        use crate::model::AgentEvent;
        let ex = JsonExporter::with_limits(1, 1, 1);
        let event = |kind| EnrichedEvent {
            identity: Identity::default(),
            workload: None,
            observation: None,
            process: None,
            provider: None,
            event: kind,
        };
        ex.export(&event(AgentEvent::FileDelete {
            pid: 1,
            path: "/tmp/a".into(),
        }));
        ex.export(&event(AgentEvent::FileDelete {
            pid: 2,
            path: "/tmp/b".into(),
        }));
        assert_eq!(ex.output_drops(), 1);
        ex.export(&event(AgentEvent::ProcessExit {
            pid: 1,
            exit_code: 0,
            signal: 0,
        }));
        assert_eq!(ex.output_drops(), 1);
    }

    #[test]
    fn json_exporter_exec_backpressure_does_not_drop() {
        use crate::model::AgentEvent;
        let ex = JsonExporter::with_limits(0, 1, 1);
        let exec = |pid| EnrichedEvent {
            identity: Identity::default(),
            workload: None,
            observation: None,
            process: None,
            provider: None,
            event: AgentEvent::ToolExec {
                pid,
                ppid: 1,
                uid: 1000,
                argv: vec!["git".into()],
                argv_truncated: false,
                argv_incomplete: false,
                exec_confirmed: true,
                argv_source: "kernel_compact".into(),
                captured_argc: 1,
                captured_bytes: 4,
                observed_argc: 1,
                observed_bytes: 4,
                cwd: String::new(),
            },
        };
        ex.export(&exec(10));
        ex.export(&exec(11));
        assert_eq!(ex.output_drops_by_kind().get("ToolExec"), None);
        assert_eq!(ex.output_drops(), 0);
    }

    #[test]
    fn json_exporter_export_is_nonblocking() {
        use crate::model::AgentEvent;
        let ex = JsonExporter::new();
        let ev = EnrichedEvent {
            identity: Identity {
                agent: Some("agent-x".into()),
                task: Some("1".into()),
                session: None,
            },
            workload: None,
            observation: None,
            process: None,
            provider: None,
            event: AgentEvent::ProcessExit {
                pid: 1,
                exit_code: 0,
                signal: 0,
            },
        };
        for _ in 0..50 {
            ex.export(&ev);
        }
        assert_eq!(ex.output_drops(), 0); // 50 << queue cap → nothing dropped, never blocks
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
