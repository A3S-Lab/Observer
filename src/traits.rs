//! Stable extension contracts: identity resolution, service classification, export.
//!
//! These are the swappable seams around the eBPF probe core. Each has a trivial default
//! implementation here; environment-specific ones (k8s, a3s-box, OTel) land with the
//! probes.

use crate::model::EnrichedEvent;
use std::net::IpAddr;

/// Who an event belongs to. Resolved from kernel-side keys (pid / cgroup / netns).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provider {
    OpenAi,
    Anthropic,
    Gemini,
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
            h if h.ends_with("openai.com") || h.ends_with("oaiusercontent.com") => Provider::OpenAi,
            h if h.ends_with("anthropic.com") => Provider::Anthropic,
            h if h.ends_with("googleapis.com") => Provider::Gemini,
            _ => return None,
        })
    }
}

/// Sink for enriched telemetry. Implementations: OTel (default target), Prometheus, log.
pub trait Exporter: Send + Sync {
    fn export(&self, event: &EnrichedEvent);
}

/// Trivial exporter that logs via `tracing`. Useful for bring-up; OTel is the real target.
pub struct LogExporter;

impl Exporter for LogExporter {
    fn export(&self, event: &EnrichedEvent) {
        tracing::info!(?event, "a3s-observer event");
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
        assert_eq!(c.classify(Some("api.openai.com"), ip), Some(Provider::OpenAi));
        assert_eq!(c.classify(Some("example.com"), ip), None);
    }
}
