//! The telemetry data model: raw kernel events, and the enriched, identity-tagged
//! events the [`Exporter`](crate::Exporter) receives.

use crate::traits::{Identity, Provider};
use std::net::IpAddr;
use std::time::Duration;

/// A raw event captured by an eBPF probe, before identity enrichment.
#[derive(Debug, Clone)]
pub enum AgentEvent {
    /// A tool / subprocess was executed (`sched_process_exec`).
    ToolExec {
        pid: u32,
        ppid: u32,
        argv: Vec<String>,
        cwd: String,
    },
    /// A file was opened (`openat`).
    FileAccess { pid: u32, path: String, write: bool },
    /// An outbound LLM call, derived from socket flow + TLS SNI.
    ///
    /// Payload (model, prompt, exact tokens) is NOT available at the network layer;
    /// `est_tokens`/cost are derived from byte counts by the correlation engine.
    LlmCall {
        pid: u32,
        /// `server_name` from the TLS ClientHello (plaintext), when present.
        sni: Option<String>,
        peer: IpAddr,
        req_bytes: u64,
        resp_bytes: u64,
        latency: Duration,
        /// Time to first response byte — a TTFT proxy for streaming responses.
        ttft: Option<Duration>,
    },
    /// A non-LLM outbound connection (egress).
    Egress {
        pid: u32,
        sni: Option<String>,
        peer: IpAddr,
        bytes: u64,
    },
}

/// An [`AgentEvent`] tagged with the resolved [`Identity`] and, for LLM calls, the
/// classified [`Provider`]. This is what an [`Exporter`](crate::Exporter) emits.
#[derive(Debug, Clone)]
pub struct EnrichedEvent {
    pub identity: Identity,
    pub provider: Option<Provider>,
    pub event: AgentEvent,
}
