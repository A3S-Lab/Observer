//! The telemetry data model: raw kernel events, and the enriched, identity-tagged
//! events the [`Exporter`](crate::Exporter) receives.

use crate::traits::{Identity, Provider};
use serde::Serialize;
use std::net::IpAddr;
use std::time::Duration;

/// A raw event captured by an eBPF probe, before identity enrichment.
#[derive(Debug, Clone, Serialize)]
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
    /// An outbound LLM call (TLS connection to a known provider), with metrics accumulated
    /// in-kernel over the connection's lifetime and emitted on close.
    ///
    /// Payload (model, prompt, exact tokens) is NOT available at the network layer — that
    /// needs the opt-in TLS-payload extension. `req_bytes`/`resp_bytes` are wire bytes
    /// (include TLS framing/handshake), a proxy for request/response size.
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
    /// A DNS query — a hostname the process resolved (`sys_enter_sendto` to :53).
    Dns { pid: u32, query: String },
    /// Plaintext from a TLS connection, captured by the **opt-in** OpenSSL uprobe extension
    /// (`A3S_OBSERVER_SSL=1`): the request (prompt) or response (completion) body. OpenSSL
    /// only (not language-agnostic), off by default. `content` is a UTF-8-lossy snapshot,
    /// truncated to the kernel snapshot length.
    SslContent {
        pid: u32,
        /// true = response (`SSL_read`, completion); false = request (`SSL_write`, prompt).
        is_read: bool,
        content: String,
    },
}

/// An [`AgentEvent`] tagged with the resolved [`Identity`] and, for LLM calls, the
/// classified [`Provider`]. This is what an [`Exporter`](crate::Exporter) emits.
#[derive(Debug, Clone, Serialize)]
pub struct EnrichedEvent {
    pub identity: Identity,
    pub provider: Option<Provider>,
    pub event: AgentEvent,
}
