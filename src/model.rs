//! The telemetry data model: raw kernel events, and the enriched, identity-tagged
//! events the [`Exporter`](crate::Exporter) receives.

use crate::traits::{Identity, Provider};
use serde::Serialize;
use std::net::IpAddr;
use std::time::Duration;

/// Kernel-observed process context used by downstream attribution engines.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
}

/// A raw event captured by an eBPF probe, before identity enrichment.
#[derive(Debug, Clone, Serialize)]
pub enum AgentEvent {
    /// A tool / subprocess was executed (`sched_process_exec`).
    ToolExec {
        pid: u32,
        ppid: u32,
        /// Real UID the tool runs as (0 = root) — surfaces privilege / privesc.
        uid: u32,
        argv: Vec<String>,
        cwd: String,
    },
    /// A process exited (`do_exit` kprobe) — the tool's outcome: exit code AND terminating signal
    /// (0 = clean; 9 = SIGKILL/OOM; 11 = SIGSEGV crash). Pairs with `ToolExec` to bracket a tool's
    /// lifecycle (started → finished / crashed / killed).
    ProcessExit {
        pid: u32,
        exit_code: u32,
        signal: u32,
    },
    /// A file was opened (`openat`).
    FileAccess { pid: u32, path: String, write: bool },
    /// A file was deleted (`unlinkat`) — a destructive action; pairs with `FileAccess`.
    FileDelete { pid: u32, path: String },
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
        /// Destination port (host order) — the service class: 443 API, 22 SSH, 5432 PG, 6379 Redis…
        port: u16,
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
    /// Structured LLM-API telemetry parsed from captured TLS content: `model` from the request
    /// body, token `usage` from the response. Best-effort (depends on the bytes landing within the
    /// snapshot); pairs with `SslContent` to turn raw plaintext into "which model, how many tokens".
    LlmApi {
        pid: u32,
        is_request: bool,
        model: Option<String>,
        prompt_tokens: Option<u32>,
        completion_tokens: Option<u32>,
    },
    /// A security-sensitive action — rare and high-signal, filtered in-kernel: privilege escalation
    /// (`setuid`/`setresuid`/`setreuid` → root from non-root — note legitimate `sudo`/`su` also fire
    /// this; it's a real transition, expected to pair with a `ToolExec`), process injection (`ptrace`
    /// attach/seize of another process), or opening an off-host-reachable listening port (`bind` to a
    /// fixed non-loopback port). `kind` names which; `detail` is kind-specific. Group (`setgid`) and
    /// loopback-only binds are intentionally out of scope.
    SecurityAction {
        pid: u32,
        /// "setuid-root" (privesc) | "ptrace" (injection) | "bind" (opened a port).
        kind: &'static str,
        /// ptrace: target pid · bind: port · setuid-root: 0.
        detail: u64,
    },
    /// Collector liveness and throughput telemetry. This is an observer-side control-plane event,
    /// not an agent action. It lets downstream platforms detect node/DaemonSet coverage gaps,
    /// slow consumers, ring drops, and feature enablement without requiring any agent SDK.
    CollectorHeartbeat {
        collector_id: String,
        node_name: Option<String>,
        namespace: Option<String>,
        pod_name: Option<String>,
        version: String,
        mode: String,
        attached_probes: u32,
        enabled_features: Vec<String>,
        interval_secs: u64,
        observed_agents: u64,
        exec: u64,
        exit: u64,
        egress: u64,
        dns: u64,
        file: u64,
        llm: u64,
        ssl: u64,
        sec: u64,
        dropped: u64,
        output_dropped: u64,
    },
}

/// An [`AgentEvent`] tagged with the resolved [`Identity`] and, for LLM calls, the
/// classified [`Provider`]. This is what an [`Exporter`](crate::Exporter) emits.
#[derive(Debug, Clone, Serialize)]
pub struct EnrichedEvent {
    pub identity: Identity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessContext>,
    pub provider: Option<Provider>,
    pub event: AgentEvent,
}
