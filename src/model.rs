//! The telemetry data model: raw kernel events, and the enriched, identity-tagged
//! events the [`Exporter`](crate::Exporter) receives.

use crate::traits::{Identity, Provider};
use crate::workload::{ObservationMetadata, WorkloadIdentity};
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

/// Kernel-observed process context used by downstream attribution engines.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProcessContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    pub pid: u32,
    pub ppid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time_ticks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_boottime_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_hz: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_parent_start_boottime_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_parent_start_boottime_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_relation_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineage_complete: Option<bool>,
    pub comm: String,
    /// Linux mount namespace inode. This scopes path-based file identity when a resolved
    /// device/inode pair is not available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mount_namespace: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    /// cgroup kernfs id captured by eBPF at event time.
    pub cgroup_id: u64,
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
        /// True when the configured argument-count or total-byte budget was exceeded.
        argv_truncated: bool,
        /// True when one or more kernel chunks were missing or reassembly timed out.
        argv_incomplete: bool,
        /// True when `sched_process_exec` confirmed that the kernel committed this exec.
        exec_confirmed: bool,
        /// `kernel_fragments` or `proc_cmdline` when a successful exec was supplemented.
        argv_source: String,
        captured_argc: u16,
        captured_bytes: u32,
        /// Argument count and bytes in the final exported argv after best-effort supplementation.
        observed_argc: u32,
        observed_bytes: u32,
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
    /// Payload (model, prompt, exact tokens) is intentionally unavailable in production
    /// metadata-only mode. `req_bytes`/`resp_bytes` are wire bytes (including TLS
    /// framing/handshake), so they are connection-level size proxies.
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
        /// Production interaction observation is source-level metadata-only: no payload buffer was
        /// read, parsed, hashed, or retained.
        capture_mode: &'static str,
        capture_completeness: &'static str,
        parse_status: &'static str,
        raw_retention_state: &'static str,
        presentation_state: &'static str,
        /// The syscall evidence is accumulated over one transport connection. It must not be
        /// presented as request-level latency for HTTP/2, WebSocket, or reused HTTP/1.1 sockets.
        timing_scope: &'static str,
        latency_availability: &'static str,
        ttft_availability: &'static str,
    },
    /// A user message extracted from a model request observed immediately before Codex/rustls
    /// encrypts it. The complete provider request is transiently parsed and then zeroized; only
    /// the selected user instruction plus bounded correlation metadata leave the Observer.
    ///
    /// This event is sensitive and belongs to the dedicated Interaction content lane. A
    /// downstream forwarder must never place it in the ordinary event/evidence ingest route.
    LlmRequestObserved {
        pid: u32,
        tid: u32,
        /// Monotonic kernel time at the first plaintext fragment. This is suitable for local
        /// ordering/correlation only; `EnrichedEvent.observation` carries wall-clock time.
        observed_at_monotonic_ns: u64,
        protocol: String,
        host: String,
        path: String,
        /// Whether host/path came from the observed HTTP upgrade/request headers or from the
        /// controlled runtime allowlist after attaching to an already-established WebSocket.
        endpoint_attribution: String,
        provider: String,
        model: Option<String>,
        session_id: Option<String>,
        thread_id: Option<String>,
        turn_id: Option<String>,
        window_id: Option<String>,
        request_kind: Option<String>,
        body_sha256: String,
        instruction_bytes: u32,
        instruction_sha256: String,
        user_instruction: String,
        capture_method: &'static str,
        capture_profile: &'static str,
        capture_completeness: &'static str,
        parse_status: &'static str,
        raw_request_retention_state: &'static str,
        presentation_state: &'static str,
    },
    /// An assistant response reassembled from plaintext observed immediately after the runtime
    /// decrypts it (kimi/OpenSSL `SSL_read` lane). SSE chunks are incrementally parsed and
    /// aggregated; only the bounded assistant text, tool calls, and token usage leave the
    /// Observer. The raw response stream is never retained.
    ///
    /// This event is sensitive and belongs to the dedicated Interaction content lane. A
    /// downstream forwarder must never place it in the ordinary event/evidence ingest route.
    LlmResponseObserved {
        pid: u32,
        tid: u32,
        /// Monotonic kernel time at the first plaintext response byte. Suitable for local
        /// ordering/correlation only; `EnrichedEvent.observation` carries wall-clock time.
        observed_at_monotonic_ns: u64,
        protocol: String,
        host: String,
        path: String,
        /// Same attribution source as the paired request (observed request headers).
        endpoint_attribution: String,
        provider: String,
        model: Option<String>,
        session_id: Option<String>,
        thread_id: Option<String>,
        turn_id: Option<String>,
        status_code: u16,
        finish_reason: Option<String>,
        /// Aggregated assistant text across all SSE deltas; empty for pure tool-call turns.
        assistant_content: String,
        content_sha256: String,
        content_bytes: u64,
        prompt_tokens: Option<u64>,
        completion_tokens: Option<u64>,
        total_tokens: Option<u64>,
        tool_calls: Vec<LlmToolCall>,
        /// First SSE `data:` arrival minus the paired request's send-complete time.
        ttft_ns: Option<u64>,
        /// Response completion minus the paired request's send-complete time.
        duration_ns: Option<u64>,
        capture_method: &'static str,
        capture_profile: &'static str,
        capture_completeness: &'static str,
        parse_status: &'static str,
        raw_response_retention_state: &'static str,
        presentation_state: &'static str,
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
        #[serde(default)]
        file_coalesced: u64,
        llm: u64,
        ssl: u64,
        sec: u64,
        exec_truncated: u64,
        exec_incomplete: u64,
        exec_reassembly_timeout: u64,
        dropped: u64,
        dropped_by_kind: BTreeMap<String, u64>,
        output_dropped: u64,
        output_dropped_by_kind: BTreeMap<String, u64>,
        interaction_capture_mode: String,
        payload_capture_enabled: bool,
        payload_kill_switch_at_unix_nanos: Option<u64>,
        payload_fragments_discarded: u64,
    },
}

/// One tool call aggregated from streaming `delta.tool_calls` chunks: `arguments` is the
/// concatenation of the incremental JSON string fragments for `function.arguments`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LlmToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

/// An [`AgentEvent`] tagged with the resolved [`Identity`] and, for LLM calls, the
/// classified [`Provider`]. This is what an [`Exporter`](crate::Exporter) emits.
#[derive(Debug, Clone, Serialize)]
pub struct EnrichedEvent {
    pub identity: Identity,
    /// Complete workload attribution, when a resolver can prove every stable identity field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload: Option<WorkloadIdentity>,
    /// Explicit timing and freshness for sampled signals. Consumers must not infer zero when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation: Option<ObservationMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessContext>,
    pub provider: Option<Provider>,
    pub event: AgentEvent,
}
