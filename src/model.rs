//! The telemetry data model: raw kernel events, and the enriched, identity-tagged
//! events the [`Exporter`](crate::Exporter) receives.

use crate::traits::{Identity, Provider};
use crate::workload::{ObservationMetadata, WorkloadIdentity};
use serde::Serialize;
use std::net::IpAddr;
use std::time::Duration;

/// Exact event and Collector-receipt timestamps for one kernel ring record.
///
/// Both values are decimal strings because Unix nanoseconds already exceed JavaScript's safe
/// integer range. They are additive top-level NDJSON fields and are omitted for legacy or
/// userspace-only events that have no kernel capture timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventTiming {
    pub event_at_unix_ns: String,
    pub received_at_unix_ns: String,
}

impl EventTiming {
    pub fn from_unix_ns(event_at_unix_ns: u128, received_at_unix_ns: u128) -> Self {
        Self {
            event_at_unix_ns: event_at_unix_ns.to_string(),
            received_at_unix_ns: received_at_unix_ns.to_string(),
        }
    }
}

/// Kernel capture decision attached to one admitted raw Ring record.
///
/// Small enum-like values stay numeric and JSON-safe. The `u64` epoch is a decimal string so a
/// JavaScript forwarding layer cannot silently round it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventCaptureDecision {
    pub capture_epoch: String,
    pub capture_profile: u8,
    pub capture_action: u8,
    pub capture_authority: u8,
    pub capture_disposition: u8,
    pub capture_selected: bool,
    pub capture_flags: u8,
}

impl EventCaptureDecision {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capture_epoch: u64,
        capture_profile: u8,
        capture_action: u8,
        capture_authority: u8,
        capture_disposition: u8,
        capture_selected: bool,
        capture_flags: u8,
    ) -> Self {
        Self {
            capture_epoch: capture_epoch.to_string(),
            capture_profile,
            capture_action,
            capture_authority,
            capture_disposition,
            capture_selected,
            capture_flags,
        }
    }
}

/// Kernel-observed process context used by downstream attribution engines.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProcessContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    pub pid: u32,
    pub ppid: u32,
    /// PID namespace inode. String encoded so downstream JSON runtimes never round a u64 identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid_namespace: Option<String>,
    /// PID as observed in the innermost namespace (`NSpid`'s last value).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_pid: Option<u32>,
    /// Parent PID in the same innermost namespace, when the parent could be proven there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time_ticks: Option<u64>,
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
    /// How an exited process's lifecycle facts were resolved. Present only for lifecycle events;
    /// ordinary process observations retain their legacy shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_source: Option<String>,
    /// A bounded, actionable reason when the collector deliberately refused to inherit ancestry
    /// from a PID-only match (for example `pid_reuse_ambiguous`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_reason: Option<String>,
}

/// Additive file-prefilter heartbeat fields. Boxed inside [`AgentEvent::CollectorHeartbeat`] so
/// rare control-plane telemetry does not inflate every high-volume event enum on the hot path.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CollectorFileFilterStats {
    pub file_access: u64,
    pub file_delete: u64,
    /// Cumulative kernel prefilter counters since this collector loaded its eBPF object.
    pub file_prefilter_access_kept: u64,
    pub file_prefilter_access_unknown_kept: u64,
    pub file_prefilter_access_sampled: u64,
    pub file_prefilter_access_dropped: u64,
    pub file_prefilter_access_suppressed: u64,
    pub file_prefilter_delete_kept: u64,
    pub file_prefilter_delete_unknown_kept: u64,
    pub file_prefilter_delete_dropped: u64,
    pub file_prefilter_rule_hits: u64,
    pub file_prefilter_rule_misses: u64,
    pub file_prefilter_stale_rules: u64,
    pub file_access_ring_dropped: u64,
    pub file_delete_ring_dropped: u64,
    pub file_filter_enabled: bool,
    pub file_filter_epoch: u64,
    pub file_filter_unknown_policy: String,
}

/// Time bounds for one delta accounting window.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorPipelineWindow {
    pub started_at_unix_ms: u64,
    pub ended_at_unix_ms: u64,
}

/// Explicit units for counters that cross the physical-record to logical-event boundary.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorPipelineUnit {
    /// `ringSubmitted`, `ringDropped`, `collectorReceived`, `collectorEnqueued`, and
    /// `collectorDropped` count physical ring records.
    pub ring: String,
    /// `logicalEvents`, `queueAdmitted`, and `queueDropped` count exported semantic events.
    pub queue: String,
}

/// Optional collector-ingress boundary counters.
///
/// Keeping the two values in one flattened option makes their wire representation additive while
/// guaranteeing they are either both present or both absent. An absent pair is a legacy heartbeat,
/// not an implied zero.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorIngressAccounting {
    pub collector_enqueued: u64,
    pub collector_dropped: u64,
}

/// Delta counters for one fixed, low-cardinality ring channel.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorRingAccounting {
    pub ring: String,
    pub ring_submitted: u64,
    pub ring_dropped: u64,
    pub collector_received: u64,
    /// Physical records admitted to or rejected by the collector's bounded ingress queues.
    /// Flattened to retain the existing ring JSON shape.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub collector_ingress: Option<CollectorIngressAccounting>,
    /// Logical events produced after decoding, reassembly, enrichment, and semantic validation.
    pub logical_events: u64,
    pub queue_admitted: u64,
    pub queue_dropped: u64,
}

/// Additive end-to-end accounting emitted by collector heartbeats.
///
/// This envelope is independently versionable and optional so legacy heartbeat consumers keep
/// their existing fields and semantics while upgraded consumers gain restart-safe delta windows.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorPipelineAccounting {
    pub schema_version: String,
    pub producer_instance_id: String,
    pub sequence: u64,
    pub window: CollectorPipelineWindow,
    pub temporality: String,
    pub unit: CollectorPipelineUnit,
    pub rings: Vec<CollectorRingAccounting>,
}

/// Additive S5 capture-decision telemetry. Decision and physical delivery counters intentionally
/// advertise separate units so callers cannot equate one Exec decision with its many fragments.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorCaptureProfileStats {
    pub mode: String,
    pub active_epoch: u64,
    pub destructive_enabled: bool,
    pub decision_unit: String,
    pub payload_unit: String,
    pub delivery_unit: String,
    pub sample_node_limit_per_window: u32,
    pub aggregate_keys: u64,
    pub aggregate_emitted: u64,
    pub aggregate_output_retried: u64,
    pub aggregate_cleaned: u64,
    pub aggregate_read_errors: u64,
    /// True once exact per-scope ledger quality degraded (map/read failure). Raw fallback remains
    /// node-bounded; callers must not treat aggregate totals as complete after this flips.
    pub aggregate_ledger_degraded: bool,
    pub probes: Vec<CollectorCaptureProbeStats>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorCaptureProbeStats {
    pub probe: String,
    pub attempted: u64,
    pub full_selected: u64,
    pub aggregate_selected: u64,
    pub sample_selected: u64,
    pub sample_rejected: u64,
    pub drop_selected: u64,
    pub not_enabled: u64,
    pub decision_error: u64,
    pub probe_error: u64,
    pub payload_selected: u64,
    pub payload_error: u64,
    pub ring_submitted: u64,
    pub ring_dropped: u64,
    pub would_full: u64,
    pub would_aggregate: u64,
    pub would_sample: u64,
    pub would_drop: u64,
    pub rule_hit: u64,
    pub rule_miss: u64,
    pub stale_rule: u64,
    pub promotion_hit: u64,
    pub promotion_error: u64,
    pub aggregate_error: u64,
}

/// One provider-neutral message extracted from the exact HTTP body sent to or received from an
/// LLM endpoint. `content` deliberately remains structured JSON: text-only flattening would lose
/// multimodal parts, tool-result blocks, and provider-specific item types.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmInteractionMessage {
    pub role: String,
    pub content: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

/// A tool instruction visible in an LLM response. The matching execution/result may arrive in a
/// later model request; downstream correlates them by `tool_call_id`, never by time alone.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmInteractionToolCall {
    pub tool_call_id: String,
    pub name: String,
    pub arguments: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at_unix_ns: Option<String>,
}

/// A tool result that the Agent actually included in a subsequent final model request.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmInteractionToolResult {
    pub tool_call_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub content: serde_json::Value,
    pub is_error: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at_unix_ns: Option<String>,
}

/// Exact, bounded content for one side of a model HTTP exchange.
///
/// `body` is UTF-8 when `encoding=utf8`, otherwise RFC 4648 base64. It contains the decoded HTTP
/// entity body only; authorization/cookie headers are intentionally never exported.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmInteractionContent {
    pub body: String,
    pub encoding: String,
    pub content_type: String,
    pub captured_bytes: u64,
    pub decoded_bytes: u64,
    pub sha256: String,
    pub completeness: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<LlmInteractionMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentPlaintextEvidence {
    pub schema_version: String,
    pub evidence_id: String,
    pub pid: u32,
    pub connection_id: String,
    pub direction: String,
    pub tls_adapter_id: String,
    pub transport_protocol: String,
    pub parse_state: String,
    pub llm_likelihood: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_fingerprint: Option<String>,
    pub observed_at_unix_ns: String,
    pub captured_bytes: u64,
    pub encoding: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_sample: Option<String>,
    pub sample_sha256: String,
    pub reasons: Vec<String>,
    pub capture_source: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmInteraction {
    pub schema_version: String,
    pub interaction_id: String,
    pub interaction_type: String,
    pub pid: u32,
    pub connection_id: String,
    pub transport: String,
    pub protocol: String,
    pub tls_adapter_id: String,
    pub transport_protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_template_id: Option<String>,
    pub parse_state: String,
    pub llm_likelihood: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_fingerprint: Option<String>,
    pub transport_completeness: String,
    pub wire_completeness: String,
    pub conversation_completeness: String,
    pub endpoint: String,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_conversation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_response_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_previous_response_id: Option<String>,
    pub started_at_unix_ns: String,
    pub request_complete_at_unix_ns: String,
    pub first_response_at_unix_ns: String,
    pub ended_at_unix_ns: String,
    pub duration_ns: String,
    pub time_quality: String,
    pub request: Box<LlmInteractionContent>,
    pub response: Box<LlmInteractionContent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<LlmInteractionToolCall>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tool_results: Vec<LlmInteractionToolResult>,
    pub completeness: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub partial_reasons: Vec<String>,
    pub capture_source: String,
}

/// A raw event captured by an eBPF probe, before identity enrichment.
#[derive(Debug, Clone, Serialize)]
pub enum AgentEvent {
    /// A tool / subprocess was executed (`sched_process_exec`).
    ToolExec {
        /// Kernel execution generation used to correlate descendant/custom-tool activity without
        /// changing any existing trace or invocation field.
        #[serde(rename = "execId")]
        exec_id: u64,
        /// Lossless decimal representation for JSON consumers. `execId` remains present for wire
        /// compatibility, but contemporary boot-time-derived generations routinely exceed
        /// JavaScript's `Number.MAX_SAFE_INTEGER` and must never be round-tripped as a number.
        #[serde(rename = "execIdExact")]
        exec_id_exact: String,
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
    /// A file was opened (`openat`). `accessMode` is additive; `write` remains for legacy readers.
    FileAccess {
        pid: u32,
        path: String,
        write: bool,
        #[serde(rename = "accessMode")]
        access_mode: String,
    },
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
    /// A complete or explicitly-partial HTTP model exchange reconstructed from plaintext captured
    /// at a TLS-library or plain-TCP boundary. This is the stable semantic output of the content
    /// pipeline; raw `SslContent` remains only as a legacy diagnostic signal.
    LlmInteraction(Box<LlmInteraction>),
    /// Bounded metadata for an Agent plaintext stream whose transport or wire template is not yet
    /// supported. No credential header or unredacted raw payload is exported. This keeps unknown
    /// protocols discoverable and re-testable without turning them into fabricated conversations.
    AgentPlaintextEvidence(Box<AgentPlaintextEvidence>),
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
    /// Exact cumulative kernel summaries emitted as admitted deltas on the Bulk lane.
    CaptureAggregate {
        #[serde(rename = "windowStartUnixNs")]
        window_start_unix_ns: u128,
        /// Lossless aliases for JavaScript/JSON control and storage paths. Keep the numeric fields
        /// above/below for compatibility with existing readers.
        #[serde(rename = "windowStartUnixNsExact")]
        window_start_unix_ns_exact: String,
        #[serde(rename = "windowEndUnixNs")]
        window_end_unix_ns: u128,
        #[serde(rename = "windowEndUnixNsExact")]
        window_end_unix_ns_exact: String,
        #[serde(rename = "cgroupId")]
        cgroup_id: u64,
        probe: String,
        #[serde(rename = "effectiveAction")]
        effective_action: String,
        qualifier: u8,
        profile: String,
        epoch: u64,
        #[serde(rename = "policyVersion")]
        policy_version: u64,
        count: u64,
        bytes: u64,
        authority: String,
        reason: String,
        terminal: bool,
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
        /// True only for the partial-window heartbeat flushed during graceful shutdown.
        shutdown_final: bool,
        attached_probes: u32,
        enabled_features: Vec<String>,
        interval_secs: u64,
        observed_agents: u64,
        exec: u64,
        exit: u64,
        egress: u64,
        dns: u64,
        /// Legacy aggregate retained for downstream compatibility: FileAccess + FileDelete.
        file: u64,
        #[serde(flatten)]
        file_filter: Box<CollectorFileFilterStats>,
        llm: u64,
        ssl: u64,
        sec: u64,
        exec_truncated: u64,
        exec_incomplete: u64,
        exec_reassembly_timeout: u64,
        dropped: u64,
        output_dropped: u64,
        #[serde(rename = "pipelineAccounting", skip_serializing_if = "Option::is_none")]
        pipeline_accounting: Option<Box<CollectorPipelineAccounting>>,
        #[serde(rename = "captureProfile", skip_serializing_if = "Option::is_none")]
        capture_profile: Option<Box<CollectorCaptureProfileStats>>,
    },
}

/// An [`AgentEvent`] tagged with the resolved [`Identity`] and, for LLM calls, the
/// classified [`Provider`]. This is what an [`Exporter`](crate::Exporter) emits.
#[derive(Debug, Clone, Serialize)]
pub struct EnrichedEvent {
    /// Additive event-time contract. Flattening preserves the legacy top-level event shape.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub timing: Option<EventTiming>,
    /// Additive in-kernel capture decision for raw Ring events.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub capture_decision: Option<EventCaptureDecision>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn collector_heartbeat(shutdown_final: bool) -> AgentEvent {
        AgentEvent::CollectorHeartbeat {
            collector_id: "collector-test".to_string(),
            node_name: None,
            namespace: None,
            pod_name: None,
            version: "test".to_string(),
            mode: "observe".to_string(),
            shutdown_final,
            attached_probes: 0,
            enabled_features: Vec::new(),
            interval_secs: 1,
            observed_agents: 0,
            exec: 0,
            exit: 0,
            egress: 0,
            dns: 0,
            file: 0,
            file_filter: Box::default(),
            llm: 0,
            ssl: 0,
            sec: 0,
            exec_truncated: 0,
            exec_incomplete: 0,
            exec_reassembly_timeout: 0,
            dropped: 0,
            output_dropped: 0,
            pipeline_accounting: None,
            capture_profile: None,
        }
    }

    fn make_pipeline_accounting(
        collector_ingress: Option<CollectorIngressAccounting>,
    ) -> CollectorPipelineAccounting {
        CollectorPipelineAccounting {
            schema_version: "anysentry.pipeline_accounting.v1".into(),
            producer_instance_id: "producer-test".into(),
            sequence: 7,
            window: CollectorPipelineWindow {
                started_at_unix_ms: 10,
                ended_at_unix_ms: 20,
            },
            temporality: "delta".into(),
            unit: CollectorPipelineUnit {
                ring: "physical_record".into(),
                queue: "logical_event".into(),
            },
            rings: vec![CollectorRingAccounting {
                ring: "exec".into(),
                ring_submitted: 4,
                ring_dropped: 1,
                collector_received: 3,
                collector_ingress,
                logical_events: 1,
                queue_admitted: 1,
                queue_dropped: 0,
            }],
        }
    }

    #[test]
    fn collector_heartbeat_serializes_explicit_shutdown_marker() {
        for expected in [false, true] {
            let value = serde_json::to_value(collector_heartbeat(expected)).unwrap();
            assert_eq!(
                value["CollectorHeartbeat"]["shutdown_final"].as_bool(),
                Some(expected)
            );
        }
    }

    #[test]
    fn additive_exec_generation_and_aggregate_wire_names_are_stable() {
        const UNSAFE_JSON_INTEGER: u64 = 13_349_539_092_725_721;
        const UNSAFE_JSON_NANOS: u128 = 1_787_232_013_745_331_900;
        let tool = serde_json::to_value(AgentEvent::ToolExec {
            exec_id: UNSAFE_JSON_INTEGER,
            exec_id_exact: UNSAFE_JSON_INTEGER.to_string(),
            pid: 1,
            ppid: 0,
            uid: 0,
            argv: Vec::new(),
            argv_truncated: false,
            argv_incomplete: false,
            exec_confirmed: true,
            argv_source: "kernel_fragments".into(),
            captured_argc: 0,
            captured_bytes: 0,
            observed_argc: 0,
            observed_bytes: 0,
            cwd: String::new(),
        })
        .unwrap();
        assert_eq!(
            tool["ToolExec"]["execId"].as_u64(),
            Some(UNSAFE_JSON_INTEGER)
        );
        assert_eq!(
            tool["ToolExec"]["execIdExact"],
            UNSAFE_JSON_INTEGER.to_string()
        );

        let aggregate = serde_json::to_value(AgentEvent::CaptureAggregate {
            window_start_unix_ns: UNSAFE_JSON_NANOS,
            window_start_unix_ns_exact: UNSAFE_JSON_NANOS.to_string(),
            window_end_unix_ns: UNSAFE_JSON_NANOS + 2,
            window_end_unix_ns_exact: (UNSAFE_JSON_NANOS + 2).to_string(),
            cgroup_id: 3,
            probe: "dns".into(),
            effective_action: "sample".into(),
            qualifier: 0,
            profile: "unknown_discovery".into(),
            epoch: 4,
            policy_version: 5,
            count: 6,
            bytes: 7,
            authority: "discovery".into(),
            reason: "rule_miss_discovery".into(),
            terminal: false,
        })
        .unwrap();
        assert_eq!(
            aggregate["CaptureAggregate"]["windowStartUnixNsExact"],
            UNSAFE_JSON_NANOS.to_string()
        );
        assert_eq!(
            aggregate["CaptureAggregate"]["windowEndUnixNsExact"],
            (UNSAFE_JSON_NANOS + 2).to_string()
        );
        assert_eq!(aggregate["CaptureAggregate"]["effectiveAction"], "sample");
        assert_eq!(aggregate["CaptureAggregate"]["policyVersion"], 5);
    }

    #[test]
    fn process_lifecycle_markers_are_additive_and_omitted_by_default() {
        let legacy = serde_json::to_value(ProcessContext {
            pid: 42,
            ppid: 7,
            comm: "worker".into(),
            cgroup_id: 99,
            ..ProcessContext::default()
        })
        .unwrap();
        assert!(legacy.get("lifecycle_source").is_none());
        assert!(legacy.get("lifecycle_reason").is_none());
        assert!(legacy.get("pid_namespace").is_none());
        assert!(legacy.get("namespace_pid").is_none());
        assert!(legacy.get("namespace_ppid").is_none());

        let marked = serde_json::to_value(ProcessContext {
            pid: 42,
            ppid: 0,
            comm: "worker".into(),
            cgroup_id: 99,
            lifecycle_source: Some("exec_tombstone".into()),
            lifecycle_reason: Some("pid_reuse_ambiguous".into()),
            ..ProcessContext::default()
        })
        .unwrap();
        assert_eq!(marked["lifecycle_source"], "exec_tombstone");
        assert_eq!(marked["lifecycle_reason"], "pid_reuse_ambiguous");

        let namespaced = serde_json::to_value(ProcessContext {
            pid: 52_000,
            ppid: 51_999,
            pid_namespace: Some("4026532441".into()),
            namespace_pid: Some(1),
            namespace_ppid: Some(0),
            comm: "pi".into(),
            cgroup_id: 99,
            ..ProcessContext::default()
        })
        .unwrap();
        assert_eq!(namespaced["pid_namespace"], "4026532441");
        assert_eq!(namespaced["namespace_pid"], 1);
        assert_eq!(namespaced["namespace_ppid"], 0);
    }

    #[test]
    fn exact_event_timing_is_additive_and_json_safe() {
        const EVENT_NS: u128 = 1_787_232_013_745_331_901;
        const RECEIVED_NS: u128 = EVENT_NS + 17_000;
        let timed = EnrichedEvent {
            timing: Some(EventTiming::from_unix_ns(EVENT_NS, RECEIVED_NS)),
            capture_decision: None,
            identity: Identity::default(),
            workload: None,
            observation: None,
            process: None,
            provider: None,
            event: AgentEvent::ProcessExit {
                pid: 7,
                exit_code: 0,
                signal: 0,
            },
        };
        let value = serde_json::to_value(timed).unwrap();
        assert_eq!(value["eventAtUnixNs"], EVENT_NS.to_string());
        assert_eq!(value["receivedAtUnixNs"], RECEIVED_NS.to_string());

        let legacy = EnrichedEvent {
            timing: None,
            capture_decision: None,
            identity: Identity::default(),
            workload: None,
            observation: None,
            process: None,
            provider: None,
            event: AgentEvent::ProcessExit {
                pid: 7,
                exit_code: 0,
                signal: 0,
            },
        };
        let legacy_value = serde_json::to_value(legacy).unwrap();
        assert!(legacy_value.get("eventAtUnixNs").is_none());
        assert!(legacy_value.get("receivedAtUnixNs").is_none());
    }

    #[test]
    fn capture_decision_epoch_is_exact_and_other_fields_are_json_safe() {
        const EPOCH: u64 = 13_349_539_092_725_721;
        let event = EnrichedEvent {
            timing: None,
            capture_decision: Some(EventCaptureDecision::new(EPOCH, 6, 3, 2, 1, true, 1)),
            identity: Identity::default(),
            workload: None,
            observation: None,
            process: None,
            provider: None,
            event: AgentEvent::ProcessExit {
                pid: 7,
                exit_code: 0,
                signal: 0,
            },
        };
        let value = serde_json::to_value(event).unwrap();
        assert_eq!(value["captureEpoch"], EPOCH.to_string());
        assert_eq!(value["captureProfile"], 6);
        assert_eq!(value["captureAction"], 3);
        assert_eq!(value["captureAuthority"], 2);
        assert_eq!(value["captureDisposition"], 1);
        assert_eq!(value["captureSelected"], true);
        assert_eq!(value["captureFlags"], 1);
    }

    #[test]
    fn collector_heartbeat_pipeline_accounting_is_optional_and_uses_explicit_units() {
        let without = serde_json::to_value(collector_heartbeat(false)).unwrap();
        assert!(without["CollectorHeartbeat"]
            .get("pipelineAccounting")
            .is_none());

        let mut with = collector_heartbeat(false);
        let AgentEvent::CollectorHeartbeat {
            pipeline_accounting,
            ..
        } = &mut with
        else {
            unreachable!()
        };
        *pipeline_accounting = Some(Box::new(make_pipeline_accounting(None)));

        let value = serde_json::to_value(with).unwrap();
        let accounting = &value["CollectorHeartbeat"]["pipelineAccounting"];
        assert_eq!(
            accounting["schemaVersion"],
            "anysentry.pipeline_accounting.v1"
        );
        assert_eq!(accounting["producerInstanceId"], "producer-test");
        assert_eq!(accounting["sequence"], 7);
        assert_eq!(accounting["temporality"], "delta");
        assert_eq!(accounting["unit"]["ring"], "physical_record");
        assert_eq!(accounting["unit"]["queue"], "logical_event");
        assert_eq!(accounting["rings"][0]["ringSubmitted"], 4);
        assert_eq!(accounting["rings"][0]["logicalEvents"], 1);
        assert!(accounting["rings"][0].get("collectorEnqueued").is_none());
        assert!(accounting["rings"][0].get("collectorDropped").is_none());
    }

    #[test]
    fn collector_ingress_accounting_is_additive_and_serializes_as_a_pair() {
        let mut heartbeat = collector_heartbeat(false);
        let AgentEvent::CollectorHeartbeat {
            pipeline_accounting: accounting,
            ..
        } = &mut heartbeat
        else {
            unreachable!()
        };
        *accounting = Some(Box::new(make_pipeline_accounting(Some(
            CollectorIngressAccounting {
                collector_enqueued: 2,
                collector_dropped: 1,
            },
        ))));

        let value = serde_json::to_value(heartbeat).unwrap();
        let ring = &value["CollectorHeartbeat"]["pipelineAccounting"]["rings"][0];
        assert_eq!(ring["collectorReceived"], 3);
        assert_eq!(ring["collectorEnqueued"], 2);
        assert_eq!(ring["collectorDropped"], 1);
        assert_eq!(ring["logicalEvents"], 1);
        assert_eq!(
            ring["collectorReceived"].as_u64(),
            Some(
                ring["collectorEnqueued"].as_u64().unwrap()
                    + ring["collectorDropped"].as_u64().unwrap()
            )
        );
    }
}
