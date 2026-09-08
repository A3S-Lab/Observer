//! Bounded HTTP/1.x, HTTP/2 (HEADERS+DATA), and SSE reconstruction for plaintext captured at TLS
//! or TCP boundaries.
//!
//! The eBPF hot path only copies bytes. This module owns framing, decompression, provider-neutral
//! message/tool extraction, request-response pairing, and explicit completeness. It intentionally
//! receives no authorization headers in its output contract. HTTP/2 decodes a bounded HPACK subset
//! (`:method`/`:path`/`:status`/`content-type`/`host`/`authority`) plus DATA bodies; HPACK desync
//! surfaces as `h2_hpack_desync` while the DATA body-only lane continues.

use a3s_observer::{
    DefaultLlmFormatAdapter, LlmConversationAnchor, LlmFormatAdapter, LlmInteractionContent,
    LlmInteractionMessage, LlmInteractionSemanticItem, LlmInteractionToolCall,
    LlmInteractionToolResult, LlmTokenUsage,
};
use a3s_observer_common::{
    classify_http_method_prefix, HTTP_METHOD_PREFIX_COMPLETE, TLS_BIND_QUALITY_FD,
};
use crate::h2_hpack::{HpackDecoder, Http2HeaderBlock};
use base64::Engine as _;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use flate2::{Decompress, FlushDecompress, Status};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Read;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const DEFAULT_MAX_CONNECTIONS: usize = 2_048;
const DEFAULT_MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_WEBSOCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_HEADERS: usize = 96;
const MAX_SSE_STRUCTURED_EVENTS: usize = 2_048;
const MAX_EXPORTED_STRUCTURED_BYTES: usize = 512 * 1024;
const SEMANTIC_PARSER_ID: &str = "observer.agent-interaction";
const SEMANTIC_PARSER_VERSION: u32 = 2;
const MAX_CONVERSATION_ANCHORS: usize = 512;
const WEBSOCKET_MAX_FRAME_HEADER_BYTES: usize = 14;
const WEBSOCKET_DEFLATE_TAIL: &[u8; 4] = b"\x00\x00\xff\xff";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ChunkDirection {
    Request,
    Response,
}

#[derive(Clone, Debug)]
pub struct PlaintextChunk {
    pub cgroup_id: u64,
    pub pid: u32,
    pub connection_id: u64,
    pub sequence: u64,
    pub direction: ChunkDirection,
    pub data: Vec<u8>,
    pub event_at_unix_ns: u128,
    pub source: String,
    pub adapter_id: String,
    /// The Rustls implementation-family adapter may admit a payload before an exact HTTP route
    /// is visible (for example a body-only request or a WebSocket data frame).  This is capture
    /// provenance only; it must never by itself make an interaction partial or complete.
    pub route_candidate: bool,
    pub partial_reasons: Vec<String>,
    /// Kernel tls_ctx↔socket bind quality (`TLS_BIND_QUALITY_*`).
    pub bind_quality: u8,
    pub socket_fd: i32,
    pub socket_cookie: u64,
    pub fd_generation: u32,
}

#[derive(Debug)]
pub struct CompletedInteraction {
    pub schema_version: String,
    pub interaction_id: String,
    pub interaction_type: String,
    pub cgroup_id: u64,
    pub pid: u32,
    pub connection_id: String,
    pub transport: String,
    pub protocol: String,
    pub tls_adapter_id: String,
    pub transport_protocol: String,
    pub wire_template_id: Option<String>,
    pub parse_state: String,
    pub llm_likelihood: String,
    pub schema_fingerprint: Option<String>,
    pub transport_completeness: String,
    pub wire_completeness: String,
    pub conversation_completeness: String,
    pub endpoint: String,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub model: Option<String>,
    pub provider_conversation_id: Option<String>,
    pub provider_response_id: Option<String>,
    pub provider_previous_response_id: Option<String>,
    pub traffic_role: String,
    pub trace_id: Option<String>,
    pub run_id: Option<String>,
    pub session_id: Option<String>,
    pub invocation_id: Option<String>,
    pub conversation_anchors: Vec<LlmConversationAnchor>,
    pub started_at_unix_ns: String,
    pub request_complete_at_unix_ns: String,
    pub first_response_at_unix_ns: String,
    pub ended_at_unix_ns: String,
    pub duration_ns: String,
    pub time_quality: String,
    pub request: LlmInteractionContent,
    pub response: LlmInteractionContent,
    pub usage: Option<LlmTokenUsage>,
    pub tool_calls: Vec<LlmInteractionToolCall>,
    pub tool_results: Vec<LlmInteractionToolResult>,
    pub semantic_parser_id: String,
    pub semantic_parser_version: u32,
    pub semantic_items: Vec<LlmInteractionSemanticItem>,
    pub completeness: String,
    pub partial_reasons: Vec<String>,
    pub capture_source: String,
    pub bind_quality: u8,
    pub socket_fd: i32,
    pub socket_cookie: u64,
    pub fd_generation: u32,
}

#[derive(Debug)]
pub struct CompletedPlaintextEvidence {
    pub schema_version: String,
    pub evidence_id: String,
    pub cgroup_id: u64,
    pub pid: u32,
    pub connection_id: String,
    pub direction: String,
    pub tls_adapter_id: String,
    pub transport_protocol: String,
    pub parse_state: String,
    pub llm_likelihood: String,
    pub schema_fingerprint: Option<String>,
    pub observed_at_unix_ns: String,
    pub captured_bytes: u64,
    pub encoding: String,
    pub redacted_sample: Option<String>,
    pub sample_sha256: String,
    pub reasons: Vec<String>,
    pub capture_source: String,
}

/// Bounded reassembly health counters.  They are cumulative and intentionally separate from
/// semantic interaction counts: an eviction/timeout is an observability gap, not evidence that an
/// Agent did nothing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReassemblyMetrics {
    pub connection_evictions: u64,
    pub connection_expirations: u64,
    pub alias_evictions: u64,
    pub evidence_evictions: u64,
    pub fragment_tracker_evictions: u64,
    pub orphan_chunks: u64,
    pub sequence_gaps: u64,
    pub parser_failures: u64,
    pub body_limit_drops: u64,
    pub truncated_chunks: u64,
    /// Number of unknown Rustls pointers for which more than one stream remained a viable owner.
    /// This is deliberately separate from parser failures: ambiguity is an evidence result, not
    /// a reason to discard the underlying bytes or silently choose a stream.
    pub ambiguous_stream_bindings: u64,
    /// Number of Rustls pointer/stream observations that could not be safely bound and were
    /// retained as a bounded metadata gap.
    pub stream_binding_gaps: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ConnectionKey {
    cgroup_id: u64,
    pid: u32,
    connection_id: u64,
}

const MAX_STREAM_IDENTITY_ANCHORS: usize = 256;
const MAX_STREAM_IDENTITY_VALUE_BYTES: usize = 512;
// Body-only Rustls callbacks are the least-framed lane, so keep a tighter per-stream budget than
// the normal HTTP decoder. Oversize bytes still produce hash/gap evidence but cannot multiply
// memory across thousands of candidate connections.
const MAX_RUSTLS_BODY_ONLY_BYTES: usize = 2 * 1024 * 1024;
const MAX_PENDING_REQUESTS: usize = 128;
const MAX_PENDING_REQUEST_BYTES: usize = 8 * 1024 * 1024;

/// Bounded, in-memory identity evidence used only to decide whether a newly observed Rustls
/// pointer can be safely aliased to an existing physical stream.  Values are immediately
/// namespaced/hashed; raw provider/session identifiers are never retained in this state map.
#[derive(Debug, Default)]
struct StreamIdentityEvidence {
    endpoints: HashSet<String>,
    paths: HashSet<String>,
    anchor_hashes: HashSet<String>,
}

#[derive(Debug, Default)]
struct StreamIdentityProbe {
    endpoints: HashSet<String>,
    paths: HashSet<String>,
    anchor_hashes: HashSet<String>,
}

#[derive(Debug, Default)]
struct RustlsBodyOnlyState {
    buffer: Vec<u8>,
    started_at_unix_ns: Option<u128>,
    partial_reasons: Vec<String>,
    response_mode: BodyOnlyResponseMode,
    response_parsed_offset: usize,
    /// Offset through which the pending SSE tail was already searched for a block delimiter.
    /// Without it every fragment re-scanned the whole undelimited tail (quadratic; a never
    /// delimiting tail pinned a core inside `sse_block_delimiter`). Maintains the invariant
    /// that `buffer[parsed_offset .. scan_offset - 3]` contains no block delimiter.
    response_scan_offset: usize,
    response_event_count: usize,
    /// Exact JSON object slices used to build a parser-only sequence. The canonical response
    /// bytes remain in `buffer`; keeping raw slices prevents serde reserialization from changing
    /// hashes or key ordering in derived evidence.
    response_raw_events: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum BodyOnlyResponseMode {
    #[default]
    Unknown,
    Json,
    Sse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyOnlyFeedResult {
    NotCandidate,
    Pending,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionResolution {
    New,
    Resolved(ConnectionKey),
    Ambiguous(usize),
    Orphan,
}

impl StreamIdentityEvidence {
    fn observe_route(&mut self, endpoint: &str, path: &str) {
        if let Some(value) = bounded_route_value(endpoint) {
            bounded_insert(
                &mut self.endpoints,
                conversation_anchor_hash("stream_endpoint", &value),
                MAX_STREAM_IDENTITY_ANCHORS,
            );
        }
        if let Some(value) = bounded_path_value(path) {
            bounded_insert(
                &mut self.paths,
                conversation_anchor_hash("stream_path", &value),
                MAX_STREAM_IDENTITY_ANCHORS,
            );
        }
    }

    fn observe_http(&mut self, message: &HttpMessage, direction: ChunkDirection) {
        let (endpoint, path) = message_route_identity(message);
        if let (Some(endpoint), Some(path)) = (endpoint.as_deref(), path.as_deref()) {
            self.observe_route(endpoint, path);
        }
        if let Some(value) = parse_json_body(&message.body)
            .filter(|value| bindable_identity_payload(value, direction))
        {
            collect_stream_identity_values(&value, direction, &mut self.anchor_hashes);
        } else {
            for value in parse_sse_json_events(&message.body) {
                if bindable_identity_payload(&value, direction) {
                    collect_stream_identity_values(&value, direction, &mut self.anchor_hashes);
                }
            }
        }
    }

    fn matches(&self, probe: &StreamIdentityProbe) -> bool {
        let anchor_match = !probe.anchor_hashes.is_empty()
            && self
                .anchor_hashes
                .iter()
                .any(|value| probe.anchor_hashes.contains(value));
        let endpoint_conflict = !probe.endpoints.is_empty()
            && !self.endpoints.is_empty()
            && self.endpoints.is_disjoint(&probe.endpoints);
        let path_conflict = !probe.paths.is_empty()
            && !self.paths.is_empty()
            && self.paths.is_disjoint(&probe.paths);
        if anchor_match && !endpoint_conflict && !path_conflict {
            return true;
        }
        if endpoint_conflict || path_conflict {
            return false;
        }
        let endpoint_match =
            !probe.endpoints.is_empty() && !self.endpoints.is_disjoint(&probe.endpoints);
        let path_match = !probe.paths.is_empty() && !self.paths.is_disjoint(&probe.paths);
        if !probe.endpoints.is_empty() && !probe.paths.is_empty() {
            endpoint_match && path_match
        } else {
            endpoint_match || path_match
        }
    }
}

impl StreamIdentityProbe {
    fn from_http(message: &HttpMessage, direction: ChunkDirection) -> Self {
        let mut probe = Self::default();
        let (endpoint, path) = message_route_identity(message);
        if let Some(endpoint) = endpoint {
            bounded_insert(
                &mut probe.endpoints,
                conversation_anchor_hash("stream_endpoint", &endpoint),
                MAX_STREAM_IDENTITY_ANCHORS,
            );
        }
        if let Some(path) = path {
            bounded_insert(
                &mut probe.paths,
                conversation_anchor_hash("stream_path", &path),
                MAX_STREAM_IDENTITY_ANCHORS,
            );
        }
        if let Some(value) = parse_json_body(&message.body)
            .filter(|value| bindable_identity_payload(value, direction))
        {
            collect_stream_identity_values(&value, direction, &mut probe.anchor_hashes);
        } else {
            for value in parse_sse_json_events(&message.body) {
                if bindable_identity_payload(&value, direction) {
                    collect_stream_identity_values(&value, direction, &mut probe.anchor_hashes);
                }
            }
        }
        probe
    }

    fn from_websocket_payload(payload: &[u8], direction: ChunkDirection) -> Option<Self> {
        let value = serde_json::from_slice::<Value>(payload).ok()?;
        if !bindable_identity_payload(&value, direction) {
            return None;
        }
        let mut probe = Self::default();
        collect_stream_identity_values(&value, direction, &mut probe.anchor_hashes);
        (!probe.anchor_hashes.is_empty()).then_some(probe)
    }

    fn has_signal(&self) -> bool {
        !self.endpoints.is_empty() || !self.paths.is_empty() || !self.anchor_hashes.is_empty()
    }
}

fn bounded_insert(set: &mut HashSet<String>, value: String, limit: usize) {
    if set.len() < limit || set.contains(&value) {
        set.insert(value);
    }
}

fn bounded_route_value(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_STREAM_IDENTITY_VALUE_BYTES {
        return None;
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return None;
    }
    let value = value
        .split_once('#')
        .map(|(prefix, _)| prefix)
        .unwrap_or(value)
        .split_once('?')
        .map(|(prefix, _)| prefix)
        .unwrap_or(value);
    let value = value
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(value);
    Some(value.to_ascii_lowercase())
}

fn message_route_identity(message: &HttpMessage) -> (Option<String>, Option<String>) {
    let endpoint =
        bounded_route_value(message.endpoint().as_str()).filter(|value| value != "unknown");
    let path =
        request_line(&message.start_line).and_then(|(_, path)| bounded_path_value(path.as_str()));
    (endpoint, path)
}

fn bounded_path_value(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_STREAM_IDENTITY_VALUE_BYTES {
        return None;
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return None;
    }
    Some(
        value
            .split_once('#')
            .map(|(prefix, _)| prefix)
            .unwrap_or(value)
            .split_once('?')
            .map(|(prefix, _)| prefix)
            .unwrap_or(value)
            .to_ascii_lowercase(),
    )
}

fn add_stream_identity_value(set: &mut HashSet<String>, value: Option<&str>) {
    let Some(value) = value.map(str::trim) else {
        return;
    };
    if value.is_empty()
        || value.len() > MAX_STREAM_IDENTITY_VALUE_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return;
    }
    // Keep only a namespaced digest in the bounded resolver state.  The same digest is used for
    // a response ID and a later previous-response/tool-result reference, allowing an evidence
    // match without retaining raw provider/session values in the long-lived connection map.
    bounded_insert(
        set,
        conversation_anchor_hash("stream_identity", value),
        MAX_STREAM_IDENTITY_ANCHORS,
    );
}

fn collect_stream_identity_values(
    value: &Value,
    direction: ChunkDirection,
    output: &mut HashSet<String>,
) {
    add_stream_identity_value(output, extract_provider_conversation_id(value).as_deref());
    add_stream_identity_value(
        output,
        value.get("previous_response_id").and_then(Value::as_str),
    );
    add_stream_identity_value(
        output,
        value
            .get("client_metadata")
            .and_then(|metadata| provider_id_from_metadata(Some(metadata), 0))
            .as_deref(),
    );
    add_stream_identity_value(
        output,
        value
            .get("client_metadata")
            .and_then(|metadata| turn_id_from_metadata(Some(metadata), 0))
            .as_deref(),
    );
    if direction == ChunkDirection::Response {
        add_stream_identity_value(output, extract_provider_response_id(value).as_deref());
    }
    for message in extract_request_messages(value) {
        add_stream_identity_value(output, message.source_item_id.as_deref());
        add_stream_identity_value(output, message.turn_id.as_deref());
        add_stream_identity_value(output, message.tool_call_id.as_deref());
    }
    for call in extract_tool_calls(value, 0) {
        add_stream_identity_value(output, Some(call.tool_call_id.as_str()));
    }
    for result in extract_tool_results(value, 0) {
        add_stream_identity_value(output, Some(result.tool_call_id.as_str()));
    }
}

fn bindable_identity_payload(value: &Value, direction: ChunkDirection) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let has_model = object.get("model").and_then(Value::as_str).is_some();
    let has_input_shape = object
        .get("input")
        .is_some_and(|input| input.is_array() || input.is_string() || input.is_object());
    match direction {
        ChunkDirection::Request => {
            (has_model
                && (has_input_shape
                    || object.contains_key("messages")
                    || object.contains_key("contents")
                    || object.contains_key("prompt")
                    || object.contains_key("instructions")))
                || object.get("type").and_then(Value::as_str) == Some("response.create")
                || object.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
                || object.get("method").and_then(Value::as_str).is_some()
        }
        ChunkDirection::Response => {
            object.get("choices").is_some_and(Value::is_array)
                || object.get("candidates").is_some_and(Value::is_array)
                || object
                    .get("output")
                    .is_some_and(|output| output.is_array() || output.is_object())
                || object.get("output_text").is_some()
                || object.get("content").is_some_and(Value::is_array)
                || object
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| {
                        kind.starts_with("response.")
                            || matches!(
                                kind,
                                "message"
                                    | "message_start"
                                    | "message_delta"
                                    | "message_stop"
                                    | "content_block_start"
                                    | "content_block_delta"
                                    | "content_block_stop"
                                    | "error"
                                    | "message_error"
                            )
                    })
                || object.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        }
    }
}

impl From<&PlaintextChunk> for ConnectionKey {
    fn from(value: &PlaintextChunk) -> Self {
        Self {
            cgroup_id: value.cgroup_id,
            pid: value.pid,
            connection_id: value.connection_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamKind {
    Request,
    Response,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WireInteractionKind {
    Model,
    Tool,
    Unparsed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WireMatch {
    template_id: &'static str,
    likelihood: &'static str,
    parse_state: &'static str,
    interaction_kind: WireInteractionKind,
}

#[derive(Debug)]
struct HttpMessage {
    start_line: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    captured_body_bytes: usize,
    started_at_unix_ns: u128,
    completed_at_unix_ns: u128,
    partial_reasons: Vec<String>,
    metadata_inferred: bool,
    transport_protocol: Option<String>,
    /// Optional parser-only representation for a body whose canonical bytes are kept in `body`.
    /// Rustls can expose a sequence of JSON lifecycle objects without HTTP framing; the sequence
    /// is converted to bounded SSE solely for the provider-neutral parser while hashes/evidence
    /// continue to use the exact observed bytes.
    derived_body: Option<Vec<u8>>,
}

impl HttpMessage {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    fn content_type(&self) -> &str {
        self.header("content-type")
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("application/octet-stream")
    }

    fn endpoint(&self) -> String {
        self.header("host").unwrap_or("unknown").to_string()
    }
}

#[derive(Debug)]
struct HttpStreamDecoder {
    kind: StreamKind,
    buffer: Vec<u8>,
    buffer_started_at_unix_ns: Option<u128>,
    last_at_unix_ns: u128,
    max_bytes: usize,
    partial_reasons: Vec<String>,
    last_decode_error: Option<String>,
    /// Terminal-scan resume cursors for the pending unframed/chunked SSE response. Offsets are
    /// relative to the current pending message body and reset on every message advance.
    sse_scan: SseTerminalScanState,
    /// Separate cursors for the de-chunked body inside `decode_chunked`: the de-chunked bytes
    /// and the raw framing bytes are different sequences and must not share resume offsets.
    chunked_scan: SseTerminalScanState,
}

impl HttpStreamDecoder {
    fn new(kind: StreamKind, max_bytes: usize) -> Self {
        Self {
            kind,
            buffer: Vec::new(),
            buffer_started_at_unix_ns: None,
            last_at_unix_ns: 0,
            max_bytes,
            partial_reasons: Vec::new(),
            last_decode_error: None,
            sse_scan: SseTerminalScanState::default(),
            chunked_scan: SseTerminalScanState::default(),
        }
    }

    fn push(
        &mut self,
        data: &[u8],
        event_at_unix_ns: u128,
        reasons: &[String],
    ) -> Vec<HttpMessage> {
        if data.is_empty() {
            return Vec::new();
        }
        if self.buffer.is_empty() {
            self.buffer_started_at_unix_ns = Some(event_at_unix_ns);
        }
        self.last_at_unix_ns = event_at_unix_ns;
        extend_unique(&mut self.partial_reasons, reasons.iter().cloned());

        let remaining = self.max_bytes.saturating_sub(self.buffer.len());
        let admitted = data.len().min(remaining);
        self.buffer.extend_from_slice(&data[..admitted]);
        if admitted < data.len() {
            extend_unique(
                &mut self.partial_reasons,
                ["reassembly_body_limit".to_string()],
            );
        }

        let mut messages = Vec::new();
        loop {
            if self.kind == StreamKind::Response {
                let detached_terminator = detached_chunk_terminator_prefix(&self.buffer);
                if detached_terminator > 0 {
                    self.buffer.drain(..detached_terminator);
                    // The body offsets the scan cursors refer to shift with the drain; restart
                    // the terminal search for whatever pending message remains.
                    self.sse_scan = SseTerminalScanState::default();
                    self.chunked_scan = SseTerminalScanState::default();
                    self.buffer_started_at_unix_ns =
                        (!self.buffer.is_empty()).then_some(event_at_unix_ns);
                    if self.buffer.is_empty() {
                        break;
                    }
                }
            }
            let kind = self.kind;
            let max_bytes = self.max_bytes;
            let Self {
                buffer,
                sse_scan,
                chunked_scan,
                ..
            } = self;
            let decoded = match decode_http_message(kind, buffer, max_bytes, sse_scan, chunked_scan)
            {
                Ok(Some(decoded)) => decoded,
                Ok(None) => break,
                Err(reason) => {
                    self.last_decode_error = Some(reason.clone());
                    // A decode error does NOT advance the message boundary: the buffer prefix
                    // (and therefore the parsed headers and the pending body start) is
                    // unchanged, so the terminal-scan resume cursors still point into the same
                    // monotonically growing body. Resetting them here would make every retry
                    // rescan the whole body from scratch — a misframed-but-persistent stream
                    // (e.g. declared chunked carrying raw LF-only SSE) re-errs on every
                    // fragment and turned that into a quadratic rescan that pinned a core.
                    // Real boundary advances (drain, detached prefix, unparsed tail) reset the
                    // cursors in their own branches.
                    extend_unique(&mut self.partial_reasons, [reason]);
                    break;
                }
            };
            self.last_decode_error = None;
            let mut reasons = std::mem::take(&mut self.partial_reasons);
            extend_unique(&mut reasons, decoded.partial_reasons);
            messages.push(HttpMessage {
                start_line: decoded.start_line,
                headers: decoded.headers,
                body: decoded.body,
                captured_body_bytes: decoded.captured_body_bytes,
                started_at_unix_ns: self.buffer_started_at_unix_ns.unwrap_or(event_at_unix_ns),
                completed_at_unix_ns: event_at_unix_ns,
                partial_reasons: reasons,
                metadata_inferred: false,
                transport_protocol: None,
                derived_body: None,
            });
            self.buffer.drain(..decoded.consumed);
            // A completed message ends the pending body the scan cursors referred to; whatever
            // bytes remain start a new pending message from offset zero.
            self.sse_scan = SseTerminalScanState::default();
            self.chunked_scan = SseTerminalScanState::default();
            self.buffer_started_at_unix_ns = (!self.buffer.is_empty()).then_some(event_at_unix_ns);
        }
        messages
    }

    fn take_unparsed_tail(&mut self) -> Vec<u8> {
        self.buffer_started_at_unix_ns = None;
        self.last_at_unix_ns = 0;
        self.partial_reasons.clear();
        self.last_decode_error = None;
        self.sse_scan = SseTerminalScanState::default();
        self.chunked_scan = SseTerminalScanState::default();
        std::mem::take(&mut self.buffer)
    }
}

#[derive(Debug)]
struct DecodedHttpMessage {
    consumed: usize,
    start_line: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    captured_body_bytes: usize,
    partial_reasons: Vec<String>,
}

#[derive(Debug)]
struct DecodedWebSocketFrame {
    consumed: usize,
    fin: bool,
    compressed: bool,
    opcode: u8,
    masked: bool,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct DecodedWebSocketMessage {
    payload: Vec<u8>,
    started_at_unix_ns: u128,
    completed_at_unix_ns: u128,
    partial_reasons: Vec<String>,
}

#[derive(Debug)]
struct FragmentedWebSocketMessage {
    compressed: bool,
    payload: Vec<u8>,
    started_at_unix_ns: u128,
    partial_reasons: Vec<String>,
}

#[derive(Debug)]
struct WebSocketFrameDecoder {
    kind: StreamKind,
    buffer: Vec<u8>,
    buffer_started_at_unix_ns: Option<u128>,
    max_bytes: usize,
    partial_reasons: Vec<String>,
    fragmented: Option<FragmentedWebSocketMessage>,
    compression_enabled: bool,
    no_context_takeover: bool,
    /// Mid-flight recovery: skip bytes to the next plausible frame header on decode errors
    /// instead of hard-resetting (first TLS callback often starts mid-frame).
    allow_midstream_resync: bool,
    inflater: Decompress,
    last_decode_error: Option<String>,
}

impl WebSocketFrameDecoder {
    fn new(kind: StreamKind, max_bytes: usize) -> Self {
        Self {
            kind,
            buffer: Vec::new(),
            buffer_started_at_unix_ns: None,
            max_bytes,
            partial_reasons: Vec::new(),
            fragmented: None,
            compression_enabled: false,
            no_context_takeover: false,
            allow_midstream_resync: false,
            inflater: Decompress::new(false),
            last_decode_error: None,
        }
    }

    fn configure_compression(&mut self, enabled: bool, no_context_takeover: bool) {
        self.compression_enabled = enabled;
        self.no_context_takeover = no_context_takeover;
        self.inflater.reset(false);
    }

    fn awaits_more_frame_bytes(&self) -> bool {
        !self.buffer.is_empty()
    }

    fn awaits_continuation_frame(&self) -> bool {
        self.fragmented.is_some()
    }

    fn push(
        &mut self,
        data: &[u8],
        event_at_unix_ns: u128,
        reasons: &[String],
    ) -> Vec<DecodedWebSocketMessage> {
        if data.is_empty() {
            return Vec::new();
        }
        if self.buffer.is_empty() {
            self.buffer_started_at_unix_ns = Some(event_at_unix_ns);
        }
        extend_unique(&mut self.partial_reasons, reasons.iter().cloned());
        let max_buffer = self
            .max_bytes
            .saturating_add(WEBSOCKET_MAX_FRAME_HEADER_BYTES);
        if self.buffer.len().saturating_add(data.len()) > max_buffer {
            self.reset_after_error("websocket_frame_limit");
            return Vec::new();
        }
        self.buffer.extend_from_slice(data);

        let mut messages = Vec::new();
        loop {
            let frame = match decode_websocket_frame(&self.buffer, self.max_bytes) {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(reason) => {
                    if self.allow_midstream_resync
                        && self.fragmented.is_none()
                        && self.try_resync_frame_header()
                    {
                        extend_unique(
                            &mut self.partial_reasons,
                            ["websocket_midstream_resync".to_string()],
                        );
                        continue;
                    }
                    self.reset_after_error(&reason);
                    break;
                }
            };
            let frame_started_at_unix_ns =
                self.buffer_started_at_unix_ns.unwrap_or(event_at_unix_ns);
            self.buffer.drain(..frame.consumed);
            self.buffer_started_at_unix_ns = (!self.buffer.is_empty()).then_some(event_at_unix_ns);
            let mut frame_reasons = std::mem::take(&mut self.partial_reasons);
            let expected_mask = self.kind == StreamKind::Request;
            if frame.masked != expected_mask {
                extend_unique(
                    &mut frame_reasons,
                    ["websocket_mask_direction_mismatch".to_string()],
                );
            }

            match frame.opcode {
                0x8..=0xA => {
                    if !frame.fin || frame.payload.len() > 125 {
                        self.reset_after_error("websocket_invalid_control_frame");
                        break;
                    }
                    continue;
                }
                0x1 | 0x2 => {
                    if self.fragmented.is_some() {
                        self.reset_after_error("websocket_nested_data_frame");
                        break;
                    }
                    if frame.fin {
                        if let Some(message) = self.finish_message(
                            frame.payload,
                            frame.compressed,
                            frame_started_at_unix_ns,
                            event_at_unix_ns,
                            frame_reasons,
                        ) {
                            messages.push(message);
                        }
                    } else {
                        self.fragmented = Some(FragmentedWebSocketMessage {
                            compressed: frame.compressed,
                            payload: frame.payload,
                            started_at_unix_ns: frame_started_at_unix_ns,
                            partial_reasons: frame_reasons,
                        });
                    }
                }
                0x0 => {
                    if frame.compressed {
                        self.reset_after_error("websocket_compressed_continuation");
                        break;
                    }
                    let Some(mut fragmented) = self.fragmented.take() else {
                        if self.allow_midstream_resync && self.try_resync_frame_header() {
                            extend_unique(
                                &mut self.partial_reasons,
                                ["websocket_midstream_resync".to_string()],
                            );
                            continue;
                        }
                        self.reset_after_error("websocket_orphan_continuation");
                        break;
                    };
                    if fragmented.payload.len().saturating_add(frame.payload.len()) > self.max_bytes
                    {
                        self.reset_after_error("websocket_message_limit");
                        break;
                    }
                    fragmented.payload.extend_from_slice(&frame.payload);
                    extend_unique(&mut fragmented.partial_reasons, frame_reasons);
                    if frame.fin {
                        if let Some(message) = self.finish_message(
                            fragmented.payload,
                            fragmented.compressed,
                            fragmented.started_at_unix_ns,
                            event_at_unix_ns,
                            fragmented.partial_reasons,
                        ) {
                            messages.push(message);
                        }
                    } else {
                        self.fragmented = Some(fragmented);
                    }
                }
                _ => {
                    self.reset_after_error("websocket_reserved_opcode");
                    break;
                }
            }
        }
        messages
    }

    fn finish_message(
        &mut self,
        payload: Vec<u8>,
        compressed: bool,
        started_at_unix_ns: u128,
        completed_at_unix_ns: u128,
        mut partial_reasons: Vec<String>,
    ) -> Option<DecodedWebSocketMessage> {
        let payload = if compressed {
            if !self.compression_enabled {
                self.last_decode_error = Some("websocket_unnegotiated_compression".to_string());
                return None;
            }
            match self.inflate_message(&payload) {
                Ok(payload) => payload,
                Err(reason) => {
                    self.last_decode_error = Some(reason.clone());
                    extend_unique(&mut partial_reasons, [reason]);
                    return None;
                }
            }
        } else {
            payload
        };
        self.last_decode_error = None;
        Some(DecodedWebSocketMessage {
            payload,
            started_at_unix_ns,
            completed_at_unix_ns,
            partial_reasons,
        })
    }

    fn inflate_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        if self.no_context_takeover {
            self.inflater.reset(false);
        }
        let mut input = Vec::with_capacity(payload.len().saturating_add(4));
        input.extend_from_slice(payload);
        input.extend_from_slice(WEBSOCKET_DEFLATE_TAIL);
        let initial_capacity = input
            .len()
            .saturating_mul(4)
            .clamp(4 * 1024, self.max_bytes);
        let mut output = Vec::with_capacity(initial_capacity);
        let mut cursor = 0usize;
        loop {
            if output.len() == output.capacity() {
                if output.len() >= self.max_bytes {
                    self.inflater.reset(false);
                    return Err("websocket_decompressed_limit".to_string());
                }
                let additional = output
                    .capacity()
                    .max(4 * 1024)
                    .min(self.max_bytes - output.len());
                output.reserve_exact(additional);
            }
            let before_in = self.inflater.total_in();
            let before_out = self.inflater.total_out();
            let status = self
                .inflater
                .decompress_vec(&input[cursor..], &mut output, FlushDecompress::Sync)
                .map_err(|_| "websocket_deflate_decode_failed".to_string())?;
            let consumed = (self.inflater.total_in() - before_in) as usize;
            let produced = (self.inflater.total_out() - before_out) as usize;
            cursor = cursor.saturating_add(consumed);
            if cursor == input.len() && status != Status::BufError {
                break;
            }
            if consumed == 0 && produced == 0 {
                if cursor == input.len() {
                    break;
                }
                self.inflater.reset(false);
                return Err("websocket_deflate_stalled".to_string());
            }
        }
        if self.no_context_takeover {
            self.inflater.reset(false);
        }
        Ok(output)
    }

    fn try_resync_frame_header(&mut self) -> bool {
        if self.buffer.len() < 2 {
            return false;
        }
        let expect_masked = self.kind == StreamKind::Request;
        // Skip the current misaligned leading byte and search for the next plausible data frame.
        for offset in 1..self.buffer.len().min(8 * 1024) {
            if !plausible_websocket_data_frame_at(&self.buffer[offset..], expect_masked) {
                continue;
            }
            self.buffer.drain(..offset);
            self.fragmented = None;
            self.last_decode_error = None;
            self.inflater.reset(false);
            return true;
        }
        false
    }

    fn reset_after_error(&mut self, reason: &str) {
        self.buffer.clear();
        self.buffer_started_at_unix_ns = None;
        self.partial_reasons.clear();
        self.fragmented = None;
        self.inflater.reset(false);
        self.last_decode_error = Some(reason.to_string());
    }
}

fn decode_websocket_frame(
    bytes: &[u8],
    max_payload_bytes: usize,
) -> Result<Option<DecodedWebSocketFrame>, String> {
    if bytes.len() < 2 {
        return Ok(None);
    }
    let first = bytes[0];
    let second = bytes[1];
    if first & 0x30 != 0 {
        return Err("websocket_reserved_bits".to_string());
    }
    let fin = first & 0x80 != 0;
    let compressed = first & 0x40 != 0;
    let opcode = first & 0x0f;
    let masked = second & 0x80 != 0;
    let mut cursor = 2usize;
    let mut payload_len = usize::from(second & 0x7f);
    if payload_len == 126 {
        let Some(length) = bytes.get(cursor..cursor + 2) else {
            return Ok(None);
        };
        payload_len = usize::from(u16::from_be_bytes([length[0], length[1]]));
        cursor += 2;
    } else if payload_len == 127 {
        let Some(length) = bytes.get(cursor..cursor + 8) else {
            return Ok(None);
        };
        if length[0] & 0x80 != 0 {
            return Err("websocket_invalid_64bit_length".to_string());
        }
        let length = u64::from_be_bytes(length.try_into().expect("eight bytes checked"));
        payload_len =
            usize::try_from(length).map_err(|_| "websocket_frame_length_overflow".to_string())?;
        cursor += 8;
    }
    if payload_len > max_payload_bytes {
        return Err("websocket_frame_limit".to_string());
    }
    let mask = if masked {
        let Some(mask) = bytes.get(cursor..cursor + 4) else {
            return Ok(None);
        };
        cursor += 4;
        Some([mask[0], mask[1], mask[2], mask[3]])
    } else {
        None
    };
    let consumed = cursor
        .checked_add(payload_len)
        .ok_or_else(|| "websocket_frame_length_overflow".to_string())?;
    let Some(raw_payload) = bytes.get(cursor..consumed) else {
        return Ok(None);
    };
    let mut payload = raw_payload.to_vec();
    if let Some(mask) = mask {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    Ok(Some(DecodedWebSocketFrame {
        consumed,
        fin,
        compressed,
        opcode,
        masked,
        payload,
    }))
}

#[derive(Debug)]
struct WebSocketResponseAccumulator {
    body: Vec<u8>,
    captured_body_bytes: usize,
    started_at_unix_ns: Option<u128>,
    partial_reasons: Vec<String>,
    tool_calls: Vec<LlmInteractionToolCall>,
    /// Payloads that passed the provider-neutral lifecycle gate; used only for the parser-derived
    /// SSE view. `body` remains the exact concatenation of every bounded observed payload.
    semantic_payloads: Vec<Vec<u8>>,
}

impl WebSocketResponseAccumulator {
    fn new() -> Self {
        Self {
            body: Vec::new(),
            captured_body_bytes: 0,
            started_at_unix_ns: None,
            partial_reasons: Vec::new(),
            tool_calls: Vec::new(),
            semantic_payloads: Vec::new(),
        }
    }

    fn clear(&mut self) {
        self.body.clear();
        self.captured_body_bytes = 0;
        self.started_at_unix_ns = None;
        self.partial_reasons.clear();
        self.tool_calls.clear();
        self.semantic_payloads.clear();
    }
}

#[derive(Debug)]
struct WebSocketConnectionState {
    upgrade_requested: bool,
    active: bool,
    recovered_without_handshake: bool,
    endpoint: String,
    path: String,
    requests: WebSocketFrameDecoder,
    responses: WebSocketFrameDecoder,
    response: WebSocketResponseAccumulator,
}

impl WebSocketConnectionState {
    fn new(max_bytes: usize) -> Self {
        Self {
            upgrade_requested: false,
            active: false,
            recovered_without_handshake: false,
            endpoint: "unknown".to_string(),
            path: "/v1/responses".to_string(),
            requests: WebSocketFrameDecoder::new(StreamKind::Request, max_bytes),
            responses: WebSocketFrameDecoder::new(StreamKind::Response, max_bytes),
            response: WebSocketResponseAccumulator::new(),
        }
    }

    fn activate(&mut self, extension: Option<&str>) {
        let extension = extension.unwrap_or_default().to_ascii_lowercase();
        let compression_enabled = extension
            .split(',')
            .any(|entry| entry.trim_start().starts_with("permessage-deflate"));
        self.requests.configure_compression(
            compression_enabled,
            extension.contains("client_no_context_takeover"),
        );
        self.responses.configure_compression(
            compression_enabled,
            extension.contains("server_no_context_takeover"),
        );
        self.active = true;
        self.recovered_without_handshake = false;
    }

    fn recover_from_frame(&mut self, data: &[u8]) {
        let compressed = data.first().is_some_and(|byte| byte & 0x40 != 0);
        // Mid-flight attach never saw the 101 extension list. Prefer no_context_takeover so each
        // RSV1 message is self-contained; shared sliding-window state from before attach is gone.
        self.requests.configure_compression(compressed, true);
        self.responses.configure_compression(compressed, true);
        self.requests.allow_midstream_resync = true;
        self.responses.allow_midstream_resync = true;
        self.active = true;
        self.recovered_without_handshake = true;
    }

    fn prepare_recovered_frame(&mut self, data: &[u8]) {
        if !self.recovered_without_handshake || data.first().is_none_or(|byte| byte & 0x40 == 0) {
            return;
        }
        self.requests.compression_enabled = true;
        self.responses.compression_enabled = true;
    }

    fn decoder(&self, direction: ChunkDirection) -> &WebSocketFrameDecoder {
        match direction {
            ChunkDirection::Request => &self.requests,
            ChunkDirection::Response => &self.responses,
        }
    }

    fn awaits_moved_fragment(&self, chunk: &PlaintextChunk) -> bool {
        if !self.active {
            return false;
        }
        let decoder = self.decoder(chunk.direction);
        if looks_like_websocket_continuation_prefix(&chunk.data) {
            return decoder.awaits_continuation_frame();
        }
        !looks_like_websocket_frame_prefix(&chunk.data) && decoder.awaits_more_frame_bytes()
    }
}


#[derive(Debug, Default)]
struct Http2StreamState {
    headers: Http2HeaderBlock,
    headers_complete: bool,
    body: Vec<u8>,
    body_started_at_unix_ns: Option<u128>,
    end_stream: bool,
}

#[derive(Debug)]
struct Http2ConnectionState {
    active: bool,
    leftover: Vec<u8>,
    request_hpack: HpackDecoder,
    response_hpack: HpackDecoder,
    streams: HashMap<u32, Http2StreamState>,
}

impl Default for Http2ConnectionState {
    fn default() -> Self {
        Self {
            active: false,
            leftover: Vec::new(),
            request_hpack: HpackDecoder::default(),
            response_hpack: HpackDecoder::default(),
            streams: HashMap::new(),
        }
    }
}

#[derive(Debug)]
struct ConnectionState {
    requests: HttpStreamDecoder,
    responses: HttpStreamDecoder,
    pending_requests: VecDeque<HttpMessage>,
    pending_request_bytes: usize,
    sequence: u64,
    fragment_sequences: HashMap<(u64, ChunkDirection), u64>,
    source: String,
    adapter_id: String,
    evidence_fingerprints: HashSet<String>,
    websocket: WebSocketConnectionState,
    http2: Http2ConnectionState,
    identity: StreamIdentityEvidence,
    rustls_request_body: RustlsBodyOnlyState,
    rustls_response_body: RustlsBodyOnlyState,
    /// Set when a moved pointer could not be uniquely attributed.  Any interaction assembled
    /// from this provisional state remains explicitly partial, even if its wire framing is valid.
    binding_uncertain: bool,
    binding_reasons: Vec<String>,
    pending_request_limit_hit: bool,
    /// Best tls_ctx↔socket bind observed on this stream (max bind_quality wins).
    bind_quality: u8,
    socket_fd: i32,
    socket_cookie: u64,
    fd_generation: u32,
    last_activity: Instant,
}

impl ConnectionState {
    fn new(max_body_bytes: usize, source: String, adapter_id: String) -> Self {
        let now = Instant::now();
        Self {
            requests: HttpStreamDecoder::new(StreamKind::Request, max_body_bytes),
            responses: HttpStreamDecoder::new(StreamKind::Response, max_body_bytes),
            pending_requests: VecDeque::new(),
            pending_request_bytes: 0,
            sequence: 0,
            fragment_sequences: HashMap::new(),
            source,
            adapter_id,
            evidence_fingerprints: HashSet::new(),
            websocket: WebSocketConnectionState::new(max_body_bytes),
            http2: Http2ConnectionState::default(),
            identity: StreamIdentityEvidence::default(),
            rustls_request_body: RustlsBodyOnlyState::default(),
            rustls_response_body: RustlsBodyOnlyState::default(),
            binding_uncertain: false,
            binding_reasons: Vec::new(),
            pending_request_limit_hit: false,
            bind_quality: 0,
            socket_fd: 0,
            socket_cookie: 0,
            fd_generation: 0,
            last_activity: now,
        }
    }

    fn idle(&self, now: Instant, timeout: Duration) -> bool {
        now.saturating_duration_since(self.last_activity) >= timeout
    }

    fn quiescent_websocket(&self) -> bool {
        self.websocket.active
            && self.pending_requests.is_empty()
            && self.requests.buffer.is_empty()
            && self.responses.buffer.is_empty()
            && self.websocket.requests.buffer.is_empty()
            && self.websocket.responses.buffer.is_empty()
            && self.websocket.response.body.is_empty()
            && self.rustls_request_body.buffer.is_empty()
            && self.rustls_response_body.buffer.is_empty()
    }

    fn push_pending_request(&mut self, request: HttpMessage) -> bool {
        let bytes = request.body.len();
        if self.pending_requests.len() >= MAX_PENDING_REQUESTS
            || self.pending_request_bytes.saturating_add(bytes) > MAX_PENDING_REQUEST_BYTES
        {
            return false;
        }
        self.pending_request_bytes = self.pending_request_bytes.saturating_add(bytes);
        self.pending_requests.push_back(request);
        true
    }

    fn pop_pending_request(&mut self) -> Option<HttpMessage> {
        let request = self.pending_requests.pop_front()?;
        self.pending_request_bytes = self
            .pending_request_bytes
            .saturating_sub(request.body.len());
        Some(request)
    }
}

/// Single-writer, bounded reassembler. The Collector owns one instance and feeds reordered
/// plaintext fragments into it, so no lock is needed on the protocol path.
#[derive(Debug)]
pub struct InteractionReassembler {
    connections: HashMap<ConnectionKey, ConnectionState>,
    connection_aliases: HashMap<ConnectionKey, ConnectionKey>,
    pending_evidence: VecDeque<CompletedPlaintextEvidence>,
    max_connections: usize,
    max_body_bytes: usize,
    idle_timeout: Duration,
    websocket_idle_timeout: Duration,
    metrics: ReassemblyMetrics,
    gap_evidence_fingerprints: HashSet<String>,
}

impl Default for InteractionReassembler {
    fn default() -> Self {
        Self::with_limits(
            DEFAULT_MAX_CONNECTIONS,
            DEFAULT_MAX_STREAM_BYTES,
            DEFAULT_IDLE_TIMEOUT,
        )
    }
}

impl InteractionReassembler {
    pub fn with_limits(
        max_connections: usize,
        max_body_bytes: usize,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            connections: HashMap::new(),
            connection_aliases: HashMap::new(),
            pending_evidence: VecDeque::new(),
            max_connections: max_connections.max(1),
            max_body_bytes: max_body_bytes.max(4 * 1024),
            idle_timeout,
            websocket_idle_timeout: DEFAULT_WEBSOCKET_IDLE_TIMEOUT.max(idle_timeout),
            metrics: ReassemblyMetrics::default(),
            gap_evidence_fingerprints: HashSet::new(),
        }
    }

    pub fn push(&mut self, mut chunk: PlaintextChunk) -> Vec<CompletedInteraction> {
        self.evict_if_needed();
        let observed_key = ConnectionKey::from(&chunk);
        let orphan_control_frame = is_websocket_control_frame(&chunk.data)
            && !self.connections.contains_key(&observed_key)
            && !self.connection_aliases.contains_key(&observed_key);
        // A moved Rustls pointer carrying only ping/pong/close bytes has no application identity.
        // Ignoring it is lossless for the Agent transcript and avoids creating a false standalone
        // state that could capture a later data frame if the allocator reuses that pointer.
        if orphan_control_frame {
            self.metrics.orphan_chunks = self.metrics.orphan_chunks.saturating_add(1);
            self.enqueue_gap_evidence(observed_key, &chunk, "orphan_control_frame", "websocket");
            return Vec::new();
        }
        let (key, binding_gap) = self.resolve_connection_key(&chunk);
        if let Some(reason) = binding_gap.as_ref() {
            if *reason == "ambiguous_stream_binding" {
                self.metrics.ambiguous_stream_bindings =
                    self.metrics.ambiguous_stream_bindings.saturating_add(1);
            }
            self.metrics.stream_binding_gaps = self.metrics.stream_binding_gaps.saturating_add(1);
            extend_unique(&mut chunk.partial_reasons, [(*reason).to_string()]);
            self.enqueue_gap_evidence(key, &chunk, reason, "stream");
            if *reason == "orphan_stream_binding" {
                return Vec::new();
            }
        }
        // A decoder error from a previous fragment means the stream can no longer prove a complete
        // exchange. Emit one bounded metadata-only evidence record before attempting recovery;
        // the next valid KernelFact is still processed normally.
        let prior_decode_gap = self.connections.get(&key).and_then(|state| {
            state
                .requests
                .last_decode_error
                .clone()
                .or_else(|| state.responses.last_decode_error.clone())
                .or_else(|| state.websocket.requests.last_decode_error.clone())
                .or_else(|| state.websocket.responses.last_decode_error.clone())
        });
        if let Some(reason) = prior_decode_gap {
            self.enqueue_gap_evidence(key, &chunk, &reason, "http/1.1");
        }
        for reason in chunk.partial_reasons.clone() {
            if reason.contains("gap") || reason.contains("limit") || reason.contains("truncat") {
                self.enqueue_gap_evidence(key, &chunk, &reason, "unknown");
            }
        }
        let mut sequence_gap_detected = false;
        let state = self.connections.entry(key).or_insert_with(|| {
            ConnectionState::new(
                self.max_body_bytes,
                chunk.source.clone(),
                chunk.adapter_id.clone(),
            )
        });
        let now = Instant::now();
        state.last_activity = now;
        observe_socket_bind(state, &chunk);
        merge_bounded_label(&mut state.source, &chunk.source);
        merge_bounded_label(&mut state.adapter_id, &chunk.adapter_id);
        // Rustls connection objects can be reused after a socket closes. A retained WebSocket
        // state must yield to an unmistakable fresh HTTP request on the same pointer.
        if state.websocket.active
            && chunk.direction == ChunkDirection::Request
            && looks_like_http_request_prefix(&chunk.data)
        {
            *state = ConnectionState::new(
                self.max_body_bytes,
                chunk.source.clone(),
                chunk.adapter_id.clone(),
            );
            state.last_activity = Instant::now();
            observe_socket_bind(state, &chunk);
        }
        if binding_gap.is_some() {
            state.binding_uncertain = true;
            extend_unique(
                &mut state.binding_reasons,
                ["ambiguous_stream_binding".to_string()],
            );
        }
        // Collector restarts and long historical idle windows can occur while the Agent keeps a
        // Responses WebSocket alive. Recover from the first strongly framed client/server data
        // message instead of requiring the already-past HTTP 101 handshake.
        if !state.websocket.active
            && recoverable_websocket_frame_prefix(&chunk.data, chunk.direction)
        {
            state.websocket.recover_from_frame(&chunk.data);
            extend_unique(
                &mut chunk.partial_reasons,
                ["websocket_handshake_recovered".to_string()],
            );
        }
        if let Some(evidence) = plaintext_transport_evidence(key, state, &chunk) {
            if self.pending_evidence.len() >= self.max_connections {
                self.pending_evidence.pop_front();
                self.metrics.evidence_evictions = self.metrics.evidence_evictions.saturating_add(1);
            }
            self.pending_evidence.push_back(evidence);
        }

        let sequence_key = (observed_key.connection_id, chunk.direction);
        if state.fragment_sequences.len() >= 64
            && !state.fragment_sequences.contains_key(&sequence_key)
        {
            if let Some(oldest) = state.fragment_sequences.keys().next().copied() {
                state.fragment_sequences.remove(&oldest);
                self.metrics.fragment_tracker_evictions =
                    self.metrics.fragment_tracker_evictions.saturating_add(1);
            }
            extend_unique(
                &mut chunk.partial_reasons,
                ["fragment_sequence_tracker_reset".to_string()],
            );
        }
        let previous_sequence = state.fragment_sequences.entry(sequence_key).or_insert(0);
        if *previous_sequence != 0 && chunk.sequence != previous_sequence.wrapping_add(1) {
            self.metrics.sequence_gaps = self.metrics.sequence_gaps.saturating_add(1);
            sequence_gap_detected = true;
            extend_unique(
                &mut chunk.partial_reasons,
                ["fragment_sequence_gap".to_string()],
            );
        }
        *previous_sequence = chunk.sequence;
        if chunk
            .partial_reasons
            .iter()
            .any(|reason| reason.contains("limit") || reason.contains("truncat"))
        {
            self.metrics.body_limit_drops = self.metrics.body_limit_drops.saturating_add(1);
            if chunk
                .partial_reasons
                .iter()
                .any(|reason| reason.contains("truncat"))
            {
                self.metrics.truncated_chunks = self.metrics.truncated_chunks.saturating_add(1);
            }
        }

        let mut deferred_body_gap_reasons = Vec::new();
        let completed = if state.http2.active
            || chunk.data.starts_with(b"PRI * HTTP/2.0")
            || looks_like_http2_frame_prefix(&chunk.data)
        {
            let (done, gaps) = process_http2_chunk(key, state, &chunk, self.max_body_bytes);
            deferred_body_gap_reasons.extend(gaps);
            done
        } else if state.websocket.active {
            process_websocket_chunk(key, state, &chunk, self.max_body_bytes)
        } else {
            match chunk.direction {
                ChunkDirection::Request => {
                    let mut effective_reasons = chunk.partial_reasons.clone();
                    extend_unique(&mut effective_reasons, state.binding_reasons.clone());
                    let body_only_candidate = rustls_like_chunk(&chunk)
                        && !looks_like_http_request_prefix(&chunk.data)
                        // Never bypass an HTTP decoder that already owns headers/body bytes. A
                        // Rustls callback can split the body after a perfectly valid request
                        // line; feeding that fragment into a second synthetic decoder would
                        // duplicate or mis-pair the exchange.
                        && state.requests.buffer.is_empty()
                        && (!state.rustls_request_body.buffer.is_empty()
                            || maybe_body_only_json_prefix(&chunk.data));
                    let body_feed = if body_only_candidate {
                        let body_state = &mut state.rustls_request_body;
                        feed_rustls_body_only(
                            body_state,
                            ChunkDirection::Request,
                            &chunk.data,
                            chunk.event_at_unix_ns,
                            &effective_reasons,
                            self.max_body_bytes,
                        )
                    } else {
                        BodyOnlyFeed {
                            result: BodyOnlyFeedResult::NotCandidate,
                            messages: Vec::new(),
                            reasons: Vec::new(),
                        }
                    };
                    for reason in &body_feed.reasons {
                        extend_unique(&mut chunk.partial_reasons, [reason.clone()]);
                        deferred_body_gap_reasons.push(reason.clone());
                    }
                    if body_feed.result == BodyOnlyFeedResult::Invalid {
                        self.metrics.parser_failures =
                            self.metrics.parser_failures.saturating_add(1);
                    }
                    if body_feed.result != BodyOnlyFeedResult::NotCandidate {
                        for mut request in body_feed.messages {
                            extend_unique(&mut request.partial_reasons, body_feed.reasons.clone());
                            state
                                .identity
                                .observe_http(&request, ChunkDirection::Request);
                            add_binding_reasons(state, &mut request.partial_reasons);
                            if !state.push_pending_request(request) {
                                self.metrics.body_limit_drops =
                                    self.metrics.body_limit_drops.saturating_add(1);
                                extend_unique(
                                    &mut deferred_body_gap_reasons,
                                    ["pending_request_limit".to_string()],
                                );
                            }
                        }
                    } else if !body_only_candidate {
                        for mut request in state.requests.push(
                            &chunk.data,
                            chunk.event_at_unix_ns,
                            &effective_reasons,
                        ) {
                            if let Some((endpoint, path)) = websocket_upgrade_metadata(&request) {
                                state.websocket.upgrade_requested = true;
                                state.websocket.endpoint = endpoint.clone();
                                state.websocket.path = path.clone();
                                state.identity.observe_route(&endpoint, &path);
                            } else {
                                state
                                    .identity
                                    .observe_http(&request, ChunkDirection::Request);
                                add_binding_reasons(state, &mut request.partial_reasons);
                                if !state.push_pending_request(request) {
                                    self.metrics.body_limit_drops =
                                        self.metrics.body_limit_drops.saturating_add(1);
                                    extend_unique(
                                        &mut deferred_body_gap_reasons,
                                        ["pending_request_limit".to_string()],
                                    );
                                }
                            }
                        }
                    } else {
                        // A candidate prefix which is not an LLM body is retained as bounded
                        // plaintext/gap evidence, never handed to the normal HTTP decoder.
                        extend_unique(
                            &mut deferred_body_gap_reasons,
                            ["rustls_body_only_not_candidate".to_string()],
                        );
                    }
                    Vec::new()
                }
                ChunkDirection::Response => {
                    let mut completed = Vec::new();
                    let mut effective_reasons = chunk.partial_reasons.clone();
                    extend_unique(&mut effective_reasons, state.binding_reasons.clone());
                    let body_only_candidate = rustls_like_chunk(&chunk)
                        && !chunk.data.starts_with(b"HTTP/")
                        // The synthetic response lane is valid only for a request that has
                        // already been reconstructed and while the regular HTTP decoder is
                        // empty. This prevents orphan/config JSON and split HTTP bodies from
                        // poisoning the next model exchange.
                        && !state.pending_requests.is_empty()
                        && state.responses.buffer.is_empty()
                        && (!state.rustls_response_body.buffer.is_empty()
                            || maybe_body_only_response_prefix(&chunk.data));
                    let orphan_body_only_response = rustls_like_chunk(&chunk)
                        && !chunk.data.starts_with(b"HTTP/")
                        && state.responses.buffer.is_empty()
                        && state.pending_requests.is_empty();
                    let body_feed = if body_only_candidate {
                        let body_state = &mut state.rustls_response_body;
                        feed_rustls_body_only_response(
                            body_state,
                            &chunk.data,
                            chunk.event_at_unix_ns,
                            &effective_reasons,
                            self.max_body_bytes,
                        )
                    } else {
                        BodyOnlyFeed {
                            result: BodyOnlyFeedResult::NotCandidate,
                            messages: Vec::new(),
                            reasons: Vec::new(),
                        }
                    };
                    for reason in &body_feed.reasons {
                        extend_unique(&mut chunk.partial_reasons, [reason.clone()]);
                        deferred_body_gap_reasons.push(reason.clone());
                    }
                    if body_feed.result == BodyOnlyFeedResult::Invalid {
                        self.metrics.parser_failures =
                            self.metrics.parser_failures.saturating_add(1);
                    }
                    if body_feed.result != BodyOnlyFeedResult::NotCandidate {
                        for mut response in body_feed.messages {
                            extend_unique(&mut response.partial_reasons, body_feed.reasons.clone());
                            state
                                .identity
                                .observe_http(&response, ChunkDirection::Response);
                            add_binding_reasons(state, &mut response.partial_reasons);
                            let Some(mut request) = state.pop_pending_request() else {
                                self.metrics.orphan_chunks =
                                    self.metrics.orphan_chunks.saturating_add(1);
                                continue;
                            };
                            add_binding_reasons(state, &mut request.partial_reasons);
                            state.sequence = state.sequence.wrapping_add(1);
                            if let Some(interaction) = build_interaction(
                                key,
                                state.sequence,
                                &state.source,
                                &state.adapter_id,
                                request,
                                response,
                                state.bind_quality,
                                state.socket_fd,
                                state.socket_cookie,
                                state.fd_generation,
                            ) {
                                completed.push(interaction);
                            }
                        }
                    } else if !body_only_candidate && !orphan_body_only_response {
                        for mut response in state.responses.push(
                            &chunk.data,
                            chunk.event_at_unix_ns,
                            &effective_reasons,
                        ) {
                            state
                                .identity
                                .observe_http(&response, ChunkDirection::Response);
                            if state.websocket.upgrade_requested
                                && response_status(&response.start_line) == Some(101)
                            {
                                let extension = response
                                    .header("sec-websocket-extensions")
                                    .map(str::to_owned);
                                state.websocket.activate(extension.as_deref());
                                let tail = state.responses.take_unparsed_tail();
                                if !tail.is_empty() {
                                    let messages = state.websocket.responses.push(
                                        &tail,
                                        chunk.event_at_unix_ns,
                                        &effective_reasons,
                                    );
                                    completed.extend(process_websocket_response_messages(
                                        key,
                                        state,
                                        messages,
                                        self.max_body_bytes,
                                    ));
                                }
                                continue;
                            }
                            // Informational responses do not consume the request they precede.
                            if response_status(&response.start_line)
                                .is_some_and(|status| (100..200).contains(&status))
                            {
                                continue;
                            }
                            add_binding_reasons(state, &mut response.partial_reasons);
                            let Some(mut request) = state.pop_pending_request() else {
                                self.metrics.orphan_chunks =
                                    self.metrics.orphan_chunks.saturating_add(1);
                                continue;
                            };
                            add_binding_reasons(state, &mut request.partial_reasons);
                            state.sequence = state.sequence.wrapping_add(1);
                            if let Some(interaction) = build_interaction(
                                key,
                                state.sequence,
                                &state.source,
                                &state.adapter_id,
                                request,
                                response,
                                state.bind_quality,
                                state.socket_fd,
                                state.socket_cookie,
                                state.fd_generation,
                            ) {
                                completed.push(interaction);
                            }
                        }
                    } else if orphan_body_only_response {
                        extend_unique(
                            &mut deferred_body_gap_reasons,
                            ["orphan_rustls_body_only_response".to_string()],
                        );
                    } else {
                        // Candidate bytes were handled by the bounded body-only lane. If that
                        // lane rejected their shape, keep the gap but do not feed arbitrary JSON
                        // into the HTTP decoder.
                        if body_feed.result == BodyOnlyFeedResult::NotCandidate {
                            extend_unique(
                                &mut deferred_body_gap_reasons,
                                ["rustls_body_only_not_candidate".to_string()],
                            );
                        }
                    }
                    completed
                }
            }
        };
        let pending_request_limit_hit = state.pending_request_limit_hit;
        state.pending_request_limit_hit = false;
        if pending_request_limit_hit {
            self.metrics.body_limit_drops = self.metrics.body_limit_drops.saturating_add(1);
            extend_unique(
                &mut deferred_body_gap_reasons,
                ["pending_request_limit".to_string()],
            );
        }
        if state.requests.last_decode_error.is_some()
            || state.responses.last_decode_error.is_some()
            || state.websocket.requests.last_decode_error.is_some()
            || state.websocket.responses.last_decode_error.is_some()
        {
            self.metrics.parser_failures = self.metrics.parser_failures.saturating_add(1);
        }
        let current_decode_gap = state
            .requests
            .last_decode_error
            .clone()
            .or_else(|| state.responses.last_decode_error.clone())
            .or_else(|| state.websocket.requests.last_decode_error.clone())
            .or_else(|| state.websocket.responses.last_decode_error.clone());
        if interaction_diagnostics_enabled_for(chunk.pid) && rustls_like_chunk(&chunk) {
            // A streaming response can produce hundreds of TLS fragments in a few
            // milliseconds. Keep per-fragment state available for targeted debugging,
            // but never put it on the default operational INFO path: a slow container
            // log sink must not be able to back-pressure or terminate the collector.
            tracing::debug!(
                pid = chunk.pid,
                observed_connection_id = format_args!("{:x}", chunk.connection_id),
                canonical_connection_id = format_args!("{:x}", key.connection_id),
                direction = ?chunk.direction,
                fragment_kind = plaintext_fragment_kind(&chunk.data),
                fragment_bytes = chunk.data.len(),
                request_buffer_bytes = state.requests.buffer.len(),
                response_buffer_bytes = state.responses.buffer.len(),
                websocket_active = state.websocket.active,
                websocket_request_buffer_bytes = state.websocket.requests.buffer.len(),
                websocket_response_buffer_bytes = state.websocket.responses.buffer.len(),
                pending_requests = state.pending_requests.len(),
                request_decode_error = ?state.requests.last_decode_error,
                response_decode_error = ?state.responses.last_decode_error,
                websocket_request_decode_error = ?state.websocket.requests.last_decode_error,
                websocket_response_decode_error = ?state.websocket.responses.last_decode_error,
                completed_interactions = completed.len(),
                "Agent interaction reassembly state"
            );
        }
        if let Some(reason) = current_decode_gap {
            self.enqueue_gap_evidence(key, &chunk, &reason, "http/1.1");
        }
        for reason in deferred_body_gap_reasons {
            let transport = if reason == "h2_hpack_desync"
                || reason.starts_with("http2_")
                || reason.starts_with("h2_")
            {
                "http/2"
            } else {
                "json-body"
            };
            self.enqueue_gap_evidence(key, &chunk, &reason, transport);
        }
        if sequence_gap_detected {
            self.enqueue_gap_evidence(key, &chunk, "fragment_sequence_gap", "unknown");
        }
        completed
    }

    /// Resolve an implementation-family pointer to a canonical stream only when the observed
    /// bytes leave one defensible owner.  In particular, this method never ranks candidates by
    /// wall-clock recency: a Rustls allocator can move pointers while several WebSocket/HTTP
    /// streams are live, and choosing the newest stream would silently cross-wire conversations.
    fn resolve_connection_key(
        &mut self,
        chunk: &PlaintextChunk,
    ) -> (ConnectionKey, Option<&'static str>) {
        let observed = ConnectionKey::from(chunk);
        if let Some(canonical) = self.connection_aliases.get(&observed).copied() {
            return (canonical, None);
        }
        // Prefer kernel tls_ctx↔socket bind when present. Bound streams use a stable socket-
        // derived connection_id already filled by eBPF; still alias any provisional TLS-pointer
        // key that may have been observed before the first bind completed.
        //
        // Even after FD bind, rustls can still surface distinct CommonState pointers for the
        // same pid (request vs response). If this observed key cannot progress an exchange but a
        // unique sibling already owns a pending Responses turn, re-home instead of splitting.
        if chunk.bind_quality >= TLS_BIND_QUALITY_FD {
            if let Some(owner) = self.preferred_websocket_exchange_owner(observed, chunk) {
                if owner != observed {
                    self.remember_connection_alias(observed, owner);
                    return (owner, None);
                }
            }
            return (observed, None);
        }
        let observed_binding_uncertain = self
            .connections
            .get(&observed)
            .is_some_and(|state| state.binding_uncertain);
        if self.connections.contains_key(&observed) && !observed_binding_uncertain {
            if let Some(owner) = self.preferred_websocket_exchange_owner(observed, chunk) {
                if owner != observed {
                    self.remember_connection_alias(observed, owner);
                    return (owner, None);
                }
            }
            return (observed, None);
        }

        if !rustls_like_chunk(chunk) {
            return (observed, None);
        }
        let resolution = self.resolve_rustls_stream(observed, chunk);
        match resolution {
            ConnectionResolution::Resolved(canonical) => {
                if canonical == observed {
                    return (canonical, None);
                }
                if observed_binding_uncertain {
                    if self.rebind_quiescent_connection(observed, canonical) {
                        self.remember_connection_alias(observed, canonical);
                        return (canonical, None);
                    }
                    // A unique hint is not enough when the target is already active: the
                    // provisional state still owns bytes that cannot be merged safely. Keep it
                    // provisional and surface the ambiguity rather than routing to the target.
                    return (observed, Some("ambiguous_stream_binding"));
                }
                self.remember_connection_alias(observed, canonical);
                (canonical, None)
            }
            ConnectionResolution::Ambiguous(_) => {
                // Keep the bytes in their observed provisional state.  The caller adds an
                // explicit partial/gap reason; no alias is created, so a later stronger pointer
                // or protocol identity cannot inherit a wrong owner.
                // Still collapse onto a unique pending Responses sibling when that is the only
                // defensible owner for response bytes on this pid.
                if let Some(owner) = self.preferred_websocket_exchange_owner(observed, chunk) {
                    if owner != observed {
                        self.remember_connection_alias(observed, owner);
                        return (owner, None);
                    }
                }
                (observed, Some("ambiguous_stream_binding"))
            }
            ConnectionResolution::Orphan => {
                // A continuation frame has no self-describing owner. Prefer a unique pending
                // sibling over dropping the bytes as orphan evidence.
                if let Some(owner) = self.preferred_websocket_exchange_owner(observed, chunk) {
                    if owner != observed {
                        self.remember_connection_alias(observed, owner);
                        return (owner, None);
                    }
                }
                // Retain bounded raw evidence, but do not create a new protocol state that could
                // steal a later stream after allocator reuse.
                (observed, Some("orphan_stream_binding"))
            }
            ConnectionResolution::New => {
                if let Some(owner) = self.preferred_websocket_exchange_owner(observed, chunk) {
                    if owner != observed {
                        self.remember_connection_alias(observed, owner);
                        return (owner, None);
                    }
                }
                (observed, None)
            }
        }
    }

    /// Prefer the unique active WebSocket on this pid that already owns a pending / in-flight
    /// Responses exchange when the observed pointer is idle or unknown.
    fn preferred_websocket_exchange_owner(
        &self,
        observed: ConnectionKey,
        chunk: &PlaintextChunk,
    ) -> Option<ConnectionKey> {
        if let Some(state) = self.connections.get(&observed) {
            let observed_busy = !state.pending_requests.is_empty()
                || state.websocket.response.started_at_unix_ns.is_some()
                || state.websocket.awaits_moved_fragment(chunk);
            if observed_busy {
                return Some(observed);
            }
            // Non-WS observed keys keep their own home for requests; responses may still join a
            // unique pending sibling below.
            if !state.websocket.active && chunk.direction != ChunkDirection::Response {
                return Some(observed);
            }
        }
        let mut owners = self
            .connections
            .iter()
            .filter_map(|(key, sibling)| {
                (*key != observed
                    && key.cgroup_id == observed.cgroup_id
                    && key.pid == observed.pid
                    && sibling.websocket.active
                    && (!sibling.pending_requests.is_empty()
                        || sibling.websocket.response.started_at_unix_ns.is_some()
                        || sibling.websocket.awaits_moved_fragment(chunk)))
                .then_some(*key)
            })
            .collect::<Vec<_>>();
        if owners.len() == 1 {
            return owners.pop();
        }
        None
    }

    fn resolve_rustls_stream(
        &self,
        observed: ConnectionKey,
        chunk: &PlaintextChunk,
    ) -> ConnectionResolution {
        let probe = chunk_identity_probe(chunk, self.max_body_bytes);

        // HTTP 101 is the strongest available bridge when a Collector starts observing after a
        // Rustls object has moved.  If two upgrades are pending, refusing to choose is safer than
        // assigning a resumed stream to whichever handshake happened last.
        if chunk.direction == ChunkDirection::Response
            && looks_like_websocket_switching_protocols(&chunk.data)
        {
            let mut candidates = self
                .connections
                .iter()
                .filter_map(|(key, state)| {
                    (key.cgroup_id == observed.cgroup_id
                        && key.pid == observed.pid
                        && state.websocket.upgrade_requested
                        && !state.websocket.active)
                        .then_some(*key)
                })
                .collect::<Vec<_>>();
            narrow_connection_candidates(&mut candidates, probe.as_ref(), &self.connections);
            return choose_connection_candidate(candidates);
        }

        // A Rustls `OutboundChunks`/`Payload` pointer can change in the middle of one frame.  The
        // continuation bytes often begin with an arbitrary JSON/deflate byte and therefore do not
        // carry a self-describing WebSocket header.  A decoder that already owns an incomplete
        // frame is the only safe owner signal; if more than one decoder is waiting, leave the
        // pointer provisional instead of selecting by recency.  Fresh HTTP request lines are
        // checked first so a reused pointer can start a new connection generation cleanly.
        if !looks_like_http_request_prefix(&chunk.data) {
            let moved_fragment_candidates = self
                .connections
                .iter()
                .filter_map(|(key, state)| {
                    (key.cgroup_id == observed.cgroup_id
                        && key.pid == observed.pid
                        && state.websocket.awaits_moved_fragment(chunk))
                    .then_some(*key)
                })
                .collect::<Vec<_>>();
            if !moved_fragment_candidates.is_empty() {
                return choose_connection_candidate(moved_fragment_candidates);
            }
        }

        let is_continuation = looks_like_websocket_continuation_prefix(&chunk.data);
        let is_websocket_frame = looks_like_websocket_frame_prefix(&chunk.data);
        if is_continuation || is_websocket_frame {
            let mut candidates = self
                .connections
                .iter()
                .filter_map(|(key, state)| {
                    if key.cgroup_id != observed.cgroup_id
                        || key.pid != observed.pid
                        || !state.websocket.active
                    {
                        return None;
                    }
                    if is_continuation {
                        if state.websocket.awaits_moved_fragment(chunk) {
                            return Some(*key);
                        }
                        // Mid-flight / pointer-split: continuations often cannot prove decoder
                        // ownership, but a sibling with a pending Responses turn is still the
                        // only safe home for server bytes on this pid.
                        return (!state.pending_requests.is_empty()
                            || state.websocket.response.started_at_unix_ns.is_some())
                        .then_some(*key);
                    }
                    if chunk.direction == ChunkDirection::Response
                        && state.pending_requests.is_empty()
                        && state.websocket.response.started_at_unix_ns.is_none()
                        && !state.websocket.recovered_without_handshake
                    {
                        return None;
                    }
                    Some(*key)
                })
                .collect::<Vec<_>>();
            narrow_connection_candidates(&mut candidates, probe.as_ref(), &self.connections);
            if is_continuation && candidates.is_empty() {
                // Prefer an open Responses exchange on this pid over dropping the bytes.
                let mut pending_owners = self
                    .connections
                    .iter()
                    .filter_map(|(key, state)| {
                        (key.cgroup_id == observed.cgroup_id
                            && key.pid == observed.pid
                            && state.websocket.active
                            && (!state.pending_requests.is_empty()
                                || state.websocket.response.started_at_unix_ns.is_some()))
                        .then_some(*key)
                    })
                    .collect::<Vec<_>>();
                narrow_connection_candidates(
                    &mut pending_owners,
                    probe.as_ref(),
                    &self.connections,
                );
                if !pending_owners.is_empty() {
                    return choose_connection_candidate(pending_owners);
                }
                return ConnectionResolution::Orphan;
            }
            return choose_connection_candidate(candidates);
        }

        // Rustls CommonState may expose a body without an HTTP request line.  Treat non-WebSocket
        // states with a pending request or an incomplete decoder/body buffer as structural
        // candidates, then use explicit IDs/route evidence if available.  A single remaining
        // candidate is sufficient; multiple candidates remain ambiguous.
        let mut candidates = self
            .connections
            .iter()
            .filter_map(|(key, state)| {
                if key.cgroup_id != observed.cgroup_id
                    || key.pid != observed.pid
                    || state.websocket.active
                {
                    return None;
                }
                let decoder_has_state = match chunk.direction {
                    ChunkDirection::Request => !state.requests.buffer.is_empty(),
                    ChunkDirection::Response => !state.responses.buffer.is_empty(),
                };
                let body_has_state = match chunk.direction {
                    ChunkDirection::Request => !state.rustls_request_body.buffer.is_empty(),
                    ChunkDirection::Response => !state.rustls_response_body.buffer.is_empty(),
                };
                let response_lifecycle = chunk.direction == ChunkDirection::Response
                    && !state.pending_requests.is_empty();
                (decoder_has_state || body_has_state || response_lifecycle).then_some(*key)
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            candidates = self
                .connections
                .iter()
                .filter_map(|(key, state)| {
                    (key.cgroup_id == observed.cgroup_id
                        && key.pid == observed.pid
                        && !state.websocket.active)
                        .then_some(*key)
                })
                .collect();
        }
        narrow_connection_candidates(&mut candidates, probe.as_ref(), &self.connections);
        choose_connection_candidate(candidates)
    }

    fn remember_connection_alias(&mut self, observed: ConnectionKey, canonical: ConnectionKey) {
        self.retain_live_connection_aliases();
        let alias_limit = self.max_connections.saturating_mul(4).max(4);
        if self.connection_aliases.len() >= alias_limit {
            if let Some(oldest) = self.connection_aliases.keys().next().copied() {
                self.connection_aliases.remove(&oldest);
                self.metrics.alias_evictions = self.metrics.alias_evictions.saturating_add(1);
            }
        }
        self.connection_aliases.insert(observed, canonical);
    }

    /// Move a provisional non-active stream onto a uniquely identified owner. Active competing
    /// WebSockets are intentionally not merged here: without a frame-level proof, retaining the
    /// provisional state and exposing `ambiguous_stream_binding` is safer than cross-wiring bytes.
    fn rebind_quiescent_connection(
        &mut self,
        observed: ConnectionKey,
        canonical: ConnectionKey,
    ) -> bool {
        let Some(mut provisional) = self.connections.remove(&observed) else {
            return false;
        };
        let Some(target) = self.connections.get_mut(&canonical) else {
            self.connections.insert(observed, provisional);
            return false;
        };
        if target.websocket.active
            || provisional.websocket.active
            || target.websocket.upgrade_requested
            || provisional.websocket.upgrade_requested
            || !target.websocket.requests.buffer.is_empty()
            || !provisional.websocket.requests.buffer.is_empty()
            || !target.websocket.responses.buffer.is_empty()
            || !provisional.websocket.responses.buffer.is_empty()
            || target.websocket.requests.fragmented.is_some()
            || provisional.websocket.requests.fragmented.is_some()
            || target.websocket.responses.fragmented.is_some()
            || provisional.websocket.responses.fragmented.is_some()
            || !target.websocket.response.body.is_empty()
            || !provisional.websocket.response.body.is_empty()
            || !target.websocket.response.semantic_payloads.is_empty()
            || !provisional.websocket.response.semantic_payloads.is_empty()
            || !target.pending_requests.is_empty()
            || (!target.requests.buffer.is_empty() && !provisional.requests.buffer.is_empty())
            || (!target.responses.buffer.is_empty() && !provisional.responses.buffer.is_empty())
            || (!target.rustls_request_body.buffer.is_empty()
                && !provisional.rustls_request_body.buffer.is_empty())
            || (!target.rustls_response_body.buffer.is_empty()
                && !provisional.rustls_response_body.buffer.is_empty())
        {
            self.connections.insert(observed, provisional);
            return false;
        }
        if target.requests.buffer.is_empty() {
            target.requests.buffer = std::mem::take(&mut provisional.requests.buffer);
            target.requests.buffer_started_at_unix_ns =
                provisional.requests.buffer_started_at_unix_ns;
        }
        if target.responses.buffer.is_empty() {
            target.responses.buffer = std::mem::take(&mut provisional.responses.buffer);
            target.responses.buffer_started_at_unix_ns =
                provisional.responses.buffer_started_at_unix_ns;
        }
        if target.rustls_request_body.buffer.is_empty() {
            target.rustls_request_body = std::mem::take(&mut provisional.rustls_request_body);
        }
        if target.rustls_response_body.buffer.is_empty() {
            target.rustls_response_body = std::mem::take(&mut provisional.rustls_response_body);
        }
        if target.pending_requests.is_empty() {
            target.pending_requests = std::mem::take(&mut provisional.pending_requests);
            target.pending_request_bytes = provisional.pending_request_bytes;
        }
        target.sequence = target.sequence.max(provisional.sequence);
        for (sequence_key, sequence) in provisional.fragment_sequences {
            match target.fragment_sequences.get(&sequence_key) {
                Some(existing) if *existing != sequence => {
                    extend_unique(
                        &mut target.binding_reasons,
                        ["fragment_sequence_conflict".to_string()],
                    );
                    target.binding_uncertain = true;
                }
                Some(_) => {}
                None if target.fragment_sequences.len() < 64 => {
                    target.fragment_sequences.insert(sequence_key, sequence);
                }
                None => {
                    extend_unique(
                        &mut target.binding_reasons,
                        ["fragment_sequence_tracker_reset".to_string()],
                    );
                    target.binding_uncertain = true;
                }
            }
        }
        merge_bounded_label(&mut target.source, &provisional.source);
        merge_bounded_label(&mut target.adapter_id, &provisional.adapter_id);
        for fingerprint in provisional.evidence_fingerprints {
            if target.evidence_fingerprints.len() < MAX_STREAM_IDENTITY_ANCHORS {
                target.evidence_fingerprints.insert(fingerprint);
            }
        }
        extend_unique(
            &mut target.requests.partial_reasons,
            provisional.requests.partial_reasons,
        );
        extend_unique(
            &mut target.responses.partial_reasons,
            provisional.responses.partial_reasons,
        );
        if target.requests.last_decode_error.is_none() {
            target.requests.last_decode_error = provisional.requests.last_decode_error;
        }
        if target.responses.last_decode_error.is_none() {
            target.responses.last_decode_error = provisional.responses.last_decode_error;
        }
        for value in provisional.identity.endpoints {
            bounded_insert(
                &mut target.identity.endpoints,
                value,
                MAX_STREAM_IDENTITY_ANCHORS,
            );
        }
        for value in provisional.identity.paths {
            bounded_insert(
                &mut target.identity.paths,
                value,
                MAX_STREAM_IDENTITY_ANCHORS,
            );
        }
        for value in provisional.identity.anchor_hashes {
            bounded_insert(
                &mut target.identity.anchor_hashes,
                value,
                MAX_STREAM_IDENTITY_ANCHORS,
            );
        }
        target.binding_uncertain |= provisional.binding_uncertain;
        extend_unique(&mut target.binding_reasons, provisional.binding_reasons);
        if provisional.bind_quality > target.bind_quality
            || (provisional.bind_quality == target.bind_quality
                && provisional.socket_cookie != 0
                && target.socket_cookie == 0)
        {
            target.bind_quality = provisional.bind_quality;
            target.socket_fd = provisional.socket_fd;
            target.socket_cookie = provisional.socket_cookie;
            target.fd_generation = provisional.fd_generation;
        }
        if provisional.last_activity > target.last_activity {
            target.last_activity = provisional.last_activity;
        }
        true
    }

    fn retain_live_connection_aliases(&mut self) {
        let connections = &self.connections;
        self.connection_aliases
            .retain(|_, canonical| connections.contains_key(canonical));
    }

    /// Remove idle state even when a request or response is incomplete. Retaining an orphaned
    /// request across a later keep-alive reuse can pair a new response with the wrong Agent turn,
    /// which is worse than explicitly losing the incomplete exchange. Coverage/drop telemetry is
    /// the authority for that missing record; completed evidence is never fabricated.
    pub fn expire_idle(&mut self, now: Instant) {
        let idle_timeout = self.idle_timeout;
        let websocket_idle_timeout = self.websocket_idle_timeout;
        let before = self.connections.len();
        self.connections.retain(|key, state| {
            let timeout = if state.quiescent_websocket() {
                websocket_idle_timeout
            } else {
                idle_timeout
            };
            let retain = !state.idle(now, timeout);
            if !retain && interaction_diagnostics_enabled_for(key.pid) {
                tracing::warn!(
                    pid = key.pid,
                    connection_id = format_args!("{:x}", key.connection_id),
                    pending_requests = state.pending_requests.len(),
                    request_buffer_bytes = state.requests.buffer.len(),
                    response_buffer_bytes = state.responses.buffer.len(),
                    "expired idle Agent interaction reassembly state"
                );
            }
            retain
        });
        self.metrics.connection_expirations = self
            .metrics
            .connection_expirations
            .saturating_add((before.saturating_sub(self.connections.len())) as u64);
        self.retain_live_connection_aliases();
    }

    /// Drop every protocol/alias state owned by a process generation as soon as its kernel Exit
    /// fact is observed.  TLS pointers and file descriptors can be reused before the normal idle
    /// TTL; retaining this state would let a new generation inherit an old request or WebSocket
    /// response. The raw chunks have already crossed the immutable evidence seam, so this cleanup
    /// only removes derived reassembly state and increments the bounded expiration metric.
    pub fn expire_process(&mut self, pid: u32, cgroup_id: u64) {
        let keys = self
            .connections
            .keys()
            .copied()
            .filter(|key| key.pid == pid && key.cgroup_id == cgroup_id)
            .collect::<Vec<_>>();
        for key in keys {
            if self.connections.remove(&key).is_some() {
                self.metrics.connection_expirations =
                    self.metrics.connection_expirations.saturating_add(1);
            }
        }
        self.connection_aliases.retain(|observed, canonical| {
            !((observed.pid == pid && observed.cgroup_id == cgroup_id)
                || (canonical.pid == pid && canonical.cgroup_id == cgroup_id))
        });
        let prefix = format!("{cgroup_id}:{pid}:");
        self.gap_evidence_fingerprints
            .retain(|fingerprint| !fingerprint.starts_with(&prefix));
    }

    pub fn active_connections(&self) -> usize {
        self.connections.len()
    }

    pub fn take_evidence(&mut self) -> Vec<CompletedPlaintextEvidence> {
        self.pending_evidence.drain(..).collect()
    }

    fn enqueue_gap_evidence(
        &mut self,
        key: ConnectionKey,
        chunk: &PlaintextChunk,
        reason: &str,
        transport_protocol: &str,
    ) {
        let direction = match chunk.direction {
            ChunkDirection::Request => "write",
            ChunkDirection::Response => "read",
        };
        // HTTP/2/WebSocket upgrade evidence is already emitted by the transport detector.  Do
        // not duplicate that canonical record when the decoder also reports its parse error.
        if reason == "unsupported_http2"
            && self.connections.get(&key).is_some_and(|state| {
                state
                    .evidence_fingerprints
                    .contains(&format!("http/2:{direction}"))
            })
        {
            return;
        }
        let fingerprint = format!(
            "{}:{}:{}:{}:{}",
            key.cgroup_id, key.pid, key.connection_id, direction, reason
        );
        if self.gap_evidence_fingerprints.len() >= self.max_connections.saturating_mul(4).max(4)
            && !self.gap_evidence_fingerprints.contains(&fingerprint)
        {
            if let Some(oldest) = self.gap_evidence_fingerprints.iter().next().cloned() {
                self.gap_evidence_fingerprints.remove(&oldest);
                self.metrics.evidence_evictions = self.metrics.evidence_evictions.saturating_add(1);
            }
        }
        if !self.gap_evidence_fingerprints.insert(fingerprint.clone()) {
            return;
        }
        let mut hash = Sha256::new();
        hash.update(b"anysentry.agent_plaintext_evidence.v1");
        hash.update(fingerprint.as_bytes());
        hash.update(chunk.event_at_unix_ns.to_ne_bytes());
        hash.update(&chunk.data);
        let evidence = CompletedPlaintextEvidence {
            schema_version: "anysentry.agent_plaintext_evidence.v1".to_string(),
            evidence_id: format!("pe_{}", hex_prefix(&hash.finalize(), 24)),
            cgroup_id: key.cgroup_id,
            pid: key.pid,
            connection_id: format!("tls:{:x}", key.connection_id),
            direction: direction.to_string(),
            tls_adapter_id: chunk.adapter_id.clone(),
            transport_protocol: transport_protocol.to_string(),
            parse_state: "unparsed".to_string(),
            llm_likelihood: "unknown".to_string(),
            schema_fingerprint: None,
            observed_at_unix_ns: chunk.event_at_unix_ns.to_string(),
            captured_bytes: chunk.data.len() as u64,
            encoding: "metadata_only".to_string(),
            redacted_sample: None,
            sample_sha256: sha256_hex(&chunk.data),
            reasons: vec![reason.to_string()],
            capture_source: chunk.source.clone(),
        };
        if self.pending_evidence.len() >= self.max_connections {
            self.pending_evidence.pop_front();
            self.metrics.evidence_evictions = self.metrics.evidence_evictions.saturating_add(1);
        }
        self.pending_evidence.push_back(evidence);
    }

    fn evict_if_needed(&mut self) {
        if self.connections.len() < self.max_connections {
            return;
        }
        if let Some(oldest) = self
            .connections
            .iter()
            .min_by_key(|(_, state)| state.last_activity)
            .map(|(key, _)| *key)
        {
            self.connections.remove(&oldest);
            self.metrics.connection_evictions = self.metrics.connection_evictions.saturating_add(1);
            self.connection_aliases
                .retain(|_, canonical| *canonical != oldest);
        }
    }

    pub fn metrics(&self) -> ReassemblyMetrics {
        self.metrics
    }
}

fn websocket_upgrade_metadata(request: &HttpMessage) -> Option<(String, String)> {
    let (method, path) = request_line(&request.start_line)?;
    if method != "GET" {
        return None;
    }
    let upgrade = request
        .header("upgrade")
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let connection = request.header("connection").is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
    });
    if !upgrade && !connection {
        return None;
    }
    let path = path
        .split('?')
        .next()
        .filter(|path| path.starts_with('/'))
        .unwrap_or("/websocket")
        .to_string();
    Some((request.endpoint(), path))
}

fn process_websocket_chunk(
    key: ConnectionKey,
    state: &mut ConnectionState,
    chunk: &PlaintextChunk,
    max_body_bytes: usize,
) -> Vec<CompletedInteraction> {
    state.websocket.prepare_recovered_frame(&chunk.data);
    match chunk.direction {
        ChunkDirection::Request => {
            let messages = state.websocket.requests.push(
                &chunk.data,
                chunk.event_at_unix_ns,
                &chunk.partial_reasons,
            );
            for message in messages {
                let Some(mut request) = body_only_llm_request(
                    &message.payload,
                    message.completed_at_unix_ns,
                    &message.partial_reasons,
                ) else {
                    continue;
                };
                request.started_at_unix_ns = message.started_at_unix_ns;
                request.start_line = format!("POST {} HTTP/1.1", state.websocket.path);
                request
                    .headers
                    .insert("host".to_string(), state.websocket.endpoint.clone());
                request.transport_protocol = Some("websocket".to_string());
                state
                    .identity
                    .observe_http(&request, ChunkDirection::Request);
                add_binding_reasons(state, &mut request.partial_reasons);
                if !state.push_pending_request(request) {
                    state.pending_request_limit_hit = true;
                    extend_unique(
                        &mut state.binding_reasons,
                        ["pending_request_limit".to_string()],
                    );
                }
            }
            Vec::new()
        }
        ChunkDirection::Response => {
            let messages = state.websocket.responses.push(
                &chunk.data,
                chunk.event_at_unix_ns,
                &chunk.partial_reasons,
            );
            process_websocket_response_messages(key, state, messages, max_body_bytes)
        }
    }
}

fn process_websocket_response_messages(
    key: ConnectionKey,
    state: &mut ConnectionState,
    messages: Vec<DecodedWebSocketMessage>,
    max_body_bytes: usize,
) -> Vec<CompletedInteraction> {
    let mut completed = Vec::new();
    for message in messages {
        {
            let response = &mut state.websocket.response;
            if response.body.len().saturating_add(message.payload.len()) <= max_body_bytes {
                response.body.extend_from_slice(&message.payload);
                response.captured_body_bytes = response
                    .captured_body_bytes
                    .saturating_add(message.payload.len());
            } else {
                extend_unique(
                    &mut response.partial_reasons,
                    ["websocket_response_body_limit".to_string()],
                );
            }
        }
        let Ok(value) = serde_json::from_slice::<Value>(&message.payload) else {
            extend_unique(
                &mut state.websocket.response.partial_reasons,
                ["websocket_response_json_parse_error".to_string()],
            );
            continue;
        };
        collect_stream_identity_values(
            &value,
            ChunkDirection::Response,
            &mut state.identity.anchor_hashes,
        );
        let Some(event_type) = value.get("type").and_then(Value::as_str) else {
            extend_unique(
                &mut state.websocket.response.partial_reasons,
                ["websocket_response_event_type_missing".to_string()],
            );
            continue;
        };
        if !event_type.starts_with("response.") && event_type != "error" {
            continue;
        }
        if state.pending_requests.is_empty() {
            if state.websocket.recovered_without_handshake {
                // Attach missed the client response.create; keep streaming server events under a
                // synthetic request so marker text / tools still surface as a parsed interaction.
                let mut synthetic = HttpMessage {
                    start_line: format!("POST {} HTTP/1.1", state.websocket.path),
                    headers: BTreeMap::from([(
                        "host".to_string(),
                        state.websocket.endpoint.clone(),
                    )]),
                    captured_body_bytes: 0,
                    body: br#"{"type":"response.create","model":"unknown","input":[]}"#.to_vec(),
                    started_at_unix_ns: message.started_at_unix_ns,
                    completed_at_unix_ns: message.started_at_unix_ns,
                    partial_reasons: vec!["websocket_request_missing_recovered".to_string()],
                    metadata_inferred: true,
                    transport_protocol: Some("websocket".to_string()),
                    derived_body: None,
                };
                add_binding_reasons(state, &mut synthetic.partial_reasons);
                if !state.push_pending_request(synthetic) {
                    state.websocket.response.clear();
                    continue;
                }
            } else {
                state.websocket.response.clear();
                continue;
            }
        }

        let binding_reasons = if state.binding_uncertain {
            state.binding_reasons.clone()
        } else {
            Vec::new()
        };
        let response = &mut state.websocket.response;
        response
            .started_at_unix_ns
            .get_or_insert(message.started_at_unix_ns);
        extend_unique(&mut response.partial_reasons, message.partial_reasons);
        extend_unique(&mut response.partial_reasons, binding_reasons);
        response
            .tool_calls
            .extend(extract_tool_calls(&value, message.completed_at_unix_ns));

        if response.semantic_payloads.len() < MAX_SSE_STRUCTURED_EVENTS {
            response.semantic_payloads.push(message.payload.clone());
        }

        let status_code = match event_type {
            "response.completed" | "response.done" => Some(200),
            "response.failed" | "response.incomplete" | "response.cancelled" | "error" => Some(502),
            _ => None,
        };
        let Some(status_code) = status_code else {
            continue;
        };
        let response = std::mem::replace(
            &mut state.websocket.response,
            WebSocketResponseAccumulator::new(),
        );
        let Some(request) = state.pop_pending_request() else {
            continue;
        };
        let started_at_unix_ns = response
            .started_at_unix_ns
            .unwrap_or(message.started_at_unix_ns);
        let response_message = HttpMessage {
            start_line: format!("HTTP/1.1 {status_code} WebSocket"),
            headers: BTreeMap::from([
                (
                    "content-type".to_string(),
                    "application/json-seq".to_string(),
                ),
                ("host".to_string(), state.websocket.endpoint.clone()),
            ]),
            captured_body_bytes: response.captured_body_bytes,
            body: response.body,
            started_at_unix_ns,
            completed_at_unix_ns: message.completed_at_unix_ns,
            partial_reasons: response.partial_reasons,
            metadata_inferred: true,
            transport_protocol: Some("websocket".to_string()),
            derived_body: Some(synthetic_sse_from_raw_events(&response.semantic_payloads)),
        };
        state.sequence = state.sequence.wrapping_add(1);
        if let Some(mut interaction) = build_interaction(
            key,
            state.sequence,
            &state.source,
            &state.adapter_id,
            request,
            response_message,
            state.bind_quality,
            state.socket_fd,
            state.socket_cookie,
            state.fd_generation,
        ) {
            let mut tool_calls = response.tool_calls;
            tool_calls.append(&mut interaction.tool_calls);
            dedup_tool_calls(&mut tool_calls);
            interaction.tool_calls = tool_calls;
            if has_unmatched_tool_calls(&interaction.tool_calls, &interaction.tool_results) {
                interaction.conversation_completeness = "tool_pending".to_string();
                interaction.completeness = "partial".to_string();
                extend_unique(
                    &mut interaction.partial_reasons,
                    ["tool_result_pending".to_string()],
                );
            }
            completed.push(interaction);
        }
    }
    completed
}

fn interaction_diagnostics_enabled_for(pid: u32) -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    let enabled = *ENABLED.get_or_init(|| {
        std::env::var("A3S_OBSERVER_TLS_DIAGNOSTICS")
            .ok()
            .is_some_and(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "on" | "yes"
                )
            })
    });
    if !enabled {
        return false;
    }
    static PID_FILTER: OnceLock<Option<u32>> = OnceLock::new();
    PID_FILTER
        .get_or_init(|| {
            std::env::var("A3S_OBSERVER_TLS_DIAGNOSTIC_PID")
                .ok()
                .and_then(|value| value.trim().parse::<u32>().ok())
                .filter(|value| *value > 0)
        })
        .is_none_or(|expected| expected == pid)
}

fn plaintext_fragment_kind(data: &[u8]) -> &'static str {
    if data.starts_with(b"POST ") {
        "http_request"
    } else if data.starts_with(b"HTTP/1.") {
        "http_response"
    } else if data.starts_with(b"PRI * HTTP/2.0") {
        "http2_preface"
    } else if data.starts_with(b"data:") || data.starts_with(b"event:") {
        "sse"
    } else if data.starts_with(b"{") || data.starts_with(b"[") {
        "json"
    } else if data.len() >= 3 && data[0] == 0x17 && data[1] == 0x03 {
        "tls_record"
    } else if data
        .iter()
        .take(16)
        .all(|byte| byte.is_ascii_hexdigit() || matches!(*byte, b'\r' | b'\n' | b';'))
    {
        "chunk_framing"
    } else {
        "continuation"
    }
}

fn plaintext_transport_evidence(
    key: ConnectionKey,
    state: &mut ConnectionState,
    chunk: &PlaintextChunk,
) -> Option<CompletedPlaintextEvidence> {
    let (transport_protocol, reason) =
        if chunk.data.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
            ("http/2", "transport_decoder_unavailable")
        } else if looks_like_websocket_upgrade(&chunk.data) {
            ("websocket", "websocket_upgrade_observed")
        } else if state.websocket.recovered_without_handshake
            && recoverable_websocket_frame_prefix(&chunk.data, chunk.direction)
        {
            ("websocket", "websocket_handshake_recovered")
        } else {
            return None;
        };
    let direction = match chunk.direction {
        ChunkDirection::Request => "write",
        ChunkDirection::Response => "read",
    };
    let fingerprint = format!("{transport_protocol}:{direction}");
    if !state.evidence_fingerprints.insert(fingerprint.clone()) {
        return None;
    }
    let mut hash = Sha256::new();
    hash.update(b"anysentry.agent_plaintext_evidence.v1");
    hash.update(key.cgroup_id.to_ne_bytes());
    hash.update(key.pid.to_ne_bytes());
    hash.update(key.connection_id.to_ne_bytes());
    hash.update(chunk.event_at_unix_ns.to_ne_bytes());
    hash.update(fingerprint.as_bytes());
    hash.update(&chunk.data);
    let evidence_id = format!("pe_{}", hex_prefix(&hash.finalize(), 24));
    Some(CompletedPlaintextEvidence {
        schema_version: "anysentry.agent_plaintext_evidence.v1".to_string(),
        evidence_id,
        cgroup_id: key.cgroup_id,
        pid: key.pid,
        connection_id: format!("tls:{:x}", key.connection_id),
        direction: direction.to_string(),
        tls_adapter_id: state.adapter_id.clone(),
        transport_protocol: transport_protocol.to_string(),
        parse_state: "unparsed".to_string(),
        llm_likelihood: "unknown".to_string(),
        schema_fingerprint: None,
        observed_at_unix_ns: chunk.event_at_unix_ns.to_string(),
        captured_bytes: chunk.data.len() as u64,
        encoding: "metadata_only".to_string(),
        redacted_sample: None,
        sample_sha256: sha256_hex(&chunk.data),
        reasons: vec![reason.to_string()],
        capture_source: state.source.clone(),
    })
}

fn looks_like_websocket_upgrade(data: &[u8]) -> bool {
    if !data.starts_with(b"GET ") {
        return false;
    }
    let captured = &data[..data.len().min(8 * 1024)];
    let lowercase = captured
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    find_bytes(&lowercase, b"\r\nupgrade: websocket").is_some()
        || find_bytes(&lowercase, b"\r\nconnection: upgrade").is_some()
}

fn looks_like_websocket_switching_protocols(data: &[u8]) -> bool {
    if !data.starts_with(b"HTTP/1.1 101") && !data.starts_with(b"HTTP/1.0 101") {
        return false;
    }
    let captured = &data[..data.len().min(8 * 1024)];
    let lowercase = captured
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    find_bytes(&lowercase, b"\r\nupgrade: websocket").is_some()
        || find_bytes(&lowercase, b"\r\nconnection: upgrade").is_some()
}

fn looks_like_http_request_prefix(data: &[u8]) -> bool {
    classify_http_method_prefix(data) == HTTP_METHOD_PREFIX_COMPLETE
}

fn websocket_frame_opcode(data: &[u8]) -> Option<u8> {
    let (&first, rest) = data.split_first()?;
    if rest.is_empty() || first & 0x30 != 0 {
        return None;
    }
    let opcode = first & 0x0f;
    matches!(opcode, 0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xA).then_some(opcode)
}

fn looks_like_websocket_frame_prefix(data: &[u8]) -> bool {
    let Some(opcode) = websocket_frame_opcode(data) else {
        return false;
    };
    if opcode == 0x0 {
        return false;
    }
    let first = data[0];
    let payload_marker = data[1] & 0x7f;
    !matches!(opcode, 0x8..=0xA) || (first & 0x80 != 0 && payload_marker <= 125)
}

fn is_websocket_control_frame(data: &[u8]) -> bool {
    looks_like_websocket_frame_prefix(data)
        && websocket_frame_opcode(data).is_some_and(|opcode| matches!(opcode, 0x8..=0xA))
}

fn recoverable_websocket_frame_prefix(data: &[u8], direction: ChunkDirection) -> bool {
    let Some(opcode) = websocket_frame_opcode(data) else {
        return false;
    };
    if !matches!(opcode, 0x1 | 0x2) {
        return false;
    }
    // Require FIN so mid-payload bytes that happen to look like opcode 1/2 do not activate a
    // decoder on a misaligned stream (live Codex attach often starts mid-frame).
    if data[0] & 0x80 == 0 {
        return false;
    }
    let masked = data.get(1).is_some_and(|byte| byte & 0x80 != 0);
    match direction {
        ChunkDirection::Request if !masked => return false,
        ChunkDirection::Response if masked => return false,
        _ => {}
    }
    if data[0] & 0x40 != 0 {
        return true;
    }
    let payload_marker = usize::from(data[1] & 0x7f);
    let length_bytes = if payload_marker == 126 {
        2
    } else if payload_marker == 127 {
        8
    } else {
        0
    };
    let header_len = 2usize.saturating_add(length_bytes);
    if masked {
        let mask_offset = header_len;
        let Some(mask) = data.get(mask_offset..mask_offset + 4) else {
            return false;
        };
        let payload_offset = mask_offset + 4;
        data.get(payload_offset..)
            .into_iter()
            .flatten()
            .take(16)
            .enumerate()
            .map(|(index, byte)| *byte ^ mask[index % 4])
            .find(|byte| !byte.is_ascii_whitespace())
            .is_some_and(|byte| matches!(byte, b'{' | b'['))
    } else {
        data.get(header_len..)
            .into_iter()
            .flatten()
            .take(16)
            .copied()
            .find(|byte| !byte.is_ascii_whitespace())
            .is_some_and(|byte| matches!(byte, b'{' | b'['))
    }
}

fn plausible_websocket_data_frame_at(data: &[u8], expect_masked: bool) -> bool {
    if data.len() < 2 || data[0] & 0x30 != 0 {
        return false;
    }
    let opcode = data[0] & 0x0f;
    if !matches!(opcode, 0x1 | 0x2) {
        return false;
    }
    if data[0] & 0x80 == 0 {
        return false;
    }
    let masked = data[1] & 0x80 != 0;
    if masked != expect_masked {
        return false;
    }
    match decode_websocket_frame(data, 16 * 1024 * 1024) {
        Ok(Some(_)) | Ok(None) => true,
        Err(_) => false,
    }
}

fn looks_like_websocket_continuation_prefix(data: &[u8]) -> bool {
    websocket_frame_opcode(data) == Some(0x0)
}

fn body_only_llm_request(
    body: &[u8],
    event_at_unix_ns: u128,
    partial_reasons: &[String],
) -> Option<HttpMessage> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let object = value.as_object()?;
    let has_model = object.get("model").and_then(Value::as_str).is_some();
    let has_input = object
        .get("input")
        .is_some_and(|input| input.is_array() || input.is_string() || input.is_object());
    let mcp_request = object.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && object.get("method").and_then(Value::as_str).is_some()
        && object.get("id").is_some();
    let generic_tool_request = (object.contains_key("instruction")
        && (object.contains_key("requested_by")
            || object.contains_key("tool")
            || object.contains_key("name")))
        || (object.get("code").and_then(Value::as_str).is_some()
            && (object.contains_key("timeout_ms")
                || object.contains_key("language")
                || object.contains_key("runtime")));
    let path = if object.get("type").and_then(Value::as_str) == Some("response.create")
        && (has_model || has_input)
    {
        "/v1/responses"
    } else if has_model && object.contains_key("messages") {
        if object.contains_key("max_tokens") || object.contains_key("anthropic_version") {
            "/v1/messages"
        } else {
            "/v1/chat/completions"
        }
    } else if has_model && has_input {
        "/v1/responses"
    } else if has_model
        && (object.contains_key("prompt")
            || object.contains_key("contents")
            || object.contains_key("instructions"))
    {
        "/v1/completions"
    } else if mcp_request {
        "/mcp"
    } else if generic_tool_request {
        "/tool/execute"
    } else {
        return None;
    };
    Some(HttpMessage {
        start_line: format!("POST {path} HTTP/1.1"),
        headers: BTreeMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("host".to_string(), "unknown".to_string()),
        ]),
        body: body.to_vec(),
        captured_body_bytes: body.len(),
        started_at_unix_ns: event_at_unix_ns,
        completed_at_unix_ns: event_at_unix_ns,
        partial_reasons: partial_reasons.to_vec(),
        metadata_inferred: true,
        transport_protocol: Some("json-body".to_string()),
        derived_body: None,
    })
}

fn body_only_llm_response(
    body: &[u8],
    event_at_unix_ns: u128,
    partial_reasons: &[String],
) -> Option<HttpMessage> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let looks_like_response = value.get("choices").is_some_and(Value::is_array)
        || value.get("candidates").is_some_and(Value::is_array)
        || value
            .get("output")
            .is_some_and(|output| output.is_array() || output.is_object())
        || value.get("output_text").is_some()
        || value
            .get("content")
            .is_some_and(|content| content.is_array() || content.is_string())
        || value
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind.starts_with("response.") || kind == "message")
        || (value.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
            && value.get("id").is_some()
            && (value.get("result").is_some() || value.get("error").is_some()))
        || value.get("tool_call_id").is_some_and(Value::is_string)
        || (value.get("execution_id").is_some()
            && value.get("exit_code").is_some()
            && (value.get("stdout").is_some() || value.get("stderr").is_some()));
    looks_like_response.then(|| HttpMessage {
        start_line: "HTTP/1.1 200 OK".to_string(),
        headers: BTreeMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("host".to_string(), "unknown".to_string()),
        ]),
        body: body.to_vec(),
        captured_body_bytes: body.len(),
        started_at_unix_ns: event_at_unix_ns,
        completed_at_unix_ns: event_at_unix_ns,
        partial_reasons: partial_reasons.to_vec(),
        metadata_inferred: true,
        transport_protocol: Some("json-body".to_string()),
        derived_body: None,
    })
}

struct BodyOnlyFeed {
    result: BodyOnlyFeedResult,
    messages: Vec<HttpMessage>,
    reasons: Vec<String>,
}

impl RustlsBodyOnlyState {
    fn clear(&mut self) {
        self.buffer.clear();
        self.started_at_unix_ns = None;
        self.partial_reasons.clear();
        self.response_mode = BodyOnlyResponseMode::Unknown;
        self.response_parsed_offset = 0;
        self.response_scan_offset = 0;
        self.response_event_count = 0;
        self.response_raw_events.clear();
    }
}

/// Incrementally parse body-only Rustls application payloads.  Some CommonState profiles expose
/// the JSON body but not the HTTP request line, and a single JSON body can be split over many
/// `OutboundChunks`/`Payload` observations.  We only enter this state after a JSON-shaped prefix;
/// arbitrary bytes are left to the normal HTTP/WebSocket decoders.  The deserializer is bounded,
/// supports back-to-back values, and emits an explicit gap for malformed/non-LLM data.
fn feed_rustls_body_only(
    state: &mut RustlsBodyOnlyState,
    direction: ChunkDirection,
    data: &[u8],
    event_at_unix_ns: u128,
    reasons: &[String],
    max_body_bytes: usize,
) -> BodyOnlyFeed {
    if data.is_empty() {
        return BodyOnlyFeed {
            result: BodyOnlyFeedResult::NotCandidate,
            messages: Vec::new(),
            reasons: Vec::new(),
        };
    }
    let starts_json = data
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| matches!(byte, b'{' | b'['));
    if state.buffer.is_empty() && !starts_json {
        if data.iter().all(u8::is_ascii_whitespace) && data.len() <= 32 {
            state.started_at_unix_ns = Some(event_at_unix_ns);
            extend_unique(&mut state.partial_reasons, reasons.iter().cloned());
            state.buffer.extend_from_slice(data);
            return BodyOnlyFeed {
                result: BodyOnlyFeedResult::Pending,
                messages: Vec::new(),
                reasons: Vec::new(),
            };
        }
        return BodyOnlyFeed {
            result: BodyOnlyFeedResult::NotCandidate,
            messages: Vec::new(),
            reasons: Vec::new(),
        };
    }
    if state.buffer.is_empty() {
        state.started_at_unix_ns = Some(event_at_unix_ns);
    }
    extend_unique(&mut state.partial_reasons, reasons.iter().cloned());
    let max_body_bytes = max_body_bytes.min(MAX_RUSTLS_BODY_ONLY_BYTES);
    if state.buffer.len().saturating_add(data.len()) > max_body_bytes {
        extend_unique(
            &mut state.partial_reasons,
            ["rustls_body_only_limit".to_string()],
        );
        let reasons = std::mem::take(&mut state.partial_reasons);
        state.clear();
        return BodyOnlyFeed {
            result: BodyOnlyFeedResult::Invalid,
            messages: Vec::new(),
            reasons,
        };
    }
    state.buffer.extend_from_slice(data);

    let mut messages = Vec::new();
    let mut invalid_reason = None;
    loop {
        let mut stream = serde_json::Deserializer::from_slice(&state.buffer).into_iter::<Value>();
        let Some(parsed) = stream.next() else {
            break;
        };
        match parsed {
            Ok(_value) => {
                let consumed = stream.byte_offset();
                if consumed == 0 {
                    break;
                }
                // Keep the exact observed JSON bytes (including key order and insignificant
                // whitespace) as the transport evidence.  Include whitespace up to the next
                // value (or the end of this fragment) so a pretty-printed body hashes exactly;
                // re-serializing `Value` here would change replay/audit bytes.
                let mut encoded_end = consumed;
                while state
                    .buffer
                    .get(encoded_end)
                    .is_some_and(|byte| byte.is_ascii_whitespace())
                {
                    encoded_end += 1;
                }
                let encoded = state.buffer[..encoded_end].to_vec();
                let started = state.started_at_unix_ns.unwrap_or(event_at_unix_ns);
                let message = match direction {
                    ChunkDirection::Request => {
                        body_only_llm_request(&encoded, started, &state.partial_reasons)
                    }
                    ChunkDirection::Response => {
                        body_only_llm_response(&encoded, started, &state.partial_reasons)
                    }
                };
                let Some(mut message) = message else {
                    invalid_reason = Some("rustls_body_only_not_llm".to_string());
                    break;
                };
                message.started_at_unix_ns = started;
                message.completed_at_unix_ns = event_at_unix_ns;
                messages.push(message);
                state.buffer.drain(..encoded_end);
                state.started_at_unix_ns = (!state.buffer.is_empty()).then_some(event_at_unix_ns);
                if state.buffer.is_empty() {
                    state.partial_reasons.clear();
                    break;
                }
            }
            Err(error) if error.is_eof() => break,
            Err(_) => {
                invalid_reason = Some("rustls_body_only_json_parse_error".to_string());
                break;
            }
        }
    }

    if let Some(reason) = invalid_reason {
        extend_unique(&mut state.partial_reasons, [reason]);
        let reasons = std::mem::take(&mut state.partial_reasons);
        state.clear();
        return BodyOnlyFeed {
            result: BodyOnlyFeedResult::Invalid,
            messages,
            reasons,
        };
    }
    BodyOnlyFeed {
        result: BodyOnlyFeedResult::Pending,
        messages,
        reasons: Vec::new(),
    }
}

fn response_event_terminal(value: &Value) -> Option<u16> {
    let kind = value.get("type").and_then(Value::as_str)?;
    match kind {
        "response.completed" | "response.done" | "message_stop" => Some(200),
        "response.failed"
        | "response.incomplete"
        | "response.cancelled"
        | "error"
        | "message_error" => Some(502),
        _ => None,
    }
}

fn body_only_response_message(
    state: &RustlsBodyOnlyState,
    raw_body: &[u8],
    status_code: u16,
    event_at_unix_ns: u128,
    derived_body: Option<Vec<u8>>,
) -> Option<HttpMessage> {
    if raw_body.is_empty() {
        return None;
    }
    let started = state.started_at_unix_ns.unwrap_or(event_at_unix_ns);
    let (content_type, transport_protocol) = if state.response_mode == BodyOnlyResponseMode::Sse {
        ("text/event-stream", "sse")
    } else if derived_body.is_some() {
        ("application/json-seq", "json-body-sequence")
    } else {
        ("application/json", "json-body")
    };
    Some(HttpMessage {
        start_line: format!("HTTP/1.1 {status_code} OK"),
        headers: BTreeMap::from([
            ("content-type".to_string(), content_type.to_string()),
            ("host".to_string(), "unknown".to_string()),
        ]),
        captured_body_bytes: raw_body.len(),
        body: raw_body.to_vec(),
        started_at_unix_ns: started,
        completed_at_unix_ns: event_at_unix_ns,
        partial_reasons: state.partial_reasons.clone(),
        metadata_inferred: true,
        transport_protocol: Some(transport_protocol.to_string()),
        derived_body,
    })
}

fn body_only_response_mode(data: &[u8]) -> Option<BodyOnlyResponseMode> {
    let leading = data.iter().position(|byte| !byte.is_ascii_whitespace())?;
    let trimmed = &data[leading..];
    let first_line = trimmed
        .split(|byte| *byte == b'\n' || *byte == b'\r')
        .next()
        .unwrap_or_default();
    if first_line.starts_with(b"data:")
        || first_line.starts_with(b"event:")
        || first_line.starts_with(b":")
    {
        Some(BodyOnlyResponseMode::Sse)
    } else if matches!(trimmed.first(), Some(b'{' | b'[')) {
        Some(BodyOnlyResponseMode::Json)
    } else {
        None
    }
}

fn maybe_body_only_json_prefix(data: &[u8]) -> bool {
    let trimmed = data.iter().position(|byte| !byte.is_ascii_whitespace());
    let Some(offset) = trimmed else {
        // Whitespace-only fragments can precede a split JSON opener. Keep only a small prefix in
        // the synthetic lane; a long whitespace run is handed to the normal decoder.
        return data.len() <= 32;
    };
    let prefix = &data[offset..];
    prefix.starts_with(b"{")
        || prefix.starts_with(b"[")
        || (prefix.len() <= 8 && (b"{".starts_with(prefix) || b"[".starts_with(prefix)))
}

fn maybe_body_only_response_prefix(data: &[u8]) -> bool {
    if body_only_response_mode(data).is_some() {
        return true;
    }
    let offset = data.iter().position(|byte| !byte.is_ascii_whitespace());
    let Some(offset) = offset else {
        return data.len() <= 32;
    };
    let prefix = &data[offset..];
    prefix.len() <= 16
        && (b"data:".starts_with(prefix)
            || b"event:".starts_with(prefix)
            || b":".starts_with(prefix)
            || maybe_body_only_json_prefix(prefix))
}

/// Accept only provider/lifecycle-shaped objects in an unframed Rustls response.  A pending
/// request is still required by the caller, but this second gate prevents health/config JSON from
/// occupying the response accumulator and contaminating a later model exchange.
fn body_only_response_value_is_candidate(value: &Value) -> bool {
    if let Some(kind) = value.get("type").and_then(Value::as_str) {
        if kind.starts_with("response.")
            || matches!(
                kind,
                "message"
                    | "message_start"
                    | "message_delta"
                    | "message_stop"
                    | "content_block_start"
                    | "content_block_delta"
                    | "content_block_stop"
                    | "error"
                    | "message_error"
            )
        {
            return true;
        }
    }
    value.get("choices").is_some_and(Value::is_array)
        || value.get("candidates").is_some_and(Value::is_array)
        || value
            .get("output")
            .is_some_and(|output| output.is_array() || output.is_object())
        || value.get("output_text").is_some()
        || value.get("content").is_some_and(Value::is_array)
        || (value.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
            && value.get("id").is_some()
            && (value.get("result").is_some() || value.get("error").is_some()))
        || value.get("tool_call_id").is_some()
        || (value.get("execution_id").is_some()
            && value.get("exit_code").is_some()
            && (value.get("stdout").is_some() || value.get("stderr").is_some()))
}

fn body_only_response_is_lifecycle(value: &Value) -> bool {
    value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| {
            kind.starts_with("response.")
                || matches!(
                    kind,
                    "message_start"
                        | "message_delta"
                        | "message_stop"
                        | "content_block_start"
                        | "content_block_delta"
                        | "content_block_stop"
                        | "error"
                        | "message_error"
                )
        })
}

fn synthetic_sse_from_raw_events(events: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for raw in events.iter().take(MAX_SSE_STRUCTURED_EVENTS) {
        body.extend_from_slice(b"data: ");
        body.extend_from_slice(raw);
        if !raw.ends_with(b"\n") {
            body.push(b'\n');
        }
        body.push(b'\n');
    }
    body
}

/// Aggregate body-only response payloads until a terminal provider event is observed.  Rustls
/// hooks can expose each decrypted WebSocket/HTTP body object independently; emitting every
/// `response.output_text.delta` as a response would pair one request with many false exchanges.
/// This state accepts SSE blocks or newline/concatenated JSON event objects, keeps all bytes within
/// the stream budget, and returns exactly one synthetic response at terminal/failure.
fn feed_rustls_body_only_response(
    state: &mut RustlsBodyOnlyState,
    data: &[u8],
    event_at_unix_ns: u128,
    reasons: &[String],
    max_body_bytes: usize,
) -> BodyOnlyFeed {
    if data.is_empty() {
        return BodyOnlyFeed {
            result: BodyOnlyFeedResult::NotCandidate,
            messages: Vec::new(),
            reasons: Vec::new(),
        };
    }
    if state.buffer.is_empty() {
        state.started_at_unix_ns = Some(event_at_unix_ns);
    }
    extend_unique(&mut state.partial_reasons, reasons.iter().cloned());
    let max_body_bytes = max_body_bytes.min(MAX_RUSTLS_BODY_ONLY_BYTES);
    if state.buffer.len().saturating_add(data.len()) > max_body_bytes {
        extend_unique(
            &mut state.partial_reasons,
            ["rustls_body_only_limit".to_string()],
        );
        let reasons = std::mem::take(&mut state.partial_reasons);
        state.clear();
        return BodyOnlyFeed {
            result: BodyOnlyFeedResult::Invalid,
            messages: Vec::new(),
            reasons,
        };
    }
    state.buffer.extend_from_slice(data);

    if state.response_mode == BodyOnlyResponseMode::Unknown {
        if let Some(mode) = body_only_response_mode(&state.buffer) {
            state.response_mode = mode;
        } else if state.buffer.len() < 32 {
            // A Rustls callback may split the `data:` or JSON opener itself. Keep the bounded
            // prefix until the next callback instead of handing it to the HTTP decoder.
            return BodyOnlyFeed {
                result: BodyOnlyFeedResult::Pending,
                messages: Vec::new(),
                reasons: Vec::new(),
            };
        } else {
            extend_unique(
                &mut state.partial_reasons,
                ["rustls_body_only_not_candidate".to_string()],
            );
            let reasons = std::mem::take(&mut state.partial_reasons);
            state.clear();
            return BodyOnlyFeed {
                result: BodyOnlyFeedResult::Invalid,
                messages: Vec::new(),
                reasons,
            };
        }
    }

    let mut messages = Vec::new();
    let mut emitted_reasons = Vec::new();
    loop {
        let mut terminal: Option<(usize, u16)> = None;
        let mut invalid_reason = None;
        if state.response_mode == BodyOnlyResponseMode::Sse {
            let mut cursor = state.response_parsed_offset;
            // Only bytes past the previous scan boundary (minus the longest delimiter minus
            // one, so a delimiter straddling that boundary is still found) can introduce a new
            // block; the prefix is delimiter-free by the scan-offset invariant.
            let mut search_from = state
                .response_scan_offset
                .saturating_sub(3)
                .max(cursor)
                .min(state.buffer.len());
            loop {
                let Some((rel, delimiter_len)) = sse_block_delimiter(&state.buffer[search_from..])
                else {
                    state.response_scan_offset = state.buffer.len();
                    break;
                };
                let end = search_from + rel + delimiter_len;
                let block = &state.buffer[cursor..end];
                cursor = end;
                search_from = end;
                let data_lines = block
                    .split(|byte| *byte == b'\n' || *byte == b'\r')
                    .filter_map(|line| {
                        let line = std::str::from_utf8(line).ok()?;
                        line.strip_prefix("data:").map(str::trim_start)
                    })
                    .collect::<Vec<_>>();
                let event_data = data_lines.join("\n");
                if event_data.trim() == "[DONE]" {
                    terminal = Some((cursor, 200));
                    break;
                }
                if event_data.trim().is_empty() {
                    continue;
                }
                let Ok(value) = serde_json::from_str::<Value>(&event_data) else {
                    invalid_reason = Some("rustls_body_only_sse_json_parse_error");
                    break;
                };
                // SSE streams may carry provider-neutral heartbeat/comment objects between
                // lifecycle events. Ignore an unrecognised object while retaining the raw block;
                // only a provider-shaped event can contribute semantic output or close the
                // response, so unrelated health JSON cannot be paired as an LLM response.
                if !body_only_response_value_is_candidate(&value) {
                    continue;
                }
                if state.response_event_count < MAX_SSE_STRUCTURED_EVENTS {
                    state.response_event_count += 1;
                } else {
                    extend_unique(
                        &mut state.partial_reasons,
                        ["rustls_body_only_event_limit".to_string()],
                    );
                }
                if let Some(status) = response_event_terminal(&value) {
                    terminal = Some((cursor, status));
                    break;
                }
            }
            state.response_parsed_offset = cursor;
        } else {
            let mut cursor = state.response_parsed_offset;
            loop {
                let mut stream = serde_json::Deserializer::from_slice(&state.buffer[cursor..])
                    .into_iter::<Value>();
                let Some(parsed) = stream.next() else {
                    break;
                };
                match parsed {
                    Ok(value) => {
                        let consumed = stream.byte_offset();
                        if consumed == 0 {
                            break;
                        }
                        let mut end = cursor + consumed;
                        while state
                            .buffer
                            .get(end)
                            .is_some_and(|byte| byte.is_ascii_whitespace())
                        {
                            end += 1;
                        }
                        let raw_value = state.buffer[cursor..end].to_vec();
                        cursor = end;
                        let regular_response = state.response_event_count == 0
                            && body_only_llm_response(
                                &raw_value,
                                event_at_unix_ns,
                                &state.partial_reasons,
                            )
                            .is_some()
                            && !body_only_response_is_lifecycle(&value);
                        if regular_response {
                            terminal = Some((cursor, 200));
                            break;
                        }
                        if !body_only_response_value_is_candidate(&value) {
                            invalid_reason = Some("rustls_body_only_not_llm");
                            break;
                        }
                        if state.response_event_count < MAX_SSE_STRUCTURED_EVENTS {
                            state.response_event_count += 1;
                            state.response_raw_events.push(raw_value);
                        } else {
                            extend_unique(
                                &mut state.partial_reasons,
                                ["rustls_body_only_event_limit".to_string()],
                            );
                        }
                        let status = response_event_terminal(&value).or_else(|| {
                            (state.response_mode == BodyOnlyResponseMode::Json
                                && value.get("type").and_then(Value::as_str) == Some("message"))
                            .then_some(200)
                        });
                        if let Some(status) = status {
                            terminal = Some((cursor, status));
                            break;
                        }
                    }
                    Err(error) if error.is_eof() => break,
                    Err(_) => {
                        invalid_reason = Some("rustls_body_only_json_parse_error");
                        break;
                    }
                }
            }
            state.response_parsed_offset = cursor;
        }

        if let Some(reason) = invalid_reason {
            extend_unique(&mut state.partial_reasons, [reason.to_string()]);
            let mut reasons = std::mem::take(&mut state.partial_reasons);
            extend_unique(&mut reasons, emitted_reasons);
            state.clear();
            return BodyOnlyFeed {
                result: BodyOnlyFeedResult::Invalid,
                messages,
                reasons,
            };
        }
        let Some((terminal_end, status_code)) = terminal else {
            return BodyOnlyFeed {
                result: BodyOnlyFeedResult::Pending,
                messages,
                reasons: Vec::new(),
            };
        };
        let raw_body = state.buffer[..terminal_end].to_vec();
        let derived_body = if state.response_mode == BodyOnlyResponseMode::Json
            && !state.response_raw_events.is_empty()
        {
            Some(synthetic_sse_from_raw_events(&state.response_raw_events))
        } else {
            None
        };
        let Some(message) = body_only_response_message(
            state,
            &raw_body,
            status_code,
            event_at_unix_ns,
            derived_body,
        ) else {
            let mut reasons = emitted_reasons;
            extend_unique(
                &mut reasons,
                ["rustls_body_only_empty_response".to_string()],
            );
            state.clear();
            return BodyOnlyFeed {
                result: BodyOnlyFeedResult::Invalid,
                messages,
                reasons,
            };
        };
        extend_unique(&mut emitted_reasons, state.partial_reasons.clone());
        messages.push(message);
        let tail = state.buffer[terminal_end..].to_vec();
        state.clear();
        if tail.is_empty() {
            return BodyOnlyFeed {
                result: BodyOnlyFeedResult::Pending,
                messages,
                reasons: emitted_reasons,
            };
        }
        // A single callback can carry a terminal object followed by the next response. Retain the
        // exact tail and continue parsing it in the same bounded call; no bytes are folded into
        // the previous interaction or silently discarded.
        state.buffer = tail;
        state.started_at_unix_ns = Some(event_at_unix_ns);
        state.response_mode =
            body_only_response_mode(&state.buffer).unwrap_or(BodyOnlyResponseMode::Unknown);
        state.response_parsed_offset = 0;
        state.response_scan_offset = 0;
    }
}

fn sse_block_delimiter(bytes: &[u8]) -> Option<(usize, usize)> {
    let lf = find_bytes(bytes, b"\n\n").map(|offset| (offset, 2));
    let crlf = find_bytes(bytes, b"\r\n\r\n").map(|offset| (offset, 4));
    let cr = find_bytes(bytes, b"\r\r").map(|offset| (offset, 2));
    [lf, crlf, cr]
        .into_iter()
        .flatten()
        .min_by_key(|(offset, _)| *offset)
}

fn rustls_like_chunk(chunk: &PlaintextChunk) -> bool {
    chunk.route_candidate || chunk.source.to_ascii_lowercase().contains("rustls")
}

fn websocket_payload_probe(
    data: &[u8],
    direction: ChunkDirection,
    max_body_bytes: usize,
) -> Option<StreamIdentityProbe> {
    let frame = decode_websocket_frame(data, max_body_bytes)
        .ok()
        .flatten()?;
    if !frame.fin
        || frame.compressed
        || !matches!(frame.opcode, 0x1 | 0x2)
        || frame.masked != (direction == ChunkDirection::Request)
    {
        return None;
    }
    StreamIdentityProbe::from_websocket_payload(&frame.payload, direction)
}

fn chunk_identity_probe(
    chunk: &PlaintextChunk,
    max_body_bytes: usize,
) -> Option<StreamIdentityProbe> {
    if !rustls_like_chunk(chunk) {
        return None;
    }
    if looks_like_websocket_frame_prefix(&chunk.data) {
        if let Some(probe) = websocket_payload_probe(&chunk.data, chunk.direction, max_body_bytes) {
            return Some(probe);
        }
    }
    let kind = match chunk.direction {
        ChunkDirection::Request if looks_like_http_request_prefix(&chunk.data) => {
            StreamKind::Request
        }
        ChunkDirection::Response if chunk.data.starts_with(b"HTTP/") => StreamKind::Response,
        _ => {
            let first = chunk
                .data
                .iter()
                .copied()
                .find(|byte| !byte.is_ascii_whitespace());
            if !matches!(first, Some(b'{' | b'[')) {
                return None;
            }
            let value = serde_json::from_slice::<Value>(&chunk.data).ok()?;
            let mut probe = StreamIdentityProbe::default();
            collect_stream_identity_values(&value, chunk.direction, &mut probe.anchor_hashes);
            return probe.has_signal().then_some(probe);
        }
    };
    // One-shot probe over a single chunk: a fresh scan state gives full-body search semantics.
    let mut probe_sse_scan = SseTerminalScanState::default();
    let mut probe_chunked_scan = SseTerminalScanState::default();
    let decoded = decode_http_message(
        kind,
        &chunk.data,
        max_body_bytes,
        &mut probe_sse_scan,
        &mut probe_chunked_scan,
    )
    .ok()
    .flatten()?;
    Some(StreamIdentityProbe::from_http(
        &HttpMessage {
            start_line: decoded.start_line,
            headers: decoded.headers,
            body: decoded.body,
            captured_body_bytes: decoded.captured_body_bytes,
            started_at_unix_ns: chunk.event_at_unix_ns,
            completed_at_unix_ns: chunk.event_at_unix_ns,
            partial_reasons: decoded.partial_reasons,
            metadata_inferred: false,
            transport_protocol: None,
            derived_body: None,
        },
        chunk.direction,
    ))
}

fn candidate_matches_probe(state: &ConnectionState, probe: Option<&StreamIdentityProbe>) -> bool {
    let Some(probe) = probe else {
        return false;
    };
    state.identity.matches(probe)
}

fn add_binding_reasons(state: &ConnectionState, reasons: &mut Vec<String>) {
    if state.binding_uncertain {
        extend_unique(reasons, state.binding_reasons.clone());
    }
}

fn choose_connection_candidate(mut candidates: Vec<ConnectionKey>) -> ConnectionResolution {
    candidates.sort_unstable_by_key(|key| (key.cgroup_id, key.pid, key.connection_id));
    candidates.dedup();
    match candidates.as_slice() {
        [] => ConnectionResolution::New,
        [candidate] => ConnectionResolution::Resolved(*candidate),
        many => ConnectionResolution::Ambiguous(many.len()),
    }
}

fn narrow_connection_candidates(
    candidates: &mut Vec<ConnectionKey>,
    probe: Option<&StreamIdentityProbe>,
    states: &HashMap<ConnectionKey, ConnectionState>,
) {
    let Some(probe) = probe else {
        return;
    };
    if !probe.has_signal() {
        return;
    }
    let matching = candidates
        .iter()
        .copied()
        .filter(|key| {
            states
                .get(key)
                .is_some_and(|state| candidate_matches_probe(state, Some(probe)))
        })
        .collect::<Vec<_>>();
    // A probe is a narrowing hint, not a reason to throw away a stream whose first request has
    // not yet supplied the same anchor.  If no state matches, retain all candidates and let the
    // unique/ambiguous decision below determine whether binding is safe.
    if !matching.is_empty() {
        *candidates = matching;
    }
}


fn observe_socket_bind(state: &mut ConnectionState, chunk: &PlaintextChunk) {
    if chunk.bind_quality < TLS_BIND_QUALITY_FD {
        return;
    }
    if chunk.bind_quality < state.bind_quality {
        return;
    }
    if chunk.bind_quality > state.bind_quality
        || (chunk.socket_cookie != 0 && state.socket_cookie == 0)
        || (chunk.socket_fd > 0 && state.socket_fd <= 0)
    {
        state.bind_quality = chunk.bind_quality;
        state.socket_fd = chunk.socket_fd;
        state.socket_cookie = chunk.socket_cookie;
        state.fd_generation = chunk.fd_generation;
    }
}

fn build_interaction(
    key: ConnectionKey,
    sequence: u64,
    source: &str,
    adapter_id: &str,
    request: HttpMessage,
    response: HttpMessage,
    bind_quality: u8,
    socket_fd: i32,
    socket_cookie: u64,
    fd_generation: u32,
) -> Option<CompletedInteraction> {
    let (method, path) = request_line(&request.start_line)?;
    let endpoint = request.endpoint();
    let status_code = response_status(&response.start_line).unwrap_or_default();
    let request_encoding = request.header("content-encoding").unwrap_or("");
    let response_encoding = response.header("content-encoding").unwrap_or("");
    let (request_body, request_decode_reason) =
        decode_content_encoding(&request.body, request_encoding, DEFAULT_MAX_STREAM_BYTES);
    let (response_body, response_decode_reason) =
        decode_content_encoding(&response.body, response_encoding, DEFAULT_MAX_STREAM_BYTES);
    // `response.body` remains the canonical observed bytes. A Rustls body-only JSON sequence may
    // additionally carry a parser-only SSE representation so provider-neutral extraction can
    // aggregate lifecycle events without changing the stored hash or transcript bytes.
    let (response_parse_body, response_parse_reason) =
        if let Some(derived) = response.derived_body.as_deref() {
            decode_content_encoding(derived, "", DEFAULT_MAX_STREAM_BYTES)
        } else {
            (response_body.clone(), None)
        };
    let request_json = parse_json_body(&request_body);
    // Unknown wire shapes are still transport facts.  Keep an explicit `unparsed` interaction so
    // downstream can emit a coverage gap and retain the KernelFact/raw provenance instead of
    // silently dropping the exchange when no provider adapter is registered.
    let mut wire_match = match_wire_protocol(&method, &request.headers, request_json.as_ref())
        .or_else(|| {
            let body = request_json.as_ref()?;
            let headers = request
                .headers
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect::<Vec<_>>();
            let adapter = DefaultLlmFormatAdapter::new();
            (adapter.detect(&method, &headers, body).confidence == "confirmed").then_some(
                WireMatch {
                    template_id: "generic-llm-json",
                    likelihood: "likely",
                    parse_state: "partial",
                    interaction_kind: WireInteractionKind::Model,
                },
            )
        })
        .unwrap_or(WireMatch {
            template_id: "unknown-json-exchange",
            likelihood: "unknown",
            parse_state: "unparsed",
            interaction_kind: WireInteractionKind::Unparsed,
        });
    let response_is_sse = response
        .content_type()
        .eq_ignore_ascii_case("text/event-stream")
        || looks_like_sse(&response_parse_body);
    // A bounded SSE parser intentionally stops materializing structured events after the cap,
    // but that must remain visible in completeness rather than silently dropping tail events.
    let response_sse_event_limit = response_is_sse && sse_event_limit_reached(&response_parse_body);
    let (response_structured, mut response_text, mut tool_calls) = if response_is_sse {
        normalize_sse_response(&response_parse_body, response.completed_at_unix_ns)
    } else {
        let structured = parse_json_body(&response_parse_body);
        let text = structured.as_ref().and_then(extract_response_text);
        let calls = structured
            .as_ref()
            .map(|value| extract_tool_calls(value, response.completed_at_unix_ns))
            .unwrap_or_default();
        (structured, text, calls)
    };
    dedup_tool_calls(&mut tool_calls);
    if status_code < 400
        && !response_matches_wire_template(
            wire_match.template_id,
            response_is_sse,
            response_structured.as_ref(),
        )
    {
        wire_match = WireMatch {
            template_id: "unknown-json-exchange",
            likelihood: "unknown",
            parse_state: "unparsed",
            interaction_kind: WireInteractionKind::Unparsed,
        };
        tool_calls.clear();
    }
    let structured_output_final = request_json
        .as_ref()
        .and_then(|request| forced_structured_output(request, &tool_calls))
        .map(|(is_final, text)| {
            response_text = Some(text);
            tool_calls.clear();
            is_final
        });
    let tool_route = wire_match.interaction_kind == WireInteractionKind::Tool;

    let mut messages = request_json
        .as_ref()
        .map(extract_request_messages)
        .unwrap_or_default();
    if structured_output_final.is_some() && request.header("x-anysentry-run-id").is_some() {
        for message in &mut messages {
            if framework_orchestration_prompt(&message.content) {
                message.message_origin = Some("agent_context".to_string());
            }
        }
    }
    let mut tool_results = request_json
        .as_ref()
        .map(|value| extract_tool_results(value, request.completed_at_unix_ns))
        .unwrap_or_default();
    dedup_tool_results(&mut tool_results);

    let model = request_json
        .as_ref()
        .and_then(|value| value.get("model"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            response_structured
                .as_ref()
                .and_then(|value| value.get("model"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    let provider_conversation_id = request_json
        .as_ref()
        .and_then(extract_provider_conversation_id)
        .or_else(|| {
            response_structured
                .as_ref()
                .and_then(extract_provider_conversation_id)
        });
    let provider_response_id = response_structured
        .as_ref()
        .and_then(extract_provider_response_id);
    let provider_previous_response_id = request_json
        .as_ref()
        .and_then(|value| bounded_provider_id(value.get("previous_response_id")));
    // Retain only explicit correlation headers. Authorization, cookies and every other HTTP
    // header remain outside the exported plaintext-content contract.
    let trace_id = trace_id_from_traceparent(&request);
    let run_id = bounded_correlation_header(&request, "x-anysentry-run-id");
    let session_id = bounded_correlation_header(&request, "x-anysentry-session-id");
    let invocation_id = bounded_correlation_header(&request, "x-anysentry-invocation-id")
        .or_else(|| run_id.clone());
    let request_schema_fingerprint = request_json.as_ref().map(schema_fingerprint);
    let usage = response_structured
        .as_ref()
        .and_then(extract_provider_token_usage);

    let request_decode_complete = request_decode_reason.is_none();
    let response_decode_complete =
        response_decode_reason.is_none() && response_parse_reason.is_none();
    let request_decode_ok = request_decode_reason.is_none();
    let response_decode_ok = response_decode_reason.is_none();
    let response_parse_ok = response_parse_reason.is_none();
    let mut partial_reasons = request.partial_reasons.clone();
    extend_unique(&mut partial_reasons, response.partial_reasons.clone());
    if let Some(reason) = request_decode_reason {
        extend_unique(&mut partial_reasons, [reason]);
    }
    if let Some(reason) = response_decode_reason {
        extend_unique(&mut partial_reasons, [reason]);
    }
    if let Some(reason) = response_parse_reason {
        extend_unique(&mut partial_reasons, [reason]);
    }
    if wire_match.parse_state != "parsed" {
        extend_unique(
            &mut partial_reasons,
            [format!("wire_template_{}", wire_match.parse_state)],
        );
    }
    let transport_completeness = if request.partial_reasons.is_empty()
        && response.partial_reasons.is_empty()
        && request_decode_complete
        && response_decode_complete
    {
        "complete"
    } else {
        "partial"
    };
    let wire_completeness = wire_completeness(
        wire_match,
        status_code,
        response_is_sse,
        &response_parse_body,
        response_structured.as_ref(),
        response_sse_event_limit,
    );
    if wire_completeness != "complete" && wire_completeness != "error" {
        extend_unique(&mut partial_reasons, [format!("wire_{wire_completeness}")]);
    }
    if response_sse_event_limit {
        extend_unique(&mut partial_reasons, ["sse_event_limit".to_string()]);
    }
    let has_pending_tool_result = has_unmatched_tool_calls(&tool_calls, &tool_results);
    let conversation_completeness = if has_pending_tool_result {
        extend_unique(&mut partial_reasons, ["tool_result_pending".to_string()]);
        "tool_pending"
    } else if wire_completeness == "complete" || wire_completeness == "error" {
        "complete"
    } else {
        "partial"
    };
    let completeness = if transport_completeness == "complete"
        && wire_completeness == "complete"
        && conversation_completeness == "complete"
    {
        "complete"
    } else {
        "partial"
    }
    .to_string();

    let request_content = make_content(
        &request_body,
        request.captured_body_bytes,
        request.content_type(),
        request_json,
        messages,
        None,
        if request.partial_reasons.is_empty() && request_decode_ok {
            "complete"
        } else {
            "partial"
        },
    );
    let response_content = make_content(
        &response_body,
        response.captured_body_bytes,
        response.content_type(),
        response_structured,
        Vec::new(),
        response_text,
        if response.partial_reasons.is_empty()
            && response_decode_ok
            && response_parse_ok
            && !response_sse_event_limit
        {
            "complete"
        } else {
            "partial"
        },
    );

    let interaction_id = interaction_id(
        key,
        sequence,
        request.started_at_unix_ns,
        &path,
        &request_content.sha256,
    );
    if tool_route {
        let rpc_request = request_content.structured.as_ref();
        let rpc_response = response_content.structured.as_ref();
        let (tool_call_id, name, arguments, result, response_error) =
            if wire_match.template_id == "generic-http-tool" {
                let tool_call_id = rpc_response
                    .and_then(|value| value.get("tool_call_id"))
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .or_else(|| {
                        rpc_response
                            .and_then(|value| value.get("execution_id"))
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                    })
                    .or_else(|| {
                        rpc_request
                            .and_then(|value| value.get("id"))
                            .map(json_scalar_id)
                            .filter(|value| !value.is_empty())
                    })
                    .unwrap_or_else(|| format!("transport:{interaction_id}"));
                let name = rpc_request
                    .and_then(|value| value.get("name").or_else(|| value.get("tool")))
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| {
                        if rpc_request.is_some_and(|value| value.get("code").is_some()) {
                            "http.code.execute"
                        } else {
                            "http.request"
                        }
                    })
                    .to_string();
                let arguments = rpc_request.cloned().unwrap_or(Value::Null);
                let result = rpc_response
                    .and_then(|value| {
                        value
                            .get("result")
                            .or_else(|| value.get("output"))
                            .or_else(|| value.get("error"))
                    })
                    .cloned()
                    .or_else(|| rpc_response.cloned())
                    .unwrap_or(Value::Null);
                let response_error = rpc_response.is_some_and(|value| {
                    value.get("error").is_some()
                        || value
                            .get("exit_code")
                            .and_then(Value::as_i64)
                            .is_some_and(|code| code != 0)
                        || value.get("timed_out").and_then(Value::as_bool) == Some(true)
                        || matches!(
                            value.get("status").and_then(Value::as_str),
                            Some("failed" | "error")
                        )
                });
                (tool_call_id, name, arguments, result, response_error)
            } else {
                let tool_call_id = rpc_request
                    .and_then(|value| value.get("id"))
                    .map(json_scalar_id)
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| format!("transport:{interaction_id}"));
                let name = rpc_request
                    .and_then(|value| value.get("params"))
                    .and_then(|params| params.get("name"))
                    .and_then(Value::as_str)
                    .or_else(|| {
                        rpc_request
                            .and_then(|value| value.get("method"))
                            .and_then(Value::as_str)
                    })
                    .unwrap_or("mcp.tools.call")
                    .to_string();
                let arguments = rpc_request
                    .and_then(|value| value.get("params"))
                    .and_then(|params| params.get("arguments").or(Some(params)))
                    .cloned()
                    .unwrap_or(Value::Null);
                let result = rpc_response
                    .and_then(|value| value.get("result").or_else(|| value.get("error")))
                    .cloned()
                    .unwrap_or(Value::Null);
                let response_error = rpc_response.is_some_and(|value| value.get("error").is_some());
                (tool_call_id, name, arguments, result, response_error)
            };
        tool_calls = vec![LlmInteractionToolCall {
            tool_call_id: tool_call_id.clone(),
            name: name.clone(),
            arguments,
            issued_at_unix_ns: Some(request.completed_at_unix_ns.to_string()),
        }];
        tool_results = vec![LlmInteractionToolResult {
            tool_call_id,
            name: Some(name),
            content: result,
            is_error: status_code >= 400 || response_error,
            observed_at_unix_ns: Some(response.completed_at_unix_ns.to_string()),
        }];
    }
    let traffic_role = if run_id.is_some() && structured_output_final.is_some() {
        "conversation"
    } else {
        classify_traffic_role(
            wire_match.interaction_kind,
            wire_match.template_id,
            request_content.structured.as_ref(),
            &request_content.messages,
            &tool_results,
        )
    }
    .to_string();
    let conversation_anchors = extract_conversation_anchors(
        request_content.structured.as_ref(),
        provider_conversation_id.as_deref(),
        provider_response_id.as_deref(),
        provider_previous_response_id.as_deref(),
        &request_content.messages,
        &tool_calls,
        &tool_results,
    );
    let duration = response
        .completed_at_unix_ns
        .saturating_sub(request.started_at_unix_ns);
    let semantic_items = build_semantic_items(
        &interaction_id,
        &request_content.messages,
        response_content.text.as_deref(),
        &tool_calls,
        &tool_results,
        structured_output_final,
        [
            request.started_at_unix_ns,
            response.started_at_unix_ns,
            response.completed_at_unix_ns,
        ],
    );

    Some(CompletedInteraction {
        schema_version: "anysentry.agent_interaction.v1".to_string(),
        interaction_id,
        interaction_type: match wire_match.interaction_kind {
            WireInteractionKind::Model => "model",
            WireInteractionKind::Tool => "tool",
            WireInteractionKind::Unparsed => "unparsed",
        }
        .to_string(),
        cgroup_id: key.cgroup_id,
        pid: key.pid,
        connection_id: format!("tls:{:x}", key.connection_id),
        transport: if source.contains("tcp") {
            "http"
        } else {
            "tls"
        }
        .to_string(),
        protocol: match request.transport_protocol.as_deref() {
            Some("websocket") => "websocket-json",
            Some("json-body") => "http/1.1-body-inferred",
            Some("http/2") => "http/2",
            _ if request.metadata_inferred => "application-body-inferred",
            _ => "http/1.1",
        }
        .to_string(),
        tls_adapter_id: adapter_id.to_string(),
        transport_protocol: request
            .transport_protocol
            .clone()
            .unwrap_or_else(|| "http/1.1".to_string()),
        wire_template_id: Some(wire_match.template_id.to_string()),
        parse_state: wire_match.parse_state.to_string(),
        llm_likelihood: wire_match.likelihood.to_string(),
        schema_fingerprint: request_schema_fingerprint,
        transport_completeness: transport_completeness.to_string(),
        wire_completeness: wire_completeness.to_string(),
        conversation_completeness: conversation_completeness.to_string(),
        endpoint,
        method,
        path,
        status_code,
        model,
        provider_conversation_id,
        provider_response_id,
        provider_previous_response_id,
        traffic_role,
        trace_id,
        run_id,
        session_id,
        invocation_id,
        conversation_anchors,
        started_at_unix_ns: request.started_at_unix_ns.to_string(),
        request_complete_at_unix_ns: request.completed_at_unix_ns.to_string(),
        first_response_at_unix_ns: response.started_at_unix_ns.to_string(),
        ended_at_unix_ns: response.completed_at_unix_ns.to_string(),
        duration_ns: duration.to_string(),
        time_quality: "collector_calibrated".to_string(),
        request: request_content,
        response: response_content,
        usage,
        tool_calls,
        tool_results,
        semantic_parser_id: SEMANTIC_PARSER_ID.to_string(),
        semantic_parser_version: SEMANTIC_PARSER_VERSION,
        semantic_items,
        completeness,
        partial_reasons,
        capture_source: source.to_string(),
        bind_quality,
        socket_fd,
        socket_cookie,
        fd_generation,
    })
}

fn build_semantic_items(
    interaction_id: &str,
    request_messages: &[LlmInteractionMessage],
    response_text: Option<&str>,
    tool_calls: &[LlmInteractionToolCall],
    tool_results: &[LlmInteractionToolResult],
    structured_output_final: Option<bool>,
    times: [u128; 3],
) -> Vec<LlmInteractionSemanticItem> {
    let [request_at_unix_ns, first_response_at_unix_ns, response_at_unix_ns] = times;
    let mut items = Vec::new();
    let mut push = |actor: &str,
                    kind: &str,
                    phase: Option<&str>,
                    origin: &str,
                    at_unix_ns: String,
                    content: Option<Value>,
                    tool_call_id: Option<String>,
                    tool_name: Option<String>,
                    source_item_id: Option<String>,
                    turn_id: Option<String>,
                    content_item_kinds: Vec<String>,
                    message_origin: Option<String>| {
        let sequence_number = items.len() as u64;
        let semantic_item_id = semantic_item_id(interaction_id, kind, sequence_number);
        items.push(LlmInteractionSemanticItem {
            semantic_item_id,
            actor: actor.to_string(),
            kind: kind.to_string(),
            phase: phase.map(ToOwned::to_owned),
            origin: origin.to_string(),
            at_unix_ns,
            content,
            tool_call_id,
            tool_name,
            source_item_id,
            turn_id,
            content_item_kinds,
            message_origin,
            output_index: None,
            content_index: None,
            sequence_number: Some(sequence_number),
            completeness: "complete".to_string(),
            partial_reasons: Vec::new(),
        });
    };

    for (index, message) in request_messages.iter().enumerate() {
        if !matches!(message.role.to_ascii_lowercase().as_str(), "user" | "human") {
            continue;
        }
        if message.message_origin.as_deref() == Some("agent_context") {
            continue;
        }
        let Some(content) = semantic_user_content(&message.content) else {
            continue;
        };
        push(
            "user",
            "user_message",
            Some("final"),
            "request",
            request_at_unix_ns.to_string(),
            Some(content),
            None,
            None,
            message
                .source_item_id
                .clone()
                .or_else(|| Some(format!("request.messages[{index}]"))),
            message.turn_id.clone(),
            message.content_item_kinds.clone(),
            message.message_origin.clone(),
        );
    }

    for result in tool_results {
        push(
            "tool",
            "tool_result",
            Some("final"),
            "request",
            result
                .observed_at_unix_ns
                .clone()
                .unwrap_or_else(|| request_at_unix_ns.to_string()),
            Some(result.content.clone()),
            Some(result.tool_call_id.clone()),
            result.name.clone(),
            Some(result.tool_call_id.clone()),
            None,
            Vec::new(),
            Some("tool_history".to_string()),
        );
    }

    if let Some(text) = response_text.filter(|text| !text.trim().is_empty()) {
        let model_final = structured_output_final.unwrap_or(tool_calls.is_empty());
        push(
            "model",
            if model_final {
                "model_final"
            } else {
                "model_progress"
            },
            Some(if model_final { "final" } else { "progress" }),
            "response",
            first_response_at_unix_ns.to_string(),
            Some(Value::String(text.to_string())),
            None,
            None,
            None,
            None,
            Vec::new(),
            None,
        );
    }

    for call in tool_calls {
        push(
            "tool",
            "tool_call",
            Some("final"),
            "response",
            call.issued_at_unix_ns
                .clone()
                .unwrap_or_else(|| response_at_unix_ns.to_string()),
            Some(call.arguments.clone()),
            Some(call.tool_call_id.clone()),
            Some(call.name.clone()),
            Some(call.tool_call_id.clone()),
            None,
            Vec::new(),
            None,
        );
    }

    items
}

fn semantic_user_content(content: &Value) -> Option<Value> {
    match content {
        Value::Array(parts) => {
            let visible = parts
                .iter()
                .filter(|part| {
                    part.get("type").and_then(Value::as_str) != Some("tool_result")
                        && !agent_runtime_context_part(part)
                })
                .cloned()
                .collect::<Vec<_>>();
            (!visible.is_empty()).then_some(Value::Array(visible))
        }
        Value::Null => None,
        value if agent_runtime_context_part(value) => None,
        value => Some(value.clone()),
    }
}

fn agent_runtime_context_part(value: &Value) -> bool {
    let text = value
        .as_str()
        .or_else(|| value.get("text").and_then(Value::as_str))
        .map(str::trim);
    text.is_some_and(|text| {
        ["environment_context", "system-reminder"]
            .iter()
            .any(|tag| {
                text.starts_with(&format!("<{tag}>")) && text.ends_with(&format!("</{tag}>"))
            })
    })
}

fn semantic_item_id(interaction_id: &str, kind: &str, sequence_number: u64) -> String {
    let mut hash = Sha256::new();
    hash.update(interaction_id.as_bytes());
    hash.update([0]);
    hash.update(kind.as_bytes());
    hash.update([0]);
    hash.update(sequence_number.to_ne_bytes());
    format!("si_{}", hex_prefix(&hash.finalize(), 24))
}

fn make_content(
    body: &[u8],
    captured_body_bytes: usize,
    content_type: &str,
    structured: Option<Value>,
    messages: Vec<LlmInteractionMessage>,
    text: Option<String>,
    completeness: &str,
) -> LlmInteractionContent {
    let (encoded, encoding) = match std::str::from_utf8(body) {
        Ok(text) => (text.to_string(), "utf8".to_string()),
        Err(_) => (
            base64::engine::general_purpose::STANDARD.encode(body),
            "base64".to_string(),
        ),
    };
    // `body` is the canonical transport evidence. Parsed JSON, normalized messages, and response
    // text duplicate portions of it, so exporting all of them for an inline multimodal payload
    // can more than double one event and push it beyond the bounded Forwarder seam. Preserve the
    // complete raw body/hash up to the stream limit, while retaining derived convenience fields
    // only for reasonably sized payloads.
    let export_derived = body.len() <= MAX_EXPORTED_STRUCTURED_BYTES;
    LlmInteractionContent {
        body: encoded,
        encoding,
        content_type: content_type.to_string(),
        captured_bytes: captured_body_bytes as u64,
        decoded_bytes: body.len() as u64,
        sha256: sha256_hex(body),
        completeness: completeness.to_string(),
        messages: if export_derived { messages } else { Vec::new() },
        text: text.filter(|value| value.len() <= MAX_EXPORTED_STRUCTURED_BYTES),
        structured: export_derived.then_some(structured).flatten(),
    }
}


const HTTP2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HTTP2_FRAME_HEADER_LEN: usize = 9;
const HTTP2_FRAME_DATA: u8 = 0x0;
const HTTP2_FRAME_HEADERS: u8 = 0x1;
const HTTP2_FLAG_END_STREAM: u8 = 0x1;
const HTTP2_FLAG_END_HEADERS: u8 = 0x4;
const HTTP2_FLAG_PADDED: u8 = 0x8;
const HTTP2_FLAG_PRIORITY: u8 = 0x20;
const MAX_HTTP2_LEFTOVER_BYTES: usize = 256 * 1024;
const MAX_HTTP2_STREAMS: usize = 64;

fn looks_like_http2_frame_prefix(data: &[u8]) -> bool {
    if data.len() < HTTP2_FRAME_HEADER_LEN {
        return false;
    }
    if data.starts_with(b"PRI ")
        || data.starts_with(b"HTTP/")
        || looks_like_http_request_prefix(data)
        || data.starts_with(b"{")
        || data.starts_with(b"[")
        || data.starts_with(b"data:")
        || data.starts_with(b"event:")
    {
        return false;
    }
    let length = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);
    let frame_type = data[3];
    let flags = data[4];
    let stream_id = u32::from_be_bytes([data[5] & 0x7f, data[6], data[7], data[8]]);
    if frame_type > 0x9 || length > MAX_HTTP2_LEFTOVER_BYTES {
        return false;
    }
    match frame_type {
        0x4 => stream_id == 0 && length % 6 == 0 && (flags & !0x1) == 0,
        0x8 => length == 4,
        0x6 => stream_id == 0 && length == 8,
        0x0 => stream_id != 0 && length > 0,
        0x1 => stream_id != 0 && length > 0,
        _ => false,
    }
}

fn http2_strip_frame_payload(payload: &[u8], flags: u8) -> Option<&[u8]> {
    let mut offset = 0usize;
    let mut end = payload.len();
    if flags & HTTP2_FLAG_PADDED != 0 {
        let pad = *payload.first()? as usize;
        offset = 1;
        if pad >= payload.len().saturating_sub(offset) {
            return None;
        }
        end = payload.len().saturating_sub(pad);
    }
    if flags & HTTP2_FLAG_PRIORITY != 0 {
        if payload.len().saturating_sub(offset) < 5 {
            return None;
        }
        offset += 5;
    }
    if offset > end {
        return None;
    }
    Some(&payload[offset..end])
}

fn http2_apply_headers(stream: &mut Http2StreamState, block: Http2HeaderBlock) {
    if block.method.is_some() {
        stream.headers.method = block.method;
    }
    if block.path.is_some() {
        stream.headers.path = block.path;
    }
    if block.status.is_some() {
        stream.headers.status = block.status;
    }
    if block.content_type.is_some() {
        stream.headers.content_type = block.content_type;
    }
    if block.authority.is_some() {
        stream.headers.authority = block.authority;
    }
    if block.host.is_some() {
        stream.headers.host = block.host;
    }
}

fn http2_message_from_stream(
    stream: &Http2StreamState,
    direction: ChunkDirection,
    at_start: u128,
    at_end: u128,
    reasons: &[String],
) -> HttpMessage {
    let mut headers = BTreeMap::new();
    if let Some(content_type) = stream.headers.content_type.clone() {
        headers.insert("content-type".to_string(), content_type);
    }
    let host = stream
        .headers
        .host
        .clone()
        .or_else(|| stream.headers.authority.clone())
        .unwrap_or_else(|| "unknown".to_string());
    headers.insert("host".to_string(), host);
    let start_line = match direction {
        ChunkDirection::Request => {
            let method = stream.headers.method.as_deref().unwrap_or("POST");
            let path = stream.headers.path.as_deref().unwrap_or("/");
            format!("{method} {path} HTTP/2.0")
        }
        ChunkDirection::Response => {
            let status = stream.headers.status.as_deref().unwrap_or("200");
            format!("HTTP/2.0 {status}")
        }
    };
    let mut partial_reasons = reasons.to_vec();
    if stream.headers.method.is_none() && matches!(direction, ChunkDirection::Request) {
        extend_unique(&mut partial_reasons, ["http2_headers_method_missing".to_string()]);
    }
    if stream.headers.path.is_none() && matches!(direction, ChunkDirection::Request) {
        extend_unique(&mut partial_reasons, ["http2_headers_path_missing".to_string()]);
    }
    HttpMessage {
        start_line,
        headers,
        captured_body_bytes: stream.body.len(),
        body: stream.body.clone(),
        started_at_unix_ns: stream.body_started_at_unix_ns.unwrap_or(at_start),
        completed_at_unix_ns: at_end,
        partial_reasons,
        metadata_inferred: stream.headers.method.is_none() || stream.headers.path.is_none(),
        transport_protocol: Some("http/2".to_string()),
        derived_body: None,
    }
}

fn process_http2_chunk(
    key: ConnectionKey,
    state: &mut ConnectionState,
    chunk: &PlaintextChunk,
    max_body_bytes: usize,
) -> (Vec<CompletedInteraction>, Vec<String>) {
    let mut gap_reasons = Vec::new();
    let mut completed = Vec::new();
    let mut buffer = std::mem::take(&mut state.http2.leftover);
    buffer.extend_from_slice(&chunk.data);

    if !state.http2.active {
        if buffer.starts_with(HTTP2_CLIENT_PREFACE) {
            state.http2.active = true;
            buffer.drain(..HTTP2_CLIENT_PREFACE.len());
        } else if HTTP2_CLIENT_PREFACE.starts_with(buffer.as_slice()) {
            state.http2.leftover = buffer;
            return (completed, gap_reasons);
        } else if buffer.starts_with(b"PRI * HTTP/2.0") {
            extend_unique(&mut gap_reasons, ["http2_preface_invalid".to_string()]);
            state.http2.leftover.clear();
            return (completed, gap_reasons);
        } else if looks_like_http2_frame_prefix(&buffer) {
            state.http2.active = true;
            extend_unique(&mut gap_reasons, ["http2_frames_without_preface".to_string()]);
        } else {
            state.http2.active = true;
        }
    }

    while buffer.len() >= HTTP2_FRAME_HEADER_LEN {
        let length = ((buffer[0] as usize) << 16)
            | ((buffer[1] as usize) << 8)
            | (buffer[2] as usize);
        let frame_end = HTTP2_FRAME_HEADER_LEN.saturating_add(length);
        if buffer.len() < frame_end {
            break;
        }
        if length > max_body_bytes {
            extend_unique(&mut gap_reasons, ["http2_frame_limit".to_string()]);
            buffer.drain(..frame_end);
            continue;
        }
        let frame_type = buffer[3];
        let flags = buffer[4];
        let stream_id = u32::from_be_bytes([
            buffer[5] & 0x7f,
            buffer[6],
            buffer[7],
            buffer[8],
        ]);
        let payload = buffer[HTTP2_FRAME_HEADER_LEN..frame_end].to_vec();
        buffer.drain(..frame_end);

        if stream_id == 0 {
            continue;
        }
        if state.http2.streams.len() >= MAX_HTTP2_STREAMS
            && !state.http2.streams.contains_key(&stream_id)
        {
            extend_unique(&mut gap_reasons, ["http2_stream_limit".to_string()]);
            continue;
        }
        if frame_type == HTTP2_FRAME_HEADERS {
            let Some(block_bytes) = http2_strip_frame_payload(&payload, flags) else {
                extend_unique(&mut gap_reasons, ["http2_headers_padding_invalid".to_string()]);
                continue;
            };
            let decoded = match chunk.direction {
                ChunkDirection::Request => state.http2.request_hpack.decode_block(block_bytes),
                ChunkDirection::Response => state.http2.response_hpack.decode_block(block_bytes),
            };
            let stream = state.http2.streams.entry(stream_id).or_default();
            match decoded {
                Ok(block) => {
                    http2_apply_headers(stream, block);
                    if flags & HTTP2_FLAG_END_HEADERS != 0 {
                        stream.headers_complete = true;
                    }
                }
                Err(()) => {
                    extend_unique(&mut gap_reasons, ["h2_hpack_desync".to_string()]);
                }
            }
            if flags & HTTP2_FLAG_END_STREAM != 0 {
                stream.end_stream = true;
            }
        } else if frame_type == HTTP2_FRAME_DATA {
            let Some(data_payload) = http2_strip_frame_payload(&payload, flags) else {
                extend_unique(&mut gap_reasons, ["http2_data_padding_invalid".to_string()]);
                continue;
            };
            let stream = state.http2.streams.entry(stream_id).or_default();
            if stream.body_started_at_unix_ns.is_none() {
                stream.body_started_at_unix_ns = Some(chunk.event_at_unix_ns);
            }
            let remaining = max_body_bytes.saturating_sub(stream.body.len());
            let admitted = data_payload.len().min(remaining);
            stream.body.extend_from_slice(&data_payload[..admitted]);
            if admitted < data_payload.len() {
                extend_unique(&mut gap_reasons, ["http2_body_limit".to_string()]);
            }
            if flags & HTTP2_FLAG_END_STREAM != 0 {
                stream.end_stream = true;
            }
        } else {
            continue;
        }

        let end_stream = state
            .http2
            .streams
            .get(&stream_id)
            .is_some_and(|stream| stream.end_stream);
        if !end_stream {
            continue;
        }
        let finished = state.http2.streams.remove(&stream_id).unwrap_or_default();
        let mut effective_reasons = chunk.partial_reasons.clone();
        extend_unique(&mut effective_reasons, state.binding_reasons.clone());
        extend_unique(&mut effective_reasons, gap_reasons.iter().cloned());
        match chunk.direction {
            ChunkDirection::Request => {
                let mut request = http2_message_from_stream(
                    &finished,
                    ChunkDirection::Request,
                    chunk.event_at_unix_ns,
                    chunk.event_at_unix_ns,
                    &effective_reasons,
                );
                // After HPACK desync, keep the DATA body-only lane: infer route from JSON body.
                if request.metadata_inferred {
                    if let Some(inferred) = body_only_llm_request(
                        &finished.body,
                        chunk.event_at_unix_ns,
                        &effective_reasons,
                    ) {
                        request.start_line = inferred.start_line;
                        for (name, value) in inferred.headers {
                            request.headers.entry(name).or_insert(value);
                        }
                        request.transport_protocol = Some("http/2".to_string());
                    }
                }
                state.identity.observe_http(&request, ChunkDirection::Request);
                add_binding_reasons(state, &mut request.partial_reasons);
                if !state.push_pending_request(request) {
                    extend_unique(&mut gap_reasons, ["pending_request_limit".to_string()]);
                }
            }
            ChunkDirection::Response => {
                let Some(mut request) = state.pop_pending_request() else {
                    extend_unique(&mut gap_reasons, ["orphan_http2_data_response".to_string()]);
                    continue;
                };
                let mut response = http2_message_from_stream(
                    &finished,
                    ChunkDirection::Response,
                    chunk.event_at_unix_ns,
                    chunk.event_at_unix_ns,
                    &effective_reasons,
                );
                if response.headers.get("content-type").is_none() {
                    if looks_like_sse(&finished.body) {
                        response.headers.insert(
                            "content-type".to_string(),
                            "text/event-stream".to_string(),
                        );
                    } else if finished
                        .body
                        .iter()
                        .find(|b| !b.is_ascii_whitespace())
                        .is_some_and(|b| matches!(*b, b'{' | b'['))
                    {
                        response.headers.insert(
                            "content-type".to_string(),
                            "application/json".to_string(),
                        );
                    }
                }
                state.identity.observe_http(&response, ChunkDirection::Response);
                add_binding_reasons(state, &mut request.partial_reasons);
                add_binding_reasons(state, &mut response.partial_reasons);
                state.sequence = state.sequence.wrapping_add(1);
                if let Some(interaction) = build_interaction(
                    key,
                    state.sequence,
                    &state.source,
                    &state.adapter_id,
                    request,
                    response,
                    state.bind_quality,
                    state.socket_fd,
                    state.socket_cookie,
                    state.fd_generation,
                ) {
                    completed.push(interaction);
                }
            }
        }
    }

    if buffer.len() > MAX_HTTP2_LEFTOVER_BYTES {
        extend_unique(&mut gap_reasons, ["http2_leftover_limit".to_string()]);
        buffer.clear();
    }
    state.http2.leftover = buffer;
    (completed, gap_reasons)
}


fn decode_http_message(
    kind: StreamKind,
    bytes: &[u8],
    max_body_bytes: usize,
    sse_scan: &mut SseTerminalScanState,
    chunked_scan: &mut SseTerminalScanState,
) -> Result<Option<DecodedHttpMessage>, String> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.starts_with(b"PRI * HTTP/2.0") {
        return Err("unsupported_http2".to_string());
    }

    let mut headers_storage = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let (header_len, start_line, headers, status_code) = match kind {
        StreamKind::Request => {
            let mut request = httparse::Request::new(&mut headers_storage);
            let status = request
                .parse(bytes)
                .map_err(|_| "http_request_parse_error".to_string())?;
            let httparse::Status::Complete(header_len) = status else {
                return Ok(None);
            };
            let method = request.method.unwrap_or_default();
            let path = request.path.unwrap_or_default();
            let version = request.version.unwrap_or(1);
            (
                header_len,
                format!("{method} {path} HTTP/1.{version}"),
                owned_headers(request.headers),
                None,
            )
        }
        StreamKind::Response => {
            let mut response = httparse::Response::new(&mut headers_storage);
            let status = response
                .parse(bytes)
                .map_err(|_| "http_response_parse_error".to_string())?;
            let httparse::Status::Complete(header_len) = status else {
                return Ok(None);
            };
            let code = response.code.unwrap_or_default();
            let version = response.version.unwrap_or(1);
            (
                header_len,
                format!("HTTP/1.{version} {code}"),
                owned_headers(response.headers),
                Some(code),
            )
        }
    };

    let body_bytes = &bytes[header_len..];
    let transfer_encoding = headers
        .get("transfer-encoding")
        .map(String::as_str)
        .unwrap_or_default();
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.trim().parse::<usize>().ok());
    let content_type = headers
        .get("content-type")
        .map(String::as_str)
        .unwrap_or_default();
    let sse_response = matches!(kind, StreamKind::Response)
        && content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"));

    let mut partial_reasons = Vec::new();
    let (body, body_consumed) = if transfer_encoding
        .split(',')
        .any(|value| value.trim().eq_ignore_ascii_case("chunked"))
    {
        let Some((decoded, consumed)) =
            decode_chunked(body_bytes, max_body_bytes, sse_response, chunked_scan)?
        else {
            return Ok(None);
        };
        (decoded, consumed)
    } else if let Some(length) = content_length {
        if length > max_body_bytes {
            return Err("declared_body_limit".to_string());
        }
        if body_bytes.len() < length {
            return Ok(None);
        }
        (body_bytes[..length].to_vec(), length)
    } else if matches!(kind, StreamKind::Request)
        || status_code.is_some_and(|code| (100..200).contains(&code) || code == 204 || code == 304)
    {
        (Vec::new(), 0)
    } else if content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
        || looks_like_sse(body_bytes)
    {
        // With Content-Encoding the wire bytes are compressed, so looking for an SSE delimiter
        // directly in `body_bytes` can never prove completion. Decode only into a bounded
        // temporary framing view; the returned message still retains the exact compressed bytes
        // as its canonical body/hash. An incomplete compressed stream simply remains pending.
        let (framing_body, framing_reason) = decode_content_encoding(
            body_bytes,
            headers
                .get("content-encoding")
                .map(String::as_str)
                .unwrap_or_default(),
            max_body_bytes,
        );
        if framing_reason.is_some() {
            return Ok(None);
        }
        let Some(_end) = sse_terminal_offset_incremental(framing_body.as_ref(), sse_scan) else {
            return Ok(None);
        };
        // No explicit HTTP framing is available here. Once the decoded stream has a terminal
        // event, all currently observed compressed bytes belong to this response; consume the
        // raw body while keeping the decoded view for the later parser stage.
        (body_bytes.to_vec(), body_bytes.len())
    } else {
        // HTTP/1.x response bodies without framing end on connection close. A TLS fragment cannot
        // prove that boundary, so wait for a close/timeout-aware path instead of guessing.
        return Ok(None);
    };

    if body.len() >= max_body_bytes {
        extend_unique(&mut partial_reasons, ["reassembly_body_limit".to_string()]);
    }

    Ok(Some(DecodedHttpMessage {
        consumed: header_len + body_consumed,
        start_line,
        headers,
        captured_body_bytes: body.len(),
        body,
        partial_reasons,
    }))
}

fn owned_headers(headers: &[httparse::Header<'_>]) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|header| {
            let name = header.name.trim().to_ascii_lowercase();
            if name.is_empty() || is_secret_header(&name) {
                return None;
            }
            let value = std::str::from_utf8(header.value).ok()?.trim().to_string();
            Some((name, value))
        })
        .collect()
}

fn is_secret_header(name: &str) -> bool {
    matches!(
        name,
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key" | "api-key"
    )
}

fn detached_chunk_terminator_prefix(bytes: &[u8]) -> usize {
    let mut consumed = 0usize;
    while bytes
        .get(consumed..)
        .is_some_and(|remaining| remaining.starts_with(b"0\r\n\r\n"))
    {
        consumed += 5;
    }
    consumed
}

fn decode_chunked(
    bytes: &[u8],
    max_body_bytes: usize,
    stop_at_sse_terminal: bool,
    sse_scan: &mut SseTerminalScanState,
) -> Result<Option<(Vec<u8>, usize)>, String> {
    let mut cursor = 0usize;
    let mut body = Vec::new();
    loop {
        let Some(line_end) = find_bytes(&bytes[cursor..], b"\r\n") else {
            return Ok(None);
        };
        let line_end = cursor + line_end;
        let size_line = std::str::from_utf8(&bytes[cursor..line_end])
            .map_err(|_| "chunk_size_utf8".to_string())?;
        let size_text = size_line.split(';').next().unwrap_or_default().trim();
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| "chunk_size_invalid".to_string())?;
        cursor = line_end + 2;
        if size == 0 {
            // The zero chunk is followed by either an empty trailer line or trailer headers.
            if bytes.get(cursor..cursor + 2) == Some(b"\r\n") {
                return Ok(Some((body, cursor + 2)));
            }
            let Some(trailer_end) = find_bytes(&bytes[cursor..], b"\r\n\r\n") else {
                return Ok(None);
            };
            return Ok(Some((body, cursor + trailer_end + 4)));
        }
        if body.len().saturating_add(size) > max_body_bytes {
            return Err("chunked_body_limit".to_string());
        }
        let Some(chunk_end) = cursor.checked_add(size) else {
            return Err("chunk_size_overflow".to_string());
        };
        if bytes.len() < chunk_end + 2 {
            return Ok(None);
        }
        if bytes.get(chunk_end..chunk_end + 2) != Some(b"\r\n") {
            return Err("chunk_terminator_invalid".to_string());
        }
        body.extend_from_slice(&bytes[cursor..chunk_end]);
        cursor = chunk_end + 2;
        if stop_at_sse_terminal {
            // The de-chunked `body` grows chunk by chunk and is rebuilt per attempt from the
            // same input prefix, so the incremental cursors stay valid across attempts.
            if let Some(terminal) = sse_terminal_offset_incremental(&body, sse_scan) {
                body.truncate(terminal);
                return Ok(Some((body, cursor)));
            }
        }
    }
}

fn decode_content_encoding<'a>(
    bytes: &'a [u8],
    encoding: &str,
    max_output_bytes: usize,
) -> (std::borrow::Cow<'a, [u8]>, Option<String>) {
    let normalized = encoding.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized == "identity" {
        // Borrow instead of copying: identity is the common case and this runs on every
        // reassembly attempt against the whole accumulated body.
        return (std::borrow::Cow::Borrowed(bytes), None);
    }
    let decoder: Box<dyn Read> = match normalized.as_str() {
        "gzip" | "x-gzip" => Box::new(GzDecoder::new(bytes)),
        "deflate" => Box::new(ZlibDecoder::new(bytes)),
        "raw-deflate" => Box::new(DeflateDecoder::new(bytes)),
        _ => {
            return (
                std::borrow::Cow::Borrowed(bytes),
                Some(format!("unsupported_content_encoding:{normalized}")),
            )
        }
    };
    let mut output = Vec::new();
    let mut bounded = decoder.take(max_output_bytes as u64 + 1);
    match bounded.read_to_end(&mut output) {
        Ok(_) if output.len() <= max_output_bytes => (std::borrow::Cow::Owned(output), None),
        Ok(_) => {
            output.truncate(max_output_bytes);
            (
                std::borrow::Cow::Owned(output),
                Some("decompressed_body_limit".to_string()),
            )
        }
        Err(_) => (
            std::borrow::Cow::Borrowed(bytes),
            Some("content_decode_error".to_string()),
        ),
    }
}

fn request_line(start_line: &str) -> Option<(String, String)> {
    let mut parts = start_line.split_whitespace();
    Some((parts.next()?.to_string(), parts.next()?.to_string()))
}

fn response_status(start_line: &str) -> Option<u16> {
    start_line.split_whitespace().nth(1)?.parse().ok()
}

fn bounded_correlation_header(message: &HttpMessage, name: &str) -> Option<String> {
    let value = message.header(name)?.trim();
    (!value.is_empty() && value.len() <= 512 && !value.bytes().any(|byte| byte.is_ascii_control()))
        .then(|| value.to_string())
}

fn trace_id_from_traceparent(message: &HttpMessage) -> Option<String> {
    let traceparent = bounded_correlation_header(message, "traceparent")?;
    let mut fields = traceparent.split('-');
    let version = fields.next()?;
    let trace_id = fields.next()?;
    let parent_id = fields.next()?;
    let flags = fields.next()?;
    if fields.next().is_some()
        || version.len() != 2
        || trace_id.len() != 32
        || parent_id.len() != 16
        || flags.len() != 2
        || trace_id.bytes().all(|byte| byte == b'0')
        || parent_id.bytes().all(|byte| byte == b'0')
        || !trace_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !parent_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some(trace_id.to_ascii_lowercase())
}

fn match_wire_protocol(
    method: &str,
    headers: &BTreeMap<String, String>,
    body: Option<&Value>,
) -> Option<WireMatch> {
    if !matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH"
    ) {
        return None;
    }
    let value = body?;
    let object = value.as_object()?;

    if object.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && object.get("method").and_then(Value::as_str).is_some()
        && object.get("id").is_some()
    {
        return Some(WireMatch {
            template_id: "mcp-jsonrpc",
            likelihood: "confirmed",
            parse_state: "parsed",
            interaction_kind: WireInteractionKind::Tool,
        });
    }
    if object.contains_key("instruction")
        && (object.contains_key("requested_by")
            || object.contains_key("tool")
            || object.contains_key("name"))
    {
        return Some(WireMatch {
            template_id: "generic-http-tool",
            likelihood: "likely",
            parse_state: "parsed",
            interaction_kind: WireInteractionKind::Tool,
        });
    }
    if object.get("code").and_then(Value::as_str).is_some()
        && (object.contains_key("timeout_ms")
            || object.contains_key("language")
            || object.contains_key("runtime"))
    {
        return Some(WireMatch {
            template_id: "generic-http-tool",
            likelihood: "likely",
            parse_state: "parsed",
            interaction_kind: WireInteractionKind::Tool,
        });
    }
    if object.contains_key("contents") {
        return Some(WireMatch {
            template_id: "gemini-generate-content",
            likelihood: "confirmed",
            parse_state: "parsed",
            interaction_kind: WireInteractionKind::Model,
        });
    }
    if object.get("commands").is_some_and(Value::is_array)
        && object.get("input").is_some_and(Value::is_array)
        && object.get("settings").is_some_and(Value::is_object)
        && object.get("model").and_then(Value::as_str).is_some()
        && object.get("type").is_none()
    {
        // Model-assisted search/tool backends may carry the complete conversation as input, but
        // they do not implement the Responses lifecycle. Match the reusable wire shape before the
        // broad `input + model` Responses fallback; URL, product and CLI version remain irrelevant.
        return Some(WireMatch {
            template_id: "generic-model-search-backend",
            likelihood: "confirmed",
            parse_state: "parsed",
            interaction_kind: WireInteractionKind::Model,
        });
    }
    if object.get("type").and_then(Value::as_str) == Some("response.create")
        || (object.contains_key("input")
            && (object.contains_key("model")
                || object.contains_key("tools")
                || object.contains_key("instructions")
                || object.contains_key("previous_response_id")))
    {
        return Some(WireMatch {
            template_id: "openai-responses",
            likelihood: "confirmed",
            parse_state: "parsed",
            interaction_kind: WireInteractionKind::Model,
        });
    }
    if object.contains_key("messages") {
        let anthropic_header =
            headers.contains_key("anthropic-version") || headers.contains_key("anthropic-beta");
        let anthropic_shape = object.contains_key("system")
            || has_nested_type(value, "tool_result", 0)
            || has_nested_type(value, "tool_use", 0);
        return Some(WireMatch {
            template_id: if anthropic_header || anthropic_shape {
                "anthropic-messages"
            } else if object.contains_key("model") {
                "openai-chat-completions"
            } else {
                "generic-role-message"
            },
            likelihood: "confirmed",
            parse_state: "parsed",
            interaction_kind: WireInteractionKind::Model,
        });
    }
    if object.contains_key("prompt") && object.contains_key("model") {
        return Some(WireMatch {
            template_id: "generic-prompt-completion",
            likelihood: "likely",
            parse_state: "partial",
            interaction_kind: WireInteractionKind::Model,
        });
    }
    if object.contains_key("model")
        && (object.contains_key("tools")
            || object.contains_key("stream")
            || object.contains_key("response_format"))
    {
        return Some(WireMatch {
            template_id: "unknown-json-llm",
            likelihood: "likely",
            parse_state: "unparsed",
            interaction_kind: WireInteractionKind::Unparsed,
        });
    }
    None
}

fn has_nested_type(value: &Value, expected: &str, depth: usize) -> bool {
    if depth > 6 {
        return false;
    }
    match value {
        Value::Object(object) => {
            object.get("type").and_then(Value::as_str) == Some(expected)
                || object
                    .values()
                    .any(|child| has_nested_type(child, expected, depth + 1))
        }
        Value::Array(items) => items
            .iter()
            .take(128)
            .any(|child| has_nested_type(child, expected, depth + 1)),
        _ => false,
    }
}

fn response_matches_wire_template(
    template_id: &str,
    response_is_sse: bool,
    response: Option<&Value>,
) -> bool {
    let Some(response) = response else {
        return false;
    };
    match template_id {
        "mcp-jsonrpc" => {
            response.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
                && response.get("id").is_some()
                && (response.get("result").is_some() || response.get("error").is_some())
        }
        "generic-http-tool" => {
            (response
                .get("tool_call_id")
                .and_then(Value::as_str)
                .is_some()
                && (response.get("result").is_some()
                    || response.get("output").is_some()
                    || response.get("error").is_some()))
                || (response
                    .get("execution_id")
                    .and_then(Value::as_str)
                    .is_some()
                    && response.get("exit_code").and_then(Value::as_i64).is_some()
                    && (response.get("stdout").is_some() || response.get("stderr").is_some()))
        }
        "openai-responses" => {
            json_has_key(response, "output", 0)
                || json_has_key(response, "output_text", 0)
                || (response_is_sse && has_nested_type_prefix(response, "response.", 0))
        }
        "generic-model-search-backend" => {
            response.get("results").is_some()
                && response.get("output").is_some()
                && response.get("encrypted_output").is_some()
        }
        "openai-chat-completions" => json_has_key(response, "choices", 0),
        "anthropic-messages" => {
            json_has_key(response, "content", 0)
                || (response_is_sse
                    && (has_nested_type(response, "message_start", 0)
                        || has_nested_type(response, "message_stop", 0)))
        }
        "gemini-generate-content" => json_has_key(response, "candidates", 0),
        "generic-role-message" | "generic-prompt-completion" => {
            json_has_key(response, "choices", 0)
                || json_has_key(response, "content", 0)
                || json_has_key(response, "text", 0)
                || json_has_key(response, "output", 0)
        }
        "generic-llm-json" => {
            json_has_key(response, "choices", 0)
                || json_has_key(response, "content", 0)
                || json_has_key(response, "output", 0)
                || json_has_key(response, "text", 0)
        }
        "unknown-json-llm" => true,
        _ => false,
    }
}

fn json_has_key(value: &Value, expected: &str, depth: usize) -> bool {
    if depth > 6 {
        return false;
    }
    match value {
        Value::Object(object) => {
            object.contains_key(expected)
                || object
                    .values()
                    .any(|child| json_has_key(child, expected, depth + 1))
        }
        Value::Array(items) => items
            .iter()
            .take(256)
            .any(|child| json_has_key(child, expected, depth + 1)),
        _ => false,
    }
}

fn has_nested_type_prefix(value: &Value, prefix: &str, depth: usize) -> bool {
    if depth > 6 {
        return false;
    }
    match value {
        Value::Object(object) => {
            object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.starts_with(prefix))
                || object
                    .values()
                    .any(|child| has_nested_type_prefix(child, prefix, depth + 1))
        }
        Value::Array(items) => items
            .iter()
            .take(256)
            .any(|child| has_nested_type_prefix(child, prefix, depth + 1)),
        _ => false,
    }
}

fn json_scalar_id(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        _ => String::new(),
    }
}

fn wire_completeness(
    wire_match: WireMatch,
    status_code: u16,
    response_is_sse: bool,
    response_body: &[u8],
    response_structured: Option<&Value>,
    sse_event_limit: bool,
) -> &'static str {
    if status_code >= 400 {
        return "error";
    }
    if wire_match.parse_state == "unparsed" {
        return "unknown";
    }
    if response_is_sse {
        if sse_event_limit {
            return "partial";
        }
        return if sse_terminal_offset(response_body).is_some() {
            "complete"
        } else {
            "partial"
        };
    }
    if response_structured.is_some() {
        "complete"
    } else {
        "unknown"
    }
}

fn schema_fingerprint(value: &Value) -> String {
    let mut descriptor = String::new();
    append_schema_descriptor(value, 0, &mut descriptor);
    format!("sf_{}", hex_prefix(&Sha256::digest(descriptor), 24))
}

fn append_schema_descriptor(value: &Value, depth: usize, output: &mut String) {
    if depth > 6 || output.len() >= 16 * 1024 {
        output.push('*');
        return;
    }
    match value {
        Value::Null => output.push('n'),
        Value::Bool(_) => output.push('b'),
        Value::Number(_) => output.push('#'),
        Value::String(_) => output.push('s'),
        Value::Array(items) => {
            output.push('[');
            for item in items.iter().take(8) {
                append_schema_descriptor(item, depth + 1, output);
                output.push(',');
            }
            output.push(']');
        }
        Value::Object(object) => {
            output.push('{');
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for key in keys.into_iter().take(128) {
                output.push_str(key);
                output.push(':');
                if let Some(child) = object.get(key) {
                    append_schema_descriptor(child, depth + 1, output);
                }
                output.push(',');
            }
            output.push('}');
        }
    }
}

fn parse_json_body(body: &[u8]) -> Option<Value> {
    serde_json::from_slice(body).ok()
}

fn bounded_provider_id(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .map(ToOwned::to_owned)
}

fn provider_id_from_metadata(value: Option<&Value>, depth: u8) -> Option<String> {
    if depth > 2 {
        return None;
    }
    let metadata = value?.as_object()?;
    for key in ["conversation_id", "thread_id", "session_id"] {
        if let Some(id) = bounded_provider_id(metadata.get(key)) {
            return Some(id);
        }
    }
    for key in ["user_id", "x-codex-turn-metadata", "turn_metadata"] {
        let Some(encoded_value) = metadata.get(key) else {
            continue;
        };
        if let Some(object) = encoded_value.as_object() {
            if let Some(id) =
                provider_id_from_metadata(Some(&Value::Object(object.clone())), depth + 1)
            {
                return Some(id);
            }
        }
        let Some(encoded) = encoded_value.as_str().map(str::trim) else {
            continue;
        };
        if encoded.is_empty() || encoded.len() > 4 * 1024 {
            continue;
        }
        if let Some(id) = serde_json::from_str::<Value>(encoded)
            .ok()
            .and_then(|parsed| provider_id_from_metadata(Some(&parsed), depth + 1))
        {
            return Some(id);
        }
    }
    None
}

fn turn_id_from_metadata(value: Option<&Value>, depth: u8) -> Option<String> {
    if depth > 2 {
        return None;
    }
    let metadata = value?.as_object()?;
    if let Some(turn_id) = bounded_provider_id(metadata.get("turn_id")) {
        return Some(turn_id);
    }
    for key in ["x-codex-turn-metadata", "turn_metadata"] {
        let Some(encoded_value) = metadata.get(key) else {
            continue;
        };
        if let Some(object) = encoded_value.as_object() {
            if let Some(turn_id) =
                turn_id_from_metadata(Some(&Value::Object(object.clone())), depth + 1)
            {
                return Some(turn_id);
            }
        }
        let Some(encoded) = encoded_value.as_str().map(str::trim) else {
            continue;
        };
        if encoded.is_empty() || encoded.len() > 4 * 1024 {
            continue;
        }
        if let Some(turn_id) = serde_json::from_str::<Value>(encoded)
            .ok()
            .and_then(|parsed| turn_id_from_metadata(Some(&parsed), depth + 1))
        {
            return Some(turn_id);
        }
    }
    None
}

fn extract_provider_conversation_id(value: &Value) -> Option<String> {
    bounded_provider_id(value.get("conversation_id"))
        .or_else(|| bounded_provider_id(value.get("thread_id")))
        .or_else(|| bounded_provider_id(value.get("session_id")))
        .or_else(|| bounded_provider_id(value.get("conversation")))
        .or_else(|| {
            value
                .get("conversation")
                .and_then(|conversation| bounded_provider_id(conversation.get("id")))
        })
        .or_else(|| {
            value
                .get("metadata")
                .and_then(|metadata| provider_id_from_metadata(Some(metadata), 0))
        })
        .or_else(|| {
            // Codex Responses WebSocket prewarm and generated turns carry the resumable Thread
            // identity in client_metadata. This is protocol evidence, not a product/version gate:
            // any Responses-compatible client using the same fields receives the same treatment.
            value
                .get("client_metadata")
                .and_then(|metadata| provider_id_from_metadata(Some(metadata), 0))
        })
}

fn conversation_anchor_hash(kind: &str, value: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(kind.as_bytes());
    hash.update([0]);
    hash.update(value.as_bytes());
    hex_prefix(&hash.finalize(), 64)
}

fn push_conversation_anchor(
    anchors: &mut Vec<LlmConversationAnchor>,
    seen: &mut HashSet<String>,
    kind: &str,
    value: Option<String>,
    strength: &str,
    source_path: &str,
) {
    let Some(value) = value else {
        return;
    };
    if anchors.len() >= MAX_CONVERSATION_ANCHORS {
        return;
    }
    let value_hash = conversation_anchor_hash(kind, &value);
    let key = format!("{kind}\0{value_hash}");
    if !seen.insert(key) {
        return;
    }
    anchors.push(LlmConversationAnchor {
        kind: kind.to_string(),
        namespace: "provider".to_string(),
        value_hash,
        strength: strength.to_string(),
        source_path: source_path.to_string(),
    });
}

fn continuity_value(value: &Value) -> Option<(String, &'static str)> {
    bounded_provider_id(value.get("prompt_cache_key"))
        .map(|value| (value, "prompt_cache_key"))
        .or_else(|| bounded_provider_id(value.get("cache_key")).map(|value| (value, "cache_key")))
        .or_else(|| {
            value.get("metadata").and_then(|metadata| {
                bounded_provider_id(metadata.get("prompt_cache_key"))
                    .map(|value| (value, "metadata.prompt_cache_key"))
                    .or_else(|| {
                        bounded_provider_id(metadata.get("cache_key"))
                            .map(|value| (value, "metadata.cache_key"))
                    })
            })
        })
}

fn extract_conversation_anchors(
    request_json: Option<&Value>,
    provider_conversation_id: Option<&str>,
    provider_response_id: Option<&str>,
    provider_previous_response_id: Option<&str>,
    messages: &[LlmInteractionMessage],
    tool_calls: &[LlmInteractionToolCall],
    tool_results: &[LlmInteractionToolResult],
) -> Vec<LlmConversationAnchor> {
    let mut anchors = Vec::new();
    let mut seen = HashSet::new();
    push_conversation_anchor(
        &mut anchors,
        &mut seen,
        "provider_conversation",
        provider_conversation_id.map(ToOwned::to_owned),
        "exact",
        "conversation_id|thread_id|session_id",
    );
    push_conversation_anchor(
        &mut anchors,
        &mut seen,
        "response_id",
        provider_response_id.map(ToOwned::to_owned),
        "exact",
        "response.id",
    );
    push_conversation_anchor(
        &mut anchors,
        &mut seen,
        "previous_response_id",
        provider_previous_response_id.map(ToOwned::to_owned),
        "exact",
        "previous_response_id",
    );
    if let Some((value, source_path)) = request_json.and_then(continuity_value) {
        push_conversation_anchor(
            &mut anchors,
            &mut seen,
            "continuity_key",
            Some(value),
            "strong",
            source_path,
        );
    }
    if let Some(turn_id) = request_json
        .and_then(|value| value.get("client_metadata"))
        .and_then(|metadata| turn_id_from_metadata(Some(metadata), 0))
    {
        push_conversation_anchor(
            &mut anchors,
            &mut seen,
            "turn_id",
            Some(turn_id),
            "exact",
            "client_metadata.turn_id",
        );
    }
    for message in messages {
        push_conversation_anchor(
            &mut anchors,
            &mut seen,
            "message_item_id",
            message.source_item_id.clone(),
            "strong",
            "input[].id|messages[].id",
        );
        push_conversation_anchor(
            &mut anchors,
            &mut seen,
            "turn_id",
            message.turn_id.clone(),
            "strong",
            "message.metadata.turn_id",
        );
    }
    for call in tool_calls {
        push_conversation_anchor(
            &mut anchors,
            &mut seen,
            "tool_call_id",
            Some(call.tool_call_id.clone()),
            "exact",
            "response.tool_call.id",
        );
    }
    for result in tool_results {
        push_conversation_anchor(
            &mut anchors,
            &mut seen,
            "tool_call_id",
            Some(result.tool_call_id.clone()),
            "exact",
            "request.tool_result.call_id",
        );
    }
    anchors
}

fn control_rpc_method(method: &str) -> bool {
    matches!(
        method,
        "initialize"
            | "notifications/initialized"
            | "ping"
            | "tools/list"
            | "resources/list"
            | "resources/templates/list"
            | "prompts/list"
            | "completion/complete"
            | "logging/setLevel"
    )
}

fn classify_traffic_role(
    interaction_kind: WireInteractionKind,
    template_id: &str,
    request_json: Option<&Value>,
    messages: &[LlmInteractionMessage],
    tool_results: &[LlmInteractionToolResult],
) -> &'static str {
    if interaction_kind == WireInteractionKind::Tool {
        let method = request_json
            .and_then(|value| value.get("method"))
            .and_then(Value::as_str);
        return if method.is_some_and(control_rpc_method) {
            "control"
        } else {
            "conversation"
        };
    }
    if interaction_kind != WireInteractionKind::Model {
        return "unclassified";
    }
    if template_id == "generic-model-search-backend" {
        return "tool_backend";
    }
    if session_title_request(messages, request_json) {
        return "derived_metadata";
    }
    // Responses WebSocket prewarm requests can carry resumable session metadata and historical
    // input while explicitly asking the server not to generate a turn. Preserve them as technical
    // bootstrap evidence; the first later generate=true request is the observable user boundary.
    if request_json
        .and_then(|value| value.get("generate"))
        .and_then(Value::as_bool)
        == Some(false)
    {
        return "bootstrap";
    }
    if messages
        .iter()
        .any(|message| message.message_origin.as_deref() == Some("human_input"))
        || !tool_results.is_empty()
    {
        return "conversation";
    }
    if messages.iter().any(|message| {
        matches!(
            message.message_origin.as_deref(),
            Some("developer_instruction" | "agent_context" | "assistant_history" | "tool_history")
        )
    }) {
        return "bootstrap";
    }
    "unclassified"
}

fn value_contains_text(value: &Value, expected: &str, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    match value {
        Value::String(text) => text.to_ascii_lowercase().contains(expected),
        Value::Array(items) => items
            .iter()
            .take(256)
            .any(|item| value_contains_text(item, expected, depth + 1)),
        Value::Object(object) => object.iter().take(256).any(|(key, item)| {
            key.to_ascii_lowercase().contains(expected)
                || value_contains_text(item, expected, depth + 1)
        }),
        _ => false,
    }
}

fn session_title_request(messages: &[LlmInteractionMessage], request_json: Option<&Value>) -> bool {
    let wrapped_session = messages.iter().any(|message| {
        message.message_origin.as_deref() == Some("human_input")
            && value_contains_text(&message.content, "<session>", 0)
            && value_contains_text(&message.content, "</session>", 0)
    });
    if !wrapped_session {
        return false;
    }
    let title_instruction = messages.iter().any(|message| {
        message.message_origin.as_deref() == Some("developer_instruction")
            && value_contains_text(&message.content, "title", 0)
            && value_contains_text(&message.content, "<session>", 0)
            && (value_contains_text(&message.content, "return json", 0)
                || value_contains_text(&message.content, "single \"title\" field", 0))
    });
    title_instruction
        || request_json
            .and_then(|request| request.get("output_config"))
            .is_some_and(|config| value_contains_text(config, "title", 0))
}

fn has_unmatched_tool_calls(
    tool_calls: &[LlmInteractionToolCall],
    tool_results: &[LlmInteractionToolResult],
) -> bool {
    if tool_calls.is_empty() {
        return false;
    }
    let result_ids = tool_results
        .iter()
        .map(|result| result.tool_call_id.as_str())
        .collect::<HashSet<_>>();
    tool_calls
        .iter()
        .any(|call| !result_ids.contains(call.tool_call_id.as_str()))
}

fn extract_provider_response_id(value: &Value) -> Option<String> {
    if let Some(response) = value.get("response") {
        if let Some(id) = bounded_provider_id(response.get("id")) {
            return Some(id);
        }
    }
    if value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.starts_with("response.") || kind == "message_start")
    {
        if let Some(id) = bounded_provider_id(value.get("id")) {
            return Some(id);
        }
        if let Some(id) = value
            .get("message")
            .and_then(|message| bounded_provider_id(message.get("id")))
        {
            return Some(id);
        }
    }
    value
        .as_array()
        .and_then(|events| events.iter().rev().find_map(extract_provider_response_id))
        .or_else(|| bounded_provider_id(value.get("id")))
}

fn message_turn_id(item: &Value) -> Option<String> {
    bounded_provider_id(item.get("turn_id"))
        .or_else(|| {
            item.get("internal_chat_message_metadata_passthrough")
                .and_then(|metadata| bounded_provider_id(metadata.get("turn_id")))
        })
        .or_else(|| {
            item.get("metadata")
                .and_then(|metadata| bounded_provider_id(metadata.get("turn_id")))
        })
}

fn message_content_item_kinds(item: &Value) -> Vec<String> {
    let kinds = item
        .get("internal_chat_message_metadata_passthrough")
        .and_then(|metadata| metadata.get("content_item_kinds"))
        .or_else(|| {
            item.get("metadata")
                .and_then(|metadata| metadata.get("content_item_kinds"))
        })
        .and_then(Value::as_array);
    let mut output = Vec::new();
    for kind in kinds.into_iter().flatten().filter_map(Value::as_str) {
        let kind = kind.trim();
        if kind.is_empty() || kind.len() > 160 || output.iter().any(|value| value == kind) {
            continue;
        }
        output.push(kind.to_string());
        if output.len() >= 32 {
            break;
        }
    }
    output
}

fn message_origin(role: &str, content_item_kinds: &[String]) -> Option<String> {
    let role = role.to_ascii_lowercase();
    if matches!(role.as_str(), "user" | "human") {
        if content_item_kinds.is_empty()
            || content_item_kinds
                .iter()
                .any(|kind| kind == "user.text" || kind.starts_with("user."))
        {
            return Some("human_input".to_string());
        }
        return Some("agent_context".to_string());
    }
    if matches!(role.as_str(), "developer" | "system") {
        return Some("developer_instruction".to_string());
    }
    if role == "assistant" {
        return Some("assistant_history".to_string());
    }
    if matches!(role.as_str(), "tool" | "function") {
        return Some("tool_history".to_string());
    }
    None
}

fn extract_request_messages(value: &Value) -> Vec<LlmInteractionMessage> {
    let mut messages = Vec::new();
    if let Some(instructions) = value.get("instructions") {
        messages.push(LlmInteractionMessage {
            role: "system".to_string(),
            content: instructions.clone(),
            name: None,
            tool_call_id: None,
            source_item_id: None,
            turn_id: None,
            content_item_kinds: Vec::new(),
            message_origin: Some("developer_instruction".to_string()),
        });
    }
    if let Some(system) = value.get("system") {
        messages.push(LlmInteractionMessage {
            role: "system".to_string(),
            content: system.clone(),
            name: None,
            tool_call_id: None,
            source_item_id: None,
            turn_id: None,
            content_item_kinds: Vec::new(),
            message_origin: Some("developer_instruction".to_string()),
        });
    }
    for item in value
        .get("messages")
        .or_else(|| value.get("input"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_SSE_STRUCTURED_EVENTS)
    {
        let role = item
            .get("role")
            .and_then(Value::as_str)
            .or_else(|| {
                item.get("type")
                    .and_then(Value::as_str)
                    .filter(|kind| *kind == "message")
                    .map(|_| "user")
            })
            .unwrap_or_else(|| item.get("type").and_then(Value::as_str).unwrap_or("input"));
        let content = item
            .get("content")
            .or_else(|| item.get("output"))
            .cloned()
            .unwrap_or_else(|| item.clone());
        let content_item_kinds = message_content_item_kinds(item);
        messages.push(LlmInteractionMessage {
            role: role.to_string(),
            content,
            name: item
                .get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            tool_call_id: item
                .get("tool_call_id")
                .or_else(|| item.get("call_id"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            source_item_id: bounded_provider_id(item.get("id")),
            turn_id: message_turn_id(item),
            message_origin: message_origin(role, &content_item_kinds),
            content_item_kinds,
        });
    }
    messages
}

fn push_bounded_text(output: &mut String, text: &str, max_bytes: usize) {
    if output.len() >= max_bytes {
        return;
    }
    let remaining = max_bytes - output.len();
    let mut used = 0usize;
    for character in text.chars() {
        let width = character.len_utf8();
        if used.saturating_add(width) > remaining {
            break;
        }
        output.push(character);
        used += width;
    }
}

fn extract_response_text(value: &Value) -> Option<String> {
    if let Some(text) = value.get("output_text").and_then(Value::as_str) {
        return Some(text.to_string());
    }
    let mut output = String::new();
    if let Some(choices) = value.get("choices").and_then(Value::as_array) {
        for choice in choices.iter().take(MAX_SSE_STRUCTURED_EVENTS) {
            if let Some(text) = choice
                .get("message")
                .and_then(|message| message.get("content"))
                .and_then(Value::as_str)
                .or_else(|| {
                    choice
                        .get("delta")
                        .and_then(|delta| delta.get("content"))
                        .and_then(Value::as_str)
                })
            {
                push_bounded_text(&mut output, text, MAX_EXPORTED_STRUCTURED_BYTES);
            }
        }
    }
    collect_text_parts(value.get("output"), &mut output);
    collect_text_parts(value.get("content"), &mut output);
    collect_text_parts(value.get("candidates"), &mut output);
    if output.is_empty() {
        value
            .get("item")
            .and_then(extract_response_text)
            .or_else(|| value.get("response").and_then(extract_response_text))
    } else {
        Some(output)
    }
}

#[derive(Default)]
struct TokenUsageAccumulator {
    observed: bool,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
    cached_input_tokens: Option<u64>,
    cache_creation_input_tokens: Option<u64>,
    reasoning_output_tokens: Option<u64>,
}

fn merge_max(target: &mut Option<u64>, value: Option<u64>) {
    if let Some(value) = value {
        *target = Some(target.map_or(value, |current| current.max(value)));
    }
}

fn usage_counter(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_u64))
}

fn merge_usage_object(usage: &Value, output: &mut TokenUsageAccumulator) {
    let Some(object) = usage.as_object() else {
        return;
    };
    output.observed = true;
    merge_max(
        &mut output.input_tokens,
        usage_counter(usage, &["input_tokens", "prompt_tokens"]),
    );
    merge_max(
        &mut output.output_tokens,
        usage_counter(usage, &["output_tokens", "completion_tokens"]),
    );
    merge_max(
        &mut output.total_tokens,
        usage_counter(usage, &["total_tokens"]),
    );
    merge_max(
        &mut output.cached_input_tokens,
        usage_counter(usage, &["cache_read_input_tokens"]),
    );
    merge_max(
        &mut output.cache_creation_input_tokens,
        usage_counter(usage, &["cache_creation_input_tokens"]),
    );
    for details_key in ["input_tokens_details", "prompt_tokens_details"] {
        if let Some(details) = object.get(details_key) {
            merge_max(
                &mut output.cached_input_tokens,
                usage_counter(details, &["cached_tokens"]),
            );
        }
    }
    for details_key in ["output_tokens_details", "completion_tokens_details"] {
        if let Some(details) = object.get(details_key) {
            merge_max(
                &mut output.reasoning_output_tokens,
                usage_counter(details, &["reasoning_tokens"]),
            );
        }
    }
}

fn collect_usage_objects(value: &Value, depth: usize, output: &mut TokenUsageAccumulator) {
    if depth > 16 {
        return;
    }
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                if key == "usage" {
                    merge_usage_object(nested, output);
                }
                collect_usage_objects(nested, depth + 1, output);
            }
        }
        Value::Array(items) => {
            for item in items.iter().take(MAX_SSE_STRUCTURED_EVENTS) {
                collect_usage_objects(item, depth + 1, output);
            }
        }
        _ => {}
    }
}

/// Extract only provider-reported usage. Streaming providers may repeat cumulative counters in
/// several events, so each counter is merged by maximum rather than summed. This prevents SSE or
/// WebSocket event replay from inflating one model call.
fn extract_provider_token_usage(value: &Value) -> Option<LlmTokenUsage> {
    let mut usage = TokenUsageAccumulator::default();
    collect_usage_objects(value, 0, &mut usage);
    if !usage.observed
        || (usage.input_tokens.is_none()
            && usage.output_tokens.is_none()
            && usage.total_tokens.is_none())
    {
        return None;
    }
    let derived_total = usage.total_tokens.is_none()
        && usage.input_tokens.is_some()
        && usage.output_tokens.is_some();
    let total_tokens = usage.total_tokens.or_else(|| {
        usage
            .input_tokens
            .zip(usage.output_tokens)
            .map(|(input, output)| input.saturating_add(output))
    });
    Some(LlmTokenUsage {
        source: "provider_reported".to_string(),
        completeness: if usage.input_tokens.is_some() && usage.output_tokens.is_some() {
            "complete"
        } else {
            "partial"
        }
        .to_string(),
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        total_tokens,
        cached_input_tokens: usage.cached_input_tokens,
        cache_creation_input_tokens: usage.cache_creation_input_tokens,
        reasoning_output_tokens: usage.reasoning_output_tokens,
        total_tokens_derived: derived_total,
    })
}

fn collect_text_parts(value: Option<&Value>, output: &mut String) {
    fn visit(value: &Value, output: &mut String, depth: usize) {
        if depth > 6 || output.len() >= MAX_EXPORTED_STRUCTURED_BYTES {
            return;
        }
        match value {
            Value::Array(items) => {
                for item in items.iter().take(MAX_SSE_STRUCTURED_EVENTS) {
                    visit(item, output, depth + 1);
                }
            }
            Value::Object(object) => {
                if let Some(text) = object.get("text").and_then(Value::as_str) {
                    push_bounded_text(output, text, MAX_EXPORTED_STRUCTURED_BYTES);
                }
                for key in [
                    "content",
                    "parts",
                    "candidates",
                    "output",
                    "message",
                    "delta",
                ] {
                    if let Some(child) = object.get(key) {
                        visit(child, output, depth + 1);
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(value) = value {
        visit(value, output, 0);
    }
}

fn forced_structured_output(
    request: &Value,
    calls: &[LlmInteractionToolCall],
) -> Option<(bool, String)> {
    if calls.len() != 1 {
        return None;
    }
    let forced_name = request
        .get("tool_choice")?
        .get("function")?
        .get("name")?
        .as_str()?;
    let tools = request.get("tools")?.as_array()?;
    if tools.len() != 1 {
        return None;
    }
    let declared_name = tools[0].get("function")?.get("name")?.as_str()?;
    let call = &calls[0];
    if forced_name != declared_name || call.name != forced_name {
        return None;
    }
    let normalized_name = forced_name.to_ascii_lowercase();
    let is_final = normalized_name.contains("final")
        || normalized_name.ends_with("answer")
        || normalized_name.ends_with("report");
    let text = if is_final {
        call.arguments
            .get("answer")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| call.arguments.to_string())
    } else {
        call.arguments.to_string()
    };
    Some((is_final, text))
}

fn framework_orchestration_prompt(content: &Value) -> bool {
    let Some(text) = content.as_str() else {
        return false;
    };
    [
        "Plan card:\n",
        "Acceptance criteria:\n",
        "Verifier feedback",
        "Sandbox stdout:\n",
        "Sandbox exit code:",
        "Verification:\n",
        "Code explanation:\n",
        "Expected output:\n",
    ]
    .iter()
    .filter(|marker| text.contains(**marker))
    .take(2)
    .count()
        >= 2
}

fn extract_tool_calls(value: &Value, issued_at_unix_ns: u128) -> Vec<LlmInteractionToolCall> {
    let mut calls = Vec::new();
    if let Some(choices) = value.get("choices").and_then(Value::as_array) {
        for tool in choices
            .iter()
            .take(MAX_SSE_STRUCTURED_EVENTS)
            .filter_map(|choice| choice.get("message"))
            .filter_map(|message| message.get("tool_calls"))
            .filter_map(Value::as_array)
            .flatten()
        {
            if let Some(call) = tool_call_from_openai(tool, issued_at_unix_ns) {
                calls.push(call);
            }
        }
    }
    collect_typed_tool_calls(value.get("output"), issued_at_unix_ns, &mut calls);
    collect_typed_tool_calls(value.get("content"), issued_at_unix_ns, &mut calls);
    let provisional_output_item =
        value.get("type").and_then(Value::as_str) == Some("response.output_item.added");
    if !provisional_output_item {
        if let Some(item) = value.get("item") {
            if let Some(call) = typed_tool_call(item, issued_at_unix_ns) {
                calls.push(call);
            }
        }
    }
    if let Some(response) = value.get("response") {
        calls.extend(extract_tool_calls(response, issued_at_unix_ns));
    }
    calls
}

fn collect_typed_tool_calls(
    value: Option<&Value>,
    issued_at_unix_ns: u128,
    calls: &mut Vec<LlmInteractionToolCall>,
) {
    let Some(items) = value.and_then(Value::as_array) else {
        return;
    };
    for item in items.iter().take(MAX_SSE_STRUCTURED_EVENTS) {
        if let Some(call) = typed_tool_call(item, issued_at_unix_ns) {
            calls.push(call);
        }
        collect_typed_tool_calls(item.get("content"), issued_at_unix_ns, calls);
    }
}

fn typed_tool_call(value: &Value, issued_at_unix_ns: u128) -> Option<LlmInteractionToolCall> {
    let kind = value.get("type").and_then(Value::as_str)?;
    if !matches!(kind, "function_call" | "custom_tool_call" | "tool_use") {
        return None;
    }
    let id = value
        .get("call_id")
        .or_else(|| value.get("id"))
        .and_then(Value::as_str)?;
    Some(LlmInteractionToolCall {
        tool_call_id: id.to_string(),
        name: value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        arguments: parse_json_string_or_value(
            value.get("arguments").or_else(|| value.get("input")),
        ),
        issued_at_unix_ns: Some(issued_at_unix_ns.to_string()),
    })
}

fn tool_call_from_openai(value: &Value, issued_at_unix_ns: u128) -> Option<LlmInteractionToolCall> {
    let id = value.get("id")?.as_str()?.to_string();
    let function = value.get("function")?;
    Some(LlmInteractionToolCall {
        tool_call_id: id,
        name: function
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        arguments: parse_json_string_or_value(function.get("arguments")),
        issued_at_unix_ns: Some(issued_at_unix_ns.to_string()),
    })
}

fn extract_tool_results(value: &Value, observed_at_unix_ns: u128) -> Vec<LlmInteractionToolResult> {
    let mut results = Vec::new();
    let arrays = [value.get("messages"), value.get("input")];
    for item in arrays
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
        .flatten()
        .take(MAX_SSE_STRUCTURED_EVENTS)
    {
        if item.get("role").and_then(Value::as_str) == Some("tool")
            || matches!(
                item.get("type").and_then(Value::as_str),
                Some("function_call_output" | "custom_tool_call_output")
            )
        {
            if let Some(id) = item
                .get("tool_call_id")
                .or_else(|| item.get("call_id"))
                .and_then(Value::as_str)
            {
                results.push(LlmInteractionToolResult {
                    tool_call_id: id.to_string(),
                    name: item
                        .get("name")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    content: item
                        .get("content")
                        .or_else(|| item.get("output"))
                        .cloned()
                        .unwrap_or(Value::Null),
                    is_error: item
                        .get("is_error")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    observed_at_unix_ns: Some(observed_at_unix_ns.to_string()),
                });
            }
        }
        for block in item
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if block.get("type").and_then(Value::as_str) != Some("tool_result") {
                continue;
            }
            if let Some(id) = block.get("tool_use_id").and_then(Value::as_str) {
                results.push(LlmInteractionToolResult {
                    tool_call_id: id.to_string(),
                    name: None,
                    content: block.get("content").cloned().unwrap_or(Value::Null),
                    is_error: block
                        .get("is_error")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    observed_at_unix_ns: Some(observed_at_unix_ns.to_string()),
                });
            }
        }
    }
    results
}

fn normalize_sse_response(
    body: &[u8],
    observed_at_unix_ns: u128,
) -> (Option<Value>, Option<String>, Vec<LlmInteractionToolCall>) {
    let events = parse_sse_json_events(body);
    let mut deltas = String::new();
    let mut final_text = None;
    let mut calls = Vec::new();
    let mut chat_calls: HashMap<String, (String, String)> = HashMap::new();
    let mut chat_call_ids: HashMap<u64, String> = HashMap::new();
    let mut anthropic_calls: HashMap<String, (String, String)> = HashMap::new();
    let mut anthropic_call_ids: HashMap<u64, String> = HashMap::new();
    let mut responses_calls: HashMap<String, (String, String)> = HashMap::new();
    let mut responses_call_ids: HashMap<u64, String> = HashMap::new();
    let mut responses_item_ids: HashMap<String, String> = HashMap::new();

    for event in &events {
        if let Some(text) = sse_model_text_fragment(event) {
            push_bounded_text(&mut deltas, text, MAX_EXPORTED_STRUCTURED_BYTES);
        }
        if let Some(choices) = event.get("choices").and_then(Value::as_array) {
            for choice in choices.iter().take(MAX_SSE_STRUCTURED_EVENTS) {
                if let Some(text) = choice
                    .get("delta")
                    .and_then(|delta| delta.get("content"))
                    .and_then(Value::as_str)
                {
                    push_bounded_text(&mut deltas, text, MAX_EXPORTED_STRUCTURED_BYTES);
                }
                for tool in choice
                    .get("delta")
                    .and_then(|delta| delta.get("tool_calls"))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .take(MAX_SSE_STRUCTURED_EVENTS)
                {
                    let index = tool
                        .get("index")
                        .and_then(Value::as_u64)
                        .unwrap_or_default();
                    let explicit_id = tool
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|id| !id.is_empty())
                        .map(ToOwned::to_owned)
                        .inspect(|id| {
                            chat_call_ids.insert(index, id.clone());
                        });
                    let key = explicit_id
                        .or_else(|| chat_call_ids.get(&index).cloned())
                        .unwrap_or_else(|| format!("index:{index}"));
                    let entry = chat_calls.entry(key).or_default();
                    if let Some(name) = tool
                        .get("function")
                        .and_then(|function| function.get("name"))
                        .and_then(Value::as_str)
                    {
                        push_bounded_text(&mut entry.0, name, 16 * 1024);
                    }
                    if let Some(arguments) = tool
                        .get("function")
                        .and_then(|function| function.get("arguments"))
                        .and_then(Value::as_str)
                    {
                        push_bounded_text(&mut entry.1, arguments, MAX_EXPORTED_STRUCTURED_BYTES);
                    }
                }
            }
        }
        let event_type = event.get("type").and_then(Value::as_str);
        if event_type == Some("content_block_start") {
            if let Some(block) = event.get("content_block") {
                if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                    if let Some(id) = block.get("id").and_then(Value::as_str) {
                        let index = event
                            .get("index")
                            .and_then(Value::as_u64)
                            .unwrap_or_default();
                        anthropic_call_ids.insert(index, id.to_string());
                        anthropic_calls.insert(
                            id.to_string(),
                            (
                                block
                                    .get("name")
                                    .and_then(Value::as_str)
                                    .unwrap_or("unknown")
                                    .to_string(),
                                String::new(),
                            ),
                        );
                    }
                }
            }
        }
        if event_type == Some("content_block_delta") {
            if let Some(arguments) = event
                .get("delta")
                .and_then(|delta| delta.get("partial_json"))
                .and_then(Value::as_str)
            {
                let index = event
                    .get("index")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                if let Some(entry) = anthropic_call_ids
                    .get(&index)
                    .and_then(|id| anthropic_calls.get_mut(id))
                {
                    push_bounded_text(&mut entry.1, arguments, MAX_EXPORTED_STRUCTURED_BYTES);
                }
            }
        }
        if event_type == Some("content_block_stop") {
            let index = event
                .get("index")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            anthropic_call_ids.remove(&index);
        }

        if event_type == Some("response.output_item.added") {
            if let Some(item) = event.get("item") {
                if matches!(
                    item.get("type").and_then(Value::as_str),
                    Some("function_call" | "custom_tool_call")
                ) {
                    if let Some(call_id) = item
                        .get("call_id")
                        .or_else(|| item.get("id"))
                        .and_then(Value::as_str)
                    {
                        let name = item
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                            .to_string();
                        let arguments = item
                            .get("arguments")
                            .or_else(|| item.get("input"))
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        responses_calls.insert(call_id.to_string(), (name, arguments));
                        if let Some(index) = event.get("output_index").and_then(Value::as_u64) {
                            responses_call_ids.insert(index, call_id.to_string());
                        }
                        if let Some(item_id) = item.get("id").and_then(Value::as_str) {
                            responses_item_ids.insert(item_id.to_string(), call_id.to_string());
                        }
                    }
                }
            }
        }
        if matches!(
            event_type,
            Some(
                "response.function_call_arguments.delta" | "response.custom_tool_call_input.delta"
            )
        ) {
            if let Some(fragment) = event.get("delta").and_then(Value::as_str) {
                if let Some(call_id) =
                    responses_event_call_id(event, &responses_call_ids, &responses_item_ids)
                {
                    let entry = responses_calls.entry(call_id).or_default();
                    push_bounded_text(&mut entry.1, fragment, MAX_EXPORTED_STRUCTURED_BYTES);
                }
            }
        }
        if matches!(
            event_type,
            Some("response.function_call_arguments.done" | "response.custom_tool_call_input.done")
        ) {
            if let Some(arguments) = event
                .get("arguments")
                .or_else(|| event.get("input"))
                .and_then(Value::as_str)
            {
                if let Some(call_id) =
                    responses_event_call_id(event, &responses_call_ids, &responses_item_ids)
                {
                    responses_calls.entry(call_id).or_default().1 = arguments.to_string();
                }
            }
        }

        if let Some(text) = sse_terminal_model_text(event) {
            if !text.is_empty() && text.len() >= deltas.len() {
                final_text = Some(text);
            }
        }
        calls.extend(extract_tool_calls(event, observed_at_unix_ns));
    }

    for (id, (name, arguments)) in chat_calls {
        calls.push(LlmInteractionToolCall {
            tool_call_id: id,
            name: if name.is_empty() {
                "unknown".to_string()
            } else {
                name
            },
            arguments: parse_json_text_or_string(&arguments),
            issued_at_unix_ns: Some(observed_at_unix_ns.to_string()),
        });
    }
    for (id, (name, arguments)) in anthropic_calls {
        calls.push(LlmInteractionToolCall {
            tool_call_id: id,
            name,
            arguments: parse_json_text_or_string(&arguments),
            issued_at_unix_ns: Some(observed_at_unix_ns.to_string()),
        });
    }
    for (id, (name, arguments)) in responses_calls {
        calls.push(LlmInteractionToolCall {
            tool_call_id: id,
            name: if name.is_empty() {
                "unknown".to_string()
            } else {
                name
            },
            arguments: parse_json_text_or_string(&arguments),
            issued_at_unix_ns: Some(observed_at_unix_ns.to_string()),
        });
    }
    // Streaming deltas are the authoritative assembled text. A per-event extractor can observe
    // only the first chunk and must not replace the longer accumulated stream; use a terminal
    // provider object only when the stream carried no text deltas.
    let text = (!deltas.is_empty()).then_some(deltas).or(final_text);
    let structured = (!events.is_empty()).then_some(Value::Array(events));
    (structured, text, calls)
}

/// Return only provider events whose schema explicitly identifies assistant text. A generic
/// top-level `delta` is not enough: OpenAI Responses also uses it for streamed function/custom
/// tool arguments, and treating those bytes as text makes tool input appear as a model reply.
fn sse_model_text_fragment(event: &Value) -> Option<&str> {
    match event.get("type").and_then(Value::as_str) {
        Some("response.output_text.delta") => event.get("delta").and_then(Value::as_str),
        Some("content_block_start") => event
            .get("content_block")
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
            .and_then(|block| block.get("text"))
            .and_then(Value::as_str),
        Some("content_block_delta") => event
            .get("delta")
            .filter(|delta| {
                matches!(
                    delta.get("type").and_then(Value::as_str),
                    Some("text_delta") | None
                ) && delta.get("partial_json").is_none()
            })
            .and_then(|delta| delta.get("text"))
            .and_then(Value::as_str),
        _ => None,
    }
}

fn sse_terminal_model_text(event: &Value) -> Option<String> {
    match event.get("type").and_then(Value::as_str) {
        Some("response.output_text.done") => event
            .get("text")
            .or_else(|| event.get("delta"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        Some("response.output_item.done") => event
            .get("item")
            .filter(|item| item.get("type").and_then(Value::as_str) == Some("message"))
            .and_then(extract_response_text),
        Some("response.completed" | "response.done") => {
            event.get("response").and_then(extract_response_text)
        }
        Some("message") => extract_response_text(event),
        _ => None,
    }
}

fn responses_event_call_id(
    event: &Value,
    by_output_index: &HashMap<u64, String>,
    by_item_id: &HashMap<String, String>,
) -> Option<String> {
    event
        .get("call_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            event
                .get("item_id")
                .and_then(Value::as_str)
                .and_then(|id| by_item_id.get(id).cloned())
        })
        .or_else(|| {
            event
                .get("output_index")
                .and_then(Value::as_u64)
                .and_then(|index| by_output_index.get(&index).cloned())
        })
}

fn parse_sse_json_events(body: &[u8]) -> Vec<Value> {
    parse_sse_json_events_bounded(body).0
}

/// Parse at most `MAX_SSE_STRUCTURED_EVENTS` values and report whether another valid JSON SSE
/// event existed after the cap. Keeping the boolean separate avoids allocating unbounded tail
/// values while making the completeness downgrade auditable.
fn parse_sse_json_events_bounded(body: &[u8]) -> (Vec<Value>, bool) {
    let mut output = Vec::new();
    let mut cursor = 0usize;
    let mut capped = false;
    while cursor < body.len() {
        let Some((offset, delimiter_len)) = sse_block_delimiter(&body[cursor..]) else {
            break;
        };
        let end = cursor + offset + delimiter_len;
        let block = &body[cursor..end];
        cursor = end;
        let data = block
            .split(|byte| *byte == b'\n' || *byte == b'\r')
            .filter_map(|line| std::str::from_utf8(line).ok())
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim_start)
            .collect::<Vec<_>>()
            .join("\n");
        if data.is_empty() || data.trim() == "[DONE]" {
            continue;
        }
        if let Ok(value) = serde_json::from_str(&data) {
            if output.len() < MAX_SSE_STRUCTURED_EVENTS {
                output.push(value);
            } else {
                capped = true;
                break;
            }
        }
    }
    (output, capped)
}

fn sse_event_limit_reached(body: &[u8]) -> bool {
    parse_sse_json_events_bounded(body).1
}

fn looks_like_sse(body: &[u8]) -> bool {
    body.starts_with(b"data:")
        || body.starts_with(b"event:")
        || body.starts_with(b":")
        || find_bytes(body, b"\ndata:").is_some()
        || find_bytes(body, b"\rdata:").is_some()
        || find_bytes(body, b"\nevent:").is_some()
        || find_bytes(body, b"\revent:").is_some()
}

/// Incremental resume cursors for SSE terminal detection on a pending, still-accumulating
/// body. Re-scanning the whole body on every reassembly fragment made long streaming responses
/// quadratic — a single large response (or a misframed stream whose tail never contains a block
/// delimiter) pinned a collector core at 100% inside `sse_block_delimiter` while the pipeline
/// starved. The decoder therefore persists how far it has searched:
///
/// - `marker` is the offset through which the literal `data: [DONE]` terminators were
///   exhaustively searched;
/// - `block` is the end offset of the last complete block already proven non-terminal.
///
/// Both are absolute offsets into the current pending message body and MUST be reset whenever
/// the message boundary advances (buffer drain, decode error, unparsed-tail takeover).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SseTerminalScanState {
    block: usize,
    marker: usize,
}

/// Longest literal terminal marker plus one block delimiter; a new terminal can only appear
/// straddling the previously searched boundary within this overlap.
const SSE_TERMINAL_MARKER_OVERLAP: usize = 32;

/// One-shot terminal search over a complete body. Equivalent to searching from scratch.
fn sse_terminal_offset(body: &[u8]) -> Option<usize> {
    let mut scan = SseTerminalScanState::default();
    sse_terminal_offset_incremental(body, &mut scan)
}

/// Terminal search that only examines bytes not yet ruled out by earlier attempts. A terminal
/// fully inside the previously searched region would have completed the message then; only the
/// overlap window at the boundary and the not-yet-searched tail can introduce a new one.
fn sse_terminal_offset_incremental(body: &[u8], scan: &mut SseTerminalScanState) -> Option<usize> {
    let from = scan
        .marker
        .saturating_sub(SSE_TERMINAL_MARKER_OVERLAP)
        .min(body.len());
    for marker in [
        b"data: [DONE]\r\n\r\n".as_slice(),
        b"data: [DONE]\n\n".as_slice(),
    ] {
        if let Some(offset) = find_bytes(&body[from..], marker) {
            return Some(from + offset + marker.len());
        }
    }
    scan.marker = body.len();
    let mut cursor = scan.block.min(body.len());
    while let Some((offset, delimiter_len)) = sse_block_delimiter(&body[cursor..]) {
        let end = cursor + offset + delimiter_len;
        let block = &body[cursor..end];
        cursor = end;
        let data = block
            .split(|byte| *byte == b'\n' || *byte == b'\r')
            .filter_map(|line| std::str::from_utf8(line).ok())
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim_start)
            .collect::<Vec<_>>()
            .join("\n");
        if data.trim() == "[DONE]" {
            scan.block = cursor;
            return Some(cursor);
        }
        if let Ok(value) = serde_json::from_str::<Value>(&data) {
            if response_event_terminal(&value).is_some() {
                scan.block = cursor;
                return Some(cursor);
            }
        }
    }
    scan.block = cursor;
    None
}

fn parse_json_string_or_value(value: Option<&Value>) -> Value {
    match value {
        Some(Value::String(text)) => parse_json_text_or_string(text),
        Some(value) => value.clone(),
        None => Value::Object(Map::new()),
    }
}

fn parse_json_text_or_string(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_string()))
}

fn dedup_tool_calls(calls: &mut Vec<LlmInteractionToolCall>) {
    let mut seen = HashMap::<String, usize>::new();
    let mut output: Vec<LlmInteractionToolCall> = Vec::new();
    for call in calls.drain(..) {
        if let Some(index) = seen.get(&call.tool_call_id).copied() {
            let existing = &mut output[index];
            if existing.name == "unknown" && call.name != "unknown" {
                existing.name = call.name;
            }
            if existing.arguments.is_null()
                || existing.arguments == Value::Object(Map::new())
                || existing.arguments == Value::String(String::new())
            {
                existing.arguments = call.arguments;
            }
        } else {
            seen.insert(call.tool_call_id.clone(), output.len());
            output.push(call);
        }
    }
    *calls = output;
}

fn dedup_tool_results(results: &mut Vec<LlmInteractionToolResult>) {
    let mut seen = HashMap::<String, usize>::new();
    let mut output: Vec<LlmInteractionToolResult> = Vec::new();
    for result in results.drain(..) {
        if let Some(index) = seen.get(&result.tool_call_id).copied() {
            output[index] = result;
        } else {
            seen.insert(result.tool_call_id.clone(), output.len());
            output.push(result);
        }
    }
    *results = output;
}

fn interaction_id(
    key: ConnectionKey,
    sequence: u64,
    started_at_unix_ns: u128,
    path: &str,
    request_sha256: &str,
) -> String {
    let mut hash = Sha256::new();
    hash.update(key.cgroup_id.to_ne_bytes());
    hash.update(key.pid.to_ne_bytes());
    hash.update(key.connection_id.to_ne_bytes());
    hash.update(sequence.to_ne_bytes());
    hash.update(started_at_unix_ns.to_ne_bytes());
    hash.update(path.as_bytes());
    hash.update(request_sha256.as_bytes());
    format!("mi_{}", hex_prefix(&hash.finalize(), 24))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_prefix(&Sha256::digest(bytes), 64)
}

fn hex_prefix(bytes: &[u8], characters: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(characters.min(bytes.len() * 2));
    for byte in bytes {
        if output.len() >= characters {
            break;
        }
        output.push(HEX[(byte >> 4) as usize] as char);
        if output.len() >= characters {
            break;
        }
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    // memchr-backed search: the SSE terminal/delimiter paths call this on every reassembly
    // fragment, where a naive sliding-window scan is quadratic in the accumulated body size.
    memchr::memmem::find(haystack, needle)
}

fn extend_unique(values: &mut Vec<String>, additions: impl IntoIterator<Item = String>) {
    for value in additions {
        if !values.iter().any(|existing| existing == &value) {
            values.push(value);
        }
    }
}

fn merge_bounded_label(current: &mut String, next: &str) {
    let next = next.trim();
    if next.is_empty() || current == next || current.split('+').any(|item| item == next) {
        return;
    }
    const MAX_LABEL_BYTES: usize = 256;
    if current.len().saturating_add(next.len()).saturating_add(1) <= MAX_LABEL_BYTES {
        current.push('+');
        current.push_str(next);
    } else if !current.split('+').any(|item| item == "mixed") {
        if current.len().saturating_add(6) <= MAX_LABEL_BYTES {
            current.push_str("+mixed");
        } else {
            current.truncate(MAX_LABEL_BYTES.saturating_sub(6));
            current.push_str("+mixed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::{Compress, Compression, FlushCompress};
    use std::io::Write;

    fn chunk(direction: ChunkDirection, data: impl Into<Vec<u8>>, at: u128) -> PlaintextChunk {
        PlaintextChunk {
            cgroup_id: 7,
            pid: 42,
            connection_id: 0x1234,
            sequence: 0,
            direction,
            data: data.into(),
            event_at_unix_ns: at,
            source: "openssl_uprobe".to_string(),
            adapter_id: "openssl-ex".to_string(),
            route_candidate: false,
            partial_reasons: Vec::new(),
            bind_quality: 0,
            socket_fd: 0,
            socket_cookie: 0,
            fd_generation: 0,
        }
    }

    fn http_request(body: &str) -> Vec<u8> {
        format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer must-not-export\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(), body
        )
        .into_bytes()
    }

    fn http_response(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    }

    fn custom_http_request(method: &str, path: &str, host: &str, body: &str) -> Vec<u8> {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    }

    fn correlated_http_request(path: &str, host: &str, body: &str) -> Vec<u8> {
        format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer must-not-export\r\nContent-Type: application/json\r\ntraceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\nx-anysentry-run-id: run-fixture-1\r\nx-anysentry-session-id: session-fixture-1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    }

    fn rustls_chunk_on(
        direction: ChunkDirection,
        data: impl Into<Vec<u8>>,
        at: u128,
        connection_id: u64,
    ) -> PlaintextChunk {
        let mut chunk = chunk(direction, data, at);
        chunk.source = "tls_uprobe_rustls".to_string();
        chunk.adapter_id = "rustls-payload".to_string();
        chunk.connection_id = connection_id;
        chunk
    }

    fn compressed_websocket_frame(
        compressor: &mut Compress,
        payload: &[u8],
        masked: bool,
    ) -> Vec<u8> {
        let before_in = compressor.total_in();
        let mut compressed =
            Vec::with_capacity(payload.len().saturating_mul(2).saturating_add(128));
        compressor
            .compress_vec(payload, &mut compressed, FlushCompress::Sync)
            .unwrap();
        assert_eq!((compressor.total_in() - before_in) as usize, payload.len());
        assert!(compressed.ends_with(WEBSOCKET_DEFLATE_TAIL));
        compressed.truncate(compressed.len() - WEBSOCKET_DEFLATE_TAIL.len());

        websocket_frame(&compressed, masked, true, true, 0x1)
    }

    fn websocket_frame(
        payload: &[u8],
        masked: bool,
        fin: bool,
        compressed: bool,
        opcode: u8,
    ) -> Vec<u8> {
        let mut first = opcode & 0x0f;
        if fin {
            first |= 0x80;
        }
        if compressed {
            first |= 0x40;
        }
        let mut frame = vec![first];
        let mask_bit = if masked { 0x80 } else { 0 };
        match payload.len() {
            length @ 0..=125 => frame.push(mask_bit | length as u8),
            length @ 126..=65_535 => {
                frame.push(mask_bit | 126);
                frame.extend_from_slice(&(length as u16).to_be_bytes());
            }
            length => {
                frame.push(mask_bit | 127);
                frame.extend_from_slice(&(length as u64).to_be_bytes());
            }
        }
        if masked {
            let mask = [0x12, 0x34, 0x56, 0x78];
            frame.extend_from_slice(&mask);
            frame.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ mask[index % mask.len()]),
            );
        } else {
            frame.extend_from_slice(payload);
        }
        frame
    }

    #[test]
    fn fragmented_chat_exchange_is_paired_without_headers_or_secret() {
        let request_body =
            r#"{"model":"fixture-model","messages":[{"role":"user","content":"hello"}]}"#;
        let response_body = r#"{"choices":[{"message":{"role":"assistant","content":"world"}}]}"#;
        let request = http_request(request_body);
        let response = http_response(response_body);
        let mut reassembler = InteractionReassembler::default();

        assert!(reassembler
            .push(chunk(ChunkDirection::Request, request[..37].to_vec(), 100))
            .is_empty());
        assert!(reassembler
            .push(chunk(ChunkDirection::Request, request[37..].to_vec(), 110))
            .is_empty());
        assert!(reassembler
            .push(chunk(
                ChunkDirection::Response,
                response[..29].to_vec(),
                200
            ))
            .is_empty());
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            response[29..].to_vec(),
            250,
        ));

        assert_eq!(completed.len(), 1);
        let interaction = &completed[0];
        assert_eq!(interaction.model.as_deref(), Some("fixture-model"));
        assert_eq!(interaction.response.text.as_deref(), Some("world"));
        assert_eq!(interaction.request.messages.len(), 1);
        assert!(!interaction.request.body.contains("must-not-export"));
        assert_eq!(interaction.started_at_unix_ns, "100");
        assert_eq!(interaction.first_response_at_unix_ns, "200");
        assert_eq!(interaction.ended_at_unix_ns, "250");
        assert_eq!(interaction.completeness, "complete");
        assert_eq!(interaction.semantic_parser_id, SEMANTIC_PARSER_ID);
        assert_eq!(
            interaction
                .semantic_items
                .iter()
                .map(|item| (item.actor.as_str(), item.kind.as_str()))
                .collect::<Vec<_>>(),
            vec![("user", "user_message"), ("model", "model_final")]
        );
    }

    #[test]
    fn conversation_anchor_contract_keeps_human_turn_identity_and_hashes_continuity_keys() {
        let request_body = r#"{
          "model":"fixture-model",
          "prompt_cache_key":"stable-resume-key-must-not-export",
          "messages":[
            {
              "id":"msg-agent-context",
              "role":"user",
              "content":[{"type":"input_text","text":"runtime instructions"}],
              "internal_chat_message_metadata_passthrough":{
                "turn_id":"turn-bootstrap",
                "content_item_kinds":["agents_md.instructions"]
              }
            },
            {
              "id":"msg-human-1",
              "role":"user",
              "content":[{"type":"input_text","text":"hello from a human"}],
              "internal_chat_message_metadata_passthrough":{
                "turn_id":"turn-human-1",
                "content_item_kinds":["user.text"]
              }
            }
          ]
        }"#;
        let response_body =
            r#"{"id":"resp-1","choices":[{"message":{"role":"assistant","content":"world"}}]}"#;
        let mut reassembler = InteractionReassembler::default();
        assert!(reassembler
            .push(chunk(
                ChunkDirection::Request,
                http_request(request_body),
                100
            ))
            .is_empty());
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(response_body),
            200,
        ));

        assert_eq!(completed.len(), 1);
        let interaction = &completed[0];
        assert_eq!(interaction.semantic_parser_version, 2);
        assert_eq!(interaction.traffic_role, "conversation");
        assert_eq!(interaction.request.messages.len(), 2);
        assert_eq!(
            interaction.request.messages[0].message_origin.as_deref(),
            Some("agent_context")
        );
        assert_eq!(
            interaction.request.messages[1].source_item_id.as_deref(),
            Some("msg-human-1")
        );
        assert_eq!(
            interaction.request.messages[1].turn_id.as_deref(),
            Some("turn-human-1")
        );
        let user_items = interaction
            .semantic_items
            .iter()
            .filter(|item| item.kind == "user_message")
            .collect::<Vec<_>>();
        assert_eq!(user_items.len(), 1);
        assert_eq!(user_items[0].source_item_id.as_deref(), Some("msg-human-1"));
        assert_eq!(user_items[0].turn_id.as_deref(), Some("turn-human-1"));
        assert!(interaction
            .conversation_anchors
            .iter()
            .any(|anchor| anchor.kind == "continuity_key" && anchor.strength == "strong"));
        assert!(interaction
            .conversation_anchors
            .iter()
            .any(|anchor| anchor.kind == "message_item_id"));
        assert!(interaction
            .conversation_anchors
            .iter()
            .any(|anchor| anchor.kind == "turn_id"));
        assert!(!serde_json::to_string(&interaction.conversation_anchors)
            .unwrap()
            .contains("stable-resume-key-must-not-export"));
    }

    #[test]
    fn responses_client_metadata_supplies_resumable_session_and_turn_anchors() {
        let request_body = r#"{
          "type":"response.create",
          "generate":false,
          "model":"fixture-model",
          "client_metadata":{
            "session_id":"session-from-client-metadata",
            "thread_id":"session-from-client-metadata",
            "turn_id":"turn-from-client-metadata"
          },
          "input":[{
            "id":"msg-current-turn",
            "type":"message",
            "role":"user",
            "content":[{"type":"input_text","text":"continue an older session"}],
            "internal_chat_message_metadata_passthrough":{
              "content_item_kinds":["user.text"]
            }
          }]
        }"#;
        let response_body = r#"{
          "id":"resp-client-metadata",
          "object":"response",
          "status":"completed",
          "output":[{
            "type":"message",
            "role":"assistant",
            "content":[{"type":"output_text","text":"continued"}]
          }]
        }"#;
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            http_request(request_body),
            100,
        ));
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(response_body),
            200,
        ));

        assert_eq!(completed.len(), 1);
        let interaction = &completed[0];
        assert_eq!(interaction.traffic_role, "bootstrap");
        assert_eq!(
            interaction.provider_conversation_id.as_deref(),
            Some("session-from-client-metadata")
        );
        assert!(interaction.conversation_anchors.iter().any(|anchor| {
            anchor.kind == "provider_conversation"
                && anchor.source_path == "conversation_id|thread_id|session_id"
        }));
        assert!(interaction.conversation_anchors.iter().any(|anchor| {
            anchor.kind == "turn_id"
                && anchor.source_path == "client_metadata.turn_id"
                && anchor.strength == "exact"
        }));
    }

    #[test]
    fn anthropic_metadata_user_id_json_supplies_resumable_session_anchor() {
        let request_body = r#"{
          "model":"claude-opus",
          "metadata":{"user_id":"{\"device_id\":\"device\",\"session_id\":\"claude-resume-session\"}"},
          "messages":[{"role":"user","content":[{"type":"text","text":"continue"}]}]
        }"#;
        let response_body = r#"{
          "id":"msg-json-session",
          "type":"message",
          "role":"assistant",
          "content":[{"type":"text","text":"continued"}]
        }"#;
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            custom_http_request("POST", "/v1/messages", "gateway.invalid", request_body),
            100,
        ));
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(response_body),
            200,
        ));

        assert_eq!(completed.len(), 1);
        let interaction = &completed[0];
        assert_eq!(
            interaction.provider_conversation_id.as_deref(),
            Some("claude-resume-session")
        );
        assert!(interaction.conversation_anchors.iter().any(|anchor| {
            anchor.kind == "provider_conversation" && anchor.strength == "exact"
        }));
    }

    #[test]
    fn rustls_body_only_request_is_paired_with_the_http_response() {
        let request_body =
            r#"{"model":"fixture-model","input":[{"role":"user","content":"hello"}]}"#;
        let response_body =
            r#"{"output":[{"type":"message","content":[{"type":"output_text","text":"world"}]}]}"#;
        let mut reassembler = InteractionReassembler::default();
        let mut request = chunk(ChunkDirection::Request, request_body.as_bytes(), 100);
        request.source = "tls_uprobe_rustls".to_string();
        assert!(reassembler.push(request).is_empty());
        let mut response = chunk(ChunkDirection::Response, http_response(response_body), 200);
        response.source = "tls_uprobe_rustls".to_string();
        let completed = reassembler.push(response);

        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].path, "/v1/responses");
        assert_eq!(completed[0].protocol, "http/1.1-body-inferred");
        assert_eq!(completed[0].endpoint, "unknown");
        assert_eq!(completed[0].request.body, request_body);
        assert_eq!(completed[0].response.text.as_deref(), Some("world"));
        assert_eq!(completed[0].completeness, "complete");
    }

    #[test]
    fn rustls_body_only_gate_rejects_unrelated_json() {
        assert!(body_only_llm_request(br#"{"operation":"health"}"#, 1, &[]).is_none());
    }

    #[test]
    fn rustls_body_only_json_request_reassembles_across_pointer_fragments() {
        let request_body = r#"{"model":"fixture-model","input":[{"role":"user","content":"split-body"}],"metadata":{"session_id":"split-session"}}"#;
        let split = request_body.len() / 2;
        let mut reassembler = InteractionReassembler::default();
        let mut first = rustls_chunk_on(
            ChunkDirection::Request,
            request_body.as_bytes()[..split].to_vec(),
            100,
            0x7100,
        );
        first.route_candidate = true;
        first.sequence = 1;
        assert!(reassembler.push(first).is_empty());
        let mut second = rustls_chunk_on(
            ChunkDirection::Request,
            request_body.as_bytes()[split..].to_vec(),
            110,
            0x7101,
        );
        second.route_candidate = true;
        second.sequence = 2;
        assert!(reassembler.push(second).is_empty());

        let mut response = rustls_chunk_on(
            ChunkDirection::Response,
            http_response(
                r#"{"output":[{"type":"message","content":[{"type":"output_text","text":"split-response"}]}]}"#,
            ),
            200,
            0x7200,
        );
        response.route_candidate = true;
        response.sequence = 1;
        let completed = reassembler.push(response);
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].request.body, request_body);
        assert_eq!(
            completed[0].request.sha256,
            sha256_hex(request_body.as_bytes())
        );
        assert_eq!(
            completed[0].request.decoded_bytes as usize,
            request_body.len()
        );
        assert_eq!(completed[0].started_at_unix_ns, "100");
        assert_eq!(completed[0].request_complete_at_unix_ns, "110");
        assert_eq!(
            completed[0].response.text.as_deref(),
            Some("split-response")
        );
        assert_eq!(completed[0].completeness, "complete");
        assert!(completed[0]
            .partial_reasons
            .iter()
            .all(|reason| reason != "route_candidate"));
    }

    #[test]
    fn rustls_body_only_sse_response_waits_for_terminal_event() {
        let request_body = r#"{"model":"fixture-model","input":[{"role":"user","content":"sse-body"}],"metadata":{"session_id":"sse-session"}}"#;
        let mut reassembler = InteractionReassembler::default();
        let mut request = rustls_chunk_on(
            ChunkDirection::Request,
            request_body.as_bytes().to_vec(),
            100,
            0x7300,
        );
        request.route_candidate = true;
        request.sequence = 1;
        reassembler.push(request);

        let first = b"data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-sse\"}}\n\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hello \"}\n\n";
        let mut first_chunk =
            rustls_chunk_on(ChunkDirection::Response, first.to_vec(), 200, 0x7400);
        first_chunk.route_candidate = true;
        first_chunk.sequence = 1;
        assert!(reassembler.push(first_chunk).is_empty());

        let second = b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"world\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-sse\"}}\n\n";
        let mut second_chunk =
            rustls_chunk_on(ChunkDirection::Response, second.to_vec(), 220, 0x7401);
        second_chunk.route_candidate = true;
        second_chunk.sequence = 2;
        let completed = reassembler.push(second_chunk);
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].response.text.as_deref(), Some("hello world"));
        assert_eq!(completed[0].response.content_type, "text/event-stream");
        assert_eq!(completed[0].first_response_at_unix_ns, "200");
        assert_eq!(completed[0].ended_at_unix_ns, "220");
        assert_eq!(completed[0].completeness, "complete");
    }

    #[test]
    fn sse_terminal_offset_incremental_matches_one_shot_at_every_prefix() {
        // The incremental cursors must reproduce the one-shot result exactly for every prefix,
        // including prefixes that split a delimiter, a marker, or a JSON event mid-way.
        let bodies = [
            b"data: {\"type\":\"response.created\"}\n\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\ndata: [DONE]\n\n".as_slice(),
            b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"a\"}\r\ndata: {\"type\":\"response.completed\"}\r\n\r\n".as_slice(),
            b": comment\n\ndata: {\"type\":\"irrelevant\"}\n\ndata: {\"type\":\"message_stop\"}\n\n".as_slice(),
            b"garbage-without-any-delimiter-or-terminal".as_slice(),
        ];
        for body in bodies {
            let mut scan = SseTerminalScanState::default();
            for split in 1..=body.len() {
                let prefix = &body[..split];
                assert_eq!(
                    sse_terminal_offset_incremental(prefix, &mut scan),
                    sse_terminal_offset(prefix),
                    "incremental diverged from one-shot at prefix len {split} of body {body:?}"
                );
            }
        }
    }

    #[test]
    fn sse_terminal_offset_incremental_is_bytescanned_bounded_by_new_data() {
        // After a feed that ends without a delimiter, the next search must resume near the
        // previous boundary instead of rescanning the whole tail: the marker cursor equals the
        // previous body length and only the overlap window plus new bytes are examined.
        let mut scan = SseTerminalScanState::default();
        let tail_without_delimiter = vec![b'x'; 4096];
        assert!(sse_terminal_offset_incremental(&tail_without_delimiter, &mut scan).is_none());
        assert_eq!(scan.marker, tail_without_delimiter.len());
        let grown = [
            tail_without_delimiter.as_slice(),
            b"data: [DONE]\n\n".as_slice(),
        ]
        .concat();
        let found = sse_terminal_offset_incremental(&grown, &mut scan);
        assert_eq!(found, sse_terminal_offset(&grown));
    }

    #[test]
    fn http_framed_sse_without_length_completes_across_fragment_boundaries() {
        // A long streaming response fed one byte-group at a time, with the terminal event
        // split across feeds, must complete exactly once with the full SSE body retained.
        let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n";
        let body = b"data: {\"type\":\"response.created\"}\n\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"chunked words \"}\n\ndata: {\"type\":\"response.completed\"}\n\n";
        let wire = [header.as_bytes(), body.as_slice()].concat();
        let mut decoder = HttpStreamDecoder::new(StreamKind::Response, 8 * 1024 * 1024);
        let mut completed = Vec::new();
        for size in [1usize, 7, 3, 64, 2, 31, 5] {
            let mut cursor = 0;
            while cursor < wire.len() {
                let end = (cursor + size).min(wire.len());
                completed.extend(decoder.push(&wire[cursor..end], 100, &[]));
                cursor = end;
            }
            if !completed.is_empty() {
                break;
            }
        }
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].body, body);
        assert_eq!(completed[0].content_type(), "text/event-stream");
        assert_eq!(completed[0].partial_reasons.len(), 0);
    }

    #[test]
    fn chunked_sse_early_stop_completes_when_terminal_spans_feeds() {
        let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
        let event_a = b"data: {\"type\":\"response.created\"}\n\n";
        let event_b = b"data: {\"type\":\"response.completed\"}\n\n";
        let chunked = |payload: &[u8]| -> Vec<u8> {
            format!("{:x}\r\n", payload.len())
                .into_bytes()
                .into_iter()
                .chain(payload.iter().copied())
                .chain(b"\r\n".iter().copied())
                .collect()
        };
        let wire = [
            header.as_bytes(),
            chunked(event_a).as_slice(),
            chunked(event_b).as_slice(),
            b"0\r\n\r\n".as_slice(),
        ]
        .concat();
        let mut decoder = HttpStreamDecoder::new(StreamKind::Response, 8 * 1024 * 1024);
        // Feed a split inside the terminal chunk so completion is decided by the incremental
        // terminal scan resuming across feeds rather than a single whole-body parse.
        let split = header.len() + chunked(event_a).len() + 5;
        let mut completed = decoder.push(&wire[..split], 100, &[]);
        assert!(completed.is_empty(), "no terminal observed yet");
        completed.extend(decoder.push(&wire[split..], 120, &[]));
        assert_eq!(completed.len(), 1);
        assert_eq!(
            completed[0].body,
            [event_a.as_slice(), event_b.as_slice()].concat()
        );
    }

    #[test]
    fn repeated_framing_errors_do_not_reset_terminal_scan_cursors() {
        // A response declared chunked whose body is actually raw CRLF SSE fails chunk-size
        // parsing on every fragment (a `data:` line is not a hex size). Framing errors do not
        // advance the message boundary, so the terminal-scan cursors must survive them: this
        // pins the invariant that a persistently misframed stream cannot force the decoder back
        // into whole-body rescans via the error path. (The misframed stream stays pending; the
        // semantic chunked→SSE fallback itself is owned by the framing layer.)
        let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
        let sse = b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"x\"}\r\n\r\n";
        let mut decoder = HttpStreamDecoder::new(StreamKind::Response, 8 * 1024 * 1024);
        assert!(decoder.push(header.as_bytes(), 100, &[]).is_empty());
        let cursors_before_error = (decoder.sse_scan, decoder.chunked_scan);
        assert!(
            decoder.push(sse, 110, &[]).is_empty(),
            "misframed chunked SSE stays pending, not completed"
        );
        assert!(
            decoder.last_decode_error.is_some(),
            "a `data:` line is not a valid chunk size"
        );
        assert_eq!(
            (decoder.sse_scan, decoder.chunked_scan),
            cursors_before_error,
            "framing errors must not reset the terminal-scan cursors"
        );
        for _ in 0..4 {
            assert!(decoder.push(sse, 120, &[]).is_empty());
            assert!(decoder.last_decode_error.is_some());
            assert_eq!(
                (decoder.sse_scan, decoder.chunked_scan),
                cursors_before_error
            );
        }
    }

    #[test]
    fn rustls_body_only_sse_split_prefix_and_cr_delimiter_preserve_raw_body() {
        let request_body =
            r#"{"model":"fixture-model","input":[{"role":"user","content":"split-sse"}]}"#;
        let mut reassembler = InteractionReassembler::default();
        let mut request = rustls_chunk_on(
            ChunkDirection::Request,
            request_body.as_bytes().to_vec(),
            100,
            0x7500,
        );
        request.route_candidate = true;
        request.sequence = 1;
        reassembler.push(request);

        let mut prefix = rustls_chunk_on(ChunkDirection::Response, b"da".to_vec(), 200, 0x7600);
        prefix.route_candidate = true;
        prefix.sequence = 1;
        assert!(reassembler.push(prefix).is_empty());
        let raw = b"ta: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\r\rdata: {\"type\":\"response.completed\"}\r\r";
        let mut terminal = rustls_chunk_on(ChunkDirection::Response, raw.to_vec(), 220, 0x7601);
        terminal.route_candidate = true;
        terminal.sequence = 2;
        let completed = reassembler.push(terminal);
        assert_eq!(completed.len(), 1);
        let expected = [b"da".as_slice(), raw.as_slice()].concat();
        assert_eq!(
            completed[0].response.body,
            String::from_utf8(expected.clone()).unwrap()
        );
        assert_eq!(completed[0].response.sha256, sha256_hex(&expected));
        assert_eq!(completed[0].response.text.as_deref(), Some("ok"));
    }

    #[test]
    fn rustls_body_only_json_sequence_keeps_raw_hash_and_parser_projection_separate() {
        let request_body =
            r#"{"model":"fixture-model","input":[{"role":"user","content":"json-seq"}]}"#;
        let mut reassembler = InteractionReassembler::default();
        let mut request = rustls_chunk_on(
            ChunkDirection::Request,
            request_body.as_bytes().to_vec(),
            100,
            0x7700,
        );
        request.route_candidate = true;
        request.sequence = 1;
        reassembler.push(request);
        let raw = br#"{"type":"response.output_text.delta","delta":"hello"} {"type":"response.completed"}"#;
        let mut response = rustls_chunk_on(ChunkDirection::Response, raw.to_vec(), 200, 0x7701);
        response.route_candidate = true;
        response.sequence = 1;
        let completed = reassembler.push(response);
        assert_eq!(completed.len(), 1);
        assert_eq!(
            completed[0].response.body,
            String::from_utf8(raw.to_vec()).unwrap()
        );
        assert_eq!(completed[0].response.sha256, sha256_hex(raw));
        assert_eq!(completed[0].response.content_type, "application/json-seq");
        assert_eq!(completed[0].response.text.as_deref(), Some("hello"));
    }

    #[test]
    fn rustls_body_only_response_does_not_buffer_orphan_bytes() {
        let mut reassembler = InteractionReassembler::default();
        let mut response = rustls_chunk_on(
            ChunkDirection::Response,
            br#"{"status":"health"}"#.to_vec(),
            100,
            0x7800,
        );
        response.route_candidate = true;
        response.sequence = 1;
        assert!(reassembler.push(response).is_empty());
        assert_eq!(reassembler.active_connections(), 1);
        let evidence = reassembler.take_evidence();
        assert!(evidence.iter().any(|item| item
            .reasons
            .iter()
            .any(|reason| reason == "orphan_rustls_body_only_response")));
    }

    #[test]
    fn rustls_body_only_anthropic_message_and_gemini_response_are_terminal() {
        let mut reassembler = InteractionReassembler::default();
        let mut anthropic_request = rustls_chunk_on(
            ChunkDirection::Request,
            br#"{"model":"claude","messages":[{"role":"user","content":"hi"}]}"#.to_vec(),
            100,
            0x7900,
        );
        anthropic_request.route_candidate = true;
        anthropic_request.sequence = 1;
        reassembler.push(anthropic_request);
        let mut anthropic_response = rustls_chunk_on(
            ChunkDirection::Response,
            br#"{"type":"message","content":[{"type":"text","text":"hello"}]}"#.to_vec(),
            200,
            0x7901,
        );
        anthropic_response.route_candidate = true;
        anthropic_response.sequence = 1;
        let first = reassembler.push(anthropic_response);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].response.text.as_deref(), Some("hello"));

        let mut gemini_request = rustls_chunk_on(
            ChunkDirection::Request,
            br#"{"model":"gemini","contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#.to_vec(),
            300,
            0x7a00,
        );
        gemini_request.route_candidate = true;
        gemini_request.sequence = 1;
        reassembler.push(gemini_request);
        let mut gemini_response = rustls_chunk_on(
            ChunkDirection::Response,
            br#"{"candidates":[{"content":{"parts":[{"text":"world"}]}}]}"#.to_vec(),
            400,
            0x7a01,
        );
        gemini_response.route_candidate = true;
        gemini_response.sequence = 1;
        let second = reassembler.push(gemini_response);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].response.text.as_deref(), Some("world"));
    }

    #[test]
    fn local_control_plane_http_is_not_misclassified_as_llm() {
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            custom_http_request(
                "POST",
                "/v1.54/containers/create",
                "api.moby.localhost",
                r#"{"model":"worker-image","input":"container configuration"}"#,
            ),
            1,
        ));
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(r#"{"Id":"container-id"}"#),
            2,
        ));
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].interaction_type, "unparsed");
        assert_eq!(completed[0].parse_state, "unparsed");
        assert_eq!(completed[0].llm_likelihood, "unknown");
    }

    #[test]
    fn unknown_wire_shape_is_retained_as_unparsed_with_explicit_gap_reason() {
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            custom_http_request(
                "POST",
                "/vendor/unknown",
                "agent.local",
                r#"{"opaque":true}"#,
            ),
            10,
        ));
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(r#"{"status":"ok"}"#),
            20,
        ));
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].interaction_type, "unparsed");
        assert_eq!(completed[0].parse_state, "unparsed");
        assert!(completed[0]
            .partial_reasons
            .iter()
            .any(|reason| reason.contains("wire_template_unparsed")));
    }

    #[test]
    fn mcp_jsonrpc_template_emits_instruction_result_and_times_without_route_gate() {
        let mut reassembler = InteractionReassembler::default();
        let request = chunk(
            ChunkDirection::Request,
            custom_http_request(
                "POST",
                "/arbitrary/gateway/path",
                "tool.fixture",
                r#"{"jsonrpc":"2.0","id":"tool-1","method":"tools/call","params":{"name":"fixture","arguments":{"instruction":"run fixture"}}}"#,
            ),
            10,
        );
        reassembler.push(request);
        let response = chunk(
            ChunkDirection::Response,
            http_response(r#"{"jsonrpc":"2.0","id":"tool-1","result":{"result":"fixture ok"}}"#),
            20,
        );
        let completed = reassembler.push(response);

        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].interaction_type, "tool");
        assert_eq!(completed[0].traffic_role, "conversation");
        assert_eq!(completed[0].path, "/arbitrary/gateway/path");
        assert_eq!(
            completed[0].wire_template_id.as_deref(),
            Some("mcp-jsonrpc")
        );
        assert_eq!(completed[0].tool_calls.len(), 1);
        assert_eq!(completed[0].tool_results.len(), 1);
        assert_eq!(
            completed[0].tool_calls[0].tool_call_id,
            completed[0].tool_results[0].tool_call_id
        );
        assert_eq!(
            completed[0].tool_calls[0].arguments["instruction"],
            "run fixture"
        );
        assert_eq!(completed[0].tool_results[0].content["result"], "fixture ok");
        assert_eq!(
            completed[0].tool_calls[0].issued_at_unix_ns.as_deref(),
            Some("10")
        );
        assert_eq!(
            completed[0].tool_results[0].observed_at_unix_ns.as_deref(),
            Some("20")
        );
    }

    #[test]
    fn mcp_lifecycle_and_discovery_are_control_traffic_not_user_conversations() {
        for (sequence, method) in ["initialize", "tools/list"].into_iter().enumerate() {
            let mut reassembler = InteractionReassembler::default();
            reassembler.push(chunk(
                ChunkDirection::Request,
                custom_http_request(
                    "POST",
                    "/mcp",
                    "tool.fixture",
                    &format!(
                        r#"{{"jsonrpc":"2.0","id":{sequence},"method":"{method}","params":{{}}}}"#
                    ),
                ),
                10,
            ));
            let completed = reassembler.push(chunk(
                ChunkDirection::Response,
                http_response(&format!(
                    r#"{{"jsonrpc":"2.0","id":{sequence},"result":{{}}}}"#
                )),
                20,
            ));
            assert_eq!(completed.len(), 1);
            assert_eq!(completed[0].interaction_type, "tool");
            assert_eq!(completed[0].traffic_role, "control");
        }
    }

    #[test]
    fn generic_http_tool_template_uses_shape_not_endpoint_and_links_result_time() {
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            custom_http_request(
                "POST",
                "/custom/tool/path",
                "changed-gateway.invalid",
                r#"{"instruction":"execute observed task","requested_by":"workflow-runtime"}"#,
            ),
            100,
        ));
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(
                r#"{"tool_call_id":"tool-http-1","status":"succeeded","result":"observed result","started_at_unix_ns":101,"finished_at_unix_ns":199}"#,
            ),
            200,
        ));

        assert_eq!(completed.len(), 1);
        let interaction = &completed[0];
        assert_eq!(interaction.interaction_type, "tool");
        assert_eq!(interaction.endpoint, "changed-gateway.invalid");
        assert_eq!(interaction.path, "/custom/tool/path");
        assert_eq!(
            interaction.wire_template_id.as_deref(),
            Some("generic-http-tool")
        );
        assert_eq!(interaction.parse_state, "parsed");
        assert_eq!(interaction.tool_calls.len(), 1);
        assert_eq!(interaction.tool_results.len(), 1);
        assert_eq!(interaction.tool_calls[0].tool_call_id, "tool-http-1");
        assert_eq!(interaction.tool_calls[0].name, "http.request");
        assert_eq!(
            interaction.tool_calls[0].arguments["instruction"],
            "execute observed task"
        );
        assert_eq!(interaction.tool_results[0].content, "observed result");
        assert!(!interaction.tool_results[0].is_error);
        assert_eq!(
            interaction.tool_calls[0].issued_at_unix_ns.as_deref(),
            Some("100")
        );
        assert_eq!(
            interaction.tool_results[0].observed_at_unix_ns.as_deref(),
            Some("200")
        );
    }

    #[test]
    fn code_sandbox_http_shape_emits_correlated_tool_call_and_result() {
        let request_body = r#"{"code":"print('fixture')","timeout_ms":4000}"#;
        let response_body = r#"{"execution_id":"sandbox-exec-1","exit_code":0,"stdout":"fixture\n","stderr":"","timed_out":false}"#;
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            correlated_http_request("/execute", "python-sandbox:8080", request_body),
            100,
        ));
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(response_body),
            200,
        ));

        assert_eq!(completed.len(), 1);
        let interaction = &completed[0];
        assert_eq!(interaction.interaction_type, "tool");
        assert_eq!(
            interaction.wire_template_id.as_deref(),
            Some("generic-http-tool")
        );
        assert_eq!(
            interaction.trace_id.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert_eq!(interaction.run_id.as_deref(), Some("run-fixture-1"));
        assert_eq!(interaction.session_id.as_deref(), Some("session-fixture-1"));
        assert_eq!(interaction.invocation_id.as_deref(), Some("run-fixture-1"));
        assert_eq!(interaction.tool_calls[0].tool_call_id, "sandbox-exec-1");
        assert_eq!(interaction.tool_calls[0].name, "http.code.execute");
        assert_eq!(interaction.tool_calls[0].arguments["timeout_ms"], 4000);
        assert_eq!(interaction.tool_results[0].content["stdout"], "fixture\n");
        assert!(!interaction.tool_results[0].is_error);
        assert!(!interaction.request.body.contains("must-not-export"));
    }

    #[test]
    fn forced_single_function_schema_is_model_output_not_a_real_tool() {
        let progress_request = r#"{
          "model":"fixture-model",
          "messages":[{"role":"user","content":"User goal:\ncreate a plan"}],
          "tools":[{"type":"function","function":{"name":"PlanCard","parameters":{"type":"object"}}}],
          "tool_choice":{"type":"function","function":{"name":"PlanCard"}}
        }"#;
        let progress_response = r#"{
          "choices":[{"finish_reason":"stop","message":{"role":"assistant","content":null,"tool_calls":[{
            "id":"call-plan","type":"function","function":{"name":"PlanCard","arguments":"{\"title\":\"fixture plan\"}"}
          }]}}]
        }"#;
        let mut progress = InteractionReassembler::default();
        progress.push(chunk(
            ChunkDirection::Request,
            correlated_http_request("/v1/chat/completions", "model-gateway", progress_request),
            100,
        ));
        let completed = progress.push(chunk(
            ChunkDirection::Response,
            http_response(progress_response),
            200,
        ));
        assert_eq!(completed.len(), 1);
        let interaction = &completed[0];
        assert!(interaction.tool_calls.is_empty());
        assert_eq!(interaction.conversation_completeness, "complete");
        assert_eq!(interaction.traffic_role, "conversation");
        assert_eq!(interaction.semantic_items.len(), 2);
        assert_eq!(interaction.semantic_items[0].kind, "user_message");
        assert_eq!(interaction.semantic_items[1].kind, "model_progress");
        assert_eq!(
            interaction.response.text.as_deref(),
            Some("{\"title\":\"fixture plan\"}")
        );

        let final_request = r#"{
          "model":"fixture-model",
          "messages":[{"role":"user","content":"Goal:\nfixture\n\nPlan card:\n{}\n\nSandbox stdout:\nfixture"}],
          "tools":[{"type":"function","function":{"name":"FinalReport","parameters":{"type":"object"}}}],
          "tool_choice":{"type":"function","function":{"name":"FinalReport"}}
        }"#;
        let final_response = r#"{
          "choices":[{"finish_reason":"stop","message":{"role":"assistant","content":null,"tool_calls":[{
            "id":"call-final","type":"function","function":{"name":"FinalReport","arguments":"{\"answer\":\"fixture final\"}"}
          }]}}]
        }"#;
        let mut final_reassembler = InteractionReassembler::default();
        final_reassembler.push(chunk(
            ChunkDirection::Request,
            correlated_http_request("/v1/chat/completions", "model-gateway", final_request),
            300,
        ));
        let completed = final_reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(final_response),
            400,
        ));
        let interaction = &completed[0];
        assert_eq!(
            interaction.request.messages[0].message_origin.as_deref(),
            Some("agent_context")
        );
        assert!(interaction.tool_calls.is_empty());
        assert_eq!(interaction.semantic_items.len(), 1);
        assert_eq!(interaction.semantic_items[0].actor, "model");
        assert_eq!(interaction.semantic_items[0].kind, "model_final");
        assert_eq!(interaction.response.text.as_deref(), Some("fixture final"));
    }

    #[test]
    fn wire_matching_uses_method_and_content_shape_but_not_url() {
        let headers = BTreeMap::new();
        assert!(match_wire_protocol(
            "GET",
            &headers,
            Some(&serde_json::json!({"model":"m","messages":[]})),
        )
        .is_none());
        assert!(match_wire_protocol(
            "POST",
            &headers,
            Some(&serde_json::json!({"operation":"health"})),
        )
        .is_none());
        let matched = match_wire_protocol(
            "POST",
            &headers,
            Some(&serde_json::json!({"model":"m","messages":[]})),
        )
        .unwrap();
        assert_eq!(matched.template_id, "openai-chat-completions");
    }

    #[test]
    fn request_line_detection_accepts_unknown_methods_without_widening_body_lane() {
        for prefix in [
            b"POST /v1/responses".as_slice(),
            b"PROPFIND /dav".as_slice(),
            b"M-SEARCH *".as_slice(),
        ] {
            assert!(looks_like_http_request_prefix(prefix));
            assert_eq!(
                classify_http_method_prefix(prefix),
                HTTP_METHOD_PREFIX_COMPLETE
            );
        }
        assert!(!looks_like_http_request_prefix(b"PROPFIND"));
        assert!(!looks_like_http_request_prefix(br#"{"model":"fixture"}"#));
        assert_eq!(
            classify_http_method_prefix(b"PROPFIND"),
            a3s_observer_common::HTTP_METHOD_PREFIX_INCOMPLETE
        );
    }

    #[test]
    fn model_search_backend_shape_is_technical_without_a_url_or_product_gate() {
        let request_body = r#"{
          "id":"search-request",
          "model":"fixture-model",
          "commands":[{"name":"search","arguments":{"query":"fixture"}}],
          "input":[{"role":"user","content":"conversation history copied by the backend"}],
          "settings":{"mode":"balanced"},
          "max_output_tokens":128
        }"#;
        let response_body = r#"{
          "encrypted_output":"opaque-fixture",
          "output":[],
          "results":[{"title":"fixture result"}]
        }"#;
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            custom_http_request(
                "POST",
                "/arbitrary/model-assisted-operation",
                "changed-gateway.invalid",
                request_body,
            ),
            10,
        ));
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(response_body),
            20,
        ));

        assert_eq!(completed.len(), 1);
        let interaction = &completed[0];
        assert_eq!(interaction.interaction_type, "model");
        assert_eq!(interaction.traffic_role, "tool_backend");
        assert_eq!(
            interaction.wire_template_id.as_deref(),
            Some("generic-model-search-backend")
        );
        assert_eq!(interaction.provider_response_id, None);
        assert_eq!(interaction.path, "/arbitrary/model-assisted-operation");
    }

    #[test]
    fn anthropic_session_title_request_is_derived_metadata() {
        let request_body = r#"{
          "model":"fixture-model",
          "max_tokens":64,
          "system":[{
            "type":"text",
            "text":"Generate a concise title. The session content is provided inside <session> tags. Return JSON with a single \"title\" field."
          }],
          "messages":[{
            "role":"user",
            "content":[{"type":"text","text":"<session>debug the fixture</session>"}]
          }],
          "output_config":{"format":{"type":"json_schema","schema":{"properties":{"title":{"type":"string"}}}}}
        }"#;
        let response_body = r#"{
          "id":"message-title-fixture",
          "type":"message",
          "role":"assistant",
          "content":[{"type":"text","text":"{\"title\":\"Debug fixture\"}"}],
          "stop_reason":"end_turn"
        }"#;
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            custom_http_request(
                "POST",
                "/arbitrary/messages",
                "changed-gateway.invalid",
                request_body,
            ),
            10,
        ));
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(response_body),
            20,
        ));

        assert_eq!(completed.len(), 1);
        let interaction = &completed[0];
        assert_eq!(interaction.traffic_role, "derived_metadata");
        assert_eq!(
            interaction.wire_template_id.as_deref(),
            Some("anthropic-messages")
        );
        assert_eq!(
            interaction.response.text.as_deref(),
            Some("{\"title\":\"Debug fixture\"}")
        );
    }

    #[test]
    fn an_old_tool_result_does_not_complete_a_new_tool_call() {
        let request_body = r#"{
          "type":"response.create",
          "model":"fixture-model",
          "input":[
            {"type":"function_call_output","call_id":"call-old","output":"old result"},
            {"type":"message","role":"user","content":"run the next command"}
          ]
        }"#;
        let response_body = r#"{
          "id":"resp-new-call",
          "object":"response",
          "status":"completed",
          "output":[{
            "type":"function_call",
            "call_id":"call-new",
            "name":"shell",
            "arguments":"{\"cmd\":\"pwd\"}"
          }]
        }"#;
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            custom_http_request(
                "POST",
                "/arbitrary/responses",
                "changed-gateway.invalid",
                request_body,
            ),
            10,
        ));
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(response_body),
            20,
        ));

        assert_eq!(completed.len(), 1);
        let interaction = &completed[0];
        assert_eq!(interaction.tool_results[0].tool_call_id, "call-old");
        assert_eq!(interaction.tool_calls[0].tool_call_id, "call-new");
        assert_eq!(interaction.conversation_completeness, "tool_pending");
        assert_eq!(interaction.completeness, "partial");
        assert_eq!(
            interaction.partial_reasons,
            vec!["tool_result_pending".to_string()]
        );
    }

    #[test]
    fn keep_alive_connection_emits_one_interaction_per_http_exchange() {
        let mut reassembler = InteractionReassembler::default();
        let request_a = http_request(r#"{"model":"m","messages":[{"role":"user","content":"a"}]}"#);
        let request_b = http_request(r#"{"model":"m","messages":[{"role":"user","content":"b"}]}"#);
        let response_a = http_response(r#"{"choices":[{"message":{"content":"A"}}]}"#);
        let response_b = http_response(r#"{"choices":[{"message":{"content":"B"}}]}"#);

        assert!(reassembler
            .push(chunk(
                ChunkDirection::Request,
                [request_a, request_b].concat(),
                10
            ))
            .is_empty());
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            [response_a, response_b].concat(),
            20,
        ));
        assert_eq!(completed.len(), 2);
        assert_ne!(completed[0].interaction_id, completed[1].interaction_id);
        assert_eq!(completed[0].response.text.as_deref(), Some("A"));
        assert_eq!(completed[1].response.text.as_deref(), Some("B"));
    }

    #[test]
    fn chunked_sse_reassembles_text_and_tool_call() {
        let request_body = r#"{"model":"gpt-test","input":"run tool"}"#;
        let sse = concat!(
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello \"}\n\n",
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"world\"}\n\n",
            "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call-1\",\"name\":\"shell\",\"arguments\":\"{\\\"cmd\\\":\\\"pwd\\\"}\"}}\n\n",
            "data: {\"type\":\"response.completed\"}\n\n",
            "data: [DONE]\n\n"
        );
        let chunks = [
            format!("{:X}\r\n{}\r\n", sse.len(), sse),
            "0\r\n\r\n".to_string(),
        ]
        .concat();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{chunks}"
        );
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            http_request(request_body),
            1,
        ));
        let completed = reassembler.push(chunk(ChunkDirection::Response, response.into_bytes(), 2));
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].response.text.as_deref(), Some("hello world"));
        assert_eq!(completed[0].tool_calls.len(), 1);
        assert_eq!(completed[0].tool_calls[0].tool_call_id, "call-1");
        assert_eq!(completed[0].tool_calls[0].name, "shell");
        assert_eq!(completed[0].tool_calls[0].arguments["cmd"], "pwd");
    }

    #[test]
    fn semantic_sse_terminal_completes_before_a_late_zero_chunk() {
        let first_request =
            r#"{"model":"gpt-test","messages":[{"role":"user","content":"first"}]}"#;
        let first_sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"first reply\"}}]}\n\n",
            "data: [DONE]\n\n"
        );
        let first_chunk = format!("{:x}\r\n{}\r\n", first_sse.len(), first_sse);
        let first_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{first_chunk}"
        );
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            http_request(first_request),
            1,
        ));
        let first = reassembler.push(chunk(
            ChunkDirection::Response,
            first_response.into_bytes(),
            2,
        ));
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].response.text.as_deref(), Some("first reply"));

        let second_request =
            r#"{"model":"gpt-test","messages":[{"role":"user","content":"second"}]}"#;
        let second_response =
            r#"{"choices":[{"message":{"role":"assistant","content":"second reply"}}]}"#;
        reassembler.push(chunk(
            ChunkDirection::Request,
            http_request(second_request),
            3,
        ));
        assert!(reassembler
            .push(chunk(ChunkDirection::Response, b"0\r\n\r\n".to_vec(), 4))
            .is_empty());
        let second = reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(second_response),
            5,
        ));
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].response.text.as_deref(), Some("second reply"));
    }

    #[test]
    fn idle_orphan_request_cannot_poison_a_later_response() {
        let request = r#"{"model":"gpt-test","messages":[{"role":"user","content":"orphan"}]}"#;
        let mut reassembler =
            InteractionReassembler::with_limits(8, 64 * 1024, Duration::from_millis(1));
        reassembler.push(chunk(ChunkDirection::Request, http_request(request), 1));
        reassembler.expire_idle(Instant::now() + Duration::from_millis(5));
        let response =
            r#"{"choices":[{"message":{"role":"assistant","content":"must not pair"}}]}"#;
        assert!(reassembler
            .push(chunk(ChunkDirection::Response, http_response(response), 2))
            .is_empty());
    }

    #[test]
    fn responses_output_item_done_exposes_final_assistant_text() {
        let request_body = r#"{"model":"gpt-test","conversation":"conv-1","previous_response_id":"resp-0","input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}]}"#;
        let sse = concat!(
            "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-1\"}}\n\n",
            "event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"final text\"}]}}\n\n",
            "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-1\"}}\n\n"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{}",
            sse.len(),
            sse
        );
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            http_request(request_body),
            1,
        ));
        let completed = reassembler.push(chunk(ChunkDirection::Response, response.into_bytes(), 2));
        assert_eq!(completed[0].response.text.as_deref(), Some("final text"));
        assert_eq!(
            completed[0].provider_conversation_id.as_deref(),
            Some("conv-1")
        );
        assert_eq!(completed[0].provider_response_id.as_deref(), Some("resp-1"));
        assert_eq!(
            completed[0].provider_previous_response_id.as_deref(),
            Some("resp-0")
        );
    }

    #[test]
    fn responses_custom_tool_input_delta_never_becomes_model_text() {
        let request_body = r#"{"model":"gpt-test","input":[{"role":"user","content":[{"type":"input_text","text":"<environment_context>injected</environment_context>"}]},{"role":"user","content":[{"type":"input_text","text":"run pwd"}]}]}"#;
        let sse = concat!(
            "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"id\":\"item-tool-1\",\"type\":\"custom_tool_call\",\"call_id\":\"call-tool-1\",\"name\":\"exec\",\"input\":\"\"}}\n\n",
            "data: {\"type\":\"response.custom_tool_call_input.delta\",\"output_index\":0,\"item_id\":\"item-tool-1\",\"delta\":\"tools.exec_command({\\\"cmd\\\":\\\"pwd\\\"})\"}\n\n",
            "data: {\"type\":\"response.custom_tool_call_input.done\",\"output_index\":0,\"item_id\":\"item-tool-1\",\"input\":\"tools.exec_command({\\\"cmd\\\":\\\"pwd\\\"})\"}\n\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-tool-1\"}}\n\n"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{}",
            sse.len(),
            sse
        );
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            http_request(request_body),
            1,
        ));
        let completed = reassembler.push(chunk(ChunkDirection::Response, response.into_bytes(), 2));

        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].response.text, None);
        assert_eq!(completed[0].tool_calls.len(), 1);
        assert_eq!(completed[0].tool_calls[0].tool_call_id, "call-tool-1");
        assert_eq!(completed[0].tool_calls[0].name, "exec");
        assert_eq!(
            completed[0].tool_calls[0].arguments,
            "tools.exec_command({\"cmd\":\"pwd\"})"
        );
        assert_eq!(completed[0].semantic_parser_version, 2);
        assert_eq!(
            completed[0]
                .semantic_items
                .iter()
                .map(|item| (item.actor.as_str(), item.kind.as_str()))
                .collect::<Vec<_>>(),
            vec![("user", "user_message"), ("tool", "tool_call")]
        );
    }

    #[test]
    fn anthropic_sse_keeps_text_separate_from_indexed_tool_arguments() {
        let request_body = r#"{"model":"claude-test","max_tokens":1024,"messages":[{"role":"user","content":"inspect files"}]}"#;
        let sse = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-1\",\"content\":[]}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"I will inspect. \"}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"Read\",\"input\":{}}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_2\",\"name\":\"Bash\",\"input\":{}}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"pwd\\\"}\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"file_path\\\":\\\"README.md\\\"}\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Done.\"}}\n\n",
            "data: {\"type\":\"message_stop\"}\n\n"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{}",
            sse.len(),
            sse
        );
        let mut reassembler = InteractionReassembler::default();
        let request = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: gateway.invalid\r\nanthropic-version: 2023-06-01\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            request_body.len(),
            request_body
        );
        reassembler.push(chunk(ChunkDirection::Request, request.into_bytes(), 1));
        let completed = reassembler.push(chunk(ChunkDirection::Response, response.into_bytes(), 2));

        assert_eq!(completed.len(), 1);
        assert_eq!(
            completed[0].response.text.as_deref(),
            Some("I will inspect. Done.")
        );
        assert_eq!(completed[0].tool_calls.len(), 2);
        let calls = completed[0]
            .tool_calls
            .iter()
            .map(|call| (call.tool_call_id.as_str(), &call.arguments))
            .collect::<HashMap<_, _>>();
        assert_eq!(calls["toolu_1"]["file_path"], "README.md");
        assert_eq!(calls["toolu_2"]["command"], "pwd");
        assert_eq!(
            completed[0]
                .semantic_items
                .iter()
                .map(|item| (item.actor.as_str(), item.kind.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("user", "user_message"),
                ("model", "model_progress"),
                ("tool", "tool_call"),
                ("tool", "tool_call"),
            ]
        );
    }

    #[test]
    fn chat_sse_tool_call_keeps_first_chunk_id_across_argument_deltas() {
        let request_body = r#"{"model":"gpt-test","messages":[{"role":"user","content":"read"}]}"#;
        let sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call-chat-1\",\"function\":{\"name\":\"read\",\"arguments\":\"\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"\",\"function\":{\"name\":\"\",\"arguments\":\"{\\\"path\\\":\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"a.txt\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: [DONE]\n\n"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{}",
            sse.len(),
            sse
        );
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            http_request(request_body),
            1,
        ));
        let completed = reassembler.push(chunk(ChunkDirection::Response, response.into_bytes(), 2));
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].tool_calls.len(), 1);
        assert_eq!(completed[0].tool_calls[0].tool_call_id, "call-chat-1");
        assert_eq!(completed[0].tool_calls[0].name, "read");
        assert_eq!(completed[0].tool_calls[0].arguments["path"], "a.txt");
    }

    #[test]
    fn tool_result_in_next_request_is_extracted() {
        let request_body = r#"{"model":"gpt-test","input":[{"type":"function_call_output","call_id":"call-1","output":"ok"}]}"#;
        let response_body =
            r#"{"output":[{"type":"message","content":[{"type":"output_text","text":"done"}]}]}"#;
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            http_request(request_body),
            10,
        ));
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(response_body),
            20,
        ));
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].tool_results.len(), 1);
        assert_eq!(completed[0].tool_results[0].tool_call_id, "call-1");
        assert_eq!(completed[0].tool_results[0].content, "ok");
    }

    #[test]
    fn anthropic_tool_result_is_tool_semantics_not_a_user_message() {
        let request_body = r#"{"model":"claude-test","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu-result-1","content":[{"type":"text","text":"command output"}]}]}]}"#;
        let request = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: gateway.invalid\r\nanthropic-version: 2023-06-01\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            request_body.len(),
            request_body
        );
        let response_body =
            r#"{"id":"msg-final","content":[{"type":"text","text":"final answer"}]}"#;
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(ChunkDirection::Request, request.into_bytes(), 10));
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(response_body),
            20,
        ));

        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].tool_results.len(), 1);
        assert_eq!(completed[0].tool_results[0].tool_call_id, "toolu-result-1");
        assert_eq!(completed[0].response.text.as_deref(), Some("final answer"));
        assert_eq!(
            completed[0]
                .semantic_items
                .iter()
                .map(|item| (item.actor.as_str(), item.kind.as_str()))
                .collect::<Vec<_>>(),
            vec![("tool", "tool_result"), ("model", "model_final")]
        );
    }

    #[test]
    fn final_multimodal_request_preserves_inline_and_reference_parts_only() {
        let request_body = r#"{"model":"gpt-test","messages":[{"role":"user","content":[{"type":"text","text":"inspect"},{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}},{"type":"input_file","file_id":"file-visible-to-model"}]}]}"#;
        let response_body = r#"{"choices":[{"message":{"content":"visible result"}}]}"#;
        let internal_rag = "INTERNAL_RAG_SENTINEL_NOT_SERIALIZED";
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            http_request(request_body),
            10,
        ));
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(response_body),
            20,
        ));

        assert_eq!(completed.len(), 1);
        let interaction = &completed[0];
        assert!(interaction.request.body.contains("data:image/png;base64"));
        assert!(interaction.request.body.contains("file-visible-to-model"));
        assert!(!interaction.request.body.contains(internal_rag));
        assert_eq!(interaction.request.messages.len(), 1);
        assert_eq!(
            interaction.request.messages[0].content[1]["type"],
            "image_url"
        );
        assert_eq!(interaction.response.text.as_deref(), Some("visible result"));
    }

    #[test]
    fn large_inline_multimodal_body_keeps_raw_evidence_without_duplicate_json_exports() {
        let inline_image = "A".repeat(600 * 1024);
        let request_body = serde_json::json!({
            "model": "gpt-test",
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "image_url",
                    "image_url": { "url": format!("data:image/png;base64,{inline_image}") }
                }]
            }]
        })
        .to_string();
        let mut reassembler = InteractionReassembler::default();
        let wire_request = http_request(&request_body);
        for (index, fragment) in wire_request.chunks(256 * 1024).enumerate() {
            let mut fragment = chunk(
                ChunkDirection::Request,
                fragment.to_vec(),
                10 + index as u128,
            );
            fragment.sequence = index as u64 + 1;
            assert!(reassembler.push(fragment).is_empty());
        }
        let completed = reassembler.push(chunk(
            ChunkDirection::Response,
            http_response(r#"{"choices":[{"message":{"content":"ok"}}]}"#),
            20,
        ));

        assert_eq!(completed.len(), 1);
        let request = &completed[0].request;
        assert_eq!(request.decoded_bytes as usize, request_body.len());
        assert_eq!(request.sha256, sha256_hex(request_body.as_bytes()));
        assert!(request.body.contains("data:image/png;base64,"));
        assert!(request.structured.is_none());
        assert!(request.messages.is_empty());
        assert_eq!(completed[0].completeness, "complete");
    }

    #[test]
    fn gzip_response_is_decoded_with_bounded_output() {
        let response_body = r#"{"choices":[{"message":{"content":"compressed"}}]}"#;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(response_body.as_bytes()).unwrap();
        let encoded = encoder.finish().unwrap();
        let response = [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                encoded.len()
            )
            .into_bytes(),
            encoded,
        ]
        .concat();
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            http_request(r#"{"model":"m","messages":[]}"#),
            1,
        ));
        let completed = reassembler.push(chunk(ChunkDirection::Response, response, 2));
        assert_eq!(completed[0].response.text.as_deref(), Some("compressed"));
        assert_eq!(completed[0].response.encoding, "utf8");
    }

    #[test]
    fn gzip_sse_without_content_length_uses_decoded_framing_and_keeps_raw_hash() {
        let sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"compressed \"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"sse\"}}]}\n\n",
            "data: [DONE]\n\n"
        );
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(sse.as_bytes()).unwrap();
        let encoded = encoder.finish().unwrap();
        let response = [
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\n\r\n"
                .to_vec(),
            encoded.clone(),
        ]
        .concat();
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            http_request(r#"{"model":"m","messages":[]}"#),
            1,
        ));
        let completed = reassembler.push(chunk(ChunkDirection::Response, response, 2));
        assert_eq!(completed.len(), 1);
        assert_eq!(
            completed[0].response.text.as_deref(),
            Some("compressed sse")
        );
        // Interaction content hashes the bounded decoded payload (the same representation shown
        // to the provider parser); the framing path above still consumed the compressed wire
        // bytes without requiring a Content-Length header.
        assert_eq!(completed[0].response.sha256, sha256_hex(sse.as_bytes()));
        assert_eq!(completed[0].completeness, "complete");
    }

    #[test]
    fn sse_event_limit_is_explicitly_partial_even_after_terminal() {
        let mut sse = String::new();
        for index in 0..=MAX_SSE_STRUCTURED_EVENTS {
            sse.push_str(&format!(
                "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{index} \"}}}}]}}\n\n"
            ));
        }
        sse.push_str("data: [DONE]\n\n");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{}",
            sse.len(),
            sse
        );
        let mut reassembler = InteractionReassembler::default();
        reassembler.push(chunk(
            ChunkDirection::Request,
            http_request(r#"{"model":"m","messages":[]}"#),
            1,
        ));
        let completed = reassembler.push(chunk(ChunkDirection::Response, response.into_bytes(), 2));
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].completeness, "partial");
        assert!(completed[0]
            .partial_reasons
            .iter()
            .any(|reason| reason == "sse_event_limit"));
    }

    #[test]
    fn unsupported_http2_emits_metadata_evidence_without_false_interaction() {
        let mut reassembler = InteractionReassembler::default();
        let completed = reassembler.push(chunk(
            ChunkDirection::Request,
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
            1,
        ));
        assert!(completed.is_empty());
        // Preface alone must not invent a semantic exchange; evidence may still record transport.
        let evidence = reassembler.take_evidence();
        assert!(evidence.iter().all(|item| item.encoding == "metadata_only"));
    }

    fn http2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut out = Vec::with_capacity(9 + len);
        out.push(((len >> 16) & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
        out.push(frame_type);
        out.push(flags);
        out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn http2_headers_and_data_yield_method_path_status_for_responses_rest() {
        let mut reassembler = InteractionReassembler::default();
        let request_headers = crate::h2_hpack::encode_headers(&[
            (":method", "POST"),
            (":path", "/v1/responses"),
            (":authority", "api.openai.com"),
            ("content-type", "application/json"),
        ]);
        let request_body = serde_json::json!({
            "model": "gpt-5",
            "input": [{"role": "user", "content": "HTTP2_RESPONSES_MARKER"}]
        })
        .to_string();
        let mut preface = HTTP2_CLIENT_PREFACE.to_vec();
        preface.extend(http2_frame(0x4, 0, 0, &[]));
        preface.extend(http2_frame(HTTP2_FRAME_HEADERS, 0x4, 1, &request_headers));
        preface.extend(http2_frame(HTTP2_FRAME_DATA, 0x1, 1, request_body.as_bytes()));
        assert!(reassembler
            .push(chunk(ChunkDirection::Request, preface, 10))
            .is_empty());

        let response_headers = crate::h2_hpack::encode_headers(&[
            (":status", "200"),
            ("content-type", "text/event-stream"),
        ]);
        let sse = concat!(
            "event: response.completed\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_h2\",\"status\":\"completed\"}}\n\n"
        );
        let mut response = http2_frame(HTTP2_FRAME_HEADERS, 0x4, 1, &response_headers);
        response.extend(http2_frame(HTTP2_FRAME_DATA, 0x1, 1, sse.as_bytes()));
        let completed = reassembler.push(chunk(ChunkDirection::Response, response, 20));
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].method, "POST");
        assert_eq!(completed[0].path, "/v1/responses");
        assert_eq!(completed[0].status_code, 200);
        assert_eq!(completed[0].transport_protocol, "http/2");
        assert_eq!(completed[0].endpoint, "api.openai.com");
        assert!(completed[0].request.body.contains("HTTP2_RESPONSES_MARKER"));
    }

    #[test]
    fn http2_hpack_desync_is_explicit_gap_without_panic() {
        let mut reassembler = InteractionReassembler::default();
        let mut frames = HTTP2_CLIENT_PREFACE.to_vec();
        frames.extend(http2_frame(
            HTTP2_FRAME_HEADERS,
            0x5,
            1,
            &[0xff, 0xff, 0xff, 0xff],
        ));
        let completed = reassembler.push(chunk(ChunkDirection::Request, frames, 1));
        assert!(completed.is_empty());
        let evidence = reassembler.take_evidence();
        assert!(evidence.iter().any(|item| {
            item.transport_protocol == "http/2"
                && item.reasons.iter().any(|reason| reason == "h2_hpack_desync")
        }));
    }

    #[test]
    fn websocket_upgrade_emits_once_per_connection_without_exporting_headers() {
        let mut reassembler = InteractionReassembler::default();
        let request = b"GET /custom/ws HTTP/1.1\r\nHost: gateway.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: must-not-export\r\n\r\n";
        assert!(reassembler
            .push(chunk(ChunkDirection::Request, request.to_vec(), 1))
            .is_empty());
        assert!(reassembler
            .push(chunk(ChunkDirection::Request, request.to_vec(), 2))
            .is_empty());
        let evidence = reassembler.take_evidence();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].transport_protocol, "websocket");
        assert!(evidence[0].redacted_sample.is_none());
    }

    #[test]
    fn quiescent_websocket_survives_the_short_http_idle_timeout() {
        let mut reassembler =
            InteractionReassembler::with_limits(8, 64 * 1024, Duration::from_millis(1));
        let upgrade = b"GET /v1/responses HTTP/1.1\r\nHost: gateway.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        reassembler.push(rustls_chunk_on(
            ChunkDirection::Request,
            upgrade,
            10,
            0x5100,
        ));
        reassembler.push(rustls_chunk_on(
            ChunkDirection::Response,
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            20,
            0x5200,
        ));
        assert_eq!(reassembler.active_connections(), 1);
        for state in reassembler.connections.values_mut() {
            state.last_activity = Instant::now() - Duration::from_secs(1);
            assert!(state.quiescent_websocket());
        }
        reassembler.expire_idle(Instant::now());
        assert_eq!(reassembler.active_connections(), 1);
    }

    #[test]
    fn websocket_frames_recover_after_handshake_state_is_missing() {
        let mut reassembler = InteractionReassembler::default();
        let request = serde_json::json!({
            "type": "response.create",
            "model": "fixture-model",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "RECOVERED_WEBSOCKET_REQUEST"}]}]
        })
        .to_string();
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Request,
                websocket_frame(request.as_bytes(), true, true, false, 0x1),
                100,
                0x6100,
            ))
            .is_empty());
        let evidence = reassembler.take_evidence();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].reasons, vec!["websocket_handshake_recovered"]);

        let delta = serde_json::json!({
            "type": "response.output_text.delta",
            "delta": "RECOVERED_WEBSOCKET_RESPONSE"
        })
        .to_string();
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Response,
                websocket_frame(delta.as_bytes(), false, true, false, 0x1),
                200,
                0x6200,
            ))
            .is_empty());
        let terminal = serde_json::json!({
            "type": "response.completed",
            "response": {
                "id": "resp-recovered",
                "usage": {
                    "input_tokens": 120,
                    "output_tokens": 30,
                    "total_tokens": 150,
                    "input_tokens_details": {"cached_tokens": 40},
                    "output_tokens_details": {"reasoning_tokens": 12}
                }
            }
        })
        .to_string();
        let completed = reassembler.push(rustls_chunk_on(
            ChunkDirection::Response,
            websocket_frame(terminal.as_bytes(), false, true, false, 0x1),
            210,
            0x6201,
        ));
        assert_eq!(completed.len(), 1);
        assert!(completed[0]
            .request
            .body
            .contains("RECOVERED_WEBSOCKET_REQUEST"));
        assert_eq!(
            completed[0].response.text.as_deref(),
            Some("RECOVERED_WEBSOCKET_RESPONSE")
        );
        let usage = completed[0].usage.as_ref().unwrap();
        assert_eq!(usage.input_tokens, Some(120));
        assert_eq!(usage.output_tokens, Some(30));
        assert_eq!(usage.total_tokens, Some(150));
        assert_eq!(usage.cached_input_tokens, Some(40));
        assert_eq!(usage.reasoning_output_tokens, Some(12));
        assert!(!usage.total_tokens_derived);
    }

    #[test]
    fn websocket_response_frames_recover_without_client_request() {
        let mut reassembler = InteractionReassembler::default();
        let delta = serde_json::json!({
            "type": "response.output_text.delta",
            "delta": "RESPONSE_ONLY_RECOVERED_MARKER"
        })
        .to_string();
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Response,
                websocket_frame(delta.as_bytes(), false, true, false, 0x1),
                300,
                0x7100,
            ))
            .is_empty());
        let evidence = reassembler.take_evidence();
        assert!(evidence.iter().any(|item| {
            item.reasons
                .iter()
                .any(|reason| reason == "websocket_handshake_recovered")
        }));
        let terminal = serde_json::json!({
            "type": "response.completed",
            "response": {
                "id": "resp-response-only",
                "usage": {
                    "input_tokens": 11,
                    "output_tokens": 7,
                    "total_tokens": 18
                }
            }
        })
        .to_string();
        let completed = reassembler.push(rustls_chunk_on(
            ChunkDirection::Response,
            websocket_frame(terminal.as_bytes(), false, true, false, 0x1),
            310,
            0x7101,
        ));
        assert_eq!(completed.len(), 1);
        assert!(completed[0]
            .partial_reasons
            .iter()
            .any(|reason| reason == "websocket_request_missing_recovered"));
        assert_eq!(
            completed[0].response.text.as_deref(),
            Some("RESPONSE_ONLY_RECOVERED_MARKER")
        );
    }

    #[test]
    fn websocket_midstream_resync_skips_prefix_garbage_after_recovery() {
        let mut reassembler = InteractionReassembler::default();
        let delta = serde_json::json!({
            "type": "response.output_text.delta",
            "delta": "RESYNCED_MARKER"
        })
        .to_string();
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Response,
                websocket_frame(delta.as_bytes(), false, true, false, 0x1),
                400,
                0x8100,
            ))
            .is_empty());
        let terminal = serde_json::json!({
            "type": "response.completed",
            "response": {
                "id": "resp-resync",
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}
            }
        })
        .to_string();
        let frame = websocket_frame(terminal.as_bytes(), false, true, false, 0x1);
        // Reserved RSV bits force a decode error so midstream resync can skip to the real frame.
        let mut garbage_then_frame = vec![0x30, 0x01, 0xaa, 0xbb];
        garbage_then_frame.extend_from_slice(&frame);
        let completed = reassembler.push(rustls_chunk_on(
            ChunkDirection::Response,
            garbage_then_frame,
            410,
            0x8100,
        ));
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].response.text.as_deref(), Some("RESYNCED_MARKER"));
        assert!(completed[0]
            .partial_reasons
            .iter()
            .any(|reason| reason == "websocket_midstream_resync"));
    }

    #[test]
    fn streaming_usage_merges_cumulative_provider_counters_without_summing_events() {
        let value = serde_json::json!([
            {"type": "message_start", "message": {"usage": {
                "input_tokens": 80,
                "output_tokens": 1,
                "cache_read_input_tokens": 20,
                "cache_creation_input_tokens": 5
            }}},
            {"type": "message_delta", "usage": {"output_tokens": 11}},
            {"type": "message_delta", "usage": {"output_tokens": 19}}
        ]);
        let usage = extract_provider_token_usage(&value).unwrap();
        assert_eq!(usage.input_tokens, Some(80));
        assert_eq!(usage.output_tokens, Some(19));
        assert_eq!(usage.total_tokens, Some(99));
        assert_eq!(usage.cached_input_tokens, Some(20));
        assert_eq!(usage.cache_creation_input_tokens, Some(5));
        assert!(usage.total_tokens_derived);
        assert_eq!(usage.completeness, "complete");
    }

    #[test]
    fn websocket_permessage_deflate_reassembles_model_tool_and_result_timeline() {
        let mut reassembler = InteractionReassembler::default();
        let handshake_write = 0x1000;
        let handshake_read = 0x2000;
        let application_connection = 0x3000;
        let upgrade = b"GET /custom/responses?credential=must-not-export HTTP/1.1\r\nHost: gateway.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Extensions: permessage-deflate\r\nSec-WebSocket-Key: must-not-export\r\n\r\n";
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Request,
                upgrade,
                10,
                handshake_write,
            ))
            .is_empty());
        let switching = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n";
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Response,
                switching,
                20,
                handshake_read,
            ))
            .is_empty());

        let mut client_compressor = Compress::new(Compression::fast(), false);
        let mut server_compressor = Compress::new(Compression::fast(), false);
        let request = serde_json::json!({
            "type": "response.create",
            "model": "fixture-model",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "WEBSOCKET_REQUEST_SENTINEL"}]}],
            "tools": [{"type": "function", "name": "shell"}]
        })
        .to_string();
        let request_frame =
            compressed_websocket_frame(&mut client_compressor, request.as_bytes(), true);
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Request,
                request_frame[..11].to_vec(),
                100,
                application_connection,
            ))
            .is_empty());
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Request,
                request_frame[11..].to_vec(),
                110,
                application_connection,
            ))
            .is_empty());

        for (at, event) in [
            (
                200,
                serde_json::json!({"type": "response.created", "response": {"id": "resp-ws-1"}}),
            ),
            (
                210,
                serde_json::json!({"type": "response.output_text.delta", "delta": "visible reply"}),
            ),
            (
                215,
                serde_json::json!({
                    "type": "response.output_item.added",
                    "item": {"type": "custom_tool_call", "call_id": "call-ws-1", "name": "shell", "input": ""}
                }),
            ),
            (
                220,
                serde_json::json!({
                    "type": "response.output_item.done",
                    "item": {"type": "custom_tool_call", "call_id": "call-ws-1", "name": "shell", "input": "{\"cmd\":\"pwd\"}"}
                }),
            ),
        ] {
            let frame = compressed_websocket_frame(
                &mut server_compressor,
                event.to_string().as_bytes(),
                false,
            );
            if at == 210 {
                assert!(reassembler
                    .push(rustls_chunk_on(
                        ChunkDirection::Response,
                        frame[..7].to_vec(),
                        at,
                        application_connection,
                    ))
                    .is_empty());
                assert!(reassembler
                    .push(rustls_chunk_on(
                        ChunkDirection::Response,
                        frame[7..].to_vec(),
                        at + 1,
                        application_connection,
                    ))
                    .is_empty());
            } else {
                assert!(reassembler
                    .push(rustls_chunk_on(
                        ChunkDirection::Response,
                        frame,
                        at,
                        application_connection,
                    ))
                    .is_empty());
            }
        }
        let terminal = serde_json::json!({
            "type": "response.completed",
            "response": {"id": "resp-ws-1"}
        })
        .to_string();
        let completed = reassembler.push(rustls_chunk_on(
            ChunkDirection::Response,
            compressed_websocket_frame(&mut server_compressor, terminal.as_bytes(), false),
            230,
            application_connection,
        ));
        assert_eq!(completed.len(), 1);
        let first = &completed[0];
        assert_eq!(first.transport_protocol, "websocket");
        assert_eq!(first.protocol, "websocket-json");
        assert_eq!(first.tls_adapter_id, "rustls-payload");
        assert_eq!(first.endpoint, "gateway.invalid");
        assert_eq!(first.path, "/custom/responses");
        assert!(first.request.body.contains("WEBSOCKET_REQUEST_SENTINEL"));
        assert!(!first.request.body.contains("must-not-export"));
        assert_eq!(first.response.text.as_deref(), Some("visible reply"));
        assert_eq!(first.started_at_unix_ns, "100");
        assert_eq!(first.request_complete_at_unix_ns, "110");
        assert_eq!(first.first_response_at_unix_ns, "200");
        assert_eq!(first.ended_at_unix_ns, "230");
        assert_eq!(first.tool_calls.len(), 1);
        assert_eq!(first.tool_calls[0].tool_call_id, "call-ws-1");
        assert_eq!(
            first.tool_calls[0].issued_at_unix_ns.as_deref(),
            Some("220")
        );

        let tool_result_request = serde_json::json!({
            "type": "response.create",
            "model": "fixture-model",
            "input": [{"type": "custom_tool_call_output", "call_id": "call-ws-1", "output": "pwd-result"}]
        })
        .to_string();
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Request,
                compressed_websocket_frame(
                    &mut client_compressor,
                    tool_result_request.as_bytes(),
                    true,
                ),
                300,
                application_connection,
            ))
            .is_empty());
        let output = serde_json::json!({
            "type": "response.output_text.delta",
            "delta": "tool observed"
        })
        .to_string();
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Response,
                compressed_websocket_frame(&mut server_compressor, output.as_bytes(), false),
                310,
                application_connection,
            ))
            .is_empty());
        let terminal = serde_json::json!({"type": "response.completed"}).to_string();
        let completed = reassembler.push(rustls_chunk_on(
            ChunkDirection::Response,
            compressed_websocket_frame(&mut server_compressor, terminal.as_bytes(), false),
            320,
            application_connection,
        ));
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].tool_results.len(), 1);
        assert_eq!(completed[0].tool_results[0].tool_call_id, "call-ws-1");
        assert_eq!(
            completed[0].tool_results[0].observed_at_unix_ns.as_deref(),
            Some("300")
        );
        assert_eq!(completed[0].response.text.as_deref(), Some("tool observed"));
    }

    #[test]
    fn rustls_moved_pointers_with_competing_websockets_remain_ambiguous() {
        let mut reassembler = InteractionReassembler::default();
        let upgrade = |path: &str| {
            format!(
                "GET {path} HTTP/1.1\r\nHost: gateway.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
            )
        };
        let switching = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n";

        for (at, write_pointer, read_pointer, path) in [
            (10, 0x1000, 0x1100, "/older"),
            (20, 0x2000, 0x2100, "/v1/responses"),
        ] {
            assert!(reassembler
                .push(rustls_chunk_on(
                    ChunkDirection::Request,
                    upgrade(path),
                    at,
                    write_pointer,
                ))
                .is_empty());
            assert!(reassembler
                .push(rustls_chunk_on(
                    ChunkDirection::Response,
                    switching,
                    at + 1,
                    read_pointer,
                ))
                .is_empty());
        }

        let mut client_compressor = Compress::new(Compression::fast(), false);
        let request = serde_json::json!({
            "type": "response.create",
            "model": "fixture-model",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "MOVED_POINTER_REQUEST"}]}]
        })
        .to_string();
        let request_frame =
            compressed_websocket_frame(&mut client_compressor, request.as_bytes(), true);
        let split = request_frame.len() / 2;
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Request,
                request_frame[..split].to_vec(),
                100,
                0x3000,
            ))
            .is_empty());
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Request,
                request_frame[split..].to_vec(),
                101,
                0x3001,
            ))
            .is_empty());

        // Both active streams are equally plausible and the frame is compressed, so there is no
        // non-destructive payload identity probe.  The resolver must not choose the newest stream
        // (or either pointer) merely by recency.
        let evidence = reassembler.take_evidence();
        assert!(evidence.iter().any(|item| {
            item.reasons
                .iter()
                .any(|reason| reason == "ambiguous_stream_binding")
        }));
        assert!(reassembler.metrics().ambiguous_stream_bindings >= 1);
        assert!(
            !reassembler.connection_aliases.contains_key(&ConnectionKey {
                cgroup_id: 7,
                pid: 42,
                connection_id: 0x3000,
            })
        );

        let text_event = serde_json::json!({
            "type": "response.output_text.delta",
            "delta": "MOVED_POINTER_RESPONSE"
        })
        .to_string();
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Response,
                websocket_frame(text_event.as_bytes(), false, true, false, 0x1),
                200,
                0x4000,
            ))
            .is_empty());

        let terminal = serde_json::json!({
            "type": "response.completed",
            "response": {"id": "resp-moved-pointer"}
        })
        .to_string();
        let terminal_bytes = terminal.as_bytes();
        let terminal_split = terminal_bytes.len() / 2;
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Response,
                websocket_frame(&terminal_bytes[..terminal_split], false, false, false, 0x1,),
                210,
                0x4001,
            ))
            .is_empty());
        let completed = reassembler.push(rustls_chunk_on(
            ChunkDirection::Response,
            websocket_frame(&terminal_bytes[terminal_split..], false, true, false, 0x0),
            211,
            0x4002,
        ));
        // The provisional stream may still be framed when later fragments make its lifecycle
        // complete.  Preserve that exchange, but keep the ambiguity visible instead of claiming
        // a definitive owner or silently assigning it to the newest WebSocket.
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].completeness, "partial");
        assert_eq!(completed[0].connection_id, "tls:3000");
        assert!(completed[0]
            .partial_reasons
            .iter()
            .any(|reason| reason == "ambiguous_stream_binding"));
    }

    #[test]
    fn rustls_moved_pointer_binds_when_a_unique_session_anchor_matches() {
        let mut reassembler = InteractionReassembler::default();
        let upgrade = |path: &str| {
            format!(
                "GET {path} HTTP/1.1\r\nHost: gateway.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            )
        };
        let switching = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        for (at, write_pointer, read_pointer, path) in [
            (10, 0x1000, 0x1100, "/older"),
            (20, 0x2000, 0x2100, "/target"),
        ] {
            reassembler.push(rustls_chunk_on(
                ChunkDirection::Request,
                upgrade(path),
                at,
                write_pointer,
            ));
            reassembler.push(rustls_chunk_on(
                ChunkDirection::Response,
                switching,
                at + 1,
                read_pointer,
            ));
        }

        let request = serde_json::json!({
            "type": "response.create",
            "model": "fixture-model",
            "client_metadata": {"session_id": "session-target"},
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "seed"}]}]
        })
        .to_string();
        // The original pointer is an explicit owner, so this seeds identity evidence on the
        // target stream without relying on timing or endpoint names.
        reassembler.push(rustls_chunk_on(
            ChunkDirection::Request,
            websocket_frame(request.as_bytes(), true, true, false, 0x1),
            100,
            0x2000,
        ));
        reassembler.push(rustls_chunk_on(
            ChunkDirection::Response,
            websocket_frame(
                serde_json::json!({"type": "response.output_text.delta", "delta": "seed-reply"})
                    .to_string()
                    .as_bytes(),
                false,
                true,
                false,
                0x1,
            ),
            110,
            0x2100,
        ));
        let seed_done = reassembler.push(rustls_chunk_on(
            ChunkDirection::Response,
            websocket_frame(
                serde_json::json!({
                    "type": "response.completed",
                    "response": {"id": "response-seed"}
                })
                .to_string()
                .as_bytes(),
                false,
                true,
                false,
                0x1,
            ),
            120,
            0x2100,
        ));
        assert_eq!(seed_done.len(), 1);

        let resumed = serde_json::json!({
            "type": "response.create",
            "model": "fixture-model",
            "client_metadata": {"session_id": "session-target"},
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "resumed"}]}]
        })
        .to_string();
        // The new pointer is ambiguous by recency, but the explicit session anchor uniquely
        // matches the target stream and is therefore safe to alias.
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Request,
                websocket_frame(resumed.as_bytes(), true, true, false, 0x1),
                200,
                0x3000,
            ))
            .is_empty());
        assert_eq!(
            reassembler
                .connection_aliases
                .get(&ConnectionKey {
                    cgroup_id: 7,
                    pid: 42,
                    connection_id: 0x3000,
                })
                .map(|key| key.connection_id),
            Some(0x2000)
        );
        reassembler.push(rustls_chunk_on(
            ChunkDirection::Response,
            websocket_frame(
                serde_json::json!({"type": "response.output_text.delta", "delta": "resumed-reply"})
                    .to_string()
                    .as_bytes(),
                false,
                true,
                false,
                0x1,
            ),
            210,
            0x4000,
        ));
        let completed = reassembler.push(rustls_chunk_on(
            ChunkDirection::Response,
            websocket_frame(
                serde_json::json!({"type": "response.completed"})
                    .to_string()
                    .as_bytes(),
                false,
                true,
                false,
                0x1,
            ),
            220,
            0x4001,
        ));
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].connection_id, "tls:2000");
        assert_eq!(
            completed[0].provider_conversation_id.as_deref(),
            Some("session-target")
        );
        assert_eq!(completed[0].response.text.as_deref(), Some("resumed-reply"));
    }

    #[test]
    fn websocket_control_frames_do_not_steal_a_resumed_threads_moved_pointer() {
        let mut reassembler = InteractionReassembler::default();
        let upgrade = |path: &str| {
            format!(
                "GET {path} HTTP/1.1\r\nHost: gateway.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            )
        };
        let switching = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

        for (at, write_pointer, read_pointer, path) in [
            (10, 0x1000, 0x1100, "/older-thread"),
            (20, 0x2000, 0x2100, "/resumed-thread"),
        ] {
            reassembler.push(rustls_chunk_on(
                ChunkDirection::Request,
                upgrade(path),
                at,
                write_pointer,
            ));
            reassembler.push(rustls_chunk_on(
                ChunkDirection::Response,
                switching,
                at + 1,
                read_pointer,
            ));
        }

        // A server ping on the older idle Thread is transport liveness only. It must not make
        // that Thread the preferred owner of a later, moved Rustls application pointer.
        reassembler.push(rustls_chunk_on(
            ChunkDirection::Response,
            websocket_frame(b"ping", false, true, false, 0x9),
            30,
            0x1100,
        ));
        let connection_count = reassembler.active_connections();
        reassembler.push(rustls_chunk_on(
            ChunkDirection::Response,
            websocket_frame(b"orphan-ping", false, true, false, 0x9),
            31,
            0x9900,
        ));
        assert_eq!(reassembler.active_connections(), connection_count);

        let request = serde_json::json!({
            "type": "response.create",
            "model": "fixture-model",
            "client_metadata": {
                "session_id": "resumed-session",
                "thread_id": "resumed-session",
                "turn_id": "resumed-turn"
            },
            "input": [{
                "id": "msg-resumed",
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "resumed request"}],
                "internal_chat_message_metadata_passthrough": {
                    "content_item_kinds": ["user.text"]
                }
            }]
        })
        .to_string();
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Request,
                websocket_frame(request.as_bytes(), true, true, false, 0x1),
                40,
                0x3000,
            ))
            .is_empty());
        let delta = serde_json::json!({
            "type": "response.output_text.delta",
            "delta": "resumed response"
        })
        .to_string();
        assert!(reassembler
            .push(rustls_chunk_on(
                ChunkDirection::Response,
                websocket_frame(delta.as_bytes(), false, true, false, 0x1),
                50,
                0x4000,
            ))
            .is_empty());
        let terminal = serde_json::json!({
            "type": "response.completed",
            "response": {"id": "resp-resumed"}
        })
        .to_string();
        let completed = reassembler.push(rustls_chunk_on(
            ChunkDirection::Response,
            websocket_frame(terminal.as_bytes(), false, true, false, 0x1),
            60,
            0x4001,
        ));

        assert_eq!(completed.len(), 1);
        // The request was kept in a provisional observed-pointer stream because two canonical
        // WebSockets competed.  It may be decoded locally, but it must remain visibly partial and
        // must not be rewritten as either canonical stream by recency.
        assert_eq!(completed[0].connection_id, "tls:3000");
        assert!(completed[0]
            .partial_reasons
            .iter()
            .any(|reason| reason == "ambiguous_stream_binding"));
        assert_eq!(completed[0].path, "/v1/responses");
        assert_eq!(
            completed[0].provider_conversation_id.as_deref(),
            Some("resumed-session")
        );
        assert_eq!(
            completed[0].response.text.as_deref(),
            Some("resumed response")
        );
    }

    #[test]
    fn invalid_utf8_body_is_base64_not_lossy() {
        let content = make_content(
            &[0xff, 0x00, 0x7f],
            3,
            "application/octet-stream",
            None,
            Vec::new(),
            None,
            "complete",
        );
        assert_eq!(content.encoding, "base64");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(content.body)
                .unwrap(),
            vec![0xff, 0x00, 0x7f]
        );
    }

    #[test]
    fn reassembly_eviction_and_sequence_gap_are_counted_without_global_clear() {
        let mut reassembler =
            InteractionReassembler::with_limits(3, 64 * 1024, Duration::from_secs(1));
        let mut first = chunk(
            ChunkDirection::Request,
            custom_http_request(
                "POST",
                "/v1/chat/completions",
                "one.local",
                r#"{"model":"m","messages":[{"role":"user","content":"a"}]}"#,
            ),
            1,
        );
        first.connection_id = 1;
        reassembler.push(first);
        let mut second = chunk(
            ChunkDirection::Request,
            custom_http_request(
                "POST",
                "/v1/chat/completions",
                "two.local",
                r#"{"model":"m","messages":[{"role":"user","content":"b"}]}"#,
            ),
            2,
        );
        second.connection_id = 2;
        reassembler.push(second);

        let mut third = chunk(
            ChunkDirection::Request,
            custom_http_request(
                "POST",
                "/v1/chat/completions",
                "three.local",
                r#"{"model":"m","messages":[{"role":"user","content":"c"}]}"#,
            ),
            3,
        );
        third.connection_id = 3;
        reassembler.push(third);
        let mut fourth = chunk(
            ChunkDirection::Request,
            custom_http_request(
                "POST",
                "/v1/chat/completions",
                "four.local",
                r#"{"model":"m","messages":[{"role":"user","content":"d"}]}"#,
            ),
            4,
        );
        fourth.connection_id = 4;
        reassembler.push(fourth);
        assert!(reassembler.metrics().connection_evictions >= 1);
        let mut response1 = chunk(
            ChunkDirection::Response,
            http_response(r#"{"choices":[{"message":{"content":"ok"}}]}"#),
            5,
        );
        response1.connection_id = 3;
        response1.sequence = 4;
        reassembler.push(response1);
        let mut gap2 = chunk(ChunkDirection::Response, b"\r\n".to_vec(), 6);
        gap2.connection_id = 3;
        gap2.sequence = 9;
        reassembler.push(gap2);
        assert!(reassembler.metrics().sequence_gaps >= 1);
        assert!(!reassembler.take_evidence().is_empty());
    }
}
