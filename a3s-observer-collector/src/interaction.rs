//! Bounded HTTP/1.x and SSE reconstruction for plaintext captured at TLS or TCP boundaries.
//!
//! The eBPF hot path only copies bytes. This module owns framing, decompression, provider-neutral
//! message/tool extraction, request-response pairing, and explicit completeness. It intentionally
//! receives no authorization headers in its output contract.

use a3s_observer::{
    LlmInteractionContent, LlmInteractionMessage, LlmInteractionToolCall, LlmInteractionToolResult,
};
use base64::Engine as _;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Read;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const DEFAULT_MAX_CONNECTIONS: usize = 2_048;
const DEFAULT_MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_HEADERS: usize = 96;
const MAX_SSE_STRUCTURED_EVENTS: usize = 2_048;
const MAX_EXPORTED_STRUCTURED_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    pub partial_reasons: Vec<String>,
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
    pub started_at_unix_ns: String,
    pub request_complete_at_unix_ns: String,
    pub first_response_at_unix_ns: String,
    pub ended_at_unix_ns: String,
    pub duration_ns: String,
    pub time_quality: String,
    pub request: LlmInteractionContent,
    pub response: LlmInteractionContent,
    pub tool_calls: Vec<LlmInteractionToolCall>,
    pub tool_results: Vec<LlmInteractionToolResult>,
    pub completeness: String,
    pub partial_reasons: Vec<String>,
    pub capture_source: String,
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ConnectionKey {
    cgroup_id: u64,
    pid: u32,
    connection_id: u64,
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
                    self.buffer_started_at_unix_ns =
                        (!self.buffer.is_empty()).then_some(event_at_unix_ns);
                    if self.buffer.is_empty() {
                        break;
                    }
                }
            }
            let decoded = match decode_http_message(self.kind, &self.buffer, self.max_bytes) {
                Ok(Some(decoded)) => decoded,
                Ok(None) => break,
                Err(reason) => {
                    self.last_decode_error = Some(reason.clone());
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
            });
            self.buffer.drain(..decoded.consumed);
            self.buffer_started_at_unix_ns = (!self.buffer.is_empty()).then_some(event_at_unix_ns);
        }
        messages
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
struct ConnectionState {
    requests: HttpStreamDecoder,
    responses: HttpStreamDecoder,
    pending_requests: VecDeque<HttpMessage>,
    sequence: u64,
    last_request_sequence: u64,
    last_response_sequence: u64,
    source: String,
    adapter_id: String,
    evidence_fingerprints: HashSet<String>,
    last_activity: Instant,
}

impl ConnectionState {
    fn new(max_body_bytes: usize, source: String, adapter_id: String) -> Self {
        Self {
            requests: HttpStreamDecoder::new(StreamKind::Request, max_body_bytes),
            responses: HttpStreamDecoder::new(StreamKind::Response, max_body_bytes),
            pending_requests: VecDeque::new(),
            sequence: 0,
            last_request_sequence: 0,
            last_response_sequence: 0,
            source,
            adapter_id,
            evidence_fingerprints: HashSet::new(),
            last_activity: Instant::now(),
        }
    }

    fn idle(&self, now: Instant, timeout: Duration) -> bool {
        now.saturating_duration_since(self.last_activity) >= timeout
    }
}

/// Single-writer, bounded reassembler. The Collector owns one instance and feeds reordered
/// plaintext fragments into it, so no lock is needed on the protocol path.
#[derive(Debug)]
pub struct InteractionReassembler {
    connections: HashMap<ConnectionKey, ConnectionState>,
    pending_evidence: VecDeque<CompletedPlaintextEvidence>,
    max_connections: usize,
    max_body_bytes: usize,
    idle_timeout: Duration,
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
            pending_evidence: VecDeque::new(),
            max_connections: max_connections.max(1),
            max_body_bytes: max_body_bytes.max(4 * 1024),
            idle_timeout,
        }
    }

    pub fn push(&mut self, mut chunk: PlaintextChunk) -> Vec<CompletedInteraction> {
        self.evict_if_needed();
        let key = ConnectionKey::from(&chunk);
        let state = self.connections.entry(key).or_insert_with(|| {
            ConnectionState::new(
                self.max_body_bytes,
                chunk.source.clone(),
                chunk.adapter_id.clone(),
            )
        });
        state.last_activity = Instant::now();
        if state.source != chunk.source {
            state.source = format!("{}+{}", state.source, chunk.source);
        }
        if state.adapter_id != chunk.adapter_id {
            state.adapter_id = format!("{}+{}", state.adapter_id, chunk.adapter_id);
        }
        if let Some(evidence) = plaintext_transport_evidence(key, state, &chunk) {
            if self.pending_evidence.len() >= self.max_connections {
                self.pending_evidence.pop_front();
            }
            self.pending_evidence.push_back(evidence);
        }

        let previous_sequence = match chunk.direction {
            ChunkDirection::Request => &mut state.last_request_sequence,
            ChunkDirection::Response => &mut state.last_response_sequence,
        };
        if *previous_sequence != 0 && chunk.sequence != previous_sequence.wrapping_add(1) {
            extend_unique(
                &mut chunk.partial_reasons,
                ["fragment_sequence_gap".to_string()],
            );
        }
        *previous_sequence = chunk.sequence;

        let completed = match chunk.direction {
            ChunkDirection::Request => {
                let body_only =
                    if chunk.source.contains("rustls") && state.requests.buffer.is_empty() {
                        body_only_llm_request(
                            &chunk.data,
                            chunk.event_at_unix_ns,
                            &chunk.partial_reasons,
                        )
                    } else {
                        None
                    };
                if let Some(request) = body_only {
                    state.pending_requests.push_back(request);
                } else {
                    for request in state.requests.push(
                        &chunk.data,
                        chunk.event_at_unix_ns,
                        &chunk.partial_reasons,
                    ) {
                        state.pending_requests.push_back(request);
                    }
                }
                Vec::new()
            }
            ChunkDirection::Response => {
                let mut completed = Vec::new();
                for response in state.responses.push(
                    &chunk.data,
                    chunk.event_at_unix_ns,
                    &chunk.partial_reasons,
                ) {
                    // Informational responses do not consume the request they precede.
                    if response_status(&response.start_line)
                        .is_some_and(|status| (100..200).contains(&status))
                    {
                        continue;
                    }
                    let Some(request) = state.pending_requests.pop_front() else {
                        continue;
                    };
                    state.sequence = state.sequence.wrapping_add(1);
                    if let Some(interaction) = build_interaction(
                        key,
                        state.sequence,
                        &state.source,
                        &state.adapter_id,
                        request,
                        response,
                    ) {
                        completed.push(interaction);
                    }
                }
                completed
            }
        };
        if interaction_diagnostics_enabled() {
            // A streaming response can produce hundreds of TLS fragments in a few
            // milliseconds. Keep per-fragment state available for targeted debugging,
            // but never put it on the default operational INFO path: a slow container
            // log sink must not be able to back-pressure or terminate the collector.
            tracing::debug!(
                pid = chunk.pid,
                connection_id = format_args!("{:x}", chunk.connection_id),
                direction = ?chunk.direction,
                fragment_kind = plaintext_fragment_kind(&chunk.data),
                fragment_bytes = chunk.data.len(),
                request_buffer_bytes = state.requests.buffer.len(),
                response_buffer_bytes = state.responses.buffer.len(),
                pending_requests = state.pending_requests.len(),
                request_decode_error = ?state.requests.last_decode_error,
                response_decode_error = ?state.responses.last_decode_error,
                completed_interactions = completed.len(),
                "Agent interaction reassembly state"
            );
        }
        completed
    }

    /// Remove idle state even when a request or response is incomplete. Retaining an orphaned
    /// request across a later keep-alive reuse can pair a new response with the wrong Agent turn,
    /// which is worse than explicitly losing the incomplete exchange. Coverage/drop telemetry is
    /// the authority for that missing record; completed evidence is never fabricated.
    pub fn expire_idle(&mut self, now: Instant) {
        let timeout = self.idle_timeout;
        self.connections.retain(|key, state| {
            let retain = !state.idle(now, timeout);
            if !retain && interaction_diagnostics_enabled() {
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
    }

    pub fn active_connections(&self) -> usize {
        self.connections.len()
    }

    pub fn take_evidence(&mut self) -> Vec<CompletedPlaintextEvidence> {
        self.pending_evidence.drain(..).collect()
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
        }
    }
}

fn interaction_diagnostics_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("A3S_OBSERVER_TLS_DIAGNOSTICS")
            .ok()
            .is_some_and(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "on" | "yes"
                )
            })
    })
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

fn body_only_llm_request(
    body: &[u8],
    event_at_unix_ns: u128,
    partial_reasons: &[String],
) -> Option<HttpMessage> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let object = value.as_object()?;
    let path = if object.get("type").and_then(Value::as_str) == Some("response.create")
        || object.contains_key("input")
    {
        "/v1/responses"
    } else if object.contains_key("messages") {
        if object.contains_key("max_tokens") || object.contains_key("anthropic_version") {
            "/v1/messages"
        } else {
            "/v1/chat/completions"
        }
    } else if object.get("model").and_then(Value::as_str).is_some() {
        "/v1/responses"
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
    })
}

fn build_interaction(
    key: ConnectionKey,
    sequence: u64,
    source: &str,
    adapter_id: &str,
    request: HttpMessage,
    response: HttpMessage,
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
    let request_json = parse_json_body(&request_body);
    let mut wire_match = match_wire_protocol(&method, &request.headers, request_json.as_ref())?;
    let response_is_sse = response
        .content_type()
        .eq_ignore_ascii_case("text/event-stream")
        || looks_like_sse(&response_body);
    let (response_structured, response_text, mut tool_calls) = if response_is_sse {
        normalize_sse_response(&response_body, response.completed_at_unix_ns)
    } else {
        let structured = parse_json_body(&response_body);
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
    let tool_route = wire_match.interaction_kind == WireInteractionKind::Tool;

    let messages = request_json
        .as_ref()
        .map(extract_request_messages)
        .unwrap_or_default();
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
    let request_schema_fingerprint = request_json.as_ref().map(schema_fingerprint);

    let request_decode_complete = request_decode_reason.is_none();
    let response_decode_complete = response_decode_reason.is_none();
    let mut partial_reasons = request.partial_reasons.clone();
    extend_unique(&mut partial_reasons, response.partial_reasons.clone());
    if let Some(reason) = request_decode_reason {
        extend_unique(&mut partial_reasons, [reason]);
    }
    if let Some(reason) = response_decode_reason {
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
        &response_body,
        response_structured.as_ref(),
    );
    if wire_completeness != "complete" && wire_completeness != "error" {
        extend_unique(&mut partial_reasons, [format!("wire_{wire_completeness}")]);
    }
    let conversation_completeness = if !tool_calls.is_empty() && tool_results.is_empty() {
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
        if request.partial_reasons.is_empty() {
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
        if response.partial_reasons.is_empty() {
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
            is_error: status_code >= 400
                || rpc_response.is_some_and(|value| value.get("error").is_some()),
            observed_at_unix_ns: Some(response.completed_at_unix_ns.to_string()),
        }];
    }
    let duration = response
        .completed_at_unix_ns
        .saturating_sub(request.started_at_unix_ns);

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
        protocol: if request.metadata_inferred {
            "http/1.1-body-inferred"
        } else {
            "http/1.1"
        }
        .to_string(),
        tls_adapter_id: adapter_id.to_string(),
        transport_protocol: if request.metadata_inferred {
            "json-body"
        } else {
            "http/1.1"
        }
        .to_string(),
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
        started_at_unix_ns: request.started_at_unix_ns.to_string(),
        request_complete_at_unix_ns: request.completed_at_unix_ns.to_string(),
        first_response_at_unix_ns: response.started_at_unix_ns.to_string(),
        ended_at_unix_ns: response.completed_at_unix_ns.to_string(),
        duration_ns: duration.to_string(),
        time_quality: "collector_calibrated".to_string(),
        request: request_content,
        response: response_content,
        tool_calls,
        tool_results,
        completeness,
        partial_reasons,
        capture_source: source.to_string(),
    })
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

fn decode_http_message(
    kind: StreamKind,
    bytes: &[u8],
    max_body_bytes: usize,
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
        let Some((decoded, consumed)) = decode_chunked(body_bytes, max_body_bytes, sse_response)?
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
        || status_code.is_some_and(|code| code == 204 || code == 304)
    {
        (Vec::new(), 0)
    } else if content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
        || looks_like_sse(body_bytes)
    {
        let Some(end) = sse_terminal_offset(body_bytes) else {
            return Ok(None);
        };
        (body_bytes[..end].to_vec(), end)
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
            if let Some(terminal) = sse_terminal_offset(&body) {
                body.truncate(terminal);
                return Ok(Some((body, cursor)));
            }
        }
    }
}

fn decode_content_encoding(
    bytes: &[u8],
    encoding: &str,
    max_output_bytes: usize,
) -> (Vec<u8>, Option<String>) {
    let normalized = encoding.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized == "identity" {
        return (bytes.to_vec(), None);
    }
    let decoder: Box<dyn Read> = match normalized.as_str() {
        "gzip" | "x-gzip" => Box::new(GzDecoder::new(bytes)),
        "deflate" => Box::new(ZlibDecoder::new(bytes)),
        "raw-deflate" => Box::new(DeflateDecoder::new(bytes)),
        _ => {
            return (
                bytes.to_vec(),
                Some(format!("unsupported_content_encoding:{normalized}")),
            )
        }
    };
    let mut output = Vec::new();
    let mut bounded = decoder.take(max_output_bytes as u64 + 1);
    match bounded.read_to_end(&mut output) {
        Ok(_) if output.len() <= max_output_bytes => (output, None),
        Ok(_) => {
            output.truncate(max_output_bytes);
            (output, Some("decompressed_body_limit".to_string()))
        }
        Err(_) => (bytes.to_vec(), Some("content_decode_error".to_string())),
    }
}

fn request_line(start_line: &str) -> Option<(String, String)> {
    let mut parts = start_line.split_whitespace();
    Some((parts.next()?.to_string(), parts.next()?.to_string()))
}

fn response_status(start_line: &str) -> Option<u16> {
    start_line.split_whitespace().nth(1)?.parse().ok()
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
    if object.contains_key("contents") {
        return Some(WireMatch {
            template_id: "gemini-generate-content",
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
        "openai-responses" => {
            json_has_key(response, "output", 0)
                || json_has_key(response, "output_text", 0)
                || (response_is_sse && has_nested_type_prefix(response, "response.", 0))
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
) -> &'static str {
    if status_code >= 400 {
        return "error";
    }
    if wire_match.parse_state == "unparsed" {
        return "unknown";
    }
    if response_is_sse {
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

fn extract_provider_conversation_id(value: &Value) -> Option<String> {
    bounded_provider_id(value.get("conversation_id"))
        .or_else(|| bounded_provider_id(value.get("session_id")))
        .or_else(|| bounded_provider_id(value.get("conversation")))
        .or_else(|| {
            value
                .get("conversation")
                .and_then(|conversation| bounded_provider_id(conversation.get("id")))
        })
        .or_else(|| {
            value.get("metadata").and_then(|metadata| {
                bounded_provider_id(metadata.get("conversation_id"))
                    .or_else(|| bounded_provider_id(metadata.get("session_id")))
            })
        })
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

fn extract_request_messages(value: &Value) -> Vec<LlmInteractionMessage> {
    let mut messages = Vec::new();
    if let Some(instructions) = value.get("instructions") {
        messages.push(LlmInteractionMessage {
            role: "system".to_string(),
            content: instructions.clone(),
            name: None,
            tool_call_id: None,
        });
    }
    if let Some(system) = value.get("system") {
        messages.push(LlmInteractionMessage {
            role: "system".to_string(),
            content: system.clone(),
            name: None,
            tool_call_id: None,
        });
    }
    for item in value
        .get("messages")
        .or_else(|| value.get("input"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
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
        });
    }
    messages
}

fn extract_response_text(value: &Value) -> Option<String> {
    if let Some(text) = value.get("output_text").and_then(Value::as_str) {
        return Some(text.to_string());
    }
    let mut output = String::new();
    if let Some(choices) = value.get("choices").and_then(Value::as_array) {
        for choice in choices {
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
                output.push_str(text);
            }
        }
    }
    collect_text_parts(value.get("output"), &mut output);
    collect_text_parts(value.get("content"), &mut output);
    if output.is_empty() {
        value
            .get("item")
            .and_then(extract_response_text)
            .or_else(|| value.get("response").and_then(extract_response_text))
    } else {
        Some(output)
    }
}

fn collect_text_parts(value: Option<&Value>, output: &mut String) {
    let Some(items) = value.and_then(Value::as_array) else {
        return;
    };
    for item in items {
        if let Some(text) = item.get("text").and_then(Value::as_str) {
            output.push_str(text);
        }
        if let Some(content) = item.get("content") {
            collect_text_parts(Some(content), output);
        }
    }
}

fn extract_tool_calls(value: &Value, issued_at_unix_ns: u128) -> Vec<LlmInteractionToolCall> {
    let mut calls = Vec::new();
    if let Some(choices) = value.get("choices").and_then(Value::as_array) {
        for tool in choices
            .iter()
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
    if let Some(item) = value.get("item") {
        if let Some(call) = typed_tool_call(item, issued_at_unix_ns) {
            calls.push(call);
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
    for item in items {
        if let Some(call) = typed_tool_call(item, issued_at_unix_ns) {
            calls.push(call);
        }
        collect_typed_tool_calls(item.get("content"), issued_at_unix_ns, calls);
    }
}

fn typed_tool_call(value: &Value, issued_at_unix_ns: u128) -> Option<LlmInteractionToolCall> {
    let kind = value.get("type").and_then(Value::as_str)?;
    if !matches!(kind, "function_call" | "tool_use") {
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
    {
        if item.get("role").and_then(Value::as_str) == Some("tool")
            || item.get("type").and_then(Value::as_str) == Some("function_call_output")
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
    let mut current_anthropic_call: Option<String> = None;

    for event in &events {
        if let Some(text) = event.get("delta").and_then(Value::as_str).or_else(|| {
            event
                .get("delta")
                .and_then(|delta| delta.get("text"))
                .and_then(Value::as_str)
        }) {
            deltas.push_str(text);
        }
        if let Some(choices) = event.get("choices").and_then(Value::as_array) {
            for choice in choices {
                if let Some(text) = choice
                    .get("delta")
                    .and_then(|delta| delta.get("content"))
                    .and_then(Value::as_str)
                {
                    deltas.push_str(text);
                }
                for tool in choice
                    .get("delta")
                    .and_then(|delta| delta.get("tool_calls"))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
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
                        entry.0.push_str(name);
                    }
                    if let Some(arguments) = tool
                        .get("function")
                        .and_then(|function| function.get("arguments"))
                        .and_then(Value::as_str)
                    {
                        entry.1.push_str(arguments);
                    }
                }
            }
        }
        if event.get("type").and_then(Value::as_str) == Some("content_block_start") {
            if let Some(block) = event.get("content_block") {
                if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                    if let Some(id) = block.get("id").and_then(Value::as_str) {
                        current_anthropic_call = Some(id.to_string());
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
        if event.get("type").and_then(Value::as_str) == Some("content_block_delta") {
            if let Some(arguments) = event
                .get("delta")
                .and_then(|delta| delta.get("partial_json"))
                .and_then(Value::as_str)
            {
                if let Some(entry) = current_anthropic_call
                    .as_ref()
                    .and_then(|id| anthropic_calls.get_mut(id))
                {
                    entry.1.push_str(arguments);
                }
            }
        }
        if let Some(text) = extract_response_text(event) {
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
    // Streaming deltas are the authoritative assembled text. A per-event extractor can observe
    // only the first chunk and must not replace the longer accumulated stream; use a terminal
    // provider object only when the stream carried no text deltas.
    let text = (!deltas.is_empty()).then_some(deltas).or(final_text);
    let structured = (!events.is_empty()).then_some(Value::Array(events));
    (structured, text, calls)
}

fn parse_sse_json_events(body: &[u8]) -> Vec<Value> {
    let text = String::from_utf8_lossy(body).replace("\r\n", "\n");
    text.split("\n\n")
        .take(MAX_SSE_STRUCTURED_EVENTS)
        .filter_map(|block| {
            let data = block
                .lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .map(str::trim_start)
                .collect::<Vec<_>>()
                .join("\n");
            if data.is_empty() || data == "[DONE]" {
                None
            } else {
                serde_json::from_str(&data).ok()
            }
        })
        .collect()
}

fn looks_like_sse(body: &[u8]) -> bool {
    body.starts_with(b"data:") || find_bytes(body, b"\ndata:").is_some()
}

fn sse_terminal_offset(body: &[u8]) -> Option<usize> {
    for marker in [
        b"data: [DONE]\r\n\r\n".as_slice(),
        b"data: [DONE]\n\n".as_slice(),
    ] {
        if let Some(offset) = find_bytes(body, marker) {
            return Some(offset + marker.len());
        }
    }
    let normalized = String::from_utf8_lossy(body).replace("\r\n", "\n");
    let mut consumed = 0usize;
    for block in normalized.split_inclusive("\n\n") {
        consumed += block.len();
        if block.contains("\"type\":\"response.completed\"")
            || block.contains("\"type\": \"response.completed\"")
            || block.contains("\"type\":\"message_stop\"")
            || block.contains("\"type\": \"message_stop\"")
        {
            // CRLF normalization may make this offset slightly shorter. The common HTTP/1 path is
            // chunk-framed; this fallback is only for unframed test/proxy streams.
            return Some(consumed.min(body.len()));
        }
    }
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
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn extend_unique(values: &mut Vec<String>, additions: impl IntoIterator<Item = String>) {
    for value in additions {
        if !values.iter().any(|existing| existing == &value) {
            values.push(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
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
            partial_reasons: Vec::new(),
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
    fn unsupported_http2_emits_metadata_evidence_without_false_interaction() {
        let mut reassembler = InteractionReassembler::default();
        let completed = reassembler.push(chunk(
            ChunkDirection::Request,
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
            1,
        ));
        assert!(completed.is_empty());
        let evidence = reassembler.take_evidence();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].transport_protocol, "http/2");
        assert_eq!(evidence[0].parse_state, "unparsed");
        assert_eq!(evidence[0].encoding, "metadata_only");
        assert!(evidence[0].redacted_sample.is_none());
        assert_eq!(evidence[0].sample_sha256.len(), 64);
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
}
