//! Runtime response-direction TLS plaintext reassembly for the kimi/OpenSSL lane.
//!
//! Read-side `SSL_read` fragments are reassembled per connection (pid + ssl_pointer) into an
//! HTTP/1.1 response stream, decoded (chunked / optional gzip), and incrementally parsed as
//! server-sent events. Each `data:` payload is aggregated into assistant text, tool calls,
//! finish reason, and token usage; the event is finalized on `data: [DONE]`, the end of the
//! chunked body, process exit, or reassembly timeout. Raw plaintext never leaves the pipeline:
//! buffers are zeroized on drop and [`ResponsePipeline::clear_plaintext`] backs the kill switch.
//!
//! Connections are persistent: kimi (undici) pools keep-alive connections, so after one
//! response completes the connection stays open and the next response is parsed from the same
//! byte stream. Interim `1xx` responses are skipped; a trailing chunked terminator that arrives
//! after `[DONE]` is drained before the next response starts.
//!
//! This module is deliberately independent from the request-side fixture pipeline. It is only
//! constructed in `runtime_payload` mode and only receives read fragments from kimi processes.

use anyhow::bail;
use flate2::{Decompress, FlushDecompress};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_SSE_LINE_BYTES: usize = 1024 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 128;
const MAX_TRAILER_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone)]
pub struct ResponsePipelineConfig {
    pub max_connections: usize,
    pub max_inflight_calls: usize,
    /// Per-connection cap on undecoded read bytes held at once.
    pub max_response_bytes: usize,
    /// Per-response cap on aggregated assistant text plus tool-call argument text.
    pub max_content_bytes: usize,
    /// Per-feed cap on gzip-decompressed body bytes.
    pub max_decompressed_bytes: usize,
    pub reassembly_timeout: Duration,
}

/// Pairing metadata registered when the request side completes on the same connection.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub host: String,
    pub path: String,
    pub endpoint_attribution: String,
    pub provider: String,
    pub model: Option<String>,
    /// Monotonic time of the final request fragment (send-complete).
    pub sent_at_monotonic_ns: u64,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
}

#[derive(Debug)]
pub struct ObservedToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

#[derive(Debug)]
pub struct ObservedLlmResponse {
    pub pid: u32,
    pub tid: u32,
    pub observed_at_monotonic_ns: u64,
    pub host: String,
    pub path: String,
    pub endpoint_attribution: String,
    pub provider: String,
    pub model: Option<String>,
    pub status_code: u16,
    pub finish_reason: Option<String>,
    pub assistant_content: String,
    pub content_sha256: String,
    pub content_bytes: u64,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub tool_calls: Vec<ObservedToolCall>,
    pub ttft_ns: Option<u64>,
    pub duration_ns: Option<u64>,
    pub capture_completeness: &'static str,
    pub parse_status: &'static str,
    /// Emission transport context captured at request pairing time so timeout/exit
    /// finalization can still attribute the event.
    pub cgroup_id: u64,
    pub comm: [u8; 16],
}

#[derive(Debug)]
pub struct ReadFragment<'a> {
    pub pid: u32,
    pub tid: u32,
    pub ssl_pointer: u64,
    pub call_sequence: u64,
    pub fragment_index: u32,
    pub fragment_offset: u64,
    pub original_length: u64,
    pub observed_at_monotonic_ns: u64,
    pub truncated: bool,
    pub bytes: &'a [u8],
}

#[derive(Default, Debug, Clone, Copy)]
pub struct ResponsePipelineStats {
    pub fragments_observed: u64,
    pub fragments_rejected: u64,
    pub calls_completed: u64,
    pub calls_incomplete: u64,
    pub responses_completed: u64,
    pub responses_paired: u64,
    pub responses_unpaired: u64,
    pub responses_failed: u64,
    pub interim_responses_skipped: u64,
    pub parse_failed: u64,
    pub capacity_dropped: u64,
    pub responses_truncated: u64,
    pub responses_timeout: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CallKey {
    pid: u32,
    tid: u32,
    ssl_pointer: u64,
    call_sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConnectionKey {
    pid: u32,
    ssl_pointer: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalReason {
    Done,
    ProcessExit,
    Timeout,
    ParseError,
    Truncated,
}

struct CallAssembly {
    bytes: Vec<u8>,
    original_length: usize,
    next_fragment_index: u32,
    observed_at_monotonic_ns: u64,
    last_seen: Instant,
}

impl Drop for CallAssembly {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyMode {
    Chunked,
    Gzip,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Consumed some input; keep looping.
    Progress,
    /// Skipped a 1xx interim response; the final response follows on the same connection.
    InterimSkipped,
    /// More bytes needed.
    NeedMore,
    /// Response complete. `drain_terminator` is set when finalization happened at SSE `[DONE]`
    /// inside a chunked body, so the chunked terminator may still be in flight.
    Done {
        drain_terminator: bool,
    },
    Failed(&'static str),
}

#[derive(Default)]
struct UsageAccumulator {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    total_tokens: Option<u64>,
}

const MAX_TOOL_CALLS: usize = 64;

#[derive(Default)]
struct ToolCallAssembly {
    id: String,
    name: String,
    arguments: String,
}

impl Drop for ToolCallAssembly {
    fn drop(&mut self) {
        self.id.zeroize();
        self.name.zeroize();
        self.arguments.zeroize();
    }
}

/// Result of feeding bytes to the SSE parser: how many input bytes were consumed and whether
/// `data: [DONE]` terminated the stream. `consumed` only differs from the input length when
/// the stream terminated mid-buffer; the caller drains exactly `consumed` so trailing bytes
/// (the next response on a keep-alive connection) stay buffered.
struct SseOutcome {
    consumed: usize,
    done: bool,
}

/// Incremental SSE parser: buffers a partial line, joins multi-`data:` event blocks, and
/// aggregates OpenAI chat-completion stream chunks.
struct SseParser {
    line: Vec<u8>,
    data_lines: Vec<String>,
    content: String,
    tool_calls: Vec<ToolCallAssembly>,
    finish_reason: Option<String>,
    model: Option<String>,
    usage: UsageAccumulator,
    content_truncated: bool,
    saw_data: bool,
    saw_done: bool,
    events_parsed: u64,
    events_failed: u64,
}

impl SseParser {
    fn new() -> Self {
        Self {
            line: Vec::new(),
            data_lines: Vec::new(),
            content: String::new(),
            tool_calls: Vec::new(),
            finish_reason: None,
            model: None,
            usage: UsageAccumulator::default(),
            content_truncated: false,
            saw_data: false,
            saw_done: false,
            events_parsed: 0,
            events_failed: 0,
        }
    }

    fn push(&mut self, bytes: &[u8], max_content_bytes: usize) -> Result<SseOutcome, &'static str> {
        // Bytes already sitting in the line buffer came from an earlier feed; consumed counts
        // only bytes from this input.
        let base = self.line.len();
        self.line.extend_from_slice(bytes);
        let mut drained_total = 0usize;
        loop {
            let Some(newline) = self.line.iter().position(|byte| *byte == b'\n') else {
                break;
            };
            let mut line: Vec<u8> = self.line.drain(..newline + 1).collect();
            drained_total += newline + 1;
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.handle_line(&line, max_content_bytes);
            line.zeroize();
            if self.saw_done {
                let consumed = drained_total.saturating_sub(base).min(bytes.len());
                self.line.zeroize();
                self.line.clear();
                return Ok(SseOutcome {
                    consumed,
                    done: true,
                });
            }
        }
        if self.line.len() > MAX_SSE_LINE_BYTES {
            return Err("sse_line_too_large");
        }
        Ok(SseOutcome {
            consumed: bytes.len(),
            done: false,
        })
    }

    fn handle_line(&mut self, line: &[u8], max_content_bytes: usize) {
        if line.is_empty() {
            self.dispatch_event(max_content_bytes);
            return;
        }
        if let Some(payload) = line.strip_prefix(b"data:") {
            let payload = payload.strip_prefix(b" ").unwrap_or(payload);
            match std::str::from_utf8(payload) {
                Ok(payload) => self.data_lines.push(payload.to_string()),
                Err(_) => self.events_failed = self.events_failed.saturating_add(1),
            }
        }
        // `event:`/`id:`/`retry:` fields and comment lines carry no payload for this lane.
    }

    fn dispatch_event(&mut self, max_content_bytes: usize) {
        if self.data_lines.is_empty() {
            return;
        }
        let mut payload = self.data_lines.join("\n");
        self.data_lines.clear();
        if payload == "[DONE]" {
            self.saw_done = true;
            payload.zeroize();
            return;
        }
        let parsed = serde_json::from_str::<Value>(&payload);
        payload.zeroize();
        match parsed {
            Ok(mut chunk) => {
                self.aggregate_chunk(&chunk, max_content_bytes);
                wipe_json(&mut chunk);
                self.saw_data = true;
                self.events_parsed = self.events_parsed.saturating_add(1);
            }
            Err(_) => {
                self.events_failed = self.events_failed.saturating_add(1);
            }
        }
    }

    fn aggregate_chunk(&mut self, chunk: &Value, max_content_bytes: usize) {
        if self.model.is_none() {
            self.model = chunk
                .get("model")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
        }
        if let Some(usage) = chunk.get("usage") {
            let tokens = |name: &str| usage.get(name).and_then(Value::as_u64);
            self.usage.prompt_tokens = tokens("prompt_tokens").or(self.usage.prompt_tokens);
            self.usage.completion_tokens =
                tokens("completion_tokens").or(self.usage.completion_tokens);
            self.usage.total_tokens = tokens("total_tokens").or(self.usage.total_tokens);
        }
        let Some(choices) = chunk.get("choices").and_then(Value::as_array) else {
            return;
        };
        for choice in choices {
            if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                self.finish_reason = Some(reason.to_string());
            }
            let Some(delta) = choice.get("delta") else {
                continue;
            };
            if let Some(text) = delta.get("content").and_then(Value::as_str) {
                self.append_content(text, max_content_bytes);
            }
            if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
                for (position, tool_call) in tool_calls.iter().enumerate() {
                    let index = tool_call
                        .get("index")
                        .and_then(Value::as_u64)
                        .map(|index| index as usize)
                        .unwrap_or(position);
                    if index >= MAX_TOOL_CALLS {
                        continue;
                    }
                    if self.tool_calls.len() <= index {
                        self.tool_calls
                            .resize_with(index + 1, ToolCallAssembly::default);
                    }
                    {
                        let entry = &mut self.tool_calls[index];
                        if let Some(id) = tool_call.get("id").and_then(Value::as_str) {
                            if !id.is_empty() && entry.id.is_empty() {
                                entry.id = id.to_string();
                            }
                        }
                        if let Some(function) = tool_call.get("function") {
                            if let Some(name) = function.get("name").and_then(Value::as_str) {
                                if !name.is_empty() && entry.name.is_empty() {
                                    entry.name = name.to_string();
                                }
                            }
                        }
                    }
                    if let Some(arguments) = tool_call
                        .get("function")
                        .and_then(|function| function.get("arguments"))
                        .and_then(Value::as_str)
                    {
                        let budget = self.content_budget(max_content_bytes);
                        let entry = &mut self.tool_calls[index];
                        if arguments.len() > budget {
                            entry
                                .arguments
                                .push_str(&arguments[..floor_char_boundary(arguments, budget)]);
                            self.content_truncated = true;
                        } else {
                            entry.arguments.push_str(arguments);
                        }
                    }
                }
            }
        }
    }

    fn content_budget(&self, max_content_bytes: usize) -> usize {
        let arguments: usize = self
            .tool_calls
            .iter()
            .map(|tool_call| tool_call.arguments.len())
            .sum();
        max_content_bytes
            .saturating_sub(self.content.len())
            .saturating_sub(arguments)
    }

    fn append_content(&mut self, text: &str, max_content_bytes: usize) {
        let budget = self.content_budget(max_content_bytes);
        if text.len() > budget {
            self.content
                .push_str(&text[..floor_char_boundary(text, budget)]);
            self.content_truncated = true;
        } else {
            self.content.push_str(text);
        }
    }
}

impl Drop for SseParser {
    fn drop(&mut self) {
        self.line.zeroize();
        for line in &mut self.data_lines {
            line.zeroize();
        }
        self.content.zeroize();
    }
}

struct ResponseAssembly {
    tid: u32,
    started_at_monotonic_ns: u64,
    last_fragment_at_monotonic_ns: u64,
    /// Monotonic time of the fragment that delivered the first SSE `data:` event.
    first_data_at_monotonic_ns: Option<u64>,
    headers_done: bool,
    body_mode: BodyMode,
    /// Remaining body bytes for `Content-Length` framed responses.
    content_length_remaining: Option<usize>,
    /// Chunked mode: bytes left in the current chunk; 0 means a size line comes next.
    chunk_remaining: usize,
    inflater: Option<Decompress>,
    parser: SseParser,
    status_code: u16,
    stream_truncated: bool,
}

impl ResponseAssembly {
    fn new(tid: u32, observed_at_monotonic_ns: u64) -> Self {
        Self {
            tid,
            started_at_monotonic_ns: observed_at_monotonic_ns,
            last_fragment_at_monotonic_ns: observed_at_monotonic_ns,
            first_data_at_monotonic_ns: None,
            headers_done: false,
            body_mode: BodyMode::Raw,
            content_length_remaining: None,
            chunk_remaining: 0,
            inflater: None,
            parser: SseParser::new(),
            status_code: 0,
            stream_truncated: false,
        }
    }
}

/// A persistent keep-alive connection: raw bytes not yet consumed by any response parser live
/// in `backlog`; `pending` holds completed requests waiting for their response, in order.
struct Connection {
    pending: VecDeque<RequestContext>,
    backlog: Vec<u8>,
    /// Set when a response was finalized at SSE `[DONE]` inside a chunked body: the chunked
    /// terminator is still in flight and must be drained before the next response.
    drain_terminator: bool,
    response: Option<ResponseAssembly>,
    last_seen: Instant,
}

impl Connection {
    fn new(now: Instant) -> Self {
        Self {
            pending: VecDeque::new(),
            backlog: Vec::new(),
            drain_terminator: false,
            response: None,
            last_seen: now,
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.backlog.zeroize();
    }
}

pub struct ResponsePipeline {
    config: ResponsePipelineConfig,
    calls: HashMap<CallKey, CallAssembly>,
    connections: HashMap<ConnectionKey, Connection>,
    observations: VecDeque<ObservedLlmResponse>,
    stats: ResponsePipelineStats,
}

impl ResponsePipeline {
    pub fn new(config: ResponsePipelineConfig) -> anyhow::Result<Self> {
        if config.max_connections == 0
            || config.max_inflight_calls == 0
            || config.max_response_bytes == 0
            || config.max_content_bytes == 0
            || config.max_decompressed_bytes == 0
        {
            bail!("runtime response pipeline limits must be greater than zero");
        }
        Ok(Self {
            config,
            calls: HashMap::new(),
            connections: HashMap::new(),
            observations: VecDeque::new(),
            stats: ResponsePipelineStats::default(),
        })
    }

    pub fn take_observations(&mut self) -> Vec<ObservedLlmResponse> {
        self.observations.drain(..).collect()
    }

    pub fn stats(&self) -> ResponsePipelineStats {
        self.stats
    }

    /// Register a completed request so the next unparsed response on this connection pairs
    /// with it. Multiple registrations queue in order (keep-alive pipelining).
    pub fn register_request(
        &mut self,
        pid: u32,
        ssl_pointer: u64,
        context: RequestContext,
        now: Instant,
    ) {
        let key = ConnectionKey { pid, ssl_pointer };
        if !self.connections.contains_key(&key)
            && self.connections.len() >= self.config.max_connections
        {
            self.stats.capacity_dropped = self.stats.capacity_dropped.saturating_add(1);
            return;
        }
        let connection = self
            .connections
            .entry(key)
            .or_insert_with(|| Connection::new(now));
        connection.last_seen = now;
        if connection.pending.len() >= self.config.max_inflight_calls {
            self.stats.capacity_dropped = self.stats.capacity_dropped.saturating_add(1);
            connection.pending.pop_front();
        }
        connection.pending.push_back(context);
    }

    pub fn push_read(&mut self, fragment: ReadFragment<'_>, now: Instant) {
        self.stats.fragments_observed = self.stats.fragments_observed.saturating_add(1);
        if fragment.pid == 0 || fragment.ssl_pointer == 0 {
            self.stats.fragments_rejected = self.stats.fragments_rejected.saturating_add(1);
            return;
        }
        let connection_key = ConnectionKey {
            pid: fragment.pid,
            ssl_pointer: fragment.ssl_pointer,
        };
        if fragment.truncated || fragment.original_length > self.config.max_response_bytes as u64 {
            self.stats.calls_incomplete = self.stats.calls_incomplete.saturating_add(1);
            self.calls.remove(&CallKey {
                pid: fragment.pid,
                tid: fragment.tid,
                ssl_pointer: fragment.ssl_pointer,
                call_sequence: fragment.call_sequence,
            });
            self.mark_stream_truncated(connection_key);
            return;
        }
        if fragment.bytes.is_empty() {
            self.stats.fragments_rejected = self.stats.fragments_rejected.saturating_add(1);
            return;
        }
        let call_key = CallKey {
            pid: fragment.pid,
            tid: fragment.tid,
            ssl_pointer: fragment.ssl_pointer,
            call_sequence: fragment.call_sequence,
        };
        if !self.calls.contains_key(&call_key) && self.calls.len() >= self.config.max_inflight_calls
        {
            self.stats.capacity_dropped = self.stats.capacity_dropped.saturating_add(1);
            self.stats.calls_incomplete = self.stats.calls_incomplete.saturating_add(1);
            return;
        }
        let original_length = fragment.original_length as usize;
        let call = self.calls.entry(call_key).or_insert_with(|| CallAssembly {
            bytes: Vec::with_capacity(original_length.min(64 * 1024)),
            original_length,
            next_fragment_index: 0,
            observed_at_monotonic_ns: fragment.observed_at_monotonic_ns,
            last_seen: now,
        });
        call.last_seen = now;
        if call.original_length != original_length
            || fragment.fragment_offset != call.bytes.len() as u64
            || fragment.fragment_index != call.next_fragment_index
            || call.bytes.len().saturating_add(fragment.bytes.len()) > call.original_length
        {
            self.stats.calls_incomplete = self.stats.calls_incomplete.saturating_add(1);
            self.calls.remove(&call_key);
            self.mark_stream_truncated(connection_key);
            return;
        }
        call.bytes.extend_from_slice(fragment.bytes);
        call.next_fragment_index = call.next_fragment_index.saturating_add(1);
        if call.bytes.len() != call.original_length {
            return;
        }
        let mut completed = self.calls.remove(&call_key).expect("call exists");
        self.stats.calls_completed = self.stats.calls_completed.saturating_add(1);
        self.push_connection_bytes(
            connection_key,
            fragment.tid,
            &completed.bytes,
            completed.observed_at_monotonic_ns,
            fragment.observed_at_monotonic_ns,
            now,
        );
        completed.bytes.zeroize();
    }

    /// Finalize any in-progress responses for an exited process (abort/cancel lane).
    pub fn forget_pid(&mut self, pid: u32) {
        let keys = self
            .connections
            .keys()
            .filter(|key| key.pid == pid)
            .copied()
            .collect::<Vec<_>>();
        for key in keys {
            self.finalize_connection(key, FinalReason::ProcessExit);
        }
        self.calls.retain(|key, _| key.pid != pid);
    }

    /// Expire idle connections and read-call reassemblies, finalizing stale responses as
    /// partial so an aborted stream still produces a bounded observation.
    pub fn expire(&mut self, now: Instant) {
        let timeout = self.config.reassembly_timeout;
        let expired_calls = self
            .calls
            .iter()
            .filter_map(|(key, value)| {
                (now.saturating_duration_since(value.last_seen) >= timeout).then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in expired_calls {
            self.calls.remove(&key);
            self.stats.calls_incomplete = self.stats.calls_incomplete.saturating_add(1);
            self.mark_stream_truncated(ConnectionKey {
                pid: key.pid,
                ssl_pointer: key.ssl_pointer,
            });
        }
        let expired_connections = self
            .connections
            .iter()
            .filter_map(|(key, value)| {
                (now.saturating_duration_since(value.last_seen) >= timeout).then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in expired_connections {
            self.finalize_connection(key, FinalReason::Timeout);
        }
    }

    pub fn clear_plaintext(&mut self) {
        self.calls.clear();
        self.connections.clear();
        for mut observation in self.observations.drain(..) {
            observation.assistant_content.zeroize();
            for tool_call in &mut observation.tool_calls {
                tool_call.id.zeroize();
                tool_call.name.zeroize();
                tool_call.arguments.zeroize();
            }
        }
    }

    fn mark_stream_truncated(&mut self, key: ConnectionKey) {
        let Some(connection) = self.connections.get_mut(&key) else {
            return;
        };
        if let Some(response) = connection.response.as_mut() {
            if !response.stream_truncated {
                self.stats.responses_truncated = self.stats.responses_truncated.saturating_add(1);
            }
            response.stream_truncated = true;
        }
    }

    fn push_connection_bytes(
        &mut self,
        key: ConnectionKey,
        tid: u32,
        bytes: &[u8],
        first_fragment_monotonic_ns: u64,
        last_fragment_monotonic_ns: u64,
        now: Instant,
    ) {
        if !self.connections.contains_key(&key)
            && self.connections.len() >= self.config.max_connections
        {
            self.stats.capacity_dropped = self.stats.capacity_dropped.saturating_add(1);
            return;
        }
        let connection = self
            .connections
            .entry(key)
            .or_insert_with(|| Connection::new(now));
        connection.last_seen = now;
        if connection.backlog.len().saturating_add(bytes.len()) > self.config.max_response_bytes {
            // The stream outgrew its budget: finalize the active response as truncated and
            // resync at the next response boundary.
            self.stats.responses_truncated = self.stats.responses_truncated.saturating_add(1);
            self.finalize_response(key, FinalReason::Truncated);
            if let Some(connection) = self.connections.get_mut(&key) {
                connection.backlog.zeroize();
                connection.backlog.clear();
                connection.drain_terminator = false;
            }
            return;
        }
        enum Action {
            Done { drain_terminator: bool },
            Failed(&'static str),
        }
        if let Some(connection) = self.connections.get_mut(&key) {
            connection.backlog.extend_from_slice(bytes);
        }
        // Each iteration re-borrows the connection so Done/Failed can finalize (which needs
        // &mut self) and the loop can immediately start on a pipelined next response.
        loop {
            let action = {
                let Some(connection) = self.connections.get_mut(&key) else {
                    break;
                };
                if connection.drain_terminator {
                    match drain_chunk_terminator(&mut connection.backlog) {
                        TerminatorDrain::Consumed | TerminatorDrain::NotTerminator => {
                            connection.drain_terminator = false;
                        }
                        TerminatorDrain::NeedMore => break,
                    }
                    if connection.backlog.is_empty() {
                        break;
                    }
                }
                if connection.backlog.is_empty() {
                    break;
                }
                if connection.response.is_none() {
                    connection.response =
                        Some(ResponseAssembly::new(tid, first_fragment_monotonic_ns));
                }
                let response = connection.response.as_mut().expect("response exists");
                response.last_fragment_at_monotonic_ns = last_fragment_monotonic_ns;
                match step_response(&self.config, response, &mut connection.backlog) {
                    Step::Progress => continue,
                    Step::InterimSkipped => {
                        self.stats.interim_responses_skipped =
                            self.stats.interim_responses_skipped.saturating_add(1);
                        continue;
                    }
                    Step::NeedMore => break,
                    Step::Done { drain_terminator } => Action::Done { drain_terminator },
                    Step::Failed(reason) => Action::Failed(reason),
                }
            };
            match action {
                Action::Done { drain_terminator } => {
                    self.finalize_response(key, FinalReason::Done);
                    if let Some(connection) = self.connections.get_mut(&key) {
                        connection.drain_terminator = drain_terminator;
                    }
                }
                Action::Failed(reason) => {
                    tracing::warn!(
                        reason,
                        pid = key.pid,
                        ssl_pointer = key.ssl_pointer,
                        "runtime response capture parse failure"
                    );
                    self.stats.parse_failed = self.stats.parse_failed.saturating_add(1);
                    self.finalize_response(key, FinalReason::ParseError);
                    // Resync at the next response boundary: whatever is buffered is mid-stream
                    // garbage for this connection.
                    if let Some(connection) = self.connections.get_mut(&key) {
                        connection.backlog.zeroize();
                        connection.backlog.clear();
                        connection.drain_terminator = false;
                    }
                    break;
                }
            }
        }
    }

    /// Finalize the active response (if any) and emit an observation when it pairs with a
    /// registered request. The connection itself stays alive for keep-alive reuse.
    fn finalize_response(&mut self, key: ConnectionKey, reason: FinalReason) {
        let Some(connection) = self.connections.get_mut(&key) else {
            return;
        };
        let Some(mut response) = connection.response.take() else {
            return;
        };
        let paired = connection.pending.pop_front();
        let Some(context) = paired else {
            // No unmatched request on this connection: a non-chat stream (telemetry, OAuth)
            // whose response must not surface as an LLM event. Drop the plaintext.
            self.stats.responses_unpaired = self.stats.responses_unpaired.saturating_add(1);
            return;
        };
        if reason == FinalReason::ParseError && !response.headers_done {
            // The stream never produced a status line (late attach or desync). Emit an explicit
            // failure so downstream loss accounting sees the gap.
            self.stats.responses_failed = self.stats.responses_failed.saturating_add(1);
            self.push_observation(key, &mut response, &context, "partial", "failed");
            return;
        }
        if !response.headers_done {
            // Timeout/exit before any header bytes: nothing worth emitting beyond accounting.
            return;
        }
        self.stats.responses_paired = self.stats.responses_paired.saturating_add(1);
        let truncated = response.stream_truncated || response.parser.content_truncated;
        let capture_completeness = if truncated {
            "truncated"
        } else if response.parser.saw_done {
            "complete"
        } else {
            "partial"
        };
        let parse_status = if response.parser.events_parsed == 0 && !response.parser.saw_done {
            self.stats.responses_failed = self.stats.responses_failed.saturating_add(1);
            "failed"
        } else if response.parser.saw_done && response.parser.events_failed == 0 && !truncated {
            "parsed"
        } else {
            "partial"
        };
        self.push_observation(
            key,
            &mut response,
            &context,
            capture_completeness,
            parse_status,
        );
    }

    fn push_observation(
        &mut self,
        key: ConnectionKey,
        response: &mut ResponseAssembly,
        context: &RequestContext,
        capture_completeness: &'static str,
        parse_status: &'static str,
    ) {
        let content = std::mem::take(&mut response.parser.content);
        let content_sha256 = sha256_hex(content.as_bytes());
        let content_bytes = content.len() as u64;
        let tool_calls = std::mem::take(&mut response.parser.tool_calls)
            .into_iter()
            .map(|mut assembly| ObservedToolCall {
                id: std::mem::take(&mut assembly.id),
                name: std::mem::take(&mut assembly.name),
                arguments: std::mem::take(&mut assembly.arguments),
            })
            .collect::<Vec<_>>();
        let sent_at = context.sent_at_monotonic_ns;
        let ttft_ns = response
            .first_data_at_monotonic_ns
            .map(|first_data| first_data.saturating_sub(sent_at));
        let duration_ns = Some(
            response
                .last_fragment_at_monotonic_ns
                .saturating_sub(sent_at),
        );
        let model = context
            .model
            .clone()
            .or_else(|| response.parser.model.clone());
        if self.observations.len() >= self.config.max_inflight_calls {
            self.stats.capacity_dropped = self.stats.capacity_dropped.saturating_add(1);
            return;
        }
        self.stats.responses_completed = self.stats.responses_completed.saturating_add(1);
        self.observations.push_back(ObservedLlmResponse {
            pid: key.pid,
            tid: response.tid,
            observed_at_monotonic_ns: response.started_at_monotonic_ns,
            host: context.host.clone(),
            path: context.path.clone(),
            endpoint_attribution: context.endpoint_attribution.clone(),
            provider: context.provider.clone(),
            model,
            status_code: response.status_code,
            finish_reason: response.parser.finish_reason.take(),
            assistant_content: content,
            content_sha256,
            content_bytes,
            prompt_tokens: response.parser.usage.prompt_tokens,
            completion_tokens: response.parser.usage.completion_tokens,
            total_tokens: response.parser.usage.total_tokens,
            tool_calls,
            ttft_ns,
            duration_ns,
            capture_completeness,
            parse_status,
            cgroup_id: context.cgroup_id,
            comm: context.comm,
        });
    }

    /// Process-exit / timeout lane: finalize the in-progress response, then drop the
    /// connection itself.
    fn finalize_connection(&mut self, key: ConnectionKey, reason: FinalReason) {
        if reason == FinalReason::Timeout {
            if let Some(connection) = self.connections.get(&key) {
                if connection.response.is_some() || !connection.pending.is_empty() {
                    self.stats.responses_timeout = self.stats.responses_timeout.saturating_add(1);
                }
            }
        }
        self.finalize_response(key, reason);
        if let Some(connection) = self.connections.get_mut(&key) {
            connection.backlog.zeroize();
        }
        self.connections.remove(&key);
    }
}

impl Drop for ResponsePipeline {
    fn drop(&mut self) {
        self.clear_plaintext();
    }
}

/// One incremental step over the connection backlog. All consumed bytes are drained from the
/// front of `backlog`; unconsumed bytes persist for the next step or the next response.
fn step_response(
    config: &ResponsePipelineConfig,
    response: &mut ResponseAssembly,
    backlog: &mut Vec<u8>,
) -> Step {
    if !response.headers_done {
        let Some(header_end) = find_bytes(backlog, b"\r\n\r\n") else {
            return if backlog.len() > MAX_HEADER_BYTES {
                Step::Failed("http_response_header_too_large")
            } else {
                Step::NeedMore
            };
        };
        let parsed = parse_response_headers(&backlog[..header_end]);
        let (status_code, headers) = match parsed {
            Ok(parsed) => parsed,
            Err(reason) => return Step::Failed(reason),
        };
        backlog.drain(..header_end + 4);
        if headers.interim {
            // `100 Continue` (or another 1xx) precedes the real response; keep waiting for the
            // final status line.
            return Step::InterimSkipped;
        }
        response.headers_done = true;
        response.status_code = status_code;
        response.body_mode = headers.body_mode;
        response.content_length_remaining = headers.content_length;
        response.inflater = (headers.body_mode == BodyMode::Gzip).then(|| Decompress::new(true));
        if headers.content_length == Some(0) {
            return Step::Done {
                drain_terminator: false,
            };
        }
        return Step::Progress;
    }
    match response.body_mode {
        BodyMode::Chunked => step_chunked(config, response, backlog),
        BodyMode::Gzip | BodyMode::Raw => step_raw(config, response, backlog),
    }
}

fn step_chunked(
    config: &ResponsePipelineConfig,
    response: &mut ResponseAssembly,
    backlog: &mut Vec<u8>,
) -> Step {
    if response.chunk_remaining == 0 {
        let Some(line_end) = find_bytes(backlog, b"\r\n") else {
            return if backlog.len() > MAX_CHUNK_LINE_BYTES {
                Step::Failed("chunk_line_too_large")
            } else {
                Step::NeedMore
            };
        };
        if line_end > MAX_CHUNK_LINE_BYTES {
            return Step::Failed("chunk_line_too_large");
        }
        let size_bytes = backlog[..line_end]
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or_default();
        let Ok(size_text) = std::str::from_utf8(trim_ascii(size_bytes)) else {
            return Step::Failed("chunk_size_invalid");
        };
        let Ok(size) = usize::from_str_radix(size_text, 16) else {
            return Step::Failed("chunk_size_invalid");
        };
        backlog.drain(..line_end + 2);
        if size == 0 {
            // Terminal chunk: an immediate CRLF or a trailer section ends the body.
            response.chunk_remaining = usize::MAX; // terminal seen, draining trailers
            return consume_chunk_terminator(response, backlog);
        }
        response.chunk_remaining = size;
    }
    if response.chunk_remaining == usize::MAX {
        return consume_chunk_terminator(response, backlog);
    }
    let needed = response.chunk_remaining.saturating_add(2);
    if backlog.len() < needed {
        return Step::NeedMore;
    }
    let data_end = response.chunk_remaining;
    if &backlog[data_end..data_end + 2] != b"\r\n" {
        return Step::Failed("chunk_delimiter_invalid");
    }
    let done = match feed_parser_bytes(config, response, &backlog[..data_end]) {
        Ok(done) => done,
        Err(reason) => return Step::Failed(reason),
    };
    backlog.drain(..needed);
    response.chunk_remaining = 0;
    if done {
        // SSE `[DONE]` fired: emit immediately and drain the chunked terminator when it lands.
        return Step::Done {
            drain_terminator: true,
        };
    }
    Step::Progress
}

/// Consume the chunked terminal zero chunk's trailer section. `chunk_remaining == usize::MAX`
/// marks that the zero-size line was already consumed.
fn consume_chunk_terminator(response: &mut ResponseAssembly, backlog: &mut Vec<u8>) -> Step {
    if response.chunk_remaining != usize::MAX {
        // The zero-size line itself is still in the backlog; the caller handled it. This path
        // is unreachable, but fail safe.
        return Step::Failed("chunk_terminator_invalid");
    }
    if backlog.starts_with(b"\r\n") {
        backlog.drain(..2);
        response.chunk_remaining = 0;
        return Step::Done {
            drain_terminator: false,
        };
    }
    let Some(trailer_end) = find_bytes(backlog, b"\r\n\r\n") else {
        return if backlog.len() > MAX_TRAILER_BYTES {
            Step::Failed("chunk_trailer_too_large")
        } else {
            Step::NeedMore
        };
    };
    backlog.drain(..trailer_end + 4);
    response.chunk_remaining = 0;
    Step::Done {
        drain_terminator: false,
    }
}

/// After a response finalized at SSE `[DONE]` mid-chunked-body, the connection waits for the
/// trailing chunked terminator before the next response may start.
enum TerminatorDrain {
    Consumed,
    NeedMore,
    NotTerminator,
}

fn drain_chunk_terminator(backlog: &mut Vec<u8>) -> TerminatorDrain {
    if backlog.is_empty() {
        return TerminatorDrain::NeedMore;
    }
    if backlog.first() != Some(&b'0') {
        // Framing violation (or a raw-mode body): tolerate and resync at the next response.
        return TerminatorDrain::NotTerminator;
    }
    let mut scratch = ResponseAssembly::new(0, 0);
    scratch.chunk_remaining = 0;
    // Reuse the chunked step machinery on a throwaway assembly: the zero line plus trailers
    // are consumed from the backlog without touching parser state.
    let mut parser_buf = std::mem::take(backlog);
    let step = step_chunked(
        &ResponsePipelineConfig {
            max_connections: 1,
            max_inflight_calls: 1,
            max_response_bytes: MAX_TRAILER_BYTES,
            max_content_bytes: 1,
            max_decompressed_bytes: 1,
            reassembly_timeout: Duration::from_secs(1),
        },
        &mut scratch,
        &mut parser_buf,
    );
    match step {
        Step::Done { .. } => {
            *backlog = parser_buf;
            TerminatorDrain::Consumed
        }
        Step::NeedMore => {
            if parser_buf.len() > MAX_TRAILER_BYTES {
                parser_buf.zeroize();
                *backlog = Vec::new();
                return TerminatorDrain::NotTerminator;
            }
            *backlog = parser_buf;
            TerminatorDrain::NeedMore
        }
        Step::Failed(_) | Step::Progress | Step::InterimSkipped => {
            parser_buf.zeroize();
            *backlog = Vec::new();
            TerminatorDrain::NotTerminator
        }
    }
}

fn step_raw(
    config: &ResponsePipelineConfig,
    response: &mut ResponseAssembly,
    backlog: &mut Vec<u8>,
) -> Step {
    let feed = match response.content_length_remaining {
        Some(remaining) => remaining.min(backlog.len()),
        None => backlog.len(),
    };
    if feed == 0 {
        return if response.content_length_remaining == Some(0) {
            Step::Done {
                drain_terminator: false,
            }
        } else {
            Step::NeedMore
        };
    }
    let outcome = match feed_parser_bytes_outcome(config, response, &backlog[..feed]) {
        Ok(outcome) => outcome,
        Err(reason) => return Step::Failed(reason),
    };
    // Without `[DONE]` the parser holds any partial line; drain everything fed. With `[DONE]`
    // only the bytes up to the terminator are consumed so a following response stays buffered.
    let drained = if outcome.done { outcome.consumed } else { feed };
    backlog.drain(..drained);
    if let Some(remaining) = response.content_length_remaining.as_mut() {
        *remaining = remaining.saturating_sub(drained);
    }
    if outcome.done {
        return Step::Done {
            drain_terminator: false,
        };
    }
    if response.content_length_remaining == Some(0) {
        return Step::Done {
            drain_terminator: false,
        };
    }
    Step::Progress
}

/// Feed raw (identity) body bytes into the SSE parser.
fn feed_parser_bytes(
    config: &ResponsePipelineConfig,
    response: &mut ResponseAssembly,
    bytes: &[u8],
) -> Result<bool, &'static str> {
    Ok(feed_parser_bytes_outcome(config, response, bytes)?.done)
}

fn feed_parser_bytes_outcome(
    config: &ResponsePipelineConfig,
    response: &mut ResponseAssembly,
    bytes: &[u8],
) -> Result<SseOutcome, &'static str> {
    let mut plain: Vec<u8> = Vec::new();
    let body: &[u8] = if response.body_mode == BodyMode::Gzip {
        let inflater = response.inflater.as_mut().expect("gzip inflater exists");
        let before = inflater.total_in();
        let ok = inflater
            .decompress_vec(bytes, &mut plain, FlushDecompress::Sync)
            .is_ok()
            && inflater.total_in() - before == bytes.len() as u64
            && plain.len() <= config.max_decompressed_bytes;
        if !ok {
            plain.zeroize();
            return Err("response_gzip_decode_failed");
        }
        &plain
    } else {
        bytes
    };
    let had_data = response.parser.saw_data;
    let outcome = response.parser.push(body, config.max_content_bytes)?;
    if !had_data && response.parser.saw_data {
        response.first_data_at_monotonic_ns = Some(response.last_fragment_at_monotonic_ns);
    }
    plain.zeroize();
    Ok(outcome)
}

struct ResponseHeaders {
    body_mode: BodyMode,
    content_length: Option<usize>,
    /// 1xx interim response (`100 Continue`); skipped, the real response follows.
    interim: bool,
}

fn parse_response_headers(header_bytes: &[u8]) -> Result<(u16, ResponseHeaders), &'static str> {
    // A bare interim response (`HTTP/1.1 100 Continue`) carries no header lines at all.
    let first_line_end = find_bytes(header_bytes, b"\r\n").unwrap_or(header_bytes.len());
    let first_line = std::str::from_utf8(&header_bytes[..first_line_end])
        .map_err(|_| "http_response_status_line_invalid")?;
    let mut start = first_line.split_whitespace();
    let version = start.next().ok_or("http_response_status_line_invalid")?;
    if !version.starts_with("HTTP/1.") {
        return Err("http_response_status_line_invalid");
    }
    let status_code = start
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("http_response_status_line_invalid")?;
    let mut chunked = false;
    let mut gzip = false;
    let mut content_length = None;
    let header_lines = if first_line_end + 2 <= header_bytes.len() {
        &header_bytes[first_line_end + 2..]
    } else {
        &[][..]
    };
    for line in header_lines.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = trim_ascii(&line[..colon]);
        let value = trim_ascii(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            chunked = ascii_contains_ignore_case(value, b"chunked");
        } else if name.eq_ignore_ascii_case(b"content-encoding") {
            gzip = value.eq_ignore_ascii_case(b"gzip");
        } else if name.eq_ignore_ascii_case(b"content-length") {
            content_length = std::str::from_utf8(value)
                .ok()
                .and_then(|value| value.parse::<usize>().ok());
        }
    }
    let interim = (100..200).contains(&status_code) && status_code != 101;
    let body_mode = if chunked {
        BodyMode::Chunked
    } else if gzip {
        BodyMode::Gzip
    } else {
        BodyMode::Raw
    };
    Ok((
        status_code,
        ResponseHeaders {
            body_mode,
            content_length,
            interim,
        },
    ))
}

fn floor_char_boundary(text: &str, index: usize) -> usize {
    if index >= text.len() {
        return text.len();
    }
    let mut boundary = index;
    while !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

fn wipe_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe_json),
        Value::Object(values) => values.values_mut().for_each(wipe_json),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn ascii_contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    let mut encoded = String::with_capacity(digest.len() * 2);
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{ReadFragment, RequestContext, ResponsePipeline, ResponsePipelineConfig};
    use std::time::{Duration, Instant};

    fn config() -> ResponsePipelineConfig {
        ResponsePipelineConfig {
            max_connections: 4,
            max_inflight_calls: 8,
            max_response_bytes: 1024 * 1024,
            max_content_bytes: 64 * 1024,
            max_decompressed_bytes: 1024 * 1024,
            reassembly_timeout: Duration::from_secs(30),
        }
    }

    fn request_context(sent_at: u64) -> RequestContext {
        RequestContext {
            host: "api.kimi.com".to_string(),
            path: "/coding/v1/chat/completions".to_string(),
            endpoint_attribution: "observed_headers".to_string(),
            provider: "openai_compatible".to_string(),
            model: Some("k3-256k".to_string()),
            sent_at_monotonic_ns: sent_at,
            cgroup_id: 7,
            comm: *b"kimi\0\0\0\0\0\0\0\0\0\0\0\0",
        }
    }

    /// Feed bytes as one SSL_read call per `call_chunk` slice, each call split into ring
    /// fragments of `fragment_bytes`.
    fn feed(
        pipeline: &mut ResponsePipeline,
        pid: u32,
        ssl_pointer: u64,
        call_sequence: &mut u64,
        bytes: &[u8],
        call_chunk: usize,
        fragment_bytes: usize,
    ) {
        for call_bytes in bytes.chunks(call_chunk) {
            *call_sequence += 1;
            let call = *call_sequence;
            for (fragment_index, fragment) in call_bytes.chunks(fragment_bytes).enumerate() {
                let offset = fragment_index * fragment_bytes;
                pipeline.push_read(
                    ReadFragment {
                        pid,
                        tid: pid,
                        ssl_pointer,
                        call_sequence: call,
                        fragment_index: fragment_index as u32,
                        fragment_offset: offset as u64,
                        original_length: call_bytes.len() as u64,
                        observed_at_monotonic_ns: call * 1_000_000 + offset as u64,
                        truncated: false,
                        bytes: fragment,
                    },
                    Instant::now(),
                );
            }
        }
    }

    fn chunked_encode(body: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut out = chunked_encode_open(body, chunk_size);
        out.extend_from_slice(b"0\r\n\r\n");
        out
    }

    /// Chunked body without the terminal zero chunk — an aborted/incomplete stream.
    fn chunked_encode_open(body: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in body.chunks(chunk_size) {
            out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            out.extend_from_slice(chunk);
            out.extend_from_slice(b"\r\n");
        }
        out
    }

    fn sse_body(events: &[&str]) -> String {
        let mut body = String::new();
        for event in events {
            body.push_str("data: ");
            body.push_str(event);
            body.push_str("\n\n");
        }
        body
    }

    const RESPONSE_HEADERS: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";

    fn full_response(events: &[&str], done: bool) -> Vec<u8> {
        let mut body = sse_body(events);
        if done {
            body.push_str("data: [DONE]\n\n");
        }
        let mut response = RESPONSE_HEADERS.to_vec();
        response.extend_from_slice(&chunked_encode(body.as_bytes(), 97));
        response
    }

    /// Headers + chunked SSE events with no `[DONE]` and no terminal chunk: the stream an
    /// aborted/cancelled response leaves behind.
    fn aborted_response(events: &[&str]) -> Vec<u8> {
        let mut response = RESPONSE_HEADERS.to_vec();
        response.extend_from_slice(&chunked_encode_open(sse_body(events).as_bytes(), 97));
        response
    }

    #[test]
    fn aggregates_sse_text_usage_and_finish_across_fragments() {
        let mut pipeline = ResponsePipeline::new(config()).unwrap();
        pipeline.register_request(42, 900, request_context(500), Instant::now());
        let response = full_response(
            &[
                r#"{"model":"k3-256k","choices":[{"delta":{"role":"assistant","content":"Hello"}}]}"#,
                r#"{"choices":[{"delta":{"content":" kimi"}}]}"#,
                r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1200,"completion_tokens":9,"total_tokens":1209}}"#,
            ],
            true,
        );
        let mut sequence = 0;
        // Single-byte ring fragments across multi-call delivery.
        feed(&mut pipeline, 42, 900, &mut sequence, &response, 4096, 61);

        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 1);
        let observed = &observations[0];
        assert_eq!(observed.pid, 42);
        assert_eq!(observed.host, "api.kimi.com");
        assert_eq!(observed.path, "/coding/v1/chat/completions");
        assert_eq!(observed.status_code, 200);
        assert_eq!(observed.assistant_content, "Hello kimi");
        assert_eq!(observed.content_bytes, 10);
        assert_eq!(observed.model.as_deref(), Some("k3-256k"));
        assert_eq!(observed.finish_reason.as_deref(), Some("stop"));
        assert_eq!(observed.prompt_tokens, Some(1200));
        assert_eq!(observed.completion_tokens, Some(9));
        assert_eq!(observed.total_tokens, Some(1209));
        assert!(observed.tool_calls.is_empty());
        assert_eq!(observed.capture_completeness, "complete");
        assert_eq!(observed.parse_status, "parsed");
        assert!(observed.ttft_ns.is_some());
        assert!(observed.duration_ns.is_some());
        assert_eq!(pipeline.stats().responses_paired, 1);
        assert_eq!(pipeline.stats().parse_failed, 0);
    }

    #[test]
    fn splits_sse_data_lines_across_ssl_calls() {
        let mut pipeline = ResponsePipeline::new(config()).unwrap();
        pipeline.register_request(7, 42, request_context(100), Instant::now());
        let response = full_response(
            &[
                r#"{"choices":[{"delta":{"content":"abcdef"}}]}"#,
                r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}"#,
            ],
            true,
        );
        let mut sequence = 0;
        // 7-byte SSL_read calls, 3-byte ring fragments: every boundary is crossed.
        feed(&mut pipeline, 7, 42, &mut sequence, &response, 7, 3);
        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].assistant_content, "abcdef");
        assert_eq!(observations[0].capture_completeness, "complete");
    }

    #[test]
    fn joins_incremental_tool_call_arguments() {
        let mut pipeline = ResponsePipeline::new(config()).unwrap();
        pipeline.register_request(9, 77, request_context(100), Instant::now());
        let response = full_response(
            &[
                r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"bash","arguments":"{\"com"}}]}}]}"#,
                r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"mand\":\"ls\"}"}}]}}]}"#,
                r#"{"choices":[{"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}"#,
            ],
            true,
        );
        let mut sequence = 0;
        feed(&mut pipeline, 9, 77, &mut sequence, &response, 1000, 53);
        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 1);
        let observed = &observations[0];
        assert_eq!(observed.assistant_content, "");
        assert_eq!(observed.finish_reason.as_deref(), Some("tool_calls"));
        assert_eq!(observed.tool_calls.len(), 1);
        assert_eq!(observed.tool_calls[0].id, "call_1");
        assert_eq!(observed.tool_calls[0].name, "bash");
        assert_eq!(observed.tool_calls[0].arguments, r#"{"command":"ls"}"#);
        assert_eq!(observed.completion_tokens, Some(20));
    }

    #[test]
    fn tolerates_missing_usage_and_supports_multi_data_line_events() {
        let mut pipeline = ResponsePipeline::new(config()).unwrap();
        pipeline.register_request(5, 8, request_context(100), Instant::now());
        // One event block split across two data: lines (valid SSE), no usage anywhere.
        let mut body = String::new();
        body.push_str("data: {\"choices\":[{\"delta\":{\"content\":\"partA\"}}],");
        body.push('\n');
        body.push_str("data: \"model\":\"k3-256k\"}\n\n");
        body.push_str("data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"length\"}]}\n\n");
        body.push_str("data: [DONE]\n\n");
        let mut response = RESPONSE_HEADERS.to_vec();
        response.extend_from_slice(&chunked_encode(body.as_bytes(), 64));
        let mut sequence = 0;
        feed(&mut pipeline, 5, 8, &mut sequence, &response, 512, 41);
        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 1);
        let observed = &observations[0];
        assert_eq!(observed.assistant_content, "partA");
        assert_eq!(observed.prompt_tokens, None);
        assert_eq!(observed.completion_tokens, None);
        assert_eq!(observed.total_tokens, None);
        assert_eq!(observed.finish_reason.as_deref(), Some("length"));
        assert_eq!(observed.parse_status, "parsed");
    }

    #[test]
    fn abort_without_done_finalizes_partial_on_process_exit() {
        let mut pipeline = ResponsePipeline::new(config()).unwrap();
        pipeline.register_request(11, 9001, request_context(100), Instant::now());
        let response =
            aborted_response(&[r#"{"choices":[{"delta":{"content":"partial answer"}}]}"#]);
        let mut sequence = 0;
        feed(&mut pipeline, 11, 9001, &mut sequence, &response, 2048, 127);
        assert!(pipeline.take_observations().is_empty());
        pipeline.forget_pid(11);
        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 1);
        let observed = &observations[0];
        assert_eq!(observed.assistant_content, "partial answer");
        assert_eq!(observed.finish_reason, None);
        assert_eq!(observed.capture_completeness, "partial");
        assert_eq!(observed.parse_status, "partial");
        assert_eq!(observed.prompt_tokens, None);
    }

    #[test]
    fn expires_idle_streams_as_partial() {
        let mut pipeline = ResponsePipeline::new(config()).unwrap();
        let start = Instant::now();
        pipeline.register_request(13, 9002, request_context(100), start);
        let response = aborted_response(&[r#"{"choices":[{"delta":{"content":"stale"}}]}"#]);
        let mut sequence = 0;
        feed(&mut pipeline, 13, 9002, &mut sequence, &response, 2048, 127);
        pipeline.expire(start + Duration::from_secs(60));
        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].capture_completeness, "partial");
        assert_eq!(pipeline.stats().responses_timeout, 1);
    }

    #[test]
    fn reads_without_pending_request_are_dropped_without_event() {
        let mut pipeline = ResponsePipeline::new(config()).unwrap();
        let response = full_response(
            &[r#"{"choices":[{"delta":{"content":"telemetry side-channel"}}]}"#],
            true,
        );
        let mut sequence = 0;
        feed(&mut pipeline, 21, 4242, &mut sequence, &response, 2048, 63);
        // Unpaired responses (telemetry, OAuth) never surface as LLM events.
        assert!(pipeline.take_observations().is_empty());
        assert_eq!(pipeline.stats().responses_unpaired, 1);
        assert_eq!(pipeline.stats().responses_paired, 0);
        assert_eq!(pipeline.stats().responses_completed, 0);
    }

    #[test]
    fn sequential_requests_on_one_connection_pair_in_order() {
        let mut pipeline = ResponsePipeline::new(config()).unwrap();
        let mut sequence = 0;
        for (index, text) in ["first", "second"].iter().enumerate() {
            let mut context = request_context(100 + index as u64);
            context.path = format!("/coding/v1/chat/completions#{index}");
            pipeline.register_request(33, 555, context, Instant::now());
            let event = format!(
                r#"{{"choices":[{{"delta":{{"content":"{text}"}},"finish_reason":"stop"}}]}}"#
            );
            let response = full_response(&[&event], true);
            feed(&mut pipeline, 33, 555, &mut sequence, &response, 2048, 200);
        }
        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].assistant_content, "first");
        assert_eq!(observations[0].path, "/coding/v1/chat/completions#0");
        assert_eq!(observations[1].assistant_content, "second");
        assert_eq!(observations[1].path, "/coding/v1/chat/completions#1");
        assert_eq!(pipeline.stats().responses_paired, 2);
    }

    #[test]
    fn content_cap_marks_truncated_but_keeps_usage() {
        let mut tight = config();
        tight.max_content_bytes = 16;
        let mut pipeline = ResponsePipeline::new(tight).unwrap();
        pipeline.register_request(55, 12, request_context(100), Instant::now());
        let long_text = "abcdefghij".repeat(10);
        let event = format!(r#"{{"choices":[{{"delta":{{"content":"{long_text}"}}}}]}}"#);
        let usage = r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}"#;
        let response = full_response(&[&event, usage], true);
        let mut sequence = 0;
        feed(&mut pipeline, 55, 12, &mut sequence, &response, 2048, 511);
        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 1);
        let observed = &observations[0];
        assert_eq!(observed.capture_completeness, "truncated");
        assert_eq!(observed.parse_status, "partial");
        assert_eq!(observed.content_bytes, 16);
        assert_eq!(observed.total_tokens, Some(3));
    }

    /// Regression: HTTP/1.1 keep-alive reuse. kimi (undici) pools connections, so response N+1
    /// follows response N on the same ssl_pointer. The chunked terminator of response N may
    /// arrive in a later SSL_read than `[DONE]`, coalesced with response N+1's headers. The
    /// pipeline must consume the terminator and keep the connection alive for the next response.
    #[test]
    fn keep_alive_reuse_coalesced_terminator_pairs_both_responses() {
        let mut pipeline = ResponsePipeline::new(config()).unwrap();
        let mut sequence = 0;
        pipeline.register_request(42, 900, request_context(500), Instant::now());
        pipeline.register_request(42, 900, request_context(600), Instant::now());

        // Response 1: headers + SSE events + [DONE], WITHOUT the chunked terminator.
        let mut resp1 = RESPONSE_HEADERS.to_vec();
        let body1 = sse_body(&[
            r#"{"choices":[{"delta":{"content":"answer-one"}}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}"#,
        ]) + "data: [DONE]\n\n";
        resp1.extend_from_slice(&chunked_encode_open(body1.as_bytes(), 64));
        feed(&mut pipeline, 42, 900, &mut sequence, &resp1, 4096, 97);

        // Response 1 completes at [DONE]; its terminator then arrives coalesced with the start
        // of response 2 on the same connection.
        let mut resp2 = b"0\r\n\r\n".to_vec();
        resp2.extend_from_slice(RESPONSE_HEADERS);
        let body2 = sse_body(&[
            r#"{"choices":[{"delta":{"content":"answer-two"}}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":5,"total_tokens":9}}"#,
        ]) + "data: [DONE]\n\n";
        resp2.extend_from_slice(&chunked_encode(body2.as_bytes(), 128));
        feed(&mut pipeline, 42, 900, &mut sequence, &resp2, 4096, 8192);

        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 2, "both responses must be emitted");
        assert_eq!(observations[0].assistant_content, "answer-one");
        assert_eq!(observations[0].capture_completeness, "complete");
        assert_eq!(observations[1].assistant_content, "answer-two");
        assert_eq!(observations[1].capture_completeness, "complete");
        assert_eq!(observations[1].total_tokens, Some(9));
        assert_eq!(pipeline.stats().responses_paired, 2);
        assert_eq!(pipeline.stats().responses_unpaired, 0);
        assert_eq!(pipeline.stats().parse_failed, 0);
    }

    #[test]
    fn keep_alive_reuse_split_terminator_and_interim_continue() {
        let mut pipeline = ResponsePipeline::new(config()).unwrap();
        let mut sequence = 0;
        pipeline.register_request(43, 901, request_context(500), Instant::now());
        pipeline.register_request(43, 901, request_context(600), Instant::now());

        let mut resp1 = RESPONSE_HEADERS.to_vec();
        let body1 =
            sse_body(&[r#"{"choices":[{"delta":{"content":"one"}}]}"#]) + "data: [DONE]\n\n";
        resp1.extend_from_slice(&chunked_encode_open(body1.as_bytes(), 64));
        feed(&mut pipeline, 43, 901, &mut sequence, &resp1, 4096, 4096);
        // Terminator arrives alone in a later read.
        feed(
            &mut pipeline,
            43,
            901,
            &mut sequence,
            b"0\r\n\r\n",
            4096,
            4096,
        );

        // Response 2 is preceded by a 100 Continue interim response.
        let mut resp2 = b"HTTP/1.1 100 Continue\r\n\r\n".to_vec();
        resp2.extend_from_slice(RESPONSE_HEADERS);
        let body2 =
            sse_body(&[r#"{"choices":[{"delta":{"content":"two"}}]}"#]) + "data: [DONE]\n\n";
        resp2.extend_from_slice(&chunked_encode(body2.as_bytes(), 128));
        feed(&mut pipeline, 43, 901, &mut sequence, &resp2, 4096, 4096);

        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].assistant_content, "one");
        assert_eq!(observations[1].assistant_content, "two");
        assert_eq!(observations[1].status_code, 200);
        assert_eq!(pipeline.stats().parse_failed, 0);
    }
    #[test]
    fn non_sse_response_fails_closed_without_panic() {
        let mut pipeline = ResponsePipeline::new(config()).unwrap();
        pipeline.register_request(77, 1, request_context(100), Instant::now());
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\nhello";
        let mut sequence = 0;
        feed(&mut pipeline, 77, 1, &mut sequence, response, 2048, 32);
        pipeline.forget_pid(77);
        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].parse_status, "failed");
        assert_eq!(observations[0].capture_completeness, "partial");
    }
}
