//! Isolated Phase -1 TLS plaintext reassembly and provider parsing.
//!
//! This module is deliberately not part of the normal Observer exporter contract. Parsed
//! plaintext is written only to a caller-selected, newly-created `0600` fixture artifact. The
//! production `metadata` mode never constructs this pipeline.

use anyhow::{bail, Context as _};
use flate2::{read::GzDecoder, Decompress, FlushDecompress};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 128;

#[derive(Debug, Clone)]
pub struct FixturePipelineConfig {
    pub output_path: PathBuf,
    pub allowed_provider_hosts: Vec<String>,
    pub max_connections: usize,
    pub max_inflight_calls: usize,
    pub max_reassembly_bytes: usize,
    pub max_decompressed_bytes: usize,
    pub reassembly_timeout: Duration,
    pub retain_instruction_content: bool,
}

#[derive(Debug, Clone)]
pub struct RuntimePipelineConfig {
    pub allowed_provider_hosts: Vec<String>,
    pub configured_endpoint_attribution: &'static str,
    pub max_connections: usize,
    pub max_inflight_calls: usize,
    pub max_reassembly_bytes: usize,
    pub max_decompressed_bytes: usize,
    pub reassembly_timeout: Duration,
}

#[derive(Debug)]
pub struct ObservedLlmRequest {
    pub pid: u32,
    pub tid: u32,
    pub observed_at_monotonic_ns: u64,
    pub protocol: String,
    pub host: String,
    pub path: String,
    pub endpoint_attribution: String,
    pub provider: String,
    pub model: Option<String>,
    pub session_id: Option<String>,
    pub thread_id: Option<String>,
    pub turn_id: Option<String>,
    pub window_id: Option<String>,
    pub request_kind: Option<String>,
    pub body_sha256: String,
    pub instruction_bytes: u32,
    pub instruction_sha256: String,
    pub user_instruction: String,
}

#[derive(Debug)]
pub struct FixtureFragment<'a> {
    pub pid: u32,
    pub tid: u32,
    pub ssl_pointer: u64,
    pub call_sequence: u64,
    pub fragment_index: u32,
    pub fragment_offset: u64,
    pub original_length: u64,
    pub observed_at_monotonic_ns: u64,
    pub is_read: bool,
    pub truncated: bool,
    pub bytes: &'a [u8],
}

#[derive(Debug)]
pub struct FixtureNativeInput<'a> {
    pub pid: u32,
    pub tid: u32,
    pub fd: u32,
    pub observed_at_monotonic_ns: u64,
    pub eof: bool,
    pub truncated: bool,
    pub comm: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Debug)]
pub struct FixtureNativeOutput<'a> {
    pub pid: u32,
    pub tid: u32,
    pub fd: u32,
    pub observed_at_monotonic_ns: u64,
    pub eof: bool,
    pub truncated: bool,
    pub comm: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CallKey {
    pid: u32,
    tid: u32,
    ssl_pointer: u64,
    call_sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StreamKey {
    pid: u32,
    ssl_pointer: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NativeInputKey {
    pid: u32,
    fd: u32,
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

struct StreamAssembly {
    bytes: Vec<u8>,
    last_seen: Instant,
}

struct WebSocketConnection {
    host: String,
    path: String,
    endpoint_attribution: String,
    inflater: Decompress,
}

struct NativeInputAssembly {
    bytes: Vec<u8>,
    observed_at_monotonic_ns: u64,
    last_tid: u32,
    comm: String,
    last_seen: Instant,
}

impl Drop for NativeInputAssembly {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.comm.zeroize();
    }
}

impl Drop for StreamAssembly {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct FixturePipelineStats {
    pub fragments_observed: u64,
    pub fragments_rejected: u64,
    pub calls_completed: u64,
    pub calls_incomplete: u64,
    /// Calls dropped because one `SSL_*` call exceeded the capture ceiling
    /// (`fragment.truncated` or `original_length > max_reassembly_bytes`). A rising value means
    /// whole requests are being lost to size, which previously surfaced only as a stall.
    pub calls_oversized: u64,
    pub requests_completed: u64,
    pub requests_parsed: u64,
    pub requests_ignored: u64,
    pub parse_failed: u64,
    pub capacity_dropped: u64,
    pub native_fragments_observed: u64,
    pub native_instructions_completed: u64,
    pub native_instructions_incomplete: u64,
    pub native_output_fragments_observed: u64,
    pub native_responses_completed: u64,
    pub native_responses_incomplete: u64,
}

pub struct FixturePipeline {
    config: FixturePipelineConfig,
    allowed_provider_hosts: HashSet<String>,
    output: Option<BufWriter<File>>,
    runtime_mode: bool,
    runtime_configured_endpoint_attribution: &'static str,
    runtime_observations: VecDeque<ObservedLlmRequest>,
    calls: HashMap<CallKey, CallAssembly>,
    streams: HashMap<StreamKey, StreamAssembly>,
    websockets: HashMap<StreamKey, WebSocketConnection>,
    native_inputs: HashMap<NativeInputKey, NativeInputAssembly>,
    native_outputs: HashMap<NativeInputKey, NativeInputAssembly>,
    /// Call sequences already counted as oversized: an over-ceiling call arrives as hundreds of
    /// fragments (captured prefix + truncated marker), but it must warn and count only once.
    oversized_calls: HashSet<CallKey>,
    stats: FixturePipelineStats,
}

impl FixturePipeline {
    pub fn new(config: FixturePipelineConfig) -> anyhow::Result<Self> {
        if !config.output_path.is_absolute() {
            bail!("fixture output path must be absolute");
        }
        if config.allowed_provider_hosts.is_empty() {
            bail!("fixture capture requires at least one explicit provider host");
        }
        if config.max_connections == 0
            || config.max_inflight_calls == 0
            || config.max_reassembly_bytes == 0
            || config.max_decompressed_bytes == 0
        {
            bail!("fixture pipeline limits must be greater than zero");
        }
        let parent = config
            .output_path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .context("fixture output has no parent directory")?;
        if !parent.exists() {
            bail!("fixture output parent does not exist");
        }
        let allowed_provider_hosts = config
            .allowed_provider_hosts
            .iter()
            .filter_map(|host| normalize_host(host))
            .collect::<HashSet<_>>();
        if allowed_provider_hosts.is_empty() {
            bail!("fixture provider host allowlist contains no valid host");
        }
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&config.output_path)
            .with_context(|| {
                format!(
                    "failed to create isolated fixture output {}",
                    config.output_path.display()
                )
            })?;
        Ok(Self {
            config,
            allowed_provider_hosts,
            output: Some(BufWriter::new(output)),
            runtime_mode: false,
            runtime_configured_endpoint_attribution: "unavailable",
            runtime_observations: VecDeque::new(),
            calls: HashMap::new(),
            streams: HashMap::new(),
            websockets: HashMap::new(),
            native_inputs: HashMap::new(),
            native_outputs: HashMap::new(),
            oversized_calls: HashSet::new(),
            stats: FixturePipelineStats::default(),
        })
    }

    pub fn new_runtime(config: RuntimePipelineConfig) -> anyhow::Result<Self> {
        if config.allowed_provider_hosts.is_empty() {
            bail!("runtime capture requires at least one explicit provider host");
        }
        if config.max_connections == 0
            || config.max_inflight_calls == 0
            || config.max_reassembly_bytes == 0
            || config.max_decompressed_bytes == 0
        {
            bail!("runtime interaction pipeline limits must be greater than zero");
        }
        let allowed_provider_hosts = config
            .allowed_provider_hosts
            .iter()
            .filter_map(|host| normalize_host(host))
            .collect::<HashSet<_>>();
        if allowed_provider_hosts.is_empty() {
            bail!("runtime provider host allowlist contains no valid host");
        }
        if !matches!(
            config.configured_endpoint_attribution,
            "configured_endpoint" | "configured_late_attach"
        ) {
            bail!("runtime configured endpoint attribution is invalid");
        }
        Ok(Self {
            config: FixturePipelineConfig {
                output_path: PathBuf::new(),
                allowed_provider_hosts: config.allowed_provider_hosts,
                max_connections: config.max_connections,
                max_inflight_calls: config.max_inflight_calls,
                max_reassembly_bytes: config.max_reassembly_bytes,
                max_decompressed_bytes: config.max_decompressed_bytes,
                reassembly_timeout: config.reassembly_timeout,
                retain_instruction_content: true,
            },
            allowed_provider_hosts,
            output: None,
            runtime_mode: true,
            runtime_configured_endpoint_attribution: config.configured_endpoint_attribution,
            runtime_observations: VecDeque::new(),
            calls: HashMap::new(),
            streams: HashMap::new(),
            websockets: HashMap::new(),
            native_inputs: HashMap::new(),
            native_outputs: HashMap::new(),
            oversized_calls: HashSet::new(),
            stats: FixturePipelineStats::default(),
        })
    }

    pub fn take_observations(&mut self) -> Vec<ObservedLlmRequest> {
        self.runtime_observations.drain(..).collect()
    }

    pub fn push(&mut self, fragment: FixtureFragment<'_>, now: Instant) -> anyhow::Result<()> {
        self.stats.fragments_observed = self.stats.fragments_observed.saturating_add(1);
        self.expire(now)?;
        if fragment.is_read {
            // The fixture lane only parses local writes. In runtime payload mode, kimi
            // read fragments are routed to `interaction_response` before reaching this
            // pipeline, so a read here is fixture-mode only and intentionally discarded.
            return Ok(());
        }
        if fragment.pid == 0 || fragment.ssl_pointer == 0 || fragment.original_length == 0 {
            self.stats.fragments_rejected = self.stats.fragments_rejected.saturating_add(1);
            return Ok(());
        }
        if fragment.truncated || fragment.original_length > self.config.max_reassembly_bytes as u64
        {
            let key = CallKey {
                pid: fragment.pid,
                tid: fragment.tid,
                ssl_pointer: fragment.ssl_pointer,
                call_sequence: fragment.call_sequence,
            };
            self.calls.remove(&key);
            // An over-ceiling call arrives as one fragment per 31 KiB of captured prefix plus a
            // truncated marker: count and warn once per call, drop the rest of its fragments
            // silently.
            if self.oversized_calls.insert(key) {
                if self.oversized_calls.len() > 1_024 {
                    self.oversized_calls.clear();
                    self.oversized_calls.insert(key);
                }
                self.stats.calls_incomplete = self.stats.calls_incomplete.saturating_add(1);
                self.stats.calls_oversized = self.stats.calls_oversized.saturating_add(1);
                self.write_loss_with_len(
                    "tls_call_truncated",
                    fragment.pid,
                    fragment.ssl_pointer,
                    fragment.call_sequence,
                    fragment.observed_at_monotonic_ns,
                    fragment.original_length,
                )?;
                // The clamped prefix may already have been reassembled and appended to the
                // stream as an uncompletable partial request; drop it so the connection is
                // aligned for the next request.
                self.streams.remove(&StreamKey {
                    pid: fragment.pid,
                    ssl_pointer: fragment.ssl_pointer,
                });
            }
            return Ok(());
        }
        if fragment.bytes.is_empty() {
            self.stats.fragments_rejected = self.stats.fragments_rejected.saturating_add(1);
            return Ok(());
        }

        let key = CallKey {
            pid: fragment.pid,
            tid: fragment.tid,
            ssl_pointer: fragment.ssl_pointer,
            call_sequence: fragment.call_sequence,
        };
        if !self.calls.contains_key(&key) && self.calls.len() >= self.config.max_inflight_calls {
            self.stats.capacity_dropped = self.stats.capacity_dropped.saturating_add(1);
            self.write_loss(
                "inflight_call_capacity",
                fragment.pid,
                fragment.ssl_pointer,
                fragment.call_sequence,
                fragment.observed_at_monotonic_ns,
            )?;
            return Ok(());
        }
        let original_length = fragment.original_length as usize;
        let call = self.calls.entry(key).or_insert_with(|| CallAssembly {
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
        {
            self.stats.calls_incomplete = self.stats.calls_incomplete.saturating_add(1);
            self.calls.remove(&key);
            self.write_loss(
                "tls_fragment_gap_or_conflict",
                fragment.pid,
                fragment.ssl_pointer,
                fragment.call_sequence,
                fragment.observed_at_monotonic_ns,
            )?;
            return Ok(());
        }
        if call.bytes.len().saturating_add(fragment.bytes.len()) > call.original_length {
            self.stats.calls_incomplete = self.stats.calls_incomplete.saturating_add(1);
            self.calls.remove(&key);
            self.write_loss(
                "tls_fragment_length_overflow",
                fragment.pid,
                fragment.ssl_pointer,
                fragment.call_sequence,
                fragment.observed_at_monotonic_ns,
            )?;
            return Ok(());
        }
        call.bytes.extend_from_slice(fragment.bytes);
        call.next_fragment_index = call.next_fragment_index.saturating_add(1);
        if call.bytes.len() != call.original_length {
            return Ok(());
        }
        let mut completed = self.calls.remove(&key).expect("call exists");
        self.stats.calls_completed = self.stats.calls_completed.saturating_add(1);
        self.push_stream(
            StreamKey {
                pid: fragment.pid,
                ssl_pointer: fragment.ssl_pointer,
            },
            fragment.tid,
            &completed.bytes,
            completed.observed_at_monotonic_ns,
            now,
        )?;
        completed.bytes.zeroize();
        Ok(())
    }

    pub fn push_native_input(
        &mut self,
        input: FixtureNativeInput<'_>,
        now: Instant,
    ) -> anyhow::Result<()> {
        self.stats.native_fragments_observed =
            self.stats.native_fragments_observed.saturating_add(1);
        self.expire(now)?;
        if input.pid == 0 || input.fd != 0 {
            self.stats.fragments_rejected = self.stats.fragments_rejected.saturating_add(1);
            return Ok(());
        }
        let key = NativeInputKey {
            pid: input.pid,
            fd: input.fd,
        };
        if input.truncated {
            self.native_inputs.remove(&key);
            self.stats.native_instructions_incomplete =
                self.stats.native_instructions_incomplete.saturating_add(1);
            self.write_loss(
                "native_stdin_read_truncated",
                input.pid,
                u64::from(input.fd) + 1,
                0,
                input.observed_at_monotonic_ns,
            )?;
            return Ok(());
        }
        if input.eof {
            let Some(mut completed) = self.native_inputs.remove(&key) else {
                return Ok(());
            };
            while completed
                .bytes
                .last()
                .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
            {
                completed.bytes.pop();
            }
            if completed.bytes.is_empty() {
                return Ok(());
            }
            self.write_native_instruction(
                key,
                completed.last_tid,
                &completed.comm,
                completed.observed_at_monotonic_ns,
                &completed.bytes,
            )?;
            completed.bytes.zeroize();
            self.stats.native_instructions_completed =
                self.stats.native_instructions_completed.saturating_add(1);
            return Ok(());
        }
        if input.bytes.is_empty() {
            self.stats.fragments_rejected = self.stats.fragments_rejected.saturating_add(1);
            return Ok(());
        }
        if !self.native_inputs.contains_key(&key)
            && self.native_inputs.len() >= self.config.max_connections
        {
            self.stats.capacity_dropped = self.stats.capacity_dropped.saturating_add(1);
            self.stats.native_instructions_incomplete =
                self.stats.native_instructions_incomplete.saturating_add(1);
            self.write_loss(
                "native_stdin_capacity",
                input.pid,
                u64::from(input.fd) + 1,
                0,
                input.observed_at_monotonic_ns,
            )?;
            return Ok(());
        }
        let assembly = self
            .native_inputs
            .entry(key)
            .or_insert_with(|| NativeInputAssembly {
                bytes: Vec::with_capacity(input.bytes.len().min(64 * 1024)),
                observed_at_monotonic_ns: input.observed_at_monotonic_ns,
                last_tid: input.tid,
                comm: input.comm.to_string(),
                last_seen: now,
            });
        if assembly.bytes.len().saturating_add(input.bytes.len()) > self.config.max_reassembly_bytes
        {
            self.native_inputs.remove(&key);
            self.stats.capacity_dropped = self.stats.capacity_dropped.saturating_add(1);
            self.stats.native_instructions_incomplete =
                self.stats.native_instructions_incomplete.saturating_add(1);
            self.write_loss(
                "native_stdin_reassembly_capacity",
                input.pid,
                u64::from(input.fd) + 1,
                0,
                input.observed_at_monotonic_ns,
            )?;
            return Ok(());
        }
        assembly.last_seen = now;
        assembly.last_tid = input.tid;
        assembly.bytes.extend_from_slice(input.bytes);
        Ok(())
    }

    pub fn push_native_output(
        &mut self,
        output: FixtureNativeOutput<'_>,
        now: Instant,
    ) -> anyhow::Result<()> {
        self.stats.native_output_fragments_observed = self
            .stats
            .native_output_fragments_observed
            .saturating_add(1);
        self.expire(now)?;
        if output.pid == 0 || output.fd != 1 {
            self.stats.fragments_rejected = self.stats.fragments_rejected.saturating_add(1);
            return Ok(());
        }
        let key = NativeInputKey {
            pid: output.pid,
            fd: output.fd,
        };
        if output.truncated {
            self.native_outputs.remove(&key);
            self.stats.native_responses_incomplete =
                self.stats.native_responses_incomplete.saturating_add(1);
            self.write_loss(
                "native_stdout_write_truncated",
                output.pid,
                u64::from(output.fd) + 1,
                0,
                output.observed_at_monotonic_ns,
            )?;
            return Ok(());
        }
        if output.eof {
            let Some(mut completed) = self.native_outputs.remove(&key) else {
                return Ok(());
            };
            while completed
                .bytes
                .last()
                .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
            {
                completed.bytes.pop();
            }
            if completed.bytes.is_empty() {
                return Ok(());
            }
            self.write_native_response(
                key,
                completed.last_tid,
                &completed.comm,
                completed.observed_at_monotonic_ns,
                output.observed_at_monotonic_ns,
                &completed.bytes,
            )?;
            completed.bytes.zeroize();
            self.stats.native_responses_completed =
                self.stats.native_responses_completed.saturating_add(1);
            return Ok(());
        }
        if output.bytes.is_empty() {
            self.stats.fragments_rejected = self.stats.fragments_rejected.saturating_add(1);
            return Ok(());
        }
        if !self.native_outputs.contains_key(&key)
            && self.native_outputs.len() >= self.config.max_connections
        {
            self.stats.capacity_dropped = self.stats.capacity_dropped.saturating_add(1);
            self.stats.native_responses_incomplete =
                self.stats.native_responses_incomplete.saturating_add(1);
            self.write_loss(
                "native_stdout_capacity",
                output.pid,
                u64::from(output.fd) + 1,
                0,
                output.observed_at_monotonic_ns,
            )?;
            return Ok(());
        }
        let assembly = self
            .native_outputs
            .entry(key)
            .or_insert_with(|| NativeInputAssembly {
                bytes: Vec::with_capacity(output.bytes.len().min(64 * 1024)),
                observed_at_monotonic_ns: output.observed_at_monotonic_ns,
                last_tid: output.tid,
                comm: output.comm.to_string(),
                last_seen: now,
            });
        if assembly.bytes.len().saturating_add(output.bytes.len())
            > self.config.max_reassembly_bytes
        {
            self.native_outputs.remove(&key);
            self.stats.capacity_dropped = self.stats.capacity_dropped.saturating_add(1);
            self.stats.native_responses_incomplete =
                self.stats.native_responses_incomplete.saturating_add(1);
            self.write_loss(
                "native_stdout_reassembly_capacity",
                output.pid,
                u64::from(output.fd) + 1,
                0,
                output.observed_at_monotonic_ns,
            )?;
            return Ok(());
        }
        assembly.last_seen = now;
        assembly.last_tid = output.tid;
        assembly.bytes.extend_from_slice(output.bytes);
        Ok(())
    }

    pub fn expire(&mut self, now: Instant) -> anyhow::Result<()> {
        let timeout = self.config.reassembly_timeout;
        let expired_calls = self
            .calls
            .iter()
            .filter_map(|(key, value)| {
                (now.saturating_duration_since(value.last_seen) >= timeout)
                    .then_some((*key, value.observed_at_monotonic_ns))
            })
            .collect::<Vec<_>>();
        for (key, observed_at) in expired_calls {
            self.calls.remove(&key);
            self.stats.calls_incomplete = self.stats.calls_incomplete.saturating_add(1);
            self.write_loss(
                "tls_call_reassembly_timeout",
                key.pid,
                key.ssl_pointer,
                key.call_sequence,
                observed_at,
            )?;
        }
        let expired_streams = self
            .streams
            .iter()
            .filter_map(|(key, value)| {
                (now.saturating_duration_since(value.last_seen) >= timeout).then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in expired_streams {
            if let Some(stream) = self.streams.remove(&key) {
                if !stream.bytes.is_empty() {
                    self.stats.parse_failed = self.stats.parse_failed.saturating_add(1);
                    self.write_loss("http_reassembly_timeout", key.pid, key.ssl_pointer, 0, 0)?;
                }
            }
        }
        let expired_native = self
            .native_inputs
            .iter()
            .filter_map(|(key, value)| {
                (now.saturating_duration_since(value.last_seen) >= timeout)
                    .then_some((*key, value.observed_at_monotonic_ns))
            })
            .collect::<Vec<_>>();
        for (key, observed_at) in expired_native {
            self.native_inputs.remove(&key);
            self.stats.native_instructions_incomplete =
                self.stats.native_instructions_incomplete.saturating_add(1);
            self.write_loss(
                "native_stdin_reassembly_timeout",
                key.pid,
                u64::from(key.fd) + 1,
                0,
                observed_at,
            )?;
        }
        let expired_native_outputs = self
            .native_outputs
            .iter()
            .filter_map(|(key, value)| {
                (now.saturating_duration_since(value.last_seen) >= timeout)
                    .then_some((*key, value.observed_at_monotonic_ns))
            })
            .collect::<Vec<_>>();
        for (key, observed_at) in expired_native_outputs {
            self.native_outputs.remove(&key);
            self.stats.native_responses_incomplete =
                self.stats.native_responses_incomplete.saturating_add(1);
            self.write_loss(
                "native_stdout_reassembly_timeout",
                key.pid,
                u64::from(key.fd) + 1,
                0,
                observed_at,
            )?;
        }
        Ok(())
    }

    pub fn forget_pid(&mut self, pid: u32) -> anyhow::Result<()> {
        self.calls.retain(|key, _| key.pid != pid);
        self.streams.retain(|key, _| key.pid != pid);
        let interrupted_native = self
            .native_inputs
            .iter()
            .filter_map(|(key, value)| {
                (key.pid == pid).then_some((*key, value.observed_at_monotonic_ns))
            })
            .collect::<Vec<_>>();
        for (key, observed_at) in interrupted_native {
            self.native_inputs.remove(&key);
            self.stats.native_instructions_incomplete =
                self.stats.native_instructions_incomplete.saturating_add(1);
            self.write_loss(
                "native_stdin_process_exit",
                key.pid,
                u64::from(key.fd) + 1,
                0,
                observed_at,
            )?;
        }
        let interrupted_outputs = self
            .native_outputs
            .iter()
            .filter_map(|(key, value)| {
                (key.pid == pid).then_some((*key, value.observed_at_monotonic_ns))
            })
            .collect::<Vec<_>>();
        for (key, observed_at) in interrupted_outputs {
            self.native_outputs.remove(&key);
            self.stats.native_responses_incomplete =
                self.stats.native_responses_incomplete.saturating_add(1);
            self.write_loss(
                "native_stdout_process_exit_without_boundary",
                key.pid,
                u64::from(key.fd) + 1,
                0,
                observed_at,
            )?;
        }
        Ok(())
    }

    pub fn clear_plaintext(&mut self) {
        self.calls.clear();
        self.streams.clear();
        self.websockets.clear();
        self.native_inputs.clear();
        self.native_outputs.clear();
        for mut observation in self.runtime_observations.drain(..) {
            observation.user_instruction.zeroize();
        }
    }

    pub fn stats(&self) -> FixturePipelineStats {
        self.stats
    }

    fn push_stream(
        &mut self,
        key: StreamKey,
        tid: u32,
        bytes: &[u8],
        observed_at_monotonic_ns: u64,
        now: Instant,
    ) -> anyhow::Result<()> {
        if !self.streams.contains_key(&key) && self.streams.len() >= self.config.max_connections {
            self.stats.capacity_dropped = self.stats.capacity_dropped.saturating_add(1);
            self.write_loss(
                "connection_capacity",
                key.pid,
                key.ssl_pointer,
                0,
                observed_at_monotonic_ns,
            )?;
            return Ok(());
        }
        let stream = self.streams.entry(key).or_insert_with(|| StreamAssembly {
            bytes: Vec::with_capacity(bytes.len().min(64 * 1024)),
            last_seen: now,
        });
        stream.last_seen = now;
        if stream.bytes.len().saturating_add(bytes.len()) > self.config.max_reassembly_bytes {
            self.streams.remove(&key);
            self.stats.capacity_dropped = self.stats.capacity_dropped.saturating_add(1);
            self.write_loss(
                "http_reassembly_capacity",
                key.pid,
                key.ssl_pointer,
                0,
                observed_at_monotonic_ns,
            )?;
            return Ok(());
        }
        stream.bytes.extend_from_slice(bytes);
        self.process_stream(key, tid, observed_at_monotonic_ns)
    }

    fn process_stream(
        &mut self,
        key: StreamKey,
        tid: u32,
        observed_at_monotonic_ns: u64,
    ) -> anyhow::Result<()> {
        loop {
            if self.websockets.contains_key(&key) {
                let frame = {
                    let Some(stream) = self.streams.get(&key) else {
                        return Ok(());
                    };
                    parse_masked_websocket_frame(&stream.bytes, self.config.max_reassembly_bytes)
                };
                match frame {
                    WebSocketProgress::NeedMore => return Ok(()),
                    WebSocketProgress::Ignored { consumed } => {
                        consume_stream_prefix(&mut self.streams, key, consumed);
                        if self
                            .streams
                            .get(&key)
                            .is_some_and(|stream| stream.bytes.is_empty())
                        {
                            self.streams.remove(&key);
                            return Ok(());
                        }
                        continue;
                    }
                    WebSocketProgress::Invalid(reason) => {
                        self.stats.parse_failed = self.stats.parse_failed.saturating_add(1);
                        self.streams.remove(&key);
                        self.websockets.remove(&key);
                        self.write_loss(
                            reason,
                            key.pid,
                            key.ssl_pointer,
                            0,
                            observed_at_monotonic_ns,
                        )?;
                        return Ok(());
                    }
                    WebSocketProgress::Complete {
                        consumed,
                        compressed,
                        mut payload,
                    } => {
                        consume_stream_prefix(&mut self.streams, key, consumed);
                        if compressed {
                            payload.extend_from_slice(&[0, 0, 0xff, 0xff]);
                            let mut decoded =
                                Vec::with_capacity(self.config.max_decompressed_bytes);
                            let Some(connection) = self.websockets.get_mut(&key) else {
                                payload.zeroize();
                                return Ok(());
                            };
                            let before = connection.inflater.total_in();
                            let decoded_ok = connection
                                .inflater
                                .decompress_vec(&payload, &mut decoded, FlushDecompress::Sync)
                                .is_ok()
                                && connection.inflater.total_in() - before == payload.len() as u64
                                && decoded.len() <= self.config.max_decompressed_bytes;
                            payload.zeroize();
                            if !decoded_ok {
                                decoded.zeroize();
                                self.stats.parse_failed = self.stats.parse_failed.saturating_add(1);
                                self.websockets.remove(&key);
                                self.write_loss(
                                    "websocket_decompression_failed",
                                    key.pid,
                                    key.ssl_pointer,
                                    0,
                                    observed_at_monotonic_ns,
                                )?;
                                return Ok(());
                            }
                            payload = decoded;
                        }
                        let Some(connection) = self.websockets.get(&key) else {
                            payload.zeroize();
                            return Ok(());
                        };
                        let mut request = HttpRequest {
                            method: "POST".to_string(),
                            path: connection.path.clone(),
                            host: connection.host.clone(),
                            endpoint_attribution: connection.endpoint_attribution.clone(),
                            content_encoding: if compressed {
                                "permessage-deflate".to_string()
                            } else {
                                "identity".to_string()
                            },
                            protocol: "websocket".to_string(),
                            body: payload,
                        };
                        self.stats.requests_completed =
                            self.stats.requests_completed.saturating_add(1);
                        self.observe_request(key, tid, observed_at_monotonic_ns, &mut request)?;
                        if self
                            .streams
                            .get(&key)
                            .is_some_and(|stream| stream.bytes.is_empty())
                        {
                            self.streams.remove(&key);
                            return Ok(());
                        }
                        continue;
                    }
                }
            }

            let handshake = {
                let Some(stream) = self.streams.get(&key) else {
                    return Ok(());
                };
                parse_websocket_handshake(&stream.bytes)
            };
            match handshake {
                WebSocketHandshakeProgress::NeedMore => return Ok(()),
                WebSocketHandshakeProgress::Complete {
                    consumed,
                    host,
                    path,
                } => {
                    consume_stream_prefix(&mut self.streams, key, consumed);
                    self.websockets.insert(
                        key,
                        WebSocketConnection {
                            host,
                            path,
                            endpoint_attribution: "observed_handshake".to_string(),
                            inflater: Decompress::new(false),
                        },
                    );
                    if self
                        .streams
                        .get(&key)
                        .is_some_and(|stream| stream.bytes.is_empty())
                    {
                        self.streams.remove(&key);
                        return Ok(());
                    }
                    continue;
                }
                WebSocketHandshakeProgress::NotHandshake => {}
                WebSocketHandshakeProgress::Invalid(reason) => {
                    self.stats.parse_failed = self.stats.parse_failed.saturating_add(1);
                    self.streams.remove(&key);
                    self.write_loss(
                        reason,
                        key.pid,
                        key.ssl_pointer,
                        0,
                        observed_at_monotonic_ns,
                    )?;
                    return Ok(());
                }
            }

            // Codex's rustls PlaintextSink may expose the first client WebSocket frame without
            // exposing the HTTP upgrade bytes. A masked client frame is still an unambiguous
            // transport boundary, but host/path then come from the explicitly configured provider
            // allowlist. Exact-PID mode labels this as late attach; exact-binary auto-discovery
            // labels it as configured endpoint attribution.
            let configured_websocket_endpoint = self.runtime_mode
                && self.streams.get(&key).is_some_and(|stream| {
                    looks_like_masked_websocket_client_frame(
                        &stream.bytes,
                        self.config.max_reassembly_bytes,
                    )
                });
            if configured_websocket_endpoint {
                let Some(host) = inferred_runtime_provider_host(&self.allowed_provider_hosts)
                else {
                    self.stats.requests_ignored = self.stats.requests_ignored.saturating_add(1);
                    self.streams.remove(&key);
                    return Ok(());
                };
                self.websockets.insert(
                    key,
                    WebSocketConnection {
                        host,
                        path: "/backend-api/codex/responses".to_string(),
                        endpoint_attribution: self
                            .runtime_configured_endpoint_attribution
                            .to_string(),
                        inflater: Decompress::new(false),
                    },
                );
                continue;
            }

            let progress = {
                let Some(stream) = self.streams.get(&key) else {
                    return Ok(());
                };
                parse_http1_request(
                    &stream.bytes,
                    self.config.max_reassembly_bytes,
                    self.config.max_decompressed_bytes,
                )
            };
            match progress {
                HttpProgress::NeedMore => return Ok(()),
                HttpProgress::Invalid(reason) => {
                    self.stats.parse_failed = self.stats.parse_failed.saturating_add(1);
                    self.streams.remove(&key);
                    self.write_loss(
                        reason,
                        key.pid,
                        key.ssl_pointer,
                        0,
                        observed_at_monotonic_ns,
                    )?;
                    return Ok(());
                }
                HttpProgress::Complete {
                    consumed,
                    mut request,
                } => {
                    self.stats.requests_completed = self.stats.requests_completed.saturating_add(1);
                    let mut current = {
                        let stream = self.streams.get_mut(&key).expect("stream exists");
                        std::mem::take(&mut stream.bytes)
                    };
                    let remainder = current.split_off(consumed);
                    current.zeroize();
                    if let Some(stream) = self.streams.get_mut(&key) {
                        stream.bytes = remainder;
                    }
                    self.observe_request(key, tid, observed_at_monotonic_ns, &mut request)?;
                    if self
                        .streams
                        .get(&key)
                        .is_some_and(|stream| stream.bytes.is_empty())
                    {
                        self.streams.remove(&key);
                        return Ok(());
                    }
                }
            }
        }
    }

    fn observe_request(
        &mut self,
        key: StreamKey,
        tid: u32,
        observed_at_monotonic_ns: u64,
        request: &mut HttpRequest,
    ) -> anyhow::Result<()> {
        let Some(host) = normalize_host(&request.host) else {
            self.stats.requests_ignored = self.stats.requests_ignored.saturating_add(1);
            return Ok(());
        };
        if !self
            .allowed_provider_hosts
            .iter()
            .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
        {
            self.stats.requests_ignored = self.stats.requests_ignored.saturating_add(1);
            return Ok(());
        }
        let mut root: Value = match serde_json::from_slice(&request.body) {
            Ok(value) => value,
            Err(_) => {
                self.stats.parse_failed = self.stats.parse_failed.saturating_add(1);
                self.write_loss(
                    "provider_json_parse_failed",
                    key.pid,
                    key.ssl_pointer,
                    0,
                    observed_at_monotonic_ns,
                )?;
                return Ok(());
            }
        };
        let model = root
            .get("model")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let mut instruction = match extract_latest_user_message(&root) {
            Some(value) if !value.trim().is_empty() => value,
            _ => {
                self.stats.requests_ignored = self.stats.requests_ignored.saturating_add(1);
                wipe_json(&mut root);
                return Ok(());
            }
        };
        let body_sha256 = sha256_hex(&request.body);
        let instruction_sha256 = sha256_hex(instruction.as_bytes());
        let provider = provider_for_host(&host).to_string();
        let client_metadata = request_client_metadata(&root);
        let session_id = client_metadata
            .as_ref()
            .and_then(|metadata| metadata.session_id.clone());
        let thread_id = client_metadata
            .as_ref()
            .and_then(|metadata| metadata.thread_id.clone());
        let turn_id = client_metadata
            .as_ref()
            .and_then(|metadata| metadata.turn_id.clone());
        let window_id = client_metadata
            .as_ref()
            .and_then(|metadata| metadata.window_id.clone());
        let request_kind = client_metadata
            .as_ref()
            .and_then(|metadata| metadata.request_kind.clone());

        if self.runtime_mode {
            if self.runtime_observations.len() >= self.config.max_inflight_calls {
                self.stats.capacity_dropped = self.stats.capacity_dropped.saturating_add(1);
                instruction.zeroize();
                wipe_json(&mut root);
                self.write_loss(
                    "runtime_observation_queue_capacity",
                    key.pid,
                    key.ssl_pointer,
                    0,
                    observed_at_monotonic_ns,
                )?;
                return Ok(());
            }
            let instruction_bytes = instruction.len().min(u32::MAX as usize) as u32;
            self.runtime_observations.push_back(ObservedLlmRequest {
                pid: key.pid,
                tid,
                observed_at_monotonic_ns,
                protocol: request.protocol.clone(),
                host,
                path: request.path.clone(),
                endpoint_attribution: request.endpoint_attribution.clone(),
                provider,
                model,
                session_id,
                thread_id,
                turn_id,
                window_id,
                request_kind,
                body_sha256,
                instruction_bytes,
                instruction_sha256,
                user_instruction: instruction,
            });
            wipe_json(&mut root);
            self.stats.requests_parsed = self.stats.requests_parsed.saturating_add(1);
            return Ok(());
        }

        let user_instruction = if self.config.retain_instruction_content {
            json!({
                "eventType": "UserInstructionObserved",
                "content": instruction,
                "contentBytes": instruction.len(),
                "contentSha256": instruction_sha256,
            })
        } else {
            json!({
                "eventType": "UserInstructionObserved",
                "contentBytes": instruction.len(),
                "contentSha256": instruction_sha256,
            })
        };
        let mut record = json!({
            "schemaVersion": "a3s.observer.interaction-fixture.v1",
            "eventType": "LlmRequestObserved",
            "captureMethod": "ebpf_tls",
            "captureProfile": "isolated_fixture",
            "captureCompleteness": "complete",
            "parseStatus": "parsed",
            "rawRetentionState": "isolated_fixture_file",
            "presentationState": "fixture_only",
            "protocol": request.protocol,
            "pid": key.pid,
            "sslPointer": key.ssl_pointer,
            "observedAtMonotonicNs": observed_at_monotonic_ns,
            "http": {
                "method": request.method,
                "path": request.path,
                "host": host,
                "contentEncoding": request.content_encoding,
            },
            "provider": provider,
            "model": model,
            "sessionId": session_id,
            "threadId": thread_id,
            "turnId": turn_id,
            "windowId": window_id,
            "requestKind": request_kind,
            "bodySha256": body_sha256,
            "userInstruction": user_instruction,
        });
        let write_result = (|| -> anyhow::Result<()> {
            let output = self
                .output
                .as_mut()
                .context("isolated fixture output is unavailable")?;
            serde_json::to_writer(&mut *output, &record)
                .context("failed to write isolated fixture observation")?;
            output
                .write_all(b"\n")
                .context("failed to terminate isolated fixture observation")?;
            output
                .flush()
                .context("failed to flush isolated fixture observation")
        })();
        wipe_json(&mut record);
        instruction.zeroize();
        wipe_json(&mut root);
        write_result?;
        self.stats.requests_parsed = self.stats.requests_parsed.saturating_add(1);
        Ok(())
    }

    fn write_native_instruction(
        &mut self,
        key: NativeInputKey,
        tid: u32,
        comm: &str,
        observed_at_monotonic_ns: u64,
        bytes: &[u8],
    ) -> anyhow::Result<()> {
        let instruction_sha256 = sha256_hex(bytes);
        let instruction = if self.config.retain_instruction_content {
            let content = std::str::from_utf8(bytes)
                .context("native stdin instruction is not valid UTF-8")?;
            json!({
                "eventType": "UserInstructionObserved",
                "content": content,
                "contentBytes": bytes.len(),
                "contentSha256": instruction_sha256,
            })
        } else {
            json!({
                "eventType": "UserInstructionObserved",
                "contentBytes": bytes.len(),
                "contentSha256": instruction_sha256,
            })
        };
        let mut record = json!({
            "schemaVersion": "a3s.observer.interaction-fixture.v1",
            "eventType": "AgentInputObserved",
            "captureMethod": "ebpf_stdin",
            "captureProfile": "isolated_fixture",
            "captureCompleteness": "complete",
            "parseStatus": "boundary_observed",
            "rawRetentionState": "isolated_fixture_file",
            "presentationState": "fixture_only",
            "protocol": "native_stdio",
            "inputScope": "agent_process_stdin",
            "pid": key.pid,
            "tid": tid,
            "fd": key.fd,
            "comm": comm,
            "observedAtMonotonicNs": observed_at_monotonic_ns,
            "userInstruction": instruction,
        });
        let result = (|| -> anyhow::Result<()> {
            let output = self
                .output
                .as_mut()
                .context("isolated fixture output is unavailable")?;
            serde_json::to_writer(&mut *output, &record)
                .context("failed to write isolated native input observation")?;
            output
                .write_all(b"\n")
                .context("failed to terminate isolated native input observation")?;
            output
                .flush()
                .context("failed to flush isolated native input observation")
        })();
        wipe_json(&mut record);
        result
    }

    fn write_native_response(
        &mut self,
        key: NativeInputKey,
        tid: u32,
        comm: &str,
        observed_at_monotonic_ns: u64,
        completed_at_monotonic_ns: u64,
        bytes: &[u8],
    ) -> anyhow::Result<()> {
        let response_sha256 = sha256_hex(bytes);
        let response = if self.config.retain_instruction_content {
            let content =
                std::str::from_utf8(bytes).context("native stdout response is not valid UTF-8")?;
            json!({
                "eventType": "AssistantResponseObserved",
                "content": content,
                "contentBytes": bytes.len(),
                "contentSha256": response_sha256,
            })
        } else {
            json!({
                "eventType": "AssistantResponseObserved",
                "contentBytes": bytes.len(),
                "contentSha256": response_sha256,
            })
        };
        let mut record = json!({
            "schemaVersion": "a3s.observer.interaction-fixture.v1",
            "eventType": "AgentOutputObserved",
            "captureMethod": "ebpf_stdout",
            "captureProfile": "isolated_fixture",
            "captureCompleteness": "complete",
            "parseStatus": "boundary_observed",
            "rawRetentionState": "isolated_fixture_file",
            "presentationState": "fixture_only",
            "protocol": "native_stdio",
            "outputScope": "agent_process_stdout",
            "pid": key.pid,
            "tid": tid,
            "fd": key.fd,
            "comm": comm,
            "observedAtMonotonicNs": observed_at_monotonic_ns,
            "completedAtMonotonicNs": completed_at_monotonic_ns,
            "assistantResponse": response,
        });
        let result = (|| -> anyhow::Result<()> {
            let output = self
                .output
                .as_mut()
                .context("isolated fixture output is unavailable")?;
            serde_json::to_writer(&mut *output, &record)
                .context("failed to write isolated native output observation")?;
            output
                .write_all(b"\n")
                .context("failed to terminate isolated native output observation")?;
            output
                .flush()
                .context("failed to flush isolated native output observation")
        })();
        wipe_json(&mut record);
        result
    }

    fn write_loss(
        &mut self,
        reason: &str,
        pid: u32,
        ssl_pointer: u64,
        call_sequence: u64,
        observed_at_monotonic_ns: u64,
    ) -> anyhow::Result<()> {
        self.write_loss_with_len(
            reason,
            pid,
            ssl_pointer,
            call_sequence,
            observed_at_monotonic_ns,
            0,
        )
    }

    fn write_loss_with_len(
        &mut self,
        reason: &str,
        pid: u32,
        ssl_pointer: u64,
        call_sequence: u64,
        observed_at_monotonic_ns: u64,
        original_len: u64,
    ) -> anyhow::Result<()> {
        let Some(output) = self.output.as_mut() else {
            tracing::warn!(
                reason,
                pid,
                ssl_pointer,
                call_sequence,
                observed_at_monotonic_ns,
                original_len,
                "runtime Interaction capture loss"
            );
            return Ok(());
        };
        let record = json!({
            "schemaVersion": "a3s.observer.interaction-fixture-loss.v1",
            "eventType": "FixtureCaptureLoss",
            "reason": reason,
            "pid": pid,
            "sslPointer": ssl_pointer,
            "callSequence": call_sequence,
            "observedAtMonotonicNs": observed_at_monotonic_ns,
            "originalLen": original_len,
        });
        serde_json::to_writer(&mut *output, &record)
            .context("failed to write isolated fixture loss")?;
        output
            .write_all(b"\n")
            .context("failed to terminate isolated fixture loss")?;
        output
            .flush()
            .context("failed to flush isolated fixture loss")
    }
}

impl Drop for FixturePipeline {
    fn drop(&mut self) {
        self.clear_plaintext();
        if let Some(output) = self.output.as_mut() {
            let _ = output.flush();
        }
    }
}

fn consume_stream_prefix(
    streams: &mut HashMap<StreamKey, StreamAssembly>,
    key: StreamKey,
    consumed: usize,
) {
    let Some(stream) = streams.get_mut(&key) else {
        return;
    };
    let mut current = std::mem::take(&mut stream.bytes);
    if consumed >= current.len() {
        current.zeroize();
        return;
    }
    let remainder = current.split_off(consumed);
    current.zeroize();
    stream.bytes = remainder;
}

enum WebSocketHandshakeProgress {
    NeedMore,
    NotHandshake,
    Invalid(&'static str),
    Complete {
        consumed: usize,
        host: String,
        path: String,
    },
}

fn parse_websocket_handshake(input: &[u8]) -> WebSocketHandshakeProgress {
    if input.len() < 4 {
        return if b"GET ".starts_with(input) {
            WebSocketHandshakeProgress::NeedMore
        } else {
            WebSocketHandshakeProgress::NotHandshake
        };
    }
    if !input.starts_with(b"GET ") {
        return WebSocketHandshakeProgress::NotHandshake;
    }
    let Some(header_end) = find_bytes(input, b"\r\n\r\n") else {
        return if input.len() > MAX_HEADER_BYTES {
            WebSocketHandshakeProgress::Invalid("websocket_handshake_too_large")
        } else {
            WebSocketHandshakeProgress::NeedMore
        };
    };
    let headers = &input[..header_end];
    let Some(first_line_end) = find_bytes(headers, b"\r\n") else {
        return WebSocketHandshakeProgress::Invalid("websocket_handshake_invalid");
    };
    let Some(first_line) = std::str::from_utf8(&headers[..first_line_end]).ok() else {
        return WebSocketHandshakeProgress::Invalid("websocket_handshake_invalid");
    };
    let mut start = first_line.split_whitespace();
    if start.next() != Some("GET") {
        return WebSocketHandshakeProgress::NotHandshake;
    }
    let Some(path) = start.next() else {
        return WebSocketHandshakeProgress::Invalid("websocket_handshake_invalid");
    };
    let Some(version) = start.next() else {
        return WebSocketHandshakeProgress::Invalid("websocket_handshake_invalid");
    };
    if !version.starts_with("HTTP/1.") {
        return WebSocketHandshakeProgress::Invalid("websocket_handshake_invalid");
    }
    let mut host = None;
    let mut upgrade = false;
    for line in headers[first_line_end + 2..].split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = trim_ascii(&line[..colon]);
        let value = trim_ascii(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"host") {
            host = std::str::from_utf8(value).ok().map(ToOwned::to_owned);
        } else if name.eq_ignore_ascii_case(b"upgrade") {
            upgrade = value.eq_ignore_ascii_case(b"websocket");
        }
    }
    if !upgrade {
        return WebSocketHandshakeProgress::Invalid("unsupported_http_get");
    }
    let Some(host) = host.and_then(|value| normalize_host(&value)) else {
        return WebSocketHandshakeProgress::Invalid("websocket_host_missing");
    };
    WebSocketHandshakeProgress::Complete {
        consumed: header_end + 4,
        host,
        path: path
            .split(['?', '#'])
            .next()
            .unwrap_or("/")
            .chars()
            .take(2_048)
            .collect(),
    }
}

enum WebSocketProgress {
    NeedMore,
    Ignored {
        consumed: usize,
    },
    Invalid(&'static str),
    Complete {
        consumed: usize,
        compressed: bool,
        payload: Vec<u8>,
    },
}

fn parse_masked_websocket_frame(input: &[u8], max_payload: usize) -> WebSocketProgress {
    if input.len() < 2 {
        return WebSocketProgress::NeedMore;
    }
    let final_frame = input[0] & 0x80 != 0;
    let compressed = input[0] & 0x40 != 0;
    let opcode = input[0] & 0x0f;
    let masked = input[1] & 0x80 != 0;
    if !final_frame || input[0] & 0x30 != 0 || !masked {
        return WebSocketProgress::Invalid("unsupported_websocket_frame");
    }
    let mut offset = 2usize;
    let mut payload_len = (input[1] & 0x7f) as usize;
    if payload_len == 126 {
        let Some(bytes) = input.get(offset..offset + 2) else {
            return WebSocketProgress::NeedMore;
        };
        payload_len = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        offset += 2;
    } else if payload_len == 127 {
        let Some(bytes) = input.get(offset..offset + 8) else {
            return WebSocketProgress::NeedMore;
        };
        let length = u64::from_be_bytes(bytes.try_into().expect("8-byte websocket length"));
        let Ok(length) = usize::try_from(length) else {
            return WebSocketProgress::Invalid("websocket_frame_too_large");
        };
        payload_len = length;
        offset += 8;
    }
    if payload_len > max_payload {
        return WebSocketProgress::Invalid("websocket_frame_too_large");
    }
    let Some(mask_bytes) = input.get(offset..offset + 4) else {
        return WebSocketProgress::NeedMore;
    };
    let mask = [mask_bytes[0], mask_bytes[1], mask_bytes[2], mask_bytes[3]];
    offset += 4;
    let Some(end) = offset.checked_add(payload_len) else {
        return WebSocketProgress::Invalid("websocket_length_overflow");
    };
    let Some(payload) = input.get(offset..end) else {
        return WebSocketProgress::NeedMore;
    };
    if matches!(opcode, 0x8 | 0x9 | 0xA) {
        return WebSocketProgress::Ignored { consumed: end };
    }
    if !matches!(opcode, 0x1 | 0x2) {
        return WebSocketProgress::Invalid("unsupported_websocket_opcode");
    }
    WebSocketProgress::Complete {
        consumed: end,
        compressed,
        payload: payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % 4])
            .collect(),
    }
}

fn looks_like_masked_websocket_client_frame(input: &[u8], max_payload: usize) -> bool {
    if input.len() < 2 {
        return false;
    }
    let final_frame = input[0] & 0x80 != 0;
    let reserved_2_or_3 = input[0] & 0x30 != 0;
    let opcode = input[0] & 0x0f;
    let masked = input[1] & 0x80 != 0;
    if !final_frame || reserved_2_or_3 || !masked || !matches!(opcode, 0x1 | 0x2 | 0x8 | 0x9 | 0xA)
    {
        return false;
    }
    let encoded_length = input[1] & 0x7f;
    match encoded_length {
        0..=125 => usize::from(encoded_length) <= max_payload,
        126 => input
            .get(2..4)
            .map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])) <= max_payload)
            .unwrap_or(true),
        127 => input
            .get(2..10)
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
            .and_then(|bytes| usize::try_from(u64::from_be_bytes(bytes)).ok())
            .map(|length| length <= max_payload)
            .unwrap_or(true),
        _ => false,
    }
}

fn inferred_runtime_provider_host(allowed_provider_hosts: &HashSet<String>) -> Option<String> {
    allowed_provider_hosts
        .get("chatgpt.com")
        .cloned()
        .or_else(|| allowed_provider_hosts.iter().min().cloned())
}

struct HttpRequest {
    method: String,
    path: String,
    host: String,
    endpoint_attribution: String,
    content_encoding: String,
    protocol: String,
    body: Vec<u8>,
}

impl Drop for HttpRequest {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

enum HttpProgress {
    NeedMore,
    Invalid(&'static str),
    Complete {
        consumed: usize,
        request: HttpRequest,
    },
}

fn parse_http1_request(
    input: &[u8],
    max_message_bytes: usize,
    max_decompressed_bytes: usize,
) -> HttpProgress {
    let Some(header_end) = find_bytes(input, b"\r\n\r\n") else {
        return if input.len() > MAX_HEADER_BYTES {
            HttpProgress::Invalid("http_header_too_large")
        } else {
            HttpProgress::NeedMore
        };
    };
    if header_end > MAX_HEADER_BYTES {
        return HttpProgress::Invalid("http_header_too_large");
    }
    let header_bytes = &input[..header_end];
    let Some(first_line_end) = find_bytes(header_bytes, b"\r\n") else {
        return HttpProgress::Invalid("http_start_line_invalid");
    };
    let Some(first_line) = std::str::from_utf8(&header_bytes[..first_line_end]).ok() else {
        return HttpProgress::Invalid("http_start_line_invalid");
    };
    let mut start = first_line.split_whitespace();
    let Some(method) = start.next() else {
        return HttpProgress::Invalid("http_start_line_invalid");
    };
    let Some(path) = start.next() else {
        return HttpProgress::Invalid("http_start_line_invalid");
    };
    let Some(version) = start.next() else {
        return HttpProgress::Invalid("http_start_line_invalid");
    };
    if !matches!(method, "POST" | "PUT" | "PATCH") || !version.starts_with("HTTP/1.") {
        return HttpProgress::Invalid("unsupported_http_message");
    }
    let mut host = None;
    let mut content_length = None;
    let mut chunked = false;
    let mut content_encoding = "identity".to_string();
    for line in header_bytes[first_line_end + 2..].split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = trim_ascii(&line[..colon]);
        let value = trim_ascii(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"host") {
            host = std::str::from_utf8(value).ok().map(ToOwned::to_owned);
        } else if name.eq_ignore_ascii_case(b"content-length") {
            content_length = std::str::from_utf8(value)
                .ok()
                .and_then(|value| value.parse::<usize>().ok());
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            chunked = ascii_contains_ignore_case(value, b"chunked");
        } else if name.eq_ignore_ascii_case(b"content-encoding") {
            if value.eq_ignore_ascii_case(b"gzip") {
                content_encoding = "gzip".to_string();
            } else if !value.eq_ignore_ascii_case(b"identity") {
                return HttpProgress::Invalid("unsupported_content_encoding");
            }
        }
    }
    let Some(host) = host else {
        return HttpProgress::Invalid("http_host_missing");
    };
    let body_start = header_end + 4;
    let (consumed, mut body) = if chunked {
        match decode_chunked(&input[body_start..], max_message_bytes) {
            ChunkProgress::NeedMore => return HttpProgress::NeedMore,
            ChunkProgress::Invalid(reason) => return HttpProgress::Invalid(reason),
            ChunkProgress::Complete { consumed, body } => (body_start + consumed, body),
        }
    } else {
        let length = content_length.unwrap_or(0);
        if length > max_message_bytes {
            return HttpProgress::Invalid("http_body_too_large");
        }
        let Some(end) = body_start.checked_add(length) else {
            return HttpProgress::Invalid("http_length_overflow");
        };
        if input.len() < end {
            return HttpProgress::NeedMore;
        }
        (end, input[body_start..end].to_vec())
    };
    if consumed > max_message_bytes.saturating_add(MAX_HEADER_BYTES) {
        body.zeroize();
        return HttpProgress::Invalid("http_message_too_large");
    }
    if content_encoding == "gzip" {
        match decode_gzip(&body, max_decompressed_bytes) {
            Ok(decoded) => {
                body.zeroize();
                body = decoded;
            }
            Err(reason) => {
                body.zeroize();
                return HttpProgress::Invalid(reason);
            }
        }
    }
    HttpProgress::Complete {
        consumed,
        request: HttpRequest {
            method: method.to_string(),
            path: path
                .split(['?', '#'])
                .next()
                .unwrap_or("/")
                .chars()
                .take(2_048)
                .collect(),
            host,
            endpoint_attribution: "observed_headers".to_string(),
            content_encoding,
            protocol: "http1".to_string(),
            body,
        },
    }
}

enum ChunkProgress {
    NeedMore,
    Invalid(&'static str),
    Complete { consumed: usize, body: Vec<u8> },
}

fn decode_chunked(input: &[u8], max_body_bytes: usize) -> ChunkProgress {
    let mut cursor = 0usize;
    let mut body = Vec::new();
    loop {
        let Some(relative_line_end) = find_bytes(&input[cursor..], b"\r\n") else {
            body.zeroize();
            return if input.len().saturating_sub(cursor) > MAX_CHUNK_LINE_BYTES {
                ChunkProgress::Invalid("chunk_line_too_large")
            } else {
                ChunkProgress::NeedMore
            };
        };
        if relative_line_end > MAX_CHUNK_LINE_BYTES {
            body.zeroize();
            return ChunkProgress::Invalid("chunk_line_too_large");
        }
        let line_end = cursor + relative_line_end;
        let size_bytes = input[cursor..line_end]
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or_default();
        let Some(size_text) = std::str::from_utf8(trim_ascii(size_bytes)).ok() else {
            body.zeroize();
            return ChunkProgress::Invalid("chunk_size_invalid");
        };
        let Ok(size) = usize::from_str_radix(size_text, 16) else {
            body.zeroize();
            return ChunkProgress::Invalid("chunk_size_invalid");
        };
        cursor = line_end + 2;
        if size == 0 {
            if input.get(cursor..cursor + 2) == Some(b"\r\n") {
                return ChunkProgress::Complete {
                    consumed: cursor + 2,
                    body,
                };
            }
            let Some(trailer_end) = find_bytes(&input[cursor..], b"\r\n\r\n") else {
                body.zeroize();
                return ChunkProgress::NeedMore;
            };
            return ChunkProgress::Complete {
                consumed: cursor + trailer_end + 4,
                body,
            };
        }
        if body.len().saturating_add(size) > max_body_bytes {
            body.zeroize();
            return ChunkProgress::Invalid("chunked_body_too_large");
        }
        let Some(data_end) = cursor.checked_add(size) else {
            body.zeroize();
            return ChunkProgress::Invalid("chunk_length_overflow");
        };
        let Some(delimiter_end) = data_end.checked_add(2) else {
            body.zeroize();
            return ChunkProgress::Invalid("chunk_length_overflow");
        };
        if input.len() < delimiter_end {
            body.zeroize();
            return ChunkProgress::NeedMore;
        }
        if input.get(data_end..delimiter_end) != Some(b"\r\n") {
            body.zeroize();
            return ChunkProgress::Invalid("chunk_delimiter_invalid");
        }
        body.extend_from_slice(&input[cursor..data_end]);
        cursor = delimiter_end;
    }
}

fn decode_gzip(input: &[u8], max_bytes: usize) -> Result<Vec<u8>, &'static str> {
    let decoder = GzDecoder::new(input);
    let mut limited = decoder.take(max_bytes.saturating_add(1) as u64);
    let mut output = Vec::new();
    limited
        .read_to_end(&mut output)
        .map_err(|_| "gzip_decode_failed")?;
    if output.len() > max_bytes {
        output.zeroize();
        return Err("gzip_output_too_large");
    }
    Ok(output)
}

fn extract_latest_user_message(root: &Value) -> Option<String> {
    if let Some(input) = root.get("input") {
        if let Some(text) = input.as_str() {
            return Some(text.to_string());
        }
        if let Some(messages) = input.as_array() {
            if let Some(value) = latest_user_in_messages(messages) {
                return Some(value);
            }
        }
    }
    root.get("messages")
        .and_then(Value::as_array)
        .and_then(|messages| latest_user_in_messages(messages))
}

#[derive(Default)]
struct RequestClientMetadata {
    session_id: Option<String>,
    thread_id: Option<String>,
    turn_id: Option<String>,
    window_id: Option<String>,
    request_kind: Option<String>,
}

fn request_client_metadata(root: &Value) -> Option<RequestClientMetadata> {
    let metadata = root.get("client_metadata")?.as_object()?;
    let turn_metadata = metadata
        .get("x-codex-turn-metadata")
        .and_then(Value::as_str)
        .and_then(|value| serde_json::from_str::<Value>(value).ok());
    let nested = turn_metadata.as_ref().and_then(Value::as_object);
    let field = |name: &str| {
        metadata
            .get(name)
            .and_then(Value::as_str)
            .or_else(|| {
                nested
                    .and_then(|value| value.get(name))
                    .and_then(Value::as_str)
            })
            .and_then(bounded_metadata_text)
    };
    let result = RequestClientMetadata {
        session_id: field("session_id"),
        thread_id: field("thread_id"),
        turn_id: field("turn_id"),
        window_id: field("window_id").or_else(|| field("x-codex-window-id")),
        request_kind: field("request_kind"),
    };
    (result.session_id.is_some()
        || result.thread_id.is_some()
        || result.turn_id.is_some()
        || result.window_id.is_some()
        || result.request_kind.is_some())
    .then_some(result)
}

fn bounded_metadata_text(value: &str) -> Option<String> {
    let normalized = value.trim();
    (!normalized.is_empty() && normalized.len() <= 240 && !normalized.chars().any(char::is_control))
        .then(|| normalized.to_string())
}

fn latest_user_in_messages(messages: &[Value]) -> Option<String> {
    messages.iter().rev().find_map(|message| {
        (message.get("role").and_then(Value::as_str) == Some("user"))
            .then(|| message.get("content").and_then(extract_text_content))
            .flatten()
    })
}

fn extract_text_content(value: &Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        return Some(text.to_string());
    }
    let parts = value.as_array()?;
    let collected = parts
        .iter()
        .filter_map(|part| {
            let kind = part.get("type").and_then(Value::as_str)?;
            if !matches!(kind, "text" | "input_text") {
                return None;
            }
            part.get("text").and_then(Value::as_str)
        })
        .collect::<Vec<_>>();
    (!collected.is_empty()).then(|| collected.join("\n"))
}

fn provider_for_host(host: &str) -> &'static str {
    if domain_matches(host, "api.openai.com") {
        "openai"
    } else if domain_matches(host, "api.anthropic.com") {
        "anthropic"
    } else if domain_matches(host, "generativelanguage.googleapis.com") {
        "gemini"
    } else {
        "openai_compatible"
    }
}

fn domain_matches(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn normalize_host(value: &str) -> Option<String> {
    let mut value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.starts_with('[') {
        let end = value.find(']')?;
        value.truncate(end + 1);
    } else if let Some((host, port)) = value.rsplit_once(':') {
        if port.chars().all(|value| value.is_ascii_digit()) {
            value = host.to_string();
        }
    }
    (!value.is_empty()
        && value.len() <= 253
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'[' | b']' | b':')
        }))
    .then_some(value)
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

fn wipe_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe_json),
        Value::Object(values) => values.values_mut().for_each(wipe_json),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_chunked, extract_latest_user_message, parse_http1_request, sha256_hex,
        ChunkProgress, FixtureFragment, FixtureNativeInput, FixtureNativeOutput, FixturePipeline,
        FixturePipelineConfig, HttpProgress, RuntimePipelineConfig,
    };
    use flate2::{write::GzEncoder, Compression};
    use serde_json::json;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    static OUTPUT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn output_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "a3s-interaction-fixture-{label}-{}-{}.jsonl",
            std::process::id(),
            OUTPUT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn fixture_config(path: PathBuf, hosts: &[&str]) -> FixturePipelineConfig {
        FixturePipelineConfig {
            output_path: path,
            allowed_provider_hosts: hosts.iter().map(|value| value.to_string()).collect(),
            max_connections: 4,
            max_inflight_calls: 8,
            max_reassembly_bytes: 1024 * 1024,
            max_decompressed_bytes: 1024 * 1024,
            reassembly_timeout: Duration::from_secs(1),
            retain_instruction_content: true,
        }
    }

    fn push_call(
        pipeline: &mut FixturePipeline,
        pid: u32,
        ssl_pointer: u64,
        call_sequence: u64,
        bytes: &[u8],
        fragment_bytes: usize,
    ) {
        for (fragment_index, chunk) in bytes.chunks(fragment_bytes).enumerate() {
            let offset = fragment_index * fragment_bytes;
            pipeline
                .push(
                    FixtureFragment {
                        pid,
                        tid: pid,
                        ssl_pointer,
                        call_sequence,
                        fragment_index: fragment_index as u32,
                        fragment_offset: offset as u64,
                        original_length: bytes.len() as u64,
                        observed_at_monotonic_ns: call_sequence,
                        is_read: false,
                        truncated: false,
                        bytes: chunk,
                    },
                    Instant::now(),
                )
                .unwrap();
        }
    }

    fn masked_websocket_text(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x81];
        if payload.len() <= 125 {
            frame.push(0x80 | payload.len() as u8);
        } else if payload.len() <= u16::MAX as usize {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        let mask = [0x13, 0x37, 0x42, 0x99];
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % mask.len()]),
        );
        frame
    }

    #[test]
    fn parses_fragmentable_openai_chat_request() {
        let body =
            br#"{"model":"gpt-5","messages":[{"role":"system","content":"safe"},{"role":"user","content":"check dependencies"}]}"#;
        let request = [
            format!(
                "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: {}\r\nAuthorization: Bearer never-output\r\n\r\n",
                body.len()
            )
            .into_bytes(),
            body.to_vec(),
        ]
        .concat();
        let HttpProgress::Complete {
            consumed,
            request: mut parsed,
        } = parse_http1_request(&request, 1024 * 1024, 1024 * 1024)
        else {
            panic!("request was not complete");
        };
        assert_eq!(consumed, request.len());
        assert_eq!(parsed.host, "api.openai.com");
        let root: serde_json::Value = serde_json::from_slice(&parsed.body).unwrap();
        assert_eq!(
            extract_latest_user_message(&root).as_deref(),
            Some("check dependencies")
        );
        parsed.body.fill(0);
    }

    #[test]
    fn parses_responses_multimodal_user_text_without_images() {
        let root = json!({
            "model": "gpt-5",
            "input": [{
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "review this image"},
                    {"type": "input_image", "image_url": "data:secret"}
                ]
            }]
        });
        assert_eq!(
            extract_latest_user_message(&root).as_deref(),
            Some("review this image")
        );
    }

    #[test]
    fn parses_chunked_body_and_waits_for_incomplete_tail() {
        let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let ChunkProgress::Complete {
            consumed,
            body: decoded,
        } = decode_chunked(body, 1024)
        else {
            panic!("chunked body was not complete");
        };
        assert_eq!(consumed, body.len());
        assert_eq!(decoded, b"hello world");
        assert!(matches!(
            decode_chunked(&body[..body.len() - 2], 1024),
            ChunkProgress::NeedMore
        ));
    }

    #[test]
    fn decodes_bounded_gzip_request_body() {
        let body = br#"{"model":"gpt-5","input":"scan the workspace"}"#;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).unwrap();
        let compressed = encoder.finish().unwrap();
        let request = [
            format!(
                "POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                compressed.len()
            )
            .into_bytes(),
            compressed,
        ]
        .concat();
        let HttpProgress::Complete { request, .. } =
            parse_http1_request(&request, 1024 * 1024, 1024 * 1024)
        else {
            panic!("gzip request was not complete");
        };
        assert_eq!(request.body, body);
    }

    #[test]
    fn rejects_unsupported_or_oversized_messages() {
        assert!(matches!(
            parse_http1_request(
                b"GET / HTTP/1.1\r\nHost: api.openai.com\r\n\r\n",
                1024,
                1024
            ),
            HttpProgress::Invalid("unsupported_http_message")
        ));
        assert!(matches!(
            parse_http1_request(
                b"POST / HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: 9999\r\n\r\n",
                1024,
                1024
            ),
            HttpProgress::Invalid("http_body_too_large")
        ));
    }

    #[test]
    fn pipeline_reassembles_fragments_and_keeps_plaintext_out_of_headers() {
        let path = output_path("fragmented");
        let mut pipeline =
            FixturePipeline::new(fixture_config(path.clone(), &["api.openai.com"])).unwrap();
        let instruction = format!("inspect {}", "dependency-tree ".repeat(180));
        let body = serde_json::to_vec(&json!({
            "model": "gpt-5",
            "messages": [{"role": "user", "content": instruction}]
        }))
        .unwrap();
        let request = [
            format!(
                "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer fixture-secret\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes(),
            body,
        ]
        .concat();
        push_call(&mut pipeline, 42, 99, 700, &request, 257);

        let artifact = fs::read_to_string(&path).unwrap();
        assert!(artifact.contains("\"eventType\":\"LlmRequestObserved\""));
        assert!(artifact.contains("\"eventType\":\"UserInstructionObserved\""));
        assert!(artifact.contains("dependency-tree"));
        assert!(!artifact.contains("fixture-secret"));
        assert_eq!(pipeline.stats().requests_parsed, 1);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(pipeline);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn pipeline_reassembles_http_across_multiple_ssl_calls() {
        let path = output_path("calls");
        let mut pipeline =
            FixturePipeline::new(fixture_config(path.clone(), &["api.anthropic.com"])).unwrap();
        let body = br#"{"model":"claude-test","messages":[{"role":"user","content":[{"type":"text","text":"trace this command"}]}]}"#;
        let header = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        push_call(&mut pipeline, 43, 100, 701, header.as_bytes(), 31);
        assert_eq!(pipeline.stats().requests_parsed, 0);
        push_call(&mut pipeline, 43, 100, 702, body, 29);
        assert_eq!(pipeline.stats().requests_parsed, 1);
        assert!(fs::read_to_string(&path)
            .unwrap()
            .contains("trace this command"));
        drop(pipeline);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn runtime_pipeline_reassembles_codex_websocket_request_without_fixture_database() {
        let mut pipeline = FixturePipeline::new_runtime(RuntimePipelineConfig {
            allowed_provider_hosts: vec!["chatgpt.com".to_string()],
            configured_endpoint_attribution: "configured_endpoint",
            max_connections: 4,
            max_inflight_calls: 8,
            max_reassembly_bytes: 1024 * 1024,
            max_decompressed_bytes: 1024 * 1024,
            reassembly_timeout: Duration::from_secs(1),
        })
        .unwrap();
        let handshake = b"GET /backend-api/codex/responses HTTP/1.1\r\nHost: chatgpt.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: fixture\r\n\r\n";
        push_call(&mut pipeline, 61, 900, 1001, handshake, 37);

        let body = serde_json::to_vec(&json!({
            "model": "gpt-5.6-sol",
            "input": [{
                "role": "user",
                "content": [{
                    "type": "input_text",
                    "text": "先运行 /usr/bin/uname -a，然后只回复 ANYSENTRY_RUSTLS_WS_0901"
                }]
            }],
            "client_metadata": {
                "session_id": "session-runtime-ws",
                "thread_id": "thread-runtime-ws",
                "turn_id": "turn-runtime-ws",
                "window_id": "window-runtime-ws",
                "request_kind": "responses.create"
            }
        }))
        .unwrap();
        let frame = masked_websocket_text(&body);
        let split = frame.len() / 2;
        push_call(&mut pipeline, 61, 900, 1002, &frame[..split], 53);
        assert!(pipeline.take_observations().is_empty());
        push_call(&mut pipeline, 61, 900, 1003, &frame[split..], 41);

        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 1);
        let observed = &observations[0];
        assert_eq!(observed.pid, 61);
        assert_eq!(observed.protocol, "websocket");
        assert_eq!(observed.host, "chatgpt.com");
        assert_eq!(observed.path, "/backend-api/codex/responses");
        assert_eq!(observed.endpoint_attribution, "observed_handshake");
        assert_eq!(observed.model.as_deref(), Some("gpt-5.6-sol"));
        assert_eq!(observed.session_id.as_deref(), Some("session-runtime-ws"));
        assert_eq!(observed.thread_id.as_deref(), Some("thread-runtime-ws"));
        assert_eq!(observed.turn_id.as_deref(), Some("turn-runtime-ws"));
        assert_eq!(observed.window_id.as_deref(), Some("window-runtime-ws"));
        assert_eq!(observed.request_kind.as_deref(), Some("responses.create"));
        assert!(observed
            .user_instruction
            .contains("ANYSENTRY_RUSTLS_WS_0901"));
        assert_eq!(pipeline.stats().requests_parsed, 1);
    }

    #[test]
    fn runtime_pipeline_recovers_when_attached_after_websocket_handshake() {
        let mut pipeline = FixturePipeline::new_runtime(RuntimePipelineConfig {
            allowed_provider_hosts: vec!["chatgpt.com".to_string()],
            configured_endpoint_attribution: "configured_late_attach",
            max_connections: 4,
            max_inflight_calls: 8,
            max_reassembly_bytes: 1024 * 1024,
            max_decompressed_bytes: 1024 * 1024,
            reassembly_timeout: Duration::from_secs(1),
        })
        .unwrap();
        let body = serde_json::to_vec(&json!({
            "model": "gpt-5.6-sol",
            "input": [{
                "role": "user",
                "content": [{
                    "type": "input_text",
                    "text": "ANYSENTRY_RUNTIME_LATE_ATTACH_0901"
                }]
            }],
            "client_metadata": {
                "session_id": "session-runtime-late",
                "thread_id": "thread-runtime-late",
                "turn_id": "turn-runtime-late",
                "request_kind": "responses.create"
            }
        }))
        .unwrap();
        let frame = masked_websocket_text(&body);
        let split = frame.len() / 3;
        push_call(&mut pipeline, 62, 901, 1101, &frame[..split], 29);
        push_call(&mut pipeline, 62, 901, 1102, &frame[split..split * 2], 31);
        push_call(&mut pipeline, 62, 901, 1103, &frame[split * 2..], 37);

        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 1);
        let observed = &observations[0];
        assert_eq!(observed.protocol, "websocket");
        assert_eq!(observed.host, "chatgpt.com");
        assert_eq!(observed.path, "/backend-api/codex/responses");
        assert_eq!(observed.endpoint_attribution, "configured_late_attach");
        assert_eq!(observed.session_id.as_deref(), Some("session-runtime-late"));
        assert!(observed
            .user_instruction
            .contains("ANYSENTRY_RUNTIME_LATE_ATTACH_0901"));
        assert_eq!(pipeline.stats().requests_parsed, 1);
        assert_eq!(pipeline.stats().parse_failed, 0);
    }

    #[test]
    fn fixture_can_hash_without_retaining_instruction_content() {
        let path = output_path("hash-only");
        let mut config = fixture_config(path.clone(), &["api.openai.com"]);
        config.retain_instruction_content = false;
        let mut pipeline = FixturePipeline::new(config).unwrap();
        let instruction = "hash-only-controlled-instruction";
        let body = serde_json::to_vec(&json!({
            "model": "gpt-5",
            "input": instruction,
        }))
        .unwrap();
        let request = [
            format!(
                "POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes(),
            body,
        ]
        .concat();
        push_call(&mut pipeline, 43, 101, 702, &request, 19);
        let artifact = fs::read_to_string(&path).unwrap();
        assert!(!artifact.contains(instruction));
        assert!(artifact.contains("\"contentBytes\":32"));
        assert!(artifact.contains(&sha256_hex(instruction.as_bytes())));
        drop(pipeline);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn native_stdin_fixture_reassembles_chunked_agent_input_until_eof() {
        let path = output_path("native-stdin");
        let mut pipeline =
            FixturePipeline::new(fixture_config(path.clone(), &["api.openai.com"])).unwrap();
        let chunks = [
            b"ANYSENTRY_CODEX_".as_slice(),
            b"STDIN_FIXTURE ".as_slice(),
            b"inspect dependencies\n".as_slice(),
        ];
        for (index, bytes) in chunks.iter().enumerate() {
            pipeline
                .push_native_input(
                    FixtureNativeInput {
                        pid: 52,
                        tid: 60,
                        fd: 0,
                        observed_at_monotonic_ns: 800 + index as u64,
                        eof: false,
                        truncated: false,
                        comm: "codex",
                        bytes,
                    },
                    Instant::now(),
                )
                .unwrap();
        }
        pipeline
            .push_native_input(
                FixtureNativeInput {
                    pid: 52,
                    tid: 60,
                    fd: 0,
                    observed_at_monotonic_ns: 804,
                    eof: true,
                    truncated: false,
                    comm: "codex",
                    bytes: &[],
                },
                Instant::now(),
            )
            .unwrap();

        let artifact = fs::read_to_string(&path).unwrap();
        assert!(artifact.contains("\"eventType\":\"AgentInputObserved\""));
        assert!(artifact.contains("\"captureMethod\":\"ebpf_stdin\""));
        assert!(artifact.contains("\"eventType\":\"UserInstructionObserved\""));
        assert!(artifact.contains("ANYSENTRY_CODEX_STDIN_FIXTURE inspect dependencies"));
        assert_eq!(pipeline.stats().native_fragments_observed, 4);
        assert_eq!(pipeline.stats().native_instructions_completed, 1);
        assert_eq!(pipeline.stats().native_instructions_incomplete, 0);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(pipeline);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn native_stdout_fixture_reassembles_agent_response_until_process_boundary() {
        let path = output_path("native-stdout");
        let mut pipeline =
            FixturePipeline::new(fixture_config(path.clone(), &["api.openai.com"])).unwrap();
        for (index, bytes) in [b"analysis complete".as_slice(), b"\nOK\n".as_slice()]
            .iter()
            .enumerate()
        {
            pipeline
                .push_native_output(
                    FixtureNativeOutput {
                        pid: 52,
                        tid: 60,
                        fd: 1,
                        observed_at_monotonic_ns: 900 + index as u64,
                        eof: false,
                        truncated: false,
                        comm: "codex",
                        bytes,
                    },
                    Instant::now(),
                )
                .unwrap();
        }
        pipeline
            .push_native_output(
                FixtureNativeOutput {
                    pid: 52,
                    tid: 60,
                    fd: 1,
                    observed_at_monotonic_ns: 904,
                    eof: true,
                    truncated: false,
                    comm: "codex",
                    bytes: &[],
                },
                Instant::now(),
            )
            .unwrap();

        let artifact = fs::read_to_string(&path).unwrap();
        assert!(artifact.contains("\"eventType\":\"AgentOutputObserved\""));
        assert!(artifact.contains("\"captureMethod\":\"ebpf_stdout\""));
        assert!(artifact.contains("\"eventType\":\"AssistantResponseObserved\""));
        assert!(artifact.contains("analysis complete\\nOK"));
        assert_eq!(pipeline.stats().native_output_fragments_observed, 3);
        assert_eq!(pipeline.stats().native_responses_completed, 1);
        assert_eq!(pipeline.stats().native_responses_incomplete, 0);
        drop(pipeline);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn native_stdin_process_exit_is_recorded_as_incomplete() {
        let path = output_path("native-stdin-exit");
        let mut pipeline =
            FixturePipeline::new(fixture_config(path.clone(), &["api.openai.com"])).unwrap();
        pipeline
            .push_native_input(
                FixtureNativeInput {
                    pid: 53,
                    tid: 61,
                    fd: 0,
                    observed_at_monotonic_ns: 900,
                    eof: false,
                    truncated: false,
                    comm: "codex",
                    bytes: b"partial instruction",
                },
                Instant::now(),
            )
            .unwrap();
        pipeline.forget_pid(53).unwrap();

        let artifact = fs::read_to_string(&path).unwrap();
        assert!(artifact.contains("\"eventType\":\"FixtureCaptureLoss\""));
        assert!(artifact.contains("\"reason\":\"native_stdin_process_exit\""));
        assert!(!artifact.contains("\"eventType\":\"AgentInputObserved\""));
        assert_eq!(pipeline.stats().native_instructions_completed, 0);
        assert_eq!(pipeline.stats().native_instructions_incomplete, 1);
        drop(pipeline);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn native_stdin_rejects_invalid_utf8_instead_of_lossy_conversion() {
        let path = output_path("native-stdin-invalid-utf8");
        let mut pipeline =
            FixturePipeline::new(fixture_config(path.clone(), &["api.openai.com"])).unwrap();
        pipeline
            .push_native_input(
                FixtureNativeInput {
                    pid: 54,
                    tid: 62,
                    fd: 0,
                    observed_at_monotonic_ns: 910,
                    eof: false,
                    truncated: false,
                    comm: "codex",
                    bytes: &[0xff, 0xfe],
                },
                Instant::now(),
            )
            .unwrap();
        let error = pipeline
            .push_native_input(
                FixtureNativeInput {
                    pid: 54,
                    tid: 62,
                    fd: 0,
                    observed_at_monotonic_ns: 911,
                    eof: true,
                    truncated: false,
                    comm: "codex",
                    bytes: &[],
                },
                Instant::now(),
            )
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("native stdin instruction is not valid UTF-8"));
        assert!(!fs::read_to_string(&path)
            .unwrap()
            .contains("\"eventType\":\"AgentInputObserved\""));
        drop(pipeline);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn provider_allowlist_and_kill_switch_prevent_cross_boundary_stitching() {
        let path = output_path("policy");
        let mut pipeline =
            FixturePipeline::new(fixture_config(path.clone(), &["api.openai.com"])).unwrap();
        let body = br#"{"model":"x","input":"must not appear"}"#;
        let disallowed = [
            format!(
                "POST /v1/responses HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes(),
            body.to_vec(),
        ]
        .concat();
        push_call(&mut pipeline, 44, 101, 703, &disallowed, 64);
        assert_eq!(pipeline.stats().requests_ignored, 1);
        assert!(!fs::read_to_string(&path)
            .unwrap()
            .contains("must not appear"));

        let header = format!(
            "POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        push_call(&mut pipeline, 44, 102, 704, header.as_bytes(), 64);
        pipeline.clear_plaintext();
        push_call(&mut pipeline, 44, 102, 705, body, 64);
        assert_eq!(pipeline.stats().requests_parsed, 0);
        assert!(!fs::read_to_string(&path)
            .unwrap()
            .contains("must not appear"));
        drop(pipeline);
        fs::remove_file(path).unwrap();
    }

    /// Regression: long-agent CLIs resend the full conversation history (reasoning included) on
    /// every turn, so one SSL_write eventually exceeds the capture ceiling and the eBPF emits a
    /// header-only truncated record. That loss must be counted explicitly (`calls_oversized`)
    /// instead of vanishing into a stall, and the dropped bytes form exactly one request, so the
    /// connection must stay aligned for the next, smaller request.
    #[test]
    fn oversized_call_is_counted_and_does_not_poison_the_connection() {
        let mut pipeline = FixturePipeline::new_runtime(RuntimePipelineConfig {
            allowed_provider_hosts: vec!["api.kimi.com".to_string()],
            configured_endpoint_attribution: "configured_endpoint",
            max_connections: 4,
            max_inflight_calls: 8,
            max_reassembly_bytes: 64 * 1024,
            max_decompressed_bytes: 64 * 1024,
            reassembly_timeout: Duration::from_secs(1),
        })
        .unwrap();

        pipeline
            .push(
                FixtureFragment {
                    pid: 88,
                    tid: 88,
                    ssl_pointer: 4242,
                    call_sequence: 10,
                    fragment_index: 0,
                    fragment_offset: 0,
                    original_length: 128 * 1024,
                    observed_at_monotonic_ns: 10,
                    is_read: false,
                    truncated: true,
                    bytes: &[],
                },
                Instant::now(),
            )
            .unwrap();
        assert_eq!(pipeline.stats().calls_oversized, 1);
        assert_eq!(pipeline.stats().calls_incomplete, 1);
        assert_eq!(pipeline.stats().requests_parsed, 0);
        assert!(pipeline.take_observations().is_empty());

        let body = serde_json::to_vec(&json!({
            "model": "kimi-for-coding",
            "messages": [{"role": "user", "content": "still alive after the oversized call"}]
        }))
        .unwrap();
        let request = [
            format!(
                "POST /coding/v1/chat/completions HTTP/1.1\r\nHost: api.kimi.com\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes(),
            body,
        ]
        .concat();
        push_call(&mut pipeline, 88, 4242, 11, &request, 509);
        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].host, "api.kimi.com");
        assert_eq!(
            observations[0].user_instruction,
            "still alive after the oversized call"
        );
        assert_eq!(pipeline.stats().requests_parsed, 1);
        assert_eq!(pipeline.stats().calls_oversized, 1);
    }

    /// A request that resends a long conversation history (megabytes of reasoning blocks) must
    /// reassemble end-to-end through the fragmentation path: one `SSL_write` larger than the old
    /// fixed caps arrives as hundreds of 31 KiB ring fragments, matching the shape the eBPF
    /// fragment loop emits for over-sized calls.
    #[test]
    fn five_mebibyte_single_write_reassembles_into_one_complete_request() {
        let mut pipeline = FixturePipeline::new_runtime(RuntimePipelineConfig {
            allowed_provider_hosts: vec!["api.kimi.com".to_string()],
            configured_endpoint_attribution: "configured_endpoint",
            max_connections: 4,
            max_inflight_calls: 8,
            max_reassembly_bytes: 16 * 1024 * 1024,
            max_decompressed_bytes: 16 * 1024 * 1024,
            reassembly_timeout: Duration::from_secs(1),
        })
        .unwrap();
        let instruction = format!("summarize {}", "reasoning-block ".repeat(330_000));
        assert!(instruction.len() > 5 * 1024 * 1024);
        let body = serde_json::to_vec(&json!({
            "model": "kimi-for-coding",
            "messages": [{"role": "user", "content": instruction}]
        }))
        .unwrap();
        let request = [
            format!(
                "POST /coding/v1/chat/completions HTTP/1.1\r\nHost: api.kimi.com\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes(),
            body,
        ]
        .concat();
        push_call(&mut pipeline, 89, 5000, 20, &request, 31 * 1024);
        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].host, "api.kimi.com");
        assert!(observations[0].user_instruction.starts_with("summarize "));
        assert_eq!(pipeline.stats().requests_parsed, 1);
        assert_eq!(pipeline.stats().calls_oversized, 0);
        assert_eq!(pipeline.stats().calls_completed, 1);
    }

    /// Beyond the absolute ceiling the eBPF emits the captured prefix as ordinary fragments
    /// (`original_len` clamped to the ceiling, `truncated=0`) followed by a header-only truncated
    /// marker carrying the true length. The prefix is a legal request header plus a partial body,
    /// so it reassembles into the stream and waits as an uncompletable request; the marker must
    /// then count the oversize exactly once, drop the poisoned stream, and keep the connection
    /// aligned for the next request.
    #[test]
    fn beyond_ceiling_call_counts_oversized_once_and_recovers() {
        const CEILING: usize = 256 * 1024;
        let mut pipeline = FixturePipeline::new_runtime(RuntimePipelineConfig {
            allowed_provider_hosts: vec!["api.kimi.com".to_string()],
            configured_endpoint_attribution: "configured_endpoint",
            max_connections: 4,
            max_inflight_calls: 8,
            max_reassembly_bytes: CEILING,
            max_decompressed_bytes: 256 * 1024,
            reassembly_timeout: Duration::from_secs(1),
        })
        .unwrap();

        let body = serde_json::to_vec(&json!({
            "model": "kimi-for-coding",
            "messages": [{"role": "user", "content": format!("over-ceiling {}", "x".repeat(400 * 1024))}]
        }))
        .unwrap();
        let request = [
            format!(
                "POST /coding/v1/chat/completions HTTP/1.1\r\nHost: api.kimi.com\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes(),
            body,
        ]
        .concat();
        assert!(request.len() > CEILING);
        // The clamped prefix, fragmented the way the eBPF tail-call pump emits it.
        let prefix = &request[..CEILING];
        push_call(&mut pipeline, 88, 4242, 10, prefix, 31 * 1024);
        assert_eq!(pipeline.stats().calls_oversized, 0);
        assert_eq!(pipeline.stats().requests_parsed, 0);
        assert!(pipeline.take_observations().is_empty());

        // Header-only truncation marker closing the call, carrying the true length.
        pipeline
            .push(
                FixtureFragment {
                    pid: 88,
                    tid: 88,
                    ssl_pointer: 4242,
                    call_sequence: 10,
                    fragment_index: CEILING.div_ceil(31 * 1024) as u32,
                    fragment_offset: 0,
                    original_length: request.len() as u64,
                    observed_at_monotonic_ns: 10,
                    is_read: false,
                    truncated: true,
                    bytes: &[],
                },
                Instant::now(),
            )
            .unwrap();
        assert_eq!(pipeline.stats().calls_oversized, 1);
        assert_eq!(pipeline.stats().calls_incomplete, 1);
        assert_eq!(pipeline.stats().requests_parsed, 0);
        assert!(pipeline.take_observations().is_empty());

        let body = serde_json::to_vec(&json!({
            "model": "kimi-for-coding",
            "messages": [{"role": "user", "content": "alive after the over-ceiling call"}]
        }))
        .unwrap();
        let request = [
            format!(
                "POST /coding/v1/chat/completions HTTP/1.1\r\nHost: api.kimi.com\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes(),
            body,
        ]
        .concat();
        push_call(&mut pipeline, 88, 4242, 11, &request, 509);
        let observations = pipeline.take_observations();
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].user_instruction,
            "alive after the over-ceiling call"
        );
        assert_eq!(pipeline.stats().requests_parsed, 1);
        assert_eq!(pipeline.stats().calls_oversized, 1);
    }
}
