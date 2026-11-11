//! a3s-observer collector — loads the eBPF probes, pumps the ring buffers, and emits
//! enriched events through the [`Exporter`] contract.
//!
//! Probes: `exec` (tools), `tls_*` (TLS ClientHello → SNI → provider), `connect` (peer IP),
//! `dns` (hostnames), `file_open` (files opened for writing). Userspace enriches with
//! identity (`/proc` comm+ppid, k8s cgroup→pod) and a `(pid,fd)→peer` correlation, then
//! exports (NDJSON or log). OTLP is a drop-in via the `Exporter` trait.

mod claude_boringssl;
mod codex_rustls;
mod interaction_fixture;
mod interaction_response;
mod openssl_symbols;
mod process_identity;
mod runtime_discovery;

use a3s_observer::{
    read_ppid, AgentEvent, EnrichedEvent, Exporter, Identity, IdentityResolver, JsonExporter,
    KubeResolver, LlmToolCall, LogExporter, ObservationMetadata, ProcessContext, Provider,
    ServiceClassifier, SniClassifier,
};
use a3s_observer_common::{
    ConnectEvent, DnsEvent, ExecRecord, ExitEvent, FileEvent, LlmEvent, ProcessKernelIdentity,
    SecEvent, SslEventHeader, TlsEvent, ARGV_SLOTS, CONTENT_OPERATION_CODEX_RUSTLS_WRITE,
    CONTENT_OPERATION_CODEX_RUSTLS_WRITEV, CONTENT_OPERATION_NATIVE_STDIN_EOF,
    CONTENT_OPERATION_NATIVE_STDIN_READ, CONTENT_OPERATION_NATIVE_STDOUT_EOF,
    CONTENT_OPERATION_NATIVE_STDOUT_WRITE, EXEC_ARG_CHUNK_LEN, EXEC_ARG_CHUNK_PAYLOAD,
    EXEC_COMPACT_ARG_LEN, EXEC_COMPACT_SLOTS, EXEC_FLAG_ARGV_INCOMPLETE, EXEC_FLAG_ARGV_TRUNCATED,
    EXEC_MAX_CHUNKS, EXEC_RECORD_ARG_CHUNK, EXEC_RECORD_COMMIT, EXEC_RECORD_COMPACT,
    EXEC_RECORD_END, EXEC_RECORD_HEADER, FILE_DELETE_FLAG, FILE_RENAME_FLAG, SEC_BIND, SEC_PTRACE,
    SEC_SETUID, SSL_EVENT_SCHEMA_VERSION, SSL_FRAGMENT_LEN, SSL_OPERATION_READ,
    SSL_OPERATION_READ_EX, SSL_OPERATION_WRITE, SSL_OPERATION_WRITE_EX, SSL_OPERATION_WRITE_EX2,
};
use anyhow::Context as _;
use aya::{
    maps::{Array, HashMap as AyaHashMap, PerCpuArray, ProgramArray, RingBuf},
    programs::{KProbe, TracePoint, UProbe},
    Ebpf,
};
use claude_boringssl::scan_claude_boringssl;
use codex_rustls::{scan_codex_rustls, RustlsOffset};
use interaction_fixture::{
    FixtureFragment, FixtureNativeInput, FixtureNativeOutput, FixturePipeline,
    FixturePipelineConfig, ObservedLlmRequest, RuntimePipelineConfig,
};
use interaction_response::{
    ObservedLlmResponse, ReadFragment, RequestContext, ResponsePipeline, ResponsePipelineConfig,
};
use openssl_symbols::resolve_openssl_ssl_offsets;
use runtime_discovery::{
    discover_a3s_runtimes, discover_claude_runtime_for_pid, discover_claude_runtimes,
    discover_codex_runtime_for_pid, discover_codex_runtimes, discover_kimi_runtime_for_pid,
    discover_kimi_runtimes, RuntimeBinaryCandidate, RuntimeDiscoveryConfig, RuntimeFileIdentity,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const EXEC_REASSEMBLY_TIMEOUT: Duration = Duration::from_millis(500);
const EXEC_REASSEMBLY_LIMIT: usize = 4096;
const PROC_CMDLINE_MAX_BYTES: usize = 2 * 1024 * 1024;
const PROCESS_CONTEXT_CACHE_TTL: Duration = Duration::from_secs(2);
const PROCESS_CONTEXT_CACHE_STALE: Duration = Duration::from_secs(30);
const PROCESS_CONTEXT_CACHE_LIMIT: usize = 65_536;
const PAYLOAD_FIXTURE_CONFIRMATION: &str = "I_UNDERSTAND_PLAINTEXT_CAPTURE";
const PAYLOAD_FIXTURE_PID_LIMIT: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InteractionCaptureMode {
    Off,
    Metadata,
    FixturePayload,
    RuntimePayload,
}

impl InteractionCaptureMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Metadata => "metadata",
            Self::FixturePayload => "fixture_payload",
            Self::RuntimePayload => "runtime_payload",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InteractionCaptureConfig {
    mode: InteractionCaptureMode,
    fixture_pids: Vec<u32>,
    fixture_output_path: Option<PathBuf>,
    fixture_provider_hosts: Vec<String>,
    ssl_library: String,
    ignored_legacy_ssl: bool,
}

fn parse_interaction_capture_config(
    mode: Option<&str>,
    environment: Option<&str>,
    confirmation: Option<&str>,
    fixture_pids: Option<&str>,
    ssl_library: Option<&str>,
    legacy_ssl: Option<&str>,
    fixture_artifact: (Option<&str>, Option<&str>),
) -> anyhow::Result<InteractionCaptureConfig> {
    let (fixture_output_path, fixture_provider_hosts) = fixture_artifact;
    let mode = match mode.unwrap_or("metadata").trim().to_ascii_lowercase().as_str() {
        "" | "metadata" => InteractionCaptureMode::Metadata,
        "off" | "disabled" | "0" | "false" => InteractionCaptureMode::Off,
        "fixture_payload" => InteractionCaptureMode::FixturePayload,
        "runtime_payload" => InteractionCaptureMode::RuntimePayload,
        other => anyhow::bail!(
            "invalid A3S_OBSERVER_INTERACTION_CAPTURE_MODE={other:?}; expected off, metadata, fixture_payload, or runtime_payload"
        ),
    };
    let legacy_enabled = legacy_ssl
        .map(|value| !value.trim().is_empty() && !env_value_disabled(value))
        .unwrap_or(false);
    let mut parsed_pids = Vec::new();
    let mut parsed_provider_hosts = Vec::new();
    let mut parsed_output_path = None;
    if mode == InteractionCaptureMode::FixturePayload {
        if environment != Some("isolated_test") {
            anyhow::bail!("fixture_payload requires A3S_OBSERVER_ENVIRONMENT=isolated_test");
        }
        if confirmation != Some(PAYLOAD_FIXTURE_CONFIRMATION) {
            anyhow::bail!(
                "fixture_payload requires the explicit A3S_OBSERVER_ALLOW_PAYLOAD_FIXTURE confirmation"
            );
        }
        for raw in fixture_pids.unwrap_or_default().split(',') {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let pid = raw
                .parse::<u32>()
                .with_context(|| format!("invalid fixture PID {raw:?}"))?;
            if pid == 0 || pid > i32::MAX as u32 {
                anyhow::bail!("fixture PID must be between 1 and {}", i32::MAX);
            }
            if !parsed_pids.contains(&pid) {
                parsed_pids.push(pid);
            }
        }
        if parsed_pids.is_empty() {
            anyhow::bail!(
                "fixture_payload requires A3S_OBSERVER_PAYLOAD_FIXTURE_PIDS with at least one PID"
            );
        }
        if parsed_pids.len() > PAYLOAD_FIXTURE_PID_LIMIT {
            anyhow::bail!(
                "fixture payload PID allowlist exceeds {PAYLOAD_FIXTURE_PID_LIMIT} entries"
            );
        }
        let output = fixture_output_path
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .context(
                "fixture_payload requires A3S_OBSERVER_PAYLOAD_FIXTURE_OUTPUT with a new absolute file path",
            )?;
        let output = PathBuf::from(output);
        if !output.is_absolute() {
            anyhow::bail!("fixture payload output path must be absolute");
        }
        parsed_output_path = Some(output);
        for raw in fixture_provider_hosts.unwrap_or_default().split(',') {
            let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
            if host.is_empty() {
                continue;
            }
            if host.len() > 253
                || !host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            {
                anyhow::bail!("invalid fixture provider host {host:?}");
            }
            if !parsed_provider_hosts.contains(&host) {
                parsed_provider_hosts.push(host);
            }
        }
        if parsed_provider_hosts.is_empty() {
            anyhow::bail!("fixture_payload requires A3S_OBSERVER_PAYLOAD_FIXTURE_PROVIDER_HOSTS");
        }
        if parsed_provider_hosts.len() > 32 {
            anyhow::bail!("fixture provider host allowlist exceeds 32 entries");
        }
    }
    Ok(InteractionCaptureConfig {
        mode,
        fixture_pids: parsed_pids,
        fixture_output_path: parsed_output_path,
        fixture_provider_hosts: parsed_provider_hosts,
        ssl_library: ssl_library
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("/usr/lib/x86_64-linux-gnu/libssl.so.3")
            .to_string(),
        ignored_legacy_ssl: legacy_enabled && mode != InteractionCaptureMode::FixturePayload,
    })
}

const RUNTIME_PAYLOAD_CONFIRMATION: &str = "I_UNDERSTAND_MODEL_REQUEST_CAPTURE";

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeCaptureConfig {
    target_pids: Vec<u32>,
    provider_hosts: Vec<String>,
    auto_discover: bool,
    discovery: RuntimeDiscoveryConfig,
    discovery_interval: Duration,
}

fn validate_runtime_capture_scope(target_pids: &[u32], auto_discover: bool) -> anyhow::Result<()> {
    if target_pids.is_empty() && !auto_discover {
        anyhow::bail!(
            "runtime_payload requires at least one exact A3S_OBSERVER_RUNTIME_TARGET_PIDS entry or A3S_OBSERVER_RUNTIME_AUTO_DISCOVER=1"
        );
    }
    if auto_discover && !target_pids.is_empty() {
        anyhow::bail!(
            "runtime_payload auto-discovery and exact target PIDs are mutually exclusive; remove A3S_OBSERVER_RUNTIME_TARGET_PIDS when A3S_OBSERVER_RUNTIME_AUTO_DISCOVER=1"
        );
    }
    if target_pids.len() > PAYLOAD_FIXTURE_PID_LIMIT {
        anyhow::bail!("runtime payload PID allowlist exceeds {PAYLOAD_FIXTURE_PID_LIMIT} entries");
    }
    Ok(())
}

fn runtime_capture_config_from_env(
    mode: InteractionCaptureMode,
) -> anyhow::Result<Option<RuntimeCaptureConfig>> {
    if mode != InteractionCaptureMode::RuntimePayload {
        return Ok(None);
    }
    let environment = std::env::var("A3S_OBSERVER_ENVIRONMENT").unwrap_or_default();
    if !matches!(
        environment.trim(),
        "local_development" | "controlled_capture"
    ) {
        anyhow::bail!(
            "runtime_payload requires A3S_OBSERVER_ENVIRONMENT=local_development or controlled_capture"
        );
    }
    if std::env::var("A3S_OBSERVER_ALLOW_RUNTIME_PAYLOAD")
        .ok()
        .as_deref()
        != Some(RUNTIME_PAYLOAD_CONFIRMATION)
    {
        anyhow::bail!(
            "runtime_payload requires the explicit A3S_OBSERVER_ALLOW_RUNTIME_PAYLOAD confirmation"
        );
    }
    let mut target_pids = Vec::new();
    for raw in std::env::var("A3S_OBSERVER_RUNTIME_TARGET_PIDS")
        .unwrap_or_default()
        .split(',')
    {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let pid = raw
            .parse::<u32>()
            .with_context(|| format!("invalid runtime payload PID {raw:?}"))?;
        if pid == 0 || pid > i32::MAX as u32 {
            anyhow::bail!("runtime payload PID must be between 1 and {}", i32::MAX);
        }
        if !target_pids.contains(&pid) {
            target_pids.push(pid);
        }
    }
    // Runtime payload capture remains an explicit, separately confirmed mode, but locating the
    // concrete TLS carrier is automatic by default. Operators may still select exact PIDs for a
    // narrow diagnostic capture; neither normal path requires a binary filename.
    let auto_discover = std::env::var("A3S_OBSERVER_RUNTIME_AUTO_DISCOVER")
        .ok()
        .map(|value| !env_value_disabled(&value))
        .unwrap_or(target_pids.is_empty());
    validate_runtime_capture_scope(&target_pids, auto_discover)?;
    let binary_override = std::env::var("A3S_OBSERVER_RUNTIME_BINARY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .map(|path| {
            if !path.is_absolute() {
                anyhow::bail!("A3S_OBSERVER_RUNTIME_BINARY override must be absolute");
            }
            Ok(path)
        })
        .transpose()?;
    let mut provider_hosts = Vec::new();
    for raw in std::env::var("A3S_OBSERVER_RUNTIME_PROVIDER_HOSTS")
        .unwrap_or_else(|_| {
            "chatgpt.com,api.openai.com,api.anthropic.com,open.bigmodel.cn".to_string()
        })
        .split(',')
    {
        let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            continue;
        }
        if host.len() > 253
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        {
            anyhow::bail!("invalid runtime provider host {host:?}");
        }
        if !provider_hosts.contains(&host) {
            provider_hosts.push(host);
        }
    }
    if provider_hosts.is_empty() {
        anyhow::bail!("runtime payload provider host allowlist is empty");
    }
    let proc_root = std::env::var("A3S_OBSERVER_PROC_ROOT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/proc"));
    let configured_host_root = std::env::var("A3S_OBSERVER_HOST_ROOT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/host"));
    let host_root = if configured_host_root.is_dir() {
        configured_host_root
    } else {
        PathBuf::from("/")
    };
    let discovery_interval = Duration::from_millis(env_bounded_usize(
        "A3S_OBSERVER_RUNTIME_DISCOVERY_INTERVAL_MS",
        1_000,
        100,
        60_000,
    ) as u64);
    let discovery = RuntimeDiscoveryConfig::new(
        proc_root,
        host_root,
        binary_override.clone(),
        target_pids.clone(),
        auto_discover,
    );
    Ok(Some(RuntimeCaptureConfig {
        target_pids,
        provider_hosts,
        auto_discover,
        discovery,
        discovery_interval,
    }))
}

fn interaction_capture_config_from_env() -> anyhow::Result<InteractionCaptureConfig> {
    let value = |name: &str| std::env::var(name).ok();
    let mode = value("A3S_OBSERVER_INTERACTION_CAPTURE_MODE");
    let environment = value("A3S_OBSERVER_ENVIRONMENT");
    let confirmation = value("A3S_OBSERVER_ALLOW_PAYLOAD_FIXTURE");
    let fixture_pids = value("A3S_OBSERVER_PAYLOAD_FIXTURE_PIDS");
    let ssl_library = value("A3S_OBSERVER_SSL_LIBRARY");
    let legacy_ssl = value("A3S_OBSERVER_SSL");
    let fixture_output_path = value("A3S_OBSERVER_PAYLOAD_FIXTURE_OUTPUT");
    let fixture_provider_hosts = value("A3S_OBSERVER_PAYLOAD_FIXTURE_PROVIDER_HOSTS");
    parse_interaction_capture_config(
        mode.as_deref(),
        environment.as_deref(),
        confirmation.as_deref(),
        fixture_pids.as_deref(),
        ssl_library.as_deref(),
        legacy_ssl.as_deref(),
        (
            fixture_output_path.as_deref(),
            fixture_provider_hosts.as_deref(),
        ),
    )
}

fn fixture_native_stdin_enabled(
    mode: InteractionCaptureMode,
    value: Option<&str>,
) -> anyhow::Result<bool> {
    let enabled = value
        .map(|raw| !raw.trim().is_empty() && !env_value_disabled(raw))
        .unwrap_or(false);
    if enabled && mode != InteractionCaptureMode::FixturePayload {
        anyhow::bail!(
            "A3S_OBSERVER_PAYLOAD_FIXTURE_NATIVE_STDIN requires fixture_payload isolated mode"
        );
    }
    Ok(enabled)
}

fn fixture_native_stdout_enabled(
    mode: InteractionCaptureMode,
    value: Option<&str>,
) -> anyhow::Result<bool> {
    let enabled = value
        .map(|raw| !raw.trim().is_empty() && !env_value_disabled(raw))
        .unwrap_or(false);
    if enabled && mode != InteractionCaptureMode::FixturePayload {
        anyhow::bail!(
            "A3S_OBSERVER_PAYLOAD_FIXTURE_NATIVE_STDOUT requires fixture_payload isolated mode"
        );
    }
    Ok(enabled)
}

fn fixture_openssl_enabled(
    mode: InteractionCaptureMode,
    value: Option<&str>,
) -> anyhow::Result<bool> {
    let enabled = value
        .map(|raw| !raw.trim().is_empty() && !env_value_disabled(raw))
        .unwrap_or(mode == InteractionCaptureMode::FixturePayload);
    if enabled && mode != InteractionCaptureMode::FixturePayload {
        anyhow::bail!(
            "A3S_OBSERVER_PAYLOAD_FIXTURE_OPENSSL requires fixture_payload isolated mode"
        );
    }
    Ok(enabled)
}

#[derive(Clone)]
struct CachedProcessContext {
    context: ProcessContext,
    refreshed_at: Instant,
}

#[derive(Default)]
struct ProcessContextCache {
    entries: HashMap<u32, CachedProcessContext>,
    hits: u64,
    misses: u64,
}

impl ProcessContextCache {
    fn get(
        &mut self,
        pid: u32,
        cgroup_id: u64,
        start_boottime_ns: Option<u64>,
        comm: &str,
        now: Instant,
    ) -> Option<ProcessContext> {
        let cached = self.entries.get(&pid)?;
        let generation_matches = match start_boottime_ns {
            Some(ns) => cached.context.start_boottime_ns == Some(ns),
            None => comm.is_empty() || cached.context.comm == comm,
        };
        let valid = now.duration_since(cached.refreshed_at) <= PROCESS_CONTEXT_CACHE_TTL
            && cached.context.cgroup_id == cgroup_id
            && generation_matches;
        if valid {
            self.hits += 1;
            let mut context = cached.context.clone();
            if !comm.is_empty() {
                context.comm = comm.to_string();
            }
            Some(context)
        } else {
            self.entries.remove(&pid);
            None
        }
    }

    fn insert(&mut self, context: ProcessContext, now: Instant) {
        if self.entries.len() >= PROCESS_CONTEXT_CACHE_LIMIT {
            self.entries.retain(|_, cached| {
                now.duration_since(cached.refreshed_at) <= PROCESS_CONTEXT_CACHE_STALE
            });
            if self.entries.len() >= PROCESS_CONTEXT_CACHE_LIMIT {
                self.entries.clear();
            }
        }
        self.entries.insert(
            context.pid,
            CachedProcessContext {
                context,
                refreshed_at: now,
            },
        );
    }

    fn remove(&mut self, pid: u32) {
        self.entries.remove(&pid);
    }
}

fn process_context_cache() -> &'static Mutex<ProcessContextCache> {
    static CACHE: OnceLock<Mutex<ProcessContextCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(ProcessContextCache::default()))
}

struct PendingExec {
    first_seen: Instant,
    cgroup_id: u64,
    identity: ProcessKernelIdentity,
    pid: u32,
    ppid: u32,
    uid: u32,
    comm: [u8; 16],
    filename: [u8; EXEC_ARG_CHUNK_LEN],
    saw_header: bool,
    saw_commit: bool,
    argc: Option<u16>,
    captured_bytes: Option<u32>,
    flags: u8,
    compact_argv: Option<Vec<u8>>,
    chunks: HashMap<u16, BTreeMap<u16, Vec<u8>>>,
}

impl PendingExec {
    fn new(record: &ExecRecord, now: Instant) -> Self {
        Self {
            first_seen: now,
            cgroup_id: record.cgroup_id,
            identity: record.identity,
            pid: record.pid,
            ppid: record.ppid,
            uid: record.uid,
            comm: record.comm,
            filename: [0; EXEC_ARG_CHUNK_LEN],
            saw_header: false,
            saw_commit: false,
            argc: None,
            captured_bytes: None,
            flags: 0,
            compact_argv: None,
            chunks: HashMap::new(),
        }
    }

    fn apply(&mut self, record: &ExecRecord) {
        self.flags |= record.flags;
        if self.cgroup_id != record.cgroup_id {
            self.flags |= EXEC_FLAG_ARGV_INCOMPLETE;
        }
        match record.kind {
            EXEC_RECORD_HEADER => {
                self.saw_header = true;
                let len = (record.data_len as usize).min(record.data.len());
                self.filename[..len].copy_from_slice(&record.data[..len]);
            }
            EXEC_RECORD_ARG_CHUNK => {
                if record.arg_index as usize >= ARGV_SLOTS
                    || record.chunk_index as usize >= EXEC_MAX_CHUNKS
                    || record.data_len as usize > record.data.len()
                {
                    self.flags |= EXEC_FLAG_ARGV_INCOMPLETE;
                    return;
                }
                let len = record.data_len as usize;
                let value = record.data[..len].to_vec();
                let chunks = self.chunks.entry(record.arg_index).or_default();
                if let Some(existing) = chunks.get(&record.chunk_index) {
                    if existing != &value {
                        self.flags |= EXEC_FLAG_ARGV_INCOMPLETE;
                    }
                } else {
                    chunks.insert(record.chunk_index, value);
                }
            }
            EXEC_RECORD_COMPACT => {
                if record.data_len as usize > record.data.len() {
                    self.flags |= EXEC_FLAG_ARGV_INCOMPLETE;
                    return;
                }
                let value = record.data[..record.data_len as usize].to_vec();
                if self.compact_argv.as_ref().is_some_and(|old| old != &value) {
                    self.flags |= EXEC_FLAG_ARGV_INCOMPLETE;
                }
                self.compact_argv = Some(value);
                self.argc = Some(record.argc.min(ARGV_SLOTS as u16));
                self.captured_bytes = Some(record.captured_bytes);
            }
            EXEC_RECORD_END => {
                self.argc = Some(record.argc.min(ARGV_SLOTS as u16));
                self.captured_bytes = Some(record.captured_bytes);
            }
            EXEC_RECORD_COMMIT => {
                self.saw_commit = true;
                self.comm = record.comm;
            }
            _ => self.flags |= EXEC_FLAG_ARGV_INCOMPLETE,
        }
    }

    fn finish(mut self, timed_out: bool) -> CompletedExec {
        let compact = self.compact_argv.take();
        let compact_format = compact.is_some();
        let mut argv_incomplete = timed_out
            || compact.is_none() && !self.saw_header
            || self.argc.is_none()
            || self.flags & EXEC_FLAG_ARGV_INCOMPLETE != 0;
        let argv_truncated = self.flags & EXEC_FLAG_ARGV_TRUNCATED != 0;
        let inferred_argc = self
            .chunks
            .keys()
            .max()
            .map(|index| index.saturating_add(1))
            .unwrap_or(0);
        let captured_argc = self.argc.unwrap_or(inferred_argc).min(ARGV_SLOTS as u16);
        let mut argv = Vec::with_capacity(captured_argc as usize);
        let mut assembled_bytes = 0u32;

        if let Some(bytes) = compact {
            if captured_argc as usize > EXEC_COMPACT_SLOTS
                || bytes.len() != captured_argc as usize * EXEC_COMPACT_ARG_LEN
            {
                argv_incomplete = true;
            }
            for arg_index in 0..captured_argc as usize {
                let start = arg_index * EXEC_COMPACT_ARG_LEN;
                let end = start + EXEC_COMPACT_ARG_LEN;
                if end > bytes.len() {
                    argv_incomplete = true;
                    break;
                }
                let slot = &bytes[start..end];
                let len = slot
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(slot.len());
                if slot[len..].iter().any(|byte| *byte != 0) {
                    argv_incomplete = true;
                }
                assembled_bytes = assembled_bytes.saturating_add(len as u32);
                argv.push(String::from_utf8_lossy(&slot[..len]).into_owned());
            }
        } else {
            for arg_index in 0..captured_argc {
                let Some(chunks) = self.chunks.remove(&arg_index) else {
                    argv_incomplete = true;
                    argv.push(String::new());
                    continue;
                };
                let mut bytes = Vec::new();
                let mut expected_chunk = 0u16;
                let mut saw_terminator = false;
                for (chunk_index, chunk) in chunks {
                    if chunk_index != expected_chunk {
                        argv_incomplete = true;
                    }
                    expected_chunk = chunk_index.saturating_add(1);
                    assembled_bytes = assembled_bytes.saturating_add(chunk.len() as u32);
                    if chunk.len() < EXEC_ARG_CHUNK_PAYLOAD {
                        saw_terminator = true;
                    }
                    bytes.extend_from_slice(&chunk);
                }
                if !(saw_terminator || argv_truncated && arg_index + 1 == captured_argc) {
                    argv_incomplete = true;
                }
                argv.push(String::from_utf8_lossy(&bytes).into_owned());
            }
            if !self.chunks.is_empty() {
                argv_incomplete = true;
            }
        }
        if let Some(expected_bytes) = self.captured_bytes {
            if expected_bytes != assembled_bytes {
                argv_incomplete = true;
            }
        }
        if argv.is_empty() {
            let filename = cstr(&self.filename);
            if !filename.is_empty() {
                argv.push(filename);
            }
        }

        CompletedExec {
            cgroup_id: self.cgroup_id,
            identity: self.identity,
            pid: self.pid,
            ppid: self.ppid,
            uid: self.uid,
            comm: self.comm,
            filename: self.filename,
            argv,
            argv_truncated,
            argv_incomplete,
            captured_argc,
            captured_bytes: self.captured_bytes.unwrap_or(assembled_bytes),
            compact: compact_format,
            reassembly_timed_out: timed_out && (self.argc.is_none() || !self.saw_header),
            exec_confirmed: self.saw_commit,
        }
    }
}

struct CompletedExec {
    cgroup_id: u64,
    identity: ProcessKernelIdentity,
    pid: u32,
    ppid: u32,
    uid: u32,
    comm: [u8; 16],
    filename: [u8; EXEC_ARG_CHUNK_LEN],
    argv: Vec<String>,
    argv_truncated: bool,
    argv_incomplete: bool,
    captured_argc: u16,
    captured_bytes: u32,
    compact: bool,
    reassembly_timed_out: bool,
    exec_confirmed: bool,
}

struct ExecAssembler {
    pending: HashMap<(u64, u32), PendingExec>,
    require_commit: bool,
}

impl Default for ExecAssembler {
    fn default() -> Self {
        Self {
            pending: HashMap::new(),
            require_commit: true,
        }
    }
}

impl ExecAssembler {
    fn new(require_commit: bool) -> Self {
        Self {
            pending: HashMap::new(),
            require_commit,
        }
    }

    fn push(&mut self, record: ExecRecord, now: Instant) -> Vec<CompletedExec> {
        let mut completed = Vec::with_capacity(2);
        let key = (record.exec_id, record.pid);
        if !self.pending.contains_key(&key) && self.pending.len() >= EXEC_REASSEMBLY_LIMIT {
            if let Some(oldest) = self
                .pending
                .iter()
                .min_by_key(|(_, pending)| pending.first_seen)
                .map(|(key, _)| *key)
            {
                if let Some(pending) = self.pending.remove(&oldest) {
                    completed.push(pending.finish(true));
                }
            }
        }

        self.pending
            .entry(key)
            .or_insert_with(|| PendingExec::new(&record, now))
            .apply(&record);
        let ready = self.pending.get(&key).is_some_and(|pending| {
            pending.argc.is_some() && (pending.saw_commit || !self.require_commit)
        });
        if ready {
            if let Some(pending) = self.pending.remove(&key) {
                completed.push(pending.finish(false));
            }
        }
        completed
    }

    fn expire(&mut self, now: Instant) -> Vec<CompletedExec> {
        let expired: Vec<(u64, u32)> = self
            .pending
            .iter()
            .filter(|(_, pending)| {
                now.duration_since(pending.first_seen) >= EXEC_REASSEMBLY_TIMEOUT
            })
            .map(|(key, _)| *key)
            .collect();
        expired
            .into_iter()
            .filter_map(|key| self.pending.remove(&key))
            .map(|pending| pending.finish(true))
            .collect()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => {
            println!("a3s-observer-collector {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("--discover-codex-runtimes") => {
            let proc_root = std::env::var("A3S_OBSERVER_PROC_ROOT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/proc"));
            let configured_host_root = std::env::var("A3S_OBSERVER_HOST_ROOT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/host"));
            let host_root = if configured_host_root.is_dir() {
                configured_host_root
            } else {
                PathBuf::from("/")
            };
            let discovery =
                RuntimeDiscoveryConfig::new(proc_root, host_root, None, Vec::new(), true);
            let candidates = discover_codex_runtimes(&discovery)?;
            let mut supported = 0usize;
            for candidate in candidates {
                let Ok(offsets) = scan_codex_rustls(&candidate.attach_path) else {
                    continue;
                };
                supported = supported.saturating_add(1);
                println!(
                    "{}",
                    serde_json::json!({
                        "binary": candidate.logical_path,
                        "attach_path": candidate.attach_path,
                        "source": candidate.source,
                        "device": candidate.identity.device,
                        "inode": candidate.identity.inode,
                        "pids": candidate.pids,
                        "rustls_offsets": offsets.len(),
                    })
                );
            }
            if supported == 0 {
                anyhow::bail!("no supported native Codex/rustls runtime discovered");
            }
            return Ok(());
        }
        Some("--discover-claude-runtimes") => {
            let proc_root = std::env::var("A3S_OBSERVER_PROC_ROOT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/proc"));
            let configured_host_root = std::env::var("A3S_OBSERVER_HOST_ROOT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/host"));
            let host_root = if configured_host_root.is_dir() {
                configured_host_root
            } else {
                PathBuf::from("/")
            };
            let discovery =
                RuntimeDiscoveryConfig::new(proc_root, host_root, None, Vec::new(), true);
            let candidates = discover_claude_runtimes(&discovery)?;
            let mut supported = 0usize;
            for candidate in candidates {
                let Ok(offsets) = scan_claude_boringssl(&candidate.attach_path) else {
                    continue;
                };
                supported = supported.saturating_add(1);
                println!(
                    "{}",
                    serde_json::json!({
                        "binary": candidate.logical_path,
                        "attach_path": candidate.attach_path,
                        "source": candidate.source,
                        "device": candidate.identity.device,
                        "inode": candidate.identity.inode,
                        "pids": candidate.pids,
                        "ssl_write_offset": offsets.ssl_write,
                        "ssl_read_offset": offsets.ssl_read,
                    })
                );
            }
            if supported == 0 {
                anyhow::bail!("no supported Claude Code/BoringSSL runtime discovered");
            }
            return Ok(());
        }
        Some("--discover-kimi-runtimes") => {
            let proc_root = std::env::var("A3S_OBSERVER_PROC_ROOT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/proc"));
            let configured_host_root = std::env::var("A3S_OBSERVER_HOST_ROOT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/host"));
            let host_root = if configured_host_root.is_dir() {
                configured_host_root
            } else {
                PathBuf::from("/")
            };
            let discovery =
                RuntimeDiscoveryConfig::new(proc_root, host_root, None, Vec::new(), true);
            let candidates = discover_kimi_runtimes(&discovery)?;
            let mut supported = 0usize;
            for candidate in candidates {
                let Ok(offsets) = resolve_openssl_ssl_offsets(&candidate.attach_path) else {
                    continue;
                };
                supported = supported.saturating_add(1);
                println!(
                    "{}",
                    serde_json::json!({
                        "binary": candidate.logical_path,
                        "attach_path": candidate.attach_path,
                        "source": candidate.source,
                        "device": candidate.identity.device,
                        "inode": candidate.identity.inode,
                        "pids": candidate.pids,
                        "ssl_write_offset": offsets.ssl_write,
                        "ssl_read_offset": offsets.ssl_read,
                    })
                );
            }
            if supported == 0 {
                anyhow::bail!("no supported kimi/OpenSSL runtime discovered");
            }
            return Ok(());
        }
        Some("--help" | "-h") => {
            println!(
                "a3s-observer-collector {} — language-agnostic eBPF observability for AI agents\n\n\
                 Run as root / CAP_BPF+CAP_PERFMON (Linux). Configure via env:\n  \
                 A3S_OBSERVER_JSON=1                         emit NDJSON (default: log)\n  \
                 A3S_OBSERVER_FILES=1                        capture file writes (off by default)\n  \
                 --discover-codex-runtimes                    verify automatic runtime discovery\n  \
                 --discover-claude-runtimes                   verify Claude/BoringSSL discovery\n  \
                 --discover-kimi-runtimes                     verify kimi/OpenSSL discovery\n  \
                 A3S_OBSERVER_INTERACTION_CAPTURE_MODE=metadata|off|runtime_payload\n  \
                     metadata is the production default and never reads TLS payload buffers.\n  \
                 runtime_payload automatically discovers native Codex ELF files from /proc and\n  \
                 the read-only host root, then attaches AnySentry's Rustls plaintext probes. It\n  \
                 additionally requires local_development/controlled_capture and an explicit\n  \
                 confirmation. A binary path is not required; A3S_OBSERVER_RUNTIME_BINARY is an\n  \
                 optional diagnostic override. Start Observer before the first model request so\n  \
                 compressed WebSocket state is observed from the handshake.\n  \
                 fixture_payload is reserved for an isolated Phase -1 test and additionally\n  \
                 requires A3S_OBSERVER_ENVIRONMENT=isolated_test, explicit confirmation, and\n  \
                 A3S_OBSERVER_PAYLOAD_FIXTURE_PIDS, a new absolute 0600 output file, and an\n  \
                 explicit provider-host allowlist. A3S_OBSERVER_PAYLOAD_FIXTURE_OPENSSL=off\n  \
                 disables the default OpenSSL fixture path; native stdin then additionally\n  \
                 requires A3S_OBSERVER_PAYLOAD_FIXTURE_NATIVE_STDIN=1. A3S_OBSERVER_SSL no\n  \
                 longer enables capture.",
                env!("CARGO_PKG_VERSION")
            );
            return Ok(());
        }
        _ => {}
    }
    // Logs go to STDERR so STDOUT stays pure NDJSON (the event stream a pipeline parses), at
    // INFO by default so the operational logs (throughput, drop counter) are actually visible.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();

    let capture_config = interaction_capture_config_from_env()?;
    let runtime_capture = runtime_capture_config_from_env(capture_config.mode)?;
    let initial_runtime_candidates = runtime_capture
        .as_ref()
        .map(|config| {
            let mut candidates = discover_codex_runtimes(&config.discovery)?;
            if config.auto_discover {
                candidates.extend(discover_a3s_runtimes(&config.discovery)?);
                candidates.extend(discover_claude_runtimes(&config.discovery)?);
                candidates.extend(discover_kimi_runtimes(&config.discovery)?);
            }
            Ok::<_, anyhow::Error>(candidates)
        })
        .transpose()?;
    let fixture_native_stdin = fixture_native_stdin_enabled(
        capture_config.mode,
        std::env::var("A3S_OBSERVER_PAYLOAD_FIXTURE_NATIVE_STDIN")
            .ok()
            .as_deref(),
    )?;
    let fixture_native_stdout = fixture_native_stdout_enabled(
        capture_config.mode,
        std::env::var("A3S_OBSERVER_PAYLOAD_FIXTURE_NATIVE_STDOUT")
            .ok()
            .as_deref(),
    )?;
    let fixture_openssl = fixture_openssl_enabled(
        capture_config.mode,
        std::env::var("A3S_OBSERVER_PAYLOAD_FIXTURE_OPENSSL")
            .ok()
            .as_deref(),
    )?;
    if capture_config.mode == InteractionCaptureMode::FixturePayload
        && !fixture_native_stdin
        && !fixture_native_stdout
        && !fixture_openssl
    {
        anyhow::bail!(
            "fixture_payload requires at least one isolated capture path: OpenSSL, native stdin, or native stdout"
        );
    }
    if capture_config.ignored_legacy_ssl {
        tracing::warn!(
            "A3S_OBSERVER_SSL was ignored: production payload capture now requires the isolated fixture_payload gate"
        );
    }

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/probes"
    )))
    .context("load eBPF object")?;

    match process_identity::config_from_sys_fs() {
        Ok(config) => {
            let map = ebpf
                .map_mut("PROCESS_IDENTITY_CONFIG")
                .context("missing PROCESS_IDENTITY_CONFIG map")?;
            let mut offsets =
                Array::<_, [u64; process_identity::PROCESS_IDENTITY_CONFIG_LEN]>::try_from(map)
                    .context("open PROCESS_IDENTITY_CONFIG map")?;
            offsets
                .set(0, config, 0)
                .context("configure BTF task_struct offsets")?;
            tracing::info!(?config, "kernel start_boottime identity enabled");
        }
        Err(error) => {
            tracing::warn!(%error, "start_boottime_unavailable; process generation identity degraded");
        }
    }

    // File-write capture is opt-in: openat is a firehose on a busy node (e.g. containerd
    // unpacking images), and the agent's own writes need downstream identity filtering.
    let legacy_files = env_enabled("A3S_OBSERVER_FILES");
    let file_access = legacy_files || env_enabled("A3S_OBSERVER_FILE_ACCESS");
    let file_delete = legacy_files || env_enabled("A3S_OBSERVER_FILE_DELETE");
    let files = file_access || file_delete;
    let file_include_paths = file_include_paths_from_env();
    let mut probes = vec![
        ("track_clone", "sys_exit_clone"),
        ("track_clone3", "sys_exit_clone3"),
        ("track_fork", "sys_exit_fork"),
        ("track_vfork", "sys_exit_vfork"),
        ("exec", "sys_enter_execve"),
        ("tls_write", "sys_enter_write"),
        ("tls_sendto", "sys_enter_sendto"),
        ("connect", "sys_enter_connect"),
        ("dns_query", "sys_enter_sendto"),
        ("dns_sendmsg", "sys_enter_sendmsg"),
        ("dns_sendmmsg", "sys_enter_sendmmsg"),
        ("read_enter", "sys_enter_read"),
        ("recv_enter", "sys_enter_recvfrom"),
        ("read_exit", "sys_exit_read"),
        ("recv_exit", "sys_exit_recvfrom"),
        ("sock_close", "sys_enter_close"),
        ("sec_setuid", "sys_enter_setuid"),
        ("sec_setresuid", "sys_enter_setresuid"),
        ("sec_setreuid", "sys_enter_setreuid"),
        ("sec_ptrace", "sys_enter_ptrace"),
        ("sec_bind", "sys_enter_bind"),
    ];
    if file_access {
        probes.push(("file_open", "sys_enter_openat"));
    }
    if file_delete {
        probes.push(("file_unlink", "sys_enter_unlinkat"));
        probes.push(("file_rename", "sys_enter_renameat"));
        probes.push(("file_rename2", "sys_enter_renameat2"));
    }
    // Per-probe attach is non-fatal: kernels vary, and one missing tracepoint shouldn't take
    // down the whole collector — degrade to whatever attaches, fail only if nothing does.
    let mut attached = 0usize;
    for (prog, tp) in &probes {
        match attach(&mut ebpf, prog, "syscalls", tp) {
            Ok(()) => attached += 1,
            Err(e) => {
                tracing::warn!(probe = prog, error = %e, "probe failed to attach — continuing")
            }
        }
    }
    // sched_process_fork runs before the child can execute, so its parent PID is available even for short-lived tools.
    match attach(
        &mut ebpf,
        "track_process_fork",
        "sched",
        "sched_process_fork",
    ) {
        Ok(()) => attached += 1,
        Err(e) => {
            tracing::warn!(error = %e, "sched_process_fork probe failed - using syscall-exit ancestry fallback")
        }
    }
    let exec_commit_probe_attached = match attach(
        &mut ebpf,
        "track_process_exec",
        "sched",
        "sched_process_exec",
    ) {
        Ok(()) => {
            attached += 1;
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, "sched_process_exec probe failed - proc cmdline supplementation disabled");
            false
        }
    };
    // proc_exit is a do_exit kprobe (not a tracepoint): do_exit fires for EVERY task exit,
    // including signal-kills (crash / OOM) that sys_enter_exit_group never sees.
    match attach_kprobe(&mut ebpf, "proc_exit", "do_exit") {
        Ok(()) => attached += 1,
        Err(e) => {
            tracing::warn!(error = %e, "proc_exit (do_exit kprobe) failed — exit signals unavailable")
        }
    }
    if attached == 0 {
        anyhow::bail!("no eBPF probes could be attached");
    }

    // Runtime payload mode loads the two Codex/rustls programs once, then attaches them to each
    // recognized exact ELF inode. The OpenSSL programs cover Claude (write-only) and kimi
    // (write + read for the response lane). A configured path is only a troubleshooting
    // override; normal operation discovers existing processes and common installations itself.
    // Auto mode may start with no Codex and attach later when one executes.
    let mut runtime_probe_state = RuntimeProbeState::default();
    if let Some(runtime) = &runtime_capture {
        load_uprobe_program(&mut ebpf, "codex_rustls_write")?;
        load_uprobe_program(&mut ebpf, "codex_rustls_write_vectored")?;
        load_uprobe_program(&mut ebpf, "ssl_write_enter")?;
        load_uprobe_program(&mut ebpf, "ssl_write_exit")?;
        load_uprobe_program(&mut ebpf, "ssl_read_enter")?;
        load_uprobe_program(&mut ebpf, "ssl_read_exit")?;
        let runtime_attached = attach_discovered_runtime_candidates(
            &mut ebpf,
            runtime,
            &mut runtime_probe_state,
            initial_runtime_candidates.as_deref().unwrap_or_default(),
        );
        if !runtime.auto_discover && runtime_attached == 0 {
            anyhow::bail!(
                "runtime_payload exact-PID scope resolved no supported Codex/rustls plaintext probe"
            );
        }
        if runtime.auto_discover && runtime_attached == 0 {
            tracing::warn!(
                proc_root = %runtime.discovery.proc_root.display(),
                host_root = %runtime.discovery.host_root.display(),
                "SENSITIVE CAPTURE armed, but no supported Codex runtime is currently installed or running; discovery will continue"
            );
        }
        attached = attached.saturating_add(runtime_attached);
    }

    // The legacy OpenSSL path remains limited to the isolated Phase -1 fixture.
    if fixture_openssl {
        let lib = &capture_config.ssl_library;
        let mut attached_probes = 0;
        let mut attached_pairs = 0;
        tracing::info!(
            lib = %lib,
            target_pid_count = capture_config.fixture_pids.len(),
            "attaching isolated OpenSSL fixture probes"
        );
        // Phase -1 is deliberately request-only: user instructions are present on the local
        // write path. Attaching SSL_read* would add synchronous response-path overhead while
        // expanding plaintext scope beyond the approved UserInstruction fixture.
        for (enter, exit, symbol) in [
            ("ssl_write_enter", "ssl_write_exit", "SSL_write"),
            ("ssl_write_ex_enter", "ssl_write_ex_exit", "SSL_write_ex"),
            ("ssl_write_ex2_enter", "ssl_write_ex2_exit", "SSL_write_ex2"),
        ] {
            tracing::info!(probe = enter, symbol, lib = %lib, "attaching SSL entry uprobe");
            let enter_ok = match attach_uprobe(
                &mut ebpf,
                enter,
                symbol,
                lib,
                &capture_config.fixture_pids,
            ) {
                Ok(()) => {
                    attached_probes += 1;
                    true
                }
                Err(e) => {
                    tracing::warn!(probe = enter, lib = %lib, error = %e, "SSL entry uprobe failed to attach");
                    false
                }
            };
            tracing::info!(probe = exit, symbol, lib = %lib, "attaching SSL return uprobe");
            let exit_ok = match attach_uprobe(
                &mut ebpf,
                exit,
                symbol,
                lib,
                &capture_config.fixture_pids,
            ) {
                Ok(()) => {
                    attached_probes += 1;
                    true
                }
                Err(e) => {
                    tracing::warn!(probe = exit, lib = %lib, error = %e, "SSL return uprobe failed to attach");
                    false
                }
            };
            if enter_ok && exit_ok {
                attached_pairs += 1;
            }
        }
        if attached_pairs == 0 {
            anyhow::bail!(
                "fixture_payload requested but no complete OpenSSL entry/return probe pair attached"
            );
        }
        tracing::warn!(
            lib = %lib,
            attached_probes,
            attached_pairs,
            target_pids = ?capture_config.fixture_pids,
            fixture_output = %capture_config.fixture_output_path.as_ref().expect("validated").display(),
            provider_hosts = ?capture_config.fixture_provider_hosts,
            "ISOLATED TEST ONLY: outbound OpenSSL payload probes attached"
        );
    }
    if fixture_native_stdin {
        for (program, tracepoint) in [
            ("native_stdin_enter", "sys_enter_read"),
            ("native_stdin_exit", "sys_exit_read"),
        ] {
            attach(&mut ebpf, program, "syscalls", tracepoint).with_context(|| {
                format!("attach isolated native stdin fixture {program} to {tracepoint}")
            })?;
            attached += 1;
        }
        tracing::warn!(
            target_pids = ?capture_config.fixture_pids,
            fd = 0,
            "ISOLATED TEST ONLY: Agent native stdin payload probes attached"
        );
    }
    if fixture_native_stdout {
        for (program, tracepoint) in [
            ("native_stdout_enter", "sys_enter_write"),
            ("native_stdout_exit", "sys_exit_write"),
        ] {
            attach(&mut ebpf, program, "syscalls", tracepoint).with_context(|| {
                format!("attach isolated native stdout fixture {program} to {tracepoint}")
            })?;
            attached += 1;
        }
        tracing::warn!(
            target_pids = ?capture_config.fixture_pids,
            fd = 1,
            boundary = "process_exit",
            "ISOLATED TEST ONLY: Agent native stdout payload probes attached"
        );
    }

    // The tail-call fragment pump is loaded alongside the other payload programs (map fixups
    // require the jump table map to still be registered), but its jump table is populated only
    // after every payload program has loaded: populating takes the map out of the loader.
    let mut jump_table: Option<ProgramArray<aya::maps::MapData>> = None;
    let payload_fragment_pump = runtime_capture.is_some()
        || fixture_openssl
        || fixture_native_stdin
        || fixture_native_stdout;
    if payload_fragment_pump {
        load_uprobe_program(&mut ebpf, "ssl_fragment_pump")?;
        jump_table = Some(populate_ssl_fragment_pump(&mut ebpf)?);
    }

    // A3S_OBSERVER_JSON=1 → NDJSON (pipe to vector/Loki/jq); otherwise human-readable log.
    let exporter: Box<dyn Exporter> = if env_enabled("A3S_OBSERVER_JSON") {
        Box::new(JsonExporter::new())
    } else {
        Box::new(LogExporter)
    };
    let classifier = SniClassifier;
    let resolver = KubeResolver; // cgroup→pod in k8s; falls back to comm on bare hosts
                                 // (pid,fd) -> peer, populated by connect, read by the TLS probe to fuse provider+peer.
    let mut peers: HashMap<u64, (IpAddr, u16)> = HashMap::new();
    // (pid,fd) -> (sni, provider, peer): recorded at ClientHello, read when the socket
    // closes (the in-kernel LlmEvent) to build the metric-bearing LlmCall.
    let mut llm_meta: HashMap<u64, (Option<String>, Option<Provider>, IpAddr)> = HashMap::new();
    // File open/unlink bursts (compiler and build workloads re-open the same paths thousands of
    // times per second). Coalescing repeats within a short per-(pid, path, flags) window keeps the
    // "which files did the workload modify" signal intact while protecting the Collector→Forwarder
    // pipe from slow-consumer backpressure that would otherwise wipe out file evidence entirely.
    let file_coalesce_ms = file_coalesce_ms_from_env();
    let mut file_coalesce_cache: HashMap<u64, u64> = HashMap::new();
    let mut exec_assembler = ExecAssembler::new(exec_commit_probe_attached);
    let mut exec_ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("`EVENTS` missing")?)?;
    let mut exec_meta_ring = RingBuf::try_from(
        ebpf.take_map("EXEC_META_EVENTS")
            .context("`EXEC_META_EVENTS` missing")?,
    )?;
    let mut exit_ring = RingBuf::try_from(
        ebpf.take_map("EXIT_EVENTS")
            .context("`EXIT_EVENTS` missing")?,
    )?;
    let mut tls_ring = RingBuf::try_from(
        ebpf.take_map("TLS_EVENTS")
            .context("`TLS_EVENTS` missing")?,
    )?;
    let mut connect_ring = RingBuf::try_from(
        ebpf.take_map("CONNECT_EVENTS")
            .context("`CONNECT_EVENTS` missing")?,
    )?;
    let mut dns_ring = RingBuf::try_from(
        ebpf.take_map("DNS_EVENTS")
            .context("`DNS_EVENTS` missing")?,
    )?;
    let mut file_ring = RingBuf::try_from(
        ebpf.take_map("FILE_EVENTS")
            .context("`FILE_EVENTS` missing")?,
    )?;
    let mut llm_ring = RingBuf::try_from(
        ebpf.take_map("LLM_EVENTS")
            .context("`LLM_EVENTS` missing")?,
    )?;
    // The payload ring exists in every object but receives bytes only in an explicitly gated,
    // exact-PID fixture or runtime mode. Metadata-only mode neither attaches plaintext probes nor
    // enables the BPF map.
    let mut ssl_ring = RingBuf::try_from(
        ebpf.take_map("SSL_EVENTS")
            .context("`SSL_EVENTS` missing")?,
    )?;
    let mut content_capture_enabled: Array<_, u32> = Array::try_from(
        ebpf.take_map("CONTENT_CAPTURE_ENABLED")
            .context("`CONTENT_CAPTURE_ENABLED` missing")?,
    )?;
    let mut content_capture_targets: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(
        ebpf.take_map("CONTENT_CAPTURE_TARGETS")
            .context("`CONTENT_CAPTURE_TARGETS` missing")?,
    )?;
    let mut codex_rustls_exact_binary_all: Array<_, u32> = Array::try_from(
        ebpf.take_map("CODEX_RUSTLS_EXACT_BINARY_ALL")
            .context("`CODEX_RUSTLS_EXACT_BINARY_ALL` missing")?,
    )?;
    let mut claude_boringssl_exact_binary_all: Array<_, u32> = Array::try_from(
        ebpf.take_map("CLAUDE_BORINGSSL_EXACT_BINARY_ALL")
            .context("`CLAUDE_BORINGSSL_EXACT_BINARY_ALL` missing")?,
    )?;
    let mut kimi_openssl_exact_binary_all: Array<_, u32> = Array::try_from(
        ebpf.take_map("KIMI_OPENSSL_EXACT_BINARY_ALL")
            .context("`KIMI_OPENSSL_EXACT_BINARY_ALL` missing")?,
    )?;
    let max_connections = env_bounded_usize("A3S_OBSERVER_PAYLOAD_MAX_CONNECTIONS", 64, 1, 1_024);
    let max_inflight_calls =
        env_bounded_usize("A3S_OBSERVER_PAYLOAD_MAX_INFLIGHT_CALLS", 512, 1, 8_192);
    let max_reassembly_bytes = env_bounded_usize(
        "A3S_OBSERVER_PAYLOAD_MAX_REASSEMBLY_BYTES",
        16 * 1024 * 1024,
        4 * 1024,
        64 * 1024 * 1024,
    );
    let max_decompressed_bytes = env_bounded_usize(
        "A3S_OBSERVER_PAYLOAD_MAX_DECOMPRESSED_BYTES",
        16 * 1024 * 1024,
        4 * 1024,
        64 * 1024 * 1024,
    );
    let reassembly_timeout = Duration::from_millis(env_bounded_usize(
        "A3S_OBSERVER_PAYLOAD_REASSEMBLY_TIMEOUT_MS",
        5_000,
        100,
        60_000,
    ) as u64);
    let mut interaction_pipeline = match capture_config.mode {
        InteractionCaptureMode::FixturePayload => {
            Some(FixturePipeline::new(FixturePipelineConfig {
                output_path: capture_config
                    .fixture_output_path
                    .clone()
                    .context("fixture output path missing after capture policy validation")?,
                allowed_provider_hosts: capture_config.fixture_provider_hosts.clone(),
                max_connections,
                max_inflight_calls,
                max_reassembly_bytes,
                max_decompressed_bytes,
                reassembly_timeout,
                retain_instruction_content: std::env::var(
                    "A3S_OBSERVER_PAYLOAD_FIXTURE_RETAIN_CONTENT",
                )
                .ok()
                .is_none_or(|value| !env_value_disabled(&value)),
            })?)
        }
        InteractionCaptureMode::RuntimePayload => {
            let runtime = runtime_capture
                .as_ref()
                .context("runtime capture config missing after validation")?;
            Some(FixturePipeline::new_runtime(RuntimePipelineConfig {
                allowed_provider_hosts: runtime.provider_hosts.clone(),
                configured_endpoint_attribution: if runtime.auto_discover {
                    "configured_endpoint"
                } else {
                    "configured_late_attach"
                },
                max_connections,
                max_inflight_calls,
                max_reassembly_bytes,
                max_decompressed_bytes,
                reassembly_timeout,
            })?)
        }
        InteractionCaptureMode::Off | InteractionCaptureMode::Metadata => None,
    };
    // Response-direction (SSL_read) reassembly is scoped to the kimi/OpenSSL lane: the ring
    // gate below only lets kimi read fragments through in runtime payload mode, so the
    // pipeline exists exactly when those fragments can arrive.
    let mut response_pipeline = match capture_config.mode {
        InteractionCaptureMode::RuntimePayload => {
            Some(ResponsePipeline::new(ResponsePipelineConfig {
                max_connections,
                max_inflight_calls,
                max_response_bytes: max_reassembly_bytes,
                max_content_bytes: max_reassembly_bytes,
                max_decompressed_bytes,
                reassembly_timeout,
            })?)
        }
        InteractionCaptureMode::Off
        | InteractionCaptureMode::Metadata
        | InteractionCaptureMode::FixturePayload => None,
    };
    let mut payload_capture_enabled = matches!(
        capture_config.mode,
        InteractionCaptureMode::FixturePayload | InteractionCaptureMode::RuntimePayload
    );
    content_capture_enabled.set(0, u32::from(payload_capture_enabled), 0)?;
    codex_rustls_exact_binary_all.set(
        0,
        u32::from(
            payload_capture_enabled
                && runtime_capture
                    .as_ref()
                    .is_some_and(|config| config.auto_discover),
        ),
        0,
    )?;
    claude_boringssl_exact_binary_all.set(
        0,
        u32::from(
            payload_capture_enabled
                && runtime_capture
                    .as_ref()
                    .is_some_and(|config| config.auto_discover),
        ),
        0,
    )?;
    kimi_openssl_exact_binary_all.set(
        0,
        u32::from(
            payload_capture_enabled
                && runtime_capture
                    .as_ref()
                    .is_some_and(|config| config.auto_discover),
        ),
        0,
    )?;
    if payload_capture_enabled {
        let target_pids = runtime_capture
            .as_ref()
            .map(|config| config.target_pids.as_slice())
            .unwrap_or(capture_config.fixture_pids.as_slice());
        for pid in target_pids {
            content_capture_targets.insert(*pid, 1, 0)?;
        }
    }
    let mut sec_ring = RingBuf::try_from(
        ebpf.take_map("SEC_EVENTS")
            .context("`SEC_EVENTS` missing")?,
    )?;
    // Cumulative count of events dropped because a ring was full (data-loss visibility).
    let drops: PerCpuArray<_, u64> =
        PerCpuArray::try_from(ebpf.take_map("DROPS").context("`DROPS` missing")?)?;
    let drops_by_kind: PerCpuArray<_, u64> = PerCpuArray::try_from(
        ebpf.take_map("DROPS_BY_KIND")
            .context("`DROPS_BY_KIND` missing")?,
    )?;
    let exec_part_drops: PerCpuArray<_, u64> = PerCpuArray::try_from(
        ebpf.take_map("EXEC_PART_DROPS")
            .context("`EXEC_PART_DROPS` missing")?,
    )?;
    let ssl_drops: PerCpuArray<_, u64> =
        PerCpuArray::try_from(ebpf.take_map("SSL_DROPS").context("`SSL_DROPS` missing")?)?;
    let ssl_pump_stats: PerCpuArray<_, u64> = PerCpuArray::try_from(
        ebpf.take_map("SSL_PUMP_STATS")
            .context("`SSL_PUMP_STATS` missing")?,
    )?;

    tracing::info!(
        attached,
        total = probes.len() + 3,
        files,
        interaction_capture_mode = capture_config.mode.as_str(),
        payload_capture_enabled,
        fixture_openssl,
        fixture_native_stdin,
        fixture_native_stdout,
        "a3s-observer-collector: probes attached (file-write capture: set A3S_OBSERVER_FILES=1); \
         streaming (Ctrl-C to stop)"
    );

    // Liveness heartbeat: refresh a file at startup and on every report tick, so a k8s
    // livenessProbe can detect a wedged collector (file goes stale → restart the pod).
    let heartbeat = std::env::var("A3S_OBSERVER_HEARTBEAT")
        .unwrap_or_else(|_| "/run/a3s-observer.alive".into());
    if let Err(e) = std::fs::write(&heartbeat, b"ok") {
        // Warn loudly: a livenessProbe watching a never-written file would false-restart.
        tracing::warn!(path = %heartbeat, error = %e,
            "heartbeat write failed — set A3S_OBSERVER_HEARTBEAT to a writable path, or a \
             livenessProbe on it will restart-loop the pod");
    }

    let collector = CollectorMeta::from_env(files, capture_config.mode, attached);

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigusr2 =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())?;
    let mut stats = Stats::default();
    let mut payload_kill_switch_at_unix_nanos = None;
    let mut payload_fragments_discarded = 0u64;
    let mut ssl_record_parse_failed = 0u64;
    let mut discard_empty_payload = 0u64;
    let mut discard_op_not_allowed = 0u64;
    let mut discard_native_gate = 0u64;
    emit_collector_heartbeat(
        exporter.as_ref(),
        &collector,
        &stats,
        CollectorHeartbeatRuntime {
            interval_secs: 0,
            dropped: 0,
            dropped_by_kind: BTreeMap::new(),
            output_dropped: exporter.output_drops(),
            output_dropped_by_kind: exporter.output_drops_by_kind(),
            payload_capture_enabled,
            payload_kill_switch_at_unix_nanos,
            payload_fragments_discarded,
        },
    );
    let mut report = tokio::time::interval(Duration::from_secs(60));
    report.tick().await; // consume the immediate first tick
    let runtime_discovery_interval = runtime_capture
        .as_ref()
        .map(|runtime| runtime.discovery_interval)
        .unwrap_or_else(|| Duration::from_secs(3_600));
    let mut runtime_discovery_tick = tokio::time::interval(runtime_discovery_interval);
    runtime_discovery_tick.tick().await;
    let runtime_capture_profile: &'static str = runtime_capture
        .as_ref()
        .map(|runtime| {
            if runtime.auto_discover {
                "exact_binary_runtime"
            } else {
                "exact_pid_runtime"
            }
        })
        .unwrap_or("exact_pid_runtime");
    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break, // k8s sends SIGTERM on pod termination
            _ = sigusr2.recv() => {
                // Operational one-way Kill Switch. Re-enabling requires a restart with the full
                // isolated-fixture gate, so a signal can never accidentally start capture.
                content_capture_enabled.set(0, 0, 0)?;
                payload_capture_enabled = false;
                payload_kill_switch_at_unix_nanos = Some(unix_nanos_now());
                while ssl_ring.next().is_some() {
                    payload_fragments_discarded = payload_fragments_discarded.saturating_add(1);
                }
                if let Some(pipeline) = interaction_pipeline.as_mut() {
                    pipeline.clear_plaintext();
                }
                if let Some(responses) = response_pipeline.as_mut() {
                    responses.clear_plaintext();
                }
                tracing::warn!(
                    payload_fragments_discarded,
                    "interaction payload Kill Switch engaged; BPF reads disabled and queued fragments discarded"
                );
            }
            _ = report.tick() => {
                let _ = std::fs::write(&heartbeat, b"ok"); // refresh liveness heartbeat
                if payload_capture_enabled {
                    if let Some(pipeline) = interaction_pipeline.as_mut() {
                        if let Err(error) = pipeline.expire(Instant::now()) {
                            content_capture_enabled.set(0, 0, 0)?;
                            payload_capture_enabled = false;
                            payload_kill_switch_at_unix_nanos = Some(unix_nanos_now());
                            pipeline.clear_plaintext();
                            tracing::error!(
                                error = %error,
                                "isolated fixture output failed; payload capture failed closed"
                            );
                        }
                    }
                    // Response-lane expiry is memory-only (no I/O), so it cannot fail; stale
                    // streams finalize as partial observations here.
                    if let Some(responses) = response_pipeline.as_mut() {
                        responses.expire(Instant::now());
                        let expired = responses.take_observations();
                        for observation in expired {
                            emit_observed_llm_response(
                                exporter.as_ref(),
                                &mut stats,
                                &resolver,
                                runtime_capture_profile,
                                observation,
                            );
                        }
                    }
                }
                let dropped: u64 = drops
                    .get(&0, 0)
                    .map(|v| v.iter().copied().sum())
                    .unwrap_or(0);
                let ssl_dropped: u64 = ssl_drops
                    .get(&0, 0)
                    .map(|v| v.iter().copied().sum())
                    .unwrap_or(0);
                let pump_stat = |slot: u32| -> u64 {
                    ssl_pump_stats
                        .get(&slot, 0)
                        .map(|v| v.iter().copied().sum())
                        .unwrap_or(0)
                };
                let output_dropped = exporter.output_drops();
                let mut dropped_by_kind = [
                    "exec", "exit", "tls", "connect", "dns", "file", "llm", "sec", "ssl",
                ]
                .into_iter()
                .enumerate()
                .map(|(index, name)| {
                    let count = drops_by_kind
                        .get(&(index as u32), 0)
                        .map(|values| values.iter().copied().sum())
                        .unwrap_or(0);
                    (name.to_string(), count)
                })
                .collect::<BTreeMap<String, u64>>();
                for (index, name) in [
                    (1, "exec_header"),
                    (2, "exec_chunk"),
                    (3, "exec_end"),
                    (4, "exec_commit"),
                    (5, "exec_compact"),
                ] {
                    let count = exec_part_drops
                        .get(&index, 0)
                        .map(|values| values.iter().copied().sum())
                        .unwrap_or(0);
                    dropped_by_kind.insert(name.to_string(), count);
                }
                emit_collector_heartbeat(
                    exporter.as_ref(),
                    &collector,
                    &stats,
                    CollectorHeartbeatRuntime {
                        interval_secs: 60,
                        dropped,
                        dropped_by_kind,
                        output_dropped,
                        output_dropped_by_kind: exporter.output_drops_by_kind(),
                        payload_capture_enabled,
                        payload_kill_switch_at_unix_nanos,
                        payload_fragments_discarded,
                    },
                );
                tracing::info!(
                    exec = stats.exec,
                    exec_truncated = stats.exec_truncated,
                    exec_incomplete = stats.exec_incomplete,
                    exec_reassembly_timeout = stats.exec_reassembly_timeout,
                    exit = stats.exit,
                    egress = stats.egress,
                    dns = stats.dns,
                    file = stats.file,
                    llm = stats.llm,
                    llm_response = stats.llm_response,
                    ssl = stats.ssl,
                    sec = stats.sec,
                    dropped,
                    ssl_dropped,
                    output_dropped,
                    ssl_record_parse_failed,
                    discard_empty_payload,
                    discard_op_not_allowed,
                    discard_native_gate,
                    pump_stashed = pump_stat(0),
                    jump_table_entries = jump_table.as_ref().map(|t| t.indices().count()).unwrap_or(0),
                    pump_tailcall_failed = pump_stat(1),
                    pump_stash_unavailable = pump_stat(2),
                    pump_entries = pump_stat(3),
                    pump_stash_missing = pump_stat(4),
                    pump_loop_failed = pump_stat(5),
                    pump_rechained = pump_stat(6),
                    pump_rechain_failed = pump_stat(7),
                    pump_hop_completed = pump_stat(8),
                    pump_emit_output_failed = pump_stat(9),
                    pump_scratch_unavailable = pump_stat(10),
                    pump_probe_read_failed = pump_stat(11),
                    pump_fastpath_calls = pump_stat(12),
                    pump_marker_sent = pump_stat(13),
                    pump_fastpath_incomplete = pump_stat(14),
                    pump_ceiling_clamped = pump_stat(15),
                    "a3s-observer: events in the last 60s (dropped = cumulative ring-full, \
                     output_dropped = slow-consumer backpressure)"
                );
                if let Some(pipeline) = interaction_pipeline.as_ref() {
                    let fixture = pipeline.stats();
                    tracing::info!(
                        fragments_observed = fixture.fragments_observed,
                        fragments_rejected = fixture.fragments_rejected,
                        calls_completed = fixture.calls_completed,
                        calls_incomplete = fixture.calls_incomplete,
                        calls_oversized = fixture.calls_oversized,
                        requests_completed = fixture.requests_completed,
                        requests_parsed = fixture.requests_parsed,
                        requests_ignored = fixture.requests_ignored,
                        parse_failed = fixture.parse_failed,
                        capacity_dropped = fixture.capacity_dropped,
                        native_fragments_observed = fixture.native_fragments_observed,
                        native_instructions_completed = fixture.native_instructions_completed,
                        native_instructions_incomplete = fixture.native_instructions_incomplete,
                        native_output_fragments_observed =
                            fixture.native_output_fragments_observed,
                        native_responses_completed = fixture.native_responses_completed,
                        native_responses_incomplete = fixture.native_responses_incomplete,
                        "isolated interaction fixture Loss Ledger counters"
                    );
                }
                if let Some(responses) = response_pipeline.as_ref() {
                    let response_stats = responses.stats();
                    tracing::info!(
                        fragments_observed = response_stats.fragments_observed,
                        fragments_rejected = response_stats.fragments_rejected,
                        calls_completed = response_stats.calls_completed,
                        calls_incomplete = response_stats.calls_incomplete,
                        responses_completed = response_stats.responses_completed,
                        responses_paired = response_stats.responses_paired,
                        responses_unpaired = response_stats.responses_unpaired,
                        responses_failed = response_stats.responses_failed,
                        interim_responses_skipped = response_stats.interim_responses_skipped,
                        parse_failed = response_stats.parse_failed,
                        capacity_dropped = response_stats.capacity_dropped,
                        responses_truncated = response_stats.responses_truncated,
                        responses_timeout = response_stats.responses_timeout,
                        "runtime response capture Loss Ledger counters"
                    );
                }
                stats = Stats::default();
            }
            _ = runtime_discovery_tick.tick(), if payload_capture_enabled
                && runtime_capture.as_ref().is_some_and(|runtime| runtime.auto_discover) => {
                if let Some(runtime) = runtime_capture.as_ref() {
                    match discover_codex_runtimes(&runtime.discovery) {
                        Ok(mut candidates) => {
                            match discover_a3s_runtimes(&runtime.discovery) {
                                Ok(a3s_candidates) => {
                                    if !a3s_candidates.is_empty() {
                                        tracing::info!(
                                            count = a3s_candidates.len(),
                                            "discovered A3S Code runtime candidates; Codex/rustls attach still requires matching PlaintextSink offsets (OpenSSL attach is a separate follow-on)"
                                        );
                                    }
                                    candidates.extend(a3s_candidates);
                                }
                                Err(error) => tracing::warn!(
                                    error = %error,
                                    "automatic A3S Code runtime reconciliation failed; will retry"
                                ),
                            }
                            match discover_claude_runtimes(&runtime.discovery) {
                                Ok(claude_candidates) => {
                                    if !claude_candidates.is_empty() {
                                        tracing::info!(
                                            count = claude_candidates.len(),
                                            "discovered Claude Code BoringSSL runtime candidates"
                                        );
                                    }
                                    candidates.extend(claude_candidates);
                                }
                                Err(error) => tracing::warn!(
                                    error = %error,
                                    "automatic Claude Code runtime reconciliation failed; will retry"
                                ),
                            }
                            match discover_kimi_runtimes(&runtime.discovery) {
                                Ok(kimi_candidates) => {
                                    if !kimi_candidates.is_empty() {
                                        tracing::info!(
                                            count = kimi_candidates.len(),
                                            "discovered kimi OpenSSL runtime candidates"
                                        );
                                    }
                                    candidates.extend(kimi_candidates);
                                }
                                Err(error) => tracing::warn!(
                                    error = %error,
                                    "automatic kimi runtime reconciliation failed; will retry"
                                ),
                            }
                            attach_discovered_runtime_candidates(
                                &mut ebpf,
                                runtime,
                                &mut runtime_probe_state,
                                &candidates,
                            );
                        }
                        Err(error) => tracing::warn!(
                            error = %error,
                            "automatic Codex runtime reconciliation failed; will retry"
                        ),
                    }
                }
            }
            // Bound the burst window so short-lived exec/exit records reach the durable lane
            // before a process-heavy workload can fill the rings.
            _ = tokio::time::sleep(Duration::from_millis(1)) => {
                let mut completed_execs = Vec::new();
                while let Some(item) = exec_ring.next() {
                    if let Some(record) = read_pod::<ExecRecord>(&item) {
                        completed_execs.extend(exec_assembler.push(record, Instant::now()));
                    }
                }
                while let Some(item) = exec_meta_ring.next() {
                    if let Some(record) = read_pod::<ExecRecord>(&item) {
                        completed_execs.extend(exec_assembler.push(record, Instant::now()));
                    }
                }
                completed_execs.extend(exec_assembler.expire(Instant::now()));
                for completed in completed_execs {
                    if completed.exec_confirmed && payload_capture_enabled {
                        if let Some(runtime) = runtime_capture.as_ref().filter(|runtime| runtime.auto_discover) {
                            if let Ok(candidate) = discover_codex_runtime_for_pid(
                                &runtime.discovery,
                                completed.pid,
                                false,
                            ) {
                                attach_discovered_runtime_candidates(
                                    &mut ebpf,
                                    runtime,
                                    &mut runtime_probe_state,
                                    &[candidate],
                                );
                            } else if let Ok(candidate) = discover_claude_runtime_for_pid(
                                &runtime.discovery,
                                completed.pid,
                                false,
                            ) {
                                attach_discovered_runtime_candidates(
                                    &mut ebpf,
                                    runtime,
                                    &mut runtime_probe_state,
                                    &[candidate],
                                );
                            } else if let Ok(candidate) = discover_kimi_runtime_for_pid(
                                &runtime.discovery,
                                completed.pid,
                                false,
                            ) {
                                attach_discovered_runtime_candidates(
                                    &mut ebpf,
                                    runtime,
                                    &mut runtime_probe_state,
                                    &[candidate],
                                );
                            }
                        }
                    }
                    emit_completed_exec(exporter.as_ref(), &mut stats, &resolver, completed);
                }
                while let Some(item) = sec_ring.next() {
                    if let Some(ev) = read_pod::<SecEvent>(&item) {
                        let kind = match ev.kind {
                            SEC_SETUID => "setuid-root",
                            SEC_PTRACE => "ptrace",
                            SEC_BIND => "bind",
                            _ => continue,
                        };
                        emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                            identity: identity_for(&resolver, ev.pid, ev.cgroup_id, &ev.comm),
                            workload: resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
                            observation: None,
                            process: Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
                            provider: None,
                            event: AgentEvent::SecurityAction {
                                pid: ev.pid,
                                kind,
                                detail: ev.detail,
                            },
                        });
                    }
                }
                // Drain connect BEFORE tls so a same-poll ClientHello finds its peer.
                while let Some(item) = connect_ring.next() {
                    if let Some(ev) = read_pod::<ConnectEvent>(&item) {
                        let peer = peer_ip(&ev);
                        if peers.len() > 8192 {
                            peers.clear(); // ponytail: crude cap; LRU if it ever matters
                        }
                        peers.insert(sock_key(ev.pid, ev.fd), (peer, ev.port));
                        emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                            identity: identity_for(&resolver, ev.pid, ev.cgroup_id, &ev.comm),
                            workload: resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
                            observation: None,
                            process: Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
                            provider: None,
                            event: AgentEvent::Egress {
                                pid: ev.pid,
                                sni: None,
                                peer,
                                port: ev.port,
                                bytes: 0,
                            },
                        });
                    }
                }
                while let Some(item) = tls_ring.next() {
                    if let Some(ev) = read_pod::<TlsEvent>(&item) {
                        let len = (ev.len as usize).min(ev.data.len());
                        let sni = parse_sni(&ev.data[..len]);
                        // Correlated peer for this socket (the LLM endpoint).
                        let (peer, port) = peers
                            .get(&sock_key(ev.pid, ev.fd))
                            .copied()
                            .unwrap_or((UNKNOWN_PEER, 0));
                        let provider =
                            sni.as_deref().and_then(|h| classifier.classify(Some(h), peer));
                        // Remember the call so the close event can build a metric-bearing
                        // LlmCall. Bounded; entries are normally removed on close.
                        if llm_meta.len() > 16384 {
                            llm_meta.clear(); // ponytail: crude cap; LRU if it ever matters
                        }
                        llm_meta.insert(sock_key(ev.pid, ev.fd), (sni.clone(), provider.clone(), peer));
                        emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                            identity: identity_for(&resolver, ev.pid, ev.cgroup_id, &ev.comm),
                            workload: resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
                            observation: None,
                            process: Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
                            provider,
                            event: AgentEvent::Egress {
                                pid: ev.pid,
                                sni,
                                peer,
                                port,
                                bytes: ev.len as u64,
                            },
                        });
                    }
                }
                while let Some(item) = dns_ring.next() {
                    if let Some(ev) = read_pod::<DnsEvent>(&item) {
                        let len = (ev.len as usize).min(ev.data.len());
                        if let Some(query) = parse_dns_qname(&ev.data[..len]) {
                            emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                                identity: identity_for(&resolver, ev.pid, ev.cgroup_id, &ev.comm),
                                workload: resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
                                observation: None,
                                process: Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
                                provider: None,
                                event: AgentEvent::Dns { pid: ev.pid, query },
                            });
                        }
                    }
                }
                while let Some(item) = file_ring.next() {
                    if let Some(ev) = read_pod::<FileEvent>(&item) {
                        let path = cstr(&ev.path);
                        if !path.is_empty()
                            && (file_include_paths.is_empty()
                                || file_include_paths
                                    .iter()
                                    .any(|prefix| path_matches_include(&path, prefix)))
                        {
                            if file_coalesce_ms > 0 {
                                let now_ms = unix_millis_now();
                                let key = file_coalesce_key(ev.pid, ev.flags, &path);
                                let is_repeat = file_coalesce_cache
                                    .get(&key)
                                    .is_some_and(|last| now_ms.saturating_sub(*last) < file_coalesce_ms);
                                if is_repeat {
                                    stats.file_coalesced += 1;
                                    continue;
                                }
                                if file_coalesce_cache.len() >= 16_384 {
                                    file_coalesce_cache.clear();
                                }
                                file_coalesce_cache.insert(key, now_ms);
                            }
                            // Same ring carries opens, deletes and rename destinations — the
                            // sentinel flag tells them apart. A rename destination is a write
                            // signal for the "which files did the workload modify" question.
                            let event = if ev.flags == FILE_DELETE_FLAG {
                                AgentEvent::FileDelete { pid: ev.pid, path }
                            } else {
                                AgentEvent::FileAccess {
                                    pid: ev.pid,
                                    path,
                                    write: ev.flags == FILE_RENAME_FLAG || ev.flags & 0x3 != 0,
                                }
                            };
                            emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                                identity: identity_for(&resolver, ev.pid, ev.cgroup_id, &ev.comm),
                                workload: resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
                                observation: None,
                                process: Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
                                provider: None,
                                event,
                            });
                        }
                    }
                }
                while let Some(item) = llm_ring.next() {
                    if let Some(ev) = read_pod::<LlmEvent>(&item) {
                        // Join the kernel's byte/timing metrics with the SNI/provider/peer
                        // recorded at ClientHello. Only provider-identified calls → LlmCall.
                        if let Some((sni, provider, peer)) =
                            llm_meta.remove(&sock_key(ev.pid, ev.fd))
                        {
                            if provider.is_some() {
                                let observed_at_unix_nanos = unix_nanos_now();
                                emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                                    identity: identity_for(&resolver, ev.pid, ev.cgroup_id, &ev.comm),
                                    workload: resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
                                    observation: ObservationMetadata::fresh(
                                        observed_at_unix_nanos,
                                        observed_at_unix_nanos,
                                        None,
                                    ).ok(),
                                    process: Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
                                    provider,
                                    event: AgentEvent::LlmCall {
                                        pid: ev.pid,
                                        sni,
                                        peer,
                                        req_bytes: ev.req_bytes,
                                        resp_bytes: ev.resp_bytes,
                                        latency: Duration::from_nanos(ev.latency_ns),
                                        ttft: (ev.ttft_ns > 0)
                                            .then(|| Duration::from_nanos(ev.ttft_ns)),
                                        capture_mode: "metadata",
                                        capture_completeness: "unavailable",
                                        parse_status: "not_attempted",
                                        raw_retention_state: "not_retained",
                                        presentation_state: "metadata_only",
                                        timing_scope: "connection",
                                        latency_availability: "available",
                                        ttft_availability: if ev.ttft_ns > 0 {
                                            "available"
                                        } else {
                                            "unavailable"
                                        },
                                    },
                                });
                            }
                        }
                    }
                }
                while let Some(item) = ssl_ring.next() {
                    let parsed = read_ssl_fragment(&item);
                    if parsed.is_none() {
                        ssl_record_parse_failed = ssl_record_parse_failed.saturating_add(1);
                    }
                    if let Some((ev, payload)) = parsed {
                        if !payload_capture_enabled {
                            payload_fragments_discarded =
                                payload_fragments_discarded.saturating_add(1);
                            continue;
                        }
                        if matches!(
                            ev.operation,
                            CONTENT_OPERATION_NATIVE_STDIN_READ
                                | CONTENT_OPERATION_NATIVE_STDIN_EOF
                        ) {
                            if !fixture_native_stdin {
                                payload_fragments_discarded =
                                    payload_fragments_discarded.saturating_add(1);
                                discard_native_gate = discard_native_gate.saturating_add(1);
                                continue;
                            }
                            let eof = ev.operation == CONTENT_OPERATION_NATIVE_STDIN_EOF;
                            if !eof && payload.is_empty() {
                                payload_fragments_discarded =
                                    payload_fragments_discarded.saturating_add(1);
                                continue;
                            }
                            let comm = cstr(&ev.comm);
                            let result = interaction_pipeline
                                .as_mut()
                                .context(
                                    "fixture pipeline unavailable while native stdin capture is enabled",
                                )?
                                .push_native_input(
                                    FixtureNativeInput {
                                        pid: ev.pid,
                                        tid: ev.tid,
                                        fd: ev.ssl_pointer.saturating_sub(1) as u32,
                                        observed_at_monotonic_ns: ev.observed_at_monotonic_ns,
                                        eof,
                                        truncated: ev.truncated != 0,
                                        comm: &comm,
                                        bytes: payload,
                                    },
                                    Instant::now(),
                                );
                            if let Err(error) = result {
                                content_capture_enabled.set(0, 0, 0)?;
                                payload_capture_enabled = false;
                                payload_kill_switch_at_unix_nanos = Some(unix_nanos_now());
                                if let Some(pipeline) = interaction_pipeline.as_mut() {
                                    pipeline.clear_plaintext();
                                }
                                if let Some(responses) = response_pipeline.as_mut() {
                                    responses.clear_plaintext();
                                }
                                tracing::error!(
                                    error = %error,
                                    "isolated native stdin fixture failed; payload capture failed closed"
                                );
                            }
                            continue;
                        }
                        if matches!(
                            ev.operation,
                            CONTENT_OPERATION_NATIVE_STDOUT_WRITE
                                | CONTENT_OPERATION_NATIVE_STDOUT_EOF
                        ) {
                            if !fixture_native_stdout {
                                payload_fragments_discarded =
                                    payload_fragments_discarded.saturating_add(1);
                                discard_native_gate = discard_native_gate.saturating_add(1);
                                continue;
                            }
                            let eof = ev.operation == CONTENT_OPERATION_NATIVE_STDOUT_EOF;
                            if !eof && payload.is_empty() {
                                payload_fragments_discarded =
                                    payload_fragments_discarded.saturating_add(1);
                                continue;
                            }
                            let comm = cstr(&ev.comm);
                            let result = interaction_pipeline
                                .as_mut()
                                .context(
                                    "fixture pipeline unavailable while native stdout capture is enabled",
                                )?
                                .push_native_output(
                                    FixtureNativeOutput {
                                        pid: ev.pid,
                                        tid: ev.tid,
                                        fd: ev.ssl_pointer.saturating_sub(1) as u32,
                                        observed_at_monotonic_ns: ev.observed_at_monotonic_ns,
                                        eof,
                                        truncated: ev.truncated != 0,
                                        comm: &comm,
                                        bytes: payload,
                                    },
                                    Instant::now(),
                                );
                            if let Err(error) = result {
                                content_capture_enabled.set(0, 0, 0)?;
                                payload_capture_enabled = false;
                                payload_kill_switch_at_unix_nanos = Some(unix_nanos_now());
                                if let Some(pipeline) = interaction_pipeline.as_mut() {
                                    pipeline.clear_plaintext();
                                }
                                if let Some(responses) = response_pipeline.as_mut() {
                                    responses.clear_plaintext();
                                }
                                tracing::error!(
                                    error = %error,
                                    "isolated native stdout fixture failed; payload capture failed closed"
                                );
                            }
                            continue;
                        }
                        if payload.is_empty() && ev.truncated == 0 {
                            payload_fragments_discarded =
                                payload_fragments_discarded.saturating_add(1);
                            discard_empty_payload = discard_empty_payload.saturating_add(1);
                            continue;
                        }
                        let kimi_read = matches!(
                            ev.operation,
                            SSL_OPERATION_READ | SSL_OPERATION_READ_EX
                        ) && capture_config.mode == InteractionCaptureMode::RuntimePayload
                            && runtime_probe_state.kimi_pids.contains(&ev.pid);
                        let runtime_operation = matches!(
                            ev.operation,
                            CONTENT_OPERATION_CODEX_RUSTLS_WRITE
                                | CONTENT_OPERATION_CODEX_RUSTLS_WRITEV
                                | SSL_OPERATION_WRITE
                        ) || kimi_read;
                        let fixture_operation = matches!(
                            ev.operation,
                            SSL_OPERATION_READ
                                | SSL_OPERATION_READ_EX
                                | SSL_OPERATION_WRITE
                                | SSL_OPERATION_WRITE_EX
                                | SSL_OPERATION_WRITE_EX2
                        );
                        let operation_allowed = match capture_config.mode {
                            InteractionCaptureMode::RuntimePayload => runtime_operation,
                            InteractionCaptureMode::FixturePayload => fixture_operation,
                            InteractionCaptureMode::Off | InteractionCaptureMode::Metadata => false,
                        };
                        if !operation_allowed {
                            payload_fragments_discarded =
                                payload_fragments_discarded.saturating_add(1);
                            discard_op_not_allowed = discard_op_not_allowed.saturating_add(1);
                            continue;
                        }
                        let is_read = matches!(
                            ev.operation,
                            SSL_OPERATION_READ | SSL_OPERATION_READ_EX
                        );
                        stats.ssl = stats.ssl.saturating_add(1);
                        if is_read && capture_config.mode == InteractionCaptureMode::RuntimePayload
                        {
                            // kimi-only response lane (the operation gate above rejects
                            // non-kimi reads in this mode). The response pipeline performs no
                            // I/O and is infallible; parse-level failures are accounted in its
                            // Loss Ledger counters instead of killing capture.
                            if let Some(responses) = response_pipeline.as_mut() {
                                responses.push_read(
                                    ReadFragment {
                                        pid: ev.pid,
                                        tid: ev.tid,
                                        ssl_pointer: ev.ssl_pointer,
                                        call_sequence: ev.call_sequence,
                                        fragment_index: ev.fragment_index,
                                        fragment_offset: ev.fragment_offset,
                                        original_length: ev.original_len,
                                        observed_at_monotonic_ns: ev.observed_at_monotonic_ns,
                                        truncated: ev.truncated != 0,
                                        bytes: payload,
                                    },
                                    Instant::now(),
                                );
                                let response_observations = responses.take_observations();
                                for observation in response_observations {
                                    emit_observed_llm_response(
                                        exporter.as_ref(),
                                        &mut stats,
                                        &resolver,
                                        runtime_capture_profile,
                                        observation,
                                    );
                                }
                            }
                            continue;
                        }
                        let result = interaction_pipeline
                            .as_mut()
                            .context("interaction pipeline unavailable while payload capture is enabled")
                            .and_then(|pipeline| {
                                pipeline.push(
                                    FixtureFragment {
                                        pid: ev.pid,
                                        tid: ev.tid,
                                        ssl_pointer: ev.ssl_pointer,
                                        call_sequence: ev.call_sequence,
                                        fragment_index: ev.fragment_index,
                                        fragment_offset: ev.fragment_offset,
                                        original_length: ev.original_len,
                                        observed_at_monotonic_ns: ev.observed_at_monotonic_ns,
                                        is_read,
                                        truncated: ev.truncated != 0,
                                        bytes: payload,
                                    },
                                    Instant::now(),
                                )?;
                                Ok(pipeline.take_observations())
                            });
                        match result {
                            Ok(observations) => {
                                for observation in observations {
                                    // Pairing hook for the kimi response lane: the completing
                                    // write fragment's ssl_pointer is the connection, and its
                                    // monotonic timestamp is the send-complete time.
                                    if runtime_probe_state.kimi_pids.contains(&ev.pid) {
                                        if let Some(responses) = response_pipeline.as_mut() {
                                            responses.register_request(
                                                ev.pid,
                                                ev.ssl_pointer,
                                                RequestContext {
                                                    host: observation.host.clone(),
                                                    path: observation.path.clone(),
                                                    endpoint_attribution: observation
                                                        .endpoint_attribution
                                                        .clone(),
                                                    provider: observation.provider.clone(),
                                                    model: observation.model.clone(),
                                                    sent_at_monotonic_ns: ev
                                                        .observed_at_monotonic_ns,
                                                    cgroup_id: ev.cgroup_id,
                                                    comm: ev.comm,
                                                },
                                                Instant::now(),
                                            );
                                        }
                                    }
                                    emit_observed_llm_request(
                                        exporter.as_ref(),
                                        &mut stats,
                                        &resolver,
                                        ev.cgroup_id,
                                        &ev.comm,
                                        observation,
                                        runtime_capture_profile,
                                        if ev.operation == SSL_OPERATION_WRITE {
                                            if runtime_probe_state.kimi_pids.contains(&ev.pid) {
                                                "ebpf_openssl"
                                            } else {
                                                "ebpf_boringssl"
                                            }
                                        } else {
                                            "ebpf_rustls"
                                        },
                                    );
                                }
                            }
                            Err(error) => {
                                content_capture_enabled.set(0, 0, 0)?;
                                payload_capture_enabled = false;
                                payload_kill_switch_at_unix_nanos = Some(unix_nanos_now());
                                if let Some(pipeline) = interaction_pipeline.as_mut() {
                                    pipeline.clear_plaintext();
                                }
                                if let Some(responses) = response_pipeline.as_mut() {
                                    responses.clear_plaintext();
                                }
                                tracing::error!(
                                    error = %error,
                                    "interaction request pipeline failed; payload capture failed closed"
                                );
                            }
                        }
                    }
                }
                // Exit is drained last so downstream process caches can attribute all prior
                // exec, file, network and security events before the PID lifecycle closes.
                while let Some(item) = exit_ring.next() {
                    if let Some(ev) = read_pod::<ExitEvent>(&item) {
                        emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                            identity: identity_for(&resolver, ev.pid, ev.cgroup_id, &ev.comm),
                            workload: resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
                            observation: None,
                            process: Some(exit_process_context(&ev)),
                            provider: None,
                            event: AgentEvent::ProcessExit {
                                pid: ev.pid,
                                exit_code: ev.exit_code,
                                signal: ev.signal,
                            },
                        });
                        if let Some(pipeline) = interaction_pipeline.as_mut() {
                            if let Err(error) = pipeline.forget_pid(ev.pid) {
                                content_capture_enabled.set(0, 0, 0)?;
                                payload_capture_enabled = false;
                                payload_kill_switch_at_unix_nanos = Some(unix_nanos_now());
                                pipeline.clear_plaintext();
                                tracing::error!(error = %error,
                                    "interaction process-exit cleanup failed; payload capture failed closed");
                            }
                        }
                        // Finalize any in-flight kimi response streams (abort/cancel lane).
                        if let Some(responses) = response_pipeline.as_mut() {
                            responses.forget_pid(ev.pid);
                            let finalized = responses.take_observations();
                            for observation in finalized {
                                emit_observed_llm_response(
                                    exporter.as_ref(),
                                    &mut stats,
                                    &resolver,
                                    runtime_capture_profile,
                                    observation,
                                );
                            }
                        }
                        runtime_probe_state.kimi_pids.remove(&ev.pid);
                        forget_process_context(ev.pid);
                    }
                }
            }
        }
    }
    let dropped: u64 = drops
        .get(&0, 0)
        .map(|v| v.iter().copied().sum())
        .unwrap_or(0);
    let ssl_dropped: u64 = ssl_drops
        .get(&0, 0)
        .map(|v| v.iter().copied().sum())
        .unwrap_or(0);
    let output_dropped = exporter.output_drops();
    let fixture = interaction_pipeline
        .as_ref()
        .map(FixturePipeline::stats)
        .unwrap_or_default();
    let response = response_pipeline
        .as_ref()
        .map(ResponsePipeline::stats)
        .unwrap_or_default();
    let (process_cache_entries, process_cache_hits, process_cache_misses) = process_context_cache()
        .lock()
        .map(|cache| (cache.entries.len(), cache.hits, cache.misses))
        .unwrap_or_default();
    tracing::info!(
        exec = stats.exec,
        exec_truncated = stats.exec_truncated,
        exec_incomplete = stats.exec_incomplete,
        exec_reassembly_timeout = stats.exec_reassembly_timeout,
        exit = stats.exit,
        egress = stats.egress,
        dns = stats.dns,
        file = stats.file,
        llm = stats.llm,
        llm_response = stats.llm_response,
        ssl = stats.ssl,
        sec = stats.sec,
        dropped,
        ssl_dropped,
        output_dropped,
        fixture_fragments_observed = fixture.fragments_observed,
        fixture_fragments_rejected = fixture.fragments_rejected,
        fixture_calls_completed = fixture.calls_completed,
        fixture_calls_incomplete = fixture.calls_incomplete,
        fixture_calls_oversized = fixture.calls_oversized,
        fixture_requests_completed = fixture.requests_completed,
        fixture_requests_parsed = fixture.requests_parsed,
        fixture_requests_ignored = fixture.requests_ignored,
        fixture_parse_failed = fixture.parse_failed,
        fixture_capacity_dropped = fixture.capacity_dropped,
        fixture_native_fragments_observed = fixture.native_fragments_observed,
        fixture_native_instructions_completed = fixture.native_instructions_completed,
        fixture_native_instructions_incomplete = fixture.native_instructions_incomplete,
        fixture_native_output_fragments_observed = fixture.native_output_fragments_observed,
        fixture_native_responses_completed = fixture.native_responses_completed,
        fixture_native_responses_incomplete = fixture.native_responses_incomplete,
        response_fragments_observed = response.fragments_observed,
        response_calls_completed = response.calls_completed,
        response_calls_incomplete = response.calls_incomplete,
        response_responses_completed = response.responses_completed,
        response_responses_paired = response.responses_paired,
        response_responses_unpaired = response.responses_unpaired,
        response_responses_failed = response.responses_failed,
        response_interim_responses_skipped = response.interim_responses_skipped,
        response_parse_failed = response.parse_failed,
        response_capacity_dropped = response.capacity_dropped,
        response_responses_truncated = response.responses_truncated,
        response_responses_timeout = response.responses_timeout,
        process_cache_entries,
        process_cache_hits,
        process_cache_misses,
        "a3s-observer-collector: stopped (final window)"
    );
    Ok(())
}

// ponytail: peer IP arrives with the flow probe (#5); SNI alone identifies the provider.
const UNKNOWN_PEER: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

fn attach(ebpf: &mut Ebpf, prog: &str, category: &str, name: &str) -> anyhow::Result<()> {
    let p: &mut TracePoint = ebpf
        .program_mut(prog)
        .with_context(|| format!("`{prog}` program not found"))?
        .try_into()?;
    p.load()?;
    p.attach(category, name)
        .with_context(|| format!("attach {category}:{name}"))?;
    Ok(())
}

fn attach_kprobe(ebpf: &mut Ebpf, prog: &str, sym: &str) -> anyhow::Result<()> {
    let p: &mut KProbe = ebpf
        .program_mut(prog)
        .with_context(|| format!("`{prog}` program not found"))?
        .try_into()?;
    p.load()?;
    p.attach(sym, 0)
        .with_context(|| format!("attach kprobe {sym}"))?;
    Ok(())
}

fn attach_uprobe(
    ebpf: &mut Ebpf,
    prog: &str,
    sym: &str,
    target: &str,
    target_pids: &[u32],
) -> anyhow::Result<()> {
    if target_pids.is_empty() {
        anyhow::bail!("refusing to attach a payload uprobe without explicit target PIDs");
    }
    let p: &mut UProbe = ebpf
        .program_mut(prog)
        .with_context(|| format!("`{prog}` program not found"))?
        .try_into()?;
    p.load()?;
    for pid in target_pids {
        p.attach(Some(sym), 0, target, Some(*pid as i32))
            .with_context(|| format!("attach uprobe {sym} in {target} to PID {pid}"))?;
    }
    Ok(())
}

#[derive(Default)]
struct RuntimeProbeState {
    attached_binaries: HashSet<RuntimeFileIdentity>,
    unsupported_binaries: HashSet<RuntimeFileIdentity>,
    attached_links: usize,
    // PIDs observed executing a kimi-attached inode, so their SSL_write/SSL_read fragments are
    // labeled ebpf_openssl instead of the BoringSSL default, and their read fragments are allowed
    // into the response-direction pipeline. New PIDs arrive through the exec fast path and
    // periodic reconciliation even when their inode was attached earlier.
    kimi_pids: HashSet<u32>,
}

fn load_uprobe_program(ebpf: &mut Ebpf, prog: &str) -> anyhow::Result<()> {
    let p: &mut UProbe = ebpf
        .program_mut(prog)
        .with_context(|| format!("`{prog}` program not found"))?
        .try_into()?;
    p.load().with_context(|| format!("load uprobe {prog}"))
}

// The fragment pump runs only via bpf_tail_call from the SSL emit path; after the program is
// loaded (next to the other payload programs), publish its fd through the SSL_FRAGMENT_PUMPS
// jump table. Never attached to any hook. The caller MUST keep the returned table alive for the
// collector's lifetime: with the last handle dropped, the slot no longer resolved at runtime
// (observed on 6.17) and every tail call fell through, silently dropping all oversized calls.
fn populate_ssl_fragment_pump(ebpf: &mut Ebpf) -> anyhow::Result<ProgramArray<aya::maps::MapData>> {
    let mut pumps = ProgramArray::try_from(
        ebpf.take_map("SSL_FRAGMENT_PUMPS")
            .context("`SSL_FRAGMENT_PUMPS` missing")?,
    )?;
    let p: &mut UProbe = ebpf
        .program_mut("ssl_fragment_pump")
        .context("`ssl_fragment_pump` program not found")?
        .try_into()?;
    let pump_fd = p.fd().context("ssl_fragment_pump fd")?.as_fd().as_raw_fd();
    pumps
        .set(0, p.fd().context("ssl_fragment_pump fd")?, 0)
        .context("populate SSL_FRAGMENT_PUMPS jump table")?;
    let filled = pumps.indices().count();
    tracing::warn!(
        pump_fd,
        table_entries = filled,
        "SSL_FRAGMENT_PUMPS jump table populated"
    );
    Ok(pumps)
}

fn attach_loaded_uprobe_offsets(
    ebpf: &mut Ebpf,
    prog: &str,
    target: &Path,
    target_pids: &[u32],
    offsets: &[RustlsOffset],
    exact_binary_all_processes: bool,
) -> anyhow::Result<usize> {
    if exact_binary_all_processes && !target_pids.is_empty() {
        anyhow::bail!(
            "refusing ambiguous runtime payload scope: exact-binary auto-discovery cannot include target PIDs"
        );
    }
    if !exact_binary_all_processes && target_pids.is_empty() {
        anyhow::bail!(
            "refusing to attach a runtime payload uprobe without exact target PIDs or exact-binary auto-discovery"
        );
    }
    if offsets.is_empty() {
        return Ok(0);
    }
    let p: &mut UProbe = ebpf
        .program_mut(prog)
        .with_context(|| format!("`{prog}` program not found"))?
        .try_into()?;
    let mut attached = 0usize;
    if exact_binary_all_processes {
        for offset in offsets {
            match p.attach(None, offset.file_offset, target, None) {
                Ok(_) => attached = attached.saturating_add(1),
                Err(error) => tracing::warn!(
                    probe = prog,
                    binary = %target.display(),
                    file_offset = format_args!("0x{:x}", offset.file_offset),
                    error = %error,
                    "runtime plaintext uprobe link failed"
                ),
            }
        }
        return Ok(attached);
    }
    for pid in target_pids {
        for offset in offsets {
            match p.attach(None, offset.file_offset, target, Some(*pid as i32)) {
                Ok(_) => attached = attached.saturating_add(1),
                Err(error) => tracing::warn!(
                    probe = prog,
                    binary = %target.display(),
                    file_offset = format_args!("0x{:x}", offset.file_offset),
                    pid,
                    error = %error,
                    "runtime plaintext exact-PID uprobe link failed"
                ),
            }
        }
    }
    Ok(attached)
}

fn attach_discovered_runtime_candidates(
    ebpf: &mut Ebpf,
    runtime: &RuntimeCaptureConfig,
    state: &mut RuntimeProbeState,
    candidates: &[RuntimeBinaryCandidate],
) -> usize {
    let mut newly_attached = 0usize;
    for candidate in candidates {
        if state.attached_binaries.contains(&candidate.identity) {
            if candidate.source.starts_with("kimi_") {
                state.kimi_pids.extend(candidate.pids.iter().copied());
            }
            continue;
        }
        if state.unsupported_binaries.contains(&candidate.identity) {
            continue;
        }
        if candidate.source.starts_with("kimi_") {
            let offsets = match resolve_openssl_ssl_offsets(&candidate.attach_path) {
                Ok(offsets) => offsets,
                Err(error) => {
                    state.unsupported_binaries.insert(candidate.identity);
                    tracing::warn!(
                        binary = %candidate.logical_path.display(),
                        attach_path = %candidate.attach_path.display(),
                        source = candidate.source,
                        error = %error,
                        "kimi runtime did not expose the expected OpenSSL symbols"
                    );
                    continue;
                }
            };
            let target_pids = if runtime.auto_discover {
                &[][..]
            } else {
                candidate.pids.as_slice()
            };
            let write_offset = [RustlsOffset {
                file_offset: offsets.ssl_write,
                vectored: false,
            }];
            let read_offset = [RustlsOffset {
                file_offset: offsets.ssl_read,
                vectored: false,
            }];
            let enter_links = attach_loaded_uprobe_offsets(
                ebpf,
                "ssl_write_enter",
                &candidate.attach_path,
                target_pids,
                &write_offset,
                runtime.auto_discover,
            )
            .unwrap_or_else(|error| {
                tracing::warn!(error = %error, "kimi OpenSSL SSL_write entry attach failed");
                0
            });
            let exit_links = attach_loaded_uprobe_offsets(
                ebpf,
                "ssl_write_exit",
                &candidate.attach_path,
                target_pids,
                &write_offset,
                runtime.auto_discover,
            )
            .unwrap_or_else(|error| {
                tracing::warn!(error = %error, "kimi OpenSSL SSL_write return attach failed");
                0
            });
            if enter_links == 0 || exit_links == 0 {
                tracing::error!(
                    binary = %candidate.logical_path.display(),
                    enter_links,
                    exit_links,
                    "kimi OpenSSL requires both entry and return probes; capture remains unavailable"
                );
                continue;
            }
            // Response direction: SSL_read entry/return at the symtab-resolved offset. A read
            // attach failure degrades the lane to request-only instead of killing capture.
            let read_enter_links = attach_loaded_uprobe_offsets(
                ebpf,
                "ssl_read_enter",
                &candidate.attach_path,
                target_pids,
                &read_offset,
                runtime.auto_discover,
            )
            .unwrap_or_else(|error| {
                tracing::warn!(error = %error, "kimi OpenSSL SSL_read entry attach failed");
                0
            });
            let read_exit_links = attach_loaded_uprobe_offsets(
                ebpf,
                "ssl_read_exit",
                &candidate.attach_path,
                target_pids,
                &read_offset,
                runtime.auto_discover,
            )
            .unwrap_or_else(|error| {
                tracing::warn!(error = %error, "kimi OpenSSL SSL_read return attach failed");
                0
            });
            if read_enter_links == 0 || read_exit_links == 0 {
                tracing::warn!(
                    binary = %candidate.logical_path.display(),
                    read_enter_links,
                    read_exit_links,
                    "kimi OpenSSL response-direction probes unavailable; request capture continues"
                );
            }
            let candidate_links = enter_links
                .saturating_add(exit_links)
                .saturating_add(read_enter_links)
                .saturating_add(read_exit_links);
            state.attached_binaries.insert(candidate.identity);
            state.kimi_pids.extend(candidate.pids.iter().copied());
            state.attached_links = state.attached_links.saturating_add(candidate_links);
            newly_attached = newly_attached.saturating_add(candidate_links);
            tracing::warn!(
                binary = %candidate.logical_path.display(),
                attach_path = %candidate.attach_path.display(),
                source = candidate.source,
                ssl_write_offset = format_args!("0x{:x}", offsets.ssl_write),
                ssl_read_offset = format_args!("0x{:x}", offsets.ssl_read),
                target_pids = ?candidate.pids,
                auto_discover = runtime.auto_discover,
                attached_links = candidate_links,
                provider_hosts = ?runtime.provider_hosts,
                "SENSITIVE CAPTURE: AnySentry kimi/OpenSSL request/response probes attached"
            );
            continue;
        }
        if candidate.source.starts_with("claude_") {
            let offsets = match scan_claude_boringssl(&candidate.attach_path) {
                Ok(offsets) => offsets,
                Err(error) => {
                    state.unsupported_binaries.insert(candidate.identity);
                    tracing::warn!(
                        binary = %candidate.logical_path.display(),
                        attach_path = %candidate.attach_path.display(),
                        source = candidate.source,
                        error = %error,
                        "Claude Code runtime did not match the supported BoringSSL signatures"
                    );
                    continue;
                }
            };
            let target_pids = if runtime.auto_discover {
                &[][..]
            } else {
                candidate.pids.as_slice()
            };
            let write_offset = [RustlsOffset {
                file_offset: offsets.ssl_write,
                vectored: false,
            }];
            let enter_links = attach_loaded_uprobe_offsets(
                ebpf,
                "ssl_write_enter",
                &candidate.attach_path,
                target_pids,
                &write_offset,
                runtime.auto_discover,
            )
            .unwrap_or_else(|error| {
                tracing::warn!(error = %error, "Claude BoringSSL SSL_write entry attach failed");
                0
            });
            let exit_links = attach_loaded_uprobe_offsets(
                ebpf,
                "ssl_write_exit",
                &candidate.attach_path,
                target_pids,
                &write_offset,
                runtime.auto_discover,
            )
            .unwrap_or_else(|error| {
                tracing::warn!(error = %error, "Claude BoringSSL SSL_write return attach failed");
                0
            });
            if enter_links == 0 || exit_links == 0 {
                tracing::error!(
                    binary = %candidate.logical_path.display(),
                    enter_links,
                    exit_links,
                    "Claude BoringSSL requires both entry and return probes; capture remains unavailable"
                );
                continue;
            }
            let candidate_links = enter_links.saturating_add(exit_links);
            state.attached_binaries.insert(candidate.identity);
            state.attached_links = state.attached_links.saturating_add(candidate_links);
            newly_attached = newly_attached.saturating_add(candidate_links);
            tracing::warn!(
                binary = %candidate.logical_path.display(),
                attach_path = %candidate.attach_path.display(),
                source = candidate.source,
                ssl_write_offset = format_args!("0x{:x}", offsets.ssl_write),
                ssl_read_offset = format_args!("0x{:x}", offsets.ssl_read),
                target_pids = ?candidate.pids,
                auto_discover = runtime.auto_discover,
                attached_links = candidate_links,
                provider_hosts = ?runtime.provider_hosts,
                "SENSITIVE CAPTURE: AnySentry Claude/BoringSSL request probes attached"
            );
            continue;
        }
        let offsets = match scan_codex_rustls(&candidate.attach_path) {
            Ok(offsets) => offsets,
            Err(error) => {
                state.unsupported_binaries.insert(candidate.identity);
                if candidate.source.starts_with("a3s_") {
                    tracing::warn!(
                        binary = %candidate.logical_path.display(),
                        attach_path = %candidate.attach_path.display(),
                        source = candidate.source,
                        pids = ?candidate.pids,
                        error = %error,
                        "A3S Code runtime discovered but Codex/rustls PlaintextSink offsets are absent; OpenSSL SSL_write* runtime_payload attach is not enabled yet"
                    );
                } else {
                    tracing::warn!(
                        binary = %candidate.logical_path.display(),
                        attach_path = %candidate.attach_path.display(),
                        source = candidate.source,
                        device = candidate.identity.device,
                        inode = candidate.identity.inode,
                        error = %error,
                        "runtime candidate is not a supported Codex/rustls build"
                    );
                }
                continue;
            }
        };
        let scalar = offsets
            .iter()
            .copied()
            .filter(|offset| !offset.vectored)
            .collect::<Vec<_>>();
        let vectored = offsets
            .iter()
            .copied()
            .filter(|offset| offset.vectored)
            .collect::<Vec<_>>();
        let target_pids = if runtime.auto_discover {
            &[][..]
        } else {
            candidate.pids.as_slice()
        };
        let mut candidate_links = 0usize;
        if !scalar.is_empty() {
            candidate_links = candidate_links.saturating_add(
                attach_loaded_uprobe_offsets(
                    ebpf,
                    "codex_rustls_write",
                    &candidate.attach_path,
                    target_pids,
                    &scalar,
                    runtime.auto_discover,
                )
                .unwrap_or_else(|error| {
                    tracing::warn!(error = %error, "scalar runtime uprobe attachment failed");
                    0
                }),
            );
        }
        if !vectored.is_empty() {
            candidate_links = candidate_links.saturating_add(
                attach_loaded_uprobe_offsets(
                    ebpf,
                    "codex_rustls_write_vectored",
                    &candidate.attach_path,
                    target_pids,
                    &vectored,
                    runtime.auto_discover,
                )
                .unwrap_or_else(|error| {
                    tracing::warn!(error = %error, "vectored runtime uprobe attachment failed");
                    0
                }),
            );
        }
        if candidate_links == 0 {
            tracing::warn!(
                binary = %candidate.logical_path.display(),
                attach_path = %candidate.attach_path.display(),
                pids = ?candidate.pids,
                "supported Codex runtime was found, but no plaintext uprobe link attached"
            );
            continue;
        }
        state.attached_binaries.insert(candidate.identity);
        state.attached_links = state.attached_links.saturating_add(candidate_links);
        newly_attached = newly_attached.saturating_add(candidate_links);
        tracing::warn!(
            binary = %candidate.logical_path.display(),
            attach_path = %candidate.attach_path.display(),
            source = candidate.source,
            device = candidate.identity.device,
            inode = candidate.identity.inode,
            target_pids = ?candidate.pids,
            auto_discover = runtime.auto_discover,
            supported_offsets = offsets.len(),
            attached_links = candidate_links,
            provider_hosts = ?runtime.provider_hosts,
            "SENSITIVE CAPTURE: AnySentry Codex/rustls request probes attached"
        );
    }
    newly_attached
}

fn read_pod<T: Copy>(item: &[u8]) -> Option<T> {
    (item.len() >= core::mem::size_of::<T>())
        .then(|| unsafe { core::ptr::read_unaligned(item.as_ptr() as *const T) })
}

fn read_ssl_fragment(item: &[u8]) -> Option<(SslEventHeader, &[u8])> {
    let header_len = core::mem::size_of::<SslEventHeader>();
    if item.len() < header_len {
        return None;
    }
    let header = unsafe { core::ptr::read_unaligned(item.as_ptr() as *const SslEventHeader) };
    let captured_len = header.captured_len as usize;
    if header.schema_version != SSL_EVENT_SCHEMA_VERSION
        || header._reserved != 0
        || captured_len > SSL_FRAGMENT_LEN
        || item.len() != header_len.checked_add(captured_len)?
        || (header.truncated == 0
            && header
                .fragment_offset
                .checked_add(header.captured_len as u64)?
                > header.original_len)
    {
        return None;
    }
    Some((header, &item[header_len..]))
}

/// The process's current working directory (≈ exec-time for a fresh process).
fn read_cwd(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{pid}/cwd"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn read_exe(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
}

fn read_cgroup(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_process_start_time_ticks(stat: &str) -> Option<u64> {
    let tail = stat.rsplit_once(')')?.1;
    // `/proc/<pid>/stat` field 22. The tail starts at field 3 (`state`).
    tail.split_whitespace().nth(19)?.parse().ok()
}

fn read_start_time_ticks(pid: u32) -> Option<u64> {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .as_deref()
        .and_then(parse_process_start_time_ticks)
}

fn boot_id() -> Option<String> {
    static BOOT_ID: OnceLock<Option<String>> = OnceLock::new();
    BOOT_ID
        .get_or_init(|| {
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .clone()
}

fn mount_namespace(pid: u32) -> Option<u64> {
    let target = std::fs::read_link(format!("/proc/{pid}/ns/mnt")).ok()?;
    let value = target.to_string_lossy();
    value
        .strip_prefix("mnt:[")
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|inode| inode.parse::<u64>().ok())
}

fn host_id() -> Option<String> {
    static HOST_ID: OnceLock<Option<String>> = OnceLock::new();
    HOST_ID
        .get_or_init(|| {
            env_any(&[
                "A3S_OBSERVER_HOST_ID",
                "A3S_NODE_NAME",
                "NODE_NAME",
                "K8S_NODE_NAME",
            ])
            .or_else(|| {
                std::fs::read_to_string("/etc/machine-id")
                    .ok()
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
            })
            .or_else(hostname)
        })
        .clone()
}

fn user_hz() -> Option<u32> {
    static USER_HZ: OnceLock<Option<u32>> = OnceLock::new();
    *USER_HZ.get_or_init(|| {
        let value = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        (value > 0).then_some(value as u32)
    })
}

fn nonzero(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

fn nonzero_pid(value: u32) -> Option<u32> {
    (value != 0).then_some(value)
}

fn read_process_context(
    pid: u32,
    cgroup_id: u64,
    comm: &str,
    expected_start_ns: Option<u64>,
) -> ProcessContext {
    let ticks = read_start_time_ticks(pid);
    let hz = user_hz();
    let proc_matches = expected_start_ns.is_none_or(|ns| {
        ticks.is_some()
            && hz.and_then(|hz| process_identity::start_boottime_ns_to_ticks(ns, hz)) == ticks
    });
    if !proc_matches {
        return ProcessContext {
            host_id: host_id(),
            boot_id: boot_id(),
            pid,
            start_boottime_ns: expected_start_ns,
            user_hz: hz,
            comm: comm.to_string(),
            cgroup_id,
            ..ProcessContext::default()
        };
    }
    let cwd = read_cwd(pid);
    let ppid = read_ppid(pid);
    ProcessContext {
        host_id: host_id(),
        boot_id: boot_id(),
        pid,
        ppid,
        start_time_ticks: ticks,
        start_boottime_ns: expected_start_ns,
        user_hz: hz,
        observed_ppid: nonzero_pid(ppid),
        parent_relation_source: Some("proc_snapshot".to_string()),
        lineage_complete: Some(false),
        comm: comm.to_string(),
        mount_namespace: mount_namespace(pid),
        exe: read_exe(pid),
        cwd: (!cwd.is_empty()).then_some(cwd),
        cgroup: read_cgroup(pid),
        cgroup_id,
        ..ProcessContext::default()
    }
}

fn apply_kernel_identity(
    context: &mut ProcessContext,
    identity: &ProcessKernelIdentity,
    observed_source: &str,
) {
    context.start_boottime_ns = nonzero(identity.start_boottime_ns).or(context.start_boottime_ns);
    context.user_hz = user_hz();
    context.creation_ppid = nonzero_pid(identity.creation_ppid).or(context.creation_ppid);
    context.creation_parent_start_boottime_ns = nonzero(identity.creation_parent_start_boottime_ns)
        .or(context.creation_parent_start_boottime_ns);
    context.observed_ppid = nonzero_pid(identity.observed_ppid).or(context.observed_ppid);
    context.observed_parent_start_boottime_ns = nonzero(identity.observed_parent_start_boottime_ns)
        .or(context.observed_parent_start_boottime_ns);
    if context.creation_ppid.is_some() {
        context.ppid = context.creation_ppid.unwrap();
        context.parent_relation_source = Some("kernel_fork".to_string());
        context.lineage_complete = None;
    } else if context.observed_ppid.is_some() {
        context.ppid = context.observed_ppid.unwrap();
        context.parent_relation_source = Some(observed_source.to_string());
        context.lineage_complete = None;
    }
}

fn process_context_with_start(
    pid: u32,
    cgroup_id: u64,
    comm: &[u8; 16],
    start_boottime_ns: Option<u64>,
) -> ProcessContext {
    let comm = cstr(comm);
    let now = Instant::now();
    if let Ok(mut cache) = process_context_cache().lock() {
        if let Some(context) = cache.get(pid, cgroup_id, start_boottime_ns, &comm, now) {
            return context;
        }
        cache.misses += 1;
    }
    let context = read_process_context(pid, cgroup_id, &comm, start_boottime_ns);
    if let Ok(mut cache) = process_context_cache().lock() {
        cache.insert(context.clone(), now);
    }
    context
}

fn process_context(pid: u32, cgroup_id: u64, comm: &[u8; 16]) -> ProcessContext {
    process_context_with_start(pid, cgroup_id, comm, None)
}

fn exit_process_context(ev: &ExitEvent) -> ProcessContext {
    let mut context = process_context_with_start(
        ev.pid,
        ev.cgroup_id,
        &ev.comm,
        nonzero(ev.identity.start_boottime_ns),
    );
    apply_kernel_identity(&mut context, &ev.identity, "kernel_exit");
    context
}

fn forget_process_context(pid: u32) {
    if let Ok(mut cache) = process_context_cache().lock() {
        cache.remove(pid);
    }
}

fn exec_ppid(ev: &CompletedExec) -> u32 {
    if ev.ppid != 0 {
        ev.ppid
    } else if ev.identity.observed_ppid != 0 {
        ev.identity.observed_ppid
    } else {
        read_ppid(ev.pid)
    }
}

fn exec_process_context(ev: &CompletedExec, ppid: u32) -> ProcessContext {
    let captured_exe = cstr(&ev.filename);
    let mut context = read_process_context(
        ev.pid,
        ev.cgroup_id,
        &cstr(&ev.comm),
        nonzero(ev.identity.start_boottime_ns),
    );
    context.ppid = ppid;
    context.exe = context
        .exe
        .or_else(|| (!captured_exe.is_empty()).then_some(captured_exe));
    apply_kernel_identity(&mut context, &ev.identity, "kernel_exec");
    if let Ok(mut cache) = process_context_cache().lock() {
        cache.insert(context.clone(), Instant::now());
    }
    context
}

struct ProcCmdline {
    argv: Vec<String>,
    observed_bytes: u32,
    truncated: bool,
}

fn read_proc_cmdline_at(
    proc_root: &Path,
    pid: u32,
    max_bytes: usize,
) -> std::io::Result<ProcCmdline> {
    let file = File::open(proc_root.join(pid.to_string()).join("cmdline"))?;
    let mut raw = Vec::new();
    file.take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut raw)?;
    let truncated = raw.len() > max_bytes;
    if truncated {
        raw.truncate(max_bytes);
    }
    let observed_bytes = raw.len().min(u32::MAX as usize) as u32;
    let argv = raw
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect();
    Ok(ProcCmdline {
        argv,
        observed_bytes,
        truncated,
    })
}

fn same_executable(ev: &CompletedExec, proc_argv: &[String]) -> bool {
    let Some(proc_argv0) = proc_argv.first().filter(|value| !value.is_empty()) else {
        return false;
    };
    if ev.argv.first().is_some_and(|value| value == proc_argv0) {
        return true;
    }
    let captured = cstr(&ev.filename);
    let captured_name = Path::new(&captured).file_name();
    let proc_name = Path::new(proc_argv0).file_name();
    captured_name.is_some() && captured_name == proc_name
}

fn supplement_exec_argv_at(
    mut ev: CompletedExec,
    proc_root: &Path,
    max_bytes: usize,
) -> (CompletedExec, &'static str, u32, u32) {
    let should_supplement = ev.exec_confirmed && (ev.argv_truncated || ev.argv_incomplete);
    if should_supplement {
        if let Ok(cmdline) = read_proc_cmdline_at(proc_root, ev.pid, max_bytes) {
            if !cmdline.argv.is_empty() && same_executable(&ev, &cmdline.argv) {
                ev.argv = cmdline.argv;
                ev.argv_truncated = cmdline.truncated;
                ev.argv_incomplete = false;
                let argc = ev.argv.len().min(u32::MAX as usize) as u32;
                return (ev, "proc_cmdline", argc, cmdline.observed_bytes);
            }
        }
    }
    let argc = ev.argv.len().min(u32::MAX as usize) as u32;
    let bytes = ev
        .argv
        .iter()
        .fold(0usize, |total, arg| total.saturating_add(arg.len()))
        .min(u32::MAX as usize) as u32;
    let source = if ev.compact {
        "kernel_compact"
    } else {
        "kernel_fragments"
    };
    (ev, source, argc, bytes)
}

fn supplement_exec_argv(ev: CompletedExec) -> (CompletedExec, &'static str, u32, u32) {
    supplement_exec_argv_at(ev, Path::new("/proc"), PROC_CMDLINE_MAX_BYTES)
}

fn emit_completed_exec(
    exporter: &dyn Exporter,
    stats: &mut Stats,
    resolver: &impl IdentityResolver,
    ev: CompletedExec,
) {
    if ev.reassembly_timed_out {
        stats.exec_reassembly_timeout += 1;
    }
    let (ev, argv_source, observed_argc, observed_bytes) = supplement_exec_argv(ev);
    let ppid = exec_ppid(&ev);
    let process = exec_process_context(&ev, ppid);
    let cwd = process.cwd.clone().unwrap_or_default();
    emit(
        exporter,
        stats,
        EnrichedEvent {
            identity: identity_for(resolver, ev.pid, ev.cgroup_id, &ev.comm),
            workload: resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
            observation: None,
            process: Some(process),
            provider: None,
            event: AgentEvent::ToolExec {
                pid: ev.pid,
                ppid,
                uid: ev.uid,
                argv: ev.argv,
                argv_truncated: ev.argv_truncated,
                argv_incomplete: ev.argv_incomplete,
                exec_confirmed: ev.exec_confirmed,
                argv_source: argv_source.to_string(),
                captured_argc: ev.captured_argc,
                captured_bytes: ev.captured_bytes,
                observed_argc,
                observed_bytes,
                cwd,
            },
        },
    );
}

/// A NUL-terminated byte buffer (from a kernel copy) as a lossy String.
fn cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Resolve identity, falling back to the in-kernel `comm` when the /proc lookup fails (a
/// short-lived process that exited before we read it) — so no event is left unattributed.
fn identity_for(r: &impl IdentityResolver, pid: u32, cgroup_id: u64, comm: &[u8; 16]) -> Identity {
    let mut id = r.resolve(pid, cgroup_id, 0);
    if id.agent.is_none() {
        let c = cstr(comm);
        if !c.is_empty() {
            id.agent = Some(c);
        }
    }
    id
}

fn emit_observed_llm_request(
    exporter: &dyn Exporter,
    stats: &mut Stats,
    resolver: &impl IdentityResolver,
    cgroup_id: u64,
    comm: &[u8; 16],
    observation: ObservedLlmRequest,
    capture_profile: &'static str,
    capture_method: &'static str,
) {
    let observed_at_unix_nanos = unix_nanos_now();
    let provider = match observation.provider.to_ascii_lowercase().as_str() {
        "openai" => Provider::OpenAi,
        "anthropic" => Provider::Anthropic,
        "gemini" => Provider::Gemini,
        other => Provider::Other(other.to_string()),
    };
    let provider_name = observation.provider;
    emit(
        exporter,
        stats,
        EnrichedEvent {
            identity: identity_for(resolver, observation.pid, cgroup_id, comm),
            workload: resolver.resolve_workload(observation.pid, cgroup_id, 0),
            observation: ObservationMetadata::fresh(
                observed_at_unix_nanos,
                observed_at_unix_nanos,
                None,
            )
            .ok(),
            process: Some(process_context(observation.pid, cgroup_id, comm)),
            provider: Some(provider),
            event: AgentEvent::LlmRequestObserved {
                pid: observation.pid,
                tid: observation.tid,
                observed_at_monotonic_ns: observation.observed_at_monotonic_ns,
                protocol: observation.protocol,
                host: observation.host,
                path: observation.path,
                endpoint_attribution: observation.endpoint_attribution,
                provider: provider_name,
                model: observation.model,
                session_id: observation.session_id,
                thread_id: observation.thread_id,
                turn_id: observation.turn_id,
                window_id: observation.window_id,
                request_kind: observation.request_kind,
                body_sha256: observation.body_sha256,
                instruction_bytes: observation.instruction_bytes,
                instruction_sha256: observation.instruction_sha256,
                user_instruction: observation.user_instruction,
                capture_method,
                capture_profile,
                capture_completeness: "complete",
                parse_status: "parsed",
                raw_request_retention_state: "not_retained",
                presentation_state: "sensitive_content_lane",
            },
        },
    );
}

fn emit_observed_llm_response(
    exporter: &dyn Exporter,
    stats: &mut Stats,
    resolver: &impl IdentityResolver,
    capture_profile: &'static str,
    observation: ObservedLlmResponse,
) {
    let observed_at_unix_nanos = unix_nanos_now();
    let provider = match observation.provider.to_ascii_lowercase().as_str() {
        "openai" => Provider::OpenAi,
        "anthropic" => Provider::Anthropic,
        "gemini" => Provider::Gemini,
        other => Provider::Other(other.to_string()),
    };
    let provider_name = observation.provider;
    let comm = observation.comm;
    let tool_calls = observation
        .tool_calls
        .into_iter()
        .map(|call| LlmToolCall {
            id: call.id,
            name: call.name,
            arguments: call.arguments,
        })
        .collect();
    emit(
        exporter,
        stats,
        EnrichedEvent {
            identity: identity_for(resolver, observation.pid, observation.cgroup_id, &comm),
            workload: resolver.resolve_workload(observation.pid, observation.cgroup_id, 0),
            observation: ObservationMetadata::fresh(
                observed_at_unix_nanos,
                observed_at_unix_nanos,
                None,
            )
            .ok(),
            process: Some(process_context(
                observation.pid,
                observation.cgroup_id,
                &comm,
            )),
            provider: Some(provider),
            event: AgentEvent::LlmResponseObserved {
                pid: observation.pid,
                tid: observation.tid,
                observed_at_monotonic_ns: observation.observed_at_monotonic_ns,
                protocol: "http1".to_string(),
                host: observation.host,
                path: observation.path,
                endpoint_attribution: observation.endpoint_attribution,
                provider: provider_name,
                model: observation.model,
                // kimi exposes no native session/thread/turn identifiers, matching the
                // request-direction event.
                session_id: None,
                thread_id: None,
                turn_id: None,
                status_code: observation.status_code,
                finish_reason: observation.finish_reason,
                assistant_content: observation.assistant_content,
                content_sha256: observation.content_sha256,
                content_bytes: observation.content_bytes,
                prompt_tokens: observation.prompt_tokens,
                completion_tokens: observation.completion_tokens,
                total_tokens: observation.total_tokens,
                tool_calls,
                ttft_ns: observation.ttft_ns,
                duration_ns: observation.duration_ns,
                capture_method: "ebpf_openssl",
                capture_profile,
                capture_completeness: observation.capture_completeness,
                parse_status: observation.parse_status,
                raw_response_retention_state: "not_retained",
                presentation_state: "sensitive_content_lane",
            },
        },
    );
}

/// Per-kind event counters for periodic throughput logging (collector operability).
#[derive(Default)]
struct Stats {
    exec: u64,
    exec_truncated: u64,
    exec_incomplete: u64,
    exec_reassembly_timeout: u64,
    exit: u64,
    egress: u64,
    dns: u64,
    file: u64,
    file_coalesced: u64,
    llm: u64,
    llm_response: u64,
    ssl: u64,
    sec: u64,
    agents: HashSet<String>,
}

struct CollectorMeta {
    collector_id: String,
    node_name: Option<String>,
    namespace: Option<String>,
    pod_name: Option<String>,
    version: String,
    mode: String,
    attached_probes: u32,
    enabled_features: Vec<String>,
    interaction_capture_mode: String,
}

impl CollectorMeta {
    fn from_env(
        files: bool,
        interaction_capture_mode: InteractionCaptureMode,
        attached: usize,
    ) -> Self {
        let node_name = env_any(&["A3S_NODE_NAME", "NODE_NAME", "K8S_NODE_NAME"]).or_else(hostname);
        let namespace = env_any(&["A3S_NAMESPACE", "POD_NAMESPACE", "K8S_NAMESPACE"]);
        let pod_name = env_any(&["A3S_POD_NAME", "POD_NAME", "HOSTNAME"]);
        let collector_id = env_any(&["A3S_OBSERVER_COLLECTOR_ID", "COLLECTOR_ID"])
            .or_else(|| pod_name.clone())
            .or_else(|| node_name.clone())
            .unwrap_or_else(|| "a3s-observer".to_string());
        let mut enabled_features = vec![
            "exec".to_string(),
            "network".to_string(),
            "dns".to_string(),
            "security".to_string(),
        ];
        if files {
            enabled_features.push("files".to_string());
        }
        if interaction_capture_mode == InteractionCaptureMode::Metadata {
            enabled_features.push("interaction_metadata".to_string());
        }
        if interaction_capture_mode == InteractionCaptureMode::FixturePayload {
            enabled_features.push("interaction_fixture_payload".to_string());
        }
        let mode = if files || interaction_capture_mode == InteractionCaptureMode::FixturePayload {
            "observe+extensions"
        } else {
            "observe"
        }
        .to_string();
        Self {
            collector_id,
            node_name,
            namespace,
            pod_name,
            version: env!("CARGO_PKG_VERSION").to_string(),
            mode,
            attached_probes: attached as u32,
            enabled_features,
            interaction_capture_mode: interaction_capture_mode.as_str().to_string(),
        }
    }
}

fn env_any(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        std::env::var(name)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

fn env_value_disabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "off" | "no" | "disabled"
    )
}

fn env_enabled(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| !value.trim().is_empty() && !env_value_disabled(&value))
        .unwrap_or(false)
}

fn file_include_paths_from_env() -> Vec<String> {
    file_include_paths(&std::env::var("A3S_OBSERVER_FILE_INCLUDE_PATHS").unwrap_or_default())
}

fn file_coalesce_ms_from_env() -> u64 {
    std::env::var("A3S_OBSERVER_FILE_COALESCE_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(200)
        .min(60_000)
}

fn unix_millis_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

/// FNV-1a over (pid, flags, path). Collisions only merge two distinct opens into one
/// coalescing slot, which the repetition window would likely have merged anyway.
fn file_coalesce_key(pid: u32, flags: u32, path: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in pid
        .to_le_bytes()
        .iter()
        .chain(flags.to_le_bytes().iter())
        .chain(path.as_bytes())
    {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn file_include_paths(value: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for raw in value.split(',').take(32) {
        let normalized = raw.trim().trim_end_matches('/');
        if normalized.starts_with('/')
            && !normalized.is_empty()
            && !paths.iter().any(|item| item == normalized)
        {
            paths.push(normalized.to_string());
        }
    }
    paths
}

fn path_matches_include(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn env_bounded_usize(name: &str, fallback: usize, minimum: usize, maximum: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .map(|value| value.clamp(minimum, maximum))
        .unwrap_or(fallback)
}

fn unix_nanos_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}

fn hostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

struct CollectorHeartbeatRuntime {
    interval_secs: u64,
    dropped: u64,
    dropped_by_kind: BTreeMap<String, u64>,
    output_dropped: u64,
    output_dropped_by_kind: BTreeMap<String, u64>,
    payload_capture_enabled: bool,
    payload_kill_switch_at_unix_nanos: Option<u64>,
    payload_fragments_discarded: u64,
}

fn emit_collector_heartbeat(
    exporter: &dyn Exporter,
    meta: &CollectorMeta,
    stats: &Stats,
    runtime: CollectorHeartbeatRuntime,
) {
    exporter.export(&EnrichedEvent {
        identity: Identity::default(),
        workload: None,
        observation: None,
        process: None,
        provider: None,
        event: AgentEvent::CollectorHeartbeat {
            collector_id: meta.collector_id.clone(),
            node_name: meta.node_name.clone(),
            namespace: meta.namespace.clone(),
            pod_name: meta.pod_name.clone(),
            version: meta.version.clone(),
            mode: meta.mode.clone(),
            attached_probes: meta.attached_probes,
            enabled_features: meta.enabled_features.clone(),
            interval_secs: runtime.interval_secs,
            observed_agents: stats.agents.len() as u64,
            exec: stats.exec,
            exit: stats.exit,
            egress: stats.egress,
            dns: stats.dns,
            file: stats.file,
            file_coalesced: stats.file_coalesced,
            llm: stats.llm,
            ssl: stats.ssl,
            sec: stats.sec,
            exec_truncated: stats.exec_truncated,
            exec_incomplete: stats.exec_incomplete,
            exec_reassembly_timeout: stats.exec_reassembly_timeout,
            dropped: runtime.dropped,
            dropped_by_kind: runtime.dropped_by_kind,
            output_dropped: runtime.output_dropped,
            output_dropped_by_kind: runtime.output_dropped_by_kind,
            interaction_capture_mode: meta.interaction_capture_mode.clone(),
            payload_capture_enabled: runtime.payload_capture_enabled,
            payload_kill_switch_at_unix_nanos: runtime.payload_kill_switch_at_unix_nanos,
            payload_fragments_discarded: runtime.payload_fragments_discarded,
        },
    });
}

/// Export an event and count it by kind for the throughput report.
fn emit(exporter: &dyn Exporter, stats: &mut Stats, ev: EnrichedEvent) {
    match &ev.event {
        AgentEvent::ToolExec {
            argv_truncated,
            argv_incomplete,
            ..
        } => {
            stats.exec += 1;
            stats.exec_truncated += u64::from(*argv_truncated);
            stats.exec_incomplete += u64::from(*argv_incomplete);
        }
        AgentEvent::ProcessExit { .. } => stats.exit += 1,
        AgentEvent::Egress { .. } => stats.egress += 1,
        AgentEvent::Dns { .. } => stats.dns += 1,
        AgentEvent::FileAccess { .. } => stats.file += 1,
        AgentEvent::FileDelete { .. } => stats.file += 1,
        AgentEvent::LlmCall { .. } => stats.llm += 1,
        AgentEvent::LlmRequestObserved { .. } => stats.llm += 1,
        AgentEvent::LlmResponseObserved { .. } => stats.llm_response += 1,
        AgentEvent::SecurityAction { .. } => stats.sec += 1,
        AgentEvent::CollectorHeartbeat { .. } => {}
    }
    if !matches!(ev.event, AgentEvent::CollectorHeartbeat { .. }) {
        if let Some(agent) = &ev.identity.agent {
            stats.agents.insert(agent.clone());
        }
    }
    exporter.export(&ev);
}

fn peer_ip(ev: &ConnectEvent) -> IpAddr {
    if ev.family == 2 {
        IpAddr::V4(Ipv4Addr::new(
            ev.addr[0], ev.addr[1], ev.addr[2], ev.addr[3],
        ))
    } else {
        IpAddr::V6(Ipv6Addr::from(ev.addr))
    }
}

fn sock_key(pid: u32, fd: u32) -> u64 {
    ((pid as u64) << 32) | fd as u64
}

/// Extract the SNI `server_name` from a TLS ClientHello record. Fully bounds-checked
/// (any malformed/truncated input returns `None`).
fn parse_sni(buf: &[u8]) -> Option<String> {
    // record(5) + handshake(4) + client_version(2) + random(32) = 43
    let mut p = 43usize;
    p += 1 + *buf.get(p)? as usize; // session_id: len(1) + id
    p += 2 + be16(buf, p)? as usize; // cipher_suites: len(2) + suites
    p += 1 + *buf.get(p)? as usize; // compression: len(1) + methods
    p += 2; // extensions: total len(2)
    while p + 4 <= buf.len() {
        let ext_type = be16(buf, p)?;
        let ext_len = be16(buf, p + 2)? as usize;
        p += 4;
        if ext_type == 0x0000 {
            // server_name: list_len(2) + name_type(1) + name_len(2) + name
            let name_len = be16(buf, p + 3)? as usize;
            let start = p + 5;
            let name = buf.get(start..start.checked_add(name_len)?)?;
            return core::str::from_utf8(name).ok().map(str::to_owned);
        }
        p = p.checked_add(ext_len)?;
    }
    None
}

fn be16(buf: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(i)?, *buf.get(i + 1)?]))
}

/// Parse the question name (hostname) from a DNS query packet. Queries carry no name
/// compression, so this is a simple length-prefixed label walk. Bounds-checked.
fn parse_dns_qname(buf: &[u8]) -> Option<String> {
    if buf.len() < 13 {
        return None;
    }
    let mut p = 12; // skip the fixed 12-byte header
    let mut name = String::new();
    loop {
        let len = *buf.get(p)? as usize;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 || name.len() + len > 255 {
            return None; // compression pointer (absent in queries) or implausibly long
        }
        p += 1;
        let label = core::str::from_utf8(buf.get(p..p + len)?).ok()?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(label);
        p += len;
    }
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::{
        env_value_disabled, exec_ppid, exec_process_context, file_coalesce_key, file_include_paths,
        fixture_native_stdin_enabled, fixture_native_stdout_enabled, fixture_openssl_enabled,
        parse_dns_qname, parse_interaction_capture_config, parse_process_start_time_ticks,
        parse_sni, path_matches_include, read_ssl_fragment, supplement_exec_argv_at,
        validate_runtime_capture_scope, CompletedExec, ExecAssembler, InteractionCaptureMode,
        ProcessContextCache, EXEC_REASSEMBLY_TIMEOUT, PAYLOAD_FIXTURE_CONFIRMATION,
        PAYLOAD_FIXTURE_PID_LIMIT,
    };
    use a3s_observer::ProcessContext;
    use a3s_observer_common::{
        ExecRecord, ProcessKernelIdentity, SslEventHeader, EXEC_ARG_CHUNK_PAYLOAD,
        EXEC_COMPACT_ARG_LEN, EXEC_FLAG_ARGV_TRUNCATED, EXEC_RECORD_ARG_CHUNK, EXEC_RECORD_COMMIT,
        EXEC_RECORD_COMPACT, EXEC_RECORD_END, EXEC_RECORD_HEADER, SSL_EVENT_SCHEMA_VERSION,
        SSL_OPERATION_WRITE_EX,
    };
    use std::collections::HashMap;
    use std::fs;
    use std::time::{Duration, Instant};

    #[test]
    fn file_coalesce_key_is_stable_and_sensitive() {
        let a = file_coalesce_key(1234, 0x2, "/app/build/out.o");
        assert_eq!(a, file_coalesce_key(1234, 0x2, "/app/build/out.o"));
        assert_ne!(a, file_coalesce_key(1235, 0x2, "/app/build/out.o"));
        assert_ne!(a, file_coalesce_key(1234, 0x1, "/app/build/out.o"));
        assert_ne!(a, file_coalesce_key(1234, 0x2, "/app/build/out.p"));
    }

    #[test]
    fn file_coalesce_repeat_window_suppresses_only_within_window() {
        // Same key inside the window is a repeat; outside the window it emits again.
        let window = 200u64;
        let mut cache: HashMap<u64, u64> = HashMap::new();
        let key = file_coalesce_key(42, 0x2, "/app/x");
        let at = 10_000u64;
        let is_repeat = |cache: &HashMap<u64, u64>, now: u64| {
            cache
                .get(&key)
                .is_some_and(|last| now.saturating_sub(*last) < window)
        };
        assert!(!is_repeat(&cache, at));
        cache.insert(key, at);
        assert!(is_repeat(&cache, at + 199));
        assert!(!is_repeat(&cache, at + 200));
    }

    #[test]
    fn observer_feature_flags_honor_explicit_off_values() {
        for disabled in ["0", "false", "FALSE", "off", "no", "disabled"] {
            assert!(env_value_disabled(disabled), "{disabled}");
        }
        for enabled in ["1", "true", "on", "/usr/lib/libssl.so"] {
            assert!(!env_value_disabled(enabled), "{enabled}");
        }
    }

    #[test]
    fn file_include_paths_are_absolute_bounded_and_normalized() {
        assert_eq!(
            file_include_paths(
            " /home/user/.gemini/tmp/ ,relative,/home/user/.gemini/tmp,/home/user/.codex/sessions/",
            ),
            vec![
                "/home/user/.gemini/tmp".to_string(),
                "/home/user/.codex/sessions".to_string(),
            ]
        );
        assert!(path_matches_include(
            "/home/user/.gemini/tmp/project/chats/session.jsonl",
            "/home/user/.gemini/tmp"
        ));
        assert!(!path_matches_include(
            "/home/user/.gemini/tmp-copy/session.jsonl",
            "/home/user/.gemini/tmp"
        ));
    }

    #[test]
    fn interaction_capture_defaults_to_source_level_metadata_only() {
        let config =
            parse_interaction_capture_config(None, None, None, None, None, Some("1"), (None, None))
                .unwrap();
        assert_eq!(config.mode, InteractionCaptureMode::Metadata);
        assert!(config.fixture_pids.is_empty());
        assert!(config.ignored_legacy_ssl);
    }

    #[test]
    fn native_stdin_fixture_is_rejected_outside_explicit_fixture_payload_mode() {
        assert!(fixture_native_stdin_enabled(InteractionCaptureMode::Metadata, Some("1")).is_err());
        assert!(fixture_native_stdin_enabled(InteractionCaptureMode::Off, Some("true")).is_err());
        assert!(
            fixture_native_stdin_enabled(InteractionCaptureMode::FixturePayload, Some("on"))
                .unwrap()
        );
        assert!(
            !fixture_native_stdin_enabled(InteractionCaptureMode::FixturePayload, Some("off"))
                .unwrap()
        );
    }

    #[test]
    fn native_stdout_fixture_is_rejected_outside_explicit_fixture_payload_mode() {
        assert!(
            fixture_native_stdout_enabled(InteractionCaptureMode::Metadata, Some("1")).is_err()
        );
        assert!(fixture_native_stdout_enabled(InteractionCaptureMode::Off, Some("true")).is_err());
        assert!(
            fixture_native_stdout_enabled(InteractionCaptureMode::FixturePayload, Some("on"))
                .unwrap()
        );
        assert!(!fixture_native_stdout_enabled(
            InteractionCaptureMode::FixturePayload,
            Some("off")
        )
        .unwrap());
    }

    #[test]
    fn openssl_fixture_defaults_on_only_inside_fixture_payload_mode() {
        assert!(!fixture_openssl_enabled(InteractionCaptureMode::Metadata, None).unwrap());
        assert!(!fixture_openssl_enabled(InteractionCaptureMode::Off, None).unwrap());
        assert!(fixture_openssl_enabled(InteractionCaptureMode::FixturePayload, None).unwrap());
        assert!(
            !fixture_openssl_enabled(InteractionCaptureMode::FixturePayload, Some("off")).unwrap()
        );
        assert!(fixture_openssl_enabled(InteractionCaptureMode::Metadata, Some("1")).is_err());
    }

    #[test]
    fn payload_fixture_requires_every_isolation_gate() {
        assert!(parse_interaction_capture_config(
            Some("fixture_payload"),
            None,
            Some(PAYLOAD_FIXTURE_CONFIRMATION),
            Some("42"),
            None,
            None,
            (Some("/tmp/a3s-fixture-test.jsonl"), Some("api.openai.com"),),
        )
        .is_err());
        assert!(parse_interaction_capture_config(
            Some("fixture_payload"),
            Some("isolated_test"),
            None,
            Some("42"),
            None,
            None,
            (Some("/tmp/a3s-fixture-test.jsonl"), Some("api.openai.com"),),
        )
        .is_err());
        assert!(parse_interaction_capture_config(
            Some("fixture_payload"),
            Some("isolated_test"),
            Some(PAYLOAD_FIXTURE_CONFIRMATION),
            None,
            None,
            None,
            (Some("/tmp/a3s-fixture-test.jsonl"), Some("api.openai.com"),),
        )
        .is_err());
        assert!(parse_interaction_capture_config(
            Some("fixture_payload"),
            Some("isolated_test"),
            Some(PAYLOAD_FIXTURE_CONFIRMATION),
            Some("42"),
            None,
            None,
            (None, Some("api.openai.com")),
        )
        .is_err());
        assert!(parse_interaction_capture_config(
            Some("fixture_payload"),
            Some("isolated_test"),
            Some(PAYLOAD_FIXTURE_CONFIRMATION),
            Some("42"),
            None,
            None,
            (Some("/tmp/a3s-fixture-test.jsonl"), None),
        )
        .is_err());
    }

    #[test]
    fn payload_fixture_deduplicates_and_bounds_explicit_pids() {
        let config = parse_interaction_capture_config(
            Some("fixture_payload"),
            Some("isolated_test"),
            Some(PAYLOAD_FIXTURE_CONFIRMATION),
            Some("42, 43,42"),
            Some("/fixture/libssl.so"),
            Some("1"),
            (
                Some("/tmp/a3s-fixture-test.jsonl"),
                Some("api.openai.com,api.anthropic.com,api.openai.com"),
            ),
        )
        .unwrap();
        assert_eq!(config.mode, InteractionCaptureMode::FixturePayload);
        assert_eq!(config.fixture_pids, [42, 43]);
        assert_eq!(
            config.fixture_provider_hosts,
            ["api.openai.com", "api.anthropic.com"]
        );
        assert_eq!(
            config.fixture_output_path.as_deref(),
            Some(std::path::Path::new("/tmp/a3s-fixture-test.jsonl"))
        );
        assert_eq!(config.ssl_library, "/fixture/libssl.so");
        assert!(!config.ignored_legacy_ssl);
    }

    #[test]
    fn interaction_capture_rejects_unknown_modes_and_host_wide_pid_zero() {
        assert!(parse_interaction_capture_config(
            Some("encrypted_full"),
            None,
            None,
            None,
            None,
            None,
            (None, None),
        )
        .is_err());
        assert!(parse_interaction_capture_config(
            Some("fixture_payload"),
            Some("isolated_test"),
            Some(PAYLOAD_FIXTURE_CONFIRMATION),
            Some("0"),
            None,
            None,
            (Some("/tmp/a3s-fixture-test.jsonl"), Some("api.openai.com"),),
        )
        .is_err());
    }

    #[test]
    fn runtime_capture_requires_one_unambiguous_scope() {
        assert!(validate_runtime_capture_scope(&[], false).is_err());
        assert!(validate_runtime_capture_scope(&[42], false).is_ok());
        assert!(validate_runtime_capture_scope(&[], true).is_ok());
        assert!(validate_runtime_capture_scope(&[42], true).is_err());
        assert!(validate_runtime_capture_scope(
            &(1..=(PAYLOAD_FIXTURE_PID_LIMIT as u32 + 1)).collect::<Vec<_>>(),
            false,
        )
        .is_err());
    }

    #[test]
    fn variable_ssl_fragment_abi_rejects_malformed_records() {
        assert_eq!(core::mem::size_of::<SslEventHeader>(), 88);
        let header = SslEventHeader {
            schema_version: SSL_EVENT_SCHEMA_VERSION,
            operation: SSL_OPERATION_WRITE_EX,
            truncated: 0,
            pid: 42,
            tid: 43,
            captured_len: 4,
            fragment_index: 2,
            _reserved: 0,
            cgroup_id: 7,
            ssl_pointer: 8,
            call_sequence: 9,
            observed_at_monotonic_ns: 10,
            original_len: 12,
            fragment_offset: 8,
            comm: [0; 16],
        };
        let header_bytes = unsafe {
            core::slice::from_raw_parts(
                &header as *const SslEventHeader as *const u8,
                core::mem::size_of::<SslEventHeader>(),
            )
        };
        let mut record = header_bytes.to_vec();
        record.extend_from_slice(b"tail");
        let (parsed, payload) = read_ssl_fragment(&record).expect("valid variable record");
        assert_eq!(parsed.fragment_index, 2);
        assert_eq!(payload, b"tail");

        let mut trailing = record.clone();
        trailing.push(0);
        assert!(read_ssl_fragment(&trailing).is_none());

        let mut invalid_schema = header;
        invalid_schema.schema_version = SSL_EVENT_SCHEMA_VERSION.saturating_sub(1);
        let invalid_bytes = unsafe {
            core::slice::from_raw_parts(
                &invalid_schema as *const SslEventHeader as *const u8,
                core::mem::size_of::<SslEventHeader>(),
            )
        };
        let mut invalid_record = invalid_bytes.to_vec();
        invalid_record.extend_from_slice(b"tail");
        assert!(read_ssl_fragment(&invalid_record).is_none());
    }

    #[test]
    fn process_context_cache_reuses_stable_instances_and_invalidates_changes() {
        let mut cache = ProcessContextCache::default();
        let now = Instant::now();
        cache.insert(
            ProcessContext {
                pid: 42,
                comm: "worker".into(),
                cgroup_id: 77,
                start_time_ticks: Some(900),
                start_boottime_ns: Some(9_000_000_000),
                ..ProcessContext::default()
            },
            now,
        );
        let cached = cache
            .get(
                42,
                77,
                Some(9_000_000_000),
                "cmain",
                now + Duration::from_millis(10),
            )
            .expect("same generation survives comm changes");
        assert_eq!(cached.start_time_ticks, Some(900));
        assert_eq!(cached.comm, "cmain");
        assert!(cache
            .get(42, 78, None, "worker", now + Duration::from_millis(20))
            .is_none());
        assert!(cache.entries.is_empty());
        assert_eq!(cache.hits, 1);
    }

    fn exec_record(exec_id: u64, kind: u8) -> ExecRecord {
        let mut record: ExecRecord = unsafe { std::mem::zeroed() };
        record.exec_id = exec_id;
        record.pid = u32::MAX;
        record.ppid = 42;
        record.uid = 1000;
        record.kind = kind;
        record
    }

    fn chunk(exec_id: u64, arg_index: u16, chunk_index: u16, value: &[u8]) -> ExecRecord {
        let mut record = exec_record(exec_id, EXEC_RECORD_ARG_CHUNK);
        record.arg_index = arg_index;
        record.chunk_index = chunk_index;
        record.data_len = value.len() as u16;
        record.data[..value.len()].copy_from_slice(value);
        record
    }

    #[test]
    fn exec_uses_kernel_parent_snapshot_and_filename_fallback() {
        let mut ev = CompletedExec {
            cgroup_id: 73,
            identity: ProcessKernelIdentity::default(),
            pid: u32::MAX,
            ppid: 42,
            uid: 1000,
            comm: [0; 16],
            filename: [0; 128],
            argv: vec!["bash".to_string()],
            argv_truncated: false,
            argv_incomplete: false,
            captured_argc: 1,
            captured_bytes: 4,
            compact: false,
            reassembly_timed_out: false,
            exec_confirmed: true,
        };
        let filename = b"/usr/bin/bash";
        ev.filename[..filename.len()].copy_from_slice(filename);

        assert_eq!(exec_ppid(&ev), 42);
        let process = exec_process_context(&ev, exec_ppid(&ev));
        assert_eq!(process.ppid, 42);
        assert_eq!(process.exe.as_deref(), Some("/usr/bin/bash"));
        assert_eq!(process.cgroup_id, 73);
    }

    #[test]
    fn reassembles_compact_exec_in_either_ring_order() {
        let now = Instant::now();
        for compact_first in [true, false] {
            let mut assembler = ExecAssembler::default();
            let mut compact = exec_record(20, EXEC_RECORD_COMPACT);
            for (index, value) in [b"git".as_slice(), b"diff", b"--stat"]
                .into_iter()
                .enumerate()
            {
                let start = index * EXEC_COMPACT_ARG_LEN;
                compact.data[start..start + value.len()].copy_from_slice(value);
                compact.captured_bytes += value.len() as u32;
            }
            compact.data_len = (3 * EXEC_COMPACT_ARG_LEN) as u16;
            compact.argc = 3;
            if compact_first {
                assert!(assembler.push(compact, now).is_empty());
                let completed = assembler
                    .push(exec_record(20, EXEC_RECORD_COMMIT), now)
                    .pop()
                    .unwrap();
                assert_eq!(completed.argv, ["git", "diff", "--stat"]);
                assert!(!completed.argv_incomplete);
                assert!(completed.exec_confirmed);
            } else {
                assert!(assembler
                    .push(exec_record(20, EXEC_RECORD_COMMIT), now)
                    .is_empty());
                let completed = assembler.push(compact, now).pop().unwrap();
                assert_eq!(completed.argv, ["git", "diff", "--stat"]);
                assert!(!completed.argv_incomplete);
                assert!(completed.exec_confirmed);
            }
        }

        let mut assembler = ExecAssembler::default();
        assembler.push(exec_record(21, EXEC_RECORD_COMMIT), now);
        let missing = assembler.expire(now + EXEC_REASSEMBLY_TIMEOUT);
        assert_eq!(missing.len(), 1);
        assert!(missing[0].exec_confirmed);
        assert!(missing[0].argv_incomplete);
    }

    #[test]
    fn reassembles_long_arguments_without_silent_truncation() {
        let now = Instant::now();
        let mut assembler = ExecAssembler::default();
        let mut header = exec_record(7, EXEC_RECORD_HEADER);
        header.data_len = 9;
        header.data[..9].copy_from_slice(b"/bin/bash");
        assert!(assembler.push(header, now).is_empty());
        assert!(assembler.push(chunk(7, 0, 0, b"bash"), now).is_empty());

        let long = [b'x'; EXEC_ARG_CHUNK_PAYLOAD + 73];
        assert!(assembler
            .push(chunk(7, 1, 0, &long[..EXEC_ARG_CHUNK_PAYLOAD]), now)
            .is_empty());
        assert!(assembler
            .push(chunk(7, 1, 1, &long[EXEC_ARG_CHUNK_PAYLOAD..]), now)
            .is_empty());
        let mut end = exec_record(7, EXEC_RECORD_END);
        end.argc = 2;
        end.captured_bytes = (4 + long.len()) as u32;
        assert!(assembler.push(end, now).is_empty());
        let completed = assembler
            .push(exec_record(7, EXEC_RECORD_COMMIT), now)
            .pop()
            .unwrap();

        assert_eq!(completed.argv[0], "bash");
        assert_eq!(completed.argv[1].len(), long.len());
        assert!(!completed.argv_truncated);
        assert!(!completed.argv_incomplete);
    }

    #[test]
    fn marks_missing_chunks_and_timeouts_as_incomplete() {
        let now = Instant::now();
        let mut assembler = ExecAssembler::default();
        let header = exec_record(8, EXEC_RECORD_HEADER);
        assembler.push(header, now);
        assembler.push(chunk(8, 0, 1, b"tail"), now);
        let mut end = exec_record(8, EXEC_RECORD_END);
        end.argc = 1;
        end.captured_bytes = 4;
        assembler.push(end, now);
        let missing = assembler
            .push(exec_record(8, EXEC_RECORD_COMMIT), now)
            .pop()
            .unwrap();
        assert!(missing.argv_incomplete);

        assembler.push(exec_record(9, EXEC_RECORD_HEADER), now);
        let timed_out = assembler.expire(now + EXEC_REASSEMBLY_TIMEOUT);
        assert_eq!(timed_out.len(), 1);
        assert!(timed_out[0].argv_incomplete);
        assert!(timed_out[0].reassembly_timed_out);
    }

    #[test]
    fn emits_without_waiting_when_exec_commit_probe_is_unavailable() {
        let now = Instant::now();
        let mut assembler = ExecAssembler::new(false);
        assembler.push(exec_record(11, EXEC_RECORD_HEADER), now);
        assembler.push(chunk(11, 0, 0, b"echo"), now);
        let mut end = exec_record(11, EXEC_RECORD_END);
        end.argc = 1;
        end.captured_bytes = 4;

        let completed = assembler.push(end, now).pop().unwrap();
        assert_eq!(completed.argv, ["echo"]);
        assert!(!completed.exec_confirmed);
        assert!(!completed.argv_incomplete);
        assert!(!completed.reassembly_timed_out);
    }

    #[test]
    fn failed_exec_is_unconfirmed_but_not_a_reassembly_timeout() {
        let now = Instant::now();
        let mut assembler = ExecAssembler::default();
        assembler.push(exec_record(12, EXEC_RECORD_HEADER), now);
        assembler.push(chunk(12, 0, 0, b"missing-command"), now);
        let mut end = exec_record(12, EXEC_RECORD_END);
        end.argc = 1;
        end.captured_bytes = 15;
        assembler.push(end, now);

        let completed = assembler
            .expire(now + EXEC_REASSEMBLY_TIMEOUT)
            .pop()
            .unwrap();
        assert!(!completed.exec_confirmed);
        assert!(completed.argv_incomplete);
        assert!(!completed.reassembly_timed_out);
    }

    #[test]
    fn preserves_explicit_kernel_truncation() {
        let now = Instant::now();
        let mut assembler = ExecAssembler::default();
        assembler.push(exec_record(10, EXEC_RECORD_HEADER), now);
        assembler.push(chunk(10, 0, 0, &[b'x'; EXEC_ARG_CHUNK_PAYLOAD]), now);
        let mut end = exec_record(10, EXEC_RECORD_END);
        end.argc = 1;
        end.captured_bytes = EXEC_ARG_CHUNK_PAYLOAD as u32;
        end.flags = EXEC_FLAG_ARGV_TRUNCATED;
        assembler.push(end, now);
        let completed = assembler
            .push(exec_record(10, EXEC_RECORD_COMMIT), now)
            .pop()
            .unwrap();
        assert!(completed.argv_truncated);
        assert!(!completed.argv_incomplete);
    }

    #[test]
    fn supplements_truncated_argv_from_matching_proc_cmdline() {
        let pid = std::process::id();
        let root = std::env::temp_dir().join(format!("observer-proc-test-{pid}"));
        let proc_dir = root.join(pid.to_string());
        fs::create_dir_all(&proc_dir).unwrap();
        fs::write(
            proc_dir.join("cmdline"),
            b"/usr/bin/bash\0-c\0echo complete-dangerous-tail\0",
        )
        .unwrap();
        let mut filename = [0; 128];
        filename[..13].copy_from_slice(b"/usr/bin/bash");
        let event = CompletedExec {
            cgroup_id: 99,
            identity: ProcessKernelIdentity::default(),
            pid,
            ppid: 1,
            uid: 1000,
            comm: [0; 16],
            filename,
            argv: vec!["/usr/bin/bash".into(), "-c".into(), "echo complete".into()],
            argv_truncated: true,
            argv_incomplete: false,
            captured_argc: 3,
            captured_bytes: 32,
            compact: false,
            reassembly_timed_out: false,
            exec_confirmed: true,
        };

        let (event, source, argc, bytes) = supplement_exec_argv_at(event, &root, 4096);
        assert_eq!(source, "proc_cmdline");
        assert_eq!(event.argv[2], "echo complete-dangerous-tail");
        assert!(!event.argv_truncated);
        assert!(!event.argv_incomplete);
        assert_eq!(argc, 3);
        assert!(bytes > event.captured_bytes);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn successful_exec_commit_updates_comm_without_changing_generation() {
        let now = Instant::now();
        let mut assembler = ExecAssembler::default();
        let mut header = exec_record(91, EXEC_RECORD_HEADER);
        header.comm[..4].copy_from_slice(b"bash");
        header.identity.start_boottime_ns = 12_345_678_900;
        header.data_len = 10;
        header.data[..10].copy_from_slice(b"/app/cmain");
        assert!(assembler.push(header, now).is_empty());
        let mut commit = exec_record(91, EXEC_RECORD_COMMIT);
        commit.comm[..5].copy_from_slice(b"cmain");
        commit.identity.start_boottime_ns = 12_345_678_900;
        assert!(assembler.push(commit, now).is_empty());
        let end = exec_record(91, EXEC_RECORD_END);
        let completed = assembler.push(end, now);
        assert_eq!(completed.len(), 1);
        assert_eq!(&completed[0].comm[..5], b"cmain");
        assert_eq!(completed[0].identity.start_boottime_ns, 12_345_678_900);
        assert!(completed[0].exec_confirmed);
    }

    #[test]
    fn parses_start_time_from_proc_stat_with_complex_comm() {
        let stat =
            "9 (worker (agent) one) R 42 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 987654 19";
        assert_eq!(parse_process_start_time_ticks(stat), Some(987654));
        assert_eq!(parse_process_start_time_ticks("garbage"), None);
    }

    #[test]
    fn parses_sni_from_minimal_clienthello() {
        let mut b = vec![0x16, 0x03, 0x01, 0x00, 0x00]; // record header
        b.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // handshake header
        b.extend_from_slice(&[0x03, 0x03]); // client_version
        b.extend_from_slice(&[0u8; 32]); // random
        b.push(0x00); // session_id len 0
        b.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: len 2 + 1 suite
        b.extend_from_slice(&[0x01, 0x00]); // compression: len 1 + null
        b.extend_from_slice(&[0x00, 0x11]); // extensions total len 17
        b.extend_from_slice(&[0x00, 0x00]); // ext type: server_name
        b.extend_from_slice(&[0x00, 0x0d]); // ext len 13
        b.extend_from_slice(&[0x00, 0x0b]); // server_name_list len 11
        b.push(0x00); // name_type host_name
        b.extend_from_slice(&[0x00, 0x08]); // name len 8
        b.extend_from_slice(b"test.com");
        assert_eq!(parse_sni(&b).as_deref(), Some("test.com"));
    }

    #[test]
    fn rejects_truncated_or_garbage() {
        assert_eq!(parse_sni(&[0u8; 8]), None);
        assert_eq!(parse_sni(&[]), None);
    }

    #[test]
    fn parses_dns_query_name() {
        let mut q = vec![0u8; 12]; // header
        q.extend_from_slice(&[
            3, b'a', b'p', b'i', 9, b'a', b'n', b't', b'h', b'r', b'o', b'p', b'i', b'c', 3, b'c',
            b'o', b'm', 0,
        ]);
        q.extend_from_slice(&[0, 1, 0, 1]); // qtype A, qclass IN
        assert_eq!(parse_dns_qname(&q).as_deref(), Some("api.anthropic.com"));
        assert_eq!(parse_dns_qname(&[0u8; 8]), None);
    }

    #[test]
    fn parse_sni_rejects_malicious_name_len_without_panicking() {
        // Long enough to reach the extension walk, but the server_name name_len (0xffff) points
        // far past the buffer — a hand-rolled parser without bounds checks would OOB-panic here.
        let mut b = vec![0x16, 0x03, 0x01, 0x00, 0x00];
        b.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        b.extend_from_slice(&[0x03, 0x03]);
        b.extend_from_slice(&[0u8; 32]);
        b.push(0x00); // session_id len 0
        b.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        b.extend_from_slice(&[0x01, 0x00]); // compression
        b.extend_from_slice(&[0x00, 0x09]); // extensions total len
        b.extend_from_slice(&[0x00, 0x00]); // ext type: server_name
        b.extend_from_slice(&[0x00, 0x05]); // ext len
        b.extend_from_slice(&[0x00, 0x03]); // server_name_list len
        b.push(0x00); // name_type
        b.extend_from_slice(&[0xff, 0xff]); // name_len 65535 — past the buffer
        assert_eq!(parse_sni(&b), None);
    }

    #[test]
    fn parse_dns_rejects_compression_pointer_and_label_overrun() {
        let mut ptr = vec![0u8; 12];
        ptr.extend_from_slice(&[0xc0, 0x0c]); // compression pointer — never valid in a query
        assert_eq!(parse_dns_qname(&ptr), None);
        let mut overrun = vec![0u8; 12];
        overrun.push(50); // claims a 50-byte label...
        overrun.extend_from_slice(b"short"); // ...but only 5 bytes follow
        assert_eq!(parse_dns_qname(&overrun), None);
    }
}
