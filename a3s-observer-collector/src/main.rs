//! a3s-observer collector — loads the eBPF probes, pumps the ring buffers, and emits
//! enriched events through the [`Exporter`] contract.
//!
//! Probes: `exec` (tools), `tls_*` (TLS ClientHello → SNI → provider), `connect` (peer IP),
//! `dns` (hostnames), `file_open` (files opened for writing). Userspace enriches with
//! identity (`/proc` comm+ppid, k8s cgroup→pod) and a `(pid,fd)→peer` correlation, then
//! exports (NDJSON or log). OTLP is a drop-in via the `Exporter` trait.

mod capture_profile;
mod event_time;
mod interaction;
mod pipeline;
mod process_lifecycle;
mod process_namespace;
mod ring_reader;
mod tls_agent_scopes;
mod tls_attach;

use a3s_observer::{
    AgentEvent, AgentPlaintextEvidence, CollectorCaptureProbeStats, CollectorCaptureProfileStats,
    CollectorFileFilterStats, CollectorIngressAccounting, CollectorPipelineAccounting,
    CollectorPipelineUnit, CollectorPipelineWindow, CollectorRingAccounting, EnrichedEvent,
    EventCaptureDecision, EventTiming, ExportOutcome, ExportPriority, Exporter, Identity,
    IdentityResolver, JsonExporter, KubeResolver, LlmInteraction, LogExporter, ProcessContext,
    Provider, ServiceClassifier, SniClassifier,
};
use a3s_observer_common::{
    file_access_mode, CaptureDecisionContext, CaptureProbeStats, ConnectEvent, DnsEvent,
    ExecRecord, ExitEvent, FileEvent, FileFilterConfig, FileFilterKey, FileFilterStats,
    FileFilterValue, LlmEvent, RingPipelineStats, SecEvent, TlsEvent, TlsPlaintextEventHeader,
    ARGV_SLOTS, CAPTURE_DECISION_FLAG_SELECTED, CAPTURE_PROFILE_AGENT_FULL,
    CAPTURE_PROFILE_INVESTIGATION_FULL, CAPTURE_PROFILE_PROBABLE_INVESTIGATION, EXEC_ARG_CHUNK_LEN,
    EXEC_ARG_CHUNK_PAYLOAD, EXEC_FLAG_ARGV_INCOMPLETE, EXEC_FLAG_ARGV_TRUNCATED, EXEC_MAX_CHUNKS,
    EXEC_RECORD_ARG_CHUNK, EXEC_RECORD_COMMIT, EXEC_RECORD_END, EXEC_RECORD_HEADER,
    FILE_ACCESS_MODE_PATH_ONLY, FILE_ACCESS_MODE_READ_ONLY, FILE_ACCESS_MODE_READ_WRITE,
    FILE_ACCESS_MODE_SPECIAL, FILE_ACCESS_MODE_WRITE_ONLY, FILE_FILTER_ACTION_DROP,
    FILE_FILTER_ACTION_KEEP, FILE_FILTER_ACTION_SAMPLE, FILE_FILTER_AUTHORITY_AUTHORITATIVE,
    FILE_FILTER_AUTHORITY_CANDIDATE, FILE_FILTER_CONFIG_ENABLED, FILE_FILTER_CONFIG_UNKNOWN_SAMPLE,
    PIPELINE_RING_CONNECT, PIPELINE_RING_COUNT, PIPELINE_RING_DNS, PIPELINE_RING_EXEC,
    PIPELINE_RING_EXIT, PIPELINE_RING_FILE_ACCESS, PIPELINE_RING_FILE_DELETE,
    PIPELINE_RING_FILE_READ, PIPELINE_RING_LLM, PIPELINE_RING_SECURITY, PIPELINE_RING_SSL,
    PIPELINE_RING_TLS, SEC_BIND, SEC_PTRACE, SEC_SETUID, TLS_PLAINTEXT_ABI_V1,
    TLS_PLAINTEXT_API_RUSTLS, TLS_PLAINTEXT_API_SSL_CLASSIC, TLS_PLAINTEXT_API_SSL_EX,
    TLS_PLAINTEXT_API_TCP, TLS_PLAINTEXT_DIRECTION_READ, TLS_PLAINTEXT_FLAG_TRUNCATED,
};
use anyhow::Context as _;
use aya::{
    maps::{Array, HashMap as BpfHashMap, MapData, PerCpuArray, PerCpuHashMap, RingBuf},
    programs::{KProbe, TracePoint, UProbe},
    Ebpf,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{watch, Notify};
use tokio::task::JoinSet;

use pipeline::{
    pipeline_channel, InboxCapacities, PipelineOrigin, PipelineReceiver, PipelineSender,
    RawEnvelope, ReorderCoordinator, ReorderPushError, RingOrigin, ServiceClass,
    PIPELINE_WEIGHTED_BATCH,
};
use process_lifecycle::ProcessLifecycleStore;
use process_namespace::read_process_namespace;
use ring_reader::{run_ring_reader, RingReaderLedger, RingReaderLedgerSnapshot};

use capture_profile::{
    ack_document, default_ack_path, parse_snapshot, rejected_ack_document, rfc3339_now,
    write_ack_atomic, CaptureAggregateReader, CaptureMapManager, CaptureProfileMode,
    CollectorGeneration, PreviewReceipt,
};
use event_time::{monotonic_now_ns, system_now_unix_ns};
use interaction::{
    ChunkDirection, CompletedInteraction, CompletedPlaintextEvidence, InteractionReassembler,
    PlaintextChunk,
};
use tls_agent_scopes::TlsAgentScopeReloader;
use tls_attach::{
    SymbolFamily, TlsAbi, TlsAttachKind, TlsAttachManager, TlsAttachPlan, TlsOffsetPair,
};

const EXEC_REASSEMBLY_TIMEOUT: Duration = Duration::from_millis(500);
const EXEC_REASSEMBLY_LIMIT: usize = 4096;
const PROC_CMDLINE_MAX_BYTES: usize = 2 * 1024 * 1024;
const PROCESS_CONTEXT_CACHE_TTL: Duration = Duration::from_secs(2);
const PROCESS_CONTEXT_CACHE_STALE: Duration = Duration::from_secs(30);
const PROCESS_CONTEXT_CACHE_LIMIT: usize = 65_536;
const FINAL_HEARTBEAT_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);
const FILTER_RULE_SNAPSHOT_SCHEMA: &str = "anysentry.filter_rule_snapshot.v1";
const FILTER_RULE_SNAPSHOT_MAX_BYTES: u64 = 4 * 1024 * 1024;
const FILTER_RULE_SNAPSHOT_MAX_ENTRIES: usize = 65_536;
const FILTER_RULE_RELOAD_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_UNKNOWN_PER_CGROUP: u32 = 20;
const DEFAULT_UNKNOWN_PER_NODE: u32 = 1_000;
const DEFAULT_UNKNOWN_WINDOW_MS: u64 = 1_000;
const DEFAULT_CRITICAL_INBOX_CAPACITY: usize = 16_384;
const DEFAULT_SEMANTIC_INBOX_CAPACITY: usize = 32_768;
const DEFAULT_BULK_INBOX_CAPACITY: usize = 4_096;
const DEFAULT_REORDER_CAPACITY: usize = 65_536;
const DEFAULT_REORDER_WINDOW_NS: u64 = 2_000_000;
const PROCESSOR_TICK: Duration = Duration::from_millis(2);
const RING_READER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const FILE_ACCESS_TRACEPOINTS: [(&str, &str); 3] = [
    ("file_open", "sys_enter_openat"),
    ("file_openat2", "sys_enter_openat2"),
    ("file_open_legacy", "sys_enter_open"),
];

type FileFilterKeyBytes = [u8; 16];
type FileFilterValueBytes = [u8; 24];
type FileFilterConfigBytes = [u8; 32];
type FileFilterStatsBytes = [u8; 104];
type RingPipelineStatsBytes = [u8; 16];
type CaptureProbeStatsBytes = [u8; 184];
type PlaintextProcessKeyBytes = [u8; 16];

struct VerifiedProcessMap {
    map: BpfHashMap<MapData, PlaintextProcessKeyBytes, u8>,
    installed: HashSet<PlaintextProcessKeyBytes>,
}

impl VerifiedProcessMap {
    fn new(map: BpfHashMap<MapData, PlaintextProcessKeyBytes, u8>) -> Self {
        Self {
            map,
            installed: HashSet::new(),
        }
    }

    fn sync(&mut self, pids: impl IntoIterator<Item = i32>) -> anyhow::Result<usize> {
        let desired = pids
            .into_iter()
            .filter_map(plaintext_process_key)
            .collect::<HashSet<_>>();
        for key in self.installed.difference(&desired) {
            let _ = self.map.remove(key);
        }
        for key in &desired {
            self.map.insert(*key, 1, 0)?;
        }
        let newly_installed = desired.difference(&self.installed).count();
        self.installed = desired;
        Ok(newly_installed)
    }
}

fn plaintext_process_key(pid: i32) -> Option<PlaintextProcessKeyBytes> {
    let cgroups = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let relative = cgroups.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        (hierarchy == "0" && controllers.is_empty()).then_some(path)
    })?;
    let mut cgroup_path = PathBuf::from("/sys/fs/cgroup");
    for component in Path::new(relative).components() {
        if let std::path::Component::Normal(value) = component {
            cgroup_path.push(value);
        }
    }
    // With `--pid=host` and a private cgroup namespace, `/proc/<container-pid>/cgroup` can be
    // reported as `../docker-<id>.scope`, while the host mount is actually below `system.slice`.
    // The target process's own cgroup mount root has the exact kernfs inode returned by
    // `bpf_get_current_cgroup_id`; use it only when the host-root reconstruction is unavailable.
    let cgroup_id = std::fs::metadata(&cgroup_path)
        .map(|metadata| metadata.ino())
        .ok()
        .or_else(|| {
            std::fs::metadata(format!("/proc/{pid}/root/sys/fs/cgroup"))
                .map(|metadata| metadata.ino())
                .ok()
                .filter(|inode| *inode > 1)
        })?;
    let pid = u32::try_from(pid).ok()?;
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&cgroup_id.to_ne_bytes());
    key[8..12].copy_from_slice(&pid.to_ne_bytes());
    Some(key)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileFeatureFlags {
    access: bool,
    delete: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum UnknownFilePolicy {
    #[default]
    Keep,
    Sample,
}

impl UnknownFilePolicy {
    fn name(self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Sample => "sample",
        }
    }

    fn sampling_enabled(self) -> bool {
        matches!(self, Self::Sample)
    }
}

fn parse_unknown_file_policy(value: Option<&str>) -> Result<UnknownFilePolicy, String> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        None | Some("keep") => Ok(UnknownFilePolicy::Keep),
        Some("sample") => Ok(UnknownFilePolicy::Sample),
        Some(_) => Err("A3S_OBSERVER_FILE_UNKNOWN_POLICY must be `keep` or `sample`".to_string()),
    }
}

fn unknown_file_policy_from_env() -> UnknownFilePolicy {
    let value = std::env::var("A3S_OBSERVER_FILE_UNKNOWN_POLICY").ok();
    match parse_unknown_file_policy(value.as_deref()) {
        Ok(policy) => policy,
        Err(error) => {
            // Invalid configuration must never silently enable a lossy policy.
            tracing::warn!(error = %error, "invalid Unknown FileAccess policy; defaulting to keep");
            UnknownFilePolicy::Keep
        }
    }
}

fn optional_env_enabled(name: &str) -> Option<bool> {
    std::env::var(name)
        .ok()
        .map(|value| !value.trim().is_empty() && !env_value_disabled(&value))
}

fn file_feature_flags_from(
    legacy: bool,
    access: Option<bool>,
    writes_alias: Option<bool>,
    delete: Option<bool>,
    deletes_alias: Option<bool>,
) -> FileFeatureFlags {
    FileFeatureFlags {
        access: access.or(writes_alias).unwrap_or(legacy),
        delete: delete.or(deletes_alias).unwrap_or(legacy),
    }
}

fn file_feature_flags() -> FileFeatureFlags {
    file_feature_flags_from(
        env_enabled("A3S_OBSERVER_FILES"),
        optional_env_enabled("A3S_OBSERVER_FILE_ACCESS"),
        optional_env_enabled("A3S_OBSERVER_FILE_WRITES"),
        optional_env_enabled("A3S_OBSERVER_FILE_DELETE"),
        optional_env_enabled("A3S_OBSERVER_FILE_DELETES"),
    )
}

fn bounded_env_u64(name: &str, fallback: u64, min: u64, max: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(fallback)
}

fn pod_bytes<T: Copy, const N: usize>(value: &T) -> [u8; N] {
    assert_eq!(std::mem::size_of::<T>(), N);
    let mut bytes = [0u8; N];
    unsafe {
        std::ptr::copy_nonoverlapping(value as *const T as *const u8, bytes.as_mut_ptr(), N);
    }
    bytes
}

fn pod_from_bytes<T: Copy, const N: usize>(bytes: &[u8; N]) -> T {
    assert_eq!(std::mem::size_of::<T>(), N);
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), value.as_mut_ptr() as *mut u8, N);
        value.assume_init()
    }
}

struct ParsedFileFilterSnapshot {
    epoch: u64,
    rules: Vec<(FileFilterKey, FileFilterValue)>,
}

fn json_string<'a>(value: &'a serde_json::Value, name: &str) -> anyhow::Result<&'a str> {
    value
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("filter rule field `{name}` must be a non-empty string"))
}

fn decimal_component(value: &str, start: usize, end: usize, name: &str) -> anyhow::Result<u32> {
    value
        .get(start..end)
        .filter(|component| component.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|component| component.parse::<u32>().ok())
        .with_context(|| format!("expiresAt has an invalid {name}"))
}

fn leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

// Howard Hinnant's civil-date conversion, offset so 1970-01-01 is day zero.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month as i64 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn parse_rfc3339_unix_nanos(value: &str) -> anyhow::Result<u128> {
    anyhow::ensure!(
        value.is_ascii() && value.len() >= 20,
        "expiresAt must be RFC3339"
    );
    anyhow::ensure!(
        value.as_bytes().get(4) == Some(&b'-')
            && value.as_bytes().get(7) == Some(&b'-')
            && matches!(value.as_bytes().get(10), Some(b'T' | b't'))
            && value.as_bytes().get(13) == Some(&b':')
            && value.as_bytes().get(16) == Some(&b':'),
        "expiresAt must be RFC3339",
    );
    let year = decimal_component(value, 0, 4, "year")? as i64;
    let month = decimal_component(value, 5, 7, "month")?;
    let day = decimal_component(value, 8, 10, "day")?;
    let hour = decimal_component(value, 11, 13, "hour")?;
    let minute = decimal_component(value, 14, 16, "minute")?;
    let second = decimal_component(value, 17, 19, "second")?;
    anyhow::ensure!(
        (1..=12).contains(&month)
            && (1..=days_in_month(year, month)).contains(&day)
            && hour <= 23
            && minute <= 59
            && second <= 59,
        "expiresAt contains an out-of-range date or time",
    );

    let (time_end, offset_seconds) = if value.ends_with(['Z', 'z']) {
        (value.len() - 1, 0i64)
    } else {
        let position = value
            .get(19..)
            .and_then(|suffix| suffix.rfind(['+', '-']).map(|offset| offset + 19))
            .context("expiresAt must include Z or a numeric offset")?;
        let sign = if value.as_bytes()[position] == b'+' {
            1i64
        } else {
            -1i64
        };
        anyhow::ensure!(
            value.len() == position + 6 && value.as_bytes()[position + 3] == b':',
            "expiresAt has an invalid offset"
        );
        let offset_hour = decimal_component(value, position + 1, position + 3, "offset hour")?;
        let offset_minute = decimal_component(value, position + 4, position + 6, "offset minute")?;
        anyhow::ensure!(
            offset_hour <= 23 && offset_minute <= 59,
            "expiresAt has an out-of-range offset"
        );
        (
            position,
            sign * (offset_hour as i64 * 3_600 + offset_minute as i64 * 60),
        )
    };

    let fraction = value.get(19..time_end).unwrap_or_default();
    let fraction_nanos = if fraction.is_empty() {
        0u32
    } else {
        anyhow::ensure!(
            fraction.starts_with('.') && fraction.len() > 1,
            "expiresAt has an invalid fraction"
        );
        let digits = &fraction[1..];
        anyhow::ensure!(
            digits.bytes().all(|byte| byte.is_ascii_digit()),
            "expiresAt has an invalid fraction"
        );
        let mut nanos = 0u32;
        for (index, byte) in digits.bytes().take(9).enumerate() {
            nanos += u32::from(byte - b'0') * 10u32.pow(8 - index as u32);
        }
        nanos
    };

    let unix_seconds = days_from_civil(year, month, day) as i128 * 86_400
        + hour as i128 * 3_600
        + minute as i128 * 60
        + second as i128
        - offset_seconds as i128;
    anyhow::ensure!(unix_seconds >= 0, "expiresAt predates the Unix epoch");
    Ok(unix_seconds as u128 * 1_000_000_000 + fraction_nanos as u128)
}

fn parse_filter_rule_snapshot(
    bytes: &[u8],
    now_unix_ns: u128,
    now_boot_ns: u64,
) -> anyhow::Result<ParsedFileFilterSnapshot> {
    anyhow::ensure!(
        bytes.len() as u64 <= FILTER_RULE_SNAPSHOT_MAX_BYTES,
        "filter rule snapshot exceeds 4 MiB"
    );
    let document: serde_json::Value =
        serde_json::from_slice(bytes).context("parse filter rule snapshot JSON")?;
    anyhow::ensure!(
        json_string(&document, "schemaVersion")? == FILTER_RULE_SNAPSHOT_SCHEMA,
        "unsupported filter rule snapshot schema",
    );
    let entries = document
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .context("filter rule snapshot `entries` must be an array")?;
    anyhow::ensure!(
        entries.len() <= FILTER_RULE_SNAPSHOT_MAX_ENTRIES,
        "too many filter rule entries"
    );

    let declared_epoch = document.get("epoch").and_then(serde_json::Value::as_u64);
    let mut epoch = declared_epoch;
    let mut seen = HashSet::with_capacity(entries.len());
    let mut rules = Vec::with_capacity(entries.len());
    for entry in entries {
        let cgroup_id = json_string(entry, "cgroupId")?
            .parse::<u64>()
            .context("filter rule cgroupId must be an unsigned decimal integer")?;
        anyhow::ensure!(cgroup_id != 0, "filter rule cgroupId must be non-zero");
        anyhow::ensure!(
            seen.insert(cgroup_id),
            "filter rule snapshot contains a duplicate cgroupId"
        );
        let entry_epoch = entry
            .get("epoch")
            .and_then(serde_json::Value::as_u64)
            .context("filter rule epoch must be an unsigned integer")?;
        anyhow::ensure!(entry_epoch != 0, "filter rule epoch must be non-zero");
        if let Some(expected) = epoch {
            anyhow::ensure!(expected == entry_epoch, "filter rule snapshot mixes epochs");
        } else {
            epoch = Some(entry_epoch);
        }
        let action = match json_string(entry, "action")? {
            "keep" => FILE_FILTER_ACTION_KEEP,
            "sample" => FILE_FILTER_ACTION_SAMPLE,
            "drop" => FILE_FILTER_ACTION_DROP,
            _ => anyhow::bail!("filter rule action must be keep, sample, or drop"),
        };
        let authority = match json_string(entry, "authority")? {
            "authoritative" => FILE_FILTER_AUTHORITY_AUTHORITATIVE,
            "candidate" => FILE_FILTER_AUTHORITY_CANDIDATE,
            _ => anyhow::bail!("filter rule authority must be authoritative or candidate"),
        };
        // A candidate may preserve or sample evidence, but can never authorize a kernel-side drop.
        let safe_action = if action == FILE_FILTER_ACTION_DROP
            && authority != FILE_FILTER_AUTHORITY_AUTHORITATIVE
        {
            FILE_FILTER_ACTION_SAMPLE
        } else {
            action
        };
        let expires_unix_ns = parse_rfc3339_unix_nanos(json_string(entry, "expiresAt")?)?;
        let remaining_ns = expires_unix_ns.saturating_sub(now_unix_ns);
        let expires_at_boot_ns =
            now_boot_ns.saturating_add(remaining_ns.min(u64::MAX as u128) as u64);
        let key = FileFilterKey {
            cgroup_id,
            epoch: entry_epoch,
        };
        let value = FileFilterValue {
            action: safe_action,
            authority,
            flags: 0,
            _reserved: 0,
            epoch: entry_epoch,
            expires_at_boot_ns,
        };
        rules.push((key, value));
    }
    let epoch = epoch.context("an empty filter snapshot must declare a top-level epoch")?;
    anyhow::ensure!(epoch != 0, "filter rule epoch must be non-zero");
    Ok(ParsedFileFilterSnapshot { epoch, rules })
}

struct FileFilterMapManager {
    rules: BpfHashMap<MapData, FileFilterKeyBytes, FileFilterValueBytes>,
    config: Array<MapData, FileFilterConfigBytes>,
    installed_keys: Vec<FileFilterKeyBytes>,
    active_epoch: u64,
    enabled: bool,
    unknown_policy: UnknownFilePolicy,
    sample_window_ns: u64,
    unknown_per_cgroup_limit: u32,
    unknown_per_cpu_limit: u32,
}

impl FileFilterMapManager {
    fn new(
        rules: BpfHashMap<MapData, FileFilterKeyBytes, FileFilterValueBytes>,
        config: Array<MapData, FileFilterConfigBytes>,
        enabled: bool,
        unknown_policy: UnknownFilePolicy,
    ) -> anyhow::Result<Self> {
        let per_cgroup = bounded_env_u64(
            "A3S_OBSERVER_FILE_UNKNOWN_PER_CGROUP",
            DEFAULT_UNKNOWN_PER_CGROUP as u64,
            1,
            100_000,
        ) as u32;
        let per_node = bounded_env_u64(
            "A3S_OBSERVER_FILE_UNKNOWN_PER_NODE",
            DEFAULT_UNKNOWN_PER_NODE as u64,
            1,
            10_000_000,
        );
        let cpus = aya::util::nr_cpus().map(|value| value.max(1)).unwrap_or(1) as u64;
        let per_cpu = per_node.div_ceil(cpus).min(u32::MAX as u64) as u32;
        let window_ms = bounded_env_u64(
            "A3S_OBSERVER_FILE_SAMPLE_WINDOW_MS",
            DEFAULT_UNKNOWN_WINDOW_MS,
            100,
            60_000,
        );
        let mut manager = Self {
            rules,
            config,
            installed_keys: Vec::new(),
            active_epoch: 0,
            enabled,
            unknown_policy,
            sample_window_ns: window_ms.saturating_mul(1_000_000),
            unknown_per_cgroup_limit: per_cgroup,
            unknown_per_cpu_limit: per_cpu.max(1),
        };
        manager.write_config(0)?;
        Ok(manager)
    }

    fn write_config(&mut self, epoch: u64) -> anyhow::Result<()> {
        let mut flags = 0;
        if self.enabled {
            flags |= FILE_FILTER_CONFIG_ENABLED;
        }
        if self.unknown_policy.sampling_enabled() {
            flags |= FILE_FILTER_CONFIG_UNKNOWN_SAMPLE;
        }
        let config = FileFilterConfig {
            active_epoch: epoch,
            sample_window_ns: self.sample_window_ns,
            unknown_per_cgroup_limit: self.unknown_per_cgroup_limit,
            unknown_per_cpu_limit: self.unknown_per_cpu_limit,
            flags,
            _reserved: [0; 7],
        };
        self.config
            .set(0, pod_bytes::<_, 32>(&config), 0)
            .context("write FILE_FILTER_CONFIG")
    }

    fn apply(&mut self, snapshot: ParsedFileFilterSnapshot) -> anyhow::Result<usize> {
        anyhow::ensure!(
            snapshot.epoch > self.active_epoch,
            "filter rule epoch must increase monotonically"
        );
        let mut inserted = Vec::with_capacity(snapshot.rules.len());
        for (key, value) in &snapshot.rules {
            let key_bytes = pod_bytes::<_, 16>(key);
            let value_bytes = pod_bytes::<_, 24>(value);
            if let Err(error) = self.rules.insert(key_bytes, value_bytes, 0) {
                for rollback_key in &inserted {
                    let _ = self.rules.remove(rollback_key);
                }
                return Err(error).context("populate next FILE_FILTER_RULES epoch");
            }
            inserted.push(key_bytes);
        }

        if let Err(error) = self.write_config(snapshot.epoch) {
            for rollback_key in &inserted {
                let _ = self.rules.remove(rollback_key);
            }
            return Err(error);
        }

        let previous = std::mem::replace(&mut self.installed_keys, inserted);
        self.active_epoch = snapshot.epoch;
        for old_key in previous {
            let _ = self.rules.remove(&old_key);
        }
        Ok(self.installed_keys.len())
    }
}

struct FileFilterRuleReloader {
    path: PathBuf,
    last_seen: Option<Vec<u8>>,
    last_error: String,
}

impl FileFilterRuleReloader {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            last_seen: None,
            last_error: String::new(),
        }
    }

    fn read_changed(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        let metadata = std::fs::metadata(&self.path)
            .with_context(|| format!("read filter snapshot metadata at {}", self.path.display()))?;
        anyhow::ensure!(
            metadata.len() <= FILTER_RULE_SNAPSHOT_MAX_BYTES,
            "filter rule snapshot exceeds 4 MiB"
        );
        let bytes = std::fs::read(&self.path)
            .with_context(|| format!("read filter snapshot at {}", self.path.display()))?;
        if self.last_seen.as_deref() == Some(bytes.as_slice()) {
            return Ok(None);
        }
        self.last_seen = Some(bytes.clone());
        Ok(Some(bytes))
    }

    fn reload(&mut self, manager: &mut FileFilterMapManager) -> anyhow::Result<Option<usize>> {
        let Some(bytes) = self.read_changed()? else {
            return Ok(None);
        };
        let parsed =
            parse_filter_rule_snapshot(&bytes, system_now_unix_ns()?, monotonic_now_ns()?)?;
        manager.apply(parsed).map(Some)
    }
}

fn finish_capture_profile_ack(
    manager: &mut CaptureMapManager,
    snapshot: &capture_profile::ParsedCaptureSnapshot,
    generation: &CollectorGeneration,
    ack_path: &Path,
    preview_receipt: &mut Option<PreviewReceipt>,
) -> anyhow::Result<()> {
    let applied_at = rfc3339_now()?;
    let applied = ack_document(snapshot, generation, "applied", Vec::new(), &applied_at);
    if let Err(error) = write_ack_atomic(ack_path, &applied) {
        // The kernel generation is already safe/non-destructive. Never open DROP unless the ACK is
        // durably visible to the Forwarder, and retry this exact ACK on the next reload tick.
        manager.revoke_destructive(snapshot.expires_at_boot_ns)?;
        return Err(error).context("write capture profile ACK");
    }
    if snapshot.destructive_granted && snapshot.downgrades.is_empty() {
        if let Err(error) = manager.enable_destructive(snapshot) {
            manager.revoke_destructive(snapshot.expires_at_boot_ns)?;
            let rejected = ack_document(
                snapshot,
                generation,
                "rejected",
                vec![format!("kernel_activation_failed:{error}")],
                &rfc3339_now()?,
            );
            let _ = write_ack_atomic(ack_path, &rejected);
            return Err(error).context("activate ACK-fenced destructive capture actions");
        }
    }
    if snapshot.activation_mode == "preview" && snapshot.downgrades.is_empty() {
        *preview_receipt = Some(PreviewReceipt {
            collector_instance_id: generation.collector_instance_id.clone(),
            host_boot_id: generation.host_boot_id.clone(),
            publisher_instance_id: snapshot.publisher_instance_id.clone(),
            epoch: snapshot.epoch,
            content_hash: snapshot.content_hash.clone(),
            intent_hash: snapshot.intent_hash.clone(),
        });
    } else {
        // A grant is single-use and must refer to the immediately preceding clean preview ACK.
        // Any intervening enforce/degraded snapshot invalidates the in-memory receipt.
        *preview_receipt = None;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn reload_capture_profile(
    reloader: &mut FileFilterRuleReloader,
    manager: &mut CaptureMapManager,
    mode: CaptureProfileMode,
    generation: &CollectorGeneration,
    ack_path: &Path,
    preview_receipt: &mut Option<PreviewReceipt>,
    pending_ack: &mut Option<capture_profile::ParsedCaptureSnapshot>,
    aggregate_reader: Option<&mut CaptureAggregateReader>,
) -> anyhow::Result<Option<usize>> {
    if let Some(snapshot) = pending_ack.as_ref() {
        finish_capture_profile_ack(manager, snapshot, generation, ack_path, preview_receipt)?;
        let entries = snapshot.entries_applied;
        *pending_ack = None;
        return Ok(Some(entries));
    }
    let Some(bytes) = reloader.read_changed()? else {
        return Ok(None);
    };
    let mut parsed = match parse_snapshot(
        &bytes,
        mode,
        generation,
        preview_receipt.as_ref(),
        system_now_unix_ns()?,
        monotonic_now_ns()?,
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            manager.revoke_destructive(0)?;
            let rejected =
                rejected_ack_document(&bytes, generation, &error.to_string(), &rfc3339_now()?);
            write_ack_atomic(ack_path, &rejected).context("write rejected capture profile ACK")?;
            return Err(error);
        }
    };
    if let Some(reader) = aggregate_reader {
        reader.register_snapshot(&parsed);
    }
    if let Err(error) = manager.apply_safe(&mut parsed) {
        let rejected = ack_document(
            &parsed,
            generation,
            "rejected",
            vec![format!("kernel_apply_failed:{error}")],
            &rfc3339_now()?,
        );
        write_ack_atomic(ack_path, &rejected).context("write kernel rejection ACK")?;
        return Err(error);
    }
    if let Err(error) =
        finish_capture_profile_ack(manager, &parsed, generation, ack_path, preview_receipt)
    {
        *pending_ack = Some(parsed);
        return Err(error);
    }
    Ok(Some(parsed.entries_applied))
}

fn aggregate_file_filter_stats(
    map: &PerCpuArray<MapData, FileFilterStatsBytes>,
) -> FileFilterStats {
    let mut aggregate = FileFilterStats::default();
    let Ok(values) = map.get(&0, 0) else {
        return aggregate;
    };
    for bytes in values.iter() {
        let item = pod_from_bytes::<FileFilterStats, 104>(bytes);
        aggregate.access_kept = aggregate.access_kept.saturating_add(item.access_kept);
        aggregate.access_unknown_kept = aggregate
            .access_unknown_kept
            .saturating_add(item.access_unknown_kept);
        aggregate.access_sampled = aggregate.access_sampled.saturating_add(item.access_sampled);
        aggregate.access_dropped = aggregate.access_dropped.saturating_add(item.access_dropped);
        aggregate.access_sample_suppressed = aggregate
            .access_sample_suppressed
            .saturating_add(item.access_sample_suppressed);
        aggregate.delete_kept = aggregate.delete_kept.saturating_add(item.delete_kept);
        aggregate.delete_unknown_kept = aggregate
            .delete_unknown_kept
            .saturating_add(item.delete_unknown_kept);
        aggregate.delete_dropped = aggregate.delete_dropped.saturating_add(item.delete_dropped);
        aggregate.rule_hits = aggregate.rule_hits.saturating_add(item.rule_hits);
        aggregate.rule_misses = aggregate.rule_misses.saturating_add(item.rule_misses);
        aggregate.stale_rules = aggregate.stale_rules.saturating_add(item.stale_rules);
        aggregate.access_ring_dropped = aggregate
            .access_ring_dropped
            .saturating_add(item.access_ring_dropped);
        aggregate.delete_ring_dropped = aggregate
            .delete_ring_dropped
            .saturating_add(item.delete_ring_dropped);
    }
    aggregate
}

fn aggregate_capture_probe_stats(
    map: &PerCpuArray<MapData, CaptureProbeStatsBytes>,
) -> Vec<CollectorCaptureProbeStats> {
    capture_profile::PROBE_NAMES
        .iter()
        .enumerate()
        .map(|(index, probe)| {
            let mut total = CaptureProbeStats::default();
            if let Ok(values) = map.get(&(index as u32), 0) {
                for bytes in values.iter() {
                    let item = pod_from_bytes::<CaptureProbeStats, 184>(bytes);
                    macro_rules! add {
                        ($field:ident) => {
                            total.$field = total.$field.saturating_add(item.$field)
                        };
                    }
                    add!(attempted);
                    add!(full_selected);
                    add!(aggregate_selected);
                    add!(sample_selected);
                    add!(sample_rejected);
                    add!(drop_selected);
                    add!(not_enabled);
                    add!(decision_error);
                    add!(probe_error);
                    add!(payload_selected);
                    add!(payload_error);
                    add!(ring_submitted);
                    add!(ring_dropped);
                    add!(would_full);
                    add!(would_aggregate);
                    add!(would_sample);
                    add!(would_drop);
                    add!(rule_hit);
                    add!(rule_miss);
                    add!(stale_rule);
                    add!(promotion_hit);
                    add!(promotion_error);
                    add!(aggregate_error);
                }
            }
            CollectorCaptureProbeStats {
                probe: (*probe).to_string(),
                attempted: total.attempted,
                full_selected: total.full_selected,
                aggregate_selected: total.aggregate_selected,
                sample_selected: total.sample_selected,
                sample_rejected: total.sample_rejected,
                drop_selected: total.drop_selected,
                not_enabled: total.not_enabled,
                decision_error: total.decision_error,
                probe_error: total.probe_error,
                payload_selected: total.payload_selected,
                payload_error: total.payload_error,
                ring_submitted: total.ring_submitted,
                ring_dropped: total.ring_dropped,
                would_full: total.would_full,
                would_aggregate: total.would_aggregate,
                would_sample: total.would_sample,
                would_drop: total.would_drop,
                rule_hit: total.rule_hit,
                rule_miss: total.rule_miss,
                stale_rule: total.stale_rule,
                promotion_hit: total.promotion_hit,
                promotion_error: total.promotion_error,
                aggregate_error: total.aggregate_error,
            }
        })
        .collect()
}

fn capture_profile_heartbeat(
    manager: Option<&CaptureMapManager>,
    stats: Option<&PerCpuArray<MapData, CaptureProbeStatsBytes>>,
    aggregates: Option<&CaptureAggregateReader>,
) -> Option<CollectorCaptureProfileStats> {
    let (manager, stats) = (manager?, stats?);
    let aggregate = aggregates
        .map(CaptureAggregateReader::stats)
        .unwrap_or_default();
    let probes = aggregate_capture_probe_stats(stats);
    let aggregate_ledger_degraded =
        aggregate.read_errors != 0 || probes.iter().any(|probe| probe.aggregate_error != 0);
    Some(CollectorCaptureProfileStats {
        mode: manager.mode().name().to_string(),
        active_epoch: manager.active_epoch,
        destructive_enabled: manager.destructive_effective(monotonic_now_ns().unwrap_or(u64::MAX)),
        decision_unit: "decision_op".to_string(),
        payload_unit: "single_record_candidate".to_string(),
        delivery_unit: "physical_record".to_string(),
        sample_node_limit_per_window: manager.sample_node_limit(),
        aggregate_keys: aggregate.keys,
        aggregate_emitted: aggregate.emitted,
        aggregate_output_retried: aggregate.output_retried,
        aggregate_cleaned: aggregate.cleaned,
        aggregate_read_errors: aggregate.read_errors,
        aggregate_ledger_degraded,
        probes,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PipelineRing {
    Exec,
    Exit,
    Tls,
    Connect,
    Dns,
    FileAccess,
    FileRead,
    FileDelete,
    Llm,
    Ssl,
    Security,
}

impl PipelineRing {
    const ALL: [Self; PIPELINE_RING_COUNT] = [
        Self::Exec,
        Self::Exit,
        Self::Tls,
        Self::Connect,
        Self::Dns,
        Self::FileAccess,
        Self::FileRead,
        Self::FileDelete,
        Self::Llm,
        Self::Ssl,
        Self::Security,
    ];

    const fn index(self) -> u32 {
        match self {
            Self::Exec => PIPELINE_RING_EXEC,
            Self::Exit => PIPELINE_RING_EXIT,
            Self::Tls => PIPELINE_RING_TLS,
            Self::Connect => PIPELINE_RING_CONNECT,
            Self::Dns => PIPELINE_RING_DNS,
            Self::FileAccess => PIPELINE_RING_FILE_ACCESS,
            Self::FileRead => PIPELINE_RING_FILE_READ,
            Self::FileDelete => PIPELINE_RING_FILE_DELETE,
            Self::Llm => PIPELINE_RING_LLM,
            Self::Ssl => PIPELINE_RING_SSL,
            Self::Security => PIPELINE_RING_SECURITY,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::Exit => "exit",
            Self::Tls => "tls",
            Self::Connect => "connect",
            Self::Dns => "dns",
            Self::FileAccess => "file_access",
            Self::FileRead => "file_read",
            Self::FileDelete => "file_delete",
            Self::Llm => "llm",
            Self::Ssl => "ssl",
            Self::Security => "security",
        }
    }

    const fn export_priority(self) -> ExportPriority {
        match self {
            Self::Exec | Self::Exit | Self::FileDelete | Self::Security => ExportPriority::Critical,
            Self::FileRead => ExportPriority::Bulk,
            Self::Tls | Self::Connect | Self::Dns | Self::FileAccess | Self::Llm | Self::Ssl => {
                ExportPriority::Semantic
            }
        }
    }
}

impl From<RingOrigin> for PipelineRing {
    fn from(origin: RingOrigin) -> Self {
        match origin {
            RingOrigin::Exec => Self::Exec,
            RingOrigin::Exit => Self::Exit,
            RingOrigin::Tls => Self::Tls,
            RingOrigin::Connect => Self::Connect,
            RingOrigin::Dns => Self::Dns,
            RingOrigin::FileAccess => Self::FileAccess,
            RingOrigin::FileRead => Self::FileRead,
            RingOrigin::FileDelete => Self::FileDelete,
            RingOrigin::Llm => Self::Llm,
            RingOrigin::Ssl => Self::Ssl,
            RingOrigin::Security => Self::Security,
        }
    }
}

fn ring_reader_index(origin: RingOrigin) -> usize {
    PipelineRing::from(origin).index() as usize
}

fn spawn_ring_reader(
    readers: &mut JoinSet<(RingOrigin, std::io::Result<()>)>,
    origin: RingOrigin,
    ring: RingBuf<MapData>,
    sender: PipelineSender,
    ready: Arc<Notify>,
    shutdown: watch::Receiver<bool>,
    ledger: Arc<RingReaderLedger>,
) {
    readers.spawn(async move {
        let result = run_ring_reader(origin, ring, sender, ready, shutdown, ledger).await;
        (origin, result)
    });
}

fn snapshot_ring_readers(
    ledgers: &[Arc<RingReaderLedger>; PIPELINE_RING_COUNT],
) -> [RingReaderLedgerSnapshot; PIPELINE_RING_COUNT] {
    std::array::from_fn(|index| ledgers[index].snapshot())
}

fn aggregate_ring_pipeline_stats(
    map: &PerCpuArray<MapData, RingPipelineStatsBytes>,
) -> [RingPipelineStats; PIPELINE_RING_COUNT] {
    let mut aggregate = [RingPipelineStats::default(); PIPELINE_RING_COUNT];
    for ring in PipelineRing::ALL {
        let Ok(values) = map.get(&ring.index(), 0) else {
            continue;
        };
        let target = &mut aggregate[ring.index() as usize];
        for bytes in values.iter() {
            let item = pod_from_bytes::<RingPipelineStats, 16>(bytes);
            target.submitted = target.submitted.saturating_add(item.submitted);
            target.dropped = target.dropped.saturating_add(item.dropped);
        }
    }
    aggregate
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
        comm: &str,
        now: Instant,
    ) -> Option<ProcessContext> {
        let cached = self.entries.get(&pid)?;
        let valid = now.duration_since(cached.refreshed_at) <= PROCESS_CONTEXT_CACHE_TTL
            && cached.context.cgroup_id == cgroup_id
            && (comm.is_empty() || cached.context.comm == comm);
        if valid {
            self.hits += 1;
            Some(cached.context.clone())
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
    event_at_unix_ns: u128,
    received_at_unix_ns: u128,
    capture_decision: CaptureDecisionContext,
    exec_id: u64,
    cgroup_id: u64,
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
    chunks: HashMap<u16, BTreeMap<u16, Vec<u8>>>,
}

impl PendingExec {
    fn new(
        record: &ExecRecord,
        event_at_unix_ns: u128,
        received_at_unix_ns: u128,
        capture_decision: CaptureDecisionContext,
        now: Instant,
    ) -> Self {
        Self {
            first_seen: now,
            event_at_unix_ns,
            received_at_unix_ns,
            capture_decision,
            exec_id: record.exec_id,
            cgroup_id: record.cgroup_id,
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
            chunks: HashMap::new(),
        }
    }

    fn apply(
        &mut self,
        record: &ExecRecord,
        event_at_unix_ns: u128,
        received_at_unix_ns: u128,
        capture_decision: CaptureDecisionContext,
    ) {
        self.received_at_unix_ns = self.received_at_unix_ns.max(received_at_unix_ns);
        self.flags |= record.flags;
        if self.capture_decision != capture_decision {
            // One logical exec must retain the syscall-entry decision through every fragment and
            // COMMIT. Preserve the first decision and surface any inconsistency as incomplete.
            self.flags |= EXEC_FLAG_ARGV_INCOMPLETE;
        }
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
            EXEC_RECORD_END => {
                self.argc = Some(record.argc.min(ARGV_SLOTS as u16));
                self.captured_bytes = Some(record.captured_bytes);
            }
            EXEC_RECORD_COMMIT => {
                self.saw_commit = true;
                // sys_enter_execve carries pre-commit facts. sched_process_exec is authoritative
                // for the successfully installed image and its event-time scope.
                self.event_at_unix_ns = event_at_unix_ns;
                self.comm = record.comm;
                self.cgroup_id = record.cgroup_id;
                self.uid = record.uid;
                if record.ppid != 0 {
                    self.ppid = record.ppid;
                }
            }
            _ => self.flags |= EXEC_FLAG_ARGV_INCOMPLETE,
        }
    }

    fn finish(mut self, timed_out: bool) -> CompletedExec {
        let mut argv_incomplete = timed_out
            || !self.saw_header
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
            event_at_unix_ns: self.event_at_unix_ns,
            received_at_unix_ns: self.received_at_unix_ns,
            capture_decision: self.capture_decision,
            exec_id: self.exec_id,
            cgroup_id: self.cgroup_id,
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
            reassembly_timed_out: timed_out && (self.argc.is_none() || !self.saw_header),
            exec_confirmed: self.saw_commit,
        }
    }
}

struct CompletedExec {
    event_at_unix_ns: u128,
    received_at_unix_ns: u128,
    capture_decision: CaptureDecisionContext,
    exec_id: u64,
    cgroup_id: u64,
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

    #[cfg(test)]
    fn push(&mut self, record: ExecRecord, now: Instant) -> Vec<CompletedExec> {
        // Test/compatibility helper for callers without the ring envelope. Production always uses
        // `push_timed`, where monotonic time has already been calibrated to Unix time.
        let fallback = u128::from(record.captured_at_boot_ns);
        let capture_decision = record.capture_decision;
        self.push_timed(record, fallback, fallback, capture_decision, now)
    }

    fn push_timed(
        &mut self,
        record: ExecRecord,
        event_at_unix_ns: u128,
        received_at_unix_ns: u128,
        capture_decision: CaptureDecisionContext,
        now: Instant,
    ) -> Vec<CompletedExec> {
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
            .or_insert_with(|| {
                PendingExec::new(
                    &record,
                    event_at_unix_ns,
                    received_at_unix_ns,
                    capture_decision,
                    now,
                )
            })
            .apply(
                &record,
                event_at_unix_ns,
                received_at_unix_ns,
                capture_decision,
            );
        // All syscall-entry fragments use the same ring and are submitted before the successful
        // sched_process_exec COMMIT. Once COMMIT is observed, waiting cannot recover a missing
        // END record; finish immediately as incomplete so a later timeout cannot resurrect a
        // lifecycle generation already consumed by ProcessExit.
        let ready = self.pending.get(&key).is_some_and(|pending| {
            if self.require_commit {
                pending.saw_commit
            } else {
                pending.argc.is_some()
            }
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
        Some("--help" | "-h") => {
            println!(
                "a3s-observer-collector {} — language-agnostic eBPF observability for AI agents\n\n\
                 Run as root / CAP_BPF+CAP_PERFMON (Linux). Configure via env:\n  \
                 A3S_OBSERVER_JSON=1    emit NDJSON (default: human-readable log)\n  \
                 A3S_OBSERVER_FILES=1   capture FileAccess + FileDelete (legacy combined switch)\n  \
                 A3S_OBSERVER_FILE_ACCESS=1  override FileAccess capture independently\n  \
                 A3S_OBSERVER_FILE_DELETE=1  override FileDelete capture independently\n  \
                 ANYSENTRY_FILTER_RULES_FILE=/path/rules.json  hot-reload cgroup file filtering\n  \
                 A3S_OBSERVER_FILE_UNKNOWN_POLICY=keep|sample  unresolved FileAccess policy \
                 (default: keep; sample is compatibility-only)\n  \
                 A3S_OBSERVER_SSL=1     also capture OpenSSL plaintext — prompts/responses \
                 (uprobe, OpenSSL-only, off by default; or set a libssl path)",
                env!("CARGO_PKG_VERSION")
            );
            return Ok(());
        }
        _ => {}
    }
    // Logs go to STDERR so STDOUT stays pure NDJSON (the event stream a pipeline parses). The
    // explicit TLS diagnostics switch raises only the subscriber ceiling; call-level diagnostics
    // remain behind their own gate and are never enabled by a generic RUST_LOG value alone.
    let diagnostic_level = if tls_diagnostics_enabled() {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(diagnostic_level)
        .init();

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/probes"
    )))
    .context("load eBPF object")?;
    // The rule maps are initialized before file probes attach. With no rules file configured the
    // config remains disabled and preserves the historical full-capture behavior. Supplying a path
    // enables authoritative decisions; Unknown remains fail-open unless compatibility sampling is
    // explicitly requested.
    let filter_rules_path = env_any(&["ANYSENTRY_FILTER_RULES_FILE"]).map(PathBuf::from);
    let capture_profile_mode = CaptureProfileMode::parse(
        std::env::var("ANYSENTRY_CAPTURE_PROFILE_MODE")
            .ok()
            .as_deref(),
    )?;
    let unknown_file_policy = unknown_file_policy_from_env();
    let filter_rules = BpfHashMap::try_from(
        ebpf.take_map("FILE_FILTER_RULES")
            .context("`FILE_FILTER_RULES` missing")?,
    )?;
    let filter_config = Array::try_from(
        ebpf.take_map("FILE_FILTER_CONFIG")
            .context("`FILE_FILTER_CONFIG` missing")?,
    )?;
    let file_filter_stats: PerCpuArray<_, FileFilterStatsBytes> = PerCpuArray::try_from(
        ebpf.take_map("FILE_FILTER_STATS")
            .context("`FILE_FILTER_STATS` missing")?,
    )?;
    let mut file_filter = FileFilterMapManager::new(
        filter_rules,
        filter_config,
        filter_rules_path.is_some() && capture_profile_mode == CaptureProfileMode::Legacy,
        unknown_file_policy,
    )?;
    let mut filter_reloader = (capture_profile_mode == CaptureProfileMode::Legacy)
        .then(|| filter_rules_path.clone().map(FileFilterRuleReloader::new))
        .flatten();
    if let Some(reloader) = filter_reloader.as_mut() {
        match reloader.reload(&mut file_filter) {
            Ok(Some(entries)) => tracing::info!(
                epoch = file_filter.active_epoch,
                entries,
                path = %reloader.path.display(),
                "loaded initial file filter snapshot"
            ),
            Ok(None) => {}
            Err(error) => {
                reloader.last_error = error.to_string();
                tracing::warn!(
                    path = %reloader.path.display(),
                    error = %error,
                    unknown_policy = file_filter.unknown_policy.name(),
                    "initial file filter snapshot unavailable; retaining the configured Unknown policy"
                );
            }
        }
    }

    let mut capture_profile = if capture_profile_mode == CaptureProfileMode::Legacy {
        None
    } else {
        let rules = BpfHashMap::try_from(
            ebpf.take_map("CAPTURE_PROFILE_RULES")
                .context("`CAPTURE_PROFILE_RULES` missing")?,
        )?;
        let config = Array::try_from(
            ebpf.take_map("CAPTURE_PROFILE_CONFIG")
                .context("`CAPTURE_PROFILE_CONFIG` missing")?,
        )?;
        let promotions = BpfHashMap::try_from(
            ebpf.take_map("CAPTURE_PROMOTED_PROCESSES")
                .context("`CAPTURE_PROMOTED_PROCESSES` missing")?,
        )?;
        let cpu_count = aya::util::nr_cpus()
            .map(|value| value.max(1))
            .unwrap_or(1)
            .min(u16::MAX as usize) as u16;
        Some(CaptureMapManager::new(
            rules,
            config,
            promotions,
            capture_profile_mode,
            bounded_env_u64("ANYSENTRY_CAPTURE_SAMPLE_WINDOW_MS", 1_000, 100, 60_000)
                .saturating_mul(1_000_000),
            bounded_env_u64(
                "ANYSENTRY_CAPTURE_INVESTIGATION_TTL_MS",
                300_000,
                1_000,
                86_400_000,
            )
            .saturating_mul(1_000_000),
            bounded_env_u64("ANYSENTRY_CAPTURE_SAMPLE_PER_SCOPE", 20, 1, 100_000) as u32,
            bounded_env_u64("ANYSENTRY_CAPTURE_SAMPLE_PER_NODE", 1_000, 1, 10_000_000) as u32,
            bounded_env_u64("ANYSENTRY_CAPTURE_FIRST_SAMPLES", 2, 1, 100) as u16,
            cpu_count,
        )?)
    };
    let mut capture_reloader = (capture_profile_mode != CaptureProfileMode::Legacy)
        .then(|| filter_rules_path.clone().map(FileFilterRuleReloader::new))
        .flatten();

    // File capture is opt-in. New per-kind switches override the legacy combined switch so delete
    // can remain enabled while high-volume write-open capture is disabled.
    let file_features = file_feature_flags();
    let mut probes = vec![
        ("track_clone", "sys_exit_clone"),
        ("track_clone3", "sys_exit_clone3"),
        ("track_fork", "sys_exit_fork"),
        ("track_vfork", "sys_exit_vfork"),
        ("exec", "sys_enter_execve"),
        ("tls_write", "sys_enter_write"),
        ("tls_sendto", "sys_enter_sendto"),
        ("http_writev", "sys_enter_writev"),
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
    if file_features.access {
        probes.extend(FILE_ACCESS_TRACEPOINTS);
    }
    if file_features.delete {
        probes.push(("file_unlink", "sys_enter_unlinkat"));
        probes.push(("file_unlink_legacy", "sys_enter_unlink"));
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

    // Opt-in TLS plaintext capture. `1`/`auto` scans selected Agent processes and resolves their
    // mapped libraries or main executable; an absolute path preserves the explicit legacy target.
    let ssl_setting = std::env::var("A3S_OBSERVER_SSL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && !env_value_disabled(value));
    let verified_processes = BpfHashMap::try_from(
        ebpf.take_map("VERIFIED_AGENT_PROCESSES")
            .context("`VERIFIED_AGENT_PROCESSES` missing")?,
    )?;
    let mut verified_process_map = VerifiedProcessMap::new(verified_processes);
    let mut tls_attach_manager = ssl_setting.as_deref().map(TlsAttachManager::from_env);
    let tls_agent_scope_path = ssl_setting.as_ref().and_then(|_| {
        env_any(&["ANYSENTRY_TLS_AGENT_CGROUPS_FILE"])
            .map(PathBuf::from)
            .or_else(|| {
                filter_rules_path
                    .as_ref()
                    .and_then(|path| path.parent())
                    .map(|parent| parent.join("tls-agent-cgroups.json"))
            })
    });
    let mut tls_agent_scope_reloader = tls_agent_scope_path.map(TlsAgentScopeReloader::new);
    if let Some(manager) = tls_attach_manager.as_mut() {
        attached = attached.saturating_add(refresh_tls_attachments(
            manager,
            &mut verified_process_map,
            &mut ebpf,
        ));
    }

    // A3S_OBSERVER_JSON=1 → NDJSON (pipe to vector/Loki/jq); otherwise human-readable log.
    let exporter: Box<dyn Exporter> = if env_enabled("A3S_OBSERVER_JSON") {
        Box::new(JsonExporter::new())
    } else {
        Box::new(LogExporter)
    };
    let classifier = SniClassifier;
    let resolver = KubeResolver; // cgroup→pod in k8s; falls back to comm on bare hosts
    let exec_ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("`EVENTS` missing")?)?;
    let exit_ring = RingBuf::try_from(
        ebpf.take_map("EXIT_EVENTS")
            .context("`EXIT_EVENTS` missing")?,
    )?;
    let tls_ring = RingBuf::try_from(
        ebpf.take_map("TLS_EVENTS")
            .context("`TLS_EVENTS` missing")?,
    )?;
    let connect_ring = RingBuf::try_from(
        ebpf.take_map("CONNECT_EVENTS")
            .context("`CONNECT_EVENTS` missing")?,
    )?;
    let dns_ring = RingBuf::try_from(
        ebpf.take_map("DNS_EVENTS")
            .context("`DNS_EVENTS` missing")?,
    )?;
    let file_ring = RingBuf::try_from(
        ebpf.take_map("FILE_EVENTS")
            .context("`FILE_EVENTS` missing")?,
    )?;
    let file_read_ring = RingBuf::try_from(
        ebpf.take_map("FILE_READ_EVENTS")
            .context("`FILE_READ_EVENTS` missing")?,
    )?;
    let file_delete_ring = RingBuf::try_from(
        ebpf.take_map("FILE_DELETE_EVENTS")
            .context("`FILE_DELETE_EVENTS` missing")?,
    )?;
    let llm_ring = RingBuf::try_from(
        ebpf.take_map("LLM_EVENTS")
            .context("`LLM_EVENTS` missing")?,
    )?;
    // Opt-in OpenSSL content ring; stays empty unless A3S_OBSERVER_SSL attached the uprobes.
    let ssl_ring = RingBuf::try_from(
        ebpf.take_map("SSL_EVENTS")
            .context("`SSL_EVENTS` missing")?,
    )?;
    let sec_ring = RingBuf::try_from(
        ebpf.take_map("SEC_EVENTS")
            .context("`SEC_EVENTS` missing")?,
    )?;
    // Cumulative count of events dropped because a ring was full (data-loss visibility).
    let drops: PerCpuArray<_, u64> =
        PerCpuArray::try_from(ebpf.take_map("DROPS").context("`DROPS` missing")?)?;
    let tls_profile_diagnostics: PerCpuArray<_, u64> = PerCpuArray::try_from(
        ebpf.take_map("TLS_PROFILE_DIAGNOSTICS")
            .context("`TLS_PROFILE_DIAGNOSTICS` missing")?,
    )?;
    let ring_pipeline_stats: PerCpuArray<_, RingPipelineStatsBytes> = PerCpuArray::try_from(
        ebpf.take_map("PIPELINE_ACCOUNTING")
            .context("`PIPELINE_ACCOUNTING` missing")?,
    )?;
    let capture_profile_stats = if capture_profile_mode == CaptureProfileMode::Legacy {
        None
    } else {
        Some(PerCpuArray::<_, CaptureProbeStatsBytes>::try_from(
            ebpf.take_map("CAPTURE_PROFILE_STATS")
                .context("`CAPTURE_PROFILE_STATS` missing")?,
        )?)
    };
    let mut capture_aggregate_reader = if capture_profile_mode == CaptureProfileMode::Legacy {
        None
    } else {
        let map: PerCpuHashMap<_, [u8; 24], [u8; 16]> = PerCpuHashMap::try_from(
            ebpf.take_map("CAPTURE_AGGREGATES")
                .context("`CAPTURE_AGGREGATES` missing")?,
        )?;
        Some(CaptureAggregateReader::new(map, system_now_unix_ns()?))
    };

    tracing::info!(
        attached,
        total = probes.len() + 3,
        file_access = file_features.access,
        file_delete = file_features.delete,
        file_filter = file_filter.enabled,
        file_filter_epoch = file_filter.active_epoch,
        file_unknown_policy = file_filter.unknown_policy.name(),
        "a3s-observer-collector: probes attached; \
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

    let collector =
        CollectorMeta::from_env(file_features, env_enabled("A3S_OBSERVER_SSL"), attached);
    let collector_started_unix_ms = unix_now_ms_u64();
    let host_boot_id = boot_id().unwrap_or_else(|| "unknown-boot".to_string());
    let collector_instance_id =
        env_any(&["A3S_OBSERVER_PRODUCER_INSTANCE_ID"]).unwrap_or_else(|| {
            format!(
                "{}:{}:{}:{}",
                collector.collector_id,
                host_boot_id,
                std::process::id(),
                collector_started_unix_ms
            )
        });
    let collector_generation = CollectorGeneration {
        node_id: env_any(&["A3S_NODE_ID", "NODE_ID"])
            .or_else(|| collector.node_name.clone())
            .unwrap_or_else(|| collector.collector_id.clone()),
        collector_id: collector.collector_id.clone(),
        collector_instance_id: collector_instance_id.clone(),
        host_boot_id,
    };
    let capture_ack_path = filter_rules_path.as_ref().map(|rules| {
        env_any(&["ANYSENTRY_FILTER_RULES_ACK_FILE"])
            .map(PathBuf::from)
            .unwrap_or_else(|| default_ack_path(rules))
    });
    let mut preview_receipt = None;
    let mut pending_capture_ack = None;
    if let (Some(reloader), Some(manager), Some(ack_path)) = (
        capture_reloader.as_mut(),
        capture_profile.as_mut(),
        capture_ack_path.as_deref(),
    ) {
        match reload_capture_profile(
            reloader,
            manager,
            capture_profile_mode,
            &collector_generation,
            ack_path,
            &mut preview_receipt,
            &mut pending_capture_ack,
            capture_aggregate_reader.as_mut(),
        ) {
            Ok(Some(entries)) => tracing::info!(
                epoch = manager.active_epoch,
                entries,
                mode = capture_profile_mode.name(),
                destructive = manager.destructive_enabled(),
                ack = %ack_path.display(),
                "loaded initial S5 capture profile snapshot"
            ),
            Ok(None) => {}
            Err(error) => tracing::warn!(
                error = %error,
                mode = capture_profile_mode.name(),
                "initial S5 snapshot unavailable; retaining discovery-safe capture"
            ),
        }
    }

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let capacities = InboxCapacities::new(
        bounded_env_u64(
            "A3S_OBSERVER_CRITICAL_INBOX_CAPACITY",
            DEFAULT_CRITICAL_INBOX_CAPACITY as u64,
            64,
            262_144,
        ) as usize,
        bounded_env_u64(
            "A3S_OBSERVER_SEMANTIC_INBOX_CAPACITY",
            DEFAULT_SEMANTIC_INBOX_CAPACITY as u64,
            64,
            262_144,
        ) as usize,
        bounded_env_u64(
            "A3S_OBSERVER_BULK_INBOX_CAPACITY",
            DEFAULT_BULK_INBOX_CAPACITY as u64,
            64,
            262_144,
        ) as usize,
    );
    let reorder_capacity = bounded_env_u64(
        "A3S_OBSERVER_REORDER_CAPACITY",
        DEFAULT_REORDER_CAPACITY as u64,
        1_024,
        1_048_576,
    ) as usize;
    let reorder_window_ns = bounded_env_u64(
        "A3S_OBSERVER_REORDER_WINDOW_NS",
        DEFAULT_REORDER_WINDOW_NS,
        0,
        100_000_000,
    );
    let (pipeline_sender, mut pipeline_receiver) = pipeline_channel(capacities);
    let pipeline_ready = Arc::new(Notify::new());
    let (reader_shutdown, _) = watch::channel(false);
    let reader_ledgers: [Arc<RingReaderLedger>; PIPELINE_RING_COUNT] =
        std::array::from_fn(|_| Arc::new(RingReaderLedger::default()));
    let mut readers = JoinSet::new();
    for (origin, ring) in [
        (RingOrigin::Exec, exec_ring),
        (RingOrigin::Exit, exit_ring),
        (RingOrigin::Tls, tls_ring),
        (RingOrigin::Connect, connect_ring),
        (RingOrigin::Dns, dns_ring),
        (RingOrigin::FileAccess, file_ring),
        (RingOrigin::FileRead, file_read_ring),
        (RingOrigin::FileDelete, file_delete_ring),
        (RingOrigin::Llm, llm_ring),
        (RingOrigin::Ssl, ssl_ring),
        (RingOrigin::Security, sec_ring),
    ] {
        spawn_ring_reader(
            &mut readers,
            origin,
            ring,
            pipeline_sender.clone(),
            pipeline_ready.clone(),
            reader_shutdown.subscribe(),
            reader_ledgers[ring_reader_index(origin)].clone(),
        );
    }
    drop(pipeline_sender);

    let mut processor = CollectorProcessor::new(exec_commit_probe_attached);
    let mut reorder = ReorderCoordinator::new(reorder_capacity, reorder_window_ns);
    let mut stats_window_started = Instant::now();
    let mut pipeline_accounting =
        PipelineAccountingState::new(collector_instance_id, collector_started_unix_ms);
    let initial_pipeline = pipeline_accounting.snapshot(
        &processor.stats,
        snapshot_ring_readers(&reader_ledgers),
        aggregate_ring_pipeline_stats(&ring_pipeline_stats),
        unix_now_ms_u64(),
    );
    let _ = exporter.export_with_priority(
        &collector_heartbeat(
            &collector,
            0,
            &processor.stats,
            0,
            exporter.output_drops(),
            FileFilterHeartbeatSnapshot {
                stats: aggregate_file_filter_stats(&file_filter_stats),
                enabled: file_filter.enabled,
                epoch: file_filter.active_epoch,
                unknown_policy: file_filter.unknown_policy,
            },
            Some(initial_pipeline),
            capture_profile_heartbeat(
                capture_profile.as_ref(),
                capture_profile_stats.as_ref(),
                capture_aggregate_reader.as_ref(),
            ),
            false,
        ),
        ExportPriority::Critical,
    );
    let mut report = tokio::time::interval(Duration::from_secs(60));
    report.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    report.tick().await; // consume the immediate first tick
    let mut filter_reload = tokio::time::interval(FILTER_RULE_RELOAD_INTERVAL);
    filter_reload.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    filter_reload.tick().await;
    let mut tls_attach_scan = tokio::time::interval(Duration::from_secs(2));
    tls_attach_scan.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tls_attach_scan.tick().await;
    let mut processor_tick = tokio::time::interval(PROCESSOR_TICK);
    processor_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    processor_tick.tick().await;
    let mut exec_expire = tokio::time::interval(Duration::from_millis(20));
    exec_expire.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    exec_expire.tick().await;
    let mut reader_failure: Option<String> = None;
    let mut last_tls_profile_diagnostics = [0u64; 21];
    let mut last_tls_agent_scope_error = String::new();
    'collect: loop {
        tokio::select! {
            biased;
            _ = sigint.recv() => break 'collect,
            _ = sigterm.recv() => break 'collect,
            joined = readers.join_next() => {
                reader_failure = Some(match joined {
                    Some(Ok((origin, Ok(())))) => {
                        format!("ring reader {origin:?} exited before collector shutdown")
                    }
                    Some(Ok((origin, Err(error)))) => {
                        format!("ring reader {origin:?} failed: {error}")
                    }
                    Some(Err(error)) => format!("ring reader task failed: {error}"),
                    None => "all ring readers exited before collector shutdown".to_string(),
                });
                break 'collect;
            }
            _ = report.tick() => {
                tokio::task::block_in_place(|| {
                    release_reorder_by_wall_clock(
                        &mut reorder,
                        &mut processor,
                        exporter.as_ref(),
                        &resolver,
                        &classifier,
                        reorder_window_ns,
                    )
                })?;
                let _ = std::fs::write(&heartbeat, b"ok");
                let dropped: u64 = drops
                    .get(&0, 0)
                    .map(|values| values.iter().copied().sum())
                    .unwrap_or(0);
                let tls_profile_snapshot = tls_profile_diagnostic_snapshot(&tls_profile_diagnostics);
                if tls_profile_snapshot != last_tls_profile_diagnostics
                    && (tls_profile_snapshot[0] > 0
                        || tls_profile_snapshot[11] > 0
                        || tls_profile_snapshot[16] > 0)
                {
                    tracing::info!(
                        write_hits = tls_profile_snapshot[0],
                        write_layout_rejected = tls_profile_snapshot[1],
                        write_multiple = tls_profile_snapshot[2],
                        write_single = tls_profile_snapshot[3],
                        write_emit_attempts = tls_profile_snapshot[4],
                        read_hits = tls_profile_snapshot[5],
                        read_layout_rejected = tls_profile_snapshot[6],
                        read_payloads = tls_profile_snapshot[7],
                        unverified_process = tls_profile_snapshot[8],
                        route_rejected = tls_profile_snapshot[9],
                        write_route_candidates = tls_profile_snapshot[10],
                        openssl_ex_entries = tls_profile_snapshot[11],
                        openssl_ex_successes = tls_profile_snapshot[12],
                        openssl_ex_unverified = tls_profile_snapshot[13],
                        openssl_ex_route_rejected = tls_profile_snapshot[14],
                        openssl_ex_capture_rejected = tls_profile_snapshot[15],
                        ssl_classic_entries = tls_profile_snapshot[16],
                        ssl_classic_successes = tls_profile_snapshot[17],
                        ssl_classic_unverified = tls_profile_snapshot[18],
                        ssl_classic_route_rejected = tls_profile_snapshot[19],
                        ssl_classic_capture_rejected = tls_profile_snapshot[20],
                        "TLS plaintext profile diagnostics"
                    );
                    last_tls_profile_diagnostics = tls_profile_snapshot;
                }
                let output_dropped = exporter.output_drops();
                let output_critical_dropped =
                    exporter.output_drops_by_priority(ExportPriority::Critical);
                let output_semantic_dropped =
                    exporter.output_drops_by_priority(ExportPriority::Semantic);
                let output_bulk_dropped =
                    exporter.output_drops_by_priority(ExportPriority::Bulk);
                let filter_stats = aggregate_file_filter_stats(&file_filter_stats);
                let aggregate_ended_at = system_now_unix_ns().unwrap_or_default();
                if let Some(reader) = capture_aggregate_reader.as_mut() {
                    reader.drain(
                        exporter.as_ref(),
                        capture_profile.as_ref().map(|manager| manager.active_epoch).unwrap_or(0),
                        aggregate_ended_at,
                        false,
                    );
                }
                let capture_heartbeat = capture_profile_heartbeat(
                    capture_profile.as_ref(),
                    capture_profile_stats.as_ref(),
                    capture_aggregate_reader.as_ref(),
                );
                let pipeline = pipeline_accounting.snapshot(
                    &processor.stats,
                    snapshot_ring_readers(&reader_ledgers),
                    aggregate_ring_pipeline_stats(&ring_pipeline_stats),
                    unix_now_ms_u64(),
                );
                let interval_secs = partial_window_interval_secs(stats_window_started.elapsed());
                let _ = exporter.export_with_priority(
                    &collector_heartbeat(
                        &collector,
                        interval_secs,
                        &processor.stats,
                        dropped,
                        output_dropped,
                        FileFilterHeartbeatSnapshot {
                            stats: filter_stats,
                            enabled: file_filter.enabled,
                            epoch: file_filter.active_epoch,
                            unknown_policy: file_filter.unknown_policy,
                        },
                        Some(pipeline),
                        capture_heartbeat,
                        false,
                    ),
                    ExportPriority::Critical,
                );
                let critical_inbox =
                    pipeline_receiver.ledger().snapshot(ServiceClass::Critical);
                let semantic_inbox =
                    pipeline_receiver.ledger().snapshot(ServiceClass::Semantic);
                let bulk_inbox = pipeline_receiver.ledger().snapshot(ServiceClass::Bulk);
                tracing::info!(
                    exec = processor.stats.exec,
                    exec_truncated = processor.stats.exec_truncated,
                    exec_incomplete = processor.stats.exec_incomplete,
                    exec_reassembly_timeout = processor.stats.exec_reassembly_timeout,
                    exit = processor.stats.exit,
                    egress = processor.stats.egress,
                    dns = processor.stats.dns,
                    file = processor.stats.file,
                    file_access = processor.stats.file_access,
                    file_delete = processor.stats.file_delete,
                    file_access_unknown_kept = filter_stats.access_unknown_kept,
                    file_access_sampled = filter_stats.access_sampled,
                    file_access_prefilter_dropped = filter_stats.access_dropped,
                    file_access_sample_suppressed = filter_stats.access_sample_suppressed,
                    file_delete_prefilter_dropped = filter_stats.delete_dropped,
                    file_delete_unknown_kept = filter_stats.delete_unknown_kept,
                    file_access_ring_dropped = filter_stats.access_ring_dropped,
                    file_delete_ring_dropped = filter_stats.delete_ring_dropped,
                    file_filter_epoch = file_filter.active_epoch,
                    file_unknown_policy = file_filter.unknown_policy.name(),
                    llm = processor.stats.llm,
                    ssl = processor.stats.ssl,
                    interaction_connections = processor.interactions.active_connections(),
                    sec = processor.stats.sec,
                    critical_inbox_depth = critical_inbox.depth,
                    critical_inbox_high_water = critical_inbox.high_water,
                    critical_inbox_dropped = critical_inbox.dropped,
                    semantic_inbox_depth = semantic_inbox.depth,
                    semantic_inbox_high_water = semantic_inbox.high_water,
                    semantic_inbox_dropped = semantic_inbox.dropped,
                    bulk_inbox_depth = bulk_inbox.depth,
                    bulk_inbox_high_water = bulk_inbox.high_water,
                    bulk_inbox_dropped = bulk_inbox.dropped,
                    reorder_depth = reorder.depth(),
                    reorder_processes = reorder.process_count(),
                    reorder_forced_flushes = processor.reorder_forced_flushes,
                    reorder_key_collisions = processor.reorder_key_collisions,
                    dropped,
                    output_dropped,
                    output_critical_dropped,
                    output_semantic_dropped,
                    output_bulk_dropped,
                    "a3s-observer: collector pipeline window"
                );
                processor.stats = Stats::default();
                stats_window_started = Instant::now();
            }
            _ = filter_reload.tick(), if filter_reloader.is_some()
                || capture_reloader.is_some()
                || capture_aggregate_reader.is_some() => {
                if let Some(reloader) = filter_reloader.as_mut() {
                    match tokio::task::block_in_place(|| reloader.reload(&mut file_filter)) {
                        Ok(Some(entries)) => {
                            reloader.last_error.clear();
                            tracing::info!(
                                epoch = file_filter.active_epoch,
                                entries,
                                path = %reloader.path.display(),
                                "hot-reloaded file filter snapshot"
                            );
                        }
                        Ok(None) => {}
                        Err(error) => {
                            let message = error.to_string();
                            if reloader.last_error != message {
                                tracing::warn!(
                                    path = %reloader.path.display(),
                                    error = %error,
                                    active_epoch = file_filter.active_epoch,
                                    "file filter reload rejected; retaining the last valid epoch"
                                );
                                reloader.last_error = message;
                            }
                        }
                    }
                } else if let (Some(reloader), Some(manager), Some(ack_path)) = (
                    capture_reloader.as_mut(),
                    capture_profile.as_mut(),
                    capture_ack_path.as_deref(),
                ) {
                    match tokio::task::block_in_place(|| reload_capture_profile(
                        reloader,
                        manager,
                        capture_profile_mode,
                        &collector_generation,
                        ack_path,
                        &mut preview_receipt,
                        &mut pending_capture_ack,
                        capture_aggregate_reader.as_mut(),
                    )) {
                        Ok(Some(entries)) => {
                            reloader.last_error.clear();
                            tracing::info!(
                                epoch = manager.active_epoch,
                                entries,
                                mode = capture_profile_mode.name(),
                                destructive = manager.destructive_enabled(),
                                path = %reloader.path.display(),
                                ack = %ack_path.display(),
                                "hot-reloaded S5 capture profile snapshot"
                            );
                        }
                        Ok(None) => {}
                        Err(error) => {
                            let message = error.to_string();
                            if reloader.last_error != message {
                                tracing::warn!(
                                    path = %reloader.path.display(),
                                    error = %error,
                                    active_epoch = manager.active_epoch,
                                    destructive = manager.destructive_enabled(),
                                    "S5 capture profile reload rejected; retaining safe/LKG state"
                                );
                                reloader.last_error = message;
                            }
                        }
                    }
                }
                // Read cumulative aggregate ledgers on the short reload cadence. This keeps old
                // epoch terminal deltas retryable and makes key cleanup bounded under rapid policy
                // rotation instead of waiting for the minute heartbeat interval.
                if let (Some(reader), Some(manager)) = (
                    capture_aggregate_reader.as_mut(),
                    capture_profile.as_ref(),
                ) {
                    reader.drain(
                        exporter.as_ref(),
                        manager.active_epoch,
                        system_now_unix_ns().unwrap_or_default(),
                        false,
                    );
                }
            }
            _ = tls_attach_scan.tick(), if tls_attach_manager.is_some() => {
                if let Some(manager) = tls_attach_manager.as_mut() {
                    if let Some(reloader) = tls_agent_scope_reloader.as_mut() {
                        match tokio::task::block_in_place(|| reloader.refresh()) {
                            Ok(refresh) => {
                                manager.set_scope_verified_pids(refresh.pids.clone());
                                last_tls_agent_scope_error.clear();
                                if refresh.changed {
                                    tracing::info!(
                                        cgroups = refresh.cgroups,
                                        pids = refresh.pids.len(),
                                        "reconciled product-neutral TLS Agent cgroup scopes"
                                    );
                                }
                            }
                            Err(error) => {
                                let message = error.to_string();
                                if last_tls_agent_scope_error != message {
                                    tracing::warn!(
                                        error = %error,
                                        "TLS Agent cgroup scope refresh failed; retaining the last valid scope"
                                    );
                                    last_tls_agent_scope_error = message;
                                }
                            }
                        }
                    }
                    let newly_attached = tokio::task::block_in_place(|| {
                        refresh_tls_attachments(manager, &mut verified_process_map, &mut ebpf)
                    });
                    if newly_attached > 0 {
                        tracing::info!(
                            newly_attached,
                            attached_targets = manager.attached_count(),
                            "refreshed Agent TLS plaintext attachments"
                        );
                    }
                }
            }
            _ = exec_expire.tick() => {
                tokio::task::block_in_place(|| {
                    processor.expire_exec(exporter.as_ref(), &resolver, Instant::now());
                });
            }
            _ = processor_tick.tick() => {
                let drained = tokio::task::block_in_place(|| {
                    process_pipeline_cycle(
                        &mut pipeline_receiver,
                        &mut reorder,
                        &mut processor,
                        exporter.as_ref(),
                        &resolver,
                        &classifier,
                        PIPELINE_WEIGHTED_BATCH,
                        reorder_window_ns,
                    )
                })?;
                if drained == PIPELINE_WEIGHTED_BATCH {
                    pipeline_ready.notify_one();
                }
                tokio::task::block_in_place(|| {
                    refresh_exec_tls_candidates(
                        &mut processor,
                        tls_attach_manager.as_mut(),
                        &mut verified_process_map,
                        &mut ebpf,
                    )
                });
            }
            _ = pipeline_ready.notified() => {
                let drained = tokio::task::block_in_place(|| {
                    process_pipeline_cycle(
                        &mut pipeline_receiver,
                        &mut reorder,
                        &mut processor,
                        exporter.as_ref(),
                        &resolver,
                        &classifier,
                        PIPELINE_WEIGHTED_BATCH,
                        reorder_window_ns,
                    )
                })?;
                if drained == PIPELINE_WEIGHTED_BATCH {
                    pipeline_ready.notify_one();
                }
                tokio::task::block_in_place(|| {
                    refresh_exec_tls_candidates(
                        &mut processor,
                        tls_attach_manager.as_mut(),
                        &mut verified_process_map,
                        &mut ebpf,
                    )
                });
            }
        }
    }

    // Detach probes before the readers' final drain so no producer can refill a Ring after it was
    // observed empty. Reader tasks then close, the bounded inbox is exhausted, and only then is
    // the output barrier allowed to acknowledge the terminal heartbeat.
    drop(ebpf);
    let _ = reader_shutdown.send(true);
    let join_readers = async {
        while let Some(joined) = readers.join_next().await {
            match joined {
                Ok((_origin, Ok(()))) => {}
                Ok((origin, Err(error))) => {
                    reader_failure.get_or_insert_with(|| {
                        format!("ring reader {origin:?} failed during shutdown: {error}")
                    });
                }
                Err(error) => {
                    reader_failure
                        .get_or_insert_with(|| format!("ring reader task failed: {error}"));
                }
            }
        }
    };
    if tokio::time::timeout(RING_READER_SHUTDOWN_TIMEOUT, join_readers)
        .await
        .is_err()
    {
        reader_failure.get_or_insert_with(|| {
            format!(
                "ring readers did not stop within {} ms",
                RING_READER_SHUTDOWN_TIMEOUT.as_millis()
            )
        });
        readers.abort_all();
        while readers.join_next().await.is_some() {}
    }

    loop {
        let drained = drain_pipeline(
            &mut pipeline_receiver,
            &mut reorder,
            &mut processor,
            exporter.as_ref(),
            &resolver,
            &classifier,
            PIPELINE_WEIGHTED_BATCH,
        );
        if drained == 0 {
            break;
        }
    }
    let ready = reorder.flush_all();
    process_ready_envelopes(
        &mut processor,
        ready,
        exporter.as_ref(),
        &resolver,
        &classifier,
    );
    processor.expire_exec(
        exporter.as_ref(),
        &resolver,
        Instant::now() + EXEC_REASSEMBLY_TIMEOUT,
    );

    // Aggregate deltas enter the Bulk lane before the terminal Critical heartbeat. The priority
    // exporter's cross-lane barrier then guarantees every admitted delta is written before the
    // terminal heartbeat is ACKed/flushed.
    if let Some(reader) = capture_aggregate_reader.as_mut() {
        reader.drain(
            exporter.as_ref(),
            capture_profile
                .as_ref()
                .map(|manager| manager.active_epoch)
                .unwrap_or(0),
            system_now_unix_ns().unwrap_or_default(),
            true,
        );
    }

    let dropped: u64 = drops
        .get(&0, 0)
        .map(|v| v.iter().copied().sum())
        .unwrap_or(0);
    let final_pipeline = pipeline_accounting.snapshot(
        &processor.stats,
        snapshot_ring_readers(&reader_ledgers),
        aggregate_ring_pipeline_stats(&ring_pipeline_stats),
        unix_now_ms_u64(),
    );
    let final_heartbeat = collector_heartbeat(
        &collector,
        partial_window_interval_secs(stats_window_started.elapsed()),
        &processor.stats,
        dropped,
        exporter.output_drops(),
        FileFilterHeartbeatSnapshot {
            stats: aggregate_file_filter_stats(&file_filter_stats),
            enabled: file_filter.enabled,
            epoch: file_filter.active_epoch,
            unknown_policy: file_filter.unknown_policy,
        },
        Some(final_pipeline),
        capture_profile_heartbeat(
            capture_profile.as_ref(),
            capture_profile_stats.as_ref(),
            capture_aggregate_reader.as_ref(),
        ),
        true,
    );
    if !exporter.export_and_flush(&final_heartbeat, FINAL_HEARTBEAT_FLUSH_TIMEOUT) {
        tracing::warn!(
            timeout_ms = FINAL_HEARTBEAT_FLUSH_TIMEOUT.as_millis(),
            output_dropped = exporter.output_drops(),
            "final collector heartbeat could not be flushed before shutdown"
        );
    }
    let output_dropped = exporter.output_drops();
    let output_critical_dropped = exporter.output_drops_by_priority(ExportPriority::Critical);
    let output_semantic_dropped = exporter.output_drops_by_priority(ExportPriority::Semantic);
    let output_bulk_dropped = exporter.output_drops_by_priority(ExportPriority::Bulk);
    let (process_cache_entries, process_cache_hits, process_cache_misses) = process_context_cache()
        .lock()
        .map(|cache| (cache.entries.len(), cache.hits, cache.misses))
        .unwrap_or_default();
    tracing::info!(
        exec = processor.stats.exec,
        exec_truncated = processor.stats.exec_truncated,
        exec_incomplete = processor.stats.exec_incomplete,
        exec_reassembly_timeout = processor.stats.exec_reassembly_timeout,
        exit = processor.stats.exit,
        egress = processor.stats.egress,
        dns = processor.stats.dns,
        file = processor.stats.file,
        file_access = processor.stats.file_access,
        file_delete = processor.stats.file_delete,
        llm = processor.stats.llm,
        ssl = processor.stats.ssl,
        sec = processor.stats.sec,
        reorder_forced_flushes = processor.reorder_forced_flushes,
        reorder_key_collisions = processor.reorder_key_collisions,
        dropped,
        output_dropped,
        output_critical_dropped,
        output_semantic_dropped,
        output_bulk_dropped,
        process_cache_entries,
        process_cache_hits,
        process_cache_misses,
        "a3s-observer-collector: stopped (final window)"
    );
    if let Some(failure) = reader_failure {
        anyhow::bail!(failure);
    }
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

fn tls_profile_diagnostic_snapshot(map: &PerCpuArray<MapData, u64>) -> [u64; 21] {
    let mut snapshot = [0u64; 21];
    for (index, value) in snapshot.iter_mut().enumerate() {
        *value = map
            .get(&(index as u32), 0)
            .map(|per_cpu| per_cpu.iter().copied().sum())
            .unwrap_or(0);
    }
    snapshot
}

fn attach_uprobe_at(
    ebpf: &mut Ebpf,
    prog: &str,
    symbol: Option<&str>,
    offset: u64,
    target: &Path,
    pid: Option<i32>,
) -> anyhow::Result<()> {
    let p: &mut UProbe = ebpf
        .program_mut(prog)
        .with_context(|| format!("`{prog}` program not found"))?
        .try_into()?;
    if p.fd().is_err() {
        p.load()?;
    }
    p.attach(symbol, offset, target, pid).with_context(|| {
        format!(
            "attach {:?} {}+0x{offset:x} in {} for pid {:?}",
            p.kind(),
            symbol.unwrap_or("<file-offset>"),
            target.display(),
            pid
        )
    })?;
    Ok(())
}

fn attach_tls_pair(
    ebpf: &mut Ebpf,
    enter_program: &str,
    exit_program: &str,
    symbol: Option<&str>,
    offset: u64,
    target: &Path,
    pid: Option<i32>,
) -> anyhow::Result<()> {
    attach_uprobe_at(ebpf, enter_program, symbol, offset, target, pid)?;
    attach_uprobe_at(ebpf, exit_program, symbol, offset, target, pid)?;
    Ok(())
}

fn attach_tls_plan(ebpf: &mut Ebpf, plan: &TlsAttachPlan) -> anyhow::Result<usize> {
    let mut attached_programs = 0usize;
    match plan.kind {
        TlsAttachKind::Symbols(SymbolFamily::OpenSsl) => {
            if attach_tls_pair(
                ebpf,
                "ssl_write_enter",
                "ssl_write_exit",
                Some("SSL_write"),
                0,
                &plan.path,
                plan.pid,
            )
            .is_ok()
            {
                attached_programs += 2;
            }
            if attach_tls_pair(
                ebpf,
                "ssl_read_enter",
                "ssl_read_exit",
                Some("SSL_read"),
                0,
                &plan.path,
                plan.pid,
            )
            .is_ok()
            {
                attached_programs += 2;
            }
            if attach_tls_pair(
                ebpf,
                "ssl_write_ex_enter",
                "ssl_write_ex_exit",
                Some("SSL_write_ex"),
                0,
                &plan.path,
                plan.pid,
            )
            .is_ok()
            {
                attached_programs += 2;
            }
            if attach_tls_pair(
                ebpf,
                "ssl_read_ex_enter",
                "ssl_read_ex_exit",
                Some("SSL_read_ex"),
                0,
                &plan.path,
                plan.pid,
            )
            .is_ok()
            {
                attached_programs += 2;
            }
            anyhow::ensure!(
                attached_programs >= 4,
                "no complete OpenSSL read/write pair attached"
            );
        }
        TlsAttachKind::Symbols(SymbolFamily::GnuTls) => {
            attach_tls_pair(
                ebpf,
                "ssl_write_enter",
                "ssl_write_exit",
                Some("gnutls_record_send"),
                0,
                &plan.path,
                plan.pid,
            )?;
            attach_tls_pair(
                ebpf,
                "ssl_read_enter",
                "ssl_read_exit",
                Some("gnutls_record_recv"),
                0,
                &plan.path,
                plan.pid,
            )?;
            attached_programs = 4;
        }
        TlsAttachKind::Symbols(SymbolFamily::Nss) => {
            attach_tls_pair(
                ebpf,
                "ssl_write_enter",
                "ssl_write_exit",
                Some("PR_Write"),
                0,
                &plan.path,
                plan.pid,
            )?;
            attach_tls_pair(
                ebpf,
                "ssl_read_enter",
                "ssl_read_exit",
                Some("PR_Read"),
                0,
                &plan.path,
                plan.pid,
            )?;
            attached_programs = 4;
        }
        TlsAttachKind::Offsets {
            read_offset,
            write_offset,
            read_abi,
            write_abi,
            ref additional_pairs,
        } => {
            attached_programs += attach_offset_pair(
                ebpf,
                &TlsOffsetPair {
                    read_offset,
                    write_offset,
                    read_abi,
                    write_abi,
                },
                &plan.path,
                plan.pid,
            )?;
            for pair in additional_pairs {
                attached_programs += attach_offset_pair(ebpf, pair, &plan.path, plan.pid)?;
            }
        }
    }
    Ok(attached_programs)
}

fn attach_offset_pair(
    ebpf: &mut Ebpf,
    pair: &TlsOffsetPair,
    target: &Path,
    pid: Option<i32>,
) -> anyhow::Result<usize> {
    let mut attached = 0usize;
    let (write_enter, write_exit) = match pair.write_abi {
        TlsAbi::Classic => ("ssl_write_enter", "ssl_write_exit"),
        TlsAbi::OpenSslEx => ("ssl_write_ex_enter", "ssl_write_ex_exit"),
        TlsAbi::RustlsOutboundChunks => {
            attach_uprobe_at(
                ebpf,
                "rustls_write_enter",
                None,
                pair.write_offset,
                target,
                pid,
            )?;
            ("", "")
        }
        TlsAbi::RustlsPayload => anyhow::bail!("rustls payload ABI is invalid for writes"),
    };
    if pair.write_abi == TlsAbi::RustlsOutboundChunks {
        attached += 1;
    } else {
        attach_tls_pair(
            ebpf,
            write_enter,
            write_exit,
            None,
            pair.write_offset,
            target,
            pid,
        )?;
        attached += 2;
    }

    match pair.read_abi {
        TlsAbi::Classic => {
            attach_tls_pair(
                ebpf,
                "ssl_read_enter",
                "ssl_read_exit",
                None,
                pair.read_offset,
                target,
                pid,
            )?;
            attached += 2;
        }
        TlsAbi::OpenSslEx => {
            attach_tls_pair(
                ebpf,
                "ssl_read_ex_enter",
                "ssl_read_ex_exit",
                None,
                pair.read_offset,
                target,
                pid,
            )?;
            attached += 2;
        }
        TlsAbi::RustlsPayload => {
            attach_uprobe_at(
                ebpf,
                "rustls_read_enter",
                None,
                pair.read_offset,
                target,
                pid,
            )?;
            attached += 1;
        }
        TlsAbi::RustlsOutboundChunks => {
            anyhow::bail!("rustls outbound-chunks ABI is invalid for reads")
        }
    }
    Ok(attached)
}

fn refresh_tls_attachments(
    manager: &mut TlsAttachManager,
    verified_process_map: &mut VerifiedProcessMap,
    ebpf: &mut Ebpf,
) -> usize {
    let plans = manager.discover();
    attach_tls_plans(manager, verified_process_map, ebpf, plans)
}

fn refresh_tls_attachment_for_pid(
    manager: &mut TlsAttachManager,
    verified_process_map: &mut VerifiedProcessMap,
    ebpf: &mut Ebpf,
    pid: i32,
    identity_verified: bool,
) -> usize {
    let plans = if identity_verified {
        manager.discover_verified_pid(pid)
    } else {
        manager.discover_pid(pid)
    };
    attach_tls_plans(manager, verified_process_map, ebpf, plans)
}

fn attach_tls_plans(
    manager: &mut TlsAttachManager,
    verified_process_map: &mut VerifiedProcessMap,
    ebpf: &mut Ebpf,
    plans: Vec<TlsAttachPlan>,
) -> usize {
    let mut attached_programs = 0usize;
    for plan in plans {
        match attach_tls_plan(ebpf, &plan) {
            Ok(count) => {
                attached_programs = attached_programs.saturating_add(count);
                tracing::info!(
                    product = %plan.product,
                    runtime_role = plan.runtime_role.as_str(),
                    transport_scope = %plan.transport_scope,
                    excluded_transport_scope = ?plan.excluded_transport_scope,
                    path = %plan.path.display(),
                    pid = ?plan.pid,
                    programs = count,
                    "attached verified Agent TLS plaintext probes"
                );
                manager.mark_attached(plan.key, plan.pid);
            }
            Err(error) => manager.mark_attach_failed(plan.key, &error.to_string()),
        }
    }
    match verified_process_map.sync(manager.verified_pids()) {
        Ok(newly_installed) if newly_installed > 0 => tracing::info!(
            newly_installed,
            installed = verified_process_map.installed.len(),
            "synchronized identity-verified Agent plaintext PID allowlist"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(
            error = %error,
            "failed to synchronize identity-verified Agent plaintext PID allowlist"
        ),
    }
    attached_programs
}

fn refresh_exec_tls_candidates(
    processor: &mut CollectorProcessor,
    manager: Option<&mut TlsAttachManager>,
    verified_process_map: &mut VerifiedProcessMap,
    ebpf: &mut Ebpf,
) {
    let candidate_pids = processor.take_tls_attach_candidate_pids(Instant::now());
    let Some(manager) = manager else {
        return;
    };
    for (pid, identity_verified, retry_attempt) in candidate_pids {
        let retry_attempt =
            retry_attempt.or_else(|| manager.is_named_agent_runtime_pid(pid).then_some(0));
        let newly_attached = refresh_tls_attachment_for_pid(
            manager,
            verified_process_map,
            ebpf,
            pid,
            identity_verified,
        );
        if newly_attached > 0 {
            processor.cancel_tls_attach_retry(pid);
            tracing::info!(
                pid,
                identity_verified,
                newly_attached,
                attached_targets = manager.attached_count(),
                "attached Agent TLS probes from exec lifecycle signal"
            );
        } else if let Some(attempt) = retry_attempt {
            processor.schedule_tls_attach_retry(pid, identity_verified, attempt, Instant::now());
        }
    }
}

fn read_pod<T: Copy>(item: &[u8]) -> Option<T> {
    (item.len() >= core::mem::size_of::<T>())
        .then(|| unsafe { core::ptr::read_unaligned(item.as_ptr() as *const T) })
}

fn read_tls_plaintext(item: &[u8]) -> Option<(TlsPlaintextEventHeader, &[u8])> {
    let header = read_pod::<TlsPlaintextEventHeader>(item)?;
    if header.abi_version != TLS_PLAINTEXT_ABI_V1 {
        return None;
    }
    let minimum = core::mem::size_of::<TlsPlaintextEventHeader>();
    let header_len = header.header_len as usize;
    let captured_len = header.captured_len as usize;
    if header_len < minimum || header_len.checked_add(captured_len)? > item.len() {
        return None;
    }
    Some((header, &item[header_len..header_len + captured_len]))
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

fn parse_process_stat(stat: &str) -> Option<(u32, u64)> {
    let tail = stat.rsplit_once(')')?.1;
    // The tail starts at field 3 (`state`): ppid is field 4 / index 1 and start time is
    // field 22 / index 19. Parse one snapshot so they cannot straddle PID reuse.
    let mut fields = tail.split_whitespace();
    fields.next()?; // state
    let ppid = fields.next()?.parse().ok()?;
    for _ in 2..19 {
        fields.next()?;
    }
    Some((ppid, fields.next()?.parse().ok()?))
}

#[cfg(test)]
fn parse_process_start_time_ticks(stat: &str) -> Option<u64> {
    parse_process_stat(stat).map(|(_, start_time_ticks)| start_time_ticks)
}

fn read_process_stat(pid: u32) -> Option<(u32, u64)> {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .as_deref()
        .and_then(parse_process_stat)
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

fn read_process_context(pid: u32, cgroup_id: u64, comm: &str) -> ProcessContext {
    let cwd = read_cwd(pid);
    let stat = read_process_stat(pid);
    let namespace = read_process_namespace(pid, stat.map(|(ppid, _)| ppid).unwrap_or(0));
    ProcessContext {
        host_id: host_id(),
        boot_id: boot_id(),
        pid,
        ppid: stat.map(|(ppid, _)| ppid).unwrap_or(0),
        pid_namespace: namespace.as_ref().map(|facts| facts.pid_namespace.clone()),
        namespace_pid: namespace.as_ref().map(|facts| facts.namespace_pid),
        namespace_ppid: namespace.and_then(|facts| facts.namespace_ppid),
        start_time_ticks: stat.map(|(_, start_time_ticks)| start_time_ticks),
        comm: comm.to_string(),
        mount_namespace: mount_namespace(pid),
        exe: read_exe(pid),
        cwd: (!cwd.is_empty()).then_some(cwd),
        cgroup: read_cgroup(pid),
        cgroup_id,
        lifecycle_source: None,
        lifecycle_reason: None,
    }
}

fn process_context(pid: u32, cgroup_id: u64, comm: &[u8; 16]) -> ProcessContext {
    let comm = cstr(comm);
    let now = Instant::now();
    if let Ok(mut cache) = process_context_cache().lock() {
        if let Some(context) = cache.get(pid, cgroup_id, &comm, now) {
            return context;
        }
        cache.misses += 1;
    }
    let context = read_process_context(pid, cgroup_id, &comm);
    if let Ok(mut cache) = process_context_cache().lock() {
        cache.insert(context.clone(), now);
    }
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
    } else {
        read_process_stat(ev.pid).map(|(ppid, _)| ppid).unwrap_or(0)
    }
}

fn exec_process_context(ev: &CompletedExec, ppid: u32) -> ProcessContext {
    let cwd = read_cwd(ev.pid);
    let captured_exe = cstr(&ev.filename);
    let stat = read_process_stat(ev.pid);
    let observed_ppid = if ev.ppid != 0 {
        ppid
    } else {
        stat.map(|(observed_ppid, _)| observed_ppid).unwrap_or(0)
    };
    let namespace = read_process_namespace(ev.pid, observed_ppid);
    let context = ProcessContext {
        host_id: host_id(),
        boot_id: boot_id(),
        pid: ev.pid,
        ppid: observed_ppid,
        pid_namespace: namespace.as_ref().map(|facts| facts.pid_namespace.clone()),
        namespace_pid: namespace.as_ref().map(|facts| facts.namespace_pid),
        namespace_ppid: namespace.and_then(|facts| facts.namespace_ppid),
        start_time_ticks: stat.map(|(_, start_time_ticks)| start_time_ticks),
        comm: cstr(&ev.comm),
        mount_namespace: mount_namespace(ev.pid),
        exe: read_exe(ev.pid).or_else(|| (!captured_exe.is_empty()).then_some(captured_exe)),
        cwd: (!cwd.is_empty()).then_some(cwd),
        cgroup: read_cgroup(ev.pid),
        cgroup_id: ev.cgroup_id,
        lifecycle_source: None,
        lifecycle_reason: None,
    };
    if let Ok(mut cache) = process_context_cache().lock() {
        cache.insert(context.clone(), Instant::now());
    }
    context
}

/// Lifecycle evidence is deliberately limited to facts carried by this Exec generation's kernel
/// records. `/proc/<pid>` enrichment above remains useful for the ToolExec event, but it may have
/// crossed PID reuse by the time userspace drains the ring and therefore must not enter a future
/// ProcessExit tombstone.
fn exec_lifecycle_context(ev: &CompletedExec) -> ProcessContext {
    let captured_exe = cstr(&ev.filename);
    ProcessContext {
        host_id: host_id(),
        boot_id: boot_id(),
        pid: ev.pid,
        ppid: ev.ppid,
        pid_namespace: None,
        namespace_pid: None,
        namespace_ppid: None,
        start_time_ticks: None,
        comm: cstr(&ev.comm),
        mount_namespace: None,
        exe: (!captured_exe.is_empty()).then_some(captured_exe),
        cwd: None,
        cgroup: None,
        cgroup_id: ev.cgroup_id,
        lifecycle_source: None,
        lifecycle_reason: None,
    }
}

fn observe_exec_commit_lifecycle(
    process_lifecycles: &mut ProcessLifecycleStore,
    record: &ExecRecord,
    now: Instant,
) {
    if record.kind != EXEC_RECORD_COMMIT {
        return;
    }
    let process = ProcessContext {
        host_id: host_id(),
        boot_id: boot_id(),
        pid: record.pid,
        ppid: record.ppid,
        pid_namespace: None,
        namespace_pid: None,
        namespace_ppid: None,
        start_time_ticks: None,
        comm: cstr(&record.comm),
        mount_namespace: None,
        exe: None,
        cwd: None,
        cgroup: None,
        cgroup_id: record.cgroup_id,
        lifecycle_source: None,
        lifecycle_reason: None,
    };
    process_lifecycles.observe_exec(
        record.exec_id,
        true,
        process,
        Identity::default(),
        None,
        now,
    );
}

fn exit_lifecycle_context(pid: u32, cgroup_id: u64, comm: String) -> ProcessContext {
    ProcessContext {
        host_id: host_id(),
        boot_id: boot_id(),
        pid,
        ppid: 0,
        pid_namespace: None,
        namespace_pid: None,
        namespace_ppid: None,
        start_time_ticks: None,
        comm,
        mount_namespace: None,
        exe: None,
        cwd: None,
        cgroup: None,
        cgroup_id,
        lifecycle_source: None,
        lifecycle_reason: None,
    }
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
    (ev, "kernel_fragments", argc, bytes)
}

fn supplement_exec_argv(ev: CompletedExec) -> (CompletedExec, &'static str, u32, u32) {
    supplement_exec_argv_at(ev, Path::new("/proc"), PROC_CMDLINE_MAX_BYTES)
}

fn emit_completed_exec(
    exporter: &dyn Exporter,
    stats: &mut Stats,
    resolver: &impl IdentityResolver,
    process_lifecycles: &mut ProcessLifecycleStore,
    ev: CompletedExec,
) {
    if ev.reassembly_timed_out {
        stats.exec_reassembly_timeout += 1;
    }
    let (ev, argv_source, observed_argc, observed_bytes) = supplement_exec_argv(ev);
    let ppid = exec_ppid(&ev);
    let process = exec_process_context(&ev, ppid);
    let cwd = process.cwd.clone().unwrap_or_default();
    let identity = identity_for(resolver, ev.pid, ev.cgroup_id, &ev.comm);
    let workload = resolver.resolve_workload(ev.pid, ev.cgroup_id, 0);
    process_lifecycles.observe_exec(
        ev.exec_id,
        ev.exec_confirmed,
        exec_lifecycle_context(&ev),
        identity.clone(),
        workload.clone(),
        Instant::now(),
    );
    emit(
        exporter,
        stats,
        PipelineRing::Exec,
        EnrichedEvent {
            timing: Some(EventTiming::from_unix_ns(
                ev.event_at_unix_ns,
                ev.received_at_unix_ns,
            )),
            capture_decision: Some(event_capture_decision(ev.capture_decision)),
            identity,
            workload,
            observation: None,
            process: Some(process),
            provider: None,
            event: AgentEvent::ToolExec {
                exec_id: ev.exec_id,
                exec_id_exact: ev.exec_id.to_string(),
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

fn tls_exec_comm_needs_refresh(value: &str) -> bool {
    let comm = value.trim().to_ascii_lowercase();
    matches!(comm.as_str(), "codex" | "claude" | "claude.exe" | "pi")
        || comm.starts_with("codex-code-mode")
        || comm.starts_with("dify-plugin-da")
}

fn tls_capture_profile_needs_refresh(profile: u8) -> bool {
    matches!(
        profile,
        CAPTURE_PROFILE_AGENT_FULL
            | CAPTURE_PROFILE_INVESTIGATION_FULL
            | CAPTURE_PROFILE_PROBABLE_INVESTIGATION
    )
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

/// Per-kind event counters for periodic throughput logging (collector operability).
#[derive(Clone, Copy, Default)]
struct RingWindowStats {
    /// Semantic events produced from this ring after decode/reassembly/enrichment.
    logical_events: u64,
    /// Logical events admitted to the exporter's output queue.
    queue_admitted: u64,
    /// Logical events rejected by the exporter's output queue or serialization boundary.
    queue_dropped: u64,
}

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
    file_access: u64,
    file_delete: u64,
    llm: u64,
    ssl: u64,
    sec: u64,
    agents: HashSet<String>,
    pipeline: [RingWindowStats; PIPELINE_RING_COUNT],
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct SocketKey {
    cgroup_id: u64,
    pid: u32,
    fd: u32,
}

fn event_capture_decision(context: CaptureDecisionContext) -> EventCaptureDecision {
    EventCaptureDecision::new(
        context.capture_epoch,
        context.capture_profile,
        context.capture_action,
        context.capture_authority,
        context.capture_disposition,
        context.flags & CAPTURE_DECISION_FLAG_SELECTED != 0,
        context.flags,
    )
}

/// Single-writer state for all expensive decoding, `/proc`/workload enrichment, protocol joins,
/// lifecycle tracking, and semantic export. Ring readers never touch this state.
struct PendingTlsAttachRetry {
    identity_verified: bool,
    attempt: usize,
    next_at: Instant,
}

struct CollectorProcessor {
    peers: HashMap<SocketKey, (IpAddr, u16)>,
    llm_meta: HashMap<SocketKey, (Option<String>, Option<Provider>, IpAddr)>,
    interactions: InteractionReassembler,
    exec_assembler: ExecAssembler,
    process_lifecycles: ProcessLifecycleStore,
    tls_attach_candidate_pids: HashSet<i32>,
    tls_verified_candidate_pids: HashSet<i32>,
    tls_fast_retry_candidate_pids: HashSet<i32>,
    tls_attach_retries: HashMap<i32, PendingTlsAttachRetry>,
    stats: Stats,
    reorder_forced_flushes: u64,
    reorder_key_collisions: u64,
}

impl CollectorProcessor {
    fn new(exec_commit_probe_attached: bool) -> Self {
        Self {
            peers: HashMap::new(),
            llm_meta: HashMap::new(),
            interactions: InteractionReassembler::default(),
            exec_assembler: ExecAssembler::new(exec_commit_probe_attached),
            process_lifecycles: ProcessLifecycleStore::default(),
            tls_attach_candidate_pids: HashSet::new(),
            tls_verified_candidate_pids: HashSet::new(),
            tls_fast_retry_candidate_pids: HashSet::new(),
            tls_attach_retries: HashMap::new(),
            stats: Stats::default(),
            reorder_forced_flushes: 0,
            reorder_key_collisions: 0,
        }
    }

    fn expire_exec(
        &mut self,
        exporter: &dyn Exporter,
        resolver: &impl IdentityResolver,
        now: Instant,
    ) {
        for completed in self.exec_assembler.expire(now) {
            emit_completed_exec(
                exporter,
                &mut self.stats,
                resolver,
                &mut self.process_lifecycles,
                completed,
            );
        }
        self.interactions.expire_idle(now);
    }

    fn take_tls_attach_candidate_pids(&mut self, now: Instant) -> Vec<(i32, bool, Option<usize>)> {
        let verified = std::mem::take(&mut self.tls_verified_candidate_pids);
        let named = std::mem::take(&mut self.tls_fast_retry_candidate_pids);
        let mut candidates = HashMap::<i32, (bool, Option<usize>)>::new();
        for pid in std::mem::take(&mut self.tls_attach_candidate_pids) {
            candidates.insert(
                pid,
                (verified.contains(&pid), named.contains(&pid).then_some(0)),
            );
        }
        for pid in verified {
            candidates
                .entry(pid)
                .and_modify(|candidate| candidate.0 = true)
                .or_insert((true, named.contains(&pid).then_some(0)));
        }
        let ready_retries = self
            .tls_attach_retries
            .iter()
            .filter_map(|(pid, retry)| (retry.next_at <= now).then_some(*pid))
            .collect::<Vec<_>>();
        for pid in ready_retries {
            if let Some(retry) = self.tls_attach_retries.remove(&pid) {
                candidates
                    .entry(pid)
                    .and_modify(|candidate| {
                        candidate.0 |= retry.identity_verified;
                        candidate.1 = Some(candidate.1.unwrap_or(retry.attempt).min(retry.attempt));
                    })
                    .or_insert((retry.identity_verified, Some(retry.attempt)));
            }
        }
        candidates
            .into_iter()
            .map(|(pid, (identity_verified, attempt))| (pid, identity_verified, attempt))
            .collect()
    }

    fn schedule_tls_attach_retry(
        &mut self,
        pid: i32,
        identity_verified: bool,
        attempt: usize,
        now: Instant,
    ) {
        const RETRY_DELAYS: [Duration; 7] = [
            Duration::from_millis(25),
            Duration::from_millis(50),
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(400),
            Duration::from_millis(800),
            Duration::from_millis(1_600),
        ];
        let Some(delay) = RETRY_DELAYS.get(attempt).copied() else {
            return;
        };
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return;
        }
        self.tls_attach_retries.insert(
            pid,
            PendingTlsAttachRetry {
                identity_verified,
                attempt: attempt + 1,
                next_at: now + delay,
            },
        );
    }

    fn cancel_tls_attach_retry(&mut self, pid: i32) {
        self.tls_attach_retries.remove(&pid);
    }

    fn process(
        &mut self,
        envelope: RawEnvelope,
        exporter: &dyn Exporter,
        resolver: &impl IdentityResolver,
        classifier: &impl ServiceClassifier,
    ) {
        let bytes = envelope.payload.as_bytes();
        let timing =
            EventTiming::from_unix_ns(envelope.event_at_unix_ns, envelope.received_at_unix_ns);
        let capture_decision = event_capture_decision(envelope.capture_decision);
        match envelope.origin {
            PipelineOrigin::Ring(RingOrigin::Exec) => {
                let Some(record) = read_pod::<ExecRecord>(bytes) else {
                    return;
                };
                if record.kind == EXEC_RECORD_COMMIT {
                    if let Ok(pid) = i32::try_from(record.pid) {
                        let named_agent_runtime = tls_exec_comm_needs_refresh(&cstr(&record.comm));
                        if named_agent_runtime {
                            self.tls_fast_retry_candidate_pids.insert(pid);
                        }
                        if tls_capture_profile_needs_refresh(
                            record.capture_decision.capture_profile,
                        ) {
                            self.tls_verified_candidate_pids.insert(pid);
                        } else if named_agent_runtime {
                            self.tls_attach_candidate_pids.insert(pid);
                        }
                    }
                }
                let now = Instant::now();
                observe_exec_commit_lifecycle(&mut self.process_lifecycles, &record, now);
                for completed in self.exec_assembler.push_timed(
                    record,
                    envelope.event_at_unix_ns,
                    envelope.received_at_unix_ns,
                    envelope.capture_decision,
                    now,
                ) {
                    emit_completed_exec(
                        exporter,
                        &mut self.stats,
                        resolver,
                        &mut self.process_lifecycles,
                        completed,
                    );
                }
            }
            PipelineOrigin::Ring(RingOrigin::Security) => {
                let Some(ev) = read_pod::<SecEvent>(bytes) else {
                    return;
                };
                let kind = match ev.kind {
                    SEC_SETUID => "setuid-root",
                    SEC_PTRACE => "ptrace",
                    SEC_BIND => "bind",
                    _ => return,
                };
                emit(
                    exporter,
                    &mut self.stats,
                    PipelineRing::Security,
                    EnrichedEvent {
                        timing: Some(timing),
                        capture_decision: Some(capture_decision),
                        identity: identity_for(resolver, ev.pid, ev.cgroup_id, &ev.comm),
                        workload: resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
                        observation: None,
                        process: Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
                        provider: None,
                        event: AgentEvent::SecurityAction {
                            pid: ev.pid,
                            kind,
                            detail: ev.detail,
                        },
                    },
                );
            }
            PipelineOrigin::Ring(RingOrigin::Connect) => {
                let Some(ev) = read_pod::<ConnectEvent>(bytes) else {
                    return;
                };
                let peer = peer_ip(&ev);
                if self.peers.len() > 8_192 {
                    self.peers.clear();
                }
                self.peers
                    .insert(sock_key(ev.cgroup_id, ev.pid, ev.fd), (peer, ev.port));
                emit(
                    exporter,
                    &mut self.stats,
                    PipelineRing::Connect,
                    EnrichedEvent {
                        timing: Some(timing),
                        capture_decision: Some(capture_decision),
                        identity: identity_for(resolver, ev.pid, ev.cgroup_id, &ev.comm),
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
                    },
                );
            }
            PipelineOrigin::Ring(RingOrigin::Tls) => {
                let Some(ev) = read_pod::<TlsEvent>(bytes) else {
                    return;
                };
                let len = (ev.len as usize).min(ev.data.len());
                let sni = parse_sni(&ev.data[..len]);
                let socket = sock_key(ev.cgroup_id, ev.pid, ev.fd);
                let (peer, port) = self
                    .peers
                    .get(&socket)
                    .copied()
                    .unwrap_or((UNKNOWN_PEER, 0));
                let provider = sni
                    .as_deref()
                    .and_then(|hostname| classifier.classify(Some(hostname), peer));
                if self.llm_meta.len() > 16_384 {
                    self.llm_meta.clear();
                }
                self.llm_meta
                    .insert(socket, (sni.clone(), provider.clone(), peer));
                emit(
                    exporter,
                    &mut self.stats,
                    PipelineRing::Tls,
                    EnrichedEvent {
                        timing: Some(timing),
                        capture_decision: Some(capture_decision),
                        identity: identity_for(resolver, ev.pid, ev.cgroup_id, &ev.comm),
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
                    },
                );
            }
            PipelineOrigin::Ring(RingOrigin::Dns) => {
                let Some(ev) = read_pod::<DnsEvent>(bytes) else {
                    return;
                };
                let len = (ev.len as usize).min(ev.data.len());
                let Some(query) = parse_dns_qname(&ev.data[..len]) else {
                    return;
                };
                emit(
                    exporter,
                    &mut self.stats,
                    PipelineRing::Dns,
                    EnrichedEvent {
                        timing: Some(timing),
                        capture_decision: Some(capture_decision),
                        identity: identity_for(resolver, ev.pid, ev.cgroup_id, &ev.comm),
                        workload: resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
                        observation: None,
                        process: Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
                        provider: None,
                        event: AgentEvent::Dns { pid: ev.pid, query },
                    },
                );
            }
            PipelineOrigin::Ring(RingOrigin::FileDelete) => {
                let Some(ev) = read_pod::<FileEvent>(bytes) else {
                    return;
                };
                let path = cstr(&ev.path);
                if path.is_empty() {
                    return;
                }
                emit(
                    exporter,
                    &mut self.stats,
                    PipelineRing::FileDelete,
                    EnrichedEvent {
                        timing: Some(timing),
                        capture_decision: Some(capture_decision),
                        identity: identity_for(resolver, ev.pid, ev.cgroup_id, &ev.comm),
                        workload: resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
                        observation: None,
                        process: Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
                        provider: None,
                        event: AgentEvent::FileDelete { pid: ev.pid, path },
                    },
                );
            }
            PipelineOrigin::Ring(origin @ (RingOrigin::FileAccess | RingOrigin::FileRead)) => {
                let Some(ev) = read_pod::<FileEvent>(bytes) else {
                    return;
                };
                let path = cstr(&ev.path);
                if path.is_empty() {
                    return;
                }
                emit(
                    exporter,
                    &mut self.stats,
                    PipelineRing::from(origin),
                    EnrichedEvent {
                        timing: Some(timing),
                        capture_decision: Some(capture_decision),
                        identity: identity_for(resolver, ev.pid, ev.cgroup_id, &ev.comm),
                        workload: resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
                        observation: None,
                        process: Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
                        provider: None,
                        event: AgentEvent::FileAccess {
                            pid: ev.pid,
                            path,
                            write: matches!(
                                file_access_mode(ev.flags),
                                FILE_ACCESS_MODE_WRITE_ONLY | FILE_ACCESS_MODE_READ_WRITE
                            ),
                            access_mode: match file_access_mode(ev.flags) {
                                FILE_ACCESS_MODE_READ_ONLY => "read_only",
                                FILE_ACCESS_MODE_WRITE_ONLY => "write_only",
                                FILE_ACCESS_MODE_READ_WRITE => "read_write",
                                FILE_ACCESS_MODE_PATH_ONLY => "path_only",
                                FILE_ACCESS_MODE_SPECIAL => "special_mode",
                                _ => "unknown",
                            }
                            .to_string(),
                        },
                    },
                );
            }
            PipelineOrigin::Ring(RingOrigin::Llm) => {
                let Some(ev) = read_pod::<LlmEvent>(bytes) else {
                    return;
                };
                let Some((sni, provider, peer)) =
                    self.llm_meta.remove(&sock_key(ev.cgroup_id, ev.pid, ev.fd))
                else {
                    return;
                };
                if provider.is_none() {
                    return;
                }
                emit(
                    exporter,
                    &mut self.stats,
                    PipelineRing::Llm,
                    EnrichedEvent {
                        timing: Some(timing),
                        capture_decision: Some(capture_decision),
                        identity: identity_for(resolver, ev.pid, ev.cgroup_id, &ev.comm),
                        workload: resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
                        observation: None,
                        process: Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
                        provider,
                        event: AgentEvent::LlmCall {
                            pid: ev.pid,
                            sni,
                            peer,
                            req_bytes: ev.req_bytes,
                            resp_bytes: ev.resp_bytes,
                            latency: Duration::from_nanos(ev.latency_ns),
                            ttft: (ev.ttft_ns > 0).then(|| Duration::from_nanos(ev.ttft_ns)),
                        },
                    },
                );
            }
            PipelineOrigin::Ring(RingOrigin::Ssl) => {
                let Some((header, plaintext)) = read_tls_plaintext(bytes) else {
                    return;
                };
                self.stats.ssl = self.stats.ssl.saturating_add(1);
                let mut partial_reasons = Vec::new();
                if header.flags & TLS_PLAINTEXT_FLAG_TRUNCATED != 0
                    || header.captured_len < header.original_len
                {
                    partial_reasons.push("probe_call_limit".to_string());
                }
                let (source, adapter_id) = match header.api_kind {
                    TLS_PLAINTEXT_API_TCP => ("tcp_plaintext", "plain-http-syscall"),
                    TLS_PLAINTEXT_API_RUSTLS => ("tls_uprobe_rustls", "rustls-payload"),
                    TLS_PLAINTEXT_API_SSL_EX => ("tls_uprobe", "openssl-ex"),
                    TLS_PLAINTEXT_API_SSL_CLASSIC => ("tls_uprobe", "ssl-classic"),
                    _ => ("tls_uprobe", "unknown-tls-abi"),
                };
                if tls_diagnostics_enabled() && header.api_kind == TLS_PLAINTEXT_API_RUSTLS {
                    // A streamed model response may cross this path hundreds of times in a
                    // burst. Keep call-level evidence off the operational INFO stream so a
                    // slow container log sink cannot back-pressure the collector.
                    tracing::debug!(
                        pid = header.pid,
                        connection_id = format_args!("{:x}", header.connection_id),
                        call_seq = header.call_seq,
                        direction = header.direction,
                        api_kind = header.api_kind,
                        original_len = header.original_len,
                        captured_len = header.captured_len,
                        flags = header.flags,
                        source,
                        "TLS plaintext fragment admitted"
                    );
                }
                let completed = self.interactions.push(PlaintextChunk {
                    cgroup_id: header.cgroup_id,
                    pid: header.pid,
                    connection_id: header.connection_id,
                    sequence: header.call_seq,
                    direction: if header.direction == TLS_PLAINTEXT_DIRECTION_READ {
                        ChunkDirection::Response
                    } else {
                        ChunkDirection::Request
                    },
                    data: plaintext.to_vec(),
                    event_at_unix_ns: envelope.event_at_unix_ns,
                    source: source.to_string(),
                    adapter_id: adapter_id.to_string(),
                    partial_reasons,
                });
                for interaction in completed {
                    emit_completed_interaction(
                        exporter,
                        &mut self.stats,
                        resolver,
                        classifier,
                        header.comm,
                        timing.clone(),
                        capture_decision.clone(),
                        interaction,
                    );
                }
                for evidence in self.interactions.take_evidence() {
                    emit_plaintext_evidence(
                        exporter,
                        &mut self.stats,
                        resolver,
                        header.comm,
                        timing.clone(),
                        capture_decision.clone(),
                        evidence,
                    );
                }
            }
            PipelineOrigin::Ring(RingOrigin::Exit) => {
                let Some(ev) = read_pod::<ExitEvent>(bytes) else {
                    return;
                };
                let comm = cstr(&ev.comm);
                let lifecycle = self.process_lifecycles.resolve_exit(
                    ev.exec_id,
                    exit_lifecycle_context(ev.pid, ev.cgroup_id, comm),
                    Instant::now(),
                );
                emit(
                    exporter,
                    &mut self.stats,
                    PipelineRing::Exit,
                    EnrichedEvent {
                        timing: Some(timing),
                        capture_decision: Some(capture_decision),
                        identity: lifecycle.identity,
                        workload: lifecycle.workload,
                        observation: None,
                        process: Some(lifecycle.process),
                        provider: None,
                        event: AgentEvent::ProcessExit {
                            pid: ev.pid,
                            exit_code: ev.exit_code,
                            signal: ev.signal,
                        },
                    },
                );
                forget_process_context(ev.pid);
            }
            PipelineOrigin::Bulk(_) => {
                // S4 does not demote raw probe evidence into Bulk. S5 aggregate/sample producers
                // will have their own typed processor path.
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_completed_interaction(
    exporter: &dyn Exporter,
    stats: &mut Stats,
    resolver: &impl IdentityResolver,
    classifier: &impl ServiceClassifier,
    comm: [u8; 16],
    timing: EventTiming,
    capture_decision: EventCaptureDecision,
    interaction: CompletedInteraction,
) {
    let CompletedInteraction {
        schema_version,
        interaction_id,
        interaction_type,
        cgroup_id,
        pid,
        connection_id,
        transport,
        protocol,
        tls_adapter_id,
        transport_protocol,
        wire_template_id,
        parse_state,
        llm_likelihood,
        schema_fingerprint,
        transport_completeness,
        wire_completeness,
        conversation_completeness,
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
        started_at_unix_ns,
        request_complete_at_unix_ns,
        first_response_at_unix_ns,
        ended_at_unix_ns,
        duration_ns,
        time_quality,
        request,
        response,
        usage,
        tool_calls,
        tool_results,
        semantic_parser_id,
        semantic_parser_version,
        semantic_items,
        completeness,
        partial_reasons,
        capture_source,
    } = interaction;
    let provider = classifier.classify(Some(&endpoint), UNKNOWN_PEER);
    emit(
        exporter,
        stats,
        PipelineRing::Ssl,
        EnrichedEvent {
            timing: Some(timing),
            capture_decision: Some(capture_decision),
            identity: identity_for(resolver, pid, cgroup_id, &comm),
            workload: resolver.resolve_workload(pid, cgroup_id, 0),
            observation: None,
            process: Some(process_context(pid, cgroup_id, &comm)),
            provider,
            event: AgentEvent::LlmInteraction(Box::new(LlmInteraction {
                schema_version,
                interaction_id,
                interaction_type,
                pid,
                connection_id,
                transport,
                protocol,
                tls_adapter_id,
                transport_protocol,
                wire_template_id,
                parse_state,
                llm_likelihood,
                schema_fingerprint,
                transport_completeness,
                wire_completeness,
                conversation_completeness,
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
                started_at_unix_ns,
                request_complete_at_unix_ns,
                first_response_at_unix_ns,
                ended_at_unix_ns,
                duration_ns,
                time_quality,
                request: Box::new(request),
                response: Box::new(response),
                usage,
                tool_calls,
                tool_results,
                semantic_parser_id,
                semantic_parser_version,
                semantic_items,
                completeness,
                partial_reasons,
                capture_source,
            })),
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn emit_plaintext_evidence(
    exporter: &dyn Exporter,
    stats: &mut Stats,
    resolver: &impl IdentityResolver,
    comm: [u8; 16],
    timing: EventTiming,
    capture_decision: EventCaptureDecision,
    evidence: CompletedPlaintextEvidence,
) {
    let CompletedPlaintextEvidence {
        schema_version,
        evidence_id,
        cgroup_id,
        pid,
        connection_id,
        direction,
        tls_adapter_id,
        transport_protocol,
        parse_state,
        llm_likelihood,
        schema_fingerprint,
        observed_at_unix_ns,
        captured_bytes,
        encoding,
        redacted_sample,
        sample_sha256,
        reasons,
        capture_source,
    } = evidence;
    emit(
        exporter,
        stats,
        PipelineRing::Ssl,
        EnrichedEvent {
            timing: Some(timing),
            capture_decision: Some(capture_decision),
            identity: identity_for(resolver, pid, cgroup_id, &comm),
            workload: resolver.resolve_workload(pid, cgroup_id, 0),
            observation: None,
            process: Some(process_context(pid, cgroup_id, &comm)),
            provider: None,
            event: AgentEvent::AgentPlaintextEvidence(Box::new(AgentPlaintextEvidence {
                schema_version,
                evidence_id,
                pid,
                connection_id,
                direction,
                tls_adapter_id,
                transport_protocol,
                parse_state,
                llm_likelihood,
                schema_fingerprint,
                observed_at_unix_ns,
                captured_bytes,
                encoding,
                redacted_sample,
                sample_sha256,
                reasons,
                capture_source,
            })),
        },
    );
}

fn process_ready_envelopes(
    processor: &mut CollectorProcessor,
    ready: impl IntoIterator<Item = RawEnvelope>,
    exporter: &dyn Exporter,
    resolver: &impl IdentityResolver,
    classifier: &impl ServiceClassifier,
) {
    for envelope in ready {
        processor.process(envelope, exporter, resolver, classifier);
    }
}

fn push_reorder_envelope(
    reorder: &mut ReorderCoordinator,
    processor: &mut CollectorProcessor,
    envelope: RawEnvelope,
    exporter: &dyn Exporter,
    resolver: &impl IdentityResolver,
    classifier: &impl ServiceClassifier,
) {
    match reorder.try_push(envelope) {
        Ok(ready) => {
            process_ready_envelopes(processor, ready, exporter, resolver, classifier);
        }
        Err(ReorderPushError::Full(envelope)) => {
            // Capacity pressure degrades only ordering, never fact retention. Flush the bounded
            // coordinator, then re-admit the rejected record into an empty buffer.
            processor.reorder_forced_flushes = processor.reorder_forced_flushes.saturating_add(1);
            let ready = reorder.flush_all();
            process_ready_envelopes(processor, ready, exporter, resolver, classifier);
            match reorder.try_push(envelope) {
                Ok(ready) => {
                    process_ready_envelopes(processor, ready, exporter, resolver, classifier)
                }
                Err(ReorderPushError::Full(envelope) | ReorderPushError::Duplicate(envelope)) => {
                    processor.process(envelope, exporter, resolver, classifier);
                }
            }
        }
        Err(ReorderPushError::Duplicate(envelope)) => {
            // A local sequence collision is not sufficient evidence to discard a kernel fact.
            // Preserve it in arrival order and surface the bounded diagnostic counter.
            processor.reorder_key_collisions = processor.reorder_key_collisions.saturating_add(1);
            processor.process(envelope, exporter, resolver, classifier);
        }
    }
}

fn drain_pipeline(
    receiver: &mut PipelineReceiver,
    reorder: &mut ReorderCoordinator,
    processor: &mut CollectorProcessor,
    exporter: &dyn Exporter,
    resolver: &impl IdentityResolver,
    classifier: &impl ServiceClassifier,
    limit: usize,
) -> usize {
    let batch = receiver.try_drain_weighted(limit);
    let count = batch.len();
    for envelope in batch {
        push_reorder_envelope(reorder, processor, envelope, exporter, resolver, classifier);
    }
    count
}

#[allow(clippy::too_many_arguments)]
fn process_pipeline_cycle(
    receiver: &mut PipelineReceiver,
    reorder: &mut ReorderCoordinator,
    processor: &mut CollectorProcessor,
    exporter: &dyn Exporter,
    resolver: &impl IdentityResolver,
    classifier: &impl ServiceClassifier,
    limit: usize,
    reorder_window_ns: u64,
) -> anyhow::Result<usize> {
    let drained = drain_pipeline(
        receiver, reorder, processor, exporter, resolver, classifier, limit,
    );
    release_reorder_by_wall_clock(
        reorder,
        processor,
        exporter,
        resolver,
        classifier,
        reorder_window_ns,
    )?;
    Ok(drained)
}

fn release_reorder_by_wall_clock(
    reorder: &mut ReorderCoordinator,
    processor: &mut CollectorProcessor,
    exporter: &dyn Exporter,
    resolver: &impl IdentityResolver,
    classifier: &impl ServiceClassifier,
    reorder_window_ns: u64,
) -> anyhow::Result<()> {
    let watermark = monotonic_now_ns()?.saturating_sub(reorder_window_ns);
    let ready = reorder.release_through_boot_ns(watermark);
    process_ready_envelopes(processor, ready, exporter, resolver, classifier);
    Ok(())
}

impl Stats {
    fn record_export(&mut self, ring: PipelineRing, outcome: ExportOutcome) {
        let counters = &mut self.pipeline[ring.index() as usize];
        counters.logical_events = counters.logical_events.saturating_add(1);
        match outcome {
            ExportOutcome::Admitted => {
                counters.queue_admitted = counters.queue_admitted.saturating_add(1)
            }
            ExportOutcome::Dropped => {
                counters.queue_dropped = counters.queue_dropped.saturating_add(1)
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
struct FileFilterHeartbeatSnapshot {
    stats: FileFilterStats,
    enabled: bool,
    epoch: u64,
    unknown_policy: UnknownFilePolicy,
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
}

struct PipelineAccountingState {
    producer_instance_id: String,
    next_sequence: u64,
    window_started_unix_ms: u64,
    previous_kernel: [RingPipelineStats; PIPELINE_RING_COUNT],
    previous_handoff: [RingReaderLedgerSnapshot; PIPELINE_RING_COUNT],
}

impl PipelineAccountingState {
    fn new(producer_instance_id: String, started_at_unix_ms: u64) -> Self {
        Self {
            producer_instance_id,
            next_sequence: 0,
            window_started_unix_ms: started_at_unix_ms,
            previous_kernel: [RingPipelineStats::default(); PIPELINE_RING_COUNT],
            previous_handoff: [RingReaderLedgerSnapshot::default(); PIPELINE_RING_COUNT],
        }
    }

    fn snapshot(
        &mut self,
        stats: &Stats,
        handoff: [RingReaderLedgerSnapshot; PIPELINE_RING_COUNT],
        kernel: [RingPipelineStats; PIPELINE_RING_COUNT],
        ended_at_unix_ms: u64,
    ) -> CollectorPipelineAccounting {
        let ended_at_unix_ms = ended_at_unix_ms.max(self.window_started_unix_ms);
        let rings = PipelineRing::ALL
            .into_iter()
            .map(|ring| {
                let index = ring.index() as usize;
                let current = kernel[index];
                let previous = self.previous_kernel[index];
                let window = stats.pipeline[index];
                let current_ingress = handoff[index];
                let previous_ingress = self.previous_handoff[index];
                let ingress = current_ingress.delta_since(previous_ingress);
                CollectorRingAccounting {
                    ring: ring.name().to_string(),
                    ring_submitted: monotonic_delta(current.submitted, previous.submitted),
                    ring_dropped: monotonic_delta(current.dropped, previous.dropped),
                    collector_received: ingress.received,
                    collector_ingress: Some(CollectorIngressAccounting {
                        collector_enqueued: ingress.enqueued,
                        collector_dropped: ingress.dropped,
                    }),
                    logical_events: window.logical_events,
                    queue_admitted: window.queue_admitted,
                    queue_dropped: window.queue_dropped,
                }
            })
            .collect();
        let accounting = CollectorPipelineAccounting {
            schema_version: "anysentry.pipeline_accounting.v1".to_string(),
            producer_instance_id: self.producer_instance_id.clone(),
            sequence: self.next_sequence,
            window: CollectorPipelineWindow {
                started_at_unix_ms: self.window_started_unix_ms,
                ended_at_unix_ms,
            },
            temporality: "delta".to_string(),
            unit: CollectorPipelineUnit {
                ring: "physical_record".to_string(),
                queue: "logical_event".to_string(),
            },
            rings,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.window_started_unix_ms = ended_at_unix_ms;
        self.previous_kernel = kernel;
        self.previous_handoff = handoff;
        accounting
    }
}

fn monotonic_delta(current: u64, previous: u64) -> u64 {
    current.checked_sub(previous).unwrap_or(current)
}

fn unix_now_ms_u64() -> u64 {
    (system_now_unix_ns().unwrap_or_default() / 1_000_000).min(u128::from(u64::MAX)) as u64
}

impl CollectorMeta {
    fn from_env(file_features: FileFeatureFlags, ssl: bool, attached: usize) -> Self {
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
        if file_features.access || file_features.delete {
            enabled_features.push("files".to_string());
        }
        if file_features.access {
            enabled_features.push("file_access".to_string());
        }
        if file_features.delete {
            enabled_features.push("file_delete".to_string());
        }
        if ssl {
            enabled_features.push("ssl".to_string());
        }
        let mode = if file_features.access || file_features.delete || ssl {
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

fn tls_diagnostics_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| env_enabled("A3S_OBSERVER_TLS_DIAGNOSTICS"))
}

fn hostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn partial_window_interval_secs(elapsed: Duration) -> u64 {
    elapsed
        .as_secs()
        .saturating_add(u64::from(elapsed.subsec_nanos() > 0))
}

#[allow(clippy::too_many_arguments)]
fn collector_heartbeat(
    meta: &CollectorMeta,
    interval_secs: u64,
    stats: &Stats,
    dropped: u64,
    output_dropped: u64,
    file_filter: FileFilterHeartbeatSnapshot,
    pipeline_accounting: Option<CollectorPipelineAccounting>,
    capture_profile: Option<CollectorCaptureProfileStats>,
    shutdown_final: bool,
) -> EnrichedEvent {
    EnrichedEvent {
        timing: None,
        capture_decision: None,
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
            shutdown_final,
            attached_probes: meta.attached_probes,
            enabled_features: meta.enabled_features.clone(),
            interval_secs,
            observed_agents: stats.agents.len() as u64,
            exec: stats.exec,
            exit: stats.exit,
            egress: stats.egress,
            dns: stats.dns,
            file: stats.file,
            file_filter: Box::new(CollectorFileFilterStats {
                file_access: stats.file_access,
                file_delete: stats.file_delete,
                file_prefilter_access_kept: file_filter.stats.access_kept,
                file_prefilter_access_unknown_kept: file_filter.stats.access_unknown_kept,
                file_prefilter_access_sampled: file_filter.stats.access_sampled,
                file_prefilter_access_dropped: file_filter.stats.access_dropped,
                file_prefilter_access_suppressed: file_filter.stats.access_sample_suppressed,
                file_prefilter_delete_kept: file_filter.stats.delete_kept,
                file_prefilter_delete_unknown_kept: file_filter.stats.delete_unknown_kept,
                file_prefilter_delete_dropped: file_filter.stats.delete_dropped,
                file_prefilter_rule_hits: file_filter.stats.rule_hits,
                file_prefilter_rule_misses: file_filter.stats.rule_misses,
                file_prefilter_stale_rules: file_filter.stats.stale_rules,
                file_access_ring_dropped: file_filter.stats.access_ring_dropped,
                file_delete_ring_dropped: file_filter.stats.delete_ring_dropped,
                file_filter_enabled: file_filter.enabled,
                file_filter_epoch: file_filter.epoch,
                file_filter_unknown_policy: file_filter.unknown_policy.name().to_string(),
            }),
            llm: stats.llm,
            ssl: stats.ssl,
            sec: stats.sec,
            exec_truncated: stats.exec_truncated,
            exec_incomplete: stats.exec_incomplete,
            exec_reassembly_timeout: stats.exec_reassembly_timeout,
            dropped,
            output_dropped,
            pipeline_accounting: pipeline_accounting.map(Box::new),
            capture_profile: capture_profile.map(Box::new),
        },
    }
}

/// Export an event and count it by kind for the throughput report.
fn emit(exporter: &dyn Exporter, stats: &mut Stats, origin: PipelineRing, ev: EnrichedEvent) {
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
        AgentEvent::FileAccess { .. } => {
            stats.file += 1;
            stats.file_access += 1;
        }
        AgentEvent::FileDelete { .. } => {
            stats.file += 1;
            stats.file_delete += 1;
        }
        AgentEvent::LlmCall { .. } => stats.llm += 1,
        AgentEvent::LlmInteraction(..) => stats.llm += 1,
        AgentEvent::AgentPlaintextEvidence(..) => {}
        AgentEvent::SslContent { .. } => stats.ssl += 1,
        AgentEvent::LlmApi { .. } => stats.llm += 1,
        AgentEvent::SecurityAction { .. } => stats.sec += 1,
        AgentEvent::CaptureAggregate { .. } => {}
        AgentEvent::CollectorHeartbeat { .. } => {}
    }
    if !matches!(ev.event, AgentEvent::CollectorHeartbeat { .. }) {
        if let Some(agent) = &ev.identity.agent {
            stats.agents.insert(agent.clone());
        }
    }
    let outcome = exporter.export_with_priority(&ev, origin.export_priority());
    stats.record_export(origin, outcome);
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

fn sock_key(cgroup_id: u64, pid: u32, fd: u32) -> SocketKey {
    SocketKey { cgroup_id, pid, fd }
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

/// Best-effort LLM-API fields from captured TLS plaintext: `"model"` from a request body, token
/// `usage` from a response. None if absent (not an LLM call, or the bytes weren't captured).
/// Consumes untrusted plaintext — every index is bounds-checked, must never panic.
#[cfg(test)]
fn parse_llm_meta(s: &str) -> Option<(Option<String>, Option<u32>, Option<u32>)> {
    let model = json_str_after(s, "\"model\"");
    let pt = json_num_after(s, "\"prompt_tokens\"");
    let ct = json_num_after(s, "\"completion_tokens\"");
    (model.is_some() || pt.is_some() || ct.is_some()).then_some((model, pt, ct))
}

#[cfg(test)]
fn json_str_after(s: &str, key: &str) -> Option<String> {
    let rest = &s[s.find(key)? + key.len()..]; // find() ≤ len, +key.len() ≤ len → in-bounds
    let body = &rest[rest.find('"')? + 1..]; // past the value's opening quote
    Some(body[..body.find('"')?].to_owned())
}

#[cfg(test)]
fn json_num_after(s: &str, key: &str) -> Option<u32> {
    let rest = s[s.find(key)? + key.len()..].trim_start_matches([':', ' ', '\t']);
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest.get(..end)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{
        collector_heartbeat, cstr, env_value_disabled, exec_ppid, exec_process_context,
        exit_lifecycle_context, file_feature_flags_from, monotonic_delta,
        observe_exec_commit_lifecycle, parse_dns_qname, parse_filter_rule_snapshot, parse_llm_meta,
        parse_process_start_time_ticks, parse_rfc3339_unix_nanos, parse_sni,
        parse_unknown_file_policy, partial_window_interval_secs, pod_bytes, pod_from_bytes,
        supplement_exec_argv_at, tls_capture_profile_needs_refresh, tls_exec_comm_needs_refresh,
        CollectorMeta, CollectorProcessor, CompletedExec, ExecAssembler, FileFeatureFlags,
        FileFilterHeartbeatSnapshot, PipelineAccountingState, PipelineRing, ProcessContextCache,
        ProcessLifecycleStore, RingReaderLedgerSnapshot, RingWindowStats, Stats, UnknownFilePolicy,
        EXEC_REASSEMBLY_TIMEOUT, FILE_ACCESS_TRACEPOINTS,
    };
    use a3s_observer::{AgentEvent, ExportPriority, ProcessContext};
    use a3s_observer_common::{
        CaptureDecisionContext, ExecRecord, FileFilterConfig, FileFilterStats, FileFilterValue,
        RingPipelineStats, CAPTURE_DECISION_FLAG_SELECTED, CAPTURE_PROFILE_AGENT_FULL,
        CAPTURE_PROFILE_INVESTIGATION_FULL, CAPTURE_PROFILE_PROBABLE_INVESTIGATION,
        EXEC_ARG_CHUNK_PAYLOAD, EXEC_FLAG_ARGV_TRUNCATED, EXEC_RECORD_ARG_CHUNK,
        EXEC_RECORD_COMMIT, EXEC_RECORD_END, EXEC_RECORD_HEADER, FILE_FILTER_ACTION_DROP,
        FILE_FILTER_ACTION_SAMPLE, FILE_FILTER_AUTHORITY_AUTHORITATIVE,
        FILE_FILTER_AUTHORITY_CANDIDATE, FILE_FILTER_CONFIG_ENABLED,
        FILE_FILTER_CONFIG_UNKNOWN_SAMPLE, PIPELINE_RING_COUNT, PIPELINE_RING_EXEC,
        PIPELINE_RING_FILE_ACCESS,
    };
    use std::fs;
    use std::time::{Duration, Instant};

    #[test]
    fn raw_ring_export_priorities_preserve_critical_capacity() {
        for ring in PipelineRing::ALL {
            let expected = match ring {
                PipelineRing::Exec
                | PipelineRing::Exit
                | PipelineRing::FileDelete
                | PipelineRing::Security => ExportPriority::Critical,
                PipelineRing::Tls
                | PipelineRing::Connect
                | PipelineRing::Dns
                | PipelineRing::FileAccess
                | PipelineRing::Llm
                | PipelineRing::Ssl => ExportPriority::Semantic,
                PipelineRing::FileRead => ExportPriority::Bulk,
            };
            assert_eq!(ring.export_priority(), expected);
        }
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
    fn exec_driven_tls_refresh_is_limited_to_known_agent_runtime_names() {
        for candidate in ["codex", "claude", "claude.exe", "pi", "codex-code-mode"] {
            assert!(tls_exec_comm_needs_refresh(candidate), "{candidate}");
        }
        for tool in ["bash", "git", "python3", "node", "curl"] {
            assert!(!tls_exec_comm_needs_refresh(tool), "{tool}");
        }
    }

    #[test]
    fn identity_verified_capture_profiles_enable_product_neutral_tls_discovery() {
        for profile in [
            CAPTURE_PROFILE_AGENT_FULL,
            CAPTURE_PROFILE_INVESTIGATION_FULL,
            CAPTURE_PROFILE_PROBABLE_INVESTIGATION,
        ] {
            assert!(tls_capture_profile_needs_refresh(profile));
        }
        for profile in [0, 1, 4, 5, 6, 7] {
            assert!(!tls_capture_profile_needs_refresh(profile));
        }
    }

    #[test]
    fn file_feature_flags_keep_legacy_behavior_and_allow_independent_overrides() {
        assert_eq!(
            file_feature_flags_from(true, None, None, None, None),
            FileFeatureFlags {
                access: true,
                delete: true
            }
        );
        assert_eq!(
            file_feature_flags_from(true, Some(false), None, Some(true), None),
            FileFeatureFlags {
                access: false,
                delete: true
            }
        );
        assert_eq!(
            file_feature_flags_from(false, None, Some(true), None, Some(false)),
            FileFeatureFlags {
                access: true,
                delete: false
            }
        );
    }

    #[test]
    fn file_access_covers_openat2_without_replacing_legacy_tracepoints() {
        assert_eq!(
            FILE_ACCESS_TRACEPOINTS,
            [
                ("file_open", "sys_enter_openat"),
                ("file_openat2", "sys_enter_openat2"),
                ("file_open_legacy", "sys_enter_open"),
            ]
        );
    }

    #[test]
    fn unknown_file_policy_defaults_to_keep_and_requires_explicit_sample() {
        assert_eq!(
            parse_unknown_file_policy(None).unwrap(),
            UnknownFilePolicy::Keep
        );
        assert_eq!(
            parse_unknown_file_policy(Some("")).unwrap(),
            UnknownFilePolicy::Keep
        );
        assert_eq!(
            parse_unknown_file_policy(Some("keep")).unwrap(),
            UnknownFilePolicy::Keep
        );
        assert_eq!(
            parse_unknown_file_policy(Some("sample")).unwrap(),
            UnknownFilePolicy::Sample
        );
        assert!(parse_unknown_file_policy(Some("true")).is_err());
        assert!(parse_unknown_file_policy(Some("drop")).is_err());
    }

    #[test]
    fn shared_config_keeps_unknown_unless_sample_flag_is_explicit() {
        let keep = FileFilterConfig {
            flags: FILE_FILTER_CONFIG_ENABLED,
            ..FileFilterConfig::default()
        };
        assert!(keep.enabled());
        assert!(!keep.unknown_sampling_enabled());

        let sample = FileFilterConfig {
            flags: FILE_FILTER_CONFIG_ENABLED | FILE_FILTER_CONFIG_UNKNOWN_SAMPLE,
            ..FileFilterConfig::default()
        };
        assert!(sample.enabled());
        assert!(sample.unknown_sampling_enabled());
        let bytes = pod_bytes::<_, 32>(&sample);
        let decoded = pod_from_bytes::<FileFilterConfig, 32>(&bytes);
        assert!(decoded.unknown_sampling_enabled());
    }

    #[test]
    fn filter_pod_encoding_preserves_the_shared_abi() {
        let value = FileFilterValue {
            action: 2,
            authority: 1,
            flags: 7,
            _reserved: 0,
            epoch: 41,
            expires_at_boot_ns: 99,
        };
        let bytes = pod_bytes::<_, 24>(&value);
        let decoded = pod_from_bytes::<FileFilterValue, 24>(&bytes);
        assert_eq!(decoded.action, value.action);
        assert_eq!(decoded.authority, value.authority);
        assert_eq!(decoded.flags, value.flags);
        assert_eq!(decoded.epoch, value.epoch);
        assert_eq!(decoded.expires_at_boot_ns, value.expires_at_boot_ns);
    }

    #[test]
    fn parses_rfc3339_expiry_with_fraction_and_offset() {
        assert_eq!(
            parse_rfc3339_unix_nanos("1970-01-01T00:00:01.250Z").unwrap(),
            1_250_000_000
        );
        assert_eq!(
            parse_rfc3339_unix_nanos("1970-01-01T01:00:00+01:00").unwrap(),
            0
        );
        assert!(parse_rfc3339_unix_nanos("2026-02-30T00:00:00Z").is_err());
    }

    #[test]
    fn filter_snapshot_downgrades_candidate_drop_and_converts_expiry() {
        let now_unix_ns = parse_rfc3339_unix_nanos("2026-08-17T00:00:00Z").unwrap();
        let snapshot = br#"{
          "schemaVersion":"anysentry.filter_rule_snapshot.v1",
          "epoch":7,
          "entries":[{
            "cgroupId":"18412",
            "action":"drop",
            "authority":"candidate",
            "epoch":7,
            "expiresAt":"2026-08-17T00:00:05Z"
          },{
            "cgroupId":"18413",
            "action":"drop",
            "authority":"authoritative",
            "epoch":7,
            "expiresAt":"2026-08-17T00:00:05Z"
          }]
        }"#;
        let parsed = parse_filter_rule_snapshot(snapshot, now_unix_ns, 10_000).unwrap();
        assert_eq!(parsed.epoch, 7);
        assert_eq!(parsed.rules.len(), 2);
        assert_eq!(parsed.rules[0].0.cgroup_id, 18_412);
        assert_eq!(parsed.rules[0].1.action, FILE_FILTER_ACTION_SAMPLE);
        assert_eq!(parsed.rules[0].1.authority, FILE_FILTER_AUTHORITY_CANDIDATE);
        assert_eq!(parsed.rules[0].1.expires_at_boot_ns, 5_000_010_000);
        assert_eq!(parsed.rules[1].1.action, FILE_FILTER_ACTION_DROP);
        assert_eq!(
            parsed.rules[1].1.authority,
            FILE_FILTER_AUTHORITY_AUTHORITATIVE
        );
    }

    #[test]
    fn filter_snapshot_rejects_mixed_epochs_and_duplicate_cgroups() {
        let mixed = br#"{
          "schemaVersion":"anysentry.filter_rule_snapshot.v1",
          "entries":[
            {"cgroupId":"1","action":"keep","authority":"authoritative","epoch":1,"expiresAt":"2026-08-17T00:00:05Z"},
            {"cgroupId":"2","action":"keep","authority":"authoritative","epoch":2,"expiresAt":"2026-08-17T00:00:05Z"}
          ]
        }"#;
        assert!(parse_filter_rule_snapshot(mixed, 0, 0).is_err());

        let duplicate = br#"{
          "schemaVersion":"anysentry.filter_rule_snapshot.v1",
          "epoch":1,
          "entries":[
            {"cgroupId":"1","action":"keep","authority":"authoritative","epoch":1,"expiresAt":"2026-08-17T00:00:05Z"},
            {"cgroupId":"1","action":"sample","authority":"candidate","epoch":1,"expiresAt":"2026-08-17T00:00:05Z"}
          ]
        }"#;
        assert!(parse_filter_rule_snapshot(duplicate, 0, 0).is_err());
    }

    #[test]
    fn collector_heartbeat_preserves_partial_window_and_drop_counters() {
        let meta = CollectorMeta {
            collector_id: "collector-test".into(),
            node_name: Some("node-test".into()),
            namespace: Some("namespace-test".into()),
            pod_name: Some("pod-test".into()),
            version: "0.11.0".into(),
            mode: "observe".into(),
            attached_probes: 24,
            enabled_features: vec!["exec".into(), "network".into()],
        };
        let mut stats = Stats {
            exec: 3,
            exec_incomplete: 1,
            exit: 2,
            egress: 4,
            dns: 5,
            file: 6,
            file_access: 4,
            file_delete: 2,
            llm: 7,
            ssl: 8,
            sec: 9,
            ..Stats::default()
        };
        stats.agents.insert("codex".into());

        let filter_stats = FileFilterStats {
            access_kept: 40,
            access_unknown_kept: 37,
            access_sampled: 3,
            access_dropped: 50,
            access_sample_suppressed: 60,
            delete_kept: 2,
            delete_unknown_kept: 1,
            delete_dropped: 1,
            rule_hits: 90,
            rule_misses: 10,
            stale_rules: 4,
            access_ring_dropped: 5,
            delete_ring_dropped: 1,
        };
        let heartbeat = collector_heartbeat(
            &meta,
            17,
            &stats,
            11,
            13,
            FileFilterHeartbeatSnapshot {
                stats: filter_stats,
                enabled: true,
                epoch: 42,
                unknown_policy: UnknownFilePolicy::Sample,
            },
            None,
            None,
            true,
        );
        let serialized = serde_json::to_value(&heartbeat).unwrap();
        let AgentEvent::CollectorHeartbeat {
            collector_id,
            interval_secs,
            shutdown_final,
            observed_agents,
            exec,
            exit,
            egress,
            dns,
            file,
            file_filter,
            llm,
            ssl,
            sec,
            exec_incomplete,
            dropped,
            output_dropped,
            ..
        } = heartbeat.event
        else {
            panic!("expected CollectorHeartbeat");
        };
        assert_eq!(collector_id, "collector-test");
        assert_eq!(interval_secs, 17);
        assert!(shutdown_final);
        assert_eq!(observed_agents, 1);
        assert_eq!((exec, exit, egress, dns, file), (3, 2, 4, 5, 6));
        assert_eq!((file_filter.file_access, file_filter.file_delete), (4, 2));
        assert_eq!(file_filter.file_prefilter_access_suppressed, 60);
        assert_eq!(file_filter.file_prefilter_access_unknown_kept, 37);
        assert_eq!(file_filter.file_prefilter_delete_unknown_kept, 1);
        assert_eq!(file_filter.file_delete_ring_dropped, 1);
        assert!(file_filter.file_filter_enabled);
        assert_eq!(file_filter.file_filter_epoch, 42);
        assert_eq!(file_filter.file_filter_unknown_policy, "sample");
        assert_eq!((llm, ssl, sec, exec_incomplete), (7, 8, 9, 1));
        assert_eq!((dropped, output_dropped), (11, 13));

        let payload = &serialized["event"]["CollectorHeartbeat"];
        assert_eq!(payload["file_access"], 4);
        assert_eq!(payload["file_filter_epoch"], 42);
        assert_eq!(payload["file_filter_unknown_policy"], "sample");
        assert!(payload.get("file_filter").is_none());
    }

    #[test]
    fn pipeline_accounting_emits_restart_safe_deltas_and_separates_exec_units() {
        let mut state = PipelineAccountingState {
            producer_instance_id: "producer-test".into(),
            next_sequence: 4,
            window_started_unix_ms: 100,
            previous_kernel: [RingPipelineStats::default(); PIPELINE_RING_COUNT],
            previous_handoff: [RingReaderLedgerSnapshot::default(); PIPELINE_RING_COUNT],
        };
        let mut stats = Stats::default();
        stats.pipeline[PIPELINE_RING_EXEC as usize] = RingWindowStats {
            logical_events: 2,
            queue_admitted: 1,
            queue_dropped: 1,
        };
        stats.pipeline[PIPELINE_RING_FILE_ACCESS as usize] = RingWindowStats {
            logical_events: 3,
            queue_admitted: 3,
            queue_dropped: 0,
        };
        let mut kernel = [RingPipelineStats::default(); PIPELINE_RING_COUNT];
        kernel[PIPELINE_RING_EXEC as usize] = RingPipelineStats {
            submitted: 7,
            dropped: 2,
        };
        kernel[PIPELINE_RING_FILE_ACCESS as usize] = RingPipelineStats {
            submitted: 3,
            dropped: 1,
        };

        let mut handoff = [RingReaderLedgerSnapshot::default(); PIPELINE_RING_COUNT];
        handoff[PIPELINE_RING_EXEC as usize] = RingReaderLedgerSnapshot {
            received: 7,
            enqueued: 6,
            dropped: 1,
        };
        handoff[PIPELINE_RING_FILE_ACCESS as usize] = RingReaderLedgerSnapshot {
            received: 3,
            enqueued: 3,
            dropped: 0,
        };
        let first = state.snapshot(&stats, handoff, kernel, 200);
        assert_eq!(first.schema_version, "anysentry.pipeline_accounting.v1");
        assert_eq!(first.producer_instance_id, "producer-test");
        assert_eq!(first.sequence, 4);
        assert_eq!(first.window.started_at_unix_ms, 100);
        assert_eq!(first.window.ended_at_unix_ms, 200);
        assert_eq!(first.temporality, "delta");
        assert_eq!(first.unit.ring, "physical_record");
        assert_eq!(first.unit.queue, "logical_event");
        let exec = first
            .rings
            .iter()
            .find(|entry| entry.ring == "exec")
            .unwrap();
        assert_eq!((exec.ring_submitted, exec.ring_dropped), (7, 2));
        assert_eq!(exec.collector_received, 7);
        let exec_ingress = exec.collector_ingress.as_ref().unwrap();
        assert_eq!(exec_ingress.collector_enqueued, 6);
        assert_eq!(exec_ingress.collector_dropped, 1);
        assert_eq!(
            exec.collector_received,
            exec_ingress.collector_enqueued + exec_ingress.collector_dropped
        );
        // Seven physical ExecRecords reassemble into two logical ToolExec events.
        assert_eq!(exec.logical_events, 2);
        assert_eq!(
            exec.logical_events,
            exec.queue_admitted + exec.queue_dropped
        );

        let mut next_kernel = kernel;
        next_kernel[PIPELINE_RING_EXEC as usize].submitted = 12;
        next_kernel[PIPELINE_RING_EXEC as usize].dropped = 3;
        let second = state.snapshot(&Stats::default(), handoff, next_kernel, 300);
        let next_exec = second
            .rings
            .iter()
            .find(|entry| entry.ring == "exec")
            .unwrap();
        assert_eq!(second.sequence, 5);
        assert_eq!(second.window.started_at_unix_ms, 200);
        assert_eq!((next_exec.ring_submitted, next_exec.ring_dropped), (5, 1));
        assert_eq!(next_exec.collector_received, 0);
    }

    #[test]
    fn monotonic_delta_treats_a_counter_reset_as_a_new_baseline() {
        assert_eq!(monotonic_delta(12, 5), 7);
        assert_eq!(monotonic_delta(3, 9), 3);
    }

    #[test]
    fn partial_window_interval_rounds_up_without_inventing_a_zero_window() {
        assert_eq!(partial_window_interval_secs(Duration::ZERO), 0);
        assert_eq!(partial_window_interval_secs(Duration::from_nanos(1)), 1);
        assert_eq!(partial_window_interval_secs(Duration::from_secs(1)), 1);
        assert_eq!(
            partial_window_interval_secs(Duration::from_secs(1) + Duration::from_nanos(1)),
            2
        );
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
                ..ProcessContext::default()
            },
            now,
        );
        assert_eq!(
            cache
                .get(42, 77, "worker", now + Duration::from_millis(10))
                .and_then(|context| context.start_time_ticks),
            Some(900),
        );
        assert!(cache
            .get(42, 78, "worker", now + Duration::from_millis(20))
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
        record.capture_decision = selected_capture_context(77);
        record
    }

    fn selected_capture_context(epoch: u64) -> CaptureDecisionContext {
        CaptureDecisionContext {
            capture_epoch: epoch,
            capture_profile: 6,
            capture_action: 1,
            capture_authority: 2,
            capture_disposition: 1,
            flags: CAPTURE_DECISION_FLAG_SELECTED,
            _reserved: [0; 3],
        }
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
            event_at_unix_ns: 1_700_000_000_000_000_000,
            received_at_unix_ns: 1_700_000_000_000_000_100,
            capture_decision: selected_capture_context(77),
            exec_id: 1,
            cgroup_id: 73,
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
    fn exec_commit_replaces_pre_exec_scope_for_lifecycle_matching() {
        let now = Instant::now();
        let mut assembler = ExecAssembler::default();
        let mut header = exec_record(6, EXEC_RECORD_HEADER);
        header.cgroup_id = 71;
        header.comm[..4].copy_from_slice(b"bash");
        assembler.push(header, now);
        let mut end = exec_record(6, EXEC_RECORD_END);
        end.cgroup_id = 71;
        end.argc = 0;
        assembler.push(end, now);
        let mut commit = exec_record(6, EXEC_RECORD_COMMIT);
        commit.cgroup_id = 72;
        commit.ppid = 43;
        commit.uid = 2000;
        commit.comm[..6].copy_from_slice(b"worker");

        let completed = assembler.push(commit, now).pop().unwrap();
        assert_eq!(cstr(&completed.comm), "worker");
        assert_eq!(completed.cgroup_id, 72);
        assert_eq!(completed.ppid, 43);
        assert_eq!(completed.uid, 2000);
    }

    #[test]
    fn exec_logical_event_uses_commit_time_and_latest_fragment_receipt() {
        let now = Instant::now();
        let mut assembler = ExecAssembler::default();
        let decision = selected_capture_context(77);
        let header = exec_record(60, EXEC_RECORD_HEADER);
        assert!(assembler
            .push_timed(header, 1_000, 1_100, decision, now)
            .is_empty());
        let mut end = exec_record(60, EXEC_RECORD_END);
        end.argc = 0;
        assert!(assembler
            .push_timed(end, 1_000, 1_200, decision, now)
            .is_empty());
        let commit = exec_record(60, EXEC_RECORD_COMMIT);
        let completed = assembler
            .push_timed(commit, 1_500, 1_600, decision, now)
            .pop()
            .unwrap();

        assert_eq!(completed.event_at_unix_ns, 1_500);
        assert_eq!(completed.received_at_unix_ns, 1_600);
        assert_eq!(completed.capture_decision, decision);
    }

    #[test]
    fn exec_fragment_decision_mismatch_is_explicit_and_never_mixes_epochs() {
        let now = Instant::now();
        let mut assembler = ExecAssembler::default();
        let original = selected_capture_context(77);
        let mismatched = selected_capture_context(78);
        let header = exec_record(62, EXEC_RECORD_HEADER);
        assert!(assembler
            .push_timed(header, 1_000, 1_100, original, now)
            .is_empty());
        let commit = exec_record(62, EXEC_RECORD_COMMIT);
        let completed = assembler
            .push_timed(commit, 1_500, 1_600, mismatched, now)
            .pop()
            .unwrap();

        assert_eq!(completed.capture_decision, original);
        assert!(completed.argv_incomplete);
    }

    #[test]
    fn commit_only_record_recovers_exit_before_argv_reassembly_timeout() {
        let now = Instant::now();
        let mut assembler = ExecAssembler::default();
        let mut lifecycles = ProcessLifecycleStore::default();
        let mut commit = exec_record(61, EXEC_RECORD_COMMIT);
        commit.cgroup_id = 99;
        commit.ppid = 7;
        commit.comm[..6].copy_from_slice(b"worker");

        observe_exec_commit_lifecycle(&mut lifecycles, &commit, now);
        let completed = assembler.push(commit, now).pop().unwrap();
        assert!(completed.exec_confirmed);
        assert!(completed.argv_incomplete);
        assert!(!completed.reassembly_timed_out);
        assert!(assembler.expire(now + EXEC_REASSEMBLY_TIMEOUT).is_empty());

        let resolved = lifecycles.resolve_exit(
            61,
            exit_lifecycle_context(u32::MAX, 99, "worker".into()),
            now + Duration::from_millis(10),
        );
        assert_eq!(resolved.process.ppid, 7);
        assert_eq!(
            resolved.process.lifecycle_source.as_deref(),
            Some("exec_tombstone")
        );
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
            event_at_unix_ns: 1_700_000_000_000_000_000,
            received_at_unix_ns: 1_700_000_000_000_000_100,
            capture_decision: selected_capture_context(77),
            exec_id: 2,
            cgroup_id: 99,
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
    fn parse_llm_meta_extracts_model_and_tokens() {
        let req = r#"POST /v1/chat/completions HTTP/1.1 ... {"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#;
        assert_eq!(parse_llm_meta(req).unwrap().0.as_deref(), Some("gpt-4o"));
        let resp = r#"{"id":"x","choices":[],"usage":{"prompt_tokens":12,"completion_tokens":34}}"#;
        let (_, pt, ct) = parse_llm_meta(resp).unwrap();
        assert_eq!((pt, ct), (Some(12), Some(34)));
        assert!(parse_llm_meta("just plaintext, no json fields here").is_none());
    }

    #[test]
    fn exact_agent_exec_gets_bounded_fast_tls_attach_retries() {
        let now = Instant::now();
        let pid = std::process::id() as i32;
        let mut processor = CollectorProcessor::new(true);
        processor.tls_verified_candidate_pids.insert(pid);
        processor.tls_fast_retry_candidate_pids.insert(pid);

        assert_eq!(
            processor.take_tls_attach_candidate_pids(now),
            vec![(pid, true, Some(0))]
        );
        processor.schedule_tls_attach_retry(pid, true, 0, now);
        assert!(processor
            .take_tls_attach_candidate_pids(now + Duration::from_millis(24))
            .is_empty());
        assert_eq!(
            processor.take_tls_attach_candidate_pids(now + Duration::from_millis(25)),
            vec![(pid, true, Some(1))]
        );
        processor.schedule_tls_attach_retry(pid, true, 7, now);
        assert!(processor.tls_attach_retries.is_empty());
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
