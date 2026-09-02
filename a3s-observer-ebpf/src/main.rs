#![no_std]
#![no_main]

use a3s_observer_common::{
    capture_cpu_sample_quota, capture_probe_is_protected, capture_profile_default_actions,
    capture_sample_partitions, file_access_mode, CaptureAggregateKey, CaptureAggregateValue,
    CaptureDecisionContext, CaptureProbeStats, CaptureProcessKey, CaptureProfileConfig,
    CaptureProfileKey, CaptureProfileValue, CapturePromotionValue, CaptureSampleKey,
    CaptureSampleWindow, ConnectEvent, DnsEvent, ExecRecord, ExitEvent, FileEvent,
    FileFilterConfig, FileFilterKey, FileFilterSampleWindow, FileFilterStats, FileFilterValue,
    FileProcessFilterKey, LlmEvent, RingPipelineStats, SecEvent, TlsEvent, TlsPlaintextEventHeader,
    TlsPlaintextEventLarge, TlsPlaintextEventMedium, TlsPlaintextEventSmall, ARGV_SLOTS,
    CAPTURE_ACTION_AGGREGATE, CAPTURE_ACTION_DROP, CAPTURE_ACTION_FULL, CAPTURE_ACTION_NOT_ENABLED,
    CAPTURE_ACTION_SAMPLE, CAPTURE_CONFIG_DESTRUCTIVE_GRANTED,
    CAPTURE_DECISION_FLAG_EMERGENCY_SAMPLE, CAPTURE_DECISION_FLAG_LEGACY,
    CAPTURE_DECISION_FLAG_PROMOTED, CAPTURE_DECISION_FLAG_PROTECTED,
    CAPTURE_DECISION_FLAG_SELECTED, CAPTURE_DECISION_FLAG_SHADOW,
    CAPTURE_DECISION_FLAG_VERIFIED_AGENT, CAPTURE_DISPOSITION_MISS, CAPTURE_DISPOSITION_RULE,
    CAPTURE_DISPOSITION_STALE, CAPTURE_MODE_SHADOW, CAPTURE_PROBE_CONNECT, CAPTURE_PROBE_DNS,
    CAPTURE_PROBE_EXEC, CAPTURE_PROBE_EXIT, CAPTURE_PROBE_FILE_ACCESS, CAPTURE_PROBE_FILE_DELETE,
    CAPTURE_PROBE_FILE_READ, CAPTURE_PROBE_LLM, CAPTURE_PROBE_SECURITY, CAPTURE_PROBE_SSL,
    CAPTURE_PROBE_TLS, CAPTURE_PROFILE_AGENT_FULL, CAPTURE_PROFILE_FLAG_AGENT,
    CAPTURE_PROFILE_FLAG_CONFLICT, CAPTURE_PROFILE_INVESTIGATION_FULL,
    CAPTURE_PROFILE_PROBABLE_INVESTIGATION, CAPTURE_PROFILE_SECURITY_FULL,
    CAPTURE_PROFILE_UNKNOWN_DISCOVERY, CAPTURE_PROMOTION_FLAG_DESCENDANT,
    CAPTURE_PROMOTION_FLAG_INVESTIGATION, CAPTURE_PROMOTION_FLAG_ROOT, DNS_SNAP_LEN,
    EXEC_ARG_CHUNK_PAYLOAD, EXEC_FLAG_ARGV_INCOMPLETE, EXEC_FLAG_ARGV_TRUNCATED, EXEC_MAX_CHUNKS,
    EXEC_RECORD_ARG_CHUNK, EXEC_RECORD_COMMIT, EXEC_RECORD_END, EXEC_RECORD_HEADER,
    FILE_ACCESS_MODE_PATH_ONLY, FILE_ACCESS_MODE_READ_ONLY, FILE_ACCESS_MODE_SPECIAL,
    FILE_ACCESS_MODE_UNKNOWN, FILE_DELETE_FLAG, FILE_FILTER_ACTION_DROP, FILE_FILTER_ACTION_KEEP,
    FILE_FILTER_AUTHORITY_AUTHORITATIVE, PATH_SNAP_LEN, PIPELINE_RING_CONNECT, PIPELINE_RING_COUNT,
    PIPELINE_RING_DNS, PIPELINE_RING_EXEC, PIPELINE_RING_EXIT, PIPELINE_RING_FILE_ACCESS,
    PIPELINE_RING_FILE_DELETE, PIPELINE_RING_FILE_READ, PIPELINE_RING_LLM, PIPELINE_RING_SECURITY,
    PIPELINE_RING_SSL, PIPELINE_RING_TLS, SEC_BIND, SEC_PTRACE, SEC_SETUID, TLS_PLAINTEXT_ABI_V1,
    TLS_PLAINTEXT_API_RUSTLS, TLS_PLAINTEXT_API_SSL_CLASSIC, TLS_PLAINTEXT_API_SSL_EX,
    TLS_PLAINTEXT_API_TCP, TLS_PLAINTEXT_DIRECTION_READ, TLS_PLAINTEXT_DIRECTION_WRITE,
    TLS_PLAINTEXT_FLAG_CONNECTION_UNBOUND, TLS_PLAINTEXT_FLAG_TRUNCATED, TLS_PLAINTEXT_TIER_LARGE,
    TLS_PLAINTEXT_TIER_MEDIUM, TLS_PLAINTEXT_TIER_SMALL, TLS_SNAP_LEN,
};
use aya_ebpf::{
    cty::c_void,
    helpers::gen::bpf_probe_read_user,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_loop,
        bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{cgroup_sock_addr, kprobe, map, tracepoint, uprobe, uretprobe},
    maps::{
        ring_buf::RingBufEntry, Array, HashMap, LruHashMap, PerCpuArray, PerCpuHashMap, RingBuf,
    },
    programs::{ProbeContext, RetProbeContext, SockAddrContext, TracePointContext},
};

// Exec records are fixed at 216 B after the additive S4 event-time and D1 decision tails. Typical commands need
// one header, a few argument chunks and one end record; long argv values can use up to
// EXEC_MAX_CHUNKS records without inflating every short exec event.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

#[map]
static EXIT_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[map]
static TLS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[map]
// Confirmed Agent workloads bypass Unknown sampling and can legitimately open thousands of files
// in a short build/tool burst. One MiB keeps that burst isolated without returning to an unbounded
// shared ring; FileDelete remains on its own high-priority channel below.
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

// Read-only opens are opt-in for exact Agent Runtime/Root scopes and intentionally use a separate
// bulk channel. A repository scan must never consume the write/delete/security ring capacity.
#[map]
static FILE_READ_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

// Package managers and container cleanup can unlink thousands of files in milliseconds. A
// dedicated 4 MiB ring prevents access traffic from starving those bursts while preserving an
// independent loss counter.
#[map]
static FILE_DELETE_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

// Userspace fills an entire epoch before switching FILE_FILTER_CONFIG.active_epoch. Keeping epoch
// in the key makes that switch atomic even when the same cgroup exists in both generations.
#[map]
static FILE_FILTER_RULES: HashMap<FileFilterKey, FileFilterValue> =
    HashMap::with_max_entries(131_072, 0);

#[map]
static FILE_FILTER_CONFIG: Array<FileFilterConfig> = Array::with_max_entries(1, 0);

#[map]
static FILE_FILTER_STATS: PerCpuArray<FileFilterStats> = PerCpuArray::with_max_entries(1, 0);

#[map]
static UNKNOWN_FILE_WINDOWS: LruHashMap<u64, FileFilterSampleWindow> =
    LruHashMap::with_max_entries(16_384, 0);

#[map]
static UNKNOWN_FILE_GLOBAL_WINDOW: PerCpuArray<FileFilterSampleWindow> =
    PerCpuArray::with_max_entries(1, 0);

// Host ProcessTree shadow skeleton. V1 deliberately does not consult it: a PID-only enforcement
// decision would be unsafe until start-generation synchronization is available to the kernel side.
#[map]
static TRACKED_FILE_PROCESSES: LruHashMap<FileProcessFilterKey, FileFilterValue> =
    LruHashMap::with_max_entries(1_024, 0);

// S5 is entirely additive to the v1 File filter. Userspace enables exactly one path: legacy keeps
// these maps disabled; shadow/enforce disable FILE_FILTER_CONFIG and switch this epoch atomically.
#[map]
static CAPTURE_PROFILE_RULES: HashMap<CaptureProfileKey, CaptureProfileValue> =
    // Two complete generations coexist until the config array atomically switches epoch.
    HashMap::with_max_entries(131_072, 0);

#[map]
static CAPTURE_PROFILE_CONFIG: Array<CaptureProfileConfig> = Array::with_max_entries(1, 0);

#[map]
static CAPTURE_PROFILE_STATS: PerCpuArray<CaptureProbeStats> =
    PerCpuArray::with_max_entries(PIPELINE_RING_COUNT as u32, 0);

#[map]
static CAPTURE_SAMPLE_WINDOWS: LruHashMap<CaptureSampleKey, CaptureSampleWindow> =
    LruHashMap::with_max_entries(16_384, 0);

#[map]
static CAPTURE_GLOBAL_SAMPLE_WINDOWS: PerCpuArray<CaptureSampleWindow> =
    PerCpuArray::with_max_entries(1, 0);

// A separate, bounded reserve protects first discovery samples from established noisy scopes while
// still enforcing a hard node/CPU cap. It is a partition of, not an addition to, the global limit.
#[map]
static CAPTURE_FIRST_SAMPLE_WINDOWS: PerCpuArray<CaptureSampleWindow> =
    PerCpuArray::with_max_entries(1, 0);

// Deliberately bounded to 4096 keys: as a per-CPU map, a 65k capacity would multiply memory by the
// host CPU count. Insert failure is visible and falls back to the bounded emergency sample lane.
#[map]
static CAPTURE_AGGREGATES: PerCpuHashMap<CaptureAggregateKey, CaptureAggregateValue> =
    PerCpuHashMap::with_max_entries(4_096, 0);

#[map]
static CAPTURE_PROMOTED_PROCESSES: LruHashMap<CaptureProcessKey, CapturePromotionValue> =
    LruHashMap::with_max_entries(131_072, 0);

#[map]
static LLM_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// Security-sensitive actions (privesc / injection / open-port). In-kernel-filtered to the loud
// cases, so this stays near-empty — a small ring is plenty.
#[map]
static SEC_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// Count of events dropped because a ring was full — data-loss visibility under extreme load.
#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// Per-ring physical-record accounting. This is additive to `DROPS`: the legacy aggregate remains
// byte-for-byte compatible while userspace can now identify which ring admitted or lost records.
#[map]
static PIPELINE_ACCOUNTING: PerCpuArray<RingPipelineStats> =
    PerCpuArray::with_max_entries(PIPELINE_RING_COUNT as u32, 0);

// child tgid -> parent tgid, captured before the child runs (with syscall-exit fallback). Exec must carry
// this in-kernel snapshot because short-lived tools can exit before userspace reads /proc.
#[map]
static PARENTS: LruHashMap<u32, u32> = LruHashMap::with_max_entries(65_536, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingExecState {
    exec_id: u64,
    capture_decision: CaptureDecisionContext,
}

// tgid -> latest syscall-entry generation and its exact capture decision. `sched_process_exec`
// consumes both only after a successful exec, so every physical fragment and COMMIT carries one
// identical D1 decision even if the active profile changes while execve is in progress.
#[map]
static EXEC_IDS: LruHashMap<u32, PendingExecState> = LruHashMap::with_max_entries(65_536, 0);

// tgid -> latest successfully committed exec generation. Unlike EXEC_IDS this survives the
// sched_process_exec commit and is consumed only by do_exit, giving ProcessExit an event-time
// generation key that cannot be confused by later `/proc/<pid>` reuse.
#[map]
static COMMITTED_EXEC_IDS: LruHashMap<u32, u64> = LruHashMap::with_max_entries(65_536, 0);

// Egress deny-list (dest IPv4, host byte order). Populated by userspace from an external
// policy; the cgroup/connect4 guard denies connect() to any IP present here. Cgroup-scoped.
#[map]
static DENY_EGRESS: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

// Per-LLM-socket accumulator: (pid<<32|fd) -> running byte/time stats, started at the
// ClientHello and flushed on close. Only TLS-to-provider sockets are tracked → stays small.
#[map]
static LLM_SOCKS: HashMap<u64, LlmStat> = HashMap::with_max_entries(4096, 0);

// Per-thread (pid_tgid) -> fd, set on read-enter for tracked sockets so read-exit can
// attribute the byte count (the exit tracepoint has the return value but not the fd).
#[map]
static READ_FD: HashMap<u64, u32> = HashMap::with_max_entries(10240, 0);

// Opt-in TLS plaintext (uprobes). Tiered records capture common small calls without padding every
// reservation to the 512 KiB ceiling while retaining bounded large request/response bodies.
#[map]
static SSL_EVENTS: RingBuf = RingBuf::with_byte_size(32 * 1024 * 1024, 0);

#[map]
static SSL_CALL_ARGS: HashMap<u64, SslCallArgs> = HashMap::with_max_entries(10240, 0);

#[map]
static SSL_CALL_SEQUENCES: LruHashMap<u64, u64> = LruHashMap::with_max_entries(16_384, 0);

// Metadata-only diagnostics for implementation-family Rustls probes. No plaintext bytes or
// pointers leave eBPF through this map; userspace uses the counters to distinguish an unused
// boundary from an ABI-layout rejection or process-admission miss.
#[map]
static TLS_PROFILE_DIAGNOSTICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(21, 0);

#[inline(always)]
fn bump_tls_profile_diagnostic(index: u32) {
    if let Some(value) = TLS_PROFILE_DIAGNOSTICS.get_ptr_mut(index) {
        unsafe { *value = (*value).wrapping_add(1) };
    }
}

// Userspace inserts only identity-verified Agent roots and explicitly trusted network runtimes.
// TLS success is a separate condition enforced by PID-scoped uprobe attachment. URL, Host, route,
// model and provider configuration are deliberately absent from this kernel admission boundary.
#[map]
static VERIFIED_AGENT_PROCESSES: LruHashMap<PlaintextProcessKey, u8> =
    LruHashMap::with_max_entries(16_384, 0);

// Plain HTTP is different from a TLS-library boundary: generic write/writev also sees stdout and
// files. Admit a socket only after a selected process writes any syntactically valid HTTP request
// line. The Collector, not eBPF, decides whether its body is an LLM interaction.
#[map]
static HTTP_SOCKS: LruHashMap<u64, u8> = LruHashMap::with_max_entries(8_192, 0);

#[map]
static HTTP_READ_ARGS: HashMap<u64, HttpReadArgs> = HashMap::with_max_entries(10_240, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct SslCallArgs {
    ssl_ptr: u64,
    buf: u64,
    requested_len: u64,
    result_len_ptr: u64,
    started_at_boot_ns: u64,
    direction: u8,
    api_kind: u8,
    route_kind: u8,
    _pad: [u8; 5],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PlaintextProcessKey {
    cgroup_id: u64,
    pid: u32,
    _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct HttpReadArgs {
    fd: u32,
    _pad: u32,
    buf: u64,
    started_at_boot_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserIovec {
    base: u64,
    len: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LlmStat {
    start_ns: u64,
    first_resp_ns: u64,
    req_bytes: u64,
    resp_bytes: u64,
}

fn sock_key(pid: u32, fd: u64) -> u64 {
    ((pid as u64) << 32) | (fd & 0xffff_ffff)
}

/// Reserve a ring-buffer slot, counting a drop if the ring is full (so userspace can report
/// data loss instead of losing events silently). A successful reservation is not a submitted
/// physical record until `submit_accounted` commits it; probes may still discard the slot.
fn reserve_or_drop<T>(ring: &RingBuf, ring_index: u32) -> Option<RingBufEntry<T>> {
    let entry = ring.reserve::<T>(0);
    unsafe {
        if let Some(stats) = PIPELINE_ACCOUNTING.get_ptr_mut(ring_index) {
            if entry.is_none() {
                (*stats).dropped = (*stats).dropped.wrapping_add(1);
            }
        }
        if entry.is_none() {
            if let Some(stats) = CAPTURE_PROFILE_STATS.get_ptr_mut(ring_index) {
                (*stats).ring_dropped = (*stats).ring_dropped.wrapping_add(1);
            }
        }
        if entry.is_none() {
            if let Some(c) = DROPS.get_ptr_mut(0) {
                *c = (*c).wrapping_add(1);
            }
        }
    }
    entry
}

#[inline(always)]
fn submit_accounted<T>(entry: RingBufEntry<T>, ring_index: u32) {
    unsafe {
        if let Some(stats) = PIPELINE_ACCOUNTING.get_ptr_mut(ring_index) {
            (*stats).submitted = (*stats).submitted.wrapping_add(1);
        }
        if let Some(stats) = CAPTURE_PROFILE_STATS.get_ptr_mut(ring_index) {
            (*stats).ring_submitted = (*stats).ring_submitted.wrapping_add(1);
        }
    }
    entry.submit(0);
}

const CAPTURE_STAT_ATTEMPTED: u8 = 1;
const CAPTURE_STAT_FULL: u8 = 2;
const CAPTURE_STAT_AGGREGATE: u8 = 3;
const CAPTURE_STAT_SAMPLE: u8 = 4;
const CAPTURE_STAT_SAMPLE_REJECTED: u8 = 5;
const CAPTURE_STAT_DROP: u8 = 6;
const CAPTURE_STAT_DECISION_ERROR: u8 = 7;
const CAPTURE_STAT_PAYLOAD_SELECTED: u8 = 8;
const CAPTURE_STAT_PAYLOAD_ERROR: u8 = 9;
const CAPTURE_STAT_WOULD_FULL: u8 = 10;
const CAPTURE_STAT_WOULD_AGGREGATE: u8 = 11;
const CAPTURE_STAT_WOULD_SAMPLE: u8 = 12;
const CAPTURE_STAT_WOULD_DROP: u8 = 13;
const CAPTURE_STAT_RULE_HIT: u8 = 14;
const CAPTURE_STAT_RULE_MISS: u8 = 15;
const CAPTURE_STAT_STALE: u8 = 16;
const CAPTURE_STAT_PROMOTION_HIT: u8 = 17;
const CAPTURE_STAT_AGGREGATE_ERROR: u8 = 18;
const CAPTURE_STAT_PROMOTION_ERROR: u8 = 19;
const CAPTURE_STAT_PROBE_ERROR: u8 = 20;
const CAPTURE_STAT_NOT_ENABLED: u8 = 21;

#[inline(always)]
fn increment_capture_stat(probe: u8, kind: u8) {
    if probe as usize >= PIPELINE_RING_COUNT {
        return;
    }
    unsafe {
        let Some(stats) = CAPTURE_PROFILE_STATS.get_ptr_mut(probe as u32) else {
            return;
        };
        match kind {
            CAPTURE_STAT_ATTEMPTED => (*stats).attempted = (*stats).attempted.wrapping_add(1),
            CAPTURE_STAT_FULL => (*stats).full_selected = (*stats).full_selected.wrapping_add(1),
            CAPTURE_STAT_AGGREGATE => {
                (*stats).aggregate_selected = (*stats).aggregate_selected.wrapping_add(1)
            }
            CAPTURE_STAT_SAMPLE => {
                (*stats).sample_selected = (*stats).sample_selected.wrapping_add(1)
            }
            CAPTURE_STAT_SAMPLE_REJECTED => {
                (*stats).sample_rejected = (*stats).sample_rejected.wrapping_add(1)
            }
            CAPTURE_STAT_DROP => (*stats).drop_selected = (*stats).drop_selected.wrapping_add(1),
            CAPTURE_STAT_DECISION_ERROR => {
                (*stats).decision_error = (*stats).decision_error.wrapping_add(1)
            }
            CAPTURE_STAT_PAYLOAD_SELECTED => {
                (*stats).payload_selected = (*stats).payload_selected.wrapping_add(1)
            }
            CAPTURE_STAT_PAYLOAD_ERROR => {
                (*stats).payload_error = (*stats).payload_error.wrapping_add(1)
            }
            CAPTURE_STAT_WOULD_FULL => (*stats).would_full = (*stats).would_full.wrapping_add(1),
            CAPTURE_STAT_WOULD_AGGREGATE => {
                (*stats).would_aggregate = (*stats).would_aggregate.wrapping_add(1)
            }
            CAPTURE_STAT_WOULD_SAMPLE => {
                (*stats).would_sample = (*stats).would_sample.wrapping_add(1)
            }
            CAPTURE_STAT_WOULD_DROP => (*stats).would_drop = (*stats).would_drop.wrapping_add(1),
            CAPTURE_STAT_RULE_HIT => (*stats).rule_hit = (*stats).rule_hit.wrapping_add(1),
            CAPTURE_STAT_RULE_MISS => (*stats).rule_miss = (*stats).rule_miss.wrapping_add(1),
            CAPTURE_STAT_STALE => (*stats).stale_rule = (*stats).stale_rule.wrapping_add(1),
            CAPTURE_STAT_PROMOTION_HIT => {
                (*stats).promotion_hit = (*stats).promotion_hit.wrapping_add(1)
            }
            CAPTURE_STAT_AGGREGATE_ERROR => {
                (*stats).aggregate_error = (*stats).aggregate_error.wrapping_add(1)
            }
            CAPTURE_STAT_PROMOTION_ERROR => {
                (*stats).promotion_error = (*stats).promotion_error.wrapping_add(1)
            }
            CAPTURE_STAT_PROBE_ERROR => (*stats).probe_error = (*stats).probe_error.wrapping_add(1),
            CAPTURE_STAT_NOT_ENABLED => (*stats).not_enabled = (*stats).not_enabled.wrapping_add(1),
            _ => {}
        }
    }
}

#[inline(always)]
fn capture_payload_candidate(probe: u8) {
    if capture_profile_enabled() {
        increment_capture_stat(probe, CAPTURE_STAT_PAYLOAD_SELECTED);
    }
}

#[inline(always)]
fn capture_payload_error(probe: u8) {
    if capture_profile_enabled() {
        increment_capture_stat(probe, CAPTURE_STAT_PAYLOAD_ERROR);
    }
}

#[inline(always)]
fn capture_profile_enabled() -> bool {
    CAPTURE_PROFILE_CONFIG
        .get(0)
        .copied()
        .is_some_and(|config| config.enabled())
}

#[inline(always)]
fn capture_would(probe: u8, action: u8) {
    // Keep the map-value offsets statically visible to the verifier. Passing the untrusted action
    // through the generic `kind` switch lets LLVM synthesize `base + action * 8`; the verifier then
    // has to admit action=255 and rejects an apparent access beyond CaptureProbeStats.
    if action == CAPTURE_ACTION_AGGREGATE {
        increment_capture_would_aggregate(probe);
        return;
    }
    if action == CAPTURE_ACTION_SAMPLE {
        increment_capture_would_sample(probe);
        return;
    }
    if action == CAPTURE_ACTION_DROP {
        increment_capture_would_drop(probe);
        return;
    }
    increment_capture_would_full(probe);
}

#[inline(never)]
fn increment_capture_would_full(probe: u8) {
    unsafe {
        if let Some(stats) = CAPTURE_PROFILE_STATS.get_ptr_mut(probe as u32) {
            (*stats).would_full = (*stats).would_full.wrapping_add(1);
        }
    }
}

#[inline(never)]
fn increment_capture_would_aggregate(probe: u8) {
    unsafe {
        if let Some(stats) = CAPTURE_PROFILE_STATS.get_ptr_mut(probe as u32) {
            (*stats).would_aggregate = (*stats).would_aggregate.wrapping_add(1);
        }
    }
}

#[inline(never)]
fn increment_capture_would_sample(probe: u8) {
    unsafe {
        if let Some(stats) = CAPTURE_PROFILE_STATS.get_ptr_mut(probe as u32) {
            (*stats).would_sample = (*stats).would_sample.wrapping_add(1);
        }
    }
}

#[inline(never)]
fn increment_capture_would_drop(probe: u8) {
    unsafe {
        if let Some(stats) = CAPTURE_PROFILE_STATS.get_ptr_mut(probe as u32) {
            (*stats).would_drop = (*stats).would_drop.wrapping_add(1);
        }
    }
}

#[inline(always)]
unsafe fn capture_window_allows(
    state: *mut CaptureSampleWindow,
    now: u64,
    window_ns: u64,
    limit: u32,
) -> bool {
    if now.wrapping_sub((*state).started_at_boot_ns) >= window_ns {
        (*state).started_at_boot_ns = now;
        (*state).count = 0;
    }
    if (*state).count >= limit {
        return false;
    }
    (*state).count = (*state).count.saturating_add(1);
    true
}

/// 1=allowed, 0=rejected, -1=state error (caller uses the bounded emergency lane).
#[inline(always)]
fn capture_sample_allowed(key: &CaptureSampleKey, config: &CaptureProfileConfig, now: u64) -> i8 {
    let window_ns = if config.sample_window_ns == 0 {
        DEFAULT_FILE_SAMPLE_WINDOW_NS
    } else {
        config.sample_window_ns
    };
    let scope_limit = config.sample_per_scope_limit.max(1);
    let cpu = unsafe { bpf_get_smp_processor_id() };
    // CPU hotplug beyond the collector-observed count gets no lossy sample budget until the next
    // snapshot; protected events remain FULL.
    let global_limit =
        capture_cpu_sample_quota(config.sample_node_limit, config.sample_cpu_count, cpu);
    let first_samples = config.first_samples.max(1) as u32;

    let scope_count = unsafe {
        if let Some(state) = CAPTURE_SAMPLE_WINDOWS.get_ptr_mut(key) {
            if now.wrapping_sub((*state).started_at_boot_ns) >= window_ns {
                (*state).started_at_boot_ns = now;
                (*state).count = 0;
            }
            if (*state).count >= scope_limit {
                return 0;
            }
            (*state).count = (*state).count.saturating_add(1);
            (*state).count
        } else {
            let initial = CaptureSampleWindow {
                started_at_boot_ns: now,
                count: 1,
                _reserved: 0,
            };
            if CAPTURE_SAMPLE_WINDOWS.insert(key, &initial, 0).is_err() {
                return -1;
            }
            1
        }
    };

    if global_limit == 0 {
        return 0;
    }
    let (first_reserve, regular_limit) = capture_sample_partitions(global_limit);
    // First samples use their own fixed partition, so established noisy scopes cannot consume the
    // discovery reserve. The two partitions sum to the hard configured global limit.
    if scope_count <= first_samples {
        return unsafe {
            match CAPTURE_FIRST_SAMPLE_WINDOWS.get_ptr_mut(0) {
                Some(state) => {
                    i8::from(capture_window_allows(state, now, window_ns, first_reserve))
                }
                None => -1,
            }
        };
    }
    if regular_limit == 0 {
        return 0;
    }
    unsafe {
        match CAPTURE_GLOBAL_SAMPLE_WINDOWS.get_ptr_mut(0) {
            Some(state) => i8::from(capture_window_allows(state, now, window_ns, regular_limit)),
            None => -1,
        }
    }
}

#[inline(always)]
fn capture_emergency_sample_allowed(_probe: u8, config: &CaptureProfileConfig, now: u64) -> i8 {
    let window_ns = if config.sample_window_ns == 0 {
        DEFAULT_FILE_SAMPLE_WINDOW_NS
    } else {
        config.sample_window_ns
    };
    let cpu = unsafe { bpf_get_smp_processor_id() };
    let quota = capture_cpu_sample_quota(config.sample_node_limit, config.sample_cpu_count, cpu);
    let (_, regular_limit) = capture_sample_partitions(quota);
    if regular_limit == 0 {
        return 0;
    }
    unsafe {
        match CAPTURE_GLOBAL_SAMPLE_WINDOWS.get_ptr_mut(0) {
            Some(state) => i8::from(capture_window_allows(state, now, window_ns, regular_limit)),
            None => -1,
        }
    }
}

#[inline(always)]
fn capture_aggregate_attempt(
    cgroup_id: u64,
    epoch: u64,
    probe: u8,
    action: u8,
    qualifier: u8,
    profile: u8,
    authority: u8,
    disposition: u8,
    bytes: u64,
) -> bool {
    let key = CaptureAggregateKey {
        cgroup_id,
        epoch,
        probe,
        action,
        qualifier,
        profile,
        authority,
        disposition,
        _reserved: [0; 2],
    };
    unsafe {
        if let Some(value) = CAPTURE_AGGREGATES.get_ptr_mut(&key) {
            (*value).count = (*value).count.saturating_add(1);
            (*value).bytes = (*value).bytes.saturating_add(bytes);
            true
        } else {
            CAPTURE_AGGREGATES
                .insert(&key, &CaptureAggregateValue { count: 1, bytes }, 0)
                .is_ok()
        }
    }
}

#[inline(always)]
fn capture_promotion_valid(
    pid: u32,
    cgroup_id: u64,
    config: &CaptureProfileConfig,
    now: u64,
) -> bool {
    let key = CaptureProcessKey {
        pid,
        _reserved: 0,
        epoch: config.active_epoch,
    };
    let Some(value) = (unsafe { CAPTURE_PROMOTED_PROCESSES.get(&key).copied() }) else {
        return false;
    };
    if value.cgroup_id != cgroup_id
        || (value.expires_at_boot_ns != 0 && now >= value.expires_at_boot_ns)
    {
        if CAPTURE_PROMOTED_PROCESSES.remove(&key).is_err() {
            increment_capture_stat(CAPTURE_PROBE_EXEC, CAPTURE_STAT_PROMOTION_ERROR);
        }
        return false;
    }
    if value.expected_exec_id != 0 {
        let committed = unsafe { COMMITTED_EXEC_IDS.get(&pid).copied().unwrap_or(0) };
        if committed != value.expected_exec_id {
            if CAPTURE_PROMOTED_PROCESSES.remove(&key).is_err() {
                increment_capture_stat(CAPTURE_PROBE_EXEC, CAPTURE_STAT_PROMOTION_ERROR);
            }
            return false;
        }
    }
    true
}

#[inline(always)]
fn inherit_capture_promotion(parent: u32, child: u32) {
    let config = CAPTURE_PROFILE_CONFIG.get(0).copied().unwrap_or_default();
    if !config.enabled() || config.active_epoch == 0 {
        return;
    }
    let now = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if !capture_promotion_valid(parent, cgroup_id, &config, now) {
        return;
    }
    let parent_key = CaptureProcessKey {
        pid: parent,
        _reserved: 0,
        epoch: config.active_epoch,
    };
    let Some(parent_value) = (unsafe { CAPTURE_PROMOTED_PROCESSES.get(&parent_key).copied() })
    else {
        return;
    };
    let child_key = CaptureProcessKey {
        pid: child,
        _reserved: 0,
        epoch: config.active_epoch,
    };
    let child_value = CapturePromotionValue {
        cgroup_id,
        expected_exec_id: 0,
        root_exec_id: parent_value.root_exec_id,
        expires_at_boot_ns: parent_value.expires_at_boot_ns,
        root_pid: parent_value.root_pid,
        flags: (parent_value.flags & CAPTURE_PROMOTION_FLAG_INVESTIGATION)
            | CAPTURE_PROMOTION_FLAG_DESCENDANT,
    };
    if CAPTURE_PROMOTED_PROCESSES
        .insert(&child_key, &child_value, 0)
        .is_err()
    {
        increment_capture_stat(CAPTURE_PROBE_EXEC, CAPTURE_STAT_PROMOTION_ERROR);
    }
}

#[inline(always)]
fn commit_capture_promotion(pid: u32, exec_id: u64, cgroup_id: u64) {
    let config = CAPTURE_PROFILE_CONFIG.get(0).copied().unwrap_or_default();
    if !config.enabled() || config.active_epoch == 0 {
        return;
    }
    let key = CaptureProcessKey {
        pid,
        _reserved: 0,
        epoch: config.active_epoch,
    };
    let Some(mut value) = (unsafe { CAPTURE_PROMOTED_PROCESSES.get(&key).copied() }) else {
        return;
    };
    let now = unsafe { bpf_ktime_get_ns() };
    if value.cgroup_id != cgroup_id
        || (value.expires_at_boot_ns != 0 && now >= value.expires_at_boot_ns)
    {
        if CAPTURE_PROMOTED_PROCESSES.remove(&key).is_err() {
            increment_capture_stat(CAPTURE_PROBE_EXEC, CAPTURE_STAT_PROMOTION_ERROR);
        }
        return;
    }
    // A configured root is fenced to the exact commit generation. A descendant begins with zero
    // at fork and is advanced to its own generation only after this successful commit hook.
    if value.flags & CAPTURE_PROMOTION_FLAG_ROOT != 0
        && value.expected_exec_id != 0
        && value.expected_exec_id != exec_id
    {
        if CAPTURE_PROMOTED_PROCESSES.remove(&key).is_err() {
            increment_capture_stat(CAPTURE_PROBE_EXEC, CAPTURE_STAT_PROMOTION_ERROR);
        }
        return;
    }
    value.expected_exec_id = exec_id;
    if CAPTURE_PROMOTED_PROCESSES.insert(&key, &value, 0).is_err() {
        increment_capture_stat(CAPTURE_PROBE_EXEC, CAPTURE_STAT_PROMOTION_ERROR);
    }
}

#[inline(always)]
fn promote_security_runtime(pid: u32, cgroup_id: u64) {
    let config = CAPTURE_PROFILE_CONFIG.get(0).copied().unwrap_or_default();
    if !config.enabled() || config.active_epoch == 0 {
        return;
    }
    let now = unsafe { bpf_ktime_get_ns() };
    let exec_id = unsafe { COMMITTED_EXEC_IDS.get(&pid).copied().unwrap_or(0) };
    let key = CaptureProcessKey {
        pid,
        _reserved: 0,
        epoch: config.active_epoch,
    };
    let value = CapturePromotionValue {
        cgroup_id,
        expected_exec_id: exec_id,
        root_exec_id: exec_id,
        expires_at_boot_ns: now.saturating_add(config.investigation_ttl_ns.max(1)),
        root_pid: pid,
        flags: CAPTURE_PROMOTION_FLAG_ROOT | CAPTURE_PROMOTION_FLAG_INVESTIGATION,
    };
    if CAPTURE_PROMOTED_PROCESSES.insert(&key, &value, 0).is_err() {
        increment_capture_stat(CAPTURE_PROBE_SECURITY, CAPTURE_STAT_PROMOTION_ERROR);
    }
}

#[inline(always)]
fn remove_capture_promotion(pid: u32) {
    let config = CAPTURE_PROFILE_CONFIG.get(0).copied().unwrap_or_default();
    if config.active_epoch == 0 {
        return;
    }
    let key = CaptureProcessKey {
        pid,
        _reserved: 0,
        epoch: config.active_epoch,
    };
    let _ = CAPTURE_PROMOTED_PROCESSES.remove(&key);
}

#[inline(always)]
fn capture_decision(
    epoch: u64,
    profile: u8,
    action: u8,
    authority: u8,
    disposition: u8,
    flags: u8,
) -> CaptureDecisionContext {
    CaptureDecisionContext {
        capture_epoch: epoch,
        capture_profile: profile,
        capture_action: action,
        capture_authority: authority,
        capture_disposition: disposition,
        flags,
        _reserved: [0; 3],
    }
}

#[inline(always)]
fn selected_capture_decision(
    epoch: u64,
    profile: u8,
    action: u8,
    authority: u8,
    disposition: u8,
    flags: u8,
) -> CaptureDecisionContext {
    capture_decision(
        epoch,
        profile,
        action,
        authority,
        disposition,
        flags | CAPTURE_DECISION_FLAG_SELECTED,
    )
}

#[inline(always)]
fn legacy_selected_capture_decision() -> CaptureDecisionContext {
    selected_capture_decision(
        0,
        CAPTURE_PROFILE_UNKNOWN_DISCOVERY,
        CAPTURE_ACTION_FULL,
        0,
        CAPTURE_DISPOSITION_MISS,
        CAPTURE_DECISION_FLAG_LEGACY,
    )
}

/// Returns the exact decision made before raw payload construction and Ring reservation.
/// AGGREGATE/DROP/sample rejection return an unselected context and terminate at the caller.
#[inline(always)]
fn capture_raw_decision(
    probe: u8,
    cgroup_id: u64,
    pid: u32,
    bytes: u64,
    qualifier: u8,
) -> CaptureDecisionContext {
    if probe as usize >= PIPELINE_RING_COUNT {
        return legacy_selected_capture_decision();
    }
    let config = CAPTURE_PROFILE_CONFIG.get(0).copied().unwrap_or_default();
    if !config.enabled() {
        return legacy_selected_capture_decision();
    }
    increment_capture_stat(probe, CAPTURE_STAT_ATTEMPTED);
    let now = unsafe { bpf_ktime_get_ns() };
    let protected = capture_probe_is_protected(probe);
    // The Collector's verified-process map is a generation-fenced positive Agent identity. It
    // intentionally outlives short cgroup/profile leases, which may be refreshed asynchronously
    // while a CLI is idle. Plaintext TLS is the interaction payload we promised to observe, so a
    // verified Agent must not fall back to the Unknown/probable sample matrix for this probe.
    let verified_agent = verified_agent_process(pid, cgroup_id);
    let promoted = !protected && capture_promotion_valid(pid, cgroup_id, &config, now);

    let key = CaptureProfileKey {
        cgroup_id,
        epoch: config.active_epoch,
    };
    let rule = unsafe { CAPTURE_PROFILE_RULES.get(&key).copied() };
    let mut profile = CAPTURE_PROFILE_UNKNOWN_DISCOVERY;
    let mut action = capture_profile_default_actions(profile)[probe as usize];
    let mut desired = action;
    let mut authority = 0;
    let mut disposition = CAPTURE_DISPOSITION_MISS;
    if config.expires_at_boot_ns != 0 && now >= config.expires_at_boot_ns {
        if !protected && !promoted {
            increment_capture_stat(probe, CAPTURE_STAT_STALE);
        }
        disposition = CAPTURE_DISPOSITION_STALE;
    } else if let Some(value) = rule {
        if value.epoch != config.active_epoch
            || (value.expires_at_boot_ns != 0 && now >= value.expires_at_boot_ns)
        {
            if !protected && !promoted {
                increment_capture_stat(probe, CAPTURE_STAT_STALE);
            }
            disposition = CAPTURE_DISPOSITION_STALE;
        } else {
            if !protected && !promoted {
                increment_capture_stat(probe, CAPTURE_STAT_RULE_HIT);
            }
            profile = value.profile;
            authority = value.authority;
            disposition = CAPTURE_DISPOSITION_RULE;
            action = value.actions[probe as usize];
            desired = value.desired_actions[probe as usize];
            if value.flags & (CAPTURE_PROFILE_FLAG_AGENT | CAPTURE_PROFILE_FLAG_CONFLICT) != 0
                && (probe != CAPTURE_PROBE_FILE_READ || action == CAPTURE_ACTION_FULL)
            {
                action = CAPTURE_ACTION_FULL;
                desired = CAPTURE_ACTION_FULL;
            }
        }
    } else {
        if !protected && !promoted {
            increment_capture_stat(probe, CAPTURE_STAT_RULE_MISS);
        }
        // TLS profiles are attached only to an identity-verified Agent PID, and plaintext reaches
        // this decision only after an exact LLM route/schema gate. A short-lived CLI can issue its
        // first model request before the control-plane cgroup snapshot catches up; treating that
        // race as unknown_discovery (where SSL is disabled) permanently loses the first turn.
        // Use the same FULL SSL policy as probable_investigation for this rule-miss window. A
        // generation-fenced process identity is the positive observation authority; it is allowed
        // to bridge a stale/unknown cgroup lease without waiting for another control-plane round.
        if probe == CAPTURE_PROBE_SSL && verified_agent {
            profile = CAPTURE_PROFILE_PROBABLE_INVESTIGATION;
            action = CAPTURE_ACTION_FULL;
            desired = CAPTURE_ACTION_FULL;
        }
    }

    if protected {
        increment_capture_stat(probe, CAPTURE_STAT_FULL);
        let protected_profile = if probe == CAPTURE_PROBE_SECURITY {
            CAPTURE_PROFILE_SECURITY_FULL
        } else {
            profile
        };
        return selected_capture_decision(
            config.active_epoch,
            protected_profile,
            CAPTURE_ACTION_FULL,
            authority,
            disposition,
            CAPTURE_DECISION_FLAG_PROTECTED,
        );
    }
    if probe == CAPTURE_PROBE_SSL
        && verified_agent
        // A valid explicit infrastructure/security profile remains authoritative. The bridge is
        // only for a missing/stale/default scope (or an Agent profile that is already positive).
        && (disposition != CAPTURE_DISPOSITION_RULE
            || matches!(
                profile,
                CAPTURE_PROFILE_UNKNOWN_DISCOVERY
                    | CAPTURE_PROFILE_PROBABLE_INVESTIGATION
                    | CAPTURE_PROFILE_AGENT_FULL
                    | CAPTURE_PROFILE_INVESTIGATION_FULL
            ))
    {
        increment_capture_stat(probe, CAPTURE_STAT_FULL);
        return selected_capture_decision(
            config.active_epoch,
            // Keep the profile label useful to operators while the cgroup lease is absent or
            // stale; the process-level identity is what authorized this full-fidelity payload.
            if profile == CAPTURE_PROFILE_UNKNOWN_DISCOVERY {
                CAPTURE_PROFILE_PROBABLE_INVESTIGATION
            } else {
                profile
            },
            CAPTURE_ACTION_FULL,
            authority,
            disposition,
            CAPTURE_DECISION_FLAG_VERIFIED_AGENT,
        );
    }
    // `file_read` is a default-off signal. Ordinary capture shadow semantics force FULL to expose
    // would-drop differences, but doing that here would send every node read into the Ring. Shadow
    // therefore records the desired decision only and preserves the baseline-off transport.
    if probe == CAPTURE_PROBE_FILE_READ && config.mode == CAPTURE_MODE_SHADOW {
        let shadow_desired = if promoted {
            CAPTURE_ACTION_FULL
        } else {
            desired
        };
        if shadow_desired != CAPTURE_ACTION_NOT_ENABLED {
            capture_would(probe, shadow_desired);
        }
        increment_capture_stat(probe, CAPTURE_STAT_NOT_ENABLED);
        return capture_decision(
            config.active_epoch,
            profile,
            CAPTURE_ACTION_NOT_ENABLED,
            authority,
            disposition,
            CAPTURE_DECISION_FLAG_SHADOW,
        );
    }

    if promoted {
        increment_capture_stat(probe, CAPTURE_STAT_PROMOTION_HIT);
        increment_capture_stat(probe, CAPTURE_STAT_FULL);
        let promotion_key = CaptureProcessKey {
            pid,
            _reserved: 0,
            epoch: config.active_epoch,
        };
        let promoted_profile = unsafe { CAPTURE_PROMOTED_PROCESSES.get(&promotion_key) }
            .map(|value| {
                if value.flags & CAPTURE_PROMOTION_FLAG_INVESTIGATION != 0 {
                    CAPTURE_PROFILE_INVESTIGATION_FULL
                } else {
                    CAPTURE_PROFILE_AGENT_FULL
                }
            })
            .unwrap_or(CAPTURE_PROFILE_AGENT_FULL);
        return selected_capture_decision(
            config.active_epoch,
            promoted_profile,
            CAPTURE_ACTION_FULL,
            authority,
            disposition,
            CAPTURE_DECISION_FLAG_PROMOTED,
        );
    }

    if config.mode == CAPTURE_MODE_SHADOW {
        capture_would(probe, desired);
        increment_capture_stat(probe, CAPTURE_STAT_FULL);
        return selected_capture_decision(
            config.active_epoch,
            profile,
            CAPTURE_ACTION_FULL,
            authority,
            disposition,
            CAPTURE_DECISION_FLAG_SHADOW,
        );
    }
    if action == CAPTURE_ACTION_NOT_ENABLED {
        increment_capture_stat(probe, CAPTURE_STAT_NOT_ENABLED);
        return capture_decision(
            config.active_epoch,
            profile,
            CAPTURE_ACTION_NOT_ENABLED,
            authority,
            disposition,
            0,
        );
    }
    if action == CAPTURE_ACTION_DROP
        && (authority != FILE_FILTER_AUTHORITY_AUTHORITATIVE
            || config.flags & CAPTURE_CONFIG_DESTRUCTIVE_GRANTED == 0)
    {
        action = capture_profile_default_actions(profile)[probe as usize];
        if action == CAPTURE_ACTION_DROP {
            action = CAPTURE_ACTION_SAMPLE;
        }
    }

    match action {
        CAPTURE_ACTION_FULL => {
            increment_capture_stat(probe, CAPTURE_STAT_FULL);
            selected_capture_decision(
                config.active_epoch,
                profile,
                CAPTURE_ACTION_FULL,
                authority,
                disposition,
                0,
            )
        }
        CAPTURE_ACTION_AGGREGATE | CAPTURE_ACTION_SAMPLE | CAPTURE_ACTION_DROP => {
            if !capture_aggregate_attempt(
                cgroup_id,
                config.active_epoch,
                probe,
                action,
                qualifier,
                profile,
                authority,
                disposition,
                bytes,
            ) {
                increment_capture_stat(probe, CAPTURE_STAT_AGGREGATE_ERROR);
                // A full aggregate map must not turn a low-value workload back into an unbounded
                // raw stream. Use the regular global sample partition as a fixed emergency lane.
                return match capture_emergency_sample_allowed(probe, &config, now) {
                    1 => {
                        increment_capture_stat(probe, CAPTURE_STAT_SAMPLE);
                        selected_capture_decision(
                            config.active_epoch,
                            profile,
                            CAPTURE_ACTION_SAMPLE,
                            authority,
                            disposition,
                            CAPTURE_DECISION_FLAG_EMERGENCY_SAMPLE,
                        )
                    }
                    0 => {
                        increment_capture_stat(probe, CAPTURE_STAT_SAMPLE_REJECTED);
                        capture_decision(
                            config.active_epoch,
                            profile,
                            CAPTURE_ACTION_SAMPLE,
                            authority,
                            disposition,
                            0,
                        )
                    }
                    _ => {
                        increment_capture_stat(probe, CAPTURE_STAT_DECISION_ERROR);
                        capture_decision(
                            config.active_epoch,
                            profile,
                            CAPTURE_ACTION_SAMPLE,
                            authority,
                            disposition,
                            0,
                        )
                    }
                };
            }
            if action == CAPTURE_ACTION_AGGREGATE {
                increment_capture_stat(probe, CAPTURE_STAT_AGGREGATE);
                return capture_decision(
                    config.active_epoch,
                    profile,
                    action,
                    authority,
                    disposition,
                    0,
                );
            }
            if action == CAPTURE_ACTION_DROP {
                increment_capture_stat(probe, CAPTURE_STAT_DROP);
                return capture_decision(
                    config.active_epoch,
                    profile,
                    action,
                    authority,
                    disposition,
                    0,
                );
            }
            let sample_key = CaptureSampleKey {
                cgroup_id,
                epoch: config.active_epoch,
                probe,
                _reserved: [0; 7],
            };
            match capture_sample_allowed(&sample_key, &config, now) {
                1 => {
                    increment_capture_stat(probe, CAPTURE_STAT_SAMPLE);
                    selected_capture_decision(
                        config.active_epoch,
                        profile,
                        CAPTURE_ACTION_SAMPLE,
                        authority,
                        disposition,
                        0,
                    )
                }
                0 => {
                    increment_capture_stat(probe, CAPTURE_STAT_SAMPLE_REJECTED);
                    capture_decision(
                        config.active_epoch,
                        profile,
                        CAPTURE_ACTION_SAMPLE,
                        authority,
                        disposition,
                        0,
                    )
                }
                _ => {
                    increment_capture_stat(probe, CAPTURE_STAT_PROBE_ERROR);
                    match capture_emergency_sample_allowed(probe, &config, now) {
                        1 => {
                            increment_capture_stat(probe, CAPTURE_STAT_SAMPLE);
                            selected_capture_decision(
                                config.active_epoch,
                                profile,
                                CAPTURE_ACTION_SAMPLE,
                                authority,
                                disposition,
                                CAPTURE_DECISION_FLAG_EMERGENCY_SAMPLE,
                            )
                        }
                        0 => {
                            increment_capture_stat(probe, CAPTURE_STAT_SAMPLE_REJECTED);
                            capture_decision(
                                config.active_epoch,
                                profile,
                                CAPTURE_ACTION_SAMPLE,
                                authority,
                                disposition,
                                0,
                            )
                        }
                        _ => {
                            increment_capture_stat(probe, CAPTURE_STAT_DECISION_ERROR);
                            capture_decision(
                                config.active_epoch,
                                profile,
                                CAPTURE_ACTION_SAMPLE,
                                authority,
                                disposition,
                                0,
                            )
                        }
                    }
                }
            }
        }
        _ => {
            increment_capture_stat(probe, CAPTURE_STAT_PROBE_ERROR);
            match capture_emergency_sample_allowed(probe, &config, now) {
                1 => {
                    increment_capture_stat(probe, CAPTURE_STAT_SAMPLE);
                    selected_capture_decision(
                        config.active_epoch,
                        profile,
                        CAPTURE_ACTION_SAMPLE,
                        authority,
                        disposition,
                        CAPTURE_DECISION_FLAG_EMERGENCY_SAMPLE,
                    )
                }
                0 => {
                    increment_capture_stat(probe, CAPTURE_STAT_SAMPLE_REJECTED);
                    capture_decision(
                        config.active_epoch,
                        profile,
                        CAPTURE_ACTION_SAMPLE,
                        authority,
                        disposition,
                        0,
                    )
                }
                _ => {
                    increment_capture_stat(probe, CAPTURE_STAT_DECISION_ERROR);
                    capture_decision(
                        config.active_epoch,
                        profile,
                        CAPTURE_ACTION_SAMPLE,
                        authority,
                        disposition,
                        0,
                    )
                }
            }
        }
    }
}

const FILE_STAT_ACCESS_KEPT: u8 = 1;
const FILE_STAT_ACCESS_UNKNOWN_KEPT: u8 = 2;
const FILE_STAT_ACCESS_SAMPLED: u8 = 3;
const FILE_STAT_ACCESS_DROPPED: u8 = 4;
const FILE_STAT_ACCESS_SUPPRESSED: u8 = 5;
const FILE_STAT_DELETE_KEPT: u8 = 6;
const FILE_STAT_DELETE_UNKNOWN_KEPT: u8 = 7;
const FILE_STAT_DELETE_DROPPED: u8 = 8;
const FILE_STAT_RULE_HIT: u8 = 9;
const FILE_STAT_RULE_MISS: u8 = 10;
const FILE_STAT_STALE_RULE: u8 = 11;
const FILE_STAT_ACCESS_RING_DROP: u8 = 12;
const FILE_STAT_DELETE_RING_DROP: u8 = 13;

const DEFAULT_FILE_SAMPLE_WINDOW_NS: u64 = 1_000_000_000;
const DEFAULT_FILE_SAMPLE_PER_CGROUP: u32 = 20;
const DEFAULT_FILE_SAMPLE_PER_CPU: u32 = 64;

#[inline(always)]
fn increment_file_stat(kind: u8) {
    unsafe {
        let Some(stats) = FILE_FILTER_STATS.get_ptr_mut(0) else {
            return;
        };
        match kind {
            FILE_STAT_ACCESS_KEPT => (*stats).access_kept = (*stats).access_kept.wrapping_add(1),
            FILE_STAT_ACCESS_UNKNOWN_KEPT => {
                (*stats).access_unknown_kept = (*stats).access_unknown_kept.wrapping_add(1)
            }
            FILE_STAT_ACCESS_SAMPLED => {
                (*stats).access_sampled = (*stats).access_sampled.wrapping_add(1)
            }
            FILE_STAT_ACCESS_DROPPED => {
                (*stats).access_dropped = (*stats).access_dropped.wrapping_add(1)
            }
            FILE_STAT_ACCESS_SUPPRESSED => {
                (*stats).access_sample_suppressed =
                    (*stats).access_sample_suppressed.wrapping_add(1)
            }
            FILE_STAT_DELETE_KEPT => (*stats).delete_kept = (*stats).delete_kept.wrapping_add(1),
            FILE_STAT_DELETE_UNKNOWN_KEPT => {
                (*stats).delete_unknown_kept = (*stats).delete_unknown_kept.wrapping_add(1)
            }
            FILE_STAT_DELETE_DROPPED => {
                (*stats).delete_dropped = (*stats).delete_dropped.wrapping_add(1)
            }
            FILE_STAT_RULE_HIT => (*stats).rule_hits = (*stats).rule_hits.wrapping_add(1),
            FILE_STAT_RULE_MISS => (*stats).rule_misses = (*stats).rule_misses.wrapping_add(1),
            FILE_STAT_STALE_RULE => (*stats).stale_rules = (*stats).stale_rules.wrapping_add(1),
            FILE_STAT_ACCESS_RING_DROP => {
                (*stats).access_ring_dropped = (*stats).access_ring_dropped.wrapping_add(1)
            }
            FILE_STAT_DELETE_RING_DROP => {
                (*stats).delete_ring_dropped = (*stats).delete_ring_dropped.wrapping_add(1)
            }
            _ => {}
        }
    }
}

#[inline(always)]
fn reserve_file_or_drop(ring: &RingBuf, delete: bool) -> Option<RingBufEntry<FileEvent>> {
    let entry = reserve_or_drop::<FileEvent>(
        ring,
        if delete {
            PIPELINE_RING_FILE_DELETE
        } else {
            PIPELINE_RING_FILE_ACCESS
        },
    );
    if entry.is_none() {
        increment_file_stat(if delete {
            FILE_STAT_DELETE_RING_DROP
        } else {
            FILE_STAT_ACCESS_RING_DROP
        });
    }
    entry
}

#[inline(always)]
unsafe fn sample_window_allows(
    state: *mut FileFilterSampleWindow,
    now: u64,
    window_ns: u64,
    limit: u32,
) -> bool {
    if now.wrapping_sub((*state).started_at_boot_ns) >= window_ns {
        (*state).started_at_boot_ns = now;
        (*state).count = 0;
    }
    if (*state).count >= limit {
        return false;
    }
    (*state).count = (*state).count.saturating_add(1);
    true
}

#[inline(always)]
fn unknown_sample_allowed(cgroup_id: u64, config: &FileFilterConfig, now: u64) -> bool {
    let window_ns = if config.sample_window_ns == 0 {
        DEFAULT_FILE_SAMPLE_WINDOW_NS
    } else {
        config.sample_window_ns
    };
    let cgroup_limit = if config.unknown_per_cgroup_limit == 0 {
        DEFAULT_FILE_SAMPLE_PER_CGROUP
    } else {
        config.unknown_per_cgroup_limit
    };
    let per_cpu_limit = if config.unknown_per_cpu_limit == 0 {
        DEFAULT_FILE_SAMPLE_PER_CPU
    } else {
        config.unknown_per_cpu_limit
    };

    let cgroup_allowed = unsafe {
        if let Some(state) = UNKNOWN_FILE_WINDOWS.get_ptr_mut(&cgroup_id) {
            sample_window_allows(state, now, window_ns, cgroup_limit)
        } else {
            let initial = FileFilterSampleWindow {
                started_at_boot_ns: now,
                count: 1,
                _reserved: 0,
            };
            UNKNOWN_FILE_WINDOWS.insert(&cgroup_id, &initial, 0).is_ok()
        }
    };
    if !cgroup_allowed {
        return false;
    }
    unsafe {
        UNKNOWN_FILE_GLOBAL_WINDOW
            .get_ptr_mut(0)
            .is_some_and(|state| sample_window_allows(state, now, window_ns, per_cpu_limit))
    }
}

#[inline(always)]
fn active_file_rule(
    cgroup_id: u64,
    config: &FileFilterConfig,
    now: u64,
) -> Option<FileFilterValue> {
    let key = FileFilterKey {
        cgroup_id,
        epoch: config.active_epoch,
    };
    let value = unsafe { FILE_FILTER_RULES.get(&key).copied() };
    let Some(value) = value else {
        increment_file_stat(FILE_STAT_RULE_MISS);
        return None;
    };
    if value.epoch != config.active_epoch
        || (value.expires_at_boot_ns != 0 && now >= value.expires_at_boot_ns)
    {
        increment_file_stat(FILE_STAT_STALE_RULE);
        return None;
    }
    increment_file_stat(FILE_STAT_RULE_HIT);
    Some(value)
}

#[inline(always)]
fn legacy_file_access_decision(cgroup_id: u64) -> CaptureDecisionContext {
    let config = FILE_FILTER_CONFIG.get(0).copied().unwrap_or_default();
    if !config.enabled() {
        increment_file_stat(FILE_STAT_ACCESS_KEPT);
        return legacy_selected_capture_decision();
    }
    let now = unsafe { bpf_ktime_get_ns() };
    let rule = active_file_rule(cgroup_id, &config, now);
    if let Some(rule) = rule {
        if rule.action == FILE_FILTER_ACTION_KEEP {
            increment_file_stat(FILE_STAT_ACCESS_KEPT);
            return selected_capture_decision(
                config.active_epoch,
                CAPTURE_PROFILE_UNKNOWN_DISCOVERY,
                CAPTURE_ACTION_FULL,
                rule.authority,
                CAPTURE_DISPOSITION_RULE,
                CAPTURE_DECISION_FLAG_LEGACY,
            );
        }
        if rule.action == FILE_FILTER_ACTION_DROP
            && rule.authority == FILE_FILTER_AUTHORITY_AUTHORITATIVE
        {
            increment_file_stat(FILE_STAT_ACCESS_DROPPED);
            return capture_decision(
                config.active_epoch,
                CAPTURE_PROFILE_UNKNOWN_DISCOVERY,
                CAPTURE_ACTION_DROP,
                rule.authority,
                CAPTURE_DISPOSITION_RULE,
                CAPTURE_DECISION_FLAG_LEGACY,
            );
        }
        // SAMPLE, an unknown action, or a candidate DROP all use the configured Unknown policy.
    }
    let authority = rule.map(|value| value.authority).unwrap_or(0);
    let disposition = if rule.is_some() {
        CAPTURE_DISPOSITION_RULE
    } else {
        CAPTURE_DISPOSITION_MISS
    };
    if !config.unknown_sampling_enabled() {
        increment_file_stat(FILE_STAT_ACCESS_KEPT);
        increment_file_stat(FILE_STAT_ACCESS_UNKNOWN_KEPT);
        return selected_capture_decision(
            config.active_epoch,
            CAPTURE_PROFILE_UNKNOWN_DISCOVERY,
            CAPTURE_ACTION_FULL,
            authority,
            disposition,
            CAPTURE_DECISION_FLAG_LEGACY,
        );
    }
    if unknown_sample_allowed(cgroup_id, &config, now) {
        increment_file_stat(FILE_STAT_ACCESS_SAMPLED);
        selected_capture_decision(
            config.active_epoch,
            CAPTURE_PROFILE_UNKNOWN_DISCOVERY,
            CAPTURE_ACTION_SAMPLE,
            authority,
            disposition,
            CAPTURE_DECISION_FLAG_LEGACY,
        )
    } else {
        increment_file_stat(FILE_STAT_ACCESS_SUPPRESSED);
        capture_decision(
            config.active_epoch,
            CAPTURE_PROFILE_UNKNOWN_DISCOVERY,
            CAPTURE_ACTION_SAMPLE,
            authority,
            disposition,
            CAPTURE_DECISION_FLAG_LEGACY,
        )
    }
}

#[inline(always)]
fn legacy_file_delete_decision(cgroup_id: u64) -> CaptureDecisionContext {
    let config = FILE_FILTER_CONFIG.get(0).copied().unwrap_or_default();
    if !config.enabled() {
        increment_file_stat(FILE_STAT_DELETE_KEPT);
        return legacy_selected_capture_decision();
    }
    let now = unsafe { bpf_ktime_get_ns() };
    let rule = active_file_rule(cgroup_id, &config, now);
    if let Some(rule) = rule {
        if rule.action == FILE_FILTER_ACTION_DROP
            && rule.authority == FILE_FILTER_AUTHORITY_AUTHORITATIVE
        {
            increment_file_stat(FILE_STAT_DELETE_DROPPED);
            return capture_decision(
                config.active_epoch,
                CAPTURE_PROFILE_UNKNOWN_DISCOVERY,
                CAPTURE_ACTION_DROP,
                rule.authority,
                CAPTURE_DISPOSITION_RULE,
                CAPTURE_DECISION_FLAG_LEGACY,
            );
        }
        if rule.action == FILE_FILTER_ACTION_KEEP {
            increment_file_stat(FILE_STAT_DELETE_KEPT);
            return selected_capture_decision(
                config.active_epoch,
                CAPTURE_PROFILE_UNKNOWN_DISCOVERY,
                CAPTURE_ACTION_FULL,
                rule.authority,
                CAPTURE_DISPOSITION_RULE,
                CAPTURE_DECISION_FLAG_LEGACY,
            );
        }
    }
    // FileDelete is fail-open for KEEP, SAMPLE, candidate DROP, misses, and stale rules.
    increment_file_stat(FILE_STAT_DELETE_KEPT);
    increment_file_stat(FILE_STAT_DELETE_UNKNOWN_KEPT);
    let authority = rule.map(|value| value.authority).unwrap_or(0);
    let disposition = if rule.is_some() {
        CAPTURE_DISPOSITION_RULE
    } else {
        CAPTURE_DISPOSITION_MISS
    };
    selected_capture_decision(
        config.active_epoch,
        CAPTURE_PROFILE_UNKNOWN_DISCOVERY,
        CAPTURE_ACTION_FULL,
        authority,
        disposition,
        CAPTURE_DECISION_FLAG_LEGACY,
    )
}

/// Read a `u64` (e.g. a pointer or length) from a user-space address.
fn read_user_u64(addr: *const u8) -> Option<u64> {
    let mut b = [0u8; 8];
    if unsafe { bpf_probe_read_user_buf(addr, &mut b) }.is_ok() {
        Some(u64::from_ne_bytes(b))
    } else {
        None
    }
}

unsafe fn init_exec_record(
    record: *mut ExecRecord,
    exec_id: u64,
    cgroup_id: u64,
    pid: u32,
    ppid: u32,
    uid: u32,
    comm: [u8; 16],
    captured_at_boot_ns: u64,
    capture_decision: CaptureDecisionContext,
) {
    (*record).exec_id = exec_id;
    (*record).cgroup_id = cgroup_id;
    (*record).pid = pid;
    (*record).ppid = ppid;
    (*record).uid = uid;
    (*record).captured_bytes = 0;
    (*record).argc = 0;
    (*record).arg_index = 0;
    (*record).chunk_index = 0;
    (*record).data_len = 0;
    (*record).kind = 0;
    (*record).flags = 0;
    (*record)._pad = [0; 2];
    (*record).comm = comm;
    zero_exec_data(record);
    (*record)._event_time_pad = [0; 4];
    (*record).captured_at_boot_ns = captured_at_boot_ns;
    (*record).capture_decision = capture_decision;
}

#[inline(always)]
unsafe fn zero_exec_data(record: *mut ExecRecord) {
    // Avoid lowering `[0; 128]` to a bounded memset loop. This function runs inside the
    // 64-iteration argv chunk loop; nesting those two loops makes the kernel verifier explore
    // more than one million instructions and reject the exec probe. Fixed stores keep the same
    // fully-initialized ring-buffer contract without adding another verifier loop.
    let data = core::ptr::addr_of_mut!((*record).data) as *mut u64;
    core::ptr::write_unaligned(data.add(0), 0);
    core::ptr::write_unaligned(data.add(1), 0);
    core::ptr::write_unaligned(data.add(2), 0);
    core::ptr::write_unaligned(data.add(3), 0);
    core::ptr::write_unaligned(data.add(4), 0);
    core::ptr::write_unaligned(data.add(5), 0);
    core::ptr::write_unaligned(data.add(6), 0);
    core::ptr::write_unaligned(data.add(7), 0);
    core::ptr::write_unaligned(data.add(8), 0);
    core::ptr::write_unaligned(data.add(9), 0);
    core::ptr::write_unaligned(data.add(10), 0);
    core::ptr::write_unaligned(data.add(11), 0);
    core::ptr::write_unaligned(data.add(12), 0);
    core::ptr::write_unaligned(data.add(13), 0);
    core::ptr::write_unaligned(data.add(14), 0);
    core::ptr::write_unaligned(data.add(15), 0);
}

#[repr(C)]
struct ExecLoopContext {
    argv: u64,
    exec_id: u64,
    cgroup_id: u64,
    captured_at_boot_ns: u64,
    capture_decision: CaptureDecisionContext,
    argp: u64,
    arg_offset: u32,
    captured_bytes: u32,
    pid: u32,
    ppid: u32,
    uid: u32,
    arg_index: u16,
    chunk_index: u16,
    captured_argc: u16,
    flags: u8,
    done: u8,
    comm: [u8; 16],
}

unsafe extern "C" fn capture_exec_chunk(_iteration: u32, raw_ctx: *mut c_void) -> i64 {
    let state = &mut *(raw_ctx as *mut ExecLoopContext);
    if state.done != 0 {
        return 1;
    }

    if state.argp == 0 {
        if state.arg_index as usize >= ARGV_SLOTS {
            match read_user_u64((state.argv as *const u8).add(ARGV_SLOTS * 8)) {
                Some(0) => {}
                Some(_) => state.flags |= EXEC_FLAG_ARGV_TRUNCATED,
                None => state.flags |= EXEC_FLAG_ARGV_INCOMPLETE,
            }
            state.done = 1;
            return 1;
        }
        let Some(next_arg) =
            read_user_u64((state.argv as *const u8).add(state.arg_index as usize * 8))
        else {
            state.flags |= EXEC_FLAG_ARGV_INCOMPLETE;
            state.done = 1;
            return 1;
        };
        if next_arg == 0 {
            state.done = 1;
            return 1;
        }
        state.argp = next_arg;
        state.captured_argc += 1;
    }

    let Some(mut chunk_entry) = reserve_or_drop::<ExecRecord>(&EVENTS, PIPELINE_RING_EXEC) else {
        state.flags |= EXEC_FLAG_ARGV_INCOMPLETE;
        state.done = 1;
        return 1;
    };
    let chunk = chunk_entry.as_mut_ptr();
    init_exec_record(
        chunk,
        state.exec_id,
        state.cgroup_id,
        state.pid,
        state.ppid,
        state.uid,
        state.comm,
        state.captured_at_boot_ns,
        state.capture_decision,
    );
    (*chunk).kind = EXEC_RECORD_ARG_CHUNK;
    (*chunk).arg_index = state.arg_index;
    (*chunk).chunk_index = state.chunk_index;

    let len = match bpf_probe_read_user_str_bytes(
        (state.argp as *const u8).add(state.arg_offset as usize),
        &mut (*chunk).data,
    ) {
        Ok(bytes) => bytes.len(),
        Err(_) => {
            chunk_entry.discard(0);
            state.flags |= EXEC_FLAG_ARGV_INCOMPLETE;
            state.done = 1;
            return 1;
        }
    };
    (*chunk).data_len = len as u16;
    submit_accounted(chunk_entry, PIPELINE_RING_EXEC);
    state.captured_bytes += len as u32;

    if len < EXEC_ARG_CHUNK_PAYLOAD {
        state.arg_index += 1;
        state.chunk_index = 0;
        state.arg_offset = 0;
        state.argp = 0;
    } else {
        state.chunk_index += 1;
        state.arg_offset += len as u32;
    }
    0
}

// ---- process ancestry + tool exec ----

#[tracepoint]
pub fn track_process_fork(ctx: TracePointContext) -> u32 {
    // Linux 6.17 tracepoint payload uses dynamic comm strings: parent_pid at offset 12, child_pid at offset 20.
    let Ok(parent) = (unsafe { ctx.read_at::<i32>(12) }) else {
        return 0;
    };
    let Ok(child) = (unsafe { ctx.read_at::<i32>(20) }) else {
        return 0;
    };
    if parent > 0 && child > 0 {
        let _ = PARENTS.insert(&(child as u32), &(parent as u32), 0);
        inherit_capture_promotion(parent as u32, child as u32);
    }
    0
}

#[tracepoint]
pub fn track_clone(ctx: TracePointContext) -> u32 {
    track_child(&ctx)
}

#[tracepoint]
pub fn track_clone3(ctx: TracePointContext) -> u32 {
    track_child(&ctx)
}

#[tracepoint]
pub fn track_fork(ctx: TracePointContext) -> u32 {
    track_child(&ctx)
}

#[tracepoint]
pub fn track_vfork(ctx: TracePointContext) -> u32 {
    track_child(&ctx)
}

fn track_child(ctx: &TracePointContext) -> u32 {
    // sys_exit_clone/fork/vfork: positive return value is the child PID in the parent process.
    let Ok(child) = (unsafe { ctx.read_at::<i64>(16) }) else {
        return 0;
    };
    if child <= 0 || child > u32::MAX as i64 {
        return 0;
    }
    let parent = (bpf_get_current_pid_tgid() >> 32) as u32;
    let _ = PARENTS.insert(&(child as u32), &parent, 0);
    inherit_capture_promotion(parent, child as u32);
    0
}

#[tracepoint]
pub fn exec(ctx: TracePointContext) -> u32 {
    try_exec(&ctx).unwrap_or(0)
}

fn try_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let ppid = unsafe { PARENTS.get(&pid).copied().unwrap_or(0) };
    let comm = bpf_get_current_comm().unwrap_or_default();
    // Every syscall-entry fragment shares one timestamp. This lets userspace reassemble a logical
    // exec without manufacturing order from the time each physical ring record was drained.
    let captured_at_boot_ns = unsafe { bpf_ktime_get_ns() };
    let exec_id = captured_at_boot_ns ^ pid_tgid;
    let capture_decision = capture_raw_decision(CAPTURE_PROBE_EXEC, cgroup_id, pid, 0, 0);
    if !capture_decision.selected() {
        return Ok(0);
    }
    capture_payload_candidate(CAPTURE_PROBE_EXEC);
    let mut flags = 0u8;
    if EXEC_IDS
        .insert(
            &pid,
            &PendingExecState {
                exec_id,
                capture_decision,
            },
            0,
        )
        .is_err()
    {
        // Never leave an older pending/committed generation behind under this PID. Losing
        // attribution is safe; attributing the next exit to a stale generation is not.
        let _ = EXEC_IDS.remove(&pid);
        let _ = COMMITTED_EXEC_IDS.remove(&pid);
        capture_payload_error(CAPTURE_PROBE_EXEC);
        return Ok(0);
    }

    let Some(mut header_entry) = reserve_or_drop::<ExecRecord>(&EVENTS, PIPELINE_RING_EXEC) else {
        return Ok(0);
    };
    let header = header_entry.as_mut_ptr();
    unsafe {
        init_exec_record(
            header,
            exec_id,
            cgroup_id,
            pid,
            ppid,
            uid,
            comm,
            captured_at_boot_ns,
            capture_decision,
        );
        (*header).kind = EXEC_RECORD_HEADER;
        // sys_enter_execve: `const char *filename` at offset 16.
        if let Ok(filename_ptr) = ctx.read_at::<*const u8>(16) {
            match bpf_probe_read_user_str_bytes(filename_ptr, &mut (*header).data) {
                Ok(bytes) => (*header).data_len = bytes.len() as u16,
                Err(_) => flags |= EXEC_FLAG_ARGV_INCOMPLETE,
            }
        } else {
            flags |= EXEC_FLAG_ARGV_INCOMPLETE;
        }
        (*header).flags = flags;
    }
    submit_accounted(header_entry, PIPELINE_RING_EXEC);

    let captured_argc: u16;
    let captured_bytes: u32;

    unsafe {
        // `const char *const *argv` at offset 24. bpf_loop verifies the callback once instead of
        // exploring every state transition through a 64-iteration in-program loop.
        if let Ok(argv) = ctx.read_at::<*const u8>(24) {
            let mut loop_ctx = ExecLoopContext {
                argv: argv as u64,
                exec_id,
                cgroup_id,
                captured_at_boot_ns,
                capture_decision,
                argp: 0,
                arg_offset: 0,
                captured_bytes: 0,
                pid,
                ppid,
                uid,
                arg_index: 0,
                chunk_index: 0,
                captured_argc: 0,
                flags,
                done: 0,
                comm,
            };
            let iterations = bpf_loop(
                EXEC_MAX_CHUNKS as u32,
                capture_exec_chunk as *mut c_void,
                &mut loop_ctx as *mut ExecLoopContext as *mut c_void,
                0,
            );
            if iterations < 0 {
                loop_ctx.flags |= EXEC_FLAG_ARGV_INCOMPLETE;
            } else if loop_ctx.done == 0 {
                loop_ctx.flags |= EXEC_FLAG_ARGV_TRUNCATED;
            }
            flags = loop_ctx.flags;
            captured_argc = loop_ctx.captured_argc;
            captured_bytes = loop_ctx.captured_bytes;
        } else {
            flags |= EXEC_FLAG_ARGV_INCOMPLETE;
            captured_argc = 0;
            captured_bytes = 0;
        }

        let Some(mut end_entry) = reserve_or_drop::<ExecRecord>(&EVENTS, PIPELINE_RING_EXEC) else {
            return Ok(0);
        };
        let end = end_entry.as_mut_ptr();
        init_exec_record(
            end,
            exec_id,
            cgroup_id,
            pid,
            ppid,
            uid,
            comm,
            captured_at_boot_ns,
            capture_decision,
        );
        (*end).kind = EXEC_RECORD_END;
        (*end).flags = flags;
        (*end).argc = captured_argc;
        (*end).captured_bytes = captured_bytes;
        submit_accounted(end_entry, PIPELINE_RING_EXEC);
    }
    Ok(0)
}

/// Successful exec commit. Userspace correlates this small record with the bounded syscall-entry
/// fragments and can then read `/proc/<pid>/cmdline` while the committed image is still alive.
#[tracepoint]
pub fn track_process_exec(_ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let Some(pending) = (unsafe { EXEC_IDS.get(&pid).copied() }) else {
        // A commit without its syscall-entry generation (for example after bounded-map loss)
        // invalidates any older generation for the same PID.
        let _ = COMMITTED_EXEC_IDS.remove(&pid);
        return 0;
    };
    let exec_id = pending.exec_id;
    let uid = bpf_get_current_uid_gid() as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let ppid = unsafe { PARENTS.get(&pid).copied().unwrap_or(0) };
    let comm = bpf_get_current_comm().unwrap_or_default();
    // Commit is a separate kernel fact from syscall entry and therefore carries the time at which
    // the new image was successfully installed. `exec_id` preserves their generation relation.
    let captured_at_boot_ns = unsafe { bpf_ktime_get_ns() };
    if COMMITTED_EXEC_IDS.insert(&pid, &exec_id, 0).is_err() {
        let _ = COMMITTED_EXEC_IDS.remove(&pid);
    }
    commit_capture_promotion(pid, exec_id, cgroup_id);
    if let Some(mut entry) = reserve_or_drop::<ExecRecord>(&EVENTS, PIPELINE_RING_EXEC) {
        let record = entry.as_mut_ptr();
        unsafe {
            init_exec_record(
                record,
                exec_id,
                cgroup_id,
                pid,
                ppid,
                uid,
                comm,
                captured_at_boot_ns,
                pending.capture_decision,
            );
            (*record).kind = EXEC_RECORD_COMMIT;
        }
        submit_accounted(entry, PIPELINE_RING_EXEC);
    }
    let _ = EXEC_IDS.remove(&pid);
    0
}

// ---- process exit (do_exit kprobe) — the tool's outcome: exit code AND terminating signal ----

#[kprobe]
pub fn proc_exit(ctx: ProbeContext) -> u32 {
    try_proc_exit(&ctx).unwrap_or(0)
}

// do_exit(long code) fires for EVERY task exit, including signal-kills (SIGSEGV crash, SIGKILL /
// OOM) that never call exit_group. `code` is the wait-status: low 7 bits = terminating signal,
// (code >> 8) & 0xff = the exit() status.
fn try_proc_exit(ctx: &ProbeContext) -> Result<u32, i64> {
    // do_exit fires per-THREAD; emit once per PROCESS by gating on the thread-group leader
    // (tgid == task pid). Without this a multithreaded agent emits N duplicate ProcessExit/pid.
    let id = bpf_get_current_pid_tgid();
    if (id >> 32) as u32 != id as u32 {
        return Ok(0);
    }
    let pid = (id >> 32) as u32;
    let code: u64 = ctx.arg(0).unwrap_or(0);
    let exec_id = unsafe { COMMITTED_EXEC_IDS.get(&pid).copied().unwrap_or(0) };
    let captured_at_boot_ns = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let capture_decision = capture_raw_decision(CAPTURE_PROBE_EXIT, cgroup_id, pid, 0, 0);
    if !capture_decision.selected() {
        return Ok(0);
    }
    capture_payload_candidate(CAPTURE_PROBE_EXIT);
    if let Some(mut entry) = reserve_or_drop::<ExitEvent>(&EXIT_EVENTS, PIPELINE_RING_EXIT) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).cgroup_id = cgroup_id;
            (*ev).pid = pid;
            (*ev).comm = bpf_get_current_comm().unwrap_or_default();
            (*ev).exit_code = ((code >> 8) & 0xff) as u32;
            (*ev).signal = (code & 0x7f) as u32; // & 0x7f intentionally drops the 0x80 core-dump bit
            (*ev)._pad = 0;
            (*ev).exec_id = exec_id;
            (*ev).captured_at_boot_ns = captured_at_boot_ns;
            (*ev).capture_decision = capture_decision;
        }
        submit_accounted(entry, PIPELINE_RING_EXIT);
    }
    let _ = PARENTS.remove(&pid);
    let _ = EXEC_IDS.remove(&pid);
    let _ = COMMITTED_EXEC_IDS.remove(&pid);
    remove_capture_promotion(pid);
    Ok(0)
}

// ---- TLS ClientHello on send (sys_enter_write / sys_enter_sendto) ----
//
// Both tracepoints share arg layout: buf @ offset 24, count @ offset 32. The probe only
// detects the ClientHello + copies its leading bytes (verifier-friendly); userspace
// parses the SNI.

#[tracepoint]
pub fn tls_write(ctx: TracePointContext) -> u32 {
    try_tls(&ctx).unwrap_or(0)
}

#[tracepoint]
pub fn tls_sendto(ctx: TracePointContext) -> u32 {
    try_tls(&ctx).unwrap_or(0)
}

fn try_tls(ctx: &TracePointContext) -> Result<u32, i64> {
    let buf: *const u8 = unsafe { ctx.read_at(24)? };
    let count: u64 = unsafe { ctx.read_at(32)? };
    let fd: u64 = unsafe { ctx.read_at(16)? };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let key = sock_key(pid, fd);
    try_plain_http_write(pid, fd, buf, count);
    // Already tracking this LLM socket → this write is request payload; accumulate + done.
    if let Some(stat) = LLM_SOCKS.get_ptr_mut(&key) {
        unsafe {
            (*stat).req_bytes = (*stat).req_bytes.saturating_add(count);
        }
        return Ok(0);
    }
    if count < 6 {
        return Ok(0);
    }
    // Peek the record header: handshake (0x16), TLS major 0x03, ClientHello (0x01 @ 5).
    let mut hdr = [0u8; 6];
    if unsafe { bpf_probe_read_user_buf(buf, &mut hdr) }.is_err() {
        return Ok(0);
    }
    if hdr[0] != 0x16 || hdr[1] != 0x03 || hdr[5] != 0x01 {
        return Ok(0);
    }
    let captured_at_boot_ns = unsafe { bpf_ktime_get_ns() };
    // New LLM call: start the metrics accumulator and emit the SNI snapshot.
    let _ = LLM_SOCKS.insert(
        &key,
        &LlmStat {
            start_ns: captured_at_boot_ns,
            first_resp_ns: 0,
            req_bytes: 0,
            resp_bytes: 0,
        },
        0,
    );
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let capture_decision = capture_raw_decision(CAPTURE_PROBE_TLS, cgroup_id, pid, count, 0);
    if !capture_decision.selected() {
        return Ok(0);
    }
    capture_payload_candidate(CAPTURE_PROBE_TLS);
    let Some(mut entry) = reserve_or_drop::<TlsEvent>(&TLS_EVENTS, PIPELINE_RING_TLS) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = cgroup_id;
        (*ev).pid = pid;
        (*ev).fd = fd as u32;
        (*ev)._pad = 0;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        // n <= TLS_SNAP_LEN (= data capacity) and n <= count (= source length).
        let n: u32 = if count > TLS_SNAP_LEN as u64 {
            TLS_SNAP_LEN as u32
        } else {
            count as u32
        };
        (*ev).len = n as u16;
        (*ev).data = [0u8; TLS_SNAP_LEN];
        if bpf_probe_read_user(
            (*ev).data.as_mut_ptr() as *mut core::ffi::c_void,
            n,
            buf as *const core::ffi::c_void,
        ) < 0
        {
            capture_payload_error(CAPTURE_PROBE_TLS);
            entry.discard(0);
            return Ok(0);
        }
        (*ev)._event_time_pad = [0; 4];
        (*ev).captured_at_boot_ns = captured_at_boot_ns;
        (*ev).capture_decision = capture_decision;
    }
    submit_accounted(entry, PIPELINE_RING_TLS);
    Ok(0)
}

// ---- OPT-IN TLS plaintext (OpenSSL/BoringSSL-compatible uprobes) ----
//
// Entry probes remember pointers only. Return probes use the API's actual successful byte count,
// then copy into the smallest fixed ring-record tier. This handles partial writes and the OpenSSL
// 3 `_ex` ABI without blocking the Agent on userspace parsing or storage.

fn remember_ssl_call(ctx: &ProbeContext, direction: u8, api_kind: u8, result_len_ptr: u64) -> u32 {
    if api_kind == TLS_PLAINTEXT_API_SSL_EX {
        bump_tls_profile_diagnostic(11);
    } else if api_kind == TLS_PLAINTEXT_API_SSL_CLASSIC {
        bump_tls_profile_diagnostic(16);
    }
    let ssl_ptr = ctx.arg::<u64>(0).unwrap_or(0);
    let buf = ctx.arg::<u64>(1).unwrap_or(0);
    let requested_len = ctx.arg::<u64>(2).unwrap_or(0);
    if buf == 0 || requested_len == 0 {
        return 0;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let args = SslCallArgs {
        ssl_ptr,
        buf,
        requested_len,
        result_len_ptr,
        started_at_boot_ns: unsafe { bpf_ktime_get_ns() },
        direction,
        api_kind,
        route_kind: 0,
        _pad: [0; 5],
    };
    let _ = SSL_CALL_ARGS.insert(&pid_tgid, &args, 0);
    0
}

#[uprobe]
pub fn ssl_write_enter(ctx: ProbeContext) -> u32 {
    remember_ssl_call(
        &ctx,
        TLS_PLAINTEXT_DIRECTION_WRITE,
        TLS_PLAINTEXT_API_SSL_CLASSIC,
        0,
    )
}

#[uretprobe]
pub fn ssl_write_exit(ctx: RetProbeContext) -> u32 {
    finish_ssl_classic(&ctx, TLS_PLAINTEXT_DIRECTION_WRITE)
}

#[uprobe]
pub fn ssl_read_enter(ctx: ProbeContext) -> u32 {
    remember_ssl_call(
        &ctx,
        TLS_PLAINTEXT_DIRECTION_READ,
        TLS_PLAINTEXT_API_SSL_CLASSIC,
        0,
    )
}

#[uretprobe]
pub fn ssl_read_exit(ctx: RetProbeContext) -> u32 {
    finish_ssl_classic(&ctx, TLS_PLAINTEXT_DIRECTION_READ)
}

#[uprobe]
pub fn ssl_write_ex_enter(ctx: ProbeContext) -> u32 {
    remember_ssl_call(
        &ctx,
        TLS_PLAINTEXT_DIRECTION_WRITE,
        TLS_PLAINTEXT_API_SSL_EX,
        ctx.arg::<u64>(3).unwrap_or(0),
    )
}

#[uretprobe]
pub fn ssl_write_ex_exit(ctx: RetProbeContext) -> u32 {
    finish_ssl_ex(&ctx, TLS_PLAINTEXT_DIRECTION_WRITE)
}

#[uprobe]
pub fn ssl_read_ex_enter(ctx: ProbeContext) -> u32 {
    remember_ssl_call(
        &ctx,
        TLS_PLAINTEXT_DIRECTION_READ,
        TLS_PLAINTEXT_API_SSL_EX,
        ctx.arg::<u64>(3).unwrap_or(0),
    )
}

#[uretprobe]
pub fn ssl_read_ex_exit(ctx: RetProbeContext) -> u32 {
    finish_ssl_ex(&ctx, TLS_PLAINTEXT_DIRECTION_READ)
}

// The observed rustls CommonState ABI family keeps application bytes in two internal boundaries:
// `CommonState::buffer_plaintext` receives an `OutboundChunks` value before encryption, while
// `CommonState::take_received_plaintext` receives a `Payload` immediately after record
// decryption. Userspace discovers both anchors and their relative relation in stripped static
// executables without checking a product, version, provider URL or whole-file fingerprint. The
// layouts remain part of that implementation-family ABI and are validated before capture.
//
// OutboundChunks::Single layout (observed x86_64 CommonState ABI family):
//   [0] = zero/niche tag, [1] = byte pointer, [2] = byte length, [3] = unused
// Payload::{Borrowed,Owned} layout:
//   [0] = tag/capacity, [1] = byte pointer, [2] = byte length

// Vectored `OutboundChunks::Multiple` is recorded by diagnostics but not dereferenced as a flat
// slice. A bounded scatter/gather decoder can be added as another ABI adapter without weakening
// the validated `Single` memory contract.
#[uprobe]
pub fn rustls_write_enter(ctx: ProbeContext) -> u32 {
    bump_tls_profile_diagnostic(0);
    let payload = ctx.arg::<u64>(1).unwrap_or(0);
    if payload == 0 {
        bump_tls_profile_diagnostic(1);
        return 0;
    }
    let mut layout = [0u64; 4];
    let read = unsafe {
        bpf_probe_read_user(
            layout.as_mut_ptr() as *mut c_void,
            core::mem::size_of_val(&layout) as u32,
            payload as *const c_void,
        )
    };
    if read < 0 || layout[1] == 0 || layout[2] == 0 {
        bump_tls_profile_diagnostic(1);
        return 0;
    }
    if layout[0] != 0 {
        bump_tls_profile_diagnostic(2);
        return 0;
    }
    bump_tls_profile_diagnostic(3);
    let args = SslCallArgs {
        ssl_ptr: ctx.arg::<u64>(0).unwrap_or(0),
        buf: layout[1],
        requested_len: layout[2],
        result_len_ptr: 0,
        started_at_boot_ns: unsafe { bpf_ktime_get_ns() },
        direction: TLS_PLAINTEXT_DIRECTION_WRITE,
        api_kind: TLS_PLAINTEXT_API_RUSTLS,
        route_kind: HTTP_PREFIX_UNKNOWN,
        _pad: [0; 5],
    };
    // `buffer_plaintext` may tail-call its encryption implementation. Capturing at this stable
    // pre-encryption boundary avoids relying on a Rust uretprobe trampoline surviving that tail
    // call. rustls normally accepts the full slice; if a future profile observes backpressure,
    // duplicate HTTP bytes are rejected by userspace framing/sequence quality rather than read
    // from encrypted socket buffers.
    bump_tls_profile_diagnostic(4);
    emit_tls_plaintext(args, layout[2])
}

#[uretprobe]
pub fn rustls_write_exit(ctx: RetProbeContext) -> u32 {
    let Some(args) = take_ssl_call(TLS_PLAINTEXT_DIRECTION_WRITE) else {
        return 0;
    };
    if args.api_kind != TLS_PLAINTEXT_API_RUSTLS {
        return 0;
    }
    let actual = ctx.ret::<u64>().unwrap_or(0).min(args.requested_len);
    emit_tls_plaintext(args, actual)
}

#[uprobe]
pub fn rustls_read_enter(ctx: ProbeContext) -> u32 {
    bump_tls_profile_diagnostic(5);
    let payload = ctx.arg::<u64>(1).unwrap_or(0);
    if payload == 0 {
        bump_tls_profile_diagnostic(6);
        return 0;
    }
    let mut layout = [0u64; 3];
    let read = unsafe {
        bpf_probe_read_user(
            layout.as_mut_ptr() as *mut c_void,
            core::mem::size_of_val(&layout) as u32,
            payload as *const c_void,
        )
    };
    if read < 0 || layout[1] == 0 || layout[2] == 0 {
        bump_tls_profile_diagnostic(6);
        return 0;
    }
    bump_tls_profile_diagnostic(7);
    emit_tls_plaintext(
        SslCallArgs {
            ssl_ptr: ctx.arg::<u64>(0).unwrap_or(0),
            buf: layout[1],
            requested_len: layout[2],
            result_len_ptr: 0,
            started_at_boot_ns: unsafe { bpf_ktime_get_ns() },
            direction: TLS_PLAINTEXT_DIRECTION_READ,
            api_kind: TLS_PLAINTEXT_API_RUSTLS,
            route_kind: 0,
            _pad: [0; 5],
        },
        layout[2],
    )
}

fn take_ssl_call(expected_direction: u8) -> Option<SslCallArgs> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let args = unsafe { SSL_CALL_ARGS.get(&pid_tgid) }.copied();
    let _ = SSL_CALL_ARGS.remove(&pid_tgid);
    args.filter(|value| value.direction == expected_direction)
}

fn finish_ssl_classic(ctx: &RetProbeContext, direction: u8) -> u32 {
    let Some(args) = take_ssl_call(direction) else {
        return 0;
    };
    if args.api_kind != TLS_PLAINTEXT_API_SSL_CLASSIC {
        return 0;
    }
    // OpenSSL/BoringSSL classic SSL_read/SSL_write return C `int`. Reading the full 64-bit rax
    // leaks undefined high bits on x86_64 and can turn a small successful read into the requested
    // buffer size after clamping, duplicating uninitialized bytes into the HTTP stream.
    let result = ctx.ret::<i32>().unwrap_or(0) as i64;
    if result <= 0 {
        return 0;
    }
    let actual = (result as u64).min(args.requested_len);
    bump_tls_profile_diagnostic(17);
    emit_tls_plaintext(args, actual)
}

fn finish_ssl_ex(ctx: &RetProbeContext, direction: u8) -> u32 {
    let Some(args) = take_ssl_call(direction) else {
        return 0;
    };
    if args.api_kind != TLS_PLAINTEXT_API_SSL_EX || ctx.ret::<i32>().unwrap_or(0) != 1 {
        return 0;
    }
    if args.result_len_ptr == 0 {
        return 0;
    }
    let mut actual = 0u64;
    let result = unsafe {
        bpf_probe_read_user(
            &mut actual as *mut u64 as *mut c_void,
            core::mem::size_of::<u64>() as u32,
            args.result_len_ptr as *const c_void,
        )
    };
    if result < 0 || actual == 0 {
        return 0;
    }
    bump_tls_profile_diagnostic(12);
    emit_tls_plaintext(args, actual.min(args.requested_len))
}

fn next_ssl_call_sequence(pid: u32, connection_id: u64, direction: u8) -> u64 {
    // Do not XOR the raw `(pid<<32)|fd` TCP connection id with `pid<<32`: that cancels the PID
    // bits and makes unrelated processes sharing the same fd corrupt each other's sequence.
    let key = connection_id.wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ (pid as u64).rotate_left(23)
        ^ ((direction as u64) << 63);
    if let Some(value) = SSL_CALL_SEQUENCES.get_ptr_mut(&key) {
        unsafe {
            *value = (*value).wrapping_add(1);
            *value
        }
    } else {
        let value = 1u64;
        let _ = SSL_CALL_SEQUENCES.insert(&key, &value, 0);
        value
    }
}

const HTTP_PREFIX_UNKNOWN: u8 = 0;
const HTTP_PREFIX_HTTP: u8 = 1;
const HTTP_REQUEST_LINE_SNAPSHOT: usize = 64;

#[inline(always)]
fn bytes_at<const N: usize>(
    data: &[u8; HTTP_REQUEST_LINE_SNAPSHOT],
    captured: usize,
    offset: usize,
    expected: &[u8; N],
) -> bool {
    if offset.saturating_add(N) > captured {
        return false;
    }
    let mut index = 0usize;
    while index < N {
        if data[offset + index] != expected[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Detect only the HTTP method prefix needed to keep plain-syscall capture away from stdout/files.
/// URL/path/provider semantics deliberately stay in userspace.
#[inline(always)]
fn http_request_prefix_kind(buf: u64, len: u64) -> u8 {
    if buf == 0 || len < 4 {
        return HTTP_PREFIX_UNKNOWN;
    }
    let mut data = [0u8; HTTP_REQUEST_LINE_SNAPSHOT];
    let captured = if len > HTTP_REQUEST_LINE_SNAPSHOT as u64 {
        HTTP_REQUEST_LINE_SNAPSHOT
    } else {
        len as usize
    };
    if unsafe {
        bpf_probe_read_user(
            data.as_mut_ptr() as *mut c_void,
            captured as u32,
            buf as *const c_void,
        )
    } < 0
    {
        return HTTP_PREFIX_UNKNOWN;
    }

    let is_http = bytes_at(&data, captured, 0, b"POST ")
        || bytes_at(&data, captured, 0, b"GET ")
        || bytes_at(&data, captured, 0, b"PUT ")
        || bytes_at(&data, captured, 0, b"PATCH ")
        || bytes_at(&data, captured, 0, b"DELETE ")
        || bytes_at(&data, captured, 0, b"HEAD ")
        || bytes_at(&data, captured, 0, b"OPTIONS ");
    if !is_http {
        return HTTP_PREFIX_UNKNOWN;
    }
    HTTP_PREFIX_HTTP
}

#[inline(always)]
fn verified_agent_process(pid: u32, cgroup_id: u64) -> bool {
    let key = PlaintextProcessKey {
        cgroup_id,
        pid,
        _pad: 0,
    };
    unsafe { VERIFIED_AGENT_PROCESSES.get(&key) }.is_some()
}

fn emit_tls_plaintext(args: SslCallArgs, actual_len: u64) -> u32 {
    if args.buf == 0 || actual_len == 0 {
        return 0;
    }
    let captured_at_boot_ns = unsafe { bpf_ktime_get_ns() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if !verified_agent_process(pid, cgroup_id) {
        if args.api_kind == TLS_PLAINTEXT_API_RUSTLS {
            bump_tls_profile_diagnostic(8);
        } else if args.api_kind == TLS_PLAINTEXT_API_SSL_EX {
            bump_tls_profile_diagnostic(13);
        } else if args.api_kind == TLS_PLAINTEXT_API_SSL_CLASSIC {
            bump_tls_profile_diagnostic(18);
        }
        return 0;
    }
    let capture_decision = capture_raw_decision(
        CAPTURE_PROBE_SSL,
        cgroup_id,
        pid,
        actual_len,
        (args.direction == TLS_PLAINTEXT_DIRECTION_READ) as u8,
    );
    if !capture_decision.selected() {
        if args.api_kind == TLS_PLAINTEXT_API_SSL_EX {
            bump_tls_profile_diagnostic(15);
        } else if args.api_kind == TLS_PLAINTEXT_API_SSL_CLASSIC {
            bump_tls_profile_diagnostic(20);
        }
        return 0;
    }
    capture_payload_candidate(CAPTURE_PROBE_SSL);
    let connection_id = if args.ssl_ptr != 0 {
        args.ssl_ptr
    } else {
        pid_tgid
    };
    let call_seq = next_ssl_call_sequence(pid, connection_id, args.direction);
    let original_len = if actual_len > u32::MAX as u64 {
        u32::MAX
    } else {
        actual_len as u32
    };

    macro_rules! emit_tier {
        ($event_type:ty, $capacity:expr) => {{
            let Some(mut entry) = reserve_or_drop::<$event_type>(&SSL_EVENTS, PIPELINE_RING_SSL)
            else {
                return 0;
            };
            let captured_len = if actual_len > $capacity as u64 {
                $capacity as u32
            } else {
                actual_len as u32
            };
            let mut flags = 0u16;
            if actual_len > $capacity as u64 {
                flags |= TLS_PLAINTEXT_FLAG_TRUNCATED;
            }
            if args.ssl_ptr == 0 {
                flags |= TLS_PLAINTEXT_FLAG_CONNECTION_UNBOUND;
            }
            let ev = entry.as_mut_ptr();
            unsafe {
                (*ev).header = TlsPlaintextEventHeader {
                    abi_version: TLS_PLAINTEXT_ABI_V1,
                    header_len: core::mem::size_of::<TlsPlaintextEventHeader>() as u16,
                    flags,
                    _pad0: 0,
                    cgroup_id,
                    pid,
                    tid,
                    connection_id,
                    call_seq,
                    original_len,
                    captured_len,
                    direction: args.direction,
                    api_kind: args.api_kind,
                    _pad1: [0; 6],
                    call_started_at_boot_ns: args.started_at_boot_ns,
                    captured_at_boot_ns,
                    comm: bpf_get_current_comm().unwrap_or_default(),
                    capture_decision,
                };
                if bpf_probe_read_user(
                    (*ev).data.as_mut_ptr() as *mut c_void,
                    captured_len,
                    args.buf as *const c_void,
                ) < 0
                {
                    capture_payload_error(CAPTURE_PROBE_SSL);
                    entry.discard(0);
                    return 0;
                }
            }
            submit_accounted(entry, PIPELINE_RING_SSL);
            return 0;
        }};
    }

    if actual_len <= TLS_PLAINTEXT_TIER_SMALL as u64 {
        emit_tier!(TlsPlaintextEventSmall, TLS_PLAINTEXT_TIER_SMALL);
    }
    if actual_len <= TLS_PLAINTEXT_TIER_MEDIUM as u64 {
        emit_tier!(TlsPlaintextEventMedium, TLS_PLAINTEXT_TIER_MEDIUM);
    }
    emit_tier!(TlsPlaintextEventLarge, TLS_PLAINTEXT_TIER_LARGE);
}

fn try_plain_http_write(pid: u32, fd: u64, buf: *const u8, len: u64) {
    if buf.is_null() || len == 0 {
        return;
    }
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if !verified_agent_process(pid, cgroup_id) {
        return;
    }
    let key = sock_key(pid, fd);
    let mut route_kind = unsafe { HTTP_SOCKS.get(&key) }
        .copied()
        .unwrap_or(HTTP_PREFIX_UNKNOWN);
    match http_request_prefix_kind(buf as u64, len) {
        HTTP_PREFIX_HTTP => {
            route_kind = HTTP_PREFIX_HTTP;
            let _ = HTTP_SOCKS.insert(&key, &route_kind, 0);
        }
        _ => {
            if route_kind != HTTP_PREFIX_HTTP {
                return;
            }
        }
    }
    if route_kind != HTTP_PREFIX_HTTP {
        return;
    }

    let args = SslCallArgs {
        ssl_ptr: key,
        buf: buf as u64,
        requested_len: len,
        result_len_ptr: 0,
        started_at_boot_ns: unsafe { bpf_ktime_get_ns() },
        direction: TLS_PLAINTEXT_DIRECTION_WRITE,
        api_kind: TLS_PLAINTEXT_API_TCP,
        route_kind,
        _pad: [0; 5],
    };
    let _ = emit_tls_plaintext(args, len);
}

#[tracepoint]
pub fn http_writev(ctx: TracePointContext) -> u32 {
    // sys_enter_writev: fd @16, iovec* @24, iovcnt @32. The first entries normally hold the HTTP
    // header and JSON body separately (notably Node/libuv). Four fixed iterations keep verifier
    // and copy cost bounded; the HTTP reassembler exposes missing bytes as partial/timeout.
    let Ok(fd) = (unsafe { ctx.read_at::<u64>(16) }) else {
        return 0;
    };
    let Ok(iov_ptr) = (unsafe { ctx.read_at::<u64>(24) }) else {
        return 0;
    };
    let Ok(iov_count) = (unsafe { ctx.read_at::<u64>(32) }) else {
        return 0;
    };
    if iov_ptr == 0 || iov_count == 0 {
        return 0;
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    for index in 0..4u64 {
        if index >= iov_count {
            break;
        }
        let mut iov = UserIovec { base: 0, len: 0 };
        let address = iov_ptr.saturating_add(index * core::mem::size_of::<UserIovec>() as u64);
        if unsafe {
            bpf_probe_read_user(
                &mut iov as *mut UserIovec as *mut c_void,
                core::mem::size_of::<UserIovec>() as u32,
                address as *const c_void,
            )
        } < 0
        {
            break;
        }
        try_plain_http_write(pid, fd, iov.base as *const u8, iov.len);
    }
    0
}

// ---- outbound connection peer (sys_enter_connect) ----

#[tracepoint]
pub fn connect(ctx: TracePointContext) -> u32 {
    try_connect(&ctx).unwrap_or(0)
}

fn try_connect(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_connect: int fd @16, struct sockaddr *uservaddr @24, int addrlen @32.
    let addr_ptr: *const u8 = unsafe { ctx.read_at(24)? };
    let addrlen: u64 = unsafe { ctx.read_at(32)? };
    let fd: u64 = unsafe { ctx.read_at(16)? };
    if addrlen < 8 {
        return Ok(0);
    }
    let mut fam = [0u8; 2];
    if unsafe { bpf_probe_read_user_buf(addr_ptr, &mut fam) }.is_err() {
        return Ok(0);
    }
    let family = u16::from_ne_bytes(fam); // sa_family is host-endian
    if family != 2 && family != 10 {
        return Ok(0); // only AF_INET / AF_INET6
    }
    let captured_at_boot_ns = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let capture_decision = capture_raw_decision(
        CAPTURE_PROBE_CONNECT,
        cgroup_id,
        pid,
        0,
        (family == 10) as u8,
    );
    if !capture_decision.selected() {
        return Ok(0);
    }
    capture_payload_candidate(CAPTURE_PROBE_CONNECT);
    let Some(mut entry) = reserve_or_drop::<ConnectEvent>(&CONNECT_EVENTS, PIPELINE_RING_CONNECT)
    else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = cgroup_id;
        (*ev).pid = pid;
        (*ev).fd = fd as u32;
        (*ev).family = family;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        let mut port = [0u8; 2];
        if bpf_probe_read_user_buf(addr_ptr.add(2), &mut port).is_err() {
            capture_payload_error(CAPTURE_PROBE_CONNECT);
            entry.discard(0);
            return Ok(0);
        }
        (*ev).port = u16::from_be_bytes(port);
        // Read into a local first to avoid an autoref through the raw event pointer.
        let mut a = [0u8; 16];
        if family == 2 {
            if bpf_probe_read_user_buf(addr_ptr.add(4), &mut a[..4]).is_err() {
                capture_payload_error(CAPTURE_PROBE_CONNECT);
                entry.discard(0);
                return Ok(0);
            }
        } else if bpf_probe_read_user_buf(addr_ptr.add(8), &mut a).is_err() {
            capture_payload_error(CAPTURE_PROBE_CONNECT);
            entry.discard(0);
            return Ok(0);
        }
        (*ev).addr = a;
        (*ev)._event_time_pad = [0; 4];
        (*ev).captured_at_boot_ns = captured_at_boot_ns;
        (*ev).capture_decision = capture_decision;
    }
    submit_accounted(entry, PIPELINE_RING_CONNECT);
    Ok(0)
}

// ---- security-sensitive actions: privesc (setuid) / injection (ptrace) / open-port (bind) ----
//
// One ring, in-kernel-filtered to the loud cases. These syscalls are rare for a normal agent, so
// when one fires it's worth a look — that's the whole point of a separate "rare and loud" tier.

fn emit_sec(kind: u32, detail: u64) {
    let captured_at_boot_ns = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // The Security event itself is hard-FULL, and atomically promotes this runtime to temporary
    // investigation_full before subsequent file/network events can be evaluated.
    promote_security_runtime(pid, cgroup_id);
    let capture_decision =
        capture_raw_decision(CAPTURE_PROBE_SECURITY, cgroup_id, pid, 0, kind as u8);
    if !capture_decision.selected() {
        return;
    }
    capture_payload_candidate(CAPTURE_PROBE_SECURITY);
    let Some(mut entry) = reserve_or_drop::<SecEvent>(&SEC_EVENTS, PIPELINE_RING_SECURITY) else {
        return;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = cgroup_id;
        (*ev).pid = pid;
        (*ev).kind = kind;
        (*ev).detail = detail;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        (*ev).captured_at_boot_ns = captured_at_boot_ns;
        (*ev).capture_decision = capture_decision;
    }
    submit_accounted(entry, PIPELINE_RING_SECURITY);
}

// Escalation TO root from a non-root caller — the loud case. Dropping privs (root → nobody, which
// every daemon does at boot) is noise and is filtered out. NOTE: legitimate setuid-root tools
// (sudo/su/passwd) also fire here — it's a genuine privilege transition, expected to pair with a
// ToolExec of the setuid binary, not inherently malicious.
fn try_setuid_to(target: u32) {
    // glibc broadcasts setuid/setresuid/setreuid to EVERY thread (NPTL setxid), so one logical
    // escalation fires this per-thread — the same fanout do_exit has. Emit once, from the
    // thread-group leader (tgid == tid), matching the proc_exit convention. (A raw setuid syscall
    // from a non-leader thread is thus missed — vanishingly rare vs the glibc/single-threaded paths.)
    let id = bpf_get_current_pid_tgid();
    if (id >> 32) as u32 != id as u32 {
        return;
    }
    if target == 0 && (bpf_get_current_uid_gid() as u32) != 0 {
        emit_sec(SEC_SETUID, 0);
    }
}

#[tracepoint]
pub fn sec_setuid(ctx: TracePointContext) -> u32 {
    try_sec_setuid(&ctx).unwrap_or(0)
}
fn try_sec_setuid(ctx: &TracePointContext) -> Result<u32, i64> {
    let uid: u64 = unsafe { ctx.read_at(16)? }; // sys_enter_setuid: uid_t uid @16
    try_setuid_to(uid as u32);
    Ok(0)
}

#[tracepoint]
pub fn sec_setresuid(ctx: TracePointContext) -> u32 {
    try_sec_setresuid(&ctx).unwrap_or(0)
}
fn try_sec_setresuid(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_setresuid: ruid @16, euid @24, suid @32 — the euid grants effective privilege.
    let euid: u64 = unsafe { ctx.read_at(24)? };
    try_setuid_to(euid as u32);
    Ok(0)
}

#[tracepoint]
pub fn sec_setreuid(ctx: TracePointContext) -> u32 {
    try_sec_setreuid(&ctx).unwrap_or(0)
}
fn try_sec_setreuid(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_setreuid: ruid @16, euid @24 — euid is the effective uid being set (the privesc
    // path os.setreuid / seteuid take, which neither setuid nor setresuid catches).
    let euid: u64 = unsafe { ctx.read_at(24)? };
    try_setuid_to(euid as u32);
    Ok(0)
}

#[tracepoint]
pub fn sec_ptrace(ctx: TracePointContext) -> u32 {
    try_sec_ptrace(&ctx).unwrap_or(0)
}
fn try_sec_ptrace(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_ptrace: long request @16, long pid @24.
    let request: u64 = unsafe { ctx.read_at(16)? };
    let target: u64 = unsafe { ctx.read_at(24)? };
    // PTRACE_ATTACH = 16, PTRACE_SEIZE = 0x4206 — the gateway to memory/register injection
    // (you must attach before POKE*). TRACEME = 0 is benign self-trace. Skip self-targeting.
    let self_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if (request == 16 || request == 0x4206) && target as u32 != self_pid {
        emit_sec(SEC_PTRACE, target);
    }
    Ok(0)
}

#[tracepoint]
pub fn sec_bind(ctx: TracePointContext) -> u32 {
    try_sec_bind(&ctx).unwrap_or(0)
}
fn try_sec_bind(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_bind: int fd @16, struct sockaddr *umyaddr @24, int addrlen @32 — same shape as connect.
    let addr_ptr: *const u8 = unsafe { ctx.read_at(24)? };
    let addrlen: u64 = unsafe { ctx.read_at(32)? };
    if addrlen < 8 {
        return Ok(0);
    }
    let mut fam = [0u8; 2];
    if unsafe { bpf_probe_read_user_buf(addr_ptr, &mut fam) }.is_err() {
        return Ok(0);
    }
    let family = u16::from_ne_bytes(fam);
    if family != 2 && family != 10 {
        return Ok(0); // AF_INET / AF_INET6 only
    }
    // Skip loopback (127.0.0.0/8) binds — local-only helper sockets (runtime debug/metrics servers)
    // are common noise; an off-host-reachable listener is the loud case. (IPv6 ::1 not filtered.)
    if family == 2 {
        let mut oct = [0u8; 1];
        let _ = unsafe { bpf_probe_read_user_buf(addr_ptr.add(4), &mut oct) }; // first octet of sin_addr
        if oct[0] == 127 {
            return Ok(0);
        }
    }
    let mut port = [0u8; 2];
    let _ = unsafe { bpf_probe_read_user_buf(addr_ptr.add(2), &mut port) }; // sin_port (network order)
    let port = u16::from_be_bytes(port);
    // port 0 = kernel picks (a client's ephemeral source port); a fixed port = a server listening.
    if port != 0 {
        emit_sec(SEC_BIND, port as u64);
    }
    Ok(0)
}

// ---- DNS query (sys_enter_sendto to :53) ----
// Detects a UDP DNS query by the dest port (sockaddr @ offset 48) and copies the packet;
// userspace parses the question name. Connected-UDP sends (NULL dest addr) aren't covered.

#[tracepoint]
pub fn dns_query(ctx: TracePointContext) -> u32 {
    try_dns(&ctx).unwrap_or(0)
}

fn try_dns(ctx: &TracePointContext) -> Result<u32, i64> {
    let addr_ptr: *const u8 = unsafe { ctx.read_at(48)? }; // dest sockaddr
    let addr_len: u64 = unsafe { ctx.read_at(56)? };
    if (addr_ptr as usize) == 0 || addr_len < 4 {
        return Ok(0);
    }
    // sockaddr: family @0 (2 bytes), port @2 (2 bytes, network order).
    let mut sa = [0u8; 4];
    if unsafe { bpf_probe_read_user_buf(addr_ptr, &mut sa) }.is_err() {
        return Ok(0);
    }
    if u16::from_be_bytes([sa[2], sa[3]]) != 53 {
        return Ok(0);
    }
    let buf: *const u8 = unsafe { ctx.read_at(24)? };
    let count: u64 = unsafe { ctx.read_at(32)? };
    if count < 13 {
        return Ok(0); // DNS header(12) + >=1 question byte
    }
    let captured_at_boot_ns = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let capture_decision = capture_raw_decision(CAPTURE_PROBE_DNS, cgroup_id, pid, count, 0);
    if !capture_decision.selected() {
        return Ok(0);
    }
    capture_payload_candidate(CAPTURE_PROBE_DNS);
    let Some(mut entry) = reserve_or_drop::<DnsEvent>(&DNS_EVENTS, PIPELINE_RING_DNS) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = cgroup_id;
        (*ev).pid = pid;
        (*ev)._pad = 0;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        let n: u32 = if count > DNS_SNAP_LEN as u64 {
            DNS_SNAP_LEN as u32
        } else {
            count as u32
        };
        (*ev).len = n as u16;
        (*ev).data = [0u8; DNS_SNAP_LEN];
        if bpf_probe_read_user(
            (*ev).data.as_mut_ptr() as *mut core::ffi::c_void,
            n,
            buf as *const core::ffi::c_void,
        ) < 0
        {
            capture_payload_error(CAPTURE_PROBE_DNS);
            entry.discard(0);
            return Ok(0);
        }
        (*ev).captured_at_boot_ns = captured_at_boot_ns;
        (*ev).capture_decision = capture_decision;
    }
    submit_accounted(entry, PIPELINE_RING_DNS);
    Ok(0)
}

// ---- DNS query via sendmsg / sendmmsg (glibc getaddrinfo) ----
// glibc's resolver sends A/AAAA queries with sendmmsg (and some resolvers use sendmsg);
// both pass a `struct msghdr` (mmsghdr.msg_hdr is at offset 0). Walk it to the dest addr
// (:53) and the first iovec (the query packet). Only the first message is parsed.

#[tracepoint]
pub fn dns_sendmsg(ctx: TracePointContext) -> u32 {
    try_dns_msghdr(&ctx).unwrap_or(0)
}

#[tracepoint]
pub fn dns_sendmmsg(ctx: TracePointContext) -> u32 {
    try_dns_msghdr(&ctx).unwrap_or(0)
}

fn try_dns_msghdr(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_sendmsg(fd, msghdr*, flags) / sys_enter_sendmmsg(fd, mmsghdr*, vlen, flags):
    // a struct msghdr is at the @24 pointer either way (mmsghdr.msg_hdr is at offset 0).
    let hdr: u64 = unsafe { ctx.read_at(24)? };
    if hdr == 0 {
        return Ok(0);
    }
    let base = hdr as *const u8;
    // struct msghdr: msg_name @0, msg_iov @16.
    let Some(msg_name) = read_user_u64(base) else {
        return Ok(0);
    };
    let Some(msg_iov) = read_user_u64(unsafe { base.add(16) }) else {
        return Ok(0);
    };
    if msg_name == 0 || msg_iov == 0 {
        return Ok(0);
    }
    // dest sockaddr: family @0, port @2 (network order).
    let mut sa = [0u8; 4];
    if unsafe { bpf_probe_read_user_buf(msg_name as *const u8, &mut sa) }.is_err() {
        return Ok(0);
    }
    if u16::from_be_bytes([sa[2], sa[3]]) != 53 {
        return Ok(0);
    }
    // iovec[0]: iov_base @0, iov_len @8 → the DNS query packet.
    let Some(iov_base) = read_user_u64(msg_iov as *const u8) else {
        return Ok(0);
    };
    let Some(iov_len) = read_user_u64(unsafe { (msg_iov as *const u8).add(8) }) else {
        return Ok(0);
    };
    if iov_base == 0 || iov_len < 13 {
        return Ok(0);
    }
    let captured_at_boot_ns = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let capture_decision = capture_raw_decision(CAPTURE_PROBE_DNS, cgroup_id, pid, iov_len, 0);
    if !capture_decision.selected() {
        return Ok(0);
    }
    capture_payload_candidate(CAPTURE_PROBE_DNS);
    let Some(mut entry) = reserve_or_drop::<DnsEvent>(&DNS_EVENTS, PIPELINE_RING_DNS) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = cgroup_id;
        (*ev).pid = pid;
        (*ev)._pad = 0;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        let n: u32 = if iov_len > DNS_SNAP_LEN as u64 {
            DNS_SNAP_LEN as u32
        } else {
            iov_len as u32
        };
        (*ev).len = n as u16;
        (*ev).data = [0u8; DNS_SNAP_LEN];
        if bpf_probe_read_user(
            (*ev).data.as_mut_ptr() as *mut core::ffi::c_void,
            n,
            iov_base as *const core::ffi::c_void,
        ) < 0
        {
            capture_payload_error(CAPTURE_PROBE_DNS);
            entry.discard(0);
            return Ok(0);
        }
        (*ev).captured_at_boot_ns = captured_at_boot_ns;
        (*ev).capture_decision = capture_decision;
    }
    submit_accounted(entry, PIPELINE_RING_DNS);
    Ok(0)
}

// ---- file opened (sys_enter_open/openat/openat2) ----
// Write/rw opens retain their existing path. Read-only opens are a separate, default-off signal
// selected only by an exact Agent Runtime/Root capture profile before path copy or Ring reserve.

#[tracepoint]
pub fn file_open(ctx: TracePointContext) -> u32 {
    try_openat(&ctx).unwrap_or(0)
}

#[tracepoint]
pub fn file_openat2(ctx: TracePointContext) -> u32 {
    try_openat2(&ctx).unwrap_or(0)
}

#[tracepoint]
pub fn file_open_legacy(ctx: TracePointContext) -> u32 {
    try_open_legacy(&ctx).unwrap_or(0)
}

fn try_openat(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_openat: dfd @16, filename @24, flags @32, mode @40.
    let flags: u64 = unsafe { ctx.read_at(32)? };
    let filename: *const u8 = unsafe { ctx.read_at(24)? };
    try_open_common(flags, filename)
}

fn try_openat2(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_openat2: dfd @16, filename @24, open_how* @32, usize @40.
    // open_how.flags is the first u64. Reading only that fixed field keeps policy selection ahead
    // of path copy and Ring reservation just like openat.
    let filename: *const u8 = unsafe { ctx.read_at(24)? };
    let how: *const u8 = unsafe { ctx.read_at(32)? };
    if how.is_null() {
        return Ok(0);
    }
    let Some(flags) = read_user_u64(how) else {
        capture_payload_error(CAPTURE_PROBE_FILE_ACCESS);
        return Ok(0);
    };
    try_open_common(flags, filename)
}

fn try_open_legacy(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_open: filename @16, flags @24, mode @32. This tracepoint is absent on some
    // architectures and is therefore attached as a non-fatal compatibility probe.
    let filename: *const u8 = unsafe { ctx.read_at(16)? };
    let flags: u64 = unsafe { ctx.read_at(24)? };
    try_open_common(flags, filename)
}

fn try_open_common(flags: u64, filename: *const u8) -> Result<u32, i64> {
    let access_mode = file_access_mode(flags as u32);
    if access_mode == FILE_ACCESS_MODE_PATH_ONLY
        || access_mode == FILE_ACCESS_MODE_SPECIAL
        || access_mode == FILE_ACCESS_MODE_UNKNOWN
    {
        return Ok(0);
    }
    let read_only = access_mode == FILE_ACCESS_MODE_READ_ONLY;
    // Legacy capture intentionally keeps the historical global read-off behavior. Selective reads
    // require an atomically loaded S5 profile/Root map and never fail open on a map miss.
    if read_only && !capture_profile_enabled() {
        return Ok(0);
    }
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // Decide before reserving ring space or copying the userspace path. This is the load-shedding
    // boundary: explicit non-Agent traffic and over-budget Unknown traffic never enter the ring.
    let capture_profile_active = capture_profile_enabled();
    let capture_decision = if capture_profile_active {
        capture_raw_decision(
            if read_only {
                CAPTURE_PROBE_FILE_READ
            } else {
                CAPTURE_PROBE_FILE_ACCESS
            },
            cgroup_id,
            pid,
            0,
            access_mode,
        )
    } else {
        legacy_file_access_decision(cgroup_id)
    };
    if !capture_decision.selected() {
        return Ok(0);
    }
    if capture_profile_active {
        capture_payload_candidate(if read_only {
            CAPTURE_PROBE_FILE_READ
        } else {
            CAPTURE_PROBE_FILE_ACCESS
        });
    }
    let captured_at_boot_ns = unsafe { bpf_ktime_get_ns() };
    if filename.is_null() {
        capture_payload_error(if read_only {
            CAPTURE_PROBE_FILE_READ
        } else {
            CAPTURE_PROBE_FILE_ACCESS
        });
        return Ok(0);
    }
    let Some(mut entry) = (if read_only {
        reserve_or_drop::<FileEvent>(&FILE_READ_EVENTS, PIPELINE_RING_FILE_READ)
    } else {
        reserve_file_or_drop(&FILE_EVENTS, false)
    }) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = cgroup_id;
        (*ev).pid = pid;
        (*ev).flags = flags as u32;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        (*ev).path = [0u8; PATH_SNAP_LEN];
        if bpf_probe_read_user_str_bytes(filename, &mut (*ev).path).is_err() {
            capture_payload_error(if read_only {
                CAPTURE_PROBE_FILE_READ
            } else {
                CAPTURE_PROBE_FILE_ACCESS
            });
            entry.discard(0);
            return Ok(0);
        }
        (*ev).captured_at_boot_ns = captured_at_boot_ns;
        (*ev).capture_decision = capture_decision;
    }
    submit_accounted(
        entry,
        if read_only {
            PIPELINE_RING_FILE_READ
        } else {
            PIPELINE_RING_FILE_ACCESS
        },
    );
    Ok(0)
}

// ---- file deleted (sys_enter_unlinkat) — the "which files did the agent destroy" signal ----

#[tracepoint]
pub fn file_unlink(ctx: TracePointContext) -> u32 {
    try_unlink(&ctx).unwrap_or(0)
}

#[tracepoint]
pub fn file_unlink_legacy(ctx: TracePointContext) -> u32 {
    try_unlink_legacy(&ctx).unwrap_or(0)
}

fn try_unlink(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_unlinkat: dfd @16, pathname @24, flag @32.
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let capture_profile_active = capture_profile_enabled();
    let capture_decision = if capture_profile_active {
        capture_raw_decision(CAPTURE_PROBE_FILE_DELETE, cgroup_id, pid, 0, 0)
    } else {
        legacy_file_delete_decision(cgroup_id)
    };
    if !capture_decision.selected() {
        return Ok(0);
    }
    if capture_profile_active {
        capture_payload_candidate(CAPTURE_PROBE_FILE_DELETE);
    }
    let pathname: *const u8 = match unsafe { ctx.read_at(24) } {
        Ok(pathname) => pathname,
        Err(error) => {
            capture_payload_error(CAPTURE_PROBE_FILE_DELETE);
            return Err(error);
        }
    };
    submit_file_delete(cgroup_id, pid, pathname, capture_decision)
}

fn try_unlink_legacy(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_unlink: pathname @16. glibc and language runtimes may use either unlink or
    // unlinkat, so both tracepoints must feed the same independently sized delete ring.
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let capture_profile_active = capture_profile_enabled();
    let capture_decision = if capture_profile_active {
        capture_raw_decision(CAPTURE_PROBE_FILE_DELETE, cgroup_id, pid, 0, 0)
    } else {
        legacy_file_delete_decision(cgroup_id)
    };
    if !capture_decision.selected() {
        return Ok(0);
    }
    if capture_profile_active {
        capture_payload_candidate(CAPTURE_PROBE_FILE_DELETE);
    }
    let pathname: *const u8 = match unsafe { ctx.read_at(16) } {
        Ok(pathname) => pathname,
        Err(error) => {
            capture_payload_error(CAPTURE_PROBE_FILE_DELETE);
            return Err(error);
        }
    };
    submit_file_delete(cgroup_id, pid, pathname, capture_decision)
}

#[inline(always)]
fn submit_file_delete(
    cgroup_id: u64,
    pid: u32,
    pathname: *const u8,
    capture_decision: CaptureDecisionContext,
) -> Result<u32, i64> {
    let captured_at_boot_ns = unsafe { bpf_ktime_get_ns() };
    let Some(mut entry) = reserve_file_or_drop(&FILE_DELETE_EVENTS, true) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = cgroup_id;
        (*ev).pid = pid;
        (*ev).flags = FILE_DELETE_FLAG;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        (*ev).path = [0u8; PATH_SNAP_LEN];
        if bpf_probe_read_user_str_bytes(pathname, &mut (*ev).path).is_err() {
            capture_payload_error(CAPTURE_PROBE_FILE_DELETE);
            entry.discard(0);
            return Ok(0);
        }
        (*ev).captured_at_boot_ns = captured_at_boot_ns;
        (*ev).capture_decision = capture_decision;
    }
    submit_accounted(entry, PIPELINE_RING_FILE_DELETE);
    Ok(0)
}

// ---- LLM-call metrics: response bytes + TTFT (read/recv enter+exit), flush on close ----
// Response side needs the byte count, which is the syscall *return* value (exit), but the
// fd is only on enter — so enter stashes the fd (for tracked sockets only) and exit reads it.

#[tracepoint]
pub fn read_enter(ctx: TracePointContext) -> u32 {
    on_read_enter(&ctx)
}

#[tracepoint]
pub fn recv_enter(ctx: TracePointContext) -> u32 {
    on_read_enter(&ctx)
}

#[tracepoint]
pub fn read_exit(ctx: TracePointContext) -> u32 {
    on_read_exit(&ctx)
}

#[tracepoint]
pub fn recv_exit(ctx: TracePointContext) -> u32 {
    on_read_exit(&ctx)
}

fn on_read_enter(ctx: &TracePointContext) -> u32 {
    // sys_enter_read / sys_enter_recvfrom: fd @16, destination buffer @24.
    let Ok(fd) = (unsafe { ctx.read_at::<u64>(16) }) else {
        return 0;
    };
    let tgid = bpf_get_current_pid_tgid();
    let key = sock_key((tgid >> 32) as u32, fd);
    // Stash only for tracked LLM sockets — keeps this node-wide hot path cheap.
    if unsafe { LLM_SOCKS.get(&key) }.is_some() {
        let _ = READ_FD.insert(&tgid, &(fd as u32), 0);
    }
    if unsafe { HTTP_SOCKS.get(&key) }.is_some() {
        if let Ok(buf) = unsafe { ctx.read_at::<u64>(24) } {
            if buf != 0 {
                let args = HttpReadArgs {
                    fd: fd as u32,
                    _pad: 0,
                    buf,
                    started_at_boot_ns: unsafe { bpf_ktime_get_ns() },
                };
                let _ = HTTP_READ_ARGS.insert(&tgid, &args, 0);
            }
        }
    }
    0
}

fn on_read_exit(ctx: &TracePointContext) -> u32 {
    let tgid = bpf_get_current_pid_tgid();
    // sys_exit_*: long ret @16 (bytes read; <=0 means error/EOF).
    let Ok(ret) = (unsafe { ctx.read_at::<i64>(16) }) else {
        return 0;
    };
    if ret <= 0 {
        let _ = READ_FD.remove(&tgid);
        let _ = HTTP_READ_ARGS.remove(&tgid);
        return 0;
    }
    let pid = (tgid >> 32) as u32;
    if let Some(value) = unsafe { READ_FD.get(&tgid) } {
        let fd = *value;
        let key = sock_key(pid, fd as u64);
        if let Some(stat) = LLM_SOCKS.get_ptr_mut(&key) {
            unsafe {
                (*stat).resp_bytes = (*stat).resp_bytes.saturating_add(ret as u64);
                if (*stat).first_resp_ns == 0 {
                    (*stat).first_resp_ns = bpf_ktime_get_ns();
                }
            }
        }
    }
    let _ = READ_FD.remove(&tgid);
    if let Some(value) = unsafe { HTTP_READ_ARGS.get(&tgid) } {
        let http_args = *value;
        let key = sock_key(pid, http_args.fd as u64);
        let route_kind = unsafe { HTTP_SOCKS.get(&key) }
            .copied()
            .unwrap_or(HTTP_PREFIX_UNKNOWN);
        if route_kind != HTTP_PREFIX_HTTP {
            let _ = HTTP_READ_ARGS.remove(&tgid);
            return 0;
        }
        let args = SslCallArgs {
            ssl_ptr: key,
            buf: http_args.buf,
            requested_len: ret as u64,
            result_len_ptr: 0,
            started_at_boot_ns: http_args.started_at_boot_ns,
            direction: TLS_PLAINTEXT_DIRECTION_READ,
            api_kind: TLS_PLAINTEXT_API_TCP,
            route_kind,
            _pad: [0; 5],
        };
        let _ = emit_tls_plaintext(args, ret as u64);
    }
    let _ = HTTP_READ_ARGS.remove(&tgid);
    0
}

#[tracepoint]
pub fn sock_close(ctx: TracePointContext) -> u32 {
    // sys_enter_close: unsigned int fd @16.
    let Ok(fd) = (unsafe { ctx.read_at::<u64>(16) }) else {
        return 0;
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let key = sock_key(pid, fd);
    let _ = HTTP_SOCKS.remove(&key);
    let Some(&stat) = (unsafe { LLM_SOCKS.get(&key) }) else {
        return 0; // not an LLM socket
    };
    let _ = LLM_SOCKS.remove(&key);
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let bytes = stat.req_bytes.saturating_add(stat.resp_bytes);
    let capture_decision = capture_raw_decision(CAPTURE_PROBE_LLM, cgroup_id, pid, bytes, 0);
    if !capture_decision.selected() {
        return 0;
    }
    capture_payload_candidate(CAPTURE_PROBE_LLM);
    if let Some(mut entry) = reserve_or_drop::<LlmEvent>(&LLM_EVENTS, PIPELINE_RING_LLM) {
        let now = unsafe { bpf_ktime_get_ns() };
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).cgroup_id = cgroup_id;
            (*ev).pid = pid;
            (*ev).fd = fd as u32;
            (*ev).req_bytes = stat.req_bytes;
            (*ev).resp_bytes = stat.resp_bytes;
            (*ev).latency_ns = now.saturating_sub(stat.start_ns);
            (*ev).ttft_ns = if stat.first_resp_ns > 0 {
                stat.first_resp_ns.saturating_sub(stat.start_ns)
            } else {
                0
            };
            (*ev).comm = bpf_get_current_comm().unwrap_or_default();
            (*ev).captured_at_boot_ns = now;
            (*ev).capture_decision = capture_decision;
        }
        submit_accounted(entry, PIPELINE_RING_LLM);
    }
    0
}

// ---- egress enforcement (cgroup/connect4) — the OPT-IN intervention mechanism ----
// Returns 1 = allow, 0 = deny (connect() then fails with EPERM). Denies only dest IPs in the
// externally-populated DENY_EGRESS map; fail-open on a miss. Only affects processes in the
// cgroup this program is attached to. See docs/enforcement.md.

#[cgroup_sock_addr(connect4)]
pub fn egress_guard(ctx: SockAddrContext) -> i32 {
    let ip = unsafe { u32::from_be((*ctx.sock_addr).user_ip4) };
    if unsafe { DENY_EGRESS.get(&ip) }.is_some() {
        return 0; // deny
    }
    1 // allow
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
