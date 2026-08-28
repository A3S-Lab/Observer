//! Types shared between the eBPF programs (kernel side) and the userspace collector.
//!
//! `no_std` + `repr(C)` plain-old-data so a value can cross the ring buffer unchanged.

#![no_std]

/// A process / tool execution, captured at `sys_enter_execve`.
///
/// Exec payloads are emitted as one header, zero or more argument chunks, and one end record.
/// Keeping each ring-buffer record small avoids the verifier/runtime failure caused by embedding
/// every argument in one large event while still allowing long shell commands to be reconstructed.
pub const ARGV_SLOTS: usize = 12;
pub const EXEC_ARG_CHUNK_LEN: usize = 128;
/// `bpf_probe_read_user_str` reserves one byte for NUL in every chunk.
pub const EXEC_ARG_CHUNK_PAYLOAD: usize = EXEC_ARG_CHUNK_LEN - 1;
pub const EXEC_MAX_CHUNKS: usize = 64;
pub const EXEC_MAX_ARGV_BYTES: usize = EXEC_ARG_CHUNK_PAYLOAD * EXEC_MAX_CHUNKS;

pub const EXEC_RECORD_HEADER: u8 = 1;
pub const EXEC_RECORD_ARG_CHUNK: u8 = 2;
pub const EXEC_RECORD_END: u8 = 3;
/// Emitted from `sched_process_exec` after the kernel successfully commits the exec.
pub const EXEC_RECORD_COMMIT: u8 = 4;

pub const EXEC_FLAG_ARGV_TRUNCATED: u8 = 1 << 0;
pub const EXEC_FLAG_ARGV_INCOMPLETE: u8 = 1 << 1;

/// Stable, low-cardinality indices for per-ring pipeline accounting.
///
/// Ring counters measure physical records crossing the kernel/userspace ABI. In particular, one
/// logical exec can submit several [`ExecRecord`] values, so consumers must not interpret the exec
/// ring's submitted count as a ToolExec event count.
pub const PIPELINE_RING_EXEC: u32 = 0;
pub const PIPELINE_RING_EXIT: u32 = 1;
pub const PIPELINE_RING_TLS: u32 = 2;
pub const PIPELINE_RING_CONNECT: u32 = 3;
pub const PIPELINE_RING_DNS: u32 = 4;
pub const PIPELINE_RING_FILE_ACCESS: u32 = 5;
pub const PIPELINE_RING_FILE_DELETE: u32 = 6;
pub const PIPELINE_RING_LLM: u32 = 7;
pub const PIPELINE_RING_SSL: u32 = 8;
pub const PIPELINE_RING_SECURITY: u32 = 9;
/// Agent-scoped read-only opens use a dedicated physical channel so repository scans cannot starve
/// write/delete/security evidence. Existing indices remain unchanged for rolling compatibility.
pub const PIPELINE_RING_FILE_READ: u32 = 10;
pub const PIPELINE_RING_COUNT: usize = 11;

/// Stable S5 capture-decision probe indices. These intentionally match the physical ring indices
/// where a probe has a ring, but the counters below use `decision_op` rather than physical-record
/// units. In particular, one Exec decision can still emit multiple [`ExecRecord`] values.
pub const CAPTURE_PROBE_EXEC: u8 = 0;
pub const CAPTURE_PROBE_EXIT: u8 = 1;
pub const CAPTURE_PROBE_TLS: u8 = 2;
pub const CAPTURE_PROBE_CONNECT: u8 = 3;
pub const CAPTURE_PROBE_DNS: u8 = 4;
pub const CAPTURE_PROBE_FILE_ACCESS: u8 = 5;
pub const CAPTURE_PROBE_FILE_DELETE: u8 = 6;
pub const CAPTURE_PROBE_LLM: u8 = 7;
pub const CAPTURE_PROBE_SSL: u8 = 8;
pub const CAPTURE_PROBE_SECURITY: u8 = 9;
pub const CAPTURE_PROBE_FILE_READ: u8 = 10;
pub const CAPTURE_PROBE_COUNT: usize = 11;

/// S5 capture actions. Numeric constants keep every byte value ABI-valid during rolling upgrades.
pub const CAPTURE_ACTION_UNSPECIFIED: u8 = 0;
pub const CAPTURE_ACTION_FULL: u8 = 1;
pub const CAPTURE_ACTION_AGGREGATE: u8 = 2;
pub const CAPTURE_ACTION_SAMPLE: u8 = 3;
pub const CAPTURE_ACTION_DROP: u8 = 4;
/// Optional high-volume signal was not enabled for this exact Runtime/Root. This is not an
/// identity judgment and does not require a destructive grant.
pub const CAPTURE_ACTION_NOT_ENABLED: u8 = 5;

pub const CAPTURE_PROFILE_UNKNOWN_DISCOVERY: u8 = 1;
pub const CAPTURE_PROFILE_AGENT_FULL: u8 = 2;
pub const CAPTURE_PROFILE_INVESTIGATION_FULL: u8 = 3;
pub const CAPTURE_PROFILE_SECURITY_FULL: u8 = 4;
pub const CAPTURE_PROFILE_BUSINESS_CONTEXT: u8 = 5;
pub const CAPTURE_PROFILE_INFRASTRUCTURE_AGGREGATE: u8 = 6;
pub const CAPTURE_PROFILE_SELF_HEALTH: u8 = 7;
/// Bounded investigation for a weak Agent candidate. It intentionally shares the safe Unknown
/// probe matrix while remaining a distinct control-plane/audit state.
pub const CAPTURE_PROFILE_PROBABLE_INVESTIGATION: u8 = 8;

pub const CAPTURE_MODE_LEGACY: u8 = 0;
pub const CAPTURE_MODE_SHADOW: u8 = 1;
pub const CAPTURE_MODE_ENFORCE: u8 = 2;

pub const CAPTURE_CONFIG_ENABLED: u8 = 1 << 0;
/// Set only after the same collector process durably ACKed the immediately preceding preview and
/// validated an activation grant fenced to its instance, host boot, publisher, intent and digest.
pub const CAPTURE_CONFIG_DESTRUCTIVE_GRANTED: u8 = 1 << 1;

pub const CAPTURE_PROFILE_FLAG_AGENT: u16 = 1 << 0;
pub const CAPTURE_PROFILE_FLAG_CONFLICT: u16 = 1 << 1;

pub const CAPTURE_PROMOTION_FLAG_ROOT: u32 = 1 << 0;
pub const CAPTURE_PROMOTION_FLAG_DESCENDANT: u32 = 1 << 1;
pub const CAPTURE_PROMOTION_FLAG_INVESTIGATION: u32 = 1 << 2;

/// Safe closed-set defaults used when the control plane names a profile without overriding every
/// probe. Protected lifecycle/security probes are always FULL. Unknown keeps non-content LLM
/// metadata for discovery but leaves TLS plaintext disabled; probable/confirmed Agent profiles
/// explicitly opt into plaintext content capture.
pub const fn capture_profile_default_actions(profile: u8) -> [u8; CAPTURE_PROBE_COUNT] {
    let full = CAPTURE_ACTION_FULL;
    let sample = CAPTURE_ACTION_SAMPLE;
    let aggregate = CAPTURE_ACTION_AGGREGATE;
    match profile {
        CAPTURE_PROFILE_AGENT_FULL | CAPTURE_PROFILE_INVESTIGATION_FULL => [full; 11],
        CAPTURE_PROFILE_SECURITY_FULL => [
            full,
            full,
            sample,
            full,
            sample,
            sample,
            full,
            full,
            CAPTURE_ACTION_NOT_ENABLED,
            full,
            CAPTURE_ACTION_NOT_ENABLED,
        ],
        CAPTURE_PROFILE_BUSINESS_CONTEXT
        | CAPTURE_PROFILE_INFRASTRUCTURE_AGGREGATE
        | CAPTURE_PROFILE_SELF_HEALTH => [
            full,
            full,
            aggregate,
            aggregate,
            aggregate,
            aggregate,
            sample,
            aggregate,
            CAPTURE_ACTION_NOT_ENABLED,
            full,
            CAPTURE_ACTION_NOT_ENABLED,
        ],
        CAPTURE_PROFILE_PROBABLE_INVESTIGATION => [
            full, full, sample, sample, sample, sample, sample, full, full, full, full,
        ],
        CAPTURE_PROFILE_UNKNOWN_DISCOVERY => [
            full,
            full,
            sample,
            sample,
            sample,
            sample,
            sample,
            full,
            CAPTURE_ACTION_NOT_ENABLED,
            full,
            CAPTURE_ACTION_NOT_ENABLED,
        ],
        _ => [
            full,
            full,
            sample,
            sample,
            sample,
            sample,
            sample,
            full,
            CAPTURE_ACTION_NOT_ENABLED,
            full,
            CAPTURE_ACTION_NOT_ENABLED,
        ],
    }
}

#[inline(always)]
pub const fn capture_probe_is_protected(probe: u8) -> bool {
    probe == CAPTURE_PROBE_EXEC || probe == CAPTURE_PROBE_EXIT || probe == CAPTURE_PROBE_SECURITY
}

/// Exact per-CPU share of one node-wide sample budget. Summing CPU ids `0..cpu_count` is exactly
/// `node_limit`, avoiding the `div_ceil * CPUs` over-admission common in per-CPU rate limiters.
pub const fn capture_cpu_sample_quota(node_limit: u32, cpu_count: u16, cpu: u32) -> u32 {
    let count = if cpu_count == 0 { 1 } else { cpu_count as u32 };
    if cpu >= count {
        return 0;
    }
    node_limit / count + if cpu < node_limit % count { 1 } else { 0 }
}

/// Partition a CPU's quota into a discovery-first reserve and a regular/emergency pool. Both are
/// shared by every non-protected probe, so cross-probe raw samples cannot multiply the node cap.
pub const fn capture_sample_partitions(quota: u32) -> (u32, u32) {
    if quota == 0 {
        return (0, 0);
    }
    let quarter = quota / 4;
    let first = if quarter == 0 { 1 } else { quarter };
    (first, quota - first)
}

/// Epoch-scoped physical-workload capture rule.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CaptureProfileKey {
    pub cgroup_id: u64,
    pub epoch: u64,
}

/// Kernel-effective and shadow-desired actions for one physical workload.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CaptureProfileValue {
    pub epoch: u64,
    pub expires_at_boot_ns: u64,
    pub actions: [u8; CAPTURE_PROBE_COUNT],
    pub desired_actions: [u8; CAPTURE_PROBE_COUNT],
    pub profile: u8,
    pub authority: u8,
    pub flags: u16,
    pub _reserved: [u8; 4],
}

/// Active S5 generation. A single array write atomically switches a completely populated epoch.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CaptureProfileConfig {
    pub active_epoch: u64,
    pub expires_at_boot_ns: u64,
    pub sample_window_ns: u64,
    pub investigation_ttl_ns: u64,
    pub sample_per_scope_limit: u32,
    /// Hard node budget divided exactly across `sample_cpu_count` CPUs in-kernel.
    pub sample_node_limit: u32,
    pub first_samples: u16,
    pub sample_cpu_count: u16,
    pub flags: u8,
    pub mode: u8,
    pub _reserved: [u8; 2],
}

impl CaptureProfileConfig {
    #[inline(always)]
    pub const fn enabled(&self) -> bool {
        self.flags & CAPTURE_CONFIG_ENABLED != 0
    }

    #[inline(always)]
    pub const fn destructive_granted(&self) -> bool {
        self.flags & CAPTURE_CONFIG_DESTRUCTIVE_GRANTED != 0
    }
}

/// Per-workload/probe state decides first-sample eligibility. Every admitted raw sample must also
/// consume the shared node-wide first/regular budget, so cardinality growth cannot bypass the hard
/// node cap.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CaptureSampleKey {
    pub cgroup_id: u64,
    pub epoch: u64,
    pub probe: u8,
    pub _reserved: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CaptureSampleWindow {
    pub started_at_boot_ns: u64,
    pub count: u32,
    pub _reserved: u32,
}

/// Exact cumulative aggregate key/value. The eBPF map is per-CPU; userspace sums CPUs then emits
/// deltas, preserving `(cgroup, probe, epoch)` context without high-cardinality metric labels.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct CaptureAggregateKey {
    pub cgroup_id: u64,
    pub epoch: u64,
    pub probe: u8,
    /// Effective action whose exact attempts are summarized (AGGREGATE, SAMPLE, or DROP).
    pub action: u8,
    /// Probe-specific closed-set qualifier (for example SSL request/response direction).
    pub qualifier: u8,
    /// Effective closed-set profile at decision time. This prevents a rule expiry from being
    /// attributed later to the profile that happened to share the same transport epoch.
    pub profile: u8,
    /// Effective authority at decision time (`0` for discovery/miss/stale).
    pub authority: u8,
    /// Closed-set rule disposition: miss, valid rule, or stale/expired.
    pub disposition: u8,
    pub _reserved: [u8; 2],
}

pub const CAPTURE_DISPOSITION_MISS: u8 = 0;
pub const CAPTURE_DISPOSITION_RULE: u8 = 1;
pub const CAPTURE_DISPOSITION_STALE: u8 = 2;

/// The raw payload was selected and submitted to its Ring Buffer.
pub const CAPTURE_DECISION_FLAG_SELECTED: u8 = 1 << 0;
/// Exec, Exit, or Security was forced to FULL by the protected-probe invariant.
pub const CAPTURE_DECISION_FLAG_PROTECTED: u8 = 1 << 1;
/// A root/descendant/investigation promotion forced the payload to FULL.
pub const CAPTURE_DECISION_FLAG_PROMOTED: u8 = 1 << 2;
/// Shadow mode observed the desired action but retained a FULL raw payload.
pub const CAPTURE_DECISION_FLAG_SHADOW: u8 = 1 << 3;
/// Aggregate-map degradation admitted this payload through the bounded emergency sample lane.
pub const CAPTURE_DECISION_FLAG_EMERGENCY_SAMPLE: u8 = 1 << 4;
/// S5 capture profiles were disabled and the legacy/default FULL path admitted the payload.
pub const CAPTURE_DECISION_FLAG_LEGACY: u8 = 1 << 5;

/// Decision metadata captured in-kernel at the same instant as Ring admission.
///
/// This is an additive fixed-size tail on every raw Ring record. `capture_epoch` remains a `u64`
/// in the kernel ABI; JSON exporters encode it as a decimal string so JavaScript readers cannot
/// round large epochs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaptureDecisionContext {
    pub capture_epoch: u64,
    pub capture_profile: u8,
    pub capture_action: u8,
    pub capture_authority: u8,
    pub capture_disposition: u8,
    pub flags: u8,
    pub _reserved: [u8; 3],
}

impl CaptureDecisionContext {
    #[inline(always)]
    pub const fn selected(self) -> bool {
        self.flags & CAPTURE_DECISION_FLAG_SELECTED != 0
    }
}

const _: [(); 16] = [(); core::mem::size_of::<CaptureDecisionContext>()];

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CaptureAggregateValue {
    pub count: u64,
    pub bytes: u64,
}

/// Generation-safe root/descendant promotion key and value.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CaptureProcessKey {
    pub pid: u32,
    pub _reserved: u32,
    pub epoch: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CapturePromotionValue {
    pub cgroup_id: u64,
    /// Zero is permitted only for a freshly forked child before its first committed exec.
    pub expected_exec_id: u64,
    pub root_exec_id: u64,
    pub expires_at_boot_ns: u64,
    pub root_pid: u32,
    pub flags: u32,
}

/// Cumulative low-cardinality S5 counters for one probe. Decision, payload and delivery layers
/// deliberately remain separate because their units differ for multi-record probes such as Exec.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CaptureProbeStats {
    pub attempted: u64,
    pub full_selected: u64,
    pub aggregate_selected: u64,
    pub sample_selected: u64,
    pub sample_rejected: u64,
    pub drop_selected: u64,
    pub not_enabled: u64,
    pub decision_error: u64,
    /// Supplemental probe/state failure counter; unlike `decision_error`, this is not a terminal
    /// decision outcome and therefore is not added to the decision conservation equation.
    pub probe_error: u64,
    /// Raw payload candidates selected before ring reservation (`single_record_candidate`).
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

const _: [(); 16] = [(); core::mem::size_of::<CaptureProfileKey>()];
const _: [(); 48] = [(); core::mem::size_of::<CaptureProfileValue>()];
const _: [(); 48] = [(); core::mem::size_of::<CaptureProfileConfig>()];
const _: [(); 24] = [(); core::mem::size_of::<CaptureSampleKey>()];
const _: [(); 16] = [(); core::mem::size_of::<CaptureSampleWindow>()];
const _: [(); 24] = [(); core::mem::size_of::<CaptureAggregateKey>()];
const _: [(); 16] = [(); core::mem::size_of::<CaptureAggregateValue>()];
const _: [(); 16] = [(); core::mem::size_of::<CaptureProcessKey>()];
const _: [(); 40] = [(); core::mem::size_of::<CapturePromotionValue>()];
const _: [(); 184] = [(); core::mem::size_of::<CaptureProbeStats>()];

/// Cumulative per-CPU counters for one physical ring-buffer channel.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RingPipelineStats {
    /// Reservations admitted to the ring. Every current probe submits an admitted reservation.
    pub submitted: u64,
    /// Reservations rejected because that ring had no capacity.
    pub dropped: u64,
}

const _: [(); 16] = [(); core::mem::size_of::<RingPipelineStats>()];

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecRecord {
    pub exec_id: u64,
    /// cgroup v2 kernfs id captured while the syscall is executing.
    pub cgroup_id: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub captured_bytes: u32,
    pub argc: u16,
    pub arg_index: u16,
    pub chunk_index: u16,
    pub data_len: u16,
    pub kind: u8,
    pub flags: u8,
    pub _pad: [u8; 2],
    pub comm: [u8; 16],
    /// Header: executable filename. Chunk: argument bytes. End: unused.
    pub data: [u8; EXEC_ARG_CHUNK_LEN],
    /// Preserves the old 192-byte ABI prefix before the additive event-time field.
    pub _event_time_pad: [u8; 4],
    /// `CLOCK_MONOTONIC` nanoseconds at capture. Header, argument chunks, and end records for one
    /// exec syscall share its entry time; the commit record uses the successful kernel commit time.
    pub captured_at_boot_ns: u64,
    /// S5/legacy selection captured before payload construction and Ring reservation.
    pub capture_decision: CaptureDecisionContext,
}

const _: [(); 216] = [(); core::mem::size_of::<ExecRecord>()];

/// A process exit (`sys_enter_exit_group`) — the other end of the tool lifecycle, carrying the
/// exit status so tool *outcomes* are visible (did the command succeed?), not just that it ran.
/// Captured via a `do_exit` kprobe, so it catches EVERY exit — clean exits and signal-kills
/// (crash / SIGKILL / OOM) alike.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub exit_code: u32, // exit() status (0 when terminated by a signal)
    pub signal: u32,    // terminating signal, 0 = clean exit (9 SIGKILL/OOM, 11 SIGSEGV crash, …)
    pub comm: [u8; 16],
    /// Makes the original 40-byte ABI prefix explicit before additive fields.
    pub _pad: u32,
    /// Successful exec generation captured in-kernel and retained until this process exits.
    /// Zero means no committed exec generation was available (for example, the process predates
    /// collector attachment or the bounded kernel map evicted its entry).
    pub exec_id: u64,
    /// `CLOCK_MONOTONIC` nanoseconds when `do_exit` observed the process exit.
    pub captured_at_boot_ns: u64,
    pub capture_decision: CaptureDecisionContext,
}

const _: [(); 72] = [(); core::mem::size_of::<ExitEvent>()];

/// The leading bytes of an outbound TLS ClientHello, captured at the send syscall.
///
/// The eBPF side only detects + copies (verifier-friendly); userspace parses the SNI
/// `server_name` out of `data[..len]` — language-agnostic LLM-provider identification
/// with no per-language uprobe.
pub const TLS_SNAP_LEN: usize = 512;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub fd: u32, // socket fd, for (pid,fd) correlation with ConnectEvent
    pub len: u16,
    pub _pad: u16,
    pub comm: [u8; 16], // in-kernel process name — reliable identity even if the proc exits
    pub data: [u8; TLS_SNAP_LEN],
    /// Preserves the old 552-byte ABI prefix before the additive event-time field.
    pub _event_time_pad: [u8; 4],
    /// `CLOCK_MONOTONIC` nanoseconds when the ClientHello was recognized.
    pub captured_at_boot_ns: u64,
    pub capture_decision: CaptureDecisionContext,
}

/// An outbound connection attempt (`sys_enter_connect`): which peer a process dialed.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub fd: u32,        // socket fd, keys the userspace (pid,fd)->peer join
    pub family: u16,    // AF_INET = 2, AF_INET6 = 10
    pub port: u16,      // host byte order
    pub addr: [u8; 16], // IPv4 in [0..4], IPv6 uses all 16
    pub comm: [u8; 16],
    /// Preserves the old 56-byte ABI prefix before the additive event-time field.
    pub _event_time_pad: [u8; 4],
    /// `CLOCK_MONOTONIC` nanoseconds when the connection attempt was captured.
    pub captured_at_boot_ns: u64,
    pub capture_decision: CaptureDecisionContext,
}

/// The leading bytes of an outbound DNS query (sendto to :53). Userspace parses the
/// question name → the hostname the process resolved. Queries have no name compression.
pub const DNS_SNAP_LEN: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub len: u16,
    pub _pad: u16,
    pub comm: [u8; 16],
    pub data: [u8; DNS_SNAP_LEN],
    /// `CLOCK_MONOTONIC` nanoseconds when the DNS query was captured.
    pub captured_at_boot_ns: u64,
    pub capture_decision: CaptureDecisionContext,
}

/// A file opened through an enabled access-mode path. Userspace reads the path from `data`.
pub const PATH_SNAP_LEN: usize = 256;

pub const FILE_ACCESS_MODE_UNKNOWN: u8 = 0;
pub const FILE_ACCESS_MODE_READ_ONLY: u8 = 1;
pub const FILE_ACCESS_MODE_WRITE_ONLY: u8 = 2;
pub const FILE_ACCESS_MODE_READ_WRITE: u8 = 3;
pub const FILE_ACCESS_MODE_PATH_ONLY: u8 = 4;
pub const FILE_ACCESS_MODE_SPECIAL: u8 = 5;

const LINUX_O_ACCMODE: u32 = 0x3;
const LINUX_O_PATH: u32 = 0x20_0000;

/// Classify Linux open flags without treating `O_RDONLY` as a presence bit (`O_RDONLY == 0`).
#[inline(always)]
pub const fn file_access_mode(flags: u32) -> u8 {
    if flags & LINUX_O_PATH != 0 {
        return FILE_ACCESS_MODE_PATH_ONLY;
    }
    match flags & LINUX_O_ACCMODE {
        0 => FILE_ACCESS_MODE_READ_ONLY,
        1 => FILE_ACCESS_MODE_WRITE_ONLY,
        2 => FILE_ACCESS_MODE_READ_WRITE,
        3 => FILE_ACCESS_MODE_SPECIAL,
        _ => FILE_ACCESS_MODE_UNKNOWN,
    }
}

/// File-observation actions shared by the userspace rule loader and the eBPF hot path.
///
/// These are numeric rather than Rust enums because every possible byte value must remain a valid
/// map value if userspace and kernel programs are upgraded independently.
pub const FILE_FILTER_ACTION_UNSPECIFIED: u8 = 0;
pub const FILE_FILTER_ACTION_KEEP: u8 = 1;
pub const FILE_FILTER_ACTION_SAMPLE: u8 = 2;
pub const FILE_FILTER_ACTION_DROP: u8 = 3;

pub const FILE_FILTER_AUTHORITY_UNSPECIFIED: u8 = 0;
pub const FILE_FILTER_AUTHORITY_CANDIDATE: u8 = 1;
pub const FILE_FILTER_AUTHORITY_AUTHORITATIVE: u8 = 2;

pub const FILE_FILTER_CONFIG_ENABLED: u8 = 1 << 0;
/// Compatibility-only bounded sampling for unresolved FileAccess. When this flag is absent,
/// Unknown, stale, conflicting, and map-miss events are kept in full.
pub const FILE_FILTER_CONFIG_UNKNOWN_SAMPLE: u8 = 1 << 1;

/// One epoch-scoped cgroup lookup key. Including the epoch makes rule replacement atomic: userspace
/// can populate the next generation completely, switch one config value, and only then delete the
/// old generation.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileFilterKey {
    pub cgroup_id: u64,
    pub epoch: u64,
}

/// One userspace-approved decision for a physical cgroup.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileFilterValue {
    pub action: u8,
    pub authority: u8,
    pub flags: u16,
    pub _reserved: u32,
    pub epoch: u64,
    /// CLOCK_MONOTONIC nanoseconds. Zero means no expiry, although the v1 JSON loader always sets it.
    pub expires_at_boot_ns: u64,
}

/// Kernel-side sampling and active-generation configuration.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileFilterConfig {
    pub active_epoch: u64,
    pub sample_window_ns: u64,
    pub unknown_per_cgroup_limit: u32,
    /// Per-CPU share of the node-wide limit; userspace derives it from the machine CPU count.
    pub unknown_per_cpu_limit: u32,
    pub flags: u8,
    pub _reserved: [u8; 7],
}

impl FileFilterConfig {
    #[inline(always)]
    pub const fn enabled(&self) -> bool {
        self.flags & FILE_FILTER_CONFIG_ENABLED != 0
    }

    #[inline(always)]
    pub const fn unknown_sampling_enabled(&self) -> bool {
        self.flags & FILE_FILTER_CONFIG_UNKNOWN_SAMPLE != 0
    }
}

/// Fixed-window state used by the bounded Unknown sampler.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileFilterSampleWindow {
    pub started_at_boot_ns: u64,
    pub count: u32,
    pub _reserved: u32,
}

/// Cumulative prefilter and per-file-ring counters. A per-CPU map avoids synchronization in the
/// syscall hot path; userspace sums the values for heartbeat reporting.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileFilterStats {
    pub access_kept: u64,
    /// Subset of `access_kept` retained because no authoritative identity decision was available.
    pub access_unknown_kept: u64,
    pub access_sampled: u64,
    pub access_dropped: u64,
    pub access_sample_suppressed: u64,
    pub delete_kept: u64,
    /// Subset of `delete_kept` retained by FileDelete's fail-open Unknown semantics.
    pub delete_unknown_kept: u64,
    pub delete_dropped: u64,
    pub rule_hits: u64,
    pub rule_misses: u64,
    pub stale_rules: u64,
    pub access_ring_dropped: u64,
    pub delete_ring_dropped: u64,
}

/// Future Host ProcessTree key. The v1 filter deliberately does not enforce this map; it exists so
/// a later shadow implementation can add PID-generation-aware lookup without changing the value ABI.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileProcessFilterKey {
    pub tgid: u32,
    pub _reserved: u32,
    pub epoch: u64,
}

const _: [(); 16] = [(); core::mem::size_of::<FileFilterKey>()];
const _: [(); 24] = [(); core::mem::size_of::<FileFilterValue>()];
const _: [(); 32] = [(); core::mem::size_of::<FileFilterConfig>()];
const _: [(); 16] = [(); core::mem::size_of::<FileFilterSampleWindow>()];
const _: [(); 104] = [(); core::mem::size_of::<FileFilterStats>()];
const _: [(); 16] = [(); core::mem::size_of::<FileProcessFilterKey>()];

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub flags: u32,
    pub comm: [u8; 16],
    pub path: [u8; PATH_SNAP_LEN],
    /// `CLOCK_MONOTONIC` nanoseconds when the file operation was captured.
    pub captured_at_boot_ns: u64,
    pub capture_decision: CaptureDecisionContext,
}

/// `FileEvent.flags` sentinel marking a deletion (`unlinkat`) rather than an open — no real
/// `openat` flag combination equals `u32::MAX`, so userspace can tell them apart on one ring.
pub const FILE_DELETE_FLAG: u32 = u32::MAX;

/// Metrics for one LLM call, emitted when its TLS socket closes. Bytes/timing are
/// accumulated in-kernel per `(pid,fd)`; userspace joins this with the SNI/provider/peer it
/// recorded at ClientHello time to build the full `LlmCall`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LlmEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub fd: u32,
    pub req_bytes: u64,  // bytes written after ClientHello (approx request size)
    pub resp_bytes: u64, // bytes read back (approx response size)
    pub latency_ns: u64, // ClientHello → close
    pub ttft_ns: u64,    // ClientHello → first response byte; 0 = no response seen
    pub comm: [u8; 16],
    /// `CLOCK_MONOTONIC` nanoseconds when the tracked socket close produced this summary.
    pub captured_at_boot_ns: u64,
    pub capture_decision: CaptureDecisionContext,
}

/// A plaintext snapshot from a TLS connection, captured by **uprobes** on OpenSSL
/// `SSL_write` / `SSL_read` — the OPT-IN content extension (LLM prompt / completion bodies).
///
/// Legacy fixed-size OpenSSL snapshot. The versioned `TlsPlaintextEvent*` records below are the
/// authoritative interaction path and can also use exact fingerprinted static profiles (for
/// example a verified BoringSSL CLI build). Neither path generically covers Go `crypto/tls` or
/// Rustls. Plaintext remains **off by default** (`A3S_OBSERVER_SSL=1`) because it captures real
/// request/response content and therefore lives outside the universal core.
pub const SSL_SNAP_LEN: usize = 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SslEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub is_read: u32, // 0 = SSL_write (request / prompt), 1 = SSL_read (response / completion)
    pub len: u32,     // bytes captured into `data` (<= SSL_SNAP_LEN)
    pub comm: [u8; 16],
    pub data: [u8; SSL_SNAP_LEN],
    /// Preserves the old 1064-byte ABI prefix before the additive event-time field.
    pub _event_time_pad: [u8; 4],
    /// `CLOCK_MONOTONIC` nanoseconds when the plaintext snapshot was captured.
    pub captured_at_boot_ns: u64,
    pub capture_decision: CaptureDecisionContext,
}

/// Versioned binary plaintext record emitted by TLS-library uprobes and plain-HTTP socket probes.
/// The common header is followed by one of three fixed-capacity payload tiers. Userspace must use
/// `captured_len` rather than the ring-record size; bytes beyond it are uninitialized ring memory.
pub const TLS_PLAINTEXT_ABI_V1: u16 = 1;
pub const TLS_PLAINTEXT_TIER_SMALL: usize = 16 * 1024;
pub const TLS_PLAINTEXT_TIER_MEDIUM: usize = 128 * 1024;
pub const TLS_PLAINTEXT_TIER_LARGE: usize = 512 * 1024;

pub const TLS_PLAINTEXT_DIRECTION_WRITE: u8 = 0;
pub const TLS_PLAINTEXT_DIRECTION_READ: u8 = 1;

pub const TLS_PLAINTEXT_API_SSL_CLASSIC: u8 = 1;
pub const TLS_PLAINTEXT_API_SSL_EX: u8 = 2;
pub const TLS_PLAINTEXT_API_GNUTLS: u8 = 3;
pub const TLS_PLAINTEXT_API_NSS: u8 = 4;
pub const TLS_PLAINTEXT_API_TCP: u8 = 5;
pub const TLS_PLAINTEXT_API_RUSTLS: u8 = 6;

pub const TLS_PLAINTEXT_FLAG_TRUNCATED: u16 = 1 << 0;
pub const TLS_PLAINTEXT_FLAG_COPY_ERROR: u16 = 1 << 1;
pub const TLS_PLAINTEXT_FLAG_CONNECTION_UNBOUND: u16 = 1 << 2;
pub const TLS_PLAINTEXT_FLAG_TOOL_ROUTE: u16 = 1 << 3;
pub const PLAINTEXT_HTTP_ROUTE_LLM: u8 = 1;
pub const PLAINTEXT_HTTP_ROUTE_TOOL: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsPlaintextEventHeader {
    pub abi_version: u16,
    pub header_len: u16,
    pub flags: u16,
    pub _pad0: u16,
    pub cgroup_id: u64,
    pub pid: u32,
    pub tid: u32,
    /// `SSL*`/TLS-session pointer, or a stable socket-derived key for plain HTTP.
    pub connection_id: u64,
    /// Monotonic sequence within `(pid, connection_id, direction)`.
    pub call_seq: u64,
    /// Actual successful bytes reported by the TLS/TCP API before the bounded copy.
    pub original_len: u32,
    /// Bytes copied into this record's payload tier.
    pub captured_len: u32,
    pub direction: u8,
    pub api_kind: u8,
    pub _pad1: [u8; 6],
    pub call_started_at_boot_ns: u64,
    pub captured_at_boot_ns: u64,
    pub comm: [u8; 16],
    pub capture_decision: CaptureDecisionContext,
}

#[repr(C)]
pub struct TlsPlaintextEventSmall {
    pub header: TlsPlaintextEventHeader,
    pub data: [u8; TLS_PLAINTEXT_TIER_SMALL],
}

#[repr(C)]
pub struct TlsPlaintextEventMedium {
    pub header: TlsPlaintextEventHeader,
    pub data: [u8; TLS_PLAINTEXT_TIER_MEDIUM],
}

#[repr(C)]
pub struct TlsPlaintextEventLarge {
    pub header: TlsPlaintextEventHeader,
    pub data: [u8; TLS_PLAINTEXT_TIER_LARGE],
}

/// A security-sensitive action — rare and high-signal, filtered in-kernel so volume stays near
/// zero. One event/ring covers several syscalls (privilege escalation, process injection, opening
/// a listening port) instead of a probe-per-syscall sprawl — keeps the model + ring count bounded.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SecEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub kind: u32,   // SEC_* below
    pub detail: u64, // SEC_SETUID: 0 (escalated-to uid) · SEC_PTRACE: target pid · SEC_BIND: port
    pub comm: [u8; 16],
    /// `CLOCK_MONOTONIC` nanoseconds when the security-sensitive action was captured.
    pub captured_at_boot_ns: u64,
    pub capture_decision: CaptureDecisionContext,
}

pub const SEC_SETUID: u32 = 1; // setuid/setresuid → euid 0 from a non-root caller (privesc)
pub const SEC_PTRACE: u32 = 2; // ptrace(ATTACH|SEIZE) of another process (injection)
pub const SEC_BIND: u32 = 3; // bind() to a fixed (non-ephemeral) port (opened a listener)

#[cfg(test)]
mod tests {
    use super::{
        capture_cpu_sample_quota, capture_profile_default_actions, capture_sample_partitions,
        file_access_mode, CaptureAggregateKey, CaptureAggregateValue, CaptureDecisionContext,
        CaptureProbeStats, CaptureProcessKey, CaptureProfileConfig, CaptureProfileKey,
        CaptureProfileValue, CapturePromotionValue, CaptureSampleKey, CaptureSampleWindow,
        ConnectEvent, DnsEvent, ExecRecord, ExitEvent, FileEvent, FileFilterConfig, LlmEvent,
        RingPipelineStats, SecEvent, SslEvent, TlsEvent, CAPTURE_ACTION_FULL,
        CAPTURE_ACTION_NOT_ENABLED, CAPTURE_ACTION_SAMPLE, CAPTURE_DECISION_FLAG_SELECTED,
        CAPTURE_PROBE_CONNECT, CAPTURE_PROBE_DNS, CAPTURE_PROBE_EXEC, CAPTURE_PROBE_EXIT,
        CAPTURE_PROBE_FILE_ACCESS, CAPTURE_PROBE_FILE_DELETE, CAPTURE_PROBE_FILE_READ,
        CAPTURE_PROBE_LLM, CAPTURE_PROBE_SECURITY, CAPTURE_PROBE_SSL, CAPTURE_PROBE_TLS,
        CAPTURE_PROFILE_AGENT_FULL, CAPTURE_PROFILE_BUSINESS_CONTEXT,
        CAPTURE_PROFILE_INVESTIGATION_FULL, CAPTURE_PROFILE_PROBABLE_INVESTIGATION,
        CAPTURE_PROFILE_SECURITY_FULL, CAPTURE_PROFILE_UNKNOWN_DISCOVERY,
        FILE_ACCESS_MODE_PATH_ONLY, FILE_ACCESS_MODE_READ_ONLY, FILE_ACCESS_MODE_READ_WRITE,
        FILE_ACCESS_MODE_SPECIAL, FILE_ACCESS_MODE_WRITE_ONLY, FILE_FILTER_CONFIG_ENABLED,
        FILE_FILTER_CONFIG_UNKNOWN_SAMPLE, PIPELINE_RING_CONNECT, PIPELINE_RING_COUNT,
        PIPELINE_RING_DNS, PIPELINE_RING_EXEC, PIPELINE_RING_EXIT, PIPELINE_RING_FILE_ACCESS,
        PIPELINE_RING_FILE_DELETE, PIPELINE_RING_FILE_READ, PIPELINE_RING_LLM,
        PIPELINE_RING_SECURITY, PIPELINE_RING_SSL, PIPELINE_RING_TLS,
    };

    macro_rules! assert_additive_event_time_abi {
        ($event:ty, $legacy_size:expr, $new_size:expr) => {{
            assert_eq!(
                core::mem::offset_of!($event, captured_at_boot_ns),
                $legacy_size
            );
            assert_eq!(core::mem::size_of::<$event>(), $new_size);
            assert_eq!(
                core::mem::offset_of!($event, capture_decision),
                core::mem::offset_of!($event, captured_at_boot_ns) + 8,
                "capture decision must remain an additive tail after event time"
            );
            assert!(
                core::mem::offset_of!($event, captured_at_boot_ns) >= $legacy_size,
                "event time must not overlap the legacy ABI prefix"
            );
        }};
    }

    macro_rules! assert_legacy_offsets {
        ($event:ty, { $($field:ident: $offset:expr),+ $(,)? }) => {{
            $(assert_eq!(core::mem::offset_of!($event, $field), $offset);)+
        }};
    }

    #[test]
    fn unknown_file_filter_policy_is_lossless_by_default() {
        let disabled = FileFilterConfig::default();
        assert!(!disabled.enabled());
        assert!(!disabled.unknown_sampling_enabled());

        let enabled = FileFilterConfig {
            flags: FILE_FILTER_CONFIG_ENABLED,
            ..FileFilterConfig::default()
        };
        assert!(enabled.enabled());
        assert!(!enabled.unknown_sampling_enabled());

        let compatibility = FileFilterConfig {
            flags: FILE_FILTER_CONFIG_ENABLED | FILE_FILTER_CONFIG_UNKNOWN_SAMPLE,
            ..FileFilterConfig::default()
        };
        assert!(compatibility.unknown_sampling_enabled());
    }

    #[test]
    fn capture_profile_abi_is_explicit_and_zero_initializable() {
        assert_eq!(core::mem::size_of::<CaptureProfileKey>(), 16);
        assert_eq!(core::mem::size_of::<CaptureProfileValue>(), 48);
        assert_eq!(core::mem::offset_of!(CaptureProfileValue, actions), 16);
        assert_eq!(
            core::mem::offset_of!(CaptureProfileValue, desired_actions),
            27
        );
        assert_eq!(core::mem::offset_of!(CaptureProfileValue, profile), 38);
        assert_eq!(core::mem::size_of::<CaptureProfileConfig>(), 48);
        assert_eq!(core::mem::offset_of!(CaptureProfileConfig, flags), 44);
        assert_eq!(core::mem::offset_of!(CaptureProfileConfig, mode), 45);
        assert_eq!(core::mem::size_of::<CaptureSampleKey>(), 24);
        assert_eq!(core::mem::size_of::<CaptureSampleWindow>(), 16);
        assert_eq!(core::mem::size_of::<CaptureAggregateKey>(), 24);
        assert_eq!(core::mem::offset_of!(CaptureAggregateKey, profile), 19);
        assert_eq!(core::mem::offset_of!(CaptureAggregateKey, disposition), 21);
        assert_eq!(core::mem::size_of::<CaptureAggregateValue>(), 16);
        assert_eq!(core::mem::size_of::<CaptureDecisionContext>(), 16);
        assert_eq!(core::mem::size_of::<CaptureProcessKey>(), 16);
        assert_eq!(core::mem::size_of::<CapturePromotionValue>(), 40);
        assert_eq!(core::mem::size_of::<CaptureProbeStats>(), 184);

        let value = CaptureProfileValue::default();
        assert_eq!(value.epoch, 0);
        assert_eq!(value.actions, [0; 11]);
        assert_eq!(value.desired_actions, [0; 11]);
        assert_eq!(value._reserved, [0; 4]);
        let config = CaptureProfileConfig::default();
        assert!(!config.enabled());
        assert!(!config.destructive_granted());
        let decision = CaptureDecisionContext {
            flags: CAPTURE_DECISION_FLAG_SELECTED,
            ..CaptureDecisionContext::default()
        };
        assert!(decision.selected());
    }

    #[test]
    fn capture_profile_default_matrix_preserves_safety_contract() {
        for profile in [
            CAPTURE_PROFILE_AGENT_FULL,
            CAPTURE_PROFILE_INVESTIGATION_FULL,
        ] {
            assert_eq!(
                capture_profile_default_actions(profile),
                [CAPTURE_ACTION_FULL; 11]
            );
        }

        let security = capture_profile_default_actions(CAPTURE_PROFILE_SECURITY_FULL);
        for probe in [
            CAPTURE_PROBE_EXEC,
            CAPTURE_PROBE_EXIT,
            CAPTURE_PROBE_CONNECT,
            CAPTURE_PROBE_FILE_DELETE,
            CAPTURE_PROBE_LLM,
            CAPTURE_PROBE_SECURITY,
        ] {
            assert_eq!(security[probe as usize], CAPTURE_ACTION_FULL);
        }
        for probe in [
            CAPTURE_PROBE_TLS,
            CAPTURE_PROBE_DNS,
            CAPTURE_PROBE_FILE_ACCESS,
        ] {
            assert_eq!(security[probe as usize], CAPTURE_ACTION_SAMPLE);
        }
        for probe in [CAPTURE_PROBE_SSL, CAPTURE_PROBE_FILE_READ] {
            assert_eq!(security[probe as usize], CAPTURE_ACTION_NOT_ENABLED);
        }

        let unknown = capture_profile_default_actions(CAPTURE_PROFILE_UNKNOWN_DISCOVERY);
        let probable = capture_profile_default_actions(CAPTURE_PROFILE_PROBABLE_INVESTIGATION);
        assert_eq!(
            probable[CAPTURE_PROBE_FILE_READ as usize],
            CAPTURE_ACTION_FULL
        );
        assert_eq!(probable[CAPTURE_PROBE_SSL as usize], CAPTURE_ACTION_FULL);
        assert_eq!(unknown[CAPTURE_PROBE_LLM as usize], CAPTURE_ACTION_FULL);
        assert_eq!(
            unknown[CAPTURE_PROBE_SSL as usize],
            CAPTURE_ACTION_NOT_ENABLED
        );
        assert_eq!(
            unknown[CAPTURE_PROBE_FILE_ACCESS as usize],
            CAPTURE_ACTION_SAMPLE
        );
        assert_eq!(
            unknown[CAPTURE_PROBE_FILE_DELETE as usize],
            CAPTURE_ACTION_SAMPLE
        );
        assert_eq!(
            unknown[CAPTURE_PROBE_FILE_READ as usize],
            CAPTURE_ACTION_NOT_ENABLED,
        );
        for probe in [
            CAPTURE_PROBE_EXEC,
            CAPTURE_PROBE_EXIT,
            CAPTURE_PROBE_SECURITY,
        ] {
            assert_eq!(unknown[probe as usize], CAPTURE_ACTION_FULL);
        }

        let business = capture_profile_default_actions(CAPTURE_PROFILE_BUSINESS_CONTEXT);
        assert_eq!(
            business[CAPTURE_PROBE_FILE_DELETE as usize],
            CAPTURE_ACTION_SAMPLE
        );
        assert_eq!(
            business[CAPTURE_PROBE_SECURITY as usize],
            CAPTURE_ACTION_FULL
        );
    }

    #[test]
    fn file_open_access_modes_are_closed_and_do_not_treat_readonly_as_a_bit() {
        assert_eq!(file_access_mode(0), FILE_ACCESS_MODE_READ_ONLY);
        assert_eq!(file_access_mode(1), FILE_ACCESS_MODE_WRITE_ONLY);
        assert_eq!(file_access_mode(2), FILE_ACCESS_MODE_READ_WRITE);
        assert_eq!(file_access_mode(3), FILE_ACCESS_MODE_SPECIAL);
        assert_eq!(file_access_mode(0x20_0000), FILE_ACCESS_MODE_PATH_ONLY);
        assert_eq!(file_access_mode(0x20_0000 | 2), FILE_ACCESS_MODE_PATH_ONLY);
    }

    #[test]
    fn node_sample_budget_is_exactly_partitioned_and_shared_across_probes() {
        for (node_limit, cpus) in [(1, 1), (7, 4), (1_000, 192), (65_535, 256)] {
            let mut sum = 0;
            for cpu in 0..u32::from(cpus) {
                let quota = capture_cpu_sample_quota(node_limit, cpus, cpu);
                sum += quota;
                let (first, regular) = capture_sample_partitions(quota);
                assert_eq!(first + regular, quota);
            }
            assert_eq!(sum, node_limit);
            assert_eq!(
                capture_cpu_sample_quota(node_limit, cpus, u32::from(cpus)),
                0
            );
        }

        // FIRST/GLOBAL are one shared bucket (map index 0), not ten independent per-probe buckets.
        // Therefore any mixture of the seven non-protected probes consumes this same total.
        let node_limit = 100u32;
        let admitted_by_probe = [17u32, 13, 11, 19, 7, 23, 10];
        assert_eq!(admitted_by_probe.iter().sum::<u32>(), node_limit);
        assert!(admitted_by_probe
            .iter()
            .all(|admitted| *admitted <= node_limit));
    }

    #[test]
    fn pipeline_ring_indices_are_unique_contiguous_and_abi_stable() {
        assert_eq!(core::mem::offset_of!(ExitEvent, cgroup_id), 0);
        assert_eq!(core::mem::offset_of!(ExitEvent, pid), 8);
        assert_eq!(core::mem::offset_of!(ExitEvent, exit_code), 12);
        assert_eq!(core::mem::offset_of!(ExitEvent, signal), 16);
        assert_eq!(core::mem::offset_of!(ExitEvent, comm), 20);
        assert_eq!(core::mem::offset_of!(ExitEvent, exec_id), 40);
        assert_additive_event_time_abi!(ExitEvent, 48, 72);
        assert_eq!(core::mem::size_of::<RingPipelineStats>(), 16);
        assert_eq!(
            [
                PIPELINE_RING_EXEC,
                PIPELINE_RING_EXIT,
                PIPELINE_RING_TLS,
                PIPELINE_RING_CONNECT,
                PIPELINE_RING_DNS,
                PIPELINE_RING_FILE_ACCESS,
                PIPELINE_RING_FILE_DELETE,
                PIPELINE_RING_LLM,
                PIPELINE_RING_SSL,
                PIPELINE_RING_SECURITY,
                PIPELINE_RING_FILE_READ,
            ],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        );
        assert_eq!(PIPELINE_RING_COUNT, 11);
    }

    #[test]
    fn event_time_is_strictly_additive_to_every_ring_record_abi() {
        // Exact pre-S4 sizes define the non-overlap boundary. Every legacy field offset is pinned:
        // changing an old prefix becomes a test failure even if the new total size still aligns.
        assert_additive_event_time_abi!(ExecRecord, 192, 216);
        assert_additive_event_time_abi!(ExitEvent, 48, 72);
        assert_additive_event_time_abi!(TlsEvent, 552, 576);
        assert_additive_event_time_abi!(ConnectEvent, 56, 80);
        assert_additive_event_time_abi!(DnsEvent, 288, 312);
        assert_additive_event_time_abi!(FileEvent, 288, 312);
        assert_additive_event_time_abi!(LlmEvent, 64, 88);
        assert_additive_event_time_abi!(SslEvent, 1064, 1088);
        assert_additive_event_time_abi!(SecEvent, 40, 64);

        assert_legacy_offsets!(ExecRecord, {
            exec_id: 0, cgroup_id: 8, pid: 16, ppid: 20, uid: 24, captured_bytes: 28,
            argc: 32, arg_index: 34, chunk_index: 36, data_len: 38, kind: 40, flags: 41,
            _pad: 42, comm: 44, data: 60, _event_time_pad: 188
        });
        assert_legacy_offsets!(ExitEvent, {
            cgroup_id: 0, pid: 8, exit_code: 12, signal: 16, comm: 20, _pad: 36, exec_id: 40
        });
        assert_legacy_offsets!(TlsEvent, {
            cgroup_id: 0, pid: 8, fd: 12, len: 16, _pad: 18, comm: 20, data: 36,
            _event_time_pad: 548
        });
        assert_legacy_offsets!(ConnectEvent, {
            cgroup_id: 0, pid: 8, fd: 12, family: 16, port: 18, addr: 20, comm: 36,
            _event_time_pad: 52
        });
        assert_legacy_offsets!(DnsEvent, {
            cgroup_id: 0, pid: 8, len: 12, _pad: 14, comm: 16, data: 32
        });
        assert_legacy_offsets!(FileEvent, {
            cgroup_id: 0, pid: 8, flags: 12, comm: 16, path: 32
        });
        assert_legacy_offsets!(LlmEvent, {
            cgroup_id: 0, pid: 8, fd: 12, req_bytes: 16, resp_bytes: 24, latency_ns: 32,
            ttft_ns: 40, comm: 48
        });
        assert_legacy_offsets!(SslEvent, {
            cgroup_id: 0, pid: 8, is_read: 12, len: 16, comm: 20, data: 36,
            _event_time_pad: 1060
        });
        assert_legacy_offsets!(SecEvent, {
            cgroup_id: 0, pid: 8, kind: 12, detail: 16, comm: 24
        });
    }
}
