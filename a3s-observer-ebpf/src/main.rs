#![no_std]
#![no_main]

use a3s_observer_common::{
    ConnectEvent, DnsEvent, ExecRecord, ExitEvent, FileEvent, LlmEvent, ProcessKernelIdentity,
    SecEvent, SslEventHeader, TlsEvent, ARGV_SLOTS, CONTENT_OPERATION_CODEX_RUSTLS_WRITE,
    CONTENT_OPERATION_CODEX_RUSTLS_WRITEV, CONTENT_OPERATION_NATIVE_STDIN_EOF,
    CONTENT_OPERATION_NATIVE_STDIN_READ, CONTENT_OPERATION_NATIVE_STDOUT_EOF,
    CONTENT_OPERATION_NATIVE_STDOUT_WRITE, DNS_SNAP_LEN, DROP_CONNECT, DROP_DNS, DROP_EXEC,
    DROP_EXIT, DROP_FILE, DROP_KIND_COUNT, DROP_LLM, DROP_SEC, DROP_SSL, DROP_TLS,
    EXEC_ARG_CHUNK_PAYLOAD, EXEC_COMPACT_ARG_LEN, EXEC_COMPACT_SLOTS, EXEC_FLAG_ARGV_INCOMPLETE,
    EXEC_FLAG_ARGV_TRUNCATED, EXEC_MAX_CHUNKS, EXEC_RECORD_ARG_CHUNK, EXEC_RECORD_COMMIT,
    EXEC_RECORD_COMPACT, EXEC_RECORD_END, EXEC_RECORD_HEADER, FILE_DELETE_FLAG, FILE_RENAME_FLAG,
    PATH_SNAP_LEN, SEC_BIND, SEC_PTRACE, SEC_SETUID, SSL_EVENT_SCHEMA_VERSION, SSL_FRAGMENT_LEN,
    SSL_LOOP_ITERATIONS, SSL_MAX_CAPTURE_LEN, SSL_OPERATION_READ, SSL_OPERATION_READ_EX,
    SSL_OPERATION_WRITE, SSL_OPERATION_WRITE_EX, SSL_OPERATION_WRITE_EX2, TLS_SNAP_LEN,
};
use aya_ebpf::{
    cty::c_void,
    helpers::gen::{bpf_probe_read_kernel as bpf_probe_read_kernel_raw, bpf_probe_read_user},
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_task_btf, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_loop,
        bpf_probe_read_kernel, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
        bpf_tail_call,
    },
    macros::{cgroup_sock_addr, kprobe, map, tracepoint, uprobe, uretprobe},
    maps::{
        ring_buf::RingBufEntry, Array, HashMap, LruHashMap, PerCpuArray, ProgramArray, RingBuf,
    },
    programs::{ProbeContext, RetProbeContext, SockAddrContext, TracePointContext},
    EbpfContext,
};

// Exec records are fixed at 224 B. Typical commands need one header, a few argument chunks and
// one end record; long argv values can use up to EXEC_MAX_CHUNKS records without inflating every
// short exec event.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(8 * 1024 * 1024, 0);

#[map]
static EXEC_META_EVENTS: RingBuf = RingBuf::with_byte_size(8 * 1024 * 1024, 0);

#[map]
static EXIT_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static TLS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

#[map]
static LLM_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// Security-sensitive actions (privesc / injection / open-port). In-kernel-filtered to the loud
// cases, so this stays near-empty — a small ring is plenty.
#[map]
static SEC_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// Count of events dropped because a ring was full — data-loss visibility under extreme load.
#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static DROPS_BY_KIND: PerCpuArray<u64> = PerCpuArray::with_max_entries(DROP_KIND_COUNT, 0);

#[map]
static EXEC_PART_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(6, 0);

#[map]
static EXEC_SCRATCH: PerCpuArray<ExecRecord> = PerCpuArray::with_max_entries(1, 0);

// Payload Fixture drops are tracked separately from the normal rings so the declared-load Gate
// cannot be hidden by, or falsely fail on, unrelated host activity.
#[map]
static SSL_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ParentRelation {
    pid: u32,
    _pad: u32,
    start_boottime_ns: u64,
}

// The fork relation is kept separate from parent pointers observed later at exec/exit.
#[map]
static PARENTS: LruHashMap<u32, ParentRelation> = LruHashMap::with_max_entries(65_536, 0);

// [enabled, group_leader offset, real_parent offset, start_boottime offset, pid offset].
// Offsets come from the running kernel's BTF; zero means explicitly degraded identity.
#[map]
static PROCESS_IDENTITY_CONFIG: Array<[u64; 5]> = Array::with_max_entries(1, 0);

// tgid -> latest syscall-entry capture. `sched_process_exec` consumes it only after a successful
// exec, so userspace can distinguish committed images from failed execve attempts.
#[map]
static EXEC_IDS: LruHashMap<u32, u64> = LruHashMap::with_max_entries(65_536, 0);

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

// Isolated-fixture OpenSSL content. Production leaves the gate at zero and never attaches these
// uprobes; the larger ring exists in the object but receives no payload records. Ring sizing:
// BPF_MAP_TYPE_RINGBUF is one ring shared by all CPUs (not per-CPU), and a worst-case burst is
// one max-size call = 16 MiB payload in 517 records of ~31.1 KiB (header included) ≈ 16.7 MiB.
// 32 MiB holds that burst plus concurrent response-side traffic while userspace drains.
#[map]
static SSL_EVENTS: RingBuf = RingBuf::with_byte_size(32 * 1024 * 1024, 0);

// Source-level payload gate. Metadata-only mode leaves this at zero and does not attach payload
// uprobes. The runtime Kill Switch also flips this value to zero before userspace drains the ring.
#[map]
static CONTENT_CAPTURE_ENABLED: Array<u32> = Array::with_max_entries(1, 0);

// Even an explicitly enabled Phase -1 fixture is limited to named target PIDs. This prevents a
// libssl uprobe from becoming an accidental host-wide plaintext collector.
#[map]
static CONTENT_CAPTURE_TARGETS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

// Runtime-only scope for Codex/rustls. When enabled, userspace has attached the Codex plaintext
// programs system-wide to one exact, canonical executable inode. Only processes executing that
// binary can hit those links; OpenSSL/native fixture probes continue to require the PID map.
#[map]
static CODEX_RUSTLS_EXACT_BINARY_ALL: Array<u32> = Array::with_max_entries(1, 0);

// Runtime-only scope for Claude/BoringSSL. Userspace only enables this after attaching the
// OpenSSL-compatible probes to an exact Claude ELF inode recognized by two independent byte
// signatures. Fixture mode leaves it at zero and continues to require explicit target PIDs.
#[map]
static CLAUDE_BORINGSSL_EXACT_BINARY_ALL: Array<u32> = Array::with_max_entries(1, 0);

// Runtime-only scope for kimi/OpenSSL. Userspace only enables this after attaching the
// OpenSSL-compatible probes to an exact kimi ELF inode whose SSL_write/SSL_read entry points
// were resolved from the binary's own ELF symbol table. Fixture mode leaves it at zero and
// continues to require explicit target PIDs.
#[map]
static KIMI_OPENSSL_EXACT_BINARY_ALL: Array<u32> = Array::with_max_entries(1, 0);

#[repr(C)]
struct SslScratch {
    header: SslEventHeader,
    data: [u8; SSL_FRAGMENT_LEN],
}

// This kernel rejects per-CPU values above 32 KiB. Keep the complete staging value under that
// boundary so an ABI constant change cannot produce bytecode that builds but fails map creation.
const _: () = assert!(core::mem::size_of::<SslScratch>() <= 32 * 1024);

// Variable-size ring records are staged in a per-CPU fragment buffer. Only the initialized
// header and the exact number of bytes returned by OpenSSL are emitted, so unused scratch bytes
// never leave BPF. Larger calls are emitted as a bounded sequence of these records.
#[map]
static SSL_SCRATCH: PerCpuArray<SslScratch> = PerCpuArray::with_max_entries(1, 0);

// Per-CPU staging of the in-flight fragmentation state between tail-call hops of
// `ssl_fragment_pump` (see emit_ssl).
#[map]
static SSL_PUMP_STASH: PerCpuArray<SslLoopContext> = PerCpuArray::with_max_entries(1, 0);

// Tail-call jump table holding the loaded `ssl_fragment_pump` program fd. Populated by the
// collector at load time and held open for the collector's lifetime: with the handle dropped,
// the slot no longer resolved at runtime and every bpf_tail_call fell through (the probe main
// frames and the pump treat fall-through as a drop).
#[map]
static SSL_FRAGMENT_PUMPS: ProgramArray = ProgramArray::with_max_entries(1, 0);

// Debug counters for the fragmentation pump (slot semantics in bump_ssl_pump_stat callers).
#[map]
static SSL_PUMP_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct SslCall {
    ssl_pointer: u64,
    buf: u64,
    requested_len: u64,
    written_len_pointer: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeInputCall {
    buffer: u64,
    requested_len: u64,
    fd: u32,
    _reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SslLoopContext {
    ssl_pointer: u64,
    buffer: u64,
    /// Bytes the fragment loop emits for this call: `min(true_len, SSL_MAX_CAPTURE_LEN)`. For an
    /// over-ceiling call the trailing truncated marker record carries the true length.
    original_len: u64,
    /// The call's actual byte count before ceiling clamping.
    true_len: u64,
    call_sequence: u64,
    observed_at_monotonic_ns: u64,
    fragment_offset: u64,
    cgroup_id: u64,
    pid: u32,
    tid: u32,
    operation: u8,
    failed: u8,
    _reserved: [u8; 6],
    comm: [u8; 16],
}

// SSL_write*/SSL_read* entry state by pid_tgid. Return probes know the actual number of bytes and
// only emit successfully transferred plaintext.
#[map]
static SSL_WRITE_CALLS: HashMap<u64, SslCall> = HashMap::with_max_entries(10240, 0);

#[map]
static SSL_READ_CALLS: HashMap<u64, SslCall> = HashMap::with_max_entries(10240, 0);

// Isolated-fixture stdin reads keyed by pid_tgid. These tracepoint programs are not attached in
// production metadata mode; the exact-PID map and global Kill Switch are still checked in-kernel.
#[map]
static NATIVE_STDIN_CALLS: HashMap<u64, NativeInputCall> = HashMap::with_max_entries(10240, 0);

// Isolated-fixture stdout writes. As with stdin, these programs are never attached in production
// metadata mode and remain guarded by the exact-PID target map plus the global Kill Switch.
#[map]
static NATIVE_STDOUT_CALLS: HashMap<u64, NativeInputCall> = HashMap::with_max_entries(10240, 0);

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
/// data loss instead of losing events silently).
fn reserve_or_drop<T>(ring: &RingBuf, kind: u32) -> Option<RingBufEntry<T>> {
    let entry = ring.reserve::<T>(0);
    if entry.is_none() {
        record_drop(kind);
    }
    entry
}

fn reserve_exec_or_drop<T>(ring: &RingBuf, record_kind: u8) -> Option<RingBufEntry<T>> {
    let entry = ring.reserve::<T>(0);
    if entry.is_none() {
        record_drop(DROP_EXEC);
        unsafe {
            if let Some(c) = EXEC_PART_DROPS.get_ptr_mut(record_kind as u32) {
                *c = (*c).wrapping_add(1);
            }
        }
    }
    entry
}

#[inline(always)]
fn record_drop(kind: u32) {
    unsafe {
        if let Some(c) = DROPS.get_ptr_mut(0) {
            *c = (*c).wrapping_add(1);
        }
        if kind < DROP_KIND_COUNT {
            if let Some(c) = DROPS_BY_KIND.get_ptr_mut(kind) {
                *c = (*c).wrapping_add(1);
            }
        }
    }
}

#[inline(always)]
fn record_ssl_drop() {
    record_drop(DROP_SSL);
    unsafe {
        if let Some(c) = SSL_DROPS.get_ptr_mut(0) {
            *c = (*c).wrapping_add(1);
        }
    }
}

// SSL_PUMP_STATS slots.
const PUMP_STASHED: u32 = 0;
const PUMP_TAILCALL_FAILED: u32 = 1;
const PUMP_STASH_UNAVAILABLE: u32 = 2;
const PUMP_ENTRIES: u32 = 3;
const PUMP_STASH_MISSING: u32 = 4;
const PUMP_LOOP_FAILED: u32 = 5;
const PUMP_RECHAINED: u32 = 6;
const PUMP_RECHAIN_FAILED: u32 = 7;
const PUMP_HOP_COMPLETED: u32 = 8;
const PUMP_EMIT_OUTPUT_FAILED: u32 = 9;
const PUMP_SCRATCH_UNAVAILABLE: u32 = 10;
const PUMP_PROBE_READ_FAILED: u32 = 11;
const PUMP_FASTPATH_CALLS: u32 = 12;
const PUMP_MARKER_SENT: u32 = 13;
const PUMP_FASTPATH_INCOMPLETE: u32 = 14;
const PUMP_CEILING_CLAMPED: u32 = 15;

#[inline(always)]
fn bump_ssl_pump_stat(slot: u32) {
    unsafe {
        if let Some(c) = SSL_PUMP_STATS.get_ptr_mut(slot) {
            *c = (*c).wrapping_add(1);
        }
    }
}

/// Issue the pump tail call from a probe main frame; on fall-through count the call as dropped.
/// Kept as a macro so the helper call lands textually in each probe main function: tail calls
/// from main frames are supported on every kernel, while bpf2bpf-subprogram tail calls depend on
/// JIT unwinding support — a risk class not worth taking on the payload path.
macro_rules! pump_tail_call_or_drop {
    ($ctx:expr) => {{
        unsafe {
            bpf_tail_call(
                $ctx,
                &SSL_FRAGMENT_PUMPS as *const ProgramArray as *mut c_void,
                0,
            );
        }
        bump_ssl_pump_stat(PUMP_TAILCALL_FAILED);
        record_ssl_drop();
        0
    }};
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

#[inline(always)]
unsafe fn init_exec_record(
    record: *mut ExecRecord,
    exec_id: u64,
    cgroup_id: u64,
    pid: u32,
    ppid: u32,
    uid: u32,
    comm: [u8; 16],
    identity: ProcessKernelIdentity,
) {
    (*record).exec_id = exec_id;
    (*record).identity = identity;
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
    identity: ProcessKernelIdentity,
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

    let Some(mut chunk_entry) = reserve_exec_or_drop::<ExecRecord>(&EVENTS, EXEC_RECORD_ARG_CHUNK)
    else {
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
        state.identity,
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
    chunk_entry.submit(0);
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

unsafe extern "C" fn capture_exec_compact(_iteration: u32, raw_ctx: *mut c_void) -> i64 {
    let state = &mut *(raw_ctx as *mut ExecLoopContext);
    if state.done != 0 {
        return 1;
    }
    if state.arg_index as usize >= EXEC_COMPACT_SLOTS {
        state.done = 2;
        return 1;
    }
    let Some(next_arg) = read_user_u64((state.argv as *const u8).add(state.arg_index as usize * 8))
    else {
        state.done = 2;
        return 1;
    };
    if next_arg == 0 {
        state.done = 1;
        return 1;
    }
    let mut value = [0u8; EXEC_ARG_CHUNK_PAYLOAD + 1];
    let len = match bpf_probe_read_user_str_bytes(next_arg as *const u8, &mut value) {
        Ok(bytes) => bytes.len(),
        Err(_) => {
            state.done = 2;
            return 1;
        }
    };
    if len >= EXEC_COMPACT_ARG_LEN {
        state.done = 2;
        return 1;
    }
    let slot = (state.arg_index as usize & (EXEC_COMPACT_SLOTS - 1)) * EXEC_COMPACT_ARG_LEN;
    let Some(scratch) = EXEC_SCRATCH.get_ptr_mut(0) else {
        state.done = 2;
        return 1;
    };
    let copy_len = core::cmp::min(len, EXEC_COMPACT_ARG_LEN - 1);
    if bpf_probe_read_kernel_raw(
        (*scratch).data.as_mut_ptr().add(slot) as *mut c_void,
        copy_len as u32,
        value.as_ptr() as *const c_void,
    ) < 0
    {
        state.done = 2;
        return 1;
    }
    (*scratch).data[slot + len] = 0;
    state.arg_offset += EXEC_COMPACT_ARG_LEN as u32;
    state.captured_bytes += len as u32;
    state.captured_argc += 1;
    state.arg_index += 1;
    0
}

fn exec_loop_context(
    argv: u64,
    exec_id: u64,
    cgroup_id: u64,
    pid: u32,
    ppid: u32,
    uid: u32,
    comm: [u8; 16],
    identity: ProcessKernelIdentity,
    flags: u8,
) -> ExecLoopContext {
    ExecLoopContext {
        argv,
        exec_id,
        cgroup_id,
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
        identity,
    }
}

// ---- process ancestry + tool exec ----

#[inline(always)]
unsafe fn task_pointer(task: *const u8, offset: u64) -> Result<*const u8, i64> {
    if offset == 0 || offset > 1024 * 1024 {
        return Err(-1);
    }
    bpf_probe_read_kernel(task.add(offset as usize) as *const *const u8)
}

#[inline(always)]
unsafe fn task_start_boottime_ns(task: *const u8, group_offset: u64, start_offset: u64) -> u64 {
    let Ok(leader) = task_pointer(task, group_offset) else {
        return 0;
    };
    if start_offset == 0 || start_offset > 1024 * 1024 {
        return 0;
    }
    bpf_probe_read_kernel(leader.add(start_offset as usize) as *const u64).unwrap_or(0)
}

#[inline(always)]
unsafe fn current_start_boottime_ns() -> u64 {
    let Some(config) = PROCESS_IDENTITY_CONFIG.get(0) else {
        return 0;
    };
    if config[0] != 1 {
        return 0;
    }
    task_start_boottime_ns(
        bpf_get_current_task_btf() as *const u8,
        config[1],
        config[3],
    )
}

#[inline(always)]
unsafe fn process_identity(pid: u32) -> ProcessKernelIdentity {
    let mut identity = ProcessKernelIdentity::default();
    if let Some(parent) = PARENTS.get(&pid) {
        identity.creation_ppid = parent.pid;
        identity.creation_parent_start_boottime_ns = parent.start_boottime_ns;
    }
    let Some(config) = PROCESS_IDENTITY_CONFIG.get(0) else {
        return identity;
    };
    if config[0] != 1 {
        return identity;
    }
    let task = bpf_get_current_task_btf() as *const u8;
    identity.start_boottime_ns = task_start_boottime_ns(task, config[1], config[3]);
    if let Ok(parent) = task_pointer(task, config[2]) {
        if config[4] > 0 && config[4] <= 1024 * 1024 {
            identity.observed_ppid =
                bpf_probe_read_kernel(parent.add(config[4] as usize) as *const u32).unwrap_or(0);
        }
        identity.observed_parent_start_boottime_ns =
            task_start_boottime_ns(parent, config[1], config[3]);
    }
    identity
}

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
        let relation = ParentRelation {
            pid: parent as u32,
            start_boottime_ns: unsafe { current_start_boottime_ns() },
            ..ParentRelation::default()
        };
        let _ = PARENTS.insert(&(child as u32), &relation, 0);
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
    let relation = ParentRelation {
        pid: parent,
        start_boottime_ns: unsafe { current_start_boottime_ns() },
        ..ParentRelation::default()
    };
    let _ = PARENTS.insert(&(child as u32), &relation, 0);
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
    let identity = unsafe { process_identity(pid) };
    let ppid = identity.creation_ppid;
    let comm = bpf_get_current_comm().unwrap_or_default();
    let exec_id = unsafe { bpf_ktime_get_ns() } ^ pid_tgid;
    let _ = EXEC_IDS.insert(&pid, &exec_id, 0);
    let argv = unsafe { ctx.read_at::<*const u8>(24) }.ok();
    let mut compact_complete = false;

    unsafe {
        if let Some(argv) = argv {
            if let Some(scratch) = EXEC_SCRATCH.get_ptr_mut(0) {
                init_exec_record(scratch, exec_id, cgroup_id, pid, ppid, uid, comm, identity);
                (*scratch).kind = EXEC_RECORD_COMPACT;
                let mut compact = exec_loop_context(
                    argv as u64,
                    exec_id,
                    cgroup_id,
                    pid,
                    ppid,
                    uid,
                    comm,
                    identity,
                    0,
                );
                let iterations = bpf_loop(
                    ARGV_SLOTS as u32 + 1,
                    capture_exec_compact as *mut c_void,
                    &mut compact as *mut ExecLoopContext as *mut c_void,
                    0,
                );
                if iterations >= 0 && compact.done == 1 {
                    (*scratch).argc = compact.captured_argc;
                    (*scratch).captured_bytes = compact.captured_bytes;
                    (*scratch).data_len = compact.arg_offset as u16;
                    if let Some(mut entry) =
                        reserve_exec_or_drop::<ExecRecord>(&EVENTS, EXEC_RECORD_COMPACT)
                    {
                        *entry.as_mut_ptr() = *scratch;
                        entry.submit(0);
                    }
                    compact_complete = true;
                }
            }
        }
    }

    if compact_complete {
        return Ok(0);
    }

    let mut flags = 0u8;
    let Some(mut header_entry) =
        reserve_exec_or_drop::<ExecRecord>(&EXEC_META_EVENTS, EXEC_RECORD_HEADER)
    else {
        return Ok(0);
    };
    let header = header_entry.as_mut_ptr();
    unsafe {
        init_exec_record(header, exec_id, cgroup_id, pid, ppid, uid, comm, identity);
        (*header).kind = EXEC_RECORD_HEADER;
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
    header_entry.submit(0);

    let captured_argc: u16;
    let captured_bytes: u32;
    unsafe {
        if let Some(argv) = argv {
            let mut loop_ctx = exec_loop_context(
                argv as u64,
                exec_id,
                cgroup_id,
                pid,
                ppid,
                uid,
                comm,
                identity,
                flags,
            );
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

        let Some(mut end_entry) =
            reserve_exec_or_drop::<ExecRecord>(&EXEC_META_EVENTS, EXEC_RECORD_END)
        else {
            return Ok(0);
        };
        let end = end_entry.as_mut_ptr();
        init_exec_record(end, exec_id, cgroup_id, pid, ppid, uid, comm, identity);
        (*end).kind = EXEC_RECORD_END;
        (*end).flags = flags;
        (*end).argc = captured_argc;
        (*end).captured_bytes = captured_bytes;
        end_entry.submit(0);
    }
    Ok(0)
}

/// Successful exec commit. Userspace correlates this small record with the bounded syscall-entry
/// fragments and can then read `/proc/<pid>/cmdline` while the committed image is still alive.
#[tracepoint]
pub fn track_process_exec(_ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let Some(exec_id) = (unsafe { EXEC_IDS.get(&pid).copied() }) else {
        return 0;
    };
    let uid = bpf_get_current_uid_gid() as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let identity = unsafe { process_identity(pid) };
    let ppid = identity.creation_ppid;
    let comm = bpf_get_current_comm().unwrap_or_default();
    if let Some(mut entry) =
        reserve_exec_or_drop::<ExecRecord>(&EXEC_META_EVENTS, EXEC_RECORD_COMMIT)
    {
        let record = entry.as_mut_ptr();
        unsafe {
            init_exec_record(record, exec_id, cgroup_id, pid, ppid, uid, comm, identity);
            (*record).kind = EXEC_RECORD_COMMIT;
        }
        entry.submit(0);
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
    let code: u64 = ctx.arg(0).unwrap_or(0);
    let pid = (id >> 32) as u32;
    if content_capture_allowed(pid) {
        emit_native_stdio_eof(id, 1, CONTENT_OPERATION_NATIVE_STDOUT_EOF);
    }
    let Some(mut entry) = reserve_or_drop::<ExitEvent>(&EXIT_EVENTS, DROP_EXIT) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = bpf_get_current_cgroup_id();
        (*ev).identity = process_identity(pid);
        (*ev).pid = (id >> 32) as u32;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        (*ev).exit_code = ((code >> 8) & 0xff) as u32;
        (*ev).signal = (code & 0x7f) as u32; // & 0x7f intentionally drops the 0x80 core-dump bit
    }
    entry.submit(0);
    let _ = PARENTS.remove(&pid);
    let _ = EXEC_IDS.remove(&pid);
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
    // New LLM call: start the metrics accumulator and emit the SNI snapshot.
    let _ = LLM_SOCKS.insert(
        &key,
        &LlmStat {
            start_ns: unsafe { bpf_ktime_get_ns() },
            first_resp_ns: 0,
            req_bytes: 0,
            resp_bytes: 0,
        },
        0,
    );
    let Some(mut entry) = reserve_or_drop::<TlsEvent>(&TLS_EVENTS, DROP_TLS) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = bpf_get_current_cgroup_id();
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
        let _ = bpf_probe_read_user(
            (*ev).data.as_mut_ptr() as *mut core::ffi::c_void,
            n,
            buf as *const core::ffi::c_void,
        );
    }
    entry.submit(0);
    Ok(0)
}

// ---- ISOLATED-FIXTURE OpenSSL content (uprobes on SSL_write* / SSL_read*) ----
//
// NOT language-agnostic and never attached in production metadata-only mode. Entry probes retain
// only pointers/limits; return probes emit bytes only after OpenSSL reports a successful transfer.

#[uprobe]
pub fn ssl_write_enter(ctx: ProbeContext) -> u32 {
    remember_ssl_call(&ctx, &SSL_WRITE_CALLS, 0)
}

#[uretprobe]
pub fn ssl_write_exit(ctx: RetProbeContext) -> u32 {
    if finish_ssl_call(&ctx, &SSL_WRITE_CALLS, SSL_OPERATION_WRITE, false) == EMIT_SSL_PUMP_PENDING
    {
        return pump_tail_call_or_drop!(ctx.as_ptr());
    }
    0
}

#[uprobe]
pub fn ssl_write_ex_enter(ctx: ProbeContext) -> u32 {
    remember_ssl_call(&ctx, &SSL_WRITE_CALLS, 3)
}

#[uretprobe]
pub fn ssl_write_ex_exit(ctx: RetProbeContext) -> u32 {
    if finish_ssl_call(&ctx, &SSL_WRITE_CALLS, SSL_OPERATION_WRITE_EX, true)
        == EMIT_SSL_PUMP_PENDING
    {
        return pump_tail_call_or_drop!(ctx.as_ptr());
    }
    0
}

#[uprobe]
pub fn ssl_write_ex2_enter(ctx: ProbeContext) -> u32 {
    // OpenSSL 3 SSL_write_ex2 adds `flags` before the output-length pointer.
    remember_ssl_call(&ctx, &SSL_WRITE_CALLS, 4)
}

#[uretprobe]
pub fn ssl_write_ex2_exit(ctx: RetProbeContext) -> u32 {
    if finish_ssl_call(&ctx, &SSL_WRITE_CALLS, SSL_OPERATION_WRITE_EX2, true)
        == EMIT_SSL_PUMP_PENDING
    {
        return pump_tail_call_or_drop!(ctx.as_ptr());
    }
    0
}

#[uprobe]
pub fn ssl_read_enter(ctx: ProbeContext) -> u32 {
    remember_ssl_call(&ctx, &SSL_READ_CALLS, 0)
}

#[uretprobe]
pub fn ssl_read_exit(ctx: RetProbeContext) -> u32 {
    if finish_ssl_call(&ctx, &SSL_READ_CALLS, SSL_OPERATION_READ, false) == EMIT_SSL_PUMP_PENDING {
        return pump_tail_call_or_drop!(ctx.as_ptr());
    }
    0
}

#[uprobe]
pub fn ssl_read_ex_enter(ctx: ProbeContext) -> u32 {
    remember_ssl_call(&ctx, &SSL_READ_CALLS, 3)
}

#[uretprobe]
pub fn ssl_read_ex_exit(ctx: RetProbeContext) -> u32 {
    if finish_ssl_call(&ctx, &SSL_READ_CALLS, SSL_OPERATION_READ_EX, true) == EMIT_SSL_PUMP_PENDING
    {
        return pump_tail_call_or_drop!(ctx.as_ptr());
    }
    0
}

// ---- Explicit-target Codex/rustls request plaintext ----
//
// Current Codex release binaries are statically linked and stripped, so there is no SSL_write
// symbol to attach to. Userspace scans the exact configured binary for supported rustls
// PlaintextSink signatures and attaches these programs by file offset and exact PID. Both the
// global Kill Switch and target map are rechecked here before any user memory is copied.

#[repr(C)]
#[derive(Clone, Copy)]
struct RustlsIoVec {
    base: u64,
    len: u64,
}

#[uprobe]
pub fn codex_rustls_write(ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    if !codex_content_capture_allowed(pid) {
        return 0;
    }
    let connection = ctx.arg::<u64>(0).unwrap_or(0);
    let buffer = ctx.arg::<u64>(1).unwrap_or(0);
    let length = ctx.arg::<u64>(2).unwrap_or(0);
    if emit_ssl(
        &EmitSslCall {
            ssl_pointer: connection,
            buf: buffer,
            len: length,
            operation: CONTENT_OPERATION_CODEX_RUSTLS_WRITE,
        },
        pid_tgid,
    ) == EMIT_SSL_PUMP_PENDING
    {
        return pump_tail_call_or_drop!(ctx.as_ptr());
    }
    0
}

#[uprobe]
pub fn codex_rustls_write_vectored(ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    if !codex_content_capture_allowed(pid) {
        return 0;
    }
    let connection = ctx.arg::<u64>(0).unwrap_or(0);
    let iovecs = ctx.arg::<u64>(1).unwrap_or(0);
    let iovec_count = ctx.arg::<u64>(2).unwrap_or(0);
    if connection == 0 || iovecs == 0 || iovec_count == 0 {
        return 0;
    }

    // rustls currently passes at most two slices on this path. Keep the verifier-visible bound
    // explicit; a larger count is intentionally truncated and userspace will mark the resulting
    // protocol message incomplete rather than inventing bytes.
    let count = if iovec_count > 2 { 2 } else { iovec_count };
    let mut index = 0u64;
    while index < count {
        let mut iovec = RustlsIoVec { base: 0, len: 0 };
        let source = (iovecs as *const RustlsIoVec).wrapping_add(index as usize);
        let read = unsafe {
            bpf_probe_read_user(
                &mut iovec as *mut RustlsIoVec as *mut core::ffi::c_void,
                core::mem::size_of::<RustlsIoVec>() as u32,
                source as *const core::ffi::c_void,
            )
        };
        if read < 0 {
            record_ssl_drop();
            break;
        }
        if iovec.base != 0 && iovec.len != 0 {
            if emit_ssl(
                &EmitSslCall {
                    ssl_pointer: connection,
                    buf: iovec.base,
                    len: iovec.len,
                    operation: CONTENT_OPERATION_CODEX_RUSTLS_WRITEV,
                },
                pid_tgid,
            ) == EMIT_SSL_PUMP_PENDING
            {
                // A successful tail call never resumes this program, so the remaining iovec is
                // only reached when the pump could not be entered (counted as a drop there).
                return pump_tail_call_or_drop!(ctx.as_ptr());
            }
        }
        index += 1;
    }
    0
}

// ---- ISOLATED-FIXTURE Agent native stdin content (sys_enter/exit_read) ----
//
// This is a Runtime-specific input-side Spike, not a production probe. It observes only fd 0 for
// explicitly allowlisted target PIDs. Capturing other FDs or a host-wide stdin stream is forbidden.

#[tracepoint]
pub fn native_stdin_enter(ctx: TracePointContext) -> u32 {
    remember_native_stdin_call(&ctx)
}

#[tracepoint]
pub fn native_stdin_exit(ctx: TracePointContext) -> u32 {
    if finish_native_stdin_call(&ctx) == EMIT_SSL_PUMP_PENDING {
        // Tracepoint programs cannot tail-call the kprobe-type pump program, so over-fast-path
        // native captures are counted as drops (documented fixture limitation).
        record_ssl_drop();
    }
    0
}

fn remember_native_stdin_call(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    if !content_capture_allowed(pid) {
        return 0;
    }
    // sys_enter_read: fd @16, buf @24, count @32.
    let Ok(fd) = (unsafe { ctx.read_at::<u64>(16) }) else {
        return 0;
    };
    if fd != 0 {
        return 0;
    }
    let Ok(buffer) = (unsafe { ctx.read_at::<u64>(24) }) else {
        return 0;
    };
    let Ok(requested_len) = (unsafe { ctx.read_at::<u64>(32) }) else {
        return 0;
    };
    if buffer == 0 || requested_len == 0 {
        return 0;
    }
    let _ = NATIVE_STDIN_CALLS.insert(
        &pid_tgid,
        &NativeInputCall {
            buffer,
            requested_len,
            fd: 0,
            _reserved: 0,
        },
        0,
    );
    0
}

fn finish_native_stdin_call(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let call = unsafe { NATIVE_STDIN_CALLS.get(&pid_tgid) }.copied();
    let _ = NATIVE_STDIN_CALLS.remove(&pid_tgid);
    let Some(call) = call else {
        return 0;
    };
    // The entry already proved exact-PID authorization. Recheck the global switch so SIGUSR2
    // cancels a read that was in flight when the Kill Switch was activated.
    if !content_capture_enabled() {
        return 0;
    }
    // sys_exit_read: long ret @16.
    let Ok(returned) = (unsafe { ctx.read_at::<i64>(16) }) else {
        return 0;
    };
    if returned < 0 {
        return 0;
    }
    if returned == 0 {
        emit_native_stdio_eof(pid_tgid, call.fd, CONTENT_OPERATION_NATIVE_STDIN_EOF);
        return 0;
    }
    emit_ssl(
        &EmitSslCall {
            ssl_pointer: u64::from(call.fd) + 1,
            buf: call.buffer,
            len: (returned as u64).min(call.requested_len),
            operation: CONTENT_OPERATION_NATIVE_STDIN_READ,
        },
        pid_tgid,
    )
}

// ---- ISOLATED-FIXTURE Agent native stdout content (sys_enter/exit_write) ----
//
// This observes fd 1 only for explicitly allowlisted target PIDs. The process-exit marker above
// provides a one-shot CLI response boundary; long-lived interactive runtimes need a native
// protocol adapter and must not infer per-turn boundaries from arbitrary stdout timing.

#[tracepoint]
pub fn native_stdout_enter(ctx: TracePointContext) -> u32 {
    remember_native_stdout_call(&ctx)
}

#[tracepoint]
pub fn native_stdout_exit(ctx: TracePointContext) -> u32 {
    if finish_native_stdout_call(&ctx) == EMIT_SSL_PUMP_PENDING {
        // See native_stdin_exit: the pump is unreachable from tracepoint programs.
        record_ssl_drop();
    }
    0
}

fn remember_native_stdout_call(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    if !content_capture_allowed(pid) {
        return 0;
    }
    // sys_enter_write: fd @16, buf @24, count @32.
    let Ok(fd) = (unsafe { ctx.read_at::<u64>(16) }) else {
        return 0;
    };
    if fd != 1 {
        return 0;
    }
    let Ok(buffer) = (unsafe { ctx.read_at::<u64>(24) }) else {
        return 0;
    };
    let Ok(requested_len) = (unsafe { ctx.read_at::<u64>(32) }) else {
        return 0;
    };
    if buffer == 0 || requested_len == 0 {
        return 0;
    }
    let _ = NATIVE_STDOUT_CALLS.insert(
        &pid_tgid,
        &NativeInputCall {
            buffer,
            requested_len,
            fd: 1,
            _reserved: 0,
        },
        0,
    );
    0
}

fn finish_native_stdout_call(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let call = unsafe { NATIVE_STDOUT_CALLS.get(&pid_tgid) }.copied();
    let _ = NATIVE_STDOUT_CALLS.remove(&pid_tgid);
    let Some(call) = call else {
        return 0;
    };
    if !content_capture_enabled() {
        return 0;
    }
    // sys_exit_write: long ret @16.
    let Ok(returned) = (unsafe { ctx.read_at::<i64>(16) }) else {
        return 0;
    };
    if returned <= 0 {
        return 0;
    }
    emit_ssl(
        &EmitSslCall {
            ssl_pointer: u64::from(call.fd) + 1,
            buf: call.buffer,
            len: (returned as u64).min(call.requested_len),
            operation: CONTENT_OPERATION_NATIVE_STDOUT_WRITE,
        },
        pid_tgid,
    )
}

fn emit_native_stdio_eof(pid_tgid: u64, fd: u32, operation: u8) {
    unsafe {
        let observed_at = bpf_ktime_get_ns();
        let state = SslLoopContext {
            ssl_pointer: u64::from(fd) + 1,
            buffer: 0,
            original_len: 0,
            true_len: 0,
            call_sequence: observed_at,
            observed_at_monotonic_ns: observed_at,
            fragment_offset: 0,
            cgroup_id: bpf_get_current_cgroup_id(),
            pid: (pid_tgid >> 32) as u32,
            tid: pid_tgid as u32,
            operation,
            failed: 0,
            _reserved: [0; 6],
            comm: bpf_get_current_comm().unwrap_or_default(),
        };
        let Some(scratch) = SSL_SCRATCH.get_ptr_mut(0) else {
            record_ssl_drop();
            return;
        };
        init_ssl_header(scratch as *mut c_void, &state, 0, 0, 0, false);
        let record = core::slice::from_raw_parts(
            scratch as *const u8,
            core::mem::size_of::<SslEventHeader>(),
        );
        if SSL_EVENTS.output(record, 0).is_err() {
            record_ssl_drop();
        }
    }
}

fn content_capture_allowed(pid: u32) -> bool {
    let enabled = CONTENT_CAPTURE_ENABLED.get(0).copied().unwrap_or(0);
    enabled == 1
        && (CLAUDE_BORINGSSL_EXACT_BINARY_ALL
            .get(0)
            .copied()
            .unwrap_or(0)
            == 1
            || KIMI_OPENSSL_EXACT_BINARY_ALL.get(0).copied().unwrap_or(0) == 1
            || unsafe { CONTENT_CAPTURE_TARGETS.get(&pid) }.is_some())
}

fn codex_content_capture_allowed(pid: u32) -> bool {
    if !content_capture_enabled() {
        return false;
    }
    if CODEX_RUSTLS_EXACT_BINARY_ALL.get(0).copied().unwrap_or(0) == 1 {
        return true;
    }
    unsafe { CONTENT_CAPTURE_TARGETS.get(&pid) }.is_some()
}

fn content_capture_enabled() -> bool {
    CONTENT_CAPTURE_ENABLED.get(0).copied().unwrap_or(0) == 1
}

fn remember_ssl_call(
    ctx: &ProbeContext,
    calls: &HashMap<u64, SslCall>,
    written_len_arg: usize,
) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    if !content_capture_allowed(pid) {
        return 0;
    }
    let ssl_pointer = ctx.arg::<u64>(0).unwrap_or(0);
    let buf = ctx.arg::<u64>(1).unwrap_or(0);
    let requested_len = ctx.arg::<u64>(2).unwrap_or(0);
    // 0 means the call has no output-length pointer (plain SSL_write/SSL_read). Argument index 0
    // is always the SSL pointer, so 0 can never be a real written-length argument position.
    let written_len_pointer = if written_len_arg == 0 {
        0
    } else {
        ctx.arg::<u64>(written_len_arg).unwrap_or(0)
    };
    if ssl_pointer == 0 || buf == 0 || requested_len == 0 {
        return 0;
    }
    let _ = calls.insert(
        &pid_tgid,
        &SslCall {
            ssl_pointer,
            buf,
            requested_len,
            written_len_pointer,
        },
        0,
    );
    0
}

fn finish_ssl_call(
    ctx: &RetProbeContext,
    calls: &HashMap<u64, SslCall>,
    operation: u8,
    extended: bool,
) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let call = unsafe { calls.get(&pid_tgid) }.copied();
    let _ = calls.remove(&pid_tgid);
    let Some(call) = call else {
        return 0;
    };
    // The presence of this call proves its entry passed the target-PID allowlist. Recheck only the
    // global switch so SIGUSR2 can still stop a call between entry and return without paying for a
    // second target-map lookup on every successful write.
    if !content_capture_enabled() {
        return 0;
    }
    let returned = ctx.ret::<i32>().unwrap_or(0);
    let actual_len = if extended {
        if returned <= 0 || call.written_len_pointer == 0 {
            return 0;
        }
        read_user_u64(call.written_len_pointer as *const u8).unwrap_or(0)
    } else {
        if returned <= 0 {
            return 0;
        }
        returned as u64
    };
    emit_ssl(
        &EmitSslCall {
            ssl_pointer: call.ssl_pointer,
            buf: call.buf,
            len: actual_len.min(call.requested_len),
            operation,
        },
        pid_tgid,
    )
}

struct EmitSslCall {
    ssl_pointer: u64,
    buf: u64,
    len: u64,
    operation: u8,
}

/// emit_ssl return value when the call was stashed for the fragmentation pump and the probe's
/// main frame must issue the tail call. Tail calls are deliberately issued only from probe main
/// frames (see pump_tail_call_or_drop!): the first pump build tail-called from this bpf2bpf
/// subprogram, and debugging that failure is what exposed the empty jump table behind it.
const EMIT_SSL_PUMP_PENDING: u32 = 1;

fn emit_ssl(call: &EmitSslCall, pid_tgid: u64) -> u32 {
    let buf = call.buf as *const u8;
    let len = call.len;
    if buf.is_null() || len == 0 {
        return 0;
    }

    unsafe {
        // Calls larger than the absolute ceiling are fragmented up to the ceiling instead of
        // being dropped header-only: long-agent CLI requests resend the full conversation
        // history and grow past any fixed small cap mid-session. Fragmentation runs in the
        // separate `ssl_fragment_pump` program reached via tail call: the kernel verifier
        // simulates bpf_loop iteration-by-iteration with a 1M-processed-insn budget per program,
        // which only tolerates ~130 iterations, while the 16 MiB ceiling needs 517 at
        // SSL_FRAGMENT_LEN. Each pump hop covers SSL_LOOP_ITERATIONS fragments and re-chains by
        // tail call until the call is fully emitted, keeping every program under budget.
        let mut loop_ctx = init_ssl_loop_ctx(call, pid_tgid);
        if len > SSL_MAX_CAPTURE_LEN as u64 {
            loop_ctx.original_len = SSL_MAX_CAPTURE_LEN as u64;
            bump_ssl_pump_stat(PUMP_CEILING_CLAMPED);
        }

        if loop_ctx.original_len <= (SSL_FRAGMENT_LEN * 4) as u64 {
            // All requests through the declared-load P95 fit in at most four records. Calling the
            // fragment emitter directly avoids bpf_loop setup/callback and tail-call overhead on
            // the latency-sensitive path.
            bump_ssl_pump_stat(PUMP_FASTPATH_CALLS);
            emit_one_ssl_fragment(&mut loop_ctx);
            if loop_ctx.fragment_offset < loop_ctx.original_len {
                emit_one_ssl_fragment(&mut loop_ctx);
            }
            if loop_ctx.fragment_offset < loop_ctx.original_len {
                emit_one_ssl_fragment(&mut loop_ctx);
            }
            if loop_ctx.fragment_offset < loop_ctx.original_len {
                emit_one_ssl_fragment(&mut loop_ctx);
            }
            if loop_ctx.fragment_offset != loop_ctx.original_len {
                bump_ssl_pump_stat(PUMP_FASTPATH_INCOMPLETE);
                record_ssl_drop();
            }
            return 0;
        }

        let Some(stash) = SSL_PUMP_STASH.get_ptr_mut(0) else {
            bump_ssl_pump_stat(PUMP_STASH_UNAVAILABLE);
            record_ssl_drop();
            return 0;
        };
        *stash = loop_ctx;
        bump_ssl_pump_stat(PUMP_STASHED);
        // The caller's probe main frame issues the tail call (see EMIT_SSL_PUMP_PENDING).
        EMIT_SSL_PUMP_PENDING
    }
}

/// Tail-call-only program (never attached) that fragments one large SSL call into ring records.
/// Emits up to SSL_LOOP_ITERATIONS fragments per hop, re-chaining to itself while fragments
/// remain; the per-CPU stash carries the state across hops (bpf_loop requires its callback
/// context on the program stack, so each hop copies it in and back). Emits the over-ceiling
/// truncated marker with the true length once the clamped prefix is fully emitted.
#[uprobe]
pub fn ssl_fragment_pump(ctx: ProbeContext) -> u32 {
    unsafe {
        bump_ssl_pump_stat(PUMP_ENTRIES);
        let Some(stash) = SSL_PUMP_STASH.get_ptr_mut(0) else {
            bump_ssl_pump_stat(PUMP_STASH_MISSING);
            return 0;
        };
        let mut state: SslLoopContext = *stash;
        let loop_failed = bpf_loop(
            SSL_LOOP_ITERATIONS as u32,
            emit_ssl_fragment_batch as *mut c_void,
            &mut state as *mut SslLoopContext as *mut c_void,
            0,
        ) < 0;
        if loop_failed {
            bump_ssl_pump_stat(PUMP_LOOP_FAILED);
            record_ssl_drop();
            return 0;
        }
        if state.fragment_offset < state.original_len {
            *stash = state;
            bump_ssl_pump_stat(PUMP_RECHAINED);
            bpf_tail_call(
                ctx.as_ptr(),
                &SSL_FRAGMENT_PUMPS as *const ProgramArray as *mut c_void,
                0,
            );
            bump_ssl_pump_stat(PUMP_RECHAIN_FAILED);
            record_ssl_drop();
            return 0;
        }
        bump_ssl_pump_stat(PUMP_HOP_COMPLETED);
        // Marker record carries the true length so userspace counts the oversize once.
        if state.true_len > state.original_len {
            state.original_len = state.true_len;
            emit_oversized_ssl_call(&state);
            bump_ssl_pump_stat(PUMP_MARKER_SENT);
        }
    }
    0
}

#[inline(always)]
fn init_ssl_loop_ctx(call: &EmitSslCall, pid_tgid: u64) -> SslLoopContext {
    unsafe {
        let call_sequence = bpf_ktime_get_ns();
        SslLoopContext {
            ssl_pointer: call.ssl_pointer,
            buffer: call.buf,
            original_len: call.len,
            true_len: call.len,
            call_sequence,
            observed_at_monotonic_ns: call_sequence,
            fragment_offset: 0,
            cgroup_id: bpf_get_current_cgroup_id(),
            pid: (pid_tgid >> 32) as u32,
            tid: pid_tgid as u32,
            operation: call.operation,
            failed: 0,
            _reserved: [0; 6],
            comm: bpf_get_current_comm().unwrap_or_default(),
        }
    }
}

unsafe fn emit_oversized_ssl_call(state: &SslLoopContext) {
    let Some(scratch) = SSL_SCRATCH.get_ptr_mut(0) else {
        record_ssl_drop();
        return;
    };
    init_ssl_header(scratch as *mut c_void, state, 0, 0, 0, true);
    let record =
        core::slice::from_raw_parts(scratch as *const u8, core::mem::size_of::<SslEventHeader>());
    if SSL_EVENTS.output(record, 0).is_err() {
        record_ssl_drop();
    }
}

unsafe extern "C" fn emit_ssl_fragment_batch(_iteration: u32, raw_ctx: *mut c_void) -> i64 {
    let state = &mut *(raw_ctx as *mut SslLoopContext);
    if state.fragment_offset >= state.original_len {
        return 1;
    }
    emit_one_ssl_fragment(state);
    if state.fragment_offset >= state.original_len {
        1
    } else {
        0
    }
}

unsafe fn emit_one_ssl_fragment(state: &mut SslLoopContext) {
    // Failure is detected by the caller via fragment_offset < original_len; keep this body
    // branch-minimal because the verifier re-walks it once per simulated bpf_loop iteration.
    let remaining = state.original_len - state.fragment_offset;
    let captured_len = if remaining > SSL_FRAGMENT_LEN as u64 {
        SSL_FRAGMENT_LEN as u32
    } else {
        remaining as u32
    };
    let Some(scratch) = SSL_SCRATCH.get_ptr_mut(0) else {
        bump_ssl_pump_stat(PUMP_SCRATCH_UNAVAILABLE);
        return;
    };
    init_ssl_header(
        scratch as *mut c_void,
        state,
        captured_len,
        (state.fragment_offset / SSL_FRAGMENT_LEN as u64) as u32,
        state.fragment_offset,
        false,
    );
    let source = (state.buffer as *const u8).add(state.fragment_offset as usize);
    if bpf_probe_read_user(
        (*scratch).data.as_mut_ptr() as *mut c_void,
        captured_len,
        source as *const c_void,
    ) < 0
    {
        bump_ssl_pump_stat(PUMP_PROBE_READ_FAILED);
        return;
    }
    let record_len = core::mem::size_of::<SslEventHeader>() + captured_len as usize;
    let record = core::slice::from_raw_parts(scratch as *const u8, record_len);
    if SSL_EVENTS.output(record, 0).is_err() {
        bump_ssl_pump_stat(PUMP_EMIT_OUTPUT_FAILED);
        return;
    }
    state.fragment_offset += captured_len as u64;
}

unsafe fn init_ssl_header(
    record: *mut c_void,
    state: &SslLoopContext,
    captured_len: u32,
    fragment_index: u32,
    fragment_offset: u64,
    truncated: bool,
) {
    *(record as *mut SslEventHeader) = SslEventHeader {
        schema_version: SSL_EVENT_SCHEMA_VERSION,
        operation: state.operation,
        truncated: u8::from(truncated),
        pid: state.pid,
        tid: state.tid,
        captured_len,
        fragment_index,
        _reserved: 0,
        cgroup_id: state.cgroup_id,
        ssl_pointer: state.ssl_pointer,
        call_sequence: state.call_sequence,
        observed_at_monotonic_ns: state.observed_at_monotonic_ns,
        original_len: state.original_len,
        fragment_offset,
        comm: state.comm,
    };
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
    let Some(mut entry) = reserve_or_drop::<ConnectEvent>(&CONNECT_EVENTS, DROP_CONNECT) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = bpf_get_current_cgroup_id();
        (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev).fd = fd as u32;
        (*ev).family = family;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        let mut port = [0u8; 2];
        let _ = bpf_probe_read_user_buf(addr_ptr.add(2), &mut port); // sin_port (network order)
        (*ev).port = u16::from_be_bytes(port);
        // Read into a local first to avoid an autoref through the raw event pointer.
        let mut a = [0u8; 16];
        if family == 2 {
            let _ = bpf_probe_read_user_buf(addr_ptr.add(4), &mut a[..4]); // sin_addr
        } else {
            let _ = bpf_probe_read_user_buf(addr_ptr.add(8), &mut a); // sin6_addr
        }
        (*ev).addr = a;
    }
    entry.submit(0);
    Ok(0)
}

// ---- security-sensitive actions: privesc (setuid) / injection (ptrace) / open-port (bind) ----
//
// One ring, in-kernel-filtered to the loud cases. These syscalls are rare for a normal agent, so
// when one fires it's worth a look — that's the whole point of a separate "rare and loud" tier.

fn emit_sec(kind: u32, detail: u64) {
    let Some(mut entry) = reserve_or_drop::<SecEvent>(&SEC_EVENTS, DROP_SEC) else {
        return;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = bpf_get_current_cgroup_id();
        (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev).kind = kind;
        (*ev).detail = detail;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
    }
    entry.submit(0);
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
    let Some(mut entry) = reserve_or_drop::<DnsEvent>(&DNS_EVENTS, DROP_DNS) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = bpf_get_current_cgroup_id();
        (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev)._pad = 0;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        let n: u32 = if count > DNS_SNAP_LEN as u64 {
            DNS_SNAP_LEN as u32
        } else {
            count as u32
        };
        (*ev).len = n as u16;
        (*ev).data = [0u8; DNS_SNAP_LEN];
        let _ = bpf_probe_read_user(
            (*ev).data.as_mut_ptr() as *mut core::ffi::c_void,
            n,
            buf as *const core::ffi::c_void,
        );
    }
    entry.submit(0);
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
    let Some(mut entry) = reserve_or_drop::<DnsEvent>(&DNS_EVENTS, DROP_DNS) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = bpf_get_current_cgroup_id();
        (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev)._pad = 0;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        let n: u32 = if iov_len > DNS_SNAP_LEN as u64 {
            DNS_SNAP_LEN as u32
        } else {
            iov_len as u32
        };
        (*ev).len = n as u16;
        (*ev).data = [0u8; DNS_SNAP_LEN];
        let _ = bpf_probe_read_user(
            (*ev).data.as_mut_ptr() as *mut core::ffi::c_void,
            n,
            iov_base as *const core::ffi::c_void,
        );
    }
    entry.submit(0);
    Ok(0)
}

// ---- file opened for writing (sys_enter_openat) ----
// Only write/rw opens are emitted (read opens are far too high-volume); userspace reads
// the path. This is the "which files did the agent modify" signal.

#[tracepoint]
pub fn file_open(ctx: TracePointContext) -> u32 {
    try_open(&ctx).unwrap_or(0)
}

fn try_open(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_openat: dfd @16, filename @24, flags @32, mode @40.
    let flags: u64 = unsafe { ctx.read_at(32)? };
    if flags & 0x3 == 0 {
        return Ok(0); // O_RDONLY — skip; keep only O_WRONLY / O_RDWR
    }
    let filename: *const u8 = unsafe { ctx.read_at(24)? };
    let Some(mut entry) = reserve_or_drop::<FileEvent>(&FILE_EVENTS, DROP_FILE) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = bpf_get_current_cgroup_id();
        (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev).flags = flags as u32;
        (*ev).path = [0u8; PATH_SNAP_LEN];
        let _ = bpf_probe_read_user_str_bytes(filename, &mut (*ev).path);
    }
    entry.submit(0);
    Ok(0)
}

// ---- file deleted (sys_enter_unlinkat) — the "which files did the agent destroy" signal ----

#[tracepoint]
pub fn file_unlink(ctx: TracePointContext) -> u32 {
    try_unlink(&ctx).unwrap_or(0)
}

fn try_unlink(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_unlinkat: dfd @16, pathname @24, flag @32.
    let pathname: *const u8 = unsafe { ctx.read_at(24)? };
    let Some(mut entry) = reserve_or_drop::<FileEvent>(&FILE_EVENTS, DROP_FILE) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = bpf_get_current_cgroup_id();
        (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev).flags = FILE_DELETE_FLAG; // distinguish from an openat on the shared FILE_EVENTS ring
        (*ev).path = [0u8; PATH_SNAP_LEN];
        let _ = bpf_probe_read_user_str_bytes(pathname, &mut (*ev).path);
    }
    entry.submit(0);
    Ok(0)
}

// ---- file renamed (sys_enter_renameat) — the write-then-rename destination ----
// Agent file tools and editors persist changes by writing a temporary file and renaming it over
// the target, so openat-only capture would miss the modified path entirely. Emit the *new* path
// as the modification signal; the source path is the temp file and is not the evidence.

#[tracepoint]
pub fn file_rename(ctx: TracePointContext) -> u32 {
    try_rename(&ctx).unwrap_or(0)
}

#[tracepoint]
pub fn file_rename2(ctx: TracePointContext) -> u32 {
    // sys_enter_renameat2 shares the renameat layout (flags @48 is irrelevant here).
    try_rename(&ctx).unwrap_or(0)
}

fn try_rename(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_renameat: olddfd @16, oldname @24, newdfd @32, newname @40.
    let newname: *const u8 = unsafe { ctx.read_at(40)? };
    let Some(mut entry) = reserve_or_drop::<FileEvent>(&FILE_EVENTS, DROP_FILE) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).cgroup_id = bpf_get_current_cgroup_id();
        (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev).flags = FILE_RENAME_FLAG; // distinguish from an openat on the shared FILE_EVENTS ring
        (*ev).path = [0u8; PATH_SNAP_LEN];
        let _ = bpf_probe_read_user_str_bytes(newname, &mut (*ev).path);
    }
    entry.submit(0);
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
    // sys_enter_read / sys_enter_recvfrom: fd @16.
    let Ok(fd) = (unsafe { ctx.read_at::<u64>(16) }) else {
        return 0;
    };
    let tgid = bpf_get_current_pid_tgid();
    let key = sock_key((tgid >> 32) as u32, fd);
    // Stash only for tracked LLM sockets — keeps this node-wide hot path cheap.
    if unsafe { LLM_SOCKS.get(&key) }.is_some() {
        let _ = READ_FD.insert(&tgid, &(fd as u32), 0);
    }
    0
}

fn on_read_exit(ctx: &TracePointContext) -> u32 {
    let tgid = bpf_get_current_pid_tgid();
    let Some(&fd) = (unsafe { READ_FD.get(&tgid) }) else {
        return 0;
    };
    let _ = READ_FD.remove(&tgid);
    // sys_exit_*: long ret @16 (bytes read; <=0 means error/EOF).
    let Ok(ret) = (unsafe { ctx.read_at::<i64>(16) }) else {
        return 0;
    };
    if ret <= 0 {
        return 0;
    }
    let key = sock_key((tgid >> 32) as u32, fd as u64);
    if let Some(stat) = LLM_SOCKS.get_ptr_mut(&key) {
        unsafe {
            (*stat).resp_bytes = (*stat).resp_bytes.saturating_add(ret as u64);
            if (*stat).first_resp_ns == 0 {
                (*stat).first_resp_ns = bpf_ktime_get_ns();
            }
        }
    }
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
    let Some(&stat) = (unsafe { LLM_SOCKS.get(&key) }) else {
        return 0; // not an LLM socket
    };
    let _ = LLM_SOCKS.remove(&key);
    if let Some(mut entry) = reserve_or_drop::<LlmEvent>(&LLM_EVENTS, DROP_LLM) {
        let now = unsafe { bpf_ktime_get_ns() };
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).cgroup_id = bpf_get_current_cgroup_id();
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
        }
        entry.submit(0);
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
