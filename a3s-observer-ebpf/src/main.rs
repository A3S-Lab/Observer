#![no_std]
#![no_main]

use a3s_observer_common::{
    ConnectEvent, DnsEvent, ExecRecord, ExitEvent, FileEvent, LlmEvent, SecEvent, SslEvent,
    TlsEvent, ARGV_SLOTS, DNS_SNAP_LEN, EXEC_ARG_CHUNK_PAYLOAD, EXEC_FLAG_ARGV_INCOMPLETE,
    EXEC_FLAG_ARGV_TRUNCATED, EXEC_MAX_CHUNKS, EXEC_RECORD_ARG_CHUNK, EXEC_RECORD_COMMIT,
    EXEC_RECORD_END, EXEC_RECORD_HEADER, FILE_DELETE_FLAG, PATH_SNAP_LEN, SEC_BIND, SEC_PTRACE,
    SEC_SETUID, SSL_SNAP_LEN, TLS_SNAP_LEN,
};
use aya_ebpf::{
    cty::c_void,
    helpers::gen::bpf_probe_read_user,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_loop, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{cgroup_sock_addr, kprobe, map, tracepoint, uprobe, uretprobe},
    maps::{ring_buf::RingBufEntry, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext, SockAddrContext, TracePointContext},
};

// Exec records are fixed at 184 B. Typical commands need one header, a few argument chunks and
// one end record; long argv values can use up to EXEC_MAX_CHUNKS records without inflating every
// short exec event.
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
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static LLM_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// Security-sensitive actions (privesc / injection / open-port). In-kernel-filtered to the loud
// cases, so this stays near-empty — a small ring is plenty.
#[map]
static SEC_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// Count of events dropped because a ring was full — data-loss visibility under extreme load.
#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// child tgid -> parent tgid, captured before the child runs (with syscall-exit fallback). Exec must carry
// this in-kernel snapshot because short-lived tools can exit before userspace reads /proc.
#[map]
static PARENTS: LruHashMap<u32, u32> = LruHashMap::with_max_entries(65_536, 0);

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

// Opt-in OpenSSL content (uprobe). Bigger ring — payloads are up to SSL_SNAP_LEN each.
#[map]
static SSL_EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

// SSL_read entry saves the caller's buffer ptr by tid so the uretprobe (which knows how many
// bytes were decrypted into it) can snapshot the plaintext.
#[map]
static SSL_READ_BUF: HashMap<u64, u64> = HashMap::with_max_entries(10240, 0);

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
fn reserve_or_drop<T>(ring: &RingBuf) -> Option<RingBufEntry<T>> {
    let entry = ring.reserve::<T>(0);
    if entry.is_none() {
        unsafe {
            if let Some(c) = DROPS.get_ptr_mut(0) {
                *c = (*c).wrapping_add(1);
            }
        }
    }
    entry
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
    pid: u32,
    ppid: u32,
    uid: u32,
    comm: [u8; 16],
) {
    (*record).exec_id = exec_id;
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

    let Some(mut chunk_entry) = reserve_or_drop::<ExecRecord>(&EVENTS) else {
        state.flags |= EXEC_FLAG_ARGV_INCOMPLETE;
        state.done = 1;
        return 1;
    };
    let chunk = chunk_entry.as_mut_ptr();
    init_exec_record(
        chunk,
        state.exec_id,
        state.pid,
        state.ppid,
        state.uid,
        state.comm,
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
    let ppid = unsafe { PARENTS.get(&pid).copied().unwrap_or(0) };
    let comm = bpf_get_current_comm().unwrap_or_default();
    let exec_id = unsafe { bpf_ktime_get_ns() } ^ pid_tgid;
    let mut flags = 0u8;
    let _ = EXEC_IDS.insert(&pid, &exec_id, 0);

    let Some(mut header_entry) = reserve_or_drop::<ExecRecord>(&EVENTS) else {
        return Ok(0);
    };
    let header = header_entry.as_mut_ptr();
    unsafe {
        init_exec_record(header, exec_id, pid, ppid, uid, comm);
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
    header_entry.submit(0);

    let captured_argc: u16;
    let captured_bytes: u32;

    unsafe {
        // `const char *const *argv` at offset 24. bpf_loop verifies the callback once instead of
        // exploring every state transition through a 64-iteration in-program loop.
        if let Ok(argv) = ctx.read_at::<*const u8>(24) {
            let mut loop_ctx = ExecLoopContext {
                argv: argv as u64,
                exec_id,
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

        let Some(mut end_entry) = reserve_or_drop::<ExecRecord>(&EVENTS) else {
            return Ok(0);
        };
        let end = end_entry.as_mut_ptr();
        init_exec_record(end, exec_id, pid, ppid, uid, comm);
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
    let ppid = unsafe { PARENTS.get(&pid).copied().unwrap_or(0) };
    let comm = bpf_get_current_comm().unwrap_or_default();
    if let Some(mut entry) = reserve_or_drop::<ExecRecord>(&EVENTS) {
        let record = entry.as_mut_ptr();
        unsafe {
            init_exec_record(record, exec_id, pid, ppid, uid, comm);
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
    let Some(mut entry) = reserve_or_drop::<ExitEvent>(&EXIT_EVENTS) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).pid = (id >> 32) as u32;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        (*ev).exit_code = ((code >> 8) & 0xff) as u32;
        (*ev).signal = (code & 0x7f) as u32; // & 0x7f intentionally drops the 0x80 core-dump bit
    }
    entry.submit(0);
    let pid = (id >> 32) as u32;
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
    let Some(mut entry) = reserve_or_drop::<TlsEvent>(&TLS_EVENTS) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
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

// ---- OPT-IN OpenSSL content (uprobes on SSL_write / SSL_read) ----
//
// NOT language-agnostic (a uprobe binds to OpenSSL symbols) and captures real plaintext, so the
// collector only attaches these when A3S_OBSERVER_SSL=1. SSL_write(ssl, buf, num): the request
// plaintext is in `buf` at entry. SSL_read(ssl, buf, num): `buf` is filled during the call, so
// snapshot it at return, with the byte count from the return value.

#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    // SSL_write(ssl, buf, num): read args as raw register values (pointers carried as u64).
    let buf = ctx.arg::<u64>(1).unwrap_or(0);
    let num = ctx.arg::<u64>(2).unwrap_or(0);
    emit_ssl(buf as *const u8, num, 0)
}

#[uprobe]
pub fn ssl_read_enter(ctx: ProbeContext) -> u32 {
    let buf = ctx.arg::<u64>(1).unwrap_or(0);
    if buf != 0 {
        let tid = bpf_get_current_pid_tgid();
        let _ = SSL_READ_BUF.insert(&tid, &buf, 0);
    }
    0
}

#[uretprobe]
pub fn ssl_read_exit(ctx: RetProbeContext) -> u32 {
    let tid = bpf_get_current_pid_tgid();
    let ret = ctx.ret::<i32>().unwrap_or(0) as i64; // SSL_read return value = bytes decrypted
    let buf = unsafe { SSL_READ_BUF.get(&tid) }.copied();
    let _ = SSL_READ_BUF.remove(&tid);
    if ret <= 0 {
        return 0;
    }
    match buf {
        Some(addr) => emit_ssl(addr as *const u8, ret as u64, 1),
        None => 0,
    }
}

fn emit_ssl(buf: *const u8, len: u64, is_read: u32) -> u32 {
    if buf.is_null() || len == 0 {
        return 0;
    }
    let Some(mut entry) = reserve_or_drop::<SslEvent>(&SSL_EVENTS) else {
        return 0;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev).is_read = is_read;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        // n <= SSL_SNAP_LEN (data capacity) and n <= len (bytes actually written/read).
        let n: u32 = if len > SSL_SNAP_LEN as u64 {
            SSL_SNAP_LEN as u32
        } else {
            len as u32
        };
        (*ev).len = n;
        (*ev).data = [0u8; SSL_SNAP_LEN];
        let _ = bpf_probe_read_user(
            (*ev).data.as_mut_ptr() as *mut core::ffi::c_void,
            n,
            buf as *const core::ffi::c_void,
        );
    }
    entry.submit(0);
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
    let Some(mut entry) = reserve_or_drop::<ConnectEvent>(&CONNECT_EVENTS) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
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
    let Some(mut entry) = reserve_or_drop::<SecEvent>(&SEC_EVENTS) else {
        return;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
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
    let Some(mut entry) = reserve_or_drop::<DnsEvent>(&DNS_EVENTS) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
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
    let Some(mut entry) = reserve_or_drop::<DnsEvent>(&DNS_EVENTS) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
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
    let Some(mut entry) = reserve_or_drop::<FileEvent>(&FILE_EVENTS) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
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
    let Some(mut entry) = reserve_or_drop::<FileEvent>(&FILE_EVENTS) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev).flags = FILE_DELETE_FLAG; // distinguish from an openat on the shared FILE_EVENTS ring
        (*ev).path = [0u8; PATH_SNAP_LEN];
        let _ = bpf_probe_read_user_str_bytes(pathname, &mut (*ev).path);
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
    if let Some(mut entry) = reserve_or_drop::<LlmEvent>(&LLM_EVENTS) {
        let now = unsafe { bpf_ktime_get_ns() };
        let ev = entry.as_mut_ptr();
        unsafe {
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
