#![no_std]
#![no_main]

use a3s_observer_common::{
    ConnectEvent, DnsEvent, ExecEvent, ExitEvent, FileEvent, LlmEvent, SslEvent, TlsEvent,
    ARGV_SLOTS, ARG_LEN, DNS_SNAP_LEN, PATH_SNAP_LEN, SSL_SNAP_LEN, TLS_SNAP_LEN,
};
use aya_ebpf::{
    helpers::gen::bpf_probe_read_user,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{cgroup_sock_addr, map, tracepoint, uprobe, uretprobe},
    maps::{ring_buf::RingBufEntry, HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext, SockAddrContext, TracePointContext},
};

// Exec events now carry full argv (~928 B each), so this ring is larger than the others to
// keep a process burst (a build spawning many subprocesses) from dropping events.
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

// Count of events dropped because a ring was full — data-loss visibility under extreme load.
#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

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

// ---- tool / subprocess exec (sys_enter_execve) ----

#[tracepoint]
pub fn exec(ctx: TracePointContext) -> u32 {
    try_exec(&ctx).unwrap_or(0)
}

fn try_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    let Some(mut entry) = reserve_or_drop::<ExecEvent>(&EVENTS) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        let pid_tgid = bpf_get_current_pid_tgid();
        (*ev).pid = (pid_tgid >> 32) as u32;
        (*ev).uid = bpf_get_current_uid_gid() as u32;
        (*ev).ppid = 0;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        (*ev).filename = [0u8; 128];
        // sys_enter_execve: `const char *filename` at offset 16.
        if let Ok(filename_ptr) = ctx.read_at::<*const u8>(16) {
            let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut (*ev).filename);
        }
        // `const char *const *argv` at offset 24 — capture up to ARGV_SLOTS args (the intent:
        // which URL / which command, not just the binary). Bounded for the verifier.
        (*ev).argc = 0;
        (*ev).args = [[0u8; ARG_LEN]; ARGV_SLOTS];
        if let Ok(argv) = ctx.read_at::<*const u8>(24) {
            for i in 0..ARGV_SLOTS {
                let Some(argp) = read_user_u64(argv.add(i * 8)) else {
                    break;
                };
                if argp == 0 {
                    break; // end of argv
                }
                let _ = bpf_probe_read_user_str_bytes(argp as *const u8, &mut (*ev).args[i]);
                (*ev).argc += 1;
            }
        }
    }
    entry.submit(0);
    Ok(0)
}

// ---- process exit (sys_enter_exit_group) — the tool's outcome / exit code ----

#[tracepoint]
pub fn proc_exit(ctx: TracePointContext) -> u32 {
    try_proc_exit(&ctx).unwrap_or(0)
}

fn try_proc_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let Some(mut entry) = reserve_or_drop::<ExitEvent>(&EXIT_EVENTS) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        // sys_enter_exit_group: `long error_code` at offset 16 (low byte = the exit() code).
        (*ev).exit_code = ctx.read_at::<u64>(16).unwrap_or(0) as u32;
    }
    entry.submit(0);
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
