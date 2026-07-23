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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecRecord {
    pub exec_id: u64,
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
}

const _: [(); 184] = [(); core::mem::size_of::<ExecRecord>()];

/// Fixed-size exec payload used only by the Linux 4.19 perf-kprobe backend.
///
/// The legacy verifier cannot load the modern chunked exec program. Keep this ABI separate from
/// `ExecRecord` so current kernels can evolve without silently changing the customer probe layout.
pub const LEGACY_ARG_LEN: usize = 128;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LegacyExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub argc: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 128],
    pub args: [[u8; LEGACY_ARG_LEN]; ARGV_SLOTS],
}

const _: [(); 1696] = [(); core::mem::size_of::<LegacyExecEvent>()];

/// A process exit (`sys_enter_exit_group`) — the other end of the tool lifecycle, carrying the
/// exit status so tool *outcomes* are visible (did the command succeed?), not just that it ran.
/// Captured via a `do_exit` kprobe, so it catches EVERY exit — clean exits and signal-kills
/// (crash / SIGKILL / OOM) alike.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitEvent {
    pub pid: u32,
    pub exit_code: u32, // exit() status (0 when terminated by a signal)
    pub signal: u32,    // terminating signal, 0 = clean exit (9 SIGKILL/OOM, 11 SIGSEGV crash, …)
    pub comm: [u8; 16],
}

/// The leading bytes of an outbound TLS ClientHello, captured at the send syscall.
///
/// The eBPF side only detects + copies (verifier-friendly); userspace parses the SNI
/// `server_name` out of `data[..len]` — language-agnostic LLM-provider identification
/// with no per-language uprobe.
pub const TLS_SNAP_LEN: usize = 512;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsEvent {
    pub pid: u32,
    pub fd: u32, // socket fd, for (pid,fd) correlation with ConnectEvent
    pub len: u16,
    pub _pad: u16,
    pub comm: [u8; 16], // in-kernel process name — reliable identity even if the proc exits
    pub data: [u8; TLS_SNAP_LEN],
}

/// An outbound connection attempt (`sys_enter_connect`): which peer a process dialed.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub pid: u32,
    pub fd: u32,        // socket fd, keys the userspace (pid,fd)->peer join
    pub family: u16,    // AF_INET = 2, AF_INET6 = 10
    pub port: u16,      // host byte order
    pub addr: [u8; 16], // IPv4 in [0..4], IPv6 uses all 16
    pub comm: [u8; 16],
}

/// The leading bytes of an outbound DNS query (sendto to :53). Userspace parses the
/// question name → the hostname the process resolved. Queries have no name compression.
pub const DNS_SNAP_LEN: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    pub pid: u32,
    pub len: u16,
    pub _pad: u16,
    pub comm: [u8; 16],
    pub data: [u8; DNS_SNAP_LEN],
}

/// A file opened for writing (`sys_enter_openat`, write/rw flags only — read opens are
/// filtered out in-kernel to keep volume sane). Userspace reads the path from `data`.
pub const PATH_SNAP_LEN: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    pub pid: u32,
    pub flags: u32,
    pub comm: [u8; 16],
    pub path: [u8; PATH_SNAP_LEN],
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
    pub pid: u32,
    pub fd: u32,
    pub req_bytes: u64,  // bytes written after ClientHello (approx request size)
    pub resp_bytes: u64, // bytes read back (approx response size)
    pub latency_ns: u64, // ClientHello → close
    pub ttft_ns: u64,    // ClientHello → first response byte; 0 = no response seen
    pub comm: [u8; 16],
}

/// A plaintext snapshot from a TLS connection, captured by **uprobes** on OpenSSL
/// `SSL_write` / `SSL_read` — the OPT-IN content extension (LLM prompt / completion bodies).
///
/// Unlike every other probe this is **not** language-agnostic: a uprobe binds to a specific
/// library symbol, so this covers **OpenSSL only** (Python `requests`/`httpx`, Node, curl, …),
/// not Go's `crypto/tls` or BoringSSL. It also captures real request/response content, so it is
/// **off by default** (`A3S_OBSERVER_SSL=1`) and must run where that's acceptable. This is why
/// it lives outside the universal core — see Rule 2 (minimal core + external extensions).
pub const SSL_SNAP_LEN: usize = 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SslEvent {
    pub pid: u32,
    pub is_read: u32, // 0 = SSL_write (request / prompt), 1 = SSL_read (response / completion)
    pub len: u32,     // bytes captured into `data` (<= SSL_SNAP_LEN)
    pub comm: [u8; 16],
    pub data: [u8; SSL_SNAP_LEN],
}

/// A security-sensitive action — rare and high-signal, filtered in-kernel so volume stays near
/// zero. One event/ring covers several syscalls (privilege escalation, process injection, opening
/// a listening port) instead of a probe-per-syscall sprawl — keeps the model + ring count bounded.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SecEvent {
    pub pid: u32,
    pub kind: u32,   // SEC_* below
    pub detail: u64, // SEC_SETUID: 0 (escalated-to uid) · SEC_PTRACE: target pid · SEC_BIND: port
    pub comm: [u8; 16],
}

pub const SEC_SETUID: u32 = 1; // setuid/setresuid → euid 0 from a non-root caller (privesc)
pub const SEC_PTRACE: u32 = 2; // ptrace(ATTACH|SEIZE) of another process (injection)
pub const SEC_BIND: u32 = 3; // bind() to a fixed (non-ephemeral) port (opened a listener)
