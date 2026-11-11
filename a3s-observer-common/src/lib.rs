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
pub const EXEC_COMPACT_SLOTS: usize = 8;
pub const EXEC_COMPACT_ARG_LEN: usize = 16;

pub const EXEC_RECORD_HEADER: u8 = 1;
pub const EXEC_RECORD_ARG_CHUNK: u8 = 2;
pub const EXEC_RECORD_END: u8 = 3;
/// Emitted from `sched_process_exec` after the kernel successfully commits the exec.
pub const EXEC_RECORD_COMMIT: u8 = 4;
/// Up to eight argv values in fixed 16-byte slots; still confirmed by COMMIT.
pub const EXEC_RECORD_COMPACT: u8 = 5;

pub const EXEC_FLAG_ARGV_TRUNCATED: u8 = 1 << 0;
pub const EXEC_FLAG_ARGV_INCOMPLETE: u8 = 1 << 1;

pub const DROP_EXEC: u32 = 0;
pub const DROP_EXIT: u32 = 1;
pub const DROP_TLS: u32 = 2;
pub const DROP_CONNECT: u32 = 3;
pub const DROP_DNS: u32 = 4;
pub const DROP_FILE: u32 = 5;
pub const DROP_LLM: u32 = 6;
pub const DROP_SEC: u32 = 7;
pub const DROP_SSL: u32 = 8;
pub const DROP_KIND_COUNT: u32 = 9;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProcessKernelIdentity {
    pub start_boottime_ns: u64,
    pub creation_ppid: u32,
    pub observed_ppid: u32,
    pub creation_parent_start_boottime_ns: u64,
    pub observed_parent_start_boottime_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecRecord {
    pub exec_id: u64,
    pub identity: ProcessKernelIdentity,
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
}

const _: [(); 224] = [(); core::mem::size_of::<ExecRecord>()];

/// A process exit (`sys_enter_exit_group`) — the other end of the tool lifecycle, carrying the
/// exit status so tool *outcomes* are visible (did the command succeed?), not just that it ran.
/// Captured via a `do_exit` kprobe, so it catches EVERY exit — clean exits and signal-kills
/// (crash / SIGKILL / OOM) alike.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitEvent {
    pub cgroup_id: u64,
    pub identity: ProcessKernelIdentity,
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
    pub cgroup_id: u64,
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
    pub cgroup_id: u64,
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
    pub cgroup_id: u64,
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
    pub cgroup_id: u64,
    pub pid: u32,
    pub flags: u32,
    pub comm: [u8; 16],
    pub path: [u8; PATH_SNAP_LEN],
}

/// `FileEvent.flags` sentinel marking a deletion (`unlinkat`) rather than an open — no real
/// `openat` flag combination equals `u32::MAX`, so userspace can tell them apart on one ring.
pub const FILE_DELETE_FLAG: u32 = u32::MAX;

/// `FileEvent.flags` sentinel marking a rename destination (`renameat`/`renameat2`). Editors and
/// agent file tools overwhelmingly write-then-rename, so the destination path would otherwise
/// never appear in the openat-based "which files did the workload modify" signal.
pub const FILE_RENAME_FLAG: u32 = u32::MAX - 1;

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
}

/// An experimental plaintext-fragment header from a TLS connection, captured by **uprobes** on
/// OpenSSL `SSL_write*` / `SSL_read*`.
///
/// This ABI is intentionally marked experimental: Phase -1 Runtime Spikes may revise it before it
/// is frozen. Production metadata-only mode never attaches these probes and never writes this ring.
/// The collector additionally requires an isolated-test gate and an explicit target-PID allowlist.
///
/// The ring record is variable-sized: this fixed header is followed by exactly `captured_len`
/// bytes. Keeping the payload outside the fixed struct lets the eBPF program emit bounded
/// fragments without zero-filling a one-megabyte record or exposing unused scratch bytes.
pub const SSL_EVENT_SCHEMA_VERSION: u16 = 4;
pub const SSL_FRAGMENT_LEN: usize = 31 * 1024;
/// Fragments emitted per `bpf_loop` run inside the tail-call pump. The kernel verifier simulates
/// `bpf_loop` iteration-by-iteration and its 1M-processed-insn budget only tolerates ~130
/// simulated iterations per program, so one program hop covers 128 fragments (4 MiB); a
/// tail-call chain of pump invocations covers the rest of the 16 MiB ceiling.
pub const SSL_LOOP_ITERATIONS: usize = 128;
/// Hard per-`SSL_*`-call plaintext ceiling. Calls larger than this are still fragmented and
/// captured up to the ceiling (followed by a truncated marker record); only the tail beyond it
/// is lost. Long-agent CLI requests resend the full conversation history (reasoning included) and
/// reach 8-15 MiB per single `SSL_write` late in a session, so the ceiling sits at 16 MiB.
pub const SSL_MAX_CAPTURE_LEN: usize = 16 * 1024 * 1024;
pub const SSL_OPERATION_WRITE: u8 = 1;
pub const SSL_OPERATION_READ: u8 = 2;
pub const SSL_OPERATION_WRITE_EX: u8 = 3;
pub const SSL_OPERATION_READ_EX: u8 = 4;
pub const SSL_OPERATION_WRITE_EX2: u8 = 5;
/// Isolated-fixture plaintext read from the exact target Agent process' standard input.
pub const CONTENT_OPERATION_NATIVE_STDIN_READ: u8 = 6;
/// Isolated-fixture EOF marker for the exact target Agent process' standard input.
pub const CONTENT_OPERATION_NATIVE_STDIN_EOF: u8 = 7;
/// Isolated-fixture plaintext written by the exact target Agent process to standard output.
pub const CONTENT_OPERATION_NATIVE_STDOUT_WRITE: u8 = 8;
/// Isolated-fixture process-exit boundary for the exact target Agent process' standard output.
pub const CONTENT_OPERATION_NATIVE_STDOUT_EOF: u8 = 9;
/// Codex/rustls `PlaintextSink::write` bytes observed immediately before TLS encryption.
pub const CONTENT_OPERATION_CODEX_RUSTLS_WRITE: u8 = 10;
/// Codex/rustls `PlaintextSink::write_vectored` bytes observed immediately before TLS encryption.
pub const CONTENT_OPERATION_CODEX_RUSTLS_WRITEV: u8 = 11;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SslEventHeader {
    pub schema_version: u16,
    pub operation: u8,
    pub truncated: u8,
    pub pid: u32,
    pub tid: u32,
    pub captured_len: u32,
    pub fragment_index: u32,
    pub _reserved: u32,
    pub cgroup_id: u64,
    pub ssl_pointer: u64,
    pub call_sequence: u64,
    pub observed_at_monotonic_ns: u64,
    pub original_len: u64,
    pub fragment_offset: u64,
    pub comm: [u8; 16],
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
}

pub const SEC_SETUID: u32 = 1; // setuid/setresuid → euid 0 from a non-root caller (privesc)
pub const SEC_PTRACE: u32 = 2; // ptrace(ATTACH|SEIZE) of another process (injection)
pub const SEC_BIND: u32 = 3; // bind() to a fixed (non-ephemeral) port (opened a listener)
