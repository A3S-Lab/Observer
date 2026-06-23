//! Types shared between the eBPF programs (kernel side) and the userspace collector.
//!
//! `no_std` + `repr(C)` plain-old-data so a value can cross the ring buffer unchanged.

#![no_std]

/// A process / tool execution, captured at `sys_enter_execve`.
///
/// This is the language-agnostic "tool ran" signal — AgentSight's flagship is catching
/// subprocesses that bypass app-level instrumentation, and this is how we see them.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 128],
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
