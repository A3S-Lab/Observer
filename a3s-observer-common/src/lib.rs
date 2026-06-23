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
}
