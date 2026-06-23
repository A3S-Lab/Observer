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
