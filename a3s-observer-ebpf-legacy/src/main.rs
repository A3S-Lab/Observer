#![no_std]
#![no_main]

use a3s_observer_common::{
    ConnectEvent, ExecEvent, ExitEvent, FileEvent, SecEvent, ARGV_SLOTS, ARG_LEN, FILE_DELETE_FLAG,
    PATH_SNAP_LEN, SEC_BIND, SEC_PTRACE, SEC_SETUID,
};
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        gen::{bpf_probe_read, bpf_probe_read_str},
    },
    macros::{kprobe, map},
    maps::{PerCpuArray, PerfEventArray},
    programs::ProbeContext,
};

#[map]
static EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);
#[map]
static EXIT_EVENTS: PerfEventArray<ExitEvent> = PerfEventArray::new(0);
#[map]
static CONNECT_EVENTS: PerfEventArray<ConnectEvent> = PerfEventArray::new(0);
#[map]
static FILE_EVENTS: PerfEventArray<FileEvent> = PerfEventArray::new(0);
#[map]
static SEC_EVENTS: PerfEventArray<SecEvent> = PerfEventArray::new(0);

// ExecEvent is larger than the 512-byte BPF stack. Per-CPU scratch slots also keep concurrent
// events isolated without requiring map locks on the target's 16 CPUs.
#[map]
static EXEC_SCRATCH: PerCpuArray<ExecEvent> = PerCpuArray::with_max_entries(1, 0);
#[map]
static EXIT_SCRATCH: PerCpuArray<ExitEvent> = PerCpuArray::with_max_entries(1, 0);
#[map]
static CONNECT_SCRATCH: PerCpuArray<ConnectEvent> = PerCpuArray::with_max_entries(1, 0);
#[map]
static FILE_SCRATCH: PerCpuArray<FileEvent> = PerCpuArray::with_max_entries(1, 0);
#[map]
static SEC_SCRATCH: PerCpuArray<SecEvent> = PerCpuArray::with_max_entries(1, 0);
#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

fn dropped() {
    unsafe {
        if let Some(value) = DROPS.get_ptr_mut(0) {
            *value = (*value).wrapping_add(1);
        }
    }
}

unsafe fn read_value(src: u64) -> Option<u64> {
    let mut value = 0u64;
    (bpf_probe_read(
        &mut value as *mut _ as *mut core::ffi::c_void,
        8,
        src as *const core::ffi::c_void,
    ) == 0)
        .then_some(value)
}

unsafe fn read_bytes(src: u64, dst: *mut u8, len: u32) -> bool {
    bpf_probe_read(
        dst as *mut core::ffi::c_void,
        len,
        src as *const core::ffi::c_void,
    ) == 0
}

unsafe fn read_string(src: u64, dst: *mut u8, len: u32) {
    let _ = bpf_probe_read_str(
        dst as *mut core::ffi::c_void,
        len,
        src as *const core::ffi::c_void,
    );
}

// Linux ARM64 syscall wrappers receive one `struct pt_regs *`; x0..x5 are the syscall arguments.
fn syscall_arg(ctx: &ProbeContext, index: usize) -> Option<u64> {
    let regs = ctx.arg::<u64>(0)?;
    unsafe { read_value(regs + (index as u64 * 8)) }
}

#[kprobe]
pub fn legacy_exec(ctx: ProbeContext) -> u32 {
    try_exec(&ctx).unwrap_or(0)
}

fn try_exec(ctx: &ProbeContext) -> Result<u32, i64> {
    let filename = syscall_arg(ctx, 0).unwrap_or(0);
    let argv = syscall_arg(ctx, 1).unwrap_or(0);
    if filename == 0 {
        return Ok(0);
    }
    let Some(ev) = EXEC_SCRATCH.get_ptr_mut(0) else {
        dropped();
        return Ok(0);
    };
    unsafe {
        let id = bpf_get_current_pid_tgid();
        (*ev).pid = (id >> 32) as u32;
        (*ev).ppid = 0;
        (*ev).uid = bpf_get_current_uid_gid() as u32;
        (*ev).argc = 0;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        (*ev).filename = [0; 128];
        (*ev).args = [[0; ARG_LEN]; ARGV_SLOTS];
        read_string(filename, (*ev).filename.as_mut_ptr(), 128);
        if argv != 0 {
            for i in 0..ARGV_SLOTS {
                let Some(arg) = read_value(argv + (i as u64 * 8)) else {
                    break;
                };
                if arg == 0 {
                    break;
                }
                read_string(arg, (*ev).args[i].as_mut_ptr(), ARG_LEN as u32);
                (*ev).argc += 1;
            }
        }
        EVENTS.output(ctx, &*ev, 0);
    }
    Ok(0)
}

#[kprobe]
pub fn legacy_exit(ctx: ProbeContext) -> u32 {
    let id = bpf_get_current_pid_tgid();
    if (id >> 32) as u32 != id as u32 {
        return 0;
    }
    let Some(ev) = EXIT_SCRATCH.get_ptr_mut(0) else {
        dropped();
        return 0;
    };
    let code = ctx.arg::<u64>(0).unwrap_or(0);
    unsafe {
        (*ev).pid = (id >> 32) as u32;
        (*ev).exit_code = ((code >> 8) & 0xff) as u32;
        (*ev).signal = (code & 0x7f) as u32;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        EXIT_EVENTS.output(&ctx, &*ev, 0);
    }
    0
}

#[kprobe]
pub fn legacy_connect(ctx: ProbeContext) -> u32 {
    let fd = syscall_arg(&ctx, 0).unwrap_or(0);
    let sockaddr = syscall_arg(&ctx, 1).unwrap_or(0);
    let addrlen = syscall_arg(&ctx, 2).unwrap_or(0);
    if sockaddr == 0 || addrlen < 8 {
        return 0;
    }
    let mut family_bytes = [0u8; 2];
    if !unsafe { read_bytes(sockaddr, family_bytes.as_mut_ptr(), 2) } {
        return 0;
    }
    let family = u16::from_ne_bytes(family_bytes);
    if family != 2 && family != 10 {
        return 0;
    }
    let Some(ev) = CONNECT_SCRATCH.get_ptr_mut(0) else {
        dropped();
        return 0;
    };
    unsafe {
        (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev).fd = fd as u32;
        (*ev).family = family;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        let mut port = [0u8; 2];
        let _ = read_bytes(sockaddr + 2, port.as_mut_ptr(), 2);
        (*ev).port = u16::from_be_bytes(port);
        (*ev).addr = [0; 16];
        let offset = if family == 2 { 4 } else { 8 };
        let len = if family == 2 { 4 } else { 16 };
        let _ = read_bytes(sockaddr + offset, (*ev).addr.as_mut_ptr(), len);
        CONNECT_EVENTS.output(&ctx, &*ev, 0);
    }
    0
}

fn emit_file(ctx: &ProbeContext, path: u64, flags: u32) {
    if path == 0 {
        return;
    }
    let Some(ev) = FILE_SCRATCH.get_ptr_mut(0) else {
        dropped();
        return;
    };
    unsafe {
        (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev).flags = flags;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        (*ev).path = [0; PATH_SNAP_LEN];
        read_string(path, (*ev).path.as_mut_ptr(), PATH_SNAP_LEN as u32);
        FILE_EVENTS.output(ctx, &*ev, 0);
    }
}

#[kprobe]
pub fn legacy_openat(ctx: ProbeContext) -> u32 {
    let path = syscall_arg(&ctx, 1).unwrap_or(0);
    let flags = syscall_arg(&ctx, 2).unwrap_or(0) as u32;
    if flags & 0x3 != 0 {
        emit_file(&ctx, path, flags);
    }
    0
}

#[kprobe]
pub fn legacy_unlinkat(ctx: ProbeContext) -> u32 {
    emit_file(&ctx, syscall_arg(&ctx, 1).unwrap_or(0), FILE_DELETE_FLAG);
    0
}

fn emit_security(ctx: &ProbeContext, kind: u32, detail: u64) {
    let Some(ev) = SEC_SCRATCH.get_ptr_mut(0) else {
        dropped();
        return;
    };
    unsafe {
        (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev).kind = kind;
        (*ev).detail = detail;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        SEC_EVENTS.output(ctx, &*ev, 0);
    }
}

#[kprobe]
pub fn legacy_setuid(ctx: ProbeContext) -> u32 {
    let target = syscall_arg(&ctx, 0).unwrap_or(u64::MAX) as u32;
    if target == 0 && bpf_get_current_uid_gid() as u32 != 0 {
        emit_security(&ctx, SEC_SETUID, 0);
    }
    0
}

#[kprobe]
pub fn legacy_ptrace(ctx: ProbeContext) -> u32 {
    let request = syscall_arg(&ctx, 0).unwrap_or(0);
    if request == 16 || request == 0x4206 {
        emit_security(&ctx, SEC_PTRACE, syscall_arg(&ctx, 1).unwrap_or(0));
    }
    0
}

#[kprobe]
pub fn legacy_bind(ctx: ProbeContext) -> u32 {
    let sockaddr = syscall_arg(&ctx, 1).unwrap_or(0);
    if sockaddr != 0 {
        let mut port = [0u8; 2];
        if unsafe { read_bytes(sockaddr + 2, port.as_mut_ptr(), 2) } {
            let port = u16::from_be_bytes(port);
            if port != 0 {
                emit_security(&ctx, SEC_BIND, port as u64);
            }
        }
    }
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
