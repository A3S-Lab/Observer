#![no_std]
#![no_main]

use a3s_observer_common::ExecEvent;
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

/// Ring buffer carrying `ExecEvent`s to userspace (256 KiB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn exec(ctx: TracePointContext) -> u32 {
    try_exec(&ctx).unwrap_or(0)
}

fn try_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        let pid_tgid = bpf_get_current_pid_tgid();
        (*ev).pid = (pid_tgid >> 32) as u32;
        (*ev).uid = bpf_get_current_uid_gid() as u32;
        (*ev).ppid = 0; // task_struct->real_parent->tgid comes later; 0 for the slice
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        (*ev).filename = [0u8; 128];
        // sys_enter_execve layout: `const char *filename` lives at offset 16.
        if let Ok(filename_ptr) = ctx.read_at::<*const u8>(16) {
            let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut (*ev).filename);
        }
    }
    entry.submit(0);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
