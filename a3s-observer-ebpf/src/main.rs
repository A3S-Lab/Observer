#![no_std]
#![no_main]

use a3s_observer_common::{ConnectEvent, ExecEvent, TlsEvent, TLS_SNAP_LEN};
use aya_ebpf::{
    helpers::gen::bpf_probe_read_user,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static TLS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static CONNECT_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// ---- tool / subprocess exec (sys_enter_execve) ----

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
        (*ev).ppid = 0;
        (*ev).comm = bpf_get_current_comm().unwrap_or_default();
        (*ev).filename = [0u8; 128];
        // sys_enter_execve: `const char *filename` at offset 16.
        if let Ok(filename_ptr) = ctx.read_at::<*const u8>(16) {
            let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut (*ev).filename);
        }
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
    let Some(mut entry) = TLS_EVENTS.reserve::<TlsEvent>(0) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev)._pad = 0;
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

// ---- outbound connection peer (sys_enter_connect) ----

#[tracepoint]
pub fn connect(ctx: TracePointContext) -> u32 {
    try_connect(&ctx).unwrap_or(0)
}

fn try_connect(ctx: &TracePointContext) -> Result<u32, i64> {
    // sys_enter_connect: int fd @16, struct sockaddr *uservaddr @24, int addrlen @32.
    let addr_ptr: *const u8 = unsafe { ctx.read_at(24)? };
    let addrlen: u64 = unsafe { ctx.read_at(32)? };
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
    let Some(mut entry) = CONNECT_EVENTS.reserve::<ConnectEvent>(0) else {
        return Ok(0);
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*ev).family = family;
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
