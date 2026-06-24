//! a3s-observer-fileguard — OPT-IN file/exec access intervention via fanotify.
//!
//! Denies `open()` **and** `exec` of the files listed in an external policy file
//! (`FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM` → `EPERM`). It marks the specific listed files (not
//! the whole mount — a mount-wide perm guard gates all system I/O and can wedge services), and
//! it **hot-reloads** the policy every ~2s, so an external controller can add/remove denials
//! live (same model as the egress enforcer).
//!
//! This covers both the file ("阻止文件读写") and exec ("阻止执行") intervention via one
//! stock-kernel mechanism — the eBPF-native equivalents (LSM `file_open`/`bprm`) need `bpf` in
//! the kernel's `lsm=` set, which isn't enabled by default. fanotify is userspace-policy-driven.
//!
//!   sudo a3s-observer-fileguard <policy-file>   # one path per line; denies open + exec of each

use anyhow::{anyhow, Context as _};
use std::collections::HashSet;
use std::fs;
use std::time::{Duration, Instant};

const FAN_DENY: u32 = 0x02;

fn perm_mask() -> u64 {
    u64::from(libc::FAN_OPEN_PERM) | u64::from(libc::FAN_OPEN_EXEC_PERM)
}

fn main() -> anyhow::Result<()> {
    let policy_path = std::env::args()
        .nth(1)
        .context("usage: a3s-observer-fileguard <policy-file>")?;

    // FAN_NONBLOCK so the read drains without blocking; we poll() with a timeout to interleave
    // event handling with periodic policy reloads.
    let fan = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
            libc::O_RDONLY as u32,
        )
    };
    if fan < 0 {
        return Err(anyhow!(
            "fanotify_init failed (needs root/CAP_SYS_ADMIN): {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut marked: HashSet<String> = HashSet::new();
    reload(fan, &policy_path, &mut marked);
    eprintln!(
        "a3s-observer-fileguard: denying open()+exec of {} file(s) from {policy_path} (hot-reload 2s)",
        marked.len()
    );

    let mut pollfd = libc::pollfd {
        fd: fan,
        events: libc::POLLIN,
        revents: 0,
    };
    let mut buf = [0u8; 8192];
    let mut last_reload = Instant::now();
    loop {
        let r = unsafe { libc::poll(&mut pollfd, 1, 500) };
        if r > 0 && pollfd.revents & libc::POLLIN != 0 {
            drain(fan, &mut buf);
        }
        if last_reload.elapsed() >= Duration::from_secs(2) {
            reload(fan, &policy_path, &mut marked);
            last_reload = Instant::now();
        }
    }
}

/// Add/remove fanotify marks to match the policy file (called at startup and on each reload).
fn reload(fan: i32, path: &str, marked: &mut HashSet<String>) {
    let want: HashSet<String> = load_policy(path).into_iter().collect();
    let add: Vec<String> = want.difference(marked).cloned().collect();
    let remove: Vec<String> = marked.difference(&want).cloned().collect();
    for p in &add {
        if mark(fan, libc::FAN_MARK_ADD, p) {
            eprintln!("[fileguard] guard {p}");
        } else {
            eprintln!("warn: cannot mark {p}: {}", std::io::Error::last_os_error());
        }
    }
    for p in &remove {
        mark(fan, libc::FAN_MARK_REMOVE, p);
        eprintln!("[fileguard] unguard {p}");
    }
    *marked = want;
}

fn mark(fan: i32, flags: u32, path: &str) -> bool {
    let Ok(c) = std::ffi::CString::new(path) else {
        return false;
    };
    unsafe { libc::fanotify_mark(fan, flags, perm_mask(), libc::AT_FDCWD, c.as_ptr()) == 0 }
}

/// Drain all pending permission events, denying each (only guarded files are marked).
fn drain(fan: i32, buf: &mut [u8]) {
    let meta_sz = std::mem::size_of::<libc::fanotify_event_metadata>();
    loop {
        let n = unsafe { libc::read(fan, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break; // EAGAIN (drained) or error
        }
        let mut off = 0usize;
        while off + meta_sz <= n as usize {
            let meta = unsafe {
                std::ptr::read_unaligned(
                    buf.as_ptr().add(off) as *const libc::fanotify_event_metadata
                )
            };
            if meta.vers != libc::FANOTIFY_METADATA_VERSION {
                break;
            }
            if meta.mask & perm_mask() != 0 && meta.fd >= 0 {
                let resp = libc::fanotify_response {
                    fd: meta.fd,
                    response: FAN_DENY,
                };
                unsafe {
                    libc::write(
                        fan,
                        &resp as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::fanotify_response>(),
                    );
                }
                let path = fs::read_link(format!("/proc/self/fd/{}", meta.fd))
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let kind = if meta.mask & u64::from(libc::FAN_OPEN_EXEC_PERM) != 0 {
                    "exec"
                } else {
                    "open"
                };
                eprintln!("[fileguard] DENY {kind} {path}");
            }
            if meta.fd >= 0 {
                unsafe { libc::close(meta.fd) };
            }
            off += meta.event_len as usize;
        }
    }
}

fn load_policy(path: &str) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}
