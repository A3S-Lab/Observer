//! a3s-observer-fileguard — OPT-IN file-access intervention via fanotify `FAN_OPEN_PERM`.
//!
//! The eBPF-native path (LSM `file_open`) needs `bpf` in the kernel's `lsm=` set, which is
//! not enabled by default (checked: `lockdown,capability,landlock,yama,apparmor`). fanotify
//! works on a stock kernel and is userspace-policy-driven — the same external-intervention
//! model: the policy lives outside (a plain deny-prefix file any controller writes), the
//! kernel asks this guard ALLOW/DENY per open. See `docs/enforcement.md`.
//!
//!   sudo a3s-observer-fileguard <watch-path> <policy-file>
//!
//! `<policy-file>`: one path prefix per line (`#` comments); an open whose resolved path
//! starts with any prefix is denied (EPERM). Fail-open on anything else.

use anyhow::{anyhow, Context as _};
use std::fs;

const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: a3s-observer-fileguard <watch-path> <policy-file>";
    let watch = args.next().context(usage)?;
    let policy_path = args.next().context(usage)?;

    // FAN_CLASS_CONTENT enables permission (allow/deny) events.
    let fan = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC,
            libc::O_RDONLY as u32,
        )
    };
    if fan < 0 {
        return Err(anyhow!(
            "fanotify_init failed (needs root/CAP_SYS_ADMIN): {}",
            std::io::Error::last_os_error()
        ));
    }
    // Read the policy BEFORE marking: once the mount is marked, any open on it (including this
    // process's own) is gated until the read loop responds — opening the policy file after the
    // mark would deadlock. ponytail: read-once; restart to reload, add mtime-poll if needed.
    let deny = load_policy(&policy_path);
    // Watch the whole mount of `watch`; we filter by path against the policy.
    let cpath = std::ffi::CString::new(watch.clone())?;
    let rc = unsafe {
        libc::fanotify_mark(
            fan,
            libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
            libc::FAN_OPEN_PERM,
            libc::AT_FDCWD,
            cpath.as_ptr(),
        )
    };
    if rc < 0 {
        return Err(anyhow!(
            "fanotify_mark {watch} failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    eprintln!(
        "a3s-observer-fileguard: FAN_OPEN_PERM on mount of {watch}; {} deny-prefixes from {policy_path}",
        deny.len()
    );

    let mut buf = [0u8; 8192];
    loop {
        let n = unsafe { libc::read(fan, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        let mut off = 0usize;
        let meta_sz = std::mem::size_of::<libc::fanotify_event_metadata>();
        while off + meta_sz <= n as usize {
            let meta = unsafe { &*(buf.as_ptr().add(off) as *const libc::fanotify_event_metadata) };
            if meta.vers != libc::FANOTIFY_METADATA_VERSION {
                break;
            }
            if meta.mask & u64::from(libc::FAN_OPEN_PERM) != 0 && meta.fd >= 0 {
                let path = fs::read_link(format!("/proc/self/fd/{}", meta.fd))
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let denied = deny.iter().any(|d| path.starts_with(d.as_str()));
                let resp = libc::fanotify_response {
                    fd: meta.fd,
                    response: if denied { FAN_DENY } else { FAN_ALLOW },
                };
                unsafe {
                    libc::write(
                        fan,
                        &resp as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::fanotify_response>(),
                    );
                }
                if denied {
                    eprintln!("[fileguard] DENY open {path}");
                }
            }
            if meta.fd >= 0 {
                unsafe { libc::close(meta.fd) };
            }
            off += meta.event_len as usize;
        }
    }
    Ok(())
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
