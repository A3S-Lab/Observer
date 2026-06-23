//! a3s-observer-fileguard — OPT-IN file-access intervention via fanotify `FAN_OPEN_PERM`.
//!
//! Marks each file path listed in the policy and denies `open()` of it (EPERM). Marking the
//! specific files (not the whole mount) is deliberate: a mount-wide `FAN_MARK_MOUNT` perm
//! guard gates *every* open on the filesystem, including system services' own I/O, and can
//! wedge them. The eBPF-native equivalent would be LSM `file_open`, but `bpf` is not in this
//! kernel's `lsm=` set (would need a custom boot cmdline); fanotify is stock-kernel and
//! userspace-policy-driven — the same external-intervention model as the egress guard.
//!
//!   sudo a3s-observer-fileguard <policy-file>   # one file path per line to deny
//!
//! ponytail: exact-file marks. Blocking a whole subtree by prefix needs FAN_MARK_MOUNT +
//! path filtering, which gates the entire mount — add that only if a real use case needs it.

use anyhow::{anyhow, Context as _};
use std::fs;

const FAN_DENY: u32 = 0x02;

fn main() -> anyhow::Result<()> {
    let policy_path = std::env::args()
        .nth(1)
        .context("usage: a3s-observer-fileguard <policy-file>")?;
    let deny = load_policy(&policy_path);
    if deny.is_empty() {
        return Err(anyhow!("no file paths in policy {policy_path}"));
    }

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

    let mut marked = 0usize;
    for p in &deny {
        let c = std::ffi::CString::new(p.as_str())?;
        let rc = unsafe {
            libc::fanotify_mark(
                fan,
                libc::FAN_MARK_ADD,
                libc::FAN_OPEN_PERM,
                libc::AT_FDCWD,
                c.as_ptr(),
            )
        };
        if rc == 0 {
            marked += 1;
        } else {
            eprintln!("warn: cannot mark {p}: {}", std::io::Error::last_os_error());
        }
    }
    eprintln!(
        "a3s-observer-fileguard: denying open() of {marked}/{} file(s) from {policy_path}",
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
            // read_unaligned: the byte buffer isn't 8-aligned, so a &reference would be UB.
            let meta = unsafe {
                std::ptr::read_unaligned(
                    buf.as_ptr().add(off) as *const libc::fanotify_event_metadata
                )
            };
            if meta.vers != libc::FANOTIFY_METADATA_VERSION {
                break;
            }
            if meta.mask & u64::from(libc::FAN_OPEN_PERM) != 0 && meta.fd >= 0 {
                // Only denied files are marked, so every permission event is a denial.
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
                eprintln!("[fileguard] DENY open {path}");
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
