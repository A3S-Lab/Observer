//! Contract for the **opt-in enforcement extension** (intervention) — see
//! `docs/enforcement.md`. The observer core never enforces; this is the seam an *external*
//! policy plugs into.
//!
//! An external policy can be implemented two ways, both producing the same [`Verdict`]s:
//! - **in-process** — a Rust `impl Policy` (like [`IdentityResolver`](crate::IdentityResolver));
//! - **out-of-process / language-agnostic** — a separate controller that consumes the event
//!   stream and drives the enforcement eBPF's policy maps through a control API.
//!
//! The verdicts here are compiled into in-kernel policy maps that the (separate, phase-2)
//! enforcement eBPF (LSM / TC) reads inline — eBPF can't do a userspace round-trip per
//! syscall. Default is fail-open ([`AllowAll`]): never block unless a policy opts in.

use crate::traits::Identity;
use std::net::IpAddr;

/// A decision for an action before it happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
}

/// External enforcement policy. All methods default to [`Verdict::Allow`] (fail-open), so an
/// implementer overrides only the actions it wants to gate.
pub trait Policy: Send + Sync {
    /// May this agent open a connection to `sni` / `peer`? (TC egress / cgroup-connect.)
    fn egress(&self, _id: &Identity, _sni: Option<&str>, _peer: IpAddr) -> Verdict {
        Verdict::Allow
    }
    /// May this agent open `path` for writing? (LSM `file_open`.)
    fn file_write(&self, _id: &Identity, _path: &str) -> Verdict {
        Verdict::Allow
    }
    /// May this agent exec `argv`? (LSM `bprm_check_security`.)
    fn exec(&self, _id: &Identity, _argv: &[String]) -> Verdict {
        Verdict::Allow
    }
}

/// The shipped default — never blocks. Enforcement is strictly opt-in.
pub struct AllowAll;
impl Policy for AllowAll {}

#[cfg(test)]
mod tests {
    use super::*;

    // A sample external policy: an egress allowlist (fail-closed for egress only).
    struct ProviderAllowlist(&'static [&'static str]);
    impl Policy for ProviderAllowlist {
        fn egress(&self, _id: &Identity, sni: Option<&str>, _peer: IpAddr) -> Verdict {
            match sni {
                Some(h) if self.0.iter().any(|a| h.ends_with(a)) => Verdict::Allow,
                _ => Verdict::Deny,
            }
        }
    }

    #[test]
    fn allow_all_never_blocks() {
        let id = Identity::default();
        let ip = IpAddr::from([0, 0, 0, 0]);
        assert_eq!(AllowAll.egress(&id, Some("evil.com"), ip), Verdict::Allow);
        assert_eq!(AllowAll.file_write(&id, "/etc/passwd"), Verdict::Allow);
    }

    #[test]
    fn external_allowlist_gates_egress_only() {
        let p = ProviderAllowlist(&["anthropic.com", "openai.com"]);
        let id = Identity::default();
        let ip = IpAddr::from([0, 0, 0, 0]);
        assert_eq!(p.egress(&id, Some("api.anthropic.com"), ip), Verdict::Allow);
        assert_eq!(p.egress(&id, Some("evil.example.com"), ip), Verdict::Deny);
        // non-egress actions still default to allow
        assert_eq!(p.file_write(&id, "/tmp/x"), Verdict::Allow);
    }
}
