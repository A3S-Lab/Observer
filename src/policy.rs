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

use crate::traits::{Identity, Provider, ServiceClassifier, SniClassifier};
use std::net::{IpAddr, Ipv4Addr};

/// Parse an egress-policy file body — the external interface's input contract. One entry per
/// line (`#` comments + blank lines ignored); each is either a literal IPv4 or a hostname.
/// Returns `(literal_ips, hostnames)`; the enforcer resolves the hostnames and denies every
/// resulting dest IP. Pure + testable (no kernel, no DNS), so the file format is CI-covered.
pub fn parse_egress_policy(body: &str) -> (Vec<Ipv4Addr>, Vec<String>) {
    let mut ips = Vec::new();
    let mut hosts = Vec::new();
    for line in body.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        match s.parse::<Ipv4Addr>() {
            Ok(ip) => ips.push(ip),
            Err(_) => hosts.push(s.to_owned()),
        }
    }
    (ips, hosts)
}

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

/// An egress allow-list **by LLM provider** — observer's side of agentfw's "keep the agent on
/// approved models, off the unapproved API relay / supply chain". Each outbound connection is
/// classified by a [`ServiceClassifier`] (SNI → [`Provider`]) and **denied unless its provider is on
/// the allow-list**; observer's `connect4`/cgroup guard enforces the deny in-kernel. Egress-only —
/// file/exec stay fail-open. This is the in-process counterpart to driving the egress deny-file from
/// an external controller (e.g. a3s-sentry), and the proactive complement to sentry's *reactive*
/// per-destination denies: only approved providers are ever reachable in the first place.
pub struct ProviderPolicy<C: ServiceClassifier = SniClassifier> {
    classifier: C,
    allowed: Vec<Provider>,
    deny_unclassified: bool,
}

impl ProviderPolicy<SniClassifier> {
    /// Allow-list these providers, classifying egress with the default [`SniClassifier`].
    pub fn new(allowed: impl IntoIterator<Item = Provider>) -> Self {
        Self::with_classifier(SniClassifier, allowed)
    }
}

impl<C: ServiceClassifier> ProviderPolicy<C> {
    /// Allow-list these providers, classifying with a custom [`ServiceClassifier`].
    pub fn with_classifier(classifier: C, allowed: impl IntoIterator<Item = Provider>) -> Self {
        Self {
            classifier,
            allowed: allowed.into_iter().collect(),
            deny_unclassified: false,
        }
    }

    /// Also deny egress that matches **no** known provider — a strict "approved LLM providers only"
    /// cage. Default off, so unknown destinations (package mirrors, telemetry, your own APIs) still
    /// pass; turn on when the agent should reach nothing but its allow-listed models.
    pub fn deny_unclassified(mut self, yes: bool) -> Self {
        self.deny_unclassified = yes;
        self
    }
}

impl<C: ServiceClassifier> Policy for ProviderPolicy<C> {
    fn egress(&self, _id: &Identity, sni: Option<&str>, peer: IpAddr) -> Verdict {
        match self.classifier.classify(sni, peer) {
            // A known provider — allow iff it's on the list.
            Some(p) if self.allowed.contains(&p) => Verdict::Allow,
            Some(_) => Verdict::Deny,
            // Unclassified destination — gate per the strict-cage knob.
            None if self.deny_unclassified => Verdict::Deny,
            None => Verdict::Allow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_never_blocks() {
        let id = Identity::default();
        let ip = IpAddr::from([0, 0, 0, 0]);
        assert_eq!(AllowAll.egress(&id, Some("evil.com"), ip), Verdict::Allow);
        assert_eq!(AllowAll.file_write(&id, "/etc/passwd"), Verdict::Allow);
    }

    #[test]
    fn provider_policy_allows_listed_denies_other_providers() {
        let p = ProviderPolicy::new([Provider::Anthropic, Provider::OpenAi]);
        let id = Identity::default();
        let ip = IpAddr::from([0, 0, 0, 0]);
        // allow-listed provider → allow
        assert_eq!(p.egress(&id, Some("api.anthropic.com"), ip), Verdict::Allow);
        // a *known* provider not on the list → deny (an unapproved model/relay)
        assert_eq!(p.egress(&id, Some("api.deepseek.com"), ip), Verdict::Deny);
        // unclassified destination → allow by default (don't cut non-LLM traffic)
        assert_eq!(p.egress(&id, Some("github.com"), ip), Verdict::Allow);
        // egress-only: file/exec still fail-open
        assert_eq!(p.file_write(&id, "/tmp/x"), Verdict::Allow);
    }

    #[test]
    fn provider_policy_strict_cage_denies_unclassified() {
        let p = ProviderPolicy::new([Provider::Anthropic]).deny_unclassified(true);
        let id = Identity::default();
        let ip = IpAddr::from([0, 0, 0, 0]);
        assert_eq!(p.egress(&id, Some("api.anthropic.com"), ip), Verdict::Allow);
        // strict cage: anything that isn't an approved provider — incl. unknown hosts — is denied
        assert_eq!(p.egress(&id, Some("github.com"), ip), Verdict::Deny);
        assert_eq!(p.egress(&id, None, ip), Verdict::Deny);
    }

    #[test]
    fn parses_egress_policy_file() {
        let (ips, hosts) =
            parse_egress_policy("# deny list\n1.1.1.1\n\n  evil.example.com \n8.8.8.8\n");
        assert_eq!(
            ips,
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]
        );
        assert_eq!(hosts, vec!["evil.example.com".to_string()]);
    }
}
