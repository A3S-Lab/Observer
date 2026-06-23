# Enforcement (design) — opt-in, externally-implemented intervention

a3s-observer **observes**. This is the design for *optional* intervention (block / redirect),
kept strictly separate so the observer core stays passive and safe.

## Why separate (first principles)

Observation is passive and read-only — tracepoints → ring buffers **cannot block**.
Enforcement is security-critical: a bug blocks legitimate traffic or breaks the agent, and it
needs fail-open/closed semantics + a policy engine. Per "minimal core + external extensions",
enforcement is an **opt-in extension**, never baked into the observer's blast radius.

## Mechanism (what the core extension would provide)

eBPF *can* enforce — but via different hooks than the observer's tracepoints:

| Intervention | eBPF hook | Effect |
|---|---|---|
| Block file open/write | **LSM-BPF** `lsm/file_open`, `lsm/path_*` | return `-EPERM` |
| Block exec | **LSM-BPF** `lsm/bprm_check_security` | return `-EPERM` |
| Block / redirect egress | **TC** egress or **cgroup/connect4** | drop / RST / redirect by SNI or peer |
| Drop at the NIC | **XDP** | drop before the stack |

Honest caveat: you can **drop / RST / redirect** a connection, but you **cannot modify
encrypted (TLS) payload** — it's encrypted. Only plaintext (pre-TLS / non-TLS) is rewritable
via TC, which is rarely useful. LSM hooks need `CONFIG_BPF_LSM` (kernel ≥ 5.7).

## External policy (the pluggable part)

eBPF can't do a userspace round-trip per syscall (too slow to block inline). So the split is:

```
external policy  ──writes──▶  BPF policy maps  ──inline lookup──▶  enforcement eBPF
(allow/deny rules)            (keyed by cgroup / SNI / path)        (LSM / TC) → allow | deny
```

The **policy lives outside the core** — two ways to implement it, both first-class:

1. **In-process** — a Rust `Policy` trait impl (mirrors `IdentityResolver` / `Exporter`):
   ```rust
   pub enum Verdict { Allow, Deny }
   pub trait Policy: Send + Sync {
       fn egress(&self, id: &Identity, sni: Option<&str>, peer: IpAddr) -> Verdict;
       fn file_write(&self, id: &Identity, path: &str) -> Verdict;
       fn exec(&self, id: &Identity, argv: &[String]) -> Verdict;
   }
   ```
   The enforcer compiles verdicts into policy-map entries the eBPF reads inline.

2. **Out-of-process (fully external / language-agnostic)** — a separate controller consumes
   the observer's existing event stream (NDJSON / OTel) and pushes verdicts through a
   **control API** (CLI / unix-socket / gRPC that updates the policy maps). The policy engine
   (OPA/Rego, a service, your own code in any language) lives entirely outside the binary; the
   core only enforces what the maps say. **This is the "外部实现" path** — see
   [`scripts/example-controller.py`](../scripts/example-controller.py) for a worked example
   (NDJSON event stream → provider allow-list policy → enforcer deny-file).

Default policy = `AllowAll` (fail-open — never break an agent unless a rule opts in).

## Fail-safe

- **fail-open** (default): unknown → allow. Observability-first; never break the agent.
- **fail-closed**: unknown → deny (e.g., an egress allowlist). Security-first; opt-in per rule.

Every deny is *also* emitted as an observed event, so enforcement is auditable.

## Staged plan (same shape the observer was built)

1. Contract + this design + `Policy` / `Verdict` (the seam).
2. PoC: TC-egress **SNI allowlist** — drop the ClientHello to non-approved providers, driven
   by a policy map. Validate on a **non-prod box**.
3. PoC: LSM `file_open` deny for a path policy.
4. Control API for the out-of-process policy path (the language-agnostic external engine).
5. Harden: fail-safe semantics, per-cgroup scoping, audit-every-deny.

> Enforcement must be validated on a **non-prod box** — blocking real syscalls/egress on a
> shared prod node is unacceptable. The validation is codified in
> [`scripts/validate-enforcement.sh`](../scripts/validate-enforcement.sh) (egress block →
> control connects → scoping → fail-open); run it there, then tag v0.3.0.
