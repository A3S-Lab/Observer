# a3s-observer

General-purpose, language-agnostic **eBPF** observability for AI agents. Turns
kernel-level events into semantic agent telemetry — which agent made which LLM call,
ran which tools, touched which files, reached which endpoints — **with zero changes to
the agent, across languages**.

> **Status: design + contracts.** This crate currently defines the stable extension
> contracts (`IdentityResolver`, `ServiceClassifier`, `Exporter`) and the data model.
> The eBPF probe set (Aya) is the next milestone — see [v1 plan](#v1-plan).

## Why eBPF (not an SDK / OTel)

- **Zero-instrumentation, language-agnostic** — observe any agent (Python/Node/Go/Rust)
  without touching its code.
- **Sees what the app won't tell you** — real subprocess execs, file I/O, network egress,
  including the agent's tool subprocesses.
- **Security angle** — detect unexpected egress / file access / spawned shells.

## Design decisions

- **Language-agnostic kernel hooks only — no per-language uprobes in v1.** Works on any
  runtime, nothing to maintain per language.
  - Trade-off: **no** LLM prompt / model name / exact token / completion content. Those
    need an opt-in TLS-payload extension (per TLS library) — deliberately **not** in the
    universal core.
- **LLM calls identified via TLS SNI + DNS** (the ClientHello `server_name` is plaintext)
  → provider + endpoint, language-agnostically. Plus flow metrics: req/resp bytes,
  latency, a TTFT proxy (first response byte), frequency. Token/cost = byte-based
  **estimate**.
  - Risk: Encrypted ClientHello (ECH) will eventually hide SNI → fall back to IP/DNS.
- **Full scope:** tool exec + file I/O + network egress + LLM flows.
- **All environments:** Kubernetes, bare host, a3s-box MicroVM — via a pluggable
  `IdentityResolver`.

## Architecture (minimal core + extensions)

Core: eBPF probes → Aya loader → ring buffer → `IdentityResolver` → correlation/spans →
`Exporter`. Everything else is a swappable trait.

Probes (all language-agnostic kernel hooks):

| probe | hook | gives |
|---|---|---|
| `exec` | `sched_process_exec` | tool / subprocess (argv, cwd, uid, ppid) |
| `file` | `openat` / `read` / `write` | file access |
| `flow` | `connect` / `sendmsg` / `recvmsg` | connections, bytes, latency |
| `sni`  | parse outbound TLS ClientHello | LLM provider identification |
| `dns`  | UDP:53 | hostnames |

Extensions (trait, swappable, degrade gracefully):
- `IdentityResolver` — k8s (cgroup→pod) / docker / a3s-box / bare pid-tree
- `ServiceClassifier` — SNI/IP → `Provider`
- `Exporter` — OTel (default target) / Prometheus / log
- *(deferred, opt-in)* TLS-payload provider — for model/tokens/prompt, per TLS library

## a3s-box note

Each box is a separate guest kernel, so **host-side eBPF can't see guest syscalls**
(exec/file). The **network layer** works host-side (box egress flows through the host
net path → SNI/flow). **file/exec inside a box need in-guest eBPF** (guest kernel built
with BPF + collector in-guest) — phase 2.

## v1 plan

1. Host-side collector: `exec + file + flow + SNI + DNS` (bare host / k8s) → OTel.
2. `IdentityResolver`: pid-tree + k8s.
3. `ServiceClassifier`: SNI → major providers.
4. a3s-box: host-side network attribution first; in-guest file/exec as phase 2.

Stack: Rust + [Aya](https://aya-rs.dev) (CO-RE for portability). The eBPF programs will
live in a sibling `a3s-observer-ebpf` crate (added with the probes); shared kernel/user
types in `a3s-observer-common`.

## License

MIT
