# a3s-observer

General-purpose, language-agnostic **eBPF** observability for AI agents. Turns
kernel-level events into semantic agent telemetry — which agent made which LLM call,
ran which tools, touched which files, reached which endpoints — **with zero changes to
the agent, across languages**.

> **Status: working collector.** Three eBPF probes — `exec` + TLS-`SNI` + `connect` —
> stream to ring buffers, enriched in userspace with identity (`/proc`) and a
> `(pid,fd)→peer` correlation, then exported as NDJSON (or human log). A single event
> captures **who** (process), **what** (LLM provider), and **where** (peer) for a call.
> Built + validated on Linux (kernel 6.8, bpf-linker 0.10, nightly `build-std`). Additive
> next: OTLP export, k8s identity, DNS, byte/latency metrics, opt-in SSL-payload — see
> [v1 plan](#v1-plan).

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

## Build & run

The eBPF crate needs nightly + `rust-src` + [`bpf-linker`](https://github.com/aya-rs/bpf-linker)
(which borrows rustc's bundled LLVM — **no system LLVM required**):

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker

# build.rs compiles the eBPF crate to BPF bytecode and links it into the collector
cargo build --release -p a3s-observer-collector

# run it (Linux only; needs root / CAP_BPF + CAP_PERFMON)
sudo ./target/release/a3s-observer-collector                          # human-readable log
A3S_OBSERVER_JSON=1 sudo -E ./target/release/a3s-observer-collector   # NDJSON (pipe to vector/Loki/jq)
```

Each event names the agent (process / k8s pod), the tool or LLM provider, and the peer.

Workspace:

| crate | role |
|---|---|
| `a3s-observer` | contracts + data model (`IdentityResolver` / `ServiceClassifier` / `Exporter`) — host-buildable |
| `a3s-observer-common` | `no_std` types shared with eBPF |
| `a3s-observer-ebpf` | the probes, compiled to BPF bytecode |
| `a3s-observer-collector` | loader + correlation + export |

## Export to OpenTelemetry

a3s-observer stays lean: it captures and emits NDJSON. Shipping telemetry — batching,
retry, routing to a backend — is the OpenTelemetry Collector's job, not a privileged
kernel-tracing tool's. So the production pipeline is:

```
capture (a3s-observer)  →  NDJSON  →  OTel Collector (filelog → OTLP)  →  your backend
```

A ready Collector config is in [`deploy/otel-collector.yaml`](deploy/otel-collector.yaml):

```bash
A3S_OBSERVER_JSON=1 sudo -E a3s-observer-collector >> /var/log/a3s-observer.ndjson
OTEL_EXPORTER_OTLP_ENDPOINT=http://otlp-backend:4317 \
    otelcol-contrib --config deploy/otel-collector.yaml
```

Every event is one valid-JSON line (verified: the `filelog` receiver's `json_parser`
ingests them directly), so a3s-observer also drops straight into vector / Loki / `jq`. In
Kubernetes, run a3s-observer as a DaemonSet writing to stdout and let a Collector DaemonSet
tail the node logs. This keeps the always-on probe binary minimal and decoupled from
backend availability; in-process OTLP push is intentionally **not** built — that's the
Collector's job.

## License

MIT
