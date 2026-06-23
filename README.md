# a3s-observer

General-purpose, language-agnostic **eBPF** observability for AI agents. Turns
kernel-level events into semantic agent telemetry — which agent made which LLM call,
ran which tools, touched which files, reached which endpoints — **with zero changes to
the agent, across languages**.

> **Status: production-ready collector.** Probes — `exec`, TLS-`SNI`, `connect`, `dns`
> (incl. `sendmsg`/`sendmmsg`), `file` (writes), and per-socket LLM metrics — stream to ring
> buffers, enriched in userspace with identity (k8s cgroup→pod, `/proc`, or in-kernel
> `comm`) and a `(pid,fd)→peer` correlation, then exported as NDJSON (or human log). A
> single event captures **who** (process / pod), **what** (tool, file, or LLM provider +
> req/resp bytes + latency + TTFT), and **where** (peer). Built + validated on Linux
> (kernel 6.8, bpf-linker 0.10, nightly `build-std`). OpenTelemetry via the Collector
> ([config](deploy/otel-collector.yaml)). Roadmap: opt-in SSL-payload (prompt/response
> content); in-guest probes for a3s-box.

## Why eBPF (not an SDK)

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
  → provider + endpoint, language-agnostically. Plus per-call metrics accumulated in-kernel:
  req/resp bytes (wire bytes, incl. TLS framing), latency, and a TTFT proxy (first response
  byte).
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
| `exec` | `sys_enter_execve` | tool / subprocess (argv, comm, uid) |
| `file` | `sys_enter_openat` (write opens) | files the agent writes — **opt-in** (`A3S_OBSERVER_FILES=1`; high-volume on busy nodes) |
| `connect` | `sys_enter_connect` | peer IP:port |
| `sni`  | TLS ClientHello on `write` / `sendto` | LLM provider |
| `dns`  | `sendto` / `sendmsg` / `sendmmsg` to :53 | resolved hostnames |
| LLM metrics | `read` / `recv` + `close`, per socket | req/resp bytes, latency, TTFT |

Extensions (trait, swappable, degrade gracefully):
- `IdentityResolver` — k8s (cgroup→pod) / bare host (`/proc` comm+ppid), with an in-kernel
  `comm` fallback so short-lived processes are still attributed
- `ServiceClassifier` — SNI → `Provider` (14 LLM providers)
- `Exporter` — NDJSON / human log → OpenTelemetry Collector (see below)
- *(deferred, opt-in)* TLS-payload provider — for model/tokens/prompt, per TLS library

## a3s-box note

Each box is a separate guest kernel, so **host-side eBPF can't see guest syscalls**
(exec/file). The **network layer** works host-side (box egress flows through the host
net path → SNI/flow). **file/exec inside a box need in-guest eBPF** (guest kernel built
with BPF + collector in-guest) — phase 2.

## Status

Implemented + validated on Linux 6.8 (language-agnostic kernel hooks, no uprobes):

- **Probes:** `exec`, `file` (writes), `connect`, TLS-`SNI`, `dns`
  (`sendto`/`sendmsg`/`sendmmsg`), and per-socket LLM metrics (req/resp bytes, latency, TTFT).
- **Identity:** k8s cgroup→pod, `/proc` comm+ppid, in-kernel `comm` fallback.
- **Correlation:** `(pid,fd)→peer`. **Export:** NDJSON / log → OTel Collector.

Roadmap: opt-in SSL-payload extension (prompt/response *content*, per TLS library — needs
uprobes, so not language-agnostic); in-guest probes for a3s-box MicroVMs (phase 2).

Stack: Rust + [Aya](https://aya-rs.dev). Probes in `a3s-observer-ebpf`; shared kernel/user
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

# file-write capture is off by default (openat is high-volume on busy nodes); opt in with:
A3S_OBSERVER_FILES=1 A3S_OBSERVER_JSON=1 sudo -E ./target/release/a3s-observer-collector
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
ingests them directly), so a3s-observer also drops straight into vector / Loki / `jq`.

**Kubernetes:** build the image with [`deploy/Dockerfile`](deploy/Dockerfile) and deploy
[`deploy/daemonset.yaml`](deploy/daemonset.yaml) (writes NDJSON to stdout); a node-level
OTel Collector DaemonSet tails the container log. No k8s API/RBAC needed — pod identity
comes from `/proc/<pid>/cgroup`. This keeps the always-on probe binary minimal and
decoupled from backend availability; in-process OTLP push is intentionally **not** built —
that's the Collector's job.

## License

MIT
