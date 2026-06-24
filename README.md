# a3s-observer

Kernel-level **eBPF observability — and optional intervention — for AI agents.** It turns
syscalls and network events into agent-semantic telemetry (which agent ran which tool, made
which LLM call, touched which files, reached which endpoint) with **zero changes to the agent
and no per-language instrumentation** — and the same kernel vantage point can **intervene**:
deny an agent's egress, file access, or process execution from an external policy.

Built and validated on Linux 6.8 (Aya). Observe-only by default; every intervention is opt-in
and isolated from the observe path.

## Architecture

A **minimal core** — probes → loader → identity → correlation → export — with everything else a
swappable trait. Two paths share one kernel vantage point: **observe** is always-on and passive
(tracepoints can't block); **intervene** is opt-in (cgroup-BPF / fanotify), so a policy mistake
can never break observability.

```
  AI agent + its tool subprocesses                  unmodified · any language
            │
            │   execve · connect · TLS ClientHello · DNS · openat · read/recv · SSL_*
  ══════════╪═══════════════════════════════════════════════  KERNEL  (eBPF + fanotify)
            ▼
   OBSERVE  (passive, always-on)            INTERVENE  (opt-in, external policy)
     exec  connect  sni  dns                  enforce   → cgroup/connect4: deny egress
     llm-metrics  file*  ssl-content*         fileguard → fanotify: deny open + exec
            │
            │  ring buffers
  ══════════╪═══════════════════════════════════════════════  USERSPACE
            ▼
   a3s-observer-collector  (Aya loader)
     identity (k8s pod / proc / comm)  ·  correlate (pid,fd)→peer  ·  export NDJSON
            │
            ▼
   OTel Collector  →  your backend            * opt-in: A3S_OBSERVER_FILES / _SSL
```

## Observe — who / what / where

One event answers **who** (process or k8s pod) / **what** (tool, file, LLM provider + bytes /
latency / TTFT, or plaintext) / **where** (peer IP / hostname).

| signal | kernel hook | event |
|---|---|---|
| `exec` | `sys_enter_execve` | `ToolExec` — tool / subprocess (argv, comm, uid) |
| `connect` | `sys_enter_connect` | `Egress` — peer IP:port |
| `sni` | TLS ClientHello (plaintext `server_name`) | LLM **provider** + endpoint |
| `dns` | `sendto` / `sendmsg` / `sendmmsg` to :53 | `Dns` — resolved hostname |
| llm metrics | per-socket `read`/`recv` + `close` | `LlmCall` — req/resp wire bytes, latency, TTFT |
| `file`\* | `sys_enter_openat` (write opens) | `FileAccess` — files written (`A3S_OBSERVER_FILES=1`) |
| `ssl`\* | OpenSSL `SSL_write` / `SSL_read` uprobes | `SslContent` — request/response plaintext (`A3S_OBSERVER_SSL=1`) |

Userspace enriches each event with **identity** (k8s cgroup→pod, `/proc` comm+ppid, or an
in-kernel `comm` fallback for short-lived processes), a `(pid,fd)→peer` **correlation**, and
**provider** classification (SNI → 15 LLM providers); then exports **NDJSON** (or a human log).

## Intervene — egress / file / exec (opt-in)

The same vantage point enforces an **external policy** — a plain file any controller writes; the
kernel asks a guard allow/deny per action. The observe-only core is untouched. Both guards are
**hot-reloaded** and **KVM-validated** (a denied action returns `EPERM`):

| guard | mechanism | denies |
|---|---|---|
| `a3s-observer-enforce` | eBPF `cgroup/connect4` | `connect()` to policy IPs/hosts — cgroup-scoped, fail-open, DNS-re-resolved |
| `a3s-observer-fileguard` | fanotify `FAN_OPEN_PERM` + `FAN_OPEN_EXEC_PERM` | `open()` **and** `exec` of policy-listed files |

Drive it in-process (the `Policy` trait) or out-of-process — `scripts/example-controller.py`
turns observed events into a deny-list. See [`docs/enforcement.md`](docs/enforcement.md).

## Why eBPF, and the boundary

- **Zero-instrumentation, language-agnostic** — observe or guard any agent (Python/Node/Go/Rust)
  without touching its code, including its tool subprocesses.
- **Kernel hooks only in the always-on core, no uprobes** — so the core gives **no LLM
  prompt/completion content**. That content is available via an **opt-in** OpenSSL uprobe
  extension (`A3S_OBSERVER_SSL=1`) — OpenSSL only (Python/Node/curl …, not Go `crypto/tls`),
  kept out of the universal core because a uprobe binds to a library symbol. (ECH will
  eventually hide SNI → fall back to IP/DNS.)
- **a3s-box** — a box is a separate guest kernel, so host-side eBPF sees box **egress** (it
  flows through the host net path) but not in-guest exec/file — those need an in-guest collector
  (phase 2).

## Build & run

eBPF needs nightly + `rust-src` + [`bpf-linker`](https://github.com/aya-rs/bpf-linker) (it
borrows rustc's bundled LLVM — no system LLVM required):

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo build --release -p a3s-observer-collector    # build.rs compiles + links the eBPF

sudo ./target/release/a3s-observer-collector                          # human-readable log
A3S_OBSERVER_JSON=1 sudo -E ./target/release/a3s-observer-collector   # NDJSON
```

Linux only; needs root (CAP_BPF + CAP_PERFMON). Env knobs: `A3S_OBSERVER_JSON` (NDJSON),
`A3S_OBSERVER_FILES` (file writes — high-volume), `A3S_OBSERVER_SSL` (OpenSSL content),
`A3S_OBSERVER_HEARTBEAT` (liveness file path).

Opt-in enforcement — run against an agent's cgroup and/or a deny-list file:

```bash
sudo ./target/release/a3s-observer-enforce   /sys/fs/cgroup/<agent>  egress-deny.txt
sudo ./target/release/a3s-observer-fileguard  file-exec-deny.txt
```

## Deploy

a3s-observer emits NDJSON; shipping it (batch / retry / route to a backend) is the OpenTelemetry
Collector's job, so in-process OTLP is intentionally **not** built:

```
a3s-observer  →  NDJSON  →  OTel Collector (filelog → OTLP)  →  your backend
```

- Collector config: [`deploy/otel-collector.yaml`](deploy/otel-collector.yaml) (`memory_limiter`
  + a retrying sending queue). Every event is one valid-JSON line — also drops into vector /
  Loki / `jq`.
- **Kubernetes:** CI publishes `ghcr.io/a3s-lab/observer:<tag>` (Trivy-scanned, cosign-signed,
  with SBOM + SLSA provenance); deploy [`deploy/daemonset.yaml`](deploy/daemonset.yaml) (NDJSON
  to stdout, pod identity from `/proc/<pid>/cgroup` — no k8s API/RBAC; liveness probe,
  `system-node-critical`). Mirror the image to a cluster-local registry for nodes that can't
  reach ghcr.io.

## Workspace

| crate | role |
|---|---|
| `a3s-observer` | contracts + data model (`IdentityResolver` / `ServiceClassifier` / `Exporter` / `Policy`) — host-buildable |
| `a3s-observer-common` | `no_std` types shared with the eBPF probes |
| `a3s-observer-ebpf` | probes + the `connect4` egress guard, compiled to BPF bytecode |
| `a3s-observer-collector` | loader, correlation, export; plus the `enforce` and `fileguard` binaries |

Rust + [Aya](https://aya-rs.dev). Validated on Linux 6.8.

## Security

Privileged component — see [SECURITY.md](SECURITY.md) for the disclosure policy and how to
verify a release image's signature (cosign / Sigstore).

## License

MIT
