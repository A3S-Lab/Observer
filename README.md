# a3s-observer

Kernel-level **eBPF** observability — and optional intervention — for AI agents. It turns
syscalls and network events into agent-semantic telemetry (which agent ran which tool, made
which LLM call, touched which files, reached which endpoint) with **zero changes to the agent
and no per-language instrumentation**. The same kernel vantage point can also **intervene** —
deny an agent's egress or file access from an external policy.

Built and validated on Linux 6.8 (Aya, no uprobes). Observe-only by default; intervention is
opt-in and never affects the observe path.

## Architecture

A **minimal core** — probes → loader → identity → correlation → export — with everything else a
swappable trait. Two paths share one kernel vantage point: **observe** is always-on and passive;
**intervene** is opt-in and isolated, so a policy mistake can never break observability.

```
  AI agent + its tool subprocesses                       unmodified · any language
              │
              │  execve · connect · TLS ClientHello · DNS · openat · read / recv
  ════════════╪══════════════════════════════════════════════  KERNEL · eBPF (no uprobes)
              ▼
    OBSERVE  (passive, always on)               INTERVENE  (opt-in)
      exec   connect   sni   dns                  connect4 egress guard  (cgroup-scoped)
      llm-metrics      file                       fanotify  file guard
              │                                            ▲
              │  ring buffers                              │  allow / DENY → EPERM
  ════════════╪═════════════════════════════════════════════╪═══════════  USERSPACE
              ▼                                              │
    a3s-observer-collector  (Aya)                 a3s-observer-enforce · fileguard
      · identity    k8s pod / proc / comm                   ▲
      · correlate   (pid,fd) → peer                         │  reads
      · export      NDJSON / human log             external policy file
              │                                    (your controller · OPA · a script)
              ▼
    OTel Collector  →  your backend
```

The four core pieces — **probes** (language-agnostic kernel hooks), **identity** (attribute an
event to an agent), **correlation** (fuse provider + endpoint), **export** (NDJSON) — plus the
opt-in **guards**, are detailed below.

## Observe — who / what / where

One event answers **who / what / where**: who (process or k8s pod), what (tool, file, or LLM
provider + bytes/latency/TTFT), where (peer IP / hostname).

| probe | kernel hook | signal |
|---|---|---|
| `exec` | `sys_enter_execve` | tools / subprocesses (argv, comm, uid) |
| `connect` | `sys_enter_connect` | peer IP:port |
| `sni` | TLS ClientHello (plaintext `server_name`) | LLM provider + endpoint |
| `dns` | `sendto` / `sendmsg` / `sendmmsg` to :53 | resolved hostnames |
| LLM metrics | per-socket `read` / `recv` + `close` | req/resp wire bytes, latency, TTFT |
| `file` | `sys_enter_openat` (write opens) | files written — **opt-in** (`A3S_OBSERVER_FILES=1`; high-volume) |

Userspace enriches each event with **identity** (k8s cgroup→pod, `/proc` comm+ppid, or an
in-kernel `comm` fallback for short-lived processes) and a `(pid,fd)→peer` **correlation**,
then exports **NDJSON** (or a human-readable log).

## Intervene (opt-in)

The same vantage point can enforce an **external** policy: the policy lives outside the binary
(a plain file any controller can write), and the kernel asks a guard allow/deny per action.
The observe-only core is untouched.

| guard | mechanism | denies |
|---|---|---|
| `a3s-observer-enforce` | `cgroup/connect4` eBPF | egress to policy IPs/hosts — **cgroup-scoped**, fail-open |
| `a3s-observer-fileguard` | fanotify `FAN_OPEN_PERM` | `open()` of policy-listed files |

Both KVM-validated: a denied connect / file-open returns `EPERM`, everything else is
untouched. Drive it in-process (the `Policy` trait) or out-of-process — `scripts/example-controller.py`
turns observed events into a deny-list. See [`docs/enforcement.md`](docs/enforcement.md).

## Why eBPF, and the boundary

- **Zero-instrumentation, language-agnostic** — observe or guard any agent
  (Python/Node/Go/Rust) without touching its code, including its tool subprocesses.
- **Sees what the app won't report** — real execs, file I/O, network egress.
- **Kernel hooks only, no uprobes.** The deliberate trade-off: **no LLM prompt / model name /
  token / completion content** — that needs an opt-in per-TLS-library uprobe extension, kept
  out of the universal core. (ECH will eventually hide SNI → fall back to IP/DNS.)
- **a3s-box:** a box is a separate guest kernel, so host-side eBPF sees box **egress** (it
  flows through the host net path) but not in-guest exec/file — those need an in-guest
  collector (phase 2).

## Build & run

eBPF needs nightly + `rust-src` + [`bpf-linker`](https://github.com/aya-rs/bpf-linker)
(it borrows rustc's bundled LLVM — no system LLVM required):

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo build --release -p a3s-observer-collector    # build.rs compiles + links the eBPF

sudo ./target/release/a3s-observer-collector                          # human-readable log
A3S_OBSERVER_JSON=1 sudo -E ./target/release/a3s-observer-collector   # NDJSON
A3S_OBSERVER_FILES=1 A3S_OBSERVER_JSON=1 sudo -E ./target/release/a3s-observer-collector  # + file writes
```

Linux only; needs root (CAP_BPF + CAP_PERFMON).

## Deploy

a3s-observer captures and emits NDJSON; shipping it (batch / retry / route to a backend) is
the OpenTelemetry Collector's job, so in-process OTLP is intentionally **not** built:

```
a3s-observer  →  NDJSON  →  OTel Collector (filelog → OTLP)  →  your backend
```

- Collector config: [`deploy/otel-collector.yaml`](deploy/otel-collector.yaml). Every event
  is one valid-JSON line, so it also drops into vector / Loki / `jq`.
- **Kubernetes:** CI publishes `ghcr.io/a3s-lab/observer:<tag>` on each tag
  ([`image.yml`](.github/workflows/image.yml) from [`deploy/Dockerfile`](deploy/Dockerfile));
  deploy [`deploy/daemonset.yaml`](deploy/daemonset.yaml) (NDJSON to stdout, pod identity from
  `/proc/<pid>/cgroup` — no k8s API/RBAC). Mirror the image to a cluster-local registry for
  nodes that can't reach ghcr.io.

## Workspace

| crate | role |
|---|---|
| `a3s-observer` | contracts + data model (`IdentityResolver` / `ServiceClassifier` / `Exporter` / `Policy`) — host-buildable |
| `a3s-observer-common` | `no_std` types shared with the eBPF probes |
| `a3s-observer-ebpf` | the probes + egress guard, compiled to BPF bytecode |
| `a3s-observer-collector` | loader, correlation, export; plus the `enforce` and `fileguard` binaries |

Rust + [Aya](https://aya-rs.dev).

## License

MIT
