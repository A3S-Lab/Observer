# Changelog

All notable changes to a3s-observer will be documented in this file.

## [Unreleased]

### Added

- **Enforcement — external intervention interface implemented** (opt-in; see
  `docs/enforcement.md`). A `cgroup/connect4` egress guard (`egress_guard` + the
  `DENY_EGRESS` map) plus `a3s-observer-enforce`, which attaches the guard to a target cgroup
  and populates the deny map from an **external policy file** (one IPv4/hostname per line,
  hot-reloaded every 2s) — the language-agnostic external interface. Cgroup-scoped, fail-open.
  **Builds clean on KVM.** Runtime validation (actual blocking) is intentionally **not** run
  on the shared prod node — blocking real egress there is off-limits — so it is **pending a
  non-prod box**.

## [0.2.5] — operator polish + enforcement design

### Added

- `--version` / `--help` flags on the collector.
- `scripts/smoke.sh` — committed end-to-end smoke test (builds, unit-tests, loads the probes,
  drives an LLM call, asserts an event flowed) so the manual validation is reproducible.
- **Enforcement extension — design + contract** (opt-in *intervention*, kept separate from
  the observe-only core): `docs/enforcement.md` (architecture) + a `Policy`/`Verdict` seam
  (`src/policy.rs`) that an **external** policy implements — in-process (`impl Policy`) or
  out-of-process (a controller driving in-kernel policy maps via a control API). Default
  `AllowAll` (fail-open). The eBPF mechanism (LSM `file_open`/`bprm` deny, TC egress drop) is
  phase 2 and must be validated on a non-prod box. Note: encrypted TLS payload can be
  dropped/RST/redirected but not modified.

## [0.2.4] — clean shutdown (k8s lifecycle)

### Changed

- Handle **SIGTERM** (not just SIGINT) so a Kubernetes DaemonSet pod shuts down cleanly on
  termination instead of being SIGKILLed after the grace period; flush a final throughput
  report on exit. Validated on KVM: SIGTERM → exit 0 + final-window log.

## [0.2.3] — data-loss visibility

### Added

- **Ring-drop counter:** events dropped because a ring buffer was full are counted in-kernel
  (`PerCpuArray`, via a `reserve_or_drop` helper across all 7 emit sites) and surfaced in the
  60s report as `dropped` — data loss is now visible, not silent. Validated on KVM:
  `dropped=0` under normal node load (exec=502, egress=458, dns=136 captured, none dropped),
  which also empirically confirms the 20ms poll loop keeps up without drops.

## [0.2.2] — operability

### Added

- **Throughput stats:** the collector logs per-kind event counts (exec / egress / dns /
  file / llm) every 60s, so operators can see it is alive and how much it is processing.
  Validated on KVM: `exec=774 egress=526 dns=144 file=0 llm=1` over a 60s window. (In-kernel
  ring-buffer drop counting — data-loss visibility under extreme load — is a noted follow-up.)

## [0.2.1] — robustness + deployability

### Changed

- **Graceful probe degradation:** per-probe attach is now non-fatal — a tracepoint missing
  on the running kernel logs a warning and the collector continues with whatever attaches
  (bails only if zero attach). One kernel-version difference no longer takes down the whole
  collector. Validated: all 12 core probes attach, events flow.

### Added

- **Kubernetes deployment:** `deploy/Dockerfile` (multi-stage build with the eBPF
  toolchain) + `deploy/daemonset.yaml` (privileged DaemonSet, NDJSON to stdout, no k8s
  API/RBAC — pod identity from `/proc/<pid>/cgroup`). Pairs with `deploy/otel-collector.yaml`.

## [0.2.0] — production-ready

Closes the gap between the design and the implementation: every capability the docs
advertise is now built and validated on Linux 6.8.

### Added

- **`file` probe** (`sys_enter_openat`, write/rw opens only) → `FileAccess` events — the
  "which files did the agent write" signal (the model variant existed but was never emitted).
- **LLM-call metrics** → `LlmCall` with req/resp **bytes**, **latency**, and **TTFT**,
  accumulated in-kernel per `(pid,fd)` and flushed on socket close (req = writes after
  ClientHello; resp = read/recv exits; bytes are wire bytes incl. TLS framing).
- **DNS coverage for `sendmsg`/`sendmmsg`** (glibc `getaddrinfo` parallel A/AAAA) via a
  shared `struct msghdr` parser, in addition to `sendto`.
- **OpenTelemetry integration** via the Collector: `deploy/otel-collector.yaml`
  (filelog → OTLP). In-process OTLP push intentionally not built — shipping is the
  Collector's job. NDJSON verified 100% valid-JSON across all event kinds.
- **`ServiceClassifier`**: 11 more providers (Mistral, Cohere, xAI, DeepSeek, Groq,
  Together, Perplexity, Fireworks, OpenRouter, Azure OpenAI, AWS Bedrock) — 14 total.

### Changed

- **Reliable identity:** every event carries the process `comm` captured in-kernel; used as
  the agent-label fallback when `/proc` resolution fails, so short-lived processes are no
  longer left `agent: null`.
- Hardening: no-panic audit of the event loop; poll tightened to 20ms (AsyncFd documented as
  the extreme-volume upgrade). Overhead ≈ 4.6% CPU / 25 MB RSS (debug, busy node).
- Docs reconciled with reality (probe set, exporter, metrics).

## [0.1.0] — v1 (working collector)

A working, language-agnostic eBPF AI-agent observability collector — validated on Linux
6.8. Captures who/what/where for an agent with zero code changes.

### Added

- **eBPF probes (Aya):** `exec` (tools/subprocesses), `tls-sni` (TLS ClientHello → LLM
  provider), `connect` (peer IP:port), `dns` (resolved hostnames). All verifier-clean.
- **Identity:** `ProcResolver` (`/proc` comm + ppid process-tree) and `KubeResolver`
  (k8s cgroup → pod/container, comm fallback).
- **Correlation:** userspace `(pid,fd)→peer` join — fuses LLM provider + endpoint into one
  event.
- **Export:** `JsonExporter` (NDJSON) and `LogExporter`, selected by `A3S_OBSERVER_JSON`.
- **Contracts:** `IdentityResolver` / `ServiceClassifier` (`SniClassifier`) / `Exporter`,
  data model (`AgentEvent`, `EnrichedEvent`); workspace = contracts lib + `-common` +
  `-ebpf` + `-collector`.
- README Build & run quickstart; CI (fmt + parser/lib tests); unit tests for the SNI,
  DNS, ppid, and cgroup parsers.

### Notes / roadmap

- Language-agnostic by design (no per-language uprobes) ⇒ no prompt/model/token content.
- DNS covers `sendto`-based resolvers; glibc `getaddrinfo` (`sendmmsg`) not yet covered.
- Roadmap: OTLP exporter; byte/latency/TTFT metrics; opt-in SSL-payload (content) extension.

### Pre-v1 history

- bpftrace PoC (`poc/`) that validated `execve`→tool and TLS-ClientHello→SNI on a live
  kernel before the Aya implementation; initial skeleton of the contracts + data model.
