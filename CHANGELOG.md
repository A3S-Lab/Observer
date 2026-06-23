# Changelog

All notable changes to a3s-observer will be documented in this file.

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
