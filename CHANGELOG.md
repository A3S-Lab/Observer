# Changelog

All notable changes to a3s-observer will be documented in this file.

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
