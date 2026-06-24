# Changelog

All notable changes to a3s-observer will be documented in this file.

## [0.9.0] — file deletions (destructive actions)

### Added

- **`FileDelete` event** — `sys_enter_unlinkat` captures which files an agent **deletes**
  (opt-in with `A3S_OBSERVER_FILES=1`), completing the file lifecycle (write + delete). You now
  see destructive actions: `rm -rf /data` shows *which* files went, not just that `rm` ran.
  Host-validated: deleting a marker file surfaced `FileDelete{path:…}`. Shares the file ring via
  a `flags` sentinel (no extra ring/struct).

## [0.8.0] — process lifecycle (exit + exit code)

### Added

- **`ProcessExit` event** — `sys_enter_exit_group` captures a process's exit + **exit code**,
  pairing with `ToolExec` to bracket a tool's lifecycle (started → finished with this status).
  You now see tool *outcomes* (did the command succeed / fail?), not just that it ran.
  Host-validated: `exit 42` surfaced `{"exit_code":42}`. Catches clean exits (the C runtime's
  `exit()` calls `exit_group`); signal kills don't.

### Changed

- Exec ring 256→512 KiB — the v0.7.0 argv buffer made `ExecEvent` ~928 B (6×), which had
  halved the exec ring; restore headroom so a process burst doesn't drop. fileguard clippy-clean.

## [0.7.0] — richer tool observability (full argv + cwd)

### Added / Changed

- **Full command line on `ToolExec`** — the exec probe captures `argv[0..]` in-kernel (up to 12
  args × 64 bytes), not just the binary, so an agent's *intent* is visible
  (`curl --url=… "two words"`, `sh -c "<cmd>"`); the working directory (`cwd`) is filled from
  `/proc/<pid>/cwd`. Host-validated: a marker exec surfaced its full argv + cwd.
- The collector warns if the liveness heartbeat write fails — an unwritable
  `A3S_OBSERVER_HEARTBEAT` path would otherwise cause a silent livenessProbe restart-loop.

## [0.6.0] — exec intervention + fileguard hot-reload

### Added / Changed

- **Exec blocking** — `a3s-observer-fileguard` now denies **exec** as well as `open()`
  (`FAN_OPEN_EXEC_PERM`), completing the intervention triad (egress + file + exec), all via
  fanotify on a stock kernel (no bpf-lsm). KVM-validated: exec of a guarded binary → `EPERM`,
  a non-guarded binary runs.
- **fileguard hot-reload** — the policy is re-read every ~2s (marks added/removed live), so an
  external controller can change denials without a restart (matching the egress enforcer).
  KVM-validated: a path added to the policy is denied within the reload window.
- SSL content-capture overhead measured (KVM, 3k-TLS-call soak): **+0.3% CPU, +~50 KB RSS** vs
  baseline — negligible.
- `SECURITY.md` — vulnerability disclosure policy + image-signature verification.
- `docs/enforcement.md` reflects the **shipped** guards (egress `cgroup/connect4` v0.3.0, file
  fanotify `FAN_OPEN_PERM` v0.4.0); the file guard uses fanotify, not LSM-BPF, because `bpf`
  isn't in this kernel's `lsm=` set.
- Removed redundant `unsafe` blocks in the eBPF probes (clean build).
- `deploy/otel-collector.yaml` hardened for production: `memory_limiter` (OOM guard under
  backpressure) + `sending_queue` / `retry_on_failure` so it actually survives a backend
  outage (which the header claimed but the config didn't do).

## [0.5.1] — production hardening

### Changed

- **Liveness heartbeat**: the collector refreshes `/run/a3s-observer.alive`
  (`A3S_OBSERVER_HEARTBEAT`) at startup and every 60s report tick, so a k8s `livenessProbe`
  restarts a collector that has wedged (stopped pumping events).
- **DaemonSet** is production-grade: `system-node-critical` priority, `RollingUpdate`
  (maxUnavailable 1), a 30s graceful-shutdown window for the SIGTERM flush, and the heartbeat
  liveness probe.
- **Release supply chain**: the image workflow scans the pushed image for CVEs (Trivy,
  report-only for now), keyless-signs it (cosign / GitHub OIDC), and attaches SLSA build
  provenance + an SBOM.

## [0.5.0] — SSL/TLS content capture (opt-in)

### Added

- **SSL/TLS content capture (#7)** — the long-deferred opt-in OpenSSL uprobe extension.
  `A3S_OBSERVER_SSL=1` attaches uprobes to `SSL_write` / `SSL_read` and emits `SslContent`
  events with the request (prompt) / response (completion) **plaintext**. Deliberately outside
  the universal core (Rule 2): a uprobe binds to a library symbol, so it is **not**
  language-agnostic (OpenSSL only — Python `requests`/`httpx`, Node, curl …, not Go
  `crypto/tls`), and it captures real content, so it is **off by default**.
- **Validated end-to-end in a throwaway KVM VM**: a marker sent *inside* a local TLS session
  surfaced as `SslContent` plaintext (the `GET / HTTP/1.1` request line and the marker header
  were captured pre-encryption), confirming the uprobe reads cleartext the wire never sees.

## [0.4.0] — file-access intervention

### Added

- **File-access intervention** (opt-in): `a3s-observer-fileguard` — a fanotify `FAN_OPEN_PERM`
  guard that denies `open()` of the specific files listed in an external policy file (the other
  example from the intervention ask, "阻止某些文件读写"). Marks the named files (not the whole
  mount — a mount-wide perm guard gates *all* system I/O and can wedge services). Chosen over
  eBPF LSM `file_open` because `bpf` is not in this kernel's active `lsm=` set; fanotify is
  stock-kernel and userspace-policy-driven — the same external model as the egress guard.
- **Validated end-to-end in a throwaway KVM VM**: the denied file's `open()` returns `EPERM`
  (`cat` → "Operation not permitted") while a sibling file opens normally and system services
  are unaffected.

## [0.3.0] — external intervention interface (enforcement)

### Added

- **Enforcement — opt-in external intervention interface** (see `docs/enforcement.md`). A
  `cgroup/connect4` egress guard (`egress_guard` + `DENY_EGRESS`) + `a3s-observer-enforce`,
  which attaches the guard to a target cgroup and populates the deny map from an **external
  policy file** (IPv4/hostname per line, hot-reloaded) — the language-agnostic external
  interface. Plus the in-process `Policy`/`Verdict` contract, a CI-tested policy parser, and a
  worked external controller (`scripts/example-controller.py`: NDJSON → provider allow-list →
  deny-file). Cgroup-scoped, fail-open; the observe-only core is unaffected.
- **Validated end-to-end in a throwaway KVM VM** (non-prod — never the shared prod node): a
  process *in* the guarded cgroup gets `EPERM` connecting to the denied IP, while the same IP
  from *outside* the cgroup and a non-denied IP *inside* it are **not** blocked — proving deny
  + scoping + fail-open. Codified in `scripts/validate-enforcement.sh`.

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
