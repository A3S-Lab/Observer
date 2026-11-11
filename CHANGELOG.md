# Changelog

All notable changes to a3s-observer will be documented in this file.

## [Unreleased]

### Added

- kimi-code response-direction plaintext lane for `runtime_payload`: the kimi attach now also
  binds `ssl_read_enter`/`ssl_read_exit` at the symtab-resolved `SSL_read` offset, and kimi
  `SSL_read` fragments (gated to `runtime_probe_state.kimi_pids` only — other runtimes' reads
  stay rejected) are
  reassembled per connection, decoded as HTTP/1.1 (chunked / optional gzip), and incrementally
  parsed as OpenAI-style SSE. Aggregated assistant text, tool calls (with incremental
  `function.arguments` concatenation), `finish_reason`, and token usage produce a new sensitive
  `AgentEvent::LlmResponseObserved` event, finalized on `data: [DONE]`, process exit, or the
  reassembly timeout (idle/abort lanes emit bounded `partial` events). Requests and responses
  pair on the same connection in order; unpaired reads are dropped. Per-connection and
  aggregated-content byte caps mark oversize streams `capture_completeness=truncated`, all
  plaintext buffers zeroize on drop, and the `SIGUSR2` kill switch clears the response pipeline
  alongside the request pipeline.
- kimi-code TLS plaintext lane for `runtime_payload`: automatic discovery of the kimi CLI
  (`~/.kimi-code/bin/kimi`, `/usr/local/bin/kimi`, and running `kimi` processes), ELF symbol
  table resolution of the statically linked `SSL_write`/`SSL_read` entry points, and
  request-direction `ssl_write_enter`/`ssl_write_exit` uprobe attachment by file offset. A
  dedicated `KIMI_OPENSSL_EXACT_BINARY_ALL` in-kernel gate scopes capture to the exact attached
  inode, and kimi fragments are labeled `capture_method=ebpf_openssl`. Moonshot provider hosts
  must be present in `A3S_OBSERVER_RUNTIME_PROVIDER_HOSTS` for requests to be attributed.
- A provider-neutral workload attribution contract: `WorkloadIdentity` requires stable workload,
  deployment, immutable revision, logical replica, provider-unit, and node IDs. Each
  `WorkloadIdentityValue` is bounded to 128 ASCII bytes and rejects whitespace, control
  characters, free-form Unicode, and non-canonical boundary characters without echoing rejected
  input in validation errors.
- Explicit `ObservationMetadata` for sampled signals, including observation timestamp, optional
  sample timestamp and collection interval, and `fresh`, `stale`, `unavailable`, or `unknown`
  state. Unavailable and unknown observations represent missing data without a zero-valued
  sentinel.
- Optional `workload` and `observation` fields in NDJSON `EnrichedEvent` output.
  `IdentityResolver::resolve_workload` defaults to `None`, preserving existing resolver
  implementations and preventing incomplete attribution.

This contract is the first slice of workload metrics support. Multi-replica Linux collection,
resource/restart/availability measurements, lifecycle fixtures, and OTLP/Prometheus metric parity
are not included yet.

### Fixed

- Fragment pump jump table is now kept alive for the collector's lifetime, fixing a total loss
  of every `SSL_write` larger than 124 KiB (4 fragments). The canary build populated
  `SSL_FRAGMENT_PUMPS` and then dropped the `ProgramArray` handle; with the handle closed the
  jump-table entry no longer resolved at runtime (observed empty via bpftool on kernel 6.17), so
  every `bpf_tail_call` fell through and the pump program never executed — each oversized call
  was silently counted as one `ssl_dropped` and no fragment was ever emitted. Production symptom:
  the first few small requests captured, then llm=0 for 45 minutes while assistant traffic
  continued. The collector now stores the populated table for its whole lifetime, logs the
  post-populate entry count, and exports it as `jump_table_entries` in the 60s report. The tail
  call itself is also hoisted out of bpf2bpf subprograms into each probe main function
  (`EMIT_SSL_PUMP_PENDING` protocol), eliminating the subprogram-tail-call failure class
  entirely. New per-CPU `SSL_PUMP_STATS` counters (stashed/entries/hops/rechain/output/probe-read
  failures, fast-path calls, ceiling clamps, markers) are exported in the 60s report alongside
  per-branch payload discard breakdown (`ssl_record_parse_failed`, `discard_empty_payload`,
  `discard_op_not_allowed`, `discard_native_gate`).
- kimi-code request lane no longer drops requests that outgrow the capture ceiling; oversized
  `SSL_write` calls are now fragmented instead of discarded. Production regression showed the
  4 MiB cap still losing every late-session request (189/232 requests over ceiling, tail writes
  estimated at 8-15 MiB): the eBPF now fragments any call up to a 16 MiB absolute ceiling through
  the ordinary fragment path (same `call_sequence`/`fragment_index`/`fragment_offset` semantics).
  Fragmentation runs in a dedicated tail-call-only program (`ssl_fragment_pump`, never attached):
  the kernel verifier simulates `bpf_loop` iteration-by-iteration and its 1M-processed-insn
  budget only tolerates ~130 iterations per program, so each hop emits 128 fragments (4 MiB) and
  re-chains via `bpf_tail_call` until the call is fully emitted. Only the tail beyond the ceiling
  is marked truncated — the captured prefix is still emitted
  and the call is counted once under `calls_oversized` (a per-call suppression set keeps hundreds
  of prefix fragments from multiplying warnings). The SSL ring grows to 32 MiB (shared across
  CPUs; one worst-case burst is ~16.9 MiB in 529 records, so the ring holds a full burst plus
  concurrent response traffic), and the default
  `A3S_OBSERVER_PAYLOAD_MAX_REASSEMBLY_BYTES`/`A3S_OBSERVER_PAYLOAD_MAX_DECOMPRESSED_BYTES` rise
  to 16 MiB (env bounds widened to 64 MiB).
- kimi-code request lane no longer stalls permanently once a conversation grows past one MiB.
  Agent CLIs resend the full conversation history — including resent `reasoning_content` blocks,
  which token usage does not reflect — on every turn, so a single `SSL_write` eventually exceeds
  the old 1 MiB `SSL_MAX_CAPTURE_LEN`. The eBPF then emitted a header-only truncated record and
  userspace dropped the call as `tls_call_truncated`; because the history only grows, every
  subsequent request failed the same way (production: 173/173 requests lost over 66 minutes,
  responses parsed but unpaired). `SSL_MAX_CAPTURE_LEN` and the default
  `A3S_OBSERVER_PAYLOAD_MAX_REASSEMBLY_BYTES` are now 4 MiB, the SSL ring is sized at 8 MiB (2×
  the per-call ceiling) so one max-size burst cannot overflow it, and oversize drops are counted
  under a dedicated `calls_oversized` Loss Ledger field (with `original_len` on the loss warning
  and fixture loss record) so this class of silent stall is visible as it starts.
- kimi-code response lane no longer drops whole responses on HTTP/1.1 keep-alive reuse. kimi
  (undici) pools TLS connections, so response N+1 follows response N on the same `ssl_pointer`;
  previously the connection state was deleted at SSE `[DONE]`, and when the trailing chunked
  terminator (`0\r\n\r\n`) arrived coalesced with the next response's headers in a later
  `SSL_read`, the fresh connection failed with `http_response_status_line_invalid` on every
  subsequent read — silently losing the entire pipelined response and its pending request.
  Connections now persist across responses with a byte backlog, the chunked terminator is
  drained independently of `[DONE]` finalization, 1xx interim responses (`100 Continue`) are
  skipped, and a headerless parse failure with a pending request emits an explicit
  `parse_status=failed`, `capture_completeness=partial` observation (counted under the new
  `responses_failed` Loss Ledger field, alongside `interim_responses_skipped`) instead of
  vanishing.
- `remember_ssl_call` no longer takes an `Option<usize>` argument: depending on inlining
  decisions, LLVM can pass the `None` payload register as `undef`, which the kernel verifier
  rejects (`R4 !read_ok`) when `ssl_write_enter` is loaded. The written-length argument index is
  now a scalar `usize` where 0 means "no output-length pointer", so no undefined register can
  cross the function boundary on any toolchain.

### Security

- Production interaction observation is now source-level `metadata-only`.
  `A3S_OBSERVER_SSL` is ignored and the ordinary event model can no longer carry `SslContent` or
  `LlmApi` plaintext. Dedicated OpenSSL and native-stdin payload paths exist only as isolated
  Phase -1 Runtime Fixtures: they require an explicit test environment and confirmation, an exact
  non-zero PID allowlist, a Provider-host allowlist, and a newly created `0600` artifact. Fixture
  fragments never enter ordinary NDJSON or logs, and `SIGUSR2` disables the eBPF read path before
  clearing queued plaintext. The outbound-request-only OpenSSL schema-4 ABI uses bounded
  variable-size records of at most 31 KiB, reassembles at most 1 MiB per successful write, and
  records larger calls as incomplete. The native-stdin path attaches only `read(2)` entry/exit
  tracepoints, accepts only fd 0 of allowlisted PIDs, and emits only after EOF. OpenSSL attachment
  can be disabled independently, preventing irrelevant TLS probes for static Rustls runtimes.
  The build tracks the shared eBPF ABI crate so a constant-only ABI change cannot silently reuse
  stale bytecode. Correctness, loss, leakage, `0600`, and Kill Switch checks pass for the exact
  Python/OpenSSL Fixture and for a real `codex-cli 0.147.0` `codex exec -` stdin Fixture. The
  OpenSSL 2% P95/TTFT declared-load Gate remains failed, and neither path is enabled in production.

## [0.11.0] — SecurityAction: privesc / injection / open-port

### Added

- **`AgentEvent::SecurityAction { pid, kind, detail }`** — one rare-and-loud, in-kernel-filtered
  event for the security-sensitive syscalls an agent rarely makes but that matter when it does.
  Three kinds, all on a single `SEC_EVENTS` ring:
  - `setuid-root` — `setuid`/`setresuid`/`setreuid` setting (e)uid 0 from a non-root caller
    (privilege escalation, including the EPERM-bound *attempt*). Gated to the thread-group leader,
    so glibc's NPTL setxid broadcast doesn't fan out one escalation into N duplicate events.
  - `ptrace` — `ptrace(ATTACH|SEIZE)` of another process (`detail` = target pid): process injection.
  - `bind` — `bind()` to a fixed **non-loopback** port (`detail` = port): an off-host-reachable
    listener. Loopback (127.0.0.0/8) binds are filtered as common local-helper noise.

  Group escalation (`setgid`) and loopback-only binds are intentionally out of scope. Validated
  live on Linux 6.8 (all three fire with correct `detail`, verifier loads clean, multithreaded
  `setuid` deduped to one event), and adversarially reviewed before release.

## [0.10.0] — richer signals: exit-signal, LLM model, dest-port, uid

### Added

- **Exit signal** — `ProcessExit` now carries `signal` (0 clean / 9 SIGKILL+OOM / 11 SIGSEGV
  crash). The probe moved from the `sys_enter_exit_group` tracepoint to a `do_exit` kprobe, so
  crashes and signal-kills — which the tracepoint never saw — are captured. Gated to the
  thread-group leader: one event per process, not per thread.
- **LLM model + tokens** — `AgentEvent::LlmApi {model, prompt_tokens, completion_tokens}`, parsed
  in userspace from the opt-in TLS content: which model the agent called + token usage. Pairs
  with the raw `SslContent`.
- **Destination port on `Egress`** — the service class the agent dials (443 API / 22 SSH / 5432
  Postgres / 6379 Redis / 11434 Ollama). The port was already read in-kernel and discarded.
- **UID on `ToolExec`** — the real UID a tool runs as (0 = root): privilege / privesc visibility.

### Fixed

- `build.rs` now emits `rerun-if-changed` for the eBPF crate, so a probe-source-only change no
  longer reuses stale bytecode.

### Tested

- Each signal validated live on the production cluster (crash/kill/OOM; LlmApi model over TLS;
  port 6443/etcd/redis; uid root/service/nobody). An adversarial fan-out review caught + fixed a
  per-thread `ProcessExit` duplication regression (multithreaded agents) before release; the
  untrusted-input LLM parser passed a 50M-iteration fuzz.

## [0.9.3] — soak validation + test coverage (no runtime change)

### Tested

- Full-stack soak validation — 15 cases, leak-free and correct under load on a prod host + an
  isolated VM. Observe: steady 20 min, edge-input, a real a3s-code agent, throughput (110k ev/60s),
  memory-bound (256 Mi), restart ×8, idle + heartbeat, SIGTERM, concurrent collectors,
  backpressure, connection-churn. Intervene: egress, file/exec, and SSL-content guards — plus all
  three running alongside the collector.
- Lib line coverage 72% → **79.6%** (`cargo llvm-cov`): adversarial SNI/DNS parser tests, the
  cgroup→pod parser, the full 14-provider SNI classifier, and the v0.9.2 writer-thread path.

## [0.9.2] — fix: output backpressure no longer stalls the event loop

### Fixed

- **A slow/stalled stdout consumer no longer wedges the collector.** The NDJSON write was
  blocking, so under sustained backpressure the event loop stalled inside the write — the 60s
  report and the liveness heartbeat stopped firing, `/run/a3s-observer.alive` went stale, and the
  livenessProbe would kill the pod (with drops going silent). Found by soak testing: the heartbeat
  aged 23→143s monotonically under a slow consumer. Now a dedicated writer thread owns stdout, fed
  by a bounded queue; when the consumer can't keep up, lines are dropped and counted
  (`output_dropped` in the 60s report) instead of blocking. Re-tested: the heartbeat refreshes on
  every tick under backpressure.

## [0.9.1] — fix: operational logs to stderr (NDJSON stdout was polluted)

### Fixed

- **Logs now go to stderr** (were on stdout, interleaved with the NDJSON event stream) — found
  by deep testing: an NDJSON consumer (`jq` / vector / OTel `filelog`) would hit the `INFO …`
  log lines and fail. stdout is now pure NDJSON; the operational logs (startup, throughput, drop
  counter) are on stderr at INFO by default. The OTel sample's `json_parser` now also skips
  non-JSON lines (for the k8s pod log, where stdout+stderr interleave).

### Tested

- Deep test (sustained mixed workload): all event types flow together, **dropped=0** at ~110 k
  events/60 s, RSS flat (no leak), no panics.

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
