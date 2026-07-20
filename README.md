# a3s-observer

Kernel-level **eBPF observability — and optional intervention — for AI agents.** It turns
syscalls and network events into agent-semantic telemetry (which agent ran which tool, made
which LLM call, touched which files, reached which endpoint, escalated privileges) with **zero changes to the agent
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
            │   execve · do_exit · connect · TLS ClientHello · DNS · openat · setuid/ptrace/bind · SSL_*
  ══════════╪═══════════════════════════════════════════════  KERNEL  (eBPF + fanotify)
            ▼
   OBSERVE  (passive, always-on)            INTERVENE  (opt-in, external policy)
     exec  exit  connect  sni  dns           enforce   → cgroup/connect4: deny egress
     security  llm-metrics  file*  ssl*      fileguard → fanotify: deny open + exec
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
| `exec` | `sys_enter_execve` + `sched_process_exec` | `ToolExec` — bounded argv fragments, successful-exec confirmation, `/proc` supplementation + cwd, comm, uid |
| `exit` | `do_exit` kprobe | `ProcessExit` — outcome: **exit code + signal** (clean / SIGSEGV crash / SIGKILL-OOM), one per process |
| `connect` | `sys_enter_connect` | `Egress` — peer IP:port |
| `sni` | TLS ClientHello (plaintext `server_name`) | LLM **provider** + endpoint |
| `dns` | `sendto` / `sendmsg` / `sendmmsg` to :53 | `Dns` — resolved hostname |
| llm metrics | per-socket `read`/`recv` + `close` | `LlmCall` — req/resp wire bytes, latency, TTFT |
| `file`\* | `sys_enter_openat` (write opens) | `FileAccess` — files written (`A3S_OBSERVER_FILES=1`) |
| `unlink`\* | `sys_enter_unlinkat` | `FileDelete` — files deleted (`A3S_OBSERVER_FILES=1`) |
| `ssl`\* | OpenSSL `SSL_write` / `SSL_read` uprobes | `SslContent` — request/response plaintext (`A3S_OBSERVER_SSL=1`) |
| `llm-api`\* | parsed from `SslContent` | `LlmApi` — **model** + token usage (`A3S_OBSERVER_SSL=1`) |
| `security` | `setuid` / `ptrace` / `bind` syscalls | `SecurityAction` — privilege escalation (→root) / process injection / opened a listening port (rare + in-kernel-filtered) |
| collector heartbeat | userspace timer | `CollectorHeartbeat` — collector id, node/pod, attached probes, feature flags, per-window counts, ring drops, output drops |

Userspace enriches each event with **identity** (k8s cgroup→pod, `/proc` comm+ppid, or an
in-kernel `comm` fallback for short-lived processes), a `(pid,fd)→peer` **correlation**, and
**provider** classification (SNI → 15 LLM providers); then exports **NDJSON** (or a human log).
`CollectorHeartbeat` is a control-plane event for platforms such as AnySentry; it is not an
agent action and should not be fed into security policy decisions.

**Example output** (`A3S_OBSERVER_JSON=1`, one event per line — wrapped here for readability):

```json
{"identity":{"agent":"python3","task":"1841","session":null},"provider":"Anthropic",
 "event":{"LlmCall":{"pid":1841,"sni":"api.anthropic.com","peer":"160.79.104.10",
 "req_bytes":284,"resp_bytes":3832,"latency":{"secs":1,"nanos":210000000},
 "ttft":{"secs":0,"nanos":410000000}}}}
{"identity":{"agent":"python3","task":"1903","session":null},"provider":null,
 "event":{"ToolExec":{"pid":1903,"ppid":1841,
 "argv":["git","clone","https://github.com/acme/repo"],"argv_truncated":false,
 "argv_incomplete":false,"exec_confirmed":true,"argv_source":"kernel_fragments",
 "captured_argc":3,"captured_bytes":36,"observed_argc":3,"observed_bytes":36,
 "cwd":"/home/agent/work"}}}
{"identity":{"agent":"python3","task":"1841","session":null},"provider":null,
 "event":{"SslContent":{"pid":1841,"is_read":false,
 "content":"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n..."}}}
```

`ToolExec.argv` is reconstructed in the collector from bounded 128-byte kernel records. The
collector captures up to 12 arguments and roughly 8 KiB across argv. `argv_truncated=true` means
the configured limit was reached; `argv_incomplete=true` means a chunk was lost or reassembly
timed out. After `sched_process_exec` confirms a successful exec, the collector attempts to replace
truncated/incomplete fragments with `/proc/<pid>/cmdline` (bounded to 2 MiB). `argv_source` states
which source won and `exec_confirmed` distinguishes committed execs from failed attempts. Very
short-lived processes can exit before `/proc` is read, so the explicit truncation/incomplete flags
remain the authoritative evidence-quality signal. Neither condition is silent, and both counters
are included in collector heartbeats.

Filter with `jq`, e.g. every LLM call and its provider:
`… | jq -c 'select(.event.LlmCall) | {agent:.identity.agent, provider, sni:.event.LlmCall.sni}'`.

Set `A3S_OBSERVER_COLLECTOR_ID` and `A3S_NODE_NAME` in DaemonSets when you want stable collector
identity in downstream fleet-health views. If unset, the collector falls back to pod/host names.

### Workload attribution and freshness contract

`EnrichedEvent` can also carry provider-neutral `workload` and `observation` objects for
per-replica signals:

```json
{
  "workload": {
    "workload_id": "workload-01HV7F5N",
    "deployment_id": "deployment-01HV7F6A",
    "revision_id": "revision-sha256:8f3a",
    "replica_id": "replica-0007",
    "provider_unit_id": "containerd:4f6c2d8a",
    "node_id": "node-us-east-1a-03"
  },
  "observation": {
    "observed_at_unix_nanos": 1720000015000000000,
    "sampled_at_unix_nanos": 1720000014000000000,
    "collection_interval_nanos": 15000000000,
    "freshness": "fresh"
  }
}
```

`WorkloadIdentity` is complete by construction: a producer must provide stable workload,
deployment, immutable revision, logical replica, current provider-unit, and node IDs. Each ID is
an opaque platform identifier limited to 128 ASCII bytes and a label-safe alphabet. Producers
must normalize provider IDs and must never copy tenant secrets, display names, or raw user labels
into these fields. A logical `replica_id` survives process restart, adoption, and rescheduling;
`provider_unit_id` changes when the runtime unit is replaced.

`ObservationMetadata` reports an observation time, an optional collection interval, and one of
`fresh`, `stale`, `unavailable`, or `unknown`. Fresh and stale data include the actual sample
timestamp. Unavailable and unknown observations omit it, giving producers an explicit
missing-data state instead of a zero-usage sentinel.

This is the transport contract, not a claim that per-replica resource collection is complete.
Existing `IdentityResolver` implementations return no workload identity by default, and the
node-wide collector intentionally does not apply one static environment identity to every event.
Multi-replica Linux collection, CPU/memory/network/process/restart/availability samples,
restart/adoption fixtures, and equivalent OTLP and Prometheus metric exporters remain follow-up
work.

## Intervene — egress / file / exec (opt-in)

The same vantage point enforces an **external policy** — a plain file any controller writes; the
kernel asks a guard allow/deny per action. The observe-only core is untouched. Both guards are
**hot-reloaded** and **KVM-validated** (a denied action returns `EPERM`):

| guard | mechanism | denies |
|---|---|---|
| `a3s-observer-enforce` | eBPF `cgroup/connect4` | `connect()` to policy IPs/hosts — cgroup-scoped, fail-open, DNS-re-resolved |
| `a3s-observer-fileguard` | fanotify `FAN_OPEN_PERM` + `FAN_OPEN_EXEC_PERM` | `open()` **and** `exec` of policy-listed files |

### Bring your own policy

The decision logic is **yours**, in any language. a3s-observer gives you the signal (events)
and the enforcement primitive (a guard that reads a deny-file); you write the policy in between:

```
events (NDJSON) → your controller (your rules) → deny-file → guard → kernel denies (EPERM)
```

**Egress allow-list** — an agent may only reach approved LLM providers; everything else is cut:

```bash
# 1. observe  →  2. your controller writes the deny-list  →  3. enforce on the agent's cgroup
A3S_OBSERVER_JSON=1 sudo -E a3s-observer-collector \
  | ./scripts/example-controller.py egress-deny.txt &
sudo a3s-observer-enforce /sys/fs/cgroup/<agent> egress-deny.txt
```

The controller is ~10 lines — the `if` is the part you own (`scripts/example-controller.py`):

```python
ALLOWED = {"Anthropic", "OpenAi", "Gemini"}          # your rule
for line in sys.stdin:                               # the NDJSON event stream
    ev = json.loads(line); call = ev.get("event", {}).get("Egress")
    if call and call.get("sni") and ev.get("provider") not in ALLOWED:
        denied.add(call["peer"])                     # → write egress-deny.txt (hot-reloaded)
        open(sys.argv[1], "w").write("\n".join(sorted(denied)) + "\n")
```

**File / exec deny** — no event stream needed, just a path list (also hot-reloaded):

```bash
printf '%s\n' /etc/shadow /usr/bin/curl > deny.txt   # deny open(/etc/shadow) + exec(curl)
sudo a3s-observer-fileguard deny.txt                 # edit deny.txt → applies within ~2s
```

Deny-file formats: **egress** = one IPv4 or hostname per line (hostnames are DNS-re-resolved
each reload); **file/exec** = one path per line. Prefer in-process (Rust) embedding? Implement
the `Policy` trait (`egress` / `file_write` / `exec` → `Verdict`). Full design + both paths:
[`docs/enforcement.md`](docs/enforcement.md).

**Built-in `ProviderPolicy`** — a shipped `Policy` that allow-lists egress **by LLM provider**
(classified from SNI by the default `SniClassifier`, or any `ServiceClassifier` via
`.with_classifier(classifier, allowed)`) and **denies any connection whose provider isn't on the
list** — the `connect4`/cgroup guard enforces the deny in-kernel. observer's side of "keep the
agent on approved models, off the unapproved API relay / supply chain". **Egress-only** —
file/exec stay fail-open. It's the proactive complement to
[a3s-sentry](https://github.com/A3S-Lab/Sentry)'s *reactive* per-destination denies (only approved
providers are ever reachable in the first place), and **host-buildable** — it adds no eBPF, the
core is untouched:

```rust
use a3s_observer::{Provider, ProviderPolicy};

// Default: only a *known, non-approved* provider is denied; unknown destinations
// (package mirrors, telemetry, your own APIs) still pass — deny_unclassified is false.
let policy = ProviderPolicy::new([Provider::Anthropic, Provider::OpenAi]);
// api.anthropic.com → Allow · api.deepseek.com → Deny (known provider, not approved) · github.com → Allow

// Strict "approved providers only" cage: anything that isn't allow-listed — incl. unknown hosts — is denied.
let cage = ProviderPolicy::new([Provider::Anthropic]).deny_unclassified(true);
// api.anthropic.com → Allow · github.com → Deny · no-SNI → Deny
```

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

## Tested

Soak-tested under sustained load — observe on real hosts (including a **24-min large-scale soak
across an 8-node Kubernetes cluster**, observe-only DaemonSet: flat RSS, zero drops, zero
restarts, non-disruptive), intervene in an isolated VM:

| path | cases (all leak-free + correct under load) |
|---|---|
| **observe** | steady 20 min · edge-input · **a real a3s-code agent** · throughput 110k ev/60s · memory-bound (256 Mi) · restart ×8 · idle + heartbeat · SIGTERM · concurrent collectors · backpressure · connection-churn · **8-node cluster** |
| **intervene** | egress · file/exec · SSL-content guards — and all three running alongside the collector |

Every new signal is validated live (correct payload, verifier loads clean) and reviewed by an
adversarial multi-agent pass before release — which has **twice** caught a per-thread event
duplication (multithreaded `do_exit` / `setuid`) that single-threaded tests missed. Soak also
surfaced two robustness bugs, since fixed: NDJSON stdout pollution (v0.9.1) and an
output-backpressure event-loop stall (v0.9.2). Lib line coverage **79.6%** (`cargo llvm-cov`) —
the untrusted SNI / DNS / cgroup parsers and the full 15-provider classifier are unit-tested.

## Security

Privileged component — see [SECURITY.md](SECURITY.md) for the disclosure policy and how to
verify a release image's signature (cosign / Sigstore).

## License

MIT
