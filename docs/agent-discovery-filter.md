# Agent Discovery Observation Contract

Status: Observer-side implementation contract for `feat/agent-discovery-filter`

## Purpose

Observer supplies stable kernel and process facts to an external Agent identity registry. It does
not decide whether an operation is safe, and this feature does not block, delay, or reject kernel
operations.

The existing tracepoint and kprobe programs remain passive. Agent classification and event routing
are performed by the collector/forwarder using local caches. Any future in-kernel observation
prefilter must be fail-open and must remain separate from Observer's opt-in intervention binaries.

## Required event facts

Every process-scoped event must make the following facts available to the collector:

```text
pid/tgid
ppid when available
cgroup_id captured at event time
kernel comm
event timestamp or lifecycle generation
```

The collector enriches these with bounded, best-effort process data:

```text
host_id
boot_id
process_start_time_ticks
exe
cwd
cgroup path
```

`cgroup_id` must be captured in eBPF rather than derived by reading `/proc` after the event. This is
required for short-lived processes and for O(1) workload lookup.

## Additive NDJSON contract

The public `process` object adds optional fields so older consumers remain compatible:

```json
{
  "process": {
    "host_id": "node-a",
    "boot_id": "8fe1...",
    "pid": 930,
    "ppid": 901,
    "start_time_ticks": 776612,
    "comm": "bash",
    "exe": "/usr/bin/bash",
    "cwd": "/workspace",
    "cgroup_id": 19281,
    "cgroup": "0::/kubepods.slice/..."
  }
}
```

No prompt, environment variable, or file content is added to identity caches. Existing redaction
and bounded argv behavior remains unchanged.

## Lifecycle semantics

- fork records parent-child identity before a short-lived child can exit;
- exec updates executable and argv evidence without changing the process instance;
- exit closes the active process entry and creates a short tombstone downstream;
- PID alone must never carry classification across a start-time change;
- an unavailable `/proc` record produces partial facts, not a fabricated identity.

The current in-kernel `PARENTS` map remains the source for exec parent snapshots. Observer exports
events in an order that drains process exit after other signal rings so downstream caches see the
action before lifecycle cleanup.

## Workload identity boundary

Observer's `WorkloadIdentity` represents a complete physical workload when a platform resolver can
provide every required field. Partial platform identity remains in process/kernel facts and must
not be promoted to a complete `WorkloadIdentity`.

Container and Kubernetes metadata resolution is external to the eBPF hot path:

```text
cgroup_id + cgroup path
  -> full container ID
  -> Pod UID/container metadata
  -> external logical Agent identity
```

Observer does not treat a generic process name, a short Container ID, or an arbitrary Pod label as
a globally stable Agent ID.

## Observation filtering boundary

The first production filter is workload-first and user-space cached:

```text
kernel event
  -> ring buffer
  -> collector process facts
  -> node forwarder WorkloadCache lookup
  -> selected NDJSON batch
```

This reduces forwarding, risk-judgment, storage, and query load without risking irreversible
kernel-side data loss during identity rollout.

An optional later kernel prefilter may use:

```text
TRACKED_CGROUPS[cgroup_id] -> workload_handle + classification
TRACKED_PROCESSES[pid_tgid] -> workload_handle + generation
```

If introduced, it must:

- retain lifecycle and high-signal security events;
- sample unknown workloads for discovery;
- expose per-reason counters;
- default to off;
- support shadow validation;
- never share allow/deny semantics with intervention policy maps.

## Performance constraints

- no control-plane API calls in eBPF or per-event collector code;
- fixed-size event records and map values;
- bounded `/proc` reads and caches;
- bounded queues with loss counters;
- lifecycle-based cache writes and O(1) signal lookups;
- no model calls or database reads;
- no unbounded argv, path, identity, or evidence fields.

Performance acceptance is based on measured filter hit rate, events copied and forwarded, CPU,
RSS, wakeups, ring drops, and output drops. A target is not considered met until validated on the
target kernel and event mix.

## Test requirements

- all raw event layouts preserve and serialize cgroup ID;
- bare-host and container cgroups remain distinguishable;
- process start time parsing handles spaces and parentheses in `comm`;
- missing `/proc` does not prevent an event from carrying kernel cgroup identity;
- PID reuse is detectable from process instance fields;
- existing argv reassembly, provider classification, file, DNS, security, and workload contracts
  remain green;
- the collector still runs observe-only unless an intervention binary is explicitly launched.
