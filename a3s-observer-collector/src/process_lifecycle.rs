use a3s_observer::{Identity, ProcessContext, WorkloadIdentity};
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

#[cfg(test)]
use std::time::Duration;

const DEFAULT_LIFECYCLE_LIMIT: usize = 65_536;
const DEFAULT_GENERATIONS_PER_PID: usize = 8;

const SOURCE_EXEC_TOMBSTONE: &str = "exec_tombstone";
const REASON_ANCESTRY_INCOMPLETE: &str = "ancestry_incomplete";
const REASON_EXITED_BEFORE_ENRICHMENT: &str = "process_exited_before_enrichment";
const REASON_PID_REUSE_AMBIGUOUS: &str = "pid_reuse_ambiguous";

#[derive(Clone)]
struct ProcessLifecycleEntry {
    exec_id: u64,
    process: ProcessContext,
    identity: Identity,
    workload: Option<WorkloadIdentity>,
    observed_at: Instant,
}

#[derive(Default)]
struct ProcessLifecycleBucket {
    generations: VecDeque<ProcessLifecycleEntry>,
}

pub(crate) struct ExitLifecycleResolution {
    pub(crate) process: ProcessContext,
    pub(crate) identity: Identity,
    pub(crate) workload: Option<WorkloadIdentity>,
}

/// Bounded, fail-closed lifecycle evidence built from confirmed Exec records.
///
/// PID is only an index. A ProcessExit may inherit a candidate only when the event-time `exec_id`
/// retained by the kernel matches exactly, and the event-time pid/cgroup/comm facts corroborate
/// it. Collector-time `/proc` snapshots never enter this store and cannot substitute for the
/// generation key.
pub(crate) struct ProcessLifecycleStore {
    by_pid: HashMap<u32, ProcessLifecycleBucket>,
    limit: usize,
    generations_per_pid: usize,
    entry_count: usize,
}

impl Default for ProcessLifecycleStore {
    fn default() -> Self {
        Self::new(DEFAULT_LIFECYCLE_LIMIT, DEFAULT_GENERATIONS_PER_PID)
    }
}

impl ProcessLifecycleStore {
    fn new(limit: usize, generations_per_pid: usize) -> Self {
        Self {
            by_pid: HashMap::new(),
            limit: limit.max(1),
            generations_per_pid: generations_per_pid.max(1),
            entry_count: 0,
        }
    }

    pub(crate) fn observe_exec(
        &mut self,
        exec_id: u64,
        exec_confirmed: bool,
        process: ProcessContext,
        identity: Identity,
        workload: Option<WorkloadIdentity>,
        now: Instant,
    ) {
        if !exec_confirmed
            || exec_id == 0
            || process.pid == 0
            || process.cgroup_id == 0
            || process.comm.trim().is_empty()
        {
            return;
        }

        let pid = process.pid;
        // When `/proc` already disappeared, resolver output may have raced with PID reuse. Keep
        // only the kernel comm identity in that case; container/workload identity is inherited
        // only from a start-tick-verified process snapshot.
        let (identity, workload) = if process.start_time_ticks.is_some() {
            (identity, workload)
        } else {
            (kernel_identity(pid, &process.comm), None)
        };
        let bucket = self.by_pid.entry(pid).or_default();
        let same_generation = bucket
            .generations
            .iter()
            .position(|entry| entry.exec_id == exec_id);

        if let Some(index) = same_generation {
            let facts_match = bucket.generations.get(index).is_some_and(|entry| {
                strong_exit_facts_match(
                    &entry.process,
                    process.pid,
                    process.cgroup_id,
                    &process.comm,
                )
            });
            if !facts_match {
                // An exec generation ID must never describe two different kernel fact tuples.
                // Drop the conflicting evidence so a later Exit cannot inherit either version.
                self.remove_generation(pid, index);
                return;
            }
            if let Some(entry) = bucket.generations.get_mut(index) {
                entry.process = merge_process_context(&entry.process, process);
                entry.identity = merge_identity(&entry.identity, identity);
                entry.workload = workload.or_else(|| entry.workload.clone());
                entry.observed_at = now;
            }
            return;
        }

        bucket.generations.push_back(ProcessLifecycleEntry {
            exec_id,
            process,
            identity,
            workload,
            observed_at: now,
        });
        self.entry_count = self.entry_count.saturating_add(1);
        while bucket.generations.len() > self.generations_per_pid {
            if bucket.generations.pop_front().is_some() {
                self.entry_count = self.entry_count.saturating_sub(1);
            }
        }
        self.enforce_limit();
    }

    pub(crate) fn resolve_exit(
        &mut self,
        exec_id: u64,
        exit: ProcessContext,
        _now: Instant,
    ) -> ExitLifecycleResolution {
        let pid = exit.pid;
        let cgroup_id = exit.cgroup_id;
        let comm = exit.comm.clone();
        let minimal = || minimal_exit_context(&exit);
        let fallback_identity = || kernel_identity(pid, &comm);

        let Some(bucket) = self.by_pid.get(&pid) else {
            return unresolved(
                minimal(),
                fallback_identity(),
                REASON_EXITED_BEFORE_ENRICHMENT,
            );
        };

        let mut candidates = bucket
            .generations
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.exec_id == exec_id)
            .map(|(index, _)| index);
        let index = candidates.next();
        if index.is_none() || candidates.next().is_some() {
            let reason = if exec_id != 0 && !bucket.generations.is_empty() {
                REASON_PID_REUSE_AMBIGUOUS
            } else {
                REASON_EXITED_BEFORE_ENRICHMENT
            };
            return unresolved(minimal(), fallback_identity(), reason);
        }

        let index = index.expect("checked above");
        let candidate = bucket.generations[index].clone();
        if !strong_exit_facts_match(&candidate.process, pid, cgroup_id, &comm) {
            self.remove_generation(pid, index);
            return unresolved(minimal(), fallback_identity(), REASON_PID_REUSE_AMBIGUOUS);
        }
        if candidate.process.ppid == 0 {
            self.remove_generation(pid, index);
            return unresolved(minimal(), fallback_identity(), REASON_ANCESTRY_INCOMPLETE);
        }

        self.remove_generation(pid, index);
        let mut process = candidate.process;
        process.pid = pid;
        process.cgroup_id = cgroup_id;
        process.comm = comm;
        process.lifecycle_source = Some(SOURCE_EXEC_TOMBSTONE.to_string());
        process.lifecycle_reason = None;
        ExitLifecycleResolution {
            process,
            identity: candidate.identity,
            workload: candidate.workload,
        }
    }

    fn remove_generation(&mut self, pid: u32, index: usize) {
        let mut remove_bucket = false;
        if let Some(bucket) = self.by_pid.get_mut(&pid) {
            if bucket.generations.remove(index).is_some() {
                self.entry_count = self.entry_count.saturating_sub(1);
            }
            remove_bucket = bucket.generations.is_empty();
        }
        if remove_bucket {
            self.by_pid.remove(&pid);
        }
    }

    fn enforce_limit(&mut self) {
        if self.entry_count <= self.limit {
            return;
        }
        let target = self.limit.saturating_sub((self.limit / 8).max(1)).max(1);
        let mut buckets: Vec<(u32, Instant)> = self
            .by_pid
            .iter()
            .filter_map(|(pid, bucket)| {
                bucket
                    .generations
                    .iter()
                    .map(|entry| entry.observed_at)
                    .min()
                    .map(|oldest| (*pid, oldest))
            })
            .collect();
        buckets.sort_by_key(|(_, oldest)| *oldest);
        for (pid, _) in buckets {
            if self.entry_count <= target {
                break;
            }
            if let Some(removed) = self.by_pid.remove(&pid) {
                self.entry_count = self.entry_count.saturating_sub(removed.generations.len());
            }
        }
    }

    #[cfg(test)]
    fn total_entries(&self) -> usize {
        self.entry_count
    }
}

fn strong_exit_facts_match(process: &ProcessContext, pid: u32, cgroup_id: u64, comm: &str) -> bool {
    pid != 0
        && process.pid == pid
        && cgroup_id != 0
        && process.cgroup_id == cgroup_id
        && !comm.trim().is_empty()
        && process.comm == comm
}

fn merge_process_context(
    existing: &ProcessContext,
    mut incoming: ProcessContext,
) -> ProcessContext {
    incoming.host_id = incoming.host_id.or_else(|| existing.host_id.clone());
    incoming.boot_id = incoming.boot_id.or_else(|| existing.boot_id.clone());
    if incoming.ppid == 0 {
        incoming.ppid = existing.ppid;
    }
    incoming.start_time_ticks = incoming.start_time_ticks.or(existing.start_time_ticks);
    if incoming.comm.is_empty() {
        incoming.comm = existing.comm.clone();
    }
    incoming.mount_namespace = incoming.mount_namespace.or(existing.mount_namespace);
    incoming.exe = incoming.exe.or_else(|| existing.exe.clone());
    incoming.cwd = incoming.cwd.or_else(|| existing.cwd.clone());
    incoming.cgroup = incoming.cgroup.or_else(|| existing.cgroup.clone());
    incoming.lifecycle_source = None;
    incoming.lifecycle_reason = None;
    incoming
}

fn merge_identity(existing: &Identity, incoming: Identity) -> Identity {
    Identity {
        agent: incoming.agent.or_else(|| existing.agent.clone()),
        task: incoming.task.or_else(|| existing.task.clone()),
        session: incoming.session.or_else(|| existing.session.clone()),
    }
}

fn minimal_exit_context(exit: &ProcessContext) -> ProcessContext {
    ProcessContext {
        host_id: exit.host_id.clone(),
        boot_id: exit.boot_id.clone(),
        pid: exit.pid,
        ppid: 0,
        pid_namespace: exit.pid_namespace.clone(),
        namespace_pid: exit.namespace_pid,
        namespace_ppid: None,
        start_time_ticks: None,
        comm: exit.comm.clone(),
        mount_namespace: exit.mount_namespace,
        exe: None,
        cwd: None,
        cgroup: None,
        cgroup_id: exit.cgroup_id,
        lifecycle_source: None,
        lifecycle_reason: None,
    }
}

fn kernel_identity(pid: u32, comm: &str) -> Identity {
    Identity {
        agent: (!comm.trim().is_empty()).then(|| comm.to_string()),
        task: Some(pid.to_string()),
        session: None,
    }
}

fn unresolved(
    mut process: ProcessContext,
    identity: Identity,
    reason: &str,
) -> ExitLifecycleResolution {
    process.lifecycle_reason = Some(reason.to_string());
    ExitLifecycleResolution {
        process,
        identity,
        workload: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(
        pid: u32,
        ppid: u32,
        cgroup_id: u64,
        comm: &str,
        start: Option<u64>,
    ) -> ProcessContext {
        ProcessContext {
            pid,
            ppid,
            cgroup_id,
            comm: comm.to_string(),
            start_time_ticks: start,
            exe: Some(format!("/usr/bin/{comm}")),
            cwd: Some("/workspace".to_string()),
            ..ProcessContext::default()
        }
    }

    fn identity(pid: u32, comm: &str) -> Identity {
        Identity {
            agent: Some(comm.to_string()),
            task: Some(pid.to_string()),
            session: None,
        }
    }

    #[test]
    fn unique_confirmed_exec_recovers_short_lived_exit_ancestry() {
        let now = Instant::now();
        let mut store = ProcessLifecycleStore::new(16, 4);
        store.observe_exec(
            11,
            true,
            context(42, 7, 99, "worker", None),
            identity(42, "worker"),
            None,
            now,
        );

        let resolved = store.resolve_exit(
            11,
            context(42, 0, 99, "worker", None),
            now + Duration::from_millis(10),
        );
        assert_eq!(resolved.process.ppid, 7);
        assert_eq!(resolved.process.exe.as_deref(), Some("/usr/bin/worker"));
        assert_eq!(
            resolved.process.lifecycle_source.as_deref(),
            Some(SOURCE_EXEC_TOMBSTONE)
        );
        assert_eq!(resolved.process.lifecycle_reason, None);
    }

    #[test]
    fn commit_snapshot_and_later_exec_enrichment_share_one_exact_generation() {
        let now = Instant::now();
        let mut store = ProcessLifecycleStore::new(16, 4);
        let mut commit = context(42, 7, 99, "worker", None);
        commit.exe = None;
        commit.mount_namespace = Some(4_026_531_840);
        store.observe_exec(111, true, commit, Identity::default(), None, now);
        store.observe_exec(
            111,
            true,
            context(42, 7, 99, "worker", None),
            identity(42, "worker"),
            None,
            now + Duration::from_millis(1),
        );
        assert_eq!(store.total_entries(), 1);

        let resolved = store.resolve_exit(
            111,
            context(42, 0, 99, "worker", None),
            now + Duration::from_millis(10),
        );
        assert_eq!(resolved.process.ppid, 7);
        assert_eq!(resolved.process.exe.as_deref(), Some("/usr/bin/worker"));
        assert_eq!(resolved.process.mount_namespace, Some(4_026_531_840));
        assert_eq!(store.total_entries(), 0);
    }

    #[test]
    fn matching_start_ticks_restore_only_the_same_process_key() {
        let now = Instant::now();
        let mut store = ProcessLifecycleStore::new(16, 4);
        store.observe_exec(
            12,
            true,
            context(42, 7, 99, "worker", Some(500)),
            identity(42, "worker"),
            None,
            now,
        );

        let resolved = store.resolve_exit(
            12,
            context(42, 0, 99, "worker", Some(500)),
            now + Duration::from_millis(10),
        );
        assert_eq!(resolved.process.ppid, 7);
        assert_eq!(resolved.process.start_time_ticks, Some(500));
        assert_eq!(
            resolved.process.lifecycle_source.as_deref(),
            Some(SOURCE_EXEC_TOMBSTONE)
        );
    }

    #[test]
    fn closed_tombstone_is_not_reused_by_a_later_exit() {
        let now = Instant::now();
        let mut store = ProcessLifecycleStore::new(16, 4);
        store.observe_exec(
            13,
            true,
            context(42, 7, 99, "worker", None),
            identity(42, "worker"),
            None,
            now,
        );
        let first = store.resolve_exit(
            13,
            context(42, 0, 99, "worker", None),
            now + Duration::from_millis(10),
        );
        assert_eq!(first.process.ppid, 7);

        let later = store.resolve_exit(
            13,
            context(42, 999, 99, "worker", Some(999)),
            now + Duration::from_millis(20),
        );
        assert_eq!(later.process.ppid, 0);
        assert_eq!(later.process.start_time_ticks, None);
        assert_eq!(
            later.process.lifecycle_reason.as_deref(),
            Some(REASON_EXITED_BEFORE_ENRICHMENT)
        );
    }

    #[test]
    fn pid_reuse_selects_only_the_event_time_exec_generation() {
        let now = Instant::now();
        let mut store = ProcessLifecycleStore::new(16, 4);
        for (exec_id, start, ppid) in [(21, 500, 7), (22, 600, 8)] {
            store.observe_exec(
                exec_id,
                true,
                context(42, ppid, 99, "worker", Some(start)),
                identity(42, "worker"),
                None,
                now,
            );
        }

        let resolved = store.resolve_exit(
            22,
            context(42, 8, 99, "worker", Some(600)),
            now + Duration::from_millis(10),
        );
        assert_eq!(resolved.process.ppid, 8);
        assert_eq!(resolved.process.start_time_ticks, Some(600));
        assert_eq!(resolved.process.exe.as_deref(), Some("/usr/bin/worker"));
        assert_eq!(
            resolved.process.lifecycle_source.as_deref(),
            Some(SOURCE_EXEC_TOMBSTONE)
        );
    }

    #[test]
    fn same_pid_cgroup_comm_never_substitute_for_a_missing_exec_generation() {
        let now = Instant::now();
        let mut store = ProcessLifecycleStore::new(16, 4);
        store.observe_exec(
            21,
            true,
            context(42, 7, 99, "worker", Some(500)),
            identity(42, "worker"),
            None,
            now,
        );

        // Models an old Exit ring record followed by PID reuse whose new Exec record was lost.
        // Even identical secondary facts and a self-consistent current /proc snapshot cannot
        // authorize inheritance without the Exit event's exact generation.
        let resolved = store.resolve_exit(
            22,
            context(42, 999, 99, "worker", Some(500)),
            now + Duration::from_millis(10),
        );
        assert_eq!(resolved.process.ppid, 0);
        assert_eq!(resolved.process.start_time_ticks, None);
        assert_eq!(resolved.process.exe, None);
        assert_eq!(
            resolved.process.lifecycle_reason.as_deref(),
            Some(REASON_PID_REUSE_AMBIGUOUS)
        );
    }

    #[test]
    fn reexec_keeps_distinct_exec_generations_and_selects_the_latest_exact_id() {
        let now = Instant::now();
        let mut store = ProcessLifecycleStore::new(16, 4);
        store.observe_exec(
            23,
            true,
            context(42, 7, 99, "bash", Some(500)),
            identity(42, "bash"),
            None,
            now,
        );
        store.observe_exec(
            24,
            true,
            context(42, 7, 99, "worker", Some(500)),
            identity(42, "worker"),
            None,
            now + Duration::from_millis(1),
        );
        assert_eq!(store.total_entries(), 2);

        let resolved = store.resolve_exit(
            24,
            context(42, 0, 99, "worker", Some(500)),
            now + Duration::from_millis(10),
        );
        assert_eq!(resolved.process.ppid, 7);
        assert_eq!(resolved.identity.agent.as_deref(), Some("worker"));
    }

    #[test]
    fn active_generation_is_size_bounded_not_age_expired() {
        let now = Instant::now();
        let ttl = Duration::from_secs(1);
        let mut store = ProcessLifecycleStore::new(16, 4);
        store.observe_exec(
            25,
            true,
            context(42, 7, 99, "worker", None),
            identity(42, "worker"),
            None,
            now,
        );

        let resolved = store.resolve_exit(
            25,
            context(42, 999, 99, "worker", Some(999)),
            now + ttl + Duration::from_millis(1),
        );
        assert_eq!(resolved.process.ppid, 7);
        assert_eq!(resolved.process.lifecycle_reason, None);
    }

    #[test]
    fn cgroup_mismatch_fails_closed_and_proc_start_cannot_override_exact_exec() {
        let now = Instant::now();
        let mut store = ProcessLifecycleStore::new(16, 4);
        store.observe_exec(
            31,
            true,
            context(42, 7, 99, "worker", Some(500)),
            identity(42, "worker"),
            None,
            now,
        );

        let cgroup_mismatch = store.resolve_exit(
            31,
            context(42, 7, 100, "worker", None),
            now + Duration::from_millis(10),
        );
        assert_eq!(cgroup_mismatch.process.ppid, 0);
        assert_eq!(
            cgroup_mismatch.process.lifecycle_reason.as_deref(),
            Some(REASON_PID_REUSE_AMBIGUOUS)
        );

        store.observe_exec(
            31,
            true,
            context(42, 7, 99, "worker", Some(500)),
            identity(42, "worker"),
            None,
            now + Duration::from_millis(11),
        );
        let start_mismatch = store.resolve_exit(
            31,
            context(42, 7, 99, "worker", Some(501)),
            now + Duration::from_millis(20),
        );
        assert_eq!(start_mismatch.process.ppid, 7);
        assert_eq!(start_mismatch.process.start_time_ticks, Some(500));
        assert_eq!(
            start_mismatch.process.lifecycle_source.as_deref(),
            Some(SOURCE_EXEC_TOMBSTONE)
        );
    }

    #[test]
    fn missing_or_unconfirmed_exec_is_marked_without_pid_inheritance() {
        let now = Instant::now();
        let mut store = ProcessLifecycleStore::new(16, 4);
        store.observe_exec(
            41,
            false,
            context(42, 7, 99, "worker", Some(500)),
            identity(42, "worker"),
            None,
            now,
        );

        let resolved = store.resolve_exit(
            41,
            context(42, 999, 99, "worker", Some(999)),
            now + Duration::from_millis(10),
        );
        assert_eq!(resolved.process.ppid, 0);
        assert_eq!(resolved.process.start_time_ticks, None);
        assert_eq!(resolved.identity.agent.as_deref(), Some("worker"));
        assert_eq!(
            resolved.process.lifecycle_reason.as_deref(),
            Some(REASON_EXITED_BEFORE_ENRICHMENT)
        );
    }

    #[test]
    fn store_is_bounded_while_retained_exact_generations_remain_usable() {
        let now = Instant::now();
        let mut store = ProcessLifecycleStore::new(2, 2);
        for pid in 1..=3 {
            store.observe_exec(
                pid as u64,
                true,
                context(pid, 1, pid as u64, "worker", Some(pid as u64)),
                identity(pid, "worker"),
                None,
                now + Duration::from_millis(pid as u64),
            );
        }
        assert!(store.total_entries() <= 2);

        let resolved = store.resolve_exit(
            3,
            context(3, 1, 3, "worker", Some(3)),
            now + Duration::from_millis(10),
        );
        assert_eq!(resolved.process.ppid, 1);
        assert_eq!(resolved.process.lifecycle_reason, None);

        let evicted = store.resolve_exit(
            1,
            context(1, 999, 1, "worker", Some(1)),
            now + Duration::from_millis(11),
        );
        assert_eq!(evicted.process.ppid, 0);
        assert_eq!(
            evicted.process.lifecycle_reason.as_deref(),
            Some(REASON_EXITED_BEFORE_ENRICHMENT)
        );
    }
}
