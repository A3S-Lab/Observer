//! compat25: kernel-side file prefilter for the 4.19 legacy backend.
//!
//! Port of the modern backend's file-filter snapshot loader (`FileFilterMapManager` +
//! `FileFilterRuleReloader` in the crate root). Parses the forwarder's
//! `anysentry.filter_rule_snapshot.v1` document from `ANYSENTRY_FILTER_RULES_FILE`, installs
//! the rules into the `FILE_FILTER_RULES` map with an atomic epoch switch, and reports honest
//! `fileFilterMetrics` from the per-CPU `FILE_FILTER_STATS` map.
//!
//! Fail-open contract: with no rules path configured, a missing map, or an unreadable
//! snapshot, the kernel config stays disabled and every file event is kept — exactly the
//! historical legacy behavior.

use a3s_observer_common::{
    FileFilterConfig, FileFilterKey, FileFilterStats, FileFilterValue, FILE_FILTER_ACTION_DROP,
    FILE_FILTER_ACTION_KEEP, FILE_FILTER_ACTION_SAMPLE, FILE_FILTER_AUTHORITY_AUTHORITATIVE,
    FILE_FILTER_AUTHORITY_CANDIDATE, FILE_FILTER_CONFIG_ENABLED, FILE_FILTER_CONFIG_UNKNOWN_DROP,
    FILE_FILTER_CONFIG_UNKNOWN_SAMPLE,
};
use aya::maps::{Array, HashMap as BpfHashMap, MapData, PerCpuArray};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::PathBuf;

use super::{bounded_env_u64, env_any, json_string, parse_rfc3339_unix_nanos, pod_bytes,
            pod_from_bytes, parse_unknown_file_policy, UnknownFilePolicy};

const FILTER_RULE_SNAPSHOT_SCHEMA: &str = "anysentry.filter_rule_snapshot.v1";
const FILTER_RULE_SNAPSHOT_MAX_BYTES: u64 = 4 * 1024 * 1024;
const FILTER_RULE_SNAPSHOT_MAX_ENTRIES: usize = 65_536;
const DEFAULT_UNKNOWN_PER_CGROUP: u32 = 20;
const DEFAULT_UNKNOWN_PER_NODE: u32 = 1_000;
const DEFAULT_UNKNOWN_WINDOW_MS: u64 = 1_000;

pub(super) struct ParsedFileFilterSnapshot {
    epoch: u64,
    rules: Vec<(FileFilterKey, FileFilterValue)>,
}

fn now_unix_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default()
}

/// CLOCK_MONOTONIC-ish base from /proc/uptime; the kernel side stamps expiry in boot ns.
fn now_boot_ns() -> u64 {
    let uptime = std::fs::read_to_string("/proc/uptime").unwrap_or_default();
    let seconds = uptime
        .split('.')
        .next()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0);
    seconds.saturating_mul(1_000_000_000)
}

pub(super) fn parse_filter_rule_snapshot(
    bytes: &[u8],
    now_unix_ns: u128,
    now_boot_ns: u64,
) -> Result<ParsedFileFilterSnapshot> {
    anyhow::ensure!(
        bytes.len() as u64 <= FILTER_RULE_SNAPSHOT_MAX_BYTES,
        "filter rule snapshot exceeds 4 MiB"
    );
    let document: serde_json::Value =
        serde_json::from_slice(bytes).context("parse filter rule snapshot JSON")?;
    anyhow::ensure!(
        json_string(&document, "schemaVersion")? == FILTER_RULE_SNAPSHOT_SCHEMA,
        "unsupported filter rule snapshot schema",
    );
    let entries = document
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .context("filter rule snapshot `entries` must be an array")?;
    anyhow::ensure!(
        entries.len() <= FILTER_RULE_SNAPSHOT_MAX_ENTRIES,
        "too many filter rule entries"
    );

    let declared_epoch = document.get("epoch").and_then(serde_json::Value::as_u64);
    let mut epoch = declared_epoch;
    let mut seen = HashSet::with_capacity(entries.len());
    let mut rules = Vec::with_capacity(entries.len());
    for entry in entries {
        let cgroup_id = json_string(entry, "cgroupId")?
            .parse::<u64>()
            .context("filter rule cgroupId must be an unsigned decimal integer")?;
        anyhow::ensure!(cgroup_id != 0, "filter rule cgroupId must be non-zero");
        anyhow::ensure!(
            seen.insert(cgroup_id),
            "filter rule snapshot contains a duplicate cgroupId"
        );
        let entry_epoch = entry
            .get("epoch")
            .and_then(serde_json::Value::as_u64)
            .context("filter rule epoch must be an unsigned integer")?;
        anyhow::ensure!(entry_epoch != 0, "filter rule epoch must be non-zero");
        if let Some(expected) = epoch {
            anyhow::ensure!(expected == entry_epoch, "filter rule snapshot mixes epochs");
        } else {
            epoch = Some(entry_epoch);
        }
        let action = match json_string(entry, "action")? {
            "keep" => FILE_FILTER_ACTION_KEEP,
            "sample" => FILE_FILTER_ACTION_SAMPLE,
            "drop" => FILE_FILTER_ACTION_DROP,
            _ => anyhow::bail!("filter rule action must be keep, sample, or drop"),
        };
        let authority = match json_string(entry, "authority")? {
            "authoritative" => FILE_FILTER_AUTHORITY_AUTHORITATIVE,
            "candidate" => FILE_FILTER_AUTHORITY_CANDIDATE,
            _ => anyhow::bail!("filter rule authority must be authoritative or candidate"),
        };
        // A candidate may preserve or sample evidence, but can never authorize a kernel-side drop.
        let safe_action = if action == FILE_FILTER_ACTION_DROP
            && authority != FILE_FILTER_AUTHORITY_AUTHORITATIVE
        {
            FILE_FILTER_ACTION_SAMPLE
        } else {
            action
        };
        let expires_unix_ns = parse_rfc3339_unix_nanos(json_string(entry, "expiresAt")?)?;
        let remaining_ns = expires_unix_ns.saturating_sub(now_unix_ns);
        let expires_at_boot_ns =
            now_boot_ns.saturating_add(remaining_ns.min(u64::MAX as u128) as u64);
        rules.push((
            FileFilterKey {
                cgroup_id,
                epoch: entry_epoch,
            },
            FileFilterValue {
                action: safe_action,
                authority,
                flags: 0,
                _reserved: 0,
                epoch: entry_epoch,
                expires_at_boot_ns,
            },
        ));
    }
    let epoch = epoch.context("an empty filter snapshot must declare a top-level epoch")?;
    anyhow::ensure!(epoch != 0, "filter rule epoch must be non-zero");
    Ok(ParsedFileFilterSnapshot { epoch, rules })
}

/// Loads and owns the kernel-side file-filter maps for the legacy backend. `Option` in the
/// manager methods mirrors the modern backend's semantics: `enabled` is false until the first
/// snapshot applies, so absence of a rules file keeps full capture.
pub(super) struct FileFilterManager {
    rules: BpfHashMap<MapData, [u8; 16], [u8; 24]>,
    config: Array<MapData, [u8; 32]>,
    stats: PerCpuArray<MapData, [u8; 104]>,
    path: PathBuf,
    last_seen: Option<Vec<u8>>,
    installed_keys: Vec<[u8; 16]>,
    active_epoch: u64,
    enabled: bool,
    unknown_policy: UnknownFilePolicy,
    sample_window_ns: u64,
    unknown_per_cgroup_limit: u32,
    unknown_per_cpu_limit: u32,
}

impl FileFilterManager {
    /// `Ok(None)` when the rules-file env is unset (feature off) or the BPF object predates the
    /// FILE_FILTER maps — both keep the historical full-capture behavior.
    pub(super) fn from_env(ebpf: &mut aya::Ebpf) -> Result<Option<Self>> {
        let Some(path) = env_any(&["ANYSENTRY_FILTER_RULES_FILE"]) else {
            return Ok(None);
        };
        let rules = BpfHashMap::try_from(
            ebpf
                .take_map("FILE_FILTER_RULES")
                .context("`FILE_FILTER_RULES` missing")?,
        )?;
        let config = Array::try_from(
            ebpf
                .take_map("FILE_FILTER_CONFIG")
                .context("`FILE_FILTER_CONFIG` missing")?,
        )?;
        let stats = PerCpuArray::try_from(
            ebpf
                .take_map("FILE_FILTER_STATS")
                .context("`FILE_FILTER_STATS` missing")?,
        )?;
        let unknown_policy =
            parse_unknown_file_policy(std::env::var("A3S_OBSERVER_FILE_UNKNOWN_POLICY").ok().as_deref())
                .map_err(anyhow::Error::msg)?;
        let per_cgroup = bounded_env_u64(
            "A3S_OBSERVER_FILE_UNKNOWN_PER_CGROUP",
            DEFAULT_UNKNOWN_PER_CGROUP as u64,
            1,
            100_000,
        ) as u32;
        let per_node = bounded_env_u64(
            "A3S_OBSERVER_FILE_UNKNOWN_PER_NODE",
            DEFAULT_UNKNOWN_PER_NODE as u64,
            1,
            10_000_000,
        );
        let cpus = aya::util::nr_cpus().map(|value| value.max(1)).unwrap_or(1) as u64;
        let per_cpu = per_node.div_ceil(cpus).min(u32::MAX as u64) as u32;
        let window_ms = bounded_env_u64(
            "A3S_OBSERVER_FILE_SAMPLE_WINDOW_MS",
            DEFAULT_UNKNOWN_WINDOW_MS,
            100,
            60_000,
        );
        tracing::info!(
            path = %path,
            unknown_policy = unknown_policy.name(),
            "legacy file prefilter armed; loading rules when the forwarder publishes them"
        );
        Ok(Some(Self {
            rules,
            config,
            stats,
            path: PathBuf::from(path),
            last_seen: None,
            installed_keys: Vec::new(),
            active_epoch: 0,
            enabled: false,
            unknown_policy,
            sample_window_ns: window_ms.saturating_mul(1_000_000),
            unknown_per_cgroup_limit: per_cgroup,
            unknown_per_cpu_limit: per_cpu,
        }))
    }

    pub(super) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(super) fn active_epoch(&self) -> u64 {
        self.active_epoch
    }

    pub(super) fn unknown_policy(&self) -> UnknownFilePolicy {
        self.unknown_policy
    }

    pub(super) fn aggregate_stats(&self) -> FileFilterStats {
        let mut aggregate = FileFilterStats::default();
        let Ok(values) = self.stats.get(&0, 0) else {
            return aggregate;
        };
        for bytes in values.iter() {
            let item = pod_from_bytes::<FileFilterStats, 104>(bytes);
            aggregate.access_kept = aggregate.access_kept.saturating_add(item.access_kept);
            aggregate.access_unknown_kept = aggregate
                .access_unknown_kept
                .saturating_add(item.access_unknown_kept);
            aggregate.access_sampled = aggregate.access_sampled.saturating_add(item.access_sampled);
            aggregate.access_dropped =
                aggregate.access_dropped.saturating_add(item.access_dropped);
            aggregate.access_sample_suppressed = aggregate
                .access_sample_suppressed
                .saturating_add(item.access_sample_suppressed);
            aggregate.delete_kept = aggregate.delete_kept.saturating_add(item.delete_kept);
            aggregate.delete_unknown_kept = aggregate
                .delete_unknown_kept
                .saturating_add(item.delete_unknown_kept);
            aggregate.delete_dropped =
                aggregate.delete_dropped.saturating_add(item.delete_dropped);
            aggregate.rule_hits = aggregate.rule_hits.saturating_add(item.rule_hits);
            aggregate.rule_misses = aggregate.rule_misses.saturating_add(item.rule_misses);
            aggregate.stale_rules = aggregate.stale_rules.saturating_add(item.stale_rules);
            aggregate.access_ring_dropped = aggregate
                .access_ring_dropped
                .saturating_add(item.access_ring_dropped);
            aggregate.delete_ring_dropped = aggregate
                .delete_ring_dropped
                .saturating_add(item.delete_ring_dropped);
        }
        aggregate
    }

    fn read_changed(&mut self) -> Result<Option<Vec<u8>>> {
        let metadata = std::fs::metadata(&self.path)
            .with_context(|| format!("read filter snapshot metadata at {}", self.path.display()))?;
        anyhow::ensure!(
            metadata.len() <= FILTER_RULE_SNAPSHOT_MAX_BYTES,
            "filter rule snapshot exceeds 4 MiB"
        );
        let bytes = std::fs::read(&self.path)
            .with_context(|| format!("read filter snapshot at {}", self.path.display()))?;
        if self.last_seen.as_deref() == Some(bytes.as_slice()) {
            return Ok(None);
        }
        self.last_seen = Some(bytes.clone());
        Ok(Some(bytes))
    }

    /// Initial load; mirrors the modern backend's startup logging on success and warning.
    pub(super) fn initial_load(&mut self) {
        match self.reload() {
            Ok(Some(entries)) => tracing::info!(
                epoch = self.active_epoch,
                entries,
                path = %self.path.display(),
                "loaded initial file filter snapshot"
            ),
            Ok(None) => {}
            Err(error) => tracing::warn!(
                path = %self.path.display(),
                error = %error,
                unknown_policy = self.unknown_policy.name(),
                "initial file filter snapshot unavailable; retaining the configured Unknown policy"
            ),
        }
    }

    /// Reload on change; `Ok(Some(entries))` when a new epoch was applied.
    pub(super) fn reload(&mut self) -> Result<Option<usize>> {
        let Some(bytes) = self.read_changed()? else {
            return Ok(None);
        };
        let parsed = parse_filter_rule_snapshot(&bytes, now_unix_ns(), now_boot_ns())?;
        self.apply(parsed).map(Some)
    }

    fn apply(&mut self, snapshot: ParsedFileFilterSnapshot) -> Result<usize> {
        anyhow::ensure!(
            snapshot.epoch > self.active_epoch,
            "filter rule epoch must increase monotonically"
        );
        let mut inserted = Vec::with_capacity(snapshot.rules.len());
        for (key, value) in &snapshot.rules {
            let key_bytes = pod_bytes::<_, 16>(key);
            let value_bytes = pod_bytes::<_, 24>(value);
            if let Err(error) = self.rules.insert(key_bytes, value_bytes, 0) {
                for rollback_key in &inserted {
                    let _ = self.rules.remove(rollback_key);
                }
                return Err(error).context("populate next FILE_FILTER_RULES epoch");
            }
            inserted.push(key_bytes);
        }

        if let Err(error) = self.write_config(snapshot.epoch) {
            for rollback_key in &inserted {
                let _ = self.rules.remove(rollback_key);
            }
            return Err(error);
        }

        let previous = std::mem::replace(&mut self.installed_keys, inserted);
        self.active_epoch = snapshot.epoch;
        for old_key in previous {
            let _ = self.rules.remove(&old_key);
        }
        Ok(self.installed_keys.len())
    }

    fn write_config(&mut self, epoch: u64) -> Result<()> {
        let mut flags = 0u8;
        // The rules file itself gates enforcement: once a snapshot applied, the prefilter is
        // enabled and the configured Unknown policy decides unmatched cgroups.
        flags |= FILE_FILTER_CONFIG_ENABLED;
        if self.unknown_policy.sampling_enabled() {
            flags |= FILE_FILTER_CONFIG_UNKNOWN_SAMPLE;
        }
        if matches!(self.unknown_policy, UnknownFilePolicy::Drop) {
            flags |= FILE_FILTER_CONFIG_UNKNOWN_DROP;
        }
        let config = FileFilterConfig {
            active_epoch: epoch,
            sample_window_ns: self.sample_window_ns,
            unknown_per_cgroup_limit: self.unknown_per_cgroup_limit,
            unknown_per_cpu_limit: self.unknown_per_cpu_limit,
            flags,
            _reserved: [0; 7],
        };
        self.config
            .set(0, pod_bytes::<_, 32>(&config), 0)
            .context("write FILE_FILTER_CONFIG")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_json(epoch: u64, entries: &str) -> Vec<u8> {
        format!(
            "{{\"schemaVersion\":\"{SCHEMA}\",\"version\":{epoch},\"epoch\":{epoch},\
             \"generatedAt\":\"2026-11-09T00:00:00Z\",\"entries\":[{entries}]}}",
            SCHEMA = FILTER_RULE_SNAPSHOT_SCHEMA
        )
        .into_bytes()
    }

    fn entry(cgroup: u64, action: &str, authority: &str, epoch: u64) -> String {
        format!(
            "{{\"cgroupId\":\"{cgroup}\",\"epoch\":{epoch},\"action\":\"{action}\",\
             \"authority\":\"{authority}\",\"expiresAt\":\"2999-01-01T00:00:00Z\"}}"
        )
    }

    #[test]
    fn parses_keep_and_authoritative_drop() {
        let bytes = snapshot_json(
            7,
            &format!(
                "{},{}",
                entry(109426, "keep", "authoritative", 7),
                entry(109415, "drop", "authoritative", 7)
            ),
        );
        let parsed = parse_filter_rule_snapshot(&bytes, 0, 0).expect("parse");
        assert_eq!(parsed.epoch, 7);
        assert_eq!(parsed.rules.len(), 2);
        let keep = &parsed.rules[0].1;
        assert_eq!(keep.action, FILE_FILTER_ACTION_KEEP);
        assert_eq!(keep.authority, FILE_FILTER_AUTHORITY_AUTHORITATIVE);
        let drop = &parsed.rules[1].1;
        assert_eq!(drop.action, FILE_FILTER_ACTION_DROP);
    }

    #[test]
    fn candidate_drop_is_downgraded_to_sample() {
        let bytes = snapshot_json(3, &entry(42, "drop", "candidate", 3));
        let parsed = parse_filter_rule_snapshot(&bytes, 0, 0).expect("parse");
        assert_eq!(parsed.rules[0].1.action, FILE_FILTER_ACTION_SAMPLE);
        assert_eq!(parsed.rules[0].1.authority, FILE_FILTER_AUTHORITY_CANDIDATE);
    }

    #[test]
    fn mixed_epochs_are_rejected() {
        let bytes = snapshot_json(
            5,
            &format!(
                "{},{}",
                entry(1, "keep", "authoritative", 5),
                entry(2, "keep", "authoritative", 6)
            ),
        );
        assert!(parse_filter_rule_snapshot(&bytes, 0, 0).is_err());
    }

    #[test]
    fn unknown_schema_is_rejected() {
        let bytes = b"{\"schemaVersion\":\"something.else.v1\",\"epoch\":1,\"entries\":[]}";
        assert!(parse_filter_rule_snapshot(bytes, 0, 0).is_err());
    }

    #[test]
    fn empty_entries_require_top_level_epoch() {
        let bytes = snapshot_json(1, "");
        assert!(parse_filter_rule_snapshot(&bytes, 0, 0).is_ok());
        let no_epoch = format!(
            "{{\"schemaVersion\":\"{SCHEMA}\",\"entries\":[]}}",
            SCHEMA = FILTER_RULE_SNAPSHOT_SCHEMA
        );
        assert!(parse_filter_rule_snapshot(no_epoch.as_bytes(), 0, 0).is_err());
    }
}
