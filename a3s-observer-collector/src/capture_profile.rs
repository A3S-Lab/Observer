use a3s_observer_common::{
    capture_profile_default_actions, CaptureAggregateKey, CaptureAggregateValue, CaptureProcessKey,
    CaptureProfileKey, CaptureProfileValue, CapturePromotionValue, CAPTURE_ACTION_AGGREGATE,
    CAPTURE_ACTION_DROP, CAPTURE_ACTION_FULL, CAPTURE_ACTION_NOT_ENABLED, CAPTURE_ACTION_SAMPLE,
    CAPTURE_DISPOSITION_RULE, CAPTURE_DISPOSITION_STALE, CAPTURE_MODE_ENFORCE, CAPTURE_MODE_LEGACY,
    CAPTURE_MODE_SHADOW, CAPTURE_PROBE_COUNT, CAPTURE_PROBE_FILE_DELETE, CAPTURE_PROBE_FILE_READ,
    CAPTURE_PROFILE_AGENT_FULL, CAPTURE_PROFILE_BUSINESS_CONTEXT, CAPTURE_PROFILE_FLAG_AGENT,
    CAPTURE_PROFILE_FLAG_CONFLICT, CAPTURE_PROFILE_INFRASTRUCTURE_AGGREGATE,
    CAPTURE_PROFILE_INVESTIGATION_FULL, CAPTURE_PROFILE_PROBABLE_INVESTIGATION,
    CAPTURE_PROFILE_SECURITY_FULL, CAPTURE_PROFILE_SELF_HEALTH, CAPTURE_PROFILE_UNKNOWN_DISCOVERY,
    CAPTURE_PROMOTION_FLAG_ROOT, FILE_FILTER_AUTHORITY_AUTHORITATIVE,
    FILE_FILTER_AUTHORITY_CANDIDATE,
};
use anyhow::Context as _;
use aya::maps::{Array, HashMap as BpfHashMap, MapData, PerCpuHashMap};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

type CaptureProfileKeyBytes = [u8; 16];
type CaptureProfileValueBytes = [u8; 48];
type CaptureProfileConfigBytes = [u8; 48];
type CaptureProcessKeyBytes = [u8; 16];
type CapturePromotionValueBytes = [u8; 40];
type CaptureAggregateKeyBytes = [u8; 24];
type CaptureAggregateValueBytes = [u8; 16];

pub(crate) const ACK_SCHEMA: &str = "anysentry.capture_profile_ack.v1";
pub(crate) const SNAPSHOT_SCHEMA: &str = "anysentry.filter_rule_snapshot.v1";
pub(crate) const MAX_SNAPSHOT_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_SNAPSHOT_ENTRIES: usize = 65_536;
pub(crate) const AGGREGATE_MAP_MAX_ENTRIES: usize = 4_096;

pub(crate) const PROBE_NAMES: [&str; CAPTURE_PROBE_COUNT] = [
    "exec",
    "exit",
    "tls",
    "connect",
    "dns",
    "file_access",
    "file_delete",
    "llm",
    "ssl",
    "security",
    "file_read",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaptureProfileMode {
    Legacy,
    Shadow,
    Enforce,
}

impl CaptureProfileMode {
    pub(crate) fn parse(value: Option<&str>) -> anyhow::Result<Self> {
        match value.map(str::trim).filter(|value| !value.is_empty()) {
            None | Some("legacy") => Ok(Self::Legacy),
            Some("shadow") => Ok(Self::Shadow),
            Some("enforce") => Ok(Self::Enforce),
            Some(_) => {
                anyhow::bail!("ANYSENTRY_CAPTURE_PROFILE_MODE must be legacy, shadow, or enforce")
            }
        }
    }

    pub(crate) const fn kernel_mode(self) -> u8 {
        match self {
            Self::Legacy => CAPTURE_MODE_LEGACY,
            Self::Shadow => CAPTURE_MODE_SHADOW,
            Self::Enforce => CAPTURE_MODE_ENFORCE,
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Shadow => "shadow",
            Self::Enforce => "enforce",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CollectorGeneration {
    pub node_id: String,
    pub collector_id: String,
    pub collector_instance_id: String,
    pub host_boot_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreviewReceipt {
    pub collector_instance_id: String,
    pub host_boot_id: String,
    pub publisher_instance_id: String,
    pub epoch: u64,
    pub content_hash: String,
    pub intent_hash: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ParsedCaptureSnapshot {
    pub epoch: u64,
    pub policy_version: u64,
    pub publisher_instance_id: String,
    pub content_hash: String,
    pub intent_hash: String,
    pub effective_actions_hash: String,
    pub expires_at_boot_ns: u64,
    pub rules: Vec<(CaptureProfileKey, CaptureProfileValue)>,
    pub promotions: Vec<(CaptureProcessKey, CapturePromotionValue)>,
    pub entries_applied: usize,
    pub activation_mode: String,
    pub destructive_granted: bool,
    pub downgrades: Vec<String>,
    pub aggregate_metadata: Vec<CaptureAggregateMetadata>,
}

#[derive(Clone, Debug)]
pub(crate) struct CaptureAggregateMetadata {
    pub cgroup_id: u64,
    pub epoch: u64,
    pub policy_version: u64,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Default)]
struct AggregateCursor {
    value: CaptureAggregateValue,
    stable_reads: u8,
    window_started_unix_ns: u128,
}

impl AggregateCursor {
    fn delta(&self, current: CaptureAggregateValue) -> CaptureAggregateValue {
        CaptureAggregateValue {
            count: current
                .count
                .checked_sub(self.value.count)
                .unwrap_or(current.count),
            bytes: current
                .bytes
                .checked_sub(self.value.bytes)
                .unwrap_or(current.bytes),
        }
    }

    fn admit(&mut self, current: CaptureAggregateValue, ended_at_unix_ns: u128) {
        self.value = current;
        self.window_started_unix_ns = ended_at_unix_ns;
        self.stable_reads = 0;
    }

    fn old_epoch_stable(&mut self) -> bool {
        self.stable_reads = self.stable_reads.saturating_add(1);
        self.stable_reads >= 2
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CaptureAggregateReaderStats {
    pub keys: u64,
    pub emitted: u64,
    pub output_retried: u64,
    pub cleaned: u64,
    pub read_errors: u64,
}

pub(crate) struct CaptureAggregateReader {
    map: PerCpuHashMap<MapData, CaptureAggregateKeyBytes, CaptureAggregateValueBytes>,
    cursors: std::collections::BTreeMap<CaptureAggregateKey, AggregateCursor>,
    metadata: std::collections::BTreeMap<(u64, u64), CaptureAggregateMetadata>,
    window_started_unix_ns: u128,
    stats: CaptureAggregateReaderStats,
}

pub(crate) struct CaptureMapManager {
    rules: BpfHashMap<MapData, CaptureProfileKeyBytes, CaptureProfileValueBytes>,
    config: Array<MapData, CaptureProfileConfigBytes>,
    promotions: BpfHashMap<MapData, CaptureProcessKeyBytes, CapturePromotionValueBytes>,
    installed_rules: Vec<CaptureProfileKeyBytes>,
    installed_promotions: Vec<CaptureProcessKeyBytes>,
    pub active_epoch: u64,
    mode: CaptureProfileMode,
    sample_window_ns: u64,
    investigation_ttl_ns: u64,
    sample_per_scope_limit: u32,
    sample_node_limit: u32,
    first_samples: u16,
    sample_cpu_count: u16,
    destructive_enabled: bool,
    expires_at_boot_ns: u64,
}

impl CaptureMapManager {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        rules: BpfHashMap<MapData, CaptureProfileKeyBytes, CaptureProfileValueBytes>,
        config: Array<MapData, CaptureProfileConfigBytes>,
        promotions: BpfHashMap<MapData, CaptureProcessKeyBytes, CapturePromotionValueBytes>,
        mode: CaptureProfileMode,
        sample_window_ns: u64,
        investigation_ttl_ns: u64,
        sample_per_scope_limit: u32,
        sample_node_limit: u32,
        first_samples: u16,
        sample_cpu_count: u16,
    ) -> anyhow::Result<Self> {
        let mut manager = Self {
            rules,
            config,
            promotions,
            installed_rules: Vec::new(),
            installed_promotions: Vec::new(),
            active_epoch: 0,
            mode,
            sample_window_ns,
            investigation_ttl_ns,
            sample_per_scope_limit,
            sample_node_limit,
            first_samples,
            sample_cpu_count,
            destructive_enabled: false,
            expires_at_boot_ns: 0,
        };
        // S5 starts in discovery-safe mode before reading disk. This closes the startup race where
        // a residual v1 authoritative DROP would otherwise execute before the first S5 ACK.
        manager.write_config(0, 0, false)?;
        Ok(manager)
    }

    fn write_config(
        &mut self,
        epoch: u64,
        expires_at_boot_ns: u64,
        destructive: bool,
    ) -> anyhow::Result<()> {
        use a3s_observer_common::{
            CaptureProfileConfig, CAPTURE_CONFIG_DESTRUCTIVE_GRANTED, CAPTURE_CONFIG_ENABLED,
        };
        let config = CaptureProfileConfig {
            active_epoch: epoch,
            expires_at_boot_ns,
            sample_window_ns: self.sample_window_ns,
            investigation_ttl_ns: self.investigation_ttl_ns,
            sample_per_scope_limit: self.sample_per_scope_limit,
            sample_node_limit: self.sample_node_limit,
            first_samples: self.first_samples,
            sample_cpu_count: self.sample_cpu_count,
            flags: CAPTURE_CONFIG_ENABLED
                | if destructive {
                    CAPTURE_CONFIG_DESTRUCTIVE_GRANTED
                } else {
                    0
                },
            mode: self.mode.kernel_mode(),
            _reserved: [0; 2],
        };
        self.config
            .set(0, super::pod_bytes::<_, 48>(&config), 0)
            .context("write CAPTURE_PROFILE_CONFIG")?;
        self.destructive_enabled = destructive;
        self.expires_at_boot_ns = expires_at_boot_ns;
        Ok(())
    }

    pub(crate) fn apply_safe(
        &mut self,
        snapshot: &mut ParsedCaptureSnapshot,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            snapshot.epoch > self.active_epoch,
            "capture profile epoch must increase monotonically"
        );
        // Revoke the previous generation before touching either map. Any population/config error
        // therefore leaves the old LKG rules usable only in non-destructive discovery-safe mode.
        self.write_config(self.active_epoch, 0, false)
            .context("revoke destructive capture before epoch population")?;
        let mut inserted_rules = Vec::with_capacity(snapshot.rules.len());
        let mut inserted_promotions = Vec::with_capacity(snapshot.promotions.len());
        for (key, value) in &snapshot.rules {
            let key = super::pod_bytes::<_, 16>(key);
            if let Err(error) = self.rules.insert(key, super::pod_bytes::<_, 48>(value), 0) {
                for rollback in &inserted_rules {
                    let _ = self.rules.remove(rollback);
                }
                return Err(error).context("populate CAPTURE_PROFILE_RULES epoch");
            }
            inserted_rules.push(key);
        }
        for (key, value) in &snapshot.promotions {
            let promotion_pid = key.pid;
            let key = super::pod_bytes::<_, 16>(key);
            if let Err(error) = self
                .promotions
                .insert(key, super::pod_bytes::<_, 40>(value), 0)
            {
                // The cgroup profile rule is already an Agent FULL safety fallback. Preserve it,
                // report the missing root-granular capability, and never enable destructive mode
                // for this snapshot rather than reverting to a possibly low-volume old profile.
                snapshot.downgrades.push(format!(
                    "root_promotion_map_failed:pid={}:{}",
                    promotion_pid, error
                ));
                continue;
            }
            inserted_promotions.push(key);
        }
        if let Err(error) = self.write_config(snapshot.epoch, snapshot.expires_at_boot_ns, false) {
            for rollback in &inserted_promotions {
                let _ = self.promotions.remove(rollback);
            }
            for rollback in &inserted_rules {
                let _ = self.rules.remove(rollback);
            }
            return Err(error);
        }
        let old_rules = std::mem::replace(&mut self.installed_rules, inserted_rules);
        let old_promotions = std::mem::replace(&mut self.installed_promotions, inserted_promotions);
        self.active_epoch = snapshot.epoch;
        for key in old_promotions {
            let _ = self.promotions.remove(&key);
        }
        for key in old_rules {
            let _ = self.rules.remove(&key);
        }
        Ok(())
    }

    pub(crate) fn enable_destructive(
        &mut self,
        snapshot: &ParsedCaptureSnapshot,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            snapshot.epoch == self.active_epoch,
            "capture profile epoch changed before ACK"
        );
        anyhow::ensure!(
            snapshot.destructive_granted,
            "capture profile has no valid destructive grant"
        );
        anyhow::ensure!(
            snapshot.downgrades.is_empty(),
            "capture profile was safety-downgraded"
        );
        self.write_config(snapshot.epoch, snapshot.expires_at_boot_ns, true)
    }

    pub(crate) fn revoke_destructive(&mut self, expires_at_boot_ns: u64) -> anyhow::Result<()> {
        self.write_config(self.active_epoch, expires_at_boot_ns, false)
    }

    pub(crate) const fn destructive_enabled(&self) -> bool {
        self.destructive_enabled
    }

    pub(crate) const fn destructive_effective(&self, now_boot_ns: u64) -> bool {
        self.destructive_enabled
            && self.expires_at_boot_ns != 0
            && now_boot_ns < self.expires_at_boot_ns
    }

    pub(crate) const fn sample_node_limit(&self) -> u32 {
        self.sample_node_limit
    }

    pub(crate) const fn mode(&self) -> CaptureProfileMode {
        self.mode
    }
}

impl CaptureAggregateReader {
    pub(crate) fn new(
        map: PerCpuHashMap<MapData, CaptureAggregateKeyBytes, CaptureAggregateValueBytes>,
        started_at_unix_ns: u128,
    ) -> Self {
        Self {
            map,
            cursors: std::collections::BTreeMap::new(),
            metadata: std::collections::BTreeMap::new(),
            window_started_unix_ns: started_at_unix_ns,
            stats: CaptureAggregateReaderStats::default(),
        }
    }

    pub(crate) fn register_snapshot(&mut self, snapshot: &ParsedCaptureSnapshot) {
        for metadata in &snapshot.aggregate_metadata {
            self.metadata
                .insert((metadata.cgroup_id, metadata.epoch), metadata.clone());
        }
    }

    pub(crate) const fn stats(&self) -> CaptureAggregateReaderStats {
        self.stats
    }

    pub(crate) fn drain(
        &mut self,
        exporter: &dyn a3s_observer::Exporter,
        active_epoch: u64,
        ended_at_unix_ns: u128,
        shutdown_terminal: bool,
    ) {
        let mut cleanup = Vec::new();
        let mut seen = 0u64;
        for item in self.map.iter() {
            let (key_bytes, per_cpu) = match item {
                Ok(item) => item,
                Err(_) => {
                    self.stats.read_errors = self.stats.read_errors.saturating_add(1);
                    continue;
                }
            };
            seen = seen.saturating_add(1);
            let key = super::pod_from_bytes::<CaptureAggregateKey, 24>(&key_bytes);
            let mut current = CaptureAggregateValue::default();
            for bytes in per_cpu.iter() {
                let value = super::pod_from_bytes::<CaptureAggregateValue, 16>(bytes);
                current.count = current.count.saturating_add(value.count);
                current.bytes = current.bytes.saturating_add(value.bytes);
            }
            let cursor = self.cursors.entry(key).or_insert(AggregateCursor {
                value: CaptureAggregateValue::default(),
                stable_reads: 0,
                window_started_unix_ns: self.window_started_unix_ns,
            });
            let delta = cursor.delta(current);
            let old_epoch = key.epoch != active_epoch;
            if delta.count != 0 || delta.bytes != 0 {
                let metadata = self.metadata.get(&(key.cgroup_id, key.epoch));
                let rule_attributed = key.disposition == CAPTURE_DISPOSITION_RULE;
                let event = a3s_observer::EnrichedEvent {
                    timing: None,
                    capture_decision: None,
                    identity: a3s_observer::Identity::default(),
                    workload: None,
                    observation: None,
                    process: Some(a3s_observer::ProcessContext {
                        cgroup_id: key.cgroup_id,
                        ..a3s_observer::ProcessContext::default()
                    }),
                    provider: None,
                    event: a3s_observer::AgentEvent::CaptureAggregate {
                        window_start_unix_ns: cursor.window_started_unix_ns,
                        window_start_unix_ns_exact: cursor.window_started_unix_ns.to_string(),
                        window_end_unix_ns: ended_at_unix_ns,
                        window_end_unix_ns_exact: ended_at_unix_ns.to_string(),
                        cgroup_id: key.cgroup_id,
                        probe: PROBE_NAMES
                            .get(key.probe as usize)
                            .copied()
                            .unwrap_or("unknown")
                            .to_string(),
                        effective_action: action_name(key.action).to_string(),
                        qualifier: key.qualifier,
                        profile: profile_name(key.profile).to_string(),
                        epoch: key.epoch,
                        policy_version: if rule_attributed {
                            metadata.map(|value| value.policy_version).unwrap_or(0)
                        } else {
                            0
                        },
                        count: delta.count,
                        bytes: delta.bytes,
                        authority: authority_name(key.authority).to_string(),
                        reason: if rule_attributed {
                            metadata
                                .map(|value| value.reason.clone())
                                .unwrap_or_else(|| "snapshot_metadata_missing".to_string())
                        } else if key.disposition == CAPTURE_DISPOSITION_STALE {
                            "stale_or_expired_discovery".to_string()
                        } else {
                            "rule_miss_discovery".to_string()
                        },
                        terminal: shutdown_terminal || old_epoch,
                    },
                };
                match exporter.export_with_priority(&event, a3s_observer::ExportPriority::Bulk) {
                    a3s_observer::ExportOutcome::Admitted => {
                        cursor.admit(current, ended_at_unix_ns);
                        self.stats.emitted = self.stats.emitted.saturating_add(1);
                    }
                    a3s_observer::ExportOutcome::Dropped => {
                        self.stats.output_retried = self.stats.output_retried.saturating_add(1);
                    }
                }
            } else if old_epoch && cursor.old_epoch_stable() {
                cleanup.push(key);
            }
        }
        self.stats.keys = seen;
        for key in cleanup {
            let raw = super::pod_bytes::<_, 24>(&key);
            match self.map.remove(&raw) {
                Ok(()) => {
                    self.cursors.remove(&key);
                    self.stats.cleaned = self.stats.cleaned.saturating_add(1);
                }
                Err(_) => self.stats.read_errors = self.stats.read_errors.saturating_add(1),
            }
        }
        // Snapshot metadata without a corresponding aggregate key must not accumulate forever.
        // Keep the active epoch plus old epochs that still have at least one admitted cursor.
        prune_aggregate_metadata(&mut self.metadata, &self.cursors, active_epoch);
        self.window_started_unix_ns = ended_at_unix_ns;
    }
}

fn prune_aggregate_metadata(
    metadata: &mut std::collections::BTreeMap<(u64, u64), CaptureAggregateMetadata>,
    cursors: &std::collections::BTreeMap<CaptureAggregateKey, AggregateCursor>,
    active_epoch: u64,
) {
    let live = cursors
        .keys()
        .map(|key| (key.cgroup_id, key.epoch))
        .collect::<std::collections::BTreeSet<_>>();
    metadata.retain(|key, _| key.1 == active_epoch || live.contains(key));
}

fn non_empty_string<'a>(value: &'a Value, field: &str) -> anyhow::Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("capture profile field `{field}` must be a non-empty string"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

/// JSON.stringify over recursively key-sorted objects. Arrays retain order and JSON has no
/// `undefined`, matching the Forwarder contract exactly.
pub(crate) fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("serialize JSON string"),
        Value::Array(values) => {
            let body = values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{body}]")
        }
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let body = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("serialize JSON key"),
                        canonical_json(&values[key])
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
    }
}

pub(crate) fn canonical_digest(value: &Value) -> String {
    sha256_hex(canonical_json(value).as_bytes())
}

fn content_hash(document: &Value) -> anyhow::Result<String> {
    let mut payload = document
        .as_object()
        .cloned()
        .context("capture profile snapshot must be an object")?;
    payload.remove("contentHash");
    Ok(canonical_digest(&Value::Object(payload)))
}

fn copy_if_present(target: &mut Map<String, Value>, source: &Value, field: &str) {
    if let Some(value) = source.get(field) {
        target.insert(field.to_string(), value.clone());
    }
}

fn intent_projection(entries: &[Value], policy_version: u64) -> anyhow::Result<Value> {
    let mut projected = Vec::with_capacity(entries.len());
    for entry in entries {
        let mut value = Map::new();
        value.insert("scopeType".to_string(), Value::String("cgroup".to_string()));
        for field in [
            "scopeKey",
            "cgroupId",
            "classification",
            "authority",
            "captureProfile",
            "captureIntent",
            "desiredProbeActions",
            "reasonCode",
            "source",
            "physicalWorkloadId",
            "agentInstanceId",
            "ruleId",
            "ruleRevision",
            "policyVersion",
            "ttlMs",
        ] {
            copy_if_present(&mut value, entry, field);
        }
        projected.push(Value::Object(value));
    }
    projected.sort_by(|left, right| {
        left.get("scopeKey")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(
                right
                    .get("scopeKey")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            )
    });
    Ok(json!({ "policyVersion": policy_version, "entries": projected }))
}

fn effective_actions_projection(entries: &[Value]) -> Value {
    let mut projected = entries
        .iter()
        .map(|entry| {
            json!({
                "scopeKey": entry.get("scopeKey").cloned().unwrap_or(Value::Null),
                "probeActions": entry.get("probeActions").cloned().unwrap_or(Value::Null),
            })
        })
        .collect::<Vec<_>>();
    projected.sort_by(|left, right| {
        left["scopeKey"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["scopeKey"].as_str().unwrap_or_default())
    });
    Value::Array(projected)
}

fn parse_action(value: &str) -> anyhow::Result<u8> {
    match value {
        "full" => Ok(CAPTURE_ACTION_FULL),
        "aggregate" => Ok(CAPTURE_ACTION_AGGREGATE),
        "sample" => Ok(CAPTURE_ACTION_SAMPLE),
        "drop" => Ok(CAPTURE_ACTION_DROP),
        "not_enabled" => Ok(CAPTURE_ACTION_NOT_ENABLED),
        _ => anyhow::bail!("unknown capture probe action `{value}`"),
    }
}

fn action_name(action: u8) -> &'static str {
    match action {
        CAPTURE_ACTION_AGGREGATE => "aggregate",
        CAPTURE_ACTION_SAMPLE => "sample",
        CAPTURE_ACTION_DROP => "drop",
        CAPTURE_ACTION_NOT_ENABLED => "not_enabled",
        _ => "full",
    }
}

fn profile_name(profile: u8) -> &'static str {
    match profile {
        CAPTURE_PROFILE_AGENT_FULL => "agent_full",
        CAPTURE_PROFILE_INVESTIGATION_FULL => "investigation_full",
        CAPTURE_PROFILE_SECURITY_FULL => "security_full",
        CAPTURE_PROFILE_BUSINESS_CONTEXT => "business_context",
        CAPTURE_PROFILE_INFRASTRUCTURE_AGGREGATE => "infrastructure_aggregate",
        CAPTURE_PROFILE_SELF_HEALTH => "self_health",
        CAPTURE_PROFILE_PROBABLE_INVESTIGATION => "probable_investigation",
        _ => "unknown_discovery",
    }
}

fn authority_name(authority: u8) -> &'static str {
    match authority {
        FILE_FILTER_AUTHORITY_AUTHORITATIVE => "authoritative",
        FILE_FILTER_AUTHORITY_CANDIDATE => "candidate",
        _ => "discovery",
    }
}

fn effective_hash_from_rules(rules: &[(CaptureProfileKey, CaptureProfileValue)]) -> String {
    let mut entries = rules
        .iter()
        .map(|(key, value)| {
            let actions = PROBE_NAMES
                .iter()
                .enumerate()
                .map(|(index, name)| {
                    (
                        (*name).to_string(),
                        Value::String(action_name(value.actions[index]).to_string()),
                    )
                })
                .collect::<Map<_, _>>();
            json!({
                "scopeKey": format!("cgroup:{}", key.cgroup_id),
                "probeActions": actions,
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left["scopeKey"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["scopeKey"].as_str().unwrap_or_default())
    });
    canonical_digest(&Value::Array(entries))
}

fn parse_profile(value: &str) -> anyhow::Result<u8> {
    match value {
        "agent_full" => Ok(CAPTURE_PROFILE_AGENT_FULL),
        "investigation_full" => Ok(CAPTURE_PROFILE_INVESTIGATION_FULL),
        "security_full" => Ok(CAPTURE_PROFILE_SECURITY_FULL),
        "business_context" => Ok(CAPTURE_PROFILE_BUSINESS_CONTEXT),
        "infrastructure_aggregate" => Ok(CAPTURE_PROFILE_INFRASTRUCTURE_AGGREGATE),
        "unknown_discovery" => Ok(CAPTURE_PROFILE_UNKNOWN_DISCOVERY),
        "self_health" => Ok(CAPTURE_PROFILE_SELF_HEALTH),
        "probable_investigation" => Ok(CAPTURE_PROFILE_PROBABLE_INVESTIGATION),
        _ => anyhow::bail!("unknown capture profile `{value}`"),
    }
}

fn parse_probe_actions(value: &Value, field: &str) -> anyhow::Result<[u8; CAPTURE_PROBE_COUNT]> {
    let object = value
        .as_object()
        .with_context(|| format!("capture profile `{field}` must be an object"))?;
    anyhow::ensure!(
        object.keys().all(|key| PROBE_NAMES.contains(&key.as_str()))
            && object.len() >= PROBE_NAMES.len() - 1
            && object.len() <= PROBE_NAMES.len(),
        "capture profile `{field}` must contain the ten legacy probes and optional file_read"
    );
    let mut actions = [CAPTURE_ACTION_FULL; CAPTURE_PROBE_COUNT];
    actions[CAPTURE_PROBE_FILE_READ as usize] = CAPTURE_ACTION_NOT_ENABLED;
    for (index, probe) in PROBE_NAMES.iter().enumerate() {
        let Some(value) = object.get(*probe) else {
            anyhow::ensure!(
                *probe == "file_read",
                "capture profile `{field}.{probe}` must be present",
            );
            continue;
        };
        actions[index] = parse_action(
            value
                .as_str()
                .with_context(|| format!("capture profile `{field}.{probe}` must be a string"))?,
        )?;
    }
    Ok(actions)
}

fn optional_exact_u64(
    entry: &Value,
    exact_field: &str,
    legacy_field: &str,
) -> anyhow::Result<Option<u64>> {
    if let Some(value) = entry.get(exact_field) {
        let decimal = value
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .with_context(|| format!("capture profile `{exact_field}` must be a decimal string"))?;
        anyhow::ensure!(
            decimal.bytes().all(|byte| byte.is_ascii_digit()),
            "capture profile `{exact_field}` must be an unsigned decimal string"
        );
        return decimal
            .parse::<u64>()
            .map(Some)
            .with_context(|| format!("capture profile `{exact_field}` exceeds u64"));
    }
    let Some(value) = entry.get(legacy_field) else {
        return Ok(None);
    };
    if let Some(decimal) = value.as_str() {
        let decimal = decimal.trim();
        anyhow::ensure!(
            !decimal.is_empty() && decimal.bytes().all(|byte| byte.is_ascii_digit()),
            "capture profile `{legacy_field}` must be an unsigned decimal"
        );
        return decimal
            .parse::<u64>()
            .map(Some)
            .with_context(|| format!("capture profile `{legacy_field}` exceeds u64"));
    }
    value
        .as_u64()
        .map(Some)
        .with_context(|| format!("capture profile `{legacy_field}` must be an unsigned integer"))
}

fn unix_expiry_to_boot(
    value: &str,
    now_unix_ns: u128,
    now_boot_ns: u64,
) -> anyhow::Result<(u128, u64)> {
    let unix_ns = super::parse_rfc3339_unix_nanos(value)?;
    anyhow::ensure!(unix_ns > now_unix_ns, "capture profile expiry is stale");
    let remaining = unix_ns.saturating_sub(now_unix_ns);
    Ok((
        unix_ns,
        now_boot_ns.saturating_add(remaining.min(u64::MAX as u128) as u64),
    ))
}

fn grant_matches(
    document: &Value,
    generation: &CollectorGeneration,
    previous: Option<&PreviewReceipt>,
    publisher: &str,
    intent_hash: &str,
    snapshot_expiry_unix_ns: u128,
    now_unix_ns: u128,
) -> Result<u128, String> {
    let grant = document
        .get("activationGrant")
        .and_then(Value::as_object)
        .ok_or_else(|| "activation_grant_missing".to_string())?;
    let field = |name: &str| {
        grant
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("activation_grant_{name}_missing"))
    };
    let preview = previous.ok_or_else(|| "preview_not_seen_by_current_instance".to_string())?;
    if field("collectorInstanceId")? != generation.collector_instance_id {
        return Err("activation_grant_collector_instance_mismatch".to_string());
    }
    if field("hostBootId")? != generation.host_boot_id {
        return Err("activation_grant_boot_mismatch".to_string());
    }
    if field("publisherInstanceId")? != publisher {
        return Err("activation_grant_publisher_mismatch".to_string());
    }
    if grant.get("previewEpoch").and_then(Value::as_u64) != Some(preview.epoch) {
        return Err("activation_grant_preview_epoch_mismatch".to_string());
    }
    if field("previewContentHash")? != preview.content_hash {
        return Err("activation_grant_preview_content_mismatch".to_string());
    }
    if field("intentHash")? != intent_hash || preview.intent_hash != intent_hash {
        return Err("activation_grant_intent_mismatch".to_string());
    }
    if preview.collector_instance_id != generation.collector_instance_id
        || preview.host_boot_id != generation.host_boot_id
        || preview.publisher_instance_id != publisher
    {
        return Err("preview_generation_mismatch".to_string());
    }
    field("centralReportId")?;
    let expires = field("expiresAt").and_then(|value| {
        super::parse_rfc3339_unix_nanos(value)
            .map_err(|_| "activation_grant_expiry_invalid".to_string())
    })?;
    if expires <= now_unix_ns || snapshot_expiry_unix_ns > expires {
        return Err("activation_grant_expired_or_shorter_than_snapshot".to_string());
    }
    Ok(expires)
}

pub(crate) fn parse_snapshot(
    bytes: &[u8],
    runtime_mode: CaptureProfileMode,
    generation: &CollectorGeneration,
    previous: Option<&PreviewReceipt>,
    now_unix_ns: u128,
    now_boot_ns: u64,
) -> anyhow::Result<ParsedCaptureSnapshot> {
    anyhow::ensure!(
        runtime_mode != CaptureProfileMode::Legacy,
        "S5 parser disabled in legacy mode"
    );
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_SNAPSHOT_BYTES,
        "capture profile snapshot exceeds 4 MiB"
    );
    let document: Value =
        serde_json::from_slice(bytes).context("parse capture profile snapshot JSON")?;
    anyhow::ensure!(
        non_empty_string(&document, "schemaVersion")? == SNAPSHOT_SCHEMA,
        "unsupported capture profile snapshot schema"
    );
    anyhow::ensure!(
        non_empty_string(&document, "captureProfileMode")? == runtime_mode.name(),
        "snapshot captureProfileMode does not match collector rollout mode"
    );
    let publisher = non_empty_string(&document, "publisherInstanceId")?.to_string();
    let epoch = document
        .get("epoch")
        .and_then(Value::as_u64)
        .context("capture profile epoch must be an unsigned integer")?;
    anyhow::ensure!(epoch != 0, "capture profile epoch must be non-zero");
    let policy_version = document
        .get("policyVersion")
        .and_then(Value::as_u64)
        .context("capture profile policyVersion must be an unsigned integer")?;
    let supplied_content_hash = non_empty_string(&document, "contentHash")?.to_string();
    anyhow::ensure!(
        supplied_content_hash == content_hash(&document)?,
        "capture profile contentHash mismatch"
    );
    let supplied_intent_hash = non_empty_string(&document, "intentHash")?.to_string();
    let entries = document
        .get("entries")
        .and_then(Value::as_array)
        .context("capture profile entries must be an array")?;
    anyhow::ensure!(
        entries.len() <= MAX_SNAPSHOT_ENTRIES,
        "too many capture profile entries"
    );
    anyhow::ensure!(
        document.get("expectedEntries").and_then(Value::as_u64) == Some(entries.len() as u64),
        "capture profile expectedEntries mismatch"
    );
    anyhow::ensure!(
        supplied_intent_hash == canonical_digest(&intent_projection(entries, policy_version)?),
        "capture profile intentHash mismatch"
    );
    let supplied_effective_hash = non_empty_string(&document, "effectiveActionsHash")?.to_string();
    anyhow::ensure!(
        supplied_effective_hash == canonical_digest(&effective_actions_projection(entries)),
        "capture profile effectiveActionsHash mismatch"
    );

    let (snapshot_expiry_unix, snapshot_expiry_boot) = unix_expiry_to_boot(
        non_empty_string(&document, "expiresAt")?,
        now_unix_ns,
        now_boot_ns,
    )?;
    let activation_mode = document
        .get("activation")
        .and_then(Value::as_object)
        .and_then(|value| value.get("mode"))
        .and_then(Value::as_str)
        .context("capture profile activation.mode missing")?
        .to_string();
    let mut downgrades = Vec::new();
    let grant_expiry =
        if runtime_mode == CaptureProfileMode::Enforce && activation_mode == "enforce" {
            match grant_matches(
                &document,
                generation,
                previous,
                &publisher,
                &supplied_intent_hash,
                snapshot_expiry_unix,
                now_unix_ns,
            ) {
                Ok(expiry) => Some(expiry),
                Err(reason) => {
                    downgrades.push(reason);
                    None
                }
            }
        } else {
            None
        };
    anyhow::ensure!(
        (runtime_mode == CaptureProfileMode::Shadow && activation_mode == "shadow")
            || (runtime_mode == CaptureProfileMode::Enforce
                && matches!(activation_mode.as_str(), "preview" | "enforce")),
        "invalid activation mode for collector rollout mode"
    );
    let destructive_granted = grant_expiry.is_some();

    let mut rules = Vec::with_capacity(entries.len());
    let mut promotions = Vec::new();
    let mut aggregate_metadata = Vec::with_capacity(entries.len());
    let mut seen = std::collections::HashSet::with_capacity(entries.len());
    for entry in entries {
        let cgroup_id = non_empty_string(entry, "cgroupId")?
            .parse::<u64>()
            .context("capture profile cgroupId must be unsigned decimal")?;
        anyhow::ensure!(
            cgroup_id != 0 && seen.insert(cgroup_id),
            "capture profile cgroupId must be unique and non-zero"
        );
        anyhow::ensure!(
            non_empty_string(entry, "scopeKey")? == format!("cgroup:{cgroup_id}"),
            "capture profile scopeKey/cgroupId mismatch"
        );
        anyhow::ensure!(
            entry.get("epoch").and_then(Value::as_u64) == Some(epoch),
            "capture profile entry epoch mismatch"
        );
        let authority = match non_empty_string(entry, "authority")? {
            "authoritative" => FILE_FILTER_AUTHORITY_AUTHORITATIVE,
            "candidate" => FILE_FILTER_AUTHORITY_CANDIDATE,
            _ => anyhow::bail!("capture profile authority must be authoritative or candidate"),
        };
        anyhow::ensure!(
            matches!(non_empty_string(entry, "action")?, "keep" | "sample"),
            "S5 legacy compatibility action must be keep or sample"
        );
        let profile = parse_profile(non_empty_string(entry, "captureProfile")?)?;
        let mut actions = parse_probe_actions(
            entry
                .get("probeActions")
                .context("capture profile probeActions missing")?,
            "probeActions",
        )?;
        let mut desired = parse_probe_actions(
            entry
                .get("desiredProbeActions")
                .context("capture profile desiredProbeActions missing")?,
            "desiredProbeActions",
        )?;
        let mut flags = 0u16;
        if matches!(
            profile,
            CAPTURE_PROFILE_AGENT_FULL | CAPTURE_PROFILE_INVESTIGATION_FULL
        ) {
            flags |= CAPTURE_PROFILE_FLAG_AGENT;
            actions = [CAPTURE_ACTION_FULL; CAPTURE_PROBE_COUNT];
            desired = actions;
        }
        if matches!(
            profile,
            CAPTURE_PROFILE_SECURITY_FULL
                | CAPTURE_PROFILE_UNKNOWN_DISCOVERY
                | CAPTURE_PROFILE_PROBABLE_INVESTIGATION
        ) {
            let fixed = capture_profile_default_actions(profile);
            if actions != fixed || desired != fixed {
                downgrades.push(format!("fixed_profile_matrix_restored:{cgroup_id}"));
            }
            actions = fixed;
            desired = fixed;
        }
        if matches!(
            profile,
            CAPTURE_PROFILE_BUSINESS_CONTEXT
                | CAPTURE_PROFILE_INFRASTRUCTURE_AGGREGATE
                | CAPTURE_PROFILE_SELF_HEALTH
        ) && (actions[CAPTURE_PROBE_FILE_DELETE as usize] != CAPTURE_ACTION_SAMPLE
            || desired[CAPTURE_PROBE_FILE_DELETE as usize] != CAPTURE_ACTION_SAMPLE)
        {
            downgrades.push(format!("file_delete_forced_sample:{cgroup_id}"));
            actions[CAPTURE_PROBE_FILE_DELETE as usize] = CAPTURE_ACTION_SAMPLE;
            desired[CAPTURE_PROBE_FILE_DELETE as usize] = CAPTURE_ACTION_SAMPLE;
        }
        if entry.get("conflict").and_then(Value::as_bool) == Some(true) {
            flags |= CAPTURE_PROFILE_FLAG_CONFLICT;
            actions = [CAPTURE_ACTION_FULL; CAPTURE_PROBE_COUNT];
            desired = actions;
        }
        for protected in [0usize, 1, 9] {
            if actions[protected] != CAPTURE_ACTION_FULL
                || desired[protected] != CAPTURE_ACTION_FULL
            {
                downgrades.push(format!(
                    "protected_probe_forced_full:{}:{}",
                    cgroup_id, PROBE_NAMES[protected]
                ));
                actions[protected] = CAPTURE_ACTION_FULL;
                desired[protected] = CAPTURE_ACTION_FULL;
            }
        }
        if runtime_mode == CaptureProfileMode::Shadow && {
            let mut shadow_safe = [CAPTURE_ACTION_FULL; CAPTURE_PROBE_COUNT];
            shadow_safe[CAPTURE_PROBE_FILE_READ as usize] = CAPTURE_ACTION_NOT_ENABLED;
            actions != shadow_safe
        } {
            downgrades.push(format!("shadow_forced_full:{cgroup_id}"));
            actions = [CAPTURE_ACTION_FULL; CAPTURE_PROBE_COUNT];
            actions[CAPTURE_PROBE_FILE_READ as usize] = CAPTURE_ACTION_NOT_ENABLED;
        }
        if !destructive_granted || authority != FILE_FILTER_AUTHORITY_AUTHORITATIVE {
            let safe = capture_profile_default_actions(profile);
            for index in 0..CAPTURE_PROBE_COUNT {
                if actions[index] == CAPTURE_ACTION_DROP {
                    actions[index] = if safe[index] == CAPTURE_ACTION_DROP {
                        CAPTURE_ACTION_SAMPLE
                    } else {
                        safe[index]
                    };
                    downgrades.push(format!(
                        "drop_not_granted:{cgroup_id}:{}",
                        PROBE_NAMES[index]
                    ));
                }
            }
        }
        let (entry_expiry_unix, mut entry_expiry_boot) = unix_expiry_to_boot(
            non_empty_string(entry, "expiresAt")?,
            now_unix_ns,
            now_boot_ns,
        )?;
        anyhow::ensure!(
            entry_expiry_unix <= snapshot_expiry_unix,
            "entry expiry exceeds snapshot expiry"
        );
        if let Some(grant_expiry) = grant_expiry {
            anyhow::ensure!(
                entry_expiry_unix <= grant_expiry,
                "entry expiry exceeds activation grant expiry"
            );
            let grant_boot = now_boot_ns.saturating_add(
                grant_expiry
                    .saturating_sub(now_unix_ns)
                    .min(u64::MAX as u128) as u64,
            );
            entry_expiry_boot = entry_expiry_boot.min(grant_boot);
        }
        let root_scope = (
            entry
                .get("rootPid")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok()),
            optional_exact_u64(entry, "rootExecIdExact", "rootExecId")?,
        );
        if root_scope.0.is_some() && root_scope.1.is_some() {
            // A shared cgroup/root binding enables reads only through the generation-fenced
            // promotion map. The cgroup profile remains default-off so sidecars and sibling roots
            // cannot inherit the optional high-volume signal.
            actions[CAPTURE_PROBE_FILE_READ as usize] = CAPTURE_ACTION_NOT_ENABLED;
            desired[CAPTURE_PROBE_FILE_READ as usize] = CAPTURE_ACTION_NOT_ENABLED;
        }
        rules.push((
            CaptureProfileKey { cgroup_id, epoch },
            CaptureProfileValue {
                epoch,
                expires_at_boot_ns: entry_expiry_boot,
                actions,
                desired_actions: desired,
                profile,
                authority,
                flags,
                _reserved: [0; 4],
            },
        ));
        aggregate_metadata.push(CaptureAggregateMetadata {
            cgroup_id,
            epoch,
            policy_version,
            reason: entry
                .get("reasonCode")
                .or_else(|| entry.get("reason"))
                .and_then(Value::as_str)
                .unwrap_or("capture_profile")
                .to_string(),
        });

        if let (Some(root_pid), Some(root_exec_id)) = root_scope {
            promotions.push((
                CaptureProcessKey {
                    pid: root_pid,
                    _reserved: 0,
                    epoch,
                },
                CapturePromotionValue {
                    cgroup_id,
                    expected_exec_id: root_exec_id,
                    root_exec_id,
                    expires_at_boot_ns: entry_expiry_boot,
                    root_pid,
                    flags: CAPTURE_PROMOTION_FLAG_ROOT,
                },
            ));
        }
    }

    let actual_effective_hash = effective_hash_from_rules(&rules);
    if actual_effective_hash != supplied_effective_hash {
        downgrades.push("effective_actions_changed_by_collector_safety".to_string());
    }
    Ok(ParsedCaptureSnapshot {
        epoch,
        policy_version,
        publisher_instance_id: publisher,
        content_hash: supplied_content_hash,
        intent_hash: supplied_intent_hash,
        effective_actions_hash: actual_effective_hash,
        expires_at_boot_ns: snapshot_expiry_boot,
        rules,
        promotions,
        entries_applied: entries.len(),
        activation_mode,
        destructive_granted,
        downgrades,
        aggregate_metadata,
    })
}

pub(crate) fn capabilities() -> Value {
    json!({
        "schemaVersions": [SNAPSHOT_SCHEMA],
        "probeNames": PROBE_NAMES,
        "probeActions": ["aggregate", "drop", "full", "not_enabled", "sample"],
        "selectiveFileRead": true,
        "captureProfileModes": ["enforce", "shadow"],
        "activationGrantV1": true,
        "maxSnapshotBytes": MAX_SNAPSHOT_BYTES,
        "maxEntries": MAX_SNAPSHOT_ENTRIES,
        "aggregateMapMaxEntries": AGGREGATE_MAP_MAX_ENTRIES,
        "aggregateLedgerFailureMode": "bounded_emergency_sample",
    })
}

pub(crate) fn ack_document(
    snapshot: &ParsedCaptureSnapshot,
    generation: &CollectorGeneration,
    status: &str,
    errors: Vec<String>,
    applied_at: &str,
) -> Value {
    let capabilities = capabilities();
    json!({
        "schemaVersion": ACK_SCHEMA,
        "status": status,
        "nodeId": generation.node_id,
        "collectorId": generation.collector_id,
        "collectorInstanceId": generation.collector_instance_id,
        "hostBootId": generation.host_boot_id,
        "publisherInstanceId": snapshot.publisher_instance_id,
        "epoch": snapshot.epoch,
        "policyVersion": snapshot.policy_version,
        "contentHash": snapshot.content_hash,
        "intentHash": snapshot.intent_hash,
        "entriesApplied": snapshot.entries_applied,
        "appliedAt": applied_at,
        "statusMode": snapshot.activation_mode,
        "destructiveEnabled": snapshot.destructive_granted
            && snapshot.downgrades.is_empty()
            && status == "applied",
        "capabilitiesHash": canonical_digest(&capabilities),
        "capabilities": capabilities,
        "effectiveActionsHash": snapshot.effective_actions_hash,
        "downgrades": snapshot.downgrades,
        "errors": errors,
    })
}

pub(crate) fn rejected_ack_document(
    raw: &[u8],
    generation: &CollectorGeneration,
    error: &str,
    applied_at: &str,
) -> Value {
    let snapshot = serde_json::from_slice::<Value>(raw).unwrap_or(Value::Null);
    let capabilities = capabilities();
    json!({
        "schemaVersion": ACK_SCHEMA,
        "status": "rejected",
        "nodeId": generation.node_id,
        "collectorId": generation.collector_id,
        "collectorInstanceId": generation.collector_instance_id,
        "hostBootId": generation.host_boot_id,
        "publisherInstanceId": snapshot["publisherInstanceId"].as_str().unwrap_or(""),
        "epoch": snapshot["epoch"].as_u64().unwrap_or(0),
        "policyVersion": snapshot["policyVersion"].as_u64().unwrap_or(0),
        "contentHash": snapshot["contentHash"].as_str().unwrap_or(""),
        "intentHash": snapshot["intentHash"].as_str().unwrap_or(""),
        "entriesApplied": 0,
        "appliedAt": applied_at,
        "statusMode": snapshot["activation"]["mode"].as_str().unwrap_or("rejected"),
        "destructiveEnabled": false,
        "capabilitiesHash": canonical_digest(&capabilities),
        "capabilities": capabilities,
        "effectiveActionsHash": snapshot["effectiveActionsHash"].as_str().unwrap_or(""),
        "downgrades": [],
        "errors": [error],
    })
}

pub(crate) fn default_ack_path(rules_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.ack.json", rules_path.display()))
}

pub(crate) fn rfc3339_now() -> anyhow::Result<String> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock predates Unix epoch")?
        .as_secs();
    let raw = i64::try_from(seconds).context("system time exceeds time_t")?;
    let mut broken_down = unsafe { std::mem::zeroed::<libc::tm>() };
    anyhow::ensure!(
        !unsafe { libc::gmtime_r(&raw, &mut broken_down) }.is_null(),
        "gmtime_r failed"
    );
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        broken_down.tm_year + 1900,
        broken_down.tm_mon + 1,
        broken_down.tm_mday,
        broken_down.tm_hour,
        broken_down.tm_min,
        broken_down.tm_sec
    ))
}

pub(crate) fn write_ack_atomic(path: &Path, document: &Value) -> anyhow::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create ACK directory {}", parent.display()))?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("capture-profile-ack"),
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o640)
        .open(&temporary)
        .with_context(|| format!("create temporary ACK {}", temporary.display()))?;
    serde_json::to_writer(&mut file, document).context("serialize capture profile ACK")?;
    file.write_all(b"\n")
        .context("terminate capture profile ACK")?;
    file.sync_all().context("fsync capture profile ACK")?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("atomically install ACK {}", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("fsync ACK directory {}", parent.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_matches_recursive_lexicographic_contract() {
        let value = json!({"z": 1, "a": {"y": 2, "b": [3, {"d": 4, "c": 5}]}});
        assert_eq!(
            canonical_json(&value),
            r#"{"a":{"b":[3,{"c":5,"d":4}],"y":2},"z":1}"#
        );
        assert_eq!(canonical_digest(&value).len(), 64);
    }

    #[test]
    fn capabilities_are_closed_and_publish_capacity() {
        let value = capabilities();
        assert_eq!(value["probeNames"].as_array().unwrap().len(), 11);
        assert_eq!(value["selectiveFileRead"], true);
        assert_eq!(value["maxSnapshotBytes"], MAX_SNAPSHOT_BYTES);
        assert_eq!(value["maxEntries"], MAX_SNAPSHOT_ENTRIES);
        assert_eq!(value["aggregateMapMaxEntries"], AGGREGATE_MAP_MAX_ENTRIES);
    }

    #[test]
    fn hashes_match_forwarder_golden_vectors() {
        let entry = json!({
            "scopeType": "cgroup",
            "scopeKey": "cgroup:314",
            "cgroupId": "314",
            "classification": "non_agent",
            "authority": "authoritative",
            "action": "drop",
            "reasonCode": "known_anysentry_infrastructure",
            "source": "platform_inventory",
            "physicalWorkloadId": "docker:node-a:service-314",
            "ruleId": "rule-314",
            "ruleRevision": 3,
            "materializationId": "mat-314",
            "policyVersion": 7,
            "captureProfile": "infrastructure_aggregate",
            "desiredProbeActions": {
                "exec": "full", "exit": "full", "tls": "aggregate",
                "connect": "aggregate", "dns": "aggregate", "file_access": "drop",
                "file_delete": "sample", "llm": "aggregate", "ssl": "aggregate",
                "security": "full", "file_read": "not_enabled"
            },
            "expiresAt": "2026-08-20T00:10:00.000Z"
        });
        assert_eq!(
            canonical_digest(&intent_projection(&[entry.clone()], 7).unwrap()),
            "eabcc170e9ce397ef52fa44fe9fe67f3d23b19198cfd50f0e3236f4bd4f01a8a"
        );

        let mut process_churn = entry.clone();
        process_churn["materializationId"] = Value::String("mat-next-preview".to_string());
        process_churn["rootProcessKey"] = Value::String("boot:pid:42".to_string());
        process_churn["rootPid"] = Value::from(42_u64);
        process_churn["rootGeneration"] = Value::String("next-generation".to_string());
        assert_eq!(
            canonical_digest(&intent_projection(&[entry.clone()], 7).unwrap()),
            canonical_digest(&intent_projection(&[process_churn], 7).unwrap()),
            "process/materialization bookkeeping is content-bound but not capture intent"
        );

        let mut declared_intent = entry.clone();
        declared_intent["captureIntent"] = json!({
            "schemaVersion": "anysentry.infrastructure_capture_intent.v1",
            "action": "drop"
        });
        declared_intent["desiredProbeActions"] = json!({
            "exec": "full", "exit": "full", "tls": "drop",
            "connect": "drop", "dns": "drop", "file_access": "drop",
            "file_delete": "sample", "llm": "drop", "ssl": "drop",
            "security": "full", "file_read": "not_enabled"
        });
        assert_eq!(
            canonical_digest(&intent_projection(&[declared_intent], 7).unwrap()),
            "8e5671f50eb139919babf65d193703d352823a66e1f885652317daeafd8e9162",
            "the approved capture intent has one shared JS/Rust semantic hash"
        );

        let snapshot = json!({
            "schemaVersion": SNAPSHOT_SCHEMA,
            "captureProfileMode": "enforce",
            "version": 7001,
            "epoch": 7001,
            "policyVersion": 7,
            "publisherInstanceId": "publisher_golden",
            "generatedAt": "2026-08-20T00:00:00.000Z",
            "expiresAt": "2026-08-20T00:02:00.000Z",
            "expectedEntries": 0,
            "expectedCapabilitiesHash": "4398b1c063a7b6e54eb4d0a3e533c5f01a35349f2fa63669e275d159a4cdac49",
            "effectiveActionsHash": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
            "intentHash": "42d08a7c3ecc8fca977e59996549a14f01ecd326f300a5bfd36ed7670e245f85",
            "controlPlaneState": "ready",
            "activation": {"mode": "preview", "reason": "awaiting_preview_ack"},
            "entries": []
        });
        assert_eq!(
            content_hash(&snapshot).unwrap(),
            "98be11f2bdf636ec4559a7df46276ec44de144c246b5ffae03c8edb7a47c70f7"
        );
    }

    #[test]
    fn atomic_ack_replaces_complete_json() {
        let directory = std::env::temp_dir().join(format!(
            "a3s-observer-ack-test-{}-{}",
            std::process::id(),
            super::super::unix_now_ms_u64()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("rules.ack.json");
        write_ack_atomic(
            &path,
            &json!({"schemaVersion": ACK_SCHEMA, "status": "applied"}),
        )
        .unwrap();
        let parsed: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(parsed["status"], "applied");
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn rejected_ack_is_generation_fenced_and_never_claims_destructive_activation() {
        let raw = br#"{
            "publisherInstanceId":"publisher-rejected","epoch":17,"policyVersion":9,
            "contentHash":"bad-content","intentHash":"intent",
            "effectiveActionsHash":"effective","activation":{"mode":"enforce"}
        }"#;
        let value = rejected_ack_document(raw, &generation(), "unknown probe", "now");
        assert_eq!(value["status"], "rejected");
        assert_eq!(value["collectorInstanceId"], "collector-instance-a");
        assert_eq!(value["hostBootId"], "boot-a");
        assert_eq!(value["publisherInstanceId"], "publisher-rejected");
        assert_eq!(value["entriesApplied"], 0);
        assert_eq!(value["destructiveEnabled"], false);
        assert_eq!(value["errors"][0], "unknown probe");
    }

    fn actions(file_access: &str) -> Value {
        json!({
            "exec": "full", "exit": "full", "tls": "aggregate",
            "connect": "aggregate", "dns": "aggregate", "file_access": file_access,
            "file_delete": "sample", "llm": "aggregate", "ssl": "aggregate",
            "security": "full", "file_read": "not_enabled"
        })
    }

    fn signed_snapshot(mode: &str, activation: &str, epoch: u64) -> Value {
        let entry = json!({
            "scopeType": "cgroup",
            "scopeKey": "cgroup:42",
            "cgroupId": "42",
            "classification": "non_agent",
            "authority": "authoritative",
            "action": "sample",
            "reasonCode": "known_anysentry_infrastructure",
            "source": "platform_inventory",
            "physicalWorkloadId": "docker:node-a:service-42",
            "ruleId": "rule-42",
            "ruleRevision": 3,
            "materializationId": "mat-42",
            "policyVersion": 7,
            "captureProfile": "infrastructure_aggregate",
            "rootPid": 4242,
            "rootExecId": "9007199254740992",
            "rootExecIdExact": "9007199254740993",
            "probeActions": if mode == "shadow" { json!({
                "exec":"full","exit":"full","tls":"full","connect":"full","dns":"full",
                "file_access":"full","file_delete":"full","llm":"full","ssl":"full","security":"full",
                "file_read":"not_enabled"
            }) } else if activation == "enforce" { actions("drop") } else { actions("aggregate") },
            "desiredProbeActions": actions("drop"),
            "expiresAt": "2026-08-20T00:01:30.000Z",
            "epoch": epoch
        });
        let entries = vec![entry];
        let mut snapshot = json!({
            "schemaVersion": SNAPSHOT_SCHEMA,
            "captureProfileMode": mode,
            "version": epoch,
            "epoch": epoch,
            "policyVersion": 7,
            "publisherInstanceId": "publisher-a",
            "generatedAt": "2026-08-20T00:00:00.000Z",
            "expiresAt": "2026-08-20T00:01:30.000Z",
            "expectedEntries": 1,
            "expectedCapabilitiesHash": "diagnostic-only",
            "effectiveActionsHash": canonical_digest(&effective_actions_projection(&entries)),
            "intentHash": canonical_digest(&intent_projection(&entries, 7).unwrap()),
            "controlPlaneState": "ready",
            "activation": {"mode": activation, "reason": "test"},
            "entries": entries
        });
        let hash = content_hash(&snapshot).unwrap();
        snapshot["contentHash"] = Value::String(hash);
        snapshot
    }

    fn generation() -> CollectorGeneration {
        CollectorGeneration {
            node_id: "node-a".into(),
            collector_id: "collector-a".into(),
            collector_instance_id: "collector-instance-a".into(),
            host_boot_id: "boot-a".into(),
        }
    }

    fn fixed_now() -> u128 {
        super::super::parse_rfc3339_unix_nanos("2026-08-20T00:00:00.000Z").unwrap()
    }

    #[test]
    fn preview_is_safe_and_only_current_preview_can_activate_drop() {
        let preview = signed_snapshot("enforce", "preview", 7001);
        let parsed = parse_snapshot(
            serde_json::to_string(&preview).unwrap().as_bytes(),
            CaptureProfileMode::Enforce,
            &generation(),
            None,
            fixed_now(),
            10,
        )
        .unwrap();
        assert!(!parsed.destructive_granted);
        assert_eq!(parsed.rules[0].1.actions[5], CAPTURE_ACTION_AGGREGATE);
        assert!(parsed.downgrades.is_empty());
        assert_eq!(
            parsed.promotions[0].1.expected_exec_id,
            9_007_199_254_740_993
        );

        let receipt = PreviewReceipt {
            collector_instance_id: generation().collector_instance_id,
            host_boot_id: generation().host_boot_id,
            publisher_instance_id: parsed.publisher_instance_id.clone(),
            epoch: parsed.epoch,
            content_hash: parsed.content_hash.clone(),
            intent_hash: parsed.intent_hash.clone(),
        };
        let mut enforce = signed_snapshot("enforce", "enforce", 7002);
        enforce["activationGrant"] = json!({
            "collectorInstanceId": "collector-instance-a",
            "hostBootId": "boot-a",
            "publisherInstanceId": "publisher-a",
            "previewEpoch": 7001,
            "previewContentHash": receipt.content_hash,
            "intentHash": receipt.intent_hash,
            "centralReportId": "report-a",
            "centralAcceptedAt": "2026-08-20T00:00:01.000Z",
            "expiresAt": "2026-08-20T00:01:30.000Z"
        });
        enforce["contentHash"] = Value::String(content_hash(&enforce).unwrap());
        let active = parse_snapshot(
            serde_json::to_string(&enforce).unwrap().as_bytes(),
            CaptureProfileMode::Enforce,
            &generation(),
            Some(&receipt),
            fixed_now(),
            10,
        )
        .unwrap();
        assert!(active.destructive_granted);
        assert_eq!(active.rules[0].1.actions[5], CAPTURE_ACTION_DROP);
        assert!(active.downgrades.is_empty());

        let restarted = CollectorGeneration {
            collector_instance_id: "collector-instance-b".into(),
            ..generation()
        };
        let safe = parse_snapshot(
            serde_json::to_string(&enforce).unwrap().as_bytes(),
            CaptureProfileMode::Enforce,
            &restarted,
            Some(&receipt),
            fixed_now(),
            10,
        )
        .unwrap();
        assert!(!safe.destructive_granted);
        assert_ne!(safe.rules[0].1.actions[5], CAPTURE_ACTION_DROP);
        assert!(!safe.downgrades.is_empty());
    }

    #[test]
    fn shadow_is_full_and_s5_legacy_drop_is_rejected() {
        let shadow = signed_snapshot("shadow", "shadow", 8001);
        let parsed = parse_snapshot(
            serde_json::to_string(&shadow).unwrap().as_bytes(),
            CaptureProfileMode::Shadow,
            &generation(),
            None,
            fixed_now(),
            10,
        )
        .unwrap();
        assert_eq!(parsed.rules[0].1.actions, {
            let mut expected = [CAPTURE_ACTION_FULL; CAPTURE_PROBE_COUNT];
            expected[CAPTURE_PROBE_FILE_READ as usize] = CAPTURE_ACTION_NOT_ENABLED;
            expected
        });

        let mut unsafe_wire = signed_snapshot("enforce", "preview", 8002);
        unsafe_wire["entries"][0]["action"] = Value::String("drop".into());
        unsafe_wire["intentHash"] = Value::String(canonical_digest(
            &intent_projection(unsafe_wire["entries"].as_array().unwrap(), 7).unwrap(),
        ));
        unsafe_wire["effectiveActionsHash"] = Value::String(canonical_digest(
            &effective_actions_projection(unsafe_wire["entries"].as_array().unwrap()),
        ));
        unsafe_wire["contentHash"] = Value::String(content_hash(&unsafe_wire).unwrap());
        assert!(parse_snapshot(
            serde_json::to_string(&unsafe_wire).unwrap().as_bytes(),
            CaptureProfileMode::Enforce,
            &generation(),
            None,
            fixed_now(),
            10,
        )
        .is_err());
    }

    #[test]
    fn selective_file_read_uses_dedicated_cgroup_or_generation_fenced_root_scope() {
        let all_full = json!({
            "exec":"full","exit":"full","tls":"full","connect":"full","dns":"full",
            "file_access":"full","file_delete":"full","llm":"full","ssl":"full",
            "security":"full","file_read":"full"
        });
        let resign = |mut snapshot: Value| {
            let entries = snapshot["entries"].as_array().unwrap().clone();
            snapshot["intentHash"] =
                Value::String(canonical_digest(&intent_projection(&entries, 7).unwrap()));
            snapshot["effectiveActionsHash"] =
                Value::String(canonical_digest(&effective_actions_projection(&entries)));
            snapshot["contentHash"] = Value::String(content_hash(&snapshot).unwrap());
            snapshot
        };

        let mut dedicated = signed_snapshot("enforce", "preview", 8101);
        dedicated["entries"][0]["classification"] = Value::String("confirmed_agent".into());
        dedicated["entries"][0]["action"] = Value::String("keep".into());
        dedicated["entries"][0]["captureProfile"] = Value::String("agent_full".into());
        dedicated["entries"][0]["probeActions"] = all_full.clone();
        dedicated["entries"][0]["desiredProbeActions"] = all_full.clone();
        dedicated["entries"][0]
            .as_object_mut()
            .unwrap()
            .remove("rootPid");
        dedicated["entries"][0]
            .as_object_mut()
            .unwrap()
            .remove("rootExecId");
        dedicated["entries"][0]
            .as_object_mut()
            .unwrap()
            .remove("rootExecIdExact");
        let dedicated = resign(dedicated);
        let parsed = parse_snapshot(
            serde_json::to_string(&dedicated).unwrap().as_bytes(),
            CaptureProfileMode::Enforce,
            &generation(),
            None,
            fixed_now(),
            10,
        )
        .unwrap();
        assert_eq!(
            parsed.rules[0].1.actions[CAPTURE_PROBE_FILE_READ as usize],
            CAPTURE_ACTION_FULL,
        );
        assert!(parsed.promotions.is_empty());
        assert!(parsed.downgrades.is_empty());

        let mut rooted = dedicated;
        rooted["epoch"] = Value::from(8102_u64);
        rooted["version"] = Value::from(8102_u64);
        rooted["entries"][0]["epoch"] = Value::from(8102_u64);
        rooted["entries"][0]["rootPid"] = Value::from(4242_u64);
        rooted["entries"][0]["rootExecId"] = Value::String("9007199254740992".into());
        rooted["entries"][0]["rootExecIdExact"] = Value::String("9007199254740993".into());
        rooted["entries"][0]["probeActions"]["file_read"] = Value::String("not_enabled".into());
        rooted["entries"][0]["desiredProbeActions"]["file_read"] =
            Value::String("not_enabled".into());
        let rooted = resign(rooted);
        let parsed = parse_snapshot(
            serde_json::to_string(&rooted).unwrap().as_bytes(),
            CaptureProfileMode::Enforce,
            &generation(),
            None,
            fixed_now(),
            10,
        )
        .unwrap();
        assert_eq!(
            parsed.rules[0].1.actions[CAPTURE_PROBE_FILE_READ as usize],
            CAPTURE_ACTION_NOT_ENABLED,
        );
        assert_eq!(parsed.promotions.len(), 1);
        assert_eq!(parsed.promotions[0].1.root_pid, 4242);
        assert!(parsed.downgrades.is_empty());
    }

    #[test]
    fn signed_grant_cannot_drop_fixed_file_delete_sample_profile() {
        let mut preview = signed_snapshot("enforce", "preview", 9001);
        preview["entries"][0]["desiredProbeActions"]["file_delete"] = Value::String("drop".into());
        preview["intentHash"] = Value::String(canonical_digest(
            &intent_projection(preview["entries"].as_array().unwrap(), 7).unwrap(),
        ));
        preview["effectiveActionsHash"] = Value::String(canonical_digest(
            &effective_actions_projection(preview["entries"].as_array().unwrap()),
        ));
        preview["contentHash"] = Value::String(content_hash(&preview).unwrap());
        let parsed_preview = parse_snapshot(
            serde_json::to_string(&preview).unwrap().as_bytes(),
            CaptureProfileMode::Enforce,
            &generation(),
            None,
            fixed_now(),
            10,
        )
        .unwrap();
        let receipt = PreviewReceipt {
            collector_instance_id: generation().collector_instance_id,
            host_boot_id: generation().host_boot_id,
            publisher_instance_id: parsed_preview.publisher_instance_id,
            epoch: parsed_preview.epoch,
            content_hash: parsed_preview.content_hash,
            intent_hash: parsed_preview.intent_hash,
        };

        let mut enforce = signed_snapshot("enforce", "enforce", 9002);
        enforce["entries"][0]["probeActions"]["file_delete"] = Value::String("drop".into());
        enforce["entries"][0]["desiredProbeActions"]["file_delete"] = Value::String("drop".into());
        enforce["intentHash"] = Value::String(receipt.intent_hash.clone());
        enforce["effectiveActionsHash"] = Value::String(canonical_digest(
            &effective_actions_projection(enforce["entries"].as_array().unwrap()),
        ));
        enforce["activationGrant"] = json!({
            "collectorInstanceId": "collector-instance-a",
            "hostBootId": "boot-a",
            "publisherInstanceId": "publisher-a",
            "previewEpoch": 9001,
            "previewContentHash": receipt.content_hash,
            "intentHash": receipt.intent_hash,
            "centralReportId": "report-fixed-matrix",
            "centralAcceptedAt": "2026-08-20T00:00:01.000Z",
            "expiresAt": "2026-08-20T00:01:30.000Z"
        });
        enforce["contentHash"] = Value::String(content_hash(&enforce).unwrap());

        let parsed = parse_snapshot(
            serde_json::to_string(&enforce).unwrap().as_bytes(),
            CaptureProfileMode::Enforce,
            &generation(),
            Some(&receipt),
            fixed_now(),
            10,
        )
        .unwrap();
        assert!(parsed.destructive_granted);
        assert_eq!(parsed.rules[0].1.actions[6], CAPTURE_ACTION_SAMPLE);
        assert_eq!(parsed.rules[0].1.desired_actions[6], CAPTURE_ACTION_SAMPLE);
        assert!(parsed
            .downgrades
            .iter()
            .any(|value| value.starts_with("file_delete_forced_sample:")));
    }

    #[test]
    fn aggregate_cursor_advances_only_after_bulk_admission_and_two_stable_reads() {
        let mut cursor = AggregateCursor {
            window_started_unix_ns: 10,
            ..AggregateCursor::default()
        };
        let current = CaptureAggregateValue {
            count: 7,
            bytes: 70,
        };
        // A rejected Bulk admission leaves the cumulative delta retryable.
        assert_eq!(cursor.delta(current).count, 7);
        assert_eq!(cursor.delta(current).count, 7);
        cursor.admit(current, 20);
        assert_eq!(cursor.delta(current).count, 0);
        assert!(!cursor.old_epoch_stable());
        assert!(cursor.old_epoch_stable());
    }

    #[test]
    fn aggregate_metadata_is_bounded_across_empty_epochs() {
        let mut metadata = std::collections::BTreeMap::new();
        for epoch in 1..=1_000 {
            metadata.insert(
                (epoch, epoch),
                CaptureAggregateMetadata {
                    cgroup_id: epoch,
                    epoch,
                    policy_version: epoch,
                    reason: "test".into(),
                },
            );
            prune_aggregate_metadata(&mut metadata, &std::collections::BTreeMap::new(), epoch);
            assert_eq!(metadata.len(), 1);
        }
    }
}
