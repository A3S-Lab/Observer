//! Product-neutral TLS admission scopes published by the co-located identity forwarder.
//!
//! The cgroup document is an admission hint, not an identity authority. A legacy entry that
//! contains only a cgroup id is retained for compatibility, but a cgroup shared by multiple
//! logical runtimes must carry a process-generation fence. In that case this module admits only
//! the fenced root and its unambiguous descendants. This prevents a Docker container that hosts
//! several Agents from turning one arbitrary cgroup label into a blanket TLS grant. Product names
//! and protocol semantics remain outside the Collector/eBPF hot path.

use anyhow::Context as _;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

const SCHEMA: &str = "anysentry.tls_agent_cgroups.v1";
const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MAX_CGROUPS: usize = 65_536;
const MAX_PROCESSES: usize = 1_048_576;
const MAX_SCOPE_TEXT: usize = 512;
const MAX_ANCESTOR_DEPTH: usize = 64;

#[derive(Debug)]
pub struct TlsAgentScopeRefresh {
    pub pids: HashSet<i32>,
    pub cgroups: usize,
    pub changed: bool,
    /// Number of process-generation roots in the current document.
    pub fenced_roots: usize,
    /// Number of cgroups for which blanket admission is unsafe.
    pub conflicts: usize,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ProcessFence {
    pid: i32,
    start_time_ticks: u64,
    cgroup_id: u64,
    /// Provenance only. Numeric pid/start/cgroup facts remain the local authority because an
    /// arbitrary producer must not be able to mint a matching opaque process key.
    root_process_key: Option<String>,
    identity_key: String,
}

#[derive(Clone, Debug, Default)]
struct CgroupAdmission {
    identities: HashSet<String>,
    fences: Vec<ProcessFence>,
    has_legacy_entry: bool,
}

#[derive(Clone, Debug, Default)]
struct ParsedScopes {
    cgroups: HashSet<u64>,
    by_cgroup: HashMap<u64, CgroupAdmission>,
    conflicts: HashSet<u64>,
}

#[derive(Clone, Copy, Debug)]
struct ProcessInfo {
    pid: i32,
    ppid: Option<i32>,
    cgroup_id: Option<u64>,
    start_time_ticks: Option<u64>,
}

#[derive(Debug)]
pub struct TlsAgentScopeReloader {
    path: PathBuf,
    proc_root: PathBuf,
    cgroup_root: PathBuf,
    last_document: Vec<u8>,
    scopes: ParsedScopes,
}

impl TlsAgentScopeReloader {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            proc_root: PathBuf::from("/proc"),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            last_document: Vec::new(),
            scopes: ParsedScopes::default(),
        }
    }

    #[cfg(test)]
    fn with_roots(path: PathBuf, proc_root: PathBuf, cgroup_root: PathBuf) -> Self {
        Self {
            path,
            proc_root,
            cgroup_root,
            last_document: Vec::new(),
            scopes: ParsedScopes::default(),
        }
    }

    pub fn refresh(&mut self) -> anyhow::Result<TlsAgentScopeRefresh> {
        let changed = self.reload_if_changed()?;
        let pids = scan_pids_for_scopes(&self.proc_root, &self.cgroup_root, &self.scopes)?;
        let fenced_roots = self
            .scopes
            .by_cgroup
            .values()
            .map(|admission| admission.fences.len())
            .sum();
        Ok(TlsAgentScopeRefresh {
            pids,
            cgroups: self.scopes.cgroups.len(),
            changed,
            fenced_roots,
            conflicts: self.scopes.conflicts.len(),
        })
    }

    fn reload_if_changed(&mut self) -> anyhow::Result<bool> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let changed = !self.last_document.is_empty() || !self.scopes.cgroups.is_empty();
                self.last_document.clear();
                self.scopes = ParsedScopes::default();
                return Ok(changed);
            }
            Err(error) => {
                return Err(error).with_context(|| format!("read {}", self.path.display()))
            }
        };
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_DOCUMENT_BYTES,
            "TLS Agent cgroup document exceeds 1 MiB"
        );
        if bytes == self.last_document {
            return Ok(false);
        }
        let parsed: Value =
            serde_json::from_slice(&bytes).context("parse TLS Agent cgroup document")?;
        anyhow::ensure!(
            parsed.get("schemaVersion").and_then(Value::as_str) == Some(SCHEMA),
            "unsupported TLS Agent cgroup schema"
        );
        let entries = parsed
            .get("entries")
            .and_then(Value::as_array)
            .context("TLS Agent cgroup entries must be an array")?;
        anyhow::ensure!(entries.len() <= MAX_CGROUPS, "too many TLS Agent cgroups");

        let mut scopes = ParsedScopes::default();
        for entry in entries {
            let cgroup_id = decimal_u64(entry.get("cgroupId"), "cgroupId")?
                .context("TLS Agent cgroup ID must be an unsigned integer")?;
            anyhow::ensure!(cgroup_id != 0, "TLS Agent cgroup ID must be non-zero");

            let agent_scope_id = bounded_optional_text(entry, "agentScopeId")?;
            let agent_instance_id = bounded_optional_text(entry, "agentInstanceId")?;
            // Labels only partition competing scopes. They never grant admission by themselves.
            let label_identity_key = format!(
                "{}\u{1f}{}",
                agent_scope_id.as_deref().unwrap_or_default(),
                agent_instance_id.as_deref().unwrap_or_default()
            );

            let root_pid = decimal_i32(entry.get("rootPid"), "rootPid")?;
            let root_start = decimal_u64(entry.get("rootStartTimeTicks"), "rootStartTimeTicks")?;
            let root_process_key = bounded_optional_text(entry, "rootProcessKey")?;
            let has_any_fence_field =
                root_pid.is_some() || root_start.is_some() || root_process_key.is_some();
            let fence = if has_any_fence_field {
                let pid = root_pid.context("rootPid is required for a process fence")?;
                let start_time_ticks =
                    root_start.context("rootStartTimeTicks is required for a process fence")?;
                anyhow::ensure!(pid > 0, "rootPid must be positive");
                anyhow::ensure!(start_time_ticks > 0, "rootStartTimeTicks must be positive");
                // If no stable logical/instance label is available, keep each generation as a
                // separate candidate instead of allowing two anonymous roots to look like one.
                let identity_key = if label_identity_key == "\u{1f}" {
                    format!("fence:{pid}:{start_time_ticks}")
                } else {
                    label_identity_key.clone()
                };
                Some(ProcessFence {
                    pid,
                    start_time_ticks,
                    cgroup_id,
                    root_process_key,
                    identity_key,
                })
            } else {
                None
            };

            scopes.cgroups.insert(cgroup_id);
            let admission = scopes.by_cgroup.entry(cgroup_id).or_default();
            // Empty labels form one anonymous identity so duplicate legacy rows stay compatible.
            admission.identities.insert(label_identity_key);
            if let Some(fence) = fence {
                if !admission.fences.contains(&fence) {
                    admission.fences.push(fence);
                }
            } else {
                admission.has_legacy_entry = true;
            }
        }
        for (cgroup_id, admission) in &scopes.by_cgroup {
            // Any generation fence disables the legacy cgroup-wide fallback. Distinct labels are
            // retained as an operator-visible conflict even when every row is fenced.
            if admission.identities.len() > 1
                || (admission.has_legacy_entry && !admission.fences.is_empty())
            {
                scopes.conflicts.insert(*cgroup_id);
            }
        }
        self.last_document = bytes;
        self.scopes = scopes;
        Ok(true)
    }
}

fn bounded_optional_text(entry: &Value, field: &str) -> anyhow::Result<Option<String>> {
    let Some(value) = entry.get(field) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .with_context(|| format!("TLS Agent {field} must be a string"))?
        .trim();
    anyhow::ensure!(
        text.len() <= MAX_SCOPE_TEXT,
        "TLS Agent scope text exceeds configured bound"
    );
    Ok((!text.is_empty()).then(|| text.to_string()))
}

fn decimal_u64(value: Option<&Value>, field: &str) -> anyhow::Result<Option<u64>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let parsed = match value {
        Value::String(text) => text
            .trim()
            .parse::<u64>()
            .with_context(|| format!("TLS Agent {field} must be an unsigned integer"))?,
        Value::Number(number) => number
            .as_u64()
            .with_context(|| format!("TLS Agent {field} must be an unsigned integer"))?,
        _ => anyhow::bail!("TLS Agent {field} must be an unsigned integer"),
    };
    Ok(Some(parsed))
}

fn decimal_i32(value: Option<&Value>, field: &str) -> anyhow::Result<Option<i32>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let parsed = match value {
        Value::String(text) => text
            .trim()
            .parse::<i32>()
            .with_context(|| format!("TLS Agent {field} must be an integer"))?,
        Value::Number(number) => {
            let value = number
                .as_i64()
                .with_context(|| format!("TLS Agent {field} must be an integer"))?;
            i32::try_from(value)
                .with_context(|| format!("TLS Agent {field} is outside the pid range"))?
        }
        _ => anyhow::bail!("TLS Agent {field} must be an integer"),
    };
    Ok(Some(parsed))
}

fn scan_pids_for_scopes(
    proc_root: &Path,
    cgroup_root: &Path,
    scopes: &ParsedScopes,
) -> anyhow::Result<HashSet<i32>> {
    if scopes.cgroups.is_empty() {
        return Ok(HashSet::new());
    }
    let mut processes = HashMap::new();
    let entries =
        fs::read_dir(proc_root).with_context(|| format!("scan {}", proc_root.display()))?;
    for entry in entries.take(MAX_PROCESSES).flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|pid| *pid > 0)
        else {
            continue;
        };
        let cgroup_id = process_cgroup_id(proc_root, cgroup_root, pid);
        let (ppid, start_time_ticks) = process_stat(proc_root, pid);
        processes.insert(
            pid,
            ProcessInfo {
                pid,
                ppid,
                cgroup_id,
                start_time_ticks,
            },
        );
    }

    let mut admitted = HashSet::new();
    for process in processes.values() {
        let Some(cgroup_id) = process.cgroup_id else {
            continue;
        };
        let Some(admission) = scopes.by_cgroup.get(&cgroup_id) else {
            continue;
        };
        if admission.fences.is_empty() {
            // No process fence means the old one-runtime-per-cgroup contract. Never apply it to a
            // cgroup that carries competing identities.
            if !scopes.conflicts.contains(&cgroup_id) {
                admitted.insert(process.pid);
            }
            continue;
        }
        if fenced_process_is_unambiguous(process, &processes, &admission.fences) {
            admitted.insert(process.pid);
        }
    }
    Ok(admitted)
}

fn fenced_process_is_unambiguous(
    process: &ProcessInfo,
    processes: &HashMap<i32, ProcessInfo>,
    fences: &[ProcessFence],
) -> bool {
    let Some(expected_cgroup) = fences.first().map(|fence| fence.cgroup_id) else {
        return false;
    };
    // Do not follow a parent chain from a process that has already moved to another cgroup. This
    // prevents a newly admitted scope from inheriting a stale root across a cgroup boundary.
    if process.cgroup_id != Some(expected_cgroup) {
        return false;
    }
    let mut current = Some(process.pid);
    let mut visited = HashSet::new();
    for _ in 0..MAX_ANCESTOR_DEPTH {
        let Some(pid) = current else {
            break;
        };
        if !visited.insert(pid) {
            break;
        }
        let Some(candidate) = processes.get(&pid) else {
            break;
        };
        if candidate.cgroup_id != Some(expected_cgroup) {
            break;
        }
        let mut matched_identities = HashSet::new();
        for fence in fences {
            if fence.pid == candidate.pid
                && fence.cgroup_id == expected_cgroup
                && candidate.start_time_ticks == Some(fence.start_time_ticks)
                && root_process_key_is_consistent(fence, candidate)
            {
                matched_identities.insert(fence.identity_key.as_str());
            }
        }
        // A container/runtime root can legitimately contain a more specific Agent root. Walk
        // from the process toward its parent and let the nearest matching generation own the
        // process; only competing identities at that same generation are ambiguous.
        if !matched_identities.is_empty() {
            return matched_identities.len() == 1;
        }
        current = candidate.ppid;
    }
    false
}

fn root_process_key_is_consistent(fence: &ProcessFence, process: &ProcessInfo) -> bool {
    let Some(key) = fence.root_process_key.as_deref() else {
        return true;
    };
    // The current Forwarder emits a JSON-array process key. Validate its pid/start components
    // when that shape is available; opaque future keys remain provenance-only and never replace
    // the independently verified numeric fence.
    let Ok(value) = serde_json::from_str::<Value>(key) else {
        return true;
    };
    let Some(parts) = value.as_array() else {
        return true;
    };
    let key_pid = parts.get(2).and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str()?.parse::<u64>().ok())
    });
    let key_start = parts.get(3).and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str()?.parse::<u64>().ok())
    });
    key_pid.is_none_or(|pid| pid == process.pid as u64)
        && key_start.is_none_or(|start| Some(start) == process.start_time_ticks)
}

fn process_stat(proc_root: &Path, pid: i32) -> (Option<i32>, Option<u64>) {
    let Ok(stat) = fs::read_to_string(proc_root.join(pid.to_string()).join("stat")) else {
        return (None, None);
    };
    // `comm` is parenthesized and may contain spaces or `)`. The final `) ` is the delimiter
    // before the state field; ppid is field 4 and starttime is field 22.
    let Some(close) = stat.rfind(") ") else {
        return (None, None);
    };
    let fields = stat
        .get(close + 2..)
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>();
    let ppid = fields.get(1).and_then(|value| value.parse::<i32>().ok());
    let start_time_ticks = fields.get(19).and_then(|value| value.parse::<u64>().ok());
    (ppid, start_time_ticks)
}

fn process_cgroup_id(proc_root: &Path, cgroup_root: &Path, pid: i32) -> Option<u64> {
    let membership = fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup")).ok()?;
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?;
    let relative = relative.trim().trim_start_matches('/');
    let path = Path::new(relative);
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return None;
    }
    fs::metadata(cgroup_root.join(path))
        .ok()
        .map(|metadata| metadata.ino())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat_line(pid: i32, ppid: i32, start_time_ticks: u64) -> String {
        let mut fields = vec!["0".to_string(); 20];
        fields[0] = "S".to_string();
        fields[1] = ppid.to_string();
        fields[19] = start_time_ticks.to_string();
        format!("{pid} (fixture-agent) {}\n", fields.join(" "))
    }

    fn fixture_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "anysentry-tls-agent-scopes-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn published_cgroups_admit_existing_and_new_processes_without_product_names() {
        let root = fixture_root("legacy");
        let proc_root = root.join("proc");
        let cgroup_root = root.join("cgroup");
        let agent_cgroup = cgroup_root.join("docker/agent");
        let ordinary_cgroup = cgroup_root.join("docker/ordinary");
        fs::create_dir_all(&agent_cgroup).unwrap();
        fs::create_dir_all(&ordinary_cgroup).unwrap();
        fs::create_dir_all(proc_root.join("101")).unwrap();
        fs::create_dir_all(proc_root.join("202")).unwrap();
        fs::write(proc_root.join("101/cgroup"), "0::/docker/agent\n").unwrap();
        fs::write(proc_root.join("202/cgroup"), "0::/docker/ordinary\n").unwrap();
        let agent_id = fs::metadata(&agent_cgroup).unwrap().ino();
        let document = root.join("tls-agent-cgroups.json");
        fs::write(
            &document,
            format!(
                "{{\"schemaVersion\":\"{SCHEMA}\",\"entries\":[{{\"cgroupId\":\"{agent_id}\",\"agentScopeId\":\"future-agent\"}}]}}\n"
            ),
        )
        .unwrap();

        let mut reloader =
            TlsAgentScopeReloader::with_roots(document, proc_root.clone(), cgroup_root);
        let first = reloader.refresh().unwrap();
        assert!(first.changed);
        assert_eq!(first.cgroups, 1);
        assert_eq!(first.conflicts, 0);
        assert_eq!(first.fenced_roots, 0);
        assert_eq!(first.pids, HashSet::from([101]));

        fs::create_dir_all(proc_root.join("303")).unwrap();
        fs::write(proc_root.join("303/cgroup"), "0::/docker/agent\n").unwrap();
        let second = reloader.refresh().unwrap();
        assert!(!second.changed);
        assert_eq!(second.pids, HashSet::from([101, 303]));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mixed_cgroup_requires_generation_fences_and_keeps_each_root_separate() {
        let root = fixture_root("mixed");
        let proc_root = root.join("proc");
        let cgroup_root = root.join("cgroup");
        let cgroup = cgroup_root.join("docker/shared");
        fs::create_dir_all(&cgroup).unwrap();
        for (pid, ppid, start) in [
            (101, 1, 100),
            (111, 101, 110),
            (202, 1, 200),
            (222, 202, 220),
            (303, 1, 300),
        ] {
            fs::create_dir_all(proc_root.join(pid.to_string())).unwrap();
            fs::write(
                proc_root.join(pid.to_string()).join("cgroup"),
                "0::/docker/shared\n",
            )
            .unwrap();
            fs::write(
                proc_root.join(pid.to_string()).join("stat"),
                stat_line(pid, ppid, start),
            )
            .unwrap();
        }
        let cgroup_id = fs::metadata(&cgroup).unwrap().ino();
        let document = root.join("scopes.json");
        fs::write(
            &document,
            format!(
                "{{\"schemaVersion\":\"{SCHEMA}\",\"entries\":[{{\"cgroupId\":\"{cgroup_id}\",\"agentScopeId\":\"codex\",\"agentInstanceId\":\"i-codex\",\"rootPid\":101,\"rootStartTimeTicks\":\"100\"}},{{\"cgroupId\":\"{cgroup_id}\",\"agentScopeId\":\"claude\",\"agentInstanceId\":\"i-claude\",\"rootPid\":202,\"rootStartTimeTicks\":\"200\"}}]}}"
            ),
        )
        .unwrap();
        let mut reloader = TlsAgentScopeReloader::with_roots(document, proc_root, cgroup_root);
        let refresh = reloader.refresh().unwrap();
        assert_eq!(refresh.conflicts, 1);
        assert_eq!(refresh.fenced_roots, 2);
        assert_eq!(refresh.pids, HashSet::from([101, 111, 202, 222]));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nearest_agent_root_overrides_a_container_root_fence() {
        let root = fixture_root("nested");
        let proc_root = root.join("proc");
        let cgroup_root = root.join("cgroup");
        let cgroup = cgroup_root.join("docker/shared");
        fs::create_dir_all(&cgroup).unwrap();
        for (pid, ppid, start) in [(50, 1, 500), (101, 50, 100), (111, 101, 110)] {
            fs::create_dir_all(proc_root.join(pid.to_string())).unwrap();
            fs::write(
                proc_root.join(pid.to_string()).join("cgroup"),
                "0::/docker/shared\n",
            )
            .unwrap();
            fs::write(
                proc_root.join(pid.to_string()).join("stat"),
                stat_line(pid, ppid, start),
            )
            .unwrap();
        }
        let cgroup_id = fs::metadata(&cgroup).unwrap().ino();
        let document = root.join("scopes.json");
        fs::write(
            &document,
            format!(
                "{{\"schemaVersion\":\"{SCHEMA}\",\"entries\":[{{\"cgroupId\":\"{cgroup_id}\",\"agentScopeId\":\"container\",\"agentInstanceId\":\"container-i\",\"rootPid\":50,\"rootStartTimeTicks\":\"500\"}},{{\"cgroupId\":\"{cgroup_id}\",\"agentScopeId\":\"codex\",\"agentInstanceId\":\"codex-i\",\"rootPid\":101,\"rootStartTimeTicks\":\"100\"}}]}}"
            ),
        )
        .unwrap();
        let mut reloader = TlsAgentScopeReloader::with_roots(document, proc_root, cgroup_root);
        let refresh = reloader.refresh().unwrap();
        assert_eq!(refresh.pids, HashSet::from([50, 101, 111]));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pid_reuse_and_legacy_scope_conflict_fail_closed() {
        let root = fixture_root("reuse");
        let proc_root = root.join("proc");
        let cgroup_root = root.join("cgroup");
        let cgroup = cgroup_root.join("docker/shared");
        fs::create_dir_all(&cgroup).unwrap();
        fs::create_dir_all(proc_root.join("101")).unwrap();
        fs::write(proc_root.join("101/cgroup"), "0::/docker/shared\n").unwrap();
        fs::write(proc_root.join("101/stat"), stat_line(101, 1, 999)).unwrap();
        let cgroup_id = fs::metadata(&cgroup).unwrap().ino();
        let document = root.join("scopes.json");
        fs::write(
            &document,
            format!(
                "{{\"schemaVersion\":\"{SCHEMA}\",\"entries\":[{{\"cgroupId\":\"{cgroup_id}\",\"agentScopeId\":\"codex\",\"rootPid\":101,\"rootStartTimeTicks\":\"100\"}}]}}"
            ),
        )
        .unwrap();
        let mut reloader = TlsAgentScopeReloader::with_roots(
            document.clone(),
            proc_root.clone(),
            cgroup_root.clone(),
        );
        assert!(reloader.refresh().unwrap().pids.is_empty());

        fs::write(
            &document,
            format!(
                "{{\"schemaVersion\":\"{SCHEMA}\",\"entries\":[{{\"cgroupId\":\"{cgroup_id}\",\"agentScopeId\":\"codex\"}},{{\"cgroupId\":\"{cgroup_id}\",\"agentScopeId\":\"claude\"}}]}}"
            ),
        )
        .unwrap();
        let refresh = reloader.refresh().unwrap();
        assert_eq!(refresh.conflicts, 1);
        assert!(refresh.pids.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn descendant_that_crosses_cgroup_boundary_is_not_admitted_by_a_root_fence() {
        let root = fixture_root("cgroup-boundary");
        let proc_root = root.join("proc");
        let cgroup_root = root.join("cgroup");
        let root_cgroup = cgroup_root.join("docker/root");
        let child_cgroup = cgroup_root.join("docker/child");
        fs::create_dir_all(&root_cgroup).unwrap();
        fs::create_dir_all(&child_cgroup).unwrap();
        for (pid, ppid, cgroup, start) in [
            (101, 1, "/docker/root", 100),
            (111, 101, "/docker/child", 110),
        ] {
            fs::create_dir_all(proc_root.join(pid.to_string())).unwrap();
            fs::write(
                proc_root.join(pid.to_string()).join("cgroup"),
                format!("0::{cgroup}\n"),
            )
            .unwrap();
            fs::write(
                proc_root.join(pid.to_string()).join("stat"),
                stat_line(pid, ppid, start),
            )
            .unwrap();
        }
        let root_id = fs::metadata(&root_cgroup).unwrap().ino();
        let child_id = fs::metadata(&child_cgroup).unwrap().ino();
        let document = root.join("scopes.json");
        fs::write(
            &document,
            format!(
                "{{\"schemaVersion\":\"{SCHEMA}\",\"entries\":[{{\"cgroupId\":\"{root_id}\",\"agentScopeId\":\"codex\",\"rootPid\":101,\"rootStartTimeTicks\":\"100\"}},{{\"cgroupId\":\"{child_id}\",\"agentScopeId\":\"codex\",\"rootPid\":101,\"rootStartTimeTicks\":\"100\"}}]}}"
            ),
        )
        .unwrap();
        let mut reloader = TlsAgentScopeReloader::with_roots(document, proc_root, cgroup_root);
        let refresh = reloader.refresh().unwrap();
        // The root belongs to the first cgroup. The child is intentionally moved to another
        // cgroup and must not inherit the root's admission through PPid traversal.
        assert_eq!(refresh.pids, HashSet::from([101]));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_fence_does_not_replace_last_good_scope() {
        let root = fixture_root("invalid");
        fs::create_dir_all(&root).unwrap();
        let document = root.join("scopes.json");
        fs::write(
            &document,
            format!("{{\"schemaVersion\":\"{SCHEMA}\",\"entries\":[{{\"cgroupId\":\"7\"}}]}}"),
        )
        .unwrap();
        let mut reloader = TlsAgentScopeReloader::with_roots(
            document.clone(),
            root.join("proc"),
            root.join("cgroup"),
        );
        assert!(reloader.reload_if_changed().unwrap());
        fs::write(
            &document,
            format!(
                "{{\"schemaVersion\":\"{SCHEMA}\",\"entries\":[{{\"cgroupId\":\"7\",\"rootPid\":101}}]}}"
            ),
        )
        .unwrap();
        assert!(reloader.reload_if_changed().is_err());
        assert_eq!(reloader.scopes.cgroups, HashSet::from([7]));
        fs::remove_dir_all(root).unwrap();
    }
}
