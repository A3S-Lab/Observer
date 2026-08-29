//! Product-neutral TLS admission scopes published by the co-located identity forwarder.
//!
//! This file is not an enforcement authority: it can only add plaintext observation for Docker
//! cgroups already carrying an exact Agent workload label. Content remains bounded by the kernel
//! ring and userspace protocol classifiers.

use anyhow::Context as _;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

const SCHEMA: &str = "anysentry.tls_agent_cgroups.v1";
const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MAX_CGROUPS: usize = 65_536;
const MAX_PROCESSES: usize = 1_048_576;

#[derive(Debug)]
pub struct TlsAgentScopeRefresh {
    pub pids: HashSet<i32>,
    pub cgroups: usize,
    pub changed: bool,
}

#[derive(Debug)]
pub struct TlsAgentScopeReloader {
    path: PathBuf,
    proc_root: PathBuf,
    cgroup_root: PathBuf,
    last_document: Vec<u8>,
    cgroups: HashSet<u64>,
}

impl TlsAgentScopeReloader {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            proc_root: PathBuf::from("/proc"),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            last_document: Vec::new(),
            cgroups: HashSet::new(),
        }
    }

    #[cfg(test)]
    fn with_roots(path: PathBuf, proc_root: PathBuf, cgroup_root: PathBuf) -> Self {
        Self {
            path,
            proc_root,
            cgroup_root,
            last_document: Vec::new(),
            cgroups: HashSet::new(),
        }
    }

    pub fn refresh(&mut self) -> anyhow::Result<TlsAgentScopeRefresh> {
        let changed = self.reload_if_changed()?;
        let pids = scan_pids_for_cgroups(&self.proc_root, &self.cgroup_root, &self.cgroups)?;
        Ok(TlsAgentScopeRefresh {
            pids,
            cgroups: self.cgroups.len(),
            changed,
        })
    }

    fn reload_if_changed(&mut self) -> anyhow::Result<bool> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let changed = !self.last_document.is_empty() || !self.cgroups.is_empty();
                self.last_document.clear();
                self.cgroups.clear();
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
        let mut cgroups = HashSet::with_capacity(entries.len());
        for entry in entries {
            let id = entry
                .get("cgroupId")
                .and_then(Value::as_str)
                .context("TLS Agent cgroup ID must be a string")?
                .parse::<u64>()
                .context("TLS Agent cgroup ID must be an unsigned integer")?;
            anyhow::ensure!(id != 0, "TLS Agent cgroup ID must be non-zero");
            cgroups.insert(id);
        }
        self.last_document = bytes;
        self.cgroups = cgroups;
        Ok(true)
    }
}

fn scan_pids_for_cgroups(
    proc_root: &Path,
    cgroup_root: &Path,
    admitted: &HashSet<u64>,
) -> anyhow::Result<HashSet<i32>> {
    if admitted.is_empty() {
        return Ok(HashSet::new());
    }
    let mut pids = HashSet::new();
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
        if process_cgroup_id(proc_root, cgroup_root, pid).is_some_and(|id| admitted.contains(&id)) {
            pids.insert(pid);
        }
    }
    Ok(pids)
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

    #[test]
    fn published_cgroups_admit_existing_and_new_processes_without_product_names() {
        let root = std::env::temp_dir().join(format!(
            "anysentry-tls-agent-scopes-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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
        assert_eq!(first.pids, HashSet::from([101]));

        fs::create_dir_all(proc_root.join("303")).unwrap();
        fs::write(proc_root.join("303/cgroup"), "0::/docker/agent\n").unwrap();
        let second = reloader.refresh().unwrap();
        assert!(!second.changed);
        assert_eq!(second.pids, HashSet::from([101, 303]));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_or_traversing_documents_do_not_replace_last_good_scope() {
        let root = std::env::temp_dir().join(format!(
            "anysentry-tls-agent-scopes-invalid-{}",
            std::process::id()
        ));
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
        fs::write(&document, "{\"schemaVersion\":\"wrong\",\"entries\":[]}").unwrap();
        assert!(reloader.reload_if_changed().is_err());
        assert_eq!(reloader.cgroups, HashSet::from([7]));
        fs::remove_dir_all(root).unwrap();
    }
}
