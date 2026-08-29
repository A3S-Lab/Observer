//! Runtime TLS-library and static executable discovery for selected Agent processes.
//!
//! Products, CLI versions, provider URLs and whole-file fingerprints are not discovery gates.
//! Exported TLS symbols are preferred; stripped static binaries are matched against bounded TLS
//! implementation-family anchors and call-pair relations, then validated by real plaintext framing.

use anyhow::Context as _;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const PROFILE_DOCUMENT: &str = include_str!("tls-profiles.json");
const STATIC_SCAN_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const MAX_ELF_PROGRAM_HEADERS: usize = 128;
const MAX_ANCHOR_MATCHES: usize = 128;
const MAX_STATIC_CANDIDATES_PER_FAMILY: usize = 4;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TlsAbi {
    Classic,
    OpenSslEx,
    RustlsPayload,
    RustlsOutboundChunks,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolFamily {
    OpenSsl,
    GnuTls,
    Nss,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeRole {
    AgentRoot,
    NetworkRuntime,
}

impl RuntimeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentRoot => "agent_root",
            Self::NetworkRuntime => "network_runtime",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TlsOffsetPair {
    pub read_offset: u64,
    pub write_offset: u64,
    pub read_abi: TlsAbi,
    pub write_abi: TlsAbi,
}

#[derive(Clone, Debug)]
pub enum TlsAttachKind {
    Symbols(SymbolFamily),
    Offsets {
        read_offset: u64,
        write_offset: u64,
        read_abi: TlsAbi,
        write_abi: TlsAbi,
        additional_pairs: Vec<TlsOffsetPair>,
    },
}

#[derive(Clone, Debug)]
pub struct TlsAttachPlan {
    pub key: String,
    pub pid: Option<i32>,
    pub path: PathBuf,
    pub product: String,
    pub runtime_role: RuntimeRole,
    pub transport_scope: String,
    pub excluded_transport_scope: Option<String>,
    pub kind: TlsAttachKind,
}

#[derive(Clone, Debug)]
struct StaticBootstrapProfile {
    read_offset: u64,
    read_prefix: Vec<u8>,
    write_offset: u64,
    write_prefix: Vec<u8>,
    read_abi: TlsAbi,
    write_abi: TlsAbi,
    additional_pairs: Vec<(TlsOffsetPair, Vec<u8>, Vec<u8>)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StaticSignatureFamily {
    family_id: String,
    read_prefix: Vec<u8>,
    write_prefix: Vec<u8>,
    read_abi: TlsAbi,
    write_abi: TlsAbi,
    write_after_read: Vec<i64>,
}

#[derive(Clone, Debug)]
struct StaticDiscoveryMatch {
    family_id: String,
    pairs: Vec<TlsOffsetPair>,
}

#[derive(Debug)]
pub struct TlsAttachManager {
    attached: HashSet<String>,
    rejected: HashSet<String>,
    verified_processes: HashMap<i32, RuntimeRole>,
    static_discovery_cache: HashMap<(u64, u64), Vec<StaticDiscoveryMatch>>,
    process_patterns: Vec<String>,
    static_targets: Vec<PathBuf>,
    explicit_target: Option<PathBuf>,
}

impl TlsAttachManager {
    pub fn from_env(ssl_setting: &str) -> Self {
        let mut process_patterns = vec![
            "codex".to_string(),
            "claude".to_string(),
            "dify-plugin-daemon".to_string(),
            "kimi".to_string(),
            "langchain".to_string(),
            "pi-coding-agent".to_string(),
            "run-pi-".to_string(),
        ];
        if let Ok(extra) = std::env::var("A3S_OBSERVER_TLS_PROCESS_PATTERNS") {
            process_patterns.extend(
                extra
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| value.to_ascii_lowercase()),
            );
        }
        process_patterns.sort();
        process_patterns.dedup();
        let explicit_target = ssl_setting
            .contains('/')
            .then(|| PathBuf::from(ssl_setting));
        let static_targets = std::env::var("A3S_OBSERVER_TLS_STATIC_TARGETS")
            .ok()
            .into_iter()
            .flat_map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|path| !path.is_empty())
                    .map(PathBuf::from)
                    .collect::<Vec<_>>()
            })
            .collect();
        Self {
            attached: HashSet::new(),
            rejected: HashSet::new(),
            verified_processes: HashMap::new(),
            static_discovery_cache: HashMap::new(),
            process_patterns,
            static_targets,
            explicit_target,
        }
    }

    pub fn discover(&mut self) -> Vec<TlsAttachPlan> {
        let mut plans = Vec::new();
        if let Some(path) = self.explicit_target.clone() {
            if let Some(plan) = self.plan_for_explicit(path) {
                plans.push(plan);
            }
        }
        for path in self.static_targets.clone() {
            plans.extend(self.plans_for_static_target(path));
        }

        let Ok(proc_entries) = fs::read_dir("/proc") else {
            return plans;
        };
        let mut verified_processes = HashMap::new();
        for entry in proc_entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<i32>().ok())
            else {
                continue;
            };
            let Some(runtime_role) = self.runtime_role(pid) else {
                continue;
            };
            verified_processes.insert(pid, runtime_role);
            plans.extend(self.plans_for_process(pid, runtime_role));
        }
        self.verified_processes = verified_processes;
        let mut seen = HashSet::new();
        plans.retain(|plan| {
            !self.attached.contains(&plan.key)
                && !self.rejected.contains(&plan.key)
                && seen.insert(plan.key.clone())
        });
        plans
    }

    pub fn discover_pid(&mut self, pid: i32) -> Vec<TlsAttachPlan> {
        let Some(runtime_role) = self.runtime_role(pid) else {
            self.verified_processes.remove(&pid);
            return Vec::new();
        };
        self.verified_processes.insert(pid, runtime_role);
        self.plans_for_process(pid, runtime_role)
            .into_iter()
            .filter(|plan| !self.attached.contains(&plan.key) && !self.rejected.contains(&plan.key))
            .collect()
    }

    /// Control-plane identity/capture evidence is authoritative for scope membership. This path
    /// lets any candidate/confirmed Agent runtime enter TLS discovery without adding its product
    /// name to the Collector. URL and protocol semantics remain userspace-only.
    pub fn discover_verified_pid(&mut self, pid: i32) -> Vec<TlsAttachPlan> {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            self.verified_processes.remove(&pid);
            return Vec::new();
        }
        let runtime_role = RuntimeRole::AgentRoot;
        self.verified_processes.insert(pid, runtime_role);
        self.plans_for_process(pid, runtime_role)
            .into_iter()
            .filter(|plan| !self.attached.contains(&plan.key) && !self.rejected.contains(&plan.key))
            .collect()
    }

    pub fn mark_attached(&mut self, key: String, _pid: Option<i32>) {
        self.attached.insert(key);
    }

    pub fn mark_rejected(&mut self, key: String, reason: &str) {
        if self.rejected.insert(key.clone()) {
            tracing::warn!(target = %key, reason, "TLS target rejected; plaintext capture remains unavailable");
        }
    }

    pub fn attached_count(&self) -> usize {
        self.attached.len()
    }

    pub fn verified_pids(&mut self) -> Vec<i32> {
        self.verified_processes
            .retain(|pid, _| Path::new(&format!("/proc/{pid}")).exists());
        self.verified_processes.keys().copied().collect()
    }

    fn runtime_role(&self, pid: i32) -> Option<RuntimeRole> {
        if self.process_matches_patterns(pid) {
            return Some(RuntimeRole::AgentRoot);
        }
        let mut current = pid;
        for _ in 0..6 {
            if current <= 1 {
                break;
            }
            // Dify provider/tool workers are separate runtimes below the plugin daemon. They stay
            // in the same bounded Agent Scope; userspace content classification separates model,
            // tool and unrelated TLS streams without a URL allowlist.
            if process_contains_pattern(current, "dify-plugin-daemon") {
                return Some(RuntimeRole::NetworkRuntime);
            }
            // Codex may delegate network work to this exact packaged runtime. Do not inherit
            // trust to arbitrary shell/git/python descendants of the Agent root.
            if current == pid
                && process_matches_trusted_network_runtime(pid)
                && ancestor_contains_pattern(pid, "codex")
            {
                return Some(RuntimeRole::NetworkRuntime);
            }
            let Some(parent) = process_parent_pid(current) else {
                break;
            };
            if parent == current {
                break;
            }
            current = parent;
        }
        None
    }

    fn process_matches_patterns(&self, pid: i32) -> bool {
        let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
            .ok()
            .map(|bytes| {
                bytes
                    .split(|byte| *byte == 0)
                    .filter_map(|part| std::str::from_utf8(part).ok())
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        matches_selected_agent_text(&comm, &cmdline, &self.process_patterns)
    }

    fn plans_for_process(&mut self, pid: i32, runtime_role: RuntimeRole) -> Vec<TlsAttachPlan> {
        let mut plans = Vec::new();
        let exe_probe_path = PathBuf::from(format!("/proc/{pid}/exe"));
        if let Ok(real_exe) = fs::read_link(&exe_probe_path) {
            plans.extend(self.plans_for_executable(pid, &exe_probe_path, &real_exe, runtime_role));
        }

        let maps = fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_default();
        let mut seen = HashSet::<(u64, u64)>::new();
        for line in maps.lines() {
            let Some(mapped) = line.split_whitespace().last() else {
                continue;
            };
            if !mapped.starts_with('/') {
                continue;
            }
            let mapped = mapped.strip_suffix(" (deleted)").unwrap_or(mapped);
            let family = classify_library(mapped);
            let Some(family) = family else {
                continue;
            };
            let rooted =
                PathBuf::from(format!("/proc/{pid}/root")).join(mapped.trim_start_matches('/'));
            let Ok(metadata) = fs::metadata(&rooted) else {
                continue;
            };
            if !seen.insert((metadata.dev(), metadata.ino())) {
                continue;
            }
            let key = format!(
                "pid:{pid}:dev:{}:ino:{}:symbols:{family:?}",
                metadata.dev(),
                metadata.ino()
            );
            plans.push(TlsAttachPlan {
                key,
                pid: Some(pid),
                path: rooted,
                product: "mapped-tls-library".to_string(),
                runtime_role,
                transport_scope: format!("{family:?}").to_ascii_lowercase(),
                excluded_transport_scope: None,
                kind: TlsAttachKind::Symbols(family),
            });
        }
        plans
    }

    fn plans_for_executable(
        &mut self,
        pid: i32,
        probe_path: &Path,
        real_exe: &Path,
        runtime_role: RuntimeRole,
    ) -> Vec<TlsAttachPlan> {
        let Ok(metadata) = fs::metadata(probe_path) else {
            return Vec::new();
        };
        let Some(file_name) = real_exe.file_name() else {
            return Vec::new();
        };
        let basename = file_name.to_string_lossy().to_ascii_lowercase();
        let identity = format!("pid:{pid}:dev:{}:ino:{}", metadata.dev(), metadata.ino());
        let mut plans = Vec::new();
        let cache_key = (metadata.dev(), metadata.ino());
        let static_probe_path = stable_executable_probe_path(pid, probe_path, real_exe, &metadata)
            .unwrap_or_else(|| probe_path.to_path_buf());
        let static_matches = if is_interpreter_or_shell(&basename) {
            Vec::new()
        } else if let Some(cached) = self.static_discovery_cache.get(&cache_key) {
            cached.clone()
        } else {
            match discover_static_signature_matches(&static_probe_path) {
                Ok(matches) => {
                    self.static_discovery_cache
                        .insert(cache_key, matches.clone());
                    matches
                }
                Err(error) => {
                    self.mark_rejected(
                        format!("{identity}:static-discovery"),
                        &format!("static_signature_discovery_failed:{error}"),
                    );
                    Vec::new()
                }
            }
        };
        plans.extend(static_matches.into_iter().map(|discovery| {
            static_discovery_plan(&static_probe_path, &metadata, discovery, runtime_role, None)
        }));

        // Interpreters commonly export OpenSSL symbols from the main ELF even when no separate
        // libssl mapping exists. This low-maintenance lane may coexist with a static-family
        // candidate; attach failures are isolated by plan key.
        if matches!(basename.as_str(), "node" | "nodejs")
            || basename.starts_with("python3.")
            || basename == "python"
        {
            plans.push(TlsAttachPlan {
                key: format!("{identity}:main-exported-openssl"),
                pid: Some(pid),
                path: probe_path.to_path_buf(),
                product: format!("{basename}-main-elf"),
                runtime_role,
                transport_scope: "main-executable-exported-openssl".to_string(),
                excluded_transport_scope: None,
                kind: TlsAttachKind::Symbols(SymbolFamily::OpenSsl),
            });
        }

        if plans.is_empty() && !is_interpreter_or_shell(&basename) {
            self.mark_rejected(
                format!("{identity}:static-signature-not-found"),
                "static_tls_family_not_discovered",
            );
        }
        plans
    }

    fn plans_for_static_target(&mut self, path: PathBuf) -> Vec<TlsAttachPlan> {
        let Ok(metadata) = fs::metadata(&path) else {
            return Vec::new();
        };
        let cache_key = (metadata.dev(), metadata.ino());
        let matches = if let Some(cached) = self.static_discovery_cache.get(&cache_key) {
            cached.clone()
        } else {
            match discover_static_signature_matches(&path) {
                Ok(matches) => {
                    self.static_discovery_cache
                        .insert(cache_key, matches.clone());
                    matches
                }
                Err(error) => {
                    self.mark_rejected(
                        format!(
                            "global:dev:{}:ino:{}:static-target",
                            metadata.dev(),
                            metadata.ino()
                        ),
                        &format!("static_signature_discovery_failed:{error}"),
                    );
                    Vec::new()
                }
            }
        };
        let mut plans = matches
            .into_iter()
            .map(|discovery| {
                static_discovery_plan(&path, &metadata, discovery, RuntimeRole::AgentRoot, None)
            })
            .collect::<Vec<_>>();
        if let Some(family) = classify_library(path.to_string_lossy().as_ref()) {
            plans.push(TlsAttachPlan {
                key: format!(
                    "global:dev:{}:ino:{}:symbols:{family:?}",
                    metadata.dev(),
                    metadata.ino()
                ),
                pid: None,
                path,
                product: "static-tls-library".to_string(),
                runtime_role: RuntimeRole::AgentRoot,
                transport_scope: format!("{family:?}").to_ascii_lowercase(),
                excluded_transport_scope: None,
                kind: TlsAttachKind::Symbols(family),
            });
        }
        plans
    }

    fn plan_for_explicit(&mut self, path: PathBuf) -> Option<TlsAttachPlan> {
        let metadata = fs::metadata(&path).ok()?;
        let family =
            classify_library(path.to_string_lossy().as_ref()).unwrap_or(SymbolFamily::OpenSsl);
        Some(TlsAttachPlan {
            key: format!(
                "explicit:dev:{}:ino:{}:{family:?}",
                metadata.dev(),
                metadata.ino()
            ),
            pid: None,
            path,
            product: "explicit-tls-target".to_string(),
            runtime_role: RuntimeRole::AgentRoot,
            transport_scope: format!("{family:?}").to_ascii_lowercase(),
            excluded_transport_scope: None,
            kind: TlsAttachKind::Symbols(family),
        })
    }
}

fn static_discovery_plan(
    path: &Path,
    metadata: &fs::Metadata,
    discovery: StaticDiscoveryMatch,
    runtime_role: RuntimeRole,
    pid: Option<i32>,
) -> TlsAttachPlan {
    let mut pairs = discovery.pairs.into_iter();
    let primary = pairs
        .next()
        .expect("static discovery matches always contain a primary pair");
    TlsAttachPlan {
        key: format!(
            "{}dev:{}:ino:{}:static-family:{}",
            pid.map(|value| format!("pid:{value}:")).unwrap_or_default(),
            metadata.dev(),
            metadata.ino(),
            discovery.family_id,
        ),
        pid,
        path: path.to_path_buf(),
        product: format!("tls-family:{}", discovery.family_id),
        runtime_role,
        transport_scope: "static-abi-discovery".to_string(),
        excluded_transport_scope: None,
        kind: TlsAttachKind::Offsets {
            read_offset: primary.read_offset,
            write_offset: primary.write_offset,
            read_abi: primary.read_abi,
            write_abi: primary.write_abi,
            additional_pairs: pairs.collect(),
        },
    }
}

fn matches_selected_agent_text(comm: &str, cmdline: &str, process_patterns: &[String]) -> bool {
    // Node running as PID 1 can retain `MainThread` in /proc/<pid>/comm even after Pi sets
    // process.title. The title still replaces argv in cmdline, so admit the exact `pi` title
    // without adding a broad `pi` substring pattern that would match unrelated Python processes.
    matches!(comm, "codex" | "claude" | "claude.exe" | "pi")
        || cmdline.trim() == "pi"
        || process_patterns
            .iter()
            .any(|pattern| comm.contains(pattern.as_str()) || cmdline.contains(pattern.as_str()))
}

fn process_parent_pid(pid: i32) -> Option<i32> {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))?
        .trim()
        .parse()
        .ok()
}

fn stable_executable_probe_path(
    pid: i32,
    probe_path: &Path,
    real_exe: &Path,
    expected: &fs::Metadata,
) -> Option<PathBuf> {
    let same_inode = |path: &Path| {
        fs::metadata(path).ok().is_some_and(|metadata| {
            metadata.dev() == expected.dev() && metadata.ino() == expected.ino()
        })
    };
    if real_exe.is_absolute() && same_inode(real_exe) {
        return Some(real_exe.to_path_buf());
    }

    let relative = real_exe.strip_prefix("/").ok()?;
    let mut current = pid;
    let mut stable = same_inode(probe_path).then(|| probe_path.to_path_buf());
    for _ in 0..12 {
        if current <= 1 {
            break;
        }
        let rooted = PathBuf::from(format!("/proc/{current}/root")).join(relative);
        if same_inode(&rooted) {
            stable = Some(rooted);
        }
        let Some(parent) = process_parent_pid(current) else {
            break;
        };
        if parent == current {
            break;
        }
        current = parent;
    }
    stable
}

fn ancestor_contains_pattern(pid: i32, pattern: &str) -> bool {
    let mut current = pid;
    for _ in 0..6 {
        let Some(parent) = process_parent_pid(current) else {
            return false;
        };
        if parent <= 1 || parent == current {
            return false;
        }
        if process_contains_pattern(parent, pattern) {
            return true;
        }
        current = parent;
    }
    false
}

fn process_matches_trusted_network_runtime(pid: i32) -> bool {
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let executable = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|value| value.to_string_lossy().to_string())
        })
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches_trusted_network_runtime_text(&comm, &executable)
}

fn matches_trusted_network_runtime_text(comm: &str, executable: &str) -> bool {
    comm == "codex-code-mode" || executable == "codex-code-mode-host"
}

fn process_contains_pattern(pid: i32, pattern: &str) -> bool {
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    if comm.contains(pattern) {
        return true;
    }
    fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .is_some_and(|cmdline| cmdline.to_ascii_lowercase().contains(pattern))
}

fn classify_library(path: &str) -> Option<SymbolFamily> {
    let name = Path::new(path).file_name()?.to_string_lossy();
    if name.starts_with("libssl.so") || name.starts_with("libssl-") {
        Some(SymbolFamily::OpenSsl)
    } else if name.starts_with("libgnutls.so") || name.starts_with("libgnutls-") {
        Some(SymbolFamily::GnuTls)
    } else if name.starts_with("libnspr4.so") || name.starts_with("libnspr4-") {
        Some(SymbolFamily::Nss)
    } else {
        None
    }
}

fn is_interpreter_or_shell(basename: &str) -> bool {
    matches!(
        basename,
        "node"
            | "nodejs"
            | "python"
            | "python3"
            | "bash"
            | "sh"
            | "dash"
            | "zsh"
            | "fish"
            | "java"
            | "ruby"
            | "perl"
    ) || basename.starts_with("python3.")
}

fn static_profiles() -> anyhow::Result<Vec<StaticBootstrapProfile>> {
    let root: Value = serde_json::from_str(PROFILE_DOCUMENT)?;
    let profiles = root
        .get("profiles")
        .and_then(Value::as_array)
        .context("TLS profile document has no profiles")?;
    profiles.iter().map(parse_profile).collect()
}

fn parse_profile(value: &Value) -> anyhow::Result<StaticBootstrapProfile> {
    let string = |name: &str| -> anyhow::Result<String> {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .with_context(|| format!("TLS profile field {name} is missing"))
    };
    let integer = |name: &str| -> anyhow::Result<u64> {
        value
            .get(name)
            .and_then(Value::as_u64)
            .with_context(|| format!("TLS profile field {name} is missing"))
    };
    let additional_pairs = value
        .get("additionalProbePairs")
        .map(|pairs| {
            pairs
                .as_array()
                .context("TLS profile additionalProbePairs must be an array")?
                .iter()
                .map(parse_additional_pair)
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(StaticBootstrapProfile {
        read_offset: integer("readOffset")?,
        read_prefix: decode_hex(&string("readExpectedPrefixHex")?)?,
        write_offset: integer("writeOffset")?,
        write_prefix: decode_hex(&string("writeExpectedPrefixHex")?)?,
        read_abi: parse_abi(&string("readAbi")?)?,
        write_abi: parse_abi(&string("writeAbi")?)?,
        additional_pairs,
    })
}

fn static_signature_families() -> anyhow::Result<Vec<StaticSignatureFamily>> {
    let mut families = Vec::<StaticSignatureFamily>::new();
    for profile in static_profiles()? {
        add_signature_observation(
            &mut families,
            &TlsOffsetPair {
                read_offset: profile.read_offset,
                write_offset: profile.write_offset,
                read_abi: profile.read_abi,
                write_abi: profile.write_abi,
            },
            &profile.read_prefix,
            &profile.write_prefix,
        )?;
        for (pair, read_prefix, write_prefix) in profile.additional_pairs {
            add_signature_observation(&mut families, &pair, &read_prefix, &write_prefix)?;
        }
    }
    for family in &mut families {
        family.write_after_read.sort_unstable();
        family.write_after_read.dedup();
    }
    families.sort_by(|left, right| left.family_id.cmp(&right.family_id));
    Ok(families)
}

fn add_signature_observation(
    families: &mut Vec<StaticSignatureFamily>,
    pair: &TlsOffsetPair,
    read_prefix: &[u8],
    write_prefix: &[u8],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        read_prefix.len() >= 12 && write_prefix.len() >= 12,
        "static TLS anchors must be at least 12 bytes"
    );
    let delta = i128::from(pair.write_offset) - i128::from(pair.read_offset);
    let delta = i64::try_from(delta).context("TLS anchor relation exceeds i64")?;
    if let Some(family) = families.iter_mut().find(|family| {
        family.read_prefix == read_prefix
            && family.write_prefix == write_prefix
            && family.read_abi == pair.read_abi
            && family.write_abi == pair.write_abi
    }) {
        family.write_after_read.push(delta);
        return Ok(());
    }
    families.push(StaticSignatureFamily {
        family_id: signature_family_id(read_prefix, write_prefix, pair.read_abi, pair.write_abi),
        read_prefix: read_prefix.to_vec(),
        write_prefix: write_prefix.to_vec(),
        read_abi: pair.read_abi,
        write_abi: pair.write_abi,
        write_after_read: vec![delta],
    });
    Ok(())
}

fn signature_family_id(
    read_prefix: &[u8],
    write_prefix: &[u8],
    read_abi: TlsAbi,
    write_abi: TlsAbi,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"anysentry.static_tls_family.v1");
    hash.update([tls_abi_code(read_abi), tls_abi_code(write_abi)]);
    hash.update(read_prefix);
    hash.update(write_prefix);
    format!(
        "{}-{}-{}",
        tls_abi_name(read_abi),
        tls_abi_name(write_abi),
        &hex(&hash.finalize())[..16]
    )
}

fn tls_abi_code(abi: TlsAbi) -> u8 {
    match abi {
        TlsAbi::Classic => 1,
        TlsAbi::OpenSslEx => 2,
        TlsAbi::RustlsPayload => 3,
        TlsAbi::RustlsOutboundChunks => 4,
    }
}

fn tls_abi_name(abi: TlsAbi) -> &'static str {
    match abi {
        TlsAbi::Classic => "classic",
        TlsAbi::OpenSslEx => "openssl-ex",
        TlsAbi::RustlsPayload => "rustls-payload",
        TlsAbi::RustlsOutboundChunks => "rustls-outbound",
    }
}

fn discover_static_signature_matches(path: &Path) -> anyhow::Result<Vec<StaticDiscoveryMatch>> {
    let ranges = executable_file_ranges(path)?;
    let families = static_signature_families()?;
    let mut patterns = families
        .iter()
        .flat_map(|family| [family.read_prefix.clone(), family.write_prefix.clone()])
        .collect::<Vec<_>>();
    patterns.sort();
    patterns.dedup();
    let anchor_matches = find_pattern_set_offsets(path, &ranges, &patterns, MAX_ANCHOR_MATCHES)?;
    let mut discovered = Vec::new();
    for family in families {
        let reads = anchor_matches
            .get(&family.read_prefix)
            .cloned()
            .unwrap_or_default();
        if reads.is_empty() {
            continue;
        }
        let writes = anchor_matches
            .get(&family.write_prefix)
            .cloned()
            .unwrap_or_default();
        if writes.is_empty() {
            continue;
        }
        let write_offsets = writes.into_iter().collect::<HashSet<_>>();
        let mut pairs = Vec::new();
        for read_offset in reads {
            for delta in &family.write_after_read {
                let candidate = i128::from(read_offset) + i128::from(*delta);
                if !(0..=i128::from(u64::MAX)).contains(&candidate) {
                    continue;
                }
                let write_offset = candidate as u64;
                if write_offsets.contains(&write_offset) {
                    pairs.push(TlsOffsetPair {
                        read_offset,
                        write_offset,
                        read_abi: family.read_abi,
                        write_abi: family.write_abi,
                    });
                }
            }
        }
        pairs.sort_by_key(|pair| (pair.read_offset, pair.write_offset));
        pairs.dedup_by_key(|pair| (pair.read_offset, pair.write_offset));
        pairs.truncate(MAX_STATIC_CANDIDATES_PER_FAMILY);
        if !pairs.is_empty() {
            discovered.push(StaticDiscoveryMatch {
                family_id: family.family_id,
                pairs,
            });
        }
    }
    Ok(discovered)
}

fn executable_file_ranges(path: &Path) -> anyhow::Result<Vec<(u64, u64)>> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let mut header = [0u8; 64];
    file.read_exact(&mut header)?;
    anyhow::ensure!(&header[..4] == b"\x7fELF", "not an ELF file");
    anyhow::ensure!(header[4] == 2, "static TLS discovery requires ELF64");
    anyhow::ensure!(
        header[5] == 1,
        "static TLS discovery requires little-endian ELF"
    );
    anyhow::ensure!(u16_le(&header, 18)? == 62, "unsupported ELF machine");
    let program_header_offset = u64_le(&header, 32)?;
    let program_header_size = usize::from(u16_le(&header, 54)?);
    let program_header_count = usize::from(u16_le(&header, 56)?);
    anyhow::ensure!(
        program_header_size >= 56 && program_header_count <= MAX_ELF_PROGRAM_HEADERS,
        "invalid ELF program-header table"
    );

    let mut ranges = Vec::new();
    let mut entry = vec![0u8; program_header_size];
    for index in 0..program_header_count {
        let offset = program_header_offset
            .checked_add((index * program_header_size) as u64)
            .context("ELF program-header offset overflow")?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut entry)?;
        let segment_type = u32_le(&entry, 0)?;
        let flags = u32_le(&entry, 4)?;
        if segment_type != 1 || flags & 1 == 0 {
            continue;
        }
        let start = u64_le(&entry, 8)?;
        let length = u64_le(&entry, 32)?;
        let end = start
            .checked_add(length)
            .context("ELF executable segment overflow")?
            .min(file_len);
        if start < end {
            ranges.push((start, end));
        }
    }
    anyhow::ensure!(!ranges.is_empty(), "ELF has no executable load segment");
    ranges.sort_unstable();
    Ok(ranges)
}

#[cfg(test)]
fn find_pattern_offsets(
    path: &Path,
    ranges: &[(u64, u64)],
    pattern: &[u8],
    limit: usize,
) -> anyhow::Result<Vec<u64>> {
    Ok(
        find_pattern_set_offsets(path, ranges, &[pattern.to_vec()], limit)?
            .remove(pattern)
            .unwrap_or_default(),
    )
}

fn find_pattern_set_offsets(
    path: &Path,
    ranges: &[(u64, u64)],
    patterns: &[Vec<u8>],
    limit: usize,
) -> anyhow::Result<HashMap<Vec<u8>, Vec<u64>>> {
    anyhow::ensure!(
        !patterns.is_empty() && patterns.iter().all(|pattern| !pattern.is_empty()),
        "empty TLS anchor set"
    );
    let mut file = File::open(path)?;
    let overlap = patterns
        .iter()
        .map(Vec::len)
        .max()
        .unwrap_or(1)
        .saturating_sub(1);
    let mut matches = patterns
        .iter()
        .cloned()
        .map(|pattern| (pattern, Vec::new()))
        .collect::<HashMap<_, _>>();
    for (start, end) in ranges {
        let mut cursor = *start;
        let mut carry = Vec::<u8>::new();
        while cursor < *end {
            let requested = (*end - cursor).min(STATIC_SCAN_CHUNK_BYTES as u64) as usize;
            let mut window = vec![0u8; carry.len() + requested];
            window[..carry.len()].copy_from_slice(&carry);
            file.seek(SeekFrom::Start(cursor))?;
            file.read_exact(&mut window[carry.len()..])?;
            let window_offset = cursor.saturating_sub(carry.len() as u64);
            for pattern in patterns {
                let Some(offsets) = matches.get_mut(pattern) else {
                    continue;
                };
                if offsets.len() >= limit {
                    continue;
                }
                find_pattern_positions(&window, pattern, limit - offsets.len(), |position| {
                    offsets.push(window_offset + position as u64);
                });
            }
            let retained = overlap.min(window.len());
            carry.clear();
            carry.extend_from_slice(&window[window.len() - retained..]);
            cursor += requested as u64;
        }
    }
    for offsets in matches.values_mut() {
        offsets.sort_unstable();
        offsets.dedup();
        offsets.truncate(limit);
    }
    Ok(matches)
}

fn find_pattern_positions(
    bytes: &[u8],
    pattern: &[u8],
    limit: usize,
    mut found: impl FnMut(usize),
) {
    if pattern.is_empty() || bytes.len() < pattern.len() || limit == 0 {
        return;
    }
    let first = pattern[0];
    let mut cursor = 0usize;
    let mut count = 0usize;
    while cursor + pattern.len() <= bytes.len() && count < limit {
        let Some(relative) = bytes[cursor..].iter().position(|byte| *byte == first) else {
            break;
        };
        let position = cursor + relative;
        if position + pattern.len() > bytes.len() {
            break;
        }
        if &bytes[position..position + pattern.len()] == pattern {
            found(position);
            count += 1;
        }
        cursor = position + 1;
    }
}

fn u16_le(bytes: &[u8], offset: usize) -> anyhow::Result<u16> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .context("ELF u16 field out of bounds")?
        .try_into()
        .expect("slice length checked");
    Ok(u16::from_le_bytes(raw))
}

fn u32_le(bytes: &[u8], offset: usize) -> anyhow::Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .context("ELF u32 field out of bounds")?
        .try_into()
        .expect("slice length checked");
    Ok(u32::from_le_bytes(raw))
}

fn u64_le(bytes: &[u8], offset: usize) -> anyhow::Result<u64> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .context("ELF u64 field out of bounds")?
        .try_into()
        .expect("slice length checked");
    Ok(u64::from_le_bytes(raw))
}

fn parse_additional_pair(value: &Value) -> anyhow::Result<(TlsOffsetPair, Vec<u8>, Vec<u8>)> {
    let string = |name: &str| -> anyhow::Result<&str> {
        value
            .get(name)
            .and_then(Value::as_str)
            .with_context(|| format!("TLS additional probe field {name} is missing"))
    };
    let integer = |name: &str| -> anyhow::Result<u64> {
        value
            .get(name)
            .and_then(Value::as_u64)
            .with_context(|| format!("TLS additional probe field {name} is missing"))
    };
    Ok((
        TlsOffsetPair {
            read_offset: integer("readOffset")?,
            write_offset: integer("writeOffset")?,
            read_abi: parse_abi(string("readAbi")?)?,
            write_abi: parse_abi(string("writeAbi")?)?,
        },
        decode_hex(string("readExpectedPrefixHex")?)?,
        decode_hex(string("writeExpectedPrefixHex")?)?,
    ))
}

fn parse_abi(value: &str) -> anyhow::Result<TlsAbi> {
    match value {
        "classic" => Ok(TlsAbi::Classic),
        "openssl_ex" => Ok(TlsAbi::OpenSslEx),
        "rustls_payload" => Ok(TlsAbi::RustlsPayload),
        "rustls_outbound_chunks" => Ok(TlsAbi::RustlsOutboundChunks),
        _ => anyhow::bail!("unsupported TLS ABI {value}"),
    }
}

fn decode_hex(value: &str) -> anyhow::Result<Vec<u8>> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    anyhow::ensure!(remainder.is_empty(), "hex string has odd length");
    pairs
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_profiles_collapse_into_tls_implementation_families() {
        let profiles = static_profiles().unwrap();
        assert_eq!(profiles.len(), 4);
        let families = static_signature_families().unwrap();
        assert_eq!(families.len(), 2);
        assert!(families.iter().all(|family| family.read_prefix.len() >= 12
            && family.write_prefix.len() >= 12
            && !family.write_after_read.is_empty()));
        let openssl = families
            .iter()
            .find(|family| family.read_abi == TlsAbi::OpenSslEx)
            .unwrap();
        assert_eq!(openssl.write_after_read, vec![592]);
        let classic = families
            .iter()
            .find(|family| family.read_abi == TlsAbi::Classic)
            .unwrap();
        assert_eq!(classic.write_after_read, vec![912, 1008]);
    }

    #[test]
    fn configured_local_cli_binaries_match_without_version_or_fingerprint() {
        let Some(candidates) = std::env::var_os("A3S_OBSERVER_TLS_TEST_BINARIES") else {
            return;
        };
        for path in candidates
            .to_string_lossy()
            .split(',')
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
        {
            assert!(
                !discover_static_signature_matches(&path).unwrap().is_empty(),
                "installed target did not match a TLS implementation family: {}",
                path.display()
            );
        }
    }

    #[test]
    fn bounded_stream_scanner_finds_anchors_across_chunk_boundaries() {
        let path = std::env::temp_dir().join(format!(
            "a3s-observer-static-scan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let pattern = b"stable-static-tls-anchor";
        let offset = STATIC_SCAN_CHUNK_BYTES - 7;
        let mut bytes = vec![0x90; STATIC_SCAN_CHUNK_BYTES + pattern.len() + 32];
        bytes[offset..offset + pattern.len()].copy_from_slice(pattern);
        fs::write(&path, &bytes).unwrap();
        let matches = find_pattern_offsets(
            &path,
            &[(0, bytes.len() as u64)],
            pattern,
            MAX_ANCHOR_MATCHES,
        )
        .unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(matches, vec![offset as u64]);
    }

    #[test]
    fn current_test_executable_has_bounded_executable_elf_ranges() {
        let path = std::env::current_exe().unwrap();
        let ranges = executable_file_ranges(&path).unwrap();
        assert!(!ranges.is_empty());
        assert!(ranges.iter().all(|(start, end)| start < end));
    }

    #[test]
    fn hex_decoder_rejects_invalid_input() {
        assert_eq!(decode_hex("00ff").unwrap(), vec![0, 255]);
        assert!(decode_hex("0").is_err());
        assert!(decode_hex("zz").is_err());
    }

    #[test]
    fn exact_pi_process_title_is_selected_without_broad_pi_substring_matching() {
        let patterns = vec!["run-pi-".to_string(), "pi-coding-agent".to_string()];
        assert!(matches_selected_agent_text(
            "mainthread",
            "pi   ",
            &patterns
        ));
        assert!(!matches_selected_agent_text(
            "python3",
            "python3 pillow_worker.py",
            &patterns
        ));
    }

    #[test]
    fn only_the_packaged_codex_network_runtime_signature_is_inherited() {
        assert!(matches_trusted_network_runtime_text(
            "codex-code-mode",
            "codex-code-mode-host"
        ));
        assert!(!matches_trusted_network_runtime_text("bash", "bash"));
        assert!(!matches_trusted_network_runtime_text("python3", "python3"));
    }
}
