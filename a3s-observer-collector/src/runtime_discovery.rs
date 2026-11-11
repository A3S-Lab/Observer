use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

const MAX_PROC_ENTRIES: usize = 262_144;
const MAX_HOME_ENTRIES: usize = 256;
const MAX_VERSION_ENTRIES: usize = 128;
const MAX_EXTENSION_ENTRIES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuntimeFileIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBinaryCandidate {
    /// A path that is readable from the Observer's mount namespace and resolves to the exact ELF
    /// inode to which the uprobe must attach.
    pub attach_path: PathBuf,
    /// The executable path as seen by the target process when it is available.
    pub logical_path: PathBuf,
    pub identity: RuntimeFileIdentity,
    pub pids: Vec<u32>,
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDiscoveryConfig {
    pub proc_root: PathBuf,
    pub host_root: PathBuf,
    pub binary_override: Option<PathBuf>,
    pub target_pids: Vec<u32>,
    pub auto_discover: bool,
}

impl RuntimeDiscoveryConfig {
    pub fn new(
        proc_root: PathBuf,
        host_root: PathBuf,
        binary_override: Option<PathBuf>,
        target_pids: Vec<u32>,
        auto_discover: bool,
    ) -> Self {
        Self {
            proc_root,
            host_root,
            binary_override,
            target_pids,
            auto_discover,
        }
    }
}

/// Discover the concrete native Codex ELF files, not the npm/node launcher. The result is
/// de-duplicated by `(st_dev, st_ino)`, which is also the identity used by Linux uprobes.
pub fn discover_codex_runtimes(
    config: &RuntimeDiscoveryConfig,
) -> anyhow::Result<Vec<RuntimeBinaryCandidate>> {
    let mut candidates = Vec::new();
    let mut identities = HashMap::new();
    let mut override_identity = None;

    if let Some(path) = config.binary_override.as_deref() {
        let candidate = candidate_from_path(path, path, Vec::new(), "configured_override")?;
        override_identity = Some(candidate.identity);
        insert_candidate(&mut candidates, &mut identities, candidate);
    }

    if config.auto_discover {
        discover_running_processes(config, &mut candidates, &mut identities);
        discover_installed_runtimes(config, &mut candidates, &mut identities);
    } else {
        for pid in &config.target_pids {
            let candidate = discover_codex_runtime_for_pid(config, *pid, true)?;
            if override_identity.is_some_and(|identity| identity != candidate.identity) {
                anyhow::bail!(
                    "runtime payload PID {pid} executable does not match A3S_OBSERVER_RUNTIME_BINARY override"
                );
            }
            insert_candidate(&mut candidates, &mut identities, candidate);
        }
    }

    if !config.target_pids.is_empty() {
        let expected = config.target_pids.iter().copied().collect::<HashSet<_>>();
        let observed = candidates
            .iter()
            .flat_map(|candidate| candidate.pids.iter().copied())
            .collect::<HashSet<_>>();
        let missing = expected.difference(&observed).copied().collect::<Vec<_>>();
        if !missing.is_empty() {
            anyhow::bail!(
                "could not resolve the executable for runtime payload target PIDs {missing:?}"
            );
        }
    }

    Ok(candidates)
}

/// Resolve one just-executed process. This fast path lets the collector attach a newly installed
/// or container-local Codex runtime without waiting for the periodic full reconciliation.
pub fn discover_codex_runtime_for_pid(
    config: &RuntimeDiscoveryConfig,
    pid: u32,
    exact_target: bool,
) -> anyhow::Result<RuntimeBinaryCandidate> {
    if pid == 0 || pid > i32::MAX as u32 {
        anyhow::bail!("runtime payload PID must be between 1 and {}", i32::MAX);
    }
    let process_dir = config.proc_root.join(pid.to_string());
    let exe_magic = process_dir.join("exe");
    let logical_path = fs::read_link(&exe_magic)
        .map_err(|error| anyhow::anyhow!("resolve {}: {error}", exe_magic.display()))?;
    let comm = fs::read_to_string(process_dir.join("comm")).unwrap_or_default();
    let cmdline = fs::read(process_dir.join("cmdline")).unwrap_or_default();
    if !exact_target && !looks_like_native_codex(&logical_path, &comm, &cmdline) {
        anyhow::bail!("PID {pid} is not a native Codex runtime");
    }

    let expected_identity = file_identity(&exe_magic)
        .map_err(|error| anyhow::anyhow!("stat {}: {error}", exe_magic.display()))?;
    let attach_path =
        accessible_process_path(config, pid, &logical_path, &exe_magic, expected_identity);
    let candidate = candidate_from_path(
        &attach_path,
        &logical_path,
        vec![pid],
        if exact_target {
            "exact_pid"
        } else {
            "running_process"
        },
    )?;
    if candidate.identity != expected_identity {
        anyhow::bail!(
            "runtime PID {pid} executable changed during discovery (possible PID reuse or upgrade)"
        );
    }
    Ok(candidate)
}

fn discover_running_processes(
    config: &RuntimeDiscoveryConfig,
    candidates: &mut Vec<RuntimeBinaryCandidate>,
    identities: &mut HashMap<RuntimeFileIdentity, usize>,
) {
    let Ok(entries) = fs::read_dir(&config.proc_root) else {
        return;
    };
    for entry in entries.filter_map(Result::ok).take(MAX_PROC_ENTRIES) {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        if let Ok(candidate) = discover_codex_runtime_for_pid(config, pid, false) {
            insert_candidate(candidates, identities, candidate);
        }
    }
}

fn discover_installed_runtimes(
    config: &RuntimeDiscoveryConfig,
    candidates: &mut Vec<RuntimeBinaryCandidate>,
    identities: &mut HashMap<RuntimeFileIdentity, usize>,
) {
    let homes = discover_host_homes(&config.host_root);
    for home in homes.iter().take(MAX_HOME_ENTRIES) {
        discover_nvm_runtimes(home, candidates, identities);
        discover_vscode_runtimes(home, candidates, identities);
        for relative in [
            ".npm-global/lib/node_modules/@openai/codex",
            ".local/lib/node_modules/@openai/codex",
        ] {
            discover_npm_package_runtime(&home.join(relative), candidates, identities);
        }
    }
    for relative in [
        "usr/local/lib/node_modules/@openai/codex",
        "usr/lib/node_modules/@openai/codex",
    ] {
        discover_npm_package_runtime(&config.host_root.join(relative), candidates, identities);
    }
}

fn discover_host_homes(host_root: &Path) -> Vec<PathBuf> {
    let mut homes = Vec::new();
    if let Ok(passwd) = fs::read_to_string(host_root.join("etc/passwd")) {
        for line in passwd.lines().take(16_384) {
            let fields = line.split(':').collect::<Vec<_>>();
            let Some(home) = fields.get(5).filter(|value| value.starts_with('/')) else {
                continue;
            };
            let accessible = host_path(host_root, Path::new(home));
            if accessible.is_dir() && !homes.contains(&accessible) {
                homes.push(accessible);
            }
        }
    }
    // Enterprise/NSS users frequently have no literal /etc/passwd row. Always enumerate
    // /home as well, rather than treating passwd as a complete source of local identities.
    let home_root = host_root.join("home");
    if let Ok(entries) = fs::read_dir(home_root) {
        for entry in entries.filter_map(Result::ok).take(MAX_HOME_ENTRIES) {
            if entry.path().is_dir() && !homes.contains(&entry.path()) {
                homes.push(entry.path());
            }
        }
    }
    let root_home = host_root.join("root");
    if root_home.is_dir() && !homes.contains(&root_home) {
        homes.push(root_home);
    }
    homes
}

fn discover_nvm_runtimes(
    home: &Path,
    candidates: &mut Vec<RuntimeBinaryCandidate>,
    identities: &mut HashMap<RuntimeFileIdentity, usize>,
) {
    let versions = home.join(".nvm/versions/node");
    let Ok(entries) = fs::read_dir(versions) else {
        return;
    };
    for entry in entries.filter_map(Result::ok).take(MAX_VERSION_ENTRIES) {
        discover_npm_package_runtime(
            &entry.path().join("lib/node_modules/@openai/codex"),
            candidates,
            identities,
        );
    }
}

fn discover_npm_package_runtime(
    package_root: &Path,
    candidates: &mut Vec<RuntimeBinaryCandidate>,
    identities: &mut HashMap<RuntimeFileIdentity, usize>,
) {
    let scope = package_root.join("node_modules/@openai");
    for (package, target) in [
        ("codex-linux-x64", "x86_64-unknown-linux-musl"),
        ("codex-linux-arm64", "aarch64-unknown-linux-musl"),
    ] {
        let path = scope
            .join(package)
            .join("vendor")
            .join(target)
            .join("bin/codex");
        if let Ok(candidate) = candidate_from_path(&path, &path, Vec::new(), "host_inventory") {
            insert_candidate(candidates, identities, candidate);
        }
    }
}

fn discover_vscode_runtimes(
    home: &Path,
    candidates: &mut Vec<RuntimeBinaryCandidate>,
    identities: &mut HashMap<RuntimeFileIdentity, usize>,
) {
    for extension_root in [".vscode/extensions", ".vscode-server/extensions"] {
        let Ok(entries) = fs::read_dir(home.join(extension_root)) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok).take(MAX_EXTENSION_ENTRIES) {
            let name = entry.file_name();
            if !name.to_string_lossy().starts_with("openai.chatgpt-") {
                continue;
            }
            for platform in ["linux-x86_64", "linux-aarch64"] {
                let path = entry.path().join("bin").join(platform).join("codex");
                if let Ok(candidate) =
                    candidate_from_path(&path, &path, Vec::new(), "host_inventory")
                {
                    insert_candidate(candidates, identities, candidate);
                }
            }
        }
    }
}

fn accessible_process_path(
    config: &RuntimeDiscoveryConfig,
    pid: u32,
    logical_path: &Path,
    exe_magic: &Path,
    expected: RuntimeFileIdentity,
) -> PathBuf {
    if logical_path.is_absolute() && !logical_path.to_string_lossy().ends_with(" (deleted)") {
        // A host-root path is stable after this PID exits, so prefer it when it resolves to the
        // executing inode. For another container's mount namespace, /proc/<pid>/root is correct.
        for candidate in [
            host_path(&config.host_root, logical_path),
            config
                .proc_root
                .join(pid.to_string())
                .join("root")
                .join(logical_path.strip_prefix("/").unwrap_or(logical_path)),
        ] {
            if file_identity(&candidate).ok() == Some(expected) {
                return candidate;
            }
        }
    }
    exe_magic.to_path_buf()
}

fn looks_like_native_codex(logical_path: &Path, comm: &str, cmdline: &[u8]) -> bool {
    let filename = logical_path.file_name().and_then(|value| value.to_str());
    let comm = comm.trim();
    if matches!(
        filename,
        Some("codex-linux-sandbox" | "codex-code-mode-host")
    ) || matches!(comm, "codex-linux-san" | "codex-code-mode-")
        || contains_bytes(cmdline, b"--codex-run-as-fs-helper")
        || contains_bytes(cmdline, b"codex-linux-sandbox")
        || contains_bytes(cmdline, b"codex-code-mode-host")
    {
        return false;
    }
    filename == Some("codex") || comm == "codex"
}

/// Match A3S Code runtimes the same way AnySentry local-record / agent signatures do.
fn looks_like_a3s_code(logical_path: &Path, comm: &str, cmdline: &[u8]) -> bool {
    let filename = logical_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let comm = comm.trim().to_ascii_lowercase();
    if filename == "a3s-code" || comm == "a3s-code" {
        return true;
    }
    if comm == "tokio-rt-worker" && filename == "a3s" {
        return true;
    }
    if filename != "a3s" && comm != "a3s" {
        return false;
    }
    // Prefer `a3s code ...`; bare admin subcommands should not be treated as the coding runtime.
    let argv1 = cmdline
        .split(|byte| *byte == 0)
        .nth(1)
        .and_then(|value| std::str::from_utf8(value).ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    argv1 == "code"
}

/// Discover native A3S Code ELF candidates for OpenSSL plaintext attach.
pub fn discover_a3s_runtimes(
    config: &RuntimeDiscoveryConfig,
) -> anyhow::Result<Vec<RuntimeBinaryCandidate>> {
    let mut candidates = Vec::new();
    let mut identities = HashMap::new();
    if let Some(path) = config.binary_override.as_deref() {
        insert_candidate(
            &mut candidates,
            &mut identities,
            candidate_from_path(path, path, Vec::new(), "a3s_configured_override")?,
        );
    }
    if config.auto_discover {
        let Ok(entries) = fs::read_dir(&config.proc_root) else {
            return Ok(candidates);
        };
        for entry in entries.filter_map(Result::ok).take(MAX_PROC_ENTRIES) {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<u32>().ok())
            else {
                continue;
            };
            if let Ok(candidate) = discover_a3s_runtime_for_pid(config, pid, false) {
                insert_candidate(&mut candidates, &mut identities, candidate);
            }
        }
        for relative in [
            "home/zhongyule/.local/bin/a3s",
            "usr/local/bin/a3s",
            "usr/bin/a3s",
        ] {
            let attach_path = config.host_root.join(relative);
            let logical = PathBuf::from("/").join(relative);
            if attach_path.is_file() {
                if let Ok(candidate) =
                    candidate_from_path(&attach_path, &logical, Vec::new(), "a3s_inventory")
                {
                    insert_candidate(&mut candidates, &mut identities, candidate);
                }
            }
        }
    } else {
        for pid in &config.target_pids {
            insert_candidate(
                &mut candidates,
                &mut identities,
                discover_a3s_runtime_for_pid(config, *pid, true)?,
            );
        }
    }
    Ok(candidates)
}

pub fn discover_a3s_runtime_for_pid(
    config: &RuntimeDiscoveryConfig,
    pid: u32,
    exact_target: bool,
) -> anyhow::Result<RuntimeBinaryCandidate> {
    if pid == 0 || pid > i32::MAX as u32 {
        anyhow::bail!("runtime payload PID must be between 1 and {}", i32::MAX);
    }
    let process_dir = config.proc_root.join(pid.to_string());
    let exe_magic = process_dir.join("exe");
    let logical_path = fs::read_link(&exe_magic)
        .map_err(|error| anyhow::anyhow!("resolve {}: {error}", exe_magic.display()))?;
    let comm = fs::read_to_string(process_dir.join("comm")).unwrap_or_default();
    let cmdline = fs::read(process_dir.join("cmdline")).unwrap_or_default();
    if !exact_target && !looks_like_a3s_code(&logical_path, &comm, &cmdline) {
        anyhow::bail!("PID {pid} is not an A3S Code runtime");
    }
    let expected_identity = file_identity(&exe_magic)
        .map_err(|error| anyhow::anyhow!("stat {}: {error}", exe_magic.display()))?;
    let attach_path =
        accessible_process_path(config, pid, &logical_path, &exe_magic, expected_identity);
    let candidate = candidate_from_path(
        &attach_path,
        &logical_path,
        vec![pid],
        if exact_target {
            "a3s_exact_pid"
        } else {
            "a3s_running_process"
        },
    )?;
    if candidate.identity != expected_identity {
        anyhow::bail!(
            "runtime PID {pid} executable changed during discovery (possible PID reuse or upgrade)"
        );
    }
    Ok(candidate)
}

fn looks_like_claude_code(logical_path: &Path, comm: &str, cmdline: &[u8]) -> bool {
    let filename = logical_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let comm = comm.trim().to_ascii_lowercase();
    filename == "claude"
        || filename == "claude.exe"
        || comm == "claude"
        || contains_bytes(cmdline, b"@anthropic-ai/claude-code/bin/claude")
}

pub fn discover_claude_runtimes(
    config: &RuntimeDiscoveryConfig,
) -> anyhow::Result<Vec<RuntimeBinaryCandidate>> {
    let mut candidates = Vec::new();
    let mut identities = HashMap::new();
    if config.auto_discover {
        let Ok(entries) = fs::read_dir(&config.proc_root) else {
            return Ok(candidates);
        };
        for entry in entries.filter_map(Result::ok).take(MAX_PROC_ENTRIES) {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|value| value.parse().ok())
            else {
                continue;
            };
            if let Ok(candidate) = discover_claude_runtime_for_pid(config, pid, false) {
                insert_candidate(&mut candidates, &mut identities, candidate);
            }
        }
        for home in discover_host_homes(&config.host_root)
            .iter()
            .take(MAX_HOME_ENTRIES)
        {
            let nvm = home.join(".nvm/versions/node");
            if let Ok(entries) = fs::read_dir(nvm) {
                for entry in entries.filter_map(Result::ok).take(MAX_VERSION_ENTRIES) {
                    let path = entry
                        .path()
                        .join("lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe");
                    if let Ok(candidate) =
                        candidate_from_path(&path, &path, Vec::new(), "claude_host_inventory")
                    {
                        insert_candidate(&mut candidates, &mut identities, candidate);
                    }
                }
            }
            for relative in [
                ".local/share/claude/versions",
                ".local/lib/node_modules/@anthropic-ai/claude-code/bin",
            ] {
                let directory = home.join(relative);
                if let Ok(entries) = fs::read_dir(directory) {
                    for entry in entries.filter_map(Result::ok).take(MAX_VERSION_ENTRIES) {
                        let path = entry.path();
                        if let Ok(candidate) =
                            candidate_from_path(&path, &path, Vec::new(), "claude_host_inventory")
                        {
                            insert_candidate(&mut candidates, &mut identities, candidate);
                        }
                    }
                }
            }
        }
    } else {
        for pid in &config.target_pids {
            insert_candidate(
                &mut candidates,
                &mut identities,
                discover_claude_runtime_for_pid(config, *pid, true)?,
            );
        }
    }
    Ok(candidates)
}

pub fn discover_claude_runtime_for_pid(
    config: &RuntimeDiscoveryConfig,
    pid: u32,
    exact_target: bool,
) -> anyhow::Result<RuntimeBinaryCandidate> {
    if pid == 0 || pid > i32::MAX as u32 {
        anyhow::bail!("runtime payload PID must be between 1 and {}", i32::MAX);
    }
    let process_dir = config.proc_root.join(pid.to_string());
    let exe_magic = process_dir.join("exe");
    let logical_path = fs::read_link(&exe_magic)
        .map_err(|error| anyhow::anyhow!("resolve {}: {error}", exe_magic.display()))?;
    let comm = fs::read_to_string(process_dir.join("comm")).unwrap_or_default();
    let cmdline = fs::read(process_dir.join("cmdline")).unwrap_or_default();
    if !exact_target && !looks_like_claude_code(&logical_path, &comm, &cmdline) {
        anyhow::bail!("PID {pid} is not a Claude Code runtime");
    }
    let expected_identity = file_identity(&exe_magic)
        .map_err(|error| anyhow::anyhow!("stat {}: {error}", exe_magic.display()))?;
    let attach_path =
        accessible_process_path(config, pid, &logical_path, &exe_magic, expected_identity);
    let candidate = candidate_from_path(
        &attach_path,
        &logical_path,
        vec![pid],
        if exact_target {
            "claude_exact_pid"
        } else {
            "claude_running_process"
        },
    )?;
    if candidate.identity != expected_identity {
        anyhow::bail!("runtime PID {pid} executable changed during Claude discovery");
    }
    Ok(candidate)
}

/// kimi-code ships as a static Node.js single-executable application installed as
/// `~/.kimi-code/bin/kimi`; containers may exec it through a `/usr/local/bin/kimi` symlink to a
/// mounted inode. Match only the exact `kimi` filename/comm so unrelated processes whose names
/// merely contain the substring stay out of the plaintext lane.
fn looks_like_kimi_code(logical_path: &Path, comm: &str) -> bool {
    let filename = logical_path.file_name().and_then(|value| value.to_str());
    filename == Some("kimi") || comm.trim() == "kimi"
}

/// Discover kimi CLI binaries for OpenSSL plaintext attach.
pub fn discover_kimi_runtimes(
    config: &RuntimeDiscoveryConfig,
) -> anyhow::Result<Vec<RuntimeBinaryCandidate>> {
    let mut candidates = Vec::new();
    let mut identities = HashMap::new();
    if config.auto_discover {
        let Ok(entries) = fs::read_dir(&config.proc_root) else {
            return Ok(candidates);
        };
        for entry in entries.filter_map(Result::ok).take(MAX_PROC_ENTRIES) {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|value| value.parse().ok())
            else {
                continue;
            };
            if let Ok(candidate) = discover_kimi_runtime_for_pid(config, pid, false) {
                insert_candidate(&mut candidates, &mut identities, candidate);
            }
        }
        for home in discover_host_homes(&config.host_root)
            .iter()
            .take(MAX_HOME_ENTRIES)
        {
            let path = home.join(".kimi-code/bin/kimi");
            if let Ok(candidate) =
                candidate_from_path(&path, &path, Vec::new(), "kimi_host_inventory")
            {
                insert_candidate(&mut candidates, &mut identities, candidate);
            }
        }
        let attach_path = config.host_root.join("usr/local/bin/kimi");
        let logical = PathBuf::from("/usr/local/bin/kimi");
        if let Ok(candidate) =
            candidate_from_path(&attach_path, &logical, Vec::new(), "kimi_host_inventory")
        {
            insert_candidate(&mut candidates, &mut identities, candidate);
        }
    } else {
        for pid in &config.target_pids {
            insert_candidate(
                &mut candidates,
                &mut identities,
                discover_kimi_runtime_for_pid(config, *pid, true)?,
            );
        }
    }
    Ok(candidates)
}

pub fn discover_kimi_runtime_for_pid(
    config: &RuntimeDiscoveryConfig,
    pid: u32,
    exact_target: bool,
) -> anyhow::Result<RuntimeBinaryCandidate> {
    if pid == 0 || pid > i32::MAX as u32 {
        anyhow::bail!("runtime payload PID must be between 1 and {}", i32::MAX);
    }
    let process_dir = config.proc_root.join(pid.to_string());
    let exe_magic = process_dir.join("exe");
    let logical_path = fs::read_link(&exe_magic)
        .map_err(|error| anyhow::anyhow!("resolve {}: {error}", exe_magic.display()))?;
    let comm = fs::read_to_string(process_dir.join("comm")).unwrap_or_default();
    if !exact_target && !looks_like_kimi_code(&logical_path, &comm) {
        anyhow::bail!("PID {pid} is not a kimi runtime");
    }
    let expected_identity = file_identity(&exe_magic)
        .map_err(|error| anyhow::anyhow!("stat {}: {error}", exe_magic.display()))?;
    let attach_path =
        accessible_process_path(config, pid, &logical_path, &exe_magic, expected_identity);
    let candidate = candidate_from_path(
        &attach_path,
        &logical_path,
        vec![pid],
        if exact_target {
            "kimi_exact_pid"
        } else {
            "kimi_running_process"
        },
    )?;
    if candidate.identity != expected_identity {
        anyhow::bail!(
            "runtime PID {pid} executable changed during kimi discovery (possible PID reuse or upgrade)"
        );
    }
    Ok(candidate)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn candidate_from_path(
    attach_path: &Path,
    logical_path: &Path,
    pids: Vec<u32>,
    source: &'static str,
) -> anyhow::Result<RuntimeBinaryCandidate> {
    let metadata = fs::metadata(attach_path).map_err(|error| {
        anyhow::anyhow!("stat runtime candidate {}: {error}", attach_path.display())
    })?;
    if !metadata.is_file() {
        anyhow::bail!(
            "runtime candidate is not a regular file: {}",
            attach_path.display()
        );
    }
    Ok(RuntimeBinaryCandidate {
        attach_path: attach_path.to_path_buf(),
        logical_path: logical_path.to_path_buf(),
        identity: RuntimeFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        pids,
        source,
    })
}

fn file_identity(path: &Path) -> std::io::Result<RuntimeFileIdentity> {
    let metadata = fs::metadata(path)?;
    Ok(RuntimeFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn insert_candidate(
    candidates: &mut Vec<RuntimeBinaryCandidate>,
    identities: &mut HashMap<RuntimeFileIdentity, usize>,
    mut candidate: RuntimeBinaryCandidate,
) {
    if let Some(index) = identities.get(&candidate.identity).copied() {
        let existing = &mut candidates[index];
        for pid in candidate.pids.drain(..) {
            if !existing.pids.contains(&pid) {
                existing.pids.push(pid);
            }
        }
        // Prefer a stable inventory/override path over a PID magic link for a global uprobe.
        if existing.attach_path.starts_with("/proc") && !candidate.attach_path.starts_with("/proc")
        {
            existing.attach_path = candidate.attach_path;
            existing.logical_path = candidate.logical_path;
            existing.source = candidate.source;
        }
        return;
    }
    identities.insert(candidate.identity, candidates.len());
    candidates.push(candidate);
}

fn host_path(host_root: &Path, logical_path: &Path) -> PathBuf {
    host_root.join(logical_path.strip_prefix("/").unwrap_or(logical_path))
}

#[cfg(test)]
mod tests {
    use super::{
        discover_codex_runtime_for_pid, discover_codex_runtimes, discover_kimi_runtime_for_pid,
        discover_kimi_runtimes, looks_like_kimi_code, looks_like_native_codex,
        RuntimeDiscoveryConfig,
    };
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestTree(PathBuf);

    impl TestTree {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "a3s-runtime-discovery-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create test tree");
            Self(path)
        }
    }

    impl Drop for TestTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_elf(path: &Path) {
        fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        fs::write(path, b"\x7fELFtest-runtime").expect("write fake ELF");
    }

    #[test]
    fn identifies_native_codex_but_excludes_helpers_and_node_launcher() {
        assert!(looks_like_native_codex(
            Path::new("/opt/codex"),
            "codex\n",
            b"/opt/codex\0resume\0"
        ));
        assert!(!looks_like_native_codex(
            Path::new("/usr/bin/node"),
            "node\n",
            b"node\0/usr/bin/codex\0"
        ));
        assert!(!looks_like_native_codex(
            Path::new("/opt/codex-linux-sandbox"),
            "codex-linux-san\n",
            b"/opt/codex-linux-sandbox\0"
        ));
        assert!(!looks_like_native_codex(
            Path::new("/opt/codex"),
            "codex\n",
            b"codex-linux-sandbox\0--sandbox-policy-cwd\0/tmp\0"
        ));
    }

    #[test]
    fn resolves_exact_pid_from_proc_without_a_configured_binary() {
        let tree = TestTree::new("pid");
        let proc_root = tree.0.join("proc");
        let runtime = tree.0.join("runtime/codex");
        write_elf(&runtime);
        fs::create_dir_all(proc_root.join("42")).expect("pid dir");
        symlink(&runtime, proc_root.join("42/exe")).expect("exe symlink");
        fs::write(proc_root.join("42/comm"), "codex\n").expect("comm");
        fs::write(proc_root.join("42/cmdline"), b"codex\0resume\0").expect("cmdline");

        let config =
            RuntimeDiscoveryConfig::new(proc_root, tree.0.join("host"), None, vec![42], false);
        let candidate = discover_codex_runtime_for_pid(&config, 42, true).expect("candidate");
        assert_eq!(candidate.pids, [42]);
        assert_eq!(candidate.attach_path, config.proc_root.join("42/exe"));
    }

    #[test]
    fn inventories_nvm_native_runtime_and_deduplicates_running_inode() {
        let tree = TestTree::new("inventory");
        let host_root = tree.0.join("host");
        let proc_root = tree.0.join("proc");
        let logical = Path::new(
            "/home/alice/.nvm/versions/node/v22/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex",
        );
        let runtime = host_root.join(logical.strip_prefix("/").expect("absolute"));
        write_elf(&runtime);
        fs::create_dir_all(host_root.join("etc")).expect("etc");
        fs::write(
            host_root.join("etc/passwd"),
            "alice:x:1000:1000::/home/alice:/bin/bash\n",
        )
        .expect("passwd");

        // Inventory alone must be sufficient so Observer may start before Codex.
        fs::create_dir_all(&proc_root).expect("proc");
        let config = RuntimeDiscoveryConfig::new(proc_root, host_root, None, Vec::new(), true);
        let candidates = discover_codex_runtimes(&config).expect("discover");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].attach_path, runtime);
        assert!(candidates[0].pids.is_empty());
        assert_eq!(candidates[0].source, "host_inventory");
    }

    #[test]
    fn identifies_kimi_but_excludes_unrelated_processes() {
        assert!(looks_like_kimi_code(
            Path::new("/home/alice/.kimi-code/bin/kimi"),
            "kimi\n"
        ));
        // Containers may exec the CLI through a symlink; the resolved exe still ends in `kimi`.
        assert!(looks_like_kimi_code(
            Path::new("/usr/local/bin/kimi"),
            "kimi\n"
        ));
        assert!(looks_like_kimi_code(
            Path::new("/mnt/runtime/bin/kimi"),
            "kimi\n"
        ));
        assert!(!looks_like_kimi_code(
            Path::new("/usr/bin/kimi-agent"),
            "kimi-agent\n"
        ));
        assert!(!looks_like_kimi_code(Path::new("/usr/bin/node"), "node\n"));
        assert!(!looks_like_kimi_code(
            Path::new("/opt/kimitool/run"),
            "run\n"
        ));
    }

    #[test]
    fn inventories_kimi_host_install_and_resolves_exact_pid() {
        let tree = TestTree::new("kimi");
        let host_root = tree.0.join("host");
        let proc_root = tree.0.join("proc");
        let runtime = host_root.join("home/alice/.kimi-code/bin/kimi");
        write_elf(&runtime);
        fs::create_dir_all(host_root.join("etc")).expect("etc");
        fs::write(
            host_root.join("etc/passwd"),
            "alice:x:1000:1000::/home/alice:/bin/bash\n",
        )
        .expect("passwd");

        // Inventory alone must be sufficient so Observer may start before kimi.
        fs::create_dir_all(&proc_root).expect("proc");
        let config = RuntimeDiscoveryConfig::new(
            proc_root.clone(),
            host_root.clone(),
            None,
            Vec::new(),
            true,
        );
        let candidates = discover_kimi_runtimes(&config).expect("discover");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].attach_path, runtime);
        assert!(candidates[0].pids.is_empty());
        assert_eq!(candidates[0].source, "kimi_host_inventory");

        // A running kimi process resolves through its /proc exe link with the kimi source prefix.
        fs::create_dir_all(proc_root.join("43")).expect("pid dir");
        symlink(&runtime, proc_root.join("43/exe")).expect("exe symlink");
        fs::write(proc_root.join("43/comm"), "kimi\n").expect("comm");
        fs::write(proc_root.join("43/cmdline"), b"kimi\0chat\0").expect("cmdline");
        let config =
            RuntimeDiscoveryConfig::new(proc_root.clone(), host_root, None, vec![43], false);
        let candidate = discover_kimi_runtime_for_pid(&config, 43, true).expect("candidate");
        assert_eq!(candidate.pids, [43]);
        assert_eq!(candidate.source, "kimi_exact_pid");
    }
}
