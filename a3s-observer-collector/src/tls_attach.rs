//! Runtime TLS-library and static executable discovery for selected Agent processes.
//!
//! Discovery is deliberately fail-closed: exported symbols are safe to resolve by name; stripped
//! static binaries require an exact whole-file fingerprint plus expected instruction prefixes.

use anyhow::Context as _;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const PROFILE_DOCUMENT: &str = include_str!("tls-profiles.json");
const HASH_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsAbi {
    Classic,
    OpenSslEx,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolFamily {
    OpenSsl,
    GnuTls,
    Nss,
}

#[derive(Clone, Debug)]
pub enum TlsAttachKind {
    Symbols(SymbolFamily),
    Offsets {
        read_offset: u64,
        write_offset: u64,
        read_abi: TlsAbi,
        write_abi: TlsAbi,
    },
}

#[derive(Clone, Debug)]
pub struct TlsAttachPlan {
    pub key: String,
    pub pid: Option<i32>,
    pub path: PathBuf,
    pub product: String,
    pub transport_scope: String,
    pub excluded_transport_scope: Option<String>,
    pub kind: TlsAttachKind,
}

#[derive(Clone, Debug)]
struct StaticProfile {
    product: String,
    version: String,
    file_size: u64,
    head64k_sha256: String,
    whole_file_sha256: String,
    transport_scope: String,
    excluded_transport_scope: Option<String>,
    read_offset: u64,
    read_prefix: Vec<u8>,
    write_offset: u64,
    write_prefix: Vec<u8>,
    read_abi: TlsAbi,
    write_abi: TlsAbi,
}

#[derive(Debug)]
pub struct TlsAttachManager {
    attached: HashSet<String>,
    rejected: HashSet<String>,
    plaintext_pids: HashSet<i32>,
    static_profile_cache: HashMap<(u64, u64), Option<StaticProfile>>,
    process_patterns: Vec<String>,
    explicit_target: Option<PathBuf>,
}

impl TlsAttachManager {
    pub fn from_env(ssl_setting: &str) -> Self {
        let mut process_patterns = vec![
            "codex".to_string(),
            "claude".to_string(),
            "dify-plugin-daemon".to_string(),
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
        Self {
            attached: HashSet::new(),
            rejected: HashSet::new(),
            plaintext_pids: HashSet::new(),
            static_profile_cache: HashMap::new(),
            process_patterns,
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

        let Ok(proc_entries) = fs::read_dir("/proc") else {
            return plans;
        };
        for entry in proc_entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<i32>().ok())
            else {
                continue;
            };
            if !self.is_selected_agent_process(pid) {
                continue;
            }
            plans.extend(self.plans_for_process(pid));
        }
        plans.retain(|plan| !self.attached.contains(&plan.key));
        plans
    }

    pub fn mark_attached(&mut self, key: String, pid: Option<i32>) {
        self.attached.insert(key);
        if let Some(pid) = pid {
            self.plaintext_pids.insert(pid);
        }
    }

    pub fn mark_rejected(&mut self, key: String, reason: &str) {
        if self.rejected.insert(key.clone()) {
            tracing::warn!(target = %key, reason, "TLS target rejected; plaintext capture remains unavailable");
        }
    }

    pub fn attached_count(&self) -> usize {
        self.attached.len()
    }

    pub fn plaintext_pids(&mut self) -> Vec<i32> {
        self.plaintext_pids
            .retain(|pid| Path::new(&format!("/proc/{pid}")).exists());
        self.plaintext_pids.iter().copied().collect()
    }

    fn is_selected_agent_process(&self, pid: i32) -> bool {
        if self.process_matches_patterns(pid) {
            return true;
        }
        let mut current = pid;
        for _ in 0..6 {
            if current <= 1 {
                break;
            }
            // Only Dify's provider-host ancestry is inherited. Treating every descendant of a
            // Codex/Claude/Pi process as a TLS Agent made ordinary tool subprocesses enter the
            // expensive resolver and could starve short-lived CLI attachment scans.
            if process_contains_pattern(current, "dify-plugin-daemon") {
                return true;
            }
            let Some(parent) = process_parent_pid(current) else {
                break;
            };
            if parent == current {
                break;
            }
            current = parent;
        }
        false
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

    fn plans_for_process(&mut self, pid: i32) -> Vec<TlsAttachPlan> {
        let mut plans = Vec::new();
        let exe_probe_path = PathBuf::from(format!("/proc/{pid}/exe"));
        if let Ok(real_exe) = fs::read_link(&exe_probe_path) {
            if let Some(plan) = self.plan_for_executable(pid, &exe_probe_path, &real_exe) {
                plans.push(plan);
            }
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
                transport_scope: format!("{family:?}").to_ascii_lowercase(),
                excluded_transport_scope: None,
                kind: TlsAttachKind::Symbols(family),
            });
        }
        plans
    }

    fn plan_for_executable(
        &mut self,
        pid: i32,
        probe_path: &Path,
        real_exe: &Path,
    ) -> Option<TlsAttachPlan> {
        let metadata = fs::metadata(probe_path).ok()?;
        let basename = real_exe.file_name()?.to_string_lossy().to_ascii_lowercase();
        let identity = format!("pid:{pid}:dev:{}:ino:{}", metadata.dev(), metadata.ino());
        if self.attached.iter().any(|key| key.starts_with(&identity))
            || self.rejected.iter().any(|key| key.starts_with(&identity))
        {
            return None;
        }

        let cache_key = (metadata.dev(), metadata.ino());
        let static_profile = if let Some(cached) = self.static_profile_cache.get(&cache_key) {
            cached.clone()
        } else {
            match match_static_profile(probe_path) {
                Ok(profile) => {
                    self.static_profile_cache.insert(cache_key, profile.clone());
                    profile
                }
                Err(error) => {
                    self.mark_rejected(
                        format!("{identity}:{basename}"),
                        &format!("fingerprint_validation_failed:{error}"),
                    );
                    return None;
                }
            }
        };
        if let Some(profile) = static_profile {
            return Some(TlsAttachPlan {
                key: format!("{identity}:profile:{}:{}", profile.product, profile.version),
                pid: Some(pid),
                path: probe_path.to_path_buf(),
                product: format!("{} {}", profile.product, profile.version),
                transport_scope: profile.transport_scope,
                excluded_transport_scope: profile.excluded_transport_scope,
                kind: TlsAttachKind::Offsets {
                    read_offset: profile.read_offset,
                    write_offset: profile.write_offset,
                    read_abi: profile.read_abi,
                    write_abi: profile.write_abi,
                },
            });
        }

        // Node and versioned Python executables commonly export OpenSSL symbols from the main ELF
        // even when no separate libssl mapping exists. Symbol resolution is exact and needs no
        // static offset guess.
        if matches!(basename.as_str(), "node" | "nodejs")
            || basename.starts_with("python3.")
            || basename == "python"
        {
            return Some(TlsAttachPlan {
                key: format!("{identity}:main-exported-openssl"),
                pid: Some(pid),
                path: probe_path.to_path_buf(),
                product: format!("{basename}-main-elf"),
                transport_scope: "main-executable-exported-openssl".to_string(),
                excluded_transport_scope: None,
                kind: TlsAttachKind::Symbols(SymbolFamily::OpenSsl),
            });
        }

        if basename.starts_with("codex") || basename.starts_with("claude") {
            self.mark_rejected(
                format!("{identity}:{basename}"),
                "unsupported_binary_fingerprint",
            );
        }
        None
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
            transport_scope: format!("{family:?}").to_ascii_lowercase(),
            excluded_transport_scope: None,
            kind: TlsAttachKind::Symbols(family),
        })
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

fn match_static_profile(path: &Path) -> anyhow::Result<Option<StaticProfile>> {
    let metadata = fs::metadata(path)?;
    let head_hash = hash_prefix(path, 64 * 1024)?;
    for profile in static_profiles()? {
        if metadata.len() != profile.file_size || head_hash != profile.head64k_sha256 {
            continue;
        }
        let whole_hash = hash_file(path)?;
        anyhow::ensure!(
            whole_hash == profile.whole_file_sha256,
            "whole_file_sha256_mismatch"
        );
        verify_prefix(path, profile.read_offset, &profile.read_prefix)
            .context("read_prefix_mismatch")?;
        verify_prefix(path, profile.write_offset, &profile.write_prefix)
            .context("write_prefix_mismatch")?;
        return Ok(Some(profile.clone()));
    }
    Ok(None)
}

fn static_profiles() -> anyhow::Result<Vec<StaticProfile>> {
    let root: Value = serde_json::from_str(PROFILE_DOCUMENT)?;
    let profiles = root
        .get("profiles")
        .and_then(Value::as_array)
        .context("TLS profile document has no profiles")?;
    profiles.iter().map(parse_profile).collect()
}

fn parse_profile(value: &Value) -> anyhow::Result<StaticProfile> {
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
    Ok(StaticProfile {
        product: string("product")?,
        version: string("version")?,
        file_size: integer("fileSize")?,
        head64k_sha256: string("head64kSha256")?,
        whole_file_sha256: string("wholeFileSha256")?,
        transport_scope: string("transportScope")?,
        excluded_transport_scope: value
            .get("excludedTransportScope")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        read_offset: integer("readOffset")?,
        read_prefix: decode_hex(&string("readExpectedPrefixHex")?)?,
        write_offset: integer("writeOffset")?,
        write_prefix: decode_hex(&string("writeExpectedPrefixHex")?)?,
        read_abi: parse_abi(&string("readAbi")?)?,
        write_abi: parse_abi(&string("writeAbi")?)?,
    })
}

fn parse_abi(value: &str) -> anyhow::Result<TlsAbi> {
    match value {
        "classic" => Ok(TlsAbi::Classic),
        "openssl_ex" => Ok(TlsAbi::OpenSslEx),
        _ => anyhow::bail!("unsupported TLS ABI {value}"),
    }
}

fn hash_prefix(path: &Path, limit: usize) -> anyhow::Result<String> {
    let mut file = File::open(path)?;
    let mut bytes = vec![0u8; limit];
    let read = file.read(&mut bytes)?;
    bytes.truncate(read);
    Ok(hex(&Sha256::digest(bytes)))
}

fn hash_file(path: &Path) -> anyhow::Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; HASH_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(hex(&hash.finalize()))
}

fn verify_prefix(path: &Path, offset: u64, expected: &[u8]) -> anyhow::Result<()> {
    use std::io::{Seek, SeekFrom};
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut actual = vec![0u8; expected.len()];
    file.read_exact(&mut actual)?;
    anyhow::ensure!(actual == expected, "instruction prefix differs");
    Ok(())
}

fn decode_hex(value: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(value.len() % 2 == 0, "hex string has odd length");
    value
        .as_bytes()
        .chunks_exact(2)
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
    fn embedded_profiles_are_complete_and_have_distinct_fingerprints() {
        let profiles = static_profiles().unwrap();
        assert_eq!(profiles.len(), 2);
        assert_ne!(profiles[0].whole_file_sha256, profiles[1].whole_file_sha256);
        assert!(profiles.iter().all(|profile| {
            !profile.read_prefix.is_empty()
                && !profile.write_prefix.is_empty()
                && profile.read_offset != profile.write_offset
        }));
    }

    #[test]
    fn exact_local_cli_profiles_match_when_installed() {
        let candidates = [
            std::env::var("HOME")
                .ok()
                .map(|home| {
                    PathBuf::from(home).join(
                        ".nvm/versions/node/v24.16.0/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe",
                    )
                }),
            std::env::var("HOME").ok().map(|home| {
                PathBuf::from(home).join(
                    ".nvm/versions/node/v24.16.0/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex",
                )
            }),
        ];
        for path in candidates
            .into_iter()
            .flatten()
            .filter(|path| path.exists())
        {
            assert!(
                match_static_profile(&path).unwrap().is_some(),
                "installed target did not match {}",
                path.display()
            );
        }
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
}
