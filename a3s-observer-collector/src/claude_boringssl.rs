use anyhow::{bail, Context as _};
use std::fs;
use std::path::Path;

// Bun-based Claude Code binaries statically link and strip BoringSSL. These stable x86_64
// function prologues are the same signatures used by AgentSight. Both ends are required and
// must be near one another; a lone generic prologue is never sufficient for a plaintext attach.
const SSL_READ_PREFIX: &[u8] = &[
    0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x50, 0x48, 0x83, 0xbf, 0x98, 0x00, 0x00,
    0x00, 0x00, 0x74,
];
const SSL_WRITE_PREFIX: &[u8] = &[
    0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83, 0xec,
    0x18, 0x41, 0x89, 0xd7, 0x49, 0x89, 0xf6, 0x48, 0x89, 0xfb,
];
const MAX_NEAR_DISTANCE: usize = 0x10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoringSslOffsets {
    pub ssl_write: u64,
    pub ssl_read: u64,
}

pub fn scan_claude_boringssl(binary: &Path) -> anyhow::Result<BoringSslOffsets> {
    let metadata = fs::metadata(binary)
        .with_context(|| format!("stat Claude Code runtime binary {}", binary.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 512 * 1024 * 1024 {
        bail!(
            "Claude Code runtime binary size is outside the supported 1-512 MiB range: {}",
            binary.display()
        );
    }
    let bytes = fs::read(binary)
        .with_context(|| format!("read Claude Code runtime binary {}", binary.display()))?;
    let reads = find_all(&bytes, SSL_READ_PREFIX);
    let writes = find_all(&bytes, SSL_WRITE_PREFIX);
    let pairs = reads
        .iter()
        .flat_map(|read| writes.iter().map(move |write| (*read, *write)))
        .filter(|(read, write)| read.abs_diff(*write) <= MAX_NEAR_DISTANCE)
        .collect::<Vec<_>>();
    if pairs.len() != 1 {
        bail!(
            "Claude/BoringSSL signatures were not uniquely recognized in {} (read={}, write={}, nearby_pairs={})",
            binary.display(),
            reads.len(),
            writes.len(),
            pairs.len()
        );
    }
    Ok(BoringSslOffsets {
        ssl_read: pairs[0].0 as u64,
        ssl_write: pairs[0].1 as u64,
    })
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, candidate)| (candidate == needle).then_some(offset))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{find_all, SSL_READ_PREFIX, SSL_WRITE_PREFIX};

    #[test]
    fn finds_boring_ssl_function_prefixes() {
        let mut bytes = vec![0x90; 0x400];
        bytes[0x80..0x80 + SSL_READ_PREFIX.len()].copy_from_slice(SSL_READ_PREFIX);
        bytes[0x180..0x180 + SSL_WRITE_PREFIX.len()].copy_from_slice(SSL_WRITE_PREFIX);
        assert_eq!(find_all(&bytes, SSL_READ_PREFIX), vec![0x80]);
        assert_eq!(find_all(&bytes, SSL_WRITE_PREFIX), vec![0x180]);
    }
}
