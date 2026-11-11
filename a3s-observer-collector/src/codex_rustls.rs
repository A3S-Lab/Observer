use anyhow::{bail, Context as _};
use std::fs;
use std::path::Path;

const MAX_OFFSETS: usize = 64;

// rustls 0.23 PlaintextSink::write. Branch displacements elsewhere in the function are
// deliberately not part of the signature so compiler patch releases can still be supported.
const WRITE_PREFIX: &[u8] = &[
    0x41, 0x56, 0x53, 0x48, 0x83, 0xec, 0x48, 0x49, 0x89, 0xfe, 0x48, 0x89, 0x74, 0x24, 0x10, 0x48,
    0x89, 0x54, 0x24, 0x18, 0x48, 0xc7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00,
];

// rustls 0.23 PlaintextSink::write_vectored. The three stable blocks are checked together to
// avoid attaching to an unrelated function that happens to share the common Rust prologue.
const WRITEV_PREFIX: &[u8] = &[
    0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83, 0xec, 0x68, 0x48, 0x85,
    0xd2, 0x74,
];
const WRITEV_IOV: &[u8] = &[0x49, 0x89, 0xfe, 0x48, 0x83, 0xfa, 0x01, 0x75];
const WRITEV_COPY: &[u8] = &[0xf3, 0x0f, 0x6f, 0x06, 0xf3, 0x0f, 0x7f, 0x44, 0x24, 0x10];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustlsOffset {
    pub file_offset: u64,
    pub vectored: bool,
}

pub fn scan_codex_rustls(binary: &Path) -> anyhow::Result<Vec<RustlsOffset>> {
    let metadata = fs::metadata(binary)
        .with_context(|| format!("stat Codex runtime binary {}", binary.display()))?;
    if !metadata.is_file() {
        bail!(
            "Codex runtime binary is not a regular file: {}",
            binary.display()
        );
    }
    if metadata.len() == 0 || metadata.len() > 512 * 1024 * 1024 {
        bail!(
            "Codex runtime binary size is outside the supported 1-512 MiB range: {}",
            binary.display()
        );
    }
    let bytes = fs::read(binary)
        .with_context(|| format!("read Codex runtime binary {}", binary.display()))?;
    let mut offsets = Vec::new();

    for offset in find_all(&bytes, WRITEV_PREFIX) {
        if offsets.len() >= MAX_OFFSETS {
            break;
        }
        if slice_eq(&bytes, offset + 19, WRITEV_IOV) && slice_eq(&bytes, offset + 28, WRITEV_COPY) {
            offsets.push(RustlsOffset {
                file_offset: offset as u64,
                vectored: true,
            });
        }
    }
    for offset in find_all(&bytes, WRITE_PREFIX) {
        if offsets.len() >= MAX_OFFSETS {
            break;
        }
        offsets.push(RustlsOffset {
            file_offset: offset as u64,
            vectored: false,
        });
    }
    offsets.sort_by_key(|item| (item.file_offset, item.vectored));
    offsets.dedup();
    if offsets.is_empty() {
        bail!(
            "Codex/rustls plaintext write signatures were not recognized in {}",
            binary.display()
        );
    }
    Ok(offsets)
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let mut matches = Vec::new();
    let mut cursor = 0usize;
    while cursor + needle.len() <= haystack.len() {
        let Some(relative) = haystack[cursor..]
            .iter()
            .position(|byte| *byte == needle[0])
        else {
            break;
        };
        let offset = cursor + relative;
        if slice_eq(haystack, offset, needle) {
            matches.push(offset);
        }
        cursor = offset + 1;
    }
    matches
}

fn slice_eq(haystack: &[u8], offset: usize, needle: &[u8]) -> bool {
    haystack
        .get(offset..offset.saturating_add(needle.len()))
        .is_some_and(|candidate| candidate == needle)
}

#[cfg(test)]
mod tests {
    use super::{find_all, slice_eq, WRITEV_COPY, WRITEV_IOV, WRITEV_PREFIX, WRITE_PREFIX};

    #[test]
    fn finds_scalar_and_validates_vectored_blocks() {
        let mut bytes = vec![0x90; 256];
        bytes[31..31 + WRITE_PREFIX.len()].copy_from_slice(WRITE_PREFIX);
        bytes[101..101 + WRITEV_PREFIX.len()].copy_from_slice(WRITEV_PREFIX);
        bytes[120..120 + WRITEV_IOV.len()].copy_from_slice(WRITEV_IOV);
        bytes[129..129 + WRITEV_COPY.len()].copy_from_slice(WRITEV_COPY);

        assert_eq!(find_all(&bytes, WRITE_PREFIX), vec![31]);
        assert_eq!(find_all(&bytes, WRITEV_PREFIX), vec![101]);
        assert!(slice_eq(&bytes, 120, WRITEV_IOV));
        assert!(slice_eq(&bytes, 129, WRITEV_COPY));
    }

    #[test]
    fn rejects_partial_matches() {
        assert!(find_all(&[1, 2, 3], &[1, 2, 3, 4]).is_empty());
        assert!(!slice_eq(&[1, 2, 3], 2, &[3, 4]));
    }
}
