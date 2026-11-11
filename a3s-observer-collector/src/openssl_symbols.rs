use anyhow::{bail, Context as _};
use object::{Object as _, ObjectSegment as _, ObjectSymbol as _, SymbolKind};
use std::fs;
use std::path::Path;

// kimi-code ships as a static Node.js single-executable application that is NOT stripped: the
// statically linked OpenSSL entry points are global text symbols in its own ELF symbol table.
// Resolving them by name and converting the virtual address to a file offset through PT_LOAD is
// exact where a byte signature can only be probabilistic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenSslSymbolOffsets {
    pub ssl_write: u64,
    pub ssl_read: u64,
}

pub fn resolve_openssl_ssl_offsets(binary: &Path) -> anyhow::Result<OpenSslSymbolOffsets> {
    let metadata = fs::metadata(binary)
        .with_context(|| format!("stat OpenSSL runtime binary {}", binary.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 512 * 1024 * 1024 {
        bail!(
            "OpenSSL runtime binary size is outside the supported 1-512 MiB range: {}",
            binary.display()
        );
    }
    let bytes = fs::read(binary)
        .with_context(|| format!("read OpenSSL runtime binary {}", binary.display()))?;
    let parsed = object::File::parse(&*bytes)
        .with_context(|| format!("parse OpenSSL runtime binary ELF {}", binary.display()))?;
    let mut writes = Vec::new();
    let mut reads = Vec::new();
    for symbol in parsed.symbols().chain(parsed.dynamic_symbols()) {
        if !symbol.is_definition() || !symbol.is_global() || symbol.kind() != SymbolKind::Text {
            continue;
        }
        match symbol.name() {
            Ok("SSL_write") => writes.push(symbol.address()),
            Ok("SSL_read") => reads.push(symbol.address()),
            _ => {}
        }
    }
    writes.sort_unstable();
    writes.dedup();
    reads.sort_unstable();
    reads.dedup();
    if writes.len() != 1 || reads.len() != 1 {
        bail!(
            "OpenSSL symbols were not uniquely recognized in {} (SSL_write={}, SSL_read={})",
            binary.display(),
            writes.len(),
            reads.len()
        );
    }
    Ok(OpenSslSymbolOffsets {
        ssl_write: file_offset(&parsed, writes[0], binary)?,
        ssl_read: file_offset(&parsed, reads[0], binary)?,
    })
}

fn file_offset<'a>(
    parsed: &object::File<'a, &'a [u8]>,
    address: u64,
    binary: &Path,
) -> anyhow::Result<u64> {
    for segment in parsed.segments() {
        let start = segment.address();
        if address < start || address >= start.saturating_add(segment.size()) {
            continue;
        }
        let relative = address - start;
        let (offset, size) = segment.file_range();
        if relative >= size {
            break;
        }
        return Ok(offset + relative);
    }
    bail!(
        "OpenSSL symbol address 0x{address:x} is not file-backed in {}",
        binary.display()
    )
}

#[cfg(test)]
mod tests {
    use super::resolve_openssl_ssl_offsets;
    use std::fs;
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
                "a3s-openssl-symbols-{label}-{}-{nonce}",
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

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn put_symbol(
        bytes: &mut [u8],
        offset: usize,
        name: u32,
        info: u8,
        section: u16,
        value: u64,
        size: u64,
    ) {
        put_u32(bytes, offset, name);
        bytes[offset + 4] = info;
        bytes[offset + 5] = 0;
        put_u16(bytes, offset + 6, section);
        put_u64(bytes, offset + 8, value);
        put_u64(bytes, offset + 16, size);
    }

    fn put_section(
        bytes: &mut [u8],
        offset: usize,
        name: u32,
        kind: u32,
        flags: u64,
        addr: u64,
        file_offset: u64,
        size: u64,
        link: u32,
        info: u32,
        align: u64,
        entry_size: u64,
    ) {
        put_u32(bytes, offset, name);
        put_u32(bytes, offset + 4, kind);
        put_u64(bytes, offset + 8, flags);
        put_u64(bytes, offset + 16, addr);
        put_u64(bytes, offset + 24, file_offset);
        put_u64(bytes, offset + 32, size);
        put_u32(bytes, offset + 40, link);
        put_u32(bytes, offset + 44, info);
        put_u64(bytes, offset + 48, align);
        put_u64(bytes, offset + 56, entry_size);
    }

    // Minimal ELF64 executable: one executable PT_LOAD at file 0x1000 / vaddr 0x401000 with
    // SSL_write at 0x401040 and SSL_read at 0x401080 as global FUNC .symtab entries.
    fn write_elf_with_ssl_symbols(path: &Path) {
        const TEXT_OFFSET: u64 = 0x1000;
        const TEXT_VADDR: u64 = 0x401000;
        const STRTAB_OFFSET: u64 = 0x1100;
        const SYMTAB_OFFSET: u64 = 0x1200;
        const SHSTRTAB_OFFSET: u64 = 0x1260;
        const SHOFF: u64 = 0x1280;
        let strtab = b"\0SSL_write\0SSL_read\0";
        let shstrtab = b"\0.text\0.symtab\0.strtab\0.shstrtab\0";
        let mut bytes = vec![0u8; 0x1280 + 5 * 64];

        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // 64-bit
        bytes[5] = 1; // little-endian
        bytes[6] = 1; // version
        put_u16(&mut bytes, 16, 2); // ET_EXEC
        put_u16(&mut bytes, 18, 62); // x86-64
        put_u32(&mut bytes, 20, 1);
        put_u64(&mut bytes, 24, TEXT_VADDR); // entry
        put_u64(&mut bytes, 32, 0x40); // phoff
        put_u64(&mut bytes, 40, SHOFF); // shoff
        put_u16(&mut bytes, 52, 64); // ehsize
        put_u16(&mut bytes, 54, 56); // phentsize
        put_u16(&mut bytes, 56, 1); // phnum
        put_u16(&mut bytes, 58, 64); // shentsize
        put_u16(&mut bytes, 60, 5); // shnum
        put_u16(&mut bytes, 62, 4); // shstrndx

        put_u32(&mut bytes, 0x40, 1); // PT_LOAD
        put_u32(&mut bytes, 0x44, 5); // R+X
        put_u64(&mut bytes, 0x48, TEXT_OFFSET);
        put_u64(&mut bytes, 0x50, TEXT_VADDR);
        put_u64(&mut bytes, 0x58, TEXT_VADDR);
        put_u64(&mut bytes, 0x60, 0x100); // filesz
        put_u64(&mut bytes, 0x68, 0x100); // memsz
        put_u64(&mut bytes, 0x70, 0x1000); // align

        bytes[TEXT_OFFSET as usize..TEXT_OFFSET as usize + 0x100].fill(0x90);
        bytes[STRTAB_OFFSET as usize..STRTAB_OFFSET as usize + strtab.len()]
            .copy_from_slice(strtab);
        bytes[SHSTRTAB_OFFSET as usize..SHSTRTAB_OFFSET as usize + shstrtab.len()]
            .copy_from_slice(shstrtab);

        let symtab = SYMTAB_OFFSET as usize;
        put_symbol(&mut bytes, symtab + 24, 1, 0x12, 1, TEXT_VADDR + 0x40, 0x20);
        put_symbol(
            &mut bytes,
            symtab + 48,
            11,
            0x12,
            1,
            TEXT_VADDR + 0x80,
            0x20,
        );

        let shoff = SHOFF as usize;
        put_section(&mut bytes, shoff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        put_section(
            &mut bytes,
            shoff + 64,
            1,
            1,
            0x6,
            TEXT_VADDR,
            TEXT_OFFSET,
            0x100,
            0,
            0,
            16,
            0,
        );
        put_section(
            &mut bytes,
            shoff + 128,
            7,
            2,
            0,
            0,
            SYMTAB_OFFSET,
            3 * 24,
            3,
            1,
            8,
            24,
        );
        put_section(
            &mut bytes,
            shoff + 192,
            15,
            3,
            0,
            0,
            STRTAB_OFFSET,
            strtab.len() as u64,
            0,
            0,
            1,
            0,
        );
        put_section(
            &mut bytes,
            shoff + 256,
            23,
            3,
            0,
            0,
            SHSTRTAB_OFFSET,
            shstrtab.len() as u64,
            0,
            0,
            1,
            0,
        );
        fs::write(path, bytes).expect("write synthetic ELF");
    }

    #[test]
    fn resolves_ssl_symbols_to_file_offsets() {
        let tree = TestTree::new("resolve");
        let binary = tree.0.join("kimi");
        write_elf_with_ssl_symbols(&binary);
        let offsets = resolve_openssl_ssl_offsets(&binary).expect("offsets");
        assert_eq!(offsets.ssl_write, 0x1040);
        assert_eq!(offsets.ssl_read, 0x1080);
    }

    #[test]
    fn rejects_binaries_without_ssl_symbols() {
        let tree = TestTree::new("reject");
        let binary = tree.0.join("not-an-elf");
        fs::write(&binary, b"\x7fELFtest-runtime").expect("write fake ELF");
        assert!(resolve_openssl_ssl_offsets(&binary).is_err());
    }

    #[test]
    fn resolves_the_installed_kimi_binary_when_present() {
        let Some(home) = std::env::var_os("HOME") else {
            return;
        };
        let binary = PathBuf::from(home).join(".kimi-code/bin/kimi");
        if !binary.is_file() {
            return;
        }
        let offsets = resolve_openssl_ssl_offsets(&binary).expect("kimi offsets");
        assert!(offsets.ssl_read < offsets.ssl_write);
        let bytes = fs::read(&binary).expect("read kimi");
        for offset in [offsets.ssl_read, offsets.ssl_write] {
            let prologue = &bytes[offset as usize..offset as usize + 4];
            assert_eq!(prologue, &[0x55, 0x48, 0x89, 0xe5]);
        }
    }
}
