//! Places the selected BPF bytecode in OUT_DIR for `include_bytes_aligned!`.
use aya_build::{Package, Toolchain};
use std::path::{Path, PathBuf};

fn install_verified_legacy_object() -> anyhow::Result<()> {
    println!("cargo:rerun-if-env-changed=A3S_LEGACY_BPF_OBJECT");
    println!("cargo:rerun-if-changed=../a3s-observer-ebpf-legacy/src/probes.c");
    let source = std::env::var("A3S_LEGACY_BPF_OBJECT").map_err(|_| {
        anyhow::anyhow!(
            "legacy-kernel-4-19 requires A3S_LEGACY_BPF_OBJECT; run scripts/build-legacy-bpf-object.sh first"
        )
    })?;
    let source = Path::new(&source);
    if !source.is_file() {
        anyhow::bail!("A3S_LEGACY_BPF_OBJECT is not a file: {}", source.display());
    }
    let destination = PathBuf::from(std::env::var("OUT_DIR")?).join("probes-legacy");
    std::fs::copy(source, &destination)?;
    println!("cargo:rerun-if-changed={}", source.display());
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let ebpf_dir = format!("{manifest_dir}/../a3s-observer-ebpf");
    if std::env::var_os("CARGO_FEATURE_LEGACY_KERNEL_4_19").is_some() {
        return install_verified_legacy_object();
    }
    // aya_build doesn't emit rerun-if for the eBPF crate, so a source-only change to the probes
    // would silently reuse stale bytecode. Track it explicitly.
    println!("cargo:rerun-if-changed={ebpf_dir}/src");
    println!("cargo:rerun-if-changed={ebpf_dir}/Cargo.toml");
    aya_build::build_ebpf(
        [Package {
            name: "a3s-observer-ebpf",
            root_dir: &ebpf_dir,
            no_default_features: false,
            features: &[],
        }],
        Toolchain::default(), // Nightly
    )?;
    Ok(())
}
