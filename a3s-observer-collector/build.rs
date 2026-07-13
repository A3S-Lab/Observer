//! Compiles the sibling `a3s-observer-ebpf` crate to BPF bytecode (via bpf-linker, on
//! the nightly toolchain) and places the object in OUT_DIR for the loader to
//! `include_bytes_aligned!`.
use aya_build::{Package, Toolchain};

fn main() -> anyhow::Result<()> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let ebpf_dir = format!("{manifest_dir}/../a3s-observer-ebpf");
    let legacy_ebpf_dir = format!("{manifest_dir}/../a3s-observer-ebpf-legacy");
    // aya_build doesn't emit rerun-if for the eBPF crate, so a source-only change to the probes
    // would silently reuse stale bytecode. Track it explicitly.
    println!("cargo:rerun-if-changed={ebpf_dir}/src");
    println!("cargo:rerun-if-changed={ebpf_dir}/Cargo.toml");
    println!("cargo:rerun-if-changed={legacy_ebpf_dir}/src");
    println!("cargo:rerun-if-changed={legacy_ebpf_dir}/Cargo.toml");
    aya_build::build_ebpf(
        [
            Package {
                name: "a3s-observer-ebpf",
                root_dir: &ebpf_dir,
                no_default_features: false,
                features: &[],
            },
            Package {
                name: "a3s-observer-ebpf-legacy",
                root_dir: &legacy_ebpf_dir,
                no_default_features: false,
                features: &[],
            },
        ],
        Toolchain::default(), // Nightly
    )?;
    Ok(())
}
