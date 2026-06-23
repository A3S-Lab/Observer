//! a3s-observer-enforce — OPT-IN egress enforcement (see `docs/enforcement.md`).
//!
//! Loads the `cgroup/connect4` guard, attaches it to a target cgroup, and denies `connect()`
//! to the dest IPs an **external policy** lists. The policy is a plain file (one IPv4 or
//! hostname per line, `#` comments) that an external controller writes/updates — the enforcer
//! re-reads it every 2s and updates the in-kernel deny map. Only processes in the target
//! cgroup are affected; everything else is unchanged (fail-open).
//!
//!   sudo a3s-observer-enforce <cgroup-path> <policy-file>

use anyhow::Context as _;
use aya::maps::HashMap as BpfHashMap;
use aya::maps::MapData;
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use aya::Ebpf;
use std::net::{IpAddr, ToSocketAddrs};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let mut args = std::env::args().skip(1);
    let usage = "usage: a3s-observer-enforce <cgroup-path> <policy-file>";
    let cgroup_path = args.next().context(usage)?;
    let policy_path = args.next().context(usage)?;

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/probes"
    )))
    .context("load eBPF object")?;

    let prog: &mut CgroupSockAddr = ebpf
        .program_mut("egress_guard")
        .context("`egress_guard` program missing")?
        .try_into()?;
    prog.load()?;
    let cgroup =
        std::fs::File::open(&cgroup_path).with_context(|| format!("open {cgroup_path}"))?;
    prog.attach(&cgroup, CgroupAttachMode::Single)
        .context("attach egress_guard to cgroup")?;

    let mut deny: BpfHashMap<MapData, u32, u8> = BpfHashMap::try_from(
        ebpf.take_map("DENY_EGRESS")
            .context("`DENY_EGRESS` missing")?,
    )?;

    tracing::info!(cgroup = %cgroup_path, policy = %policy_path,
        "a3s-observer-enforce: egress guard attached (cgroup-scoped); applying policy every 2s");

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            _ = tick.tick() => {
                if let Err(e) = apply_policy(&mut deny, &policy_path) {
                    tracing::warn!(error = %e, "policy reload failed");
                }
            }
        }
    }
    tracing::info!("a3s-observer-enforce: stopped");
    Ok(())
}

/// (Re)load the external policy file into the deny map: each non-empty, non-`#` line is an
/// IPv4 or a hostname (resolved to its IPv4s) to deny egress to. Replaces the map each time.
fn apply_policy(deny: &mut BpfHashMap<MapData, u32, u8>, path: &str) -> anyhow::Result<()> {
    let body = std::fs::read_to_string(path).with_context(|| format!("read policy {path}"))?;
    // Parsing is the lib's CI-tested contract; the binary only resolves hostnames + DNS.
    let (ips, hosts) = a3s_observer::parse_egress_policy(&body);
    let mut want: Vec<u32> = ips.iter().map(|ip| u32::from(*ip)).collect();
    for h in &hosts {
        if let Ok(addrs) = (h.as_str(), 0u16).to_socket_addrs() {
            for a in addrs {
                if let IpAddr::V4(v4) = a.ip() {
                    want.push(u32::from(v4));
                }
            }
        }
    }
    let existing: Vec<u32> = deny.keys().filter_map(Result::ok).collect();
    for k in existing {
        let _ = deny.remove(&k);
    }
    for ip in &want {
        deny.insert(ip, 1u8, 0)?;
    }
    tracing::info!(
        rules = want.len(),
        "egress policy applied (deny by dest IP)"
    );
    Ok(())
}
