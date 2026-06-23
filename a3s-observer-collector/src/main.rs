//! a3s-observer collector — loads the eBPF probes, pumps the ring buffers, and emits
//! enriched events through the [`Exporter`] contract.
//!
//! Probes wired so far: `exec` (tools/subprocesses) and `tls_*` (TLS ClientHello → SNI →
//! provider). Identity resolution + OTel export are the next milestones.

use a3s_observer::{
    read_ppid, AgentEvent, EnrichedEvent, Exporter, IdentityResolver, JsonExporter, KubeResolver,
    LogExporter, ServiceClassifier, SniClassifier,
};
use a3s_observer_common::{ConnectEvent, ExecEvent, TlsEvent};
use anyhow::Context as _;
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/probes"
    )))
    .context("load eBPF object")?;

    attach(&mut ebpf, "exec", "syscalls", "sys_enter_execve")?;
    attach(&mut ebpf, "tls_write", "syscalls", "sys_enter_write")?;
    attach(&mut ebpf, "tls_sendto", "syscalls", "sys_enter_sendto")?;
    attach(&mut ebpf, "connect", "syscalls", "sys_enter_connect")?;

    // A3S_OBSERVER_JSON=1 → NDJSON (pipe to vector/Loki/jq); otherwise human-readable log.
    let exporter: Box<dyn Exporter> = if std::env::var_os("A3S_OBSERVER_JSON").is_some() {
        Box::new(JsonExporter)
    } else {
        Box::new(LogExporter)
    };
    let classifier = SniClassifier;
    let resolver = KubeResolver; // cgroup→pod in k8s; falls back to comm on bare hosts
    // (pid,fd) -> peer, populated by connect, read by the TLS probe to fuse provider+peer.
    let mut peers: HashMap<u64, IpAddr> = HashMap::new();
    let mut exec_ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("`EVENTS` missing")?)?;
    let mut tls_ring =
        RingBuf::try_from(ebpf.take_map("TLS_EVENTS").context("`TLS_EVENTS` missing")?)?;
    let mut connect_ring =
        RingBuf::try_from(ebpf.take_map("CONNECT_EVENTS").context("`CONNECT_EVENTS` missing")?)?;

    tracing::info!(
        "a3s-observer-collector: exec + TLS-SNI + connect probes attached; streaming (Ctrl-C to stop)"
    );

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            // ponytail: poll loop; AsyncFd on the ring fds is the production form.
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                while let Some(item) = exec_ring.next() {
                    if let Some(ev) = read_pod::<ExecEvent>(&item) {
                        exporter.export(&EnrichedEvent {
                            identity: resolver.resolve(ev.pid, 0, 0),
                            provider: None,
                            event: AgentEvent::ToolExec {
                                pid: ev.pid,
                                ppid: read_ppid(ev.pid),
                                argv: argv_of(&ev.filename),
                                cwd: String::new(),
                            },
                        });
                    }
                }
                // Drain connect BEFORE tls so a same-poll ClientHello finds its peer.
                while let Some(item) = connect_ring.next() {
                    if let Some(ev) = read_pod::<ConnectEvent>(&item) {
                        let peer = peer_ip(&ev);
                        if peers.len() > 8192 {
                            peers.clear(); // ponytail: crude cap; LRU if it ever matters
                        }
                        peers.insert(sock_key(ev.pid, ev.fd), peer);
                        exporter.export(&EnrichedEvent {
                            identity: resolver.resolve(ev.pid, 0, 0),
                            provider: None,
                            event: AgentEvent::Egress {
                                pid: ev.pid,
                                sni: None,
                                peer,
                                bytes: 0,
                            },
                        });
                    }
                }
                while let Some(item) = tls_ring.next() {
                    if let Some(ev) = read_pod::<TlsEvent>(&item) {
                        let len = (ev.len as usize).min(ev.data.len());
                        let sni = parse_sni(&ev.data[..len]);
                        // Correlated peer for this socket (the LLM endpoint).
                        let peer = peers
                            .get(&sock_key(ev.pid, ev.fd))
                            .copied()
                            .unwrap_or(UNKNOWN_PEER);
                        let provider =
                            sni.as_deref().and_then(|h| classifier.classify(Some(h), peer));
                        exporter.export(&EnrichedEvent {
                            identity: resolver.resolve(ev.pid, 0, 0),
                            provider,
                            event: AgentEvent::Egress {
                                pid: ev.pid,
                                sni,
                                peer,
                                bytes: ev.len as u64,
                            },
                        });
                    }
                }
            }
        }
    }
    tracing::info!("a3s-observer-collector: stopped");
    Ok(())
}

// ponytail: peer IP arrives with the flow probe (#5); SNI alone identifies the provider.
const UNKNOWN_PEER: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

fn attach(ebpf: &mut Ebpf, prog: &str, category: &str, name: &str) -> anyhow::Result<()> {
    let p: &mut TracePoint = ebpf
        .program_mut(prog)
        .with_context(|| format!("`{prog}` program not found"))?
        .try_into()?;
    p.load()?;
    p.attach(category, name)
        .with_context(|| format!("attach {category}:{name}"))?;
    Ok(())
}

fn read_pod<T: Copy>(item: &[u8]) -> Option<T> {
    (item.len() >= core::mem::size_of::<T>())
        .then(|| unsafe { core::ptr::read_unaligned(item.as_ptr() as *const T) })
}

fn argv_of(filename: &[u8; 128]) -> Vec<String> {
    let end = filename.iter().position(|&b| b == 0).unwrap_or(filename.len());
    vec![String::from_utf8_lossy(&filename[..end]).into_owned()]
}

fn peer_ip(ev: &ConnectEvent) -> IpAddr {
    if ev.family == 2 {
        IpAddr::V4(Ipv4Addr::new(ev.addr[0], ev.addr[1], ev.addr[2], ev.addr[3]))
    } else {
        IpAddr::V6(Ipv6Addr::from(ev.addr))
    }
}

fn sock_key(pid: u32, fd: u32) -> u64 {
    ((pid as u64) << 32) | fd as u64
}

/// Extract the SNI `server_name` from a TLS ClientHello record. Fully bounds-checked
/// (any malformed/truncated input returns `None`).
fn parse_sni(buf: &[u8]) -> Option<String> {
    // record(5) + handshake(4) + client_version(2) + random(32) = 43
    let mut p = 43usize;
    p += 1 + *buf.get(p)? as usize; // session_id: len(1) + id
    p += 2 + be16(buf, p)? as usize; // cipher_suites: len(2) + suites
    p += 1 + *buf.get(p)? as usize; // compression: len(1) + methods
    p += 2; // extensions: total len(2)
    while p + 4 <= buf.len() {
        let ext_type = be16(buf, p)?;
        let ext_len = be16(buf, p + 2)? as usize;
        p += 4;
        if ext_type == 0x0000 {
            // server_name: list_len(2) + name_type(1) + name_len(2) + name
            let name_len = be16(buf, p + 3)? as usize;
            let start = p + 5;
            let name = buf.get(start..start.checked_add(name_len)?)?;
            return core::str::from_utf8(name).ok().map(str::to_owned);
        }
        p = p.checked_add(ext_len)?;
    }
    None
}

fn be16(buf: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(i)?, *buf.get(i + 1)?]))
}

#[cfg(test)]
mod tests {
    use super::parse_sni;

    #[test]
    fn parses_sni_from_minimal_clienthello() {
        let mut b = vec![0x16, 0x03, 0x01, 0x00, 0x00]; // record header
        b.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // handshake header
        b.extend_from_slice(&[0x03, 0x03]); // client_version
        b.extend_from_slice(&[0u8; 32]); // random
        b.push(0x00); // session_id len 0
        b.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: len 2 + 1 suite
        b.extend_from_slice(&[0x01, 0x00]); // compression: len 1 + null
        b.extend_from_slice(&[0x00, 0x11]); // extensions total len 17
        b.extend_from_slice(&[0x00, 0x00]); // ext type: server_name
        b.extend_from_slice(&[0x00, 0x0d]); // ext len 13
        b.extend_from_slice(&[0x00, 0x0b]); // server_name_list len 11
        b.push(0x00); // name_type host_name
        b.extend_from_slice(&[0x00, 0x08]); // name len 8
        b.extend_from_slice(b"test.com");
        assert_eq!(parse_sni(&b).as_deref(), Some("test.com"));
    }

    #[test]
    fn rejects_truncated_or_garbage() {
        assert_eq!(parse_sni(&[0u8; 8]), None);
        assert_eq!(parse_sni(&[]), None);
    }
}
