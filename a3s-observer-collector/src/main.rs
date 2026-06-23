//! a3s-observer collector — loads the eBPF probes, pumps the ring buffers, and emits
//! enriched events through the [`Exporter`] contract.
//!
//! Probes: `exec` (tools), `tls_*` (TLS ClientHello → SNI → provider), `connect` (peer IP),
//! `dns` (hostnames), `file_open` (files opened for writing). Userspace enriches with
//! identity (`/proc` comm+ppid, k8s cgroup→pod) and a `(pid,fd)→peer` correlation, then
//! exports (NDJSON or log). OTLP is a drop-in via the `Exporter` trait.

use a3s_observer::{
    read_ppid, AgentEvent, EnrichedEvent, Exporter, IdentityResolver, JsonExporter, KubeResolver,
    LogExporter, Provider, ServiceClassifier, SniClassifier,
};
use a3s_observer_common::{ConnectEvent, DnsEvent, ExecEvent, FileEvent, LlmEvent, TlsEvent};
use anyhow::Context as _;
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

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
    attach(&mut ebpf, "dns_query", "syscalls", "sys_enter_sendto")?;
    attach(&mut ebpf, "dns_sendmsg", "syscalls", "sys_enter_sendmsg")?;
    attach(&mut ebpf, "dns_sendmmsg", "syscalls", "sys_enter_sendmmsg")?;
    attach(&mut ebpf, "file_open", "syscalls", "sys_enter_openat")?;
    attach(&mut ebpf, "read_enter", "syscalls", "sys_enter_read")?;
    attach(&mut ebpf, "recv_enter", "syscalls", "sys_enter_recvfrom")?;
    attach(&mut ebpf, "read_exit", "syscalls", "sys_exit_read")?;
    attach(&mut ebpf, "recv_exit", "syscalls", "sys_exit_recvfrom")?;
    attach(&mut ebpf, "sock_close", "syscalls", "sys_enter_close")?;

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
    // (pid,fd) -> (sni, provider, peer): recorded at ClientHello, read when the socket
    // closes (the in-kernel LlmEvent) to build the metric-bearing LlmCall.
    let mut llm_meta: HashMap<u64, (Option<String>, Option<Provider>, IpAddr)> = HashMap::new();
    let mut exec_ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("`EVENTS` missing")?)?;
    let mut tls_ring = RingBuf::try_from(
        ebpf.take_map("TLS_EVENTS")
            .context("`TLS_EVENTS` missing")?,
    )?;
    let mut connect_ring = RingBuf::try_from(
        ebpf.take_map("CONNECT_EVENTS")
            .context("`CONNECT_EVENTS` missing")?,
    )?;
    let mut dns_ring = RingBuf::try_from(
        ebpf.take_map("DNS_EVENTS")
            .context("`DNS_EVENTS` missing")?,
    )?;
    let mut file_ring = RingBuf::try_from(
        ebpf.take_map("FILE_EVENTS")
            .context("`FILE_EVENTS` missing")?,
    )?;
    let mut llm_ring = RingBuf::try_from(
        ebpf.take_map("LLM_EVENTS")
            .context("`LLM_EVENTS` missing")?,
    )?;

    tracing::info!(
        "a3s-observer-collector: exec + TLS-SNI + connect + dns + file + LLM-metrics probes attached; streaming (Ctrl-C to stop)"
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
                        // Remember the call so the close event can build a metric-bearing
                        // LlmCall. Bounded; entries are normally removed on close.
                        if llm_meta.len() > 16384 {
                            llm_meta.clear(); // ponytail: crude cap; LRU if it ever matters
                        }
                        llm_meta.insert(sock_key(ev.pid, ev.fd), (sni.clone(), provider.clone(), peer));
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
                while let Some(item) = dns_ring.next() {
                    if let Some(ev) = read_pod::<DnsEvent>(&item) {
                        let len = (ev.len as usize).min(ev.data.len());
                        if let Some(query) = parse_dns_qname(&ev.data[..len]) {
                            exporter.export(&EnrichedEvent {
                                identity: resolver.resolve(ev.pid, 0, 0),
                                provider: None,
                                event: AgentEvent::Dns { pid: ev.pid, query },
                            });
                        }
                    }
                }
                while let Some(item) = file_ring.next() {
                    if let Some(ev) = read_pod::<FileEvent>(&item) {
                        let path = cstr(&ev.path);
                        if !path.is_empty() {
                            exporter.export(&EnrichedEvent {
                                identity: resolver.resolve(ev.pid, 0, 0),
                                provider: None,
                                event: AgentEvent::FileAccess {
                                    pid: ev.pid,
                                    path,
                                    write: ev.flags & 0x3 != 0,
                                },
                            });
                        }
                    }
                }
                while let Some(item) = llm_ring.next() {
                    if let Some(ev) = read_pod::<LlmEvent>(&item) {
                        // Join the kernel's byte/timing metrics with the SNI/provider/peer
                        // recorded at ClientHello. Only provider-identified calls → LlmCall.
                        if let Some((sni, provider, peer)) =
                            llm_meta.remove(&sock_key(ev.pid, ev.fd))
                        {
                            if provider.is_some() {
                                exporter.export(&EnrichedEvent {
                                    identity: resolver.resolve(ev.pid, 0, 0),
                                    provider,
                                    event: AgentEvent::LlmCall {
                                        pid: ev.pid,
                                        sni,
                                        peer,
                                        req_bytes: ev.req_bytes,
                                        resp_bytes: ev.resp_bytes,
                                        latency: Duration::from_nanos(ev.latency_ns),
                                        ttft: (ev.ttft_ns > 0)
                                            .then(|| Duration::from_nanos(ev.ttft_ns)),
                                    },
                                });
                            }
                        }
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
    vec![cstr(filename)]
}

/// A NUL-terminated byte buffer (from a kernel copy) as a lossy String.
fn cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn peer_ip(ev: &ConnectEvent) -> IpAddr {
    if ev.family == 2 {
        IpAddr::V4(Ipv4Addr::new(
            ev.addr[0], ev.addr[1], ev.addr[2], ev.addr[3],
        ))
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

/// Parse the question name (hostname) from a DNS query packet. Queries carry no name
/// compression, so this is a simple length-prefixed label walk. Bounds-checked.
fn parse_dns_qname(buf: &[u8]) -> Option<String> {
    if buf.len() < 13 {
        return None;
    }
    let mut p = 12; // skip the fixed 12-byte header
    let mut name = String::new();
    loop {
        let len = *buf.get(p)? as usize;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 || name.len() + len > 255 {
            return None; // compression pointer (absent in queries) or implausibly long
        }
        p += 1;
        let label = core::str::from_utf8(buf.get(p..p + len)?).ok()?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(label);
        p += len;
    }
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::{parse_dns_qname, parse_sni};

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

    #[test]
    fn parses_dns_query_name() {
        let mut q = vec![0u8; 12]; // header
        q.extend_from_slice(&[
            3, b'a', b'p', b'i', 9, b'a', b'n', b't', b'h', b'r', b'o', b'p', b'i', b'c', 3, b'c',
            b'o', b'm', 0,
        ]);
        q.extend_from_slice(&[0, 1, 0, 1]); // qtype A, qclass IN
        assert_eq!(parse_dns_qname(&q).as_deref(), Some("api.anthropic.com"));
        assert_eq!(parse_dns_qname(&[0u8; 8]), None);
    }
}
