//! a3s-observer collector — loads the eBPF probes, pumps the ring buffers, and emits
//! enriched events through the [`Exporter`] contract.
//!
//! Probes: `exec` (tools), `tls_*` (TLS ClientHello → SNI → provider), `connect` (peer IP),
//! `dns` (hostnames), `file_open` (files opened for writing). Userspace enriches with
//! identity (`/proc` comm+ppid, k8s cgroup→pod) and a `(pid,fd)→peer` correlation, then
//! exports (NDJSON or log). OTLP is a drop-in via the `Exporter` trait.

use a3s_observer::{
    read_ppid, AgentEvent, EnrichedEvent, Exporter, Identity, IdentityResolver, JsonExporter,
    KubeResolver, LogExporter, Provider, ServiceClassifier, SniClassifier,
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

    // File-write capture is opt-in: openat is a firehose on a busy node (e.g. containerd
    // unpacking images), and the agent's own writes need downstream identity filtering.
    let files = std::env::var_os("A3S_OBSERVER_FILES").is_some();
    let mut probes = vec![
        ("exec", "sys_enter_execve"),
        ("tls_write", "sys_enter_write"),
        ("tls_sendto", "sys_enter_sendto"),
        ("connect", "sys_enter_connect"),
        ("dns_query", "sys_enter_sendto"),
        ("dns_sendmsg", "sys_enter_sendmsg"),
        ("dns_sendmmsg", "sys_enter_sendmmsg"),
        ("read_enter", "sys_enter_read"),
        ("recv_enter", "sys_enter_recvfrom"),
        ("read_exit", "sys_exit_read"),
        ("recv_exit", "sys_exit_recvfrom"),
        ("sock_close", "sys_enter_close"),
    ];
    if files {
        probes.push(("file_open", "sys_enter_openat"));
    }
    // Per-probe attach is non-fatal: kernels vary, and one missing tracepoint shouldn't take
    // down the whole collector — degrade to whatever attaches, fail only if nothing does.
    let mut attached = 0usize;
    for (prog, tp) in &probes {
        match attach(&mut ebpf, prog, "syscalls", tp) {
            Ok(()) => attached += 1,
            Err(e) => {
                tracing::warn!(probe = prog, error = %e, "probe failed to attach — continuing")
            }
        }
    }
    if attached == 0 {
        anyhow::bail!("no eBPF probes could be attached");
    }

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
        attached,
        total = probes.len(),
        files,
        "a3s-observer-collector: probes attached (file-write capture: set A3S_OBSERVER_FILES=1); \
         streaming (Ctrl-C to stop)"
    );

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut stats = Stats::default();
    let mut report = tokio::time::interval(Duration::from_secs(60));
    report.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = report.tick() => {
                tracing::info!(
                    exec = stats.exec,
                    egress = stats.egress,
                    dns = stats.dns,
                    file = stats.file,
                    llm = stats.llm,
                    "a3s-observer: events processed in the last 60s"
                );
                stats = Stats::default();
            }
            // Drain all rings every 20ms. Adequate for production at moderate volume; the
            // rings (64-256 KiB) absorb bursts between ticks. For sustained extreme volume,
            // switch to AsyncFd (epoll) on the ring fds and/or enlarge the rings.
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                while let Some(item) = exec_ring.next() {
                    if let Some(ev) = read_pod::<ExecEvent>(&item) {
                        emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                            identity: identity_for(&resolver, ev.pid, &ev.comm),
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
                        emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                            identity: identity_for(&resolver, ev.pid, &ev.comm),
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
                        emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                            identity: identity_for(&resolver, ev.pid, &ev.comm),
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
                            emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                                identity: identity_for(&resolver, ev.pid, &ev.comm),
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
                            emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                                identity: identity_for(&resolver, ev.pid, &ev.comm),
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
                                emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                                    identity: identity_for(&resolver, ev.pid, &ev.comm),
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

/// Resolve identity, falling back to the in-kernel `comm` when the /proc lookup fails (a
/// short-lived process that exited before we read it) — so no event is left unattributed.
fn identity_for(r: &impl IdentityResolver, pid: u32, comm: &[u8; 16]) -> Identity {
    let mut id = r.resolve(pid, 0, 0);
    if id.agent.is_none() {
        let c = cstr(comm);
        if !c.is_empty() {
            id.agent = Some(c);
        }
    }
    id
}

/// Per-kind event counters for periodic throughput logging (collector operability).
#[derive(Default)]
struct Stats {
    exec: u64,
    egress: u64,
    dns: u64,
    file: u64,
    llm: u64,
}

/// Export an event and count it by kind for the throughput report.
fn emit(exporter: &dyn Exporter, stats: &mut Stats, ev: EnrichedEvent) {
    match &ev.event {
        AgentEvent::ToolExec { .. } => stats.exec += 1,
        AgentEvent::Egress { .. } => stats.egress += 1,
        AgentEvent::Dns { .. } => stats.dns += 1,
        AgentEvent::FileAccess { .. } => stats.file += 1,
        AgentEvent::LlmCall { .. } => stats.llm += 1,
    }
    exporter.export(&ev);
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
