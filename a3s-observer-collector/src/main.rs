#![cfg_attr(feature = "legacy-kernel-4-19", allow(dead_code, unused_imports))]

//! a3s-observer collector — loads the eBPF probes, pumps the ring buffers, and emits
//! enriched events through the [`Exporter`] contract.
//!
//! Probes: `exec` (tools), `tls_*` (TLS ClientHello → SNI → provider), `connect` (peer IP),
//! `dns` (hostnames), `file_open` (files opened for writing). Userspace enriches with
//! identity (`/proc` comm+ppid, k8s cgroup→pod) and a `(pid,fd)→peer` correlation, then
//! exports (NDJSON or log). OTLP is a drop-in via the `Exporter` trait.

use a3s_observer::{
    read_ppid, AgentEvent, EnrichedEvent, Exporter, Identity, IdentityResolver, JsonExporter,
    KubeResolver, LogExporter, ProcessContext, Provider, ServiceClassifier, SniClassifier,
};
use a3s_observer_common::{
    ConnectEvent, DnsEvent, ExecEvent, ExitEvent, FileEvent, LlmEvent, SecEvent, SslEvent,
    TlsEvent, FILE_DELETE_FLAG, SEC_BIND, SEC_PTRACE, SEC_SETUID,
};
use anyhow::Context as _;
use aya::{
    maps::{PerCpuArray, RingBuf},
    programs::{KProbe, TracePoint, UProbe},
    Ebpf,
};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[cfg(feature = "legacy-kernel-4-19")]
mod legacy;

#[cfg(not(feature = "legacy-kernel-4-19"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => {
            println!("a3s-observer-collector {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("--help" | "-h") => {
            println!(
                "a3s-observer-collector {} — language-agnostic eBPF observability for AI agents\n\n\
                 Run as root / CAP_BPF+CAP_PERFMON (Linux). Configure via env:\n  \
                 A3S_OBSERVER_JSON=1    emit NDJSON (default: human-readable log)\n  \
                 A3S_OBSERVER_FILES=1   also capture file writes (high-volume; off by default)\n  \
                 A3S_OBSERVER_SSL=1     also capture OpenSSL plaintext — prompts/responses \
                 (uprobe, OpenSSL-only, off by default; or set a libssl path)",
                env!("CARGO_PKG_VERSION")
            );
            return Ok(());
        }
        _ => {}
    }
    // Logs go to STDERR so STDOUT stays pure NDJSON (the event stream a pipeline parses), at
    // INFO by default so the operational logs (throughput, drop counter) are actually visible.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();

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
        ("sec_setuid", "sys_enter_setuid"),
        ("sec_setresuid", "sys_enter_setresuid"),
        ("sec_setreuid", "sys_enter_setreuid"),
        ("sec_ptrace", "sys_enter_ptrace"),
        ("sec_bind", "sys_enter_bind"),
    ];
    if files {
        probes.push(("file_open", "sys_enter_openat"));
        probes.push(("file_unlink", "sys_enter_unlinkat"));
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
    // proc_exit is a do_exit kprobe (not a tracepoint): do_exit fires for EVERY task exit,
    // including signal-kills (crash / OOM) that sys_enter_exit_group never sees.
    match attach_kprobe(&mut ebpf, "proc_exit", "do_exit") {
        Ok(()) => attached += 1,
        Err(e) => {
            tracing::warn!(error = %e, "proc_exit (do_exit kprobe) failed — exit signals unavailable")
        }
    }
    if attached == 0 {
        anyhow::bail!("no eBPF probes could be attached");
    }

    // Opt-in OpenSSL content capture (uprobes). Off by default — it captures real plaintext
    // (prompts/completions) and binds to OpenSSL only. A3S_OBSERVER_SSL=1, or set it to a
    // libssl path on distros where the default below is wrong.
    if let Some(val) = std::env::var("A3S_OBSERVER_SSL")
        .ok()
        .filter(|v| !v.is_empty())
    {
        let lib = if val.contains('/') {
            val
        } else {
            "/usr/lib/x86_64-linux-gnu/libssl.so.3".to_string()
        };
        let mut ssl_ok = 0;
        for (prog, sym) in [
            ("ssl_write", "SSL_write"),
            ("ssl_read_enter", "SSL_read"),
            ("ssl_read_exit", "SSL_read"),
        ] {
            match attach_uprobe(&mut ebpf, prog, sym, &lib) {
                Ok(()) => ssl_ok += 1,
                Err(e) => {
                    tracing::warn!(probe = prog, lib = %lib, error = %e, "SSL uprobe failed to attach")
                }
            }
        }
        tracing::info!(lib = %lib, attached = ssl_ok, "A3S_OBSERVER_SSL: OpenSSL content capture (uprobes)");
    }

    // A3S_OBSERVER_JSON=1 → NDJSON (pipe to vector/Loki/jq); otherwise human-readable log.
    let exporter: Box<dyn Exporter> = if std::env::var_os("A3S_OBSERVER_JSON").is_some() {
        Box::new(JsonExporter::new())
    } else {
        Box::new(LogExporter)
    };
    let classifier = SniClassifier;
    let resolver = KubeResolver; // cgroup→pod in k8s; falls back to comm on bare hosts
                                 // (pid,fd) -> peer, populated by connect, read by the TLS probe to fuse provider+peer.
    let mut peers: HashMap<u64, (IpAddr, u16)> = HashMap::new();
    // (pid,fd) -> (sni, provider, peer): recorded at ClientHello, read when the socket
    // closes (the in-kernel LlmEvent) to build the metric-bearing LlmCall.
    let mut llm_meta: HashMap<u64, (Option<String>, Option<Provider>, IpAddr)> = HashMap::new();
    let mut exec_ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("`EVENTS` missing")?)?;
    let mut exit_ring = RingBuf::try_from(
        ebpf.take_map("EXIT_EVENTS")
            .context("`EXIT_EVENTS` missing")?,
    )?;
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
    // Opt-in OpenSSL content ring; stays empty unless A3S_OBSERVER_SSL attached the uprobes.
    let mut ssl_ring = RingBuf::try_from(
        ebpf.take_map("SSL_EVENTS")
            .context("`SSL_EVENTS` missing")?,
    )?;
    let mut sec_ring = RingBuf::try_from(
        ebpf.take_map("SEC_EVENTS")
            .context("`SEC_EVENTS` missing")?,
    )?;
    // Cumulative count of events dropped because a ring was full (data-loss visibility).
    let drops: PerCpuArray<_, u64> =
        PerCpuArray::try_from(ebpf.take_map("DROPS").context("`DROPS` missing")?)?;

    tracing::info!(
        attached,
        total = probes.len(),
        files,
        "a3s-observer-collector: probes attached (file-write capture: set A3S_OBSERVER_FILES=1); \
         streaming (Ctrl-C to stop)"
    );

    // Liveness heartbeat: refresh a file at startup and on every report tick, so a k8s
    // livenessProbe can detect a wedged collector (file goes stale → restart the pod).
    let heartbeat = std::env::var("A3S_OBSERVER_HEARTBEAT")
        .unwrap_or_else(|_| "/run/a3s-observer.alive".into());
    if let Err(e) = std::fs::write(&heartbeat, b"ok") {
        // Warn loudly: a livenessProbe watching a never-written file would false-restart.
        tracing::warn!(path = %heartbeat, error = %e,
            "heartbeat write failed — set A3S_OBSERVER_HEARTBEAT to a writable path, or a \
             livenessProbe on it will restart-loop the pod");
    }

    let collector = CollectorMeta::from_env(
        files,
        std::env::var_os("A3S_OBSERVER_SSL").is_some(),
        attached,
    );

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut stats = Stats::default();
    emit_collector_heartbeat(
        exporter.as_ref(),
        &collector,
        0,
        &stats,
        0,
        exporter.output_drops(),
    );
    let mut report = tokio::time::interval(Duration::from_secs(60));
    report.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break, // k8s sends SIGTERM on pod termination
            _ = report.tick() => {
                let _ = std::fs::write(&heartbeat, b"ok"); // refresh liveness heartbeat
                let dropped: u64 = drops
                    .get(&0, 0)
                    .map(|v| v.iter().copied().sum())
                    .unwrap_or(0);
                let output_dropped = exporter.output_drops();
                emit_collector_heartbeat(exporter.as_ref(), &collector, 60, &stats, dropped, output_dropped);
                tracing::info!(
                    exec = stats.exec,
                    exit = stats.exit,
                    egress = stats.egress,
                    dns = stats.dns,
                    file = stats.file,
                    llm = stats.llm,
                    ssl = stats.ssl,
                    sec = stats.sec,
                    dropped,
                    output_dropped,
                    "a3s-observer: events in the last 60s (dropped = cumulative ring-full, \
                     output_dropped = slow-consumer backpressure)"
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
                            process: Some(process_context(ev.pid, &ev.comm)),
                            provider: None,
                            event: AgentEvent::ToolExec {
                                pid: ev.pid,
                                ppid: read_ppid(ev.pid),
                                uid: ev.uid,
                                argv: argv_of(&ev),
                                cwd: read_cwd(ev.pid),
                            },
                        });
                    }
                }
                while let Some(item) = exit_ring.next() {
                    if let Some(ev) = read_pod::<ExitEvent>(&item) {
                        emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                            identity: identity_for(&resolver, ev.pid, &ev.comm),
                            process: Some(process_context(ev.pid, &ev.comm)),
                            provider: None,
                            event: AgentEvent::ProcessExit {
                                pid: ev.pid,
                                exit_code: ev.exit_code,
                                signal: ev.signal,
                            },
                        });
                    }
                }
                while let Some(item) = sec_ring.next() {
                    if let Some(ev) = read_pod::<SecEvent>(&item) {
                        let kind = match ev.kind {
                            SEC_SETUID => "setuid-root",
                            SEC_PTRACE => "ptrace",
                            SEC_BIND => "bind",
                            _ => continue,
                        };
                        emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                            identity: identity_for(&resolver, ev.pid, &ev.comm),
                            process: Some(process_context(ev.pid, &ev.comm)),
                            provider: None,
                            event: AgentEvent::SecurityAction {
                                pid: ev.pid,
                                kind,
                                detail: ev.detail,
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
                        peers.insert(sock_key(ev.pid, ev.fd), (peer, ev.port));
                        emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                            identity: identity_for(&resolver, ev.pid, &ev.comm),
                            process: Some(process_context(ev.pid, &ev.comm)),
                            provider: None,
                            event: AgentEvent::Egress {
                                pid: ev.pid,
                                sni: None,
                                peer,
                                port: ev.port,
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
                        let (peer, port) = peers
                            .get(&sock_key(ev.pid, ev.fd))
                            .copied()
                            .unwrap_or((UNKNOWN_PEER, 0));
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
                            process: Some(process_context(ev.pid, &ev.comm)),
                            provider,
                            event: AgentEvent::Egress {
                                pid: ev.pid,
                                sni,
                                peer,
                                port,
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
                                process: Some(process_context(ev.pid, &ev.comm)),
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
                            // Same ring carries opens and deletes — the sentinel flag tells them apart.
                            let event = if ev.flags == FILE_DELETE_FLAG {
                                AgentEvent::FileDelete { pid: ev.pid, path }
                            } else {
                                AgentEvent::FileAccess {
                                    pid: ev.pid,
                                    path,
                                    write: ev.flags & 0x3 != 0,
                                }
                            };
                            emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                                identity: identity_for(&resolver, ev.pid, &ev.comm),
                                process: Some(process_context(ev.pid, &ev.comm)),
                                provider: None,
                                event,
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
                                    process: Some(process_context(ev.pid, &ev.comm)),
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
                while let Some(item) = ssl_ring.next() {
                    if let Some(ev) = read_pod::<SslEvent>(&item) {
                        let len = (ev.len as usize).min(ev.data.len());
                        let content = String::from_utf8_lossy(&ev.data[..len]).into_owned();
                        if !content.is_empty() {
                            let identity = identity_for(&resolver, ev.pid, &ev.comm);
                            // Structured LLM telemetry (model/tokens) alongside the raw content.
                            if let Some((model, prompt_tokens, completion_tokens)) =
                                parse_llm_meta(&content)
                            {
                                emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                                    identity: identity.clone(),
                                    process: Some(process_context(ev.pid, &ev.comm)),
                                    provider: None,
                                    event: AgentEvent::LlmApi {
                                        pid: ev.pid,
                                        is_request: ev.is_read == 0,
                                        model,
                                        prompt_tokens,
                                        completion_tokens,
                                    },
                                });
                            }
                            emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                                identity,
                                process: Some(process_context(ev.pid, &ev.comm)),
                                provider: None,
                                event: AgentEvent::SslContent {
                                    pid: ev.pid,
                                    is_read: ev.is_read != 0,
                                    content,
                                },
                            });
                        }
                    }
                }
            }
        }
    }
    tracing::info!(
        exec = stats.exec,
        exit = stats.exit,
        egress = stats.egress,
        dns = stats.dns,
        file = stats.file,
        llm = stats.llm,
        ssl = stats.ssl,
        sec = stats.sec,
        "a3s-observer-collector: stopped (final window)"
    );
    Ok(())
}

#[cfg(feature = "legacy-kernel-4-19")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    legacy::run().await
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

fn attach_kprobe(ebpf: &mut Ebpf, prog: &str, sym: &str) -> anyhow::Result<()> {
    let p: &mut KProbe = ebpf
        .program_mut(prog)
        .with_context(|| format!("`{prog}` program not found"))?
        .try_into()?;
    p.load()?;
    p.attach(sym, 0)
        .with_context(|| format!("attach kprobe {sym}"))?;
    Ok(())
}

fn attach_uprobe(ebpf: &mut Ebpf, prog: &str, sym: &str, target: &str) -> anyhow::Result<()> {
    let p: &mut UProbe = ebpf
        .program_mut(prog)
        .with_context(|| format!("`{prog}` program not found"))?
        .try_into()?;
    p.load()?;
    p.attach(Some(sym), 0, target, None)
        .with_context(|| format!("attach uprobe {sym} in {target}"))?;
    Ok(())
}

fn read_pod<T: Copy>(item: &[u8]) -> Option<T> {
    (item.len() >= core::mem::size_of::<T>())
        .then(|| unsafe { core::ptr::read_unaligned(item.as_ptr() as *const T) })
}

/// Full argv (argv[0..argc]) captured in-kernel; falls back to the binary path if none.
fn argv_of(ev: &ExecEvent) -> Vec<String> {
    let n = (ev.argc as usize).min(ev.args.len());
    let argv: Vec<String> = ev.args[..n]
        .iter()
        .map(|a| cstr(a))
        .filter(|s| !s.is_empty())
        .collect();
    if argv.is_empty() {
        vec![cstr(&ev.filename)]
    } else {
        argv
    }
}

/// The process's current working directory (≈ exec-time for a fresh process).
fn read_cwd(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{pid}/cwd"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn read_exe(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
}

fn read_cgroup(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn process_context(pid: u32, comm: &[u8; 16]) -> ProcessContext {
    let cwd = read_cwd(pid);
    ProcessContext {
        pid,
        ppid: read_ppid(pid),
        comm: cstr(comm),
        exe: read_exe(pid),
        cwd: (!cwd.is_empty()).then_some(cwd),
        cgroup: read_cgroup(pid),
    }
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
    exit: u64,
    egress: u64,
    dns: u64,
    file: u64,
    llm: u64,
    ssl: u64,
    sec: u64,
    agents: HashSet<String>,
}

struct CollectorMeta {
    collector_id: String,
    node_name: Option<String>,
    namespace: Option<String>,
    pod_name: Option<String>,
    version: String,
    mode: String,
    attached_probes: u32,
    enabled_features: Vec<String>,
}

impl CollectorMeta {
    fn from_env(files: bool, ssl: bool, attached: usize) -> Self {
        let node_name = env_any(&["A3S_NODE_NAME", "NODE_NAME", "K8S_NODE_NAME"]).or_else(hostname);
        let namespace = env_any(&["A3S_NAMESPACE", "POD_NAMESPACE", "K8S_NAMESPACE"]);
        let pod_name = env_any(&["A3S_POD_NAME", "POD_NAME", "HOSTNAME"]);
        let collector_id = env_any(&["A3S_OBSERVER_COLLECTOR_ID", "COLLECTOR_ID"])
            .or_else(|| pod_name.clone())
            .or_else(|| node_name.clone())
            .unwrap_or_else(|| "a3s-observer".to_string());
        let mut enabled_features = vec![
            "exec".to_string(),
            "network".to_string(),
            "dns".to_string(),
            "security".to_string(),
        ];
        if files {
            enabled_features.push("files".to_string());
        }
        if ssl {
            enabled_features.push("ssl".to_string());
        }
        let mode = if files || ssl {
            "observe+extensions"
        } else {
            "observe"
        }
        .to_string();
        Self {
            collector_id,
            node_name,
            namespace,
            pod_name,
            version: env!("CARGO_PKG_VERSION").to_string(),
            mode,
            attached_probes: attached as u32,
            enabled_features,
        }
    }
}

fn env_any(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        std::env::var(name)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

fn hostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn emit_collector_heartbeat(
    exporter: &dyn Exporter,
    meta: &CollectorMeta,
    interval_secs: u64,
    stats: &Stats,
    dropped: u64,
    output_dropped: u64,
) {
    exporter.export(&EnrichedEvent {
        identity: Identity::default(),
        process: None,
        provider: None,
        event: AgentEvent::CollectorHeartbeat {
            collector_id: meta.collector_id.clone(),
            node_name: meta.node_name.clone(),
            namespace: meta.namespace.clone(),
            pod_name: meta.pod_name.clone(),
            version: meta.version.clone(),
            mode: meta.mode.clone(),
            attached_probes: meta.attached_probes,
            enabled_features: meta.enabled_features.clone(),
            interval_secs,
            observed_agents: stats.agents.len() as u64,
            exec: stats.exec,
            exit: stats.exit,
            egress: stats.egress,
            dns: stats.dns,
            file: stats.file,
            llm: stats.llm,
            ssl: stats.ssl,
            sec: stats.sec,
            dropped,
            output_dropped,
        },
    });
}

/// Export an event and count it by kind for the throughput report.
fn emit(exporter: &dyn Exporter, stats: &mut Stats, ev: EnrichedEvent) {
    match &ev.event {
        AgentEvent::ToolExec { .. } => stats.exec += 1,
        AgentEvent::ProcessExit { .. } => stats.exit += 1,
        AgentEvent::Egress { .. } => stats.egress += 1,
        AgentEvent::Dns { .. } => stats.dns += 1,
        AgentEvent::FileAccess { .. } => stats.file += 1,
        AgentEvent::FileDelete { .. } => stats.file += 1,
        AgentEvent::LlmCall { .. } => stats.llm += 1,
        AgentEvent::SslContent { .. } => stats.ssl += 1,
        AgentEvent::LlmApi { .. } => stats.llm += 1,
        AgentEvent::SecurityAction { .. } => stats.sec += 1,
        AgentEvent::CollectorHeartbeat { .. } => {}
    }
    if !matches!(ev.event, AgentEvent::CollectorHeartbeat { .. }) {
        if let Some(agent) = &ev.identity.agent {
            stats.agents.insert(agent.clone());
        }
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

/// Best-effort LLM-API fields from captured TLS plaintext: `"model"` from a request body, token
/// `usage` from a response. None if absent (not an LLM call, or the bytes weren't captured).
/// Consumes untrusted plaintext — every index is bounds-checked, must never panic.
fn parse_llm_meta(s: &str) -> Option<(Option<String>, Option<u32>, Option<u32>)> {
    let model = json_str_after(s, "\"model\"");
    let pt = json_num_after(s, "\"prompt_tokens\"");
    let ct = json_num_after(s, "\"completion_tokens\"");
    (model.is_some() || pt.is_some() || ct.is_some()).then_some((model, pt, ct))
}

fn json_str_after(s: &str, key: &str) -> Option<String> {
    let rest = &s[s.find(key)? + key.len()..]; // find() ≤ len, +key.len() ≤ len → in-bounds
    let body = &rest[rest.find('"')? + 1..]; // past the value's opening quote
    Some(body[..body.find('"')?].to_owned())
}

fn json_num_after(s: &str, key: &str) -> Option<u32> {
    let rest = s[s.find(key)? + key.len()..].trim_start_matches([':', ' ', '\t']);
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest.get(..end)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{parse_dns_qname, parse_llm_meta, parse_sni};

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
    fn parse_llm_meta_extracts_model_and_tokens() {
        let req = r#"POST /v1/chat/completions HTTP/1.1 ... {"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#;
        assert_eq!(parse_llm_meta(req).unwrap().0.as_deref(), Some("gpt-4o"));
        let resp = r#"{"id":"x","choices":[],"usage":{"prompt_tokens":12,"completion_tokens":34}}"#;
        let (_, pt, ct) = parse_llm_meta(resp).unwrap();
        assert_eq!((pt, ct), (Some(12), Some(34)));
        assert!(parse_llm_meta("just plaintext, no json fields here").is_none());
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

    #[test]
    fn parse_sni_rejects_malicious_name_len_without_panicking() {
        // Long enough to reach the extension walk, but the server_name name_len (0xffff) points
        // far past the buffer — a hand-rolled parser without bounds checks would OOB-panic here.
        let mut b = vec![0x16, 0x03, 0x01, 0x00, 0x00];
        b.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        b.extend_from_slice(&[0x03, 0x03]);
        b.extend_from_slice(&[0u8; 32]);
        b.push(0x00); // session_id len 0
        b.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        b.extend_from_slice(&[0x01, 0x00]); // compression
        b.extend_from_slice(&[0x00, 0x09]); // extensions total len
        b.extend_from_slice(&[0x00, 0x00]); // ext type: server_name
        b.extend_from_slice(&[0x00, 0x05]); // ext len
        b.extend_from_slice(&[0x00, 0x03]); // server_name_list len
        b.push(0x00); // name_type
        b.extend_from_slice(&[0xff, 0xff]); // name_len 65535 — past the buffer
        assert_eq!(parse_sni(&b), None);
    }

    #[test]
    fn parse_dns_rejects_compression_pointer_and_label_overrun() {
        let mut ptr = vec![0u8; 12];
        ptr.extend_from_slice(&[0xc0, 0x0c]); // compression pointer — never valid in a query
        assert_eq!(parse_dns_qname(&ptr), None);
        let mut overrun = vec![0u8; 12];
        overrun.push(50); // claims a 50-byte label...
        overrun.extend_from_slice(b"short"); // ...but only 5 bytes follow
        assert_eq!(parse_dns_qname(&overrun), None);
    }
}
