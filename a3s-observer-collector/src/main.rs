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
    ConnectEvent, DnsEvent, ExecRecord, ExitEvent, FileEvent, LlmEvent, SecEvent, SslEvent,
    TlsEvent, ARGV_SLOTS, EXEC_ARG_CHUNK_LEN, EXEC_ARG_CHUNK_PAYLOAD, EXEC_FLAG_ARGV_INCOMPLETE,
    EXEC_FLAG_ARGV_TRUNCATED, EXEC_MAX_CHUNKS, EXEC_RECORD_ARG_CHUNK, EXEC_RECORD_COMMIT,
    EXEC_RECORD_END, EXEC_RECORD_HEADER, FILE_DELETE_FLAG, SEC_BIND, SEC_PTRACE, SEC_SETUID,
};
use anyhow::Context as _;
use aya::{
    maps::{PerCpuArray, RingBuf},
    programs::{KProbe, TracePoint, UProbe},
    Ebpf,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::{Duration, Instant};

const EXEC_REASSEMBLY_TIMEOUT: Duration = Duration::from_millis(500);
const EXEC_REASSEMBLY_LIMIT: usize = 4096;
const PROC_CMDLINE_MAX_BYTES: usize = 2 * 1024 * 1024;

struct PendingExec {
    first_seen: Instant,
    pid: u32,
    ppid: u32,
    uid: u32,
    comm: [u8; 16],
    filename: [u8; EXEC_ARG_CHUNK_LEN],
    saw_header: bool,
    saw_commit: bool,
    argc: Option<u16>,
    captured_bytes: Option<u32>,
    flags: u8,
    chunks: HashMap<u16, BTreeMap<u16, Vec<u8>>>,
}

impl PendingExec {
    fn new(record: &ExecRecord, now: Instant) -> Self {
        Self {
            first_seen: now,
            pid: record.pid,
            ppid: record.ppid,
            uid: record.uid,
            comm: record.comm,
            filename: [0; EXEC_ARG_CHUNK_LEN],
            saw_header: false,
            saw_commit: false,
            argc: None,
            captured_bytes: None,
            flags: 0,
            chunks: HashMap::new(),
        }
    }

    fn apply(&mut self, record: &ExecRecord) {
        self.flags |= record.flags;
        match record.kind {
            EXEC_RECORD_HEADER => {
                self.saw_header = true;
                let len = (record.data_len as usize).min(record.data.len());
                self.filename[..len].copy_from_slice(&record.data[..len]);
            }
            EXEC_RECORD_ARG_CHUNK => {
                if record.arg_index as usize >= ARGV_SLOTS
                    || record.chunk_index as usize >= EXEC_MAX_CHUNKS
                    || record.data_len as usize > record.data.len()
                {
                    self.flags |= EXEC_FLAG_ARGV_INCOMPLETE;
                    return;
                }
                let len = record.data_len as usize;
                let value = record.data[..len].to_vec();
                let chunks = self.chunks.entry(record.arg_index).or_default();
                if let Some(existing) = chunks.get(&record.chunk_index) {
                    if existing != &value {
                        self.flags |= EXEC_FLAG_ARGV_INCOMPLETE;
                    }
                } else {
                    chunks.insert(record.chunk_index, value);
                }
            }
            EXEC_RECORD_END => {
                self.argc = Some(record.argc.min(ARGV_SLOTS as u16));
                self.captured_bytes = Some(record.captured_bytes);
            }
            EXEC_RECORD_COMMIT => self.saw_commit = true,
            _ => self.flags |= EXEC_FLAG_ARGV_INCOMPLETE,
        }
    }

    fn finish(mut self, timed_out: bool) -> CompletedExec {
        let mut argv_incomplete = timed_out
            || !self.saw_header
            || self.argc.is_none()
            || self.flags & EXEC_FLAG_ARGV_INCOMPLETE != 0;
        let argv_truncated = self.flags & EXEC_FLAG_ARGV_TRUNCATED != 0;
        let inferred_argc = self
            .chunks
            .keys()
            .max()
            .map(|index| index.saturating_add(1))
            .unwrap_or(0);
        let captured_argc = self.argc.unwrap_or(inferred_argc).min(ARGV_SLOTS as u16);
        let mut argv = Vec::with_capacity(captured_argc as usize);
        let mut assembled_bytes = 0u32;

        for arg_index in 0..captured_argc {
            let Some(chunks) = self.chunks.remove(&arg_index) else {
                argv_incomplete = true;
                argv.push(String::new());
                continue;
            };
            let mut bytes = Vec::new();
            let mut expected_chunk = 0u16;
            let mut saw_terminator = false;
            for (chunk_index, chunk) in chunks {
                if chunk_index != expected_chunk {
                    argv_incomplete = true;
                }
                expected_chunk = chunk_index.saturating_add(1);
                assembled_bytes = assembled_bytes.saturating_add(chunk.len() as u32);
                if chunk.len() < EXEC_ARG_CHUNK_PAYLOAD {
                    saw_terminator = true;
                }
                bytes.extend_from_slice(&chunk);
            }
            if !(saw_terminator || argv_truncated && arg_index + 1 == captured_argc) {
                argv_incomplete = true;
            }
            argv.push(String::from_utf8_lossy(&bytes).into_owned());
        }
        if !self.chunks.is_empty() {
            argv_incomplete = true;
        }
        if let Some(expected_bytes) = self.captured_bytes {
            if expected_bytes != assembled_bytes {
                argv_incomplete = true;
            }
        }
        if argv.is_empty() {
            let filename = cstr(&self.filename);
            if !filename.is_empty() {
                argv.push(filename);
            }
        }

        CompletedExec {
            pid: self.pid,
            ppid: self.ppid,
            uid: self.uid,
            comm: self.comm,
            filename: self.filename,
            argv,
            argv_truncated,
            argv_incomplete,
            captured_argc,
            captured_bytes: self.captured_bytes.unwrap_or(assembled_bytes),
            reassembly_timed_out: timed_out && (self.argc.is_none() || !self.saw_header),
            exec_confirmed: self.saw_commit,
        }
    }
}

struct CompletedExec {
    pid: u32,
    ppid: u32,
    uid: u32,
    comm: [u8; 16],
    filename: [u8; EXEC_ARG_CHUNK_LEN],
    argv: Vec<String>,
    argv_truncated: bool,
    argv_incomplete: bool,
    captured_argc: u16,
    captured_bytes: u32,
    reassembly_timed_out: bool,
    exec_confirmed: bool,
}

struct ExecAssembler {
    pending: HashMap<(u64, u32), PendingExec>,
    require_commit: bool,
}

impl Default for ExecAssembler {
    fn default() -> Self {
        Self {
            pending: HashMap::new(),
            require_commit: true,
        }
    }
}

impl ExecAssembler {
    fn new(require_commit: bool) -> Self {
        Self {
            pending: HashMap::new(),
            require_commit,
        }
    }

    fn push(&mut self, record: ExecRecord, now: Instant) -> Vec<CompletedExec> {
        let mut completed = Vec::with_capacity(2);
        let key = (record.exec_id, record.pid);
        if !self.pending.contains_key(&key) && self.pending.len() >= EXEC_REASSEMBLY_LIMIT {
            if let Some(oldest) = self
                .pending
                .iter()
                .min_by_key(|(_, pending)| pending.first_seen)
                .map(|(key, _)| *key)
            {
                if let Some(pending) = self.pending.remove(&oldest) {
                    completed.push(pending.finish(true));
                }
            }
        }

        self.pending
            .entry(key)
            .or_insert_with(|| PendingExec::new(&record, now))
            .apply(&record);
        let ready = self.pending.get(&key).is_some_and(|pending| {
            pending.argc.is_some() && (pending.saw_commit || !self.require_commit)
        });
        if ready {
            if let Some(pending) = self.pending.remove(&key) {
                completed.push(pending.finish(false));
            }
        }
        completed
    }

    fn expire(&mut self, now: Instant) -> Vec<CompletedExec> {
        let expired: Vec<(u64, u32)> = self
            .pending
            .iter()
            .filter(|(_, pending)| {
                now.duration_since(pending.first_seen) >= EXEC_REASSEMBLY_TIMEOUT
            })
            .map(|(key, _)| *key)
            .collect();
        expired
            .into_iter()
            .filter_map(|key| self.pending.remove(&key))
            .map(|pending| pending.finish(true))
            .collect()
    }
}

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
        ("track_clone", "sys_exit_clone"),
        ("track_clone3", "sys_exit_clone3"),
        ("track_fork", "sys_exit_fork"),
        ("track_vfork", "sys_exit_vfork"),
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
    // sched_process_fork runs before the child can execute, so its parent PID is available even for short-lived tools.
    match attach(
        &mut ebpf,
        "track_process_fork",
        "sched",
        "sched_process_fork",
    ) {
        Ok(()) => attached += 1,
        Err(e) => {
            tracing::warn!(error = %e, "sched_process_fork probe failed - using syscall-exit ancestry fallback")
        }
    }
    let exec_commit_probe_attached = match attach(
        &mut ebpf,
        "track_process_exec",
        "sched",
        "sched_process_exec",
    ) {
        Ok(()) => {
            attached += 1;
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, "sched_process_exec probe failed - proc cmdline supplementation disabled");
            false
        }
    };
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
    let mut exec_assembler = ExecAssembler::new(exec_commit_probe_attached);
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
        total = probes.len() + 3,
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
                    exec_truncated = stats.exec_truncated,
                    exec_incomplete = stats.exec_incomplete,
                    exec_reassembly_timeout = stats.exec_reassembly_timeout,
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
                    if let Some(record) = read_pod::<ExecRecord>(&item) {
                        for completed in exec_assembler.push(record, Instant::now()) {
                            emit_completed_exec(
                                exporter.as_ref(),
                                &mut stats,
                                &resolver,
                                completed,
                            );
                        }
                    }
                }
                for completed in exec_assembler.expire(Instant::now()) {
                    emit_completed_exec(exporter.as_ref(), &mut stats, &resolver, completed);
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
                            workload: resolver.resolve_workload(ev.pid, 0, 0),
                            observation: None,
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
                            workload: resolver.resolve_workload(ev.pid, 0, 0),
                            observation: None,
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
                            workload: resolver.resolve_workload(ev.pid, 0, 0),
                            observation: None,
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
                                workload: resolver.resolve_workload(ev.pid, 0, 0),
                                observation: None,
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
                                workload: resolver.resolve_workload(ev.pid, 0, 0),
                                observation: None,
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
                                    workload: resolver.resolve_workload(ev.pid, 0, 0),
                                    observation: None,
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
                            let workload = resolver.resolve_workload(ev.pid, 0, 0);
                            // Structured LLM telemetry (model/tokens) alongside the raw content.
                            if let Some((model, prompt_tokens, completion_tokens)) =
                                parse_llm_meta(&content)
                            {
                                emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                                    identity: identity.clone(),
                                    workload: workload.clone(),
                                    observation: None,
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
                                workload,
                                observation: None,
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
                // Exit is drained last so downstream process caches can attribute all prior
                // exec, file, network and security events before the PID lifecycle closes.
                while let Some(item) = exit_ring.next() {
                    if let Some(ev) = read_pod::<ExitEvent>(&item) {
                        emit(exporter.as_ref(), &mut stats, EnrichedEvent {
                            identity: identity_for(&resolver, ev.pid, &ev.comm),
                            workload: resolver.resolve_workload(ev.pid, 0, 0),
                            observation: None,
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
            }
        }
    }
    let dropped: u64 = drops
        .get(&0, 0)
        .map(|v| v.iter().copied().sum())
        .unwrap_or(0);
    let output_dropped = exporter.output_drops();
    tracing::info!(
        exec = stats.exec,
        exec_truncated = stats.exec_truncated,
        exec_incomplete = stats.exec_incomplete,
        exec_reassembly_timeout = stats.exec_reassembly_timeout,
        exit = stats.exit,
        egress = stats.egress,
        dns = stats.dns,
        file = stats.file,
        llm = stats.llm,
        ssl = stats.ssl,
        sec = stats.sec,
        dropped,
        output_dropped,
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

fn exec_ppid(ev: &CompletedExec) -> u32 {
    if ev.ppid != 0 {
        ev.ppid
    } else {
        read_ppid(ev.pid)
    }
}

fn exec_process_context(ev: &CompletedExec, ppid: u32) -> ProcessContext {
    let cwd = read_cwd(ev.pid);
    let captured_exe = cstr(&ev.filename);
    ProcessContext {
        pid: ev.pid,
        ppid,
        comm: cstr(&ev.comm),
        exe: read_exe(ev.pid).or_else(|| (!captured_exe.is_empty()).then_some(captured_exe)),
        cwd: (!cwd.is_empty()).then_some(cwd),
        cgroup: read_cgroup(ev.pid),
    }
}

struct ProcCmdline {
    argv: Vec<String>,
    observed_bytes: u32,
    truncated: bool,
}

fn read_proc_cmdline_at(
    proc_root: &Path,
    pid: u32,
    max_bytes: usize,
) -> std::io::Result<ProcCmdline> {
    let file = File::open(proc_root.join(pid.to_string()).join("cmdline"))?;
    let mut raw = Vec::new();
    file.take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut raw)?;
    let truncated = raw.len() > max_bytes;
    if truncated {
        raw.truncate(max_bytes);
    }
    let observed_bytes = raw.len().min(u32::MAX as usize) as u32;
    let argv = raw
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect();
    Ok(ProcCmdline {
        argv,
        observed_bytes,
        truncated,
    })
}

fn same_executable(ev: &CompletedExec, proc_argv: &[String]) -> bool {
    let Some(proc_argv0) = proc_argv.first().filter(|value| !value.is_empty()) else {
        return false;
    };
    if ev.argv.first().is_some_and(|value| value == proc_argv0) {
        return true;
    }
    let captured = cstr(&ev.filename);
    let captured_name = Path::new(&captured).file_name();
    let proc_name = Path::new(proc_argv0).file_name();
    captured_name.is_some() && captured_name == proc_name
}

fn supplement_exec_argv_at(
    mut ev: CompletedExec,
    proc_root: &Path,
    max_bytes: usize,
) -> (CompletedExec, &'static str, u32, u32) {
    let should_supplement = ev.exec_confirmed && (ev.argv_truncated || ev.argv_incomplete);
    if should_supplement {
        if let Ok(cmdline) = read_proc_cmdline_at(proc_root, ev.pid, max_bytes) {
            if !cmdline.argv.is_empty() && same_executable(&ev, &cmdline.argv) {
                ev.argv = cmdline.argv;
                ev.argv_truncated = cmdline.truncated;
                ev.argv_incomplete = false;
                let argc = ev.argv.len().min(u32::MAX as usize) as u32;
                return (ev, "proc_cmdline", argc, cmdline.observed_bytes);
            }
        }
    }
    let argc = ev.argv.len().min(u32::MAX as usize) as u32;
    let bytes = ev
        .argv
        .iter()
        .fold(0usize, |total, arg| total.saturating_add(arg.len()))
        .min(u32::MAX as usize) as u32;
    (ev, "kernel_fragments", argc, bytes)
}

fn supplement_exec_argv(ev: CompletedExec) -> (CompletedExec, &'static str, u32, u32) {
    supplement_exec_argv_at(ev, Path::new("/proc"), PROC_CMDLINE_MAX_BYTES)
}

fn emit_completed_exec(
    exporter: &dyn Exporter,
    stats: &mut Stats,
    resolver: &impl IdentityResolver,
    ev: CompletedExec,
) {
    if ev.reassembly_timed_out {
        stats.exec_reassembly_timeout += 1;
    }
    let (ev, argv_source, observed_argc, observed_bytes) = supplement_exec_argv(ev);
    let ppid = exec_ppid(&ev);
    let cwd = read_cwd(ev.pid);
    emit(
        exporter,
        stats,
        EnrichedEvent {
            identity: identity_for(resolver, ev.pid, &ev.comm),
            workload: resolver.resolve_workload(ev.pid, 0, 0),
            observation: None,
            process: Some(exec_process_context(&ev, ppid)),
            provider: None,
            event: AgentEvent::ToolExec {
                pid: ev.pid,
                ppid,
                uid: ev.uid,
                argv: ev.argv,
                argv_truncated: ev.argv_truncated,
                argv_incomplete: ev.argv_incomplete,
                exec_confirmed: ev.exec_confirmed,
                argv_source: argv_source.to_string(),
                captured_argc: ev.captured_argc,
                captured_bytes: ev.captured_bytes,
                observed_argc,
                observed_bytes,
                cwd,
            },
        },
    );
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
    exec_truncated: u64,
    exec_incomplete: u64,
    exec_reassembly_timeout: u64,
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
        workload: None,
        observation: None,
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
            exec_truncated: stats.exec_truncated,
            exec_incomplete: stats.exec_incomplete,
            exec_reassembly_timeout: stats.exec_reassembly_timeout,
            dropped,
            output_dropped,
        },
    });
}

/// Export an event and count it by kind for the throughput report.
fn emit(exporter: &dyn Exporter, stats: &mut Stats, ev: EnrichedEvent) {
    match &ev.event {
        AgentEvent::ToolExec {
            argv_truncated,
            argv_incomplete,
            ..
        } => {
            stats.exec += 1;
            stats.exec_truncated += u64::from(*argv_truncated);
            stats.exec_incomplete += u64::from(*argv_incomplete);
        }
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
    use super::{
        exec_ppid, exec_process_context, parse_dns_qname, parse_llm_meta, parse_sni,
        supplement_exec_argv_at, CompletedExec, ExecAssembler, EXEC_REASSEMBLY_TIMEOUT,
    };
    use a3s_observer_common::{
        ExecRecord, EXEC_ARG_CHUNK_PAYLOAD, EXEC_FLAG_ARGV_TRUNCATED, EXEC_RECORD_ARG_CHUNK,
        EXEC_RECORD_COMMIT, EXEC_RECORD_END, EXEC_RECORD_HEADER,
    };
    use std::fs;
    use std::time::Instant;

    fn exec_record(exec_id: u64, kind: u8) -> ExecRecord {
        let mut record: ExecRecord = unsafe { std::mem::zeroed() };
        record.exec_id = exec_id;
        record.pid = u32::MAX;
        record.ppid = 42;
        record.uid = 1000;
        record.kind = kind;
        record
    }

    fn chunk(exec_id: u64, arg_index: u16, chunk_index: u16, value: &[u8]) -> ExecRecord {
        let mut record = exec_record(exec_id, EXEC_RECORD_ARG_CHUNK);
        record.arg_index = arg_index;
        record.chunk_index = chunk_index;
        record.data_len = value.len() as u16;
        record.data[..value.len()].copy_from_slice(value);
        record
    }

    #[test]
    fn exec_uses_kernel_parent_snapshot_and_filename_fallback() {
        let mut ev = CompletedExec {
            pid: u32::MAX,
            ppid: 42,
            uid: 1000,
            comm: [0; 16],
            filename: [0; 128],
            argv: vec!["bash".to_string()],
            argv_truncated: false,
            argv_incomplete: false,
            captured_argc: 1,
            captured_bytes: 4,
            reassembly_timed_out: false,
            exec_confirmed: true,
        };
        let filename = b"/usr/bin/bash";
        ev.filename[..filename.len()].copy_from_slice(filename);

        assert_eq!(exec_ppid(&ev), 42);
        let process = exec_process_context(&ev, exec_ppid(&ev));
        assert_eq!(process.ppid, 42);
        assert_eq!(process.exe.as_deref(), Some("/usr/bin/bash"));
    }

    #[test]
    fn reassembles_long_arguments_without_silent_truncation() {
        let now = Instant::now();
        let mut assembler = ExecAssembler::default();
        let mut header = exec_record(7, EXEC_RECORD_HEADER);
        header.data_len = 9;
        header.data[..9].copy_from_slice(b"/bin/bash");
        assert!(assembler.push(header, now).is_empty());
        assert!(assembler.push(chunk(7, 0, 0, b"bash"), now).is_empty());

        let long = [b'x'; EXEC_ARG_CHUNK_PAYLOAD + 73];
        assert!(assembler
            .push(chunk(7, 1, 0, &long[..EXEC_ARG_CHUNK_PAYLOAD]), now)
            .is_empty());
        assert!(assembler
            .push(chunk(7, 1, 1, &long[EXEC_ARG_CHUNK_PAYLOAD..]), now)
            .is_empty());
        let mut end = exec_record(7, EXEC_RECORD_END);
        end.argc = 2;
        end.captured_bytes = (4 + long.len()) as u32;
        assert!(assembler.push(end, now).is_empty());
        let completed = assembler
            .push(exec_record(7, EXEC_RECORD_COMMIT), now)
            .pop()
            .unwrap();

        assert_eq!(completed.argv[0], "bash");
        assert_eq!(completed.argv[1].len(), long.len());
        assert!(!completed.argv_truncated);
        assert!(!completed.argv_incomplete);
    }

    #[test]
    fn marks_missing_chunks_and_timeouts_as_incomplete() {
        let now = Instant::now();
        let mut assembler = ExecAssembler::default();
        let header = exec_record(8, EXEC_RECORD_HEADER);
        assembler.push(header, now);
        assembler.push(chunk(8, 0, 1, b"tail"), now);
        let mut end = exec_record(8, EXEC_RECORD_END);
        end.argc = 1;
        end.captured_bytes = 4;
        assembler.push(end, now);
        let missing = assembler
            .push(exec_record(8, EXEC_RECORD_COMMIT), now)
            .pop()
            .unwrap();
        assert!(missing.argv_incomplete);

        assembler.push(exec_record(9, EXEC_RECORD_HEADER), now);
        let timed_out = assembler.expire(now + EXEC_REASSEMBLY_TIMEOUT);
        assert_eq!(timed_out.len(), 1);
        assert!(timed_out[0].argv_incomplete);
        assert!(timed_out[0].reassembly_timed_out);
    }

    #[test]
    fn emits_without_waiting_when_exec_commit_probe_is_unavailable() {
        let now = Instant::now();
        let mut assembler = ExecAssembler::new(false);
        assembler.push(exec_record(11, EXEC_RECORD_HEADER), now);
        assembler.push(chunk(11, 0, 0, b"echo"), now);
        let mut end = exec_record(11, EXEC_RECORD_END);
        end.argc = 1;
        end.captured_bytes = 4;

        let completed = assembler.push(end, now).pop().unwrap();
        assert_eq!(completed.argv, ["echo"]);
        assert!(!completed.exec_confirmed);
        assert!(!completed.argv_incomplete);
        assert!(!completed.reassembly_timed_out);
    }

    #[test]
    fn failed_exec_is_unconfirmed_but_not_a_reassembly_timeout() {
        let now = Instant::now();
        let mut assembler = ExecAssembler::default();
        assembler.push(exec_record(12, EXEC_RECORD_HEADER), now);
        assembler.push(chunk(12, 0, 0, b"missing-command"), now);
        let mut end = exec_record(12, EXEC_RECORD_END);
        end.argc = 1;
        end.captured_bytes = 15;
        assembler.push(end, now);

        let completed = assembler
            .expire(now + EXEC_REASSEMBLY_TIMEOUT)
            .pop()
            .unwrap();
        assert!(!completed.exec_confirmed);
        assert!(completed.argv_incomplete);
        assert!(!completed.reassembly_timed_out);
    }

    #[test]
    fn preserves_explicit_kernel_truncation() {
        let now = Instant::now();
        let mut assembler = ExecAssembler::default();
        assembler.push(exec_record(10, EXEC_RECORD_HEADER), now);
        assembler.push(chunk(10, 0, 0, &[b'x'; EXEC_ARG_CHUNK_PAYLOAD]), now);
        let mut end = exec_record(10, EXEC_RECORD_END);
        end.argc = 1;
        end.captured_bytes = EXEC_ARG_CHUNK_PAYLOAD as u32;
        end.flags = EXEC_FLAG_ARGV_TRUNCATED;
        assembler.push(end, now);
        let completed = assembler
            .push(exec_record(10, EXEC_RECORD_COMMIT), now)
            .pop()
            .unwrap();
        assert!(completed.argv_truncated);
        assert!(!completed.argv_incomplete);
    }

    #[test]
    fn supplements_truncated_argv_from_matching_proc_cmdline() {
        let pid = std::process::id();
        let root = std::env::temp_dir().join(format!("observer-proc-test-{pid}"));
        let proc_dir = root.join(pid.to_string());
        fs::create_dir_all(&proc_dir).unwrap();
        fs::write(
            proc_dir.join("cmdline"),
            b"/usr/bin/bash\0-c\0echo complete-dangerous-tail\0",
        )
        .unwrap();
        let mut filename = [0; 128];
        filename[..13].copy_from_slice(b"/usr/bin/bash");
        let event = CompletedExec {
            pid,
            ppid: 1,
            uid: 1000,
            comm: [0; 16],
            filename,
            argv: vec!["/usr/bin/bash".into(), "-c".into(), "echo complete".into()],
            argv_truncated: true,
            argv_incomplete: false,
            captured_argc: 3,
            captured_bytes: 32,
            reassembly_timed_out: false,
            exec_confirmed: true,
        };

        let (event, source, argc, bytes) = supplement_exec_argv_at(event, &root, 4096);
        assert_eq!(source, "proc_cmdline");
        assert_eq!(event.argv[2], "echo complete-dangerous-tail");
        assert!(!event.argv_truncated);
        assert!(!event.argv_incomplete);
        assert_eq!(argc, 3);
        assert!(bytes > event.captured_bytes);
        fs::remove_dir_all(root).unwrap();
    }

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
