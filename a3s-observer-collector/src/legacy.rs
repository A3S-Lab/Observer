use super::interaction::{ChunkDirection, InteractionReassembler, PlaintextChunk};
use super::tls_agent_scopes::TlsAgentScopeReloader;
use super::{
    cstr, emit, fallback_raw_observation, hash_prefix, identity_for, peer_ip, process_context,
    safe_unix_now_ns, CollectorMeta, Stats,
};
use a3s_observer::{
    read_ppid, AgentEvent, EnrichedEvent, EventCaptureDecision, EventTiming, Exporter,
    IdentityResolver, JsonExporter, KubeResolver, LogExporter, RawObservation, SniClassifier,
};
use a3s_observer_common::{
    classic_tls_sock_connection_id, ConnectEvent, ExitEvent, FileEvent, LegacyExecEvent,
    LegacyPlaintextEvent, SecEvent, ARGV_SLOTS, FILE_DELETE_FLAG, LEGACY_ARG_LEN,
    LEGACY_PLAINTEXT_DIRECTION_READ, LEGACY_PLAINTEXT_LEN, SEC_BIND, SEC_PTRACE, SEC_SETUID,
};
use anyhow::Context as _;
use aya::{
    maps::{perf::AsyncPerfEventArray, HashMap as BpfHashMap, MapData, PerCpuArray},
    programs::KProbe,
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use std::{
    collections::HashSet,
    mem::size_of,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

enum RawEvent {
    Exec(Box<LegacyExecEvent>),
    Exit(ExitEvent),
    Connect(ConnectEvent),
    File(Box<FileEvent>),
    Security(SecEvent),
    Plaintext(Box<LegacyPlaintextEvent>),
}

pub(crate) async fn run() -> anyhow::Result<()> {
    if matches!(std::env::args().nth(1).as_deref(), Some("--version" | "-V")) {
        println!(
            "a3s-observer-collector {} backend=perf-kprobe-legacy",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .init();

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/probes-legacy"
    )))
    .context("load Linux 4.19 legacy eBPF object")?;

    let files = std::env::var_os("A3S_OBSERVER_FILES").is_some();
    let mut attached = Vec::new();
    attach_first(
        &mut ebpf,
        "legacy_exec",
        &["__arm64_sys_execve"],
        &mut attached,
    );
    attach_first(&mut ebpf, "legacy_exit", &["do_exit"], &mut attached);
    attach_first(
        &mut ebpf,
        "legacy_connect",
        &["__arm64_sys_connect"],
        &mut attached,
    );
    attach_first(
        &mut ebpf,
        "legacy_setuid",
        &["__arm64_sys_setuid"],
        &mut attached,
    );
    attach_first(
        &mut ebpf,
        "legacy_ptrace",
        &["__arm64_sys_ptrace"],
        &mut attached,
    );
    attach_first(
        &mut ebpf,
        "legacy_bind",
        &["__arm64_sys_bind"],
        &mut attached,
    );
    if files {
        attach_first(
            &mut ebpf,
            "legacy_openat",
            &["__arm64_sys_openat"],
            &mut attached,
        );
        attach_first(
            &mut ebpf,
            "legacy_unlinkat",
            &["__arm64_sys_unlinkat"],
            &mut attached,
        );
    }

    // HTTP plaintext admission is an independent switch from TLS uprobe capture: the legacy
    // backend implements only the syscall-boundary path (kprobe write/sendto + kprobe/kretprobe
    // read/recvfrom) for identity-whitelisted PIDs. A3S_OBSERVER_SSL has no effect here — TLS
    // library probing is not implemented on Linux 4.19; warn instead of silently ignoring it.
    let plaintext_http = plaintext_http_enabled();
    if std::env::var_os("A3S_OBSERVER_SSL").is_some() {
        tracing::warn!(
            "A3S_OBSERVER_SSL is set but the perf-kprobe-legacy backend does not implement TLS uprobe capture; the setting is ignored"
        );
    }
    let mut plaintext_allowed: Option<BpfHashMap<MapData, u32, u8>> = None;
    if plaintext_http {
        for (program, symbols) in [
            ("legacy_http_write", ["__arm64_sys_write"].as_slice()),
            ("legacy_http_sendto", ["__arm64_sys_sendto"].as_slice()),
            ("legacy_http_read_enter", ["__arm64_sys_read"].as_slice()),
            (
                "legacy_http_recvfrom_enter",
                ["__arm64_sys_recvfrom"].as_slice(),
            ),
            ("legacy_http_read_exit", ["__arm64_sys_read"].as_slice()),
            (
                "legacy_http_recvfrom_exit",
                ["__arm64_sys_recvfrom"].as_slice(),
            ),
        ] {
            attach_first(&mut ebpf, program, symbols, &mut attached);
        }
        let map = BpfHashMap::try_from(
            ebpf.take_map("PLAINTEXT_ALLOWED")
                .context("`PLAINTEXT_ALLOWED` missing")?,
        )?;
        plaintext_allowed = Some(map);
    }

    let effective_probes = attached
        .iter()
        .filter(|name| {
            matches!(
                name.as_str(),
                "legacy_exec" | "legacy_connect" | "legacy_openat"
            )
        })
        .count();
    if effective_probes == 0 {
        anyhow::bail!("no effective legacy probes attached; refusing blind collector health");
    }
    tracing::info!(
        backend = "perf-kprobe-legacy",
        attached = attached.len(),
        effective_probes,
        probes = ?attached,
        "legacy Observer probes attached"
    );

    let (tx, mut rx) = mpsc::channel(4096);
    let perf_lost = Arc::new(AtomicU64::new(0));
    spawn_perf(
        &mut ebpf,
        "EVENTS",
        tx.clone(),
        perf_lost.clone(),
        wrap_exec,
    )?;
    spawn_perf(
        &mut ebpf,
        "EXIT_EVENTS",
        tx.clone(),
        perf_lost.clone(),
        RawEvent::Exit,
    )?;
    spawn_perf(
        &mut ebpf,
        "CONNECT_EVENTS",
        tx.clone(),
        perf_lost.clone(),
        RawEvent::Connect,
    )?;
    spawn_perf(
        &mut ebpf,
        "FILE_EVENTS",
        tx.clone(),
        perf_lost.clone(),
        wrap_file,
    )?;
    if plaintext_http {
        spawn_perf(
            &mut ebpf,
            "PLAINTEXT_EVENTS",
            tx.clone(),
            perf_lost.clone(),
            wrap_plaintext,
        )?;
    }
    spawn_perf(
        &mut ebpf,
        "SEC_EVENTS",
        tx,
        perf_lost.clone(),
        RawEvent::Security,
    )?;
    let drops: PerCpuArray<_, u64> =
        PerCpuArray::try_from(ebpf.take_map("DROPS").context("`DROPS` missing")?)?;

    let exporter: Box<dyn Exporter> = if std::env::var_os("A3S_OBSERVER_JSON").is_some() {
        Box::new(JsonExporter::new())
    } else {
        Box::new(LogExporter)
    };
    let resolver = KubeResolver;
    let mut collector = CollectorMeta::from_env(
        super::FileFeatureFlags {
            access: files,
            delete: files,
            read: false,
        },
        false,
        attached.len(),
    );
    collector.mode = "perf-kprobe-legacy".to_string();
    collector.enabled_features = vec![
        "exec".to_string(),
        "process-exit".to_string(),
        "network".to_string(),
        "security".to_string(),
    ];
    if files {
        collector.enabled_features.push("files".to_string());
    }
    if plaintext_http {
        collector
            .enabled_features
            .push("plaintext-http".to_string());
    }
    let classifier = SniClassifier;
    let mut plaintext_scope =
        plaintext_http.then(|| TlsAgentScopeReloader::new(plaintext_scope_path()));
    let mut interactions = plaintext_http.then(InteractionReassembler::default);
    let mut plaintext_tick = tokio::time::interval(Duration::from_secs(2));
    plaintext_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    plaintext_tick.tick().await;
    let heartbeat_path = std::env::var("A3S_OBSERVER_HEARTBEAT")
        .unwrap_or_else(|_| "/run/a3s-observer.alive".to_string());
    let _ = std::fs::write(&heartbeat_path, b"ok");

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut report = tokio::time::interval(Duration::from_secs(60));
    report.tick().await;
    let mut stats = Stats::default();
    emit_legacy_heartbeat(exporter.as_ref(), &collector, 0, &stats, 0);

    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            _ = report.tick() => {
                let _ = std::fs::write(&heartbeat_path, b"ok");
                let map_drops = drops.get(&0, 0).map(|values| values.iter().copied().sum()).unwrap_or(0);
                let dropped = map_drops + perf_lost.load(Ordering::Relaxed);
                emit_legacy_heartbeat(exporter.as_ref(), &collector, 60, &stats, dropped);
                stats = Stats::default();
            }
            _ = plaintext_tick.tick(), if plaintext_http => {
                if let (Some(reloader), Some(map)) =
                    (plaintext_scope.as_mut(), plaintext_allowed.as_mut())
                {
                    match reloader.refresh() {
                        Ok(refresh) => {
                            sync_plaintext_allowed(map, &refresh.pids);
                            if refresh.changed {
                                tracing::info!(
                                    cgroups = refresh.cgroups,
                                    pids = refresh.pids.len(),
                                    fenced_roots = refresh.fenced_roots,
                                    conflicts = refresh.conflicts,
                                    "legacy plaintext Agent cgroup scopes reconciled"
                                );
                            }
                        }
                        Err(error) => tracing::warn!(
                            error = %error,
                            "legacy plaintext scope refresh failed; retaining the last valid scope"
                        ),
                    }
                }
                if let Some(reassembler) = interactions.as_mut() {
                    reassembler.expire_idle(Instant::now());
                    let retired = reassembler.take_completed();
                    emit_plaintext_interactions(
                        exporter.as_ref(),
                        &mut stats,
                        &resolver,
                        &classifier,
                        [0u8; 16],
                        retired,
                    );
                }
            }
            raw = rx.recv() => {
                let Some(raw) = raw else { anyhow::bail!("legacy perf readers stopped"); };
                match raw {
                    RawEvent::Plaintext(ev) => {
                        if let Some(reassembler) = interactions.as_mut() {
                            let chunk = plaintext_chunk_from_event(&ev, safe_unix_now_ns());
                            let completed = reassembler.push(chunk);
                            emit_plaintext_interactions(
                                exporter.as_ref(),
                                &mut stats,
                                &resolver,
                                &classifier,
                                ev.comm,
                                completed,
                            );
                        }
                    }
                    other => handle_raw(exporter.as_ref(), &resolver, &mut stats, other),
                }
            }
        }
    }
    Ok(())
}

fn plaintext_http_enabled() -> bool {
    std::env::var("A3S_OBSERVER_PLAINTEXT_HTTP")
        .map(|value| {
            let value = value.trim();
            !value.is_empty()
                && !matches!(
                    value.to_ascii_lowercase().as_str(),
                    "0" | "false" | "off" | "no" | "disabled"
                )
        })
        .unwrap_or(false)
}

fn plaintext_scope_path() -> PathBuf {
    if let Some(path) = std::env::var_os("ANYSENTRY_TLS_AGENT_CGROUPS_FILE") {
        return PathBuf::from(path);
    }
    if let Some(rules) = std::env::var_os("ANYSENTRY_FILTER_RULES_FILE") {
        if let Some(parent) = PathBuf::from(rules).parent().map(|path| path.to_path_buf()) {
            return parent.join("tls-agent-cgroups.json");
        }
    }
    PathBuf::from("/run/anysentry-filter/tls-agent-cgroups.json")
}

fn sync_plaintext_allowed(map: &mut BpfHashMap<MapData, u32, u8>, pids: &HashSet<i32>) {
    let desired: HashSet<u32> = pids
        .iter()
        .filter_map(|pid| u32::try_from(*pid).ok())
        .collect();
    let existing: Vec<u32> = map.keys().filter_map(|key| key.ok()).collect();
    for key in existing {
        if !desired.contains(&key) {
            let _ = map.remove(&key);
        }
    }
    for pid in desired {
        if let Err(error) = map.insert(pid, 1u8, 0) {
            tracing::warn!(pid, error = %error, "legacy plaintext admission insert failed");
        }
    }
}

fn plaintext_chunk_from_event(ev: &LegacyPlaintextEvent, now_unix_ns: u128) -> PlaintextChunk {
    let len = (ev.len as usize).min(LEGACY_PLAINTEXT_LEN);
    PlaintextChunk {
        cgroup_id: 0,
        pid: ev.pid,
        // The legacy ABI carries no kernel cgroup id; (pid, fd) is the connection key. The
        // reassembler pairs requests and responses on it exactly like the modern TCP path.
        connection_id: classic_tls_sock_connection_id(0, ev.pid, u64::from(ev.fd)),
        sequence: ev.captured_at_boot_ns,
        direction: if ev.direction == LEGACY_PLAINTEXT_DIRECTION_READ {
            ChunkDirection::Response
        } else {
            ChunkDirection::Request
        },
        data: ev.data[..len].to_vec(),
        event_at_unix_ns: now_unix_ns,
        source: "tcp_plaintext".to_string(),
        adapter_id: "plain-http-syscall".to_string(),
        route_candidate: false,
        partial_reasons: if ev.len < ev.orig_len {
            vec!["probe_call_limit".to_string()]
        } else {
            Vec::new()
        },
        bind_quality: 0,
        socket_fd: ev.fd as i32,
        socket_cookie: 0,
        fd_generation: 0,
    }
}

fn emit_plaintext_interactions(
    exporter: &dyn Exporter,
    stats: &mut Stats,
    resolver: &KubeResolver,
    classifier: &SniClassifier,
    comm: [u8; 16],
    completed: Vec<super::interaction::CompletedInteraction>,
) {
    for interaction in completed {
        let now = safe_unix_now_ns();
        let timing = EventTiming::from_unix_ns(now, now);
        let capture_decision = EventCaptureDecision::new(0, 0, 0, 0, 0, false, 0);
        let raw_observation = plaintext_raw_observation(&interaction.interaction_id, &timing);
        super::emit_completed_interaction(
            exporter,
            stats,
            resolver,
            classifier,
            comm,
            timing,
            capture_decision,
            raw_observation,
            Vec::new(),
            interaction,
        );
    }
}

/// Provenance record for a legacy syscall-boundary plaintext interaction. The dummy event fed
/// to `fallback_raw_observation` only seeds the hash token shape; identity is pinned to the
/// interaction id and the source fields honestly describe the syscall probe.
fn plaintext_raw_observation(interaction_id: &str, timing: &EventTiming) -> RawObservation {
    let mut raw = fallback_raw_observation(
        &AgentEvent::ProcessExit {
            pid: 0,
            exit_code: 0,
            signal: 0,
        },
        Some(timing),
    );
    let token = hash_prefix(format!("legacy-tcp|{interaction_id}").as_bytes());
    raw.observation_id = format!("ro_{token}");
    raw.idempotency_key = format!("idem_{token}");
    raw.source.source_type = "socket_payload".to_string();
    raw.source.probe_id = Some("plain-http-syscall".to_string());
    raw.payload.kind = "tls_plaintext_chunk".to_string();
    raw.payload.encoding = Some("binary".to_string());
    raw.payload.redaction_state = "hash_only".to_string();
    raw
}

fn attach_first(ebpf: &mut Ebpf, program: &str, symbols: &[&str], attached: &mut Vec<String>) {
    let Some(raw) = ebpf.program_mut(program) else {
        tracing::warn!(program, "legacy probe program missing");
        return;
    };
    let probe: &mut KProbe = match raw.try_into() {
        Ok(probe) => probe,
        Err(error) => {
            tracing::warn!(program, error = %error, "legacy program type mismatch");
            return;
        }
    };
    if let Err(error) = probe.load() {
        tracing::warn!(program, error = %error, "legacy probe load failed");
        return;
    }
    for symbol in symbols {
        match probe.attach(symbol, 0) {
            Ok(_) => {
                attached.push(program.to_string());
                tracing::info!(program, symbol, "legacy probe attached");
                return;
            }
            Err(error) => {
                tracing::warn!(program, symbol, error = %error, "legacy symbol unavailable")
            }
        }
    }
}

fn spawn_perf<T: Copy + Send + 'static>(
    ebpf: &mut Ebpf,
    map_name: &str,
    tx: mpsc::Sender<RawEvent>,
    lost: Arc<AtomicU64>,
    wrap: fn(T) -> RawEvent,
) -> anyhow::Result<()> {
    let mut array = AsyncPerfEventArray::try_from(
        ebpf.take_map(map_name)
            .with_context(|| format!("`{map_name}` missing"))?,
    )?;
    for cpu in online_cpus().map_err(|(_, error)| error)? {
        let mut buffer = array.open(cpu, Some(8))?;
        let tx = tx.clone();
        let lost = lost.clone();
        tokio::spawn(async move {
            let mut slots = (0..32)
                .map(|_| BytesMut::with_capacity(size_of::<T>()))
                .collect::<Vec<_>>();
            loop {
                let events = match buffer.read_events(&mut slots).await {
                    Ok(events) => events,
                    Err(error) => {
                        tracing::error!(cpu, error = %error, "legacy perf reader failed");
                        break;
                    }
                };
                lost.fetch_add(events.lost as u64, Ordering::Relaxed);
                for slot in slots.iter().take(events.read) {
                    if let Some(value) = read_value::<T>(slot) {
                        if tx.send(wrap(value)).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
    }
    Ok(())
}

fn read_value<T: Copy>(bytes: &[u8]) -> Option<T> {
    (bytes.len() >= size_of::<T>())
        .then(|| unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

fn wrap_exec(event: LegacyExecEvent) -> RawEvent {
    RawEvent::Exec(Box::new(event))
}

fn wrap_file(event: FileEvent) -> RawEvent {
    RawEvent::File(Box::new(event))
}

fn wrap_plaintext(event: LegacyPlaintextEvent) -> RawEvent {
    RawEvent::Plaintext(Box::new(event))
}

fn legacy_argv(event: &LegacyExecEvent) -> Vec<String> {
    event.args[..(event.argc as usize).min(ARGV_SLOTS)]
        .iter()
        .map(|arg| cstr(arg))
        .filter(|arg| !arg.is_empty())
        .collect()
}

fn handle_raw(exporter: &dyn Exporter, resolver: &KubeResolver, stats: &mut Stats, raw: RawEvent) {
    let enriched = match raw {
        RawEvent::Exec(ev) => {
            let argv = legacy_argv(&ev);
            let captured_argc = argv.len().min(u16::MAX as usize) as u16;
            let captured_bytes = argv
                .iter()
                .fold(0usize, |total, arg| total.saturating_add(arg.len()))
                .min(u32::MAX as usize) as u32;
            let argv_truncated = ev.argc as usize >= ARGV_SLOTS
                || ev.args[..(ev.argc as usize).min(ARGV_SLOTS)]
                    .iter()
                    .any(|arg| arg[LEGACY_ARG_LEN - 1] != 0);
            let ppid = read_ppid(ev.pid);
            legacy_enriched(
                identity_for(resolver, ev.pid, 0, &ev.comm),
                resolver.resolve_workload(ev.pid, 0, 0),
                Some(process_context(ev.pid, 0, &ev.comm)),
                AgentEvent::ToolExec {
                    // Linux 4.19 perf ABI has no kernel exec generation. Zero marks that absence.
                    exec_id: 0,
                    exec_id_exact: "0".to_string(),
                    pid: ev.pid,
                    ppid,
                    uid: ev.uid,
                    argv,
                    argv_truncated,
                    argv_incomplete: false,
                    exec_confirmed: false,
                    argv_source: "legacy-kprobe".to_string(),
                    captured_argc,
                    captured_bytes,
                    observed_argc: captured_argc as u32,
                    observed_bytes: captured_bytes,
                    cwd: super::read_cwd(ev.pid),
                },
            )
        }
        RawEvent::Exit(ev) => legacy_enriched(
            identity_for(resolver, ev.pid, ev.cgroup_id, &ev.comm),
            resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
            Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
            AgentEvent::ProcessExit {
                pid: ev.pid,
                exit_code: ev.exit_code,
                signal: ev.signal,
            },
        ),
        RawEvent::Connect(ev) => legacy_enriched(
            identity_for(resolver, ev.pid, ev.cgroup_id, &ev.comm),
            resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
            Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
            AgentEvent::Egress {
                pid: ev.pid,
                sni: None,
                peer: peer_ip(&ev),
                port: ev.port,
                bytes: 0,
                fd: None,
            },
        ),
        RawEvent::File(ev) => {
            let path = cstr(&ev.path);
            if ev.flags == FILE_DELETE_FLAG {
                legacy_enriched(
                    identity_for(resolver, ev.pid, ev.cgroup_id, &ev.comm),
                    resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
                    Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
                    AgentEvent::FileDelete { pid: ev.pid, path },
                )
            } else {
                legacy_enriched(
                    identity_for(resolver, ev.pid, ev.cgroup_id, &ev.comm),
                    resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
                    Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
                    AgentEvent::FileAccess {
                        pid: ev.pid,
                        path,
                        write: true,
                        access_mode: "write".to_string(),
                    },
                )
            }
        }
        RawEvent::Security(ev) => legacy_enriched(
            identity_for(resolver, ev.pid, ev.cgroup_id, &ev.comm),
            resolver.resolve_workload(ev.pid, ev.cgroup_id, 0),
            Some(process_context(ev.pid, ev.cgroup_id, &ev.comm)),
            AgentEvent::SecurityAction {
                pid: ev.pid,
                kind: match ev.kind {
                    SEC_SETUID => "setuid-root",
                    SEC_PTRACE => "ptrace",
                    SEC_BIND => "bind",
                    _ => "unknown",
                },
                detail: ev.detail,
            },
        ),
        // Plaintext chunks are intercepted in the main loop before handle_raw; this arm only
        // exists so the match stays exhaustive.
        RawEvent::Plaintext(_) => return,
    };
    let ring = match &enriched.event {
        AgentEvent::ToolExec { .. } => super::PipelineRing::Exec,
        AgentEvent::ProcessExit { .. } => super::PipelineRing::Exit,
        AgentEvent::Egress { .. } => super::PipelineRing::Connect,
        AgentEvent::FileAccess { .. } => super::PipelineRing::FileAccess,
        AgentEvent::FileDelete { .. } => super::PipelineRing::FileDelete,
        AgentEvent::SecurityAction { .. } => super::PipelineRing::Security,
        _ => super::PipelineRing::Security,
    };
    emit(exporter, stats, ring, enriched);
}

fn emit_legacy_heartbeat(
    exporter: &dyn Exporter,
    collector: &CollectorMeta,
    interval_secs: u64,
    stats: &Stats,
    dropped: u64,
) {
    let event = super::collector_heartbeat(
        collector,
        interval_secs,
        stats,
        dropped,
        exporter.output_drops(),
        super::FileFilterHeartbeatSnapshot::default(),
        None,
        None,
        None,
        Vec::new(),
        false,
    );
    exporter.export(&event);
}

fn legacy_enriched(
    identity: a3s_observer::Identity,
    workload: Option<a3s_observer::WorkloadIdentity>,
    process: Option<a3s_observer::ProcessContext>,
    event: AgentEvent,
) -> EnrichedEvent {
    EnrichedEvent {
        timing: None,
        capture_decision: None,
        identity,
        workload,
        observation: None,
        raw_observation: None,
        coverage_gaps: Vec::new(),
        process,
        provider: None,
        event,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plaintext_event(direction: u32, len: u32, orig_len: u32) -> LegacyPlaintextEvent {
        let mut event = LegacyPlaintextEvent {
            pid: 4242,
            fd: 7,
            direction,
            len,
            orig_len,
            _pad: 0,
            comm: [0u8; 16],
            captured_at_boot_ns: 123_456_789,
            data: [0u8; LEGACY_PLAINTEXT_LEN],
        };
        event.data[..5].copy_from_slice(b"GET /");
        event
    }

    #[test]
    fn plaintext_chunk_maps_request_direction_and_bounds_payload() {
        let chunk = plaintext_chunk_from_event(&plaintext_event(0, 5, 5), 999);
        assert!(matches!(chunk.direction, ChunkDirection::Request));
        assert_eq!(chunk.data, b"GET /");
        assert_eq!(chunk.pid, 4242);
        assert_eq!(chunk.sequence, 123_456_789);
        assert_eq!(chunk.source, "tcp_plaintext");
        assert_eq!(chunk.adapter_id, "plain-http-syscall");
        assert!(chunk.partial_reasons.is_empty());
        assert_eq!(
            chunk.connection_id,
            classic_tls_sock_connection_id(0, 4242, 7),
            "connection identity must be the (pid, fd) join"
        );
    }

    #[test]
    fn plaintext_chunk_maps_response_and_marks_truncation() {
        let chunk = plaintext_chunk_from_event(
            &plaintext_event(LEGACY_PLAINTEXT_DIRECTION_READ, 512, 4096),
            999,
        );
        assert!(matches!(chunk.direction, ChunkDirection::Response));
        assert_eq!(chunk.partial_reasons, vec!["probe_call_limit".to_string()]);
    }

    #[test]
    fn plaintext_chunk_never_overruns_the_fixed_payload() {
        // A corrupted length field must not read past the fixed record.
        let chunk = plaintext_chunk_from_event(&plaintext_event(0, u32::MAX, u32::MAX), 999);
        assert_eq!(chunk.data.len(), LEGACY_PLAINTEXT_LEN);
    }

    #[test]
    fn plaintext_http_switch_parsing_matches_operator_convention() {
        // The switch shares the SSL switch's truthy/disabled vocabulary (see
        // plaintext_admission_enabled in the modern backend).
        for (value, expected) in [
            (Some("1"), true),
            (Some("on"), true),
            (Some(" 1 "), true),
            (Some("0"), false),
            (Some("off"), false),
            (Some("disabled"), false),
            (None, false),
        ] {
            match value {
                Some(v) => std::env::set_var("A3S_OBSERVER_PLAINTEXT_HTTP", v),
                None => std::env::remove_var("A3S_OBSERVER_PLAINTEXT_HTTP"),
            }
            assert_eq!(plaintext_http_enabled(), expected, "value={value:?}");
        }
        std::env::remove_var("A3S_OBSERVER_PLAINTEXT_HTTP");
    }
}
