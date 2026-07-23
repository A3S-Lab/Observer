use super::{cstr, emit, identity_for, peer_ip, process_context, CollectorMeta, Stats};
use a3s_observer::{
    read_ppid, AgentEvent, EnrichedEvent, Exporter, IdentityResolver, JsonExporter, KubeResolver,
    LogExporter,
};
use a3s_observer_common::{
    ConnectEvent, ExitEvent, FileEvent, LegacyExecEvent, SecEvent, ARGV_SLOTS, FILE_DELETE_FLAG,
    LEGACY_ARG_LEN, SEC_BIND, SEC_PTRACE, SEC_SETUID,
};
use anyhow::Context as _;
use aya::{
    maps::{perf::AsyncPerfEventArray, PerCpuArray},
    programs::KProbe,
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use std::{
    mem::size_of,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::mpsc;

enum RawEvent {
    Exec(Box<LegacyExecEvent>),
    Exit(ExitEvent),
    Connect(ConnectEvent),
    File(Box<FileEvent>),
    Security(SecEvent),
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
    let mut collector = CollectorMeta::from_env(files, false, attached.len());
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
    let heartbeat_path = std::env::var("A3S_OBSERVER_HEARTBEAT")
        .unwrap_or_else(|_| "/run/a3s-observer.alive".to_string());
    let _ = std::fs::write(&heartbeat_path, b"ok");

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut report = tokio::time::interval(Duration::from_secs(60));
    report.tick().await;
    let mut stats = Stats::default();
    super::emit_collector_heartbeat(
        exporter.as_ref(),
        &collector,
        0,
        &stats,
        0,
        exporter.output_drops(),
    );

    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            _ = report.tick() => {
                let _ = std::fs::write(&heartbeat_path, b"ok");
                let map_drops = drops.get(&0, 0).map(|values| values.iter().copied().sum()).unwrap_or(0);
                let dropped = map_drops + perf_lost.load(Ordering::Relaxed);
                super::emit_collector_heartbeat(exporter.as_ref(), &collector, 60, &stats, dropped, exporter.output_drops());
                stats = Stats::default();
            }
            raw = rx.recv() => {
                let Some(raw) = raw else { anyhow::bail!("legacy perf readers stopped"); };
                handle_raw(exporter.as_ref(), &resolver, &mut stats, raw);
            }
        }
    }
    Ok(())
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
            EnrichedEvent {
                identity: identity_for(resolver, ev.pid, &ev.comm),
                workload: resolver.resolve_workload(ev.pid, 0, 0),
                observation: None,
                process: Some(process_context(ev.pid, &ev.comm)),
                provider: None,
                event: AgentEvent::ToolExec {
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
            }
        }
        RawEvent::Exit(ev) => EnrichedEvent {
            identity: identity_for(resolver, ev.pid, &ev.comm),
            workload: resolver.resolve_workload(ev.pid, 0, 0),
            observation: None,
            process: Some(process_context(ev.pid, &ev.comm)),
            provider: None,
            event: AgentEvent::ProcessExit {
                pid: ev.pid,
                exit_code: ev.exit_code,
                signal: ev.signal,
            },
        },
        RawEvent::Connect(ev) => EnrichedEvent {
            identity: identity_for(resolver, ev.pid, &ev.comm),
            workload: resolver.resolve_workload(ev.pid, 0, 0),
            observation: None,
            process: Some(process_context(ev.pid, &ev.comm)),
            provider: None,
            event: AgentEvent::Egress {
                pid: ev.pid,
                sni: None,
                peer: peer_ip(&ev),
                port: ev.port,
                bytes: 0,
            },
        },
        RawEvent::File(ev) => {
            let path = cstr(&ev.path);
            if ev.flags == FILE_DELETE_FLAG {
                EnrichedEvent {
                    identity: identity_for(resolver, ev.pid, &ev.comm),
                    workload: resolver.resolve_workload(ev.pid, 0, 0),
                    observation: None,
                    process: Some(process_context(ev.pid, &ev.comm)),
                    provider: None,
                    event: AgentEvent::FileDelete { pid: ev.pid, path },
                }
            } else {
                EnrichedEvent {
                    identity: identity_for(resolver, ev.pid, &ev.comm),
                    workload: resolver.resolve_workload(ev.pid, 0, 0),
                    observation: None,
                    process: Some(process_context(ev.pid, &ev.comm)),
                    provider: None,
                    event: AgentEvent::FileAccess {
                        pid: ev.pid,
                        path,
                        write: true,
                    },
                }
            }
        }
        RawEvent::Security(ev) => EnrichedEvent {
            identity: identity_for(resolver, ev.pid, &ev.comm),
            workload: resolver.resolve_workload(ev.pid, 0, 0),
            observation: None,
            process: Some(process_context(ev.pid, &ev.comm)),
            provider: None,
            event: AgentEvent::SecurityAction {
                pid: ev.pid,
                kind: match ev.kind {
                    SEC_SETUID => "setuid-root",
                    SEC_PTRACE => "ptrace",
                    SEC_BIND => "bind",
                    _ => "unknown",
                },
                detail: ev.detail,
            },
        },
    };
    emit(exporter, stats, enriched);
}
