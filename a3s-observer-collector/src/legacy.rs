//! Linux 4.19 legacy (perf-kprobe) collector backend.
//!
//! Plaintext latency contract: interactions that do not complete on the wire are flushed at the
//! reassembler idle boundary, not immediately. A quiet connection (one-off probe GET, health
//! check, short POST) therefore takes the reassembler idle timeout (90s by default) plus the
//! 2s plaintext tick to appear in storage, instead of the sub-second latency of a completed
//! request/response pair. Acceptance scripts must wait beyond that boundary before declaring
//! plaintext capture missing; it is normal for a first event to arrive roughly 60-90s late.
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
    classic_tls_sock_connection_id, fnv1a64, ConnectEvent, ExitEvent, FileEvent,
    LegacyCursorExt, LegacyExecEvent, LegacyPlaintextEvent, LegacyTlsPlaintextEvent, SecEvent,
    A3S_CONFIG_FLAG_CURSOR_REREAD, ARGV_SLOTS, FILE_DELETE_FLAG, LEGACY_ARG_LEN,
    LEGACY_CURSOR_EXT_MAGIC, LEGACY_CURSOR_TAIL_LEN, LEGACY_PLAINTEXT_DIRECTION_READ,
    LEGACY_PLAINTEXT_LEN, SEC_BIND, SEC_PTRACE, SEC_SETUID,
};
use anyhow::Context as _;
use aya::{
    maps::{perf::AsyncPerfEventArray, Array as BpfArray, HashMap as BpfHashMap, MapData, PerCpuArray},
    programs::{KProbe, ProgramError, UProbe, UProbeError},
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet, VecDeque},
    mem::size_of,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

/// Syscall kprobe symbol prefix for the target architecture.
/// UOS 20 ARM64 exposes `__arm64_sys_*` aliases; x86_64 kernels expose `__x64_sys_*`.
macro_rules! sys_sym {
    ($name:literal) => {{
        #[cfg(target_arch = "aarch64")]
        { concat!("__arm64_sys_", $name) }
        #[cfg(not(target_arch = "aarch64"))]
        { concat!("__x64_sys_", $name) }
    }};
}

enum RawEvent {
    Exec(Box<LegacyExecEvent>),
    Exit(ExitEvent),
    Connect(ConnectEvent),
    File(Box<FileEvent>),
    Security(SecEvent),
    Plaintext(Box<LegacyPlaintextEvent>, Option<LegacyCursorExt>),
    PlaintextTls(Box<LegacyTlsPlaintextEvent>, Option<LegacyCursorExt>),
}

// Diagnostic counters (UOS 4.19 field investigation): the legacy plaintext path produced zero
// events on the customer kernel while every static check passed. Count and preview what (if
// anything) arrives from the PLAINTEXT_EVENTS ring, and log every completed interaction.
static PLAINTEXT_CHUNK_SEEN: AtomicU64 = AtomicU64::new(0);
static PLAINTEXT_TLS_CHUNK_SEEN: AtomicU64 = AtomicU64::new(0);
static PLAINTEXT_INTERACTION_SEEN: AtomicU64 = AtomicU64::new(0);

// R3 截断补读计数器：拼接成功/字节数与四类拒绝，60s 心跳周期随 report tick 输出。
static CURSOR_PATCHED: AtomicU64 = AtomicU64::new(0);
static CURSOR_PATCH_BYTES: AtomicU64 = AtomicU64::new(0);
static CURSOR_REJECT_TTL: AtomicU64 = AtomicU64::new(0);
static CURSOR_REJECT_SELF_FNV: AtomicU64 = AtomicU64::new(0);
static CURSOR_REJECT_OVERLAP_FNV: AtomicU64 = AtomicU64::new(0);
static CURSOR_REJECT_READ: AtomicU64 = AtomicU64::new(0);
static DUPLICATE_FRAGMENT_SUPPRESSED: AtomicU64 = AtomicU64::new(0);

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
        &[sys_sym!("execve")],
        &mut attached,
    );
    attach_first(&mut ebpf, "legacy_exit", &["do_exit"], &mut attached);
    attach_first(
        &mut ebpf,
        "legacy_connect",
        &[sys_sym!("connect")],
        &mut attached,
    );
    attach_first(
        &mut ebpf,
        "legacy_setuid",
        &[sys_sym!("setuid")],
        &mut attached,
    );
    attach_first(
        &mut ebpf,
        "legacy_ptrace",
        &[sys_sym!("ptrace")],
        &mut attached,
    );
    attach_first(
        &mut ebpf,
        "legacy_bind",
        &[sys_sym!("bind")],
        &mut attached,
    );
    if files {
        attach_first(
            &mut ebpf,
            "legacy_openat",
            &[sys_sym!("openat")],
            &mut attached,
        );
        attach_first(
            &mut ebpf,
            "legacy_unlinkat",
            &[sys_sym!("unlinkat")],
            &mut attached,
        );
    }

    // HTTP plaintext admission is an independent switch from TLS uprobe capture. The legacy
    // backend implements both: the syscall-boundary path (kprobe write/sendto + kprobe/kretprobe
    // read/recvfrom) and, when A3S_OBSERVER_SSL is set, OpenSSL uprobe capture
    // (SSL_write entry / SSL_read entry+return) on whitelisted processes' libssl — the
    // AgentSight-style user-space path; connection identity is the SSL* pointer.
    let plaintext_http = plaintext_http_enabled();
    let ssl_uprobes = plaintext_http && ssl_uprobes_enabled();
    let mut ssl_manager = ssl_uprobes.then(SslUprobeManager::default);
    let mut plaintext_allowed: Option<BpfHashMap<MapData, u32, u8>> = None;
    if plaintext_http {
        for (program, symbols) in [
            ("legacy_http_write", [sys_sym!("write")].as_slice()),
            ("legacy_http_sendto", [sys_sym!("sendto")].as_slice()),
            ("legacy_http_read_enter", [sys_sym!("read")].as_slice()),
            (
                "legacy_http_recvfrom_enter",
                [sys_sym!("recvfrom")].as_slice(),
            ),
            ("legacy_http_read_exit", [sys_sym!("read")].as_slice()),
            (
                "legacy_http_recvfrom_exit",
                [sys_sym!("recvfrom")].as_slice(),
            ),
            ("legacy_http_accept_ret", [sys_sym!("accept")].as_slice()),
            ("legacy_http_accept4_ret", [sys_sym!("accept4")].as_slice()),
            ("legacy_http_close", [sys_sym!("close")].as_slice()),
        ] {
            attach_first(&mut ebpf, program, symbols, &mut attached);
        }
        let map = BpfHashMap::try_from(
            ebpf.take_map("PLAINTEXT_ALLOWED")
                .context("`PLAINTEXT_ALLOWED` missing")?,
        )?;
        plaintext_allowed = Some(map);
    }

    // R3 截断补读：默认关。开启时置位 BPF 运行时开关（A3S_RUNTIME_CONFIG[0] bit0），
    // 窗口用尽末片才开始携带续读游标扩展；map 缺失（arm64 冻结对象）时特性整体关闭。
    let cursor_rereader = if plaintext_http {
        CursorRereader::from_env().and_then(|rereader| match enable_cursor_reread(&mut ebpf) {
            Ok(()) => {
                tracing::info!(
                    max_bytes = rereader.max_bytes,
                    ttl_ns = rereader.ttl_ns,
                    "legacy cursor reread enabled"
                );
                Some(rereader)
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "legacy cursor reread unavailable; leaving BPF cursor generation off"
                );
                None
            }
        })
    } else {
        None
    };

    // Dev-machine x86_64 diagnosis (A3S_BPF_DIAG build only): unconditional connect-boundary
    // trace_printk probe. Absent from the frozen arm64 object; attach is a no-op then.
    if std::env::var_os("A3S_OBSERVER_DIAG").is_some() {
        attach_first(&mut ebpf, "legacy_diag_connect", &[sys_sym!("connect")], &mut attached);
        attach_first(&mut ebpf, "legacy_diag_sysconnect", &["__sys_connect"], &mut attached);
        attach_first(&mut ebpf, "legacy_diag_ksysread", &["ksys_read"], &mut attached);
        attach_first(&mut ebpf, "legacy_diag_ksysread_ret", &["ksys_read"], &mut attached);
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

    let ring_pages = perf_ring_pages();
    let (tx, mut rx) = mpsc::channel(4096);
    let perf_lost = Arc::new(PerfLostCounters::default());
    spawn_perf(
        &mut ebpf,
        "EVENTS",
        tx.clone(),
        perf_lost.clone(),
        wrap_exec,
        ring_pages,
    )?;
    spawn_perf(
        &mut ebpf,
        "EXIT_EVENTS",
        tx.clone(),
        perf_lost.clone(),
        RawEvent::Exit,
        ring_pages,
    )?;
    spawn_perf(
        &mut ebpf,
        "CONNECT_EVENTS",
        tx.clone(),
        perf_lost.clone(),
        RawEvent::Connect,
        ring_pages,
    )?;
    spawn_perf(
        &mut ebpf,
        "FILE_EVENTS",
        tx.clone(),
        perf_lost.clone(),
        wrap_file,
        ring_pages,
    )?;
    if plaintext_http {
        spawn_plaintext_perf(
            &mut ebpf,
            "PLAINTEXT_EVENTS",
            tx.clone(),
            perf_lost.clone(),
            ring_pages,
        )?;
    }
    if ssl_uprobes {
        spawn_tls_plaintext_perf(
            &mut ebpf,
            "PLAINTEXT_TLS_EVENTS",
            tx.clone(),
            perf_lost.clone(),
            ring_pages,
        )?;
    }
    spawn_perf(
        &mut ebpf,
        "SEC_EVENTS",
        tx,
        perf_lost.clone(),
        RawEvent::Security,
        ring_pages,
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
    if ssl_uprobes {
        collector
            .enabled_features
            .push("openssl-uprobe".to_string());
    }
    if cursor_rereader.is_some() {
        collector
            .enabled_features
            .push("cursor-reread".to_string());
    }
    let classifier = SniClassifier;
    let mut plaintext_scope =
        plaintext_http.then(|| TlsAgentScopeReloader::new(plaintext_scope_path()));
    let mut interactions = plaintext_http.then(|| {
        InteractionReassembler::with_idle_lanes(
            InteractionReassembler::reassembly_idle_timeout(),
            InteractionReassembler::inflight_idle_timeout(),
        )
    });
    let mut sequencer = PlaintextSequencer::default();
    let mut fragment_dedup = FragmentDedup::default();
    let mut suppressed_shells = 0u64;
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
    let mut ssl_attach_diag = tokio::time::interval(Duration::from_secs(30));
    ssl_attach_diag.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ssl_attach_diag.tick().await;
    let mut stats = Stats::default();
    emit_legacy_heartbeat(
        exporter.as_ref(),
        &collector,
        0,
        &stats,
        0,
        Some(perf_lost.snapshot()),
    );

    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            _ = ssl_attach_diag.tick(), if ssl_uprobes => {
                if let Some(manager) = ssl_manager.as_ref() {
                    manager.log_attach_summary();
                }
            }
            _ = report.tick() => {
                let _ = std::fs::write(&heartbeat_path, b"ok");
                let map_drops = drops.get(&0, 0).map(|values| values.iter().copied().sum()).unwrap_or(0);
                let dropped = map_drops + perf_lost.total();
                emit_legacy_heartbeat(
                    exporter.as_ref(),
                    &collector,
                    60,
                    &stats,
                    dropped,
                    Some(perf_lost.snapshot()),
                );
                if suppressed_shells > 0 {
                    // Unparsed interactions with zero request/response payload are noise (idle
                    // expiries, non-HTTP streams). They are counted here instead of occupying
                    // interaction rows the conversation view cannot render anyway.
                    tracing::info!(
                        suppressed = suppressed_shells,
                        "legacy plaintext empty-shell interactions demoted to metrics"
                    );
                    suppressed_shells = 0;
                }
                {
                    // R3 截断补读 60s 窗口统计：拼接成功/字节与四类拒绝（默认关时恒零不输出）。
                    let patched = CURSOR_PATCHED.swap(0, Ordering::Relaxed);
                    let patched_bytes = CURSOR_PATCH_BYTES.swap(0, Ordering::Relaxed);
                    let reject_ttl = CURSOR_REJECT_TTL.swap(0, Ordering::Relaxed);
                    let reject_self = CURSOR_REJECT_SELF_FNV.swap(0, Ordering::Relaxed);
                    let reject_overlap = CURSOR_REJECT_OVERLAP_FNV.swap(0, Ordering::Relaxed);
                    let reject_read = CURSOR_REJECT_READ.swap(0, Ordering::Relaxed);
                    if patched > 0
                        || reject_ttl > 0
                        || reject_self > 0
                        || reject_overlap > 0
                        || reject_read > 0
                    {
                        tracing::info!(
                            patched,
                            patched_bytes,
                            reject_ttl,
                            reject_self_fingerprint = reject_self,
                            reject_overlap_fingerprint = reject_overlap,
                            reject_read,
                            "legacy cursor reread stats (60s window)"
                        );
                    }
                }
                let duplicate_fragment_suppressed =
                    DUPLICATE_FRAGMENT_SUPPRESSED.swap(0, Ordering::Relaxed);
                if duplicate_fragment_suppressed > 0 {
                    tracing::info!(
                        duplicate_fragment_suppressed,
                        "legacy plaintext duplicate fragment suppression stats (60s window)"
                    );
                }
                stats = Stats::default();
            }
            _ = plaintext_tick.tick(), if plaintext_http => {
                if let (Some(reloader), Some(map)) =
                    (plaintext_scope.as_mut(), plaintext_allowed.as_mut())
                {
                    let mut attach_pids: Option<HashSet<i32>> = None;
                    match reloader.refresh() {
                        Ok(refresh) => {
                            sync_plaintext_allowed(map, &refresh.pids);
                            if ssl_manager.is_some() {
                                attach_pids = Some(refresh.pids.clone());
                            }
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
                    if let (Some(manager), Some(pids)) = (ssl_manager.as_mut(), attach_pids) {
                        manager.ensure_attached(&mut ebpf, &pids);
                    }
                }
                if let Some(reassembler) = interactions.as_mut() {
                    fragment_dedup.expire_idle(
                        boot_now_ns(),
                        InteractionReassembler::reassembly_idle_timeout(),
                    );
                    reassembler.expire_idle(Instant::now());
                    let retired = reassembler.take_completed();
                    emit_plaintext_interactions(
                        exporter.as_ref(),
                        &mut stats,
                        &resolver,
                        &classifier,
                        [0u8; 16],
                        retired,
                        &mut suppressed_shells,
                    );
                }
            }
            raw = rx.recv() => {
                let Some(raw) = raw else { anyhow::bail!("legacy perf readers stopped"); };
                match raw {
                    RawEvent::Plaintext(ev, cursor) => {
                        let seen = PLAINTEXT_CHUNK_SEEN.fetch_add(1, Ordering::Relaxed) + 1;
                        if seen <= 50 || seen.is_multiple_of(500) {
                            let take = (ev.len as usize).min(32).min(ev.data.len());
                            let preview: String = ev.data[..take]
                                .iter()
                                .map(|b| {
                                    if b.is_ascii_graphic() || *b == b' ' {
                                        *b as char
                                    } else {
                                        '.'
                                    }
                                })
                                .collect();
                            tracing::info!(
                                seen,
                                pid = ev.pid,
                                fd = ev.fd,
                                direction = ev.direction,
                                len = ev.len,
                                orig_len = ev.orig_len,
                                read_rc1 = ev._pad & 0xffff,
                                read_rc2 = (ev._pad >> 16) & 0xffff,
                                preview = %preview,
                                "legacy plaintext chunk received"
                            );
                        }
                        if let Some(reassembler) = interactions.as_mut() {
                            let mut chunk = plaintext_chunk_from_event(
                                &ev,
                                safe_unix_now_ns(),
                                &mut sequencer,
                            );
                            let duplicate = suppress_duplicate_fragment(
                                &mut fragment_dedup,
                                &mut sequencer,
                                &chunk,
                                ev.orig_len,
                                ev.captured_at_boot_ns,
                                ev.fd,
                                ev.fd_generation,
                            );
                            let completed = if duplicate {
                                Vec::new()
                            } else if cursor_patch_and_log(
                                cursor_rereader.as_ref(),
                                cursor,
                                &mut chunk,
                                ev.captured_at_boot_ns,
                            ) {
                                reassembler.push(chunk)
                            } else {
                                Vec::new()
                            };
                            emit_plaintext_interactions(
                                exporter.as_ref(),
                                &mut stats,
                                &resolver,
                                &classifier,
                                ev.comm,
                                completed,
                                &mut suppressed_shells,
                            );
                        }
                    }
                    RawEvent::PlaintextTls(ev, cursor) => {
                        let seen = PLAINTEXT_TLS_CHUNK_SEEN.fetch_add(1, Ordering::Relaxed) + 1;
                        if seen <= 50 || seen.is_multiple_of(500) {
                            let take = (ev.len as usize).min(32).min(ev.data.len());
                            let preview: String = ev.data[..take]
                                .iter()
                                .map(|b| {
                                    if b.is_ascii_graphic() || *b == b' ' {
                                        *b as char
                                    } else {
                                        '.'
                                    }
                                })
                                .collect();
                            tracing::info!(
                                seen,
                                pid = ev.pid,
                                tls_ctx = ev.tls_ctx,
                                connection_id = ev.tls_ctx ^ 0x5353_6c73_0000_0000,
                                captured_at_boot_ns = ev.captured_at_boot_ns,
                                direction = ev.direction,
                                len = ev.len,
                                orig_len = ev.orig_len,
                                preview = %preview,
                                "legacy tls plaintext chunk received"
                            );
                        }
                        if let Some(reassembler) = interactions.as_mut() {
                            let mut chunk = tls_plaintext_chunk_from_event(
                                &ev,
                                safe_unix_now_ns(),
                                &mut sequencer,
                            );
                            let duplicate = suppress_duplicate_fragment(
                                &mut fragment_dedup,
                                &mut sequencer,
                                &chunk,
                                ev.orig_len,
                                ev.captured_at_boot_ns,
                                ev.tls_ctx as u32,
                                (ev.tls_ctx >> 32) as u32,
                            );
                            let completed = if duplicate {
                                Vec::new()
                            } else if cursor_patch_and_log(
                                cursor_rereader.as_ref(),
                                cursor,
                                &mut chunk,
                                ev.captured_at_boot_ns,
                            ) {
                                reassembler.push(chunk)
                            } else {
                                Vec::new()
                            };
                            emit_plaintext_interactions(
                                exporter.as_ref(),
                                &mut stats,
                                &resolver,
                                &classifier,
                                ev.comm,
                                completed,
                                &mut suppressed_shells,
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

fn ssl_uprobes_enabled() -> bool {
    // Opt-in user-space OpenSSL capture on the legacy backend (AgentSight-style):
    // attaches uprobe/uretprobe to libssl SSL_write/SSL_read of whitelisted processes.
    // User-space reads go through probe_read_user (helper 112/114) — PAN-safe on the
    // UOS 4.19 backport and verified on the dev host's 5.14.
    std::env::var_os("A3S_OBSERVER_SSL").is_some()
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

/// CLOCK_MONOTONIC nanoseconds — the same clock as the BPF-side `captured_at_boot_ns`,
/// so cursor TTL compares like with like.
fn boot_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out-pointer; clock_gettime with CLOCK_MONOTONIC cannot fail.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// R3 截断补读（见 probes.c 游标扩展注释）：窗口用尽末片携带续读游标时，用
/// process_vm_readv 从目标进程内存补读剩余部分。默认关（A3S_OBSERVER_CURSOR_REREAD）；
/// 开启后 collector 在加载后置位 A3S_RUNTIME_CONFIG[0]，BPF 才开始产生游标。
struct CursorRereader {
    max_bytes: usize,
    ttl_ns: u64,
    claims: RefCell<VecDeque<CursorClaim>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CursorClaim {
    pid: u32,
    connection_id: u64,
    resume_buf: u64,
    remaining: u32,
    tail_fnv64: u64,
}

const CURSOR_CLAIM_LIMIT: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatchReject {
    /// 游标超过 TTL：buffer 大概率已被复用，拼接风险不可接受。
    TtlExpired,
    /// chunk 自带尾部与游标指纹不一致（解析串道/数据被改写）。
    SelfFingerprint,
    /// 补读到的衔接处 64B 与已采尾部指纹不一致：目标内存已变，错拼风险。
    OverlapFingerprint,
    /// process_vm_readv 失败或连衔接 64B 都读不全。
    ReadFailed,
}

impl CursorRereader {
    fn from_env() -> Option<Self> {
        let enabled = std::env::var("A3S_OBSERVER_CURSOR_REREAD")
            .map(|value| {
                let value = value.trim();
                !value.is_empty()
                    && !matches!(
                        value.to_ascii_lowercase().as_str(),
                        "0" | "false" | "off" | "no" | "disabled"
                    )
            })
            .unwrap_or(false);
        if !enabled {
            return None;
        }
        let max_kb = std::env::var("A3S_OBSERVER_CURSOR_REREAD_MAX_KB")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(1_024)
            .clamp(64, 8_192);
        let ttl_ms = std::env::var("A3S_OBSERVER_CURSOR_REREAD_TTL_MS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(500)
            .clamp(1, 10_000);
        Some(Self {
            max_bytes: max_kb * 1_024,
            ttl_ns: ttl_ms * 1_000_000,
            claims: RefCell::new(VecDeque::new()),
        })
    }

    fn claim(&self, chunk: &PlaintextChunk, cursor: &LegacyCursorExt) -> bool {
        // captured_at_boot_ns 标识一次发射，不属于游标身份；同一游标经不同时间/路径
        // 重发时仍必须命中同一台账项。
        let claim = CursorClaim {
            pid: chunk.pid,
            connection_id: chunk.connection_id,
            resume_buf: cursor.resume_buf,
            remaining: cursor.remaining,
            tail_fnv64: cursor.tail_fnv64,
        };
        let mut claims = self.claims.borrow_mut();
        if claims.contains(&claim) {
            return false;
        }
        if claims.len() >= CURSOR_CLAIM_LIMIT {
            claims.pop_front();
        }
        claims.push_back(claim);
        true
    }

    /// 校验并拼接。任何一步存疑都原样保留 partial chunk（宁可不拼，不可错拼）。
    /// `reader(pid, addr, len)` 注入目标内存读取，测试用假实现，生产用 process_vm_readv。
    /// 同连接相同游标再次消费返回 Ok(None)，不会二次读取或追加；调用方必须跳过该分片。
    fn patch(
        &self,
        chunk: &mut PlaintextChunk,
        cursor: &LegacyCursorExt,
        captured_at_boot_ns: u64,
        now_boot_ns: u64,
        reader: &dyn Fn(u32, u64, usize) -> Option<Vec<u8>>,
    ) -> Result<Option<usize>, PatchReject> {
        if !self.claim(chunk, cursor) {
            return Ok(None);
        }
        if now_boot_ns.saturating_sub(captured_at_boot_ns) > self.ttl_ns {
            return Err(PatchReject::TtlExpired);
        }
        let tail_len = cursor.tail_len as usize;
        if tail_len != LEGACY_CURSOR_TAIL_LEN
            || cursor.remaining == 0
            || cursor.resume_buf < tail_len as u64
            || chunk.data.len() < tail_len
        {
            return Err(PatchReject::SelfFingerprint);
        }
        // 自证：带上游标的 chunk 尾部必须与 BPF 指纹一致（防解析串道）。
        if fnv1a64(&chunk.data[chunk.data.len() - tail_len..]) != cursor.tail_fnv64 {
            return Err(PatchReject::SelfFingerprint);
        }
        let want = (cursor.remaining as usize).min(self.max_bytes);
        let base = cursor.resume_buf - tail_len as u64;
        let read = reader(chunk.pid, base, tail_len + want).ok_or(PatchReject::ReadFailed)?;
        if read.len() < tail_len {
            return Err(PatchReject::ReadFailed);
        }
        // 衔接校验：目标进程内存里 resume_buf 前的 64B 必须仍是已采尾部。
        if fnv1a64(&read[..tail_len]) != cursor.tail_fnv64 {
            return Err(PatchReject::OverlapFingerprint);
        }
        let payload = &read[tail_len..];
        chunk.data.extend_from_slice(payload);
        chunk.partial_reasons.push("cursor_reread_patched".to_string());
        if payload.len() < cursor.remaining as usize {
            chunk
                .partial_reasons
                .push("cursor_reread_capped".to_string());
        }
        Ok(Some(payload.len()))
    }
}

/// 生产侧 reader：process_vm_readv 直读目标进程内存。部分读取保留可用前缀
/// （不足衔接 64B 由调用方判 ReadFailed）。
fn process_vm_read(pid: u32, addr: u64, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as usize as *mut libc::c_void,
        iov_len: len,
    };
    // SAFETY: both iovecs reference valid ranges for the duration of the call; the remote
    // range is validated by the kernel (ptrace access mode), never dereferenced locally.
    let n = unsafe { libc::process_vm_readv(pid as libc::pid_t, &local, 1, &remote, 1, 0) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(buf)
}

/// 开启 BPF 侧游标产生：写 A3S_RUNTIME_CONFIG[0] bit0。arm64 冻结对象不含此 map，
/// 返回错误后特性整体关闭（行为与旧版一致）。
fn enable_cursor_reread(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let map = ebpf
        .map_mut("A3S_RUNTIME_CONFIG")
        .context("`A3S_RUNTIME_CONFIG` missing (legacy object without cursor support)")?;
    let mut config: BpfArray<_, u64> =
        BpfArray::try_from(map).context("`A3S_RUNTIME_CONFIG` type mismatch")?;
    config
        .set(0, A3S_CONFIG_FLAG_CURSOR_REREAD, 0)
        .context("`A3S_RUNTIME_CONFIG` write failed")?;
    Ok(())
}

/// Legacy perf maps and their short heartbeat keys, in registration order. The short key is
/// the stable `perfLostByMap` dimension; the map name is the BPF object name.
const PERF_RINGS: [(&str, &str); 7] = [
    ("EVENTS", "events"),
    ("EXIT_EVENTS", "exit"),
    ("CONNECT_EVENTS", "connect"),
    ("FILE_EVENTS", "file"),
    ("SEC_EVENTS", "security"),
    ("PLAINTEXT_EVENTS", "plaintext"),
    ("PLAINTEXT_TLS_EVENTS", "plaintext_tls"),
];

fn perf_ring_index(map_name: &str) -> usize {
    PERF_RINGS
        .iter()
        .position(|(name, _)| *name == map_name)
        .unwrap_or_else(|| panic!("unknown legacy perf map `{map_name}`"))
}

/// Per-map perf buffer lost-event counters. `total` keeps the heartbeat `dropped` accounting
/// on its historical aggregate while the per-map slots identify which of the seven
/// PERF_EVENT_ARRAY maps is shedding records under burst load. The breakdown rides the
/// additive `perfLostByMap` heartbeat field rather than `pipelineAccounting.rings`: the rings
/// envelope is reserved for the ring-buffer pipeline's submitted/received/enqueued delta
/// windows, which the perf backend cannot produce without inventing zero-valued counters that
/// consumers would misread as "no traffic".
#[derive(Default)]
struct PerfLostCounters {
    total: AtomicU64,
    by_map: [AtomicU64; PERF_RINGS.len()],
}

impl PerfLostCounters {
    fn record(&self, ring: usize, lost: u64) {
        self.by_map[ring].fetch_add(lost, Ordering::Relaxed);
        self.total.fetch_add(lost, Ordering::Relaxed);
    }

    fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    fn snapshot(&self) -> BTreeMap<String, u64> {
        PERF_RINGS
            .iter()
            .enumerate()
            .map(|(index, (_, key))| {
                ((*key).to_string(), self.by_map[index].load(Ordering::Relaxed))
            })
            .collect()
    }
}

/// Host page size in bytes: the exchange rate between the byte-oriented ring budget and the
/// page count the perf mmap API takes. Falls back to 4 KiB if sysconf fails.
fn host_page_size() -> usize {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size > 0 {
        page_size as usize
    } else {
        4096
    }
}

/// Perf ring buffer sizing per CPU per map. The page size is an exchange rate, not the intent:
/// operators budget burst absorption in bytes, so the primary knob is the byte target
/// (A3S_OBSERVER_PERF_RING_KB, KiB per CPU per map) converted to pages through the host page
/// size, which generalizes across 4 KiB- and 64 KiB-page hosts. A3S_OBSERVER_PERF_RING_PAGES
/// remains as an explicit page-count override and beats the adaptive default, but not an
/// explicit byte target. The default targets 512 KiB per CPU per map clamped to 8..=1024
/// pages: 128 pages on 4 KiB-page hosts (x86 5.14) and 8 pages on 64 KiB-page hosts (arm64
/// 4.19), matching both release channels. Larger values absorb SSE bursts at the cost of
/// pages * page_size * cpu_count bytes of locked memory per perf map.
fn perf_ring_pages() -> usize {
    let page_size = host_page_size();
    let target_kb = std::env::var("A3S_OBSERVER_PERF_RING_KB")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|kb| *kb > 0);
    if let Some(kb) = target_kb {
        return kb.saturating_mul(1024).div_ceil(page_size).clamp(8, 1_024);
    }
    std::env::var("A3S_OBSERVER_PERF_RING_PAGES")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|pages| (1..=1_024).contains(pages))
        .unwrap_or_else(|| (512 * 1024_usize).div_ceil(page_size).clamp(8, 1_024))
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

/// Per-connection, per-direction consecutive sequence numbers. The reassembler flags
/// `fragment_sequence_gap` whenever a chunk's sequence is not exactly previous+1, so the raw
/// monotonic capture timestamp must NOT be used as the sequence (that was the compat25 bug that
/// stamped every multi-chunk interaction with a spurious gap). Counters are userspace state:
/// zero kernel cost and the same semantics as the modern `call_seq`.
#[derive(Default)]
struct PlaintextSequencer {
    counters: std::collections::HashMap<(u32, u32, u32, bool), u64>,
}

impl PlaintextSequencer {
    fn next(&mut self, pid: u32, fd: u32, generation: u32, is_read: bool) -> u64 {
        if self.counters.len() >= 4_096 && !self.counters.contains_key(&(pid, fd, generation, is_read)) {
            // Bounded state: evict one arbitrary baseline. A fresh key restarts at 1, which the
            // reassembler treats as a new baseline (no gap), never as a fabricated continuity.
            if let Some(oldest) = self.counters.keys().next().copied() {
                self.counters.remove(&oldest);
            }
        }
        let slot = self.counters.entry((pid, fd, generation, is_read)).or_insert(0);
        *slot = slot.wrapping_add(1);
        *slot
    }

    fn rollback(&mut self, pid: u32, fd: u32, generation: u32, is_read: bool) {
        if let Some(slot) = self.counters.get_mut(&(pid, fd, generation, is_read)) {
            *slot = slot.saturating_sub(1);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FragmentKey {
    is_read: bool,
    orig_len: u32,
    hash: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct FragmentEntry {
    key: FragmentKey,
    first_seen_boot_ns: u64,
}

#[derive(Default)]
struct ConnectionDedup {
    entries: VecDeque<FragmentEntry>,
    last_seen_boot_ns: u64,
}

// 25ms 覆盖实测约 5ms 的重复发射；窗口只抑制完全相同的分片，超过窗口的合法重复
// 请求和不同 orig_len/内容的 delta 一律放行。captured_at 只用于窗口，不参与键。
const DUPLICATE_FRAGMENT_WINDOW_NS: u64 = 25_000_000;
const DUPLICATE_FRAGMENT_KEYS_PER_CONNECTION: usize = 64;
const DUPLICATE_FRAGMENT_MAX_CONNECTIONS: usize = 1_024;

#[derive(Default)]
struct FragmentDedup {
    connections: std::collections::HashMap<(u64, u32), ConnectionDedup>,
}

impl FragmentDedup {
    fn should_suppress(
        &mut self,
        chunk: &PlaintextChunk,
        orig_len: u32,
        captured_at_boot_ns: u64,
    ) -> bool {
        let key = FragmentKey {
            is_read: matches!(chunk.direction, ChunkDirection::Response),
            orig_len,
            hash: Sha256::digest(&chunk.data).into(),
        };
        let connection_key = (chunk.connection_id, chunk.pid);
        if self.connections.len() >= DUPLICATE_FRAGMENT_MAX_CONNECTIONS
            && !self.connections.contains_key(&connection_key)
        {
            if let Some(oldest) = self
                .connections
                .iter()
                .min_by_key(|(_, connection)| connection.last_seen_boot_ns)
                .map(|(key, _)| *key)
            {
                self.connections.remove(&oldest);
            }
        }
        let connection = self.connections.entry(connection_key).or_default();
        connection.last_seen_boot_ns = connection.last_seen_boot_ns.max(captured_at_boot_ns);
        if let Some(index) = connection
            .entries
            .iter()
            .position(|entry| entry.key == key)
        {
            let first_seen_boot_ns = connection.entries[index].first_seen_boot_ns;
            let duplicate =
                captured_at_boot_ns.saturating_sub(first_seen_boot_ns) <= DUPLICATE_FRAGMENT_WINDOW_NS;
            connection.entries.remove(index);
            connection.entries.push_back(FragmentEntry {
                key,
                first_seen_boot_ns: if duplicate {
                    first_seen_boot_ns
                } else {
                    captured_at_boot_ns
                },
            });
            return duplicate;
        }
        connection.entries.push_back(FragmentEntry {
            key,
            first_seen_boot_ns: captured_at_boot_ns,
        });
        if connection.entries.len() > DUPLICATE_FRAGMENT_KEYS_PER_CONNECTION {
            connection.entries.pop_front();
        }
        false
    }

    fn expire_idle(&mut self, now_boot_ns: u64, timeout: Duration) {
        let timeout_ns = timeout.as_nanos().min(u64::MAX as u128) as u64;
        self.connections.retain(|_, connection| {
            now_boot_ns.saturating_sub(connection.last_seen_boot_ns) <= timeout_ns
        });
    }
}

/// 在 cursor patch 前判定，保证补读扩展后的分片不再进入去重；被抑制的分片同时回滚
/// userspace sequence，避免把主动去重视为真实 fragment_sequence_gap。
fn suppress_duplicate_fragment(
    dedup: &mut FragmentDedup,
    sequencer: &mut PlaintextSequencer,
    chunk: &PlaintextChunk,
    orig_len: u32,
    captured_at_boot_ns: u64,
    fd: u32,
    generation: u32,
) -> bool {
    if !dedup.should_suppress(chunk, orig_len, captured_at_boot_ns) {
        return false;
    }
    sequencer.rollback(
        chunk.pid,
        fd,
        generation,
        matches!(chunk.direction, ChunkDirection::Response),
    );
    let count = DUPLICATE_FRAGMENT_SUPPRESSED.fetch_add(1, Ordering::Relaxed) + 1;
    if count == 1 || count.is_multiple_of(64) {
        tracing::info!(
            pid = chunk.pid,
            connection_id = chunk.connection_id,
            direction = ?chunk.direction,
            orig_len,
            duplicate_fragment_suppressed = count,
            "duplicate plaintext fragment suppressed"
        );
    }
    true
}

fn tls_plaintext_chunk_from_event(
    ev: &LegacyTlsPlaintextEvent,
    now_unix_ns: u128,
    sequencer: &mut PlaintextSequencer,
) -> PlaintextChunk {
    let len = (ev.len as usize).min(LEGACY_PLAINTEXT_LEN);
    let is_read = ev.direction == LEGACY_PLAINTEXT_DIRECTION_READ;
    let lo = ev.tls_ctx as u32;
    let hi = (ev.tls_ctx >> 32) as u32;
    PlaintextChunk {
        cgroup_id: 0,
        pid: ev.pid,
        // SSL* 指针即连接身份（uprobe 天然免疫 fd 复用）。tag 位避免与 fd 哈希空间相碰。
        connection_id: ev.tls_ctx ^ 0x5353_6c73_0000_0000,
        sequence: sequencer.next(ev.pid, lo, hi, is_read),
        direction: if is_read {
            ChunkDirection::Response
        } else {
            ChunkDirection::Request
        },
        data: ev.data[..len].to_vec(),
        event_at_unix_ns: now_unix_ns,
        source: "openssl_uprobe".to_string(),
        adapter_id: "openssl-uprobe".to_string(),
        route_candidate: false,
        partial_reasons: if ev.len < ev.orig_len {
            vec!["probe_call_limit".to_string()]
        } else {
            Vec::new()
        },
        bind_quality: 0,
        socket_fd: 0,
        socket_cookie: 0,
        fd_generation: 0,
    }
}

fn plaintext_chunk_from_event(
    ev: &LegacyPlaintextEvent,
    now_unix_ns: u128,
    sequencer: &mut PlaintextSequencer,
) -> PlaintextChunk {
    let len = (ev.len as usize).min(LEGACY_PLAINTEXT_LEN);
    let is_read = ev.direction == LEGACY_PLAINTEXT_DIRECTION_READ;
    // The legacy ABI carries no kernel cgroup id; (pid, fd) keyed lanes alone spliced
    // unrelated connections after fd-number reuse (observed on the dev host: an auth
    // response landed on an LLM request). The kernel-side fd generation makes every
    // connect/accept/close a fresh lane; gen 0 keeps the pre-attach baseline.
    let base_connection_id = classic_tls_sock_connection_id(0, ev.pid, u64::from(ev.fd));
    let connection_id = if ev.fd_generation == 0 {
        base_connection_id
    } else {
        base_connection_id ^ u64::from(ev.fd_generation).rotate_left(32)
    };
    PlaintextChunk {
        cgroup_id: 0,
        pid: ev.pid,
        connection_id,
        sequence: sequencer.next(ev.pid, ev.fd, ev.fd_generation, is_read),
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
        fd_generation: ev.fd_generation,
    }
}

/// R3 截断补读入口：游标存在且特性开启时尝试补读拼接；结果只影响本 chunk，
/// 失败原样保留 partial。计数进 60s 心跳窗口。返回 false 表示同连接游标重复，
/// 该分片已在首次消费时进入重组器，不能再次 push。
fn cursor_patch_and_log(
    rereader: Option<&CursorRereader>,
    cursor: Option<LegacyCursorExt>,
    chunk: &mut PlaintextChunk,
    captured_at_boot_ns: u64,
) -> bool {
    let (Some(rereader), Some(cursor)) = (rereader, cursor) else {
        return true;
    };
    match rereader.patch(
        chunk,
        &cursor,
        captured_at_boot_ns,
        boot_now_ns(),
        &process_vm_read,
    ) {
        Ok(Some(appended)) => {
            CURSOR_PATCHED.fetch_add(1, Ordering::Relaxed);
            CURSOR_PATCH_BYTES.fetch_add(appended as u64, Ordering::Relaxed);
            tracing::info!(
                pid = chunk.pid,
                connection_id = chunk.connection_id,
                captured_at_boot_ns,
                resume_buf = cursor.resume_buf,
                tail_fnv64 = cursor.tail_fnv64,
                appended,
                remaining = cursor.remaining,
                "legacy cursor reread patched truncated call"
            );
            true
        }
        Ok(None) => false,
        Err(reason) => {
            let counter = match reason {
                PatchReject::TtlExpired => &CURSOR_REJECT_TTL,
                PatchReject::SelfFingerprint => &CURSOR_REJECT_SELF_FNV,
                PatchReject::OverlapFingerprint => &CURSOR_REJECT_OVERLAP_FNV,
                PatchReject::ReadFailed => &CURSOR_REJECT_READ,
            };
            counter.fetch_add(1, Ordering::Relaxed);
            tracing::info!(
                pid = chunk.pid,
                ?reason,
                remaining = cursor.remaining,
                "legacy cursor reread rejected; keeping partial"
            );
            true
        }
    }
}

fn emit_plaintext_interactions(
    exporter: &dyn Exporter,
    stats: &mut Stats,
    resolver: &KubeResolver,
    classifier: &SniClassifier,
    comm: [u8; 16],
    completed: Vec<super::interaction::CompletedInteraction>,
    suppressed_shells: &mut u64,
) {
    for interaction in completed {
        // Unparsed interactions with zero payload on both sides are pure noise (idle expiries
        // and non-HTTP streams sharing an admitted pid). Demote them to a metric instead of
        // storing empty interaction rows the conversation view cannot render.
        if interaction.is_empty_unparsed_shell() {
            *suppressed_shells = suppressed_shells.saturating_add(1);
            continue;
        }
        let n = PLAINTEXT_INTERACTION_SEEN.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::info!(
            n,
            interaction_id = %interaction.interaction_id,
            "legacy plaintext interaction completed; exporting"
        );
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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct SslAttachKey {
    pid: i32,
    start_time_ticks: u64,
    dev: u64,
    ino: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SslProcessState {
    Present(u64),
    Exited,
    Unavailable,
}

impl SslAttachKey {
    fn matches(self, state: SslProcessState) -> bool {
        match state {
            SslProcessState::Present(start_time_ticks) => {
                start_time_ticks == self.start_time_ticks
            }
            SslProcessState::Exited => false,
            // 瞬时 proc 读取/解析失败不是退出证据；保留现有链接和台账，避免重复挂接。
            SslProcessState::Unavailable => true,
        }
    }

    fn is_current(self) -> bool {
        self.matches(ssl_process_state(self.pid))
    }
}

fn ssl_process_state(pid: i32) -> SslProcessState {
    match super::read_process_stat(pid as u32) {
        Some((_, start_time_ticks)) => SslProcessState::Present(start_time_ticks),
        None if !Path::new("/proc").join(pid.to_string()).exists() => SslProcessState::Exited,
        None => SslProcessState::Unavailable,
    }
}

fn ssl_process_start_ticks(pid: i32) -> Option<u64> {
    super::read_process_stat(pid as u32).map(|(_, start_time_ticks)| start_time_ticks)
}

struct SslDiagEntry {
    path: PathBuf,
    attach_entries: u64,
}

const SSL_ATTACH_DIAG_LIMIT: usize = 4_096;

/// OpenSSL uprobe lifecycle on the legacy backend: attach once per process/start and mapped
/// inode. PID-scoped links prevent global registrations for other containers from replaying one
/// SSL call into this collector. Process start ticks allow safe PID reuse without reattaching to
/// every process on every refresh.
#[derive(Default)]
struct SslUprobeManager {
    attached: HashSet<SslAttachKey>,
    failed: HashSet<SslAttachKey>,
    diag_entries: BTreeMap<SslAttachKey, SslDiagEntry>,
    logged_scan: bool,
    read_failed: HashSet<i32>,
    logged_ssl_pids: HashSet<i32>,
}

impl SslUprobeManager {
    fn record_attach_success(&mut self, key: SslAttachKey, path: &Path) {
        self.attached.insert(key);
        if self.diag_entries.len() >= SSL_ATTACH_DIAG_LIMIT
            && !self.diag_entries.contains_key(&key)
        {
            if let Some(oldest) = self.diag_entries.keys().next().copied() {
                self.diag_entries.remove(&oldest);
            }
        }
        let entry = self.diag_entries.entry(key).or_insert_with(|| SslDiagEntry {
            path: path.to_path_buf(),
            attach_entries: 0,
        });
        entry.path = path.to_path_buf();
        entry.attach_entries += 1;
    }

    fn log_attach_summary(&self) {
        tracing::info!(
            entries = self.diag_entries.len(),
            "legacy SSL attach table summary (30s)"
        );
        for (key, entry) in &self.diag_entries {
            tracing::info!(
                pid = key.pid,
                invalid_pid = key.pid <= 0,
                start_time_ticks = key.start_time_ticks,
                dev = key.dev,
                inode = key.ino,
                path = %entry.path.display(),
                attach_entries = entry.attach_entries,
                duplicate_suspect = entry.attach_entries > 1,
                "legacy SSL attach entry"
            );
        }
    }

    fn prune_stale(&mut self) {
        self.attached.retain(|key| key.is_current());
        self.failed.retain(|key| key.is_current());
    }

    fn ensure_attached(&mut self, ebpf: &mut Ebpf, pids: &HashSet<i32>) {
        use std::os::unix::fs::MetadataExt;
        self.prune_stale();
        if !self.logged_scan {
            self.logged_scan = true;
            tracing::info!(pids = pids.len(), "legacy openssl uprobe scan started");
        }
        let mut seen = HashSet::new();
        for pid in pids {
            let maps = match std::fs::read_to_string(format!("/proc/{pid}/maps")) {
                Ok(maps) => maps,
                Err(error) => {
                    if self.read_failed.insert(*pid) {
                        tracing::warn!(pid = *pid, error = %error, "legacy openssl uprobe: maps read failed");
                    }
                    continue;
                }
            };
            let mut ssl_lines = 0usize;
            for line in maps.lines() {
                let Some(path) = line.split_whitespace().nth(5) else {
                    continue;
                };
                if !path.contains("libssl.so") {
                    continue;
                }
                ssl_lines += 1;
                if !seen.insert((*pid, path.to_string())) {
                    continue;
                }
                if ssl_lines == 1 && self.logged_ssl_pids.insert(*pid) {
                    tracing::info!(pid = *pid, path, "legacy openssl uprobe scan: libssl mapped");
                }
                let host_path = PathBuf::from(format!("/proc/{pid}/root{path}"));
                let Ok(metadata) = std::fs::metadata(&host_path) else {
                    continue;
                };
                let Some(start_time_ticks) = ssl_process_start_ticks(*pid) else {
                    continue;
                };
                let key = SslAttachKey {
                    pid: *pid,
                    start_time_ticks,
                    dev: metadata.dev(),
                    ino: metadata.ino(),
                };
                if self.attached.contains(&key) || self.failed.contains(&key) {
                    continue;
                }
                match attach_ssl_uprobes(ebpf, &host_path, *pid) {
                    Ok(()) => {
                        self.record_attach_success(key, &host_path);
                        tracing::info!(
                            pid = *pid,
                            start_time_ticks,
                            path = %host_path.display(),
                            "legacy openssl uprobes attached (SSL_write/SSL_read)"
                        );
                    }
                    Err(error) => {
                        self.failed.insert(key);
                        tracing::warn!(
                            pid = *pid,
                            path = %host_path.display(),
                            error = %error,
                            "legacy openssl uprobe attach failed"
                        );
                    }
                }
            }
        }
    }
}

fn attach_ssl_symbol(
    ebpf: &mut Ebpf,
    program: &str,
    symbol: &str,
    path: &Path,
    pid: i32,
) -> Result<(), ProgramError> {
    let raw = ebpf
        .program_mut(program)
        .ok_or_else(|| ProgramError::InvalidName {
            name: program.to_string(),
        })?;
    let probe: &mut UProbe = raw
        .try_into()
        .map_err(|_| ProgramError::UnexpectedProgramType)?;
    match probe.load() {
        Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
        Err(error) => return Err(error),
    }
    probe.attach(Some(symbol), 0, path, Some(pid)).map(|_| ())
}

fn attach_ssl_with_fallback(
    ex: (&str, &str),
    legacy: (&str, &str),
    attach: &mut dyn FnMut(&str, &str) -> Result<(), ProgramError>,
) -> Result<(), ProgramError> {
    match attach(ex.0, ex.1) {
        Ok(()) => Ok(()),
        Err(ProgramError::UProbeError(UProbeError::SymbolError { .. })) => {
            attach(legacy.0, legacy.1)
        }
        Err(error) => Err(error),
    }
}

fn checked_ssl_attach_pid(pid: i32) -> anyhow::Result<i32> {
    anyhow::ensure!(pid > 0, "refusing invalid SSL uprobe pid {pid}");
    Ok(pid)
}

fn attach_ssl_uprobes(ebpf: &mut Ebpf, path: &Path, pid: i32) -> anyhow::Result<()> {
    // _ex 与 legacy 包装符号不能同时挂：OpenSSL 包装会把一次调用变成两组完整分片。
    // 仅当目标 libssl 确实没有 _ex 符号时回退到 legacy；加载/权限等错误不能触发回退。
    let pid = checked_ssl_attach_pid(pid)?;
    let mut attach = |program: &str, symbol: &str| {
        attach_ssl_symbol(ebpf, program, symbol, path, pid)
    };
    for (ex, legacy) in [
        (
            ("legacy_ssl_write_ex", "SSL_write_ex"),
            ("legacy_ssl_write", "SSL_write"),
        ),
        (
            ("legacy_ssl_read_enter_ex", "SSL_read_ex"),
            ("legacy_ssl_read_enter", "SSL_read"),
        ),
        (
            ("legacy_ssl_read_exit", "SSL_read_ex"),
            ("legacy_ssl_read_exit", "SSL_read"),
        ),
    ] {
        attach_ssl_with_fallback(ex, legacy, &mut attach).with_context(|| {
            format!("uprobe attach `{}` with `{}` fallback failed", ex.1, legacy.1)
        })?;
    }
    Ok(())
}

fn spawn_perf<T: Copy + Send + 'static>(
    ebpf: &mut Ebpf,
    map_name: &str,
    tx: mpsc::Sender<RawEvent>,
    lost: Arc<PerfLostCounters>,
    wrap: fn(T) -> RawEvent,
    ring_pages: usize,
) -> anyhow::Result<()> {
    let mut array = AsyncPerfEventArray::try_from(
        ebpf.take_map(map_name)
            .with_context(|| format!("`{map_name}` missing"))?,
    )?;
    let ring_index = perf_ring_index(map_name);
    for cpu in online_cpus().map_err(|(_, error)| error)? {
        let mut buffer = array.open(cpu, Some(ring_pages))?;
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
                lost.record(ring_index, events.lost as u64);
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

fn spawn_plaintext_perf(
    ebpf: &mut Ebpf,
    map_name: &str,
    tx: mpsc::Sender<RawEvent>,
    lost: Arc<PerfLostCounters>,
    ring_pages: usize,
) -> anyhow::Result<()> {
    let mut array = AsyncPerfEventArray::try_from(
        ebpf.take_map(map_name)
            .with_context(|| format!("`{map_name}` missing"))?,
    )?;
    let ring_index = perf_ring_index(map_name);
    for cpu in online_cpus().map_err(|(_, error)| error)? {
        let mut buffer = array.open(cpu, Some(ring_pages))?;
        let tx = tx.clone();
        let lost = lost.clone();
        tokio::spawn(async move {
            let mut slots = (0..32)
                .map(|_| BytesMut::with_capacity(size_of::<LegacyPlaintextEvent>()))
                .collect::<Vec<_>>();
            loop {
                let events = match buffer.read_events(&mut slots).await {
                    Ok(events) => events,
                    Err(error) => {
                        tracing::error!(cpu, error = %error, "legacy plaintext perf reader failed");
                        break;
                    }
                };
                lost.record(ring_index, events.lost as u64);
                for slot in slots.iter().take(events.read) {
                    if let Some(event) = plaintext_event_from_record(slot) {
                        let cursor = cursor_ext_from_record(
                            slot,
                            size_of::<LegacyPlaintextEvent>() - LEGACY_PLAINTEXT_LEN,
                            event.len as usize,
                        );
                        if tx
                            .send(RawEvent::Plaintext(Box::new(event), cursor))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
        });
    }
    Ok(())
}

fn tls_plaintext_event_from_record(bytes: &[u8]) -> Option<LegacyTlsPlaintextEvent> {
    // Same trimmed-record convention as `plaintext_event_from_record`: the kernel emits
    // header + len only. Header layout: pid@0 direction@4 len@8 orig_len@12 tls_ctx@16
    // comm@24 captured_at_boot_ns@40, data@48.
    const HEADER_LEN: usize = size_of::<LegacyTlsPlaintextEvent>() - LEGACY_PLAINTEXT_LEN;
    if bytes.len() < HEADER_LEN {
        return None;
    }
    let read_u32 = |offset: usize| {
        bytes
            .get(offset..offset + 4)
            .and_then(|value| value.try_into().ok())
            .map(u32::from_ne_bytes)
    };
    let len = read_u32(8)? as usize;
    if len > LEGACY_PLAINTEXT_LEN || bytes.len() < HEADER_LEN + len {
        return None;
    }
    let mut event = LegacyTlsPlaintextEvent {
        pid: read_u32(0)?,
        direction: read_u32(4)?,
        len: len as u32,
        orig_len: read_u32(12)?,
        tls_ctx: u64::from_ne_bytes(bytes.get(16..24)?.try_into().ok()?),
        comm: bytes.get(24..40)?.try_into().ok()?,
        captured_at_boot_ns: u64::from_ne_bytes(bytes.get(40..48)?.try_into().ok()?),
        data: [0; LEGACY_PLAINTEXT_LEN],
    };
    event.data[..len].copy_from_slice(&bytes[HEADER_LEN..HEADER_LEN + len]);
    Some(event)
}

fn spawn_tls_plaintext_perf(
    ebpf: &mut Ebpf,
    map_name: &str,
    tx: mpsc::Sender<RawEvent>,
    lost: Arc<PerfLostCounters>,
    ring_pages: usize,
) -> anyhow::Result<()> {
    let mut array = AsyncPerfEventArray::try_from(
        ebpf.take_map(map_name)
            .with_context(|| format!("`{map_name}` missing"))?,
    )?;
    let ring_index = perf_ring_index(map_name);
    for cpu in online_cpus().map_err(|(_, error)| error)? {
        let mut buffer = array.open(cpu, Some(ring_pages))?;
        let tx = tx.clone();
        let lost = lost.clone();
        tokio::spawn(async move {
            let mut slots = (0..32)
                .map(|_| BytesMut::with_capacity(size_of::<LegacyTlsPlaintextEvent>()))
                .collect::<Vec<_>>();
            loop {
                let events = match buffer.read_events(&mut slots).await {
                    Ok(events) => events,
                    Err(error) => {
                        tracing::error!(cpu, error = %error, "legacy tls plaintext perf reader failed");
                        break;
                    }
                };
                lost.record(ring_index, events.lost as u64);
                for slot in slots.iter().take(events.read) {
                    if let Some(event) = tls_plaintext_event_from_record(slot) {
                        let cursor = cursor_ext_from_record(
                            slot,
                            size_of::<LegacyTlsPlaintextEvent>() - LEGACY_PLAINTEXT_LEN,
                            event.len as usize,
                        );
                        if tx
                            .send(RawEvent::PlaintextTls(Box::new(event), cursor))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
        });
    }
    Ok(())
}

fn plaintext_event_from_record(bytes: &[u8]) -> Option<LegacyPlaintextEvent> {
    const HEADER_LEN: usize = size_of::<LegacyPlaintextEvent>() - LEGACY_PLAINTEXT_LEN;
    if bytes.len() < HEADER_LEN {
        return None;
    }
    let read_u32 = |offset: usize| {
        bytes
            .get(offset..offset + 4)
            .and_then(|value| value.try_into().ok())
            .map(u32::from_ne_bytes)
    };
    let len = read_u32(12)? as usize;
    if len > LEGACY_PLAINTEXT_LEN || bytes.len() < HEADER_LEN + len {
        return None;
    }
    let mut event = LegacyPlaintextEvent {
        pid: read_u32(0)?,
        fd: read_u32(4)?,
        direction: read_u32(8)?,
        len: len as u32,
        orig_len: read_u32(16)?,
        _pad: read_u32(20)?,
        fd_generation: read_u32(24)?,
        comm: bytes.get(28..44)?.try_into().ok()?,
        captured_at_boot_ns: u64::from_ne_bytes(bytes.get(48..56)?.try_into().ok()?),
        data: [0; LEGACY_PLAINTEXT_LEN],
    };
    event.data[..len].copy_from_slice(&bytes[HEADER_LEN..HEADER_LEN + len]);
    Some(event)
}

fn read_value<T: Copy>(bytes: &[u8]) -> Option<T> {
    (bytes.len() >= size_of::<T>())
        .then(|| unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

/// R3 游标扩展尾部：record 布局为 header + len + [ext]。旧解析只读到 header+len，
/// 多余尾部天然忽略（宽容性已由 trimmed-record 约定保证）；新解析仅在 record 足够长
/// 且 magic 匹配时采纳，其余字段的合法性由 CursorRereader::patch 复核。
fn cursor_ext_from_record(
    bytes: &[u8],
    header_len: usize,
    len: usize,
) -> Option<LegacyCursorExt> {
    let start = header_len.checked_add(len)?;
    let ext = bytes.get(start..start + size_of::<LegacyCursorExt>())?;
    let cursor = LegacyCursorExt {
        magic: u64::from_ne_bytes(ext.get(0..8)?.try_into().ok()?),
        resume_buf: u64::from_ne_bytes(ext.get(8..16)?.try_into().ok()?),
        tail_fnv64: u64::from_ne_bytes(ext.get(16..24)?.try_into().ok()?),
        remaining: u32::from_ne_bytes(ext.get(24..28)?.try_into().ok()?),
        tail_len: u32::from_ne_bytes(ext.get(28..32)?.try_into().ok()?),
    };
    (cursor.magic == LEGACY_CURSOR_EXT_MAGIC).then_some(cursor)
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
        RawEvent::Plaintext(..) => return,
        RawEvent::PlaintextTls(..) => return,
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
    perf_lost_by_map: Option<BTreeMap<String, u64>>,
) {
    let event = super::collector_heartbeat(
        collector,
        interval_secs,
        stats,
        dropped,
        exporter.output_drops(),
        perf_lost_by_map,
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
            fd_generation: 0,
            comm: [0u8; 16],
            captured_at_boot_ns: 123_456_789,
            data: [0u8; LEGACY_PLAINTEXT_LEN],
        };
        event.data[..5].copy_from_slice(b"GET /");
        event
    }

    #[test]
    fn plaintext_chunk_maps_request_direction_and_bounds_payload() {
        let chunk = plaintext_chunk_from_event(
            &plaintext_event(0, 5, 5),
            999,
            &mut PlaintextSequencer::default(),
        );
        assert!(matches!(chunk.direction, ChunkDirection::Request));
        assert_eq!(chunk.data, b"GET /");
        assert_eq!(chunk.pid, 4242);
        assert_eq!(
            chunk.sequence, 1,
            "userspace sequencer starts at 1, not ktime"
        );
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
            &mut PlaintextSequencer::default(),
        );
        assert!(matches!(chunk.direction, ChunkDirection::Response));
        assert_eq!(chunk.partial_reasons, vec!["probe_call_limit".to_string()]);
    }

    #[test]
    fn plaintext_chunk_never_overruns_the_fixed_payload() {
        // A corrupted length field must not read past the fixed record.
        let chunk = plaintext_chunk_from_event(
            &plaintext_event(0, u32::MAX, u32::MAX),
            999,
            &mut PlaintextSequencer::default(),
        );
        assert_eq!(chunk.data.len(), LEGACY_PLAINTEXT_LEN);
    }

    #[test]
    fn plaintext_variable_perf_record_round_trips_without_ring_padding() {
        const HEADER_LEN: usize = size_of::<LegacyPlaintextEvent>() - LEGACY_PLAINTEXT_LEN;
        let mut event = plaintext_event(LEGACY_PLAINTEXT_DIRECTION_READ, 2048, 4096);
        for (index, byte) in event.data[..2048].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        let mut record = Vec::with_capacity(HEADER_LEN + 2048);
        record.extend_from_slice(&event.pid.to_ne_bytes());
        record.extend_from_slice(&event.fd.to_ne_bytes());
        record.extend_from_slice(&event.direction.to_ne_bytes());
        record.extend_from_slice(&event.len.to_ne_bytes());
        record.extend_from_slice(&event.orig_len.to_ne_bytes());
        record.extend_from_slice(&event._pad.to_ne_bytes());
        record.extend_from_slice(&event.fd_generation.to_ne_bytes());
        record.extend_from_slice(&event.comm);
        // repr(C) pads the header so captured_at_boot_ns lands on an 8-byte boundary.
        record.extend_from_slice(&[0u8; 4]);
        record.extend_from_slice(&event.captured_at_boot_ns.to_ne_bytes());
        record.extend_from_slice(&event.data[..2048]);

        let decoded = plaintext_event_from_record(&record).expect("valid variable record");
        assert_eq!(decoded.len, 2048);
        assert_eq!(decoded.orig_len, 4096);
        assert_eq!(decoded.direction, LEGACY_PLAINTEXT_DIRECTION_READ);
        assert_eq!(decoded.data[..2048], event.data[..2048]);
        assert!(decoded.data[2048..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn plaintext_variable_perf_record_rejects_overstated_lengths() {
        const HEADER_LEN: usize = size_of::<LegacyPlaintextEvent>() - LEGACY_PLAINTEXT_LEN;
        let event = plaintext_event(0, (LEGACY_PLAINTEXT_LEN + 1) as u32, 0);
        let mut record = vec![0u8; HEADER_LEN];
        record[12..16].copy_from_slice(&event.len.to_ne_bytes());
        assert!(plaintext_event_from_record(&record).is_none());
    }

    fn cursor_test_rereader() -> CursorRereader {
        CursorRereader {
            max_bytes: 1_024 * 1_024,
            ttl_ns: 500_000_000,
            claims: RefCell::new(VecDeque::new()),
        }
    }

    fn patterned_chunk(len: usize) -> PlaintextChunk {
        let mut event = plaintext_event(0, len as u32, (len * 2) as u32);
        for (index, byte) in event.data[..len].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        plaintext_chunk_from_event(&event, 999, &mut PlaintextSequencer::default())
    }

    fn cursor_for(chunk: &PlaintextChunk, remaining: u32, resume_buf: u64) -> LegacyCursorExt {
        LegacyCursorExt {
            magic: LEGACY_CURSOR_EXT_MAGIC,
            resume_buf,
            tail_fnv64: fnv1a64(&chunk.data[chunk.data.len() - LEGACY_CURSOR_TAIL_LEN..]),
            remaining,
            tail_len: LEGACY_CURSOR_TAIL_LEN as u32,
        }
    }

    #[test]
    fn fnv1a64_matches_reference_vectors() {
        assert_eq!(fnv1a64(b""), 14_695_981_039_346_656_037);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn cursor_ext_record_tail_round_trips_and_stays_optional() {
        const HEADER_LEN: usize = size_of::<LegacyPlaintextEvent>() - LEGACY_PLAINTEXT_LEN;
        // 无扩展尾部的普通 record：游标为 None（旧对象/常规分片，旧解析行为不变）。
        let record = vec![0u8; HEADER_LEN + 1_024];
        assert!(cursor_ext_from_record(&record, HEADER_LEN, 1_024).is_none());
        // 尾部字节存在但 magic 不匹配（随机尾部）同样判 None。
        let record = vec![0u8; HEADER_LEN + 1_024 + size_of::<LegacyCursorExt>()];
        assert!(cursor_ext_from_record(&record, HEADER_LEN, 1_024).is_none());
        // 合法扩展尾部完整往返。
        let cursor = LegacyCursorExt {
            magic: LEGACY_CURSOR_EXT_MAGIC,
            resume_buf: 0x7f00_1000,
            tail_fnv64: 0x1122_3344_5566_7788,
            remaining: 300_000,
            tail_len: LEGACY_CURSOR_TAIL_LEN as u32,
        };
        let mut record = vec![0u8; HEADER_LEN + 1_024];
        record.extend_from_slice(&cursor.magic.to_ne_bytes());
        record.extend_from_slice(&cursor.resume_buf.to_ne_bytes());
        record.extend_from_slice(&cursor.tail_fnv64.to_ne_bytes());
        record.extend_from_slice(&cursor.remaining.to_ne_bytes());
        record.extend_from_slice(&cursor.tail_len.to_ne_bytes());
        assert_eq!(
            cursor_ext_from_record(&record, HEADER_LEN, 1_024),
            Some(cursor)
        );
    }

    #[test]
    fn cursor_patch_appends_payload_on_fingerprint_match() {
        let rereader = cursor_test_rereader();
        let mut chunk = patterned_chunk(LEGACY_PLAINTEXT_LEN);
        let payload_len = 100_000usize;
        let cursor = cursor_for(&chunk, payload_len as u32, 0x7f00_0000);
        let overlap: Vec<u8> = chunk.data[chunk.data.len() - LEGACY_CURSOR_TAIL_LEN..].to_vec();
        let reader = move |_pid: u32, addr: u64, len: usize| {
            assert_eq!(addr, 0x7f00_0000 - LEGACY_CURSOR_TAIL_LEN as u64);
            assert_eq!(len, LEGACY_CURSOR_TAIL_LEN + payload_len);
            let mut buf = overlap.clone();
            buf.extend(std::iter::repeat(9u8).take(payload_len));
            Some(buf)
        };
        let appended = rereader
            .patch(&mut chunk, &cursor, 1_000, 2_000, &reader)
            .expect("fingerprint match must patch");
        assert_eq!(appended, Some(payload_len));
        assert_eq!(chunk.data.len(), LEGACY_PLAINTEXT_LEN + payload_len);
        assert!(chunk
            .partial_reasons
            .contains(&"cursor_reread_patched".to_string()));
        assert!(!chunk
            .partial_reasons
            .contains(&"cursor_reread_capped".to_string()));
        // 原始 partial 元数据保留可追溯。
        assert!(chunk
            .partial_reasons
            .contains(&"probe_call_limit".to_string()));
    }

    #[test]
    fn cursor_patch_rejects_overlap_fingerprint_mismatch() {
        let rereader = cursor_test_rereader();
        let mut chunk = patterned_chunk(LEGACY_PLAINTEXT_LEN);
        let cursor = cursor_for(&chunk, 50_000, 0x7f00_0000);
        let before = chunk.data.clone();
        // 目标内存已被复用：衔接处 64B 全零，指纹必不匹配。
        let reader = |_pid: u32, _addr: u64, len: usize| Some(vec![0u8; len]);
        let reject = rereader
            .patch(&mut chunk, &cursor, 1_000, 2_000, &reader)
            .expect_err("stale target memory must reject");
        assert_eq!(reject, PatchReject::OverlapFingerprint);
        assert_eq!(
            chunk.data, before,
            "rejected patch must keep the partial untouched"
        );
        assert!(!chunk
            .partial_reasons
            .contains(&"cursor_reread_patched".to_string()));
    }

    #[test]
    fn cursor_patch_rejects_self_fingerprint_mismatch() {
        let rereader = cursor_test_rereader();
        let mut chunk = patterned_chunk(LEGACY_PLAINTEXT_LEN);
        let mut cursor = cursor_for(&chunk, 50_000, 0x7f00_0000);
        cursor.tail_fnv64 ^= 0xffff; // 解析串道：游标不是为本 chunk 算的
        let before = chunk.data.len();
        let reader = |_pid: u32, _addr: u64, _len: usize| -> Option<Vec<u8>> {
            panic!("self fingerprint mismatch must not touch target memory")
        };
        let reject = rereader
            .patch(&mut chunk, &cursor, 1_000, 2_000, &reader)
            .expect_err("self fingerprint mismatch must reject");
        assert_eq!(reject, PatchReject::SelfFingerprint);
        assert_eq!(chunk.data.len(), before);
    }

    #[test]
    fn cursor_patch_rejects_expired_cursor_without_reading() {
        let rereader = cursor_test_rereader();
        let mut chunk = patterned_chunk(LEGACY_PLAINTEXT_LEN);
        let cursor = cursor_for(&chunk, 50_000, 0x7f00_0000);
        let reader = |_pid: u32, _addr: u64, _len: usize| -> Option<Vec<u8>> {
            panic!("expired cursor must not touch target memory")
        };
        let reject = rereader
            .patch(&mut chunk, &cursor, 1_000, 1_000 + 600_000_000, &reader)
            .expect_err("expired cursor must reject");
        assert_eq!(reject, PatchReject::TtlExpired);
    }

    #[test]
    fn cursor_patch_caps_payload_at_max_bytes() {
        let rereader = CursorRereader {
            max_bytes: 256 * 1_024,
            ttl_ns: 500_000_000,
            claims: RefCell::new(VecDeque::new()),
        };
        let mut chunk = patterned_chunk(LEGACY_PLAINTEXT_LEN);
        let cursor = cursor_for(&chunk, 700_000, 0x7f00_0000);
        let overlap: Vec<u8> = chunk.data[chunk.data.len() - LEGACY_CURSOR_TAIL_LEN..].to_vec();
        let reader = move |_pid: u32, _addr: u64, len: usize| {
            assert_eq!(len, LEGACY_CURSOR_TAIL_LEN + 256 * 1_024);
            let mut buf = overlap.clone();
            buf.extend(std::iter::repeat(7u8).take(len - overlap.len()));
            Some(buf)
        };
        let appended = rereader
            .patch(&mut chunk, &cursor, 1_000, 2_000, &reader)
            .expect("capped patch must still append");
        assert_eq!(appended, Some(256 * 1_024));
        assert_eq!(chunk.data.len(), LEGACY_PLAINTEXT_LEN + 256 * 1_024);
        assert!(chunk
            .partial_reasons
            .contains(&"cursor_reread_patched".to_string()));
        assert!(chunk
            .partial_reasons
            .contains(&"cursor_reread_capped".to_string()));
    }

    #[test]
    fn oversized_single_write_retires_as_partial_after_idle() {
        // 开发机 R3 验收实测形状：单次 sendto(32858) 被采成一个 len=16384、orig_len=32858
        // 的截断 chunk（partial_reasons=["probe_call_limit"]），网关收下完整 body 后回小包。
        // 该测试钉住存量行为：交互不在响应到达时完成（请求不完整），而是在 idle 边界以
        // partial 退休导出——验收脚本必须等过 idle 边界再判"零事件"。
        let body_len = 32_768usize;
        let head = format!("POST /r3test HTTP/1.1\r\nHost: x\r\nContent-Length: {body_len}\r\n\r\n");
        let mut full = head.into_bytes();
        full.extend(std::iter::repeat(b'x').take(body_len));
        let total = full.len();

        let mut request_event =
            plaintext_event(0, LEGACY_PLAINTEXT_LEN as u32, total as u32);
        request_event.data[..LEGACY_PLAINTEXT_LEN].copy_from_slice(&full[..LEGACY_PLAINTEXT_LEN]);
        let response_wire = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut response_event = plaintext_event(
            LEGACY_PLAINTEXT_DIRECTION_READ,
            response_wire.len() as u32,
            response_wire.len() as u32,
        );
        response_event.data[..response_wire.len()].copy_from_slice(response_wire);

        let mut sequencer = PlaintextSequencer::default();
        let mut reassembler = InteractionReassembler::with_idle_lanes(
            Duration::from_secs(90),
            Duration::from_secs(90),
        );
        let request_chunk = plaintext_chunk_from_event(&request_event, 1, &mut sequencer);
        assert_eq!(
            request_chunk.partial_reasons,
            vec!["probe_call_limit".to_string()]
        );
        assert_eq!(request_chunk.data.len(), LEGACY_PLAINTEXT_LEN);
        assert!(
            reassembler.push(request_chunk).is_empty(),
            "truncated request must stay buffered, not complete"
        );
        let response_chunk = plaintext_chunk_from_event(&response_event, 2, &mut sequencer);
        assert!(
            reassembler.push(response_chunk).is_empty(),
            "response completing while the request is partial must not flush early"
        );
        reassembler.expire_idle(Instant::now() + Duration::from_secs(91));
        let completed = reassembler.take_completed();
        assert_eq!(completed.len(), 1, "idle boundary must retire the partial: {completed:?}");
        assert!(completed[0]
            .partial_reasons
            .iter()
            .any(|r| r.contains("reassembly_idle_expire")));
        assert!(
            completed[0].request.captured_bytes > 0,
            "the truncated request prefix must be retained as partial evidence"
        );
    }

    fn repetitive_json_body(body_len: usize) -> String {
        let prefix = r#"{"model":"fixture-model","messages":[{"role":"user","content":""#;
        let suffix = r#""}]}"#;
        let pattern = b"0123456789abcdef";
        let mut body = String::with_capacity(body_len);
        body.push_str(prefix);
        body.extend(
            (0..body_len - prefix.len() - suffix.len())
                .map(|index| pattern[index % pattern.len()] as char),
        );
        body.push_str(suffix);
        assert_eq!(body.len(), body_len);
        body
    }

    fn assert_tls_cursor_reread_reassembles(full: Vec<u8>, expected_body: &str) {
        let tls_ctx = 0x7f12_3456_7890_u64;
        let rereader = cursor_test_rereader();
        let patch_reads = std::cell::Cell::new(0usize);
        let reader = |_pid, addr, len| {
            patch_reads.set(patch_reads.get() + 1);
            assert_eq!(addr, 0x7f00_0000 - LEGACY_CURSOR_TAIL_LEN as u64);
            assert_eq!(len, full.len() - 131_072 + LEGACY_CURSOR_TAIL_LEN);
            Some(full[131_072 - LEGACY_CURSOR_TAIL_LEN..].to_vec())
        };
        let mut sequencer = PlaintextSequencer::default();
        let mut reassembler = InteractionReassembler::default();
        let mut completed = Vec::new();
        for index in 0..8usize {
            let start = index * LEGACY_PLAINTEXT_LEN;
            let end = start + LEGACY_PLAINTEXT_LEN;
            let mut event = LegacyTlsPlaintextEvent {
                pid: 2_531_223,
                direction: 0,
                len: LEGACY_PLAINTEXT_LEN as u32,
                orig_len: (full.len() - start) as u32,
                tls_ctx,
                comm: [0; 16],
                captured_at_boot_ns: 1_000 + index as u64,
                data: [0; LEGACY_PLAINTEXT_LEN],
            };
            event.data.copy_from_slice(&full[start..end]);
            let mut chunk = tls_plaintext_chunk_from_event(
                &event,
                index as u128 + 1,
                &mut sequencer,
            );
            if index == 7 {
                let cursor = cursor_for(
                    &chunk,
                    (full.len() - 131_072) as u32,
                    0x7f00_0000,
                );
                assert_eq!(
                    rereader.patch(
                        &mut chunk,
                        &cursor,
                        event.captured_at_boot_ns,
                        2_000,
                        &reader,
                    ),
                    Ok(Some(full.len() - 131_072))
                );
                completed.extend(reassembler.push(chunk));

                let mut replay_results = Vec::new();
                for replay_index in 1..4u64 {
                    let mut replay = tls_plaintext_chunk_from_event(
                        &event,
                        index as u128 + replay_index as u128 + 1,
                        &mut sequencer,
                    );
                    let replay_cursor = cursor_for(
                        &replay,
                        (full.len() - 131_072) as u32,
                        0x7f00_0000,
                    );
                    let outcome = rereader.patch(
                        &mut replay,
                        &replay_cursor,
                        event.captured_at_boot_ns + replay_index * 6_000_000,
                        2_000 + replay_index * 6_000_000,
                        &reader,
                    );
                    let replay_len = replay.data.len();
                    if outcome != Ok(None) {
                        completed.extend(reassembler.push(replay));
                    }
                    replay_results.push((outcome, replay_len));
                }
                assert!(
                    replay_results.iter().all(|(outcome, len)| {
                        *outcome == Ok(None) && *len == LEGACY_PLAINTEXT_LEN
                    }),
                    "the same cursor must be consumed once across timestamped paths: {replay_results:?}"
                );
                continue;
            }
            completed.extend(reassembler.push(chunk));
        }

        let response_body = r#"{"choices":[{"message":{"content":"ok"}}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{response_body}",
            response_body.len()
        );
        let mut response_event = LegacyTlsPlaintextEvent {
            pid: 2_531_223,
            direction: LEGACY_PLAINTEXT_DIRECTION_READ,
            len: response.len() as u32,
            orig_len: response.len() as u32,
            tls_ctx,
            comm: [0; 16],
            captured_at_boot_ns: 2_000,
            data: [0; LEGACY_PLAINTEXT_LEN],
        };
        response_event.data[..response.len()].copy_from_slice(response.as_bytes());
        let response_chunk = tls_plaintext_chunk_from_event(&response_event, 9, &mut sequencer);
        completed.extend(reassembler.push(response_chunk));

        assert_eq!(patch_reads.get(), 1, "one cursor must be consumed once");
        assert_eq!(completed.len(), 1, "{completed:?}");
        assert_eq!(completed[0].request.body, expected_body);
        assert_eq!(completed[0].response.text.as_deref(), Some("ok"));
        assert!(completed[0]
            .partial_reasons
            .iter()
            .any(|reason| reason == "cursor_reread_patched"));
    }

    #[test]
    fn tls_cursor_reread_repetitive_body_reassembles_content_length_once() {
        let body_len = 307_200usize;
        let head = format!(
            "POST /r4 HTTP/1.1\r\nHost: 10.1.3.119:18443\r\nX-R4: 12345\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\n\r\n"
        );
        assert_eq!(head.len(), 114);
        let body = repetitive_json_body(body_len);
        let mut full = head.into_bytes();
        full.extend_from_slice(body.as_bytes());
        assert_eq!(full.len(), 307_314);
        assert_tls_cursor_reread_reassembles(full, &body);
    }

    #[test]
    fn tls_cursor_reread_reassembles_chunked_request_once() {
        let body = repetitive_json_body(220_000);
        let mut full = b"POST /v1/chat/completions HTTP/1.1\r\nHost: 10.1.3.119:18443\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for part in body.as_bytes().chunks(16 * 1024) {
            full.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            full.extend_from_slice(part);
            full.extend_from_slice(b"\r\n");
        }
        full.extend_from_slice(b"0\r\n\r\n");
        assert!(full.len() > 131_072);
        assert_tls_cursor_reread_reassembles(full, &body);
    }

    #[test]
    fn ssl_attach_keys_dedup_repeats_without_blocking_other_processes() {
        let first = SslAttachKey {
            pid: 42,
            start_time_ticks: 100,
            dev: 7,
            ino: 99,
        };
        let other_process = SslAttachKey { pid: 43, ..first };
        let reused_process = SslAttachKey {
            start_time_ticks: 101,
            ..first
        };
        let mut manager = SslUprobeManager::default();
        assert!(manager.attached.insert(first));
        for _ in 0..3 {
            assert!(!manager.attached.insert(first));
        }
        assert!(manager.attached.insert(other_process));
        assert!(manager.attached.insert(reused_process));
        assert_eq!(manager.attached.len(), 3);
    }

    #[test]
    fn ssl_attach_state_prunes_dead_or_reused_processes() {
        let pid = std::process::id() as i32;
        let start_time_ticks = ssl_process_start_ticks(pid).expect("current process start");
        let current = SslAttachKey {
            pid,
            start_time_ticks,
            dev: 7,
            ino: 99,
        };
        let stale = SslAttachKey {
            start_time_ticks: start_time_ticks.wrapping_sub(1),
            ..current
        };
        let mut manager = SslUprobeManager::default();
        manager.attached.extend([current, stale]);
        manager.failed.insert(stale);
        manager.prune_stale();
        assert!(manager.attached.contains(&current));
        assert!(!manager.attached.contains(&stale));
        assert!(!manager.failed.contains(&stale));
    }

    #[test]
    fn ssl_attach_key_retains_unavailable_process() {
        let key = SslAttachKey {
            pid: 42,
            start_time_ticks: 100,
            dev: 7,
            ino: 99,
        };
        assert!(key.matches(SslProcessState::Unavailable));
        assert!(key.matches(SslProcessState::Present(100)));
        assert!(!key.matches(SslProcessState::Present(101)));
        assert!(!key.matches(SslProcessState::Exited));
    }

    #[test]
    fn checked_ssl_attach_pid_rejects_invalid_values() {
        assert_eq!(checked_ssl_attach_pid(1).unwrap(), 1);
        for pid in [0, -1, i32::MIN] {
            assert!(checked_ssl_attach_pid(pid).is_err(), "pid={pid}");
        }
    }

    #[test]
    fn ssl_attach_diag_counts_repeat_successes() {
        let key = SslAttachKey {
            pid: 42,
            start_time_ticks: 100,
            dev: 7,
            ino: 99,
        };
        let mut manager = SslUprobeManager::default();
        for _ in 0..3 {
            manager.record_attach_success(key, Path::new("/tmp/libssl.so"));
        }
        assert_eq!(manager.attached.len(), 1);
        assert_eq!(manager.diag_entries[&key].attach_entries, 3);
        let invalid = SslAttachKey { pid: 0, ..key };
        manager.record_attach_success(invalid, Path::new("/tmp/libssl.so"));
        assert_eq!(manager.diag_entries[&invalid].attach_entries, 1);
        assert!(invalid.pid <= 0, "summary must mark invalid pid entries");
    }

    #[test]
    fn proc_root_alias_preserves_dev_and_inode() {
        use std::os::unix::fs::MetadataExt;

        let direct = std::fs::metadata("/etc/hosts").expect("direct metadata");
        let via_proc = std::fs::metadata(format!(
            "/proc/{}/root/etc/hosts",
            std::process::id()
        ))
        .expect("proc root metadata");
        assert_eq!(
            (direct.dev(), direct.ino()),
            (via_proc.dev(), via_proc.ino())
        );
    }

    fn missing_symbol_error() -> ProgramError {
        ProgramError::UProbeError(UProbeError::SymbolError {
            symbol: "SSL_write_ex".to_string(),
            error: Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "missing symbol",
            )),
        })
    }

    #[test]
    fn ssl_symbol_fallback_prefers_ex_without_adding_legacy() {
        let mut calls = Vec::new();
        attach_ssl_with_fallback(
            ("ex", "SSL_write_ex"),
            ("legacy", "SSL_write"),
            &mut |program, symbol| {
                calls.push((program.to_string(), symbol.to_string()));
                Ok(())
            },
        )
        .expect("_ex attach succeeds");
        assert_eq!(calls, [("ex".to_string(), "SSL_write_ex".to_string())]);
    }

    #[test]
    fn ssl_symbol_fallback_uses_legacy_only_when_ex_is_missing() {
        let mut calls = Vec::new();
        attach_ssl_with_fallback(
            ("ex", "SSL_write_ex"),
            ("legacy", "SSL_write"),
            &mut |program, symbol| {
                calls.push((program.to_string(), symbol.to_string()));
                if program == "ex" {
                    Err(missing_symbol_error())
                } else {
                    Ok(())
                }
            },
        )
        .expect("legacy fallback succeeds");
        assert_eq!(
            calls,
            [
                ("ex".to_string(), "SSL_write_ex".to_string()),
                ("legacy".to_string(), "SSL_write".to_string())
            ]
        );
    }

    #[test]
    fn ssl_symbol_fallback_does_not_hide_real_attach_errors() {
        let mut calls = Vec::new();
        let result = attach_ssl_with_fallback(
            ("ex", "SSL_write_ex"),
            ("legacy", "SSL_write"),
            &mut |program, symbol| {
                calls.push((program.to_string(), symbol.to_string()));
                Err(ProgramError::AlreadyLoaded)
            },
        );
        assert!(result.is_err());
        assert_eq!(calls, [("ex".to_string(), "SSL_write_ex".to_string())]);
    }

    #[test]
    fn duplicate_fragment_window_and_lru_rules() {
        let chunk = patterned_chunk(LEGACY_PLAINTEXT_LEN);
        let mut dedup = FragmentDedup::default();
        assert!(!dedup.should_suppress(&chunk, 307_314, 1_000));
        assert!(dedup.should_suppress(&chunk, 307_314, 1_000 + 5_000_000));
        assert!(!dedup.should_suppress(&chunk, 290_930, 1_000 + 6_000_000));
        let mut different = patterned_chunk(LEGACY_PLAINTEXT_LEN);
        different.data[0] ^= 1;
        assert!(!dedup.should_suppress(&different, 307_314, 1_000 + 7_000_000));
        assert!(!dedup.should_suppress(&chunk, 307_314, 1_000 + 26_000_000));
        assert!(dedup.should_suppress(&chunk, 307_314, 1_000 + 30_000_000));

        let mut bounded = FragmentDedup::default();
        for orig_len in 0..70 {
            assert!(!bounded.should_suppress(&chunk, orig_len, 1_000 + orig_len as u64));
        }
        let connection = &bounded.connections[&(chunk.connection_id, chunk.pid)];
        assert_eq!(connection.entries.len(), DUPLICATE_FRAGMENT_KEYS_PER_CONNECTION);
        assert!(!connection.entries.iter().any(|entry| entry.key.orig_len == 0));
        bounded.expire_idle(100_000_000, Duration::from_millis(25));
        assert!(bounded.connections.is_empty());

        let mut capped = FragmentDedup::default();
        for pid in 1..=(DUPLICATE_FRAGMENT_MAX_CONNECTIONS as u32 + 10) {
            let mut other = chunk.clone();
            other.pid = pid;
            capped.should_suppress(&other, 307_314, 1_000);
        }
        assert_eq!(capped.connections.len(), DUPLICATE_FRAGMENT_MAX_CONNECTIONS);
    }

    #[test]
    fn duplicate_fragment_groups_are_suppressed_before_reassembly() {
        let tls_ctx = 0x7f12_3456_7890_u64;
        let body_len = 307_200usize;
        let head = format!(
            "POST /r4 HTTP/1.1\r\nHost: 10.1.3.119:18443\r\nX-R4: 12345\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\n\r\n"
        );
        assert_eq!(head.len(), 114);
        let body = repetitive_json_body(body_len);
        let mut full = head.into_bytes();
        full.extend_from_slice(body.as_bytes());
        assert_eq!(full.len(), 307_314);

        let rereader = cursor_test_rereader();
        let patch_reads = std::cell::Cell::new(0usize);
        let reader = |_pid, addr, len| {
            patch_reads.set(patch_reads.get() + 1);
            assert_eq!(addr, 0x7f00_0000 - LEGACY_CURSOR_TAIL_LEN as u64);
            assert_eq!(len, full.len() - 131_072 + LEGACY_CURSOR_TAIL_LEN);
            Some(full[131_072 - LEGACY_CURSOR_TAIL_LEN..].to_vec())
        };
        let mut dedup = FragmentDedup::default();
        let mut sequencer = PlaintextSequencer::default();
        let mut reassembler = InteractionReassembler::default();
        let mut completed = Vec::new();
        for group in 0..2u64 {
            for index in 0..8usize {
                let start = index * LEGACY_PLAINTEXT_LEN;
                let end = start + LEGACY_PLAINTEXT_LEN;
                let captured_at_boot_ns = 1_000 + index as u64 + group * 5_000_000;
                let mut event = LegacyTlsPlaintextEvent {
                    pid: 2_531_223,
                    direction: 0,
                    len: LEGACY_PLAINTEXT_LEN as u32,
                    orig_len: (full.len() - start) as u32,
                    tls_ctx,
                    comm: [0; 16],
                    captured_at_boot_ns,
                    data: [0; LEGACY_PLAINTEXT_LEN],
                };
                event.data.copy_from_slice(&full[start..end]);
                let mut chunk = tls_plaintext_chunk_from_event(
                    &event,
                    captured_at_boot_ns as u128,
                    &mut sequencer,
                );
                let duplicate = suppress_duplicate_fragment(
                    &mut dedup,
                    &mut sequencer,
                    &chunk,
                    event.orig_len,
                    captured_at_boot_ns,
                    tls_ctx as u32,
                    (tls_ctx >> 32) as u32,
                );
                assert_eq!(duplicate, group == 1, "group={group} index={index}");
                if duplicate {
                    continue;
                }
                if index == 7 {
                    let cursor = cursor_for(
                        &chunk,
                        (full.len() - 131_072) as u32,
                        0x7f00_0000,
                    );
                    assert_eq!(
                        rereader.patch(&mut chunk, &cursor, captured_at_boot_ns, 20_000_000, &reader),
                        Ok(Some(full.len() - 131_072))
                    );
                }
                completed.extend(reassembler.push(chunk));
            }
        }

        let response_head = b"HTTP/1.0 200 OK\r\nServer: BaseHTTP/0.6 Python/3.9.21\r\nDate: Sun, 25 Oct 2026 18:59:16 GMT\r\nContent-Length: 2\r\n\r\n";
        assert_eq!(response_head.len(), 111);
        let response_event = |data: &[u8], captured_at_boot_ns: u64| {
            let mut event = LegacyTlsPlaintextEvent {
                pid: 2_531_223,
                direction: LEGACY_PLAINTEXT_DIRECTION_READ,
                len: data.len() as u32,
                orig_len: data.len() as u32,
                tls_ctx,
                comm: [0; 16],
                captured_at_boot_ns,
                data: [0; LEGACY_PLAINTEXT_LEN],
            };
            event.data[..data.len()].copy_from_slice(data);
            event
        };
        let response_chunk = tls_plaintext_chunk_from_event(
            &response_event(response_head, 30_000_000),
            30_000_000,
            &mut sequencer,
        );
        completed.extend(reassembler.push(response_chunk));
        assert!(
            completed.is_empty(),
            "a header-only response must wait for its declared two-byte body"
        );
        let response_chunk = tls_plaintext_chunk_from_event(
            &response_event(b"ok", 31_000_000),
            31_000_000,
            &mut sequencer,
        );
        completed.extend(reassembler.push(response_chunk));

        assert_eq!(patch_reads.get(), 1, "duplicate group must not patch again");
        assert_eq!(completed.len(), 1, "{completed:?}");
        assert_eq!(completed[0].request.body, body);
        assert_eq!(completed[0].response.body, "ok");
        assert_eq!(reassembler.metrics().sequence_gaps, 0);
        assert!(completed[0]
            .partial_reasons
            .iter()
            .any(|reason| reason == "cursor_reread_patched"));
        let evidence = reassembler.take_evidence();
        assert!(evidence.iter().any(|item| {
            item.reasons
                .iter()
                .any(|reason| reason == "probe_call_limit")
        }));
    }

    #[test]
    fn plaintext_sequencer_is_consecutive_per_connection_and_direction() {
        let mut sequencer = PlaintextSequencer::default();
        let ev = plaintext_event(0, 5, 5);
        let first = plaintext_chunk_from_event(&ev, 1, &mut sequencer);
        let second = plaintext_chunk_from_event(&ev, 2, &mut sequencer);
        assert_eq!(first.sequence, 1);
        assert_eq!(
            second.sequence, 2,
            "sequence must be previous+1 or the reassembler flags a gap"
        );
        let response = plaintext_chunk_from_event(
            &plaintext_event(LEGACY_PLAINTEXT_DIRECTION_READ, 5, 5),
            3,
            &mut sequencer,
        );
        assert_eq!(
            response.sequence, 1,
            "response direction has its own baseline"
        );
        let mut other_fd = plaintext_event(0, 5, 5);
        other_fd.fd = 99;
        let other = plaintext_chunk_from_event(&other_fd, 4, &mut sequencer);
        assert_eq!(other.sequence, 1, "a different fd is a different stream");
    }

    #[test]
    fn perf_ring_pages_env_priority_and_bounds() {
        // Both knobs live in one test body: env mutation is process-global, so splitting the
        // cases across parallel tests would race.
        let default_pages = (512 * 1024_usize)
            .div_ceil(host_page_size())
            .clamp(8, 1_024);
        std::env::remove_var("A3S_OBSERVER_PERF_RING_KB");
        for (value, expected) in [
            (None, default_pages),
            (Some("64"), 64),
            (Some("0"), default_pages),
            (Some("99999"), default_pages),
            (Some("not-a-number"), default_pages),
        ] {
            match value {
                Some(v) => std::env::set_var("A3S_OBSERVER_PERF_RING_PAGES", v),
                None => std::env::remove_var("A3S_OBSERVER_PERF_RING_PAGES"),
            }
            assert_eq!(perf_ring_pages(), expected, "pages value={value:?}");
        }
        std::env::remove_var("A3S_OBSERVER_PERF_RING_PAGES");
        for (value, expected) in [
            (Some("256"), (256 * 1024_usize).div_ceil(host_page_size()).clamp(8, 1_024)),
            // Sub-page byte targets clamp up to the minimum page budget.
            (Some("1"), 8),
            // Huge byte targets clamp down to the maximum page budget.
            (Some("1048576"), 1_024),
            (Some("0"), default_pages),
            (Some("not-a-number"), default_pages),
        ] {
            std::env::set_var("A3S_OBSERVER_PERF_RING_KB", value.unwrap());
            assert_eq!(perf_ring_pages(), expected, "kb value={value:?}");
        }
        // An explicit byte target wins over an explicit page count.
        std::env::set_var("A3S_OBSERVER_PERF_RING_PAGES", "64");
        std::env::set_var("A3S_OBSERVER_PERF_RING_KB", "256");
        assert_eq!(
            perf_ring_pages(),
            (256 * 1024_usize).div_ceil(host_page_size()).clamp(8, 1_024)
        );
        std::env::remove_var("A3S_OBSERVER_PERF_RING_PAGES");
        std::env::remove_var("A3S_OBSERVER_PERF_RING_KB");
    }

    #[test]
    fn perf_lost_counters_split_totals_by_map() {
        let counters = PerfLostCounters::default();
        counters.record(perf_ring_index("PLAINTEXT_EVENTS"), 3);
        counters.record(perf_ring_index("EVENTS"), 2);
        counters.record(perf_ring_index("PLAINTEXT_EVENTS"), 4);
        assert_eq!(counters.total(), 9);
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.get("plaintext"), Some(&7));
        assert_eq!(snapshot.get("events"), Some(&2));
        assert_eq!(snapshot.get("plaintext_tls"), Some(&0));
        assert_eq!(snapshot.len(), PERF_RINGS.len());
    }

    #[test]
    fn reassembly_idle_timeout_env_is_bounded() {
        for (value, expected_secs) in [
            (None, 90),
            (Some("600"), 600),
            (Some("0"), 90),
            (Some("99999999"), 90),
            (Some("not-a-number"), 90),
        ] {
            match value {
                Some(v) => std::env::set_var("A3S_OBSERVER_REASSEMBLY_IDLE_TIMEOUT_SECONDS", v),
                None => std::env::remove_var("A3S_OBSERVER_REASSEMBLY_IDLE_TIMEOUT_SECONDS"),
            }
            assert_eq!(
                InteractionReassembler::reassembly_idle_timeout(),
                Duration::from_secs(expected_secs),
                "value={value:?}"
            );
        }
        std::env::remove_var("A3S_OBSERVER_REASSEMBLY_IDLE_TIMEOUT_SECONDS");
    }

    #[test]
    fn inflight_idle_timeout_defaults_to_fast_lane_and_is_bounded() {
        for (fast, slow, expected_secs) in [
            (None, None, 90),
            (None, Some("900"), 900),
            (Some("120"), None, 120), // 慢车道缺省跟随快车道
            (Some("120"), Some("900"), 900),
            (None, Some("0"), 90), // 越界回退快车道
            (None, Some("99999999"), 90),
            (None, Some("not-a-number"), 90),
        ] {
            match fast {
                Some(v) => std::env::set_var("A3S_OBSERVER_REASSEMBLY_IDLE_TIMEOUT_SECONDS", v),
                None => std::env::remove_var("A3S_OBSERVER_REASSEMBLY_IDLE_TIMEOUT_SECONDS"),
            }
            match slow {
                Some(v) => std::env::set_var("A3S_OBSERVER_INFLIGHT_IDLE_TIMEOUT_SECONDS", v),
                None => std::env::remove_var("A3S_OBSERVER_INFLIGHT_IDLE_TIMEOUT_SECONDS"),
            }
            assert_eq!(
                InteractionReassembler::inflight_idle_timeout(),
                Duration::from_secs(expected_secs),
                "fast={fast:?} slow={slow:?}"
            );
        }
        std::env::remove_var("A3S_OBSERVER_REASSEMBLY_IDLE_TIMEOUT_SECONDS");
        std::env::remove_var("A3S_OBSERVER_INFLIGHT_IDLE_TIMEOUT_SECONDS");
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
