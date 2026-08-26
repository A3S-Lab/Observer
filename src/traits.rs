//! Stable extension contracts: identity resolution, service classification, export.
//!
//! These are the swappable seams around the eBPF probe core. Each has a trivial default
//! implementation here; environment-specific ones (k8s, a3s-box, OTel) land with the
//! probes.

use crate::model::EnrichedEvent;
use crate::workload::WorkloadIdentity;
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Who an event belongs to. Resolved from kernel-side keys (pid / cgroup / netns).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Identity {
    pub agent: Option<String>,
    pub task: Option<String>,
    pub session: Option<String>,
}

/// Maps a kernel event's process/namespace keys to an [`Identity`].
///
/// Implementations: k8s (cgroup→pod), docker, a3s-box (pid/netns→box), bare pid-tree.
pub trait IdentityResolver: Send + Sync {
    fn resolve(&self, pid: u32, cgroup_id: u64, netns: u64) -> Identity;

    /// Resolve a complete, provider-neutral workload identity when one is available.
    ///
    /// Existing process-only resolvers remain valid and default to no workload attribution.
    /// Implementations must return `None` rather than inventing or partially filling identity.
    fn resolve_workload(
        &self,
        _pid: u32,
        _cgroup_id: u64,
        _netns: u64,
    ) -> Option<WorkloadIdentity> {
        None
    }
}

/// Known service providers, identified language-agnostically from TLS SNI / DNS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Provider {
    OpenAi,
    Anthropic,
    Gemini,
    Mistral,
    Cohere,
    XAi,
    DeepSeek,
    Groq,
    Together,
    Perplexity,
    Fireworks,
    OpenRouter,
    AzureOpenAi,
    Bedrock,
    Ollama,
    Other(String),
}

/// Classifies a network destination (SNI hostname and/or peer IP) into a [`Provider`].
pub trait ServiceClassifier: Send + Sync {
    fn classify(&self, sni: Option<&str>, peer: IpAddr) -> Option<Provider>;
}

/// Default classifier: maps well-known provider hostnames from the TLS ClientHello SNI.
///
/// SNI is plaintext today; Encrypted ClientHello (ECH) will eventually hide it, at which
/// point classification must fall back to IP/DNS correlation.
pub struct SniClassifier;

impl ServiceClassifier for SniClassifier {
    fn classify(&self, sni: Option<&str>, _peer: IpAddr) -> Option<Provider> {
        let host = sni?;
        Some(match host {
            h if h.ends_with("openai.azure.com") => Provider::AzureOpenAi,
            h if h.ends_with("openai.com") || h.ends_with("oaiusercontent.com") => Provider::OpenAi,
            h if h.ends_with("anthropic.com") => Provider::Anthropic,
            h if h.ends_with("googleapis.com") => Provider::Gemini,
            h if h.ends_with("mistral.ai") => Provider::Mistral,
            h if h.ends_with("cohere.ai") || h.ends_with("cohere.com") => Provider::Cohere,
            h if h.ends_with("x.ai") => Provider::XAi,
            h if h.ends_with("deepseek.com") => Provider::DeepSeek,
            h if h.ends_with("groq.com") => Provider::Groq,
            h if h.ends_with("together.xyz") || h.ends_with("together.ai") => Provider::Together,
            h if h.ends_with("perplexity.ai") => Provider::Perplexity,
            h if h.ends_with("fireworks.ai") => Provider::Fireworks,
            h if h.ends_with("openrouter.ai") => Provider::OpenRouter,
            h if h.ends_with("amazonaws.com") && h.contains("bedrock") => Provider::Bedrock,
            _ => return None,
        })
    }
}

/// Sink for enriched telemetry. Implementations: OTel (default target), Prometheus, log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportOutcome {
    Admitted,
    Dropped,
}

/// Service level used to isolate export backpressure.
///
/// `Semantic` is the compatibility default: existing callers keep their previous behavior until
/// they deliberately opt into priority-aware admission.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ExportPriority {
    Critical,
    #[default]
    Semantic,
    Bulk,
}

pub trait Exporter: Send + Sync {
    fn export(&self, event: &EnrichedEvent);
    /// Attempt to admit one event to the export queue.
    ///
    /// Synchronous and legacy exporters are admitted by definition. Queued exporters override
    /// this method so the collector can attribute backpressure to the originating ring without
    /// changing the existing `export` contract.
    fn export_with_outcome(&self, event: &EnrichedEvent) -> ExportOutcome {
        self.export(event);
        ExportOutcome::Admitted
    }
    /// Attempt to admit one event at an explicit service level.
    ///
    /// Exporters that do not implement priority isolation retain the legacy admission behavior.
    fn export_with_priority(
        &self,
        event: &EnrichedEvent,
        _priority: ExportPriority,
    ) -> ExportOutcome {
        self.export_with_outcome(event)
    }
    /// Export one terminal event and wait up to `timeout` for asynchronous output to be flushed.
    /// Synchronous exporters can rely on this default; queued exporters should override it.
    fn export_and_flush(&self, event: &EnrichedEvent, _timeout: Duration) -> bool {
        self.export(event);
        true
    }
    /// Output events rejected by a full queue or left unconfirmed by write/flush failure.
    /// Cumulative.
    fn output_drops(&self) -> u64 {
        0
    }
    /// Output drops for one service level. This is additive observability; the cumulative
    /// `output_drops` counter remains the compatibility contract.
    fn output_drops_by_priority(&self, _priority: ExportPriority) -> u64 {
        0
    }
}

/// Trivial exporter that logs via `tracing`. Useful for bring-up; OTel is the real target.
pub struct LogExporter;

impl Exporter for LogExporter {
    fn export(&self, event: &EnrichedEvent) {
        tracing::info!(?event, "a3s-observer event");
    }
}

/// Exporter that writes each event as one NDJSON line to stdout — consumable by any log
/// pipeline (vector / Loki / jq / files). OTLP is a drop-in via this same trait.
///
/// A dedicated writer thread owns stdout, fed by a bounded queue, so a slow/stalled consumer can
/// never block the caller's event loop — which would stall the 60s report + liveness heartbeat
/// and get the collector killed. When the queue is full, lines are dropped and counted instead.
pub struct JsonExporter {
    critical_tx: std::sync::mpsc::SyncSender<WriterData>,
    semantic_tx: std::sync::mpsc::SyncSender<WriterData>,
    bulk_tx: std::sync::mpsc::SyncSender<WriterData>,
    control_tx: std::sync::mpsc::SyncSender<FlushCommand>,
    next_barrier_id: std::sync::atomic::AtomicU64,
    dropped: std::sync::Arc<PriorityDropCounters>,
}

#[derive(Default)]
struct PriorityDropCounters {
    total: std::sync::atomic::AtomicU64,
    critical: std::sync::atomic::AtomicU64,
    semantic: std::sync::atomic::AtomicU64,
    bulk: std::sync::atomic::AtomicU64,
}

impl PriorityDropCounters {
    fn increment(&self, priority: ExportPriority) {
        self.increment_by(priority, 1);
    }

    fn increment_by(&self, priority: ExportPriority, count: u64) {
        use std::sync::atomic::Ordering;
        self.total.fetch_add(count, Ordering::Relaxed);
        self.for_priority(priority)
            .fetch_add(count, Ordering::Relaxed);
    }

    fn for_priority(&self, priority: ExportPriority) -> &std::sync::atomic::AtomicU64 {
        match priority {
            ExportPriority::Critical => &self.critical,
            ExportPriority::Semantic => &self.semantic,
            ExportPriority::Bulk => &self.bulk,
        }
    }
}

struct FlushCommand {
    event: EnrichedEvent,
    barrier_id: u64,
    ack: std::sync::mpsc::Sender<bool>,
}

enum WriterData {
    Event(Box<EnrichedEvent>),
    Barrier(u64),
}

struct WriterReceivers {
    critical: std::sync::mpsc::Receiver<WriterData>,
    semantic: std::sync::mpsc::Receiver<WriterData>,
    bulk: std::sync::mpsc::Receiver<WriterData>,
    control: std::sync::mpsc::Receiver<FlushCommand>,
    dropped: std::sync::Arc<PriorityDropCounters>,
}

#[derive(Default)]
struct PendingPriorityWrites {
    critical: u64,
    semantic: u64,
    bulk: u64,
}

impl PendingPriorityWrites {
    fn increment(&mut self, priority: ExportPriority) {
        let value = match priority {
            ExportPriority::Critical => &mut self.critical,
            ExportPriority::Semantic => &mut self.semantic,
            ExportPriority::Bulk => &mut self.bulk,
        };
        *value = value.saturating_add(1);
    }

    fn total(&self) -> u64 {
        self.critical
            .saturating_add(self.semantic)
            .saturating_add(self.bulk)
    }

    fn confirm(&mut self) {
        *self = Self::default();
    }

    fn reject(&mut self, dropped: &PriorityDropCounters) {
        dropped.increment_by(ExportPriority::Critical, self.critical);
        dropped.increment_by(ExportPriority::Semantic, self.semantic);
        dropped.increment_by(ExportPriority::Bulk, self.bulk);
        self.confirm();
    }
}

fn write_json_event<W: std::io::Write>(out: &mut W, event: &EnrichedEvent) -> bool {
    if serde_json::to_writer(&mut *out, event).is_err() {
        return false;
    }
    writeln!(out).is_ok()
}

// The lane-specific state is intentionally explicit so one call cannot accidentally update a
// different priority's disconnect, pending-write, barrier, or drop accounting.
#[allow(clippy::too_many_arguments)]
fn drain_priority<W: std::io::Write>(
    rx: &std::sync::mpsc::Receiver<WriterData>,
    out: &mut W,
    priority: ExportPriority,
    weight: usize,
    disconnected: &mut bool,
    pending: &mut PendingPriorityWrites,
    barrier_seen: &mut u64,
    dropped: &PriorityDropCounters,
) -> bool {
    let mut made_progress = false;
    for _ in 0..weight {
        match rx.try_recv() {
            Ok(WriterData::Event(event)) => {
                made_progress = true;
                if write_json_event(out, &event) {
                    pending.increment(priority);
                } else {
                    dropped.increment(priority);
                }
            }
            Ok(WriterData::Barrier(barrier_id)) => {
                made_progress = true;
                *barrier_seen = (*barrier_seen).max(barrier_id);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => break,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                *disconnected = true;
                break;
            }
        }
    }
    made_progress
}

fn run_json_writer<W: std::io::Write>(receivers: WriterReceivers, out: &mut W) {
    const MAX_BATCH_LINES: usize = 256;
    const MAX_BATCH_WAIT: Duration = Duration::from_millis(5);
    const IDLE_POLL_WAIT: Duration = Duration::from_millis(1);
    const CRITICAL_WEIGHT: usize = 8;
    const SEMANTIC_WEIGHT: usize = 4;
    const BULK_WEIGHT: usize = 1;

    let mut pending = PendingPriorityWrites::default();
    let mut last_flush = Instant::now();
    let mut critical_disconnected = false;
    let mut semantic_disconnected = false;
    let mut bulk_disconnected = false;
    let mut control_disconnected = false;
    let mut critical_barrier_seen = 0u64;
    let mut semantic_barrier_seen = 0u64;
    let mut bulk_barrier_seen = 0u64;
    let mut pending_flushes = std::collections::VecDeque::<FlushCommand>::new();

    loop {
        let mut made_progress = false;
        made_progress |= drain_priority(
            &receivers.critical,
            out,
            ExportPriority::Critical,
            CRITICAL_WEIGHT,
            &mut critical_disconnected,
            &mut pending,
            &mut critical_barrier_seen,
            receivers.dropped.as_ref(),
        );
        made_progress |= drain_priority(
            &receivers.semantic,
            out,
            ExportPriority::Semantic,
            SEMANTIC_WEIGHT,
            &mut semantic_disconnected,
            &mut pending,
            &mut semantic_barrier_seen,
            receivers.dropped.as_ref(),
        );
        made_progress |= drain_priority(
            &receivers.bulk,
            out,
            ExportPriority::Bulk,
            BULK_WEIGHT,
            &mut bulk_disconnected,
            &mut pending,
            &mut bulk_barrier_seen,
            receivers.dropped.as_ref(),
        );

        // Flush commands travel on an independent lane, but their per-data-lane barriers preserve
        // the legacy promise that all events admitted before a terminal heartbeat are durable
        // before it is written and acknowledged.
        match receivers.control.try_recv() {
            Ok(command) => {
                made_progress = true;
                pending_flushes.push_back(command);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                control_disconnected = true;
            }
        }

        while pending_flushes.front().is_some_and(|command| {
            critical_barrier_seen >= command.barrier_id
                && semantic_barrier_seen >= command.barrier_id
                && bulk_barrier_seen >= command.barrier_id
        }) {
            let command = pending_flushes.pop_front().expect("front checked above");
            let terminal_written = write_json_event(out, &command.event);
            let flushed = out.flush().is_ok();
            if flushed {
                pending.confirm();
            } else {
                pending.reject(receivers.dropped.as_ref());
            }
            last_flush = Instant::now();
            let _ = command.ack.send(terminal_written && flushed);
        }

        if pending.total() >= MAX_BATCH_LINES as u64
            || (pending.total() > 0 && last_flush.elapsed() >= MAX_BATCH_WAIT)
        {
            if out.flush().is_ok() {
                pending.confirm();
            } else {
                pending.reject(receivers.dropped.as_ref());
            }
            last_flush = Instant::now();
        }

        if critical_disconnected
            && semantic_disconnected
            && bulk_disconnected
            && control_disconnected
            && pending_flushes.is_empty()
        {
            if pending.total() > 0 {
                if out.flush().is_ok() {
                    pending.confirm();
                } else {
                    pending.reject(receivers.dropped.as_ref());
                }
            }
            break;
        }

        if !made_progress {
            std::thread::sleep(IDLE_POLL_WAIT);
        }
    }
}

const DEFAULT_CRITICAL_QUEUE_CAPACITY: usize = 8_192;
const DEFAULT_SEMANTIC_QUEUE_CAPACITY: usize = 32_768;
const DEFAULT_BULK_QUEUE_CAPACITY: usize = 8_192;
const MIN_PRIORITY_QUEUE_CAPACITY: usize = 64;
const MAX_PRIORITY_QUEUE_CAPACITY: usize = 262_144;
const CONTROL_QUEUE_CAPACITY: usize = 64;

fn configured_capacity(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(MIN_PRIORITY_QUEUE_CAPACITY, MAX_PRIORITY_QUEUE_CAPACITY)
}

impl JsonExporter {
    pub fn new() -> Self {
        let legacy_semantic_capacity = std::env::var("A3S_OBSERVER_JSON_QUEUE_CAPACITY")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_SEMANTIC_QUEUE_CAPACITY)
            .clamp(4_096, 262_144);

        let critical_capacity = configured_capacity(
            "A3S_OBSERVER_JSON_CRITICAL_QUEUE_CAPACITY",
            DEFAULT_CRITICAL_QUEUE_CAPACITY,
        );
        let semantic_capacity = std::env::var("A3S_OBSERVER_JSON_SEMANTIC_QUEUE_CAPACITY")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .map(|capacity| {
                capacity.clamp(MIN_PRIORITY_QUEUE_CAPACITY, MAX_PRIORITY_QUEUE_CAPACITY)
            })
            .unwrap_or(legacy_semantic_capacity);
        let bulk_capacity = configured_capacity(
            "A3S_OBSERVER_JSON_BULK_QUEUE_CAPACITY",
            DEFAULT_BULK_QUEUE_CAPACITY,
        );

        let dropped = std::sync::Arc::new(PriorityDropCounters::default());
        let (critical_tx, critical) = std::sync::mpsc::sync_channel(critical_capacity);
        let (semantic_tx, semantic) = std::sync::mpsc::sync_channel(semantic_capacity);
        let (bulk_tx, bulk) = std::sync::mpsc::sync_channel(bulk_capacity);
        let (control_tx, control) = std::sync::mpsc::sync_channel(CONTROL_QUEUE_CAPACITY);
        let writer_dropped = dropped.clone();
        std::thread::spawn(move || {
            let stdout = std::io::stdout();
            // Stdout is line-buffered; an outer buffer avoids one pipe write per event while the
            // writer loop above still bounds latency to five milliseconds.
            let mut out = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
            run_json_writer(
                WriterReceivers {
                    critical,
                    semantic,
                    bulk,
                    control,
                    dropped: writer_dropped,
                },
                &mut out,
            );
        });
        Self {
            critical_tx,
            semantic_tx,
            bulk_tx,
            control_tx,
            next_barrier_id: std::sync::atomic::AtomicU64::new(0),
            dropped,
        }
    }

    fn sender_for(&self, priority: ExportPriority) -> &std::sync::mpsc::SyncSender<WriterData> {
        match priority {
            ExportPriority::Critical => &self.critical_tx,
            ExportPriority::Semantic => &self.semantic_tx,
            ExportPriority::Bulk => &self.bulk_tx,
        }
    }
}

impl Default for JsonExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for JsonExporter {
    fn export(&self, event: &EnrichedEvent) {
        let _ = self.export_with_outcome(event);
    }

    fn export_with_outcome(&self, event: &EnrichedEvent) -> ExportOutcome {
        self.export_with_priority(event, ExportPriority::Semantic)
    }

    fn export_with_priority(
        &self,
        event: &EnrichedEvent,
        priority: ExportPriority,
    ) -> ExportOutcome {
        // Clone + try_send is bounded and never waits for stdout, JSON serialization, or another
        // service level. Independent queues reserve critical capacity from bulk saturation.
        if self
            .sender_for(priority)
            .try_send(WriterData::Event(Box::new(event.clone())))
            .is_err()
        {
            self.dropped.increment(priority);
            ExportOutcome::Dropped
        } else {
            ExportOutcome::Admitted
        }
    }

    fn export_and_flush(&self, event: &EnrichedEvent, timeout: Duration) -> bool {
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        let started = Instant::now();
        let barrier_id = self
            .next_barrier_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .wrapping_add(1);

        // A marker in each FIFO data lane forms a snapshot barrier without sharing capacity
        // between service levels. Full lanes are retried only within the caller's flush timeout;
        // ordinary export remains strictly non-blocking.
        for sender in [&self.critical_tx, &self.semantic_tx, &self.bulk_tx] {
            let mut marker = WriterData::Barrier(barrier_id);
            loop {
                match sender.try_send(marker) {
                    Ok(()) => break,
                    Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                        marker = returned;
                        let remaining = timeout.saturating_sub(started.elapsed());
                        if remaining.is_zero() {
                            self.dropped.increment(ExportPriority::Critical);
                            return false;
                        }
                        std::thread::sleep(remaining.min(Duration::from_millis(1)));
                    }
                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                        self.dropped.increment(ExportPriority::Critical);
                        return false;
                    }
                }
            }
        }

        let mut command = FlushCommand {
            event: event.clone(),
            barrier_id,
            ack: ack_tx,
        };

        loop {
            match self.control_tx.try_send(command) {
                Ok(()) => break,
                Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                    command = returned;
                    let remaining = timeout.saturating_sub(started.elapsed());
                    if remaining.is_zero() {
                        self.dropped.increment(ExportPriority::Critical);
                        return false;
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(1)));
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    self.dropped.increment(ExportPriority::Critical);
                    return false;
                }
            }
        }

        let flushed = matches!(
            ack_rx.recv_timeout(timeout.saturating_sub(started.elapsed())),
            Ok(true)
        );
        if !flushed {
            self.dropped.increment(ExportPriority::Critical);
        }
        flushed
    }

    fn output_drops(&self) -> u64 {
        self.dropped
            .total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn output_drops_by_priority(&self, priority: ExportPriority) -> u64 {
        self.dropped
            .for_priority(priority)
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Default [`IdentityResolver`]: reads `/proc/<pid>` — the process `comm` as the agent
/// label and the parent pid from `stat`. Works on bare hosts; a cgroup→pod resolver for
/// k8s is a future addition. (A short-lived process may exit before resolution; then the
/// agent label is `None`.)
pub struct ProcResolver;

impl IdentityResolver for ProcResolver {
    fn resolve(&self, pid: u32, _cgroup_id: u64, _netns: u64) -> Identity {
        Identity {
            agent: read_comm(pid),
            task: Some(pid.to_string()),
            session: None,
        }
    }
}

/// Parent pid of `pid` via `/proc/<pid>/stat` (0 if unavailable). Userspace process-tree
/// without eBPF CO-RE.
pub fn read_ppid(pid: u32) -> u32 {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .as_deref()
        .and_then(parse_ppid_from_stat)
        .unwrap_or(0)
}

fn read_comm(pid: u32) -> Option<String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

/// Field 4 (ppid) of a `/proc/<pid>/stat` line — robust to `)` / spaces inside the comm.
fn parse_ppid_from_stat(stat: &str) -> Option<u32> {
    let tail = stat.rsplit_once(')')?.1; // drop "pid (comm)"
    tail.split_whitespace().nth(1)?.parse().ok() // remaining = [state, ppid, ...]
}

/// [`IdentityResolver`] for Kubernetes / containers: reads `/proc/<pid>/cgroup` once per
/// cgroup identity and caches the parsed pod UID + container id. Bare-host process names are
/// supplied by the collector's kernel `comm` fallback, avoiding another per-event `/proc` read.
/// Pod *names* still come from the AnySentry Kubernetes identity snapshot.
pub struct KubeResolver;

impl IdentityResolver for KubeResolver {
    fn resolve(&self, pid: u32, cgroup_id: u64, _netns: u64) -> Identity {
        let cache_key = (cgroup_id, if cgroup_id == 0 { pid } else { 0 });
        let now = Instant::now();
        let cached = kube_identity_cache().lock().ok().and_then(|mut cache| {
            let cached = cache.get(&cache_key)?;
            if now.duration_since(cached.refreshed_at) <= KUBE_IDENTITY_CACHE_TTL {
                Some(cached.identity.clone())
            } else {
                cache.remove(&cache_key);
                None
            }
        });
        let resolved = cached.or_else(|| {
            let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
            let parsed = parse_cgroup(&cgroup);
            if let Ok(mut cache) = kube_identity_cache().lock() {
                if cache.len() >= KUBE_IDENTITY_CACHE_LIMIT {
                    cache.clear();
                }
                cache.insert(
                    cache_key,
                    CachedKubeId {
                        identity: parsed.clone(),
                        refreshed_at: now,
                    },
                );
            }
            Some(parsed)
        });
        if let Some(kube) = resolved {
            if kube.pod_uid.is_some() || kube.container_id.is_some() {
                return Identity {
                    agent: kube.pod_uid.or_else(|| kube.container_id.clone()),
                    task: Some(pid.to_string()),
                    session: kube.container_id,
                };
            }
        }
        Identity {
            agent: None,
            task: Some(pid.to_string()),
            session: None,
        }
    }
}

const KUBE_IDENTITY_CACHE_LIMIT: usize = 65_536;
const KUBE_IDENTITY_CACHE_TTL: Duration = Duration::from_secs(30);

fn kube_identity_cache() -> &'static Mutex<HashMap<(u64, u32), CachedKubeId>> {
    static CACHE: OnceLock<Mutex<HashMap<(u64, u32), CachedKubeId>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

struct CachedKubeId {
    identity: KubeId,
    refreshed_at: Instant,
}

#[derive(Clone)]
struct KubeId {
    pod_uid: Option<String>,
    container_id: Option<String>,
}

/// Extract pod UID + (short) container id from a `/proc/<pid>/cgroup` body. Handles the
/// common containerd (`...-pod<uid>.slice/cri-containerd-<64hex>.scope`) and docker
/// (`docker-<64hex>.scope`) layouts; returns `None`s for a non-container cgroup.
fn parse_cgroup(s: &str) -> KubeId {
    let mut pod_uid = None;
    let mut container_id = None;
    for seg in s.split(['/', '.', '-']) {
        if seg.len() == 64 && seg.bytes().all(|b| b.is_ascii_hexdigit()) {
            container_id = Some(seg[..12].to_owned()); // short id
        } else if let Some(uid) = seg.strip_prefix("pod") {
            if uid.len() >= 30 {
                pod_uid = Some(uid.replace('_', "-")); // containerd uses '_' in the UID
            }
        }
    }
    KubeId {
        pod_uid,
        container_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EventCaptureDecision, EventTiming};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct SharedWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
        flushes: Arc<AtomicUsize>,
    }

    impl std::io::Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct WriteFailWriter;

    impl std::io::Write for WriteFailWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "test writer is closed",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct FlushFailWriter;

    impl std::io::Write for FlushFailWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "test flush is closed",
            ))
        }
    }

    fn exit_event(pid: u32) -> EnrichedEvent {
        EnrichedEvent {
            timing: None,
            capture_decision: None,
            identity: Identity {
                agent: Some("agent-x".into()),
                task: Some(pid.to_string()),
                session: None,
            },
            workload: None,
            observation: None,
            process: None,
            provider: None,
            event: crate::model::AgentEvent::ProcessExit {
                pid,
                exit_code: 0,
                signal: 0,
            },
        }
    }

    fn exporter_harness(
        critical_capacity: usize,
        semantic_capacity: usize,
        bulk_capacity: usize,
        control_capacity: usize,
    ) -> (JsonExporter, WriterReceivers) {
        let dropped = Arc::new(PriorityDropCounters::default());
        let (critical_tx, critical) = std::sync::mpsc::sync_channel(critical_capacity);
        let (semantic_tx, semantic) = std::sync::mpsc::sync_channel(semantic_capacity);
        let (bulk_tx, bulk) = std::sync::mpsc::sync_channel(bulk_capacity);
        let (control_tx, control) = std::sync::mpsc::sync_channel(control_capacity);
        (
            JsonExporter {
                critical_tx,
                semantic_tx,
                bulk_tx,
                control_tx,
                next_barrier_id: std::sync::atomic::AtomicU64::new(0),
                dropped: dropped.clone(),
            },
            WriterReceivers {
                critical,
                semantic,
                bulk,
                control,
                dropped,
            },
        )
    }

    fn output_pids(output: &SharedWriter) -> Vec<u64> {
        let body = String::from_utf8(output.bytes.lock().unwrap().clone()).unwrap();
        body.lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["event"]["ProcessExit"]
                    ["pid"]
                    .as_u64()
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn ndjson_writer_preserves_exact_additive_event_times() {
        const EVENT_NS: u128 = 1_787_232_013_745_331_901;
        const RECEIVED_NS: u128 = EVENT_NS + 42;
        let mut event = exit_event(7);
        event.timing = Some(EventTiming::from_unix_ns(EVENT_NS, RECEIVED_NS));
        event.capture_decision = Some(EventCaptureDecision::new(
            13_349_539_092_725_721,
            6,
            1,
            2,
            1,
            true,
            1,
        ));
        let mut output = Vec::new();

        assert!(write_json_event(&mut output, &event));
        assert_eq!(output.last(), Some(&b'\n'));
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["eventAtUnixNs"], EVENT_NS.to_string());
        assert_eq!(value["receivedAtUnixNs"], RECEIVED_NS.to_string());
        assert_eq!(value["captureEpoch"], "13349539092725721");
        assert_eq!(value["captureProfile"], 6);
        assert_eq!(value["captureSelected"], true);
    }

    #[test]
    fn ppid_parse_handles_parens_in_comm() {
        assert_eq!(parse_ppid_from_stat("7 (bash) S 1 1 0"), Some(1));
        assert_eq!(parse_ppid_from_stat("9 (weird (x) y) R 42 9 0"), Some(42));
        assert_eq!(parse_ppid_from_stat("garbage"), None);
    }

    #[test]
    fn sni_classifier_maps_known_hosts() {
        let c = SniClassifier;
        let ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            c.classify(Some("api.anthropic.com"), ip),
            Some(Provider::Anthropic)
        );
        assert_eq!(
            c.classify(Some("api.openai.com"), ip),
            Some(Provider::OpenAi)
        );
        assert_eq!(
            c.classify(Some("api.mistral.ai"), ip),
            Some(Provider::Mistral)
        );
        assert_eq!(
            c.classify(Some("api.deepseek.com"), ip),
            Some(Provider::DeepSeek)
        );
        assert_eq!(
            c.classify(Some("myorg.openai.azure.com"), ip),
            Some(Provider::AzureOpenAi)
        );
        assert_eq!(
            c.classify(Some("bedrock-runtime.us-east-1.amazonaws.com"), ip),
            Some(Provider::Bedrock)
        );
        assert_eq!(
            c.classify(Some("generativelanguage.googleapis.com"), ip),
            Some(Provider::Gemini)
        );
        assert_eq!(
            c.classify(Some("api.cohere.ai"), ip),
            Some(Provider::Cohere)
        );
        assert_eq!(c.classify(Some("api.x.ai"), ip), Some(Provider::XAi));
        assert_eq!(c.classify(Some("api.groq.com"), ip), Some(Provider::Groq));
        assert_eq!(
            c.classify(Some("api.together.xyz"), ip),
            Some(Provider::Together)
        );
        assert_eq!(
            c.classify(Some("api.perplexity.ai"), ip),
            Some(Provider::Perplexity)
        );
        assert_eq!(
            c.classify(Some("api.fireworks.ai"), ip),
            Some(Provider::Fireworks)
        );
        assert_eq!(
            c.classify(Some("openrouter.ai"), ip),
            Some(Provider::OpenRouter)
        );
        assert_eq!(c.classify(None, ip), None); // no SNI → unclassified
        assert_eq!(c.classify(Some("example.com"), ip), None);
    }

    #[test]
    fn parse_cgroup_extracts_containerd_pod_and_container() {
        // containerd / cri-o systemd layout — pod UID uses '_' which must become '-'.
        let cg = "0::/kubepods.slice/kubepods-besteffort.slice/\
                  kubepods-besteffort-poda1b2c3d4_e5f6_7890_abcd_ef1234567890.slice/\
                  cri-containerd-1111111111111111111111111111111111111111111111111111111111111111.scope\n";
        let k = parse_cgroup(cg);
        assert_eq!(
            k.pod_uid.as_deref(),
            Some("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        );
        assert_eq!(k.container_id.as_deref(), Some("111111111111")); // short id (12)
    }

    #[test]
    fn parse_cgroup_extracts_docker_container_only() {
        let cg = "0::/system.slice/\
                  docker-2222222222222222222222222222222222222222222222222222222222222222.scope\n";
        let k = parse_cgroup(cg);
        assert_eq!(k.container_id.as_deref(), Some("222222222222"));
        assert_eq!(k.pod_uid, None);
    }

    #[test]
    fn parse_cgroup_none_for_bare_host() {
        let k = parse_cgroup("0::/user.slice/user-1000.slice/session-2.scope\n");
        assert!(k.pod_uid.is_none());
        assert!(k.container_id.is_none());
    }

    #[test]
    fn json_exporter_export_is_nonblocking() {
        let (ex, _receivers) = exporter_harness(64, 64, 64, 4);
        let ev = exit_event(1);
        let started = Instant::now();
        for _ in 0..50 {
            ex.export(&ev);
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(ex.output_drops(), 0); // 50 << queue cap → nothing dropped, never blocks
    }

    #[test]
    fn json_exporter_reports_queue_admission_and_drop_without_changing_legacy_counter() {
        let (ex, _receivers) = exporter_harness(1, 1, 1, 1);

        assert_eq!(
            ex.export_with_outcome(&exit_event(1)),
            ExportOutcome::Admitted
        );
        let started = Instant::now();
        assert_eq!(
            ex.export_with_outcome(&exit_event(2)),
            ExportOutcome::Dropped
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(ex.output_drops(), 1);
        assert_eq!(ex.output_drops_by_priority(ExportPriority::Semantic), 1);
        assert_eq!(ex.output_drops_by_priority(ExportPriority::Critical), 0);
        assert_eq!(ex.output_drops_by_priority(ExportPriority::Bulk), 0);
    }

    #[test]
    fn json_exporter_bulk_saturation_preserves_critical_admission() {
        let (ex, _receivers) = exporter_harness(1, 1, 1, 1);

        assert_eq!(
            ex.export_with_priority(&exit_event(1), ExportPriority::Bulk),
            ExportOutcome::Admitted
        );
        assert_eq!(
            ex.export_with_priority(&exit_event(2), ExportPriority::Bulk),
            ExportOutcome::Dropped
        );
        assert_eq!(
            ex.export_with_priority(&exit_event(3), ExportPriority::Critical),
            ExportOutcome::Admitted
        );
        assert_eq!(ex.output_drops(), 1);
        assert_eq!(ex.output_drops_by_priority(ExportPriority::Bulk), 1);
        assert_eq!(ex.output_drops_by_priority(ExportPriority::Critical), 0);
    }

    #[test]
    fn json_writer_weighted_round_services_all_priorities() {
        let (ex, receivers) = exporter_harness(16, 16, 16, 1);
        for pid in 100..109 {
            assert_eq!(
                ex.export_with_priority(&exit_event(pid), ExportPriority::Critical),
                ExportOutcome::Admitted
            );
        }
        for pid in 200..205 {
            assert_eq!(
                ex.export_with_priority(&exit_event(pid), ExportPriority::Semantic),
                ExportOutcome::Admitted
            );
        }
        for pid in 300..302 {
            assert_eq!(
                ex.export_with_priority(&exit_event(pid), ExportPriority::Bulk),
                ExportOutcome::Admitted
            );
        }
        drop(ex);

        let mut output = SharedWriter::default();
        run_json_writer(receivers, &mut output);
        let pids = output_pids(&output);

        assert_eq!(&pids[..8], &[100, 101, 102, 103, 104, 105, 106, 107]);
        assert_eq!(&pids[8..12], &[200, 201, 202, 203]);
        assert_eq!(pids[12], 300);
        assert_eq!(&pids[13..], &[108, 204, 301]);
    }

    #[test]
    fn json_exporter_terminal_event_is_fifo_flushed_and_acknowledged() {
        let (ex, receivers) = exporter_harness(4, 4, 1, 1);
        assert_eq!(
            ex.export_with_priority(&exit_event(99), ExportPriority::Bulk),
            ExportOutcome::Admitted
        );
        assert_eq!(
            ex.export_with_priority(&exit_event(100), ExportPriority::Bulk),
            ExportOutcome::Dropped
        );
        ex.export(&exit_event(1));
        let output = SharedWriter::default();
        let observed = output.clone();
        let writer = std::thread::spawn(move || {
            let mut output = output;
            run_json_writer(receivers, &mut output);
        });

        assert!(ex.export_and_flush(&exit_event(2), Duration::from_secs(1)));
        assert_eq!(observed.flushes.load(Ordering::SeqCst), 1);
        let pids = output_pids(&observed);
        assert_eq!(pids, [1, 99, 2]);
        assert_eq!(ex.output_drops(), 1);
        assert_eq!(ex.output_drops_by_priority(ExportPriority::Bulk), 1);

        drop(ex);
        writer.join().unwrap();
    }

    #[test]
    fn json_exporter_terminal_barrier_flushes_more_than_one_weighted_round() {
        let (ex, receivers) = exporter_harness(18, 10, 4, 1);
        let mut expected = Vec::new();
        for pid in 100..118 {
            expected.push(pid as u64);
            assert_eq!(
                ex.export_with_priority(&exit_event(pid), ExportPriority::Critical),
                ExportOutcome::Admitted
            );
        }
        for pid in 200..210 {
            expected.push(pid as u64);
            assert_eq!(
                ex.export_with_priority(&exit_event(pid), ExportPriority::Semantic),
                ExportOutcome::Admitted
            );
        }
        for pid in 300..304 {
            expected.push(pid as u64);
            assert_eq!(
                ex.export_with_priority(&exit_event(pid), ExportPriority::Bulk),
                ExportOutcome::Admitted
            );
        }

        let output = SharedWriter::default();
        let observed = output.clone();
        let writer = std::thread::spawn(move || {
            let mut output = output;
            run_json_writer(receivers, &mut output);
        });

        assert!(ex.export_and_flush(&exit_event(999), Duration::from_secs(1)));
        let pids = output_pids(&observed);
        assert_eq!(pids.last(), Some(&999));
        assert_eq!(pids.len(), expected.len() + 1);
        let mut before_terminal = pids[..pids.len() - 1].to_vec();
        before_terminal.sort_unstable();
        assert_eq!(before_terminal, expected);
        assert!(observed.flushes.load(Ordering::SeqCst) >= 1);

        drop(ex);
        writer.join().unwrap();
    }

    #[test]
    fn json_writer_disconnect_drains_every_admitted_lane_before_exit() {
        let (ex, receivers) = exporter_harness(18, 10, 4, 1);
        let mut expected = Vec::new();
        for pid in 100..118 {
            expected.push(pid as u64);
            assert_eq!(
                ex.export_with_priority(&exit_event(pid), ExportPriority::Critical),
                ExportOutcome::Admitted
            );
        }
        for pid in 200..210 {
            expected.push(pid as u64);
            assert_eq!(
                ex.export_with_priority(&exit_event(pid), ExportPriority::Semantic),
                ExportOutcome::Admitted
            );
        }
        for pid in 300..304 {
            expected.push(pid as u64);
            assert_eq!(
                ex.export_with_priority(&exit_event(pid), ExportPriority::Bulk),
                ExportOutcome::Admitted
            );
        }
        drop(ex);

        let mut output = SharedWriter::default();
        run_json_writer(receivers, &mut output);
        let mut pids = output_pids(&output);
        pids.sort_unstable();
        assert_eq!(pids, expected);
    }

    #[test]
    fn json_writer_counts_write_failures_by_priority() {
        let (ex, receivers) = exporter_harness(1, 1, 1, 1);
        assert_eq!(
            ex.export_with_priority(&exit_event(1), ExportPriority::Critical),
            ExportOutcome::Admitted
        );
        assert_eq!(
            ex.export_with_priority(&exit_event(2), ExportPriority::Semantic),
            ExportOutcome::Admitted
        );
        assert_eq!(
            ex.export_with_priority(&exit_event(3), ExportPriority::Bulk),
            ExportOutcome::Admitted
        );
        let dropped = ex.dropped.clone();
        drop(ex);

        run_json_writer(receivers, &mut WriteFailWriter);

        assert_eq!(dropped.total.load(Ordering::Relaxed), 3);
        assert_eq!(
            dropped
                .for_priority(ExportPriority::Critical)
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            dropped
                .for_priority(ExportPriority::Semantic)
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            dropped
                .for_priority(ExportPriority::Bulk)
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn json_writer_counts_unconfirmed_buffered_events_when_flush_fails() {
        let (ex, receivers) = exporter_harness(1, 1, 1, 1);
        assert_eq!(
            ex.export_with_priority(&exit_event(1), ExportPriority::Critical),
            ExportOutcome::Admitted
        );
        assert_eq!(
            ex.export_with_priority(&exit_event(2), ExportPriority::Semantic),
            ExportOutcome::Admitted
        );
        assert_eq!(
            ex.export_with_priority(&exit_event(3), ExportPriority::Bulk),
            ExportOutcome::Admitted
        );
        let dropped = ex.dropped.clone();
        drop(ex);

        run_json_writer(receivers, &mut FlushFailWriter);

        assert_eq!(dropped.total.load(Ordering::Relaxed), 3);
        for priority in [
            ExportPriority::Critical,
            ExportPriority::Semantic,
            ExportPriority::Bulk,
        ] {
            assert_eq!(dropped.for_priority(priority).load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn json_exporter_terminal_event_timeout_is_bounded_and_counted() {
        let (ex, _receivers) = exporter_harness(1, 1, 1, 1);
        let started = Instant::now();

        assert!(!ex.export_and_flush(&exit_event(2), Duration::from_millis(20)));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(ex.output_drops(), 1);
        assert_eq!(ex.output_drops_by_priority(ExportPriority::Critical), 1);
    }

    #[test]
    fn cgroup_parse_containerd_docker_bare() {
        let cd = "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1a2b3c4d_5e6f_7890_abcd_ef1234567890.slice/cri-containerd-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.scope";
        let k = parse_cgroup(cd);
        assert_eq!(
            k.pod_uid.as_deref(),
            Some("1a2b3c4d-5e6f-7890-abcd-ef1234567890")
        );
        assert_eq!(k.container_id.as_deref(), Some("abcdef012345"));

        let dk = "0::/system.slice/docker-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.scope";
        let k2 = parse_cgroup(dk);
        assert_eq!(k2.container_id.as_deref(), Some("abcdef012345"));
        assert_eq!(k2.pod_uid, None);

        let bare = "0::/user.slice/user-1000.slice/session-3.scope";
        let k3 = parse_cgroup(bare);
        assert!(k3.pod_uid.is_none() && k3.container_id.is_none());
    }
}
