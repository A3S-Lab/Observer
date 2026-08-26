//! Bounded, non-blocking handoff primitives for the Collector's ring-drain hot path.
//!
//! This module deliberately has no dependency on eBPF or enrichment types. A ring reader only
//! needs to copy an owned payload into one of three physically independent inboxes. Expensive
//! enrichment and serialization can then consume the weighted output separately.

use a3s_observer_common::CaptureDecisionContext;
use std::cmp::Reverse;
#[cfg(test)]
use std::collections::VecDeque;
use std::collections::{BTreeMap, BinaryHeap};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::{self, error::TryRecvError, error::TrySendError, Receiver, Sender};

/// Every physical ring currently emitted by the Observer.
///
/// Keep this enum closed: adding a ring requires making an explicit service-class decision.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RingOrigin {
    Exec,
    Exit,
    Tls,
    Connect,
    Dns,
    FileAccess,
    FileRead,
    FileDelete,
    Llm,
    Ssl,
    Security,
}

impl RingOrigin {
    #[cfg(test)]
    pub const ALL: [Self; 11] = [
        Self::Exec,
        Self::Exit,
        Self::Tls,
        Self::Connect,
        Self::Dns,
        Self::FileAccess,
        Self::FileRead,
        Self::FileDelete,
        Self::Llm,
        Self::Ssl,
        Self::Security,
    ];

    pub const fn service_class(self) -> ServiceClass {
        match self {
            Self::Exec | Self::Exit | Self::FileDelete | Self::Security => ServiceClass::Critical,
            Self::FileRead => ServiceClass::Bulk,
            Self::Tls | Self::Connect | Self::Dns | Self::FileAccess | Self::Llm | Self::Ssl => {
                ServiceClass::Semantic
            }
        }
    }

    const fn tie_break_rank(self) -> u8 {
        // Same-timestamp correlation facts are intentionally ordered before their consumers;
        // lifecycle exits are ordered last. The timestamp remains the primary ordering fact.
        match self {
            Self::Exec => 0,
            Self::Connect => 1,
            Self::Tls => 2,
            Self::Dns => 3,
            Self::FileAccess => 4,
            Self::FileRead => 5,
            Self::FileDelete => 6,
            Self::Llm => 7,
            Self::Ssl => 8,
            Self::Security => 9,
            Self::Exit => 10,
        }
    }
}

/// Bulk data can only enter through a producer that explicitly creates an aggregate or sample.
/// No current raw ring maps to this class.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // S5 aggregate/sample producers opt into these lanes incrementally.
pub enum BulkOrigin {
    ServiceSummary,
    InfrastructureAggregate,
    UnknownSample,
}

impl BulkOrigin {
    const fn tie_break_rank(self) -> u8 {
        match self {
            Self::ServiceSummary => 0,
            Self::InfrastructureAggregate => 1,
            Self::UnknownSample => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PipelineOrigin {
    Ring(RingOrigin),
    #[allow(dead_code)] // S5 aggregate/sample producers opt into this lane incrementally.
    Bulk(BulkOrigin),
}

impl PipelineOrigin {
    pub const fn service_class(self) -> ServiceClass {
        match self {
            Self::Ring(origin) => origin.service_class(),
            Self::Bulk(_) => ServiceClass::Bulk,
        }
    }

    const fn tie_break_rank(self) -> (u8, u8) {
        match self {
            Self::Ring(origin) => (0, origin.tie_break_rank()),
            Self::Bulk(origin) => (1, origin.tie_break_rank()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ServiceClass {
    Critical,
    Semantic,
    Bulk,
}

pub const PIPELINE_WEIGHTED_BATCH: usize = 256 + 128 + 32;

const PIPELINE_SCHEDULE: [ServiceClass; 13] = [
    ServiceClass::Critical,
    ServiceClass::Semantic,
    ServiceClass::Critical,
    ServiceClass::Critical,
    ServiceClass::Semantic,
    ServiceClass::Critical,
    ServiceClass::Bulk,
    ServiceClass::Critical,
    ServiceClass::Semantic,
    ServiceClass::Critical,
    ServiceClass::Critical,
    ServiceClass::Semantic,
    ServiceClass::Critical,
];

/// The minimum stable process identity available in every raw ring record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProcessKey {
    pub cgroup_id: u64,
    pub pid: u32,
}

impl ProcessKey {
    pub const fn new(cgroup_id: u64, pid: u32) -> Self {
        Self { cgroup_id, pid }
    }
}

/// Owned bytes copied out of a ring record before the ring is drained again.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedPayload(Box<[u8]>);

impl OwnedPayload {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<Vec<u8>> for OwnedPayload {
    fn from(value: Vec<u8>) -> Self {
        Self(value.into_boxed_slice())
    }
}

impl From<Box<[u8]>> for OwnedPayload {
    fn from(value: Box<[u8]>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for OwnedPayload {
    fn from(value: &[u8]) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawEnvelope {
    pub origin: PipelineOrigin,
    /// Monotonic event time from `bpf_ktime_get_ns`, not userspace receipt time.
    pub captured_at_boot_ns: u64,
    /// Kernel event time translated through a Collector-owned monotonic/realtime calibration.
    pub event_at_unix_ns: u128,
    /// Time the ring reader copied this physical record, translated through the same calibration.
    pub received_at_unix_ns: u128,
    /// In-kernel decision copied from the additive Ring record tail.
    pub capture_decision: CaptureDecisionContext,
    pub cgroup_id: u64,
    pub pid: u32,
    /// Monotonic within one physical producer/ring. It is only a deterministic tie-breaker.
    pub local_sequence: u64,
    pub payload: OwnedPayload,
}

impl RawEnvelope {
    pub fn new(
        origin: PipelineOrigin,
        captured_at_boot_ns: u64,
        event_at_unix_ns: u128,
        received_at_unix_ns: u128,
        capture_decision: CaptureDecisionContext,
        cgroup_id: u64,
        pid: u32,
        local_sequence: u64,
        payload: impl Into<OwnedPayload>,
    ) -> Self {
        Self {
            origin,
            captured_at_boot_ns,
            event_at_unix_ns,
            received_at_unix_ns,
            capture_decision,
            cgroup_id,
            pid,
            local_sequence,
            payload: payload.into(),
        }
    }

    fn order_key(&self) -> EventOrderKey {
        let (origin_group, origin_rank) = self.origin.tie_break_rank();
        EventOrderKey {
            captured_at_boot_ns: self.captured_at_boot_ns,
            origin_group,
            origin_rank,
            local_sequence: self.local_sequence,
        }
    }

    pub const fn process_key(&self) -> ProcessKey {
        ProcessKey::new(self.cgroup_id, self.pid)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InboxLedger {
    pub depth: usize,
    pub high_water: usize,
    pub admitted: u64,
    pub dropped: u64,
}

impl InboxLedger {
    #[cfg(test)]
    pub fn offered(self) -> u64 {
        self.admitted.saturating_add(self.dropped)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboxCapacities {
    pub critical: usize,
    pub semantic: usize,
    pub bulk: usize,
}

impl InboxCapacities {
    pub const fn new(critical: usize, semantic: usize, bulk: usize) -> Self {
        Self {
            critical,
            semantic,
            bulk,
        }
    }
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
pub struct InboxFull {
    pub class: ServiceClass,
    pub envelope: RawEnvelope,
}

#[cfg(test)]
#[derive(Debug)]
struct BoundedInbox {
    capacity: usize,
    entries: VecDeque<RawEnvelope>,
    ledger: InboxLedger,
}

#[cfg(test)]
impl BoundedInbox {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            // Avoid an up-front allocation large enough to hide accidental oversized settings.
            entries: VecDeque::new(),
            ledger: InboxLedger::default(),
        }
    }

    fn try_push(&mut self, envelope: RawEnvelope) -> Result<(), RawEnvelope> {
        if self.entries.len() >= self.capacity {
            self.ledger.dropped = self.ledger.dropped.saturating_add(1);
            return Err(envelope);
        }

        self.entries.push_back(envelope);
        self.ledger.admitted = self.ledger.admitted.saturating_add(1);
        self.ledger.depth = self.entries.len();
        self.ledger.high_water = self.ledger.high_water.max(self.ledger.depth);
        Ok(())
    }

    fn pop_front(&mut self) -> Option<RawEnvelope> {
        let envelope = self.entries.pop_front()?;
        self.ledger.depth = self.entries.len();
        Some(envelope)
    }

    fn ledger(&self) -> InboxLedger {
        self.ledger
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Three physically independent bounded inboxes.
///
/// The schedule is the exact 256:128:32 ratio reduced to an 8:4:1 cycle. Empty classes lend their
/// slot to another non-empty class, so configured capacity is usable without changing isolation.
#[cfg(test)]
#[derive(Debug)]
pub struct PipelineInbox {
    critical: BoundedInbox,
    semantic: BoundedInbox,
    bulk: BoundedInbox,
    schedule_position: usize,
}

#[cfg(test)]
impl PipelineInbox {
    pub const CRITICAL_WEIGHT: usize = 256;
    pub const SEMANTIC_WEIGHT: usize = 128;
    pub const BULK_WEIGHT: usize = 32;
    pub const WEIGHTED_BATCH: usize =
        Self::CRITICAL_WEIGHT + Self::SEMANTIC_WEIGHT + Self::BULK_WEIGHT;

    pub fn new(capacities: InboxCapacities) -> Self {
        Self {
            critical: BoundedInbox::new(capacities.critical),
            semantic: BoundedInbox::new(capacities.semantic),
            bulk: BoundedInbox::new(capacities.bulk),
            schedule_position: 0,
        }
    }

    /// Attempts one O(1), non-waiting handoff. A full inbox returns ownership to the caller.
    pub fn try_push(&mut self, envelope: RawEnvelope) -> Result<(), InboxFull> {
        let class = envelope.origin.service_class();
        self.inbox_mut(class)
            .try_push(envelope)
            .map_err(|envelope| InboxFull { class, envelope })
    }

    /// Drains at most `limit` entries according to 256:128:32 weighted round-robin.
    pub fn drain_weighted(&mut self, limit: usize) -> Vec<RawEnvelope> {
        let mut drained = Vec::with_capacity(limit.min(self.depth()));
        while drained.len() < limit && !self.is_empty() {
            let scheduled = PIPELINE_SCHEDULE[self.schedule_position];
            self.schedule_position = (self.schedule_position + 1) % PIPELINE_SCHEDULE.len();

            if let Some(envelope) = self.pop_with_borrow(scheduled) {
                drained.push(envelope);
            }
        }
        drained
    }

    pub fn ledger(&self, class: ServiceClass) -> InboxLedger {
        self.inbox(class).ledger()
    }

    pub fn depth(&self) -> usize {
        self.critical.entries.len() + self.semantic.entries.len() + self.bulk.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.critical.is_empty() && self.semantic.is_empty() && self.bulk.is_empty()
    }

    fn pop_with_borrow(&mut self, scheduled: ServiceClass) -> Option<RawEnvelope> {
        // Borrow order rotates with the scheduled class instead of permanently favoring Critical.
        let candidates = match scheduled {
            ServiceClass::Critical => [
                ServiceClass::Critical,
                ServiceClass::Semantic,
                ServiceClass::Bulk,
            ],
            ServiceClass::Semantic => [
                ServiceClass::Semantic,
                ServiceClass::Bulk,
                ServiceClass::Critical,
            ],
            ServiceClass::Bulk => [
                ServiceClass::Bulk,
                ServiceClass::Critical,
                ServiceClass::Semantic,
            ],
        };
        candidates
            .into_iter()
            .find_map(|class| self.inbox_mut(class).pop_front())
    }

    fn inbox(&self, class: ServiceClass) -> &BoundedInbox {
        match class {
            ServiceClass::Critical => &self.critical,
            ServiceClass::Semantic => &self.semantic,
            ServiceClass::Bulk => &self.bulk,
        }
    }

    fn inbox_mut(&mut self, class: ServiceClass) -> &mut BoundedInbox {
        match class {
            ServiceClass::Critical => &mut self.critical,
            ServiceClass::Semantic => &mut self.semantic,
            ServiceClass::Bulk => &mut self.bulk,
        }
    }
}

#[derive(Debug)]
struct ChannelLaneLedger {
    capacity: usize,
    depth: AtomicUsize,
    high_water: AtomicUsize,
    admitted: AtomicU64,
    dropped: AtomicU64,
}

impl ChannelLaneLedger {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            depth: AtomicUsize::new(0),
            high_water: AtomicUsize::new(0),
            admitted: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    fn record_admitted(&self) {
        // Called before the reserved channel permit is published, so a receiver cannot decrement
        // depth first and high-water remains exact under producer/consumer concurrency.
        let depth = self.depth.fetch_add(1, Ordering::AcqRel) + 1;
        self.admitted.fetch_add(1, Ordering::Relaxed);
        self.high_water.fetch_max(depth, Ordering::Relaxed);
    }

    fn record_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn record_consumed(&self) {
        let previous = self.depth.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "pipeline channel depth underflow");
    }

    fn snapshot(&self) -> InboxLedger {
        InboxLedger {
            depth: self.depth.load(Ordering::Relaxed),
            high_water: self.high_water.load(Ordering::Relaxed),
            admitted: self.admitted.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }
}

/// Shared, lock-free accounting for the three physical channel lanes.
#[derive(Clone, Debug)]
pub struct PipelineChannelLedger {
    critical: Arc<ChannelLaneLedger>,
    semantic: Arc<ChannelLaneLedger>,
    bulk: Arc<ChannelLaneLedger>,
}

impl PipelineChannelLedger {
    pub fn snapshot(&self, class: ServiceClass) -> InboxLedger {
        self.lane(class).snapshot()
    }

    fn lane(&self, class: ServiceClass) -> &ChannelLaneLedger {
        match class {
            ServiceClass::Critical => self.critical.as_ref(),
            ServiceClass::Semantic => self.semantic.as_ref(),
            ServiceClass::Bulk => self.bulk.as_ref(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipelineSendErrorKind {
    Full,
    Disconnected,
}

#[derive(Debug, Eq, PartialEq)]
pub struct PipelineSendError {
    pub class: ServiceClass,
    pub kind: PipelineSendErrorKind,
    pub envelope: RawEnvelope,
}

/// Cloneable MPSC producer handle. Each service class has its own bounded physical channel.
#[derive(Clone, Debug)]
pub struct PipelineSender {
    critical: Sender<RawEnvelope>,
    semantic: Sender<RawEnvelope>,
    bulk: Sender<RawEnvelope>,
    ledger: PipelineChannelLedger,
}

impl PipelineSender {
    /// Attempts one admission. Only true lane-capacity exhaustion is reported as `Full`; producer
    /// concurrency retries the atomic reservation and cannot create a false drop.
    pub fn try_send(&self, envelope: RawEnvelope) -> Result<(), PipelineSendError> {
        let class = envelope.origin.service_class();
        let lane = self.ledger.lane(class);
        if lane.capacity == 0 {
            lane.record_dropped();
            return Err(PipelineSendError {
                class,
                kind: PipelineSendErrorKind::Full,
                envelope,
            });
        }

        let sender = match class {
            ServiceClass::Critical => &self.critical,
            ServiceClass::Semantic => &self.semantic,
            ServiceClass::Bulk => &self.bulk,
        };
        match sender.try_reserve() {
            Ok(permit) => {
                lane.record_admitted();
                permit.send(envelope);
                Ok(())
            }
            Err(error) => {
                lane.record_dropped();
                let kind = match error {
                    TrySendError::Full(()) => PipelineSendErrorKind::Full,
                    TrySendError::Closed(()) => PipelineSendErrorKind::Disconnected,
                };
                Err(PipelineSendError {
                    class,
                    kind,
                    envelope,
                })
            }
        }
    }

    #[cfg(test)]
    pub fn ledger(&self) -> &PipelineChannelLedger {
        &self.ledger
    }
}

/// Single consumer with persistent 256:128:32 weighted state across drain calls.
#[derive(Debug)]
pub struct PipelineReceiver {
    critical: Receiver<RawEnvelope>,
    semantic: Receiver<RawEnvelope>,
    bulk: Receiver<RawEnvelope>,
    ledger: PipelineChannelLedger,
    schedule_position: usize,
}

impl PipelineReceiver {
    pub fn try_drain_weighted(&mut self, limit: usize) -> Vec<RawEnvelope> {
        let total_depth = self
            .ledger
            .snapshot(ServiceClass::Critical)
            .depth
            .saturating_add(self.ledger.snapshot(ServiceClass::Semantic).depth)
            .saturating_add(self.ledger.snapshot(ServiceClass::Bulk).depth);
        let mut drained = Vec::with_capacity(limit.min(total_depth));
        while drained.len() < limit {
            let scheduled = PIPELINE_SCHEDULE[self.schedule_position];
            self.schedule_position = (self.schedule_position + 1) % PIPELINE_SCHEDULE.len();
            let Some(envelope) = self.try_recv_with_borrow(scheduled) else {
                break;
            };
            drained.push(envelope);
        }
        drained
    }

    pub fn ledger(&self) -> &PipelineChannelLedger {
        &self.ledger
    }

    fn try_recv_with_borrow(&mut self, scheduled: ServiceClass) -> Option<RawEnvelope> {
        let candidates = match scheduled {
            ServiceClass::Critical => [
                ServiceClass::Critical,
                ServiceClass::Semantic,
                ServiceClass::Bulk,
            ],
            ServiceClass::Semantic => [
                ServiceClass::Semantic,
                ServiceClass::Bulk,
                ServiceClass::Critical,
            ],
            ServiceClass::Bulk => [
                ServiceClass::Bulk,
                ServiceClass::Critical,
                ServiceClass::Semantic,
            ],
        };
        for class in candidates {
            let receiver = match class {
                ServiceClass::Critical => &mut self.critical,
                ServiceClass::Semantic => &mut self.semantic,
                ServiceClass::Bulk => &mut self.bulk,
            };
            match receiver.try_recv() {
                Ok(envelope) => {
                    self.ledger.lane(class).record_consumed();
                    return Some(envelope);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
            }
        }
        None
    }
}

/// Creates three independent bounded MPSC lanes and their shared accounting view.
pub fn pipeline_channel(capacities: InboxCapacities) -> (PipelineSender, PipelineReceiver) {
    // Tokio requires a positive physical capacity. A configured zero-capacity lane is kept closed
    // by `PipelineSender::try_send` and the one physical slot remains unreachable.
    let (critical_sender, critical_receiver) = mpsc::channel(capacities.critical.max(1));
    let (semantic_sender, semantic_receiver) = mpsc::channel(capacities.semantic.max(1));
    let (bulk_sender, bulk_receiver) = mpsc::channel(capacities.bulk.max(1));
    let ledger = PipelineChannelLedger {
        critical: Arc::new(ChannelLaneLedger::new(capacities.critical)),
        semantic: Arc::new(ChannelLaneLedger::new(capacities.semantic)),
        bulk: Arc::new(ChannelLaneLedger::new(capacities.bulk)),
    };
    (
        PipelineSender {
            critical: critical_sender,
            semantic: semantic_sender,
            bulk: bulk_sender,
            ledger: ledger.clone(),
        },
        PipelineReceiver {
            critical: critical_receiver,
            semantic: semantic_receiver,
            bulk: bulk_receiver,
            ledger,
            schedule_position: 0,
        },
    )
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EventOrderKey {
    captured_at_boot_ns: u64,
    origin_group: u8,
    origin_rank: u8,
    local_sequence: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ReorderPushError {
    Full(RawEnvelope),
    Duplicate(RawEnvelope),
}

#[derive(Debug, Default)]
struct ProcessBuffer {
    max_seen_boot_ns: u64,
    events: BTreeMap<EventOrderKey, RawEnvelope>,
}

/// Bounded event-time reorder buffer with an independent watermark for each `ProcessKey`.
///
/// An event from one process can never advance another process's watermark. That property is what
/// makes cross-ring ordering safe without depending on ring polling order.
#[derive(Debug)]
pub struct ReorderCoordinator {
    capacity: usize,
    reorder_window_ns: u64,
    depth: usize,
    processes: BTreeMap<ProcessKey, ProcessBuffer>,
    wall_clock_order: BinaryHeap<Reverse<(u64, ProcessKey, EventOrderKey)>>,
}

impl ReorderCoordinator {
    pub fn new(capacity: usize, reorder_window_ns: u64) -> Self {
        Self {
            capacity,
            reorder_window_ns,
            depth: 0,
            processes: BTreeMap::new(),
            wall_clock_order: BinaryHeap::new(),
        }
    }

    /// Adds one event and returns any same-process events made ready by its event-time watermark.
    /// Full and duplicate inputs are returned intact; this API never waits and never evicts facts.
    pub fn try_push(
        &mut self,
        envelope: RawEnvelope,
    ) -> Result<Vec<RawEnvelope>, ReorderPushError> {
        let process_key = envelope.process_key();
        let order_key = envelope.order_key();
        if self
            .processes
            .get(&process_key)
            .is_some_and(|process| process.events.contains_key(&order_key))
        {
            return Err(ReorderPushError::Duplicate(envelope));
        }

        // A future event may advance this process's watermark and make room. Check that before
        // rejecting a full coordinator so a bounded buffer cannot become permanently wedged.
        let mut ready = Vec::new();
        if self.depth >= self.capacity {
            if let Some(process) = self.processes.get_mut(&process_key) {
                let prospective_max = process.max_seen_boot_ns.max(envelope.captured_at_boot_ns);
                let prospective_watermark = prospective_max.saturating_sub(self.reorder_window_ns);
                let has_releasable = process
                    .events
                    .first_key_value()
                    .is_some_and(|(key, _)| key.captured_at_boot_ns <= prospective_watermark);
                if has_releasable {
                    ready = Self::release_through(process, prospective_watermark);
                    self.depth -= ready.len();
                }
            }
            if self.depth >= self.capacity {
                return Err(ReorderPushError::Full(envelope));
            }
        }

        let process = self.processes.entry(process_key).or_default();
        process.max_seen_boot_ns = process.max_seen_boot_ns.max(envelope.captured_at_boot_ns);
        process.events.insert(order_key, envelope);
        self.wall_clock_order.push(Reverse((
            order_key.captured_at_boot_ns,
            process_key,
            order_key,
        )));
        self.depth += 1;

        let watermark = process
            .max_seen_boot_ns
            .saturating_sub(self.reorder_window_ns);
        let newly_ready = Self::release_through(process, watermark);
        self.depth -= newly_ready.len();
        ready.extend(newly_ready);
        if process.events.is_empty() {
            self.processes.remove(&process_key);
        }
        Ok(ready)
    }

    /// Flushes all buffered events in deterministic process-key and event-time order.
    pub fn flush_all(&mut self) -> Vec<RawEnvelope> {
        let mut ready = Vec::with_capacity(self.depth);
        for process in self.processes.values_mut() {
            ready.extend(std::mem::take(&mut process.events).into_values());
        }
        self.processes.clear();
        self.wall_clock_order.clear();
        self.depth = 0;
        ready
    }

    /// Releases every buffered event whose kernel monotonic timestamp is at or before the given
    /// wall-clock watermark. Ring readers and userspace use the same boot-time monotonic domain,
    /// so a quiet process cannot leave its final event buffered forever waiting for a later event.
    pub fn release_through_boot_ns(&mut self, watermark: u64) -> Vec<RawEnvelope> {
        let mut ready = Vec::new();
        while self
            .wall_clock_order
            .peek()
            .is_some_and(|Reverse((captured_at_boot_ns, _, _))| *captured_at_boot_ns <= watermark)
        {
            let Reverse((_, process_key, order_key)) = self
                .wall_clock_order
                .pop()
                .expect("wall-clock heap was checked as non-empty");
            let mut remove_process = false;
            if let Some(process) = self.processes.get_mut(&process_key) {
                if let Some(envelope) = process.events.remove(&order_key) {
                    self.depth = self.depth.saturating_sub(1);
                    ready.push(envelope);
                }
                remove_process = process.events.is_empty();
            }
            if remove_process {
                self.processes.remove(&process_key);
            }
        }
        ready
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    fn release_through(process: &mut ProcessBuffer, watermark: u64) -> Vec<RawEnvelope> {
        if watermark == u64::MAX {
            return std::mem::take(&mut process.events).into_values().collect();
        }
        let keep_from = EventOrderKey {
            captured_at_boot_ns: watermark + 1,
            origin_group: 0,
            origin_rank: 0,
            local_sequence: 0,
        };
        let future = process.events.split_off(&keep_from);
        let ready = std::mem::replace(&mut process.events, future)
            .into_values()
            .collect();
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring(origin: RingOrigin, timestamp: u64, pid: u32, sequence: u64) -> RawEnvelope {
        RawEnvelope::new(
            PipelineOrigin::Ring(origin),
            timestamp,
            u128::from(timestamp) + 1_700_000_000_000_000_000,
            u128::from(timestamp) + 1_700_000_000_000_000_100,
            CaptureDecisionContext {
                capture_epoch: 77,
                capture_profile: 6,
                capture_action: 3,
                capture_authority: 2,
                capture_disposition: 1,
                flags: a3s_observer_common::CAPTURE_DECISION_FLAG_SELECTED,
                _reserved: [0; 3],
            },
            7,
            pid,
            sequence,
            vec![origin.tie_break_rank(); 32],
        )
    }

    fn bulk(sequence: u64) -> RawEnvelope {
        RawEnvelope::new(
            PipelineOrigin::Bulk(BulkOrigin::ServiceSummary),
            sequence,
            u128::from(sequence) + 1_700_000_000_000_000_000,
            u128::from(sequence) + 1_700_000_000_000_000_100,
            CaptureDecisionContext::default(),
            7,
            1,
            sequence,
            vec![0; 32],
        )
    }

    #[test]
    fn all_eleven_ring_origins_have_explicit_service_class_mapping() {
        let critical = RingOrigin::ALL
            .into_iter()
            .filter(|origin| origin.service_class() == ServiceClass::Critical)
            .collect::<Vec<_>>();
        let semantic = RingOrigin::ALL
            .into_iter()
            .filter(|origin| origin.service_class() == ServiceClass::Semantic)
            .collect::<Vec<_>>();

        assert_eq!(
            critical,
            vec![
                RingOrigin::Exec,
                RingOrigin::Exit,
                RingOrigin::FileDelete,
                RingOrigin::Security
            ]
        );
        assert_eq!(semantic.len(), 6);
        assert_eq!(RingOrigin::FileRead.service_class(), ServiceClass::Bulk);
        assert_eq!(
            PipelineOrigin::Bulk(BulkOrigin::UnknownSample).service_class(),
            ServiceClass::Bulk
        );
    }

    #[test]
    fn saturated_bulk_never_consumes_critical_capacity() {
        let mut inbox = PipelineInbox::new(InboxCapacities::new(2, 1, 1));
        inbox.try_push(bulk(1)).unwrap();
        let rejected = inbox.try_push(bulk(2)).unwrap_err();
        assert_eq!(rejected.class, ServiceClass::Bulk);

        inbox.try_push(ring(RingOrigin::Security, 3, 1, 1)).unwrap();
        inbox.try_push(ring(RingOrigin::Exec, 4, 1, 2)).unwrap();

        assert_eq!(inbox.ledger(ServiceClass::Bulk).depth, 1);
        assert_eq!(inbox.ledger(ServiceClass::Bulk).dropped, 1);
        assert_eq!(inbox.ledger(ServiceClass::Critical).depth, 2);
        assert_eq!(inbox.ledger(ServiceClass::Critical).dropped, 0);
    }

    #[test]
    fn full_try_push_is_non_blocking_and_ledger_conserves_every_offer() {
        let mut inbox = PipelineInbox::new(InboxCapacities::new(3, 0, 0));
        for sequence in 0..10 {
            let _ = inbox.try_push(ring(RingOrigin::Exec, sequence, 1, sequence));
        }

        let ledger = inbox.ledger(ServiceClass::Critical);
        assert_eq!(ledger.depth, 3);
        assert_eq!(ledger.high_water, 3);
        assert_eq!(ledger.admitted, 3);
        assert_eq!(ledger.dropped, 7);
        assert_eq!(ledger.offered(), 10);

        assert_eq!(inbox.drain_weighted(2).len(), 2);
        assert_eq!(inbox.ledger(ServiceClass::Critical).depth, 1);
        assert_eq!(inbox.ledger(ServiceClass::Critical).admitted, 3);
    }

    #[test]
    fn weighted_drain_is_exact_and_no_class_starves() {
        let mut inbox = PipelineInbox::new(InboxCapacities::new(300, 200, 100));
        for sequence in 0..300 {
            inbox
                .try_push(ring(RingOrigin::Security, sequence, 1, sequence))
                .unwrap();
        }
        for sequence in 0..200 {
            inbox
                .try_push(ring(RingOrigin::Connect, sequence, 1, sequence))
                .unwrap();
        }
        for sequence in 0..100 {
            inbox.try_push(bulk(sequence)).unwrap();
        }

        let drained = inbox.drain_weighted(PipelineInbox::WEIGHTED_BATCH);
        let count = |class| {
            drained
                .iter()
                .filter(|event| event.origin.service_class() == class)
                .count()
        };
        assert_eq!(count(ServiceClass::Critical), 256);
        assert_eq!(count(ServiceClass::Semantic), 128);
        assert_eq!(count(ServiceClass::Bulk), 32);

        // The shortest class interval in the reduced schedule is bounded, even with limit=1 calls.
        let first_thirteen = drained
            .iter()
            .take(13)
            .map(|event| event.origin.service_class())
            .collect::<Vec<_>>();
        assert!(first_thirteen.contains(&ServiceClass::Critical));
        assert!(first_thirteen.contains(&ServiceClass::Semantic));
        assert!(first_thirteen.contains(&ServiceClass::Bulk));
    }

    #[test]
    fn empty_classes_lend_their_entire_quota() {
        let mut inbox = PipelineInbox::new(InboxCapacities::new(0, 500, 0));
        for sequence in 0..500 {
            inbox
                .try_push(ring(RingOrigin::Tls, sequence, 1, sequence))
                .unwrap();
        }

        assert_eq!(
            inbox.drain_weighted(PipelineInbox::WEIGHTED_BATCH).len(),
            PipelineInbox::WEIGHTED_BATCH
        );
        assert_eq!(inbox.ledger(ServiceClass::Semantic).depth, 84);
    }

    #[test]
    fn more_than_twenty_thousand_events_remain_memory_bounded() {
        let capacities = InboxCapacities::new(512, 1_024, 128);
        let mut inbox = PipelineInbox::new(capacities);
        let mut offered = [0_u64; 3];

        for sequence in 0..50_000_u64 {
            let envelope = match sequence % 3 {
                0 => {
                    offered[0] += 1;
                    ring(
                        RingOrigin::Exec,
                        sequence,
                        (sequence % 128) as u32,
                        sequence,
                    )
                }
                1 => {
                    offered[1] += 1;
                    ring(
                        RingOrigin::Connect,
                        sequence,
                        (sequence % 128) as u32,
                        sequence,
                    )
                }
                _ => {
                    offered[2] += 1;
                    bulk(sequence)
                }
            };
            let _ = inbox.try_push(envelope);
            if sequence % 64 == 0 {
                let _ = inbox.drain_weighted(32);
            }
            assert!(inbox.ledger(ServiceClass::Critical).depth <= capacities.critical);
            assert!(inbox.ledger(ServiceClass::Semantic).depth <= capacities.semantic);
            assert!(inbox.ledger(ServiceClass::Bulk).depth <= capacities.bulk);
        }

        for (index, class) in [
            ServiceClass::Critical,
            ServiceClass::Semantic,
            ServiceClass::Bulk,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(inbox.ledger(class).offered(), offered[index]);
        }
        assert!(inbox.depth() <= capacities.critical + capacities.semantic + capacities.bulk);
    }

    #[test]
    fn sixty_seconds_at_twenty_thousand_records_per_second_stays_bounded_and_lossless() {
        const TOTAL: u64 = 20_000 * 60;
        let capacities = InboxCapacities::new(4_096, 8_192, 256);
        let (sender, mut receiver) = pipeline_channel(capacities);
        let mut consumed = 0_u64;

        for sequence in 0..TOTAL {
            let envelope = if sequence % 10 == 0 {
                ring(
                    RingOrigin::Exec,
                    sequence + 1,
                    (sequence % 512) as u32,
                    sequence,
                )
            } else {
                ring(
                    RingOrigin::FileAccess,
                    sequence + 1,
                    (sequence % 512) as u32,
                    sequence,
                )
            };
            sender
                .try_send(envelope)
                .expect("consumer cadence must preserve configured headroom");
            if sequence % 64 == 63 {
                consumed = consumed.saturating_add(receiver.try_drain_weighted(64).len() as u64);
            }
        }
        loop {
            let batch = receiver.try_drain_weighted(PipelineInbox::WEIGHTED_BATCH);
            if batch.is_empty() {
                break;
            }
            consumed = consumed.saturating_add(batch.len() as u64);
        }

        assert_eq!(consumed, TOTAL);
        for (class, capacity) in [
            (ServiceClass::Critical, capacities.critical),
            (ServiceClass::Semantic, capacities.semantic),
            (ServiceClass::Bulk, capacities.bulk),
        ] {
            let ledger = receiver.ledger().snapshot(class);
            assert_eq!(ledger.dropped, 0);
            assert_eq!(ledger.depth, 0);
            assert!(ledger.high_water <= capacity);
        }
    }

    #[test]
    fn channel_bulk_saturation_cannot_consume_critical_capacity() {
        let (sender, mut receiver) = pipeline_channel(InboxCapacities::new(2, 1, 1));
        sender.try_send(bulk(1)).unwrap();
        let rejected = sender.try_send(bulk(2)).unwrap_err();
        assert_eq!(rejected.class, ServiceClass::Bulk);
        assert_eq!(rejected.kind, PipelineSendErrorKind::Full);

        sender
            .try_send(ring(RingOrigin::Security, 3, 1, 1))
            .unwrap();
        sender.try_send(ring(RingOrigin::Exec, 4, 1, 2)).unwrap();

        assert_eq!(sender.ledger().snapshot(ServiceClass::Bulk).depth, 1);
        assert_eq!(sender.ledger().snapshot(ServiceClass::Bulk).dropped, 1);
        assert_eq!(sender.ledger().snapshot(ServiceClass::Critical).depth, 2);
        assert_eq!(sender.ledger().snapshot(ServiceClass::Critical).dropped, 0);
        assert_eq!(receiver.try_drain_weighted(3).len(), 3);
        assert_eq!(receiver.ledger().snapshot(ServiceClass::Critical).depth, 0);
        assert_eq!(receiver.ledger().snapshot(ServiceClass::Bulk).depth, 0);
    }

    #[test]
    fn channel_receiver_preserves_exact_weighted_fairness() {
        let (sender, mut receiver) = pipeline_channel(InboxCapacities::new(300, 200, 100));
        for sequence in 0..300 {
            sender
                .try_send(ring(RingOrigin::Security, sequence, 1, sequence))
                .unwrap();
        }
        for sequence in 0..200 {
            sender
                .try_send(ring(RingOrigin::Connect, sequence, 1, sequence))
                .unwrap();
        }
        for sequence in 0..100 {
            sender.try_send(bulk(sequence)).unwrap();
        }

        let drained = receiver.try_drain_weighted(PipelineInbox::WEIGHTED_BATCH);
        let count = |class| {
            drained
                .iter()
                .filter(|event| event.origin.service_class() == class)
                .count()
        };
        assert_eq!(count(ServiceClass::Critical), 256);
        assert_eq!(count(ServiceClass::Semantic), 128);
        assert_eq!(count(ServiceClass::Bulk), 32);
    }

    #[test]
    fn concurrent_producers_and_consumer_do_not_create_contention_drops() {
        use std::sync::atomic::{AtomicBool, Ordering};

        const PRODUCERS: usize = 8;
        const PER_PRODUCER: usize = 2_500;
        const TOTAL: usize = PRODUCERS * PER_PRODUCER;

        let (sender, mut receiver) = pipeline_channel(InboxCapacities::new(TOTAL, 1, 1));
        let done = Arc::new(AtomicBool::new(false));

        let consumed = std::thread::scope(|scope| {
            let consumer_done = done.clone();
            let consumer = scope.spawn(move || {
                let mut count = 0;
                loop {
                    count += receiver.try_drain_weighted(256).len();
                    if consumer_done.load(Ordering::Acquire)
                        && receiver.ledger().snapshot(ServiceClass::Critical).depth == 0
                    {
                        return count;
                    }
                    std::thread::yield_now();
                }
            });

            let mut producers = Vec::new();
            for producer in 0..PRODUCERS {
                let sender = sender.clone();
                producers.push(scope.spawn(move || {
                    for offset in 0..PER_PRODUCER {
                        let sequence = (producer * PER_PRODUCER + offset) as u64;
                        sender
                            .try_send(ring(RingOrigin::Exec, sequence, producer as u32, sequence))
                            .unwrap();
                    }
                }));
            }
            for producer in producers {
                producer.join().unwrap();
            }
            done.store(true, Ordering::Release);
            consumer.join().unwrap()
        });

        let ledger = sender.ledger().snapshot(ServiceClass::Critical);
        assert_eq!(consumed, TOTAL);
        assert_eq!(ledger.admitted, TOTAL as u64);
        assert_eq!(ledger.dropped, 0);
        assert_eq!(ledger.depth, 0);
        assert_eq!(ledger.offered(), TOTAL as u64);
        assert!(ledger.high_water <= TOTAL);
    }

    #[test]
    fn channel_full_accounting_conserves_every_offer() {
        let (sender, mut receiver) = pipeline_channel(InboxCapacities::new(3, 0, 0));
        for sequence in 0..10 {
            let _ = sender.try_send(ring(RingOrigin::Exec, sequence, 1, sequence));
        }
        let before = sender.ledger().snapshot(ServiceClass::Critical);
        assert_eq!(before.depth, 3);
        assert_eq!(before.high_water, 3);
        assert_eq!(before.admitted, 3);
        assert_eq!(before.dropped, 7);
        assert_eq!(before.offered(), 10);

        assert_eq!(receiver.try_drain_weighted(2).len(), 2);
        assert_eq!(sender.ledger().snapshot(ServiceClass::Critical).depth, 1);
    }

    #[test]
    fn coordinator_orders_inverse_connect_tls_and_exec_exit_by_event_time() {
        let mut coordinator = ReorderCoordinator::new(16, 50);

        assert!(coordinator
            .try_push(ring(RingOrigin::Tls, 200, 10, 1))
            .unwrap()
            .is_empty());
        let ready = coordinator
            .try_push(ring(RingOrigin::Connect, 100, 10, 1))
            .unwrap();
        assert_eq!(ready[0].origin, PipelineOrigin::Ring(RingOrigin::Connect));

        assert!(coordinator
            .try_push(ring(RingOrigin::Exit, 400, 20, 1))
            .unwrap()
            .is_empty());
        let ready = coordinator
            .try_push(ring(RingOrigin::Exec, 300, 20, 1))
            .unwrap();
        assert_eq!(ready[0].origin, PipelineOrigin::Ring(RingOrigin::Exec));

        let flushed = coordinator.flush_all();
        assert_eq!(
            flushed.iter().map(|event| event.origin).collect::<Vec<_>>(),
            vec![
                PipelineOrigin::Ring(RingOrigin::Tls),
                PipelineOrigin::Ring(RingOrigin::Exit)
            ]
        );
    }

    #[test]
    fn same_timestamp_ties_put_correlation_and_exec_before_consumers_and_exit() {
        let mut coordinator = ReorderCoordinator::new(8, 10);
        coordinator
            .try_push(ring(RingOrigin::Exit, 100, 1, 1))
            .unwrap();
        coordinator
            .try_push(ring(RingOrigin::Tls, 100, 1, 1))
            .unwrap();
        coordinator
            .try_push(ring(RingOrigin::Connect, 100, 1, 1))
            .unwrap();
        coordinator
            .try_push(ring(RingOrigin::Exec, 100, 1, 1))
            .unwrap();

        assert_eq!(
            coordinator
                .flush_all()
                .into_iter()
                .map(|event| event.origin)
                .collect::<Vec<_>>(),
            vec![
                PipelineOrigin::Ring(RingOrigin::Exec),
                PipelineOrigin::Ring(RingOrigin::Connect),
                PipelineOrigin::Ring(RingOrigin::Tls),
                PipelineOrigin::Ring(RingOrigin::Exit),
            ]
        );
    }

    #[test]
    fn process_watermarks_are_isolated() {
        let mut coordinator = ReorderCoordinator::new(8, 100);
        coordinator
            .try_push(ring(RingOrigin::Connect, 100, 1, 1))
            .unwrap();
        let ready = coordinator
            .try_push(ring(RingOrigin::Tls, 10_000, 2, 1))
            .unwrap();

        assert!(ready.is_empty());
        assert_eq!(coordinator.depth(), 2);
        assert_eq!(coordinator.process_count(), 2);
    }

    #[test]
    fn wall_clock_watermark_releases_the_last_event_of_a_quiet_process() {
        let mut coordinator = ReorderCoordinator::new(8, 100);
        coordinator
            .try_push(ring(RingOrigin::Connect, 1_000, 1, 1))
            .unwrap();

        assert!(coordinator.release_through_boot_ns(999).is_empty());
        let ready = coordinator.release_through_boot_ns(1_000);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].origin, PipelineOrigin::Ring(RingOrigin::Connect));
        assert_eq!(coordinator.depth(), 0);
        assert_eq!(coordinator.process_count(), 0);
    }

    #[test]
    fn reorder_preserves_calibrated_event_and_receipt_times() {
        let mut coordinator = ReorderCoordinator::new(8, 0);
        let expected = ring(RingOrigin::FileAccess, 1_000, 1, 7);
        let ready = coordinator.try_push(expected.clone()).unwrap();

        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].event_at_unix_ns, expected.event_at_unix_ns);
        assert_eq!(ready[0].received_at_unix_ns, expected.received_at_unix_ns);
        assert!(ready[0].received_at_unix_ns >= ready[0].event_at_unix_ns);
        assert_eq!(ready[0].capture_decision, expected.capture_decision);
    }

    #[test]
    fn coordinator_is_bounded_and_returns_rejected_fact_intact() {
        let mut coordinator = ReorderCoordinator::new(1, 100);
        coordinator
            .try_push(ring(RingOrigin::Connect, 100, 1, 1))
            .unwrap();
        let rejected = ring(RingOrigin::Tls, 101, 1, 2);

        assert_eq!(
            coordinator.try_push(rejected.clone()),
            Err(ReorderPushError::Full(rejected))
        );
        assert_eq!(coordinator.depth(), 1);
    }

    #[test]
    fn full_coordinator_uses_incoming_watermark_to_make_progress() {
        let mut coordinator = ReorderCoordinator::new(2, 50);
        coordinator
            .try_push(ring(RingOrigin::Connect, 100, 1, 1))
            .unwrap();
        coordinator
            .try_push(ring(RingOrigin::Tls, 110, 1, 1))
            .unwrap();

        let ready = coordinator
            .try_push(ring(RingOrigin::Dns, 1_000, 1, 1))
            .unwrap();
        assert_eq!(ready.len(), 2);
        assert_eq!(coordinator.depth(), 1);
    }
}
