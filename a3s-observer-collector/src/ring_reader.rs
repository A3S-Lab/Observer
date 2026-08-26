//! Event-driven, per-ring reader used by the Collector's minimal capture hot path.
//!
//! A reader copies one fixed-size POD record, extracts only ordering identity, attempts a
//! non-waiting inbox admission, and immediately continues draining its ring. It deliberately does
//! no `/proc` access, path parsing, classification, enrichment, serialization, or export.

use crate::event_time::EventClock;
use crate::pipeline::{OwnedPayload, PipelineOrigin, PipelineSender, RawEnvelope, RingOrigin};
use a3s_observer_common::{
    CaptureDecisionContext, ConnectEvent, DnsEvent, ExecRecord, ExitEvent, FileEvent, LlmEvent,
    SecEvent, SslEvent, TlsEvent, CAPTURE_ACTION_FULL, CAPTURE_DECISION_FLAG_LEGACY,
    CAPTURE_DECISION_FLAG_SELECTED, CAPTURE_DISPOSITION_MISS, CAPTURE_PROFILE_UNKNOWN_DISCOVERY,
};
use aya::maps::{MapData, RingBuf};
use std::io;
use std::mem::{offset_of, size_of};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::sync::{watch, Notify};

const RING_DRAIN_BUDGET: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DrainState {
    Empty,
    BudgetExhausted,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RingReaderLedgerSnapshot {
    pub received: u64,
    pub enqueued: u64,
    pub dropped: u64,
}

impl RingReaderLedgerSnapshot {
    pub fn delta_since(self, previous: Self) -> Self {
        Self {
            received: self.received.saturating_sub(previous.received),
            enqueued: self.enqueued.saturating_sub(previous.enqueued),
            dropped: self.dropped.saturating_sub(previous.dropped),
        }
    }
}

/// Thread-safe cumulative counters for one physical ring reader.
///
/// Each physical item performs exactly one final outcome write. `received` is structurally derived
/// as `enqueued + dropped`, so every concurrent snapshot and every delta between snapshots obeys
/// conservation without a mutex, seqlock retry, or three independently swapped window counters.
#[derive(Debug, Default)]
pub struct RingReaderLedger {
    enqueued: AtomicU64,
    dropped: AtomicU64,
}

impl RingReaderLedger {
    pub fn snapshot(&self) -> RingReaderLedgerSnapshot {
        let enqueued = self.enqueued.load(Ordering::Relaxed);
        let dropped = self.dropped.load(Ordering::Relaxed);
        RingReaderLedgerSnapshot {
            received: enqueued.saturating_add(dropped),
            enqueued,
            dropped,
        }
    }

    fn record_outcome(&self, enqueued: bool) {
        if enqueued {
            self.enqueued.fetch_add(1, Ordering::Relaxed);
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PodLayout {
    len: usize,
    captured_at_boot_ns: usize,
    capture_decision: usize,
    cgroup_id: usize,
    pid: usize,
}

fn pod_layout(origin: RingOrigin) -> PodLayout {
    macro_rules! layout {
        ($event:ty) => {
            PodLayout {
                len: size_of::<$event>(),
                captured_at_boot_ns: offset_of!($event, captured_at_boot_ns),
                capture_decision: offset_of!($event, capture_decision),
                cgroup_id: offset_of!($event, cgroup_id),
                pid: offset_of!($event, pid),
            }
        };
    }

    match origin {
        RingOrigin::Exec => layout!(ExecRecord),
        RingOrigin::Exit => layout!(ExitEvent),
        RingOrigin::Tls => layout!(TlsEvent),
        RingOrigin::Connect => layout!(ConnectEvent),
        RingOrigin::Dns => layout!(DnsEvent),
        RingOrigin::FileAccess | RingOrigin::FileRead | RingOrigin::FileDelete => {
            layout!(FileEvent)
        }
        RingOrigin::Llm => layout!(LlmEvent),
        RingOrigin::Ssl => layout!(SslEvent),
        RingOrigin::Security => layout!(SecEvent),
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes
            .get(offset..offset.checked_add(size_of::<u32>())?)?
            .try_into()
            .ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(
        bytes
            .get(offset..offset.checked_add(size_of::<u64>())?)?
            .try_into()
            .ok()?,
    ))
}

fn read_capture_decision(bytes: &[u8], offset: usize) -> Option<CaptureDecisionContext> {
    Some(CaptureDecisionContext {
        capture_epoch: read_u64(bytes, offset)?,
        capture_profile: *bytes.get(offset + 8)?,
        capture_action: *bytes.get(offset + 9)?,
        capture_authority: *bytes.get(offset + 10)?,
        capture_disposition: *bytes.get(offset + 11)?,
        flags: *bytes.get(offset + 12)?,
        _reserved: bytes.get(offset + 13..offset + 16)?.try_into().ok()?,
    })
}

const fn legacy_capture_decision() -> CaptureDecisionContext {
    CaptureDecisionContext {
        capture_epoch: 0,
        capture_profile: CAPTURE_PROFILE_UNKNOWN_DISCOVERY,
        capture_action: CAPTURE_ACTION_FULL,
        capture_authority: 0,
        capture_disposition: CAPTURE_DISPOSITION_MISS,
        flags: CAPTURE_DECISION_FLAG_SELECTED | CAPTURE_DECISION_FLAG_LEGACY,
        _reserved: [0; 3],
    }
}

fn envelope_from_pod(
    origin: RingOrigin,
    item: &[u8],
    local_sequence: u64,
    clock: &EventClock,
) -> Option<RawEnvelope> {
    let layout = pod_layout(origin);
    // D1 is an additive tail. A new Collector can still consume the immediately preceding S4
    // record size and marks it as a selected legacy FULL decision; an old Collector naturally
    // copies only its known prefix from a new record.
    if item.len() < layout.capture_decision {
        return None;
    }
    let mut pod = vec![0_u8; layout.len];
    let copied = item.len().min(layout.len);
    pod[..copied].copy_from_slice(&item[..copied]);
    let captured_at_boot_ns = read_u64(&pod, layout.captured_at_boot_ns)?;
    let cgroup_id = read_u64(&pod, layout.cgroup_id)?;
    let pid = read_u32(&pod, layout.pid)?;
    let capture_decision = if copied >= layout.capture_decision + 16 {
        read_capture_decision(&pod, layout.capture_decision)?
    } else {
        legacy_capture_decision()
    };
    let times = clock.event_times(captured_at_boot_ns).ok()?;
    Some(RawEnvelope::new(
        PipelineOrigin::Ring(origin),
        captured_at_boot_ns,
        times.event_at_unix_ns,
        times.received_at_unix_ns,
        capture_decision,
        cgroup_id,
        pid,
        local_sequence,
        OwnedPayload::from(pod),
    ))
}

/// Copies and admits one physical record. Returning `true` means a consumer notification is due.
fn admit_item(
    origin: RingOrigin,
    item: &[u8],
    local_sequence: &mut u64,
    sender: &PipelineSender,
    ledger: &RingReaderLedger,
    clock: &EventClock,
) -> bool {
    let sequence = *local_sequence;
    *local_sequence = local_sequence.wrapping_add(1);

    let Some(envelope) = envelope_from_pod(origin, item, sequence, clock) else {
        ledger.record_outcome(false);
        return false;
    };

    if sender.try_send(envelope).is_err() {
        ledger.record_outcome(false);
        return false;
    }

    ledger.record_outcome(true);
    true
}

fn drain_ring(
    origin: RingOrigin,
    ring: &mut RingBuf<MapData>,
    sender: &PipelineSender,
    ready: &Notify,
    ledger: &RingReaderLedger,
    local_sequence: &mut u64,
    clock: &mut EventClock,
) -> (usize, DrainState) {
    clock.refresh();
    let mut admitted = 0;
    for _ in 0..RING_DRAIN_BUDGET {
        let Some(item) = ring.next() else {
            return (admitted, DrainState::Empty);
        };
        if admit_item(origin, &item, local_sequence, sender, ledger, clock) {
            admitted += 1;
            // Notify per admission. `Notify` coalesces an unconsumed permit, while a consumer that
            // already handled an earlier wake can still receive a later one during a long drain.
            ready.notify_one();
        }
    }
    (admitted, DrainState::BudgetExhausted)
}

async fn drain_ring_to_empty(
    origin: RingOrigin,
    ring: &mut RingBuf<MapData>,
    sender: &PipelineSender,
    ready: &Notify,
    ledger: &RingReaderLedger,
    local_sequence: &mut u64,
    clock: &mut EventClock,
) {
    loop {
        let (_, state) = drain_ring(origin, ring, sender, ready, ledger, local_sequence, clock);
        if state == DrainState::Empty {
            return;
        }
        // Even shutdown draining is cooperative: one perpetually busy ring cannot prevent the
        // other nine readers from completing their own final drain before the deadline.
        tokio::task::yield_now().await;
    }
}

/// Runs one event-driven reader until shutdown, then performs one final drain-to-empty.
///
/// Read readiness is cleared only after `RingBuf::next()` returns `None`. A full userspace inbox
/// never terminates the drain loop; every subsequent ring item is still consumed and accounted.
pub async fn run_ring_reader(
    origin: RingOrigin,
    ring: RingBuf<MapData>,
    sender: PipelineSender,
    ready: Arc<Notify>,
    mut shutdown: watch::Receiver<bool>,
    ledger: Arc<RingReaderLedger>,
) -> io::Result<()> {
    let mut ring = AsyncFd::new(ring)?;
    let mut local_sequence = 0_u64;
    let mut event_clock = EventClock::new()?;

    loop {
        if *shutdown.borrow() {
            drain_ring_to_empty(
                origin,
                ring.get_mut(),
                &sender,
                ready.as_ref(),
                ledger.as_ref(),
                &mut local_sequence,
                &mut event_clock,
            )
            .await;
            return Ok(());
        }

        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    drain_ring_to_empty(
                        origin,
                        ring.get_mut(),
                        &sender,
                        ready.as_ref(),
                        ledger.as_ref(),
                        &mut local_sequence,
                        &mut event_clock,
                    ).await;
                    return Ok(());
                }
            }
            readable = ring.readable_mut() => {
                let mut guard = readable?;
                let (_, state) = drain_ring(
                    origin,
                    guard.get_inner_mut(),
                    &sender,
                    ready.as_ref(),
                    ledger.as_ref(),
                    &mut local_sequence,
                    &mut event_clock,
                );
                if state == DrainState::Empty {
                    // Readiness is cleared only after `next()` actually observed an empty ring.
                    guard.clear_ready();
                } else {
                    // Keep readiness set, release the guard, and yield cooperatively so a hot
                    // Semantic ring cannot monopolize a runtime worker over Critical readers.
                    drop(guard);
                    tokio::task::yield_now().await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_time::ClockCalibration;
    use crate::pipeline::{pipeline_channel, InboxCapacities, ServiceClass};

    fn event_clock() -> EventClock {
        EventClock::from_calibration(ClockCalibration::from_anchor(
            100,
            1_700_000_000_000_000_000,
        ))
    }

    fn pod(origin: RingOrigin, captured_at: u64, cgroup_id: u64, pid: u32) -> Vec<u8> {
        let layout = pod_layout(origin);
        let mut bytes = vec![0_u8; layout.len];
        bytes[layout.captured_at_boot_ns..layout.captured_at_boot_ns + 8]
            .copy_from_slice(&captured_at.to_ne_bytes());
        bytes[layout.cgroup_id..layout.cgroup_id + 8].copy_from_slice(&cgroup_id.to_ne_bytes());
        bytes[layout.pid..layout.pid + 4].copy_from_slice(&pid.to_ne_bytes());
        bytes[layout.capture_decision..layout.capture_decision + 8]
            .copy_from_slice(&77_u64.to_ne_bytes());
        bytes[layout.capture_decision + 8] = 6;
        bytes[layout.capture_decision + 9] = 3;
        bytes[layout.capture_decision + 10] = 2;
        bytes[layout.capture_decision + 11] = 1;
        bytes[layout.capture_decision + 12] = CAPTURE_DECISION_FLAG_SELECTED;
        bytes
    }

    #[test]
    fn every_ring_layout_extracts_event_time_and_process_identity() {
        let clock = event_clock();
        for (index, origin) in RingOrigin::ALL.into_iter().enumerate() {
            let bytes = pod(
                origin,
                100 + index as u64,
                200 + index as u64,
                300 + index as u32,
            );
            let envelope = envelope_from_pod(origin, &bytes, 400 + index as u64, &clock).unwrap();

            assert_eq!(envelope.origin, PipelineOrigin::Ring(origin));
            assert_eq!(envelope.captured_at_boot_ns, 100 + index as u64);
            assert_eq!(
                envelope.event_at_unix_ns,
                1_700_000_000_000_000_000 + index as u128
            );
            assert!(envelope.received_at_unix_ns >= envelope.event_at_unix_ns);
            assert_eq!(envelope.capture_decision.capture_epoch, 77);
            assert_eq!(envelope.capture_decision.capture_profile, 6);
            assert_eq!(envelope.capture_decision.capture_action, 3);
            assert_eq!(envelope.capture_decision.capture_authority, 2);
            assert_eq!(envelope.capture_decision.capture_disposition, 1);
            assert!(envelope.capture_decision.selected());
            assert_eq!(envelope.cgroup_id, 200 + index as u64);
            assert_eq!(envelope.pid, 300 + index as u32);
            assert_eq!(envelope.local_sequence, 400 + index as u64);
            assert_eq!(envelope.payload.as_bytes(), bytes);
        }
    }

    #[test]
    fn oversized_item_copies_only_the_fixed_pod() {
        let clock = event_clock();
        let origin = RingOrigin::Connect;
        let mut bytes = pod(origin, 1, 2, 3);
        let pod_len = bytes.len();
        bytes.extend_from_slice(&[0xaa; 64]);

        let envelope = envelope_from_pod(origin, &bytes, 0, &clock).unwrap();
        assert_eq!(envelope.payload.len(), pod_len);
        assert!(!envelope.payload.as_bytes().ends_with(&[0xaa; 64]));
    }

    #[test]
    fn previous_event_time_only_tail_is_read_as_selected_legacy_full() {
        let clock = event_clock();
        let origin = RingOrigin::Exit;
        let layout = pod_layout(origin);
        let mut bytes = pod(origin, 101, 202, 303);
        bytes.truncate(layout.capture_decision);

        let envelope = envelope_from_pod(origin, &bytes, 0, &clock).unwrap();
        assert_eq!(envelope.payload.len(), layout.len);
        assert_eq!(envelope.capture_decision, legacy_capture_decision());
        assert!(envelope.capture_decision.selected());
    }

    #[test]
    fn malformed_and_full_items_drop_without_stopping_later_admission() {
        let (sender, mut receiver) = pipeline_channel(InboxCapacities::new(1, 1, 0));
        let ledger = RingReaderLedger::default();
        let mut sequence = 0;
        let clock = event_clock();

        assert!(!admit_item(
            RingOrigin::Exec,
            &[0; 8],
            &mut sequence,
            &sender,
            &ledger,
            &clock,
        ));
        assert!(admit_item(
            RingOrigin::Exec,
            &pod(RingOrigin::Exec, 2, 3, 4),
            &mut sequence,
            &sender,
            &ledger,
            &clock,
        ));
        assert!(!admit_item(
            RingOrigin::Exec,
            &pod(RingOrigin::Exec, 3, 3, 4),
            &mut sequence,
            &sender,
            &ledger,
            &clock,
        ));

        // Free Critical and prove the reader can continue admitting a later record.
        let drained = receiver.try_drain_weighted(1);
        assert_eq!(drained[0].local_sequence, 1);
        assert!(admit_item(
            RingOrigin::Exec,
            &pod(RingOrigin::Exec, 4, 3, 4),
            &mut sequence,
            &sender,
            &ledger,
            &clock,
        ));

        assert_eq!(sequence, 4);
        assert_eq!(
            ledger.snapshot(),
            RingReaderLedgerSnapshot {
                received: 4,
                enqueued: 2,
                dropped: 2,
            }
        );
    }

    #[test]
    fn cloned_sender_does_not_drop_when_lane_has_capacity() {
        let (sender, _receiver) = pipeline_channel(InboxCapacities::new(2, 1, 1));
        let ledger = RingReaderLedger::default();
        let mut sequence = 0;
        let clock = event_clock();

        assert!(admit_item(
            RingOrigin::Security,
            &pod(RingOrigin::Security, 1, 2, 3),
            &mut sequence,
            &sender,
            &ledger,
            &clock,
        ));
        assert!(admit_item(
            RingOrigin::Exec,
            &pod(RingOrigin::Exec, 2, 2, 3),
            &mut sequence,
            &sender.clone(),
            &ledger,
            &clock,
        ));
        assert_eq!(ledger.snapshot().dropped, 0);
        assert_eq!(ledger.snapshot().received, 2);
    }

    #[test]
    fn ring_class_capacity_is_preserved_at_admission() {
        let (sender, _receiver) = pipeline_channel(InboxCapacities::new(1, 1, 0));
        let ledger = RingReaderLedger::default();
        let mut sequence = 0;
        let clock = event_clock();

        assert!(admit_item(
            RingOrigin::Security,
            &pod(RingOrigin::Security, 1, 1, 1),
            &mut sequence,
            &sender,
            &ledger,
            &clock,
        ));
        assert!(admit_item(
            RingOrigin::Connect,
            &pod(RingOrigin::Connect, 2, 1, 1),
            &mut sequence,
            &sender,
            &ledger,
            &clock,
        ));

        assert_eq!(sender.ledger().snapshot(ServiceClass::Critical).depth, 1);
        assert_eq!(sender.ledger().snapshot(ServiceClass::Semantic).depth, 1);
    }

    #[test]
    fn cumulative_delta_is_structurally_conserved() {
        let ledger = RingReaderLedger::default();
        let baseline = ledger.snapshot();
        ledger.record_outcome(true);
        ledger.record_outcome(false);

        let expected = RingReaderLedgerSnapshot {
            received: 2,
            enqueued: 1,
            dropped: 1,
        };
        assert_eq!(ledger.snapshot().delta_since(baseline), expected);
        assert_eq!(ledger.snapshot(), expected);
        assert_eq!(expected.received, expected.enqueued + expected.dropped);
    }

    #[test]
    fn concurrent_snapshots_never_expose_a_residual() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let ledger = Arc::new(RingReaderLedger::default());
        let done = Arc::new(AtomicBool::new(false));
        std::thread::scope(|scope| {
            let writer_ledger = ledger.clone();
            let writer_done = done.clone();
            scope.spawn(move || {
                for index in 0..50_000 {
                    writer_ledger.record_outcome(index % 3 != 0);
                }
                writer_done.store(true, Ordering::Release);
            });

            while !done.load(Ordering::Acquire) {
                let snapshot = ledger.snapshot();
                assert_eq!(snapshot.received, snapshot.enqueued + snapshot.dropped);
            }
        });
        let final_snapshot = ledger.snapshot();
        assert_eq!(final_snapshot.received, 50_000);
        assert_eq!(
            final_snapshot.received,
            final_snapshot.enqueued + final_snapshot.dropped
        );
    }
}
