//! Conversion between the kernel's monotonic event clock and Unix wall time.
//!
//! `bpf_ktime_get_ns()` is in the same domain as `CLOCK_MONOTONIC`; it is never a Unix
//! timestamp. A calibration samples realtime between two monotonic reads and uses their midpoint
//! as the anchor. Ring readers refresh the anchor once per drain and use a separate monotonic read
//! for each admitted record's Collector receipt time.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CalibratedEventTimes {
    pub event_at_unix_ns: u128,
    pub received_at_unix_ns: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClockCalibration {
    boot_ns: u64,
    unix_ns: u128,
}

impl ClockCalibration {
    pub(crate) fn sample() -> io::Result<Self> {
        let before = monotonic_now_ns()?;
        let unix_ns = system_now_unix_ns()?;
        let after = monotonic_now_ns()?;
        let boot_ns = before.saturating_add(after.saturating_sub(before) / 2);
        Ok(Self { boot_ns, unix_ns })
    }

    #[cfg(test)]
    pub(crate) const fn from_anchor(boot_ns: u64, unix_ns: u128) -> Self {
        Self { boot_ns, unix_ns }
    }

    pub(crate) fn unix_ns_for_boot(self, boot_ns: u64) -> u128 {
        if boot_ns >= self.boot_ns {
            self.unix_ns
                .saturating_add(u128::from(boot_ns - self.boot_ns))
        } else {
            self.unix_ns
                .saturating_sub(u128::from(self.boot_ns - boot_ns))
        }
    }

    pub(crate) fn event_times(
        self,
        captured_at_boot_ns: u64,
        received_at_boot_ns: u64,
    ) -> CalibratedEventTimes {
        let received_at_boot_ns = received_at_boot_ns.max(captured_at_boot_ns);
        let received_at_unix_ns = self.unix_ns_for_boot(received_at_boot_ns);
        CalibratedEventTimes {
            // A zero timestamp can only come from a legacy/malformed record. Preserve the event
            // instead of inventing the machine boot instant as its occurrence time.
            event_at_unix_ns: if captured_at_boot_ns == 0 {
                received_at_unix_ns
            } else {
                self.unix_ns_for_boot(captured_at_boot_ns)
            },
            received_at_unix_ns,
        }
    }
}

pub(crate) struct EventClock {
    calibration: ClockCalibration,
}

impl EventClock {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            calibration: ClockCalibration::sample()?,
        })
    }

    #[cfg(test)]
    pub(crate) const fn from_calibration(calibration: ClockCalibration) -> Self {
        Self { calibration }
    }

    /// A refresh failure keeps the previous valid mapping. Losing one calibration sample must not
    /// turn a healthy ring into data loss, and the next drain retries automatically.
    pub(crate) fn refresh(&mut self) {
        if let Ok(calibration) = ClockCalibration::sample() {
            self.calibration = calibration;
        }
    }

    pub(crate) fn event_times(&self, captured_at_boot_ns: u64) -> io::Result<CalibratedEventTimes> {
        let received_at_boot_ns = monotonic_now_ns()?.max(captured_at_boot_ns);
        Ok(self
            .calibration
            .event_times(captured_at_boot_ns, received_at_boot_ns))
    }
}

pub(crate) fn monotonic_now_ns() -> io::Result<u64> {
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut timestamp) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((timestamp.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(timestamp.tv_nsec as u64))
}

pub(crate) fn system_now_unix_ns() -> io::Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .as_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_values_are_translated_through_a_unix_anchor() {
        let calibration = ClockCalibration::from_anchor(10_000, 1_700_000_000_000_000_000);
        let times = calibration.event_times(9_500, 10_250);

        assert_eq!(times.event_at_unix_ns, 1_699_999_999_999_999_500);
        assert_eq!(times.received_at_unix_ns, 1_700_000_000_000_000_250);
        assert_ne!(times.event_at_unix_ns, u128::from(9_500_u64));
    }

    #[test]
    fn receipt_never_precedes_the_kernel_capture() {
        let calibration = ClockCalibration::from_anchor(100, 10_000);
        let times = calibration.event_times(150, 120);
        assert_eq!(times.event_at_unix_ns, 10_050);
        assert_eq!(times.received_at_unix_ns, 10_050);
    }

    #[test]
    fn a_legacy_zero_capture_uses_receipt_time_not_machine_boot_time() {
        let calibration = ClockCalibration::from_anchor(1_000, 100_000);
        let times = calibration.event_times(0, 1_100);
        assert_eq!(times.event_at_unix_ns, 100_100);
        assert_eq!(times.received_at_unix_ns, 100_100);
    }
}
