//! Time for permit lifetimes and recovery tries. Production reads qualified
//! Roughtime bounds.
use bh_confidential_host::TimeSampler;
pub use bh_qualified_time::Bounds;
use bh_qualified_time::Counter;
use std::{sync::Arc, time::Instant};

/// Trusted absolute time in milliseconds. An error means no permit is issued.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> Result<u64, ClockError>;
    /// The interval the true time is in: no earlier than `earliest_ms`, no
    /// later than `latest_ms`.
    fn bounds_ms(&self) -> Result<Bounds, ClockError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockError;
impl std::fmt::Display for ClockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("trusted time unavailable")
    }
}
impl std::error::Error for ClockError {}

/// Nanosecond ticks of this process's monotonic clock.
pub struct MonotonicCounter(Instant);
impl MonotonicCounter {
    /// Ticks per second: the qualified-time configuration's rate must be this.
    pub const HZ: u64 = 1_000_000_000;
    pub fn new() -> Self {
        Self(Instant::now())
    }
}
impl Default for MonotonicCounter {
    fn default() -> Self {
        Self::new()
    }
}
impl Counter for MonotonicCounter {
    fn ticks(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

/// The earliest bound of qualified Roughtime time: a permit's life never
/// starts after its supporting check. The caller refreshes the sampler.
pub struct RoughtimeClock {
    sampler: Arc<TimeSampler>,
    counter: Arc<MonotonicCounter>,
}
impl RoughtimeClock {
    pub fn new(sampler: Arc<TimeSampler>, counter: Arc<MonotonicCounter>) -> Self {
        Self { sampler, counter }
    }
}
impl Clock for RoughtimeClock {
    fn now_ms(&self) -> Result<u64, ClockError> {
        self.sampler
            .now(self.counter.as_ref())
            .map(|bounds| bounds.earliest_ms)
            .map_err(|_| ClockError)
    }
    fn bounds_ms(&self) -> Result<Bounds, ClockError> {
        self.sampler
            .now(self.counter.as_ref())
            .map_err(|_| ClockError)
    }
}

/// Test-only settable time: `now` is the earliest bound, and the latest is
/// `uncertainty` milliseconds later.
#[cfg(feature = "synthetic-attestation")]
pub struct FixedClock {
    now: std::sync::atomic::AtomicU64,
    uncertainty: std::sync::atomic::AtomicU64,
}
#[cfg(feature = "synthetic-attestation")]
impl FixedClock {
    pub fn new(ms: u64) -> Self {
        Self {
            now: ms.into(),
            uncertainty: 0.into(),
        }
    }
    pub fn now(&self) -> u64 {
        self.now.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn set(&self, ms: u64) {
        self.now.store(ms, std::sync::atomic::Ordering::SeqCst);
    }
    pub fn advance(&self, ms: u64) {
        self.now.fetch_add(ms, std::sync::atomic::Ordering::SeqCst);
    }
    pub fn set_uncertainty(&self, ms: u64) {
        self.uncertainty
            .store(ms, std::sync::atomic::Ordering::SeqCst);
    }
}
#[cfg(feature = "synthetic-attestation")]
impl Clock for FixedClock {
    fn now_ms(&self) -> Result<u64, ClockError> {
        Ok(self.now())
    }
    fn bounds_ms(&self) -> Result<Bounds, ClockError> {
        let earliest_ms = self.now();
        let uncertainty = self.uncertainty.load(std::sync::atomic::Ordering::SeqCst);
        Ok(Bounds {
            earliest_ms,
            latest_ms: earliest_ms.checked_add(uncertainty).ok_or(ClockError)?,
        })
    }
}

/// Local-only: this machine's wall clock, for the synthetic local stack.
#[cfg(feature = "synthetic-attestation")]
pub struct LocalClock;
#[cfg(feature = "synthetic-attestation")]
impl Clock for LocalClock {
    fn now_ms(&self) -> Result<u64, ClockError> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .map_err(|_| ClockError)
    }
    fn bounds_ms(&self) -> Result<Bounds, ClockError> {
        let now = self.now_ms()?;
        Ok(Bounds {
            earliest_ms: now,
            latest_ms: now,
        })
    }
}

#[cfg(all(test, feature = "synthetic-attestation"))]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_reports_its_uncertainty_as_bounds() {
        let clock = FixedClock::new(1_000);
        let exact = Bounds {
            earliest_ms: 1_000,
            latest_ms: 1_000,
        };
        assert_eq!(clock.bounds_ms(), Ok(exact));
        clock.set_uncertainty(25);
        clock.advance(5);
        assert_eq!(
            clock.bounds_ms(),
            Ok(Bounds {
                earliest_ms: 1_005,
                latest_ms: 1_030,
            })
        );
        assert_eq!(clock.now_ms(), Ok(1_005));
        clock.set(u64::MAX);
        assert_eq!(clock.bounds_ms(), Err(ClockError));
    }
}
