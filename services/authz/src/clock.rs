//! Time for permit lifetimes. Production reads qualified Roughtime bounds.
use bh_confidential_host::TimeSampler;
use bh_qualified_time::Counter;
use std::{sync::Arc, time::Instant};

/// Trusted absolute time in milliseconds. An error means no permit is issued.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> Result<u64, ClockError>;
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
}

/// Test-only settable time.
#[cfg(feature = "synthetic-attestation")]
pub struct FixedClock(std::sync::atomic::AtomicU64);
#[cfg(feature = "synthetic-attestation")]
impl FixedClock {
    pub fn new(ms: u64) -> Self {
        Self(ms.into())
    }
    pub fn now(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn set(&self, ms: u64) {
        self.0.store(ms, std::sync::atomic::Ordering::SeqCst);
    }
    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, std::sync::atomic::Ordering::SeqCst);
    }
}
#[cfg(feature = "synthetic-attestation")]
impl Clock for FixedClock {
    fn now_ms(&self) -> Result<u64, ClockError> {
        Ok(self.now())
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
}
