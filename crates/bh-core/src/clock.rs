//! Monotonic time for device-local approval deadlines.
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// Monotonic clock used for device-local deadlines, independent of wall time.
#[derive(Clone)]
pub struct Clock(Arc<Source>);

enum Source {
    System(Instant),
    Manual { millis: AtomicU64, changed: Notify },
}

/// Controllable clock handle; advancing it wakes deadline sleepers.
#[derive(Clone)]
pub struct ManualClock(Clock);

impl Clock {
    /// Starts a clock at the current monotonic instant.
    pub fn system() -> Self {
        Self(Arc::new(Source::System(Instant::now())))
    }

    /// Creates a clock and its manual advance handle, initially at zero.
    pub fn manual() -> (Self, ManualClock) {
        let clock = Self(Arc::new(Source::Manual {
            millis: AtomicU64::new(0),
            changed: Notify::new(),
        }));
        (clock.clone(), ManualClock(clock))
    }

    /// Milliseconds since this clock's start.
    pub fn now_ms(&self) -> u64 {
        match &*self.0 {
            Source::System(start) => start.elapsed().as_millis().min(u64::MAX as u128) as u64,
            Source::Manual { millis, .. } => millis.load(Ordering::SeqCst),
        }
    }

    /// Waits for a monotonic deadline; does not need the network.
    pub async fn sleep_until(&self, deadline: u64) {
        match &*self.0 {
            Source::System(start) => {
                let due = start
                    .checked_add(Duration::from_millis(deadline))
                    .unwrap_or(*start);
                tokio::time::sleep_until(tokio::time::Instant::from_std(due)).await;
            }
            Source::Manual { changed, .. } => loop {
                let notified = changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.now_ms() >= deadline {
                    return;
                }
                notified.await;
            },
        }
    }
}

impl ManualClock {
    /// Advances a manual clock and wakes waiting operations.
    pub fn advance(&self, duration: Duration) {
        if let Source::Manual { millis, changed } = &*self.0.0 {
            millis
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    Some(n.saturating_add(duration.as_millis().min(u64::MAX as u128) as u64))
                })
                .ok();
            changed.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn manual_clock_wakes_sleepers_when_advanced() {
        let (clock, manual) = Clock::manual();
        let sleep = clock.sleep_until(clock.now_ms() + 1_000);
        tokio::pin!(sleep);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(std::future::Future::poll(sleep.as_mut(), &mut cx).is_pending());
        manual.advance(Duration::from_millis(999));
        assert!(std::future::Future::poll(sleep.as_mut(), &mut cx).is_pending());
        manual.advance(Duration::from_millis(1));
        sleep.await;
    }
}
