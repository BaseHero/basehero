//! Opt-in, unit-test-only lock timing. No product instrumentation or allocator hooks.
use std::{cell::RefCell, time::Instant};
#[derive(Clone, Default)]
pub(crate) struct Stats {
    pub count: u64,
    pub wait_ns: u128,
    pub hold_ns: u128,
    pub max_wait: u128,
    pub max_hold: u128,
    pub wait_buckets: [u64; 32],
    pub hold_buckets: [u64; 32],
}
thread_local! {static STATS:RefCell<Option<Stats>>=const {RefCell::new(None)};}
pub(crate) fn start() {
    STATS.with(|s| *s.borrow_mut() = Some(Stats::default()));
}
pub(crate) fn finish() -> Stats {
    STATS.with(|s| s.borrow_mut().take().unwrap())
}
pub(crate) fn waiting() -> Option<Instant> {
    STATS.with(|s| s.borrow().as_ref().map(|_| Instant::now()))
}
pub(crate) struct Held {
    start: Instant,
    wait: u128,
}
pub(crate) fn acquired(start: Instant) -> Held {
    let now = Instant::now();
    Held {
        start: now,
        wait: now.duration_since(start).as_nanos(),
    }
}
impl Drop for Held {
    fn drop(&mut self) {
        let hold = self.start.elapsed().as_nanos();
        STATS.with(|s| {
            if let Some(s) = s.borrow_mut().as_mut() {
                s.count += 1;
                s.wait_ns += self.wait;
                s.hold_ns += hold;
                s.max_wait = s.max_wait.max(self.wait);
                s.max_hold = s.max_hold.max(hold);
                s.wait_buckets[bucket(self.wait)] += 1;
                s.hold_buckets[bucket(hold)] += 1;
            }
        });
    }
}
fn bucket(n: u128) -> usize {
    n.max(1).ilog2().min(31) as usize
}
