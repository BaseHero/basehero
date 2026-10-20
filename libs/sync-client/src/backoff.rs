//! Reconnect and retry delays: 250 ms × 2ⁿ, capped at 30 s, ±20 % jitter.
use std::time::Duration;

const FIRST_MS: u64 = 250;
const CAP_MS: u64 = 30_000;

#[derive(Default)]
pub(crate) struct Backoff {
    failures: u32,
}
impl Backoff {
    pub(crate) fn reset(&mut self) {
        self.failures = 0;
    }
    /// The delay before the next attempt after another failure.
    pub(crate) fn next(&mut self) -> Duration {
        let base = FIRST_MS
            .saturating_mul(1 << self.failures.min(16))
            .min(CAP_MS);
        self.failures = self.failures.saturating_add(1);
        jittered(base, u64::from_be_bytes(bh_crypto::random()))
    }
}

/// `base` scaled by a factor in [0.8, 1.2] chosen by `random`.
fn jittered(base: u64, random: u64) -> Duration {
    let spread = base / 5;
    let offset = random % (2 * spread + 1);
    Duration::from_millis(base - spread + offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_from_a_quarter_second_to_thirty_with_a_fifth_either_way() {
        let mut backoff = Backoff::default();
        let mut bases = Vec::new();
        for _ in 0..10 {
            let delay = backoff.next().as_millis() as u64;
            bases.push(delay);
        }
        for (n, delay) in bases.iter().enumerate() {
            let base = (250u64 << n).min(30_000);
            assert!(
                (base * 4 / 5..=base * 6 / 5).contains(delay),
                "{n}: {delay}"
            );
        }
        assert_eq!(jittered(1000, 0), Duration::from_millis(800));
        assert_eq!(jittered(1000, 400), Duration::from_millis(1200));
        backoff.reset();
        assert!(backoff.next() <= Duration::from_millis(300));
    }
}
