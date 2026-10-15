//! One serialized app-root policy, clock high-water and atomic storage boundary.
use crate::Error;
use crate::attestation::{Time, VerifiedEvidence};
use bh_confidential_policy::{Limits, PolicyGate, Role, Snapshot, TimeBounds};
use std::sync::{Arc, Mutex};

/// Fresh is an explicit new-install initialization, not a missing file.
#[derive(Clone)]
pub enum StoredState {
    Fresh,
    Committed(Snapshot),
    Missing,
}
/// Implementations atomically replace the whole record and return only after
/// durable commit. This interface supplies no production no-op or disk adapter.
pub trait PolicyStore: Send {
    type Error;
    fn load(&mut self) -> Result<StoredState, Self::Error>;
    fn save(&mut self, snapshot: &Snapshot) -> Result<(), Self::Error>;
}
#[derive(Clone, Copy)]
pub struct Sample {
    pub system_seconds: Option<u64>,
    pub monotonic_ms: u64,
}
/// Trusted, nonblocking local clock adapter. Never fetch network time here.
/// The context calls it only while holding its policy lock; callers must not
/// return previously sampled values or share a mutable sample queue in production.
pub trait Clock: Send + Sync {
    fn sample(&self) -> Sample;
}
impl<F: Fn() -> Sample + Send + Sync> Clock for F {
    fn sample(&self) -> Sample {
        self()
    }
}
struct Inner<S: PolicyStore> {
    clock: Box<dyn Clock>,
    store: S,
    gate: PolicyGate,
    pending: Option<bh_confidential_policy::Candidate>,
    outage_while_pending: bool,
    high_system: Option<u64>,
    high_mono: Option<u64>,
    clock_failed: bool,
    build_floor: u64,
    root: [u8; 32],
}
pub struct PolicyContext<S: PolicyStore>(Arc<Mutex<Inner<S>>>);
impl<S: PolicyStore> Clone for PolicyContext<S> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}
impl<S: PolicyStore> PolicyContext<S> {
    /// `build_floor` is the signed app build date at UTC midnight in POSIX seconds.
    /// An established missing/corrupt record fails; never silently initializes.
    pub fn new(
        root: [u8; 32],
        limits: Limits,
        build_floor: u64,
        mut store: S,
        clock: impl Clock + 'static,
    ) -> Result<Self, Error> {
        if build_floor == 0 || build_floor > i64::MAX as u64 {
            return Err(Error::Clock);
        }
        let gate = match store.load().map_err(|_| Error::PersistenceUnavailable)? {
            StoredState::Fresh => PolicyGate::new(root, limits)?,
            StoredState::Committed(snapshot) => {
                PolicyGate::restore_unavailable(root, limits, &snapshot)?
            }
            StoredState::Missing => return Err(Error::PersistenceUnavailable),
        };
        Ok(Self(Arc::new(Mutex::new(Inner {
            clock: Box::new(clock),
            store,
            gate,
            pending: None,
            outage_while_pending: false,
            high_system: None,
            high_mono: None,
            clock_failed: false,
            build_floor,
            root,
        }))))
    }
    /// The root is not supplied by the untrusted handshake caller.
    pub fn root_hash(&self) -> Result<[u8; 32], Error> {
        Ok(bh_crypto::hash(&self.lock()?.root))
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner<S>>, Error> {
        self.0.lock().map_err(|_| Error::Unavailable)
    }
    // Called synchronously by a test clock on the same thread, without other contenders.
    #[cfg(test)]
    pub(crate) fn lock_held_for_test(&self) -> bool {
        self.0.try_lock().is_err()
    }
    pub fn deliver_policy(&self, payload: &[u8], signature: &[u8]) -> Result<(), Error> {
        let mut inner = self.lock()?;
        if inner.pending.is_some() {
            return Err(Error::PersistenceUnavailable);
        }
        let candidate = inner.gate.prepare_delivery(payload, signature)?;
        if candidate.advancing() && inner.store.save(candidate.snapshot()).is_err() {
            inner.pending = Some(candidate);
            return Err(Error::PersistenceUnavailable);
        }
        inner.gate.publish_delivery(candidate)?;
        Ok(())
    }
    /// Resolve only the exact retained pending candidate. Re-saving is safe even
    /// after an ambiguous committed-but-unacknowledged atomic replacement.
    pub fn resolve_pending(&self) -> Result<(), Error> {
        let mut inner = self.lock()?;
        let Some(candidate) = inner.pending.take() else {
            return Err(Error::Unavailable);
        };
        if inner.store.save(candidate.snapshot()).is_err() {
            inner.pending = Some(candidate);
            return Err(Error::PersistenceUnavailable);
        }
        inner.gate.publish_delivery(candidate)?;
        if inner.outage_while_pending {
            inner.gate.mark_unavailable();
            inner.outage_while_pending = false;
        }
        Ok(())
    }
    pub fn mark_unavailable(&self) -> Result<(), Error> {
        let mut inner = self.lock()?;
        // A failed save already poisons every user. Remember the outage without
        // changing the pending candidate's revision; restore refusal after it
        // commits, until a fresh authenticated policy delivery arrives.
        if inner.pending.is_some() {
            inner.outage_while_pending = true;
            return Err(Error::PersistenceUnavailable);
        }
        inner.gate.mark_unavailable();
        Ok(())
    }
    fn sample(inner: &mut Inner<S>) -> Result<(Sample, TimeBounds), Error> {
        let sample = inner.clock.sample();
        if inner.high_mono.is_some_and(|p| sample.monotonic_ms < p) {
            inner.clock_failed = true;
        }
        if inner.clock_failed {
            return Err(Error::Clock);
        }
        if inner.pending.is_some() {
            return Err(Error::PersistenceUnavailable);
        }
        let Some(seconds) = sample.system_seconds else {
            return Err(Error::Clock);
        };
        if seconds > i64::MAX as u64 {
            return Err(Error::Clock);
        }
        if inner.high_system.is_some_and(|p| seconds < p) {
            inner.clock_failed = true;
            return Err(Error::Clock);
        }
        if seconds < inner.build_floor {
            return Err(Error::Clock);
        }
        inner.high_system = Some(seconds);
        inner.high_mono = Some(sample.monotonic_ms);
        Ok((
            sample,
            TimeBounds {
                earliest: seconds,
                latest: seconds,
            },
        ))
    }
    // Initial Hello/admission need clock qualification but not an installed policy.
    pub(crate) fn with_clock<R>(
        &self,
        action: impl FnOnce(Sample) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let mut inner = self.lock()?;
        let (sample, _) = Self::sample(&mut inner)?;
        action(sample)
    }
    /// Sample, immutable horizon, CURRENT policy and actual use share one lock.
    /// Heavy QVL/log work never happens here; historical Proof is not redelivered.
    pub(crate) fn with_current<R>(
        &self,
        evidence: &VerifiedEvidence,
        use_current: impl FnOnce(Sample) -> Result<R, Error>,
    ) -> Result<R, Error> {
        #[cfg(test)]
        let timing = crate::lock_measurements::waiting();
        let mut inner = self.lock()?;
        #[cfg(test)]
        let _timing = timing.map(crate::lock_measurements::acquired);
        let (sample, time) = Self::sample(&mut inner)?;
        evidence.check_time(Some(Time {
            earliest: time.earliest,
            latest: time.latest,
            max_uncertainty_secs: 0,
        }))?;
        let measured = evidence.measured();
        inner.gate.check_measurements(
            Role::Checker,
            measured.build(),
            measured.machine(),
            Some(time),
        )?;
        use_current(sample)
    }
}
