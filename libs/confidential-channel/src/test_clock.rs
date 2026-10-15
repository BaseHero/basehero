//! Private fixture controls. The production API always samples its owned clock
//! under the policy lock; these setters never pass raw samples to client methods.
use crate::appraisal::Sample;
use std::cell::Cell;
thread_local! { static NOW: Cell<Sample> = const { Cell::new(Sample {system_seconds:Some(120),monotonic_ms:0}) }; }
pub(crate) fn read() -> Sample {
    NOW.with(Cell::get)
}
pub(crate) fn set(sample: Sample) {
    NOW.with(|n| n.set(sample));
}
pub(crate) fn clock_at(ms: u64) -> fn() -> Sample {
    set(Sample {
        system_seconds: Some(120),
        monotonic_ms: ms,
    });
    read
}
pub(crate) trait At: Sized {
    fn at(self, sample: Sample) -> Self {
        set(sample);
        self
    }
}
impl<S: crate::appraisal::PolicyStore> At for crate::handshake::ClientHello<S> {}
impl<S: crate::appraisal::PolicyStore> At for crate::handshake::ProofChecked<S> {}
impl<S: crate::appraisal::PolicyStore> At for crate::handshake::ClientAwaitServer<S> {}
impl<S: crate::appraisal::PolicyStore> crate::record::Session<S> {
    pub(crate) fn at(&mut self, sample: Sample) -> &mut Self {
        set(sample);
        self
    }
}
