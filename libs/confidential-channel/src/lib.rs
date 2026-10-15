//! Native, checker-only attested channel; no device authentication or authorization.
#![forbid(unsafe_code)]

// Compile the verifier source into unit tests so synthetic assembly stays private:
// no production feature, claims constructor or dependency-facing test bypass.
#[cfg(test)]
#[path = "../../confidential-attestation/src/lib.rs"]
mod attestation;
#[cfg(not(test))]
use bh_confidential_attestation as attestation;

pub mod appraisal;
pub mod handshake;
pub mod record;
pub mod wire;
#[cfg(test)]
extern crate self as bh_confidential_channel;
#[cfg(test)]
mod lock_measurements;
#[cfg(test)]
mod persistence_tests;
#[cfg(test)]
mod scale_tests;
#[cfg(test)]
mod test_clock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Frame,
    Limit,
    Order,
    Direction,
    Sequence,
    Authentication,
    Policy(bh_confidential_policy::Error),
    Attestation(attestation::Error),
    Clock,
    Deadline,
    PersistenceUnavailable,
    Unavailable,
}
impl From<bh_confidential_policy::Error> for Error {
    fn from(e: bh_confidential_policy::Error) -> Self {
        Self::Policy(e)
    }
}
impl From<attestation::Error> for Error {
    fn from(e: attestation::Error) -> Self {
        Self::Attestation(e)
    }
}
