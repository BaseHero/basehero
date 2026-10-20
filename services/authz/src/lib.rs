//! The authorization service for hosted sync. Devices reach it inside an
//! attested channel; it authenticates a device's possession proof, checks the
//! account's current verified history, which it reads from the edge before
//! every answer, and signs short permits for the edge and log objects.
//!
//! It never sees note content or content keys, and it orders nothing: the log
//! objects do. A base's metadata root arrives inside the channel only to
//! verify that base's genesis or a control, and is never kept. Its disk holds
//! verified account histories, as a cache, the registry of verified base
//! geneses (each base's creator account and content epoch), and each base's
//! control record, which holds no key.
//!
//! The synthetic attestation and test clock exist only with the
//! `synthetic-attestation` feature, which no release build enables:
#![cfg_attr(
    not(feature = "synthetic-attestation"),
    doc = "```compile_fail\nlet _ = bh_authz::SyntheticAttestation;\n```"
)]
#![cfg_attr(
    not(feature = "synthetic-attestation"),
    doc = "```compile_fail\nlet _ = bh_authz::FixedClock::new(0);\n```"
)]
#![forbid(unsafe_code)]

mod attest;
mod authority;
mod channel;
mod clock;
mod edge;
mod store;

pub use bh_authz_proto as proto;

#[cfg(feature = "synthetic-attestation")]
pub use attest::SyntheticAttestation;
pub use attest::{AttestError, Attestation, DstackAttestation, Evidence};
#[cfg(feature = "synthetic-attestation")]
pub use authority::Observer;
pub use authority::{Connection, Service};
pub use channel::ChannelConfig;
pub use clock::{Clock, ClockError, MonotonicCounter, RoughtimeClock};
#[cfg(feature = "synthetic-attestation")]
pub use clock::{FixedClock, LocalClock};
pub use edge::{EdgeClient, EdgeError, EdgeReader, HomeObjectsAck, LogItems, LogRead};

use bh_crypto::SigningKey;
use bh_sync::receipt::CERTIFICATE_LEN;
use std::fmt;

/// The permit-signing key and its certificate under the hosting root.
pub struct PermitKeys {
    pub(crate) key: SigningKey,
    pub(crate) certificate: [u8; CERTIFICATE_LEN],
}
impl PermitKeys {
    /// The certificate must name `key`; the edge checks it against its pinned root.
    pub fn new(key: SigningKey, certificate: [u8; CERTIFICATE_LEN]) -> Result<Self, ServiceError> {
        if certificate[34..66] != key.public() {
            return Err(ServiceError::Config);
        }
        Ok(Self { key, certificate })
    }
    /// The hosting root the certificate names.
    pub fn root(&self) -> [u8; 32] {
        self.certificate[2..34].try_into().expect("fixed width")
    }
}

/// Fixed, content-free failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceError {
    Config,
    Storage,
    Channel,
    Transport,
    Attestation,
}
impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "authorization service: {self:?}")
    }
}
impl std::error::Error for ServiceError {}
