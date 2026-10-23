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
//! control record, which holds no key. For recovery it also keeps each
//! account's current recovery record and the personal key's recovery seal,
//! indexed by the hash of the code's proof alone, the tries against each
//! record, and when each record was released.
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

#[cfg(test)]
extern crate self as bh_authz;

mod attest;
mod authority;
mod channel;
mod clock;
mod confirm;
mod edge;
pub mod recovery;
mod store;

pub use bh_authz_proto as proto;

#[cfg(feature = "synthetic-attestation")]
pub use attest::SyntheticAttestation;
pub use attest::{AttestError, Attestation, DstackAttestation, Evidence};
#[cfg(feature = "synthetic-attestation")]
pub use authority::Observer;
pub use authority::{Connection, Service};
pub use channel::ChannelConfig;
pub use clock::{Bounds, Clock, ClockError, MonotonicCounter, RoughtimeClock};
#[cfg(feature = "synthetic-attestation")]
pub use clock::{FixedClock, LocalClock};
pub use edge::{EdgeClient, EdgeError, EdgeReader, HomeObjectsAck, LogItems, LogRead};

use bh_crypto::{KemKey, SigningKey};
use bh_sync::{evidence::RecoveryKeyCertificate, receipt::CERTIFICATE_LEN};
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

/// The home's recovery X-Wing key, which recovering devices seal their
/// claims to, and its certificate under the hosting root, which they check.
pub struct RecoveryHomeKey {
    pub(crate) key: KemKey,
    certificate: RecoveryKeyCertificate,
}
impl RecoveryHomeKey {
    /// The certificate must name `key` under `root`.
    pub fn new(
        key: KemKey,
        certificate: RecoveryKeyCertificate,
        root: &[u8; 32],
    ) -> Result<Self, ServiceError> {
        if certificate.public != key.public() || certificate.verify(root).is_err() {
            return Err(ServiceError::Config);
        }
        Ok(Self { key, certificate })
    }
    pub fn certificate(&self) -> &RecoveryKeyCertificate {
        &self.certificate
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
