//! Root-certified hosting statements about observed heads, not proof of current authority.
//!
//! The caller obtains and pins the trusted hosting authority independently of these
//! frames; a self-declared root in a certificate never establishes trust. A root
//! may certify successive receipt keys: keep historical certificates and receipts
//! to verify past statements after rotation. Signatures alone cannot establish
//! when a statement was made, whether a key was compromised, or which head is
//! currently authoritative.
//!
//! This codec authenticates an arbitrary base, position and opaque history digest,
//! including [`Head::EMPTY`]. It does not establish genesis/registration, verify
//! original authors or log history, or attest that a body or head was durably
//! stored. The hosting adapter must sign only authenticated durable results from
//! the correct base object; readers must verify original history separately.
//! Different positions require history proofs, not this module's comparison.

use std::fmt;

use bh_crypto::{SigningKey, hash, verify as verify_signature};

use crate::{BaseId, Digest, Head};

pub const CERTIFICATE_LEN: usize = 130;
pub const RECEIPT_LEN: usize = 300;

const CERT_DOMAIN: &[u8] = b"bh/hosting-receipt-certificate/v1\0";
const CERT_ID_DOMAIN: &[u8] = b"bh/hosting-receipt-certificate-id/v1\0";
const RECEIPT_DOMAIN: &[u8] = b"bh/observed-head-receipt/v1\0";

/// Fixed, input-free errors: neither frames nor keys appear in diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Version,
    WrongAuthority,
    WrongBase,
    WrongSigningKey,
    BadCertificate,
    CertificateMismatch,
    BadSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// A certificate verified against a caller-supplied, independently trusted root.
#[derive(Clone)]
pub struct CertifiedReceiptKey {
    bytes: [u8; CERTIFICATE_LEN],
}

impl fmt::Debug for CertifiedReceiptKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CertifiedReceiptKey")
    }
}
impl CertifiedReceiptKey {
    pub fn as_bytes(&self) -> &[u8; CERTIFICATE_LEN] {
        &self.bytes
    }
}

/// An authenticated service statement, not evidence of currentness or durability.
#[derive(Clone)]
pub struct VerifiedHeadReceipt {
    bytes: [u8; RECEIPT_LEN],
    base: BaseId,
    head: Head,
    authority: [u8; 32],
}

impl fmt::Debug for VerifiedHeadReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedHeadReceipt")
    }
}
impl VerifiedHeadReceipt {
    pub fn base(&self) -> BaseId {
        self.base
    }
    pub fn head(&self) -> Head {
        self.head
    }
    pub fn authority(&self) -> [u8; 32] {
        self.authority
    }
    /// Retain the exact signed evidence, including its historical certificate.
    pub fn as_bytes(&self) -> &[u8; RECEIPT_LEN] {
        &self.bytes
    }
}

/// Certify one receipt public key under the hosting root.
pub fn certify(authority: &SigningKey, receipt_public: [u8; 32]) -> [u8; CERTIFICATE_LEN] {
    let mut bytes = [0; CERTIFICATE_LEN];
    bytes[..2].copy_from_slice(&1u16.to_be_bytes());
    bytes[2..34].copy_from_slice(&authority.public());
    bytes[34..66].copy_from_slice(&receipt_public);
    let signature = authority.sign(&[CERT_DOMAIN, &bytes[..66]].concat());
    bytes[66..].copy_from_slice(&signature);
    bytes
}

/// Verify the entire certificate against an independently pinned authority.
pub fn verify_certificate(
    trusted_authority: &[u8; 32],
    encoded: &[u8],
) -> Result<CertifiedReceiptKey, Error> {
    let bytes: [u8; CERTIFICATE_LEN] = encoded.try_into().map_err(|_| Error::Encoding)?;
    if bytes[..2] != 1u16.to_be_bytes() {
        return Err(Error::Version);
    }
    if bytes[2..34] != trusted_authority[..] {
        return Err(Error::WrongAuthority);
    }
    verify_signature(
        trusted_authority,
        &[CERT_DOMAIN, &bytes[..66]].concat(),
        &bytes[66..130].try_into().expect("fixed certificate frame"),
    )
    .map_err(|_| Error::BadCertificate)?;
    Ok(CertifiedReceiptKey { bytes })
}

/// Sign a head statement with exactly the private key certified above.
/// The caller, not this codec, is responsible for sourcing a durable head.
pub fn sign(
    certificate: &CertifiedReceiptKey,
    signer: &SigningKey,
    base: BaseId,
    head: Head,
) -> Result<[u8; RECEIPT_LEN], Error> {
    if certificate.bytes[34..66] != signer.public() {
        return Err(Error::WrongSigningKey);
    }
    let mut bytes = [0; RECEIPT_LEN];
    bytes[..CERTIFICATE_LEN].copy_from_slice(&certificate.bytes);
    bytes[130..132].copy_from_slice(&1u16.to_be_bytes());
    bytes[132..164].copy_from_slice(&hash(&[CERT_ID_DOMAIN, &certificate.bytes].concat()));
    bytes[164..196].copy_from_slice(&base.0);
    bytes[196..204].copy_from_slice(&head.position.to_be_bytes());
    bytes[204..236].copy_from_slice(&head.hash.0);
    let signature = signer.sign(&[RECEIPT_DOMAIN, &bytes[130..236]].concat());
    bytes[236..].copy_from_slice(&signature);
    Ok(bytes)
}

/// Authenticate one exact statement under a caller-supplied root and base.
pub fn verify(
    trusted_authority: &[u8; 32],
    expected_base: BaseId,
    encoded: &[u8],
) -> Result<VerifiedHeadReceipt, Error> {
    let bytes: [u8; RECEIPT_LEN] = encoded.try_into().map_err(|_| Error::Encoding)?;
    let certificate = verify_certificate(trusted_authority, &bytes[..CERTIFICATE_LEN])?;
    if bytes[130..132] != 1u16.to_be_bytes() {
        return Err(Error::Version);
    }
    if bytes[132..164] != hash(&[CERT_ID_DOMAIN, certificate.as_bytes()].concat()) {
        return Err(Error::CertificateMismatch);
    }
    if bytes[164..196] != expected_base.0 {
        return Err(Error::WrongBase);
    }
    verify_signature(
        &certificate.bytes[34..66]
            .try_into()
            .expect("fixed certificate frame"),
        &[RECEIPT_DOMAIN, &bytes[130..236]].concat(),
        &bytes[236..300].try_into().expect("fixed receipt frame"),
    )
    .map_err(|_| Error::BadSignature)?;
    Ok(VerifiedHeadReceipt {
        bytes,
        base: expected_base,
        head: Head {
            position: u64::from_be_bytes(bytes[196..204].try_into().expect("fixed receipt frame")),
            hash: Digest(bytes[204..236].try_into().expect("fixed receipt frame")),
        },
        authority: *trusted_authority,
    })
}

/// Only an authenticated same-root/base/position different-hash pair conflicts.
/// `false` says nothing about consistency at distinct positions.
pub fn conflicts_at_same_position(left: &VerifiedHeadReceipt, right: &VerifiedHeadReceipt) -> bool {
    left.authority == right.authority
        && left.base == right.base
        && left.head.position == right.head.position
        && left.head.hash != right.head.hash
}
