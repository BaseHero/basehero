//! Signed evidence issued by an account log's access checker. Signatures use
//! the existing certified permit key, verified against a pinned hosting root.
use crate::{
    Digest, Head,
    permit::{self, LogId, LogKind},
    receipt,
};
use bh_crypto::{SigningKey, hash, verify as verify_signature};

const VERSION: [u8; 2] = 1u16.to_be_bytes();
const CONFIRM_DOMAIN: &[u8] = b"bh/ordering-confirmation/v1\0";
const HEAD_DOMAIN: &[u8] = b"bh/accepted-head/v1\0";
const KEY_DOMAIN: &[u8] = b"bh/recovery-key/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    Encoding,
    Certificate,
    Signature,
    Binding,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeBounds {
    pub earliest_ms: u64,
    pub latest_ms: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmationClaim {
    pub log: LogId,
    pub original: Digest,
    pub original_previous: Head,
    pub original_head: Head,
    pub body: Option<Digest>,
    pub ordered: Head,
    pub bounds: TimeBounds,
}
pub fn original_digest(original: &[u8]) -> Digest {
    Digest(hash(
        &[b"bh/account-original/v1\0".as_slice(), original].concat(),
    ))
}
struct Input<'a>(&'a [u8]);
impl Input<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], EvidenceError> {
        let (part, rest) = self.0.split_at_checked(N).ok_or(EvidenceError::Encoding)?;
        self.0 = rest;
        part.try_into().map_err(|_| EvidenceError::Encoding)
    }
    fn version(&mut self) -> Result<(), EvidenceError> {
        if self.take::<2>()? == VERSION {
            Ok(())
        } else {
            Err(EvidenceError::Encoding)
        }
    }
    fn log(&mut self) -> Result<LogId, EvidenceError> {
        if self.take::<1>()?[0] != LogKind::Account as u8 {
            return Err(EvidenceError::Encoding);
        }
        Ok(LogId {
            kind: LogKind::Account,
            id: self.take()?,
        })
    }
    fn head(&mut self) -> Result<Head, EvidenceError> {
        Ok(Head {
            position: u64::from_be_bytes(self.take()?),
            hash: Digest(self.take()?),
        })
    }
    fn bounds(&mut self) -> Result<TimeBounds, EvidenceError> {
        let bounds = TimeBounds {
            earliest_ms: u64::from_be_bytes(self.take()?),
            latest_ms: u64::from_be_bytes(self.take()?),
        };
        if bounds.earliest_ms > bounds.latest_ms {
            return Err(EvidenceError::Encoding);
        }
        Ok(bounds)
    }
    fn finish(&self) -> Result<(), EvidenceError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(EvidenceError::Encoding)
        }
    }
}
fn put_log(out: &mut Vec<u8>, log: LogId) {
    out.push(log.kind as u8);
    out.extend(log.id);
}
fn put_head(out: &mut Vec<u8>, head: Head) {
    out.extend(head.position.to_be_bytes());
    out.extend(head.hash.0);
}
fn put_bounds(out: &mut Vec<u8>, bounds: TimeBounds) {
    out.extend(bounds.earliest_ms.to_be_bytes());
    out.extend(bounds.latest_ms.to_be_bytes());
}
fn verify_signed(
    root: &[u8; 32],
    cert: &[u8; receipt::CERTIFICATE_LEN],
    signature: &[u8; 64],
    domain: &[u8],
    payload: &[u8],
) -> Result<(), EvidenceError> {
    let key = permit::verify_certificate(root, cert).map_err(|_| EvidenceError::Certificate)?;
    verify_signature(&key.public_key(), &[domain, payload].concat(), signature)
        .map_err(|_| EvidenceError::Signature)
}

/// Exact statement that a signed original account control is durably ordered.
#[derive(Clone, Debug)]
pub struct OrderingConfirmation {
    claim: ConfirmationClaim,
    certificate: [u8; receipt::CERTIFICATE_LEN],
    signature: [u8; 64],
}
impl OrderingConfirmation {
    pub const LEN: usize = 2 + 33 + 32 + 40 + 40 + 33 + 40 + 16 + receipt::CERTIFICATE_LEN + 64;
    fn payload(claim: &ConfirmationClaim) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN - receipt::CERTIFICATE_LEN - 64);
        out.extend(VERSION);
        put_log(&mut out, claim.log);
        out.extend(claim.original.0);
        put_head(&mut out, claim.original_previous);
        put_head(&mut out, claim.original_head);
        out.push(u8::from(claim.body.is_some()));
        out.extend(claim.body.unwrap_or(Digest([0; 32])).0);
        put_head(&mut out, claim.ordered);
        put_bounds(&mut out, claim.bounds);
        out
    }
    pub fn sign(
        key: &SigningKey,
        certificate: &[u8; receipt::CERTIFICATE_LEN],
        claim: ConfirmationClaim,
    ) -> Self {
        let signature = key.sign(&[CONFIRM_DOMAIN, &Self::payload(&claim)].concat());
        Self {
            claim,
            certificate: *certificate,
            signature,
        }
    }
    pub fn claim(&self) -> &ConfirmationClaim {
        &self.claim
    }
    pub fn verify(&self, root: &[u8; 32]) -> Result<&ConfirmationClaim, EvidenceError> {
        if self.claim.log.kind != LogKind::Account
            || self.claim.bounds.earliest_ms > self.claim.bounds.latest_ms
        {
            return Err(EvidenceError::Encoding);
        }
        verify_signed(
            root,
            &self.certificate,
            &self.signature,
            CONFIRM_DOMAIN,
            &Self::payload(&self.claim),
        )?;
        Ok(&self.claim)
    }
    pub fn verify_for(
        &self,
        root: &[u8; 32],
        original: &[u8],
        body: Option<Digest>,
    ) -> Result<&ConfirmationClaim, EvidenceError> {
        let claim = self.verify(root)?;
        if claim.original != original_digest(original) || claim.body != body {
            return Err(EvidenceError::Binding);
        }
        Ok(claim)
    }
    pub fn commitment(&self) -> [u8; 32] {
        hash(&self.encode())
    }
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = Self::payload(&self.claim);
        out.extend(self.certificate);
        out.extend(self.signature);
        out.try_into().expect("fixed confirmation length")
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, EvidenceError> {
        if bytes.len() != Self::LEN {
            return Err(EvidenceError::Encoding);
        }
        let mut input = Input(bytes);
        input.version()?;
        let log = input.log()?;
        let original = Digest(input.take()?);
        let original_previous = input.head()?;
        let original_head = input.head()?;
        let present = input.take::<1>()?[0];
        let digest = input.take()?;
        let body = match present {
            0 if digest == [0; 32] => None,
            1 => Some(Digest(digest)),
            _ => return Err(EvidenceError::Encoding),
        };
        let ordered = input.head()?;
        let bounds = input.bounds()?;
        let certificate = input.take()?;
        let signature = input.take()?;
        input.finish()?;
        Ok(Self {
            claim: ConfirmationClaim {
                log,
                original,
                original_previous,
                original_head,
                body,
                ordered,
                bounds,
            },
            certificate,
            signature,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedHead {
    pub log: LogId,
    pub challenge: [u8; 32],
    pub original_head: Head,
    /// Confirmation commitment at this head; zero for a legacy head.
    pub evidence: [u8; 32],
    pub bounds: TimeBounds,
}
impl AcceptedHead {
    const LEN: usize = 2 + 33 + 32 + 40 + 32 + 16 + receipt::CERTIFICATE_LEN + 64;
    fn payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN - receipt::CERTIFICATE_LEN - 64);
        out.extend(VERSION);
        put_log(&mut out, self.log);
        out.extend(self.challenge);
        put_head(&mut out, self.original_head);
        out.extend(self.evidence);
        put_bounds(&mut out, self.bounds);
        out
    }
    pub fn sign(
        key: &SigningKey,
        certificate: &[u8; receipt::CERTIFICATE_LEN],
        log: LogId,
        challenge: [u8; 32],
        original_head: Head,
        evidence: [u8; 32],
        bounds: TimeBounds,
    ) -> Vec<u8> {
        let value = Self {
            log,
            challenge,
            original_head,
            evidence,
            bounds,
        };
        let payload = value.payload();
        let mut out = payload.clone();
        out.extend(certificate);
        out.extend(key.sign(&[HEAD_DOMAIN, &payload].concat()));
        out
    }
    pub fn verify(
        bytes: &[u8],
        root: &[u8; 32],
        log: LogId,
        challenge: &[u8; 32],
    ) -> Result<Self, EvidenceError> {
        if bytes.len() != Self::LEN {
            return Err(EvidenceError::Encoding);
        }
        let mut input = Input(bytes);
        input.version()?;
        let value = Self {
            log: input.log()?,
            challenge: input.take()?,
            original_head: input.head()?,
            evidence: input.take()?,
            bounds: input.bounds()?,
        };
        let certificate = input.take()?;
        let signature = input.take()?;
        input.finish()?;
        verify_signed(
            root,
            &certificate,
            &signature,
            HEAD_DOMAIN,
            &value.payload(),
        )?;
        if value.log != log {
            return Err(EvidenceError::Binding);
        }
        if &value.challenge != challenge {
            return Err(EvidenceError::Signature);
        }
        Ok(value)
    }
}

/// Recovery public key authenticated directly under the pinned hosting root.
#[derive(Clone, Debug)]
pub struct RecoveryKeyCertificate {
    pub public: [u8; 1216],
    root: [u8; 32],
    signature: [u8; 64],
}
impl RecoveryKeyCertificate {
    pub const LEN: usize = 2 + 32 + 1216 + 64;
    fn payload(&self) -> Vec<u8> {
        [VERSION.as_slice(), &self.root, &self.public].concat()
    }
    pub fn verify(&self, root: &[u8; 32]) -> Result<(), EvidenceError> {
        if &self.root != root {
            return Err(EvidenceError::Certificate);
        }
        verify_signature(
            root,
            &[KEY_DOMAIN, &self.payload()].concat(),
            &self.signature,
        )
        .map_err(|_| EvidenceError::Signature)
    }
    pub fn encode(&self) -> [u8; Self::LEN] {
        [self.payload().as_slice(), &self.signature]
            .concat()
            .try_into()
            .expect("fixed key certificate length")
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, EvidenceError> {
        if bytes.len() != Self::LEN {
            return Err(EvidenceError::Encoding);
        }
        let mut input = Input(bytes);
        input.version()?;
        let value = Self {
            root: input.take()?,
            public: input.take()?,
            signature: input.take()?,
        };
        input.finish()?;
        Ok(value)
    }
}
pub fn certify_recovery_key(authority: &SigningKey, public: &[u8; 1216]) -> RecoveryKeyCertificate {
    let mut value = RecoveryKeyCertificate {
        public: *public,
        root: authority.public(),
        signature: [0; 64],
    };
    value.signature = authority.sign(&[KEY_DOMAIN, &value.payload()].concat());
    value
}
