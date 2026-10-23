//! Short-lived, operation-scoped hosting permissions and durable append acknowledgements.
//! Verification requires an independently pinned hosting root and a trusted clock.
use std::fmt;

use bh_crypto::{SigningKey, verify as verify_signature};

use crate::{BaseId, Commitment, Digest, EventId, Head, OpaqueEvent, Route, receipt};

pub const MAX_PERMIT_WINDOW_MS: u64 = 30_000;
const CERT_DOMAIN: &[u8] = b"bh/permit-key/v1\0";
const SIGN_DOMAIN: &[u8] = b"bh/permit/v1\0";
const VERSION: u16 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum LogKind {
    Base = 1,
    Account = 2,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LogId {
    pub kind: LogKind,
    pub id: [u8; 32],
}
#[derive(Clone, PartialEq, Eq)]
pub enum Scope {
    ReadEvents {
        log: LogId,
        first: u64,
        last: u64,
    },
    ReadBodies {
        log: LogId,
        bodies: Vec<Digest>,
    },
    Stage {
        log: LogId,
        body: Digest,
        len: u32,
    },
    Append {
        log: LogId,
        event: Digest,
        body: Option<Digest>,
        /// For content, the epoch the log must be in. For a control, the epoch
        /// in effect once it is ordered; `[0; 32]` means the epoch is closed.
        epoch: [u8; 32],
        /// `Some(head)` makes this a control append, ordered on the control
        /// route, whose predecessor must be the log's control head: the last
        /// control-route event, or `Head::EMPTY` before genesis. `None` makes
        /// it content.
        after: Option<Head>,
        /// A second staged body a control commits to inside its own body (a
        /// rekey's seal set), ordered with it so it is kept as long as the
        /// event's own body. Only a control with a body may attach one.
        attached: Option<Digest>,
    },
    Subscribe {
        log: LogId,
    },
    /// Up to 64 control-route events after position `after`; 0 is the empty
    /// head, so the read starts at the genesis.
    ReadControls {
        log: LogId,
        after: u64,
    },
    /// Immutable private signup objects at an account home; no log append.
    StoreHomeObjects {
        log: LogId,
        /// Verified original account-chain head hash, not the outer log head.
        prefix_digest: Digest,
        bundle_digest: Digest,
    },
    Presence {
        log: LogId,
        epoch: [u8; 32],
    },
    ReadDirectory {
        log: LogId,
    },
    StoreDirectoryEntry {
        log: LogId,
        entry: [u8; 32],
        version: u64,
        body: Digest,
        len: u32,
    },
    RetireHomeObjects {
        log: LogId,
        prefix_digest: Digest,
    },
    /// Authenticated device read, capped at the verified ordered head at issue.
    ReadControlRange {
        log: LogId,
        after: u64,
        through: u64,
    },
}
#[derive(Clone, PartialEq, Eq)]
pub struct Permit {
    pub scope: Scope,
    pub issued_ms: u64,
    pub deadline_ms: u64,
    pub batch: [u8; 16],
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PermitError {
    Encoding,
    Version,
    Certificate,
    Signature,
    Expired,
    Window,
    Bounds,
}
impl fmt::Display for PermitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PermitError {}

/// A permit-key certificate authenticated under a caller-pinned hosting root.
#[derive(Clone)]
pub struct CertifiedPermitKey {
    bytes: [u8; receipt::CERTIFICATE_LEN],
}
impl fmt::Debug for CertifiedPermitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CertifiedPermitKey")
    }
}
impl CertifiedPermitKey {
    pub fn as_bytes(&self) -> &[u8; receipt::CERTIFICATE_LEN] {
        &self.bytes
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.bytes[34..66]
            .try_into()
            .expect("fixed certificate key")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AppendAck {
    pub log: LogId,
    pub event: EventId,
    pub head: Head,
    pub receipt: Option<[u8; receipt::RECEIPT_LEN]>,
}

impl fmt::Debug for LogId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LogId")
    }
}
impl fmt::Debug for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReadEvents { .. } => "ReadEvents",
            Self::ReadBodies { .. } => "ReadBodies",
            Self::Stage { .. } => "Stage",
            Self::Append { .. } => "Append",
            Self::Subscribe { .. } => "Subscribe",
            Self::ReadControls { .. } => "ReadControls",
            Self::StoreHomeObjects { .. } => "StoreHomeObjects",
            Self::Presence { .. } => "Presence",
            Self::ReadDirectory { .. } => "ReadDirectory",
            Self::StoreDirectoryEntry { .. } => "StoreDirectoryEntry",
            Self::RetireHomeObjects { .. } => "RetireHomeObjects",
            Self::ReadControlRange { .. } => "ReadControlRange",
        })
    }
}
impl fmt::Debug for Permit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Permit")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for AppendAck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppendAck")
    }
}

struct Input<'a>(&'a [u8]);
impl Input<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], PermitError> {
        let (head, rest) = self.0.split_at_checked(N).ok_or(PermitError::Encoding)?;
        self.0 = rest;
        head.try_into().map_err(|_| PermitError::Encoding)
    }
    fn version(&mut self) -> Result<(), PermitError> {
        if u16::from_be_bytes(self.take()?) != VERSION {
            return Err(PermitError::Version);
        }
        Ok(())
    }
    fn log(&mut self) -> Result<LogId, PermitError> {
        let kind = match self.take::<1>()?[0] {
            1 => LogKind::Base,
            2 => LogKind::Account,
            _ => return Err(PermitError::Encoding),
        };
        Ok(LogId {
            kind,
            id: self.take()?,
        })
    }
    fn head(&mut self) -> Result<Head, PermitError> {
        Ok(Head {
            position: u64::from_be_bytes(self.take()?),
            hash: Digest(self.take()?),
        })
    }
    fn option<T>(
        &mut self,
        mut read: impl FnMut(&mut Self) -> Result<T, PermitError>,
    ) -> Result<Option<T>, PermitError> {
        match self.take::<1>()?[0] {
            0 => Ok(None),
            1 => read(self).map(Some),
            _ => Err(PermitError::Encoding),
        }
    }
    fn finish(&self) -> Result<(), PermitError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(PermitError::Encoding)
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
fn put_option<T>(out: &mut Vec<u8>, value: Option<T>, mut put: impl FnMut(&mut Vec<u8>, T)) {
    if let Some(value) = value {
        out.push(1);
        put(out, value);
    } else {
        out.push(0);
    }
}
fn valid_scope(scope: &Scope) -> Result<(), PermitError> {
    match scope {
        Scope::ReadEvents { first, last, .. }
            if *first == 0 || last.checked_sub(*first).is_none_or(|n| n >= 64) =>
        {
            Err(PermitError::Bounds)
        }
        Scope::ReadControlRange { after, through, .. }
            if after > through || *through > (1 << 53) - 1 =>
        {
            Err(PermitError::Bounds)
        }
        Scope::ReadBodies { bodies, .. } if !(1..=64).contains(&bodies.len()) => {
            Err(PermitError::Bounds)
        }
        Scope::StoreHomeObjects { log, .. } if log.kind != LogKind::Account => {
            Err(PermitError::Bounds)
        }
        Scope::Presence { log, .. } if log.kind != LogKind::Base => Err(PermitError::Bounds),
        Scope::Append {
            body,
            after,
            attached: Some(attached),
            ..
        } if after.is_none() || body.is_none_or(|body| body == *attached) => {
            Err(PermitError::Bounds)
        }
        Scope::ReadDirectory { log }
        | Scope::StoreDirectoryEntry { log, .. }
        | Scope::RetireHomeObjects { log, .. }
            if log.kind != LogKind::Account =>
        {
            Err(PermitError::Bounds)
        }
        _ => Ok(()),
    }
}
fn encode_permit(permit: &Permit) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(VERSION.to_be_bytes());
    let log = match &permit.scope {
        Scope::ReadEvents { log, .. } => {
            out.push(1);
            *log
        }
        Scope::ReadBodies { log, .. } => {
            out.push(2);
            *log
        }
        Scope::Stage { log, .. } => {
            out.push(3);
            *log
        }
        Scope::Append { log, .. } => {
            out.push(4);
            *log
        }
        Scope::Subscribe { log } => {
            out.push(5);
            *log
        }
        Scope::ReadControls { log, .. } => {
            out.push(6);
            *log
        }
        Scope::StoreHomeObjects { log, .. } => {
            out.push(7);
            *log
        }
        Scope::Presence { log, .. } => {
            out.push(8);
            *log
        }
        Scope::ReadDirectory { log } => {
            out.push(9);
            *log
        }
        Scope::StoreDirectoryEntry { log, .. } => {
            out.push(10);
            *log
        }
        Scope::RetireHomeObjects { log, .. } => {
            out.push(11);
            *log
        }
        Scope::ReadControlRange { log, .. } => {
            out.push(14);
            *log
        }
    };
    put_log(&mut out, log);
    match &permit.scope {
        Scope::ReadEvents { first, last, .. } => {
            out.extend(first.to_be_bytes());
            out.extend(last.to_be_bytes());
        }
        Scope::ReadBodies { bodies, .. } => {
            out.extend((bodies.len() as u16).to_be_bytes());
            for body in bodies {
                out.extend(body.0);
            }
        }
        Scope::Stage { body, len, .. } => {
            out.extend(body.0);
            out.extend(len.to_be_bytes());
        }
        Scope::Append {
            event,
            body,
            epoch,
            after,
            attached,
            ..
        } => {
            out.extend(event.0);
            put_option(&mut out, *body, |out, body| out.extend(body.0));
            out.extend(epoch);
            put_option(&mut out, *after, put_head);
            put_option(&mut out, *attached, |out, body| out.extend(body.0));
        }
        Scope::Subscribe { .. } => {}
        Scope::ReadControls { after, .. } => out.extend(after.to_be_bytes()),
        Scope::StoreHomeObjects {
            prefix_digest,
            bundle_digest,
            ..
        } => {
            out.extend(prefix_digest.0);
            out.extend(bundle_digest.0);
        }
        Scope::Presence { epoch, .. } => out.extend(epoch),
        Scope::ReadDirectory { .. } => {}
        Scope::StoreDirectoryEntry {
            entry,
            version,
            body,
            len,
            ..
        } => {
            out.extend(entry);
            out.extend(version.to_be_bytes());
            out.extend(body.0);
            out.extend(len.to_be_bytes());
        }
        Scope::RetireHomeObjects { prefix_digest, .. } => out.extend(prefix_digest.0),
        Scope::ReadControlRange { after, through, .. } => {
            out.extend(after.to_be_bytes());
            out.extend(through.to_be_bytes());
        }
    }
    out.extend(permit.issued_ms.to_be_bytes());
    out.extend(permit.deadline_ms.to_be_bytes());
    out.extend(permit.batch);
    out
}
fn decode_permit(bytes: &[u8]) -> Result<Permit, PermitError> {
    let mut input = Input(bytes);
    input.version()?;
    let tag = input.take::<1>()?[0];
    let log = input.log()?;
    let scope = match tag {
        1 => Scope::ReadEvents {
            log,
            first: u64::from_be_bytes(input.take()?),
            last: u64::from_be_bytes(input.take()?),
        },
        2 => {
            let count = u16::from_be_bytes(input.take()?) as usize;
            if !(1..=64).contains(&count) {
                return Err(PermitError::Bounds);
            }
            let mut bodies = Vec::with_capacity(count);
            for _ in 0..count {
                bodies.push(Digest(input.take()?));
            }
            Scope::ReadBodies { log, bodies }
        }
        3 => Scope::Stage {
            log,
            body: Digest(input.take()?),
            len: u32::from_be_bytes(input.take()?),
        },
        4 => Scope::Append {
            log,
            event: Digest(input.take()?),
            body: input.option(|i| Ok(Digest(i.take()?)))?,
            epoch: input.take()?,
            after: input.option(Input::head)?,
            attached: input.option(|i| Ok(Digest(i.take()?)))?,
        },
        5 => Scope::Subscribe { log },
        6 => Scope::ReadControls {
            log,
            after: u64::from_be_bytes(input.take()?),
        },
        7 => Scope::StoreHomeObjects {
            log,
            prefix_digest: Digest(input.take()?),
            bundle_digest: Digest(input.take()?),
        },
        8 => Scope::Presence {
            log,
            epoch: input.take()?,
        },
        9 => Scope::ReadDirectory { log },
        10 => Scope::StoreDirectoryEntry {
            log,
            entry: input.take()?,
            version: u64::from_be_bytes(input.take()?),
            body: Digest(input.take()?),
            len: u32::from_be_bytes(input.take()?),
        },
        11 => Scope::RetireHomeObjects {
            log,
            prefix_digest: Digest(input.take()?),
        },
        14 => Scope::ReadControlRange {
            log,
            after: u64::from_be_bytes(input.take()?),
            through: u64::from_be_bytes(input.take()?),
        },
        _ => return Err(PermitError::Encoding),
    };
    let result = Permit {
        scope,
        issued_ms: u64::from_be_bytes(input.take()?),
        deadline_ms: u64::from_be_bytes(input.take()?),
        batch: input.take()?,
    };
    input.finish()?;
    valid_scope(&result.scope)?;
    Ok(result)
}
/// Certify a short-lived permit signing key under the independently pinned root.
pub fn certify(authority: &SigningKey, permit_public: [u8; 32]) -> [u8; receipt::CERTIFICATE_LEN] {
    let mut bytes = [0; receipt::CERTIFICATE_LEN];
    bytes[..2].copy_from_slice(&VERSION.to_be_bytes());
    bytes[2..34].copy_from_slice(&authority.public());
    bytes[34..66].copy_from_slice(&permit_public);
    let signature = authority.sign(&[CERT_DOMAIN, &bytes[..66]].concat());
    bytes[66..].copy_from_slice(&signature);
    bytes
}
/// Authenticate exactly one permit-key certificate in the permit-key domain,
/// not a receipt certificate or an issued permit.
pub fn verify_certificate(
    root: &[u8; 32],
    encoded: &[u8],
) -> Result<CertifiedPermitKey, PermitError> {
    let bytes: [u8; receipt::CERTIFICATE_LEN] =
        encoded.try_into().map_err(|_| PermitError::Encoding)?;
    if bytes[..2] != VERSION.to_be_bytes() {
        return Err(PermitError::Version);
    }
    if bytes[2..34] != root[..] {
        return Err(PermitError::Certificate);
    }
    verify_signature(
        root,
        &[CERT_DOMAIN, &bytes[..66]].concat(),
        &bytes[66..].try_into().expect("fixed certificate signature"),
    )
    .map_err(|_| PermitError::Certificate)?;
    Ok(CertifiedPermitKey { bytes })
}

/// Sign the exact scope and deadline; the certificate must name `key.public()`.
pub fn sign(
    key: &SigningKey,
    certificate: &[u8; receipt::CERTIFICATE_LEN],
    permit: &Permit,
) -> Vec<u8> {
    let body = encode_permit(permit);
    let mut bytes = Vec::with_capacity(certificate.len() + body.len() + 64);
    bytes.extend(certificate);
    bytes.extend(&body);
    bytes.extend(key.sign(&[SIGN_DOMAIN, &body].concat()));
    bytes
}
/// The issue time a signed permit names, decoded but not authenticated: for
/// a holder to pass as the time to [`verify`] a permit it just received.
pub fn issued_ms(signed: &[u8]) -> Result<u64, PermitError> {
    if signed.len() < receipt::CERTIFICATE_LEN + 64 + 2 || signed.len() > 4096 {
        return Err(PermitError::Encoding);
    }
    decode_permit(&signed[receipt::CERTIFICATE_LEN..signed.len() - 64]).map(|p| p.issued_ms)
}

/// Authenticate a permit against a pinned root and trusted time. Expiry is exclusive.
pub fn verify(root: [u8; 32], signed: &[u8], now_ms: u64) -> Result<Permit, PermitError> {
    // Bound untrusted frames before parsing; the scope decoder separately limits count.
    if signed.len() < receipt::CERTIFICATE_LEN + 64 + 2 || signed.len() > 4096 {
        return Err(PermitError::Encoding);
    }
    let cert = verify_certificate(&root, &signed[..receipt::CERTIFICATE_LEN])?;
    let end = signed.len() - 64;
    let body = &signed[receipt::CERTIFICATE_LEN..end];
    let permit = decode_permit(body)?;
    verify_signature(
        &cert.public_key(),
        &[SIGN_DOMAIN, body].concat(),
        &signed[end..].try_into().expect("fixed signature"),
    )
    .map_err(|_| PermitError::Signature)?;
    if permit
        .deadline_ms
        .checked_sub(permit.issued_ms)
        .is_none_or(|n| n == 0 || n > MAX_PERMIT_WINDOW_MS)
        || now_ms < permit.issued_ms
    {
        return Err(PermitError::Window);
    }
    if now_ms >= permit.deadline_ms {
        return Err(PermitError::Expired);
    }
    Ok(permit)
}
/// Only a validated *ordering statement*. It does not accept the author,
/// advance a chain cursor, bridge a history gap, or authorize any operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofError {
    Encoding,
    Binding,
    Receipt,
}

/// Check a compound reply against an independently pinned hosting root, the
/// expected Base content log and the *exact* descriptor originally sent.
/// Returns its checked commitment, not content or author acceptance.
pub fn verify_published_ordering(
    root: &[u8; 32],
    expected_log: LogId,
    expected_event: &OpaqueEvent,
    ack_bytes: &[u8],
    commitment_bytes: &[u8],
) -> Result<Commitment, ProofError> {
    let ack = AppendAck::decode(ack_bytes).map_err(|_| ProofError::Encoding)?;
    let commitment = Commitment::decode(commitment_bytes).map_err(|_| ProofError::Encoding)?;
    if expected_log.kind != LogKind::Base
        || ack.log != expected_log
        || commitment.base() != BaseId(expected_log.id)
        || commitment.route() != Route::Content
        || ack.event != expected_event.publication_id(Route::Content)
        || commitment.verify_body(expected_event).is_err()
        || commitment
            .verify_next(BaseId(expected_log.id), commitment.previous())
            .is_err()
        || ack.head != commitment.head()
    {
        return Err(ProofError::Binding);
    }
    let signed = ack.receipt.ok_or(ProofError::Receipt)?;
    let verified =
        receipt::verify(root, BaseId(expected_log.id), &signed).map_err(|_| ProofError::Receipt)?;
    if verified.head() != ack.head {
        return Err(ProofError::Receipt);
    }
    Ok(commitment)
}

impl AppendAck {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 33 + 32 + 40 + 1 + receipt::RECEIPT_LEN);
        out.extend(VERSION.to_be_bytes());
        put_log(&mut out, self.log);
        out.extend(self.event.0);
        put_head(&mut out, self.head);
        put_option(&mut out, self.receipt, |out, r| out.extend(r));
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, PermitError> {
        let mut input = Input(bytes);
        input.version()?;
        let result = Self {
            log: input.log()?,
            event: EventId(input.take()?),
            head: input.head()?,
            receipt: input.option(Input::take)?,
        };
        input.finish()?;
        Ok(result)
    }
}
