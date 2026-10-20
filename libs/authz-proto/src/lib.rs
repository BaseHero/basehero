//! Messages between devices and the authorization service, carried one per
//! record inside the attested channel, the deterministic wrapping of original
//! account events into account-home log events, and the padded body of a
//! personal-key delivery an account control carries.
//!
//! All integers are big-endian. Every message is `version:u16 = 1 || tag:u8 ||
//! fields`; byte strings are `length:u32 || bytes`, lists `count:u16 || items`
//! and options `0 | 1 || value`. Decoders refuse other versions, unknown tags,
//! truncation, trailing bytes and out-of-bounds lists. One message is at most
//! one channel record, 65,536 bytes.
#![forbid(unsafe_code)]

use std::fmt;

use bh_account::{
    AccountId, DeviceId, DevicePublicKeys, Head as AccountHead, device_auth::PROOF_LEN,
};
use bh_crypto::Secret;
use bh_sync::{
    BaseId, BodyObject, Commitment, Digest, EventId, Head, OpaqueEvent, receipt::RECEIPT_LEN,
};

pub use bh_sync::permit::{LogId, LogKind};

const VERSION: u16 = 1;
const READ_BATCH_VERSION: u16 = 2;
const READ_BATCH_TAG: u8 = 33;
/// Largest log position representable exactly by the hosted edge transport.
pub const MAX_SAFE_POSITION: u64 = (1 << 53) - 1;
const MAX_BATCH_PERMIT: usize = 4096;
/// The largest message: one channel record's plaintext.
pub const MAX_MESSAGE: usize = 65_536;
/// Permit requests in one `Permits` message.
pub const MAX_ITEMS: usize = 64;
/// Positions in one ReadEvents and bodies in one ReadBodies request.
pub const MAX_READ: u64 = 64;
/// Bodies named across one `Permits` message, so its answer fits one record.
pub const MAX_BODIES: usize = 1024;
/// The epoch every account-home log carries: account events are controls.
pub const ACCOUNT_EPOCH: [u8; 32] = [0; 32];

/// What a device asks a permit for. An append carries its exact event bytes,
/// so the service derives the body the event references instead of trusting a
/// claimed digest.
#[derive(Clone, PartialEq, Eq)]
pub enum Want {
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
        event: Vec<u8>,
        epoch: [u8; 32],
    },
    Subscribe {
        log: LogId,
    },
    Presence {
        log: LogId,
        epoch: [u8; 32],
    },
    ReadBatch {
        log: LogId,
        after: Head,
        max_events: u16,
    },
}

/// A base's metadata root M, which the service needs for one request to verify
/// the base's genesis or a base control. It travels only inside the attested
/// channel, in a wiped allocation, and is never stored or shown.
pub struct MetadataKey(Secret<32>);
impl MetadataKey {
    pub fn new(key: &Secret<32>) -> Self {
        Self(Secret::from_slice(key.expose()).expect("fixed width"))
    }
    pub fn expose(&self) -> &Secret<32> {
        &self.0
    }
}
impl Clone for MetadataKey {
    fn clone(&self) -> Self {
        Self::new(&self.0)
    }
}
impl PartialEq for MetadataKey {
    fn eq(&self, other: &Self) -> bool {
        bh_crypto::constant_time_eq(self.0.expose(), other.0.expose())
    }
}
impl Eq for MetadataKey {}
impl fmt::Debug for MetadataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MetadataKey(..)")
    }
}

/// The signed personal-key delivery an AddDevice control carries, and the
/// public keys of the device it adds, which the frame must be sealed to.
#[derive(Clone, PartialEq, Eq)]
pub struct Delivery {
    pub recipient: DevicePublicKeys,
    pub frame: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
pub enum ToService {
    /// Exact encrypted initial signup objects. The authenticated account, not
    /// caller routing, selects their home. Success means a durable home write.
    StoreHomeObjects {
        prefix: AccountHead,
        record: Vec<u8>,
        device_seal: Vec<u8>,
        recovery_seal: Vec<u8>,
    },
    /// Possession of `device`'s ordinary key, over the session's channel
    /// binding and the service's challenge, at an account head the service has
    /// verified. `genesis` is the account's original genesis: it names the
    /// account's log and is checked against `account`.
    Authenticate {
        proof: Box<[u8; PROOF_LEN]>,
        account: AccountId,
        device: DeviceId,
        genesis: Vec<u8>,
    },
    /// 1-64 permit requests, answered in order.
    Permits {
        items: Vec<Want>,
    },
    /// One original account event for the session's account log, checked
    /// against the account's current verified history before an append permit.
    /// A device addition may carry the personal-key delivery to the added
    /// device, which is then staged and ordered as the event's body.
    SubmitControl {
        log: LogId,
        event: Vec<u8>,
        delivery: Option<Box<Delivery>>,
    },
    /// Registers a base the session's account created: its exact genesis
    /// descriptor (an encoded log event) and body, the creator account head
    /// the genesis names, and its metadata root M to verify it with. Answers
    /// the permits to stage that body and append that genesis first.
    RegisterBase {
        descriptor: Vec<u8>,
        body: Vec<u8>,
        creator_head: AccountHead,
        metadata: MetadataKey,
    },
    /// One control for a base the session's account owns: its exact
    /// descriptor (an encoded log event) and body, and the base's metadata
    /// root M to verify it with. Answers the permits to stage that body and
    /// append that control after the base's control head.
    SubmitBaseControl {
        log: LogId,
        descriptor: Vec<u8>,
        body: Vec<u8>,
        metadata: MetadataKey,
    },
    ReadBatch {
        want: Want,
    },
}

// A selected reply carries the fixed signed receipt inline; avoid a second
// heap allocation on every reply solely to make the small variants smaller.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq)]
pub enum FromService {
    /// Durable immutable storage of the canonical bundle at this signup prefix.
    /// Match both fields to the retained originals. Home setup also requires
    /// independently verifying the public prefix's ordering, not just this reply.
    HomeObjectsStored {
        prefix: AccountHead,
        digest: [u8; 32],
    },
    /// The session's single-use authentication challenge, sent first.
    Challenge { challenge: [u8; 32] },
    /// The account head the service verified for this session.
    Authenticated { account_head: AccountHead },
    /// Signed permits, or a refusal, in request order.
    Permits {
        items: Vec<Result<Vec<u8>, Refusal>>,
    },
    /// The whole request was refused.
    Refused { reason: Refusal },
    /// Current authority could not be established; nothing was issued.
    Unavailable,
    /// Committed descriptors on the attested channel; bodies stay on the edge.
    ReadBatch {
        log: LogId,
        after: Head,
        issued_ms: u64,
        deadline_ms: u64,
        result: ReadBatchResult,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq)]
pub enum ReadBatchResult {
    Selected {
        items: Vec<(Vec<u8>, Vec<u8>)>,
        receipt: Option<[u8; RECEIPT_LEN]>,
        body_permit: Option<Vec<u8>>,
        possibly_more: bool,
    },
    Repair {
        events_permit: Vec<u8>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Refusal {
    Malformed = 1,
    /// No authenticated device on this session, or the proof did not verify.
    Unauthenticated,
    /// The device is not active in the account at its current head.
    NotActive,
    /// The log is not the session account's log or one of its bases.
    Unknown,
    /// An append's epoch is not the base's current epoch.
    Epoch,
    /// The control does not verify against the account's current history.
    Invalid,
    /// The base is registered to another account, or the log has moved on.
    Conflict,
    Unsupported,
    /// The account has changes the base has not copied yet; copy them first.
    AccountChangePending,
    /// The service does not know the base's latest controls; send
    /// `RegisterBase` with M, then retry.
    Resync,
}
const REFUSALS: [Refusal; 10] = [
    Refusal::Malformed,
    Refusal::Unauthenticated,
    Refusal::NotActive,
    Refusal::Unknown,
    Refusal::Epoch,
    Refusal::Invalid,
    Refusal::Conflict,
    Refusal::Unsupported,
    Refusal::AccountChangePending,
    Refusal::Resync,
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    Encoding,
    Version,
    Size,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

impl fmt::Debug for Want {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReadEvents { .. } => "ReadEvents",
            Self::ReadBodies { .. } => "ReadBodies",
            Self::Stage { .. } => "Stage",
            Self::Append { .. } => "Append",
            Self::Subscribe { .. } => "Subscribe",
            Self::Presence { .. } => "Presence",
            Self::ReadBatch { .. } => "ReadBatch",
        })
    }
}
impl fmt::Debug for ToService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Authenticate { .. } => "Authenticate",
            Self::Permits { .. } => "Permits",
            Self::SubmitControl { .. } => "SubmitControl",
            Self::RegisterBase { .. } => "RegisterBase",
            Self::SubmitBaseControl { .. } => "SubmitBaseControl",
            Self::StoreHomeObjects { .. } => "StoreHomeObjects",
            Self::ReadBatch { .. } => "ReadBatch",
        })
    }
}
impl fmt::Debug for FromService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Challenge { .. } => f.write_str("Challenge"),
            Self::Authenticated { .. } => f.write_str("Authenticated"),
            Self::Permits { items } => f
                .debug_struct("Permits")
                .field("items", &items.len())
                .finish(),
            Self::Refused { reason } => f.debug_struct("Refused").field("reason", reason).finish(),
            Self::Unavailable => f.write_str("Unavailable"),
            Self::HomeObjectsStored { .. } => f.write_str("HomeObjectsStored"),
            Self::ReadBatch { result, .. } => f.write_str(match result {
                ReadBatchResult::Selected { .. } => "ReadBatch(Selected)",
                ReadBatchResult::Repair { .. } => "ReadBatch(Repair)",
            }),
        }
    }
}

struct Output(Vec<u8>);
impl Output {
    fn new(tag: u8) -> Self {
        Self::with_capacity(tag, 0)
    }
    /// Reserved up front, so a message carrying a key is never reallocated
    /// and copied while it is built.
    fn with_capacity(tag: u8, capacity: usize) -> Self {
        Self::versioned(VERSION, tag, capacity)
    }
    fn versioned(version: u16, tag: u8, capacity: usize) -> Self {
        let mut out = Vec::with_capacity(3 + capacity);
        out.extend(version.to_be_bytes());
        out.push(tag);
        Self(out)
    }
    fn bytes(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
    fn blob(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let len = u32::try_from(bytes.len()).map_err(|_| Error::Size)?;
        self.bytes(&len.to_be_bytes());
        self.bytes(bytes);
        Ok(())
    }
    fn count(&mut self, n: usize) -> Result<(), Error> {
        self.bytes(&u16::try_from(n).map_err(|_| Error::Size)?.to_be_bytes());
        Ok(())
    }
    fn log(&mut self, log: LogId) {
        self.0.push(log.kind as u8);
        self.bytes(&log.id);
    }
    fn head(&mut self, head: Head) {
        self.bytes(&head.position.to_be_bytes());
        self.bytes(&head.hash.0);
    }
    fn finish(self) -> Result<Vec<u8>, Error> {
        if self.0.len() > MAX_MESSAGE {
            return Err(Error::Size);
        }
        Ok(self.0)
    }
}

struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(Error::Encoding)?;
        self.0 = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn blob(&mut self) -> Result<Vec<u8>, Error> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }
    fn keys(&mut self) -> Result<DevicePublicKeys, Error> {
        DevicePublicKeys::new(self.array()?, self.array()?, self.array()?)
            .map_err(|_| Error::Encoding)
    }
    fn cursor(&mut self) -> Result<Head, Error> {
        Ok(Head {
            position: self.u64()?,
            hash: Digest(self.array()?),
        })
    }
    fn head(&mut self) -> Result<AccountHead, Error> {
        Ok(AccountHead {
            position: self.u64()?,
            hash: self.array()?,
        })
    }
    fn log(&mut self) -> Result<LogId, Error> {
        let kind = match self.u8()? {
            1 => LogKind::Base,
            2 => LogKind::Account,
            _ => return Err(Error::Encoding),
        };
        Ok(LogId {
            kind,
            id: self.array()?,
        })
    }
    fn option<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        match self.u8()? {
            0 => Ok(None),
            1 => read(self).map(Some),
            _ => Err(Error::Encoding),
        }
    }
    fn start(bytes: &'a [u8]) -> Result<(Self, u16, u8), Error> {
        if bytes.len() > MAX_MESSAGE {
            return Err(Error::Size);
        }
        let mut input = Self(bytes);
        let version = input.u16()?;
        if version != VERSION && version != READ_BATCH_VERSION {
            return Err(Error::Version);
        }
        let tag = input.u8()?;
        if version == READ_BATCH_VERSION && tag != READ_BATCH_TAG {
            return Err(Error::Version);
        }
        if version == VERSION && tag == READ_BATCH_TAG {
            return Err(Error::Encoding);
        }
        Ok((input, version, tag))
    }
    fn finish(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Encoding)
        }
    }
}

fn check_items(items: &[Want]) -> Result<(), Error> {
    if !(1..=MAX_ITEMS).contains(&items.len()) {
        return Err(Error::Size);
    }
    let mut bodies = 0;
    for item in items {
        match item {
            Want::ReadEvents { first, last, .. }
                if *first == 0 || last.checked_sub(*first).is_none_or(|n| n >= MAX_READ) =>
            {
                return Err(Error::Size);
            }
            Want::ReadBatch { .. } => return Err(Error::Encoding),
            Want::ReadBodies { bodies: list, .. } => {
                if list.is_empty() || list.len() as u64 > MAX_READ {
                    return Err(Error::Size);
                }
                bodies += list.len();
            }
            _ => {}
        }
    }
    if bodies > MAX_BODIES {
        return Err(Error::Size);
    }
    Ok(())
}

fn check_batch(after: Head, max_events: u16) -> Result<(), Error> {
    if !(1..=MAX_READ as u16).contains(&max_events)
        || after
            .position
            .checked_add(u64::from(max_events))
            .is_none_or(|p| p > MAX_SAFE_POSITION)
        || (after.position == 0 && after.hash != Head::EMPTY.hash)
    {
        return Err(Error::Size);
    }
    Ok(())
}

impl ToService {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out;
        match self {
            Self::ReadBatch {
                want:
                    Want::ReadBatch {
                        log,
                        after,
                        max_events,
                    },
            } => {
                check_batch(*after, *max_events)?;
                out = Output::versioned(READ_BATCH_VERSION, READ_BATCH_TAG, 76);
                out.bytes(&[7]);
                out.log(*log);
                out.head(*after);
                out.bytes(&max_events.to_be_bytes());
            }
            Self::ReadBatch { .. } => return Err(Error::Encoding),
            Self::StoreHomeObjects {
                prefix,
                record,
                device_seal,
                recovery_seal,
            } => {
                let bundle = bh_sync::home_objects::encode(record, device_seal, recovery_seal)
                    .map_err(|_| Error::Encoding)?;
                out = Output::new(6);
                out.bytes(&prefix.position.to_be_bytes());
                out.bytes(&prefix.hash);
                out.blob(&bundle)?;
            }
            Self::Authenticate {
                proof,
                account,
                device,
                genesis,
            } => {
                out = Output::new(1);
                out.bytes(proof.as_slice());
                out.bytes(&account.0);
                out.bytes(&device.0);
                out.blob(genesis)?;
            }
            Self::Permits { items } => {
                check_items(items)?;
                out = Output::new(2);
                out.count(items.len())?;
                for item in items {
                    match item {
                        Want::ReadEvents { log, first, last } => {
                            out.bytes(&[1]);
                            out.log(*log);
                            out.bytes(&first.to_be_bytes());
                            out.bytes(&last.to_be_bytes());
                        }
                        Want::ReadBodies { log, bodies } => {
                            out.bytes(&[2]);
                            out.log(*log);
                            out.count(bodies.len())?;
                            for body in bodies {
                                out.bytes(&body.0);
                            }
                        }
                        Want::Stage { log, body, len } => {
                            out.bytes(&[3]);
                            out.log(*log);
                            out.bytes(&body.0);
                            out.bytes(&len.to_be_bytes());
                        }
                        Want::Append { log, event, epoch } => {
                            out.bytes(&[4]);
                            out.log(*log);
                            out.blob(event)?;
                            out.bytes(epoch);
                        }
                        Want::Subscribe { log } => {
                            out.bytes(&[5]);
                            out.log(*log);
                        }
                        Want::Presence { log, epoch } => {
                            out.bytes(&[6]);
                            out.log(*log);
                            out.bytes(epoch);
                        }
                        Want::ReadBatch { .. } => return Err(Error::Encoding),
                    }
                }
            }
            Self::SubmitControl {
                log,
                event,
                delivery,
            } => {
                out = Output::new(3);
                out.log(*log);
                out.blob(event)?;
                match delivery {
                    None => out.bytes(&[0]),
                    Some(delivery) => {
                        let Delivery { recipient, frame } = delivery.as_ref();
                        out.bytes(&[1]);
                        out.bytes(recipient.signing());
                        out.bytes(recipient.control());
                        out.bytes(recipient.receiving());
                        out.blob(frame)?;
                    }
                }
            }
            Self::RegisterBase {
                descriptor,
                body,
                creator_head,
                metadata,
            } => {
                let size = 8 + descriptor.len() + body.len() + 40 + 32;
                if size > MAX_MESSAGE {
                    return Err(Error::Size);
                }
                out = Output::with_capacity(4, size);
                out.blob(descriptor)?;
                out.blob(body)?;
                out.bytes(&creator_head.position.to_be_bytes());
                out.bytes(&creator_head.hash);
                out.bytes(metadata.0.expose());
            }
            Self::SubmitBaseControl {
                log,
                descriptor,
                body,
                metadata,
            } => {
                let size = 33 + 8 + descriptor.len() + body.len() + 32;
                if size > MAX_MESSAGE {
                    return Err(Error::Size);
                }
                out = Output::with_capacity(5, size);
                out.log(*log);
                out.blob(descriptor)?;
                out.blob(body)?;
                out.bytes(metadata.0.expose());
            }
        }
        out.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (mut input, version, tag) = Input::start(bytes)?;
        let message = match tag {
            READ_BATCH_TAG if version == READ_BATCH_VERSION => {
                if input.u8()? != 7 {
                    return Err(Error::Encoding);
                }
                let log = input.log()?;
                let after = input.cursor()?;
                let max_events = input.u16()?;
                check_batch(after, max_events)?;
                Self::ReadBatch {
                    want: Want::ReadBatch {
                        log,
                        after,
                        max_events,
                    },
                }
            }
            6 => {
                let prefix = input.head()?;
                let bytes = input.blob()?;
                let bundle =
                    bh_sync::home_objects::Bundle::decode(&bytes).map_err(|_| Error::Encoding)?;
                Self::StoreHomeObjects {
                    prefix,
                    record: bundle.record.to_vec(),
                    device_seal: bundle.device_seal.to_vec(),
                    recovery_seal: bundle.recovery_seal.to_vec(),
                }
            }
            1 => Self::Authenticate {
                proof: Box::new(input.array()?),
                account: AccountId(input.array()?),
                device: DeviceId(input.array()?),
                genesis: input.blob()?,
            },
            2 => {
                let count = input.u16()? as usize;
                if !(1..=MAX_ITEMS).contains(&count) {
                    return Err(Error::Size);
                }
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(match input.u8()? {
                        1 => Want::ReadEvents {
                            log: input.log()?,
                            first: input.u64()?,
                            last: input.u64()?,
                        },
                        2 => {
                            let log = input.log()?;
                            let n = input.u16()? as usize;
                            if !(1..=MAX_READ as usize).contains(&n) {
                                return Err(Error::Size);
                            }
                            let mut bodies = Vec::with_capacity(n);
                            for _ in 0..n {
                                bodies.push(Digest(input.array()?));
                            }
                            Want::ReadBodies { log, bodies }
                        }
                        3 => Want::Stage {
                            log: input.log()?,
                            body: Digest(input.array()?),
                            len: input.u32()?,
                        },
                        4 => Want::Append {
                            log: input.log()?,
                            event: input.blob()?,
                            epoch: input.array()?,
                        },
                        5 => Want::Subscribe { log: input.log()? },
                        6 => Want::Presence {
                            log: input.log()?,
                            epoch: input.array()?,
                        },
                        _ => return Err(Error::Encoding),
                    });
                }
                check_items(&items)?;
                Self::Permits { items }
            }
            3 => Self::SubmitControl {
                log: input.log()?,
                event: input.blob()?,
                delivery: input.option(|input| {
                    Ok(Box::new(Delivery {
                        recipient: input.keys()?,
                        frame: input.blob()?,
                    }))
                })?,
            },
            4 => Self::RegisterBase {
                descriptor: input.blob()?,
                body: input.blob()?,
                creator_head: input.head()?,
                // Straight from the (wiped) record plaintext into a wiped key.
                metadata: MetadataKey(
                    Secret::from_slice(input.take(32)?).map_err(|_| Error::Encoding)?,
                ),
            },
            5 => Self::SubmitBaseControl {
                log: input.log()?,
                descriptor: input.blob()?,
                body: input.blob()?,
                metadata: MetadataKey(
                    Secret::from_slice(input.take(32)?).map_err(|_| Error::Encoding)?,
                ),
            },
            _ => return Err(Error::Encoding),
        };
        input.finish()?;
        Ok(message)
    }
}

impl FromService {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out;
        match self {
            Self::Challenge { challenge } => {
                out = Output::new(1);
                out.bytes(challenge);
            }
            Self::Authenticated { account_head } => {
                out = Output::new(2);
                out.bytes(&account_head.position.to_be_bytes());
                out.bytes(&account_head.hash);
            }
            Self::Permits { items } => {
                if items.len() > MAX_ITEMS {
                    return Err(Error::Size);
                }
                out = Output::new(3);
                out.count(items.len())?;
                for item in items {
                    match item {
                        Ok(permit) => {
                            out.bytes(&[0]);
                            out.blob(permit)?;
                        }
                        Err(reason) => out.bytes(&[1, *reason as u8]),
                    }
                }
            }
            Self::Refused { reason } => {
                out = Output::new(4);
                out.bytes(&[*reason as u8]);
            }
            Self::Unavailable => out = Output::new(5),
            Self::HomeObjectsStored { prefix, digest } => {
                out = Output::new(6);
                out.bytes(&prefix.position.to_be_bytes());
                out.bytes(&prefix.hash);
                out.bytes(digest);
            }
            Self::ReadBatch {
                log,
                after,
                issued_ms,
                deadline_ms,
                result,
            } => {
                if *issued_ms >= *deadline_ms || *deadline_ms - *issued_ms > 30_000 {
                    return Err(Error::Size);
                }
                out = Output::versioned(READ_BATCH_VERSION, READ_BATCH_TAG, 0);
                out.log(*log);
                out.head(*after);
                out.bytes(&issued_ms.to_be_bytes());
                out.bytes(&deadline_ms.to_be_bytes());
                match result {
                    ReadBatchResult::Selected {
                        items,
                        receipt,
                        body_permit,
                        possibly_more,
                    } => {
                        if items.len() > MAX_READ as usize
                            || (items.is_empty()
                                && (receipt.is_some() || body_permit.is_some() || *possibly_more))
                            || (log.kind == LogKind::Base && !items.is_empty() && receipt.is_none())
                            || (log.kind == LogKind::Account && receipt.is_some())
                            || body_permit
                                .as_ref()
                                .is_some_and(|p| p.len() > MAX_BATCH_PERMIT)
                        {
                            return Err(Error::Size);
                        }
                        // Bound the reply before copying any descriptor into a
                        // second allocation. Oversized pages become Repair.
                        let fixed = out.0.len()
                            + 1
                            + 2
                            + 1
                            + 1
                            + 1
                            + receipt.as_ref().map_or(0, |_| RECEIPT_LEN)
                            + body_permit.as_ref().map_or(0, |p| 4 + p.len());
                        let size = items
                            .iter()
                            .try_fold(fixed, |size, (c, d)| {
                                size.checked_add(8)?
                                    .checked_add(c.len())?
                                    .checked_add(d.len())
                            })
                            .ok_or(Error::Size)?;
                        if size > MAX_MESSAGE {
                            return Err(Error::Size);
                        }
                        out.bytes(&[0]);
                        out.count(items.len())?;
                        for (commitment, descriptor) in items {
                            if commitment.len() != Commitment::LEN
                                || OpaqueEvent::decode(descriptor).is_err()
                            {
                                return Err(Error::Encoding);
                            }
                            out.blob(commitment)?;
                            out.blob(descriptor)?;
                        }
                        out.bytes(&[u8::from(receipt.is_some())]);
                        if let Some(receipt) = receipt {
                            out.bytes(receipt);
                        }
                        out.bytes(&[u8::from(body_permit.is_some())]);
                        if let Some(permit) = body_permit {
                            out.blob(permit)?;
                        }
                        out.bytes(&[u8::from(*possibly_more)]);
                    }
                    ReadBatchResult::Repair { events_permit } => {
                        if events_permit.len() > MAX_BATCH_PERMIT {
                            return Err(Error::Size);
                        }
                        out.bytes(&[1]);
                        out.blob(events_permit)?;
                    }
                }
            }
        }
        out.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (mut input, version, tag) = Input::start(bytes)?;
        let refusal = |input: &mut Input<'_>| {
            let code = input.u8()?;
            REFUSALS
                .into_iter()
                .find(|r| *r as u8 == code)
                .ok_or(Error::Encoding)
        };
        let message = match tag {
            READ_BATCH_TAG if version == READ_BATCH_VERSION => {
                let log = input.log()?;
                let after = input.cursor()?;
                if after.position > MAX_SAFE_POSITION
                    || (after.position == 0 && after.hash != Head::EMPTY.hash)
                {
                    return Err(Error::Size);
                }
                let issued_ms = input.u64()?;
                let deadline_ms = input.u64()?;
                if issued_ms >= deadline_ms || deadline_ms - issued_ms > 30_000 {
                    return Err(Error::Size);
                }
                let result = match input.u8()? {
                    0 => {
                        let count = input.u16()? as usize;
                        if count > MAX_READ as usize {
                            return Err(Error::Size);
                        }
                        let mut items = Vec::with_capacity(count);
                        for _ in 0..count {
                            let commitment = input.blob()?;
                            let descriptor = input.blob()?;
                            if commitment.len() != Commitment::LEN
                                || OpaqueEvent::decode(&descriptor).is_err()
                            {
                                return Err(Error::Encoding);
                            }
                            items.push((commitment, descriptor));
                        }
                        let receipt = input.option(|i| i.array::<RECEIPT_LEN>())?;
                        let body_permit = input.option(|i| i.blob())?;
                        if body_permit
                            .as_ref()
                            .is_some_and(|p| p.len() > MAX_BATCH_PERMIT)
                        {
                            return Err(Error::Size);
                        }
                        let possibly_more = match input.u8()? {
                            0 => false,
                            1 => true,
                            _ => return Err(Error::Encoding),
                        };
                        if (count == 0
                            && (receipt.is_some() || body_permit.is_some() || possibly_more))
                            || (log.kind == LogKind::Base && count > 0 && receipt.is_none())
                            || (log.kind == LogKind::Account && receipt.is_some())
                        {
                            return Err(Error::Encoding);
                        }
                        ReadBatchResult::Selected {
                            items,
                            receipt,
                            body_permit,
                            possibly_more,
                        }
                    }
                    1 => {
                        let events_permit = input.blob()?;
                        if events_permit.len() > MAX_BATCH_PERMIT {
                            return Err(Error::Size);
                        }
                        ReadBatchResult::Repair { events_permit }
                    }
                    _ => return Err(Error::Encoding),
                };
                Self::ReadBatch {
                    log,
                    after,
                    issued_ms,
                    deadline_ms,
                    result,
                }
            }
            1 => Self::Challenge {
                challenge: input.array()?,
            },
            2 => Self::Authenticated {
                account_head: input.head()?,
            },
            3 => {
                let count = input.u16()? as usize;
                if count > MAX_ITEMS {
                    return Err(Error::Size);
                }
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(match input.u8()? {
                        0 => Ok(input.blob()?),
                        1 => Err(refusal(&mut input)?),
                        _ => return Err(Error::Encoding),
                    });
                }
                Self::Permits { items }
            }
            4 => Self::Refused {
                reason: refusal(&mut input)?,
            },
            5 => Self::Unavailable,
            6 => Self::HomeObjectsStored {
                prefix: input.head()?,
                digest: input.array()?,
            },
            _ => return Err(Error::Encoding),
        };
        input.finish()?;
        Ok(message)
    }
}

/// An original account event or delivery frame that cannot be wrapped or
/// unwrapped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WrapError {
    /// Empty, or too large for the largest envelope or body.
    Size,
    /// Not exactly the canonical wrapping of its contents.
    Encoding,
}
impl fmt::Display for WrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for WrapError {}

const ACCOUNT_EVENT_DOMAIN: &[u8] = b"bh/account-log-event/v2\0";
/// The ordered log's envelope size classes, smallest first.
const ENVELOPE_SIZES: &[usize] = &bh_sync::ENVELOPE_SIZES;
/// Body object size classes, smallest first.
const BODY_SIZES: &[usize] = &bh_sync::BODY_SIZES;
/// Commitment and length ahead of the original in a wrapped account event.
const WRAP_HEADER: usize = 32 + 4;

fn smallest(sizes: &[usize], len: usize) -> Result<usize, WrapError> {
    sizes
        .iter()
        .copied()
        .find(|size| len <= *size)
        .ok_or(WrapError::Size)
}

/// The account-home log event carrying one original account event and the
/// commitment of the body it carries, if any. The envelope is `body:32 ||
/// length:u32 || original || zeros` in the smallest envelope size that fits,
/// with `body` all zeros for none, so the log object's body reference (the
/// first 32 envelope bytes) is the carried body. The event id is
/// `H("bh/account-log-event/v2\0" || body:32 || length:u32 || original)`, so
/// the same original with another body is another event.
pub fn account_log_wrap(original: &[u8], body: Option<Digest>) -> Result<OpaqueEvent, WrapError> {
    if original.is_empty() {
        return Err(WrapError::Size);
    }
    let commitment = match body {
        // All zeros means none, so it is never a body's commitment.
        Some(Digest(commitment)) if commitment == [0; 32] => return Err(WrapError::Encoding),
        Some(Digest(commitment)) => commitment,
        None => [0; 32],
    };
    let len = u32::try_from(original.len()).map_err(|_| WrapError::Size)?;
    let size = smallest(ENVELOPE_SIZES, WRAP_HEADER + original.len())?;
    let mut envelope = Vec::with_capacity(size);
    envelope.extend(commitment);
    envelope.extend(len.to_be_bytes());
    envelope.extend_from_slice(original);
    let id = EventId(bh_crypto::hash(
        &[ACCOUNT_EVENT_DOMAIN, envelope.as_slice()].concat(),
    ));
    envelope.resize(size, 0);
    OpaqueEvent::new(id, envelope).map_err(|_| WrapError::Size)
}

/// The original account event inside `event` and the body it carries, only if
/// `event` is exactly their canonical wrapping.
pub fn account_log_unwrap(event: &OpaqueEvent) -> Result<(&[u8], Option<Digest>), WrapError> {
    let envelope = event.envelope();
    let header = envelope.get(..WRAP_HEADER).ok_or(WrapError::Encoding)?;
    let commitment: [u8; 32] = header[..32].try_into().map_err(|_| WrapError::Encoding)?;
    let len =
        u32::from_be_bytes(header[32..].try_into().map_err(|_| WrapError::Encoding)?) as usize;
    let original = envelope
        .get(WRAP_HEADER..WRAP_HEADER + len)
        .ok_or(WrapError::Encoding)?;
    let body = (commitment != [0; 32]).then_some(Digest(commitment));
    if account_log_wrap(original, body).map_err(|_| WrapError::Encoding)? != *event {
        return Err(WrapError::Encoding);
    }
    Ok((original, body))
}

/// The account-home log of the account whose original genesis is given: the
/// digest of its wrapped genesis, which carries no body.
pub fn account_log_id(genesis_original: &[u8]) -> Result<[u8; 32], WrapError> {
    Ok(BaseId::from_genesis(&account_log_wrap(genesis_original, None)?).0)
}

/// The purpose byte of a personal-key delivery body.
const DELIVERY_PURPOSE: u8 = 1;
const DELIVERY_HEADER: usize = 1 + 4;

/// The body object carrying a signed personal-key delivery frame: `purpose:u8
/// = 1 || length:u32 || frame || zeros` in the smallest body size that fits.
pub fn delivery_body(frame: &[u8]) -> Result<BodyObject, WrapError> {
    if frame.is_empty() {
        return Err(WrapError::Size);
    }
    let len = u32::try_from(frame.len()).map_err(|_| WrapError::Size)?;
    let size = smallest(BODY_SIZES, DELIVERY_HEADER + frame.len())?;
    let mut bytes = Vec::with_capacity(size);
    bytes.push(DELIVERY_PURPOSE);
    bytes.extend(len.to_be_bytes());
    bytes.extend_from_slice(frame);
    bytes.resize(size, 0);
    BodyObject::new(bytes).map_err(|_| WrapError::Size)
}

/// The delivery frame inside a body, only if `body` is exactly its canonical
/// delivery body.
pub fn delivery_frame(body: &[u8]) -> Result<&[u8], WrapError> {
    let header = body.get(..DELIVERY_HEADER).ok_or(WrapError::Encoding)?;
    if header[0] != DELIVERY_PURPOSE {
        return Err(WrapError::Encoding);
    }
    let len = u32::from_be_bytes(header[1..].try_into().map_err(|_| WrapError::Encoding)?) as usize;
    let frame = body
        .get(DELIVERY_HEADER..DELIVERY_HEADER + len)
        .ok_or(WrapError::Encoding)?;
    if delivery_body(frame)
        .map_err(|_| WrapError::Encoding)?
        .bytes()
        != body
    {
        return Err(WrapError::Encoding);
    }
    Ok(frame)
}
