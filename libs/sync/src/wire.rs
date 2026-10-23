//! One versioned, bounded binary frame per WebSocket message. Transport framing
//! authenticates nothing: consumers verify the permit and original event bytes.
use std::fmt;

use crate::{Commitment, Digest, Head, OrderState, receipt::RECEIPT_LEN};

pub const MAX_FRAME_LEN: usize = 4 * 1024 * 1024 + 64 * 1024;
/// Maximum length of one opaque sealed presence frame.
pub const MAX_PRESENCE: usize = 512;
const PRESENCE_JOIN_TAG: u8 = 33;
const PRESENCE_REQUEST_TAG: u8 = 34;
const PRESENCE_RESPONSE_TAG: u8 = 35;
const PEERS_TAG: u8 = 36;
const DIRECTORY_READ_TAG: u8 = 37;
const DIRECTORY_STORE_TAG: u8 = 38;
const HOME_RETIRE_TAG: u8 = 39;
const DIRECTORY_MAX_BODY: usize = 65536;
/// Data transport version; independent of the opaque event framing version.
const VERSION: u16 = 3;
const COMPOUND_TAG: u8 = 32;

#[derive(Clone, PartialEq, Eq)]
pub enum Request {
    ReadDirectory {
        id: u32,
        permit: Vec<u8>,
        after: Option<[u8; 32]>,
    },
    StoreDirectoryEntry {
        id: u32,
        permit: Vec<u8>,
        body: Vec<u8>,
    },
    RetireHomeObjects {
        id: u32,
        permit: Vec<u8>,
    },
    StoreHomeObjects {
        id: u32,
        permit: Vec<u8>,
        bundle: Vec<u8>,
    },
    Read {
        id: u32,
        permit: Vec<u8>,
    },
    Stage {
        id: u32,
        permit: Vec<u8>,
        body: Vec<u8>,
    },
    Append {
        id: u32,
        permit: Vec<u8>,
        event: Vec<u8>,
    },
    /// Version 3/tag 32: four length-prefixed blobs in field order. Both
    /// existing grants bind the immutable descriptor and body separately.
    Publish {
        id: u32,
        stage_permit: Vec<u8>,
        append_permit: Vec<u8>,
        event: Vec<u8>,
        body: Vec<u8>,
    },
    Subscribe {
        id: u32,
        permit: Vec<u8>,
        after: u64,
    },
    /// Grants the edge `bytes` more send window on this socket. It answers no
    /// request, so its frame's request id is always 0.
    Credit {
        bytes: u32,
    },
    PresenceJoin {
        id: u32,
        permit: Vec<u8>,
    },
    Presence {
        id: u32,
        sealed: Vec<u8>,
    },
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CoverageEndpoint {
    pub order: OrderState,
    /// None only for the genuinely empty log.
    pub receipt: Option<[u8; RECEIPT_LEN]>,
}

// Keep the fixed receipt inline (336-byte enum) rather than allocating for
// every bounded read. DataSocket queues encoded frames, not these enums.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq)]
pub enum Response {
    Directory {
        id: u32,
        entries: Vec<Vec<u8>>,
        more: bool,
    },
    DirectoryEntryStored {
        id: u32,
    },
    HomeObjectsRetired {
        id: u32,
    },
    HomeObjectsStored {
        id: u32,
        prefix_digest: Digest,
        bundle_digest: Digest,
    },
    Events {
        id: u32,
        items: Vec<(Vec<u8>, Vec<u8>)>,
        /// Hosting receipt for the exact last returned base commitment, not
        /// content acceptance. None for empty reads and account logs.
        /// Encoding: after count, flag 0/1 and exactly RECEIPT_LEN bytes if 1,
        /// then the count's commitment/descriptor pairs.
        receipt: Option<[u8; RECEIPT_LEN]>,
        /// Distinct sparse endpoint. Absent on full and account reads.
        coverage: Option<CoverageEndpoint>,
    },
    Body {
        id: u32,
        index: u8,
        last: bool,
        bytes: Vec<u8>,
    },
    Staged {
        id: u32,
    },
    Acked {
        id: u32,
        ack: Vec<u8>,
    },
    /// Version 3/tag 32: one length-prefixed AppendAck, then exactly
    /// 149 canonical commitment bytes. Ordering proof, not author acceptance.
    Published {
        id: u32,
        ack: Vec<u8>,
        commitment: Vec<u8>,
    },
    Head {
        id: u32,
        head: Head,
        receipt: Option<Vec<u8>>,
    },
    Refused {
        id: u32,
        reason: Refusal,
    },
    Presence {
        id: u32,
        from: u32,
        sealed: Vec<u8>,
    },
    Peers {
        id: u32,
        others: u16,
        /// 0 snapshot, 1 joined, 2 left.
        event: u8,
        slot: u32,
    },
}
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, id) = match self {
            Self::Read { id, .. } => ("Read", id),
            Self::ReadDirectory { id, .. } => ("ReadDirectory", id),
            Self::StoreDirectoryEntry { id, .. } => ("StoreDirectoryEntry", id),
            Self::RetireHomeObjects { id, .. } => ("RetireHomeObjects", id),
            Self::StoreHomeObjects { id, .. } => ("StoreHomeObjects", id),
            Self::Stage { id, .. } => ("Stage", id),
            Self::Append { id, .. } => ("Append", id),
            Self::Publish { id, .. } => ("Publish", id),
            Self::Subscribe { id, .. } => ("Subscribe", id),
            Self::PresenceJoin { id, .. } => ("PresenceJoin", id),
            Self::Presence { id, .. } => ("Presence", id),
            Self::Credit { bytes } => {
                return f.debug_struct("Credit").field("bytes", bytes).finish();
            }
        };
        f.debug_struct(name).field("id", id).finish_non_exhaustive()
    }
}
impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, id) = match self {
            Self::Events { id, .. } => ("Events", id),
            Self::Directory { id, .. } => ("Directory", id),
            Self::DirectoryEntryStored { id } => ("DirectoryEntryStored", id),
            Self::HomeObjectsRetired { id } => ("HomeObjectsRetired", id),
            Self::HomeObjectsStored { id, .. } => ("HomeObjectsStored", id),
            Self::Body { id, .. } => ("Body", id),
            Self::Staged { id } => ("Staged", id),
            Self::Acked { id, .. } => ("Acked", id),
            Self::Published { id, .. } => ("Published", id),
            Self::Head { id, .. } => ("Head", id),
            Self::Refused { id, .. } => ("Refused", id),
            Self::Presence { id, .. } => ("Presence", id),
            Self::Peers { id, .. } => ("Peers", id),
        };
        f.debug_struct(name).field("id", id).finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Refusal {
    Expired = 1,
    Scope,
    Epoch,
    Predecessor,
    Conflict,
    NotStaged,
    Reclaiming,
    Missing,
    Malformed,
    Unavailable,
}
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

struct Input<'a>(&'a [u8]);
impl Input<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], Error> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(Error::Encoding)?;
        self.0 = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    fn blob(&mut self) -> Result<Vec<u8>, Error> {
        self.bounded_blob(MAX_FRAME_LEN)
    }
    fn bounded_blob(&mut self, max: usize) -> Result<Vec<u8>, Error> {
        let n = u32::from_be_bytes(self.array()?) as usize;
        if n > max {
            return Err(Error::Size);
        }
        Ok(self.take(n)?.to_vec())
    }
    fn head(&mut self) -> Result<Head, Error> {
        Ok(Head {
            position: u64::from_be_bytes(self.array()?),
            hash: Digest(self.array()?),
        })
    }
    fn finish(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Encoding)
        }
    }
}
fn header(tag: u8, id: u32, capacity: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(capacity);
    out.extend(VERSION.to_be_bytes());
    out.push(tag);
    out.extend(id.to_be_bytes());
    out
}
fn checked_size(current: usize, additional: usize) -> Result<usize, Error> {
    let size = current.checked_add(additional).ok_or(Error::Size)?;
    if size > MAX_FRAME_LEN {
        return Err(Error::Size);
    }
    Ok(size)
}
fn checked_blob(current: usize, bytes: &[u8]) -> Result<usize, Error> {
    u32::try_from(bytes.len()).map_err(|_| Error::Size)?;
    checked_size(checked_size(current, 4)?, bytes.len())
}
fn blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend((bytes.len() as u32).to_be_bytes());
    out.extend(bytes);
}
fn head(out: &mut Vec<u8>, value: Head) {
    out.extend(value.position.to_be_bytes());
    out.extend(value.hash.0);
}
fn decode_header(bytes: &[u8]) -> Result<(u8, u32, Input<'_>), Error> {
    if bytes.len() > MAX_FRAME_LEN {
        return Err(Error::Size);
    }
    let mut input = Input(bytes);
    let version = u16::from_be_bytes(input.array()?);
    let tag = input.array::<1>()?[0];
    if version != VERSION || !matches!(tag, 1..=7 | COMPOUND_TAG..=HOME_RETIRE_TAG) {
        return Err(Error::Version);
    }
    let id = u32::from_be_bytes(input.array()?);
    Ok((tag, id, input))
}
impl Request {
    /// Check the entire frame length without copying any of its payloads.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        let permit = match self {
            Self::Read { permit, .. }
            | Self::ReadDirectory { permit, .. }
            | Self::StoreDirectoryEntry { permit, .. }
            | Self::RetireHomeObjects { permit, .. }
            | Self::Stage { permit, .. }
            | Self::Append { permit, .. }
            | Self::Subscribe { permit, .. }
            | Self::StoreHomeObjects { permit, .. }
            | Self::PresenceJoin { permit, .. } => permit,
            Self::Presence { sealed, .. } => {
                if sealed.len() > MAX_PRESENCE {
                    return Err(Error::Size);
                }
                return checked_blob(7, sealed);
            }
            Self::Publish {
                stage_permit,
                append_permit,
                event,
                body,
                ..
            } => {
                let size = checked_blob(7, stage_permit)?;
                let size = checked_blob(size, append_permit)?;
                let size = checked_blob(size, event)?;
                return checked_blob(size, body);
            }
            Self::Credit { bytes: 0 } => return Err(Error::Encoding),
            Self::Credit { .. } => return Ok(11),
        };
        let size = checked_blob(7, permit)?;
        match self {
            Self::Read { .. }
            | Self::RetireHomeObjects { .. }
            | Self::Credit { .. }
            | Self::Publish { .. }
            | Self::PresenceJoin { .. }
            | Self::Presence { .. } => Ok(size),
            Self::ReadDirectory { after, .. } => {
                checked_size(size, 1 + if after.is_some() { 32 } else { 0 })
            }
            Self::StoreDirectoryEntry { body, .. } if body.len() <= DIRECTORY_MAX_BODY => {
                checked_blob(size, body)
            }
            Self::StoreDirectoryEntry { .. } => Err(Error::Size),
            Self::Stage { body, .. } => checked_blob(size, body),
            Self::Append { event, .. } => checked_blob(size, event),
            Self::Subscribe { .. } => checked_size(size, 8),
            Self::StoreHomeObjects { bundle, .. } => {
                crate::home_objects::Bundle::decode(bundle).map_err(|_| Error::Encoding)?;
                checked_blob(size, bundle)
            }
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let length = self.encoded_len()?;
        let (tag, id, permit) = match self {
            Self::Read { id, permit } => (1, *id, permit),
            Self::ReadDirectory { id, permit, .. } => (DIRECTORY_READ_TAG, *id, permit),
            Self::StoreDirectoryEntry { id, permit, .. } => (DIRECTORY_STORE_TAG, *id, permit),
            Self::RetireHomeObjects { id, permit } => (HOME_RETIRE_TAG, *id, permit),
            Self::Stage { id, permit, .. } => (2, *id, permit),
            Self::Append { id, permit, .. } => (3, *id, permit),
            Self::Subscribe { id, permit, .. } => (4, *id, permit),
            Self::StoreHomeObjects { id, permit, .. } => (6, *id, permit),
            Self::PresenceJoin { id, permit } => (PRESENCE_JOIN_TAG, *id, permit),
            Self::Publish {
                id,
                stage_permit,
                append_permit,
                event,
                body,
            } => {
                let mut out = header(COMPOUND_TAG, *id, length);
                for part in [stage_permit, append_permit, event, body] {
                    blob(&mut out, part);
                }
                return Ok(out);
            }
            Self::Presence { id, sealed } => {
                let mut out = header(PRESENCE_REQUEST_TAG, *id, length);
                blob(&mut out, sealed);
                return Ok(out);
            }
            Self::Credit { bytes } => {
                let mut out = header(5, 0, length);
                out.extend(bytes.to_be_bytes());
                return Ok(out);
            }
        };
        let mut out = header(tag, id, length);
        blob(&mut out, permit);
        match self {
            Self::ReadDirectory { after, .. } => {
                out.push(u8::from(after.is_some()));
                if let Some(after) = after {
                    out.extend(after);
                }
            }
            Self::StoreDirectoryEntry { body, .. } => blob(&mut out, body),
            Self::Stage { body, .. } => blob(&mut out, body),
            Self::StoreHomeObjects { bundle, .. } => blob(&mut out, bundle),
            Self::Append { event, .. } => blob(&mut out, event),
            Self::Subscribe { after, .. } => out.extend(after.to_be_bytes()),
            Self::Read { .. }
            | Self::RetireHomeObjects { .. }
            | Self::Credit { .. }
            | Self::Publish { .. }
            | Self::PresenceJoin { .. }
            | Self::Presence { .. } => {}
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (tag, id, mut input) = decode_header(bytes)?;
        if tag == PRESENCE_REQUEST_TAG {
            let result = Self::Presence {
                id,
                sealed: input.bounded_blob(MAX_PRESENCE)?,
            };
            input.finish()?;
            return Ok(result);
        }
        if tag == COMPOUND_TAG {
            let result = Self::Publish {
                id,
                stage_permit: input.blob()?,
                append_permit: input.blob()?,
                event: input.blob()?,
                body: input.blob()?,
            };
            input.finish()?;
            return Ok(result);
        }
        if tag == 5 {
            let bytes = u32::from_be_bytes(input.array()?);
            if id != 0 || bytes == 0 {
                return Err(Error::Encoding);
            }
            input.finish()?;
            return Ok(Self::Credit { bytes });
        }
        let permit = input.blob()?;
        let result = match tag {
            1 => Self::Read { id, permit },
            DIRECTORY_READ_TAG => Self::ReadDirectory {
                id,
                permit,
                after: match input.array::<1>()?[0] {
                    0 => None,
                    1 => Some(input.array()?),
                    _ => return Err(Error::Encoding),
                },
            },
            DIRECTORY_STORE_TAG => Self::StoreDirectoryEntry {
                id,
                permit,
                body: input.bounded_blob(DIRECTORY_MAX_BODY)?,
            },
            HOME_RETIRE_TAG => Self::RetireHomeObjects { id, permit },
            PRESENCE_JOIN_TAG => Self::PresenceJoin { id, permit },
            2 => Self::Stage {
                id,
                permit,
                body: input.blob()?,
            },
            3 => Self::Append {
                id,
                permit,
                event: input.blob()?,
            },
            4 => Self::Subscribe {
                id,
                permit,
                after: u64::from_be_bytes(input.array()?),
            },
            6 => {
                let bundle = input.blob()?;
                crate::home_objects::Bundle::decode(&bundle).map_err(|_| Error::Encoding)?;
                Self::StoreHomeObjects { id, permit, bundle }
            }
            _ => return Err(Error::Encoding),
        };
        input.finish()?;
        Ok(result)
    }
}
impl Response {
    /// Preflight every field before allocating or copying any payload.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        match self {
            Self::Directory { entries, .. } => {
                if entries.len() > 64 {
                    return Err(Error::Size);
                }
                let mut size = 10;
                for entry in entries {
                    if entry.len() > DIRECTORY_MAX_BODY {
                        return Err(Error::Size);
                    }
                    size = checked_blob(size, entry)?;
                }
                Ok(size)
            }
            Self::DirectoryEntryStored { .. } | Self::HomeObjectsRetired { .. } => Ok(7),
            Self::Events {
                items,
                receipt,
                coverage,
                ..
            } => {
                if items.len() > 64 {
                    return Err(Error::Size);
                }
                if receipt.is_some() && (items.is_empty() || coverage.is_some()) {
                    return Err(Error::Encoding);
                }
                let endpoint_len = match coverage {
                    None => 0,
                    Some(endpoint)
                        if endpoint.order == OrderState::EMPTY && endpoint.receipt.is_none() =>
                    {
                        OrderState::LEN
                    }
                    Some(endpoint)
                        if endpoint.order != OrderState::EMPTY && endpoint.receipt.is_some() =>
                    {
                        OrderState::LEN + RECEIPT_LEN
                    }
                    _ => return Err(Error::Encoding),
                };
                let mut size = checked_size(
                    7 + 2 + 1 + 1,
                    if receipt.is_some() { RECEIPT_LEN } else { 0 } + endpoint_len,
                )?;
                for (commitment, event) in items {
                    if commitment.len() != Commitment::LEN {
                        return Err(Error::Encoding);
                    }
                    size = checked_blob(size, commitment)?;
                    size = checked_blob(size, event)?;
                }
                Ok(size)
            }
            Self::Body { index, bytes, .. } => {
                if *index > 63 {
                    return Err(Error::Encoding);
                }
                checked_blob(checked_size(7, 2)?, bytes)
            }
            Self::Staged { .. } => Ok(7),
            Self::HomeObjectsStored { .. } => Ok(71),
            Self::Acked { ack, .. } => checked_blob(7, ack),
            Self::Published {
                ack, commitment, ..
            } => {
                if commitment.len() != Commitment::LEN {
                    return Err(Error::Encoding);
                }
                checked_size(checked_blob(7, ack)?, Commitment::LEN)
            }
            Self::Head { receipt, .. } => {
                let size = checked_size(7, 41)?;
                receipt
                    .as_ref()
                    .map_or(Ok(size), |receipt| checked_blob(size, receipt))
            }
            Self::Refused { .. } => Ok(8),
            Self::Presence { sealed, .. } => {
                if sealed.len() > MAX_PRESENCE {
                    return Err(Error::Size);
                }
                checked_blob(11, sealed)
            }
            Self::Peers { event, .. } => {
                if *event > 2 {
                    return Err(Error::Encoding);
                }
                Ok(14)
            }
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let length = self.encoded_len()?;
        let (tag, id) = match self {
            Self::Events { id, .. } => (1, *id),
            Self::Directory { id, .. } => (DIRECTORY_READ_TAG, *id),
            Self::DirectoryEntryStored { id } => (DIRECTORY_STORE_TAG, *id),
            Self::HomeObjectsRetired { id } => (HOME_RETIRE_TAG, *id),
            Self::Body { id, .. } => (2, *id),
            Self::Staged { id } => (3, *id),
            Self::Acked { id, .. } => (4, *id),
            Self::Published { id, .. } => (COMPOUND_TAG, *id),
            Self::Head { id, .. } => (5, *id),
            Self::Refused { id, .. } => (6, *id),
            Self::HomeObjectsStored { id, .. } => (7, *id),
            Self::Presence { id, .. } => (PRESENCE_RESPONSE_TAG, *id),
            Self::Peers { id, .. } => (PEERS_TAG, *id),
        };
        let mut out = header(tag, id, length);
        match self {
            Self::Directory { entries, more, .. } => {
                out.extend((entries.len() as u16).to_be_bytes());
                out.push(u8::from(*more));
                for entry in entries {
                    blob(&mut out, entry);
                }
            }
            Self::DirectoryEntryStored { .. } | Self::HomeObjectsRetired { .. } => {}
            Self::Events {
                items,
                receipt,
                coverage,
                ..
            } => {
                out.extend((items.len() as u16).to_be_bytes());
                out.push(u8::from(receipt.is_some()));
                if let Some(receipt) = receipt {
                    out.extend(receipt);
                }
                match coverage {
                    None => out.push(0),
                    Some(endpoint) => {
                        out.push(if endpoint.receipt.is_some() { 2 } else { 1 });
                        out.extend(endpoint.order.encode());
                        if let Some(receipt) = endpoint.receipt {
                            out.extend(receipt);
                        }
                    }
                }
                for (commitment, event) in items {
                    blob(&mut out, commitment);
                    blob(&mut out, event);
                }
            }
            Self::Body {
                index, last, bytes, ..
            } => {
                out.push(*index);
                out.push(u8::from(*last));
                blob(&mut out, bytes);
            }
            Self::Staged { .. } => {}
            Self::HomeObjectsStored {
                prefix_digest,
                bundle_digest,
                ..
            } => {
                out.extend(prefix_digest.0);
                out.extend(bundle_digest.0);
            }
            Self::Acked { ack, .. } => blob(&mut out, ack),
            Self::Published {
                ack, commitment, ..
            } => {
                blob(&mut out, ack);
                out.extend(commitment);
            }
            Self::Head {
                head: value,
                receipt,
                ..
            } => {
                head(&mut out, *value);
                if let Some(receipt) = receipt {
                    out.push(1);
                    blob(&mut out, receipt);
                } else {
                    out.push(0);
                }
            }
            Self::Refused { reason, .. } => out.push(*reason as u8),
            Self::Presence { from, sealed, .. } => {
                out.extend(from.to_be_bytes());
                blob(&mut out, sealed);
            }
            Self::Peers {
                others,
                event,
                slot,
                ..
            } => {
                out.extend(others.to_be_bytes());
                out.push(*event);
                out.extend(slot.to_be_bytes());
            }
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (tag, id, mut input) = decode_header(bytes)?;
        let result = match tag {
            DIRECTORY_READ_TAG => {
                let count = u16::from_be_bytes(input.array()?) as usize;
                if count > 64 {
                    return Err(Error::Size);
                }
                let more = match input.array::<1>()?[0] {
                    0 => false,
                    1 => true,
                    _ => return Err(Error::Encoding),
                };
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    entries.push(input.bounded_blob(DIRECTORY_MAX_BODY)?);
                }
                Self::Directory { id, entries, more }
            }
            DIRECTORY_STORE_TAG => Self::DirectoryEntryStored { id },
            HOME_RETIRE_TAG => Self::HomeObjectsRetired { id },
            1 => {
                let count = u16::from_be_bytes(input.array()?) as usize;
                if count > 64 {
                    return Err(Error::Size);
                }
                let receipt = match input.array::<1>()?[0] {
                    0 => None,
                    1 => Some(input.array()?),
                    _ => return Err(Error::Encoding),
                };
                let coverage_tag = input.array::<1>()?[0];
                let coverage = match coverage_tag {
                    0 => None,
                    1 | 2 => {
                        let order = OrderState::decode(input.take(OrderState::LEN)?)
                            .map_err(|_| Error::Encoding)?;
                        let receipt = if coverage_tag == 2 {
                            Some(input.array()?)
                        } else {
                            None
                        };
                        Some(CoverageEndpoint { order, receipt })
                    }
                    _ => return Err(Error::Encoding),
                };
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    let commitment = input.blob()?;
                    if commitment.len() != Commitment::LEN {
                        return Err(Error::Encoding);
                    }
                    items.push((commitment, input.blob()?));
                }
                let result = Self::Events {
                    id,
                    items,
                    receipt,
                    coverage,
                };
                result.encoded_len()?;
                result
            }
            2 => {
                let index = input.array::<1>()?[0];
                if index > 63 {
                    return Err(Error::Encoding);
                }
                let last = match input.array::<1>()?[0] {
                    0 => false,
                    1 => true,
                    _ => return Err(Error::Encoding),
                };
                Self::Body {
                    id,
                    index,
                    last,
                    bytes: input.blob()?,
                }
            }
            3 => Self::Staged { id },
            4 => Self::Acked {
                id,
                ack: input.blob()?,
            },
            COMPOUND_TAG => Self::Published {
                id,
                ack: input.blob()?,
                commitment: input.take(Commitment::LEN)?.to_vec(),
            },
            5 => {
                let head = input.head()?;
                let receipt = match input.array::<1>()?[0] {
                    0 => None,
                    1 => Some(input.blob()?),
                    _ => return Err(Error::Encoding),
                };
                Self::Head { id, head, receipt }
            }
            6 => {
                let reason = match input.array::<1>()?[0] {
                    1 => Refusal::Expired,
                    2 => Refusal::Scope,
                    3 => Refusal::Epoch,
                    4 => Refusal::Predecessor,
                    5 => Refusal::Conflict,
                    6 => Refusal::NotStaged,
                    7 => Refusal::Reclaiming,
                    8 => Refusal::Missing,
                    9 => Refusal::Malformed,
                    10 => Refusal::Unavailable,
                    _ => return Err(Error::Encoding),
                };
                Self::Refused { id, reason }
            }
            7 => Self::HomeObjectsStored {
                id,
                prefix_digest: Digest(input.array()?),
                bundle_digest: Digest(input.array()?),
            },
            PRESENCE_RESPONSE_TAG => Self::Presence {
                id,
                from: u32::from_be_bytes(input.array()?),
                sealed: input.bounded_blob(MAX_PRESENCE)?,
            },
            PEERS_TAG => {
                let others = u16::from_be_bytes(input.array()?);
                let event = input.array::<1>()?[0];
                if event > 2 {
                    return Err(Error::Encoding);
                }
                Self::Peers {
                    id,
                    others,
                    event,
                    slot: u32::from_be_bytes(input.array()?),
                }
            }
            _ => return Err(Error::Encoding),
        };
        input.finish()?;
        Ok(result)
    }
}
