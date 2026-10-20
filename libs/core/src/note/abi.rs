//! The note engine's result encoding, shared by the engine and the host.
//! Each export returns [`OK`] with its result in the output buffer, or
//! [`ERR`] with an encoded error there. The host trusts none of it: anything
//! it cannot decode exactly makes the engine unavailable.

use super::{IncomingRefusal, NoteError, WriterError, WriterPrefix};
use yrs::encoding::read::Error as ReadError;

pub const OK: i32 = 0;
pub const ERR: i32 = 1;

/// What the host asks of a new instance's note.
pub const READER: i32 = 0;
pub const WRITER: i32 = 1;

pub fn note_error(error: &NoteError, out: &mut Vec<u8>) {
    match error {
        NoteError::Unavailable | NoteError::Decode(ReadError::NotEnoughMemory(_)) => out.push(0),
        NoteError::Decode(e) => {
            out.push(1);
            match e {
                ReadError::InvalidVarInt => out.push(0),
                ReadError::EndOfBuffer(n) => {
                    out.push(1);
                    out.extend_from_slice(&(*n as u64).to_le_bytes());
                }
                ReadError::UnexpectedValue => out.push(2),
                // JSON, type and custom details cross only as text.
                other => {
                    out.push(3);
                    out.extend_from_slice(other.to_string().as_bytes());
                }
            }
        }
        NoteError::Apply(yrs::error::UpdateError::InvalidParent(id, kind)) => {
            out.push(2);
            out.extend_from_slice(&id.client.get().to_le_bytes());
            out.extend_from_slice(&id.clock.to_le_bytes());
            out.push(*kind);
        }
    }
}

pub fn read_note_error(bytes: &[u8]) -> Option<NoteError> {
    let (&tag, rest) = bytes.split_first()?;
    Some(match (tag, rest) {
        (0, []) => NoteError::Unavailable,
        (1, [0]) => NoteError::Decode(ReadError::InvalidVarInt),
        (1, [1, n @ ..]) => {
            let n = u64::from_le_bytes(n.try_into().ok()?);
            NoteError::Decode(ReadError::EndOfBuffer(usize::try_from(n).ok()?))
        }
        (1, [2]) => NoteError::Decode(ReadError::UnexpectedValue),
        (1, [3, text @ ..]) => {
            NoteError::Decode(ReadError::Custom(String::from_utf8(text.to_vec()).ok()?))
        }
        (2, [rest @ .., kind]) if rest.len() == 12 => {
            let client = u64::from_le_bytes(rest[..8].try_into().ok()?);
            if client >= 1 << 53 {
                return None;
            }
            let clock = u32::from_le_bytes(rest[8..].try_into().ok()?);
            let id = yrs::ID::new(yrs::ClientID::new(client), clock);
            NoteError::Apply(yrs::error::UpdateError::InvalidParent(id, *kind))
        }
        _ => return None,
    })
}

pub fn writer_error(error: &WriterError, out: &mut Vec<u8>) {
    match error {
        WriterError::InvalidWriter => out.push(10),
        WriterError::Exhausted => out.push(11),
        WriterError::TooLarge => out.push(12),
        WriterError::Update(e) => {
            out.push(13);
            note_error(e, out);
        }
    }
}

pub fn read_writer_error(bytes: &[u8]) -> Option<WriterError> {
    Some(match bytes.split_first()? {
        (10, []) => WriterError::InvalidWriter,
        (11, []) => WriterError::Exhausted,
        (12, []) => WriterError::TooLarge,
        (13, rest) => WriterError::Update(read_note_error(rest)?),
        _ => return None,
    })
}

const REFUSALS: [IncomingRefusal; 6] = [
    IncomingRefusal::ForeignWriter,
    IncomingRefusal::NotContinuous,
    IncomingRefusal::Duplicate,
    IncomingRefusal::MissingDependency,
    IncomingRefusal::Undecodable,
    IncomingRefusal::ApplyFailed,
];

pub fn refusal(reason: IncomingRefusal, changed: bool, out: &mut Vec<u8>) {
    let code = REFUSALS.iter().position(|r| *r == reason).expect("listed");
    out.extend_from_slice(&[code as u8, u8::from(changed)]);
}

pub fn read_refusal(bytes: &[u8]) -> Option<(IncomingRefusal, bool)> {
    match bytes {
        [code, changed @ (0 | 1)] => Some((*REFUSALS.get(usize::from(*code))?, *changed == 1)),
        _ => None,
    }
}

pub fn prefix(prefix: WriterPrefix, out: &mut Vec<u8>) {
    match prefix {
        WriterPrefix::Ready(end) => {
            out.push(0);
            out.extend_from_slice(&end.to_le_bytes());
        }
        WriterPrefix::Pending => out.push(1),
        WriterPrefix::Incomplete => out.push(2),
    }
}

pub fn read_prefix(bytes: &[u8]) -> Option<WriterPrefix> {
    match bytes.split_first()? {
        (0, end) => Some(WriterPrefix::Ready(u32::from_le_bytes(
            end.try_into().ok()?,
        ))),
        (1, []) => Some(WriterPrefix::Pending),
        (2, []) => Some(WriterPrefix::Incomplete),
        _ => None,
    }
}

pub fn read_bool(bytes: &[u8]) -> Option<bool> {
    match bytes {
        [0] => Some(false),
        [1] => Some(true),
        _ => None,
    }
}

/// `u32 len || bytes`, little-endian, for each part of a compound input.
pub fn framed(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| 4 + p.len()).sum());
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// The parts [`framed`] wrote, exactly.
pub fn unframed(mut bytes: &[u8]) -> Option<Vec<&[u8]>> {
    let mut parts = Vec::new();
    while !bytes.is_empty() {
        let (len, rest) = bytes.split_at_checked(4)?;
        let len = u32::from_le_bytes(len.try_into().ok()?) as usize;
        let (part, rest) = rest.split_at_checked(len)?;
        parts.push(part);
        bytes = rest;
    }
    Some(parts)
}

/// A verification result: rebuilds spent, then whether it verified, then for
/// a compaction its encoded [`super::OrderedState`].
pub fn rebuilt(rebuilds: usize, found: Option<&[u8]>, out: &mut Vec<u8>) {
    out.extend_from_slice(&(rebuilds as u32).to_le_bytes());
    match found {
        None => out.push(0),
        Some(state) => {
            out.push(1);
            out.extend_from_slice(state);
        }
    }
}

pub fn read_rebuilt(bytes: &[u8]) -> Option<(usize, Option<&[u8]>)> {
    let (count, rest) = bytes.split_at_checked(4)?;
    let count = u32::from_le_bytes(count.try_into().ok()?) as usize;
    match rest.split_first()? {
        (0, []) => Some((count, None)),
        (1, state) => Some((count, Some(state))),
        _ => None,
    }
}
