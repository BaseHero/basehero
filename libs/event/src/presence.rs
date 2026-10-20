//! Ephemeral own-device cursor format; it is not an ordered event or a storage object.
use std::fmt;

use bh_account::DeviceId;
use bh_crypto::{Secret, aead_open, aead_seal, derive_key, hash};

pub const RECORD_LEN: usize = 320;
pub const SEALED_LEN: usize = 393;
const VERSION: u8 = 1;
const AD_DOMAIN: &[u8] = b"bh/presence/v1\0";
const HANDLE_DOMAIN: &[u8] = b"bh/presence-handle/v1\0";

#[derive(Clone, PartialEq, Eq)]
pub struct PresenceRecord {
    /// 1 selection, 2 cleared.
    pub kind: u8,
    pub handle: [u8; 16],
    pub seq: u64,
    /// Index of one of six preset colours (0–5).
    pub colour: u8,
    pub note: [u8; 32],
    /// Yjs v1 relative positions, up to 96 bytes each. The client validates
    /// the referenced writers before sealing and decodes positions on receipt.
    pub anchor: Vec<u8>,
    pub head: Vec<u8>,
    /// UTF-8 device label for the sender's own personal audience only.
    pub label: String,
}

impl fmt::Debug for PresenceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PresenceRecord")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
}

impl PresenceRecord {
    /// Fixed-width lengths, slots and zero padding. All unused bytes, including
    /// the final two, must be zero so no alternate plaintext encoding exists.
    pub fn encode(&self) -> Result<[u8; RECORD_LEN], Error> {
        let label = self.label.as_bytes();
        if !(1..=2).contains(&self.kind)
            || self.colour > 5
            || self.anchor.len() > 96
            || self.head.len() > 96
            || label.len() > 64
        {
            return Err(Error::Invalid);
        }
        let mut out = [0; RECORD_LEN];
        out[0] = VERSION;
        out[1] = self.kind;
        out[2..18].copy_from_slice(&self.handle);
        out[18..26].copy_from_slice(&self.seq.to_be_bytes());
        out[26] = self.colour;
        out[27..59].copy_from_slice(&self.note);
        for (len_at, value) in [
            (59, self.anchor.as_slice()),
            (156, self.head.as_slice()),
            (253, label),
        ] {
            out[len_at] = value.len() as u8;
            out[len_at + 1..len_at + 1 + value.len()].copy_from_slice(value);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != RECORD_LEN
            || bytes[0] != VERSION
            || !(1..=2).contains(&bytes[1])
            || bytes[26] > 5
            || bytes[318..].iter().any(|v| *v != 0)
        {
            return Err(Error::Invalid);
        }
        fn field(bytes: &[u8], len_at: usize, max: usize) -> Result<&[u8], Error> {
            let len = bytes[len_at] as usize;
            if len > max
                || bytes[len_at + 1 + len..len_at + 1 + max]
                    .iter()
                    .any(|v| *v != 0)
            {
                return Err(Error::Invalid);
            }
            Ok(&bytes[len_at + 1..len_at + 1 + len])
        }
        let label = std::str::from_utf8(field(bytes, 253, 64)?).map_err(|_| Error::Invalid)?;
        Ok(Self {
            kind: bytes[1],
            handle: bytes[2..18].try_into().map_err(|_| Error::Invalid)?,
            seq: u64::from_be_bytes(bytes[18..26].try_into().map_err(|_| Error::Invalid)?),
            colour: bytes[26],
            note: bytes[27..59].try_into().map_err(|_| Error::Invalid)?,
            anchor: field(bytes, 59, 96)?.to_vec(),
            head: field(bytes, 156, 96)?.to_vec(),
            label: label.to_owned(),
        })
    }
}

fn ad(base: [u8; 32], audience: [u8; 32], key_id: [u8; 32]) -> Vec<u8> {
    [AD_DOMAIN, &base, &audience, &key_id, &[VERSION]].concat()
}

/// The caller supplies the current audience epoch root and its key ID. The
/// caller checks that these belong together; this codec binds the supplied ID.
pub fn seal(
    key: &Secret<32>,
    base: [u8; 32],
    audience: [u8; 32],
    key_id: [u8; 32],
    record: &PresenceRecord,
) -> Result<Vec<u8>, Error> {
    let plain = record.encode()?;
    let key = derive_key(key, b"bhPres01", 0);
    let (nonce, cipher) =
        aead_seal(&key, &ad(base, audience, key_id), &plain).map_err(|_| Error::Invalid)?;
    let mut out = Vec::with_capacity(SEALED_LEN);
    out.push(VERSION);
    out.extend(key_id);
    out.extend(nonce);
    out.extend(cipher);
    debug_assert_eq!(out.len(), SEALED_LEN);
    Ok(out)
}

/// Rejects malformed lengths and a wrong epoch before decrypting.
pub fn open(
    key: &Secret<32>,
    base: [u8; 32],
    audience: [u8; 32],
    key_id: [u8; 32],
    frame: &[u8],
) -> Result<PresenceRecord, Error> {
    if frame.len() != SEALED_LEN || frame[0] != VERSION || frame[1..33] != key_id {
        return Err(Error::Invalid);
    }
    let nonce = frame[33..57].try_into().map_err(|_| Error::Invalid)?;
    let key = derive_key(key, b"bhPres01", 0);
    let plain = aead_open(&key, nonce, &ad(base, audience, key_id), &frame[57..])
        .map_err(|_| Error::Invalid)?;
    PresenceRecord::decode(plain.expose())
}

/// Stable for one device and epoch without disclosing its device or writer ID.
pub fn handle(key: &Secret<32>, device: DeviceId) -> [u8; 16] {
    let subkey = derive_key(key, b"bhPrsId1", 0);
    let digest = hash(&[HANDLE_DOMAIN, subkey.expose(), &device.0].concat());
    digest[..16].try_into().expect("fixed hash length")
}
