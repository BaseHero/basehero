//! Canonical transport identity of private initial-signup ciphertext objects.
//! This digest is NOT a replacement for their signed account commitments.
//! Encoding: big-endian version:u16 = 1, then record, device seal, recovery seal,
//! each as length:u32 || exact bytes (242, 1299, 1299). Total: 2854 bytes.
//! No padding, omitted slots or trailing bytes; no recovery retrieval authority.
use crate::Digest;

pub const RECORD_LEN: usize = 242;
pub const SEAL_LEN: usize = 1299;
pub const BUNDLE_LEN: usize = 2 + 3 * 4 + RECORD_LEN + 2 * SEAL_LEN;
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error;
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid home object bundle")
    }
}
impl std::error::Error for Error {}

/// Borrowed ciphertext, deliberately without Debug.
pub struct Bundle<'a> {
    pub record: &'a [u8],
    pub device_seal: &'a [u8],
    pub recovery_seal: &'a [u8],
}
impl<'a> Bundle<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() != BUNDLE_LEN || bytes[..2] != VERSION.to_be_bytes() {
            return Err(Error);
        }
        let mut remaining = &bytes[2..];
        fn field<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], Error> {
            let (size, rest) = input.split_at_checked(4).ok_or(Error)?;
            if u32::from_be_bytes(size.try_into().map_err(|_| Error)?) as usize != length {
                return Err(Error);
            }
            let (bytes, rest) = rest.split_at_checked(length).ok_or(Error)?;
            *input = rest;
            Ok(bytes)
        }
        let result = Self {
            record: field(&mut remaining, RECORD_LEN)?,
            device_seal: field(&mut remaining, SEAL_LEN)?,
            recovery_seal: field(&mut remaining, SEAL_LEN)?,
        };
        if !remaining.is_empty() {
            return Err(Error);
        }
        Ok(result)
    }
}

pub fn encode(record: &[u8], device_seal: &[u8], recovery_seal: &[u8]) -> Result<Vec<u8>, Error> {
    if record.len() != RECORD_LEN
        || device_seal.len() != SEAL_LEN
        || recovery_seal.len() != SEAL_LEN
    {
        return Err(Error);
    }
    let mut bytes = Vec::with_capacity(BUNDLE_LEN);
    bytes.extend(VERSION.to_be_bytes());
    for object in [record, device_seal, recovery_seal] {
        bytes.extend((object.len() as u32).to_be_bytes());
        bytes.extend(object);
    }
    Ok(bytes)
}

/// Validate the canonical encoding before hashing, preventing padding aliases.
pub fn digest(bundle: &[u8]) -> Result<Digest, Error> {
    Bundle::decode(bundle)?;
    Ok(crate::log::hash(b"bh/home-objects/v1\0", &[bundle]))
}
