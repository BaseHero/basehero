//! Device-local re-sealing of base roots to this account's accepted personal
//! key. Never exported: base-key packages on the wire stay signed base-key
//! frames; this unsigned frame only keeps held roots at rest.
use crate::crypto::{self, Secret};
use crate::personal::{self, PersonalKey};
use crate::{AccountId, Error};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LocalKeyPurpose {
    Metadata = 1,
    Content = 2,
}
impl TryFrom<i64> for LocalKeyPurpose {
    type Error = Error;
    fn try_from(value: i64) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Metadata),
            2 => Ok(Self::Content),
            _ => Err(Error::Malformed),
        }
    }
}

/// Everything one sealed root is bound to. `key_id` is the root's committed id.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LocalKeyContext {
    pub account: AccountId,
    pub base: [u8; 32],
    pub purpose: LocalKeyPurpose,
    pub key_id: [u8; 32],
}

const PREFIX: &[u8; 8] = b"BHLKEY01";
const DOMAIN: &[u8] = b"BH local base key seal v1\0";
const KDF: &[u8; 8] = b"BHLKSE01";
const HEADER_LEN: usize = 8 + 2 + 1 + 4 * 32;
pub const FRAME_LEN: usize = HEADER_LEN + 1120 + 24 + 48;

// Prefix, version, purpose, account, personal-key id, base, key id.
fn header(context: &LocalKeyContext, personal: &[u8; 1216]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_LEN);
    out.extend(PREFIX);
    out.extend(1u16.to_be_bytes());
    out.push(context.purpose as u8);
    out.extend(context.account.0);
    out.extend(personal::id(personal));
    out.extend(context.base);
    out.extend(context.key_id);
    out
}

fn seal_frame(
    context: &LocalKeyContext,
    recipient: &[u8; 1216],
    root: &Secret<32>,
) -> Result<Vec<u8>, Error> {
    let mut frame = header(context, recipient);
    let (kem, shared) = crypto::encapsulate(recipient).map_err(|_| Error::CryptoFailure)?;
    let key = crypto::derive_key(&shared, KDF, context.purpose as u64);
    let (nonce, ciphertext) = crypto::aead_seal(&key, &[DOMAIN, &frame].concat(), root.expose())
        .map_err(|_| Error::CryptoFailure)?;
    frame.extend(kem);
    frame.extend(nonce);
    frame.extend(ciphertext);
    debug_assert_eq!(frame.len(), FRAME_LEN);
    Ok(frame)
}

/// Seal `root` to the personal key `recipient`, only under its committed id.
pub fn seal(
    context: &LocalKeyContext,
    recipient: &[u8; 1216],
    root: &Secret<32>,
) -> Result<Vec<u8>, Error> {
    if crypto::committed_key_id(root) != context.key_id {
        return Err(Error::InvalidCredentials);
    }
    seal_frame(context, recipient, root)
}

/// Open a frame bound to exactly `context` and `personal`, then re-derive the
/// root's committed id: a root is never accepted for an id it does not commit to.
pub fn open(
    context: &LocalKeyContext,
    personal: &PersonalKey,
    frame: &[u8],
) -> Result<Secret<32>, Error> {
    let header = header(context, &personal.public());
    if frame.len() != FRAME_LEN {
        return Err(Error::Malformed);
    }
    if frame[..HEADER_LEN] != header {
        return Err(Error::InvalidCredentials);
    }
    let kem = frame[HEADER_LEN..HEADER_LEN + 1120]
        .try_into()
        .map_err(|_| Error::Malformed)?;
    let nonce = frame[HEADER_LEN + 1120..HEADER_LEN + 1144]
        .try_into()
        .map_err(|_| Error::Malformed)?;
    let shared = personal.decapsulate(&kem)?;
    let key = crypto::derive_key(&shared, KDF, context.purpose as u64);
    let plaintext = crypto::aead_open(
        &key,
        &nonce,
        &[DOMAIN, &header].concat(),
        &frame[HEADER_LEN + 1144..],
    )
    .map_err(|_| Error::InvalidCredentials)?;
    let root = Secret::from_slice(plaintext.expose()).map_err(|_| Error::Malformed)?;
    if !crypto::constant_time_eq(&crypto::committed_key_id(&root), &context.key_id) {
        return Err(Error::InvalidCredentials);
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::committed_key_id;

    #[test]
    fn local_key_seal_checks_every_context_and_rederived_key_id() {
        let personal = PersonalKey::generate();
        let root = Secret::<32>::random();
        let context = LocalKeyContext {
            account: AccountId([1; 32]),
            base: [2; 32],
            purpose: LocalKeyPurpose::Content,
            key_id: committed_key_id(&root),
        };
        let frame = seal(&context, &personal.public(), &root).unwrap();
        assert_eq!(frame.len(), FRAME_LEN);
        assert_eq!(
            open(&context, &personal, &frame).unwrap().expose(),
            root.expose()
        );
        // Each bound field, and the personal key, is part of what opens it.
        for changed in [
            LocalKeyContext {
                account: AccountId([9; 32]),
                ..context
            },
            LocalKeyContext {
                base: [9; 32],
                ..context
            },
            LocalKeyContext {
                purpose: LocalKeyPurpose::Metadata,
                ..context
            },
            LocalKeyContext {
                key_id: [9; 32],
                ..context
            },
        ] {
            assert!(open(&changed, &personal, &frame).is_err());
        }
        assert!(open(&context, &PersonalKey::generate(), &frame).is_err());
        for offset in [0, 10, 11, 43, 75, 107, 139, FRAME_LEN - 1] {
            let mut altered = frame.clone();
            altered[offset] ^= 1;
            assert!(open(&context, &personal, &altered).is_err(), "{offset}");
        }
        assert!(open(&context, &personal, &frame[..FRAME_LEN - 1]).is_err());
        // A root whose committed id is not the bound one never seals...
        let other = Secret::<32>::random();
        assert!(seal(&context, &personal.public(), &other).is_err());
        // ...and opening re-derives the id, even for an authentic frame.
        let unchecked = seal_frame(&context, &personal.public(), &other).unwrap();
        assert!(open(&context, &personal, &unchecked).is_err());
    }
}
