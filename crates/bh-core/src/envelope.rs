//! The sealed format: `[format 1][epoch u32 BE][nonce 24][ciphertext and tag]`,
//! bound by associated data `"bh.v1" ‖ purpose ‖ base ‖ object ‖ epoch BE`.

use crate::Error;
use bh_crypto::Secret;
use zeroize::Zeroizing;

pub(crate) const FORMAT: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code, reason = "purposes of later tasks and plans")]
pub(crate) enum Purpose {
    ObjectUpdate = 1,
    ObjectState = 2,
    FileBlob = 3,
    BaseKeyForAccount = 4,
    BaseKeyForApp = 5,
    AccountKey = 6,
    AccountData = 7,
    ApprovalTransfer = 8,
    ApprovalDeviceName = 9, // Reserved: the approval reveal no longer carries a name.
    HiddenBaseKey = 10,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Aad {
    pub purpose: Purpose,
    pub base: [u8; 16],
    pub object: [u8; 16],
    pub epoch: u32,
}

const HEADER: usize = 1 + 4 + 24;
const TAG: usize = 16;
/// What sealing adds to the plaintext's length.
pub(crate) const OVERHEAD: usize = HEADER + TAG;

impl Aad {
    fn bytes(&self) -> [u8; 42] {
        let mut out = [0; 42];
        out[..5].copy_from_slice(b"bh.v1");
        out[5] = self.purpose as u8;
        out[6..22].copy_from_slice(&self.base);
        out[22..38].copy_from_slice(&self.object);
        out[38..].copy_from_slice(&self.epoch.to_be_bytes());
        out
    }
}

pub(crate) fn seal(key: &Secret<32>, ad: &Aad, plaintext: &[u8]) -> Vec<u8> {
    let (nonce, ciphertext) = bh_crypto::aead_seal(key, &ad.bytes(), plaintext);
    let mut out = Vec::with_capacity(HEADER + ciphertext.len());
    out.push(FORMAT);
    out.extend_from_slice(&ad.epoch.to_be_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// A format this version doesn't know is `NeedsUpdate`; anything else that
/// doesn't authenticate under `key` and `ad` is `Crypto`.
pub(crate) fn open(key: &Secret<32>, ad: &Aad, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    match sealed.first() {
        Some(&FORMAT) => {}
        Some(_) => return Err(Error::NeedsUpdate),
        None => return Err(Error::Crypto),
    }
    if sealed.len() < HEADER + TAG || sealed[1..5] != ad.epoch.to_be_bytes() {
        return Err(Error::Crypto);
    }
    let nonce: [u8; 24] = sealed[5..HEADER].try_into().expect("nonce length");
    Ok(bh_crypto::aead_open(
        key,
        &nonce,
        &ad.bytes(),
        &sealed[HEADER..],
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AAD: Aad = Aad {
        purpose: Purpose::AccountData,
        base: [0; 16],
        object: [9; 16],
        epoch: 1,
    };

    #[test]
    fn envelope_is_bound_to_purpose_base_object_and_epoch() {
        let key = Secret::<32>::random();
        let ad = Aad {
            purpose: Purpose::ObjectUpdate,
            base: [1; 16],
            object: [2; 16],
            epoch: 1,
        };
        let sealed = seal(&key, &ad, b"x");
        assert_eq!(sealed[0], 1);
        assert_eq!(&*open(&key, &ad, &sealed).unwrap(), b"x");
        for other in [
            Aad {
                purpose: Purpose::ObjectState,
                ..ad
            },
            Aad {
                base: [3; 16],
                ..ad
            },
            Aad {
                object: [3; 16],
                ..ad
            },
            Aad { epoch: 2, ..ad },
        ] {
            assert!(open(&key, &other, &sealed).is_err());
        }
    }

    #[test]
    fn unknown_envelope_format_needs_update() {
        let mut sealed = seal(&Secret::<32>::random(), &AAD, b"x");
        sealed[0] = 2;
        assert!(matches!(
            open(&Secret::<32>::random(), &AAD, &sealed),
            Err(Error::NeedsUpdate)
        ));
    }

    #[test]
    fn envelope_layout_matches_the_format() {
        let key = Secret::<32>::random();
        let ad = Aad { epoch: 7, ..AAD };
        let sealed = seal(&key, &ad, b"hello");
        assert_eq!(sealed.len(), 1 + 4 + 24 + 5 + 16);
        assert_eq!(&sealed[1..5], &7u32.to_be_bytes());
        let mut ad_bytes = b"bh.v1".to_vec();
        ad_bytes.push(Purpose::AccountData as u8);
        ad_bytes.extend_from_slice(&[0; 16]);
        ad_bytes.extend_from_slice(&[9; 16]);
        ad_bytes.extend_from_slice(&7u32.to_be_bytes());
        let nonce: [u8; 24] = sealed[5..29].try_into().unwrap();
        let plain = bh_crypto::aead_open(&key, &nonce, &ad_bytes, &sealed[29..]).unwrap();
        assert_eq!(&*plain, b"hello");
    }

    #[test]
    fn wrong_key_and_truncation_fail_with_crypto() {
        let sealed = seal(&Secret::<32>::random(), &AAD, b"x");
        assert_eq!(
            open(&Secret::<32>::random(), &AAD, &sealed),
            Err(Error::Crypto)
        );
        assert_eq!(
            open(&Secret::<32>::random(), &AAD, &sealed[..20]),
            Err(Error::Crypto)
        );
        assert_eq!(open(&Secret::<32>::random(), &AAD, &[]), Err(Error::Crypto));
    }
}
