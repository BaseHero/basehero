//! The password secret, recovery kit, and keys derived from the account key.

use crate::Error;
use crate::envelope::{Aad, Purpose};
use bh_crypto::Secret;
use std::fmt;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub(crate) use bh_proto::KdfParams as Kdf;

/// Argon2id parameters for new accounts and the only ones this version accepts.
pub(crate) const DEFAULT_KDF: Kdf = Kdf {
    ops_limit: 3,
    mem_limit_kib: 65536,
};

/// `P = argon2id(NFKC(password), salt, kdf)`.
pub(crate) struct PasswordSecret(Secret<32>);

impl PasswordSecret {
    /// Parameters other than [`DEFAULT_KDF`] are refused with `NeedsUpdate`,
    /// so a server can't weaken the derivation.
    pub(crate) fn derive(
        password: &str,
        salt: &[u8; 16],
        kdf: Kdf,
    ) -> Result<PasswordSecret, Error> {
        if kdf != DEFAULT_KDF {
            return Err(Error::NeedsUpdate);
        }
        let normalized = Zeroizing::new(password.nfkc().collect::<String>());
        let mem = usize::try_from(kdf.mem_limit_kib).expect("memory limit fits") * 1024;
        let secret = bh_crypto::argon2id(normalized.as_bytes(), salt, kdf.ops_limit.into(), mem)
            .map_err(|e| match e {
                bh_crypto::Error::ResourceFailure => Error::Storage("not enough memory".into()),
                _ => Error::invalid("password"),
            })?;
        Ok(PasswordSecret(secret))
    }

    /// `L = kdf(P, "bhlogin1", 1)`, the only value derived from the password that leaves the device.
    pub(crate) fn login_key(&self) -> [u8; 32] {
        *bh_crypto::kdf(&self.0, b"bhlogin1", 1).expose()
    }

    /// `W = generichash(key = P, "bh.v1.account-wrap" ‖ kit)`.
    pub(crate) fn wrap_key(&self, kit: &RecoveryKit) -> Secret<32> {
        let hash = Zeroizing::new(bh_crypto::generichash(
            Some(self.0.expose()),
            &[b"bh.v1.account-wrap", &*kit.0],
        ));
        Secret::from_slice(&*hash).expect("32-byte hash")
    }
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const KIT_CHARS: usize = 26;

/// 16 random bytes, shown as 26 Crockford base-32 characters in groups of four.
#[derive(Clone)]
pub struct RecoveryKit(Zeroizing<[u8; 16]>);

impl RecoveryKit {
    /// Generates a fresh random kit; keep it for account recovery.
    pub fn generate() -> Self {
        Self(Zeroizing::new(bh_crypto::random::<16>()))
    }

    /// Ignores case, spaces and hyphens, and reads I and L as 1 and O as 0.
    /// Anything else that isn't a kit is `BadKit`.
    ///
    /// # Errors
    /// Returns [`Error::BadKit`] for malformed text.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut bytes = Zeroizing::new([0u8; 16]);
        let (mut bits, mut acc, mut count, mut index) = (0u32, 0u32, 0usize, 0usize);
        for c in text.chars() {
            let value = match c.to_ascii_uppercase() {
                ' ' | '-' => continue,
                'I' | 'L' => 1,
                'O' => 0,
                c => CROCKFORD
                    .iter()
                    .position(|&d| d as char == c)
                    .ok_or(Error::BadKit)? as u32,
            };
            count += 1;
            if count > KIT_CHARS {
                return Err(Error::BadKit);
            }
            acc = (acc << 5) | value;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                bytes[index] = (acc >> bits) as u8;
                index += 1;
                acc &= (1 << bits) - 1;
            }
        }
        // 26 characters carry 130 bits: the last two must be zero.
        if count != KIT_CHARS || acc != 0 {
            return Err(Error::BadKit);
        }
        Ok(Self(bytes))
    }

    /// Formats the kit in groups for the person to save; do not log it.
    pub fn display(&self) -> String {
        let mut chars = Zeroizing::new(Vec::with_capacity(KIT_CHARS));
        let (mut acc, mut bits) = (0u32, 0u32);
        for &byte in self.0.iter() {
            acc = (acc << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                chars.push(CROCKFORD[((acc >> bits) & 31) as usize]);
            }
            acc &= (1 << bits) - 1;
        }
        chars.push(CROCKFORD[((acc << (5 - bits)) & 31) as usize]);
        let mut out = String::with_capacity(KIT_CHARS + 6);
        for (i, group) in chars.chunks(4).enumerate() {
            if i > 0 {
                out.push('-');
            }
            out.extend(group.iter().map(|&c| c as char));
        }
        out
    }
}

impl PartialEq for RecoveryKit {
    fn eq(&self, other: &Self) -> bool {
        bh_crypto::constant_time_eq(&*self.0, &*other.0)
    }
}

impl Eq for RecoveryKit {}

impl fmt::Debug for RecoveryKit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKit(…)")
    }
}

/// The associated data of an account key envelope.
pub(crate) fn account_key_aad(account: &bh_proto::AccountId) -> Aad {
    Aad {
        purpose: Purpose::AccountKey,
        base: [0; 16],
        object: account.0,
        epoch: 1,
    }
}

/// The associated data of sealed account data.
pub(crate) fn account_data_aad(account: &bh_proto::AccountId) -> Aad {
    Aad {
        purpose: Purpose::AccountData,
        base: [0; 16],
        object: account.0,
        epoch: 1,
    }
}

/// `activation = kdf(AK, "bhactiv1", 1)`.
pub(crate) fn activation(account_key: &Secret<32>) -> Secret<32> {
    bh_crypto::kdf(account_key, b"bhactiv1", 1)
}

/// `kdf(AK, "bhacdat1", 1)`, which seals account data.
pub(crate) fn account_data_key(account_key: &Secret<32>) -> Secret<32> {
    bh_crypto::kdf(account_key, b"bhacdat1", 1)
}

/// The associated data of an account's base key wrapper.
pub(crate) fn account_wrapper_aad(base: &bh_proto::BaseId, epoch: u32) -> Aad {
    Aad {
        purpose: Purpose::BaseKeyForAccount,
        base: base.0,
        object: [0; 16],
        epoch,
    }
}

/// The associated data of an app device's base key wrapper.
pub(crate) fn app_wrapper_aad(
    base: &bh_proto::BaseId,
    device: &bh_proto::DeviceId,
    epoch: u32,
) -> Aad {
    Aad {
        purpose: Purpose::BaseKeyForApp,
        base: base.0,
        object: device.0,
        epoch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kit_displays_and_parses_forgivingly() {
        let k = RecoveryKit::generate();
        let s = k.display();
        assert_eq!(s.replace('-', "").len(), 26);
        assert_eq!(
            RecoveryKit::parse(&s.to_lowercase().replace('-', " ")).unwrap(),
            k
        );
    }

    #[test]
    fn kit_display_is_groups_of_four_crockford_characters() {
        let k = RecoveryKit([0xff; 16].into());
        let s = k.display();
        let groups: Vec<_> = s.split('-').map(str::len).collect();
        assert_eq!(groups, [4, 4, 4, 4, 4, 4, 2]);
        assert!(
            s.chars()
                .all(|c| c == '-' || "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c))
        );
        assert_eq!(
            RecoveryKit([0; 16].into()).display(),
            "0000-0000-0000-0000-0000-0000-00"
        );
    }

    #[test]
    fn kit_parse_reads_look_alike_letters() {
        let zero = RecoveryKit([0; 16].into());
        assert_eq!(
            RecoveryKit::parse("oooo oooo OOOO-0000-0000-0000-00").unwrap(),
            zero
        );
        let k = RecoveryKit::parse("1111-1111-1111-1111-1111-1111-10").unwrap();
        assert_eq!(
            RecoveryKit::parse("iiii-llll-IIII-LLLL-1111-1111-10").unwrap(),
            k
        );
    }

    #[test]
    fn kit_parse_rejects_wrong_length_letters_and_padding() {
        for bad in [
            "0000-0000-0000-0000-0000-0000-0",
            "0000-0000-0000-0000-0000-0000-000",
            "0000-0000-0000-0000-0000-0000-0U",
            "0000-0000-0000-0000-0000-0000-01",
        ] {
            assert_eq!(RecoveryKit::parse(bad), Err(Error::BadKit), "{bad}");
        }
    }

    #[test]
    fn password_secret_matches_the_documented_derivations() {
        let salt = [7; 16];
        let p = PasswordSecret::derive("pässword", &salt, DEFAULT_KDF).unwrap();
        // NFKC: a composed ä and a + combining diaeresis are the same password.
        let q = PasswordSecret::derive("pa\u{308}ssword", &salt, DEFAULT_KDF).unwrap();
        assert_eq!(p.login_key(), q.login_key());
        let raw = bh_crypto::argon2id("pässword".as_bytes(), &salt, 3, 64 << 20).unwrap();
        assert_eq!(
            p.login_key(),
            *bh_crypto::kdf(&raw, b"bhlogin1", 1).expose()
        );
        let kit = RecoveryKit([5; 16].into());
        let expected =
            bh_crypto::generichash(Some(raw.expose()), &[b"bh.v1.account-wrap", &[5; 16]]);
        assert_eq!(p.wrap_key(&kit).expose(), &expected);
    }

    #[test]
    fn only_the_known_kdf_parameters_are_accepted() {
        let weak = Kdf {
            ops_limit: 1,
            mem_limit_kib: 8,
        };
        assert!(matches!(
            PasswordSecret::derive("pw", &[0; 16], weak),
            Err(Error::NeedsUpdate)
        ));
    }

    #[test]
    fn debug_hides_the_kit() {
        let k = RecoveryKit::generate();
        assert_eq!(format!("{k:?}"), "RecoveryKit(…)");
    }
}
