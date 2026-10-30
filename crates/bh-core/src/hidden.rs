//! Keys for bases opened with an extra password.

use crate::Error;
use crate::base::BaseKey;
use crate::envelope::{self, Aad, Purpose};
use crate::keys::Kdf;
use bh_crypto::Secret;
use bh_proto::{AccountId, BaseId};
use std::fmt;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// A stable account-specific Argon2id salt, never persisted.
pub fn salt(account_key: &Secret<32>) -> [u8; 16] {
    let derived = bh_crypto::kdf(account_key, b"bhhsalt1", 1);
    derived.expose()[..16].try_into().expect("16-byte salt")
}

/// Argon2id parameters for hidden wrapper format 1. Nothing stores them beside a
/// wrapper, so they stay fixed even if new accounts get other defaults.
const HIDDEN_KDF: Kdf = Kdf {
    ops_limit: 3,
    mem_limit_kib: 65536,
};

/// A password-derived key for opening hidden base wrappers. Wiped on drop.
pub struct HiddenKey(Secret<32>);

impl HiddenKey {
    pub(crate) fn duplicate(&self) -> Self {
        Self(Secret::from_slice(self.0.expose()).expect("hidden key length"))
    }

    /// Derives a hidden key on the caller's thread; asynchronous callers must use `spawn_blocking`.
    pub fn derive(account_key: &Secret<32>, password: &str) -> Result<Self, Error> {
        if password.is_empty() {
            return Err(Error::invalid("password"));
        }
        #[cfg(feature = "test-support")]
        ARGON2_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let normalized = Zeroizing::new(password.nfkc().collect::<String>());
        let mem = usize::try_from(HIDDEN_KDF.mem_limit_kib).expect("memory limit fits") * 1024;
        let secret = bh_crypto::argon2id(
            normalized.as_bytes(),
            &salt(account_key),
            HIDDEN_KDF.ops_limit.into(),
            mem,
        )
        .map_err(|e| match e {
            bh_crypto::Error::ResourceFailure => Error::Storage("not enough memory".into()),
            _ => Error::invalid("password"),
        })?;
        Ok(Self(secret))
    }

    /// Per-base key, bound to this base's identifier.
    fn wrap_key(&self, base: BaseId) -> Secret<32> {
        let digest = Zeroizing::new(bh_crypto::generichash(
            Some(self.0.expose()),
            &[b"bh.v1.hidden-base", &base.0],
        ));
        Secret::from_slice(&*digest).expect("32-byte hash")
    }

    /// Seals a base key for this account, base and epoch.
    pub(crate) fn wrap(
        &self,
        account: AccountId,
        base: BaseId,
        epoch: u32,
        key: &BaseKey,
    ) -> Vec<u8> {
        envelope::seal(
            &self.wrap_key(base),
            &Aad {
                purpose: Purpose::HiddenBaseKey,
                base: base.0,
                object: account.0,
                epoch,
            },
            key.secret().expose(),
        )
    }

    /// Seals a hidden base under its password and the account key for this epoch.
    pub(crate) fn wrap_v2(
        &self,
        account_key: &Secret<32>,
        account: AccountId,
        base: BaseId,
        epoch: u32,
        key: &BaseKey,
    ) -> Vec<u8> {
        envelope::seal(
            &self.wrap_key_v2(account_key, base),
            &Aad {
                purpose: Purpose::HiddenBaseKey,
                base: base.0,
                object: account.0,
                epoch,
            },
            key.secret().expose(),
        )
    }

    fn wrap_key_v2(&self, account_key: &Secret<32>, base: BaseId) -> Secret<32> {
        let mix = bh_crypto::kdf(account_key, b"bhhidnk1", 1);
        let digest = Zeroizing::new(bh_crypto::generichash(
            Some(self.0.expose()),
            &[b"bh.v2.hidden-base", &base.0, mix.expose()],
        ));
        Secret::from_slice(&*digest).expect("32-byte hash")
    }

    /// Opens a legacy wrapper first, otherwise tries the supplied account keys in order.
    /// Returns the index of the account key used, or `None` for a legacy wrapper.
    pub(crate) fn open_any(
        &self,
        account_keys: &[&Secret<32>],
        account: AccountId,
        base: BaseId,
        epoch: u32,
        wrapper: &[u8],
    ) -> Option<(BaseKey, Option<usize>)> {
        if let Some(key) = self.open(account, base, epoch, wrapper) {
            return Some((key, None));
        }
        let aad = Aad {
            purpose: Purpose::HiddenBaseKey,
            base: base.0,
            object: account.0,
            epoch,
        };
        account_keys
            .iter()
            .enumerate()
            .find_map(|(index, account_key)| {
                let bytes =
                    envelope::open(&self.wrap_key_v2(account_key, base), &aad, wrapper).ok()?;
                Some((BaseKey::new(&bytes).ok()?, Some(index)))
            })
    }

    /// Opens a matching hidden wrapper, returning nothing on an invalid or unrelated wrapper.
    pub(crate) fn open(
        &self,
        account: AccountId,
        base: BaseId,
        epoch: u32,
        wrapper: &[u8],
    ) -> Option<BaseKey> {
        let plaintext = envelope::open(
            &self.wrap_key(base),
            &Aad {
                purpose: Purpose::HiddenBaseKey,
                base: base.0,
                object: account.0,
                epoch,
            },
            wrapper,
        )
        .ok()?;
        BaseKey::new(&plaintext).ok()
    }
}

impl fmt::Debug for HiddenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HiddenKey(…)")
    }
}

/// A hidden base's store key, distinct from its content key.
pub(crate) fn store_key(key: &BaseKey) -> Secret<32> {
    bh_crypto::kdf(key.secret(), b"bhhstor1", 1)
}

#[cfg(feature = "test-support")]
static ARGON2_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(feature = "test-support")]
pub(crate) fn argon2_calls() -> u64 {
    ARGON2_CALLS.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::BaseKey;
    use crate::envelope::{self, Aad, Purpose};
    use bh_crypto::Secret;
    use bh_proto::{AccountId, BaseId};

    fn ak(n: u8) -> Secret<32> {
        Secret::from_slice(&[n; 32]).unwrap()
    }
    fn bk() -> BaseKey {
        BaseKey::new(&[3; 32]).unwrap()
    }
    fn acct(n: u8) -> AccountId {
        AccountId([n; 16])
    }
    fn base(n: u8) -> BaseId {
        BaseId([n; 16])
    }

    #[test]
    fn a_v2_hidden_wrapper_needs_the_account_key_it_was_made_under() {
        let first = ak(1);
        let current = ak(2);
        let unrelated = ak(3);
        let hk = HiddenKey::derive(&first, "ferry lantern quartz").unwrap();
        let wrapper = hk.wrap_v2(&current, acct(1), base(2), 2, &bk());
        assert!(
            hk.open_any(&[&first, &unrelated], acct(1), base(2), 2, &wrapper)
                .is_none()
        );
        let (opened, index) = hk
            .open_any(&[&first, &current], acct(1), base(2), 2, &wrapper)
            .unwrap();
        assert_eq!(opened.secret().expose(), bk().secret().expose());
        assert_eq!(index, Some(1));
        assert!(
            hk.open_any(&[&current], acct(2), base(2), 2, &wrapper)
                .is_none()
        );
        assert!(
            hk.open_any(&[&current], acct(1), base(3), 2, &wrapper)
                .is_none()
        );
        assert!(
            hk.open_any(&[&current], acct(1), base(2), 1, &wrapper)
                .is_none()
        );
        let legacy = hk.wrap(acct(1), base(2), 1, &bk());
        let (opened, index) = hk.open_any(&[], acct(1), base(2), 1, &legacy).unwrap();
        assert_eq!(opened.secret().expose(), bk().secret().expose());
        assert_eq!(index, None);
    }

    #[test]
    fn the_salt_is_per_account_and_stable() {
        assert_eq!(salt(&ak(1)), salt(&ak(1)));
        assert_ne!(salt(&ak(1)), salt(&ak(2)));
    }

    #[test]
    fn a_wrapper_opens_only_with_its_password_account_key_account_base_and_epoch() {
        let hk = HiddenKey::derive(&ak(1), "ferry lantern quartz").unwrap();
        let w = hk.wrap(acct(1), base(1), 1, &bk());
        assert_eq!(
            hk.open(acct(1), base(1), 1, &w).unwrap().secret().expose(),
            bk().secret().expose()
        );
        assert!(
            HiddenKey::derive(&ak(1), "ferry lantern quartx")
                .unwrap()
                .open(acct(1), base(1), 1, &w)
                .is_none()
        );
        assert!(
            HiddenKey::derive(&ak(2), "ferry lantern quartz")
                .unwrap()
                .open(acct(1), base(1), 1, &w)
                .is_none()
        );
        assert!(hk.open(acct(2), base(1), 1, &w).is_none());
        assert!(hk.open(acct(1), base(2), 1, &w).is_none());
        assert!(hk.open(acct(1), base(1), 2, &w).is_none());
        assert!(hk.open(acct(1), base(1), 1, &w[..20]).is_none());
    }

    #[test]
    fn the_account_key_alone_opens_no_hidden_wrapper() {
        let wrapper = HiddenKey::derive(&ak(1), "ferry lantern quartz")
            .unwrap()
            .wrap(acct(1), base(2), 1, &bk());
        let ordinary_key = bh_crypto::kdf(&ak(1), b"bhbasew1", 1);
        for purpose in [Purpose::BaseKeyForAccount, Purpose::HiddenBaseKey] {
            let ad = Aad {
                purpose,
                base: base(2).0,
                object: acct(1).0,
                epoch: 1,
            };
            assert!(matches!(
                envelope::open(&ordinary_key, &ad, &wrapper),
                Err(crate::Error::Crypto)
            ));
        }
    }

    #[test]
    fn unicode_forms_of_one_password_open_the_same_base() {
        let w = HiddenKey::derive(&ak(1), "caf\u{e9} lantern")
            .unwrap()
            .wrap(acct(1), base(2), 1, &bk());
        assert!(
            HiddenKey::derive(&ak(1), "cafe\u{301} lantern")
                .unwrap()
                .open(acct(1), base(2), 1, &w)
                .is_some()
        );
    }

    #[test]
    fn hidden_and_ordinary_wrappers_have_the_same_length() {
        let hidden = HiddenKey::derive(&ak(1), "ferry lantern quartz")
            .unwrap()
            .wrap(acct(1), base(2), 1, &bk());
        let ordinary = envelope::seal(
            &bh_crypto::kdf(&ak(1), b"bhbasew1", 1),
            &Aad {
                purpose: Purpose::BaseKeyForAccount,
                base: base(2).0,
                object: [0; 16],
                epoch: 1,
            },
            bk().secret().expose(),
        );
        assert_eq!(hidden.len(), ordinary.len());
        assert_eq!(hidden.len(), 77);
    }

    #[test]
    fn the_store_key_is_not_the_content_key() {
        assert_ne!(
            store_key(&bk()).expose(),
            bh_crypto::kdf(bk().secret(), b"bhcntnt1", 1).expose()
        );
    }

    #[test]
    fn derivation_matches_its_recorded_vector() {
        let key = HiddenKey::derive(&ak(7), "ferry lantern quartz").unwrap();
        let wrap_key = key.wrap_key(base(2));
        assert_eq!(
            hex::encode(wrap_key.expose()),
            "6ba0ac21b86ae6500758fcf6e8ca1ecafd0fa810154fbfe6bb5fab183f6c972c"
        );
        assert_eq!(
            hex::encode(store_key(&bk()).expose()),
            "4695e39af72c11a09a33c67d11f1d10a8295b59c5b0c25e1fc68457a6779f0b8"
        );
    }

    #[test]
    fn hidden_parameters_match_todays_account_default() {
        assert_eq!(HIDDEN_KDF, crate::keys::DEFAULT_KDF);
    }

    /// A wrapper made by the first version: if its format, binding or
    /// parameters change, existing hidden bases would stop opening.
    #[test]
    fn a_recorded_wrapper_still_opens() {
        let wrapper = hex::decode(
            "0100000001f7d22bf33f076d281cc0c04209e17b4c7739e3909ca6a8cfbadf23e9e12e13\
             2000df686e261ca12d88adfe79185ca90dcbd9ddf697374b6e1deef1719bb901d34b01a4\
             ee5e9ed746",
        )
        .unwrap();
        let key = HiddenKey::derive(&ak(7), "ferry lantern quartz").unwrap();
        let opened = key.open(acct(1), base(2), 1, &wrapper).unwrap();
        assert_eq!(opened.secret().expose(), bk().secret().expose());
    }

    #[test]
    fn empty_password_is_invalid_and_debug_hides_the_key() {
        assert!(matches!(
            HiddenKey::derive(&ak(1), ""),
            Err(crate::Error::Invalid(_))
        ));
        let key = HiddenKey::derive(&ak(1), "ferry lantern quartz").unwrap();
        assert_eq!(format!("{key:?}"), "HiddenKey(…)");
    }
}
