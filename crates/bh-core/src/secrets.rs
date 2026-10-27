//! Where a device keeps its keys and tokens.

use crate::Error;
use bh_crypto::Secret;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use zeroize::Zeroizing;

pub trait SecretStore: Send + Sync + 'static {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error>;
    fn put(&self, name: &str, value: &[u8]) -> Result<(), Error>;
    fn delete(&self, name: &str) -> Result<(), Error>;
}

/// One file per secret, mode 0600, in a directory with mode 0700. For
/// development and for platforms whose file protection is the boundary.
pub struct FileSecretStore {
    dir: PathBuf,
}

impl FileSecretStore {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, Error> {
        let dir = dir.into();
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        Ok(Self { dir })
    }

    /// Names are file names in one directory: letters, digits, `.`, `_` and
    /// `-`, not starting with `.`.
    fn path(&self, name: &str) -> Result<PathBuf, Error> {
        let valid = !name.is_empty()
            && !name.starts_with('.')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !valid {
            return Err(Error::invalid("secret name"));
        }
        Ok(self.dir.join(name))
    }
}

impl SecretStore for FileSecretStore {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        match fs::read(self.path(name)?) {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Writes a temporary file with mode 0600, then renames it into place.
    fn put(&self, name: &str, value: &[u8]) -> Result<(), Error> {
        let path = self.path(name)?;
        let temporary = self.dir.join(format!(
            ".{name}.{:016x}",
            u64::from_le_bytes(bh_crypto::random())
        ));
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(value)?;
            file.sync_all()?;
            fs::rename(&temporary, &path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        Ok(result?)
    }

    fn delete(&self, name: &str) -> Result<(), Error> {
        match fs::remove_file(self.path(name)?) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }
}

/// Each secret is a file sealed with XChaCha20-Poly1305 under one key the app
/// keeps in the Keychain or Android Keystore, bound to its name.
pub struct SealedFileSecretStore {
    files: FileSecretStore,
    key: Secret<32>,
}

/// A sealed file is `[format 1][nonce 24][ciphertext and tag]`, with
/// associated data `"bh.v1.secret" ‖ 0x00 ‖ name`.
const SEALED_FORMAT: u8 = 1;

fn sealed_ad(name: &str) -> Vec<u8> {
    [b"bh.v1.secret\0".as_slice(), name.as_bytes()].concat()
}

impl SealedFileSecretStore {
    pub fn new(dir: PathBuf, key: Zeroizing<[u8; 32]>) -> Result<SealedFileSecretStore, Error> {
        Ok(Self {
            files: FileSecretStore::new(dir)?,
            key: Secret::from_slice(&*key)?,
        })
    }
}

impl SecretStore for SealedFileSecretStore {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let Some(sealed) = self.files.get(name)? else {
            return Ok(None);
        };
        match sealed.first() {
            Some(&SEALED_FORMAT) if sealed.len() > 24 => {}
            Some(&format) if format > SEALED_FORMAT => return Err(Error::NeedsUpdate),
            _ => return Err(Error::Crypto),
        }
        let nonce: [u8; 24] = sealed[1..25].try_into().expect("nonce length");
        Ok(Some(bh_crypto::aead_open(
            &self.key,
            &nonce,
            &sealed_ad(name),
            &sealed[25..],
        )?))
    }

    fn put(&self, name: &str, value: &[u8]) -> Result<(), Error> {
        self.files.path(name)?;
        let (nonce, ciphertext) = bh_crypto::aead_seal(&self.key, &sealed_ad(name), value);
        let sealed = [&[SEALED_FORMAT], nonce.as_slice(), &ciphertext].concat();
        self.files.put(name, &sealed)
    }

    fn delete(&self, name: &str) -> Result<(), Error> {
        self.files.delete(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed(dir: &std::path::Path, key: u8) -> SealedFileSecretStore {
        SealedFileSecretStore::new(dir.to_path_buf(), Zeroizing::new([key; 32])).unwrap()
    }

    #[test]
    fn file_secrets_round_trip_with_private_modes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("secrets");
        let store = FileSecretStore::new(&dir).unwrap();
        assert_eq!(store.get("acct.x.key").unwrap(), None);
        store.put("acct.x.key", b"one").unwrap();
        store.put("acct.x.key", b"two").unwrap();
        assert_eq!(&**store.get("acct.x.key").unwrap().unwrap(), b"two");
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(dir.clone()), 0o700);
        assert_eq!(mode(dir.join("acct.x.key")), 0o600);
        store.delete("acct.x.key").unwrap();
        store.delete("acct.x.key").unwrap();
        assert_eq!(store.get("acct.x.key").unwrap(), None);
    }

    #[test]
    fn secret_names_cannot_leave_the_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::new(tmp.path().join("s")).unwrap();
        for name in ["", "../x", "a/b", ".hidden", "a\0b"] {
            assert!(
                matches!(store.put(name, b"v"), Err(Error::Invalid(_))),
                "{name:?}"
            );
        }
    }

    #[test]
    fn sealed_secret_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let store = sealed(tmp.path(), 1);
        store.put("first", b"secret").unwrap();
        assert_eq!(
            store.get("first").unwrap().as_deref().map(Vec::as_slice),
            Some(&b"secret"[..])
        );
        assert_eq!(store.get("second").unwrap(), None);
        let raw = std::fs::read(tmp.path().join("first")).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"secret"));
        store.delete("first").unwrap();
        assert_eq!(store.get("first").unwrap(), None);
    }

    #[test]
    fn a_different_key_cannot_open_a_sealed_secret() {
        let tmp = tempfile::tempdir().unwrap();
        sealed(tmp.path(), 1).put("first", b"secret").unwrap();
        assert_eq!(sealed(tmp.path(), 2).get("first"), Err(Error::Crypto));
    }

    #[test]
    fn renaming_a_sealed_file_does_not_change_its_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let store = sealed(tmp.path(), 1);
        store.put("first", b"secret").unwrap();
        std::fs::rename(tmp.path().join("first"), tmp.path().join("second")).unwrap();
        assert_eq!(store.get("second"), Err(Error::Crypto));
    }
}
