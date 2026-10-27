//! Each install keeps one master key in the OS key store: the Keychain on the
//! Mac, Android Keystore on Android. It seals every other secret the core
//! keeps, in files under `data_dir/secrets`. Linux development builds keep
//! plain files instead.
#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "macos")]
pub mod mac;

use crate::error::CommandError;
use bh_core::{FileSecretStore, SealedFileSecretStore, SecretStore};
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

/// The install's master key, created the first time.
#[cfg(target_os = "macos")]
pub fn master_key(app: &tauri::AppHandle) -> Result<Zeroizing<[u8; 32]>, CommandError> {
    mac::master_key(&app.config().identifier)
}

/// The install's master key, created the first time.
#[cfg(target_os = "android")]
pub fn master_key(_app: &tauri::AppHandle) -> Result<Zeroizing<[u8; 32]>, CommandError> {
    android::master_key()
}

#[cfg(target_os = "macos")]
pub fn delete_master_key(app: &tauri::AppHandle) -> Result<(), CommandError> {
    mac::delete_master_key(&app.config().identifier)
}

#[cfg(target_os = "android")]
pub fn delete_master_key(_app: &tauri::AppHandle) -> Result<(), CommandError> {
    android::delete_master_key()
}

#[cfg(not(any(target_os = "macos", target_os = "android")))]
pub fn delete_master_key(_app: &tauri::AppHandle) -> Result<(), CommandError> {
    Ok(())
}

/// Sealed files under `data_dir/secrets`, or plain files without a master key,
/// which only Linux development builds accept.
pub fn store(
    data_dir: &Path,
    master: Option<Zeroizing<[u8; 32]>>,
) -> Result<Arc<dyn SecretStore>, CommandError> {
    let dir = data_dir.join("secrets");
    Ok(match master {
        Some(key) => Arc::new(SealedFileSecretStore::new(dir, key)?),
        None if cfg!(any(target_os = "macos", target_os = "android")) => {
            return Err(CommandError::key_unavailable("no master key"));
        }
        None => Arc::new(FileSecretStore::new(dir)?),
    })
}

const CANARY: &str = "app.canary";
const CANARY_VALUE: &[u8] = b"BaseHero";

/// Writes `app.canary` the first time. Later, a store that can't open it
/// has the wrong key, so the app stops rather than start over beside the
/// secrets it can no longer read.
pub fn check_canary(store: &dyn SecretStore) -> Result<(), CommandError> {
    match store.get(CANARY) {
        Ok(Some(value)) if *value == CANARY_VALUE => Ok(()),
        Ok(None) => Ok(store.put(CANARY, CANARY_VALUE)?),
        Ok(Some(_)) => Err(CommandError::key_unavailable(
            "the master key doesn't open this device's secrets: canary mismatch",
        )),
        // Secrets from a newer BaseHero open after updating; they aren't lost.
        Err(e @ bh_core::Error::NeedsUpdate) => Err(e.into()),
        Err(e) => Err(CommandError::key_unavailable(format!(
            "the master key doesn't open this device's secrets: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn key(byte: u8) -> Zeroizing<[u8; 32]> {
        Zeroizing::new([byte; 32])
    }

    #[test]
    fn a_different_master_key_is_refused_not_ignored() {
        let dir = tempdir();
        let a = store(dir.path(), Some(key(1))).unwrap();
        check_canary(&*a).unwrap();
        let b = store(dir.path(), Some(key(2))).unwrap();
        assert_eq!(check_canary(&*b).unwrap_err().kind, "KeyUnavailable");
    }

    #[test]
    fn a_future_canary_format_reports_the_cause() {
        let dir = tempdir();
        let secrets = store(dir.path(), Some(key(1))).unwrap();
        check_canary(&*secrets).unwrap();
        let path = dir.path().join("secrets").join(CANARY);
        let mut sealed = std::fs::read(&path).unwrap();
        sealed[0] = 2;
        std::fs::write(path, sealed).unwrap();
        let error = check_canary(&*secrets).unwrap_err();
        // Not a key error: updating opens these secrets, so reset isn't offered.
        assert_eq!(error.kind, "NeedsUpdate");
    }

    #[test]
    fn the_same_master_key_opens_the_store_again() {
        let dir = tempdir();
        check_canary(&*store(dir.path(), Some(key(1))).unwrap()).unwrap();
        check_canary(&*store(dir.path(), Some(key(1))).unwrap()).unwrap();
        let raw = std::fs::read(dir.path().join("secrets").join(CANARY)).unwrap();
        assert!(!raw.windows(CANARY_VALUE.len()).any(|w| w == CANARY_VALUE));
    }

    #[cfg(any(target_os = "macos", target_os = "android"))]
    #[test]
    fn without_a_master_key_nothing_is_stored_in_plain_files() {
        let dir = tempdir();
        assert_eq!(
            store(dir.path(), None).err().unwrap().kind,
            "KeyUnavailable"
        );
        assert!(!dir.path().join("secrets").exists());
    }
}
