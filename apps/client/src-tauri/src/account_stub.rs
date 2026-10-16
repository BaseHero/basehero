//! Non-macOS stand-in for the Mac platform bridge, so the crate (and its
//! first-account state machine) compiles and checks on Linux CI. It never
//! signs, never stores a key and never prints, mails or writes a kit; the
//! first-run screens report the account service as unavailable on this build.
use bh_account::{
    crypto::Secret,
    journal::{PendingSetupProtector, ProtectorError},
    platform::{ControlKeyPolicy, DeviceKeyStore, KeyHandle, KeyStoreError, StoredDevice},
    recovery::RecoveryCode,
};

#[derive(Clone, Copy, Default)]
pub(crate) struct LoginStore;

impl DeviceKeyStore for LoginStore {
    async fn create(&mut self, _: ControlKeyPolicy) -> Result<StoredDevice, KeyStoreError> {
        Err(KeyStoreError::Unavailable)
    }
    async fn load(&mut self, _: KeyHandle) -> Result<StoredDevice, KeyStoreError> {
        Err(KeyStoreError::Unavailable)
    }
    async fn sign_control(&mut self, _: KeyHandle, _: Vec<u8>) -> Result<[u8; 64], KeyStoreError> {
        Err(KeyStoreError::Unavailable)
    }
    async fn sign_content(&mut self, _: KeyHandle, _: Vec<u8>) -> Result<[u8; 64], KeyStoreError> {
        Err(KeyStoreError::Unavailable)
    }
    async fn decapsulate(
        &mut self,
        _: KeyHandle,
        _: [u8; 1120],
    ) -> Result<Secret<32>, KeyStoreError> {
        Err(KeyStoreError::Unavailable)
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct KitProtector;

impl PendingSetupProtector for KitProtector {
    fn seal(&mut self, _: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        Err(ProtectorError::Unavailable)
    }
    fn open(&mut self, _: &[u8]) -> Result<bh_account::crypto::SecretBytes, ProtectorError> {
        Err(ProtectorError::Unavailable)
    }
    fn reseal_without_code(&mut self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        Err(ProtectorError::Unavailable)
    }
    fn retire_kit_key(&mut self, _: &[u8]) -> Result<(), ProtectorError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Mac-only success variants keep the UI result shape uniform
pub(crate) enum Destination {
    Saved,
    Opened,
    Cancelled,
}

pub(crate) fn email_kit(_: &RecoveryCode) -> Result<Destination, ()> {
    Ok(Destination::Cancelled)
}

pub(crate) async fn save_kit_file(_: &RecoveryCode) -> Result<Destination, ()> {
    Ok(Destination::Cancelled)
}
