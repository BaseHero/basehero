//! TEST-ONLY identity protector: stores the pending blob verbatim. It provides
//! no protection and must never be used as a production fallback.
use bh_account::crypto::SecretBytes;
use bh_account::journal::{PendingSetupProtector, ProtectorError};

#[derive(Clone, Default)]
pub struct PlainProtector;

impl PendingSetupProtector for PlainProtector {
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        Ok(plaintext.to_vec())
    }

    fn open(&mut self, blob: &[u8]) -> Result<SecretBytes, ProtectorError> {
        SecretBytes::from_parts(&[blob]).map_err(|_| ProtectorError::Failed)
    }
    fn reseal_without_code(
        &mut self,
        _: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProtectorError> {
        self.seal(plaintext)
    }
    fn retire_kit_key(&mut self, _: &[u8]) -> Result<(), ProtectorError> {
        Ok(())
    }
}

// Test-only Keychain model: ciphertext in an actual SQLite backup must fail to
// open after its per-setup key is deleted. No synthetic test proves macOS SecItem.
use bh_account::crypto::{Secret, random};
use bh_account::journal::{open_pending_setup, seal_pending_setup};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Default)]
pub struct RotatingProtector {
    keys: Arc<Mutex<HashMap<[u8; 32], [u8; 32]>>>,
    fail_retire: Arc<AtomicBool>,
}
const KIT: u8 = 1;
const HOME: u8 = 2;
impl RotatingProtector {
    /// Keys held now.
    #[allow(dead_code)] // Not every test binary counts them.
    pub fn live(&self) -> usize {
        self.keys.lock().unwrap().len()
    }
    pub fn fail_next_retirement(&self) {
        self.fail_retire.store(true, Ordering::SeqCst);
    }
    fn make(
        &self,
        kind: u8,
        retired: Option<[u8; 32]>,
        text: &[u8],
    ) -> Result<Vec<u8>, ProtectorError> {
        let handle: [u8; 32] = random();
        let key = Secret::<32>::random();
        let encrypted = seal_pending_setup(&key, text)?;
        self.keys.lock().unwrap().insert(handle, *key.expose());
        let mut blob = vec![kind];
        blob.extend_from_slice(&handle);
        if let Some(old) = retired {
            blob.extend_from_slice(&old);
        }
        blob.extend(encrypted);
        Ok(blob)
    }
}
impl PendingSetupProtector for RotatingProtector {
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        self.make(KIT, None, plaintext)
    }
    fn open(&mut self, blob: &[u8]) -> Result<SecretBytes, ProtectorError> {
        if blob.len() < 1 + 32 + 24 + 16 {
            return Err(ProtectorError::Failed);
        }
        let kind = blob[0];
        let start = match kind {
            KIT => 33,
            HOME => 65,
            _ => return Err(ProtectorError::Failed),
        };
        let handle: [u8; 32] = blob[1..33].try_into().map_err(|_| ProtectorError::Failed)?;
        let key = *self
            .keys
            .lock()
            .unwrap()
            .get(&handle)
            .ok_or(ProtectorError::Unavailable)?;
        open_pending_setup(
            &Secret::from_slice(&key).map_err(|_| ProtectorError::Failed)?,
            blob.get(start..).ok_or(ProtectorError::Failed)?,
        )
    }
    fn reseal_without_code(
        &mut self,
        old: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProtectorError> {
        if old.len() < 33 || old[0] != KIT {
            return Err(ProtectorError::Failed);
        }
        self.make(
            HOME,
            Some(old[1..33].try_into().map_err(|_| ProtectorError::Failed)?),
            plaintext,
        )
    }
    fn retire_kit_key(&mut self, saved: &[u8]) -> Result<(), ProtectorError> {
        if self.fail_retire.swap(false, Ordering::SeqCst) {
            return Err(ProtectorError::Failed);
        }
        if saved.len() < 65 || saved[0] != HOME {
            return Err(ProtectorError::Failed);
        }
        let handle: [u8; 32] = saved[33..65]
            .try_into()
            .map_err(|_| ProtectorError::Failed)?;
        self.keys.lock().unwrap().remove(&handle);
        Ok(())
    }
    fn retire_key(&mut self, blob: &[u8]) -> Result<(), ProtectorError> {
        let handle: [u8; 32] = blob
            .get(1..33)
            .and_then(|h| h.try_into().ok())
            .ok_or(ProtectorError::Failed)?;
        self.keys.lock().unwrap().remove(&handle);
        Ok(())
    }
}
