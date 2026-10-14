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
}
