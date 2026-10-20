//! Authentication of the three private initial-signup ciphertext objects.
use crate::{Error, VerifiedAccount, personal, recovery};

impl VerifiedAccount {
    /// Check exact ciphertext lengths and the separate signed initial slots.
    /// Call on the verified historical signup prefix, not caller-supplied digests.
    /// This neither decrypts nor authorizes retrieval of recovery objects.
    pub fn verify_initial_objects(
        &self,
        record: &[u8],
        device_seal: &[u8],
        recovery_seal: &[u8],
    ) -> Result<(), Error> {
        let (record_digest, publication) = self.initial_materials()?;
        if record.len() != 242
            || device_seal.len() != 1299
            || recovery_seal.len() != 1299
            || recovery::commitment(record)? != *record_digest
            || personal::commitment(device_seal) != *publication.device_digest()
            || personal::commitment(recovery_seal) != *publication.recovery_digest()
        {
            return Err(Error::InvalidCredentials);
        }
        Ok(())
    }
}
