//! Durable account state the owner needs, expressed as domain operations.
//!
//! A storage adapter must commit the original signed event bytes, the resulting
//! verified head and the sticky integrity stop in one transaction: a head is
//! never durable without the bytes that produced it. The pending first-device
//! setup blob is opaque here and is protected by the account owner, not the
//! journal. This is deliberately not a generic key-value store.

use crate::crypto::{Secret, SecretBytes};
use crate::history::{AccountId, DevicePublicKeys, Head};
use crate::platform::{ControlKeyPolicy, DeviceKeyStoreKind, KeyHandle};

/// Framing version of the owner's pending first-device setup blob.
pub const PENDING_SETUP_VERSION: u16 = 1;

/// First-device setup stage. Whether the home has ordered the staged bytes is
/// derived from the journal, not stored here; `kit_saved` is a separate explicit
/// confirmation so it survives a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupStage {
    /// Local materials generated and signed; not submitted or ordered yet.
    Prepared,
    /// Submitted to the account home, result unknown. Reconcile the exact signed
    /// bytes before treating it as ordered; never record it as a verified head.
    HomePending,
}

impl SetupStage {
    pub fn code(self) -> u8 {
        match self {
            Self::Prepared => 0,
            Self::HomePending => 1,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Prepared),
            1 => Some(Self::HomePending),
            _ => None,
        }
    }
}

/// Opaque, native-protected pending-setup material plus its stage and the
/// person's explicit kit-save confirmation.
#[derive(Clone)]
pub struct PendingSetupRecord {
    pub version: u16,
    pub stage: SetupStage,
    pub kit_saved: bool,
    pub blob: Vec<u8>,
}

/// Recorded local device identity. The owner still checks these keys against
/// verified active history; this record is not authority by itself.
#[derive(Clone)]
pub struct JournaledDevice {
    pub handle: KeyHandle,
    pub keys: DevicePublicKeys,
    pub policy: ControlKeyPolicy,
    pub kind: DeviceKeyStoreKind,
}

/// Durable verified account: trusted anchor, original signed history, head, stop.
#[derive(Clone)]
pub struct JournaledAccount {
    pub anchor: AccountId,
    pub history: Vec<Vec<u8>>,
    pub head: Head,
    pub stopped: bool,
}

/// Journal failures carry no identity, key or input bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalError {
    /// The storage adapter failed; no state change is implied.
    Storage,
    /// Stored account state is internally inconsistent.
    Corrupt,
}

/// Durable state an account owner needs. Implementations commit each mutation
/// atomically, and never let a head outlive its signed bytes.
pub trait AccountJournal {
    /// Load the trusted anchor, original signed history, remembered head and stop.
    fn load(&self) -> Result<Option<JournaledAccount>, JournalError>;

    /// Append original signed bytes and set the resulting head and stop flag in
    /// one commit. An empty `events` slice only updates the stop flag; the head
    /// then refers to bytes already stored.
    fn commit_verified(
        &mut self,
        anchor: AccountId,
        events: &[&[u8]],
        head: Head,
        stopped: bool,
    ) -> Result<(), JournalError>;

    fn device(&self) -> Result<Option<JournaledDevice>, JournalError>;
    fn commit_device(&mut self, device: &JournaledDevice) -> Result<(), JournalError>;

    fn pending_setup(&self) -> Result<Option<PendingSetupRecord>, JournalError>;
    fn commit_pending_setup(&mut self, setup: &PendingSetupRecord) -> Result<(), JournalError>;
    /// Delete pending setup material. Called only once the journal holds the
    /// staged bytes (home ordered) and the person confirmed the kit saved.
    fn clear_pending_setup(&mut self) -> Result<(), JournalError>;
}

/// Native protection for the pending setup blob. A production adapter seals it
/// with an OS-held key; no software fallback is offered here.
pub trait PendingSetupProtector {
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError>;
    fn open(&mut self, blob: &[u8]) -> Result<SecretBytes, ProtectorError>;
}

/// Protector failures carry no secret or handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectorError {
    Unavailable,
    Failed,
}

/// Length of the nonce prefix in the pending-setup seal framing (XChaCha20-Poly1305).
pub const PENDING_SETUP_NONCE_LEN: usize = 24;

/// Associated data for the pending-setup seal. It fixes the purpose and framing
/// version, so a blob sealed here cannot be opened under another domain or
/// version. Keep the trailing version in step with `PENDING_SETUP_VERSION`.
pub const PENDING_SETUP_SEAL_AD: &[u8] = b"BaseHero pending setup v1";

/// Seal pending-setup plaintext under a native-held 32-byte wrapping key.
///
/// Framing is the 24-byte nonce followed by the AEAD ciphertext; open must use
/// the same framing and associated data. This is shared framing, not a protector:
/// a native adapter owns the wrapping key and its storage, and only that adapter
/// decides whether a key exists.
pub fn seal_pending_setup(
    wrapping: &Secret<32>,
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtectorError> {
    let (nonce, ciphertext) = crate::crypto::aead_seal(wrapping, PENDING_SETUP_SEAL_AD, plaintext)
        .map_err(|_| ProtectorError::Failed)?;
    let mut out = Vec::with_capacity(PENDING_SETUP_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a blob produced by [`seal_pending_setup`]. A wrong key, altered bytes,
/// a truncated blob or a future framing are all `Failed`. A missing wrapping key
/// is the adapter's `Unavailable`, never a silent regeneration here.
pub fn open_pending_setup(
    wrapping: &Secret<32>,
    blob: &[u8],
) -> Result<SecretBytes, ProtectorError> {
    if blob.len() < PENDING_SETUP_NONCE_LEN {
        return Err(ProtectorError::Failed);
    }
    let (nonce, ciphertext) = blob.split_at(PENDING_SETUP_NONCE_LEN);
    let nonce: [u8; PENDING_SETUP_NONCE_LEN] =
        nonce.try_into().map_err(|_| ProtectorError::Failed)?;
    crate::crypto::aead_open(wrapping, &nonce, PENDING_SETUP_SEAL_AD, ciphertext)
        .map_err(|_| ProtectorError::Failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_setup_seal_round_trips_and_rejects_tampering() {
        let wrapping = Secret::<32>::random();
        let plaintext = b"BHPEND01 pending setup material";
        let blob = seal_pending_setup(&wrapping, plaintext).expect("seal");
        assert_eq!(
            blob.len(),
            PENDING_SETUP_NONCE_LEN + plaintext.len() + 16,
            "framing is nonce plus AEAD ciphertext"
        );
        assert_ne!(
            blob.as_slice(),
            plaintext,
            "plaintext is not stored verbatim"
        );
        assert_eq!(
            open_pending_setup(&wrapping, &blob).expect("open").expose(),
            plaintext
        );

        // A different wrapping key and any altered byte are refused.
        let other = Secret::<32>::random();
        assert!(matches!(
            open_pending_setup(&other, &blob),
            Err(ProtectorError::Failed)
        ));
        for index in [0, PENDING_SETUP_NONCE_LEN, blob.len() - 1] {
            let mut tampered = blob.clone();
            tampered[index] ^= 1;
            assert!(matches!(
                open_pending_setup(&wrapping, &tampered),
                Err(ProtectorError::Failed)
            ));
        }
        assert!(matches!(
            open_pending_setup(&wrapping, &blob[..PENDING_SETUP_NONCE_LEN - 1]),
            Err(ProtectorError::Failed)
        ));
        assert!(matches!(
            open_pending_setup(&wrapping, &blob[..PENDING_SETUP_NONCE_LEN]),
            Err(ProtectorError::Failed)
        ));

        // A fresh nonce makes two seals of the same plaintext differ.
        assert_ne!(seal_pending_setup(&wrapping, plaintext).unwrap(), blob);
    }
}
