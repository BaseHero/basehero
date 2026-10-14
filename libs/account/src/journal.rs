//! Durable account state the owner needs, expressed as domain operations.
//!
//! A storage adapter must commit the original signed event bytes, the resulting
//! verified head and the sticky integrity stop in one transaction: a head is
//! never durable without the bytes that produced it. The pending first-device
//! setup blob is opaque here and is protected by the account owner, not the
//! journal. This is deliberately not a generic key-value store.

use crate::crypto::SecretBytes;
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
