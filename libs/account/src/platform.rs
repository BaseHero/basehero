//! Platform-owned device secrets. No software store is offered as a production
//! fallback. A shell adapter must qualify persistence and authentication on its OS.

use crate::{AccountEvent, DevicePublicKeys, Error, SigningRequest, crypto::Secret};

/// Opaque local handle, never an account or base-service credential.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyHandle(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlKeyPolicy {
    /// Bound to the biometric set at creation, with no passcode fallback.
    CurrentBiometricsOnly,
    /// Only for a platform treated as having no qualifying biometric capability.
    DevicePasscodeWithoutBiometrics,
    /// M1 Mac only: before each control action the app requires a fresh standard
    /// macOS owner confirmation (Touch ID, the Mac password or a paired Apple
    /// Watch). Enforced by the app, NOT bound to release of the stored key, and
    /// not a passcode key-release guarantee. Code running as the same Mac user
    /// can bypass the gate. Every other platform keeps the key-release rule above.
    AppEnforcedOwnerConfirmation,
}

/// Local storage lineage, not a credential. M1 login items must never be
/// mistaken for M2 items with OS-bound current-biometric control protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKeyStoreKind {
    MacLoginKeychainV1,
    MacDataProtectionKeychainV1,
    AndroidKeystoreV1,
}

#[derive(Clone)]
pub struct StoredDevice {
    pub handle: KeyHandle,
    pub keys: DevicePublicKeys,
    pub policy: ControlKeyPolicy,
    pub kind: DeviceKeyStoreKind,
}

/// No raw OS diagnostics: they may contain keys, handles, or personal data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStoreError {
    Unavailable,
    AuthenticationCancelled,
    Invalidated,
    StorageFailure,
    WrongKey,
    InvalidSignature,
}

// Concrete app adapters are used through this generic trait; no Send-bound
// future or object-safe trait is promised before the UI-thread bridge exists.
//
// Owner obligations for every adapter, and especially the app-enforced M1 gate:
// run synchronous OS Security work (SecItem reads/writes and prompts) off the UI
// thread; hold no account or SQLite lock across a prompt; bind each request to
// the exact request bytes and the account/window generation it was issued for;
// drop obsolete pending operations instead of dispatching their results; and
// recheck the generation before consuming or dispatching a result. A late
// operation that no longer matches the current generation must be discarded.
#[allow(async_fn_in_trait)]
pub trait DeviceKeyStore {
    /// Persist independent ordinary/control Ed25519 keys and an X-Wing receiver
    /// before returning. Never silently weaken the requested control policy.
    async fn create(&mut self, policy: ControlKeyPolicy) -> Result<StoredDevice, KeyStoreError>;

    /// Restore the same public keys/policy from a durable handle. Missing or
    /// invalidated material never silently generates a replacement identity.
    async fn load(&mut self, handle: KeyHandle) -> Result<StoredDevice, KeyStoreError>;

    /// Compare the returned handle and public halves before using a saved identity.
    /// An account owner must ALSO check these keys against verified active history.
    async fn load_matching(&mut self, device: &StoredDevice) -> Result<(), KeyStoreError> {
        let loaded = self.load(device.handle.clone()).await?;
        if loaded.handle != device.handle
            || loaded.keys != device.keys
            || loaded.policy != device.policy
            || loaded.kind != device.kind
        {
            return Err(KeyStoreError::WrongKey);
        }
        Ok(())
    }

    /// Release the second key under its recorded policy for this exact request.
    /// Cancellation/invalidation never falls back to ordinary signing.
    async fn sign_control(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError>;

    async fn sign_content(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError>;

    /// Open an exact X-Wing encapsulation using this device's receiver, returning
    /// only the zeroizing shared secret, never the receiver seed. The caller
    /// authenticates the full envelope before invoking this operation.
    async fn decapsulate(
        &mut self,
        handle: KeyHandle,
        ciphertext: [u8; 1120],
    ) -> Result<Secret<32>, KeyStoreError>;
}

impl SigningRequest {
    /// Complete an exact control request using the native second key.
    /// This does not imply hosted ordering, admission or current authority.
    pub async fn sign_with(
        &self,
        device: &StoredDevice,
        store: &mut impl DeviceKeyStore,
    ) -> Result<AccountEvent, KeyStoreError> {
        if device.keys.control() != self.expected_key() {
            return Err(KeyStoreError::WrongKey);
        }
        store.load_matching(device).await?;
        let signature = store
            .sign_control(device.handle.clone(), self.signing_bytes().to_vec())
            .await?;
        self.finish(signature).map_err(|error| match error {
            Error::BadSignature => KeyStoreError::InvalidSignature,
            _ => KeyStoreError::WrongKey,
        })
    }
}
