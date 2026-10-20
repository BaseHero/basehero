//! Test-only native stand-ins, labelled as such: a protector that seals
//! nothing and a key store holding software keys, with switches for prompts
//! and failures. Never part of an app build (feature `test-support`).
use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex},
};

use crate::accounts::HostKeyStore;
use bh_account::{
    crypto::{self, KemKey, Secret, SecretBytes, SigningKey},
    journal::{PendingSetupProtector, ProtectorError},
    platform::{ControlKeyPolicy, DeviceKeyStore, KeyHandle, KeyStoreError, StoredDevice},
};

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

type FakeKeyMap = HashMap<[u8; 32], (SigningKey, SigningKey, KemKey)>;
#[derive(Clone, Default)]
pub struct FakeStore {
    /// With a gate, control signatures behave as the Mac login route's:
    /// each asks for a confirmation unless an armed copy covers it.
    pub gate: Option<crate::confirm::ActionGate>,
    /// Confirmations asked for, and whether the next ones are refused.
    pub prompts: Arc<std::sync::atomic::AtomicUsize>,
    pub refuse_prompts: Arc<std::sync::atomic::AtomicBool>,
    pub keys: Arc<StdMutex<FakeKeyMap>>,
    pub cancel_next_load: Arc<std::sync::atomic::AtomicBool>,
    pub fail_next_load: Arc<std::sync::atomic::AtomicBool>,
    pub delayed_handle: Arc<StdMutex<Option<[u8; 32]>>>,
}

impl FakeStore {
    fn find(&self, handle: &KeyHandle) -> Option<(SigningKey, SigningKey, KemKey)> {
        self.keys
            .lock()
            .unwrap()
            .get(&handle.0)
            .map(|(ordinary, control, receiver)| {
                (
                    SigningKey::from_seed(&ordinary.export_seed()),
                    SigningKey::from_seed(&control.export_seed()),
                    KemKey::from_seed(&receiver.export_seed()),
                )
            })
    }
}

impl DeviceKeyStore for FakeStore {
    async fn create(&mut self, policy: ControlKeyPolicy) -> Result<StoredDevice, KeyStoreError> {
        if policy != ControlKeyPolicy::AppEnforcedOwnerConfirmation {
            return Err(KeyStoreError::Unavailable);
        }
        let ordinary = SigningKey::generate();
        let control = SigningKey::generate();
        let receiver = KemKey::generate();
        let handle = KeyHandle(crypto::random());
        let keys = bh_account::DevicePublicKeys::new(
            ordinary.public(),
            control.public(),
            receiver.public(),
        )
        .unwrap();
        self.keys
            .lock()
            .unwrap()
            .insert(handle.0, (ordinary, control, receiver));
        Ok(StoredDevice {
            handle,
            keys,
            policy,
            kind: bh_account::platform::DeviceKeyStoreKind::MacLoginKeychainV1,
        })
    }
    async fn load(&mut self, handle: KeyHandle) -> Result<StoredDevice, KeyStoreError> {
        if *self.delayed_handle.lock().unwrap() == Some(handle.0) {
            std::future::pending::<()>().await;
        }
        if self
            .fail_next_load
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(KeyStoreError::StorageFailure);
        }
        if self
            .cancel_next_load
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(KeyStoreError::AuthenticationCancelled);
        }
        let (ordinary, control, receiver) = self.find(&handle).ok_or(KeyStoreError::Invalidated)?;
        Ok(StoredDevice {
            handle,
            keys: bh_account::DevicePublicKeys::new(
                ordinary.public(),
                control.public(),
                receiver.public(),
            )
            .unwrap(),
            policy: ControlKeyPolicy::AppEnforcedOwnerConfirmation,
            kind: bh_account::platform::DeviceKeyStoreKind::MacLoginKeychainV1,
        })
    }
    async fn sign_control(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        let (_, control, _) = self.find(&handle).ok_or(KeyStoreError::Invalidated)?;
        match self.gate.clone() {
            Some(gate) => {
                crate::confirm::sign_control_gated(
                    &gate,
                    control.public(),
                    &message,
                    self.confirm_owner(),
                    || Ok(control.sign(&message)),
                )
                .await
            }
            None => Ok(control.sign(&message)),
        }
    }
    async fn sign_content(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        let (ordinary, _, _) = self.find(&handle).ok_or(KeyStoreError::Invalidated)?;
        Ok(ordinary.sign(&message))
    }
    async fn decapsulate(
        &mut self,
        handle: KeyHandle,
        ciphertext: [u8; 1120],
    ) -> Result<Secret<32>, KeyStoreError> {
        let (_, _, receiver) = self.find(&handle).ok_or(KeyStoreError::Invalidated)?;
        crypto::decapsulate(&receiver, &ciphertext).map_err(|_| KeyStoreError::WrongKey)
    }
}

impl FakeStore {
    /// A store whose control signatures are gated as on the Mac login route.
    pub fn gated() -> Self {
        Self {
            gate: Some(crate::confirm::ActionGate::default()),
            ..Self::default()
        }
    }
    pub fn prompts(&self) -> usize {
        self.prompts.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl crate::accounts::HostKeyStore for FakeStore {
    const JOIN_POLICY: ControlKeyPolicy = ControlKeyPolicy::AppEnforcedOwnerConfirmation;
    fn action_gate(&self) -> Option<crate::confirm::ActionGate> {
        self.gate.clone()
    }
    fn confirm_owner(&mut self) -> impl std::future::Future<Output = Result<(), KeyStoreError>> {
        let (prompts, refuse) = (self.prompts.clone(), self.refuse_prompts.clone());
        async move {
            prompts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if refuse.load(std::sync::atomic::Ordering::SeqCst) {
                Err(KeyStoreError::AuthenticationCancelled)
            } else {
                Ok(())
            }
        }
    }
}
