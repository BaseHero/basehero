//! TEST-ONLY configurable `DeviceKeyStore`. It never touches an OS key store and
//! is never compiled into production. Shared across test binaries, so unused
//! helpers are allowed.
#![allow(dead_code)]
use std::cell::{Ref, RefCell};
use std::rc::Rc;

use bh_account::crypto::{self, KemKey, Secret, SigningKey};
use bh_account::owner::AccountGeneration;
use bh_account::platform::{
    ControlKeyPolicy, DeviceKeyStore, DeviceKeyStoreKind, KeyHandle, KeyStoreError, StoredDevice,
};

pub struct StoreState {
    pub handle: KeyHandle,
    pub ordinary: Option<SigningKey>,
    pub control: Option<SigningKey>,
    pub receiver: Option<KemKey>,
    pub policy: ControlKeyPolicy,
    pub kind: DeviceKeyStoreKind,
    /// `load` reports `Unavailable` (a missing native key).
    pub fail_load: bool,
    /// `load` reports this specific error instead (e.g. a cancelled prompt).
    pub load_error: Option<KeyStoreError>,
    /// `load` returns different public keys (the native key no longer matches).
    pub wrong_public: bool,
    /// Advance the owner's generation while a native load is in flight, standing
    /// in for a concurrent lock, removal or stop.
    pub advance_generation_on_load: bool,
    /// Advance the owner's generation while a control signature is in flight,
    /// standing in for a concurrent lock, removal or stop.
    pub advance_generation_on_sign: bool,
    pub create_calls: usize,
    pub sign_calls: usize,
}

#[derive(Clone)]
pub struct FakeStore {
    generation: AccountGeneration,
    state: Rc<RefCell<StoreState>>,
}

impl FakeStore {
    pub fn new(generation: AccountGeneration) -> Self {
        Self {
            generation,
            state: Rc::new(RefCell::new(StoreState {
                handle: KeyHandle([7; 32]),
                ordinary: None,
                control: None,
                receiver: None,
                policy: ControlKeyPolicy::AppEnforcedOwnerConfirmation,
                kind: DeviceKeyStoreKind::MacLoginKeychainV1,
                fail_load: false,
                load_error: None,
                wrong_public: false,
                advance_generation_on_load: false,
                advance_generation_on_sign: false,
                create_calls: 0,
                sign_calls: 0,
            })),
        }
    }

    pub fn state(&self) -> Ref<'_, StoreState> {
        self.state.borrow()
    }

    pub fn state_mut(&self) -> std::cell::RefMut<'_, StoreState> {
        self.state.borrow_mut()
    }

    fn device(&self) -> StoredDevice {
        let state = self.state.borrow();
        let ordinary = state.ordinary.as_ref().expect("created ordinary key");
        let control = state.control.as_ref().expect("created control key");
        let receiver = state.receiver.as_ref().expect("created receiver");
        StoredDevice {
            handle: state.handle.clone(),
            keys: bh_account::DevicePublicKeys::new(
                ordinary.public(),
                control.public(),
                receiver.public(),
            )
            .expect("independent keys"),
            policy: state.policy,
            kind: state.kind,
        }
    }
}

impl DeviceKeyStore for FakeStore {
    async fn create(&mut self, policy: ControlKeyPolicy) -> Result<StoredDevice, KeyStoreError> {
        let mut state = self.state.borrow_mut();
        state.create_calls += 1;
        state.policy = policy;
        state.ordinary = Some(SigningKey::generate());
        state.control = Some(SigningKey::generate());
        state.receiver = Some(KemKey::generate());
        drop(state);
        Ok(self.device())
    }

    async fn load(&mut self, handle: KeyHandle) -> Result<StoredDevice, KeyStoreError> {
        let (error, advance, wrong_public) = {
            let state = self.state.borrow();
            (
                state.load_error,
                state.advance_generation_on_load,
                state.wrong_public,
            )
        };
        if advance {
            // A concurrent lock/removal/stop lands while the native load runs.
            self.generation.advance();
        }
        if let Some(error) = error {
            return Err(error);
        }
        let state = self.state.borrow();
        if state.fail_load || handle != state.handle {
            return Err(KeyStoreError::Unavailable);
        }
        if state.ordinary.is_none() {
            return Err(KeyStoreError::Invalidated);
        }
        let mut device = self.device();
        if wrong_public {
            device.keys = bh_account::DevicePublicKeys::new(
                SigningKey::generate().public(),
                SigningKey::generate().public(),
                KemKey::generate().public(),
            )
            .expect("independent keys");
        }
        Ok(device)
    }

    async fn sign_control(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        let (signature, advance) = {
            let mut state = self.state.borrow_mut();
            state.sign_calls += 1;
            if handle != state.handle {
                return Err(KeyStoreError::Unavailable);
            }
            let control = state.control.as_ref().ok_or(KeyStoreError::Invalidated)?;
            (control.sign(&message), state.advance_generation_on_sign)
        };
        if advance {
            // A concurrent lock/removal/stop lands while the prompt is open.
            self.generation.advance();
        }
        Ok(signature)
    }

    async fn sign_content(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        let state = self.state.borrow();
        if handle != state.handle {
            return Err(KeyStoreError::Unavailable);
        }
        let ordinary = state.ordinary.as_ref().ok_or(KeyStoreError::Invalidated)?;
        let signature = ordinary.sign(&message);
        if state.advance_generation_on_sign {
            self.generation.advance();
        }
        Ok(signature)
    }

    async fn decapsulate(
        &mut self,
        handle: KeyHandle,
        ciphertext: [u8; 1120],
    ) -> Result<Secret<32>, KeyStoreError> {
        let state = self.state.borrow();
        if handle != state.handle {
            return Err(KeyStoreError::Unavailable);
        }
        let receiver = state.receiver.as_ref().ok_or(KeyStoreError::Invalidated)?;
        crypto::decapsulate(receiver, &ciphertext).map_err(|_| KeyStoreError::WrongKey)
    }
}
