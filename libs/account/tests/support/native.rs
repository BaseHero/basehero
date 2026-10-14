//! Explicit synthetic native receiver for materials tests; never compiled into production.
use bh_account::{
    DevicePublicKeys, Error, VerifiedAccount,
    crypto::{self, KemKey, Secret},
    personal::{self, PersonalKey, SealPurpose},
    platform::{
        ControlKeyPolicy, DeviceKeyStore, DeviceKeyStoreKind, KeyHandle, KeyStoreError,
        StoredDevice,
    },
};
use std::future::Future;

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => panic!("synthetic receiver unexpectedly pending"),
    }
}

struct SyntheticReceiver<'a> {
    keys: DevicePublicKeys,
    receiver: &'a KemKey,
}
impl DeviceKeyStore for SyntheticReceiver<'_> {
    async fn create(&mut self, _: ControlKeyPolicy) -> Result<StoredDevice, KeyStoreError> {
        unreachable!("only a stored synthetic test receiver is used")
    }
    async fn load(&mut self, handle: KeyHandle) -> Result<StoredDevice, KeyStoreError> {
        if handle != KeyHandle([1; 32]) {
            return Err(KeyStoreError::Unavailable);
        }
        Ok(StoredDevice {
            handle,
            keys: self.keys.clone(),
            policy: ControlKeyPolicy::CurrentBiometricsOnly,
            kind: DeviceKeyStoreKind::MacDataProtectionKeychainV1,
        })
    }
    async fn sign_control(&mut self, _: KeyHandle, _: Vec<u8>) -> Result<[u8; 64], KeyStoreError> {
        unreachable!("synthetic receiver cannot sign")
    }
    async fn sign_content(&mut self, _: KeyHandle, _: Vec<u8>) -> Result<[u8; 64], KeyStoreError> {
        unreachable!("synthetic receiver cannot sign")
    }
    async fn decapsulate(
        &mut self,
        handle: KeyHandle,
        ciphertext: [u8; 1120],
    ) -> Result<Secret<32>, KeyStoreError> {
        if handle != KeyHandle([1; 32]) {
            return Err(KeyStoreError::Unavailable);
        }
        crypto::decapsulate(self.receiver, &ciphertext).map_err(|_| KeyStoreError::WrongKey)
    }
}

pub fn open_for_receiver(
    state: &VerifiedAccount,
    envelope: &[u8],
    purpose: SealPurpose,
    receiver: &KemKey,
) -> Result<PersonalKey, Error> {
    if purpose == SealPurpose::Recovery {
        return personal::open_for_recovery(state, envelope, receiver);
    }
    // Tests here construct only an initial device. Never interpret an arbitrary
    // X-Wing key as a production device's authority or use this helper outside tests.
    let keys = state
        .active_devices()?
        .find(|keys| keys.receiving() == &receiver.public())
        .ok_or(Error::InvalidCredentials)?
        .clone();
    let device = StoredDevice {
        handle: KeyHandle([1; 32]),
        keys: keys.clone(),
        policy: ControlKeyPolicy::CurrentBiometricsOnly,
        kind: DeviceKeyStoreKind::MacDataProtectionKeychainV1,
    };
    ready(personal::open_for_receiver(
        state,
        envelope,
        &device,
        &mut SyntheticReceiver { keys, receiver },
    ))
}
