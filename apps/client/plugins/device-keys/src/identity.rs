//! The Android adapter's one identity-load decision, shared by JNI and host tests.
//! Native I/O owns decryption; ordinary loads never release the protected seed.
use bh_account::{
    DevicePublicKeys,
    crypto::{KemKey, SigningKey},
    platform::{KeyHandle, KeyStoreError},
};

pub(crate) trait IdentityIo {
    fn ordinary(&mut self, handle: &KeyHandle) -> Result<SigningKey, KeyStoreError>;
    fn receiver(&mut self, handle: &KeyHandle) -> Result<KemKey, KeyStoreError>;
    fn control(&mut self, handle: &KeyHandle) -> Result<SigningKey, KeyStoreError>;
    fn control_public(&mut self, handle: &KeyHandle) -> Result<[u8; 32], KeyStoreError>;
}

pub(crate) fn load_keys(
    io: &mut impl IdentityIo,
    handle: &KeyHandle,
) -> Result<DevicePublicKeys, KeyStoreError> {
    let ordinary = io.ordinary(handle)?;
    let receiver = io.receiver(handle)?;
    let public = io.control_public(handle)?;
    DevicePublicKeys::new(ordinary.public(), public, receiver.public())
        .map_err(|_| KeyStoreError::WrongKey)
}

pub(crate) fn sign_control(
    io: &mut impl IdentityIo,
    handle: &KeyHandle,
    message: &[u8],
) -> Result<[u8; 64], KeyStoreError> {
    Ok(io.control(handle)?.sign(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_account::crypto::{self, SigningKey};

    struct Fake {
        ordinary: SigningKey,
        receiver: KemKey,
        control: SigningKey,
        metadata: Result<[u8; 32], KeyStoreError>,
        releases: usize,
    }
    impl Fake {
        fn new() -> Self {
            let control = SigningKey::generate();
            Self {
                ordinary: SigningKey::generate(),
                receiver: KemKey::generate(),
                metadata: Ok(control.public()),
                control,
                releases: 0,
            }
        }
    }
    impl IdentityIo for Fake {
        fn ordinary(&mut self, _: &KeyHandle) -> Result<SigningKey, KeyStoreError> {
            // The test's native-I/O seam uses the same seed type as the adapter.
            Ok(SigningKey::from_seed(&self.ordinary.export_seed()))
        }
        fn receiver(&mut self, _: &KeyHandle) -> Result<KemKey, KeyStoreError> {
            Ok(KemKey::from_seed(&self.receiver.export_seed()))
        }
        fn control(&mut self, _: &KeyHandle) -> Result<SigningKey, KeyStoreError> {
            self.releases += 1;
            Ok(SigningKey::from_seed(&self.control.export_seed()))
        }
        fn control_public(&mut self, _: &KeyHandle) -> Result<[u8; 32], KeyStoreError> {
            self.metadata
        }
    }

    #[test]
    fn android_adapter_routes_load_exclusively_through_the_tested_decision() {
        // android.rs is target-gated on Linux. Keep its tiny native entry point
        // from adding a second gated read outside the exercised decision.
        let source = include_str!("android.rs");
        let entry = source
            .split("async fn load(&mut self, handle: KeyHandle)")
            .nth(1)
            .unwrap()
            .split("async fn sign_content(")
            .next()
            .unwrap();
        assert!(entry.contains("identity::load_keys(&mut NativeIdentityIo, &handle)?"));
        assert!(!entry.contains("verified_signing("));
        assert!(!entry.contains("readControl"));
    }

    #[test]
    fn production_load_and_control_signing_release_only_when_needed() {
        let mut io = Fake::new();
        let handle = KeyHandle([7; 32]);
        for _ in 0..3 {
            // identity activation, ordinary delivery, ordinary receiving
            assert_eq!(
                load_keys(&mut io, &handle).unwrap().control(),
                &io.control.public()
            );
        }
        assert_eq!(io.releases, 0);
        let message = b"account change";
        let signature = sign_control(&mut io, &handle, message).unwrap();
        assert!(crypto::verify(&io.control.public(), message, &signature).is_ok());
        assert_eq!(io.releases, 1);
    }

    #[test]
    fn missing_or_corrupt_metadata_fails_without_control_release() {
        let mut io = Fake::new();
        let handle = KeyHandle([7; 32]);
        for failure in [
            KeyStoreError::Invalidated,
            KeyStoreError::StorageFailure,
            KeyStoreError::WrongKey,
        ] {
            io.metadata = Err(failure);
            assert!(matches!(load_keys(&mut io, &handle), Err(error) if error == failure));
            assert_eq!(io.releases, 0);
        }
    }
}
