//! Synthetic-only adapter contract: these tests do not exercise an OS key store.
use bh_account::{
    AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount,
    crypto::{self, KemKey, Secret, SigningKey},
    personal::{self, PersonalKey, open_for_receiver, prepare_publication},
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
        std::task::Poll::Pending => panic!("synthetic adapter unexpectedly pending"),
    }
}

struct Fake {
    handle: KeyHandle,
    ordinary: SigningKey,
    control: SigningKey,
    receiver: KemKey,
    denied: Option<KeyStoreError>,
    wrong_public: bool,
    wrong_loaded_handle: bool,
    wrong_loaded_policy: bool,
    wrong_loaded_kind: bool,
    wrong_control: bool,
    wrong_receiver: bool,
    sign_calls: usize,
    decap_calls: usize,
    control_releases: usize,
}
impl Fake {
    fn new() -> Self {
        Self {
            handle: KeyHandle([7; 32]),
            ordinary: SigningKey::generate(),
            control: SigningKey::generate(),
            receiver: KemKey::generate(),
            denied: None,
            wrong_public: false,
            wrong_loaded_handle: false,
            wrong_loaded_policy: false,
            wrong_loaded_kind: false,
            wrong_control: false,
            wrong_receiver: false,
            sign_calls: 0,
            decap_calls: 0,
            control_releases: 0,
        }
    }
    fn stored(&self) -> StoredDevice {
        StoredDevice {
            handle: self.handle.clone(),
            keys: DevicePublicKeys::new(
                self.ordinary.public(),
                self.control.public(),
                self.receiver.public(),
            )
            .unwrap(),
            policy: ControlKeyPolicy::AppEnforcedOwnerConfirmation,
            kind: DeviceKeyStoreKind::MacLoginKeychainV1,
        }
    }
}
impl DeviceKeyStore for Fake {
    async fn create(&mut self, _: ControlKeyPolicy) -> Result<StoredDevice, KeyStoreError> {
        Ok(self.stored())
    }
    async fn load(&mut self, handle: KeyHandle) -> Result<StoredDevice, KeyStoreError> {
        if handle != self.handle {
            return Err(KeyStoreError::Unavailable);
        }
        // Public identity loading must not release the protected control seed.
        let mut stored = self.stored();
        if self.wrong_loaded_handle {
            stored.handle = KeyHandle([8; 32]);
        }
        if self.wrong_loaded_policy {
            // The M1 kind must carry the M1 app-enforced policy; any other
            // recorded policy (here the passcode alternative) is divergent.
            stored.policy = ControlKeyPolicy::DevicePasscodeWithoutBiometrics;
        }
        if self.wrong_loaded_kind {
            stored.kind = DeviceKeyStoreKind::MacDataProtectionKeychainV1;
        }
        if self.wrong_public {
            stored.keys = DevicePublicKeys::new(
                self.ordinary.public(),
                self.control.public(),
                KemKey::generate().public(),
            )
            .unwrap();
        }
        Ok(stored)
    }
    async fn sign_control(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        self.sign_calls += 1;
        self.control_releases += 1;
        if handle != self.handle {
            return Err(KeyStoreError::Unavailable);
        }
        if let Some(e) = self.denied {
            return Err(e);
        }
        Ok(if self.wrong_control {
            self.ordinary.sign(&message)
        } else {
            self.control.sign(&message)
        })
    }
    async fn sign_content(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        if handle != self.handle {
            return Err(KeyStoreError::Unavailable);
        }
        Ok(self.ordinary.sign(&message))
    }
    async fn decapsulate(
        &mut self,
        handle: KeyHandle,
        ciphertext: [u8; 1120],
    ) -> Result<Secret<32>, KeyStoreError> {
        self.decap_calls += 1;
        if handle != self.handle {
            return Err(KeyStoreError::Unavailable);
        }
        if self.wrong_receiver {
            return crypto::decapsulate(&KemKey::generate(), &ciphertext)
                .map_err(|_| KeyStoreError::WrongKey);
        }
        crypto::decapsulate(&self.receiver, &ciphertext).map_err(|_| KeyStoreError::WrongKey)
    }
}

#[test]
fn async_key_boundary_refuses_wrong_handle_cancel_invalidation_and_wrong_signer() {
    let mut store = Fake::new();
    let device = ready(store.create(ControlKeyPolicy::AppEnforcedOwnerConfirmation)).unwrap();
    assert_eq!(
        ready(store.load(device.handle.clone())).unwrap().keys,
        device.keys
    );
    assert!(matches!(
        ready(store.load(KeyHandle([8; 32]))),
        Err(KeyStoreError::Unavailable)
    ));
    let request = AccountEvent::genesis(
        device.keys.clone(),
        RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public()),
    );
    // A valid handle whose loaded *identity* has diverged must fail before
    // native signing, rather than relying on the fake's unknown-handle guard.
    for fault in 0..4 {
        store.wrong_loaded_handle = fault == 0;
        store.wrong_public = fault == 1;
        store.wrong_loaded_policy = fault == 2;
        store.wrong_loaded_kind = fault == 3;
        assert!(matches!(
            ready(request.sign_with(&device, &mut store)),
            Err(KeyStoreError::WrongKey)
        ));
        assert_eq!(store.sign_calls, 0, "fault {fault} signed");
    }
    store.wrong_loaded_handle = false;
    store.wrong_public = false;
    store.wrong_loaded_policy = false;
    store.wrong_loaded_kind = false;
    assert!(
        crypto::verify(
            device.keys.signing(),
            request.signing_bytes(),
            &ready(store.sign_content(device.handle.clone(), request.signing_bytes().to_vec()))
                .unwrap()
        )
        .is_ok()
    );
    store.denied = Some(KeyStoreError::AuthenticationCancelled);
    assert!(matches!(
        ready(request.sign_with(&device, &mut store)),
        Err(KeyStoreError::AuthenticationCancelled)
    ));
    store.denied = Some(KeyStoreError::Invalidated);
    assert!(matches!(
        ready(request.sign_with(&device, &mut store)),
        Err(KeyStoreError::Invalidated)
    ));
    store.denied = None;
    store.wrong_control = true;
    assert!(matches!(
        ready(request.sign_with(&device, &mut store)),
        Err(KeyStoreError::InvalidSignature)
    ));
    store.wrong_control = false;
    assert!(ready(request.sign_with(&device, &mut store)).is_ok());
    assert_eq!(store.sign_calls, 4);
    // The successful control signature releases exactly once; load must not.
    let before = store.control_releases;
    assert!(ready(request.sign_with(&device, &mut store)).is_ok());
    assert_eq!(store.control_releases - before, 1);
    let mut wrong = store.stored();
    wrong.handle = KeyHandle([8; 32]);
    assert!(matches!(
        ready(request.sign_with(&wrong, &mut store)),
        Err(KeyStoreError::Unavailable)
    ));
}

#[test]
fn first_device_seal_requires_matching_native_receiver() {
    let mut store = Fake::new();
    let device = ready(store.create(ControlKeyPolicy::AppEnforcedOwnerConfirmation)).unwrap();
    let draft = AccountEvent::genesis(
        device.keys.clone(),
        RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public()),
    );
    let genesis = ready(draft.sign_with(&device, &mut store)).unwrap();
    let mut state =
        VerifiedAccount::from_genesis(AccountId::of_genesis(&genesis).unwrap(), genesis.as_bytes())
            .unwrap();
    let draft = state
        .prepare_recovery_record(device.keys.id(), [9; 32])
        .unwrap();
    let committed = ready(draft.sign_with(&device, &mut store)).unwrap();
    state.apply(committed.as_bytes()).unwrap();
    let uncommitted = state.clone();
    let personal = PersonalKey::generate();
    let prepared = prepare_publication(&state, &personal).unwrap();
    let draft = state
        .publish_personal_key(
            device.keys.id(),
            prepared.public(),
            prepared.device_digest(),
            prepared.recovery_digest(),
        )
        .unwrap();
    let published = ready(draft.sign_with(&device, &mut store)).unwrap();
    state.apply(published.as_bytes()).unwrap();
    let seal = prepared.device_seal();
    // A valid device with mismatched loaded identity never invokes native
    // decapsulation; changing the saved identity itself is a separate case.
    for fault in 0..4 {
        store.wrong_loaded_handle = fault == 0;
        store.wrong_public = fault == 1;
        store.wrong_loaded_policy = fault == 2;
        store.wrong_loaded_kind = fault == 3;
        assert!(ready(open_for_receiver(&state, seal, &device, &mut store)).is_err());
        assert_eq!(store.decap_calls, 0, "fault {fault} decapsulated");
    }
    store.wrong_loaded_handle = false;
    store.wrong_public = false;
    store.wrong_loaded_policy = false;
    store.wrong_loaded_kind = false;
    let mut tampered = seal.to_vec();
    tampered[107] ^= 1; // correct shape, bad signed full-envelope commitment
    for (source, candidate) in [
        (&state, tampered.as_slice()),
        (&uncommitted, seal),
        (&state, prepared.recovery_seal()),
    ] {
        assert!(ready(open_for_receiver(source, candidate, &device, &mut store)).is_err());
        assert_eq!(
            store.decap_calls, 0,
            "unauthenticated envelope reached receiver"
        );
    }
    let foreign = Fake::new().stored();
    assert!(ready(open_for_receiver(&state, seal, &foreign, &mut store)).is_err());
    assert_eq!(
        store.decap_calls, 0,
        "misbound public device reached receiver"
    );
    let mut removed = state.clone();
    let draft = removed.remove_self(device.keys.id()).unwrap();
    let event = ready(draft.sign_with(&device, &mut store)).unwrap();
    removed.apply(event.as_bytes()).unwrap();
    assert!(ready(open_for_receiver(&removed, seal, &device, &mut store)).is_err());
    assert_eq!(store.decap_calls, 0, "verified removal reached receiver");
    let mut stopped = state.clone();
    assert!(stopped.apply(&[0]).is_err());
    assert!(ready(open_for_receiver(&stopped, seal, &device, &mut store)).is_err());
    assert_eq!(store.decap_calls, 0, "sticky stop reached receiver");
    store.control_releases = 0;
    assert_eq!(
        ready(open_for_receiver(&state, seal, &device, &mut store))
            .unwrap()
            .public(),
        personal.public()
    );
    assert_eq!(store.decap_calls, 1);
    assert_eq!(
        store.control_releases, 0,
        "ordinary receiving must not release control"
    );

    let mut recipient_store = Fake::new();
    let recipient = recipient_store.stored();
    let draft = state
        .add_device(device.keys.id(), recipient.keys.clone())
        .unwrap();
    let admission = ready(draft.sign_with(&device, &mut store)).unwrap();
    store.control_releases = 0;
    let delivery = ready(personal::seal_for_device(
        &state,
        &personal,
        &device,
        &recipient.keys,
        &admission,
        &mut store,
    ))
    .unwrap();
    assert_eq!(
        store.control_releases, 0,
        "ordinary delivery released control"
    );
    state.apply(admission.as_bytes()).unwrap();
    let received = ready(personal::open_for_device(
        &state,
        &delivery,
        &recipient,
        &mut recipient_store,
    ))
    .unwrap();
    assert_eq!(received.public(), personal.public());
    assert_eq!(
        recipient_store.control_releases, 0,
        "ordinary delivery receive released control"
    );
    store.wrong_receiver = true;
    assert!(
        ready(open_for_receiver(
            &state,
            prepared.device_seal(),
            &device,
            &mut store
        ))
        .is_err()
    );
    store.wrong_receiver = false;
    let mut wrong_keys = store.stored();
    wrong_keys.keys = DevicePublicKeys::new(
        store.ordinary.public(),
        store.control.public(),
        KemKey::generate().public(),
    )
    .unwrap();
    assert!(
        ready(open_for_receiver(
            &state,
            prepared.device_seal(),
            &wrong_keys,
            &mut store
        ))
        .is_err()
    );
    let mut wrong_handle = store.stored();
    wrong_handle.handle = KeyHandle([8; 32]);
    assert!(
        ready(open_for_receiver(
            &state,
            prepared.device_seal(),
            &wrong_handle,
            &mut store
        ))
        .is_err()
    );
}
