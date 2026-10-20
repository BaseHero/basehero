use bh_account::{
    AccountEvent, AccountId, DevicePublicKeys, Error, RecoveryPublicKeys, VerifiedAccount,
    crypto::{KemKey, SigningKey},
    device_auth::{self, Context},
};

const DOMAIN: &[u8] = b"bh/sync-device-possession/v1\0";

struct Fixture {
    ordinary: SigningKey,
    control: SigningKey,
    account: VerifiedAccount,
    device: bh_account::DeviceId,
    context: Context,
}

impl Fixture {
    fn new() -> Self {
        let ordinary = SigningKey::generate();
        let control = SigningKey::generate();
        let keys = DevicePublicKeys::new(
            ordinary.public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        let device = keys.id();
        let recovery =
            RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public());
        let draft = AccountEvent::genesis(keys, recovery);
        let genesis = draft.finish(control.sign(draft.signing_bytes())).unwrap();
        let account = VerifiedAccount::from_genesis(
            AccountId::of_genesis(&genesis).unwrap(),
            genesis.as_bytes(),
        )
        .unwrap();
        Self {
            ordinary,
            control,
            account,
            device,
            context: Context {
                channel_binding: [0x4b; 32],
                challenge: [0xa6; 32],
            },
        }
    }

    fn request(&self) -> device_auth::SigningRequest {
        device_auth::prepare(&self.account, self.device, self.context).unwrap()
    }

    fn proof(&self) -> device_auth::Proof {
        let request = self.request();
        let signature = self.ordinary.sign(request.message());
        request.finish(signature).unwrap()
    }
}

#[test]
fn round_trip() {
    let f = Fixture::new();
    let proof = f.proof();
    let bytes = proof.as_bytes();
    assert_eq!(bytes.len(), 234);
    assert_eq!(&bytes[0..2], &[0, 1]);
    assert_eq!(&bytes[2..34], &f.account.id().0);
    assert_eq!(&bytes[34..66], &f.device.0);
    assert_eq!(&bytes[66..74], &1u64.to_be_bytes());
    assert_eq!(&bytes[74..106], &f.account.head().hash);
    assert_eq!(&bytes[106..138], &[0x4b; 32]);
    assert_eq!(&bytes[138..170], &[0xa6; 32]);
    assert_eq!(
        &bytes[170..],
        &f.ordinary.sign(&[DOMAIN, &bytes[..170]].concat()),
    );
    let at = device_auth::verify_at(&f.account, f.context, bytes).unwrap();
    assert!(at.account() == f.account.id());
    assert!(at.device() == f.device);
    assert_eq!(at.head(), f.account.head());
}

#[test]
fn context_is_exact() {
    let f = Fixture::new();
    let proof = f.proof();
    let mut changed = f.context;
    changed.channel_binding[0] ^= 1;
    assert_eq!(
        device_auth::verify_at(&f.account, changed, proof.as_bytes()).err(),
        Some(Error::InvalidCredentials)
    );
    changed = f.context;
    changed.challenge[0] ^= 1;
    assert_eq!(
        device_auth::verify_at(&f.account, changed, proof.as_bytes()).err(),
        Some(Error::InvalidCredentials)
    );
    for offset in [106, 138] {
        let mut tampered = *proof.as_bytes();
        tampered[offset] ^= 1;
        assert_eq!(
            device_auth::verify_at(&f.account, f.context, &tampered).err(),
            Some(Error::InvalidCredentials)
        );
    }
}

#[test]
fn head_is_exact() {
    let f = Fixture::new();
    let proof = f.proof();
    let before = f.account.head();
    let add = f
        .account
        .add_device(
            f.device,
            DevicePublicKeys::new(
                SigningKey::generate().public(),
                SigningKey::generate().public(),
                KemKey::generate().public(),
            )
            .unwrap(),
        )
        .unwrap();
    let event = add.finish(f.control.sign(add.signing_bytes())).unwrap();
    let later = f
        .account
        .clone()
        .applied_batch(&[event.as_bytes()])
        .unwrap();
    assert_eq!(
        device_auth::verify_at(&later, f.context, proof.as_bytes()).err(),
        Some(Error::InvalidCredentials)
    );
    let other = Fixture::new();
    assert_eq!(
        device_auth::verify_at(&other.account, f.context, proof.as_bytes()).err(),
        Some(Error::WrongAccount)
    );
    let remove = later.remove_self(f.device).unwrap();
    let removal = remove
        .finish(f.control.sign(remove.signing_bytes()))
        .unwrap();
    let removed = later.clone().applied_batch(&[removal.as_bytes()]).unwrap();
    assert_eq!(
        device_auth::prepare(&removed, f.device, f.context).err(),
        Some(Error::NotActive)
    );
    assert_eq!(
        device_auth::verify_at(&removed, f.context, proof.as_bytes()).err(),
        Some(Error::InvalidCredentials)
    );
    assert_eq!(f.account.head(), before);
    assert!(!f.account.is_stopped());
    assert!(!later.is_stopped());
    assert!(!removed.is_stopped());
}

#[test]
fn ordinary_key_and_domain_only() {
    let f = Fixture::new();
    let request = f.request();
    assert_eq!(
        request.finish(f.control.sign(f.request().message())).err(),
        Some(Error::BadSignature)
    );
    assert_eq!(
        f.request()
            .finish(SigningKey::generate().sign(f.request().message()))
            .err(),
        Some(Error::BadSignature)
    );
    let unsigned_request = f.request();
    let unsigned = &unsigned_request.message()[DOMAIN.len()..];
    assert_eq!(
        f.request().finish(f.ordinary.sign(unsigned)).err(),
        Some(Error::BadSignature)
    );
    let mut forged = *f.proof().as_bytes();
    forged[170..].copy_from_slice(&f.control.sign(f.request().message()));
    assert_eq!(
        device_auth::verify_at(&f.account, f.context, &forged).err(),
        Some(Error::BadSignature)
    );
}

#[test]
fn strict_encoding() {
    let f = Fixture::new();
    let proof = f.proof();
    let before = f.account.head();
    for len in 0..234 {
        assert_eq!(
            device_auth::verify_at(&f.account, f.context, &proof.as_bytes()[..len]).err(),
            Some(Error::Malformed),
            "length {len}"
        );
    }
    let mut trailing = proof.as_bytes().to_vec();
    trailing.push(0);
    assert_eq!(
        device_auth::verify_at(&f.account, f.context, &trailing).err(),
        Some(Error::Malformed)
    );
    for version in [[0, 0], [0, 2], [1, 0]] {
        let mut changed = *proof.as_bytes();
        changed[..2].copy_from_slice(&version);
        assert_eq!(
            device_auth::verify_at(&f.account, f.context, &changed).err(),
            Some(Error::UnsupportedVersion)
        );
    }
    let mut changed = *proof.as_bytes();
    changed[233] ^= 1;
    assert_eq!(
        device_auth::verify_at(&f.account, f.context, &changed).err(),
        Some(Error::BadSignature)
    );
    assert_eq!(f.account.head(), before);
    assert!(!f.account.is_stopped());
}

#[test]
fn diagnostics_are_redacted() {
    let f = Fixture::new();
    let request = f.request();
    assert_eq!(format!("{request:?}"), "SigningRequest(..)");
    let proof = f.proof();
    assert_eq!(format!("{proof:?}"), "Proof(..)");
    let at = device_auth::verify_at(&f.account, f.context, proof.as_bytes()).unwrap();
    assert_eq!(format!("{at:?}"), "PossessionAtHead(..)");
    assert_eq!(format!("{:?}", Error::BadSignature), "BadSignature");
}
