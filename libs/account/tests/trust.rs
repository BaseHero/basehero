use bh_account::{
    AccountChange, AccountEvent, AccountId, ConfirmedTime, DeviceId, DevicePublicKeys, Error,
    RecoveryPublicKeys, RequestState, VerifiedAccount,
    crypto::{KemKey, SigningKey, hash},
    recovery::RecoveryKeys,
};

const DOMAIN: &[u8] = b"BaseHero account event\0";
const VERSION_AT: usize = DOMAIN.len();
const TAG_AT: usize = DOMAIN.len() + 2 + 2 + 8 + 32 + 32 + 32;

struct Device {
    ordinary: SigningKey,
    control: SigningKey,
    public: DevicePublicKeys,
}
impl Device {
    fn new() -> Self {
        let ordinary = SigningKey::generate();
        let control = SigningKey::generate();
        let public = DevicePublicKeys::new(
            ordinary.public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        Self {
            ordinary,
            control,
            public,
        }
    }
    fn id(&self) -> DeviceId {
        self.public.id()
    }
}

struct Fixture {
    mac: Device,
    fold: Device,
    recovery: RecoveryKeys,
    acct: VerifiedAccount,
}

fn t(earliest_ms: u64, latest_ms: u64) -> Option<ConfirmedTime> {
    Some(ConfirmedTime {
        earliest_ms,
        latest_ms,
    })
}

/// The Mac signs up with complete materials and adds the Fold.
fn setup() -> Fixture {
    let mac = Device::new();
    let fold = Device::new();
    let recovery = RecoveryKeys::generate();
    let draft = AccountEvent::genesis(mac.public.clone(), recovery.public());
    let genesis = draft
        .finish(mac.control.sign(draft.signing_bytes()))
        .unwrap();
    let mut acct =
        VerifiedAccount::from_genesis(AccountId::of_genesis(&genesis).unwrap(), genesis.as_bytes())
            .unwrap();
    let record = acct.prepare_recovery_record(mac.id(), [3; 32]).unwrap();
    let record = record
        .finish(mac.control.sign(record.signing_bytes()))
        .unwrap();
    acct.apply(record.as_bytes()).unwrap();
    let personal = acct
        .publish_personal_key(mac.id(), KemKey::generate().public(), [4; 32], [5; 32])
        .unwrap();
    let personal = personal
        .finish(mac.control.sign(personal.signing_bytes()))
        .unwrap();
    acct.apply(personal.as_bytes()).unwrap();
    let add = acct.add_device(mac.id(), fold.public.clone()).unwrap();
    let add = add.finish(mac.control.sign(add.signing_bytes())).unwrap();
    acct.apply(add.as_bytes()).unwrap();
    Fixture {
        mac,
        fold,
        recovery,
        acct,
    }
}

// Assemble a version-two event without the request builders, whose checks must
// not mask missing checks on incoming history.
fn wire(
    acct: &VerifiedAccount,
    author: DeviceId,
    tag: u8,
    signer: u8,
    body: &[u8],
    key: &SigningKey,
) -> Vec<u8> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(2u16.to_be_bytes());
    bytes.extend(2u16.to_be_bytes());
    bytes.extend((acct.head().position + 1).to_be_bytes());
    bytes.extend(acct.head().hash);
    bytes.extend(acct.id().0);
    bytes.extend(author.0);
    bytes.push(tag);
    bytes.push(signer);
    bytes.extend(body);
    bytes.extend(key.sign(&bytes));
    bytes
}

fn resign(bytes: &mut [u8], key: &SigningKey) {
    let split = bytes.len() - 64;
    let signature = key.sign(&bytes[..split]);
    bytes[split..].copy_from_slice(&signature);
}

fn device_bytes(keys: &DevicePublicKeys) -> Vec<u8> {
    [
        keys.signing().as_slice(),
        keys.control().as_slice(),
        keys.receiving().as_slice(),
    ]
    .concat()
}

fn rejects(acct: &VerifiedAccount, bytes: &[u8], expected: Error) {
    let mut candidate = acct.clone();
    let before = candidate.head();
    assert_eq!(candidate.apply_timed(bytes, t(20, 20)), Err(expected));
    assert_eq!(candidate.head(), before);
}

fn signed(request: bh_account::SigningRequest, key: &SigningKey) -> AccountEvent {
    request.finish(key.sign(request.signing_bytes())).unwrap()
}

fn cosigned(f: &Fixture, author: &Device, target: DeviceId) -> AccountEvent {
    let r = f.acct.remove_now(author.id(), target).unwrap();
    r.finish(
        author.control.sign(&r.device_signing_bytes()),
        r.sign_recovery(&f.recovery),
    )
    .unwrap()
}

#[test]
fn recovery_key_adds_a_device_as_version_two() {
    let mut f = setup();
    let phone = Device::new();
    let request = f.acct.add_device_by_recovery(phone.public.clone()).unwrap();
    assert_eq!(request.expected_key(), f.recovery.public().signing());
    let event = request.finish_with_recovery(&f.recovery).unwrap();
    assert_eq!(&event.as_bytes()[VERSION_AT..VERSION_AT + 4], &[0, 2, 0, 2]);
    f.acct.apply_timed(event.as_bytes(), t(10, 12)).unwrap();
    assert!(f.acct.active_device(phone.id()).is_ok());
    // Only the current recovery key signs as the recovery author.
    let other = RecoveryKeys::generate();
    let request = f.acct.add_device_by_recovery(Device::new().public).unwrap();
    assert_eq!(
        request.finish_with_recovery(&other).err(),
        Some(Error::BadSignature)
    );
}

#[test]
fn a_version_one_reader_pauses_on_new_tags() {
    let f = setup();
    let other = RecoveryKeys::generate().public();
    let events = [
        f.acct
            .add_device_by_recovery(Device::new().public)
            .unwrap()
            .finish_with_recovery(&f.recovery)
            .unwrap(),
        signed(
            f.acct.request_removal(f.mac.id(), f.fold.id()).unwrap(),
            &f.mac.control,
        ),
        f.acct
            .request_removal_by_recovery(f.fold.id())
            .unwrap()
            .finish_with_recovery(&f.recovery)
            .unwrap(),
        cosigned(&f, &f.mac, f.fold.id()),
        signed(
            f.acct.cancel_removal(f.mac.id(), 4).unwrap(),
            &f.mac.control,
        ),
        f.acct
            .cancel_removal_by_recovery(4)
            .unwrap()
            .finish_with_recovery(&f.recovery)
            .unwrap(),
        signed(
            f.acct
                .replace_recovery(f.mac.id(), other, [6; 32], [7; 32])
                .unwrap(),
            &f.mac.control,
        ),
        signed(
            f.acct
                .rotate_personal(f.mac.id(), 4, KemKey::generate().public(), [8; 32], [9; 32])
                .unwrap(),
            &f.mac.ordinary,
        ),
    ];
    for event in &events {
        // A version-one reader refuses any version but 1, as unsupported,
        // before reading the tag; it pauses rather than stopping.
        assert_eq!(&event.as_bytes()[VERSION_AT..VERSION_AT + 4], &[0, 2, 0, 2]);
        // This reader treats a still newer version the same way.
        let mut newer = event.as_bytes().to_vec();
        newer[VERSION_AT..VERSION_AT + 4].copy_from_slice(&[0, 3, 0, 3]);
        assert_eq!(
            AccountEvent::decode(&newer).err(),
            Some(Error::UnsupportedVersion)
        );
        rejects(&f.acct, &newer, Error::UnsupportedVersion);
    }
    // A device-signed addition stays version one, unchanged.
    let add = signed(
        f.acct.add_device(f.mac.id(), Device::new().public).unwrap(),
        &f.mac.control,
    );
    assert_eq!(&add.as_bytes()[VERSION_AT..VERSION_AT + 4], &[0, 1, 0, 1]);
}

#[test]
fn target_cannot_request_its_own_removal() {
    let f = setup();
    let (fold, mac) = (f.fold.id(), f.mac.id());
    let acct = &f.acct;
    assert_eq!(
        acct.request_removal(fold, fold).err(),
        Some(Error::NotPermitted)
    );
    assert_eq!(
        acct.request_removal(mac, DeviceId([1; 32])).err(),
        Some(Error::NotActive)
    );
    let own = wire(acct, fold, 5, 1, &fold.0, &f.fold.control);
    rejects(acct, &own, Error::NotPermitted);
    let missing = wire(acct, mac, 5, 1, &[1; 32], &f.mac.control);
    rejects(acct, &missing, Error::NotActive);
    // Immediate removal of oneself is not this control either.
    assert_eq!(acct.remove_now(mac, mac).err(), Some(Error::NotPermitted));
}

#[test]
fn removal_request_needs_a_second_key_or_the_recovery_key() {
    let f = setup();
    let (fold, mac) = (f.fold.id(), f.mac.id());
    let request = f.acct.request_removal(mac, fold).unwrap();
    assert_eq!(request.expected_key(), f.mac.public.control());
    let ordinary = wire(&f.acct, mac, 5, 1, &fold.0, &f.mac.ordinary);
    rejects(&f.acct, &ordinary, Error::BadSignature);
    let control = wire(&f.acct, mac, 5, 1, &fold.0, &f.mac.control);
    let mut acct = f.acct.clone();
    acct.apply_timed(&control, t(10, 10)).unwrap();
    assert!(
        acct.active_device(fold).is_ok(),
        "a request removes nothing yet"
    );

    let author = f.acct.recovery_author().unwrap();
    let by_recovery = f.acct.request_removal_by_recovery(fold).unwrap();
    assert_eq!(by_recovery.expected_key(), f.recovery.public().signing());
    let event = by_recovery.finish_with_recovery(&f.recovery).unwrap();
    f.acct
        .clone()
        .apply_timed(event.as_bytes(), t(10, 10))
        .unwrap();
    // The recovery author's role cannot be claimed with a device's key.
    let forged = wire(&f.acct, author, 5, 2, &fold.0, &f.mac.control);
    rejects(&f.acct, &forged, Error::BadSignature);
    // Nor can a device id claim the recovery key's role.
    let claimed = wire(&f.acct, mac, 5, 2, &fold.0, &f.mac.control);
    rejects(&f.acct, &claimed, Error::NotActive);
}

#[test]
fn remove_now_signatures_cover_the_same_unsigned_bytes_with_distinct_roles() {
    let f = setup();
    let (fold, mac) = (f.fold.id(), f.mac.id());
    let r = f.acct.remove_now(mac, fold).unwrap();
    assert_eq!(r.device_key(), f.mac.public.control());
    assert_eq!(r.recovery_key(), f.recovery.public().signing());
    let device = f.mac.control.sign(&r.device_signing_bytes());
    let recovery = r.sign_recovery(&f.recovery);
    let event = r.finish(device, recovery).unwrap();
    let unsigned_len = event.as_bytes().len() - 128;
    let unsigned = &event.as_bytes()[..unsigned_len];
    assert_ne!(r.device_signing_bytes(), r.recovery_signing_bytes());
    assert_eq!(
        &r.device_signing_bytes()[r.device_signing_bytes().len() - unsigned_len..],
        &r.recovery_signing_bytes()[r.recovery_signing_bytes().len() - unsigned_len..]
    );
    assert_eq!(
        r.device_signing_bytes(),
        [b"BaseHero account cosign\0".as_slice(), &[1], unsigned].concat()
    );
    assert_eq!(
        r.recovery_signing_bytes(),
        [b"BaseHero account cosign\0".as_slice(), &[2], unsigned].concat()
    );
    assert_eq!(event.as_bytes(), [unsigned, &device, &recovery].concat());
    assert_eq!(r.finish(recovery, device).err(), Some(Error::BadSignature));
    rejects(&f.acct, event.as_bytes(), Error::NotMature);

    let with = |device: [u8; 64], recovery: [u8; 64]| {
        [unsigned, device.as_slice(), recovery.as_slice()].concat()
    };
    rejects(&f.acct, &with(recovery, device), Error::BadSignature);
    rejects(&f.acct, &with(device, [0; 64]), Error::BadSignature);
    rejects(&f.acct, &with([0; 64], recovery), Error::BadSignature);
    // The device key over the recovery role's bytes, or the plain event bytes;
    // the recovery key's side is a unit test, as only the crate signs raw bytes.
    let crossed = with(f.mac.control.sign(&r.recovery_signing_bytes()), recovery);
    rejects(&f.acct, &crossed, Error::BadSignature);
    let plain = with(f.mac.control.sign(unsigned), recovery);
    rejects(&f.acct, &plain, Error::BadSignature);
    // Signatures for another removal.
    let elsewhere = f.acct.remove_now(fold, mac).unwrap();
    let foreign = with(
        f.fold.control.sign(&elsewhere.device_signing_bytes()),
        elsewhere.sign_recovery(&f.recovery),
    );
    rejects(&f.acct, &foreign, Error::BadSignature);
    // The ordinary key cannot stand in for the device's second key.
    let ordinary = with(f.mac.ordinary.sign(&r.device_signing_bytes()), recovery);
    rejects(&f.acct, &ordinary, Error::BadSignature);
}

#[test]
fn time_dependent_controls_need_maturity_or_an_established_effect() {
    let f = setup();
    let (fold, mac) = (f.fold.id(), f.mac.id());
    let far = t(u64::MAX / 2, u64::MAX / 2);
    // As the first confirmed entry, an immediate removal finds every device
    // newly matured from it, so not yet mature.
    let now = cosigned(&f, &f.mac, fold);
    assert_eq!(
        f.acct.clone().apply_timed(now.as_bytes(), far),
        Err(Error::NotMature)
    );
    let mut acct = f.acct.clone();
    acct.apply_timed(
        signed(acct.request_removal(mac, fold).unwrap(), &f.mac.control).as_bytes(),
        t(10, 10),
    )
    .unwrap();
    let request = acct.head().position;
    let early = signed(acct.cancel_removal(mac, request).unwrap(), &f.mac.control);
    assert_eq!(
        acct.clone().apply_timed(early.as_bytes(), t(11, 11)),
        Err(Error::NotMature)
    );
    let rotate = signed(
        acct.rotate_personal(mac, request, KemKey::generate().public(), [8; 32], [9; 32])
            .unwrap(),
        &f.mac.ordinary,
    );
    assert_eq!(
        acct.clone().apply_timed(rotate.as_bytes(), t(11, 11)),
        Err(Error::TooEarly)
    );
    let cancel = acct
        .cancel_removal_by_recovery(request)
        .unwrap()
        .finish_with_recovery(&f.recovery)
        .unwrap();
    acct.clone()
        .apply_timed(cancel.as_bytes(), t(11, 11))
        .unwrap();
    // Far later, the Mac has matured and the removal has taken effect.
    acct.clone().apply_timed(early.as_bytes(), far).unwrap();
    acct.clone().apply_timed(rotate.as_bytes(), far).unwrap();
    assert_eq!(bh_account::REMOVAL_WAIT_MS, 3 * 24 * 60 * 60 * 1000);
}

#[test]
fn the_recovery_author_cannot_sign_as_a_device() {
    let f = setup();
    let author = f.acct.recovery_author().unwrap();
    let fold = f.fold.id();
    let as_device = wire(&f.acct, author, 5, 1, &fold.0, &f.mac.control);
    rejects(&f.acct, &as_device, Error::NotActive);
}

#[test]
fn replacing_the_recovery_key_lapses_its_pending_requests() {
    let mut f = setup();
    let fold = f.fold.id();
    let by_recovery = f
        .acct
        .request_removal_by_recovery(fold)
        .unwrap()
        .finish_with_recovery(&f.recovery)
        .unwrap();
    f.acct
        .apply_timed(by_recovery.as_bytes(), t(10, 10))
        .unwrap();
    let stale = f.acct.head().position;
    let by_mac = signed(
        f.acct.request_removal(f.mac.id(), fold).unwrap(),
        &f.mac.control,
    );
    f.acct.apply_timed(by_mac.as_bytes(), t(10, 10)).unwrap();
    let kept = f.acct.head().position;
    let replace = signed(
        f.acct
            .replace_recovery(
                f.mac.id(),
                RecoveryKeys::generate().public(),
                [6; 32],
                [7; 32],
            )
            .unwrap(),
        &f.mac.control,
    );
    f.acct.apply_timed(replace.as_bytes(), t(11, 11)).unwrap();
    assert_eq!(f.acct.request_state(stale, 11), Ok(RequestState::Lapsed));
    let deadline_ms = 10 + bh_account::REMOVAL_WAIT_MS;
    assert_eq!(
        f.acct.request_state(kept, 11),
        Ok(RequestState::Pending { deadline_ms })
    );
    let pending: Vec<_> = f
        .acct
        .pending_removals(11)
        .iter()
        .map(|p| p.request)
        .collect();
    assert_eq!(pending, [kept]);
}

#[test]
fn personal_keys_are_never_reused_as_other_keys() {
    let mut f = setup();
    let mac = f.mac.id();
    let initial = *f.acct.personal_public().unwrap();
    let device = |receiving| {
        DevicePublicKeys::new(
            SigningKey::generate().public(),
            SigningKey::generate().public(),
            receiving,
        )
        .unwrap()
    };
    let as_device = device_bytes(&device(initial));
    let mut incoming = wire(&f.acct, mac, 1, 1, &as_device, &f.mac.control);
    // A device addition is version one, with no signer byte.
    incoming.remove(TAG_AT + 1);
    incoming[VERSION_AT..VERSION_AT + 4].copy_from_slice(&[0, 1, 0, 1]);
    resign(&mut incoming, &f.mac.control);
    rejects(&f.acct, &incoming, Error::KeyReuse);
    let next = RecoveryKeys::generate().public();
    let replace = signed(
        f.acct
            .replace_recovery(mac, next.clone(), [6; 32], [7; 32])
            .unwrap(),
        &f.mac.control,
    );
    f.acct.apply_timed(replace.as_bytes(), t(10, 10)).unwrap();
    let replaced = f.acct.head().position;
    let rotated = KemKey::generate().public();
    let rotate = signed(
        f.acct
            .rotate_personal(mac, replaced, rotated, [8; 32], [9; 32])
            .unwrap(),
        &f.mac.ordinary,
    );
    f.acct.apply_timed(rotate.as_bytes(), t(10, 10)).unwrap();
    assert_eq!(f.acct.personal_public().unwrap(), &rotated);

    // Neither personal key, the earlier or the current, may return as a
    // recovery or device receiving key.
    for used in [initial, rotated] {
        let recovery = RecoveryPublicKeys::new(SigningKey::generate().public(), used);
        assert_eq!(
            f.acct
                .replace_recovery(mac, recovery.clone(), [1; 32], [1; 32])
                .err(),
            Some(Error::KeyReuse)
        );
        let mut body = [recovery.signing().as_slice(), recovery.receiving()].concat();
        body.extend([1; 64]);
        let incoming = wire(&f.acct, mac, 8, 1, &body, &f.mac.control);
        rejects(&f.acct, &incoming, Error::KeyReuse);
        assert_eq!(
            f.acct.add_device(mac, device(used)).err(),
            Some(Error::KeyReuse)
        );
    }
    // Nor may a rotation bring back a personal key, or reuse a device's or
    // a recovery key's, retired or current.
    let left = signed(f.acct.remove_self(f.fold.id()).unwrap(), &f.fold.control);
    f.acct.apply_timed(left.as_bytes(), t(11, 11)).unwrap();
    let removed = f.acct.head().position;
    for used in [
        initial,
        rotated,
        *f.fold.public.receiving(),
        *f.mac.public.receiving(),
        *f.recovery.public().receiving(),
        *next.receiving(),
    ] {
        let again = signed(
            f.acct
                .rotate_personal(mac, removed, used, [8; 32], [9; 32])
                .unwrap(),
            &f.mac.ordinary,
        );
        rejects(&f.acct, again.as_bytes(), Error::KeyReuse);
    }
}

#[test]
fn replace_recovery_retires_the_old_recovery_author() {
    let mut f = setup();
    let old_author = f.acct.recovery_author().unwrap();
    assert_eq!(f.acct.record_digest(), Ok([3; 32]));
    let next = RecoveryKeys::generate();
    let request = f
        .acct
        .replace_recovery(f.mac.id(), next.public(), [6; 32], [7; 32])
        .unwrap();
    assert_eq!(request.expected_key(), f.mac.public.control());
    let ordinary = wire(
        &f.acct,
        f.mac.id(),
        8,
        1,
        &request.signing_bytes()[TAG_AT + 2..],
        &f.mac.ordinary,
    );
    rejects(&f.acct, &ordinary, Error::BadSignature);
    // A recovery key cannot replace itself.
    let by_recovery = wire(
        &f.acct,
        old_author,
        8,
        2,
        &request.signing_bytes()[TAG_AT + 2..],
        &SigningKey::generate(),
    );
    rejects(&f.acct, &by_recovery, Error::Malformed);
    let event = signed(request, &f.mac.control);
    f.acct.apply_timed(event.as_bytes(), t(10, 10)).unwrap();
    assert_eq!(f.acct.record_digest(), Ok([6; 32]));
    assert!(f.acct.recovery_keys().unwrap() == &next.public());
    assert!(f.acct.recovery_author().unwrap() != old_author);

    // The old recovery key's author is no longer a signer.
    let phone = Device::new();
    let stale = wire(
        &f.acct,
        old_author,
        1,
        2,
        &device_bytes(&phone.public),
        &SigningKey::generate(),
    );
    rejects(&f.acct, &stale, Error::NotActive);
    let fresh = f.acct.add_device_by_recovery(phone.public.clone()).unwrap();
    assert_eq!(
        fresh.finish_with_recovery(&f.recovery).err(),
        Some(Error::BadSignature)
    );
    let fresh = fresh.finish_with_recovery(&next).unwrap();
    f.acct.apply_timed(fresh.as_bytes(), t(11, 11)).unwrap();

    // Neither the retired recovery keys nor a device's keys may return.
    for reused in [
        f.recovery.public(),
        RecoveryPublicKeys::new(*f.fold.public.control(), KemKey::generate().public()),
        RecoveryPublicKeys::new(SigningKey::generate().public(), *phone.public.receiving()),
    ] {
        assert_eq!(
            f.acct
                .replace_recovery(f.mac.id(), reused.clone(), [1; 32], [1; 32])
                .err(),
            Some(Error::KeyReuse)
        );
        let mut body = [reused.signing().as_slice(), reused.receiving()].concat();
        body.extend([1; 64]);
        let incoming = wire(&f.acct, f.mac.id(), 8, 1, &body, &f.mac.control);
        rejects(&f.acct, &incoming, Error::KeyReuse);
    }
}

#[test]
fn rotation_must_be_signed_with_the_ordinary_key() {
    let f = setup();
    let request = f
        .acct
        .rotate_personal(f.mac.id(), 4, KemKey::generate().public(), [8; 32], [9; 32])
        .unwrap();
    assert_eq!(request.expected_key(), f.mac.public.signing());
    assert_eq!(
        request
            .finish(f.mac.control.sign(request.signing_bytes()))
            .err(),
        Some(Error::BadSignature)
    );
    let mut rotation = signed(
        f.acct
            .rotate_personal(f.mac.id(), 4, KemKey::generate().public(), [8; 32], [9; 32])
            .unwrap(),
        &f.mac.ordinary,
    )
    .as_bytes()
    .to_vec();
    // Position 4 added the Fold: not an effect a rotation can follow.
    rejects(&f.acct, &rotation, Error::NotPermitted);
    resign(&mut rotation, &f.mac.control);
    rejects(&f.acct, &rotation, Error::BadSignature);
    let author = f.acct.recovery_author().unwrap();
    let mut by_recovery = rotation.clone();
    by_recovery[TAG_AT - 32..TAG_AT].copy_from_slice(&author.0);
    by_recovery[TAG_AT + 1] = 2;
    resign(&mut by_recovery, &SigningKey::generate());
    rejects(&f.acct, &by_recovery, Error::Malformed);
}

#[test]
fn changes_describe_each_event() {
    let mut f = setup();
    let (fold, mac) = (f.fold.id(), f.mac.id());
    let phone = Device::new();
    let added = f
        .acct
        .add_device_by_recovery(phone.public.clone())
        .unwrap()
        .finish_with_recovery(&f.recovery)
        .unwrap();
    assert!(
        added.change()
            == AccountChange::DeviceAdded {
                device: phone.id(),
                by_recovery: true,
                by: None,
            }
    );
    f.acct.apply_timed(added.as_bytes(), t(10, 10)).unwrap();
    let tablet = Device::new();
    let by_device = signed(
        f.acct.add_device(mac, tablet.public.clone()).unwrap(),
        &f.mac.control,
    );
    assert!(
        by_device.change()
            == AccountChange::DeviceAdded {
                device: tablet.id(),
                by_recovery: false,
                by: Some(mac),
            }
    );
    let request = signed(f.acct.request_removal(mac, fold).unwrap(), &f.mac.control);
    let position = request.head().position;
    assert!(
        request.change()
            == AccountChange::RemovalRequested {
                request: position,
                target: fold,
                by: Some(mac),
            }
    );
    let by_recovery = f
        .acct
        .request_removal_by_recovery(fold)
        .unwrap()
        .finish_with_recovery(&f.recovery)
        .unwrap();
    assert!(
        by_recovery.change()
            == AccountChange::RemovalRequested {
                request: position,
                target: fold,
                by: None,
            }
    );
    assert!(
        cosigned(&f, &f.mac, fold).change()
            == AccountChange::RemovedNow {
                target: fold,
                by: mac
            }
    );
    let cancel = signed(f.acct.cancel_removal(fold, 9).unwrap(), &f.fold.control);
    assert!(
        cancel.change()
            == AccountChange::RemovalCancelled {
                request: 9,
                by: Some(fold)
            }
    );
    let cancel = f
        .acct
        .cancel_removal_by_recovery(9)
        .unwrap()
        .finish_with_recovery(&f.recovery)
        .unwrap();
    assert!(
        cancel.change()
            == AccountChange::RemovalCancelled {
                request: 9,
                by: None
            }
    );
    let replaced = signed(
        f.acct
            .replace_recovery(mac, RecoveryKeys::generate().public(), [6; 32], [7; 32])
            .unwrap(),
        &f.mac.control,
    );
    assert!(replaced.change() == AccountChange::RecoveryReplaced { by: mac });
    let rotated = signed(
        f.acct
            .rotate_personal(fold, 9, KemKey::generate().public(), [8; 32], [9; 32])
            .unwrap(),
        &f.fold.ordinary,
    );
    assert!(
        rotated.change()
            == AccountChange::PersonalRotated {
                reason: 9,
                by: fold
            }
    );
    let left = signed(f.acct.remove_self(fold).unwrap(), &f.fold.control);
    assert!(left.change() == AccountChange::DeviceRemovedSelf { device: fold });
    let first = Device::new();
    let genesis = signed(
        AccountEvent::genesis(first.public.clone(), RecoveryKeys::generate().public()),
        &first.control,
    );
    assert!(genesis.change() == AccountChange::Setup);
}

#[test]
fn strict_decoding_of_new_tags() {
    let f = setup();
    let (fold, mac) = (f.fold.id(), f.mac.id());
    let request = signed(f.acct.request_removal(mac, fold).unwrap(), &f.mac.control);
    let now = cosigned(&f, &f.mac, fold);
    let replace = signed(
        f.acct
            .replace_recovery(mac, RecoveryKeys::generate().public(), [6; 32], [7; 32])
            .unwrap(),
        &f.mac.control,
    );
    let rotate = signed(
        f.acct
            .rotate_personal(mac, 4, KemKey::generate().public(), [8; 32], [9; 32])
            .unwrap(),
        &f.mac.ordinary,
    );
    for event in [&request, &now, &replace, &rotate] {
        let bytes = event.as_bytes();
        assert!(AccountEvent::decode(bytes).is_ok());
        for end in 0..bytes.len() {
            assert!(AccountEvent::decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert_eq!(
            AccountEvent::decode(&trailing).err(),
            Some(Error::Malformed)
        );
    }
    let bytes = request.as_bytes();
    // A new tag under version one never existed.
    let mut old = bytes.to_vec();
    old[VERSION_AT..VERSION_AT + 4].copy_from_slice(&[0, 1, 0, 1]);
    old.remove(TAG_AT + 1);
    assert_eq!(AccountEvent::decode(&old).err(), Some(Error::Malformed));
    // Signer roles: unknown, or not allowed for the tag.
    for (event, signer) in [
        (&request, 0),
        (&request, 3),
        (&now, 2),
        (&replace, 2),
        (&rotate, 2),
    ] {
        let mut changed = event.as_bytes().to_vec();
        changed[TAG_AT + 1] = signer;
        assert_eq!(
            AccountEvent::decode(&changed).err(),
            Some(Error::Malformed),
            "tag {} signer {signer}",
            changed[TAG_AT]
        );
    }
    // Version two defines no device-signed addition or setup tags.
    let add = signed(
        f.acct.add_device(mac, Device::new().public).unwrap(),
        &f.mac.control,
    );
    let mut add = add.as_bytes().to_vec();
    add[VERSION_AT..VERSION_AT + 4].copy_from_slice(&[0, 2, 0, 2]);
    add.insert(TAG_AT + 1, 1);
    assert_eq!(AccountEvent::decode(&add).err(), Some(Error::Malformed));
    for tag in [0, 2, 3, 4] {
        let mut setup = bytes.to_vec();
        setup[TAG_AT] = tag;
        assert_eq!(AccountEvent::decode(&setup).err(), Some(Error::Malformed));
    }
    let mut unknown = bytes.to_vec();
    unknown[TAG_AT] = 10;
    assert_eq!(
        AccountEvent::decode(&unknown).err(),
        Some(Error::UnsupportedControl)
    );
    // A version-two event still requires a version-two reader.
    let mut stale = bytes.to_vec();
    stale[VERSION_AT + 2..VERSION_AT + 4].copy_from_slice(&[0, 1]);
    assert_eq!(
        AccountEvent::decode(&stale).err(),
        Some(Error::UnsupportedVersion)
    );
    assert_eq!(hash(bytes), request.head().hash);
}
