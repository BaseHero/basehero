use bh_account::{
    AccountEvent, AccountId, DeviceId, DevicePublicKeys, Error, RecoveryPublicKeys,
    VerifiedAccount,
    crypto::{KemKey, SigningKey, hash},
};

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
}
fn setup() -> (Device, AccountEvent, VerifiedAccount) {
    let first = Device::new();
    let recovery =
        RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public());
    let draft = AccountEvent::genesis(first.public.clone(), recovery);
    let event = draft
        .finish(first.control.sign(draft.signing_bytes()))
        .unwrap();
    let account =
        VerifiedAccount::from_genesis(AccountId::of_genesis(&event).unwrap(), event.as_bytes())
            .unwrap();
    (first, event, account)
}

// Assemble the documented wire format without the local request builder, whose
// checks must not mask missing checks on incoming untrusted history.
fn wire_event(
    account: AccountId,
    position: u64,
    previous: [u8; 32],
    author: DeviceId,
    tag: u8,
    body: &[u8],
    signer: &SigningKey,
) -> Vec<u8> {
    let mut bytes = b"BaseHero account event\0".to_vec();
    bytes.extend(1u16.to_be_bytes());
    bytes.extend(1u16.to_be_bytes());
    bytes.extend(position.to_be_bytes());
    bytes.extend(previous);
    bytes.extend(account.0);
    bytes.extend(author.0);
    bytes.push(tag);
    bytes.extend(body);
    bytes.extend(signer.sign(&bytes));
    bytes
}

fn device_bytes(keys: &DevicePublicKeys) -> Vec<u8> {
    [
        keys.signing().as_slice(),
        keys.control().as_slice(),
        keys.receiving().as_slice(),
    ]
    .concat()
}

fn incoming(
    account: &VerifiedAccount,
    author: &Device,
    tag: u8,
    body: &[u8],
    signer: &SigningKey,
) -> Vec<u8> {
    wire_event(
        account.id(),
        account.head().position + 1,
        account.head().hash,
        author.public.id(),
        tag,
        body,
        signer,
    )
}

fn assert_integrity_stop(
    mut account: VerifiedAccount,
    author: DeviceId,
    bytes: &[u8],
    expected: Error,
) {
    let before = account.head();
    assert_eq!(account.apply(bytes), Err(expected));
    assert_eq!(account.head(), before);
    assert!(account.is_stopped());
    // In particular, forged removal must never look like verified removal.
    assert_eq!(account.active_device(author).err(), Some(Error::Stopped));
    assert_eq!(account.apply(bytes), Err(Error::Stopped));
}

#[test]
fn incoming_genesis_requires_signature_even_with_matching_hash_anchor() {
    let first = Device::new();
    let mut body = device_bytes(&first.public);
    body.extend(SigningKey::generate().public());
    body.extend(KemKey::generate().public());
    let valid = wire_event(
        AccountId([0; 32]),
        1,
        [0; 32],
        first.public.id(),
        0,
        &body,
        &first.control,
    );
    assert!(VerifiedAccount::from_genesis(AccountId(hash(&valid)), &valid).is_ok());
    let mut invalid = valid;
    *invalid.last_mut().unwrap() ^= 1;
    // Recompute the anchor: this must fail signature verification, not id matching.
    assert_eq!(
        VerifiedAccount::from_genesis(AccountId(hash(&invalid)), &invalid).err(),
        Some(Error::BadSignature)
    );
}

#[test]
fn incoming_addition_and_removal_require_control_not_ordinary_signature() {
    let (first, _, account) = setup();
    for (tag, body) in [(1, device_bytes(&Device::new().public)), (2, Vec::new())] {
        let valid = incoming(&account, &first, tag, &body, &first.control);
        assert!(account.clone().apply(&valid).is_ok());
        let ordinary = incoming(&account, &first, tag, &body, &first.ordinary);
        assert_integrity_stop(
            account.clone(),
            first.public.id(),
            &ordinary,
            Error::BadSignature,
        );
    }
}

#[test]
fn incoming_signed_additions_cannot_reuse_historic_or_recovery_keys() {
    let (first, _, mut account) = setup();
    let second = Device::new();
    account
        .apply(&incoming(
            &account,
            &first,
            1,
            &device_bytes(&second.public),
            &first.control,
        ))
        .unwrap();
    account
        .apply(&incoming(&account, &first, 2, &[], &first.control))
        .unwrap();
    assert_eq!(
        account.active_device(first.public.id()).err(),
        Some(Error::NotActive)
    );
    let third = Device::new();
    account
        .apply(&incoming(
            &account,
            &second,
            1,
            &device_bytes(&third.public),
            &second.control,
        ))
        .unwrap();
    account
        .apply(&incoming(&account, &third, 2, &[], &third.control))
        .unwrap();
    assert_eq!(
        account.active_device(third.public.id()).err(),
        Some(Error::NotActive)
    );
    let fresh = Device::new();
    let recovery = account.recovery_keys().unwrap();
    let cases = [
        (first.public.clone(), Error::DuplicateDevice),
        // Reusing only part of a removed identity still must not bypass history.
        (
            DevicePublicKeys::new(
                *first.public.signing(),
                *fresh.public.control(),
                *fresh.public.receiving(),
            )
            .unwrap(),
            Error::KeyReuse,
        ),
        // Both currently active and removed devices added after genesis must
        // remain in the index; control keys cannot be reused as signing keys.
        (
            DevicePublicKeys::new(
                *second.public.signing(),
                *fresh.public.control(),
                *fresh.public.receiving(),
            )
            .unwrap(),
            Error::KeyReuse,
        ),
        (
            DevicePublicKeys::new(
                *third.public.signing(),
                *fresh.public.control(),
                *fresh.public.receiving(),
            )
            .unwrap(),
            Error::KeyReuse,
        ),
        (
            DevicePublicKeys::new(
                *second.public.control(),
                *fresh.public.control(),
                *fresh.public.receiving(),
            )
            .unwrap(),
            Error::KeyReuse,
        ),
        (
            DevicePublicKeys::new(
                *third.public.control(),
                *fresh.public.control(),
                *fresh.public.receiving(),
            )
            .unwrap(),
            Error::KeyReuse,
        ),
        (
            DevicePublicKeys::new(
                *fresh.public.signing(),
                *fresh.public.control(),
                *second.public.receiving(),
            )
            .unwrap(),
            Error::KeyReuse,
        ),
        (
            DevicePublicKeys::new(
                *fresh.public.signing(),
                *fresh.public.control(),
                *third.public.receiving(),
            )
            .unwrap(),
            Error::KeyReuse,
        ),
        (
            DevicePublicKeys::new(
                *recovery.signing(),
                *fresh.public.control(),
                *fresh.public.receiving(),
            )
            .unwrap(),
            Error::KeyReuse,
        ),
        (
            DevicePublicKeys::new(
                *fresh.public.signing(),
                *recovery.signing(),
                *fresh.public.receiving(),
            )
            .unwrap(),
            Error::KeyReuse,
        ),
        (
            DevicePublicKeys::new(
                *fresh.public.signing(),
                *fresh.public.control(),
                *recovery.receiving(),
            )
            .unwrap(),
            Error::KeyReuse,
        ),
    ];
    let valid = incoming(
        &account,
        &second,
        1,
        &device_bytes(&fresh.public),
        &second.control,
    );
    assert!(account.clone().apply(&valid).is_ok());
    for (keys, error) in cases {
        let bytes = incoming(&account, &second, 1, &device_bytes(&keys), &second.control);
        assert_integrity_stop(account.clone(), second.public.id(), &bytes, error);
    }
}

#[test]
fn trailing_bytes_on_short_controls_are_rejected_below_the_size_cap() {
    let (first, genesis, account) = setup();
    for (tag, body) in [(1, device_bytes(&Device::new().public)), (2, Vec::new())] {
        let mut bytes = incoming(&account, &first, tag, &body, &first.control);
        assert!(AccountEvent::decode(&bytes).is_ok());
        bytes.push(0);
        assert!(bytes.len() < genesis.as_bytes().len());
        assert_eq!(AccountEvent::decode(&bytes).err(), Some(Error::Malformed));
        assert_integrity_stop(account.clone(), first.public.id(), &bytes, Error::Malformed);
    }
}

#[test]
fn genesis_and_admission_replay_from_explicit_anchor() {
    let (first, genesis, mut account) = setup();
    let next = Device::new();
    let draft = account
        .add_device(first.public.id(), next.public.clone())
        .unwrap();
    let event = draft
        .finish(first.control.sign(draft.signing_bytes()))
        .unwrap();
    account.apply(event.as_bytes()).unwrap();
    assert_eq!(account.head().position, 2);
    assert_eq!(
        account.active_device(next.public.id()).unwrap(),
        &next.public
    );
    let checkpoint = account.head();
    let restored = VerifiedAccount::replay(
        account.id(),
        &[genesis.as_bytes(), event.as_bytes()],
        checkpoint,
    )
    .unwrap();
    assert_eq!(restored.head(), checkpoint);
    assert_eq!(
        restored.active_device(first.public.id()).unwrap(),
        &first.public
    );
}

#[test]
fn ordinary_key_cannot_authorize_device_admission() {
    let (first, _, account) = setup();
    let draft = account
        .add_device(first.public.id(), Device::new().public)
        .unwrap();
    assert_eq!(
        draft
            .finish(first.ordinary.sign(draft.signing_bytes()))
            .err(),
        Some(Error::BadSignature)
    );
}

#[test]
fn tampered_remote_event_stops_without_mutating_verified_state() {
    let (first, _, mut account) = setup();
    let draft = account
        .add_device(first.public.id(), Device::new().public)
        .unwrap();
    let event = draft
        .finish(first.control.sign(draft.signing_bytes()))
        .unwrap();
    let before = account.head();
    let mut corrupt = event.as_bytes().to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    assert_eq!(account.apply(&corrupt), Err(Error::BadSignature));
    assert_eq!(account.head(), before);
    assert!(account.is_stopped());
    assert_eq!(account.apply(event.as_bytes()), Err(Error::Stopped));
    assert_eq!(
        account.active_device(first.public.id()).err(),
        Some(Error::Stopped)
    );
}

#[test]
fn fork_and_rollback_do_not_replace_a_remembered_head() {
    let (first, genesis, mut account) = setup();
    let make = || {
        let draft = account
            .add_device(first.public.id(), Device::new().public)
            .unwrap();
        draft
            .finish(first.control.sign(draft.signing_bytes()))
            .unwrap()
    };
    let a = make();
    let b = make();
    account.apply(a.as_bytes()).unwrap();
    let pinned = account.head();
    assert_eq!(
        VerifiedAccount::replay(account.id(), &[genesis.as_bytes(), b.as_bytes()], pinned).err(),
        Some(Error::Fork)
    );
    assert_eq!(
        VerifiedAccount::replay(account.id(), &[genesis.as_bytes()], pinned).err(),
        Some(Error::TruncatedHistory)
    );
    let before = account.head();
    assert_eq!(account.apply(b.as_bytes()), Err(Error::WrongPredecessor));
    assert_eq!(account.head(), before);
}

#[test]
fn self_removal_disables_signing_and_readdition_with_the_same_keys() {
    let (first, _, mut account) = setup();
    let second = Device::new();
    let draft = account
        .add_device(first.public.id(), second.public.clone())
        .unwrap();
    let add = draft
        .finish(first.control.sign(draft.signing_bytes()))
        .unwrap();
    account.apply(add.as_bytes()).unwrap();
    let draft = account.remove_self(first.public.id()).unwrap();
    let remove = draft
        .finish(first.control.sign(draft.signing_bytes()))
        .unwrap();
    account.apply(remove.as_bytes()).unwrap();
    assert_eq!(
        account.active_device(first.public.id()).err(),
        Some(Error::NotActive)
    );
    assert_eq!(
        account
            .add_device(first.public.id(), Device::new().public)
            .err(),
        Some(Error::NotActive)
    );
    assert_eq!(
        account.add_device(second.public.id(), first.public).err(),
        Some(Error::DuplicateDevice)
    );
}

#[test]
fn unknown_controls_versions_and_trailing_bytes_are_rejected() {
    let (_, genesis, account) = setup();
    let domain_len = b"BaseHero account event\0".len();
    let mut future = genesis.as_bytes().to_vec();
    future[domain_len + 1] = 2;
    assert_eq!(
        AccountEvent::decode(&future).err(),
        Some(Error::UnsupportedVersion)
    );
    let mut control = genesis.as_bytes().to_vec();
    control[domain_len + 2 + 2 + 8 + 32 + 32 + 32] = 200;
    assert_eq!(
        AccountEvent::decode(&control).err(),
        Some(Error::UnsupportedControl)
    );
    let mut trailing = genesis.as_bytes().to_vec();
    trailing.push(0);
    assert_eq!(
        AccountEvent::decode(&trailing).err(),
        Some(Error::Malformed)
    );
    for end in 0..genesis.as_bytes().len() {
        assert!(AccountEvent::decode(&genesis.as_bytes()[..end]).is_err());
    }
    assert_eq!(
        VerifiedAccount::from_genesis(AccountId([7; 32]), genesis.as_bytes()).err(),
        Some(Error::WrongAccount)
    );
    assert_eq!(account.head().position, 1);
}

#[test]
fn a_batch_is_atomic_even_if_its_tail_is_invalid() {
    let (first, _, mut account) = setup();
    let draft = account
        .add_device(first.public.id(), Device::new().public)
        .unwrap();
    let event = draft
        .finish(first.control.sign(draft.signing_bytes()))
        .unwrap();
    let before = account.head();
    assert_eq!(
        account.apply_batch(&[event.as_bytes(), b"invalid"]),
        Err(Error::Malformed)
    );
    assert_eq!(account.head(), before);
    assert!(account.is_stopped());
}

#[test]
fn account_substitution_and_cross_role_key_reuse_are_refused() {
    let (first, _, mut account) = setup();
    let second = Device::new();
    let reused = DevicePublicKeys::new(
        first.public.control().to_owned(),
        second.control.public(),
        second.public.receiving().to_owned(),
    )
    .unwrap();
    assert_eq!(
        account.add_device(first.public.id(), reused).err(),
        Some(Error::KeyReuse)
    );
    let draft = account
        .add_device(first.public.id(), second.public)
        .unwrap();
    let event = draft
        .finish(first.control.sign(draft.signing_bytes()))
        .unwrap();
    let mut foreign = event.as_bytes().to_vec();
    let account_offset = b"BaseHero account event\0".len() + 2 + 2 + 8 + 32;
    foreign[account_offset] ^= 1;
    let split = foreign.len() - 64;
    let signature = first.control.sign(&foreign[..split]);
    foreign[split..].copy_from_slice(&signature);
    let before = account.head();
    assert_eq!(account.apply(&foreign), Err(Error::WrongAccount));
    assert_eq!(account.head(), before);
}

#[test]
fn removed_device_cannot_authorize_a_successor_even_with_a_valid_signature() {
    let (first, _, mut account) = setup();
    let draft = account.remove_self(first.public.id()).unwrap();
    let remove = draft
        .finish(first.control.sign(draft.signing_bytes()))
        .unwrap();
    // Keep a correctly signed candidate from before removal, then give it the
    // current predecessor. Cryptographic validity must not revive its signer.
    let draft = account
        .add_device(first.public.id(), Device::new().public)
        .unwrap();
    let event = draft
        .finish(first.control.sign(draft.signing_bytes()))
        .unwrap();
    account.apply(remove.as_bytes()).unwrap();
    let mut forged = event.as_bytes().to_vec();
    let position = b"BaseHero account event\0".len() + 4;
    forged[position..position + 8].copy_from_slice(&3u64.to_be_bytes());
    forged[position + 8..position + 40].copy_from_slice(&account.head().hash);
    let split = forged.len() - 64;
    let sig = first.control.sign(&forged[..split]);
    forged[split..].copy_from_slice(&sig);
    assert_eq!(account.apply(&forged), Err(Error::NotActive));
    assert!(account.is_stopped());
}

#[test]
fn consumed_application_matches_mutable_application_across_materials_and_membership() {
    let (first, _, mut mutable) = setup();
    let second = Device::new();
    let third = Device::new();
    let mut personal_body = vec![9; 1216];
    personal_body.extend([10; 32]);
    personal_body.extend([11; 32]);
    let mut consumed = mutable.clone();
    for (tag, body, author, signer) in [
        (3, vec![7; 32], &first, &first.control),
        (4, personal_body, &first, &first.control),
        (1, device_bytes(&second.public), &first, &first.control),
        (1, device_bytes(&third.public), &second, &second.control),
        (2, vec![], &first, &first.control),
    ] {
        let bytes = incoming(&mutable, author, tag, &body, signer);
        mutable.apply(&bytes).unwrap();
        consumed = consumed.applied(&bytes).unwrap();
        assert!(consumed.id() == mutable.id());
        assert_eq!(consumed.head(), mutable.head());
        assert_eq!(consumed.materials_ready(), mutable.materials_ready());
        assert!(consumed.recovery_keys().unwrap() == mutable.recovery_keys().unwrap());
        for device in [&first, &second, &third] {
            assert_eq!(
                consumed.active_device(device.public.id()),
                mutable.active_device(device.public.id())
            );
            assert_eq!(
                consumed.has_seen_device(device.public.id()),
                mutable.has_seen_device(device.public.id())
            );
        }
        assert_eq!(
            consumed.active_devices().unwrap().collect::<Vec<_>>(),
            mutable.active_devices().unwrap().collect::<Vec<_>>()
        );
    }
    assert_eq!(mutable.head().position, 6);
    assert_eq!(
        consumed.active_device(first.public.id()),
        Err(Error::NotActive)
    );
    assert_eq!(consumed.materials_ready(), Ok(true));
}

#[test]
fn consumed_application_refuses_the_same_errors_as_mutable_application() {
    let (first, _, account) = setup();
    let second = Device::new();
    let body = device_bytes(&second.public);
    let valid = incoming(&account, &first, 1, &body, &first.control);
    let wrong_account = wire_event(
        AccountId([3; 32]),
        2,
        account.head().hash,
        first.public.id(),
        1,
        &body,
        &first.control,
    );
    let wrong_position = wire_event(
        account.id(),
        3,
        account.head().hash,
        first.public.id(),
        1,
        &body,
        &first.control,
    );
    let wrong_previous = wire_event(
        account.id(),
        2,
        [8; 32],
        first.public.id(),
        1,
        &body,
        &first.control,
    );
    let bad_signature = incoming(&account, &first, 1, &body, &first.ordinary);
    let reused = DevicePublicKeys::new(
        *first.public.signing(),
        *second.public.control(),
        *second.public.receiving(),
    )
    .unwrap();
    let key_reuse = incoming(&account, &first, 1, &device_bytes(&reused), &first.control);
    for (bytes, expected) in [
        (&wrong_account, Error::WrongAccount),
        (&wrong_position, Error::WrongPredecessor),
        (&wrong_previous, Error::WrongPredecessor),
        (&bad_signature, Error::BadSignature),
        (&key_reuse, Error::KeyReuse),
    ] {
        let mut retained = account.clone();
        assert_eq!(retained.apply(bytes), Err(expected));
        assert_eq!(account.clone().applied(bytes).err(), Some(expected));
        assert!(retained.is_stopped());
    }
    let mut stopped = account.clone();
    assert_eq!(stopped.apply(&wrong_account), Err(Error::WrongAccount));
    assert_eq!(stopped.apply(&valid), Err(Error::Stopped));
    assert_eq!(
        stopped.clone().applied(&wrong_account).err(),
        Some(Error::Stopped)
    );
    assert_eq!(stopped.applied(&valid).err(), Some(Error::Stopped));
}
