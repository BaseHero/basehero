#[path = "support/native.rs"]
mod native;
use native::open_for_receiver;

use bh_account::{
    AccountEvent, AccountId, DevicePublicKeys, Error, VerifiedAccount,
    crypto::{KemKey, SigningKey},
    personal::{self, PersonalKey, PreparedPublication, SealPurpose, prepare_publication},
    recovery::{
        Password, PreparedRecoveryRecord, RecoveryCode, RecoveryKeys, open_record, prepare_record,
    },
};

struct Fixture {
    first: DevicePublicKeys,
    ordinary: SigningKey,
    control: SigningKey,
    receiver: KemKey,
    recovery: RecoveryKeys,
    code: RecoveryCode,
    password: Password,
    genesis: AccountEvent,
    state: VerifiedAccount,
    record: PreparedRecoveryRecord,
    publication: PreparedPublication,
    personal: PersonalKey,
    commitment: AccountEvent,
    published: AccountEvent,
}
fn initial() -> Fixture {
    let ordinary = SigningKey::generate();
    let control = SigningKey::generate();
    let receiver = KemKey::generate();
    let first =
        DevicePublicKeys::new(ordinary.public(), control.public(), receiver.public()).unwrap();
    let recovery = RecoveryKeys::generate();
    let code = RecoveryCode::generate();
    let password = Password::new("pa\0ssé").unwrap();
    let draft = AccountEvent::genesis(first.clone(), recovery.public());
    let genesis = draft.finish(control.sign(draft.signing_bytes())).unwrap();
    let mut state =
        VerifiedAccount::from_genesis(AccountId::of_genesis(&genesis).unwrap(), genesis.as_bytes())
            .unwrap();
    let record = prepare_record(&state, &recovery, &password, &code).unwrap();
    assert!(!state.materials_ready().unwrap());
    assert!(open_record(&state, record.as_bytes(), &password, &code).is_err());
    let draft = state
        .prepare_recovery_record(first.id(), record.digest())
        .unwrap();
    let commitment = draft.finish(control.sign(draft.signing_bytes())).unwrap();
    state.apply(commitment.as_bytes()).unwrap();
    let personal = PersonalKey::generate();
    let publication = prepare_publication(&state, &personal).unwrap();
    assert!(
        open_for_receiver(
            &state,
            publication.device_seal(),
            SealPurpose::FirstDevice,
            &receiver
        )
        .is_err()
    );
    let draft = state
        .publish_personal_key(
            first.id(),
            publication.public(),
            publication.device_digest(),
            publication.recovery_digest(),
        )
        .unwrap();
    let published = draft.finish(control.sign(draft.signing_bytes())).unwrap();
    state.apply(published.as_bytes()).unwrap();
    assert!(state.materials_ready().unwrap());
    Fixture {
        first,
        ordinary,
        control,
        receiver,
        recovery,
        code,
        password,
        genesis,
        state,
        record,
        publication,
        personal,
        commitment,
        published,
    }
}
#[test]
fn initial_objects_require_exact_signed_slots_and_lengths() {
    let f = initial();
    let record = f.record.as_bytes();
    let device = f.publication.device_seal();
    let recovery = f.publication.recovery_seal();
    assert_eq!(
        f.state.verify_initial_objects(record, device, recovery),
        Ok(())
    );
    assert!(
        f.state
            .verify_initial_objects(record, recovery, device)
            .is_err()
    );
    let other = initial();
    assert!(
        other
            .state
            .verify_initial_objects(record, device, recovery)
            .is_err()
    );
    for slot in 0..3 {
        let mut objects = [record.to_vec(), device.to_vec(), recovery.to_vec()];
        objects[slot][100] ^= 1;
        assert!(
            f.state
                .verify_initial_objects(&objects[0], &objects[1], &objects[2])
                .is_err()
        );
        objects[slot].clear();
        assert!(
            f.state
                .verify_initial_objects(&objects[0], &objects[1], &objects[2])
                .is_err()
        );
    }
    let incomplete = VerifiedAccount::from_genesis(f.state.id(), f.genesis.as_bytes()).unwrap();
    assert!(
        incomplete
            .verify_initial_objects(record, device, recovery)
            .is_err()
    );
}

// Independent incoming encoder: does not call SigningRequest or AccountEvent::draft.
fn incoming(
    state: &VerifiedAccount,
    author: &DevicePublicKeys,
    signer: &SigningKey,
    position: u64,
    previous: [u8; 32],
    tag: u8,
    body: &[u8],
) -> Vec<u8> {
    let mut wire = b"BaseHero account event\0".to_vec();
    wire.extend_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&position.to_be_bytes());
    wire.extend_from_slice(&previous);
    wire.extend_from_slice(&state.id().0);
    wire.extend_from_slice(&author.id().0);
    wire.push(tag);
    wire.extend_from_slice(body);
    wire.extend_from_slice(&signer.sign(&wire));
    wire
}
fn successor(f: &Fixture, tag: u8, body: &[u8], signer: &SigningKey) -> Vec<u8> {
    incoming(
        &f.state,
        &f.first,
        signer,
        f.state.head().position + 1,
        f.state.head().hash,
        tag,
        body,
    )
}
fn stopped(mut state: VerifiedAccount, wire: &[u8]) {
    let head = state.head();
    assert!(state.apply(wire).is_err());
    assert_eq!(state.head(), head);
    assert!(state.is_stopped());
    assert_eq!(state.materials_ready(), Err(Error::Stopped));
}

#[test]
fn signed_initial_materials_roundtrip_replay_and_no_public_secret_metadata() {
    let f = initial();
    let restored = open_record(&f.state, f.record.as_bytes(), &f.password, &f.code).unwrap();
    assert_eq!(restored.public().signing(), f.recovery.public().signing());
    assert_eq!(
        restored.public().receiving(),
        f.recovery.public().receiving()
    );
    assert_eq!(
        open_for_receiver(
            &f.state,
            f.publication.device_seal(),
            SealPurpose::FirstDevice,
            &f.receiver
        )
        .unwrap()
        .public(),
        f.personal.public()
    );
    assert_eq!(
        open_for_receiver(
            &f.state,
            f.publication.recovery_seal(),
            SealPurpose::Recovery,
            restored.receiver()
        )
        .unwrap()
        .public(),
        f.personal.public()
    );
    assert_eq!(
        VerifiedAccount::replay(
            f.state.id(),
            &[
                f.genesis.as_bytes(),
                f.commitment.as_bytes(),
                f.published.as_bytes()
            ],
            f.state.head()
        )
        .unwrap()
        .head(),
        f.state.head()
    );
    assert_ne!(
        f.recovery.public().signing(),
        RecoveryKeys::generate().public().signing()
    );
    for public in [
        f.genesis.as_bytes(),
        f.commitment.as_bytes(),
        f.published.as_bytes(),
    ] {
        for private in [
            f.code.expose().as_slice(),
            &f.record.as_bytes()[98..178],
            &f.record.as_bytes()[178..210],
            &f.record.as_bytes()[210..242],
            f.publication.device_seal(),
            f.publication.recovery_seal(),
        ] {
            assert!(!public.windows(private.len()).any(|w| w == private));
        }
    }
}

#[test]
fn signed_device_delivery_requires_active_sender_recipient_and_current_publication() {
    let mut f = initial();
    let ordinary2 = SigningKey::generate();
    let control2 = SigningKey::generate();
    let receiver2 = KemKey::generate();
    let second =
        DevicePublicKeys::new(ordinary2.public(), control2.public(), receiver2.public()).unwrap();
    let draft = f.state.add_device(f.first.id(), second.clone()).unwrap();
    let added = draft.finish(f.control.sign(draft.signing_bytes())).unwrap();
    let object = native::seal_for_device(
        &f.state,
        &f.personal,
        &f.first,
        &f.ordinary,
        &second,
        &added,
    )
    .unwrap();
    f.state.apply(added.as_bytes()).unwrap();
    let opened = native::open_device(&f.state, &object, &second, &receiver2).unwrap();
    assert_eq!(opened.public(), f.personal.public());
    for offset in [
        0,
        8,
        10,
        11,
        43,
        75,
        107,
        1227,
        1251,
        object.len() - 65,
        object.len() - 1,
    ] {
        let mut tampered = object.clone();
        tampered[offset] ^= 1;
        assert!(
            native::open_device(&f.state, &tampered, &second, &receiver2).is_err(),
            "tampered {offset}"
        );
    }
    assert!(
        native::open_device(&f.state, f.publication.device_seal(), &second, &receiver2).is_err()
    );
    let wrong = KemKey::generate();
    assert!(
        native::open_device(&f.state, &object, &second, &wrong).is_err(),
        "wrong native receiver"
    );
    assert!(
        native::open_device(&f.state, &object, &f.first, &f.receiver).is_err(),
        "not the opener's recipient"
    );
    let resign = |change: &dyn Fn(&mut Vec<u8>)| {
        let mut copy = object.clone();
        change(&mut copy);
        let n = copy.len();
        let signature = f.ordinary.sign(&copy[..n - 64]);
        copy[n - 64..].copy_from_slice(&signature);
        copy
    };
    let wrong_domain = resign(&|b| b[0] ^= 1);
    assert!(
        native::open_device(&f.state, &wrong_domain, &second, &receiver2).is_err(),
        "domain checked even with valid signature"
    );
    let wrong_purpose = resign(&|b| b[8 + 10] = 1);
    assert!(native::open_device(&f.state, &wrong_purpose, &second, &receiver2).is_err());
    let recovery_purpose = resign(&|b| b[8 + 10] = 2);
    assert!(native::open_device(&f.state, &recovery_purpose, &second, &receiver2).is_err());
    let stale_personal = resign(&|b| b[8 + 43] ^= 1);
    assert!(native::open_device(&f.state, &stale_personal, &second, &receiver2).is_err());
    let wrong_recipient = resign(&|b| b[8 + 75] ^= 1);
    assert!(native::open_device(&f.state, &wrong_recipient, &second, &receiver2).is_err());
    // A valid signature and valid AEAD can still carry the wrong personal seed;
    // opening must reconstruct the public receiver and compare it to history.
    let wrong_seed = resign(&|b| {
        let (ct, shared) = bh_account::crypto::encapsulate(second.receiving()).unwrap();
        let key = bh_account::crypto::derive_key(&shared, b"BHPSEA01", 1);
        let personal_id = bh_account::crypto::hash(
            &[b"BH personal key id v1\0".as_slice(), &f.personal.public()].concat(),
        );
        let recipient_hash = bh_account::crypto::hash(
            &[b"BH personal recipient v1\0".as_slice(), second.receiving()].concat(),
        );
        let ad = [
            b"BH personal seed seal v1\0".as_slice(),
            &1u16.to_be_bytes(),
            &[3u8],
            &f.state.id().0,
            &personal_id,
            &recipient_hash,
        ]
        .concat();
        let (nonce, ciphertext) = bh_account::crypto::aead_seal(&key, &ad, &[99; 32]).unwrap();
        b[8 + 107..8 + 1227].copy_from_slice(&ct);
        b[8 + 1227..8 + 1251].copy_from_slice(&nonce);
        b[8 + 1251..8 + 1299].copy_from_slice(&ciphertext);
    });
    assert!(native::open_device(&f.state, &wrong_seed, &second, &receiver2).is_err());
    let mut recipient_removed = f.state.clone();
    let draft = recipient_removed.remove_self(second.id()).unwrap();
    let removed = draft.finish(control2.sign(draft.signing_bytes())).unwrap();
    recipient_removed.apply(removed.as_bytes()).unwrap();
    assert!(
        recipient_removed.active_device(f.first.id()).is_ok(),
        "sender remains active"
    );
    assert!(
        native::open_device(&recipient_removed, &object, &second, &receiver2).is_err(),
        "verified recipient removal refuses an otherwise-valid delivery"
    );
    let draft = f.state.remove_self(f.first.id()).unwrap();
    f.state
        .apply(
            draft
                .finish(f.control.sign(draft.signing_bytes()))
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    assert!(
        native::open_device(&f.state, &object, &second, &receiver2).is_err(),
        "inactive sender"
    );
}

#[test]
fn device_delivery_verifies_publicly_like_opening_without_secret_keys() {
    let mut f = initial();
    let ordinary2 = SigningKey::generate();
    let control2 = SigningKey::generate();
    let receiver2 = KemKey::generate();
    let second =
        DevicePublicKeys::new(ordinary2.public(), control2.public(), receiver2.public()).unwrap();
    let predecessor = f.state.clone();
    let draft = f.state.add_device(f.first.id(), second.clone()).unwrap();
    let added = draft.finish(f.control.sign(draft.signing_bytes())).unwrap();
    let object = native::seal_for_device(
        &f.state,
        &f.personal,
        &f.first,
        &f.ordinary,
        &second,
        &added,
    )
    .unwrap();
    // Before the add is applied, the recipient is not a device of the account.
    assert!(personal::verify_device_delivery(&predecessor, &object, &second).is_err());
    f.state.apply(added.as_bytes()).unwrap();
    assert!(personal::verify_device_delivery(&f.state, &object, &second) == Ok(f.first.id()));
    // Every byte the opener checks before decapsulating is checked here too.
    for offset in [
        0,
        8,
        10,
        11,
        43,
        75,
        107,
        1227,
        1251,
        object.len() - 65,
        object.len() - 1,
    ] {
        let mut tampered = object.clone();
        tampered[offset] ^= 1;
        assert!(
            personal::verify_device_delivery(&f.state, &tampered, &second).is_err(),
            "tampered {offset}"
        );
    }
    for wrong in [
        &object[..object.len() - 1],
        &[object.as_slice(), &[0]].concat(),
    ] {
        assert!(
            personal::verify_device_delivery(&f.state, wrong, &second) == Err(Error::Malformed)
        );
    }
    assert!(
        personal::verify_device_delivery(&f.state, &object, &f.first).is_err(),
        "another active device is not the recipient"
    );
    let resign = |change: &dyn Fn(&mut Vec<u8>)| {
        let mut copy = object.clone();
        change(&mut copy);
        let n = copy.len();
        let signature = f.ordinary.sign(&copy[..n - 64]);
        copy[n - 64..].copy_from_slice(&signature);
        copy
    };
    for (what, change) in [
        (
            "domain",
            (&|b: &mut Vec<u8>| b[0] ^= 1) as &dyn Fn(&mut Vec<u8>),
        ),
        ("first-device purpose", &|b| b[8 + 10] = 1),
        ("recovery purpose", &|b| b[8 + 10] = 2),
        ("account", &|b| b[8 + 11] ^= 1),
        ("personal publication", &|b| b[8 + 43] ^= 1),
        ("recipient", &|b| b[8 + 75] ^= 1),
    ] {
        assert!(
            personal::verify_device_delivery(&f.state, &resign(change), &second).is_err(),
            "{what}"
        );
    }
    // A delivery from another account's device, signed validly, is refused.
    let foreign = initial();
    assert!(personal::verify_device_delivery(&foreign.state, &object, &second).is_err());
    let draft = f.state.remove_self(f.first.id()).unwrap();
    f.state
        .apply(
            draft
                .finish(f.control.sign(draft.signing_bytes()))
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    assert!(
        personal::verify_device_delivery(&f.state, &object, &second).is_err(),
        "inactive sender"
    );
}

#[test]
fn record_rejects_changed_credentials_or_private_record_or_foreign_account() {
    let f = initial();
    for password in ["pa\0ss", "pa\0sse", "pa\0ssé "] {
        assert!(
            open_record(
                &f.state,
                f.record.as_bytes(),
                &Password::new(password).unwrap(),
                &f.code
            )
            .is_err()
        );
    }
    assert!(
        open_record(
            &f.state,
            f.record.as_bytes(),
            &f.password,
            &RecoveryCode::from_raw(&[0; 16])
        )
        .is_err()
    );
    let mut tampered = f.record.as_bytes().to_vec();
    for offset in [0, 8, 11, 42, 74, 98, 177, 178, 210] {
        tampered.copy_from_slice(f.record.as_bytes());
        tampered[offset] ^= 1;
        assert!(open_record(&f.state, &tampered, &f.password, &f.code).is_err());
    }
    let mut trailing = f.record.as_bytes().to_vec();
    trailing.push(0);
    assert!(open_record(&f.state, &trailing, &f.password, &f.code).is_err());
    let foreign = initial();
    assert!(open_record(&foreign.state, f.record.as_bytes(), &f.password, &f.code).is_err());
    let mut wrong_digest = f.record.digest();
    wrong_digest[0] ^= 1;
    let mut changed = VerifiedAccount::from_genesis(f.state.id(), f.genesis.as_bytes()).unwrap();
    let bad_commit = incoming(
        &changed,
        &f.first,
        &f.control,
        2,
        changed.head().hash,
        3,
        &wrong_digest,
    );
    changed.apply(&bad_commit).unwrap();
    let publish = incoming(
        &changed,
        &f.first,
        &f.control,
        3,
        changed.head().hash,
        4,
        &[
            f.publication.public().as_slice(),
            &f.publication.device_digest(),
            &f.publication.recovery_digest(),
        ]
        .concat(),
    );
    changed.apply(&publish).unwrap();
    assert!(open_record(&changed, f.record.as_bytes(), &f.password, &f.code).is_err());
    assert!(Password::new("").is_err());
    assert!(Password::new(&"x".repeat(1025)).is_err());
}

#[test]
fn private_home_proof_depends_on_code_alone_and_token_on_both_inputs() {
    let f = initial();
    let prefix = VerifiedAccount::from_genesis(f.state.id(), f.genesis.as_bytes()).unwrap();
    let password_changed = prepare_record(
        &prefix,
        &f.recovery,
        &Password::new("other-password").unwrap(),
        &f.code,
    )
    .unwrap();
    assert_eq!(
        &f.record.as_bytes()[210..242],
        &password_changed.as_bytes()[210..242]
    );
    assert_ne!(
        &f.record.as_bytes()[178..210],
        &password_changed.as_bytes()[178..210]
    );
    let mut alternate_code = *f.code.expose();
    alternate_code[0] ^= 1;
    let code_changed = prepare_record(
        &prefix,
        &f.recovery,
        &f.password,
        &RecoveryCode::from_raw(&alternate_code),
    )
    .unwrap();
    assert_ne!(
        &f.record.as_bytes()[210..242],
        &code_changed.as_bytes()[210..242]
    );
    assert_ne!(
        &f.record.as_bytes()[178..210],
        &code_changed.as_bytes()[178..210]
    );
}

#[test]
fn personal_seals_reject_slot_purpose_recipient_account_and_removed_first_device() {
    let f = initial();
    assert!(
        open_for_receiver(
            &f.state,
            f.publication.device_seal(),
            SealPurpose::Recovery,
            &f.receiver
        )
        .is_err()
    );
    assert!(
        open_for_receiver(
            &f.state,
            f.publication.recovery_seal(),
            SealPurpose::FirstDevice,
            &f.receiver
        )
        .is_err()
    );
    assert!(
        open_for_receiver(
            &f.state,
            f.publication.device_seal(),
            SealPurpose::FirstDevice,
            &KemKey::generate()
        )
        .is_err()
    );
    let mut tampered = f.publication.device_seal().to_vec();
    for offset in [0, 8, 10, 12, 43, 75, 107, 1227, 1251, 1298] {
        tampered.copy_from_slice(f.publication.device_seal());
        tampered[offset] ^= 1;
        assert!(
            open_for_receiver(&f.state, &tampered, SealPurpose::FirstDevice, &f.receiver).is_err()
        );
    }
    tampered.push(0);
    assert!(open_for_receiver(&f.state, &tampered, SealPurpose::FirstDevice, &f.receiver).is_err());
    assert!(
        open_for_receiver(
            &initial().state,
            f.publication.device_seal(),
            SealPurpose::FirstDevice,
            &f.receiver
        )
        .is_err()
    );
    let mut removed = f.state.clone();
    removed.apply(&successor(&f, 2, &[], &f.control)).unwrap();
    assert!(
        open_for_receiver(
            &removed,
            f.publication.device_seal(),
            SealPurpose::FirstDevice,
            &f.receiver
        )
        .is_err()
    );
}

#[test]
fn hostile_initial_controls_fail_closed_but_partial_old_histories_remain_valid() {
    let f = initial();
    let genesis = VerifiedAccount::from_genesis(f.state.id(), f.genesis.as_bytes()).unwrap();
    let digest = f.record.digest();
    let key = f.publication.public();
    let publication_body = [
        key.as_slice(),
        &f.publication.device_digest(),
        &f.publication.recovery_digest(),
    ]
    .concat();
    assert!(!genesis.materials_ready().unwrap());
    assert!(
        genesis
            .publish_personal_key(
                f.first.id(),
                key,
                f.publication.device_digest(),
                f.publication.recovery_digest()
            )
            .is_err()
    );
    stopped(
        genesis.clone(),
        &incoming(
            &genesis,
            &f.first,
            &f.control,
            2,
            genesis.head().hash,
            4,
            &publication_body,
        ),
    );
    stopped(
        genesis.clone(),
        &incoming(
            &genesis,
            &f.first,
            &f.ordinary,
            2,
            genesis.head().hash,
            3,
            &digest,
        ),
    );
    stopped(
        genesis.clone(),
        &incoming(
            &genesis,
            &f.first,
            &f.control,
            2,
            genesis.head().hash,
            5,
            &[],
        ),
    );
    for (tag, body) in [(3, digest.as_slice()), (4, publication_body.as_slice())] {
        let wrong = incoming(
            &genesis,
            &f.first,
            &SigningKey::generate(),
            2,
            genesis.head().hash,
            tag,
            body,
        );
        stopped(genesis.clone(), &wrong);
    }
    for body in [&digest[..31], [digest.as_slice(), &[0]].concat().as_slice()] {
        stopped(
            genesis.clone(),
            &incoming(
                &genesis,
                &f.first,
                &f.control,
                2,
                genesis.head().hash,
                3,
                body,
            ),
        );
    }
    let mut after_record = genesis.clone();
    after_record.apply(f.commitment.as_bytes()).unwrap();
    assert!(!after_record.materials_ready().unwrap());
    stopped(
        after_record.clone(),
        &incoming(
            &after_record,
            &f.first,
            &f.control,
            3,
            after_record.head().hash,
            3,
            &digest,
        ),
    );
    stopped(
        f.state.clone(),
        &successor(&f, 4, &publication_body, &f.control),
    );
    stopped(f.state.clone(), &successor(&f, 3, &digest, &f.control));
    let mut compromised_view = f.state.clone();
    assert!(
        compromised_view
            .apply(&successor(&f, 3, &digest, &f.control))
            .is_err()
    );
    assert_eq!(
        open_record(&compromised_view, f.record.as_bytes(), &f.password, &f.code).err(),
        Some(Error::Stopped)
    );
    assert!(
        open_for_receiver(
            &compromised_view,
            f.publication.device_seal(),
            SealPurpose::FirstDevice,
            &f.receiver
        )
        .is_err()
    );
    let other = SigningKey::generate();
    stopped(
        f.state.clone(),
        &successor(&f, 4, &publication_body, &other),
    );
    let mut wrong_public = after_record.clone();
    let foreign_public = PersonalKey::generate().public();
    let wrong_body = [
        foreign_public.as_slice(),
        &f.publication.device_digest(),
        &f.publication.recovery_digest(),
    ]
    .concat();
    wrong_public
        .apply(&incoming(
            &wrong_public,
            &f.first,
            &f.control,
            3,
            wrong_public.head().hash,
            4,
            &wrong_body,
        ))
        .unwrap();
    assert!(
        open_for_receiver(
            &wrong_public,
            f.publication.device_seal(),
            SealPurpose::FirstDevice,
            &f.receiver
        )
        .is_err()
    );
    let mut wrong_version = incoming(
        &genesis,
        &f.first,
        &f.control,
        2,
        genesis.head().hash,
        3,
        &digest,
    );
    wrong_version[23] = 2; // first byte of the signed protocol version is at offset 23
    stopped(genesis.clone(), &wrong_version);
    let mut malformed = publication_body.clone();
    malformed.push(0);
    stopped(
        after_record.clone(),
        &incoming(
            &after_record,
            &f.first,
            &f.control,
            3,
            after_record.head().hash,
            4,
            &malformed,
        ),
    );
    let second = DevicePublicKeys::new(
        SigningKey::generate().public(),
        SigningKey::generate().public(),
        KemKey::generate().public(),
    )
    .unwrap();
    let body = [
        second.signing().as_slice(),
        second.control(),
        second.receiving(),
    ]
    .concat();
    let mut partial = genesis.clone();
    partial
        .apply(&incoming(
            &partial,
            &f.first,
            &f.control,
            2,
            partial.head().hash,
            1,
            &body,
        ))
        .unwrap();
    assert!(!partial.materials_ready().unwrap());
    stopped(
        partial.clone(),
        &incoming(
            &partial,
            &f.first,
            &f.control,
            3,
            partial.head().hash,
            3,
            &digest,
        ),
    );
}
