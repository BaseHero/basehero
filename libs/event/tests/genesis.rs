use bh_account::{AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount};
use bh_core::note::Note;
use bh_crypto::{KemKey, Secret, SigningKey};
use bh_event::{
    Binding, CLASS_CONTROL, GENESIS, History, Outcome, Payload, key_id, prepare_genesis, seal,
    verify_genesis,
};
use bh_sync::{BaseId, Commitment, EventId, Head, OpaqueEvent};

fn make_account(
    signing: &SigningKey,
    control: &SigningKey,
) -> (VerifiedAccount, bh_account::DeviceId, Vec<u8>) {
    let keys = DevicePublicKeys::new(
        signing.public(),
        control.public(),
        KemKey::generate().public(),
    )
    .unwrap();
    let device = keys.id();
    let draft = AccountEvent::genesis(
        keys,
        RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public()),
    );
    let first = draft.finish(control.sign(draft.signing_bytes())).unwrap();
    let id = AccountId::of_genesis(&first).unwrap();
    let mut account = VerifiedAccount::from_genesis(id, first.as_bytes()).unwrap();
    let record = account.prepare_recovery_record(device, [3; 32]).unwrap();
    let record = record.finish(control.sign(record.signing_bytes())).unwrap();
    account.apply(record.as_bytes()).unwrap();
    (account, device, first.as_bytes().to_vec())
}

#[test]
fn external_signature_after_account_setup_and_note_under_epoch() {
    let signing = SigningKey::generate();
    let control = SigningKey::generate();
    let (account, device, first) = make_account(&signing, &control);
    let m = Secret::<32>::random();
    let epoch = Secret::<32>::random();
    let request = prepare_genesis(&account, device, &m, &epoch).unwrap();
    assert_eq!(*request.expected_key(), signing.public());
    let bad_signature = control.sign(request.signing_bytes());
    assert!(request.finish(bad_signature).is_err());
    let request = prepare_genesis(&account, device, &m, &epoch).unwrap();
    let signature = signing.sign(request.signing_bytes());
    let (encoded, base) = request.finish(signature).unwrap();
    let verified = verify_genesis(&account, &encoded.descriptor, &encoded.body, &m, 1).unwrap();
    assert_eq!(verified.base, base);
    assert!(verified.creator == account.id());
    assert!(verified.device == device);
    assert_eq!(verified.account_head, account.head());
    assert_eq!(verified.metadata_key_id, key_id(&m));
    assert_eq!(verified.content_key_id, key_id(&epoch));
    let mut history = History::with_account(&account, base, 1).unwrap();
    let ordered = Commitment::order(base, Head::EMPTY, &encoded.descriptor).unwrap();
    let prepared = history
        .prepare(&ordered, &encoded.descriptor, Some(&encoded.body), &m, None)
        .unwrap();
    assert!(prepared.note_id().is_none());
    // The existing account-genesis-only constructor cannot silently substitute
    // the older account head for the introduction's head.
    let old_account = VerifiedAccount::from_genesis(account.id(), &first).unwrap();
    assert!(verify_genesis(&old_account, &encoded.descriptor, &encoded.body, &m, 1).is_err());
    let mut older = History::new(account.id(), &first, base, 1).unwrap();
    assert!(matches!(
        older.prepare(&ordered, &encoded.descriptor, Some(&encoded.body), &m, None),
        Err(Outcome::IntegrityStop)
    ));
    let transition = history.materialize(prepared, None).unwrap().transition;
    history.publish_committed(transition).unwrap();
    let mut data = vec![7; 32];
    data.extend(Note::new().append_paragraph("hello"));
    let note = seal(
        Binding {
            version: 1,
            highest: 1,
            mode: 0,
            base: base.0,
            audience: [0; 32],
            epoch: key_id(&epoch),
            event_id: EventId(bh_crypto::random()),
            account: account.id(),
            device,
            account_head: account.head(),
            seen: history.head(),
            seen_control: ordered.event_digest().0,
            class: bh_event::CLASS_CONTENT,
            padded: 0,
            commitment: [0; 32],
        },
        Payload {
            kind: bh_event::NOTE,
            data: &data,
        },
        &signing,
        &m,
        Some(&epoch),
    )
    .unwrap();
    let note_order = Commitment::order(base, history.head(), &note.descriptor).unwrap();
    let replay = History::replay_with_account(
        &account,
        base,
        1,
        &m,
        Some(&epoch),
        [
            (ordered, encoded.descriptor.encode(), encoded.body.clone()),
            (note_order, note.descriptor.encode(), note.body.clone()),
        ],
    )
    .unwrap();
    assert_eq!(replay.head(), note_order.head());
    assert_eq!(
        history
            .inspect(&note_order, &note.descriptor, &m)
            .unwrap()
            .epoch,
        key_id(&epoch)
    );
    assert!(
        history
            .prepare(
                &note_order,
                &note.descriptor,
                Some(&note.body),
                &m,
                Some(&epoch)
            )
            .is_ok()
    );
}

#[test]
fn genesis_refuses_substitutions_and_bad_first_events() {
    let signing = SigningKey::generate();
    let control = SigningKey::generate();
    let (account, device, _) = make_account(&signing, &control);
    let m = Secret::<32>::random();
    let epoch = Secret::<32>::random();
    let request = prepare_genesis(&account, device, &m, &epoch).unwrap();
    let signature = signing.sign(request.signing_bytes());
    let (encoded, base) = request.finish(signature).unwrap();
    let refuses = |account: &VerifiedAccount,
                   descriptor: &OpaqueEvent,
                   body: &[u8],
                   m: &Secret<32>,
                   floor| {
        assert!(verify_genesis(account, descriptor, body, m, floor).is_err());
    };
    refuses(
        &account,
        &encoded.descriptor,
        &encoded.body,
        &Secret::<32>::random(),
        1,
    );
    refuses(&account, &encoded.descriptor, &encoded.body, &m, 2);
    let (other, _, _) = make_account(&SigningKey::generate(), &SigningKey::generate());
    refuses(&other, &encoded.descriptor, &encoded.body, &m, 1);
    let mut bad_body = encoded.body.clone();
    bad_body[40] ^= 1;
    refuses(&account, &encoded.descriptor, &bad_body, &m, 1);
    let mut raw = encoded.descriptor.encode();
    raw[50] ^= 1;
    refuses(
        &account,
        &OpaqueEvent::decode(&raw).unwrap(),
        &encoded.body,
        &m,
        1,
    );
    let binding = Binding {
        version: 1,
        highest: 1,
        mode: 1,
        base: [0; 32],
        audience: [0; 32],
        epoch: key_id(&m),
        event_id: EventId(bh_crypto::random()),
        account: account.id(),
        device,
        account_head: account.head(),
        seen: Head::EMPTY,
        seen_control: [0; 32],
        class: CLASS_CONTROL,
        padded: 0,
        commitment: [0; 32],
    };
    let mut data = Vec::new();
    data.extend(account.id().0);
    data.extend(account.head().position.to_be_bytes());
    data.extend(account.head().hash);
    data.extend([0; 32]);
    data.extend(key_id(&epoch));
    data.extend(key_id(&m));
    let second_key = seal(
        binding,
        Payload {
            kind: GENESIS,
            data: &data,
        },
        &control,
        &m,
        None,
    )
    .unwrap();
    refuses(&account, &second_key.descriptor, &second_key.body, &m, 1);
    let another_key = seal(
        binding,
        Payload {
            kind: GENESIS,
            data: &data,
        },
        &SigningKey::generate(),
        &m,
        None,
    )
    .unwrap();
    refuses(&account, &another_key.descriptor, &another_key.body, &m, 1);
    data[72] = 1;
    let reserved = seal(
        binding,
        Payload {
            kind: GENESIS,
            data: &data,
        },
        &signing,
        &m,
        None,
    )
    .unwrap();
    refuses(&account, &reserved.descriptor, &reserved.body, &m, 1);
    data[72] = 0;
    let non_genesis = seal(
        Binding {
            mode: 0,
            base: base.0,
            ..binding
        },
        Payload {
            kind: bh_event::ACCOUNT_CHANGE,
            data: &data,
        },
        &control,
        &m,
        None,
    )
    .unwrap();
    refuses(&account, &non_genesis.descriptor, &non_genesis.body, &m, 1);
    let second = seal(
        binding,
        Payload {
            kind: GENESIS,
            data: &data,
        },
        &signing,
        &m,
        None,
    )
    .unwrap();
    let mut history = History::with_account(&account, base, 1).unwrap();
    let order = Commitment::order(base, Head::EMPTY, &encoded.descriptor).unwrap();
    let prepared = history
        .prepare(&order, &encoded.descriptor, Some(&encoded.body), &m, None)
        .unwrap();
    history
        .publish_committed(history.materialize(prepared, None).unwrap().transition)
        .unwrap();
    let second_order = Commitment::order(base, history.head(), &second.descriptor).unwrap();
    assert!(matches!(
        history.prepare(
            &second_order,
            &second.descriptor,
            Some(&second.body),
            &m,
            None
        ),
        Err(Outcome::IntegrityStop)
    ));
    let remove = account.remove_self(device).unwrap();
    let remove = remove.finish(control.sign(remove.signing_bytes())).unwrap();
    let mut inactive = account.clone();
    inactive.apply(remove.as_bytes()).unwrap();
    assert!(prepare_genesis(&inactive, device, &m, &epoch).is_err());
    // Match the removed account's head in both authenticated fields: rejection
    // must reach the active-device check, not just the account-head check.
    let mut removed_data = data.clone();
    removed_data[32..40].copy_from_slice(&inactive.head().position.to_be_bytes());
    removed_data[40..72].copy_from_slice(&inactive.head().hash);
    let removed = seal(
        Binding {
            account_head: inactive.head(),
            ..binding
        },
        Payload {
            kind: GENESIS,
            data: &removed_data,
        },
        &signing,
        &m,
        None,
    )
    .unwrap();
    assert_eq!(
        verify_genesis(&inactive, &removed.descriptor, &removed.body, &m, 1).err(),
        Some(Outcome::IntegrityStop)
    );
    assert_ne!(BaseId::from_genesis(&reserved.descriptor), base);
}

#[test]
fn stopped_creator_account_refuses_genesis_even_at_its_last_verified_head() {
    let signing = SigningKey::generate();
    let control = SigningKey::generate();
    let (mut account, device, _) = make_account(&signing, &control);
    let m = Secret::<32>::random();
    let epoch = Secret::<32>::random();
    let request = prepare_genesis(&account, device, &m, &epoch).unwrap();
    let signature = signing.sign(request.signing_bytes());
    let (encoded, base) = request.finish(signature).unwrap();
    let head = account.head();
    assert!(account.apply(&[0]).is_err());
    assert!(account.is_stopped());
    assert_eq!(account.head(), head);
    assert!(prepare_genesis(&account, device, &m, &epoch).is_err());
    assert!(History::with_account(&account, base, 1).is_err());
    assert_eq!(
        verify_genesis(&account, &encoded.descriptor, &encoded.body, &m, 1).err(),
        Some(Outcome::IntegrityStop)
    );
}
