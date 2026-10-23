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
        // Validly signed at the next position, extending another head.
        (&wrong_previous, Error::Fork),
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

fn signed(request: bh_account::SigningRequest, key: &SigningKey) -> Vec<u8> {
    request
        .finish(key.sign(request.signing_bytes()))
        .unwrap()
        .as_bytes()
        .to_vec()
}

/// A native journal holding a signed-up Mac with complete materials and the
/// Fold, all untimed, and the indexed view at its head.
fn journaled(
    path: &std::path::Path,
) -> (
    bh_account::storage::DeviceJournal,
    Device,
    Device,
    bh_account::recovery::RecoveryKeys,
    VerifiedAccount,
) {
    use bh_account::journal::AccountJournal;
    let mut journal = bh_account::storage::DeviceJournal::open(path).unwrap();
    let (mac, fold) = (Device::new(), Device::new());
    let recovery = bh_account::recovery::RecoveryKeys::generate();
    let genesis = signed(
        AccountEvent::genesis(mac.public.clone(), recovery.public()),
        &mac.control,
    );
    let id = AccountId(hash(&genesis));
    let head = bh_account::Head {
        position: 1,
        hash: hash(&genesis),
    };
    journal
        .commit_verified(id, &[&genesis], head, false)
        .unwrap();
    let mut acct = journal.load_projection().unwrap().unwrap().account;
    let mut events = Vec::new();
    let record = signed(
        acct.prepare_recovery_record(mac.public.id(), [3; 32])
            .unwrap(),
        &mac.control,
    );
    acct.apply(&record).unwrap();
    events.push(record);
    let personal = signed(
        acct.publish_personal_key(
            mac.public.id(),
            KemKey::generate().public(),
            [4; 32],
            [5; 32],
        )
        .unwrap(),
        &mac.control,
    );
    acct.apply(&personal).unwrap();
    events.push(personal);
    let add = signed(
        acct.add_device(mac.public.id(), fold.public.clone())
            .unwrap(),
        &mac.control,
    );
    acct.apply(&add).unwrap();
    events.push(add);
    let acct = commit(&mut journal, acct, &events);
    (journal, mac, fold, recovery, acct)
}

/// Commit as the owner does, returning the view rebased on the stored index.
fn commit(
    journal: &mut bh_account::storage::DeviceJournal,
    acct: VerifiedAccount,
    events: &[Vec<u8>],
) -> VerifiedAccount {
    commit_timed(journal, acct, events, &vec![None; events.len()])
}

fn commit_timed(
    journal: &mut bh_account::storage::DeviceJournal,
    acct: VerifiedAccount,
    events: &[Vec<u8>],
    times: &[Option<bh_account::ConfirmedTime>],
) -> VerifiedAccount {
    use bh_account::journal::AccountJournal;
    let refs: Vec<_> = events.iter().map(Vec::as_slice).collect();
    let evidence: Vec<_> = times
        .iter()
        .map(|time| time.map(|time| (time, b"verified confirmation fixture".to_vec())))
        .collect();
    journal
        .commit_timed_fenced(
            acct.id(),
            &refs,
            &evidence,
            acct.head(),
            false,
            Some(&acct),
            |ok| assert!(ok),
        )
        .unwrap();
    journal.rebase_projection(acct).unwrap()
}

#[test]
fn projection_round_trips_pending_effects_and_times() {
    use bh_account::journal::AccountJournal;
    use bh_account::{
        ConfirmedTime, DeviceState, REMOVAL_WAIT_MS as W, RequestState, RotationReason,
        recovery::RecoveryKeys,
    };
    let t = |earliest_ms, latest_ms| {
        Some(ConfirmedTime {
            earliest_ms,
            latest_ms,
        })
    };
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, mac, fold, _, mut acct) = journaled(&dir.path().join("account.sqlite"));
    let (phone, tablet) = (Device::new(), Device::new());
    let next = RecoveryKeys::generate();
    let mut events = Vec::new();
    let mut times = Vec::new();
    let mut step = |acct: &mut VerifiedAccount, bytes: Vec<u8>, time| {
        acct.apply_timed(&bytes, time).unwrap();
        events.push(bytes);
        times.push(time);
        acct.head().position
    };
    let bytes = signed(
        acct.add_device(mac.public.id(), phone.public.clone())
            .unwrap(),
        &mac.control,
    );
    step(&mut acct, bytes, t(0, 0));
    let bytes = signed(
        acct.add_device(mac.public.id(), tablet.public.clone())
            .unwrap(),
        &mac.control,
    );
    step(&mut acct, bytes, t(50, 60));
    let bytes = signed(
        acct.request_removal(mac.public.id(), fold.public.id())
            .unwrap(),
        &mac.control,
    );
    let pending = step(&mut acct, bytes, t(100, 100));
    let bytes = signed(
        acct.replace_recovery(mac.public.id(), next.public(), [6; 32], [7; 32])
            .unwrap(),
        &mac.control,
    );
    let replaced = step(&mut acct, bytes, t(110, 110));
    let bytes = signed(
        acct.request_removal(mac.public.id(), phone.public.id())
            .unwrap(),
        &mac.control,
    );
    let cancelled = step(&mut acct, bytes, t(120, 120));
    let bytes = acct
        .cancel_removal_by_recovery(cancelled)
        .unwrap()
        .finish_with_recovery(&next)
        .unwrap()
        .as_bytes()
        .to_vec();
    step(&mut acct, bytes, t(130, 130));
    commit_timed(&mut journal, acct.clone(), &events, &times);

    let loaded = journal.load_projection().unwrap().unwrap().account;
    assert_eq!(loaded.head(), acct.head(), "the stored view, not a rebuild");
    // How a request ended is kept only while the projection is loaded.
    assert_eq!(
        acct.request_state(cancelled, 200),
        Ok(RequestState::Cancelled)
    );
    assert_eq!(
        loaded.request_state(cancelled, 200),
        Ok(RequestState::Resolved)
    );
    for view in [&acct, &loaded] {
        assert_eq!(view.pending_removals(200), acct.pending_removals(200));
        assert_eq!(view.pending_removals(200).len(), 1);
        assert_eq!(
            view.request_state(pending, 200),
            Ok(RequestState::Pending {
                deadline_ms: 100 + W
            })
        );
        assert_eq!(
            view.rotation_due(200),
            Some(RotationReason::RecoveryReplaced { position: replaced })
        );
        assert_eq!(
            view.device_state(fold.public.id(), 100 + W),
            Ok(DeviceState::Removed)
        );
        assert!(view.recovery_keys().unwrap() == &next.public());
        assert_eq!(view.record_digest(), Ok([6; 32]));
        // Devices from before the first confirmed entry mature from it.
        assert_eq!(view.added_at(mac.public.id()), Some(0));
        assert_eq!(view.added_at(phone.public.id()), Some(0));
        // The last confirmed bounds persist: times never go backwards, and
        // every later entry needs a confirmation.
        let more = signed(
            view.add_device(mac.public.id(), Device::new().public)
                .unwrap(),
            &mac.control,
        );
        assert_eq!(
            view.clone().apply_timed(&more, t(129, 140)),
            Err(Error::TimeRegressed)
        );
        assert_eq!(
            view.clone().apply_timed(&more, None),
            Err(Error::MissingTime)
        );
        view.clone().apply_timed(&more, t(130, 130)).unwrap();
        // Personal keys stay used keys, the current one and, after a
        // rotation, the one it replaced.
        let initial = *view.personal_public().unwrap();
        let reusing = |receiving| {
            DevicePublicKeys::new(
                SigningKey::generate().public(),
                SigningKey::generate().public(),
                receiving,
            )
            .unwrap()
        };
        assert_eq!(
            view.add_device(mac.public.id(), reusing(initial)).err(),
            Some(Error::KeyReuse)
        );
        let mut rotated = view.clone();
        let rotation = signed(
            rotated
                .rotate_personal(
                    mac.public.id(),
                    replaced,
                    KemKey::generate().public(),
                    [8; 32],
                    [9; 32],
                )
                .unwrap(),
            &mac.ordinary,
        );
        rotated.apply_timed(&rotation, t(130, 130)).unwrap();
        assert_eq!(rotated.rotation_due(200), None);
        assert_eq!(
            rotated.add_device(mac.public.id(), reusing(initial)).err(),
            Some(Error::KeyReuse)
        );
    }
    assert_eq!(acct.added_at(tablet.public.id()), Some(60));
    assert_eq!(loaded.added_at(tablet.public.id()), Some(60));
    assert!(loaded.is_mature(tablet.public.id(), 60 + W));
}

#[test]
fn a_summary_from_before_confirmed_times_loads_with_none() {
    use bh_account::journal::AccountJournal;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let (journal, mac, _, _, acct) = journaled(&path);
    let raw = rusqlite::Connection::open(&path).unwrap();
    let mut summary: Vec<u8> = raw
        .query_row("SELECT summary FROM account_projection", [], |r| r.get(0))
        .unwrap();
    assert_eq!(&summary[..8], b"BHACSM02");
    // The earlier summary is this one's prefix under its own magic.
    summary.truncate(2602);
    summary[..8].copy_from_slice(b"BHACSM01");
    raw.execute("UPDATE account_projection SET summary=?1", [&summary])
        .unwrap();
    let loaded = journal.load_projection().unwrap().unwrap().account;
    assert_eq!(loaded.head(), acct.head(), "the stored view, not a rebuild");
    assert!(loaded.pending_removals(0).is_empty());
    assert_eq!(loaded.rotation_due(u64::MAX), None);
    assert_eq!(loaded.added_at(mac.public.id()), None);
    assert_eq!(loaded.record_digest(), Ok([3; 32]));
    let more = signed(
        loaded
            .add_device(mac.public.id(), Device::new().public)
            .unwrap(),
        &mac.control,
    );
    loaded.clone().apply_timed(&more, None).unwrap();
}

#[test]
fn resolved_outcomes_are_not_in_the_summary() {
    use bh_account::journal::AccountJournal;
    use bh_account::{ConfirmedTime, RequestState};
    let t = |ms| {
        Some(ConfirmedTime {
            earliest_ms: ms,
            latest_ms: ms,
        })
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let (mut journal, mac, fold, recovery, mut acct) = journaled(&path);
    let raw = rusqlite::Connection::open(&path).unwrap();
    let size = || {
        raw.query_row("SELECT length(summary) FROM account_projection", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap()
    };
    let before = size();
    let mut events = Vec::new();
    let mut first = None;
    for i in 0..1000 {
        let request = signed(
            acct.request_removal(mac.public.id(), fold.public.id())
                .unwrap(),
            &mac.control,
        );
        acct.apply_timed(&request, t(10 + 2 * i)).unwrap();
        let position = acct.head().position;
        first.get_or_insert(position);
        let cancel = acct
            .cancel_removal_by_recovery(position)
            .unwrap()
            .finish_with_recovery(&recovery)
            .unwrap()
            .as_bytes()
            .to_vec();
        acct.apply_timed(&cancel, t(11 + 2 * i)).unwrap();
        events.extend([request, cancel]);
    }
    let first = first.unwrap();
    let times: Vec<_> = (10..2010).map(t).collect();
    commit_timed(&mut journal, acct.clone(), &events, &times);
    assert_eq!(size(), before);
    assert_eq!(acct.request_state(first, 5000), Ok(RequestState::Cancelled));
    let loaded = journal.load_projection().unwrap().unwrap().account;
    assert_eq!(loaded.head(), acct.head(), "the stored view, not a rebuild");
    assert_eq!(
        loaded.request_state(first, 5000),
        Ok(RequestState::Resolved)
    );
    assert!(loaded.pending_removals(5000).is_empty());
}

#[test]
fn a_new_kit_supersedes_an_unrotated_kit_change() {
    use bh_account::{ConfirmedTime, RotationReason, recovery::RecoveryKeys};
    let t = |ms| {
        Some(ConfirmedTime {
            earliest_ms: ms,
            latest_ms: ms,
        })
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let (mut journal, mac, _, _, mut acct) = journaled(&path);
    let raw = rusqlite::Connection::open(&path).unwrap();
    let size = || {
        raw.query_row("SELECT length(summary) FROM account_projection", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap()
    };
    let replace = |acct: &mut VerifiedAccount, ms| {
        let bytes = signed(
            acct.replace_recovery(
                mac.public.id(),
                RecoveryKeys::generate().public(),
                [6; 32],
                [7; 32],
            )
            .unwrap(),
            &mac.control,
        );
        acct.apply_timed(&bytes, t(ms)).unwrap();
        (bytes, acct.head().position)
    };
    let rotate = |acct: &VerifiedAccount, reason| {
        let bytes = signed(
            acct.rotate_personal(
                mac.public.id(),
                reason,
                KemKey::generate().public(),
                [8; 32],
                [9; 32],
            )
            .unwrap(),
            &mac.ordinary,
        );
        let mut rotated = acct.clone();
        rotated.apply_timed(&bytes, t(5000)).map(|()| rotated)
    };

    let (bytes, first) = replace(&mut acct, 10);
    let acct = commit_timed(&mut journal, acct, &[bytes], &[t(10)]);
    let single = size();
    let mut acct = acct;
    let (bytes, second) = replace(&mut acct, 11);
    let mut events = vec![bytes];
    // Only the latest kit is due; the rotation seals to it alone.
    assert_eq!(
        acct.rotation_due(5000),
        Some(RotationReason::RecoveryReplaced { position: second })
    );
    assert_eq!(rotate(&acct, first).err(), Some(Error::NotPermitted));
    let rotated = rotate(&acct, second).unwrap();
    assert_eq!(rotated.rotation_due(5000), None);

    for i in 2..1000 {
        let (bytes, _) = replace(&mut acct, 10 + i);
        events.push(bytes);
    }
    let times: Vec<_> = (11..1010).map(t).collect();
    let acct = commit_timed(&mut journal, acct, &events, &times);
    assert_eq!(size(), single, "one outstanding kit change");
    assert_eq!(
        acct.rotation_due(5000),
        Some(RotationReason::RecoveryReplaced {
            position: acct.head().position
        })
    );
}
