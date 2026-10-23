//! A container joining an existing account by QR: the showing device's hint,
//! then one transaction committing its verified admission (delivery, own base
//! and a registration without a genesis receipt), then one activation once
//! the base is caught up. None of these rows is authority; the native owners
//! verify before writing them.
use bh_storage::{DeviceDatabase, StoreError, own_base::OwnBaseRecord, sync_state::LOG_BASE};

fn record(account: u8, base: u8) -> OwnBaseRecord {
    OwnBaseRecord {
        account: [account; 32],
        base: [base; 32],
        genesis_descriptor: b"exact signed descriptor".to_vec(),
        genesis_body: b"exact encrypted body".to_vec(),
        initial_key_package: b"exact sealed package".to_vec(),
    }
}

#[test]
fn hint_admission_and_activation_commit_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("joined.sqlite");
    let mut db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.joined().unwrap(), None);

    // The hint is kept, and replaced by a newer pairing's until admitted.
    db.record_join_hint([3; 32], b"first hint").unwrap();
    db.record_join_hint([3; 32], b"second hint").unwrap();
    let joined = db.joined().unwrap().unwrap();
    assert_eq!(joined.account, [3; 32]);
    assert_eq!(joined.hint, b"second hint");
    assert_eq!(joined.delivery, None);
    assert!(!joined.activated);

    // Admission needs the verified account committed first.
    assert!(matches!(
        db.commit_joined_admission(b"delivery", 4, &record(3, 5), [8; 32]),
        Err(StoreError::AuthorityChanged)
    ));
    db.commit_account_verified([3; 32], &[b"signed account"], 1, [4; 32], false)
        .unwrap();
    // Not for another account's base.
    assert!(matches!(
        db.commit_joined_admission(b"delivery", 4, &record(6, 5), [8; 32]),
        Err(StoreError::AuthorityChanged)
    ));
    db.commit_joined_admission(b"delivery", 4, &record(3, 5), [8; 32])
        .unwrap();
    // Exactly repeatable after a crash; other bytes are refused.
    db.commit_joined_admission(b"delivery", 4, &record(3, 5), [8; 32])
        .unwrap();
    assert!(
        db.commit_joined_admission(b"other", 4, &record(3, 5), [8; 32])
            .is_err()
    );
    assert!(
        db.commit_joined_admission(b"delivery", 4, &record(3, 6), [8; 32])
            .is_err()
    );
    assert!(db.record_join_hint([3; 32], b"late hint").is_err());
    let joined = db.joined().unwrap().unwrap();
    assert_eq!(joined.delivery.as_deref(), Some(&b"delivery"[..]));
    assert_eq!(joined.added_at, Some(4));
    assert_eq!(joined.hint, b"second hint");
    assert_eq!(db.own_base().unwrap(), Some(record(3, 5)));
    let registration = db.registration([5; 32]).unwrap().unwrap();
    assert!(registration.registered);
    assert_eq!(registration.genesis_receipt, None);
    let progress = db.log_progress(LOG_BASE, [5; 32]).unwrap().unwrap();
    assert_eq!((progress.position, progress.hosting_root), (0, [8; 32]));

    // Activation waits for the base's verified progress.
    assert!(db.activate_joined().is_err());
    assert!(!db.joined().unwrap().unwrap().activated);
    drop(db);
    let raw = rusqlite::Connection::open(&path).unwrap();
    // Model an already verified canonical genesis rather than constructing an
    // opening from the visible Head or relabelling markerless progress.
    let genesis = bh_sync::canonical::CanonicalCommitment::order(
        bh_sync::BaseId([5; 32]),
        bh_sync::OrderState::EMPTY,
        bh_sync::Digest([5; 32]),
        bh_sync::Route::Control,
    )
    .unwrap();
    raw.execute(
        "UPDATE log_progress SET position=1, head_hash=?1, opening=?2, account_position=3, account_hash=zeroblob(32), metadata_id=zeroblob(32)",
        rusqlite::params![genesis.head().hash.0.as_slice(), genesis.after().encode().as_slice()],
    )
    .unwrap();
    let mut db = DeviceDatabase::open(&path).unwrap();
    db.activate_joined().unwrap();
    db.activate_joined().unwrap();
    assert!(db.joined().unwrap().unwrap().activated);
    drop(db);
    // Activation changes no typed state: a bootstrap reads the base from its
    // start, so ordered decisions made during it were fully informed and there
    // was no coverage to restore.
    let raw = rusqlite::Connection::open(&path).unwrap();
    let scope = bh_data::Scope {
        base: [5; 32],
        audience: [0; 32],
    };
    assert!(
        bh_data::store::records::lookup_scope(&raw, scope)
            .unwrap()
            .is_none(),
        "activation records no typed scope or coverage"
    );
}

#[test]
fn activation_needs_an_admitted_join() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    assert!(db.activate_joined().is_err());
    db.record_join_hint([3; 32], b"hint").unwrap();
    assert!(db.activate_joined().is_err());
}
