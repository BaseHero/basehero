//! Test-only identities and keys. No production session is inferred from these.
use bh_account::{AccountId, DeviceId, Head as AccountHead};
use bh_core::note::Note;
use bh_crypto::{Secret, SigningKey};
use bh_event::{Binding, CLASS_CONTENT, Encoded, NOTE, Payload, key_id, seal};
use bh_storage::{DeviceDatabase, NoteKey, PackagePreparation, StoreError};
use bh_sync::{BaseId, Commitment, Digest, EventId, Head, OrderState, RawControlHead, Route};

// Untrusted opening fixture for outbox Ack comparisons only, never a
// verified history or authority for the base.
fn before_content() -> OrderState {
    OrderState::new(
        RawControlHead {
            position: 1,
            node_hash: Digest([9; 32]),
        },
        0,
        Digest([0; 32]),
    )
    .unwrap()
}
use rusqlite::Connection;

fn key() -> NoteKey {
    NoteKey {
        base: [1; 32],
        audience: [0; 32],
        note: [3; 32],
    }
}
fn package(id: EventId, delta: &[u8]) -> Encoded {
    let metadata = Secret::from_slice(&[4; 32]).unwrap();
    let content = Secret::from_slice(&[5; 32]).unwrap();
    let signer = SigningKey::generate();
    let mut data = key().note.to_vec();
    data.extend(delta);
    seal(
        Binding {
            version: 3,
            highest: 3,
            mode: 0,
            base: key().base,
            audience: key().audience,
            epoch: key_id(&content),
            event_id: id,
            account: AccountId([6; 32]),
            device: DeviceId([7; 32]),
            account_head: AccountHead {
                position: 0,
                hash: [0; 32],
            },
            seen: Head::EMPTY,
            seen_control: [0; 32],
            class: CLASS_CONTENT,
            padded: 0,
            commitment: [0; 32],
            // Packaging only: the outbox never verifies the receipt.
            seen_receipt: [0; bh_sync::receipt::RECEIPT_LEN],
        },
        Payload {
            kind: NOTE,
            data: &data,
        },
        &signer,
        &metadata,
        Some(&content),
    )
    .unwrap()
}
fn sealed(
    id: EventId,
    delta: &[u8],
) -> Result<(bh_sync::OpaqueEvent, bh_sync::BodyObject), StoreError> {
    let encoded = package(id, delta);
    Ok((
        encoded.descriptor,
        bh_sync::BodyObject::new(encoded.body).unwrap(),
    ))
}
fn setup(path: &std::path::Path) -> (DeviceDatabase, i64, Vec<u8>) {
    let mut db = DeviceDatabase::open(path).unwrap();
    let mut note = Note::new().unwrap();
    let delta = note.append_paragraph("test-only note").unwrap();
    let id = db
        .apply_local_update(key(), [8; 16], &delta)
        .unwrap()
        .update_id;
    (db, id, delta)
}

#[test]
fn two_phase_sealing_runs_without_a_container_guard_and_cas_persists_exact_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("two-phase.db");
    let (db, update, delta) = setup(&path);
    let writer = std::sync::Mutex::new(db);
    let candidate = match writer.lock().unwrap().prepare_note_package(update).unwrap() {
        PackagePreparation::Candidate(candidate) => candidate,
        PackagePreparation::Existing(_) => panic!("fresh pending row has no package"),
    };
    let (descriptor, body) = sealed(candidate.event_id, &delta).unwrap();
    let expected = body.bytes().to_vec();
    let stored = writer
        .lock()
        .unwrap()
        .publish_note_package(candidate, descriptor, body)
        .unwrap();
    assert_eq!(stored.body, expected);
    match writer.lock().unwrap().prepare_note_package(update).unwrap() {
        PackagePreparation::Existing(existing) => assert_eq!(existing.body, expected),
        PackagePreparation::Candidate(_) => panic!("duplicate must retain exact attempt"),
    }
}

#[test]
fn sealing_does_not_hold_a_sqlite_write_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("outbox.sqlite");
    let (mut db, update, delta) = setup(&path);
    db.package_note_update(update,|id,_| {
        let independent=Connection::open(&path).unwrap();
        independent.busy_timeout(std::time::Duration::from_millis(20)).unwrap();
        independent.execute("INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",rusqlite::params![[2u8;32].as_slice(),[0u8;32].as_slice(),[3u8;32].as_slice(),[2u8;16].as_slice(),delta.as_slice()]).unwrap();
        sealed(id,&delta)
    }).unwrap();
}

#[test]
fn packaged_exact_bytes_survive_reopen_and_duplicate_ack() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("outbox.sqlite");
    let (mut db, update, delta) = setup(&path);
    let first = db
        .package_note_update(update, |id, pending| {
            assert_eq!(pending.bytes, delta);
            sealed(id, &delta)
        })
        .unwrap();
    assert_ne!(first.event_id.0, [8; 32]);
    assert_eq!(
        first.descriptor.publication_id(Route::Content),
        first.event_id
    );
    assert_ne!(first.descriptor.nonce(), first.event_id);
    let exact_descriptor = first.descriptor.encode();
    let exact_body = first.body.clone();
    let mut called = false;
    let same = db
        .package_note_update(update, |_, _| {
            called = true;
            unreachable!()
        })
        .unwrap();
    assert!(!called);
    assert_eq!(same.descriptor.encode(), exact_descriptor);
    drop(db);
    let mut db = DeviceDatabase::open(&path).unwrap();
    let reopened = db
        .package_note_update(update, |_, _| unreachable!())
        .unwrap();
    assert_eq!(reopened.descriptor.encode(), exact_descriptor);
    assert_eq!(reopened.body, exact_body);
    let ordered = Commitment::order(
        BaseId(key().base),
        before_content(),
        &first.descriptor,
        Route::Content,
    )
    .unwrap();
    assert!(db.acknowledge_note_update(update, &ordered).unwrap());
    assert!(!db.acknowledge_note_update(update, &ordered).unwrap());
    // An ordered Ack records the position; only the verified echo of an
    // accepted package retires its local work.
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    let progress = db.package_progress(update).unwrap().unwrap();
    assert_eq!(progress.position, Some(2));
    assert_eq!(
        progress.outcome,
        Some(bh_storage::sync_state::PackageOutcome::Acked)
    );
    drop(db);
    let mut db = DeviceDatabase::open(&path).unwrap();
    assert!(!db.acknowledge_note_update(update, &ordered).unwrap());
    assert_eq!(
        db.package_note_update(update, |_, _| unreachable!())
            .unwrap()
            .body,
        exact_body
    );
    let conn = Connection::open(&path).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM note_outbox WHERE ack IS NOT NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn rejects_mismatched_package_and_ack_without_retiring_work() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("outbox.sqlite");
    let (mut db, update, delta) = setup(&path);
    assert!(matches!(
        db.package_note_update(update, |_, _| sealed(EventId([99; 32]), &delta)),
        Err(StoreError::InvalidPackage)
    ));
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    let bad_body = db.package_note_update(update, |id, _| {
        let (descriptor, object) = sealed(id, &delta)?;
        let mut bytes = object.bytes().to_vec();
        bytes[0] ^= 1;
        Ok((descriptor, bh_sync::BodyObject::new(bytes).unwrap()))
    });
    assert!(matches!(bad_body, Err(StoreError::InvalidPackage)));
    let first = db
        .package_note_update(update, |id, pending| {
            assert_eq!(pending.bytes, delta);
            sealed(id, &delta)
        })
        .unwrap();
    // A real ordered commitment can use our stored descriptor but place it
    // in another base's log. It must not retire this base's pending update.
    let wrong_base = Commitment::order(
        BaseId([10; 32]),
        before_content(),
        &first.descriptor,
        Route::Content,
    )
    .unwrap();
    assert!(matches!(
        db.acknowledge_note_update(update, &wrong_base),
        Err(StoreError::AckConflict)
    ));
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    assert_eq!(
        db.package_note_update(update, |_, _| unreachable!())
            .unwrap()
            .descriptor
            .encode(),
        first.descriptor.encode()
    );
    let other = package(EventId([99; 32]), &delta);
    let wrong = Commitment::order(
        BaseId(key().base),
        before_content(),
        &other.descriptor,
        Route::Content,
    )
    .unwrap();
    assert!(matches!(
        db.acknowledge_note_update(update, &wrong),
        Err(StoreError::AckConflict)
    ));
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    let ack = Commitment::order(
        BaseId(key().base),
        before_content(),
        &first.descriptor,
        Route::Content,
    )
    .unwrap();
    assert!(db.acknowledge_note_update(update, &ack).unwrap());
    let different = Commitment::order(
        BaseId(key().base),
        ack.after(),
        &first.descriptor,
        Route::Content,
    )
    .unwrap();
    assert!(matches!(
        db.acknowledge_note_update(update, &different),
        Err(StoreError::AckConflict)
    ));
}

#[test]
fn failed_package_insert_does_not_persist_bytes_or_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("outbox.sqlite");
    let (mut db, update, delta) = setup(&path);
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_package BEFORE INSERT ON note_outbox BEGIN SELECT RAISE(ABORT, 'fail'); END;").unwrap();
    assert!(
        db.package_note_update(update, |id, _| sealed(id, &delta))
            .is_err()
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM note_outbox", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    conn.execute_batch("DROP TRIGGER fail_package").unwrap();
    let sealed = db
        .package_note_update(update, |id, _| sealed(id, &delta))
        .unwrap();
    assert_eq!(
        db.package_note_update(update, |_, _| unreachable!())
            .unwrap()
            .descriptor
            .encode(),
        sealed.descriptor.encode()
    );
}

#[test]
fn child_abort_after_package_keeps_exact_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("child.sqlite");
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("child_package_then_abort")
        .arg("--nocapture")
        .env("BH_TEST_CHILD_DB", &path)
        .status()
        .unwrap();
    assert!(!result.success());
    let mut db = DeviceDatabase::open(&path).unwrap();
    let pending = db.pending_note_updates().unwrap();
    assert_eq!(pending.len(), 1);
    let original = db
        .package_note_update(pending[0].update_id, |_, _| unreachable!())
        .unwrap();
    assert_eq!(
        original.event_id,
        original.descriptor.publication_id(Route::Content)
    );
    let conn = Connection::open(&path).unwrap();
    let bytes: Vec<u8> = conn
        .query_row("SELECT descriptor FROM note_outbox", [], |r| r.get(0))
        .unwrap();
    assert_eq!(bytes, original.descriptor.encode());
}

#[test]
fn child_package_then_abort() {
    let Ok(path) = std::env::var("BH_TEST_CHILD_DB") else {
        return;
    };
    let (mut db, update, delta) = setup(std::path::Path::new(&path));
    db.package_note_update(update, |id, _| sealed(id, &delta))
        .unwrap();
    std::process::abort();
}

#[test]
fn failed_ack_commit_retains_pending_and_retries_exact_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("outbox.sqlite");
    let (mut db, update, delta) = setup(&path);
    let first = db
        .package_note_update(update, |id, pending| {
            assert_eq!(pending.bytes, delta);
            sealed(id, &delta)
        })
        .unwrap();
    let ack = Commitment::order(
        BaseId(key().base),
        before_content(),
        &first.descriptor,
        Route::Content,
    )
    .unwrap();
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_ack BEFORE INSERT ON note_outbox_progress BEGIN SELECT RAISE(ABORT, 'fail'); END;").unwrap();
    assert!(db.acknowledge_note_update(update, &ack).is_err());
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    let stored: Option<Vec<u8>> = conn
        .query_row(
            "SELECT ack FROM note_outbox WHERE update_id=?1",
            [update],
            |r| r.get(0),
        )
        .unwrap();
    assert!(stored.is_none());
    conn.execute_batch("DROP TRIGGER fail_ack").unwrap();
    assert!(db.acknowledge_note_update(update, &ack).unwrap());
}

/// The publisher's view: each note's oldest pending update with no Ack and
/// no outcome, in commit order of those heads, and none for a note whose
/// earlier package was refused, rejected or conflicted.
#[test]
fn outbox_heads_one_per_note_in_order_and_summary() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = DeviceDatabase::open(dir.path().join("heads.db")).unwrap();
    let other = NoteKey {
        note: [9; 32],
        ..key()
    };
    let third = NoteKey {
        note: [10; 32],
        ..key()
    };
    let mut ids = Vec::new();
    for (n, key) in [key(), other, key(), other, third].into_iter().enumerate() {
        let mut note = Note::new().unwrap();
        let delta = note.append_paragraph(&format!("update {n}")).unwrap();
        ids.push((
            key,
            db.apply_local_update(key, [n as u8; 16], &delta)
                .unwrap()
                .update_id,
        ));
    }
    let heads = |db: &DeviceDatabase, after| {
        db.outbox_heads(after, 10)
            .unwrap()
            .into_iter()
            .map(|h| (h.key.note, h.update_id))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        heads(&db, 0),
        vec![
            (key().note, ids[0].1),
            (other.note, ids[1].1),
            (third.note, ids[4].1)
        ]
    );
    assert_eq!(heads(&db, ids[0].1), heads(&db, 0)[1..]);
    assert_eq!(db.outbox_heads(0, 1).unwrap().len(), 1);
    let summary = db.outbox_summary().unwrap();
    assert_eq!((summary.unacknowledged, summary.not_accepted_notes), (5, 0));

    // An Ack moves the note's head to its next update.
    let stored = db
        .package_note_update(ids[0].1, |id, pending| sealed(id, &pending.bytes))
        .unwrap();
    let ack = Commitment::order(
        BaseId(key().base),
        before_content(),
        &stored.descriptor,
        Route::Content,
    )
    .unwrap();
    assert!(db.acknowledge_note_update(ids[0].1, &ack).unwrap());
    assert_eq!(
        heads(&db, 0),
        vec![
            (other.note, ids[1].1),
            (key().note, ids[2].1),
            (third.note, ids[4].1)
        ]
    );
    assert_eq!(db.outbox_summary().unwrap().unacknowledged, 4);

    // A refused package holds its note back; the others carry on.
    db.package_note_update(ids[1].1, |id, pending| sealed(id, &pending.bytes))
        .unwrap();
    let raw = Connection::open(dir.path().join("heads.db")).unwrap();
    raw.execute(
        "INSERT INTO note_outbox_progress(update_id,staged,outcome,refusal) VALUES (?1,1,3,2)
         ON CONFLICT(update_id) DO UPDATE SET outcome=3,refusal=2",
        [ids[1].1],
    )
    .unwrap();
    assert_eq!(
        heads(&db, 0),
        vec![(key().note, ids[2].1), (third.note, ids[4].1)]
    );
    let summary = db.outbox_summary().unwrap();
    assert_eq!((summary.unacknowledged, summary.not_accepted_notes), (3, 1));
}

/// A package under an epoch the base's verified content has passed is
/// replaced, in one transaction, by its run sealed again with a new id: only
/// while nothing acknowledged it and content is in another epoch.
#[test]
fn a_package_under_a_passed_epoch_is_replaced_by_its_run_sealed_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reseal.sqlite");
    let (mut db, update, delta) = setup(&path);
    db.record_registration(key().base, None, [7; 32]).unwrap();
    let sealed_under = [0x5e; 32];
    let epoch = |epoch: Option<[u8; 32]>| {
        let sql = Connection::open(&path).unwrap();
        sql.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        sql.execute(
            "UPDATE log_progress SET epoch_id=?2 WHERE log_kind=1 AND log_id=?1",
            rusqlite::params![key().base.as_slice(), epoch.as_ref().map(|e| e.as_slice())],
        )
        .unwrap();
    };
    epoch(Some(sealed_under));
    let first = db
        .package_note_update(update, |id, _| sealed(id, &delta))
        .unwrap();
    let reseal = |db: &mut DeviceDatabase, old: EventId| {
        let candidate = db.prepare_note_reseal(update).unwrap().unwrap();
        assert_eq!(candidate.pending.bytes, delta);
        let (descriptor, body) = sealed(candidate.event_id, &delta).unwrap();
        db.publish_note_reseal(candidate, old, sealed_under, descriptor, body)
            .unwrap()
    };
    // Content is still in the package's epoch: it stays as it is.
    assert!(reseal(&mut db, first.event_id).is_none());
    // Content passed the removal that closed it.
    epoch(None);
    assert!(
        reseal(&mut db, EventId([1; 32])).is_none(),
        "only the package as read"
    );
    let again = reseal(&mut db, first.event_id).unwrap();
    assert_ne!(again.event_id, first.event_id);
    assert!(
        reseal(&mut db, first.event_id).is_none(),
        "the old package is gone"
    );
    drop(db);
    let mut db = DeviceDatabase::open(&path).unwrap();
    let kept = db
        .package_note_update(update, |_, _| unreachable!())
        .unwrap();
    assert_eq!(kept.event_id, again.event_id);
    assert_eq!(kept.descriptor.encode(), again.descriptor.encode());
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    // Acknowledged, a package is never replaced.
    let ordered = Commitment::order(
        BaseId(key().base),
        before_content(),
        &again.descriptor,
        Route::Content,
    )
    .unwrap();
    db.acknowledge_note_update(update, &ordered).unwrap();
    epoch(Some([0x6f; 32]));
    assert!(db.prepare_note_reseal(update).unwrap().is_none());
}
