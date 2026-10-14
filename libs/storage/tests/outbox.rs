//! Test-only identities and keys. No production session is inferred from these.
use bh_account::{AccountId, DeviceId, Head as AccountHead};
use bh_core::note::Note;
use bh_crypto::{Secret, SigningKey};
use bh_event::{Binding, CLASS_CONTENT, Encoded, NOTE, Payload, key_id, seal};
use bh_storage::{DeviceDatabase, NoteKey, StoreError};
use bh_sync::{BaseId, Commitment, EventId, Head};
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
            version: 1,
            highest: 1,
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
    let mut note = Note::new();
    let delta = note.append_paragraph("test-only note");
    let id = db
        .apply_local_update(key(), [8; 16], &delta)
        .unwrap()
        .update_id;
    (db, id, delta)
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
    assert_eq!(first.descriptor.id(), first.event_id);
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
        Head {
            position: 1,
            hash: bh_sync::Digest([9; 32]),
        },
        &first.descriptor,
    )
    .unwrap();
    assert!(db.acknowledge_note_update(update, &ordered).unwrap());
    assert!(!db.acknowledge_note_update(update, &ordered).unwrap());
    assert!(db.pending_note_updates().unwrap().is_empty());
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
        Head {
            position: 1,
            hash: bh_sync::Digest([9; 32]),
        },
        &first.descriptor,
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
        Head {
            position: 1,
            hash: bh_sync::Digest([9; 32]),
        },
        &other.descriptor,
    )
    .unwrap();
    assert!(matches!(
        db.acknowledge_note_update(update, &wrong),
        Err(StoreError::AckConflict)
    ));
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    let ack = Commitment::order(
        BaseId(key().base),
        Head {
            position: 1,
            hash: bh_sync::Digest([9; 32]),
        },
        &first.descriptor,
    )
    .unwrap();
    assert!(db.acknowledge_note_update(update, &ack).unwrap());
    let different = Commitment::order(
        BaseId(key().base),
        Head {
            position: 2,
            hash: bh_sync::Digest([9; 32]),
        },
        &first.descriptor,
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
    assert_eq!(original.event_id, original.descriptor.id());
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
        Head {
            position: 1,
            hash: bh_sync::Digest([9; 32]),
        },
        &first.descriptor,
    )
    .unwrap();
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_ack BEFORE DELETE ON pending_note_work BEGIN SELECT RAISE(ABORT, 'fail'); END;").unwrap();
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
