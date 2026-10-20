//! Genuine v11 fixtures use the production migration chain only through 11,
//! never a current database with its version number relabelled.
use super::*;
use rusqlite::{
    hooks::{AuthAction, Authorization},
    types::Value,
};
use std::collections::BTreeMap;

fn legacy(path: &Path) -> Connection {
    let mut conn = Connection::open(path).unwrap();
    conn.pragma_update(None, "foreign_keys", true).unwrap();
    for (_, to, migrate) in MIGRATIONS.iter().filter(|(_, to, _)| *to <= 11) {
        let tx = conn.transaction().unwrap();
        migrate(&tx).unwrap();
        tx.pragma_update(None, "user_version", to).unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(version(&conn).unwrap(), 11);
    conn.execute(
        "INSERT INTO account_state VALUES(1,?1,3,?2,0)",
        params![[1u8; 32], [2u8; 32]],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO account_device VALUES(1,?1,?2,?3,?4,0,0)",
        params![[3u8; 32], [4u8; 32], [5u8; 32], vec![6u8; 1216]],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO own_base VALUES(1,?1,?2,?3,?4,?5)",
        params![
            [1u8; 32],
            [2u8; 32],
            b"genesis descriptor",
            b"genesis body",
            b"retained encrypted keys"
        ],
    )
    .unwrap();
    for id in 1i64..=14 {
        let note = ((id - 1) / 3 + 3) as u8;
        conn.execute(
            "INSERT INTO note_updates VALUES(?1,?2,zeroblob(32),?3,?4,x'0000')",
            params![id, [2u8; 32], [note; 32], (id as u128).to_le_bytes()],
        )
        .unwrap();
        conn.execute("INSERT INTO pending_note_work VALUES(?1)", [id])
            .unwrap();
        conn.execute(
            "INSERT INTO pending_scope SELECT id,base,audience,note FROM note_updates WHERE id=?1",
            [id],
        )
        .unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO note_writer_slots VALUES(?1,zeroblob(32),?2,?3,?4,0,?5,42,0)",
            params![[2u8; 32], [note; 32], [1u8; 32], [3u8; 32], [7u8; 32]],
        )
        .unwrap();
        conn.execute("INSERT INTO note_update_writer SELECT id,base,audience,note,?2,?3,0 FROM note_updates WHERE id=?1",params![id,[1u8;32],[3u8;32]]).unwrap();
    }
    for (id, outcome) in [
        (1, None),
        (4, Some(1)),
        (7, Some(3)),
        (10, Some(6)),
        (14, None),
    ] {
        let (descriptor, body) = sealed(id as u8);
        let ack = if outcome.is_some() {
            Some(
                Commitment::order(
                    bh_sync::BaseId([2; 32]),
                    bh_sync::Head {
                        position: 1,
                        hash: bh_sync::Digest([8; 32]),
                    },
                    &descriptor,
                    bh_sync::Route::Content,
                )
                .unwrap()
                .encode(),
            )
        } else {
            None
        };
        conn.execute(
            "INSERT INTO note_outbox VALUES(?1,?2,?3,?4,?5)",
            params![
                id,
                descriptor.id().0,
                descriptor.encode(),
                body.bytes(),
                ack
            ],
        )
        .unwrap();
        if let Some(outcome) = outcome {
            conn.execute(
                "INSERT INTO note_outbox_progress VALUES(?1,1,2,?2,?3)",
                params![id, outcome, if outcome == 3 { Some(2) } else { None }],
            )
            .unwrap();
        }
    }
    conn
}
fn sealed(id: u8) -> (OpaqueEvent, BodyObject) {
    use bh_event::{Binding, Payload};
    let content = bh_crypto::Secret::from_slice(&[5; 32]).unwrap();
    let encoded = bh_event::seal(
        Binding {
            version: 2,
            highest: 2,
            mode: 0,
            base: [2; 32],
            audience: [0; 32],
            epoch: bh_event::key_id(&content),
            event_id: EventId([id; 32]),
            account: bh_account::AccountId([1; 32]),
            device: bh_account::DeviceId([3; 32]),
            account_head: bh_account::Head {
                position: 3,
                hash: [8; 32],
            },
            seen: bh_sync::Head::EMPTY,
            seen_control: [0; 32],
            class: bh_event::CLASS_CONTENT,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: [0; 300],
        },
        Payload {
            kind: bh_event::NOTE,
            data: &[0, 0],
        },
        &bh_crypto::SigningKey::generate(),
        &content,
        Some(&content),
    )
    .unwrap();
    (encoded.descriptor, BodyObject::new(encoded.body).unwrap())
}
fn snapshot(conn: &Connection) -> BTreeMap<String, Vec<Vec<Value>>> {
    let tables:Vec<String> = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name!='note_outbox_members' ORDER BY name").unwrap()
        .query_map([],|r|r.get(0)).unwrap().map(Result::unwrap).collect();
    tables
        .into_iter()
        .map(|name| {
            let mut s = conn
                .prepare(&format!("SELECT * FROM {name} ORDER BY 1,2"))
                .or_else(|_| conn.prepare(&format!("SELECT * FROM {name} ORDER BY 1")))
                .unwrap();
            let n = s.column_count();
            let rows = s
                .query_map([], |r| (0..n).map(|i| r.get(i)).collect())
                .unwrap()
                .map(Result::unwrap)
                .collect();
            (name, rows)
        })
        .collect()
}
#[test]
fn genuine_v11_upgrade_preserves_every_row_and_legacy_singletons() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v11.db");
    let raw = legacy(&path);
    let before = snapshot(&raw);
    let mut db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.data_version(), 12);
    assert_eq!(snapshot(&raw), before);
    assert_eq!(
        raw.query_row("SELECT count(*) FROM note_outbox_members", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0,
        "no historical backfill"
    );
    assert_eq!(db.package_pending_count(1).unwrap(), 1);
    assert!(
        db.package_progress(13).unwrap().is_none(),
        "a future singleton never covers its predecessor"
    );
    let heads = db.outbox_heads(0, 256).unwrap();
    assert!(heads.iter().any(|h| h.update_id == 1)); // old unacked
    assert!(heads.iter().any(|h| h.update_id == 6)); // after old Ack
    assert!(!heads.iter().any(|h| h.key.note == [5; 32])); // old refusal
    assert!(heads.iter().any(|h| h.update_id == 12)); // after old held echo
    assert!(heads.iter().any(|h| h.update_id == 13)); // stops before singleton 14
    let PackagePreparation::Candidate(c) = db.prepare_note_package(6).unwrap() else {
        panic!("new run")
    };
    let (descriptor, body) = package(c.event_id, &c.pending);
    db.publish_note_package(c, descriptor, body).unwrap();
    assert_eq!(db.package_pending_count(4).unwrap(), 1);
    assert_eq!(db.package_pending_count(6).unwrap(), 2);
    assert_eq!(db.package_progress(5).unwrap().unwrap().outcome, None);
    drop(db);
    let mut db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.data_version(), 12);
    assert_eq!(db.package_pending_count(6).unwrap(), 2);
    let after = snapshot(&raw);
    for table in [
        "account_state",
        "account_device",
        "own_base",
        "note_updates",
        "note_update_writer",
        "note_outbox_progress",
    ] {
        assert_eq!(after[table], before[table], "{table} bytes retained");
    }
    assert!(
        before["note_outbox"]
            .iter()
            .all(|row| after["note_outbox"].contains(row)),
        "every legacy descriptor, body and Ack is byte-identical"
    );
    let mapping: Vec<(i64, i64)> = raw
        .prepare("SELECT update_id,package_update_id FROM note_outbox_members ORDER BY update_id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        mapping,
        vec![(5, 6), (6, 6)],
        "all new members, including terminal; no legacy backfill"
    );
    db.record_registration([2; 32], None, [8; 32]).unwrap();
    let PackagePreparation::Existing(stored) = db.prepare_note_package(6).unwrap() else {
        panic!("persisted")
    };
    let ordered = Commitment::order(
        bh_sync::BaseId([2; 32]),
        bh_sync::Head {
            position: 1,
            hash: bh_sync::Digest([8; 32]),
        },
        &stored.descriptor,
        bh_sync::Route::Content,
    )
    .unwrap();
    db.release_held(
        &sync_state::IncomingNote {
            key: NoteKey {
                base: [2; 32],
                audience: [0; 32],
                note: [4; 32],
            },
            accepted: vec![],
            compacted: None,
            bindings: vec![],
            remote: vec![],
            rebuild_working: None,
            title: None,
        },
        2,
        &[sync_state::OwnOutcome {
            update_id: 6,
            ordered,
            outcome: sync_state::PackageOutcome::Accepted,
            publishing_stopped: false,
        }],
    )
    .unwrap();
    assert_eq!(db.package_pending_count(6).unwrap(), 0);
    assert_eq!(
        db.package_pending_count(4).unwrap(),
        1,
        "accepted batch never retires older singleton"
    );
    assert_eq!(
        db.package_progress(5).unwrap().unwrap().outcome,
        Some(sync_state::PackageOutcome::Accepted)
    );
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM note_outbox_members WHERE package_update_id=6",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2,
        "retain historical membership"
    );
}
fn package(event: EventId, pending: &PendingNoteUpdate) -> (OpaqueEvent, BodyObject) {
    let content = bh_crypto::Secret::from_slice(&[5; 32]).unwrap();
    let encoded = bh_event::seal(
        bh_event::Binding {
            version: 2,
            highest: 2,
            mode: 0,
            base: pending.key.base,
            audience: pending.key.audience,
            epoch: bh_event::key_id(&content),
            event_id: event,
            account: bh_account::AccountId([1; 32]),
            device: bh_account::DeviceId([3; 32]),
            account_head: bh_account::Head {
                position: 3,
                hash: [8; 32],
            },
            seen: bh_sync::Head::EMPTY,
            seen_control: [0; 32],
            class: bh_event::CLASS_CONTENT,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: [0; 300],
        },
        bh_event::Payload {
            kind: bh_event::NOTE,
            data: &pending.bytes,
        },
        &bh_crypto::SigningKey::generate(),
        &content,
        Some(&content),
    )
    .unwrap();
    (encoded.descriptor, BodyObject::new(encoded.body).unwrap())
}
#[test]
fn failed_v12_version_write_rolls_back_table_index_and_data_then_retries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fail.db");
    let mut raw = legacy(&path);
    let before = snapshot(&raw);
    raw.authorizer(Some(|ctx: rusqlite::hooks::AuthContext<'_>| {
        match ctx.action {
            AuthAction::Pragma {
                pragma_name: "user_version",
                pragma_value: Some("12"),
            } => Authorization::Deny,
            _ => Authorization::Allow,
        }
    }))
    .unwrap();
    assert!(
        initialize(&mut raw).is_err(),
        "failure after DDL, before version commit"
    );
    raw.authorizer(None::<fn(rusqlite::hooks::AuthContext<'_>) -> Authorization>)
        .unwrap();
    assert_eq!(version(&raw).unwrap(), 11);
    assert_eq!(snapshot(&raw), before);
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM sqlite_master WHERE name LIKE 'note_outbox_members%'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    initialize(&mut raw).unwrap();
    assert_eq!(version(&raw).unwrap(), 12);
    assert_eq!(snapshot(&raw), before);
}
#[test]
fn package_and_members_are_atomic_and_overlapping_candidates_cannot_both_win() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("race.db");
    let raw = legacy(&path);
    let mut db = DeviceDatabase::open(&path).unwrap();
    let candidate = |db: &DeviceDatabase, id| match db.prepare_note_package(id).unwrap() {
        PackagePreparation::Candidate(c) => c,
        _ => panic!("fresh"),
    };
    let short = candidate(&db, 5);
    let long = candidate(&db, 6);
    raw.execute_batch("CREATE TRIGGER fail_members BEFORE INSERT ON note_outbox_members WHEN NEW.update_id=6 BEGIN SELECT RAISE(ABORT,'injected member failure'); END").unwrap();
    let (d, b) = package(long.event_id, &long.pending);
    assert!(db.publish_note_package(long, d, b).is_err());
    assert!(db.package_progress(5).unwrap().is_none());
    assert!(db.package_progress(6).unwrap().is_none());
    assert_eq!(
        raw.query_row("SELECT count(*) FROM note_outbox_members", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    raw.execute_batch("DROP TRIGGER fail_members").unwrap();
    let long = candidate(&db, 6);
    let (d, b) = package(long.event_id, &long.pending);
    db.publish_note_package(long, d, b).unwrap();
    let (d, b) = package(short.event_id, &short.pending);
    assert!(matches!(
        db.publish_note_package(short, d, b),
        Err(StoreError::RequestConflict)
    ));
    assert_eq!(db.package_pending_count(6).unwrap(), 2);
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM note_outbox WHERE update_id=5",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    // Reverse winning order on another note: a shorter package cannot be
    // absorbed by a stale, longer candidate either.
    let short = candidate(&db, 11);
    let long = candidate(&db, 12);
    let (d, b) = package(short.event_id, &short.pending);
    db.publish_note_package(short, d, b).unwrap();
    let (d, b) = package(long.event_id, &long.pending);
    assert!(matches!(
        db.publish_note_package(long, d, b),
        Err(StoreError::RequestConflict)
    ));
    assert!(db.package_progress(12).unwrap().is_none());
    assert_eq!(db.package_pending_count(11).unwrap(), 1);
}
