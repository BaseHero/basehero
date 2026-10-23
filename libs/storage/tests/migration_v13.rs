//! Device-local v12→v13: the typed-data layout starts from the existing
//! catalogue without rewriting any pre-v13 row, and a failed step leaves v12.
use bh_core::LOCAL_DATA_VERSION;
use bh_data::{
    FieldPath, KeyRef, Position, Scope, TypeId,
    catalogue::Shipped,
    query::{Budget, Completeness, Gap, Query, SortKey, TypeSelect, run},
    store::{coverage, records},
};
use bh_event::{Binding, CLASS_CONTENT, NOTE, Payload, key_id, seal};
use bh_storage::{
    DeviceDatabase, NoteKey, StoreError,
    sync_state::{LOG_BASE, PackageOutcome},
};
use bh_sync::{BodyObject, EventId};
use rusqlite::{Connection, params};
use std::collections::BTreeMap;

#[path = "support/legacy.rs"]
mod legacy;

const ACCOUNT: [u8; 32] = [1; 32];
const BASE: [u8; 32] = [2; 32];
const OWN_BASE: [u8; 32] = [3; 32];
const AUDIENCE: [u8; 32] = [0; 32];
const NOTES: [[u8; 32]; 3] = [[10; 32], [11; 32], [12; 32]];

fn key(note: [u8; 32]) -> NoteKey {
    NoteKey {
        base: BASE,
        audience: AUDIENCE,
        note,
    }
}

fn sealed(id: u8) -> (Vec<u8>, Vec<u8>) {
    let metadata = bh_crypto::Secret::from_slice(&[4; 32]).unwrap();
    let content = bh_crypto::Secret::from_slice(&[5; 32]).unwrap();
    let encoded = seal(
        Binding {
            version: 2,
            highest: 2,
            mode: 0,
            base: BASE,
            audience: AUDIENCE,
            epoch: key_id(&content),
            event_id: EventId([id; 32]),
            account: bh_account::AccountId(ACCOUNT),
            device: bh_account::DeviceId([6; 32]),
            account_head: bh_account::Head {
                position: 0,
                hash: [0; 32],
            },
            seen: bh_sync::Head::EMPTY,
            seen_control: [0; 32],
            class: CLASS_CONTENT,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: [0; bh_sync::receipt::RECEIPT_LEN],
        },
        Payload {
            kind: NOTE,
            data: &[id, id],
        },
        &bh_crypto::SigningKey::generate(),
        &metadata,
        Some(&content),
    )
    .unwrap();
    let body = BodyObject::new(encoded.body).unwrap();
    (encoded.descriptor.encode(), body.bytes().to_vec())
}

fn insert_update(conn: &Connection, id: i64, note: [u8; 32], delta: &[u8], pending: bool) {
    conn.execute(
        "INSERT INTO note_updates(id,base,audience,note,request,delta) VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            id,
            BASE.as_slice(),
            AUDIENCE.as_slice(),
            note.as_slice(),
            [id as u8; 16].as_slice(),
            delta
        ],
    )
    .unwrap();
    if pending {
        conn.execute("INSERT INTO pending_note_work(update_id) VALUES(?1)", [id])
            .unwrap();
        conn.execute(
            "INSERT INTO pending_scope(update_id,base,audience,note) VALUES(?1,?2,?3,?4)",
            params![id, BASE.as_slice(), AUDIENCE.as_slice(), note.as_slice()],
        )
        .unwrap();
    }
}

fn insert_outbox(conn: &Connection, package: i64, members: &[i64], progress: Option<i64>) {
    let (descriptor, body) = sealed((package + 20) as u8);
    conn.execute(
        "INSERT INTO note_outbox(update_id,event_id,descriptor,body) VALUES(?1,?2,?3,?4)",
        params![
            package,
            [(package + 20) as u8; 32].as_slice(),
            descriptor,
            body
        ],
    )
    .unwrap();
    for member in members {
        conn.execute(
            "INSERT INTO note_outbox_members(update_id,package_update_id) VALUES(?1,?2)",
            params![member, package],
        )
        .unwrap();
    }
    if let Some(outcome) = progress {
        conn.execute(
            "INSERT INTO note_outbox_progress(update_id,staged,acked_position,outcome) VALUES(?1,1,2,?2)",
            params![package, outcome],
        )
        .unwrap();
    }
}

/// A genuine v12 database: the current chain's pre-v13 rows, then its v13
/// additions and marker removed. The packages look exactly as the previous
/// version wrote them.
fn v12_fixture(path: &std::path::Path) -> Connection {
    let conn = legacy::v12(path);
    conn.execute("UPDATE note_counter SET value=3 WHERE id=1", [])
        .unwrap();
    for (index, note) in NOTES.iter().enumerate() {
        conn.execute(
            "INSERT INTO notes(base,audience,note,touched,title) VALUES(?1,?2,?3,?4,?5)",
            params![
                BASE.as_slice(),
                AUDIENCE.as_slice(),
                note.as_slice(),
                (index + 1) as i64,
                format!("title {index}")
            ],
        )
        .unwrap();
    }
    insert_update(&conn, 1, NOTES[0], b"pending one", true);
    insert_update(&conn, 2, NOTES[1], b"member two", true);
    insert_update(&conn, 3, NOTES[1], b"member three", true);
    insert_update(&conn, 4, NOTES[2], b"accepted four", false);
    insert_update(&conn, 5, NOTES[2], b"accepted five", false);
    insert_update(&conn, 8, NOTES[0], b"old singleton", true);
    insert_update(&conn, 9, NOTES[2], b"held nine", false);
    insert_outbox(&conn, 3, &[2, 3], None);
    insert_outbox(&conn, 5, &[4, 5], Some(2));
    insert_outbox(&conn, 8, &[], None);
    insert_outbox(&conn, 9, &[9], Some(6));
    conn.execute(
        "INSERT INTO note_writer_slots(base,audience,note,account,device,slot,nonce,client_id,retired)
         VALUES(?1,?2,?3,?4,?5,0,?6,42,0)",
        params![
            BASE.as_slice(),
            AUDIENCE.as_slice(),
            NOTES[0].as_slice(),
            ACCOUNT.as_slice(),
            [6u8; 32].as_slice(),
            [7u8; 32].as_slice()
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO note_update_writer(base,audience,note,update_id,account,device,slot)
         VALUES(?1,?2,?3,1,?4,?5,0)",
        params![
            BASE.as_slice(),
            AUDIENCE.as_slice(),
            NOTES[0].as_slice(),
            ACCOUNT.as_slice(),
            [6u8; 32].as_slice()
        ],
    )
    .unwrap();
    for (note, position) in [(NOTES[2], 2), ([13u8; 32], 3)] {
        conn.execute(
            "INSERT INTO held_note_event(base,audience,note,position,commitment) VALUES(?1,?2,?3,?4,?5)",
            params![
                OWN_BASE.as_slice(),
                AUDIENCE.as_slice(),
                note.as_slice(),
                position,
                [position as u8; 44].as_slice()
            ],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO own_base(id,account,base,genesis_descriptor,genesis_body,initial_key_package)
         VALUES(1,?1,?2,x'01',x'02',x'03')",
        params![ACCOUNT.as_slice(), OWN_BASE.as_slice()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO log_progress(log_kind,log_id,position,head_hash,receipt,control_digest,stopped_reason,hosting_root,account_position,account_hash,metadata_id,epoch_id,floor)
         VALUES(1,?1,0,zeroblob(32),NULL,zeroblob(32),NULL,zeroblob(32),NULL,NULL,NULL,NULL,1)",
        [BASE.as_slice()],
    )
    .unwrap();
    conn
}

fn v12_tables(conn: &Connection) -> Vec<String> {
    conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'data\\_%' ESCAPE '\\' AND name<>'note_projection_repair' AND name<>'sqlite_sequence' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn snapshot(
    conn: &Connection,
    tables: &[String],
) -> BTreeMap<String, Vec<Vec<rusqlite::types::Value>>> {
    tables
        .iter()
        .map(|table| (table.clone(), legacy::dump(conn, table)))
        .collect()
}

/// An earlier v12 build without the held-note extension: no held table and a
/// progress domain that stops at 5. The next open must widen it after v13.
fn without_held_layout(conn: &Connection) {
    conn.execute_batch(
        "DELETE FROM note_outbox_progress WHERE update_id=9;
         DELETE FROM note_outbox_members WHERE package_update_id=9;
         DELETE FROM note_outbox WHERE update_id=9;
         DELETE FROM note_updates WHERE id=9;
         DROP TABLE held_note_event;
         DROP TABLE note_outbox_progress;
         CREATE TABLE note_outbox_progress (
            update_id INTEGER PRIMARY KEY REFERENCES note_outbox(update_id),
            staged INTEGER NOT NULL DEFAULT 0 CHECK(staged IN (0,1)),
            acked_position INTEGER CHECK(acked_position IS NULL OR acked_position>0),
            outcome INTEGER CHECK(outcome IS NULL OR outcome BETWEEN 1 AND 5),
            refusal INTEGER CHECK(refusal IS NULL OR (outcome=3 AND refusal BETWEEN 1 AND 255)),
            CHECK(outcome!=3 OR refusal IS NOT NULL));",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO note_outbox_progress(update_id,staged,acked_position,outcome) VALUES(5,1,2,2)",
        [],
    )
    .unwrap();
}
#[test]
fn genuine_v12_upgrade_preserves_rows_and_package_outcomes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v12.sqlite");
    let raw = v12_fixture(&path);
    let tables = v12_tables(&raw);
    let before = snapshot(&raw, &tables);
    drop(raw);

    let db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.data_version(), LOCAL_DATA_VERSION);
    let raw = Connection::open(&path).unwrap();
    assert_eq!(legacy::version(&raw), LOCAL_DATA_VERSION);
    assert_eq!(snapshot(&raw, &tables), before, "every v12 row survives");
    for table in [
        "note_outbox",
        "note_outbox_members",
        "note_outbox_progress",
        "held_note_event",
        "log_progress",
        "note_writer_slots",
    ] {
        assert!(legacy::table_exists(&raw, table), "{table}");
    }

    // Historical sealed rows retain their exact bytes, but nonce-keyed
    // packages must not be reinterpreted as routed canonical publications.
    for member in [2, 3, 4, 5, 8, 9] {
        for _ in 0..2 {
            assert!(matches!(
                db.prepare_note_package(member),
                Err(StoreError::CorruptOutbox)
            ));
        }
    }
    assert_eq!(
        db.package_progress(4).unwrap().unwrap().outcome,
        Some(PackageOutcome::Accepted)
    );
    assert_eq!(
        db.package_progress(9).unwrap().unwrap().outcome,
        Some(PackageOutcome::Held)
    );
    assert_eq!(db.package_pending_count(3).unwrap(), 2);
    assert_eq!(db.package_pending_count(8).unwrap(), 1);
    assert_eq!(db.package_pending_count(5).unwrap(), 0);
    let pending: Vec<i64> = db
        .pending_note_updates()
        .unwrap()
        .into_iter()
        .map(|update| update.update_id)
        .collect();
    assert_eq!(pending, vec![1, 2, 3, 8]);
    assert!(db.has_held_notes().unwrap());
    assert!(!db.note_is_held(key(NOTES[2])).unwrap());
    for note in [NOTES[2], [13; 32]] {
        assert!(
            db.note_is_held(NoteKey {
                base: OWN_BASE,
                audience: AUDIENCE,
                note,
            })
            .unwrap()
        );
    }
    assert_eq!(db.writer_reservations(key(NOTES[0])).unwrap().len(), 1);
    assert!(
        matches!(
            db.log_progress(LOG_BASE, BASE),
            Err(StoreError::CorruptSyncState)
        ),
        "a populated markerless log cannot be relabelled canonical"
    );

    assert_eq!(
        raw.query_row("SELECT count(*) FROM data_record", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM data_text_job", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM data_fts", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0,
        "only body jobs are queued, not eager FTS rows"
    );
    let ready: i64 = raw
        .query_row(
            "SELECT count(*) FROM data_index WHERE name='recent' AND state='ready'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let changed: Vec<i64> = raw
        .prepare("SELECT k1 FROM data_index_entry ORDER BY k1")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(ready, 2, "the Note scope and the empty own-base scope");
    assert_eq!(changed.len(), 3);
    assert!(changed.windows(2).all(|pair| pair[0] < pair[1]));
    let seeded_titles: Vec<String> = raw
        .prepare(
            "SELECT json_extract(r.accepted,'$.title') FROM data_index_entry e
             JOIN data_record r ON r.id=e.rec ORDER BY e.k1",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(seeded_titles, ["title 0", "title 1", "title 2"]);
    let page = run(
        &raw,
        Scope {
            base: BASE,
            audience: AUDIENCE,
        },
        &[Scope {
            base: BASE,
            audience: AUDIENCE,
        }],
        &Shipped,
        &Query {
            select: TypeSelect::Family(TypeId::core("note")),
            filter: None,
            sort: vec![SortKey {
                key: KeyRef::Changed,
                desc: true,
            }],
            fields: vec![FieldPath::parse("/title").unwrap()],
            follow: vec![],
            text: None,
            limit: 50,
            after: None,
        },
        Budget::INTERACTIVE,
    )
    .unwrap();
    let listed: Vec<String> = page
        .rows
        .iter()
        .map(|row| row.values["/title"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        listed,
        ["title 2", "title 1", "title 0"],
        "the complete Note list is visible without a backfill wait"
    );
    assert_eq!(
        page.completeness,
        Completeness::Complete,
        "every catalogue Note is projected after the upgrade"
    );
    let sid: i64 = records::lookup_scope(
        &raw,
        Scope {
            base: BASE,
            audience: AUDIENCE,
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        coverage::get(&raw, sid).unwrap(),
        coverage::Coverage {
            through: Some(Position(0)),
            complete: true,
        },
        "no held Note is missing from this scope"
    );
    let own_sid = records::lookup_scope(
        &raw,
        Scope {
            base: OWN_BASE,
            audience: AUDIENCE,
        },
    )
    .unwrap()
    .expect("the own base's ordinary audience exists before its first Note");
    assert_eq!(
        coverage::get(&raw, own_sid).unwrap(),
        coverage::Coverage {
            through: Some(Position(0)),
            complete: true,
        },
        "the typed log is complete; a held Note is a gap in its own record"
    );
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM data_note_gap WHERE scope=?1",
            [own_sid],
            |r| r.get::<_, i64>(0),
        )
        .unwrap(),
        2,
        "both held Notes carry their gaps into v13"
    );
    let held = run(
        &raw,
        Scope {
            base: OWN_BASE,
            audience: AUDIENCE,
        },
        &[Scope {
            base: OWN_BASE,
            audience: AUDIENCE,
        }],
        &Shipped,
        &Query {
            select: TypeSelect::Family(TypeId::core("note")),
            filter: None,
            sort: vec![SortKey {
                key: KeyRef::Changed,
                desc: true,
            }],
            fields: vec![FieldPath::parse("/title").unwrap()],
            follow: vec![],
            text: None,
            limit: 50,
            after: None,
        },
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert!(held.rows.is_empty());
    assert_eq!(
        held.completeness,
        Completeness::Incomplete(vec![Gap::NoteUnavailable]),
        "a held Note never reads as an empty audience"
    );

    drop(db);
    let db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.data_version(), LOCAL_DATA_VERSION);
    let raw = Connection::open(&path).unwrap();
    assert_eq!(
        snapshot(&raw, &tables),
        before,
        "ordinary reopen rewrites no v12 row"
    );
    for member in [2, 3, 4, 5, 8, 9] {
        assert!(matches!(
            db.prepare_note_package(member),
            Err(StoreError::CorruptOutbox)
        ));
    }
    assert_eq!(
        raw.query_row("SELECT count(*) FROM data_record", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        3
    );
}

#[test]
fn empty_own_base_lists_complete_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.sqlite");
    let raw = v12_fixture(&path);
    raw.execute("DELETE FROM notes", []).unwrap();
    raw.execute("DELETE FROM held_note_event", []).unwrap();
    let tables = v12_tables(&raw);
    let before = snapshot(&raw, &tables);
    drop(raw);

    drop(DeviceDatabase::open(&path).unwrap());
    let raw = Connection::open(&path).unwrap();
    assert_eq!(snapshot(&raw, &tables), before, "empty v12 rows survive");
    let scope = Scope {
        base: OWN_BASE,
        audience: AUDIENCE,
    };
    let sid = records::lookup_scope(&raw, scope)
        .unwrap()
        .expect("the own base's ordinary audience");
    assert_eq!(
        coverage::get(&raw, sid).unwrap(),
        coverage::Coverage {
            through: Some(Position(0)),
            complete: true,
        },
        "an empty base with nothing held lists as complete-empty"
    );
    let page = run(
        &raw,
        scope,
        &[scope],
        &Shipped,
        &Query {
            select: TypeSelect::Family(TypeId::core("note")),
            filter: None,
            sort: vec![SortKey {
                key: KeyRef::Changed,
                desc: true,
            }],
            fields: vec![FieldPath::parse("/title").unwrap()],
            follow: vec![],
            text: None,
            limit: 50,
            after: None,
        },
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert!(page.rows.is_empty());
    assert_eq!(page.completeness, Completeness::Complete);
}

#[test]
fn earlier_v12_without_held_layout_gains_it_after_v13() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("earlier-v12.sqlite");
    let raw = v12_fixture(&path);
    without_held_layout(&raw);
    let tables = v12_tables(&raw);
    let before = snapshot(&raw, &tables);
    drop(raw);

    let db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.data_version(), LOCAL_DATA_VERSION);
    let raw = Connection::open(&path).unwrap();
    assert_eq!(snapshot(&raw, &tables), before, "v12 rows survive");
    assert!(legacy::table_exists(&raw, "held_note_event"));
    assert!(!db.has_held_notes().unwrap());
    let sid = records::lookup_scope(
        &raw,
        Scope {
            base: BASE,
            audience: AUDIENCE,
        },
    )
    .unwrap()
    .unwrap();
    assert!(
        coverage::get(&raw, sid).unwrap().complete,
        "a layout with no held-note table holds nothing back"
    );
    assert_eq!(
        db.package_progress(5).unwrap().unwrap().outcome,
        Some(PackageOutcome::Accepted)
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM data_record", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        3,
        "held rows are not catalogue Notes and are not seeded"
    );
    drop(db);
    let db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.data_version(), LOCAL_DATA_VERSION);
    assert_eq!(
        db.package_progress(5).unwrap().unwrap().outcome,
        Some(PackageOutcome::Accepted)
    );
}
#[test]
fn failed_v13_step_rolls_back_to_v12() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("failed.sqlite");
    let raw = v12_fixture(&path);
    let tables = v12_tables(&raw);
    let before = snapshot(&raw, &tables);
    drop(raw);
    bh_storage::testkit::fail_seeding_after(Some(1));
    let result = DeviceDatabase::open(&path);
    bh_storage::testkit::fail_seeding_after(None);
    assert!(
        result.is_err(),
        "injected failure after the first projection"
    );
    let raw = Connection::open(&path).unwrap();
    assert_eq!(legacy::version(&raw), 12, "failed step leaves v12");
    assert_eq!(snapshot(&raw, &tables), before, "v12 rows untouched");
    assert!(!legacy::table_exists(&raw, "data_record"));
    assert!(!legacy::table_exists(&raw, "data_scope"));
    assert_eq!(
        raw.query_row("SELECT count(*) FROM note_outbox_members", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        5
    );
}

fn counts(conn: &Connection) -> (i64, i64, i64, i64, i64) {
    let count = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap() };
    (
        count("SELECT next FROM data_seq WHERE id=1"),
        count("SELECT count(*) FROM data_record"),
        count("SELECT count(*) FROM data_text_job"),
        count("SELECT count(*) FROM data_index_entry"),
        count("SELECT count(*) FROM note_updates"),
    )
}

#[test]
fn reopen_does_not_reseed_or_replay_notes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reopen.sqlite");
    drop(v12_fixture(&path));
    drop(DeviceDatabase::open(&path).unwrap());
    let raw = Connection::open(&path).unwrap();
    let before = counts(&raw);
    drop(raw);
    drop(DeviceDatabase::open(&path).unwrap());
    let raw = Connection::open(&path).unwrap();
    let after = counts(&raw);
    assert_eq!(after, before, "reopen repeats no seeding or history work");
}
