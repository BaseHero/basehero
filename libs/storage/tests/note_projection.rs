//! Note saves keep the shared projection coherent; a derived-state failure is
//! repaired later without losing the Note.
use bh_core::note::Note;
use bh_data::{
    FieldPath, KeyRef, Position, Scope, TypeId,
    catalogue::Shipped,
    query::{Budget, Completeness, Gap, Query, SortKey, TextMatch, TypeSelect, run},
    store::{coverage, records},
};
use bh_storage::{
    DeviceDatabase, NoteKey,
    sync_state::{IncomingCommit, IncomingNote, IncomingStep, LOG_BASE, SeenRow, VerifiedRecord},
};
use rusqlite::{Connection, params};

const BASE: [u8; 32] = [2; 32];
const AUDIENCE: [u8; 32] = [0; 32];
const ANCHOR: [u8; 32] = [4; 32];

fn recent_query() -> Query {
    Query {
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
    }
}

fn titles(conn: &Connection) -> Vec<(String, String)> {
    let scope = bh_data::Scope {
        base: BASE,
        audience: AUDIENCE,
    };
    let page = run(
        conn,
        scope,
        &[scope],
        &Shipped,
        &recent_query(),
        Budget::INTERACTIVE,
    )
    .unwrap();
    page.rows
        .into_iter()
        .map(|row| {
            (
                hex(&row.record.0),
                row.values["/title"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn open(path: &std::path::Path) -> DeviceDatabase {
    let mut db = DeviceDatabase::open(path).unwrap();
    db.commit_account_verified(ANCHOR, &[b"genesis"], 1, [5; 32], false)
        .unwrap();
    db
}

/// The scope's coverage, which says how much of its Note state is proven
/// present on this replica.
fn scope_coverage(conn: &Connection, base: [u8; 32], audience: [u8; 32]) -> coverage::Coverage {
    let scope = Scope { base, audience };
    let sid = records::lookup_scope(conn, scope)
        .unwrap()
        .expect("scope exists");
    coverage::get(conn, sid).unwrap()
}

/// The Note gaps the scope records, one row per Note this replica cannot show.
fn scope_gaps(conn: &Connection, base: [u8; 32], audience: [u8; 32]) -> i64 {
    let sid = records::lookup_scope(conn, Scope { base, audience })
        .unwrap()
        .expect("scope exists");
    conn.query_row(
        "SELECT count(*) FROM data_note_gap WHERE scope=?1",
        [sid],
        |r| r.get(0),
    )
    .unwrap()
}

fn note_commits(path: &std::path::Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT count(*) FROM note_updates", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap()
}

#[test]
fn create_and_local_commit_project_the_note_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("projection.sqlite");
    let mut db = open(&path);
    let note = db.create_note(BASE, AUDIENCE).unwrap();
    let key = NoteKey {
        base: BASE,
        audience: AUDIENCE,
        note,
    };
    let raw = Connection::open(&path).unwrap();
    assert_eq!(
        raw.query_row("SELECT count(*) FROM data_record", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1,
        "creation itself is a visible Note"
    );
    assert_eq!(
        scope_coverage(&raw, BASE, AUDIENCE),
        coverage::Coverage {
            through: Some(Position(0)),
            complete: true,
        },
        "a fresh install's first Note scope is complete-empty rather than unknown"
    );
    let mut working = Note::new().unwrap();
    let delta = working.append_paragraph("hello").unwrap();
    db.commit_working_update_with_title(key, 0, ANCHOR, [1; 16], &delta, "hello")
        .unwrap();
    assert_eq!(note_commits(&path), 1);
    let (accepted, changed): (String, i64) = raw
        .query_row(
            "SELECT accepted,changed FROM data_record WHERE record=?1",
            [note.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&accepted).unwrap()["title"],
        "hello"
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM data_text_job", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1,
        "one queued body revision, not a duplicate title hook"
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM data_index_entry", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(changed > 0);
    assert_eq!(titles(&raw), vec![(hex(&note), "hello".to_owned())]);

    // A replay is the same save, not another projection.
    db.commit_working_update_with_title(key, 0, ANCHOR, [1; 16], &delta, "hello")
        .unwrap();
    assert_eq!(
        raw.query_row("SELECT count(*) FROM data_text_job", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(titles(&raw).len(), 1);
}

#[test]
fn incoming_apply_projects_the_final_title() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("incoming.sqlite");
    let mut db = open(&path);
    let note = db.create_note(BASE, AUDIENCE).unwrap();
    let key = NoteKey {
        base: BASE,
        audience: AUDIENCE,
        note,
    };
    {
        let raw = Connection::open(&path).unwrap();
        raw.execute(
            "INSERT INTO log_progress(log_kind,log_id,position,head_hash,receipt,control_digest,stopped_reason,hosting_root,account_position,account_hash,metadata_id,epoch_id,floor)
             VALUES(1,?1,0,?2,NULL,zeroblob(32),NULL,?3,NULL,NULL,NULL,NULL,1)",
            params![BASE.as_slice(), [7u8; 32].as_slice(), [8u8; 32].as_slice()],
        )
        .unwrap();
    }
    let mut working = Note::new().unwrap();
    let first = working.append_paragraph("incoming title").unwrap();
    let commit = |position: u64, after: (u64, [u8; 32]), delta: Vec<u8>, title: Option<String>| {
        IncomingCommit {
            log_kind: LOG_BASE,
            log_id: BASE,
            hosting_root: [8; 32],
            after,
            receipt: [0; bh_sync::receipt::RECEIPT_LEN],
            records: vec![VerifiedRecord {
                seen: SeenRow {
                    position,
                    head_hash: [9u8; 32],
                    control_digest: [0; 32],
                    account_position: 1,
                    account_hash: [0; 32],
                },
                event_id: [position as u8; 32],
                digest: [11; 32],
                account_change: None,
                judged_floor: 1,
                floor: 1,
            }],
            metadata_id: [0; 32],
            epoch_id: None,
            notes: vec![IncomingNote {
                key,
                accepted: vec![(position, delta)],
                compacted: None,
                bindings: vec![],
                remote: vec![],
                rebuild_working: None,
                title,
            }],
            steps: vec![IncomingStep::Note(0)],
            own: vec![],
            held: vec![],
        }
    };
    db.commit_incoming(
        &commit(1, (0, [7; 32]), first, Some("incoming title".to_owned())),
        |_| Ok(()),
    )
    .unwrap();
    let raw = Connection::open(&path).unwrap();
    assert_eq!(
        titles(&raw),
        vec![(hex(&note), "incoming title".to_owned())]
    );

    // A later apply with no derived title keeps the catalogue title.
    let second = working.append_paragraph("later").unwrap();
    db.commit_incoming(&commit(2, (1, [9; 32]), second, None), |_| Ok(()))
        .unwrap();
    assert_eq!(
        titles(&raw),
        vec![(hex(&note), "incoming title".to_owned())]
    );
    let sid = bh_data::store::records::lookup_scope(
        &raw,
        bh_data::Scope {
            base: BASE,
            audience: AUDIENCE,
        },
    )
    .unwrap()
    .unwrap();
    assert!(
        coverage::get(&raw, sid).unwrap().complete,
        "an incoming Note keeps the scope's honest Note coverage"
    );
}

#[test]
fn a_repeated_note_step_is_corrupt_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("duplicate-step.sqlite");
    let mut db = open(&path);
    let note = db.create_note(BASE, AUDIENCE).unwrap();
    let key = NoteKey {
        base: BASE,
        audience: AUDIENCE,
        note,
    };
    {
        let raw = Connection::open(&path).unwrap();
        raw.execute(
            "INSERT INTO log_progress(log_kind,log_id,position,head_hash,receipt,control_digest,stopped_reason,hosting_root,account_position,account_hash,metadata_id,epoch_id,floor)
             VALUES(1,?1,0,?2,NULL,zeroblob(32),NULL,?3,NULL,NULL,NULL,NULL,1)",
            params![BASE.as_slice(), [7u8; 32].as_slice(), [8u8; 32].as_slice()],
        )
        .unwrap();
    }
    let before = note_commits(&path);
    let mut working = Note::new().unwrap();
    let delta = working.append_paragraph("twice").unwrap();
    let commit = IncomingCommit {
        log_kind: LOG_BASE,
        log_id: BASE,
        hosting_root: [8; 32],
        after: (0, [7; 32]),
        receipt: [0; bh_sync::receipt::RECEIPT_LEN],
        records: vec![VerifiedRecord {
            seen: SeenRow {
                position: 1,
                head_hash: [9u8; 32],
                control_digest: [0; 32],
                account_position: 1,
                account_hash: [0; 32],
            },
            event_id: [1; 32],
            digest: [11; 32],
            account_change: None,
            judged_floor: 1,
            floor: 1,
        }],
        metadata_id: [0; 32],
        epoch_id: None,
        notes: vec![IncomingNote {
            key,
            accepted: vec![(1, delta)],
            compacted: None,
            bindings: vec![],
            remote: vec![],
            rebuild_working: None,
            title: Some("twice".to_owned()),
        }],
        steps: vec![IncomingStep::Note(0), IncomingStep::Note(0)],
        own: vec![],
        held: vec![],
    };
    assert!(matches!(
        db.commit_incoming(&commit, |_| Ok(())),
        Err(bh_storage::StoreError::CorruptSyncState)
    ));
    let raw = Connection::open(&path).unwrap();
    assert_eq!(note_commits(&path), before, "no Note step was applied");
    let position: i64 = raw
        .query_row(
            "SELECT position FROM log_progress WHERE log_id=?1",
            [BASE.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(position, 0, "the batch was not committed");
    assert!(
        titles(&raw).iter().all(|(_, title)| title != "twice"),
        "the duplicated Note step wrote nothing"
    );
}

#[test]
fn projection_failure_keeps_the_note_and_repairs_from_canonical_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("repair.sqlite");
    let mut db = open(&path);
    let note = db.create_note(BASE, AUDIENCE).unwrap();
    let key = NoteKey {
        base: BASE,
        audience: AUDIENCE,
        note,
    };
    let mut working = Note::new().unwrap();
    let first = working.append_paragraph("first").unwrap();
    db.commit_working_update_with_title(key, 0, ANCHOR, [1; 16], &first, "first")
        .unwrap();
    let raw = Connection::open(&path).unwrap();
    let before: (i64, i64, i64) = raw
        .query_row(
            "SELECT changed,(SELECT count(*) FROM data_index_entry),(SELECT count(*) FROM note_projection_repair) FROM data_record WHERE record=?1",
            [note.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    raw.execute_batch(
        "CREATE TRIGGER fail_projection BEFORE INSERT ON data_index_entry
         BEGIN SELECT RAISE(ABORT,'injected projection failure'); END;
         CREATE TRIGGER fail_projection_update BEFORE UPDATE ON data_index_entry
         BEGIN SELECT RAISE(ABORT,'injected projection failure'); END;",
    )
    .unwrap();

    let second = working.append_paragraph("second").unwrap();
    db.commit_working_update_with_title(key, 1, ANCHOR, [2; 16], &second, "first")
        .unwrap();
    assert_eq!(note_commits(&path), 2, "the Note save still commits");
    let after: (String, i64, i64, i64, i64) = raw
        .query_row(
            "SELECT accepted,changed,(SELECT count(*) FROM data_index_entry),
                    (SELECT count(*) FROM note_projection_repair),
                    (SELECT count(*) FROM note_updates)
             FROM data_record WHERE record=?1",
            [note.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(after.0, serde_json::json!({"title": "first"}).to_string());
    assert_eq!(after.1, before.0, "the failed projection rolled back");
    assert_eq!(after.2, before.1, "no partial index entry survives");
    assert_eq!(after.3, 1, "durable repair work remains");
    assert_eq!(after.4, 2);
    raw.execute_batch("DROP TRIGGER fail_projection; DROP TRIGGER fail_projection_update")
        .unwrap();

    assert_eq!(db.repair_projections(4).unwrap(), 1);
    let repaired: (String, i64, i64, i64) = raw
        .query_row(
            "SELECT accepted,changed,(SELECT count(*) FROM note_projection_repair),
                    (SELECT count(*) FROM data_text_job)
             FROM data_record WHERE record=?1",
            [note.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        repaired.0,
        serde_json::json!({"title": "first"}).to_string(),
        "repair re-derives the canonical title"
    );
    assert!(repaired.1 > before.0);
    assert_eq!(repaired.2, 0, "successful repair clears its record");
    assert!(repaired.3 > 0);

    // The body extraction turn indexes the canonical body, including the
    // paragraph whose commit first failed to project. Selecting a batch is a
    // read-only half: it writes nothing and needs no writer.
    let sequence = |conn: &Connection| -> i64 {
        conn.query_row("SELECT next FROM data_seq WHERE id=1", [], |r| r.get(0))
            .unwrap()
    };
    let before_batch = sequence(&raw);
    let source = db
        .note_body_source()
        .expect("a file container has a read source");
    for _ in 0..8 {
        let batch = source.next_batch(4).unwrap();
        if batch.is_empty() {
            break;
        }
        assert_eq!(sequence(&raw), before_batch, "selection writes nothing");
        let outcome = db.store_body_batch(&batch, 30_000).unwrap();
        if outcome.attempted == 0 {
            break;
        }
    }
    let scope = bh_data::Scope {
        base: BASE,
        audience: AUDIENCE,
    };
    let page = run(
        &raw,
        scope,
        &[scope],
        &Shipped,
        &Query {
            text: Some(TextMatch {
                terms: "second".into(),
                on: None,
                require_revision: None,
            }),
            ..recent_query()
        },
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(page.rows.len(), 1);
}

#[test]
fn failed_first_projection_is_incomplete_until_repaired() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("first-projection.sqlite");
    let mut db = open(&path);
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch(
        "CREATE TRIGGER fail_projection BEFORE INSERT ON data_index_entry
         BEGIN SELECT RAISE(ABORT,'injected projection failure'); END;",
    )
    .unwrap();

    // The Note's own save commits, but its first projection fails, so this
    // replica does not yet hold that identity in typed state.
    let note = db.create_note(BASE, AUDIENCE).unwrap();
    assert_eq!(note_commits(&path), 0);
    assert_eq!(
        scope_coverage(&raw, BASE, AUDIENCE),
        coverage::Coverage {
            through: Some(Position(0)),
            complete: true,
        },
        "the typed log is complete; the missing projection is a gap in its record"
    );
    assert_eq!(scope_gaps(&raw, BASE, AUDIENCE), 1);
    assert_eq!(
        raw.query_row("SELECT count(*) FROM note_projection_repair", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    // A Note this replica cannot show never reads as an empty audience.
    let scope = Scope {
        base: BASE,
        audience: AUDIENCE,
    };
    let page = run(
        &raw,
        scope,
        &[scope],
        &Shipped,
        &recent_query(),
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert!(page.rows.is_empty());
    assert_eq!(
        page.completeness,
        Completeness::Incomplete(vec![Gap::NoteUnavailable])
    );

    raw.execute_batch("DROP TRIGGER fail_projection").unwrap();
    assert_eq!(db.repair_projections(4).unwrap(), 1);
    assert_eq!(
        raw.query_row("SELECT count(*) FROM note_projection_repair", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0,
        "a successful repair clears its record"
    );
    assert_eq!(
        scope_coverage(&raw, BASE, AUDIENCE),
        coverage::Coverage {
            through: Some(Position(0)),
            complete: true,
        },
        "the typed log stays complete over the proven position"
    );
    assert_eq!(
        scope_gaps(&raw, BASE, AUDIENCE),
        0,
        "the repair closed the gap"
    );
    let scope = Scope {
        base: BASE,
        audience: AUDIENCE,
    };
    let page = run(
        &raw,
        scope,
        &[scope],
        &Shipped,
        &recent_query(),
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(hex(&page.rows[0].record.0), hex(&note));
    assert_eq!(page.completeness, Completeness::Complete);
}

#[test]
fn a_later_successful_save_completes_a_scope_left_incomplete() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("later-success.sqlite");
    let mut db = open(&path);
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch(
        "CREATE TRIGGER fail_projection BEFORE INSERT ON data_index_entry
         BEGIN SELECT RAISE(ABORT,'injected projection failure'); END;",
    )
    .unwrap();
    let note = db.create_note(BASE, AUDIENCE).unwrap();
    assert_eq!(scope_gaps(&raw, BASE, AUDIENCE), 1);
    assert_eq!(
        raw.query_row("SELECT count(*) FROM note_projection_repair", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );

    raw.execute_batch("DROP TRIGGER fail_projection").unwrap();
    let key = NoteKey {
        base: BASE,
        audience: AUDIENCE,
        note,
    };
    let mut working = Note::new().unwrap();
    let first = working.append_paragraph("first").unwrap();
    db.commit_working_update_with_title(key, 0, ANCHOR, [1; 16], &first, "first")
        .unwrap();

    assert_eq!(
        raw.query_row("SELECT count(*) FROM note_projection_repair", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0,
        "a successful projection clears its repair record"
    );
    assert_eq!(
        scope_coverage(&raw, BASE, AUDIENCE),
        coverage::Coverage {
            through: Some(Position(0)),
            complete: true,
        },
        "the typed log stays complete over the proven position"
    );
    assert_eq!(
        scope_gaps(&raw, BASE, AUDIENCE),
        0,
        "the save closed the gap"
    );
    let scope = Scope {
        base: BASE,
        audience: AUDIENCE,
    };
    let page = run(
        &raw,
        scope,
        &[scope],
        &Shipped,
        &recent_query(),
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(page.completeness, Completeness::Complete);
    assert_eq!(page.rows.len(), 1);
}

#[test]
fn untitled_local_commits_project_the_note() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("untitled.sqlite");
    let mut db = open(&path);
    let note = db.create_note(BASE, AUDIENCE).unwrap();
    let key = NoteKey {
        base: BASE,
        audience: AUDIENCE,
        note,
    };
    let mut working = Note::new().unwrap();
    let first = working.append_paragraph("first").unwrap();
    db.commit_working_update_with_title(key, 0, ANCHOR, [1; 16], &first, "first")
        .unwrap();
    let raw = Connection::open(&path).unwrap();
    let before: (i64, i64) = raw
        .query_row(
            "SELECT changed,text_rev FROM data_record WHERE record=?1",
            [note.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();

    let second = working.append_paragraph("second").unwrap();
    db.commit_working_update(key, 1, ANCHOR, [2; 16], &second)
        .unwrap();
    let after: (String, i64, i64) = raw
        .query_row(
            "SELECT accepted,changed,text_rev FROM data_record WHERE record=?1",
            [note.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&after.0).unwrap()["title"],
        "first",
        "an untitled save keeps the catalogue title"
    );
    assert!(after.1 > before.0, "an untitled save still moves $changed");
    assert!(after.2 > before.1, "and queues the changed body");

    // A direct local write with no catalogue title yet gains a projection too.
    let direct = [9u8; 32];
    let delta = Note::new().unwrap().append_paragraph("direct").unwrap();
    db.apply_local_update(
        NoteKey {
            base: BASE,
            audience: AUDIENCE,
            note: direct,
        },
        [3; 16],
        &delta,
    )
    .unwrap();
    let accepted: String = raw
        .query_row(
            "SELECT accepted FROM data_record WHERE record=?1",
            [direct.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&accepted).unwrap()["title"],
        ""
    );
}
