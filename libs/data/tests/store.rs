use bh_data::{
    AppId, CompiledType, CoreCatalogue, Position, RecordId, RevisionId, Scope, SearchMap, TypeDocs,
    TypeId, TypeKind, catalogue,
    store::{self, coverage, records, registry},
};
use rusqlite::{Connection, params};
use serde_json::json;

fn scope(n: u8) -> Scope {
    Scope {
        base: [n; 32],
        audience: [n + 1; 32],
    }
}
fn ty(n: u8) -> TypeId {
    TypeId([n; 32])
}
fn rev(n: u8) -> RevisionId {
    RevisionId([n; 32])
}
fn record(n: u8) -> RecordId {
    RecordId([n; 32])
}
fn connection() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    let tx = conn.transaction().unwrap();
    store::migrate(&tx).unwrap();
    tx.commit().unwrap();
    conn
}
fn fixture(
    type_id: TypeId,
    revision: RevisionId,
    lineage: Vec<(TypeId, RevisionId)>,
) -> CompiledType {
    CompiledType {
        type_id,
        revision,
        kind: TypeKind::Record,
        app: Some(AppId([8; 32])),
        name: "example".into(),
        lineage,
        effective_schema: json!({"type":"object"}),
        resources: vec![],
        fields: vec![],
        indexes: vec![],
        uniques: vec![],
        queries: vec![],
        search: SearchMap {
            title: None,
            text: vec![],
            builtin_body: false,
        },
        actions: vec![],
        builtin: None,
        previous: None,
        docs: TypeDocs {
            description: String::new(),
            rationale: vec![],
            examples_valid: vec![],
            examples_invalid: vec![],
            migration: None,
        },
    }
}

#[test]
fn migrate_creates_layout() {
    let conn = connection();
    let names: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'data_%'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    for name in [
        "data_scope",
        "data_app",
        "data_definition",
        "data_type",
        "data_type_at",
        "data_app_at",
        "data_family",
        "data_seq",
        "data_record",
        "data_field_clock",
        "data_history",
        "data_pending",
        "data_index",
        "data_index_entry",
        "data_unique",
        "data_ref",
        "data_fts",
        "data_text_job",
        "data_coverage",
        "data_note_gap",
        "data_parked",
        "data_ordered",
    ] {
        assert!(names.contains(&name.to_owned()), "missing {name}");
    }
    assert_eq!(store::LAYOUT_VERSION, 1);
    assert_eq!(
        conn.query_row("SELECT next FROM data_seq WHERE id=1", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    conn.execute(
        "INSERT INTO data_fts(rowid,scope,title,body) VALUES(1,'s1','hello','world')",
        [],
    )
    .unwrap();
    conn.execute("DELETE FROM data_fts WHERE rowid=1", [])
        .unwrap();
    let hits: i64 = conn
        .query_row(
            "SELECT count(*) FROM data_fts WHERE data_fts MATCH 'hello'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(hits, 0);
}
#[test]
fn index_cursor_and_progress_columns_have_stable_layout() {
    let conn = connection();
    let columns: Vec<(String, String)> = conn
        .prepare("PRAGMA table_info(data_index)")
        .unwrap()
        .query_map([], |r| Ok((r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(columns.contains(&("cursor_type".into(), "BLOB".into())));
    assert!(!columns.iter().any(|(name, _)| name == "cursor_member"));
    assert!(columns.contains(&("built".into(), "INTEGER".into())));
    assert!(columns.contains(&("estimate".into(), "INTEGER".into())));
    assert!(columns.contains(&("local_claim".into(), "INTEGER".into())));
    conn.execute("INSERT INTO data_index(scope,family,keys,unique_,origin,state,cursor_id) VALUES(1,?1,'[]',0,'local','building',0)",[ty(1).0.as_slice()]).unwrap();
    let (cursor, built, estimate): (Option<Vec<u8>>, i64, Option<i64>) = conn
        .query_row(
            "SELECT cursor_type,built,estimate FROM data_index",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((cursor, built, estimate), (None, 0, None));
    assert!(
        !conn
            .query_row("SELECT local_claim FROM data_index", [], |r| r
                .get::<_, bool>(0))
            .unwrap()
    );
}
#[test]
fn relational_rows_reject_missing_scope() {
    let conn = connection();
    // Each statement supplies every other required column, so a failure here
    // must be due to the missing scope rather than an unrelated constraint.
    for (table, insert) in [
        (
            "data_app",
            "INSERT INTO data_app(scope,app) VALUES(NULL,x'01')",
        ),
        (
            "data_definition",
            "INSERT INTO data_definition(scope,revision,bytes,compiled) VALUES(NULL,x'01',x'01','{}')",
        ),
        (
            "data_type",
            "INSERT INTO data_type(scope,type) VALUES(NULL,x'01')",
        ),
        (
            "data_family",
            "INSERT INTO data_family(scope,type,ancestor) VALUES(NULL,x'01',x'02')",
        ),
        (
            "data_record",
            "INSERT INTO data_record(scope,record,type,revision,changed) VALUES(NULL,x'01',x'01',x'01',1)",
        ),
        (
            "data_pending",
            "INSERT INTO data_pending(scope,payload,state) VALUES(NULL,x'01','queued')",
        ),
        ("data_index", "INSERT INTO data_index(scope) VALUES(NULL)"),
        (
            "data_ref",
            "INSERT INTO data_ref(src,path,dst_scope,dst,scope) VALUES(1,'/a',1,x'01',NULL)",
        ),
        (
            "data_text_job",
            "INSERT INTO data_text_job(rec,scope,wanted) VALUES(1,NULL,1)",
        ),
        (
            "data_coverage",
            "INSERT INTO data_coverage(scope,complete) VALUES(NULL,0)",
        ),
        (
            "data_note_gap",
            "INSERT INTO data_note_gap(scope,record) VALUES(NULL,x'01')",
        ),
        (
            "data_parked",
            "INSERT INTO data_parked(scope,position) VALUES(NULL,1)",
        ),
    ] {
        assert!(
            conn.execute(insert, []).is_err(),
            "{table} accepted an unscoped row"
        );
    }
}

#[test]
fn fts5_available() {
    let conn = connection();
    assert_eq!(
        conn.query_row("SELECT sqlite_compileoption_used('ENABLE_FTS5')", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
#[test]
fn json_available() {
    let conn = connection();
    assert_eq!(
        conn.query_row("SELECT json_extract('{\"a\":7}', '$.a')", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        7
    );
}
#[test]
fn scope_ids_are_stable_and_distinct() {
    let mut conn = connection();
    let tx = conn.transaction().unwrap();
    let a = records::scope_id(&tx, scope(1), &catalogue::Shipped).unwrap();
    assert_eq!(
        records::scope_id(&tx, scope(1), &catalogue::Shipped).unwrap(),
        a
    );
    let b = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    assert_ne!(a, b);
    assert_eq!(records::lookup_scope(&tx, scope(1)).unwrap(), Some(a));
    assert_eq!(records::lookup_scope(&tx, scope(3)).unwrap(), None);
}
#[test]
fn record_put_get_round_trip() {
    let mut conn = connection();
    let tx = conn.transaction().unwrap();
    let s = records::scope_id(&tx, scope(1), &catalogue::Shipped).unwrap();
    let mut row = records::RecordRow {
        id: 0,
        scope: s,
        record: record(1),
        type_id: ty(1),
        revision: rev(1),
        accepted: Some(json!({"a":1})),
        doc: None,
        deleted: false,
        pending: false,
        changed_at: Some(Position(42)),
        changed: 0,
        text_rev: 0,
    };
    let id = records::put(&tx, &mut row).unwrap();
    assert_eq!(row.id, id);
    assert_eq!(row.changed, 1);
    row.doc = Some(json!({"a":2}));
    row.pending = true;
    assert_eq!(row.view(), row.doc.as_ref());
    assert_eq!(records::put(&tx, &mut row).unwrap(), id);
    assert_eq!(row.changed, 2);
    assert_eq!(
        records::get(&tx, s, record(1)).unwrap().unwrap().view(),
        row.doc.as_ref()
    );
    assert_eq!(records::count_type_upto(&tx, s, &[ty(1)], 0).unwrap(), 1);
    assert_eq!(records::count_type_upto(&tx, s, &[ty(2)], 2).unwrap(), 0);
    assert_eq!(records::count_type_upto(&tx, s, &[], 2).unwrap(), 0);
    tx.commit().unwrap();
    assert_eq!(
        records::get(&conn, s, record(1)).unwrap().unwrap().doc,
        row.doc
    );
}
#[test]
fn registry_current_and_permitted() {
    let mut conn = connection();
    let tx = conn.transaction().unwrap();
    let s = records::scope_id(&tx, scope(1), &catalogue::Shipped).unwrap();
    let compiled = fixture(ty(1), rev(2), vec![(ty(1), rev(2))]);
    let core = catalogue::Shipped;
    let note = core.core_type(TypeId::core("note")).unwrap();
    registry::store_definition(&tx, s, &compiled, b"source", Position(7)).unwrap();
    registry::set_current(&tx, s, ty(1), rev(2), &[rev(1), rev(2)], Position(7)).unwrap();
    assert_eq!(
        registry::compiled(&tx, s, rev(2)).unwrap(),
        Some(compiled.clone())
    );
    assert_eq!(
        registry::current(&tx, s, ty(1), &core).unwrap(),
        Some(compiled.clone())
    );
    assert_eq!(
        registry::permitted(&tx, s, ty(1), &core).unwrap(),
        vec![rev(1), rev(2)]
    );
    assert_eq!(
        registry::current(&tx, s, note.type_id, &core).unwrap(),
        Some(note.clone())
    );
    assert_eq!(
        registry::permitted(&tx, s, note.type_id, &core).unwrap(),
        vec![note.revision]
    );
    assert!(
        registry::list_types(&tx, s, &core)
            .unwrap()
            .contains(&compiled)
    );
    assert!(registry::list_types(&tx, s, &core).unwrap().contains(&note));
    registry::set_app(&tx, s, AppId([8; 32]), "example", true, Position(7)).unwrap();
    assert_eq!(
        registry::app_active(&tx, s, AppId([8; 32])).unwrap(),
        Some(true)
    );
    registry::set_app(&tx, s, AppId([8; 32]), "example", false, Position(8)).unwrap();
    assert_eq!(
        registry::app_active(&tx, s, AppId([8; 32])).unwrap(),
        Some(false)
    );
    // Reads at a position see only changes accepted before it.
    assert_eq!(
        registry::current_before(&tx, s, ty(1), &core, Some(Position(7))).unwrap(),
        None
    );
    assert_eq!(
        registry::current_before(&tx, s, ty(1), &core, Some(Position(8))).unwrap(),
        Some(compiled.clone())
    );
    assert_eq!(
        registry::compiled_before(&tx, s, rev(2), Some(Position(7))).unwrap(),
        None
    );
    assert_eq!(
        registry::permitted_before(&tx, s, ty(1), &core, Some(Position(7))).unwrap(),
        Vec::<RevisionId>::new()
    );
    for (before, active) in [(7, None), (8, Some(true)), (9, Some(false))] {
        assert_eq!(
            registry::app_active_before(&tx, s, AppId([8; 32]), Some(Position(before))).unwrap(),
            active
        );
    }
    let other = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    assert_eq!(
        registry::app_active(&tx, other, AppId([8; 32])).unwrap(),
        None
    );
    assert_eq!(registry::compiled(&tx, other, rev(2)).unwrap(), None);
    assert_eq!(registry::current(&tx, other, ty(1), &core).unwrap(), None);
    assert!(
        registry::list_types(&tx, other, &core)
            .unwrap()
            .contains(&note)
    );
}
#[test]
fn rejected_type_revision_pair_does_not_change_registry() {
    let mut conn = connection();
    let tx = conn.transaction().unwrap();
    let s = records::scope_id(&tx, scope(1), &catalogue::Shipped).unwrap();
    let core = catalogue::Shipped;
    registry::store_definition(
        &tx,
        s,
        &fixture(ty(1), rev(1), vec![(ty(1), rev(1))]),
        b"one",
        Position(1),
    )
    .unwrap();
    assert!(registry::set_current(&tx, s, ty(2), rev(1), &[rev(1)], Position(1)).is_err());
    assert_eq!(registry::current(&tx, s, ty(2), &core).unwrap(), None);
}

#[test]
fn bound_core_current_resolves_shipped_revision() {
    let mut conn = connection();
    let tx = conn.transaction().unwrap();
    let s = records::scope_id(&tx, scope(1), &catalogue::Shipped).unwrap();
    let note = TypeId::core("note");
    let core = catalogue::Shipped;
    let shipped = core.core_type(note).unwrap();
    registry::set_current(
        &tx,
        s,
        note,
        shipped.revision,
        &[shipped.revision],
        Position(1),
    )
    .unwrap();
    assert_eq!(
        registry::current(&tx, s, note, &core).unwrap(),
        Some(shipped.clone())
    );
    assert_eq!(registry::list_types(&tx, s, &core).unwrap(), vec![shipped]);
}

#[test]
fn family_members_include_self_and_subtypes() {
    let mut conn = connection();
    let tx = conn.transaction().unwrap();
    let s = records::scope_id(&tx, scope(1), &catalogue::Shipped).unwrap();
    registry::store_definition(
        &tx,
        s,
        &fixture(ty(2), rev(2), vec![(ty(2), rev(2)), (ty(1), rev(1))]),
        b"child",
        Position(1),
    )
    .unwrap();
    registry::set_current(&tx, s, ty(2), rev(2), &[rev(2)], Position(1)).unwrap();
    assert_eq!(
        registry::family_members(&tx, s, ty(1)).unwrap(),
        vec![ty(1), ty(2)]
    );
    let other = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    assert_eq!(
        registry::family_members(&tx, other, ty(1)).unwrap(),
        vec![ty(1)]
    );
}
#[test]
fn family_members_exclude_inactive_definitions() {
    let mut conn = connection();
    let tx = conn.transaction().unwrap();
    let s = records::scope_id(&tx, scope(1), &catalogue::Shipped).unwrap();
    registry::store_definition(
        &tx,
        s,
        &fixture(ty(2), rev(2), vec![(ty(2), rev(2)), (ty(1), rev(1))]),
        b"unactivated",
        Position(1),
    )
    .unwrap();
    assert_eq!(
        registry::family_members(&tx, s, ty(1)).unwrap(),
        vec![ty(1)]
    );
}

#[test]
fn unseen_scope_coverage_is_incomplete() {
    let mut conn = connection();
    assert_eq!(
        coverage::get(&conn, 123).unwrap(),
        coverage::Coverage {
            through: None,
            complete: false
        }
    );
    let tx = conn.transaction().unwrap();
    coverage::set(&tx, 123, Position(11), true).unwrap();
    assert_eq!(
        coverage::get(&tx, 123).unwrap(),
        coverage::Coverage {
            through: Some(Position(11)),
            complete: true
        }
    );
}
#[test]
fn migrate_is_atomic_on_failure() {
    let mut conn = Connection::open_in_memory().unwrap();
    {
        let tx = conn.transaction().unwrap();
        // Conflict with a later table, after earlier CREATE statements have executed.
        tx.execute("CREATE TABLE data_index(id INTEGER)", [])
            .unwrap();
        assert!(store::migrate(&tx).is_err());
    }
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name LIKE 'data_%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}
#[test]
fn index_entry_accepts_missing_optional_key() {
    let conn = connection();
    conn.execute(
        "INSERT INTO data_index_entry(ix,k1,k2,k3,k4,rec,record) VALUES(1,NULL,0,0,0,3,zeroblob(32))",
        [],
    )
    .unwrap();
    assert_eq!(
        conn.query_row("SELECT k2 FROM data_index_entry WHERE rec=3", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn fts_scope_token_isolates_scopes() {
    let conn = connection();
    conn.execute("INSERT INTO data_fts(rowid,scope,title,body) VALUES(1,'s1','hello','world'),(2,'s2','hello','world')", []).unwrap();
    let ids: Vec<i64> = conn
        .prepare(
            "SELECT rowid FROM data_fts WHERE data_fts MATCH 'scope:s1 AND (hello)' ORDER BY rowid",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(ids, vec![1]);
}
#[test]
fn record_ids_not_reused_after_delete() {
    let mut conn = connection();
    let tx = conn.transaction().unwrap();
    let s = records::scope_id(&tx, scope(1), &catalogue::Shipped).unwrap();
    let mut row = records::RecordRow {
        id: 0,
        scope: s,
        record: record(1),
        type_id: ty(1),
        revision: rev(1),
        accepted: None,
        doc: Some(json!({})),
        deleted: false,
        pending: true,
        changed_at: None,
        changed: 0,
        text_rev: 0,
    };
    let first = records::put(&tx, &mut row).unwrap();
    tx.execute("DELETE FROM data_record WHERE id=?1", params![first])
        .unwrap();
    row.id = 0;
    row.record = record(2);
    assert!(records::put(&tx, &mut row).unwrap() > first);
}
#[test]
fn seq_is_monotonic_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.sqlite");
    {
        let mut conn = Connection::open(&path).unwrap();
        let tx = conn.transaction().unwrap();
        store::migrate(&tx).unwrap();
        assert_eq!(records::next_seq(&tx).unwrap(), 1);
        tx.commit().unwrap();
    }
    let mut conn = Connection::open(&path).unwrap();
    let tx = conn.transaction().unwrap();
    assert_eq!(records::next_seq(&tx).unwrap(), 2);
}
