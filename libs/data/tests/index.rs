use bh_data::{
    AppId, CompiledType, CoreCatalogue, FieldKind, FieldPath, FieldSpec, IndexDecl, KeyRef,
    Position, RecordId, RevisionId, Scope, SearchMap, TypeDocs, TypeId, TypeKind, UniqueDecl,
    WritePolicy, catalogue, compose, definition,
    index::{
        self,
        unique::{self, UniqueCheck},
    },
    store::{
        self, coverage,
        records::{self, RecordRow},
    },
};
use rusqlite::{Connection, OptionalExtension, types::Value as SqlValue};
use serde_json::json;

fn ty(n: u8) -> TypeId {
    TypeId([n; 32])
}
fn rid(n: u32) -> RecordId {
    let mut b = [0; 32];
    b[..4].copy_from_slice(&n.to_be_bytes());
    RecordId(b)
}
fn scope(n: u8) -> Scope {
    Scope {
        base: [1; 32],
        audience: [n; 32],
    }
}
fn ct(n: u8, family: u8) -> CompiledType {
    CompiledType {
        type_id: ty(n),
        revision: RevisionId([n; 32]),
        kind: TypeKind::Record,
        app: Some(AppId([1; 32])),
        name: "test".into(),
        lineage: vec![
            (ty(n), RevisionId([n; 32])),
            (ty(family), RevisionId([family; 32])),
        ],
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
fn key() -> KeyRef {
    KeyRef::Field(FieldPath::parse("/name").unwrap())
}
fn conn() -> Connection {
    let mut c = Connection::open_in_memory().unwrap();
    let t = c.transaction().unwrap();
    store::migrate(&t).unwrap();
    t.commit().unwrap();
    c
}
fn row(s: i64, n: u32, t: &CompiledType, doc: serde_json::Value) -> RecordRow {
    RecordRow {
        id: 0,
        scope: s,
        record: rid(n),
        type_id: t.type_id,
        revision: t.revision,
        accepted: Some(doc),
        doc: None,
        deleted: false,
        pending: false,
        changed_at: None,
        changed: 0,
        text_rev: 0,
    }
}
fn entries(c: &Connection, ix: i64) -> i64 {
    c.query_row(
        "SELECT count(*) FROM data_index_entry WHERE ix=?",
        [ix],
        |r| r.get(0),
    )
    .unwrap()
}
fn index_rows(
    conn: &Connection,
    ix: i64,
) -> Vec<(i64, SqlValue, SqlValue, SqlValue, SqlValue, i64)> {
    conn.prepare(
        "SELECT ix,k1,k2,k3,k4,rec FROM data_index_entry WHERE ix=?1 ORDER BY ix,k1,k2,k3,k4,rec",
    )
    .unwrap()
    .query_map([ix], |r| {
        Ok((
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
        ))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}
fn bind(tx: &rusqlite::Transaction<'_>, scope: i64, t: &CompiledType) {
    store::registry::store_definition(tx, scope, t, b"definition", Position(1)).unwrap();
    store::registry::set_current(tx, scope, t.type_id, t.revision, &[t.revision], Position(1))
        .unwrap();
}

#[test]
fn generic_index_maintenance_does_not_visit_unrelated_types() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let sid = records::scope_id(&tx, scope(0), &catalogue::Shipped).unwrap();
    let t = ct(1, 1);
    let mut r = row(sid, 1, &t, json!({"name":"fixed"}));
    records::put(&tx, &mut r).unwrap();
    let steps = Arc::new(AtomicUsize::new(0));
    let count = steps.clone();
    tx.progress_handler(
        1,
        Some(move || {
            count.fetch_add(1, Ordering::Relaxed);
            false
        }),
    )
    .unwrap();
    index::on_record_changed(&tx, &r, &t).unwrap();
    let before = steps.swap(0, Ordering::Relaxed);
    tx.progress_handler(0, None::<fn() -> bool>).unwrap();
    for n in 0u32..1000 {
        let mut other = ct(9, 9);
        other.type_id.0[..4].copy_from_slice(&(n + 100).to_be_bytes());
        other.lineage = vec![(other.type_id, other.revision)];
        for k in 0..3 {
            other.indexes.push(IndexDecl {
                name: format!("ix{k}"),
                keys: vec![KeyRef::Field(FieldPath::parse(&format!("/k{k}")).unwrap())],
                declared_by: other.type_id,
            });
        }
        index::ensure(&tx, sid, &other).unwrap();
    }
    let count = steps.clone();
    tx.progress_handler(
        1,
        Some(move || {
            count.fetch_add(1, Ordering::Relaxed);
            false
        }),
    )
    .unwrap();
    index::on_record_changed(&tx, &r, &t).unwrap();
    let after = steps.load(Ordering::Relaxed);
    tx.progress_handler(0, None::<fn() -> bool>).unwrap();
    assert!(after <= before + 200, "VM steps {before} -> {after}");
}

#[test]
fn reference_first_scope_initializes_note_index_once() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut c = Connection::open(file.path()).unwrap();
    let tx = c.transaction().unwrap();
    store::migrate(&tx).unwrap();
    let source = records::scope_id(&tx, scope(0), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.fields.push(FieldSpec {
        path: FieldPath::parse("/target").unwrap(),
        kind: FieldKind::Reference(bh_data::RefSpec {
            targets: vec![TypeId::core("note")],
            family: true,
        }),
        write: WritePolicy::Direct,
        required: false,
        nullable: false,
        declared_by: t.type_id,
        meaning: "Reference".into(),
        unit: None,
        absent: None,
    });
    let mut r = row(
        source,
        1,
        &t,
        json!({"target":bh_data::RecordRef{record:rid(0),audience:Some(scope(7).audience)}}),
    );
    records::put(&tx, &mut r).unwrap();
    index::on_record_changed(&tx, &r, &t).unwrap();
    let sid = records::lookup_scope(&tx, scope(7)).unwrap().unwrap();
    for n in 0..2001 {
        bh_data::note::upsert_projection(&tx, scope(7), rid(n), "Note").unwrap();
    }
    let ready: i64 = tx
        .query_row(
            "SELECT count(*) FROM data_index WHERE scope=?1 AND state='ready'",
            [sid],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(ready, 1);
    tx.commit().unwrap();
    drop(c);
    let c = Connection::open(file.path()).unwrap();
    let query = bh_data::query::Query {
        select: bh_data::query::TypeSelect::Family(TypeId::core("note")),
        filter: None,
        sort: vec![bh_data::query::SortKey {
            key: KeyRef::Changed,
            desc: true,
        }],
        fields: vec![],
        follow: vec![],
        text: None,
        limit: 50,
        after: None,
    };
    let page = bh_data::query::run(
        &c,
        scope(7),
        &[scope(7)],
        &catalogue::Shipped,
        &query,
        bh_data::query::Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(page.rows.len(), 50);
    assert_eq!(page.rows[0].record, rid(2000));
    assert!(records::lookup_scope(&c, scope(8)).unwrap().is_none());
}

#[test]
fn interrupted_rebuild_never_exposes_free_uniqueness() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut c = Connection::open(file.path()).unwrap();
    let tx = c.transaction().unwrap();
    store::migrate(&tx).unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.uniques.push(UniqueDecl {
        name: "u".into(),
        keys: vec![key()],
        declared_by: t.type_id,
    });
    bind(&tx, s, &t);
    let ix = index::ensure(&tx, s, &t).unwrap()[0];
    for n in 1..=550 {
        let mut r = row(s, n, &t, json!({"name":format!("key-{n}")}));
        records::put(&tx, &mut r).unwrap();
        index::on_record_changed(&tx, &r, &t).unwrap();
    }
    coverage::set(&tx, s, Position(1), true).unwrap();
    tx.commit().unwrap();
    drop(c);
    let mut calls = 0;
    let interrupted = index::rebuild_all(|| {
        calls += 1;
        if calls == 3 {
            return Err(bh_data::DataError::Sql("simulated restart".into()));
        }
        Connection::open(file.path()).map_err(|e| bh_data::DataError::Sql(e.to_string()))
    });
    assert!(interrupted.is_err());
    assert!(calls >= 3);
    let c = Connection::open(file.path()).unwrap();
    assert_eq!(index::state(&c, ix).unwrap().state, "clearing");
    assert_eq!(
        unique::check(&c, s, &t, None, &json!({"name":"key-1"})).unwrap(),
        UniqueCheck::Unknown
    );
    drop(c);
    index::rebuild_all(|| {
        Connection::open(file.path()).map_err(|e| bh_data::DataError::Sql(e.to_string()))
    })
    .unwrap();
    let mut c = Connection::open(file.path()).unwrap();
    let tx = c.transaction().unwrap();
    assert_eq!(index::state(&tx, ix).unwrap().state, "building");
    assert_eq!(
        unique::check(&tx, s, &t, None, &json!({"name":"key-1"})).unwrap(),
        UniqueCheck::Unknown
    );
    while !index::backfill_step(&tx, ix, 500).unwrap().ready {}
    assert_eq!(
        unique::check(&tx, s, &t, None, &json!({"name":"key-1"})).unwrap(),
        UniqueCheck::Taken(rid(1))
    );
    let resumed: Vec<(i64, String, i64)> = tx
        .prepare("SELECT ix,k1,rec FROM data_index_entry WHERE ix=?1 ORDER BY ix,k1,rec")
        .unwrap()
        .query_map([ix], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    tx.execute("DELETE FROM data_index_entry WHERE ix=?1", [ix])
        .unwrap();
    tx.execute("DELETE FROM data_unique WHERE ix=?1", [ix])
        .unwrap();
    tx.execute("UPDATE data_index SET state='building',cursor_type=NULL,cursor_id=0,built=0,estimate=NULL WHERE id=?1",[ix]).unwrap();
    while !index::backfill_step(&tx, ix, 500).unwrap().ready {}
    let fresh: Vec<(i64, String, i64)> = tx
        .prepare("SELECT ix,k1,rec FROM data_index_entry WHERE ix=?1 ORDER BY ix,k1,rec")
        .unwrap()
        .query_map([ix], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(resumed, fresh);
}

#[test]
fn interrupted_text_phase_is_pending_and_resumes_without_clearing_built_indexes() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut c = Connection::open(file.path()).unwrap();
    let tx = c.transaction().unwrap();
    store::migrate(&tx).unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.indexes.push(IndexDecl {
        name: "name".into(),
        keys: vec![key()],
        declared_by: t.type_id,
    });
    bind(&tx, s, &t);
    let ix = index::ensure(&tx, s, &t).unwrap()[0];
    for n in 1..=550 {
        let mut r = row(s, n, &t, json!({"name":format!("value-{n}")}));
        records::put(&tx, &mut r).unwrap();
        index::on_record_changed(&tx, &r, &t).unwrap();
    }
    tx.commit().unwrap();
    drop(c);
    assert!(
        index::rebuild_all(|| {
            let conn = Connection::open(file.path())
                .map_err(|e| bh_data::DataError::Sql(e.to_string()))?;
            let cursor: Option<i64> = conn
                .query_row(
                    "SELECT cursor FROM data_text_rebuild WHERE phase='building'",
                    [],
                    |r| r.get(0),
                )
                .optional()
                .unwrap();
            if cursor.is_some_and(|cursor| cursor > 0 && cursor < 550) {
                return Err(bh_data::DataError::Sql("simulated restart".into()));
            }
            Ok(conn)
        })
        .is_err()
    );
    let mut c = Connection::open(file.path()).unwrap();
    assert!(
        index::pending_work(&c)
            .unwrap()
            .contains(&index::TEXT_REBUILD_WORK)
    );
    let tx = c.transaction().unwrap();
    for pending in index::pending_work(&tx).unwrap() {
        if pending != index::TEXT_REBUILD_WORK {
            while !index::backfill_step(&tx, pending, 500).unwrap().ready {}
        }
    }
    tx.commit().unwrap();
    let before = index_rows(&c, ix);
    assert_eq!(before.len(), 550);
    assert_eq!(index::state(&c, ix).unwrap().state, "ready");
    assert_eq!(
        index::pending_work(&c).unwrap(),
        vec![index::TEXT_REBUILD_WORK]
    );
    drop(c);
    index::rebuild_all(|| {
        Connection::open(file.path()).map_err(|e| bh_data::DataError::Sql(e.to_string()))
    })
    .unwrap();
    let c = Connection::open(file.path()).unwrap();
    assert_eq!(index::state(&c, ix).unwrap().state, "ready");
    assert_eq!(index_rows(&c, ix), before);
    assert!(index::pending_work(&c).unwrap().is_empty());
}

#[test]
fn local_claim_survives_definition_retirement_with_identical_keys() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.indexes.push(IndexDecl {
        name: "defined".into(),
        keys: vec![key()],
        declared_by: t.type_id,
    });
    let ix = index::ensure(&tx, s, &t).unwrap()[0];
    assert_eq!(
        index::ensure_local(&tx, s, t.type_id, vec![key()]).unwrap(),
        ix
    );
    t.indexes.clear();
    index::ensure(&tx, s, &t).unwrap();
    assert_eq!(index::state(&tx, ix).unwrap().state, "ready");
    assert!(index::state(&tx, ix).unwrap().local_claim);
    assert_eq!(index::state(&tx, ix).unwrap().origin, "local");
    let mut r = row(s, 1, &t, json!({"name":"kept"}));
    records::put(&tx, &mut r).unwrap();
    index::on_record_changed(&tx, &r, &t).unwrap();
    assert_eq!(entries(&tx, ix), 1);
}

#[test]
fn existing_scope_lookup_does_not_parse_definitions() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let t = ct(2, 2);
    bind(&tx, s, &t);
    tx.execute(
        "UPDATE data_definition SET compiled='not-json' WHERE scope=?1",
        [s],
    )
    .unwrap();
    assert_eq!(
        records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap(),
        s
    );
}

#[test]
fn definition_change_hook_retires_only_at_transition() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.indexes.push(IndexDecl {
        name: "old".into(),
        keys: vec![key()],
        declared_by: t.type_id,
    });
    bind(&tx, s, &t);
    index::on_definitions_changed(&tx, s, &catalogue::Shipped).unwrap();
    let ix: i64 = tx
        .query_row(
            "SELECT id FROM data_index WHERE scope=?1 AND family=?2",
            rusqlite::params![s, t.type_id.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    t.revision = RevisionId([7; 32]);
    t.indexes.clear();
    bind(&tx, s, &t);
    assert_eq!(index::state(&tx, ix).unwrap().state, "ready");
    index::on_definitions_changed(&tx, s, &catalogue::Shipped).unwrap();
    assert_eq!(index::state(&tx, ix).unwrap().state, "retiring");
}

#[test]
fn definition_reconciliation_cost_grows_linearly_with_type_count() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    fn steps(total: u8) -> usize {
        let mut c = conn();
        let tx = c.transaction().unwrap();
        let s = records::scope_id(&tx, scope(3), &catalogue::Shipped).unwrap();
        for n in 1..=total {
            let mut t = ct(n, n);
            for j in 0..4 {
                t.indexes.push(IndexDecl {
                    name: format!("by_{j}"),
                    keys: vec![KeyRef::Field(FieldPath::parse(&format!("/k{j}")).unwrap())],
                    declared_by: t.type_id,
                });
            }
            bind(&tx, s, &t);
        }
        let counter = Arc::new(AtomicUsize::new(0));
        let progress = counter.clone();
        tx.progress_handler(
            100,
            Some(move || {
                progress.fetch_add(1, Ordering::Relaxed);
                false
            }),
        )
        .unwrap();
        index::on_definitions_changed(&tx, s, &catalogue::Shipped).unwrap();
        tx.progress_handler(0, None::<fn() -> bool>).unwrap();
        let rows: i64 = tx.query_row("SELECT count(*) FROM data_index WHERE scope=?1 AND origin='definition' AND state='ready'", [s], |r| r.get(0)).unwrap();
        assert_eq!(rows, i64::from(total) * 4 + 1); // includes shipped Note's index
        counter.load(Ordering::Relaxed)
    }
    let small = steps(20);
    let large = steps(200);
    eprintln!("reconciliation VM steps (per 100): 20 types={small}, 200 types={large}");
    assert!(
        large <= small * 12,
        "reconciliation VM steps (per 100): 20 types={small}, 200 types={large}"
    );
}

#[test]
fn shared_family_declaration_remains_until_last_consumer_retires_it() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut a = ct(2, 2);
    a.indexes.push(IndexDecl {
        name: "shared".into(),
        keys: vec![key()],
        declared_by: a.type_id,
    });
    let mut b = ct(3, 2);
    b.indexes = a.indexes.clone();
    bind(&tx, s, &a);
    bind(&tx, s, &b);
    index::on_definitions_changed(&tx, s, &catalogue::Shipped).unwrap();
    let ix: i64 = tx
        .query_row(
            "SELECT id FROM data_index WHERE scope=?1 AND family=?2",
            rusqlite::params![s, a.type_id.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    a.indexes.clear();
    a.revision = RevisionId([12; 32]);
    bind(&tx, s, &a);
    index::on_definitions_changed(&tx, s, &catalogue::Shipped).unwrap();
    assert_eq!(index::state(&tx, ix).unwrap().state, "ready");
    b.indexes.clear();
    b.revision = RevisionId([13; 32]);
    bind(&tx, s, &b);
    index::on_definitions_changed(&tx, s, &catalogue::Shipped).unwrap();
    assert_eq!(index::state(&tx, ix).unwrap().state, "retiring");
}

#[test]
fn unique_rejects_changed_key() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.uniques.push(UniqueDecl {
        name: "invalid".into(),
        keys: vec![KeyRef::Changed],
        declared_by: t.type_id,
    });
    assert!(matches!(
        index::ensure(&tx, s, &t),
        Err(bh_data::DataError::Definition(_))
    ));
    assert!(index::pending_work(&tx).unwrap().is_empty());
}

#[test]
fn entries_follow_record_changes() {
    let mut c = conn();
    let t = ct(2, 2);
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let ix = index::ensure_local(&tx, s, t.type_id, vec![key()]).unwrap();
    let mut r = row(s, 1, &t, json!({"name":"before"}));
    records::put(&tx, &mut r).unwrap();
    index::on_record_changed(&tx, &r, &t).unwrap();
    assert_eq!(entries(&tx, ix), 1);
    r.accepted = Some(json!({"name":"after"}));
    records::put(&tx, &mut r).unwrap();
    index::on_record_changed(&tx, &r, &t).unwrap();
    let name: String = tx
        .query_row("SELECT k1 FROM data_index_entry WHERE ix=?", [ix], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(name, "after");
    tx.commit().unwrap();
}
#[test]
fn identical_index_reused_across_consumers() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut a = ct(2, 2);
    a.indexes.push(IndexDecl {
        name: "one".into(),
        keys: vec![key()],
        declared_by: a.type_id,
    });
    let mut b = ct(3, 2);
    b.indexes.push(IndexDecl {
        name: "two".into(),
        keys: vec![key()],
        declared_by: a.type_id,
    });
    assert_eq!(
        index::ensure(&tx, s, &a).unwrap(),
        index::ensure(&tx, s, &b).unwrap()
    );
}
#[test]
fn subtype_declared_index_covers_only_subtype_family() {
    let mut source: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/types/JournalEntry.json")).unwrap();
    source["indexes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"by_mood","keys":["/mood"]}));
    let definition = definition::parse(&serde_json::to_vec(&source).unwrap()).unwrap();
    let journal = compose::compile(
        &definition,
        RevisionId::of(&definition.bytes),
        &|id, rev| {
            catalogue::Shipped
                .core_type(id)
                .filter(|core| core.revision == rev)
        },
    )
    .unwrap();
    let note = &catalogue::core_types()[0];
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    bind(&tx, s, &journal);
    index::ensure(&tx, s, &journal).unwrap();
    let ix: i64 = tx
        .query_row(
            "SELECT id FROM data_index WHERE scope=?1 AND family=?2 AND keys=?3 AND unique_=0",
            rusqlite::params![
                s,
                journal.type_id.0.as_slice(),
                serde_json::to_string(&vec![KeyRef::Field(FieldPath::parse("/mood").unwrap())])
                    .unwrap()
            ],
            |r| r.get(0),
        )
        .unwrap();
    let mut plain = row(s, 1, note, json!({"title":"Plain note"}));
    records::put(&tx, &mut plain).unwrap();
    index::on_record_changed(&tx, &plain, note).unwrap();
    let mut specialised = row(s, 2, &journal, json!({"date":1,"mood":"calm"}));
    records::put(&tx, &mut specialised).unwrap();
    index::on_record_changed(&tx, &specialised, &journal).unwrap();
    while !index::backfill_step(&tx, ix, 500).unwrap().ready {}
    assert_eq!(index::state(&tx, ix).unwrap().family, journal.type_id);
    assert_eq!(entries(&tx, ix), 1);
    let (indexed_record, mood): (i64, String) = tx
        .query_row(
            "SELECT rec,k1 FROM data_index_entry WHERE ix=?1",
            [ix],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((indexed_record, mood.as_str()), (specialised.id, "calm"));
}

#[test]
fn missing_optional_key_indexed_as_null() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let t = ct(2, 2);
    let ix = index::ensure_local(&tx, s, t.type_id, vec![key()]).unwrap();
    let mut r = row(s, 1, &t, json!({}));
    records::put(&tx, &mut r).unwrap();
    index::on_record_changed(&tx, &r, &t).unwrap();
    assert_eq!(entries(&tx, ix), 1);
    assert!(
        tx.query_row(
            "SELECT k1 IS NULL FROM data_index_entry WHERE ix=?",
            [ix],
            |r| r.get::<_, bool>(0)
        )
        .unwrap()
    );
}
#[test]
fn backfill_bounded_by_batch() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.indexes.push(IndexDecl {
        name: "name".into(),
        keys: vec![key()],
        declared_by: t.type_id,
    });
    for n in 1..=1100 {
        let mut r = row(s, n, &t, json!({"name":n}));
        records::put(&tx, &mut r).unwrap();
    }
    let ix = index::ensure(&tx, s, &t).unwrap()[0];
    let p = index::backfill_step(&tx, ix, 500).unwrap();
    assert!(!p.ready);
    assert_eq!(entries(&tx, ix), 500);
    while !index::backfill_step(&tx, ix, 500).unwrap().ready {}
    assert_eq!(entries(&tx, ix), 1100);
}
#[test]
fn backfill_work_bound_resumes_without_skipping_rows() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let sid = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut ty = ct(2, 2);
    ty.indexes.push(IndexDecl {
        name: "name".into(),
        keys: vec![key()],
        declared_by: ty.type_id,
    });
    for n in 1..=1100 {
        let mut r = row(sid, n, &ty, json!({"name":n}));
        records::put(&tx, &mut r).unwrap();
    }
    let ix = index::ensure(&tx, sid, &ty).unwrap()[0];
    let mut steps = 0;
    loop {
        let progress = index::backfill_step_bounded(&tx, ix, 500, 500).unwrap();
        steps += 1;
        if progress.ready {
            break;
        }
        assert!(
            progress.done < (steps * 500) as u64,
            "work cap did not interrupt row batch"
        );
        assert!(steps < 1101, "no forward progress");
    }
    assert!(
        steps > 3,
        "row cap, not work cap, limited the steps: {steps}"
    );
    assert_eq!(entries(&tx, ix), 1100);
}
#[test]
fn unique_detects_taken_and_existing_duplicates() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.uniques.push(UniqueDecl {
        name: "u".into(),
        keys: vec![key()],
        declared_by: t.type_id,
    });
    let ix = index::ensure(&tx, s, &t).unwrap()[0];
    let mut a = row(s, 1, &t, json!({"name":"x"}));
    let mut b = row(s, 2, &t, json!({"name":"x"}));
    for r in [&mut a, &mut b] {
        records::put(&tx, r).unwrap();
        index::on_record_changed(&tx, r, &t).unwrap();
    }
    assert_eq!(
        tx.query_row("SELECT count(*) FROM data_unique WHERE ix=?", [ix], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        2
    );
    coverage::set(&tx, s, Position(1), true).unwrap();
    assert_eq!(
        unique::check(&tx, s, &t, Some(a.id), &json!({"name":"x"})).unwrap(),
        UniqueCheck::Taken(b.record)
    );
}

#[test]
fn entries_only_reference_index_scope() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let a = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let b = records::scope_id(&tx, scope(3), &catalogue::Shipped).unwrap();
    let t = ct(2, 2);
    let ix = index::ensure_local(&tx, a, t.type_id, vec![key()]).unwrap();
    let mut r = row(b, 1, &t, json!({"name":"private"}));
    records::put(&tx, &mut r).unwrap();
    index::on_record_changed(&tx, &r, &t).unwrap();
    assert_eq!(entries(&tx, ix), 0);
    let mut forged = r.clone();
    forged.scope = a;
    assert!(index::on_record_changed(&tx, &forged, &t).is_err());
}
#[test]
fn doc_only_revision_keeps_index_ready() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.indexes.push(IndexDecl {
        name: "a".into(),
        keys: vec![key()],
        declared_by: t.type_id,
    });
    let ix = index::ensure(&tx, s, &t).unwrap()[0];
    t.revision = RevisionId([9; 32]);
    t.docs.description = "updated".into();
    assert_eq!(index::ensure(&tx, s, &t).unwrap(), vec![ix]);
    assert_eq!(index::state(&tx, ix).unwrap().state, "ready");
}
#[test]
fn local_index_not_retired_by_definition_change() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let t = ct(2, 2);
    let local = index::ensure_local(&tx, s, t.type_id, vec![key()]).unwrap();
    let mut old = t.clone();
    old.indexes.push(IndexDecl {
        name: "old".into(),
        keys: vec![KeyRef::Changed],
        declared_by: old.type_id,
    });
    let obsolete = index::ensure(&tx, s, &old).unwrap()[0];
    index::ensure(&tx, s, &t).unwrap();
    assert_eq!(index::state(&tx, local).unwrap().state, "ready");
    assert_eq!(index::state(&tx, obsolete).unwrap().state, "retiring");
}
#[test]
fn shipped_note_recent_index_ready_in_new_scope() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let note = &catalogue::core_types()[0];
    assert!(note.indexes.iter().any(|decl| decl.name == "recent"
        && decl.keys == [KeyRef::Changed]
        && decl.declared_by == note.type_id));
    let ix = index::pending_work(&tx).unwrap();
    assert!(ix.is_empty());
    let count: i64 = tx
        .query_row(
            "SELECT count(*) FROM data_index WHERE scope=?1 AND family=?2 AND keys=?3 AND state='ready'",
            rusqlite::params![s, note.type_id.0.as_slice(), serde_json::to_string(&vec![KeyRef::Changed]).unwrap()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
    let other = ct(3, 3);
    index::ensure(&tx, s, &other).unwrap();
    assert_eq!(
        tx.query_row(
            "SELECT count(*) FROM data_index WHERE scope=?1 AND state='ready'",
            [s],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}
#[test]
fn unique_unknown_while_building_or_uncovered() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.uniques.push(UniqueDecl {
        name: "u".into(),
        keys: vec![key()],
        declared_by: t.type_id,
    });
    assert_eq!(
        unique::check(&tx, s, &t, None, &json!({"name":"x"})).unwrap(),
        UniqueCheck::Unknown
    );
    let ix = index::ensure(&tx, s, &t).unwrap()[0];
    coverage::set(&tx, s, Position(1), true).unwrap();
    assert_eq!(
        unique::check(&tx, s, &t, None, &json!({"name":"x"})).unwrap(),
        UniqueCheck::Free
    );
    tx.execute("UPDATE data_index SET state='building' WHERE id=?1", [ix])
        .unwrap();
    assert_eq!(
        unique::check(&tx, s, &t, None, &json!({"name":"x"})).unwrap(),
        UniqueCheck::Unknown
    );
}
#[test]
fn referrers_signal_incomplete_reader_scope() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let incomplete = index::refs::referrers(&tx, s, s, rid(1), 10).unwrap();
    assert!(!incomplete.complete);
    assert!(incomplete.rows.is_empty());
    coverage::set(&tx, s, Position(1), true).unwrap();
    assert!(
        index::refs::referrers(&tx, s, s, rid(1), 10)
            .unwrap()
            .complete
    );
}
#[test]
fn refs_track_reference_fields() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.fields.push(FieldSpec {
        path: FieldPath::parse("/friend").unwrap(),
        kind: FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(2)],
            family: false,
        }),
        write: WritePolicy::Direct,
        required: false,
        nullable: true,
        declared_by: t.type_id,
        meaning: String::new(),
        unit: None,
        absent: None,
    });
    let mut r = row(s, 1, &t, json!({"friend":{"record":rid(2)}}));
    records::put(&tx, &mut r).unwrap();
    index::on_record_changed(&tx, &r, &t).unwrap();
    coverage::set(&tx, s, Position(1), true).unwrap();
    assert_eq!(
        index::refs::referrers(&tx, s, s, rid(2), 10).unwrap().rows,
        vec![(r.id, FieldPath::parse("/friend").unwrap())]
    );
    let other = records::scope_id(&tx, scope(3), &catalogue::Shipped).unwrap(); // JSON encodes audience as lowercase hex, never a byte array.
    r.accepted = Some(
        json!({"friend":{"audience":"0303030303030303030303030303030303030303030303030303030303030303","record":rid(3)}}),
    );
    records::put(&tx, &mut r).unwrap();
    index::on_record_changed(&tx, &r, &t).unwrap();
    assert!(
        index::refs::referrers(&tx, s, s, rid(2), 10)
            .unwrap()
            .rows
            .is_empty()
    );
    assert_eq!(
        index::refs::referrers(&tx, s, other, rid(3), 10)
            .unwrap()
            .rows
            .len(),
        1
    );
    assert!(
        !index::refs::referrers(&tx, other, other, rid(3), 10)
            .unwrap()
            .complete
    );
}
#[test]
fn retiring_index_drains_in_steps() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.indexes.push(IndexDecl {
        name: "i".into(),
        keys: vec![key()],
        declared_by: t.type_id,
    });
    let ix = index::ensure(&tx, s, &t).unwrap()[0];
    for n in 1..=8 {
        let mut r = row(s, n, &t, json!({"name":n}));
        records::put(&tx, &mut r).unwrap();
        index::on_record_changed(&tx, &r, &t).unwrap();
    }
    t.indexes.clear();
    index::ensure(&tx, s, &t).unwrap();
    assert_eq!(index::state(&tx, ix).unwrap().state, "retiring");
    assert!(!index::backfill_step(&tx, ix, 3).unwrap().ready);
    assert_eq!(entries(&tx, ix), 5);
    while !index::backfill_step(&tx, ix, 3).unwrap().ready {}
    assert!(index::state(&tx, ix).is_err());
}
#[test]
fn backfill_catches_concurrent_writes() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.indexes.push(IndexDecl {
        name: "i".into(),
        keys: vec![key()],
        declared_by: t.type_id,
    });
    for n in 1..=12 {
        let mut r = row(s, n, &t, json!({"name":n}));
        records::put(&tx, &mut r).unwrap();
    }
    let ix = index::ensure(&tx, s, &t).unwrap()[0];
    index::backfill_step(&tx, ix, 5).unwrap();
    for n in [2, 10] {
        let mut r = records::get(&tx, s, rid(n)).unwrap().unwrap();
        r.accepted = Some(json!({"name":"edited"}));
        records::put(&tx, &mut r).unwrap();
        index::on_record_changed(&tx, &r, &t).unwrap();
    }
    while !index::backfill_step(&tx, ix, 5).unwrap().ready {}
    assert_eq!(entries(&tx, ix), 12);
    let count: i64 = tx
        .query_row(
            "SELECT count(*) FROM data_index_entry WHERE ix=?1 AND k1='edited'",
            [ix],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 2);
    let concurrent = index_rows(&tx, ix);
    tx.execute("DELETE FROM data_index_entry WHERE ix=?1", [ix])
        .unwrap();
    tx.execute("UPDATE data_index SET state='building',cursor_type=NULL,cursor_id=0,built=0,estimate=NULL WHERE id=?1",[ix]).unwrap();
    while !index::backfill_step(&tx, ix, 5).unwrap().ready {}
    assert_eq!(concurrent, index_rows(&tx, ix));
}

#[test]
fn interrupted_backfill_matches_rebuild() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut c = Connection::open(file.path()).unwrap();
    let tx = c.transaction().unwrap();
    store::migrate(&tx).unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.indexes.push(IndexDecl {
        name: "i".into(),
        keys: vec![key()],
        declared_by: t.type_id,
    });
    for n in 1..=21 {
        let mut r = row(s, n, &t, json!({"name":n}));
        records::put(&tx, &mut r).unwrap();
    }
    let ix = index::ensure(&tx, s, &t).unwrap()[0];
    index::backfill_step(&tx, ix, 7).unwrap();
    tx.commit().unwrap();
    drop(c);
    let mut c = Connection::open(file.path()).unwrap();
    {
        let tx = c.transaction().unwrap();
        while !index::backfill_step(&tx, ix, 7).unwrap().ready {}
        tx.commit().unwrap();
    }
    let original: Vec<(i64, i64)> = c
        .prepare("SELECT k1,rec FROM data_index_entry WHERE ix=?1 ORDER BY rec")
        .unwrap()
        .query_map([ix], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    // Rebuild a copy from the persistent accepted records, leaving the original untouched.
    let copy = tempfile::NamedTempFile::new().unwrap();
    std::fs::copy(file.path(), copy.path()).unwrap();
    let mut rebuilt = Connection::open(copy.path()).unwrap();
    {
        let tx = rebuilt.transaction().unwrap();
        tx.execute("DELETE FROM data_index_entry WHERE ix=?1", [ix])
            .unwrap();
        tx.execute(
            "UPDATE data_index SET state='building',cursor_type=NULL,cursor_id=0,built=0,estimate=NULL WHERE id=?1",
            [ix],
        )
        .unwrap();
        while !index::backfill_step(&tx, ix, 7).unwrap().ready {}
        tx.commit().unwrap();
    }
    let fresh: Vec<(i64, i64)> = rebuilt
        .prepare("SELECT k1,rec FROM data_index_entry WHERE ix=?1 ORDER BY rec")
        .unwrap()
        .query_map([ix], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(original, fresh);
}

#[test]
fn backfill_reads_bounded_records_at_scale() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    fn measure(total: u32) -> usize {
        let mut c = conn();
        let tx = c.transaction().unwrap();
        let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
        let mut a = ct(2, 2);
        let b = ct(3, 2);
        a.indexes.push(IndexDecl {
            name: "i".into(),
            keys: vec![key()],
            declared_by: a.type_id,
        });
        bind(&tx, s, &b);
        for n in 1..=total {
            let t = if n % 2 == 0 { &a } else { &b };
            let mut r = row(s, n, t, json!({"name":"x"}));
            records::put(&tx, &mut r).unwrap();
        }
        let ix = index::ensure(&tx, s, &a).unwrap()[0];
        tx.commit().unwrap();
        let ticks = Arc::new(AtomicUsize::new(0));
        let counter = ticks.clone();
        c.progress_handler(
            100,
            Some(move || {
                counter.fetch_add(1, Ordering::Relaxed);
                false
            }),
        )
        .unwrap();
        let tx = c.transaction().unwrap();
        index::backfill_step(&tx, ix, 500).unwrap();
        let count = ticks.load(Ordering::Relaxed);
        tx.rollback().unwrap();
        count
    }
    let small = measure(1_000);
    let large = measure(10_000);
    assert!(
        large * 2 <= small * 3,
        "10k: {large} ticks, 1k: {small} ticks"
    );
}

#[test]
fn progress_is_cumulative_across_steps_and_reopen() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut c = Connection::open(file.path()).unwrap();
    let tx = c.transaction().unwrap();
    store::migrate(&tx).unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.indexes.push(IndexDecl {
        name: "i".into(),
        keys: vec![key()],
        declared_by: t.type_id,
    });
    for n in 1..=5 {
        let mut r = row(s, n, &t, json!({"name":n}));
        records::put(&tx, &mut r).unwrap();
    }
    let ix = index::ensure(&tx, s, &t).unwrap()[0];
    assert_eq!(
        (
            index::state(&tx, ix).unwrap().built,
            index::state(&tx, ix).unwrap().estimate
        ),
        (0, Some(5))
    );
    let first = index::backfill_step(&tx, ix, 2).unwrap();
    assert_eq!((first.done, first.total, first.ready), (2, 5, false));
    tx.commit().unwrap();
    drop(c);
    let mut c = Connection::open(file.path()).unwrap();
    let tx = c.transaction().unwrap();
    let second = index::backfill_step(&tx, ix, 2).unwrap();
    assert_eq!((second.done, second.total, second.ready), (4, 5, false));
    let last = index::backfill_step(&tx, ix, 2).unwrap();
    assert_eq!((last.done, last.total, last.ready), (5, 5, true));
    assert_eq!(
        (
            index::state(&tx, ix).unwrap().built,
            index::state(&tx, ix).unwrap().estimate
        ),
        (5, Some(5))
    );
}

#[test]
fn registered_member_before_cursor_is_maintained_inline() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut root = ct(2, 2);
    root.indexes.push(IndexDecl {
        name: "i".into(),
        keys: vec![key()],
        declared_by: root.type_id,
    });
    for n in 1..=6 {
        let mut r = row(s, n, &root, json!({"name":n}));
        records::put(&tx, &mut r).unwrap();
    }
    let ix = index::ensure(&tx, s, &root).unwrap()[0];
    index::backfill_step(&tx, ix, 3).unwrap();
    assert_eq!(index::state(&tx, ix).unwrap().cursor_type, Some(ty(2)));
    let earlier = ct(1, 2);
    bind(&tx, s, &earlier);
    let mut r = row(s, 7, &earlier, json!({"name":"new"}));
    records::put(&tx, &mut r).unwrap();
    index::on_record_changed(&tx, &r, &earlier).unwrap();
    assert_eq!(entries(&tx, ix), 4);
    while !index::backfill_step(&tx, ix, 3).unwrap().ready {}
    assert_eq!(entries(&tx, ix), 7);
}

#[test]
fn unique_reads_accepted_not_optimistic_doc() {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.uniques.push(UniqueDecl {
        name: "name".into(),
        keys: vec![key()],
        declared_by: t.type_id,
    });
    let ix = index::ensure(&tx, s, &t).unwrap()[0];
    let mut r = row(s, 1, &t, json!({"name":"accepted"}));
    r.doc = Some(json!({"name":"draft"}));
    records::put(&tx, &mut r).unwrap();
    index::on_record_changed(&tx, &r, &t).unwrap();
    let (visible,stable):(String,String)=tx.query_row("SELECT e.k1,u.k1 FROM data_index_entry e JOIN data_unique u ON e.ix=u.ix AND e.rec=u.rec WHERE e.ix=?1",[ix],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert_eq!((visible.as_str(), stable.as_str()), ("draft", "accepted"));
}

#[test]
fn rebuild_clears_derived_entries_in_bounded_transactions() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut c = Connection::open(file.path()).unwrap();
    let tx = c.transaction().unwrap();
    store::migrate(&tx).unwrap();
    let s = records::scope_id(&tx, scope(2), &catalogue::Shipped).unwrap();
    let mut t = ct(2, 2);
    t.indexes.push(IndexDecl {
        name: "x".into(),
        keys: vec![key()],
        declared_by: t.type_id,
    });
    bind(&tx, s, &t);
    let ix = index::ensure(&tx, s, &t).unwrap()[0];
    for n in 1..=601 {
        let mut r = row(s, n, &t, json!({"name":"x"}));
        records::put(&tx, &mut r).unwrap();
        index::on_record_changed(&tx, &r, &t).unwrap();
    }
    tx.commit().unwrap();
    drop(c);
    index::rebuild_all(|| {
        Connection::open(file.path()).map_err(|e| bh_data::DataError::Sql(e.to_string()))
    })
    .unwrap();
    let mut c = Connection::open(file.path()).unwrap();
    assert_eq!(entries(&c, ix), 0);
    assert_eq!(index::state(&c, ix).unwrap().state, "building");
    let tx = c.transaction().unwrap();
    while !index::backfill_step(&tx, ix, 500).unwrap().ready {}
    assert_eq!(entries(&tx, ix), 601);
}

/// VM steps the pending-work probes take, with `ready` idle indexes and
/// optionally one index still building.
fn pending_probe_steps(ready: u32, building: bool) -> (usize, bool) {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let s = records::scope_id(&tx, scope(3), &catalogue::Shipped).unwrap();
    for n in 0..ready {
        let key = KeyRef::Field(FieldPath::parse(&format!("/k{n}")).unwrap());
        let ix = index::ensure_local(&tx, s, ty(9), vec![key]).unwrap();
        assert_eq!(index::state(&tx, ix).unwrap().state, "ready");
    }
    if building {
        let t = ct(8, 8);
        bind(&tx, s, &t);
        records::put(&tx, &mut row(s, 1, &t, json!({"name": "a"}))).unwrap();
        let ix = index::ensure_local(&tx, s, ty(8), vec![key()]).unwrap();
        assert_eq!(index::state(&tx, ix).unwrap().state, "building");
    }
    let counter = Arc::new(AtomicUsize::new(0));
    let progress = counter.clone();
    tx.progress_handler(
        1,
        Some(move || {
            progress.fetch_add(1, Ordering::Relaxed);
            false
        }),
    )
    .unwrap();
    let pending = index::has_pending(&tx).unwrap();
    let next = index::next_pending(&tx).unwrap();
    let clearing = index::clearing_pending(&tx).unwrap();
    tx.progress_handler(0, None::<fn() -> bool>).unwrap();
    assert_eq!(next.is_some(), pending);
    assert!(!clearing);
    (counter.load(Ordering::Relaxed), pending)
}

#[test]
fn pending_probe_work_does_not_grow_with_ready_indexes() {
    let (idle_small, none) = pending_probe_steps(4, false);
    let (idle_large, still_none) = pending_probe_steps(400, false);
    assert!(!none && !still_none);
    assert_eq!(idle_small, idle_large, "probe visited ready indexes");
    let (busy_small, some) = pending_probe_steps(4, true);
    let (busy_large, still_some) = pending_probe_steps(400, true);
    assert!(some && still_some);
    assert_eq!(busy_small, busy_large, "probe visited ready indexes");
}
