//! Typed records, filtered queries, and local full-text search.

use bh_core::{
    Base, Error, FieldDef, FieldKind, Filter, NewObject, ObjectId, Op, Order, Query, TypeDef,
    TypeRef,
};
use bh_testkit::{two_devices, two_devices_sharing_a_base, wait_for_base};
use serde_json::{Map, Value, json};
use std::path::Path;
use yrs::updates::decoder::Decode;
use yrs::{
    Any, Doc, Map as _, ReadTxn, Transact, Update, WriteTxn, XmlElementPrelim, XmlFragment,
    XmlTextPrelim,
};

fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}
fn field(name: &str, kind: FieldKind, required: bool) -> FieldDef {
    FieldDef {
        name: name.into(),
        kind,
        required,
        unit: None,
        doc: String::new(),
    }
}
fn sleep_type() -> TypeDef {
    TypeDef {
        name: "demo.sleep".into(),
        version: 1,
        doc: String::new(),
        title_field: None,
        fields: vec![
            field("date", FieldKind::Date, true),
            field("score", FieldKind::Integer, false),
            field("memo", FieldKind::Text, false),
            field("token", FieldKind::Secret, false),
        ],
    }
}
fn new(ty: &str, fields: Value) -> NewObject {
    NewObject {
        ty: TypeRef::new(ty, 1),
        parent: None,
        after: None,
        fields: map(fields),
    }
}
fn local() -> (tempfile::TempDir, Base) {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::open_local(dir.path(), [7; 32]).unwrap();
    (dir, base)
}
fn note_text(base: &Base, text: &str) -> ObjectId {
    let id = base.create(new("core.note", json!({}))).unwrap();
    let doc = Doc::new();
    let mut txn = doc.transact_mut();
    txn.get_or_insert_xml_fragment("default").push_back(
        &mut txn,
        XmlElementPrelim::new("paragraph", [XmlTextPrelim::new(text).into()]),
    );
    base.note(id)
        .unwrap()
        .apply(1, &txn.encode_update_v1())
        .unwrap();
    id
}
fn query() -> Query {
    Query {
        ty: "demo.sleep".into(),
        filters: vec![],
        order_by: None,
        limit: None,
    }
}

#[tokio::test]
async fn a_type_defined_on_one_device_checks_records_on_another() {
    let (a, b) = two_devices_sharing_a_base().await;
    a.base.define_type(sleep_type()).unwrap();
    a.base.flush().await.unwrap();
    wait_for_base(&b.base, || b.base.types().unwrap().contains(&sleep_type())).await;
    assert!(matches!(
        b.base.create(new("demo.sleep", json!({ "score": 80 }))),
        Err(Error::Invalid(_))
    ));
    assert!(
        b.base
            .create(new(
                "demo.sleep",
                json!({ "date": "2026-11-01", "score": 80 })
            ))
            .is_ok()
    );
}

#[test]
fn a_synced_definition_cannot_make_an_existing_field_required() {
    let (_dir_a, a) = local();
    let (_dir_b, b) = local();
    let old = sleep_type();
    a.define_type(old.clone()).unwrap();
    let id = a.test_type_id(&old.name, old.version);
    let initial = a
        .test_outbox()
        .into_iter()
        .find(|(object, _)| *object == id)
        .unwrap()
        .1;
    b.test_apply_remote(id, &initial).unwrap();
    let doc = Doc::with_client_id((1 << 53) - 1);
    let mut txn = doc.transact_mut();
    txn.apply_update(Update::decode_v1(&initial).unwrap())
        .unwrap();
    let before = txn.state_vector();
    let mut changed = old.clone();
    changed
        .fields
        .iter_mut()
        .find(|field| field.name == "score")
        .unwrap()
        .required = true;
    let fields = txn.get_or_insert_map("fields");
    fields.insert(
        &mut txn,
        "def",
        serde_json::from_value::<Any>(json!(changed)).unwrap(),
    );
    let update = txn.encode_state_as_update_v1(&before);
    drop(txn);
    assert!(matches!(
        b.test_apply_remote(id, &update),
        Err(Error::Invalid(_))
    ));
    assert_eq!(b.types().unwrap(), vec![old]);
}

#[tokio::test]
async fn queries_filter_and_order_by_fields() {
    let (_dir, base) = local();
    base.define_type(sleep_type()).unwrap();
    let mut expected = Vec::new();
    for n in 0..30 {
        let id = base
            .create(new(
                "demo.sleep",
                json!({"date": format!("2026-11-{:02}", n + 1), "score": n * 4}),
            ))
            .unwrap();
        if n >= 20 {
            expected.push(id);
        }
    }
    expected.reverse();
    expected.truncate(5);
    let result = base
        .query(&Query {
            filters: vec![Filter {
                field: "score".into(),
                op: Op::Gte,
                value: json!(80),
            }],
            order_by: Some(("date".into(), Order::Desc)),
            limit: Some(5),
            ..query()
        })
        .unwrap();
    assert_eq!(result.iter().map(|s| s.id).collect::<Vec<_>>(), expected);
}

#[tokio::test]
async fn search_finds_note_text_and_record_text() {
    let (_dir, base) = local();
    base.define_type(sleep_type()).unwrap();
    let note = note_text(&base, "Ferry leaves at nine");
    let record = base
        .create(new(
            "demo.sleep",
            json!({ "date": "2026-11-01", "memo": format!("{} ferry terminal", "x".repeat(200)) }),
        ))
        .unwrap();
    let hits = base.search("ferry", 10).unwrap();
    assert_eq!(hits.len(), 2);
    assert!(hits.iter().any(|h| h.id == note
        && h.ty == TypeRef::new("core.note", 1)
        && h.title == "Ferry leaves at nine"));
    assert!(
        hits.iter().any(|h| h.id == record
            && h.ty == TypeRef::new("demo.sleep", 1)
            && h.snippet.to_lowercase().contains("ferry")),
        "{hits:?}"
    );
    assert!(hits.iter().all(|h| h.snippet.chars().count() <= 160));
    assert!(base.search("ferry", 1).unwrap().len() == 1);
}

#[tokio::test]
async fn search_excludes_chats_and_messages() {
    let (_dir, base) = local();
    let note = note_text(&base, "ferry leaves");
    for name in ["core.chat", "core.message"] {
        // These core types are provided by Hero later; simulate their incoming documents now.
        let doc = Doc::new();
        let mut txn = doc.transact_mut();
        let meta = txn.get_or_insert_map("meta");
        meta.insert(&mut txn, "type", name);
        meta.insert(&mut txn, "v", 1);
        let fields = txn.get_or_insert_map("fields");
        fields.insert(&mut txn, "name", "ferry secret");
        base.test_apply_remote(ObjectId::random(), &txn.encode_update_v1())
            .unwrap();
    }
    let hits = base.search("ferry", 10).unwrap();
    assert_eq!(hits.iter().map(|h| h.id).collect::<Vec<_>>(), vec![note]);
}

#[tokio::test]
async fn deleted_objects_leave_queries_and_search() {
    let (_dir, base) = local();
    base.define_type(sleep_type()).unwrap();
    let id = base
        .create(new(
            "demo.sleep",
            json!({"date":"2026-11-01", "memo":"ferry"}),
        ))
        .unwrap();
    assert_eq!(base.query(&query()).unwrap().len(), 1);
    assert_eq!(base.search("ferry", 10).unwrap().len(), 1);
    base.delete(id).unwrap();
    assert!(base.query(&query()).unwrap().is_empty());
    assert!(base.search("ferry", 10).unwrap().is_empty());
    assert!(base.trash().unwrap().iter().any(|s| s.id == id));
    base.undelete(id).unwrap();
    assert_eq!(base.search("ferry", 10).unwrap().len(), 1);
}

#[tokio::test]
async fn an_older_app_keeps_fields_it_does_not_know() {
    let (a, b) = two_devices_sharing_a_base().await;
    let mut older = sleep_type();
    older.fields.retain(|f| f.name != "memo");
    a.base.define_type(older.clone()).unwrap();
    a.base.flush().await.unwrap();
    wait_for_base(&b.base, || b.base.types().unwrap().contains(&older)).await;
    // Unknown fields are kept even before the optional field is defined.
    let id = a
        .base
        .create(new(
            "demo.sleep",
            json!({"date":"2026-11-01", "score":60, "source":"ferry"}),
        ))
        .unwrap();
    a.base.flush().await.unwrap();
    wait_for_base(&b.base, || b.base.get(id).unwrap().is_some()).await;
    assert!(
        !b.base.types().unwrap()[0]
            .fields
            .iter()
            .any(|f| f.name == "source")
    );
    let mut newer = older;
    newer.fields.push(field("source", FieldKind::Text, false));
    a.base.define_type(newer).unwrap();
    b.base.test_pause_sync();
    b.base.set_fields(id, map(json!({"score": 90}))).unwrap();
    b.base.test_resume_sync();
    b.base.flush().await.unwrap();
    wait_for_base(&a.base, || {
        a.base
            .get(id)
            .unwrap()
            .is_some_and(|s| s.fields["score"] == 90)
    })
    .await;
    for base in [&a.base, &b.base] {
        assert_eq!(base.get(id).unwrap().unwrap().fields["source"], "ferry");
    }
}

#[test]
fn an_undefined_remote_record_stays_unindexed_until_its_definition_arrives() {
    let (_dir_a, a) = local();
    let (_dir_b, b) = local();
    let mut def = sleep_type();
    def.title_field = Some("memo".into());
    a.define_type(def.clone()).unwrap();
    let record = a
        .create(new(
            "demo.sleep",
            json!({"date":"2026-11-01", "memo":"ferry timetable"}),
        ))
        .unwrap();
    let updates = a.test_outbox();
    let record_update = updates.iter().find(|(id, _)| *id == record).unwrap();
    b.test_apply_remote(record, &record_update.1).unwrap();
    assert_eq!(b.get(record).unwrap().unwrap().title, "");
    assert!(b.search("ferry", 10).unwrap().is_empty());
    assert!(matches!(
        b.set_fields(record, map(json!({"memo":"changed"}))),
        Err(Error::NeedsUpdate)
    ));
    let definition = a.test_type_id(&def.name, def.version);
    let definition_update = updates.iter().find(|(id, _)| *id == definition).unwrap();
    b.test_apply_remote(definition, &definition_update.1)
        .unwrap();
    assert_eq!(b.get(record).unwrap().unwrap().title, "ferry timetable");
    assert_eq!(b.search("ferry", 10).unwrap()[0].title, "ferry timetable");
}

#[tokio::test]
async fn a_late_definition_completes_a_record_through_sync() {
    let (a, b) = two_devices().await;
    let base = a.create_base("Late definition").await.unwrap();
    let mut def = sleep_type();
    def.title_field = Some("memo".into());
    base.define_type(def.clone()).unwrap();
    base.flush().await.unwrap();
    let record = base
        .create(new(
            "demo.sleep",
            json!({"date":"2026-11-01", "memo":"ferry timetable"}),
        ))
        .unwrap();
    base.flush().await.unwrap();
    def.doc = "Revised documentation".into();
    base.define_type(def).unwrap();
    base.flush().await.unwrap();

    b.refresh().await.unwrap();
    let other = b.base(base.id()).unwrap();
    let mut events = other.events();
    wait_for_base(&other, || {
        other
            .get(record)
            .unwrap()
            .is_some_and(|s| s.title == "ferry timetable")
    })
    .await;
    assert_eq!(other.get(record).unwrap().unwrap().title, "ferry timetable");
    let hits = other.search("ferry", 10).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, record);
    assert_eq!(hits[0].title, "ferry timetable");
    assert!(other.test_future_bodies(record).is_empty());
    while let Ok(event) = events.try_recv() {
        assert_ne!(format!("{event:?}"), "NeedsUpdate");
    }
}

#[tokio::test]
async fn remote_edits_and_deletes_update_search() {
    let (a, b) = two_devices_sharing_a_base().await;
    let id = a
        .base
        .create(new("core.folder", json!({"name":"ferry"})))
        .unwrap();
    a.base.flush().await.unwrap();
    wait_for_base(&b.base, || {
        b.base
            .search("ferry", 10)
            .unwrap()
            .iter()
            .any(|h| h.id == id)
    })
    .await;

    a.base
        .set_fields(id, map(json!({"name":"harbor"})))
        .unwrap();
    a.base.flush().await.unwrap();
    wait_for_base(&b.base, || {
        b.base
            .search("harbor", 10)
            .unwrap()
            .iter()
            .any(|h| h.id == id)
            && b.base
                .search("ferry", 10)
                .unwrap()
                .iter()
                .all(|h| h.id != id)
    })
    .await;

    a.base.delete(id).unwrap();
    a.base.flush().await.unwrap();
    wait_for_base(&b.base, || {
        b.base.get(id).unwrap().is_some_and(|s| s.deleted)
    })
    .await;
    assert!(
        b.base
            .search("harbor", 10)
            .unwrap()
            .iter()
            .all(|h| h.id != id)
    );
}

#[tokio::test]
async fn secret_fields_are_not_searchable() {
    let (_dir, base) = local();
    base.define_type(sleep_type()).unwrap();
    base.create(new(
        "demo.sleep",
        json!({"date":"2026-11-01", "token":"private-file-key-marker"}),
    ))
    .unwrap();
    assert!(
        base.search("private-file-key-marker", 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn interrupted_search_backfill_retries_all_records_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::open_local(dir.path(), [7; 32]).unwrap();
    let first = note_text(&base, "ferry first");
    let second = note_text(&base, "ferry second");
    let path = dir.path().join(format!("{}.sqlite", base.id()));
    drop(base);
    let key = bh_crypto::kdf(
        &bh_crypto::Secret::from_slice(&[7; 32]).unwrap(),
        b"bhtestdb",
        1,
    );
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(&format!(
        "PRAGMA key = \"x'{}'\";",
        key.expose()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
    .unwrap();
    let (last_id, state): (String, Vec<u8>) = db
        .query_row(
            "SELECT object_id, state FROM objects ORDER BY object_id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    db.execute(
        "UPDATE objects SET state = ? WHERE object_id = ?",
        rusqlite::params![vec![0u8], last_id],
    )
    .unwrap();
    db.execute_batch(
        "DROP TABLE object_search; DROP INDEX set_aside_unique; PRAGMA user_version = 2;",
    )
    .unwrap();
    assert!(Base::open_local(dir.path(), [7; 32]).is_err());
    db.execute(
        "UPDATE objects SET state = ? WHERE object_id = ?",
        rusqlite::params![state, last_id],
    )
    .unwrap();
    drop(db);
    let reopened = Base::open_local(dir.path(), [7; 32]).unwrap();
    let ids: Vec<_> = reopened
        .search("ferry", 10)
        .unwrap()
        .iter()
        .map(|h| h.id)
        .collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&first));
    assert!(ids.contains(&second));
}

#[test]
fn migrating_foundation_version_3_store_adds_search() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::open_local(dir.path(), [7; 32]).unwrap();
    let id = note_text(&base, "ferry foundation");
    let path = dir.path().join(format!("{}.sqlite", base.id()));
    drop(base);
    let key = bh_crypto::kdf(
        &bh_crypto::Secret::from_slice(&[7; 32]).unwrap(),
        b"bhtestdb",
        1,
    );
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(&format!(
        "PRAGMA key = \"x'{}'\";",
        key.expose()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
    .unwrap();
    db.execute_batch("DROP TABLE object_search; PRAGMA user_version = 3;")
        .unwrap();
    drop(db);
    let reopened = Base::open_local(dir.path(), [7; 32]).unwrap();
    assert_eq!(reopened.search("ferry", 10).unwrap()[0].id, id);
}

#[test]
fn migrating_main_version_4_store_keeps_future_changes_and_adds_search() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::open_local(dir.path(), [7; 32]).unwrap();
    let id = note_text(&base, "ferry migration");
    let path = dir.path().join(format!("{}.sqlite", base.id()));
    drop(base);
    let key = bh_crypto::kdf(
        &bh_crypto::Secret::from_slice(&[7; 32]).unwrap(),
        b"bhtestdb",
        1,
    );
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(&format!(
        "PRAGMA key = \"x'{}'\";",
        key.expose()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
    .unwrap();
    db.execute_batch("DROP TABLE object_search; PRAGMA user_version = 4;")
        .unwrap();
    db.execute(
        "INSERT INTO future_changes (object_id, seq, state, device_id, body) VALUES (?, 1, 0, 'device', x'01')",
        [id.to_string()],
    )
    .unwrap();
    drop(db);
    let reopened = Base::open_local(dir.path(), [7; 32]).unwrap();
    assert_eq!(reopened.search("ferry", 10).unwrap()[0].id, id);
    assert_eq!(reopened.test_future_bodies(id), vec![vec![1]]);
}

#[test]
fn migrating_early_search_version_4_store_adds_future_changes() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::open_local(dir.path(), [7; 32]).unwrap();
    let id = note_text(&base, "ferry migration");
    let path = dir.path().join(format!("{}.sqlite", base.id()));
    drop(base);
    let key = bh_crypto::kdf(
        &bh_crypto::Secret::from_slice(&[7; 32]).unwrap(),
        b"bhtestdb",
        1,
    );
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(&format!(
        "PRAGMA key = \"x'{}'\";",
        key.expose()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
    .unwrap();
    db.execute_batch("DROP TABLE future_changes; PRAGMA user_version = 4;")
        .unwrap();
    drop(db);
    let reopened = Base::open_local(dir.path(), [7; 32]).unwrap();
    assert_eq!(reopened.search("ferry", 10).unwrap()[0].id, id);
    assert!(reopened.test_future_bodies(id).is_empty());
}

#[test]
fn migrating_a_version_2_store_adds_search() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::open_local(dir.path(), [7; 32]).unwrap();
    let id = note_text(&base, "ferry migration");
    let path = dir.path().join(format!("{}.sqlite", base.id()));
    drop(base);
    let key = bh_crypto::kdf(
        &bh_crypto::Secret::from_slice(&[7; 32]).unwrap(),
        b"bhtestdb",
        1,
    );
    let db = rusqlite::Connection::open(Path::new(&path)).unwrap();
    db.execute_batch(&format!(
        "PRAGMA key = \"x'{}'\";",
        key.expose()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
    .unwrap();
    db.execute_batch("DROP TABLE IF EXISTS object_search; DROP INDEX IF EXISTS set_aside_unique; PRAGMA user_version = 2;")
        .unwrap();
    drop(db);
    let base = Base::open_local(dir.path(), [7; 32]).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(&format!(
        "PRAGMA key = \"x'{}'\";",
        key.expose()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
    .unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        5
    );
    assert_eq!(base.search("ferry", 10).unwrap()[0].id, id);
}
