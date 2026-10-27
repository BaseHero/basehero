//! Objects, types and the local store, without a server.

use bh_core::{
    Base, Error, FieldDef, FieldKind, NewObject, ObjectId, ObjectSummary, TypeDef, TypeRef,
};
use serde_json::{Map, Value, json};
use std::ops::Deref;
use std::path::Path;
use yrs::updates::decoder::Decode;
use yrs::{
    Any, Doc, Map as _, ReadTxn, Transact, Update, WriteTxn, XmlElementPrelim, XmlFragment,
    XmlTextPrelim,
};

struct LocalBase {
    base: Base,
    dir: tempfile::TempDir,
}

impl Deref for LocalBase {
    type Target = Base;
    fn deref(&self) -> &Base {
        &self.base
    }
}

fn local_base_with(key: [u8; 32]) -> LocalBase {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::open_local(dir.path(), key).unwrap();
    LocalBase { base, dir }
}

fn local_base() -> LocalBase {
    local_base_with([7; 32])
}

fn fields(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => panic!("fields must be an object"),
    }
}

fn new(ty: &str, parent: Option<ObjectId>, value: Value) -> NewObject {
    NewObject {
        ty: TypeRef {
            name: ty.into(),
            version: 1,
        },
        parent,
        after: None,
        fields: fields(value),
    }
}

fn note() -> NewObject {
    new("core.note", None, json!({}))
}

fn note_in(parent: ObjectId) -> NewObject {
    new("core.note", Some(parent), json!({}))
}

fn folder(name: &str) -> NewObject {
    new("core.folder", None, json!({ "name": name }))
}

fn record(ty: &str, value: Value) -> NewObject {
    new(ty, None, value)
}

fn ids(summaries: Vec<ObjectSummary>) -> Vec<ObjectId> {
    summaries.into_iter().map(|s| s.id).collect()
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

fn trip_type() -> TypeDef {
    TypeDef {
        name: "demo.trip".into(),
        version: 1,
        doc: "A trip".into(),
        title_field: Some("title".into()),
        fields: vec![
            field("start", FieldKind::Date, true),
            field("title", FieldKind::Text, false),
        ],
    }
}

/// An update that adds one paragraph of `text` to a note's body.
fn insert_text(text: &str) -> Vec<u8> {
    let doc = Doc::new();
    let mut txn = doc.transact_mut();
    let body = txn.get_or_insert_xml_fragment("default");
    body.push_back(
        &mut txn,
        XmlElementPrelim::new("paragraph", [XmlTextPrelim::new(text).into()]),
    );
    txn.encode_update_v1()
}

/// An update that adds a paragraph of `text` after the document in `state`,
/// as an editor holding that document would.
fn append_text(state: &[u8], text: &str) -> Vec<u8> {
    let doc = Doc::new();
    let mut txn = doc.transact_mut();
    txn.apply_update(Update::decode_v1(state).unwrap()).unwrap();
    let before = txn.state_vector();
    let body = txn.get_or_insert_xml_fragment("default");
    body.push_back(
        &mut txn,
        XmlElementPrelim::new("paragraph", [XmlTextPrelim::new(text).into()]),
    );
    txn.encode_state_as_update_v1(&before)
}

/// Copies an object's whole state from one base to another, as sync would.
fn copy(from: &Base, to: &Base, id: ObjectId) {
    to.test_apply_remote(id, &from.note(id).unwrap().state())
        .unwrap();
}

fn files_under(dir: &Path) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else {
            out.push(std::fs::read(&path).unwrap());
        }
    }
    out
}

#[test]
fn children_are_ordered_and_creation_after_a_sibling_lands_after_it() {
    let base = local_base();
    let f = base.create(folder("Trips")).unwrap();
    let a = base.create(note_in(f)).unwrap();
    let c = base.create(note_in(f)).unwrap();
    let b = base
        .create(NewObject {
            after: Some(a),
            ..note_in(f)
        })
        .unwrap();
    assert_eq!(ids(base.children(Some(f)).unwrap()), vec![a, b, c]);
    assert_eq!(ids(base.children(None).unwrap()), vec![f]);
    assert_eq!(base.get(f).unwrap().unwrap().title, "Trips");
}

#[test]
fn moving_places_an_object_first_or_after_a_sibling() {
    let base = local_base();
    let f = base.create(folder("Trips")).unwrap();
    let a = base.create(note_in(f)).unwrap();
    let b = base.create(note_in(f)).unwrap();
    let c = base.create(note_in(f)).unwrap();
    base.move_to(c, Some(f), None).unwrap();
    assert_eq!(ids(base.children(Some(f)).unwrap()), vec![c, a, b]);
    base.move_to(c, Some(f), Some(a)).unwrap();
    assert_eq!(ids(base.children(Some(f)).unwrap()), vec![a, c, b]);
    base.move_to(a, None, None).unwrap();
    assert_eq!(base.get(a).unwrap().unwrap().parent, None);
    assert_eq!(ids(base.children(Some(f)).unwrap()), vec![c, b]);
    assert!(matches!(
        base.move_to(f, Some(f), None),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn concurrent_moves_converge_to_one_parent() {
    let (one, two) = (local_base(), local_base());
    let p1 = one.create(folder("One")).unwrap();
    let p2 = one.create(folder("Two")).unwrap();
    let n = one.create(note()).unwrap();
    for id in [p1, p2, n] {
        copy(&one, &two, id);
    }
    one.move_to(n, Some(p1), None).unwrap();
    two.move_to(n, Some(p2), None).unwrap();
    let (from_one, from_two) = (one.note(n).unwrap().state(), two.note(n).unwrap().state());
    two.test_apply_remote(n, &from_one).unwrap();
    one.test_apply_remote(n, &from_two).unwrap();
    let parent = one.get(n).unwrap().unwrap().parent;
    assert!(parent == Some(p1) || parent == Some(p2));
    assert_eq!(two.get(n).unwrap().unwrap().parent, parent);
    assert_eq!(ids(one.children(parent).unwrap()), vec![n]);
    assert_eq!(ids(two.children(parent).unwrap()), vec![n]);
}

#[test]
fn a_cycle_shows_its_lowest_id_at_the_top_level() {
    let (one, two) = (local_base(), local_base());
    let x = one.create(folder("X")).unwrap();
    let y = one.create(folder("Y")).unwrap();
    copy(&one, &two, x);
    copy(&one, &two, y);
    one.move_to(x, Some(y), None).unwrap();
    two.move_to(y, Some(x), None).unwrap();
    copy(&one, &two, x);
    copy(&two, &one, y);
    let (low, high) = (x.min(y), x.max(y));
    for base in [&one, &two] {
        assert_eq!(ids(base.children(None).unwrap()), vec![low]);
        assert_eq!(ids(base.children(Some(low)).unwrap()), vec![high]);
        assert!(base.children(Some(high)).unwrap().is_empty());
        assert_eq!(base.get(low).unwrap().unwrap().parent, None);
        assert_eq!(base.get(high).unwrap().unwrap().parent, Some(low));
    }
}

#[test]
fn fields_are_checked_against_their_type() {
    let base = local_base();
    base.define_type(trip_type()).unwrap(); // requires "start": Date
    assert!(matches!(
        base.create(record("demo.trip", json!({}))),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        base.create(record("demo.trip", json!({ "start": "2026-02-30" }))),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        base.create(record("demo.unknown", json!({}))),
        Err(Error::Invalid(_))
    ));
    let id = base
        .create(record(
            "demo.trip",
            json!({ "start": "2026-11-01", "extra": 1, "title": "Kyoto" }),
        ))
        .unwrap();
    let trip = base.get(id).unwrap().unwrap();
    assert_eq!(trip.fields["extra"], 1); // unknown fields are kept
    assert_eq!(trip.title, "Kyoto");
    assert_eq!(trip.ty.name, "demo.trip");

    assert!(matches!(
        base.set_fields(id, fields(json!({ "start": 5 }))),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        base.set_fields(id, fields(json!({ "start": null }))),
        Err(Error::Invalid(_))
    ));
    base.set_fields(id, fields(json!({ "title": "Osaka", "extra": null })))
        .unwrap();
    let trip = base.get(id).unwrap().unwrap();
    assert_eq!(trip.title, "Osaka");
    assert_eq!(trip.fields["start"], "2026-11-01");
    assert!(!trip.fields.contains_key("extra"));
}

#[test]
fn redefining_a_type_may_only_add_optional_fields_or_change_docs() {
    let base = local_base();
    base.define_type(trip_type()).unwrap();
    let mut wider = trip_type();
    wider.doc = "A journey".into();
    wider
        .fields
        .push(field("nights", FieldKind::Integer, false));
    base.define_type(wider.clone()).unwrap();
    assert_eq!(base.types().unwrap(), vec![wider.clone()]);

    let mut required = wider.clone();
    required.fields.push(field("cost", FieldKind::Number, true));
    let mut removed = wider.clone();
    removed.fields.retain(|f| f.name != "nights");
    let mut kind = wider.clone();
    kind.fields[0].kind = FieldKind::Text;
    let mut stricter = wider.clone();
    stricter.fields[2].required = true;
    for def in [required, removed, kind, stricter] {
        assert!(matches!(base.define_type(def), Err(Error::Invalid(_))));
    }
    assert_eq!(base.types().unwrap(), vec![wider]);

    let mut next = trip_type();
    next.version = 2;
    next.fields[0].kind = FieldKind::DateTime;
    base.define_type(next).unwrap();
    assert_eq!(base.types().unwrap().len(), 2);
    assert!(matches!(
        base.define_type(TypeDef {
            name: "core.trip".into(),
            ..trip_type()
        }),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn type_definition_ids_are_keyed_by_the_base() {
    let (one, same_key, other) = (
        local_base_with([1; 32]),
        local_base_with([1; 32]),
        local_base_with([2; 32]),
    );
    let id = one.test_type_id("demo.trip", 1);
    assert_eq!(id, one.test_type_id("demo.trip", 1));
    assert_ne!(id, one.test_type_id("demo.trip", 2));
    assert_ne!(id, one.test_type_id("demo.tri", 1));
    assert_eq!(id, same_key.test_type_id("demo.trip", 1));
    assert_ne!(id, other.test_type_id("demo.trip", 1));
    one.define_type(trip_type()).unwrap();
    let stored = one.get(id).unwrap().unwrap();
    assert_eq!(stored.ty.name, "core.type");
    assert!(one.children(None).unwrap().is_empty());
}

#[test]
fn an_object_of_a_newer_type_version_is_left_untouched() {
    let base = local_base();
    let id = ObjectId::random();
    let doc = Doc::new();
    let update = {
        let mut txn = doc.transact_mut();
        let meta = txn.get_or_insert_map("meta");
        meta.insert(&mut txn, "type", "core.note");
        meta.insert(&mut txn, "v", Any::from(2));
        meta.insert(&mut txn, "pos", "V");
        meta.insert(&mut txn, "deleted", false);
        txn.encode_update_v1()
    };
    base.test_apply_remote(id, &update).unwrap();
    let outbox = base.test_outbox().len();
    assert!(matches!(
        base.set_fields(id, fields(json!({ "x": 1 }))),
        Err(Error::NeedsUpdate)
    ));
    let opened = base.note(id).unwrap();
    assert!(matches!(
        opened.apply(11, &insert_text("hi")),
        Err(Error::NeedsUpdate)
    ));
    assert!(matches!(base.delete(id), Err(Error::NeedsUpdate)));
    assert!(matches!(
        base.move_to(id, None, None),
        Err(Error::NeedsUpdate)
    ));
    assert_eq!(opened.text(), "");
    assert_eq!(base.test_outbox().len(), outbox);
    let shown = base.get(id).unwrap().unwrap();
    assert_eq!(
        shown.ty,
        TypeRef {
            name: "core.note".into(),
            version: 2
        }
    );
    assert_eq!(ids(base.children(None).unwrap()), vec![id]);
}

#[test]
fn note_title_is_its_first_nonempty_paragraph_or_heading() {
    let base = local_base();
    let id = base.create(note()).unwrap();
    let doc = Doc::new();
    let update = {
        let mut txn = doc.transact_mut();
        let body = txn.get_or_insert_xml_fragment("default");
        body.push_back(&mut txn, XmlElementPrelim::empty("paragraph"));
        body.push_back(
            &mut txn,
            XmlElementPrelim::new("heading", [XmlTextPrelim::new("Kyoto in March").into()]),
        );
        body.push_back(
            &mut txn,
            XmlElementPrelim::new("paragraph", [XmlTextPrelim::new("…").into()]),
        );
        txn.encode_update_v1()
    };
    let opened = base.note(id).unwrap();
    opened.apply(11, &update).unwrap();
    assert_eq!(opened.title(), "Kyoto in March");
    assert_eq!(opened.text(), "Kyoto in March\n…");
    assert_eq!(base.get(id).unwrap().unwrap().title, "Kyoto in March");
}

#[test]
fn a_note_open_twice_is_one_document() {
    let base = local_base();
    let id = base.create(note()).unwrap();
    let (w1, w2) = (base.note(id).unwrap(), base.note(id).unwrap());
    let mut rx = w2.subscribe();
    w1.apply(11, &insert_text("hi")).unwrap();
    assert_eq!(rx.try_recv().unwrap().origin, 11);
    assert_eq!(w2.text(), "hi");
    assert_eq!(w1.id(), id);
    // The edit is stored with its update in the outbox.
    drop((w1, w2));
    assert_eq!(base.note(id).unwrap().text(), "hi");
    assert_eq!(base.get(id).unwrap().unwrap().title, "hi");
    let outbox = base.test_outbox();
    assert_eq!(outbox.iter().filter(|(o, _)| *o == id).count(), 2);
}

#[test]
fn an_edit_whose_save_failed_reaches_the_outbox_with_the_next_edit() {
    let base = local_base();
    let id = base.create(note()).unwrap();
    let opened = base.note(id).unwrap();
    base.test_fail_next_save();
    assert!(matches!(
        opened.apply(11, &append_text(&opened.state(), "one")),
        Err(Error::Storage(_))
    ));
    opened
        .apply(11, &append_text(&opened.state(), "two"))
        .unwrap();
    // Another device that gets only the outbox sees both edits.
    let other = local_base_with([8; 32]);
    for (object, update) in base.test_outbox() {
        assert_eq!(object, id);
        other.test_apply_remote(id, &update).unwrap();
    }
    assert_eq!(other.note(id).unwrap().text(), "one\ntwo");
    drop(opened);
    assert_eq!(base.note(id).unwrap().text(), "one\ntwo");
}

#[test]
fn a_remote_update_stores_unsaved_local_edits_with_their_outbox() {
    let base = local_base();
    let id = base.create(note()).unwrap();
    let opened = base.note(id).unwrap();
    base.test_fail_next_save();
    let local = append_text(&opened.state(), "local");
    assert!(opened.apply(11, &local).is_err());
    let remote = append_text(&opened.state(), "remote");
    base.test_apply_remote(id, &remote).unwrap();
    let outbox = base.test_outbox();
    assert_eq!(outbox.last().unwrap().1, local);
    drop(opened);
    assert_eq!(base.note(id).unwrap().text(), "local\nremote");
}

#[test]
fn an_update_over_8_mib_is_refused_locally() {
    let base = local_base();
    let id = base.create(note()).unwrap();
    let before = base.test_outbox().len();
    let big = insert_text(&"a".repeat(9 << 20));
    assert!(matches!(
        base.note(id).unwrap().apply(11, &big),
        Err(Error::TooLarge)
    ));
    assert!(matches!(
        base.set_fields(id, fields(json!({ "big": "a".repeat(9 << 20) }))),
        Err(Error::TooLarge)
    ));
    assert_eq!(base.test_outbox().len(), before);
    assert_eq!(base.note(id).unwrap().text(), "");
}

#[test]
fn deleted_objects_leave_children_and_appear_in_trash() {
    let base = local_base();
    let f = base.create(folder("Trips")).unwrap();
    let n = base.create(note_in(f)).unwrap();
    base.delete(n).unwrap();
    assert!(base.children(Some(f)).unwrap().is_empty());
    assert_eq!(ids(base.trash().unwrap()), vec![n]);
    assert!(base.get(n).unwrap().unwrap().deleted);
    base.undelete(n).unwrap();
    assert_eq!(ids(base.children(Some(f)).unwrap()), vec![n]);
    assert!(base.trash().unwrap().is_empty());
    assert!(matches!(
        base.delete(ObjectId::random()),
        Err(Error::NotFound)
    ));
}

#[test]
fn store_files_are_unreadable_without_their_key() {
    let base = local_base();
    let marker = "Plaintext ferry marker";
    let f = base.create(folder(marker)).unwrap();
    let n = base.create(note_in(f)).unwrap();
    base.note(n)
        .unwrap()
        .apply(11, &insert_text(marker))
        .unwrap();
    let LocalBase { base, dir } = base;
    drop(base);
    let files = files_under(dir.path());
    assert!(!files.is_empty());
    for bytes in files {
        assert!(!bytes.windows(marker.len()).any(|w| w == marker.as_bytes()));
        assert!(!bytes.starts_with(b"SQLite format 3"));
    }
    let path = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "sqlite"))
        .unwrap();
    let raw = rusqlite::Connection::open(&path).unwrap();
    assert!(
        raw.query_row("SELECT count(*) FROM sqlite_master", [], |r| r
            .get::<_, i64>(0))
            .is_err()
    );
    // The right key opens it again.
    let reopened = Base::open_local(dir.path(), [7; 32]).unwrap();
    assert_eq!(reopened.get(f).unwrap().unwrap().title, marker);
}
