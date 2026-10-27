//! Deterministic, direct core-API workloads for the scale checks.
use crate::note;
use bh_core::{Base, FieldDef, FieldKind, NewObject, ObjectId, TypeDef, TypeRef};
use serde_json::{Map, Value};
use std::time::Instant;
use yrs::updates::decoder::Decode;
use yrs::{
    Doc, ReadTxn, StateVector, Transact, Update, WriteTxn, XmlElementPrelim, XmlFragment,
    XmlTextPrelim,
};

/// Creates notes with searchable text; every marker occurs in multiple notes.
pub fn notes(base: &Base, count: usize) -> Vec<ObjectId> {
    base.test_bulk_create((0..count).map(|i| {
        (
            note(),
            Some(crate::insert_text(&format!(
                "marker{} project meeting notes",
                i % 50
            ))),
        )
    }))
    .expect("bulk notes")
}

/// Creates a wide folder, as a normal sequence of new notes.
pub fn children(base: &Base, folder: ObjectId, count: usize) -> Vec<ObjectId> {
    base.test_bulk_create((0..count).map(|_| {
        (
            NewObject {
                ty: TypeRef::new("core.note", 1),
                parent: Some(folder),
                after: None,
                fields: Map::new(),
            },
            None,
        )
    }))
    .expect("bulk children")
}

/// Defines a record type and inserts `count` varied records through the core API.
pub fn records(base: &Base, ty: &str, count: usize) -> Vec<ObjectId> {
    base.define_type(TypeDef {
        name: ty.into(),
        version: 1,
        doc: String::new(),
        title_field: Some("name".into()),
        fields: vec![FieldDef {
            name: "name".into(),
            kind: FieldKind::Text,
            required: true,
            unit: None,
            doc: String::new(),
        }],
    })
    .expect("define record type");
    base.test_bulk_create((0..count).map(|i| {
        (
            NewObject {
                ty: TypeRef::new(ty, 1),
                parent: None,
                after: None,
                fields: Map::from_iter([("name".into(), Value::from(format!("Record {i}")))]),
            },
            None,
        )
    }))
    .expect("bulk records")
}

/// A year of independent Yjs edit sessions without replaying typing. Each
/// chronological chunk saves only the state reached so far, queues its
/// individual sessions, and syncs them before generating the next chunk.
pub async fn year_of_editing(base: &Base, count: usize, sessions: usize) -> Vec<ObjectId> {
    assert!(count > 0);
    let started = Instant::now();
    let ids = notes(base, count);
    let created = started.elapsed();
    base.flush().await.expect("sync initial notes");
    let initial_sync = started.elapsed() - created;
    base.test_preserve_sync_updates();
    let docs: Vec<Doc> = ids
        .iter()
        .map(|&id| {
            let doc = Doc::new();
            doc.transact_mut()
                .apply_update(
                    Update::decode_v1(&base.note(id).expect("note").state())
                        .expect("initial state"),
                )
                .expect("apply initial state");
            doc
        })
        .collect();
    let (mut generated, mut stored, mut synced) = (
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    for first in (0..sessions).step_by(1_000) {
        // Keep sync paused until this chunk's state and updates are committed.
        base.test_pause_sync();
        let start = Instant::now();
        let mut updates = Vec::with_capacity((sessions - first).min(1_000));
        for i in first..(first + 1_000).min(sessions) {
            // Every fiftieth session hits the hot note; the rest visit all notes.
            let index = if i % 50 == 0 { 0 } else { (i * 131) % count };
            let words = if i % 10 == 0 {
                180 + i % 21
            } else {
                3 + i % 15
            };
            let mut txn = docs[index].transact_mut();
            let before: StateVector = txn.state_vector();
            txn.get_or_insert_xml_fragment("default").push_back(
                &mut txn,
                XmlElementPrelim::new(
                    "paragraph",
                    [XmlTextPrelim::new("edited ".repeat(words)).into()],
                ),
            );
            updates.push((ids[index], txn.encode_state_as_update_v1(&before)));
        }
        generated += start.elapsed();
        let start = Instant::now();
        base.test_bulk_apply(&updates)
            .expect("queue editing history");
        stored += start.elapsed();
        base.test_resume_sync();
        let start = Instant::now();
        base.flush().await.expect("sync editing history");
        synced += start.elapsed();
    }
    println!(
        "history generator: create={created:?}, initial-sync={initial_sync:?}, Yjs={generated:?}, local-store={stored:?}, network+compaction={synced:?}, load={}",
        std::fs::read_to_string("/proc/loadavg")
            .unwrap_or_default()
            .trim()
    );
    ids
}
