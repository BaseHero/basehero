//! Deterministic, direct core-API workloads for the scale checks.
use crate::{RawDevice, b64, note, random_id};
use bh_core::{Base, BaseId, FieldDef, FieldKind, NewFile, NewObject, ObjectId, TypeDef, TypeRef};
use serde_json::{Map, Value, json};
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

/// Adds `count` different files with random content through the real file API.
/// Callers can keep the returned IDs without retaining the plaintext bodies.
pub fn files(base: &Base, parent: Option<ObjectId>, count: usize, size: usize) -> Vec<ObjectId> {
    (0..count)
        .map(|i| {
            let mut content = vec![0; size];
            getrandom::fill(&mut content).expect("random file content");
            base.add_file(
                NewFile {
                    parent,
                    name: format!("file-{i:05}.bin"),
                    mime: "application/octet-stream".into(),
                },
                &content,
            )
            .expect("add scale file")
        })
        .collect()
}

/// Posts synthetic kept states directly to the local Worker, from 2 KiB to
/// twice `mean_size`. These opaque bodies exercise server storage and listing;
/// callers needing a restorable version must also post a real sealed state.
pub async fn kept_versions(
    raw: &RawDevice,
    base: BaseId,
    object: ObjectId,
    n: usize,
    mean_size: usize,
) {
    assert!(mean_size >= 1024 && n > 0);
    let (status, reply) = raw
        .post(
            &format!("/v1/bases/{base}/fetch"),
            json!({ "objectIds": [object] }),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{reply}");
    let covers = reply["objects"][0]["head"].as_u64().expect("object head");
    assert!(covers > 0, "a kept state needs an existing object");
    let started = Instant::now();
    for first in (0..n).step_by(100) {
        let changes: Vec<Value> = (first..(first + 100).min(n))
            .map(|i| {
                let size = 2_048 + i * (2 * mean_size - 2_048) / n;
                json!({"changeId": random_id(), "objectId": object,
                    "kind": "state", "covers": covers, "keep": true,
                    "body": b64(&vec![i as u8; size])})
            })
            .collect();
        let (status, reply) = raw
            .post(
                &format!("/v1/bases/{base}/changes"),
                json!({"changes": changes}),
            )
            .await;
        assert_eq!(status, reqwest::StatusCode::OK, "{reply}");
        assert_eq!(
            reply["results"].as_array().unwrap().len(),
            (first + 100).min(n) - first
        );
        assert!(
            reply["results"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["stale"] == false)
        );
    }
    println!(
        "kept-version generator: {n} states, mean {mean_size} bytes in {:?}, load={}",
        started.elapsed(),
        std::fs::read_to_string("/proc/loadavg")
            .unwrap_or_default()
            .trim()
    );
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
