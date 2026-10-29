//! Moving items between bases, against the local Worker.

use bh_core::{
    Account, AppRequest, Base, BaseGrantRequest, Error, FieldDef, FieldKind, FileStatus, Mode,
    NewFile, NewObject, ObjectId, ObjectSummary, TypeDef, TypeRef,
};
use bh_testkit::{
    append_text, device, insert_text, new_signup, note_with_text, two_devices, wait_for,
    wait_for_base,
};
use serde_json::{Value, json};
use std::sync::atomic::Ordering;

struct Setup {
    full: Account,
    personal: Base,
    work: Base,
}

async fn setup() -> Setup {
    let full = device("laptop").sign_up(new_signup()).await.unwrap().0;
    let personal = full.create_base("Personal").await.unwrap();
    let work = full.create_base("Work").await.unwrap();
    Setup {
        full,
        personal,
        work,
    }
}

fn object(ty: &str, parent: Option<ObjectId>, fields: Value) -> NewObject {
    let Value::Object(fields) = fields else {
        panic!("fields must be an object")
    };
    NewObject {
        ty: TypeRef::new(ty, 1),
        parent,
        after: None,
        fields,
    }
}

fn folder(base: &Base, name: &str) -> ObjectId {
    base.create(object("core.folder", None, json!({ "name": name })))
        .unwrap()
}

fn note_in(base: &Base, parent: ObjectId, text: &str) -> ObjectId {
    let id = base
        .create(object("core.note", Some(parent), json!({})))
        .unwrap();
    base.note(id).unwrap().apply(5, &insert_text(text)).unwrap();
    id
}

fn pdf(parent: ObjectId) -> NewFile {
    NewFile {
        parent: Some(parent),
        name: "ticket.pdf".into(),
        mime: "application/pdf".into(),
    }
}

fn trip_type() -> TypeDef {
    let field = |name: &str, kind| FieldDef {
        name: name.into(),
        kind,
        required: false,
        unit: None,
        doc: String::new(),
    };
    TypeDef {
        name: "demo.trip".into(),
        version: 1,
        doc: "A trip".into(),
        title_field: Some("title".into()),
        fields: vec![
            field("start", FieldKind::Date),
            field("title", FieldKind::Text),
        ],
    }
}

fn ids(summaries: Vec<ObjectSummary>) -> Vec<ObjectId> {
    summaries.into_iter().map(|s| s.id).collect()
}

fn live(base: &Base, id: ObjectId) -> bool {
    base.get(id).ok().flatten().is_some_and(|s| !s.deleted)
}

#[tokio::test]
async fn a_note_moves_to_another_base_with_its_id_and_content() {
    let (full, other) = two_devices().await;
    let personal = full.create_base("Personal").await.unwrap();
    let work = full.create_base("Work").await.unwrap();
    let note = note_with_text(&personal, "ferry");
    full.move_between(personal.id(), note, work.id(), None)
        .await
        .unwrap();
    assert!(live(&work, note));
    assert_eq!(work.note(note).unwrap().text(), "ferry");
    assert_eq!(ids(work.children(None).unwrap()), [note]);
    assert!(personal.get(note).unwrap().unwrap().deleted);
    // The marker left behind doesn't move again, and a base isn't moved into itself.
    assert_eq!(
        full.move_between(personal.id(), note, work.id(), None)
            .await,
        Err(Error::NotFound)
    );
    assert!(matches!(
        full.move_between(work.id(), note, work.id(), None).await,
        Err(Error::Invalid(_))
    ));

    other.refresh().await.unwrap();
    let (personal, work) = (
        other.base(personal.id()).unwrap(),
        other.base(work.id()).unwrap(),
    );
    wait_for_base(&work, || {
        live(&work, note) && work.note(note).is_ok_and(|n| n.text() == "ferry")
    })
    .await;
    wait_for_base(&personal, || {
        personal.get(note).ok().flatten().is_some_and(|s| s.deleted)
    })
    .await;
}

#[tokio::test]
async fn its_children_files_and_record_types_move_with_it() {
    let Setup {
        full,
        personal,
        work,
    } = setup().await;
    let trips = folder(&personal, "Trips");
    let child = note_in(&personal, trips, "ferry");
    let file = personal.add_file(pdf(trips), b"pdf bytes").unwrap();
    personal.define_type(trip_type()).unwrap();
    let trip = personal
        .create(object(
            "demo.trip",
            Some(trips),
            json!({ "start": "2026-11-01", "title": "Ferry to Skye" }),
        ))
        .unwrap();
    let fields = personal.get(trip).unwrap().unwrap().fields;
    full.move_between(personal.id(), trips, work.id(), None)
        .await
        .unwrap();
    assert!(
        work.types()
            .unwrap()
            .iter()
            .any(|d| d.name == "demo.trip" && d.version == 1)
    );
    assert_eq!(work.file_bytes(file).await.unwrap(), b"pdf bytes");
    let moved = work.get(trip).unwrap().unwrap();
    assert_eq!(
        (moved.fields, moved.title.as_str()),
        (fields, "Ferry to Skye")
    );
    assert_eq!(work.get(child).unwrap().unwrap().parent, Some(trips));
    assert_eq!(ids(work.children(None).unwrap()), [trips]);
    assert_eq!(ids(work.children(Some(trips)).unwrap()).len(), 3);
    for id in [trips, child, file, trip] {
        assert!(personal.get(id).unwrap().unwrap().deleted);
    }
    // The moved file is uploaded again, sealed for its new base.
    wait_for_base(&work, || {
        work.file(file).unwrap().unwrap().status == FileStatus::Here
            && work.get(file).unwrap().unwrap().fields.get("uploaded") == Some(&json!(true))
    })
    .await;
}

#[tokio::test]
async fn the_old_copy_is_a_marker_out_of_the_tree_trash_and_search() {
    let Setup {
        full,
        personal,
        work,
    } = setup().await;
    let trips = folder(&personal, "Trips");
    let kept = note_in(&personal, trips, "ferry times");
    let thrown = note_in(&personal, trips, "old ferry times");
    personal.delete(thrown).unwrap();
    full.move_between(personal.id(), trips, work.id(), None)
        .await
        .unwrap();
    assert!(personal.children(None).unwrap().is_empty());
    assert!(personal.trash().unwrap().is_empty());
    assert!(personal.search("ferry", 10).unwrap().is_empty());
    assert_eq!(ids(work.trash().unwrap()), [thrown]);
    let found: Vec<_> = work
        .search("ferry", 10)
        .unwrap()
        .into_iter()
        .map(|hit| hit.id)
        .collect();
    assert_eq!(found, [kept]);
}

#[tokio::test]
async fn a_move_that_stopped_midway_finishes_on_refresh() {
    let Setup {
        full,
        personal,
        work,
    } = setup().await;
    let note = note_with_text(&personal, "ferry");
    personal.flush().await.unwrap();
    // The note reaches Work, but marking the copy left behind fails.
    personal.test_fail_next_save();
    assert!(matches!(
        full.move_between(personal.id(), note, work.id(), None)
            .await,
        Err(Error::Storage(_))
    ));
    full.refresh().await.unwrap();
    assert_eq!(ids(work.children(None).unwrap()), [note]);
    assert_eq!(work.note(note).unwrap().text(), "ferry");
    assert!(personal.get(note).unwrap().unwrap().deleted);
    assert!(personal.children(None).unwrap().is_empty());
}

#[tokio::test]
async fn moving_an_item_back_revives_its_old_copy() {
    let Setup {
        full,
        personal,
        work,
    } = setup().await;
    let note = note_with_text(&personal, "ferry");
    full.move_between(personal.id(), note, work.id(), None)
        .await
        .unwrap();
    let doc = work.note(note).unwrap();
    doc.apply(5, &append_text(&doc.state(), "and back"))
        .unwrap();
    full.move_between(work.id(), note, personal.id(), None)
        .await
        .unwrap();
    assert!(live(&personal, note));
    assert_eq!(personal.note(note).unwrap().text(), "ferry\nand back");
    assert_eq!(ids(personal.children(None).unwrap()), [note]);
    assert!(work.get(note).unwrap().unwrap().deleted);
    assert!(work.children(None).unwrap().is_empty());
}

#[tokio::test]
async fn a_file_not_yet_downloaded_moves_with_its_content() {
    let (full, other) = two_devices().await;
    let personal = full.create_base("Personal").await.unwrap();
    let work = full.create_base("Work").await.unwrap();
    personal.flush().await.unwrap();
    work.flush().await.unwrap();
    other.refresh().await.unwrap();
    let theirs = other.base(personal.id()).unwrap();
    let _work = other.base(work.id()).unwrap();
    // The other device never downloads the file in the background.
    let held = theirs.test_hold_file_gets();
    let scans = folder(&personal, "Scans");
    let content: Vec<u8> = (0..5 << 20).map(|i| (i % 251) as u8).collect();
    let file = personal.add_file(pdf(scans), &content).unwrap();
    wait_for_base(&personal, || {
        personal.file(file).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    personal.flush().await.unwrap();
    wait_for(|| held.load(Ordering::SeqCst)).await;
    assert!(matches!(
        theirs.file(file).unwrap().unwrap().status,
        FileStatus::Fetching { done: 0, .. }
    ));
    wait_for_base(&theirs, || live(&theirs, scans)).await;

    other
        .move_between(personal.id(), scans, work.id(), None)
        .await
        .unwrap();
    wait_for_base(&work, || {
        work.file(file)
            .ok()
            .flatten()
            .is_some_and(|f| f.status == FileStatus::Here)
    })
    .await;
    assert!(work.file_bytes(file).await.unwrap() == content);
    assert_eq!(work.get(file).unwrap().unwrap().parent, Some(scans));
}

#[tokio::test]
async fn a_move_waits_for_file_upload_before_its_device_closes() {
    let (full, other) = two_devices().await;
    let personal = full.create_base("Personal").await.unwrap();
    let work = full.create_base("Work").await.unwrap();
    let (personal_id, work_id) = (personal.id(), work.id());
    personal.flush().await.unwrap();
    work.flush().await.unwrap();
    other.refresh().await.unwrap();
    let remote = other.base(work_id).unwrap();

    let scans = folder(&personal, "Scans");
    let bytes = vec![37; 5 << 20];
    let file = personal.add_file(pdf(scans), &bytes).unwrap();
    wait_for_base(&personal, || {
        personal.file(file).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    // The destination's uploader is the only route for these newly sealed parts.
    work.pause_files();
    let moving = tokio::spawn({
        let full = full.clone();
        async move { full.move_between(personal_id, scans, work_id, None).await }
    });
    wait_for_base(&remote, || remote.file(file).ok().flatten().is_some()).await;
    assert!(
        !moving.is_finished(),
        "move returned while the target's file parts were queued"
    );
    work.resume_files();
    tokio::time::timeout(std::time::Duration::from_secs(30), moving)
        .await
        .expect("move must finish after upload resumes")
        .unwrap()
        .unwrap();
    drop(work);
    drop(personal);
    drop(full);
    wait_for_base(&remote, || {
        remote
            .file(file)
            .ok()
            .flatten()
            .is_some_and(|f| f.status == FileStatus::Here)
    })
    .await;
    assert_eq!(remote.file_bytes(file).await.unwrap(), bytes);
}

#[tokio::test]
async fn upload_completion_between_queue_check_and_wait_does_not_stall_move() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let Setup {
            full,
            personal,
            work,
        } = setup().await;
        let scans = folder(&personal, "Scans");
        let file = personal.add_file(pdf(scans), b"pdf bytes").unwrap();
        wait_for_base(&personal, || {
            personal.get(file).unwrap().unwrap().fields.get("uploaded") == Some(&json!(true))
        })
        .await;
        work.pause_files();
        let idle = work.test_uploader_idle();
        let entered = work.test_hold_next_upload_wait();
        let moving = tokio::spawn({
            let full = full.clone();
            let from = personal.id();
            let to = work.id();
            async move { full.move_between(from, scans, to, None).await }
        });
        wait_for(|| entered.load(Ordering::SeqCst)).await;
        work.resume_files();
        wait_for_base(&work, || {
            work.get(file).unwrap().unwrap().fields.get("uploaded") == Some(&json!(true))
        })
        .await;
        // Wait for its final empty-queue progress, not just the uploaded field.
        wait_for(|| idle.load(Ordering::SeqCst)).await;
        work.test_resume_upload_wait();
        moving.await.unwrap().unwrap();
    })
    .await
    .expect("move must finish after the last upload");
}

#[tokio::test]
async fn a_failed_file_upload_leaves_the_move_to_resume() {
    let (full, other) = two_devices().await;
    let personal = full.create_base("Personal").await.unwrap();
    let work = full.create_base("Work").await.unwrap();
    let (personal_id, work_id) = (personal.id(), work.id());
    personal.flush().await.unwrap();
    work.flush().await.unwrap();
    other.refresh().await.unwrap();
    let remote = other.base(work_id).unwrap();
    let scans = folder(&personal, "Scans");
    let file = personal.add_file(pdf(scans), b"pdf bytes").unwrap();
    wait_for_base(&personal, || {
        personal.file(file).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    work.pause_files();
    let moving = tokio::spawn({
        let full = full.clone();
        async move { full.move_between(personal_id, scans, work_id, None).await }
    });
    wait_for_base(&remote, || remote.file(file).ok().flatten().is_some()).await;
    // The first PUT succeeds at the server, but its reply is lost.
    work.fail_file_put_after(0);
    work.resume_files();
    let result = tokio::time::timeout(std::time::Duration::from_secs(30), moving)
        .await
        .expect("upload failure must return")
        .unwrap();
    assert!(matches!(result, Err(Error::Network(_))), "{result:?}");
    wait_for_base(&work, || {
        work.file(file)
            .ok()
            .flatten()
            .is_some_and(|f| f.status == FileStatus::Here)
    })
    .await;
    full.refresh().await.unwrap();
    // Retrying an acknowledged part resends the same ciphertext; no third PUT.
    assert_eq!(
        full.test_request_count(&format!("v1/bases/{work_id}/files/{file}/0")),
        2
    );
    drop(work);
    drop(personal);
    drop(full);
    wait_for_base(&remote, || {
        remote
            .file(file)
            .ok()
            .flatten()
            .is_some_and(|f| f.status == FileStatus::Here)
    })
    .await;
    assert_eq!(remote.file_bytes(file).await.unwrap(), b"pdf bytes");
}

#[tokio::test]
async fn app_devices_cannot_move_between_bases() {
    let Setup {
        full,
        personal,
        work,
    } = setup().await;
    let bases = [&personal, &work]
        .map(|base| BaseGrantRequest::Existing {
            base: base.id(),
            mode: Mode::ReadWrite,
        })
        .to_vec();
    let credentials = full
        .connect_app(AppRequest {
            app_name: "Demo Health App".into(),
            app_id: Some("dev:health".into()),
            bases,
            replaces: None,
        })
        .await
        .unwrap();
    let app = device("app").install_app(credentials).await.unwrap();
    let note = note_with_text(&app.base(personal.id()).unwrap(), "ferry");
    assert_eq!(
        app.move_between(personal.id(), note, work.id(), None).await,
        Err(Error::Forbidden)
    );
}
