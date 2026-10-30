//! Granting an app one folder: the folder becomes a base underneath, shown in
//! place on full devices. Against the local Worker.

use bh_core::{
    Account, AccountEvent, AppRequest, Base, BaseGrantRequest, BaseId, Error, FileStatus, Mode,
    Mount, NewFile, NewObject, ObjectId, TypeRef,
};
use bh_testkit::{device, new_signup, note_with_text, two_devices, wait_for, wait_for_base};
use serde_json::{Value, json};
use std::time::Duration;
use zeroize::Zeroizing;

struct Setup {
    full: Account,
    personal: Base,
    outside: ObjectId,
    folder: ObjectId,
    inside: ObjectId,
    file: ObjectId,
}

/// A full device whose Personal base holds a note "Outside" and a folder
/// "Health" with a note "Inside" and a file.
async fn setup_on(full: Account) -> Setup {
    let personal = full.create_base("Personal").await.unwrap();
    let outside = note_with_text(&personal, "Outside");
    let folder = folder_in(&personal, None, "Health");
    let inside = note_in(&personal, folder, "Inside");
    let file = personal
        .add_file(
            NewFile {
                parent: Some(folder),
                name: "scan.pdf".into(),
                mime: "application/pdf".into(),
            },
            b"pdf bytes",
        )
        .unwrap();
    Setup {
        full,
        personal,
        outside,
        folder,
        inside,
        file,
    }
}

async fn setup() -> Setup {
    setup_on(device("laptop").sign_up(new_signup()).await.unwrap().0).await
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

fn folder_in(base: &Base, parent: Option<ObjectId>, name: &str) -> ObjectId {
    base.create(object("core.folder", parent, json!({ "name": name })))
        .unwrap()
}

fn note_in(base: &Base, parent: ObjectId, text: &str) -> ObjectId {
    let id = note_with_text(base, text);
    base.move_to(id, Some(parent), None).unwrap();
    id
}

fn folder_grant(base: &Base, folder: ObjectId, mode: Mode) -> BaseGrantRequest {
    BaseGrantRequest::Folder {
        base: base.id(),
        folder,
        mode,
    }
}

/// Connects and installs an app with `bases`, returning its device.
async fn connect(full: &Account, name: &str, bases: Vec<BaseGrantRequest>) -> Account {
    let credentials = full
        .connect_app(AppRequest {
            app_name: name.into(),
            app_id: Some(format!("dev:{}", name.to_lowercase().replace(' ', "-"))),
            bases,
            replaces: None,
        })
        .await
        .unwrap();
    device(name).install_app(credentials).await.unwrap()
}

fn ids(account: &Account) -> Vec<BaseId> {
    account.bases().iter().map(|base| base.id).collect()
}

async fn base_epoch(account: &Account, base: BaseId) -> u64 {
    let server = bh_testkit::LocalServer::from_env();
    let response: Value = reqwest::Client::new()
        .get(server.url().join(&format!("/v1/bases/{base}/key")).unwrap())
        .header("BH-Protocol", "2")
        .header("BH-Test-Bypass", server.operator_token())
        .bearer_auth(bh_testkit::raw_device(account).token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    response["epoch"].as_u64().unwrap()
}

fn live(base: &Base, id: ObjectId) -> bool {
    base.get(id).ok().flatten().is_some_and(|s| !s.deleted)
}

fn listed(base: &Base, parent: Option<ObjectId>) -> Vec<ObjectId> {
    base.children(parent)
        .map(|list| list.into_iter().map(|s| s.id).collect())
        .unwrap_or_default()
}

#[tokio::test]
async fn an_app_granted_a_folder_sees_only_that_folder() {
    let s = setup().await;
    let app = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadWrite)],
    )
    .await;
    let bases = app.bases();
    assert_eq!(bases.len(), 1);
    assert_eq!(bases[0].mode, Mode::ReadWrite);
    // The granting device has no handle to this base after connect returns.
    let health = app.base(bases[0].id).unwrap();
    wait_for_base(&health, || {
        health.name() == "Health"
            && live(&health, s.inside)
            && health
                .file(s.file)
                .ok()
                .flatten()
                .is_some_and(|f| f.status == FileStatus::Remote)
    })
    .await;
    assert_eq!(health.note(s.inside).unwrap().text(), "Inside");
    assert_eq!(health.file_bytes(s.file).await.unwrap(), b"pdf bytes");
    assert_eq!(app.base(s.personal.id()).unwrap_err(), Error::NotFound);
    assert_eq!(health.get(s.outside).unwrap(), None);
    assert!(app.bases().iter().all(|b| b.name == "Health"));
}

#[tokio::test]
async fn the_folder_stays_in_place_on_full_devices() {
    let s = setup().await;
    let app = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadOnly)],
    )
    .await;
    let health = app.bases()[0].id;
    let mount = Mount {
        base: health,
        parent: s.personal.id(),
        folder: s.folder,
    };
    assert_eq!(s.full.mounts(), vec![mount]);
    let summary = s.full.bases().into_iter().find(|b| b.id == health).unwrap();
    assert_eq!(
        (summary.name.as_str(), summary.mount),
        ("Health", Some(mount))
    );
    assert!(live(&s.personal, s.folder));
    assert_eq!(listed(&s.personal, None), [s.outside, s.folder]);
    assert!(listed(&s.personal, Some(s.folder)).is_empty());
    // The folder's contents now live in its base, keeping their IDs.
    let base = s.full.base(health).unwrap();
    assert_eq!(listed(&base, None), [s.inside, s.file]);
    assert!(s.personal.get(s.inside).unwrap().unwrap().deleted);
}

#[tokio::test]
async fn granting_the_same_folder_again_reuses_its_base() {
    let s = setup().await;
    let first = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadWrite)],
    )
    .await;
    let second = connect(
        &s.full,
        "Meal Planner",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadOnly)],
    )
    .await;
    assert_eq!(ids(&first), ids(&second));
    assert_eq!(s.full.mounts().len(), 1);
    assert_eq!(second.bases()[0].mode, Mode::ReadOnly);
}

#[tokio::test]
async fn granting_a_folder_again_after_an_interruption_reuses_its_base() {
    let s = setup().await;
    let notes = s.full.create_base("Notes").await.unwrap();
    let app = connect(
        &s.full,
        "Health App",
        vec![BaseGrantRequest::Existing {
            base: notes.id(),
            mode: Mode::ReadWrite,
        }],
    )
    .await;
    s.personal.flush().await.unwrap();
    // The contents reach the new base, but marking the copies left behind fails.
    s.personal.test_fail_next_save();
    let grant = || folder_grant(&s.personal, s.folder, Mode::ReadWrite);
    assert!(matches!(
        s.full.add_app_grant(app.device_id(), grant()).await,
        Err(Error::Storage(_))
    ));
    let health = s
        .full
        .add_app_grant(app.device_id(), grant())
        .await
        .unwrap();
    assert_eq!(s.full.mounts().len(), 1);
    assert_eq!(s.full.mounts()[0].base, health);
    let base = s.full.base(health).unwrap();
    assert_eq!(listed(&base, None), [s.inside, s.file]);
    assert!(s.personal.get(s.inside).unwrap().unwrap().deleted);
    app.refresh().await.unwrap();
    assert!(ids(&app).contains(&health));
}

#[tokio::test]
async fn an_app_with_the_whole_base_keeps_the_folders_contents() {
    let s = setup().await;
    let whole = connect(
        &s.full,
        "Notes App",
        vec![BaseGrantRequest::Existing {
            base: s.personal.id(),
            mode: Mode::ReadWrite,
        }],
    )
    .await;
    let narrow = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadOnly)],
    )
    .await;
    let health = ids(&narrow)[0];
    whole.refresh().await.unwrap();
    let listed_bases = ids(&whole);
    assert!(listed_bases.contains(&s.personal.id()) && listed_bases.contains(&health));
    let base = whole.base(health).unwrap();
    assert_eq!(base.mode(), Mode::ReadWrite);
    wait_for_base(&base, || live(&base, s.inside)).await;
}

#[tokio::test]
async fn a_folder_inside_a_granted_folder_gets_every_grant_above() {
    let s = setup().await;
    let x = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadOnly)],
    )
    .await;
    let health = s.full.base(ids(&x)[0]).unwrap();
    let meals = folder_in(&health, None, "Meals");
    let y = connect(
        &s.full,
        "Meal Planner",
        vec![folder_grant(&health, meals, Mode::ReadWrite)],
    )
    .await;
    let meals_base = ids(&y)[0];
    assert_ne!(meals_base, health.id());
    x.refresh().await.unwrap();
    let mut seen: Vec<_> = x.bases().into_iter().map(|b| (b.id, b.mode)).collect();
    seen.sort_by_key(|(id, _)| *id);
    let mut expected = vec![(health.id(), Mode::ReadOnly), (meals_base, Mode::ReadOnly)];
    expected.sort_by_key(|(id, _)| *id);
    assert_eq!(seen, expected);
    let only: Vec<_> = y.bases().into_iter().map(|b| (b.id, b.mode)).collect();
    assert_eq!(only, [(meals_base, Mode::ReadWrite)]);
}

#[tokio::test]
async fn interrupted_folder_removal_stays_pending_until_refresh() {
    let (full, other) = two_devices().await;
    let s = setup_on(full).await;
    let app = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadWrite)],
    )
    .await;
    let health = ids(&app)[0];
    other.refresh().await.unwrap();
    s.full.test_inject_fault(bh_core::test_support::Fault {
        method: "POST",
        path: "v1/bases/",
        lost_reply: false,
        times: 1,
    });
    s.full
        .remove_app_grant(app.device_id(), health)
        .await
        .unwrap();
    assert!(
        s.full
            .devices()
            .await
            .unwrap()
            .iter()
            .any(|d| d.id == app.device_id() && d.pending_removal)
    );
    assert!(s.full.test_app_readers(health).contains(&app.device_id()));
    other.refresh().await.unwrap();
    assert!(
        !other
            .devices()
            .await
            .unwrap()
            .iter()
            .any(|d| d.id == app.device_id() && d.pending_removal)
    );
    assert!(!other.test_app_readers(health).contains(&app.device_id()));
}

#[tokio::test]
async fn taking_a_folder_from_an_app_rekeys_that_folder() {
    let s = setup().await;
    let removed = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadWrite)],
    )
    .await;
    let health = ids(&removed)[0];
    let remaining = connect(
        &s.full,
        "Other App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadOnly)],
    )
    .await;
    let old_epoch = base_epoch(&s.full, health).await;
    s.full
        .remove_app_grant(removed.device_id(), health)
        .await
        .unwrap();
    let new_epoch = base_epoch(&s.full, health).await;
    assert!(
        new_epoch > old_epoch,
        "folder removal must re-key rather than just revoke"
    );
    let base = s.full.base(health).unwrap();
    let fresh = note_with_text(&base, "written after removal");
    base.flush().await.unwrap();
    remaining.refresh().await.unwrap();
    let on_remaining = remaining.base(health).unwrap();
    wait_for_base(&on_remaining, || on_remaining.note(fresh).is_ok()).await;
    removed.refresh().await.unwrap();
    assert!(removed.base(health).is_err());
}

#[tokio::test]
async fn removing_a_folder_grant_erases_it_from_the_app() {
    let s = setup().await;
    let app = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadWrite)],
    )
    .await;
    let health = ids(&app)[0];
    s.full
        .remove_app_grant(app.device_id(), health)
        .await
        .unwrap();
    app.refresh().await.unwrap();
    assert!(app.bases().is_empty());
    assert_eq!(s.full.mounts().len(), 1);
    assert!(live(&s.personal, s.folder));
    assert!(live(&s.full.base(health).unwrap(), s.inside));
}

#[tokio::test]
async fn deleting_a_granted_folder_keeps_access_and_restoring_brings_it_back() {
    let s = setup().await;
    let app = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadWrite)],
    )
    .await;
    let health = ids(&app)[0];
    s.personal.delete(s.folder).unwrap();
    app.refresh().await.unwrap();
    assert_eq!(ids(&app), [health]);
    let theirs = app.base(health).unwrap();
    wait_for_base(&theirs, || live(&theirs, s.inside)).await;
    s.personal.undelete(s.folder).unwrap();
    assert!(listed(&s.personal, None).contains(&s.folder));
    assert_eq!(s.full.mounts()[0].folder, s.folder);
    assert_eq!(
        listed(&s.full.base(health).unwrap(), None),
        [s.inside, s.file]
    );
}

#[tokio::test]
async fn renaming_a_granted_folder_syncs_without_reopening_its_base() {
    let s = setup().await;
    let app = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadWrite)],
    )
    .await;
    let health = ids(&app)[0];
    let theirs = app.base(health).unwrap();
    wait_for_base(&theirs, || theirs.name() == "Health").await;
    wait_for(|| !s.full.test_base_is_open(health)).await;

    // Freeze the full device's two sync workers (`WORKERS` in core.rs) during the
    // synchronous rename, so a racing send can't rescue a short-lived handle.
    let (ready, blocked) = std::sync::mpsc::channel();
    for _ in 0..2 {
        let ready = ready.clone();
        s.full.test_runtime_handle().spawn(async move {
            ready.send(std::thread::current()).unwrap();
            std::thread::park();
        });
    }
    let threads: Vec<_> = (0..2)
        .map(|_| {
            blocked
                .recv_timeout(Duration::from_secs(30))
                .expect("sync workers")
        })
        .collect();
    let renamed = s.full.rename(s.personal.id(), s.folder, "Wellbeing");
    for thread in threads {
        thread.unpark();
    }
    renamed.unwrap();
    app.refresh().await.unwrap();
    wait_for_base(&theirs, || theirs.name() == "Wellbeing").await;
}

#[tokio::test]
async fn renaming_a_granted_folder_renames_its_base() {
    let s = setup().await;
    let app = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadWrite)],
    )
    .await;
    let health = ids(&app)[0];
    s.full
        .rename(s.personal.id(), s.folder, "Wellbeing")
        .unwrap();
    assert_eq!(
        s.personal.get(s.folder).unwrap().unwrap().title,
        "Wellbeing"
    );
    app.refresh().await.unwrap();
    let theirs = app.base(health).unwrap();
    wait_for_base(&theirs, || theirs.name() == "Wellbeing").await;
    assert_eq!(s.full.base(health).unwrap().name(), "Wellbeing");
    assert_eq!(app.bases()[0].name, "Wellbeing");
    assert!(matches!(
        s.full.rename(s.personal.id(), s.outside, "Elsewhere"),
        Err(Error::Invalid(_))
    ));
}

#[tokio::test]
async fn moving_into_and_out_of_a_granted_folder_moves_between_bases() {
    let s = setup().await;
    let app = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadWrite)],
    )
    .await;
    let health = ids(&app)[0];
    let theirs = app.base(health).unwrap();
    s.full
        .move_between(s.personal.id(), s.outside, health, None)
        .await
        .unwrap();
    wait_for_base(&theirs, || live(&theirs, s.outside)).await;
    s.full
        .move_between(health, s.outside, s.personal.id(), None)
        .await
        .unwrap();
    assert!(live(&s.personal, s.outside));
    wait_for_base(&theirs, || !listed(&theirs, None).contains(&s.outside)).await;
}

#[tokio::test]
async fn moving_a_granted_folder_moves_its_mount() {
    let s = setup().await;
    let work = s.full.create_base("Work").await.unwrap();
    let worker = connect(
        &s.full,
        "Work App",
        vec![BaseGrantRequest::Existing {
            base: work.id(),
            mode: Mode::ReadOnly,
        }],
    )
    .await;
    let app = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadWrite)],
    )
    .await;
    let health = ids(&app)[0];
    s.full
        .move_between(s.personal.id(), s.folder, work.id(), None)
        .await
        .unwrap();
    assert_eq!(s.full.mounts()[0].parent, work.id());
    assert_eq!(s.full.mounts()[0].folder, s.folder);
    assert!(live(&work, s.folder));
    worker.refresh().await.unwrap();
    assert!(ids(&worker).contains(&health));
    assert_eq!(worker.base(health).unwrap().mode(), Mode::ReadOnly);
}

#[tokio::test]
async fn a_marker_in_a_moved_folder_does_not_carry_its_mount() {
    let s = setup().await;
    let work = s.full.create_base("Work").await.unwrap();
    let outer = folder_in(&s.personal, None, "Outer");
    s.personal.move_to(s.folder, Some(outer), None).unwrap();
    let app = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadWrite)],
    )
    .await;
    let health = ids(&app)[0];
    // The mount is account data; this marker is only base content.
    s.personal.test_mark_moved(s.folder, work.id()).unwrap();
    s.full
        .move_between(s.personal.id(), outer, work.id(), None)
        .await
        .unwrap();
    assert_eq!(s.full.mounts()[0].parent, s.personal.id());
    assert!(!live(&work, s.folder));
    assert!(live(&work, outer));
    assert_eq!(s.full.mounts()[0].base, health);
}

#[tokio::test]
async fn a_stale_device_refuses_to_move_a_newly_mounted_folder_into_a_hidden_base() {
    let (full, other) = two_devices().await;
    let s = setup_on(full).await;
    let hidden = s
        .full
        .create_hidden_base("Diary", Zeroizing::new("ferry lantern quartz".into()))
        .await
        .unwrap();
    s.personal.flush().await.unwrap();
    other.refresh().await.unwrap();
    let theirs = other.base(s.personal.id()).unwrap();
    wait_for_base(&theirs, || live(&theirs, s.folder)).await;
    let app = connect(
        &other,
        "Health App",
        vec![folder_grant(&theirs, s.folder, Mode::ReadWrite)],
    )
    .await;
    assert_eq!(s.full.mounts().len(), 0);
    assert_eq!(other.mounts()[0].base, ids(&app)[0]);
    assert_eq!(
        s.full
            .move_between(s.personal.id(), s.folder, hidden.id(), None)
            .await,
        Err(Error::Forbidden)
    );
    assert!(live(&s.personal, s.folder));
    assert_eq!(s.full.mounts()[0].parent, s.personal.id());
}

#[tokio::test]
async fn a_granted_folder_never_moves_into_a_hidden_base() {
    let s = setup().await;
    let outer = folder_in(&s.personal, None, "Outer");
    s.personal.move_to(s.folder, Some(outer), None).unwrap();
    connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadWrite)],
    )
    .await;
    let hidden = s
        .full
        .create_hidden_base("Diary", Zeroizing::new("ferry lantern quartz".into()))
        .await
        .unwrap();
    for item in [s.folder, outer] {
        assert_eq!(
            s.full
                .move_between(s.personal.id(), item, hidden.id(), None)
                .await,
            Err(Error::Forbidden)
        );
    }
    s.full
        .move_between(s.personal.id(), s.outside, hidden.id(), None)
        .await
        .unwrap();
    assert!(live(&hidden, s.outside));
}

#[tokio::test]
async fn a_granted_folder_cannot_move_into_itself() {
    let s = setup().await;
    let x = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadWrite)],
    )
    .await;
    let health = s.full.base(ids(&x)[0]).unwrap();
    let meals = folder_in(&health, None, "Meals");
    let y = connect(
        &s.full,
        "Meal Planner",
        vec![folder_grant(&health, meals, Mode::ReadWrite)],
    )
    .await;
    let meals_base = ids(&y)[0];
    assert!(matches!(
        s.full
            .move_between(s.personal.id(), s.folder, meals_base, None)
            .await,
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        s.full
            .move_between(s.personal.id(), s.folder, health.id(), None)
            .await,
        Err(Error::Invalid(_))
    ));
}

#[tokio::test]
async fn folders_in_hidden_bases_are_never_granted() {
    let s = setup().await;
    let app = connect(
        &s.full,
        "Health App",
        vec![BaseGrantRequest::Existing {
            base: s.personal.id(),
            mode: Mode::ReadWrite,
        }],
    )
    .await;
    let hidden = s
        .full
        .create_hidden_base("Diary", Zeroizing::new("ferry lantern quartz".into()))
        .await
        .unwrap();
    let secret = folder_in(&hidden, None, "Secret");
    assert_eq!(
        s.full
            .add_app_grant(
                app.device_id(),
                folder_grant(&hidden, secret, Mode::ReadOnly)
            )
            .await,
        Err(Error::Forbidden)
    );
    assert!(s.full.mounts().is_empty());
    // A note isn't a folder, and an unknown one isn't there.
    assert!(matches!(
        s.full
            .add_app_grant(
                app.device_id(),
                folder_grant(&s.personal, s.outside, Mode::ReadOnly)
            )
            .await,
        Err(Error::Invalid(_))
    ));
    assert_eq!(
        s.full
            .add_app_grant(
                app.device_id(),
                folder_grant(&s.personal, ObjectId::random(), Mode::ReadOnly)
            )
            .await,
        Err(Error::NotFound)
    );
}

#[tokio::test]
async fn a_second_full_device_shows_the_folder_in_place_after_refresh() {
    let (full, other) = two_devices().await;
    let s = setup_on(full).await;
    s.personal.flush().await.unwrap();
    other.refresh().await.unwrap();
    let theirs = other.base(s.personal.id()).unwrap();
    wait_for_base(&theirs, || live(&theirs, s.inside)).await;

    let app = connect(
        &s.full,
        "Health App",
        vec![folder_grant(&s.personal, s.folder, Mode::ReadWrite)],
    )
    .await;
    let health = ids(&app)[0];
    let mut events = other.events();
    other.refresh().await.unwrap();
    assert_eq!(events.try_recv().unwrap(), AccountEvent::BasesChanged);
    let summary = other.bases().into_iter().find(|b| b.id == health).unwrap();
    assert_eq!(
        summary.mount,
        Some(Mount {
            base: health,
            parent: s.personal.id(),
            folder: s.folder
        })
    );
    let base = other.base(health).unwrap();
    wait_for_base(&theirs, || listed(&theirs, Some(s.folder)).is_empty()).await;
    wait_for_base(&base, || {
        listed(&base, None) == [s.inside, s.file]
            && base.note(s.inside).is_ok_and(|n| n.text() == "Inside")
    })
    .await;
}
