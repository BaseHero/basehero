//! Granted folders shown in place on full devices: the tree, the trash, export,
//! links and history follow a folder's contents into its base. Against the
//! local Worker.

use bh_core::{
    Account, AppRequest, Base, BaseGrantRequest, BaseId, Clock, Core, Error, Mode, NewFile,
    NewObject, ObjectId, TreeItem, TypeRef,
};
use bh_testkit::{device, device_with_clock, new_signup, note_with_text, wait_for_base};
use serde_json::json;
use std::path::Path;
use std::time::Duration;

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
async fn setup_on(core: Core) -> Setup {
    let full = core.sign_up(new_signup()).await.unwrap().0;
    let personal = full.create_base("Personal").await.unwrap();
    let outside = note_with_text(&personal, "Outside");
    let folder = personal
        .create(NewObject {
            ty: TypeRef::new("core.folder", 1),
            parent: None,
            after: None,
            fields: json!({ "name": "Health" }).as_object().unwrap().clone(),
        })
        .unwrap();
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
    setup_on(device("laptop")).await
}

fn note_in(base: &Base, parent: ObjectId, text: &str) -> ObjectId {
    let id = note_with_text(base, text);
    base.move_to(id, Some(parent), None).unwrap();
    id
}

/// Grants the folder to a new app "Health App", returning the app's device
/// and the folder's base.
async fn grant(s: &Setup) -> (Account, BaseId) {
    let credentials = s
        .full
        .connect_app(AppRequest {
            app_name: "Health App".into(),
            app_id: Some("dev:health-app".into()),
            bases: vec![BaseGrantRequest::Folder {
                base: s.personal.id(),
                folder: s.folder,
                mode: Mode::ReadWrite,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = device("Health App").install_app(credentials).await.unwrap();
    let health = app.bases()[0].id;
    (app, health)
}

fn rows(items: &[TreeItem]) -> Vec<(ObjectId, BaseId)> {
    items
        .iter()
        .map(|item| (item.summary.id, item.base))
        .collect()
}

/// Every path under `dir`, sorted, with `/` separators.
fn listing(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(at) = pending.pop() {
        for entry in std::fs::read_dir(&at).unwrap() {
            let path = entry.unwrap().path();
            let relative = path.strip_prefix(dir).unwrap();
            out.push(relative.to_string_lossy().replace('\\', "/"));
            if path.is_dir() {
                pending.push(path);
            }
        }
    }
    out.sort();
    out
}

#[tokio::test]
async fn the_tree_shows_mounted_contents_under_the_folder() {
    let s = setup().await;
    let (_app, health) = grant(&s).await;
    let personal = s.personal.id();
    let top = s.full.tree_children(personal, None).unwrap();
    assert_eq!(rows(&top), [(s.outside, personal), (s.folder, personal)]);
    assert_eq!((top[0].mounted, top[0].readers.len()), (None, 0));
    assert_eq!(top[1].mounted, Some(health));
    assert_eq!(top[1].readers, ["Health App"]);
    // An older build still writes into the folder in Personal.
    let older = note_in(&s.personal, s.folder, "Older");
    let inside = s.full.tree_children(personal, Some(s.folder)).unwrap();
    assert_eq!(
        rows(&inside),
        [(older, personal), (s.inside, health), (s.file, health)]
    );
    assert!(inside.iter().all(|item| item.mounted.is_none()));
}

#[tokio::test]
async fn the_trash_of_a_base_includes_its_mounted_folders() {
    let s = setup().await;
    let (_app, health) = grant(&s).await;
    s.full.base(health).unwrap().delete(s.inside).unwrap();
    let trash = s.full.trash(s.personal.id()).unwrap();
    assert_eq!(rows(&trash), [(s.inside, health)]);
}

#[tokio::test]
async fn export_writes_mounted_folders_in_place() {
    let s = setup().await;
    let (_app, _health) = grant(&s).await;
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("copy");
    let summary = s.full.export(s.personal.id(), &out).await.unwrap();
    assert_eq!((summary.notes, summary.files), (2, 1));
    let paths = listing(&out);
    for path in [
        "notes/Outside.md",
        "notes/Health/Inside.md",
        "notes/Health/scan.pdf",
    ] {
        assert!(paths.iter().any(|p| p == path), "{path} in {paths:?}");
    }
    assert!(!paths.iter().any(|p| p.starts_with("trash")), "{paths:?}");
    assert_eq!(
        std::fs::read(out.join("notes/Health/scan.pdf")).unwrap(),
        b"pdf bytes"
    );
}

#[tokio::test]
async fn a_link_to_a_moved_note_leads_on() {
    let s = setup().await;
    let (_app, health) = grant(&s).await;
    let personal = s.personal.id();
    assert_eq!(s.full.locate(personal, s.inside), Ok(health));
    assert_eq!(s.full.locate(personal, s.outside), Ok(personal));
    let work = s.full.create_base("Work").await.unwrap();
    s.full
        .move_between(health, s.inside, work.id(), None)
        .await
        .unwrap();
    assert_eq!(s.full.locate(personal, s.inside), Ok(work.id()));
    assert_eq!(
        s.full.locate(personal, ObjectId::random()),
        Err(Error::NotFound)
    );
}

#[tokio::test]
async fn a_moved_notes_earlier_versions_stay_in_the_old_base() {
    let (clock, manual) = Clock::manual();
    let s = setup_on(device_with_clock("laptop", &clock)).await;
    s.personal.flush().await.unwrap();
    manual.advance(Duration::from_secs(6 * 60));
    s.personal.tick_versions().await.unwrap();
    let (kept, _) = s.personal.versions(s.inside, None, 50).await.unwrap();
    assert!(!kept.is_empty());
    let (_app, health) = grant(&s).await;
    assert_eq!(s.full.moved_from(health, s.inside), Some(s.personal.id()));
    assert_eq!(s.full.moved_from(s.personal.id(), s.inside), None);
    assert_eq!(s.full.moved_from(health, s.outside), None);
    let (old, _) = s.personal.versions(s.inside, None, 50).await.unwrap();
    assert!(kept.iter().all(|v| old.contains(v)), "{old:?}");
    let base = s.full.base(health).unwrap();
    let (new, _) = base.versions(s.inside, None, 50).await.unwrap();
    assert!(new.is_empty(), "{new:?}");
}

#[tokio::test]
async fn app_devices_see_granted_folders_as_bases() {
    let s = setup().await;
    let (app, health) = grant(&s).await;
    let theirs = app.base(health).unwrap();
    wait_for_base(&theirs, || {
        theirs.children(None).is_ok_and(|list| list.len() == 2)
    })
    .await;
    let items = app.tree_children(health, None).unwrap();
    assert_eq!(rows(&items), [(s.inside, health), (s.file, health)]);
    assert!(
        items
            .iter()
            .all(|item| item.mounted.is_none() && item.readers.is_empty())
    );
    assert!(app.mounts().is_empty());
}
