//! Rebuilding backed-up content as new bases in a full account.
use bh_core::{
    Account, BackupLocation, BaseId, Clock, Core, Error, FileStatus, NewObject, TypeRef,
    list_backups,
};
use bh_testkit::{
    LocalServer, TEST_PASSWORD,
    backup::{Fixture, everything, normalized_export},
    device, device_on_server,
    folder::MemoryFolder,
    invite, new_signup, note_with_text, signin_for, wait_for_base,
};
use serde_json::{Map, json};
use std::sync::Arc;
use zeroize::Zeroizing;

async fn prepared() -> (Core, Fixture, Arc<MemoryFolder>, bh_core::OpenedBackup, i64) {
    let core = device("backup source");
    let fixture = everything(&core).await;
    let folder = Arc::new(MemoryFolder::default());
    core.set_document_folders(folder.clone());
    fixture
        .account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .unwrap();
    fixture.account.backup_now().await.unwrap();
    let listing = list_backups(&*folder).unwrap().remove(0);
    let opened = core
        .open_backup(
            folder.clone(),
            &listing,
            Zeroizing::new(TEST_PASSWORD.into()),
            &fixture.kit.display(),
        )
        .await
        .unwrap();
    let at = opened.points()[0];
    (core, fixture, folder, opened, at)
}

fn personal(account: &Account) -> BaseId {
    account
        .bases()
        .into_iter()
        .find(|b| b.name == "Personal")
        .unwrap()
        .id
}

#[tokio::test]
async fn restoring_a_base_into_this_account_makes_a_new_base_with_the_same_content() {
    let (_core, fixture, folder, opened, at) = prepared().await;
    let original = personal(&fixture.account);
    let before = folder.files();
    let original_out = tempfile::tempdir().unwrap();
    fixture
        .account
        .base(original)
        .unwrap()
        .export(original_out.path().join("original").as_path())
        .await
        .unwrap();
    let result = opened
        .restore_into(&fixture.account, at, &[original], "restored 29 Oct")
        .await
        .unwrap();
    let new = result
        .restored
        .iter()
        .find(|(old, _)| *old == original)
        .unwrap()
        .1;
    assert_ne!(new, original);
    assert_eq!(
        fixture.account.base(new).unwrap().name(),
        "Personal (restored 29 Oct)"
    );
    assert_eq!(fixture.account.base(original).unwrap().name(), "Personal");
    let restored_out = tempfile::tempdir().unwrap();
    fixture
        .account
        .base(new)
        .unwrap()
        .export(restored_out.path().join("restored").as_path())
        .await
        .unwrap();
    let left = normalized_export(&original_out.path().join("original"), true);
    let right = normalized_export(&restored_out.path().join("restored"), true);
    let changed: Vec<_> = left
        .keys()
        .chain(right.keys())
        .filter(|p| left.get(*p) != right.get(*p))
        .collect();
    assert!(changed.is_empty(), "different paths: {changed:?}");
    assert_eq!(folder.files(), before);
    fixture
        .account
        .base(original)
        .unwrap()
        .export(original_out.path().join("after").as_path())
        .await
        .unwrap();
    assert_eq!(
        normalized_export(&original_out.path().join("original"), false),
        normalized_export(&original_out.path().join("after"), false)
    );
    assert_eq!(result.locked, 1);
    let check = opened.check(at).await.unwrap();
    assert_eq!(
        result.unreadable,
        check
            .bases
            .iter()
            .map(|base| base.unreadable)
            .sum::<usize>()
    );
    assert_eq!(result.ignored_files, check.ignored_files);
    assert!(result.missing_files.is_empty());
}

#[tokio::test]
async fn links_between_restored_objects_keep_working() {
    let core = device("linked notes");
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    let target = note_with_text(&base, "Target");
    let linked = note_with_text(&base, &format!("bh://notes/{target}"));
    let folder = Arc::new(MemoryFolder::default());
    core.set_document_folders(folder.clone());
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .unwrap();
    account.backup_now().await.unwrap();
    let listing = list_backups(&*folder).unwrap().remove(0);
    let opened = core
        .open_backup(
            folder,
            &listing,
            Zeroizing::new(TEST_PASSWORD.into()),
            &kit.display(),
        )
        .await
        .unwrap();
    let restored = opened
        .restore_into(
            &account,
            opened.points()[0],
            &[base.id()],
            "restored 29 Oct",
        )
        .await
        .unwrap()
        .restored[0]
        .1;
    let new = account.base(restored).unwrap();
    assert_eq!(
        new.note(linked).unwrap().text(),
        format!("bh://notes/{target}")
    );
    assert!(new.get(target).unwrap().is_some());
}

#[tokio::test]
async fn records_keep_their_types_in_the_new_base() {
    let (_core, fixture, _folder, opened, at) = prepared().await;
    let old = personal(&fixture.account);
    let new = opened
        .restore_into(&fixture.account, at, &[old], "restored 29 Oct")
        .await
        .unwrap()
        .restored
        .into_iter()
        .find(|(id, _)| *id == old)
        .unwrap()
        .1;
    let found = fixture
        .account
        .base(new)
        .unwrap()
        .query(&bh_core::Query {
            ty: "demo.measurement".into(),
            filters: vec![],
            order_by: None,
            limit: None,
        })
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].fields["reading"], json!(6.5));
}

#[tokio::test]
async fn a_restored_base_brings_its_mounted_folders() {
    let (_core, fixture, _folder, opened, at) = prepared().await;
    let old = personal(&fixture.account);
    let old_mount = fixture
        .account
        .mounts()
        .into_iter()
        .find(|m| m.parent == old)
        .unwrap();
    let summary = opened
        .restore_into(&fixture.account, at, &[old], "restored 29 Oct")
        .await
        .unwrap();
    let parent = summary
        .restored
        .iter()
        .find(|(id, _)| *id == old)
        .unwrap()
        .1;
    let child = summary
        .restored
        .iter()
        .find(|(id, _)| *id == old_mount.base)
        .unwrap()
        .1;
    let mount = fixture
        .account
        .mounts()
        .into_iter()
        .find(|m| m.base == child)
        .unwrap();
    assert_eq!((mount.parent, mount.folder), (parent, old_mount.folder));
    assert_eq!(
        fixture.account.base(child).unwrap().name(),
        "Shared folder (restored 29 Oct)"
    );
}

#[tokio::test]
async fn move_markers_point_only_to_restored_targets() {
    let core = device("moved note");
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let from = account.create_base("Personal").await.unwrap();
    let to = account.create_base("Work").await.unwrap();
    let note = note_with_text(&from, "Moved note");
    let file = from
        .add_file(
            bh_core::NewFile {
                parent: None,
                name: "moved.txt".into(),
                mime: "text/plain".into(),
            },
            b"file moved across bases",
        )
        .unwrap();
    for object in [note, file] {
        account
            .move_between(from.id(), object, to.id(), None)
            .await
            .unwrap();
    }
    let folder = Arc::new(MemoryFolder::default());
    core.set_document_folders(folder.clone());
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .unwrap();
    account.backup_now().await.unwrap();
    let listing = list_backups(&*folder).unwrap().remove(0);
    let opened = core
        .open_backup(
            folder,
            &listing,
            Zeroizing::new(TEST_PASSWORD.into()),
            &kit.display(),
        )
        .await
        .unwrap();
    let at = opened.points()[0];
    let together = opened
        .restore_into(&account, at, &[from.id(), to.id()], "restored 29 Oct")
        .await
        .unwrap();
    let mapped = |id| {
        together
            .restored
            .iter()
            .find(|(old, _)| *old == id)
            .unwrap()
            .1
    };
    assert_eq!(
        account.locate(mapped(from.id()), note).unwrap(),
        mapped(to.id())
    );
    assert_eq!(
        account.moved_from(mapped(to.id()), note),
        Some(mapped(from.id()))
    );
    assert_eq!(
        account.locate(mapped(from.id()), file).unwrap(),
        mapped(to.id())
    );
    assert_eq!(
        account
            .base(mapped(to.id()))
            .unwrap()
            .file_bytes(file)
            .await
            .unwrap(),
        b"file moved across bases"
    );
    let alone = opened
        .restore_into(&account, at, &[from.id()], "restored 29 Oct")
        .await
        .unwrap();
    assert_eq!(
        account.locate(alone.restored[0].1, note),
        Err(Error::NotFound)
    );
    assert_eq!(
        account.locate(alone.restored[0].1, file),
        Err(Error::NotFound)
    );
}

#[tokio::test]
async fn files_are_sealed_for_the_new_base_and_reach_another_device() {
    let (_core, fixture, _folder, opened, at) = prepared().await;
    let old = personal(&fixture.account);
    let new = opened
        .restore_into(&fixture.account, at, &[old], "restored 29 Oct")
        .await
        .unwrap()
        .restored
        .into_iter()
        .find(|(id, _)| *id == old)
        .unwrap()
        .1;
    let base = fixture.account.base(new).unwrap();
    wait_for_base(&base, || {
        base.file(fixture.big_file).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    base.flush().await.unwrap();
    let other = device("other device");
    let second = other
        .sign_in(signin_for(&fixture.account))
        .await
        .unwrap()
        .with_kit(&fixture.kit.display())
        .await
        .unwrap();
    second.refresh().await.unwrap();
    let received = second.base(new).unwrap();
    wait_for_base(&received, || {
        received
            .file(fixture.big_file)
            .unwrap()
            .is_some_and(|file| file.status == FileStatus::Here)
    })
    .await;
    assert_eq!(
        received.file_bytes(fixture.big_file).await.unwrap(),
        vec![42; 9 * 1024 * 1024]
    );
}

#[tokio::test]
async fn unavailable_file_parts_are_reported_without_changing_the_backup() {
    let (_core, fixture, folder, opened, at) = prepared().await;
    let old = personal(&fixture.account);
    let part = format!("/files/{old}/{}/0", fixture.big_file);
    let path = folder
        .files()
        .into_keys()
        .find(|name| name.ends_with(&part))
        .unwrap();
    folder.remove_file(&path);
    let before = folder.files();
    let restored = opened
        .restore_into(&fixture.account, at, &[old], "restored 29 Oct")
        .await
        .unwrap();
    assert_eq!(restored.missing_files, [fixture.big_file]);
    assert_eq!(folder.files(), before);
}

#[tokio::test]
async fn a_hidden_base_comes_back_hidden_under_the_same_password() {
    let (_core, fixture, _folder, mut opened, at) = prepared().await;
    opened
        .unlock(Zeroizing::new(fixture.extra_password.clone()))
        .await
        .unwrap();
    let summary = opened
        .restore_into(
            &fixture.account,
            at,
            &[fixture.hidden.id()],
            "restored 29 Oct",
        )
        .await
        .unwrap();
    let new = summary.restored[0].1;
    assert!(
        fixture
            .account
            .bases()
            .iter()
            .any(|b| b.id == new && b.hidden)
    );
    fixture.account.lock_all_hidden().await;
    assert!(!fixture.account.bases().iter().any(|b| b.id == new));
    let unlocked = fixture
        .account
        .unlock_hidden(Zeroizing::new(fixture.extra_password.clone()))
        .await
        .unwrap();
    assert!(unlocked.iter().any(|b| b.id == new));
}

#[tokio::test]
async fn restoring_into_a_new_account_on_another_server_gives_the_same_content() {
    let mut server_a = LocalServer::start();
    let source = device_on_server("old account", &Clock::system(), &server_a);
    let mut signup = new_signup();
    signup.server = server_a.url();
    signup.invite = invite(&server_a);
    let (old_account, old_kit) = source.sign_up(signup).await.unwrap();
    let base = old_account.create_base("Personal").await.unwrap();
    let note = note_with_text(&base, "Old server note");
    let folder_id = base
        .create(NewObject {
            ty: TypeRef::new("core.folder", 1),
            parent: None,
            after: None,
            fields: Map::from_iter([("name".into(), json!("Shared"))]),
        })
        .unwrap();
    let _credentials = old_account
        .connect_app(bh_core::AppRequest {
            app_name: "Shared app".into(),
            app_id: Some("dev:two-server".into()),
            replaces: None,
            bases: vec![bh_core::BaseGrantRequest::Folder {
                base: base.id(),
                folder: folder_id,
                mode: bh_core::Mode::ReadWrite,
            }],
        })
        .await
        .unwrap();
    let mount = old_account
        .mounts()
        .into_iter()
        .find(|m| m.parent == base.id())
        .unwrap();
    let mounted = old_account.base(mount.base).unwrap();
    let child_note = note_with_text(&mounted, "Mounted on old server");
    let hidden = old_account
        .create_hidden_base("Diary", Zeroizing::new("extra password".into()))
        .await
        .unwrap();
    let hidden_note = note_with_text(&hidden, "Private old server note");
    let backup_folder = Arc::new(MemoryFolder::default());
    source.set_document_folders(backup_folder.clone());
    old_account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .unwrap();
    old_account.backup_now().await.unwrap();
    let expected = tempfile::tempdir().unwrap();
    old_account
        .export(base.id(), &expected.path().join("parent"))
        .await
        .unwrap();
    hidden
        .export(&expected.path().join("hidden"))
        .await
        .unwrap();
    let old_ids = (base.id(), mounted.id(), hidden.id());
    let listing = list_backups(&*backup_folder).unwrap().remove(0);
    drop(hidden);
    drop(mounted);
    drop(base);
    drop(old_account);
    drop(source);
    server_a.stop();
    drop(server_a);

    let server_b = LocalServer::start();
    let core = device_on_server("new account", &Clock::system(), &server_b);
    let mut signup = new_signup();
    signup.server = server_b.url();
    signup.invite = invite(&server_b);
    let (account, kit) = core.sign_up(signup).await.unwrap();
    assert!(account.bases().is_empty());
    let mut opened = core
        .open_backup(
            backup_folder.clone(),
            &listing,
            Zeroizing::new(TEST_PASSWORD.into()),
            &old_kit.display(),
        )
        .await
        .unwrap();
    opened
        .unlock(Zeroizing::new("extra password".into()))
        .await
        .unwrap();
    let before = backup_folder.files();
    let ids: Vec<_> = opened
        .bases(opened.points()[0])
        .await
        .unwrap()
        .iter()
        .map(|b| b.id)
        .collect();
    let restored = opened
        .restore_into(&account, opened.points()[0], &ids, "restored 29 Oct")
        .await
        .unwrap();
    assert_eq!(restored.restored.len(), 3);
    assert_eq!(backup_folder.files(), before);
    let map = |old| {
        restored
            .restored
            .iter()
            .find(|(id, _)| *id == old)
            .unwrap()
            .1
    };
    let (parent, child, private) = (map(old_ids.0), map(old_ids.1), map(old_ids.2));
    let actual = tempfile::tempdir().unwrap();
    account
        .export(parent, &actual.path().join("parent"))
        .await
        .unwrap();
    account
        .base(private)
        .unwrap()
        .export(&actual.path().join("hidden"))
        .await
        .unwrap();
    for name in ["parent", "hidden"] {
        assert_eq!(
            normalized_export(&expected.path().join(name), true),
            normalized_export(&actual.path().join(name), true)
        );
    }
    let new_mount = account
        .mounts()
        .into_iter()
        .find(|m| m.base == child)
        .unwrap();
    assert_eq!((new_mount.parent, new_mount.folder), (parent, folder_id));
    for id in [parent, child, private] {
        account.base(id).unwrap().flush().await.unwrap();
    }
    let other = device_on_server("new account second", &Clock::system(), &server_b);
    let mut signin = signin_for(&account);
    signin.server = server_b.url();
    let second = other
        .sign_in(signin)
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    second.refresh().await.unwrap();
    assert_eq!(
        second
            .mounts()
            .into_iter()
            .find(|m| m.base == child)
            .unwrap()
            .parent,
        parent
    );
    let other_parent = second.base(parent).unwrap();
    bh_testkit::wait_for(|| other_parent.get(note).unwrap().is_some()).await;
    let other_child = second.base(child).unwrap();
    bh_testkit::wait_for(|| other_child.get(child_note).unwrap().is_some()).await;
    assert!(!second.bases().iter().any(|b| b.id == private));
    second
        .unlock_hidden(Zeroizing::new("extra password".into()))
        .await
        .unwrap();
    let other_private = second.base(private).unwrap();
    bh_testkit::wait_for(|| other_private.get(hidden_note).unwrap().is_some()).await;
    let remote = tempfile::tempdir().unwrap();
    second
        .export(parent, &remote.path().join("parent"))
        .await
        .unwrap();
    other_private
        .export(&remote.path().join("hidden"))
        .await
        .unwrap();
    for name in ["parent", "hidden"] {
        assert_eq!(
            normalized_export(&expected.path().join(name), true),
            normalized_export(&remote.path().join(name), true)
        );
    }
}

#[tokio::test]
async fn a_backup_restores_into_a_new_account_on_the_same_server() {
    let (_source, fixture, folder, mut opened, at) = prepared().await;
    let expected = tempfile::tempdir().unwrap();
    for base in fixture.account.bases() {
        fixture
            .account
            .export(base.id, &expected.path().join(&base.name))
            .await
            .unwrap();
    }
    opened
        .unlock(Zeroizing::new(fixture.extra_password.clone()))
        .await
        .unwrap();
    let original_mount = fixture.account.mounts()[0];
    let backup_before = folder.files();
    let target = device_on_server(
        "restored account",
        &Clock::system(),
        LocalServer::from_env(),
    );
    let (account, kit) = target.sign_up(new_signup()).await.unwrap();
    let ids = opened
        .bases(at)
        .await
        .unwrap()
        .into_iter()
        .map(|base| base.id)
        .collect::<Vec<_>>();
    let result = opened
        .restore_into(&account, at, &ids, "restored 29 Oct")
        .await
        .unwrap();
    assert_ne!(account.id(), fixture.account.id());
    assert_eq!(result.restored.len(), ids.len());
    assert!(result.missing_files.is_empty());
    assert_eq!(folder.files(), backup_before);
    let mapped = |id| {
        result
            .restored
            .iter()
            .find(|(old, _)| *old == id)
            .unwrap()
            .1
    };
    let restored_mount = account
        .mounts()
        .into_iter()
        .find(|mount| mount.base == mapped(original_mount.base))
        .unwrap();
    assert_eq!(
        (restored_mount.parent, restored_mount.folder),
        (mapped(original_mount.parent), original_mount.folder)
    );
    let actual = tempfile::tempdir().unwrap();
    for (old, new) in &result.restored {
        let name = if *old == fixture.hidden.id() {
            "Diary".to_string()
        } else {
            fixture.account.base(*old).unwrap().name()
        };
        account
            .export(*new, &actual.path().join(&name))
            .await
            .unwrap();
        assert_eq!(
            normalized_export(&expected.path().join(&name), true),
            normalized_export(&actual.path().join(&name), true),
            "{name}"
        );
    }
    let signin = signin_for(&account);
    target.shutdown();
    drop(account);
    drop(target);
    let second_core = device_on_server(
        "restored second device",
        &Clock::system(),
        LocalServer::from_env(),
    );
    let second = second_core
        .sign_in(signin)
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    second.refresh().await.unwrap();
    second
        .unlock_hidden(Zeroizing::new(fixture.extra_password.clone()))
        .await
        .unwrap();
    assert_eq!(second.bases().len(), ids.len());
    let remote = tempfile::tempdir().unwrap();
    for (old, new) in &result.restored {
        let name = if *old == fixture.hidden.id() {
            "Diary".to_string()
        } else {
            fixture.account.base(*old).unwrap().name()
        };
        second
            .export(*new, &remote.path().join(&name))
            .await
            .unwrap();
        assert_eq!(
            normalized_export(&expected.path().join(&name), true),
            normalized_export(&remote.path().join(&name), true),
            "second device {name}"
        );
    }
}

#[tokio::test]
async fn an_app_device_cannot_restore_into_its_account() {
    let (_core, fixture, folder, _opened, _at) = prepared().await;
    let creds = fixture
        .account
        .connect_app(bh_core::AppRequest {
            app_name: "Restore app".into(),
            app_id: Some("dev:restore-app".into()),
            replaces: None,
            bases: vec![bh_core::BaseGrantRequest::Existing {
                base: personal(&fixture.account),
                mode: bh_core::Mode::ReadWrite,
            }],
        })
        .await
        .unwrap();
    let app_core = device("app");
    let app = app_core.install_app(creds).await.unwrap();
    let listing = list_backups(&*folder).unwrap().remove(0);
    let opened = app_core
        .open_backup(
            folder,
            &listing,
            Zeroizing::new(TEST_PASSWORD.into()),
            &fixture.kit.display(),
        )
        .await
        .unwrap();
    assert!(matches!(
        opened
            .restore_into(&app, opened.points()[0], &[], "restored 29 Oct")
            .await,
        Err(Error::Forbidden)
    ));
}
