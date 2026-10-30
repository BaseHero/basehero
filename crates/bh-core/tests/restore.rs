//! Backup recovery from a folder with no server reads during restore.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bh_core::{
    Account, BackupLocation, Clock, Core, CoreConfig, Error, FileSecretStore, list_backups,
    test_support::Fault,
};
use bh_testkit::{
    TEST_PASSWORD, append_text,
    backup::{everything, normalized_export},
    device, device_with_clock,
    folder::{MemoryFolder, record_paths},
    new_signup, note_with_text, pause_sync, raw_device, signin_for,
};
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

fn select(core: &Core, account: &Account, folder: &Arc<MemoryFolder>) {
    core.set_document_folders(folder.clone());
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .unwrap();
}
async fn open(core: &Core, folder: &Arc<MemoryFolder>, kit: &str) -> bh_core::OpenedBackup {
    let listing = list_backups(&**folder).unwrap();
    core.open_backup(
        folder.clone(),
        &listing[0],
        Zeroizing::new(TEST_PASSWORD.into()),
        kit,
    )
    .await
    .unwrap()
}

async fn server_base_epoch(account: &Account, base: bh_core::BaseId) -> serde_json::Value {
    let server = bh_testkit::LocalServer::from_env();
    let reply = reqwest::Client::new()
        .get(server.url().join(&format!("/v1/bases/{base}/key")).unwrap())
        .header("BH-Protocol", "2")
        .header("BH-Test-Bypass", server.operator_token())
        .bearer_auth(raw_device(account).token)
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), reqwest::StatusCode::OK);
    reply.json().await.unwrap()
}

async fn restored_notes(
    opened: &bh_core::OpenedBackup,
    at: i64,
    base: bh_core::BaseId,
) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("export");
    opened.export(at, base, &target).await.unwrap();
    normalized_export(&target, false)
        .into_iter()
        .filter(|(path, _)| path.extension().is_some_and(|extension| extension == "md"))
        .map(|(_, bytes)| String::from_utf8(bytes).unwrap().trim().to_string())
        .collect()
}
#[test]
fn opening_a_core_removes_unusable_temporary_restore_stores() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("core");
    let stale = data_dir.join("restore/stale/base.sqlite");
    std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
    std::fs::write(&stale, b"leftover encrypted store").unwrap();
    let core = Core::open(CoreConfig {
        data_dir: data_dir.clone(),
        secrets: Arc::new(FileSecretStore::new(dir.path().join("secrets")).unwrap()),
    })
    .unwrap();
    assert!(!data_dir.join("restore").exists());
    drop(core);
}

fn changed(folder: &MemoryFolder, path: &str, edit: impl FnOnce(&mut Vec<u8>)) {
    let bytes = folder.files().remove(path).unwrap();
    let mut records = bh_core::test_support::backup_records(folder, path).unwrap();
    edit(&mut records[0]);
    let mut out = bytes[..6].to_vec();
    for record in records {
        out.extend_from_slice(&(record.len() as u32).to_be_bytes());
        out.extend_from_slice(&record);
    }
    let hash = bh_crypto::sha256(&out);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(1u64).to_be_bytes());
    out.extend_from_slice(&hash);
    folder.put(path, &out);
}

#[tokio::test]
async fn opening_a_point_reuses_one_temporary_copy_and_replaces_it_on_switch() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("core");
    let core = Core::open(CoreConfig {
        data_dir: data_dir.clone(),
        secrets: Arc::new(FileSecretStore::new(dir.path().join("secrets")).unwrap()),
    })
    .unwrap();
    let (account, kit) = core
        .sign_up(bh_core::SignUp {
            device_name: "point copies".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let base = account.create_base("Personal").await.unwrap();
    note_with_text(&base, "first");
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    note_with_text(&base, "second");
    account.backup_now().await.unwrap();
    let opened = open(&core, &folder, &kit.display()).await;
    let copies = || {
        let roots: Vec<_> = std::fs::read_dir(data_dir.join("restore"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(roots.len(), 1);
        std::fs::read_dir(&roots[0]).unwrap().count()
    };
    let points = opened.points();
    assert!(points.len() >= 2);
    for _ in 0..3 {
        opened.bases(points[0]).await.unwrap();
    }
    opened.check(points[0]).await.unwrap();
    assert_eq!(copies(), 1);
    opened.bases(points[1]).await.unwrap();
    assert_eq!(copies(), 1);
}

#[tokio::test]
async fn a_backup_restores_with_no_server_and_matches_export() {
    let core = device("offline restore");
    let f = everything(&core).await;
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &f.account, &folder);
    let run = f.account.backup_now().await.unwrap();
    assert!(run.snapshots >= 2, "{run:?}");
    let expected = tempfile::tempdir().unwrap();
    let originals: Vec<_> = f
        .account
        .bases()
        .into_iter()
        .filter(|b| !b.hidden)
        .collect();
    for summary in &originals {
        f.account
            .export(summary.id, &expected.path().join(summary.id.to_string()))
            .await
            .unwrap();
    }
    for summary in &originals {
        pause_sync(&f.account.base(summary.id).unwrap());
    }
    let before = f.account.test_request_count("v1/account");
    let opened = open(&core, &folder, &f.kit.display()).await;
    let point = opened.points()[0];
    let report = opened.check(point).await.unwrap();
    assert_eq!(report.locked, 1); // The extra password has not opened the hidden wrapper.
    assert_eq!(report.missing, 0);
    assert!(
        report
            .bases
            .iter()
            .all(|b| b.unreadable == 0 && b.missing_files.is_empty()),
        "{report:?}"
    );
    let restored = tempfile::tempdir().unwrap();
    for summary in originals {
        let out = restored.path().join(summary.id.to_string());
        opened.export(point, summary.id, &out).await.unwrap();
        let left = normalized_export(&expected.path().join(summary.id.to_string()), false);
        let right = normalized_export(&out, false);
        let differing: Vec<_> = left
            .keys()
            .chain(right.keys())
            .filter(|p| left.get(*p) != right.get(*p))
            .collect();
        assert!(differing.is_empty(), "different paths: {differing:?}");
    }
    assert_eq!(f.account.test_request_count("v1/account"), before);
}

#[tokio::test]
async fn a_new_kit_opens_the_backup_when_the_account_data_write_fails() {
    let core = device("kit after data failure");
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    note_with_text(&base, "remember this");
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.refresh().await.unwrap();
    account.test_inject_fault(Fault {
        method: "PUT",
        path: "v1/account/data",
        lost_reply: false,
        times: 1,
    });
    let next = account.new_kit(TEST_PASSWORD).await.unwrap();
    assert!(account.backup_now().await.unwrap().run.is_some());
    let opened = open(&core, &folder, &next.display()).await;
    let report = opened.check(opened.points()[0]).await.unwrap();
    assert_eq!(
        report
            .bases
            .iter()
            .find(|b| b.id == base.id())
            .unwrap()
            .unreadable,
        0
    );
}

#[tokio::test]
async fn a_backup_from_before_a_removal_restores_with_the_new_kit() {
    let core = device("rotation backup");
    let (account, old_kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    note_with_text(&base, "before");
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    let other = device("removed")
        .sign_in(signin_for(&account))
        .await
        .unwrap()
        .with_kit(&old_kit.display())
        .await
        .unwrap();
    let outcome = account
        .remove_device(
            other.device_id(),
            bh_core::Removal::Full {
                password: Zeroizing::new(TEST_PASSWORD.to_owned()),
                lost: true,
            },
        )
        .await
        .unwrap();
    account.wait_for_removals().await.unwrap();
    let new_kit = outcome.new_kit.unwrap();
    note_with_text(&base, "after");
    account.backup_now().await.unwrap();
    let opened = open(&core, &folder, &new_kit.display()).await;
    let points = opened.points();
    assert!(points.len() >= 2, "{points:?}");
    assert_eq!(
        restored_notes(&opened, *points.last().unwrap(), base.id()).await,
        ["before"]
    );
    assert_eq!(
        restored_notes(&opened, points[0], base.id()).await,
        ["after", "before"]
    );
    let listing = list_backups(&*folder).unwrap();
    let opened_old = core
        .open_backup(
            folder,
            &listing[0],
            Zeroizing::new(TEST_PASSWORD.into()),
            &old_kit.display(),
        )
        .await
        .unwrap();
    assert_eq!(
        opened_old
            .check(*points.last().unwrap())
            .await
            .unwrap()
            .bases[0]
            .unreadable,
        0
    );
    assert!(matches!(
        opened_old.check(points[0]).await,
        Err(Error::BadKit)
    ));
}

#[tokio::test]
async fn an_older_keys_file_without_chains_still_restores() {
    let core = device("main-format restore");
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    note_with_text(&base, "main-format note");
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    let path = record_paths(&folder, ".bhk").pop().unwrap();
    let records = bh_core::test_support::backup_records(&*folder, &path).unwrap();
    let mut main: serde_json::Value = serde_json::from_slice(&records[0]).unwrap();
    assert_eq!(main["v"], 1);
    for wrapper in main["wrappers"].as_array_mut().unwrap() {
        wrapper.as_object_mut().unwrap().remove("chain");
    }
    assert!(
        main["wrappers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|w| w.get("chain").is_none())
    );
    let body = serde_json::to_vec(&main).unwrap();
    let mut bytes = b"BHBK\x01\x01".to_vec(); // Main's v1 keys record framing.
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&body);
    let hash = bh_crypto::sha256(&bytes);
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&1u64.to_be_bytes());
    bytes.extend_from_slice(&hash);
    folder.put(&path, &bytes);
    let opened = open(&core, &folder, &kit.display()).await;
    assert_eq!(
        restored_notes(&opened, opened.points()[0], base.id()).await,
        ["main-format note"]
    );
}

#[tokio::test]
async fn a_pending_removal_defers_backup_until_the_base_has_its_new_key() {
    let core = device("pending backup");
    let (account, old_kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    note_with_text(&base, "before removal");
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    let old_snapshots = record_paths(&folder, ".bhs");
    pause_sync(&base); // Hold the local row behind while the re-key reply is held.
    let other = device("removed while backing up")
        .sign_in(signin_for(&account))
        .await
        .unwrap()
        .with_kit(&old_kit.display())
        .await
        .unwrap();
    let (release, entered) = account.test_hold_next_hidden_rekey_reply();
    account.test_inject_fault(Fault {
        method: "DELETE",
        path: "v1/devices/",
        lost_reply: true,
        times: 1,
    });
    let outcome = account
        .remove_device(
            other.device_id(),
            bh_core::Removal::Full {
                password: Zeroizing::new(TEST_PASSWORD.to_owned()),
                lost: true,
            },
        )
        .await
        .unwrap();
    // Server committed; local wrapper is still old.
    bh_testkit::wait_entered(&entered, std::panic::Location::caller()).await;
    let new_kit = outcome.new_kit.unwrap();
    assert_eq!(
        &account.test_backup_credentials().unwrap().unwrap().envelope[1..5],
        &2u32.to_be_bytes()
    );
    note_with_text(&base, "edited while pending");
    let pending = account.backup_now().await.unwrap();
    assert_eq!(
        pending.objects, 0,
        "pending base was backed up: {pending:?}"
    );
    assert_eq!(record_paths(&folder, ".bhs"), old_snapshots);
    let immediate = open(&core, &folder, &new_kit.display()).await;
    assert_eq!(
        restored_notes(&immediate, immediate.points()[0], base.id()).await,
        ["before removal"]
    );
    release.add_permits(1);
    account.wait_for_removals().await.unwrap();
    let finished = account.backup_now().await.unwrap();
    assert_eq!(finished.snapshots, 1, "{finished:?}");
    let opened = open(&core, &folder, &new_kit.display()).await;
    assert_eq!(
        restored_notes(&opened, opened.points()[0], base.id()).await,
        ["before removal", "edited while pending"]
    );
}

#[tokio::test]
async fn an_offline_device_backs_up_with_the_envelope_it_adopts_after_rotation() {
    let core = device("rotating mac");
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    let note = note_with_text(&base, "before");
    base.flush().await.unwrap();
    let fold_core = device("offline fold");
    let fold = fold_core
        .sign_in(signin_for(&account))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    fold.refresh().await.unwrap();
    let fold_base = fold.base(base.id()).unwrap();
    bh_testkit::wait_for_base(&fold_base, || fold_base.note(note).is_ok()).await;
    let removed = device("removed fold")
        .sign_in(signin_for(&account))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let new_kit = account
        .remove_device(
            removed.device_id(),
            bh_core::Removal::Full {
                password: Zeroizing::new(TEST_PASSWORD.to_owned()),
                lost: true,
            },
        )
        .await
        .unwrap()
        .new_kit
        .unwrap();
    account.wait_for_removals().await.unwrap();
    fold.refresh().await.unwrap();
    let folder = Arc::new(MemoryFolder::default());
    select(&fold_core, &fold, &folder);
    fold.backup_now().await.unwrap();
    assert_eq!(
        &fold.test_backup_credentials().unwrap().unwrap().envelope[1..5],
        &2u32.to_be_bytes()
    );
    let opened = open(&fold_core, &folder, &new_kit.display()).await;
    assert_eq!(
        restored_notes(&opened, opened.points()[0], base.id()).await,
        ["before"]
    );
}

#[tokio::test]
async fn a_backup_after_a_rekey_starts_fresh_snapshots() {
    let core = device("fresh snapshot");
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    note_with_text(&base, "before");
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    let old_keys: Vec<_> = folder
        .files()
        .keys()
        .filter(|p| p.ends_with(".bhk"))
        .cloned()
        .collect();
    let other = device("removed snapshot")
        .sign_in(signin_for(&account))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    account
        .remove_device(
            other.device_id(),
            bh_core::Removal::Full {
                password: Zeroizing::new(TEST_PASSWORD.to_owned()),
                lost: false,
            },
        )
        .await
        .unwrap();
    account.wait_for_removals().await.unwrap();
    let run = account.backup_now().await.unwrap();
    assert_eq!(run.snapshots, 1, "{run:?}");
    for path in old_keys {
        folder.remove_file(&path);
    }
    let opened = open(&core, &folder, &kit.display()).await;
    let report = opened.check(opened.points()[0]).await.unwrap();
    assert_eq!(report.bases[0].unreadable, 0);
}

#[tokio::test]
async fn a_hidden_base_rekeyed_after_a_backup_restores_with_its_extra_password() {
    let core = device("hidden rotation backup");
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let hidden_password = || Zeroizing::new("hidden extra password".to_owned());
    let hidden = account
        .create_hidden_base("Diary", hidden_password())
        .await
        .unwrap();
    note_with_text(&hidden, "before");
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    let other = device("removed hidden")
        .sign_in(signin_for(&account))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    account.lock_hidden(hidden.id()).await.unwrap();
    account
        .remove_device(
            other.device_id(),
            bh_core::Removal::Full {
                password: Zeroizing::new(TEST_PASSWORD.to_owned()),
                lost: false,
            },
        )
        .await
        .unwrap();
    account.wait_for_removals().await.unwrap();
    account.unlock_hidden(hidden_password()).await.unwrap();
    for _ in 0..30 {
        let row = server_base_epoch(&account, hidden.id()).await;
        if row["epoch"] == 2 {
            break;
        }
        account.refresh().await.unwrap();
    }
    let row = server_base_epoch(&account, hidden.id()).await;
    assert_eq!(row["epoch"], 2, "hidden base did not re-key: {row}");
    let reopened = account.base(hidden.id()).unwrap();
    note_with_text(&reopened, "after");
    account.backup_now().await.unwrap();
    let mut opened = open(&core, &folder, &kit.display()).await;
    opened.unlock(hidden_password()).await.unwrap();
    let points = opened.points();
    assert!(points.len() >= 2);
    assert_eq!(
        restored_notes(&opened, *points.last().unwrap(), hidden.id()).await,
        ["before"]
    );
    assert_eq!(
        restored_notes(&opened, points[0], hidden.id()).await,
        ["after", "before"]
    );
}

#[tokio::test]
async fn a_wrong_password_or_kit_is_bad_kit() {
    let core = device("wrong keys");
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    account.create_base("Personal").await.unwrap();
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    let listing = list_backups(&*folder).unwrap();
    for (password, kit) in [
        ("wrong", kit.display()),
        (TEST_PASSWORD, "0000-0000-0000-0000-0000-0000-00".into()),
    ] {
        assert!(matches!(
            core.open_backup(
                folder.clone(),
                &listing[0],
                Zeroizing::new(password.into()),
                &kit
            )
            .await,
            Err(Error::BadKit)
        ));
    }
}

#[tokio::test]
async fn the_listing_shows_email_device_and_time_without_a_password() {
    let core = device("listing");
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    account.create_base("Personal").await.unwrap();
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    let listed = list_backups(&*folder).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].account, account.id());
    assert_eq!(listed[0].device, account.device_id());
    assert_eq!(listed[0].email, account.email());
    assert!(listed[0].written_at > 0);
}

#[tokio::test]
async fn listing_time_uses_newest_run_names_without_reading_them() {
    let core = device("listing runs");
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    let original = list_backups(&*folder).unwrap()[0].written_at;
    let prefix = format!("{}/{}", account.id(), account.device_id());
    let snapshot = format!("{prefix}/snapshots/{}/20300101T010101000Z.bhs", base.id());
    let log = format!("{prefix}/log/20300101-20400101T010101000Z.bhl");
    folder.put(&snapshot, b"unreadable snapshot");
    let from_snapshot = list_backups(&*folder).unwrap()[0].written_at;
    assert!(from_snapshot > original);
    folder.put(&log, b"unreadable log");
    let after = list_backups(&*folder).unwrap()[0].written_at;
    assert!(after > from_snapshot);
    assert!(after > 2_000_000_000_000);
    assert_eq!(folder.reads(&snapshot), 0);
    assert_eq!(folder.reads(&log), 0);
}

#[tokio::test]
async fn two_devices_share_a_folder_without_touching_each_other() {
    let a = device("first");
    let (first, kit) = a.sign_up(new_signup()).await.unwrap();
    let base = first.create_base("Personal").await.unwrap();
    note_with_text(&base, "shared note");
    let b = device("second");
    let second = b
        .sign_in(signin_for(&first))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    second.refresh().await.unwrap();
    let folder = Arc::new(MemoryFolder::default());
    select(&a, &first, &folder);
    select(&b, &second, &folder);
    first.backup_now().await.unwrap();
    let before = folder.files();
    second.backup_now().await.unwrap();
    for (path, bytes) in before {
        assert_eq!(folder.files().get(&path), Some(&bytes), "{path}");
    }
    let listed = list_backups(&*folder).unwrap();
    assert_eq!(listed.len(), 2);
    for item in listed {
        let opened = a
            .open_backup(
                folder.clone(),
                &item,
                Zeroizing::new(TEST_PASSWORD.into()),
                &kit.display(),
            )
            .await
            .unwrap();
        assert!(
            !opened
                .check(opened.points()[0])
                .await
                .unwrap()
                .bases
                .is_empty()
        );
    }
}

#[tokio::test]
async fn each_run_is_a_point_in_time_with_that_runs_content() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("points", &clock);
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    let note = note_with_text(&base, "first");
    let trash = note_with_text(&base, "old draft");
    base.flush().await.unwrap();
    manual.advance(Duration::from_secs(6 * 60));
    base.tick_versions().await.unwrap();
    let original = base.versions(note, None, 1).await.unwrap().0[0].seq;
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    let outputs = tempfile::tempdir().unwrap();
    let mut exports = Vec::new();
    for i in 0..4 {
        if i == 1 {
            base.note(note)
                .unwrap()
                .apply(5, &bh_testkit::insert_text("second"))
                .unwrap();
        }
        if i == 2 {
            base.delete(trash).unwrap();
        }
        if i == 3 {
            base.restore_version(note, original).await.unwrap();
        }
        account.backup_now().await.unwrap();
        let out = outputs.path().join(i.to_string());
        base.export(&out).await.unwrap();
        exports.push(normalized_export(&out, false));
    }
    let opened = open(&core, &folder, &kit.display()).await;
    assert_eq!(opened.points().len(), 4);
    for (index, point) in opened.points().into_iter().rev().enumerate() {
        let out = outputs.path().join(format!("restored-{index}"));
        opened.export(point, base.id(), &out).await.unwrap();
        let actual = normalized_export(&out, false);
        let expected = &exports[index];
        let differing: Vec<_> = expected
            .keys()
            .chain(actual.keys())
            .filter(|p| expected.get(*p) != actual.get(*p))
            .collect();
        assert!(
            differing.is_empty(),
            "point {index} differing paths: {differing:?}"
        );
    }
}

#[tokio::test]
async fn a_snapshot_without_changed_keys_or_log_records_is_a_restorable_point() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("snapshot only", &clock);
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    note_with_text(&base, "still here");
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    let first = account.backup_now().await.unwrap();
    let expected = tempfile::tempdir().unwrap();
    base.export(&expected.path().join("good")).await.unwrap();
    let good = normalized_export(&expected.path().join("good"), false);

    manual.advance(Duration::from_secs(7 * 86_400));
    let second = account.backup_now().await.unwrap();
    assert_eq!(second.snapshots, 1);
    assert_eq!(record_paths(&folder, ".bhk").len(), 1);
    let latest_log = record_paths(&folder, ".bhl").pop().unwrap();
    assert!(
        bh_core::test_support::backup_records(&*folder, &latest_log)
            .unwrap()
            .is_empty()
    );
    assert_ne!(second.run, first.run);

    let opened = open(&core, &folder, &kit.display()).await;
    assert_eq!(opened.points().len(), 2);
    let restored = expected.path().join("restored");
    opened
        .export(opened.points()[0], base.id(), &restored)
        .await
        .unwrap();
    assert_eq!(normalized_export(&restored, false), good);
}

#[tokio::test]
async fn a_truncated_file_restores_the_last_good_point() {
    let core = device("truncated");
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    let note = note_with_text(&base, "first");
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    let exports = tempfile::tempdir().unwrap();
    base.export(&exports.path().join("good")).await.unwrap();
    let good = normalized_export(&exports.path().join("good"), false);
    base.note(note)
        .unwrap()
        .apply(5, &bh_testkit::insert_text("second"))
        .unwrap();
    account.backup_now().await.unwrap();
    let newest = record_paths(&folder, ".bhl").pop().unwrap();
    folder.put(&newest, &folder.files()[&newest][..12]);
    let opened = open(&core, &folder, &kit.display()).await;
    assert_eq!(opened.points().len(), 1);
    assert!(
        opened
            .check(opened.points()[0])
            .await
            .unwrap()
            .ignored_files
            .contains(&newest)
    );
    let restored = exports.path().join("recovered");
    opened
        .export(opened.points()[0], base.id(), &restored)
        .await
        .unwrap();
    assert_eq!(normalized_export(&restored, false), good);
    folder.remove_file(&record_paths(&folder, ".bhs")[0]);
    let reopened = open(&core, &folder, &kit.display()).await;
    let report = reopened.check(reopened.points()[0]).await.unwrap();
    assert_eq!(report.locked, 0);
    assert_eq!(report.missing, 1);
}

#[tokio::test]
async fn a_missing_base_snapshot_is_not_locked_or_unlocked_by_a_password() {
    let core = device("missing base snapshot");
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let present = account.create_base("Present").await.unwrap();
    let absent = account.create_base("Absent").await.unwrap();
    note_with_text(&present, "still here");
    note_with_text(&absent, "gone");
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    let snapshot = record_paths(&folder, ".bhs")
        .into_iter()
        .find(|path| path.contains(&absent.id().to_string()))
        .unwrap();
    folder.remove_file(&snapshot);
    let mut opened = open(&core, &folder, &kit.display()).await;
    let point = opened.points()[0];
    let report = opened.check(point).await.unwrap();
    assert_eq!(
        (report.locked, report.missing, report.bases.len()),
        (0, 1, 1)
    );
    assert_eq!(
        opened.unlock(Zeroizing::new("extra password".into())).await,
        Err(Error::NothingUnlocked)
    );
    let summary = opened
        .restore_into(&account, point, &[present.id()], "Recovered")
        .await
        .unwrap();
    assert_eq!((summary.locked, summary.missing), (0, 1));
}

#[tokio::test]
async fn a_missing_middle_log_reports_later_unapplied_edits() {
    let core = device("missing middle log");
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    let note_id = note_with_text(&base, "first");
    note_with_text(&base, &"padding ".repeat(20_000));
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    let note = base.note(note_id).unwrap();
    note.apply(5, &append_text(&note.state(), "second"))
        .unwrap();
    account.backup_now().await.unwrap();
    let middle = record_paths(&folder, ".bhl").pop().unwrap();
    note.apply(5, &append_text(&note.state(), "third")).unwrap();
    account.backup_now().await.unwrap();
    folder.remove_file(&middle);
    let opened = open(&core, &folder, &kit.display()).await;
    let report = opened.check(opened.points()[0]).await.unwrap();
    let checked = report.bases.iter().find(|b| b.id == base.id()).unwrap();
    assert!(checked.unreadable > 0, "{report:?}");
}

#[tokio::test]
async fn a_tampered_record_is_unreadable_and_never_applied() {
    let core = device("tamper");
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    let note = note_with_text(&base, "first");
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    let exports = tempfile::tempdir().unwrap();
    base.export(&exports.path().join("good")).await.unwrap();
    let good = normalized_export(&exports.path().join("good"), false);
    base.note(note)
        .unwrap()
        .apply(5, &bh_testkit::insert_text("second"))
        .unwrap();
    account.backup_now().await.unwrap();
    let log = record_paths(&folder, ".bhl").pop().unwrap();
    changed(&folder, &log, |record| *record.last_mut().unwrap() ^= 1);
    let opened = open(&core, &folder, &kit.display()).await;
    let point = opened.points()[0];
    assert_eq!(opened.check(point).await.unwrap().bases[0].unreadable, 1);
    let restored = exports.path().join("recovered");
    opened.export(point, base.id(), &restored).await.unwrap();
    assert_eq!(normalized_export(&restored, false), good);
}

#[tokio::test]
async fn a_record_moved_to_another_object_or_base_doesnt_open() {
    for offset in [1, 17] {
        let core = device("moved record");
        let (account, kit) = core.sign_up(new_signup()).await.unwrap();
        let base = account.create_base("Personal").await.unwrap();
        let note = note_with_text(&base, "first");
        let folder = Arc::new(MemoryFolder::default());
        select(&core, &account, &folder);
        account.backup_now().await.unwrap();
        let exports = tempfile::tempdir().unwrap();
        base.export(&exports.path().join("good")).await.unwrap();
        let good = normalized_export(&exports.path().join("good"), false);
        base.note(note)
            .unwrap()
            .apply(5, &bh_testkit::insert_text("second"))
            .unwrap();
        account.backup_now().await.unwrap();
        let log = record_paths(&folder, ".bhl").pop().unwrap();
        changed(&folder, &log, |record| record[offset] ^= 1);
        let opened = open(&core, &folder, &kit.display()).await;
        let point = opened.points()[0];
        let check = opened.check(point).await.unwrap();
        assert_eq!(check.bases[0].unreadable, 1, "offset {offset}");
        let restored = exports.path().join("recovered");
        opened.export(point, base.id(), &restored).await.unwrap();
        assert_eq!(normalized_export(&restored, false), good, "offset {offset}");
    }
}

#[tokio::test]
async fn a_merged_record_without_a_timestamp_is_reported_but_not_a_point() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("merged malformed record", &clock);
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    let note = note_with_text(&base, "first");
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    base.note(note)
        .unwrap()
        .apply(5, &bh_testkit::insert_text("second"))
        .unwrap();
    account.backup_now().await.unwrap();
    manual.advance(Duration::from_secs(86_400));
    base.note(note)
        .unwrap()
        .apply(5, &bh_testkit::insert_text("third"))
        .unwrap();
    account.backup_now().await.unwrap();
    let merged = record_paths(&folder, ".bhl")
        .into_iter()
        .find(|path| path.contains("19700101-"))
        .unwrap();
    // Give the merged file a distinct parseable timestamp: it is only an error bound.
    let renamed = format!(
        "{}/19700101-19700101T000000500Z.bhl",
        merged.rsplit_once('/').unwrap().0
    );
    let bytes = folder.files()[&merged].clone();
    folder.remove_file(&merged);
    folder.put(&renamed, &bytes);
    changed(&folder, &renamed, |record| record.truncate(33));
    let opened = open(&core, &folder, &kit.display()).await;
    assert_eq!(
        opened.points().len(),
        2,
        "merged filename is not a user point"
    );
    assert!(!opened.points().contains(&500));
    let report = opened.check(opened.points()[0]).await.unwrap();
    assert_eq!(report.bases[0].unreadable, 1, "{report:?}");
}

#[tokio::test]
async fn a_backup_of_another_account_is_listed_separately() {
    let folder = Arc::new(MemoryFolder::default());
    for name in ["one account", "another account"] {
        let core = device(name);
        let (account, _) = core.sign_up(new_signup()).await.unwrap();
        account.create_base("Personal").await.unwrap();
        select(&core, &account, &folder);
        account.backup_now().await.unwrap();
    }
    let listings = list_backups(&*folder).unwrap();
    assert_eq!(listings.len(), 2);
    assert_ne!(listings[0].account, listings[1].account);
}

#[tokio::test]
async fn a_missing_file_part_is_named() {
    let core = device("part missing");
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    let file = base
        .add_file(
            bh_core::NewFile {
                parent: None,
                name: "large.bin".into(),
                mime: "application/octet-stream".into(),
            },
            &vec![13; 9 * 1024 * 1024],
        )
        .unwrap();
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    let path = format!(
        "{}/{}/files/{}/{file}/1",
        account.id(),
        account.device_id(),
        base.id()
    );
    folder.remove_file(&path);
    let opened = open(&core, &folder, &kit.display()).await;
    let point = opened.points()[0];
    assert_eq!(
        opened.check(point).await.unwrap().bases[0].missing_files,
        vec![file]
    );
    let out = tempfile::tempdir().unwrap();
    let summary = opened
        .export(point, base.id(), &out.path().join("missing"))
        .await
        .unwrap();
    assert_eq!(summary.missing_files, vec![file]);
}

#[tokio::test]
async fn a_backup_written_with_a_wrong_server_envelope_still_opens() {
    let core = device("checked credentials");
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    note_with_text(&base, "keep this");
    let original = account.test_backup_credentials().unwrap().unwrap();
    let login_key = bh_core::test_support::login_key(TEST_PASSWORD, &original.salt).unwrap();
    let response = raw_device(&account)
        .put(
            "/v1/account/credentials",
            serde_json::json!({
                "currentLoginKey": URL_SAFE_NO_PAD.encode(login_key),
                "loginKey": URL_SAFE_NO_PAD.encode(login_key),
                "salt": URL_SAFE_NO_PAD.encode(original.salt),
                "kdf": { "opsLimit": 3, "memLimitKib": 65536 },
                "accountKeyEnvelope": URL_SAFE_NO_PAD.encode(bh_core::test_support::seal_envelope(
                    &[8; 32], &original.salt, TEST_PASSWORD, &kit, account.id(),
                ).unwrap()),
            }),
        )
        .await;
    assert_eq!(response.0, reqwest::StatusCode::OK, "{:?}", response.1);
    account.refresh().await.unwrap();
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &account, &folder);
    account.backup_now().await.unwrap();
    let listing = list_backups(&*folder).unwrap();
    let opened = core
        .open_backup(
            folder,
            &listing[0],
            Zeroizing::new(TEST_PASSWORD.into()),
            &kit.display(),
        )
        .await
        .unwrap();
    assert_eq!(
        opened.check(opened.points()[0]).await.unwrap().bases[0].unreadable,
        0
    );
}
