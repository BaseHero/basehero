//! Device-local encrypted backup through an in-memory folder.

use bh_core::{
    AccountEvent, AppRequest, BackupFolder, BackupLocation, BackupProblem, BaseGrantRequest, Clock,
    Error, FolderError, LocalFolder, Mode, NewFile, test_support,
};
use bh_testkit::{
    device, device_with_clock,
    folder::{MemoryFolder, backup_device as setup, record_paths as files},
    insert_text, new_signup, note_with_text, pause_sync, raw_device, signin_for,
    two_devices_sharing_a_base, wait_for_base,
};
use std::sync::Arc;

#[test]
fn a_missing_file_in_an_existing_folder_is_other() {
    let dir = tempfile::tempdir().unwrap();
    let local = LocalFolder::new(dir.path().to_path_buf());
    let memory = MemoryFolder::default();
    for folder in [&local as &dyn BackupFolder, &memory as &dyn BackupFolder] {
        assert!(matches!(folder.read("missing"), Err(FolderError::Other(_))));
    }
}

#[tokio::test]
async fn the_first_run_writes_a_keys_file_a_snapshot_per_base_and_every_file_part() {
    let (account, base, folder) = setup().await;
    let note = note_with_text(&base, "a private note");
    let part = base
        .add_file(
            NewFile {
                parent: Some(note),
                name: "image".into(),
                mime: "image/png".into(),
            },
            b"a few bytes",
        )
        .unwrap();
    let run = account.backup_now().await.unwrap();
    assert_eq!(run.snapshots, 1);
    assert!(run.objects >= 2);
    assert_eq!(run.parts, 1);
    let keys = files(&folder, ".bhk");
    let snapshots = files(&folder, ".bhs");
    assert_eq!(keys.len(), 1);
    assert_eq!(snapshots.len(), 1);
    assert_eq!(files(&folder, ".bhl").len(), 1);
    assert_eq!(
        test_support::backup_records(&*folder, &keys[0])
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        test_support::backup_records(&*folder, &snapshots[0])
            .unwrap()
            .len(),
        run.objects
    );
    assert!(
        folder
            .files()
            .keys()
            .any(|path| path.ends_with(&format!("/files/{}/{part}/0", base.id())))
    );
}

#[tokio::test]
async fn a_run_after_one_edit_writes_one_update_record() {
    let (account, base, folder) = setup().await;
    let note = note_with_text(&base, "first");
    account.backup_now().await.unwrap();
    base.note(note)
        .unwrap()
        .apply(5, &insert_text("second"))
        .unwrap();
    let run = account.backup_now().await.unwrap();
    assert_eq!(run.objects, 1);
    assert_eq!(run.snapshots, 0);
    let logs = files(&folder, ".bhl");
    assert_eq!(logs.len(), 2);
    let records = test_support::backup_records(&*folder, logs.last().unwrap()).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0][0], 0);
    assert_eq!(&records[0][17..33], &note.0);
}

#[tokio::test]
async fn a_base_that_cannot_open_does_not_stop_the_other_bases_backup() {
    let (account, good, folder) = setup().await;
    let bad = account.create_base("Unavailable").await.unwrap();
    let note = note_with_text(&good, "first");
    note_with_text(&bad, "other");
    account.backup_now().await.unwrap();
    let mut invalid_wrapper = vec![1, 0, 0, 0, 1];
    invalid_wrapper.extend(bh_crypto::random::<72>());
    account
        .test_replace_base_wrapper(bad.id(), invalid_wrapper)
        .unwrap();
    assert_eq!(account.base(bad.id()).unwrap_err(), Error::NotFound);
    good.note(note)
        .unwrap()
        .apply(5, &insert_text("second"))
        .unwrap();
    assert!(account.backup_estimate().unwrap() > 0);
    let run = account.backup_now().await.unwrap();
    assert_eq!(run.objects, 1);
    assert!(run.run.is_some());
    assert!(account.backup_status().unwrap().problem.is_none());
    let log = files(&folder, ".bhl").pop().unwrap();
    assert_eq!(
        test_support::backup_records(&*folder, &log).unwrap().len(),
        1
    );
    // A broken wrapper cannot be put in a new keys file for this run, and
    // only a second failure should turn the transient skip into a warning.
    let latest = files(&folder, ".bhk").pop().unwrap();
    let record = test_support::backup_records(&*folder, &latest)
        .unwrap()
        .remove(0);
    let keys: serde_json::Value = serde_json::from_slice(&record).unwrap();
    assert!(
        !keys["wrappers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["base"] == bad.id().to_string())
    );
    account.backup_now().await.unwrap();
    assert_eq!(
        account.backup_status().unwrap().problem,
        Some(BackupProblem::UsingLastChecked)
    );
}

#[tokio::test]
async fn another_bases_large_log_does_not_make_an_unchanged_base_snapshot_due() {
    let (account, large, folder) = setup().await;
    let small = account.create_base("Small").await.unwrap();
    let note = note_with_text(&large, &"a".repeat(100_000));
    note_with_text(&small, &"b".repeat(20_000));
    assert_eq!(account.backup_now().await.unwrap().snapshots, 2);
    large
        .note(note)
        .unwrap()
        .apply(5, &insert_text(&"c".repeat(30_000)))
        .unwrap();
    assert_eq!(account.backup_now().await.unwrap().snapshots, 0);
    let next = account.backup_now().await.unwrap();
    assert_eq!(next.snapshots, 0, "{next:?}");
    assert_eq!(files(&folder, ".bhs").len(), 2);
}

#[tokio::test]
async fn deleting_a_note_is_recorded_in_the_next_log() {
    let (account, base, _) = setup().await;
    let note = note_with_text(&base, "first");
    account.backup_now().await.unwrap();
    base.delete(note).unwrap();
    assert_eq!(account.backup_now().await.unwrap().objects, 1);
}

#[tokio::test]
async fn a_run_with_nothing_changed_writes_nothing() {
    let (account, _, folder) = setup().await;
    account.backup_now().await.unwrap();
    let before = folder.files();
    assert!(account.backup_now().await.unwrap().run.is_none());
    assert_eq!(folder.files(), before);
}

#[tokio::test]
async fn a_run_cut_off_midway_is_written_again_next_time() {
    let (account, base, folder) = setup().await;
    let note = note_with_text(&base, "first");
    account.backup_now().await.unwrap();
    base.note(note)
        .unwrap()
        .apply(5, &insert_text("second"))
        .unwrap();
    account.new_kit(bh_testkit::TEST_PASSWORD).await.unwrap();
    folder.fail_writes_after(1);
    assert!(account.backup_now().await.unwrap().run.is_none());
    assert!(account.backup_status().unwrap().problem.is_some());
    folder.fail_writes_after(100);
    let retry = account.backup_now().await.unwrap();
    assert_eq!(retry.objects, 1);
    assert!(account.backup_status().unwrap().problem.is_none());
}

#[tokio::test]
async fn a_truncated_write_is_ignored_and_rewritten() {
    let (account, base, folder) = setup().await;
    let note = note_with_text(&base, "first");
    account.backup_now().await.unwrap();
    base.note(note)
        .unwrap()
        .apply(5, &insert_text("second"))
        .unwrap();
    folder.truncate_next_write(10);
    account.backup_now().await.unwrap();
    let damaged = files(&folder, ".bhl").last().unwrap().clone();
    assert!(test_support::backup_records(&*folder, &damaged).is_err());
    let next = account.backup_now().await.unwrap();
    assert_eq!(next.objects, 1);
    assert_ne!(damaged, files(&folder, ".bhl").last().unwrap().as_str());
}

#[tokio::test]
async fn a_folder_that_goes_away_mid_run_pauses_the_backup() {
    let (account, base, folder) = setup().await;
    let note = note_with_text(&base, "first");
    base.add_file(
        NewFile {
            parent: Some(note),
            name: "attachment".into(),
            mime: "application/octet-stream".into(),
        },
        b"sealed bytes",
    )
    .unwrap();
    folder.go_away_on_write("/files/");
    assert!(account.backup_now().await.unwrap().run.is_none());
    assert_eq!(
        account.backup_status().unwrap().problem,
        Some(bh_core::BackupProblem::Unreachable)
    );
    folder.come_back();
    assert_eq!(account.backup_now().await.unwrap().parts, 1);
    assert!(account.backup_status().unwrap().problem.is_none());
}

#[tokio::test]
async fn an_unchanged_run_does_not_read_the_current_snapshot() {
    let (account, base, folder) = setup().await;
    note_with_text(&base, "first");
    account.backup_now().await.unwrap();
    let snapshot = files(&folder, ".bhs").remove(0);
    let reads = folder.reads(&snapshot);
    assert!(account.backup_now().await.unwrap().run.is_none());
    assert_eq!(folder.reads(&snapshot), reads);
}

#[tokio::test]
async fn a_snapshot_with_the_wrong_size_starts_a_fresh_generation() {
    let (account, base, folder) = setup().await;
    note_with_text(&base, "first");
    account.backup_now().await.unwrap();
    let snapshot = files(&folder, ".bhs").remove(0);
    folder.put(&snapshot, b"short");
    assert_eq!(account.backup_now().await.unwrap().snapshots, 1);
    assert_eq!(files(&folder, ".bhk").len(), 2);
}

#[tokio::test]
async fn a_missing_snapshot_starts_a_fresh_generation() {
    let (account, base, folder) = setup().await;
    note_with_text(&base, "first");
    account.backup_now().await.unwrap();
    let snapshot = files(&folder, ".bhs").remove(0);
    folder.remove_file(&snapshot);
    let run = account.backup_now().await.unwrap();
    assert_eq!(run.snapshots, 1);
    assert_eq!(files(&folder, ".bhk").len(), 2);
    assert_eq!(files(&folder, ".bhs").len(), 1);
}

#[tokio::test]
async fn switching_folders_starts_fresh_without_erasing_the_old_one() {
    let (account, _, old) = setup().await;
    account.backup_now().await.unwrap();
    let previous = old.files();
    let next = Arc::new(MemoryFolder::default());
    account.test_set_document_folders(next.clone());
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "second".into(),
            label: "Backup".into(),
        }))
        .unwrap();
    assert!(account.backup_status().unwrap().last_run_at.is_none());
    assert_eq!(account.backup_now().await.unwrap().snapshots, 1);
    assert_eq!(old.files(), previous);
    assert_eq!(files(&next, ".bhk").len(), 1);
}

#[tokio::test]
async fn changing_the_destination_mid_run_keeps_the_new_generation() {
    let (account, base, folder) = setup().await;
    note_with_text(&base, "first");
    let guard = folder.hang_writes();
    let running = account.clone();
    let run = tokio::spawn(async move { running.backup_now().await.unwrap() });
    let waiting = folder.clone();
    tokio::task::spawn_blocking(move || waiting.wait_for_write())
        .await
        .unwrap();
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "new-destination".into(),
            label: "New folder".into(),
        }))
        .unwrap();
    drop(guard);
    run.await.unwrap();
    let status = account.backup_status().unwrap();
    assert_eq!(
        status.location,
        Some(BackupLocation::Document {
            uri: "new-destination".into(),
            label: "New folder".into(),
        })
    );
    assert!(status.last_run_at.is_none());
    assert_eq!(account.backup_now().await.unwrap().snapshots, 1);
    assert_eq!(files(&folder, ".bhk").len(), 1);
}

#[tokio::test]
async fn changing_only_the_label_mid_run_keeps_the_completed_progress() {
    let (account, base, folder) = setup().await;
    note_with_text(&base, "first");
    let guard = folder.hang_writes();
    let running = account.clone();
    let run = tokio::spawn(async move { running.backup_now().await.unwrap() });
    let waiting = folder.clone();
    tokio::task::spawn_blocking(move || waiting.wait_for_write())
        .await
        .unwrap();
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Renamed backup".into(),
        }))
        .unwrap();
    drop(guard);
    let completed = run.await.unwrap();
    assert!(completed.run.is_some());
    let status = account.backup_status().unwrap();
    assert_eq!(
        status.location,
        Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Renamed backup".into(),
        })
    );
    assert!(status.last_run_at.is_some());
    assert!(status.bytes > 0);
    assert!(account.backup_now().await.unwrap().run.is_none());
}

#[tokio::test]
async fn turning_backup_off_mid_run_stays_off() {
    let (account, base, folder) = setup().await;
    note_with_text(&base, "first");
    let guard = folder.hang_writes();
    let running = account.clone();
    let run = tokio::spawn(async move { running.backup_now().await.unwrap() });
    let waiting = folder.clone();
    tokio::task::spawn_blocking(move || waiting.wait_for_write())
        .await
        .unwrap();
    account.set_backup(None).unwrap();
    let writes_before_release = folder.writes();
    drop(guard);
    run.await.unwrap();
    assert_eq!(folder.writes(), writes_before_release + 1);
    let status = account.backup_status().unwrap();
    assert!(!status.enabled);
    assert!(status.last_run_at.is_none());
    assert!(account.backup_now().await.unwrap().run.is_none());
}

#[tokio::test]
async fn an_edit_during_a_write_reaches_the_next_run() {
    let (account, base, folder) = setup().await;
    let note = note_with_text(&base, "first");
    account.backup_now().await.unwrap();
    base.note(note)
        .unwrap()
        .apply(5, &insert_text("second"))
        .unwrap();
    let guard = folder.hang_writes();
    let running = account.clone();
    let run = tokio::spawn(async move { running.backup_now().await.unwrap() });
    let waiting = folder.clone();
    tokio::task::spawn_blocking(move || waiting.wait_for_write())
        .await
        .unwrap();
    base.note(note)
        .unwrap()
        .apply(11, &insert_text("third"))
        .unwrap();
    drop(guard);
    assert_eq!(run.await.unwrap().objects, 1);
    let next = account.backup_now().await.unwrap();
    assert_eq!(next.objects, 1);
    let log = files(&folder, ".bhl").last().unwrap().clone();
    let records = test_support::backup_records(&*folder, &log).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(&records[0][17..33], &note.0);
}

#[tokio::test]
async fn a_damaged_keys_file_is_written_again() {
    let (account, _, folder) = setup().await;
    account.backup_now().await.unwrap();
    let damaged = files(&folder, ".bhk").remove(0);
    folder.put(&damaged, b"truncated");
    let retry = account.backup_now().await.unwrap();
    assert!(retry.run.is_some());
    let keys = files(&folder, ".bhk");
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0], keys[1]);
    assert!(test_support::backup_records(&*folder, &damaged).is_err());
    assert_eq!(
        test_support::backup_records(&*folder, keys.last().unwrap())
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn a_full_folder_reports_full() {
    let (account, _, folder) = setup().await;
    folder.fill_up();
    account.backup_now().await.unwrap();
    assert_eq!(
        account.backup_status().unwrap().problem,
        Some(bh_core::BackupProblem::Full)
    );
}

#[tokio::test]
async fn runs_in_the_same_millisecond_get_distinct_later_names() {
    let (clock, _) = Clock::manual();
    let core = device_with_clock("backup", &clock);
    let folder = Arc::new(MemoryFolder::default());
    core.set_document_folders(folder.clone());
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    let note = note_with_text(&base, "first");
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .unwrap();
    let mut runs = Vec::new();
    for _ in 0..3 {
        base.note(note)
            .unwrap()
            .apply(5, &insert_text("more"))
            .unwrap();
        runs.push(account.backup_now().await.unwrap().run.unwrap());
    }
    assert!(runs[0] < runs[1] && runs[1] < runs[2], "{runs:?}");
}

#[tokio::test]
async fn a_keys_file_is_written_again_only_when_its_contents_change() {
    let (account, _, folder) = setup().await;
    account.backup_now().await.unwrap();
    account.backup_now().await.unwrap();
    assert_eq!(files(&folder, ".bhk").len(), 1);
    account.create_base("Second").await.unwrap();
    account.backup_now().await.unwrap();
    assert_eq!(files(&folder, ".bhk").len(), 2);
}

#[tokio::test]
async fn the_keys_file_lists_the_account_in_plain_text() {
    let (account, _, folder) = setup().await;
    account.backup_now().await.unwrap();
    let record = test_support::backup_records(&*folder, &files(&folder, ".bhk")[0])
        .unwrap()
        .remove(0);
    let keys: serde_json::Value = serde_json::from_slice(&record).unwrap();
    assert_eq!(keys["email"], account.email());
    assert_eq!(keys["account"], account.id().to_string());
    assert_eq!(keys["device"], account.device_id().to_string());
    assert!(keys["server"].as_str().unwrap().starts_with("http"));
    assert!(keys["writtenAt"].is_i64());
}

#[tokio::test]
async fn the_writer_makes_no_server_request() {
    let (account, base, _) = setup().await;
    pause_sync(&base);
    note_with_text(&base, "offline");
    let before = account.test_request_count("");
    account.backup_now().await.unwrap();
    assert_eq!(account.test_request_count(""), before);
}

#[test]
fn a_document_location_needs_a_registered_folder_opener() {
    let core = device("without-folder");
    let location = BackupLocation::Document {
        uri: "memory".into(),
        label: "Backup".into(),
    };
    assert!(matches!(core.open_folder(&location), Err(Error::NotFound)));
}

#[tokio::test]
async fn backups_off_write_nothing() {
    let (account, _, folder) = setup().await;
    account.set_backup(None).unwrap();
    assert!(account.backup_now().await.unwrap().run.is_none());
    assert!(folder.files().is_empty());
}

#[tokio::test]
async fn edits_from_another_device_and_unsent_local_edits_reach_the_next_run() {
    let (a, b) = two_devices_sharing_a_base().await;
    let folder = Arc::new(MemoryFolder::default());
    // An account handle keeps the same core-wide document opener as its base.
    a.account.test_set_document_folders(folder.clone());
    a.account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .unwrap();
    let x = note_with_text(&b.base, "remote");
    b.base.flush().await.unwrap();
    wait_for_base(&a.base, || a.base.get(x).unwrap().is_some()).await;
    a.account.backup_now().await.unwrap();
    pause_sync(&a.base);
    b.base
        .note(x)
        .unwrap()
        .apply(5, &insert_text("remote again"))
        .unwrap();
    b.base.flush().await.unwrap();
    // Resuming fetch and pausing before the next local edit leaves that edit unsent.
    a.base.test_resume_sync();
    wait_for_base(&a.base, || {
        a.base.note(x).unwrap().text().contains("remote again")
    })
    .await;
    pause_sync(&a.base);
    let y = note_with_text(&a.base, "unsent");
    let run = a.account.backup_now().await.unwrap();
    let logs = files(&folder, ".bhl");
    let records = test_support::backup_records(&*folder, logs.last().unwrap()).unwrap();
    assert_eq!(run.objects, 2);
    assert!(records.iter().any(|r| r[17..33] == x.0));
    assert!(records.iter().any(|r| r[17..33] == y.0));
}

#[tokio::test]
async fn an_app_device_cannot_back_up() {
    let (account, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Shared").await.unwrap();
    let credentials = account
        .connect_app(AppRequest {
            app_name: "viewer".into(),
            app_id: None,
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = device("app").install_app(credentials).await.unwrap();
    assert_eq!(
        app.set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into()
        }))
        .unwrap_err(),
        Error::Forbidden
    );
    assert_eq!(app.backup_now().await.unwrap_err(), Error::Forbidden);
}

#[tokio::test]
async fn signing_in_again_writes_a_new_device_folder_and_keeps_the_old() {
    let core = device("first");
    let folder = Arc::new(MemoryFolder::default());
    core.set_document_folders(folder.clone());
    let (a, kit) = core.sign_up(new_signup()).await.unwrap();
    a.create_base("Shared").await.unwrap();
    let location = BackupLocation::Document {
        uri: "memory".into(),
        label: "Backup".into(),
    };
    a.set_backup(Some(location.clone())).unwrap();
    a.backup_now().await.unwrap();
    let before = folder.files();
    let second = device("second");
    second.set_document_folders(folder.clone());
    let b = second
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    b.refresh().await.unwrap();
    b.set_backup(Some(location)).unwrap();
    b.backup_now().await.unwrap();
    for (path, bytes) in before {
        assert_eq!(folder.files()[&path], bytes);
    }
    assert_eq!(files(&folder, ".bhk").len(), 2);
}

#[tokio::test]
async fn a_device_the_server_signed_out_keeps_backing_up() {
    let (account, base, folder) = setup().await;
    let other = device("other").sign_in(signin_for(&account)).await.unwrap();
    let other = other
        .with_kit(&account.recovery_kit().unwrap().unwrap().display())
        .await
        .unwrap();
    let note = note_with_text(&base, "first");
    base.flush().await.unwrap();
    account.backup_now().await.unwrap();
    let mut events = account.events();
    let server = bh_testkit::LocalServer::from_env();
    let reply = reqwest::Client::new()
        .delete(
            server
                .url()
                .join(&format!("/v1/devices/{}", account.device_id()))
                .unwrap(),
        )
        .header("BH-Protocol", "2")
        .header("BH-Test-Bypass", server.operator_token())
        .bearer_auth(raw_device(&other).token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), reqwest::StatusCode::OK);
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if matches!(
                events.recv().await.unwrap(),
                AccountEvent::SignedOutByServer
            ) {
                break;
            }
        }
    })
    .await
    .unwrap();
    base.note(note)
        .unwrap()
        .apply(5, &insert_text("offline"))
        .unwrap();
    assert_eq!(account.backup_now().await.unwrap().objects, 1);
    assert_eq!(files(&folder, ".bhl").len(), 2);
}

#[tokio::test]
async fn erasing_a_device_leaves_its_backup_untouched() {
    let (account, base, folder) = setup().await;
    let other = device("other").sign_in(signin_for(&account)).await.unwrap();
    let other = other
        .with_kit(&account.recovery_kit().unwrap().unwrap().display())
        .await
        .unwrap();
    note_with_text(&base, "first");
    account.backup_now().await.unwrap();
    let before = folder.files();
    let mut events = account.events();
    other
        .remove_device(
            account.device_id(),
            bh_core::Removal::Full {
                password: zeroize::Zeroizing::new("correct horse battery staple".to_owned()),
                lost: false,
            },
        )
        .await
        .unwrap();
    // The notice starts erasure asynchronously; don't race backup_now against it.
    while events.recv().await.unwrap() != AccountEvent::Removed {}
    assert_eq!(account.backup_now().await.unwrap_err(), Error::Revoked);
    assert_eq!(folder.files(), before);
}
