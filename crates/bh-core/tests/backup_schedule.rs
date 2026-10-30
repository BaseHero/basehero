//! Device-local backup scheduling, stop and size reporting.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bh_core::test_support;
use bh_core::{BackupLocation, BackupProblem, BackupSchedule, Clock, NewFile};
use bh_testkit::{
    TEST_PASSWORD, device, device_with_clock,
    folder::{MemoryFolder, backup_device, record_paths},
    insert_text, new_signup, note_with_text, raw_device, signin_for,
};
use serde_json::json;
use std::{sync::Arc, time::Duration};

async fn manual_backup() -> (
    bh_core::Account,
    bh_core::Base,
    Arc<MemoryFolder>,
    bh_core::ManualClock,
) {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("scheduled-backup", &clock);
    let folder = Arc::new(MemoryFolder::default());
    core.set_document_folders(folder.clone());
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .unwrap();
    (account, base, folder, manual)
}

async fn until(mut condition: impl FnMut() -> bool) {
    for _ in 0..10000 {
        if condition() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("scheduled backup did not finish");
}

#[tokio::test]
async fn the_mac_schedule_runs_five_minutes_after_the_first_change() {
    let (account, base, folder, clock) = manual_backup().await;
    account.backup_now().await.unwrap();
    account.start_backups(BackupSchedule::MAC);
    let note = note_with_text(&base, "first");
    until(|| clock.scheduled_deadlines().contains(&300_000)).await;
    clock.advance(Duration::from_secs(299));
    base.note(note)
        .unwrap()
        .apply(5, &insert_text("again"))
        .unwrap();
    assert_eq!(record_paths(&folder, ".bhl").len(), 1);
    clock.advance(Duration::from_secs(1));
    until(|| record_paths(&folder, ".bhl").len() == 2).await;
    assert_eq!(record_paths(&folder, ".bhl").len(), 2);
}

#[tokio::test]
async fn the_phone_schedule_runs_at_most_every_fifteen_minutes() {
    let (account, base, folder, clock) = manual_backup().await;
    account.backup_now().await.unwrap();
    account.start_backups(BackupSchedule::PHONE);
    note_with_text(&base, "first");
    until(|| clock.scheduled_deadlines().contains(&900_000)).await;
    clock.advance(Duration::from_secs(899));
    assert_eq!(record_paths(&folder, ".bhl").len(), 1);
    clock.advance(Duration::from_secs(1));
    until(|| record_paths(&folder, ".bhl").len() == 2).await;
    note_with_text(&base, "second");
    until(|| clock.scheduled_deadlines().contains(&1_800_000)).await;
    clock.advance(Duration::from_secs(899));
    assert_eq!(record_paths(&folder, ".bhl").len(), 2);
    clock.advance(Duration::from_secs(1));
    until(|| record_paths(&folder, ".bhl").len() == 3).await;
}

#[tokio::test]
async fn stopping_a_run_doesnt_wait_for_a_hung_folder() {
    let (account, base, folder) = backup_device().await;
    note_with_text(&base, "first");
    let guard = folder.hang_writes();
    let running = account.clone();
    let task = tokio::spawn(async move { running.backup_now().await.unwrap() });
    let waiting = folder.clone();
    tokio::task::spawn_blocking(move || waiting.wait_for_write())
        .await
        .unwrap();
    account.stop_backup();
    assert!(account.backup_status().unwrap().last_run_at.is_none());
    drop(guard);
    assert!(task.await.unwrap().run.is_none());
    assert!(record_paths(&folder, ".bhs").is_empty());
    assert!(account.backup_status().unwrap().last_run_at.is_none());
    assert!(account.backup_now().await.unwrap().run.is_some());
}

#[tokio::test]
async fn stopping_a_queued_run_prevents_it_from_writing_but_later_runs_work() {
    let (account, base, folder) = backup_device().await;
    note_with_text(&base, "first");
    let guard = folder.hang_writes();
    let first_account = account.clone();
    let first = tokio::spawn(async move { first_account.backup_now().await.unwrap() });
    let waiting = folder.clone();
    tokio::task::spawn_blocking(move || waiting.wait_for_write())
        .await
        .unwrap();

    let queued_account = account.clone();
    let queued = tokio::spawn(async move { queued_account.backup_now().await.unwrap() });
    tokio::task::yield_now().await;
    account.stop_backup();
    drop(guard);
    assert!(first.await.unwrap().run.is_none());
    assert!(queued.await.unwrap().run.is_none());
    assert!(record_paths(&folder, ".bhs").is_empty());
    assert!(record_paths(&folder, ".bhl").is_empty());
    assert!(account.backup_now().await.unwrap().run.is_some());
}

#[tokio::test]
async fn stopping_after_new_keys_keeps_the_previous_completed_backup_in_status() {
    let (account, _, folder, clock) = manual_backup().await;
    account.backup_now().await.unwrap();
    let first = account.backup_status().unwrap().last_run_at;
    assert!(first.is_some());
    clock.advance(Duration::from_secs(60));
    account.create_base("Second").await.unwrap();
    let guard = folder.hang_writes_after(1);
    let running = account.clone();
    let task = tokio::spawn(async move { running.backup_now().await.unwrap() });
    let waiting = folder.clone();
    tokio::task::spawn_blocking(move || waiting.wait_for_write())
        .await
        .unwrap();
    assert_eq!(record_paths(&folder, ".bhk").len(), 2);
    account.stop_backup();
    drop(guard);
    assert!(task.await.unwrap().run.is_none());
    let status = account.backup_status().unwrap();
    assert_eq!(status.last_run_at, first);
    assert!(!status.stale);
}

#[tokio::test]
async fn choosing_the_same_folder_again_keeps_the_backup() {
    let (account, _, folder) = backup_device().await;
    account.backup_now().await.unwrap();
    let saved = folder.files();
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Renamed".into(),
        }))
        .unwrap();
    assert!(account.backup_now().await.unwrap().run.is_none());
    assert_eq!(folder.files(), saved);
    let other = Arc::new(MemoryFolder::default());
    account.test_set_document_folders(other.clone());
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "other".into(),
            label: "Other".into(),
        }))
        .unwrap();
    assert!(account.backup_status().unwrap().last_run_at.is_none());
    assert_eq!(account.backup_now().await.unwrap().snapshots, 1);
    assert_eq!(folder.files(), saved);
}

#[tokio::test]
async fn status_reports_folder_problems_and_clears_them_after_a_good_run() {
    let (account, base, folder) = backup_device().await;
    note_with_text(&base, "first");
    folder.go_away();
    account.backup_now().await.unwrap();
    assert_eq!(
        account.backup_status().unwrap().problem,
        Some(BackupProblem::Unreachable)
    );
    folder.come_back();
    folder.fill_up();
    account.backup_now().await.unwrap();
    assert_eq!(
        account.backup_status().unwrap().problem,
        Some(BackupProblem::Full)
    );
    folder.make_room();
    folder.lose_permission();
    account.backup_now().await.unwrap();
    assert_eq!(
        account.backup_status().unwrap().problem,
        Some(BackupProblem::PermissionLost)
    );
    folder.grant_permission();
    account.backup_now().await.unwrap();
    assert_eq!(account.backup_status().unwrap().problem, None);
}

#[tokio::test]
async fn a_change_arriving_from_another_device_schedules_a_run() {
    let (clock, manual) = Clock::manual();
    let (first, kit) = device("first").sign_up(new_signup()).await.unwrap();
    let base = first.create_base("Shared").await.unwrap();
    base.flush().await.unwrap();
    let second = device_with_clock("second", &clock)
        .sign_in(signin_for(&first))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    second.refresh().await.unwrap();
    let remote = second.base(base.id()).unwrap();
    remote.sync_now().await.unwrap();
    let folder = Arc::new(MemoryFolder::default());
    second.test_set_document_folders(folder.clone());
    second
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .unwrap();
    second.backup_now().await.unwrap();
    second.start_backups(BackupSchedule::MAC);
    let note = note_with_text(&base, "other device");
    base.flush().await.unwrap();
    remote.sync_now().await.unwrap();
    assert!(remote.get(note).unwrap().is_some());
    until(|| manual.scheduled_deadlines().contains(&300_000)).await;
    manual.advance(Duration::from_secs(300));
    until(|| record_paths(&folder, ".bhl").len() == 2).await;
}

#[tokio::test]
async fn status_distinguishes_last_checked_and_no_kit_record() {
    let (account, _) = device("checked").sign_up(new_signup()).await.unwrap();
    let folder = Arc::new(MemoryFolder::default());
    account.test_set_document_folders(folder.clone());
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .unwrap();
    let original = account.test_backup_credentials().unwrap().unwrap();
    let login = test_support::login_key(TEST_PASSWORD, &original.salt).unwrap();
    let (status, body) = raw_device(&account)
        .put(
            "/v1/account/credentials",
            json!({
                "currentLoginKey": URL_SAFE_NO_PAD.encode(login),
                "loginKey": URL_SAFE_NO_PAD.encode(login),
                "salt": URL_SAFE_NO_PAD.encode(original.salt),
                "kdf": { "opsLimit": 3, "memLimitKib": 65536 },
                "accountKeyEnvelope": URL_SAFE_NO_PAD.encode(test_support::seal_envelope(
                    &[8; 32], &original.salt, TEST_PASSWORD,
                    &account.recovery_kit().unwrap().unwrap(), account.id(),
                ).unwrap()),
            }),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    account.refresh().await.unwrap();
    assert_eq!(
        account.backup_status().unwrap().problem,
        Some(BackupProblem::UsingLastChecked)
    );
    folder.go_away();
    account.backup_now().await.unwrap();
    assert_eq!(
        account.backup_status().unwrap().problem,
        Some(BackupProblem::Unreachable)
    );
    folder.come_back();
    account.backup_now().await.unwrap();
    assert_eq!(
        account.backup_status().unwrap().problem,
        Some(BackupProblem::UsingLastChecked)
    );

    let (first, _) = device("no-kit").sign_up(new_signup()).await.unwrap();
    first.test_remove_kit_record(false).await.unwrap();
    let pending = device("new-device")
        .sign_in(signin_for(&first))
        .await
        .unwrap();
    let mut approval = pending.request_approval().await.unwrap();
    let (opened, digits) =
        tokio::try_join!(first.open_request(approval.id()), approval.digits()).unwrap();
    first.approve(opened, &digits).await.unwrap();
    let other = approval.wait().await.unwrap();
    other.refresh().await.unwrap();
    other.test_set_document_folders(folder.clone());
    let keys_before = record_paths(&folder, ".bhk");
    other
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .unwrap();
    assert_eq!(
        other.backup_status().unwrap().problem,
        Some(BackupProblem::NoKitRecord)
    );
    assert!(other.backup_now().await.unwrap().run.is_some());
    let new_keys: Vec<_> = record_paths(&folder, ".bhk")
        .into_iter()
        .filter(|path| !keys_before.contains(path))
        .collect();
    assert_eq!(new_keys.len(), 1, "unchecked backup keys file missing");
    let body = &test_support::backup_records(&*folder, &new_keys[0]).unwrap()[0];
    let keys: serde_json::Value = serde_json::from_slice(body).unwrap();
    assert_eq!(keys["envelopeChecked"], false);
    assert_eq!(
        other.backup_status().unwrap().problem,
        Some(BackupProblem::NoKitRecord)
    );
}

#[tokio::test]
async fn status_is_stale_after_seven_days_without_a_backup() {
    let (account, _, _, clock) = manual_backup().await;
    account.backup_now().await.unwrap();
    clock.advance(Duration::from_secs(7 * 86_400 - 1));
    assert!(!account.backup_status().unwrap().stale);
    clock.advance(Duration::from_secs(1));
    assert!(account.backup_status().unwrap().stale);
}

#[tokio::test]
async fn the_estimate_counts_object_states_and_file_parts() {
    let (account, base, _) = backup_device().await;
    let before = account.backup_estimate().unwrap();
    let note = note_with_text(&base, "first");
    let after_note = account.backup_estimate().unwrap();
    assert!(after_note > before);
    base.add_file(
        NewFile {
            parent: Some(note),
            name: "attachment".into(),
            mime: "application/octet-stream".into(),
        },
        b"payload",
    )
    .unwrap();
    assert!(account.backup_estimate().unwrap() > after_note + 7);
}
