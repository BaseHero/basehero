//! Retention of restorable runs in a device's backup folder.
use bh_core::{BackupLocation, Clock, Core, ManualClock, NewFile, list_backups};
use bh_testkit::{
    TEST_PASSWORD,
    backup::normalized_export,
    device_with_clock,
    folder::{MemoryFolder, record_paths},
    insert_text, new_signup, note_with_text,
};
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

const DAY: Duration = Duration::from_secs(86_400);

async fn setup() -> (
    Core,
    bh_core::Account,
    bh_core::Base,
    Arc<MemoryFolder>,
    ManualClock,
    String,
) {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("retention", &clock);
    let folder = Arc::new(MemoryFolder::default());
    core.set_document_folders(folder.clone());
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Personal").await.unwrap();
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .unwrap();
    (core, account, base, folder, manual, kit.display())
}

async fn opened(
    core: &Core,
    folder: &Arc<MemoryFolder>,
    password: &str,
    kit: &str,
) -> bh_core::OpenedBackup {
    core.open_backup(
        folder.clone(),
        &list_backups(&**folder).unwrap()[0],
        Zeroizing::new(password.into()),
        kit,
    )
    .await
    .unwrap()
}

fn edit(base: &bh_core::Base, note: bh_core::ObjectId, text: &str) {
    base.note(note)
        .unwrap()
        .apply(5, &insert_text(text))
        .unwrap();
}

#[tokio::test]
async fn a_snapshot_follows_when_the_log_passes_half_its_size() {
    let (_, account, base, folder, _, _) = setup().await;
    let note = note_with_text(&base, "first");
    account.backup_now().await.unwrap();
    let mut taken = false;
    for _ in 0..30 {
        edit(
            &base,
            note,
            "a fairly long additional sentence to grow the log",
        );
        if account.backup_now().await.unwrap().snapshots != 0 {
            taken = true;
            break;
        }
    }
    assert!(taken);
    assert!(record_paths(&folder, ".bhs").len() >= 2);
}

#[tokio::test]
async fn a_snapshot_follows_after_a_week() {
    let (_, account, _, folder, manual, _) = setup().await;
    account.backup_now().await.unwrap();
    manual.advance(DAY * 7);
    assert_eq!(account.backup_now().await.unwrap().snapshots, 1);
    assert_eq!(record_paths(&folder, ".bhs").len(), 2);
}

#[tokio::test]
async fn a_days_runs_merge_into_one_file_the_next_day_and_every_run_stays_a_point() {
    let (core, account, base, folder, manual, kit) = setup().await;
    let note = note_with_text(&base, "first");
    let expected_dir = tempfile::tempdir().unwrap();
    let mut runs = Vec::new();
    for n in 0..3 {
        edit(&base, note, &format!("edit {n}"));
        let run = account.backup_now().await.unwrap().run.unwrap();
        let out = expected_dir.path().join(format!("day-one-{n}"));
        account.export(base.id(), &out).await.unwrap();
        runs.push((run, normalized_export(&out, false)));
    }
    manual.advance(DAY);
    edit(&base, note, "tomorrow");
    account.backup_now().await.unwrap();
    let logs = record_paths(&folder, ".bhl");
    assert_eq!(
        logs.iter().filter(|p| p.contains("19700101-")).count(),
        1,
        "{logs:?}"
    );
    // The snapshot-only run's empty log stays separate to preserve its timestamp.
    assert_eq!(logs.len(), 3, "{logs:?}");
    let backup = opened(&core, &folder, TEST_PASSWORD, &kit).await;
    for (n, (run, expected)) in runs.into_iter().enumerate() {
        let at = run_time(&run);
        assert!(backup.points().contains(&at), "{run}");
        let checked = backup.check(at).await.unwrap();
        assert!(
            checked.bases.iter().all(|b| b.unreadable == 0),
            "{checked:?}"
        );
        let out = expected_dir.path().join(format!("restored-{n}"));
        backup.export(at, base.id(), &out).await.unwrap();
        assert_eq!(normalized_export(&out, false), expected, "{run}");
    }
}

fn run_time(run: &str) -> i64 {
    let date = &run[..8];
    let hours: i64 = run[9..11].parse().unwrap();
    let minutes: i64 = run[11..13].parse().unwrap();
    let seconds: i64 = run[13..15].parse().unwrap();
    let millis: i64 = run[15..18].parse().unwrap();
    assert_eq!(date, "19700101");
    ((hours * 60 + minutes) * 60 + seconds) * 1000 + millis
}

#[tokio::test]
async fn a_crash_during_a_merge_loses_nothing() {
    let (core, account, base, folder, manual, kit) = setup().await;
    let note = note_with_text(&base, "first");
    account.backup_now().await.unwrap();
    edit(&base, note, "second");
    account.backup_now().await.unwrap();
    let before = record_paths(&folder, ".bhl");
    manual.advance(DAY);
    folder.go_away_on_write("19700101-");
    edit(&base, note, "third");
    let run = account.backup_now().await.unwrap();
    assert!(run.run.is_some());
    folder.come_back();
    for name in &before {
        assert!(folder.files().contains_key(name));
    }
    let backup = opened(&core, &folder, TEST_PASSWORD, &kit).await;
    assert!(backup.points().contains(&0));
    manual.advance(DAY);
    edit(&base, note, "fourth");
    account.backup_now().await.unwrap();
    assert_eq!(
        record_paths(&folder, ".bhl")
            .iter()
            .filter(|p| p.contains("19700101-"))
            .count(),
        1
    );
}

#[tokio::test]
async fn invalid_logs_are_left_during_merging_and_eventually_pruned() {
    let (_, account, base, folder, manual, _) = setup().await;
    let note = note_with_text(&base, "first");
    account.backup_now().await.unwrap();
    edit(&base, note, "second");
    account.backup_now().await.unwrap();
    let damaged = record_paths(&folder, ".bhl").pop().unwrap();
    folder.put(&damaged, b"incomplete");
    manual.advance(DAY);
    edit(&base, note, "third");
    account.backup_now().await.unwrap();
    assert!(folder.files().contains_key(&damaged));
    assert!(
        record_paths(&folder, ".bhl")
            .iter()
            .any(|path| path.ends_with("19700101T000000000Z.bhl"))
    );
    manual.advance(DAY * 30);
    edit(&base, note, "last");
    account.backup_now().await.unwrap();
    assert!(!folder.files().contains_key(&damaged));
}

#[tokio::test]
async fn pruning_keeps_thirty_days_and_what_the_oldest_point_needs() {
    let (core, account, base, folder, manual, kit) = setup().await;
    let note = note_with_text(&base, "first");
    let expected_dir = tempfile::tempdir().unwrap();
    let mut expected_oldest = None;
    let mut runs = Vec::new();
    for day in 0..40 {
        if day != 0 {
            manual.advance(DAY);
            edit(&base, note, "x");
        }
        runs.push(account.backup_now().await.unwrap().run.unwrap());
        if day == 10 {
            let out = expected_dir.path().join("oldest-original");
            account.export(base.id(), &out).await.unwrap();
            expected_oldest = Some(normalized_export(&out, false));
        }
    }
    let opened = opened(&core, &folder, TEST_PASSWORD, &kit).await;
    let earliest_kept = opened.points().iter().copied().min().unwrap();
    assert!(earliest_kept > 0, "old runs were never pruned");
    let oldest = runs[10].as_str();
    // A retained snapshot may precede the exact 30-day cutoff.
    assert!(
        opened.points().contains(&((10 * DAY.as_millis()) as i64)),
        "{oldest}"
    );
    assert!(
        opened
            .check((10 * DAY.as_millis()) as i64)
            .await
            .unwrap()
            .bases
            .iter()
            .any(|b| b.id == base.id() && b.unreadable == 0)
    );
    let out = expected_dir.path().join("oldest-restored");
    opened
        .export((10 * DAY.as_millis()) as i64, base.id(), &out)
        .await
        .unwrap();
    assert_eq!(normalized_export(&out, false), expected_oldest.unwrap());
    let bytes: u64 = folder
        .files()
        .iter()
        .filter(|(p, _)| p.starts_with(&format!("{}/{}/", account.id(), account.device_id())))
        .map(|(_, v)| v.len() as u64)
        .sum();
    assert_eq!(account.backup_status().unwrap().bytes, bytes);
}

#[tokio::test]
async fn the_oldest_point_has_a_keys_file_even_when_a_snapshot_is_older() {
    let (core, account, base, folder, manual, kit) = setup().await;
    let note = note_with_text(&base, "first");
    for day in 0..41 {
        if day != 0 {
            manual.advance(DAY);
            edit(&base, note, "x");
        }
        if day == 9 {
            account.create_base("Second").await.unwrap();
        }
        account.backup_now().await.unwrap();
    }
    let backup = opened(&core, &folder, TEST_PASSWORD, &kit).await;
    assert_eq!(record_paths(&folder, ".bhk").len(), 1);
    assert!(
        backup
            .points()
            .iter()
            .all(|point| *point >= 9 * DAY.as_millis() as i64)
    );
    for point in backup.points() {
        assert!(
            backup.check(point).await.is_ok(),
            "unopenable point {point}"
        );
    }
}

#[tokio::test]
async fn points_survive_a_password_change_and_a_new_kit() {
    let (core, account, base, folder, manual, kit) = setup().await;
    let note = note_with_text(&base, "first");
    account.backup_now().await.unwrap();
    manual.advance(DAY);
    account
        .change_password(TEST_PASSWORD, &kit, "replacement password")
        .await
        .unwrap();
    edit(&base, note, "second");
    account.backup_now().await.unwrap();
    manual.advance(DAY);
    let new = account.new_kit("replacement password").await.unwrap();
    edit(&base, note, "third");
    account.backup_now().await.unwrap();
    let backup = opened(&core, &folder, "replacement password", &new.display()).await;
    assert_eq!(backup.points().len(), 3);
    for point in backup.points() {
        assert!(
            backup
                .check(point)
                .await
                .unwrap()
                .bases
                .iter()
                .any(|b| b.id == base.id())
        );
    }
}

#[tokio::test]
async fn a_cleared_folder_starts_again_with_fresh_snapshots() {
    let (core, account, base, folder, _, kit) = setup().await;
    let note = note_with_text(&base, "first");
    let file = base
        .add_file(
            NewFile {
                parent: Some(note),
                name: "image".into(),
                mime: "image/png".into(),
            },
            b"private bytes",
        )
        .unwrap();
    account.backup_now().await.unwrap();
    let root = format!("{}/{}", account.id(), account.device_id());
    bh_core::BackupFolder::remove(&*folder, &format!("{root}/snapshots")).unwrap();
    bh_core::BackupFolder::remove(&*folder, &format!("{root}/files")).unwrap();
    let next = account.backup_now().await.unwrap();
    assert_eq!((next.snapshots, next.parts), (1, 1));
    assert!(
        folder
            .files()
            .keys()
            .any(|p| p.ends_with(&format!("/files/{}/{file}/0", base.id())))
    );
    let backup = opened(&core, &folder, TEST_PASSWORD, &kit).await;
    let check = backup.check(backup.points()[0]).await.unwrap();
    assert!(
        check
            .bases
            .iter()
            .any(|b| b.id == base.id() && b.missing_files.is_empty())
    );
    let bytes: u64 = folder
        .files()
        .iter()
        .filter(|(path, _)| path.starts_with(&format!("{root}/")))
        .map(|(_, bytes)| bytes.len() as u64)
        .sum();
    assert_eq!(account.backup_status().unwrap().bytes, bytes);
}

#[tokio::test]
async fn old_merged_log_files_are_physically_pruned() {
    let (_, account, base, folder, manual, _) = setup().await;
    let note = note_with_text(&base, "first");
    account.backup_now().await.unwrap();
    edit(&base, note, "second");
    account.backup_now().await.unwrap();
    manual.advance(DAY);
    edit(&base, note, "third");
    account.backup_now().await.unwrap();
    let merged = record_paths(&folder, ".bhl")
        .into_iter()
        .find(|path| path.contains("19700101-"))
        .unwrap();
    manual.advance(DAY * 40);
    edit(&base, note, "fourth");
    account.backup_now().await.unwrap();
    assert!(
        !folder.files().contains_key(&merged),
        "old merged log remains: {merged}"
    );
}

#[tokio::test]
async fn changing_destination_during_maintenance_does_not_update_new_progress() {
    let (_, account, base, folder, manual, _) = setup().await;
    let note = note_with_text(&base, "first");
    account.backup_now().await.unwrap();
    edit(&base, note, "second");
    account.backup_now().await.unwrap();
    manual.advance(DAY);
    edit(&base, note, "third");
    let guard = folder.hang_writes();
    let running = account.clone();
    let run = tokio::spawn(async move { running.backup_now().await.unwrap() });
    let waiting = folder.clone();
    tokio::task::spawn_blocking(move || waiting.wait_for_write())
        .await
        .unwrap();
    let destination = BackupLocation::Document {
        uri: "new-destination".into(),
        label: "New backup".into(),
    };
    account.set_backup(Some(destination.clone())).unwrap();
    drop(guard);
    run.await.unwrap();
    let status = account.backup_status().unwrap();
    assert_eq!(status.location, Some(destination));
    assert_eq!(status.bytes, 0);
    assert!(status.last_run_at.is_none());
    // The next run must not skip maintenance because the old folder's day was recorded.
    manual.advance(DAY);
    account.backup_now().await.unwrap();
    assert_eq!(record_paths(&folder, ".bhk").len(), 2);
}

#[tokio::test]
async fn parts_only_run_remains_a_point_through_merge_then_expires() {
    let (core, account, base, folder, manual, kit) = setup().await;
    let note = note_with_text(&base, "first");
    base.add_file(
        NewFile {
            parent: Some(note),
            name: "attachment".into(),
            mime: "application/octet-stream".into(),
        },
        b"private bytes",
    )
    .unwrap();
    folder.go_away_on_write("/files/");
    assert!(account.backup_now().await.unwrap().run.is_none());
    folder.come_back();
    let run = account.backup_now().await.unwrap();
    assert_eq!((run.objects, run.parts), (0, 1), "{run:?}");
    let name = run.run.unwrap();
    let part_time = run_time(&name);
    let path = record_paths(&folder, ".bhl")
        .into_iter()
        .find(|path| path.ends_with(&format!("/{name}.bhl")))
        .unwrap();
    assert!(
        opened(&core, &folder, TEST_PASSWORD, &kit)
            .await
            .points()
            .contains(&part_time)
    );
    manual.advance(DAY);
    edit(&base, note, "next day");
    account.backup_now().await.unwrap();
    assert!(
        folder.files().contains_key(&path),
        "empty run log was merged"
    );
    assert!(
        opened(&core, &folder, TEST_PASSWORD, &kit)
            .await
            .points()
            .contains(&part_time)
    );
    manual.advance(DAY * 40);
    edit(&base, note, "later");
    account.backup_now().await.unwrap();
    assert!(
        !folder.files().contains_key(&path),
        "expired empty run log remains"
    );
}

fn reencode(folder: &MemoryFolder, path: &str, edit: impl FnOnce(&mut Vec<Vec<u8>>)) {
    let mut records = bh_core::test_support::backup_records(folder, path).unwrap();
    edit(&mut records);
    let mut out = b"BHBK\x01".to_vec();
    out.push(if path.ends_with(".bhk") { 1 } else { 2 });
    for record in &records {
        out.extend_from_slice(&(record.len() as u32).to_be_bytes());
        out.extend_from_slice(record);
    }
    let hash = bh_crypto::sha256(&out);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(records.len() as u64).to_be_bytes());
    out.extend_from_slice(&hash);
    folder.put(path, &out);
}

#[derive(Clone, Copy)]
enum DamagedAnchor {
    Truncated,
    KeysIdentity,
    KeysDevice,
    KeysTimestamp,
    KeysVersion,
    SnapshotBase,
    SnapshotRun,
    SnapshotUpdate,
    SnapshotMalformed,
}

async fn older_anchors_survive(damage: DamagedAnchor) {
    let (core, account, base, folder, manual, kit) = setup().await;
    let note = note_with_text(&base, &"initial ".repeat(200));
    let mut oldest_keys = String::new();
    let mut damaged_keys = String::new();
    let mut older_snapshot = String::new();
    let mut damaged_snapshot = String::new();
    let mut expected = None;
    for day in 0..41 {
        if day > 0 {
            manual.advance(DAY);
        }
        if day == 8 || day == 9 {
            account.create_base(&format!("Extra {day}")).await.unwrap();
        }
        if day == 8 || day == 10 {
            edit(&base, note, "x");
        }
        account.backup_now().await.unwrap();
        if day == 0 {
            older_snapshot = record_paths(&folder, ".bhs")
                .into_iter()
                .find(|p| p.contains(&base.id().to_string()))
                .unwrap();
        }
        if day == 7 {
            damaged_snapshot = record_paths(&folder, ".bhs")
                .into_iter()
                .find(|p| p.contains(&base.id().to_string()) && p.contains("19700108"))
                .unwrap();
        }
        if day == 8 {
            oldest_keys = record_paths(&folder, ".bhk").last().unwrap().clone();
        }
        if day == 9 {
            damaged_keys = record_paths(&folder, ".bhk").last().unwrap().clone();
        }
        if day == 10 {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("expected");
            account.export(base.id(), &out).await.unwrap();
            expected = Some(normalized_export(&out, false));
        }
        if day == 36 {
            match damage {
                DamagedAnchor::Truncated => {
                    folder.put(&damaged_keys, b"truncated keys");
                    folder.put(&damaged_snapshot, b"truncated snapshot");
                }
                DamagedAnchor::KeysIdentity
                | DamagedAnchor::KeysDevice
                | DamagedAnchor::KeysTimestamp
                | DamagedAnchor::KeysVersion => {
                    reencode(&folder, &damaged_keys, |records| {
                        let mut file: serde_json::Value =
                            serde_json::from_slice(&records[0]).unwrap();
                        match damage {
                            DamagedAnchor::KeysIdentity => {
                                file["account"] =
                                    serde_json::json!("ffffffffffffffffffffffffffffffff")
                            }
                            DamagedAnchor::KeysDevice => {
                                file["device"] =
                                    serde_json::json!("ffffffffffffffffffffffffffffffff")
                            }
                            DamagedAnchor::KeysTimestamp => {
                                file["writtenAt"] = serde_json::json!(-1)
                            }
                            DamagedAnchor::KeysVersion => file["v"] = serde_json::json!(2),
                            _ => unreachable!(),
                        }
                        records[0] = serde_json::to_vec(&file).unwrap();
                    });
                }
                DamagedAnchor::SnapshotBase => reencode(&folder, &damaged_snapshot, |records| {
                    records[0][1] ^= 1;
                }),
                DamagedAnchor::SnapshotRun => reencode(&folder, &damaged_snapshot, |records| {
                    records[0][33] ^= 1;
                }),
                DamagedAnchor::SnapshotUpdate => reencode(&folder, &damaged_snapshot, |records| {
                    records[0][0] = 0;
                }),
                DamagedAnchor::SnapshotMalformed => {
                    reencode(&folder, &damaged_snapshot, |records| {
                        records[0].truncate(34);
                    })
                }
            }
        }
    }
    if matches!(
        damage,
        DamagedAnchor::Truncated
            | DamagedAnchor::KeysIdentity
            | DamagedAnchor::KeysDevice
            | DamagedAnchor::KeysTimestamp
            | DamagedAnchor::KeysVersion
    ) {
        assert!(folder.files().contains_key(&oldest_keys));
    } else {
        assert!(folder.files().contains_key(&damaged_keys));
    }
    if matches!(
        damage,
        DamagedAnchor::Truncated
            | DamagedAnchor::SnapshotBase
            | DamagedAnchor::SnapshotRun
            | DamagedAnchor::SnapshotUpdate
            | DamagedAnchor::SnapshotMalformed
    ) {
        assert!(folder.files().contains_key(&older_snapshot));
    } else {
        assert!(folder.files().contains_key(&damaged_snapshot));
    }
    let opened = opened(&core, &folder, TEST_PASSWORD, &kit).await;
    let at = (10 * DAY.as_millis()) as i64;
    assert!(opened.points().contains(&at));
    let out_dir = tempfile::tempdir().unwrap();
    let out = out_dir.path().join("restored");
    opened.export(at, base.id(), &out).await.unwrap();
    assert_eq!(normalized_export(&out, false), expected.unwrap());
}

#[tokio::test]
async fn an_empty_newer_snapshot_does_not_displace_older_content() {
    let (core, account, base, folder, manual, kit) = setup().await;
    let note = note_with_text(&base, &"original content ".repeat(200));
    let mut populated_snapshot = String::new();
    let mut empty_snapshot = String::new();
    let mut expected = None;
    for day in 0..41 {
        if day > 0 {
            manual.advance(DAY);
        }
        if day == 8 || day == 10 {
            edit(&base, note, "later edit");
        }
        account.backup_now().await.unwrap();
        if day == 0 {
            populated_snapshot = record_paths(&folder, ".bhs")[0].clone();
        }
        if day == 7 {
            let current_snapshot = record_paths(&folder, ".bhs")
                .into_iter()
                .find(|path| path.contains("19700108"))
                .unwrap();
            // A later, non-current run is considered by pruning without making
            // the writer start a new generation for a changed current snapshot.
            empty_snapshot = current_snapshot.replace("19700108", "19700109");
            folder.put(&empty_snapshot, &folder.files()[&current_snapshot]);
            // The file still has a valid closing count and checksum, but no states.
            reencode(&folder, &empty_snapshot, Vec::clear);
            assert!(
                bh_core::test_support::backup_records(&*folder, &empty_snapshot)
                    .unwrap()
                    .is_empty()
            );
        }
        if day == 10 {
            let out_dir = tempfile::tempdir().unwrap();
            let out = out_dir.path().join("expected");
            account.export(base.id(), &out).await.unwrap();
            expected = Some(normalized_export(&out, false));
        }
    }
    // An empty snapshot cannot replace the last populated old anchor.
    assert!(!folder.files().contains_key(&empty_snapshot));
    assert!(
        record_paths(&folder, ".bhs")
            .iter()
            .any(|path| path != &populated_snapshot && path != &empty_snapshot)
    );
    let backup = opened(&core, &folder, TEST_PASSWORD, &kit).await;
    let at = (10 * DAY.as_millis()) as i64;
    assert!(backup.points().contains(&at));
    let out_dir = tempfile::tempdir().unwrap();
    let out = out_dir.path().join("restored");
    backup.export(at, base.id(), &out).await.unwrap();
    assert_eq!(normalized_export(&out, false), expected.unwrap());
}

#[tokio::test]
async fn an_empty_snapshot_remains_readable_when_it_is_the_only_old_anchor() {
    let (core, account, base, folder, manual, kit) = setup().await;
    account.backup_now().await.unwrap();
    let empty_snapshot = record_paths(&folder, ".bhs")[0].clone();
    reencode(&folder, &empty_snapshot, Vec::clear);
    manual.advance(DAY * 31);
    account.backup_now().await.unwrap();
    assert!(folder.files().contains_key(&empty_snapshot));
    let backup = opened(&core, &folder, TEST_PASSWORD, &kit).await;
    assert!(backup.points().contains(&0));
    assert!(
        backup
            .check(0)
            .await
            .unwrap()
            .bases
            .iter()
            .any(|b| b.id == base.id() && b.objects == 0)
    );
}

#[tokio::test]
async fn damaged_newest_old_anchors_do_not_remove_earlier_valid_anchors() {
    older_anchors_survive(DamagedAnchor::Truncated).await;
}

#[tokio::test]
async fn wrong_identity_keys_do_not_displace_an_older_restorable_anchor() {
    older_anchors_survive(DamagedAnchor::KeysIdentity).await;
}

#[tokio::test]
async fn wrong_device_keys_do_not_displace_an_older_restorable_anchor() {
    older_anchors_survive(DamagedAnchor::KeysDevice).await;
}

#[tokio::test]
async fn wrong_timestamp_keys_do_not_displace_an_older_restorable_anchor() {
    older_anchors_survive(DamagedAnchor::KeysTimestamp).await;
}

#[tokio::test]
async fn wrong_version_keys_do_not_displace_an_older_restorable_anchor() {
    older_anchors_survive(DamagedAnchor::KeysVersion).await;
}

#[tokio::test]
async fn wrong_base_snapshot_does_not_displace_an_older_restorable_anchor() {
    older_anchors_survive(DamagedAnchor::SnapshotBase).await;
}

#[tokio::test]
async fn wrong_run_snapshot_does_not_displace_an_older_restorable_anchor() {
    older_anchors_survive(DamagedAnchor::SnapshotRun).await;
}

#[tokio::test]
async fn update_snapshot_does_not_displace_an_older_restorable_anchor() {
    older_anchors_survive(DamagedAnchor::SnapshotUpdate).await;
}

#[tokio::test]
async fn malformed_snapshot_does_not_displace_an_older_restorable_anchor() {
    older_anchors_survive(DamagedAnchor::SnapshotMalformed).await;
}

#[tokio::test]
async fn unreadable_keys_do_not_trigger_destructive_pruning() {
    let (_, account, base, folder, manual, _) = setup().await;
    let note = note_with_text(&base, "first");
    let file = base
        .add_file(
            NewFile {
                parent: Some(note),
                name: "attachment".into(),
                mime: "application/octet-stream".into(),
            },
            b"private bytes",
        )
        .unwrap();
    account.backup_now().await.unwrap();
    let first_snapshot = record_paths(&folder, ".bhs")[0].clone();
    let keys = record_paths(&folder, ".bhk")[0].clone();
    let part = folder
        .files()
        .keys()
        .find(|p| p.ends_with(&format!("/files/{}/{file}/0", base.id())))
        .unwrap()
        .clone();
    manual.advance(DAY * 31);
    edit(&base, note, "later");
    let guard = folder.hang_writes();
    let running = account.clone();
    let run = tokio::spawn(async move { running.backup_now().await.unwrap() });
    let waiting = folder.clone();
    tokio::task::spawn_blocking(move || waiting.wait_for_write())
        .await
        .unwrap();
    folder.put(&keys, b"damaged keys");
    drop(guard);
    run.await.unwrap();
    assert!(folder.files().contains_key(&first_snapshot));
    assert!(folder.files().contains_key(&part));
}

#[tokio::test]
async fn file_parts_stay_while_their_base_has_a_kept_snapshot() {
    let (_, account, base, folder, manual, _) = setup().await;
    let note = note_with_text(&base, "first");
    let file = base
        .add_file(
            NewFile {
                parent: Some(note),
                name: "image".into(),
                mime: "image/png".into(),
            },
            b"private bytes",
        )
        .unwrap();
    account.backup_now().await.unwrap();
    for _ in 0..32 {
        manual.advance(DAY);
        edit(&base, note, "x");
        account.backup_now().await.unwrap();
    }
    assert!(
        folder
            .files()
            .keys()
            .any(|p| p.ends_with(&format!("/files/{}/{file}/0", base.id())))
    );
}
