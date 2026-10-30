//! Hidden bases in an offline folder backup.

use bh_core::{BackupLocation, Clock, Core, Error, OpenedBackup, list_backups, test_support};
use bh_testkit::{
    TEST_PASSWORD,
    backup::everything,
    device, device_with_clock,
    folder::{MemoryFolder, record_paths},
    note_with_text,
};
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

fn select(core: &Core, account: &bh_core::Account, folder: &Arc<MemoryFolder>) {
    core.set_document_folders(folder.clone());
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .unwrap();
}

async fn open(core: &Core, folder: &Arc<MemoryFolder>, kit: &str) -> OpenedBackup {
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

#[tokio::test]
async fn an_unlocked_hidden_base_is_backed_up_and_a_locked_one_isnt() {
    let core = device("hidden backup");
    let f = everything(&core).await;
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &f.account, &folder);
    let first = f.account.backup_now().await.unwrap();
    assert!(first.snapshots >= 3, "{first:?}");
    assert!(
        record_paths(&folder, ".bhs")
            .iter()
            .any(|p| p.contains(&format!("/snapshots/{}/", f.hidden.id())))
    );
    f.account.lock_hidden(f.hidden.id()).await.unwrap();
    let before = folder.files();
    f.account.backup_now().await.unwrap();
    assert_eq!(folder.files(), before);
}

#[tokio::test]
async fn a_hidden_base_restores_with_its_extra_password_and_is_counted_without_it() {
    let core = device("hidden restore");
    let f = everything(&core).await;
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &f.account, &folder);
    f.account.backup_now().await.unwrap();
    let mut opened = open(&core, &folder, &f.kit.display()).await;
    let at = opened.points()[0];
    assert_eq!(opened.check(at).await.unwrap().locked, 1);
    assert!(matches!(
        opened.unlock(Zeroizing::new("wrong".into())).await,
        Err(Error::NothingUnlocked)
    ));
    assert_eq!(
        opened
            .unlock(Zeroizing::new(f.extra_password.clone()))
            .await
            .unwrap(),
        1
    );
    assert!(matches!(
        opened
            .unlock(Zeroizing::new(f.extra_password.clone()))
            .await,
        Err(Error::NothingUnlocked)
    ));
    assert_eq!(opened.check(at).await.unwrap().locked, 0);
    let hidden = opened
        .bases(at)
        .await
        .unwrap()
        .into_iter()
        .find(|b| b.id == f.hidden.id())
        .unwrap();
    assert!(hidden.hidden);
    assert_eq!(hidden.notes, 1);
    let dir = tempfile::tempdir().unwrap();
    opened.export(at, f.hidden.id(), dir.path()).await.unwrap();
    assert!(
        bh_testkit::backup::normalized_export(dir.path(), false)
            .values()
            .any(|bytes| String::from_utf8_lossy(bytes).contains("Hidden note"))
    );
}

#[tokio::test]
async fn locking_mid_run_restores_to_the_last_good_point() {
    let core = device("hidden mid run");
    let f = everything(&core).await;
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &f.account, &folder);
    let guard = folder.hang_writes();
    let account = f.account.clone();
    let running = tokio::spawn(async move { account.backup_now().await.unwrap() });
    let waiting = folder.clone();
    tokio::task::spawn_blocking(move || waiting.wait_for_write())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), f.account.lock_hidden(f.hidden.id()))
        .await
        .unwrap()
        .unwrap();
    drop(guard);
    assert!(running.await.unwrap().run.is_some());
    let mut opened = open(&core, &folder, &f.kit.display()).await;
    assert_eq!(
        opened
            .unlock(Zeroizing::new(f.extra_password))
            .await
            .unwrap(),
        1
    );
    let at = opened.points()[0];
    let hidden = opened
        .bases(at)
        .await
        .unwrap()
        .into_iter()
        .find(|b| b.id == f.hidden.id())
        .unwrap();
    assert_eq!(hidden.notes, 1);
    assert_eq!(opened.check(at).await.unwrap().locked, 0);
    let dir = tempfile::tempdir().unwrap();
    opened.export(at, f.hidden.id(), dir.path()).await.unwrap();
    assert!(
        bh_testkit::backup::normalized_export(dir.path(), false)
            .values()
            .any(|bytes| String::from_utf8_lossy(bytes).contains("Hidden note"))
    );
    let reopened = f
        .account
        .unlock_hidden(Zeroizing::new("ferry lantern quartz".into()))
        .await
        .unwrap();
    assert_eq!(reopened.len(), 1);
    assert_eq!(f.account.backup_now().await.unwrap().snapshots, 1);
}

#[tokio::test]
async fn locking_a_hidden_base_doesnt_wait_for_folder_writes() {
    let core = device("hidden writes");
    let f = everything(&core).await;
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &f.account, &folder);
    f.account.backup_now().await.unwrap();
    note_with_text(&f.hidden, "Another hidden note");
    let guard = folder.hang_writes();
    let account = f.account.clone();
    let running = tokio::spawn(async move { account.backup_now().await.unwrap() });
    let waiting = folder.clone();
    tokio::task::spawn_blocking(move || waiting.wait_for_write())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), f.account.lock_hidden(f.hidden.id()))
        .await
        .unwrap()
        .unwrap();
    drop(guard);
    assert!(running.await.unwrap().run.is_some());
    f.account
        .unlock_hidden(Zeroizing::new(f.extra_password))
        .await
        .unwrap();
    assert!(f.account.backup_now().await.unwrap().objects >= 1);
}

#[tokio::test]
async fn pruning_keeps_the_locked_hidden_bases_snapshot() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("hidden retention", &clock);
    let f = everything(&core).await;
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &f.account, &folder);
    f.account.backup_now().await.unwrap();
    let snapshot = record_paths(&folder, ".bhs")
        .into_iter()
        .find(|p| p.contains(&format!("/snapshots/{}/", f.hidden.id())))
        .unwrap();
    f.account.lock_hidden(f.hidden.id()).await.unwrap();
    manual.advance(Duration::from_secs(31 * 86_400));
    assert!(f.account.backup_now().await.unwrap().run.is_some());
    assert!(folder.files().contains_key(&snapshot));
    let mut opened = open(&core, &folder, &f.kit.display()).await;
    assert_eq!(
        opened
            .unlock(Zeroizing::new(f.extra_password))
            .await
            .unwrap(),
        1
    );
    assert!(
        opened
            .bases(opened.points()[0])
            .await
            .unwrap()
            .iter()
            .any(|b| b.id == f.hidden.id() && b.hidden && b.notes == 1)
    );
}

#[tokio::test]
async fn the_keys_file_doesnt_mark_hidden_wrappers() {
    let core = device("anonymous wrappers");
    let f = everything(&core).await;
    let folder = Arc::new(MemoryFolder::default());
    select(&core, &f.account, &folder);
    f.account.backup_now().await.unwrap();
    let path = record_paths(&folder, ".bhk").remove(0);
    let records = test_support::backup_records(&*folder, &path).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&records[0]).unwrap();
    let wrappers = json["wrappers"].as_array().unwrap();
    assert!(wrappers.len() >= 3);
    for wrapper in wrappers {
        let fields: Vec<_> = wrapper
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(fields, ["base", "epoch", "wrapper"]);
    }
    assert!(!String::from_utf8_lossy(&records[0]).contains("hidden"));
    assert!(!String::from_utf8_lossy(&records[0]).contains("Diary"));
}
