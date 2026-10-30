mod common;

use basehero_app_lib::backup::{default_location_for, label_for_home, prepare_mac_account};
use basehero_app_lib::commands::{account, backup};
use basehero_app_lib::views::SignUpForm;
use basehero_app_lib::windows::{backup_bounded, last_backup_before_quit};
use bh_testkit::{LocalServer, TEST_PASSWORD, folder::backup_device, invite};
use common::state_at;
use std::path::Path;

#[test]
fn labels_read_like_finder() {
    let home = Path::new("/Users/person");
    assert_eq!(
        label_for_home(
            &home.join("Library/Mobile Documents/com~apple~CloudDocs/BaseHero"),
            home
        ),
        "iCloud Drive › BaseHero"
    );
    assert_eq!(
        label_for_home(Path::new("/Volumes/USB Drive/BaseHero"), home),
        "USB Drive › BaseHero"
    );
    assert_eq!(
        label_for_home(&home.join("Documents/BaseHero Backup"), home),
        "Documents › BaseHero Backup"
    );
}

#[test]
fn default_location_uses_icloud_only_when_cloud_docs_exists() {
    let home = tempfile::tempdir().unwrap();
    assert!(
        format!("{:?}", default_location_for(home.path())).contains("Documents/BaseHero Backup")
    );
    std::fs::create_dir_all(
        home.path()
            .join("Library/Mobile Documents/com~apple~CloudDocs"),
    )
    .unwrap();
    assert!(format!("{:?}", default_location_for(home.path())).contains("iCloud Drive › BaseHero"));
}

#[tokio::test]
async fn a_new_mac_account_backs_up_to_the_default_folder_unacknowledged() {
    let server = LocalServer::shared();
    let (state, events) = state_at(server.url());
    let signed = account::sign_up(
        &state,
        SignUpForm {
            invite: invite(server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: TEST_PASSWORD.into(),
            device_name: "Mac".into(),
        },
    )
    .await
    .unwrap();
    let home = events.home();
    let account = state.core.account(signed.account.id).unwrap();
    prepare_mac_account(&account, home).unwrap();
    let status = account.backup_status().unwrap();
    assert!(status.enabled);
    assert!(!status.acknowledged);
    assert_eq!(status.location, Some(default_location_for(home)));
    assert!(home.join("Documents/BaseHero Backup").is_dir());
    account.set_backup(None).unwrap();
    prepare_mac_account(&account, home).unwrap();
    assert!(!account.backup_status().unwrap().enabled);
}

/// The app chooses the Mac default in its state's home folder, which every test
/// replaces with its own, so no test reaches the person's real one.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn a_mac_account_backs_up_under_the_states_own_home() {
    let server = LocalServer::shared();
    let (state, events) = state_at(server.url());
    let signed = account::sign_up(
        &state,
        SignUpForm {
            invite: invite(server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: TEST_PASSWORD.into(),
            device_name: "Mac".into(),
        },
    )
    .await
    .unwrap();
    let status = state
        .core
        .account(signed.account.id)
        .unwrap()
        .backup_status()
        .unwrap();
    let Some(bh_core::BackupLocation::Path { path, .. }) = status.location else {
        panic!("no default folder: {:?}", status.location);
    };
    assert!(path.starts_with(events.home()), "{}", path.display());
}

#[tokio::test]
async fn quitting_writes_a_last_backup() {
    let server = LocalServer::shared();
    let (state, _events) = state_at(server.url());
    let signed = account::sign_up(
        &state,
        SignUpForm {
            invite: invite(server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: TEST_PASSWORD.into(),
            device_name: "Mac".into(),
        },
    )
    .await
    .unwrap();
    let folder = tempfile::tempdir().unwrap();
    let location = bh_core::BackupLocation::Path {
        path: folder.path().to_path_buf(),
        label: "Backup".into(),
    };
    backup::set_backup(&state, signed.account.id, Some(location.clone())).unwrap();
    last_backup_before_quit(&state.core).await;
    assert!(
        backup::backup_status(&state, signed.account.id)
            .unwrap()
            .last_run_at
            .is_some()
    );
    assert_eq!(backup::restore_list(&state, &location).unwrap().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn quitting_runs_a_last_backup_within_five_seconds() {
    let (account, base, folder) = backup_device().await;
    bh_testkit::note_with_text(&base, "before quit");
    let guard = folder.hang_writes();
    let first_account = account.clone();
    let first = tokio::spawn(async move { first_account.backup_now().await.unwrap() });
    let waiting = folder.clone();
    tokio::task::spawn_blocking(move || waiting.wait_for_write())
        .await
        .unwrap();

    let queued = account.clone();
    let stopper = account.clone();
    let quit = tokio::spawn(async move {
        backup_bounded(
            async {
                let _ = queued.backup_now().await;
            },
            || stopper.stop_backup(),
        )
        .await;
    });
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    quit.await.unwrap();
    drop(guard);
    assert!(first.await.unwrap().run.is_none());
    assert!(bh_testkit::folder::record_paths(&folder, ".bhs").is_empty());
    assert!(account.backup_now().await.unwrap().run.is_some());
}

async fn opened_handle(
    state: &basehero_app_lib::state::AppState,
    server: &LocalServer,
) -> (bh_core::AccountId, String) {
    let signed = account::sign_up(
        state,
        SignUpForm {
            invite: invite(server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: TEST_PASSWORD.into(),
            device_name: "Mac".into(),
        },
    )
    .await
    .unwrap();
    let folder = tempfile::tempdir().unwrap();
    let location = bh_core::BackupLocation::Path {
        path: folder.path().to_path_buf(),
        label: "Backup".into(),
    };
    backup::set_backup(state, signed.account.id, Some(location.clone())).unwrap();
    backup::backup_now(state, signed.account.id).await.unwrap();
    let listing = backup::restore_list(state, &location).unwrap().remove(0);
    let handle = backup::restore_open(state, &location, &listing, TEST_PASSWORD.into(), signed.kit)
        .await
        .unwrap();
    (signed.account.id, handle)
}

#[tokio::test]
async fn opening_a_backup_after_its_source_account_leaves_does_not_retain_a_handle() {
    let server = LocalServer::shared();
    let (state, _events) = state_at(server.url());
    let signed = account::sign_up(
        &state,
        SignUpForm {
            invite: invite(server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: TEST_PASSWORD.into(),
            device_name: "Mac".into(),
        },
    )
    .await
    .unwrap();
    let folder = tempfile::tempdir().unwrap();
    let location = bh_core::BackupLocation::Path {
        path: folder.path().to_path_buf(),
        label: "Backup".into(),
    };
    backup::set_backup(&state, signed.account.id, Some(location.clone())).unwrap();
    backup::backup_now(&state, signed.account.id).await.unwrap();
    let listing = backup::restore_list(&state, &location).unwrap().remove(0);
    // The offline reader can finish independently of the app account's lifetime.
    let opened = state
        .core
        .open_backup(
            state.core.open_folder(&location).unwrap(),
            &(&listing).into(),
            TEST_PASSWORD.to_string().into(),
            &signed.kit,
        )
        .await
        .unwrap();
    account::sign_out(&state, signed.account.id).await.unwrap();
    assert!(state.core.account(signed.account.id).is_err());
    // Simulate the awaited offline open finishing only after sign-out completed.
    let result = state.insert_open_restore(listing.account, true, opened);
    assert!(result.is_err(), "removed account must not reopen a handle");
    assert!(state.open_backups.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_offline_backup_from_an_absent_account_still_opens() {
    let server = LocalServer::shared();
    let (state, _events) = state_at(server.url());
    let signed = account::sign_up(
        &state,
        SignUpForm {
            invite: invite(server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: TEST_PASSWORD.into(),
            device_name: "Mac".into(),
        },
    )
    .await
    .unwrap();
    let folder = tempfile::tempdir().unwrap();
    let location = bh_core::BackupLocation::Path {
        path: folder.path().to_path_buf(),
        label: "Backup".into(),
    };
    backup::set_backup(&state, signed.account.id, Some(location.clone())).unwrap();
    backup::backup_now(&state, signed.account.id).await.unwrap();
    let listing = backup::restore_list(&state, &location).unwrap().remove(0);
    account::sign_out(&state, signed.account.id).await.unwrap();
    let handle = backup::restore_open(
        &state,
        &location,
        &listing,
        TEST_PASSWORD.into(),
        signed.kit,
    )
    .await
    .unwrap();
    assert!(
        !backup::restore_points(&state, &handle)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn signing_out_closes_open_restore_handles() {
    let server = LocalServer::shared();
    let (state, _events) = state_at(server.url());
    let (id, handle) = opened_handle(&state, server).await;
    assert!(backup::restore_points(&state, &handle).await.is_ok());
    account::sign_out(&state, id).await.unwrap();
    assert!(backup::restore_points(&state, &handle).await.is_err());
}

#[tokio::test]
async fn removing_this_device_closes_open_restore_handles() {
    let server = LocalServer::shared();
    let (state, _events) = state_at(server.url());
    let (id, handle) = opened_handle(&state, server).await;
    let device = state.core.account(id).unwrap().device_id();
    account::remove_device(&state, id, device, None, None)
        .await
        .unwrap();
    assert!(backup::restore_points(&state, &handle).await.is_err());
}

#[tokio::test]
async fn core_removal_event_closes_restore_handles() {
    let server = LocalServer::shared();
    let (state, events) = state_at(server.url());
    let (id, handle) = opened_handle(&state, server).await;
    state.core.account(id).unwrap().sign_out().await.unwrap();
    events.wait_for(|event| {
        matches!(event, basehero_app_lib::views::AppEvent::Account { account, event: bh_core::AccountEvent::Removed } if *account == id)
    });
    assert!(backup::restore_points(&state, &handle).await.is_err());
}

#[tokio::test]
async fn removing_a_restore_destination_closes_its_handle() {
    let server = LocalServer::shared();
    let (state, _events) = state_at(server.url());
    let (_, handle) = opened_handle(&state, server).await;
    let target = account::sign_up(
        &state,
        SignUpForm {
            invite: invite(server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: TEST_PASSWORD.into(),
            device_name: "Mac".into(),
        },
    )
    .await
    .unwrap();
    let at = backup::restore_points(&state, &handle).await.unwrap()[0];
    let bases = backup::restore_bases(&state, &handle, at).await.unwrap();
    backup::restore_into(
        &state,
        &handle,
        target.account.id,
        at,
        &bases.iter().map(|base| base.id).collect::<Vec<_>>(),
        "restored",
    )
    .await
    .unwrap();
    account::sign_out(&state, target.account.id).await.unwrap();
    assert!(backup::restore_points(&state, &handle).await.is_err());
}

#[tokio::test]
async fn restore_commands_open_list_and_restore_into_the_account() {
    let server = LocalServer::shared();
    let (state, _events) = state_at(server.url());
    let signed = account::sign_up(
        &state,
        SignUpForm {
            invite: invite(server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: TEST_PASSWORD.into(),
            device_name: "Mac".into(),
        },
    )
    .await
    .unwrap();
    let folder = tempfile::tempdir().unwrap();
    let location = bh_core::BackupLocation::Path {
        path: folder.path().to_path_buf(),
        label: "Backup".into(),
    };
    backup::set_backup(&state, signed.account.id, Some(location.clone())).unwrap();
    backup::backup_now(&state, signed.account.id).await.unwrap();
    let listings = backup::restore_list(&state, &location).unwrap();
    assert_eq!(listings.len(), 1);
    let handle = backup::restore_open(
        &state,
        &location,
        &listings[0],
        TEST_PASSWORD.into(),
        signed.kit,
    )
    .await
    .unwrap();
    let points = backup::restore_points(&state, &handle).await.unwrap();
    assert!(!points.is_empty());
    let check = backup::restore_check(&state, &handle, points[0])
        .await
        .unwrap();
    assert_eq!(check.locked, 0);
    let bases = backup::restore_bases(&state, &handle, points[0])
        .await
        .unwrap();
    assert!(bases.iter().any(|base| base.name == "Personal"));
    let summary = backup::restore_into(
        &state,
        &handle,
        signed.account.id,
        points[0],
        &bases.iter().map(|b| b.id).collect::<Vec<_>>(),
        "restored today",
    )
    .await
    .unwrap();
    assert_eq!(summary.restored.len(), 1);
    let new = backup::restore_sign_up(
        &state,
        &handle,
        SignUpForm {
            invite: invite(server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: TEST_PASSWORD.into(),
            device_name: "Mac".into(),
        },
        points[0],
        "restored 29 Oct",
    )
    .await
    .unwrap();
    assert_eq!(new.summary.unwrap().restored.len(), 1);
    assert!(
        !state
            .core
            .account(new.account.id)
            .unwrap()
            .bases()
            .iter()
            .any(|base| base.name == "Personal")
    );
    assert!(
        state
            .core
            .account(new.account.id)
            .unwrap()
            .bases()
            .iter()
            .any(|base| base.name == "Personal (restored 29 Oct)")
    );
    backup::restore_close(&state, &handle).unwrap();
    assert!(backup::restore_points(&state, &handle).await.is_err());
}
