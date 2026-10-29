//! Adding and removing an app's grants after it connected, against the local Worker.

use bh_core::{
    Account, AccountEvent, AppRequest, Base, BaseGrantRequest, BaseId, Core, CoreConfig, Error,
    FileSecretStore, Mode, test_support::Fault,
};
use bh_testkit::{device, new_signup, raw_device, wait_for};
use reqwest::StatusCode;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use zeroize::Zeroizing;

struct Setup {
    full: Account,
    app: Account,
    personal: Base,
    notes: Base,
}

/// A full device with Personal and Notes, and an app granted Personal, and Notes too
/// if `grant_notes`.
async fn setup(grant_notes: bool) -> Setup {
    let full = device("laptop").sign_up(new_signup()).await.unwrap().0;
    let personal = full.create_base("Personal").await.unwrap();
    let notes = full.create_base("Notes").await.unwrap();
    let mut bases = vec![BaseGrantRequest::Existing {
        base: personal.id(),
        mode: Mode::ReadWrite,
    }];
    if grant_notes {
        bases.push(BaseGrantRequest::Existing {
            base: notes.id(),
            mode: Mode::ReadWrite,
        });
    }
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
    Setup {
        full,
        app,
        personal,
        notes,
    }
}

fn ids(account: &Account) -> Vec<BaseId> {
    account.bases().iter().map(|base| base.id).collect()
}

#[tokio::test]
async fn adding_a_base_grant_reaches_the_app_on_refresh() {
    let Setup {
        full,
        app,
        personal,
        notes,
    } = setup(false).await;
    let granted = full
        .add_app_grant(
            app.device_id(),
            BaseGrantRequest::Existing {
                base: notes.id(),
                mode: Mode::ReadOnly,
            },
        )
        .await
        .unwrap();
    assert_eq!(granted, notes.id());
    app.refresh().await.unwrap();
    let listed = ids(&app);
    assert!(listed.contains(&personal.id()) && listed.contains(&notes.id()));
    assert_eq!(app.base(notes.id()).unwrap().mode(), Mode::ReadOnly);

    let created = full
        .add_app_grant(
            app.device_id(),
            BaseGrantRequest::New {
                name: "Meals".into(),
                mode: Mode::ReadWrite,
            },
        )
        .await
        .unwrap();
    app.refresh().await.unwrap();
    assert_eq!(app.base(created).unwrap().mode(), Mode::ReadWrite);
    assert!(full.test_app_readers(created).contains(&app.device_id()));
}

#[tokio::test]
async fn removing_a_grant_erases_that_base_from_the_app() {
    let Setup {
        full,
        app,
        personal,
        notes,
    } = setup(true).await;
    let open = app.base(notes.id()).unwrap();
    full.remove_app_grant(app.device_id(), notes.id())
        .await
        .unwrap();
    let mut events = app.events();
    app.refresh().await.unwrap();
    assert_eq!(events.try_recv().unwrap(), AccountEvent::BasesChanged);
    assert_eq!(ids(&app), vec![personal.id()]);
    assert_eq!(app.base(notes.id()).unwrap_err(), Error::NotFound);
    assert_eq!(open.children(None).unwrap_err(), Error::NotFound);
    assert_eq!(
        app.test_secrets()
            .get(&format!("base.{}.dbkey", notes.id()))
            .unwrap(),
        None
    );
    let (status, body) = raw_device(&app)
        .get(&format!("/v1/bases/{}/key", notes.id()), json!({}))
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden"))
    );
    assert!(full.test_app_readers(notes.id()).is_empty());
}

#[tokio::test]
async fn concurrent_settles_do_not_restore_a_removed_grant() {
    let Setup {
        full,
        app,
        personal,
        notes,
    } = setup(false).await;
    let personal_path = format!("v1/bases/{}/grants/{}", personal.id(), app.device_id());
    let notes_path = format!("v1/bases/{}/grants/{}", notes.id(), app.device_id());
    let before = full.test_request_count(&personal_path) + full.test_request_count(&notes_path);
    let held = full.test_hold_next_grant();
    let adding = {
        let full = full.clone();
        let id = notes.id();
        let device = app.device_id();
        tokio::spawn(async move {
            full.add_app_grant(
                device,
                BaseGrantRequest::Existing {
                    base: id,
                    mode: Mode::ReadOnly,
                },
            )
            .await
        })
    };
    wait_for(|| {
        full.test_request_count(&personal_path) + full.test_request_count(&notes_path) > before
    })
    .await;
    let mut removing = {
        let full = full.clone();
        let id = notes.id();
        let device = app.device_id();
        tokio::spawn(async move { full.remove_app_grant(device, id).await })
    };
    wait_for(|| {
        full.apps().iter().any(|entry| {
            entry.device_id == app.device_id() && !entry.bases.iter().any(|g| g.base == notes.id())
        })
    })
    .await;
    // Before the fix the second settle can finish while the first PUT is held.
    // With the lock it waits, and releasing the PUT lets it revoke last.
    let early = tokio::time::timeout(Duration::from_secs(2), &mut removing).await;
    held.add_permits(1);
    if let Ok(result) = early {
        result.unwrap().unwrap();
    } else {
        removing.await.unwrap().unwrap();
    }
    adding.await.unwrap().unwrap();
    app.refresh().await.unwrap();
    assert!(!ids(&app).contains(&notes.id()));
    assert!(full.test_app_readers(notes.id()).is_empty());
}

#[tokio::test]
async fn failed_erase_does_not_stop_erasing_other_revoked_bases() {
    let full = device("laptop").sign_up(new_signup()).await.unwrap().0;
    let first = full.create_base("First").await.unwrap();
    let second = full.create_base("Second").await.unwrap();
    let retained = full.create_base("Retained").await.unwrap();
    let credentials = full
        .connect_app(AppRequest {
            app_name: "Demo App".into(),
            app_id: Some("dev:erase".into()),
            bases: [first.id(), second.id(), retained.id()]
                .map(|base| BaseGrantRequest::Existing {
                    base,
                    mode: Mode::ReadWrite,
                })
                .to_vec(),
            replaces: None,
        })
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let secrets = dir.path().join("secrets");
    let app_core = Core::open(CoreConfig {
        data_dir: dir.path().join("data"),
        secrets: Arc::new(FileSecretStore::new(&secrets).unwrap()),
    })
    .unwrap();
    let app = app_core.install_app(credentials).await.unwrap();
    let retained_on_app = app.base(retained.id()).unwrap();
    wait_for(|| retained_on_app.sync_state().online).await;
    full.remove_app_grant(app.device_id(), first.id())
        .await
        .unwrap();
    full.remove_app_grant(app.device_id(), second.id())
        .await
        .unwrap();
    let blocked = secrets.join(format!("base.{}.dbkey", first.id()));
    std::fs::remove_file(&blocked).unwrap();
    std::fs::create_dir(&blocked).unwrap();
    let since = format!("v1/bases/{}/since", retained.id());
    let before = app.test_request_count(&since);
    assert!(matches!(app.refresh().await, Err(Error::Storage(_))));
    wait_for(|| app.test_request_count(&since) > before).await;
    assert_eq!(
        app.test_secrets()
            .get(&format!("base.{}.dbkey", second.id()))
            .unwrap(),
        None
    );
    assert_eq!(ids(&app), [retained.id()]);
    std::fs::remove_dir(blocked).unwrap();
    app.refresh().await.unwrap();
    assert_eq!(ids(&app), [retained.id()]);
}

#[tokio::test]
async fn a_grant_change_that_stopped_midway_finishes_on_refresh() {
    let Setup {
        full, app, notes, ..
    } = setup(true).await;
    full.test_inject_fault(Fault {
        method: "DELETE",
        path: Box::leak(
            format!("v1/bases/{}/grants/{}", notes.id(), app.device_id()).into_boxed_str(),
        ),
        lost_reply: false,
        times: 1,
    });
    assert!(matches!(
        full.remove_app_grant(app.device_id(), notes.id()).await,
        Err(Error::Network(_))
    ));
    // Pending: the old and new readers count together.
    assert_eq!(
        full.test_app_readers(notes.id()),
        BTreeSet::from([app.device_id()])
    );
    full.refresh().await.unwrap();
    assert!(full.test_app_readers(notes.id()).is_empty());
    app.refresh().await.unwrap();
    assert!(!ids(&app).contains(&notes.id()));
}

#[tokio::test]
async fn a_pending_change_for_a_removed_app_does_not_hold_up_others() {
    let Setup {
        full, app, notes, ..
    } = setup(false).await;
    let credentials = full
        .connect_app(AppRequest {
            app_name: "Second app".into(),
            app_id: Some("dev:second".into()),
            bases: vec![BaseGrantRequest::Existing {
                base: notes.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let second = device("second").install_app(credentials).await.unwrap();
    // A change for each app stops midway. Every change settles all pending apps,
    // so the first app's fails twice to stay pending through the second's.
    for (method, device, times) in [
        ("PUT", app.device_id(), 2),
        ("DELETE", second.device_id(), 1),
    ] {
        full.test_inject_fault(Fault {
            method,
            path: Box::leak(format!("v1/bases/{}/grants/{device}", notes.id()).into_boxed_str()),
            lost_reply: false,
            times,
        });
    }
    assert!(
        full.add_app_grant(
            app.device_id(),
            BaseGrantRequest::Existing {
                base: notes.id(),
                mode: Mode::ReadOnly,
            }
        )
        .await
        .is_err()
    );
    assert!(
        full.remove_app_grant(second.device_id(), notes.id())
            .await
            .is_err()
    );
    // The first app's device goes from the server, but its entry stays in account data.
    let (status, _) = raw_device(&full)
        .delete(&format!("/v1/devices/{}", app.device_id()), json!({}))
        .await;
    assert_eq!(status, StatusCode::OK);
    full.refresh().await.unwrap();
    assert!(full.apps().iter().all(|a| a.device_id != app.device_id()));
    assert!(full.test_app_readers(notes.id()).is_empty());
    second.refresh().await.unwrap();
    assert!(!ids(&second).contains(&notes.id()));
}

#[tokio::test]
async fn hidden_bases_are_never_granted_later() {
    let Setup { full, app, .. } = setup(false).await;
    let hidden = full
        .create_hidden_base("Diary", Zeroizing::new("ferry lantern quartz".into()))
        .await
        .unwrap();
    assert_eq!(
        full.add_app_grant(
            app.device_id(),
            BaseGrantRequest::Existing {
                base: hidden.id(),
                mode: Mode::ReadOnly,
            },
        )
        .await,
        Err(Error::Forbidden)
    );
    assert!(full.test_app_readers(hidden.id()).is_empty());
}

#[tokio::test]
async fn app_devices_cannot_change_grants() {
    let Setup {
        full,
        app,
        personal,
        notes,
    } = setup(false).await;
    assert_eq!(
        app.add_app_grant(
            app.device_id(),
            BaseGrantRequest::Existing {
                base: notes.id(),
                mode: Mode::ReadWrite,
            },
        )
        .await,
        Err(Error::Forbidden)
    );
    assert_eq!(
        app.remove_app_grant(app.device_id(), personal.id()).await,
        Err(Error::Forbidden)
    );
    assert!(app.mounts().is_empty());
    assert_eq!(
        full.add_app_grant(
            bh_core::DeviceId::random(),
            BaseGrantRequest::Existing {
                base: notes.id(),
                mode: Mode::ReadWrite,
            },
        )
        .await,
        Err(Error::NotFound)
    );
}
