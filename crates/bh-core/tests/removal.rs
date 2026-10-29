//! Device removal through the real local Worker and encrypted core stores.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bh_core::{
    Account, AccountEvent, AccountId, AppRequest, BaseGrantRequest, Core, CoreConfig, DeviceId,
    Error, FileSecretStore, Mode, SecretStore,
};
use bh_testkit::{new_signup, raw_device, two_devices_sharing_a_base, wait_for, wait_for_base};
use futures_util::StreamExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn local_core(dir: &std::path::Path) -> (Core, Arc<FileSecretStore>) {
    let secrets = Arc::new(FileSecretStore::new(dir.join("secrets")).unwrap());
    let core = Core::open(CoreConfig {
        data_dir: dir.join("data"),
        secrets: secrets.clone(),
    })
    .unwrap();
    (core, secrets)
}

#[tokio::test]
async fn a_removed_device_is_refused_and_erases_itself() {
    let (a, kit) = bh_testkit::device("a").sign_up(new_signup()).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (core, secrets) = local_core(dir.path());
    let b = core
        .sign_in(bh_core::SignIn {
            device_name: "fold".into(),
            ..bh_testkit::signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let base = a.create_base("Shared").await.unwrap();
    base.flush().await.unwrap();
    b.refresh().await.unwrap();
    let b_base = b.base(base.id()).unwrap();
    wait_for_base(&b_base, || b_base.sync_state().online).await;
    let old = raw_device(&b);
    let mut events = b.events();
    let start = Instant::now();
    a.remove_device(b.device_id()).await.unwrap();
    wait_for(|| core.accounts().is_empty()).await;
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "revocation was slow"
    );
    assert!(matches!(events.try_recv(), Ok(AccountEvent::Removed)));
    assert!(
        !dir.path()
            .join("data/accounts")
            .join(b.id().to_string())
            .exists()
    );
    for suffix in ["key", "token", "dbkey"] {
        assert!(
            secrets
                .get(&format!("acct.{}.{suffix}", b.id()))
                .unwrap()
                .is_none()
        );
    }
    assert!(
        secrets
            .get(&format!("base.{}.dbkey", base.id()))
            .unwrap()
            .is_none()
    );
    let (status, body) = old.get("/v1/me", serde_json::json!({})).await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "revoked");
}

#[tokio::test]
async fn removing_a_device_without_an_open_base_erases_it() {
    let (a, kit) = bh_testkit::device("a").sign_up(new_signup()).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (core, secrets) = local_core(dir.path());
    let b = core
        .sign_in(bh_core::SignIn {
            device_name: "fold".into(),
            ..bh_testkit::signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let mut events = b.events();
    // Ensure the approval listener is connected before triggering removal.
    wait_for(|| b.test_request_count("v1/approvals/live") > 0).await;
    a.remove_device(b.device_id()).await.unwrap();
    wait_for(|| core.accounts().is_empty()).await;
    assert!(matches!(events.try_recv(), Ok(AccountEvent::Removed)));
    assert!(
        secrets
            .get(&format!("acct.{}.token", b.id()))
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn removal_closes_the_live_socket() {
    let (a, b) = two_devices_sharing_a_base().await;
    wait_for_base(&b.base, || b.base.sync_state().online).await;
    let mut socket = raw_device(&b.account)
        .live(&format!("/v1/bases/{}/live", b.base.id()))
        .await;
    a.account
        .remove_device(b.account.device_id())
        .await
        .unwrap();
    let message = tokio::time::timeout(Duration::from_secs(30), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // The removing device's notice comes with it.
    let message: serde_json::Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
    assert_eq!(message["t"], "revoked");
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(message["notice"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    let close = tokio::time::timeout(Duration::from_secs(30), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    match close {
        tokio_tungstenite::tungstenite::Message::Close(Some(frame)) => {
            assert_eq!(u16::from(frame.code), 4001);
        }
        other => panic!("expected revocation close, got {other:?}"),
    }
}

#[tokio::test]
async fn removing_this_device_signs_out() {
    let dir = tempfile::tempdir().unwrap();
    let (core, secrets) = local_core(dir.path());
    let (account, _) = core
        .sign_up(bh_core::SignUp {
            device_name: "mac".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let old = raw_device(&account);
    let mut events = account.events();
    account.remove_device(account.device_id()).await.unwrap();
    assert!(core.accounts().is_empty());
    assert!(
        !dir.path()
            .join("data/accounts")
            .join(account.id().to_string())
            .exists()
    );
    assert!(
        secrets
            .get(&format!("acct.{}.token", account.id()))
            .unwrap()
            .is_none()
    );
    assert!(matches!(events.try_recv(), Ok(AccountEvent::Removed)));
    let (status, body) = old.get("/v1/me", serde_json::json!({})).await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "revoked");
}

#[tokio::test]
async fn a_network_error_does_not_erase_local_data() {
    let dir = tempfile::tempdir().unwrap();
    let (core, secrets) = local_core(dir.path());
    let (account, _) = core
        .sign_up(bh_core::SignUp {
            device_name: "mac".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    core.inject_fault(bh_core::test_support::Fault {
        method: "GET",
        path: "v1/account",
        lost_reply: false,
        times: 1,
    });
    assert!(matches!(account.devices().await, Err(Error::Network(_))));
    assert_eq!(core.accounts().len(), 1);
    assert!(
        dir.path()
            .join("data/accounts")
            .join(account.id().to_string())
            .exists()
    );
    assert!(
        secrets
            .get(&format!("acct.{}.token", account.id()))
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn a_fanout_502_still_erases_this_device() {
    let dir = tempfile::tempdir().unwrap();
    let (core, _) = local_core(dir.path());
    let (account, _) = core
        .sign_up(bh_core::SignUp {
            device_name: "mac".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let base = account.create_base("Shared").await.unwrap();
    let old = raw_device(&account);
    let fault = format!("/v1/bases/{}/fail-next-device-close", base.id());
    assert_eq!(
        old.post(&fault, serde_json::json!({})).await.0,
        reqwest::StatusCode::OK
    );
    account.remove_device(account.device_id()).await.unwrap();
    assert!(core.accounts().is_empty());
    assert_eq!(
        account.test_request_count("v1/me"),
        1,
        "confirm the fanout 502"
    );
    let (status, body) = old.get("/v1/me", serde_json::json!({})).await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "revoked");
}

#[tokio::test]
async fn pre_revocation_502_keeps_the_device_and_original_error() {
    let dir = tempfile::tempdir().unwrap();
    let (core, secrets) = local_core(dir.path());
    let (account, _) = core
        .sign_up(bh_core::SignUp {
            device_name: "mac".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let old = raw_device(&account);
    assert_eq!(
        old.post("/v1/devices/fail-next-removal", serde_json::json!({}))
            .await
            .0,
        reqwest::StatusCode::OK
    );
    assert_eq!(
        account.remove_device(account.device_id()).await,
        Err(Error::Network("pre-revocation fault".into()))
    );
    assert_eq!(account.test_request_count("v1/me"), 1);
    assert_eq!(core.accounts().len(), 1);
    assert!(core.account(account.id()).is_ok());
    assert!(
        secrets
            .get(&format!("acct.{}.token", account.id()))
            .unwrap()
            .is_some()
    );
    assert!(
        dir.path()
            .join("data/accounts")
            .join(account.id().to_string())
            .exists()
    );
    assert_eq!(
        old.get("/v1/me", serde_json::json!({})).await.0,
        reqwest::StatusCode::OK
    );
}

#[tokio::test]
async fn ambiguous_removal_only_erases_after_revocation_is_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let (core, secrets) = local_core(dir.path());
    let (account, _) = core
        .sign_up(bh_core::SignUp {
            device_name: "mac".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let id = account.id();
    core.inject_fault(bh_core::test_support::Fault {
        method: "DELETE",
        path: "v1/devices/",
        lost_reply: false,
        times: 1,
    });
    assert!(matches!(
        account.remove_device(account.device_id()).await,
        Err(Error::Network(_))
    ));
    assert_eq!(core.accounts().len(), 1);
    assert!(secrets.get(&format!("acct.{id}.token")).unwrap().is_some());
    core.inject_fault(bh_core::test_support::Fault {
        method: "DELETE",
        path: "v1/devices/",
        lost_reply: true,
        times: 1,
    });
    account.remove_device(account.device_id()).await.unwrap();
    assert!(core.accounts().is_empty());
    assert!(secrets.get(&format!("acct.{id}.token")).unwrap().is_none());
}

#[tokio::test]
async fn a_removed_app_loses_its_grants() {
    let (a, _) = bh_testkit::device("a").sign_up(new_signup()).await.unwrap();
    let base = a.create_base("Shared").await.unwrap();
    let credentials = a
        .connect_app(AppRequest {
            app_name: "Demo".into(),
            app_id: Some("dev:demo".into()),
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = bh_testkit::device("app")
        .install_app(credentials)
        .await
        .unwrap();
    let token = raw_device(&app);
    let path = format!("/v1/bases/{}/key", base.id());
    assert_eq!(
        token.get(&path, serde_json::json!({})).await.0,
        reqwest::StatusCode::OK
    );
    a.remove_device(app.device_id()).await.unwrap();
    for path in ["/v1/me", path.as_str()] {
        let (status, body) = token.get(path, serde_json::json!({})).await;
        assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED, "{path}: {body}");
        assert_eq!(body["error"], "revoked", "{path}");
    }
}

#[tokio::test]
async fn sign_out_erases_local_data() {
    let dir = tempfile::tempdir().unwrap();
    let (core, secrets) = local_core(dir.path());
    let (account, _) = core
        .sign_up(bh_core::SignUp {
            device_name: "mac".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let base = account.create_base("Erase me").await.unwrap();
    let id = account.id();
    let account_dir = dir.path().join("data/accounts").join(id.to_string());
    assert!(account_dir.exists());
    assert!(
        secrets
            .get(&format!("base.{}.dbkey", base.id()))
            .unwrap()
            .is_some()
    );
    let mut events = account.events();
    account.sign_out().await.unwrap();
    assert!(core.accounts().is_empty());
    assert!(!account_dir.exists());
    assert!(secrets.get(&format!("acct.{id}.key")).unwrap().is_none());
    assert!(secrets.get(&format!("acct.{id}.token")).unwrap().is_none());
    assert!(
        secrets
            .get(&format!("base.{}.dbkey", base.id()))
            .unwrap()
            .is_none()
    );
    assert!(matches!(events.try_recv(), Ok(AccountEvent::Removed)));
    account.sign_out().await.unwrap();
    assert!(events.try_recv().is_err(), "Removed was sent twice");
}

#[tokio::test]
async fn removing_blocks_existing_note_and_base_open_before_erasure() {
    let dir = tempfile::tempdir().unwrap();
    let (core, _) = local_core(dir.path());
    let (account, _) = core
        .sign_up(bh_core::SignUp {
            device_name: "mac".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let base = account.create_base("Erase me").await.unwrap();
    let note = base
        .create(bh_core::NewObject {
            ty: bh_core::TypeRef::new("core.note", 1),
            parent: None,
            after: None,
            fields: Default::default(),
        })
        .unwrap();
    let doc = base.note(note).unwrap();
    let base_id = base.id();
    let gate = core.test_hold_next_erase();
    let removing = tokio::spawn({
        let account = account.clone();
        async move { account.sign_out().await }
    });
    let account_dir = dir
        .path()
        .join("data/accounts")
        .join(account.id().to_string());
    wait_for(|| account_dir.join(".erasing").exists()).await;
    assert!(matches!(account.base(base_id), Err(Error::Revoked)));
    assert!(matches!(doc.apply(0, &[]), Err(Error::Revoked)));
    assert!(matches!(
        base.create(bh_core::NewObject {
            ty: bh_core::TypeRef::new("core.note", 1),
            parent: None,
            after: None,
            fields: Default::default(),
        }),
        Err(Error::Revoked)
    ));
    gate.add_permits(1);
    removing.await.unwrap().unwrap();
    assert!(!account_dir.exists());
}

#[tokio::test]
async fn running_hero_turn_ends_before_erasure() {
    let dir = tempfile::tempdir().unwrap();
    let (core, _) = local_core(dir.path());
    let (account, _) = core
        .sign_up(bh_core::SignUp {
            device_name: "mac".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let base = account.create_base("Chat").await.unwrap();
    let model = bh_models::testing::ScriptedModel::new(vec![bh_models::testing::Scripted::Hang]);
    let hero = account.hero_with_model(model.clone());
    let chat = hero.new_chat(base.id()).unwrap();
    hero.send(base.id(), chat, "Hello", None).unwrap();
    wait_for(|| !model.requests().is_empty()).await;
    account.sign_out().await.unwrap();
    assert!(matches!(
        hero.send(base.id(), chat, "Again", None),
        Err(Error::Revoked)
    ));
    assert!(
        !dir.path()
            .join("data/accounts")
            .join(account.id().to_string())
            .exists()
    );
}

#[tokio::test]
async fn failed_erase_remains_blocked_and_core_open_finishes_it() {
    let dir = tempfile::tempdir().unwrap();
    let (core, secrets) = local_core(dir.path());
    let (account, _) = core
        .sign_up(bh_core::SignUp {
            device_name: "mac".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let base = account.create_base("Erase me").await.unwrap();
    let id = account.id();
    let base_id = base.id();
    core.test_fail_next_erase();
    assert!(matches!(account.sign_out().await, Err(Error::Storage(_))));
    assert!(core.accounts().is_empty());
    assert!(matches!(core.account(id), Err(Error::NotFound)));
    assert!(matches!(account.base(base_id), Err(Error::Revoked)));
    assert!(matches!(account.sign_out().await, Err(Error::Revoked)));
    drop((base, account, core));
    let (reopened, _) = local_core(dir.path());
    assert!(reopened.accounts().is_empty());
    assert!(
        !dir.path()
            .join("data/accounts")
            .join(id.to_string())
            .exists()
    );
    assert!(
        secrets
            .get(&format!("base.{base_id}.dbkey"))
            .unwrap()
            .is_none()
    );
}

/// What a removing device sends: `generichash(key = kdf(K, "bhremov1", 1), account ‖ device)`.
fn notice(key: &[u8], account: AccountId, device: DeviceId) -> String {
    let key = bh_crypto::kdf(
        &bh_crypto::Secret::<32>::from_slice(key).unwrap(),
        b"bhremov1",
        1,
    );
    URL_SAFE_NO_PAD.encode(bh_crypto::generichash(
        Some(key.expose()),
        &[&account.0, &device.0],
    ))
}

fn account_key(account: &Account) -> Vec<u8> {
    account
        .test_secrets()
        .get(&format!("acct.{}.key", account.id()))
        .unwrap()
        .unwrap()
        .to_vec()
}

/// What a hostile server, or a stolen full-device token, can do: revoke a device
/// with no notice, or with one that isn't for it.
async fn revoke(by: &Account, device: DeviceId, notice: Option<String>) {
    let body = notice.map_or(
        serde_json::json!({}),
        |n| serde_json::json!({ "notice": n }),
    );
    let (status, body) = raw_device(by)
        .delete(&format!("/v1/devices/{device}"), body)
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
}

/// The first removal event: `SignedOutByServer` keeps the device, `Removed` erases it.
async fn removal_event(
    events: &mut tokio::sync::broadcast::Receiver<AccountEvent>,
) -> AccountEvent {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let event = events.recv().await.unwrap();
            if matches!(
                event,
                AccountEvent::Removed | AccountEvent::SignedOutByServer
            ) {
                return event;
            }
        }
    })
    .await
    .expect("no removal event within 30 s")
}

fn assert_kept(core: &Core, dir: &std::path::Path, secrets: &FileSecretStore, account: &Account) {
    let id = account.id();
    assert!(
        core.account(id).is_ok(),
        "the account was taken off this device"
    );
    assert!(dir.join("data/accounts").join(id.to_string()).exists());
    let key = match account.kind() {
        bh_core::DeviceKind::Full => "key",
        bh_core::DeviceKind::App => "appkey",
    };
    for suffix in [key, "token", "dbkey"] {
        assert!(
            secrets
                .get(&format!("acct.{id}.{suffix}"))
                .unwrap()
                .is_some(),
            "acct.{suffix} was erased"
        );
    }
    assert!(account.signed_out_by_server());
}

#[tokio::test]
async fn a_server_revoking_without_a_notice_keeps_the_device() {
    let (a, kit) = bh_testkit::device("a").sign_up(new_signup()).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (core, secrets) = local_core(dir.path());
    let b = core
        .sign_in(bh_core::SignIn {
            device_name: "fold".into(),
            ..bh_testkit::signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let base = a.create_base("Shared").await.unwrap();
    base.flush().await.unwrap();
    b.refresh().await.unwrap();
    let b_base = b.base(base.id()).unwrap();
    wait_for_base(&b_base, || b_base.sync_state().online).await;
    let note = b_base
        .create(bh_core::NewObject {
            ty: bh_core::TypeRef::new("core.note", 1),
            parent: None,
            after: None,
            fields: Default::default(),
        })
        .unwrap();
    b_base.flush().await.unwrap();
    let mut events = b.events();
    // The open base hears `{"t":"revoked"}` live, with no notice.
    revoke(&a, b.device_id(), None).await;
    assert!(matches!(
        removal_event(&mut events).await,
        AccountEvent::SignedOutByServer
    ));
    assert_kept(&core, dir.path(), &secrets, &b);
    // A window opened later reads the state from the account list.
    assert!(core.accounts()[0].signed_out_by_server);
    assert!(
        secrets
            .get(&format!("base.{}.dbkey", base.id()))
            .unwrap()
            .is_some()
    );
    // Sync stops; the local copy stays readable.
    wait_for_base(&b_base, || !b_base.sync_state().online).await;
    assert!(b_base.get(note).unwrap().is_some());
    assert_eq!(b.base(base.id()).unwrap().id(), base.id());
    // Later 401 revoked answers over HTTP don't erase it either.
    assert_eq!(b.devices().await.unwrap_err(), Error::Revoked);
    assert_kept(&core, dir.path(), &secrets, &b);
    // Erasing stays the person's choice.
    b.sign_out().await.unwrap();
    assert!(core.accounts().is_empty());
    assert!(
        secrets
            .get(&format!("acct.{}.key", b.id()))
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_notice_for_another_device_or_account_is_refused() {
    let (a, kit) = bh_testkit::device("a").sign_up(new_signup()).await.unwrap();
    let (other, _) = bh_testkit::device("other")
        .sign_up(new_signup())
        .await
        .unwrap();
    // The right account's key for another device, then another account's key.
    for i in 0..2 {
        let dir = tempfile::tempdir().unwrap();
        let (core, secrets) = local_core(dir.path());
        let b = core
            .sign_in(bh_core::SignIn {
                device_name: "fold".into(),
                ..bh_testkit::signin_for(&a)
            })
            .await
            .unwrap()
            .with_kit(&kit.display())
            .await
            .unwrap();
        let mut events = b.events();
        let wrong = match i {
            0 => notice(&account_key(&a), a.id(), DeviceId::random()),
            _ => notice(&account_key(&other), other.id(), b.device_id()),
        };
        revoke(&a, b.device_id(), Some(wrong)).await;
        // An HTTP answer with the wrong notice.
        assert_eq!(b.devices().await.unwrap_err(), Error::Revoked, "case {i}");
        assert!(
            matches!(
                removal_event(&mut events).await,
                AccountEvent::SignedOutByServer
            ),
            "case {i}"
        );
        assert_kept(&core, dir.path(), &secrets, &b);
    }
    // The same account's key for the right device is a genuine notice.
    let dir = tempfile::tempdir().unwrap();
    let (core, _) = local_core(dir.path());
    let b = core
        .sign_in(bh_core::SignIn {
            device_name: "fold".into(),
            ..bh_testkit::signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    revoke(
        &a,
        b.device_id(),
        Some(notice(&account_key(&a), a.id(), b.device_id())),
    )
    .await;
    assert_eq!(b.devices().await.unwrap_err(), Error::Revoked);
    wait_for(|| core.accounts().is_empty()).await;
}

#[tokio::test]
async fn an_app_erases_only_on_a_notice_from_its_own_key() {
    let (a, _) = bh_testkit::device("a").sign_up(new_signup()).await.unwrap();
    let base = a.create_base("Shared").await.unwrap();
    // Revoked with no notice, with a notice from the account key rather than the app's
    // key, then removed by the person's own device.
    for case in 0..3 {
        let credentials = a
            .connect_app(AppRequest {
                app_name: "Demo".into(),
                app_id: Some(format!("dev:demo{case}")),
                bases: vec![BaseGrantRequest::Existing {
                    base: base.id(),
                    mode: Mode::ReadOnly,
                }],
                replaces: None,
            })
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (core, secrets) = local_core(dir.path());
        let app = core.install_app(credentials).await.unwrap();
        app.refresh().await.unwrap();
        let mut events = app.events();
        match case {
            0 => revoke(&a, app.device_id(), None).await,
            1 => {
                let wrong = notice(&account_key(&a), a.id(), app.device_id());
                revoke(&a, app.device_id(), Some(wrong)).await;
            }
            _ => a.remove_device(app.device_id()).await.unwrap(),
        }
        assert_eq!(
            app.refresh().await.unwrap_err(),
            Error::Revoked,
            "case {case}"
        );
        if case < 2 {
            assert!(
                matches!(
                    removal_event(&mut events).await,
                    AccountEvent::SignedOutByServer
                ),
                "case {case}"
            );
            assert_kept(&core, dir.path(), &secrets, &app);
        } else {
            wait_for(|| core.accounts().is_empty()).await;
            assert!(matches!(
                removal_event(&mut events).await,
                AccountEvent::Removed
            ));
            assert!(
                secrets
                    .get(&format!("acct.{}.appkey", app.id()))
                    .unwrap()
                    .is_none()
            );
        }
    }
}

#[tokio::test]
async fn an_app_removing_itself_erases_itself() {
    let (a, _) = bh_testkit::device("a").sign_up(new_signup()).await.unwrap();
    let base = a.create_base("Shared").await.unwrap();
    let credentials = a
        .connect_app(AppRequest {
            app_name: "Demo".into(),
            app_id: Some("dev:demo".into()),
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (core, secrets) = local_core(dir.path());
    let app = core.install_app(credentials).await.unwrap();
    let old = raw_device(&app);
    let app_key = secrets
        .get(&format!("acct.{}.appkey", app.id()))
        .unwrap()
        .unwrap()
        .to_vec();
    app.remove_device(app.device_id()).await.unwrap();
    assert!(core.accounts().is_empty());
    assert!(
        secrets
            .get(&format!("acct.{}.appkey", app.id()))
            .unwrap()
            .is_none()
    );
    let (status, body) = old.get("/v1/me", serde_json::json!({})).await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "revoked");
    // The notice it sent is its own.
    assert_eq!(body["notice"], notice(&app_key, app.id(), app.device_id()));
}

fn new_note() -> bh_core::NewObject {
    bh_core::NewObject {
        ty: bh_core::TypeRef::new("core.note", 1),
        parent: None,
        after: None,
        fields: Default::default(),
    }
}

/// Keeps local reads and writes, but never says the server has them.
async fn assert_stopped(base: &bh_core::Base, label: &str) {
    let note = base.create(new_note()).unwrap();
    assert!(base.get(note).unwrap().is_some());
    let state = base.sync_state();
    assert!(!state.online, "{label}");
    assert!(state.pending > 0, "{label}");
    let flushed = base.flush().await;
    assert!(
        matches!(flushed, Err(Error::Network(_))),
        "{label}: {flushed:?}"
    );
    let synced = base.sync_now().await;
    assert!(
        matches!(synced, Err(Error::Network(_))),
        "{label}: {synced:?}"
    );
}

#[tokio::test]
async fn bases_opened_after_a_server_sign_out_never_report_a_sync() {
    let dir = tempfile::tempdir().unwrap();
    let (core, _) = local_core(dir.path());
    let (account, _) = core
        .sign_up(bh_core::SignUp {
            device_name: "mac".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let password = || zeroize::Zeroizing::new("ferry lantern quartz".to_string());
    let base = account.create_base("Kept").await.unwrap();
    base.flush().await.unwrap();
    let id = base.id();
    drop(base);
    let hidden = account
        .create_hidden_base("Diary", password())
        .await
        .unwrap();
    hidden.flush().await.unwrap();
    let hidden_id = hidden.id();
    drop(hidden);
    account.lock_hidden(hidden_id).await.unwrap();
    let open = account.create_base("Open").await.unwrap();
    wait_for_base(&open, || open.sync_state().online).await;
    let mut events = account.events();
    revoke(&account, account.device_id(), None).await;
    assert_eq!(account.devices().await.unwrap_err(), Error::Revoked);
    assert!(matches!(
        removal_event(&mut events).await,
        AccountEvent::SignedOutByServer
    ));
    // A base open at the time, one reopened after, and a hidden one unlocked after.
    assert_stopped(&open, "open").await;
    assert_stopped(&account.base(id).unwrap(), "reopened").await;
    account.unlock_hidden(password()).await.unwrap();
    assert_stopped(&account.base(hidden_id).unwrap(), "hidden").await;
}

#[tokio::test]
async fn a_server_sign_out_waits_for_a_hidden_unlock_and_stops_its_sync() {
    let dir = tempfile::tempdir().unwrap();
    let (core, _) = local_core(dir.path());
    let (account, _) = core
        .sign_up(bh_core::SignUp {
            device_name: "mac".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let password = || zeroize::Zeroizing::new("ferry lantern quartz".to_string());
    let hidden = account
        .create_hidden_base("Diary", password())
        .await
        .unwrap();
    let hidden_id = hidden.id();
    drop(hidden);
    account.lock_hidden(hidden_id).await.unwrap();
    let (release, entered) = account.test_hold_next_hidden_open();
    let unlocking = tokio::spawn({
        let account = account.clone();
        async move { account.unlock_hidden(password()).await }
    });
    wait_for(|| entered.load(std::sync::atomic::Ordering::SeqCst)).await;
    let mut events = account.events();
    revoke(&account, account.device_id(), None).await;
    assert_eq!(account.devices().await.unwrap_err(), Error::Revoked);
    // Stopping shares the unlock's gate, so it can't miss the base being opened.
    assert!(
        tokio::time::timeout(Duration::from_secs(1), removal_event(&mut events))
            .await
            .is_err(),
        "stopped while a hidden base was being opened"
    );
    release.add_permits(1);
    unlocking.await.unwrap().unwrap();
    assert!(matches!(
        removal_event(&mut events).await,
        AccountEvent::SignedOutByServer
    ));
    assert_stopped(&account.base(hidden_id).unwrap(), "hidden").await;
}
