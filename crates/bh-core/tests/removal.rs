//! Device removal through the real local Worker and encrypted core stores.

use bh_core::{
    AccountEvent, AppRequest, BaseGrantRequest, Core, CoreConfig, Error, FileSecretStore, Mode,
    SecretStore,
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
    assert_eq!(message.to_text().unwrap(), "{\"t\":\"revoked\"}");
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
