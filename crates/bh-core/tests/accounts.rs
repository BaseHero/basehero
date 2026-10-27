use bh_core::test_support::Fault;
use bh_core::{Core, CoreConfig, DeviceKind, Error, FileSecretStore, RecoveryKit, SignIn};
use bh_testkit::{
    LocalServer, TEST_PASSWORD, device, local_only, new_signup, pending_device_for, raw_device,
    signin_for,
};
use std::sync::Arc;

fn with_password(account: &bh_core::Account, password: &str) -> SignIn {
    SignIn {
        password: password.to_string().into(),
        ..signin_for(account)
    }
}

#[tokio::test]
async fn sign_up_then_sign_in_with_kit_reaches_the_same_account() {
    let (a, kit) = device("mac").sign_up(new_signup()).await.unwrap();
    let b = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    assert_eq!(a.id(), b.id());
    assert_eq!(b.email(), a.email());
    assert_eq!(b.kind(), DeviceKind::Full);
    assert_ne!(a.device_id(), b.device_id());
    let names: Vec<_> = a
        .devices()
        .await
        .unwrap()
        .into_iter()
        .map(|d| d.name)
        .collect();
    assert!(
        names.contains(&"mac".into()) && names.contains(&"fold".into()),
        "{names:?}"
    );
    let devices = b.devices().await.unwrap();
    let this: Vec<_> = devices.iter().filter(|d| d.this_device).collect();
    assert_eq!(this.len(), 1);
    assert_eq!(
        (this[0].id, this[0].name.as_str(), this[0].status.as_str()),
        (b.device_id(), "fold", "active")
    );
}

#[tokio::test]
async fn wrong_kit_can_be_retried_on_the_same_pending_sign_in() {
    let (a, kit) = device("mac").sign_up(new_signup()).await.unwrap();
    let pending = device("fold").sign_in(signin_for(&a)).await.unwrap();
    let other = RecoveryKit::generate().display();
    assert_eq!(pending.with_kit(&other).await.unwrap_err(), Error::BadKit);
    assert_eq!(
        pending.with_kit("not a kit").await.unwrap_err(),
        Error::BadKit
    );
    let b = pending.with_kit(&kit.display()).await.unwrap();
    assert_eq!(b.id(), a.id());
    assert_eq!(
        pending.with_kit(&kit.display()).await.unwrap_err(),
        Error::Invalid("signed in".into())
    );
}

#[tokio::test]
async fn wrong_password_is_refused() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let result = device("fold")
        .sign_in(with_password(&a, "wrong password"))
        .await;
    assert_eq!(result.err(), Some(Error::BadCredentials));
}

#[tokio::test]
async fn unknown_email_is_refused_like_a_wrong_password() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let request = SignIn {
        email: format!("nobody-{}", a.email()),
        ..signin_for(&a)
    };
    assert_eq!(
        device("fold").sign_in(request).await.err(),
        Some(Error::BadCredentials)
    );
}

#[tokio::test]
async fn a_used_invite_and_a_taken_email_are_conflicts() {
    let first = new_signup();
    let (invite, email) = (first.invite.clone(), first.email.clone());
    device("mac").sign_up(first).await.unwrap();
    let reused = bh_core::SignUp {
        invite,
        ..new_signup()
    };
    assert_eq!(
        device("mac").sign_up(reused).await.err(),
        Some(Error::Conflict("invite_used".into()))
    );
    let taken = bh_core::SignUp {
        email,
        ..new_signup()
    };
    assert_eq!(
        device("mac").sign_up(taken).await.err(),
        Some(Error::Conflict("email_taken".into()))
    );
}

#[tokio::test]
async fn device_names_never_reach_the_server_in_readable_form() {
    local_only!();
    let (a, _) = device("Kitchen Laptop")
        .sign_up(new_signup())
        .await
        .unwrap();
    let names: Vec<_> = a
        .devices()
        .await
        .unwrap()
        .into_iter()
        .map(|d| d.name)
        .collect();
    assert_eq!(names, ["Kitchen Laptop"]);
    let mut stack = vec![LocalServer::from_env().persist_dir().to_path_buf()];
    let mut files = 0;
    while let Some(path) = stack.pop() {
        if path.is_dir() {
            stack.extend(std::fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
        } else if let Ok(bytes) = std::fs::read(&path) {
            files += 1;
            assert!(
                !bytes.windows(14).any(|w| w == b"Kitchen Laptop"),
                "{} holds the device name",
                path.display()
            );
        }
    }
    assert!(files > 0);
}

#[tokio::test]
async fn new_kit_replaces_the_old_one() {
    let (a, old) = device("mac").sign_up(new_signup()).await.unwrap();
    assert_eq!(
        a.new_kit("wrong password").await.unwrap_err(),
        Error::BadCredentials
    );
    let new = a.new_kit(TEST_PASSWORD).await.unwrap();
    assert_ne!(new, old);
    let pending = device("fold").sign_in(signin_for(&a)).await.unwrap();
    assert_eq!(
        pending.with_kit(&old.display()).await.unwrap_err(),
        Error::BadKit
    );
    assert_eq!(pending.with_kit(&new.display()).await.unwrap().id(), a.id());
}

#[tokio::test]
async fn change_password_keeps_the_account() {
    let (a, kit) = device("mac").sign_up(new_signup()).await.unwrap();
    assert_eq!(
        a.change_password(
            TEST_PASSWORD,
            &RecoveryKit::generate().display(),
            "new password"
        )
        .await
        .unwrap_err(),
        Error::BadKit
    );
    assert_eq!(
        a.change_password("wrong password", &kit.display(), "new password")
            .await
            .unwrap_err(),
        Error::BadKit
    );
    a.change_password(TEST_PASSWORD, &kit.display(), "new password")
        .await
        .unwrap();
    assert_eq!(
        device("fold").sign_in(signin_for(&a)).await.err(),
        Some(Error::BadCredentials)
    );
    let b = device("fold")
        .sign_in(with_password(&a, "new password"))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    assert_eq!(b.id(), a.id());
    // The device that changed the password stays signed in.
    assert_eq!(a.devices().await.unwrap().len(), 2);
}

fn fault(method: &'static str, path: &'static str, lost_reply: bool, times: u32) -> Fault {
    Fault {
        method,
        path,
        lost_reply,
        times,
    }
}

#[tokio::test]
async fn sign_up_returns_the_kit_when_the_device_name_cannot_be_written() {
    let core = device("mac");
    core.inject_fault(fault("PUT", "v1/account/data", false, 1));
    let (a, kit) = core.sign_up(new_signup()).await.unwrap();
    let b = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    assert_eq!(b.id(), a.id());
    let devices = a.devices().await.unwrap();
    let mac = devices.iter().find(|d| d.this_device).unwrap();
    assert_eq!(mac.name, "");
}

#[tokio::test]
async fn a_wrong_kit_or_password_changes_nothing() {
    // No account data exists, as after a sign-up whose name write failed.
    let core = device("mac");
    core.inject_fault(fault("PUT", "v1/account/data", false, 1));
    let (a, kit) = core.sign_up(new_signup()).await.unwrap();
    let mistyped = RecoveryKit::generate().display();
    assert_eq!(
        a.change_password(TEST_PASSWORD, &mistyped, "new password")
            .await
            .unwrap_err(),
        Error::BadKit
    );
    assert_eq!(
        a.change_password("wrong password", &kit.display(), "new password")
            .await
            .unwrap_err(),
        Error::BadKit
    );
    assert_eq!(
        a.new_kit("wrong password").await.unwrap_err(),
        Error::BadCredentials
    );
    let pending = device("fold").sign_in(signin_for(&a)).await.unwrap();
    assert_eq!(
        pending.with_kit(&mistyped).await.unwrap_err(),
        Error::BadKit
    );
    assert_eq!(pending.with_kit(&kit.display()).await.unwrap().id(), a.id());
}

#[tokio::test]
async fn new_kit_repeats_its_request_after_a_lost_reply() {
    let core = device("mac");
    let (a, _) = core.sign_up(new_signup()).await.unwrap();
    core.inject_fault(fault("PUT", "v1/account/credentials", true, 1));
    let new = a.new_kit(TEST_PASSWORD).await.unwrap();
    let b = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&new.display())
        .await
        .unwrap();
    assert_eq!(b.id(), a.id());
}

#[tokio::test]
async fn new_kit_asks_for_another_kit_when_it_cannot_confirm_one() {
    let core = device("mac");
    let (a, _) = core.sign_up(new_signup()).await.unwrap();
    core.inject_fault(fault("PUT", "v1/account/credentials", true, 2));
    let Err(Error::Network(message)) = a.new_kit(TEST_PASSWORD).await else {
        panic!("expected a network error");
    };
    assert!(message.contains("make a new kit"), "{message}");
    let new = a.new_kit(TEST_PASSWORD).await.unwrap();
    let pending = device("fold").sign_in(signin_for(&a)).await.unwrap();
    assert_eq!(pending.with_kit(&new.display()).await.unwrap().id(), a.id());
}

#[tokio::test]
async fn a_new_kit_from_another_device_works_for_change_password() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let new = a.new_kit(TEST_PASSWORD).await.unwrap();
    let b = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&new.display())
        .await
        .unwrap();
    b.change_password(TEST_PASSWORD, &new.display(), "new password")
        .await
        .unwrap();
}

#[tokio::test]
async fn a_reopened_core_lists_its_accounts() {
    let tmp = tempfile::tempdir().unwrap();
    let open = || {
        Core::open(CoreConfig {
            data_dir: tmp.path().join("data"),
            secrets: Arc::new(FileSecretStore::new(tmp.path().join("secrets")).unwrap()),
        })
    };
    let core = open().unwrap();
    let signup = bh_core::SignUp {
        device_name: "mac".into(),
        ..new_signup()
    };
    let (a, _) = core.sign_up(signup).await.unwrap();
    assert_eq!(core.accounts().len(), 1);
    // One core at a time uses a data directory, until its accounts are dropped too.
    drop(core);
    assert_eq!(
        open().err(),
        Some(Error::Storage("data directory in use".into()))
    );
    let (id, email, device_id) = (a.id(), a.email(), a.device_id());
    drop(a);
    let reopened = open().unwrap();
    assert_eq!(
        open().err(),
        Some(Error::Storage("data directory in use".into()))
    );
    let summaries = reopened.accounts();
    assert_eq!(summaries.len(), 1);
    assert_eq!(
        (summaries[0].id, summaries[0].email.as_str()),
        (id, email.as_str())
    );
    let again = reopened.account(id).unwrap();
    assert_eq!(again.device_id(), device_id);
    assert_eq!(again.devices().await.unwrap()[0].name, "mac");
    assert_eq!(
        reopened.account(bh_core::AccountId::random()).err(),
        Some(Error::NotFound)
    );
}

#[tokio::test]
async fn the_core_works_from_another_executor() {
    let core = device("mac");
    let (a, _) = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(core.sign_up(new_signup()))
    })
    .join()
    .unwrap()
    .unwrap();
    assert_eq!(a.devices().await.unwrap().len(), 1);
}

#[tokio::test]
async fn raw_devices_for_an_account() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let (status, me) = raw_device(&a).get("/v1/me", serde_json::json!({})).await;
    assert_eq!(status.as_u16(), 200);
    assert_eq!(me["deviceId"], a.device_id().to_string());
    let pending = pending_device_for(&a).await;
    let (status, body) = pending.get("/v1/account", serde_json::json!({})).await;
    assert_eq!(
        (status.as_u16(), body["error"].as_str()),
        (403, Some("pending"))
    );
}
