//! A removed full device's stolen local copy must not open later server data.

use bh_core::{Account, AccountId, Base, Core, CoreConfig, FileSecretStore, SecretStore, SignIn};
use bh_testkit::{new_signup, note_with_text, request_count, signin_for, wait_for_base};
use std::{fs, path::Path, sync::Arc};
use tempfile::TempDir;
use zeroize::Zeroizing;

fn local_core(dir: &Path) -> (Core, Arc<FileSecretStore>) {
    let secrets = Arc::new(FileSecretStore::new(dir.join("secrets")).unwrap());
    let core = Core::open(CoreConfig {
        data_dir: dir.join("data"),
        secrets: secrets.clone(),
    })
    .unwrap();
    (core, secrets)
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), dest).unwrap();
        }
    }
}

fn stolen_copy(dir: &Path) -> TempDir {
    let stolen = tempfile::tempdir().unwrap();
    copy_tree(&dir.join("data"), &stolen.path().join("data"));
    copy_tree(&dir.join("secrets"), &stolen.path().join("secrets"));
    stolen
}

fn attacker(
    stolen: &Path,
    live_token_from: &FileSecretStore,
    account: AccountId,
) -> (Core, Account) {
    let token_name = format!("acct.{account}.token");
    let live_token = live_token_from.get(&token_name).unwrap().unwrap();
    let stolen_secrets = FileSecretStore::new(stolen.join("secrets")).unwrap();
    stolen_secrets.put(&token_name, &live_token).unwrap();
    let (core, _) = local_core(stolen);
    let account = core.account(account).unwrap();
    (core, account)
}

async fn wait_for_catch_up_attempt(account: &Account, base: &Base) {
    let path = format!("v1/bases/{}/since", base.id());
    for _ in 0..20 {
        let before = request_count(account, &path);
        // The sync task resolves the flush only after its round has handled
        // the /since reply (or the round's error). An early pre-sync error
        // cannot satisfy the count check.
        let _ = base.flush().await;
        if request_count(account, &path) > before {
            return;
        }
        // The first round may already have finished before the count above.
        // Force another catch-up instead of treating an old count as evidence.
        let before = request_count(account, &path);
        let _ = base.sync_now().await;
        if request_count(account, &path) > before {
            return;
        }
    }
    panic!("attacker never completed or failed a post-removal /since request for {path}");
}

fn password() -> Zeroizing<String> {
    Zeroizing::new(bh_testkit::TEST_PASSWORD.to_string())
}

async fn server_base_key(account: &Account, base: bh_core::BaseId) -> serde_json::Value {
    let server = bh_testkit::LocalServer::from_env();
    let token = bh_testkit::raw_device(account).token;
    let reply = reqwest::Client::new()
        .get(server.url().join(&format!("/v1/bases/{base}/key")).unwrap())
        .header("BH-Protocol", "2")
        .header("BH-Test-Bypass", server.operator_token())
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), reqwest::StatusCode::OK);
    reply.json().await.unwrap()
}

fn note_texts(base: &Base) -> Vec<String> {
    let mut pending = vec![None];
    let mut texts = Vec::new();
    while let Some(parent) = pending.pop() {
        for child in base.children(parent).unwrap() {
            if child.ty.name == "core.note" {
                texts.push(base.note(child.id).unwrap().text());
            }
            pending.push(Some(child.id));
        }
    }
    texts
}

#[tokio::test]
async fn disconnecting_an_app_rekeys_its_bases() {
    use bh_core::{AppRequest, BaseGrantRequest, Mode, Removal};
    let a_dir = tempfile::tempdir().unwrap();
    let (core, a_secrets) = local_core(a_dir.path());
    let (a, _) = core
        .sign_up(bh_core::SignUp {
            device_name: "mac".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let base = a.create_base("Shared").await.unwrap();
    let before = note_with_text(&base, "before");
    base.flush().await.unwrap();
    let connect = |name: &str| AppRequest {
        app_name: name.into(),
        app_id: None,
        bases: vec![BaseGrantRequest::Existing {
            base: base.id(),
            mode: Mode::ReadWrite,
        }],
        replaces: None,
    };
    let dir = tempfile::tempdir().unwrap();
    let (app_core, _) = local_core(dir.path());
    let removed = app_core
        .install_app(a.connect_app(connect("removed")).await.unwrap())
        .await
        .unwrap();
    let remaining = bh_testkit::device("remaining")
        .install_app(a.connect_app(connect("remaining")).await.unwrap())
        .await
        .unwrap();
    removed.refresh().await.unwrap();
    remaining.refresh().await.unwrap();
    let old_reader = removed.base(base.id()).unwrap();
    wait_for_base(&old_reader, || old_reader.note(before).is_ok()).await;
    let stolen = stolen_copy(dir.path());
    let account_epoch = server_base_key(&a, base.id()).await["accountEpoch"].clone();
    let outcome = a
        .remove_device(removed.device_id(), Removal::Plain)
        .await
        .unwrap();
    assert!(!outcome.pending);
    assert_eq!(
        server_base_key(&a, base.id()).await["accountEpoch"],
        account_epoch
    );
    let after = note_with_text(&base, "after");
    base.flush().await.unwrap();
    remaining.refresh().await.unwrap();
    let reader = remaining.base(base.id()).unwrap();
    wait_for_base(&reader, || {
        reader.note(before).is_ok() && reader.note(after).is_ok()
    })
    .await;
    let (_stolen_core, stolen_account) = attacker(stolen.path(), &a_secrets, a.id());
    let _ = stolen_account.refresh().await;
    let old = stolen_account.base(base.id()).unwrap();
    wait_for_catch_up_attempt(&stolen_account, &old).await;
    assert!(old.note(before).is_ok());
    assert!(
        old.note(after).is_err(),
        "removed app opened a later note with its old key"
    );
}

#[tokio::test]
async fn a_lost_app_delete_reply_survives_a_later_account_data_write() {
    use bh_core::{AppRequest, BaseGrantRequest, Mode, Removal, test_support::Fault};
    let (a, b) = bh_testkit::two_devices().await;
    let base = a.create_base("Shared").await.unwrap();
    let credentials = a
        .connect_app(AppRequest {
            app_name: "reader".into(),
            app_id: None,
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = bh_testkit::device("reader")
        .install_app(credentials)
        .await
        .unwrap();
    b.refresh().await.unwrap();
    let (release, entered) = a.test_hold_next_delete_reply();
    a.test_inject_fault(Fault {
        method: "DELETE",
        path: "v1/devices/",
        lost_reply: true,
        times: 1,
    });
    let removing = {
        let a = a.clone();
        let id = app.device_id();
        tokio::spawn(async move { a.remove_device(id, Removal::Plain).await })
    };
    // DELETE committed; its reply has not reached A.
    bh_testkit::wait_entered(&entered, std::panic::Location::caller()).await;
    let (_, before) = bh_testkit::raw_device(&b)
        .get("/v1/account", serde_json::json!({}))
        .await;
    b.refresh().await.unwrap(); // Re-key and clear the pending entry in another data write.
    let (_, after) = bh_testkit::raw_device(&b)
        .get("/v1/account", serde_json::json!({}))
        .await;
    assert!(
        after["data"]["version"].as_u64().unwrap() > before["data"]["version"].as_u64().unwrap()
    );
    release.add_permits(1);
    let outcome = removing.await.unwrap().unwrap();
    assert!(!outcome.pending);
    assert!(
        !a.devices()
            .await
            .unwrap()
            .iter()
            .any(|d| d.id == app.device_id() && d.pending_removal)
    );
    assert!(
        server_base_key(&a, base.id()).await["dataFloor"]
            .as_u64()
            .unwrap()
            > 0
    );
}

#[tokio::test]
async fn another_device_finishes_an_interrupted_app_removal() {
    use bh_core::{AppRequest, BaseGrantRequest, Mode, Removal, test_support::Fault};
    let (a, b) = bh_testkit::two_devices().await;
    let base = a.create_base("Shared").await.unwrap();
    let credentials = a
        .connect_app(AppRequest {
            app_name: "reader".into(),
            app_id: None,
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = bh_testkit::device("reader")
        .install_app(credentials)
        .await
        .unwrap();
    b.refresh().await.unwrap();
    a.test_inject_fault(Fault {
        method: "POST",
        path: "v1/bases/",
        lost_reply: false,
        times: 1,
    });
    let result = a
        .remove_device(app.device_id(), Removal::Plain)
        .await
        .unwrap();
    assert!(result.pending);
    assert!(
        a.devices()
            .await
            .unwrap()
            .iter()
            .any(|d| d.id == app.device_id() && d.pending_removal)
    );
    assert!(a.test_app_readers(base.id()).contains(&app.device_id()));
    b.refresh().await.unwrap();
    assert!(
        !b.devices()
            .await
            .unwrap()
            .iter()
            .any(|d| d.id == app.device_id() && d.pending_removal)
    );
    assert!(!b.test_app_readers(base.id()).contains(&app.device_id()));
    assert!(
        server_base_key(&a, base.id()).await["dataFloor"]
            .as_u64()
            .unwrap()
            > 0
    );
}

#[tokio::test]
async fn full_removal_returns_kit_while_base_rekey_is_pending_and_then_clears_devices() {
    // Catches returning only after the re-key POST reply, and losing the pending
    // device marker before all ordinary bases have advanced.
    let (a, b) = bh_testkit::two_devices().await;
    let base = a.create_base("Shared").await.unwrap();
    let (release, entered) = a.test_hold_next_hidden_rekey_reply();
    let mut events = a.events();
    let removed = b.device_id();
    let removing = tokio::spawn({
        let a = a.clone();
        async move {
            a.remove_device(
                removed,
                bh_core::Removal::Full {
                    password: password(),
                    lost: true,
                },
            )
            .await
        }
    });
    // The reply is held after the server commits the first base re-key.
    bh_testkit::wait_entered(&entered, std::panic::Location::caller()).await;
    tokio::task::yield_now().await;
    let returned_while_held = removing.is_finished();
    let pending = a
        .devices()
        .await
        .unwrap()
        .into_iter()
        .find(|d| d.id == removed)
        .unwrap();
    while events.try_recv().is_ok() {} // Ignore the commit event; require the clearing event.
    release.add_permits(1);
    assert!(
        returned_while_held,
        "removal waited for the base re-key reply"
    );
    let outcome = removing.await.unwrap().unwrap();
    assert!(
        outcome.new_kit.is_some(),
        "replacement kit must arrive at commit"
    );
    assert!(outcome.pending);
    assert_eq!(pending.name, "b");
    assert!(pending.pending_removal);
    a.wait_for_removals().await.unwrap();
    assert!(
        !a.devices()
            .await
            .unwrap()
            .into_iter()
            .find(|d| d.id == removed)
            .unwrap()
            .pending_removal
    );
    assert_eq!(server_base_key(&a, base.id()).await["accountEpoch"], 2);
    assert!(
        std::iter::from_fn(|| events.try_recv().ok())
            .any(|event| matches!(event, bh_core::AccountEvent::DevicesChanged))
    );
}

#[tokio::test]
async fn signing_out_stops_a_held_background_rekey_before_erasing() {
    let dir = tempfile::tempdir().unwrap();
    let (core, _) = local_core(dir.path());
    let (a, kit) = core
        .sign_up(bh_core::SignUp {
            device_name: "original".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let b = bh_testkit::device("removed")
        .sign_in(SignIn {
            device_name: "removed".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let base = a.create_base("Shared").await.unwrap();
    let (release, entered) = a.test_hold_next_hidden_rekey_reply();
    let account_dir = dir.path().join("data/accounts").join(a.id().to_string());
    let outcome = a
        .remove_device(
            b.device_id(),
            bh_core::Removal::Full {
                password: password(),
                lost: false,
            },
        )
        .await
        .unwrap();
    assert!(outcome.pending);
    bh_testkit::wait_entered(&entered, std::panic::Location::caller()).await;
    assert!(a.test_background_rekey_running());
    a.sign_out().await.unwrap();
    let after_erase = a.test_request_count("v1/");
    release.add_permits(1);
    tokio::task::yield_now().await;
    assert!(
        !a.test_background_rekey_running(),
        "re-key worker survived sign-out"
    );
    assert_eq!(
        a.test_request_count("v1/"),
        after_erase,
        "worker made requests after erase"
    );
    assert!(!account_dir.exists(), "account directory survived erase");
    drop(base);
}

#[tokio::test]
async fn another_device_finishes_a_full_removal_after_the_remover_closes() {
    // Catches a pending marker that exists only in the removing device's cache.
    use bh_core::test_support::Fault;
    let dir = tempfile::tempdir().unwrap();
    let (core, _) = local_core(dir.path());
    let (a, kit) = core
        .sign_up(bh_core::SignUp {
            device_name: "original".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let b = bh_testkit::device("other")
        .sign_in(SignIn {
            device_name: "other".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let c = bh_testkit::device("removed")
        .sign_in(SignIn {
            device_name: "removed".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    b.refresh().await.unwrap();
    let base = a.create_base("Shared").await.unwrap();
    a.test_inject_fault(Fault {
        method: "POST",
        path: "v1/bases/",
        lost_reply: false,
        times: 1,
    });
    let removed = c.device_id();
    let outcome = a
        .remove_device(
            removed,
            bh_core::Removal::Full {
                password: password(),
                lost: false,
            },
        )
        .await
        .unwrap();
    assert!(outcome.pending);
    assert!(
        b.devices()
            .await
            .unwrap()
            .iter()
            .any(|d| d.id == removed && d.pending_removal)
    );
    drop((a, core));
    b.refresh().await.unwrap();
    b.wait_for_removals().await.unwrap();
    assert_eq!(server_base_key(&b, base.id()).await["accountEpoch"], 2);
    assert!(
        !b.devices()
            .await
            .unwrap()
            .iter()
            .any(|d| d.id == removed && d.pending_removal)
    );
}

#[tokio::test]
async fn removing_a_full_device_advances_the_account_and_base_epochs() {
    let (a, b) = bh_testkit::two_devices().await;
    let base = a.create_base("Shared").await.unwrap();
    let before = bh_testkit::raw_device(&a);
    let (_, state) = before.get("/v1/me", serde_json::json!({})).await;
    assert_eq!(state["epoch"], 1);
    a.remove_device(
        b.device_id(),
        bh_core::Removal::Full {
            password: password(),
            lost: false,
        },
    )
    .await
    .unwrap();
    let server = bh_testkit::LocalServer::from_env();
    let read = |path: String| {
        let token = before.token.clone();
        let url = server.url().join(&path).unwrap();
        let bypass = server.operator_token().to_string();
        async move {
            reqwest::Client::new()
                .get(url)
                .header("BH-Protocol", "2")
                .header("BH-Test-Bypass", bypass)
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap()
        }
    };
    let state = read("/v1/me".into()).await;
    assert_eq!(state["epoch"], 2, "{state}");
    a.wait_for_removals().await.unwrap();
    let key = read(format!("/v1/bases/{}/key", base.id())).await;
    assert_eq!(key["accountEpoch"], 2, "{key}");
}

#[tokio::test]
async fn removing_a_device_gives_everyone_else_new_keys_silently() {
    let (a, b) = bh_testkit::two_devices().await;
    let kit = a.recovery_kit().unwrap().unwrap();
    let c = bh_testkit::device("phone")
        .sign_in(SignIn {
            device_name: "phone".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    b.refresh().await.unwrap();
    use bh_core::{AppRequest, BaseGrantRequest, Mode};
    let status = a.kit_status().unwrap();
    let base = a.create_base("Shared").await.unwrap();
    let old = note_with_text(&base, "before");
    base.flush().await.unwrap();
    let credentials = a
        .connect_app(AppRequest {
            app_name: "reader".into(),
            app_id: None,
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = bh_testkit::device("reader")
        .install_app(credentials)
        .await
        .unwrap();
    app.refresh().await.unwrap();
    let outcome = a
        .remove_device(
            c.device_id(),
            bh_core::Removal::Full {
                password: password(),
                lost: false,
            },
        )
        .await
        .unwrap();
    assert!(outcome.pending);
    a.wait_for_removals().await.unwrap();
    assert!(outcome.new_kit.is_none());
    assert_eq!(a.kit_status().unwrap(), status);
    b.refresh().await.unwrap();
    app.refresh().await.unwrap();
    let fresh = note_with_text(&base, "after");
    base.flush().await.unwrap();
    for reader in [&b, &app] {
        let opened = reader.base(base.id()).unwrap();
        wait_for_base(&opened, || {
            opened.note(old).is_ok() && opened.note(fresh).is_ok()
        })
        .await;
    }
    let newcomer = bh_testkit::device("new")
        .sign_in(SignIn {
            device_name: "new".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    newcomer.refresh().await.unwrap();
    let ring = b
        .test_secrets()
        .get(&format!("acct.{}.key", b.id()))
        .unwrap()
        .unwrap();
    assert_eq!(u32::from_be_bytes(ring[36..40].try_into().unwrap()), 2);
}

#[tokio::test]
async fn a_wrong_password_removes_nothing() {
    let (a, b) = bh_testkit::two_devices().await;
    let result = a
        .remove_device(
            b.device_id(),
            bh_core::Removal::Full {
                password: "not the account password".to_string().into(),
                lost: true,
            },
        )
        .await;
    assert!(matches!(result, Err(bh_core::Error::BadCredentials)));
    b.refresh().await.unwrap();
    assert_eq!(
        a.test_secrets()
            .get(&format!("acct.{}.key", a.id()))
            .unwrap()
            .unwrap()
            .len(),
        36
    );
    assert!(
        a.devices()
            .await
            .unwrap()
            .iter()
            .any(|d| d.id == b.device_id() && d.status == "active")
    );
}

#[tokio::test]
async fn removing_a_lost_device_makes_a_new_kit() {
    let (a, b) = bh_testkit::two_devices().await;
    let old = a.recovery_kit().unwrap().unwrap();
    let base = a.create_base("Shared").await.unwrap();
    let old_note = note_with_text(&base, "before");
    base.flush().await.unwrap();
    let result = a
        .remove_device(
            b.device_id(),
            bh_core::Removal::Full {
                password: password(),
                lost: true,
            },
        )
        .await
        .unwrap();
    assert!(result.pending);
    let kit = result.new_kit.unwrap();
    a.wait_for_removals().await.unwrap();
    assert_ne!(kit, old);
    let signin = || SignIn {
        device_name: "new".into(),
        ..signin_for(&a)
    };
    assert!(matches!(
        bh_testkit::device("wrong kit")
            .sign_in(signin())
            .await
            .unwrap()
            .with_kit(&old.display())
            .await,
        Err(bh_core::Error::BadKit)
    ));
    let c = bh_testkit::device("new kit")
        .sign_in(signin())
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    c.refresh().await.unwrap();
    let new_note = note_with_text(&base, "after");
    base.flush().await.unwrap();
    let opened = c.base(base.id()).unwrap();
    wait_for_base(&opened, || {
        opened.note(old_note).is_ok() && opened.note(new_note).is_ok()
    })
    .await;
    let mut approval = bh_testkit::device("approved")
        .sign_in(signin())
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) =
        tokio::try_join!(a.open_request(approval.id()), approval.digits()).unwrap();
    a.approve(open, &digits).await.unwrap();
    let approved = approval.wait().await.unwrap();
    approved.refresh().await.unwrap();
    let approved_base = approved.base(base.id()).unwrap();
    wait_for_base(&approved_base, || approved_base.note(old_note).is_ok()).await;
}

#[tokio::test]
async fn an_idle_rekey_refresh_fetches_a_base_key_only_once() {
    let (a, _) = bh_testkit::two_devices().await;
    let base = a.create_base("Idle").await.unwrap();
    let path = format!("v1/bases/{}/key", base.id());
    let before = request_count(&a, &path);
    a.finish_rekeys().await.unwrap();
    assert_eq!(request_count(&a, &path) - before, 1);
}

#[tokio::test]
async fn a_base_rekey_uses_one_authenticated_account_snapshot() {
    let (a, _) = bh_testkit::device("a").sign_up(new_signup()).await.unwrap();
    let base = a.create_base("Snapshot").await.unwrap();
    let before = request_count(&a, "v1/account?afterEpoch=");
    a.test_rekey_base(base.id()).await.unwrap();
    assert_eq!(request_count(&a, "v1/account?afterEpoch=") - before, 1);
}

#[tokio::test]
async fn a_lost_reply_to_the_removal_still_succeeds() {
    use bh_core::test_support::Fault;
    let (a, b) = bh_testkit::two_devices().await;
    a.test_inject_fault(Fault {
        method: "DELETE",
        path: "v1/devices/",
        lost_reply: true,
        times: 1,
    });
    let outcome = a
        .remove_device(
            b.device_id(),
            bh_core::Removal::Full {
                password: password(),
                lost: false,
            },
        )
        .await
        .unwrap();
    assert!(outcome.pending);
    a.wait_for_removals().await.unwrap();
    assert_eq!(
        a.test_secrets()
            .get(&format!("acct.{}.key", a.id()))
            .unwrap()
            .unwrap()
            .len(),
        72
    );
}

#[tokio::test]
async fn a_lost_full_delete_reply_survives_another_devices_completed_rekeys() {
    use bh_core::test_support::Fault;
    let (a, b) = bh_testkit::two_devices().await;
    let base = a.create_base("Shared").await.unwrap();
    b.refresh().await.unwrap();
    let (release, entered) = a.test_hold_next_delete_reply();
    a.test_inject_fault(Fault {
        method: "DELETE",
        path: "v1/devices/",
        lost_reply: true,
        times: 1,
    });
    let removed = bh_testkit::device("removed")
        .sign_in(SignIn {
            device_name: "removed".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&a.recovery_kit().unwrap().unwrap().display())
        .await
        .unwrap();
    let removing = tokio::spawn({
        let a = a.clone();
        async move {
            a.remove_device(
                removed.device_id(),
                bh_core::Removal::Full {
                    password: password(),
                    lost: true,
                },
            )
            .await
        }
    });
    bh_testkit::wait_entered(&entered, std::panic::Location::caller()).await;
    b.refresh().await.unwrap();
    b.wait_for_removals().await.unwrap();
    assert_eq!(server_base_key(&b, base.id()).await["accountEpoch"], 2);
    b.new_kit(bh_testkit::TEST_PASSWORD).await.unwrap(); // Changes the committed envelope.
    release.add_permits(1);
    let outcome = removing
        .await
        .unwrap()
        .expect("confirmed DELETE survived a later kit and data write");
    assert!(outcome.new_kit.is_some());
    a.wait_for_removals().await.unwrap();
}

#[tokio::test]
async fn a_lost_reply_to_a_competing_rotation_preserves_the_network_error() {
    use bh_core::test_support::Fault;
    let (a, b) = bh_testkit::two_devices().await;
    let c = bh_testkit::device("target")
        .sign_in(SignIn {
            device_name: "target".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&a.recovery_kit().unwrap().unwrap().display())
        .await
        .unwrap();
    b.refresh().await.unwrap();
    let (release, entered) = a.test_hold_next_delete_send();
    a.test_inject_fault(Fault {
        method: "DELETE",
        path: "v1/devices/",
        lost_reply: true,
        times: 1,
    });
    let target = c.device_id();
    let removing = tokio::spawn(async move {
        a.remove_device(
            target,
            bh_core::Removal::Full {
                password: password(),
                lost: false,
            },
        )
        .await
    });
    bh_testkit::wait_entered(&entered, std::panic::Location::caller()).await;
    b.remove_device(
        target,
        bh_core::Removal::Full {
            password: password(),
            lost: false,
        },
    )
    .await
    .unwrap();
    release.add_permits(1);
    assert!(matches!(
        removing.await.unwrap(),
        Err(bh_core::Error::Network(_))
    ));
}

#[tokio::test]
async fn a_post_commit_read_failure_returns_the_new_kit_and_finishes_on_refresh() {
    use bh_core::test_support::Fault;
    let (a, b) = bh_testkit::two_devices().await;
    let old_kit = a.recovery_kit().unwrap().unwrap();
    let base = a.create_base("Shared").await.unwrap();
    let (release, entered) = a.test_hold_next_delete_reply();
    let inject = async {
        bh_testkit::wait_entered(&entered, std::panic::Location::caller()).await;
        a.test_inject_fault(Fault {
            method: "GET",
            path: "v1/account?afterEpoch=1",
            lost_reply: false,
            times: 1,
        });
        release.add_permits(1);
    };
    let (result, ()) = tokio::join!(
        a.remove_device(
            b.device_id(),
            bh_core::Removal::Full {
                password: password(),
                lost: true,
            }
        ),
        inject
    );
    let outcome =
        result.expect("the DELETE committed; a later read must not turn success into an error");
    assert!(outcome.pending);
    let kit = outcome
        .new_kit
        .expect("the replacement kit must reach the caller");
    assert_ne!(kit, old_kit);
    assert_eq!(server_base_key(&a, base.id()).await["accountEpoch"], 1);
    a.refresh().await.unwrap();
    assert_eq!(server_base_key(&a, base.id()).await["accountEpoch"], 2);
    a.finish_rekeys().await.unwrap();
}

#[tokio::test]
async fn an_interrupted_removal_is_finished_by_another_device() {
    use bh_core::test_support::Fault;
    let (a, b) = bh_testkit::two_devices().await;
    let kit = a.recovery_kit().unwrap().unwrap();
    let c = bh_testkit::device("c")
        .sign_in(SignIn {
            device_name: "c".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let base = a.create_base("Shared").await.unwrap();
    b.refresh().await.unwrap();
    a.test_inject_fault(Fault {
        method: "POST",
        path: "v1/bases/",
        lost_reply: false,
        times: 1,
    });
    let outcome = a
        .remove_device(
            c.device_id(),
            bh_core::Removal::Full {
                password: password(),
                lost: false,
            },
        )
        .await
        .unwrap();
    assert!(outcome.pending);
    // Prevent A from doing any further base work; B must advance the server.
    let rekey_path: &'static str =
        Box::leak(format!("v1/bases/{}/rekey", base.id()).into_boxed_str());
    a.test_inject_fault(Fault {
        method: "POST",
        path: rekey_path,
        lost_reply: false,
        times: 100,
    });
    assert_eq!(server_base_key(&a, base.id()).await["accountEpoch"], 1);
    b.refresh().await.unwrap();
    assert_eq!(server_base_key(&b, base.id()).await["accountEpoch"], 2);
    let old = note_with_text(&base, "before");
    base.flush().await.unwrap();
    let second = b.base(base.id()).unwrap();
    wait_for_base(&second, || second.note(old).is_ok()).await;
}

#[tokio::test]
async fn two_removals_at_once_both_land() {
    let (a, b) = bh_testkit::two_devices().await;
    let kit = a.recovery_kit().unwrap().unwrap();
    let c = bh_testkit::device("c")
        .sign_in(SignIn {
            device_name: "c".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let d = bh_testkit::device("d")
        .sign_in(SignIn {
            device_name: "d".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    c.refresh().await.unwrap();
    d.refresh().await.unwrap();
    let base = a.create_base("Shared").await.unwrap();
    let before = note_with_text(&base, "before");
    base.flush().await.unwrap();
    let (release_a, entered_a) = a.test_hold_next_delete_send();
    let (release_b, entered_b) = b.test_hold_next_delete_send();
    let release = async {
        let (first, second) = tokio::join!(entered_a.acquire(), entered_b.acquire());
        first.unwrap().forget();
        second.unwrap().forget();
        release_a.add_permits(1);
        release_b.add_permits(1);
    };
    let (first, second, ()) = tokio::join!(
        a.remove_device(
            c.device_id(),
            bh_core::Removal::Full {
                password: password(),
                lost: false
            }
        ),
        b.remove_device(
            d.device_id(),
            bh_core::Removal::Full {
                password: password(),
                lost: false
            }
        ),
        release,
    );
    assert!(first.unwrap().pending);
    assert!(second.unwrap().pending);
    a.wait_for_removals().await.unwrap();
    b.wait_for_removals().await.unwrap();
    let attempts = a.test_request_count(&format!("v1/devices/{}", c.device_id()))
        + b.test_request_count(&format!("v1/devices/{}", d.device_id()));
    assert!(
        attempts >= 3,
        "one DELETE must encounter a conflict and retry; got {attempts}"
    );
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    let after = note_with_text(&base, "after");
    base.flush().await.unwrap();
    let opened = b.base(base.id()).unwrap();
    wait_for_base(&opened, || {
        opened.note(before).is_ok() && opened.note(after).is_ok()
    })
    .await;
    let ring = b
        .test_secrets()
        .get(&format!("acct.{}.key", b.id()))
        .unwrap()
        .unwrap();
    assert_eq!(u32::from_be_bytes(ring[72..76].try_into().unwrap()), 3);
    assert_eq!(server_base_key(&a, base.id()).await["accountEpoch"], 3);
    assert!(
        a.devices()
            .await
            .unwrap()
            .iter()
            .filter(|d| d.status == "revoked")
            .count()
            >= 2
    );
}

#[tokio::test]
async fn a_second_full_removal_waits_for_background_rekeys_without_deadlock() {
    let (a, b) = bh_testkit::two_devices().await;
    let kit = a.recovery_kit().unwrap().unwrap();
    let c = bh_testkit::device("c")
        .sign_in(SignIn {
            device_name: "c".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    c.refresh().await.unwrap();
    let base = a.create_base("Shared").await.unwrap();
    let (release, entered) = a.test_hold_next_hidden_rekey_reply();
    a.remove_device(
        b.device_id(),
        bh_core::Removal::Full {
            password: password(),
            lost: false,
        },
    )
    .await
    .unwrap();
    bh_testkit::wait_entered(&entered, std::panic::Location::caller()).await;
    let second = tokio::spawn({
        let a = a.clone();
        async move {
            a.remove_device(
                c.device_id(),
                bh_core::Removal::Full {
                    password: password(),
                    lost: false,
                },
            )
            .await
        }
    });
    release.add_permits(1);
    second.await.unwrap().unwrap();
    a.wait_for_removals().await.unwrap();
    assert_eq!(server_base_key(&a, base.id()).await["accountEpoch"], 3);
    assert!(
        a.devices()
            .await
            .unwrap()
            .iter()
            .filter(|d| d.id == b.device_id() || d.name == "c")
            .all(|d| d.status == "revoked" && !d.pending_removal)
    );
}

#[tokio::test]
async fn a_lost_reply_to_a_rekey_keeps_one_key() {
    use bh_core::test_support::Fault;
    let (a, b) = bh_testkit::two_devices().await;
    let kit = a.recovery_kit().unwrap().unwrap();
    let c = bh_testkit::device("c")
        .sign_in(SignIn {
            device_name: "c".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    b.refresh().await.unwrap();
    let base = a.create_base("Shared").await.unwrap();
    let before = note_with_text(&base, "before");
    base.flush().await.unwrap();
    a.test_inject_fault(Fault {
        method: "POST",
        path: "v1/bases/",
        lost_reply: true,
        times: 1,
    });
    let outcome = a
        .remove_device(
            c.device_id(),
            bh_core::Removal::Full {
                password: password(),
                lost: false,
            },
        )
        .await
        .unwrap();
    assert!(outcome.pending);
    a.wait_for_removals().await.unwrap();
    b.refresh().await.unwrap();
    let after = note_with_text(&base, "after");
    base.flush().await.unwrap();
    let opened = b.base(base.id()).unwrap();
    wait_for_base(&opened, || {
        opened.note(before).is_ok() && opened.note(after).is_ok()
    })
    .await;
    let from_a = server_base_key(&a, base.id()).await;
    let from_b = server_base_key(&b, base.id()).await;
    assert_eq!(from_a["epoch"], 2);
    assert_eq!(from_a["accountEpoch"], 2);
    assert_eq!(from_a["wrapper"], from_b["wrapper"]);
    assert_eq!(from_a["epoch"], from_b["epoch"]);
}

#[tokio::test]
async fn a_device_offline_across_two_removals_catches_up() {
    let (a, b) = bh_testkit::two_devices().await;
    let kit = a.recovery_kit().unwrap().unwrap();
    let c = bh_testkit::device("c")
        .sign_in(SignIn {
            device_name: "c".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let d = bh_testkit::device("d")
        .sign_in(SignIn {
            device_name: "d".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    d.refresh().await.unwrap();
    let base = a.create_base("Shared").await.unwrap();
    b.refresh().await.unwrap();
    let on_b = b.base(base.id()).unwrap();
    on_b.test_pause_sync();
    let edited = note_with_text(&on_b, "from offline fold");
    a.remove_device(
        c.device_id(),
        bh_core::Removal::Full {
            password: password(),
            lost: false,
        },
    )
    .await
    .unwrap();
    a.remove_device(
        d.device_id(),
        bh_core::Removal::Full {
            password: password(),
            lost: false,
        },
    )
    .await
    .unwrap();
    b.refresh().await.unwrap();
    on_b.test_resume_sync();
    on_b.flush().await.unwrap();
    let on_a = a.base(base.id()).unwrap();
    wait_for_base(&on_a, || on_a.note(edited).is_ok()).await;
    a.wait_for_removals().await.unwrap();
    let server_key = server_base_key(&a, base.id()).await;
    assert_eq!(server_key["accountEpoch"], 3);
    assert_eq!(server_key["epoch"], 3);
    let fresh = bh_testkit::device("new")
        .sign_in(SignIn {
            device_name: "new".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    fresh.refresh().await.unwrap();
    let fresh_base = fresh.base(base.id()).unwrap();
    wait_for_base(&fresh_base, || fresh_base.note(edited).is_ok()).await;
    assert!(c.refresh().await.is_err());
    c.settle_removal().await.unwrap();
    assert!(
        c.test_secrets()
            .get(&format!("acct.{}.key", c.id()))
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn an_app_keeps_reading_after_a_device_is_removed() {
    use bh_core::{AppRequest, BaseGrantRequest, Mode};
    let (a, b) = bh_testkit::two_devices().await;
    let kit = a.recovery_kit().unwrap().unwrap();
    let c = bh_testkit::device("phone")
        .sign_in(SignIn {
            device_name: "phone".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let base = a.create_base("Shared").await.unwrap();
    let old = note_with_text(&base, "before");
    base.flush().await.unwrap();
    let credentials = a
        .connect_app(AppRequest {
            app_name: "reader".into(),
            app_id: None,
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = bh_testkit::device("reader")
        .install_app(credentials)
        .await
        .unwrap();
    app.refresh().await.unwrap();
    b.refresh().await.unwrap();
    let result = a
        .remove_device(
            c.device_id(),
            bh_core::Removal::Full {
                password: password(),
                lost: false,
            },
        )
        .await
        .unwrap();
    assert!(result.pending);
    a.wait_for_removals().await.unwrap();
    app.refresh().await.unwrap();
    let fresh = note_with_text(&base, "after");
    base.flush().await.unwrap();
    let opened = app.base(base.id()).unwrap();
    wait_for_base(&opened, || {
        opened.note(old).is_ok() && opened.note(fresh).is_ok()
    })
    .await;
}

#[tokio::test]
async fn refresh_finishes_a_base_created_elsewhere_before_the_removal() {
    use bh_core::test_support::Fault;
    let (a, b) = bh_testkit::two_devices().await;
    let kit = a.recovery_kit().unwrap().unwrap();
    let c = bh_testkit::device("phone")
        .sign_in(SignIn {
            device_name: "phone".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    b.refresh().await.unwrap();
    let base = b.create_base("Created on Fold").await.unwrap();
    // A has never listed this base locally. The inventory must still include it.
    a.test_inject_fault(Fault {
        method: "POST",
        path: "v1/bases/",
        lost_reply: false,
        times: 1,
    });
    let outcome = a
        .remove_device(
            c.device_id(),
            bh_core::Removal::Full {
                password: password(),
                lost: false,
            },
        )
        .await
        .unwrap();
    assert!(outcome.pending);
    a.refresh().await.unwrap();
    assert_eq!(server_base_key(&a, base.id()).await["accountEpoch"], 2);
    let after = note_with_text(&base, "after");
    base.flush().await.unwrap();
    let a_base = a.base(base.id()).unwrap();
    wait_for_base(&a_base, || a_base.note(after).is_ok()).await;
}

#[tokio::test]
async fn a_rekey_across_account_adoption_never_seals_to_an_old_app_key() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use bh_core::{AppRequest, BaseGrantRequest, Mode, Removal, test_support};
    let (a, b) = bh_testkit::two_devices().await;
    let kit = a.recovery_kit().unwrap().unwrap();
    let removed = bh_testkit::device("lost")
        .sign_in(SignIn {
            device_name: "lost".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let base = a.create_base("Shared").await.unwrap();
    let credentials = a
        .connect_app(AppRequest {
            app_name: "reader".into(),
            app_id: None,
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadWrite,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let old_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(credentials.app_key.as_bytes())
        .unwrap()
        .try_into()
        .unwrap();
    let app = bh_testkit::device("reader")
        .install_app(credentials)
        .await
        .unwrap();
    b.refresh().await.unwrap();
    let (release_key, entered_key) = a.test_hold_next_base_key_reply();
    let rekey = {
        let a = a.clone();
        let id = base.id();
        tokio::spawn(async move { a.test_rekey_base(id).await })
    };
    bh_testkit::wait_entered(&entered_key, std::panic::Location::caller()).await;
    let (release_delete, entered_delete) = b.test_hold_next_delete_reply();
    let removal = {
        let b = b.clone();
        let id = removed.device_id();
        tokio::spawn(async move {
            b.remove_device(
                id,
                Removal::Full {
                    password: password(),
                    lost: false,
                },
            )
            .await
        })
    };
    // Account epoch 2 committed; base still at 1.
    bh_testkit::wait_entered(&entered_delete, std::panic::Location::caller()).await;
    a.devices().await.unwrap(); // Adopt epoch 2 without finishing its bases.
    release_key.add_permits(1);
    let _ = rekey.await.unwrap();
    let key = server_base_key(&app, base.id()).await;
    if key["accountEpoch"] == 2 {
        let wrapper = URL_SAFE_NO_PAD
            .decode(key["wrapper"].as_str().unwrap())
            .unwrap();
        assert!(
            test_support::open_app_wrapper(&wrapper, &old_key, base.id(), app.device_id()).is_err(),
            "a post-rotation base wrapper opened with the old app key"
        );
    }
    release_delete.add_permits(1);
    removal.await.unwrap().unwrap();
    b.wait_for_removals().await.unwrap();
    a.refresh().await.unwrap();
    let key = server_base_key(&app, base.id()).await;
    assert_eq!(key["accountEpoch"], 2);
    let wrapper = URL_SAFE_NO_PAD
        .decode(key["wrapper"].as_str().unwrap())
        .unwrap();
    assert!(
        test_support::open_app_wrapper(&wrapper, &old_key, base.id(), app.device_id()).is_err()
    );
}

#[tokio::test]
async fn a_full_device_without_a_published_public_key_does_not_block_removal() {
    let (a, old) = bh_testkit::two_devices().await;
    let kit = a.recovery_kit().unwrap().unwrap();
    let removed = bh_testkit::device("lost")
        .sign_in(SignIn {
            device_name: "lost".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let base = a.create_base("Shared").await.unwrap();
    old.refresh().await.unwrap();
    let old_base = old.base(base.id()).unwrap();
    a.test_forget_device_public(old.device_id()).await.unwrap();
    a.remove_device(
        removed.device_id(),
        bh_core::Removal::Full {
            password: password(),
            lost: false,
        },
    )
    .await
    .unwrap();
    a.wait_for_removals().await.unwrap();
    let new_note = note_with_text(&base, "after removal");
    base.flush().await.unwrap();
    let _ = old.refresh().await;
    wait_for_catch_up_attempt(&old, &old_base).await;
    assert!(
        old_base.note(new_note).is_err(),
        "old-build device opened new content"
    );
}

#[tokio::test]
async fn protocol_one_cannot_remove_another_full_device_before_rotation() {
    use bh_core::DeviceId;
    let (a, b) = bh_testkit::two_devices().await;
    let old = bh_testkit::raw_device(&a);
    let path = format!("/v1/devices/{}", b.device_id());
    let (status, result) = old.delete(&path, serde_json::json!({})).await;
    assert_eq!(status, reqwest::StatusCode::UPGRADE_REQUIRED, "{result}");
    assert_eq!(result["error"], "needs_update");
    let (status, _) = old.get("/v1/account", serde_json::json!({})).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let app = DeviceId::random();
    let (status, _) = old
        .post(
            "/v1/devices",
            serde_json::json!({"deviceId": app, "kind": "app"}),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let (status, _) = old
        .delete(&format!("/v1/devices/{app}"), serde_json::json!({}))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let (status, _) = bh_testkit::raw_device(&b)
        .delete(
            &format!("/v1/devices/{}", b.device_id()),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn an_unrecorded_server_app_does_not_block_a_full_removal_or_disconnect() {
    use bh_core::{DeviceId, Removal};
    let (a, removed) = bh_testkit::two_devices().await;
    let app = DeviceId::random();
    let (status, body) = bh_testkit::raw_device(&a)
        .post(
            "/v1/devices",
            serde_json::json!({ "deviceId": app, "kind": "app" }),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    a.remove_device(
        removed.device_id(),
        Removal::Full {
            password: password(),
            lost: false,
        },
    )
    .await
    .unwrap();
    a.wait_for_removals().await.unwrap();
    a.remove_device(app, Removal::Plain).await.unwrap();
    assert!(
        !a.devices()
            .await
            .unwrap()
            .iter()
            .any(|d| d.id == app && d.status == "active")
    );
}

#[tokio::test]
async fn a_failed_pending_rekey_does_not_block_the_next_full_removal() {
    use bh_core::test_support::Fault;
    let (a, b) = bh_testkit::two_devices().await;
    let kit = a.recovery_kit().unwrap().unwrap();
    let c = bh_testkit::device("c")
        .sign_in(SignIn {
            device_name: "c".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let d = bh_testkit::device("d")
        .sign_in(SignIn {
            device_name: "d".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    b.refresh().await.unwrap();
    d.refresh().await.unwrap();
    let base = a.create_base("Shared").await.unwrap();
    a.test_inject_fault(Fault {
        method: "POST",
        path: "v1/bases/",
        lost_reply: false,
        times: 2,
    });
    assert!(
        a.remove_device(
            c.device_id(),
            bh_core::Removal::Full {
                password: password(),
                lost: false,
            }
        )
        .await
        .unwrap()
        .pending
    );
    assert!(
        a.remove_device(
            d.device_id(),
            bh_core::Removal::Full {
                password: password(),
                lost: false
            }
        )
        .await
        .unwrap()
        .pending
    );
    a.wait_for_removals().await.unwrap();
    assert_eq!(server_base_key(&a, base.id()).await["accountEpoch"], 3);
    assert!(
        !a.devices()
            .await
            .unwrap()
            .iter()
            .any(|entry| entry.pending_removal)
    );
}

#[tokio::test]
async fn an_unopenable_ordinary_base_does_not_report_finished() {
    let (a, b) = bh_testkit::two_devices().await;
    let base = a.create_base("Shared").await.unwrap();
    let (status, body) = bh_testkit::raw_device(&a)
        .post(
            &format!("/v1/bases/{}/rekey", base.id()),
            serde_json::json!({
                "from": 1, "wrapper": "AQ", "previous": "AQ", "apps": [],
                "accountEpoch": 1, "dataVersion": 1_000_000,
            }),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    let result = a
        .remove_device(
            b.device_id(),
            bh_core::Removal::Full {
                password: password(),
                lost: false,
            },
        )
        .await
        .unwrap();
    assert!(
        result.pending,
        "an ordinary base cannot be re-keyed without its key"
    );
}

#[tokio::test]
async fn a_stuck_base_does_not_block_other_bases_or_clear_the_removal() {
    let (a, b) = bh_testkit::two_devices().await;
    let stuck = a.create_base("Stuck").await.unwrap();
    let healthy = a.create_base("Healthy").await.unwrap();
    let (status, body) = bh_testkit::raw_device(&a)
        .post(
            &format!("/v1/bases/{}/rekey", stuck.id()),
            serde_json::json!({
                "from": 1, "wrapper": "AQ", "previous": "AQ", "apps": [],
                "accountEpoch": 1, "dataVersion": 1_000_000,
            }),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    a.remove_device(
        b.device_id(),
        bh_core::Removal::Full {
            password: password(),
            lost: false,
        },
    )
    .await
    .unwrap();
    assert!(a.finish_rekeys().await.is_err());
    assert_eq!(server_base_key(&a, healthy.id()).await["accountEpoch"], 2);
    assert!(
        a.devices()
            .await
            .unwrap()
            .iter()
            .any(|entry| entry.pending_removal)
    );
}

#[tokio::test]
async fn a_test_rotation_without_a_target_uses_a_disposable_app() {
    let (a, b) = bh_testkit::two_devices().await;
    b.refresh().await.unwrap();
    a.test_rotate_account(None).await.unwrap();
    b.refresh().await.unwrap();
    let stored = b
        .test_secrets()
        .get(&format!("acct.{}.key", b.id()))
        .unwrap()
        .unwrap();
    assert_eq!(u32::from_be_bytes(stored[36..40].try_into().unwrap()), 2);
}

#[tokio::test]
async fn a_device_adopts_an_authenticated_new_account_key() {
    let (a, b) = bh_testkit::two_devices().await;
    let base = a.create_base("Shared").await.unwrap();
    let old = note_with_text(&base, "before");
    base.flush().await.unwrap();
    b.refresh().await.unwrap();
    let c = bh_testkit::device("phone")
        .sign_in(SignIn {
            device_name: "phone".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&a.recovery_kit().unwrap().unwrap().display())
        .await
        .unwrap();
    a.test_rotate_account(Some(c.device_id())).await.unwrap();
    b.refresh().await.unwrap();
    let new = note_with_text(&base, "after");
    base.flush().await.unwrap();
    let other = b.base(base.id()).unwrap();
    wait_for_base(&other, || {
        other.note(old).is_ok() && other.note(new).is_ok()
    })
    .await;
    let stored = b
        .test_secrets()
        .get(&format!("acct.{}.key", b.id()))
        .unwrap()
        .unwrap();
    assert_eq!(u32::from_be_bytes(stored[36..40].try_into().unwrap()), 2);
}

#[tokio::test]
async fn adopted_keys_survive_a_restart() {
    let (a, kit) = bh_testkit::device("a").sign_up(new_signup()).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (core, _) = local_core(dir.path());
    let b = core
        .sign_in(SignIn {
            device_name: "b".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    b.refresh().await.unwrap();
    a.test_rotate_account(None).await.unwrap();
    b.refresh().await.unwrap();
    let id = b.id();
    drop(b);
    drop(core);
    let (restarted, _) = local_core(dir.path());
    let b = restarted.account(id).unwrap();
    b.refresh().await.unwrap();
    let key = b
        .test_secrets()
        .get(&format!("acct.{id}.key"))
        .unwrap()
        .unwrap();
    assert_eq!(u32::from_be_bytes(key[36..40].try_into().unwrap()), 2);
}

#[tokio::test]
async fn kit_sign_in_after_a_rotation_starts_at_the_current_epoch() {
    let (a, b) = bh_testkit::two_devices().await;
    let kit = a.recovery_kit().unwrap().unwrap();
    a.test_rotate_account(Some(b.device_id())).await.unwrap();
    let newcomer = bh_testkit::device("new")
        .sign_in(SignIn {
            device_name: "new".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    newcomer.refresh().await.unwrap();
    let stored = newcomer
        .test_secrets()
        .get(&format!("acct.{}.key", newcomer.id()))
        .unwrap()
        .unwrap();
    assert_eq!(u32::from_be_bytes(stored[..4].try_into().unwrap()), 2);
}

#[tokio::test]
async fn a_device_offline_across_two_rotations_walks_both() {
    let (a, b) = bh_testkit::two_devices().await;
    let kit = a.recovery_kit().unwrap().unwrap();
    let c = bh_testkit::device("c")
        .sign_in(SignIn {
            device_name: "c".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let d = bh_testkit::device("d")
        .sign_in(SignIn {
            device_name: "d".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    b.refresh().await.unwrap();
    d.refresh().await.unwrap();
    a.test_rotate_account(Some(c.device_id())).await.unwrap();
    a.test_rotate_account(Some(d.device_id())).await.unwrap();
    b.refresh().await.unwrap();
    let stored = b
        .test_secrets()
        .get(&format!("acct.{}.key", b.id()))
        .unwrap()
        .unwrap();
    assert_eq!(u32::from_be_bytes(stored[72..76].try_into().unwrap()), 3);
}

#[tokio::test]
async fn an_app_connected_after_a_rotation_starts_at_that_epoch() {
    use bh_core::{AppRequest, BaseGrantRequest, Mode};
    let (a, b) = bh_testkit::two_devices().await;
    let base = a.create_base("Shared").await.unwrap();
    a.test_rotate_account(Some(b.device_id())).await.unwrap();
    let credentials = a
        .connect_app(AppRequest {
            app_name: "reader".into(),
            app_id: Some("reader".into()),
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = bh_testkit::device("reader")
        .install_app(credentials)
        .await
        .unwrap();
    app.refresh().await.unwrap();
    let stored = app
        .test_secrets()
        .get(&format!("acct.{}.appkey", app.id()))
        .unwrap()
        .unwrap();
    assert_eq!(u32::from_be_bytes(stored[..4].try_into().unwrap()), 2);
    assert!(app.base(base.id()).is_ok());
}

#[tokio::test]
async fn app_credentials_retain_the_epoch_that_recorded_their_key() {
    use bh_core::{AppRequest, BaseGrantRequest, Mode};
    let (a, b) = bh_testkit::two_devices().await;
    let base = a.create_base("Shared").await.unwrap();
    let old = note_with_text(&base, "before rotation");
    base.flush().await.unwrap();
    let (release, entered) = a.test_hold_next_app_credentials();
    let caller = a.clone();
    let id = base.id();
    let connecting = tokio::spawn(async move {
        caller
            .connect_app(AppRequest {
                app_name: "reader".into(),
                app_id: Some("reader".into()),
                bases: vec![BaseGrantRequest::Existing {
                    base: id,
                    mode: Mode::ReadOnly,
                }],
                replaces: None,
            })
            .await
    });
    bh_testkit::wait_entered(&entered, std::panic::Location::caller()).await;
    // The app key was committed at epoch 1; the app is in the recipient set
    // for the intervening rotation, even though its credentials are still held.
    a.test_rotate_account(Some(b.device_id())).await.unwrap();
    a.wait_for_removals().await.unwrap();
    let fresh = note_with_text(&base, "after rotation");
    base.flush().await.unwrap();
    release.add_permits(1);
    let credentials = connecting.await.unwrap().unwrap();
    assert_eq!(credentials.epoch, 1);
    let app = bh_testkit::device("reader")
        .install_app(credentials)
        .await
        .unwrap();
    app.refresh().await.unwrap();
    let reader = app.base(base.id()).unwrap();
    wait_for_base(&reader, || {
        reader.note(old).is_ok() && reader.note(fresh).is_ok()
    })
    .await;
    let ring = app
        .test_secrets()
        .get(&format!("acct.{}.appkey", app.id()))
        .unwrap()
        .unwrap();
    assert_eq!(u32::from_be_bytes(ring[36..40].try_into().unwrap()), 2);
}

#[tokio::test]
async fn an_app_adopts_its_new_app_key() {
    use bh_core::{AppRequest, BaseGrantRequest, Mode};
    let (a, b) = bh_testkit::two_devices().await;
    let base = a.create_base("Shared").await.unwrap();
    let credentials = a
        .connect_app(AppRequest {
            app_name: "reader".into(),
            app_id: Some("reader".into()),
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = bh_testkit::device("reader")
        .install_app(credentials)
        .await
        .unwrap();
    app.refresh().await.unwrap();
    let old = note_with_text(&base, "before");
    base.flush().await.unwrap();
    a.test_rotate_account(Some(b.device_id())).await.unwrap();
    app.refresh().await.unwrap();
    let fresh = note_with_text(&base, "after");
    base.flush().await.unwrap();
    let reader = app.base(base.id()).unwrap();
    wait_for_base(&reader, || {
        reader.note(old).is_ok() && reader.note(fresh).is_ok()
    })
    .await;
    let stored = app
        .test_secrets()
        .get(&format!("acct.{}.appkey", app.id()))
        .unwrap()
        .unwrap();
    assert_eq!(u32::from_be_bytes(stored[36..40].try_into().unwrap()), 2);
}

#[tokio::test]
async fn a_base_created_after_rotation_declares_the_verified_epoch() {
    let (a, b) = bh_testkit::two_devices().await;
    a.test_rotate_account(Some(b.device_id())).await.unwrap();
    let base = a.create_base("Later").await.unwrap();
    let note = note_with_text(&base, "at epoch two");
    base.flush().await.unwrap();
    assert_eq!(base.note(note).unwrap().text(), "at epoch two");
}

#[tokio::test]
async fn new_kit_and_password_change_after_a_rotation_use_the_current_epoch() {
    let (a, b) = bh_testkit::two_devices().await;
    a.test_rotate_account(Some(b.device_id())).await.unwrap();
    let kit = a.new_kit(bh_testkit::TEST_PASSWORD).await.unwrap();
    a.change_password(bh_testkit::TEST_PASSWORD, &kit.display(), "new diary pass")
        .await
        .unwrap();
    let newcomer = bh_testkit::device("new")
        .sign_in(SignIn {
            password: "new diary pass".to_string().into(),
            device_name: "new".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    newcomer.refresh().await.unwrap();
    let stored = newcomer
        .test_secrets()
        .get(&format!("acct.{}.key", newcomer.id()))
        .unwrap()
        .unwrap();
    assert_eq!(u32::from_be_bytes(stored[..4].try_into().unwrap()), 2);
}

#[tokio::test]
async fn a_device_approved_after_a_rotation_reads_old_notes() {
    let (a, b) = bh_testkit::two_devices().await;
    let base = a.create_base("Shared").await.unwrap();
    let old = note_with_text(&base, "old note");
    base.flush().await.unwrap();
    a.test_rotate_account(Some(b.device_id())).await.unwrap();
    let mut approval = bh_testkit::device("new")
        .sign_in(SignIn {
            device_name: "new".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) =
        tokio::try_join!(a.open_request(approval.id()), approval.digits()).unwrap();
    a.approve(open, &digits).await.unwrap();
    let newcomer = approval.wait().await.unwrap();
    newcomer.refresh().await.unwrap();
    let other = newcomer.base(base.id()).unwrap();
    wait_for_base(&other, || other.note(old).is_ok()).await;
    let stored = newcomer
        .test_secrets()
        .get(&format!("acct.{}.key", newcomer.id()))
        .unwrap()
        .unwrap();
    assert_eq!(u32::from_be_bytes(stored[..4].try_into().unwrap()), 2);
}

#[tokio::test]
async fn after_a_rekey_both_devices_read_old_and_new_notes() {
    use bh_core::{AppRequest, BaseGrantRequest, Mode};
    let (a, b) = bh_testkit::two_devices().await;
    let base = a.create_base("Shared").await.unwrap();
    let old = note_with_text(&base, "old");
    base.flush().await.unwrap();
    b.refresh().await.unwrap();
    let other = b.base(base.id()).unwrap();
    wait_for_base(&other, || other.note(old).is_ok_and(|n| n.text() == "old")).await;
    let credentials = a
        .connect_app(AppRequest {
            app_name: "reader".into(),
            app_id: Some("app.reader".into()),
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadWrite,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = bh_testkit::device("reader")
        .install_app(credentials)
        .await
        .unwrap();
    app.refresh().await.unwrap();
    let app_base = app.base(base.id()).unwrap();
    wait_for_base(&app_base, || app_base.note(old).is_ok()).await;

    a.test_rekey_base(base.id()).await.unwrap();
    let fresh = note_with_text(&base, "new from a");
    base.flush().await.unwrap();
    wait_for_base(&other, || {
        other.note(fresh).is_ok_and(|n| n.text() == "new from a")
    })
    .await;
    let from_b = note_with_text(&other, "new from b");
    other.flush().await.unwrap();
    for reader in [&base, &other, &app_base] {
        wait_for_base(reader, || {
            [old, fresh, from_b]
                .iter()
                .all(|id| reader.note(*id).is_ok())
        })
        .await;
    }
}

#[tokio::test]
async fn a_change_from_a_newer_epoch_waits_for_its_key() {
    use bh_core::test_support::Fault;
    let (a, b) = bh_testkit::two_devices().await;
    let first = a.create_base("Shared").await.unwrap();
    first.flush().await.unwrap();
    b.refresh().await.unwrap();
    let second = b.base(first.id()).unwrap();
    second.test_pause_sync();
    a.test_rekey_base(first.id()).await.unwrap();
    let note = note_with_text(&first, "must wait");
    first.flush().await.unwrap();
    let path = format!("v1/bases/{}/key", first.id());
    let path: &'static str = Box::leak(path.into_boxed_str());
    b.test_inject_fault(Fault {
        method: "GET",
        path,
        lost_reply: false,
        times: 1,
    });
    let before = b.test_request_count(path);
    second.test_resume_sync();
    wait_for_base(&second, || b.test_request_count(path) > before).await;
    assert!(second.test_set_aside().is_empty());
    let _ = second.sync_now().await;
    wait_for_base(&second, || {
        second.note(note).is_ok_and(|n| n.text() == "must wait")
    })
    .await;
    assert!(
        b.test_request_count(path) >= before + 2,
        "key fetch was not retried"
    );
    assert!(second.test_set_aside().is_empty());
}

#[tokio::test]
async fn an_edit_sealed_before_a_rekey_is_resent_under_the_new_key() {
    use bh_core::test_support::Fault;
    let (a, b) = bh_testkit::two_devices().await;
    let first = a.create_base("Shared").await.unwrap();
    first.flush().await.unwrap();
    b.refresh().await.unwrap();
    let second = b.base(first.id()).unwrap();
    second.test_pause_sync();
    let note = note_with_text(&second, "queued old epoch");
    let path = format!("v1/bases/{}/changes", first.id());
    let path: &'static str = Box::leak(path.into_boxed_str());
    b.test_inject_fault(Fault {
        method: "POST",
        path,
        lost_reply: false,
        times: 1,
    });
    let failed_before = b.test_request_count(path);
    second.test_resume_sync();
    wait_for_base(&second, || {
        b.test_request_count(path) > failed_before
            && !second.sync_state().online
            && second.test_sending(note)
    })
    .await;
    second.test_hold_sends();
    // Reconnect without resending the queued row before its key advances.
    second.sync_now().await.unwrap();
    assert!(second.test_sending(note));
    a.test_rekey_base(first.id()).await.unwrap();
    second.test_resume_sends();
    second.flush().await.unwrap();
    wait_for_base(&first, || {
        first
            .note(note)
            .is_ok_and(|n| n.text() == "queued old epoch")
    })
    .await;
    let server = bh_testkit::LocalServer::from_env();
    let fetched: serde_json::Value = reqwest::Client::new()
        .post(
            server
                .url()
                .join(&format!("/v1/bases/{}/fetch", first.id()))
                .unwrap(),
        )
        .header("BH-Protocol", "2")
        .header("BH-Test-Bypass", server.operator_token())
        .bearer_auth(bh_testkit::raw_device(&a).token)
        .json(&serde_json::json!({"objectIds": [note.to_string()]}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    use base64::Engine as _;
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(
            fetched["objects"][0]["updates"][0]["body"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    assert_eq!(u32::from_be_bytes(body[1..5].try_into().unwrap()), 2);
}

#[tokio::test]
async fn a_live_epoch_before_a_refused_old_send_reseals_the_waiting_edit() {
    use bh_core::test_support::Fault;
    let (a, b) = bh_testkit::two_devices().await;
    let first = a.create_base("Shared").await.unwrap();
    first.flush().await.unwrap();
    b.refresh().await.unwrap();
    let second = b.base(first.id()).unwrap();
    second.test_pause_sync();
    let note = note_with_text(&second, "old sealed edit");
    let path = format!("v1/bases/{}/changes", first.id());
    let path: &'static str = Box::leak(path.into_boxed_str());
    b.test_inject_fault(Fault {
        method: "POST",
        path,
        lost_reply: false,
        times: 1,
    });
    let failed_before = b.test_request_count(path);
    second.test_resume_sync();
    wait_for_base(&second, || {
        b.test_request_count(path) > failed_before && !second.sync_state().online
    })
    .await;
    second.test_hold_sends();
    // The failed send disconnected the socket; reconnect without sending the queued row.
    second.sync_now().await.unwrap();
    let sent = b.test_request_count(path);
    a.test_rekey_base(first.id()).await.unwrap();
    // The live epoch notice has installed epoch 2 while the old edit remains in sending.
    wait_for_base(&second, || {
        let body = second.test_seal_update(note, b"probe");
        u32::from_be_bytes(body[1..5].try_into().unwrap()) == 2
    })
    .await;
    assert_eq!(
        b.test_request_count(path),
        sent,
        "held sender posted before the live epoch"
    );
    second.test_resume_sends();
    second.flush().await.unwrap();
    wait_for_base(&first, || {
        first
            .note(note)
            .is_ok_and(|n| n.text() == "old sealed edit")
    })
    .await;
    assert!(second.test_set_aside().is_empty());
}

#[tokio::test]
async fn type_ids_and_records_survive_a_rekey() {
    use bh_core::{FieldDef, FieldKind, NewObject, Query, TypeDef, TypeRef};
    use serde_json::{Map, json};
    let (a, b) = bh_testkit::two_devices().await;
    let first = a.create_base("Shared").await.unwrap();
    let definition = TypeDef {
        name: "demo.rotation".into(),
        version: 1,
        doc: String::new(),
        title_field: None,
        fields: vec![FieldDef {
            name: "memo".into(),
            kind: FieldKind::Text,
            required: false,
            unit: None,
            doc: String::new(),
        }],
    };
    first.define_type(definition.clone()).unwrap();
    let type_id = first.test_type_id("demo.rotation", 1);
    let record = first
        .create(NewObject {
            ty: TypeRef::new("demo.rotation", 1),
            parent: None,
            after: None,
            fields: Map::from_iter([("memo".to_string(), json!("before"))]),
        })
        .unwrap();
    first.flush().await.unwrap();
    b.refresh().await.unwrap();
    let second = b.base(first.id()).unwrap();
    wait_for_base(&second, || second.get(record).unwrap().is_some()).await;
    a.test_rekey_base(first.id()).await.unwrap();
    assert_eq!(first.test_type_id("demo.rotation", 1), type_id);
    wait_for_base(&second, || {
        second.test_type_id("demo.rotation", 1) == type_id
    })
    .await;
    assert!(first.types().unwrap().contains(&definition));
    assert!(first.get(type_id).unwrap().is_some());
    let query = Query {
        ty: "demo.rotation".into(),
        filters: vec![],
        order_by: None,
        limit: None,
    };
    for base in [&first, &second] {
        assert!(base.types().unwrap().contains(&definition));
        assert!(
            base.query(&query)
                .unwrap()
                .iter()
                .any(|row| row.id == record)
        );
    }
}

#[tokio::test]
async fn publishing_a_public_key_does_not_write_on_every_refresh() {
    let (account, _) = bh_testkit::device("a")
        .sign_up(bh_core::SignUp {
            device_name: "a".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    account.refresh().await.unwrap();
    let before = account.test_request_count("v1/account/data");
    account.refresh().await.unwrap();
    account.refresh().await.unwrap();
    assert_eq!(account.test_request_count("v1/account/data"), before);
}

#[tokio::test]
async fn app_credentials_carry_a_key_pair_seed() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use bh_core::{AppRequest, BaseGrantRequest, Mode};
    let full_dir = tempfile::tempdir().unwrap();
    let (full_core, full_secrets) = local_core(full_dir.path());
    let (full, _) = full_core
        .sign_up(bh_core::SignUp {
            device_name: "a".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let base = full.create_base("Personal").await.unwrap();
    let credentials = full
        .connect_app(AppRequest {
            app_name: "sample".into(),
            app_id: Some("app.sample".into()),
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadWrite,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let seed = URL_SAFE_NO_PAD
        .decode(credentials.kem_seed.as_ref().unwrap().as_bytes())
        .unwrap();
    let public = URL_SAFE_NO_PAD.encode(
        bh_crypto::KemKey::from_seed(&bh_crypto::Secret::<32>::from_slice(&seed).unwrap()).public(),
    );
    let db_key = full_secrets
        .get(&format!("acct.{}.dbkey", full.id()))
        .unwrap()
        .unwrap();
    let db = full_dir
        .path()
        .join("data/accounts")
        .join(full.id().to_string())
        .join("account.sqlite");
    let db = rusqlite::Connection::open(&db).unwrap();
    let hex: String = db_key.iter().map(|byte| format!("{byte:02x}")).collect();
    db.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))
        .unwrap();
    let data: String = db
        .query_row("SELECT json FROM account_data WHERE id = 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    let data: serde_json::Value = serde_json::from_str(&data).unwrap();
    assert_eq!(
        data["apps"][credentials.device_id.to_string()]["public"],
        public
    );
    let raw = serde_json::to_value(&credentials).unwrap();
    assert_eq!(
        raw["kemSeed"],
        credentials.kem_seed.as_ref().unwrap().as_str()
    );
    let app_dir = tempfile::tempdir().unwrap();
    let (core, secrets) = local_core(app_dir.path());
    let app = core.install_app(credentials).await.unwrap();
    assert_eq!(
        &*secrets
            .get(&format!("acct.{}.kem", app.id()))
            .unwrap()
            .unwrap(),
        seed.as_slice()
    );
}

#[tokio::test]
async fn an_installed_app_missing_its_seed_gets_one_on_refresh() {
    use bh_core::{AppRequest, BaseGrantRequest, Mode};
    let (full, _) = bh_testkit::device("a")
        .sign_up(bh_core::SignUp {
            device_name: "a".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let base = full.create_base("Personal").await.unwrap();
    let credentials = full
        .connect_app(AppRequest {
            app_name: "sample".into(),
            app_id: Some("app.sample".into()),
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadWrite,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (core, secrets) = local_core(dir.path());
    let app = core.install_app(credentials).await.unwrap();
    let key = format!("acct.{}.kem", app.id());
    secrets.delete(&key).unwrap();
    app.refresh().await.unwrap();
    assert_eq!(secrets.get(&key).unwrap().unwrap().len(), 32);
}

#[tokio::test]
async fn failed_full_install_erases_the_key_pair_secret() {
    let dir = tempfile::tempdir().unwrap();
    let (core, _) = local_core(dir.path());
    let accounts = dir.path().join("data/accounts");
    fs::remove_dir(&accounts).unwrap();
    fs::write(&accounts, b"not a directory").unwrap();
    assert!(
        core.sign_up(bh_core::SignUp {
            device_name: "mac".into(),
            ..new_signup()
        })
        .await
        .is_err()
    );
    let names: Vec<_> = fs::read_dir(dir.path().join("secrets"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(
        names.is_empty(),
        "failed full install left secrets: {names:?}"
    );
    fs::remove_file(accounts).unwrap();
}

#[tokio::test]
async fn failed_app_install_erases_the_key_pair_secret() {
    use bh_core::{AppRequest, BaseGrantRequest, Mode};
    let (full, _) = bh_testkit::device("a")
        .sign_up(bh_core::SignUp {
            device_name: "a".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let base = full.create_base("Personal").await.unwrap();
    let credentials = full
        .connect_app(AppRequest {
            app_name: "sample".into(),
            app_id: Some("app.sample".into()),
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadWrite,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let id = credentials.account_id;
    let app_dir = tempfile::tempdir().unwrap();
    let (core, secrets) = local_core(app_dir.path());
    let db = app_dir
        .path()
        .join("data/accounts")
        .join(id.to_string())
        .join("account.sqlite");
    fs::create_dir_all(&db).unwrap();
    assert!(core.install_app(credentials).await.is_err());
    assert!(secrets.get(&format!("acct.{id}.kem")).unwrap().is_none());
}

#[tokio::test]
async fn a_hidden_base_rekeys_at_its_next_unlock() {
    let (a, b) = bh_testkit::two_devices().await;
    let diary = a.create_hidden_base("Diary", password()).await.unwrap();
    let before = note_with_text(&diary, "before");
    diary.flush().await.unwrap();
    b.refresh().await.unwrap();
    a.lock_hidden(diary.id()).await.unwrap();
    a.remove_device(
        b.device_id(),
        bh_core::Removal::Full {
            password: password(),
            lost: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(server_base_key(&a, diary.id()).await["epoch"], 1);
    a.unlock_hidden(password()).await.unwrap();
    let reopened = a.base(diary.id()).unwrap();
    for _ in 0..20 {
        if server_base_key(&a, diary.id()).await["epoch"] == 2 {
            break;
        }
        a.refresh().await.unwrap();
    }
    let row = server_base_key(&a, diary.id()).await;
    assert_eq!(row["epoch"], 2, "hidden base was not re-keyed: {row}");
    assert_eq!(row["accountEpoch"], 2);
    assert_eq!(reopened.note(before).unwrap().text(), "before");
    let after = note_with_text(&reopened, "after");
    reopened.flush().await.unwrap();
    a.lock_hidden(diary.id()).await.unwrap();
    a.unlock_hidden(password()).await.unwrap();
    let reopened = a.base(diary.id()).unwrap();
    assert_eq!(reopened.note(before).unwrap().text(), "before");
    assert_eq!(reopened.note(after).unwrap().text(), "after");
}

#[tokio::test]
async fn a_lost_hidden_rekey_reply_reloads_the_new_wrapper() {
    use bh_core::test_support::Fault;
    let (a, b) = bh_testkit::two_devices().await;
    let diary = a.create_hidden_base("Diary", password()).await.unwrap();
    diary.flush().await.unwrap();
    a.lock_hidden(diary.id()).await.unwrap();
    a.remove_device(
        b.device_id(),
        bh_core::Removal::Full {
            password: password(),
            lost: false,
        },
    )
    .await
    .unwrap();
    let path: &'static str = Box::leak(format!("v1/bases/{}/rekey", diary.id()).into_boxed_str());
    a.test_inject_fault(Fault {
        method: "POST",
        path,
        lost_reply: true,
        times: 1,
    });
    a.unlock_hidden(password()).await.unwrap();
    for _ in 0..20 {
        if server_base_key(&a, diary.id()).await["epoch"] == 2 {
            break;
        }
        a.refresh().await.unwrap();
    }
    assert_eq!(server_base_key(&a, diary.id()).await["epoch"], 2);
    let reopened = a.base(diary.id()).unwrap();
    let note = note_with_text(&reopened, "after lost reply");
    reopened.flush().await.unwrap();
    assert_eq!(reopened.note(note).unwrap().text(), "after lost reply");
}

#[tokio::test]
async fn a_removed_device_with_a_later_copy_of_the_server_reads_nothing_new() {
    let a_dir = tempfile::tempdir().unwrap();
    let (a_core, a_secrets) = local_core(a_dir.path());
    let (a, kit) = a_core
        .sign_up(bh_core::SignUp {
            device_name: "mac".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let (b_core, _) = local_core(b_dir.path());
    let b = b_core
        .sign_in(SignIn {
            device_name: "phone".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();

    let personal = a.create_base("Personal").await.unwrap();
    let before_id = note_with_text(&personal, "before-marker");
    let diary = a.create_hidden_base("Diary", password()).await.unwrap();
    let hidden_before_id = note_with_text(&diary, "hidden-before");
    personal.flush().await.unwrap();
    diary.flush().await.unwrap();
    b.refresh().await.unwrap();
    b.unlock_hidden(password()).await.unwrap();
    let b_personal = b.base(personal.id()).unwrap();
    let b_diary = b.base(diary.id()).unwrap();
    wait_for_base(&b_personal, || {
        b_personal.sync_state().online
            && b_personal.sync_state().pending == 0
            && b_personal
                .note(before_id)
                .is_ok_and(|note| note.text() == "before-marker")
    })
    .await;
    wait_for_base(&b_diary, || {
        b_diary.sync_state().online
            && b_diary.sync_state().pending == 0
            && b_diary
                .note(hidden_before_id)
                .is_ok_and(|note| note.text() == "hidden-before")
    })
    .await;
    let stolen = stolen_copy(b_dir.path());

    a.remove_device(
        b.device_id(),
        bh_core::Removal::Full {
            password: password(),
            lost: false,
        },
    )
    .await
    .unwrap();
    a.wait_for_removals().await.unwrap();
    let after_id = note_with_text(&personal, "after-marker");
    let later = a.create_base("Later").await.unwrap();
    note_with_text(&later, "later-marker");
    a.unlock_hidden(password()).await.unwrap();
    note_with_text(&diary, "hidden-after");
    personal.flush().await.unwrap();
    later.flush().await.unwrap();
    diary.flush().await.unwrap();

    let (_stolen_core, stolen_account) = attacker(stolen.path(), &a_secrets, a.id());
    let _ = stolen_account.refresh().await;
    let stolen_personal = stolen_account.base(personal.id()).unwrap();
    stolen_account.unlock_hidden(password()).await.unwrap();
    let stolen_diary = stolen_account.base(diary.id()).unwrap();
    wait_for_catch_up_attempt(&stolen_account, &stolen_personal).await;
    wait_for_catch_up_attempt(&stolen_account, &stolen_diary).await;

    assert_eq!(
        stolen_personal.note(before_id).unwrap().text(),
        "before-marker"
    );
    assert_eq!(
        stolen_diary.note(hidden_before_id).unwrap().text(),
        "hidden-before"
    );
    assert!(
        stolen_personal
            .search("after-marker", 100)
            .unwrap()
            .is_empty(),
        "removed device read after-marker from the server"
    );
    assert!(stolen_personal.note(after_id).is_err());
    for base in [&stolen_personal, &stolen_diary] {
        for marker in ["after-marker", "later-marker", "hidden-after"] {
            assert!(
                base.search(marker, 100).unwrap().is_empty(),
                "found {marker} in search"
            );
            assert!(
                note_texts(base).iter().all(|text| !text.contains(marker)),
                "found {marker} in note text"
            );
        }
    }
    assert!(stolen_account.base(later.id()).is_err());
}
