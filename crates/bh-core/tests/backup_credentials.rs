use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bh_core::{
    Account, BackupLocation, BackupProblem, Core, RecoveryKit, list_backups, test_support,
};
use bh_testkit::{
    TEST_PASSWORD, device,
    folder::{MemoryFolder, record_paths},
    new_signup, raw_device, signin_for,
};
use reqwest::StatusCode;
use serde_json::json;
use std::sync::Arc;
use zeroize::Zeroizing;

async fn signed_up() -> (Account, RecoveryKit) {
    device("mac").sign_up(new_signup()).await.unwrap()
}

fn checked(account: &Account, password: &str, kit: &RecoveryKit) -> Vec<u8> {
    let c = account.test_backup_credentials().unwrap().unwrap();
    assert!(c.checked);
    assert_eq!(
        test_support::open_envelope(&c.envelope, &c.salt, password, kit, account.id()).unwrap(),
        account.test_account_key()
    );
    c.envelope
}

async fn replace_credentials(account: &Account, salt: [u8; 16], envelope: Vec<u8>, password: &str) {
    let current = account.test_backup_credentials().unwrap().unwrap();
    let key = test_support::login_key(TEST_PASSWORD, &current.salt).unwrap();
    let next_key = test_support::login_key(password, &salt).unwrap();
    let (status, body) = raw_device(account)
        .put(
            "/v1/account/credentials",
            json!({
                "currentLoginKey": URL_SAFE_NO_PAD.encode(key),
                "loginKey": URL_SAFE_NO_PAD.encode(next_key),
                "salt": URL_SAFE_NO_PAD.encode(salt),
                "kdf": { "opsLimit": 3, "memLimitKib": 65536 },
                "accountKeyEnvelope": URL_SAFE_NO_PAD.encode(envelope),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn sign_up_keeps_an_envelope_and_salt_that_open_with_the_password_and_kit() {
    let (a, kit) = signed_up().await;
    checked(&a, TEST_PASSWORD, &kit);
    let c = a.test_backup_credentials().unwrap().unwrap();
    let debug = format!("{c:?}");
    assert!(!debug.contains(&URL_SAFE_NO_PAD.encode(&c.envelope)));
    assert!(!debug.contains(&URL_SAFE_NO_PAD.encode(c.salt)));
}

#[tokio::test]
async fn a_device_signed_in_by_approval_checks_the_envelope_against_the_kit_record() {
    let (a, kit) = signed_up().await;
    let original = checked(&a, TEST_PASSWORD, &kit);
    let pending = device("fold").sign_in(signin_for(&a)).await.unwrap();
    let mut approval = pending.request_approval().await.unwrap();
    let (opened, digits) =
        tokio::try_join!(a.open_request(approval.id()), approval.digits()).unwrap();
    a.approve(opened, &digits).await.unwrap();
    let b = approval.wait().await.unwrap();
    b.refresh().await.unwrap();
    assert_eq!(checked(&b, TEST_PASSWORD, &kit), original);
}

#[tokio::test]
async fn a_new_kit_and_a_password_change_replace_the_checked_details() {
    let (a, old) = signed_up().await;
    let first = checked(&a, TEST_PASSWORD, &old);
    let next = a.new_kit(TEST_PASSWORD).await.unwrap();
    let second = checked(&a, TEST_PASSWORD, &next);
    assert_ne!(first, second);
    a.change_password(TEST_PASSWORD, &next.display(), "another correct password")
        .await
        .unwrap();
    let third = checked(&a, "another correct password", &next);
    assert_ne!(second, third);
}

#[tokio::test]
async fn a_server_serving_another_envelope_leaves_the_last_checked_one() {
    let (a, kit) = signed_up().await;
    let original = checked(&a, TEST_PASSWORD, &kit);
    let salt = a.test_backup_credentials().unwrap().unwrap().salt;
    let wrong = test_support::seal_envelope(&[8; 32], &salt, TEST_PASSWORD, &kit, a.id()).unwrap();
    replace_credentials(&a, salt, wrong, TEST_PASSWORD).await;
    a.refresh().await.unwrap();
    assert_eq!(checked(&a, TEST_PASSWORD, &kit), original);
    let folder = Arc::new(MemoryFolder::default());
    a.test_set_document_folders(folder.clone());
    a.set_backup(Some(BackupLocation::Document {
        uri: "memory".into(),
        label: "Backup".into(),
    }))
    .unwrap();
    a.backup_now().await.unwrap();
    for path in record_paths(&folder, ".bhk") {
        let body = &test_support::backup_records(&*folder, &path).unwrap()[0];
        let saved: serde_json::Value = serde_json::from_slice(body).unwrap();
        let envelope = URL_SAFE_NO_PAD
            .decode(saved["envelope"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            envelope, original,
            "forged envelope was written to keys file"
        );
    }
}

#[tokio::test]
async fn a_forged_envelope_after_rotation_cannot_be_backed_up_by_an_adopting_device() {
    let (a, kit) = signed_up().await;
    a.test_remove_kit_record(false).await.unwrap();
    let pending = device("recipient").sign_in(signin_for(&a)).await.unwrap();
    let mut approval = pending.request_approval().await.unwrap();
    let (opened, digits) =
        tokio::try_join!(a.open_request(approval.id()), approval.digits()).unwrap();
    a.approve(opened, &digits).await.unwrap();
    let b = approval.wait().await.unwrap();
    b.refresh().await.unwrap();
    assert!(!b.test_backup_credentials().unwrap().unwrap().checked);
    let removed = device("removed")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    b.refresh().await.unwrap();
    let outcome = a
        .remove_device(
            removed.device_id(),
            bh_core::Removal::Full {
                password: zeroize::Zeroizing::new(TEST_PASSWORD.into()),
                lost: true,
            },
        )
        .await
        .unwrap();
    assert!(outcome.new_kit.is_some());
    a.wait_for_removals().await.unwrap();
    let credentials = a.test_backup_credentials().unwrap().unwrap();
    let mut forged = credentials.envelope.clone();
    *forged.last_mut().unwrap() ^= 1;
    let server = bh_testkit::LocalServer::from_env();
    let login = test_support::login_key(TEST_PASSWORD, &credentials.salt).unwrap();
    let reply = reqwest::Client::new()
        .put(server.url().join("/v1/account/credentials").unwrap())
        .header("BH-Protocol", "2")
        .header("BH-Test-Bypass", server.operator_token())
        .bearer_auth(raw_device(&a).token)
        .json(&json!({
            "currentLoginKey": URL_SAFE_NO_PAD.encode(login),
            "loginKey": URL_SAFE_NO_PAD.encode(login),
            "salt": URL_SAFE_NO_PAD.encode(credentials.salt),
            "kdf": {"opsLimit": 3, "memLimitKib": 65536},
            "accountKeyEnvelope": URL_SAFE_NO_PAD.encode(&forged),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), StatusCode::OK);
    let served = reqwest::Client::new()
        .get(server.url().join("/v1/account").unwrap())
        .header("BH-Protocol", "2")
        .header("BH-Test-Bypass", server.operator_token())
        .bearer_auth(raw_device(&b).token)
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(served["accountKeyEnvelope"].as_str().unwrap())
            .unwrap(),
        forged
    );
    b.refresh().await.unwrap();
    let saved = b.test_backup_credentials().unwrap().unwrap();
    assert_eq!(saved.envelope[1..5], 1u32.to_be_bytes());
    assert_ne!(saved.envelope, forged);
    let folder = Arc::new(MemoryFolder::default());
    b.test_set_document_folders(folder.clone());
    b.set_backup(Some(BackupLocation::Document {
        uri: "memory".into(),
        label: "Backup".into(),
    }))
    .unwrap();
    assert_eq!(b.backup_now().await.unwrap().run, None);
    assert_eq!(
        b.backup_status().unwrap().problem,
        Some(bh_core::BackupProblem::UsingLastChecked)
    );
    assert!(record_paths(&folder, ".bhk").is_empty());
}

#[tokio::test]
async fn a_server_serving_another_salt_leaves_the_last_checked_one() {
    let (a, kit) = signed_up().await;
    let original = checked(&a, TEST_PASSWORD, &kit);
    let envelope = test_support::seal_envelope(
        &a.test_account_key(),
        &[7; 16],
        "other password",
        &kit,
        a.id(),
    )
    .unwrap();
    replace_credentials(&a, [7; 16], envelope, "other password").await;
    a.refresh().await.unwrap();
    assert_eq!(checked(&a, TEST_PASSWORD, &kit), original);
}

#[tokio::test]
async fn an_account_without_a_kit_record_keeps_an_unchecked_envelope() {
    let (a, _) = signed_up().await;
    a.test_remove_kit_record(false).await.unwrap();
    let pending = device("fold").sign_in(signin_for(&a)).await.unwrap();
    let mut approval = pending.request_approval().await.unwrap();
    let (opened, digits) =
        tokio::try_join!(a.open_request(approval.id()), approval.digits()).unwrap();
    a.approve(opened, &digits).await.unwrap();
    let b = approval.wait().await.unwrap();
    b.refresh().await.unwrap();
    let stored = b.test_backup_credentials().unwrap().unwrap();
    assert!(!stored.checked);
    let (status, account) = raw_device(&b).get("/v1/account", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let (status, params) = raw_device(&b)
        .post("/v1/login/params", json!({ "email": b.email() }))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        stored.envelope,
        URL_SAFE_NO_PAD
            .decode(account["accountKeyEnvelope"].as_str().unwrap())
            .unwrap()
    );
    assert_eq!(
        stored.salt.as_slice(),
        URL_SAFE_NO_PAD
            .decode(params["salt"].as_str().unwrap())
            .unwrap()
    );
}

#[tokio::test]
async fn an_older_kit_record_gets_its_salt_from_the_first_device_that_refreshes() {
    let (a, kit) = signed_up().await;
    let salt = a.test_backup_credentials().unwrap().unwrap().salt;
    a.test_remove_kit_record(true).await.unwrap();
    a.refresh().await.unwrap();
    assert_eq!(a.test_kit_record_salt(), Some(salt));
    checked(&a, TEST_PASSWORD, &kit);
}

#[tokio::test]
async fn signing_in_with_the_kit_records_the_salt_it_opened_with() {
    let (a, kit) = signed_up().await;
    let salt = a.test_backup_credentials().unwrap().unwrap().salt;
    a.test_remove_kit_record(true).await.unwrap();
    let b = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    assert_eq!(b.test_kit_record_salt(), Some(salt));
    checked(&b, TEST_PASSWORD, &kit);
}

/// A second full device of `a`, signed in by approval, which writes its name
/// into account data but doesn't refresh.
async fn approved(a: &Account) -> (Core, Account) {
    let core = device("fold");
    let pending = core.sign_in(signin_for(a)).await.unwrap();
    let mut approval = pending.request_approval().await.unwrap();
    let (opened, digits) =
        tokio::try_join!(a.open_request(approval.id()), approval.digits()).unwrap();
    a.approve(opened, &digits).await.unwrap();
    let b = approval.wait().await.unwrap();
    (core, b)
}

#[tokio::test]
async fn a_rotation_names_the_new_envelope_for_an_adopting_devices_backup() {
    let (a, _) = signed_up().await;
    let (_core, b) = approved(&a).await;
    b.refresh().await.unwrap();
    let removed = device("removed")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&a.recovery_kit().unwrap().unwrap().display())
        .await
        .unwrap();
    a.refresh().await.unwrap();
    let result = a
        .remove_device(
            removed.device_id(),
            bh_core::Removal::Full {
                password: Zeroizing::new(TEST_PASSWORD.into()),
                lost: true,
            },
        )
        .await
        .unwrap();
    let kit = result.new_kit.unwrap();
    b.refresh().await.unwrap();
    let adopted = b.test_backup_credentials().unwrap().unwrap();
    assert!(
        adopted.checked,
        "the rotation's kit record must name its envelope"
    );
    assert_eq!(
        adopted.envelope,
        a.test_backup_credentials().unwrap().unwrap().envelope
    );
    checked(&b, TEST_PASSWORD, &kit);
}

/// An envelope in the account's own format and epoch, sealed under a kit the
/// person doesn't have, as a hostile server could serve.
fn forged(account: &Account, salt: [u8; 16]) -> Vec<u8> {
    let other = RecoveryKit::generate();
    test_support::seal_envelope(
        &account.test_account_key(),
        &salt,
        TEST_PASSWORD,
        &other,
        account.id(),
    )
    .unwrap()
}

/// Backs `account` up to a new in-memory folder and returns it.
async fn back_up(core: &Core, account: &Account) -> Arc<MemoryFolder> {
    let folder = Arc::new(MemoryFolder::default());
    core.set_document_folders(folder.clone());
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .unwrap();
    let _ = account.backup_now().await;
    folder
}

#[tokio::test]
async fn a_server_envelope_the_kit_record_doesnt_name_never_replaces_unchecked_details() {
    let (a, kit) = signed_up().await;
    let salt = a.test_backup_credentials().unwrap().unwrap().salt;
    // A kit record without its salt can't check the envelope, so the new
    // device keeps the genuine one unchecked; the record still names it.
    a.test_remove_kit_record(true).await.unwrap();
    let (core, b) = approved(&a).await;
    let before = b.test_backup_credentials().unwrap().unwrap();
    assert!(!before.checked);
    replace_credentials(&a, salt, forged(&a, salt), TEST_PASSWORD).await;
    b.refresh().await.unwrap();
    let after = b.test_backup_credentials().unwrap().unwrap();
    assert_eq!(after.envelope, before.envelope);
    let folder = back_up(&core, &b).await;
    let listing = list_backups(&*folder).unwrap();
    core.open_backup(
        folder,
        &listing[0],
        Zeroizing::new(TEST_PASSWORD.into()),
        &kit.display(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn unchecked_details_become_checked_once_the_server_serves_the_named_envelope() {
    let (a, kit) = signed_up().await;
    a.test_remove_kit_record(true).await.unwrap();
    let (_core, b) = approved(&a).await;
    assert!(!b.test_backup_credentials().unwrap().unwrap().checked);
    b.refresh().await.unwrap();
    checked(&b, TEST_PASSWORD, &kit);
}

#[tokio::test]
async fn a_device_that_only_ever_saw_a_forged_envelope_writes_no_keys() {
    let (a, _) = signed_up().await;
    let original = a.test_backup_credentials().unwrap().unwrap();
    replace_credentials(&a, original.salt, forged(&a, original.salt), TEST_PASSWORD).await;
    let (core, b) = approved(&a).await;
    b.refresh().await.unwrap();
    assert!(b.test_backup_credentials().unwrap().is_none());
    let folder = back_up(&core, &b).await;
    assert!(list_backups(&*folder).unwrap().is_empty());
    assert_eq!(
        b.backup_status().unwrap().problem,
        Some(BackupProblem::NoKitRecord)
    );
    // The status asks for a new kit, which gives the device details it sealed itself.
    let kit = b.new_kit(TEST_PASSWORD).await.unwrap();
    checked(&b, TEST_PASSWORD, &kit);
    b.backup_now().await.unwrap();
    assert_eq!(list_backups(&*folder).unwrap().len(), 1);
}

#[tokio::test]
async fn an_unchecked_envelope_kept_before_the_kit_record_arrived_is_dropped_once_it_names_another()
{
    let (a, kit) = signed_up().await;
    let genuine = a.test_backup_credentials().unwrap().unwrap();
    // Account data without a kit record, as when a server withholds it, lets a
    // new device keep the server's forged envelope unchecked.
    a.test_remove_kit_record(false).await.unwrap();
    replace_credentials(&a, genuine.salt, forged(&a, genuine.salt), TEST_PASSWORD).await;
    let (core, b) = approved(&a).await;
    assert!(!b.test_backup_credentials().unwrap().unwrap().checked);
    a.test_put_kit_record(&kit, &genuine.envelope, genuine.salt)
        .await
        .unwrap();
    b.refresh().await.unwrap();
    assert!(b.test_backup_credentials().unwrap().is_none());
    let folder = back_up(&core, &b).await;
    assert!(list_backups(&*folder).unwrap().is_empty());
    assert_eq!(
        b.backup_status().unwrap().problem,
        Some(BackupProblem::NoKitRecord)
    );
}
