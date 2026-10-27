use bh_testkit::{LocalServer, RawAccount, RawDevice, b64, random, random_id};
use reqwest::StatusCode;
use serde_json::{Value, json};

async fn create_base(device: &RawDevice) -> (String, Value) {
    let base = random_id();
    let request = json!({"baseId": base, "epoch": 1, "wrapper": b64(&random(77))});
    let (status, body) = device.post("/v1/bases", request.clone()).await;
    assert_eq!((status, body), (StatusCode::OK, json!({})));
    (base, request)
}
fn refused(response: (StatusCode, Value), status: StatusCode, code: &str) {
    assert_eq!(
        (response.0, response.1["error"].as_str()),
        (status, Some(code)),
        "{}",
        response.1
    );
}

#[tokio::test]
async fn a_full_device_creates_a_base_and_reads_its_wrapper() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let (base, request) = create_base(&a.full).await;
    let (status, key) = a
        .full
        .get(&format!("/v1/bases/{base}/key"), json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{key}");
    assert_eq!(
        key,
        json!({"epoch": 1, "wrapper": request["wrapper"], "mode": "rw"})
    );
    refused(
        a.full.post("/v1/bases", request).await,
        StatusCode::CONFLICT,
        "exists",
    );
}

#[tokio::test]
async fn a_second_full_device_of_the_account_reads_the_same_wrapper() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let (base, request) = create_base(&a.full).await;
    let second = a.second_full(s).await;
    let (status, key) = second
        .get(&format!("/v1/bases/{base}/key"), json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{key}");
    assert_eq!(key["wrapper"], request["wrapper"]);
    assert_eq!(key["mode"], "rw");
}

#[tokio::test]
async fn other_accounts_pending_devices_and_ungranted_apps_are_refused() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let (base, _) = create_base(&a.full).await;
    let path = format!("/v1/bases/{base}/key");
    let other = RawAccount::signup(s).await;
    refused(
        other.full.get(&path, json!({})).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    let pending = a.pending(s).await;
    refused(
        pending.get(&path, json!({})).await,
        StatusCode::FORBIDDEN,
        "pending",
    );
    let app = a.app(s).await;
    refused(
        app.get(&path, json!({})).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    // Another account can't claim the base or grant on it.
    refused(
        other
            .full
            .post(
                "/v1/bases",
                json!({"baseId": base, "epoch": 1, "wrapper": b64(&random(77))}),
            )
            .await,
        StatusCode::CONFLICT,
        "exists",
    );
    let other_app = other.app(s).await;
    refused(
        other
            .full
            .put(
                &format!("/v1/bases/{base}/grants/{}", other_app.device_id),
                json!({"mode": "rw", "epoch": 1, "wrapper": b64(&random(77))}),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
}

#[tokio::test]
async fn a_granted_app_reads_its_own_wrapper_and_a_revoked_grant_is_gone() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let (base, _) = create_base(&a.full).await;
    let app = a.app(s).await;
    let grant = format!("/v1/bases/{base}/grants/{}", app.device_id);
    let wrapper = b64(&random(77));
    // An app device can't grant itself.
    refused(
        app.put(
            &grant,
            json!({"mode": "rw", "epoch": 1, "wrapper": wrapper}),
        )
        .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    let (status, body) = a
        .full
        .put(
            &grant,
            json!({"mode": "ro", "epoch": 1, "wrapper": wrapper}),
        )
        .await;
    assert_eq!((status, body), (StatusCode::OK, json!({})));
    let path = format!("/v1/bases/{base}/key");
    let (status, key) = app.get(&path, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{key}");
    assert_eq!(key, json!({"epoch": 1, "wrapper": wrapper, "mode": "ro"}));
    let (status, body) = a.full.delete(&grant, json!({})).await;
    assert_eq!((status, body), (StatusCode::OK, json!({})));
    refused(
        app.get(&path, json!({})).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    let (_, me) = app.get("/v1/me", json!({})).await;
    assert_eq!(me["bases"], json!([]));
}

#[tokio::test]
async fn grants_are_only_for_the_accounts_app_devices() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let (base, _) = create_base(&a.full).await;
    let grant = json!({"mode": "rw", "epoch": 1, "wrapper": b64(&random(77))});
    let second = a.second_full(s).await;
    refused(
        a.full
            .put(
                &format!("/v1/bases/{base}/grants/{}", second.device_id),
                grant.clone(),
            )
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    let stranger = RawAccount::signup(s).await.app(s).await;
    refused(
        a.full
            .put(
                &format!("/v1/bases/{base}/grants/{}", stranger.device_id),
                grant.clone(),
            )
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    let app = a.app(s).await;
    refused(
        a.full
            .put(
                &format!("/v1/bases/{base}/grants/{}", app.device_id),
                json!({"mode": "admin", "epoch": 1, "wrapper": b64(&random(77))}),
            )
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    );
}

#[tokio::test]
async fn me_and_account_list_the_bases() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let (first, _) = create_base(&a.full).await;
    let (second, _) = create_base(&a.full).await;
    let app = a.app(s).await;
    let (status, _) = a
        .full
        .put(
            &format!("/v1/bases/{first}/grants/{}", app.device_id),
            json!({"mode": "rw", "epoch": 1, "wrapper": b64(&random(77))}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, me) = app.get("/v1/me", json!({})).await;
    assert_eq!(me["bases"], json!([first]));
    let mut both = vec![first, second];
    both.sort();
    let (_, account) = a.full.get("/v1/account", json!({})).await;
    assert_eq!(account["bases"], json!(both));
    let (_, me) = a.full.get("/v1/me", json!({})).await;
    assert_eq!(me["bases"], json!(both));
}

#[tokio::test]
async fn ids_must_be_lowercase_hex() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let (base, _) = create_base(&a.full).await;
    refused(
        a.full
            .get(&format!("/v1/bases/{}/key", base.to_uppercase()), json!({}))
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    );
    refused(
        a.full
            .post(
                "/v1/bases",
                json!({"baseId": random_id().to_uppercase(), "epoch": 1, "wrapper": b64(&random(77))}),
            )
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    );
    refused(
        a.full
            .put(
                &format!("/v1/bases/{base}/grants/abc"),
                json!({"mode": "rw", "epoch": 1, "wrapper": b64(&random(77))}),
            )
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    );
    refused(
        a.full
            .post(
                &format!("/v1/bases/{base}/changes"),
                json!({"changes": [{"changeId": "XYZ", "objectId": random_id(), "kind": "update", "body": "AA"}]}),
            )
            .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    );
}
