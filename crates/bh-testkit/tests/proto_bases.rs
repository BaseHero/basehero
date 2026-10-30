use bh_testkit::{LocalServer, RawAccount, RawDevice, b64, random, random_id};
use futures_util::StreamExt;
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

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

fn rekey_request(from: u32, wrapper: &str, previous: &str, apps: Value) -> Value {
    json!({"from": from, "wrapper": wrapper, "previous": previous, "apps": apps})
}

fn sealed_at(epoch: u32) -> String {
    let mut body = vec![1];
    body.extend_from_slice(&epoch.to_be_bytes());
    body.extend_from_slice(&random(12));
    b64(&body)
}

async fn protocol_two(
    server: &LocalServer,
    device: &RawDevice,
    method: reqwest::Method,
    path: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let response = reqwest::Client::new()
        .request(method, server.url().join(path).unwrap())
        .header("BH-Protocol", "2")
        .bearer_auth(&device.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    let status = response.status();
    (status, response.json().await.unwrap())
}

async fn rotate_account(server: &LocalServer, owner: &RawAccount) {
    let removed = owner.second_full(server).await;
    let mut envelope = random(64);
    envelope[0] = 1;
    envelope[1..5].copy_from_slice(&2u32.to_be_bytes());
    let response = protocol_two(
        server,
        &owner.full,
        reqwest::Method::DELETE,
        &format!("/v1/devices/{}", removed.device_id),
        json!({
            "rotation": {"epoch":2, "loginKey":owner.login_key,
                "accountKeyEnvelope":b64(&envelope), "activationHash":b64(&random(32)),
                "deviceKeys":[{"deviceId":owner.full.device_id,"sealed":"AQI"}]},
            "data":{"ciphertext":"AQI","expectedVersion":0,"accountEpoch":2}
        }),
    )
    .await;
    assert_eq!(response.0, StatusCode::OK, "{response:?}");
}

fn change(epoch: u32, size: usize) -> Value {
    let mut body = vec![1];
    body.extend_from_slice(&epoch.to_be_bytes());
    body.resize(size, 7);
    json!({"changeId":random_id(), "objectId":random_id(), "kind":"update", "body":b64(&body)})
}

#[tokio::test]
async fn account_rotation_fences_all_old_base_writes_and_creation_until_rekey() {
    let server = LocalServer::from_env();
    let owner = RawAccount::signup(server).await;
    let (base, _) = create_base(&owner.full).await;
    let path = format!("/v1/bases/{base}/changes");
    let accepted = change(1, 20);
    let original = owner
        .full
        .post(&path, json!({"changes":[accepted.clone()]}))
        .await;
    assert_eq!(original.0, StatusCode::OK);
    rotate_account(server, &owner).await;
    assert_eq!(
        protocol_two(
            server,
            &owner.full,
            reqwest::Method::POST,
            &path,
            json!({"changes":[accepted.clone()]})
        )
        .await,
        original
    );
    refused(
        protocol_two(
            server,
            &owner.full,
            reqwest::Method::POST,
            &path,
            json!({"changes":[accepted, change(1,20)]}),
        )
        .await,
        StatusCode::CONFLICT,
        "rekey_needed",
    );
    for size in [20, 1024 * 1024 + 1] {
        let old = change(1, size);
        refused(
            protocol_two(
                server,
                &owner.full,
                reqwest::Method::POST,
                &path,
                json!({"changes":[old.clone(), change(1, 20)]}),
            )
            .await,
            StatusCode::CONFLICT,
            "rekey_needed",
        );
        let (_, since) = protocol_two(
            server,
            &owner.full,
            reqwest::Method::GET,
            &format!("/v1/bases/{base}/since?after=0"),
            json!({}),
        )
        .await;
        assert_eq!(since["head"], 1);
    }
    refused(
        protocol_two(
            server,
            &owner.full,
            reqwest::Method::POST,
            "/v1/bases",
            json!({"baseId":random_id(),"epoch":1,"accountEpoch":1,"wrapper":"AQI"}),
        )
        .await,
        StatusCode::CONFLICT,
        "epoch_conflict",
    );
    let new_base = random_id();
    assert_eq!(
        protocol_two(
            server,
            &owner.full,
            reqwest::Method::POST,
            "/v1/bases",
            json!({"baseId":new_base,"epoch":1,"accountEpoch":2,"wrapper":"AQI"})
        )
        .await
        .0,
        StatusCode::OK
    );
    let rekey = format!("/v1/bases/{base}/rekey");
    refused(protocol_two(server, &owner.full, reqwest::Method::POST, &rekey,
        json!({"from":1,"accountEpoch":1,"dataVersion":1,"wrapper":"AQI","previous":"AwQ","apps":[]})).await,
        StatusCode::CONFLICT, "epoch_conflict");
    assert_eq!(protocol_two(server, &owner.full, reqwest::Method::POST, &rekey,
        json!({"from":1,"accountEpoch":2,"dataVersion":1,"wrapper":"AQI","previous":"AwQ","apps":[]})).await.0,
        StatusCode::OK);
    let (_, key) = protocol_two(
        server,
        &owner.full,
        reqwest::Method::GET,
        &format!("/v1/bases/{base}/key"),
        json!({}),
    )
    .await;
    assert_eq!(
        (key["accountEpoch"].as_u64(), key["dataFloor"].as_u64()),
        (Some(2), Some(1))
    );
    refused(protocol_two(server, &owner.full, reqwest::Method::POST, &rekey,
        json!({"from":2,"accountEpoch":1,"dataVersion":2,"wrapper":"AQI","previous":"AwQ","apps":[]})).await,
        StatusCode::CONFLICT, "epoch_conflict");
    refused(
        protocol_two(
            server,
            &owner.full,
            reqwest::Method::POST,
            &path,
            json!({"changes":[change(1,20),change(2,20)]}),
        )
        .await,
        StatusCode::CONFLICT,
        "stale_epoch",
    );
    assert_eq!(
        protocol_two(
            server,
            &owner.full,
            reqwest::Method::POST,
            &path,
            json!({"changes":[change(2,20)]})
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn old_account_key_cannot_upload_a_file_part_after_rotation() {
    let server = LocalServer::from_env();
    let owner = RawAccount::signup(server).await;
    let (base, _) = create_base(&owner.full).await;
    rotate_account(server, &owner).await;
    let bytes = random(64);
    let response = reqwest::Client::new()
        .put(
            server
                .url()
                .join(&format!("/v1/bases/{base}/files/{}/0", random_id()))
                .unwrap(),
        )
        .header("BH-Protocol", "2")
        .header("Content-Type", "application/octet-stream")
        .bearer_auth(&owner.full.token)
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        "rekey_needed"
    );
}

#[tokio::test]
async fn stale_grant_and_rekey_cannot_undo_a_removal_version_floor() {
    let server = LocalServer::from_env();
    let owner = RawAccount::signup(server).await;
    let (base, _) = create_base(&owner.full).await;
    let app = owner.app(server).await;
    let rekey = format!("/v1/bases/{base}/rekey");
    let grant = format!("/v1/bases/{base}/grants/{}", app.device_id);
    let earlier = json!({"from":1,"accountEpoch":1,"dataVersion":3,"wrapper":"AQI","previous":"AwQ","apps":[]});
    assert_eq!(owner.full.post(&rekey, earlier).await.0, StatusCode::OK);
    let (_, key) = protocol_two(
        server,
        &owner.full,
        reqwest::Method::GET,
        &format!("/v1/bases/{base}/key"),
        json!({}),
    )
    .await;
    assert_eq!(key["dataFloor"], 3);
    // An earlier rekey does not complete the removal at version 5.
    assert_eq!(
        protocol_two(
            server,
            &owner.full,
            reqwest::Method::POST,
            &rekey,
            json!({"from":2,"accountEpoch":1,"dataVersion":5,
        "wrapper":"AQI","previous":"AwQ","apps":[]})
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, key) = protocol_two(
        server,
        &owner.full,
        reqwest::Method::GET,
        &format!("/v1/bases/{base}/key"),
        json!({}),
    )
    .await;
    assert_eq!(key["dataFloor"], 5);
    refused(
        protocol_two(
            server,
            &owner.full,
            reqwest::Method::PUT,
            &grant,
            json!({"mode":"ro","epoch":3,"accountEpoch":1,
        "dataVersion":4,"wrapper":"AQI"}),
        )
        .await,
        StatusCode::CONFLICT,
        "stale_grant",
    );
    refused(
        protocol_two(
            server,
            &owner.full,
            reqwest::Method::POST,
            &rekey,
            json!({"from":3,"accountEpoch":1,"dataVersion":4,
        "wrapper":"AQI","previous":"AwQ","apps":[]}),
        )
        .await,
        StatusCode::CONFLICT,
        "stale_grant",
    );
    assert_eq!(
        protocol_two(
            server,
            &owner.full,
            reqwest::Method::GET,
            &format!("/v1/bases/{base}/key"),
            json!({})
        )
        .await
        .1["epoch"],
        3
    );
    assert_eq!(
        protocol_two(
            server,
            &app,
            reqwest::Method::GET,
            &format!("/v1/bases/{base}/key"),
            json!({})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn malformed_grant_does_not_list_base() {
    let server = LocalServer::from_env();
    let owner = RawAccount::signup(server).await;
    let (base, _) = create_base(&owner.full).await;
    let app = owner.app(server).await;
    let grant = format!("/v1/bases/{base}/grants/{}", app.device_id);
    refused(
        protocol_two(
            server,
            &owner.full,
            reqwest::Method::PUT,
            &grant,
            json!({"mode":"ro","epoch":1,"accountEpoch":1,"dataVersion":-1,"wrapper":"AQI"}),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    );
    let (_, me) = app.get("/v1/me", json!({})).await;
    assert_eq!(me["bases"], json!([]));
}

#[tokio::test]
async fn refused_regrant_preserves_existing_app_listing() {
    let server = LocalServer::from_env();
    let owner = RawAccount::signup(server).await;
    let (base, _) = create_base(&owner.full).await;
    let app = owner.app(server).await;
    let grant = format!("/v1/bases/{base}/grants/{}", app.device_id);
    let rekey = format!("/v1/bases/{base}/rekey");
    assert_eq!(
        owner
            .full
            .post(
                &rekey,
                json!({"from":1,"accountEpoch":1,"dataVersion":3,
            "wrapper":"AQI","previous":"AwQ","apps":[]})
            )
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        protocol_two(
            server,
            &owner.full,
            reqwest::Method::PUT,
            &grant,
            json!({"mode":"ro","epoch":2,"accountEpoch":1,
        "dataVersion":3,"wrapper":"AQI"})
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, me) = app.get("/v1/me", json!({})).await;
    assert_eq!(me["bases"], json!([base.clone()]));
    refused(
        protocol_two(
            server,
            &owner.full,
            reqwest::Method::PUT,
            &grant,
            json!({"mode":"ro","epoch":2,"accountEpoch":1,"dataVersion":2,"wrapper":"AQI"}),
        )
        .await,
        StatusCode::CONFLICT,
        "stale_grant",
    );
    let (_, me) = app.get("/v1/me", json!({})).await;
    assert_eq!(
        me["bases"],
        json!([base]),
        "refused regrant removed an existing listing"
    );
}

#[tokio::test]
async fn protocol_one_cannot_write_after_app_only_rekey() {
    let server = LocalServer::from_env();
    let owner = RawAccount::signup(server).await;
    let (base, _) = create_base(&owner.full).await;
    assert_eq!(
        owner
            .full
            .post(
                &format!("/v1/bases/{base}/rekey"),
                rekey_request(1, "AQI", "AwQ", json!([]))
            )
            .await
            .0,
        StatusCode::OK
    );
    refused(
        owner
            .full
            .post(
                &format!("/v1/bases/{base}/changes"),
                json!({"changes":[change(2,20)]}),
            )
            .await,
        StatusCode::UPGRADE_REQUIRED,
        "needs_update",
    );
    refused(
        owner
            .full
            .delete(
                &format!("/v1/bases/{base}/grants/{}", random_id()),
                json!({}),
            )
            .await,
        StatusCode::UPGRADE_REQUIRED,
        "needs_update",
    );
    assert_eq!(
        protocol_two(
            server,
            &owner.full,
            reqwest::Method::POST,
            &format!("/v1/bases/{base}/changes"),
            json!({"changes":[change(2,20)]})
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn rekey_moves_the_epoch_and_keeps_the_chain() {
    let s = LocalServer::from_env();
    let owner = RawAccount::signup(s).await;
    let (base, original) = create_base(&owner.full).await;
    let app = owner.app(s).await;
    let grant = format!("/v1/bases/{base}/grants/{}", app.device_id);
    assert_eq!(
        owner
            .full
            .put(
                &grant,
                json!({"mode":"ro", "epoch":1, "wrapper":b64(&random(77))})
            )
            .await
            .0,
        StatusCode::OK
    );
    let key = format!("/v1/bases/{base}/key");
    let path = format!("/v1/bases/{base}/rekey");
    let first = b64(&random(77));
    let app_first = b64(&random(77));
    let previous = b64(&random(85));
    let apps = json!([{"deviceId":app.device_id, "wrapper":app_first}]);
    assert_eq!(
        owner
            .full
            .post(&path, rekey_request(1, &first, &previous, apps.clone()))
            .await,
        (StatusCode::OK, json!({}))
    );
    assert_eq!(
        protocol_two(s, &owner.full, reqwest::Method::GET, &key, json!({})).await,
        (
            StatusCode::OK,
            json!({"epoch":2, "wrapper":first, "mode":"rw", "previous":[{"epoch":1, "sealed":previous}], "accountEpoch":1,"dataFloor":0})
        )
    );
    assert_eq!(
        protocol_two(s, &app, reqwest::Method::GET, &key, json!({})).await,
        (
            StatusCode::OK,
            json!({"epoch":2, "wrapper":app_first, "mode":"ro", "previous":[{"epoch":1, "sealed":previous}], "accountEpoch":1,"dataFloor":0})
        )
    );
    let second = b64(&random(77));
    let previous_two = b64(&random(85));
    assert_eq!(
        protocol_two(
            s,
            &owner.full,
            reqwest::Method::POST,
            &path,
            rekey_request(2, &second, &previous_two, apps)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        protocol_two(s, &owner.full, reqwest::Method::GET, &key, json!({}))
            .await
            .1,
        json!({"epoch":3, "wrapper":second, "mode":"rw", "previous":[{"epoch":1, "sealed":previous}, {"epoch":2, "sealed":previous_two}],"accountEpoch":1,"dataFloor":0})
    );
    assert_ne!(original["wrapper"], second);
}

#[tokio::test]
async fn rekey_needs_the_current_epoch() {
    let s = LocalServer::from_env();
    let owner = RawAccount::signup(s).await;
    let (base, _) = create_base(&owner.full).await;
    let path = format!("/v1/bases/{base}/rekey");
    let first = rekey_request(1, &b64(&random(77)), &b64(&random(85)), json!([]));
    assert_eq!(
        owner.full.post(&path, first.clone()).await.0,
        StatusCode::OK
    );
    refused(
        protocol_two(s, &owner.full, reqwest::Method::POST, &path, first.clone()).await,
        StatusCode::CONFLICT,
        "epoch_conflict",
    );
    let (_, key) = protocol_two(
        s,
        &owner.full,
        reqwest::Method::GET,
        &format!("/v1/bases/{base}/key"),
        json!({}),
    )
    .await;
    assert_eq!(key["wrapper"], first["wrapper"]);
    assert_eq!(
        key["previous"],
        json!([{"epoch":1, "sealed":first["previous"]}])
    );
    assert_eq!(
        protocol_two(
            s,
            &owner.full,
            reqwest::Method::POST,
            &path,
            rekey_request(2, &b64(&random(77)), &b64(&random(85)), json!([]))
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn rekey_drops_unlisted_apps() {
    let s = LocalServer::from_env();
    let owner = RawAccount::signup(s).await;
    let (base, _) = create_base(&owner.full).await;
    let app = owner.app(s).await;
    assert_eq!(
        owner
            .full
            .put(
                &format!("/v1/bases/{base}/grants/{}", app.device_id),
                json!({"mode":"rw", "epoch":1, "wrapper":b64(&random(77))})
            )
            .await
            .0,
        StatusCode::OK
    );
    let mut socket = app.live(&format!("/v1/bases/{base}/live")).await;
    assert_eq!(
        owner
            .full
            .post(
                &format!("/v1/bases/{base}/rekey"),
                rekey_request(1, &b64(&random(77)), &b64(&random(85)), json!([]))
            )
            .await
            .0,
        StatusCode::OK
    );
    refused(
        app.get(&format!("/v1/bases/{base}/key"), json!({})).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    let notice = tokio::time::timeout(Duration::from_secs(30), socket.next())
        .await
        .expect("socket did not receive epoch");
    assert!(
        matches!(notice, Some(Ok(Message::Text(ref text))) if text.as_str() == r#"{"t":"epoch","epoch":2}"#),
        "{notice:?}"
    );
    let closed = tokio::time::timeout(Duration::from_secs(30), socket.next())
        .await
        .expect("socket did not close");
    assert!(
        matches!(closed, Some(Ok(Message::Close(_))) | None),
        "{closed:?}"
    );
}

#[tokio::test]
async fn rekey_tells_live_sockets() {
    let s = LocalServer::from_env();
    let owner = RawAccount::signup(s).await;
    let (base, _) = create_base(&owner.full).await;
    let mut socket = owner.full.live(&format!("/v1/bases/{base}/live")).await;
    assert_eq!(
        owner
            .full
            .post(
                &format!("/v1/bases/{base}/rekey"),
                rekey_request(1, &b64(&random(77)), &b64(&random(85)), json!([]))
            )
            .await
            .0,
        StatusCode::OK
    );
    let notice = tokio::time::timeout(Duration::from_secs(30), socket.next())
        .await
        .expect("socket did not receive epoch");
    assert!(
        matches!(notice, Some(Ok(Message::Text(ref text))) if text.as_str() == r#"{"t":"epoch","epoch":2}"#),
        "{notice:?}"
    );
    socket.close(None).await.unwrap();
}

#[tokio::test]
async fn writes_sealed_below_the_epoch_are_refused() {
    let s = LocalServer::from_env();
    let owner = RawAccount::signup(s).await;
    let (base, _) = create_base(&owner.full).await;
    let changes = format!("/v1/bases/{base}/changes");
    let old = json!({"changeId":random_id(), "objectId":random_id(), "kind":"update", "body":sealed_at(1)});
    let stored = owner
        .full
        .post(&changes, json!({"changes":[old.clone()]}))
        .await;
    assert_eq!(stored.0, StatusCode::OK);
    assert_eq!(
        owner
            .full
            .post(
                &format!("/v1/bases/{base}/rekey"),
                rekey_request(1, &b64(&random(77)), &b64(&random(85)), json!([]))
            )
            .await
            .0,
        StatusCode::OK
    );
    let stale = json!({"changeId":random_id(), "objectId":random_id(), "kind":"update", "body":sealed_at(1)});
    let current = json!({"changeId":random_id(), "objectId":random_id(), "kind":"update", "body":sealed_at(2)});
    refused(
        protocol_two(
            s,
            &owner.full,
            reqwest::Method::POST,
            &changes,
            json!({"changes":[current.clone(), stale]}),
        )
        .await,
        StatusCode::CONFLICT,
        "stale_epoch",
    );
    // Kept states use the R2 path; its preflight must also reject the whole batch.
    let kept = json!({"changeId":random_id(), "objectId":old["objectId"], "kind":"state", "covers":1, "keep":true, "body":sealed_at(2)});
    let stale_state = json!({"changeId":random_id(), "objectId":random_id(), "kind":"state", "covers":0, "keep":true, "body":sealed_at(1)});
    refused(
        protocol_two(
            s,
            &owner.full,
            reqwest::Method::POST,
            &changes,
            json!({"changes":[kept, stale_state]}),
        )
        .await,
        StatusCode::CONFLICT,
        "stale_epoch",
    );
    let retried = protocol_two(
        s,
        &owner.full,
        reqwest::Method::POST,
        &changes,
        json!({"changes":[old]}),
    )
    .await;
    assert_eq!(retried, stored);
    let accepted = protocol_two(
        s,
        &owner.full,
        reqwest::Method::POST,
        &changes,
        json!({"changes":[current]}),
    )
    .await;
    assert_eq!(accepted.0, StatusCode::OK, "{}", accepted.1);
    assert_eq!(accepted.1["results"][0]["seq"], 2);
}

#[tokio::test]
async fn an_app_granted_before_rekey_cannot_write_under_the_previous_epoch() {
    let s = LocalServer::from_env();
    let owner = RawAccount::signup(s).await;
    let (base, _) = create_base(&owner.full).await;
    let app = owner.app(s).await;
    let grant = format!("/v1/bases/{base}/grants/{}", app.device_id);
    assert_eq!(
        owner
            .full
            .put(
                &grant,
                json!({"mode":"rw", "epoch":1, "wrapper":b64(&random(77))})
            )
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        owner
            .full
            .post(
                &format!("/v1/bases/{base}/rekey"),
                rekey_request(
                    1,
                    &b64(&random(77)),
                    &b64(&random(85)),
                    json!([{"deviceId":app.device_id, "wrapper":b64(&random(77))}])
                )
            )
            .await
            .0,
        StatusCode::OK
    );
    let changes = format!("/v1/bases/{base}/changes");
    let stale = json!({"changeId":random_id(), "objectId":random_id(), "kind":"update", "body":sealed_at(1)});
    refused(
        protocol_two(
            s,
            &app,
            reqwest::Method::POST,
            &changes,
            json!({"changes":[stale]}),
        )
        .await,
        StatusCode::CONFLICT,
        "stale_epoch",
    );
    let stale_state = json!({"changeId":random_id(), "objectId":random_id(), "kind":"state", "covers":0, "keep":true, "body":sealed_at(1)});
    refused(
        protocol_two(
            s,
            &app,
            reqwest::Method::POST,
            &changes,
            json!({"changes":[stale_state]}),
        )
        .await,
        StatusCode::CONFLICT,
        "stale_epoch",
    );
}

#[tokio::test]
async fn a_grant_settling_after_rekey_cannot_restore_an_old_wrapper() {
    let s = LocalServer::from_env();
    let owner = RawAccount::signup(s).await;
    let (base, _) = create_base(&owner.full).await;
    let app = owner.app(s).await;
    let grant = format!("/v1/bases/{base}/grants/{}", app.device_id);
    assert_eq!(
        owner
            .full
            .put(
                &grant,
                json!({"mode":"rw", "epoch":1, "wrapper":b64(&random(77))})
            )
            .await
            .0,
        StatusCode::OK
    );
    let new_wrapper = b64(&random(77));
    assert_eq!(
        owner
            .full
            .post(
                &format!("/v1/bases/{base}/rekey"),
                rekey_request(
                    1,
                    &b64(&random(77)),
                    &b64(&random(85)),
                    json!([{"deviceId":app.device_id, "wrapper":new_wrapper}])
                )
            )
            .await
            .0,
        StatusCode::OK
    );
    refused(
        protocol_two(
            s,
            &owner.full,
            reqwest::Method::PUT,
            &grant,
            json!({"mode":"ro", "epoch":1, "wrapper":b64(&random(77))}),
        )
        .await,
        StatusCode::CONFLICT,
        "epoch_conflict",
    );
    let key = protocol_two(
        s,
        &app,
        reqwest::Method::GET,
        &format!("/v1/bases/{base}/key"),
        json!({}),
    )
    .await;
    assert_eq!(key.0, StatusCode::OK);
    assert_eq!(key.1["epoch"], 2);
    assert_eq!(key.1["wrapper"], new_wrapper);
    assert_eq!(key.1["mode"], "rw");
    let current_wrapper = b64(&random(77));
    assert_eq!(
        protocol_two(
            s,
            &owner.full,
            reqwest::Method::PUT,
            &grant,
            json!({"mode":"ro", "epoch":2, "wrapper":current_wrapper})
        )
        .await
        .0,
        StatusCode::OK
    );
    let key = protocol_two(
        s,
        &app,
        reqwest::Method::GET,
        &format!("/v1/bases/{base}/key"),
        json!({}),
    )
    .await;
    assert_eq!(key.1["epoch"], 2);
    assert_eq!(key.1["wrapper"], current_wrapper);
    assert_eq!(key.1["mode"], "ro");
}

#[tokio::test]
async fn only_owners_rekey() {
    let s = LocalServer::from_env();
    let owner = RawAccount::signup(s).await;
    let (base, _) = create_base(&owner.full).await;
    let app = owner.app(s).await;
    assert_eq!(
        owner
            .full
            .put(
                &format!("/v1/bases/{base}/grants/{}", app.device_id),
                json!({"mode":"rw", "epoch":1, "wrapper":b64(&random(77))})
            )
            .await
            .0,
        StatusCode::OK
    );
    let stranger = RawAccount::signup(s).await;
    let path = format!("/v1/bases/{base}/rekey");
    let request = rekey_request(1, &b64(&random(77)), &b64(&random(85)), json!([]));
    refused(
        app.post(&path, request.clone()).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    refused(
        stranger.full.post(&path, request).await,
        StatusCode::FORBIDDEN,
        "forbidden",
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
        json!({"epoch": 1, "wrapper": request["wrapper"], "mode": "rw", "previous": [], "accountEpoch":1,"dataFloor":0})
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
    assert_eq!(
        key,
        json!({"epoch": 1, "wrapper": wrapper, "mode": "ro", "previous": [], "accountEpoch":1,"dataFloor":0})
    );
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

async fn assert_revoked_socket(
    writer: &RawDevice,
    device: &RawDevice,
    base: &str,
    expected: StatusCode,
    mut socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
) {
    let path = format!("/v1/bases/{base}/live");
    let (status, body) = writer.post(&format!("/v1/bases/{base}/changes"), json!({"changes":[{
        "changeId": random_id(), "objectId": random_id(), "kind": "update", "body": b64(&random(8))
    }]})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    tokio::time::timeout(Duration::from_secs(30), async {
        if expected == StatusCode::UNAUTHORIZED {
            let notice = socket.next().await;
            assert!(matches!(&notice, Some(Ok(Message::Text(text))) if text.as_str() == r#"{"t":"revoked"}"#), "{notice:?}");
        }
        let closed = socket.next().await;
        assert!(matches!(closed, Some(Ok(Message::Close(_))) | None), "{closed:?}");
    }).await.expect("socket was not closed");
    let refused = device
        .try_live(&path)
        .await
        .expect_err("revoked connection accepted");
    match refused {
        WsError::Http(response) => assert_eq!(response.status(), expected),
        other => panic!("connection failed unexpectedly: {other:?}"),
    }
}

#[tokio::test]
async fn revoking_a_grant_closes_the_app_socket_before_later_changes() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let (base, _) = create_base(&a.full).await;
    let app = a.app(s).await;
    let grant = format!("/v1/bases/{base}/grants/{}", app.device_id);
    assert_eq!(
        a.full
            .put(
                &grant,
                json!({"mode":"rw", "epoch":1, "wrapper": b64(&random(77))})
            )
            .await
            .0,
        StatusCode::OK
    );
    let socket = app.live(&format!("/v1/bases/{base}/live")).await;
    assert_eq!(a.full.delete(&grant, json!({})).await.0, StatusCode::OK);
    assert_revoked_socket(&a.full, &app, &base, StatusCode::FORBIDDEN, socket).await;
}

#[tokio::test]
async fn removing_a_device_closes_its_sockets_on_every_readable_base() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let (first, _) = create_base(&a.full).await;
    let (second, _) = create_base(&a.full).await;
    let full = a.second_full(s).await;
    let first_socket = full.live(&format!("/v1/bases/{first}/live")).await;
    let second_socket = full.live(&format!("/v1/bases/{second}/live")).await;
    assert_eq!(
        reqwest::Client::new()
            .delete(
                s.url()
                    .join(&format!("/v1/devices/{}", full.device_id))
                    .unwrap()
            )
            .header("BH-Protocol", "2")
            .header("BH-Test-Bypass", s.operator_token())
            .bearer_auth(&a.full.token)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_revoked_socket(
        &a.full,
        &full,
        &first,
        StatusCode::UNAUTHORIZED,
        first_socket,
    )
    .await;
    assert_revoked_socket(
        &a.full,
        &full,
        &second,
        StatusCode::UNAUTHORIZED,
        second_socket,
    )
    .await;
}

#[tokio::test]
async fn failed_base_close_still_removes_device_from_other_bases_and_retry_heals_it() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let (first, _) = create_base(&a.full).await;
    let (second, _) = create_base(&a.full).await;
    let mut bases = [first, second];
    bases.sort();
    let full = a.second_full(s).await;
    let failed_socket = full.live(&format!("/v1/bases/{}/live", bases[0])).await;
    let other_socket = full.live(&format!("/v1/bases/{}/live", bases[1])).await;
    let (status, body) = a
        .full
        .post(
            &format!("/v1/bases/{}/fail-next-device-close", bases[0]),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let remove = format!("/v1/devices/{}", full.device_id);
    let (status, body) =
        protocol_two(s, &a.full, reqwest::Method::DELETE, &remove, json!({})).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_revoked_socket(
        &a.full,
        &full,
        &bases[1],
        StatusCode::UNAUTHORIZED,
        other_socket,
    )
    .await;
    // The failed base retains the old socket until retry or its age limit.
    let (status, count) = a
        .full
        .get(&format!("/v1/bases/{}/live-count", bases[0]), json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{count}");
    assert_eq!(count["count"], 1);
    assert_eq!(
        protocol_two(s, &a.full, reqwest::Method::DELETE, &remove, json!({}))
            .await
            .0,
        StatusCode::OK
    );
    assert_revoked_socket(
        &a.full,
        &full,
        &bases[0],
        StatusCode::UNAUTHORIZED,
        failed_socket,
    )
    .await;
}

#[tokio::test]
async fn an_aged_socket_is_closed_before_a_change_is_sent() {
    let s = LocalServer::start_with_vars(&[("LIVE_SOCKET_MAX_AGE_MS", "300")]);
    let a = RawAccount::signup(&s).await;
    let (base, _) = create_base(&a.full).await;
    let full = a.second_full(&s).await;
    let mut socket = full.live(&format!("/v1/bases/{base}/live")).await;
    tokio::time::sleep(Duration::from_millis(450)).await;
    let (status, body) = a.full.post(&format!("/v1/bases/{base}/changes"), json!({"changes":[{
        "changeId": random_id(), "objectId": random_id(), "kind": "update", "body": b64(&random(8))
    }]})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let closed = tokio::time::timeout(Duration::from_secs(3), socket.next())
        .await
        .expect("socket was not closed");
    assert!(
        matches!(closed, Some(Ok(Message::Close(_))) | None),
        "aged socket received a change: {closed:?}"
    );
    // A valid device can reconnect and read the change from the committed history.
    let mut reconnect = full.live(&format!("/v1/bases/{base}/live")).await;
    let (status, since) = full
        .get(&format!("/v1/bases/{base}/since?after=0"), json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{since}");
    assert_eq!(since["objects"].as_array().unwrap().len(), 1);
    reconnect.close(None).await.unwrap();
}

#[tokio::test]
async fn removing_an_app_closes_its_granted_base_socket() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let (base, _) = create_base(&a.full).await;
    let app = a.app(s).await;
    assert_eq!(
        a.full
            .put(
                &format!("/v1/bases/{base}/grants/{}", app.device_id),
                json!({"mode":"ro", "epoch":1, "wrapper": b64(&random(77))})
            )
            .await
            .0,
        StatusCode::OK
    );
    let socket = app.live(&format!("/v1/bases/{base}/live")).await;
    assert_eq!(
        a.full
            .delete(&format!("/v1/devices/{}", app.device_id), json!({}))
            .await
            .0,
        StatusCode::OK
    );
    assert_revoked_socket(&a.full, &app, &base, StatusCode::UNAUTHORIZED, socket).await;
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
    let both = vec![first, second];
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

/// The server keeps a removing device's notice and returns it with every `revoked`
/// answer, so the removed device can check who removed it.
#[tokio::test]
async fn a_removal_notice_comes_back_with_every_revoked_answer() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let (base, _) = create_base(&a.full).await;
    let full = a.second_full(s).await;
    let mut socket = full.live(&format!("/v1/bases/{base}/live")).await;
    let remove = format!("/v1/devices/{}", full.device_id);
    for bad in [
        json!({"notice": b64(&random(31))}),
        json!({"notice": "not base64!"}),
        json!({"notice": 7}),
    ] {
        refused(
            a.full.delete(&remove, bad).await,
            StatusCode::BAD_REQUEST,
            "bad_request",
        );
    }
    assert_eq!(full.get("/v1/me", json!({})).await.0, StatusCode::OK);
    let notice = b64(&random(32));
    let (status, body) = protocol_two(
        s,
        &a.full,
        reqwest::Method::DELETE,
        &remove,
        json!({ "notice": notice }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let live = tokio::time::timeout(Duration::from_secs(30), socket.next())
        .await
        .expect("no revocation message");
    match live {
        Some(Ok(Message::Text(text))) => assert_eq!(
            serde_json::from_str::<Value>(&text).unwrap(),
            json!({"t": "revoked", "notice": notice})
        ),
        other => panic!("expected the revocation message, got {other:?}"),
    }
    let (status, body) = full.get("/v1/me", json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        (&body["error"], &body["notice"]),
        (&json!("revoked"), &json!(notice))
    );
    // Socket upgrades are refused too. tungstenite can hand back a refusal before
    // its body arrives, so the core reads the notice from its next HTTP answer.
    for path in [
        format!("/v1/bases/{base}/live"),
        "/v1/approvals/live".into(),
    ] {
        match full.try_live(&path).await {
            Err(WsError::Http(response)) => {
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}")
            }
            other => panic!("{path}: expected a refusal, got {other:?}"),
        }
    }
}

/// A bodyless protocol-2 removal still revokes and returns the old answers.
#[tokio::test]
async fn a_removal_without_a_body_revokes_without_a_notice() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let full = a.second_full(s).await;
    let response = reqwest::Client::new()
        .delete(
            s.url()
                .join(&format!("/v1/devices/{}", full.device_id))
                .unwrap(),
        )
        .header("BH-Protocol", "2")
        .bearer_auth(&a.full.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (status, body) = full.get("/v1/me", json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error": "revoked", "message": "revoked"}));
}
