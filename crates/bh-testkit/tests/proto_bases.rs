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
        a.full
            .delete(&format!("/v1/devices/{}", full.device_id), json!({}))
            .await
            .0,
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
    let (status, body) = a.full.delete(&remove, json!({})).await;
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
    assert_eq!(a.full.delete(&remove, json!({})).await.0, StatusCode::OK);
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
