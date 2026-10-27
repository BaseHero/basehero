//! The approval relay over the raw protocol. The server never parses the messages,
//! so each is random bytes of its real size.

use bh_testkit::{LocalServer, RawAccount, RawDevice, b64, random, random_id};
use futures_util::StreamExt;
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite, tungstenite::Message};

type Live = WebSocketStream<MaybeTlsStream<TcpStream>>;

const REQUEST_BYTES: usize = 1282;
const RESPONSE_BYTES: usize = 1186;
const REVEAL_BYTES: usize = 95;
const TRANSFER_BYTES: usize = 95;

fn path(id: &str) -> String {
    format!("/v1/approvals/{id}")
}
fn code((status, body): (StatusCode, Value)) -> (StatusCode, Option<String>) {
    (status, body["error"].as_str().map(str::to_string))
}
fn refused(status: StatusCode, error: &str) -> (StatusCode, Option<String>) {
    (status, Some(error.to_string()))
}
async fn try_create(device: &RawDevice, id: &str, request: &[u8]) -> (StatusCode, Value) {
    device
        .post(
            "/v1/approvals",
            json!({"approvalId": id, "request": b64(request)}),
        )
        .await
}
/// A new request from `device`, with its ID and bytes.
async fn create(device: &RawDevice) -> (String, Vec<u8>) {
    let id = random_id();
    let request = random(REQUEST_BYTES);
    let (status, body) = try_create(device, &id, &request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (id, request)
}
async fn step(device: &RawDevice, id: &str, name: &str, bytes: &[u8]) -> (StatusCode, Value) {
    let field = match name {
        "respond" => "response",
        other => other,
    };
    device
        .post(
            &format!("{}/{name}", path(id)),
            json!({ field: b64(bytes) }),
        )
        .await
}
async fn state(device: &RawDevice, id: &str) -> Value {
    let (status, body) = device.get(&path(id), json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}
async fn listed(device: &RawDevice) -> Vec<String> {
    let (status, body) = device.get("/v1/approvals", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["approvalId"].as_str().unwrap().to_string())
        .collect()
}
/// The next text message, skipping pings and pongs.
async fn next(live: &mut Live) -> Value {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), live.next())
            .await
            .expect("a live message within 5 s")
            .expect("socket open")
            .expect("live frame");
        match message {
            Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("unexpected live frame {other:?}"),
        }
    }
}
fn announced(id: &str, state: &str) -> Value {
    json!({"t": "approval", "approvalId": id, "state": state})
}

#[tokio::test]
async fn only_pending_devices_create_and_only_full_devices_list() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let pending = a.pending(s).await;
    let id = random_id();
    let request = random(REQUEST_BYTES);
    let (status, created) = try_create(&pending, &id, &request).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let (created_at, expires_at) = (
        created["createdAt"].as_i64().unwrap(),
        created["expiresAt"].as_i64().unwrap(),
    );
    assert_eq!(expires_at - created_at, 120_000);
    assert_eq!(
        code(try_create(&a.full, &random_id(), &request).await),
        refused(StatusCode::FORBIDDEN, "forbidden")
    );
    assert_eq!(
        code(pending.get("/v1/approvals", json!({})).await),
        refused(StatusCode::FORBIDDEN, "pending")
    );
    let app = a.app(s).await;
    assert_eq!(
        code(app.get("/v1/approvals", json!({})).await),
        refused(StatusCode::FORBIDDEN, "forbidden")
    );
    assert_eq!(
        code(app.get(&path(&id), json!({})).await),
        refused(StatusCode::FORBIDDEN, "forbidden")
    );
    let (status, list) = a.full.get("/v1/approvals", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(
        list,
        json!({"approvals": [{
            "approvalId": id, "deviceId": pending.device_id, "createdAt": created_at,
            "expiresAt": expires_at, "request": b64(&request)
        }]})
    );
    assert_eq!(state(&pending, &id).await, json!({"state": "requested"}));
}

#[tokio::test]
async fn another_accounts_full_device_cannot_read_an_approval() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let b = RawAccount::signup(s).await;
    let (id, _) = create(&a.pending(s).await).await;
    assert_eq!(
        code(b.full.get(&path(&id), json!({})).await),
        refused(StatusCode::NOT_FOUND, "not_found")
    );
}

#[tokio::test]
async fn ids_are_lowercase_hex() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let pending = a.pending(s).await;
    let upper = random_id().to_uppercase();
    assert_eq!(
        code(try_create(&pending, &upper, &random(REQUEST_BYTES)).await),
        refused(StatusCode::BAD_REQUEST, "bad_request")
    );
    for bad in [upper.as_str(), "abc", "live2"] {
        assert_eq!(
            code(a.full.get(&path(bad), json!({})).await),
            refused(StatusCode::BAD_REQUEST, "bad_request"),
            "{bad}"
        );
    }
    assert_eq!(
        code(a.full.get(&path(&random_id()), json!({})).await),
        refused(StatusCode::NOT_FOUND, "not_found")
    );
}

#[tokio::test]
async fn the_first_response_wins() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let b = a.second_full(s).await;
    let pending = a.pending(s).await;
    let (id, _) = create(&pending).await;
    let response = random(RESPONSE_BYTES);
    assert_eq!(
        step(&a.full, &id, "respond", &response).await,
        (StatusCode::OK, json!({}))
    );
    assert_eq!(
        code(step(&b, &id, "respond", &random(RESPONSE_BYTES)).await),
        refused(StatusCode::CONFLICT, "exists")
    );
    assert_eq!(
        state(&pending, &id).await,
        json!({"state": "responded", "response": b64(&response)})
    );
    // A request that has been answered leaves the list.
    assert!(listed(&b).await.is_empty());
}

#[tokio::test]
async fn each_step_belongs_to_its_party() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let b = a.second_full(s).await;
    let pending = a.pending(s).await;
    let other = a.pending(s).await;
    let (id, _) = create(&pending).await;
    let response = random(RESPONSE_BYTES);
    assert_eq!(
        code(step(&pending, &id, "reveal", &random(REVEAL_BYTES)).await),
        refused(StatusCode::CONFLICT, "version_conflict")
    );
    assert_eq!(
        step(&a.full, &id, "respond", &response).await.0,
        StatusCode::OK
    );
    assert_eq!(
        code(step(&a.full, &id, "reveal", &random(REVEAL_BYTES)).await),
        refused(StatusCode::FORBIDDEN, "forbidden")
    );
    // A pending device reaches only its own approval's reveal, read and end.
    for name in ["respond", "transfer"] {
        assert_eq!(
            code(step(&pending, &id, name, &random(TRANSFER_BYTES)).await),
            refused(StatusCode::FORBIDDEN, "pending")
        );
    }
    assert_eq!(
        code(step(&b, &id, "transfer", &random(TRANSFER_BYTES)).await),
        refused(StatusCode::FORBIDDEN, "forbidden")
    );
    assert_eq!(
        code(step(&a.full, &id, "transfer", &random(TRANSFER_BYTES)).await),
        refused(StatusCode::CONFLICT, "version_conflict")
    );
    assert_eq!(
        code(other.get(&path(&id), json!({})).await),
        refused(StatusCode::FORBIDDEN, "forbidden")
    );
    assert_eq!(
        code(
            other
                .delete(&path(&id), json!({"reason": "cancelled"}))
                .await
        ),
        refused(StatusCode::FORBIDDEN, "forbidden")
    );
    let reveal = random(REVEAL_BYTES);
    assert_eq!(
        step(&pending, &id, "reveal", &reveal).await,
        (StatusCode::OK, json!({}))
    );
    assert_eq!(
        code(step(&pending, &id, "reveal", &reveal).await),
        refused(StatusCode::CONFLICT, "version_conflict")
    );
    assert_eq!(
        state(&a.full, &id).await,
        json!({"state": "revealed", "response": b64(&response), "reveal": b64(&reveal)})
    );
    let transfer = random(TRANSFER_BYTES);
    assert_eq!(
        step(&a.full, &id, "transfer", &transfer).await,
        (StatusCode::OK, json!({}))
    );
    assert_eq!(
        state(&pending, &id).await,
        json!({"state": "transferred", "response": b64(&response), "reveal": b64(&reveal),
               "transfer": b64(&transfer)})
    );
}

#[tokio::test]
async fn a_message_over_4_kib_is_refused() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let pending = a.pending(s).await;
    assert_eq!(
        code(try_create(&pending, &random_id(), &random(4097)).await),
        refused(StatusCode::PAYLOAD_TOO_LARGE, "too_large")
    );
    let id = random_id();
    assert_eq!(
        try_create(&pending, &id, &random(4096)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        code(step(&a.full, &id, "respond", &random(4097)).await),
        refused(StatusCode::PAYLOAD_TOO_LARGE, "too_large")
    );
}

#[tokio::test]
async fn the_eleventh_request_in_an_hour_is_rate_limited() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let pending = a.pending(s).await;
    for _ in 0..10 {
        create(&pending).await;
    }
    let (id, request) = (random_id(), random(REQUEST_BYTES));
    assert_eq!(
        code(try_create(&pending, &id, &request).await),
        refused(StatusCode::TOO_MANY_REQUESTS, "rate_limited")
    );
    // The refused request leaves the device's open one alone.
    assert_eq!(listed(&a.full).await.len(), 1);
    let b = RawAccount::signup(s).await;
    create(&b.pending(s).await).await;
}

#[tokio::test]
async fn a_new_request_ends_the_devices_earlier_one() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let pending = a.pending(s).await;
    let (x, _) = create(&pending).await;
    let (y, _) = create(&pending).await;
    assert_eq!(
        state(&pending, &x).await,
        json!({"state": "ended", "endReason": "cancelled"})
    );
    assert_eq!(listed(&a.full).await, vec![y.clone()]);
    assert_eq!(
        code(try_create(&pending, &y, &random(REQUEST_BYTES)).await),
        refused(StatusCode::CONFLICT, "exists")
    );
}

#[tokio::test]
async fn an_ended_request_leaves_the_list() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let pending = a.pending(s).await;
    let (id, _) = create(&pending).await;
    assert_eq!(
        code(a.full.delete(&path(&id), json!({"reason": "bored"})).await),
        refused(StatusCode::BAD_REQUEST, "bad_request")
    );
    assert_eq!(
        a.full
            .delete(&path(&id), json!({"reason": "declined"}))
            .await,
        (StatusCode::OK, json!({}))
    );
    assert_eq!(
        state(&pending, &id).await,
        json!({"state": "ended", "endReason": "declined"})
    );
    assert!(listed(&a.full).await.is_empty());
    // The first end stands.
    assert_eq!(
        pending
            .delete(&path(&id), json!({"reason": "cancelled"}))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(state(&a.full, &id).await["endReason"], "declined");
    assert_eq!(
        code(step(&a.full, &id, "respond", &random(RESPONSE_BYTES)).await),
        refused(StatusCode::CONFLICT, "version_conflict")
    );
}

#[tokio::test]
async fn requests_expire_on_the_server() {
    bh_testkit::local_only!();
    let s = LocalServer::start_with_vars(&[("APPROVAL_TTL_MS", "300")]);
    let a = RawAccount::signup(&s).await;
    let pending = a.pending(&s).await;
    let mut full_live = a.full.live("/v1/approvals/live").await;
    let (id, _) = create(&pending).await;
    assert_eq!(next(&mut full_live).await, announced(&id, "requested"));
    assert_eq!(listed(&a.full).await, vec![id.clone()]);
    assert_eq!(
        next(&mut full_live).await,
        json!({"t": "approval", "approvalId": id, "state": "ended", "endReason": "expired"})
    );
    assert!(listed(&a.full).await.is_empty());
    assert_eq!(
        state(&pending, &id).await,
        json!({"state": "ended", "endReason": "expired"})
    );
    assert_eq!(
        code(step(&a.full, &id, "respond", &random(RESPONSE_BYTES)).await),
        refused(StatusCode::CONFLICT, "version_conflict")
    );
}

#[tokio::test]
async fn the_live_socket_announces_changes_to_the_right_devices() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let first = a.pending(s).await;
    let second = a.pending(s).await;
    let mut full_live = a.full.live("/v1/approvals/live").await;
    let mut first_live = first.live("/v1/approvals/live").await;
    let mut second_live = second.live("/v1/approvals/live").await;

    let (x, _) = create(&first).await;
    assert_eq!(next(&mut full_live).await, announced(&x, "requested"));
    assert_eq!(next(&mut first_live).await, announced(&x, "requested"));
    let ok = (StatusCode::OK, json!({}));
    assert_eq!(
        step(&a.full, &x, "respond", &random(RESPONSE_BYTES)).await,
        ok
    );
    assert_eq!(next(&mut full_live).await, announced(&x, "responded"));
    assert_eq!(next(&mut first_live).await, announced(&x, "responded"));

    // Messages arrive in order, so each pending device's first message shows it
    // heard nothing of the other's request.
    let (y, _) = create(&second).await;
    assert_eq!(next(&mut full_live).await, announced(&y, "requested"));
    assert_eq!(next(&mut second_live).await, announced(&y, "requested"));
    assert_eq!(step(&first, &x, "reveal", &random(REVEAL_BYTES)).await, ok);
    assert_eq!(next(&mut first_live).await, announced(&x, "revealed"));
    assert_eq!(next(&mut full_live).await, announced(&x, "revealed"));
    assert_eq!(
        a.full
            .delete(&path(&y), json!({"reason": "declined"}))
            .await,
        ok
    );
    assert_eq!(next(&mut second_live).await, announced(&y, "ended"));
    assert_eq!(next(&mut full_live).await, announced(&y, "ended"));
}

#[tokio::test]
async fn revoking_a_device_closes_its_approval_sockets() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let b = a.second_full(s).await;
    let pending = a.pending(s).await;
    let mut b_live = b.live("/v1/approvals/live").await;
    let mut pending_live = pending.live("/v1/approvals/live").await;
    let mut a_live = a.full.live("/v1/approvals/live").await;
    let (id, _) = create(&pending).await;
    assert_eq!(next(&mut b_live).await, announced(&id, "requested"));
    assert_eq!(next(&mut pending_live).await, announced(&id, "requested"));
    assert_eq!(next(&mut a_live).await, announced(&id, "requested"));

    for device in [&b, &pending] {
        let (status, body) = a
            .full
            .delete(&format!("/v1/devices/{}", device.device_id), json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    for live in [&mut b_live, &mut pending_live] {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), live.next())
                .await
                .expect("socket closes within 5 s")
            {
                Some(Ok(Message::Close(frame))) => {
                    assert_eq!(u16::from(frame.expect("close frame").code), 4001);
                    break;
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                other => panic!("expected a close, got {other:?}"),
            }
        }
    }
    // The revoked device's request ends with it.
    assert_eq!(next(&mut a_live).await, announced(&id, "ended"));
    assert!(listed(&a.full).await.is_empty());
    for device in [&b, &pending] {
        match device.try_live("/v1/approvals/live").await {
            Err(tungstenite::Error::Http(response)) => {
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED.as_u16())
            }
            other => panic!("expected 401, got {:?}", other.map(|_| ())),
        }
        assert_eq!(
            code(device.get("/v1/approvals/live", json!({})).await),
            refused(StatusCode::UNAUTHORIZED, "revoked")
        );
    }
}

#[tokio::test]
async fn revoking_the_approver_ends_the_exchange_as_failed() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let approver = a.second_full(s).await;
    let pending = a.pending(s).await;
    let mut pending_live = pending.live("/v1/approvals/live").await;
    let (id, _) = create(&pending).await;
    assert_eq!(next(&mut pending_live).await, announced(&id, "requested"));
    assert_eq!(
        step(&approver, &id, "respond", &random(RESPONSE_BYTES))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(next(&mut pending_live).await, announced(&id, "responded"));

    assert_eq!(
        a.full
            .delete(&format!("/v1/devices/{}", approver.device_id), json!({}))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(next(&mut pending_live).await, announced(&id, "ended"));
    assert_eq!(state(&pending, &id).await["endReason"], "failed");
    assert_eq!(
        code(step(&pending, &id, "reveal", &random(REVEAL_BYTES)).await),
        refused(StatusCode::CONFLICT, "version_conflict")
    );
}

#[tokio::test]
async fn activation_ends_open_requests() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let pending = a.pending(s).await;
    let mut full_live = a.full.live("/v1/approvals/live").await;
    let mut pending_live = pending.live("/v1/approvals/live").await;
    let (id, _) = create(&pending).await;
    assert_eq!(next(&mut full_live).await, announced(&id, "requested"));
    assert_eq!(next(&mut pending_live).await, announced(&id, "requested"));
    let (status, body) = pending
        .post("/v1/devices/activate", json!({"activation": a.activation}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(next(&mut full_live).await, announced(&id, "ended"));
    match tokio::time::timeout(Duration::from_secs(5), pending_live.next()).await {
        Ok(Some(Ok(Message::Close(Some(frame))))) => assert_eq!(u16::from(frame.code), 1000),
        other => panic!("expected normal close on activation, got {other:?}"),
    }
    let (status, body) = a.full.get(&path(&id), json!({})).await;
    assert!(
        status == StatusCode::NOT_FOUND || body["state"] == "ended",
        "{status} {body}"
    );
    assert!(listed(&a.full).await.is_empty());
}
