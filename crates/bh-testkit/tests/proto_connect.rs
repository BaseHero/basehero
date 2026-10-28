//! App connection relay through raw wire requests.
use bh_testkit::{LocalServer, RawAccount, RawConnect, b64, random, random_id, send};
use futures_util::StreamExt;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

fn error((status, body): (StatusCode, Value)) -> (StatusCode, Value) {
    (status, body["error"].clone())
}
fn refused(status: StatusCode, code: &str) -> (StatusCode, Value) {
    (status, json!(code))
}
async fn create_bytes(s: &LocalServer, email: &str, request: Vec<u8>) -> (StatusCode, Value) {
    send(s, Method::POST, "/v1/connect", json!({"email": email, "approvalId": random_id(),
        "deviceId": random_id(), "secretHash": b64(&Sha256::digest(random(32))), "request": b64(&request)}), None).await
}
#[tokio::test]
async fn an_app_request_reaches_the_accounts_full_devices() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let mut socket = a.full.live("/v1/approvals/live").await;
    let (c, status, created) = RawConnect::create(s, &a.email).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(
        created["expiresAt"].as_i64().unwrap() - created["createdAt"].as_i64().unwrap(),
        120_000
    );
    let (status, list) = a.full.get("/v1/approvals", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["approvals"][0]["approvalId"], c.approval_id);
    assert_eq!(list["approvals"][0]["deviceId"], c.device_id);
    assert_eq!(list["approvals"][0]["kind"], "app");
    let frame = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Message::Text(text) = frame else {
        panic!("expected approval announcement")
    };
    let live: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        live,
        json!({"t":"approval", "approvalId":c.approval_id, "kind":"app", "state":"requested"})
    );
    let app = a.app(s).await;
    assert_eq!(
        error(app.get("/v1/approvals", json!({})).await),
        refused(StatusCode::FORBIDDEN, "forbidden")
    );
}
#[tokio::test]
async fn only_the_secret_reaches_an_app_request() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let (c, _, _) = RawConnect::create(s, &a.email).await;
    let (other, _, _) = RawConnect::create(s, &a.email).await;
    let url = s
        .url()
        .join(&format!("/v1/connect/{}", c.approval_id))
        .unwrap();
    for method in [Method::GET, Method::DELETE, Method::POST] {
        let path = if method == Method::POST {
            format!("{url}/reveal")
        } else {
            url.to_string()
        };
        for auth in [
            None,
            Some(format!("Connect {}", other.secret)),
            Some(format!("Bearer {}", a.full.token)),
        ] {
            let mut request = reqwest::Client::new()
                .request(method.clone(), &path)
                .header("BH-Protocol", "1")
                .header("BH-Email", &a.email)
                .json(&json!({"reveal":b64(&random(50)), "reason":"cancelled"}));
            if let Some(auth) = auth {
                request = request.header("Authorization", auth);
            }
            let reply = request.send().await.unwrap();
            assert_eq!(reply.status(), StatusCode::FORBIDDEN, "{method} {path}");
        }
    }
    let unknown = s
        .url()
        .join(&format!("/v1/connect/{}", random_id()))
        .unwrap();
    let reply = reqwest::Client::new()
        .get(unknown)
        .header("BH-Protocol", "1")
        .header("BH-Email", &a.email)
        .header("Authorization", format!("Connect {}", c.secret))
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn the_app_and_the_approver_each_take_their_own_steps() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let b = a.second_full(s).await;
    let (c, _, _) = RawConnect::create(s, &a.email).await;
    let path = format!("/v1/approvals/{}", c.approval_id);
    let response = random(1186);
    assert_eq!(
        a.full
            .post(
                &format!("{path}/respond"),
                json!({"response":b64(&response)})
            )
            .await,
        (StatusCode::OK, json!({}))
    );
    assert_eq!(c.reveal(&random(50)).await, (StatusCode::OK, json!({})));
    assert_eq!(
        error(
            a.full
                .post(
                    &format!("{path}/reveal"),
                    json!({"reveal":b64(&random(50))})
                )
                .await
        ),
        refused(StatusCode::FORBIDDEN, "forbidden")
    );
    assert_eq!(
        error(
            b.post(
                &format!("{path}/transfer"),
                json!({"transfer":b64(&random(95))})
            )
            .await
        ),
        refused(StatusCode::FORBIDDEN, "forbidden")
    );
    let transfer = random(95);
    assert_eq!(
        a.full
            .post(
                &format!("{path}/transfer"),
                json!({"transfer":b64(&transfer)})
            )
            .await,
        (StatusCode::OK, json!({}))
    );
    assert_eq!(c.state().await.1["transfer"], b64(&transfer));
}
#[tokio::test]
async fn the_eleventh_app_request_in_an_hour_is_rate_limited() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    for email in [a.email.clone(), format!("{}@example.test", random_id())] {
        for _ in 0..10 {
            assert_eq!(RawConnect::create(s, &email).await.1, StatusCode::OK);
        }
        assert_eq!(
            error({
                let (_, status, body) = RawConnect::create(s, &email).await;
                (status, body)
            }),
            refused(StatusCode::TOO_MANY_REQUESTS, "rate_limited")
        );
    }
    let pending = a.pending(s).await;
    assert_eq!(
        pending
            .post(
                "/v1/approvals",
                json!({"approvalId":random_id(),"request":b64(&random(1282))})
            )
            .await
            .0,
        StatusCode::OK
    );
}
#[tokio::test]
async fn app_messages_over_4_kib_are_refused() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    assert_eq!(
        error(create_bytes(s, &a.email, random(4097)).await),
        refused(StatusCode::PAYLOAD_TOO_LARGE, "too_large")
    );
    let (c, _, _) = RawConnect::create(s, &a.email).await;
    assert_eq!(
        a.full
            .post(
                &format!("/v1/approvals/{}/respond", c.approval_id),
                json!({"response":b64(&random(1186))})
            )
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        error(c.reveal(&random(4097)).await),
        refused(StatusCode::PAYLOAD_TOO_LARGE, "too_large")
    );
}
#[tokio::test]
async fn a_pending_device_cannot_use_the_connect_routes() {
    let s = LocalServer::from_env();
    let a = RawAccount::signup(s).await;
    let pending = a.pending(s).await;
    let (c, _, _) = RawConnect::create(s, &a.email).await;
    assert_eq!(
        error(
            pending
                .get(&format!("/v1/connect/{}", c.approval_id), json!({}))
                .await
        ),
        refused(StatusCode::FORBIDDEN, "forbidden")
    );
}
#[tokio::test]
async fn looking_up_an_unrequested_email_creates_no_relay_tables() {
    bh_testkit::local_only!();
    let s = LocalServer::start();
    let unknown = format!("{}@example.test", random_id());
    let id = random_id();
    let secret = b64(&random(32));
    let calls = [
        (Method::GET, "", json!({})),
        (Method::POST, "/reveal", json!({"reveal": b64(&random(50))})),
        (Method::DELETE, "", json!({"reason": "cancelled"})),
    ];
    let mut missing = Vec::new();
    for (method, suffix, payload) in &calls {
        let url = s.url().join(&format!("/v1/connect/{id}{suffix}")).unwrap();
        let reply = reqwest::Client::new()
            .request(method.clone(), url)
            .header("BH-Protocol", "1")
            .header("BH-Email", &unknown)
            .header("Authorization", format!("Connect {secret}"))
            .json(payload)
            .send()
            .await
            .unwrap();
        missing.push((reply.status(), reply.json::<Value>().await.unwrap()));
    }
    assert!(missing.iter().all(|reply| reply
        == &(
            StatusCode::NOT_FOUND,
            json!({"error":"not_found", "message":"not_found"})
        )));
    let storage = s.persist_dir().join("do");
    assert!(
        bh_testkit::inspect::files_containing(&storage, b"CREATE TABLE approvals").is_empty(),
        "unrequested email must not create approvals tables"
    );
    assert_eq!(RawConnect::create(&s, &unknown).await.1, StatusCode::OK);
    assert!(
        !bh_testkit::inspect::files_containing(&storage, b"CREATE TABLE approvals").is_empty(),
        "the storage inspection must see the schema after a request"
    );
    let known = RawAccount::signup(&s).await;
    for ((method, suffix, payload), expected) in calls.iter().zip(missing) {
        let url = s.url().join(&format!("/v1/connect/{id}{suffix}")).unwrap();
        let reply = reqwest::Client::new()
            .request(method.clone(), url)
            .header("BH-Protocol", "1")
            .header("BH-Email", &known.email)
            .header("Authorization", format!("Connect {secret}"))
            .json(payload)
            .send()
            .await
            .unwrap();
        assert_eq!(
            (reply.status(), reply.json::<Value>().await.unwrap()),
            expected
        );
    }
}
#[tokio::test]
async fn an_unknown_email_gets_the_same_answers() {
    bh_testkit::local_only!();
    let s = LocalServer::start_with_vars(&[("APPROVAL_TTL_MS", "300")]);
    let a = RawAccount::signup(&s).await;
    let unknown = format!("{}@example.test", random_id());
    let (known, k, reply) = RawConnect::create(&s, &a.email).await;
    let (other, u, other_reply) = RawConnect::create(&s, &unknown).await;
    assert_eq!((k, u), (StatusCode::OK, StatusCode::OK));
    assert_eq!(
        reply.as_object().unwrap().keys().collect::<Vec<_>>(),
        other_reply.as_object().unwrap().keys().collect::<Vec<_>>()
    );
    assert_eq!(
        known.state().await,
        (StatusCode::OK, json!({"state":"requested"}))
    );
    assert_eq!(other.state().await, known.state().await);
    // The deadline is shared, not one wait per request.
    tokio::time::sleep(Duration::from_millis(400)).await;
    for c in [&known, &other] {
        assert_eq!(
            c.state().await,
            (
                StatusCode::OK,
                json!({"state":"ended", "endReason":"expired"})
            )
        );
    }
    let (known, _, _) = RawConnect::create(&s, &a.email).await;
    let (other, _, _) = RawConnect::create(&s, &unknown).await;
    for c in [&known, &other] {
        assert_eq!(c.end("cancelled").await, (StatusCode::OK, json!({})));
        assert_eq!(
            c.state().await,
            (
                StatusCode::OK,
                json!({"state":"ended", "endReason":"cancelled"})
            )
        );
    }
}
