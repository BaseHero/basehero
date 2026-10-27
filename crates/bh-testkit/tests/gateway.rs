#![cfg(debug_assertions)]
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bh_core::{Core, CoreConfig, FileSecretStore, SignUp};
use bh_models::{testing::*, *};
use bh_testkit::{
    LocalServer, LocalServerOptions, RawDevice, TEST_PASSWORD, b64, invite, random, random_id,
    raw_device,
};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde_json::{Value, json};
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

struct Fixture {
    enclave: TestEnclave,
    server: LocalServer,
    device: RawDevice,
    email: String,
}
async fn new_account(server: &LocalServer) -> (RawDevice, String) {
    let tmp = tempfile::tempdir().unwrap();
    let core = Core::open(CoreConfig {
        data_dir: tmp.path().join("data"),
        secrets: Arc::new(FileSecretStore::new(tmp.path().join("secrets")).unwrap()),
    })
    .unwrap();
    let signup = SignUp {
        server: server.url(),
        invite: invite(server),
        email: format!("{}@example.test", bh_core::AccountId::random()),
        password: TEST_PASSWORD.to_string().into(),
        device_name: "gateway test".into(),
    };
    let (account, _) = core.sign_up(signup).await.unwrap();
    let raw = raw_device(&account);
    (
        RawDevice::new(server, raw.account_id, raw.device_id, raw.token),
        account.email(),
    )
}
async fn new_device(server: &LocalServer) -> RawDevice {
    new_account(server).await.0
}
async fn pending_device(server: &LocalServer, account_id: &str, email: &str) -> RawDevice {
    let client = Client::new();
    let params: Value = client
        .post(server.url().join("/v1/login/params").unwrap())
        .header("BH-Protocol", "1")
        .json(&json!({"email":email}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let salt = URL_SAFE_NO_PAD
        .decode(params["salt"].as_str().unwrap())
        .unwrap();
    let key = bh_core::test_support::login_key(TEST_PASSWORD, &salt.try_into().unwrap()).unwrap();
    let id = bh_core::AccountId::random().to_string();
    let response: Value = client
        .post(server.url().join("/v1/login").unwrap())
        .header("BH-Protocol", "1")
        .json(&json!({"email":email,"loginKey":URL_SAFE_NO_PAD.encode(key),"deviceId":id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    RawDevice::new(
        server,
        account_id.into(),
        id,
        response["token"].as_str().unwrap().into(),
    )
}
fn fixture() -> &'static Mutex<Fixture> {
    static FIXTURE: OnceLock<Mutex<Fixture>> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        std::thread::spawn(|| {
            let enclave = TestEnclave::start();
            let server = LocalServer::start_with(LocalServerOptions {
                tinfoil_upstream: Some(enclave.url()),
                vars: vec![
                    ("TINFOIL_MODELS".into(), "deepseek-v4-1-flash".into()),
                    ("GATEWAY_NOW_MS".into(), "1793102400000".into()),
                ],
            });
            let (device, email) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(new_account(&server));
            Mutex::new(Fixture {
                enclave,
                server,
                device,
                email,
            })
        })
        .join()
        .unwrap()
    })
}
fn raw(f: &Fixture, key: &str) -> RequestBuilder {
    call(&f.server, &f.device.token, key)
}
fn call(server: &LocalServer, token: &str, key: &str) -> RequestBuilder {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .post(
            server
                .url()
                .join("/v1/models/tinfoil/v1/chat/completions")
                .unwrap(),
        )
        .header("BH-Protocol", "1")
        .bearer_auth(token)
        .header("ehbp-encapsulated-key", key)
        .header("x-tinfoil-enclave-url", "https://inference.tinfoil.sh")
        .header("x-tinfoil-model", "deepseek-v4-1-flash")
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body("opaque")
}
async fn usage(server: &LocalServer, account: &str, token: &str) -> reqwest::Response {
    Client::new()
        .get(
            server
                .url()
                .join(&format!("/v1/admin/usage?account={account}"))
                .unwrap(),
        )
        .header("BH-Protocol", "1")
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}
fn reply(headers: Vec<(&str, &str)>) -> EnclaveReply {
    EnclaveReply::Raw {
        status: 200,
        headers: headers
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect(),
        body: b"ciphertext".to_vec(),
    }
}
#[tokio::test]
async fn the_gateway_swaps_the_credential_and_forwards_ciphertext_unchanged() {
    let f = fixture().lock().await;
    let key = "ab".repeat(32);
    let nonce = "cd".repeat(32);
    f.enclave.reply(reply(vec![
        ("ehbp-response-nonce", &nonce),
        ("content-type", "application/json"),
    ]));
    let response = raw(&f, &key).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["ehbp-response-nonce"], nonce);
    assert_eq!(response.headers()["bh-protocol"], "1");
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"ciphertext");
    let seen = f.enclave.requests().pop().unwrap();
    assert_eq!(
        seen.original_url,
        "https://inference.tinfoil.sh/v1/chat/completions"
    );
    assert_eq!(seen.headers["authorization"], "Bearer local-tinfoil-key");
    assert_eq!(seen.headers["x-tinfoil-request-usage-metrics"], "true");
    assert_eq!(seen.headers["ehbp-encapsulated-key"], key);
    assert_eq!(seen.body, b"opaque");
    assert!(seen.headers.values().all(|v| !v.contains(&f.device.token)));
}
#[tokio::test]
async fn only_listed_headers_reach_tinfoil_and_upstream_auth_failure_is_gateway_error() {
    let f = fixture().lock().await;
    f.enclave.reply(EnclaveReply::Status(403));
    let response = raw(&f, &"ac".repeat(32))
        .header("cookie", "private")
        .header("x-forwarded-for", "10.0.0.1")
        .header("x-extra", "private")
        .header("x-tinfoil-request-usage-metrics", "false")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        "bad_gateway"
    );
    let seen = f.enclave.requests().pop().unwrap();
    for header in ["cookie", "x-forwarded-for", "x-extra"] {
        assert!(!seen.headers.contains_key(header), "{header}");
    }
    assert_eq!(seen.headers["x-tinfoil-request-usage-metrics"], "true");
}
#[tokio::test]
async fn upstream_unauthorized_and_compressed_replies_are_gateway_errors() {
    let f = fixture().lock().await;
    for upstream in [
        EnclaveReply::Status(401),
        reply(vec![("content-encoding", "gzip")]),
    ] {
        f.enclave.reply(upstream);
        let response = raw(&f, &"bc".repeat(32)).send().await.unwrap();
        assert_eq!(response.status(), 502);
        assert_eq!(
            response.json::<Value>().await.unwrap()["error"],
            "bad_gateway"
        );
    }
}
#[tokio::test]
async fn a_redirect_is_not_followed() {
    let f = fixture().lock().await;
    let before = f.enclave.requests().len();
    f.enclave
        .reply(EnclaveReply::Redirect("http://127.0.0.1:9/".into()));
    let response = raw(&f, &"ad".repeat(32)).send().await.unwrap();
    assert_eq!(response.status(), 502);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        "bad_gateway"
    );
    assert_eq!(f.enclave.requests().len(), before + 1);
}
#[tokio::test]
async fn bad_requests_never_leave_the_worker() {
    let f = fixture().lock().await;
    let before = f.enclave.requests().len();
    let key = "ae".repeat(32);
    for (req, expected) in [
        (raw(&f, ""), 400),
        (raw(&f, "not-hex"), 400),
        (
            raw(&f, &key).header("x-tinfoil-enclave-url", "https://evil.invalid"),
            400,
        ),
        (raw(&f, &key).header("x-tinfoil-model", "other"), 400),
        (raw(&f, &key).body(""), 400),
        (raw(&f, &key).body(vec![b'x'; 1024 * 1024 + 1]), 413),
        (raw(&f, &key).header("authorization", ""), 401),
        (raw(&f, &key).header("authorization", "Bearer wrong"), 401),
        (raw(&f, &key).header("BH-Protocol", "2"), 426),
    ] {
        assert_eq!(req.send().await.unwrap().status().as_u16(), expected);
    }
    for name in ["ehbp-encapsulated-key", "authorization"] {
        let mut req = raw(&f, &key).build().unwrap();
        req.headers_mut().remove(name);
        assert_eq!(
            Client::new().execute(req).await.unwrap().status().as_u16(),
            if name == "authorization" { 401 } else { 400 }
        );
    }
    assert_eq!(f.enclave.requests().len(), before);
}
#[tokio::test]
async fn a_key_config_problem_passes_through() {
    let f = fixture().lock().await;
    f.enclave.reply(EnclaveReply::KeyMismatch);
    let response = raw(&f, &"af".repeat(32)).send().await.unwrap();
    assert_eq!(response.status(), 422);
    assert_eq!(
        response.headers()["content-type"],
        "application/problem+json"
    );
    assert_eq!(
        response.text().await.unwrap(),
        r#"{"type":"urn:ietf:params:ehbp:error:key-config","title":"rotate key"}"#
    );
}
#[tokio::test]
async fn bh_models_talks_to_the_enclave_through_the_local_gateway() {
    let f = fixture().lock().await;
    let base = create_base(&f.device).await;
    f.enclave.reply(EnclaveReply::Completion(json!({"choices":[{"message":{"role":"assistant","content":"ferry"},"finish_reason":"stop"}]})));
    let model = Tinfoil::unverified_for_tests(
        Gateway::new(f.server.url().join("/v1/models/tinfoil/").unwrap().as_str()).unwrap(),
        Zeroizing::new(f.device.token.clone()),
        f.enclave.key_hex(),
    )
    .with_base(base.clone());
    let c = model
        .complete(ChatRequest {
            messages: vec![Message {
                role: Role::User,
                content: Some("One word".into()),
                tool_calls: vec![],
                tool_call_id: None,
            }],
            tools: vec![],
            tool_choice: None,
            max_tokens: 64,
        })
        .await
        .unwrap();
    assert_eq!(c.text.as_deref(), Some("ferry"));
    let seen = f.enclave.requests().pop().unwrap();
    assert_eq!(seen.headers["authorization"], "Bearer local-tinfoil-key");
    assert!(!seen.headers.contains_key("bh-base"));
    assert!(!String::from_utf8_lossy(&seen.body).contains("One word"));
}
#[tokio::test]
async fn the_model_client_sends_the_base_header() {
    let f = fixture().lock().await;
    let before = f.enclave.requests().len();
    let model = Tinfoil::unverified_for_tests(
        Gateway::new(f.server.url().join("/v1/models/tinfoil/").unwrap().as_str()).unwrap(),
        Zeroizing::new(f.device.token.clone()),
        f.enclave.key_hex(),
    )
    .with_base(random_id());
    let result = model
        .complete(ChatRequest {
            messages: vec![Message {
                role: Role::User,
                content: Some("secret".into()),
                tool_calls: vec![],
                tool_call_id: None,
            }],
            tools: vec![],
            tool_choice: None,
            max_tokens: 64,
        })
        .await;
    assert!(matches!(result, Err(ModelError::Forbidden)), "{result:?}");
    assert_eq!(f.enclave.requests().len(), before);
}
#[tokio::test]
async fn the_operator_token_no_longer_calls_models() {
    let f = fixture().lock().await;
    let before = f.enclave.requests().len();
    let r = call(&f.server, f.server.operator_token(), &"a1".repeat(32))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.json::<Value>().await.unwrap()["error"], "unauthorized");
    assert_eq!(f.enclave.requests().len(), before);
}
#[tokio::test]
async fn pending_and_removed_devices_are_refused() {
    let f = fixture().lock().await;
    let app_id = bh_core::AccountId::random().to_string();
    let (status, body) = f
        .device
        .post("/v1/devices", json!({"deviceId":app_id,"kind":"app"}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let app = RawDevice::new(
        &f.server,
        f.device.account_id.clone(),
        app_id.clone(),
        body["token"].as_str().unwrap().into(),
    );
    let (status, _) = f
        .device
        .delete(&format!("/v1/devices/{app_id}"), json!({}))
        .await;
    assert_eq!(status, StatusCode::OK);
    let before = f.enclave.requests().len();
    let r = call(&f.server, &app.token, &"a2".repeat(32))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.json::<Value>().await.unwrap()["error"], "revoked");
    let pending = pending_device(&f.server, &f.device.account_id, &f.email).await;
    let response = call(&f.server, &pending.token, &"a2".repeat(32))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(response.json::<Value>().await.unwrap()["error"], "pending");
    assert_eq!(f.enclave.requests().len(), before);
}
#[tokio::test]
async fn app_devices_may_call_models() {
    let f = fixture().lock().await;
    let app_id = bh_core::AccountId::random().to_string();
    let (status, body) = f
        .device
        .post("/v1/devices", json!({"deviceId":app_id,"kind":"app"}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    f.enclave.reply(reply(vec![]));
    let before = f.enclave.requests().len();
    let r = call(&f.server, body["token"].as_str().unwrap(), &"a3".repeat(32))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(f.enclave.requests().len(), before + 1);
}
#[tokio::test]
async fn reported_usage_is_recorded_per_account() {
    let f = fixture().lock().await;
    let a = new_device(&f.server).await;
    f.enclave.reply(reply(vec![
        (
            "x-tinfoil-usage-metrics",
            "prompt=10,completion=5,cost_usd=0.0001,model=deepseek-v4-1-flash",
        ),
        ("x-extra", "private"),
    ]));
    let response = call(&f.server, &a.token, &"b1".repeat(32))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("x-tinfoil-usage-metrics"));
    assert!(!response.headers().contains_key("x-extra"));
    let days = usage(&f.server, &a.account_id, f.server.operator_token()).await;
    assert_eq!(days.status(), 200);
    let days: Value = days.json().await.unwrap();
    let today = &days["days"][0];
    assert_eq!(today["requests"], 1);
    assert_eq!(today["prompt"], 10);
    assert_eq!(today["completion"], 5);
    assert_eq!(today["costUsd"], 0.0001);
    assert_eq!(today["missing"], 0);
    f.enclave.reply(reply(vec![]));
    assert_eq!(
        call(&f.server, &a.token, &"b2".repeat(32))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let days: Value = usage(&f.server, &a.account_id, f.server.operator_token())
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(days["days"][0]["requests"], 2);
    assert_eq!(days["days"][0]["missing"], 1);
}
#[tokio::test]
async fn exponent_form_usage_is_recorded() {
    let f = fixture().lock().await;
    let a = new_device(&f.server).await;
    f.enclave.reply(reply(vec![(
        "x-tinfoil-usage-metrics",
        "prompt=2,completion=1,cost_usd=1e-05,model=deepseek-v4-1-flash",
    )]));
    assert_eq!(
        call(&f.server, &a.token, &"b3".repeat(32))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let days: Value = usage(&f.server, &a.account_id, f.server.operator_token())
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(days["days"][0]["requests"], 1);
    assert_eq!(days["days"][0]["prompt"], 2);
    assert_eq!(days["days"][0]["completion"], 1);
    assert_eq!(days["days"][0]["costUsd"], 0.00001);
    assert_eq!(days["days"][0]["missing"], 0);
}
#[tokio::test]
async fn malformed_usage_is_counted_as_missing() {
    let f = fixture().lock().await;
    let a = new_device(&f.server).await;
    f.enclave
        .reply(reply(vec![("x-tinfoil-usage-metrics", "prompt=x")]));
    assert_eq!(
        call(&f.server, &a.token, &"b4".repeat(32))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let days: Value = usage(&f.server, &a.account_id, f.server.operator_token())
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(days["days"][0]["requests"], 1);
    assert_eq!(days["days"][0]["costUsd"], 0);
    assert_eq!(days["days"][0]["missing"], 1);
}
#[tokio::test]
async fn invalid_limits_fail_closed() {
    for (name, value) in [
        ("GATEWAY_PER_MINUTE", ""),
        ("GATEWAY_PER_DAY", "not-a-number"),
        ("GATEWAY_DAILY_COST_USD", "Infinity"),
        ("GATEWAY_PER_MINUTE", "0"),
        ("GATEWAY_DAILY_COST_USD", "-1"),
    ] {
        let enclave = TestEnclave::start();
        let server = LocalServer::start_with(LocalServerOptions {
            tinfoil_upstream: Some(enclave.url()),
            vars: vec![(name.into(), value.into())],
        });
        let a = new_device(&server).await;
        let response = call(&server, &a.token, &"b5".repeat(32))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 502, "{name}={value:?}");
        assert_eq!(
            response.json::<Value>().await.unwrap()["error"],
            "bad_gateway"
        );
        assert!(enclave.requests().is_empty(), "{name}={value:?}");
    }
}
#[tokio::test]
async fn each_account_has_its_own_rate_limit() {
    let enclave = TestEnclave::start();
    let server = LocalServer::start_with(LocalServerOptions {
        tinfoil_upstream: Some(enclave.url()),
        vars: vec![
            ("GATEWAY_PER_MINUTE".into(), "3".into()),
            ("GATEWAY_NOW_MS".into(), "1793102400000".into()),
        ],
    });
    let a = new_device(&server).await;
    let b = new_device(&server).await;
    for _ in 0..3 {
        enclave.reply(reply(vec![]));
        assert_eq!(
            call(&server, &a.token, &"c1".repeat(32))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }
    let response = call(&server, &a.token, &"c1".repeat(32))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 429);
    assert_eq!(response.headers()["retry-after"], "60");
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        "rate_limited"
    );
    assert_eq!(enclave.requests().len(), 3);
    enclave.reply(reply(vec![]));
    assert_eq!(
        call(&server, &b.token, &"c1".repeat(32))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}
#[tokio::test]
async fn a_pinned_clock_without_the_test_bypass_does_not_shift_accounting() {
    let enclave = TestEnclave::start();
    let server = LocalServer::start_with(LocalServerOptions {
        tinfoil_upstream: Some(enclave.url()),
        vars: vec![
            ("ALLOW_TEST_BYPASS".into(), "0".into()),
            ("GATEWAY_NOW_MS".into(), "946684800000".into()),
        ],
    });
    let a = new_device(&server).await;
    enclave.reply(reply(vec![(
        "x-tinfoil-usage-metrics",
        "prompt=2,completion=1,cost_usd=0.00001",
    )]));
    assert_eq!(
        call(&server, &a.token, &"c2".repeat(32))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let days: Value = usage(&server, &a.account_id, server.operator_token())
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(days["days"].as_array().unwrap().len(), 1);
    assert_ne!(days["days"][0]["day"], "2000-01-01");
    assert_eq!(days["days"][0]["requests"], 1);
    assert_eq!(days["days"][0]["prompt"], 2);
}
#[tokio::test]
async fn the_daily_cost_cap_stops_further_calls() {
    let enclave = TestEnclave::start();
    let server = LocalServer::start_with(LocalServerOptions {
        tinfoil_upstream: Some(enclave.url()),
        vars: vec![("GATEWAY_DAILY_COST_USD".into(), "0.0002".into())],
    });
    let a = new_device(&server).await;
    for _ in 0..2 {
        enclave.reply(reply(vec![(
            "x-tinfoil-usage-metrics",
            "prompt=10,completion=5,cost_usd=0.0001,model=deepseek-v4-1-flash",
        )]));
        assert_eq!(
            call(&server, &a.token, &"d1".repeat(32))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }
    let response = call(&server, &a.token, &"d1".repeat(32))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 429);
    assert_eq!(enclave.requests().len(), 2);
}
async fn create_base(device: &RawDevice) -> String {
    let base = random_id();
    let (status, body) = device
        .post(
            "/v1/bases",
            json!({"baseId": base, "epoch": 1, "wrapper": b64(&random(77))}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    base
}
async fn account_usage(server: &LocalServer, token: &str, month: &str) -> reqwest::Response {
    Client::new()
        .get(
            server
                .url()
                .join(&format!("/v1/usage?month={month}"))
                .unwrap(),
        )
        .header("BH-Protocol", "1")
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}
#[tokio::test]
async fn calls_are_recorded_by_base_and_device() {
    let f = fixture().lock().await;
    let a = new_device(&f.server).await;
    let base = create_base(&a).await;
    let app_id = random_id();
    let (status, added) = a
        .post("/v1/devices", json!({"deviceId":app_id,"kind":"app"}))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, grant) = a
        .put(
            &format!("/v1/bases/{base}/grants/{app_id}"),
            json!({"mode":"ro","epoch":1,"wrapper":b64(&random(77))}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    let metric = "prompt=10,completion=5,cost_usd=0.000101";
    for (token, base_id, metrics) in [
        (a.token.as_str(), Some(base.as_str()), Some(metric)),
        (a.token.as_str(), Some(base.as_str()), Some(metric)),
        (
            added["token"].as_str().unwrap(),
            Some(base.as_str()),
            Some(metric),
        ),
        (a.token.as_str(), None, None),
    ] {
        f.enclave.reply(reply(
            metrics.map_or(vec![], |m| vec![("x-tinfoil-usage-metrics", m)]),
        ));
        let mut req = call(&f.server, token, &"e1".repeat(32));
        if let Some(base_id) = base_id {
            req = req.header("BH-Base", base_id);
        }
        assert_eq!(req.send().await.unwrap().status(), 200);
    }
    let result: Value = account_usage(&f.server, &a.token, "2026-10")
        .await
        .json()
        .await
        .unwrap();
    let rows = result["days"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "{result}");
    let row = rows
        .iter()
        .find(|r| r["base"] == base && r["device"] == a.device_id)
        .unwrap();
    assert_eq!(row["period"], "2026-10-27");
    assert_eq!(row["service"], "model");
    assert_eq!(row["requests"], 2);
    assert_eq!(row["promptTokens"], 20);
    assert_eq!(row["costMicroUsd"], 202);
    assert_eq!(row["priceMicroUsd"], 303);
    assert_eq!(
        rows.iter().find(|r| r["device"] == app_id).unwrap()["requests"],
        1
    );
    let none = rows.iter().find(|r| r["base"].is_null()).unwrap();
    assert_eq!(none["unreported"], 1);
    assert_eq!(
        result["months"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["requests"].as_u64().unwrap())
            .sum::<u64>(),
        4
    );
}
#[tokio::test]
async fn a_call_naming_a_base_the_device_cannot_read_is_refused() {
    let f = fixture().lock().await;
    let a = new_device(&f.server).await;
    let base = create_base(&a).await;
    let app_id = random_id();
    let (_, added) = a
        .post("/v1/devices", json!({"deviceId":app_id,"kind":"app"}))
        .await;
    let other = new_device(&f.server).await;
    let before = f.enclave.requests().len();
    for (token, named) in [
        (added["token"].as_str().unwrap(), base.as_str()),
        (other.token.as_str(), base.as_str()),
    ] {
        let response = call(&f.server, token, &"e2".repeat(32))
            .header("BH-Base", named)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        assert_eq!(
            response.json::<Value>().await.unwrap()["error"],
            "forbidden"
        );
    }
    assert_eq!(f.enclave.requests().len(), before);
    assert!(
        account_usage(&f.server, &a.token, "2026-10")
            .await
            .json::<Value>()
            .await
            .unwrap()["days"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
#[tokio::test]
async fn only_the_accounts_full_devices_read_usage() {
    let f = fixture().lock().await;
    let (a, email) = new_account(&f.server).await;
    f.enclave.reply(reply(vec![]));
    assert_eq!(
        call(&f.server, &a.token, &"ed".repeat(32))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let app_id = random_id();
    let (_, added) = a
        .post("/v1/devices", json!({"deviceId":app_id,"kind":"app"}))
        .await;
    let pending = pending_device(&f.server, &a.account_id, &email).await;
    let other = new_device(&f.server).await;
    assert!(
        account_usage(&f.server, &other.token, "2026-10")
            .await
            .json::<Value>()
            .await
            .unwrap()["days"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        account_usage(&f.server, &a.token, "2026-10")
            .await
            .json::<Value>()
            .await
            .unwrap()["days"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    for (token, status, code) in [
        (added["token"].as_str().unwrap(), 403, "forbidden"),
        (&pending.token, 403, "pending"),
        ("", 401, "unauthorized"),
    ] {
        let response = account_usage(&f.server, token, "2026-10").await;
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.json::<Value>().await.unwrap()["error"], code);
    }
}
#[tokio::test]
async fn days_before_the_breakdown_show_as_not_broken_down() {
    let f = fixture().lock().await;
    let a = new_device(&f.server).await;
    let seeded = Client::new()
        .post(
            f.server
                .url()
                .join(&format!(
                    "/v1/admin/test/legacy-usage?account={}",
                    a.account_id
                ))
                .unwrap(),
        )
        .header("BH-Protocol", "1")
        .bearer_auth(f.server.operator_token())
        .send()
        .await
        .unwrap();
    assert_eq!(seeded.status(), 200);
    let result: Value = account_usage(&f.server, &a.token, "2026-10")
        .await
        .json()
        .await
        .unwrap();
    let day = &result["days"][0];
    assert_eq!(result["days"].as_array().unwrap().len(), 1);
    assert_eq!(day["requests"], 2);
    assert_eq!(day["base"], Value::Null);
    assert_eq!(day["device"], Value::Null);
    assert_eq!(day["unreported"], 1);
    assert_eq!(day["costMicroUsd"], 101);
    assert_eq!(day["priceMicroUsd"], 152);
    assert_eq!(result["months"][0]["requests"], 2);
    f.enclave.reply(reply(vec![(
        "x-tinfoil-usage-metrics",
        "prompt=4,completion=2,cost_usd=0.00001",
    )]));
    assert_eq!(
        call(&f.server, &a.token, &"f1".repeat(32))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let updated: Value = account_usage(&f.server, &a.token, "2026-10")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(updated["days"].as_array().unwrap().len(), 2);
    assert_eq!(
        updated["days"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["requests"].as_u64().unwrap())
            .sum::<u64>(),
        3
    );
    assert_eq!(
        updated["months"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["costMicroUsd"].as_u64().unwrap())
            .sum::<u64>(),
        111
    );
}
#[tokio::test]
async fn a_malformed_month_is_a_bad_request() {
    let f = fixture().lock().await;
    for month in ["2026-13", "abc"] {
        let response = account_usage(&f.server, &f.device.token, month).await;
        assert_eq!(response.status(), 400);
        assert_eq!(
            response.json::<Value>().await.unwrap()["error"],
            "bad_request"
        );
    }
}
#[tokio::test]
async fn usage_is_operator_only() {
    let f = fixture().lock().await;
    let response = usage(&f.server, &f.device.account_id, &f.device.token).await;
    assert_eq!(response.status(), 401);
}
