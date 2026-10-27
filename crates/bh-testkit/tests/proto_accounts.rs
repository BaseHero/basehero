use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bh_testkit::{LocalServer, RawDevice, invite};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn random(bytes: usize) -> Vec<u8> {
    let mut result = vec![0; bytes];
    getrandom::fill(&mut result).unwrap();
    result
}
fn id() -> String {
    hex(&random(16))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
fn email() -> String {
    format!("{}@example.test", id())
}

async fn request(
    server: &LocalServer,
    method: Method,
    path: &str,
    body: Value,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut r = reqwest::Client::new()
        .request(method, server.url().join(path).unwrap())
        .header("BH-Protocol", "1")
        .header("BH-Test-Bypass", server.operator_token())
        .json(&body);
    if let Some(t) = token {
        r = r.bearer_auth(t);
    }
    let response = r.send().await.unwrap();
    let status = response.status();
    assert_eq!(response.headers()["BH-Protocol"], "1");
    (status, response.json().await.unwrap())
}
struct Fixture {
    email: String,
    login_key: String,
    activation: String,
    account_id: String,
    device_id: String,
    token: String,
}
impl Fixture {
    fn device(&self, server: &LocalServer) -> RawDevice {
        RawDevice::new(
            server,
            self.account_id.clone(),
            self.device_id.clone(),
            self.token.clone(),
        )
    }
}
async fn signup(server: &LocalServer, email: String, code: String) -> (StatusCode, Value, Fixture) {
    let login_key = b64(&random(32));
    let activation = b64(&random(32));
    let account_id = id();
    let device_id = id();
    let payload = json!({
        "invite": code, "email": email, "accountId": account_id,
        "salt": b64(&random(16)), "kdf": { "opsLimit": 3, "memLimitKib": 65536 },
        "loginKey": login_key, "accountKeyEnvelope": b64(&random(64)),
        "activationHash": b64(&Sha256::digest(URL_SAFE_NO_PAD.decode(&activation).unwrap())),
        "deviceId": device_id
    });
    let (status, response) = request(server, Method::POST, "/v1/signup", payload, None).await;
    let fixture = Fixture {
        email,
        login_key,
        activation,
        account_id,
        device_id,
        token: response["token"].as_str().unwrap_or("").to_string(),
    };
    (status, response, fixture)
}
async fn registered(server: &LocalServer) -> Fixture {
    let (status, response, fixture) = signup(server, email(), invite(server)).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    fixture
}

#[tokio::test]
async fn invite_works_once() {
    let s = LocalServer::from_env();
    let code = invite(s);
    assert_eq!(signup(s, email(), code.clone()).await.0, StatusCode::OK);
    let (status, response, _) = signup(s, email(), code).await;
    assert_eq!(
        (status, response["error"].as_str()),
        (StatusCode::CONFLICT, Some("invite_used"))
    );
}
#[tokio::test]
async fn email_is_unique() {
    let s = LocalServer::from_env();
    let address = email();
    assert_eq!(
        signup(s, address.clone(), invite(s)).await.0,
        StatusCode::OK
    );
    let (status, response, _) = signup(s, address, invite(s)).await;
    assert_eq!(
        (status, response["error"].as_str()),
        (StatusCode::CONFLICT, Some("email_taken"))
    );
}
#[tokio::test]
async fn login_with_wrong_key_is_refused() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let (status, body) = request(
        s,
        Method::POST,
        "/v1/login",
        json!({"email":f.email,"loginKey":b64(&random(32)),"deviceId":id()}),
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("bad_credentials"))
    );
}
#[tokio::test]
async fn unknown_email_gets_stable_fake_params() {
    let s = LocalServer::from_env();
    let address = email();
    let params = json!({"email":address});
    let (a, first) = request(s, Method::POST, "/v1/login/params", params.clone(), None).await;
    let (b, second) = request(s, Method::POST, "/v1/login/params", params, None).await;
    assert_eq!((a, b), (StatusCode::OK, StatusCode::OK));
    assert_eq!(first, second);
    assert_eq!(first["kdf"], json!({"opsLimit":3,"memLimitKib":65536}));
    let (status, body) = request(
        s,
        Method::POST,
        "/v1/login",
        json!({"email":address,"loginKey":b64(&random(32)),"deviceId":id()}),
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("bad_credentials"))
    );
}
#[tokio::test]
async fn pending_device_may_only_activate() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let (status, login) = request(
        s,
        Method::POST,
        "/v1/login",
        json!({"email":f.email,"loginKey":f.login_key,"deviceId":id()}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{login}");
    assert_eq!(login["accountId"], f.account_id);
    let token = login["token"].as_str().unwrap();
    let (status, body) = request(s, Method::GET, "/v1/account", json!({}), Some(token)).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("pending"))
    );
    let (status, body) = request(
        s,
        Method::POST,
        "/v1/devices/activate",
        json!({"activation":b64(&random(32))}),
        Some(token),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("unauthorized"))
    );
    let (status, body) = request(
        s,
        Method::POST,
        "/v1/devices/activate",
        json!({"activation":f.activation}),
        Some(token),
    )
    .await;
    assert_eq!((status, body), (StatusCode::OK, json!({})));
    let (status, account) = request(s, Method::GET, "/v1/account", json!({}), Some(token)).await;
    assert_eq!(status, StatusCode::OK, "{account}");
    assert_eq!(account["devices"].as_array().unwrap().len(), 2);
}
#[tokio::test]
async fn eleventh_bad_login_in_window_is_rate_limited() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    for _ in 0..10 {
        let (status, _) = request(
            s,
            Method::POST,
            "/v1/login",
            json!({"email":f.email,"loginKey":b64(&random(32)),"deviceId":id()}),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, body) = request(
        s,
        Method::POST,
        "/v1/login",
        json!({"email":f.email,"loginKey":b64(&random(32)),"deviceId":id()}),
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited"))
    );
}
#[tokio::test]
async fn concurrent_bad_logins_exhaust_the_account_window() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let mut attempts = tokio::task::JoinSet::new();
    for _ in 0..12 {
        let email = f.email.clone();
        attempts.spawn(async move {
            request(
                s,
                Method::POST,
                "/v1/login",
                json!({"email":email,"loginKey":b64(&random(32)),"deviceId":id()}),
                None,
            )
            .await
        });
    }
    let mut refused = 0;
    let mut throttled = 0;
    while let Some(response) = attempts.join_next().await {
        match response.unwrap().0 {
            StatusCode::UNAUTHORIZED => refused += 1,
            StatusCode::TOO_MANY_REQUESTS => throttled += 1,
            other => panic!("unexpected login status {other}"),
        }
    }
    assert_eq!((refused, throttled), (10, 2));
    let (status, body) = request(
        s,
        Method::POST,
        "/v1/login",
        json!({"email":f.email,"loginKey":b64(&random(32)),"deviceId":id()}),
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited"))
    );
}
#[tokio::test]
async fn account_data_uses_versions() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let payload = json!({"ciphertext":b64(&random(60)),"expectedVersion":0});
    let (status, response) = f.device(s).put("/v1/account/data", payload.clone()).await;
    assert_eq!((status, response), (StatusCode::OK, json!({"version":1})));
    let (status, response) = f.device(s).put("/v1/account/data", payload).await;
    assert_eq!(
        (status, response["error"].as_str()),
        (StatusCode::CONFLICT, Some("version_conflict"))
    );
}
#[tokio::test]
async fn account_data_accepts_128_kib_of_ciphertext() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let ciphertext = b64(&random(128 * 1024));
    let (status, body) = f
        .device(s)
        .put(
            "/v1/account/data",
            json!({"ciphertext":ciphertext,"expectedVersion":0}),
        )
        .await;
    assert_eq!((status, body), (StatusCode::OK, json!({"version":1})));
}
#[tokio::test]
async fn account_data_over_one_mib_is_rejected() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let ciphertext = b64(&random(1024 * 1024 + 1));
    let (status, body) = f
        .device(s)
        .put(
            "/v1/account/data",
            json!({"ciphertext":ciphertext,"expectedVersion":0}),
        )
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::PAYLOAD_TOO_LARGE, Some("too_large"))
    );
}
#[tokio::test]
async fn app_device_cannot_read_the_account() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let (status, response) = f
        .device(s)
        .post("/v1/devices", json!({"deviceId":id(),"kind":"app"}))
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let token = response["token"].as_str().unwrap();
    let (status, body) = request(s, Method::GET, "/v1/account", json!({}), Some(token)).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden"))
    );
    let (status, body) = request(s, Method::GET, "/v1/me", json!({}), Some(token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["kind"], "app");
    assert_eq!(body["bases"], json!([]));
}
#[tokio::test]
async fn credentials_rotate_the_verifier_and_envelope() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let new_key = b64(&random(32));
    let new_salt = b64(&random(16));
    let new_envelope = b64(&random(64));
    let (status, body) = f
        .device(s)
        .put(
            "/v1/account/credentials",
            json!({
                "currentLoginKey":f.login_key,"loginKey":new_key,"salt":new_salt,
                "kdf":{"opsLimit":3,"memLimitKib":65536},"accountKeyEnvelope":new_envelope
            }),
        )
        .await;
    assert_eq!((status, body), (StatusCode::OK, json!({})));
    let (_, params) = request(
        s,
        Method::POST,
        "/v1/login/params",
        json!({"email":f.email}),
        None,
    )
    .await;
    assert_eq!(params["salt"], new_salt);
    let (status, body) = request(
        s,
        Method::POST,
        "/v1/login",
        json!({"email":f.email,"loginKey":f.login_key,"deviceId":id()}),
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("bad_credentials"))
    );
    let (status, body) = request(
        s,
        Method::POST,
        "/v1/login",
        json!({"email":f.email,"loginKey":new_key,"deviceId":id()}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accountKeyEnvelope"], new_envelope);
    let (status, account) = f.device(s).get("/v1/account", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{account}");
    assert_eq!(account["accountKeyEnvelope"], new_envelope);
}
#[tokio::test]
async fn deleted_device_token_is_revoked() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let app_id = id();
    let (status, body) = f
        .device(s)
        .post("/v1/devices", json!({"deviceId":app_id,"kind":"app"}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let app = RawDevice::new(
        s,
        f.account_id.clone(),
        app_id.clone(),
        body["token"].as_str().unwrap().to_string(),
    );
    assert_eq!(
        app.delete(&format!("/v1/devices/{app_id}"), json!({}))
            .await
            .0,
        StatusCode::OK
    );
    let (status, body) = app.get("/v1/me", json!({})).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("revoked"))
    );
}
#[tokio::test]
async fn invalid_invite_does_not_reserve_email() {
    let s = LocalServer::from_env();
    let email = email();
    let (status, body, _) = signup(s, email.clone(), "0000000000".into()).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("invite_used"))
    );
    assert_eq!(signup(s, email, invite(s)).await.0, StatusCode::OK);
}
#[tokio::test]
async fn invalid_invite_does_not_disclose_registered_email() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let (status, body, _) = signup(s, f.email, "0000000000".into()).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("invite_used"))
    );
}
#[tokio::test]
async fn malformed_ids_are_rejected() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let (status, body) = f
        .device(s)
        .post(
            "/v1/devices",
            json!({"deviceId":f.device_id.to_uppercase(),"kind":"app"}),
        )
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("bad_request"))
    );
    let (status, body) = f.device(s).delete("/v1/devices/ABCDEF", json!({})).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("bad_request"))
    );
}
