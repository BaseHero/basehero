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
fn account_envelope(epoch: u32) -> String {
    let mut bytes = [9; 64];
    bytes[0] = 1;
    bytes[1..5].copy_from_slice(&epoch.to_be_bytes());
    b64(&bytes)
}

async fn request(
    server: &LocalServer,
    method: Method,
    path: &str,
    body: Value,
    token: Option<&str>,
) -> (StatusCode, Value) {
    request_protocol(server, method, path, body, token, "1").await
}
async fn request_protocol(
    server: &LocalServer,
    method: Method,
    path: &str,
    body: Value,
    token: Option<&str>,
    protocol: &str,
) -> (StatusCode, Value) {
    let mut r = reqwest::Client::new()
        .request(method, server.url().join(path).unwrap())
        .header("BH-Protocol", protocol)
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
async fn an_app_device_gets_a_cap_of_one_dollar_unless_given_one() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let first = id();
    let second = id();
    for (device, cap) in [(&first, None), (&second, Some(250_000))] {
        let mut payload = json!({"deviceId":device,"kind":"app"});
        if let Some(cap) = cap {
            payload["capMicroUsd"] = json!(cap);
        }
        assert_eq!(
            f.device(s).post("/v1/devices", payload).await.0,
            StatusCode::OK
        );
    }
    let (status, account) = f.device(s).get("/v1/account", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let devices = account["devices"].as_array().unwrap();
    assert!(
        devices
            .iter()
            .find(|d| d["deviceId"] == f.device_id)
            .unwrap()
            .get("capMicroUsd")
            .is_none()
    );
    assert_eq!(
        devices.iter().find(|d| d["deviceId"] == first).unwrap()["capMicroUsd"],
        1_000_000
    );
    assert_eq!(
        devices.iter().find(|d| d["deviceId"] == second).unwrap()["capMicroUsd"],
        250_000
    );
}
#[tokio::test]
async fn only_full_devices_change_an_app_cap() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let app_id = id();
    let (_, created) = f
        .device(s)
        .post("/v1/devices", json!({"deviceId":app_id,"kind":"app"}))
        .await;
    let app = RawDevice::new(
        s,
        f.account_id.clone(),
        app_id.clone(),
        created["token"].as_str().unwrap().to_string(),
    );
    let path = format!("/v1/devices/{app_id}/cap");
    assert_eq!(
        f.device(s)
            .put(&path, json!({"capMicroUsd":5_000_000}))
            .await
            .0,
        StatusCode::OK
    );
    let (_, account) = f.device(s).get("/v1/account", json!({})).await;
    assert_eq!(
        account["devices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["deviceId"] == app_id)
            .unwrap()["capMicroUsd"],
        5_000_000
    );
    assert_eq!(
        app.put(&path, json!({"capMicroUsd":1})).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.device(s)
            .put(
                &format!("/v1/devices/{}/cap", f.device_id),
                json!({"capMicroUsd":1})
            )
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    for bad in [json!(-1), json!(1.5), json!("1")] {
        assert_eq!(
            f.device(s).put(&path, json!({"capMicroUsd":bad})).await.0,
            StatusCode::BAD_REQUEST
        );
    }
}
#[tokio::test]
async fn account_bases_come_in_creation_order() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let first = "ffffffffffffffffffffffffffffffff";
    let second = "00000000000000000000000000000000";
    for base in [first, second] {
        assert_eq!(
            f.device(s)
                .post(
                    "/v1/bases",
                    json!({"baseId":base,"epoch":1,"wrapper":b64(&random(48))})
                )
                .await
                .0,
            StatusCode::OK
        );
    }
    let (_, account) = f.device(s).get("/v1/account", json!({})).await;
    assert_eq!(account["bases"], json!([first, second]));
}
#[tokio::test]
async fn credentials_rotate_the_verifier_and_envelope() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let new_key = b64(&random(32));
    let new_salt = b64(&random(16));
    let new_envelope = account_envelope(1);
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
async fn deletion_with_an_empty_body_still_revokes() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let app_id = id();
    let (_, created) = f
        .device(s)
        .post("/v1/devices", json!({"deviceId":app_id,"kind":"app"}))
        .await;
    let app = RawDevice::new(
        s,
        f.account_id.clone(),
        app_id.clone(),
        created["token"].as_str().unwrap().to_owned(),
    );
    let response = reqwest::Client::new()
        .delete(s.url().join(&format!("/v1/devices/{app_id}")).unwrap())
        .header("BH-Protocol", "1")
        .bearer_auth(&f.token)
        .body(reqwest::Body::wrap_stream(futures_util::stream::empty::<
            Result<Vec<u8>, std::io::Error>,
        >()))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{}",
        response.text().await.unwrap()
    );
    assert_eq!(
        app.get("/v1/me", json!({})).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn deletion_without_a_body_still_revokes() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let app_id = id();
    let (_, created) = f
        .device(s)
        .post("/v1/devices", json!({"deviceId":app_id,"kind":"app"}))
        .await;
    let app = RawDevice::new(
        s,
        f.account_id.clone(),
        app_id.clone(),
        created["token"].as_str().unwrap().to_owned(),
    );
    let response = reqwest::Client::new()
        .delete(s.url().join(&format!("/v1/devices/{app_id}")).unwrap())
        .header("BH-Protocol", "1")
        .bearer_auth(&f.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        app.get("/v1/me", json!({})).await.0,
        StatusCode::UNAUTHORIZED
    );
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
async fn full_device(s: &LocalServer, f: &Fixture) -> RawDevice {
    let device_id = id();
    let (status, login) = request(
        s,
        Method::POST,
        "/v1/login",
        json!({
            "email": f.email, "loginKey": f.login_key, "deviceId": device_id
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{login}");
    let token = login["token"].as_str().unwrap();
    let (status, activated) = request(
        s,
        Method::POST,
        "/v1/devices/activate",
        json!({"activation": f.activation}),
        Some(token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{activated}");
    RawDevice::new(s, f.account_id.clone(), device_id, token.to_owned())
}

fn rotation(f: &Fixture, epoch: u32, keys: &[(&str, &str)]) -> Value {
    json!({"epoch": epoch, "loginKey": f.login_key,
        "accountKeyEnvelope": account_envelope(epoch), "activationHash": b64(&Sha256::digest([8; 32])),
        "deviceKeys": keys.iter().map(|(device_id, sealed)| json!({"deviceId": device_id, "sealed": sealed})).collect::<Vec<_>>()})
}

#[tokio::test]
async fn removal_with_rotation_moves_the_epoch_and_hands_out_device_keys() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let b = full_device(s, &f).await;
    let c = full_device(s, &f).await;
    let pending = id();
    let (_, login) = request(
        s,
        Method::POST,
        "/v1/login",
        json!({"email":f.email,"loginKey":f.login_key,"deviceId":pending}),
        None,
    )
    .await;
    let token = login["token"].as_str().unwrap();
    let notice = b64(&[7; 32]);
    let path = format!("/v1/devices/{}", c.device_id);
    let (status, body) = request_protocol(s, Method::DELETE, &path, json!({
        "notice": notice, "rotation": rotation(&f, 2, &[(&f.device_id, "AQI"), (&b.device_id, "AwQ")]),
        "data": {"ciphertext":"BQY", "expectedVersion": 0, "accountEpoch": 2}
    }), Some(&f.token), "2").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, me) =
        request_protocol(s, Method::GET, "/v1/me", json!({}), Some(&b.token), "2").await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["epoch"], 2);
    assert_eq!(me["deviceKeys"], json!([{"epoch":2,"sealed":"AwQ"}]));
    let (status, account) = request_protocol(
        s,
        Method::GET,
        "/v1/account",
        json!({}),
        Some(&f.token),
        "2",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{account}");
    assert_eq!(account["epoch"], 2);
    assert_eq!(account["deviceKeys"], json!([{"epoch":2,"sealed":"AQI"}]));
    assert_eq!(account["accountKeyEnvelope"], account_envelope(2));
    assert_eq!(account["data"], json!({"ciphertext":"BQY", "version":1}));
    let (status, revoked) = c.get("/v1/me", json!({})).await;
    assert_eq!(
        (
            status,
            revoked["error"].as_str(),
            revoked["notice"].as_str()
        ),
        (
            StatusCode::UNAUTHORIZED,
            Some("revoked"),
            Some(notice.as_str())
        )
    );
    assert_eq!(
        request_protocol(
            s,
            Method::POST,
            "/v1/devices/activate",
            json!({"activation":f.activation}),
            Some(token),
            "2"
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request_protocol(
            s,
            Method::POST,
            "/v1/devices/activate",
            json!({"activation":b64(&[8;32])}),
            Some(token),
            "2"
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn consecutive_rotations_keep_only_the_callers_history_and_filter_after_epoch() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let survivor = full_device(s, &f).await;
    let removed_a = full_device(s, &f).await;
    let removed_b = full_device(s, &f).await;
    let (status, body) = request_protocol(s, Method::DELETE, &format!("/v1/devices/{}", removed_a.device_id), json!({
        "rotation":rotation(&f, 2, &[(&f.device_id, "AQI"), (&survivor.device_id, "AwQ"), (&removed_b.device_id, "BQY")]),
        "data":{"ciphertext":"AQI", "expectedVersion":0, "accountEpoch":2}
    }), Some(&f.token), "2").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = request_protocol(
        s,
        Method::DELETE,
        &format!("/v1/devices/{}", removed_b.device_id),
        json!({
            "rotation":rotation(&f, 3, &[(&f.device_id, "Bwg"), (&survivor.device_id, "CQo")]),
            "data":{"ciphertext":"AwQ", "expectedVersion":1, "accountEpoch":3}
        }),
        Some(&f.token),
        "2",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, me) = request_protocol(
        s,
        Method::GET,
        "/v1/me",
        json!({}),
        Some(&survivor.token),
        "2",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(
        me["deviceKeys"],
        json!([{"epoch":2,"sealed":"AwQ"},{"epoch":3,"sealed":"CQo"}])
    );
    let (status, account) = request_protocol(
        s,
        Method::GET,
        "/v1/account?afterEpoch=2",
        json!({}),
        Some(&f.token),
        "2",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{account}");
    assert_eq!(account["deviceKeys"], json!([{"epoch":3,"sealed":"Bwg"}]));
    let (status, me) = request_protocol(
        s,
        Method::GET,
        "/v1/me?afterEpoch=2",
        json!({}),
        Some(&survivor.token),
        "2",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["deviceKeys"], json!([{"epoch":3,"sealed":"CQo"}]));
    for bad in [
        "-1",
        "1.5",
        "4294967296",
        "NaN",
        "",
        "0x2",
        "2&afterEpoch=1",
    ] {
        let path = format!("/v1/me?afterEpoch={bad}");
        assert_eq!(
            request_protocol(s, Method::GET, &path, json!({}), Some(&survivor.token), "2")
                .await
                .0,
            StatusCode::BAD_REQUEST,
            "{path}"
        );
    }
    // Revoked recipients cannot fetch their history, even through a later query.
    assert_eq!(
        request_protocol(
            s,
            Method::GET,
            "/v1/me?afterEpoch=0",
            json!({}),
            Some(&removed_b.token),
            "2"
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn rotation_cannot_store_a_delivery_for_the_removed_device() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let removed = full_device(s, &f).await;
    let (status, body) = request_protocol(
        s,
        Method::DELETE,
        &format!("/v1/devices/{}", removed.device_id),
        json!({
            "rotation":rotation(&f, 2, &[(&f.device_id, "AQI"), (&removed.device_id, "AwQ")]),
            "data":{"ciphertext":"AQI", "expectedVersion":0,"accountEpoch":2}
        }),
        Some(&f.token),
        "2",
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("bad_request"))
    );
    assert_eq!(removed.get("/v1/me", json!({})).await.0, StatusCode::OK);
}

#[tokio::test]
async fn rotation_without_account_data_is_refused_without_revocation() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let c = full_device(s, &f).await;
    let (status, body) = request_protocol(
        s,
        Method::DELETE,
        &format!("/v1/devices/{}", c.device_id),
        json!({"rotation":rotation(&f, 2, &[(&f.device_id, "AQI")])}),
        Some(&f.token),
        "2",
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("bad_request"))
    );
    assert_eq!(c.get("/v1/me", json!({})).await.0, StatusCode::OK);
    let (_, account) = f.device(s).get("/v1/account", json!({})).await;
    assert_eq!(account["epoch"], 1);
    assert_eq!(account["data"], Value::Null);
}

#[tokio::test]
async fn rotation_refuses_an_envelope_from_the_old_epoch() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let c = full_device(s, &f).await;
    let mut rotate = rotation(&f, 2, &[(&f.device_id, "AQI")]);
    rotate["accountKeyEnvelope"] = json!(account_envelope(1));
    let (status, body) = request_protocol(s, Method::DELETE,
        &format!("/v1/devices/{}", c.device_id),
        json!({"rotation":rotate, "data":{"ciphertext":"AQI", "expectedVersion":0, "accountEpoch":2}}),
        Some(&f.token), "2").await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("bad_request"))
    );
    assert_eq!(c.get("/v1/me", json!({})).await.0, StatusCode::OK);
    let (_, account) = f.device(s).get("/v1/account", json!({})).await;
    assert_eq!(account["epoch"], 1);
    assert_eq!(account["data"], Value::Null);
}

#[tokio::test]
async fn a_credentials_change_cannot_restore_the_old_epoch_envelope() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let c = full_device(s, &f).await;
    let (status, body) = request_protocol(
        s,
        Method::DELETE,
        &format!("/v1/devices/{}", c.device_id),
        json!({"rotation":rotation(&f, 2, &[(&f.device_id, "AQI")]),
            "data":{"ciphertext":"AQI", "expectedVersion":0,"accountEpoch":2}}),
        Some(&f.token),
        "2",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = request_protocol(
        s,
        Method::PUT,
        "/v1/account/credentials",
        json!({
            "currentLoginKey":f.login_key, "loginKey":b64(&[3;32]), "salt":b64(&[4;16]),
            "kdf":{"opsLimit":3,"memLimitKib":65536}, "accountKeyEnvelope":account_envelope(1)
        }),
        Some(&f.token),
        "2",
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("epoch_conflict"))
    );
    let (status, account) = request_protocol(
        s,
        Method::GET,
        "/v1/account",
        json!({}),
        Some(&f.token),
        "2",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{account}");
    assert_eq!(account["epoch"], 2);
    assert_eq!(account["accountKeyEnvelope"], account_envelope(2));
    assert_eq!(account["data"]["version"], 1);
    // A write that passed the protocol gate before rotation cannot commit
    // with its stale declared account epoch.
    let (status, body) = request_protocol(
        s,
        Method::PUT,
        "/v1/account/data",
        json!({"ciphertext":"AwQ", "expectedVersion":0}),
        Some(&f.token),
        "2",
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("epoch_conflict"))
    );
}

#[tokio::test]
async fn stale_account_key_cannot_write_data_with_the_current_version() {
    let server = LocalServer::from_env();
    let fixture = registered(server).await;
    let removed = full_device(server, &fixture).await;
    let path = format!("/v1/devices/{}", removed.device_id);
    let (status, body) = request_protocol(
        server,
        Method::DELETE,
        &path,
        json!({"rotation":rotation(&fixture, 2, &[(&fixture.device_id,"AQI")]),
            "data":{"ciphertext":"AQI","expectedVersion":0,"accountEpoch":2}}),
        Some(&fixture.token),
        "2",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = request_protocol(
        server,
        Method::PUT,
        "/v1/account/data",
        json!({"ciphertext":"AwQ","expectedVersion":1,"accountEpoch":1}),
        Some(&fixture.token),
        "2",
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("epoch_conflict"))
    );
    let (status, body) = request_protocol(
        server,
        Method::PUT,
        "/v1/account/data",
        json!({"ciphertext":"AwQ","expectedVersion":1,"accountEpoch":2}),
        Some(&fixture.token),
        "2",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, account) = request_protocol(
        server,
        Method::GET,
        "/v1/account",
        json!({}),
        Some(&fixture.token),
        "2",
    )
    .await;
    assert_eq!(account["data"], json!({"ciphertext":"AwQ","version":2}));
}

#[tokio::test]
async fn app_removal_data_is_fenced_after_account_rotation() {
    let server = LocalServer::from_env();
    let fixture = registered(server).await;
    let full = full_device(server, &fixture).await;
    let (status, body) = request_protocol(
        server,
        Method::DELETE,
        &format!("/v1/devices/{}", full.device_id),
        json!({"rotation":rotation(&fixture, 2, &[(&fixture.device_id,"AQI")]),
            "data":{"ciphertext":"AQI","expectedVersion":0,"accountEpoch":2}}),
        Some(&fixture.token),
        "2",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let app = id();
    assert_eq!(
        request_protocol(
            server,
            Method::POST,
            "/v1/devices",
            json!({"deviceId":app,"kind":"app"}),
            Some(&fixture.token),
            "2"
        )
        .await
        .0,
        StatusCode::OK
    );
    let (status, body) = request_protocol(
        server,
        Method::DELETE,
        &format!("/v1/devices/{app}"),
        json!({"data":{"ciphertext":"AwQ","expectedVersion":1,"accountEpoch":1}}),
        Some(&fixture.token),
        "2",
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("epoch_conflict"))
    );
    let (_, account) = request_protocol(
        server,
        Method::GET,
        "/v1/account",
        json!({}),
        Some(&fixture.token),
        "2",
    )
    .await;
    assert_eq!(account["data"], json!({"ciphertext":"AQI","version":1}));
}

#[tokio::test]
async fn rotation_rejects_data_with_the_old_declared_account_epoch() {
    let server = LocalServer::from_env();
    let fixture = registered(server).await;
    let removed = full_device(server, &fixture).await;
    let (status, body) = request_protocol(
        server,
        Method::DELETE,
        &format!("/v1/devices/{}", removed.device_id),
        json!({"rotation":rotation(&fixture, 2, &[(&fixture.device_id,"AQI")]),
            "data":{"ciphertext":"AQI","expectedVersion":0,"accountEpoch":1}}),
        Some(&fixture.token),
        "2",
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("epoch_conflict"))
    );
    assert_eq!(removed.get("/v1/me", json!({})).await.0, StatusCode::OK);
}

#[tokio::test]
async fn rotation_is_all_or_nothing() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let c = full_device(s, &f).await;
    let path = format!("/v1/devices/{}", c.device_id);
    let mut rotate = rotation(&f, 2, &[(&f.device_id, "AQI")]);
    for (key, value, expected_status, code) in [
        (
            "loginKey",
            json!(b64(&[1; 32])),
            StatusCode::UNAUTHORIZED,
            "bad_credentials",
        ),
        ("epoch", json!(3), StatusCode::CONFLICT, "epoch_conflict"),
        ("epoch", json!(2), StatusCode::CONFLICT, "version_conflict"),
    ] {
        rotate["loginKey"] = json!(f.login_key);
        rotate[key] = value;
        rotate["accountKeyEnvelope"] =
            json!(account_envelope(rotate["epoch"].as_u64().unwrap() as u32));
        let (status, body) = request_protocol(
            s,
            Method::DELETE,
            &path,
            json!({"rotation":rotate,
            "data":{"ciphertext":"AQI", "expectedVersion": 1, "accountEpoch":2}}),
            Some(&f.token),
            "2",
        )
        .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (expected_status, Some(code)),
            "{body}"
        );
        let (_, account) = f.device(s).get("/v1/account", json!({})).await;
        assert_eq!(account["epoch"], 1);
        assert_eq!(account["deviceKeys"], json!([]));
        assert_eq!(account["data"], Value::Null);
        assert_eq!(c.get("/v1/me", json!({})).await.0, StatusCode::OK);
    }
}

#[tokio::test]
async fn two_rotations_at_once_only_one_lands() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let b = full_device(s, &f).await;
    let c = full_device(s, &f).await;
    let d = full_device(s, &f).await;
    let a_path = format!("/v1/devices/{}", c.device_id);
    let b_path = format!("/v1/devices/{}", d.device_id);
    let a_request = request_protocol(
        s,
        Method::DELETE,
        &a_path,
        json!({"rotation": rotation(&f, 2, &[(&f.device_id,"AQI")]), "data":{"ciphertext":"AQI", "expectedVersion":0, "accountEpoch":2}}),
        Some(&f.token),
        "2",
    );
    let b_request = request_protocol(
        s,
        Method::DELETE,
        &b_path,
        json!({"rotation": rotation(&f, 2, &[(&b.device_id,"AwQ")]), "data":{"ciphertext":"AwQ", "expectedVersion":0, "accountEpoch":2}}),
        Some(&b.token),
        "2",
    );
    let (a, b) = tokio::join!(a_request, b_request);
    let statuses = [a.0, b.0];
    assert_eq!(
        statuses.iter().filter(|&&s| s == StatusCode::OK).count(),
        1,
        "{a:?} {b:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|&&s| s == StatusCode::CONFLICT)
            .count(),
        1,
        "{a:?} {b:?}"
    );
    assert_eq!(
        if a.0 == StatusCode::CONFLICT {
            &a.1["error"]
        } else {
            &b.1["error"]
        },
        "epoch_conflict"
    );
}

#[tokio::test]
async fn an_app_removal_can_carry_account_data() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let app_id = id();
    assert_eq!(
        f.device(s)
            .post("/v1/devices", json!({"deviceId":app_id,"kind":"app"}))
            .await
            .0,
        StatusCode::OK
    );
    let (status, body) = f
        .device(s)
        .delete(
            &format!("/v1/devices/{app_id}"),
            json!({
                "data":{"ciphertext":"AQI", "expectedVersion":0}
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, account) = f.device(s).get("/v1/account", json!({})).await;
    assert_eq!(account["epoch"], 1);
    assert_eq!(account["data"], json!({"ciphertext":"AQI","version":1}));
}

#[tokio::test]
async fn rotation_fences_an_old_protocol_write_already_waiting_on_its_body() {
    use futures_util::StreamExt;
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let b = full_device(s, &f).await;
    let c = full_device(s, &f).await;
    // Set the caller's last-seen marker so another device can observe that
    // authentication (and its epoch check) happened before releasing the body.
    assert_eq!(
        b.post(
            "/v1/devices/test-last-seen",
            json!({"deviceId":f.device_id,"lastSeenAt":0})
        )
        .await
        .0,
        StatusCode::OK
    );
    let (release, held) = tokio::sync::oneshot::channel::<()>();
    let stream = futures_util::stream::once(async {
        Ok::<Vec<u8>, std::io::Error>(b"{\"ciphertext\":\"AwQ\",".to_vec())
    })
    .chain(futures_util::stream::once(async move {
        held.await.unwrap();
        Ok::<Vec<u8>, std::io::Error>(b"\"expectedVersion\":0}".to_vec())
    }));
    let path = s.url().join("/v1/account/data").unwrap();
    let token = f.token.clone();
    let old_write = tokio::spawn(async move {
        reqwest::Client::new()
            .put(path)
            .header("BH-Protocol", "1")
            .bearer_auth(token)
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
            .unwrap()
    });
    let mut observed = false;
    for _ in 0..200 {
        let (_, account) = b.get("/v1/account", json!({})).await;
        if account["devices"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["deviceId"] == f.device_id && d["lastSeenAt"].as_i64().unwrap() > 0)
        {
            observed = true;
            break;
        }
    }
    assert!(observed, "the old request did not reach authentication");
    let (status, body) = request_protocol(
        s,
        Method::DELETE,
        &format!("/v1/devices/{}", c.device_id),
        json!({"rotation":rotation(&f, 2, &[(&f.device_id,"AQI"), (&b.device_id,"AwQ")]),
            "data":{"ciphertext":"AQI","expectedVersion":0,"accountEpoch":2}}),
        Some(&b.token),
        "2",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    release.send(()).unwrap();
    let response = old_write.await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        "epoch_conflict"
    );
    let (_, account) = request_protocol(
        s,
        Method::GET,
        "/v1/account",
        json!({}),
        Some(&b.token),
        "2",
    )
    .await;
    assert_eq!(account["data"], json!({"ciphertext":"AQI","version":1}));
}

#[tokio::test]
async fn protocol_one_is_refused_once_an_account_has_rotated() {
    let s = LocalServer::from_env();
    let f = registered(s).await;
    let c = full_device(s, &f).await;
    assert_eq!(f.device(s).get("/v1/me", json!({})).await.0, StatusCode::OK);
    let (status, body) = request_protocol(s, Method::DELETE,
        &format!("/v1/devices/{}", c.device_id),
        json!({"rotation":rotation(&f, 2, &[(&f.device_id,"AQI")]), "data":{"ciphertext":"AQI", "expectedVersion":0,"accountEpoch":2}}),
        Some(&f.token), "2").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = f.device(s).get("/v1/me", json!({})).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UPGRADE_REQUIRED, Some("needs_update"))
    );
    let (status, me) =
        request_protocol(s, Method::GET, "/v1/me", json!({}), Some(&f.token), "2").await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["epoch"], 2);
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
