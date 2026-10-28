use crate::{LocalServer, RawDevice, invite};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub fn random(bytes: usize) -> Vec<u8> {
    let mut result = vec![0; bytes];
    getrandom::fill(&mut result).unwrap();
    result
}
/// A random 32-character lowercase hex ID, as clients make them.
pub fn random_id() -> String {
    random(16).iter().map(|b| format!("{b:02x}")).collect()
}
pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn unb64(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value.as_str().expect("base64url string"))
        .expect("base64url")
}

/// An unauthenticated protocol request, or one with an explicit token.
pub async fn send(
    server: &LocalServer,
    method: Method,
    path: &str,
    body: Value,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = reqwest::Client::new()
        .request(method, server.url().join(path).unwrap())
        .header("BH-Protocol", "1")
        .header("BH-Test-Bypass", server.operator_token())
        .json(&body);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.expect("raw request");
    let status = response.status();
    assert_eq!(response.headers()["BH-Protocol"], "1");
    (status, response.json().await.expect("raw JSON"))
}

/// An app-side approval over the unauthenticated connect routes.
pub struct RawConnect {
    pub email: String,
    pub approval_id: String,
    pub device_id: String,
    pub secret: String,
    server: url::Url,
    bypass: String,
}
impl RawConnect {
    pub async fn create(server: &LocalServer, email: &str) -> (Self, StatusCode, Value) {
        let app = Self {
            email: email.to_string(),
            approval_id: random_id(),
            device_id: random_id(),
            secret: b64(&random(32)),
            server: server.url(),
            bypass: server.operator_token().to_string(),
        };
        let hash = Sha256::digest(URL_SAFE_NO_PAD.decode(&app.secret).unwrap());
        let result = app
            .request(
                Method::POST,
                "/v1/connect",
                json!({
                    "email": email, "approvalId": app.approval_id, "deviceId": app.device_id,
                    "secretHash": b64(&hash), "request": b64(&random(1282))
                }),
                false,
            )
            .await;
        (app, result.0, result.1)
    }
    async fn request(
        &self,
        method: Method,
        path: &str,
        payload: Value,
        secret: bool,
    ) -> (StatusCode, Value) {
        let mut req = reqwest::Client::new()
            .request(method, self.server.join(path).unwrap())
            .header("BH-Protocol", "1")
            .header("BH-Test-Bypass", &self.bypass)
            .header("BH-Email", &self.email)
            .json(&payload);
        if secret {
            req = req.header("Authorization", format!("Connect {}", self.secret));
        }
        let response = req.send().await.expect("connect request");
        let status = response.status();
        assert_eq!(response.headers()["BH-Protocol"], "1");
        (status, response.json().await.expect("connect JSON"))
    }
    pub async fn state(&self) -> (StatusCode, Value) {
        self.request(
            Method::GET,
            &format!("/v1/connect/{}", self.approval_id),
            json!({}),
            true,
        )
        .await
    }
    pub async fn reveal(&self, bytes: &[u8]) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            &format!("/v1/connect/{}/reveal", self.approval_id),
            json!({"reveal": b64(bytes)}),
            true,
        )
        .await
    }
    pub async fn end(&self, reason: &str) -> (StatusCode, Value) {
        self.request(
            Method::DELETE,
            &format!("/v1/connect/{}", self.approval_id),
            json!({"reason": reason}),
            true,
        )
        .await
    }
}

/// An account made over the wire, with its first full device.
pub struct RawAccount {
    pub email: String,
    pub login_key: String,
    pub activation: String,
    pub full: RawDevice,
}
impl RawAccount {
    pub async fn signup(server: &LocalServer) -> Self {
        let email = format!("{}@example.test", random_id());
        let login_key = b64(&random(32));
        let activation = b64(&random(32));
        let account_id = random_id();
        let device_id = random_id();
        let (status, body) = send(
            server,
            Method::POST,
            "/v1/signup",
            json!({
                "invite": invite(server), "email": email, "accountId": account_id,
                "salt": b64(&random(16)), "kdf": { "opsLimit": 3, "memLimitKib": 65536 },
                "loginKey": login_key, "accountKeyEnvelope": b64(&random(64)),
                "activationHash": b64(&Sha256::digest(URL_SAFE_NO_PAD.decode(&activation).unwrap())),
                "deviceId": device_id
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let token = body["token"].as_str().unwrap().to_string();
        Self {
            email,
            login_key,
            activation,
            full: RawDevice::new(server, account_id, device_id, token),
        }
    }
    /// A full device that has signed in but not activated.
    pub async fn pending(&self, server: &LocalServer) -> RawDevice {
        let device_id = random_id();
        let (status, body) = send(
            server,
            Method::POST,
            "/v1/login",
            json!({"email": self.email, "loginKey": self.login_key, "deviceId": device_id}),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let token = body["token"].as_str().unwrap().to_string();
        RawDevice::new(server, self.full.account_id.clone(), device_id, token)
    }
    /// Another active full device of this account.
    pub async fn second_full(&self, server: &LocalServer) -> RawDevice {
        let device = self.pending(server).await;
        let (status, body) = device
            .post(
                "/v1/devices/activate",
                json!({"activation": self.activation}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        device
    }
    /// An active app device of this account, with no grants.
    pub async fn app(&self, server: &LocalServer) -> RawDevice {
        let device_id = random_id();
        let (status, body) = self
            .full
            .post("/v1/devices", json!({"deviceId": device_id, "kind": "app"}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let token = body["token"].as_str().unwrap().to_string();
        RawDevice::new(server, self.full.account_id.clone(), device_id, token)
    }
}
