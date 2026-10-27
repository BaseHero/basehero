use crate::LocalServer;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bh_core::{Account, Clock, Core, CoreConfig, FileSecretStore, SignIn, SignUp};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use url::Url;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn raw_changes_retry_when_the_local_worker_drops_the_http_reply() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            first
                .write_all(b"HTTP/1.1 200 OK\r\nContent-")
                .await
                .unwrap();
            drop(first);
            let (mut second, _) = listener.accept().await.unwrap();
            second.write_all(b"HTTP/1.1 200 OK\r\nBH-Protocol: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
        });
        let device = RawDevice {
            account_id: String::new(),
            device_id: String::new(),
            token: String::new(),
            server: Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap(),
            bypass: String::new(),
        };
        let (status, body) = device
            .post("/v1/bases/test/changes", serde_json::json!({}))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({}));
        server.await.unwrap();
    }
}

/// The password every test account signs up with.
pub const TEST_PASSWORD: &str = "correct horse battery staple";

/// Wire-level device used by protocol tests without the bh-core client.
#[derive(Clone)]
pub struct RawDevice {
    pub account_id: String,
    pub device_id: String,
    pub token: String,
    server: Url,
    bypass: String,
}
impl RawDevice {
    pub fn new(server: &LocalServer, account_id: String, device_id: String, token: String) -> Self {
        Self {
            account_id,
            device_id,
            token,
            server: server.url(),
            bypass: server.operator_token().to_string(),
        }
    }
    async fn request(&self, method: Method, path: &str, payload: Value) -> (StatusCode, Value) {
        self.send(method, path, payload, true).await
    }
    async fn send(
        &self,
        method: Method,
        path: &str,
        payload: Value,
        authenticated: bool,
    ) -> (StatusCode, Value) {
        let repeat = method == Method::GET
            || (method == Method::POST
                && path.starts_with("/v1/bases/")
                && path.ends_with("/changes"));
        let mut request = reqwest::Client::new()
            .request(method, self.server.join(path).expect("protocol path"))
            .header("BH-Protocol", "1")
            .header("BH-Test-Bypass", &self.bypass);
        if authenticated {
            request = request.bearer_auth(&self.token);
        }
        let request = request.json(&payload);
        // Local workerd occasionally drops an HTTP connection under parallel test load.
        // Only replay reads and the change POST, whose change IDs make it idempotent.
        let retry = if repeat { request.try_clone() } else { None };
        let response = match request.send().await {
            Ok(response) => response,
            Err(_) if retry.is_some() => retry.unwrap().send().await.expect("raw request retry"),
            Err(error) => panic!("raw request: {error}"),
        };
        let status = response.status();
        assert_eq!(response.headers()["BH-Protocol"], "1");
        (status, response.json().await.expect("raw JSON"))
    }
    pub async fn get(&self, path: &str, payload: Value) -> (StatusCode, Value) {
        self.request(Method::GET, path, payload).await
    }
    pub async fn post(&self, path: &str, payload: Value) -> (StatusCode, Value) {
        self.request(Method::POST, path, payload).await
    }
    async fn post_anonymous(&self, path: &str, payload: Value) -> (StatusCode, Value) {
        self.send(Method::POST, path, payload, false).await
    }
    pub async fn put(&self, path: &str, payload: Value) -> (StatusCode, Value) {
        self.request(Method::PUT, path, payload).await
    }
    pub async fn delete(&self, path: &str, payload: Value) -> (StatusCode, Value) {
        self.request(Method::DELETE, path, payload).await
    }
    /// Send opaque bytes to a protocol endpoint, returning its JSON response.
    pub async fn put_bytes(&self, path: &str, body: &[u8]) -> (StatusCode, Value) {
        let response = reqwest::Client::new()
            .put(self.server.join(path).expect("protocol path"))
            .header("BH-Protocol", "1")
            .header("BH-Test-Bypass", &self.bypass)
            .bearer_auth(&self.token)
            .header("Content-Type", "application/octet-stream")
            .body(body.to_vec())
            .send()
            .await
            .expect("raw byte PUT");
        assert_eq!(response.headers()["BH-Protocol"], "1");
        (response.status(), response.json().await.expect("raw JSON"))
    }
    /// Read opaque bytes, including a JSON error body on failure.
    pub async fn get_bytes(&self, path: &str) -> (StatusCode, Vec<u8>) {
        let response = reqwest::Client::new()
            .get(self.server.join(path).expect("protocol path"))
            .header("BH-Protocol", "1")
            .header("BH-Test-Bypass", &self.bypass)
            .bearer_auth(&self.token)
            .send()
            .await
            .expect("raw byte GET");
        assert_eq!(response.headers()["BH-Protocol"], "1");
        (
            response.status(),
            response.bytes().await.expect("raw bytes").to_vec(),
        )
    }
    pub async fn live(&self, path: &str) -> WebSocketStream<MaybeTlsStream<TcpStream>> {
        self.try_live(path).await.expect("live connection")
    }
    /// A live connection, or the error that refused it, such as an HTTP 401.
    pub async fn try_live(
        &self,
        path: &str,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, tungstenite::Error> {
        // Raw TLS sockets use tungstenite's default rustls connector. Both ring
        // and aws-lc-rs are in the test binary; select one before a wss call.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut url = self.server.join(path).expect("live path");
        url.set_scheme(if url.scheme() == "https" { "wss" } else { "ws" })
            .unwrap();
        let mut request = url
            .to_string()
            .into_client_request()
            .expect("websocket request");
        request
            .headers_mut()
            .insert("BH-Protocol", "1".parse().unwrap());
        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {}", self.token).parse().unwrap(),
        );
        connect_async(request).await.map(|(stream, _)| stream)
    }
}

/// Creates an invite through the admin endpoint.
pub fn invite(server: &LocalServer) -> String {
    let url = server.url().join("/v1/admin/invites").unwrap();
    let token = server.operator_token().to_string();
    // Test callers may already be inside a Tokio runtime.
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let response = reqwest::Client::new()
                    .post(url)
                    .header("BH-Protocol", "1")
                    .header("BH-Test-Bypass", &token)
                    .bearer_auth(&token)
                    .json(&serde_json::json!({}))
                    .send()
                    .await
                    .expect("create invite request")
                    .error_for_status()
                    .expect("create invite response");
                response
                    .json::<serde_json::Value>()
                    .await
                    .expect("invite JSON")["code"]
                    .as_str()
                    .expect("invite code")
                    .to_string()
            })
    })
    .join()
    .expect("invite thread")
}

/// A fresh device: a `Core` with a temporary data directory and a
/// `FileSecretStore`, named `name` when it signs up or in.
pub fn device(name: &str) -> Core {
    device_with_clock(name, &Clock::system())
}

/// A test device using the caller's monotonic clock.
pub fn device_with_clock(name: &str, clock: &Clock) -> Core {
    device_on_server(name, clock, LocalServer::from_env())
}

/// A test device pointed at a restartable local server.
pub fn device_on_server(name: &str, clock: &Clock, server: &LocalServer) -> Core {
    bh_core::test_support::set_test_bypass(server.operator_token());
    let tmp = tempfile::Builder::new()
        .prefix("bh-device-")
        .tempdir()
        .expect("device directory");
    let core = Core::open_with_clock(
        CoreConfig {
            data_dir: tmp.path().join("data"),
            secrets: Arc::new(
                FileSecretStore::new(tmp.path().join("secrets")).expect("secret store"),
            ),
        },
        clock.clone(),
    )
    .expect("open core");
    core.set_test_device_name(name);
    core.keep_alive(tmp);
    core
}

/// Number of core HTTP requests made to a protocol path (without the leading slash).
pub fn request_count(account: &Account, path: &str) -> usize {
    account.test_request_count(path)
}

fn random_hex() -> String {
    bh_core::AccountId::random().to_string()
}

/// A sign-up for a new email with a new invite on `LocalServer::from_env()`.
pub fn new_signup() -> SignUp {
    let server = LocalServer::from_env();
    SignUp {
        server: server.url(),
        invite: invite(server),
        email: format!("{}@example.test", random_hex()),
        password: TEST_PASSWORD.to_string().into(),
        device_name: String::new(),
    }
}

/// A sign-in to `account` with the test password.
pub fn signin_for(account: &Account) -> SignIn {
    SignIn {
        server: LocalServer::from_env().url(),
        email: account.email(),
        password: TEST_PASSWORD.to_string().into(),
        device_name: String::new(),
    }
}

/// The wire-level view of `account`'s device, with the token from its secret store.
pub fn raw_device(account: &Account) -> RawDevice {
    let token = account
        .test_secrets()
        .get(&format!("acct.{}.token", account.id()))
        .expect("read token")
        .expect("device token");
    RawDevice::new(
        LocalServer::from_env(),
        account.id().to_string(),
        account.device_id().to_string(),
        String::from_utf8(token.to_vec()).expect("token text"),
    )
}

/// A new pending device of `account`, logged in with the test password and not activated.
pub async fn pending_device_for(account: &Account) -> RawDevice {
    pending_device_on(account, LocalServer::from_env()).await
}

/// A pending wire-level device pointed at a restartable local server.
pub async fn pending_device_on(account: &Account, server: &LocalServer) -> RawDevice {
    let anonymous = RawDevice::new(server, String::new(), String::new(), String::new());
    let (status, params) = anonymous
        .post_anonymous(
            "/v1/login/params",
            serde_json::json!({ "email": account.email() }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "login params: {params}");
    let salt: [u8; 16] = URL_SAFE_NO_PAD
        .decode(params["salt"].as_str().expect("salt"))
        .expect("salt bytes")
        .try_into()
        .expect("16-byte salt");
    let login_key = bh_core::test_support::login_key(TEST_PASSWORD, &salt).expect("login key");
    let device_id = random_hex();
    let (status, login) = anonymous
        .post_anonymous(
            "/v1/login",
            serde_json::json!({
                "email": account.email(),
                "loginKey": URL_SAFE_NO_PAD.encode(login_key),
                "deviceId": device_id,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "login: {login}");
    RawDevice::new(
        server,
        account.id().to_string(),
        device_id,
        login["token"].as_str().expect("token").to_string(),
    )
}
