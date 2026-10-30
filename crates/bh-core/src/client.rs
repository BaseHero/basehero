//! HTTP client for `/v1`. Every request carries `BH-Protocol: 2`; server error
//! codes map to [`Error`].

use crate::{EndReason, Error};
use crate::{envelope, files::FILE_PART};
use bh_proto::*;
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
#[cfg(feature = "test-support")]
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::client::IntoClientRequest,
};
use url::Url;
use zeroize::Zeroizing;

/// The TLS configuration the core's clients use: webpki roots and the ring provider.
pub(crate) fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

/// How long opening a live socket may take: TCP, TLS and the upgrade. Without a
/// bound, a stalled handshake, as on a network that changes mid-connect, would
/// hold a sync or approval task until the system gave up, or forever.
const LIVE_HANDSHAKE: Duration = Duration::from_secs(20);

fn http_client(tls: &rustls::ClientConfig) -> reqwest::Client {
    let builder = reqwest::Client::builder()
        .use_preconfigured_tls(tls.clone())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60));
    // Local workerd resets reused HTTP connections under parallel test load.
    // No idle connections in test builds; release clients retain their pool.
    #[cfg(any(test, feature = "test-support"))]
    let builder = builder.pool_max_idle_per_host(0);
    builder.build().expect("HTTP client")
}

#[cfg(any(test, feature = "test-support"))]
static TEST_BYPASS: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// Test kit only: send `BH-Test-Bypass` so suites against `dev` skip the per-address limit.
#[cfg(any(test, feature = "test-support"))]
pub fn set_test_bypass(operator_token: &str) {
    *TEST_BYPASS.write().unwrap() = Some(operator_token.to_string());
}

/// Test kit only: the next `times` `method` requests to `path` (such as
/// `"v1/account/data"`) fail with a network error, after the server has
/// handled them when `lost_reply` is set.
#[cfg(feature = "test-support")]
#[derive(Clone, Debug)]
pub struct Fault {
    /// HTTP method matched by this injected failure.
    pub method: &'static str,
    /// Request path matched by this injected failure.
    pub path: &'static str,
    /// Whether to discard the response after the server handles the request.
    pub lost_reply: bool,
    /// Number of matching calls to fail.
    pub times: u32,
}

#[cfg(feature = "test-support")]
pub(crate) type Faults = Arc<std::sync::Mutex<Vec<Fault>>>;

#[cfg(feature = "test-support")]
type TestGate =
    Arc<std::sync::Mutex<Option<(Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>)>>>;

#[cfg(feature = "test-support")]
pub(crate) struct ApprovalPostGate {
    pub entered: tokio::sync::oneshot::Sender<()>,
    pub release: tokio::sync::oneshot::Receiver<()>,
}
#[cfg(feature = "test-support")]
pub(crate) type ApprovalPostPause = Arc<std::sync::Mutex<Option<ApprovalPostGate>>>;

/// Told of every `revoked` answer, with the removal notice that came with it.
type OnRevoked = Arc<dyn Fn(Option<&[u8]>) + Send + Sync>;

/// One client per account or sign-in, so its connections belong to the
/// runtime that uses it.
#[derive(Clone)]
pub(crate) struct Api {
    server: Url,
    token: Option<Arc<Zeroizing<String>>>,
    /// An app's one-time connect secret, base64url, and the email it typed.
    connect: Option<Arc<(Zeroizing<String>, String)>>,
    http: reqwest::Client,
    on_revoked: Option<OnRevoked>,
    #[cfg(test)]
    tls: Arc<rustls::ClientConfig>,
    #[cfg(feature = "test-support")]
    faults: Faults,
    #[cfg(feature = "test-support")]
    approval_post_pause: ApprovalPostPause,
    #[cfg(feature = "test-support")]
    counts: Arc<std::sync::Mutex<HashMap<String, usize>>>,
    #[cfg(feature = "test-support")]
    held_account_get: Arc<std::sync::Mutex<Option<Arc<tokio::sync::Semaphore>>>>,
    #[cfg(feature = "test-support")]
    held_grant: Arc<std::sync::Mutex<Option<Arc<tokio::sync::Semaphore>>>>,
    #[cfg(feature = "test-support")]
    held_delete_reply: TestGate,
    #[cfg(feature = "test-support")]
    held_base_key_reply: TestGate,
    #[cfg(feature = "test-support")]
    held_rekey_reply: TestGate,
    #[cfg(feature = "test-support")]
    held_delete_send: TestGate,
}

impl Api {
    pub(crate) fn new(server: Url, token: Option<String>) -> Self {
        Self::new_secret(server, token.map(Zeroizing::new))
    }

    pub(crate) fn new_secret(server: Url, token: Option<Zeroizing<String>>) -> Self {
        let tls = tls_config();
        Self {
            server,
            token: token.map(Arc::new),
            connect: None,
            http: http_client(&tls),
            on_revoked: None,
            #[cfg(test)]
            tls,
            #[cfg(feature = "test-support")]
            faults: Faults::default(),
            #[cfg(feature = "test-support")]
            approval_post_pause: ApprovalPostPause::default(),
            #[cfg(feature = "test-support")]
            counts: Arc::default(),
            #[cfg(feature = "test-support")]
            held_account_get: Arc::default(),
            #[cfg(feature = "test-support")]
            held_grant: Arc::default(),
            #[cfg(feature = "test-support")]
            held_delete_reply: Arc::default(),
            #[cfg(feature = "test-support")]
            held_base_key_reply: Arc::default(),
            #[cfg(feature = "test-support")]
            held_rekey_reply: Arc::default(),
            #[cfg(feature = "test-support")]
            held_delete_send: Arc::default(),
        }
    }

    /// A client for an app's own connection request, which has no token yet.
    pub(crate) fn with_connect(mut self, secret: Zeroizing<String>, email: &str) -> Self {
        self.connect = Some(Arc::new((secret, email.to_string())));
        self
    }

    pub(crate) fn with_revocation(
        mut self,
        callback: impl Fn(Option<&[u8]>) + Send + Sync + 'static,
    ) -> Self {
        self.on_revoked = Some(Arc::new(callback));
        self
    }

    /// Passes on a `revoked` answer and its base64url notice; a malformed notice is none.
    pub(crate) fn revoked(&self, notice: Option<&str>) {
        if let Some(callback) = &self.on_revoked {
            let notice = notice.and_then(|n| {
                use base64::Engine;
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(n)
                    .ok()
            });
            callback(notice.as_deref());
        }
    }

    /// The error in a refused answer. A `revoked` one is passed on unless it
    /// answers a removal, which is confirmed separately with `GET /v1/me`.
    fn refused(&self, status: StatusCode, bytes: &[u8], removal: bool) -> Error {
        let (error, notice) = match serde_json::from_slice::<ErrorBody>(bytes) {
            Ok(body) => (map_error(status, &body.error, body.message), body.notice),
            Err(_) => (map_error(status, "", status.to_string()), None),
        };
        if error == Error::Revoked && !removal {
            self.revoked(notice.as_deref());
        }
        error
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn with_faults(mut self, faults: Faults, pause: ApprovalPostPause) -> Self {
        self.faults = faults;
        self.approval_post_pause = pause;
        self
    }

    #[cfg(feature = "test-support")]
    fn fault(&self, method: &Method, path: &str, lost_reply: bool) -> Result<(), Error> {
        let mut faults = self.faults.lock().unwrap();
        let Some(fault) = faults.iter_mut().find(|f| {
            f.method == method.as_str()
                && (f.path == path || (f.path.ends_with('/') && path.starts_with(f.path)))
                && f.lost_reply == lost_reply
                && f.times > 0
        }) else {
            return Ok(());
        };
        fault.times -= 1;
        Err(Error::Network("injected fault".into()))
    }

    /// Hold one account GET after it starts, until the test releases the permit.
    #[cfg(feature = "test-support")]
    pub(crate) fn hold_next_account_get(&self) -> Arc<tokio::sync::Semaphore> {
        let hold = Arc::new(tokio::sync::Semaphore::new(0));
        *self.held_account_get.lock().unwrap() = Some(hold.clone());
        hold
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn hold_next_grant(&self) -> Arc<tokio::sync::Semaphore> {
        let hold = Arc::new(tokio::sync::Semaphore::new(0));
        *self.held_grant.lock().unwrap() = Some(hold.clone());
        hold
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn hold_next_delete_reply(
        &self,
    ) -> (Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>) {
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        *self.held_delete_reply.lock().unwrap() = Some((release.clone(), entered.clone()));
        (release, entered)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn hold_next_base_key_reply(
        &self,
    ) -> (Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>) {
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        *self.held_base_key_reply.lock().unwrap() = Some((release.clone(), entered.clone()));
        (release, entered)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn hold_next_rekey_reply(
        &self,
    ) -> (Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>) {
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        *self.held_rekey_reply.lock().unwrap() = Some((release.clone(), entered.clone()));
        (release, entered)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn hold_next_delete_send(
        &self,
    ) -> (Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>) {
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        *self.held_delete_send.lock().unwrap() = Some((release.clone(), entered.clone()));
        (release, entered)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn count(&self, path: &str) -> usize {
        self.counts
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p.starts_with(path))
            .map(|(_, count)| *count)
            .sum()
    }

    pub(crate) fn token(&self) -> Option<Zeroizing<String>> {
        self.token
            .as_ref()
            .map(|t| Zeroizing::new(t.as_str().to_owned()))
    }

    #[cfg(test)]
    pub(crate) fn tls(&self) -> Arc<rustls::ClientConfig> {
        self.tls.clone()
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<T, Error> {
        let url = self
            .server
            .join(path)
            .map_err(|_| Error::invalid("server address"))?;
        let mut request = self
            .http
            .request(method.clone(), url)
            .header("BH-Protocol", PROTOCOL.to_string());
        if let Some(token) = &self.token {
            request = request.bearer_auth(token.as_str());
        } else if let Some(connect) = &self.connect {
            request = request
                .header("Authorization", format!("Connect {}", connect.0.as_str()))
                .header("BH-Email", connect.1.as_str());
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(bypass) = TEST_BYPASS.read().unwrap().as_deref() {
            request = request.header("BH-Test-Bypass", bypass);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        #[cfg(feature = "test-support")]
        {
            *self
                .counts
                .lock()
                .unwrap()
                .entry(path.to_string())
                .or_default() += 1;
            self.fault(&method, path, false)?;
            if method == Method::DELETE && path.starts_with("v1/devices/") {
                let held = self.held_delete_send.lock().unwrap().take();
                if let Some((release, entered)) = held {
                    entered.add_permits(1);
                    release
                        .acquire()
                        .await
                        .expect("test DELETE send hold is open")
                        .forget();
                }
            }
            if method == Method::GET && path == "v1/account" {
                let held = self.held_account_get.lock().unwrap().take();
                if let Some(held) = held {
                    held.acquire().await.expect("test hold is open").forget();
                }
            }
            if method == Method::PUT && path.contains("/grants/") {
                let held = self.held_grant.lock().unwrap().take();
                if let Some(held) = held {
                    held.acquire().await.expect("test hold is open").forget();
                }
            }
        }
        // Only changes and reads can be repeated after an ambiguous transport failure.
        // A change resent after another device compacts its object may be stored twice;
        // applying it again changes nothing. Other POSTs may have applied.
        let repeat = method == Method::GET
            || (method == Method::POST
                && path.starts_with("v1/bases/")
                && path.ends_with("/changes"));
        let retry = if repeat { request.try_clone() } else { None };
        let response = match request.send().await {
            Ok(response) => response,
            Err(_) if retry.is_some() => retry
                .expect("cloneable JSON request")
                .send()
                .await
                .map_err(|e| Error::Network(e.without_url().to_string()))?,
            Err(e) => return Err(Error::Network(e.without_url().to_string())),
        };
        let status = response.status();
        match response
            .headers()
            .get("BH-Protocol")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok())
        {
            Some(1..=PROTOCOL) => {}
            Some(v) if v > PROTOCOL => return Err(Error::NeedsUpdate),
            _ if status == StatusCode::UPGRADE_REQUIRED => return Err(Error::NeedsUpdate),
            _ => return Err(Error::Network(format!("unexpected response ({status})"))),
        }
        // Fetch normally targets 16 MiB decoded, but always includes the first
        // object even if larger; leave generous room for base64 JSON framing.
        let mut response = response;
        let mut bytes = Vec::new();
        const API_RESPONSE_MAX: usize = 64 * 1024 * 1024;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| Error::Network(e.without_url().to_string()))?
        {
            if chunk.len() > API_RESPONSE_MAX - bytes.len() {
                return Err(Error::Network("API response too large".into()));
            }
            bytes.extend_from_slice(&chunk);
        }
        #[cfg(feature = "test-support")]
        {
            if method == Method::DELETE && path.starts_with("v1/devices/") && status.is_success() {
                let held = self.held_delete_reply.lock().unwrap().take();
                if let Some((release, entered)) = held {
                    entered.add_permits(1);
                    release
                        .acquire()
                        .await
                        .expect("test DELETE reply hold is open")
                        .forget();
                }
            }
            if method == Method::GET && path.ends_with("/key") && status.is_success() {
                let held = self.held_base_key_reply.lock().unwrap().take();
                if let Some((release, entered)) = held {
                    entered.add_permits(1);
                    release
                        .acquire()
                        .await
                        .expect("test base key hold is open")
                        .forget();
                }
            }
            if method == Method::POST && path.ends_with("/rekey") && status.is_success() {
                let held = self.held_rekey_reply.lock().unwrap().take();
                if let Some((release, entered)) = held {
                    entered.add_permits(1);
                    release
                        .acquire()
                        .await
                        .expect("test re-key reply hold is open")
                        .forget();
                }
            }
            self.fault(&method, path, true)?;
        }
        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(|_| Error::Network("malformed response".into()))
        } else {
            let removal = method == Method::DELETE && path.starts_with("v1/devices/");
            Err(self.refused(status, &bytes, removal))
        }
    }

    pub(crate) async fn versions(
        &self,
        base: BaseId,
        id: ObjectId,
        before: Option<u64>,
        limit: usize,
    ) -> Result<VersionsResponse, Error> {
        let mut path = format!("v1/bases/{base}/objects/{id}/versions?limit={limit}");
        if let Some(before) = before {
            path.push_str(&format!("&before={before}"));
        }
        self.call(Method::GET, &path, None::<&VersionsResponse>)
            .await
    }

    pub(crate) async fn version(
        &self,
        base: BaseId,
        id: ObjectId,
        seq: u64,
    ) -> Result<VersionResponse, Error> {
        self.call(
            Method::GET,
            &format!("v1/bases/{base}/objects/{id}/versions/{seq}"),
            None::<&VersionResponse>,
        )
        .await
    }

    /// Fetches one opaque file part, preserving the binary response unchanged.
    pub(crate) async fn get_file_part(
        &self,
        base: BaseId,
        id: ObjectId,
        n: u32,
    ) -> Result<Vec<u8>, Error> {
        let path = format!("v1/bases/{base}/files/{id}/{n}");
        let url = self
            .server
            .join(&path)
            .map_err(|_| Error::invalid("server address"))?;
        let mut request = self
            .http
            .get(url)
            .header("BH-Protocol", PROTOCOL.to_string());
        if let Some(token) = &self.token {
            request = request.bearer_auth(token.as_str());
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(bypass) = TEST_BYPASS.read().unwrap().as_deref() {
            request = request.header("BH-Test-Bypass", bypass);
        }
        #[cfg(feature = "test-support")]
        {
            *self.counts.lock().unwrap().entry(path.clone()).or_default() += 1;
            self.fault(&Method::GET, &path, false)?;
        }
        let mut response = request
            .send()
            .await
            .map_err(|e| Error::Network(e.without_url().to_string()))?;
        let status = response.status();
        match response
            .headers()
            .get("BH-Protocol")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok())
        {
            Some(1..=PROTOCOL) => {}
            Some(v) if v > PROTOCOL => return Err(Error::NeedsUpdate),
            _ if status == StatusCode::UPGRADE_REQUIRED => return Err(Error::NeedsUpdate),
            _ => return Err(Error::Network(format!("unexpected response ({status})"))),
        }
        let limit = FILE_PART + envelope::OVERHEAD;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| Error::Network(e.without_url().to_string()))?
        {
            if chunk.len() > limit - bytes.len() {
                return Err(Error::Network("file part response too large".into()));
            }
            bytes.extend_from_slice(&chunk);
        }
        #[cfg(feature = "test-support")]
        self.fault(&Method::GET, &path, true)?;
        if status.is_success() {
            return Ok(bytes);
        }
        Err(self.refused(status, &bytes, false))
    }

    /// Uploads the *persisted* sealed bytes, not a fresh sealing on retry.
    pub(crate) async fn put_file_part(
        &self,
        base: BaseId,
        id: ObjectId,
        n: u32,
        bytes: Vec<u8>,
    ) -> Result<(), Error> {
        let path = format!("v1/bases/{base}/files/{id}/{n}");
        let url = self
            .server
            .join(&path)
            .map_err(|_| Error::invalid("server address"))?;
        let mut request = self
            .http
            .put(url)
            .header("BH-Protocol", PROTOCOL.to_string())
            .header("Content-Type", "application/octet-stream");
        if let Some(token) = &self.token {
            request = request.bearer_auth(token.as_str());
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(bypass) = TEST_BYPASS.read().unwrap().as_deref() {
            request = request.header("BH-Test-Bypass", bypass);
        }
        #[cfg(feature = "test-support")]
        {
            *self.counts.lock().unwrap().entry(path.clone()).or_default() += 1;
            self.fault(&Method::PUT, &path, false)?;
        }
        let response = request
            .body(bytes)
            .send()
            .await
            .map_err(|e| Error::Network(e.without_url().to_string()))?;
        let status = response.status();
        let protocol = response
            .headers()
            .get("BH-Protocol")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());
        if !matches!(protocol, Some(1..=PROTOCOL)) {
            return Err(
                if protocol.is_some_and(|v| v > PROTOCOL) || status == StatusCode::UPGRADE_REQUIRED
                {
                    Error::NeedsUpdate
                } else {
                    Error::Network(format!("unexpected response ({status})"))
                },
            );
        }
        // Successful uploads have no useful response body; errors are small JSON.
        let mut response = response;
        let mut body = Vec::new();
        const UPLOAD_RESPONSE_MAX: usize = 1024 * 1024;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| Error::Network(e.without_url().to_string()))?
        {
            if chunk.len() > UPLOAD_RESPONSE_MAX - body.len() {
                return Err(Error::Network("API response too large".into()));
            }
            body.extend_from_slice(&chunk);
        }
        #[cfg(feature = "test-support")]
        self.fault(&Method::PUT, &path, true)?;
        if status.is_success() {
            return Ok(());
        }
        Err(self.refused(status, &body, false))
    }

    #[allow(dead_code, reason = "used by the approval exchange")]
    pub(crate) async fn approval_create(
        &self,
        id: ApprovalId,
        request: Bytes,
    ) -> Result<ApprovalCreate, Error> {
        #[cfg(feature = "test-support")]
        let gate = { self.approval_post_pause.lock().unwrap().take() };
        #[cfg(feature = "test-support")]
        if let Some(gate) = gate {
            let _ = gate.entered.send(());
            let _ = gate.release.await;
        }
        self.call(
            Method::POST,
            "v1/approvals",
            Some(&serde_json::json!({ "approvalId": id, "request": request })),
        )
        .await
    }

    pub(crate) async fn approvals(&self) -> Result<ApprovalList, Error> {
        self.call(Method::GET, "v1/approvals", None::<&()>).await
    }

    #[allow(dead_code, reason = "used by the approval exchange")]
    /// A missing approval has ended and been deleted by the relay; its reason is unknown.
    pub(crate) async fn approval(&self, id: ApprovalId) -> Result<Option<ApprovalState>, Error> {
        match self
            .call(Method::GET, &format!("v1/approvals/{id}"), None::<&()>)
            .await
        {
            Ok(state) => Ok(Some(state)),
            Err(Error::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    #[allow(dead_code, reason = "used by the approval exchange")]
    pub(crate) async fn approval_respond(
        &self,
        id: ApprovalId,
        response: Bytes,
    ) -> Result<(), Error> {
        self.call::<serde_json::Value>(
            Method::POST,
            &format!("v1/approvals/{id}/respond"),
            Some(&serde_json::json!({ "response": response })),
        )
        .await
        .map(|_| ())
    }

    #[allow(dead_code, reason = "used by the approval exchange")]
    pub(crate) async fn approval_reveal(&self, id: ApprovalId, reveal: Bytes) -> Result<(), Error> {
        self.call::<serde_json::Value>(
            Method::POST,
            &format!("v1/approvals/{id}/reveal"),
            Some(&serde_json::json!({ "reveal": reveal })),
        )
        .await
        .map(|_| ())
    }

    #[allow(dead_code, reason = "used by the approval exchange")]
    pub(crate) async fn approval_transfer(
        &self,
        id: ApprovalId,
        transfer: Bytes,
    ) -> Result<(), Error> {
        self.call::<serde_json::Value>(
            Method::POST,
            &format!("v1/approvals/{id}/transfer"),
            Some(&serde_json::json!({ "transfer": transfer })),
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn approval_end(
        &self,
        id: ApprovalId,
        reason: EndReason,
    ) -> Result<(), Error> {
        let reason = match reason {
            EndReason::WrongDigits => "wrong_digits",
            EndReason::Declined => "declined",
            EndReason::Cancelled => "cancelled",
            EndReason::Expired => "expired",
            EndReason::AlreadyAnswered | EndReason::BadMessage => "failed",
        };
        self.call::<serde_json::Value>(
            Method::DELETE,
            &format!("v1/approvals/{id}"),
            Some(&serde_json::json!({ "reason": reason })),
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn connect_create(
        &self,
        body: &ConnectCreateRequest,
    ) -> Result<ApprovalCreate, Error> {
        self.call(Method::POST, "v1/connect", Some(body)).await
    }

    /// A missing request has ended and been deleted by the relay.
    pub(crate) async fn connect_state(
        &self,
        id: ApprovalId,
    ) -> Result<Option<ApprovalState>, Error> {
        match self
            .call(Method::GET, &format!("v1/connect/{id}"), None::<&()>)
            .await
        {
            Ok(state) => Ok(Some(state)),
            Err(Error::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn connect_reveal(&self, id: ApprovalId, reveal: Bytes) -> Result<(), Error> {
        self.call::<serde_json::Value>(
            Method::POST,
            &format!("v1/connect/{id}/reveal"),
            Some(&ConnectRevealRequest { reveal }),
        )
        .await
        .map(|_| ())
    }

    /// The app ends its own request only as cancelled, expired or failed.
    pub(crate) async fn connect_end(&self, id: ApprovalId, reason: EndReason) -> Result<(), Error> {
        let reason = match reason {
            EndReason::Cancelled => ApprovalEndReason::Cancelled,
            EndReason::Expired => ApprovalEndReason::Expired,
            _ => ApprovalEndReason::Failed,
        };
        self.call::<serde_json::Value>(
            Method::DELETE,
            &format!("v1/connect/{id}"),
            Some(&ConnectEndRequest { reason }),
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn approvals_live(
        &self,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, Error> {
        self.live("v1/approvals/live").await
    }

    pub(crate) async fn base_live(
        &self,
        base: BaseId,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, Error> {
        self.live(&format!("v1/bases/{base}/live")).await
    }

    async fn live(&self, path: &str) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, Error> {
        let mut url = self
            .server
            .join(path)
            .map_err(|_| Error::invalid("server address"))?;
        url.set_scheme(if url.scheme() == "https" { "wss" } else { "ws" })
            .map_err(|_| Error::invalid("server address"))?;
        let mut request = url
            .to_string()
            .into_client_request()
            .map_err(|e| Error::Network(e.to_string()))?;
        request
            .headers_mut()
            .insert("BH-Protocol", PROTOCOL.to_string().parse().unwrap());
        if let Some(token) = &self.token {
            request.headers_mut().insert(
                "Authorization",
                format!("Bearer {}", token.as_str())
                    .parse()
                    .map_err(|_| Error::Unauthorized)?,
            );
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(bypass) = TEST_BYPASS.read().unwrap().as_deref() {
            request.headers_mut().insert(
                "BH-Test-Bypass",
                bypass.parse().map_err(|_| Error::Unauthorized)?,
            );
        }
        #[cfg(feature = "test-support")]
        {
            *self.counts.lock().unwrap().entry(path.into()).or_default() += 1;
        }
        let connect = connect_async_tls_with_config(
            request,
            None,
            false,
            Some(Connector::Rustls(tls_config())),
        );
        match tokio::time::timeout(LIVE_HANDSHAKE, connect).await {
            Err(_) => Err(Error::Network("live connection timed out".into())),
            Ok(Ok((socket, _))) => Ok(socket),
            Ok(Err(tokio_tungstenite::tungstenite::Error::Http(response))) => {
                let status = response.status();
                let body = response
                    .body()
                    .as_deref()
                    .and_then(|body| serde_json::from_slice::<ErrorBody>(body).ok());
                if status == StatusCode::UNAUTHORIZED
                    && body.as_ref().is_some_and(|body| body.error == "revoked")
                {
                    self.revoked(body.and_then(|body| body.notice).as_deref());
                    Err(Error::Revoked)
                } else {
                    Err(Error::Network(format!(
                        "live connection refused ({status})"
                    )))
                }
            }
            Ok(Err(e)) => Err(Error::Network(e.to_string())),
        }
    }

    pub(crate) async fn signup(&self, body: &SignupRequest) -> Result<SignupResponse, Error> {
        self.call(Method::POST, "v1/signup", Some(body)).await
    }

    pub(crate) async fn login_params(&self, email: &str) -> Result<LoginParamsResponse, Error> {
        let body = LoginParamsRequest {
            email: email.to_string(),
        };
        self.call(Method::POST, "v1/login/params", Some(&body))
            .await
    }

    pub(crate) async fn login(&self, body: &LoginRequest) -> Result<LoginResponse, Error> {
        self.call(Method::POST, "v1/login", Some(body)).await
    }

    pub(crate) async fn activate(&self, body: &ActivateRequest) -> Result<ActivateResponse, Error> {
        self.call(Method::POST, "v1/devices/activate", Some(body))
            .await
    }

    pub(crate) async fn me(&self) -> Result<MeResponse, Error> {
        self.call(Method::GET, "v1/me", None::<&()>).await
    }

    pub(crate) async fn me_after(&self, epoch: u32) -> Result<MeResponse, Error> {
        self.call(
            Method::GET,
            &format!("v1/me?afterEpoch={epoch}"),
            None::<&()>,
        )
        .await
    }

    pub(crate) async fn account(&self) -> Result<AccountResponse, Error> {
        self.call(Method::GET, "v1/account", None::<&()>).await
    }

    pub(crate) async fn account_after(&self, epoch: u32) -> Result<AccountResponse, Error> {
        self.call(
            Method::GET,
            &format!("v1/account?afterEpoch={epoch}"),
            None::<&()>,
        )
        .await
    }

    pub(crate) async fn usage(&self, month: Option<&str>) -> Result<UsageResponse, Error> {
        let path = month.map_or_else(
            || "v1/usage".to_owned(),
            |month| format!("v1/usage?month={month}"),
        );
        self.call(Method::GET, &path, None::<&()>).await
    }

    pub(crate) async fn put_account_data(
        &self,
        body: &AccountDataRequest,
    ) -> Result<AccountDataResponse, Error> {
        self.call(Method::PUT, "v1/account/data", Some(body)).await
    }

    pub(crate) async fn put_credentials(
        &self,
        body: &CredentialsRequest,
    ) -> Result<CredentialsResponse, Error> {
        self.call(Method::PUT, "v1/account/credentials", Some(body))
            .await
    }

    pub(crate) async fn create_base(&self, body: &BasesRequest) -> Result<BasesResponse, Error> {
        self.call(Method::POST, "v1/bases", Some(body)).await
    }

    pub(crate) async fn base_key(&self, base: BaseId) -> Result<BaseKeyResponse, Error> {
        self.call(Method::GET, &format!("v1/bases/{base}/key"), None::<&()>)
            .await
    }

    pub(crate) async fn changes(
        &self,
        base: BaseId,
        body: &ChangesRequest,
    ) -> Result<ChangesResponse, Error> {
        self.call(
            Method::POST,
            &format!("v1/bases/{base}/changes"),
            Some(body),
        )
        .await
    }

    pub(crate) async fn since(&self, base: BaseId, after: u64) -> Result<SinceResponse, Error> {
        self.call(
            Method::GET,
            &format!("v1/bases/{base}/since?after={after}"),
            None::<&()>,
        )
        .await
    }

    pub(crate) async fn fetch(
        &self,
        base: BaseId,
        body: &FetchRequest,
    ) -> Result<FetchResponse, Error> {
        self.call(Method::POST, &format!("v1/bases/{base}/fetch"), Some(body))
            .await
    }

    pub(crate) async fn rekey(&self, base: BaseId, request: &RekeyRequest) -> Result<(), Error> {
        self.call::<RekeyResponse>(
            Method::POST,
            &format!("v1/bases/{base}/rekey"),
            Some(request),
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn grant(
        &self,
        base: BaseId,
        device: DeviceId,
        body: &GrantRequest,
    ) -> Result<(), Error> {
        self.call::<serde_json::Value>(
            Method::PUT,
            &format!("v1/bases/{base}/grants/{device}"),
            Some(body),
        )
        .await
        .map(|_| ())
    }

    /// Removes `device`'s grant on `base`; a grant already gone counts as removed.
    pub(crate) async fn revoke(&self, base: BaseId, device: DeviceId) -> Result<(), Error> {
        match self
            .call::<serde_json::Value>(
                Method::DELETE,
                &format!("v1/bases/{base}/grants/{device}"),
                None::<&()>,
            )
            .await
        {
            Ok(_) | Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn add_device(&self, body: &DevicesRequest) -> Result<DevicesResponse, Error> {
        self.call(Method::POST, "v1/devices", Some(body)).await
    }

    pub(crate) async fn set_app_cap(&self, id: DeviceId, cap_micro_usd: u64) -> Result<(), Error> {
        self.call::<serde_json::Value>(
            Method::PUT,
            &format!("v1/devices/{id}/cap"),
            Some(&serde_json::json!({ "capMicroUsd": cap_micro_usd })),
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn delete_device(
        &self,
        id: DeviceId,
        request: &DeleteDeviceRequest,
    ) -> Result<(), Error> {
        self.call::<DeleteDeviceResponse>(
            Method::DELETE,
            &format!("v1/devices/{id}"),
            Some(request),
        )
        .await
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApprovalRow {
    pub approval_id: ApprovalId,
    pub kind: ApprovalKind,
    pub device_id: DeviceId,
    pub created_at: i64,
    pub expires_at: i64,
    #[allow(dead_code, reason = "used by the approval exchange")]
    pub request: Bytes,
}

#[derive(Deserialize)]
pub(crate) struct ApprovalList {
    pub approvals: Vec<ApprovalRow>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code, reason = "used by the approval exchange")]
pub(crate) struct ApprovalCreate {
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code, reason = "used by the approval exchange")]
pub(crate) struct ApprovalState {
    pub state: String,
    pub response: Option<Bytes>,
    pub reveal: Option<Bytes>,
    pub transfer: Option<Bytes>,
    #[serde(default, deserialize_with = "deserialize_approval_end_reason")]
    pub end_reason: Option<EndReason>,
}

#[allow(dead_code, reason = "used by approval state deserialization")]
fn deserialize_approval_end_reason<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<EndReason>, D::Error> {
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|code| match code.as_str() {
            "wrong_digits" => Ok(EndReason::WrongDigits),
            "declined" => Ok(EndReason::Declined),
            "cancelled" => Ok(EndReason::Cancelled),
            "expired" => Ok(EndReason::Expired),
            // The relay's generic failure means the exchange cannot be completed.
            "failed" => Ok(EndReason::BadMessage),
            _ => Err(serde::de::Error::custom("unknown approval end reason")),
        })
        .transpose()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApprovalLive {
    pub t: String,
    pub approval_id: ApprovalId,
    pub state: String,
}

fn map_error(status: StatusCode, code: &str, message: String) -> Error {
    match code {
        "bad_request" => Error::Invalid(message),
        "unauthorized" => Error::Unauthorized,
        "bad_credentials" => Error::BadCredentials,
        "revoked" if status == StatusCode::UNAUTHORIZED => Error::Revoked,
        "pending" => Error::Pending,
        "forbidden" => Error::Forbidden,
        "read_only" => Error::ReadOnly,
        "not_found" => Error::NotFound,
        "email_taken" | "invite_used" | "exists" | "version_conflict" | "epoch_conflict"
        | "stale_epoch" | "rekey_needed" | "stale_grant" => Error::Conflict(code.to_string()),
        "too_large" => Error::TooLarge,
        "storage_limit" => Error::StorageFull,
        "needs_update" => Error::NeedsUpdate,
        "rate_limited" => Error::RateLimited,
        _ => match status.as_u16() {
            401 => Error::Unauthorized,
            403 => Error::Forbidden,
            404 => Error::NotFound,
            413 => Error::TooLarge,
            426 => Error::NeedsUpdate,
            429 => Error::RateLimited,
            400..=499 => Error::Invalid(message),
            _ => Error::Network(message),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_limit_is_not_an_individual_request_size_error() {
        assert_eq!(
            map_error(StatusCode::PAYLOAD_TOO_LARGE, "storage_limit", "m".into()),
            Error::StorageFull
        );
    }

    #[test]
    fn every_protocol_error_code_maps_to_an_error() {
        let cases = [
            ("bad_request", 400, Error::Invalid("m".into())),
            ("unauthorized", 401, Error::Unauthorized),
            ("bad_credentials", 401, Error::BadCredentials),
            ("revoked", 401, Error::Revoked),
            ("pending", 403, Error::Pending),
            ("forbidden", 403, Error::Forbidden),
            ("read_only", 403, Error::ReadOnly),
            ("not_found", 404, Error::NotFound),
            ("email_taken", 409, Error::Conflict("email_taken".into())),
            ("invite_used", 409, Error::Conflict("invite_used".into())),
            ("exists", 409, Error::Conflict("exists".into())),
            (
                "version_conflict",
                409,
                Error::Conflict("version_conflict".into()),
            ),
            ("too_large", 413, Error::TooLarge),
            ("storage_limit", 413, Error::StorageFull),
            ("needs_update", 426, Error::NeedsUpdate),
            ("rate_limited", 429, Error::RateLimited),
            ("bad_gateway", 502, Error::Network("m".into())),
        ];
        for (code, status, expected) in cases {
            assert_eq!(
                map_error(StatusCode::from_u16(status).unwrap(), code, "m".into()),
                expected,
                "{code}"
            );
        }
    }

    #[tokio::test]
    async fn approval_relay_methods_follow_the_wire_contract() {
        use bh_testkit::{device, new_signup, pending_device_for};
        let (full, _) = device("mac").sign_up(new_signup()).await.unwrap();
        let pending = pending_device_for(&full).await;
        let server = bh_testkit::LocalServer::from_env().url();
        let token = full
            .test_secrets()
            .get(&format!("acct.{}.token", full.id()))
            .unwrap()
            .unwrap();
        let newcomer = Api::new(server.clone(), Some(pending.token.clone()));
        let approver = Api::new(server, Some(String::from_utf8(token.to_vec()).unwrap()));
        let id = ApprovalId::random();
        let body = Bytes(vec![1]);
        let created = newcomer.approval_create(id, body.clone()).await.unwrap();
        assert!(created.expires_at > created.created_at);
        let listed = approver.approvals().await.unwrap().approvals;
        assert!(listed.iter().any(|row| row.approval_id == id
            && row.device_id.to_string() == pending.device_id
            && row.request.0 == body.0));
        assert_eq!(
            newcomer.approval(id).await.unwrap().unwrap().state,
            "requested"
        );
        approver.approval_respond(id, body.clone()).await.unwrap();
        assert_eq!(
            newcomer
                .approval(id)
                .await
                .unwrap()
                .unwrap()
                .response
                .unwrap()
                .0,
            body.0
        );
        newcomer.approval_reveal(id, body.clone()).await.unwrap();
        assert_eq!(
            approver
                .approval(id)
                .await
                .unwrap()
                .unwrap()
                .reveal
                .unwrap()
                .0,
            body.0
        );
        approver.approval_transfer(id, body).await.unwrap();
        assert!(
            newcomer
                .approval(id)
                .await
                .unwrap()
                .unwrap()
                .transfer
                .is_some()
        );
        newcomer
            .approval_end(id, EndReason::WrongDigits)
            .await
            .unwrap();
        assert_eq!(
            newcomer.approval(id).await.unwrap().unwrap().end_reason,
            Some(EndReason::WrongDigits)
        );
        assert!(
            newcomer
                .approval(ApprovalId::random())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn relay_end_reasons_are_mapped_without_camel_case_assumptions() {
        for (wire, reason) in [
            ("wrong_digits", EndReason::WrongDigits),
            ("declined", EndReason::Declined),
            ("cancelled", EndReason::Cancelled),
            ("expired", EndReason::Expired),
            ("failed", EndReason::BadMessage),
        ] {
            let state: ApprovalState = serde_json::from_value(serde_json::json!({
                "state": "ended", "endReason": wire,
            }))
            .unwrap();
            assert_eq!(state.end_reason, Some(reason), "{wire}");
        }
        assert!(
            serde_json::from_value::<ApprovalState>(serde_json::json!({
                "state": "ended", "endReason": "future_reason"
            }))
            .is_err()
        );
    }

    #[tokio::test]
    async fn idempotent_change_post_recovers_when_the_server_closes_without_a_response() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let server = std::thread::spawn(move || {
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = [0; 8192];
                let length = stream.read(&mut bytes).unwrap();
                let request = String::from_utf8_lossy(&bytes[..length]);
                assert!(request.starts_with("POST /v1/bases/"), "{request}");
                assert!(request.contains("/changes HTTP/1.1"), "{request}");
                if attempt == 0 {
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                } else {
                    let body = r#"{"results":[],"head":0}"#;
                    write!(stream, "HTTP/1.1 200 OK\r\nBH-Protocol: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                }
            }
        });
        let api = Api::new(url, None);
        let result = api
            .changes(BaseId::random(), &ChangesRequest { changes: vec![] })
            .await;
        assert!(result.is_ok(), "{result:?}");
        server.join().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_live_handshake_that_never_answers_times_out() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = Url::parse(&format!("http://{addr}/")).unwrap();
        // Accept, then hold the connection without ever answering the upgrade.
        let (held, release) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = release.recv();
            drop(stream);
        });
        let api = Api::new(url, None);
        let result = tokio::time::timeout(Duration::from_secs(120), api.approvals_live())
            .await
            .expect("a stalled handshake must end on its own");
        assert!(
            matches!(&result, Err(Error::Network(message)) if message == "live connection timed out"),
            "{:?}",
            result.map(|_| ())
        );
        drop(held);
        // On macOS the paused clock can time out before the client's connection
        // completes; connecting here lets the server's accept return either way.
        let _ = std::net::TcpStream::connect(addr);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn json_response_rejects_an_oversized_stream_without_content_length() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 8192];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(b"HTTP/1.1 200 OK\r\nBH-Protocol: 1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").unwrap();
            let payload = vec![b' '; 1024 * 1024];
            for _ in 0..66 {
                if stream.write_all(b"100000\r\n").is_err()
                    || stream.write_all(&payload).is_err()
                    || stream.write_all(b"\r\n").is_err()
                {
                    break;
                }
            }
        });
        let result = Api::new(url, None).me().await;
        assert!(
            matches!(&result, Err(Error::Network(message)) if message == "API response too large"),
            "{result:?}"
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn file_part_rejects_an_oversized_stream_without_content_length() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 8192];
            let length = stream.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..length]).contains("/files/"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nBH-Protocol: 1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").unwrap();
            let size = crate::files::FILE_PART + crate::envelope::OVERHEAD + 1;
            write!(stream, "{size:X}\r\n").unwrap();
            stream.write_all(&vec![0x5a; size]).unwrap();
            stream.write_all(b"\r\n0\r\n\r\n").unwrap();
        });
        let result = Api::new(url, None)
            .get_file_part(BaseId::random(), ObjectId::random(), 0)
            .await;
        assert!(matches!(result, Err(Error::Network(_))), "{result:?}");
        server.join().unwrap();
    }

    #[tokio::test]
    async fn read_recovers_when_the_server_closes_without_a_response() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let server = std::thread::spawn(move || {
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = [0; 8192];
                let length = stream.read(&mut bytes).unwrap();
                assert!(
                    String::from_utf8_lossy(&bytes[..length]).starts_with("GET /v1/me HTTP/1.1")
                );
                if attempt == 0 {
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                } else {
                    let body = r#"{"accountId":"00000000000000000000000000000001","deviceId":"00000000000000000000000000000002","kind":"full","bases":[]}"#;
                    write!(stream, "HTTP/1.1 200 OK\r\nBH-Protocol: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                }
            }
        });
        let api = Api::new(url, None);
        assert_eq!(api.me().await.unwrap().kind, DeviceKind::Full);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn only_a_401_revoked_answer_triggers_local_removal() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            for (status, code, notice) in [
                (401, "unauthorized", None),
                (503, "revoked", None),
                (401, "revoked", None),
                (401, "revoked", Some("AQI")),
                (401, "revoked", Some("not base64!")),
            ] {
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                && std::time::Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) => panic!("test server accept failed: {e}"),
                    }
                };
                // On macOS an accepted socket inherits the listener's non-blocking mode.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = [0; 8192];
                let _ = stream.read(&mut bytes).unwrap();
                let mut body = serde_json::json!({ "error": code, "message": "unavailable" });
                if let Some(notice) = notice {
                    body["notice"] = notice.into();
                }
                let body = body.to_string();
                write!(stream, "HTTP/1.1 {status} Error\r\nBH-Protocol: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let removals = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = removals.clone();
        let api = Api::new(url, None).with_revocation(move |notice| {
            seen.lock().unwrap().push(notice.map(<[u8]>::to_vec));
        });
        assert_eq!(api.me().await.unwrap_err(), Error::Unauthorized);
        assert!(removals.lock().unwrap().is_empty());
        assert!(matches!(api.me().await.unwrap_err(), Error::Network(_)));
        assert!(removals.lock().unwrap().is_empty());
        for _ in 0..3 {
            assert_eq!(api.me().await.unwrap_err(), Error::Revoked);
        }
        // The notice is passed on as bytes; a malformed one is none.
        assert_eq!(*removals.lock().unwrap(), [None, Some(vec![1, 2]), None]);
        server.join().unwrap();
    }

    #[test]
    fn the_client_uses_the_shared_tls_config() {
        let api = Api::new(Url::parse("https://example.test/").unwrap(), None);
        assert!(Arc::ptr_eq(&api.tls(), &tls_config()));
        assert!(Arc::ptr_eq(&tls_config(), &tls_config()));
    }
}
