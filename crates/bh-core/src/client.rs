//! HTTP client for `/v1`. Every request carries `BH-Protocol: 1`; server error
//! codes map to [`Error`].

use crate::{EndReason, Error};
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

fn http_client(tls: &rustls::ClientConfig) -> reqwest::Client {
    reqwest::Client::builder()
        .use_preconfigured_tls(tls.clone())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .build()
        .expect("HTTP client")
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
    pub method: &'static str,
    pub path: &'static str,
    pub lost_reply: bool,
    pub times: u32,
}

#[cfg(feature = "test-support")]
pub(crate) type Faults = Arc<std::sync::Mutex<Vec<Fault>>>;

/// One client per account or sign-in, so its connections belong to the
/// runtime that uses it.
#[derive(Clone)]
pub(crate) struct Api {
    server: Url,
    token: Option<Arc<Zeroizing<String>>>,
    http: reqwest::Client,
    #[cfg(test)]
    tls: Arc<rustls::ClientConfig>,
    #[cfg(feature = "test-support")]
    faults: Faults,
    #[cfg(feature = "test-support")]
    counts: Arc<std::sync::Mutex<HashMap<String, usize>>>,
}

impl Api {
    pub(crate) fn new(server: Url, token: Option<String>) -> Self {
        let tls = tls_config();
        Self {
            server,
            token: token.map(|t| Arc::new(Zeroizing::new(t))),
            http: http_client(&tls),
            #[cfg(test)]
            tls,
            #[cfg(feature = "test-support")]
            faults: Faults::default(),
            #[cfg(feature = "test-support")]
            counts: Arc::default(),
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn with_faults(mut self, faults: Faults) -> Self {
        self.faults = faults;
        self
    }

    #[cfg(feature = "test-support")]
    fn fault(&self, method: &Method, path: &str, lost_reply: bool) -> Result<(), Error> {
        let mut faults = self.faults.lock().unwrap();
        let Some(fault) = faults.iter_mut().find(|f| {
            f.method == method.as_str()
                && f.path == path
                && f.lost_reply == lost_reply
                && f.times > 0
        }) else {
            return Ok(());
        };
        fault.times -= 1;
        Err(Error::Network("injected fault".into()))
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn count(&self, path: &str) -> usize {
        *self.counts.lock().unwrap().get(path).unwrap_or(&0)
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
        }
        let response = request
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
            Some(PROTOCOL) => {}
            Some(v) if v > PROTOCOL => return Err(Error::NeedsUpdate),
            _ if status == StatusCode::UPGRADE_REQUIRED => return Err(Error::NeedsUpdate),
            _ => return Err(Error::Network(format!("unexpected response ({status})"))),
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Network(e.without_url().to_string()))?;
        #[cfg(feature = "test-support")]
        self.fault(&method, path, true)?;
        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(|_| Error::Network("malformed response".into()))
        } else {
            Err(match serde_json::from_slice::<ErrorBody>(&bytes) {
                Ok(body) => map_error(status, &body.error, body.message),
                Err(_) => map_error(status, "", status.to_string()),
            })
        }
    }

    #[allow(dead_code, reason = "used by the approval exchange")]
    pub(crate) async fn approval_create(
        &self,
        id: ApprovalId,
        request: Bytes,
    ) -> Result<ApprovalCreate, Error> {
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

    pub(crate) async fn approvals_live(
        &self,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, Error> {
        let mut url = self
            .server
            .join("v1/approvals/live")
            .map_err(|_| Error::invalid("server address"))?;
        url.set_scheme(if url.scheme() == "https" { "wss" } else { "ws" })
            .map_err(|_| Error::invalid("server address"))?;
        let mut request = url
            .to_string()
            .into_client_request()
            .map_err(|e| Error::Network(e.to_string()))?;
        request
            .headers_mut()
            .insert("BH-Protocol", "1".parse().unwrap());
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
            *self
                .counts
                .lock()
                .unwrap()
                .entry("v1/approvals/live".into())
                .or_default() += 1;
        }
        connect_async_tls_with_config(request, None, false, Some(Connector::Rustls(tls_config())))
            .await
            .map(|(socket, _)| socket)
            .map_err(|e| Error::Network(e.to_string()))
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

    pub(crate) async fn account(&self) -> Result<AccountResponse, Error> {
        self.call(Method::GET, "v1/account", None::<&()>).await
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

    #[allow(dead_code, reason = "used once app devices are connected")]
    pub(crate) async fn add_device(&self, body: &DevicesRequest) -> Result<DevicesResponse, Error> {
        self.call(Method::POST, "v1/devices", Some(body)).await
    }

    #[allow(dead_code, reason = "used once devices can be removed")]
    pub(crate) async fn delete_device(&self, id: DeviceId) -> Result<DeleteDeviceResponse, Error> {
        self.call(Method::DELETE, &format!("v1/devices/{id}"), None::<&()>)
            .await
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApprovalRow {
    pub approval_id: ApprovalId,
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
        "revoked" => Error::Revoked,
        "pending" => Error::Pending,
        "forbidden" => Error::Forbidden,
        "read_only" => Error::ReadOnly,
        "not_found" => Error::NotFound,
        "email_taken" | "invite_used" | "exists" | "version_conflict" => {
            Error::Conflict(code.to_string())
        }
        "too_large" => Error::TooLarge,
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

    #[test]
    fn the_client_uses_the_shared_tls_config() {
        let api = Api::new(Url::parse("https://example.test/").unwrap(), None);
        assert!(Arc::ptr_eq(&api.tls(), &tls_config()));
        assert!(Arc::ptr_eq(&tls_config(), &tls_config()));
    }
}
