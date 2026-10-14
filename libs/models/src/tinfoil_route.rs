//! Fixed Tinfoil route. The SDK verifies the enclave before any content dispatch;
//! only its active verification document supplies the EHBP sealing key. EHBP's
//! public raw API retains decrypted SSE framing, including the real `[DONE]`.
//! This deliberately avoids the SDK's relaxed SSE parser and hidden replay path.
//! A gateway credential authenticates our proxy, NOT the provider. This module
//! neither trusts response usage for billing nor cancels remote charges on Stop.

use crate::{
    accounting::{Attempt, Delivery, Route, WorkKind},
    response::{Completion, DecodeError, Delta, Limits, ResponseDecoder},
};
use futures_util::StreamExt;
use reqwest::{Url, header};
use serde::Serialize;
use serde_json::Value;
use std::{fmt, sync::Arc};
use tokio::sync::{Mutex, mpsc, watch};

const HOST: &str = "inference.tinfoil.sh";
const REPO: &str = "tinfoilsh/confidential-model-router";
const ENCLAVE: &str = "https://inference.tinfoil.sh";
const MODEL: &str = "deepseek-v4-1-flash";
const PATH: &str = "v1/chat/completions";
const MAX_REQUEST_BYTES: usize = 1024 * 1024;

/// All failures are fixed diagnostic kinds; never include SDK, HTTP, proxy,
/// provider, decrypted response, credential, or caller input in public errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteError {
    InvalidGateway,
    InvalidRequest,
    Verification,
    Encryption,
    Transport,
    HttpStatus,
    Response(DecodeError),
}
impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "model route: {self:?}")
    }
}
impl std::error::Error for RouteError {}

/// Caller-controlled URL names ONLY the ordinary credential-holding gateway.
/// A caller cannot construct a verified route from an arbitrary key:
/// ```compile_fail
/// use basehero_models::tinfoil_route::Verified;
/// let _route: Option<Verified> = None;
/// ```
/// Production accepts HTTPS, with no userinfo, fragment or query. The path can
/// name a gateway mount point; the fixed completion path is appended below it.
#[derive(Clone)]
pub struct Gateway(Url);
impl Gateway {
    pub fn new(url: &str) -> Result<Self, RouteError> {
        let parsed = Url::parse(url).map_err(|_| RouteError::InvalidGateway)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || parsed.query().is_some()
            || parsed.port() == Some(0)
        {
            return Err(RouteError::InvalidGateway);
        }
        Ok(Self(parsed))
    }

    /// One new caller-authorized attempt. The caller must first durably reserve
    /// and gate this attempt; this local handle is NOT a durable dispatch journal.
    /// Verification runs before constructing/sending a content request. Stop is
    /// available immediately, including while verification or headers stall.
    pub fn start(
        &self,
        request: ChatRequest,
        proxy_credential: String,
        kind: WorkKind,
        limits: Limits,
    ) -> Result<StreamHandle, RouteError> {
        let body = request.encode()?;
        let bearer = bearer(&proxy_credential)?;
        let gateway = self.clone();
        Ok(start_attempt(body, bearer, kind, limits, async move {
            Verified::connect(&gateway, &proxy_credential).await
        }))
    }
}

// One lifecycle for the real verifier and the private synthetic-key fixture.
// The production entry above always supplies standard SDK verification; only
// module tests may substitute a controlled future. Stop and error delivery are
// therefore tested on exactly the production runner, not a copied spawn block.
fn start_attempt<F>(
    body: Vec<u8>,
    bearer: header::HeaderValue,
    kind: WorkKind,
    limits: Limits,
    verification: F,
) -> StreamHandle
where
    F: std::future::Future<Output = Result<Verified, RouteError>> + Send + 'static,
{
    let attempt = Arc::new(Mutex::new(Attempt::new(Route::Tinfoil, kind)));
    let (stop_tx, stop_rx) = watch::channel(false);
    let (output_tx, output_rx) = mpsc::channel(8);
    let state = Arc::clone(&attempt);
    tokio::spawn(async move {
        let outcome = tokio::select! {
            biased;
            _ = stopped(stop_rx.clone()) => return,
            verified = verification => verified,
        };
        let result = match outcome {
            Ok(route) => {
                route
                    .dispatch(body, bearer, limits, &state, &output_tx, stop_rx)
                    .await
            }
            Err(err) => Err(err),
        };
        if let Err(err) = result {
            let mut attempt = state.lock().await;
            if attempt.may_deliver() || attempt.delivery() == Delivery::Ready {
                let _ = attempt.fail();
                drop(attempt);
                // Do not lose a failure when provisional output filled the
                // channel. Stop never waits on this send or on the transport.
                let _ = output_tx.send(Err(err)).await;
            }
        }
    });
    StreamHandle {
        attempt,
        stop_tx,
        output_rx,
    }
}

/// Explicit fields only. Message/tool contents, history and schemas are all
/// inside the single EHBP-sealed JSON body, never forwarded as plain headers.
#[derive(Serialize)]
pub struct ChatRequest {
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<Value>,
    pub max_tokens: u32,
}
#[derive(Serialize)]
pub struct Message {
    pub role: Role,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    Developer,
    User,
    Assistant,
    Tool,
}

impl ChatRequest {
    fn encode(self) -> Result<Vec<u8>, RouteError> {
        if self.messages.is_empty() || self.max_tokens == 0 || self.max_tokens > 32768 {
            return Err(RouteError::InvalidRequest);
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            model: &'static str,
            stream: bool,
            stream_options: Value,
            #[serde(flatten)]
            request: &'a ChatRequest,
        }
        let bytes = serde_json::to_vec(&Wire {
            model: MODEL,
            stream: true,
            stream_options: serde_json::json!({"include_usage": true}),
            request: &self,
        })
        .map_err(|_| RouteError::InvalidRequest)?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(RouteError::InvalidRequest);
        }
        Ok(bytes)
    }
}

fn bearer(credential: &str) -> Result<header::HeaderValue, RouteError> {
    if credential.is_empty() {
        return Err(RouteError::InvalidRequest);
    }
    header::HeaderValue::from_str(&format!("Bearer {credential}"))
        .map_err(|_| RouteError::InvalidRequest)
}

// Gateway TLS is our connection (unlike SDK attestation and enclave EHBP).
// Select aws-lc-rs explicitly: the SDK installs ring as the process default,
// which lacks our required hybrid-first TLS key exchange. Keep normal roots,
// certificate/hostname checks and rustls safe protocol versions.
fn gateway_tls_config() -> Result<rustls::ClientConfig, RouteError> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        roots.add(cert).map_err(|_| RouteError::Transport)?;
    }
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| RouteError::Transport)?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

/// Only the production constructor below can create this type. No public API
/// accepts an attestation claim, GroundTruth, HPKE key, or request endpoint.
struct Verified {
    ehbp: tinfoil_ehbp::Client,
    url: Url,
    http: reqwest::Client,
}
impl Verified {
    async fn connect(gateway: &Gateway, credential: &str) -> Result<Self, RouteError> {
        let mut verified =
            tinfoil::SecureClient::new_with_proxy(HOST, REPO, credential, gateway.0.as_str());
        verified
            .verify()
            .await
            .map_err(|_| RouteError::Verification)?;
        if !verified.is_verified() {
            return Err(RouteError::Verification);
        }
        let doc = verified
            .verification_document()
            .ok_or(RouteError::Verification)?;
        if !doc.security_verified
            || doc.enclave_host != HOST
            || doc.config_repo != REPO
            || doc.hpke_public_key.is_empty()
        {
            return Err(RouteError::Verification);
        }
        Self::from_verified_key(gateway, &doc.hpke_public_key)
    }

    // Private fixture entry exists only in this module's tests. Production
    // never permits a caller to supply a key instead of standard SDK verify().
    fn from_verified_key(gateway: &Gateway, key: &str) -> Result<Self, RouteError> {
        // Reqwest 0.13 retry::never() disables its default idempotent replay;
        // Policy::none() prevents redirecting credential or ciphertext.
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .use_preconfigured_tls(gateway_tls_config()?)
            .build()
            .map_err(|_| RouteError::Transport)?;
        let ehbp = tinfoil_ehbp::Client::with_public_key_hex_and_http_client(
            gateway.0.as_str(),
            key,
            http.clone(),
        )
        .map_err(|_| RouteError::Encryption)?;
        let mut base = gateway.0.clone();
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        let url = base.join(PATH).map_err(|_| RouteError::InvalidGateway)?;
        Ok(Self { ehbp, url, http })
    }

    async fn dispatch(
        self,
        body: Vec<u8>,
        bearer: header::HeaderValue,
        limits: Limits,
        attempt: &Arc<Mutex<Attempt>>,
        output: &mpsc::Sender<Result<Event, RouteError>>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<(), RouteError> {
        let request = self
            .http
            .post(self.url)
            .header(header::AUTHORIZATION, bearer)
            .header("x-tinfoil-enclave-url", ENCLAVE)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "text/event-stream")
            .body(body)
            .build()
            .map_err(|_| RouteError::InvalidRequest)?;
        {
            let mut state = attempt.lock().await;
            if *stop.borrow() {
                state.stop();
                return Ok(());
            }
            state.mark_dispatched().map_err(|_| RouteError::Transport)?;
        }
        let response = tokio::select! {
            biased;
            _ = stopped(stop.clone()) => return Ok(()),
            response = self.ehbp.execute(request) => response.map_err(|_| RouteError::Transport)?,
        };
        if !response.status().is_success() {
            return Err(RouteError::HttpStatus);
        }
        let mut source = response.bytes_stream();
        let mut decoder = ResponseDecoder::new(limits);
        loop {
            let next = tokio::select! {
                biased;
                _ = stopped(stop.clone()) => return Ok(()),
                next = source.next() => next,
            };
            match next {
                None => break,
                Some(Err(_)) => return Err(RouteError::Transport),
                Some(Ok(chunk)) => {
                    for delta in decoder.push(&chunk).map_err(RouteError::Response)? {
                        let Delta::Text(text) = delta;
                        if !publish(Event::Text(text), attempt, output, &mut stop, false).await {
                            return Ok(());
                        }
                    }
                }
            }
        }
        let completion = decoder.finish().map_err(RouteError::Response)?;
        // An observed body usage remains an untrusted observation. Never
        // reconcile or treat client-visible headers as provider receipts.
        if !publish(
            Event::Complete(completion),
            attempt,
            output,
            &mut stop,
            true,
        )
        .await
        {
            return Ok(());
        }
        Ok(())
    }
}

async fn stopped(mut stop: watch::Receiver<bool>) {
    if *stop.borrow() {
        return;
    }
    while stop.changed().await.is_ok() {
        if *stop.borrow() {
            return;
        }
    }
}

async fn publish(
    event: Event,
    attempt: &Arc<Mutex<Attempt>>,
    output: &mpsc::Sender<Result<Event, RouteError>>,
    stop: &mut watch::Receiver<bool>,
    final_event: bool,
) -> bool {
    let permit = tokio::select! {
        biased;
        _ = stopped(stop.clone()) => return false,
        permit = output.reserve() => match permit { Ok(p) => p, Err(_) => return false },
    };
    let mut state = attempt.lock().await;
    if !state.may_deliver() || *stop.borrow() {
        return false;
    }
    if final_event && state.complete().is_err() {
        return false;
    }
    permit.send(Ok(event));
    true
}

pub enum Event {
    Text(String),
    Complete(Completion),
}
impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Event([redacted])")
    }
}

pub struct StreamHandle {
    attempt: Arc<Mutex<Attempt>>,
    stop_tx: watch::Sender<bool>,
    output_rx: mpsc::Receiver<Result<Event, RouteError>>,
}
impl StreamHandle {
    /// Local Stop releases a blocked caller without waiting for headers/chunks.
    /// Dispatch remains Pending even when the transport is dropped.
    pub async fn stop(&self) {
        let mut state = self.attempt.lock().await;
        state.stop();
        self.stop_tx.send_replace(true);
    }
    pub async fn delivery(&self) -> Delivery {
        self.attempt.lock().await.delivery()
    }
    pub async fn billing(&self) -> crate::accounting::BillingRecord {
        self.attempt.lock().await.billing()
    }
    pub async fn next(&mut self) -> Option<Result<Event, RouteError>> {
        if *self.stop_tx.borrow() {
            return None;
        }
        let next = tokio::select! {
            biased;
            _ = stopped(self.stop_tx.subscribe()) => return None,
            next = self.output_rx.recv() => next,
        };
        if *self.stop_tx.borrow() {
            return None;
        }
        let state = self.attempt.lock().await;
        if state.delivery() == Delivery::Stopped {
            return None;
        }
        next
    }
}
impl Drop for StreamHandle {
    fn drop(&mut self) {
        self.stop_tx.send_replace(true);
    }
}

#[cfg(test)]
#[path = "tinfoil_route_tests.rs"]
mod tests;
