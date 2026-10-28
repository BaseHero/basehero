use crate::{ChatModel, ChatRequest, Completion, ModelError, TINFOIL_MODEL, response, stream};
use futures_util::{StreamExt, future::BoxFuture};
use reqwest::{Url, header};
use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, mpsc::UnboundedSender};
use zeroize::Zeroizing;

const HOST: &str = "inference.tinfoil.sh";
const REPO: &str = "tinfoilsh/confidential-model-router";
const ENCLAVE: &str = "https://inference.tinfoil.sh";

/// Validated gateway endpoint for encrypted model requests.
#[derive(Clone)]
pub struct Gateway(Url);
impl Gateway {
    /// Accepts HTTPS, or HTTP on loopback, without URL credentials or query.
    ///
    /// # Errors
    /// Returns [`ModelError::InvalidGateway`] for a malformed or disallowed URL.
    pub fn new(url: &str) -> Result<Self, ModelError> {
        let parsed = Url::parse(url).map_err(|_| ModelError::InvalidGateway)?;
        let loopback = match parsed.host() {
            Some(url::Host::Domain("localhost")) => true,
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        if !(parsed.scheme() == "https" || parsed.scheme() == "http" && loopback)
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || parsed.query().is_some()
            || parsed.port() == Some(0)
        {
            return Err(ModelError::InvalidGateway);
        }
        Ok(Self(parsed))
    }
}

/// Model implementation that verifies the enclave and encrypts each
/// completion request and response; credentials stay on the calling device.
pub struct Tinfoil {
    gateway: Gateway,
    base: Option<String>,
    credential: Zeroizing<String>,
    cache_secret: Zeroizing<String>,
    tls: Arc<rustls::ClientConfig>,
    verified: Mutex<Option<Arc<Verified>>>,
    #[cfg(all(feature = "testing", debug_assertions))]
    test_key: Option<String>,
}
impl Tinfoil {
    /// Configures a gateway with device credentials and a TLS client.
    /// Verification and network requests occur on [`ChatModel::complete`].
    pub fn new(
        gateway: Gateway,
        credential: Zeroizing<String>,
        cache_secret: Zeroizing<String>,
        tls: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self {
            gateway,
            base: None,
            credential,
            cache_secret,
            tls,
            verified: Mutex::new(None),
            #[cfg(all(feature = "testing", debug_assertions))]
            test_key: None,
        }
    }

    /// Creates a fixture model with a supplied enclave key for local tests.
    #[cfg(all(feature = "testing", debug_assertions))]
    pub fn unverified_for_tests(
        gateway: Gateway,
        credential: Zeroizing<String>,
        key_hex: String,
    ) -> Self {
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let mut model = Self::new(
            gateway,
            credential,
            Zeroizing::new("cache-secret-for-tests".into()),
            Arc::new(tls),
        );
        model.test_key = Some(key_hex);
        model
    }

    /// Attributes calls to a base ID; the gateway checks this device's read grant.
    pub fn with_base(mut self, base: String) -> Self {
        self.base = Some(base);
        self
    }

    async fn connect(&self) -> Result<Verified, ModelError> {
        #[cfg(all(feature = "testing", debug_assertions))]
        if let Some(key) = &self.test_key {
            return Verified::from_verified_key(&self.gateway, key, &self.tls);
        }
        Verified::connect(&self.gateway, &self.credential, &self.tls).await
    }

    async fn run(
        &self,
        req: ChatRequest,
        text: &UnboundedSender<String>,
    ) -> Result<Completion, ModelError> {
        let body = req.encode(&self.cache_secret)?;
        if self.credential.is_empty() {
            return Err(ModelError::InvalidRequest);
        }
        let mut bearer = header::HeaderValue::from_str(&format!("Bearer {}", *self.credential))
            .map_err(|_| ModelError::InvalidRequest)?;
        bearer.set_sensitive(true);
        for attempt in 0..2 {
            let route = {
                let mut cache = self.verified.lock().await;
                if cache.is_none() {
                    *cache = Some(Arc::new(self.connect().await?));
                }
                cache.as_ref().unwrap().clone()
            };
            let mut builder = route.http.post(route.url.clone());
            if let Some(base) = &self.base {
                builder = builder.header("BH-Base", base);
            }
            let request = builder
                .header(header::AUTHORIZATION, bearer.clone())
                .header("x-tinfoil-enclave-url", ENCLAVE)
                .header("x-tinfoil-model", TINFOIL_MODEL)
                .header("BH-Protocol", "1")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "text/event-stream")
                .header("x-tinfoil-max-output-tokens", req.max_tokens.to_string())
                .body(body.clone())
                .build()
                .map_err(|_| ModelError::InvalidRequest)?;
            let response = match route.ehbp.execute(request).await {
                Ok(response) => response,
                Err(tinfoil_ehbp::Error::KeyConfigMismatch(_)) => {
                    let mut cache = self.verified.lock().await;
                    // Don't invalidate another call's freshly verified route.
                    if cache.as_ref().is_some_and(|r| Arc::ptr_eq(r, &route)) {
                        *cache = None;
                    }
                    if attempt == 0 {
                        continue;
                    }
                    return Err(ModelError::Encryption);
                }
                Err(tinfoil_ehbp::Error::Http(_)) => return Err(ModelError::Transport),
                Err(_) => return Err(ModelError::Encryption),
            };
            if !response.status().is_success() {
                return Err(match response.status().as_u16() {
                    401 => ModelError::Unauthorized,
                    403 => ModelError::Forbidden,
                    413 => ModelError::TooLarge,
                    426 => ModelError::NeedsUpdate,
                    429 => ModelError::RateLimited,
                    status => ModelError::HttpStatus(status),
                });
            }
            let events = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(';').next())
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("text/event-stream"));
            let mut chunks = response.bytes_stream();
            if events {
                let mut decoder = stream::Decoder::new();
                while let Some(chunk) = chunks.next().await {
                    // The stream stopped partway, whether cut or tampered with.
                    let chunk = chunk.map_err(|_| ModelError::Response)?;
                    for piece in decoder.push(&chunk)? {
                        let _ = text.send(piece);
                    }
                    // [DONE] is authenticated; the gateway can finish reading the trailer
                    // without keeping the device's completion waiting for EOF.
                    if decoder.done() {
                        return decoder.finish();
                    }
                }
                return decoder.finish();
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = chunks.next().await {
                let chunk = chunk.map_err(|_| ModelError::Encryption)?;
                if chunk.len() > 8 * 1024 * 1024 - bytes.len() {
                    return Err(ModelError::Response);
                }
                bytes.extend_from_slice(&chunk);
            }
            let completion = response::decode(&bytes)?;
            if let Some(whole) = completion.text.as_ref().filter(|t| !t.is_empty()) {
                let _ = text.send(whole.clone());
            }
            return Ok(completion);
        }
        unreachable!()
    }
}
impl ChatModel for Tinfoil {
    fn complete(&self, req: ChatRequest) -> BoxFuture<'_, Result<Completion, ModelError>> {
        self.complete_streaming(req, tokio::sync::mpsc::unbounded_channel().0)
    }
    fn complete_streaming(
        &self,
        req: ChatRequest,
        text: UnboundedSender<String>,
    ) -> BoxFuture<'_, Result<Completion, ModelError>> {
        Box::pin(async move {
            tokio::time::timeout(Duration::from_secs(120), self.run(req, &text))
                .await
                .map_err(|_| ModelError::Transport)?
        })
    }
}

struct Verified {
    ehbp: tinfoil_ehbp::Client,
    url: Url,
    http: reqwest::Client,
}
impl Verified {
    async fn connect(
        gateway: &Gateway,
        credential: &str,
        tls: &rustls::ClientConfig,
    ) -> Result<Self, ModelError> {
        let mut verified =
            tinfoil::SecureClient::new_with_proxy(HOST, REPO, credential, gateway.0.as_str());
        verified
            .verify()
            .await
            .map_err(|_| ModelError::Verification)?;
        if !verified.is_verified() {
            return Err(ModelError::Verification);
        }
        let doc = verified
            .verification_document()
            .ok_or(ModelError::Verification)?;
        if !doc.security_verified
            || doc.enclave_host != HOST
            || doc.config_repo != REPO
            || doc.hpke_public_key.is_empty()
        {
            return Err(ModelError::Verification);
        }
        Self::from_verified_key(gateway, &doc.hpke_public_key, tls)
    }
    fn from_verified_key(
        gateway: &Gateway,
        key: &str,
        tls: &rustls::ClientConfig,
    ) -> Result<Self, ModelError> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(120))
            .use_preconfigured_tls(tls.clone())
            .build()
            .map_err(|_| ModelError::Transport)?;
        let ehbp = tinfoil_ehbp::Client::with_public_key_hex_and_http_client(
            gateway.0.as_str(),
            key,
            http.clone(),
        )
        .map_err(|_| ModelError::Encryption)?;
        let mut base = gateway.0.clone();
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        let url = base
            .join("v1/chat/completions")
            .map_err(|_| ModelError::InvalidGateway)?;
        Ok(Self { ehbp, url, http })
    }
}
