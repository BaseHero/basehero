//! Synthetic attestation fixture: real independent enclave-side EHBP crypto.
//! No live hardware or SDK verification is asserted here.
use crate::{ChatModel, ChatRequest, Completion, ModelError};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::HeaderMap,
    response::Response,
    routing::post,
};
use futures_util::future::BoxFuture;
use hpke::{
    Deserializable as _, OpModeR, Serializable as _,
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{Kem, X25519HkdfSha256},
    setup_receiver,
};
use rand::{SeedableRng as _, rngs::StdRng};
use serde_json::Value;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};
use tokio::sync::oneshot;
use url::Url;

const NONCE: [u8; 32] = [5; 32];
type KemSuite = X25519HkdfSha256;
struct Enclave {
    private: <KemSuite as Kem>::PrivateKey,
    public: <KemSuite as Kem>::PublicKey,
}
impl Enclave {
    fn new() -> Self {
        let (private, public) = KemSuite::gen_keypair(&mut StdRng::from_os_rng());
        Self { private, public }
    }
    fn open(&self, enc_hex: &str, framed: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let enc = hex::decode(enc_hex).ok()?;
        let encapsulated = <KemSuite as Kem>::EncappedKey::from_bytes(&enc).ok()?;
        let mut receiver = setup_receiver::<AesGcm256, HkdfSha256, KemSuite>(
            &OpModeR::Base,
            &self.private,
            &encapsulated,
            tinfoil_ehbp::HPKE_REQUEST_INFO,
        )
        .ok()?;
        let mut secret = vec![0; tinfoil_ehbp::EXPORT_LENGTH];
        receiver
            .export(tinfoil_ehbp::EXPORT_LABEL, &mut secret)
            .ok()?;
        let mut plain = Vec::new();
        let mut rest = framed;
        while !rest.is_empty() {
            let n = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
            rest = &rest[4..];
            if n != 0 {
                plain.extend(receiver.open(rest.get(..n)?, &[]).ok()?);
            }
            rest = rest.get(n..)?;
        }
        Some((plain, secret, enc))
    }
}
fn encrypted(secret: &[u8], enc: &[u8], bytes: &[u8]) -> Vec<u8> {
    let keys = tinfoil_ehbp::derive_response_keys(secret, enc, &NONCE).unwrap();
    let cipher = Aes256Gcm::new_from_slice(&keys.key).unwrap();
    let mut framed = Vec::new();
    for (i, chunk) in bytes.chunks(16 * 1024).enumerate() {
        let nonce = Nonce::from(tinfoil_ehbp::compute_nonce(&keys.nonce_base, i as u64));
        let cipher = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: chunk,
                    aad: &[],
                },
            )
            .unwrap();
        framed.extend((cipher.len() as u32).to_be_bytes());
        framed.extend(cipher);
    }
    framed
}

/// Gateway request captured by a test enclave for assertions.
#[derive(Clone, Debug)]
pub struct SeenRequest {
    /// Original upstream URL forwarded by the gateway.
    pub original_url: String,
    /// Captured request headers.
    pub headers: BTreeMap<String, String>,
    /// Encrypted request body.
    pub body: Vec<u8>,
    /// Opened JSON payload, when decryptable.
    pub plaintext: Option<Value>,
}
/// Reply a local test enclave gives for its next request.
pub enum EnclaveReply {
    /// Encrypt a completion JSON value.
    Completion(Value),
    /// Return an HTTP status without a completion.
    Status(u16),
    /// Redirect to another URL.
    Redirect(String),
    /// Report an enclave key mismatch.
    KeyMismatch,
    /// Leave the request unanswered.
    Hang,
    /// Corrupt an encrypted completion.
    Corrupted(Value),
    /// Unencrypted fixture response for testing gateway byte/header fidelity.
    Raw {
        /// HTTP status for the fixture response.
        status: u16,
        /// Response headers.
        headers: Vec<(String, String)>,
        /// Response body bytes.
        body: Vec<u8>,
    },
}
struct Fixture {
    enclave: Enclave,
    replies: Mutex<VecDeque<EnclaveReply>>,
    seen: Mutex<Vec<SeenRequest>>,
}
/// Local HTTP enclave fixture; stopping it joins its server thread.
pub struct TestEnclave {
    url: Url,
    state: Arc<Fixture>,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl TestEnclave {
    /// Starts an enclave fixture on an ephemeral loopback port.
    pub fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let state = Arc::new(Fixture {
            enclave: Enclave::new(),
            replies: Mutex::new(VecDeque::new()),
            seen: Mutex::new(vec![]),
        });
        let copy = state.clone();
        let (stop, stopped) = oneshot::channel();
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let app = Router::new()
                        .route("/v1/chat/completions", post(serve))
                        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
                        .with_state(copy);
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    tokio::select! {
                        _ = axum::serve(listener, app).into_future() => {},
                        _ = stopped => {},
                    }
                });
        });
        Self {
            url,
            state,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
    /// Base URL of this test server.
    pub fn url(&self) -> Url {
        self.url.clone()
    }
    /// Hex-encoded public key used by the fixture.
    pub fn key_hex(&self) -> String {
        hex::encode(self.state.enclave.public.to_bytes())
    }
    /// Queues the next response.
    pub fn reply(&self, reply: EnclaveReply) {
        self.state.replies.lock().unwrap().push_back(reply);
    }
    /// Returns captured requests in arrival order.
    pub fn requests(&self) -> Vec<SeenRequest> {
        self.state.seen.lock().unwrap().clone()
    }
}
impl Drop for TestEnclave {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
async fn serve(State(state): State<Arc<Fixture>>, headers: HeaderMap, body: Bytes) -> Response {
    let opened = headers
        .get("ehbp-encapsulated-key")
        .and_then(|v| v.to_str().ok())
        .and_then(|key| state.enclave.open(key, &body));
    state.seen.lock().unwrap().push(SeenRequest {
        original_url: headers
            .get("x-test-original-url")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .into(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").into()))
            .collect(),
        body: body.to_vec(),
        plaintext: opened
            .as_ref()
            .and_then(|(p, _, _)| serde_json::from_slice(p).ok()),
    });
    let reply = state
        .replies
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or(EnclaveReply::Status(500));
    let response = Response::builder();
    let corrupt = matches!(reply, EnclaveReply::Corrupted(_));
    match reply {
        EnclaveReply::Completion(value) | EnclaveReply::Corrupted(value) => {
            let (_, secret, enc) = opened.expect("valid encrypted fixture request");
            let mut bytes = encrypted(&secret, &enc, &serde_json::to_vec(&value).unwrap());
            if corrupt {
                let last = bytes.last_mut().unwrap();
                *last ^= 1;
            }
            response
                .header("ehbp-response-nonce", hex::encode(NONCE))
                .header("content-type", "application/json")
                .body(bytes.into())
                .unwrap()
        }
        EnclaveReply::Status(code) => response.status(code).body("fixture error".into()).unwrap(),
        EnclaveReply::Redirect(url) => response
            .status(307)
            .header("location", url)
            .body("redirect".into())
            .unwrap(),
        EnclaveReply::KeyMismatch => response
            .status(422)
            .header("content-type", "application/problem+json")
            .body(r#"{"type":"urn:ietf:params:ehbp:error:key-config","title":"rotate key"}"#.into())
            .unwrap(),
        EnclaveReply::Hang => std::future::pending().await,
        EnclaveReply::Raw {
            status,
            headers,
            body,
        } => {
            let mut response = response.status(status);
            for (key, value) in headers {
                response = response.header(key, value);
            }
            response.body(body.into()).unwrap()
        }
    }
}

/// Response scripted for one synthetic model call.
pub enum Scripted {
    /// Produce a completion.
    Reply(Completion),
    /// Produce a typed error.
    Fail(ModelError),
    /// Wait indefinitely.
    Hang,
}
/// Local model fixture that records requests and consumes queued responses.
pub struct ScriptedModel {
    replies: Mutex<VecDeque<Scripted>>,
    requests: Mutex<Vec<ChatRequest>>,
}
impl ScriptedModel {
    /// Creates a model with responses consumed in order.
    pub fn new(replies: Vec<Scripted>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(replies.into()),
            requests: Mutex::new(vec![]),
        })
    }
    /// Returns all captured completion requests.
    pub fn requests(&self) -> Vec<ChatRequest> {
        self.requests.lock().unwrap().clone()
    }
}
impl ChatModel for ScriptedModel {
    fn complete(&self, req: ChatRequest) -> BoxFuture<'_, Result<Completion, ModelError>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(req);
            let reply = self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("script exhausted");
            match reply {
                Scripted::Reply(c) => Ok(c),
                Scripted::Fail(e) => Err(e),
                Scripted::Hang => std::future::pending().await,
            }
        })
    }
}
