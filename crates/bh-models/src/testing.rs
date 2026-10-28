//! Synthetic attestation fixture: real independent enclave-side EHBP crypto.
//! No live hardware or SDK verification is asserted here.
use crate::{ChatModel, ChatRequest, Completion, ModelError};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{
        ConnectInfo, DefaultBodyLimit, State,
        connect_info::{Connected, IntoMakeServiceWithConnectInfo},
    },
    http::{HeaderMap, Uri},
    response::Response,
    serve::{IncomingStream, Listener},
};
use futures_util::future::BoxFuture;
use hpke::{
    Deserializable as _, OpModeR, Serializable as _,
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{Kem, X25519HkdfSha256},
    setup_receiver,
};
use http_body::Frame;
use http_body_util::StreamBody;
use rand::{SeedableRng as _, rngs::StdRng};
use serde_json::Value;
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{Notify, mpsc, oneshot},
};
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
/// Encrypts each chunk as one length-prefixed EHBP frame.
fn frames<'a>(
    secret: &[u8],
    enc: &[u8],
    chunks: impl IntoIterator<Item = &'a [u8]>,
) -> Vec<Vec<u8>> {
    let keys = tinfoil_ehbp::derive_response_keys(secret, enc, &NONCE).unwrap();
    let cipher = Aes256Gcm::new_from_slice(&keys.key).unwrap();
    let mut framed = Vec::new();
    for (i, chunk) in chunks.into_iter().enumerate() {
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
        let mut frame = (cipher.len() as u32).to_be_bytes().to_vec();
        frame.extend(cipher);
        framed.push(frame);
    }
    framed
}
fn encrypted(secret: &[u8], enc: &[u8], bytes: &[u8]) -> Vec<u8> {
    frames(secret, enc, bytes.chunks(16 * 1024)).concat()
}

/// Gateway request captured by a test enclave for assertions.
#[derive(Clone, Debug)]
pub struct SeenRequest {
    /// Request path.
    pub path: String,
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
    /// Encrypt each event as `data: <json>` in its own EHBP frame of an event stream.
    /// Unless `cut`, it ends with `data: [DONE]` and then the usage trailer, which
    /// is sent only when the request carries `te: trailers`.
    Stream {
        /// Events, in order.
        events: Vec<Value>,
        /// `x-tinfoil-usage-metrics` trailer value.
        trailer: Option<String>,
        /// Send the first frame, then wait for [`TestEnclave::release`].
        gated: bool,
        /// Close the connection after the events, without a last chunk.
        cut: bool,
        /// Hold the trailer and EOF until [`TestEnclave::release`], after sending `[DONE]`.
        hold_trailer: bool,
    },
    /// Unencrypted fixture response, written on the socket exactly as given and
    /// then closed, for testing the gateway's HTTP/1.1 framing and header fidelity.
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
    release: Notify,
}
/// Bytes a reply writes on its connection in place of hyper's own response.
#[derive(Clone, Debug, Default)]
struct Verbatim(Arc<Mutex<Option<Vec<u8>>>>);
struct Socket {
    tcp: TcpStream,
    verbatim: Verbatim,
    pending: Option<(Vec<u8>, usize)>,
    replaced: bool,
}
impl AsyncRead for Socket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tcp).poll_read(cx, buf)
    }
}
impl AsyncWrite for Socket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.replaced
            && let Some(bytes) = this.verbatim.0.lock().unwrap().take()
        {
            this.pending = Some((bytes, 0));
            this.replaced = true;
        }
        if !this.replaced {
            return Pin::new(&mut this.tcp).poll_write(cx, buf);
        }
        while let Some((bytes, at)) = &mut this.pending {
            if *at == bytes.len() {
                this.pending = None;
                break;
            }
            *at += ready!(Pin::new(&mut this.tcp).poll_write(cx, &bytes[*at..]))?;
        }
        // Hyper's own response is discarded.
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tcp).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tcp).poll_shutdown(cx)
    }
}
struct Sockets(TcpListener);
impl Listener for Sockets {
    type Io = Socket;
    type Addr = Verbatim;
    async fn accept(&mut self) -> (Socket, Verbatim) {
        loop {
            if let Ok((tcp, _)) = self.0.accept().await {
                let verbatim = Verbatim::default();
                let socket = Socket {
                    tcp,
                    verbatim: verbatim.clone(),
                    pending: None,
                    replaced: false,
                };
                return (socket, verbatim);
            }
        }
    }
    fn local_addr(&self) -> io::Result<Verbatim> {
        Ok(Verbatim::default())
    }
}
impl Connected<IncomingStream<'_, Sockets>> for Verbatim {
    fn connect_info(stream: IncomingStream<'_, Sockets>) -> Self {
        stream.remote_addr().clone()
    }
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
            release: Notify::new(),
        });
        let copy = state.clone();
        let (stop, stopped) = oneshot::channel();
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let app: IntoMakeServiceWithConnectInfo<_, Verbatim> = Router::new()
                        .fallback(serve)
                        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
                        .with_state(copy)
                        .into_make_service_with_connect_info();
                    let listener = Sockets(TcpListener::from_std(listener).unwrap());
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
    /// Lets a gated stream send the rest of its reply.
    pub fn release(&self) {
        self.state.release.notify_one();
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
async fn serve(
    State(state): State<Arc<Fixture>>,
    ConnectInfo(verbatim): ConnectInfo<Verbatim>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let opened = headers
        .get("ehbp-encapsulated-key")
        .and_then(|v| v.to_str().ok())
        .and_then(|key| state.enclave.open(key, &body));
    state.seen.lock().unwrap().push(SeenRequest {
        path: uri.path().into(),
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
        EnclaveReply::Stream {
            events,
            trailer,
            gated,
            cut,
            hold_trailer,
        } => {
            // A request the fixture can't open gets frames under a fixed key.
            let (secret, enc) = opened.map_or_else(
                || (vec![0; tinfoil_ehbp::EXPORT_LENGTH], vec![0; 32]),
                |(_, secret, enc)| (secret, enc),
            );
            let mut events: Vec<Vec<u8>> = events
                .iter()
                .map(|event| format!("data: {event}\n\n").into_bytes())
                .collect();
            if !cut {
                events.push(b"data: [DONE]\n\n".to_vec());
            }
            let frames = frames(&secret, &enc, events.iter().map(Vec::as_slice));
            // One slot, so hyper writes each frame before it sees the next item.
            let (send, receive) = mpsc::channel::<Result<Frame<Bytes>, io::Error>>(1);
            let release = state.clone();
            tokio::spawn(async move {
                for (i, frame) in frames.into_iter().enumerate() {
                    if i == 1 && gated {
                        release.release.notified().await;
                    }
                    if send.send(Ok(Frame::data(frame.into()))).await.is_err() {
                        return;
                    }
                }
                if hold_trailer {
                    release.release.notified().await;
                }
                if cut {
                    let _ = send.send(Err(io::Error::other("cut"))).await;
                } else if let Some(trailer) = trailer {
                    let mut trailers = HeaderMap::new();
                    // Tinfoil's router sends the usage field twice with the same value.
                    let value: axum::http::HeaderValue = trailer.parse().unwrap();
                    trailers.append("x-tinfoil-usage-metrics", value.clone());
                    trailers.append("x-tinfoil-usage-metrics", value);
                    let _ = send.send(Ok(Frame::trailers(trailers))).await;
                }
            });
            let body = futures_util::stream::unfold(receive, |mut receive| async move {
                receive.recv().await.map(|item| (item, receive))
            });
            response
                .header("ehbp-response-nonce", hex::encode(NONCE))
                .header("content-type", "text/event-stream")
                .header("trailer", "x-tinfoil-usage-metrics")
                .body(Body::new(StreamBody::new(body)))
                .unwrap()
        }
        EnclaveReply::Raw {
            status,
            headers,
            body,
        } => {
            let mut bytes = format!("HTTP/1.1 {status} Fixture\r\n").into_bytes();
            for (key, value) in headers {
                bytes.extend(format!("{key}: {value}\r\n").into_bytes());
            }
            bytes.extend(b"\r\n");
            bytes.extend(body);
            *verbatim.0.lock().unwrap() = Some(bytes);
            response.body(Body::empty()).unwrap()
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
    /// Stream text as a test pushes it, until it finishes or fails the call.
    Stream(StreamScript),
}
enum Piece {
    Text(String),
    Finish(Completion),
    Fail(ModelError),
}
/// A scripted streamed reply, driven by its [`StreamControl`].
pub struct StreamScript(mpsc::UnboundedReceiver<Piece>);
/// Pushes a [`StreamScript`]'s text; the call waits until `finish` or `fail`.
pub struct StreamControl(mpsc::UnboundedSender<Piece>);
impl StreamScript {
    /// Creates a script and the control that drives it.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> (StreamScript, StreamControl) {
        let (send, receive) = mpsc::unbounded_channel();
        (StreamScript(receive), StreamControl(send))
    }
}
impl StreamControl {
    /// Sends one piece of reply text.
    pub fn text(&self, text: &str) {
        let _ = self.0.send(Piece::Text(text.into()));
    }
    /// Ends the call with a completion.
    pub fn finish(self, completion: Completion) {
        let _ = self.0.send(Piece::Finish(completion));
    }
    /// Ends the call with an error.
    pub fn fail(self, error: ModelError) {
        let _ = self.0.send(Piece::Fail(error));
    }
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
        self.complete_streaming(req, mpsc::unbounded_channel().0)
    }
    fn complete_streaming(
        &self,
        req: ChatRequest,
        text: mpsc::UnboundedSender<String>,
    ) -> BoxFuture<'_, Result<Completion, ModelError>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(req);
            let reply = self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("script exhausted");
            match reply {
                Scripted::Reply(c) => {
                    if let Some(whole) = c.text.as_ref().filter(|t| !t.is_empty()) {
                        let _ = text.send(whole.clone());
                    }
                    Ok(c)
                }
                Scripted::Fail(e) => Err(e),
                Scripted::Hang => std::future::pending().await,
                Scripted::Stream(StreamScript(mut pieces)) => loop {
                    match pieces.recv().await {
                        Some(Piece::Text(piece)) => {
                            let _ = text.send(piece);
                        }
                        Some(Piece::Finish(c)) => return Ok(c),
                        Some(Piece::Fail(e)) => return Err(e),
                        // A dropped control never finishes the call.
                        None => std::future::pending().await,
                    }
                },
            }
        })
    }
}
