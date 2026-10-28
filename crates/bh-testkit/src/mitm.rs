//! An active, local-only approval relay for exercising the real core exchange.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bh_core::{
    AccountId, ApprovalId, Digits,
    approval::protocol::{self, Exchange, Ids, Message, Transcript, email_scope},
};
use bh_crypto::{KemKey, Secret, decapsulate, encapsulate, generichash, kdf, random};
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    service::service_fn,
    upgrade,
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    convert::Infallible,
    net::TcpListener,
    sync::{Arc, Mutex, mpsc},
    thread,
};
use tokio::net::TcpStream;
use url::Url;

struct MitmExchange {
    kind: protocol::Exchange,
    ids: Ids,
    pending_token: String,
    real_pk: Box<[u8; bh_crypto::XWING_PUBLIC_BYTES]>,
    real_commitment: [u8; 32],
    fake_kem: Box<KemKey>,
    fake_pk: Box<[u8; bh_crypto::XWING_PUBLIC_BYTES]>,
    fake_r_new: [u8; 32],
    fake_commitment: [u8; 32],
    response_for_new: Option<Vec<u8>>,
    new_key: Option<Secret<32>>,
    approver_key: Option<Secret<32>>,
    approver_digits: Option<Digits>,
    approver_hello_key: Option<Secret<32>>,
}

#[derive(Default)]
struct State {
    account: Option<AccountId>,
    exchanges: HashMap<ApprovalId, MitmExchange>,
    digits_for_new: Option<Digits>,
    digits_for_approver: Option<Digits>,
    opened_a_transfer: bool,
    opened_a_hello: bool,
}

/// A loopback HTTP and WebSocket relay which substitutes its own X-Wing request
/// and response, while leaving the server's authentication and state machine intact.
pub struct ApprovalMitm {
    url: Url,
    state: Arc<Mutex<State>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ApprovalMitm {
    /// Start forwarding to `target`, binding only to `127.0.0.1`.
    pub fn start(target: Url) -> Self {
        assert_eq!(target.scheme(), "http", "MITM is for the local HTTP server");
        assert_eq!(
            target.host_str(),
            Some("127.0.0.1"),
            "MITM must not contact a remote server"
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("MITM loopback port");
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        listener.set_nonblocking(true).unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let for_thread = state.clone();
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let (ready, receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    ready.send(()).unwrap();
                    loop {
                        tokio::select! {
                            _ = &mut stopped => break,
                            accepted = listener.accept() => {
                                let Ok((socket, _)) = accepted else { break };
                                let state = for_thread.clone();
                                let target = target.clone();
                                tokio::spawn(async move {
                                    let service = service_fn(move |request| forward(request, target.clone(), state.clone()));
                                    let _ = hyper::server::conn::http1::Builder::new()
                                        .serve_connection(TokioIo::new(socket), service)
                                        .with_upgrades().await;
                                });
                            }
                        }
                    }
                });
        });
        receiver.recv().expect("MITM ready");
        Self {
            url,
            state,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    /// The local URL to give both devices instead of the real relay's URL.
    pub fn url(&self) -> Url {
        self.url.clone()
    }

    /// Digits the relay derived for the new device, after its reveal.
    pub fn digits_for_new(&self) -> Option<Digits> {
        self.state.lock().unwrap().digits_for_new.clone()
    }

    /// Digits the relay derived for the approving device, after the reveal.
    pub fn digits_for_approver(&self) -> Option<Digits> {
        self.state.lock().unwrap().digits_for_approver.clone()
    }

    /// Whether the relay opened the app's sealed claim before forwarding it.
    pub fn opened_a_hello(&self) -> bool {
        self.state.lock().unwrap().opened_a_hello
    }

    /// Whether either of the relay's transfer keys opened a posted transfer.
    pub fn opened_a_transfer(&self) -> bool {
        self.state.lock().unwrap().opened_a_transfer
    }
}

impl Drop for ApprovalMitm {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn decode(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value.as_str().expect("approval bytes"))
        .expect("base64url approval")
}

fn token(request: &Request<Incoming>) -> String {
    request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned()
}

// Envelope AAD is specified by the approval protocol; use the same bytes to
// attempt a transfer without giving the test kit access to core internals.
fn aad(ids: &Ids, purpose: u8) -> [u8; 42] {
    let mut aad = [0; 42];
    aad[..5].copy_from_slice(b"bh.v1");
    aad[5] = purpose;
    aad[6..22].copy_from_slice(&ids.approval.0);
    aad[22..38].copy_from_slice(&ids.new.0);
    aad[38..].copy_from_slice(&1u32.to_be_bytes());
    aad
}

fn open(key: &Secret<32>, ids: &Ids, purpose: u8, envelope: &[u8]) -> Option<Vec<u8>> {
    if envelope.len() < 1 + 4 + 24 + 16 || envelope[0] != 1 || envelope[1..5] != 1u32.to_be_bytes()
    {
        return None;
    }
    let nonce: [u8; 24] = envelope[5..29].try_into().unwrap();
    bh_crypto::aead_open(key, &nonce, &aad(ids, purpose), &envelope[29..])
        .ok()
        .map(|opened| opened.to_vec())
}

fn seal(key: &Secret<32>, ids: &Ids, purpose: u8, plaintext: &[u8]) -> Vec<u8> {
    let (nonce, ciphertext) = bh_crypto::aead_seal(key, &aad(ids, purpose), plaintext);
    let mut out = vec![1];
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

fn fake_commit(
    kind: protocol::Exchange,
    ids: &Ids,
    pk: &[u8; bh_crypto::XWING_PUBLIC_BYTES],
    r: &[u8; 32],
) -> [u8; 32] {
    match kind {
        Exchange::Device => protocol::commitment(ids, pk, r),
        Exchange::App => generichash(
            None,
            &[
                b"bh.v1.app-connect-commit",
                &ids.account.0,
                &ids.approval.0,
                &ids.new.0,
                pk,
                r,
            ],
        ),
    }
}

fn derive(
    kind: protocol::Exchange,
    shared: &Secret<32>,
    transcript: &[u8],
) -> (Digits, Secret<32>, Option<Secret<32>>) {
    if kind == Exchange::Device {
        let (digits, key) = protocol::derive(shared, transcript);
        return (digits, key, None);
    }
    let bound = Secret::from_slice(&generichash(Some(shared.expose()), &[transcript])).unwrap();
    (
        protocol::digits_from(&kdf(&bound, b"bhapcdg1", 1)),
        kdf(&bound, b"bhapctk1", 1),
        Some(kdf(&bound, b"bhapchl1", 1)),
    )
}

fn parse(kind: protocol::Exchange, bytes: &[u8], id: ApprovalId) -> Message {
    let mut bytes = bytes.to_vec();
    if kind == Exchange::App {
        bytes[1] = match bytes[1] {
            5 => 1,
            6 => 2,
            other => panic!("unexpected app message kind {other}"),
        };
    }
    Message::parse(&bytes, id).expect("well-formed approval message")
}

fn encode(kind: protocol::Exchange, message: Message) -> Vec<u8> {
    let mut bytes = message.encode();
    if kind == Exchange::App {
        bytes[1] = match bytes[1] {
            1 => 5,
            2 => 6,
            _ => unreachable!(),
        };
    }
    bytes
}

fn rewrite_request(state: &mut State, payload: &mut Value, bearer: &str, kind: protocol::Exchange) {
    let id: ApprovalId = payload["approvalId"].as_str().unwrap().parse().unwrap();
    let Message::Request {
        new,
        pk,
        commitment,
        ..
    } = parse(kind, &decode(&payload["request"]), id)
    else {
        panic!("not an approval request")
    };
    let ids = Ids {
        account: match kind {
            Exchange::Device => state.account.expect("account ID from login"),
            Exchange::App => email_scope(payload["email"].as_str().expect("app email")),
        },
        approval: id,
        new,
    };
    let fake_kem = Box::new(KemKey::generate());
    let fake_pk = Box::new(fake_kem.public());
    let fake_r_new = random::<32>();
    let fake_commitment = fake_commit(kind, &ids, &fake_pk, &fake_r_new);
    payload["request"] = json!(URL_SAFE_NO_PAD.encode(encode(
        kind,
        Message::Request {
            approval: id,
            new,
            pk: fake_pk.clone(),
            commitment: fake_commitment,
        }
    )));
    state.exchanges.insert(
        id,
        MitmExchange {
            kind,
            ids,
            pending_token: bearer.to_owned(),
            real_pk: pk,
            real_commitment: commitment,
            fake_kem,
            fake_pk,
            fake_r_new,
            fake_commitment,
            response_for_new: None,
            new_key: None,
            approver_key: None,
            approver_digits: None,
            approver_hello_key: None,
        },
    );
}

fn rewrite_respond(state: &mut State, id: ApprovalId, payload: &Value) {
    let exchange = state
        .exchanges
        .get_mut(&id)
        .expect("request already forwarded");
    let Message::Response {
        approver,
        ct,
        r_approver,
        ..
    } = parse(exchange.kind, &decode(&payload["response"]), id)
    else {
        panic!("not a response")
    };
    let shared = decapsulate(&exchange.fake_kem, &ct).expect("MITM request was answered");
    let approver_transcript = Transcript {
        ids: &exchange.ids,
        approver,
        pk: &exchange.fake_pk,
        commitment: &exchange.fake_commitment,
        ct: &ct,
        r_approver: &r_approver,
        r_new: &exchange.fake_r_new,
    }
    .encode_as(exchange.kind);
    let (digits, key, hello_key) = derive(exchange.kind, &shared, &approver_transcript);
    exchange.approver_key = Some(key);
    exchange.approver_hello_key = hello_key;
    exchange.approver_digits = Some(digits);

    let (fake_ct, shared) = encapsulate(&exchange.real_pk).expect("real public key");
    let fake_r_approver = random::<32>();
    // The real rN is hidden until the new device sends its reveal.
    // Keep the shared secret for deriving the new side's key on reveal.
    exchange.response_for_new = Some(encode(
        exchange.kind,
        Message::Response {
            approval: id,
            approver,
            ct: Box::new(fake_ct),
            r_approver: fake_r_approver,
        },
    ));
    exchange.new_key = Some(shared);
}

fn rewrite_reveal(state: &mut State, id: ApprovalId, payload: &mut Value) {
    let exchange = state
        .exchanges
        .get_mut(&id)
        .expect("request already forwarded");
    let reveal = decode(&payload["reveal"]);
    let r_new: [u8; 32] = reveal[18..50].try_into().expect("reveal random value");
    let hello = if exchange.kind == Exchange::App {
        assert_eq!(reveal[1], 7, "app reveal kind");
        Some(&reveal[50..])
    } else {
        assert_eq!(reveal[1], 3, "device reveal kind");
        None
    };
    let Message::Response {
        approver,
        ct,
        r_approver,
        ..
    } = parse(
        exchange.kind,
        exchange.response_for_new.as_ref().expect("response"),
        id,
    )
    else {
        unreachable!()
    };
    let transcript = Transcript {
        ids: &exchange.ids,
        approver,
        pk: &exchange.real_pk,
        commitment: &exchange.real_commitment,
        ct: &ct,
        r_approver: &r_approver,
        r_new: &r_new,
    }
    .encode_as(exchange.kind);
    let (digits, key, hello_key) = derive(
        exchange.kind,
        exchange.new_key.as_ref().expect("shared secret"),
        &transcript,
    );
    let hello = hello.map(|sealed| {
        let opened = open(
            &hello_key.expect("app hello key"),
            &exchange.ids,
            11,
            sealed,
        )
        .expect("the relay opens the app's hello");
        state.opened_a_hello = true;
        seal(
            exchange.approver_hello_key.as_ref().unwrap(),
            &exchange.ids,
            11,
            &opened,
        )
    });
    state.digits_for_new = Some(digits);
    state.digits_for_approver = exchange.approver_digits.clone();
    exchange.new_key = Some(key);
    let mut forwarded = vec![1, if exchange.kind == Exchange::App { 7 } else { 3 }];
    forwarded.extend_from_slice(&id.0);
    forwarded.extend_from_slice(&exchange.fake_r_new);
    if let Some(hello) = hello {
        forwarded.extend_from_slice(&hello);
    }
    payload["reveal"] = json!(URL_SAFE_NO_PAD.encode(forwarded));
}

fn transform_request(
    state: &mut State,
    method: &hyper::Method,
    path: &str,
    bearer: &str,
    body: Vec<u8>,
) -> Vec<u8> {
    if *method != hyper::Method::POST
        || !(path.starts_with("/v1/approvals") || path.starts_with("/v1/connect"))
    {
        return body;
    }
    let mut payload: Value = serde_json::from_slice(&body).expect("approval JSON");
    if path == "/v1/approvals" || path == "/v1/connect" {
        let kind = if path == "/v1/connect" {
            Exchange::App
        } else {
            Exchange::Device
        };
        rewrite_request(state, &mut payload, bearer, kind);
    } else if let Some((id, action)) = approval_action(path).or_else(|| connect_action(path)) {
        match action {
            "respond" => rewrite_respond(state, id, &payload),
            "reveal" => rewrite_reveal(state, id, &mut payload),
            "transfer" => {
                if let Some(exchange) = state.exchanges.get(&id) {
                    let bytes = decode(&payload["transfer"]);
                    let (purpose, sealed) = match (exchange.kind, bytes.get(1)) {
                        (Exchange::Device, Some(4)) if bytes.len() == 18 + 77 => (8, &bytes[18..]),
                        (Exchange::App, Some(8)) if bytes.len() >= 18 + 45 => (12, &bytes[18..]),
                        _ => (0, &[][..]),
                    };
                    state.opened_a_transfer |=
                        [exchange.new_key.as_ref(), exchange.approver_key.as_ref()]
                            .into_iter()
                            .flatten()
                            .any(|key| open(key, &exchange.ids, purpose, sealed).is_some());
                }
            }
            _ => {}
        }
    }
    serde_json::to_vec(&payload).unwrap()
}

fn approval_action(path: &str) -> Option<(ApprovalId, &str)> {
    let rest = path.strip_prefix("/v1/approvals/")?;
    let (id, action) = rest.split_once('/')?;
    Some((id.parse().ok()?, action))
}

fn connect_action(path: &str) -> Option<(ApprovalId, &str)> {
    let rest = path.strip_prefix("/v1/connect/")?;
    let (id, action) = rest.split_once('/')?;
    Some((id.parse().ok()?, action))
}

fn transform_response(
    state: &mut State,
    method: &hyper::Method,
    path: &str,
    bearer: &str,
    body: Vec<u8>,
    success: bool,
) -> Vec<u8> {
    if !success {
        return body;
    }
    if *method == hyper::Method::POST && path == "/v1/login" {
        let payload: Value = serde_json::from_slice(&body).expect("login response");
        state.account = Some(payload["accountId"].as_str().unwrap().parse().unwrap());
    }
    if *method != hyper::Method::GET {
        return body;
    }
    let Some(id) = path
        .strip_prefix("/v1/approvals/")
        .or_else(|| path.strip_prefix("/v1/connect/"))
        .and_then(|id| id.parse::<ApprovalId>().ok())
    else {
        return body;
    };
    let Some(exchange) = state.exchanges.get(&id) else {
        return body;
    };
    if bearer != exchange.pending_token {
        return body;
    }
    let Some(response) = exchange.response_for_new.as_ref() else {
        return body;
    };
    let mut payload: Value = serde_json::from_slice(&body).expect("approval state");
    if payload.get("response").is_some() {
        payload["response"] = json!(URL_SAFE_NO_PAD.encode(response));
        return serde_json::to_vec(&payload).unwrap();
    }
    body
}

async fn forward(
    mut request: Request<Incoming>,
    target: Url,
    state: Arc<Mutex<State>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match forward_inner(&mut request, target, state).await {
        Ok(response) => Ok(response),
        Err(error) => Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from(error.to_string())))
            .unwrap()),
    }
}

async fn forward_inner(
    request: &mut Request<Incoming>,
    target: Url,
    state: Arc<Mutex<State>>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let bearer = token(request);
    let websocket = request.headers().get(hyper::header::UPGRADE).is_some();
    let incoming_upgrade = websocket.then(|| upgrade::on(&mut *request));
    let body = request.body_mut().collect().await?.to_bytes().to_vec();
    let body = if websocket {
        body
    } else {
        transform_request(&mut state.lock().unwrap(), &method, &path, &bearer, body)
    };
    let socket = TcpStream::connect((
        target.host_str().unwrap(),
        target.port_or_known_default().unwrap(),
    ))
    .await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(socket)).await?;
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let mut outbound = Request::builder()
        .method(method.clone())
        .uri(request.uri().clone())
        .body(Full::new(Bytes::from(body)))?;
    *outbound.headers_mut() = request.headers().clone();
    outbound.headers_mut().insert(
        hyper::header::HOST,
        format!(
            "{}:{}",
            target.host_str().unwrap(),
            target.port_or_known_default().unwrap()
        )
        .parse()?,
    );
    outbound.headers_mut().remove(hyper::header::CONTENT_LENGTH);
    let mut response = sender.send_request(outbound).await?;
    if websocket && response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let outgoing_upgrade = upgrade::on(&mut response);
        tokio::spawn(async move {
            if let (Ok(incoming), Ok(outgoing)) =
                (incoming_upgrade.unwrap().await, outgoing_upgrade.await)
            {
                let _ = tokio::io::copy_bidirectional(
                    &mut TokioIo::new(incoming),
                    &mut TokioIo::new(outgoing),
                )
                .await;
            }
        });
        let mut forwarded = Response::new(Full::new(Bytes::new()));
        *forwarded.status_mut() = response.status();
        *forwarded.headers_mut() = response.headers().clone();
        return Ok(forwarded);
    }
    let status = response.status();
    let headers = response.headers().clone();
    let mut bytes = response.body_mut().collect().await?.to_bytes().to_vec();
    bytes = transform_response(
        &mut state.lock().unwrap(),
        &method,
        &path,
        &bearer,
        bytes,
        status.is_success(),
    );
    let mut forwarded = Response::new(Full::new(Bytes::from(bytes)));
    *forwarded.status_mut() = status;
    *forwarded.headers_mut() = headers;
    forwarded
        .headers_mut()
        .remove(hyper::header::CONTENT_LENGTH);
    Ok(forwarded)
}
