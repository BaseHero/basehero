//! An active, local-only approval relay for exercising the real core exchange.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bh_core::{
    AccountId, ApprovalId, Digits,
    approval::protocol::{self, Ids, Message, Transcript},
};
use bh_crypto::{KemKey, Secret, decapsulate, encapsulate, random};
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

struct Exchange {
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
}

#[derive(Default)]
struct State {
    account: Option<AccountId>,
    exchanges: HashMap<ApprovalId, Exchange>,
    digits_for_new: Option<Digits>,
    digits_for_approver: Option<Digits>,
    opened_a_transfer: bool,
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

    /// Whether either of the relay's transfer keys opened a posted account key.
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
fn transfer_aad(ids: &Ids) -> [u8; 42] {
    let mut aad = [0; 42];
    aad[..5].copy_from_slice(b"bh.v1");
    aad[5] = 8; // ApprovalTransfer
    aad[6..22].copy_from_slice(&ids.approval.0);
    aad[22..38].copy_from_slice(&ids.new.0);
    aad[38..].copy_from_slice(&1u32.to_be_bytes());
    aad
}

fn opened(key: &Secret<32>, ids: &Ids, envelope: &[u8]) -> bool {
    if envelope.len() != 1 + 4 + 24 + 32 + 16
        || envelope[0] != 1
        || envelope[1..5] != 1u32.to_be_bytes()
    {
        return false;
    }
    let nonce: [u8; 24] = envelope[5..29].try_into().unwrap();
    bh_crypto::aead_open(key, &nonce, &transfer_aad(ids), &envelope[29..]).is_ok()
}

fn rewrite_request(state: &mut State, payload: &mut Value, bearer: &str) {
    let id: ApprovalId = payload["approvalId"].as_str().unwrap().parse().unwrap();
    let Message::Request {
        new,
        pk,
        commitment,
        ..
    } = Message::parse(&decode(&payload["request"]), id).unwrap()
    else {
        panic!("not an approval request")
    };
    let ids = Ids {
        account: state.account.expect("account ID from login"),
        approval: id,
        new,
    };
    let fake_kem = Box::new(KemKey::generate());
    let fake_pk = Box::new(fake_kem.public());
    let fake_r_new = random::<32>();
    let fake_commitment = protocol::commitment(&ids, &fake_pk, &fake_r_new);
    payload["request"] = json!(
        URL_SAFE_NO_PAD.encode(
            Message::Request {
                approval: id,
                new,
                pk: fake_pk.clone(),
                commitment: fake_commitment,
            }
            .encode()
        )
    );
    state.exchanges.insert(
        id,
        Exchange {
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
    } = Message::parse(&decode(&payload["response"]), id).unwrap()
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
    .encode();
    let (digits, key) = protocol::derive(&shared, &approver_transcript);
    exchange.approver_key = Some(key);
    exchange.approver_digits = Some(digits);

    let (fake_ct, shared) = encapsulate(&exchange.real_pk).expect("real public key");
    let fake_r_approver = random::<32>();
    // The real rN is hidden until the new device sends its reveal.
    // Keep the shared secret for deriving the new side's key on reveal.
    exchange.response_for_new = Some(
        Message::Response {
            approval: id,
            approver,
            ct: Box::new(fake_ct),
            r_approver: fake_r_approver,
        }
        .encode(),
    );
    exchange.new_key = Some(shared);
}

fn rewrite_reveal(state: &mut State, id: ApprovalId, payload: &mut Value) {
    let exchange = state
        .exchanges
        .get_mut(&id)
        .expect("request already forwarded");
    let Message::Reveal { r_new, .. } = Message::parse(&decode(&payload["reveal"]), id).unwrap()
    else {
        panic!("not a reveal")
    };
    let Message::Response {
        approver,
        ct,
        r_approver,
        ..
    } = Message::parse(exchange.response_for_new.as_ref().expect("response"), id).unwrap()
    else {
        unreachable!()
    };
    let (digits, key) = protocol::derive(
        exchange.new_key.as_ref().expect("shared secret"),
        &Transcript {
            ids: &exchange.ids,
            approver,
            pk: &exchange.real_pk,
            commitment: &exchange.real_commitment,
            ct: &ct,
            r_approver: &r_approver,
            r_new: &r_new,
        }
        .encode(),
    );
    state.digits_for_new = Some(digits);
    state.digits_for_approver = exchange.approver_digits.clone();
    exchange.new_key = Some(key);
    payload["reveal"] = json!(
        URL_SAFE_NO_PAD.encode(
            Message::Reveal {
                approval: id,
                r_new: exchange.fake_r_new,
            }
            .encode()
        )
    );
}

fn transform_request(
    state: &mut State,
    method: &hyper::Method,
    path: &str,
    bearer: &str,
    body: Vec<u8>,
) -> Vec<u8> {
    if *method != hyper::Method::POST || !path.starts_with("/v1/approvals") {
        return body;
    }
    let mut payload: Value = serde_json::from_slice(&body).expect("approval JSON");
    if path == "/v1/approvals" {
        rewrite_request(state, &mut payload, bearer);
    } else if let Some((id, action)) = approval_action(path) {
        match action {
            "respond" => rewrite_respond(state, id, &payload),
            "reveal" => rewrite_reveal(state, id, &mut payload),
            "transfer" => {
                if let Some(exchange) = state.exchanges.get(&id) {
                    let bytes = decode(&payload["transfer"]);
                    if let Ok(Message::Transfer { account_key, .. }) = Message::parse(&bytes, id) {
                        state.opened_a_transfer |=
                            [exchange.new_key.as_ref(), exchange.approver_key.as_ref()]
                                .into_iter()
                                .flatten()
                                .any(|key| opened(key, &exchange.ids, &account_key));
                    }
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
