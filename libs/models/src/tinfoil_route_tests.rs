//! SYNTHETIC ATTESTATION FIXTURE: real independent EHBP enclave-side crypto,
//! but no live hardware, Sigstore, provider or SDK attestation is asserted here.
use super::*;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use hpke::{
    Deserializable as _, OpModeR, Serializable as _,
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{Kem, X25519HkdfSha256},
    setup_receiver,
};
use rand::{SeedableRng as _, rngs::StdRng};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::{Duration, timeout},
};

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
    fn key(&self) -> String {
        hex::encode(self.public.to_bytes())
    }
    fn open(&self, enc_hex: &str, framed: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let enc = hex::decode(enc_hex).unwrap();
        let encapsulated = <KemSuite as Kem>::EncappedKey::from_bytes(&enc).unwrap();
        let mut receiver = setup_receiver::<AesGcm256, HkdfSha256, KemSuite>(
            &OpModeR::Base,
            &self.private,
            &encapsulated,
            tinfoil_ehbp::HPKE_REQUEST_INFO,
        )
        .unwrap();
        let mut secret = vec![0; tinfoil_ehbp::EXPORT_LENGTH];
        receiver
            .export(tinfoil_ehbp::EXPORT_LABEL, &mut secret)
            .unwrap();
        let mut plain = Vec::new();
        let mut offset = 0;
        while offset < framed.len() {
            let n = u32::from_be_bytes(framed[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if n != 0 {
                plain.extend(receiver.open(&framed[offset..offset + n], &[]).unwrap());
            }
            offset += n;
        }
        (plain, secret, enc)
    }
}
fn encrypted(secret: &[u8], enc: &[u8], fragments: &[&[u8]]) -> Vec<Vec<u8>> {
    let keys = tinfoil_ehbp::derive_response_keys(secret, enc, &NONCE).unwrap();
    let cipher = Aes256Gcm::new_from_slice(&keys.key).unwrap();
    fragments
        .iter()
        .enumerate()
        .map(|(i, bytes)| {
            let nonce = Nonce::from(tinfoil_ehbp::compute_nonce(&keys.nonce_base, i as u64));
            let cipher = cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: bytes,
                        aad: &[],
                    },
                )
                .unwrap();
            let mut frame = Vec::from((cipher.len() as u32).to_be_bytes());
            frame.extend(cipher);
            frame
        })
        .collect()
}
fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}
fn split_at(buf: &[u8], pattern: &[u8]) -> Option<usize> {
    buf.windows(pattern.len()).position(|w| w == pattern)
}
async fn read_request(socket: &mut TcpStream) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let end = loop {
        if let Some(pos) = split_at(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        let mut tmp = [0; 4096];
        let n = socket.read(&mut tmp).await.unwrap();
        assert!(n > 0);
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8(buf[..end].to_vec()).unwrap();
    let mut rest = buf[end..].to_vec();
    let mut body = Vec::new();
    if header(&head, "transfer-encoding").as_deref() == Some("chunked") {
        let mut pos = 0;
        loop {
            let line = loop {
                if let Some(at) = split_at(&rest[pos..], b"\r\n") {
                    break pos + at;
                }
                let mut buf = [0; 4096];
                let n = socket.read(&mut buf).await.unwrap();
                assert!(n > 0);
                rest.extend(&buf[..n]);
            };
            let size =
                usize::from_str_radix(std::str::from_utf8(&rest[pos..line]).unwrap(), 16).unwrap();
            pos = line + 2;
            if size == 0 {
                break;
            }
            while rest.len() < pos + size + 2 {
                let mut buf = [0; 4096];
                let n = socket.read(&mut buf).await.unwrap();
                assert!(n > 0);
                rest.extend(&buf[..n]);
            }
            body.extend(&rest[pos..pos + size]);
            pos += size + 2;
        }
    } else {
        let size: usize = header(&head, "content-length").unwrap().parse().unwrap();
        while rest.len() < size {
            let mut buf = [0; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            assert!(n > 0);
            rest.extend(&buf[..n]);
        }
        body.extend(&rest[..size]);
    }
    (head, body)
}
async fn chunk(socket: &mut TcpStream, frame: &[u8]) {
    socket
        .write_all(format!("{:x}\r\n", frame.len()).as_bytes())
        .await
        .unwrap();
    socket.write_all(frame).await.unwrap();
    socket.write_all(b"\r\n").await.unwrap();
}
fn input() -> ChatRequest {
    ChatRequest {
        messages: vec![
            Message {
                role: Role::User,
                content: Some(json!("PROMPT_CANARY_4584")),
                tool_calls: None,
                tool_call_id: None,
            },
            Message {
                role: Role::Assistant,
                content: None,
                tool_calls: Some(vec![
                    json!({"id":"call0","type":"function","function":{"name":"lookup","arguments":"HISTORY_CANARY_2779"}}),
                ]),
                tool_call_id: None,
            },
            Message {
                role: Role::Tool,
                content: Some(json!("TOOL_RESULT_CANARY_0019")),
                tool_calls: None,
                tool_call_id: Some("call0".into()),
            },
        ],
        tools: Some(vec![
            json!({"type":"function","function":{"name":"TOOL_CANARY_8462", "parameters":{"type":"object"}}}),
        ]),
        tool_choice: Some(json!("auto")),
        response_format: Some(json!({"type":"json_object", "marker":"FORMAT_CANARY_1872"})),
        max_tokens: 512,
    }
}
fn fixture(route: Verified) -> StreamHandle {
    start_attempt(
        input().encode().unwrap(),
        bearer("PROXY_CREDENTIAL_CANARY").unwrap(),
        WorkKind::AskedTurn,
        Limits::default(),
        async move { Ok(route) }, // synthetic key only in this private unit fixture
    )
}
fn local(addr: std::net::SocketAddr, key: &str) -> Verified {
    // The SDK normally installs the ring provider in its public constructor.
    let _ = tinfoil::SecureClient::new(HOST, REPO, "");
    // Only tests can construct an HTTP route with a synthetic key. Production
    // Gateway::new always rejects HTTP and Verified::connect always verifies.
    let gateway = Gateway(Url::parse(&format!("http://{addr}/gateway/")).unwrap());
    Verified::from_verified_key(&gateway, key).unwrap()
}
async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    timeout(Duration::from_secs(4), future)
        .await
        .expect("local fixture stalled")
}
fn text_event(text: &str) -> Vec<u8> {
    format!(
        "data: {}\n\n",
        json!({"choices":[{"index":0,"delta":{"content":text}}]})
    )
    .into_bytes()
}
fn tools_event() -> Vec<u8> {
    format!("data: {}\n\n", json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call0","type":"function","function":{"name":"lookup","arguments":"{\"ok\":true}"}}]},"finish_reason":"tool_calls"}]})).into_bytes()
}

#[test]
fn owned_gateway_tls_prefers_hybrid_even_after_sdk_installs_ring() {
    // The real SDK constructor selects ring as the process default on first use.
    let _ = tinfoil::SecureClient::new(HOST, REPO, "");
    assert_eq!(
        rustls::crypto::CryptoProvider::get_default()
            .unwrap()
            .kx_groups[0]
            .name(),
        rustls::NamedGroup::X25519,
    );
    let config = gateway_tls_config().unwrap();
    assert_eq!(
        config.crypto_provider().kx_groups[0].name(),
        rustls::NamedGroup::X25519MLKEM768,
    );
}

#[tokio::test]
async fn encrypted_stream_is_incremental_and_final_tools_are_terminal_only() {
    let enclave = Enclave::new();
    let key = enclave.key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (release_tx, release_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (head, body) = bounded(read_request(&mut socket)).await;
        assert!(head.starts_with("POST /gateway/v1/chat/completions "));
        assert_eq!(
            header(&head, "x-tinfoil-enclave-url").as_deref(),
            Some(ENCLAVE)
        );
        assert_eq!(
            header(&head, "authorization").as_deref(),
            Some("Bearer PROXY_CREDENTIAL_CANARY")
        );
        for canary in [
            "PROMPT_CANARY_4584",
            "TOOL_CANARY_8462",
            "FORMAT_CANARY_1872",
            "HISTORY_CANARY_2779",
            "TOOL_RESULT_CANARY_0019",
        ] {
            assert!(!String::from_utf8_lossy(&body).contains(canary));
            assert!(!head.contains(canary));
        }
        let (plain, secret, enc) =
            enclave.open(&header(&head, "ehbp-encapsulated-key").unwrap(), &body);
        let request: Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(request["model"], MODEL);
        assert_eq!(request["max_tokens"], 512);
        assert_eq!(request["messages"][0]["content"], "PROMPT_CANARY_4584");
        assert_eq!(request["tools"][0]["function"]["name"], "TOOL_CANARY_8462");
        assert_eq!(
            request["messages"][1]["tool_calls"][0]["function"]["arguments"],
            "HISTORY_CANARY_2779"
        );
        assert_eq!(request["messages"][2]["content"], "TOOL_RESULT_CANARY_0019");
        assert_eq!(request["response_format"]["marker"], "FORMAT_CANARY_1872");
        let a = text_event("💡");
        // Fragment UTF-8 and SSE across authenticated EHBP frames and TCP writes.
        let frames = encrypted(
            &secret,
            &enc,
            &[
                &a[..9],
                &a[9..16],
                &a[16..],
                &tools_event(),
                b"data: [DONE]\n\n",
            ],
        );
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nEhbp-Response-Nonce: {}\r\nTransfer-Encoding: chunked\r\n\r\n", hex::encode(NONCE)).as_bytes()).await.unwrap();
        for frame in &frames[..3] {
            for part in frame.chunks(3) {
                chunk(&mut socket, part).await;
            }
        }
        // Do not end the upstream stream until the consumer sees text.
        let _ = release_rx.await;
        for frame in &frames[3..] {
            chunk(&mut socket, frame).await;
        }
        socket.write_all(b"0\r\n\r\n").await.unwrap();
    });
    let mut handle = fixture(local(addr, &key));
    match bounded(handle.next()).await.unwrap().unwrap() {
        Event::Text(text) => assert_eq!(text, "💡"),
        _ => panic!("expected provisional text"),
    }
    assert_eq!(handle.delivery().await, Delivery::Running);
    release_tx.send(()).unwrap();
    match bounded(handle.next()).await.unwrap().unwrap() {
        Event::Complete(done) => {
            assert_eq!(done.text, "💡");
            assert_eq!(done.tools.len(), 1);
            assert_eq!(done.tools[0].arguments, json!({"ok":true}));
            assert_eq!(done.json(), Err(DecodeError::InvalidJson));
        }
        _ => panic!("expected completion"),
    }
    assert!(bounded(handle.next()).await.is_none());
    assert_eq!(handle.delivery().await, Delivery::Completed);
    assert!(matches!(
        handle.billing().await.settlement,
        crate::accounting::Settlement::Pending
    ));
    bounded(server).await.unwrap();
}

#[tokio::test]
async fn stop_during_pending_verification_never_dispatches() {
    let enclave = Enclave::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let route = local(listener.local_addr().unwrap(), &enclave.key());
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let mut handle = start_attempt(
        input().encode().unwrap(),
        bearer("PROXY_CREDENTIAL_CANARY").unwrap(),
        WorkKind::AskedTurn,
        Limits::default(),
        async move {
            entered_tx.send(()).unwrap();
            let _ = release_rx.await;
            Ok(route)
        },
    );
    bounded(entered_rx).await.unwrap();
    handle.stop().await;
    assert!(bounded(handle.next()).await.is_none());
    assert_eq!(handle.delivery().await, Delivery::Stopped);
    assert!(matches!(
        handle.billing().await.settlement,
        crate::accounting::Settlement::NotDispatched
    ));
    bounded(async {
        while !release_tx.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        release_tx.send(()).is_err(),
        "stopped verifier must be dropped"
    );
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn stop_during_stalled_headers_releases_caller_and_preserves_pending() {
    let enclave = Enclave::new();
    let key = enclave.key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (arrived_tx, arrived_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let _ = bounded(read_request(&mut socket)).await;
        arrived_tx.send(()).unwrap();
        let _ = release_rx.await;
        let _ = socket
            .write_all(b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n")
            .await;
    });
    let mut handle = fixture(local(addr, &key));
    bounded(arrived_rx).await.unwrap();
    handle.stop().await;
    assert!(bounded(handle.next()).await.is_none());
    assert_eq!(handle.delivery().await, Delivery::Stopped);
    assert!(matches!(
        handle.billing().await.settlement,
        crate::accounting::Settlement::Pending
    ));
    release_tx.send(()).unwrap();
    bounded(server).await.unwrap();
}

#[tokio::test]
async fn stop_between_chunks_discards_buffered_late_tools() {
    let enclave = Enclave::new();
    let key = enclave.key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (release_tx, release_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (head, body) = bounded(read_request(&mut socket)).await;
        let (_, secret, enc) =
            enclave.open(&header(&head, "ehbp-encapsulated-key").unwrap(), &body);
        let text = text_event("early");
        let frames = encrypted(&secret, &enc, &[&text, &tools_event(), b"data: [DONE]\n\n"]);
        socket.write_all(format!("HTTP/1.1 200 OK\r\nEhbp-Response-Nonce: {}\r\nTransfer-Encoding: chunked\r\n\r\n", hex::encode(NONCE)).as_bytes()).await.unwrap();
        chunk(&mut socket, &frames[0]).await;
        let _ = release_rx.await;
        for frame in &frames[1..] {
            if socket
                .write_all(format!("{:x}\r\n", frame.len()).as_bytes())
                .await
                .is_err()
            {
                return;
            }
            if socket.write_all(frame).await.is_err() {
                return;
            }
            if socket.write_all(b"\r\n").await.is_err() {
                return;
            }
        }
        let _ = socket.write_all(b"0\r\n\r\n").await;
    });
    let mut handle = fixture(local(addr, &key));
    assert!(matches!(bounded(handle.next()).await.unwrap().unwrap(),Event::Text(s) if s=="early"));
    handle.stop().await;
    release_tx.send(()).unwrap();
    assert!(bounded(handle.next()).await.is_none());
    assert_eq!(handle.delivery().await, Delivery::Stopped);
    assert!(matches!(
        handle.billing().await.settlement,
        crate::accounting::Settlement::Pending
    ));
    bounded(server).await.unwrap();
}

#[tokio::test]
async fn structured_json_requires_real_done_and_does_not_claim_schema() {
    let enclave = Enclave::new();
    let key = enclave.key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (head, body) = bounded(read_request(&mut socket)).await;
        let (_, secret, enc) =
            enclave.open(&header(&head, "ehbp-encapsulated-key").unwrap(), &body);
        let text = text_event("{\"answer\":42}");
        let finish = format!(
            "data: {}\n\n",
            json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]})
        );
        let usage = format!(
            "data: {}\n\n",
            json!({"choices":[],"usage":{"prompt_tokens":88,"completion_tokens":99}})
        );
        let frames = encrypted(
            &secret,
            &enc,
            &[
                &text,
                &finish.into_bytes(),
                &usage.into_bytes(),
                b"data: [DONE]\n\n",
            ],
        );
        socket.write_all(format!("HTTP/1.1 200 OK\r\nEhbp-Response-Nonce: {}\r\nTransfer-Encoding: chunked\r\n\r\n",hex::encode(NONCE)).as_bytes()).await.unwrap();
        for frame in frames {
            chunk(&mut socket, &frame).await;
        }
        socket.write_all(b"0\r\n\r\n").await.unwrap();
    });
    let mut handle = fixture(local(addr, &key));
    assert!(matches!(
        bounded(handle.next()).await.unwrap().unwrap(),
        Event::Text(_)
    ));
    match bounded(handle.next()).await.unwrap().unwrap() {
        Event::Complete(c) => {
            assert_eq!(c.json().unwrap(), json!({"answer":42}));
            assert_eq!(c.reported_usage.unwrap().input, 88);
        }
        _ => panic!("expected complete"),
    }
    assert!(matches!(
        handle.billing().await.settlement,
        crate::accounting::Settlement::Pending
    ));
    bounded(server).await.unwrap();
}

#[tokio::test]
async fn corruption_truncation_and_key_mismatch_fail_without_replay_or_secret_diagnostics() {
    for scenario in [
        "corrupt",
        "truncated",
        "wrong_key",
        "http_mismatch",
        "redirect",
    ] {
        let enclave = Enclave::new();
        let key = enclave.key();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (head, body) = bounded(read_request(&mut socket)).await;
            assert!(!String::from_utf8_lossy(&body).contains("PROMPT_CANARY_4584"));
            if scenario == "http_mismatch" {
                socket.write_all(b"HTTP/1.1 422 Key Mismatch\r\nContent-Type: application/problem+json\r\nContent-Length: 35\r\n\r\nSECRET_PROVIDER_CANARY_CONTENT_1234").await.unwrap();
            } else if scenario == "redirect" {
                socket.write_all(format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{addr}/retry\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.unwrap();
            } else {
                let (_, secret, enc) =
                    enclave.open(&header(&head, "ehbp-encapsulated-key").unwrap(), &body);
                let text = text_event("SECRET_PROVIDER_CANARY_CONTENT_1234");
                let frames = if scenario == "wrong_key" {
                    encrypted(
                        &[8; tinfoil_ehbp::EXPORT_LENGTH],
                        &enc,
                        &[&text, b"data: [DONE]\n\n"],
                    )
                } else {
                    encrypted(&secret, &enc, &[&text, b"data: [DONE]\n\n"])
                };
                let mut bytes = frames.concat();
                if scenario == "corrupt" {
                    *bytes.last_mut().unwrap() ^= 1;
                }
                if scenario == "truncated" {
                    bytes.pop();
                }
                socket.write_all(format!("HTTP/1.1 200 OK\r\nEhbp-Response-Nonce: {}\r\nContent-Length: {}\r\n\r\n",hex::encode(NONCE),bytes.len()).as_bytes()).await.unwrap();
                socket.write_all(&bytes).await.unwrap();
            }
            // A second dispatch would be an invisible extra charge; fail the test.
            assert!(
                timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err()
            );
        });
        let mut handle = fixture(local(addr, &key));
        let first = bounded(handle.next()).await.unwrap();
        if matches!(first, Ok(Event::Text(_))) {
            let err = bounded(handle.next()).await.unwrap().unwrap_err();
            let diagnostic = err.to_string();
            assert!(!diagnostic.contains("SECRET_PROVIDER_CANARY"));
        } else {
            let err = first.unwrap_err();
            assert!(!err.to_string().contains("SECRET_PROVIDER_CANARY"));
        }
        assert_eq!(handle.delivery().await, Delivery::Failed);
        assert!(matches!(
            handle.billing().await.settlement,
            crate::accounting::Settlement::Pending
        ));
        bounded(server).await.unwrap();
    }
}

#[tokio::test]
async fn full_output_queue_still_reports_terminal_failure() {
    let enclave = Enclave::new();
    let key = enclave.key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (head, body) = bounded(read_request(&mut socket)).await;
        let (_, secret, enc) =
            enclave.open(&header(&head, "ehbp-encapsulated-key").unwrap(), &body);
        let texts: Vec<_> = (0..8).map(|_| text_event("x")).collect();
        let parts: Vec<_> = texts.iter().map(Vec::as_slice).collect();
        let frames = encrypted(&secret, &enc, &parts);
        socket.write_all(format!("HTTP/1.1 200 OK\r\nEhbp-Response-Nonce: {}\r\nTransfer-Encoding: chunked\r\n\r\n",hex::encode(NONCE)).as_bytes()).await.unwrap();
        for frame in frames {
            chunk(&mut socket, &frame).await;
        }
        socket.write_all(b"0\r\n\r\n").await.unwrap();
    });
    let mut handle = fixture(local(addr, &key));
    bounded(async {
        while handle.delivery().await != Delivery::Failed {
            tokio::task::yield_now().await;
        }
    })
    .await;
    for _ in 0..8 {
        assert!(matches!(
            bounded(handle.next()).await.unwrap().unwrap(),
            Event::Text(_)
        ));
    }
    assert!(matches!(
        bounded(handle.next()).await.unwrap(),
        Err(RouteError::Response(DecodeError::Incomplete))
    ));
    bounded(server).await.unwrap();
}

#[tokio::test]
async fn missing_done_and_untrusted_usage_cannot_settle() {
    let enclave = Enclave::new();
    let key = enclave.key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (head, body) = bounded(read_request(&mut socket)).await;
        let (_, secret, enc) =
            enclave.open(&header(&head, "ehbp-encapsulated-key").unwrap(), &body);
        let sse = format!(
            "data: {}\n\n",
            json!({"choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":88,"completion_tokens":99}})
        );
        let frame = encrypted(&secret, &enc, &[sse.as_bytes()]).remove(0);
        socket.write_all(format!("HTTP/1.1 200 OK\r\nEhbp-Response-Nonce: {}\r\nX-Tinfoil-Usage-Metrics: 1000000\r\nContent-Length: {}\r\n\r\n",hex::encode(NONCE),frame.len()).as_bytes()).await.unwrap();
        socket.write_all(&frame).await.unwrap();
    });
    let mut handle = fixture(local(addr, &key));
    assert!(matches!(
        bounded(handle.next()).await.unwrap().unwrap(),
        Event::Text(_)
    ));
    assert!(matches!(
        bounded(handle.next()).await.unwrap(),
        Err(RouteError::Response(DecodeError::Incomplete))
    ));
    assert!(bounded(handle.next()).await.is_none());
    assert_eq!(handle.delivery().await, Delivery::Failed);
    assert!(matches!(
        handle.billing().await.settlement,
        crate::accounting::Settlement::Pending
    ));
    bounded(server).await.unwrap();
}
