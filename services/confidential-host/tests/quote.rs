#![cfg(unix)]

use bh_confidential_attestation::{Evidence, Expected, Time, report_data, verify};
use bh_confidential_host::{QuoteSocket, UnverifiedQuote};
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};

const SIGNING: [u8; 32] = [1; 32];
const RECEIVING: [u8; 1216] = [2; 1216];
const NONCE: [u8; 32] = [3; 32];
const VALID: &[u8] = b"{\"quote\":\"00\",\"event_log\":\"[]\"}";
// Independently mirrors the documented aggregate wire ceiling for mutation tests.
const WIRE_LIMIT: usize = 8 * 1_048_576 + 4096;

// The peer stays connected until the acquisition has returned (or the
// independent watchdog has expired). Thus EOF cannot substitute for a bound
// or deadline. Readiness means the response has been attempted, not guessed
// from scheduling. Always release/join the server before asserting.
async fn held_response(response: Vec<u8>, budget: Duration) -> bool {
    let dir = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(dir.path().join("agent.sock")).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(conn.read(&mut request).await.unwrap() > 0);
        let _ = conn.write_all(&response).await; // early refusal can close mid-write
        let _ = ready_tx.send(());
        let _ = release_rx.await;
    });
    let mut request = tokio::spawn(async move { acquire(&socket(&dir), budget).await });
    let ready = tokio::time::timeout(Duration::from_secs(2), ready_rx).await;
    let result = if ready.is_ok() {
        Some(tokio::time::timeout(Duration::from_secs(1), &mut request).await)
    } else {
        None
    };
    if !matches!(result, Some(Ok(_))) {
        request.abort();
        let _ = request.await;
    }
    let _ = release_tx.send(());
    server.await.unwrap();
    assert!(ready.unwrap().is_ok(), "socket response never became ready");
    match result {
        Some(Ok(Ok(Err(error)))) => error.to_string() == "quote acquisition unavailable",
        Some(Ok(Ok(Ok(_)))) => false,
        Some(Ok(Err(error))) => panic!("acquisition task failed: {error}"),
        _ => false, // timeout is failure, not an acceptable refusal
    }
}

async fn serve<F>(path: &Path, reply: F) -> tokio::task::JoinHandle<Vec<u8>>
where
    F: FnOnce() -> Vec<u8> + Send + 'static,
{
    let listener = UnixListener::bind(path).unwrap();
    tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let header_end = loop {
            let mut buf = [0u8; 4096];
            let n = conn.read(&mut buf).await.unwrap();
            assert!(n > 0 && request.len() + n < 8192);
            request.extend_from_slice(&buf[..n]);
            if let Some(n) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                break n + 4;
            }
        };
        let header = std::str::from_utf8(&request[..header_end]).unwrap();
        let len: usize = header
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|n| n.parse().ok())
            })
            .unwrap();
        while request.len() < header_end + len {
            let mut buf = [0u8; 4096];
            let n = conn.read(&mut buf).await.unwrap();
            assert!(n > 0);
            request.extend_from_slice(&buf[..n]);
        }
        let _ = conn.write_all(&reply()).await;
        request
    })
}
fn http(status: &str, body: &[u8]) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}
fn socket(dir: &tempfile::TempDir) -> QuoteSocket {
    QuoteSocket::new(dir.path().join("agent.sock"))
}
async fn acquire(
    s: &QuoteSocket,
    deadline: Duration,
) -> Result<UnverifiedQuote, bh_confidential_host::Error> {
    s.get_quote(&SIGNING, &RECEIVING, &NONCE, deadline).await
}
#[tokio::test]
async fn raw_report_data_and_current_schema_are_unverified() {
    let dir = tempfile::tempdir().unwrap();
    let response =
        serde_json::json!({"quote":"00ff", "event_log":"[]", "report_data":"", "vm_config":"{}"});
    let listener = serve(&dir.path().join("agent.sock"), move || {
        http("200 OK", response.to_string().as_bytes())
    })
    .await;
    let quote = acquire(&socket(&dir), Duration::from_secs(2))
        .await
        .unwrap();
    let request = listener.await.unwrap();
    assert!(request.starts_with(b"POST /GetQuote HTTP/1.1\r\n"));
    let headers = String::from_utf8_lossy(
        &request[..request.windows(4).position(|w| w == b"\r\n\r\n").unwrap()],
    )
    .to_ascii_lowercase();
    assert!(!headers.contains("authorization:") && !headers.contains("cookie:"));
    let start = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let request_json: serde_json::Value = serde_json::from_slice(&request[start..]).unwrap();
    assert_eq!(
        request_json,
        serde_json::json!({"report_data":hex::encode(report_data(&SIGNING, &RECEIVING, &NONCE))})
    );
    assert_eq!(quote.quote(), &[0, 255]);
    assert_eq!(quote.event_log(), b"[]");
    assert!(
        verify(
            Evidence {
                quote: quote.quote(),
                collateral: b"{}",
                event_log: quote.event_log()
            },
            &Expected {
                signing: SIGNING,
                receiving: RECEIVING,
                nonce: NONCE,
                role: bh_confidential_policy::Role::Runner
            },
            Some(Time {
                earliest: 1,
                latest: 1,
                max_uncertainty_secs: 0
            })
        )
        .is_err()
    );
}
#[tokio::test]
async fn bad_status_schema_and_truncated_body_refuse() {
    for reply in [
        http("200 OK", b"{}"),
        http("200 OK", b"{\"quote\":\"00\"}"),
        http("200 OK", b"{\"event_log\":\"[]\"}"),
        http(
            "200 OK",
            b"{\"quote\":\"00\",\"quote\":\"01\",\"event_log\":\"[]\"}",
        ),
        http(
            "200 OK",
            b"{\"quote\":\"00\",\"event_log\":\"[]\",\"event_log\":\"[]\"}",
        ),
        http("200 OK", b"{\"quote\":\"zz\",\"event_log\":\"[]\"}"),
        http("200 OK", b"not json"),
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{}".to_vec(),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let listener = serve(&dir.path().join("agent.sock"), move || reply).await;
        let err = acquire(&socket(&dir), Duration::from_secs(2))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "quote acquisition unavailable");
        listener.await.unwrap();
    }
}
#[tokio::test]
async fn aggregate_streaming_limit_refuses_valid_json_before_unfinished_stream_ends() {
    // Only ignored optional public metadata makes this otherwise-valid reply
    // exceed the aggregate cap. Decoded quote/log remain well below 1 MiB.
    let json =
        serde_json::json!({"quote":"00", "event_log":"[]", "vm_config":"x".repeat(WIRE_LIMIT)})
            .to_string();
    assert!(json.len() > WIRE_LIMIT);
    let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    response.extend_from_slice(format!("{:x}\r\n", json.len()).as_bytes());
    response.extend_from_slice(json.as_bytes());
    response.extend_from_slice(b"\r\n"); // no terminating chunk: peer remains open
    assert!(held_response(response, Duration::from_secs(5)).await);
}
#[tokio::test]
async fn advertised_aggregate_limit_refuses_before_body_or_eof() {
    // The advertised size exceeds the cap; the prefix already contains
    // otherwise-valid JSON with small quote/log and ignored public metadata.
    // Hold the body open at a shorter length: without the pre-read check the
    // streaming guard cannot fire and the client must wait for remaining bytes.
    let body =
        serde_json::json!({"quote":"00", "event_log":"[]", "vm_config":"public"}).to_string();
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        WIRE_LIMIT + 1
    )
    .into_bytes();
    response.extend_from_slice(body.as_bytes());
    assert!(held_response(response, Duration::from_secs(5)).await);
}
#[tokio::test]
async fn decoded_individual_limits_refuse() {
    for body in [
        serde_json::json!({"quote": "00".repeat(1024 * 1024 + 1), "event_log":"[]"}),
        serde_json::json!({"quote":"00", "event_log":"x".repeat(1024 * 1024 + 1)}),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let listener = serve(&dir.path().join("agent.sock"), move || {
            http("200 OK", body.to_string().as_bytes())
        })
        .await;
        assert!(
            acquire(&socket(&dir), Duration::from_secs(5))
                .await
                .is_err()
        );
        listener.await.unwrap();
    }
}
#[tokio::test]
async fn unsuccessful_status_refuses_even_valid_quote_json() {
    assert!(held_response(http("500 Failed", VALID), Duration::from_secs(2)).await);
}
#[tokio::test]
async fn redirect_never_makes_a_second_local_socket_request() {
    let dir = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(dir.path().join("agent.sock")).unwrap();
    let (release_tx, mut release_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        let mut buf = [0; 4096];
        assert!(first.read(&mut buf).await.unwrap() > 0);
        first.write_all(b"HTTP/1.1 302 Found\r\nLocation: /GetQuote\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        drop(first);
        // A changed redirect policy can succeed entirely inside this UDS:
        // no TCP listener, external URL or live egress is involved.
        tokio::select! {
            second = listener.accept() => {
                let (mut second, _) = second.unwrap();
                assert!(second.read(&mut buf).await.unwrap() > 0);
                second.write_all(&http("200 OK", VALID)).await.unwrap();
                2
            }
            _ = &mut release_rx => 1,
        }
    });
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        acquire(&socket(&dir), Duration::from_secs(2)),
    )
    .await;
    let _ = release_tx.send(());
    let count = server.await.unwrap();
    assert_eq!(count, 1, "redirect issued a second Unix-socket request");
    assert!(
        matches!(result, Ok(Err(_))),
        "redirect must refuse promptly"
    );
}
#[tokio::test]
async fn deadline_covers_stalled_headers() {
    assert!(held_response(Vec::new(), Duration::from_millis(80)).await);
}
#[tokio::test]
async fn deadline_covers_stalled_body() {
    assert!(
        held_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{".to_vec(),
            Duration::from_millis(80)
        )
        .await
    );
}
#[test]
fn proxy_environment_cannot_reroute_socket() {
    if std::env::var_os("BH_PROXY_CHILD").is_some() {
        return;
    }
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("proxy_child_only")
        .arg("--nocapture")
        .env("BH_PROXY_CHILD", "1")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert!(result.status.success(), "child failed");
}
#[test]
fn proxy_child_only() {
    if std::env::var_os("BH_PROXY_CHILD").is_none() {
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let listener = serve(&dir.path().join("agent.sock"), || {
                http("200 OK", b"{\"quote\":\"00\",\"event_log\":\"[]\"}")
            })
            .await;
            assert!(acquire(&socket(&dir), Duration::from_secs(2)).await.is_ok());
            listener.await.unwrap();
        });
}
