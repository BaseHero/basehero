//! Socket-observed tests run only in the isolated network namespace.
use crate::{
    FetchError, JobSources, Limits, Reader,
    fetch::{RawResponse, tls_config},
    resolve::{Lookup, LookupFuture},
};
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
};

struct Dns {
    answers: Mutex<VecDeque<Vec<IpAddr>>>,
    calls: AtomicUsize,
}
impl Dns {
    fn new(answers: &[&[&str]]) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(
                answers
                    .iter()
                    .map(|list| list.iter().map(|ip| ip.parse().unwrap()).collect())
                    .collect(),
            ),
            calls: AtomicUsize::new(0),
        })
    }
}
impl Lookup for Dns {
    fn lookup(&self, _: String) -> LookupFuture {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut answers = self.answers.lock().unwrap();
        let next = if answers.len() > 1 {
            answers.pop_front().unwrap()
        } else {
            answers.front().cloned().unwrap_or_default()
        };
        Box::pin(async move { Ok(next) })
    }
}

#[derive(Default)]
struct Seen {
    connections: usize,
    requests: Vec<String>,
    sni: Vec<String>,
}
struct Server {
    addr: SocketAddr,
    seen: Arc<Mutex<Seen>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start(
        ip: &str,
        port: u16,
        tls: Option<rustls::ServerConfig>,
        reply: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static,
    ) -> Self {
        assert_eq!(std::env::var("PUBLIC_WEB_NETNS").as_deref(), Ok("1"));
        let listener = TcpListener::bind((ip, port)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let (log, reply, tls) = (seen.clone(), Arc::new(reply), tls.map(Arc::new));
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                log.lock().unwrap().connections += 1;
                let (log, reply, tls) = (log.clone(), reply.clone(), tls.clone());
                tokio::spawn(async move {
                    if let Some(config) = tls {
                        let acceptor = tokio_rustls::LazyConfigAcceptor::new(
                            rustls::server::Acceptor::default(),
                            stream,
                        );
                        if let Ok(start) = acceptor.await {
                            log.lock()
                                .unwrap()
                                .sni
                                .push(start.client_hello().server_name().unwrap_or("").to_owned());
                            if let Ok(stream) = start.into_stream(config).await {
                                respond(stream, log, reply).await;
                            }
                        }
                    } else {
                        respond(stream, log, reply).await;
                    }
                });
            }
        });
        Self { addr, seen, task }
    }
    fn count(&self) -> usize {
        self.seen.lock().unwrap().connections
    }
    fn url(&self, path: &str) -> String {
        format!("http://public.example:{}{path}", self.addr.port())
    }
}
type Reply = Arc<dyn Fn(&str) -> Vec<u8> + Send + Sync>;
async fn respond(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    log: Arc<Mutex<Seen>>,
    reply: Reply,
) {
    let Some(request) = read_request(&mut stream).await else {
        return;
    };
    log.lock().unwrap().requests.push(request.clone());
    let bytes = reply(&request);
    let _ = stream.write_all(&bytes).await;
    let _ = stream.shutdown().await;
}
async fn read_request(stream: &mut (impl AsyncRead + Unpin)) -> Option<String> {
    let mut head = Vec::new();
    let mut buf = [0; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        head.extend_from_slice(&buf[..n]);
        if head.len() > 16384 {
            return None;
        }
    }
    let header_end = head.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let headers = String::from_utf8_lossy(&head[..header_end]);
    let length: usize = headers
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")?
                .trim()
                .parse()
                .ok()
        })
        .unwrap_or(0);
    if length > 16384 {
        return None;
    }
    while head.len() < header_end + length {
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        head.extend_from_slice(&buf[..n]);
    }
    String::from_utf8(head).ok()
}
fn response(status: u16, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
fn reader(dns: Arc<Dns>) -> Reader {
    Reader {
        lookup: dns,
        tls: tls_config(rustls::RootCertStore::empty()).unwrap(),
        limits: Limits::default(),
    }
}
async fn fetch(reader: &Reader, url: &str) -> Result<RawResponse, FetchError> {
    let mut sources = JobSources::new();
    sources.register_typed_url(url)?;
    reader.fetch(&sources.permit(url)?).await
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn fixed_get_ignores_proxies_cookies_and_referer() {
    let proxy = Server::start("11.0.0.20", 19099, None, |_| response(500, "", b"proxy")).await;
    let server = Server::start("11.0.0.10", 0, None, |request| {
        if request.starts_with("GET /start ") {
            response(302, "Location: /end\r\nSet-Cookie: token=secret\r\n", b"")
        } else {
            response(200, "Content-Type: text/plain\r\n", b"public page")
        }
    })
    .await;
    let dns = Dns::new(&[&["11.0.0.10"]]);
    let page = fetch(&reader(dns.clone()), &server.url("/start"))
        .await
        .unwrap();
    assert_eq!(page.body, b"public page");
    assert_eq!(page.hops.len(), 2);
    assert_eq!(dns.calls.load(Ordering::SeqCst), 2);
    assert_eq!(server.count(), 2);
    assert_eq!(proxy.count(), 0);
    for request in &server.seen.lock().unwrap().requests {
        assert!(request.starts_with("GET /"));
        let lower = request.to_lowercase();
        for forbidden in [
            "authorization:",
            "cookie:",
            "referer:",
            "proxy-authorization:",
        ] {
            assert!(!lower.contains(forbidden));
        }
        assert!(lower.contains("accept: text/markdown"));
    }
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn redirects_and_rebinding_never_connect_to_private_addresses() {
    let private = Server::start("10.77.0.10", 0, None, |_| response(200, "", b"secret")).await;
    let private_port = private.addr.port();
    let metadata = Server::start("169.254.169.254", 80, None, |_| {
        response(200, "", b"metadata secret")
    })
    .await;
    for target in [
        format!("http://10.77.0.10:{private_port}/"),
        format!("http://private.example:{private_port}/"),
        format!("http://user:secret@public.example:{private_port}/"),
        "http://169.254.169.254/latest".into(),
        "file:///etc/passwd".into(),
    ] {
        let server = Server::start("11.0.0.10", 0, None, move |_| {
            response(302, &format!("Location: {target}\r\n"), b"")
        })
        .await;
        let dns = Dns::new(&[&["11.0.0.10"], &["10.77.0.10"]]);
        assert!(fetch(&reader(dns), &server.url("/")).await.is_err());
        assert_eq!(server.count(), 1);
        assert_eq!(private.count(), 0);
        assert_eq!(metadata.count(), 0);
    }
    // A rebinding bypass would reach a listener on the same port.
    let server = Server::start("11.0.0.10", private_port, None, |_| {
        response(302, "Location: /again\r\n", b"")
    })
    .await;
    let dns = Dns::new(&[&["11.0.0.10"], &["10.77.0.10"]]);
    assert!(fetch(&reader(dns.clone()), &server.url("/")).await.is_err());
    assert_eq!(dns.calls.load(Ordering::SeqCst), 2);
    assert_eq!(server.count(), 1);
    assert_eq!(private.count(), 0);
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn private_dns_and_literals_are_refused_but_mixed_dns_uses_only_public() {
    let private = Server::start("10.77.0.10", 0, None, |_| response(200, "", b"secret")).await;
    let dns = Dns::new(&[&["10.77.0.10", "::ffff:127.0.0.1", "fd00::1"]]);
    assert!(
        fetch(
            &reader(dns.clone()),
            &format!("http://private.example:{}/", private.addr.port())
        )
        .await
        .is_err()
    );
    assert_eq!(private.count(), 0);
    let before = dns.calls.load(Ordering::SeqCst);
    assert!(
        fetch(&reader(dns.clone()), "http://2130706433/")
            .await
            .is_err()
    );
    assert_eq!(dns.calls.load(Ordering::SeqCst), before);
    // Both DNS alternatives have real listeners at this exact port.
    let public = Server::start("11.0.0.10", private.addr.port(), None, |_| {
        response(200, "", b"public")
    })
    .await;
    let dns = Dns::new(&[&["10.77.0.10", "11.0.0.10"]]);
    assert_eq!(
        fetch(&reader(dns), &public.url("/")).await.unwrap().body,
        b"public"
    );
    assert_eq!(public.count(), 1);
    assert_eq!(private.count(), 0);
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn body_limits_and_compression_are_explicit() {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&vec![b'x'; 10000]).unwrap();
    let gzip = encoder.finish().unwrap();
    let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 4, 22);
    encoder.write_all(&vec![b'x'; 10000]).unwrap();
    let brotli = encoder.into_inner();
    let complete = b"Exact public source evidence.";
    let complete_gzip = gzip_bytes(complete);
    let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 4, 22);
    encoder.write_all(complete).unwrap();
    let complete_brotli = encoder.into_inner();
    let server = Server::start("11.0.0.10", 0, None, move |r| {
        if r.starts_with("GET /complete-gzip ") {
            response(200, "Content-Encoding: gzip\r\n", &complete_gzip)
        } else if r.starts_with("GET /complete-brotli ") {
            response(200, "Content-Encoding: br\r\n", &complete_brotli)
        } else if r.starts_with("GET /gzip ") {
            response(200, "Content-Encoding: gzip\r\n", &gzip)
        } else if r.starts_with("GET /brotli ") {
            response(200, "Content-Encoding: br\r\n", &brotli)
        } else if r.starts_with("GET /corrupt ") {
            response(200, "Content-Encoding: gzip\r\n", b"not-gzip")
        } else if r.starts_with("GET /unsupported ") {
            response(200, "Content-Encoding: CANARY\r\n", b"not-supported")
        } else if r.starts_with("GET /broken ") {
            b"HTTP/1.1 200 Test\r\nContent-Length: 1000\r\n\r\nshort".to_vec()
        } else {
            response(200, "", &vec![b'x'; 1000])
        }
    })
    .await;
    let mut reader = reader(Dns::new(&[&["11.0.0.10"]]));
    reader.limits.max_compressed_bytes = 128;
    reader.limits.max_decoded_bytes = 64;
    assert!(matches!(
        fetch(&reader, &server.url("/unsupported")).await,
        Err(FetchError::UnsupportedEncoding)
    ));
    for path in ["/complete-gzip", "/complete-brotli"] {
        let raw = fetch(&reader, &server.url(path)).await.unwrap();
        assert_eq!(raw.body, complete, "{path}");
        assert!(!raw.partial, "{path}");
        assert_eq!(raw.partial_reason, None);
    }
    for (path, prefix, reason) in [
        ("/gzip", vec![b'x'; 64], "decoded input limit"),
        ("/brotli", vec![b'x'; 64], "decoded input limit"),
        ("/corrupt", vec![], "incomplete compressed body"),
        ("/plain", vec![b'x'; 64], "compressed input limit"),
        ("/broken", b"short".to_vec(), "incomplete response body"),
    ] {
        let raw = fetch(&reader, &server.url(path)).await.unwrap();
        assert!(raw.partial, "{path}");
        assert_eq!(raw.body, prefix, "{path}");
        assert_eq!(raw.partial_reason.as_deref(), Some(reason), "{path}");
        assert!(raw.compressed_bytes <= 128);
    }
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn search_registers_only_exact_result_urls_and_sends_private_headers() {
    let server = Server::start("11.0.0.10", 0, None, |_| response(200, "Content-Type: application/json\r\n", br#"{"items":[{"url":"https://example.com/exact?q=1","title":"https://bad.example/title","description":"https://bad.example/snippet"}],"metadata":{}}"#)).await;
    let client = crate::search::SearchClient::test_client(
        &format!("http://public.example:{}", server.addr.port()),
        Dns::new(&[&["11.0.0.10"]]),
    );
    let mut job = JobSources::new();
    let result = client.search("raw query + secret", &mut job).await.unwrap();
    assert_eq!(result.provider(), crate::search::Provider::Ceramic);
    assert_eq!(result.hits().len(), 1);
    assert!(job.permit("https://example.com/exact?q=1").is_ok());
    assert!(matches!(
        job.source("https://example.com/exact?q=1"),
        Some(crate::provenance::UrlSource::SearchResult)
    ));
    for url in [
        "https://bad.example/title",
        "https://bad.example/snippet",
        "https://example.com/exact?q=2",
    ] {
        assert!(job.permit(url).is_err());
    }
    let seen = server.seen.lock().unwrap();
    assert_eq!(seen.requests.len(), 1);
    let req = &seen.requests[0];
    assert!(req.starts_with("POST /client/v4/accounts/account/ai/websearch/ HTTP/1.1"));
    assert!(
        req.to_ascii_lowercase()
            .contains("cf-aig-collect-log: false")
    );
    assert!(
        req.to_ascii_lowercase()
            .contains("authorization: bearer test-token")
    );
    assert!(req.contains("\"query\":\"raw query + secret\""));
    assert!(req.contains("\"provider\":\"ceramic\""));
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn search_falls_back_once_and_reports_both_failures_without_provenance() {
    let server = Server::start("11.0.0.10", 0, None, |req| {
        if req.contains("\"provider\":\"ceramic\"") {
            response(503, "", b"private failure")
        } else {
            response(
                200,
                "",
                br#"{"items":[{"url":"https://example.com/linkup"}]}"#,
            )
        }
    })
    .await;
    let client = crate::search::SearchClient::test_client(
        &format!("http://public.example:{}", server.addr.port()),
        Dns::new(&[&["11.0.0.10"]]),
    );
    let mut job = JobSources::new();
    assert_eq!(
        client
            .search("unaltered", &mut job)
            .await
            .unwrap()
            .provider(),
        crate::search::Provider::Linkup
    );
    assert!(job.permit("https://example.com/linkup").is_ok());
    let requests = server.seen.lock().unwrap().requests.clone();
    assert_eq!(requests.len(), 2);
    for req in requests {
        let lower = req.to_ascii_lowercase();
        assert!(lower.contains("cf-aig-collect-log: false"));
        assert!(lower.contains("authorization: bearer test-token"));
        assert!(req.contains("\"query\":\"unaltered\""));
    }
    let failed = Server::start("11.0.0.10", 0, None, |_| {
        response(503, "", b"CANARY provider secret")
    })
    .await;
    let client = crate::search::SearchClient::test_client(
        &format!("http://public.example:{}", failed.addr.port()),
        Dns::new(&[&["11.0.0.10"]]),
    );
    let error = client.search("unaltered", &mut job).await.err().unwrap();
    assert_eq!(
        error,
        crate::search::SearchError::Failed {
            ceramic: crate::search::SearchFailure::HttpStatus,
            linkup: crate::search::SearchFailure::HttpStatus
        }
    );
    assert!(!format!("{error:?}").contains("CANARY"));
    assert_eq!(failed.count(), 2);
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn search_rejects_bad_responses_atomically() {
    use crate::search::{SearchError, SearchFailure};
    for (name, body, expected) in [
        ("malformed", b"not json".to_vec(), SearchFailure::Malformed),
        ("empty", br#"{"items":[]}"#.to_vec(), SearchFailure::Empty),
        ("missing", br#"{"metadata":{}}"#.to_vec(), SearchFailure::Malformed),
        ("oversized", vec![b'x'; 256 * 1024 + 1], SearchFailure::Oversized),
        ("credentials", br#"{"items":[{"url":"https://example.com/good"},{"url":"https://u:pw@example.com/bad"}]}"#.to_vec(), SearchFailure::UnsafeUrl),
        ("private", br#"{"items":[{"url":"http://127.0.0.1/private"}]}"#.to_vec(), SearchFailure::UnsafeUrl),
        ("scheme", br#"{"items":[{"url":"file:///secret"}]}"#.to_vec(), SearchFailure::UnsafeUrl),
    ] {
        let server = Server::start("11.0.0.10", 0, None, move |_| response(200, "", &body)).await;
        let client = crate::search::SearchClient::test_client(&format!("http://public.example:{}", server.addr.port()), Dns::new(&[&["11.0.0.10"]]));
        let mut job = JobSources::new();
        assert_eq!(client.search("q", &mut job).await.err(), Some(SearchError::Failed { ceramic: expected, linkup: expected }), "{name}");
        assert!(job.permit("https://example.com/good").is_err(), "{name}");
        assert_eq!(server.count(), 2, "{name}");
    }
    let broken = Server::start("11.0.0.10", 0, None, |_| {
        b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n{\"items\":[]}".to_vec()
    })
    .await;
    let client = crate::search::SearchClient::test_client(
        &format!("http://public.example:{}", broken.addr.port()),
        Dns::new(&[&["11.0.0.10"]]),
    );
    assert_eq!(
        client.search("q", &mut JobSources::new()).await.err(),
        Some(SearchError::Failed {
            ceramic: SearchFailure::Partial,
            linkup: SearchFailure::Partial
        })
    );
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn dropping_search_future_closes_the_pending_request() {
    let listener = TcpListener::bind(("11.0.0.10", 0)).await.unwrap();
    let client = crate::search::SearchClient::test_client(
        &format!(
            "http://public.example:{}",
            listener.local_addr().unwrap().port()
        ),
        Dns::new(&[&["11.0.0.10"]]),
    );
    let mut job = JobSources::new();
    let mut pending = Box::pin(client.search("q", &mut job));
    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            accepted = listener.accept() => accepted.unwrap(),
            _ = &mut pending => panic!("search completed without a provider response"),
        }
    })
    .await
    .unwrap();
    let mut buf = [0; 2048];
    let received = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            received = socket.read(&mut buf) => received.unwrap(),
            _ = &mut pending => panic!("search completed without a provider response"),
        }
    })
    .await
    .unwrap();
    assert!(received > 0);
    drop(pending);
    assert!(job.permit("https://example.com/backup").is_err());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), socket.read(&mut buf))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn unicode_queries_reach_provider_unmodified_with_character_bounds() {
    let server = Server::start("11.0.0.10", 0, None, |_| {
        response(200, "", br#"{"items":[{"url":"https://example.com/hit"}]}"#)
    })
    .await;
    let client = crate::search::SearchClient::test_client(
        &format!("http://public.example:{}", server.addr.port()),
        Dns::new(&[&["11.0.0.10"]]),
    );
    let mut sources = JobSources::new();
    for query in ["界".repeat(400), "界".repeat(1024)] {
        assert!(client.search(&query, &mut sources).await.is_ok());
        let req = server.seen.lock().unwrap().requests.last().unwrap().clone();
        let body = req.split_once("\r\n\r\n").unwrap().1;
        let decoded: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(decoded["query"].as_str(), Some(query.as_str()));
    }
    let count = server.count();
    for query in [String::new(), "界".repeat(1025)] {
        assert!(matches!(
            client.search(&query, &mut sources).await,
            Err(crate::search::SearchError::InvalidQuery)
        ));
    }
    assert_eq!(server.count(), count);
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn search_never_follows_redirects_to_a_sentinel() {
    use crate::search::{SearchError, SearchFailure};
    let target = Server::start("11.0.0.20", 0, None, |_| {
        response(
            200,
            "",
            br#"{"items":[{"url":"https://example.com/leaked"}]}"#,
        )
    })
    .await;
    for status in [307, 308] {
        let location = format!("http://target.example:{}/redirected", target.addr.port());
        let server = Server::start("11.0.0.10", 0, None, move |_| {
            response(status, &format!("Location: {location}\r\n"), b"")
        })
        .await;
        let client = crate::search::SearchClient::test_client(
            &format!("http://public.example:{}", server.addr.port()),
            Dns::new(&[&["11.0.0.10", "11.0.0.20"]]),
        );
        let mut job = JobSources::new();
        assert_eq!(
            client.search("private query", &mut job).await.err(),
            Some(SearchError::Failed {
                ceramic: SearchFailure::HttpStatus,
                linkup: SearchFailure::HttpStatus
            })
        );
        assert_eq!(server.count(), 2);
        assert_eq!(target.count(), 0);
        assert!(job.permit("https://example.com/leaked").is_err());
    }
}

async fn stalled_search_server(linkup_healthy: bool) -> (Server, Arc<AtomicUsize>) {
    assert_eq!(std::env::var("PUBLIC_WEB_NETNS").as_deref(), Ok("1"));
    let listener = TcpListener::bind(("11.0.0.10", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let cancelled = Arc::new(AtomicUsize::new(0));
    let (log, cancellations) = (seen.clone(), cancelled.clone());
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            log.lock().unwrap().connections += 1;
            let (log, cancellations) = (log.clone(), cancellations.clone());
            tokio::spawn(async move {
                let Some(req) = read_request(&mut socket).await else {
                    return;
                };
                let is_linkup = req.contains("\"provider\":\"linkup\"");
                log.lock().unwrap().requests.push(req);
                if is_linkup && linkup_healthy {
                    let _ = socket
                        .write_all(&response(
                            200,
                            "",
                            br#"{"items":[{"url":"https://example.com/backup"}]}"#,
                        ))
                        .await;
                } else {
                    // Stay pending asynchronously until the abandoned client drops its socket.
                    let mut byte = [0];
                    if socket.read(&mut byte).await.ok() == Some(0) {
                        cancellations.fetch_add(1, Ordering::SeqCst);
                    }
                }
            });
        }
    });
    (Server { addr, seen, task }, cancelled)
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn stalled_ceramic_falls_back_and_both_stalled_fail_within_budget() {
    use crate::search::{Provider, SearchError, SearchFailure};
    for healthy in [true, false] {
        let (server, cancelled) = stalled_search_server(healthy).await;
        let client = crate::search::SearchClient::test_client_timed(
            &format!("http://public.example:{}", server.addr.port()),
            Dns::new(&[&["11.0.0.10"]]),
            Duration::from_millis(800),
            Duration::from_millis(100),
        );
        let mut job = JobSources::new();
        let outcome =
            tokio::time::timeout(Duration::from_millis(700), client.search("q", &mut job))
                .await
                .expect("bounded search");
        if healthy {
            assert_eq!(outcome.unwrap().provider(), Provider::Linkup);
            assert!(job.permit("https://example.com/backup").is_ok());
        } else {
            assert_eq!(
                outcome.err(),
                Some(SearchError::Failed {
                    ceramic: SearchFailure::Timeout,
                    linkup: SearchFailure::Timeout
                })
            );
            assert!(job.permit("https://example.com/backup").is_err());
        }
        assert_eq!(server.count(), 2);
        // Both attempts are completed or abandoned before returning, never left in flight.
        tokio::time::timeout(Duration::from_millis(500), async {
            while cancelled.load(Ordering::SeqCst) < if healthy { 1 } else { 2 } {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stalled sockets closed");
    }
}

fn gzip_bytes(body: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(body).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn concatenated_gzip_preserves_all_members_and_marks_incomplete_tail() {
    let first = b"First gzip member. ";
    let second = b"Second gzip member. ";
    let mut complete = gzip_bytes(first);
    complete.extend(gzip_bytes(second));
    // Missing later member's checksum: its decoded bytes exist but aren't complete.
    let incomplete = complete[..complete.len() - 4].to_vec();
    let server = Server::start("11.0.0.10", 0, None, move |r| {
        let body = if r.starts_with("GET /complete ") {
            &complete
        } else {
            &incomplete
        };
        response(200, "Content-Encoding: gzip\r\n", body)
    })
    .await;
    let reader = reader(Dns::new(&[&["11.0.0.10"]]));
    let all = [first.as_slice(), second.as_slice()].concat();
    let complete = fetch(&reader, &server.url("/complete")).await.unwrap();
    assert_eq!(complete.body, all);
    assert!(!complete.partial);
    assert_eq!(complete.partial_reason, None);
    let incomplete = fetch(&reader, &server.url("/incomplete")).await.unwrap();
    assert_eq!(incomplete.body, all);
    assert!(incomplete.partial);
    assert_eq!(
        incomplete.partial_reason.as_deref(),
        Some("incomplete compressed body")
    );
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn partial_reads_never_admit_a_shortened_reference_destination() {
    let prefix = b"[go][r]\n\n[r]: https://site.example/delete";
    let body = [prefix.as_slice(), b"?dry_run=true\n"].concat();
    let gzip = gzip_bytes(&body);
    let server = Server::start("11.0.0.10", 0, None, move |r| {
        if r.starts_with("GET /decode ") {
            response(
                200,
                "Content-Type: text/markdown\r\nContent-Encoding: gzip\r\n",
                &gzip,
            )
        } else if r.starts_with("GET /interrupted ") {
            let mut bytes = format!(
                "HTTP/1.1 200 Test\r\nContent-Type: text/markdown\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            bytes.extend_from_slice(prefix);
            bytes
        } else {
            response(200, "Content-Type: text/markdown\r\n", &body)
        }
    })
    .await;
    for path in ["/cap", "/decode", "/interrupted", "/complete"] {
        let mut reader = reader(Dns::new(&[&["11.0.0.10"]]));
        if path == "/cap" {
            reader.limits.max_compressed_bytes = prefix.len();
        }
        if path == "/decode" {
            reader.limits.max_decoded_bytes = prefix.len();
        }
        let mut job = JobSources::new();
        job.register_typed_url(&server.url(path)).unwrap();
        let page = job.read(&reader, &server.url(path), "now").await.unwrap();
        assert_eq!(page.input_partial, path != "/complete", "{path}");
        assert!(job.permit("https://site.example/delete").is_err(), "{path}");
        if page.input_partial {
            assert!(page.links().is_empty(), "{path}");
            assert!(
                job.permit("https://site.example/delete?dry_run=true")
                    .is_err()
            );
        } else {
            assert!(
                job.permit("https://site.example/delete?dry_run=true")
                    .is_ok()
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn redirect_limit_is_bounded_and_errors_are_content_free() {
    let server = Server::start("11.0.0.10", 0, None, |_| {
        response(302, "Location: /CANARY\r\n", b"")
    })
    .await;
    let mut reader = reader(Dns::new(&[&["11.0.0.10"]]));
    reader.limits.max_redirects = 2;
    let result = fetch(&reader, &server.url("/CANARY")).await;
    assert!(matches!(result, Err(FetchError::RedirectLimit)));
    assert_eq!(server.count(), 3);
    assert!(!format!("{:?}", result.err().unwrap()).contains("CANARY"));
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn deadline_includes_dns_and_releases_caller() {
    struct HangingDns;
    impl Lookup for HangingDns {
        fn lookup(&self, _: String) -> LookupFuture {
            Box::pin(std::future::pending::<io::Result<Vec<IpAddr>>>())
        }
    }
    let mut reader = reader(Dns::new(&[]));
    reader.lookup = Arc::new(HangingDns);
    reader.limits.total_timeout_ms = 30;
    let result = tokio::time::timeout(
        Duration::from_millis(500),
        fetch(&reader, "https://public.example/CANARY"),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(FetchError::Timeout)));
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn fetched_links_extend_only_the_reading_job_without_executing_them() {
    let server = Server::start("11.0.0.10", 0, None, |_| {
        response(
            200,
            "Content-Type: text/markdown\r\n",
            b"[next](/next) and https://invented.example/not-a-link; [private](http://127.0.0.1/)",
        )
    })
    .await;
    let reader = reader(Dns::new(&[&["11.0.0.10"]]));
    let mut job = JobSources::new();
    job.register_typed_url(&server.url("/start")).unwrap();
    let page = job
        .read(&reader, &server.url("/start"), "2026-10-14T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(page.fetched_at, "2026-10-14T00:00:00Z");
    assert!(job.permit(&server.url("/next")).is_ok());
    assert!(
        matches!(job.source(&server.url("/next")), Some(crate::provenance::UrlSource::FetchedPage { url }) if url == &server.url("/start"))
    );
    assert!(JobSources::new().permit(&server.url("/next")).is_err());
    assert!(job.permit("https://invented.example/not-a-link").is_err());
    assert!(job.permit("http://127.0.0.1/").is_err());
    assert_eq!(server.count(), 1);
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn evidence_reads_freeze_revisions_and_do_not_promote_search_snippets() {
    use crate::evidence::{Evidence, QuoteError};
    let revision = Arc::new(AtomicUsize::new(0));
    let current = revision.clone();
    let server = Server::start("11.0.0.10", 0, None, move |_| {
        let text = if current.load(Ordering::SeqCst) == 0 { "first revision" } else { "second revision" };
        let html = format!("<html><head><title>Field notes</title></head><body><article><p>{}</p></article></body></html>", format!("{text} carries detailed observations about this field study and its methods. ").repeat(12));
        response(200, "Content-Type: text/html\r\n", html.as_bytes())
    }).await;
    let url = server.url("/report");
    let reader = reader(Dns::new(&[&["11.0.0.10"]]));
    let mut job = JobSources::new();
    job.register_search_url(&url).unwrap();
    let mut evidence = Evidence::new(2);
    // A search hit's title/description and URL permit are not a completed read.
    assert_eq!(evidence.len(), 0);
    assert_eq!(
        evidence.validate_quote(0, "first revision").err(),
        Some(QuoteError::UnknownSource)
    );
    let old = evidence
        .read(&mut job, &reader, &url, "2026-10-14T12:00Z")
        .await
        .unwrap();
    assert_eq!(old.index(), 0);
    assert_eq!(evidence.source(0).unwrap().title(), Some("Field notes"));
    assert_eq!(evidence.source(0).unwrap().requested_url(), url);
    assert_eq!(evidence.source(0).unwrap().final_url(), url);
    assert_eq!(
        evidence.source(0).unwrap().fetched_at(),
        "2026-10-14T12:00Z"
    );
    let old_quote = evidence.validate_quote(0, "first revision").unwrap();
    assert_eq!(old_quote.quote(), "first revision");
    assert_eq!(old_quote.source().id(), old);
    revision.store(1, Ordering::SeqCst);
    let new = evidence
        .read(&mut job, &reader, &url, "2026-10-14T13:00Z")
        .await
        .unwrap();
    assert_eq!(new.index(), 1);
    let old_quote = evidence.validate_quote(0, "first revision").unwrap();
    assert_eq!(
        old_quote.source().markdown(),
        evidence.source(0).unwrap().markdown()
    );
    assert!(!old_quote.source().markdown().contains("second revision"));
    assert_eq!(
        evidence.validate_quote(0, "second revision").err(),
        Some(QuoteError::MissingQuote)
    );
    assert_eq!(
        evidence.validate_quote(1, "first revision").err(),
        Some(QuoteError::MissingQuote)
    );
    assert!(evidence.validate_quote(1, "second revision").is_ok());
    assert_eq!(
        evidence.validate_quote(7, "first revision").err(),
        Some(QuoteError::UnknownSource)
    );
    assert_eq!(
        evidence.validate_quote(0, "  ").err(),
        Some(QuoteError::EmptyQuote)
    );
    assert_eq!(
        evidence.validate_quote(0, "fabricated").err(),
        Some(QuoteError::MissingQuote)
    );
    assert!(job.permit(&url).is_ok());
    assert_eq!(server.count(), 2);
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn evidence_capacity_and_failed_or_dropped_reads_do_not_insert() {
    use crate::evidence::{CaptureError, Evidence};
    let server = Server::start("11.0.0.10", 0, None, |request| {
        if request.starts_with("GET /bad ") {
            response(302, "Location: http://127.0.0.1/private\r\n", b"")
        } else {
            response(200, "Content-Type: text/markdown\r\n", b"a useful page with enough words for the reader to accept this article as evidence of the exact text present here today and no other facts")
        }
    }).await;
    let url = server.url("/read");
    let reader = reader(Dns::new(&[&["11.0.0.10"]]));
    let mut job = JobSources::new();
    job.register_search_url(&url).unwrap();
    let mut none = Evidence::new(0);
    assert!(matches!(
        none.read(&mut job, &reader, &url, "now").await,
        Err(CaptureError::Capacity)
    ));
    assert_eq!(server.count(), 0);
    assert_eq!(none.len(), 0);
    let mut evidence = Evidence::new(2);
    assert!(matches!(
        evidence
            .read(&mut job, &reader, "https://not-registered.example/", "now")
            .await,
        Err(CaptureError::Fetch(FetchError::NeedsOutsideEffect))
    ));
    assert_eq!(evidence.len(), 0);
    let bad = server.url("/bad");
    job.register_search_url(&bad).unwrap();
    assert!(matches!(
        evidence.read(&mut job, &reader, &bad, "now").await,
        Err(CaptureError::Fetch(FetchError::NonPublic))
    ));
    assert_eq!(server.count(), 1);
    assert_eq!(evidence.len(), 0);
    let pending = Box::pin(evidence.read(&mut job, &reader, &url, "now"));
    // A never-polled (dropped) read may not create evidence.
    drop(pending);
    assert_eq!(evidence.len(), 0);
    assert_eq!(server.count(), 1);
    evidence.read(&mut job, &reader, &url, "now").await.unwrap();
    assert_eq!(evidence.len(), 1);
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn evidence_retains_partial_excerpt_but_rejects_unusable_pages() {
    use crate::evidence::{Evidence, QuoteError};
    use crate::extract::Verdict;
    let prose = format!(
        "observed excerpt with direct evidence and extra descriptive words about the site. {}",
        "more descriptive observations here. ".repeat(30)
    );
    let partial_body = prose.as_bytes().to_vec();
    let server = Server::start("11.0.0.10", 0, None, move |request| {
        if request.starts_with("GET /partial ") {
            let mut bytes = format!(
                "HTTP/1.1 200 Test\r\nContent-Type: text/markdown\r\nContent-Length: {}\r\n\r\n",
                partial_body.len() + 40
            )
            .into_bytes();
            bytes.extend_from_slice(&partial_body);
            bytes
        } else if request.starts_with("GET /login ") {
            response(
                200,
                "Content-Type: text/html\r\n",
                b"<title>Sign in</title><form><input type=password></form>",
            )
        } else {
            response(404, "Content-Type: text/plain\r\n", b"missing evidence")
        }
    })
    .await;
    let mut reader = reader(Dns::new(&[&["11.0.0.10"]]));
    reader.limits.max_output_bytes = 100;
    let mut job = JobSources::new();
    let mut evidence = Evidence::new(3);
    for path in ["/partial", "/login", "/error"] {
        job.register_typed_url(&server.url(path)).unwrap();
        evidence
            .read(&mut job, &reader, &server.url(path), "now")
            .await
            .unwrap();
    }
    let citation = evidence.validate_quote(0, "observed excerpt").unwrap();
    assert_eq!(citation.quote(), "observed excerpt");
    assert_eq!(citation.source().verdict(), Verdict::Useful);
    assert!(citation.source().input_partial());
    assert!(citation.source().output_truncated());
    assert!(citation.source().markdown().len() <= 100);
    assert_eq!(evidence.source(1).unwrap().verdict(), Verdict::Login);
    assert_eq!(evidence.source(2).unwrap().verdict(), Verdict::HttpError);
    assert_eq!(
        evidence.validate_quote(1, "Sign in").err(),
        Some(QuoteError::UnusableSource)
    );
    assert_eq!(
        evidence.validate_quote(2, "missing evidence").err(),
        Some(QuoteError::UnusableSource)
    );
}

#[tokio::test]
#[ignore = "requires netns.sh"]
async fn tls_verifies_root_and_original_host_with_hybrid_first() {
    let certified = rcgen::generate_simple_self_signed(vec!["public.example".into()]).unwrap();
    let cert = certified.cert.der().clone();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into()),
    )
    .unwrap();
    let server = Server::start("11.0.0.10", 0, Some(config), |_| {
        response(200, "", b"TLS page")
    })
    .await;
    let dns = Dns::new(&[&["11.0.0.10"]]);
    let mut reader = reader(dns);
    let url = format!("https://public.example:{}/", server.addr.port());
    assert!(fetch(&reader, &url).await.is_err());
    assert!(server.seen.lock().unwrap().requests.is_empty());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    reader.tls = tls_config(roots).unwrap();
    assert_eq!(
        reader.tls.crypto_provider().kx_groups[0].name(),
        rustls::NamedGroup::X25519MLKEM768
    );
    assert!(
        fetch(&reader, &url.replace("public.example", "wrong.example"))
            .await
            .is_err()
    );
    assert!(server.seen.lock().unwrap().requests.is_empty());
    assert_eq!(fetch(&reader, &url).await.unwrap().body, b"TLS page");
    let log = server.seen.lock().unwrap();
    assert_eq!(log.requests.len(), 1);
    assert!(log.sni.iter().any(|name| name == "public.example"));
    assert!(log.sni.iter().any(|name| name == "wrong.example"));
}
