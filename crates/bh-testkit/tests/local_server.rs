use std::time::{Duration, Instant};

use bh_testkit::{DelayProxy, LocalServer};

#[tokio::test]
async fn local_server_answers_health() {
    let s = LocalServer::shared();
    let r: serde_json::Value = reqwest::Client::new()
        .get(s.url().join("/v1/health").unwrap())
        .header("BH-Protocol", "1")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r, serde_json::json!({ "ok": true, "protocol": 1 }));
}

#[tokio::test]
async fn requests_without_protocol_header_need_update() {
    let s = LocalServer::shared();
    let r = reqwest::Client::new()
        .get(s.url().join("/v1/health").unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 426);
    assert_eq!(r.headers()["BH-Protocol"], "1");
    assert_eq!(
        r.json::<serde_json::Value>().await.unwrap()["error"],
        "needs_update"
    );
}

#[tokio::test]
async fn delay_proxy_adds_round_trip() {
    let s = LocalServer::shared();
    let p = DelayProxy::start(s.url(), Duration::from_millis(100));
    let t = Instant::now();
    reqwest::Client::new()
        .get(p.url().join("/v1/health").unwrap())
        .header("BH-Protocol", "1")
        .send()
        .await
        .unwrap();
    assert!(t.elapsed() >= Duration::from_millis(100));
}

#[tokio::test]
async fn separate_servers_have_separate_ports_and_storage_and_restart_in_place() {
    let mut first = LocalServer::start_with_vars(&[("EXTRA", "some=value")]);
    let second = LocalServer::start();
    assert_ne!(first.url(), second.url());
    assert_ne!(first.persist_dir(), second.persist_dir());
    let url = first.url();
    let persist = first.persist_dir().to_path_buf();
    first.restart();
    assert_eq!(first.url(), url);
    assert_eq!(first.persist_dir(), persist);
    let r = reqwest::Client::new()
        .get(first.url().join("/v1/health").unwrap())
        .header("BH-Protocol", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}
