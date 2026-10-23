//! The `bh-authz` binary in its local synthetic mode: keys and policy from
//! files, the edge's data socket for account logs, devices on `/v1/channel`.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_authz::proto::{FromService, ToService};
use bh_crypto::SigningKey;
use bh_sync::{
    permit,
    wire::{Request, Response},
};
use futures_util::{SinkExt, StreamExt};
use std::{
    io::{BufRead, BufReader, Read},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use support::{device::*, *};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

/// A data socket on which every account log is still empty.
async fn empty_edge() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/data", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                while let Some(Ok(Message::Binary(bytes))) = ws.next().await {
                    if let Ok(Request::Read { id, .. }) = Request::decode(&bytes) {
                        let empty = Response::Events {
                            id,
                            items: vec![],
                            receipt: None,
                            coverage: None,
                        };
                        let _ = ws
                            .send(Message::Binary(empty.encode().unwrap().into()))
                            .await;
                    }
                }
            });
        }
    });
    url
}

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        // Only the child this test started.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The binary in synthetic mode with fresh keys and policy, its child
/// process, the address it listens on, the hosting root and policy root.
struct Started {
    _child: Running,
    address: String,
    root: SigningKey,
    policy_root: SigningKey,
}
fn file(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path.display().to_string()
}
/// The binary in synthetic mode with fresh keys and policy under `root`.
fn command(
    dir: &tempfile::TempDir,
    edge: &str,
    root: &SigningKey,
    policy_root: &SigningKey,
) -> Command {
    let file = |name: &str, bytes: &[u8]| PathBuf::from(file(dir, name, bytes));
    let seed: [u8; 32] = bh_crypto::random();
    let key = SigningKey::from_seed(&bh_crypto::Secret::from_slice(&seed).unwrap());
    let config = channel_config(policy_root);
    let args = [
        ("--listen", "127.0.0.1:0".to_string()),
        (
            "--db",
            dir.path().join("authz.sqlite").display().to_string(),
        ),
        ("--edge", edge.to_string()),
        ("--hosting-root", hex::encode(root.public())),
        (
            "--permit-key",
            file("key", hex::encode(seed).as_bytes())
                .display()
                .to_string(),
        ),
        (
            "--permit-cert",
            file(
                "cert",
                hex::encode(permit::certify(root, key.public())).as_bytes(),
            )
            .display()
            .to_string(),
        ),
        ("--app-root", hex::encode(config.app_root)),
        (
            "--policy",
            file("policy", &config.policy).display().to_string(),
        ),
        (
            "--policy-signature",
            file("signature", hex::encode(config.policy_signature).as_bytes())
                .display()
                .to_string(),
        ),
    ];
    let mut command = Command::new(env!("CARGO_BIN_EXE_bh-authz"));
    for (flag, value) in &args {
        command.arg(flag).arg(value);
    }
    command.arg("--synthetic-attestation");
    command
}
fn start(dir: &tempfile::TempDir, edge: &str) -> Started {
    let root = SigningKey::generate();
    let policy_root = SigningKey::generate();
    let mut child = Running(
        command(dir, edge, &root, &policy_root)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stderr = BufReader::new(child.0.stderr.take().unwrap());
    let mut listening = String::new();
    while !listening.contains("listening on") {
        listening.clear();
        assert!(
            stderr.read_line(&mut listening).unwrap() > 0,
            "bh-authz exited"
        );
    }
    let address = listening.trim().rsplit(' ').next().unwrap().to_string();
    // Keep draining its log so the child never blocks on a full pipe.
    std::thread::spawn(move || {
        let mut sink = String::new();
        while stderr.read_line(&mut sink).unwrap_or(0) > 0 {
            sink.clear();
        }
    });
    Started {
        _child: child,
        address,
        root,
        policy_root,
    }
}

#[tokio::test]
async fn the_binary_serves_the_attested_channel_locally() {
    let dir = tempfile::tempdir().unwrap();
    let Started {
        _child,
        address,
        root,
        policy_root,
    } = start(&dir, &empty_edge().await);

    let device = Device::new();
    let account = Account::create(&device);
    let (mut ws, mut session) = open(&format!("ws://{address}/v1/channel"), &policy_root).await;
    let FromService::Challenge { challenge } = receive(&mut ws, &mut session).await else {
        panic!("challenge first")
    };
    let binding = session.binding().unwrap();
    let answer = ask(
        &mut ws,
        &mut session,
        authenticate_message(&account, &device, binding, challenge),
    )
    .await;
    assert!(
        matches!(answer, FromService::Authenticated { account_head } if account_head == account.verified.head()),
        "{answer:?}"
    );
    // The new account's genesis is its first control.
    let answer = ask(
        &mut ws,
        &mut session,
        ToService::SubmitControl {
            log: account.log,
            event: account.genesis.clone(),
            delivery: None,
            attachment: None,
        },
    )
    .await;
    let permit = single_permit(answer);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(permit::verify(root.public(), &permit, now).is_ok());
    // Any other path is not served.
    assert!(
        tokio_tungstenite::connect_async(format!("ws://{address}/v1/other"))
            .await
            .is_err()
    );
}

#[test]
fn a_time_config_rate_other_than_nanoseconds_is_refused() {
    // The monotonic counter counts nanoseconds; any other rate would scale
    // trusted time wrongly.
    let output = Command::new(env!("CARGO_BIN_EXE_bh-authz"))
        .args(["--time-config", "1000,100,0,1,1"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.contains("--time-config: HZ must be 1000000000"),
        "{message}"
    );
}

#[tokio::test]
async fn a_connection_that_never_upgrades_is_closed() {
    let dir = tempfile::tempdir().unwrap();
    let started = start(&dir, &empty_edge().await);
    let address = started.address.clone();
    // A TCP connection that sends nothing holds its connection slot only
    // until the upgrade timeout, then is closed.
    let start = Instant::now();
    let mut stream = std::net::TcpStream::connect(&address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut byte = [0; 1];
    assert_eq!(stream.read(&mut byte).unwrap(), 0, "closed by the service");
    let waited = start.elapsed();
    assert!(
        waited >= Duration::from_secs(4) && waited < Duration::from_secs(10),
        "{waited:?}"
    );
}

#[tokio::test]
async fn a_recovery_certificate_must_name_its_key_under_the_hosting_root() {
    use bh_crypto::{KemKey, Secret};
    use bh_sync::evidence::certify_recovery_key;
    let dir = tempfile::tempdir().unwrap();
    let edge = empty_edge().await;
    let (root, policy_root) = (SigningKey::generate(), SigningKey::generate());
    let seed: [u8; 32] = bh_crypto::random();
    let key = KemKey::from_seed(&Secret::from_slice(&seed).unwrap());
    let other = KemKey::generate();
    let key_file = file(&dir, "recovery-key", hex::encode(seed).as_bytes());
    for (named, under) in [
        (other.public(), &root),
        (key.public(), &SigningKey::generate()),
    ] {
        let certificate = certify_recovery_key(under, &named).encode();
        let output = command(&dir, &edge, &root, &policy_root)
            .args(["--recovery-key", &key_file])
            .args([
                "--recovery-cert",
                &file(&dir, "recovery-cert", hex::encode(certificate).as_bytes()),
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(
            message.contains("--recovery-cert does not name --recovery-key under --hosting-root"),
            "{message}"
        );
        // The key itself is never written out.
        assert!(!message.contains(&hex::encode(seed)));
    }
    // A key without its certificate is refused too.
    let output = command(&dir, &edge, &root, &policy_root)
        .args(["--recovery-key", &key_file])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--recovery-cert is required"));
    // With its certificate, the service starts.
    let certificate = certify_recovery_key(&root, &key.public()).encode();
    let mut child = Running(
        command(&dir, &edge, &root, &policy_root)
            .args(["--recovery-key", &key_file])
            .args([
                "--recovery-cert",
                &file(&dir, "recovery-cert", hex::encode(certificate).as_bytes()),
            ])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stderr = BufReader::new(child.0.stderr.take().unwrap());
    let mut line = String::new();
    while !line.contains("listening on") {
        line.clear();
        assert!(stderr.read_line(&mut line).unwrap() > 0, "bh-authz exited");
        assert!(!line.contains(&hex::encode(seed)));
    }
}
