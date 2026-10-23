//! Smoke tests against the running local stack (`scripts/local-stack.sh
//! up`): a freshly signed-up device registers its own base, publishes and
//! receives its own echoes back, and completes its setup at its account home
//! through the real Worker, log object, body store and authorization
//! service; and a second device with its own keys pairs by the QR text over
//! the real relay, bootstraps the base and writes a note the first device
//! receives. Attestation is the labelled synthetic one. Needs the stack, so
//! they are ignored by default:
//!
//! ```sh
//! LOCAL_STACK_DIR=… cargo test -p bh-sync-client-tests --features synthetic-attestation \
//!   --test local_stack -- --ignored --test-threads 1
//! ```
//!
//! The restart test stops and starts the whole stack itself;
//! `tests/sync-client/home-stack.test.sh` runs it on a fresh stack.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_authz::proto::{FromService, ToService, Want};
use bh_sync::{
    BodyObject, Commitment, OpaqueEvent, receipt, referenced_body,
    wire::{Request, Response},
};
use bh_sync_client::{
    Appraisal, Client, Endpoint, SyncStatus, bootstrap,
    data::DataSocket,
    pairing::{HttpRelay, JoiningPairing, ShowingPairing},
    transport::WsConnector,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::Ordering,
};
use support::{
    device::{Device, until},
    pair::Joiner,
};

async fn read(client: &Client, data: &DataSocket, want: Want) -> Response {
    let answer = client
        .authz()
        .await
        .unwrap()
        .ask(ToService::Permits { items: vec![want] })
        .await
        .unwrap();
    let FromService::Permits { items } = answer else {
        panic!("read permits")
    };
    let permit = items.into_iter().next().unwrap().unwrap();
    data.ask(|id| Request::Read { id, permit }).await.unwrap()
}

struct Fetched {
    items: Vec<(Vec<u8>, Vec<u8>)>,
    receipt: [u8; receipt::RECEIPT_LEN],
}

async fn fetch(
    client: &Client,
    data: &DataSocket,
    device: &Device,
    first: u64,
    last: u64,
) -> Fetched {
    let Response::Events { items, receipt, .. } = read(
        client,
        data,
        Want::ReadEvents {
            log: device.log(),
            first,
            last,
        },
    )
    .await
    else {
        panic!("events")
    };
    for (_, descriptor) in &items {
        let digest = referenced_body(&OpaqueEvent::decode(descriptor).unwrap()).unwrap();
        let Response::Body {
            index: 0,
            last: true,
            bytes,
            ..
        } = read(
            client,
            data,
            Want::ReadBodies {
                log: device.log(),
                bodies: vec![digest],
            },
        )
        .await
        else {
            panic!("complete body")
        };
        assert_eq!(BodyObject::new(bytes).unwrap().commitment(), digest);
    }
    Fetched {
        items,
        receipt: receipt.expect("exact returned tail receipt"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs scripts/local-stack.sh up and LOCAL_STACK_DIR"]
async fn historical_read_receipts_commit_bounded_batches_and_resume() {
    let dir = PathBuf::from(std::env::var("LOCAL_STACK_DIR").expect("LOCAL_STACK_DIR"));
    let device = Device::new();
    let endpoint = endpoint(&dir);
    let root = endpoint.hosting_root;
    let connector = WsConnector::new(&endpoint.edge_url);
    let (client, _) = device.start_on(endpoint);
    let ids: Vec<_> = (0..129)
        .map(|_| device.new_note("bounded read fixture").1)
        .collect();
    client.wake();
    until(90, "all 129 notes ordered", || {
        ids.iter().all(|id| device.acked(*id).is_some())
    })
    .await;
    assert_eq!(
        ids.iter().filter_map(|id| device.acked(*id)).max(),
        Some(130)
    );
    // The client's receiver applies the 129 echoes in bounded batches from
    // stored progress, each with the receipt for the head it reached.
    until(90, "every echo accepted", || {
        device.progress().position == 130 && device.pending() == 0
    })
    .await;
    let stored = device.progress().receipt.expect("verified receipt");
    assert_eq!(
        receipt::verify(&root, device.base, &stored)
            .unwrap()
            .head()
            .position,
        130
    );
    // Historical and short reads still carry the receipt for exactly their
    // returned tail, not the current head.
    let data = DataSocket::open(connector.as_ref()).await.unwrap();
    for (first, last, reached) in [(2, 65, 65), (66, 129, 129), (130, 193, 130)] {
        let fetched = fetch(&client, &data, &device, first, last).await;
        let proven = receipt::verify(&root, device.base, &fetched.receipt)
            .unwrap()
            .head();
        assert_eq!(proven.position, reached);
        assert_eq!(
            Commitment::decode(&fetched.items.last().unwrap().0)
                .unwrap()
                .head(),
            proven
        );
    }
    let Response::Events { items, receipt, .. } = read(
        &client,
        &data,
        Want::ReadEvents {
            log: device.log(),
            first: 131,
            last: 194,
        },
    )
    .await
    else {
        panic!("empty read")
    };
    assert!(items.is_empty());
    assert_eq!(receipt, None);
    let Response::Events { items, receipt, .. } = read(
        &client,
        &data,
        Want::ReadEvents {
            log: device.account_log,
            first: 1,
            last: 64,
        },
    )
    .await
    else {
        panic!("account read")
    };
    assert_eq!(items.len(), 3);
    assert_eq!(receipt, None);
    println!(
        "real workerd exact receipts: client committed 130 from stored progress; historical 65 / 129 / 130; empty/account None"
    );
    client.shutdown().await;
}

fn unhex<const N: usize>(text: &str) -> [u8; N] {
    let text = text.trim();
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

fn endpoint(dir: &Path) -> Endpoint {
    let env = fs::read_to_string(dir.join("env")).expect("the local stack is up");
    let value = |key: &str| {
        env.lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("{key} in the stack's env"))
            .to_string()
    };
    let keys = dir.join("keys");
    Endpoint {
        edge_url: value("LOCAL_STACK_HOST_EDGE_URL"),
        hosting_root: unhex(&value("LOCAL_STACK_HOSTING_ROOT")),
        app_root: unhex(&value("LOCAL_STACK_APP_ROOT")),
        policy: fs::read(value("LOCAL_STACK_POLICY")).unwrap(),
        policy_signature: unhex::<64>(&fs::read_to_string(keys.join("policy.sig")).unwrap())
            .to_vec(),
        limits: bh_confidential_policy::Limits {
            max_lifetime_secs: 86_400,
            max_uncertainty_secs: 0,
        },
        build_floor: 1,
        appraisal: Appraisal::Synthetic,
        device_clock: std::sync::Arc::new(bh_sync_client::SystemDeviceClock),
        recovery_key: bh_sync::evidence::RecoveryKeyCertificate::decode(&unhex::<1314>(&value(
            "LOCAL_STACK_RECOVERY_KEY",
        )))
        .unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs scripts/local-stack.sh up and LOCAL_STACK_DIR"]
async fn a_new_account_registers_and_publishes_through_the_local_stack() {
    let dir = PathBuf::from(std::env::var("LOCAL_STACK_DIR").expect("LOCAL_STACK_DIR"));
    let device = Device::new();
    let (client, mut status) = device.start_on(endpoint(&dir));
    let (writer, id) = device.new_note("hello from the local stack");
    client.wake();
    until(60, "registered", || {
        device.registered() && device.progress().position >= 1
    })
    .await;
    until(60, "acked", || device.acked(id).is_some()).await;
    // Its own echo is verified, applied once and retires the work.
    until(60, "accepted from its echo", || {
        device.pending() == 0 && device.progress().position == device.acked(id).unwrap()
    })
    .await;
    assert_eq!(
        device.inserted(writer.note, "hello from the local stack"),
        1
    );
    until(60, "home confirmed", || !device.home_pending()).await;
    assert_eq!(
        device.signer.home_ordered.lock().unwrap().as_slice(),
        &[(device.retained().head, 0)]
    );
    until(30, "synced", || {
        *status.borrow_and_update() == SyncStatus::Synced
    })
    .await;
    client.shutdown().await;

    // A restart reads on from stored progress: same note, no repeated text.
    let position = device.progress().position;
    let (client, mut status) = device.start_on(endpoint(&dir));
    until(30, "synced again", || {
        *status.borrow_and_update() == SyncStatus::Synced
    })
    .await;
    assert_eq!(device.progress().position, position);
    assert_eq!(
        device.inserted(writer.note, "hello from the local stack"),
        1
    );
    assert!(!device.home_pending());
    println!(
        "one-owner smoke: base {:02x?}…, note acked and accepted at {}, home setup completed, restart without repeats; synthetic attestation",
        &device.base.0[..4],
        position
    );
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs scripts/local-stack.sh up and LOCAL_STACK_DIR"]
async fn a_paired_device_bootstraps_and_writes_through_the_local_stack() {
    let dir = PathBuf::from(std::env::var("LOCAL_STACK_DIR").expect("LOCAL_STACK_DIR"));
    let endpoint = endpoint(&dir);
    let connector = WsConnector::new(&endpoint.edge_url);
    let relay = HttpRelay::new(&endpoint.edge_url);
    let mac = Device::new();
    mac.signer.approve_controls.store(false, Ordering::SeqCst);
    let (mac_client, _) = mac.start_on(endpoint.clone());
    let (writer, id) = mac.new_note("written before pairing");
    mac_client.wake();
    until(60, "accepted", || {
        mac.pending() == 0 && mac.acked(id).is_some()
    })
    .await;

    // The new device scans the code's text alone; nothing else passes
    // between the two devices but the relay's sealed messages.
    let (mut showing, qr) = ShowingPairing::start(
        mac.signer.identity_account(),
        mac.signer.device_id(),
        relay.clone(),
    );
    let joiner = Joiner::new();
    let mut joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", relay.clone())
        .await
        .unwrap();
    let candidate = showing.candidate().await.unwrap();
    assert!(candidate.keys == joiner.keys);
    let (mut account, capability, _) = mac.signer.account_owner();
    let personal = account.open_personal(&capability).await.unwrap();
    showing
        .stage(&mut account, &capability, &personal, &mac.signer.approvals)
        .await
        .unwrap();
    drop(account);
    let (head, admission) = tokio::join!(
        showing.finish(&mac_client),
        joining.wait_admitted(
            &endpoint,
            connector.clone(),
            joiner.owner.clone(),
            joiner.id,
            joiner.prover(),
        )
    );
    let head = head.unwrap();
    joiner.admit(&admission.unwrap()).await;
    let fold = joiner.into_device();
    assert!(!fold.usable());
    let (progress, watching) = tokio::sync::watch::channel(bootstrap::Progress::default());
    bootstrap::run(
        endpoint.clone(),
        connector.clone(),
        fold.owner.clone(),
        fold.id,
        fold.signer.clone(),
        progress,
    )
    .await
    .unwrap();
    assert!(fold.usable());
    assert_eq!(
        fold.reopened(writer.note).digest().unwrap(),
        mac.reopened(writer.note).digest().unwrap()
    );
    let read = *watching.borrow();
    until(60, "addition copied", || {
        mac.progress().account.map(|(position, _)| position) == Some(head.position)
    })
    .await;

    fold.authorize().unwrap();
    let (fold_client, _) = fold.start_on(endpoint.clone());
    let (theirs, theirs_id) = fold.new_note("written on the joined device");
    fold_client.wake();
    until(60, "joined device accepted", || {
        fold.pending() == 0 && fold.acked(theirs_id).is_some()
    })
    .await;
    mac_client.wake();
    until(60, "first device received", || {
        mac.inserted(theirs.note, "written on the joined device") == 1
    })
    .await;
    assert_eq!(
        mac.reopened(theirs.note).digest().unwrap(),
        fold.reopened(theirs.note).digest().unwrap()
    );
    println!(
        "pairing over the local stack: second identity added at account position {}, bootstrap read {} of {} base positions, its note accepted at {} and received by the first device; synthetic attestation",
        head.position,
        read.done,
        read.total,
        fold.acked(theirs_id).unwrap()
    );
    fold_client.shutdown().await;
    mac_client.shutdown().await;
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Run one step of the stack's own tooling from the repository root.
fn run(program: &str, args: &[&str], dir: &Path) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let status = Command::new(program)
        .args(args)
        .current_dir(root)
        .env("LOCAL_STACK_DIR", dir)
        .status()
        .unwrap();
    assert!(status.success(), "{program} {args:?}");
}

/// With the stack stopped, read the account home's log object back in a new
/// workerd through the test-only fixture: exactly one stored bundle, the
/// expected one, beside the three public signup positions; then verify its
/// objects against the signed signup prefix.
fn read_back(dir: &Path) {
    run(
        "node",
        &["tests/sync-worker/home-readback.mjs", dir.to_str().unwrap()],
        dir,
    );
    let probe = Path::new(&std::env::var("CARGO_TARGET_DIR").expect("CARGO_TARGET_DIR"))
        .join("debug/examples/local_probe");
    run(
        probe.to_str().unwrap(),
        &["home-verify", dir.to_str().unwrap()],
        dir,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs scripts/local-stack.sh up and LOCAL_STACK_DIR; restarts the stack"]
async fn home_setup_survives_a_full_stack_restart() {
    let dir = PathBuf::from(std::env::var("LOCAL_STACK_DIR").expect("LOCAL_STACK_DIR"));
    let device = Device::new();
    let retained = device.retained();
    let bundle = device.retained_bundle();
    // The host stops before recording completion: the home stores the
    // objects and answers, but setup stays pending.
    device.signer.refuse_confirm.store(true, Ordering::SeqCst);
    let (client, _) = device.start_on(endpoint(&dir));
    let (_, id) = device.new_note("before the restart");
    client.wake();
    until(60, "acked", || device.acked(id).is_some()).await;
    until(60, "home answered", || {
        device.signer.confirm_attempts.load(Ordering::SeqCst) > 0
    })
    .await;
    client.shutdown().await;
    assert!(device.home_pending());
    assert!(device.signer.home_ordered.lock().unwrap().is_empty());
    let expected = format!(
        r#"{{"log":"02{}","prefix":"{}","digest":"{}","bundle":"{}","originals":[{}]}}"#,
        hex(&device.account_log.id),
        hex(&retained.head.hash),
        hex(&bh_sync::home_objects::digest(&bundle).unwrap().0),
        hex(&bundle),
        device
            .originals
            .iter()
            .take(3)
            .map(|o| format!("\"{}\"", hex(o)))
            .collect::<Vec<_>>()
            .join(","),
    );
    fs::write(dir.join("home-probe.json"), expected).unwrap();
    run("bash", &["scripts/local-stack.sh", "down"], &dir);
    read_back(&dir);
    // A cold service: its database is set aside, so all authority is
    // replayed from the account home.
    fs::rename(dir.join("authz.db"), dir.join("authz-before-restart.db")).unwrap();
    run("bash", &["scripts/local-stack.sh", "up"], &dir);
    device.signer.refuse_confirm.store(false, Ordering::SeqCst);
    let (client, _) = device.start_on(endpoint(&dir));
    until(60, "home confirmed", || !device.home_pending()).await;
    assert_eq!(
        device.signer.home_ordered.lock().unwrap().as_slice(),
        &[(retained.head, 0)]
    );
    assert!(
        device.retained() == retained,
        "retained bytes kept as they were"
    );
    client.shutdown().await;
    run("bash", &["scripts/local-stack.sh", "down"], &dir);
    read_back(&dir);
    println!(
        "home restart: stored before a full stack stop, read back from a new workerd, cold service, same bundle retried, then setup completed"
    );
}
