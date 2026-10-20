//! Real local data socket + the same synthetic device-side channel helper as
//! the authorization service's tests. No production client shortcut or fake edge.
#[path = "../tests/support/device.rs"]
mod device_channel;
#[path = "support/home_probe.rs"]
mod home_probe;

use bh_account::{
    AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount,
    crypto::KemKey,
    device_auth::{self, Context},
};
use bh_authz::proto::{FromService, ToService, Want, account_log_id, account_log_wrap};
use bh_confidential_policy::{Policy, Snapshot};
use bh_crypto::{Secret, SigningKey};
use bh_sync::{
    BaseId, Commitment, Head, Route,
    permit::{self, LogId, LogKind, Permit, Scope},
    wire::{Request, Response},
};
use futures_util::{SinkExt, StreamExt};
use std::{
    fs,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};

fn key(path: &Path) -> SigningKey {
    let seed = hex::decode(fs::read_to_string(path).unwrap()).unwrap();
    SigningKey::from_seed(&Secret::from_slice(&seed).unwrap())
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn socket_url(edge: &str, path: &str) -> String {
    format!("{}{path}", edge.replacen("http://", "ws://", 1))
}
fn sign(root: &Path, scope: Scope) -> Vec<u8> {
    let keys = root.join("keys");
    let cert: [u8; 130] = hex::decode(fs::read_to_string(keys.join("permit.cert")).unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let issued = now();
    permit::sign(
        &key(&keys.join("permit.seed")),
        &cert,
        &Permit {
            scope,
            issued_ms: issued,
            deadline_ms: issued + 30_000,
            batch: bh_crypto::random(),
        },
    )
}
async fn data(edge: &str, request: Request) -> Response {
    let (mut ws, upgrade) = connect_async(socket_url(edge, "/v1/data")).await.unwrap();
    assert_eq!(upgrade.status(), 101, "data WebSocket upgrade");
    ws.send(Message::Binary(request.encode().unwrap().into()))
        .await
        .unwrap();
    let Message::Binary(frame) = ws.next().await.unwrap().unwrap() else {
        panic!("data response is binary")
    };
    Response::decode(&frame).unwrap()
}
// Test fixture only: replace the on-disk policy with a valid, expired one.
// Save the exact signed bytes as the device's persisted policy snapshot.
fn expire_policy(dir: &Path) {
    let keys = dir.join("keys");
    let app = key(&keys.join("app-root.seed"));
    let path = keys.join("policy.json");
    let mut policy: Policy = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let seconds = now() / 1000;
    policy.issued_at = seconds - 3600;
    policy.expires_at = seconds - 120;
    let bytes = serde_json::to_vec(&policy).unwrap();
    let signature =
        hex::encode(app.sign(&[b"basehero.confidential-policy.v1\0".as_slice(), &bytes].concat()));
    fs::write(&path, &bytes).unwrap();
    fs::write(keys.join("policy.sig"), &signature).unwrap();
    fs::write(keys.join("prior-policy.json"), bytes).unwrap();
    fs::write(keys.join("prior-policy.sig"), signature).unwrap();
    assert!(policy.expires_at < seconds);
}
fn state(path: &Path) -> i64 {
    if !path.exists() {
        return 0;
    }
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row("SELECT count(*) FROM accounts", [], |r| r.get(0))
        .unwrap()
}
async fn run(phase: &str, dir: &Path) {
    let env = fs::read_to_string(dir.join("env")).unwrap();
    let edge = env
        .lines()
        .find_map(|line| line.strip_prefix("LOCAL_STACK_HOST_EDGE_URL="))
        .unwrap();
    let keys = dir.join("keys");
    let app = key(&keys.join("app-root.seed"));
    let genesis_path = keys.join("probe-genesis");
    let ordinary_path = keys.join("probe-ordinary.seed");
    let device_path = keys.join("probe-device.id");
    let (genesis, ordinary, device_id) = if phase == "first" {
        assert_eq!(state(&dir.join("authz.db")), 0);
        let ordinary_seed: [u8; 32] = bh_crypto::random();
        fs::write(&ordinary_path, hex::encode(ordinary_seed)).unwrap();
        let ordinary = key(&ordinary_path);
        let control = SigningKey::generate();
        let device = DevicePublicKeys::new(
            ordinary.public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        let recovery =
            RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public());
        let draft = AccountEvent::genesis(device.clone(), recovery);
        let genesis = draft
            .finish(control.sign(draft.signing_bytes()))
            .unwrap()
            .as_bytes()
            .to_vec();
        fs::write(&genesis_path, &genesis).unwrap();
        fs::write(&device_path, hex::encode(device.id().0)).unwrap();
        (genesis, ordinary, device.id())
    } else {
        assert_eq!(phase, "again");
        assert_eq!(
            state(&dir.join("authz.db")),
            1,
            "authorization state survived restart"
        );
        (
            fs::read(&genesis_path).unwrap(),
            key(&ordinary_path),
            bh_account::DeviceId(
                hex::decode(fs::read_to_string(&device_path).unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
        )
    };
    let account = AccountId::of_genesis(&AccountEvent::decode(&genesis).unwrap()).unwrap();
    let view = VerifiedAccount::from_genesis(account, &genesis).unwrap();
    let wrapped = account_log_wrap(&genesis, None).unwrap();
    let log = LogId {
        kind: LogKind::Account,
        id: account_log_id(&genesis).unwrap(),
    };
    if phase == "first" {
        let permit = sign(
            dir,
            Scope::Append {
                log,
                event: wrapped.digest(),
                body: None,
                epoch: [0; 32],
                after: Some(Head::EMPTY),
            },
        );
        assert!(matches!(
            data(
                edge,
                Request::Append {
                    id: 1,
                    permit,
                    event: wrapped.encode()
                }
            )
            .await,
            Response::Acked { id: 1, .. }
        ));
    }
    let read = |permit| Request::Read { id: 2, permit };
    let read_scope = || Scope::ReadEvents {
        log,
        first: 1,
        last: 1,
    };
    // Every account-log event, its genesis included, is a control.
    let expected = Commitment::order(BaseId(log.id), Head::EMPTY, &wrapped, Route::Control)
        .unwrap()
        .encode();
    assert!(
        matches!(data(edge, read(sign(dir, read_scope()))).await, Response::Events { id: 2, items, receipt: None } if items.len() == 1 && items[0].1 == wrapped.encode() && items[0].0 == expected),
        "persisted account log and head"
    );

    let old_policy = if phase == "again" {
        let payload = fs::read(keys.join("prior-policy.json")).unwrap();
        let signature = hex::decode(fs::read_to_string(keys.join("prior-policy.sig")).unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        Some(Snapshot {
            root: app.public(),
            payload,
            signature,
        })
    } else {
        None
    };
    let (mut ws, mut channel) =
        device_channel::open_with_snapshot(&socket_url(edge, "/v1/authz"), &app, old_policy).await;
    let FromService::Challenge { challenge } = device_channel::receive(&mut ws, &mut channel).await
    else {
        panic!("channel challenge")
    };
    let request = device_auth::prepare(
        &view,
        device_id,
        Context {
            channel_binding: channel.binding().unwrap(),
            challenge,
        },
    )
    .unwrap();
    let signature = ordinary.sign(request.message());
    let proof = *request.finish(signature).unwrap().as_bytes();
    assert!(
        matches!(device_channel::ask(&mut ws, &mut channel, ToService::Authenticate { proof: Box::new(proof), account, device: device_id, genesis: genesis.clone() }).await,
        FromService::Authenticated { account_head } if account_head == view.head()),
        "real attested authorization"
    );
    let FromService::Permits { mut items } = device_channel::ask(
        &mut ws,
        &mut channel,
        ToService::Permits {
            items: vec![Want::ReadEvents {
                log,
                first: 1,
                last: 1,
            }],
        },
    )
    .await
    else {
        panic!("authorization read permit")
    };
    let permit = items.remove(0).unwrap();
    assert!(
        matches!(data(edge, read(permit)).await, Response::Events { items, receipt: None, .. } if items.len() == 1 && items[0].1 == wrapped.encode() && items[0].0 == expected),
        "service-issued read through edge"
    );
    assert_eq!(state(&dir.join("authz.db")), 1);
    println!("{phase}: data upgrade, synthetic channel, authorized read and persisted log OK");
}
#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let phase = args.next().expect("first|again");
    let dir = args.next().expect("stack directory");
    if phase == "expire-policy" {
        expire_policy(Path::new(&dir));
        return;
    }
    if phase == "home-verify" {
        home_probe::verify_readback(Path::new(&dir));
        return;
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        if phase.starts_with("home-") {
            home_probe::run(&phase, Path::new(&dir)).await;
        } else {
            run(&phase, Path::new(&dir)).await;
        }
    })
    .await
    .expect("local stack timed out");
}
