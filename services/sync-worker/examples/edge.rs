//! Native-only edge test material, never included in the Worker module.
//! `edge fixtures <now_ms>` prints deterministic keys, events and permits
//! issued relative to the caller's clock. `edge frames <root> <base> <frame>...`
//! strictly decodes data-wire responses and verifies any receipt they carry.
#[path = "support/home_objects.rs"]
mod home_objects;
use bh_crypto::{Secret, SigningKey};
use bh_sync::permit::{self, AppendAck, LogId, LogKind, Permit, Scope};
use bh_sync::wire::Response;
use bh_sync::{BaseId, BodyObject, Commitment, EventId, Head, OpaqueEvent, Route, receipt};
use serde_json::{Map, Value, json};

const EPOCH: [u8; 32] = [0xe1; 32];
const WINDOW: u64 = permit::MAX_PERMIT_WINDOW_MS;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "odd hex");
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex"))
        .collect()
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&Secret::from_slice(&[seed; 32]).unwrap())
}
fn name(log: LogId) -> String {
    format!("{:02x}{}", log.kind as u8, hex(&log.id))
}
fn event(id: u8, body: Option<&BodyObject>, seed: u8) -> OpaqueEvent {
    let mut envelope = body.map_or_else(|| vec![seed; 32], |b| b.commitment().0.to_vec());
    envelope.extend(vec![seed; 1024 - 32]);
    OpaqueEvent::new(EventId([id; 32]), envelope).unwrap()
}
fn head(value: Head) -> Value {
    json!({ "position": value.position, "hash": hex(&value.hash.0) })
}

struct Signer {
    key: SigningKey,
    certificate: [u8; 130],
    batch: u8,
}
impl Signer {
    fn new(root: &SigningKey, seed: u8) -> Self {
        let key = key(seed);
        let certificate = permit::certify(root, key.public());
        Self {
            key,
            certificate,
            batch: 0,
        }
    }
    fn sign(&mut self, scope: Scope, issued_ms: u64) -> String {
        self.batch += 1;
        hex(&permit::sign(
            &self.key,
            &self.certificate,
            &Permit {
                scope,
                issued_ms,
                deadline_ms: issued_ms + WINDOW,
                batch: [self.batch; 16],
            },
        ))
    }
}

fn fixtures(now: u64) {
    let root = key(70);
    let mut signer = Signer::new(&root, 71);
    let mut stranger = Signer::new(&key(72), 73);
    let receipt_key = key(74);
    let receipt_cert = receipt::certify(&root, receipt_key.public());

    let genesis = event(1, None, 0x11);
    let base = LogId {
        kind: LogKind::Base,
        id: genesis.digest().0,
    };
    let b1 = BodyObject::new(vec![0xb1; 1024]).unwrap();
    let b2 = BodyObject::new(vec![0xb2; 4096]).unwrap();
    let c1 = event(2, Some(&b1), 0x21);
    let c2 = event(3, Some(&b2), 0x31);
    let b3 = BodyObject::new(vec![0xb3; 65536]).unwrap();
    let c3 = event(4, Some(&b3), 0x41);
    let b4 = BodyObject::new(vec![0xb4; 1024 * 1024]).unwrap();
    let c4 = event(5, Some(&b4), 0x51);
    let g = Commitment::order(BaseId(base.id), Head::EMPTY, &genesis, Route::Control).unwrap();
    let k1 = Commitment::order(BaseId(base.id), g.head(), &c1, Route::Content).unwrap();
    let k2 = Commitment::order(BaseId(base.id), k1.head(), &c2, Route::Content).unwrap();
    // A control ordered after c1, naming the control head (the genesis).
    let control = event(6, None, 0x61);
    let kc = Commitment::order(BaseId(base.id), k1.head(), &control, Route::Control).unwrap();
    let account_genesis = event(7, None, 0x71);
    let account = LogId {
        kind: LogKind::Account,
        id: account_genesis.digest().0,
    };
    let ag = Commitment::order(
        BaseId(account.id),
        Head::EMPTY,
        &account_genesis,
        Route::Control,
    )
    .unwrap();

    let controls = |after| Scope::ReadControls { log: base, after };
    let read = |first, last| Scope::ReadEvents {
        log: base,
        first,
        last,
    };
    let bodies = |list: &[&BodyObject]| Scope::ReadBodies {
        log: base,
        bodies: list.iter().map(|b| b.commitment()).collect(),
    };
    let stage = |body: &BodyObject| Scope::Stage {
        log: base,
        body: body.commitment(),
        len: body.bytes().len() as u32,
    };
    let append =
        |log, event: &OpaqueEvent, body: Option<&BodyObject>, epoch, after| Scope::Append {
            log,
            event: event.digest(),
            body: body.map(BodyObject::commitment),
            epoch,
            after,
        };
    let mut out: Map<String, Value> = [
        ("root", json!(hex(&root.public()))),
        ("receipt_key", json!(hex(&[74; 32]))),
        ("receipt_cert", json!(hex(&receipt_cert))),
        ("base", json!(name(base))),
        ("account", json!(name(account))),
        ("genesis", json!(hex(&genesis.encode()))),
        ("genesis_id", json!(hex(&genesis.id().0))),
        ("genesis_commitment", json!(hex(&g.encode()))),
        ("genesis_head", head(g.head())),
        ("b1", json!(hex(b1.bytes()))),
        ("b2", json!(hex(b2.bytes()))),
        ("b2_commitment", json!(hex(&b2.commitment().0))),
        ("c1", json!(hex(&c1.encode()))),
        ("c1_commitment", json!(hex(&k1.encode()))),
        ("c1_head", head(k1.head())),
        ("c2", json!(hex(&c2.encode()))),
        ("b3", json!(hex(b3.bytes()))),
        ("c3", json!(hex(&c3.encode()))),
        ("b4", json!(hex(b4.bytes()))),
        ("c4", json!(hex(&c4.encode()))),
        ("c2_head", head(k2.head())),
        ("control", json!(hex(&control.encode()))),
        ("control_id", json!(hex(&control.id().0))),
        ("control_commitment", json!(hex(&kc.encode()))),
        ("control_head", head(kc.head())),
        (
            "append_control",
            json!(signer.sign(append(base, &control, None, EPOCH, Some(g.head())), now)),
        ),
        (
            "append_removal",
            json!(signer.sign(append(base, &control, None, [0; 32], Some(g.head())), now)),
        ),
        ("read_controls_0", json!(signer.sign(controls(0), now))),
        ("read_controls_1", json!(signer.sign(controls(1), now))),
        ("account_genesis", json!(hex(&account_genesis.encode()))),
        ("account_head", head(ag.head())),
        (
            "append_genesis",
            json!(signer.sign(append(base, &genesis, None, EPOCH, Some(Head::EMPTY)), now)),
        ),
        ("stage_b1", json!(signer.sign(stage(&b1), now))),
        ("stage_b2", json!(signer.sign(stage(&b2), now))),
        ("stage_b3", json!(signer.sign(stage(&b3), now))),
        ("stage_b4", json!(signer.sign(stage(&b4), now))),
        (
            "append_c1",
            json!(signer.sign(append(base, &c1, Some(&b1), EPOCH, None), now)),
        ),
        (
            "append_c2",
            json!(signer.sign(append(base, &c2, Some(&b2), EPOCH, None), now)),
        ),
        (
            "append_c3",
            json!(signer.sign(append(base, &c3, Some(&b3), EPOCH, None), now)),
        ),
        (
            "append_c4",
            json!(signer.sign(append(base, &c4, Some(&b4), EPOCH, None), now)),
        ),
        ("read_bodies_b4", json!(signer.sign(bodies(&[&b4]), now))),
        (
            "append_account_genesis",
            json!(signer.sign(
                append(account, &account_genesis, None, [0; 32], Some(Head::EMPTY)),
                now
            )),
        ),
        ("read_1_2", json!(signer.sign(read(1, 2), now))),
        ("read_1_64", json!(signer.sign(read(1, 64), now))),
        ("read_1_65", json!(signer.sign(read(1, 65), now))),
        ("read_expired", json!(signer.sign(read(1, 2), now - WINDOW))),
        ("read_other_root", json!(stranger.sign(read(1, 2), now))),
        ("read_bodies_b1", json!(signer.sign(bodies(&[&b1]), now))),
        (
            "read_bodies_b1_b2",
            json!(signer.sign(bodies(&[&b1, &b2]), now)),
        ),
        (
            "read_bodies_b3_x64",
            json!(signer.sign(bodies(&[&b3; 64]), now)),
        ),
        (
            "subscribe",
            json!(signer.sign(Scope::Subscribe { log: base }, now)),
        ),
        (
            "subscribe_short",
            json!(signer.sign(Scope::Subscribe { log: base }, now - WINDOW + 3_000)),
        ),
        (
            "presence",
            json!(signer.sign(
                Scope::Presence {
                    log: base,
                    epoch: EPOCH
                },
                now
            )),
        ),
        (
            "presence_short",
            json!(signer.sign(
                Scope::Presence {
                    log: base,
                    epoch: EPOCH
                },
                now - WINDOW + 3_000
            )),
        ),
        (
            "presence_stale",
            json!(signer.sign(
                Scope::Presence {
                    log: base,
                    epoch: [0xe2; 32]
                },
                now
            )),
        ),
        ("epoch", json!(hex(&EPOCH))),
        (
            "subscribe_account",
            json!(signer.sign(Scope::Subscribe { log: account }, now)),
        ),
        (
            "subscribe_many",
            (1..=68u8)
                .map(|i| {
                    let log = LogId {
                        kind: LogKind::Account,
                        id: [i; 32],
                    };
                    json!(signer.sign(Scope::Subscribe { log }, now))
                })
                .collect(),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect();
    out.extend(home_objects::fixtures(account, base, |scope| {
        signer.sign(scope, now)
    }));
    println!("{}", Value::Object(out));
}

fn verified(root: &[u8; 32], base: BaseId, bytes: &[u8], head: Head) -> Value {
    match receipt::verify(root, base, bytes) {
        Ok(receipt) if receipt.head() == head => json!("verified"),
        Ok(_) => json!("head-mismatch"),
        Err(error) => json!(format!("{error:?}")),
    }
}

fn frames(root: &str, base: &str, frames: &[String]) {
    let root: [u8; 32] = unhex(root).try_into().expect("root");
    let base = BaseId(unhex(base).try_into().expect("base"));
    let decoded: Vec<Value> = frames
        .iter()
        .map(|frame| match Response::decode(&unhex(frame)) {
            Err(error) => json!({ "error": format!("{error:?}") }),
            Ok(Response::Events { id, items, receipt }) => {
                let tail = items.last().and_then(|(c, _)| Commitment::decode(c).ok()).map(|c| c.head());
                json!({
                    "type": "events", "id": id,
                    "items": items.iter().map(|(c, e)| json!({ "commitment": hex(c), "event": hex(e) })).collect::<Vec<_>>(),
                    "head": tail.map(head),
                    "receipt": receipt.map(|r| tail.map(|h| verified(&root, base, &r, h))),
                })
            },
            Ok(Response::Body {
                id,
                index,
                last,
                bytes,
            }) => json!({ "type": "body", "id": id, "index": index, "last": last, "bytes": hex(&bytes) }),
            Ok(Response::Staged { id }) => json!({ "type": "staged", "id": id }),
            Ok(Response::Presence { id, from, sealed }) => {
                json!({ "type": "presence", "id": id, "from": from, "sealed": hex(&sealed) })
            },
            Ok(Response::Peers { id, others, event, slot }) => {
                let event = ["snapshot", "joined", "left"].get(event as usize).copied();
                json!({ "type": "peers", "id": id, "others": others, "event": event, "slot": slot })
            },
            Ok(Response::HomeObjectsStored { id, prefix_digest, bundle_digest }) => json!({
                "type": "home_objects_stored", "id": id,
                "prefix_digest": hex(&prefix_digest.0), "bundle_digest": hex(&bundle_digest.0),
            }),
            Ok(Response::Refused { id, reason }) => {
                json!({ "type": "refused", "id": id, "reason": format!("{reason:?}") })
            }
            Ok(Response::Acked { id, ack }) => match AppendAck::decode(&ack) {
                Err(error) => json!({ "type": "acked", "id": id, "error": format!("{error:?}") }),
                Ok(ack) => json!({
                    "type": "acked", "id": id, "log": name(ack.log),
                    "event_id": hex(&ack.event.0), "head": head(ack.head),
                    "receipt": ack.receipt.map(|r| verified(&root, BaseId(ack.log.id), &r, ack.head)),
                }),
            },
            Ok(Response::Published { id, ack, commitment }) => match (AppendAck::decode(&ack), Commitment::decode(&commitment)) {
                (Ok(ack), Ok(ordered)) => json!({
                    "type": "published", "id": id, "log": name(ack.log),
                    "event_id": hex(&ack.event.0), "head": head(ack.head),
                    "receipt": ack.receipt.map(|r| verified(&root, BaseId(ack.log.id), &r, ack.head)),
                    "commitment": hex(&commitment), "proof_head": head(ordered.head()),
                }),
                _ => json!({ "type": "published", "id": id, "error": "invalid proof" }),
            },
            Ok(Response::Head {
                id,
                head: value,
                receipt,
            }) => json!({
                "type": "head", "id": id, "head": head(value),
                "receipt": receipt.map(|r| verified(&root, base, &r, value)),
            }),
        })
        .collect();
    println!("{}", Value::Array(decoded));
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("fixtures") if args.len() == 2 => fixtures(args[1].parse().expect("now_ms")),
        Some("frames") if args.len() >= 3 => frames(&args[1], &args[2], &args[3..]),
        _ => panic!("usage: edge fixtures <now_ms> | edge frames <root> <base> <frame>..."),
    }
}
