//! Native-only deterministic permit fixtures for the log object tests. Never
//! included in the Worker module, which holds no signing key.
#[path = "support/home_objects.rs"]
mod home_objects;
use bh_crypto::{Secret, SigningKey, hash};
use bh_sync::permit::{self, LogId, LogKind, Permit, Scope};
use bh_sync::{BaseId, BodyObject, Commitment, EventId, Head, OpaqueEvent, Route};
use serde_json::{Map, Value, json};

/// Fixed test clock, far enough ahead that a real alarm never fires mid-test.
const TIME_START: u64 = 1_900_000_000_000;
/// One day and an hour later: staged rows from `TIME_START` are past the 24 h sweep.
const TIME_LATER: u64 = TIME_START + 25 * 3_600_000;
const EPOCH: [u8; 32] = [0xe1; 32];
const OTHER_EPOCH: [u8; 32] = [0xe2; 32];
/// The epoch a removal control leaves the log in: closed.
const CLOSED: [u8; 32] = [0; 32];
/// Controls chained after the genesis: one more than a controls read returns.
const CHAIN: u8 = 65;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&Secret::from_slice(&[seed; 32]).unwrap())
}
fn name(log: LogId) -> String {
    format!("{:02x}{}", log.kind as u8, hex(&log.id))
}
/// An event whose first 32 envelope bytes name its detached body.
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
                deadline_ms: issued_ms + permit::MAX_PERMIT_WINDOW_MS,
                batch: [self.batch; 16],
            },
        ))
    }
    fn stage(&mut self, log: LogId, body: &BodyObject, at: u64) -> String {
        let scope = Scope::Stage {
            log,
            body: body.commitment(),
            len: body.bytes().len() as u32,
        };
        self.sign(scope, at)
    }
    fn append(
        &mut self,
        log: LogId,
        event: &OpaqueEvent,
        body: Option<&BodyObject>,
        epoch: [u8; 32],
        after: Option<Head>,
        at: u64,
    ) -> String {
        let scope = Scope::Append {
            log,
            event: event.digest(),
            body: body.map(BodyObject::commitment),
            epoch,
            after,
            attached: None,
        };
        self.sign(scope, at)
    }
    /// A control append that also orders `attached`, as a rekey does.
    fn append_attached(
        &mut self,
        log: LogId,
        event: &OpaqueEvent,
        body: &BodyObject,
        attached: &BodyObject,
        after: Head,
        at: u64,
    ) -> String {
        let scope = Scope::Append {
            log,
            event: event.digest(),
            body: Some(body.commitment()),
            epoch: OTHER_EPOCH,
            after: Some(after),
            attached: Some(attached.commitment()),
        };
        self.sign(scope, at)
    }
}

fn main() {
    let root = key(60);
    let mut signer = Signer::new(&root, 61);
    let mut stranger = Signer::new(&key(62), 63);

    // Base log: a body-free control genesis whose digest names the log, then
    // content events with detached bodies.
    let genesis = event(1, None, 0x11);
    let base = LogId {
        kind: LogKind::Base,
        id: genesis.digest().0,
    };
    let b1 = BodyObject::new(vec![0xb1; 1024]).unwrap();
    let b2 = BodyObject::new(vec![0xb2; 4096]).unwrap();
    let c1 = event(2, Some(&b1), 0x21);
    let c1_other = event(2, Some(&b1), 0x2f);
    let c2 = event(4, Some(&b2), 0x41);
    let control = event(3, None, 0x31);

    let h0 = Head::EMPTY;
    let g = Commitment::order(
        BaseId(base.id),
        bh_sync::OrderState::EMPTY,
        &genesis,
        Route::Control,
    )
    .unwrap();
    let k1 = Commitment::order(BaseId(base.id), g.after(), &c1, Route::Content).unwrap();
    let k2 = Commitment::order(BaseId(base.id), k1.after(), &c2, Route::Content).unwrap();
    let k1_control =
        Commitment::order(BaseId(base.id), g.after(), &control, Route::Control).unwrap();
    // A second control naming the same predecessor, and a removal that closes
    // the epoch; each is ordered after the genesis or after c1.
    let control2 = event(5, None, 0x51);
    let removal = event(6, None, 0x61);
    let control_after_c1 =
        Commitment::order(BaseId(base.id), k1.after(), &control, Route::Control).unwrap();
    let control2_after_control = Commitment::order(
        BaseId(base.id),
        control_after_c1.after(),
        &control2,
        Route::Control,
    )
    .unwrap();
    let removal_after_c1 =
        Commitment::order(BaseId(base.id), k1.after(), &removal, Route::Control).unwrap();
    let c2_after_control = Commitment::order(
        BaseId(base.id),
        control_after_c1.after(),
        &c2,
        Route::Content,
    )
    .unwrap();

    // A rekey after the genesis: its own body, and the seal set it attaches.
    let b3 = BodyObject::new(vec![0xb3; 1024]).unwrap();
    let s1 = BodyObject::new(vec![0x51; 4096]).unwrap();
    let rekey = event(8, Some(&b3), 0x81);
    let rekey_order =
        Commitment::order(BaseId(base.id), g.after(), &rekey, Route::Control).unwrap();

    // A chain of controls directly after the genesis, each after the last.
    let mut chain = Vec::new();
    let mut chain_head = g.head();
    let mut chain_order = g.after();
    for i in 0..CHAIN {
        let link = event(100 + i, None, 0x80 + i);
        let ordered =
            Commitment::order(BaseId(base.id), chain_order, &link, Route::Control).unwrap();
        chain.push(json!({
            "event": hex(&link.encode()),
            "commitment": hex(&ordered.encode()),
            "append": signer.append(base, &link, None, EPOCH, Some(chain_head), TIME_START),
        }));
        chain_head = ordered.head();
        chain_order = ordered.after();
    }

    // Account-home log served by the same object class.
    let account_genesis = event(7, None, 0x71);
    let account = LogId {
        kind: LogKind::Account,
        id: account_genesis.digest().0,
    };
    let ag = Commitment::order(
        BaseId(account.id),
        bh_sync::OrderState::EMPTY,
        &account_genesis,
        Route::Control,
    )
    .unwrap();

    let mut out: Map<String, Value> = [
        ("root", json!(hex(&root.public()))),
        ("t0", json!(TIME_START)),
        ("t1", json!(TIME_LATER)),
        ("window", json!(permit::MAX_PERMIT_WINDOW_MS)),
        ("epoch", json!(hex(&EPOCH))),
        ("base", json!(name(base))),
        ("account", json!(name(account))),
        ("genesis", json!(hex(&genesis.encode()))),
        ("genesis_commitment", json!(hex(&g.encode()))),
        ("genesis_id", json!(hex(&g.event_id().0))),
        ("genesis_head", json!(head(g.head()))),
        (
            "append_genesis",
            json!(signer.append(base, &genesis, None, EPOCH, Some(h0), TIME_START)),
        ),
        ("b1", json!(hex(b1.bytes()))),
        ("b1_commitment", json!(hex(&b1.commitment().0))),
        ("b2", json!(hex(b2.bytes()))),
        ("b2_commitment", json!(hex(&b2.commitment().0))),
        ("stage_b1", json!(signer.stage(base, &b1, TIME_START))),
        ("stage_b1_late", json!(signer.stage(base, &b1, TIME_LATER))),
        ("stage_b2", json!(signer.stage(base, &b2, TIME_START))),
        (
            "stage_b1_other_root",
            json!(stranger.stage(base, &b1, TIME_START)),
        ),
        (
            "stage_b1_account",
            json!(signer.stage(account, &b1, TIME_START)),
        ),
        ("c1", json!(hex(&c1.encode()))),
        ("c1_id", json!(hex(&c1.publication_id(Route::Content).0))),
        ("c1_commitment", json!(hex(&k1.encode()))),
        ("c1_head", json!(head(k1.head()))),
        (
            "append_c1",
            json!(signer.append(base, &c1, Some(&b1), EPOCH, None, TIME_START)),
        ),
        (
            "append_c1_again",
            json!(signer.append(base, &c1, Some(&b1), EPOCH, None, TIME_START)),
        ),
        (
            "append_c1_late",
            json!(signer.append(base, &c1, Some(&b1), EPOCH, None, TIME_LATER)),
        ),
        (
            "append_c1_late_again",
            json!(signer.append(base, &c1, Some(&b1), EPOCH, None, TIME_LATER)),
        ),
        (
            "append_c1_other_epoch",
            json!(signer.append(base, &c1, Some(&b1), OTHER_EPOCH, None, TIME_START)),
        ),
        ("c1_other", json!(hex(&c1_other.encode()))),
        (
            "append_c1_other",
            json!(signer.append(base, &c1_other, Some(&b1), EPOCH, None, TIME_START)),
        ),
        ("c2", json!(hex(&c2.encode()))),
        ("c2_commitment", json!(hex(&k2.encode()))),
        ("c2_id", json!(hex(&k2.event_id().0))),
        ("c2_head", json!(head(k2.head()))),
        (
            "append_c2",
            json!(signer.append(base, &c2, Some(&b2), EPOCH, None, TIME_START)),
        ),
        ("control", json!(hex(&control.encode()))),
        ("control_commitment", json!(hex(&k1_control.encode()))),
        ("control_id", json!(hex(&k1_control.event_id().0))),
        (
            "append_control_stale",
            json!(signer.append(base, &control, None, EPOCH, Some(h0), TIME_START)),
        ),
        (
            "append_control",
            json!(signer.append(base, &control, None, EPOCH, Some(g.head()), TIME_START)),
        ),
        (
            "control_after_c1_commitment",
            json!(hex(&control_after_c1.encode())),
        ),
        (
            "control_after_c1_head",
            json!(head(control_after_c1.head())),
        ),
        (
            "append_control_after_log_head",
            json!(signer.append(base, &control, None, EPOCH, Some(k1.head()), TIME_START)),
        ),
        (
            "append_control_as_content",
            json!(signer.append(base, &control, None, EPOCH, None, TIME_START)),
        ),
        (
            "append_c1_as_control",
            json!(signer.append(base, &c1, Some(&b1), EPOCH, Some(k1.head()), TIME_START)),
        ),
        ("control2", json!(hex(&control2.encode()))),
        (
            "control2_after_control_commitment",
            json!(hex(&control2_after_control.encode())),
        ),
        (
            "append_control2",
            json!(signer.append(base, &control2, None, EPOCH, Some(g.head()), TIME_START)),
        ),
        (
            "append_control2_after_control",
            json!(signer.append(
                base,
                &control2,
                None,
                EPOCH,
                Some(control_after_c1.head()),
                TIME_START
            )),
        ),
        (
            "c2_after_control_commitment",
            json!(hex(&c2_after_control.encode())),
        ),
        (
            "c2_after_control_head",
            json!(head(c2_after_control.head())),
        ),
        ("removal", json!(hex(&removal.encode()))),
        ("removal_id", json!(hex(&removal_after_c1.event_id().0))),
        (
            "removal_after_c1_commitment",
            json!(hex(&removal_after_c1.encode())),
        ),
        (
            "removal_after_c1_head",
            json!(head(removal_after_c1.head())),
        ),
        (
            "append_removal",
            json!(signer.append(base, &removal, None, CLOSED, Some(g.head()), TIME_START)),
        ),
        (
            "append_c1_closed_epoch",
            json!(signer.append(base, &c1, Some(&b1), CLOSED, None, TIME_START)),
        ),
        ("chain", Value::Array(chain)),
        ("other_epoch", json!(hex(&OTHER_EPOCH))),
        ("b3", json!(hex(b3.bytes()))),
        ("b3_commitment", json!(hex(&b3.commitment().0))),
        ("s1", json!(hex(s1.bytes()))),
        ("s1_commitment", json!(hex(&s1.commitment().0))),
        ("stage_b3", json!(signer.stage(base, &b3, TIME_START))),
        ("stage_s1", json!(signer.stage(base, &s1, TIME_START))),
        ("rekey", json!(hex(&rekey.encode()))),
        ("rekey_head", json!(head(rekey_order.head()))),
        ("rekey_id", json!(hex(&rekey_order.event_id().0))),
        (
            "append_rekey",
            json!(signer.append_attached(base, &rekey, &b3, &s1, g.head(), TIME_START)),
        ),
        (
            "append_content_on_empty",
            json!(signer.append(base, &c1, Some(&b1), EPOCH, None, TIME_START)),
        ),
        ("account_genesis", json!(hex(&account_genesis.encode()))),
        ("account_genesis_commitment", json!(hex(&ag.encode()))),
        ("account_genesis_id", json!(hex(&ag.event_id().0))),
        ("account_genesis_head", json!(head(ag.head()))),
        (
            "append_account_genesis",
            json!(signer.append(
                account,
                &account_genesis,
                None,
                [0; 32],
                Some(h0),
                TIME_START
            )),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect();
    let directory = [0xa5; 1024];
    let directory_other = [0xb5; 1024];
    let entry = [0x20; 32];
    let store = |log, version, body: &[u8]| Scope::StoreDirectoryEntry {
        log,
        entry,
        version,
        body: bh_sync::Digest(hash(body)),
        len: body.len() as u32,
    };
    let directory_page: Vec<Value> = (0..66u8)
        .map(|i| {
            let entry = [i; 32];
            json!({ "entry": hex(&entry), "permit": signer.sign(Scope::StoreDirectoryEntry {
            log: account, entry, version: 1, body: bh_sync::Digest(hash(&directory)), len: 1024,
        }, TIME_START) })
        })
        .collect();
    out.extend([
        ("directory_page".into(), json!(directory_page)),
        ("directory_body".into(), json!(hex(&directory))),
        ("directory_other".into(), json!(hex(&directory_other))),
        ("directory_entry".into(), json!(hex(&entry))),
        ("directory_digest".into(), json!(hex(&hash(&directory)))),
        (
            "directory_other_digest".into(),
            json!(hex(&hash(&directory_other))),
        ),
        (
            "directory_read".into(),
            json!(signer.sign(Scope::ReadDirectory { log: account }, TIME_START)),
        ),
        (
            "directory_store_1".into(),
            json!(signer.sign(store(account, 1, &directory), TIME_START)),
        ),
        (
            "directory_store_2".into(),
            json!(signer.sign(store(account, 2, &directory_other), TIME_START)),
        ),
        (
            "directory_store_conflict".into(),
            json!(signer.sign(store(account, 1, &directory_other), TIME_START)),
        ),
        (
            "directory_store_base".into(),
            json!(signer.sign(store(base, 1, &directory), TIME_START)),
        ),
        (
            "directory_read_base".into(),
            json!(signer.sign(Scope::ReadDirectory { log: base }, TIME_START)),
        ),
        (
            "directory_retire".into(),
            json!(signer.sign(
                Scope::RetireHomeObjects {
                    log: account,
                    prefix_digest: bh_sync::Digest([6; 32]),
                },
                TIME_START
            )),
        ),
    ]);
    out.extend(home_objects::fixtures(account, base, |scope| {
        signer.sign(scope, TIME_START)
    }));
    out.insert(
        "home_store_other".into(),
        json!(
            signer.sign(
                Scope::StoreHomeObjects {
                    log: account,
                    prefix_digest: bh_sync::Digest([7; 32]),
                    bundle_digest: bh_sync::home_objects::digest(
                        &bh_sync::home_objects::encode(&[1; 242], &[2; 1299], &[3; 1299]).unwrap()
                    )
                    .unwrap(),
                },
                TIME_START
            )
        ),
    );
    println!("{}", Value::Object(out));
}
