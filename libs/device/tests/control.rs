//! The own base's control feed and seal-set waits, from a real signed-up
//! account: controls (removals included) are judged with M alone and kept as
//! facts while content waits at a missing content key; a withheld seal set
//! arrives later and content resumes in order, a typed record included. Every
//! event is really sealed, ordered and verified under a pinned hosting root,
//! and every account change carries a confirmation that root certifies.
use bh_account::{
    AccountEvent, ConfirmedTime, DevicePublicKeys, Head as AccountHead, VerifiedAccount,
    journal::AccountJournal,
    owner::{AccountCapability, AccountGeneration, AccountLoad, AccountOwner},
    personal::{PersonalKey, prepare_rotation},
    platform::ControlKeyPolicy,
    recovery::Password,
    storage::DeviceJournal,
};
use bh_core::note::Note;
use bh_crypto::{KemKey, Secret, SigningKey, hash};
use bh_data::{MutationId, Position, RecordId, Scope, mutation::ops::Operation};
use bh_device::{
    ContainerId, Owner, OwnerError, SealRefusal,
    base_keys::{BaseKeyPurpose, SealHeader, prepare_seal},
    control::{
        Author, CONTROL_PAGE, ControlPage, ControlStep, CurrentKey, InstallError, ScanError,
        ScanStep, VerifiedControlView, install_sealed_epoch, open_seal_set,
    },
    incoming::{LogId, LogKind, NoteOutcome, VerifiedBatch},
    own_base::create_or_open,
};
use bh_event::{
    Binding, CLASS_CONTENT, Copier, Encoded, History, HistoryLookup, LookupError, NOTE, Outcome,
    Payload, Seen, TYPED_DATA,
    account_run::apply_copies,
    account_run::prepare_account_run,
    key_id, note_payload,
    rekey::prepare_rekey,
    seal,
    writer::{DeviceWriterDeclaration, WriterScope},
};
use bh_storage::NoteKey;
use bh_sync::{
    BaseId, Commitment, Digest, EventId, Head, OpaqueEvent, OrderState, Route,
    canonical::RawControlHead,
    receipt::{self, CertifiedReceiptKey, RECEIPT_LEN},
};
use std::{collections::BTreeMap, future::Future, sync::Arc};

#[allow(dead_code)]
#[path = "../../account/tests/support/protector.rs"]
mod protector;
#[path = "../../account/tests/support/store.rs"]
mod store;

type Account = AccountOwner<DeviceJournal, store::FakeStore, protector::PlainProtector>;

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(v) => v,
        _ => panic!("unexpected async platform"),
    }
}

/// Confirmed times on a fake clock.
const START: u64 = 1_000_000;

struct Hosting {
    root: SigningKey,
    certificate: CertifiedReceiptKey,
    key: SigningKey,
}
impl Hosting {
    fn new() -> Self {
        let root = SigningKey::generate();
        let key = SigningKey::generate();
        let certificate =
            receipt::verify_certificate(&root.public(), &receipt::certify(&root, key.public()))
                .unwrap();
        Self {
            root,
            certificate,
            key,
        }
    }
    fn receipt(&self, base: BaseId, head: Head) -> [u8; RECEIPT_LEN] {
        receipt::sign(&self.certificate, &self.key, base, head).unwrap()
    }
}

/// Another device of the account.
struct Other {
    signing: SigningKey,
    control: SigningKey,
    receive: KemKey,
}
impl Other {
    fn new() -> Self {
        Self {
            signing: SigningKey::generate(),
            control: SigningKey::generate(),
            receive: KemKey::generate(),
        }
    }
    fn keys(&self) -> DevicePublicKeys {
        DevicePublicKeys::new(
            self.signing.public(),
            self.control.public(),
            self.receive.public(),
        )
        .unwrap()
    }
}

type Entry = (Commitment, OpaqueEvent, Vec<u8>);

/// The Mac: a signed-up account with its registered own base. It writes the
/// base's log as the service orders it (`log`), and receives it as a device
/// does: the control feed, then content in order.
struct Mac {
    dir: tempfile::TempDir,
    owner: Owner,
    id: ContainerId,
    cap: Arc<AccountCapability>,
    account: Account,
    store: store::FakeStore,
    base: BaseId,
    metadata: Secret<32>,
    hosting: Hosting,
    anchor: VerifiedAccount,
    /// Content keys the producer holds, by id.
    keys: BTreeMap<[u8; 32], Secret<32>>,
    log: Vec<Entry>,
    /// The producer's verified history with every key, for seen claims.
    producer: History,
    last_control: [u8; 32],
    /// The base's copy of the account, as produced.
    base_view: VerifiedAccount,
    /// The epoch each content pull asked a key for, by position.
    asked: Vec<(u64, Option<[u8; 32]>)>,
}

fn copy_secret(secret: &Secret<32>) -> Secret<32> {
    Secret::from_slice(secret.expose()).unwrap()
}

impl Mac {
    fn new() -> Self {
        Self::with_setup(None)
    }
    /// As `new`, with the account home's confirmations of the setup at
    /// `setup_at` when given (a legacy home's untimed setup otherwise); the
    /// creator anchor is then the timed verified account at that head.
    fn with_setup(setup_at: Option<u64>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let owner = Owner::default();
        let id = owner.create_container(dir.path()).unwrap();
        let db = owner.shared_database(id).unwrap();
        let generation = AccountGeneration::new();
        let store = store::FakeStore::new(generation.clone());
        let mut account = Account::new(
            DeviceJournal::from_shared(db.clone()),
            store.clone(),
            protector::PlainProtector,
            generation,
        );
        let status = ready(account.begin_first_device(
            ControlKeyPolicy::AppEnforcedOwnerConfirmation,
            &Password::new("correct horse battery staple").unwrap(),
        ))
        .unwrap();
        let evidence = setup_at.map(|at| {
            let time = ConfirmedTime {
                earliest_ms: at,
                latest_ms: at,
            };
            [
                (time, b"record proof".to_vec()),
                (time, b"key proof".to_vec()),
            ]
        });
        account.confirm_home_ordered(status.head, evidence).unwrap();
        account.confirm_kit_saved().unwrap();
        let record = DeviceJournal::from_shared(db.clone())
            .load()
            .unwrap()
            .unwrap();
        let history = record.history.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let untimed = VerifiedAccount::replay(record.anchor, &history, record.head).unwrap();
        owner.anchor(id, &untimed).unwrap();
        let cap = match ready(account.activate()).unwrap() {
            AccountLoad::Active(c) => Arc::new(c),
            _ => panic!("not active"),
        };
        // With the home's setup times, the creator view is the timed
        // verified account at the head the base genesis names, as the host
        // reads it; a legacy home's is the untimed replay. (The owner's view
        // answers only while that owner runs, so a restarted fixture keeps
        // the replay.)
        let anchor = match setup_at {
            Some(_) => account.verified_at(&cap, record.head.position).unwrap(),
            None => untimed.clone(),
        };
        assert_eq!(anchor.head(), untimed.head());
        let own = ready(create_or_open(&mut account, cap.clone(), db.clone())).unwrap();
        let base = own.id();
        let (metadata, content) = own
            .with_keys(|m, k| (copy_secret(m), copy_secret(k)))
            .unwrap();
        drop(own);
        let stored = db.lock().unwrap().own_base().unwrap().unwrap();
        owner.authorize(id, cap.clone(), base.0).unwrap();
        let hosting = Hosting::new();
        owner
            .record_registration(
                id,
                base.0,
                Some(hosting.receipt(base, Head::EMPTY)),
                hosting.root.public(),
            )
            .unwrap();
        let producer = History::with_account(&anchor, base, hosting.root.public(), 1).unwrap();
        let mut keys = BTreeMap::new();
        keys.insert(key_id(&content), content);
        let mut mac = Self {
            dir,
            owner,
            id,
            cap,
            account,
            store,
            base,
            metadata,
            hosting,
            base_view: anchor.clone(),
            anchor,
            keys,
            log: Vec::new(),
            producer,
            last_control: [0; 32],
            asked: Vec::new(),
        };
        let genesis = Encoded {
            descriptor: OpaqueEvent::decode(&stored.genesis_descriptor).unwrap(),
            body: stored.genesis_body.clone(),
        };
        mac.order(&genesis, Route::Control);
        mac
    }
    fn log_id(&self) -> LogId {
        LogId {
            kind: LogKind::Base,
            id: self.base.0,
        }
    }
    fn head(&self, position: u64) -> Head {
        self.log[position as usize - 1].0.head()
    }
    fn digest(&self, position: u64) -> [u8; 32] {
        self.log[position as usize - 1].0.event_digest().0
    }
    /// The service orders `event` after the log's head; the producer
    /// verifies it with every key. Returns its position.
    fn order(&mut self, event: &Encoded, route: Route) -> u64 {
        let ordered = Commitment::order(
            self.base,
            self.producer.order_state(),
            &event.descriptor,
            route,
        )
        .unwrap();
        let key = self.producer.epoch_id().and_then(|e| self.keys.get(&e));
        let prepared = self
            .producer
            .prepare(
                &ordered,
                &event.descriptor,
                Some(&event.body),
                &self.metadata,
                key,
            )
            .unwrap();
        let applied = self.producer.consume_unapplied(prepared).unwrap();
        assert!(
            matches!(applied.outcome(), Outcome::Accepted | Outcome::Retained),
            "produced event not accepted: {:?}",
            applied.outcome()
        );
        if route == Route::Control {
            self.last_control = ordered.event_digest().0;
        }
        self.log
            .push((ordered, event.descriptor.clone(), event.body.clone()));
        ordered.head().position
    }
    /// As `order`, but the service may order what the producer rejects:
    /// returns its position and the full reader's verdict.
    fn order_any(&mut self, event: &Encoded, route: Route) -> (u64, Outcome) {
        let ordered = Commitment::order(
            self.base,
            self.producer.order_state(),
            &event.descriptor,
            route,
        )
        .unwrap();
        let key = self.producer.epoch_id().and_then(|e| self.keys.get(&e));
        let prepared = self
            .producer
            .prepare(
                &ordered,
                &event.descriptor,
                Some(&event.body),
                &self.metadata,
                key,
            )
            .unwrap();
        let outcome = self.producer.consume_unapplied(prepared).unwrap().outcome();
        if route == Route::Control && outcome == Outcome::Accepted {
            self.last_control = ordered.event_digest().0;
        }
        self.log
            .push((ordered, event.descriptor.clone(), event.body.clone()));
        (ordered.head().position, outcome)
    }
    /// The service orders `event` without the producer judging it; only
    /// for a test's last event, as the producer stops following.
    fn order_unjudged(&mut self, event: &Encoded, route: Route) -> u64 {
        let before = self
            .log
            .last()
            .map_or(OrderState::EMPTY, |(c, _, _)| c.after());
        let ordered = Commitment::order(self.base, before, &event.descriptor, route).unwrap();
        self.log
            .push((ordered, event.descriptor.clone(), event.body.clone()));
        ordered.head().position
    }
    /// A run copy claiming `seen`, with a receipt for its head, signed by
    /// this Mac's control key; not ordered and not applied to the base view.
    fn run_copy_seeing(&self, run: &[(Vec<u8>, Vec<u8>)], seen: Seen) -> Encoded {
        let request = prepare_account_run(
            self.base,
            &self.base_view,
            Copier::Device(self.cap.device_id()),
            &self.metadata,
            seen,
            self.hosting.receipt(self.base, seen.head),
            run,
        )
        .unwrap();
        let state = self.store.state();
        let control = state.control.as_ref().unwrap();
        let signature = control.sign(request.signing_bytes());
        request.finish(signature).unwrap()
    }
    fn seen(&self) -> (Seen, [u8; RECEIPT_LEN]) {
        let head = self.producer.head();
        (
            Seen {
                head,
                control: self.last_control,
                account: self.producer.account_head(),
            },
            self.hosting.receipt(self.base, head),
        )
    }
    /// An ordering confirmation for `event`, the account's next after
    /// `before`, at `at` under the base's hosting root.
    fn confirmation(&self, event: &AccountEvent, before: AccountHead, at: u64) -> Vec<u8> {
        use bh_sync::evidence::{
            ConfirmationClaim, OrderingConfirmation, TimeBounds, original_digest,
        };
        use bh_sync::permit::{self, LogId as PermitLog, LogKind as PermitKind};
        let head = |h: AccountHead| Head {
            position: h.position,
            hash: Digest(h.hash),
        };
        let key = SigningKey::generate();
        let claim = ConfirmationClaim {
            log: PermitLog {
                kind: PermitKind::Account,
                id: [0x64; 32],
            },
            original: original_digest(event.as_bytes()),
            original_previous: head(before),
            original_head: head(event.head()),
            body: None,
            ordered: Head {
                position: event.head().position,
                hash: Digest([0x65; 32]),
            },
            bounds: TimeBounds {
                earliest_ms: at,
                latest_ms: at,
            },
        };
        OrderingConfirmation::sign(
            &key,
            &permit::certify(&self.hosting.root, key.public()),
            claim,
        )
        .encode()
        .to_vec()
    }
    /// The account home orders `event`, confirmed at `at`; the account owner
    /// follows it. Returns the original and its confirmation.
    fn ordered(&mut self, event: &AccountEvent, at: u64) -> (Vec<u8>, Vec<u8>) {
        let before = self.account.verified(&self.cap).unwrap().head();
        let confirmation = self.confirmation(event, before, at);
        let time = ConfirmedTime {
            earliest_ms: at,
            latest_ms: at,
        };
        self.account
            .apply_incoming_timed(&[(event.as_bytes(), Some((time, vec![1])))])
            .unwrap();
        (event.as_bytes().to_vec(), confirmation)
    }
    fn add(&mut self, other: &Other, at: u64) -> (Vec<u8>, Vec<u8>) {
        let request = self
            .account
            .prepare_add_device(&self.cap, other.keys())
            .unwrap();
        let event = ready(self.account.sign_control(&self.cap, &request)).unwrap();
        self.ordered(&event, at)
    }
    fn leave(&mut self, other: &Other, at: u64) -> (Vec<u8>, Vec<u8>) {
        let request = self
            .account
            .verified(&self.cap)
            .unwrap()
            .remove_self(other.keys().id())
            .unwrap();
        let event = request
            .finish(other.control.sign(request.signing_bytes()))
            .unwrap();
        self.ordered(&event, at)
    }
    /// A run of confirmed account events, copied by this Mac's control key.
    fn copy_run(&mut self, run: &[(Vec<u8>, Vec<u8>)]) -> u64 {
        let (seen, receipt) = self.seen();
        let request = prepare_account_run(
            self.base,
            &self.base_view,
            Copier::Device(self.cap.device_id()),
            &self.metadata,
            seen,
            receipt,
            run,
        )
        .unwrap();
        let state = self.store.state();
        let control = state.control.as_ref().unwrap();
        let signature = control.sign(request.signing_bytes());
        let encoded = request.finish(signature).unwrap();
        drop(state);
        self.copied(run);
        self.order(&encoded, Route::Control)
    }
    fn copied(&mut self, run: &[(Vec<u8>, Vec<u8>)]) {
        let copies: Vec<_> = run
            .iter()
            .map(|(original, confirmation)| bh_event::AccountCopy {
                original: original.clone(),
                confirmation: Some(confirmation.clone()),
            })
            .collect();
        apply_copies(&mut self.base_view, &copies, &self.hosting.root.public()).unwrap();
    }
    /// Rotate the personal key for the last removal, accept it on this
    /// device, and order the base's rekey to a new content key sealed to
    /// it. Returns the rekey's position, its seal set and the new key's id.
    fn rotate_and_rekey(&mut self, removal: u64, at: u64) -> (u64, Vec<u8>, [u8; 32]) {
        let next = PersonalKey::generate();
        let view = self.account.verified(&self.cap).unwrap().clone();
        let prepared = prepare_rotation(&view.advanced(at), &next).unwrap();
        let request = view
            .rotate_personal(
                self.cap.device_id(),
                removal,
                prepared.public,
                prepared.device_seals_digest,
                prepared.recovery_seal_digest,
            )
            .unwrap();
        let signature = ready(
            self.account
                .sign_content(&self.cap, request.signing_bytes()),
        )
        .unwrap();
        let rotation = request.finish(signature).unwrap();
        let (original, confirmation) = self.ordered(&rotation, at);
        let db = self.owner.shared_database(self.id).unwrap();
        ready(bh_device::own_base::ensure_keyring(
            &mut self.account,
            self.cap.clone(),
            db,
        ))
        .unwrap();
        let accepted = ready(self.account.accept_rotation(
            &self.cap,
            rotation.head().position,
            &prepared.body,
        ))
        .unwrap();
        assert_eq!(accepted.public(), next.public());
        let k = Secret::<32>::random();
        let history = self.account.verified(&self.cap).unwrap().clone();
        let header = SealHeader {
            purpose: BaseKeyPurpose::Content,
            base: self.base,
            audience: [0; 32],
            key_id: key_id(&k),
            recipient: hash(&next.public()),
            sender: history.id(),
            device: self.cap.device_id(),
            head: history.head(),
        };
        let unsigned = prepare_seal(&history, header, &next.public(), &k).unwrap();
        let signature = ready(
            self.account
                .sign_content(&self.cap, unsigned.signing_bytes()),
        )
        .unwrap();
        let sealed = unsigned.finish(signature).unwrap();
        let (seen, receipt) = self.seen();
        let rekey = prepare_rekey(
            self.base,
            &self.base_view,
            self.cap.device_id(),
            &self.metadata,
            seen,
            receipt,
            &original,
            &confirmation,
            &k,
            &[sealed],
        )
        .unwrap();
        let set = rekey.seal_set.bytes().to_vec();
        let signature = ready(
            self.account
                .sign_content(&self.cap, rekey.control.signing_bytes()),
        )
        .unwrap();
        let control = rekey.control.finish(signature).unwrap();
        self.copied(&[(original, confirmation)]);
        let id = key_id(&k);
        self.keys.insert(id, k);
        (self.order(&control, Route::Control), set, id)
    }
    fn binding(&self, device: bh_account::DeviceId) -> (Binding, Secret<32>) {
        let (seen, receipt) = self.seen();
        let epoch = self.producer.epoch_id().unwrap();
        (
            Binding {
                version: 3,
                highest: 3,
                mode: 0,
                base: self.base.0,
                audience: [0; 32],
                epoch,
                event_id: EventId(bh_crypto::random()),
                account: self.cap.account_id(),
                device,
                account_head: seen.account,
                seen: seen.head,
                seen_control: seen.control,
                class: CLASS_CONTENT,
                padded: 0,
                commitment: [0; 32],
                seen_receipt: receipt,
            },
            copy_secret(&self.keys[&epoch]),
        )
    }
    /// A note's first paragraph by `device`, signed with `signing`.
    fn note(
        &mut self,
        device: bh_account::DeviceId,
        signing: &SigningKey,
        note: [u8; 32],
        text: &str,
    ) -> u64 {
        let writer = DeviceWriterDeclaration {
            account: self.cap.account_id().0,
            device: device.0,
            nonce: [9; 32],
        };
        let update = Note::with_writer(writer.client_id(WriterScope {
            base: self.base.0,
            audience: [0; 32],
            note,
        }))
        .unwrap()
        .try_append_paragraph(text)
        .unwrap();
        let (binding, k) = self.binding(device);
        let encoded = seal(
            binding,
            Payload {
                kind: NOTE,
                data: &note_payload(note, writer, &update),
            },
            signing,
            &self.metadata,
            Some(&k),
        )
        .unwrap();
        self.order(&encoded, Route::Content)
    }
    fn mac_note(&mut self, note: [u8; 32], text: &str) -> u64 {
        let store = self.store.clone();
        let state = store.state();
        self.note(
            self.cap.device_id(),
            state.ordinary.as_ref().unwrap(),
            note,
            text,
        )
    }
    /// A typed record by this Mac.
    fn typed(&mut self, op: &Operation) -> u64 {
        let store = self.store.clone();
        let state = store.state();
        let ordinary = state.ordinary.as_ref().unwrap();
        let (binding, k) = self.binding(self.cap.device_id());
        let encoded = seal(
            binding,
            Payload {
                kind: TYPED_DATA,
                data: &bh_data::payload::encode(MutationId::random(), op).unwrap(),
            },
            ordinary,
            &self.metadata,
            Some(&k),
        )
        .unwrap();
        drop(state);
        self.order(&encoded, Route::Content)
    }

    // ---- The receiving device ----

    /// The last control-route position: where a hosted read is bounded.
    fn control_head(&self) -> u64 {
        self.log
            .iter()
            .rev()
            .find(|(c, _, _)| c.route() == Route::Control)
            .map_or(0, |(c, _, _)| c.head().position)
    }
    /// A hosted control read after `after`, bounded by `through`, as the
    /// edge serves it: at most a page of control-route events, and the
    /// endpoint opening at `through` with a receipt for its head. Positions
    /// in `withheld` are left out, as a dishonest server might.
    fn serve(&self, after: u64, through: u64, withheld: &[u64]) -> ControlPage {
        // A body the descriptor does not name is one the server has none of.
        let items = self
            .log
            .iter()
            .filter(|(c, _, _)| {
                let at = c.head().position;
                c.route() == Route::Control
                    && at > after
                    && at <= through
                    && !withheld.contains(&at)
            })
            .take(CONTROL_PAGE)
            .map(|(c, e, b)| {
                let named = bh_sync::referenced_body(e).ok();
                let held = bh_sync::BodyObject::new(b.clone())
                    .is_ok_and(|o| Some(o.commitment()) == named);
                (*c, e.clone(), held.then(|| b.clone()))
            })
            .collect();
        let endpoint = self.log[through as usize - 1].0.after();
        ControlPage {
            items,
            endpoint,
            receipt: Some(self.hosting.receipt(self.base, endpoint.head(self.base))),
        }
    }
    /// One feed scan to the current control head, page by page.
    fn feed(&self) -> Result<ControlStep, ScanError> {
        self.feed_to(self.control_head(), &[]).map(|(step, _)| step)
    }
    /// A feed scan bounded at `through` with `withheld` left out; also the
    /// number of pages it read.
    fn feed_to(&self, through: u64, withheld: &[u64]) -> Result<(ControlStep, usize), ScanError> {
        let mut scan = self
            .owner
            .control_scan(self.id, self.log_id(), &self.anchor)
            .unwrap();
        let mut pages = 0;
        loop {
            pages += 1;
            let page = self.serve(scan.after(), through, withheld);
            match scan.page(&self.metadata, page)? {
                ScanStep::More => continue,
                ScanStep::Complete => {
                    let step = self.owner.commit_controls(self.id, scan).unwrap();
                    return Ok((step, pages));
                }
            }
        }
    }
    /// Content batches from the content cursor until one makes no progress.
    fn pull(&mut self) -> Vec<(NoteKey, NoteOutcome)> {
        let mut outcomes = Vec::new();
        loop {
            let before = self.progress().position;
            outcomes.extend(self.batch());
            if self.progress().position == before {
                return outcomes;
            }
        }
    }
    /// One content batch from the content cursor, as a puller reads it: each
    /// event judged with its own epoch's held key, stopping at a control the
    /// feed has not judged or at a key this device does not hold. The local
    /// keyring names M only once the genesis is applied.
    fn batch(&mut self) -> Vec<(NoteKey, NoteOutcome)> {
        let log = self.log_id();
        let root = self.hosting.root.public();
        let mut history = self
            .owner
            .history(self.id, log, &self.anchor, root, 1)
            .unwrap();
        let from = self.progress().position;
        let judged = self.owner.control_after(self.id, log).unwrap();
        let judged =
            |at: u64| at <= judged && self.owner.control_fact(self.id, log, at).unwrap().is_some();
        let personal = ready(self.account.open_current_personal(&self.cap)).unwrap();
        let mut events = Vec::new();
        for (ordered, event, body) in self.log.iter().skip(from as usize) {
            if ordered.route() == Route::Control && !judged(ordered.head().position) {
                break;
            }
            let epoch = history.epoch_id();
            self.asked.push((ordered.head().position, epoch));
            let key = epoch.and_then(|epoch| {
                self.owner
                    .with_epoch_key(self.id, self.base, epoch, &personal, |_, k| copy_secret(k))
                    .ok()
            });
            match history.prepare(ordered, event, Some(body), &self.metadata, key.as_ref()) {
                Ok(prepared) => events.push(history.consume_unapplied(prepared).unwrap()),
                Err(Outcome::UnavailablePause) => break,
                Err(other) => panic!("content verdict {other:?}"),
            }
        }
        let Some(last) = events.last() else {
            return Vec::new();
        };
        let head = last.head();
        self.owner
            .apply_remote_batch(
                self.id,
                VerifiedBatch {
                    log,
                    events,
                    head,
                    receipt: self.hosting.receipt(self.base, head),
                },
            )
            .unwrap()
    }
    fn install(&mut self, set: &[u8]) -> Result<(), InstallError> {
        let wait = self.owner.seal_waits(self.id).unwrap()[0];
        let seals = open_seal_set(&wait, &self.metadata, set)?;
        let db = self.owner.shared_database(self.id).unwrap();
        ready(install_sealed_epoch(
            &mut self.account,
            self.cap.clone(),
            db,
            &wait,
            &seals,
        ))
        .map(drop)
    }
    fn progress(&self) -> bh_storage::sync_state::LogProgress {
        let db = self.owner.shared_database(self.id).unwrap();
        let progress = db.lock().unwrap().log_progress(1, self.base.0).unwrap();
        progress.unwrap()
    }
    fn view(&self) -> VerifiedControlView {
        self.owner
            .control_view(self.id, self.log_id(), &self.anchor)
            .unwrap()
    }
    fn held_key(&mut self, epoch: [u8; 32]) -> bool {
        let personal = ready(self.account.open_current_personal(&self.cap)).unwrap();
        self.owner
            .with_epoch_key(self.id, self.base, epoch, &personal, |_, _| ())
            .is_ok()
    }
    fn key(&self, note: [u8; 32]) -> NoteKey {
        NoteKey {
            base: self.base.0,
            audience: [0; 32],
            note,
        }
    }
    fn author(&self, device: bh_account::DeviceId) -> Author {
        Author {
            account: self.cap.account_id(),
            device,
        }
    }
    fn raw(&self) -> rusqlite::Connection {
        let path = std::fs::read_dir(self.dir.path().join("accounts"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "sqlite"))
            .unwrap();
        rusqlite::Connection::open(path).unwrap()
    }
    fn accepted_record(&self, record: [u8; 32]) -> Option<serde_json::Value> {
        let raw = self.raw();
        let sid = bh_data::store::records::lookup_scope(
            &raw,
            Scope {
                base: self.base.0,
                audience: [0; 32],
            },
        )
        .unwrap()?;
        bh_data::store::records::get(&raw, sid, RecordId(record))
            .unwrap()?
            .accepted
    }
    /// Fixture catalogue, accepted at typed positions 1–3, as in the
    /// incoming-transaction tests. It contains no note/content under test.
    fn seed_journal_type(&self) {
        let bytes = include_bytes!("../../data/tests/fixtures/types/JournalEntry.json");
        let app = bh_data::AppId([2; 32]);
        let raw = self.raw();
        let scope = Scope {
            base: self.base.0,
            audience: [0; 32],
        };
        let actor = bh_data::Actor::Device {
            account: self.cap.account_id().0,
            device: self.cap.device_id().0,
        };
        let operations = [
            Operation::DefineApp {
                app,
                name: "Journal".into(),
            },
            Operation::DefineType {
                bytes: bytes.to_vec(),
            },
            Operation::SetAppState { app, active: true },
        ];
        for (i, op) in operations.iter().enumerate() {
            let tx = raw.unchecked_transaction().unwrap();
            let payload = bh_data::testkit::assumed_payload(
                &tx,
                &bh_data::catalogue::Shipped,
                scope,
                &actor,
                MutationId::random(),
                op,
            )
            .unwrap();
            let outcome = bh_data::testkit::apply_payload(
                &tx,
                &bh_data::catalogue::Shipped,
                scope,
                Position(i as u64 + 1),
                &actor,
                &payload,
            )
            .unwrap();
            assert!(matches!(
                outcome,
                bh_data::mutation::apply::Outcome::Accepted { .. }
            ));
            tx.commit().unwrap();
        }
    }
    fn typed_through(&self) -> Option<Position> {
        let raw = self.raw();
        let scope = Scope {
            base: self.base.0,
            audience: [0; 32],
        };
        let sid = bh_data::store::records::lookup_scope(&raw, scope).unwrap()?;
        raw.query_row(
            "SELECT position FROM data_ordered WHERE scope=?1",
            [sid],
            |r| r.get::<_, i64>(0),
        )
        .ok()
        .map(|p| Position(p as u64))
    }
    /// A fresh process over the same container: a new device owner and
    /// account owner over the surviving files.
    fn restart(self) -> Self {
        let Mac {
            dir,
            owner,
            account,
            store,
            base,
            metadata,
            hosting,
            anchor,
            keys,
            log,
            producer,
            last_control,
            base_view,
            asked,
            ..
        } = self;
        let lock_path = std::fs::read_dir(dir.path().join("accounts"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|ext| ext == "lock"))
            .unwrap();
        drop(account);
        drop(owner);
        // A worker may still hold its last reference: wait for the actual
        // container lock, not a timer.
        let lock = std::fs::File::open(lock_path).unwrap();
        lock.lock().unwrap();
        drop(lock);
        let owner = Owner::default();
        let id = owner
            .open_containers(dir.path())
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .1
            .unwrap();
        let db = owner.shared_database(id).unwrap();
        let mut account = Account::new(
            DeviceJournal::from_shared(db),
            store.clone(),
            protector::PlainProtector,
            AccountGeneration::new(),
        );
        let cap = match ready(account.activate()).unwrap() {
            AccountLoad::Active(c) => Arc::new(c),
            _ => panic!("not active"),
        };
        owner.anchor(id, account.verified(&cap).unwrap()).unwrap();
        owner.authorize(id, cap.clone(), base.0).unwrap();
        Mac {
            dir,
            owner,
            id,
            cap,
            account,
            store,
            base,
            metadata,
            hosting,
            anchor,
            keys,
            log,
            producer,
            last_control,
            base_view,
            asked,
        }
    }
}

/// The scenario: two other devices join; one leaves (the epoch closes); the
/// personal key rotates and the base rekeys; the Mac writes a note and a
/// typed record under the new key; then the other device leaves too.
struct Scenario {
    mac: Mac,
    fold: Other,
    fold2: Other,
    set: Vec<u8>,
    epoch: [u8; 32],
    genesis_epoch: [u8; 32],
    note: [u8; 32],
}
fn scenario() -> Scenario {
    let mut mac = Mac::new();
    let genesis_epoch = mac.producer.epoch_id().unwrap();
    let (fold, fold2) = (Other::new(), Other::new());
    let add = mac.add(&fold, START);
    let add2 = mac.add(&fold2, START + 1);
    assert_eq!(mac.copy_run(&[add, add2]), 2);
    let fold_device = fold.keys().id();
    assert_eq!(mac.note(fold_device, &fold.signing, [3; 32], "before"), 3);
    let leave = mac.leave(&fold, START + 2);
    let removal = mac.account.verified(&mac.cap).unwrap().head().position;
    assert_eq!(mac.copy_run(&[leave]), 4);
    let (at, set, epoch) = mac.rotate_and_rekey(removal, START + 3);
    assert_eq!(at, 5);
    let note = [6; 32];
    assert_eq!(mac.mac_note(note, "under the new key"), 6);
    mac.seed_journal_type();
    let definition = include_bytes!("../../data/tests/fixtures/types/JournalEntry.json");
    assert_eq!(
        mac.typed(&Operation::BindNote {
            note: RecordId(note),
            type_id: bh_data::definition::parse(definition).unwrap().type_id,
            revision: bh_data::RevisionId::of(definition),
            doc: serde_json::json!({ "date": 1_700_000_000_000_i64 }),
        }),
        7
    );
    let leave2 = mac.leave(&fold2, START + 4);
    assert_eq!(mac.copy_run(&[leave2]), 8);
    Scenario {
        mac,
        fold,
        fold2,
        set,
        epoch,
        genesis_epoch,
        note,
    }
}

#[test]
fn controls_and_a_removal_progress_while_content_waits_for_a_withheld_seal_set() {
    let Scenario {
        mut mac,
        fold,
        fold2,
        set,
        epoch,
        genesis_epoch,
        note,
    } = scenario();
    // The feed judges every control with M alone, the removal included.
    assert_eq!(mac.feed(), committed(8));
    let waits = mac.owner.seal_waits(mac.id).unwrap();
    assert_eq!(waits.len(), 1);
    assert_eq!((waits[0].key_id, waits[0].position), (epoch, 5));
    // Content stops at the first event under the key it does not hold.
    mac.pull();
    assert_eq!(mac.progress().position, 5);
    assert_eq!(mac.progress().epoch_id, Some(epoch));
    assert!(mac.pull().is_empty());
    assert_eq!(mac.progress().position, 5);
    // Control state is current although content is behind: the epoch the
    // rekey installed was closed by the later removal.
    let view = mac.view();
    assert_eq!(view.current_key(), Ok(None));
    assert_eq!(view.control_head_at(8), Ok(Some(mac.head(8))));
    assert_eq!(view.control_head_at(7), Ok(Some(mac.head(5))));
    assert!(
        !view
            .authorised_at(mac.author(fold2.keys().id()), 8)
            .unwrap()
    );
    assert!(
        view.authorised_at(mac.author(fold2.keys().id()), 7)
            .unwrap()
    );
    assert!(!view.authorised_at(mac.author(fold.keys().id()), 4).unwrap());
    // Nothing stands in for the missing key: neither the genesis key nor
    // any other opens the next event, and no write can use an old key.
    assert!(!mac.held_key(epoch));
    assert!(mac.held_key(genesis_epoch));
    assert!(
        mac.asked
            .iter()
            .filter(|(position, _)| *position >= 6)
            .all(|(_, asked)| *asked == Some(epoch))
    );
    // The set arrives: its key installs and content resumes in order, the
    // typed record at its own position.
    assert_eq!(mac.typed_through(), Some(Position(3))); // catalogue only
    assert_eq!(mac.accepted_record(note), None);
    mac.install(&set).unwrap();
    assert!(mac.owner.seal_waits(mac.id).unwrap().is_empty());
    let outcomes = mac.pull();
    assert_eq!(outcomes, vec![(mac.key(note), NoteOutcome::Accepted)]);
    assert_eq!(mac.progress().position, 8);
    assert_eq!(mac.typed_through(), Some(Position(7)));
    assert_eq!(
        mac.accepted_record(note).unwrap()["date"],
        1_700_000_000_000_i64
    );
    // Once content reaches the removal the epoch is closed for writes.
    assert_eq!(mac.progress().epoch_id, None);
    let _ = (fold, fold2);
}

#[test]
fn each_event_opens_with_its_own_epoch_key() {
    let Scenario {
        mut mac,
        set,
        epoch,
        genesis_epoch,
        ..
    } = scenario();
    assert_eq!(mac.feed(), committed(8));
    // The new key is held before any content is read: earlier content still
    // opens only with its own, older key.
    mac.install(&set).unwrap();
    mac.pull();
    assert_eq!(mac.progress().position, 8);
    let asked: Vec<_> = mac.asked.clone();
    for (position, epoch_asked) in asked {
        // The removal at 4 closed the genesis epoch; the rekey at 5 opened
        // the new one.
        let expected = match position {
            1 | 5 => None,
            2..=4 => Some(genesis_epoch),
            _ => Some(epoch),
        };
        assert_eq!(epoch_asked, expected, "position {position}");
    }
    // The genesis key does not open content of the new epoch.
    let mut history =
        History::with_account(&mac.anchor, mac.base, mac.hosting.root.public(), 1).unwrap();
    for (ordered, event, body) in &mac.log[..5] {
        let key = history.epoch_id().and_then(|e| mac.keys.get(&e));
        let prepared = history
            .prepare(ordered, event, Some(body), &mac.metadata, key)
            .unwrap();
        history.consume_unapplied(prepared).unwrap();
    }
    let (ordered, event, body) = &mac.log[5];
    assert_eq!(
        history
            .prepare(
                ordered,
                event,
                Some(body),
                &mac.metadata,
                Some(&mac.keys[&genesis_epoch])
            )
            .err(),
        Some(Outcome::UnavailablePause)
    );
}

#[test]
fn wrong_seal_bytes_never_install_and_metadata_only_copies_continue() {
    let Scenario {
        mut mac,
        set,
        epoch,
        ..
    } = scenario();
    assert_eq!(mac.feed(), committed(8));
    mac.pull();
    assert_eq!(mac.progress().position, 5);
    // Another set's bytes, or the right set cut short, are never installed.
    let mut other = set.clone();
    other[40] ^= 1;
    for wrong in [other, set[..set.len() - 1].to_vec(), vec![0; 4096]] {
        assert_eq!(mac.install(&wrong), Err(InstallError::Invalid));
        assert_eq!(mac.owner.seal_waits(mac.id).unwrap().len(), 1);
        assert!(!mac.held_key(epoch));
    }
    // While the key is pending, copying an account change needs only M and
    // claims the feed's current control state, which the base accepts.
    let third = Other::new();
    let add = mac.add(&third, START + 5);
    let request = mac
        .owner
        .prepare_account_run_copy(
            mac.id,
            &mac.anchor,
            &mac.metadata,
            std::slice::from_ref(&add),
            Copier::Device(mac.cap.device_id()),
        )
        .unwrap();
    let state = mac.store.state();
    let control = state.control.as_ref().unwrap();
    let signature = control.sign(request.signing_bytes());
    let copy = request.finish(signature).unwrap();
    drop(state);
    mac.copied(std::slice::from_ref(&add));
    assert_eq!(mac.order(&copy, Route::Control), 9);
    assert_eq!(mac.feed(), committed(9));
    assert!(
        mac.view()
            .authorised_at(mac.author(third.keys().id()), 9)
            .unwrap()
    );
    // The right set still installs afterwards.
    mac.install(&set).unwrap();
    mac.pull();
    assert_eq!(mac.progress().position, 9);
}

#[test]
fn facts_and_the_seal_wait_survive_restart_and_answer_as_of_older_positions() {
    let Scenario {
        mac,
        fold,
        fold2,
        set,
        epoch,
        genesis_epoch,
        ..
    } = scenario();
    assert_eq!(mac.feed(), committed(8));
    let mut mac = mac;
    mac.pull();
    let mut mac = mac.restart();
    assert_eq!(mac.owner.control_after(mac.id, mac.log_id()).unwrap(), 8);
    assert_eq!(mac.owner.seal_waits(mac.id).unwrap().len(), 1);
    let view = mac.view();
    let creator = mac.cap.account_id();
    let account_at = |position: u64| view.account_head_at(creator, position).unwrap().unwrap();
    // Each of the view's answers, as of positions the content cursor (5)
    // and the control head (8) bound, and earlier.
    assert_eq!(view.control_head_at(0), Ok(None));
    assert_eq!(view.control_head_at(1), Ok(Some(mac.head(1))));
    assert_eq!(view.control_head_at(3), Ok(Some(mac.head(2))));
    assert_eq!(view.control_head_at(6), Ok(Some(mac.head(5))));
    assert_eq!(view.control_digest_at(3), Ok(Some(mac.digest(2))));
    assert_eq!(view.control_digest_at(8), Ok(Some(mac.digest(8))));
    assert_eq!(account_at(1), mac.anchor.head());
    assert!(account_at(3).position > mac.anchor.head().position);
    assert!(account_at(8).position > account_at(6).position);
    assert_eq!(
        view.account_head_at(bh_account::AccountId([9; 32]), 3),
        Ok(None)
    );
    assert!(view.authorised_at(mac.author(fold.keys().id()), 3).unwrap());
    assert!(!view.authorised_at(mac.author(fold.keys().id()), 4).unwrap());
    assert!(
        view.authorised_at(mac.author(fold2.keys().id()), 7)
            .unwrap()
    );
    assert!(
        !view
            .authorised_at(mac.author(fold2.keys().id()), 8)
            .unwrap()
    );
    assert!(!view.authorised_at(mac.author(fold.keys().id()), 1).unwrap());
    // Positions past what the feed and content verified are not answered.
    assert!(view.control_head_at(9).is_err());
    assert!(
        view.authorised_at(mac.author(fold2.keys().id()), 9)
            .is_err()
    );
    assert_eq!(view.current_key(), Ok(None));
    // What content verified and what the feed judged, by position.
    assert_eq!(view.seen(3).unwrap().unwrap().control, mac.digest(2));
    assert_eq!(view.seen(8).unwrap().unwrap().control, mac.digest(8));
    let _ = genesis_epoch;
    drop(view);
    // The kept wait completes after restart, and content resumes.
    mac.install(&set).unwrap();
    assert!(mac.held_key(epoch));
    mac.pull();
    assert_eq!(mac.progress().position, 8);
    // The installed key's control, before the removal closed it.
    let mut mac = mac.restart();
    assert!(mac.held_key(epoch));
    assert_eq!(
        mac.view().current_key(),
        Ok(None),
        "closed by the removal at 8"
    );
}

/// The base's copy of the account is replayed and verified once per
/// accepted account head a view is asked about, not once per lookup.
#[test]
fn a_second_lookup_at_one_account_head_verifies_nothing_again() {
    let Scenario {
        mac, fold, fold2, ..
    } = scenario();
    assert_eq!(mac.feed(), committed(8));
    let view = mac.view();
    let (fold, fold2) = (mac.author(fold.keys().id()), mac.author(fold2.keys().id()));
    assert_eq!(view.account_replays(), 0);
    assert_eq!(view.authorised_at(fold, 2), Ok(true));
    assert_eq!(view.account_replays(), 1);
    // The same account head, at another position and for another device.
    assert_eq!(view.authorised_at(fold, 3), Ok(true));
    assert_eq!(view.authorised_at(fold2, 3), Ok(true));
    assert_eq!(view.account_replays(), 1);
    // Another head is replayed once.
    assert_eq!(view.authorised_at(fold, 4), Ok(false));
    assert_eq!(view.authorised_at(fold2, 4), Ok(true));
    assert_eq!(view.account_replays(), 2);
    assert_eq!(view.authorised_at(fold, 2), Ok(true));
    assert_eq!(view.account_replays(), 2);
}

#[test]
fn rejected_controls_keep_the_last_accepted_facts_after_reopen() {
    let mut mac = Mac::new();
    mac.feed().unwrap();
    let event = OpaqueEvent::new(EventId([91; 32]), vec![42; 1024]).unwrap();
    let ordered =
        Commitment::order(mac.base, mac.log[0].0.after(), &event, Route::Control).unwrap();
    mac.log.push((ordered, event, vec![42; 1024]));
    assert_eq!(mac.feed(), committed(2));
    let mac = mac.restart();
    let fact = mac
        .owner
        .control_fact(mac.id, mac.log_id(), 2)
        .unwrap()
        .unwrap();
    assert!(!fact.accepted);
    assert_eq!(fact.digest, mac.digest(2));
    assert_eq!(fact.control_digest, mac.digest(1));
    let view = mac.view();
    assert_eq!(view.control_head_at(2), Ok(Some(mac.head(1))));
    assert_eq!(view.control_digest_at(2), Ok(Some(mac.digest(1))));
    assert_eq!(
        view.account_head_at(mac.anchor.id(), 2).unwrap().unwrap(),
        mac.anchor.head()
    );
    assert!(
        view.authorised_at(mac.author(mac.cap.device_id()), 2)
            .unwrap()
    );
    assert_eq!(
        view.current_key().unwrap().unwrap().installed_at,
        mac.head(1)
    );
    assert!(
        view.account_head_at(bh_account::AccountId([9; 32]), 3)
            .is_err()
    );
}

#[test]
fn installation_requires_the_exact_durable_wait() {
    let Scenario {
        mut mac,
        set,
        epoch,
        ..
    } = scenario();
    mac.feed().unwrap();
    mac.pull();
    let mut wait = mac.owner.seal_waits(mac.id).unwrap()[0];
    wait.position += 1;
    let seals = open_seal_set(&wait, &mac.metadata, &set).unwrap();
    let db = mac.owner.shared_database(mac.id).unwrap();
    assert_eq!(
        ready(install_sealed_epoch(
            &mut mac.account,
            mac.cap.clone(),
            db,
            &wait,
            &seals
        ))
        .err(),
        Some(InstallError::Invalid)
    );
    assert!(!mac.held_key(epoch));
    assert_eq!(mac.owner.seal_waits(mac.id).unwrap().len(), 1);
}

#[test]
fn installing_over_a_tampered_keyring_row_is_invalid_and_keeps_the_wait() {
    let Scenario {
        mut mac,
        set,
        epoch,
        ..
    } = scenario();
    mac.feed().unwrap();
    mac.pull();
    let db = mac.owner.shared_database(mac.id).unwrap();
    {
        let mut db = db.lock().unwrap();
        let mut row = db.epoch_keys(mac.base.0).unwrap().remove(0);
        row.epoch_id = epoch;
        row.purpose = bh_account::local_seal::LocalKeyPurpose::Content as i64;
        let delivery = db.personal_delivery().unwrap();
        db.install_epoch_keys(delivery.as_ref(), &[row], || true)
            .unwrap();
    }
    assert_eq!(mac.install(&set), Err(InstallError::Invalid));
    assert_eq!(mac.owner.seal_waits(mac.id).unwrap().len(), 1);
}

#[test]
fn the_current_key_names_the_rekey_that_installed_it() {
    let mut mac = Mac::new();
    let genesis = mac.producer.epoch_id().unwrap();
    assert_eq!(mac.feed(), committed(1));
    assert_eq!(
        mac.view().current_key(),
        Ok(Some(CurrentKey {
            key_id: genesis,
            installed_at: mac.head(1),
        }))
    );
    let fold = Other::new();
    let add = mac.add(&fold, START);
    mac.copy_run(&[add]);
    let leave = mac.leave(&fold, START + 1);
    let removal = mac.account.verified(&mac.cap).unwrap().head().position;
    mac.copy_run(&[leave]);
    let (at, _, epoch) = mac.rotate_and_rekey(removal, START + 2);
    assert_eq!(mac.feed(), committed(at));
    assert_eq!(
        mac.view().current_key(),
        Ok(Some(CurrentKey {
            key_id: epoch,
            installed_at: mac.head(at),
        }))
    );
}

#[test]
fn a_closed_epoch_refuses_content_seals() {
    let Scenario { mut mac, set, .. } = scenario();
    mac.feed().unwrap();
    mac.install(&set).unwrap();
    mac.pull();
    assert_eq!(mac.progress().epoch_id, None);
    let db = mac.owner.shared_database(mac.id).unwrap();
    let note = mac.owner.create_note(mac.id).unwrap();
    mac.owner.show_note("w", mac.id, note).unwrap();
    let opened = mac.owner.open_leased("w", note).unwrap();
    let lease = opened.writer.unwrap();
    let delta = Owner::core_author(&opened)
        .unwrap()
        .try_append_paragraph("kept while closed")
        .unwrap();
    mac.owner
        .commit_leased("w", opened.generation, lease.token, [1; 16], &delta)
        .unwrap();
    let update_id = db.lock().unwrap().pending_note_updates().unwrap()[0].update_id;
    let candidate = match db.lock().unwrap().prepare_note_package(update_id).unwrap() {
        bh_storage::PackagePreparation::Candidate(c) => c,
        bh_storage::PackagePreparation::Existing(_) => panic!("already packaged"),
    };
    let any = mac.keys.values().next().map(copy_secret).unwrap();
    assert!(matches!(
        mac.owner.prepare_note_seal(
            mac.id,
            &mac.anchor,
            mac.hosting.root.public(),
            &mac.metadata,
            &any,
            &candidate,
        ),
        Err(OwnerError::SealRefused(SealRefusal::EpochClosed))
    ));
}

/// A pending note update's package candidate, as the outbox prepares it.
fn note_candidate(mac: &Mac, window: &str, text: &str) -> bh_storage::PackageCandidate {
    let db = mac.owner.shared_database(mac.id).unwrap();
    let note = mac.owner.create_note(mac.id).unwrap();
    mac.owner.show_note(window, mac.id, note).unwrap();
    let opened = mac.owner.open_leased(window, note).unwrap();
    let lease = opened.writer.unwrap();
    let delta = Owner::core_author(&opened)
        .unwrap()
        .try_append_paragraph(text)
        .unwrap();
    mac.owner
        .commit_leased(window, opened.generation, lease.token, [1; 16], &delta)
        .unwrap();
    let update_id = db
        .lock()
        .unwrap()
        .pending_note_updates()
        .unwrap()
        .into_iter()
        .map(|p| p.update_id)
        .max()
        .unwrap();
    let candidate = db.lock().unwrap().prepare_note_package(update_id).unwrap();
    match candidate {
        bh_storage::PackagePreparation::Candidate(c) => c,
        bh_storage::PackagePreparation::Existing(_) => panic!("already packaged"),
    }
}

/// Content behind a removal the control feed judged: content's epoch is
/// still the old one, and this device holds its key, but no new content is
/// sealed under it. Content reaching the removal keeps it closed.
#[test]
fn no_content_is_sealed_under_an_epoch_the_feed_judged_closed() {
    let mut mac = Mac::new();
    let genesis = mac.producer.epoch_id().unwrap();
    assert_eq!(mac.feed(), committed(1));
    mac.pull();
    let key = copy_secret(&mac.keys[&genesis]);
    let seal = |mac: &Mac, window: &str| {
        let candidate = note_candidate(mac, window, "a note");
        mac.owner.prepare_note_seal(
            mac.id,
            &mac.anchor,
            mac.hosting.root.public(),
            &mac.metadata,
            &key,
            &candidate,
        )
    };
    // Feed and content agree: the note seals under the current epoch.
    assert!(seal(&mac, "w1").is_ok());
    let fold = Other::new();
    let add = mac.add(&fold, START);
    assert_eq!(mac.copy_run(&[add]), 2);
    let leave = mac.leave(&fold, START + 1);
    assert_eq!(mac.copy_run(&[leave]), 3);
    // The feed judged the removal; content has not reached it.
    assert_eq!(mac.feed(), committed(3));
    assert_eq!(mac.progress().position, 1);
    assert_eq!(mac.progress().epoch_id, Some(genesis));
    assert!(matches!(
        seal(&mac, "w2"),
        Err(OwnerError::SealRefused(SealRefusal::EpochClosed))
    ));
    mac.pull();
    assert_eq!(mac.progress().position, 3);
    assert!(matches!(
        seal(&mac, "w3"),
        Err(OwnerError::SealRefused(SealRefusal::EpochClosed))
    ));
}

fn committed(at: u64) -> Result<ControlStep, ScanError> {
    Ok(ControlStep::Committed {
        control: at,
        covered: at,
    })
}

/// The base's creator view carries the account home's setup times: the
/// first device matures from the setup's confirmation, not from the first
/// confirmed change after it. Its cancel of its own request to remove a
/// device added later, confirmed after that maturity but before it would
/// have matured from that addition, takes effect in the base's copy of the
/// account.
#[test]
fn the_creator_view_judges_first_device_maturity_from_the_setup_times() {
    let wait = bh_account::REMOVAL_WAIT_MS;
    let setup_at = 1_000;
    let mut mac = Mac::with_setup(Some(setup_at));
    assert_eq!(
        mac.anchor.added_at(mac.cap.device_id()),
        Some(setup_at),
        "the anchor carries the setup's time"
    );
    let fold = Other::new();
    let add = mac.add(&fold, START);
    assert_eq!(mac.copy_run(&[add]), 2);
    // The Mac asks to remove the fold, then cancels once it is mature by
    // its setup, before it would be by the fold's addition.
    let store = mac.store.clone();
    let control = |request: bh_account::SigningRequest| {
        let state = store.state();
        let signature = state
            .control
            .as_ref()
            .unwrap()
            .sign(request.signing_bytes());
        request.finish(signature).unwrap()
    };
    let request = control(
        mac.account
            .verified(&mac.cap)
            .unwrap()
            .request_removal(mac.cap.device_id(), fold.keys().id())
            .unwrap(),
    );
    let requested = mac.ordered(&request, START + 1);
    assert_eq!(mac.copy_run(&[requested]), 3);
    let cancel_at = setup_at + wait + 1;
    assert!(cancel_at < START + wait);
    let cancel = control(
        mac.account
            .verified(&mac.cap)
            .unwrap()
            .cancel_removal(mac.cap.device_id(), request.head().position)
            .unwrap(),
    );
    let cancelled = mac.ordered(&cancel, cancel_at);
    assert_eq!(mac.copy_run(&[cancelled]), 4);
    assert_eq!(mac.feed(), committed(4));
    let fact = mac
        .owner
        .control_fact(mac.id, mac.log_id(), 4)
        .unwrap()
        .unwrap();
    assert!(fact.accepted, "the cancel took effect in the base");
    assert_eq!(
        (fact.account.0, fact.account.1),
        (mac.base_view.head().position, mac.base_view.head().hash)
    );
}

/// The review's trace: controls 1 and 2 delivered, the removal at 4
/// withheld, the rekey at 5 and the removal at 8 delivered with their
/// genuine bytes and the endpoint's receipt. Nothing past 2 may become
/// authority: the rekey does not link to 2, so the scan waits.
#[test]
fn an_omitted_removal_publishes_no_authority_past_it() {
    let Scenario {
        mac,
        fold,
        genesis_epoch,
        ..
    } = scenario();
    assert_eq!(mac.feed_to(8, &[4]).err(), Some(ScanError::Unavailable));
    let view = mac.view();
    assert_eq!(
        view.authorised_at(mac.author(fold.keys().id()), 8),
        Err(LookupError)
    );
    assert_eq!(view.current_key(), Err(LookupError));
    assert_ne!(
        view.current_key().ok().flatten().map(|k| k.key_id),
        Some(genesis_epoch)
    );
    assert_eq!(mac.owner.control_after(mac.id, mac.log_id()).unwrap(), 0);
    // Withholding every control after 2 leaves a short page before the
    // endpoint's raw control: no proof either.
    assert_eq!(
        mac.feed_to(8, &[4, 5, 8]).err(),
        Some(ScanError::Unavailable)
    );
    assert_eq!(view.control_head_at(2), Err(LookupError));
    // The complete read covers it.
    assert_eq!(mac.feed(), committed(8));
    assert!(!view.authorised_at(mac.author(fold.keys().id()), 8).unwrap());
    assert_eq!(view.current_key(), Ok(None));
}

/// A rejected control's first use of its ID is kept: the same original
/// ordered again later is a duplicate, though nothing else about it is
/// wrong there.
#[test]
fn a_rejected_controls_id_is_used_and_its_repeat_is_a_duplicate() {
    let mut mac = Mac::new();
    assert_eq!(mac.mac_note([2; 32], "two"), 2);
    // The author saw a head at 3 the service never ordered there: its copy
    // ordered at 3 claims to have seen its own position.
    let fork = OpaqueEvent::new(EventId([77; 32]), vec![7; 1024]).unwrap();
    let seen_head = Commitment::order(mac.base, mac.log[1].0.after(), &fork, Route::Content)
        .unwrap()
        .head();
    let fold = Other::new();
    let add = mac.add(&fold, START);
    let copy = mac.run_copy_seeing(
        std::slice::from_ref(&add),
        Seen {
            head: seen_head,
            control: mac.last_control,
            account: mac.base_view.head(),
        },
    );
    assert_eq!(mac.order_any(&copy, Route::Control), (3, Outcome::Rejected));
    let garbage = Encoded {
        descriptor: OpaqueEvent::new(EventId([91; 32]), vec![42; 1024]).unwrap(),
        body: vec![42; 1024],
    };
    assert_eq!(mac.order_any(&garbage, Route::Control).1, Outcome::Rejected);
    // The first use is kept durably, across a restart.
    assert_eq!(mac.feed(), committed(4));
    let mut mac = mac.restart();
    // Ordered again, every claim holds; only its ID was used before.
    assert_eq!(mac.order_any(&copy, Route::Control), (5, Outcome::Rejected));
    assert_eq!(mac.feed(), committed(5));
    let fact = |at| {
        mac.owner
            .control_fact(mac.id, mac.log_id(), at)
            .unwrap()
            .unwrap()
    };
    assert!(!fact(3).accepted);
    assert!(!fact(5).accepted, "a repeated ID was accepted");
    assert_eq!(fact(5).event_id, fact(3).event_id);
    let view = mac.view();
    assert!(!view.authorised_at(mac.author(fold.keys().id()), 5).unwrap());
    // The ID's first use is the rejected original.
    assert_eq!(
        view.event_digest(fact(3).event_id),
        Ok(Some(Digest(fact(3).digest)))
    );
}

/// An original and its repeat judged in one scan: the repeat is a
/// duplicate of the first use this scan has not committed yet.
#[test]
fn a_repeated_id_within_one_scan_is_a_duplicate() {
    let mut mac = Mac::new();
    assert_eq!(mac.mac_note([2; 32], "two"), 2);
    let fork = OpaqueEvent::new(EventId([77; 32]), vec![7; 1024]).unwrap();
    let seen_head = Commitment::order(mac.base, mac.log[1].0.after(), &fork, Route::Content)
        .unwrap()
        .head();
    let fold = Other::new();
    let add = mac.add(&fold, START);
    let copy = mac.run_copy_seeing(
        std::slice::from_ref(&add),
        Seen {
            head: seen_head,
            control: mac.last_control,
            account: mac.base_view.head(),
        },
    );
    assert_eq!(mac.order_any(&copy, Route::Control), (3, Outcome::Rejected));
    assert_eq!(mac.order_any(&copy, Route::Control), (4, Outcome::Rejected));
    assert_eq!(mac.feed_to(4, &[]), Ok((committed(4).unwrap(), 1)));
    let fact = |at| {
        mac.owner
            .control_fact(mac.id, mac.log_id(), at)
            .unwrap()
            .unwrap()
    };
    assert!(!fact(4).accepted, "a repeated ID was accepted");
    assert_eq!(fact(4).event_id, fact(3).event_id);
    assert_eq!(
        mac.view().event_digest(fact(3).event_id),
        Ok(Some(Digest(fact(3).digest)))
    );
}

/// The same control bytes ordered on the content route first reserve no
/// control ID and grant nothing; on the control route they apply.
#[test]
fn wrong_route_bytes_neither_reserve_nor_grant_the_control() {
    let mut mac = Mac::new();
    let fold = Other::new();
    let add = mac.add(&fold, START);
    let (seen, _) = mac.seen();
    let copy = mac.run_copy_seeing(std::slice::from_ref(&add), seen);
    assert_eq!(mac.order_any(&copy, Route::Content), (2, Outcome::Rejected));
    // Bounded at the log head, the read covers the wrong-route bytes.
    assert_eq!(
        mac.feed_to(2, &[]).map(|(step, _)| step),
        Ok(ControlStep::Committed {
            control: 1,
            covered: 2
        })
    );
    assert!(
        !mac.view()
            .authorised_at(mac.author(fold.keys().id()), 2)
            .unwrap()
    );
    mac.copied(std::slice::from_ref(&add));
    assert_eq!(mac.order_any(&copy, Route::Control), (3, Outcome::Accepted));
    assert_eq!(mac.feed(), committed(3));
    assert!(
        mac.view()
            .authorised_at(mac.author(fold.keys().id()), 3)
            .unwrap()
    );
}

/// `count` invalid controls, each rejected, ordered after the log's head.
fn rejected_controls(mac: &mut Mac, count: u8) {
    for i in 0..count {
        let garbage = Encoded {
            descriptor: OpaqueEvent::new(EventId([i; 32]), vec![i; 1024]).unwrap(),
            body: vec![i; 1024],
        };
        assert_eq!(mac.order_any(&garbage, Route::Control).1, Outcome::Rejected);
    }
}

#[test]
fn a_scan_reads_pages_against_one_endpoint() {
    let mut mac = Mac::new();
    // Exactly one full page ending at the endpoint's raw control needs no
    // further read.
    rejected_controls(&mut mac, CONTROL_PAGE as u8 - 1);
    assert_eq!(
        mac.feed_to(mac.control_head(), &[]),
        Ok((committed(64).unwrap(), 1))
    );
    // Seventy more: a full page, then the rest against the same endpoint.
    rejected_controls(&mut mac, 70);
    let fold = Other::new();
    let add = mac.add(&fold, START);
    assert_eq!(mac.copy_run(&[add]), 135);
    assert_eq!(
        mac.feed_to(mac.control_head(), &[]),
        Ok((committed(135).unwrap(), 2))
    );
    assert!(
        mac.view()
            .authorised_at(mac.author(fold.keys().id()), 135)
            .unwrap()
    );
}

#[test]
fn a_page_naming_another_endpoint_ends_the_scan_with_nothing_kept() {
    let mut mac = Mac::new();
    rejected_controls(&mut mac, 70);
    let first = mac.control_head();
    let mut scan = mac
        .owner
        .control_scan(mac.id, mac.log_id(), &mac.anchor)
        .unwrap();
    let page = mac.serve(0, first, &[]);
    assert_eq!(scan.page(&mac.metadata, page), Ok(ScanStep::More));
    // A control is appended between the reads: the next page's bound and
    // endpoint move with it.
    rejected_controls(&mut mac, 1);
    let page = mac.serve(scan.after(), mac.control_head(), &[]);
    assert_eq!(scan.page(&mac.metadata, page), Err(ScanError::Unavailable));
    drop(scan);
    assert_eq!(mac.owner.control_after(mac.id, mac.log_id()).unwrap(), 0);
    assert_eq!(mac.view().control_head_at(1), Err(LookupError));
    // A fresh scan freezes the new endpoint and completes.
    assert_eq!(mac.feed(), committed(72));
}

#[test]
fn an_empty_or_short_page_is_not_proof_and_trailing_content_is_covered() {
    let mut mac = Mac::new();
    assert_eq!(mac.feed(), committed(1));
    assert_eq!(mac.mac_note([2; 32], "two"), 2);
    assert_eq!(mac.mac_note([3; 32], "three"), 3);
    // An empty page whose endpoint has the same raw control covers the
    // trailing content, and nothing else changes.
    assert_eq!(
        mac.feed_to(3, &[]),
        Ok((
            ControlStep::Committed {
                control: 1,
                covered: 3
            },
            1
        ))
    );
    let view = mac.view();
    assert_eq!(view.control_head_at(3), Ok(Some(mac.head(1))));
    assert_eq!(view.control_head_at(4), Err(LookupError));
    // Content this device verified after the same last raw control is
    // covered too, with no further read.
    assert_eq!(mac.mac_note([4; 32], "four"), 4);
    assert_eq!(view.control_head_at(4), Err(LookupError));
    mac.pull();
    assert_eq!(mac.progress().position, 4);
    assert_eq!(view.control_head_at(4), Ok(Some(mac.head(1))));
    assert_eq!(
        view.current_key().unwrap().unwrap().installed_at,
        mac.head(1)
    );
    assert_eq!(view.control_head_at(5), Err(LookupError));
    // A control after it, withheld from an empty page: no proof.
    rejected_controls(&mut mac, 1);
    assert_eq!(mac.feed_to(5, &[5]).err(), Some(ScanError::Unavailable));
    assert_eq!(view.control_head_at(5), Err(LookupError));
    // An older endpoint than the coverage changes nothing.
    assert_eq!(
        mac.feed_to(2, &[]).map(|(step, _)| step),
        Ok(ControlStep::Committed {
            control: 1,
            covered: 3
        })
    );
    assert_eq!(mac.feed(), committed(5));
}

#[test]
fn an_endpoint_needs_a_receipt_under_the_pinned_root() {
    let mut mac = Mac::new();
    let fold = Other::new();
    let add = mac.add(&fold, START);
    mac.copy_run(&[add]);
    let other = Hosting::new();
    for receipt in [
        Some(other.receipt(mac.base, mac.head(2))),
        // The pinned root's receipt for a different head.
        Some(mac.hosting.receipt(mac.base, mac.head(1))),
        None,
    ] {
        let mut scan = mac
            .owner
            .control_scan(mac.id, mac.log_id(), &mac.anchor)
            .unwrap();
        let mut page = mac.serve(0, 2, &[]);
        page.receipt = receipt;
        assert_eq!(scan.page(&mac.metadata, page), Err(ScanError::Unavailable));
    }
    assert_eq!(mac.owner.control_after(mac.id, mac.log_id()).unwrap(), 0);
    assert_eq!(mac.feed(), committed(2));
}

/// An endpoint under the pinned root that names another raw control at the
/// position this device's covered chain already reached contradicts it, as
/// does one naming another head where content verified one: that base
/// stops, keeping its facts.
#[test]
fn an_authenticated_endpoint_contradicting_the_covered_chain_stops_the_base() {
    let raw = |mac: &Mac, node: Option<Digest>| RawControlHead {
        position: 2,
        node_hash: node.unwrap_or(mac.log[1].0.after().raw_control().node_hash),
    };
    // Another raw control at 2, its head at a position nothing else knows;
    // the same raw control with a content suffix content verified otherwise.
    for (node, suffix) in [
        (Some(Digest([1; 32])), Digest([0; 32])),
        (None, Digest([3; 32])),
    ] {
        let mut mac = Mac::new();
        let fold = Other::new();
        let add = mac.add(&fold, START);
        mac.copy_run(&[add]);
        assert_eq!(mac.feed(), committed(2));
        assert_eq!(mac.mac_note([3; 32], "three"), 3);
        mac.pull();
        assert_eq!(mac.progress().position, 3);
        let forged = OrderState::new(raw(&mac, node), 1, suffix).unwrap();
        assert_ne!(forged.head(mac.base), mac.head(3));
        stops(&mac, forged);
        assert!(
            mac.view()
                .authorised_at(mac.author(fold.keys().id()), 2)
                .unwrap()
        );
    }
    // Another raw control at the covered one's position, its head where
    // this device knows no other.
    let mac = Mac::new();
    mac.feed().unwrap();
    let forged = OrderState::new(
        RawControlHead {
            position: 1,
            node_hash: Digest([1; 32]),
        },
        3,
        Digest([3; 32]),
    )
    .unwrap();
    stops(&mac, forged);
    // A raw control inside the range an earlier endpoint's receipt proved
    // holds none.
    let mut mac = Mac::new();
    mac.feed().unwrap();
    assert_eq!(mac.mac_note([2; 32], "two"), 2);
    assert_eq!(mac.mac_note([3; 32], "three"), 3);
    mac.feed_to(3, &[]).unwrap();
    let forged = OrderState::new(
        RawControlHead {
            position: 2,
            node_hash: Digest([1; 32]),
        },
        4,
        Digest([3; 32]),
    )
    .unwrap();
    stops(&mac, forged);
    // An endpoint past this device's raw checkpoint naming an earlier last
    // control: the checkpoint's control is missing from it.
    let mut mac = Mac::new();
    let fold = Other::new();
    let add = mac.add(&fold, START);
    mac.copy_run(&[add]);
    assert_eq!(mac.feed(), committed(2));
    let forged = OrderState::new(mac.log[0].0.after().raw_control(), 2, Digest([3; 32])).unwrap();
    assert_eq!(forged.position(), 3);
    stops(&mac, forged);
}

/// A scan given only `forged`, under the pinned root, stops the base.
fn stops(mac: &Mac, forged: OrderState) {
    let mut scan = mac
        .owner
        .control_scan(mac.id, mac.log_id(), &mac.anchor)
        .unwrap();
    let page = ControlPage {
        items: Vec::new(),
        endpoint: forged,
        receipt: Some(mac.hosting.receipt(mac.base, forged.head(mac.base))),
    };
    assert_eq!(scan.page(&mac.metadata, page), Ok(ScanStep::Complete));
    assert_eq!(
        mac.owner.commit_controls(mac.id, scan).unwrap(),
        ControlStep::Stopped
    );
    assert!(mac.progress().stopped.is_some());
}

/// What a hosting service that forked the log after position `keep` serves
/// a scan from the device's cursor `after`: the forked log's controls after
/// it, each with its body where the descriptor names it, and the endpoint
/// at the forked head with a genuine receipt under the pinned root.
fn forked(mac: &Mac, keep: u64, events: &[(&Encoded, Route)], after: u64) -> ControlPage {
    let mut order = mac.log[keep as usize - 1].0.after();
    let mut items = Vec::new();
    for (event, route) in events {
        let ordered = Commitment::order(mac.base, order, &event.descriptor, *route).unwrap();
        order = ordered.after();
        if *route == Route::Control && ordered.head().position > after {
            let named = bh_sync::referenced_body(&event.descriptor).ok();
            let held = bh_sync::BodyObject::new(event.body.clone())
                .is_ok_and(|o| Some(o.commitment()) == named);
            items.push((
                ordered,
                event.descriptor.clone(),
                held.then(|| event.body.clone()),
            ));
        }
    }
    ControlPage {
        items,
        endpoint: order,
        receipt: Some(mac.hosting.receipt(mac.base, order.head(mac.base))),
    }
}

/// A content event or an invalid control, `n` apart from any other.
fn filler(n: u8) -> Encoded {
    Encoded {
        descriptor: OpaqueEvent::new(EventId([150 + n; 32]), vec![n; 1024]).unwrap(),
        body: vec![n; 1024],
    }
}

/// A genuine copy of a device addition, ordered nowhere yet, that saw only
/// the genesis: it links right after it in any log.
fn addition_after_genesis(mac: &mut Mac) -> (Other, Encoded) {
    let fold = Other::new();
    let add = mac.add(&fold, START);
    let copy = mac.run_copy_seeing(
        std::slice::from_ref(&add),
        Seen {
            head: mac.head(1),
            control: mac.digest(1),
            account: mac.base_view.head(),
        },
    );
    (fold, copy)
}

/// One scan of `page` from the durable cursor, committed.
fn scanned(mac: &Mac, page: ControlPage) -> ControlStep {
    let mut scan = mac
        .owner
        .control_scan(mac.id, mac.log_id(), &mac.anchor)
        .unwrap();
    assert_eq!(scan.page(&mac.metadata, page), Ok(ScanStep::Complete));
    mac.owner.commit_controls(mac.id, scan).unwrap()
}

/// A control the service orders inside a range an earlier endpoint's
/// receipt already proved holds none contradicts that receipt: once the
/// linked chain reaches the new endpoint the base stops, and the control
/// grants nothing.
#[test]
fn a_control_inside_a_receipt_covered_range_stops_the_base() {
    let mut mac = Mac::new();
    assert_eq!(mac.feed(), committed(1));
    assert_eq!(mac.mac_note([2; 32], "two"), 2);
    assert_eq!(mac.mac_note([3; 32], "three"), 3);
    assert_eq!(
        mac.feed_to(3, &[]).map(|(step, _)| step),
        Ok(ControlStep::Committed {
            control: 1,
            covered: 3
        })
    );
    // The fork: a genuine addition at 2, content, an invalid control at 5
    // and an endpoint at 6, whose raw control lies past the covered range.
    let (fold, copy) = addition_after_genesis(&mut mac);
    let (c3, c4, garbage, c6) = (filler(3), filler(4), filler(5), filler(6));
    let page = forked(
        &mac,
        1,
        &[
            (&copy, Route::Control),
            (&c3, Route::Content),
            (&c4, Route::Content),
            (&garbage, Route::Control),
            (&c6, Route::Content),
        ],
        1,
    );
    assert_eq!(page.endpoint.raw_control().position, 5);
    assert_eq!(scanned(&mac, page), ControlStep::Stopped);
    assert!(mac.progress().stopped.is_some());
    // Nothing from the fork was kept.
    assert_eq!(mac.owner.control_after(mac.id, mac.log_id()).unwrap(), 1);
    assert!(
        mac.owner
            .control_fact(mac.id, mac.log_id(), 2)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        mac.view().authorised_at(mac.author(fold.keys().id()), 3),
        Ok(false)
    );
}

/// A control at a position where content verified another head, under the
/// same pinned root, stops the base once the endpoint covers it.
#[test]
fn a_control_where_content_verified_another_head_stops_the_base() {
    let mut mac = Mac::new();
    assert_eq!(mac.feed(), committed(1));
    assert_eq!(mac.mac_note([2; 32], "two"), 2);
    assert_eq!(mac.mac_note([3; 32], "three"), 3);
    mac.pull();
    assert_eq!(mac.progress().position, 3);
    let (fold, copy) = addition_after_genesis(&mut mac);
    let (c3, c4) = (filler(3), filler(4));
    let page = forked(
        &mac,
        1,
        &[
            (&copy, Route::Control),
            (&c3, Route::Content),
            (&c4, Route::Content),
        ],
        1,
    );
    assert_eq!(page.endpoint.position(), 4);
    assert_eq!(scanned(&mac, page), ControlStep::Stopped);
    assert!(mac.progress().stopped.is_some());
    assert!(
        mac.owner
            .control_fact(mac.id, mac.log_id(), 2)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        mac.view().authorised_at(mac.author(fold.keys().id()), 3),
        Ok(false)
    );
}

/// An endpoint older than this device's coverage but past a control it
/// names inside that coverage is a contradiction the service made, not
/// local corruption: the base stops.
#[test]
fn an_older_endpoint_past_a_contradicting_control_stops_the_base() {
    let mut mac = Mac::new();
    assert_eq!(mac.feed(), committed(1));
    for at in 2..=5u8 {
        assert_eq!(mac.mac_note([at; 32], "note"), u64::from(at));
    }
    assert_eq!(
        mac.feed_to(5, &[]).map(|(step, _)| step),
        Ok(ControlStep::Committed {
            control: 1,
            covered: 5
        })
    );
    let (_, copy) = addition_after_genesis(&mut mac);
    let c3 = filler(3);
    let page = forked(
        &mac,
        1,
        &[(&copy, Route::Control), (&c3, Route::Content)],
        1,
    );
    assert_eq!(page.endpoint.position(), 3);
    assert_eq!(scanned(&mac, page), ControlStep::Stopped);
    assert!(mac.progress().stopped.is_some());
    assert_eq!(mac.owner.control_after(mac.id, mac.log_id()).unwrap(), 1);
}

/// Facts, first-use IDs, the cursor and its coverage survive restart; an
/// older position answers only inside coverage, and nothing below the
/// history floor is needed: every per-content row may go.
#[test]
fn restart_keeps_coverage_and_ids_and_answers_need_no_content_rows() {
    let Scenario {
        mut mac,
        fold,
        fold2,
        genesis_epoch,
        ..
    } = scenario();
    assert_eq!(mac.feed(), committed(8));
    mac.pull();
    assert_eq!(mac.progress().position, 5);
    let mut mac = mac.restart();
    // Nothing a history expiry deletes is read by the view's methods.
    mac.raw()
        .execute_batch("DELETE FROM log_seen; DELETE FROM log_event_id;")
        .unwrap();
    let view = mac.view();
    let creator = mac.cap.account_id();
    assert_eq!(view.control_head_at(2), Ok(Some(mac.head(2))));
    assert_eq!(view.control_head_at(7), Ok(Some(mac.head(5))));
    // Global heads, never the raw control node.
    assert_ne!(
        view.control_head_at(8).unwrap().unwrap().hash,
        mac.log[7].0.after().raw_control().node_hash
    );
    assert_eq!(view.control_digest_at(4), Ok(Some(mac.digest(4))));
    assert!(view.account_head_at(creator, 8).unwrap().is_some());
    assert!(view.authorised_at(mac.author(fold.keys().id()), 3).unwrap());
    assert!(
        !view
            .authorised_at(mac.author(fold2.keys().id()), 8)
            .unwrap()
    );
    assert_eq!(view.current_key(), Ok(None));
    assert_eq!(view.control_head_at(9), Err(LookupError));
    assert_eq!(view.seen(9), Err(LookupError));
    // A content position the feed covers but content has not verified.
    assert_eq!(view.seen(7), Err(LookupError));
    let _ = genesis_epoch;
    drop(view);
    // The first use of every judged ID is still known: the removal at 4
    // ordered again is a duplicate, not a second removal.
    let (_, descriptor, body) = mac.log[3].clone();
    let encoded = Encoded { descriptor, body };
    let (at, outcome) = mac.order_any(&encoded, Route::Control);
    assert_eq!((at, outcome), (9, Outcome::Rejected));
    assert_eq!(mac.feed(), committed(9));
    assert!(
        !mac.owner
            .control_fact(mac.id, mac.log_id(), 9)
            .unwrap()
            .unwrap()
            .accepted
    );
}

/// A control whose seen receipt, under the pinned root, names a head other
/// than the one the linked chain has at that position proves the service
/// contradicted itself, once the endpoint covers that control: the base
/// stops. Short of that coverage it is only missing evidence.
#[test]
fn a_seen_receipt_contradicting_the_linked_chain_stops_once_covered() {
    let mut mac = Mac::new();
    rejected_controls(&mut mac, 1);
    let forged = Head {
        position: 2,
        hash: Digest([5; 32]),
    };
    assert_ne!(forged, mac.head(2));
    let fold = Other::new();
    let add = mac.add(&fold, START);
    let copy = mac.run_copy_seeing(
        std::slice::from_ref(&add),
        Seen {
            head: forged,
            control: mac.last_control,
            account: mac.base_view.head(),
        },
    );
    assert_eq!(mac.order_unjudged(&copy, Route::Control), 3);
    rejected_controls_unjudged(&mut mac, 1);
    // The endpoint withheld from the scan: nothing is proven.
    assert_eq!(mac.feed_to(4, &[4]).err(), Some(ScanError::Unavailable));
    assert!(mac.progress().stopped.is_none());
    assert_eq!(mac.feed(), Ok(ControlStep::Stopped));
    assert!(mac.progress().stopped.is_some());
}

fn rejected_controls_unjudged(mac: &mut Mac, count: u8) {
    for i in 0..count {
        let garbage = Encoded {
            descriptor: OpaqueEvent::new(EventId([200 + i; 32]), vec![i; 1024]).unwrap(),
            body: vec![i; 1024],
        };
        mac.order_unjudged(&garbage, Route::Control);
    }
}
