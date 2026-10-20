//! Verified base-log batches applied to each note's accepted state, kept apart
//! from this device's pending work, and committed atomically with progress.
//! Every event here is really sealed, ordered and verified by `History`
//! under a pinned hosting root, from a real signed-up account and own base.
use bh_account::{
    DeviceId, DevicePublicKeys, VerifiedAccount,
    journal::AccountJournal,
    owner::{AccountCapability, AccountGeneration, AccountLoad, AccountOwner},
    platform::ControlKeyPolicy,
    recovery::Password,
    storage::DeviceJournal,
};
use bh_core::note::Note;
use bh_crypto::{KemKey, Secret, SigningKey};
use bh_device::{
    ContainerId, Owner, OwnerError, SealRefusal,
    coordinator::Delivery,
    incoming::{LogId, LogKind, NoteOutcome, RefusalReason, StopReason, Unaccepted, VerifiedBatch},
    own_base::create_or_open,
};
use bh_event::{
    ACCOUNT_CHANGE, Binding, CLASS_CONTENT, CLASS_CONTROL, Encoded, History, NOTE, Payload, key_id,
    note_payload, seal,
    writer::{DeviceWriterDeclaration, WriterScope},
};
use bh_storage::{NoteKey, StoreError, sync_state::SyncAlarm};
use bh_sync::{
    BaseId, BodyObject, Commitment, Digest, EventId, Head, OpaqueEvent, Route,
    receipt::{self, CertifiedReceiptKey, RECEIPT_LEN},
};
use rusqlite::types::Value;
use std::{cell::RefCell, future::Future, sync::Arc, time::Instant};

#[allow(dead_code)]
#[path = "../../account/tests/support/protector.rs"]
mod protector;
#[path = "../../account/tests/support/store.rs"]
mod store;

type Account = AccountOwner<DeviceJournal, store::FakeStore, protector::PlainProtector>;

#[test]
fn incoming_log_id_is_the_permit_log_id_and_storage_codes_match_the_wire() {
    fn accepts_permit_log(_: bh_sync::permit::LogId) {}
    for (kind, wire, stored) in [
        (LogKind::Base, 1, bh_storage::sync_state::LOG_BASE),
        (LogKind::Account, 2, bh_storage::sync_state::LOG_ACCOUNT),
    ] {
        accepts_permit_log(LogId { kind, id: [0; 32] });
        assert_eq!(kind as u8, wire);
        assert_eq!(stored, wire);
    }
}

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

struct Fixture {
    dir: tempfile::TempDir,
    owner: Owner,
    id: ContainerId,
    cap: Arc<AccountCapability>,
    store: store::FakeStore,
    base: BaseId,
    metadata: Secret<32>,
    content: Secret<32>,
    hosting: Hosting,
    history: History,
    control: [u8; 32],
    /// Descriptor digests of the control-class events `seal_binding`
    /// sealed, so each is ordered on the control route.
    controls: RefCell<Vec<Digest>>,
    anchor: VerifiedAccount,
    account: Option<Account>,
}

impl Fixture {
    /// Sign up, create the own base, register it and apply its genesis.
    fn new() -> Self {
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
        account.confirm_home_ordered(status.head).unwrap();
        account.confirm_kit_saved().unwrap();
        let record = DeviceJournal::from_shared(db.clone())
            .load()
            .unwrap()
            .unwrap();
        let history = record.history.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let verified = VerifiedAccount::replay(record.anchor, &history, record.head).unwrap();
        owner.anchor(id, &verified).unwrap();
        let cap = match ready(account.activate()).unwrap() {
            AccountLoad::Active(c) => Arc::new(c),
            _ => panic!("not active"),
        };
        let own = ready(create_or_open(&mut account, cap.clone(), db.clone())).unwrap();
        let base = own.id();
        let (metadata, content) = own
            .with_keys(|m, k| {
                (
                    Secret::from_slice(m.expose()).unwrap(),
                    Secret::from_slice(k.expose()).unwrap(),
                )
            })
            .unwrap();
        let stored = db.lock().unwrap().own_base().unwrap().unwrap();
        owner.authorize(id, cap.clone(), base.0).unwrap();
        let hosting = Hosting::new();
        let history = History::with_account(&verified, base, hosting.root.public(), 1).unwrap();
        let genesis = Encoded {
            descriptor: OpaqueEvent::decode(&stored.genesis_descriptor).unwrap(),
            body: stored.genesis_body.clone(),
        };
        let mut fixture = Self {
            dir,
            owner,
            id,
            cap,
            store,
            base,
            metadata,
            content,
            hosting,
            history,
            control: [0; 32],
            controls: RefCell::new(Vec::new()),
            anchor: verified,
            account: Some(account),
        };
        fixture
            .owner
            .record_registration(
                fixture.id,
                base.0,
                Some(fixture.hosting.receipt(base, Head::EMPTY)),
                fixture.hosting.root.public(),
            )
            .unwrap();
        fixture.control = Commitment::order(base, Head::EMPTY, &genesis.descriptor, Route::Control)
            .unwrap()
            .event_digest()
            .0;
        assert!(fixture.apply(&[&genesis]).is_empty());
        fixture
    }
    fn log(&self) -> LogId {
        LogId {
            kind: LogKind::Base,
            id: self.base.0,
        }
    }
    fn key(&self, note: [u8; 32]) -> NoteKey {
        NoteKey {
            base: self.base.0,
            audience: [0; 32],
            note,
        }
    }
    fn writer(&self, nonce: [u8; 32]) -> DeviceWriterDeclaration {
        DeviceWriterDeclaration {
            account: self.cap.account_id().0,
            device: self.cap.device_id().0,
            nonce,
        }
    }
    fn client(&self, note: [u8; 32], writer: DeviceWriterDeclaration) -> u64 {
        writer.client_id(WriterScope {
            base: self.base.0,
            audience: [0; 32],
            note,
        })
    }
    fn seal(
        &self,
        event_id: EventId,
        note: [u8; 32],
        writer: DeviceWriterDeclaration,
        update: &[u8],
    ) -> Encoded {
        let receipt = self.hosting.receipt(self.base, self.history.head());
        self.seal_with_receipt(event_id, note, writer, update, receipt)
    }
    fn seal_with_receipt(
        &self,
        event_id: EventId,
        note: [u8; 32],
        writer: DeviceWriterDeclaration,
        update: &[u8],
        receipt: [u8; RECEIPT_LEN],
    ) -> Encoded {
        let binding = self.binding(event_id, self.cap.device_id(), CLASS_CONTENT, receipt);
        let state = self.store.state();
        self.seal_binding(
            binding,
            NOTE,
            &note_payload(note, writer, update),
            state.ordinary.as_ref().unwrap(),
        )
    }
    /// A v2 binding by one of this account's devices, seeing this head.
    fn binding(
        &self,
        event_id: EventId,
        device: DeviceId,
        class: u8,
        receipt: [u8; RECEIPT_LEN],
    ) -> Binding {
        Binding {
            version: 2,
            highest: 2,
            mode: 0,
            base: self.base.0,
            audience: [0; 32],
            epoch: key_id(if class == CLASS_CONTROL {
                &self.metadata
            } else {
                &self.content
            }),
            event_id,
            account: self.cap.account_id(),
            device,
            account_head: self.history.account_head(),
            seen: self.history.head(),
            seen_control: self.control,
            class,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: receipt,
        }
    }
    fn seal_binding(
        &self,
        binding: Binding,
        kind: u16,
        data: &[u8],
        signer: &SigningKey,
    ) -> Encoded {
        let content = (binding.class == CLASS_CONTENT).then_some(&self.content);
        let encoded = seal(
            binding,
            Payload { kind, data },
            signer,
            &self.metadata,
            content,
        )
        .unwrap();
        if binding.class == CLASS_CONTROL {
            self.controls.borrow_mut().push(encoded.descriptor.digest());
        }
        encoded
    }
    /// An account change adding a new device, signed by this device under
    /// `event_id`. Returns the new device's ID and signing key.
    fn add_device(&self, event_id: EventId) -> (Encoded, DeviceId, SigningKey) {
        let signing = SigningKey::generate();
        let keys = DevicePublicKeys::new(
            signing.public(),
            SigningKey::generate().public(),
            KemKey::generate().public(),
        )
        .unwrap();
        let device = keys.id();
        let state = self.store.state();
        let control = state.control.as_ref().unwrap();
        let request = self.anchor.add_device(self.cap.device_id(), keys).unwrap();
        let change = request
            .finish(control.sign(request.signing_bytes()))
            .unwrap();
        let binding = self.binding(
            event_id,
            self.cap.device_id(),
            CLASS_CONTROL,
            self.hosting.receipt(self.base, self.history.head()),
        );
        let encoded = self.seal_binding(binding, ACCOUNT_CHANGE, change.as_bytes(), control);
        (encoded, device, signing)
    }
    /// The route a log object orders this event on after `previous`: the
    /// class it was sealed with.
    fn route(&self, previous: Head, event: &OpaqueEvent) -> Route {
        if previous == Head::EMPTY || self.controls.borrow().contains(&event.digest()) {
            Route::Control
        } else {
            Route::Content
        }
    }
    /// Apply a control on its own and remember it as the latest seen.
    fn apply_control(&mut self, control: &Encoded) {
        let ordered = Commitment::order(
            self.base,
            self.history.head(),
            &control.descriptor,
            Route::Control,
        )
        .unwrap();
        assert!(self.apply(&[control]).is_empty());
        self.control = ordered.event_digest().0;
    }
    /// This device's committed "mine" in a new note, with its pending ID.
    fn own_work(&mut self) -> ([u8; 32], i64) {
        let note = self.owner.create_note(self.id).unwrap();
        self.owner.show_note("w", self.id, note).unwrap();
        let opened = self.owner.open_leased("w", note).unwrap();
        let lease = opened.writer.unwrap();
        let delta = Owner::core_author(&opened)
            .unwrap()
            .try_append_paragraph("mine")
            .unwrap();
        self.owner
            .commit_leased("w", opened.generation, lease.token, [1; 16], &delta)
            .unwrap();
        let ids = self.pending_ids();
        (note, *ids.last().unwrap())
    }
    fn progress(&self) -> bh_storage::sync_state::LogProgress {
        let db = self.owner.shared_database(self.id).unwrap();
        let progress = db.lock().unwrap().log_progress(1, self.base.0).unwrap();
        progress.unwrap()
    }
    /// Another producer's event: this account and device, its own writer slot.
    fn remote(&self, note: [u8; 32], nonce: [u8; 32], update: &[u8]) -> Encoded {
        self.seal(
            EventId(bh_crypto::random()),
            note,
            self.writer(nonce),
            update,
        )
    }
    /// Order and verify these events after `history`'s head, as a puller does.
    fn batch_from(&self, history: &mut History, events: &[&Encoded]) -> VerifiedBatch {
        let mut applied = Vec::new();
        for event in events {
            let route = self.route(history.head(), &event.descriptor);
            let ordered =
                Commitment::order(self.base, history.head(), &event.descriptor, route).unwrap();
            let prepared = history
                .prepare(
                    &ordered,
                    &event.descriptor,
                    Some(&event.body),
                    &self.metadata,
                    Some(&self.content),
                )
                .unwrap();
            applied.push(history.consume_unapplied(prepared).unwrap());
        }
        VerifiedBatch {
            log: self.log(),
            events: applied,
            head: history.head(),
            receipt: self.hosting.receipt(self.base, history.head()),
        }
    }
    fn batch(&mut self, events: &[&Encoded]) -> VerifiedBatch {
        let mut history = self.history.clone();
        let batch = self.batch_from(&mut history, events);
        self.history = history;
        batch
    }
    fn apply(&mut self, events: &[&Encoded]) -> Vec<(NoteKey, NoteOutcome)> {
        let batch = self.batch(events);
        self.owner.apply_remote_batch(self.id, batch).unwrap()
    }
    fn accepted(&self, note: [u8; 32]) -> Note {
        let db = self.owner.shared_database(self.id).unwrap();
        let accepted = db.lock().unwrap().accepted_note(self.key(note)).unwrap();
        Note::from_ordered(&accepted.ordered()).unwrap()
    }
    fn working(&self, note: [u8; 32]) -> Note {
        let db = self.owner.shared_database(self.id).unwrap();
        let ordered = db.lock().unwrap().note_ordered(self.key(note)).unwrap();
        Note::from_ordered(&ordered).unwrap()
    }
    fn pending(&self) -> usize {
        let db = self.owner.shared_database(self.id).unwrap();
        db.lock().unwrap().pending_note_updates().unwrap().len()
    }
    /// This device's sealed package for a pending update, as its outbox makes it.
    fn package(&self, update_id: i64) -> Encoded {
        self.package_with_receipt(
            update_id,
            self.hosting.receipt(self.base, self.history.head()),
        )
    }
    fn package_with_receipt(&self, update_id: i64, receipt: [u8; RECEIPT_LEN]) -> Encoded {
        let db = self.owner.shared_database(self.id).unwrap();
        let candidate = match db.lock().unwrap().prepare_note_package(update_id).unwrap() {
            bh_storage::PackagePreparation::Candidate(c) => c,
            bh_storage::PackagePreparation::Existing(_) => panic!("already packaged"),
        };
        let writer = bh_device::writers::pending_declaration(&candidate.pending)
            .unwrap()
            .unwrap();
        let encoded = self.seal_with_receipt(
            candidate.event_id,
            candidate.pending.key.note,
            writer,
            &candidate.pending.bytes,
            receipt,
        );
        db.lock()
            .unwrap()
            .publish_note_package(
                candidate,
                encoded.descriptor.clone(),
                BodyObject::new(encoded.body.clone()).unwrap(),
            )
            .unwrap();
        encoded
    }
    /// The append's Ack for this device's package, arriving before its echo.
    fn ack(&self, update_id: i64, ordered: &Commitment) {
        let db = self.owner.shared_database(self.id).unwrap();
        db.lock()
            .unwrap()
            .acknowledge_note_update(update_id, ordered)
            .unwrap();
    }
    fn unaccepted(&self, note: [u8; 32]) -> Vec<(i64, Unaccepted)> {
        self.owner
            .unaccepted(self.id, self.key(note))
            .unwrap()
            .into_iter()
            .map(|p| (p.update_id, p.state))
            .collect()
    }
    fn alarms(&self) -> Vec<SyncAlarm> {
        let db = self.owner.shared_database(self.id).unwrap();
        db.lock().unwrap().sync_alarms().unwrap()
    }
    fn pending_ids(&self) -> Vec<i64> {
        let db = self.owner.shared_database(self.id).unwrap();
        db.lock()
            .unwrap()
            .pending_note_updates()
            .unwrap()
            .iter()
            .map(|p| p.update_id)
            .collect()
    }
    fn raw(&self) -> rusqlite::Connection {
        let path = std::fs::read_dir(self.dir.path().join("accounts"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "sqlite"))
            .unwrap();
        rusqlite::Connection::open(path).unwrap()
    }
    fn dump(&self) -> Vec<Vec<Vec<Value>>> {
        let raw = self.raw();
        [
            "log_progress",
            "held_note_event",
            "accepted_note",
            "accepted_note_tail",
            "writer_binding",
            "note_outbox",
            "note_outbox_progress",
            "log_seen",
            "log_event_id",
            "log_account_change",
            "log_floor",
            "sync_alarm",
            "note_updates",
            "pending_note_work",
            "pending_scope",
            "note_checkpoints",
            "notes",
            "note_counter",
        ]
        .iter()
        .map(|table| {
            let columns = raw
                .prepare(&format!("SELECT * FROM {table}"))
                .unwrap()
                .column_count();
            let order: Vec<String> = (1..=columns).map(|c| c.to_string()).collect();
            let mut stmt = raw
                .prepare(&format!(
                    "SELECT * FROM {table} ORDER BY {}",
                    order.join(",")
                ))
                .unwrap();
            stmt.query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        })
        .collect()
    }
    fn drain(&self, window: &str) -> Vec<Delivery> {
        let mut seen = Vec::new();
        assert!(self.owner.drain_surface(window, &mut |d| seen.push(d)));
        seen
    }
}

/// A window's copy: the opened ordered state, then each delivery in turn.
fn replay_window(opened: &bh_core::note::OrderedState, deliveries: &[Delivery]) -> Note {
    let mut view = Note::from_ordered(opened).unwrap();
    for d in deliveries {
        if d.reload {
            view = Note::new().unwrap();
        }
        if d.resync {
            for segment in &d.segments {
                view.apply_update(segment).unwrap();
            }
        } else {
            view.apply_update(&d.update).unwrap();
        }
    }
    view
}

fn var(out: &mut Vec<u8>, mut n: u64) {
    while n >= 128 {
        out.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// One string item with a left and an optional right origin (lib0 v1).
fn item(
    client: u64,
    clock: u32,
    origin: (u64, u32),
    right: Option<(u64, u32)>,
    text: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    var(&mut out, 1);
    var(&mut out, 1);
    var(&mut out, client);
    var(&mut out, clock as u64);
    out.push(0x84 | if right.is_some() { 0x40 } else { 0 });
    var(&mut out, origin.0);
    var(&mut out, origin.1 as u64);
    if let Some((c, k)) = right {
        var(&mut out, c);
        var(&mut out, k as u64);
    }
    var(&mut out, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
    var(&mut out, 0);
    out
}

/// A paragraph with "hello" by writer `s`: clocks 0..7, the text ends at 6.
fn seed(s: u64) -> Vec<u8> {
    let mut author = Note::with_writer(s).unwrap();
    author.append_paragraph("hello").unwrap()
}

fn nonce(tag: u8, counter: u32) -> [u8; 32] {
    let mut n = [0; 32];
    n[0] = tag;
    n[1..5].copy_from_slice(&counter.to_be_bytes());
    n
}

fn digest_of(updates: &[&[u8]]) -> ([u8; 32], String) {
    let mut note = Note::new().unwrap();
    for u in updates {
        note.apply_update(u).unwrap();
    }
    (note.digest().unwrap(), note.title_preview().unwrap())
}

#[test]
fn unavailable_note_waits_without_holding_log_progress() {
    let mut f = Fixture::new();
    let (note, _) = f.own_work();
    let writer = f.writer([9; 32]);
    let event = f.remote(note, [9; 32], &seed(f.client(note, writer)));
    let batch = f.batch(&[&event]);
    let before = f.progress();
    let accepted = f.accepted(note).state().unwrap();
    let working = f.working(note).state().unwrap();
    let db = f.owner.shared_database(f.id).unwrap();
    let pending = || {
        db.lock()
            .unwrap()
            .pending_note_updates()
            .unwrap()
            .into_iter()
            .map(|p| (p.update_id, p.bytes))
            .collect::<Vec<_>>()
    };
    let before_pending = pending();
    let failed = bh_core::contained::with_fuel(0, || f.owner.apply_remote_batch(f.id, batch));
    assert_eq!(failed.unwrap(), vec![(f.key(note), NoteOutcome::Waiting)]);
    assert_eq!(f.progress().position, before.position + 1);
    assert!(f.progress().stopped.is_none());
    assert_eq!(f.accepted(note).state().unwrap(), accepted);
    assert_eq!(f.working(note).state().unwrap(), working);
    assert_eq!(pending(), before_pending);
    // Appending to a held note cannot open the engine, even under zero fuel.
    let next = f.remote(note, [10; 32], &seed(f.client(note, f.writer([10; 32]))));
    let batch = f.batch(&[&next]);
    let waiting = bh_core::contained::with_fuel(0, || f.owner.apply_remote_batch(f.id, batch));
    assert_eq!(waiting.unwrap(), vec![(f.key(note), NoteOutcome::Waiting)]);
    assert_eq!(f.progress().position, before.position + 2);
    assert_eq!(pending(), before_pending);
}

#[test]
fn held_exact_echo_is_not_rejected_by_duplicates_and_retries_to_acceptance() {
    let mut f = Fixture::new();
    let (note, id) = f.own_work();
    let own = f.package(id);
    let batch = f.batch(&[&own, &own]);
    let waiting =
        bh_core::contained::with_fuel(0, || f.owner.apply_remote_batch(f.id, batch)).unwrap();
    assert_eq!(waiting, vec![(f.key(note), NoteOutcome::Waiting)]);
    assert_eq!(f.unaccepted(note), vec![(id, Unaccepted::Acked)]);
    assert!(f.apply(&[&own]).is_empty());
    assert_eq!(f.unaccepted(note), vec![(id, Unaccepted::Acked)]);
    let db = f.owner.shared_database(f.id).unwrap();
    assert!(db.lock().unwrap().outbox_heads(0, 256).unwrap().is_empty());
    assert_eq!(
        db.lock()
            .unwrap()
            .package_progress(id)
            .unwrap()
            .unwrap()
            .outcome,
        Some(bh_storage::sync_state::PackageOutcome::Held)
    );
    let held = db
        .lock()
        .unwrap()
        .next_held_event(f.key(note), 0)
        .unwrap()
        .unwrap();
    assert_eq!(held.own_update, Some(id));
    assert_eq!(
        held.delta.as_deref(),
        Some(
            db.lock().unwrap().pending_note_updates().unwrap()[0]
                .bytes
                .as_slice()
        )
    );
    let before = f.progress();
    let (outcomes, _) = f.owner.retry_held(f.id, f.key(note)).unwrap();
    assert_eq!(outcomes, vec![(f.key(note), NoteOutcome::Accepted)]);
    assert_eq!(f.progress(), before);
    assert_eq!(f.pending(), 0);
    assert!(!db.lock().unwrap().has_held_notes().unwrap());
    assert_eq!(
        f.accepted(note).digest().unwrap(),
        f.working(note).digest().unwrap()
    );
}

fn trap_update(client: u64) -> Vec<u8> {
    let mut bomb = vec![1, 1];
    var(&mut bomb, client);
    bomb.extend_from_slice(&[0, 8, 1, 4, b'b', b'o', b'm', b'b', 1]);
    for _ in 0..100_000 {
        bomb.extend_from_slice(&[117, 1]);
    }
    bomb.extend_from_slice(&[126, 0]);
    bomb
}

#[test]
fn a_trapped_note_defers_its_whole_share_not_a_healthy_notes_echo() {
    let mut f = Fixture::new();
    let (healthy, id) = f.own_work();
    let own = f.package(id);
    let poisoned = [222; 32];
    let writer = f.writer([42; 32]);
    let client = f.client(poisoned, writer);
    let first = f.remote(poisoned, [42; 32], &seed(client));
    let bomb = f.remote(
        poisoned,
        [43; 32],
        &trap_update(f.client(poisoned, f.writer([43; 32]))),
    );
    let remote = f.remote(
        healthy,
        [44; 32],
        &seed(f.client(healthy, f.writer([44; 32]))),
    );
    let batch = f.batch(&[&first, &own, &bomb, &remote]);
    let head = batch.head;
    assert_eq!(
        f.owner.apply_remote_batch(f.id, batch).unwrap(),
        vec![
            (f.key(poisoned), NoteOutcome::Waiting),
            (f.key(healthy), NoteOutcome::Accepted),
            (f.key(poisoned), NoteOutcome::Waiting),
            (f.key(healthy), NoteOutcome::Accepted)
        ]
    );
    assert_eq!(f.progress().position, head.position);
    assert_eq!(f.pending(), 0);
    let db = f.owner.shared_database(f.id).unwrap();
    assert_eq!(
        db.lock()
            .unwrap()
            .accepted_note(f.key(poisoned))
            .unwrap()
            .through,
        0
    );
    assert_eq!(
        f.raw()
            .query_row(
                "SELECT COUNT(*) FROM notes WHERE note=?1",
                [poisoned.as_slice()],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        f.raw()
            .query_row(
                "SELECT COUNT(*) FROM writer_binding WHERE note=?1",
                [poisoned.as_slice()],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    let before = f.progress();
    // The good prefix is released once; the permanent trap remains held.
    let (released, _) = f.owner.retry_held(f.id, f.key(poisoned)).unwrap();
    assert_eq!(
        released,
        vec![
            (f.key(poisoned), NoteOutcome::Accepted),
            (f.key(poisoned), NoteOutcome::Waiting)
        ]
    );
    assert_eq!(f.accepted(poisoned).title_preview().unwrap(), "hello");
    assert_eq!(f.progress(), before);
    let before = f.dump();
    let (again, _) = f.owner.retry_held(f.id, f.key(poisoned)).unwrap();
    assert_eq!(again, vec![(f.key(poisoned), NoteOutcome::Waiting)]);
    assert_eq!(f.dump(), before);
    f.owner.show_note("healthy", f.id, healthy).unwrap();
    assert!(
        f.owner
            .open_leased("healthy", healthy)
            .unwrap()
            .writer
            .is_some()
    );
}

#[test]
fn transient_hold_releases_like_an_uninterrupted_device() {
    let mut f = Fixture::new();
    let (note, id) = f.own_work();
    let own = f.package(id);
    let remote = f.remote(note, [9; 32], &seed(f.client(note, f.writer([9; 32]))));
    let malformed = f.remote(note, [10; 32], &[255, 255, 255]);
    let events = [&remote, &malformed, &own];
    // A consistent SQLite copy of this synthetic device, before either path
    // judges the identical signed events. Both use the production owner API.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("accounts")).unwrap();
    let path = dir
        .path()
        .join("accounts/00000000000000000000000000000000.sqlite");
    f.raw()
        .execute("VACUUM INTO ?1", [path.to_str().unwrap()])
        .unwrap();
    let control = Owner::default();
    let control_id = control
        .open_containers(dir.path())
        .unwrap()
        .remove(0)
        .1
        .unwrap();
    control.anchor(control_id, &f.anchor).unwrap();
    control
        .authorize(control_id, f.cap.clone(), f.base.0)
        .unwrap();
    let mut history = f.history.clone();
    let uninterrupted = control
        .apply_remote_batch(control_id, f.batch_from(&mut history, &events))
        .unwrap();
    let batch = f.batch(&events);
    let waiting =
        bh_core::contained::with_fuel(0, || f.owner.apply_remote_batch(f.id, batch)).unwrap();
    assert!(waiting.iter().all(|(_, o)| *o == NoteOutcome::Waiting));
    let before = f.progress();
    let (released, _) = f.owner.retry_held(f.id, f.key(note)).unwrap();
    assert_eq!(released, uninterrupted);
    assert_eq!(
        released[1].1,
        NoteOutcome::Refused(RefusalReason::Undecodable)
    );
    assert_eq!(f.progress(), before);
    let db = control.shared_database(control_id).unwrap();
    let db = db.lock().unwrap();
    let accepted = Note::from_ordered(&db.accepted_note(f.key(note)).unwrap().ordered()).unwrap();
    let working = Note::from_ordered(&db.note_ordered(f.key(note)).unwrap()).unwrap();
    assert_eq!(
        accepted.digest().unwrap(),
        f.accepted(note).digest().unwrap()
    );
    assert_eq!(working.digest().unwrap(), f.working(note).digest().unwrap());
    assert_eq!(
        db.package_progress(id).unwrap(),
        f.owner
            .shared_database(f.id)
            .unwrap()
            .lock()
            .unwrap()
            .package_progress(id)
            .unwrap()
    );
}

#[test]
fn two_notes_settle_the_healthy_own_echo_and_hold_the_poisoned_own_echo() {
    let mut f = Fixture::new();
    let (healthy, hid) = f.own_work();
    let honest = f.package(hid);
    let (poisoned, pid) = f.own_work();
    let held_own = f.package(pid);
    let bomb = f.remote(
        poisoned,
        [43; 32],
        &trap_update(f.client(poisoned, f.writer([43; 32]))),
    );
    let remote = f.remote(
        healthy,
        [44; 32],
        &seed(f.client(healthy, f.writer([44; 32]))),
    );
    let accepted = f.accepted(poisoned).state().unwrap();
    let working = f.working(poisoned).state().unwrap();
    let batch = f.batch(&[&honest, &held_own, &remote, &bomb]);
    let ordered = batch.events[1].commitment();
    let tail = batch.head;
    assert_eq!(
        f.owner.apply_remote_batch(f.id, batch).unwrap(),
        vec![
            (f.key(healthy), NoteOutcome::Accepted),
            (f.key(poisoned), NoteOutcome::Waiting),
            (f.key(healthy), NoteOutcome::Accepted),
            (f.key(poisoned), NoteOutcome::Waiting)
        ]
    );
    assert_eq!(f.pending_ids(), vec![pid]);
    assert_eq!(f.progress().position, tail.position);
    assert_eq!(f.accepted(poisoned).state().unwrap(), accepted);
    assert_eq!(f.working(poisoned).state().unwrap(), working);
    assert_eq!(f.unaccepted(poisoned), vec![(pid, Unaccepted::Acked)]);
    let db = f.owner.shared_database(f.id).unwrap();
    let held = db
        .lock()
        .unwrap()
        .next_held_event(f.key(poisoned), 0)
        .unwrap()
        .unwrap();
    assert_eq!(held.ordered, ordered);
    assert_eq!(held.own_update, Some(pid));
    assert_eq!(
        f.raw()
            .query_row(
                "SELECT title FROM notes WHERE note=?1",
                [poisoned.as_slice()],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
        "mine"
    );
}

/// Prepare a real authenticated own echo for the storage release boundary.
/// The interleaving below deliberately stops *after* preparation, not before
/// Owner's early check. The same prepared input also has a successful control.
fn prepared_held_own(
    f: &mut Fixture,
) -> (
    bh_storage::sync_state::IncomingNote,
    bh_storage::sync_state::OwnOutcome,
) {
    use bh_storage::sync_state::{IncomingNote, OwnOutcome, PackageOutcome};
    let (note, id) = f.own_work();
    let own = f.package(id);
    let batch = f.batch(&[&own]);
    bh_core::contained::with_fuel(0, || f.owner.apply_remote_batch(f.id, batch)).unwrap();
    let key = f.key(note);
    let db = f.owner.shared_database(f.id).unwrap();
    let held = db.lock().unwrap().next_held_event(key, 0).unwrap().unwrap();
    let delta = held.delta.unwrap();
    let (account, device, nonce) = held.writer.unwrap();
    let client_id = f.client(
        note,
        DeviceWriterDeclaration {
            account,
            device,
            nonce,
        },
    );
    let mut accepted = f.accepted(note);
    accepted.apply_incoming(&delta, client_id).unwrap();
    let mut state = db.lock().unwrap().accepted_note(key).unwrap().ordered();
    state.push(delta.clone());
    let prepared = IncomingNote {
        key,
        accepted: vec![(held.ordered.head().position, delta)],
        compacted: None,
        bindings: vec![bh_storage::sync_state::AcceptedBinding {
            client_id,
            account,
            device,
            nonce,
            accepted_end: accepted.writer_end(client_id).unwrap().unwrap(),
        }],
        remote: Vec::new(),
        rebuild_working: Some(state),
        title: Some("mine".into()),
    };
    let own = OwnOutcome {
        update_id: id,
        ordered: held.ordered,
        outcome: PackageOutcome::Accepted,
        publishing_stopped: false,
    };
    (prepared, own)
}

#[test]
fn storage_stop_keeps_the_owner_stop_classification() {
    assert!(matches!(
        OwnerError::from(StoreError::LogStopped),
        OwnerError::Stopped
    ));
}

#[test]
fn prepared_held_release_requires_base_progress() {
    let mut f = Fixture::new();
    let (prepared, own) = prepared_held_own(&mut f);
    f.raw().execute("DELETE FROM log_progress", []).unwrap();
    let before = f.dump();
    let db = f.owner.shared_database(f.id).unwrap();
    let result = db
        .lock()
        .unwrap()
        .release_held(&prepared, own.ordered.head().position, &[own]);
    assert!(
        matches!(result, Err(StoreError::MissingProgress)),
        "{result:?}"
    );
    assert_eq!(f.dump(), before);
}

#[test]
fn prepared_held_release_is_fenced_by_a_later_stop() {
    let mut f = Fixture::new();
    let (prepared, own) = prepared_held_own(&mut f);
    f.owner
        .record_stop(f.id, f.log(), StopReason::Integrity)
        .unwrap();
    let before = f.dump();
    let db = f.owner.shared_database(f.id).unwrap();
    let result = db
        .lock()
        .unwrap()
        .release_held(&prepared, own.ordered.head().position, &[own]);
    assert!(matches!(result, Err(StoreError::LogStopped)), "{result:?}");
    assert_eq!(f.dump(), before);
    assert!(matches!(
        f.owner.retry_held(f.id, prepared.key),
        Err(OwnerError::Stopped)
    ));
    assert!(!f.owner.has_queued_delivery("w"));
}

#[test]
fn prepared_held_release_allows_unrelated_log_progress() {
    let mut f = Fixture::new();
    let (prepared, own) = prepared_held_own(&mut f);
    let earlier = f.progress();
    let other = [221; 32];
    let event = f.remote(other, [89; 32], &seed(f.client(other, f.writer([89; 32]))));
    assert_eq!(
        f.apply(&[&event]),
        vec![(f.key(other), NoteOutcome::Accepted)]
    );
    let later = f.progress();
    assert!(later.position > earlier.position);
    let db = f.owner.shared_database(f.id).unwrap();
    db.lock()
        .unwrap()
        .release_held(&prepared, own.ordered.head().position, &[own])
        .unwrap();
    assert_eq!(f.progress(), later);
    assert_eq!(f.pending(), 0);
    assert!(!db.lock().unwrap().note_is_held(prepared.key).unwrap());
    assert_eq!(
        f.accepted(prepared.key.note).digest().unwrap(),
        f.working(prepared.key.note).digest().unwrap()
    );
}

#[test]
fn release_failure_keeps_hold_pending_and_all_note_tables() {
    let mut f = Fixture::new();
    let (note, id) = f.own_work();
    let own = f.package(id);
    let batch = f.batch(&[&own]);
    bh_core::contained::with_fuel(0, || f.owner.apply_remote_batch(f.id, batch)).unwrap();
    let raw = f.raw();
    raw.execute_batch("CREATE TRIGGER fail_release BEFORE DELETE ON held_note_event BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    let before = f.dump();
    assert!(f.owner.retry_held(f.id, f.key(note)).is_err());
    assert_eq!(f.dump(), before);
    raw.execute_batch("DROP TRIGGER fail_release;").unwrap();
    assert_eq!(
        f.owner.retry_held(f.id, f.key(note)).unwrap().0,
        vec![(f.key(note), NoteOutcome::Accepted)]
    );
    assert_eq!(f.pending(), 0);
}

#[test]
fn own_clash_still_stops_publishing_under_a_hold() {
    let mut f = Fixture::new();
    let (note, id) = f.own_work();
    let own = f.package(id);
    let clash = f.seal(own.descriptor.id(), note, f.writer([99; 32]), &[255, 255]);
    let batch = f.batch(&[&clash]);
    let result =
        bh_core::contained::with_fuel(0, || f.owner.apply_remote_batch(f.id, batch)).unwrap();
    assert_eq!(result, vec![(f.key(note), NoteOutcome::Waiting)]);
    assert_eq!(f.unaccepted(note), vec![(id, Unaccepted::Conflicted)]);
    assert!(
        f.alarms()
            .iter()
            .any(|a| matches!(a,SyncAlarm::PublishingStopped {update_id} if *update_id==id))
    );
    assert_eq!(f.pending(), 1);
    assert!(f.progress().stopped.is_none());
}

#[test]
fn a_save_on_a_held_note_acks_and_retains_its_exact_work() {
    let mut f = Fixture::new();
    let (note, id) = f.own_work();
    let own = f.package(id);
    let batch = f.batch(&[&own]);
    bh_core::contained::with_fuel(0, || f.owner.apply_remote_batch(f.id, batch)).unwrap();
    let opened = f.owner.open_leased("w", note).unwrap();
    let lease = opened.writer.unwrap();
    let delta = Owner::core_author(&opened)
        .unwrap()
        .try_append_paragraph("queued")
        .unwrap();
    let (ack, _) = f
        .owner
        .commit_leased("w", opened.generation, lease.token, [2; 16], &delta)
        .unwrap();
    assert!(!ack.replayed);
    assert_eq!(f.pending(), 2);
    let (retry, _) = f
        .owner
        .commit_leased("w", opened.generation, lease.token, [2; 16], &delta)
        .unwrap();
    assert!(retry.replayed);
    assert_eq!(f.pending(), 2);
    let db = f.owner.shared_database(f.id).unwrap();
    assert_eq!(
        db.lock().unwrap().pending_note_updates().unwrap()[1].bytes,
        delta
    );
}

#[test]
fn held_rows_survive_reopen_without_exposing_an_empty_remote_note() {
    let mut f = Fixture::new();
    let note = [222; 32];
    let writer = f.writer([99; 32]);
    let delta = seed(f.client(note, writer));
    let event = f.remote(note, [99; 32], &delta);
    let batch = f.batch(&[&event]);
    let commitment = batch.events[0].commitment();
    bh_core::contained::with_fuel(0, || f.owner.apply_remote_batch(f.id, batch)).unwrap();
    assert!(f.owner.show_note("remote", f.id, note).is_err());
    assert_ne!(f.owner.home_note(f.id).unwrap(), note);
    let key = f.key(note);
    let raw = f.raw();
    let path = std::path::PathBuf::from(raw.path().unwrap());
    drop(raw);
    let Fixture {
        dir,
        owner,
        account,
        ..
    } = f;
    drop(account);
    drop(owner);
    let db = bh_storage::DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.data_version(), bh_core::LOCAL_DATA_VERSION);
    let held = db.next_held_event(key, 0).unwrap().unwrap();
    assert_eq!(held.ordered, commitment);
    assert_eq!(held.delta, Some(delta));
    assert_eq!(
        held.writer,
        Some((writer.account, writer.device, writer.nonce))
    );
    assert_eq!(held.author, Some((writer.account, writer.device)));
    assert_eq!(db.accepted_note(key).unwrap().through, 0);
    drop(db);
    drop(dir);
}

#[test]
fn held_batch_commit_failure_is_atomic() {
    let mut f = Fixture::new();
    let (healthy, id) = f.own_work();
    let own = f.package(id);
    let poisoned = [222; 32];
    let bomb = f.remote(
        poisoned,
        [43; 32],
        &trap_update(f.client(poisoned, f.writer([43; 32]))),
    );
    let batch = f.batch(&[&bomb, &own]);
    let before = f.dump();
    let result = f
        .owner
        .apply_remote_batch_with_hook(f.id, batch, |_| Err(StoreError::CorruptSyncState));
    assert!(result.is_err());
    assert_eq!(f.dump(), before);
    assert_eq!(f.unaccepted(healthy), vec![(id, Unaccepted::Sealed)]);
}

#[test]
fn remote_edit_applies_and_fans_out() {
    let mut f = Fixture::new();
    let note = f.owner.create_note(f.id).unwrap();
    f.owner.show_note("reader", f.id, note).unwrap();
    let opened = f.owner.open("reader", note).unwrap();
    let writer = f.writer([9; 32]);
    let s = f.client(note, writer);
    let event = f.remote(note, [9; 32], &seed(s));
    let outcomes = f.apply(&[&event]);
    assert_eq!(outcomes, vec![(f.key(note), NoteOutcome::Accepted)]);
    assert_eq!(f.accepted(note).title_preview().unwrap(), "hello");
    assert_eq!(
        f.working(note).digest().unwrap(),
        f.accepted(note).digest().unwrap()
    );
    let deliveries = f.drain("reader");
    assert_eq!(deliveries.len(), 1);
    assert!(!deliveries[0].resync);
    assert_eq!(
        replay_window(&opened.state, &deliveries)
            .title_preview()
            .unwrap(),
        "hello"
    );
    // The binding is the production reader's verified answer.
    let db = f.owner.shared_database(f.id).unwrap();
    let binding = db
        .lock()
        .unwrap()
        .accepted_binding(f.key(note), s)
        .unwrap()
        .unwrap();
    assert_eq!(binding.nonce, [9; 32]);
    assert_eq!(binding.accepted_end, 7);
    let progress = db
        .lock()
        .unwrap()
        .log_progress(1, f.base.0)
        .unwrap()
        .unwrap();
    assert_eq!(progress.position, 2);
    assert_eq!(progress.head_hash, f.history.head().hash.0);
    assert_eq!(
        progress.receipt,
        Some(f.hosting.receipt(f.base, f.history.head()))
    );
    // A note this device has never seen arrives in its catalogue.
    let fresh = [42; 32];
    let event = f.remote(fresh, [9; 32], &seed(f.client(fresh, writer)));
    assert_eq!(
        f.apply(&[&event]),
        vec![(f.key(fresh), NoteOutcome::Accepted)]
    );
    assert!(f.owner.has_note(f.id, fresh).unwrap());
    let listed = f.owner.list_notes(f.id, None, 10).unwrap();
    assert!(listed.iter().any(|e| e.note == fresh && e.title == "hello"));
}

#[test]
fn foreign_writer_refused_no_effect() {
    let mut f = Fixture::new();
    let note = [7; 32];
    let writer = f.writer([1; 32]);
    let s = f.client(note, writer);
    f.apply(&[&f.remote(note, [1; 32], &seed(s))]);
    let accepted = f.accepted(note).digest().unwrap();
    let working = f.working(note).digest().unwrap();
    let other = f.client(note, f.writer([2; 32]));
    // Inserting under a writer it did not declare.
    let undeclared = f.remote(note, [2; 32], &item(s, 7, (s, 6), None, "x"));
    // Declaring another device's writer: the author is this device.
    let mut impostor = f.writer([3; 32]);
    impostor.device = [0xee; 32];
    let claimed = f.client(note, impostor);
    let impersonating = f.seal(
        EventId(bh_crypto::random()),
        note,
        impostor,
        &item(claimed, 0, (s, 6), None, "y"),
    );
    // A writer ID already bound to another nonce (a derivation collision,
    // planted here) is not this declaration's writer.
    let colliding = f.client(note, f.writer([4; 32]));
    f.raw()
        .execute(
            "INSERT INTO writer_binding VALUES (?1,?2,?3,?4,?5,?6,?7,0)",
            rusqlite::params![
                f.base.0.as_slice(),
                [0u8; 32].as_slice(),
                note.as_slice(),
                colliding as i64,
                f.cap.account_id().0.as_slice(),
                f.cap.device_id().0.as_slice(),
                [0xaau8; 32].as_slice()
            ],
        )
        .unwrap();
    let collision = f.remote(note, [4; 32], &item(colliding, 0, (s, 6), None, "z"));
    let outcomes = f.apply(&[&undeclared, &impersonating, &collision]);
    assert_eq!(
        outcomes,
        vec![
            (
                f.key(note),
                NoteOutcome::Refused(RefusalReason::ForeignWriter)
            );
            3
        ]
    );
    assert_eq!(f.accepted(note).digest().unwrap(), accepted);
    assert_eq!(f.working(note).digest().unwrap(), working);
    let db = f.owner.shared_database(f.id).unwrap();
    assert_eq!(
        db.lock()
            .unwrap()
            .accepted_binding(f.key(note), other)
            .unwrap(),
        None
    );
    assert_eq!(
        db.lock()
            .unwrap()
            .log_progress(1, f.base.0)
            .unwrap()
            .unwrap()
            .position,
        5,
        "refused events still advance the log"
    );
}

#[test]
fn not_continuous_refused() {
    let mut f = Fixture::new();
    let note = [7; 32];
    let s = f.client(note, f.writer([1; 32]));
    f.apply(&[&f.remote(note, [1; 32], &seed(s))]);
    let before = f.accepted(note).digest().unwrap();
    let gap = f.remote(note, [1; 32], &item(s, 8, (s, 6), None, "gap"));
    let again = f.remote(note, [1; 32], &seed(s));
    assert_eq!(
        f.apply(&[&gap, &again]),
        vec![
            (
                f.key(note),
                NoteOutcome::Refused(RefusalReason::NotContinuous)
            ),
            (f.key(note), NoteOutcome::Refused(RefusalReason::Duplicate)),
        ]
    );
    assert_eq!(f.accepted(note).digest().unwrap(), before);
    assert_eq!(f.working(note).digest().unwrap(), before);
}

#[test]
fn missing_dependency_refused() {
    let mut f = Fixture::new();
    let note = [7; 32];
    let s = f.client(note, f.writer([1; 32]));
    let p = f.client(note, f.writer([2; 32]));
    let absent = f.client(note, f.writer([3; 32]));
    f.apply(&[&f.remote(note, [1; 32], &seed(s))]);
    let before = f.accepted(note).digest().unwrap();
    // Its left origin was never accepted: it cannot attach where ordered.
    let dangling = f.remote(note, [2; 32], &item(p, 0, (absent, 0), None, "lost"));
    // The same writer's honest edit, later in the same batch, still applies.
    let honest = f.remote(note, [2; 32], &item(p, 0, (s, 6), None, " there"));
    assert_eq!(
        f.apply(&[&dangling, &honest]),
        vec![
            (
                f.key(note),
                NoteOutcome::Refused(RefusalReason::MissingDependency)
            ),
            (f.key(note), NoteOutcome::Accepted),
        ]
    );
    let mut expected = Note::new().unwrap();
    expected.apply_update(&seed(s)).unwrap();
    assert_eq!(expected.digest().unwrap(), before);
    expected
        .apply_update(&item(p, 0, (s, 6), None, " there"))
        .unwrap();
    assert_eq!(
        f.accepted(note).digest().unwrap(),
        expected.digest().unwrap()
    );
    assert_eq!(f.accepted(note).title_preview().unwrap(), "hello there");
    assert!(!f.accepted(note).has_pending().unwrap());
    assert_eq!(
        f.working(note).digest().unwrap(),
        expected.digest().unwrap()
    );
}

#[test]
fn rejected_submission_advances_and_the_next_event_applies() {
    let mut f = Fixture::new();
    let note = [7; 32];
    let s = f.client(note, f.writer([1; 32]));
    // Complete committed bytes without a valid mandatory receipt: ordered,
    // rejected with no effect, and verification goes on.
    let forged = f.seal_with_receipt(
        EventId(bh_crypto::random()),
        note,
        f.writer([1; 32]),
        &seed(s),
        [0; RECEIPT_LEN],
    );
    let honest = f.remote(note, [1; 32], &seed(s));
    let outcomes = f.apply(&[&forged, &honest]);
    assert_eq!(outcomes, vec![(f.key(note), NoteOutcome::Accepted)]);
    assert_eq!(f.accepted(note).title_preview().unwrap(), "hello");
    let db = f.owner.shared_database(f.id).unwrap();
    let progress = db
        .lock()
        .unwrap()
        .log_progress(1, f.base.0)
        .unwrap()
        .unwrap();
    assert_eq!(progress.position, 3);
    assert_eq!(progress.stopped, None);
}

#[test]
fn atomic_failure_leaves_no_partial_state() {
    let mut f = Fixture::new();
    let (one, two) = ([1; 32], [2; 32]);
    let a = f.remote(one, [1; 32], &seed(f.client(one, f.writer([1; 32]))));
    let b = f.remote(two, [1; 32], &seed(f.client(two, f.writer([1; 32]))));
    // This device's package, whose stored Ack lies (an alarm on its echo),
    // and an account change: their rows share the transaction too.
    let (mine, id) = f.own_work();
    let own = f.package(id);
    let lie = Commitment::order(
        f.base,
        Head {
            position: 40,
            hash: Digest([4; 32]),
        },
        &own.descriptor,
        Route::Content,
    )
    .unwrap();
    f.ack(id, &lie);
    let (change, _, _) = f.add_device(EventId(bh_crypto::random()));
    let before = f.dump();
    let mut history = f.history.clone();
    let batch = f.batch_from(&mut history, &[&a, &change, &own, &b]);
    let mut calls = Vec::new();
    let failed = f.owner.apply_remote_batch_with_hook(f.id, batch, |index| {
        calls.push(index);
        if index == 1 {
            Err(StoreError::InvalidUpdate)
        } else {
            Ok(())
        }
    });
    assert!(failed.is_err());
    assert_eq!(calls, vec![0, 1], "failed between two notes' writes");
    assert_eq!(f.dump(), before, "no table changed");
    // The same verified batch applies in full on retry.
    let mut outcomes = f.apply(&[&a, &change, &own, &b]);
    outcomes.sort_by_key(|(k, _)| k.note);
    let mut expected = vec![
        (f.key(one), NoteOutcome::Accepted),
        (f.key(mine), NoteOutcome::Accepted),
        (f.key(two), NoteOutcome::Accepted),
    ];
    expected.sort_by_key(|(k, _)| k.note);
    assert_eq!(outcomes, expected);
    assert_eq!(f.accepted(two).title_preview().unwrap(), "hello");
    assert_eq!(f.pending(), 0);
    assert_eq!(f.alarms().len(), 1);
    let db = f.owner.shared_database(f.id).unwrap();
    assert_eq!(
        db.lock()
            .unwrap()
            .log_account_changes(1, f.base.0)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn another_bases_package_replayed_here_is_an_ordinary_event() {
    let mut f = Fixture::new();
    let (note, id) = f.own_work();
    // This device's package for another base (planted: notes are created
    // only in the own base so far), signed for that base.
    let other = [0x0b; 32];
    let raw = f.raw();
    raw.execute(
        "UPDATE note_updates SET base=?1 WHERE id=?2",
        rusqlite::params![other.as_slice(), id],
    )
    .unwrap();
    raw.execute(
        "UPDATE pending_scope SET base=?1 WHERE update_id=?2",
        rusqlite::params![other.as_slice(), id],
    )
    .unwrap();
    let db = f.owner.shared_database(f.id).unwrap();
    let candidate = match db.lock().unwrap().prepare_note_package(id).unwrap() {
        bh_storage::PackagePreparation::Candidate(c) => c,
        bh_storage::PackagePreparation::Existing(_) => panic!("already packaged"),
    };
    assert_eq!(candidate.pending.key.base, other);
    let mut binding = f.binding(
        candidate.event_id,
        f.cap.device_id(),
        CLASS_CONTENT,
        f.hosting.receipt(BaseId(other), Head::EMPTY),
    );
    binding.base = other;
    let writer = f.writer([1; 32]);
    let package = {
        let state = f.store.state();
        f.seal_binding(
            binding,
            NOTE,
            &note_payload(note, writer, &candidate.pending.bytes),
            state.ordinary.as_ref().unwrap(),
        )
    };
    db.lock()
        .unwrap()
        .publish_note_package(
            candidate,
            package.descriptor.clone(),
            BodyObject::new(package.body.clone()).unwrap(),
        )
        .unwrap();
    // Its exact bytes ordered in this base's log: an invalid submission
    // here, which says nothing about that package.
    assert!(f.apply(&[&package]).is_empty());
    let progress = f.progress();
    assert_eq!(progress.position, f.history.head().position);
    assert_eq!(progress.stopped, None);
    assert!(f.alarms().is_empty());
    assert_eq!(f.pending(), 1);
    let state = db.lock().unwrap().package_progress(id).unwrap().unwrap();
    assert_eq!(state.outcome, None);
}

#[test]
fn a_control_under_this_devices_id_conflicts_its_package() {
    let mut f = Fixture::new();
    let (note, id) = f.own_work();
    let honest = f.package(id);
    // This device's own key signed an account change under its package's
    // ID: judged as the control it is, and the package conflicts.
    let (change, _, _) = f.add_device(honest.descriptor.id());
    f.apply_control(&change);
    assert_eq!(f.unaccepted(note), vec![(id, Unaccepted::Conflicted)]);
    assert_eq!(f.pending(), 1);
    assert!(
        f.alarms()
            .iter()
            .any(|a| matches!(a, SyncAlarm::PublishingStopped { update_id } if *update_id == id))
    );
    let progress = f.progress();
    assert_eq!(progress.stopped, None);
    assert_eq!(progress.position, f.history.head().position);
    assert_eq!(f.working(note).title_preview().unwrap(), "mine");
}

#[test]
fn another_devices_event_under_this_devices_id_conflicts_its_package() {
    let mut f = Fixture::new();
    let (note, id) = f.own_work();
    let honest = f.package(id);
    let (change, device, signing) = f.add_device(EventId(bh_crypto::random()));
    f.apply_control(&change);
    // The account's other device, valid in every respect, takes this
    // package's event ID: an ordinary event, and no alarm.
    let writer = DeviceWriterDeclaration {
        account: f.cap.account_id().0,
        device: device.0,
        nonce: [5; 32],
    };
    let binding = f.binding(
        honest.descriptor.id(),
        device,
        CLASS_CONTENT,
        f.hosting.receipt(f.base, f.history.head()),
    );
    let taken = f.seal_binding(
        binding,
        NOTE,
        &note_payload(note, writer, &seed(f.client(note, writer))),
        &signing,
    );
    assert_eq!(
        f.apply(&[&taken]),
        vec![(f.key(note), NoteOutcome::Accepted)]
    );
    assert_eq!(f.unaccepted(note), vec![(id, Unaccepted::Conflicted)]);
    assert!(f.alarms().is_empty());
    assert!(
        !f.owner
            .shared_database(f.id)
            .unwrap()
            .lock()
            .unwrap()
            .publishing_stopped()
            .unwrap()
    );
    assert_eq!(f.pending(), 1);
    assert_eq!(f.progress().stopped, None);
}

#[test]
fn own_event_attaches_and_retires_outbox() {
    let mut f = Fixture::new();
    let note = f.owner.create_note(f.id).unwrap();
    f.owner.show_note("w", f.id, note).unwrap();
    let opened = f.owner.open_leased("w", note).unwrap();
    let lease = opened.writer.unwrap();
    let mut author = Owner::core_author(&opened).unwrap();
    let delta = author.try_append_paragraph("mine").unwrap();
    f.owner
        .commit_leased("w", opened.generation, lease.token, [1; 16], &delta)
        .unwrap();
    let ids = f.pending_ids();
    assert_eq!(ids.len(), 1);
    let rows_before: i64 = f
        .raw()
        .query_row("SELECT COUNT(*) FROM note_updates", [], |r| r.get(0))
        .unwrap();
    let own = f.package(ids[0]);
    assert_eq!(f.apply(&[&own]), vec![(f.key(note), NoteOutcome::Accepted)]);
    assert_eq!(
        f.pending(),
        0,
        "the ordered package retired its pending row"
    );
    let rows_after: i64 = f
        .raw()
        .query_row("SELECT COUNT(*) FROM note_updates", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows_after, rows_before, "not reapplied to working state");
    let (ack, position): (Vec<u8>, i64) = f
        .raw()
        .query_row(
            "SELECT o.ack,p.acked_position FROM note_outbox o JOIN note_outbox_progress p USING(update_id)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(Commitment::decode(&ack).unwrap().head(), f.history.head());
    assert_eq!(position, 2);
    assert_eq!(f.accepted(note).title_preview().unwrap(), "mine");
    assert_eq!(
        f.accepted(note).digest().unwrap(),
        f.working(note).digest().unwrap()
    );
    // The local writer keeps writing from its accepted end.
    let next = author.try_append_paragraph("more").unwrap();
    f.owner
        .commit_leased("w", opened.generation, lease.token, [2; 16], &next)
        .unwrap();

    // Other bytes under one of this device's event IDs, authored by its own
    // key: a clone or a local bug, not evidence against the log. The event
    // is judged like any other and the log goes on; this device's package
    // is conflicted, its work kept, and its publishing stops with an alarm.
    let ids = f.pending_ids();
    let honest = f.package(ids[0]);
    let forged = f.seal(
        honest.descriptor.id(),
        note,
        f.writer([5; 32]),
        &item(
            f.client(note, f.writer([5; 32])),
            0,
            (lease.client_id, 0),
            None,
            "x",
        ),
    );
    assert_eq!(
        f.apply(&[&forged]),
        vec![(f.key(note), NoteOutcome::Accepted)]
    );
    assert_eq!(f.pending(), 1, "the local work is kept");
    assert_eq!(f.unaccepted(note), vec![(ids[0], Unaccepted::Conflicted)]);
    assert!(f.working(note).title_preview().unwrap().starts_with("mine"));
    assert!(
        f.alarms().iter().any(
            |a| matches!(a, SyncAlarm::PublishingStopped { update_id } if *update_id == ids[0])
        )
    );
    let db = f.owner.shared_database(f.id).unwrap();
    let progress = db
        .lock()
        .unwrap()
        .log_progress(1, f.base.0)
        .unwrap()
        .unwrap();
    assert_eq!(progress.stopped, None);
    assert_eq!(progress.position, f.history.head().position);
    assert!(matches!(
        db.lock().unwrap().prepare_note_package(ids[0]),
        Err(StoreError::PublishingStopped)
    ));
}

#[test]
fn an_invalid_event_under_this_devices_id_conflicts_its_package() {
    let mut f = Fixture::new();
    let note = f.owner.create_note(f.id).unwrap();
    f.owner.show_note("w", f.id, note).unwrap();
    let opened = f.owner.open_leased("w", note).unwrap();
    let lease = opened.writer.unwrap();
    let delta = Owner::core_author(&opened)
        .unwrap()
        .try_append_paragraph("mine")
        .unwrap();
    f.owner
        .commit_leased("w", opened.generation, lease.token, [1; 16], &delta)
        .unwrap();
    let id = f.pending_ids()[0];
    let honest = f.package(id);
    // Someone else's invalid submission takes this package's event ID: it
    // holds that position with no effect, so this package cannot be
    // ordered under its ID. Resealing is a later, deliberate step.
    let taken = f.seal_with_receipt(
        honest.descriptor.id(),
        note,
        f.writer([5; 32]),
        &seed(f.client(note, f.writer([5; 32]))),
        [0; RECEIPT_LEN],
    );
    assert!(f.apply(&[&taken]).is_empty());
    assert_eq!(f.pending(), 1);
    assert_eq!(f.unaccepted(note), vec![(id, Unaccepted::Conflicted)]);
    assert!(
        f.alarms().is_empty(),
        "no evidence it was this device's key"
    );
    assert_eq!(f.working(note).title_preview().unwrap(), "mine");
}

#[test]
fn rejected_and_refused_own_packages_keep_local_work() {
    let mut f = Fixture::new();
    let note = f.owner.create_note(f.id).unwrap();
    f.owner.show_note("w", f.id, note).unwrap();
    let opened = f.owner.open_leased("w", note).unwrap();
    let lease = opened.writer.unwrap();
    let mut author = Owner::core_author(&opened).unwrap();
    let a = author.try_append_paragraph("mine").unwrap();
    f.owner
        .commit_leased("w", opened.generation, lease.token, [1; 16], &a)
        .unwrap();
    let pa = f.package(f.pending_ids()[0]);
    assert_eq!(f.apply(&[&pa]), vec![(f.key(note), NoteOutcome::Accepted)]);
    let only_a = f.accepted(note).digest().unwrap();

    // B: sealed with a receipt that does not verify (a stale or misconfigured
    // hosting key, say): ordered, then Rejected at envelope level.
    let b = author.try_append_paragraph("second").unwrap();
    f.owner
        .commit_leased("w", opened.generation, lease.token, [2; 16], &b)
        .unwrap();
    let id_b = f.pending_ids()[0];
    let pb = f.package_with_receipt(id_b, [0; RECEIPT_LEN]);
    let order_b =
        Commitment::order(f.base, f.history.head(), &pb.descriptor, Route::Content).unwrap();
    // The append's Ack arrives before the puller's echo.
    f.ack(id_b, &order_b);

    // C: an honest continuation by the same writer, Acked too.
    let c = author.try_append_paragraph("third").unwrap();
    f.owner
        .commit_leased("w", opened.generation, lease.token, [3; 16], &c)
        .unwrap();
    let id_c = *f.pending_ids().iter().max().unwrap();
    assert_ne!(id_b, id_c);
    let pc = f.package(id_c);
    let order_c =
        Commitment::order(f.base, order_b.head(), &pc.descriptor, Route::Content).unwrap();
    f.ack(id_c, &order_c);
    assert_eq!(f.pending(), 2, "an ordered Ack is not acceptance");
    assert_eq!(
        f.unaccepted(note),
        vec![(id_b, Unaccepted::Acked), (id_c, Unaccepted::Acked)]
    );
    let working_before = f.working(note).digest().unwrap();
    assert_ne!(working_before, only_a);

    // The echo: B is rejected, so C cannot continue and is refused.
    assert_eq!(
        f.apply(&[&pb, &pc]),
        vec![(
            f.key(note),
            NoteOutcome::Refused(RefusalReason::NotContinuous)
        )]
    );
    assert_eq!(f.pending(), 2, "neither package was accepted");
    assert_eq!(
        f.working(note).digest().unwrap(),
        working_before,
        "local work kept"
    );
    assert_eq!(f.accepted(note).digest().unwrap(), only_a);
    assert_eq!(
        f.unaccepted(note),
        vec![
            (id_b, Unaccepted::Rejected),
            (id_c, Unaccepted::Refused(RefusalReason::NotContinuous)),
        ]
    );
    f.owner.show_note("again", f.id, note).unwrap();
    let reopened = f.owner.open("again", note).unwrap();
    assert_eq!(
        Note::from_ordered(&reopened.state)
            .unwrap()
            .digest()
            .unwrap(),
        working_before
    );
}

#[test]
fn own_refused_with_nothing_else_pending_keeps_working() {
    let mut f = Fixture::new();
    let note = f.owner.create_note(f.id).unwrap();
    f.owner.show_note("w", f.id, note).unwrap();
    let opened = f.owner.open_leased("w", note).unwrap();
    let lease = opened.writer.unwrap();
    let delta = Owner::core_author(&opened)
        .unwrap()
        .try_append_paragraph("mine")
        .unwrap();
    f.owner
        .commit_leased("w", opened.generation, lease.token, [1; 16], &delta)
        .unwrap();
    let id = f.pending_ids()[0];
    let own = f.package(id);
    // Another writer's accepted edit, then this device's writer ID already
    // bound to another nonce: its package is refused as a foreign writer.
    let s = f.client(note, f.writer([9; 32]));
    f.apply(&[&f.remote(note, [9; 32], &seed(s))]);
    f.raw()
        .execute(
            "INSERT INTO writer_binding VALUES (?1,?2,?3,?4,?5,?6,?7,0)",
            rusqlite::params![
                f.base.0.as_slice(),
                [0u8; 32].as_slice(),
                note.as_slice(),
                lease.client_id as i64,
                f.cap.account_id().0.as_slice(),
                f.cap.device_id().0.as_slice(),
                [0xaau8; 32].as_slice()
            ],
        )
        .unwrap();
    let working = f.working(note).digest().unwrap();
    f.owner.show_note("reader", f.id, note).unwrap();
    f.owner.open("reader", note).unwrap();
    assert_eq!(
        f.apply(&[&own]),
        vec![(
            f.key(note),
            NoteOutcome::Refused(RefusalReason::ForeignWriter)
        )]
    );
    assert_eq!(f.pending(), 1);
    assert_eq!(
        f.working(note).digest().unwrap(),
        working,
        "no rebuild over it"
    );
    assert!(f.drain("reader").iter().all(|d| !d.reload));
    assert_eq!(
        f.unaccepted(note),
        vec![(id, Unaccepted::Refused(RefusalReason::ForeignWriter))]
    );
}

#[test]
fn a_lying_ack_is_overwritten_by_the_verified_echo() {
    let mut f = Fixture::new();
    let note = f.owner.create_note(f.id).unwrap();
    f.owner.show_note("w", f.id, note).unwrap();
    let opened = f.owner.open_leased("w", note).unwrap();
    let lease = opened.writer.unwrap();
    let delta = Owner::core_author(&opened)
        .unwrap()
        .try_append_paragraph("mine")
        .unwrap();
    f.owner
        .commit_leased("w", opened.generation, lease.token, [1; 16], &delta)
        .unwrap();
    let id = f.pending_ids()[0];
    let own = f.package(id);
    let lie = Commitment::order(
        f.base,
        Head {
            position: 40,
            hash: Digest([4; 32]),
        },
        &own.descriptor,
        Route::Content,
    )
    .unwrap();
    f.ack(id, &lie);
    assert_eq!(f.apply(&[&own]), vec![(f.key(note), NoteOutcome::Accepted)]);
    assert_eq!(f.pending(), 0);
    let ack: Vec<u8> = f
        .raw()
        .query_row(
            "SELECT ack FROM note_outbox WHERE update_id=?1",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(Commitment::decode(&ack).unwrap().head(), f.history.head());
    assert!(f.alarms().iter().any(|a| matches!(
        a,
        SyncAlarm::AckMismatch { update_id, position } if *update_id == id && *position == 2
    )));
}

#[test]
fn a_spliced_or_misreceipted_batch_is_invalid() {
    let mut f = Fixture::new();
    let note = [7; 32];
    let s = f.client(note, f.writer([1; 32]));
    let first = f.remote(note, [1; 32], &seed(s));
    let other = f.remote(note, [2; 32], &seed(f.client(note, f.writer([2; 32]))));
    let next = f.remote(note, [1; 32], &item(s, 7, (s, 6), None, "!"));
    // Two verified forks from the same head, spliced together.
    let mut one = f.history.clone();
    let left = f.batch_from(&mut one, &[&first]);
    let mut two = f.history.clone();
    f.batch_from(&mut two, &[&other]);
    let right = f.batch_from(&mut two, &[&next]);
    let before = f.dump();
    let spliced = VerifiedBatch {
        log: f.log(),
        head: right.head,
        receipt: right.receipt,
        events: left.events.into_iter().chain(right.events).collect(),
    };
    assert!(matches!(
        f.owner.apply_remote_batch(f.id, spliced),
        Err(OwnerError::InvalidBatch)
    ));
    // A receipt that does not name the batch's head.
    let mut three = f.history.clone();
    let mut batch = f.batch_from(&mut three, &[&first]);
    batch.receipt = f.hosting.receipt(f.base, f.history.head());
    assert!(matches!(
        f.owner.apply_remote_batch(f.id, batch),
        Err(OwnerError::InvalidBatch)
    ));
    assert_eq!(f.dump(), before);
    assert_eq!(
        f.apply(&[&first]),
        vec![(f.key(note), NoteOutcome::Accepted)]
    );
}

#[test]
fn resume_continues_without_replay_and_judges_alike() {
    let mut f = Fixture::new();
    let note = f.owner.create_note(f.id).unwrap();
    let first = f.remote(note, [9; 32], &seed(f.client(note, f.writer([9; 32]))));
    f.apply(&[&first]);
    // Drop everything in memory: the owner, its caches and the History.
    // A new owner opens the container from disk and resumes verification
    // from its stored continuation; nothing is replayed.
    let live = f.history.clone();
    f.account = None;
    f.owner = Owner::default();
    // The old owner's background compaction may hold the file briefly.
    let mut tries = 0;
    f.id = loop {
        let opened = f.owner.open_containers(f.dir.path()).unwrap();
        match opened[0].1.as_ref().copied() {
            Ok(id) => break id,
            Err(e) => {
                tries += 1;
                assert!(tries < 50, "{e:?}");
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    };
    f.owner.anchor(f.id, &f.anchor).unwrap();
    let resumed = f
        .owner
        .history(f.id, f.log(), &f.anchor, f.hosting.root.public(), 1)
        .unwrap();
    assert_eq!(resumed.head(), live.head());
    assert_eq!(resumed.account_head(), live.account_head());
    assert_eq!(resumed.floor(), live.floor());
    assert_eq!(resumed.metadata_id(), live.metadata_id());
    assert_eq!(resumed.epoch_id(), live.epoch_id());

    // A K2 batch and a reused event ID reach the same outcomes from the
    // resumed History as from the live one.
    let (ns, np, nh, nl) = k2_nonces(&f, note);
    let [s, p, h, l] = [ns, np, nh, nl].map(|x| f.client(note, f.writer(x)));
    let mut events: Vec<Encoded> = [ns, np, nh, nl]
        .iter()
        .zip(k2_updates(s, p, h, l))
        .map(|(n, u)| f.remote(note, *n, &u))
        .collect();
    events.push(f.seal(
        first.descriptor.id(),
        note,
        f.writer(nl),
        &item(l, 6, (l, 5), None, "?"),
    ));
    let refs: Vec<&Encoded> = events.iter().collect();
    let mut from_live = live.clone();
    let expected: Vec<_> = f
        .batch_from(&mut from_live, &refs)
        .events
        .iter()
        .map(|e| e.outcome())
        .collect();
    let mut from_resumed = resumed;
    let batch = f.batch_from(&mut from_resumed, &refs);
    let outcomes: Vec<_> = batch.events.iter().map(|e| e.outcome()).collect();
    assert_eq!(outcomes, expected);
    assert_eq!(*outcomes.last().unwrap(), bh_event::Outcome::Rejected);
    assert_eq!(from_resumed.head(), from_live.head());
    assert!(
        f.owner
            .apply_remote_batch(f.id, batch)
            .unwrap()
            .iter()
            .all(|(_, o)| *o == NoteOutcome::Accepted)
    );
    let updates = k2_updates(s, p, h, l);
    let mut refs: Vec<&[u8]> = vec![];
    let seeded = seed(f.client(note, f.writer([9; 32])));
    refs.push(&seeded);
    refs.extend(updates.iter().map(Vec::as_slice));
    assert_eq!(f.accepted(note).digest().unwrap(), digest_of(&refs).0);
    // The next resume continues from the batch just committed.
    let again = f
        .owner
        .history(f.id, f.log(), &f.anchor, f.hosting.root.public(), 1)
        .unwrap();
    assert_eq!(again.head(), from_live.head());
}

#[test]
fn a_floor_rise_is_stored_at_its_position() {
    let mut f = Fixture::new();
    let note = [7; 32];
    let s = f.client(note, f.writer([1; 32]));
    let first = f.remote(note, [1; 32], &seed(s));
    f.apply(&[&first]);
    let db = f.owner.shared_database(f.id).unwrap();
    assert_eq!(
        db.lock().unwrap().floor_rises(1, f.base.0).unwrap(),
        vec![(2, 2)]
    );
    // This device learns floor 3 and resumes under it: events from here on
    // are judged under it, events before it stay as they were judged.
    f.history = f
        .owner
        .history(f.id, f.log(), &f.anchor, f.hosting.root.public(), 3)
        .unwrap();
    let later = f.remote(note, [1; 32], &item(s, 7, (s, 6), None, "!"));
    assert!(f.apply(&[&later]).is_empty(), "a v2 event under floor 3");
    assert_eq!(
        db.lock().unwrap().floor_rises(1, f.base.0).unwrap(),
        vec![(2, 3)]
    );
    assert_eq!(f.accepted(note).title_preview().unwrap(), "hello");
    let resumed = f
        .owner
        .history(f.id, f.log(), &f.anchor, f.hosting.root.public(), 1)
        .unwrap();
    assert_eq!(resumed.floor(), 3);
    // Replaying the originals with the stored rises judges each event under
    // the floor in force at its position, as live verification did.
    let stored = db.lock().unwrap().own_base().unwrap().unwrap();
    let genesis = OpaqueEvent::decode(&stored.genesis_descriptor).unwrap();
    let mut records = vec![(
        Commitment::order(f.base, Head::EMPTY, &genesis, Route::Control).unwrap(),
        stored.genesis_descriptor.clone(),
        stored.genesis_body.clone(),
    )];
    for event in [&first, &later] {
        let previous = records.last().unwrap().0.head();
        records.push((
            Commitment::order(f.base, previous, &event.descriptor, Route::Content).unwrap(),
            event.descriptor.encode(),
            event.body.clone(),
        ));
    }
    let replayed = History::replay_with_account(
        &f.anchor,
        f.base,
        f.hosting.root.public(),
        &db.lock().unwrap().floor_rises(1, f.base.0).unwrap(),
        &f.metadata,
        Some(&f.content),
        records,
    )
    .unwrap();
    assert_eq!(replayed.head(), resumed.head());
    assert_eq!(replayed.floor(), 3);
}

#[test]
fn a_history_pinned_to_another_root_is_unavailable() {
    let f = Fixture::new();
    let other = Hosting::new();
    assert!(matches!(
        f.owner
            .history(f.id, f.log(), &f.anchor, other.root.public(), 1),
        Err(OwnerError::Unavailable)
    ));
    // A batch some History verified under another root never commits.
    let mut history = History::with_account(&f.anchor, f.base, other.root.public(), 1).unwrap();
    let genesis = {
        let db = f.owner.shared_database(f.id).unwrap();
        let stored = db.lock().unwrap().own_base().unwrap().unwrap();
        Encoded {
            descriptor: OpaqueEvent::decode(&stored.genesis_descriptor).unwrap(),
            body: stored.genesis_body,
        }
    };
    f.batch_from(&mut history, &[&genesis]);
    let note = [7; 32];
    let event = f.seal_with_receipt(
        EventId(bh_crypto::random()),
        note,
        f.writer([1; 32]),
        &seed(f.client(note, f.writer([1; 32]))),
        other.receipt(f.base, history.head()),
    );
    let before = f.dump();
    let batch = f.batch_from(&mut history, &[&event]);
    assert_eq!(batch.events[0].outcome(), bh_event::Outcome::Accepted);
    assert!(matches!(
        f.owner.apply_remote_batch(f.id, batch),
        Err(OwnerError::Unavailable)
    ));
    assert_eq!(f.dump(), before, "no progress");
}

#[test]
fn stop_is_sticky_and_keeps_state() {
    let mut f = Fixture::new();
    let note = [7; 32];
    let s = f.client(note, f.writer([1; 32]));
    f.apply(&[&f.remote(note, [1; 32], &seed(s))]);
    f.owner
        .record_stop(f.id, f.log(), StopReason::Integrity)
        .unwrap();
    let before = f.dump();
    let later = f.remote(note, [1; 32], &item(s, 7, (s, 6), None, "!"));
    let batch = f.batch(&[&later]);
    assert!(matches!(
        f.owner.apply_remote_batch(f.id, batch),
        Err(OwnerError::Stopped)
    ));
    // A second stop keeps the first; the verified state stays readable.
    f.owner
        .record_stop(f.id, f.log(), StopReason::Integrity)
        .unwrap();
    assert_eq!(f.dump(), before);
    assert_eq!(f.accepted(note).title_preview().unwrap(), "hello");
    let db = f.owner.shared_database(f.id).unwrap();
    assert_eq!(
        db.lock()
            .unwrap()
            .log_progress(1, f.base.0)
            .unwrap()
            .unwrap()
            .stopped,
        Some(StopReason::Integrity as u8)
    );
}

/// Find writer nonces for the K2 shape whose live (log-order) text differs
/// from one merged full state reopened: the divergence order-preserving
/// state exists to prevent.
fn k2_nonces(f: &Fixture, note: [u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    for c in 0..20_000 {
        let n = (nonce(1, c), nonce(2, c), nonce(3, c), nonce(4, c));
        let [s, p, h, l] = [n.0, n.1, n.2, n.3].map(|x| f.client(note, f.writer(x)));
        let updates = k2_updates(s, p, h, l);
        let refs: Vec<&[u8]> = updates.iter().map(Vec::as_slice).collect();
        let (_, live) = digest_of(&refs);
        let mut merged = Note::new().unwrap();
        merged
            .apply_update(&{
                let mut n = Note::new().unwrap();
                for u in &refs {
                    n.apply_update(u).unwrap();
                }
                n.state().unwrap()
            })
            .unwrap();
        if live != merged.title_preview().unwrap() {
            return n;
        }
    }
    panic!("no divergent K2 assignment");
}

fn k2_updates(s: u64, p: u64, h: u64, l: u64) -> [Vec<u8>; 4] {
    [
        seed(s),
        item(p, 0, (s, 6), None, "HL"),
        // Non-adjacent anchors: after "hell", before the peer's "L".
        item(h, 0, (s, 4), Some((p, 1)), "abcd"),
        item(l, 0, (s, 6), None, " world"),
    ]
}

#[test]
fn k2_via_real_admission_converges() {
    let mut f = Fixture::new();
    let note = f.owner.create_note(f.id).unwrap();
    f.owner.show_note("reader", f.id, note).unwrap();
    let opened = f.owner.open("reader", note).unwrap();
    let (ns, np, nh, nl) = k2_nonces(&f, note);
    let [s, p, h, l] = [ns, np, nh, nl].map(|x| f.client(note, f.writer(x)));
    let updates = k2_updates(s, p, h, l);
    let events: Vec<Encoded> = [ns, np, nh, nl]
        .iter()
        .zip(&updates)
        .map(|(n, u)| f.remote(note, *n, u))
        .collect();
    let outcomes = f.apply(&events.iter().collect::<Vec<_>>());
    assert!(outcomes.iter().all(|(_, o)| *o == NoteOutcome::Accepted));
    let refs: Vec<&[u8]> = updates.iter().map(Vec::as_slice).collect();
    let (live_digest, live_title) = digest_of(&refs);
    let accepted = f.accepted(note);
    assert_eq!(accepted.digest().unwrap(), live_digest);
    assert_eq!(accepted.title_preview().unwrap(), live_title);
    // Reopening the stored accepted and working states gives the same note.
    assert_eq!(f.working(note).digest().unwrap(), live_digest);
    f.owner.show_note("again", f.id, note).unwrap();
    let reopened = f.owner.open("again", note).unwrap();
    assert_eq!(
        Note::from_ordered(&reopened.state)
            .unwrap()
            .digest()
            .unwrap(),
        live_digest
    );
    // The open window applied the same updates in the same order.
    let view = replay_window(&opened.state, &f.drain("reader"));
    assert_eq!(view.title_preview().unwrap(), live_title);
    assert_eq!(view.digest().unwrap(), live_digest);
}

#[test]
fn k2_resync_delivers_ordered_segments_to_an_open_window() {
    let mut f = Fixture::new();
    let note = f.owner.create_note(f.id).unwrap();
    f.owner.show_note("reader", f.id, note).unwrap();
    let opened = f.owner.open("reader", note).unwrap();
    let (ns, np, nh, nl) = k2_nonces(&f, note);
    let [s, p, h, l] = [ns, np, nh, nl].map(|x| f.client(note, f.writer(x)));
    let updates = k2_updates(s, p, h, l);
    let events: Vec<Encoded> = [ns, np, nh, nl]
        .iter()
        .zip(&updates)
        .map(|(n, u)| f.remote(note, *n, u))
        .collect();
    f.apply(&events.iter().collect::<Vec<_>>());
    // A failed page evaluation turns everything queued into one resync.
    let first = {
        let mut one = None;
        f.owner.drain_surface_once("reader", &mut |d| one = Some(d));
        one.unwrap()
    };
    f.owner.retry_delivery(&first);
    let deliveries = f.drain("reader");
    assert_eq!(deliveries.len(), 1);
    assert!(deliveries[0].resync && deliveries[0].update.is_empty());
    let view = replay_window(&opened.state, &deliveries);
    let refs: Vec<&[u8]> = updates.iter().map(Vec::as_slice).collect();
    assert_eq!(view.title_preview().unwrap(), digest_of(&refs).1);
}

#[test]
fn working_rebuilt_when_digest_differs() {
    let mut f = Fixture::new();
    let note = f.owner.create_note(f.id).unwrap();
    f.owner.show_note("w1", f.id, note).unwrap();
    f.owner.show_note("w2", f.id, note).unwrap();
    f.owner.show_note("reader", f.id, note).unwrap();
    // This device seeds the note; its package is ordered first.
    let one = f.owner.open_leased("w1", note).unwrap();
    let s = one.writer.unwrap().client_id;
    let seed_delta = Owner::core_author(&one)
        .unwrap()
        .try_append_paragraph("hello")
        .unwrap();
    f.owner
        .commit_leased(
            "w1",
            one.generation,
            one.writer.unwrap().token,
            [1; 16],
            &seed_delta,
        )
        .unwrap();
    let seeded = f.package(f.pending_ids()[0]);
    f.apply(&[&seeded]);
    // Then it appends " world" locally from a second producer: pending.
    let two = f.owner.open_leased("w2", note).unwrap();
    let l = two.writer.unwrap().client_id;
    let later = item(l, 0, (s, 6), None, " world");
    f.owner
        .commit_leased(
            "w2",
            two.generation,
            two.writer.unwrap().token,
            [2; 16],
            &later,
        )
        .unwrap();
    let local = f.package(f.pending_ids()[0]);
    // Meanwhile two other producers' K2-shaped edits are ordered before it,
    // chosen so that integrating the local edit first gives another structure.
    let (np, nh) = (0..20_000)
        .map(|c| (nonce(2, c), nonce(3, c)))
        .find(|(np, nh)| {
            let p = f.client(note, f.writer(*np));
            let h = f.client(note, f.writer(*nh));
            let peer = item(p, 0, (s, 6), None, "HL");
            let hostile = item(h, 0, (s, 4), Some((p, 1)), "abcd");
            digest_of(&[&seed_delta, &later, &peer, &hostile]).0
                != digest_of(&[&seed_delta, &peer, &hostile, &later]).0
        })
        .expect("a divergent assignment");
    let p = f.client(note, f.writer(np));
    let h = f.client(note, f.writer(nh));
    let peer = item(p, 0, (s, 6), None, "HL");
    let hostile = item(h, 0, (s, 4), Some((p, 1)), "abcd");
    let remote = [f.remote(note, np, &peer), f.remote(note, nh, &hostile)];
    f.apply(&[&remote[0], &remote[1]]);
    assert_eq!(f.pending(), 1);
    let working_order = digest_of(&[&seed_delta, &later, &peer, &hostile]);
    assert_eq!(f.working(note).digest().unwrap(), working_order.0);
    let opened = f.owner.open("reader", note).unwrap();
    // Its own package is ordered last: nothing is pending, the digests
    // differ, so working state is rebuilt from accepted and windows reload.
    assert_eq!(
        f.apply(&[&local]),
        vec![(f.key(note), NoteOutcome::Accepted)]
    );
    assert_eq!(f.pending(), 0);
    let accepted_order = digest_of(&[&seed_delta, &peer, &hostile, &later]);
    assert_eq!(f.accepted(note).digest().unwrap(), accepted_order.0);
    assert_eq!(f.working(note).digest().unwrap(), accepted_order.0);
    f.owner.show_note("again", f.id, note).unwrap();
    let reopened = f.owner.open("again", note).unwrap();
    assert_eq!(
        Note::from_ordered(&reopened.state)
            .unwrap()
            .digest()
            .unwrap(),
        accepted_order.0
    );
    let deliveries = f.drain("reader");
    assert!(deliveries.iter().any(|d| d.reload));
    let view = replay_window(&opened.state, &deliveries);
    assert_eq!(view.digest().unwrap(), accepted_order.0);
    assert_eq!(view.title_preview().unwrap(), accepted_order.1);
}

#[test]
fn batch_of_64_small_events_apply_time() {
    let mut f = Fixture::new();
    let notes: Vec<[u8; 32]> = (0..8u8).map(|n| [n + 1; 32]).collect();
    let mut events = Vec::new();
    let mut ends = vec![0u32; notes.len()];
    let mut seeded = vec![false; notes.len()];
    for i in 0..64 {
        let n = i % notes.len();
        let note = notes[n];
        let c = f.client(note, f.writer([1; 32]));
        let update = if !seeded[n] {
            seeded[n] = true;
            ends[n] = 7;
            seed(c)
        } else {
            let u = item(c, ends[n], (c, ends[n] - 1), None, "x");
            ends[n] += 1;
            u
        };
        events.push(f.remote(note, [1; 32], &update));
    }
    let batch = f.batch(&events.iter().collect::<Vec<_>>());
    let started = Instant::now();
    let outcomes = f.owner.apply_remote_batch(f.id, batch).unwrap();
    let elapsed = started.elapsed();
    assert_eq!(outcomes.len(), 64);
    assert!(outcomes.iter().all(|(_, o)| *o == NoteOutcome::Accepted));
    eprintln!("apply_remote_batch: 64 small events over 8 notes in {elapsed:?}");
}

#[test]
fn an_own_package_ordered_twice_keeps_its_first_verdict() {
    let mut f = Fixture::new();
    let note = f.owner.create_note(f.id).unwrap();
    f.owner.show_note("w", f.id, note).unwrap();
    let opened = f.owner.open_leased("w", note).unwrap();
    let lease = opened.writer.unwrap();
    let delta = Owner::core_author(&opened)
        .unwrap()
        .try_append_paragraph("mine")
        .unwrap();
    f.owner
        .commit_leased("w", opened.generation, lease.token, [1; 16], &delta)
        .unwrap();
    let id = f.pending_ids()[0];
    let own = f.package(id);
    // The service orders the same bytes twice: the second reuses the ID and
    // is rejected, which says nothing about this device's package.
    assert_eq!(
        f.apply(&[&own, &own]),
        vec![(f.key(note), NoteOutcome::Accepted)]
    );
    assert_eq!(f.pending(), 0);
    assert!(f.alarms().is_empty());
    let db = f.owner.shared_database(f.id).unwrap();
    let progress = db.lock().unwrap().package_progress(id).unwrap().unwrap();
    assert_eq!(
        progress.outcome,
        Some(bh_storage::sync_state::PackageOutcome::Accepted)
    );
    assert_eq!(progress.position, Some(2));
    // And again in a later batch.
    assert!(f.apply(&[&own]).is_empty());
    let progress = db.lock().unwrap().package_progress(id).unwrap().unwrap();
    assert_eq!(progress.position, Some(2));
    assert!(f.alarms().is_empty());
}

/// This device's own sealing: the binding claims the verified head with its
/// receipt, the base's last control and copy of the account, and the payload
/// is `note || declaration || update`, so History and the writer rule accept it.
#[test]
fn native_note_seal_is_accepted_as_this_devices_package() {
    let mut f = Fixture::new();
    let (note, id) = f.own_work();
    let db = f.owner.shared_database(f.id).unwrap();
    let bh_storage::PackagePreparation::Candidate(candidate) =
        db.lock().unwrap().prepare_note_package(id).unwrap()
    else {
        panic!("already packaged")
    };
    let request = f
        .owner
        .prepare_note_seal(
            f.id,
            &f.anchor,
            f.hosting.root.public(),
            &f.metadata,
            &f.content,
            &candidate,
        )
        .unwrap();
    let signature = f
        .store
        .state()
        .ordinary
        .as_ref()
        .unwrap()
        .sign(request.signing_bytes());
    let encoded = request.finish(signature).unwrap();
    assert_eq!(encoded.descriptor.id(), candidate.event_id);
    db.lock()
        .unwrap()
        .publish_note_package(
            candidate,
            encoded.descriptor.clone(),
            BodyObject::new(encoded.body.clone()).unwrap(),
        )
        .unwrap();
    assert_eq!(
        f.apply(&[&encoded]),
        vec![(f.key(note), NoteOutcome::Accepted)]
    );
    assert_eq!(f.pending(), 0);
    assert!(f.alarms().is_empty());
}

/// Sealing cannot check the receipt it signs, so the producer does: a seen
/// receipt that does not verify under the pinned root for the stored head,
/// a closed epoch, or another hosting root seals nothing.
#[test]
fn native_note_seal_refuses_unverified_seen_closed_epoch_and_other_root() {
    let mut f = Fixture::new();
    let (_, id) = f.own_work();
    let db = f.owner.shared_database(f.id).unwrap();
    let bh_storage::PackagePreparation::Candidate(candidate) =
        db.lock().unwrap().prepare_note_package(id).unwrap()
    else {
        panic!("already packaged")
    };
    let seal = |f: &Fixture, root: [u8; 32]| {
        f.owner
            .prepare_note_seal(f.id, &f.anchor, root, &f.metadata, &f.content, &candidate)
            .map(|_| ())
    };
    let root = f.hosting.root.public();
    assert!(seal(&f, root).is_ok());
    assert!(matches!(
        seal(&f, SigningKey::generate().public()),
        Err(OwnerError::Unavailable)
    ));
    let raw = f.raw();
    // A receipt for another head, validly signed under the pinned root.
    let other = f.hosting.receipt(
        f.base,
        Head {
            position: 1,
            hash: Digest([9; 32]),
        },
    );
    raw.execute("UPDATE log_progress SET receipt=?1", [other.as_slice()])
        .unwrap();
    assert!(matches!(
        seal(&f, root),
        Err(OwnerError::SealRefused(SealRefusal::SeenUnverified))
    ));
    // Signed by a key the pinned root never certified.
    let stranger = Hosting::new().receipt(f.base, f.history.head());
    raw.execute("UPDATE log_progress SET receipt=?1", [stranger.as_slice()])
        .unwrap();
    assert!(matches!(
        seal(&f, root),
        Err(OwnerError::SealRefused(SealRefusal::SeenUnverified))
    ));
    let good = f.hosting.receipt(f.base, f.history.head());
    raw.execute("UPDATE log_progress SET receipt=?1", [good.as_slice()])
        .unwrap();
    assert!(seal(&f, root).is_ok());
    raw.execute("UPDATE log_progress SET epoch_id=NULL", [])
        .unwrap();
    assert!(matches!(
        seal(&f, root),
        Err(OwnerError::SealRefused(SealRefusal::EpochClosed))
    ));
    assert_eq!(db.lock().unwrap().package_progress(id).unwrap(), None);
}

/// A sync fence holds across ordinary content history, and ends with its
/// authority: after lock nothing runs inside it and none is taken.
#[test]
fn a_sync_fence_ends_with_its_authority_and_runs_nothing_after() {
    let mut f = Fixture::new();
    let fence = f.owner.sync_fence(f.id, f.log()).unwrap();
    assert_eq!(f.owner.with_sync_fence(&fence, |_| Ok(7)).unwrap(), 7);
    let note = [41; 32];
    let event = f.remote(note, [9; 32], &seed(f.client(note, f.writer([9; 32]))));
    f.apply(&[&event]);
    assert!(
        f.owner.with_sync_fence(&fence, |_| Ok(())).is_ok(),
        "an older content observation is still truthful"
    );
    f.account.as_mut().unwrap().lock().unwrap();
    let mut ran = false;
    let fenced = f.owner.with_sync_fence(&fence, |_| {
        ran = true;
        Ok(())
    });
    assert!(matches!(fenced, Err(OwnerError::Unbound)), "{fenced:?}");
    assert!(!ran, "nothing runs once its authority ended");
    assert!(matches!(
        f.owner.sync_fence(f.id, f.log()),
        Err(OwnerError::Unbound)
    ));
}

/// A control, a new epoch or a stop ends a fence; a stopped log gives none.
#[test]
fn a_sync_fence_ends_at_a_control_an_epoch_change_or_a_stop() {
    let mut f = Fixture::new();
    let changed = |f: &Fixture, fence| {
        matches!(
            f.owner.with_sync_fence(fence, |_| Ok(())),
            Err(OwnerError::Changed)
        )
    };
    let fence = f.owner.sync_fence(f.id, f.log()).unwrap();
    let (control, _, _) = f.add_device(EventId(bh_crypto::random()));
    f.apply_control(&control);
    assert!(changed(&f, &fence), "a control and account copy");
    let fence = f.owner.sync_fence(f.id, f.log()).unwrap();
    f.raw()
        .execute("UPDATE log_progress SET epoch_id=NULL", [])
        .unwrap();
    assert!(changed(&f, &fence), "the epoch");
    let fence = f.owner.sync_fence(f.id, f.log()).unwrap();
    f.owner
        .record_stop(f.id, f.log(), StopReason::Integrity)
        .unwrap();
    assert!(matches!(
        f.owner.with_sync_fence(&fence, |_| Ok(())),
        Err(OwnerError::Stopped)
    ));
    assert!(matches!(
        f.owner.sync_fence(f.id, f.log()),
        Err(OwnerError::Stopped)
    ));
}

/// An incoming batch read under an authority that ended meanwhile commits
/// nothing; read again under the new one, it commits.
#[test]
fn an_incoming_commit_rechecks_the_authority_it_was_read_under() {
    let mut f = Fixture::new();
    let fence = f.owner.sync_fence(f.id, f.log()).unwrap();
    let note = [42; 32];
    let event = f.remote(note, [9; 32], &seed(f.client(note, f.writer([9; 32]))));
    let mut stale = f.history.clone();
    let batch = f.batch_from(&mut stale, &[&event]);
    f.account.as_mut().unwrap().lock().unwrap();
    let position = f.progress().position;
    let applied = f.owner.apply_remote_batch_fenced(f.id, &fence, batch);
    assert!(matches!(applied, Err(OwnerError::Unbound)), "{applied:?}");
    assert_eq!(f.progress().position, position);
    assert!(!f.owner.has_note(f.id, note).unwrap_or(false));
    let cap = match ready(f.account.as_mut().unwrap().activate()).unwrap() {
        AccountLoad::Active(c) => Arc::new(c),
        _ => panic!("not active"),
    };
    f.owner.authorize(f.id, cap, f.base.0).unwrap();
    let fence = f.owner.sync_fence(f.id, f.log()).unwrap();
    let batch = f.batch(&[&event]);
    let (outcomes, _) = f
        .owner
        .apply_remote_batch_fenced(f.id, &fence, batch)
        .unwrap();
    assert_eq!(outcomes, vec![(f.key(note), NoteOutcome::Accepted)]);
    assert_eq!(f.progress().position, position + 1);
}
