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
use bh_data::{
    Actor, AppId, MutationId, Position, RecordId, RevisionId, Scope, TypeId,
    catalogue::Shipped,
    mutation::{
        ops::{FieldChange, Operation},
        pending::LocalSaved,
    },
    store::{coverage::Coverage, records::RecordRow},
};
use bh_device::{
    ContainerId, Owner, OwnerError, SealRefusal,
    coordinator::Delivery,
    incoming::{LogId, LogKind, NoteOutcome, RefusalReason, StopReason, Unaccepted, VerifiedBatch},
    own_base::create_or_open,
};
use bh_event::{
    ACCOUNT_CHANGE, Binding, CLASS_CONTENT, CLASS_CONTROL, Encoded, History, NOTE, Payload,
    TYPED_DATA, key_id, note_payload, seal,
    writer::{DeviceWriterDeclaration, WriterScope},
};
use bh_storage::{
    NoteKey, PackagePreparation, StoreError,
    retained::RetainedContent,
    sync_state::{PackageOutcome, SyncAlarm},
    typed_outbox::TypedPackagePreparation,
};
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

// A deliberately untrusted far-ahead opening for Ack-mismatch tests. It is
// not derived from a Head and never becomes this device's verified history.
fn forged_ack_before() -> bh_sync::OrderState {
    bh_sync::OrderState::new(
        bh_sync::RawControlHead {
            position: 1,
            node_hash: Digest([3; 32]),
        },
        39,
        Digest([4; 32]),
    )
    .unwrap()
}

/// The Note specialisation these tests bind a Note to: a shipped fixture
/// definition extending the core Note, with an optional `/mood` string.
struct JournalEntry;
impl JournalEntry {
    fn bytes() -> &'static [u8] {
        include_bytes!("../../data/tests/fixtures/types/JournalEntry.json")
    }
    fn app() -> AppId {
        AppId([2; 32])
    }
    fn type_id() -> TypeId {
        bh_data::definition::parse(Self::bytes()).unwrap().type_id
    }
    fn revision() -> RevisionId {
        RevisionId::of(Self::bytes())
    }
    fn bind(note: [u8; 32]) -> Operation {
        Operation::BindNote {
            note: RecordId(note),
            type_id: Self::type_id(),
            revision: Self::revision(),
            doc: serde_json::json!({ "date": 1_700_000_000_000_i64 }),
        }
    }
    fn edit(note: [u8; 32], mood: &str) -> Operation {
        Operation::Edit {
            record: RecordId(note),
            revision: Self::revision(),
            changes: vec![FieldChange {
                path: bh_data::FieldPath::parse("/mood").unwrap(),
                value: Some(serde_json::json!(mood)),
            }],
        }
    }
}

/// A non-Note record type, with the value type it uses, for typed work that
/// must keep applying beside a Note this build cannot show.
struct Recipe;
impl Recipe {
    fn address() -> &'static [u8] {
        include_bytes!("../../data/tests/fixtures/types/Address.json")
    }
    fn bytes() -> &'static [u8] {
        include_bytes!("../../data/tests/fixtures/types/Recipe.json")
    }
    fn type_id() -> TypeId {
        bh_data::definition::parse(Self::bytes()).unwrap().type_id
    }
    fn revision() -> RevisionId {
        RevisionId::of(Self::bytes())
    }
    fn create(record: [u8; 32], name: &str) -> Operation {
        Operation::Create {
            record: RecordId(record),
            type_id: Self::type_id(),
            revision: Self::revision(),
            doc: serde_json::json!({ "name": name }),
        }
    }
}

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
        Self::with_owner(Owner::without_maintenance())
    }
    fn with_owner(owner: Owner) -> Self {
        let dir = tempfile::tempdir().unwrap();
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
        account.confirm_home_ordered(status.head, None).unwrap();
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
        fixture.control = Commitment::order(
            base,
            bh_sync::OrderState::EMPTY,
            &genesis.descriptor,
            Route::Control,
        )
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
            version: 3,
            highest: 3,
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
            self.history.order_state(),
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
    /// A content event of any class-content kind, signed by this device.
    fn content_event(&self, kind: u16, data: &[u8]) -> Encoded {
        let binding = self.binding(
            EventId(bh_crypto::random()),
            self.cap.device_id(),
            CLASS_CONTENT,
            self.hosting.receipt(self.base, self.history.head()),
        );
        let state = self.store.state();
        self.seal_binding(binding, kind, data, state.ordinary.as_ref().unwrap())
    }
    /// A note event for `note` by writer `nonce`, with its declaration and
    /// update authored by the same writer.
    fn note_event(&self, note: [u8; 32], nonce: [u8; 32]) -> Encoded {
        let writer = self.writer(nonce);
        self.remote(note, nonce, &seed(self.client(note, writer)))
    }
    /// A note payload whose writer declaration this build cannot read: the
    /// declaration version is 2, and the Yjs update is otherwise valid.
    fn unsupported_declaration(&self, note: [u8; 32], nonce: [u8; 32]) -> Vec<u8> {
        let writer = self.writer(nonce);
        let mut payload = note_payload(note, writer, &seed(self.client(note, writer)));
        payload[33] = 2;
        payload
    }
    /// The signed author of every event this fixture seals.
    fn actor(&self) -> Actor {
        Actor::Device {
            account: self.cap.account_id().0,
            device: self.cap.device_id().0,
        }
    }
    fn base_scope(&self) -> Scope {
        Scope {
            base: self.base.0,
            audience: [0; 32],
        }
    }
    /// One typed operation's payload, as a publisher hands it to the envelope.
    fn typed_bytes(op: &Operation) -> Vec<u8> {
        bh_data::payload::encode(MutationId::random(), op).unwrap()
    }
    /// A typed-data content event carrying `op`.
    fn typed(&self, op: &Operation) -> Encoded {
        self.content_event(TYPED_DATA, &Self::typed_bytes(op))
    }
    /// Seed the accepted typed state a build with host admission would have
    /// ordered earlier in the log: an app, a Note specialisation and its
    /// activation at typed positions 1-3. Only typed events advance the typed
    /// position, so a test's first typed event must sit at a log position
    /// above 3; Note and control events do not consume those positions.
    fn seed_note_specialisation(&self) {
        self.seed_types(&[JournalEntry::bytes()]);
    }
    /// Seed the app's active state and these type definitions, as a build with
    /// host admission would have ordered them before the log's first typed
    /// event: DefineApp at 1, each definition at 2.., activation last.
    fn seed_types(&self, defs: &[&[u8]]) {
        let raw = self.raw();
        let actor = self.actor();
        let last = defs.len() as u64 + 2;
        let mut ops = vec![(
            1,
            Operation::DefineApp {
                app: JournalEntry::app(),
                name: "Journal".into(),
            },
        )];
        for (index, bytes) in defs.iter().enumerate() {
            ops.push((
                index as u64 + 2,
                Operation::DefineType {
                    bytes: bytes.to_vec(),
                },
            ));
        }
        ops.push((
            last,
            Operation::SetAppState {
                app: JournalEntry::app(),
                active: true,
            },
        ));
        for (position, op) in ops {
            let tx = raw.unchecked_transaction().unwrap();
            let outcome = bh_data::testkit::apply_payload(
                &tx,
                &Shipped,
                self.base_scope(),
                Position(position),
                &actor,
                &bh_data::testkit::assumed_payload(
                    &tx,
                    &Shipped,
                    self.base_scope(),
                    &actor,
                    MutationId::random(),
                    &op,
                )
                .unwrap(),
            )
            .unwrap();
            assert!(
                matches!(outcome, bh_data::mutation::apply::Outcome::Accepted { .. }),
                "seeded definition rejected: {outcome:?}"
            );
            tx.commit().unwrap();
        }
    }
    /// Save a typed operation as this device's pending work, as a local write
    /// would, and return the exact bytes to publish for it.
    fn submit_typed(&self, op: Operation) -> LocalSaved {
        let raw = self.raw();
        let tx = raw.unchecked_transaction().unwrap();
        let saved =
            bh_data::testkit::submit(&tx, &Shipped, self.base_scope(), &self.actor(), op).unwrap();
        tx.commit().unwrap();
        saved
    }
    /// Save and seal the exact local typed package for an incoming echo.
    fn own_typed_package(&self, op: Operation) -> (Encoded, i64, MutationId) {
        let db = self.owner.shared_database(self.id).unwrap();
        let mut db = db.lock().unwrap();
        let queued = db
            .submit_typed(
                &Shipped,
                self.base_scope(),
                &self.actor(),
                op,
                &bh_data::testkit::AssumedAdmission,
            )
            .unwrap();
        let candidate = match db.prepare_typed_package(queued.package).unwrap() {
            TypedPackagePreparation::Candidate(candidate) => candidate,
            TypedPackagePreparation::Existing(_) => panic!("new package already sealed"),
        };
        let binding = self.binding(
            candidate.event_id,
            self.cap.device_id(),
            CLASS_CONTENT,
            self.hosting.receipt(self.base, self.history.head()),
        );
        let encoded = self.seal_binding(
            binding,
            TYPED_DATA,
            &candidate.payload,
            self.store.state().ordinary.as_ref().unwrap(),
        );
        db.publish_typed_package(
            candidate,
            encoded.descriptor.clone(),
            BodyObject::new(encoded.body.clone()).unwrap(),
        )
        .unwrap();
        (encoded, queued.package, queued.saved.mutation)
    }
    fn typed_package_outcome(&self, package: i64) -> Option<PackageOutcome> {
        self.owner
            .shared_database(self.id)
            .unwrap()
            .lock()
            .unwrap()
            .typed_package_progress(package)
            .unwrap()
            .unwrap()
            .outcome
    }
    fn typed_record(&self, note: [u8; 32]) -> Option<RecordRow> {
        let raw = self.raw();
        let sid = bh_data::store::records::lookup_scope(&raw, self.base_scope()).unwrap()?;
        bh_data::store::records::get(&raw, sid, RecordId(note)).unwrap()
    }
    fn typed_coverage(&self) -> Option<Coverage> {
        let raw = self.raw();
        let sid = bh_data::store::records::lookup_scope(&raw, self.base_scope()).unwrap()?;
        Some(bh_data::store::coverage::get(&raw, sid).unwrap())
    }
    /// The Note gaps this replica records for its ordinary scope.
    fn note_gaps(&self) -> i64 {
        let raw = self.raw();
        let Some(sid) = bh_data::store::records::lookup_scope(&raw, self.base_scope()).unwrap()
        else {
            return 0;
        };
        raw.query_row(
            "SELECT count(*) FROM data_note_gap WHERE scope=?1",
            [sid],
            |r| r.get(0),
        )
        .unwrap()
    }
    /// One page of a typed listing, through the shared query contract.
    fn page(&self, select: bh_data::query::TypeSelect) -> bh_data::query::Page {
        let raw = self.raw();
        let scope = self.base_scope();
        bh_data::query::run(
            &raw,
            scope,
            &[scope],
            &Shipped,
            &bh_data::query::Query {
                select,
                filter: None,
                sort: vec![],
                fields: vec![],
                follow: vec![],
                text: None,
                limit: 50,
                after: None,
            },
            bh_data::query::Budget::INTERACTIVE,
        )
        .unwrap_or_else(|e| panic!("query failed: {e:?}"))
    }
    fn parked(&self) -> i64 {
        self.raw()
            .query_row("SELECT count(*) FROM data_parked", [], |r| r.get(0))
            .unwrap()
    }
    fn parked_rows(&self) -> Vec<(i64, String, Vec<u8>)> {
        self.raw()
            .prepare("SELECT position,affects,payload FROM data_parked ORDER BY position")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }
    fn pending_typed(&self) -> i64 {
        self.raw()
            .query_row("SELECT count(*) FROM data_pending", [], |r| r.get(0))
            .unwrap()
    }
    fn retained(&self) -> Vec<RetainedContent> {
        self.owner
            .shared_database(self.id)
            .unwrap()
            .lock()
            .unwrap()
            .retained_content(self.base.0, [0; 32], None, 256)
            .unwrap()
    }
    /// Order and verify these events after `history`'s head, as a puller does.
    fn batch_from(&self, history: &mut History, events: &[&Encoded]) -> VerifiedBatch {
        let mut applied = Vec::new();
        for event in events {
            let route = self.route(history.head(), &event.descriptor);
            let ordered =
                Commitment::order(self.base, history.order_state(), &event.descriptor, route)
                    .unwrap();
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
            "data_scope",
            "data_app",
            "data_app_at",
            "data_type",
            "data_type_at",
            "data_definition",
            "data_ordered",
            "data_coverage",
            "data_record",
            "data_field_clock",
            "data_history",
            "data_pending",
            "data_parked",
            "data_retained",
            "data_note_gap",
            "data_index_entry",
            "data_unique",
            "data_ref",
            "data_text_state",
            "data_text_job",
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
fn same_nonce_under_a_hold_does_not_conflict_with_the_package() {
    let mut f = Fixture::new();
    let (note, id) = f.own_work();
    let own = f.package(id);
    let clash = f.seal(
        own.descriptor.nonce(),
        note,
        f.writer([99; 32]),
        &[255, 255],
    );
    let batch = f.batch(&[&clash]);
    let result =
        bh_core::contained::with_fuel(0, || f.owner.apply_remote_batch(f.id, batch)).unwrap();
    assert_eq!(result, vec![(f.key(note), NoteOutcome::Waiting)]);
    assert_ne!(
        clash.descriptor.publication_id(Route::Content),
        own.descriptor.publication_id(Route::Content)
    );
    assert_eq!(f.unaccepted(note), vec![(id, Unaccepted::Sealed)]);
    assert!(f.alarms().is_empty());
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
    let catalogue = f
        .owner
        .shared_database(f.id)
        .unwrap()
        .lock()
        .unwrap()
        .list_notes(f.base.0, [0; 32], None, 10)
        .unwrap();
    assert_eq!(
        listed.iter().map(|e| e.note).collect::<Vec<_>>(),
        catalogue.iter().map(|e| e.note).collect::<Vec<_>>(),
        "incoming ordinary Note changes preserve catalogue order"
    );
}

#[test]
fn plain_note_list_matches_catalogue_after_local_and_incoming_commits() {
    let mut f = Fixture::new();
    let (local, _) = f.own_work();
    let first_remote = [70; 32];
    let incoming = f.note_event(first_remote, [1; 32]);
    assert_eq!(f.apply(&[&incoming]).len(), 1);
    let (next_local, _) = f.own_work();
    let second_remote = [71; 32];
    let incoming = f.note_event(second_remote, [2; 32]);
    assert_eq!(f.apply(&[&incoming]).len(), 1);
    let writer = f.writer([1; 32]);
    let client = f.client(first_remote, writer);
    let incoming = f.remote(
        first_remote,
        [1; 32],
        &item(client, 7, (client, 6), None, "more"),
    );
    assert_eq!(
        f.apply(&[&incoming]),
        vec![(f.key(first_remote), NoteOutcome::Accepted)]
    );
    let old = f
        .owner
        .shared_database(f.id)
        .unwrap()
        .lock()
        .unwrap()
        .list_notes(f.base.0, [0; 32], None, 50)
        .unwrap();
    let new = f.owner.list_notes_page(f.id, None, 50).unwrap();
    assert_eq!(new.completeness, bh_data::query::Completeness::Complete);
    assert_eq!(
        new.rows.iter().map(|r| r.note).collect::<Vec<_>>(),
        old.iter().map(|r| r.note).collect::<Vec<_>>()
    );
    assert_eq!(
        new.rows.iter().map(|r| r.note).collect::<Vec<_>>(),
        vec![first_remote, second_remote, next_local, local]
    );
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
    let lie =
        Commitment::order(f.base, forged_ack_before(), &own.descriptor, Route::Content).unwrap();
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
fn a_control_with_the_same_nonce_does_not_conflict_with_a_content_package() {
    let mut f = Fixture::new();
    let (note, id) = f.own_work();
    let honest = f.package(id);
    // Even this device's signed control with the same nonce is a distinct
    // route-derived publication and cannot reserve the content package ID.
    let (change, _, _) = f.add_device(honest.descriptor.nonce());
    f.apply_control(&change);
    assert_eq!(change.descriptor.nonce(), honest.descriptor.nonce());
    assert_ne!(
        change.descriptor.publication_id(Route::Control),
        honest.descriptor.publication_id(Route::Content)
    );
    assert_eq!(f.unaccepted(note), vec![(id, Unaccepted::Sealed)]);
    assert_eq!(f.pending(), 1);
    assert!(f.alarms().is_empty());
    let progress = f.progress();
    assert_eq!(progress.stopped, None);
    assert_eq!(progress.position, f.history.head().position);
    assert_eq!(f.working(note).title_preview().unwrap(), "mine");
}

#[test]
fn another_devices_content_with_the_same_nonce_does_not_conflict() {
    let mut f = Fixture::new();
    let (note, id) = f.own_work();
    let honest = f.package(id);
    let (change, device, signing) = f.add_device(EventId(bh_crypto::random()));
    f.apply_control(&change);
    // The account's other device reuses the nonce, not the publication ID.
    let writer = DeviceWriterDeclaration {
        account: f.cap.account_id().0,
        device: device.0,
        nonce: [5; 32],
    };
    let binding = f.binding(
        honest.descriptor.nonce(),
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
    assert_ne!(
        taken.descriptor.publication_id(Route::Content),
        honest.descriptor.publication_id(Route::Content)
    );
    assert_eq!(f.unaccepted(note), vec![(id, Unaccepted::Sealed)]);
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

    // Other bytes with this device's nonce are a separate publication.
    // The local package remains sealed and can still be sent unchanged.
    let ids = f.pending_ids();
    let honest = f.package(ids[0]);
    let forged = f.seal(
        honest.descriptor.nonce(),
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
    assert_eq!(f.unaccepted(note), vec![(ids[0], Unaccepted::Sealed)]);
    assert!(f.working(note).title_preview().unwrap().starts_with("mine"));
    assert!(f.alarms().is_empty());
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
        Ok(PackagePreparation::Existing(_))
    ));
}

#[test]
fn an_invalid_event_with_the_same_nonce_does_not_conflict() {
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
    // The invalid submission consumes its distinct routed ID; its matching
    // nonce cannot consume the pending package's publication identity.
    let taken = f.seal_with_receipt(
        honest.descriptor.nonce(),
        note,
        f.writer([5; 32]),
        &seed(f.client(note, f.writer([5; 32]))),
        [0; RECEIPT_LEN],
    );
    assert!(f.apply(&[&taken]).is_empty());
    assert_eq!(f.pending(), 1);
    assert_eq!(f.unaccepted(note), vec![(id, Unaccepted::Sealed)]);
    assert!(f.alarms().is_empty());
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
    let order_b = Commitment::order(
        f.base,
        f.history.order_state(),
        &pb.descriptor,
        Route::Content,
    )
    .unwrap();
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
        Commitment::order(f.base, order_b.after(), &pc.descriptor, Route::Content).unwrap();
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
    let lie =
        Commitment::order(f.base, forged_ack_before(), &own.descriptor, Route::Content).unwrap();
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

    // K2 work and a fresh publication reusing a nonce are accepted; an
    // exact original already stored before the restart is rejected by its
    // routed ID while structural history still advances.
    let (ns, np, nh, nl) = k2_nonces(&f, note);
    let [s, p, h, l] = [ns, np, nh, nl].map(|x| f.client(note, f.writer(x)));
    let mut events: Vec<Encoded> = [ns, np, nh, nl]
        .iter()
        .zip(k2_updates(s, p, h, l))
        .map(|(n, u)| f.remote(note, *n, &u))
        .collect();
    let reused_nonce_update = item(l, 6, (l, 5), None, "?");
    events.push(f.seal(
        first.descriptor.nonce(),
        note,
        f.writer(nl),
        &reused_nonce_update,
    ));
    assert_ne!(
        events
            .last()
            .unwrap()
            .descriptor
            .publication_id(Route::Content),
        first.descriptor.publication_id(Route::Content)
    );
    events.push(Encoded {
        descriptor: first.descriptor.clone(),
        body: first.body.clone(),
    });
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
    assert_eq!(outcomes[outcomes.len() - 2], bh_event::Outcome::Accepted);
    assert_eq!(*outcomes.last().unwrap(), bh_event::Outcome::Rejected);
    assert_eq!(
        batch.events.last().unwrap().commitment().event_id(),
        first.descriptor.publication_id(Route::Content)
    );
    assert_eq!(from_resumed.head(), from_live.head());
    assert_eq!(
        from_resumed.order_state(),
        batch.events.last().unwrap().commitment().after()
    );
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
    refs.push(&reused_nonce_update);
    assert_eq!(f.accepted(note).digest().unwrap(), digest_of(&refs).0);
    // The next resume continues from the batch just committed.
    let again = f
        .owner
        .history(f.id, f.log(), &f.anchor, f.hosting.root.public(), 1)
        .unwrap();
    assert_eq!(again.head(), from_live.head());
    assert_eq!(again.order_state(), from_live.order_state());
}

#[test]
fn canonical_genesis_floor_is_stored_at_its_position() {
    let mut f = Fixture::new();
    let note = [7; 32];
    let s = f.client(note, f.writer([1; 32]));
    let first = f.remote(note, [1; 32], &seed(s));
    f.apply(&[&first]);
    let db = f.owner.shared_database(f.id).unwrap();
    assert_eq!(
        db.lock().unwrap().floor_rises(1, f.base.0).unwrap(),
        vec![(1, 3)]
    );
    // After the first v3 event was accepted at floor 3, a remembered
    // rise above v3 must reject the next v3 event and persist at position 2.
    f.history = f
        .owner
        .history(f.id, f.log(), &f.anchor, f.hosting.root.public(), 4)
        .unwrap();
    let later = f.remote(note, [1; 32], &item(s, 7, (s, 6), None, "!"));
    assert!(f.apply(&[&later]).is_empty(), "v3 after a floor rise to 4");
    assert_eq!(
        db.lock().unwrap().floor_rises(1, f.base.0).unwrap(),
        vec![(1, 3), (2, 4)]
    );
    assert!(
        f.accepted(note)
            .title_preview()
            .unwrap()
            .starts_with("hello")
    );
    let resumed = f
        .owner
        .history(f.id, f.log(), &f.anchor, f.hosting.root.public(), 1)
        .unwrap();
    assert_eq!(resumed.floor(), 4);
    // Replaying the originals with the stored rises judges each event under
    // the floor in force at its position, as live verification did.
    let stored = db.lock().unwrap().own_base().unwrap().unwrap();
    let genesis = OpaqueEvent::decode(&stored.genesis_descriptor).unwrap();
    let mut records = vec![(
        Commitment::order(f.base, bh_sync::OrderState::EMPTY, &genesis, Route::Control).unwrap(),
        stored.genesis_descriptor.clone(),
        stored.genesis_body.clone(),
    )];
    for event in [&first, &later] {
        let previous = records.last().unwrap().0.after();
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
    assert_eq!(replayed.floor(), 4);
    assert_eq!(replayed.account_head(), resumed.account_head());
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

/// Generous bound on waiting for a worker report; it only stops a hung test.
const HANG: std::time::Duration = std::time::Duration::from_secs(60);

/// Waits out the maintenance setup scheduled itself (registration, genesis):
/// a turn decides whether it continues before reporting, so an idle
/// container after a report has nothing queued, deferred or running.
fn settle_setup_maintenance(f: &Fixture, turns: &std::sync::mpsc::Receiver<(ContainerId, usize)>) {
    while !f.owner.maintenance_idle(f.id) {
        let (id, _) = turns.recv_timeout(HANG).expect("setup maintenance");
        assert_eq!(id, f.id);
    }
    while turns.try_recv().is_ok() {}
}

#[test]
fn typed_only_saves_schedule_a_quiet_checkpoint() {
    let clock = Arc::new(std::sync::Mutex::new(Instant::now()));
    let (completed, turns) = std::sync::mpsc::channel();
    let now = {
        let clock = Arc::clone(&clock);
        move || *clock.lock().unwrap()
    };
    let f = Fixture::with_owner(Owner::notifying_maintenance_with_clock(
        completed,
        now,
        std::time::Duration::from_millis(750),
    ));
    settle_setup_maintenance(&f, &turns);
    let before = f.owner.maintenance_stats(f.id).unwrap().len();
    assert!(before < 64, "the diagnostics ring still counts new turns");
    let records = f.owner.records(f.id).unwrap();
    let db = f.owner.shared_database(f.id).unwrap();
    db.lock()
        .unwrap()
        .with_data_read(|conn| {
            conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
                .unwrap();
            Ok(())
        })
        .unwrap();
    for n in 0..100u8 {
        records
            .submit(Operation::DefineApp {
                app: AppId([n; 32]),
                name: format!("App {n}"),
            })
            .unwrap();
    }
    // The burst's turn waits for a quiet period the test clock has not
    // reached, so nothing ran during the burst.
    assert!(
        !f.owner.maintenance_idle(f.id),
        "typed saves must schedule quiet maintenance"
    );
    assert!(turns.try_recv().is_err());
    assert_eq!(f.owner.maintenance_stats(f.id).unwrap().len(), before);
    *clock.lock().unwrap() += std::time::Duration::from_millis(751);
    f.owner.wake_maintenance();
    let (id, _) = turns.recv_timeout(HANG).expect("the post-burst turn");
    assert_eq!(id, f.id);
    let stats = f.owner.maintenance_stats(f.id).unwrap();
    assert_eq!(stats.len(), before + 1, "exactly the post-burst turn ran");
    assert!(
        stats[before].checkpoint_frames > 0,
        "typed saves must checkpoint in a quiet turn, below the inline cap: {:?}",
        stats[before]
    );
}

#[test]
fn a_records_handle_kept_after_owner_drop_holds_no_workers() {
    let (completed, turns) = std::sync::mpsc::channel();
    let f = Fixture::with_owner(Owner::notifying_maintenance(completed));
    let records = f.owner.records(f.id).unwrap();
    let (dir, owner, id) = {
        let f = f;
        let Fixture { dir, owner, id, .. } = f;
        (dir, owner, id)
    };
    drop(owner);
    // Dropping the Owner joined its workers: the scheduler and both workers
    // held the only senders, so the report channel closes once they exit.
    loop {
        match turns.recv_timeout(HANG) {
            Ok((turn, _)) => assert_eq!(turn, id),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                panic!("a records handle kept the Owner's workers alive")
            }
        }
    }
    // The handle still saves; with no scheduler left it schedules nothing.
    records
        .submit(Operation::DefineApp {
            app: AppId([3; 32]),
            name: "After".into(),
        })
        .unwrap();
    drop(records);
    // Nothing holds the container now: an ordinary Owner opens the same file.
    let path = std::fs::read_dir(dir.path().join("accounts"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "sqlite"))
        .unwrap();
    bh_storage::DeviceDatabase::open(&path).expect("container released after the handle");
}

#[test]
fn stop_is_sticky_and_keeps_state() {
    // The fixture excludes unrelated body extraction between exact snapshots.
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
    assert_eq!(encoded.descriptor.nonce(), candidate.event_id);
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

#[test]
fn note_seal_checks_base_and_anchor_before_missing_declaration() {
    let mut f = Fixture::new();
    let (_, id) = f.own_work();
    let db = f.owner.shared_database(f.id).unwrap();
    let bh_storage::PackagePreparation::Candidate(mut candidate) =
        db.lock().unwrap().prepare_note_package(id).unwrap()
    else {
        panic!("already packaged")
    };
    candidate.pending.writer = None;
    candidate.pending.key.base = [3; 32];
    let seal = |candidate: &bh_storage::PackageCandidate, anchor: &bh_account::VerifiedAccount| {
        f.owner
            .prepare_note_seal(
                f.id,
                anchor,
                f.hosting.root.public(),
                &f.metadata,
                &f.content,
                candidate,
            )
            .map(|_| ())
    };
    assert!(matches!(
        seal(&candidate, &f.anchor),
        Err(OwnerError::Unbound)
    ));
    candidate.pending.key.base = f.base.0;
    let other = Fixture::new();
    assert!(matches!(
        seal(&candidate, &other.anchor),
        Err(OwnerError::AnchorMismatch)
    ));
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

/// A content kind this build does not know is kept exactly where it was
/// ordered: the notes around it apply, verified progress advances, and the
/// scope's typed coverage stays incomplete while the bytes are held.
#[test]
fn unsupported_typed_version_requires_newer_build_for_its_base() {
    let mut f = Fixture::new();
    let mut bytes = Fixture::typed_bytes(&JournalEntry::bind([21; 32]));
    bytes[..2].copy_from_slice(&2u16.to_be_bytes());
    let event = f.content_event(TYPED_DATA, &bytes);
    assert!(f.apply(&[&event]).is_empty());
    assert_eq!(f.parked(), 1);
    let db = f.owner.shared_database(f.id).unwrap();
    assert!(!db.lock().unwrap().needs_newer_build([91; 32]).unwrap());
    assert!(db.lock().unwrap().needs_newer_build(f.base.0).unwrap());
}

#[test]
fn retained_unknown_content_keeps_its_bytes_and_notes_apply() {
    let mut f = Fixture::new();
    f.seed_note_specialisation();
    let (a, b) = ([21; 32], [22; 32]);
    let create_a = f.note_event(a, [1; 32]);
    let unknown = f.content_event(0xf123, b"unknown content kind");
    let create_b = f.note_event(b, [2; 32]);
    let outcomes = f.apply(&[&create_a, &unknown, &create_b]);
    assert_eq!(
        outcomes,
        vec![
            (f.key(a), NoteOutcome::Accepted),
            (f.key(b), NoteOutcome::Accepted)
        ]
    );
    assert_eq!(f.progress().position, 4);
    let retained = f.retained();
    assert_eq!(retained.len(), 1);
    let row = &retained[0];
    assert_eq!(row.position, Position(3));
    assert_eq!(row.kind, 0xf123);
    assert_eq!(row.payload, b"unknown content kind");
    assert_eq!(row.note, None);
    assert_eq!(row.audience, [0; 32]);
    assert_eq!(
        row.author,
        Some((f.cap.account_id().0, f.cap.device_id().0))
    );
    let coverage = f.typed_coverage().unwrap();
    assert_eq!(coverage.through, Some(Position(4)));
    assert!(
        coverage.complete,
        "the typed log is complete; unknown content is not a typed gap"
    );
    assert_eq!(f.accepted(a).title_preview().unwrap(), "hello");
    // A newer build is needed, and only that line says so.
    let db = f.owner.shared_database(f.id).unwrap();
    assert!(db.lock().unwrap().needs_newer_build(f.base.0).unwrap());
    // Unknown outer content is not a Note gap: Note listings stay complete.
    assert_eq!(f.note_gaps(), 0);
    assert_eq!(
        f.page(bh_data::query::TypeSelect::Family(TypeId::core("note")))
            .completeness,
        bh_data::query::Completeness::Complete
    );

    // Unknown content is not a blanket stop: typed work still applies here.
    let bind = f.typed(&JournalEntry::bind(a)); // position 5
    assert!(f.apply(&[&bind]).is_empty());
    let record = f.typed_record(a).unwrap();
    assert_eq!(record.type_id, JournalEntry::type_id());
    assert_eq!(record.accepted.unwrap()["date"], 1_700_000_000_000_i64);
    assert!(f.typed_coverage().unwrap().complete);

    // Reopen: the exact bytes and the honest incomplete coverage survive.
    let raw = f.raw();
    let path = std::path::PathBuf::from(raw.path().unwrap());
    drop(raw);
    let raw = rusqlite::Connection::open(&path).unwrap();
    let rows: Vec<(i64, i64, Vec<u8>)> = raw
        .prepare("SELECT position,kind,payload FROM data_retained ORDER BY position")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows, vec![(3, 0xf123, b"unknown content kind".to_vec())]);
    let sid = bh_data::store::records::lookup_scope(&raw, f.base_scope())
        .unwrap()
        .unwrap();
    let coverage = bh_data::store::coverage::get(&raw, sid).unwrap();
    assert_eq!(coverage.through, Some(Position(5)));
    assert!(coverage.complete);
    assert_eq!(
        raw.query_row("SELECT count(*) FROM data_note_gap", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0,
        "unknown outer content names no Note"
    );
}

/// A Note is created, bound to its specialisation and extended by typed
/// operations interleaved with another Note's update. Every effect lands in
/// log order: the binding sees the Note created before it, and the extension
/// edit sees both.
#[test]
fn typed_note_binding_and_extension_apply_in_log_order() {
    let mut f = Fixture::new();
    f.seed_note_specialisation();
    let (a, b) = ([31; 32], [32; 32]);
    let wa = f.writer([1; 32]);
    let wb = f.writer([2; 32]);
    let create_a = f.remote(a, [1; 32], &seed(f.client(a, wa))); // position 2
    let create_b = f.remote(b, [2; 32], &seed(f.client(b, wb))); // position 3
    let bind = f.typed(&JournalEntry::bind(a)); // position 4
    let update_b = f.remote(b, [3; 32], &seed(f.client(b, f.writer([3; 32])))); // position 5
    let edit = f.typed(&JournalEntry::edit(a, "glad")); // position 6
    let outcomes = f.apply(&[&create_a, &create_b, &bind, &update_b, &edit]);
    assert_eq!(
        outcomes,
        vec![
            (f.key(a), NoteOutcome::Accepted),
            (f.key(b), NoteOutcome::Accepted),
            (f.key(b), NoteOutcome::Accepted),
        ]
    );
    let record = f.typed_record(a).unwrap();
    assert_eq!(record.type_id, JournalEntry::type_id());
    assert_eq!(record.revision, JournalEntry::revision());
    let accepted = record.accepted.unwrap();
    assert_eq!(accepted["date"], 1_700_000_000_000_i64);
    assert_eq!(accepted["mood"], "glad");
    // The other Note is untouched by typed work and keeps its own update.
    assert_eq!(f.typed_record(b).unwrap().type_id, TypeId::core("note"));
    assert_eq!(f.accepted(a).title_preview().unwrap(), "hello");
    assert_eq!(f.parked(), 0);
    assert!(f.typed_coverage().unwrap().complete);
}

/// A typed binding ordered before its Note creates parks, then applies at its
/// own position once the Note's projection arrives: in the same batch, and in
/// a later one.
#[test]
fn a_binding_before_its_note_parks_then_applies_at_its_position() {
    let mut f = Fixture::new();
    f.seed_note_specialisation();
    let (a, b) = ([41; 32], [42; 32]);
    let wb = f.writer([2; 32]);
    // Non-typed events first, so the typed operations sit above the fixture's
    // seeded typed positions.
    let create_b = f.remote(b, [1; 32], &seed(f.client(b, wb)));
    let update_b = f.remote(b, [2; 32], &seed(f.client(b, f.writer([3; 32]))));
    let bind = f.typed(&JournalEntry::bind(a));
    assert_eq!(f.apply(&[&create_b, &update_b, &bind]).len(), 2);

    // The binding waits for its Note, under that record only.
    assert_eq!(f.parked(), 1);
    let parked = f.parked_rows();
    assert_eq!(parked[0].0, 4);
    assert_eq!(parked[0].1, format!("r:{}", hex(&a)));
    assert!(f.typed_record(a).is_none());

    // The Note's projection arrives in the next batch and unblocks it.
    let wa = f.writer([1; 32]);
    let create_a = f.remote(a, [1; 32], &seed(f.client(a, wa)));
    let outcomes = f.apply(&[&create_a]);
    assert_eq!(outcomes, vec![(f.key(a), NoteOutcome::Accepted)]);
    assert_eq!(f.parked(), 0, "the parked binding replayed in order");
    let record = f.typed_record(a).unwrap();
    assert_eq!(record.type_id, JournalEntry::type_id());
    assert_eq!(record.accepted.unwrap()["date"], 1_700_000_000_000_i64);
}

/// The same relation inside one batch: the Note's projection is created at
/// its first accepted position, so a binding ordered after it applies, and a
/// binding ordered before it waits.
#[test]
fn a_batch_applies_a_binding_after_its_note_and_parks_one_before_it() {
    let mut f = Fixture::new();
    f.seed_note_specialisation();
    let (a, b) = ([51; 32], [52; 32]);
    let create_a = f.note_event(a, [1; 32]); // position 2
    let update_a = f.note_event(a, [2; 32]); // position 3
    let bind_b = f.typed(&JournalEntry::bind(b)); // position 4: before b exists
    let create_b = f.note_event(b, [3; 32]); // position 5
    let bind_a = f.typed(&JournalEntry::bind(a)); // position 6: after a exists
    let outcomes = f.apply(&[&create_a, &update_a, &bind_b, &create_b, &bind_a]);
    assert_eq!(
        outcomes,
        vec![
            (f.key(a), NoteOutcome::Accepted),
            (f.key(a), NoteOutcome::Accepted),
            (f.key(b), NoteOutcome::Accepted),
        ]
    );
    // Both bindings applied: the early one from the batch's dependency replay,
    // the later one directly, each at its own position.
    assert_eq!(f.typed_record(a).unwrap().type_id, JournalEntry::type_id());
    assert_eq!(f.typed_record(b).unwrap().type_id, JournalEntry::type_id());
    assert_eq!(f.parked(), 0);
}

/// An unreadable Note declaration waits for its own Note only: later events
/// for that Note are kept behind it in order, other Notes carry on, and the
/// Note never appears empty or partly updated.
#[test]
fn an_unreadable_note_declaration_waits_for_its_own_note_only() {
    let mut f = Fixture::new();
    f.seed_types(&[Recipe::address(), Recipe::bytes()]);
    let (a, b, c) = ([61; 32], [62; 32], [63; 32]);
    let create_b = f.note_event(b, [1; 32]); // 2
    let create_a = f.note_event(a, [2; 32]); // 3
    let bad_a = f.content_event(NOTE, &f.unsupported_declaration(a, [3; 32])); // 4
    let bad_c = f.content_event(NOTE, &f.unsupported_declaration(c, [4; 32])); // 5
    let later_a = f.note_event(a, [5; 32]); // 6
    let later_c = f.note_event(c, [6; 32]); // 7
    let later_b = f.note_event(b, [7; 32]); // 8
    let outcomes = f.apply(&[
        &create_b, &create_a, &bad_a, &bad_c, &later_a, &later_c, &later_b,
    ]);
    assert_eq!(
        outcomes,
        vec![
            (f.key(b), NoteOutcome::Accepted),
            (f.key(a), NoteOutcome::Accepted),
            (f.key(a), NoteOutcome::Waiting),
            (f.key(c), NoteOutcome::Waiting),
            (f.key(b), NoteOutcome::Accepted),
        ]
    );
    assert_eq!(f.progress().position, 8);
    let retained = f.retained();
    let positions: Vec<u64> = retained.iter().map(|r| r.position.0).collect();
    assert_eq!(positions, vec![4, 5, 6, 7]);
    assert!(retained.iter().all(|r| r.kind == NOTE));
    assert_eq!(retained[0].payload, f.unsupported_declaration(a, [3; 32]));
    assert_eq!(retained[1].payload, f.unsupported_declaration(c, [4; 32]));
    assert_eq!(retained[0].note, Some(a));
    assert_eq!(retained[1].note, Some(c));
    // The later events are kept exactly as their authors sealed them.
    assert_eq!(
        retained[2].payload,
        note_payload(a, f.writer([5; 32]), &seed(f.client(a, f.writer([5; 32]))))
    );
    assert_eq!(
        retained[3].payload,
        note_payload(c, f.writer([6; 32]), &seed(f.client(c, f.writer([6; 32]))))
    );
    // A keeps the content it had before the wait; C never appears at all.
    assert_eq!(f.accepted(a).title_preview().unwrap(), "hello");
    assert!(f.owner.show_note("c", f.id, c).is_err());
    assert!(f.typed_record(c).is_none());
    let coverage = f.typed_coverage().unwrap();
    assert_eq!(coverage.through, Some(Position(8)));
    assert!(coverage.complete, "the typed log is complete through 8");
    // Each Note with unreadable content is a gap in that record, and only the
    // Note family reads incomplete.
    assert_eq!(f.note_gaps(), 2);
    assert_eq!(
        f.page(bh_data::query::TypeSelect::Family(TypeId::core("note")))
            .completeness,
        bh_data::query::Completeness::Incomplete(vec![bh_data::query::Gap::NoteUnavailable])
    );
    assert_eq!(
        f.page(bh_data::query::TypeSelect::Exact(Recipe::type_id()))
            .completeness,
        bh_data::query::Completeness::Complete
    );
    // Unrelated typed work still applies, with nothing parked.
    let soup = f.typed(&Recipe::create([200; 32], "Soup")); // 9
    assert!(f.apply(&[&soup]).is_empty());
    assert_eq!(
        f.typed_record([200; 32]).unwrap().type_id,
        Recipe::type_id()
    );
    assert_eq!(f.parked(), 0);
    // A typed change to the gapped Note waits for that record, undecided.
    let edit = f.typed(&Operation::Edit {
        record: RecordId(c),
        revision: bh_data::catalogue::baseline_note().1,
        changes: vec![FieldChange {
            path: bh_data::FieldPath::parse("/mood").unwrap(),
            value: Some(serde_json::json!("waiting")),
        }],
    }); // 10
    assert!(f.apply(&[&edit]).is_empty());
    let parked = f.parked_rows();
    assert_eq!(parked.len(), 1);
    assert_eq!(parked[0].0, 10);
    assert_eq!(parked[0].1, format!("r:{}", hex(&c)));
    // Nothing here is retried on a timer: only a newer build can read it.
    let (retried, _) = f.owner.retry_held(f.id, f.key(a)).unwrap();
    assert!(retried.is_empty());
    assert_eq!(f.accepted(a).title_preview().unwrap(), "hello");
    assert_eq!(
        f.retained(),
        retained,
        "reopen-equivalent state is unchanged"
    );
}

/// A malformed typed payload, an unsupported inner version and content the
/// rules refuse each take their own outcome; none of them stops Notes, and an
/// unsupported version waits under its declared `affects` only.
#[test]
fn malformed_unsupported_and_invalid_typed_payloads_take_their_own_outcomes() {
    let mut f = Fixture::new();
    f.seed_note_specialisation();
    let (a, b) = ([71; 32], [72; 32]);
    let create_a = f.note_event(a, [1; 32]); // 2
    let create_b = f.note_event(b, [2; 32]); // 3
    // Version 1 with a header that parses but is not a payload header.
    let malformed = f.content_event(TYPED_DATA, &[0, 1, 0, 0, 0, 2, b'{', b'}']); // 4
    // A well-formed edit whose version bytes are from the future: the
    // header's `affects` still names the record it would change.
    let mut bytes = Fixture::typed_bytes(&JournalEntry::edit(a, "glad"));
    bytes[0] = 0xff;
    bytes[1] = 0xff;
    let unsupported = f.content_event(TYPED_DATA, &bytes); // 5
    // A well-formed edit the rules refuse: /mood is not a core Note field.
    // It names another record, so the unreadable version above does not
    // queue it behind that record's wait.
    let invalid = f.typed(&Operation::Edit {
        record: RecordId(b),
        revision: bh_data::catalogue::baseline_note().1,
        changes: vec![FieldChange {
            path: bh_data::FieldPath::parse("/mood").unwrap(),
            value: Some(serde_json::json!("cross")),
        }],
    }); // 6
    let later_a = f.note_event(a, [3; 32]); // 7
    let bind_b = f.typed(&JournalEntry::bind(b)); // 8: another record applies
    let bind_a = f.typed(&JournalEntry::bind(a)); // 9: queued behind the wait
    let outcomes = f.apply(&[
        &create_a,
        &create_b,
        &malformed,
        &unsupported,
        &invalid,
        &later_a,
        &bind_b,
        &bind_a,
    ]);
    assert_eq!(
        outcomes,
        vec![
            (f.key(a), NoteOutcome::Accepted),
            (f.key(b), NoteOutcome::Accepted),
            (f.key(a), NoteOutcome::Accepted),
        ],
        "typed outcomes never become Note outcomes"
    );
    // The refused edit left the Note alone: only the later binding changed it.
    let projection = f.typed_record(b).unwrap();
    assert_eq!(projection.type_id, JournalEntry::type_id());
    let accepted = projection.accepted.unwrap();
    assert!(accepted.get("mood").is_none(), "{accepted}");
    assert_eq!(accepted["date"], 1_700_000_000_000_i64);
    // The unreadable version waits under its own record only, and the binding
    // of that record queues behind it.
    let parked = f.parked_rows();
    assert_eq!(parked.len(), 2);
    assert_eq!(parked[0].0, 5);
    assert_eq!(parked[0].1, format!("r:{}", hex(&a)));
    assert_eq!(parked[0].2, bytes);
    assert_eq!(parked[1].0, 9);
    assert_eq!(parked[1].1, format!("r:{}", hex(&a)));
    assert_eq!(f.accepted(a).title_preview().unwrap(), "hello");
    assert_eq!(f.progress().position, 9);
}

/// This replica's own typed work is retired by its exact ordered echo, once;
/// a second delivery of the same payload changes nothing more.
#[test]
fn own_typed_echo_retires_local_work_exactly_once() {
    let mut f = Fixture::new();
    f.seed_note_specialisation();
    let a = [81; 32];
    let create_a = f.note_event(a, [1; 32]); // 2
    let filler = f.note_event([82; 32], [2; 32]); // 3
    assert_eq!(f.apply(&[&create_a, &filler]).len(), 2);
    let saved = f.submit_typed(JournalEntry::bind(a));
    assert_eq!(f.pending_typed(), 1);
    let echo = f.content_event(TYPED_DATA, &saved.payload); // 4
    assert!(f.apply(&[&echo]).is_empty());
    assert_eq!(f.pending_typed(), 0, "the exact echo retired the work");
    let record = f.typed_record(a).unwrap();
    assert_eq!(record.type_id, JournalEntry::type_id());
    assert_eq!(
        record.accepted.clone().unwrap()["date"],
        1_700_000_000_000_i64
    );
    // A duplicate delivery of the same bytes is idempotent.
    let again = f.content_event(TYPED_DATA, &saved.payload); // 5
    assert!(f.apply(&[&again]).is_empty());
    assert_eq!(f.pending_typed(), 0);
    assert_eq!(f.typed_record(a).unwrap().accepted, record.accepted);
    assert_eq!(f.parked(), 0);
}

/// A missing Note projection parks this device's exact edit, which a
/// later Note projection and replay settle in the same incoming transaction.
#[test]
fn parked_own_typed_edit_settles_after_later_projection() {
    let mut f = Fixture::new();
    f.seed_note_specialisation();
    let record = [131; 32];
    let creation = f.note_event(record, [9; 32]);
    let filler = f.note_event([180; 32], [20; 32]);
    assert_eq!(f.apply(&[&creation, &filler]).len(), 2);
    let binding = f.typed(&JournalEntry::bind(record));
    assert!(f.apply(&[&binding]).is_empty());
    let (edit, package, mutation) = f.own_typed_package(JournalEntry::edit(record, "bright"));
    let raw = f.raw();
    let tx = raw.unchecked_transaction().unwrap();
    // Simulate a missing local Note projection while keeping the signed
    // ordered history and the saved pending edit intact.
    tx.execute(
        "DELETE FROM data_record WHERE record=?1",
        [record.as_slice()],
    )
    .unwrap();
    bh_data::note::mark_unavailable(&tx, f.base_scope(), RecordId(record)).unwrap();
    tx.commit().unwrap();
    let rebound = f.typed(&JournalEntry::bind(record));
    assert!(f.apply(&[&rebound]).is_empty());
    assert!(f.apply(&[&edit]).is_empty());
    assert_eq!(f.parked(), 2);
    assert_eq!(f.pending_typed(), 1);
    let waiting = f
        .owner
        .shared_database(f.id)
        .unwrap()
        .lock()
        .unwrap()
        .typed_package_progress(package)
        .unwrap()
        .unwrap();
    assert_eq!(waiting.outcome, None);
    assert_eq!(waiting.payload_position, Some(6));
    let next = f.note_event(record, [10; 32]);
    assert_eq!(f.apply(&[&next]).len(), 1);
    assert_eq!(f.parked(), 0);
    assert_eq!(
        f.typed_package_outcome(package),
        Some(PackageOutcome::Accepted)
    );
    let remaining: i64 = f
        .raw()
        .query_row(
            "SELECT count(*) FROM data_pending WHERE mutation=?1",
            [mutation.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(remaining, 0);
    assert_eq!(
        f.typed_record(record).unwrap().accepted.unwrap()["mood"],
        "bright"
    );
    let settled = f
        .owner
        .shared_database(f.id)
        .unwrap()
        .lock()
        .unwrap()
        .typed_package_progress(package)
        .unwrap()
        .unwrap();
    assert!(f.apply(&[&edit]).is_empty());
    assert_eq!(
        f.owner
            .shared_database(f.id)
            .unwrap()
            .lock()
            .unwrap()
            .typed_package_progress(package)
            .unwrap()
            .unwrap(),
        settled
    );
}

#[test]
fn parked_own_typed_edit_rejected_on_replay_stays_visible() {
    let mut f = Fixture::new();
    f.seed_note_specialisation();
    let record = [132; 32];
    let first = f.note_event(record, [9; 32]);
    let filler = f.note_event([181; 32], [20; 32]);
    assert_eq!(f.apply(&[&first, &filler]).len(), 2);
    let binding = f.typed(&JournalEntry::bind(record));
    assert!(f.apply(&[&binding]).is_empty());
    let (edit, package, mutation) = f.own_typed_package(JournalEntry::edit(record, "bright"));
    let raw = f.raw();
    let tx = raw.unchecked_transaction().unwrap();
    tx.execute(
        "DELETE FROM data_record WHERE record=?1",
        [record.as_slice()],
    )
    .unwrap();
    bh_data::note::mark_unavailable(&tx, f.base_scope(), RecordId(record)).unwrap();
    tx.commit().unwrap();
    let phantom = f.note_event([183; 32], [24; 32]);
    let extra = Commitment::order(
        f.base,
        f.history.order_state(),
        &phantom.descriptor,
        Route::Content,
    )
    .unwrap();
    let wrong_ack =
        Commitment::order(f.base, extra.after(), &edit.descriptor, Route::Content).unwrap();
    f.owner
        .shared_database(f.id)
        .unwrap()
        .lock()
        .unwrap()
        .acknowledge_typed_package(package, &wrong_ack)
        .unwrap();
    assert!(f.apply(&[&edit]).is_empty());
    assert_eq!(f.parked(), 1);
    assert_eq!(
        f.typed_package_outcome(package),
        Some(PackageOutcome::Acked)
    );
    assert!(f.alarms().contains(&SyncAlarm::TypedAckMismatch {
        package,
        position: 5
    }));
    let next = f.note_event(record, [10; 32]);
    assert_eq!(f.apply(&[&next]).len(), 1);
    assert_eq!(f.parked(), 0);
    assert_eq!(
        f.typed_package_outcome(package),
        Some(PackageOutcome::Rejected)
    );
    let state: String = f
        .raw()
        .query_row(
            "SELECT state FROM data_pending WHERE mutation=?1",
            [mutation.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "rejected");
}

#[test]
fn releasing_held_note_settles_parked_own_typed_package() {
    let mut f = Fixture::new();
    f.seed_note_specialisation();
    let (note, _) = f.own_work();
    let filler_a = f.note_event([183; 32], [21; 32]);
    let filler_b = f.note_event([184; 32], [22; 32]);
    assert_eq!(f.apply(&[&filler_a, &filler_b]).len(), 2);
    let (echo, package, mutation) = f.own_typed_package(JournalEntry::bind(note));
    let raw = f.raw();
    raw.execute("DELETE FROM data_record WHERE record=?1", [note.as_slice()])
        .unwrap();
    let creation = f.note_event(note, [23; 32]);
    let batch = f.batch(&[&creation]);
    let waiting =
        bh_core::contained::with_fuel(0, || f.owner.apply_remote_batch(f.id, batch)).unwrap();
    assert_eq!(waiting, vec![(f.key(note), NoteOutcome::Waiting)]);
    assert!(f.apply(&[&echo]).is_empty());
    assert_eq!(f.parked(), 1);
    assert_ne!(f.typed_package_outcome(package), Some(PackageOutcome::Held));
    let (released, _) = f.owner.retry_held(f.id, f.key(note)).unwrap();
    assert_eq!(released, vec![(f.key(note), NoteOutcome::Accepted)]);
    assert_eq!(
        f.typed_package_outcome(package),
        Some(PackageOutcome::Accepted)
    );
    let remaining: i64 = f
        .raw()
        .query_row(
            "SELECT count(*) FROM data_pending WHERE mutation=?1",
            [mutation.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(remaining, 0);
}

#[test]
fn incoming_typed_echo_alarms_a_mismatched_ack() {
    let mut f = Fixture::new();
    f.seed_types(&[Recipe::address(), Recipe::bytes()]);
    let fillers: Vec<_> = (0..3)
        .map(|i| f.note_event([i + 185; 32], [i + 30; 32]))
        .collect();
    assert_eq!(f.apply(&[&fillers[0], &fillers[1], &fillers[2]]).len(), 3);
    let (echo, package, _) = f.own_typed_package(Recipe::create([140; 32], "Soup"));
    let phantom = f.note_event([190; 32], [35; 32]);
    let extra = Commitment::order(
        f.base,
        f.history.order_state(),
        &phantom.descriptor,
        Route::Content,
    )
    .unwrap();
    let wrong_ack =
        Commitment::order(f.base, extra.after(), &echo.descriptor, Route::Content).unwrap();
    f.owner
        .shared_database(f.id)
        .unwrap()
        .lock()
        .unwrap()
        .acknowledge_typed_package(package, &wrong_ack)
        .unwrap();
    assert!(f.apply(&[&echo]).is_empty());
    assert_eq!(
        f.typed_package_outcome(package),
        Some(PackageOutcome::Accepted)
    );
    assert!(f.alarms().contains(&SyncAlarm::TypedAckMismatch {
        package,
        position: 5
    }));
}

#[test]
fn incoming_same_nonce_preserves_pending_typed_package() {
    let mut f = Fixture::new();
    f.seed_types(&[Recipe::address(), Recipe::bytes()]);
    let fillers: Vec<_> = (0..3)
        .map(|i| f.note_event([i + 195; 32], [i + 40; 32]))
        .collect();
    assert_eq!(f.apply(&[&fillers[0], &fillers[1], &fillers[2]]).len(), 3);
    let (own, package, _) = f.own_typed_package(Recipe::create([141; 32], "Soup"));
    let binding = f.binding(
        own.descriptor.nonce(),
        f.cap.device_id(),
        CLASS_CONTENT,
        f.hosting.receipt(f.base, f.history.head()),
    );
    let conflict = f.seal_binding(
        binding,
        TYPED_DATA,
        &Fixture::typed_bytes(&Recipe::create([142; 32], "Stew")),
        f.store.state().ordinary.as_ref().unwrap(),
    );
    assert!(f.apply(&[&conflict]).is_empty());
    assert_ne!(
        conflict.descriptor.publication_id(Route::Content),
        own.descriptor.publication_id(Route::Content)
    );
    assert_eq!(f.typed_package_outcome(package), None);
    assert!(f.alarms().is_empty());
}

/// A failure part-way through a batch leaves progress, the notes, the typed
/// operations and any retained content exactly as they were.
#[test]
fn a_failed_batch_leaves_typed_and_retained_state_unchanged() {
    let mut f = Fixture::new();
    f.seed_note_specialisation();
    let (a, b) = ([91; 32], [92; 32]);
    let wa = f.writer([1; 32]);
    let create_a = f.remote(a, [1; 32], &seed(f.client(a, wa))); // 2
    let create_b = f.remote(b, [2; 32], &seed(f.client(b, f.writer([2; 32])))); // 3
    let bind = f.typed(&JournalEntry::bind(a)); // 4
    let unknown = f.content_event(0xf123, b"unknown content kind"); // 5
    let before = f.dump();
    let before_progress = f.progress();
    let mut calls = Vec::new();
    let mut history = f.history.clone();
    let batch = f.batch_from(&mut history, &[&create_a, &create_b, &bind, &unknown]);
    let failed = f.owner.apply_remote_batch_with_hook(f.id, batch, |index| {
        calls.push(index);
        // Steps are Note a, Note b, the typed binding, then the retained
        // content: failing before the last one proves the typed writes roll
        // back with the rest of the batch.
        if index == 3 {
            Err(StoreError::InvalidUpdate)
        } else {
            Ok(())
        }
    });
    assert!(failed.is_err());
    assert_eq!(
        calls,
        vec![0, 1, 2, 3],
        "failed after the typed operation wrote"
    );
    assert_eq!(f.dump(), before, "no table changed");
    assert_eq!(f.progress(), before_progress);
    // The same verified batch applies in full on retry.
    assert_eq!(f.apply(&[&create_a, &create_b, &bind, &unknown]).len(), 2);
    assert_eq!(f.typed_record(a).unwrap().type_id, JournalEntry::type_id());
    assert_eq!(f.retained().len(), 1);
}

/// Coverage states that the typed log is applied through the committed
/// position. A Note this replica cannot show is a gap in that record, not in
/// the scope: unrelated typed work and listings continue, and releasing the
/// hold closes the gap.
#[test]
fn coverage_tracks_the_typed_log_and_a_note_gap_stays_in_its_record() {
    let mut f = Fixture::new();
    f.seed_types(&[Recipe::address(), Recipe::bytes()]);
    let (a, b) = ([101; 32], [102; 32]);
    let create_a = f.note_event(a, [1; 32]); // 2
    assert_eq!(f.apply(&[&create_a]).len(), 1);
    let coverage = f.typed_coverage().unwrap();
    assert_eq!(coverage.through, Some(Position(2)));
    assert!(coverage.complete);
    assert_eq!(f.note_gaps(), 0);

    // A Note the engine cannot judge is a gap in that record at the committed
    // position, and only the Note family reads incomplete.
    let hold = f.note_event(b, [2; 32]); // 3
    let batch = f.batch(&[&hold]);
    let waiting =
        bh_core::contained::with_fuel(0, || f.owner.apply_remote_batch(f.id, batch)).unwrap();
    assert!(waiting.iter().all(|(_, o)| *o == NoteOutcome::Waiting));
    let coverage = f.typed_coverage().unwrap();
    assert_eq!(coverage.through, Some(Position(3)));
    assert!(coverage.complete);
    assert_eq!(f.note_gaps(), 1);
    assert_eq!(
        f.page(bh_data::query::TypeSelect::Family(TypeId::core("note")))
            .completeness,
        bh_data::query::Completeness::Incomplete(vec![bh_data::query::Gap::NoteUnavailable])
    );
    assert_eq!(
        f.page(bh_data::query::TypeSelect::Exact(Recipe::type_id()))
            .completeness,
        bh_data::query::Completeness::Complete,
        "an unrelated type is complete while a Note is held"
    );

    // Unrelated typed work applies and parks nothing. (The seeded definitions
    // hold typed positions 1-4, so this sits at log position 5.)
    let filler = f.note_event([103; 32], [3; 32]); // 4
    assert_eq!(f.apply(&[&filler]).len(), 1);
    let soup = f.typed(&Recipe::create([201; 32], "Soup")); // 5
    assert!(f.apply(&[&soup]).is_empty());
    assert_eq!(
        f.typed_record([201; 32]).unwrap().type_id,
        Recipe::type_id()
    );
    assert_eq!(f.parked(), 0);

    // Releasing the held row closes the record's gap over the proven position.
    let (released, _) = f.owner.retry_held(f.id, f.key(b)).unwrap();
    assert_eq!(released, vec![(f.key(b), NoteOutcome::Accepted)]);
    let coverage = f.typed_coverage().unwrap();
    assert_eq!(coverage.through, Some(Position(5)));
    assert!(coverage.complete);
    assert_eq!(f.note_gaps(), 0);
    assert_eq!(
        f.page(bh_data::query::TypeSelect::Family(TypeId::core("note")))
            .completeness,
        bh_data::query::Completeness::Complete
    );

    // Unknown outer content asks for a newer build but is no gap anywhere, and
    // no batch closes it: only a newer build's replay deletes the row.
    let unknown = f.content_event(0xf123, b"unknown content kind"); // 6
    f.apply(&[&unknown]);
    assert!(f.typed_coverage().unwrap().complete);
    assert_eq!(f.note_gaps(), 0);
    let db = f.owner.shared_database(f.id).unwrap();
    assert!(db.lock().unwrap().needs_newer_build(f.base.0).unwrap());
}

/// A joined container bootstrapping from genesis is fully informed at every
/// position it applies, so its typed work applies rather than parking; and
/// activation only marks it usable.
#[test]
fn typed_work_applies_during_a_joined_bootstrap() {
    let mut f = Fixture::new();
    f.seed_types(&[Recipe::address(), Recipe::bytes()]);
    // This container is also the joined one, before its bootstrap ended.
    let account = f.cap.account_id().0;
    f.raw()
        .execute(
            "INSERT INTO joined_device(id,account,hint,delivery,added_at,activated)
             VALUES(1,?1,zeroblob(1),zeroblob(1),2,0)",
            [account.as_slice()],
        )
        .unwrap();
    // Typed events must sit above the fixture's seeded typed positions 1-4.
    let first = f.note_event([111; 32], [1; 32]); // 2
    let second = f.note_event([112; 32], [2; 32]); // 3
    let third = f.note_event([113; 32], [3; 32]); // 4
    assert_eq!(f.apply(&[&first, &second, &third]).len(), 3);
    let create = f.typed(&Recipe::create([210; 32], "Bootstrap soup")); // 5
    assert!(f.apply(&[&create]).is_empty());
    assert_eq!(f.parked(), 0, "a bootstrap does not park typed work");
    assert_eq!(
        f.typed_record([210; 32]).unwrap().type_id,
        Recipe::type_id()
    );
    let coverage = f.typed_coverage().unwrap();
    assert_eq!(coverage.through, Some(Position(5)));
    assert!(coverage.complete);

    f.owner
        .shared_database(f.id)
        .unwrap()
        .lock()
        .unwrap()
        .activate_joined()
        .unwrap();
    let coverage = f.typed_coverage().unwrap();
    assert_eq!(coverage.through, Some(Position(5)));
    assert!(coverage.complete);
    assert_eq!(f.parked(), 0);
}

#[test]
fn typed_creation_before_a_held_notes_first_event_keeps_its_verdict() {
    let note = [123; 32];
    let mut held = Fixture::new();
    let mut normal = Fixture::new();
    for f in [&mut held, &mut normal] {
        f.seed_types(&[Recipe::address(), Recipe::bytes()]);
        // Typed positions seeded through 4; the next typed event is position 6.
        for n in 124..128 {
            let filler = f.note_event([n; 32], [1; 32]);
            f.apply(&[&filler]);
        }
    }
    let create_held = held.typed(&Recipe::create(note, "Soup"));
    let note_held = held.note_event(note, [2; 32]);
    let batch = held.batch(&[&create_held, &note_held]);
    let outcomes =
        bh_core::contained::with_fuel(0, || held.owner.apply_remote_batch(held.id, batch)).unwrap();
    assert_eq!(outcomes, vec![(held.key(note), NoteOutcome::Waiting)]);
    let create_normal = normal.typed(&Recipe::create(note, "Soup"));
    let note_normal = normal.note_event(note, [2; 32]);
    normal.apply(&[&create_normal, &note_normal]);
    assert_eq!(
        held.parked(),
        0,
        "the earlier creation must not see a later hold"
    );
    assert_eq!(
        held.typed_record(note).unwrap().accepted,
        Some(serde_json::json!({"name": "Soup"}))
    );
    let (released, _) = held.owner.retry_held(held.id, held.key(note)).unwrap();
    assert_eq!(released, vec![(held.key(note), NoteOutcome::Accepted)]);
    assert_eq!(
        held.typed_record(note).unwrap().accepted,
        normal.typed_record(note).unwrap().accepted
    );
}

/// Releasing a held Note creates its projection and closes its record's gap,
/// which are the dependencies its parked typed work waits for: the release
/// replays that record's queue rather than the whole scope's.
#[test]
fn releasing_a_held_note_replays_work_parked_on_its_projection() {
    let mut f = Fixture::new();
    f.seed_note_specialisation();
    let (c, filler) = ([121; 32], [122; 32]);
    let create_c = f.note_event(c, [1; 32]); // 2
    let filler_event = f.note_event(filler, [2; 32]); // 3
    let bind_c = f.typed(&JournalEntry::bind(c)); // 4, parked: c is not projected
    let edit_c = f.typed(&Operation::Edit {
        record: RecordId(c),
        revision: JournalEntry::revision(),
        changes: vec![FieldChange {
            path: bh_data::FieldPath::parse("/mood").unwrap(),
            value: Some(serde_json::json!("waiting")),
        }],
    }); // 5, parked behind the same gap
    let batch = f.batch(&[&create_c, &filler_event, &bind_c, &edit_c]);
    let waiting =
        bh_core::contained::with_fuel(0, || f.owner.apply_remote_batch(f.id, batch)).unwrap();
    assert!(waiting.iter().all(|(_, o)| *o == NoteOutcome::Waiting));
    assert!(f.typed_record(c).is_none());
    assert_eq!(f.parked(), 2);
    let parked = f.parked_rows();
    assert!(
        parked
            .iter()
            .all(|(_, affects, _)| affects == &format!("r:{}", hex(&c)))
    );

    // Releasing another Note's hold does not touch this record's queue.
    let (first, _) = f.owner.retry_held(f.id, f.key(filler)).unwrap();
    assert_eq!(first, vec![(f.key(filler), NoteOutcome::Accepted)]);
    assert_eq!(f.note_gaps(), 1);
    assert_eq!(f.parked(), 2);

    // Releasing this one replays its queue: the binding applies at its
    // position, and the edit behind it applies, leaving nothing parked.
    let (released, _) = f.owner.retry_held(f.id, f.key(c)).unwrap();
    assert_eq!(released, vec![(f.key(c), NoteOutcome::Accepted)]);
    let row = f.typed_record(c).unwrap();
    assert_eq!(row.type_id, JournalEntry::type_id());
    assert_eq!(row.accepted.unwrap()["mood"], "waiting");
    assert_eq!(f.parked(), 0);
    assert_eq!(f.note_gaps(), 0);
    assert!(f.typed_coverage().unwrap().complete);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
