//! The base copy of an account change: this device's control key signs a
//! base control that copies the next account event into its own base, and
//! `History` applies it to the base's copy of the account.
use bh_account::{
    AccountEvent, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount,
    journal::AccountJournal,
    owner::{AccountCapability, AccountGeneration, AccountLoad, AccountOwner},
    platform::ControlKeyPolicy,
    recovery::Password,
    storage::DeviceJournal,
};
use bh_core::note::Note;
use bh_crypto::{KemKey, Secret, SigningKey};
use bh_device::{
    ContainerId, Owner, OwnerError,
    incoming::{LogId, LogKind, NoteOutcome, Unaccepted, VerifiedBatch},
    own_base::create_or_open,
};
use bh_event::{
    Binding, CLASS_CONTENT, ControlSpine, Copier, Encoded, History, NOTE, Outcome, Payload, key_id,
    note_payload, seal,
    writer::{DeviceWriterDeclaration, WriterScope},
};
use bh_storage::NoteKey;
use bh_sync::{
    BaseId, BodyObject, Commitment, EventId, Head, OpaqueEvent, Route,
    receipt::{self, CertifiedReceiptKey, RECEIPT_LEN},
};
use std::{future::Future, sync::Arc};

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

/// Another device of the account: the Fold, before and after pairing.
struct Fold {
    signing: SigningKey,
    control: SigningKey,
    receive: KemKey,
}
impl Fold {
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

/// The Mac: a signed-up account whose own base is registered and verified
/// through its genesis.
struct Mac {
    _dir: tempfile::TempDir,
    owner: Owner,
    id: ContainerId,
    cap: Arc<AccountCapability>,
    account: Account,
    store: store::FakeStore,
    base: BaseId,
    metadata: Secret<32>,
    content: Secret<32>,
    hosting: Hosting,
    /// The base's verified history, as a puller keeps it.
    history: History,
    /// The account at the head the base genesis names.
    anchor: VerifiedAccount,
    /// The account as it is ordered so far, for drafting account events.
    ordered: VerifiedAccount,
    control: [u8; 32],
}

impl Mac {
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
        account.confirm_home_ordered(status.head, None).unwrap();
        account.confirm_kit_saved().unwrap();
        let record = DeviceJournal::from_shared(db.clone())
            .load()
            .unwrap()
            .unwrap();
        let history = record.history.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let anchor = VerifiedAccount::replay(record.anchor, &history, record.head).unwrap();
        owner.anchor(id, &anchor).unwrap();
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
        let history = History::with_account(&anchor, base, hosting.root.public(), 1).unwrap();
        let genesis = Encoded {
            descriptor: OpaqueEvent::decode(&stored.genesis_descriptor).unwrap(),
            body: stored.genesis_body.clone(),
        };
        owner
            .record_registration(
                id,
                base.0,
                Some(hosting.receipt(base, Head::EMPTY)),
                hosting.root.public(),
            )
            .unwrap();
        let mut mac = Self {
            _dir: dir,
            owner,
            id,
            cap,
            account,
            store,
            base,
            metadata,
            content,
            hosting,
            history,
            ordered: anchor.clone(),
            anchor,
            control: [0; 32],
        };
        assert_eq!(
            mac.apply(&genesis, Route::Control),
            (Outcome::Accepted, vec![])
        );
        mac
    }
    fn key(&self, note: [u8; 32]) -> NoteKey {
        NoteKey {
            base: self.base.0,
            audience: [0; 32],
            note,
        }
    }
    /// Order one event after the base's head, verify it as a puller does
    /// and commit it to the Mac's store.
    fn apply(&mut self, event: &Encoded, route: Route) -> (Outcome, Vec<(NoteKey, NoteOutcome)>) {
        let ordered = Commitment::order(
            self.base,
            self.history.order_state(),
            &event.descriptor,
            route,
        )
        .unwrap();
        let prepared = self
            .history
            .prepare(
                &ordered,
                &event.descriptor,
                Some(&event.body),
                &self.metadata,
                Some(&self.content),
            )
            .unwrap();
        let applied = self.history.consume_unapplied(prepared).unwrap();
        let outcome = applied.outcome();
        if route == Route::Control && outcome == Outcome::Accepted {
            self.control = ordered.event_digest().0;
        }
        let batch = VerifiedBatch {
            log: LogId {
                kind: LogKind::Base,
                id: self.base.0,
            },
            events: vec![applied],
            head: self.history.head(),
            receipt: self.hosting.receipt(self.base, self.history.head()),
        };
        let notes = self.owner.apply_remote_batch(self.id, batch).unwrap();
        (outcome, notes)
    }
    /// Pair a device: its AddDevice, signed under this Mac's confirmation
    /// and ordered, confirmed, in the account log. Returns it with its
    /// confirmed entry.
    fn pair(&mut self, fold: &Fold) -> (AccountEvent, (Vec<u8>, Vec<u8>)) {
        let request = self
            .ordered
            .add_device(self.cap.device_id(), fold.keys())
            .unwrap();
        let event = ready(self.account.sign_control(&self.cap, &request)).unwrap();
        let entry = self.order_confirmed(&event, START + event.head().position);
        (event, entry)
    }
    /// The base copy of one confirmed account entry, a run of one signed
    /// with this Mac's control key.
    fn copy(&mut self, entry: &(Vec<u8>, Vec<u8>)) -> Result<Encoded, OwnerError> {
        let request = self.owner.prepare_account_run_copy(
            self.id,
            &self.anchor,
            &self.metadata,
            std::slice::from_ref(entry),
            Copier::Device(self.cap.device_id()),
        )?;
        assert_eq!(
            request.expected_key(),
            self.ordered
                .active_device(self.cap.device_id())
                .unwrap()
                .control()
        );
        let signature = ready(self.account.sign_base_control(
            &self.cap,
            request.expected_key(),
            request.signing_bytes(),
        ))
        .unwrap();
        Ok(request.finish(signature).unwrap())
    }
    /// A note event by the Fold, as its outbox seals it.
    fn fold_note(&self, fold: &Fold, note: [u8; 32], text: &str) -> Encoded {
        let writer = DeviceWriterDeclaration {
            account: self.cap.account_id().0,
            device: fold.keys().id().0,
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
        seal(
            Binding {
                version: 3,
                highest: 3,
                mode: 0,
                base: self.base.0,
                audience: [0; 32],
                epoch: key_id(&self.content),
                event_id: EventId(bh_crypto::random()),
                account: self.cap.account_id(),
                device: fold.keys().id(),
                account_head: self.history.account_head(),
                seen: self.history.head(),
                seen_control: self.control,
                class: CLASS_CONTENT,
                padded: 0,
                commitment: [0; 32],
                seen_receipt: self.hosting.receipt(self.base, self.history.head()),
            },
            Payload {
                kind: NOTE,
                data: &note_payload(note, writer, &update),
            },
            &fold.signing,
            &self.metadata,
            Some(&self.content),
        )
        .unwrap()
    }
    /// This Mac's committed local work in a new note, sealed by its outbox.
    fn own_work(&mut self, text: &str) -> ([u8; 32], i64, Encoded) {
        let note = self.owner.create_note(self.id).unwrap();
        self.owner.show_note("w", self.id, note).unwrap();
        let opened = self.owner.open_leased("w", note).unwrap();
        let lease = opened.writer.unwrap();
        let delta = Owner::core_author(&opened)
            .unwrap()
            .try_append_paragraph(text)
            .unwrap();
        self.owner
            .commit_leased("w", opened.generation, lease.token, [1; 16], &delta)
            .unwrap();
        let db = self.owner.shared_database(self.id).unwrap();
        let update_id = db.lock().unwrap().pending_note_updates().unwrap()[0].update_id;
        let candidate = match db.lock().unwrap().prepare_note_package(update_id).unwrap() {
            bh_storage::PackagePreparation::Candidate(c) => c,
            bh_storage::PackagePreparation::Existing(_) => panic!("already packaged"),
        };
        let writer = bh_device::writers::pending_declaration(&candidate.pending)
            .unwrap()
            .unwrap();
        let state = self.store.state();
        let encoded = seal(
            Binding {
                version: 3,
                highest: 3,
                mode: 0,
                base: self.base.0,
                audience: [0; 32],
                epoch: key_id(&self.content),
                event_id: candidate.event_id,
                account: self.cap.account_id(),
                device: self.cap.device_id(),
                account_head: self.history.account_head(),
                seen: self.history.head(),
                seen_control: self.control,
                class: CLASS_CONTENT,
                padded: 0,
                commitment: [0; 32],
                seen_receipt: self.hosting.receipt(self.base, self.history.head()),
            },
            Payload {
                kind: NOTE,
                data: &note_payload(note, writer, &candidate.pending.bytes),
            },
            state.ordinary.as_ref().unwrap(),
            &self.metadata,
            Some(&self.content),
        )
        .unwrap();
        db.lock()
            .unwrap()
            .publish_note_package(
                candidate,
                encoded.descriptor.clone(),
                BodyObject::new(encoded.body.clone()).unwrap(),
            )
            .unwrap();
        (note, update_id, encoded)
    }
    fn working(&self, note: [u8; 32]) -> Note {
        let db = self.owner.shared_database(self.id).unwrap();
        let ordered = db.lock().unwrap().note_ordered(self.key(note)).unwrap();
        Note::from_ordered(&ordered).unwrap()
    }
    fn progress(&self) -> bh_storage::sync_state::LogProgress {
        let db = self.owner.shared_database(self.id).unwrap();
        let progress = db.lock().unwrap().log_progress(1, self.base.0).unwrap();
        progress.unwrap()
    }
}

#[test]
fn copy_accepted_by_history() {
    let mut mac = Mac::new();
    let fold = Fold::new();
    let (add, added) = mac.pair(&fold);
    // Before the copy the Fold is in the account but not in the base's copy
    // of it: its note is an invalid submission.
    let early = mac.fold_note(&fold, [5; 32], "too early");
    assert_eq!(mac.apply(&early, Route::Content).0, Outcome::Rejected);
    let copy = mac.copy(&added).unwrap();
    let stored = mac
        .owner
        .shared_database(mac.id)
        .unwrap()
        .lock()
        .unwrap()
        .own_base()
        .unwrap()
        .unwrap();
    let genesis = OpaqueEvent::decode(&stored.genesis_descriptor).unwrap();
    let genesis_order = Commitment::order(
        mac.base,
        bh_sync::OrderState::EMPTY,
        &genesis,
        Route::Control,
    )
    .unwrap();
    let (mut spine, _) = ControlSpine::from_genesis(
        &mac.anchor,
        &genesis,
        &stored.genesis_body,
        &mac.metadata,
        mac.hosting.root.public(),
        &genesis_order,
    )
    .unwrap();
    let ordered = Commitment::order(
        mac.base,
        mac.history.order_state(),
        &copy.descriptor,
        Route::Control,
    )
    .unwrap();
    let submitted = spine
        .check_submission(
            &mac.anchor,
            &copy.descriptor,
            &copy.body,
            &mac.metadata,
            &|id| Ok(id == genesis_order.event_id()),
        )
        .unwrap();
    let checked = spine
        .check(
            &mac.anchor,
            &copy.descriptor,
            &copy.body,
            &mac.metadata,
            &ordered,
            &|id| Ok(id == genesis_order.event_id()),
        )
        .unwrap();
    assert_eq!(submitted, checked);
    assert_eq!(checked.digest, ordered.event_digest());
    assert_eq!(checked.account_head_after, add.head());
    assert_eq!(checked.epoch_after, Some(key_id(&mac.content)));
    spine.apply(submitted, &ordered).unwrap();
    assert_eq!(
        mac.apply(&copy, Route::Control),
        (Outcome::Accepted, vec![])
    );
    assert_eq!(spine.state().account, mac.history.account_head());
    assert_eq!(spine.state().epoch, mac.history.epoch_id());
    assert_eq!(spine.state().control_digest, mac.control);
    assert_eq!(mac.history.account_head(), add.head());
    let progress = mac.progress();
    assert_eq!(
        progress.account,
        Some((add.head().position, add.head().hash))
    );
    assert_eq!(progress.control_digest, mac.control);
    assert_eq!(progress.epoch_id, Some(key_id(&mac.content)));
    let note = mac.fold_note(&fold, [6; 32], "from the Fold");
    let (outcome, notes) = mac.apply(&note, Route::Content);
    assert_eq!(outcome, Outcome::Accepted);
    assert_eq!(notes, vec![(mac.key([6; 32]), NoteOutcome::Accepted)]);
}

#[test]
fn copy_of_non_next_account_event_refused() {
    let mut mac = Mac::new();
    let fold = Fold::new();
    let (_, added) = mac.pair(&fold);
    // The event after the next one skips the Fold's addition.
    let (skipping, skipped) = mac.pair(&Fold::new());
    assert!(matches!(mac.copy(&skipped), Err(OwnerError::CopyRefused)));
    assert!(matches!(
        mac.copy(&(b"not an account event".to_vec(), added.1.clone())),
        Err(OwnerError::CopyRefused)
    ));
    // Another entry's confirmation does not time this one.
    assert!(matches!(
        mac.copy(&(added.0.clone(), skipped.1.clone())),
        Err(OwnerError::CopyRefused)
    ));
    let copy = mac.copy(&added).unwrap();
    assert_eq!(mac.apply(&copy, Route::Control).0, Outcome::Accepted);
    // Once copied it is no longer the next one.
    assert!(matches!(mac.copy(&added), Err(OwnerError::CopyRefused)));
    let next = mac.copy(&skipped).unwrap();
    assert_eq!(mac.apply(&next, Route::Control).0, Outcome::Accepted);
    assert_eq!(mac.history.account_head(), skipping.head());
}

#[test]
fn remove_copy_closes_epoch_in_history() {
    let mut mac = Mac::new();
    let fold = Fold::new();
    let (_, added) = mac.pair(&fold);
    let copy = mac.copy(&added).unwrap();
    assert_eq!(mac.apply(&copy, Route::Control).0, Outcome::Accepted);
    // The Fold removes itself in the account; the Mac copies the removal.
    let request = mac.ordered.remove_self(fold.keys().id()).unwrap();
    let removal = request
        .finish(fold.control.sign(request.signing_bytes()))
        .unwrap();
    let removed = mac.order_confirmed(&removal, START + removal.head().position);
    let (note, update_id, package) = mac.own_work("mine");
    let copy = mac.copy(&removed).unwrap();
    assert_eq!(mac.apply(&copy, Route::Control).0, Outcome::Accepted);
    assert_eq!(mac.history.epoch_id(), None);
    assert_eq!(mac.progress().epoch_id, None);
    // Content sealed under the closed epoch is refused, and the Mac keeps
    // its work.
    let working = mac.working(note).digest().unwrap();
    let (outcome, notes) = mac.apply(&package, Route::Content);
    assert_eq!(outcome, Outcome::Rejected);
    assert!(notes.is_empty());
    let unaccepted = mac.owner.unaccepted(mac.id, mac.key(note)).unwrap();
    assert_eq!(unaccepted.len(), 1);
    assert_eq!(unaccepted[0].update_id, update_id);
    assert_eq!(unaccepted[0].state, Unaccepted::Rejected);
    assert_eq!(mac.working(note).digest().unwrap(), working);
    assert_eq!(mac.working(note).title_preview().unwrap(), "mine");
}

const START: u64 = 1_000_000;

impl Mac {
    /// Order `event` in the account log, confirmed at `at` under this base's
    /// hosting root: the original and its confirmation.
    fn order_confirmed(&mut self, event: &AccountEvent, at: u64) -> (Vec<u8>, Vec<u8>) {
        use bh_sync::evidence::{
            ConfirmationClaim, OrderingConfirmation, TimeBounds, original_digest,
        };
        use bh_sync::permit::{self, LogId as PermitLog, LogKind as PermitKind};
        let head = |h: bh_account::Head| Head {
            position: h.position,
            hash: bh_sync::Digest(h.hash),
        };
        let key = SigningKey::generate();
        let claim = ConfirmationClaim {
            log: PermitLog {
                kind: PermitKind::Account,
                id: [0x64; 32],
            },
            original: original_digest(event.as_bytes()),
            original_previous: head(self.ordered.head()),
            original_head: head(event.head()),
            body: None,
            ordered: Head {
                position: event.head().position,
                hash: bh_sync::Digest([0x65; 32]),
            },
            bounds: TimeBounds {
                earliest_ms: at,
                latest_ms: at,
            },
        };
        let confirmation = OrderingConfirmation::sign(
            &key,
            &permit::certify(&self.hosting.root, key.public()),
            claim,
        );
        self.ordered
            .apply_timed(
                event.as_bytes(),
                Some(bh_account::ConfirmedTime {
                    earliest_ms: at,
                    latest_ms: at,
                }),
            )
            .unwrap();
        (event.as_bytes().to_vec(), confirmation.encode().to_vec())
    }
    /// A run copied by this Mac's control key.
    fn copy_run(&mut self, run: &[(Vec<u8>, Vec<u8>)]) -> Encoded {
        let request = self
            .owner
            .prepare_account_run_copy(
                self.id,
                &self.anchor,
                &self.metadata,
                run,
                Copier::Device(self.cap.device_id()),
            )
            .unwrap();
        let signature = ready(self.account.sign_base_control(
            &self.cap,
            request.expected_key(),
            request.signing_bytes(),
        ))
        .unwrap();
        request.finish(signature).unwrap()
    }
}

#[test]
fn recovery_run_copy_accepted_by_history() {
    let mut mac = Mac::new();
    // The account replaces its recovery key, and the new key adds the Fold:
    // a recovered device with no surviving peer. The base saw neither.
    let next = SigningKey::generate();
    let recovery = RecoveryPublicKeys::new(next.public(), KemKey::generate().public());
    let request = mac
        .ordered
        .replace_recovery(mac.cap.device_id(), recovery, [1; 32], [2; 32])
        .unwrap();
    let replace = ready(mac.account.sign_control(&mac.cap, &request)).unwrap();
    let replaced = mac.order_confirmed(&replace, START);
    let fold = Fold::new();
    let request = mac.ordered.add_device_by_recovery(fold.keys()).unwrap();
    let add = request.finish(next.sign(request.signing_bytes())).unwrap();
    let added = mac.order_confirmed(&add, START + 1);
    let run = [replaced, added];
    // Only this device or the recovery key copies from here.
    assert!(matches!(
        mac.owner.prepare_account_run_copy(
            mac.id,
            &mac.anchor,
            &mac.metadata,
            &run,
            Copier::Device(fold.keys().id()),
        ),
        Err(OwnerError::CopyRefused)
    ));
    let request = mac
        .owner
        .prepare_account_run_copy(mac.id, &mac.anchor, &mac.metadata, &run, Copier::Recovery)
        .unwrap();
    assert_eq!(request.expected_key(), &next.public());
    let signature = next.sign(request.signing_bytes());
    let copy = request.finish(signature).unwrap();
    assert_eq!(
        mac.apply(&copy, Route::Control),
        (Outcome::Accepted, vec![])
    );
    assert_eq!(mac.history.account_head(), add.head());
    assert_eq!(
        mac.progress().account,
        Some((add.head().position, add.head().hash))
    );
    let note = mac.fold_note(&fold, [6; 32], "recovered");
    assert_eq!(mac.apply(&note, Route::Content).0, Outcome::Accepted);
    // The stored run rebuilds the base's copy: this device copies the next
    // confirmed event after it.
    let third = Fold::new();
    let request = mac
        .ordered
        .add_device(mac.cap.device_id(), third.keys())
        .unwrap();
    let add = ready(mac.account.sign_control(&mac.cap, &request)).unwrap();
    let added = mac.order_confirmed(&add, START + 2);
    let copy = mac.copy_run(&[added]);
    assert_eq!(mac.apply(&copy, Route::Control).0, Outcome::Accepted);
    assert_eq!(mac.history.account_head(), add.head());
}

#[test]
fn rekey_of_own_base_reopens_its_epoch() {
    let mut mac = Mac::new();
    let fold = Fold::new();
    let request = mac
        .ordered
        .add_device(mac.cap.device_id(), fold.keys())
        .unwrap();
    let add = ready(mac.account.sign_control(&mac.cap, &request)).unwrap();
    let added = mac.order_confirmed(&add, START);
    let copy = mac.copy_run(&[added]);
    assert_eq!(mac.apply(&copy, Route::Control).0, Outcome::Accepted);
    let request = mac.ordered.remove_self(fold.keys().id()).unwrap();
    let leave = request
        .finish(fold.control.sign(request.signing_bytes()))
        .unwrap();
    let left = mac.order_confirmed(&leave, START + 1);
    let copy = mac.copy_run(&[left]);
    assert_eq!(mac.apply(&copy, Route::Control).0, Outcome::Accepted);
    assert_eq!(mac.progress().epoch_id, None);
    // The rotation is signed with the ordinary key, as is the rekey.
    let request = mac
        .ordered
        .rotate_personal(
            mac.cap.device_id(),
            leave.head().position,
            KemKey::generate().public(),
            [3; 32],
            [4; 32],
        )
        .unwrap();
    let signature = ready(mac.account.sign_content(&mac.cap, request.signing_bytes())).unwrap();
    let rotate = request.finish(signature).unwrap();
    let (rotation, confirmation) = mac.order_confirmed(&rotate, START + 2);
    let next = Secret::<32>::random();
    let seals = vec![vec![5; 1499]];
    let prepared = mac
        .owner
        .prepare_rekey(
            mac.id,
            &mac.anchor,
            &mac.metadata,
            &rotation,
            &confirmation,
            &next,
            seals.clone(),
        )
        .unwrap();
    let set = prepared.seal_set.bytes().to_vec();
    let signature = ready(
        mac.account
            .sign_content(&mac.cap, prepared.control.signing_bytes()),
    )
    .unwrap();
    let rekey = prepared.control.finish(signature).unwrap();
    let ordered = Commitment::order(
        mac.base,
        mac.history.order_state(),
        &rekey.descriptor,
        Route::Control,
    )
    .unwrap();
    let mut history = mac.history.clone();
    let prepared = history
        .prepare(
            &ordered,
            &rekey.descriptor,
            Some(&rekey.body),
            &mac.metadata,
            None,
        )
        .unwrap();
    let applied = history.consume_unapplied(prepared).unwrap();
    assert_eq!(
        bh_event::rekey::rekey_seals(&applied, &mac.metadata, Some(&set)),
        Ok(Some((key_id(&next), seals.clone())))
    );
    // What a seal-set wait keeps, read from the control's own bytes.
    let kept =
        bh_event::rekey::rekey_seal_set(mac.base, &rekey.descriptor, &rekey.body, &mac.metadata)
            .unwrap()
            .unwrap();
    assert_eq!(kept.event_id, rekey.descriptor.nonce());
    assert_eq!(kept.key_id, key_id(&next));
    assert_eq!(kept.count, 1);
    assert_eq!(
        kept.commitment,
        BodyObject::new(set.clone()).unwrap().commitment()
    );
    assert_eq!(kept.open(&mac.metadata, mac.base, &set), Ok(seals));
    assert_eq!(
        bh_event::rekey::rekey_seal_set(mac.base, &copy.descriptor, &copy.body, &mac.metadata),
        Ok(None)
    );
    assert_eq!(mac.apply(&rekey, Route::Control).0, Outcome::Accepted);
    assert_eq!(mac.progress().epoch_id, Some(key_id(&next)));
    assert_eq!(mac.history.account_head(), rotate.head());
}

/// A rotation that takes effect is copied only by the base's rekey: a plan
/// over the missing entries ends a run before it, and starts with the rekey
/// when it is next. The rekey's new key is drawn and sealed inside, to the
/// rotated personal key, and only its id and seals leave; each seal and the
/// control are signed with the ordinary key, and the base installs the id.
#[test]
fn a_rotation_that_takes_effect_is_planned_as_a_rekey_sealed_to_its_new_key() {
    let mut mac = Mac::new();
    let fold = Fold::new();
    let (_, added) = mac.pair(&fold);
    let request = mac.ordered.remove_self(fold.keys().id()).unwrap();
    let leave = request
        .finish(fold.control.sign(request.signing_bytes()))
        .unwrap();
    let left = mac.order_confirmed(&leave, START + 5);
    let next = KemKey::generate();
    let request = mac
        .ordered
        .rotate_personal(
            mac.cap.device_id(),
            leave.head().position,
            next.public(),
            [3; 32],
            [4; 32],
        )
        .unwrap();
    let signature = ready(mac.account.sign_content(&mac.cap, request.signing_bytes())).unwrap();
    let rotate = request.finish(signature).unwrap();
    let rotated = mac.order_confirmed(&rotate, START + 6);
    let plan = |mac: &Mac, entries: &[(Vec<u8>, Vec<u8>)]| {
        mac.owner
            .plan_account_copy(mac.id, &mac.anchor, &mac.metadata, entries)
    };
    let all = [added.clone(), left.clone(), rotated.clone()];
    assert!(matches!(plan(&mac, &all), Ok(bh_device::CopyPlan::Run(2))));
    // A forged confirmation ends the run before it; a first entry that
    // does not apply is refused.
    let forged = (left.0.clone(), added.1.clone());
    assert!(matches!(
        plan(&mac, &[added.clone(), forged.clone()]),
        Ok(bh_device::CopyPlan::Run(1))
    ));
    assert!(matches!(
        plan(&mac, &[forged]),
        Err(OwnerError::CopyRefused)
    ));
    assert!(matches!(plan(&mac, &[]), Err(OwnerError::CopyRefused)));
    // No rekey before its rotation is next.
    assert!(matches!(
        mac.owner
            .prepare_rekey_seals(mac.id, &mac.anchor, &mac.metadata, &rotated.0, &rotated.1),
        Err(OwnerError::CopyRefused)
    ));
    let copy = mac.copy_run(&all[..2]);
    assert_eq!(mac.apply(&copy, Route::Control).0, Outcome::Accepted);
    assert!(matches!(
        plan(&mac, &all[2..]),
        Ok(bh_device::CopyPlan::Rekey)
    ));

    let sealed = mac
        .owner
        .prepare_rekey_seals(mac.id, &mac.anchor, &mac.metadata, &rotated.0, &rotated.1)
        .unwrap();
    assert_eq!(sealed.seals.len(), 1);
    let ordinary = *mac
        .ordered
        .active_device(mac.cap.device_id())
        .unwrap()
        .signing();
    let seals: Vec<Vec<u8>> = sealed
        .seals
        .into_iter()
        .map(|seal| {
            assert_eq!(seal.expected_key(), &ordinary);
            let signature =
                ready(mac.account.sign_content(&mac.cap, seal.signing_bytes())).unwrap();
            seal.finish(signature).unwrap()
        })
        .collect();
    let header = bh_device::base_keys::SealHeader::decode(&seals[0]).unwrap();
    assert_eq!(header.key_id, sealed.key_id);
    assert_eq!(header.recipient, bh_crypto::hash(&next.public()));
    assert_eq!(header.head, rotate.head());
    assert!(header.device == mac.cap.device_id());
    bh_device::base_keys::verify_seal(&mac.ordered, &header, &seals[0]).unwrap();
    let prepared = mac
        .owner
        .prepare_rekey_for(
            mac.id,
            &mac.anchor,
            &mac.metadata,
            &rotated.0,
            &rotated.1,
            sealed.key_id,
            seals.clone(),
        )
        .unwrap();
    assert_eq!(prepared.control.expected_key(), &ordinary);
    let set = prepared.seal_set.bytes().to_vec();
    let signature = ready(
        mac.account
            .sign_content(&mac.cap, prepared.control.signing_bytes()),
    )
    .unwrap();
    let rekey = prepared.control.finish(signature).unwrap();
    let kept =
        bh_event::rekey::rekey_seal_set(mac.base, &rekey.descriptor, &rekey.body, &mac.metadata)
            .unwrap()
            .unwrap();
    assert_eq!(kept.key_id, sealed.key_id);
    assert_eq!(kept.open(&mac.metadata, mac.base, &set), Ok(seals));
    assert_eq!(mac.apply(&rekey, Route::Control).0, Outcome::Accepted);
    assert_eq!(mac.progress().epoch_id, Some(sealed.key_id));
    assert_eq!(mac.history.account_head(), rotate.head());
}

/// A run fits one authorization message: it ends before the entry that
/// would take its data past `RUN_BYTES`, whatever `MAX_RUN` allows.
#[test]
fn a_run_ends_within_the_bytes_one_control_carries() {
    let mut mac = Mac::new();
    let entries: Vec<_> = (0..12).map(|_| mac.pair(&Fold::new()).1).collect();
    let mut fits = 0;
    let mut bytes = 1;
    for (original, confirmation) in &entries {
        bytes += 4 + original.len() + confirmation.len();
        if bytes > bh_device::RUN_BYTES {
            break;
        }
        fits += 1;
    }
    assert!(fits < entries.len(), "twelve device additions do not fit");
    let plan = mac
        .owner
        .plan_account_copy(mac.id, &mac.anchor, &mac.metadata, &entries)
        .unwrap();
    assert!(matches!(plan, bh_device::CopyPlan::Run(n) if n == fits));
    // That run's control seals into the largest body one message carries.
    let copy = mac.copy_run(&entries[..fits]);
    assert!(copy.body.len() <= 16 * 1024);
    assert_eq!(mac.apply(&copy, Route::Control).0, Outcome::Accepted);
}
