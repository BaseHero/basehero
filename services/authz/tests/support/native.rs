//! A Mac as the app makes one: an account owner signed up on its own key
//! store, its own base, a puller's verified base history, and the native
//! producer of base copies. Base controls in these tests come from here,
//! never from hand-built bytes.
#![allow(dead_code)]

use super::Harness;
use bh_account::{
    AccountEvent, DeviceId, DevicePublicKeys, VerifiedAccount,
    crypto::{KemKey, Secret, SigningKey},
    device_auth::{self, Context},
    journal::AccountJournal,
    owner::{AccountCapability, AccountGeneration, AccountLoad, AccountOwner},
    platform::ControlKeyPolicy,
    recovery::Password,
    storage::DeviceJournal,
};
use bh_authz::{
    Connection, Service,
    proto::{
        FromService, LogId, LogKind, MetadataKey, ToService, account_log_id, account_log_wrap,
    },
};
use bh_core::note::Note;
use bh_device::{
    ContainerId, Owner, OwnerError,
    incoming::{self, VerifiedBatch},
    own_base::create_or_open,
};
use bh_event::{
    Binding, CLASS_CONTENT, Encoded, History, NOTE, Outcome, Payload, Seen, key_id, note_payload,
    seal,
    writer::{DeviceWriterDeclaration, WriterScope},
};
use bh_sync::{
    BaseId, EventId, Head, OpaqueEvent,
    receipt::{self, CertifiedReceiptKey, RECEIPT_LEN},
};
use std::{future::Future, sync::Arc};

#[allow(dead_code)]
#[path = "../../../../libs/account/tests/support/protector.rs"]
mod protector;
#[path = "../../../../libs/account/tests/support/store.rs"]
mod store;

type AccountOwnerOf = AccountOwner<DeviceJournal, store::FakeStore, protector::PlainProtector>;

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

/// Another device of the account: the Fold, before and after pairing.
pub struct Fold {
    pub signing: SigningKey,
    pub control: SigningKey,
    receive: KemKey,
}
impl Fold {
    pub fn new() -> Self {
        Self {
            signing: SigningKey::generate(),
            control: SigningKey::generate(),
            receive: KemKey::generate(),
        }
    }
    pub fn keys(&self) -> DevicePublicKeys {
        DevicePublicKeys::new(
            self.signing.public(),
            self.control.public(),
            self.receive.public(),
        )
        .unwrap()
    }
    pub fn id(&self) -> DeviceId {
        self.keys().id()
    }
}

/// Connect and authenticate a device at `view`, the account's current head;
/// `sign` signs with its ordinary key.
pub async fn session_as(
    service: &Service,
    view: &VerifiedAccount,
    genesis: &[u8],
    device: DeviceId,
    sign: impl Fn(&[u8]) -> [u8; 64],
) -> Connection {
    let binding = bh_crypto::random();
    let (mut connection, challenge) = service.connect(binding);
    let FromService::Challenge { challenge } = challenge else {
        panic!("challenge")
    };
    let request = device_auth::prepare(
        view,
        device,
        Context {
            channel_binding: binding,
            challenge,
        },
    )
    .unwrap();
    let signature = sign(request.message());
    let proof = request.finish(signature).unwrap();
    let answer = connection
        .handle(ToService::Authenticate {
            proof: Box::new(*proof.as_bytes()),
            account: view.id(),
            device,
            genesis: genesis.to_vec(),
        })
        .await;
    assert!(
        matches!(answer, FromService::Authenticated { .. }),
        "{answer:?}"
    );
    connection
}

/// The Mac: a signed-up account whose own base the service registered and
/// the edge ordered, with the base's verified history as its puller keeps it.
pub struct Mac {
    _dir: tempfile::TempDir,
    pub owner: Owner,
    pub id: ContainerId,
    pub cap: Arc<AccountCapability>,
    account: AccountOwnerOf,
    store: store::FakeStore,
    pub base: BaseId,
    pub metadata: Secret<32>,
    pub content: Secret<32>,
    pub genesis: Encoded,
    pub history: History,
    /// The account at the head the base genesis names.
    pub anchor: VerifiedAccount,
    /// The account as ordered so far, and its originals in order.
    pub ordered: VerifiedAccount,
    pub originals: Vec<Vec<u8>>,
    pub log: LogId,
    pub home_objects: ToService,
    receipts: (CertifiedReceiptKey, SigningKey),
    root: [u8; 32],
    evidence_keys: (SigningKey, [u8; bh_sync::receipt::CERTIFICATE_LEN]),
    clock: Arc<bh_authz::FixedClock>,
    edge: Arc<super::FakeEdge>,
}

impl Mac {
    /// Sign up, create the own base, and publish the account on the edge.
    /// The base is not registered yet.
    pub fn new(harness: &Harness) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let owner = Owner::default();
        let id = owner.create_container(dir.path()).unwrap();
        let db = owner.shared_database(id).unwrap();
        let generation = AccountGeneration::new();
        let store = store::FakeStore::new(generation.clone());
        let mut account = AccountOwnerOf::new(
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
        let objects = account.pending_home_objects().unwrap();
        let home_objects = ToService::StoreHomeObjects {
            prefix: status.head,
            record: objects.record,
            device_seal: objects.device_seal,
            recovery_seal: objects.recovery_seal,
        };
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
        let genesis = Encoded {
            descriptor: OpaqueEvent::decode(&stored.genesis_descriptor).unwrap(),
            body: stored.genesis_body.clone(),
        };
        let root = harness.root.public();
        let key = SigningKey::generate();
        let certificate =
            receipt::verify_certificate(&root, &receipt::certify(&harness.root, key.public()))
                .unwrap();
        let originals = record.history.clone();
        let log = LogId {
            kind: LogKind::Account,
            id: account_log_id(&originals[0]).unwrap(),
        };
        let evidence_key = SigningKey::generate();
        let evidence_certificate = bh_sync::permit::certify(&harness.root, evidence_key.public());
        let mac = Self {
            _dir: dir,
            owner,
            id,
            cap,
            account,
            store,
            base,
            metadata,
            content,
            genesis,
            history: History::with_account(&anchor, base, root, 1).unwrap(),
            ordered: anchor.clone(),
            anchor,
            originals,
            log,
            home_objects,
            receipts: (certificate, key),
            root,
            evidence_keys: (evidence_key, evidence_certificate),
            clock: harness.clock.clone(),
            edge: harness.edge.clone(),
        };
        mac.owner
            .record_registration(mac.id, mac.base.0, Some(mac.receipt(Head::EMPTY)), mac.root)
            .unwrap();
        for original in &mac.originals {
            harness.order_original(mac.log, original);
        }
        mac
    }
    pub fn receipt(&self, head: Head) -> [u8; RECEIPT_LEN] {
        receipt::sign(&self.receipts.0, &self.receipts.1, self.base, head).unwrap()
    }
    pub fn base_log(&self) -> LogId {
        LogId {
            kind: LogKind::Base,
            id: self.base.0,
        }
    }
    pub fn device(&self) -> DeviceId {
        self.cap.device_id()
    }
    pub async fn session(&self, service: &Service) -> Connection {
        session_as(
            service,
            &self.ordered,
            &self.originals[0],
            self.device(),
            |message| self.store.state().ordinary.as_ref().unwrap().sign(message),
        )
        .await
    }
    pub async fn fold_session(&self, service: &Service, fold: &Fold) -> Connection {
        session_as(
            service,
            &self.ordered,
            &self.originals[0],
            fold.id(),
            |message| fold.signing.sign(message),
        )
        .await
    }
    pub fn register(&self) -> ToService {
        ToService::RegisterBase {
            descriptor: self.genesis.descriptor.encode(),
            body: self.genesis.body.clone(),
            creator_head: self.anchor.head(),
            metadata: MetadataKey::new(&self.metadata),
        }
    }
    /// Register the base with the service, order its genesis and pull it.
    pub async fn register_and_order(&mut self, harness: &Harness, connection: &mut Connection) {
        let answer = connection.handle(self.register()).await;
        let genesis = Encoded {
            descriptor: self.genesis.descriptor.clone(),
            body: self.genesis.body.clone(),
        };
        order(harness, &answer, &genesis).unwrap();
        self.pull(harness);
    }
    /// Verify every newly ordered base event as a puller does and commit it.
    pub fn pull(&mut self, harness: &Harness) -> Vec<Outcome> {
        let mut outcomes = vec![];
        for (ordered, event, body) in harness
            .edge
            .after(self.base_log(), self.history.head().position)
        {
            let prepared = self
                .history
                .prepare(
                    &ordered,
                    &event,
                    Some(&body),
                    &self.metadata,
                    Some(&self.content),
                )
                .unwrap();
            let applied = self.history.consume_unapplied(prepared).unwrap();
            outcomes.push(applied.outcome());
            let head = self.history.head();
            let batch = VerifiedBatch {
                log: incoming::LogId {
                    kind: incoming::LogKind::Base,
                    id: self.base.0,
                },
                events: vec![applied],
                head,
                receipt: self.receipt(head),
            };
            self.owner.apply_remote_batch(self.id, batch).unwrap();
        }
        outcomes
    }
    /// A device addition signed under this Mac's confirmation, applied to
    /// the account as ordered; the caller orders it.
    pub fn pair(&mut self, fold: &Fold) -> AccountEvent {
        let event = self.sign_add(&self.ordered.clone(), fold);
        self.accept(&event);
        event
    }
    /// A device addition signed at `view`, applied to nothing.
    pub fn sign_add(&mut self, view: &VerifiedAccount, fold: &Fold) -> AccountEvent {
        let request = view.add_device(self.device(), fold.keys()).unwrap();
        ready(self.account.sign_control(&self.cap, &request)).unwrap()
    }
    /// A note by this Mac, sealed as its outbox seals one, claiming the
    /// base's verified head.
    pub fn note(&self, text: &str) -> Encoded {
        let note = bh_crypto::random();
        let writer = DeviceWriterDeclaration {
            account: self.cap.account_id().0,
            device: self.device().0,
            nonce: bh_crypto::random(),
        };
        let update = Note::with_writer(writer.client_id(WriterScope {
            base: self.base.0,
            audience: [0; 32],
            note,
        }))
        .unwrap()
        .try_append_paragraph(text)
        .unwrap();
        let head = self.history.head();
        let state = self.store.state();
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
                device: self.device(),
                account_head: self.history.account_head(),
                seen: head,
                seen_control: self.history_control(),
                class: CLASS_CONTENT,
                padded: 0,
                commitment: [0; 32],
                seen_receipt: self.receipt(head),
            },
            Payload {
                kind: NOTE,
                data: &note_payload(note, writer, &update),
            },
            state.ordinary.as_ref().unwrap(),
            &self.metadata,
            Some(&self.content),
        )
        .unwrap()
    }
    /// The Fold's removal of itself, applied to the account as ordered.
    pub fn remove(&mut self, fold: &Fold) -> AccountEvent {
        let request = self.ordered.remove_self(fold.id()).unwrap();
        let event = request
            .finish(fold.control.sign(request.signing_bytes()))
            .unwrap();
        self.accept(&event);
        event
    }
    fn accept(&mut self, event: &AccountEvent) {
        self.ordered.apply(event.as_bytes()).unwrap();
        self.originals.push(event.as_bytes().to_vec());
    }
    /// Order an account event through the service, as the Mac does.
    pub async fn submit_account(
        &self,
        harness: &Harness,
        connection: &mut Connection,
        event: &AccountEvent,
    ) {
        let answer = connection
            .handle(ToService::SubmitControl {
                log: self.log,
                event: event.as_bytes().to_vec(),
                delivery: None,
                attachment: None,
            })
            .await;
        let FromService::Permits { items } = answer else {
            panic!("{answer:?}")
        };
        harness
            .edge
            .append(
                items[0].as_ref().unwrap(),
                &account_log_wrap(event.as_bytes(), None).unwrap(),
            )
            .unwrap();
    }
    /// The base copy of an account event, from the native producer and
    /// signed with this Mac's control key.
    pub fn copy(&mut self, account_event: &[u8]) -> Result<Encoded, OwnerError> {
        let event = AccountEvent::decode(account_event).unwrap();
        let confirmation = self.confirm_at(&event, bh_authz::Clock::now_ms(&*self.clock).unwrap());
        let request = self.owner.prepare_account_run_copy(
            self.id,
            &self.anchor,
            &self.metadata,
            &[(account_event.to_vec(), confirmation)],
            bh_event::Copier::Device(self.device()),
        )?;
        let signature = ready(self.account.sign_base_control(
            &self.cap,
            request.expected_key(),
            request.signing_bytes(),
        ))
        .unwrap();
        Ok(request.finish(signature).unwrap())
    }
    /// A validly signed copy carrying an independently signed seen receipt
    /// supplied by a potentially equivocating hosting authority.
    pub fn copy_with_seen_receipt(
        &mut self,
        account_event: &[u8],
        seen: Head,
        seen_receipt: [u8; RECEIPT_LEN],
    ) -> Encoded {
        let event = AccountEvent::decode(account_event).unwrap();
        let confirmation = self.confirm_at(&event, bh_authz::Clock::now_ms(&*self.clock).unwrap());
        let request = bh_event::account_run::prepare_account_run(
            self.base,
            &self.anchor,
            bh_event::Copier::Device(self.device()),
            &self.metadata,
            Seen {
                head: seen,
                control: self.history_control(),
                account: self.anchor.head(),
            },
            seen_receipt,
            &[(account_event.to_vec(), confirmation)],
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

    /// A copy the device producer refuses to make: it claims `base_account`
    /// is the base's copy of the account. For copies of the wrong account
    /// event only.
    pub fn copy_claiming(
        &mut self,
        base_account: &VerifiedAccount,
        account_event: &[u8],
    ) -> Encoded {
        let head = self.history.head();
        let confirmation = self.confirm_at(
            &AccountEvent::decode(account_event).unwrap(),
            bh_authz::Clock::now_ms(&*self.clock).unwrap(),
        );
        let request = bh_event::account_run::prepare_account_run(
            self.base,
            base_account,
            bh_event::Copier::Device(self.device()),
            &self.metadata,
            Seen {
                head,
                control: self.history_control(),
                account: base_account.head(),
            },
            self.receipt(head),
            &[(account_event.to_vec(), confirmation)],
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
    fn history_control(&self) -> [u8; 32] {
        let db = self.owner.shared_database(self.id).unwrap();
        let progress = db.lock().unwrap().log_progress(1, self.base.0).unwrap();
        progress.unwrap().control_digest
    }
    pub fn submit_copy(&self, copy: &Encoded) -> ToService {
        self.submit_copy_with(copy, &self.metadata)
    }
    pub fn submit_copy_with(&self, copy: &Encoded, metadata: &Secret<32>) -> ToService {
        ToService::SubmitBaseControl {
            log: self.base_log(),
            descriptor: copy.descriptor.encode(),
            body: copy.body.clone(),
            metadata: MetadataKey::new(metadata),
        }
    }
    /// Copy an account event through the service, order it and pull it.
    pub async fn copy_ordered(
        &mut self,
        harness: &Harness,
        connection: &mut Connection,
        account_event: &[u8],
    ) -> FromService {
        let copy = self.copy(account_event).unwrap();
        let answer = connection.handle(self.submit_copy(&copy)).await;
        order(harness, &answer, &copy).unwrap();
        assert_eq!(self.pull(harness), vec![Outcome::Accepted]);
        answer
    }
    /// The ordering confirmation the account's checker signs at the
    /// fixture clock, under the harness's hosting root.
    pub fn confirm(&self, event: &AccountEvent) -> Vec<u8> {
        self.confirm_at(event, bh_authz::Clock::now_ms(&*self.clock).unwrap())
    }

    fn confirm_at(&self, event: &AccountEvent, at: u64) -> Vec<u8> {
        use bh_sync::evidence::{
            ConfirmationClaim, OrderingConfirmation, TimeBounds, original_digest,
        };
        let head = |h: bh_account::Head| Head {
            position: h.position,
            hash: bh_sync::Digest(h.hash),
        };
        // The predecessor's head is its own original's hash: no replay, so
        // timed trust events (never valid untimed) can be confirmed too.
        let position = event.head().position;
        let before = bh_account::Head {
            position: position - 1,
            hash: bh_crypto::hash(&self.originals[position as usize - 2]),
        };
        let claim = ConfirmationClaim {
            log: self.log,
            original: original_digest(event.as_bytes()),
            original_previous: head(before),
            original_head: head(event.head()),
            body: None,
            ordered: self.edge.head(self.log),
            bounds: TimeBounds {
                earliest_ms: at,
                latest_ms: at,
            },
        };
        OrderingConfirmation::sign(&self.evidence_keys.0, &self.evidence_keys.1, claim)
            .encode()
            .to_vec()
    }
    /// The base copy of a run of confirmed account events, from the native
    /// producer and signed with this Mac's control key.
    pub fn copy_run(&mut self, run: &[(Vec<u8>, Vec<u8>)]) -> Encoded {
        let request = self
            .owner
            .prepare_account_run_copy(
                self.id,
                &self.anchor,
                &self.metadata,
                run,
                bh_event::Copier::Device(self.device()),
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
    /// Sign a personal-key rotation without advancing the local fixture's
    /// untimed legacy view; the home returns its real timed confirmation.
    pub fn sign_rotation(
        &mut self,
        reason: u64,
        prepared: &bh_account::personal::PreparedRotation,
    ) -> AccountEvent {
        let request = self
            .ordered
            .rotate_personal(
                self.device(),
                reason,
                prepared.public,
                prepared.device_seals_digest,
                prepared.recovery_seal_digest,
            )
            .unwrap();
        request
            .finish(
                self.store
                    .state()
                    .ordinary
                    .as_ref()
                    .unwrap()
                    .sign(request.signing_bytes()),
            )
            .unwrap()
    }
    /// Sign a base rekey carrying the home's exact verified rotation proof.
    pub fn signed_rekey(
        &self,
        rotation: &AccountEvent,
        confirmation: &[u8],
        next: &Secret<32>,
    ) -> (Encoded, bh_sync::BodyObject) {
        let seen = Seen {
            head: self.history.head(),
            control: self.history_control(),
            account: self.ordered.head(),
        };
        let prepared = bh_event::rekey::prepare_rekey(
            self.base,
            &self.ordered,
            self.device(),
            &self.metadata,
            seen,
            self.receipt(seen.head),
            rotation.as_bytes(),
            confirmation,
            next,
            &[vec![17; 1499]],
        )
        .unwrap();
        let state = self.store.state();
        let signature = state
            .ordinary
            .as_ref()
            .unwrap()
            .sign(prepared.control.signing_bytes());
        (
            prepared.control.finish(signature).unwrap(),
            prepared.seal_set,
        )
    }
    /// The account at an earlier position, as an older device holds it.
    pub fn at(&self, position: usize) -> VerifiedAccount {
        let history: Vec<&[u8]> = self.originals[..position]
            .iter()
            .map(Vec::as_slice)
            .collect();
        let mut view = VerifiedAccount::from_genesis(self.anchor.id(), history[0]).unwrap();
        view.apply_batch(&history[1..]).unwrap();
        view
    }
}

/// Stage and append an event under a `[Stage, Append]` answer.
pub fn order(harness: &Harness, answer: &FromService, event: &Encoded) -> Result<Head, String> {
    let FromService::Permits { items } = answer else {
        panic!("permits: {answer:?}")
    };
    harness
        .edge
        .stage(items[0].as_ref().unwrap(), &event.body)?;
    harness
        .edge
        .append(items[1].as_ref().unwrap(), &event.descriptor)
}
