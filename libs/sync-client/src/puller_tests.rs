//! Controlled-clock checks of the production receiver's wait path. No task
//! loop or wall-clock timeout can hide a permanently ready stopped timer.
use super::*;
use bh_sync::{EventId, Route};

// Actual production commitment, receipt and permit encoders, not a selector
// substitute. Two distinct bodies exercise order; [a,a] exercises duplicates.
struct SelectedFixture {
    root: bh_crypto::SigningKey,
    key: bh_crypto::SigningKey,
    log: LogId,
    items: Vec<(Vec<u8>, Vec<u8>)>,
    receipt: [u8; RECEIPT_LEN],
    digests: [Digest; 2],
}
impl SelectedFixture {
    fn new(duplicate: bool) -> Self {
        let root = bh_crypto::SigningKey::generate();
        let key = bh_crypto::SigningKey::generate();
        let mut log = LogId {
            kind: LogKind::Base,
            id: [3; 32],
        };
        let a = BodyObject::new(vec![1; 1024]).unwrap().commitment();
        let b = BodyObject::new(vec![2; 1024]).unwrap().commitment();
        let digests = [a, if duplicate { a } else { b }];
        let mut head = Head::EMPTY;
        let mut order = bh_sync::OrderState::EMPTY;
        let items = digests
            .iter()
            .enumerate()
            .map(|(n, digest)| {
                let mut envelope = vec![n as u8; 1024];
                envelope[..32].copy_from_slice(&digest.0);
                let event = OpaqueEvent::new(EventId([n as u8 + 1; 32]), envelope).unwrap();
                if n == 0 {
                    log.id = BaseId::from_genesis(&event).0;
                }
                let route = if n == 0 {
                    Route::Control
                } else {
                    Route::Content
                };
                let commitment = Commitment::order(BaseId(log.id), order, &event, route).unwrap();
                head = commitment.head();
                order = commitment.after();
                (commitment.encode(), event.encode())
            })
            .collect();
        let receipt_cert =
            receipt::verify_certificate(&root.public(), &receipt::certify(&root, key.public()))
                .unwrap();
        let receipt = receipt::sign(&receipt_cert, &key, BaseId(log.id), head).unwrap();
        Self {
            root,
            key,
            log,
            items,
            receipt,
            digests,
        }
    }
    fn grant(&self, bodies: Vec<Digest>, issued_ms: u64, deadline_ms: u64) -> Vec<u8> {
        permit::sign(
            &self.key,
            &permit::certify(&self.root, self.key.public()),
            &permit::Permit {
                scope: Scope::ReadBodies {
                    log: self.log,
                    bodies,
                },
                issued_ms,
                deadline_ms,
                batch: [1; 16],
            },
        )
    }
    fn reply(&self) -> FromService {
        FromService::ReadBatch {
            log: self.log,
            after: Head::EMPTY,
            issued_ms: 100,
            deadline_ms: 30_100,
            result: ReadBatchResult::Selected {
                items: self.items.clone(),
                receipt: Some(self.receipt),
                body_permit: Some(self.grant(self.digests.to_vec(), 100, 30_100)),
                possibly_more: false,
            },
        }
    }
    fn accepts(&self, reply: FromService) -> bool {
        validate_batch_reply(
            self.root.public(),
            self.log,
            Head::EMPTY,
            Instant::now(),
            reply,
        )
        .is_ok()
    }
}

#[test]
fn selected_page_requires_exact_ordered_body_grant_including_duplicates() {
    let f = SelectedFixture::new(false);
    assert!(f.accepts(f.reply()));
    for bodies in [
        vec![f.digests[1], f.digests[0]],
        vec![f.digests[0]],
        vec![f.digests[0], f.digests[1], f.digests[1]],
    ] {
        let mut reply = f.reply();
        let FromService::ReadBatch {
            result: ReadBatchResult::Selected { body_permit, .. },
            ..
        } = &mut reply
        else {
            unreachable!()
        };
        *body_permit = Some(f.grant(bodies, 100, 30_100));
        assert!(!f.accepts(reply));
    }
    let f = SelectedFixture::new(true);
    assert!(f.accepts(f.reply()));
    for bodies in [
        vec![f.digests[0]],
        vec![
            f.digests[0],
            BodyObject::new(vec![2; 1024]).unwrap().commitment(),
        ],
    ] {
        let mut reply = f.reply();
        let FromService::ReadBatch {
            result: ReadBatchResult::Selected { body_permit, .. },
            ..
        } = &mut reply
        else {
            unreachable!()
        };
        *body_permit = Some(f.grant(bodies, 100, 30_100));
        assert!(!f.accepts(reply));
    }
}

#[test]
fn selected_page_rejects_wrong_grant_time_root_absence_and_tail_receipt() {
    let f = SelectedFixture::new(true);
    assert!(f.accepts(f.reply()));
    for (issued, deadline) in [(101, 30_101), (100, 30_000)] {
        let mut reply = f.reply();
        let FromService::ReadBatch {
            result: ReadBatchResult::Selected { body_permit, .. },
            ..
        } = &mut reply
        else {
            unreachable!()
        };
        *body_permit = Some(f.grant(f.digests.to_vec(), issued, deadline));
        assert!(!f.accepts(reply));
    }
    let other = bh_crypto::SigningKey::generate();
    let mut reply = f.reply();
    let FromService::ReadBatch {
        result: ReadBatchResult::Selected { body_permit, .. },
        ..
    } = &mut reply
    else {
        unreachable!()
    };
    *body_permit = Some(permit::sign(
        &f.key,
        &permit::certify(&other, f.key.public()),
        &permit::Permit {
            scope: Scope::ReadBodies {
                log: f.log,
                bodies: f.digests.to_vec(),
            },
            issued_ms: 100,
            deadline_ms: 30_100,
            batch: [1; 16],
        },
    ));
    assert!(!f.accepts(reply));
    let mut reply = f.reply();
    let FromService::ReadBatch {
        result: ReadBatchResult::Selected { body_permit, .. },
        ..
    } = &mut reply
    else {
        unreachable!()
    };
    *body_permit = None;
    assert!(!f.accepts(reply));
    for receipt_value in [
        None,
        Some([0; RECEIPT_LEN]),
        Some(
            receipt::sign(
                &receipt::verify_certificate(
                    &f.root.public(),
                    &receipt::certify(&f.root, f.key.public()),
                )
                .unwrap(),
                &f.key,
                BaseId(f.log.id),
                Head::EMPTY,
            )
            .unwrap(),
        ),
    ] {
        let mut reply = f.reply();
        let FromService::ReadBatch {
            result: ReadBatchResult::Selected { receipt, .. },
            ..
        } = &mut reply
        else {
            unreachable!()
        };
        *receipt = receipt_value;
        assert!(!f.accepts(reply));
    }
}

#[tokio::test(start_paused = true)]
async fn batch_reply_rejects_wrong_echo_count_grant_and_stale_empty() {
    let root = bh_crypto::SigningKey::generate();
    let key = bh_crypto::SigningKey::generate();
    let cert = permit::certify(&root, key.public());
    let log = LogId {
        kind: LogKind::Base,
        id: [3; 32],
    };
    let after = Head::EMPTY;
    let now = Instant::now();
    let empty = |log, after, body_permit, items: Vec<(Vec<u8>, Vec<u8>)>| FromService::ReadBatch {
        log,
        after,
        issued_ms: 100,
        deadline_ms: 30_100,
        result: ReadBatchResult::Selected {
            items,
            receipt: None,
            body_permit,
            possibly_more: false,
        },
    };
    assert!(
        validate_batch_reply(
            root.public(),
            log,
            after,
            now,
            empty(log, after, None, vec![])
        )
        .is_ok()
    );
    assert!(
        validate_batch_reply(
            root.public(),
            log,
            after,
            now,
            empty(LogId { id: [2; 32], ..log }, after, None, vec![])
        )
        .is_err()
    );
    assert!(
        validate_batch_reply(
            root.public(),
            log,
            after,
            now,
            empty(
                log,
                Head {
                    position: 1,
                    hash: Digest([1; 32])
                },
                None,
                vec![]
            )
        )
        .is_err()
    );
    assert!(
        validate_batch_reply(
            root.public(),
            log,
            after,
            now,
            empty(log, after, None, vec![(vec![], vec![]); 49])
        )
        .is_err()
    );
    let grant = permit::sign(
        &key,
        &cert,
        &permit::Permit {
            scope: Scope::ReadBodies {
                log,
                bodies: vec![Digest([9; 32])],
            },
            issued_ms: 100,
            deadline_ms: 30_100,
            batch: [1; 16],
        },
    );
    assert!(
        validate_batch_reply(
            root.public(),
            log,
            after,
            now,
            empty(log, after, Some(grant), vec![])
        )
        .is_err()
    );
    tokio::time::advance(Duration::from_secs(26)).await;
    assert!(
        validate_batch_reply(
            root.public(),
            log,
            after,
            now,
            empty(log, after, None, vec![])
        )
        .is_err()
    );
}

#[test]
fn transient_batch_refusals_request_follow_and_missing_hold() {
    let log = LogId {
        kind: LogKind::Base,
        id: [3; 32],
    };
    for reason in [Refusal::AccountChangePending, Refusal::NotActive] {
        assert!(matches!(
            validate_batch_reply(
                [4; 32],
                log,
                Head::EMPTY,
                Instant::now(),
                FromService::Refused { reason }
            ),
            Err(Fail::Missing)
        ));
    }
}

#[test]
fn unsupported_batch_refusal_is_not_relabelled_as_network_or_legacy_fallback() {
    let log = LogId {
        kind: LogKind::Base,
        id: [3; 32],
    };
    assert!(matches!(
        validate_batch_reply(
            [4; 32],
            log,
            Head::EMPTY,
            Instant::now(),
            FromService::Refused {
                reason: Refusal::Unsupported
            }
        ),
        Err(Fail::Unsupported)
    ));
}

#[test]
fn repair_page_cannot_exceed_its_authorized_positions() {
    assert!(repair_page_length(11, 58, 48).is_ok());
    assert!(repair_page_length(11, 58, 49).is_err());
    assert!(repair_page_length(11, 11, 2).is_err());
}

#[tokio::test(start_paused = true)]
async fn repair_grant_must_be_exact_range_root_and_original_deadline() {
    let root = bh_crypto::SigningKey::generate();
    let wrong_root = bh_crypto::SigningKey::generate();
    let key = bh_crypto::SigningKey::generate();
    let cert = permit::certify(&root, key.public());
    let log = LogId {
        kind: LogKind::Base,
        id: [3; 32],
    };
    let after = Head::EMPTY;
    let now = Instant::now();
    for (first, last, issued, expected) in [
        (1, 48, 100, true),
        (2, 48, 100, false),
        (1, 64, 100, false),
        (1, 48, 200, false),
    ] {
        let grant = permit::sign(
            &key,
            &cert,
            &permit::Permit {
                scope: Scope::ReadEvents { log, first, last },
                issued_ms: issued,
                deadline_ms: issued + 30_000,
                batch: [1; 16],
            },
        );
        let reply = FromService::ReadBatch {
            log,
            after,
            issued_ms: 100,
            deadline_ms: 30_100,
            result: ReadBatchResult::Repair {
                events_permit: grant,
            },
        };
        assert_eq!(
            validate_batch_reply(root.public(), log, after, now, reply.clone()).is_ok(),
            expected
        );
        assert!(validate_batch_reply(wrong_root.public(), log, after, now, reply).is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn signed_grant_lifetime_is_anchored_before_authz_queue_and_reply() {
    let root = bh_crypto::SigningKey::generate();
    let key = bh_crypto::SigningKey::generate();
    let cert = permit::certify(&root, key.public());
    let signed = permit::sign(
        &key,
        &cert,
        &permit::Permit {
            scope: Scope::Subscribe {
                log: LogId {
                    kind: LogKind::Base,
                    id: [3; 32],
                },
            },
            issued_ms: 100,
            deadline_ms: 30_100,
            batch: [1; 16],
        },
    );
    let requested_at = Instant::now();
    tokio::time::advance(Duration::from_secs(24)).await;
    let until = usable_until(root.public(), &signed, requested_at).expect("still usable");
    assert_eq!(
        until.saturating_duration_since(Instant::now()),
        Duration::from_secs(1)
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(usable_until(root.public(), &signed, requested_at).is_none());
}

use crate::{
    AccountApplyError, Appraisal, BaseControlRequest, ControlSignError, Endpoint, HomeSetup,
    Identity, Signer, SignerError, SyncStatus,
};
use bh_account::{Head as AccountHead, VerifiedAccount, device_auth};
use bh_crypto::Secret;
use bh_device::Owner;
use futures_util::{Sink, Stream, future::BoxFuture};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

// Waiting and the stopped pull must never consult signing authority.
struct NoSigner;
impl Signer for NoSigner {
    fn identity(&self) -> Result<Identity, SignerError> {
        panic!("unexpected signer call")
    }
    fn device_proof(
        &self,
        _: device_auth::Context,
    ) -> BoxFuture<'_, Result<device_auth::Proof, SignerError>> {
        panic!("unexpected signer call")
    }
    fn device_proof_at(
        &self,
        _: AccountHead,
        _: device_auth::Context,
    ) -> BoxFuture<'_, Result<device_auth::Proof, SignerError>> {
        panic!("unexpected signer call")
    }
    fn initial_home_setup(&self) -> Result<Option<HomeSetup>, SignerError> {
        panic!("unexpected signer call")
    }
    fn confirm_home_ordered(
        &self,
        _: &HomeSetup,
        _: [(bh_account::ConfirmedTime, Vec<u8>); 2],
    ) -> Result<(), SignerError> {
        panic!("unexpected signer call")
    }
    fn sign_event(&self, _: Vec<u8>) -> BoxFuture<'_, Result<[u8; 64], SignerError>> {
        panic!("unexpected signer call")
    }
    fn current_account(&self) -> Result<VerifiedAccount, SignerError> {
        panic!("unexpected signer call")
    }
    fn apply_account_timed(
        &self,
        _: AccountHead,
        _: Vec<crate::TimedOriginal>,
    ) -> BoxFuture<'_, Result<AccountHead, AccountApplyError>> {
        panic!("unexpected signer call")
    }
    fn observe_account_accepted(
        &self,
        _: AccountHead,
        _: bh_account::ConfirmedTime,
    ) -> Result<(), SignerError> {
        panic!("unexpected signer call")
    }
    fn sign_base_control(
        &self,
        _: BaseControlRequest,
    ) -> BoxFuture<'_, Result<[u8; 64], ControlSignError>> {
        panic!("unexpected signer call")
    }
    fn with_metadata_key(
        &self,
        _: BaseId,
        _: &mut dyn FnMut(&Secret<32>),
    ) -> Result<(), SignerError> {
        panic!("unexpected signer call")
    }
    fn with_epoch_keys(
        &self,
        _: BaseId,
        _: Option<[u8; 32]>,
        _: &mut dyn FnMut(&Secret<32>, Option<&Secret<32>>),
    ) -> Result<(), SignerError> {
        panic!("unexpected signer call")
    }
    fn install_epoch(
        &self,
        _: bh_device::control::SealWait,
        _: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), bh_device::control::InstallError>> {
        panic!("unexpected signer call")
    }
    fn staged_control(&self) -> Result<Option<bh_account::journal::StagedControl>, SignerError> {
        panic!("unexpected signer call")
    }
    fn stage_rotation(
        &self,
        _: u64,
    ) -> BoxFuture<'_, Result<bh_account::journal::StagedControl, SignerError>> {
        panic!("unexpected signer call")
    }
    fn settle_staged(&self) -> Result<Option<bh_account::owner::staging::Settlement>, SignerError> {
        panic!("unexpected signer call")
    }
    fn discard_staged(&self, _: &bh_account::journal::StagedControl) -> Result<(), SignerError> {
        panic!("unexpected signer call")
    }
    fn accept_rotation(&self, _: u64, _: Vec<u8>) -> BoxFuture<'_, Result<(), SignerError>> {
        panic!("unexpected signer call")
    }
    fn prepare_base_entry(
        &self,
        _: BaseId,
        _: [u8; 32],
        _: String,
        _: u64,
    ) -> BoxFuture<'_, Result<Vec<u8>, SignerError>> {
        panic!("unexpected signer call")
    }
    fn open_directory_entries(
        &self,
        _: Vec<Vec<u8>>,
    ) -> BoxFuture<'_, Result<crate::OpenedEntries, SignerError>> {
        panic!("unexpected signer call")
    }
    fn directory_state(&self) -> Result<Option<(u64, bool)>, SignerError> {
        panic!("unexpected signer call")
    }
    fn set_directory_state(&self, _: u64, _: bool) -> Result<(), SignerError> {
        panic!("unexpected signer call")
    }
    // A fixture with no account directory: nothing of its own to write
    // and no read asked for.
    fn own_entries(&self) -> BoxFuture<'_, Result<crate::OwnEntries, SignerError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn own_entry_held(&self, _: [u8; 32], _: u64) -> Result<(), SignerError> {
        panic!("unexpected signer call")
    }
    fn directory_wanted(&self) -> bool {
        false
    }
    fn directory_read(&self, _: crate::DirectoryRead) {
        panic!("unexpected signer call")
    }
}

// Real DataSocket/Answers over an idle transport: subscriptions remain open
// but never send frames, so only their renewal deadlines can wake the receiver.
struct Quiet;
impl Stream for Quiet {
    type Item = Result<Message, WsError>;
    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}
impl Sink<Message> for Quiet {
    type Error = WsError;
    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Poll::Ready(Ok(()))
    }
    fn start_send(self: Pin<&mut Self>, _: Message) -> Result<(), WsError> {
        Ok(())
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Poll::Ready(Ok(()))
    }
}
impl crate::transport::Connector for Quiet {
    fn connect(
        &self,
        _: crate::transport::Route,
    ) -> BoxFuture<'_, Result<crate::transport::Socket, crate::transport::TransportError>> {
        Box::pin(async { Ok(Box::pin(Quiet) as crate::transport::Socket) })
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    shared: Arc<Shared>,
    receiver: Receiver,
    key: bh_storage::NoteKey,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(Owner::default());
        let container = owner.create_container(dir.path()).unwrap();
        let genesis = OpaqueEvent::new(bh_sync::EventId([4; 32]), vec![9; 1024]).unwrap();
        let base = BaseId::from_genesis(&genesis);
        let first = Commitment::order(
            base,
            bh_sync::OrderState::EMPTY,
            &genesis,
            bh_sync::Route::Control,
        )
        .unwrap();
        let key = bh_storage::NoteKey {
            base: base.0,
            audience: [0; 32],
            note: [2; 32],
        };
        owner
            .shared_database(container)
            .unwrap()
            .lock()
            .unwrap()
            .record_registration(key.base, None, [3; 32])
            .unwrap();
        // Storage-level synthetic continuation: wait must not mutate either
        // durable held candidates or pending local bytes. This does not forge
        // an AppliedEvent or bypass the Owner's authenticated-event boundary.
        {
            use bh_storage::{
                held_notes::HeldEvent,
                sync_state::{IncomingCommit, IncomingStep, SeenRow, VerifiedRecord},
            };
            let database = owner.shared_database(container).unwrap();
            let mut db = database.lock().unwrap();
            db.apply_local_update(key, [1; 16], &[0, 0]).unwrap();
            let event = OpaqueEvent::new(bh_sync::EventId([5; 32]), vec![0; 1024]).unwrap();
            let ordered =
                Commitment::order(base, first.after(), &event, bh_sync::Route::Content).unwrap();
            let mut commit = IncomingCommit {
                log_kind: bh_storage::sync_state::LOG_BASE,
                log_id: key.base,
                hosting_root: [3; 32],
                after: (0, [0; 32]),
                after_order: bh_sync::OrderState::EMPTY,
                receipt: [0; RECEIPT_LEN],
                records: [first, ordered]
                    .into_iter()
                    .map(|record| VerifiedRecord {
                        order: record.after(),
                        seen: SeenRow {
                            position: record.head().position,
                            head_hash: record.head().hash.0,
                            control_digest: first.event_digest().0,
                            account_position: 1,
                            account_hash: [6; 32],
                        },
                        event_id: record.event_id().0,
                        digest: record.event_digest().0,
                        account_change: None,
                        judged_floor: 1,
                        floor: 1,
                    })
                    .collect(),
                metadata_id: [7; 32],
                epoch_id: Some([8; 32]),
                notes: Vec::new(),
                steps: vec![IncomingStep::Hold(0)],
                own: Vec::new(),
                held: vec![(
                    key,
                    vec![HeldEvent {
                        ordered,
                        author: None,
                        writer: None,
                        delta: Some(vec![0, 0]),
                        own_update: None,
                    }],
                )],
            };
            // A held row without its ordered step must not silently vanish.
            commit.steps.clear();
            assert!(matches!(
                db.commit_incoming(&commit, |_| Ok(())),
                Err(bh_storage::StoreError::CorruptSyncState)
            ));
            commit.steps.push(IncomingStep::Hold(0));
            db.commit_incoming(&commit, |_| Ok(())).unwrap();
        }
        let endpoint = Endpoint {
            edge_url: "http://unused.invalid".into(),
            hosting_root: [3; 32],
            app_root: [4; 32],
            policy: Vec::new(),
            policy_signature: Vec::new(),
            limits: bh_confidential_policy::Limits {
                max_lifetime_secs: 60,
                max_uncertainty_secs: 1,
            },
            build_floor: 0,
            appraisal: Appraisal::Hardware,
            device_clock: Arc::new(crate::SystemDeviceClock),
            recovery_key: bh_sync::evidence::certify_recovery_key(
                &bh_crypto::SigningKey::generate(),
                &bh_crypto::KemKey::generate().public(),
            ),
        };
        let shared = Shared::new(
            endpoint,
            Arc::new(Quiet),
            owner,
            container,
            Arc::new(NoSigner),
            tokio::sync::watch::channel(SyncStatus::Synced).0,
            crate::Tuning::default(),
        );
        let mut receiver = Receiver {
            log: Some(LogId {
                kind: LogKind::Base,
                id: key.base,
            }),
            ..Receiver::default()
        };
        assert!(receiver.retries.permit(key, Instant::now()));
        receiver.watch(&shared, None);
        Self {
            _dir: dir,
            shared,
            receiver,
            key,
        }
    }
    fn assert_retained(&self) {
        fn check(db: &bh_storage::DeviceDatabase, key: bh_storage::NoteKey) {
            let held = db.next_held_event(key, 0).unwrap().unwrap();
            assert_eq!(held.delta, Some(vec![0, 0]));
            assert_eq!(held.ordered.head().position, 2);
            let pending = db.pending_note_updates().unwrap();
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].key, key);
            assert_eq!(pending[0].bytes, vec![0, 0]);
        }
        let database = self
            .shared
            .owner
            .shared_database(self.shared.container)
            .unwrap();
        check(&database.lock().unwrap(), self.key);
    }
    fn stop_base(&self) {
        self.shared
            .owner
            .record_stop(
                self.shared.container,
                self.receiver.log.unwrap(),
                StopReason::Integrity,
            )
            .unwrap();
    }
    async fn subscriptions(&mut self) -> crate::data::DataSocket {
        let socket = crate::data::DataSocket::open(&Quiet).await.unwrap();
        for sub in [&mut self.receiver.base, &mut self.receiver.account] {
            *sub = Some(Subscription {
                answers: socket
                    .send(|id| Request::Subscribe {
                        id,
                        permit: vec![1],
                        after: 0,
                    })
                    .unwrap(),
                renew_at: Instant::now() + Duration::from_secs(2),
            });
        }
        socket
    }
}

async fn assert_quiet(f: &mut Fixture, account_stopped: bool) {
    // Both held and renewal deadlines are now in the past. Poll exactly once
    // per observation, so the regression fails rather than spinning forever.
    tokio::time::advance(Duration::from_secs(3)).await;
    let before = progress(&f.shared, f.receiver.log.unwrap()).unwrap();
    {
        let wait = f
            .receiver
            .wait(&f.shared, Duration::from_secs(10), account_stopped);
        tokio::pin!(wait);
        assert!(
            futures_util::poll!(&mut wait).is_pending(),
            "terminal timer was runnable"
        );
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(
            futures_util::poll!(&mut wait).is_pending(),
            "normal delay was shortened"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(futures_util::poll!(&mut wait).is_ready());
    }
    f.assert_retained();
    assert_eq!(
        progress(&f.shared, f.receiver.log.unwrap()).unwrap(),
        before
    );
}

#[tokio::test(start_paused = true)]
async fn stopped_base_pull_does_not_leave_runnable_timers() {
    let mut f = Fixture::new();
    let _socket = f.subscriptions().await;
    f.stop_base();
    let log = f.receiver.log.unwrap();
    assert!(
        !pull(&f.shared, &mut Link::default(), &mut f.receiver, log)
            .await
            .unwrap()
    );
    assert_quiet(&mut f, false).await;
}

#[tokio::test(start_paused = true)]
async fn stopped_account_skipping_pull_does_not_leave_runnable_timers() {
    let mut f = Fixture::new();
    let _socket = f.subscriptions().await;
    // outbox skips pull once Copier is stopped; its flag must reach wait.
    let mut copier = crate::copier::Copier::default();
    copier.stopped = true;
    assert_quiet(&mut f, copier.stopped).await;
}

#[tokio::test(start_paused = true)]
async fn stop_after_retry_scheduling_is_seen_before_wait() {
    let mut f = Fixture::new();
    // A stop recorded during guest preparation/commit, after pull's early
    // check. The final durable check must not rely on that earlier result.
    assert!(
        progress(&f.shared, f.receiver.log.unwrap())
            .unwrap()
            .stopped
            .is_none()
    );
    f.stop_base();
    assert_quiet(&mut f, false).await;
}

#[tokio::test(start_paused = true)]
async fn stopped_subscription_deadlines_are_quiet_without_any_held_deadline() {
    let mut f = Fixture::new();
    f.receiver.retries.notes.clear();
    let _socket = f.subscriptions().await;
    f.stop_base();
    assert_quiet(&mut f, false).await;
}

#[tokio::test(start_paused = true)]
async fn healthy_wakes_and_reconnect_preserve_held_backoff() {
    let mut f = Fixture::new();
    // Foreground wake ends a wait, but must not permit another engine turn.
    f.shared.wake();
    f.receiver
        .wait(&f.shared, Duration::from_secs(10), false)
        .await;
    assert!(!f.receiver.retries.permit(f.key, Instant::now()));
    f.receiver.drop_subscriptions();
    let wait = f.receiver.wait(&f.shared, Duration::from_secs(10), false);
    tokio::pin!(wait);
    assert!(futures_util::poll!(&mut wait).is_pending());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(futures_util::poll!(&mut wait).is_ready());
}

#[tokio::test(start_paused = true)]
async fn stopped_wait_still_accepts_an_external_wake() {
    let mut f = Fixture::new();
    f.stop_base();
    tokio::time::advance(Duration::from_secs(3)).await;
    let wait = f.receiver.wait(&f.shared, Duration::from_secs(10), false);
    tokio::pin!(wait);
    assert!(futures_util::poll!(&mut wait).is_pending());
    f.shared.wake();
    assert!(futures_util::poll!(&mut wait).is_ready());
}

#[tokio::test(start_paused = true)]
async fn stopped_wait_preserves_holds_pending_bytes_and_stop_on_reopen() {
    let mut f = Fixture::new();
    f.stop_base();
    assert_quiet(&mut f, false).await;
    let before = progress(&f.shared, f.receiver.log.unwrap()).unwrap();
    let Fixture {
        _dir, shared, key, ..
    } = f;
    let path = std::fs::read_dir(_dir.path().join("accounts"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "sqlite"))
        .unwrap();
    // DeviceDatabase intentionally owns an exclusive file lock: release the
    // original owner before reopening, just as a stopped process would.
    drop(shared);
    let reopened = bh_storage::DeviceDatabase::open(&path).unwrap();
    assert_eq!(reopened.log_progress(1, key.base).unwrap(), Some(before));
    assert!(before.stopped.is_some());
    assert_eq!(
        reopened.next_held_event(key, 0).unwrap().unwrap().delta,
        Some(vec![0, 0])
    );
    let pending = reopened.pending_note_updates().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].bytes, vec![0, 0]);
}

#[test]
fn retry_stop_is_terminal_for_the_client() {
    assert_eq!(
        owner_fail(OwnerError::from(bh_storage::StoreError::LogStopped)),
        Fail::Stopped
    );
}
