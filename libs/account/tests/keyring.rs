//! The accepted personal key and the local keyring it re-seals, over the real
//! device database, real crypto and a native store held at its await points.
use std::cell::Cell;
use std::future::Future;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

#[allow(dead_code)]
#[path = "support/protector.rs"]
mod protector;
#[path = "support/store.rs"]
mod store;

use bh_account::crypto::{KemKey, Secret, SigningKey, committed_key_id};
use bh_account::journal::JournalError;
use bh_account::local_seal::{self, LocalKeyContext, LocalKeyPurpose};
use bh_account::owner::{AccountCapability, AccountGeneration, AccountLoad, OwnerError};
use bh_account::personal::{PersonalKey, prepare_rotation};
use bh_account::platform::{
    ControlKeyPolicy, DeviceKeyStore, KeyHandle, KeyStoreError, StoredDevice,
};
use bh_account::recovery::Password;
use bh_account::storage::DeviceJournal;
use bh_account::{AccountId, ConfirmedTime, DevicePublicKeys};
use bh_storage::DeviceDatabase;
use bh_storage::{EpochKeyRow, StagedControl};
use protector::PlainProtector;
use store::FakeStore;

type Owner = bh_account::owner::AccountOwner<DeviceJournal, HeldStore, PlainProtector>;

fn poll<F: Future + ?Sized>(future: std::pin::Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn ready<F: Future>(future: F) -> F::Output {
    match poll(std::pin::pin!(future)) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("unexpectedly pending"),
    }
}

/// A real fake key store whose native decapsulation waits while `hold` is set,
/// standing in for a prompt the person has not answered yet.
#[derive(Clone)]
struct HeldStore {
    inner: FakeStore,
    hold: Rc<Cell<bool>>,
    entered: Rc<Cell<usize>>,
}
impl DeviceKeyStore for HeldStore {
    async fn create(&mut self, p: ControlKeyPolicy) -> Result<StoredDevice, KeyStoreError> {
        self.inner.create(p).await
    }
    async fn load(&mut self, h: KeyHandle) -> Result<StoredDevice, KeyStoreError> {
        self.inner.load(h).await
    }
    async fn sign_control(&mut self, h: KeyHandle, m: Vec<u8>) -> Result<[u8; 64], KeyStoreError> {
        self.inner.sign_control(h, m).await
    }
    async fn sign_content(&mut self, h: KeyHandle, m: Vec<u8>) -> Result<[u8; 64], KeyStoreError> {
        self.inner.sign_content(h, m).await
    }
    async fn decapsulate(
        &mut self,
        h: KeyHandle,
        ct: [u8; 1120],
    ) -> Result<Secret<32>, KeyStoreError> {
        self.entered.set(self.entered.get() + 1);
        std::future::poll_fn(|_| {
            if self.hold.get() {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        self.inner.decapsulate(h, ct).await
    }
}

struct Harness {
    dir: tempfile::TempDir,
    db: Arc<Mutex<DeviceDatabase>>,
    generation: AccountGeneration,
    store: HeldStore,
}
impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Mutex::new(
            DeviceDatabase::open(dir.path().join("account.sqlite")).unwrap(),
        ));
        let generation = AccountGeneration::new();
        Self {
            dir,
            db,
            store: HeldStore {
                inner: FakeStore::new(generation.clone()),
                hold: Rc::new(Cell::new(false)),
                entered: Rc::new(Cell::new(0)),
            },
            generation,
        }
    }
    fn owner(&self) -> Owner {
        bh_account::owner::AccountOwner::new(
            DeviceJournal::from_shared(self.db.clone()),
            self.store.clone(),
            PlainProtector,
            self.generation.clone(),
        )
    }
    fn signup(&self) -> (Owner, Arc<AccountCapability>) {
        let mut owner = self.owner();
        let setup = ready(owner.begin_first_device(
            ControlKeyPolicy::AppEnforcedOwnerConfirmation,
            &Password::new("synthetic keyring test").unwrap(),
        ))
        .unwrap();
        owner.confirm_kit_saved().unwrap();
        // A legacy home: the setup prefix stays untimed.
        owner.confirm_home_ordered(setup.head, None).unwrap();
        let cap = activate(&mut owner);
        (owner, cap)
    }
    /// A fresh process over the same file and native store.
    fn restart(&self) -> (Owner, Arc<AccountCapability>) {
        let db = Arc::new(Mutex::new(
            DeviceDatabase::open(self.dir.path().join("account.sqlite")).unwrap(),
        ));
        let mut owner = bh_account::owner::AccountOwner::new(
            DeviceJournal::from_shared(db),
            self.store.clone(),
            PlainProtector,
            AccountGeneration::new(),
        );
        let cap = activate(&mut owner);
        (owner, cap)
    }
    fn rows(&self) -> Vec<EpochKeyRow> {
        let db = self.db.lock().unwrap();
        let mut rows = Vec::new();
        for base in [BASE_A, BASE_B] {
            rows.extend(db.epoch_keys(base).unwrap());
        }
        rows
    }
    fn delivery(&self) -> Option<(u64, Vec<u8>)> {
        self.db.lock().unwrap().personal_delivery().unwrap()
    }
}

fn activate(owner: &mut Owner) -> Arc<AccountCapability> {
    match ready(owner.activate()).unwrap() {
        AccountLoad::Active(c) => Arc::new(c),
        _ => panic!("not active"),
    }
}

const BASE_A: [u8; 32] = [0xa1; 32];
const BASE_B: [u8; 32] = [0xb1; 32];

fn timed(at: u64) -> Option<(ConfirmedTime, Vec<u8>)> {
    Some((
        ConfirmedTime {
            earliest_ms: at,
            latest_ms: at,
        },
        vec![1],
    ))
}

/// Another device joins and leaves; this device then rotates the personal key
/// for that removal. Returns the rotation's position, its ordered device-seal
/// body, the new key and the leaving event's position.
fn rotate(owner: &mut Owner, cap: &AccountCapability) -> (u64, Vec<u8>, PersonalKey, u64) {
    rotate_at(owner, cap, 0)
}
fn rotate_at(
    owner: &mut Owner,
    cap: &AccountCapability,
    offset: u64,
) -> (u64, Vec<u8>, PersonalKey, u64) {
    let control = SigningKey::generate();
    let other = DevicePublicKeys::new(
        SigningKey::generate().public(),
        control.public(),
        KemKey::generate().public(),
    )
    .unwrap();
    let request = owner.prepare_add_device(cap, other.clone()).unwrap();
    let add = ready(owner.sign_control(cap, &request)).unwrap();
    owner
        .apply_incoming_timed(&[(add.as_bytes(), timed(offset + 1_000))])
        .unwrap();
    let request = owner
        .verified(cap)
        .unwrap()
        .remove_self(other.id())
        .unwrap();
    let leave = request
        .finish(control.sign(request.signing_bytes()))
        .unwrap();
    owner
        .apply_incoming_timed(&[(leave.as_bytes(), timed(offset + 2_000))])
        .unwrap();
    let next = PersonalKey::generate();
    let prepared = prepare_rotation(
        &owner.verified(cap).unwrap().advanced(offset + 2_000),
        &next,
    )
    .unwrap();
    let request = owner
        .verified(cap)
        .unwrap()
        .rotate_personal(
            cap.device_id(),
            leave.head().position,
            prepared.public,
            prepared.device_seals_digest,
            prepared.recovery_seal_digest,
        )
        .unwrap();
    let signature = ready(owner.sign_content(cap, request.signing_bytes())).unwrap();
    let rotation = request.finish(signature).unwrap();
    owner
        .apply_incoming_timed(&[(rotation.as_bytes(), timed(offset + 3_000))])
        .unwrap();
    (
        rotation.head().position,
        prepared.body,
        next,
        leave.head().position,
    )
}

fn context(
    account: AccountId,
    base: [u8; 32],
    purpose: LocalKeyPurpose,
    root: &Secret<32>,
) -> LocalKeyContext {
    LocalKeyContext {
        account,
        base,
        purpose,
        key_id: committed_key_id(root),
    }
}
fn row(
    account: AccountId,
    base: [u8; 32],
    purpose: LocalKeyPurpose,
    root: &Secret<32>,
    to: &PersonalKey,
) -> EpochKeyRow {
    let context = context(account, base, purpose, root);
    EpochKeyRow {
        base,
        epoch_id: context.key_id,
        purpose: purpose as i64,
        seal: local_seal::seal(&context, &to.public(), root).unwrap(),
    }
}
fn opens(account: AccountId, row: &EpochKeyRow, with: &PersonalKey) -> Option<[u8; 32]> {
    let purpose = if row.purpose == 1 {
        LocalKeyPurpose::Metadata
    } else {
        LocalKeyPurpose::Content
    };
    let context = LocalKeyContext {
        account,
        base: row.base,
        purpose,
        key_id: row.epoch_id,
    };
    local_seal::open(&context, with, &row.seal)
        .ok()
        .map(|root| *root.expose())
}

/// Metadata and genesis content for one base, a retained earlier epoch key, and
/// another base's content key: every row sealed to `to`.
/// Keep `row` as production does: added under the accepted delivery, never
/// replacing a row already held.
fn install(h: &Harness, row: &EpochKeyRow) {
    let mut db = h.db.lock().unwrap();
    let delivery = db.personal_delivery().unwrap();
    db.install_epoch_keys(delivery.as_ref(), std::slice::from_ref(row), || true)
        .unwrap();
}

fn retained(h: &Harness, account: AccountId, to: &PersonalKey) -> Vec<([u8; 32], EpochKeyRow)> {
    let mut out = Vec::new();
    for (base, purpose) in [
        (BASE_A, LocalKeyPurpose::Metadata),
        (BASE_A, LocalKeyPurpose::Content),
        (BASE_A, LocalKeyPurpose::Content),
        (BASE_B, LocalKeyPurpose::Content),
    ] {
        let root = Secret::<32>::random();
        let row = row(account, base, purpose, &root, to);
        install(h, &row);
        out.push((*root.expose(), row));
    }
    out
}

#[test]
fn current_personal_key_changes_only_when_rotation_is_accepted() {
    let h = Harness::new();
    let (mut owner, cap) = h.signup();
    let initial = ready(owner.open_current_personal(&cap)).unwrap();
    assert_eq!(
        &initial.public(),
        owner.verified(&cap).unwrap().personal_public().unwrap()
    );
    let (position, body, next, leave) = rotate(&mut owner, &cap);
    // A client stages its proposal before ordering; staging is not acceptance.
    h.db.lock()
        .unwrap()
        .stage_account_control(&StagedControl {
            kind: 9,
            event: vec![9],
            body: Some(body.clone()),
            attachment: None,
            sealed_kit: None,
        })
        .unwrap();
    // Verified history now publishes the new key; this device has not accepted it.
    assert_eq!(
        owner.verified(&cap).unwrap().personal_public().unwrap(),
        &next.public()
    );
    let current = ready(owner.open_current_personal(&cap)).unwrap();
    assert_eq!(current.public(), initial.public());

    // Only an effective RotatePersonal that published this key is accepted.
    assert!(ready(owner.accept_rotation(&cap, leave, &body)).is_err());
    let mut tampered = body.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(ready(owner.accept_rotation(&cap, position, &tampered)).is_err());
    assert!(ready(owner.accept_rotation(&cap, position + 1, &body)).is_err());
    assert_eq!(h.delivery(), None);

    let accepted = ready(owner.accept_rotation(&cap, position, &body)).unwrap();
    assert_eq!(accepted.public(), next.public());
    assert_eq!(h.delivery(), Some((position, body.clone())));
    // An exact retry is idempotent; other bytes at the accepted position are not.
    let again = ready(owner.accept_rotation(&cap, position, &body)).unwrap();
    assert_eq!(again.public(), next.public());
    assert!(ready(owner.accept_rotation(&cap, position, &tampered)).is_err());
    assert_eq!(h.delivery(), Some((position, body.clone())));
    assert_eq!(
        ready(owner.open_current_personal(&cap)).unwrap().public(),
        next.public()
    );
    drop(owner);
    let (mut owner, cap) = h.restart();
    assert_eq!(
        ready(owner.open_current_personal(&cap)).unwrap().public(),
        next.public()
    );
}

#[test]
fn accepted_current_rotation_opens_without_replaying_middle_history() {
    let h = Harness::new();
    let (mut owner, cap) = h.signup();
    let (position, body, next, _) = rotate(&mut owner, &cap);
    ready(owner.accept_rotation(&cap, position, &body)).unwrap();
    // A later account event makes the accepted rotation historical.
    let other = DevicePublicKeys::new(
        SigningKey::generate().public(),
        SigningKey::generate().public(),
        KemKey::generate().public(),
    )
    .unwrap();
    let request = owner.prepare_add_device(&cap, other).unwrap();
    let add = ready(owner.sign_control(&cap, &request)).unwrap();
    owner
        .apply_incoming_timed(&[(add.as_bytes(), timed(4_000))])
        .unwrap();
    drop(owner);
    let (mut owner, cap) = h.restart(); // The saved projection has the current head.
    assert!(cap.head().position > position);
    // This original is neither the signup prefix nor the current publication.
    // A historical replay of the accepted rotation must now fail.
    let raw = rusqlite::Connection::open(h.dir.path().join("account.sqlite")).unwrap();
    raw.execute_batch(
        "PRAGMA ignore_check_constraints=ON; UPDATE account_events SET bytes=x'2a' WHERE id=4;",
    )
    .unwrap();
    let bad: Vec<u8> = raw
        .query_row("SELECT bytes FROM account_events WHERE id=4", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(bad, [42]);
    assert!(
        owner.verified_at(&cap, position).is_err(),
        "historical replay touches the corrupted original"
    );
    assert_eq!(
        ready(owner.open_current_personal(&cap)).unwrap().public(),
        next.public()
    );
}

#[test]
fn newer_unaccepted_publication_keeps_historical_accepted_key() {
    let h = Harness::new();
    let (mut owner, cap) = h.signup();
    let (position, body, accepted, _) = rotate(&mut owner, &cap);
    ready(owner.accept_rotation(&cap, position, &body)).unwrap();
    let (newer, _, proposed, _) = rotate_at(&mut owner, &cap, 3_000);
    assert!(newer > position);
    assert_ne!(proposed.public(), accepted.public());
    drop(owner);
    let (mut owner, cap) = h.restart();
    assert_eq!(cap.head().position, newer);
    assert_eq!(
        ready(owner.open_current_personal(&cap)).unwrap().public(),
        accepted.public(),
        "newer verified publication is not locally accepted"
    );
}

#[test]
fn accept_rotation_atomically_reseals_retained_keys() {
    let h = Harness::new();
    let (mut owner, cap) = h.signup();
    let account = cap.account_id();
    let initial = ready(owner.open_current_personal(&cap)).unwrap();
    let before = retained(&h, account, &initial);
    let (position, body, next, _) = rotate(&mut owner, &cap);
    ready(owner.accept_rotation(&cap, position, &body)).unwrap();
    let after = h.rows();
    assert_eq!(after.len(), before.len());
    for (root, old) in &before {
        let new = after
            .iter()
            .find(|r| (r.base, r.epoch_id, r.purpose) == (old.base, old.epoch_id, old.purpose))
            .expect("every retained row kept");
        assert_ne!(new.seal, old.seal);
        assert_eq!(opens(account, new, &next), Some(*root));
        assert_eq!(opens(account, new, &initial), None);
    }
    assert_eq!(h.delivery(), Some((position, body)));
}

#[test]
fn failed_acceptance_keeps_old_delivery_and_rows() {
    let h = Harness::new();
    let (mut owner, cap) = h.signup();
    let account = cap.account_id();
    let initial = ready(owner.open_current_personal(&cap)).unwrap();
    retained(&h, account, &initial);
    let before = h.rows();
    let (position, body, next, _) = rotate(&mut owner, &cap);
    // The second re-sealed row fails after the old rows were replaced in the
    // same transaction.
    rusqlite::Connection::open(h.dir.path().join("account.sqlite"))
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_reseal BEFORE INSERT ON base_epoch_keys
             WHEN (SELECT count(*) FROM base_epoch_keys) >= 1
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .unwrap();
    assert!(ready(owner.accept_rotation(&cap, position, &body)).is_err());
    assert_eq!(h.rows(), before);
    assert_eq!(h.delivery(), None);
    assert_eq!(
        ready(owner.open_current_personal(&cap)).unwrap().public(),
        initial.public()
    );
    rusqlite::Connection::open(h.dir.path().join("account.sqlite"))
        .unwrap()
        .execute_batch("DROP TRIGGER fail_reseal")
        .unwrap();
    assert_eq!(
        ready(owner.accept_rotation(&cap, position, &body))
            .unwrap()
            .public(),
        next.public()
    );
}

#[test]
fn concurrent_key_insert_is_not_lost_by_acceptance() {
    let h = Harness::new();
    let (mut owner, cap) = h.signup();
    let account = cap.account_id();
    let initial = ready(owner.open_current_personal(&cap)).unwrap();
    retained(&h, account, &initial);
    let (position, body, next, _) = rotate(&mut owner, &cap);
    let late_root = Secret::<32>::random();
    let late = row(
        account,
        BASE_B,
        LocalKeyPurpose::Content,
        &late_root,
        &initial,
    );
    {
        h.store.hold.set(true);
        let mut accept = Box::pin(owner.accept_rotation(&cap, position, &body));
        assert!(poll(accept.as_mut()).is_pending());
        assert!(h.store.entered.get() >= 1);
        // Native key work holds no writer: a receive can store a new key now.
        install(&h, &late);
        h.store.hold.set(false);
        let Poll::Ready(result) = poll(accept.as_mut()) else {
            panic!("released store still pending")
        };
        assert!(matches!(
            result,
            Err(OwnerError::Journal(JournalError::KeyringChanged))
        ));
    }
    assert_eq!(h.delivery(), None);
    let kept = h.rows();
    assert!(kept.contains(&late), "the concurrent key is kept as stored");
    // A retry re-seals every row, including the one inserted meanwhile.
    ready(owner.accept_rotation(&cap, position, &body)).unwrap();
    let after = h.rows();
    assert_eq!(after.len(), kept.len());
    let resealed = after
        .iter()
        .find(|r| (r.base, r.epoch_id) == (late.base, late.epoch_id))
        .unwrap();
    assert_eq!(opens(account, resealed, &next), Some(*late_root.expose()));
}

#[test]
fn stale_generation_during_native_open_refuses_acceptance() {
    let h = Harness::new();
    let (mut owner, cap) = h.signup();
    let account = cap.account_id();
    let initial = ready(owner.open_current_personal(&cap)).unwrap();
    retained(&h, account, &initial);
    let before = h.rows();
    let (position, body, _, _) = rotate(&mut owner, &cap);
    {
        h.store.hold.set(true);
        let mut accept = Box::pin(owner.accept_rotation(&cap, position, &body));
        assert!(poll(accept.as_mut()).is_pending());
        assert!(h.db.try_lock().is_ok(), "no writer across native work");
        h.generation.advance();
        h.store.hold.set(false);
        let Poll::Ready(result) = poll(accept.as_mut()) else {
            panic!("released store still pending")
        };
        assert!(matches!(result, Err(OwnerError::Stale)));
    }
    assert_eq!(h.rows(), before);
    assert_eq!(h.delivery(), None);
    let cap = activate(&mut owner);
    assert_eq!(
        ready(owner.open_current_personal(&cap)).unwrap().public(),
        initial.public()
    );
}

#[test]
fn a_lagging_owner_catches_its_view_up_before_accepting() {
    let h = Harness::new();
    let (mut owner, cap) = h.signup();
    let (position, body, next, _) = rotate(&mut owner, &cap);
    // Another process loads now; this one then commits further history,
    // so the other's view lags the durable head.
    let (mut lagging, lagging_cap) = h.restart();
    let other = DevicePublicKeys::new(
        SigningKey::generate().public(),
        SigningKey::generate().public(),
        KemKey::generate().public(),
    )
    .unwrap();
    let request = owner.prepare_add_device(&cap, other).unwrap();
    let add = ready(owner.sign_control(&cap, &request)).unwrap();
    owner
        .apply_incoming_timed(&[(add.as_bytes(), timed(4_000))])
        .unwrap();
    let durable = owner.verified(&cap).unwrap().head();
    assert!(lagging.verified(&lagging_cap).unwrap().head().position < durable.position);
    // Not a keyring change to retry forever: the view catches up first.
    let accepted = ready(lagging.accept_rotation(&lagging_cap, position, &body)).unwrap();
    assert_eq!(accepted.public(), next.public());
    assert_eq!(lagging.verified(&lagging_cap).unwrap().head(), durable);
}
