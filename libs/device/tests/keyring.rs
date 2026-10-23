//! The own base opened from the authenticated local keyring across an accepted
//! personal-key rotation: real crypto, a file-backed database and journal.
use bh_account::{
    ConfirmedTime, DevicePublicKeys,
    crypto::{KemKey, Secret, SigningKey, committed_key_id},
    journal::JournalError,
    local_seal::{self, LocalKeyContext, LocalKeyPurpose},
    owner::{AccountCapability, AccountGeneration, AccountLoad, AccountOwner, OwnerError},
    personal::{PersonalKey, prepare_rotation},
    platform::ControlKeyPolicy,
    recovery::Password,
    storage::DeviceJournal,
};
use bh_device::own_base::{OwnBase, OwnBaseError, create_or_open, ensure_keyring};
use bh_storage::{DeviceDatabase, EpochKeyRow, sync_state::LOG_BASE};
use std::{
    future::Future,
    sync::{Arc, Mutex},
};
#[allow(dead_code)]
#[path = "../../account/tests/support/protector.rs"]
mod protector;
#[path = "../../account/tests/support/store.rs"]
mod store;
use protector::RotatingProtector;
use store::FakeStore;

type Owner = AccountOwner<DeviceJournal, FakeStore, RotatingProtector>;

// Structurally canonical genesis fixture for tests of key selection rather
// than original signing; no visible Head is converted into an opening.
fn canonical_genesis(base: [u8; 32]) -> bh_sync::canonical::CanonicalCommitment {
    bh_sync::canonical::CanonicalCommitment::order(
        bh_sync::BaseId(base),
        bh_sync::OrderState::EMPTY,
        bh_sync::Digest(base),
        bh_sync::Route::Control,
    )
    .unwrap()
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut f = std::pin::pin!(future);
    match f
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(r) => r,
        _ => panic!("unexpected pending"),
    }
}
fn activate(owner: &mut Owner) -> Arc<AccountCapability> {
    match ready(owner.activate()).unwrap() {
        AccountLoad::Active(c) => Arc::new(c),
        _ => panic!("not active"),
    }
}
struct Fixture {
    dir: tempfile::TempDir,
    db: Arc<Mutex<DeviceDatabase>>,
    generation: AccountGeneration,
    store: FakeStore,
    protector: RotatingProtector,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Mutex::new(
            DeviceDatabase::open(dir.path().join("account.sqlite")).unwrap(),
        ));
        let generation = AccountGeneration::new();
        Self {
            dir,
            db,
            store: FakeStore::new(generation.clone()),
            generation,
            protector: RotatingProtector::default(),
        }
    }
    fn signup(&self) -> (Owner, Arc<AccountCapability>) {
        let mut owner = AccountOwner::new(
            DeviceJournal::from_shared(self.db.clone()),
            self.store.clone(),
            self.protector.clone(),
            self.generation.clone(),
        );
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
    /// A fresh process: new connection and owner over the surviving native store.
    fn restart(&self) -> (Owner, Arc<AccountCapability>, Arc<Mutex<DeviceDatabase>>) {
        let db = Arc::new(Mutex::new(
            DeviceDatabase::open(self.dir.path().join("account.sqlite")).unwrap(),
        ));
        let mut owner = AccountOwner::new(
            DeviceJournal::from_shared(db.clone()),
            self.store.clone(),
            self.protector.clone(),
            AccountGeneration::new(),
        );
        let cap = activate(&mut owner);
        (owner, cap, db)
    }
    fn raw(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.dir.path().join("account.sqlite")).unwrap()
    }
    fn key_rows(&self) -> i64 {
        self.raw()
            .query_row("SELECT count(*) FROM base_epoch_keys", [], |r| r.get(0))
            .unwrap()
    }
    /// The base's canonical genesis continuation as sync stores it.
    fn set_epoch(&self, base: [u8; 32], metadata_id: [u8; 32], epoch: Option<[u8; 32]>) {
        let genesis = canonical_genesis(base);
        self.raw()
            .execute(
                "INSERT INTO log_progress(log_kind,log_id,position,head_hash,control_digest,hosting_root,account_position,account_hash,metadata_id,epoch_id,floor,order_format,opening,floor_opening)
                 VALUES(?1,?2,1,?3,?4,zeroblob(32),3,zeroblob(32),?5,?6,1,2,?7,?8)
                 ON CONFLICT(log_kind,log_id) DO UPDATE SET position=1,head_hash=excluded.head_hash,opening=excluded.opening,metadata_id=excluded.metadata_id,epoch_id=excluded.epoch_id",
                rusqlite::params![LOG_BASE, base.as_slice(), genesis.head().hash.0.as_slice(), base.as_slice(), metadata_id.as_slice(), epoch.as_ref().map(|e| e.as_slice()), genesis.after().encode().as_slice(), bh_sync::OrderState::EMPTY.encode().as_slice()],
            )
            .unwrap();
    }
}

fn timed(at: u64) -> Option<(ConfirmedTime, Vec<u8>)> {
    Some((
        ConfirmedTime {
            earliest_ms: at,
            latest_ms: at,
        },
        vec![1],
    ))
}

/// Another device joins and leaves; this device rotates the personal key for
/// that removal. Returns the rotation's position, ordered body and new key.
fn rotate(owner: &mut Owner, cap: &AccountCapability) -> (u64, Vec<u8>, PersonalKey) {
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
        .apply_incoming_timed(&[(add.as_bytes(), timed(1_000))])
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
        .apply_incoming_timed(&[(leave.as_bytes(), timed(2_000))])
        .unwrap();
    let next = PersonalKey::generate();
    let prepared = prepare_rotation(&owner.verified(cap).unwrap().advanced(2_000), &next).unwrap();
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
        .apply_incoming_timed(&[(rotation.as_bytes(), timed(3_000))])
        .unwrap();
    (rotation.head().position, prepared.body, next)
}

type Roots = ([u8; 32], [u8; 32]);
fn roots(base: &bh_device::own_base::OwnBase) -> Roots {
    base.with_keys(|m, k| (*m.expose(), *k.expose())).unwrap()
}

#[test]
fn rotation_after_a_fresh_upgrade_still_opens_the_own_base() {
    let f = Fixture::new();
    let (mut owner, cap) = f.signup();
    // Rotation never invents a base: with none held there is nothing to keep.
    ready(ensure_keyring(&mut owner, cap.clone(), f.db.clone())).unwrap();
    assert!(f.db.lock().unwrap().own_base().unwrap().is_none());
    assert_eq!(f.key_rows(), 0);
    let base = ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).unwrap();
    let before = roots(&base);
    let export = base.bootstrap_export(&owner).unwrap();
    drop(base);
    // An earlier build kept no local keyring, and this build has not opened
    // the base yet when the rotation arrives.
    f.raw().execute("DELETE FROM base_epoch_keys", []).unwrap();
    let (position, body, next) = rotate(&mut owner, &cap);
    assert!(matches!(
        ready(owner.accept_rotation(&cap, position, &body)),
        Err(OwnerError::Journal(JournalError::KeyringIncomplete))
    ));
    assert_eq!(f.db.lock().unwrap().personal_delivery().unwrap(), None);
    ready(ensure_keyring(&mut owner, cap.clone(), f.db.clone())).unwrap();
    assert_eq!(f.key_rows(), 2);
    let accepted = ready(owner.accept_rotation(&cap, position, &body)).unwrap();
    assert_eq!(accepted.public(), next.public());
    drop(owner);
    let (mut owner, cap, db) = f.restart();
    let base = ready(create_or_open(&mut owner, cap, db)).unwrap();
    assert_eq!(roots(&base), before);
    assert!(base.bootstrap_export(&owner).unwrap() == export);
}

#[test]
fn accepted_rotation_reopens_own_base_without_middle_account_replay() {
    let f = Fixture::new();
    let (mut owner, cap) = f.signup();
    let before = roots(&ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).unwrap());
    let (position, body, _) = rotate(&mut owner, &cap);
    ready(owner.accept_rotation(&cap, position, &body)).unwrap();
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
    let (mut owner, cap, db) = f.restart(); // Load the current indexed projection.
    assert!(cap.head().position > position);
    // Neither package history (signup prefix) nor the current verified view
    // needs the middle AddDevice original. A replay through it fails.
    f.raw()
        .execute_batch(
            "PRAGMA ignore_check_constraints=ON; UPDATE account_events SET bytes=x'2a' WHERE id=4;",
        )
        .unwrap();
    let bad: Vec<u8> = f
        .raw()
        .query_row("SELECT bytes FROM account_events WHERE id=4", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(bad, [42]);
    assert!(
        owner.verified_at(&cap, position).is_err(),
        "historical replay touches the corrupted original"
    );
    let base = ready(create_or_open(&mut owner, cap, db)).unwrap();
    assert_eq!(roots(&base), before);
}

#[test]
fn keyring_reopen_still_refuses_tampered_original_package() {
    let f = Fixture::new();
    let (mut owner, cap) = f.signup();
    let base = ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).unwrap();
    let before = roots(&base);
    let record = base.bootstrap_export(&owner).unwrap().protected.own_base;
    drop(base);
    let (position, body, _) = rotate(&mut owner, &cap);
    ready(owner.accept_rotation(&cap, position, &body)).unwrap();
    // The package is sealed to the earlier key: only the keyring opens it now.
    let base = ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).unwrap();
    assert_eq!(roots(&base), before);
    drop(base);
    for offset in [
        14 + 11,
        14 + 75,
        14 + 107,
        14 + 139,
        14 + 211,
        14 + 1387,
        14 + 1435,
        18 + 1499 + 107,
        18 + 1499 + 1387,
        3015,
    ] {
        let mut changed = record.initial_key_package.clone();
        changed[offset] ^= 1;
        f.raw()
            .execute("UPDATE own_base SET initial_key_package=?1", [&changed])
            .unwrap();
        assert!(
            ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).is_err(),
            "accepted mutation {offset}"
        );
    }
    f.raw()
        .execute(
            "UPDATE own_base SET initial_key_package=?1",
            [&record.initial_key_package],
        )
        .unwrap();
    let mut body = record.genesis_body.clone();
    body[100] ^= 1;
    f.raw()
        .execute("UPDATE own_base SET genesis_body=?1", [&body])
        .unwrap();
    assert!(ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).is_err());
    f.raw()
        .execute(
            "UPDATE own_base SET genesis_body=?1",
            [&record.genesis_body],
        )
        .unwrap();
    let base = ready(create_or_open(&mut owner, cap, f.db.clone())).unwrap();
    assert_eq!(roots(&base), before);
}

#[test]
fn missing_current_epoch_key_never_falls_back_to_genesis_for_writes() {
    let f = Fixture::new();
    let (mut owner, cap) = f.signup();
    let base = ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).unwrap();
    let id = base.id().0;
    let (metadata, genesis) = roots(&base);
    drop(base);
    let metadata_id = committed_key_id(&Secret::from_slice(&metadata).unwrap());
    assert_ne!(
        committed_key_id(&Secret::from_slice(&genesis).unwrap()),
        [9; 32]
    );
    // Verified history moved to an epoch whose key this device does not hold.
    f.set_epoch(id, metadata_id, Some([9; 32]));
    let base = ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).unwrap();
    let mut called = false;
    assert!(matches!(
        base.with_keys(|_, _| called = true),
        Err(OwnBaseError::KeyPending)
    ));
    assert!(!called);
    drop(base);
    // Holding the verified epoch's key makes it, not genesis, current.
    let next = Secret::<32>::random();
    let personal = ready(owner.open_current_personal(&cap)).unwrap();
    let context = LocalKeyContext {
        account: cap.account_id(),
        base: id,
        purpose: LocalKeyPurpose::Content,
        key_id: committed_key_id(&next),
    };
    let row = EpochKeyRow {
        base: id,
        epoch_id: context.key_id,
        purpose: LocalKeyPurpose::Content as i64,
        seal: local_seal::seal(&context, &personal.public(), &next).unwrap(),
    };
    let mut db = f.db.lock().unwrap();
    let delivery = db.personal_delivery().unwrap();
    db.install_epoch_keys(delivery.as_ref(), &[row], || true)
        .unwrap();
    drop(db);
    f.set_epoch(id, metadata_id, Some(context.key_id));
    let base = ready(create_or_open(&mut owner, cap, f.db.clone())).unwrap();
    assert_eq!(roots(&base), (metadata, *next.expose()));
}

#[test]
fn epoch_key_opens_only_a_held_verified_epoch_with_the_accepted_key() {
    use bh_device::{Owner as Device, OwnerError as DeviceError};
    let dir = tempfile::tempdir().unwrap();
    let device = Device::default();
    let id = device.create_container(dir.path()).unwrap();
    let db = device.shared_database(id).unwrap();
    let generation = AccountGeneration::new();
    let mut owner = AccountOwner::new(
        DeviceJournal::from_shared(db.clone()),
        FakeStore::new(generation.clone()),
        RotatingProtector::default(),
        generation,
    );
    let setup = ready(owner.begin_first_device(
        ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        &Password::new("synthetic keyring test").unwrap(),
    ))
    .unwrap();
    owner.confirm_kit_saved().unwrap();
    // A legacy home: the setup prefix stays untimed.
    owner.confirm_home_ordered(setup.head, None).unwrap();
    let cap = activate(&mut owner);
    device.anchor(id, owner.verified(&cap).unwrap()).unwrap();
    let base = ready(create_or_open(&mut owner, cap.clone(), db.clone())).unwrap();
    let (metadata, genesis) = roots(&base);
    let base = base.id();
    let personal = ready(owner.open_current_personal(&cap)).unwrap();
    let genesis_id = committed_key_id(&Secret::from_slice(&genesis).unwrap());
    let keys = |epoch, with: &PersonalKey| {
        device.with_epoch_key(id, base, epoch, with, |m, k| (*m.expose(), *k.expose()))
    };
    // M comes only from the base's verified history.
    assert!(matches!(
        keys(genesis_id, &personal),
        Err(DeviceError::NotRegistered)
    ));
    let metadata_id = committed_key_id(&Secret::from_slice(&metadata).unwrap());
    db.lock()
        .unwrap()
        .record_registration(base.0, None, [3; 32])
        .unwrap();
    let file = std::fs::read_dir(dir.path().join("accounts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "sqlite"))
        .unwrap();
    // The verified canonical continuation sync stores once genesis is ordered.
    let ordered = canonical_genesis(base.0);
    rusqlite::Connection::open(file)
        .unwrap()
        .execute(
            "UPDATE log_progress SET position=1,head_hash=?1,opening=?2,account_position=3,account_hash=zeroblob(32),metadata_id=?3,epoch_id=?4",
            rusqlite::params![ordered.head().hash.0.as_slice(), ordered.after().encode().as_slice(), metadata_id.as_slice(), genesis_id.as_slice()],
        )
        .unwrap();
    assert_eq!(keys(genesis_id, &personal).unwrap(), (metadata, genesis));
    // An epoch with no row is not held: wait for it.
    assert!(matches!(
        keys([9; 32], &personal),
        Err(DeviceError::Unavailable)
    ));
    // A row that does not open to its committed root is refused as invalid,
    // never reported as merely missing.
    assert!(matches!(
        keys(genesis_id, &PersonalKey::generate()),
        Err(DeviceError::Store(bh_storage::StoreError::CorruptSecurity))
    ));
    let raw = rusqlite::Connection::open(file_path(&dir)).unwrap();
    raw.execute(
        "UPDATE base_epoch_keys SET seal=CAST(zeroblob(length(seal)) AS BLOB) WHERE epoch_id=?1",
        [genesis_id.as_slice()],
    )
    .unwrap();
    assert!(matches!(
        keys(genesis_id, &personal),
        Err(DeviceError::Store(bh_storage::StoreError::CorruptSecurity))
    ));
}

fn file_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
    std::fs::read_dir(dir.path().join("accounts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "sqlite"))
        .unwrap()
}

fn poll<F: Future>(future: std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
    future.poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
}
fn copy(secret: &Secret<32>) -> Secret<32> {
    Secret::from_slice(secret.expose()).unwrap()
}

#[test]
fn an_own_base_holds_every_held_epoch_key_and_m_while_pending_or_closed() {
    let f = Fixture::new();
    let (mut owner, cap) = f.signup();
    let base = ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).unwrap();
    let id = base.id().0;
    let (metadata, genesis) = roots(&base);
    drop(base);
    let metadata_id = committed_key_id(&Secret::from_slice(&metadata).unwrap());
    let genesis_id = committed_key_id(&Secret::from_slice(&genesis).unwrap());
    // A later epoch's key this device holds, sealed to its accepted key.
    let personal = ready(owner.open_current_personal(&cap)).unwrap();
    let later = Secret::<32>::random();
    let later_id = committed_key_id(&later);
    let context = LocalKeyContext {
        account: cap.account_id(),
        base: id,
        purpose: LocalKeyPurpose::Content,
        key_id: later_id,
    };
    let row = EpochKeyRow {
        base: id,
        epoch_id: later_id,
        purpose: LocalKeyPurpose::Content as i64,
        seal: local_seal::seal(&context, &personal.public(), &later).unwrap(),
    };
    let mut db = f.db.lock().unwrap();
    let delivery = db.personal_delivery().unwrap();
    db.install_epoch_keys(delivery.as_ref(), &[row], || true)
        .unwrap();
    drop(db);
    let epoch = |base: &OwnBase, epoch| {
        base.with_epoch_key(epoch, |m, k| (*m.expose(), k.map(|k| *k.expose())))
            .unwrap()
    };

    // The verified epoch's key is not held: no write key, but M and every
    // held epoch's own key are, and nothing stands in for the missing one.
    let pending = Secret::<32>::random();
    f.set_epoch(id, metadata_id, Some(committed_key_id(&pending)));
    let base = ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).unwrap();
    assert!(matches!(
        base.with_keys(|_, _| ()),
        Err(OwnBaseError::KeyPending)
    ));
    assert_eq!(base.with_metadata_key(|m| *m.expose()).unwrap(), metadata);
    assert_eq!(epoch(&base, Some(genesis_id)), (metadata, Some(genesis)));
    assert_eq!(
        epoch(&base, Some(later_id)),
        (metadata, Some(*later.expose()))
    );
    assert_eq!(
        epoch(&base, Some(committed_key_id(&pending))),
        (metadata, None)
    );
    assert_eq!(epoch(&base, None), (metadata, None));
    // Once installed, the key is in memory: writes need no reopen.
    base.remember_epoch(copy(&pending)).unwrap();
    assert_eq!(roots(&base), (metadata, *pending.expose()));
    drop(base);

    // A closed epoch has no write key; M and held keys stay for reading.
    f.set_epoch(id, metadata_id, None);
    let base = ready(create_or_open(&mut owner, cap, f.db.clone())).unwrap();
    assert!(matches!(
        base.with_keys(|_, _| ()),
        Err(OwnBaseError::KeyPending)
    ));
    assert_eq!(base.with_metadata_key(|m| *m.expose()).unwrap(), metadata);
    assert_eq!(epoch(&base, Some(genesis_id)), (metadata, Some(genesis)));
    assert_eq!(epoch(&base, None), (metadata, None));
}

#[test]
fn a_rotation_accepted_by_another_process_during_reopen_is_a_retry() {
    let f = Fixture::new();
    let (mut owner, cap) = f.signup();
    let before = roots(&ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).unwrap());
    let (position, body, _) = rotate(&mut owner, &cap);
    // Another process reopens the base; its native key use is overtaken by
    // this one accepting the rotation, which re-seals every keyring row.
    let (mut other, other_cap, other_db) = f.restart();
    let gate = std::rc::Rc::new(store::SignGate::default());
    f.store.state_mut().decapsulate_gate = Some(gate.clone());
    let result = {
        let mut reopening = std::pin::pin!(create_or_open(
            &mut other,
            other_cap.clone(),
            other_db.clone()
        ));
        assert!(poll(reopening.as_mut()).is_pending());
        assert!(gate.entered());
        ready(owner.accept_rotation(&cap, position, &body)).unwrap();
        gate.open();
        match poll(reopening.as_mut()) {
            std::task::Poll::Ready(result) => result.map(|base| roots(&base)),
            std::task::Poll::Pending => panic!("reopen still pending"),
        }
    };
    // Rows sealed to the newer key are not tampering: the reopen retries.
    assert!(matches!(result, Err(OwnBaseError::Stale)), "{result:?}");
    let base = ready(create_or_open(&mut other, other_cap, other_db)).unwrap();
    assert_eq!(roots(&base), before);
}
