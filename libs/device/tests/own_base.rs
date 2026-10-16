use bh_account::{
    owner::{AccountCapability, AccountGeneration, AccountLoad, AccountOwner},
    platform::ControlKeyPolicy,
    recovery::Password,
    storage::DeviceJournal,
};
use bh_device::own_base::{OwnBaseError, create_or_open};
use bh_storage::DeviceDatabase;
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
fn activate<S: bh_account::platform::DeviceKeyStore>(
    owner: &mut AccountOwner<DeviceJournal, S, RotatingProtector>,
) -> Arc<AccountCapability> {
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
    fn owner(&self) -> Owner {
        AccountOwner::new(
            DeviceJournal::from_shared(self.db.clone()),
            self.store.clone(),
            self.protector.clone(),
            self.generation.clone(),
        )
    }
    fn signup(
        &self,
    ) -> (
        Owner,
        Arc<AccountCapability>,
        bh_account::owner::SetupStatus,
    ) {
        let mut owner = self.owner();
        let setup = ready(owner.begin_first_device(
            ControlKeyPolicy::AppEnforcedOwnerConfirmation,
            &Password::new("synthetic own base test").unwrap(),
        ))
        .unwrap();
        owner.confirm_kit_saved().unwrap();
        let cap = activate(&mut owner);
        (owner, cap, setup)
    }
    fn raw(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.dir.path().join("account.sqlite")).unwrap()
    }
}

// A real signing backend paused at native I/O, not a mocked base producer.
struct PausedStore {
    inner: FakeStore,
    wait: std::rc::Rc<std::cell::Cell<bool>>,
}
impl bh_account::platform::DeviceKeyStore for PausedStore {
    async fn create(
        &mut self,
        p: ControlKeyPolicy,
    ) -> Result<bh_account::platform::StoredDevice, bh_account::platform::KeyStoreError> {
        self.inner.create(p).await
    }
    async fn load(
        &mut self,
        h: bh_account::platform::KeyHandle,
    ) -> Result<bh_account::platform::StoredDevice, bh_account::platform::KeyStoreError> {
        self.inner.load(h).await
    }
    async fn sign_control(
        &mut self,
        h: bh_account::platform::KeyHandle,
        m: Vec<u8>,
    ) -> Result<[u8; 64], bh_account::platform::KeyStoreError> {
        self.inner.sign_control(h, m).await
    }
    async fn sign_content(
        &mut self,
        h: bh_account::platform::KeyHandle,
        m: Vec<u8>,
    ) -> Result<[u8; 64], bh_account::platform::KeyStoreError> {
        std::future::poll_fn(|_| {
            if self.wait.get() {
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(())
            }
        })
        .await;
        self.inner.sign_content(h, m).await
    }
    async fn decapsulate(
        &mut self,
        h: bh_account::platform::KeyHandle,
        ct: [u8; 1120],
    ) -> Result<bh_crypto::Secret<32>, bh_account::platform::KeyStoreError> {
        self.inner.decapsulate(h, ct).await
    }
}

#[test]
fn concurrent_creation_returns_one_base() {
    let f = Fixture::new();
    let (mut other, other_cap, _) = f.signup();
    let wait = std::rc::Rc::new(std::cell::Cell::new(true));
    let mut owner = AccountOwner::new(
        DeviceJournal::from_shared(f.db.clone()),
        PausedStore {
            inner: f.store.clone(),
            wait: wait.clone(),
        },
        f.protector.clone(),
        f.generation.clone(),
    );
    let cap = activate(&mut owner);
    let mut first = Box::pin(create_or_open(&mut owner, cap, f.db.clone()));
    assert!(
        first
            .as_mut()
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
            .is_pending()
    );
    assert!(
        f.db.try_lock().is_ok(),
        "native signing must not hold the writer"
    );
    let winner = ready(create_or_open(&mut other, other_cap, f.db.clone())).unwrap();
    let original = winner.bootstrap_export(&other).unwrap();
    wait.set(false);
    let loser = ready(first).unwrap();
    assert!(loser.bootstrap_export(&owner).unwrap() == original);
    assert_eq!(
        loser.with_keys(|m, k| (*m.expose(), *k.expose())).unwrap(),
        winner.with_keys(|m, k| (*m.expose(), *k.expose())).unwrap()
    );
    let count: i64 = f
        .raw()
        .query_row("SELECT count(*) FROM own_base", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn control_advancing_during_native_signing_prevents_signup_base_publication() {
    let f = Fixture::new();
    let (mut other, other_cap, _) = f.signup();
    let wait = std::rc::Rc::new(std::cell::Cell::new(true));
    let mut owner = AccountOwner::new(
        DeviceJournal::from_shared(f.db.clone()),
        PausedStore {
            inner: f.store.clone(),
            wait: wait.clone(),
        },
        f.protector.clone(),
        f.generation.clone(),
    );
    let cap = activate(&mut owner);
    let mut creation = Box::pin(create_or_open(&mut owner, cap, f.db.clone()));
    assert!(
        creation
            .as_mut()
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
            .is_pending()
    );
    let keys = bh_account::DevicePublicKeys::new([80; 32], [81; 32], [82; 1216]).unwrap();
    let request = other.prepare_add_device(&other_cap, keys).unwrap();
    let event = ready(other.sign_control(&other_cap, &request)).unwrap();
    other.apply_incoming(&[event.as_bytes()]).unwrap();
    wait.set(false);
    assert!(ready(creation).is_err());
    assert!(f.db.lock().unwrap().own_base().unwrap().is_none());
}

#[test]
fn unregistered_writing_has_no_ordered_head_or_signed_successor() {
    let f = Fixture::new();
    let (mut owner, cap, _) = f.signup();
    let base = ready(create_or_open(&mut owner, cap, f.db.clone())).unwrap();
    let export = base.bootstrap_export(&owner).unwrap();
    let key = bh_storage::NoteKey {
        base: base.id().0,
        audience: [0; 32],
        note: [11; 32],
    };
    let delta = bh_core::note::Note::new().append_paragraph("unregistered local writing");
    let mut db = f.db.lock().unwrap();
    db.apply_local_update(key, [12; 16], &delta).unwrap();
    let pending = db.pending_note_updates().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].bytes, delta);
    let signed: i64 = f
        .raw()
        .query_row("SELECT count(*) FROM note_outbox", [], |r| r.get(0))
        .unwrap();
    assert_eq!(signed, 0);
    assert_eq!(db.own_base().unwrap().unwrap(), export.protected.own_base);
    // The stored bootstrap has originals only, not an invented ordered cut.
    let heads: i64 = f.raw().query_row("SELECT count(*) FROM pragma_table_info('own_base') WHERE name LIKE '%head%' OR name LIKE '%receipt%'", [], |r| r.get(0)).unwrap();
    assert_eq!(heads, 0);
}

#[test]
fn signup_own_base_identity_and_original_bytes_survive_restart() {
    let f = Fixture::new();
    let (mut owner, cap, setup) = f.signup();
    let base = ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).unwrap();
    let export = base.bootstrap_export(&owner).unwrap();
    let roots = base.with_keys(|m, k| (*m.expose(), *k.expose())).unwrap();
    assert_eq!(export.account.events, setup.submission);
    assert_eq!(export.account.head, setup.head);
    assert_eq!(export.protected.own_base.account, setup.anchor.0);
    assert_eq!(export.protected.own_base.base, base.id().0);
    assert_eq!(export.protected.own_base.initial_key_package.len(), 3016);
    owner.confirm_home_ordered(setup.head).unwrap();
    assert!(f.db.lock().unwrap().pending_setup().unwrap().is_none());
    assert!(owner.pending_kit_code().is_err());
    drop(base);
    drop(cap);
    drop(owner);
    // New connection and owner model a fresh process; native key store survives.
    let db = Arc::new(Mutex::new(
        DeviceDatabase::open(f.dir.path().join("account.sqlite")).unwrap(),
    ));
    let mut owner = AccountOwner::new(
        DeviceJournal::from_shared(db.clone()),
        f.store.clone(),
        f.protector.clone(),
        AccountGeneration::new(),
    );
    let cap = activate(&mut owner);
    let base = ready(create_or_open(&mut owner, cap, db)).unwrap();
    assert!(base.bootstrap_export(&owner).unwrap() == export);
    assert_eq!(
        base.with_keys(|m, k| (*m.expose(), *k.expose())).unwrap(),
        roots
    );
}

#[test]
fn kit_saved_before_own_base_crash_retries_without_regenesis() {
    let f = Fixture::new();
    let (owner, _, setup) = f.signup();
    drop(owner);
    let mut owner = f.owner();
    let cap = activate(&mut owner);
    let base = ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).unwrap();
    let first = base.bootstrap_export(&owner).unwrap();
    assert_eq!(first.account.events, setup.submission);
    drop(base);
    drop(owner);
    let mut owner = f.owner();
    let cap = activate(&mut owner);
    f.store.state_mut().advance_generation_on_sign = true; // reopening must not sign again
    let reopened = ready(create_or_open(&mut owner, cap, f.db.clone())).unwrap();
    assert!(reopened.bootstrap_export(&owner).unwrap() == first);
    assert_eq!(f.store.state().create_calls, 1);
}

#[test]
fn stale_generation_cannot_publish_or_use_keys() {
    let f = Fixture::new();
    let (mut owner, cap, _) = f.signup();
    f.store.state_mut().advance_generation_on_sign = true;
    assert!(ready(create_or_open(&mut owner, cap, f.db.clone())).is_err());
    assert!(f.db.lock().unwrap().own_base().unwrap().is_none());
    f.store.state_mut().advance_generation_on_sign = false;
    let cap = activate(&mut owner);
    let base = ready(create_or_open(&mut owner, cap, f.db.clone())).unwrap();
    assert!(matches!(
        base.with_keys(|_, _| {
            f.generation.advance();
        }),
        Err(OwnBaseError::Stale)
    ));
    let mut called = false;
    assert!(
        base.with_keys(|_, _| {
            called = true;
        })
        .is_err()
    );
    assert!(!called);
    assert!(base.bootstrap_export(&owner).is_err());
}

#[test]
fn wrong_recipient_or_key_id_refuses_before_note_authority() {
    let f = Fixture::new();
    let (mut owner, cap, _) = f.signup();
    let base = ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).unwrap();
    let record = base.bootstrap_export(&owner).unwrap().protected.own_base;
    drop(base);
    for offset in [
        14 + 11,
        14 + 75,
        14 + 107,
        14 + 139,
        14 + 211,
        14 + 1387,
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
    f.raw()
        .execute(
            "UPDATE account_events SET bytes=zeroblob(length(bytes)) WHERE id=2",
            [],
        )
        .unwrap();
    assert!(ready(create_or_open(&mut owner, cap, f.db.clone())).is_err());
}

#[test]
fn valid_signed_content_seal_for_another_root_cannot_replace_genesis_key() {
    use bh_device::base_keys::{InitialBaseKeyPackage, SealHeader, prepare_seal};
    let f = Fixture::new();
    let (mut owner, cap, _) = f.signup();
    let base = ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).unwrap();
    let package = base.initial_key_package().unwrap();
    let personal = ready(owner.open_personal(&cap)).unwrap();
    let different = bh_crypto::Secret::random();
    let mut header = SealHeader::decode(package.content_seal()).unwrap();
    header.key_id = bh_event::key_id(&different);
    let request = prepare_seal(
        owner.verified(&cap).unwrap(),
        header,
        &personal.public(),
        &different,
    )
    .unwrap();
    let signature = ready(owner.sign_content(&cap, request.signing_bytes())).unwrap();
    let wrong = request.finish(signature).unwrap();
    let forged = InitialBaseKeyPackage::new(package.metadata_seal(), &wrong).unwrap();
    f.raw()
        .execute(
            "UPDATE own_base SET initial_key_package=?1",
            [forged.as_bytes()],
        )
        .unwrap();
    assert!(matches!(
        ready(create_or_open(&mut owner, cap, f.db.clone())),
        Err(OwnBaseError::Invalid)
    ));
}

#[test]
fn reopen_uses_initial_cut_but_missing_base_after_later_control_never_regenesises() {
    let f = Fixture::new();
    let (mut owner, cap, _) = f.signup();
    let base = ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).unwrap();
    let before = base.bootstrap_export(&owner).unwrap();
    let keys = bh_account::DevicePublicKeys::new([80; 32], [81; 32], [82; 1216]).unwrap();
    let request = owner.prepare_add_device(&cap, keys).unwrap();
    let event = ready(owner.sign_control(&cap, &request)).unwrap();
    owner.apply_incoming(&[event.as_bytes()]).unwrap();
    let reopened = ready(create_or_open(&mut owner, cap.clone(), f.db.clone())).unwrap();
    assert!(reopened.bootstrap_export(&owner).unwrap() == before);
    f.raw().execute("DELETE FROM own_base", []).unwrap();
    assert!(ready(create_or_open(&mut owner, cap, f.db.clone())).is_err());
    assert!(f.db.lock().unwrap().own_base().unwrap().is_none());
}
