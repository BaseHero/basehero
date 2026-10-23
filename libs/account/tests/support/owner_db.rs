//! An account owner over the real device database in a temporary directory,
//! with a fake native store, and other devices held as plain test keys.
// Shared by independent test binaries, so not every helper is used by each.
#![allow(dead_code)]
use std::future::Future;
use std::sync::{Arc, Mutex};

use bh_account::crypto::{KemKey, SigningKey};
use bh_account::owner::{AccountCapability, AccountGeneration, AccountLoad};
use bh_account::platform::ControlKeyPolicy;
use bh_account::recovery::Password;
use bh_account::storage::DeviceJournal;
use bh_account::{AccountEvent, ConfirmedTime, DeviceId, DevicePublicKeys, SigningRequest};
use bh_storage::DeviceDatabase;

use crate::protector::PlainProtector;
use crate::store::FakeStore;

pub type Owner = bh_account::owner::AccountOwner<DeviceJournal, FakeStore, PlainProtector>;

pub fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => panic!("unexpectedly pending"),
    }
}

/// Confirmed bounds with stand-in proof bytes: the owner stores, never
/// checks, the proof.
pub fn at(earliest_ms: u64, latest_ms: u64) -> Option<(ConfirmedTime, Vec<u8>)> {
    Some((
        ConfirmedTime {
            earliest_ms,
            latest_ms,
        },
        vec![1],
    ))
}

/// Another device of the account, as plain keys this test holds.
pub struct Other {
    pub ordinary: SigningKey,
    pub control: SigningKey,
    pub receiver: KemKey,
    pub public: DevicePublicKeys,
}
impl Other {
    pub fn new() -> Self {
        let ordinary = SigningKey::generate();
        let control = SigningKey::generate();
        let receiver = KemKey::generate();
        let public =
            DevicePublicKeys::new(ordinary.public(), control.public(), receiver.public()).unwrap();
        Self {
            ordinary,
            control,
            receiver,
            public,
        }
    }
    pub fn id(&self) -> DeviceId {
        self.public.id()
    }
    pub fn sign_control(&self, request: SigningRequest) -> AccountEvent {
        request
            .finish(self.control.sign(request.signing_bytes()))
            .unwrap()
    }
    pub fn sign_ordinary(&self, request: SigningRequest) -> AccountEvent {
        request
            .finish(self.ordinary.sign(request.signing_bytes()))
            .unwrap()
    }
}

pub struct Harness {
    pub dir: tempfile::TempDir,
    pub db: Arc<Mutex<DeviceDatabase>>,
    pub generation: AccountGeneration,
    pub store: FakeStore,
}
impl Harness {
    pub fn new() -> Self {
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
        }
    }
    pub fn owner(&self) -> Owner {
        bh_account::owner::AccountOwner::new(
            DeviceJournal::from_shared(self.db.clone()),
            self.store.clone(),
            PlainProtector,
            self.generation.clone(),
        )
    }
    /// A first device whose setup the home ordered untimed, as a legacy home.
    pub fn signup(&self) -> (Owner, AccountCapability) {
        let mut owner = self.owner();
        let setup = ready(owner.begin_first_device(
            ControlKeyPolicy::AppEnforcedOwnerConfirmation,
            &Password::new("synthetic staging test").unwrap(),
        ))
        .unwrap();
        owner.confirm_kit_saved().unwrap();
        owner.confirm_home_ordered(setup.head, None).unwrap();
        let cap = activate(&mut owner);
        (owner, cap)
    }
    /// A fresh process over the same file and native store.
    pub fn restart(&mut self) -> (Owner, AccountCapability) {
        self.db = Arc::new(Mutex::new(
            DeviceDatabase::open(self.dir.path().join("account.sqlite")).unwrap(),
        ));
        self.generation = AccountGeneration::new();
        let mut owner = self.owner();
        let cap = activate(&mut owner);
        (owner, cap)
    }
    pub fn journal(&self) -> DeviceJournal {
        DeviceJournal::from_shared(self.db.clone())
    }
}

pub fn activate(owner: &mut Owner) -> AccountCapability {
    match ready(owner.activate()).unwrap() {
        AccountLoad::Active(cap) => cap,
        other => panic!("not active: {other:?}"),
    }
}

/// This device adds `other`, confirmed at `ms`.
pub fn add(owner: &mut Owner, cap: &AccountCapability, other: &Other, ms: u64) -> u64 {
    let request = owner.prepare_add_device(cap, other.public.clone()).unwrap();
    let event = ready(owner.sign_control(cap, &request)).unwrap();
    apply(owner, &event, ms)
}

/// Order `event` next, confirmed at exactly `ms`; returns its position.
pub fn apply(owner: &mut Owner, event: &AccountEvent, ms: u64) -> u64 {
    apply_at(owner, event.as_bytes(), ms, ms)
}

pub fn apply_at(owner: &mut Owner, bytes: &[u8], earliest_ms: u64, latest_ms: u64) -> u64 {
    owner
        .apply_incoming_timed(&[(bytes, at(earliest_ms, latest_ms))])
        .unwrap()
        .position
}
