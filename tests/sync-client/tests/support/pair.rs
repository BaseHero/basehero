//! A device about to join an account by QR: a fresh container whose own
//! native keys are journaled first (`pairing::scanner_identity`), and the
//! host-side pieces pairing needs from it: its possession proof while it has
//! no account yet, and committing its verified admission.
#![allow(dead_code)]

use super::device::{Account, Device, Seeds, protector, ready, store};
use bh_account::{
    AccountId, DevicePublicKeys, Head as AccountHead,
    device_auth::{Context, Proof},
    journal::AccountJournal,
    owner::{AccountCapability, AccountGeneration, AccountLoad},
    pairing,
    platform::ControlKeyPolicy,
    storage::DeviceJournal,
};
use bh_device::{
    ContainerId, Owner, OwnerError,
    join::{Admission, JoinError},
    own_base::{OwnBaseError, create_or_open},
};
use bh_sync_client::{
    Client, SignerError,
    bootstrap::{self, Progress},
    pairing::{JoinProver, JoiningPairing, ShowingPairing, Side},
};
use futures_util::future::BoxFuture;
use std::sync::{Arc, atomic::Ordering};
use tokio::sync::watch;

pub struct Joiner {
    pub dir: tempfile::TempDir,
    pub owner: Arc<Owner>,
    pub id: ContainerId,
    pub keys: DevicePublicKeys,
    pub generation: AccountGeneration,
    seeds: Seeds,
}

impl Joiner {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(Owner::default());
        let id = owner.create_container(dir.path()).unwrap();
        let db = owner.shared_database(id).unwrap();
        let generation = AccountGeneration::new();
        let store = store::FakeStore::new(generation.clone());
        let identity = ready(pairing::scanner_identity(
            &mut DeviceJournal::from_shared(db),
            &mut store.clone(),
            ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        ))
        .unwrap();
        Self {
            dir,
            owner,
            id,
            keys: identity.keys,
            generation,
            seeds: Seeds::of(&store),
        }
    }

    /// The host's account owner over this container, not activated.
    pub fn account(&self) -> Account {
        Account::new(
            DeviceJournal::from_shared(self.owner.shared_database(self.id).unwrap()),
            self.seeds.store(&self.generation),
            protector::PlainProtector,
            self.generation.clone(),
        )
    }

    /// Its possession proof while it has no account yet, as the host's
    /// native signer makes it.
    pub fn prover(&self) -> Arc<dyn JoinProver> {
        Arc::new(Prover {
            database: self.owner.shared_database(self.id).unwrap(),
            seeds: self.seeds.clone(),
            generation: self.generation.clone(),
        })
    }

    /// Commit a verified admission, as the host does once pairing returns it.
    pub async fn admit(&self, admission: &Admission) {
        self.try_admit(admission).await.unwrap();
    }
    pub async fn try_admit(&self, admission: &Admission) -> Result<(), JoinError> {
        let mut account = self.account();
        bh_device::join::admit(&mut account, &self.owner, self.id, admission)
            .await
            .map(drop)
    }
    /// The account owner activated over the committed account history.
    fn active(&self) -> (Account, Arc<AccountCapability>) {
        let mut account = self.account();
        match ready(account.activate()) {
            Ok(AccountLoad::Active(cap)) => (account, Arc::new(cap)),
            _ => panic!("joined account not active"),
        }
    }
    /// Install note authority for `base`, as the host does on open.
    pub fn authorize(&self, base: [u8; 32]) -> Result<(), OwnerError> {
        let (_, cap) = self.active();
        self.owner.authorize(self.id, cap, base)
    }
    /// Open the own base as the host does on open; a joined container never
    /// creates one.
    pub fn open_own_base(&self) -> Result<(), OwnBaseError> {
        let (mut account, cap) = self.active();
        let database = self.owner.shared_database(self.id).unwrap();
        ready(create_or_open(&mut account, cap, database)).map(drop)
    }

    pub fn has_account(&self) -> bool {
        DeviceJournal::from_shared(self.owner.shared_database(self.id).unwrap())
            .has_account()
            .unwrap()
    }
    pub fn has_own_base(&self) -> bool {
        let db = self.owner.shared_database(self.id).unwrap();
        db.lock().unwrap().own_base().unwrap().is_some()
    }

    /// The joined device, with a signer as its host builds it after admission.
    pub fn into_device(self) -> Device {
        Device::joined(self.dir, self.owner, self.id, self.generation, self.seeds)
    }
}

/// Pair a new device to `mac` through the real QR flow, end to end, and
/// commit its verified admission. Returns the joined device (not started and
/// not yet bootstrapped) and the ordered addition's head.
pub async fn paired(
    hosted: &Arc<super::fake::Hosted>,
    mac: &Device,
    mac_client: &Client,
) -> (Device, AccountHead) {
    // The base copies controls only under the approval the person gives.
    mac.signer.approve_controls.store(false, Ordering::SeqCst);
    let (mut showing, qr) = ShowingPairing::start(
        mac.signer.identity_account(),
        mac.signer.device_id(),
        hosted.relay(),
    );
    let joiner = Joiner::new();
    let mut joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    // The relay holds sealed bytes only: neither the joining device's keys
    // nor its label.
    for held in hosted.relay_held(Side::Join) {
        let contains = |part: &[u8]| held.windows(part.len()).any(|w| w == part);
        assert!(!contains(joiner.keys.signing()) && !contains(b"Fold"));
    }
    let candidate = showing.candidate().await.unwrap();
    assert_eq!(candidate.keys, joiner.keys);
    assert_eq!(candidate.label, b"Fold");
    {
        let (mut account, capability, _) = mac.signer.account_owner();
        let personal = account.open_personal(&capability).await.unwrap();
        showing
            .stage(&mut account, &capability, &personal, &mac.signer.approvals)
            .await
            .unwrap();
    }
    let endpoint = mac.endpoint(hosted);
    let (head, admission) = tokio::join!(
        showing.finish(mac_client),
        joining.wait_admitted(
            &endpoint,
            hosted.connector(),
            joiner.owner.clone(),
            joiner.id,
            joiner.prover(),
        )
    );
    let head = head.unwrap();
    let admission = admission.unwrap();
    joiner.admit(&admission).await;
    (joiner.into_device(), head)
}

/// Bootstrap a joined device to the base's tail through the receiver.
pub async fn bootstrapped(hosted: &Arc<super::fake::Hosted>, fold: &Device) {
    let (progress, _) = watch::channel(Progress::default());
    bootstrap::run(
        fold.endpoint(hosted),
        hosted.connector(),
        fold.owner.clone(),
        fold.id,
        fold.signer.clone(),
        progress,
    )
    .await
    .unwrap();
}

struct Prover {
    database: Arc<std::sync::Mutex<bh_storage::DeviceDatabase>>,
    seeds: Seeds,
    generation: AccountGeneration,
}
impl JoinProver for Prover {
    fn joining_proof(
        &self,
        account: AccountId,
        head: AccountHead,
        context: Context,
    ) -> BoxFuture<'_, Result<Proof, SignerError>> {
        // The test key store is not Send: the work is done before the future.
        let mut owner = Account::new(
            DeviceJournal::from_shared(self.database.clone()),
            self.seeds.store(&self.generation),
            protector::PlainProtector,
            self.generation.clone(),
        );
        let result = ready(owner.prove_joining(account, head, context)).map_err(|_| SignerError);
        Box::pin(async move { result })
    }
}
