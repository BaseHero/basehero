use super::*;
use crate::{
    AccountApplyError, BaseControlRequest, ControlSignError, HomeSetup, Identity, Signer,
    SignerError,
};
use bh_account::{VerifiedAccount, device_auth};
use bh_crypto::Secret;
use bh_sync::BaseId;
use futures_util::future::BoxFuture;
use std::sync::atomic::AtomicUsize;

pub(super) struct Offline {
    pub calls: AtomicUsize,
    pub pause: AtomicBool,
}
impl crate::transport::Connector for Offline {
    fn connect(&self, _: Route) -> BoxFuture<'_, Result<Socket, crate::transport::TransportError>> {
        Box::pin(async {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.pause.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            Err(crate::transport::TransportError)
        })
    }
}
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
pub(super) fn shared(authz: Arc<Authz>) -> (tempfile::TempDir, Arc<Shared>, Arc<Offline>) {
    let authz = Arc::try_unwrap(authz).ok().expect("sole fixture owner");
    let dir = tempfile::tempdir().unwrap();
    let owner = Arc::new(bh_device::Owner::default());
    let container = owner.create_container(dir.path()).unwrap();
    let endpoint = Endpoint {
        edge_url: "http://invalid".into(),
        hosting_root: [0; 32],
        app_root: [0; 32],
        policy: vec![],
        policy_signature: vec![],
        limits: bh_confidential_policy::Limits {
            max_lifetime_secs: 86400,
            max_uncertainty_secs: 0,
        },
        build_floor: 1,
        appraisal: Appraisal::Synthetic,
        device_clock: Arc::new(crate::SystemDeviceClock),
        recovery_key: bh_sync::evidence::certify_recovery_key(
            &bh_crypto::SigningKey::generate(),
            &bh_crypto::KemKey::generate().public(),
        ),
    };
    let home_authz = Authz::new(&endpoint);
    let connector = Arc::new(Offline {
        calls: AtomicUsize::new(0),
        pause: AtomicBool::new(false),
    });
    let shared = Arc::new(Shared {
        endpoint,
        connector: connector.clone(),
        owner,
        container,
        signer: Arc::new(NoSigner),
        authz,
        home_authz,
        wake: watch::Sender::new(0),
        home_wake: tokio::sync::Notify::new(),
        removal_wake: tokio::sync::Notify::new(),
        halt: watch::Sender::new(false),
        status: watch::Sender::new(crate::SyncStatus::WaitingNetwork),
        windows: crate::WindowWakes::default(),
        home_status: watch::Sender::new(crate::HomeStatus::Pending),
        installed: watch::Sender::new(None),
        removal_verdict: watch::Sender::new(crate::RemovalVerdict::Active),
        ordered: watch::Sender::new(None),
        presence: crate::presence::Presence::new(),
        tuning: crate::Tuning::default(),
    });
    (dir, shared, connector)
}
pub(super) async fn pending<F: std::future::Future>(future: std::pin::Pin<&mut F>) {
    assert!(futures_util::poll!(future).is_pending());
}
