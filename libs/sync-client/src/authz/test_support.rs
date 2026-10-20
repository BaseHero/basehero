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
    fn confirm_home_ordered(&self, _: &HomeSetup) -> Result<(), SignerError> {
        panic!("unexpected signer call")
    }
    fn sign_event(&self, _: Vec<u8>) -> BoxFuture<'_, Result<[u8; 64], SignerError>> {
        panic!("unexpected signer call")
    }
    fn current_account(&self) -> Result<VerifiedAccount, SignerError> {
        panic!("unexpected signer call")
    }
    fn apply_account(
        &self,
        _: AccountHead,
        _: Vec<Vec<u8>>,
    ) -> BoxFuture<'_, Result<AccountHead, AccountApplyError>> {
        panic!("unexpected signer call")
    }
    fn sign_base_control(
        &self,
        _: BaseControlRequest,
    ) -> BoxFuture<'_, Result<[u8; 64], ControlSignError>> {
        panic!("unexpected signer call")
    }
    fn with_base_keys(
        &self,
        _: BaseId,
        _: &mut dyn FnMut(&Secret<32>, &Secret<32>),
    ) -> Result<(), SignerError> {
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
        halt: watch::Sender::new(false),
        status: watch::Sender::new(crate::SyncStatus::WaitingNetwork),
        windows: crate::WindowWakes::default(),
        home_status: watch::Sender::new(crate::HomeStatus::Pending),
        presence: crate::presence::Presence::new(),
        tuning: crate::Tuning::default(),
    });
    (dir, shared, connector)
}
pub(super) async fn pending<F: std::future::Future>(future: std::pin::Pin<&mut F>) {
    assert!(futures_util::poll!(future).is_pending());
}
