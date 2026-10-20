//! Native sync for each ready account: its client, the client's signer over
//! the account's one native owner, and what its windows are told.
//!
//! The signer holds no owner of its own. Each use borrows the account's one
//! `AccountOwner` from the account registry (`SharedAccountHost::run_lent`)
//! on a native worker, or uses it briefly under the registry lock, and
//! returns it; a prompt on one account never holds the registry or another
//! account. The base roots stay in the account's own base, used in place.
use crate::{
    accounts::{HostKeyStore, Owner, SharedAccountHost},
    confirm::{ActionGate, LIFE},
};
use bh_account::{
    AccountId, DeviceId, Error as HistoryError, Head as AccountHead, VerifiedAccount,
    device_auth::{Context, Proof},
    journal::{AccountJournal, HistoryCursor, PendingSetupProtector, StagedAdmission},
    owner::{AccountCapability, AccountGeneration, OwnerError, SetupError},
    platform::KeyStoreError,
    storage::DeviceJournal,
};
use bh_crypto::Secret;
use bh_device::{ContainerId, own_base::OwnBase};
use bh_sync::BaseId;
use bh_sync_client::{
    AccountApplyError, BaseControlRequest, Client, ControlSignError, Endpoint, HomeRetryReason,
    HomeSetup, HomeStatus, Identity, Signer, SignerError, SyncStatus,
    pairing::{Approvals, HttpRelay, Relay},
    transport::{Connector, WsConnector},
};
pub use bh_sync_client::{Presence, RemotePresence, RemoteState};
use futures_util::future::BoxFuture;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};
use tokio::sync::watch;

/// The account as the signer last saw it, for the host and its windows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccountState {
    #[default]
    Active,
    /// Authenticated history contradicts this device's: stopped for good.
    Stopped,
    /// Verified history removed this device: its authority has ended.
    Removed,
}

/// What the signer tells the host. No content, ids or keys.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Notice {
    pub account: AccountState,
    /// A base copy of an account change waits for the person's confirmation.
    pub confirm: bool,
}

/// The client's signer for one ready account.
pub struct HostSigner<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    accounts: SharedAccountHost<S, P>,
    id: ContainerId,
    capability: Arc<AccountCapability>,
    generation: AccountGeneration,
    own_base: Arc<OwnBase>,
    database: Arc<Mutex<bh_storage::DeviceDatabase>>,
    account: AccountId,
    device: DeviceId,
    genesis: Vec<u8>,
    anchor: VerifiedAccount,
    control_key: [u8; 32],
    /// The account at its verified head, published by the owner after each
    /// commit this signer made. Read-only; never written elsewhere.
    current: RwLock<VerifiedAccount>,
    home: Mutex<Option<HomeSetup>>,
    approvals: Approvals,
    gate: Option<ActionGate>,
    store: S,
    /// The exact account event whose base copy waits for the person.
    waiting_copy: Mutex<Option<Vec<u8>>>,
    notices: watch::Sender<Notice>,
}

fn copy_setup(setup: &HomeSetup) -> HomeSetup {
    HomeSetup {
        prefix: setup.prefix.clone(),
        objects: setup.objects.clone(),
        generation: setup.generation,
    }
}

/// A device's retained signup for its account home, read exactly as kept.
/// `None` only for a device that is not active in the account's original
/// three-event prefix (one added later), found by a bounded read of that
/// prefix. A first device whose record is missing or fails is an error.
pub fn retained_home_setup<S, P>(
    owner: &Owner<S, P>,
    capability: &AccountCapability,
    journal: &DeviceJournal,
    generation: &AccountGeneration,
) -> Result<Option<HomeSetup>, SignerError>
where
    S: bh_account::platform::DeviceKeyStore,
    P: PendingSetupProtector,
{
    if !capability.is_current() {
        return Err(SignerError);
    }
    if journal
        .initial_bootstrap()
        .map_err(|_| SignerError)?
        .is_none()
    {
        let head = owner.verified(capability).map_err(|_| SignerError)?.head();
        let page = journal
            .history_prefix(
                Some(HistoryCursor {
                    anchor: capability.account_id(),
                    cut: head,
                    next_position: 1,
                }),
                3,
            )
            .map_err(|_| SignerError)?
            .ok_or(SignerError)?;
        let (genesis, rest) = page.events.split_first().ok_or(SignerError)?;
        let mut prefix = VerifiedAccount::from_genesis(capability.account_id(), genesis)
            .map_err(|_| SignerError)?;
        for event in rest.iter().take(2) {
            prefix.apply(event).map_err(|_| SignerError)?;
        }
        return if prefix.active_device(capability.device_id()).is_ok() {
            Err(SignerError)
        } else {
            Ok(None)
        };
    }
    let read_at = generation.current();
    let (prefix, objects) = owner
        .initial_bootstrap(capability)
        .map_err(|_| SignerError)?;
    if !capability.is_current() || generation.current() != read_at {
        return Err(SignerError);
    }
    Ok(Some(HomeSetup {
        prefix,
        objects,
        generation: read_at,
    }))
}

impl<S, P> HostSigner<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    /// The signer of ready account `id`, read from its owner under the
    /// registry lock. Settles a staged addition that verified history
    /// already resolved.
    pub async fn start(
        accounts: SharedAccountHost<S, P>,
        id: ContainerId,
    ) -> Result<Arc<Self>, SignerError> {
        let ready = accounts.ready_parts(id).ok_or(SignerError)?;
        let capability = ready.capability;
        let own_base = ready.own_base;
        let package_head = own_base
            .initial_key_package()
            .ok()
            .and_then(|package| {
                bh_device::base_keys::SealHeader::decode(package.metadata_seal()).ok()
            })
            .ok_or(SignerError)?
            .head;
        let journal = DeviceJournal::from_shared(ready.database.clone());
        let generation = ready.generation.clone();
        let read = generation.clone();
        // Read with the account's one owner, waiting for it like every
        // other use: never from a second owner, never failing on a busy one.
        let (genesis, anchor, current, home) = accounts
            .run_lent(id, &capability, move |owner, capability| {
                Box::pin(async move {
                    let current = owner.verified(&capability).ok()?.clone();
                    let anchor = owner.verified_at(&capability, package_head.position).ok()?;
                    if anchor.head() != package_head {
                        return None;
                    }
                    let genesis = journal
                        .history_prefix(
                            Some(HistoryCursor {
                                anchor: current.id(),
                                cut: current.head(),
                                next_position: 1,
                            }),
                            1,
                        )
                        .ok()??
                        .events
                        .into_iter()
                        .next()?;
                    if owner.staged_admission().is_ok_and(|row| row.is_some()) {
                        let _ = owner.reconcile_staged_admission(None);
                    }
                    let home = retained_home_setup(owner, &capability, &journal, &read).ok();
                    Some((genesis, anchor, current, home))
                })
            })
            .await
            .ok()
            .flatten()
            .ok_or(SignerError)?;
        let control_key = *current
            .active_device(capability.device_id())
            .map_err(|_| SignerError)?
            .control();
        let (notices, _) = watch::channel(Notice::default());
        Ok(Arc::new(Self {
            id,
            account: capability.account_id(),
            device: capability.device_id(),
            capability,
            generation,
            own_base,
            database: ready.database,
            genesis,
            anchor,
            control_key,
            current: RwLock::new(current),
            home: Mutex::new(home.flatten()),
            approvals: Approvals::default(),
            gate: ready.store.action_gate(),
            store: ready.store,
            waiting_copy: Mutex::new(None),
            notices,
            accounts,
        }))
    }

    pub fn notices(&self) -> watch::Receiver<Notice> {
        self.notices.subscribe()
    }
    #[cfg(test)]
    pub fn approvals(&self) -> &Approvals {
        &self.approvals
    }
    #[cfg(test)]
    pub fn base(&self) -> BaseId {
        self.own_base.id()
    }
    #[cfg(test)]
    pub fn control_key(&self) -> [u8; 32] {
        self.control_key
    }

    fn current(&self) -> Result<(), SignerError> {
        self.capability
            .is_current()
            .then_some(())
            .ok_or(SignerError)
    }
    fn set_account(&self, state: AccountState) {
        self.notices.send_modify(|notice| notice.account = state);
    }
    fn wait_for_person(&self, copies: Vec<u8>) {
        *self.waiting_copy.lock().expect("waiting copy") = Some(copies);
        self.notices.send_modify(|notice| notice.confirm = true);
    }

    /// The person is approving a device addition now: on a store whose
    /// gate the app enforces, its confirmation will also cover the copy.
    pub fn open_pairing_action(&self) {
        if let Some(gate) = &self.gate
            && self.capability.is_current()
        {
            gate.open(self.control_key, self.account, self.generation.current());
        }
    }
    /// The approval did not stage (cancelled, expired or failed).
    pub fn end_pairing_action(&self) {
        if let Some(gate) = &self.gate {
            gate.revoke(self.control_key);
        }
    }
    /// The armed copy `message` was not signed: its grant, if still there,
    /// ends, and nobody else's.
    fn withdraw(&self, message: &[u8]) {
        if let Some(gate) = &self.gate {
            gate.disarm(self.control_key, message);
        }
    }

    /// The person asked to finish the base copy that waits for them, after
    /// its earlier approval was lost (a restart or expiry). One fresh owner
    /// confirmation covers exactly that copy, once.
    pub async fn reconfirm(&self) -> Result<(), SignerError> {
        self.current()?;
        let copies = self
            .waiting_copy
            .lock()
            .expect("waiting copy")
            .clone()
            .ok_or(SignerError)?;
        if let Some(gate) = self.gate.clone() {
            let (key, account, generation) =
                (self.control_key, self.account, self.generation.current());
            let mut store = self.store.clone();
            let event = copies.clone();
            tokio::task::spawn_blocking(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| SignerError)?;
                runtime
                    .block_on(gate.reconfirm(
                        key,
                        account,
                        generation,
                        &event,
                        store.confirm_owner(),
                    ))
                    .map_err(|_| SignerError)
            })
            .await
            .map_err(|_| SignerError)??;
        }
        self.current()?;
        self.approvals
            .grant(copies, tokio::time::Instant::now() + LIFE);
        Ok(())
    }

    fn proof(
        &self,
        head: Option<AccountHead>,
        context: Context,
    ) -> BoxFuture<'_, Result<Proof, SignerError>> {
        Box::pin(async move {
            self.accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(async move {
                        match head {
                            None => owner.prove_sync_device(&cap, context).await,
                            Some(head) => {
                                if owner.verified_at(&cap, head.position)?.head() != head {
                                    return Err(OwnerError::Invalid(
                                        HistoryError::InvalidCredentials,
                                    ));
                                }
                                owner
                                    .prove_sync_device_at(&cap, head.position, context)
                                    .await
                            }
                        }
                    })
                })
                .await
                .map_err(|_| SignerError)?
                .map_err(|_| SignerError)
        })
    }
}

/// How an account owner judged incoming history, for the client. A failed
/// write of a stop the live owner latched is still a stop.
fn judged<S, P>(
    owner: &Owner<S, P>,
    capability: &AccountCapability,
    error: OwnerError,
) -> AccountApplyError
where
    S: bh_account::platform::DeviceKeyStore,
    P: PendingSetupProtector,
{
    match error {
        OwnerError::Refused(_) => AccountApplyError::Refused,
        OwnerError::Unsupported(_) => AccountApplyError::Unsupported,
        OwnerError::Invalid(HistoryError::Unavailable) => AccountApplyError::Unavailable,
        OwnerError::Invalid(_) | OwnerError::Stopped => AccountApplyError::Stopped,
        _ if matches!(owner.verified(capability), Err(OwnerError::Stopped)) => {
            AccountApplyError::Stopped
        }
        _ => AccountApplyError::Unavailable,
    }
}

impl<S, P> Signer for HostSigner<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    fn identity(&self) -> Result<Identity, SignerError> {
        Ok(Identity {
            account: self.account,
            device: self.device,
            genesis: self.genesis.clone(),
            anchor: self.anchor.clone(),
        })
    }
    fn device_proof(&self, context: Context) -> BoxFuture<'_, Result<Proof, SignerError>> {
        self.proof(None, context)
    }
    fn device_proof_at(
        &self,
        head: AccountHead,
        context: Context,
    ) -> BoxFuture<'_, Result<Proof, SignerError>> {
        self.proof(Some(head), context)
    }
    fn initial_home_setup(&self) -> Result<Option<HomeSetup>, SignerError> {
        self.current()?;
        if let Some(setup) = self.home.lock().expect("home setup").as_ref()
            && setup.generation == self.generation.current()
        {
            return Ok(Some(copy_setup(setup)));
        }
        let journal = DeviceJournal::from_shared(self.database.clone());
        let setup = self
            .accounts
            .with_owner(self.id, &self.capability, |owner| {
                retained_home_setup(owner, &self.capability, &journal, &self.generation)
            })
            .ok_or(SignerError)??;
        *self.home.lock().expect("home setup") = setup.as_ref().map(copy_setup);
        Ok(setup)
    }
    fn confirm_home_ordered(&self, setup: &HomeSetup) -> Result<(), SignerError> {
        // Under the registry lock: nothing locks, stops or lends the owner
        // between this check and the commit.
        self.accounts
            .with_owner(self.id, &self.capability, |owner| {
                if !self.capability.is_current()
                    || self.generation.current() != setup.generation
                    || self.capability.account_id() != setup.prefix.anchor
                {
                    return Err(SignerError);
                }
                match owner.confirm_home_ordered(setup.prefix.head) {
                    // Already cleared: the client calls this only after the
                    // home's exact answer for these retained bytes.
                    Ok(()) | Err(SetupError::NotStarted) => Ok(()),
                    Err(_) => Err(SignerError),
                }
            })
            .ok_or(SignerError)?
    }
    fn sign_event(&self, message: Vec<u8>) -> BoxFuture<'_, Result<[u8; 64], SignerError>> {
        Box::pin(async move {
            self.accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(async move { owner.sign_content(&cap, &message).await })
                })
                .await
                .map_err(|_| SignerError)?
                .map_err(|_| SignerError)
        })
    }
    fn current_account(&self) -> Result<VerifiedAccount, SignerError> {
        self.current()?;
        Ok(self.current.read().expect("current account").clone())
    }
    fn apply_account(
        &self,
        after: AccountHead,
        originals: Vec<Vec<u8>>,
    ) -> BoxFuture<'_, Result<AccountHead, AccountApplyError>> {
        Box::pin(async move {
            let lent = self
                .accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(async move {
                        match owner.verified(&cap).map(VerifiedAccount::head) {
                            Ok(head) if head == after => {}
                            Ok(_) => return Err(AccountApplyError::Unavailable),
                            Err(error) => return Err(judged(owner, &cap, error)),
                        }
                        let refs: Vec<&[u8]> = originals.iter().map(Vec::as_slice).collect();
                        let head = owner
                            .apply_incoming(&refs)
                            .map_err(|error| judged(owner, &cap, error))?;
                        // A staged addition this history resolved is settled
                        // now; one still ahead stays as it is.
                        if owner.staged_admission().is_ok_and(|row| row.is_some()) {
                            let _ = owner.reconcile_staged_admission(None);
                        }
                        Ok((head, owner.verified(&cap).ok().cloned()))
                    })
                })
                .await;
            match lent {
                Ok(Ok((head, current))) => {
                    match current {
                        Some(current) => *self.current.write().expect("current account") = current,
                        None => self.set_account(AccountState::Removed),
                    }
                    Ok(head)
                }
                Ok(Err(AccountApplyError::Stopped)) => {
                    self.set_account(AccountState::Stopped);
                    Err(AccountApplyError::Stopped)
                }
                Ok(Err(error)) => Err(error),
                Err(_) => Err(AccountApplyError::Unavailable),
            }
        })
    }
    fn sign_base_control(
        &self,
        request: BaseControlRequest,
    ) -> BoxFuture<'_, Result<[u8; 64], ControlSignError>> {
        Box::pin(async move {
            if !self.capability.is_current() {
                return Err(ControlSignError::Unavailable);
            }
            // Only an action the person approved; never a prompt from here.
            if !self.approvals.take(&request.copies) {
                self.wait_for_person(request.copies);
                return Err(ControlSignError::ConfirmationNeeded);
            }
            if let Some(gate) = &self.gate
                && !gate.arm(
                    self.control_key,
                    self.account,
                    self.generation.current(),
                    &request.copies,
                    &request.message,
                )
            {
                self.wait_for_person(request.copies);
                return Err(ControlSignError::ConfirmationNeeded);
            }
            let BaseControlRequest {
                expected_key,
                message,
                copies,
            } = request;
            let armed = message.clone();
            let signed = self
                .accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(
                        async move { owner.sign_base_control(&cap, &expected_key, &message).await },
                    )
                })
                .await;
            match signed {
                Ok(Ok(signature)) => {
                    *self.waiting_copy.lock().expect("waiting copy") = None;
                    self.notices.send_modify(|notice| notice.confirm = false);
                    Ok(signature)
                }
                // Its grant ended before the owner signed it (another gate
                // use came between): the copy waits for the person.
                Ok(Err(OwnerError::Device(KeyStoreError::Unavailable)))
                    if self.gate.is_some() && self.current().is_ok() =>
                {
                    self.withdraw(&armed);
                    self.wait_for_person(copies);
                    Err(ControlSignError::ConfirmationNeeded)
                }
                _ => {
                    self.withdraw(&armed);
                    Err(ControlSignError::Unavailable)
                }
            }
        })
    }
    fn staged_addition(&self) -> Result<Option<StagedAdmission>, SignerError> {
        self.current()?;
        DeviceJournal::from_shared(self.database.clone())
            .staged_admission()
            .map_err(|_| SignerError)
    }
    fn with_base_keys(
        &self,
        base: BaseId,
        use_keys: &mut dyn FnMut(&Secret<32>, &Secret<32>),
    ) -> Result<(), SignerError> {
        if base != self.own_base.id() {
            return Err(SignerError);
        }
        // No lock of ours is held: the closure takes the Owner's own.
        self.own_base
            .with_keys(|metadata, content| use_keys(metadata, content))
            .map_err(|_| SignerError)
    }
}

// ---- One client per ready account, and what its windows are told ----

/// The build's sync endpoint (`crate::endpoint_config`).
#[derive(Clone)]
pub enum Configured {
    /// No endpoint in this build: notes stay on this device.
    Missing,
    /// An endpoint this build cannot use: sync never starts.
    Invalid,
    Ready(Endpoint),
}

impl Configured {
    /// The endpoint an app build carries, from its checked endpoint file
    /// (`crate::endpoint`). Synthetic appraisal only with this crate's
    /// `synthetic-attestation` feature.
    pub fn from_text(text: &str) -> Self {
        let synthetic = cfg!(feature = "synthetic-attestation");
        match crate::endpoint::parse(text, synthetic) {
            Ok(None) => Self::Missing,
            Err(_) => Self::Invalid,
            Ok(Some(fields)) => {
                let appraisal = if fields.synthetic {
                    #[cfg(feature = "synthetic-attestation")]
                    {
                        bh_sync_client::Appraisal::Synthetic
                    }
                    #[cfg(not(feature = "synthetic-attestation"))]
                    {
                        return Self::Invalid;
                    }
                } else {
                    bh_sync_client::Appraisal::Hardware
                };
                Self::Ready(Endpoint {
                    edge_url: fields.edge_url,
                    hosting_root: fields.hosting_root,
                    app_root: fields.app_root,
                    policy: fields.policy,
                    policy_signature: fields.policy_signature,
                    limits: bh_confidential_policy::Limits {
                        max_lifetime_secs: fields.max_lifetime_secs,
                        max_uncertainty_secs: fields.max_uncertainty_secs,
                    },
                    build_floor: fields.build_floor,
                    appraisal,
                })
            }
        }
    }
}

/// The `sync://status` message: counts and fixed reasons only, never
/// content, ids or keys. Local saving is acknowledged by the editor
/// separately; this is the network's view.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusView {
    /// The host's publication order, set when it publishes (0 before): a
    /// newer status always has a larger revision, so a page keeps the newest
    /// whether it was pushed or asked for.
    pub revision: u64,
    pub state: &'static str,
    /// Local updates not yet accepted from their verified echo.
    pub pending: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<u64>,
    /// "on", or "off" for a build without an endpoint, or "unsupported".
    pub network: &'static str,
    /// The first device's account-home setup, on its own: "pending",
    /// "retrying", "done" or "not-needed".
    pub home: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_reason: Option<&'static str>,
    /// "active", "stopped" or "removed".
    pub account: &'static str,
    /// A base copy of an account change waits for the person to confirm.
    pub confirm: bool,
}

pub fn state_name(status: SyncStatus) -> &'static str {
    match status {
        SyncStatus::SavedLocal { .. } => "saved-local",
        SyncStatus::Syncing { .. } => "syncing",
        SyncStatus::Synced => "synced",
        SyncStatus::UpdateNeeded => "update-needed",
        SyncStatus::WaitingNetwork => "waiting-network",
        SyncStatus::WaitingAuthorization => "waiting-authorization",
        SyncStatus::HistoryMissing => "history-missing",
        SyncStatus::Unsupported => "unsupported",
        SyncStatus::Stopped => "stopped",
        SyncStatus::PublishingStopped => "publishing-stopped",
        SyncStatus::NotAccepted { .. } => "not-accepted",
        SyncStatus::ControlNotAccepted => "control-not-accepted",
    }
}

impl StatusView {
    pub fn of(
        status: Option<SyncStatus>,
        home: Option<HomeStatus>,
        notice: Notice,
        pending: u64,
    ) -> Self {
        let (home, home_reason) = match home {
            None => (None, None),
            Some(HomeStatus::Pending) => (Some("pending"), None),
            Some(HomeStatus::Done) => (Some("done"), None),
            Some(HomeStatus::NotNeeded) => (Some("not-needed"), None),
            Some(HomeStatus::Retrying(reason)) => (
                Some("retrying"),
                Some(match reason {
                    HomeRetryReason::Unavailable => "unavailable",
                    HomeRetryReason::Refused => "refused",
                    HomeRetryReason::SetupNotReady => "setup-not-ready",
                    HomeRetryReason::Other => "other",
                }),
            ),
        };
        let account = match notice.account {
            AccountState::Active => "active",
            AccountState::Stopped => "stopped",
            AccountState::Removed => "removed",
        };
        let status = status.unwrap_or(SyncStatus::SavedLocal { pending });
        let state = match notice.account {
            AccountState::Stopped => "stopped",
            _ => state_name(status),
        };
        Self {
            revision: 0,
            state,
            pending,
            notes: match status {
                SyncStatus::NotAccepted { notes } => Some(notes),
                _ => None,
            },
            network: "on",
            home,
            home_reason,
            account,
            confirm: notice.confirm,
        }
    }
    fn local(pending: u64, network: &'static str) -> Self {
        Self {
            state: if network == "unsupported" {
                "unsupported"
            } else {
                "saved-local"
            },
            network,
            ..Self::of(None, None, Notice::default(), pending)
        }
    }
}

/// The windows of the app, as the sync host reaches them.
pub trait StatusWindows: Send + Sync + 'static {
    /// Tell every window now bound to `container` (and only those, each on
    /// its current page) the account's status.
    fn post_status(&self, container: ContainerId, view: &StatusView);
    /// Remote changes committed for `window`: run the note delivery.
    fn wake_delivery(&self, window: String);
    /// The account's authority ended (removed or stopped) and `windows`
    /// lost their routes: they reload into the account's own screen.
    fn authority_ended(&self, container: ContainerId, windows: Vec<String>);
}

/// What pairing needs from a ready account's signer, without its types.
pub trait AccountOps: Send + Sync {
    fn account(&self) -> AccountId;
    fn device(&self) -> DeviceId;
    fn is_current(&self) -> bool;
    /// Stage a pairing approval with the account's lent owner (its one
    /// confirmation), granting the copy approval. `None` if the owner
    /// could not be lent, which ends the session.
    fn stage(
        &self,
        showing: bh_sync_client::pairing::ShowingPairing,
    ) -> BoxFuture<
        '_,
        (
            Option<bh_sync_client::pairing::ShowingPairing>,
            Result<(), bh_sync_client::pairing::PairingError>,
        ),
    >;
    /// The person asked to finish a copy that waits for them.
    fn reconfirm(&self) -> BoxFuture<'_, Result<(), SignerError>>;
}

impl<S, P> AccountOps for HostSigner<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    fn account(&self) -> AccountId {
        self.account
    }
    fn device(&self) -> DeviceId {
        self.device
    }
    fn is_current(&self) -> bool {
        self.capability.is_current()
    }
    fn stage(
        &self,
        mut showing: bh_sync_client::pairing::ShowingPairing,
    ) -> BoxFuture<
        '_,
        (
            Option<bh_sync_client::pairing::ShowingPairing>,
            Result<(), bh_sync_client::pairing::PairingError>,
        ),
    > {
        use bh_sync_client::pairing::PairingError;
        Box::pin(async move {
            let first_device = DeviceJournal::from_shared(self.database.clone())
                .initial_bootstrap()
                .is_ok_and(|row| row.is_some());
            let joined = self
                .database
                .lock()
                .expect("container writer lock")
                .joined()
                .ok()
                .flatten();
            let approvals = self.approvals.clone();
            self.open_pairing_action();
            let staged = self
                .accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(async move {
                        let personal = match (first_device, joined) {
                            (true, _) => owner.open_personal(&cap).await,
                            (false, Some(joined)) => match (joined.delivery, joined.added_at) {
                                (Some(delivery), Some(added_at)) => {
                                    owner
                                        .open_delivered_personal(&cap, &delivery, added_at)
                                        .await
                                }
                                _ => Err(OwnerError::NotActive),
                            },
                            (false, None) => Err(OwnerError::NotActive),
                        };
                        let result = match personal {
                            Ok(personal) => showing.stage(owner, &cap, &personal, &approvals).await,
                            Err(error) => Err(PairingError::Owner(error)),
                        };
                        (showing, result)
                    })
                })
                .await;
            match staged {
                Ok((showing, Ok(()))) => (Some(showing), Ok(())),
                Ok((showing, Err(error))) => {
                    self.end_pairing_action();
                    (Some(showing), Err(error))
                }
                Err(_) => {
                    self.end_pairing_action();
                    (None, Err(PairingError::Local))
                }
            }
        })
    }
    fn reconfirm(&self) -> BoxFuture<'_, Result<(), SignerError>> {
        Box::pin(HostSigner::reconfirm(self))
    }
}

/// The build's transport, for a device joining before it has a client.
pub struct Transport {
    pub endpoint: Endpoint,
    pub connector: Arc<dyn Connector>,
    pub relay: Arc<dyn Relay>,
    pub owner: Arc<bh_device::Owner>,
}

/// One account's running client, as pairing borrows it. Holding it does not
/// keep the client running: when the account's sync stops, the client stops
/// all the same and `stopping` turns true.
#[derive(Clone)]
pub struct SyncHandle {
    pub client: Arc<Client>,
    pub ops: Arc<dyn AccountOps>,
    pub relay: Arc<dyn Relay>,
    /// Becomes true when the account's sync stops.
    pub stopping: watch::Receiver<bool>,
}

struct Running {
    handle: SyncHandle,
    #[cfg(any(test, feature = "test-support"))]
    signer: Arc<dyn Signer>,
    capability: Arc<AccountCapability>,
    /// This device's preset hue among the account's active devices, chosen
    /// once per client; the host shows its own caret and its other devices'
    /// in these colours.
    colour: Option<u8>,
    stopping: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// A container's client, or the one start that may make it.
enum Slot {
    /// Later starts wait for this one (`started` ends with it).
    Starting {
        token: u64,
        started: watch::Receiver<()>,
    },
    Running(Running),
}

struct SyncInner {
    configured: Configured,
    owner: Arc<bh_device::Owner>,
    connector: Option<Arc<dyn Connector>>,
    relay: Option<Arc<dyn Relay>>,
    /// At most one start or client per container. Held only briefly, never
    /// across an await.
    running: Mutex<HashMap<ContainerId, Slot>>,
    starts: std::sync::atomic::AtomicU64,
    /// Accounts without a client (no endpoint): their windows still hear
    /// their local status.
    local: Mutex<HashMap<ContainerId, Arc<dyn StatusWindows>>>,
    views: Mutex<Published>,
}

/// Each account's last published status, and the host's newest revision:
/// one counter for the life of the host, whichever client published.
#[derive(Default)]
struct Published {
    views: HashMap<ContainerId, StatusView>,
    revision: u64,
}

impl SyncInner {
    fn slots(&self) -> std::sync::MutexGuard<'_, HashMap<ContainerId, Slot>> {
        self.running.lock().expect("sync clients")
    }
}

/// One start's claim on its container's slot. Dropped, by failure or by
/// its caller giving up, it frees the slot if it still holds it.
struct Start {
    inner: Arc<SyncInner>,
    id: ContainerId,
    token: u64,
    _started: watch::Sender<()>,
}
impl Start {
    fn holds(&self, slots: &HashMap<ContainerId, Slot>) -> bool {
        matches!(slots.get(&self.id), Some(Slot::Starting { token, .. }) if *token == self.token)
    }
}
impl Drop for Start {
    fn drop(&mut self) {
        let mut slots = self.inner.slots();
        if self.holds(&slots) {
            slots.remove(&self.id);
        }
    }
}

/// Every ready account's sync. One client per anchored container, started
/// once its account is ready and stopped when its authority ends.
#[derive(Clone)]
pub struct SyncHost(Arc<SyncInner>);

impl SyncHost {
    pub fn new(configured: Configured, owner: Arc<bh_device::Owner>) -> Self {
        let host = Self(Arc::new(SyncInner {
            configured,
            owner,
            connector: None,
            relay: None,
            running: Mutex::default(),
            starts: Default::default(),
            local: Mutex::default(),
            views: Mutex::default(),
        }));
        host.install_records_wake();
        host
    }
    fn install_records_wake(&self) {
        let weak = Arc::downgrade(&self.0);
        self.0.owner.set_records_wake(Arc::new(move |id| {
            if let Some(inner) = weak.upgrade() {
                Self(inner).wake(id);
            }
        }));
    }
    /// As `new`, over another transport to the same edge routes.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_transport(
        configured: Configured,
        owner: Arc<bh_device::Owner>,
        connector: Arc<dyn Connector>,
        relay: Arc<dyn Relay>,
    ) -> Self {
        let host = Self::new(configured, owner);
        let mut inner = Arc::try_unwrap(host.0).ok().expect("new host");
        inner.connector = Some(connector);
        inner.relay = Some(relay);
        let host = Self(Arc::new(inner));
        host.install_records_wake();
        host
    }

    /// The edge and roots this build syncs with, if any.
    pub fn transport(&self) -> Option<Transport> {
        let Configured::Ready(endpoint) = &self.0.configured else {
            return None;
        };
        Some(Transport {
            endpoint: endpoint.clone(),
            connector: self
                .0
                .connector
                .clone()
                .unwrap_or_else(|| WsConnector::new(&endpoint.edge_url)),
            relay: self
                .0
                .relay
                .clone()
                .unwrap_or_else(|| HttpRelay::new(&endpoint.edge_url)),
            owner: self.0.owner.clone(),
        })
    }

    /// Start (or keep) ready account `id`'s client. Without an endpoint,
    /// its windows still hear that their work is saved on this device.
    ///
    /// One start per container at a time: a second waits for the first
    /// (holding no lock) and keeps what it made. A start installs its
    /// client only while its authority is still the account's current one;
    /// one that fails, or whose caller stops waiting, leaves nothing behind.
    /// Other accounts' starts never wait for this one.
    pub async fn ensure_started<S, P>(
        &self,
        accounts: &SharedAccountHost<S, P>,
        id: ContainerId,
        windows: Arc<dyn StatusWindows>,
    ) where
        S: HostKeyStore,
        P: PendingSetupProtector + Clone + Send + Sync + 'static,
    {
        let (start, replaced, endpoint) = loop {
            let Some(parts) = accounts.ready_parts(id) else {
                return;
            };
            let endpoint = match &self.0.configured {
                Configured::Ready(endpoint) => endpoint.clone(),
                Configured::Missing | Configured::Invalid => {
                    let network = match self.0.configured {
                        Configured::Missing => "off",
                        _ => "unsupported",
                    };
                    self.0
                        .local
                        .lock()
                        .expect("local windows")
                        .insert(id, windows.clone());
                    let view = StatusView::local(self.pending(id), network);
                    self.publish(id, view, windows.as_ref());
                    return;
                }
            };
            let claimed = {
                let mut slots = self.0.slots();
                match slots.get(&id) {
                    Some(Slot::Running(current))
                        if Arc::ptr_eq(&current.capability, &parts.capability)
                            && current.capability.is_current() =>
                    {
                        return;
                    }
                    Some(Slot::Starting { started, .. }) => Err(started.clone()),
                    _ => {
                        let token = self
                            .0
                            .starts
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let (claim, started) = watch::channel(());
                        let replaced = slots.insert(id, Slot::Starting { token, started });
                        Ok((token, claim, replaced))
                    }
                }
            };
            match claimed {
                Ok((token, claim, replaced)) => {
                    let start = Start {
                        inner: self.0.clone(),
                        id,
                        token,
                        _started: claim,
                    };
                    break (start, replaced, endpoint);
                }
                // Ends when that start installs its client or gives up.
                Err(mut started) => {
                    let _ = started.changed().await;
                }
            }
        };
        // A client of an earlier authority stops before this one starts.
        if let Some(Slot::Running(old)) = replaced {
            stop_running(old).await;
        }
        let Ok(signer) = HostSigner::start(accounts.clone(), id).await else {
            return;
        };
        let capability = signer.capability.clone();
        if !accounts
            .ready_parts(id)
            .is_some_and(|now| Arc::ptr_eq(&now.capability, &capability))
        {
            return;
        }
        let connector = self
            .0
            .connector
            .clone()
            .unwrap_or_else(|| WsConnector::new(&endpoint.edge_url));
        let relay = self
            .0
            .relay
            .clone()
            .unwrap_or_else(|| HttpRelay::new(&endpoint.edge_url));
        // The initial count is a snapshot; status reports update it later.
        // Never hold the all-accounts slots lock during a container SQLite read.
        let pending = self.pending(id);
        let mut slots = self.0.slots();
        // Stopped or locked meanwhile: nothing is installed after it.
        if !start.holds(&slots) || !capability.is_current() {
            return;
        }
        // The account's active-device order fixes this device's hue, the same
        // on every screen. A later addition may shift it only on restart.
        let colour = signer.current_account().ok().and_then(|account| {
            account
                .active_devices()
                .ok()?
                .position(|keys| keys.id() == capability.device_id())
                .map(|index| (index % 6) as u8)
        });
        let (status, status_rx) = watch::channel(SyncStatus::SavedLocal { pending });
        let client = Arc::new(Client::start_with(
            endpoint,
            connector,
            self.0.owner.clone(),
            id,
            signer.clone(),
            status,
        ));
        let (stopping, stopping_rx) = watch::channel(false);
        #[cfg(any(test, feature = "test-support"))]
        let handle_signer: Arc<dyn Signer> = signer.clone();
        let wakes = client.window_wakes();
        let wake_windows = windows.clone();
        let forward_wakes = tokio::spawn(async move {
            loop {
                for window in wakes.next().await {
                    wake_windows.wake_delivery(window);
                }
            }
        });
        let report = tokio::spawn(report(
            Arc::downgrade(&self.0),
            id,
            capability.clone(),
            status_rx,
            client.home_status(),
            signer.notices(),
            windows,
        ));
        let handle = SyncHandle {
            client,
            ops: signer,
            relay,
            stopping: stopping_rx,
        };
        slots.insert(
            id,
            Slot::Running(Running {
                #[cfg(any(test, feature = "test-support"))]
                signer: handle_signer,
                handle,
                capability,
                colour,
                stopping,
                tasks: vec![forward_wakes, report],
            }),
        );
        drop(slots);
        drop(start);
    }

    fn pending(&self, id: ContainerId) -> u64 {
        self.0
            .owner
            .shared_database(id)
            .ok()
            .and_then(|db| db.lock().ok()?.outbox_summary().ok())
            .map_or(0, |summary| summary.unaccepted_notes)
    }

    fn publish(&self, id: ContainerId, view: StatusView, windows: &dyn StatusWindows) {
        publish(&self.0, id, view, windows);
    }

    fn running_handle(&self, id: ContainerId) -> Option<SyncHandle> {
        match self.0.slots().get(&id)? {
            Slot::Running(running) => Some(running.handle.clone()),
            Slot::Starting { .. } => None,
        }
    }

    /// Local note work committed in `id`: look for it now, and tell its
    /// windows what is still unsaved to the network.
    pub fn wake(&self, id: ContainerId) {
        if let Some(handle) = self.running_handle(id) {
            handle.client.wake();
            return;
        }
        let windows = self
            .0
            .local
            .lock()
            .expect("local windows")
            .get(&id)
            .cloned();
        if let Some(windows) = windows {
            let network = match self.0.configured {
                Configured::Invalid => "unsupported",
                _ => "off",
            };
            self.publish(
                id,
                StatusView::local(self.pending(id), network),
                windows.as_ref(),
            );
        }
    }

    /// The account's current status, for a window (re)binding to it.
    pub fn view(&self, id: ContainerId) -> Option<StatusView> {
        self.0
            .views
            .lock()
            .expect("sync views")
            .views
            .get(&id)
            .cloned()
    }

    pub fn handle(&self, id: ContainerId) -> Option<SyncHandle> {
        self.running_handle(id)
            .filter(|handle| handle.ops.is_current())
    }
    /// This container's own-device presence handle, if its client is current.
    /// The caller configures it once, reports selections, and clears a window
    /// when it closes or navigates.
    pub fn presence(&self, id: ContainerId) -> Option<Presence> {
        self.handle(id).map(|handle| handle.client.presence())
    }
    /// This device's preset hue in `id`, from its position among the
    /// account's active devices when the client started.
    pub fn presence_colour(&self, id: ContainerId) -> Option<u8> {
        match self.0.slots().get(&id)? {
            Slot::Running(running) => running.colour,
            Slot::Starting { .. } => None,
        }
    }
    /// The remote carets this device shows for `id`. Each published value is
    /// the whole bounded state, so a reader can miss a change but never a
    /// removal.
    pub fn remote_presence(&self, id: ContainerId) -> Option<watch::Receiver<RemoteState>> {
        self.presence(id).map(|presence| presence.subscribe())
    }
    /// Pause or quit: every running account announces that it has nothing to
    /// show and closes its presence join. Best effort and nonblocking.
    pub fn leave_presence(&self) {
        for slot in self.0.slots().values() {
            if let Slot::Running(running) = slot {
                running.handle.client.presence().leave();
            }
        }
    }
    /// Android resumed: presence opens its join again and resends each
    /// window's kept selection.
    pub fn resume_presence(&self) {
        for slot in self.0.slots().values() {
            if let Slot::Running(running) = slot {
                running.handle.client.presence().foreground(true);
            }
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn client(&self, id: ContainerId) -> Option<Arc<Client>> {
        self.handle(id).map(|handle| handle.client)
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn signer(&self, id: ContainerId) -> Option<Arc<dyn Signer>> {
        match self.0.slots().get(&id)? {
            Slot::Running(running) => Some(running.signer.clone()),
            Slot::Starting { .. } => None,
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn running(&self, id: ContainerId) -> bool {
        matches!(self.0.slots().get(&id), Some(Slot::Running(_)))
    }

    /// Lock every account, then stop every client and start: the one way
    /// an account lock reaches sync. Holders of a handle do not delay it.
    pub async fn lock_accounts<S, P>(&self, accounts: &SharedAccountHost<S, P>)
    where
        S: HostKeyStore,
        P: PendingSetupProtector + Clone + Send + Sync + 'static,
    {
        accounts.lock().stop_accounts();
        self.shutdown_all().await;
    }
    /// Quit: stop every client and start. Their exact bytes are already kept.
    pub async fn shutdown_all(&self) {
        let all: Vec<_> = self.0.slots().drain().map(|(_, slot)| slot).collect();
        futures_util::future::join_all(all.into_iter().filter_map(|slot| match slot {
            Slot::Running(running) => Some(stop_running(running)),
            Slot::Starting { .. } => None,
        }))
        .await;
    }
}

/// Send `view` to the account's windows if its status changed, under the
/// host's next revision. Posts may reach a page out of order; the page keeps
/// the larger revision, and the stored view is always the newest.
fn publish(inner: &SyncInner, id: ContainerId, mut view: StatusView, windows: &dyn StatusWindows) {
    {
        let mut published = inner.views.lock().expect("sync views");
        if let Some(current) = published.views.get(&id) {
            view.revision = current.revision;
            if *current == view {
                return;
            }
        }
        published.revision += 1;
        view.revision = published.revision;
        published.views.insert(id, view.clone());
    }
    windows.post_status(id, &view);
}

/// Stop one client: tell its borrowers, end its report and wake forwarding,
/// then stop the client itself, however many hold it. It runs to the end in
/// its own task, so a caller that stops waiting cannot leave it half done.
async fn stop_running(running: Running) {
    let Running {
        handle,
        stopping,
        tasks,
        ..
    } = running;
    let _ = stopping.send(true);
    for task in &tasks {
        task.abort();
    }
    let stopped = tokio::spawn(async move {
        for task in tasks {
            let _ = task.await;
        }
        handle.client.shutdown().await;
    });
    let _ = stopped.await;
}

/// Follow one client's note status, home status and account notices, and
/// tell the account's windows. When the account's authority ends, end its
/// windows' routes and stop the client.
async fn report(
    host: std::sync::Weak<SyncInner>,
    id: ContainerId,
    capability: Arc<AccountCapability>,
    mut status: watch::Receiver<SyncStatus>,
    mut home: watch::Receiver<HomeStatus>,
    mut notices: watch::Receiver<Notice>,
    windows: Arc<dyn StatusWindows>,
) {
    loop {
        let Some(inner) = host.upgrade() else { return };
        let notice = *notices.borrow_and_update();
        let current = *status.borrow_and_update();
        let home_now = *home.borrow_and_update();
        let pending = SyncHost(inner.clone()).pending(id);
        let view = StatusView::of(Some(current), Some(home_now), notice, pending);
        publish(&inner, id, view, windows.as_ref());
        if notice.account != AccountState::Active {
            let routed = inner.owner.deauthorize(id).unwrap_or_default();
            windows.authority_ended(id, routed);
            // Only this client: a newer start or client stays.
            let running = {
                let mut slots = inner.slots();
                match slots.get(&id) {
                    Some(Slot::Running(running))
                        if Arc::ptr_eq(&running.capability, &capability) =>
                    {
                        slots.remove(&id)
                    }
                    _ => None,
                }
            };
            drop(inner);
            if let Some(Slot::Running(running)) = running {
                tokio::spawn(stop_running(running));
            }
            return;
        }
        drop(inner);
        tokio::select! {
            changed = status.changed() => if changed.is_err() { return },
            changed = home.changed() => if changed.is_err() { return },
            changed = notices.changed() => if changed.is_err() { return },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        accounts::{SharedAccountHost, ready_test_host},
        test_support::{FakeStore, PlainProtector},
    };
    use bh_account::{
        DevicePublicKeys,
        crypto::{KemKey, SigningKey},
        journal::AccountJournal,
        storage::DeviceJournal,
    };
    use bh_sync_client::{AccountApplyError, BaseControlRequest, ControlSignError, Signer};
    use std::{path::Path, sync::Arc};

    type Host = SharedAccountHost<FakeStore, PlainProtector>;
    const COPY_MESSAGE: &[u8] = b"bh/original-envelope/v1\0exact copy";

    struct Fixture {
        _dir: tempfile::TempDir,
        owner: Arc<bh_device::Owner>,
        host: Host,
        store: FakeStore,
        id: ContainerId,
        cap: Arc<AccountCapability>,
    }

    async fn fixture(store: FakeStore) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let host = ready_test_host(&owner, dir.path(), store.clone()).await;
        let (id, cap) = host.ready_authority().unwrap();
        Fixture {
            _dir: dir,
            owner,
            host,
            store,
            id,
            cap,
        }
    }

    fn real_keys() -> DevicePublicKeys {
        DevicePublicKeys::new(
            SigningKey::generate().public(),
            SigningKey::generate().public(),
            KemKey::generate().public(),
        )
        .unwrap()
    }

    /// A device addition this account's control key signs, not applied.
    async fn signed_addition(f: &Fixture, keys: DevicePublicKeys) -> Vec<u8> {
        f.host
            .run_lent(f.id, &f.cap, move |owner, cap| {
                Box::pin(async move {
                    let request = owner.prepare_add_device(&cap, keys).unwrap();
                    owner
                        .sign_control(&cap, &request)
                        .await
                        .unwrap()
                        .as_bytes()
                        .to_vec()
                })
            })
            .await
            .unwrap()
    }

    /// Stage an addition with its delivery, as pairing's approval does.
    async fn staged_addition(f: &Fixture, keys: DevicePublicKeys) -> Vec<u8> {
        f.host
            .run_lent(f.id, &f.cap, move |owner, cap| {
                Box::pin(async move {
                    let personal = owner.open_personal(&cap).await.unwrap();
                    let request = owner.prepare_add_device(&cap, keys.clone()).unwrap();
                    let event = owner.sign_control(&cap, &request).await.unwrap();
                    let delivery = owner
                        .seal_personal_for_device(&cap, &personal, &keys, &event)
                        .await
                        .unwrap();
                    owner
                        .stage_signed_admission(&cap, &keys, event.as_bytes(), &delivery)
                        .unwrap();
                    event.as_bytes().to_vec()
                })
            })
            .await
            .unwrap()
    }

    fn raw(path: &Path) -> rusqlite::Connection {
        let file = std::fs::read_dir(path.join("accounts"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "sqlite"))
            .unwrap();
        rusqlite::Connection::open(file).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn identity_is_the_base_genesis_account_and_current_follows_the_owner() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let identity = signer.identity().unwrap();
        assert!(identity.account == f.cap.account_id());
        assert!(identity.device == f.cap.device_id());
        assert_eq!(
            identity.anchor.head().position,
            3,
            "the base genesis's head"
        );
        let database = f.owner.shared_database(f.id).unwrap();
        let journal = DeviceJournal::from_shared(database);
        assert_eq!(
            identity.genesis,
            journal.load().unwrap().unwrap().history[0]
        );
        let head = signer.current_account().unwrap().head();
        assert_eq!(head, f.cap.head());
        let addition = signed_addition(&f, real_keys()).await;
        let applied = signer.apply_account(head, vec![addition]).await.unwrap();
        assert_eq!(applied.position, 4);
        assert_eq!(signer.current_account().unwrap().head(), applied);
        assert_eq!(identity.anchor.head().position, 3, "identity is unchanged");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn account_follow_keeps_refused_unsupported_stopped_and_unavailable_apart() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let head = signer.current_account().unwrap().head();
        let addition = signed_addition(&f, real_keys()).await;
        // Not the owner's head: nothing applied.
        let mut elsewhere = head;
        elsewhere.position += 1;
        assert_eq!(
            signer
                .apply_account(elsewhere, vec![addition.clone()])
                .await,
            Err(AccountApplyError::Unavailable)
        );
        // Not this account's next verified history: refused, no stop.
        let mut forged = addition.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(
            signer.apply_account(head, vec![forged]).await,
            Err(AccountApplyError::Refused)
        );
        assert_eq!(
            signer.apply_account(head, vec![b"junk".to_vec()]).await,
            Err(AccountApplyError::Refused)
        );
        assert_eq!(signer.current_account().unwrap().head(), head);
        assert!(f.cap.is_current());
        assert_eq!(*signer.notices().borrow(), Notice::default());
        // An authenticated fork stops the account.
        let (taken, fork) = fork_pair(&f).await;
        let at = signer.apply_account(head, vec![taken]).await.unwrap();
        assert_eq!(
            signer.apply_account(at, vec![fork]).await,
            Err(AccountApplyError::Stopped)
        );
        assert_eq!(signer.notices().borrow().account, AccountState::Stopped);
        assert!(signer.current_account().is_err());
        assert!(signer.sign_event(b"after".to_vec()).await.is_err());
    }

    /// Two signed successors of the current head, and an event extending
    /// the second: the owner applies the first, then gets the third.
    async fn fork_pair(f: &Fixture) -> (Vec<u8>, Vec<u8>) {
        let device = f.cap.device_id();
        f.host
            .run_lent(f.id, &f.cap, move |owner, cap| {
                Box::pin(async move {
                    let taken = owner.prepare_add_device(&cap, real_keys()).unwrap();
                    let taken = owner.sign_control(&cap, &taken).await.unwrap();
                    let other = owner.prepare_add_device(&cap, real_keys()).unwrap();
                    let other = owner.sign_control(&cap, &other).await.unwrap();
                    let mut branch = owner.verified(&cap).unwrap().clone();
                    branch.apply(other.as_bytes()).unwrap();
                    let next = branch.add_device(device, real_keys()).unwrap();
                    let next = owner.sign_control(&cap, &next).await.unwrap();
                    (taken.as_bytes().to_vec(), next.as_bytes().to_vec())
                })
            })
            .await
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_stop_write_is_still_a_stop() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let head = signer.current_account().unwrap().head();
        let (taken, fork) = fork_pair(&f).await;
        let at = signer.apply_account(head, vec![taken]).await.unwrap();
        raw(f._dir.path())
            .execute_batch(
                "CREATE TRIGGER fail_stop BEFORE UPDATE ON account_state \
                 BEGIN SELECT RAISE(FAIL, 'no space'); END;",
            )
            .unwrap();
        assert_eq!(
            signer.apply_account(at, vec![fork]).await,
            Err(AccountApplyError::Stopped),
            "the live owner latched its stop"
        );
        assert!(!f.cap.is_current());
        assert_eq!(signer.notices().borrow().account, AccountState::Stopped);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_removed_device_is_reported_and_its_authority_ends() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let head = signer.current_account().unwrap().head();
        let removal = f
            .host
            .run_lent(f.id, &f.cap, |owner, cap| {
                Box::pin(async move {
                    let request = owner.prepare_remove_self(&cap).unwrap();
                    owner
                        .sign_control(&cap, &request)
                        .await
                        .unwrap()
                        .as_bytes()
                        .to_vec()
                })
            })
            .await
            .unwrap();
        assert!(signer.apply_account(head, vec![removal]).await.is_ok());
        assert_eq!(signer.notices().borrow().account, AccountState::Removed);
        assert!(!f.cap.is_current());
        assert!(signer.current_account().is_err());
        let mut used = false;
        assert!(
            signer
                .with_base_keys(signer.base(), &mut |_, _| used = true)
                .is_err()
        );
        assert!(!used);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_staged_addition_settles_once_its_account_event_applies() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let head = signer.current_account().unwrap().head();
        let event = staged_addition(&f, real_keys()).await;
        let staged = signer.staged_addition().unwrap().unwrap();
        assert_eq!((staged.position, staged.event.clone()), (4, event.clone()));
        signer.apply_account(head, vec![event]).await.unwrap();
        assert!(signer.staged_addition().unwrap().is_none(), "admitted");

        // Another event at the staged position: not added, row settled.
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let head = signer.current_account().unwrap().head();
        let _ = staged_addition(&f, real_keys()).await;
        let competitor = f
            .host
            .run_lent(f.id, &f.cap, |owner, cap| {
                Box::pin(async move {
                    let view = owner.verified(&cap).unwrap().clone();
                    let request = view.add_device(cap.device_id(), real_keys()).unwrap();
                    owner
                        .sign_control(&cap, &request)
                        .await
                        .unwrap()
                        .as_bytes()
                        .to_vec()
                })
            })
            .await
            .unwrap();
        signer.apply_account(head, vec![competitor]).await.unwrap();
        assert!(signer.staged_addition().unwrap().is_none(), "not added");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_first_devices_home_setup_is_its_retained_signup_or_an_error() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let setup = signer.initial_home_setup().unwrap().expect("first device");
        assert_eq!(setup.prefix.head.position, 3);
        assert!(setup.prefix.anchor == f.cap.account_id());
        let journal = DeviceJournal::from_shared(f.owner.shared_database(f.id).unwrap());
        let retained = journal.initial_bootstrap().unwrap().unwrap();
        assert!(setup.objects.record == retained.recovery_record);
        // Missing retained signup on a first device: an error, never None.
        raw(f._dir.path())
            .execute_batch("DELETE FROM account_initial_bootstrap")
            .unwrap();
        let again = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        assert!(again.initial_home_setup().is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_device_added_later_has_no_home_obligation() {
        let f = fixture(FakeStore::default()).await;
        // A second container whose device the first adds at position 4.
        let id = f.owner.create_container(f._dir.path()).unwrap();
        let database = f.owner.shared_database(id).unwrap();
        let mut journal = DeviceJournal::from_shared(database.clone());
        let identity = bh_account::pairing::scanner_identity(
            &mut journal,
            &mut f.store.clone(),
            bh_account::platform::ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        )
        .await
        .unwrap();
        let addition = signed_addition(&f, identity.keys.clone()).await;
        let first = DeviceJournal::from_shared(f.owner.shared_database(f.id).unwrap());
        let mut history = first.load().unwrap().unwrap().history;
        history.push(addition);
        let refs: Vec<&[u8]> = history.iter().map(Vec::as_slice).collect();
        let generation = bh_account::owner::AccountGeneration::new();
        let mut joined = Owner::new(
            DeviceJournal::from_shared(database),
            f.store.clone(),
            PlainProtector,
            generation.clone(),
        );
        joined.adopt_joined(f.cap.account_id(), &refs).unwrap();
        let bh_account::owner::AccountLoad::Active(cap) = joined.activate().await.unwrap() else {
            panic!("joined device active");
        };
        assert!(
            retained_home_setup(&joined, &cap, &journal, &generation)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn home_confirmation_is_fenced_by_generation_and_account() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let setup = signer.initial_home_setup().unwrap().unwrap();
        let journal = DeviceJournal::from_shared(f.owner.shared_database(f.id).unwrap());
        let mut stale = signer.initial_home_setup().unwrap().unwrap();
        stale.generation += 1;
        assert!(signer.confirm_home_ordered(&stale).is_err());
        let mut other = signer.initial_home_setup().unwrap().unwrap();
        other.prefix.anchor = bh_account::AccountId([9; 32]);
        assert!(signer.confirm_home_ordered(&other).is_err());
        assert!(journal.pending_setup().unwrap().is_some());
        signer.confirm_home_ordered(&setup).unwrap();
        assert!(journal.pending_setup().unwrap().is_none());
        // Already cleared: the same exact acknowledged setup completes again.
        signer.confirm_home_ordered(&setup).unwrap();
        assert!(journal.initial_bootstrap().unwrap().is_some(), "retained");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_base_control_without_the_persons_approval_never_prompts() {
        let f = fixture(FakeStore::gated()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let addition = signed_addition(&f, real_keys()).await;
        let prompts = f.store.prompts();
        let request = || BaseControlRequest {
            expected_key: signer.control_key(),
            message: COPY_MESSAGE.to_vec(),
            copies: addition.clone(),
        };
        assert_eq!(
            signer.sign_base_control(request()).await,
            Err(ControlSignError::ConfirmationNeeded)
        );
        assert!(signer.notices().borrow().confirm, "the person is asked");
        // Approved copy, but no confirmation it can reuse: still no prompt.
        signer
            .approvals()
            .grant(addition.clone(), tokio::time::Instant::now() + LIFE);
        assert_eq!(
            signer.sign_base_control(request()).await,
            Err(ControlSignError::ConfirmationNeeded)
        );
        assert_eq!(
            f.store.prompts(),
            prompts,
            "nothing prompted in the background"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_pairing_confirmation_signs_the_addition_and_exactly_its_copy() {
        let f = fixture(FakeStore::gated()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let before = f.store.prompts();
        signer.open_pairing_action();
        let addition = signed_addition(&f, real_keys()).await;
        assert_eq!(f.store.prompts(), before + 1, "the addition's confirmation");
        signer
            .approvals()
            .grant(addition.clone(), tokio::time::Instant::now() + LIFE);
        let request = |copies: &[u8]| BaseControlRequest {
            expected_key: signer.control_key(),
            message: COPY_MESSAGE.to_vec(),
            copies: copies.to_vec(),
        };
        let mut other = addition.clone();
        other[10] ^= 1;
        assert_eq!(
            signer.sign_base_control(request(&other)).await,
            Err(ControlSignError::ConfirmationNeeded),
            "another event's copy"
        );
        let signature = signer.sign_base_control(request(&addition)).await.unwrap();
        assert!(
            bh_account::crypto::verify(&signer.control_key(), COPY_MESSAGE, &signature).is_ok()
        );
        assert_eq!(
            f.store.prompts(),
            before + 1,
            "no second prompt for the copy"
        );
        assert!(!signer.notices().borrow().confirm);
        // Used once: the same copy again needs the person again.
        assert_eq!(
            signer.sign_base_control(request(&addition)).await,
            Err(ControlSignError::ConfirmationNeeded)
        );
        assert_eq!(f.store.prompts(), before + 1);
    }

    /// An armed copy whose grant another gate use ends before the owner
    /// signs it (`revoke`: a failed pairing; `open`: another approval)
    /// waits for the person; it never prompts from the background.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_armed_copy_that_loses_its_grant_waits_and_never_prompts() {
        for another_pairing in [false, true] {
            let f = fixture(FakeStore::gated()).await;
            let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
            signer.open_pairing_action();
            let addition = signed_addition(&f, real_keys()).await;
            signer
                .approvals()
                .grant(addition.clone(), tokio::time::Instant::now() + LIFE);
            // The owner is busy, so the armed copy waits for it.
            let (release, held) = tokio::sync::oneshot::channel::<()>();
            let busy = tokio::spawn({
                let (host, id, cap) = (f.host.clone(), f.id, f.cap.clone());
                async move {
                    host.run_lent(id, &cap, move |_, _| {
                        Box::pin(async move {
                            let _ = held.await;
                        })
                    })
                    .await
                }
            });
            while f.host.with_owner(f.id, &f.cap, |_| ()).is_some() {
                tokio::task::yield_now().await;
            }
            let prompts = f.store.prompts();
            let mut copy = Box::pin(signer.sign_base_control(BaseControlRequest {
                expected_key: signer.control_key(),
                message: COPY_MESSAGE.to_vec(),
                copies: addition.clone(),
            }));
            assert!(
                futures_util::poll!(&mut copy).is_pending(),
                "armed, waiting"
            );
            if another_pairing {
                signer.open_pairing_action();
            } else {
                signer.end_pairing_action();
            }
            release.send(()).unwrap();
            busy.await.unwrap().unwrap();
            assert_eq!(copy.await, Err(ControlSignError::ConfirmationNeeded));
            assert_eq!(f.store.prompts(), prompts, "no background prompt");
            assert!(signer.notices().borrow().confirm, "the person is asked");
            // A deliberate control still asks for its fresh confirmation.
            signed_addition(&f, real_keys()).await;
            assert_eq!(f.store.prompts(), prompts + 1);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn after_a_restart_the_copy_waits_for_an_explicit_fresh_confirmation() {
        let f = fixture(FakeStore::gated()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        signer.open_pairing_action();
        let addition = signed_addition(&f, real_keys()).await;
        drop(signer);
        // The host restarted: the approval and its confirmation are gone.
        f.store.gate.as_ref().unwrap().clear();
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let request = || BaseControlRequest {
            expected_key: signer.control_key(),
            message: COPY_MESSAGE.to_vec(),
            copies: addition.clone(),
        };
        assert_eq!(
            signer.sign_base_control(request()).await,
            Err(ControlSignError::ConfirmationNeeded)
        );
        assert!(signer.notices().borrow().confirm);
        // A cancelled confirmation grants nothing.
        f.store
            .refuse_prompts
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(signer.reconfirm().await.is_err());
        assert_eq!(
            signer.sign_base_control(request()).await,
            Err(ControlSignError::ConfirmationNeeded)
        );
        f.store
            .refuse_prompts
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let prompts = f.store.prompts();
        signer.reconfirm().await.unwrap();
        assert_eq!(f.store.prompts(), prompts + 1, "one fresh confirmation");
        signer.sign_base_control(request()).await.unwrap();
        assert_eq!(f.store.prompts(), prompts + 1);
        assert!(!signer.notices().borrow().confirm);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_platform_bound_store_never_signs_a_copy_without_approval() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let addition = signed_addition(&f, real_keys()).await;
        let request = BaseControlRequest {
            expected_key: signer.control_key(),
            message: COPY_MESSAGE.to_vec(),
            copies: addition,
        };
        assert_eq!(
            signer.sign_base_control(request).await,
            Err(ControlSignError::ConfirmationNeeded),
            "no background signature without the person's approval"
        );
        assert!(signer.notices().borrow().confirm);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_platform_bound_store_signs_an_approved_copy_with_its_own_check() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let addition = signed_addition(&f, real_keys()).await;
        signer
            .approvals()
            .grant(addition.clone(), tokio::time::Instant::now() + LIFE);
        let request = BaseControlRequest {
            expected_key: signer.control_key(),
            message: COPY_MESSAGE.to_vec(),
            copies: addition,
        };
        assert!(signer.sign_base_control(request).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_locked_account_refuses_every_signer_use() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        assert!(signer.sign_event(b"before".to_vec()).await.is_ok());
        let mut keys_used = false;
        signer
            .with_base_keys(signer.base(), &mut |_, _| {
                // The client's lock order: the owner's own writer lock is
                // free while the keys are in use.
                let database = f.owner.shared_database(f.id).unwrap();
                keys_used = database.try_lock().is_ok();
            })
            .unwrap();
        assert!(keys_used);
        assert!(
            signer
                .with_base_keys(bh_sync::BaseId([7; 32]), &mut |_, _| {})
                .is_err(),
            "only the own base"
        );
        f.host.lock().stop_accounts();
        assert!(signer.current_account().is_err());
        assert!(signer.sign_event(b"after".to_vec()).await.is_err());
        assert!(signer.initial_home_setup().is_err());
        assert!(
            signer
                .with_base_keys(signer.base(), &mut |_, _| {})
                .is_err()
        );
    }
}
