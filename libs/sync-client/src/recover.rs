//! Recovering an account on a fresh device with its password and kit, when
//! no device of the account survives to pair with.
//!
//! The device seals a claim (the code's proof and the password-and-code
//! token) to the home's certified recovery key, for the nonce of one
//! attested connection. A released record names the account it belongs to;
//! the account's history is read from its genesis as public evidence, every
//! entry with its confirmation verified under the hosting root, and the
//! released record and personal-key seal must be the ones it names. The
//! recovery key then adds this device: one recovery-signed addition, with
//! the personal key sealed to it, ordered and confirmed on that same
//! connection. A retry that finds this device already active resumes it; a
//! correct claim again costs no try, and no second device is added.
//!
//! Authenticated as itself, the device reads the account directory and
//! admits its own base from the entry's key package while the base's epoch
//! is still its genesis's (`bh_device::join::admit_current`); a later epoch
//! is admitted only from an admission snapshot. It reads the base, then
//! copies every account entry the base lacks into it, signed by the
//! recovery key (`ACCOUNT_CHANGE_V2` runs, each entry with its
//! confirmation), and waits until the base has them. Only then is recovery
//! done: the code, the claim, the released record and the recovery keys are
//! never stored, and are wiped when they drop, on success, error or
//! interruption. Interrupted before the copies are done, recovery asks for
//! the password and kit again and resumes.
use crate::{
    AccountApplyError, BaseControlRequest, Client, ControlSignError, Endpoint, HomeSetup, Identity,
    OpenedEntries, Shared, Signer, SignerError, SyncStatus, TimedOriginal,
    account_evidence::{self, EvidenceFailure, VerifiedEvent},
    backoff::Backoff,
    bootstrap::{self, BootstrapError, Progress},
    outbox::{Fail, Link},
    pairing::JoinProver,
    puller::{self, Receiver, granted, only, ordered_events, read_events_exclusive},
    transport::{Connector, Route, Socket},
};
use bh_account::{
    AccountEvent, AccountId, ConfirmedTime, DeviceId, DevicePublicKeys, Head as AccountHead,
    VerifiedAccount,
    device_auth::{Context, Proof},
    directory::{DirectoryEntry, open_entry},
    journal::{AccountJournal, PendingSetupProtector, StagedControl},
    owner::{
        AccountCapability, AccountOwner, OwnerError as AccountOwnerError, staging::Settlement,
    },
    personal::{self, PersonalKey},
    platform::DeviceKeyStore,
    recovery::{self, Password, RecoveryClaim, RecoveryCode, RecoveryKeys},
    storage::DeviceJournal,
};
use bh_authz_proto::{
    Delivery, FromService, MetadataKey, RecoverPurpose, RecoveryAnswer, Refusal, ToService, Want,
    account_log_id, account_log_wrap, delivery_body, delivery_frame,
};
use bh_confidential_channel::{
    appraisal::{PolicyContext, PolicyStore, Sample, StoredState},
    handshake::ClientHello,
    record::{Opened, Session},
};
use bh_confidential_policy::Snapshot;
use bh_crypto::{Secret, SecretBytes};
use bh_device::{
    ContainerId, CopyPlan, Owner,
    base_keys::SealHeader,
    control::{InstallError, SealWait},
    join::{CurrentAdmission, JoinError, admit_current},
    own_base::{OwnBase, OwnBaseError, create_or_open},
};
use bh_sync::{
    BaseId, BodyObject, Digest, Head, OrderState,
    evidence::{AcceptedHead, OrderingConfirmation, TimeBounds},
    permit::{AppendAck, LogId, LogKind},
    receipt, referenced_body,
    wire::{self, Request, Response},
};
use futures_util::{SinkExt, StreamExt, future::BoxFuture};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;

/// Attempts of one recovery before it reports the home unreachable.
const ATTEMPTS: usize = 5;
/// The handshake, and then each answer, must arrive within this.
const ANSWER_WAIT: Duration = Duration::from_secs(30);
/// Passes reading the base for a copy this device's append ordered.
const COPY_READS: usize = 64;

/// Why recovery did not finish. Nothing recovery-derived is kept, whatever
/// the answer; progress that is the account's own (its verified history, an
/// added device) stays, and the next attempt resumes from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoverError {
    /// The home knows no kit with this code. No try was used.
    NotRecognised,
    /// The code is right and the password is not: a try was used.
    PasswordMismatch {
        tries_left: u8,
        next_try_ms: Option<u64>,
    },
    /// No try is allowed before `next_try_ms`.
    Wait { next_try_ms: u64 },
    /// The home could not be reached or could not answer now. Asking again
    /// resumes.
    Unreachable,
    /// What the home released or served does not verify against the
    /// account's history. Never retried silently.
    Invalid,
    /// The own base's key changed since its genesis: only an admission
    /// snapshot admits it. The account's progress is kept; nothing of the
    /// base, and no earlier epoch's key.
    AwaitingAdmission,
}

/// How far a recovery has come, for its screen. Once the account is open
/// here, these are a join's stages: admitted, then the own base's download.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RecoverStage {
    /// The home checks the password and kit; this device is being added.
    #[default]
    Checking,
    /// This device is added and admitted: the account is open here.
    Open,
    /// The own base downloads, as `bootstrap::run` reports it.
    Downloading(Progress),
}

impl From<Fail> for RecoverError {
    fn from(fail: Fail) -> Self {
        match fail {
            Fail::Stopped | Fail::Unsupported => Self::Invalid,
            _ => Self::Unreachable,
        }
    }
}

/// Recover the account whose kit `code` is, with `password`, onto
/// `container`, a fresh container whose own device keys are journaled
/// (`bh_account::pairing::scanner_identity`). `prover` proves possession of
/// those keys before the container holds the account. Returns the account's
/// capability once the own base holds this device's addition; the container
/// is then usable and its client may start.
#[allow(clippy::too_many_arguments)] // One recovery's exact inputs.
pub async fn recover<J, S, P>(
    endpoint: &Endpoint,
    connector: Arc<dyn Connector>,
    owner: Arc<Owner>,
    container: ContainerId,
    account: &mut AccountOwner<J, S, P>,
    prover: Arc<dyn JoinProver>,
    password: &Password,
    code: &RecoveryCode,
) -> Result<Arc<AccountCapability>, RecoverError>
where
    J: AccountJournal,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    let (stages, _) = watch::channel(RecoverStage::default());
    recover_reporting(
        endpoint, connector, owner, container, account, prover, password, code, &stages,
    )
    .await
}

/// As [`recover`], telling `stages` how far it has come.
#[allow(clippy::too_many_arguments)] // One recovery's exact inputs.
pub async fn recover_reporting<J, S, P>(
    endpoint: &Endpoint,
    connector: Arc<dyn Connector>,
    owner: Arc<Owner>,
    container: ContainerId,
    account: &mut AccountOwner<J, S, P>,
    prover: Arc<dyn JoinProver>,
    password: &Password,
    code: &RecoveryCode,
    stages: &watch::Sender<RecoverStage>,
) -> Result<Arc<AccountCapability>, RecoverError>
where
    J: AccountJournal,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    let keys = DeviceJournal::from_shared(
        owner
            .shared_database(container)
            .map_err(|_| RecoverError::Unreachable)?,
    )
    .device()
    .map_err(|_| RecoverError::Unreachable)?
    .ok_or(RecoverError::Unreachable)?
    .keys;
    let claim = recovery::claim(password, code).map_err(|_| RecoverError::Invalid)?;
    let attempt = Attempt {
        endpoint,
        connector,
        owner,
        container,
        prover,
        keys,
        password,
        code,
        claim: &claim,
        unjudged: AtomicBool::new(false),
        stages,
    };
    let mut backoff = Backoff::default();
    let mut tries = 0;
    loop {
        tries += 1;
        // Boxed: one attempt's future is too large for a thread's stack.
        match Box::pin(attempt.run(account)).await {
            // Asking again after a claim whose answer was lost could use
            // another of the person's tries: they ask again instead.
            Err(RecoverError::Unreachable)
                if tries < ATTEMPTS && !attempt.unjudged.load(Ordering::SeqCst) =>
            {
                tokio::time::sleep(backoff.next()).await;
            }
            result => return result,
        }
    }
}

/// The verified account a page of history leads to, and where it ends.
struct History {
    events: Vec<VerifiedEvent>,
    outer: OrderState,
    prior: Option<TimeBounds>,
    state: VerifiedAccount,
}

/// What a released record and seal opened: the recovery keys and the
/// personal key. Both are wiped when this drops.
struct Unlocked {
    keys: RecoveryKeys,
    personal: PersonalKey,
}

/// One recovery attempt's inputs.
struct Attempt<'a> {
    endpoint: &'a Endpoint,
    connector: Arc<dyn Connector>,
    owner: Arc<Owner>,
    container: ContainerId,
    prover: Arc<dyn JoinProver>,
    keys: DevicePublicKeys,
    password: &'a Password,
    code: &'a RecoveryCode,
    claim: &'a RecoveryClaim,
    /// A claim was sent and no judged answer came back.
    unjudged: AtomicBool,
    stages: &'a watch::Sender<RecoverStage>,
}

impl Attempt<'_> {
    async fn run<J, S, P>(
        &self,
        account: &mut AccountOwner<J, S, P>,
    ) -> Result<Arc<AccountCapability>, RecoverError>
    where
        J: AccountJournal,
        S: DeviceKeyStore,
        P: PendingSetupProtector,
    {
        let mut channel = Channel::open(self.endpoint, self.connector.as_ref()).await?;
        let nonce = channel.nonce.take().ok_or(RecoverError::Unreachable)?;
        let released = claim(
            &mut channel,
            self.endpoint,
            self.claim,
            &nonce,
            RecoverPurpose::AddDevice,
        )
        .await
        .inspect_err(|error| {
            if *error == RecoverError::Unreachable {
                self.unjudged.store(true, Ordering::SeqCst);
            }
        })?;
        // The record names its account, authenticated by this password and
        // code; the genesis must be that account's.
        let account_id =
            recovery::account_of_record(released.record.expose(), self.password, self.code)
                .map_err(|_| RecoverError::Invalid)?;
        let genesis = AccountEvent::decode(&released.genesis).map_err(|_| RecoverError::Invalid)?;
        if AccountId::of_genesis(&genesis).ok() != Some(account_id) {
            return Err(RecoverError::Invalid);
        }
        let signer = Arc::new(Recovering::new(
            account_id,
            self.keys.id(),
            released.genesis.clone(),
            VerifiedAccount::from_genesis(account_id, &released.genesis)
                .map_err(|_| RecoverError::Invalid)?,
            self.prover.clone(),
        ));
        let (status, _) = watch::channel(SyncStatus::SavedLocal { pending: 0 });
        let shared = Shared::new(
            self.endpoint.clone(),
            self.connector.clone(),
            self.owner.clone(),
            self.container,
            signer.clone(),
            status,
            crate::Tuning::default(),
        );
        let mut link = Link::default();
        let result =
            Box::pin(self.finish(account, &shared, &mut link, &mut channel, &signer, released))
                .await;
        link.shutdown().await;
        shared.authz.stop();
        shared.authz.close().await;
        channel.close().await;
        result
    }

    async fn finish<J, S, P>(
        &self,
        account: &mut AccountOwner<J, S, P>,
        shared: &Shared,
        link: &mut Link,
        channel: &mut Channel,
        signer: &Arc<Recovering>,
        released: Released,
    ) -> Result<Arc<AccountCapability>, RecoverError>
    where
        J: AccountJournal,
        S: DeviceKeyStore,
        P: PendingSetupProtector,
    {
        let mut history = History::read(shared, link, &released.genesis, signer.account).await?;
        let opened = open_released(&history.state, &released, self.password, self.code)?;
        drop(released);
        if history.state.active_device(self.keys.id()).ok() != Some(&self.keys) {
            add(channel, shared, link, &history.state, &opened, &self.keys).await?;
            history.extend(shared, link).await?;
        }
        let (added_at, body) = history.added(&self.keys)?;
        signer.set_current(history.state.clone());
        // Authenticated as this device from here.
        let log = account_log(&signer.genesis)?;
        let frame = read_body(shared, link, log, body).await?;
        let frame = delivery_frame(&frame)
            .map_err(|_| RecoverError::Invalid)?
            .to_vec();
        let at_addition = history.at(added_at)?;
        personal::verify_device_delivery(&at_addition, &frame, &self.keys)
            .map_err(|_| RecoverError::Invalid)?;
        let entry = own_base_entry(shared, link, &history.state, &opened.personal).await?;
        let base = LogId {
            kind: LogKind::Base,
            id: entry.base,
        };
        let (genesis_descriptor, genesis_body) = base_genesis(shared, link, base).await?;
        let admission = CurrentAdmission {
            account: signer.account,
            history: history.timed(),
            added_at,
            delivery: frame,
            base: entry.base,
            genesis_descriptor,
            genesis_body,
            epoch_id: entry.epoch_id,
            metadata_seal: entry.metadata_seal,
            content_seal: entry.content_seal,
            hosting_root: self.endpoint.hosting_root,
        };
        let capability = admit_current(account, &self.owner, self.container, &admission)
            .await
            .map_err(|error| match error {
                JoinError::AwaitingAdmission => RecoverError::AwaitingAdmission,
                JoinError::OwnBase(OwnBaseError::Invalid | OwnBaseError::Seal(_))
                | JoinError::Account(
                    AccountOwnerError::Invalid(_) | AccountOwnerError::Refused(_),
                ) => RecoverError::Invalid,
                _ => RecoverError::Unreachable,
            })?;
        drop(admission);
        self.stages.send_replace(RecoverStage::Open);
        let database = self
            .owner
            .shared_database(self.container)
            .map_err(|_| RecoverError::Unreachable)?;
        let own = create_or_open(account, capability.clone(), database)
            .await
            .map_err(|_| RecoverError::Unreachable)?;
        // The account at the head the base's genesis names, as its package
        // seals record it.
        let anchor_at = own
            .initial_key_package()
            .ok()
            .and_then(|package| SealHeader::decode(package.metadata_seal()).ok())
            .ok_or(RecoverError::Unreachable)?
            .head
            .position;
        signer.set_anchor(
            account
                .verified_at(&capability, anchor_at)
                .map_err(|_| RecoverError::Unreachable)?,
        );
        signer.set_own_base(Arc::new(own));
        let joined = self
            .owner
            .joined(self.container)
            .map_err(|_| RecoverError::Unreachable)?
            .ok_or(RecoverError::Unreachable)?;
        if !joined.activated {
            let (progress, mut downloaded) = watch::channel(Progress::default());
            // Every report until the download ends with its sender.
            let report = async {
                loop {
                    let done = *downloaded.borrow_and_update();
                    self.stages.send_replace(RecoverStage::Downloading(done));
                    if downloaded.changed().await.is_err() {
                        return;
                    }
                }
            };
            let download = Box::pin(bootstrap::run(
                self.endpoint.clone(),
                self.connector.clone(),
                self.owner.clone(),
                self.container,
                signer.clone(),
                progress,
            ));
            match tokio::join!(download, report).0 {
                Ok(()) | Err(BootstrapError::Active) => {}
                Err(BootstrapError::Stopped | BootstrapError::Unsupported) => {
                    return Err(RecoverError::Invalid);
                }
                Err(_) => return Err(RecoverError::Unreachable),
            }
        }
        self.owner
            .authorize(self.container, capability.clone(), base.id)
            .map_err(|_| RecoverError::Unreachable)?;
        Box::pin(copy_all(shared, link, signer, &history, &opened.keys, base)).await?;
        Ok(capability)
    }
}

/// What a release carried: the account's genesis, its current record and
/// the personal key's seal to the recovery key.
struct Released {
    genesis: Vec<u8>,
    record: SecretBytes,
    recovery_seal: Vec<u8>,
}

/// Seal `claim` for this connection's `nonce` and `purpose`, and judge the
/// home's answer.
async fn claim(
    channel: &mut Channel,
    endpoint: &Endpoint,
    claim: &RecoveryClaim,
    nonce: &[u8; 32],
    purpose: RecoverPurpose,
) -> Result<Released, RecoverError> {
    endpoint
        .recovery_key
        .verify(&endpoint.hosting_root)
        .map_err(|_| RecoverError::Invalid)?;
    let sealed = recovery::seal_claim(&endpoint.recovery_key.public, claim, nonce, purpose as u8)
        .map_err(|_| RecoverError::Invalid)?;
    match channel.ask(ToService::Recover { sealed, purpose }).await? {
        FromService::Recovery(RecoveryAnswer::Released {
            genesis,
            record,
            recovery_seal,
        }) => Ok(Released {
            genesis,
            record: SecretBytes::from_vec(record),
            recovery_seal,
        }),
        FromService::Recovery(RecoveryAnswer::NotRecognised) => Err(RecoverError::NotRecognised),
        FromService::Recovery(RecoveryAnswer::PasswordMismatch {
            tries_left,
            next_try_ms,
        }) => Err(RecoverError::PasswordMismatch {
            tries_left,
            next_try_ms,
        }),
        FromService::Recovery(RecoveryAnswer::Wait { next_try_ms }) => {
            Err(RecoverError::Wait { next_try_ms })
        }
        _ => Err(RecoverError::Unreachable),
    }
}

/// Open the released record and seal as the ones `state` names current.
fn open_released(
    state: &VerifiedAccount,
    released: &Released,
    password: &Password,
    code: &RecoveryCode,
) -> Result<Unlocked, RecoverError> {
    let keys = recovery::open_current_record(state, released.record.expose(), password, code)
        .map_err(|_| RecoverError::Invalid)?;
    let personal = personal::open_for_recovery(state, &released.recovery_seal, keys.receiver())
        .map_err(|_| RecoverError::Invalid)?;
    Ok(Unlocked { keys, personal })
}

fn account_log(genesis: &[u8]) -> Result<LogId, RecoverError> {
    Ok(LogId {
        kind: LogKind::Account,
        id: account_log_id(genesis).map_err(|_| RecoverError::Invalid)?,
    })
}

fn evidence_failure(failure: EvidenceFailure) -> RecoverError {
    match failure {
        EvidenceFailure::Invalid => RecoverError::Invalid,
        EvidenceFailure::Unavailable(fail) => fail.into(),
    }
}

impl History {
    /// The account's whole history from its genesis, as public evidence.
    async fn read(
        shared: &Shared,
        link: &mut Link,
        genesis: &[u8],
        account: AccountId,
    ) -> Result<Self, RecoverError> {
        let mut history = Self {
            events: Vec::new(),
            outer: OrderState::EMPTY,
            prior: None,
            state: VerifiedAccount::from_genesis(account, genesis)
                .map_err(|_| RecoverError::Invalid)?,
        };
        history.extend_from(shared, link, genesis).await?;
        Ok(history)
    }

    /// Read on from where this history ends.
    async fn extend(&mut self, shared: &Shared, link: &mut Link) -> Result<(), RecoverError> {
        let genesis = self
            .events
            .first()
            .ok_or(RecoverError::Invalid)?
            .original
            .clone();
        self.extend_from(shared, link, &genesis).await
    }

    /// Every bounded page after `outer`, each verified under the hosting
    /// root, and every challenged head matched with its exact original and
    /// confirmation, until a short page ends at the challenged head.
    async fn extend_from(
        &mut self,
        shared: &Shared,
        link: &mut Link,
        genesis: &[u8],
    ) -> Result<(), RecoverError> {
        let mut pending = Vec::new();
        loop {
            let last = self
                .outer
                .position()
                .checked_add(64)
                .ok_or(RecoverError::Invalid)?;
            let page =
                account_evidence::read_public(shared, link, genesis, self.outer, self.prior, last)
                    .await
                    .map_err(evidence_failure)?;
            let count = page.events.len();
            account_evidence::match_page_claims(&mut pending, &page.events, page.accepted)
                .map_err(|_| RecoverError::Invalid)?;
            let ahead = page.accepted.original_head.position
                > page
                    .events
                    .last()
                    .map_or(self.outer.position(), |event| event.opening.position());
            for event in page.events {
                if event.opening.position() > 1 {
                    let time = event.time.ok_or(RecoverError::Invalid)?;
                    self.state
                        .apply_timed(
                            &event.original,
                            Some(ConfirmedTime {
                                earliest_ms: time.earliest_ms,
                                latest_ms: time.latest_ms,
                            }),
                        )
                        .map_err(|_| RecoverError::Invalid)?;
                } else if event.original != genesis {
                    return Err(RecoverError::Invalid);
                }
                self.outer = event.opening;
                self.prior = event.time.or(self.prior);
                self.events.push(event);
            }
            // A challenged head may name an entry read on an earlier page.
            let mut i = 0;
            while i < pending.len() {
                let position = pending[i].original_head.position;
                if position <= self.outer.position() {
                    let index =
                        usize::try_from(position.checked_sub(1).ok_or(RecoverError::Invalid)?)
                            .map_err(|_| RecoverError::Invalid)?;
                    let event = self.events.get(index).ok_or(RecoverError::Invalid)?;
                    account_evidence::match_accepted_event(pending[i], event)
                        .map_err(|_| RecoverError::Invalid)?;
                    pending.remove(i);
                } else {
                    i += 1;
                }
            }
            if count < 64 {
                if ahead || !pending.is_empty() {
                    return Err(RecoverError::Unreachable);
                }
                if self.events.is_empty() {
                    return Err(RecoverError::Invalid);
                }
                return Ok(());
            }
        }
    }

    /// Where `keys` were first added, still active at the end, and the body
    /// (the delivery) that addition carried.
    fn added(&self, keys: &DevicePublicKeys) -> Result<(u64, Digest), RecoverError> {
        if self.state.active_device(keys.id()).ok() != Some(keys) {
            return Err(RecoverError::Invalid);
        }
        let mut view = self.at(1)?;
        for (index, event) in self.events.iter().enumerate().skip(1) {
            let time = event.time.ok_or(RecoverError::Invalid)?;
            view.apply_timed(
                &event.original,
                Some(ConfirmedTime {
                    earliest_ms: time.earliest_ms,
                    latest_ms: time.latest_ms,
                }),
            )
            .map_err(|_| RecoverError::Invalid)?;
            if view.active_device(keys.id()).is_ok() {
                return Ok((index as u64 + 1, event.body.ok_or(RecoverError::Invalid)?));
            }
        }
        Err(RecoverError::Invalid)
    }

    /// The account at `position` of this history.
    fn at(&self, position: u64) -> Result<VerifiedAccount, RecoverError> {
        let (genesis, rest) = self.events.split_first().ok_or(RecoverError::Invalid)?;
        let mut view = VerifiedAccount::from_genesis(self.state.id(), &genesis.original)
            .map_err(|_| RecoverError::Invalid)?;
        let count =
            usize::try_from(position.saturating_sub(1)).map_err(|_| RecoverError::Invalid)?;
        for event in rest.iter().take(count) {
            let time = event.time.ok_or(RecoverError::Invalid)?;
            view.apply_timed(
                &event.original,
                Some(ConfirmedTime {
                    earliest_ms: time.earliest_ms,
                    latest_ms: time.latest_ms,
                }),
            )
            .map_err(|_| RecoverError::Invalid)?;
        }
        if view.head().position != position {
            return Err(RecoverError::Invalid);
        }
        Ok(view)
    }

    /// Each original with its confirmed time and exact confirmation.
    fn timed(&self) -> Vec<TimedOriginal> {
        self.events
            .iter()
            .map(|event| {
                (
                    event.original.clone(),
                    event.time.zip(event.proof.as_ref()).map(|(time, proof)| {
                        (
                            ConfirmedTime {
                                earliest_ms: time.earliest_ms,
                                latest_ms: time.latest_ms,
                            },
                            proof.encode().to_vec(),
                        )
                    }),
                )
            })
            .collect()
    }
}

/// Add this device with the recovery key, on the connection the release
/// opened as its recovery session: the signed addition with the personal
/// key sealed to this device, appended under the permits it answers and
/// confirmed. Verified history then shows the device, or another entry
/// that took its place; following decides, not this answer.
async fn add(
    channel: &mut Channel,
    shared: &Shared,
    link: &mut Link,
    state: &VerifiedAccount,
    opened: &Unlocked,
    keys: &DevicePublicKeys,
) -> Result<(), RecoverError> {
    let log = account_log(
        &shared
            .signer
            .identity()
            .map_err(|_| RecoverError::Invalid)?
            .genesis,
    )?;
    let event = state
        .add_device_by_recovery(keys.clone())
        .and_then(|request| request.finish_with_recovery(&opened.keys))
        .map_err(|_| RecoverError::Invalid)?;
    let frame =
        personal::seal_for_device_by_recovery(state, &opened.personal, &opened.keys, keys, &event)
            .map_err(|_| RecoverError::Invalid)?;
    let body = delivery_body(&frame).map_err(|_| RecoverError::Invalid)?;
    let wrapped = account_log_wrap(event.as_bytes(), Some(body.commitment()))
        .map_err(|_| RecoverError::Invalid)?;
    let answer = channel
        .ask(ToService::SubmitControl {
            log,
            event: event.as_bytes().to_vec(),
            delivery: Some(Box::new(Delivery {
                recipient: keys.clone(),
                frame,
            })),
            attachment: None,
        })
        .await?;
    let FromService::Permits { items } = answer else {
        // Not the account's next entry now: reading it again decides.
        return Err(RecoverError::Unreachable);
    };
    let [stage, append] = <[_; 2]>::try_from(items).map_err(|_| RecoverError::Unreachable)?;
    let (stage, append) = (granted(stage)?, granted(append)?);
    let data = link.data(shared).await?;
    let bytes = body.bytes().to_vec();
    let staged = data
        .ask(|id| Request::Stage {
            id,
            permit: stage,
            body: bytes,
        })
        .await
        .map_err(|_| RecoverError::Unreachable)?;
    if !matches!(staged, Response::Staged { .. }) {
        return Err(RecoverError::Unreachable);
    }
    let encoded = wrapped.encode();
    match data
        .ask(|id| Request::Append {
            id,
            permit: append,
            event: encoded,
        })
        .await
        .map_err(|_| RecoverError::Unreachable)?
    {
        Response::Acked { ack, .. } => {
            let ack = AppendAck::decode(&ack).map_err(|_| RecoverError::Unreachable)?;
            if ack.log != log
                || ack.event != wrapped.publication_id(bh_sync::Route::Control)
                || ack.head.position != state.head().position + 1
            {
                return Err(RecoverError::Invalid);
            }
        }
        _ => return Err(RecoverError::Unreachable),
    }
    // Its order, confirmed for a fresh challenge under the hosting root.
    let challenge: [u8; 32] = bh_crypto::random();
    let FromService::Confirmed { confirmation, head } = channel
        .ask(ToService::ConfirmControl {
            log,
            event: wrapped.digest(),
            challenge,
        })
        .await?
    else {
        return Err(RecoverError::Unreachable);
    };
    let root = shared.endpoint.hosting_root;
    let proof = OrderingConfirmation::decode(&confirmation).map_err(|_| RecoverError::Invalid)?;
    let claim = proof
        .verify_for(&root, event.as_bytes(), Some(body.commitment()))
        .map_err(|_| RecoverError::Invalid)?;
    let accepted =
        AcceptedHead::verify(&head, &root, log, &challenge).map_err(|_| RecoverError::Invalid)?;
    let expected = Head {
        position: state.head().position + 1,
        hash: Digest(bh_crypto::hash(event.as_bytes())),
    };
    if claim.log != log
        || claim.original_head != expected
        || claim.original_previous
            != (Head {
                position: state.head().position,
                hash: Digest(state.head().hash),
            })
        || accepted.original_head.position < expected.position
    {
        return Err(RecoverError::Invalid);
    }
    Ok(())
}

/// One body of `log`, checked against its commitment.
async fn read_body(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    body: Digest,
) -> Result<Vec<u8>, RecoverError> {
    let answer = {
        let mut session = shared.authz.session(shared).await.map_err(Fail::from)?;
        session
            .ask(ToService::Permits {
                items: vec![Want::ReadBodies {
                    log,
                    bodies: vec![body],
                }],
            })
            .await
            .map_err(Fail::from)?
    };
    let permit = only(answer)?;
    let data = link.data(shared).await?;
    match data
        .ask(|id| Request::Read { id, permit })
        .await
        .map_err(|_| RecoverError::Unreachable)?
    {
        Response::Body {
            index: 0, bytes, ..
        } if BodyObject::new(bytes.clone()).is_ok_and(|o| o.commitment() == body) => Ok(bytes),
        Response::Body { .. } => Err(RecoverError::Invalid),
        _ => Err(RecoverError::Unreachable),
    }
}

/// The own base's directory entry, as the account's current personal key
/// opens it: its newest version.
struct BaseEntry {
    base: [u8; 32],
    epoch_id: [u8; 32],
    metadata_seal: Vec<u8>,
    content_seal: Vec<u8>,
    own: bool,
}

/// The one base whose newest entry, signed by a device of the account,
/// marks it the account's own. Other bases' entries are left for their
/// own admission; two own bases are refused.
async fn own_base_entry(
    shared: &Shared,
    link: &mut Link,
    state: &VerifiedAccount,
    personal: &PersonalKey,
) -> Result<BaseEntry, RecoverError> {
    let entries = crate::directory::read(shared, link).await?;
    let mut newest: BTreeMap<[u8; 32], (u64, BaseEntry)> = BTreeMap::new();
    for bytes in entries {
        // An entry this history does not authenticate is not the account's.
        let Ok(opened) = open_entry(state, personal, &bytes) else {
            continue;
        };
        let DirectoryEntry::Base {
            base,
            epoch_id,
            current_key_seal,
            metadata_seal,
            own,
            ..
        } = opened.entry
        else {
            continue;
        };
        if newest
            .get(&base)
            .is_none_or(|(version, _)| *version < opened.version)
        {
            newest.insert(
                base,
                (
                    opened.version,
                    BaseEntry {
                        base,
                        epoch_id,
                        metadata_seal,
                        content_seal: current_key_seal,
                        own,
                    },
                ),
            );
        }
    }
    let mut own = newest
        .into_values()
        .map(|(_, entry)| entry)
        .filter(|entry| entry.own);
    match (own.next(), own.next()) {
        (Some(entry), None) => Ok(entry),
        // No entry yet: a device of the account writes it, once it runs.
        (None, _) => Err(RecoverError::Unreachable),
        (Some(_), Some(_)) => Err(RecoverError::Invalid),
    }
}

/// The base's genesis as its log orders it first, and its body.
async fn base_genesis(
    shared: &Shared,
    link: &mut Link,
    base: LogId,
) -> Result<(Vec<u8>, Vec<u8>), RecoverError> {
    let (items, _) = read_events_exclusive(shared, link, base, 1, 1).await?;
    let ordered = ordered_events(BaseId(base.id), 1, &items)?;
    let [(commitment, descriptor)] = ordered.as_slice() else {
        return Err(RecoverError::Unreachable);
    };
    if commitment
        .verify_next(BaseId(base.id), Head::EMPTY)
        .is_err()
        || BaseId::from_genesis(descriptor) != BaseId(base.id)
    {
        return Err(RecoverError::Invalid);
    }
    let body = read_body(
        shared,
        link,
        base,
        referenced_body(descriptor).map_err(|_| RecoverError::Invalid)?,
    )
    .await?;
    Ok((descriptor.encode(), body))
}

/// Copy every account entry the base lacks into it, signed with the
/// recovery key, and wait until the base holds them: runs of at most 64,
/// each entry with the confirmation the history was verified with.
async fn copy_all(
    shared: &Shared,
    link: &mut Link,
    signer: &Recovering,
    history: &History,
    keys: &RecoveryKeys,
    base: LogId,
) -> Result<(), RecoverError> {
    let mut receiver = Receiver::default();
    receiver.watch(shared, None);
    let anchor = signer.anchor();
    let head = history.state.head().position;
    loop {
        let reached = copied(shared, link, &mut receiver, base).await?;
        if reached >= head {
            return Ok(());
        }
        let first = usize::try_from(reached).map_err(|_| RecoverError::Invalid)?;
        let entries = history.events[first..]
            .iter()
            .take(bh_event::account_run::MAX_RUN)
            .map(|event| {
                Ok((
                    event.original.clone(),
                    event
                        .proof
                        .as_ref()
                        .ok_or(RecoverError::Invalid)?
                        .encode()
                        .to_vec(),
                ))
            })
            .collect::<Result<Vec<_>, RecoverError>>()?;
        let mut prepared = None;
        signer
            .with_metadata_key(BaseId(base.id), &mut |m| {
                prepared = Some(
                    shared
                        .owner
                        .plan_account_copy(shared.container, &anchor, m, &entries)
                        .and_then(|plan| match plan {
                            CopyPlan::Run(n) => shared
                                .owner
                                .prepare_account_run_copy(
                                    shared.container,
                                    &anchor,
                                    m,
                                    &entries[..n],
                                    bh_event::Copier::Recovery,
                                )
                                .map(Some),
                            // A rotation the base must rekey for: its key
                            // comes only with an admission snapshot.
                            CopyPlan::Rekey => Ok(None),
                        })
                        .map(|request| (request, MetadataKey::new(m))),
                );
            })
            .map_err(|_| RecoverError::Unreachable)?;
        let (request, metadata) = prepared
            .ok_or(RecoverError::Unreachable)?
            .map_err(|_| RecoverError::Invalid)?;
        let request = request.ok_or(RecoverError::AwaitingAdmission)?;
        let signature = keys
            .sign_base_control(
                &history.state,
                request.expected_key(),
                request.signing_bytes(),
            )
            .map_err(|_| RecoverError::Invalid)?;
        let encoded = request
            .finish(signature)
            .map_err(|_| RecoverError::Invalid)?;
        match submit(shared, link, base, encoded, metadata).await {
            Ok(position) => receiver.exists(position),
            // Another copy took its place, or the base moved on: read it.
            Err(RecoverError::Unreachable) => receiver.recheck(),
            Err(error) => return Err(error),
        }
        // The copy is the base's once this device read and verified it.
        let mut reads = 0;
        while copied(shared, link, &mut receiver, base).await? <= reached {
            reads += 1;
            if reads >= COPY_READS {
                return Err(RecoverError::Unreachable);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

/// How far the base's verified copy of the account reaches, after reading
/// the base on.
async fn copied(
    shared: &Shared,
    link: &mut Link,
    receiver: &mut Receiver,
    base: LogId,
) -> Result<u64, RecoverError> {
    receiver.take_news();
    puller::pull(shared, link, receiver, base).await?;
    Ok(shared
        .owner
        .verified_copy(shared.container, base)
        .map_err(|_| RecoverError::Unreachable)?
        .ok_or(RecoverError::Unreachable)?
        .account
        .0)
}

/// Send one signed copy: its permits, its body, its append. The base
/// position its append was acknowledged at.
async fn submit(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    encoded: bh_event::Encoded,
    metadata: MetadataKey,
) -> Result<u64, RecoverError> {
    let descriptor = encoded.descriptor.encode();
    let event_id = encoded.descriptor.publication_id(bh_sync::Route::Control);
    let answer = {
        let mut session = shared.authz.session(shared).await.map_err(Fail::from)?;
        session
            .ask(ToService::SubmitBaseControl {
                log,
                descriptor: descriptor.clone(),
                body: encoded.body.clone(),
                metadata,
            })
            .await
            .map_err(Fail::from)?
    };
    let FromService::Permits { items } = answer else {
        return match answer {
            FromService::Refused {
                reason: Refusal::Invalid | Refusal::Conflict,
            } => Err(RecoverError::Unreachable),
            other => Err(Fail::from_answer(&other).into()),
        };
    };
    let [stage, append] = <[_; 2]>::try_from(items).map_err(|_| RecoverError::Unreachable)?;
    let (stage, append) = (granted(stage)?, granted(append)?);
    let data = link.data(shared).await?;
    let body = encoded.body;
    if !matches!(
        data.ask(|id| Request::Stage {
            id,
            permit: stage,
            body,
        })
        .await
        .map_err(|_| RecoverError::Unreachable)?,
        Response::Staged { .. }
    ) {
        return Err(RecoverError::Unreachable);
    }
    match data
        .ask(|id| Request::Append {
            id,
            permit: append,
            event: descriptor,
        })
        .await
        .map_err(|_| RecoverError::Unreachable)?
    {
        Response::Acked { ack, .. } => {
            let ack = AppendAck::decode(&ack).map_err(|_| RecoverError::Unreachable)?;
            let proven = ack.receipt.is_some_and(|r| {
                receipt::verify(&shared.endpoint.hosting_root, BaseId(log.id), &r)
                    .is_ok_and(|r| r.head() == ack.head)
            });
            if ack.log != log || ack.event != event_id || !proven {
                return Err(RecoverError::Unreachable);
            }
            Ok(ack.head.position)
        }
        Response::Refused {
            reason: wire::Refusal::Predecessor | wire::Refusal::Conflict,
            ..
        } => Err(RecoverError::Unreachable),
        other => Err(Fail::from_response(&other).into()),
    }
}

/// Check this account's password and kit on a running client and open its
/// current recovery keys, to sign a change that needs them. The service
/// counts a wrong password as a try, as for recovery; a wrong code is not
/// recognised and costs none.
pub(crate) async fn keys(
    shared: &Shared,
    password: &Password,
    code: &RecoveryCode,
) -> Result<RecoveryKeys, RecoverError> {
    let identity = shared
        .signer
        .identity()
        .map_err(|_| RecoverError::Unreachable)?;
    let claim_bytes = recovery::claim(password, code).map_err(|_| RecoverError::Invalid)?;
    let mut channel = Channel::open(&shared.endpoint, shared.connector.as_ref()).await?;
    let result = async {
        let nonce = channel.nonce.ok_or(RecoverError::Unreachable)?;
        let context = Context {
            channel_binding: channel
                .session
                .binding()
                .map_err(|_| RecoverError::Unreachable)?,
            challenge: nonce,
        };
        let proof = shared
            .signer
            .device_proof(context)
            .await
            .map_err(|_| RecoverError::Unreachable)?;
        match channel
            .ask(ToService::Authenticate {
                proof: Box::new(*proof.as_bytes()),
                account: identity.account,
                device: identity.device,
                genesis: identity.genesis.clone(),
            })
            .await?
        {
            FromService::Authenticated { .. } => {}
            _ => return Err(RecoverError::Unreachable),
        }
        let released = claim(
            &mut channel,
            &shared.endpoint,
            &claim_bytes,
            &nonce,
            RecoverPurpose::Sign,
        )
        .await?;
        if released.genesis != identity.genesis {
            return Err(RecoverError::Invalid);
        }
        let state = shared
            .signer
            .current_account()
            .map_err(|_| RecoverError::Unreachable)?;
        recovery::open_current_record(&state, released.record.expose(), password, code)
            .map_err(|_| RecoverError::Invalid)
    }
    .await;
    channel.close().await;
    result
}

impl Client {
    /// Check this account's password and kit with its home, for a change
    /// the recovery key must sign, and open the current recovery keys. A
    /// wrong password uses a try; a wrong code is `NotRecognised` and uses
    /// none. Keep the keys no longer than that change needs.
    pub async fn recovery_keys(
        &self,
        password: &Password,
        code: &RecoveryCode,
    ) -> Result<RecoveryKeys, RecoverError> {
        keys(&self.shared, password, code).await
    }
}

/// The policy a recovery connection accepted, for its own life.
struct Policy(Option<Snapshot>);
impl PolicyStore for Policy {
    type Error = ();
    fn load(&mut self) -> Result<StoredState, ()> {
        Ok(self
            .0
            .clone()
            .map_or(StoredState::Fresh, StoredState::Committed))
    }
    fn save(&mut self, snapshot: &Snapshot) -> Result<(), ()> {
        self.0 = Some(snapshot.clone());
        Ok(())
    }
}

fn sample() -> Sample {
    static START: std::sync::LazyLock<std::time::Instant> =
        std::sync::LazyLock::new(std::time::Instant::now);
    Sample {
        system_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs()),
        monotonic_ms: START.elapsed().as_millis() as u64,
    }
}

/// One attested connection to the authorization service that is not
/// authenticated as a device when it opens: its challenge is the nonce of
/// one recovery claim, and a released claim makes it the account's recovery
/// session for the one device addition it permits.
struct Channel {
    socket: Socket,
    session: Session<Policy>,
    nonce: Option<[u8; 32]>,
}

impl Channel {
    async fn open(endpoint: &Endpoint, connector: &dyn Connector) -> Result<Self, RecoverError> {
        tokio::time::timeout(ANSWER_WAIT, Self::handshake(endpoint, connector))
            .await
            .map_err(|_| RecoverError::Unreachable)?
    }

    async fn handshake(
        endpoint: &Endpoint,
        connector: &dyn Connector,
    ) -> Result<Self, RecoverError> {
        let unsupported = |_| RecoverError::Unreachable;
        let policy = PolicyContext::new(
            endpoint.app_root,
            endpoint.limits,
            endpoint.build_floor,
            Policy(None),
            sample,
        )
        .map_err(unsupported)?;
        if !endpoint.policy.is_empty() {
            policy
                .deliver_policy(&endpoint.policy, &endpoint.policy_signature)
                .map_err(unsupported)?;
        }
        let mut socket = connector
            .connect(Route::Authz)
            .await
            .map_err(|_| RecoverError::Unreachable)?;
        let channel = |_| RecoverError::Unreachable;
        let hello = ClientHello::new(policy).map_err(channel)?;
        send(&mut socket, hello.frame().to_vec()).await?;
        let proof = receive(&mut socket).await?;
        let checked = match endpoint.appraisal {
            crate::Appraisal::Hardware => hello.accept_proof(&proof),
            #[cfg(feature = "synthetic-attestation")]
            crate::Appraisal::Synthetic => hello.accept_synthetic_proof(&proof),
        }
        .map_err(channel)?;
        let (encapsulation, pending) = checked.encapsulate().map_err(channel)?;
        send(&mut socket, encapsulation).await?;
        let finish = receive(&mut socket).await?;
        let (confirm, session) = pending.accept_finish(&finish).map_err(channel)?;
        send(&mut socket, confirm).await?;
        let mut opened = Self {
            socket,
            session,
            nonce: None,
        };
        match opened.receive().await? {
            FromService::Challenge { challenge } => opened.nonce = Some(challenge),
            _ => return Err(RecoverError::Unreachable),
        }
        Ok(opened)
    }

    async fn receive(&mut self) -> Result<FromService, RecoverError> {
        let frame = receive(&mut self.socket).await?;
        match self.session.open(&frame) {
            Ok(Opened::Data(plain)) => {
                FromService::decode(plain.expose()).map_err(|_| RecoverError::Unreachable)
            }
            _ => Err(RecoverError::Unreachable),
        }
    }

    async fn ask(&mut self, message: ToService) -> Result<FromService, RecoverError> {
        let plain = SecretBytes::from_vec(message.encode().map_err(|_| RecoverError::Invalid)?);
        drop(message);
        let sealed = self
            .session
            .seal(plain)
            .map_err(|_| RecoverError::Unreachable)?;
        send(&mut self.socket, sealed).await?;
        match tokio::time::timeout(ANSWER_WAIT, self.receive()).await {
            Ok(answer) => answer,
            Err(_) => Err(RecoverError::Unreachable),
        }
    }

    async fn close(&mut self) {
        let _ = self.socket.close().await;
    }
}

async fn receive(socket: &mut Socket) -> Result<Vec<u8>, RecoverError> {
    loop {
        match tokio::time::timeout(ANSWER_WAIT, socket.next()).await {
            Ok(Some(Ok(Message::Binary(bytes)))) => return Ok(bytes.to_vec()),
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            _ => return Err(RecoverError::Unreachable),
        }
    }
}

async fn send(socket: &mut Socket, bytes: Vec<u8>) -> Result<(), RecoverError> {
    socket
        .send(Message::Binary(bytes.into()))
        .await
        .map_err(|_| RecoverError::Unreachable)
}

/// The recovering device's standing for the client's reads: who it is, the
/// account as recovery verified it, its possession proof, and once its own
/// base opened, that base's keys. It signs nothing and holds no account
/// authority of its own.
struct Recovering {
    account: AccountId,
    device: DeviceId,
    genesis: Vec<u8>,
    prover: Arc<dyn JoinProver>,
    current: Mutex<VerifiedAccount>,
    /// The account at the head the own base's genesis names.
    anchor: Mutex<VerifiedAccount>,
    own_base: Mutex<Option<Arc<OwnBase>>>,
}

impl Recovering {
    fn new(
        account: AccountId,
        device: DeviceId,
        genesis: Vec<u8>,
        at_genesis: VerifiedAccount,
        prover: Arc<dyn JoinProver>,
    ) -> Self {
        Self {
            account,
            device,
            genesis,
            prover,
            current: Mutex::new(at_genesis.clone()),
            anchor: Mutex::new(at_genesis),
            own_base: Mutex::new(None),
        }
    }
    fn set_current(&self, current: VerifiedAccount) {
        *self.current.lock().expect("recovering account") = current;
    }
    fn set_anchor(&self, anchor: VerifiedAccount) {
        *self.anchor.lock().expect("recovering anchor") = anchor;
    }
    fn anchor(&self) -> VerifiedAccount {
        self.anchor.lock().expect("recovering anchor").clone()
    }
    fn set_own_base(&self, own: Arc<OwnBase>) {
        *self.own_base.lock().expect("recovering base") = Some(own);
    }
    fn own(&self, base: BaseId) -> Result<Arc<OwnBase>, SignerError> {
        self.own_base
            .lock()
            .expect("recovering base")
            .clone()
            .filter(|own| own.id() == base)
            .ok_or(SignerError)
    }
}

impl Signer for Recovering {
    fn identity(&self) -> Result<Identity, SignerError> {
        Ok(Identity {
            account: self.account,
            device: self.device,
            genesis: self.genesis.clone(),
            anchor: self.anchor(),
        })
    }
    fn device_proof(&self, context: Context) -> BoxFuture<'_, Result<Proof, SignerError>> {
        let head = self.current.lock().expect("recovering account").head();
        self.prover.joining_proof(self.account, head, context)
    }
    fn device_proof_at(
        &self,
        head: AccountHead,
        context: Context,
    ) -> BoxFuture<'_, Result<Proof, SignerError>> {
        self.prover.joining_proof(self.account, head, context)
    }
    fn initial_home_setup(&self) -> Result<Option<HomeSetup>, SignerError> {
        Ok(None)
    }
    fn confirm_home_ordered(
        &self,
        _: &HomeSetup,
        _: [(ConfirmedTime, Vec<u8>); 2],
    ) -> Result<(), SignerError> {
        Err(SignerError)
    }
    fn sign_event(&self, _: Vec<u8>) -> BoxFuture<'_, Result<[u8; 64], SignerError>> {
        Box::pin(async { Err(SignerError) })
    }
    fn current_account(&self) -> Result<VerifiedAccount, SignerError> {
        Ok(self.current.lock().expect("recovering account").clone())
    }
    // Recovery verified the history it holds; nothing more is applied here.
    fn apply_account_timed(
        &self,
        _: AccountHead,
        _: Vec<TimedOriginal>,
    ) -> BoxFuture<'_, Result<AccountHead, AccountApplyError>> {
        Box::pin(async { Err(AccountApplyError::Unavailable) })
    }
    fn observe_account_accepted(
        &self,
        _: AccountHead,
        _: ConfirmedTime,
    ) -> Result<(), SignerError> {
        Err(SignerError)
    }
    fn sign_base_control(
        &self,
        _: BaseControlRequest,
    ) -> BoxFuture<'_, Result<[u8; 64], ControlSignError>> {
        Box::pin(async { Err(ControlSignError::Unavailable) })
    }
    fn with_metadata_key(
        &self,
        base: BaseId,
        use_key: &mut dyn FnMut(&Secret<32>),
    ) -> Result<(), SignerError> {
        self.own(base)?
            .with_metadata_key(|metadata| use_key(metadata))
            .map_err(|_| SignerError)
    }
    fn with_epoch_keys(
        &self,
        base: BaseId,
        epoch: Option<[u8; 32]>,
        use_keys: &mut dyn FnMut(&Secret<32>, Option<&Secret<32>>),
    ) -> Result<(), SignerError> {
        self.own(base)?
            .with_epoch_key(epoch, |metadata, content| use_keys(metadata, content))
            .map_err(|_| SignerError)
    }
    // A later epoch's key comes only with an admission snapshot.
    fn install_epoch(&self, _: SealWait, _: Vec<u8>) -> BoxFuture<'_, Result<(), InstallError>> {
        Box::pin(async { Err(InstallError::Unavailable) })
    }
    fn staged_control(&self) -> Result<Option<StagedControl>, SignerError> {
        Err(SignerError)
    }
    fn stage_rotation(&self, _: u64) -> BoxFuture<'_, Result<StagedControl, SignerError>> {
        Box::pin(async { Err(SignerError) })
    }
    fn settle_staged(&self) -> Result<Option<Settlement>, SignerError> {
        Err(SignerError)
    }
    fn discard_staged(&self, _: &StagedControl) -> Result<(), SignerError> {
        Err(SignerError)
    }
    fn accept_rotation(&self, _: u64, _: Vec<u8>) -> BoxFuture<'_, Result<(), SignerError>> {
        Box::pin(async { Err(SignerError) })
    }
    fn prepare_base_entry(
        &self,
        _: BaseId,
        _: [u8; 32],
        _: String,
        _: u64,
    ) -> BoxFuture<'_, Result<Vec<u8>, SignerError>> {
        Box::pin(async { Err(SignerError) })
    }
    fn open_directory_entries(
        &self,
        _: Vec<Vec<u8>>,
    ) -> BoxFuture<'_, Result<OpenedEntries, SignerError>> {
        Box::pin(async { Err(SignerError) })
    }
    fn directory_state(&self) -> Result<Option<(u64, bool)>, SignerError> {
        Err(SignerError)
    }
    fn set_directory_state(&self, _: u64, _: bool) -> Result<(), SignerError> {
        Err(SignerError)
    }
    // It opens no directory and writes no entry of its own: its name and any
    // check are written by the device's own signer once recovery finishes.
    fn own_entries(&self) -> BoxFuture<'_, Result<crate::OwnEntries, SignerError>> {
        Box::pin(async { Err(SignerError) })
    }
    fn own_entry_held(&self, _: [u8; 32], _: u64) -> Result<(), SignerError> {
        Err(SignerError)
    }
    fn directory_wanted(&self) -> bool {
        false
    }
    fn directory_read(&self, _: crate::DirectoryRead) {}
}
