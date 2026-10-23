//! QR pairing through the edge's relay.
//!
//! The device already in the account shows a code (`qr_text`): the account,
//! the showing device, a session and a one-time secret. The relay is named
//! by a keyed hash of that secret and never sees it; every relay message is
//! sealed with keys derived from it. The new device replies with its own
//! journaled keys, authenticated with the secret; the showing device checks
//! the reply, and a second, different reply ends the session.
//!
//! Approval is one action the person takes on the showing device: its
//! control key signs exactly this addition once, the current personal key is
//! sealed to the new device, and both are staged before anything is sent.
//! The same approval covers the addition's copy into the own base: a
//! single-use approval of that exact account event, until the session's end.
//! The client orders the staged bytes and copies them; cancelling after
//! staging ends the code, not the admission.
//!
//! The showing device then sends one hint, sealed with the secret: the
//! account's genesis, the head after the addition, and its own base with the
//! base's key package. A hint is not admission. The new device authenticates
//! with its own key, reads the account log from genesis and verifies it from
//! the code's account, each event after the genesis with its confirmation
//! verified under the hosting root, requires an addition of exactly its keys carrying a
//! delivery to it, and reads the own base's genesis from its log; only then
//! may the host commit it, those confirmations with it
//! (`bh_device::join::admit`).
use crate::{
    AccountApplyError, Client, ClientError, ControlSignError, Endpoint, HomeSetup, Identity,
    Shared, Signer, SignerError, SyncStatus, TimedOriginal,
    backoff::Backoff,
    outbox::{Fail, Link},
    puller::{only, ordered_events, read_events_exclusive},
    transport::Connector,
};
use base64::{
    Engine as _,
    alphabet::URL_SAFE,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use bh_account::{
    AccountEvent, AccountId, ConfirmedTime, DeviceId, DevicePublicKeys, Head as AccountHead,
    VerifiedAccount,
    device_auth::{Context, Proof},
    journal::{AccountJournal, PendingSetupProtector},
    owner::{AccountCapability, AccountOwner, OwnerError},
    pairing::{PairError, Reply, ShowingSession},
    personal::{self, PersonalKey},
    platform::DeviceKeyStore,
};
use bh_authz_proto::{ToService, Want, account_log_id, delivery_frame};
use bh_crypto::Secret;
use bh_device::{ContainerId, Owner, join::Admission};
use bh_sync::{
    BaseId, BodyObject, Digest, Head, OrderState,
    permit::{LogId, LogKind},
    referenced_body,
    wire::{Request, Response},
};
use futures_util::future::BoxFuture;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::watch, time::Instant};

pub use crate::relay::{Got, HttpRelay, Put, Relay, Side};
pub use bh_account::pairing::{QrCode, RelayKeys};

/// The text a code shows and a scanner reads: this prefix, then the 122
/// code bytes in base64url without padding (163 characters in all).
pub const QR_PREFIX: &str = "BH1:";
/// A pairing's life on both devices: the relay's five minutes, counted from
/// the code (showing) or the reply (joining), which start no later.
pub const SESSION_LIFE: Duration = Duration::from_secs(300);
/// Replies a showing device reads: the relay keeps four per side.
const REPLIES: u8 = 4;
const POLL_FIRST: Duration = Duration::from_millis(250);
const POLL_CAP: Duration = Duration::from_secs(2);
/// Network retries while verifying an admission.
const VERIFY_ATTEMPTS: usize = 8;
const HINT_DOMAIN: &[u8; 8] = b"BHPHNT01";

const ENGINE: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone),
);

/// The code as text. It carries the secret: show it, never log or keep it.
pub fn qr_text(code: &QrCode) -> String {
    let bytes = code.encode();
    format!("{QR_PREFIX}{}", ENGINE.encode(bytes))
}

/// Read a code's text: exactly the prefix and canonical base64url.
pub fn parse_qr_text(text: &str) -> Result<QrCode, PairingError> {
    let encoded = text.strip_prefix(QR_PREFIX).ok_or(PairingError::Invalid)?;
    let bytes = ENGINE.decode(encoded).map_err(|_| PairingError::Invalid)?;
    let code = QrCode::decode(&bytes).map_err(PairingError::Pair)?;
    // One text per code: a decoder that accepted other spellings would let
    // two texts name one session.
    if ENGINE.encode(&bytes) != encoded {
        return Err(PairingError::Invalid);
    }
    Ok(code)
}

/// Fixed, content-free pairing failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingError {
    /// The session ended: cancelled, past its five minutes, or ended by a
    /// competing reply.
    Ended,
    /// A second, different reply arrived; the session has ended.
    Competing,
    /// The code, a reply or the hint did not decode or authenticate, or
    /// names another account.
    Invalid,
    /// Verified history does not admit this device, or the service refused
    /// it.
    Refused,
    Pair(PairError),
    /// The account owner could not act (locked, stale, a prompt cancelled).
    Owner(OwnerError),
    Network,
    Local,
}

/// The reply a showing device verified.
#[derive(Clone, PartialEq, Eq)]
pub struct Candidate {
    pub keys: DevicePublicKeys,
    pub label: Vec<u8>,
}
impl std::fmt::Debug for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Candidate(..)")
    }
}

/// Approvals of base-control copies the person gave: at most one, of the
/// copy of exactly one account event, used once, until it expires. A host's
/// `Signer::sign_base_control` consults it; nothing else is signed.
#[derive(Clone, Default)]
pub struct Approvals(Arc<Mutex<Option<Approval>>>);
/// The exact account event whose copy is approved, and until when.
type Approval = (Vec<u8>, Instant);
impl Approvals {
    /// Approve the base copy of `event` (its exact bytes) until `until`.
    pub fn grant(&self, event: Vec<u8>, until: Instant) {
        *self.0.lock().expect("approvals") = Some((event, until));
    }
    /// Whether copying `copies` is approved now; an approval is used up by
    /// the request it covers.
    pub fn take(&self, copies: &[u8]) -> bool {
        let mut approval = self.0.lock().expect("approvals");
        match approval.as_ref() {
            Some((_, until)) if Instant::now() >= *until => {
                *approval = None;
                false
            }
            Some((event, _)) if event.as_slice() == copies => {
                *approval = None;
                true
            }
            _ => false,
        }
    }
}

/// What the showing device sends the joining one once the addition is
/// ordered: a hint, sealed with the code's secret. None of it is trusted:
/// the genesis is checked against the code's account, the head by the
/// service, and the base and its key package against verified history.
#[derive(Clone, PartialEq, Eq)]
pub struct AdmissionHint {
    /// The account's original genesis event.
    pub genesis: Vec<u8>,
    /// The account head after the addition.
    pub head: AccountHead,
    /// The account's own base.
    pub base: [u8; 32],
    /// The own base's initial key package, sealed to the personal key.
    pub package: Vec<u8>,
}
impl AdmissionHint {
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(8 + 2 + self.genesis.len() + 40 + 32 + 2 + self.package.len());
        out.extend_from_slice(HINT_DOMAIN);
        out.extend_from_slice(&(self.genesis.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.genesis);
        out.extend_from_slice(&self.head.position.to_be_bytes());
        out.extend_from_slice(&self.head.hash);
        out.extend_from_slice(&self.base);
        out.extend_from_slice(&(self.package.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.package);
        out
    }
    pub fn decode(raw: &[u8]) -> Result<Self, PairingError> {
        let invalid = PairingError::Invalid;
        let mut input = raw.strip_prefix(HINT_DOMAIN.as_slice()).ok_or(invalid)?;
        let mut take = |n: usize| -> Result<&[u8], PairingError> {
            let (head, rest) = input.split_at_checked(n).ok_or(invalid)?;
            input = rest;
            Ok(head)
        };
        let len = u16::from_be_bytes(take(2)?.try_into().unwrap()) as usize;
        let genesis = take(len)?.to_vec();
        let position = u64::from_be_bytes(take(8)?.try_into().unwrap());
        let hash = take(32)?.try_into().unwrap();
        let base = take(32)?.try_into().unwrap();
        let len = u16::from_be_bytes(take(2)?.try_into().unwrap()) as usize;
        let package = take(len)?.to_vec();
        if !input.is_empty() || genesis.is_empty() || package.is_empty() {
            return Err(invalid);
        }
        Ok(Self {
            genesis,
            head: AccountHead { position, hash },
            base,
            package,
        })
    }
    /// The sealed relay message.
    pub fn seal(&self, keys: &RelayKeys) -> Vec<u8> {
        keys.seal_show(&self.encode()).expect("bounded hint")
    }
}

async fn pause(backoff: &mut Duration, deadline: Instant) {
    let wait = (*backoff).min(deadline.saturating_duration_since(Instant::now()));
    tokio::time::sleep(wait).await;
    *backoff = (*backoff * 2).min(POLL_CAP);
}

/// The device in the account, showing a code.
pub struct ShowingPairing {
    session: ShowingSession,
    relay: Arc<dyn Relay>,
    keys: RelayKeys,
    deadline: Instant,
    candidate: Option<Candidate>,
    /// The exact staged addition, or `None` with `added` for a candidate the
    /// account already holds.
    staged: Option<Vec<u8>>,
    added: bool,
    ended: bool,
}

impl ShowingPairing {
    /// Start a session for `device` of `account`. Returns the code's text.
    pub fn start(account: AccountId, device: DeviceId, relay: Arc<dyn Relay>) -> (Self, String) {
        let session = ShowingSession::new(account, device);
        let text = qr_text(&session.qr().expect("a new session is live"));
        let keys = session.relay().expect("a new session is live");
        (
            Self {
                session,
                relay,
                keys,
                deadline: Instant::now() + SESSION_LIFE,
                candidate: None,
                staged: None,
                added: false,
                ended: false,
            },
            text,
        )
    }

    fn end(&mut self) {
        self.session.cancel();
        self.ended = true;
    }
    fn live(&mut self) -> Result<(), PairingError> {
        if !self.ended && Instant::now() >= self.deadline {
            self.end();
        }
        if self.ended {
            Err(PairingError::Ended)
        } else {
            Ok(())
        }
    }

    /// Wait for a verified reply. Every reply the relay holds is checked:
    /// one that does not authenticate is ignored, and a second, different
    /// one ends the session. Call again just before staging, to see a late
    /// competitor.
    pub async fn candidate(&mut self) -> Result<Candidate, PairingError> {
        let mut backoff = POLL_FIRST;
        loop {
            self.live()?;
            let mut found = None;
            for index in 0..REPLIES {
                match self.relay.get(self.keys.name(), Side::Join, index).await {
                    Ok(Got::Message(sealed)) => {
                        let Some(reply) = self
                            .keys
                            .open_join(&sealed)
                            .ok()
                            .and_then(|opened| Reply::decode(opened.expose()).ok())
                        else {
                            continue;
                        };
                        match self.session.receive(&reply) {
                            Ok(keys) => {
                                found.get_or_insert(Candidate {
                                    keys,
                                    label: reply.label,
                                });
                            }
                            Err(PairError::CompetingReply) => {
                                self.end();
                                return Err(PairingError::Competing);
                            }
                            Err(PairError::Ended) => {
                                self.end();
                                return Err(PairingError::Ended);
                            }
                            Err(_) => {}
                        }
                    }
                    Ok(Got::Expired) => {
                        self.end();
                        return Err(PairingError::Ended);
                    }
                    Ok(Got::Empty) | Err(_) => break,
                }
            }
            if let Some(candidate) = found {
                self.candidate = Some(candidate.clone());
                return Ok(candidate);
            }
            pause(&mut backoff, self.deadline).await;
        }
    }

    /// The person approved the candidate. Sign exactly its addition with the
    /// control key (the one confirmation), seal the current personal key to
    /// it, and stage both before anything is sent; then approve the
    /// addition's base copy until the session's end. Nothing reaches the
    /// network here, and nothing is staged if the code ended while the
    /// prompt was open. A candidate the account already holds needs no
    /// signature: only the hint is sent.
    pub async fn stage<J, S, P>(
        &mut self,
        account: &mut AccountOwner<J, S, P>,
        capability: &AccountCapability,
        personal: &PersonalKey,
        approvals: &Approvals,
    ) -> Result<(), PairingError>
    where
        J: AccountJournal,
        S: DeviceKeyStore,
        P: PendingSetupProtector,
    {
        self.live()?;
        let request = match self.session.prepare_with_re_read(account, capability) {
            Ok(request) => request,
            Err(PairError::AlreadyAdded) => {
                let candidate = self
                    .candidate
                    .as_ref()
                    .ok_or(PairingError::Pair(PairError::NoReply))?;
                let verified = account.verified(capability).map_err(PairingError::Owner)?;
                if verified.active_device(candidate.keys.id()).ok() != Some(&candidate.keys) {
                    return Err(PairingError::Refused);
                }
                self.added = true;
                return Ok(());
            }
            Err(PairError::Ended) => return Err(PairingError::Ended),
            Err(error) => return Err(PairingError::Pair(error)),
        };
        let keys = self
            .candidate
            .as_ref()
            .ok_or(PairingError::Pair(PairError::NoReply))?
            .keys
            .clone();
        let event = account
            .sign_control(capability, &request)
            .await
            .map_err(PairingError::Owner)?;
        let delivery = account
            .seal_personal_for_device(capability, personal, &keys, &event)
            .await
            .map_err(PairingError::Owner)?;
        // The prompt may be answered after the code ended: late bytes are
        // never staged, sent or approved for a copy.
        self.live()?;
        self.session
            .stage_journal(account, capability, event.as_bytes(), &delivery)
            .map_err(|error| match error {
                PairError::Ended => PairingError::Ended,
                other => PairingError::Pair(other),
            })?;
        // The admission outlives the code; so does the approval of its copy,
        // for long enough to order and copy it.
        approvals.grant(
            event.as_bytes().to_vec(),
            self.deadline.max(Instant::now() + SESSION_LIFE),
        );
        self.staged = Some(event.as_bytes().to_vec());
        Ok(())
    }

    /// Wait until `client` has ordered the staged addition and its account
    /// owner verified it, then, unless the session was cancelled, send the
    /// joining device its hint. Returns the account head after the
    /// addition. The client copies it into the own base under the approval.
    pub async fn finish(&mut self, client: &Client) -> Result<AccountHead, PairingError> {
        let shared = &client.shared;
        // A stopped client orders nothing; the staged addition waits for
        // the next start.
        let stopped = || shared.authz.is_stopped();
        if stopped() {
            return Err(PairingError::Local);
        }
        let candidate = self
            .candidate
            .clone()
            .ok_or(PairingError::Pair(PairError::NoReply))?;
        let head = if self.added {
            shared
                .signer
                .current_account()
                .map_err(|_| PairingError::Local)?
                .head()
        } else {
            let staged = self
                .staged
                .as_ref()
                .ok_or(PairingError::Pair(PairError::NoReply))?;
            let target = AccountEvent::decode(staged)
                .map_err(|_| PairingError::Local)?
                .head();
            let wait_until = self.deadline.max(Instant::now() + Duration::from_secs(30));
            let mut woken = Instant::now();
            client.wake();
            loop {
                if stopped() {
                    return Err(PairingError::Local);
                }
                if woken.elapsed() >= Duration::from_secs(1) {
                    client.wake();
                    woken = Instant::now();
                }
                let current = shared
                    .signer
                    .current_account()
                    .map_err(|_| PairingError::Local)?;
                if current.head().position >= target.position {
                    if current.active_device(candidate.keys.id()).ok() != Some(&candidate.keys) {
                        return Err(PairingError::Refused);
                    }
                    break target;
                }
                if Instant::now() >= wait_until {
                    return Err(PairingError::Network);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        if self.ended {
            return Ok(head);
        }
        let identity = shared.signer.identity().map_err(|_| PairingError::Local)?;
        let record = shared
            .owner
            .shared_database(shared.container)
            .map_err(|_| PairingError::Local)?
            .lock()
            .expect("container writer lock")
            .own_base()
            .map_err(|_| PairingError::Local)?
            .ok_or(PairingError::Local)?;
        let hint = AdmissionHint {
            genesis: identity.genesis,
            head,
            base: record.base,
            package: record.initial_key_package,
        }
        .seal(&self.keys);
        // At the first free index: bytes someone else put first do not
        // open with the secret, and the joining device skips them.
        let mut backoff = POLL_FIRST;
        let mut index = 0;
        loop {
            if stopped() {
                return Err(PairingError::Local);
            }
            match self
                .relay
                .put(self.keys.name(), Side::Show, index, hint.clone())
                .await
            {
                Ok(Put::Stored) => break,
                Ok(Put::Taken) if index + 1 < REPLIES => index += 1,
                Ok(Put::Expired) => {
                    self.end();
                    return Err(PairingError::Ended);
                }
                Ok(_) => return Err(PairingError::Invalid),
                Err(_) if Instant::now() < self.deadline => {
                    pause(&mut backoff, self.deadline).await
                }
                Err(_) => return Err(PairingError::Network),
            }
        }
        self.end();
        Ok(head)
    }

    /// End the code. After staging, the admission still completes.
    pub fn cancel(&mut self) {
        self.end();
    }
}

/// Possession of the joining device's journaled ordinary key at a head of
/// `account` it cannot verify yet (`AccountOwner::prove_joining`). The
/// service checks it against its own verified history.
pub trait JoinProver: Send + Sync {
    fn joining_proof(
        &self,
        account: AccountId,
        head: AccountHead,
        context: Context,
    ) -> BoxFuture<'_, Result<Proof, SignerError>>;
}

/// The device that scanned a code.
pub struct JoiningPairing {
    code: QrCode,
    keys: DevicePublicKeys,
    relay: Arc<dyn Relay>,
    deadline: Instant,
}

impl JoiningPairing {
    /// Reply to the code with this device's journaled keys
    /// (`pairing::scanner_identity`), authenticated with its secret.
    pub async fn join(
        text: &str,
        keys: DevicePublicKeys,
        label: &[u8],
        relay: Arc<dyn Relay>,
    ) -> Result<Self, PairingError> {
        let code = parse_qr_text(text)?;
        let names = code.relay();
        let reply = names
            .seal_join(
                &Reply::make(&code, keys.clone(), label)
                    .map_err(PairingError::Pair)?
                    .encode(),
            )
            .map_err(PairingError::Pair)?;
        let name = names.name();
        // The first free index: another device may have replied first, and
        // the showing device then ends the session.
        let mut stored = false;
        for index in 0..REPLIES {
            match relay.put(name, Side::Join, index, reply.clone()).await {
                Ok(Put::Stored) => {
                    stored = true;
                    break;
                }
                Ok(Put::Taken) => continue,
                Ok(Put::Full | Put::Expired) => return Err(PairingError::Ended),
                Ok(Put::Refused) => return Err(PairingError::Invalid),
                Err(_) => return Err(PairingError::Network),
            }
        }
        if !stored {
            return Err(PairingError::Ended);
        }
        Ok(Self {
            code,
            keys,
            relay,
            deadline: Instant::now() + SESSION_LIFE,
        })
    }

    /// Wait for the showing device's hint, keep it, then verify this
    /// device's admission (see the module). Refused or invalid: nothing
    /// is committed; the host commits a returned admission with
    /// `bh_device::join::admit`.
    pub async fn wait_admitted(
        &mut self,
        endpoint: &Endpoint,
        connector: Arc<dyn Connector>,
        owner: Arc<Owner>,
        container: ContainerId,
        prover: Arc<dyn JoinProver>,
    ) -> Result<Admission, PairingError> {
        let names = self.code.relay();
        let mut backoff = POLL_FIRST;
        // The first showing-side message that opens with the secret.
        let mut index = 0;
        let opened = loop {
            if Instant::now() >= self.deadline {
                return Err(PairingError::Ended);
            }
            match self.relay.get(names.name(), Side::Show, index).await {
                Ok(Got::Message(sealed)) => match names.open_show(&sealed) {
                    Ok(opened) => break opened,
                    Err(_) if index + 1 < REPLIES => index += 1,
                    Err(_) => return Err(PairingError::Invalid),
                },
                Ok(Got::Expired) => return Err(PairingError::Ended),
                Ok(Got::Empty) | Err(_) => pause(&mut backoff, self.deadline).await,
            }
        };
        let hint = AdmissionHint::decode(opened.expose())?;
        let genesis = AccountEvent::decode(&hint.genesis).map_err(|_| PairingError::Invalid)?;
        if AccountId::of_genesis(&genesis).ok() != Some(self.code.account) {
            return Err(PairingError::Invalid);
        }
        owner
            .record_join_hint(container, self.code.account, opened.expose())
            .map_err(|_| PairingError::Local)?;
        verify(
            endpoint,
            connector,
            owner,
            container,
            prover,
            self.code.account,
            &self.keys,
            hint,
            crate::Tuning::default(),
        )
        .await
    }
}

/// Verify a kept hint's admission again, after an interruption before it
/// was committed. `None` once the container holds a committed admission.
pub async fn resume_admission(
    endpoint: &Endpoint,
    connector: Arc<dyn Connector>,
    owner: Arc<Owner>,
    container: ContainerId,
    keys: &DevicePublicKeys,
    prover: Arc<dyn JoinProver>,
) -> Result<Option<Admission>, PairingError> {
    resume_admission_with(
        endpoint,
        connector,
        owner,
        container,
        keys,
        prover,
        crate::Tuning::default(),
    )
    .await
}

/// As `resume_admission`, with test pacing: see `Tuning`.
#[cfg(feature = "test-support")]
pub async fn resume_admission_tuned(
    endpoint: &Endpoint,
    connector: Arc<dyn Connector>,
    owner: Arc<Owner>,
    container: ContainerId,
    keys: &DevicePublicKeys,
    prover: Arc<dyn JoinProver>,
    tuning: crate::Tuning,
) -> Result<Option<Admission>, PairingError> {
    resume_admission_with(endpoint, connector, owner, container, keys, prover, tuning).await
}

async fn resume_admission_with(
    endpoint: &Endpoint,
    connector: Arc<dyn Connector>,
    owner: Arc<Owner>,
    container: ContainerId,
    keys: &DevicePublicKeys,
    prover: Arc<dyn JoinProver>,
    tuning: crate::Tuning,
) -> Result<Option<Admission>, PairingError> {
    let joined = owner
        .joined(container)
        .map_err(|_| PairingError::Local)?
        .ok_or(PairingError::Pair(PairError::NoReply))?;
    if joined.delivery.is_some() {
        return Ok(None);
    }
    let hint = AdmissionHint::decode(&joined.hint)?;
    verify(
        endpoint,
        connector,
        owner,
        container,
        prover,
        AccountId(joined.account),
        keys,
        hint,
        tuning,
    )
    .await
    .map(Some)
}

/// The joining device's identity before it holds any history: the code's
/// account, the hint's genesis and head, and its own proof.
struct Joining {
    account: AccountId,
    device: DeviceId,
    genesis: Vec<u8>,
    anchor: VerifiedAccount,
    head: AccountHead,
    prover: Arc<dyn JoinProver>,
}
impl Signer for Joining {
    fn identity(&self) -> Result<Identity, SignerError> {
        Ok(Identity {
            account: self.account,
            device: self.device,
            genesis: self.genesis.clone(),
            anchor: self.anchor.clone(),
        })
    }
    fn device_proof(&self, context: Context) -> BoxFuture<'_, Result<Proof, SignerError>> {
        self.prover.joining_proof(self.account, self.head, context)
    }
    fn device_proof_at(
        &self,
        _: AccountHead,
        context: Context,
    ) -> BoxFuture<'_, Result<Proof, SignerError>> {
        self.prover.joining_proof(self.account, self.head, context)
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
        Ok(self.anchor.clone())
    }
    // Nothing is applied before the admission commits its verified history.
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
        _: crate::BaseControlRequest,
    ) -> BoxFuture<'_, Result<[u8; 64], ControlSignError>> {
        Box::pin(async { Err(ControlSignError::Unavailable) })
    }
    fn with_metadata_key(
        &self,
        _: BaseId,
        _: &mut dyn FnMut(&Secret<32>),
    ) -> Result<(), SignerError> {
        Err(SignerError)
    }
    fn with_epoch_keys(
        &self,
        _: BaseId,
        _: Option<[u8; 32]>,
        _: &mut dyn FnMut(&Secret<32>, Option<&Secret<32>>),
    ) -> Result<(), SignerError> {
        Err(SignerError)
    }
    fn install_epoch(
        &self,
        _: bh_device::control::SealWait,
        _: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), bh_device::control::InstallError>> {
        Box::pin(async { Err(bh_device::control::InstallError::Unavailable) })
    }
    // No account authority here: every trust and directory use is refused.
    fn staged_control(&self) -> Result<Option<bh_account::journal::StagedControl>, SignerError> {
        Err(SignerError)
    }
    fn stage_rotation(
        &self,
        _: u64,
    ) -> BoxFuture<'_, Result<bh_account::journal::StagedControl, SignerError>> {
        Box::pin(async { Err(SignerError) })
    }
    fn settle_staged(&self) -> Result<Option<bh_account::owner::staging::Settlement>, SignerError> {
        Err(SignerError)
    }
    fn discard_staged(&self, _: &bh_account::journal::StagedControl) -> Result<(), SignerError> {
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
    ) -> BoxFuture<'_, Result<crate::OpenedEntries, SignerError>> {
        Box::pin(async { Err(SignerError) })
    }
    fn directory_state(&self) -> Result<Option<(u64, bool)>, SignerError> {
        Err(SignerError)
    }
    fn set_directory_state(&self, _: u64, _: bool) -> Result<(), SignerError> {
        Err(SignerError)
    }
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

/// Why verifying an admission stopped: retry the network, or give up.
enum Stop {
    Retry,
    Error(PairingError),
}
impl From<Fail> for Stop {
    fn from(fail: Fail) -> Self {
        match fail {
            Fail::Network | Fail::Retry | Fail::Missing => Self::Retry,
            Fail::Authorization | Fail::Unregistered => Self::Error(PairingError::Refused),
            Fail::Unsupported | Fail::Local | Fail::Stopped => Self::Error(PairingError::Local),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn verify(
    endpoint: &Endpoint,
    connector: Arc<dyn Connector>,
    owner: Arc<Owner>,
    container: ContainerId,
    prover: Arc<dyn JoinProver>,
    account: AccountId,
    keys: &DevicePublicKeys,
    hint: AdmissionHint,
    tuning: crate::Tuning,
) -> Result<Admission, PairingError> {
    let anchor =
        VerifiedAccount::from_genesis(account, &hint.genesis).map_err(|_| PairingError::Invalid)?;
    let signer = Arc::new(Joining {
        account,
        device: keys.id(),
        genesis: hint.genesis.clone(),
        anchor,
        head: hint.head,
        prover,
    });
    let (status, _) = watch::channel(SyncStatus::SavedLocal { pending: 0 });
    let shared = Shared::new(
        endpoint.clone(),
        connector,
        owner,
        container,
        signer,
        status,
        tuning,
    );
    let mut link = Link::default();
    let mut backoff = Backoff::default();
    let mut result = Err(PairingError::Network);
    for _ in 0..VERIFY_ATTEMPTS {
        match admission(&shared, &mut link, account, keys, &hint).await {
            Ok(admission) => {
                result = Ok(admission);
                break;
            }
            Err(Stop::Error(error)) => {
                result = Err(error);
                break;
            }
            Err(Stop::Retry) => {
                link.drop_data();
                // The retry decision is unchanged; a test may only skip the
                // shipped backoff's wall-clock wait (`Tuning::verify_retry`).
                let wait = tuning.verify_retry.unwrap_or_else(|| backoff.next());
                tokio::time::sleep(wait).await;
            }
        }
    }
    shared.authz.close().await;
    result
}

/// Where `events`, the account's original history from genesis verified
/// from `account` with each confirmed time, first adds exactly `keys`,
/// which are still active at its end: that position, the body (the
/// delivery) the addition carries, and the account just after it.
fn admitted_in(
    account: AccountId,
    keys: &DevicePublicKeys,
    events: &[(TimedOriginal, Option<Digest>)],
) -> Result<(u64, Digest, VerifiedAccount), PairingError> {
    let refused = PairingError::Refused;
    let (genesis, rest) = events.split_first().ok_or(refused)?;
    let mut view = VerifiedAccount::from_genesis(account, &genesis.0.0).map_err(|_| refused)?;
    let mut added = None;
    for (index, ((original, evidence), body)) in rest.iter().enumerate() {
        let time = evidence.as_ref().map(|(time, _)| *time).ok_or(refused)?;
        view.apply_timed(original, Some(time))
            .map_err(|_| refused)?;
        if added.is_none() && view.active_device(keys.id()).is_ok() {
            added = Some((index as u64 + 2, *body, view.clone()));
        }
    }
    if view.active_device(keys.id()).ok() != Some(keys) {
        return Err(refused);
    }
    let (position, body, at) = added.ok_or(refused)?;
    Ok((position, body.ok_or(refused)?, at))
}

/// One body of `log`, checked against its commitment.
async fn read_body(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    body: Digest,
) -> Result<Vec<u8>, Fail> {
    let answer = {
        let mut session = shared.authz.session(shared).await?;
        session
            .ask(ToService::Permits {
                items: vec![Want::ReadBodies {
                    log,
                    bodies: vec![body],
                }],
            })
            .await?
    };
    let permit = only(answer)?;
    let data = link.data(shared).await?;
    match data
        .ask(|id| Request::Read { id, permit })
        .await
        .map_err(|_| Fail::Network)?
    {
        Response::Body {
            index: 0, bytes, ..
        } if BodyObject::new(bytes.clone()).is_ok_and(|o| o.commitment() == body) => Ok(bytes),
        Response::Refused { .. } => Err(Fail::Missing),
        _ => Err(Fail::Network),
    }
}

async fn admission(
    shared: &Shared,
    link: &mut Link,
    account: AccountId,
    keys: &DevicePublicKeys,
    hint: &AdmissionHint,
) -> Result<Admission, Stop> {
    // Authenticate first: a refusal here is this device not being active
    // at the head the hint names.
    match shared.authz.session(shared).await {
        Ok(_) => {}
        Err(ClientError::Refused(_)) => return Err(Stop::Error(PairingError::Refused)),
        Err(ClientError::Signer | ClientError::Local) => {
            return Err(Stop::Error(PairingError::Local));
        }
        Err(ClientError::Unsupported) => return Err(Stop::Error(PairingError::Local)),
        Err(_) => return Err(Stop::Retry),
    }
    let log = LogId {
        kind: LogKind::Account,
        id: account_log_id(&hint.genesis).map_err(|_| Stop::Error(PairingError::Invalid))?,
    };
    // Verify each bounded account page before treating its wrappers as an
    // admission history. The service's head may be ahead of a page.
    let genesis = AccountEvent::decode(&hint.genesis).map_err(|_| Stop::Retry)?;
    if AccountId::of_genesis(&genesis).map_err(|_| Stop::Retry)? != account {
        return Err(Stop::Error(PairingError::Refused));
    }
    // Keep each independently verified opening with its original and proof.
    // A later challenged head can name any already-read position, including
    // the last item of a full page when the next page is empty.
    let mut events: Vec<crate::account_evidence::VerifiedEvent> = Vec::new();
    let mut outer = OrderState::EMPTY;
    let mut prior = None;
    let mut pending = Vec::new();
    loop {
        let last = outer.position().checked_add(64).ok_or(Stop::Retry)?;
        let page = crate::account_evidence::read(
            shared,
            link,
            &hint.genesis,
            outer,
            prior,
            last,
            crate::account_evidence::Session::Exclusive,
        )
        .await?;
        let count = page.events.len();
        crate::account_evidence::match_page_claims(&mut pending, &page.events, page.accepted)?;
        let ahead = page.accepted.original_head.position
            > page
                .events
                .last()
                .map_or(outer.position(), |e| e.opening.position());
        if let Some(last) = page.events.last() {
            outer = last.opening;
            prior = last.time.or(prior);
        }
        events.extend(page.events);
        // A new response can challenge an already-read original (notably
        // the empty terminal response after an exact 64-entry page). Index
        // the collected history rather than replaying it on every page.
        let mut i = 0;
        while i < pending.len() {
            let position = pending[i].original_head.position;
            if position <= outer.position() {
                let index = usize::try_from(position.checked_sub(1).ok_or(Stop::Retry)?)
                    .map_err(|_| Stop::Retry)?;
                let event = events.get(index).ok_or(Stop::Retry)?;
                crate::account_evidence::match_accepted_event(pending[i], event)?;
                pending.remove(i);
            } else {
                i += 1;
            }
        }
        if count < 64 {
            if ahead || !pending.is_empty() {
                return Err(Stop::Retry);
            }
            break;
        }
    }
    let events: Vec<(TimedOriginal, Option<Digest>)> = events
        .into_iter()
        .map(|event| {
            let evidence = event.time.zip(event.proof).map(|(time, proof)| {
                (
                    ConfirmedTime {
                        earliest_ms: time.earliest_ms,
                        latest_ms: time.latest_ms,
                    },
                    proof.encode().to_vec(),
                )
            });
            ((event.original, evidence), event.body)
        })
        .collect();
    if events.first().map(|((genesis, _), _)| genesis) != Some(&hint.genesis) {
        return Err(Stop::Error(PairingError::Refused));
    }
    let (added_at, body, at_addition) = admitted_in(account, keys, &events).map_err(Stop::Error)?;
    let delivery = read_body(shared, link, log, body).await?;
    let frame = delivery_frame(&delivery)
        .map_err(|_| Stop::Error(PairingError::Refused))?
        .to_vec();
    personal::verify_device_delivery(&at_addition, &frame, keys)
        .map_err(|_| Stop::Error(PairingError::Refused))?;
    // The own base's genesis, as its log orders it first.
    let base = LogId {
        kind: LogKind::Base,
        id: hint.base,
    };
    let (items, _) = read_events_exclusive(shared, link, base, 1, 1).await?;
    let ordered = ordered_events(BaseId(hint.base), 1, &items)?;
    let [(commitment, descriptor)] = ordered.as_slice() else {
        return Err(Stop::Error(PairingError::Refused));
    };
    if commitment
        .verify_next(BaseId(hint.base), Head::EMPTY)
        .is_err()
        || BaseId::from_genesis(descriptor) != BaseId(hint.base)
    {
        return Err(Stop::Error(PairingError::Refused));
    }
    let genesis_body = read_body(
        shared,
        link,
        base,
        referenced_body(descriptor).map_err(|_| Stop::Error(PairingError::Refused))?,
    )
    .await?;
    Ok(Admission {
        account,
        history: events.into_iter().map(|(timed, _)| timed).collect(),
        added_at,
        delivery: frame,
        base: hint.base,
        genesis_descriptor: descriptor.encode(),
        genesis_body,
        package: hint.package.clone(),
        hosting_root: shared.endpoint.hosting_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_account::{AccountEvent, crypto::KemKey, recovery::RecoveryKeys};
    use bh_crypto::SigningKey;

    struct Key {
        control: SigningKey,
        keys: DevicePublicKeys,
    }
    fn key() -> Key {
        let control = SigningKey::generate();
        let keys = DevicePublicKeys::new(
            SigningKey::generate().public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        Key { control, keys }
    }
    /// An account of `first`, then additions of `added` signed by `first`.
    fn history(first: &Key, added: &[&DevicePublicKeys]) -> (AccountId, Vec<Vec<u8>>) {
        let draft = AccountEvent::genesis(first.keys.clone(), RecoveryKeys::generate().public());
        let genesis = draft
            .finish(first.control.sign(draft.signing_bytes()))
            .unwrap();
        let account = AccountId::of_genesis(&genesis).unwrap();
        let mut view = VerifiedAccount::from_genesis(account, genesis.as_bytes()).unwrap();
        let mut events = vec![genesis.as_bytes().to_vec()];
        for keys in added {
            let draft = view.add_device(first.keys.id(), (*keys).clone()).unwrap();
            let event = draft
                .finish(first.control.sign(draft.signing_bytes()))
                .unwrap();
            view.apply(event.as_bytes()).unwrap();
            events.push(event.as_bytes().to_vec());
        }
        (account, events)
    }
    /// Each event after the genesis with a verified confirmation.
    fn with(events: &[Vec<u8>], body: Option<Digest>) -> Vec<(TimedOriginal, Option<Digest>)> {
        events
            .iter()
            .enumerate()
            .map(|(index, e)| {
                let at = index as u64 * 10;
                let time = ConfirmedTime {
                    earliest_ms: at,
                    latest_ms: at + 2,
                };
                let evidence = (index > 0).then(|| (time, b"proof".to_vec()));
                ((e.clone(), evidence), body)
            })
            .collect()
    }

    #[test]
    fn admission_needs_exactly_this_devices_addition_with_its_delivery() {
        let first = key();
        let joining = key();
        let other = key();
        let delivery = Some(Digest([7; 32]));
        let (account, events) = history(&first, &[&other.keys, &joining.keys]);
        let (position, body, at) =
            admitted_in(account, &joining.keys, &with(&events, delivery)).unwrap();
        assert_eq!((position, body), (3, Digest([7; 32])));
        assert_eq!(at.head().position, 3);
        // Another device's addition alone, no delivery, another account, or
        // altered history: refused.
        assert_eq!(
            admitted_in(account, &joining.keys, &with(&events[..2], delivery)).err(),
            Some(PairingError::Refused)
        );
        assert_eq!(
            admitted_in(account, &joining.keys, &with(&events, None)).err(),
            Some(PairingError::Refused)
        );
        let (elsewhere, _) = history(&other, &[]);
        assert_eq!(
            admitted_in(elsewhere, &joining.keys, &with(&events, delivery)).err(),
            Some(PairingError::Refused)
        );
        let mut altered = events.clone();
        let last = altered[2].len() - 1;
        altered[2][last] ^= 1;
        assert_eq!(
            admitted_in(account, &joining.keys, &with(&altered, delivery)).err(),
            Some(PairingError::Refused)
        );
        // The same device id with other keys is not this device.
        let mut lookalike = joining.keys.clone();
        lookalike = DevicePublicKeys::new(
            *lookalike.signing(),
            *lookalike.control(),
            KemKey::generate().public(),
        )
        .unwrap();
        assert!(admitted_in(account, &lookalike, &with(&events, delivery)).is_err());
        // An event after the genesis without its confirmation.
        let mut untimed = with(&events, delivery);
        untimed[1].0.1 = None;
        assert_eq!(
            admitted_in(account, &joining.keys, &untimed).err(),
            Some(PairingError::Refused)
        );
    }

    #[test]
    fn qr_text_is_one_canonical_spelling() {
        let session = ShowingSession::new(AccountId([1; 32]), DeviceId([2; 32]));
        let code = session.qr().unwrap();
        let text = qr_text(&code);
        assert_eq!(text.len(), 4 + 163, "122 bytes are 163 characters");
        assert!(text.starts_with("BH1:"));
        assert_eq!(parse_qr_text(&text).unwrap().encode(), code.encode());
        // The last character carries two unused bits: setting one spells the
        // same bytes another way.
        let last = text.as_bytes()[text.len() - 1];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let value = alphabet.iter().position(|c| *c == last).unwrap();
        let other = format!("{}{}", &text[..text.len() - 1], alphabet[value ^ 1] as char);
        for bad in [
            text[4..].to_string(),
            format!("BH2:{}", &text[4..]),
            format!("{text}="),
            format!("{text}A"),
            format!("{}+{}", &text[..10], &text[11..]),
            text[..text.len() - 1].to_string(),
            other,
        ] {
            assert!(parse_qr_text(&bad).is_err(), "{}", bad.len());
        }
    }

    #[test]
    fn hint_round_trips_strictly() {
        let hint = AdmissionHint {
            genesis: vec![1; 2700],
            head: AccountHead {
                position: 4,
                hash: [2; 32],
            },
            base: [3; 32],
            package: vec![4; 3016],
        };
        let encoded = hint.encode();
        assert!(encoded.len() < 8192 - 40, "fits one relay message sealed");
        assert!(AdmissionHint::decode(&encoded).unwrap() == hint);
        assert!(AdmissionHint::decode(&encoded[..encoded.len() - 1]).is_err());
        assert!(AdmissionHint::decode(&[encoded.as_slice(), &[0]].concat()).is_err());
    }
}
