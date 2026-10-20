//! QR pairing for windows: an account's bound note window shows a code and
//! approves the device that scanned it; the unbound setup window of a
//! device without an account joins by a scanned or pasted code.
//!
//! Sessions and tickets are opaque handles owned here, tied to the window
//! that made them (and, for showing, its page and account). The page names
//! no account, base, container, key or path. Showing stages its approval as
//! local native work with the account's lent owner (its one confirmation),
//! then waits for the client to order the addition without holding that
//! owner. Joining uses this device's one scanner identity, verifies its
//! admission, commits it, then bootstraps before any note opens; an
//! interrupted join resumes from what it kept.
use crate::{
    accounts::{AccountOperation, HostKeyStore, JoinLease, JoinRefused, Screen, SharedAccountHost},
    sync::{HostSigner, SyncHandle, SyncHost, Transport},
};
use bh_account::{
    AccountId, DevicePublicKeys, Head as AccountHead,
    device_auth::{Context, Proof},
    journal::{AccountJournal, PendingSetupProtector},
    owner::{AccountCapability, AccountLoad, OwnerError},
    platform::KeyStoreError,
    storage::DeviceJournal,
};
use bh_device::{ContainerId, join::Admission, own_base::OwnBase};
use bh_sync_client::{
    SignerError,
    bootstrap::{self, BootstrapError, Progress},
    pairing::{JoinProver, JoiningPairing, PairingError, ShowingPairing, parse_qr_text},
};
use futures_util::future::{BoxFuture, LocalBoxFuture};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, watch};

/// Which window, on which page and for which account, is asking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub window: String,
    pub page: Option<u64>,
    pub container: Option<ContainerId>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Shown {
    pub session: String,
    pub qr_text: String,
    pub qr_svg: String,
}

/// A showing session as its window sees it. `label` is the scanning
/// device's own unverified name, as plain text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PairingStatus {
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}
impl PairingStatus {
    fn of(state: &'static str) -> Self {
        Self {
            state,
            label: None,
            reason: None,
        }
    }
}

#[derive(Serialize)]
pub struct Ticket {
    pub ticket: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JoinStatus {
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub done: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}
impl JoinStatus {
    fn of(state: &'static str) -> Self {
        Self {
            state,
            done: None,
            total: None,
            reason: None,
        }
    }
    fn ended(state: &'static str, reason: &'static str) -> Self {
        Self {
            reason: Some(reason),
            ..Self::of(state)
        }
    }
}

/// Why a pairing command was refused: fixed text for the page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No such session or ticket for this window, page and account.
    Session,
    /// Not a BaseHero pairing code.
    Code,
    /// This device already has an account.
    AccountExists,
    Busy,
    /// No sync in this build, or the account is not ready.
    Unavailable,
}
impl Refusal {
    pub fn message(self) -> &'static str {
        match self {
            Self::Session => "pairing session unavailable",
            Self::Code => "pairing code invalid",
            Self::AccountExists => "account exists",
            Self::Busy => "account busy",
            Self::Unavailable => "pairing unavailable",
        }
    }
}

/// A new device's name as plain text: no control characters, at most 64
/// characters, never markup the page parses.
pub fn label(raw: &[u8]) -> Option<String> {
    let text: String = String::from_utf8_lossy(raw)
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let text: String = text.trim().chars().take(64).collect();
    (!text.is_empty()).then_some(text)
}

/// The code drawn as one SVG path of dark modules with a four-module quiet
/// zone: no text, script, style or links. Colours come from the page's CSS.
pub fn qr_svg(text: &str) -> Option<String> {
    use std::fmt::Write;
    let code =
        qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M).ok()?;
    let width = code.width();
    let colors = code.to_colors();
    let size = width + 8;
    let mut path = String::new();
    for (at, color) in colors.iter().enumerate() {
        if *color == qrcode::Color::Dark {
            let (x, y) = (at % width + 4, at / width + 4);
            write!(path, "M{x} {y}h1v1h-1z").ok()?;
        }
    }
    Some(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\"><path d=\"{path}\"/></svg>"
    ))
}

fn failed(reason: &'static str) -> PairingStatus {
    PairingStatus {
        reason: Some(reason),
        ..PairingStatus::of("failed")
    }
}

fn reason(error: PairingError) -> &'static str {
    match error {
        PairingError::Ended => "expired",
        PairingError::Competing => "competing",
        PairingError::Invalid | PairingError::Pair(_) => "invalid",
        PairingError::Refused => "refused",
        PairingError::Owner(OwnerError::Device(KeyStoreError::AuthenticationCancelled)) => {
            "not-confirmed"
        }
        PairingError::Network => "network",
        PairingError::Owner(_) | PairingError::Local => "unavailable",
    }
}

/// A staging that did not happen. Late answers to an ended code show as
/// expired, never as ordered.
pub fn staging_failed(error: PairingError) -> PairingStatus {
    failed(reason(error))
}

enum Command {
    Approve,
    Cancel,
}

struct Showing {
    scope: Scope,
    status: Arc<Mutex<PairingStatus>>,
    commands: mpsc::UnboundedSender<Command>,
    task: tokio::task::JoinHandle<()>,
}

struct Joining {
    window: String,
    status: Arc<Mutex<JoinStatus>>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
struct Inner {
    showing: Mutex<HashMap<String, Showing>>,
    joining: Mutex<HashMap<String, Joining>>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        for showing in self.showing.get_mut().expect("showing").values() {
            showing.task.abort();
        }
        for joining in self.joining.get_mut().expect("joining").values() {
            joining.task.abort();
        }
    }
}

/// The app's pairing sessions and join tickets.
#[derive(Clone, Default)]
pub struct PairingHost(Arc<Inner>);

fn handle() -> String {
    bh_crypto::random::<16>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn set<T>(status: &Mutex<T>, value: T) {
    *status.lock().expect("pairing status") = value;
}

impl PairingHost {
    // ---- Showing, from an account's bound note window ----

    /// Show a new code for the calling window's account, with that
    /// account's own client (`scope.container`'s). Ends that window's
    /// earlier code.
    pub fn show(&self, scope: Scope, sync: &SyncHost) -> Result<Shown, Refusal> {
        let sync = &scope
            .container
            .and_then(|container| sync.handle(container))
            .ok_or(Refusal::Unavailable)?;
        if scope.page.is_none() || !sync.ops.is_current() {
            return Err(Refusal::Unavailable);
        }
        self.end_showing(&scope.window);
        let (showing, qr_text) =
            ShowingPairing::start(sync.ops.account(), sync.ops.device(), sync.relay.clone());
        let qr_svg = qr_svg(&qr_text).ok_or(Refusal::Unavailable)?;
        let status = Arc::new(Mutex::new(PairingStatus::of("waiting")));
        let (commands, receiver) = mpsc::unbounded_channel();
        let task = tokio::spawn(run_show(showing, sync.clone(), status.clone(), receiver));
        let session = handle();
        self.0.showing.lock().expect("showing").insert(
            session.clone(),
            Showing {
                scope,
                status,
                commands,
                task,
            },
        );
        Ok(Shown {
            session,
            qr_text,
            qr_svg,
        })
    }

    fn with_session<R>(
        &self,
        scope: &Scope,
        session: &str,
        use_session: impl FnOnce(&Showing) -> R,
    ) -> Result<R, Refusal> {
        let showing = self.0.showing.lock().expect("showing");
        let found = showing.get(session).ok_or(Refusal::Session)?;
        if found.scope != *scope || scope.container.is_none() || scope.page.is_none() {
            return Err(Refusal::Session);
        }
        Ok(use_session(found))
    }

    pub fn status(&self, scope: &Scope, session: &str) -> Result<PairingStatus, Refusal> {
        self.with_session(scope, session, |found| {
            found.status.lock().expect("pairing status").clone()
        })
    }

    /// The person approves the candidate shown. The native prompt follows.
    pub fn approve(&self, scope: &Scope, session: &str) -> Result<PairingStatus, Refusal> {
        self.with_session(scope, session, |found| {
            let mut status = found.status.lock().expect("pairing status");
            if status.state == "candidate" {
                status.state = "approving";
                let _ = found.commands.send(Command::Approve);
            }
            status.clone()
        })
    }

    /// End the code. Before staging nothing is added; after it, the
    /// approved addition still completes in the background.
    pub fn cancel(&self, scope: &Scope, session: &str) -> Result<PairingStatus, Refusal> {
        self.with_session(scope, session, |found| {
            let _ = found.commands.send(Command::Cancel);
            let mut status = found.status.lock().expect("pairing status");
            if matches!(status.state, "waiting" | "candidate") {
                *status = PairingStatus {
                    label: status.label.take(),
                    ..PairingStatus::of("cancelled")
                };
            }
            status.clone()
        })
    }

    fn end_showing(&self, window: &str) {
        self.0.showing.lock().expect("showing").retain(|_, found| {
            let keep = found.scope.window != window;
            if !keep {
                let _ = found.commands.send(Command::Cancel);
            }
            keep
        });
    }

    /// A window's page went away: its code ends with it. A join keeps
    /// going; its window picks it up again when it loads.
    pub fn window_gone(&self, window: &str) {
        self.end_showing(window);
    }

    // ---- Joining, from the unbound setup window ----

    /// The setup window's screen after the person's account `operation`
    /// (a load, Try again, signup or the kit's confirmation), the one way a
    /// window starts, retries or resumes an account. A join that runs is
    /// followed, whatever was asked: the page gets its ticket, and its
    /// account is never taken from it. A join this device kept, committed
    /// or not, resumes exactly as kept. The page gets a ticket it can
    /// follow, never an empty one.
    pub async fn setup_screen<S, P>(
        &self,
        window: &str,
        accounts: &SharedAccountHost<S, P>,
        sync: &SyncHost,
        operation: AccountOperation,
    ) -> Result<Screen, &'static str>
    where
        S: HostKeyStore,
        P: PendingSetupProtector + Clone + Send + Sync + 'static,
    {
        // No join begins while the operation runs: it holds the account.
        if let Some(ticket) = self.live_join(window) {
            return Ok(Screen::Joining { ticket });
        }
        Ok(match accounts.run(operation).await? {
            Screen::Joining { .. } => match self.resume_join(window, accounts, sync) {
                Ok(ticket) => Screen::Joining {
                    ticket: ticket.ticket,
                },
                Err(_) => Screen::Unavailable,
            },
            other => other,
        })
    }

    /// `window`'s join that has not ended. An ended join has given its
    /// container back before its window can see that it ended.
    fn live_join(&self, window: &str) -> Option<String> {
        self.0
            .joining
            .lock()
            .expect("joining")
            .iter()
            .find(|(_, found)| {
                found.window == window
                    && !found.task.is_finished()
                    && !ended(&found.status.lock().expect("join status"))
            })
            .map(|(ticket, _)| ticket.clone())
    }

    /// Join the account whose code `qr_text` is. A second submission while
    /// one runs follows the same join.
    pub fn join<S, P>(
        &self,
        window: &str,
        accounts: &SharedAccountHost<S, P>,
        sync: &SyncHost,
        qr_text: &str,
        device_label: Vec<u8>,
    ) -> Result<Ticket, Refusal>
    where
        S: HostKeyStore,
        P: PendingSetupProtector + Clone + Send + Sync + 'static,
    {
        if let Some(ticket) = self.live_join(window) {
            return Ok(Ticket { ticket });
        }
        parse_qr_text(qr_text).map_err(|_| Refusal::Code)?;
        let transport = sync.transport().ok_or(Refusal::Unavailable)?;
        let lease = accounts.begin_join().map_err(refused)?;
        Ok(self.spawn_join(
            window,
            accounts,
            transport,
            lease,
            Some(qr_text.to_owned()),
            device_label,
        ))
    }

    /// Pick up a join this device kept (after a restart, a reload or a
    /// failure after its commit).
    fn resume_join<S, P>(
        &self,
        window: &str,
        accounts: &SharedAccountHost<S, P>,
        sync: &SyncHost,
    ) -> Result<Ticket, Refusal>
    where
        S: HostKeyStore,
        P: PendingSetupProtector + Clone + Send + Sync + 'static,
    {
        if let Some(ticket) = self.live_join(window) {
            return Ok(Ticket { ticket });
        }
        let transport = sync.transport().ok_or(Refusal::Unavailable)?;
        let lease = accounts.begin_join().map_err(refused)?;
        if lease.joined.is_none() {
            accounts.return_join(lease);
            return Err(Refusal::Session);
        }
        Ok(self.spawn_join(window, accounts, transport, lease, None, Vec::new()))
    }

    fn spawn_join<S, P>(
        &self,
        window: &str,
        accounts: &SharedAccountHost<S, P>,
        transport: Transport,
        lease: JoinLease<S, P>,
        code: Option<String>,
        device_label: Vec<u8>,
    ) -> Ticket
    where
        S: HostKeyStore,
        P: PendingSetupProtector + Clone + Send + Sync + 'static,
    {
        let status = Arc::new(Mutex::new(JoinStatus::of("waiting-approval")));
        let slot = Arc::new(JoinSlot {
            lease: Mutex::new(Some(lease)),
            accounts: accounts.clone(),
        });
        let task = tokio::spawn(run_join(
            slot,
            accounts.clone(),
            transport,
            code,
            device_label,
            status.clone(),
        ));
        let ticket = handle();
        self.0.joining.lock().expect("joining").insert(
            ticket.clone(),
            Joining {
                window: window.to_owned(),
                status,
                task,
            },
        );
        Ticket { ticket }
    }

    pub fn join_status(&self, window: &str, ticket: &str) -> Result<JoinStatus, Refusal> {
        let joining = self.0.joining.lock().expect("joining");
        let found = joining.get(ticket).ok_or(Refusal::Session)?;
        if found.window != window {
            return Err(Refusal::Session);
        }
        Ok(found.status.lock().expect("join status").clone())
    }
}

fn ended(status: &JoinStatus) -> bool {
    matches!(status.state, "ready" | "refused" | "failed")
}

fn refused(error: JoinRefused) -> Refusal {
    match error {
        JoinRefused::AccountExists => Refusal::AccountExists,
        JoinRefused::Busy => Refusal::Busy,
        JoinRefused::Unavailable => Refusal::Unavailable,
    }
}

async fn cancelled(commands: &mut mpsc::UnboundedReceiver<Command>) {
    loop {
        match commands.recv().await {
            Some(Command::Cancel) | None => return,
            Some(Command::Approve) => {}
        }
    }
}

/// One showing session: wait for a verified reply, then for the person's
/// approval, stage it with the one confirmation, and wait for its order.
async fn run_show(
    mut showing: ShowingPairing,
    sync: SyncHandle,
    status: Arc<Mutex<PairingStatus>>,
    mut commands: mpsc::UnboundedReceiver<Command>,
) {
    let mut stopping = sync.stopping.clone();
    let candidate = loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Approve) => {}
                Some(Command::Cancel) | None => {
                    showing.cancel();
                    set(&status, PairingStatus::of("cancelled"));
                    return;
                }
            },
            found = showing.candidate() => match found {
                Ok(candidate) => break candidate,
                Err(error) => return set(&status, failed(reason(error))),
            },
            _ = stopping.changed() => {
                showing.cancel();
                return set(&status, failed("unavailable"));
            }
        }
    };
    let shown = label(&candidate.label);
    {
        let mut current = status.lock().expect("pairing status");
        if current.state == "cancelled" {
            showing.cancel();
            return;
        }
        *current = PairingStatus {
            label: shown.clone(),
            ..PairingStatus::of("candidate")
        };
    }
    tokio::select! {
        command = commands.recv() => match command {
            Some(Command::Approve) => {}
            Some(Command::Cancel) | None => {
                showing.cancel();
                return set(&status, PairingStatus { label: shown, ..PairingStatus::of("cancelled") });
            }
        },
        _ = stopping.changed() => {
            showing.cancel();
            return set(&status, failed("unavailable"));
        }
    }
    let approving = PairingStatus {
        label: shown.clone(),
        ..PairingStatus::of("approving")
    };
    set(&status, approving.clone());
    // Replies that arrived since are judged before anything is signed.
    match showing.candidate().await {
        Ok(again) if again == candidate => {}
        Ok(_) => return set(&status, failed("competing")),
        Err(error) => return set(&status, failed(reason(error))),
    }
    if let Ok(Command::Cancel) = commands.try_recv() {
        showing.cancel();
        return set(
            &status,
            PairingStatus {
                label: shown,
                ..PairingStatus::of("cancelled")
            },
        );
    }
    let (back, staged) = sync.ops.stage(showing).await;
    let Some(mut showing) = back else {
        return set(&status, failed("unavailable"));
    };
    if let Err(error) = staged {
        return set(
            &status,
            PairingStatus {
                label: shown,
                ..staging_failed(error)
            },
        );
    }
    sync.client.wake();
    let client = sync.client.clone();
    tokio::select! {
        done = showing.finish(&client) => match done {
            Ok(_) => set(&status, PairingStatus { label: shown, ..PairingStatus::of("ordered") }),
            Err(error) => set(&status, PairingStatus { label: shown, ..failed(reason(error)) }),
        },
        // The code ends; the approved addition is ordered and copied by
        // the client in the background all the same.
        () = cancelled(&mut commands) => set(&status, PairingStatus {
            label: shown,
            reason: Some("approved"),
            ..PairingStatus::of("cancelled")
        }),
        _ = stopping.changed() => set(&status, failed("unavailable")),
    }
}

/// A join's lent container: its one account owner, used on a native worker
/// and returned to the account registry unless the join commits it.
struct JoinSlot<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    lease: Mutex<Option<JoinLease<S, P>>>,
    accounts: SharedAccountHost<S, P>,
}
impl<S, P> Drop for JoinSlot<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    fn drop(&mut self) {
        if let Some(lease) = self.lease.get_mut().ok().and_then(Option::take) {
            self.accounts.return_join(lease);
        }
    }
}
impl<S, P> JoinSlot<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    /// Run `operation` with the lease on a native worker with its own
    /// current-thread executor (a platform prompt may not move threads).
    async fn with<R: Send + 'static>(
        self: &Arc<Self>,
        operation: impl for<'a> FnOnce(&'a mut JoinLease<S, P>) -> LocalBoxFuture<'a, R>
        + Send
        + 'static,
    ) -> Option<R> {
        let slot = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut lease = slot.lease.lock().ok()?.take()?;
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                *slot.lease.lock().ok()? = Some(lease);
                return None;
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                runtime.block_on(operation(&mut lease))
            }));
            match result {
                Ok(result) => {
                    *slot.lease.lock().ok()? = Some(lease);
                    Some(result)
                }
                // As a lent account owner's panic: the owner locks and goes
                // back to the registry; this join cannot use it again.
                Err(_) => {
                    let _ = lease.owner.lock();
                    slot.accounts.return_join(lease);
                    None
                }
            }
        })
        .await
        .ok()
        .flatten()
    }
    fn take(&self) -> Option<JoinLease<S, P>> {
        self.lease.lock().ok()?.take()
    }
    /// The join ended before its commit: the container goes back now,
    /// before its window can see the end.
    fn give_back(&self) {
        if let Some(lease) = self.take() {
            self.accounts.return_join(lease);
        }
    }
}

/// The joining device's possession proof before it holds its history,
/// made by its own owner on the lent container.
struct SlotProver<S, P>(Arc<JoinSlot<S, P>>)
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static;
impl<S, P> JoinProver for SlotProver<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    fn joining_proof(
        &self,
        account: AccountId,
        head: AccountHead,
        context: Context,
    ) -> BoxFuture<'_, Result<Proof, SignerError>> {
        Box::pin(async move {
            self.0
                .with(move |lease| {
                    Box::pin(async move {
                        lease
                            .owner
                            .prove_joining(account, head, context)
                            .await
                            .map_err(|_| SignerError)
                    })
                })
                .await
                .unwrap_or(Err(SignerError))
        })
    }
}

/// This device's one scanner identity: journaled once, never replaced.
async fn scanner_keys<S, P>(lease: &mut JoinLease<S, P>) -> Option<DevicePublicKeys>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    let mut journal = DeviceJournal::from_shared(lease.database.clone());
    if journal.has_account().ok()? {
        return Some(journal.device().ok()??.keys);
    }
    bh_account::pairing::scanner_identity(&mut journal, &mut lease.store, S::JOIN_POLICY)
        .await
        .ok()
        .map(|identity| identity.keys)
}

fn join_failed(error: PairingError) -> JoinStatus {
    match error {
        PairingError::Refused | PairingError::Invalid | PairingError::Pair(_) => {
            JoinStatus::ended("refused", reason(error))
        }
        _ => JoinStatus::ended("failed", reason(error)),
    }
}

/// A committed join's authority and own base.
type Opened = (Arc<AccountCapability>, Arc<OwnBase>);

/// One join: reply to the code, verify this device's admission, commit it,
/// then read the account's own base before the account is ready. Before
/// the commit the container goes back to the registry when the join ends;
/// after it, a join that does not become ready goes back to the kept join
/// it is on disk (`SharedAccountHost::suspend_join`), also if cancelled.
/// Either happens before the window can see that the join ended.
async fn run_join<S, P>(
    slot: Arc<JoinSlot<S, P>>,
    accounts: SharedAccountHost<S, P>,
    transport: Transport,
    code: Option<String>,
    device_label: Vec<u8>,
    status: Arc<Mutex<JoinStatus>>,
) where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    let end = |value: JoinStatus| {
        slot.give_back();
        set(&status, value);
    };
    let Some((id, kept)) = slot
        .lease
        .lock()
        .ok()
        .and_then(|lease| lease.as_ref().map(|l| (l.id, l.joined.clone())))
    else {
        return end(JoinStatus::ended("failed", "unavailable"));
    };
    let Some(keys) = slot
        .with(|lease| Box::pin(scanner_keys(lease)))
        .await
        .flatten()
    else {
        return end(JoinStatus::ended("failed", "unavailable"));
    };
    let committed = kept
        .as_ref()
        .is_some_and(|joined| joined.delivery.is_some());
    let prover: Arc<dyn JoinProver> = Arc::new(SlotProver(slot.clone()));
    let Transport {
        endpoint,
        connector,
        relay,
        owner,
    } = transport;
    let admission: Option<Admission> = if committed {
        None
    } else if let Some(code) = code {
        let mut joining =
            match JoiningPairing::join(&code, keys.clone(), &device_label, relay).await {
                Ok(joining) => joining,
                Err(error) => return end(join_failed(error)),
            };
        match joining
            .wait_admitted(&endpoint, connector.clone(), owner.clone(), id, prover)
            .await
        {
            Ok(admission) => Some(admission),
            Err(error) => return end(join_failed(error)),
        }
    } else {
        match bh_sync_client::pairing::resume_admission(
            &endpoint,
            connector.clone(),
            owner.clone(),
            id,
            &keys,
            prover,
        )
        .await
        {
            Ok(admission) => admission,
            Err(error) => return end(join_failed(error)),
        }
    };
    let device_owner = owner.clone();
    let opened: Option<Result<Opened, &'static str>> = slot
        .with(move |lease| {
            Box::pin(async move {
                let capability = match admission {
                    Some(admission) => bh_device::join::admit(
                        &mut lease.owner,
                        &device_owner,
                        lease.id,
                        &admission,
                    )
                    .await
                    .map_err(|_| "unavailable")?,
                    None => match lease.owner.activate().await {
                        Ok(AccountLoad::Active(capability)) => Arc::new(capability),
                        Ok(AccountLoad::Stopped) => return Err("stopped"),
                        _ => return Err("unavailable"),
                    },
                };
                let base = bh_device::own_base::create_or_open(
                    &mut lease.owner,
                    capability.clone(),
                    lease.database.clone(),
                )
                .await
                .map_err(|_| "unavailable")?;
                Ok((capability, Arc::new(base)))
            })
        })
        .await;
    let (capability, own_base) = match opened {
        Some(Ok(opened)) => opened,
        Some(Err(reason)) => return end(JoinStatus::ended("failed", reason)),
        None => return end(JoinStatus::ended("failed", "unavailable")),
    };
    let Some(lease) = slot.take() else {
        return end(JoinStatus::ended("failed", "unavailable"));
    };
    accounts.finish_join(lease, capability.clone(), own_base);
    let mut joined = Joined {
        accounts: &accounts,
        id,
        capability,
        ready: false,
    };
    set(&status, JoinStatus::of("admitted"));
    let ended = bootstrap_joined(&accounts, id, endpoint, connector, owner, &status).await;
    joined.ready = ended.state == "ready";
    drop(joined);
    set(&status, ended);
}

/// A committed join on its way to ready. Dropped before, it suspends the
/// join.
struct Joined<'a, S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    accounts: &'a SharedAccountHost<S, P>,
    id: ContainerId,
    capability: Arc<AccountCapability>,
    ready: bool,
}
impl<S, P> Drop for Joined<'_, S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    fn drop(&mut self) {
        if !self.ready {
            self.accounts.suspend_join(self.id, &self.capability);
        }
    }
}

/// A committed join's bootstrap, to the status it ends with.
async fn bootstrap_joined<S, P>(
    accounts: &SharedAccountHost<S, P>,
    id: ContainerId,
    endpoint: bh_sync_client::Endpoint,
    connector: Arc<dyn bh_sync_client::transport::Connector>,
    owner: Arc<bh_device::Owner>,
    status: &Arc<Mutex<JoinStatus>>,
) -> JoinStatus
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    let Ok(signer) = HostSigner::start(accounts.clone(), id).await else {
        return JoinStatus::ended("failed", "unavailable");
    };
    let (progress, mut watching) = watch::channel(Progress::default());
    let shown = status.clone();
    let forward = tokio::spawn(async move {
        loop {
            let Progress { done, total } = *watching.borrow_and_update();
            set(
                &shown,
                JoinStatus {
                    done: Some(done),
                    total: Some(total),
                    ..JoinStatus::of("bootstrapping")
                },
            );
            if watching.changed().await.is_err() {
                return;
            }
        }
    });
    let result = bootstrap::run(endpoint, connector, owner, id, signer, progress).await;
    forward.abort();
    let _ = forward.await;
    match result {
        Ok(()) if accounts.join_ready(id) => {
            let current = status.lock().expect("join status").clone();
            JoinStatus {
                state: "ready",
                ..current
            }
        }
        Ok(()) => JoinStatus::ended("failed", "unavailable"),
        Err(BootstrapError::Stopped) => JoinStatus::ended("failed", "stopped"),
        Err(BootstrapError::Unsupported) => JoinStatus::ended("failed", "unsupported"),
        Err(_) => JoinStatus::ended("failed", "unavailable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_code_is_drawn_as_one_path_without_script() {
        let text = format!("BH1:{}", "A".repeat(163));
        let svg = qr_svg(&text).unwrap();
        assert!(svg.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 "));
        assert_eq!(svg.matches('<').count(), 3, "svg, one path, close");
        assert!(svg.contains("<path d=\"M"));
        for forbidden in ["script", "on", "href", "style", "foreignObject"] {
            assert!(
                !svg.replace("svg", "")
                    .replace("xmlns", "")
                    .contains(&format!("{forbidden}=")),
                "{forbidden}"
            );
        }
        assert!(!svg.contains("script"));
    }

    #[test]
    fn a_candidates_label_is_bounded_plain_text() {
        assert_eq!(
            label(b"Pixel 10 Pro Fold"),
            Some("Pixel 10 Pro Fold".into())
        );
        assert_eq!(label(b""), None);
        assert_eq!(label(b"  \n\t "), None);
        assert_eq!(label(b"a\x00b\x1bc\nd"), Some("abcd".into()));
        assert_eq!(label(&[0xff, b'x']), Some("\u{fffd}x".into()));
        assert_eq!(
            label("é".repeat(100).as_bytes()).unwrap().chars().count(),
            64
        );
        assert_eq!(
            label(b"<img src=x onerror=alert(1)>"),
            Some("<img src=x onerror=alert(1)>".into()),
            "kept as text; the page never parses it"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_join_worker_that_panics_gives_its_container_back_locked() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let store = crate::test_support::FakeStore::default();
        let (accounts, _) = crate::accounts::fresh_test_host(&owner, dir.path(), store).await;
        let lease = accounts.begin_join().unwrap();
        let id = lease.id;
        let slot = Arc::new(JoinSlot {
            lease: Mutex::new(Some(lease)),
            accounts: accounts.clone(),
        });
        let panicked = slot
            .with(|_| Box::pin(async { panic!("a native step failed") }))
            .await;
        assert_eq!(panicked, None::<()>);
        // The join cannot use the container again; the registry has it back.
        assert!(slot.take().is_none());
        assert_eq!(slot.with(|_| Box::pin(async {})).await, None);
        let again = accounts.begin_join().expect("not left busy");
        assert_eq!(again.id, id, "the same container");
        accounts.return_join(again);
    }

    #[test]
    fn a_late_or_cancelled_approval_never_shows_as_ordered() {
        use bh_sync_client::pairing::PairingError;
        assert_eq!(staging_failed(PairingError::Ended).reason, Some("expired"));
        assert_eq!(staging_failed(PairingError::Ended).state, "failed");
        assert_eq!(
            staging_failed(PairingError::Owner(bh_account::owner::OwnerError::Device(
                bh_account::platform::KeyStoreError::AuthenticationCancelled
            )))
            .reason,
            Some("not-confirmed")
        );
        assert_eq!(
            staging_failed(PairingError::Competing).reason,
            Some("competing")
        );
    }
}
