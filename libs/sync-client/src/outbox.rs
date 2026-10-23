//! Publishing this device's content packages: the publisher lane. Each round
//! takes up to sixteen candidates in local commit order — a note's next
//! unacknowledged run, or one pending typed mutation — seals any that has no
//! package yet, persists its exact bytes, then publishes those bytes under
//! both fresh permits. A verified ordering proof records the position; the
//! next run of that note or mutation goes in a later round. A package that
//! cannot progress waits on its own; everything else carries on.
//!
//! A note's new packages start at least `SPACING` apart and, by default,
//! only after a quiet spell: 300 ms without an edit on that note, and at
//! most 1 s after its first unsent edit. Both compose (`spaced.max(quiet)`),
//! so the spacing still bounds how fast starts follow one another. That
//! policy is about typing: it applies to note work only, while typed work is
//! already committed by its own layer and travels in the same bounded round.
//! A run is captured when it becomes eligible. Tests may choose another
//! pacing (`Pacing`); the default is the shipped policy.
//! A retry of a sealed package is not a new start: it keeps its bytes and
//! its own backoff. Only a package under an epoch the base's verified
//! content has since left, which no device or service accepts content under
//! any more, is never sent again: once its work is sealed under the current
//! epoch, the new package replaces it in one transaction.
//! Work held for its epoch is looked at again once content's epoch moves or
//! a new key installs, not only after its backoff. The lane publishes only
//! while the receiver grants it, and every step after an await (persisting
//! a seal, enqueueing, recording an Ack) runs inside the owner's sync fence.
use crate::{
    ClientError, Shared,
    backoff::Backoff,
    data::DataSocket,
    scheduler::{PublishFacts, ReceiveFacts},
    status::Condition,
};
use bh_authz_proto::{FromService, MAX_MESSAGE, Refusal, ToService, Want};
use bh_device::{OwnerError, SealRefusal, SyncFence};
use bh_storage::{
    NoteKey, OutboxCandidate, OutboxOrder, PackagePreparation, StoredNotePackage, TypedHead,
    TypedPackagePreparation, sync_state::OutboxHead,
};
use bh_sync::{
    BaseId, BodyObject, Commitment, OpaqueEvent,
    permit::{self, LogId, LogKind},
    wire::{self, Request, Response},
};
use futures_util::future::join_all;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::watch;
// The runtime's clock, so that tests with a paused clock control permit lives.
use tokio::time::Instant;

/// Packages of both kinds published together in one round.
const ROUND: usize = 16;
/// The least time between one note's new package starts.
pub(crate) const SPACING: Duration = Duration::from_millis(500);
/// A permit is used only this long before its lifetime ends, so it is never
/// sent past its deadline.
const PERMIT_MARGIN: Duration = Duration::from_secs(5);
/// How often the store is checked for new work without a wake.
const POLL: Duration = Duration::from_secs(1);

/// Why a step could not finish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fail {
    Network,
    Authorization,
    /// The service no longer knows the own base: register it again.
    Unregistered,
    /// Retry soon with fresh permits and the same bytes.
    Retry,
    Local,
    /// The endpoint's policy, or the next event in the log, cannot be used
    /// by this build.
    Unsupported,
    /// Bytes, a key or configuration needed to judge the log are missing.
    Missing,
    /// The account owner stopped on history contradicting its own.
    Stopped,
}
impl From<ClientError> for Fail {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::Network | ClientError::Channel => Self::Network,
            ClientError::Refused(Refusal::Unknown | Refusal::Resync) => Self::Unregistered,
            ClientError::Local | ClientError::Stopped => Self::Local,
            ClientError::Unsupported => Self::Unsupported,
            _ => Self::Authorization,
        }
    }
}
impl Fail {
    pub(crate) fn from_answer(answer: &FromService) -> Self {
        match answer {
            FromService::Refused { reason } => ClientError::Refused(*reason).into(),
            FromService::Unavailable => Self::Authorization,
            _ => Self::Network,
        }
    }
    pub(crate) fn from_response(response: &Response) -> Self {
        match response {
            Response::Refused {
                reason: wire::Refusal::Epoch,
                ..
            } => Self::Authorization,
            _ => Self::Network,
        }
    }
}

/// The client's data socket, opened when first needed and replaced after
/// it closes.
#[derive(Default)]
pub(crate) struct Link {
    data: Option<DataSocket>,
}
impl Link {
    pub(crate) async fn data(&mut self, shared: &Shared) -> Result<&DataSocket, Fail> {
        if self.data.as_ref().is_none_or(DataSocket::is_closed) {
            self.data = None;
            let socket = DataSocket::open(shared.connector.as_ref())
                .await
                .map_err(|_| Fail::Network)?;
            self.data = Some(socket);
        }
        self.data.as_ref().ok_or(Fail::Network)
    }
    pub(crate) fn drop_data(&mut self) {
        self.data = None;
    }
    /// Close the socket and wait until its tasks ended.
    pub(crate) async fn shutdown(&mut self) {
        if let Some(mut data) = self.data.take() {
            data.shutdown().await;
        }
    }
}

/// One package's identity in this lane's permits, holds and Acks. A note
/// update id and a typed outbox id are separate spaces, so they never mix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum PackageKey {
    Note(i64),
    Typed(i64),
}

/// Permits this client holds, by package and kind, until shortly before
/// their deadline. A refused or expired one is dropped.
#[derive(Default)]
struct Permits(HashMap<(PackageKey, bool), (Vec<u8>, Instant)>);
impl Permits {
    fn get(&mut self, update_id: PackageKey, append: bool) -> Option<Vec<u8>> {
        let key = (update_id, append);
        match self.0.get(&key) {
            Some((permit, until)) if Instant::now() < *until => Some(permit.clone()),
            Some(_) => {
                self.0.remove(&key);
                None
            }
            None => None,
        }
    }
    fn insert(
        &mut self,
        update_id: PackageKey,
        append: bool,
        root: [u8; 32],
        signed: Vec<u8>,
        requested_at: Instant,
    ) {
        if let Some(until) = usable_until(root, &signed, requested_at) {
            self.0.insert((update_id, append), (signed, until));
        }
    }
    fn forget(&mut self, update_id: PackageKey, append: bool) {
        self.0.remove(&(update_id, append));
    }
    fn retain(&mut self, live: &[PackageKey]) {
        self.0.retain(|(id, _), _| live.contains(id));
    }
}

/// A signed permit is usable only within its original lifetime, including
/// the time spent waiting for authorization. Not one under `root`: never.
pub(crate) fn usable_until(
    root: [u8; 32],
    signed: &[u8],
    requested_at: Instant,
) -> Option<Instant> {
    let issued = permit::issued_ms(signed).ok()?;
    let permit = permit::verify(root, signed, issued).ok()?;
    let life = Duration::from_millis(permit.deadline_ms - permit.issued_ms);
    let until = requested_at.checked_add(life.checked_sub(PERMIT_MARGIN)?)?;
    (Instant::now() < until).then_some(until)
}

/// Work whose next package cannot progress now, by that package: each waits
/// out its own backoff and holds nothing else back. An alarm (a refusal an
/// honest device never causes) shows as not accepted; its work is kept and
/// retried, byte for byte, only after its backoff.
#[derive(Default)]
pub(crate) struct Holds(HashMap<PackageKey, Hold>);
struct Hold {
    until: Instant,
    backoff: Backoff,
    alarm: bool,
}
impl Holds {
    fn held(&self, update_id: PackageKey) -> bool {
        self.0
            .get(&update_id)
            .is_some_and(|hold| Instant::now() < hold.until)
    }
    fn hold(&mut self, update_id: PackageKey, alarm: bool) {
        let hold = self.0.entry(update_id).or_insert(Hold {
            until: Instant::now(),
            backoff: Backoff::default(),
            alarm,
        });
        hold.alarm = alarm;
        hold.until = Instant::now() + hold.backoff.next();
    }
    fn release(&mut self, update_id: PackageKey) {
        self.0.remove(&update_id);
    }
    /// Notes held by an alarm.
    pub(crate) fn alarms(&self) -> u64 {
        self.0.values().filter(|hold| hold.alarm).count() as u64
    }
    /// Whether some note's work cannot be sealed as it stands.
    fn local(&self) -> bool {
        self.0.values().any(|hold| !hold.alarm)
    }
    /// Forget alarms on packages verified history has since judged: the
    /// store shows those, and they are never sent again.
    fn settle(&mut self, db: &bh_storage::DeviceDatabase) -> Result<(), Fail> {
        use bh_storage::sync_state::PackageOutcome;
        let mut judged = Vec::new();
        for (update_id, hold) in &self.0 {
            if !hold.alarm {
                continue;
            }
            let outcome = match update_id {
                PackageKey::Note(id) => db
                    .package_progress(*id)
                    .map_err(|_| Fail::Local)?
                    .map(|p| p.outcome),
                PackageKey::Typed(id) => db
                    .typed_package_progress(*id)
                    .map_err(|_| Fail::Local)?
                    .map(|p| p.outcome),
            };
            if outcome.is_none_or(|outcome| {
                !matches!(
                    outcome,
                    None | Some(PackageOutcome::Acked | PackageOutcome::Held)
                )
            }) {
                judged.push(*update_id);
            }
        }
        for update_id in judged {
            self.0.remove(&update_id);
        }
        Ok(())
    }
}

/// One package to publish this round, of either kind: exactly the bytes its
/// own store persisted, under its own package identity.
struct Package {
    key: PackageKey,
    descriptor: OpaqueEvent,
    body: Vec<u8>,
}
impl Package {
    fn new(key: PackageKey, stored: StoredNotePackage) -> Self {
        Self {
            key,
            descriptor: stored.descriptor,
            body: stored.body,
        }
    }
}

/// What a round achieved.
struct Round {
    /// Some Ack was recorded or more work is ready.
    progressed: bool,
    /// Why some work is waiting, if it is.
    waiting: Option<Fail>,
    /// The highest head a verified Ack proved.
    acked: u64,
    /// The service said the base lacks an account change.
    follow: bool,
    /// When a note skipped for its spacing may start its next package.
    due: Option<Instant>,
}
impl Round {
    fn waiting(waiting: Option<Fail>, due: Option<Instant>) -> Self {
        Self {
            progressed: false,
            waiting,
            acked: 0,
            follow: false,
            due,
        }
    }
}

/// Where the next round's work starts: after the last package the previous
/// round took, from the start once every candidate was considered.
#[derive(Default)]
struct Cursor(OutboxOrder);

/// When each note may start its next new package. An entry lives only
/// until then.
pub(crate) struct Spacing {
    due: HashMap<NoteKey, Instant>,
    pacing: crate::Pacing,
    /// Set only with a quiet period.
    edits: Option<Arc<Mutex<Edits>>>,
}
impl Spacing {
    fn new(pacing: crate::Pacing, edits: Option<Arc<Mutex<Edits>>>) -> Self {
        Self {
            due: HashMap::new(),
            pacing,
            edits,
        }
    }
    /// `Err` with the instant it may, if `head`'s note may not start one now.
    fn eligible(&self, head: &OutboxHead, now: Instant) -> Result<(), Instant> {
        let spaced = match self.due.get(&head.key) {
            Some(due) if now < *due => *due,
            _ => now,
        };
        let quiet = match (self.pacing.quiet, &self.edits) {
            (Some(quiet), Some(edits)) => {
                let mut edits = edits.lock().expect("edit times");
                // Once its last edit is `after` old, or its first `within`.
                let last = edits.at(head.update_id, now).map(|at| at + quiet.after);
                let first = edits.at(head.first, now).map(|at| at + quiet.within);
                match (last, first) {
                    (Some(last), Some(first)) => last.min(first).max(now),
                    _ => now,
                }
            }
            _ => now,
        };
        match spaced.max(quiet) {
            due if now < due => Err(due),
            _ => Ok(()),
        }
    }
    /// A new package of `key` started at `at`.
    fn started(&mut self, key: NoteKey, at: Instant) {
        self.due.insert(key, at + self.pacing.spacing);
    }
    fn expire(&mut self, now: Instant) {
        self.due.retain(|_, due| now < *due);
    }
}

/// When this client first saw local updates, for a quiet period only: the
/// highest pending update at each wake, with the instant of that wake.
/// Entries older than `within` are forgotten; an update at or before the
/// last one forgotten counts as long ago.
pub(crate) struct Edits {
    seen: VecDeque<(i64, Instant)>,
    forgotten: i64,
    within: Duration,
}
impl Edits {
    fn new(within: Duration) -> Self {
        Self {
            seen: VecDeque::new(),
            forgotten: 0,
            within,
        }
    }
    fn record(&mut self, highest: i64, now: Instant) {
        if self.seen.back().is_none_or(|(id, _)| highest > *id) && highest > self.forgotten {
            self.seen.push_back((highest, now));
        }
        while let Some((id, at)) = self.seen.front().copied() {
            if now.saturating_duration_since(at) <= self.within {
                break;
            }
            self.forgotten = self.forgotten.max(id);
            self.seen.pop_front();
        }
    }
    /// Edits at or below `highest` were pending before this client started,
    /// or are older than the tracker kept: their times are unknown, so a
    /// note resting on them sends without waiting for a quiet period.
    fn unknown_through(&mut self, highest: i64) {
        self.forgotten = self.forgotten.max(highest);
        self.seen.retain(|(id, _)| *id > self.forgotten);
    }
    /// When `update_id` was first seen; `None` if long ago. Not seen yet:
    /// it was just committed, and is seen now.
    fn at(&mut self, update_id: i64, now: Instant) -> Option<Instant> {
        if update_id <= self.forgotten {
            return None;
        }
        if let Some((_, at)) = self.seen.iter().find(|(id, _)| *id >= update_id) {
            return Some(*at);
        }
        self.record(update_id, now);
        Some(now)
    }
}

/// The highest local update still queued to publish, if any: one indexed
/// lookup, so timing a wake costs the same however large the backlog is.
fn highest_pending(shared: &Shared) -> Option<i64> {
    let db = shared.owner.shared_database(shared.container).ok()?;
    let db = db.lock().expect("container writer lock");
    db.highest_pending_update().ok().flatten()
}

/// Record when local updates appear, at every wake, for a quiet period.
async fn record_edits(shared: &Shared, edits: Arc<Mutex<Edits>>) {
    let mut wake = shared.wake.subscribe();
    loop {
        wake.borrow_and_update();
        if let Some(highest) = highest_pending(shared) {
            edits
                .lock()
                .expect("edit times")
                .record(highest, Instant::now());
        }
        if wake.changed().await.is_err() {
            return std::future::pending().await;
        }
    }
}

/// The publisher lane. Ends at halt, closing its link.
pub(crate) async fn run_publisher(
    shared: Arc<Shared>,
    log: LogId,
    receive: watch::Receiver<ReceiveFacts>,
    facts: watch::Sender<PublishFacts>,
) {
    let mut link = Link::default();
    let pacing = shared.tuning.pacing;
    let edits = pacing
        .quiet
        .map(|quiet| Arc::new(Mutex::new(Edits::new(quiet.within))));
    if let Some(edits) = &edits {
        // Work already queued when this run starts was not typed now: a
        // restart or reconnect finds a backlog whose edit times this run
        // never saw. Those rows send without waiting for a quiet period;
        // their durable bytes were saved long ago, so nothing is at risk.
        if let Some(highest) = highest_pending(&shared) {
            edits.lock().expect("edit times").unknown_through(highest);
        }
    }
    let recorder = async {
        match &edits {
            Some(edits) => record_edits(&shared, edits.clone()).await,
            None => std::future::pending().await,
        }
    };
    let spacing = Spacing::new(pacing, edits.clone());
    tokio::select! {
        _ = shared.halted() => {}
        _ = publish(&shared, &mut link, log, receive, &facts, spacing) => {}
        _ = recorder => {}
    }
    link.shutdown().await;
}

async fn publish(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    mut receive: watch::Receiver<ReceiveFacts>,
    facts: &watch::Sender<PublishFacts>,
    mut spacing: Spacing,
) {
    let mut permits = Permits::default();
    let mut holds = Holds::default();
    let mut cursor = Cursor::default();
    let mut backoff = Backoff::default();
    let mut wake = shared.wake.subscribe();
    let mut installed = shared.installed.subscribe();
    loop {
        // Every wake so far is seen before durable work is looked at.
        wake.borrow_and_update();
        installed.borrow_and_update();
        let ready = receive.borrow_and_update().ready;
        let Some(generation) = ready else {
            // Not granted: the receiver says why. Wait for its grant.
            tokio::select! {
                changed = receive.wait_for(|facts| facts.ready.is_some()) => {
                    if changed.is_err() { return }
                }
                _ = wake.changed() => {}
            }
            continue;
        };
        let mut state = State {
            link,
            permits: &mut permits,
            holds: &mut holds,
            cursor: &mut cursor,
            spacing: &mut spacing,
            ready: (&receive, generation),
        };
        let epoch = current_epoch(shared, log.id).ok().flatten();
        let round = round(shared, &mut state, log)
            .await
            .unwrap_or_else(|fail| Round::waiting(Some(fail), None));
        // Work held locally still shows as saved here between its retries.
        let waiting = match round.waiting {
            None if holds.local() => Some(Fail::Local),
            waiting => waiting,
        };
        facts.send_modify(|f| {
            f.started = true;
            f.waiting = waiting;
            f.alarms = holds.alarms();
            f.latest = f.latest.max(round.acked);
            if round.follow {
                f.follow = f.follow.wrapping_add(1);
            }
            if waiting == Some(Fail::Unregistered) {
                f.unregistered = f.unregistered.wrapping_add(1);
            }
        });
        let wait = match waiting {
            Some(Fail::Network) => {
                link.drop_data();
                backoff.next()
            }
            Some(
                Fail::Unregistered
                | Fail::Authorization
                | Fail::Missing
                | Fail::Unsupported
                | Fail::Stopped,
            ) => backoff.next(),
            Some(Fail::Retry) if !round.progressed => backoff.next(),
            _ if round.progressed => {
                backoff.reset();
                continue;
            }
            _ => {
                backoff.reset();
                POLL
            }
        };
        let until = round
            .due
            .map_or(Instant::now() + wait, |due| due.min(Instant::now() + wait));
        // Work held for its epoch (closed, its key not held, or refused
        // under it) goes on once content is in another epoch, not after its
        // backoff.
        let held = waiting == Some(Fail::Authorization);
        let passes = receive.clone();
        tokio::select! {
            _ = tokio::time::sleep_until(until) => {}
            _ = wake.changed() => {}
            // The receiver's other facts change every pass; only a new or
            // withdrawn grant matters here.
            changed = receive.wait_for(|facts| facts.ready != ready) => {
                if changed.is_err() { return }
            }
            _ = epoch_moved(shared, log, passes, &mut installed, epoch), if held => {}
        }
    }
}

/// Ends on the receiver's next pass after a new content key installed (the
/// install alone is too early: content must also reach its epoch), or after
/// a pass that left the base's content in another epoch than `seen`, its
/// epoch when the round began.
async fn epoch_moved(
    shared: &Shared,
    log: LogId,
    mut passes: watch::Receiver<ReceiveFacts>,
    installed: &mut watch::Receiver<Option<crate::EpochInstalled>>,
    seen: Option<[u8; 32]>,
) {
    loop {
        let pass = passes.borrow_and_update().revision;
        tokio::select! {
            changed = installed.changed() => {
                if changed.is_err()
                    || passes.wait_for(|facts| facts.revision != pass).await.is_err()
                {
                    return std::future::pending().await;
                }
                return;
            }
            changed = passes.changed() => {
                if changed.is_err() {
                    return std::future::pending().await;
                }
            }
        }
        if current_epoch(shared, log.id).is_ok_and(|now| now != seen) {
            return;
        }
    }
}

pub(crate) fn condition_of(fail: Fail) -> Condition {
    match fail {
        Fail::Network => Condition::Network,
        Fail::Authorization | Fail::Unregistered => Condition::Authorization,
        Fail::Retry | Fail::Missing => Condition::Working,
        Fail::Local => Condition::Held,
        Fail::Unsupported => Condition::Unsupported,
        Fail::Stopped => Condition::Stopped,
    }
}

/// What a fenced step's refusal means here: authority ended, or the base's
/// control, account copy or epoch moved on (decide again soon), or it
/// stopped.
fn fenced_fail(error: OwnerError) -> Fail {
    match error {
        OwnerError::Unbound | OwnerError::AnchorMismatch => Fail::Authorization,
        OwnerError::Changed => Fail::Retry,
        _ => Fail::Local,
    }
}

/// The content epoch new packages of `base` are sealed under: the one its
/// verified history holds now (None while closed). The seal checks it again.
fn current_epoch(shared: &Shared, base: [u8; 32]) -> Result<Option<[u8; 32]>, Fail> {
    let database = shared
        .owner
        .shared_database(shared.container)
        .map_err(|_| Fail::Local)?;
    let progress = database
        .lock()
        .expect("container writer lock")
        .log_progress(LogKind::Base as u8, base)
        .map_err(|_| Fail::Local)?;
    Ok(progress.and_then(|p| p.epoch_id))
}

/// Seal `head` if it has no package yet, capturing its run now, or again
/// once content has left its package's epoch. Its exact bytes are persisted
/// before this returns, and otherwise never replaced; only while `fence`
/// holds, after the signer's await. Whether it is new.
async fn sealed(
    shared: &Shared,
    head: OutboxHead,
    fence: &SyncFence,
) -> Result<(StoredNotePackage, bool), Fail> {
    let database = shared
        .owner
        .shared_database(shared.container)
        .map_err(|_| Fail::Local)?;
    let preparation = database
        .lock()
        .expect("container writer lock")
        .prepare_note_package(head.update_id)
        .map_err(|_| Fail::Local)?;
    let (candidate, replacing) = match preparation {
        PackagePreparation::Existing(stored) => {
            // Under an epoch content has passed, its bytes can never be
            // ordered: its work is sealed again, replacing it.
            let Some(sealed_under) = passed(
                shared,
                head.key.base,
                &stored.descriptor,
                stored.ack.is_some(),
            )?
            else {
                return Ok((stored, false));
            };
            let reseal = database
                .lock()
                .expect("container writer lock")
                .prepare_note_reseal(head.update_id)
                .map_err(|_| Fail::Local)?;
            let Some(candidate) = reseal else {
                return Ok((stored, false));
            };
            (candidate, Some((stored.event_id, sealed_under)))
        }
        PackagePreparation::Candidate(candidate) => (candidate, None),
    };
    let identity = shared.signer.identity().map_err(|_| Fail::Authorization)?;
    let epoch = current_epoch(shared, head.key.base)?;
    let mut request = None;
    shared
        .signer
        .with_epoch_keys(BaseId(head.key.base), epoch, &mut |m, k| {
            request = k.map(|k| {
                shared.owner.prepare_note_seal(
                    shared.container,
                    &identity.anchor,
                    shared.endpoint.hosting_root,
                    m,
                    k,
                    &candidate,
                )
            })
        })
        .map_err(|_| Fail::Authorization)?;
    // A closed epoch, or one whose key this device does not hold yet, waits.
    let request = match request.ok_or(Fail::Authorization)? {
        Ok(request) => request,
        Err(OwnerError::SealRefused(SealRefusal::EpochClosed)) => return Err(Fail::Authorization),
        Err(OwnerError::Unbound | OwnerError::AnchorMismatch) => return Err(Fail::Authorization),
        Err(_) => return Err(Fail::Local),
    };
    // No lock is held while the platform signs.
    let signature = shared
        .signer
        .sign_event(request.signing_bytes().to_vec())
        .await
        .map_err(|_| Fail::Authorization)?;
    let encoded = request.finish(signature).map_err(|_| Fail::Local)?;
    let body = BodyObject::new(encoded.body).map_err(|_| Fail::Local)?;
    shared.commit_time(1).await;
    let mut stored = None;
    shared
        .owner
        .with_sync_fence(fence, |db| {
            stored = Some(match replacing {
                None => db
                    .publish_note_package(candidate, encoded.descriptor, body)
                    .map(Some),
                Some((old, sealed_under)) => {
                    db.publish_note_reseal(candidate, old, sealed_under, encoded.descriptor, body)
                }
            });
            Ok(())
        })
        .map_err(fenced_fail)?;
    // A package that changed meanwhile is looked at again.
    let stored = stored
        .ok_or(Fail::Local)?
        .map_err(|_| Fail::Local)?
        .ok_or(Fail::Retry)?;
    Ok((stored, true))
}

/// Seal a typed mutation's package if it has none yet, or again once
/// content has left its package's epoch. Its exact payload bytes are
/// persisted before this returns and otherwise never replaced; only while
/// `fence` holds, after the signer's await. Whether it is new.
async fn sealed_typed(
    shared: &Shared,
    head: TypedHead,
    fence: &SyncFence,
) -> Result<(Package, bool), Fail> {
    let database = shared
        .owner
        .shared_database(shared.container)
        .map_err(|_| Fail::Local)?;
    let preparation = database
        .lock()
        .expect("container writer lock")
        .prepare_typed_package(head.id)
        .map_err(|_| Fail::Local)?;
    let existing = |stored: bh_storage::StoredTypedPackage| Package {
        key: PackageKey::Typed(head.id),
        descriptor: stored.descriptor,
        body: stored.body,
    };
    let (candidate, replacing) = match preparation {
        TypedPackagePreparation::Existing(stored) => {
            // As for a note: sealed again once content passed its epoch.
            let Some(sealed_under) =
                passed(shared, head.base, &stored.descriptor, stored.ack.is_some())?
            else {
                return Ok((existing(stored), false));
            };
            let reseal = database
                .lock()
                .expect("container writer lock")
                .prepare_typed_reseal(head.id)
                .map_err(|_| Fail::Local)?;
            let Some(candidate) = reseal else {
                return Ok((existing(stored), false));
            };
            (candidate, Some((stored.event_id, sealed_under)))
        }
        TypedPackagePreparation::Candidate(candidate) => (candidate, None),
    };
    let identity = shared.signer.identity().map_err(|_| Fail::Authorization)?;
    let epoch = current_epoch(shared, head.base)?;
    let mut request = None;
    shared
        .signer
        .with_epoch_keys(BaseId(head.base), epoch, &mut |m, k| {
            request = k.map(|k| {
                shared.owner.prepare_typed_seal(
                    shared.container,
                    &identity.anchor,
                    shared.endpoint.hosting_root,
                    m,
                    k,
                    &candidate,
                )
            })
        })
        .map_err(|_| Fail::Authorization)?;
    // A closed epoch, or one whose key this device does not hold yet, waits.
    let request = match request.ok_or(Fail::Authorization)? {
        Ok(request) => request,
        Err(OwnerError::SealRefused(SealRefusal::EpochClosed)) => return Err(Fail::Authorization),
        Err(OwnerError::SealRefused(SealRefusal::AudienceUnsupported)) => return Err(Fail::Local),
        Err(OwnerError::Unbound | OwnerError::AnchorMismatch) => return Err(Fail::Authorization),
        Err(_) => return Err(Fail::Local),
    };
    // No lock is held while the platform signs.
    let signature = shared
        .signer
        .sign_event(request.signing_bytes().to_vec())
        .await
        .map_err(|_| Fail::Authorization)?;
    let encoded = request.finish(signature).map_err(|_| Fail::Local)?;
    let body = BodyObject::new(encoded.body).map_err(|_| Fail::Local)?;
    shared.commit_time(1).await;
    let mut stored = None;
    shared
        .owner
        .with_sync_fence(fence, |db| {
            stored = Some(match replacing {
                None => db
                    .publish_typed_package(candidate, encoded.descriptor, body)
                    .map(Some),
                Some((old, sealed_under)) => {
                    db.publish_typed_reseal(candidate, old, sealed_under, encoded.descriptor, body)
                }
            });
            Ok(())
        })
        .map_err(fenced_fail)?;
    let stored = stored
        .ok_or(Fail::Local)?
        .map_err(|_| Fail::Local)?
        .ok_or(Fail::Retry)?;
    Ok((
        Package {
            key: PackageKey::Typed(head.id),
            descriptor: stored.descriptor,
            body: stored.body,
        },
        true,
    ))
}

/// The epoch a package of `base` nothing acknowledged was sealed under, if
/// the base's verified content is no longer in it: content has passed the
/// control that replaced it, after which no device or service accepts
/// content under it, so it can never be ordered. None while it may: until
/// content passes that control it waits as it is.
fn passed(
    shared: &Shared,
    base: [u8; 32],
    descriptor: &OpaqueEvent,
    acked: bool,
) -> Result<Option<[u8; 32]>, Fail> {
    if acked {
        return Ok(None);
    }
    // Its own bytes do not open: it waits alone when its permits are asked.
    let sealed_under = match descriptor_epoch(shared, base, descriptor) {
        Ok(epoch) => epoch,
        Err(Fail::Local) => return Ok(None),
        Err(fail) => return Err(fail),
    };
    Ok((current_epoch(shared, base)? != Some(sealed_under)).then_some(sealed_under))
}

/// The epoch `descriptor`, a package of `base`, was sealed under.
fn descriptor_epoch(
    shared: &Shared,
    base: [u8; 32],
    descriptor: &OpaqueEvent,
) -> Result<[u8; 32], Fail> {
    let mut epoch = None;
    shared
        .signer
        .with_metadata_key(BaseId(base), &mut |m| {
            epoch = Some(bh_event::sealed_epoch(descriptor, m, BaseId(base)))
        })
        .map_err(|_| Fail::Authorization)?;
    epoch.ok_or(Fail::Authorization)?.map_err(|_| Fail::Local)
}

/// The worse of two reasons to wait: a stop, then unsupported, then
/// authority, then network, then missing history, then a retry, then local
/// holds.
pub(crate) fn worse(a: Option<Fail>, b: Fail) -> Option<Fail> {
    let rank = |f: &Fail| match f {
        Fail::Stopped => 7,
        Fail::Unsupported => 6,
        Fail::Unregistered => 5,
        Fail::Authorization => 4,
        Fail::Network => 3,
        Fail::Missing => 2,
        Fail::Retry => 1,
        Fail::Local => 0,
    };
    match a {
        Some(a) if rank(&a) >= rank(&b) => Some(a),
        _ => Some(b),
    }
}

/// What rounds keep between them.
struct State<'a> {
    link: &'a mut Link,
    permits: &'a mut Permits,
    holds: &'a mut Holds,
    cursor: &'a mut Cursor,
    spacing: &'a mut Spacing,
    /// The receiver's grant this round runs under.
    ready: (&'a watch::Receiver<ReceiveFacts>, u64),
}

/// Up to a round of candidates that are not held, from the cursor on and
/// then from the start: note work and typed work in one local commit order,
/// each note or mutation at most once. A note's head with no package yet
/// waits out its note's spacing; the earliest such instant is returned.
fn take_candidates(
    db: &bh_storage::DeviceDatabase,
    holds: &Holds,
    cursor: &mut Cursor,
    spacing: &Spacing,
) -> Result<(Vec<OutboxCandidate>, Option<Instant>), Fail> {
    let start = cursor.0;
    let now = Instant::now();
    let mut candidates = Vec::new();
    let mut due: Option<Instant> = None;
    let mut after = start;
    // Scanning again from the start, up to where this round began.
    let mut wrapped = false;
    loop {
        let page = db
            .outbox_candidates(after, wrapped.then_some(start), ROUND)
            .map_err(|_| Fail::Local)?;
        for candidate in &page {
            after = candidate.order();
            match candidate {
                OutboxCandidate::Note(head) => {
                    if holds.held(PackageKey::Note(head.first))
                        || holds.held(PackageKey::Note(head.update_id))
                    {
                        continue;
                    }
                    // A sealed package is a retry, not a new start.
                    let sealed = db
                        .package_progress(head.update_id)
                        .map_err(|_| Fail::Local)?
                        .is_some();
                    if !sealed && let Err(next) = spacing.eligible(head, now) {
                        due = Some(due.map_or(next, |due| due.min(next)));
                        continue;
                    }
                }
                OutboxCandidate::Typed(head) => {
                    if holds.held(PackageKey::Typed(head.id)) {
                        continue;
                    }
                }
            }
            candidates.push(*candidate);
            if candidates.len() == ROUND {
                cursor.0 = after;
                return Ok((candidates, due));
            }
        }
        if page.len() < ROUND {
            if wrapped || start == OutboxOrder::START {
                cursor.0 = OutboxOrder::START;
                return Ok((candidates, due));
            }
            wrapped = true;
            after = OutboxOrder::START;
        }
    }
}

async fn round(shared: &Shared, state: &mut State<'_>, log: LogId) -> Result<Round, Fail> {
    let State {
        link,
        permits,
        holds,
        cursor,
        spacing,
        ready: (receive, generation),
    } = state;
    let database = shared
        .owner
        .shared_database(shared.container)
        .map_err(|_| Fail::Local)?;
    spacing.expire(Instant::now());
    let (candidates, due, epoch) = {
        let db = database.lock().expect("container writer lock");
        holds.settle(&db)?;
        let (candidates, due) = take_candidates(&db, holds, cursor, spacing)?;
        let progress = db
            .log_progress(log.kind as u8, log.id)
            .map_err(|_| Fail::Local)?
            .ok_or(Fail::Local)?;
        if progress.stopped.is_some() {
            return Err(Fail::Local);
        }
        (candidates, due, progress.epoch_id)
    };
    let live: Vec<PackageKey> = candidates
        .iter()
        .map(|candidate| match candidate {
            OutboxCandidate::Note(head) => PackageKey::Note(head.update_id),
            OutboxCandidate::Typed(head) => PackageKey::Typed(head.id),
        })
        .collect();
    permits.retain(&live);
    if candidates.is_empty() {
        return Ok(Round::waiting(None, due));
    }
    // Everything this round decides is decided under the authority, control,
    // account copy and epoch current now.
    let fence = match shared.owner.sync_fence(shared.container, log) {
        Ok(fence) => fence,
        Err(OwnerError::Stopped) => return Err(Fail::Local),
        Err(_) => return Err(Fail::Authorization),
    };
    let mut waiting = None;
    let mut packages = Vec::new();
    for candidate in candidates {
        let captured = Instant::now();
        match candidate {
            OutboxCandidate::Note(head) => match sealed(shared, head, &fence).await {
                Ok((stored, new)) => {
                    if new {
                        spacing.started(head.key, captured);
                        // Any permits under its key were for bytes it replaced.
                        permits.forget(PackageKey::Note(head.update_id), false);
                        permits.forget(PackageKey::Note(head.update_id), true);
                    }
                    // A failed unsealed run is held by its stable first row;
                    // later keystrokes must not bypass that note's backoff.
                    if head.first != head.update_id {
                        holds.release(PackageKey::Note(head.first));
                    }
                    packages.push(Package::new(PackageKey::Note(head.update_id), stored));
                }
                // This note's work cannot be sealed as it stands (no writer
                // declaration, or its writer unreadable): it waits alone.
                Err(Fail::Local) => {
                    holds.hold(PackageKey::Note(head.first), false);
                    waiting = worse(waiting, Fail::Local);
                }
                Err(fail) => waiting = worse(waiting, fail),
            },
            OutboxCandidate::Typed(head) => match sealed_typed(shared, head, &fence).await {
                Ok((package, new)) => {
                    if new {
                        permits.forget(package.key, false);
                        permits.forget(package.key, true);
                    }
                    packages.push(package);
                }
                // Its saved work changed or retired between selection and the
                // seal: it waits alone.
                Err(Fail::Local) => {
                    holds.hold(PackageKey::Typed(head.id), false);
                    waiting = worse(waiting, Fail::Local);
                }
                Err(fail) => waiting = worse(waiting, fail),
            },
        }
    }
    // While the epoch is closed nothing is sent: a package under the epoch
    // it replaced is sealed again once content holds a new one.
    if epoch.is_none() {
        return Ok(Round::waiting(worse(waiting, Fail::Authorization), due));
    }
    if packages.is_empty() {
        return Ok(Round::waiting(waiting, due));
    }
    let mut follow = false;
    if let Err(fail) = request_permits(shared, permits, holds, log, &packages, &mut follow).await {
        return Ok(Round {
            follow,
            ..Round::waiting(worse(waiting, fail), due)
        });
    }
    let data = link.data(shared).await?;
    let root = shared.endpoint.hosting_root;

    // Each note gets one compound DATA request, with exactly its persisted
    // descriptor and body. The edge stages durably before ordering
    // internally. Each is enqueued only while the round's fence and the
    // receiver's grant still hold: a send admitted then is in flight, not
    // revoked by a later change.
    let mut sent = Vec::with_capacity(packages.len());
    for p in &packages {
        let (Some(stage_permit), Some(append_permit)) =
            (permits.get(p.key, false), permits.get(p.key, true))
        else {
            sent.push(None);
            waiting = worse(waiting, Fail::Authorization);
            continue;
        };
        let event = p.descriptor.encode();
        let body = p.body.clone();
        let enqueued = shared.owner.with_sync_fence(&fence, |_| {
            if receive.borrow().ready != Some(*generation) {
                return Err(OwnerError::Changed);
            }
            Ok(data.send(|id| Request::Publish {
                id,
                stage_permit,
                append_permit,
                event,
                body,
            }))
        });
        match enqueued {
            Ok(Ok(answers)) => sent.push(Some(Ok(answers))),
            Ok(Err(_)) if data.is_closed() => sent.push(Some(Err(Lost))),
            // Refused admission on an open socket: not sent, and the socket
            // is sound. Today it cannot happen: this link carries only this
            // lane's rounds, and a round's at most sixteen frames, each at
            // most MAX_FRAME_LEN, fit both outbound bounds. After a bound or
            // round change it retries the same bytes, without reconnecting.
            Ok(Err(_)) => {
                sent.push(None);
                waiting = worse(waiting, Fail::Retry);
            }
            Err(error) => {
                sent.push(None);
                waiting = worse(waiting, fenced_fail(error));
            }
        }
    }
    let replies = join_all(sent.into_iter().map(|answers| async move {
        match answers? {
            Ok(mut answers) => Some(answers.next().await.ok_or(Lost)),
            Err(lost) => Some(Err(lost)),
        }
    }))
    .await;
    let mut acked = Vec::new();
    let mut lost = false;
    for (package, answer) in packages.iter().zip(replies) {
        match answer {
            Some(Ok(Response::Published {
                ack, commitment, ..
            })) => {
                match permit::verify_published_ordering(
                    &root,
                    log,
                    &package.descriptor,
                    &ack,
                    &commitment,
                ) {
                    Ok(ordered) => acked.push((package, ordered)),
                    Err(_) => {
                        lost = true;
                        waiting = worse(waiting, Fail::Network);
                    }
                }
            }
            Some(Ok(Response::Refused { reason, .. })) => {
                // After either internal operation fails, neither grant is
                // assumed usable. The persisted bytes remain immutable.
                permits.forget(package.key, false);
                permits.forget(package.key, true);
                match refused(reason) {
                    Some(fail) => waiting = worse(waiting, fail),
                    None => holds.hold(package.key, true),
                }
            }
            // Not sent: its reason is already counted.
            None => {}
            _ => lost = true,
        }
    }
    shared.commit_time(acked.len()).await;
    let recorded = record_acks(shared, &fence, &acked);
    let latest = recorded.as_ref().map_or(0, |done| {
        acked
            .iter()
            .filter(|(package, _)| done.contains(&package.key))
            .map(|(_, ordered)| ordered.head().position)
            .max()
            .unwrap_or(0)
    });
    if let Ok(done) = &recorded {
        for update_id in done {
            holds.release(*update_id);
        }
    }
    if lost {
        link.drop_data();
        waiting = worse(waiting, Fail::Network);
    }
    let progressed = match recorded {
        Ok(done) => {
            if done.len() < acked.len() {
                waiting = worse(waiting, Fail::Retry);
            }
            !done.is_empty()
        }
        Err(fail) => {
            waiting = worse(waiting, fail);
            false
        }
    };
    Ok(Round {
        progressed: progressed || waiting.is_none(),
        waiting,
        acked: latest,
        follow,
        due,
    })
}

/// A request's frames were lost: its socket closed or went silent.
struct Lost;

/// What a compound publication refusal means for its package: Epoch
/// waits for authority without resealing. Conflict, Malformed and Scope are
/// alarms (`None`): an honest device never causes them, so the note is held
/// on its own. Anything else (Expired, NotStaged, Reclaiming among them) is
/// retried with fresh permits and the same immutable bytes.
fn refused(reason: wire::Refusal) -> Option<Fail> {
    match reason {
        wire::Refusal::Epoch => Some(Fail::Authorization),
        wire::Refusal::Conflict | wire::Refusal::Malformed | wire::Refusal::Scope => None,
        _ => Some(Fail::Retry),
    }
}

/// The epoch `package` was sealed under, which its append permit must name
/// whatever the log's epoch is now: a package is never moved to another.
fn sealed_epoch(shared: &Shared, log: LogId, package: &Package) -> Result<[u8; 32], Fail> {
    descriptor_epoch(shared, log.id, &package.descriptor)
}

/// Fetch fresh permits for every package that lacks one, in as few
/// messages as fit.
async fn request_permits(
    shared: &Shared,
    permits: &mut Permits,
    holds: &mut Holds,
    log: LogId,
    packages: &[Package],
    follow: &mut bool,
) -> Result<(), Fail> {
    let mut wants: Vec<(PackageKey, bool, Want)> = Vec::new();
    for p in packages {
        if permits.get(p.key, false).is_none() {
            let body = BodyObject::new(p.body.clone()).map_err(|_| Fail::Local)?;
            wants.push((
                p.key,
                false,
                Want::Stage {
                    log,
                    body: body.commitment(),
                    len: body.bytes().len() as u32,
                },
            ));
        }
        if permits.get(p.key, true).is_none() {
            let epoch = match sealed_epoch(shared, log, p) {
                Ok(epoch) => epoch,
                // Its own persisted bytes do not open: it waits alone.
                Err(Fail::Local) => {
                    holds.hold(p.key, false);
                    continue;
                }
                Err(fail) => return Err(fail),
            };
            wants.push((
                p.key,
                true,
                Want::Append {
                    log,
                    event: p.descriptor.encode(),
                    epoch,
                },
            ));
        }
    }
    let mut waiting = None;
    let mut rest = wants.as_slice();
    while !rest.is_empty() {
        let mut take = 0;
        let mut size = 64;
        while take < rest.len() && take < bh_authz_proto::MAX_ITEMS {
            let item = match &rest[take].2 {
                Want::Append { event, .. } => 80 + event.len(),
                _ => 80,
            };
            if take > 0 && size + item > MAX_MESSAGE - 1024 {
                break;
            }
            size += item;
            take += 1;
        }
        let (batch, later) = rest.split_at(take);
        rest = later;
        let requested_at = Instant::now();
        let answer = shared
            .authz
            .request(
                shared,
                ToService::Permits {
                    items: batch.iter().map(|(_, _, want)| want.clone()).collect(),
                },
            )
            .await?;
        let FromService::Permits { items } = answer else {
            return Err(Fail::from_answer(&answer));
        };
        if items.len() != batch.len() {
            return Err(Fail::Network);
        }
        for ((package, append, _), item) in batch.iter().zip(items) {
            match item {
                Ok(signed) => permits.insert(
                    *package,
                    *append,
                    shared.endpoint.hosting_root,
                    signed,
                    requested_at,
                ),
                // The service could not read this package's event.
                Err(Refusal::Malformed) => holds.hold(*package, true),
                Err(reason) => {
                    // The base must first copy an account change, or this
                    // device's place in it changed: follow the account.
                    *follow |= matches!(reason, Refusal::AccountChangePending | Refusal::NotActive);
                    waiting = worse(waiting, ClientError::Refused(reason).into());
                }
            }
        }
    }
    match waiting {
        // One package's refusal leaves the others their permits.
        Some(Fail::Unregistered) => Err(Fail::Unregistered),
        _ => Ok(()),
    }
}

/// Persist only checked ordering commitments, while `fence` holds. An Ack
/// does not accept the author or retire any pending member; the receiver's
/// echo does that. One not recorded is learned again by an exact retry.
fn record_acks(
    shared: &Shared,
    fence: &SyncFence,
    acked: &[(&Package, Commitment)],
) -> Result<Vec<PackageKey>, Fail> {
    let mut recorded = Vec::new();
    for (package, ordered) in acked {
        let key = package.key;
        shared
            .owner
            .with_sync_fence(fence, |db| {
                match key {
                    PackageKey::Note(update_id) => db.acknowledge_note_update(update_id, ordered),
                    PackageKey::Typed(id) => db.acknowledge_typed_package(id, ordered),
                }
                .map(|_| ())
                .map_err(OwnerError::from)
            })
            .map_err(|error| match error {
                OwnerError::Store(_) => Fail::Local,
                other => fenced_fail(other),
            })?;
        recorded.push(key);
    }
    Ok(recorded)
}

#[cfg(test)]
mod pacing_tests {
    use super::*;
    use crate::tuning::{Pacing, Quiet};

    const fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }
    fn head(first: i64, update_id: i64) -> OutboxHead {
        OutboxHead {
            first,
            update_id,
            key: NoteKey {
                base: [1; 32],
                audience: [0; 32],
                note: [2; 32],
            },
        }
    }

    #[test]
    fn shipped_pacing_waits_after_the_last_edit_or_its_limit() {
        let t0 = Instant::now();
        let pacing = Pacing::default();
        assert_eq!(pacing.spacing, SPACING);
        assert_eq!(pacing.quiet, Some(Quiet::default()));
        let quiet = pacing.quiet.unwrap();
        let edits = Arc::new(Mutex::new(Edits::new(quiet.within)));
        let mut spacing = Spacing::new(pacing, Some(edits.clone()));
        // A fresh edit waits until it is 300 ms old.
        edits.lock().unwrap().record(1, t0);
        assert_eq!(spacing.eligible(&head(1, 1), t0), Err(t0 + quiet.after));
        assert_eq!(spacing.eligible(&head(1, 1), t0 + quiet.after), Ok(()));
        spacing.started(head(1, 1).key, t0 + quiet.after);
        // The spacing still composes: a start is at least 500 ms after the
        // previous one, even when the note is already quiet.
        edits.lock().unwrap().record(2, t0 + ms(350));
        assert_eq!(
            spacing.eligible(&head(1, 2), t0 + ms(650)),
            Err(t0 + quiet.after + SPACING)
        );
        assert_eq!(
            spacing.eligible(&head(1, 2), t0 + quiet.after + SPACING),
            Ok(())
        );
    }

    #[test]
    fn a_note_sends_within_one_second_of_its_first_unsent_edit() {
        let quiet = Quiet::default();
        let pacing = Pacing {
            spacing: Duration::ZERO,
            quiet: Some(quiet),
        };
        let t0 = Instant::now();
        let edits = Arc::new(Mutex::new(Edits::new(quiet.within)));
        let spacing = Spacing::new(pacing, Some(edits.clone()));
        // Continuous edits 100 ms apart: quiet never comes, so the first
        // unsent edit's limit decides.
        for id in 1..=11 {
            edits
                .lock()
                .unwrap()
                .record(id, t0 + ms(100) * (id as u32 - 1));
        }
        assert_eq!(
            spacing.eligible(&head(1, 11), t0 + ms(999)),
            Err(t0 + quiet.within)
        );
        assert_eq!(spacing.eligible(&head(1, 11), t0 + quiet.within), Ok(()));
    }

    #[test]
    fn edits_from_before_start_are_unknown_and_send_at_once() {
        let quiet = Quiet::default();
        let pacing = Pacing {
            spacing: Duration::ZERO,
            quiet: Some(quiet),
        };
        let t0 = Instant::now();
        let edits = Arc::new(Mutex::new(Edits::new(quiet.within)));
        // This client started with rows 5..=7 already pending: a backlog,
        // not typing, whose edit times it never saw.
        edits.lock().unwrap().unknown_through(7);
        let mut spacing = Spacing::new(pacing, Some(edits.clone()));
        assert_eq!(edits.lock().unwrap().at(5, t0), None);
        assert_eq!(spacing.eligible(&head(5, 7), t0), Ok(()));
        // Draining the backlog, then new typing, is timed normally: a note
        // whose first unsent edit is known again waits for quiet.
        spacing.started(head(5, 7).key, t0);
        edits.lock().unwrap().record(8, t0 + ms(50));
        assert_eq!(
            spacing.eligible(&head(8, 8), t0 + ms(100)),
            Err(t0 + ms(350))
        );
        assert_eq!(spacing.eligible(&head(8, 8), t0 + ms(350)), Ok(()));
    }

    #[test]
    fn a_quiet_period_waits_for_quiet_or_its_limit() {
        let quiet = Quiet {
            after: ms(300),
            within: ms(1000),
        };
        let pacing = Pacing {
            spacing: Duration::ZERO,
            quiet: Some(quiet),
        };
        let t0 = Instant::now();
        let edits = Arc::new(Mutex::new(Edits::new(quiet.within)));
        let spacing = Spacing::new(pacing, Some(edits.clone()));
        edits.lock().unwrap().record(1, t0);
        edits.lock().unwrap().record(3, t0 + ms(200));
        // The last edit is 100 ms old: wait until it is 300 ms old.
        assert_eq!(
            spacing.eligible(&head(1, 3), t0 + ms(300)),
            Err(t0 + ms(500))
        );
        assert_eq!(spacing.eligible(&head(1, 3), t0 + ms(500)), Ok(()));
        // Edits keep coming: no later than 1000 ms after the first.
        for n in 4..=9 {
            edits
                .lock()
                .unwrap()
                .record(n, t0 + ms(200) + ms(120) * (n as u32 - 3));
        }
        assert_eq!(
            spacing.eligible(&head(1, 9), t0 + ms(950)),
            Err(t0 + ms(1000))
        );
        assert_eq!(spacing.eligible(&head(1, 9), t0 + ms(1000)), Ok(()));
        // An edit not seen yet at a wake was just made.
        assert_eq!(
            spacing.eligible(&head(10, 10), t0 + ms(1000)),
            Err(t0 + ms(1300))
        );
        // No recorder wake saw id 11: its first eligibility check must
        // remember the time, rather than moving the deadline at each poll.
        assert_eq!(
            spacing.eligible(&head(11, 11), t0 + ms(2000)),
            Err(t0 + ms(2300))
        );
        assert_eq!(spacing.eligible(&head(11, 11), t0 + ms(2300)), Ok(()));
    }

    #[test]
    fn edits_older_than_the_limit_count_as_long_ago() {
        let t0 = Instant::now();
        let mut edits = Edits::new(ms(1000));
        edits.record(4, t0);
        edits.record(6, t0 + ms(1500));
        assert_eq!(edits.at(3, t0 + ms(1500)), None);
        assert_eq!(edits.at(4, t0 + ms(1500)), None);
        assert_eq!(edits.at(5, t0 + ms(1500)), Some(t0 + ms(1500)));
        // A highest id at or below one seen before adds nothing.
        edits.record(6, t0 + ms(1600));
        edits.record(2, t0 + ms(1600));
        assert_eq!(edits.at(6, t0 + ms(1700)), Some(t0 + ms(1500)));
    }
}
