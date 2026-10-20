//! Receiving the own base's log. Bounded batches are read from this
//! device's stored progress, never replayed from the genesis: each batch is
//! checked as transport (chained, bodies matching their commitments, a
//! receipt under the pinned hosting root for its exact last head), judged by
//! a `History` resumed from SQLite for that batch alone, and committed by the
//! owner with the receipt for the head it reaches. Only that COMMIT moves
//! progress; a failed batch is read again from the same place.
//!
//! A batch holds at most 64 events and is cut once its bodies pass a byte
//! budget, or where a body is missing. A cut prefix commits only with its own
//! exact receipt, from a read ending there. A missing body or an
//! unavailable key waits; unsupported semantics pause; only a verified
//! hosting receipt whose history contradicts this device's verified prefix
//! stops the log. Transport faults are retried and never judged.
//!
//! Subscriptions to the base log and the account log tell the client when
//! to read. They are hints: renewed over the same data socket before their
//! short permits end, and replaced after an expired or lost one.
//!
//! The receiver lane (`run_receiver`) owns this, the account following and
//! copying (`copier`) and its own data link. Each batch is read under a
//! `SyncFence` taken before its first request, and commits only while that
//! authority is still current.
use crate::{
    ClientError, Shared,
    backoff::Backoff,
    copier::{self, Copier},
    data::Answers,
    outbox::{self, Fail, Link, usable_until},
    register,
    scheduler::{PublishFacts, Readiness, ReceiveFacts},
};
use bh_authz_proto::{
    FromService, ReadBatchResult, Refusal, ToService, Want, account_log_id, account_log_unwrap,
};
use bh_device::{
    OwnerError,
    incoming::{StopReason, VerifiedBatch},
};
use bh_event::Outcome;
use bh_storage::sync_state::LogProgress;
use bh_sync::{
    BaseId, BodyObject, Commitment, Digest, Head, OpaqueEvent,
    permit::{self, LogId, LogKind, Scope},
    receipt::{self, RECEIPT_LEN},
    referenced_body,
    wire::{Request, Response},
};
use std::{sync::Arc, time::Duration};
use tokio::{sync::watch, time::Instant};

/// Positions in one read.
const BATCH: u64 = 64;
/// Ordinary base selection stays within the checked authorization reply.
const BASE_BATCH: u64 = 48;
/// Body bytes a batch holds before it is cut; its first event always fits.
const BATCH_BYTES: usize = 8 * 1024 * 1024;
/// Batches in one pass, so that publishing and copying are not starved.
const PASS: usize = 4;

/// Why receiving waits, if it does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Held {
    #[default]
    No,
    /// Bytes, a key or local configuration needed to judge the next event
    /// are missing.
    Missing,
    /// The next event needs semantics this build does not support.
    Unsupported,
}

/// One immediate attempt for each newly discovered hold, then 1s doubling
/// to 60s per note. Foreground wakes never reset these deadlines.
/// Metadata maintenance is O(H) in discovered held notes per invocation;
/// a sweep of H expired persistent holds can perform O(H²) existence checks.
#[derive(Default)]
struct HeldRetries {
    notes: std::collections::HashMap<bh_storage::NoteKey, (Instant, Duration)>,
    cursor: Option<bh_storage::NoteKey>,
}
impl HeldRetries {
    fn permit(&mut self, key: bh_storage::NoteKey, now: Instant) -> bool {
        let entry = self
            .notes
            .entry(key)
            .or_insert((now, Duration::from_secs(1)));
        if now < entry.0 {
            return false;
        }
        entry.0 = now + entry.1;
        entry.1 = (entry.1 * 2).min(Duration::from_secs(60));
        true
    }
    fn retry(&mut self, shared: &Shared) -> Result<bool, Fail> {
        let database = local(shared.owner.shared_database(shared.container))?;
        // Finish expired entries even if a caller explicitly released their
        // rows, so an obsolete deadline cannot cause a busy loop.
        let now = Instant::now();
        let expired: Vec<_> = self
            .notes
            .iter()
            .filter(|(_, v)| v.0 <= now)
            .map(|(k, _)| *k)
            .collect();
        for key in expired {
            if !local(
                database
                    .lock()
                    .expect("container writer lock")
                    .note_is_held(key),
            )? {
                self.notes.remove(&key);
            }
        }
        let keys = local(
            database
                .lock()
                .expect("container writer lock")
                .held_notes(self.cursor, 256),
        )?;
        if keys.is_empty() {
            self.cursor = None;
        }
        let mut moved = false;
        for key in keys {
            self.cursor = Some(key);
            let started = Instant::now();
            if !self.permit(key, started) {
                continue;
            }
            let result = shared.owner.retry_held(shared.container, key);
            // Backoff starts after the budgeted work, even if that work
            // takes longer than the initial delay.
            let entry = self.notes.get_mut(&key).expect("permitted retry");
            entry.0 = Instant::now() + entry.0.saturating_duration_since(started);
            let (outcomes, windows) = result.map_err(owner_fail)?;
            shared.windows.wake(windows);
            moved |= outcomes
                .iter()
                .any(|(_, o)| *o != bh_device::incoming::NoteOutcome::Waiting);
            if !local(
                database
                    .lock()
                    .expect("container writer lock")
                    .note_is_held(key),
            )? {
                self.notes.remove(&key);
            }
            // One budgeted note per pass; give receiving and publishing a
            // turn even when many notes cannot run on this device.
            break;
        }
        Ok(moved)
    }
}

struct Subscription {
    answers: Answers,
    renew_at: Instant,
}

/// What the receiver keeps between passes. None of it is durable: progress
/// lives in SQLite.
#[derive(Default)]
pub(crate) struct Receiver {
    log: Option<LogId>,
    retries: HeldRetries,
    base: Option<Subscription>,
    account: Option<Subscription>,
    /// The highest base head known to exist, proven by a hosting receipt.
    pub(crate) latest: u64,
    /// A producer-selected page needing legacy evidence. Retained across
    /// passes until the durable cursor passes this range.
    repair: Option<(u64, u64)>,
    /// ReadBatch reported an account/view change; ask the copier to follow.
    follow_account: bool,
    /// The last read reached the end of the log and nothing since has said
    /// it moved on.
    pub(crate) tail_known: bool,
    pub(crate) held: Held,
    /// The highest account-log position a notice mentioned.
    pub(crate) account_hint: u64,
    /// Told each committed batch's head, while a joined device bootstraps.
    pub(crate) progress: Option<tokio::sync::watch::Sender<crate::bootstrap::Progress>>,
    /// A joined device's bootstrap, before any authority exists for its
    /// container, commits without a sync fence. Never set otherwise.
    pub(crate) bootstrap: bool,
    /// The client's wakes, watched from before the first pass.
    wake: Option<watch::Receiver<u64>>,
    /// The publisher's facts, in the receiver lane.
    publish: Option<watch::Receiver<PublishFacts>>,
    /// The publisher's follow and unregistered counts already acted on.
    seen: (u64, u64),
}

/// What the publisher told the receiver since its last pass.
#[derive(Default)]
pub(crate) struct News {
    pub follow: bool,
    pub unregistered: bool,
}

async fn changed<T>(watched: &mut Option<watch::Receiver<T>>) {
    let Some(rx) = watched else {
        return std::future::pending().await;
    };
    if rx.changed().await.is_err() {
        std::future::pending().await
    }
}

impl Receiver {
    /// Watch the client's wakes, and in the receiver lane the publisher's
    /// facts, from now on.
    pub(crate) fn watch(
        &mut self,
        shared: &Shared,
        publish: Option<watch::Receiver<PublishFacts>>,
    ) {
        self.wake = Some(shared.wake.subscribe());
        self.publish = publish;
    }
    /// Mark every wake so far as seen, and take in the publisher's facts.
    /// Called before a pass looks at durable work, so a later wake is never
    /// lost.
    pub(crate) fn take_news(&mut self) -> News {
        if let Some(wake) = &mut self.wake {
            wake.borrow_and_update();
        }
        let Some(publish) = &mut self.publish else {
            return News::default();
        };
        let facts = publish.borrow_and_update().clone();
        self.exists(facts.latest);
        let news = News {
            follow: facts.follow != self.seen.0,
            unregistered: facts.unregistered != self.seen.1,
        };
        self.seen = (facts.follow, facts.unregistered);
        news
    }
    /// Whether the publisher's facts call for a pass now.
    fn publish_news(&self) -> bool {
        self.publish.as_ref().is_some_and(|publish| {
            let facts = publish.borrow();
            facts.latest > self.latest
                || facts.follow != self.seen.0
                || facts.unregistered != self.seen.1
        })
    }
    /// Whether verified progress has reached every head known to exist.
    pub(crate) fn caught_up(&self, position: u64) -> bool {
        self.tail_known && position >= self.latest && self.held == Held::No
    }
    /// A base head proven to exist, by an Ack or a receipt.
    pub(crate) fn exists(&mut self, position: u64) {
        self.latest = self.latest.max(position);
    }
    /// Read again before trusting the tail.
    pub(crate) fn recheck(&mut self) {
        self.tail_known = false;
    }
    pub(crate) fn take_follow_account(&mut self) -> bool {
        std::mem::take(&mut self.follow_account)
    }
    /// Tell a bootstrap's watcher how far verified progress has come.
    pub(crate) fn report(&self, done: u64) {
        if let Some(progress) = &self.progress {
            progress.send_replace(crate::bootstrap::Progress {
                done,
                total: self.latest.max(done),
            });
        }
    }
    /// Subscriptions end with their socket.
    pub(crate) fn drop_subscriptions(&mut self) {
        self.base = None;
        self.account = None;
        self.tail_known = false;
    }

    /// Wait up to `wait` for a wake, a renewal or a notice worth acting on.
    pub(crate) async fn wait(&mut self, shared: &Shared, wait: Duration, account_stopped: bool) {
        // Account stop skips pull entirely. Base stop can land at any point in
        // pull/retry, including after its initial check, so read the durable
        // latch here before selecting timers. Only disposable scheduling goes
        // away: held evidence and pending bytes stay in SQLite.
        let stopped = account_stopped
            || self
                .log
                .is_some_and(|log| progress(shared, log).is_ok_and(|p| p.stopped.is_some()));
        if stopped {
            self.retries = HeldRetries::default();
            // These subscriptions will no longer renew. Their past deadlines
            // must not replace the stopped client's ordinary backoff either.
            self.drop_subscriptions();
        }
        let mut until = Instant::now() + wait;
        if let Some(next) = self.retries.notes.values().map(|v| v.0).min() {
            until = until.min(next);
        }
        for renew in [&self.base, &self.account].into_iter().flatten() {
            until = until.min(renew.renew_at);
        }
        let root = shared.endpoint.hosting_root;
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(until) => return,
                _ = changed(&mut self.wake) => return,
                _ = changed(&mut self.publish) => {
                    if self.publish_news() {
                        return;
                    }
                }
                frame = next(&mut self.base) => {
                    if self.base_notice(root, frame) {
                        return;
                    }
                }
                frame = next(&mut self.account) => {
                    let Some(Response::Head { head, .. }) = frame else {
                        self.account = None;
                        return;
                    };
                    if head.position > self.account_hint {
                        self.account_hint = head.position;
                        return;
                    }
                }
            }
        }
    }

    /// Whether a base notice calls for a read. Only a receipt verified for
    /// the notice's own head proves that head exists.
    fn base_notice(&mut self, root: [u8; 32], frame: Option<Response>) -> bool {
        let (Some(Response::Head { head, receipt, .. }), Some(log)) = (frame, self.log) else {
            // Expired, refused or lost: subscribe again, then read.
            self.base = None;
            self.tail_known = false;
            return true;
        };
        let proven = receipt
            .filter(|bytes| bytes.len() == RECEIPT_LEN)
            .and_then(|bytes| receipt::verify(&root, BaseId(log.id), &bytes).ok())
            .is_some_and(|r| r.head() == head);
        if !proven {
            self.tail_known = false;
            return true;
        }
        let newer = head.position > self.latest;
        self.exists(head.position);
        newer
    }
}

async fn next(subscription: &mut Option<Subscription>) -> Option<Response> {
    match subscription {
        Some(sub) => sub.answers.next().await,
        None => std::future::pending().await,
    }
}

fn local<T, E>(result: Result<T, E>) -> Result<T, Fail> {
    result.map_err(|_| Fail::Local)
}

/// A permit, or why the service refused it: an unknown base is registered
/// again, other refusals wait for authority.
pub(crate) fn granted(item: Result<Vec<u8>, Refusal>) -> Result<Vec<u8>, Fail> {
    item.map_err(|reason| ClientError::Refused(reason).into())
}

/// The one permit a single-item request was answered with.
pub(crate) fn only(answer: FromService) -> Result<Vec<u8>, Fail> {
    let FromService::Permits { items } = answer else {
        return Err(Fail::from_answer(&answer));
    };
    let [item] = <[_; 1]>::try_from(items).map_err(|_| Fail::Network)?;
    granted(item)
}

fn progress(shared: &Shared, log: LogId) -> Result<LogProgress, Fail> {
    let database = local(shared.owner.shared_database(shared.container))?;
    let progress = local(
        database
            .lock()
            .expect("container writer lock")
            .log_progress(log.kind as u8, log.id),
    )?;
    progress.ok_or(Fail::Local)
}

/// Keep both subscriptions current: one taken now if it is missing or its
/// permit is near its end. A renewal replaces the earlier one on the same
/// socket; the edge ends the old one silently.
async fn subscribe(
    shared: &Shared,
    link: &mut Link,
    receiver: &mut Receiver,
    log: LogId,
    position: u64,
) -> Result<(), Fail> {
    let identity = shared.signer.identity().map_err(|_| Fail::Authorization)?;
    let account = LogId {
        kind: LogKind::Account,
        id: local(account_log_id(&identity.genesis))?,
    };
    let account_at = shared
        .signer
        .current_account()
        .map_err(|_| Fail::Authorization)?
        .head()
        .position;
    let now = Instant::now();
    let due = |s: &Option<Subscription>| s.as_ref().is_none_or(|s| now >= s.renew_at);
    let mut wants = Vec::new();
    if due(&receiver.base) {
        wants.push((true, log, position));
    }
    if due(&receiver.account) {
        wants.push((false, account, account_at));
    }
    if wants.is_empty() {
        return Ok(());
    }
    let requested_at = Instant::now();
    let answer = shared
        .authz
        .request(
            shared,
            ToService::Permits {
                items: wants
                    .iter()
                    .map(|(_, log, _)| Want::Subscribe { log: *log })
                    .collect(),
            },
        )
        .await?;
    let FromService::Permits { items } = answer else {
        return Err(Fail::from_answer(&answer));
    };
    if items.len() != wants.len() {
        return Err(Fail::Network);
    }
    let data = link.data(shared).await?;
    for ((base, _, after), item) in wants.into_iter().zip(items) {
        let permit = granted(item)?;
        let renew_at = usable_until(shared.endpoint.hosting_root, &permit, requested_at)
            .ok_or(Fail::Network)?;
        let answers = data
            .send(|id| Request::Subscribe { id, permit, after })
            .map_err(|_| Fail::Network)?;
        let subscription = Some(Subscription { answers, renew_at });
        if base {
            if receiver.base.is_none() {
                // Notices before this one may have been missed.
                receiver.tail_known = false;
            }
            receiver.base = subscription;
        } else {
            receiver.account = subscription;
        }
    }
    Ok(())
}

/// One pass: read and commit up to a few batches while the log is known to
/// have more. Returns whether anything committed.
pub(crate) async fn pull(
    shared: &Shared,
    link: &mut Link,
    receiver: &mut Receiver,
    log: LogId,
) -> Result<bool, Fail> {
    receiver.log = Some(log);
    let start = progress(shared, log)?;
    if start.stopped.is_some() {
        return Ok(false);
    }
    let mut committed = receiver.retries.retry(shared)?;
    subscribe(shared, link, receiver, log, start.position).await?;
    for _ in 0..PASS {
        let progress = progress(shared, log)?;
        if progress.stopped.is_some() || receiver.caught_up(progress.position) {
            break;
        }
        match batch(shared, link, receiver, log, &progress).await? {
            Batch::End => {
                receiver.held = Held::No;
                if progress.position < receiver.latest {
                    receiver.tail_known = false;
                    return Err(Fail::Missing);
                }
                receiver.tail_known = true;
                break;
            }
            Batch::Committed { more } => {
                committed = true;
                receiver.held = Held::No;
                receiver.report(self::progress(shared, log)?.position);
                receiver.retries.retry(shared)?;
                if !more {
                    break;
                }
            }
            Batch::Held(held) => {
                receiver.held = held;
                // Whatever committed before the wait is kept; try again later.
                return match held {
                    Held::Unsupported => Err(Fail::Unsupported),
                    _ => Err(Fail::Missing),
                };
            }
            Batch::Stopped => break,
        }
    }
    Ok(committed)
}

enum Batch {
    /// Nothing after this device's progress.
    End,
    /// A batch committed; `more` if the log is known to go on.
    Committed {
        more: bool,
    },
    Held(Held),
    Stopped,
}

/// An exact read of `first..=last` and the receipt for its returned tail,
/// its permit asked for on the shared authorization dispatcher.
pub(crate) async fn read_events(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    first: u64,
    last: u64,
) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, Option<[u8; RECEIPT_LEN]>), Fail> {
    let answer = shared
        .authz
        .request(
            shared,
            ToService::Permits {
                items: vec![Want::ReadEvents { log, first, last }],
            },
        )
        .await?;
    let permit = only(answer)?;
    read_events_with_permit(shared, link, permit).await
}

/// As `read_events`, holding the exclusive authorization lease: pairing's
/// reads, which run on their own client.
pub(crate) async fn read_events_exclusive(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    first: u64,
    last: u64,
) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, Option<[u8; RECEIPT_LEN]>), Fail> {
    let answer = {
        let mut session = shared.authz.session(shared).await?;
        session
            .ask(ToService::Permits {
                items: vec![Want::ReadEvents { log, first, last }],
            })
            .await?
    };
    let permit = only(answer)?;
    read_events_with_permit(shared, link, permit).await
}

async fn read_events_with_permit(
    shared: &Shared,
    link: &mut Link,
    permit: Vec<u8>,
) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, Option<[u8; RECEIPT_LEN]>), Fail> {
    let data = link.data(shared).await?;
    let response = data
        .ask(|id| Request::Read { id, permit })
        .await
        .map_err(|_| Fail::Network)?;
    match response {
        Response::Events { items, receipt, .. } => Ok((items, receipt)),
        other => Err(Fail::from_response(&other)),
    }
}

/// Validated authorization selection; the permit signs exactly this page's
/// ordered body references, not any other objects. History still judges it.
enum ReadBatchPage {
    Selected {
        items: Vec<(Vec<u8>, Vec<u8>)>,
        receipt: Box<Option<[u8; RECEIPT_LEN]>>,
        body_permit: Option<Vec<u8>>,
        possibly_more: bool,
    },
    Repair(Vec<u8>),
}

async fn selected_batch(shared: &Shared, log: LogId, after: Head) -> Result<ReadBatchPage, Fail> {
    let requested_at = Instant::now();
    let answer = shared
        .authz
        .request(
            shared,
            ToService::ReadBatch {
                want: Want::ReadBatch {
                    log,
                    after,
                    max_events: BASE_BATCH as u16,
                },
            },
        )
        .await?;
    validate_batch_reply(
        shared.endpoint.hosting_root,
        log,
        after,
        requested_at,
        answer,
    )
}

fn validate_batch_reply(
    root: [u8; 32],
    log: LogId,
    after: Head,
    requested_at: Instant,
    answer: FromService,
) -> Result<ReadBatchPage, Fail> {
    let FromService::ReadBatch {
        log: echoed_log,
        after: echoed_after,
        issued_ms,
        deadline_ms,
        result,
    } = answer
    else {
        return Err(match answer {
            FromService::Refused {
                reason: Refusal::AccountChangePending | Refusal::NotActive,
            } => Fail::Missing,
            FromService::Refused {
                reason: Refusal::Unsupported,
            } => Fail::Unsupported,
            FromService::Refused {
                reason: Refusal::Malformed,
            } => Fail::Network,
            _ => Fail::from_answer(&answer),
        });
    };
    let lifetime = deadline_ms
        .checked_sub(issued_ms)
        .filter(|n| *n > 0 && *n <= permit::MAX_PERMIT_WINDOW_MS)
        .and_then(|n| Duration::from_millis(n).checked_sub(Duration::from_secs(5)))
        .ok_or(Fail::Network)?;
    if echoed_log != log || echoed_after != after || requested_at.elapsed() >= lifetime {
        return Err(Fail::Network);
    }
    let check_permit = |signed: &[u8]| -> Result<permit::Permit, Fail> {
        let until = usable_until(root, signed, requested_at).ok_or(Fail::Network)?;
        if Instant::now() >= until {
            return Err(Fail::Network);
        }
        let signed_issued = permit::issued_ms(signed).map_err(|_| Fail::Network)?;
        let verified = permit::verify(root, signed, signed_issued).map_err(|_| Fail::Network)?;
        if verified.issued_ms != issued_ms || verified.deadline_ms != deadline_ms {
            return Err(Fail::Network);
        }
        Ok(verified)
    };
    match result {
        ReadBatchResult::Repair { events_permit } => {
            let verified = check_permit(&events_permit)?;
            if verified.scope
                != (Scope::ReadEvents {
                    log,
                    first: after.position + 1,
                    last: after.position + BASE_BATCH,
                })
            {
                return Err(Fail::Network);
            }
            Ok(ReadBatchPage::Repair(events_permit))
        }
        ReadBatchResult::Selected {
            items,
            receipt,
            body_permit,
            possibly_more,
        } => {
            if items.len() > BASE_BATCH as usize
                || (items.is_empty()
                    && (receipt.is_some() || body_permit.is_some() || possibly_more))
            {
                return Err(Fail::Network);
            }
            let ordered = ordered_events(BaseId(log.id), after.position + 1, &items)?;
            if let Some((tail, _)) = ordered.last() {
                proven(root, BaseId(log.id), receipt, tail.head())?;
            }
            let bodies: Vec<_> = ordered
                .iter()
                .filter_map(|(_, event)| referenced_body(event).ok())
                .collect();
            match (body_permit.as_deref(), bodies.is_empty()) {
                (None, true) => {}
                (Some(signed), false) => {
                    let verified = check_permit(signed)?;
                    if verified.scope != (Scope::ReadBodies { log, bodies }) {
                        return Err(Fail::Network);
                    }
                }
                _ => return Err(Fail::Network),
            }
            Ok(ReadBatchPage::Selected {
                items,
                receipt: Box::new(receipt),
                body_permit,
                possibly_more,
            })
        }
    }
}

fn repair_page_length(first: u64, last: u64, count: usize) -> Result<(), Fail> {
    let range = last
        .checked_sub(first)
        .and_then(|n| n.checked_add(1))
        .ok_or(Fail::Network)?;
    if count as u64 > range {
        return Err(Fail::Network);
    }
    Ok(())
}

/// The batch's ordered events, checked as transport: in this base, at the
/// positions asked for, chained among themselves and each committing its
/// descriptor. Not judged: whether the first continues this device's
/// verified head is `History`'s decision.
pub(crate) fn ordered_events(
    base: BaseId,
    first: u64,
    items: &[(Vec<u8>, Vec<u8>)],
) -> Result<Vec<(Commitment, OpaqueEvent)>, Fail> {
    let mut ordered: Vec<(Commitment, OpaqueEvent)> = Vec::with_capacity(items.len());
    for (index, (commitment, event)) in items.iter().enumerate() {
        let commitment = Commitment::decode(commitment).map_err(|_| Fail::Network)?;
        let event = OpaqueEvent::decode(event).map_err(|_| Fail::Network)?;
        let chained = match ordered.last() {
            None => true,
            Some((before, _)) => commitment.verify_next(base, before.head()).is_ok(),
        };
        if commitment.base() != base
            || commitment.head().position != first + index as u64
            || !chained
            || commitment.verify_body(&event).is_err()
        {
            return Err(Fail::Network);
        }
        ordered.push((commitment, event));
    }
    Ok(ordered)
}

/// The bodies of a prefix of `events`, in order: `None` for an event that
/// names no readable body (History judges it without one). Stops at the
/// byte budget, and at a body the log says is missing (`true`).
async fn read_bodies(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    events: &[(Commitment, OpaqueEvent)],
    selected_permit: Option<Vec<u8>>,
) -> Result<(Vec<Option<Vec<u8>>>, bool), Fail> {
    let named: Vec<Option<Digest>> = events
        .iter()
        .map(|(_, event)| referenced_body(event).ok())
        .collect();
    let wanted: Vec<Digest> = named.iter().flatten().copied().collect();
    let mut fetched: Vec<Vec<u8>> = Vec::new();
    let mut missing = false;
    if !wanted.is_empty() {
        let permit = if let Some(permit) = selected_permit {
            permit
        } else {
            let answer = shared
                .authz
                .request(
                    shared,
                    ToService::Permits {
                        items: vec![Want::ReadBodies {
                            log,
                            bodies: wanted.clone(),
                        }],
                    },
                )
                .await?;
            only(answer)?
        };
        let data = link.data(shared).await?;
        let mut answers = data
            .send(|id| Request::Read { id, permit })
            .map_err(|_| Fail::Network)?;
        let mut bytes = 0;
        while fetched.len() < wanted.len() && bytes < BATCH_BYTES {
            match answers.next().await {
                Some(Response::Body {
                    index,
                    last,
                    bytes: body,
                    ..
                }) => {
                    let expected = wanted[fetched.len()];
                    let matches = BodyObject::new(body.clone())
                        .is_ok_and(|object| object.commitment() == expected);
                    if usize::from(index) != fetched.len()
                        || last != (fetched.len() + 1 == wanted.len())
                        || !matches
                    {
                        return Err(Fail::Network);
                    }
                    bytes += body.len();
                    fetched.push(body);
                }
                Some(Response::Refused {
                    reason: bh_sync::wire::Refusal::Missing,
                    ..
                }) => {
                    missing = true;
                    break;
                }
                // Only expiry is a partial page, not an arbitrary refusal.
                Some(Response::Refused {
                    reason: bh_sync::wire::Refusal::Expired,
                    ..
                }) if !fetched.is_empty() => break,
                Some(other) => return Err(Fail::from_response(&other)),
                // A stream that ends without its last frame is incomplete.
                None => return Err(Fail::Network),
            }
        }
    }
    let mut fetched = fetched.into_iter();
    let mut bodies = Vec::with_capacity(events.len());
    for name in named {
        match name {
            None => bodies.push(None),
            Some(_) => match fetched.next() {
                Some(body) => bodies.push(Some(body)),
                None => break,
            },
        }
    }
    let missing = missing && bodies.len() < events.len();
    Ok((bodies, missing))
}

/// A receipt for exactly `head`, verified under the pinned root.
fn proven(
    root: [u8; 32],
    base: BaseId,
    receipt: Option<[u8; RECEIPT_LEN]>,
    head: Head,
) -> Result<[u8; RECEIPT_LEN], Fail> {
    let receipt = receipt.ok_or(Fail::Network)?;
    match receipt::verify(&root, base, &receipt) {
        Ok(verified) if verified.head() == head => Ok(receipt),
        _ => Err(Fail::Network),
    }
}

fn owner_fail(error: OwnerError) -> Fail {
    match error {
        OwnerError::Unbound | OwnerError::AnchorMismatch => Fail::Authorization,
        // A receipt or chain the owner would not take: read it again.
        OwnerError::InvalidBatch => Fail::Network,
        OwnerError::Stopped => Fail::Stopped,
        _ => Fail::Local,
    }
}

async fn batch(
    shared: &Shared,
    link: &mut Link,
    receiver: &mut Receiver,
    log: LogId,
    progress: &LogProgress,
) -> Result<Batch, Fail> {
    let root = shared.endpoint.hosting_root;
    let base = BaseId(log.id);
    let first = progress.position + 1;
    // Everything below is decided under the authority current now; the
    // commit rechecks it. A bootstrap has none yet.
    let fence = if receiver.bootstrap {
        None
    } else {
        Some(
            shared
                .owner
                .sync_fence(shared.container, log)
                .map_err(owner_fail)?,
        )
    };
    if receiver
        .repair
        .is_some_and(|(_, last)| progress.position >= last)
    {
        receiver.repair = None;
    }
    // This device's account may be ahead of the last base event it applied,
    // including while a joined device replays the base. Keep the existing
    // control-copy catch-up path until its locally known account head appears
    // in applied history. This is deliberately broader than the producer's
    // server-side copy-lag refusal and is not fallback after a failed batch.
    let copied = progress.account.map_or(0, |(position, _)| position);
    let account_ahead = shared
        .signer
        .current_account()
        .map_err(|_| Fail::Authorization)?
        .head()
        .position
        > copied;
    let (items, receipt, body_permit, more) = if let Some((_, last)) = receiver.repair {
        let bound = last.min(first + BATCH - 1);
        let (items, receipt) = read_events(shared, link, log, first, bound).await?;
        repair_page_length(first, bound, items.len())?;
        (items, receipt, None, true)
    } else if account_ahead {
        let (items, receipt) = read_events(shared, link, log, first, first + BATCH - 1).await?;
        let full = items.len() as u64 == BATCH;
        (items, receipt, None, full)
    } else {
        let after = Head {
            position: progress.position,
            hash: Digest(progress.head_hash),
        };
        let selected = match selected_batch(shared, log, after).await {
            // Today only AccountChangePending and NotActive map to Missing
            // from selected_batch. Revisit this follow if a new source does.
            // A routine account change is followed, not missing history: the
            // tail is not known, so nothing claims to be caught up.
            Err(Fail::Missing) => {
                receiver.follow_account = true;
                receiver.tail_known = false;
                return Err(Fail::Missing);
            }
            other => other?,
        };
        match selected {
            ReadBatchPage::Selected {
                items,
                receipt,
                body_permit,
                possibly_more,
            } => (items, *receipt, body_permit, possibly_more),
            ReadBatchPage::Repair(events_permit) => {
                receiver.repair = Some((first, first + BASE_BATCH - 1));
                let (items, receipt) = read_events_with_permit(shared, link, events_permit).await?;
                repair_page_length(first, first + BASE_BATCH - 1, items.len())?;
                (items, receipt, None, false)
            }
        }
    };
    if items.is_empty() {
        return Ok(Batch::End);
    }
    let ordered = ordered_events(base, first, &items)?;
    let tail = ordered.last().expect("not empty").0.head();
    let receipt = proven(root, base, receipt, tail)?;
    receiver.exists(tail.position);
    drop(items);
    let (bodies, missing) = read_bodies(shared, link, log, &ordered, body_permit).await?;

    // A History from the durable continuation, for this batch only. Its
    // in-memory transitions are dropped with it: only the owner's COMMIT
    // below makes them durable.
    let identity = shared.signer.identity().map_err(|_| Fail::Authorization)?;
    let mut history = match shared
        .owner
        .history(shared.container, log, &identity.anchor, root, 1)
    {
        Ok(history) => history,
        Err(OwnerError::Stopped) => return Ok(Batch::Stopped),
        Err(OwnerError::Unavailable) => return Ok(Batch::Held(Held::Missing)),
        Err(error) => return Err(owner_fail(error)),
    };
    let mut events = Vec::with_capacity(bodies.len());
    let mut stop = false;
    let mut held = missing.then_some(Held::Missing);
    for ((ordered, event), body) in ordered.iter().zip(&bodies) {
        let mut prepared = None;
        shared
            .signer
            .with_base_keys(base, &mut |m, k| {
                prepared = Some(history.prepare(ordered, event, body.as_deref(), m, Some(k)));
            })
            .map_err(|_| Fail::Authorization)?;
        match prepared.ok_or(Fail::Authorization)? {
            Ok(prepared) => {
                events.push(
                    history
                        .consume_unapplied(prepared)
                        .map_err(|_| Fail::Local)?,
                );
            }
            // The receipt for this batch's tail verified: the hosting
            // service ordered history that contradicts this device's.
            Err(Outcome::IntegrityStop) => {
                stop = true;
                break;
            }
            Err(Outcome::UnsupportedPause) => {
                held = Some(Held::Unsupported);
                break;
            }
            Err(_) => {
                held = Some(Held::Missing);
                break;
            }
        }
    }
    drop(history);
    let reached = events.last().map(|e| e.head());
    if let Some(head) = reached {
        // A cut prefix is committed with a receipt for its own head.
        let receipt = if head == tail {
            receipt
        } else {
            let (items, receipt) =
                read_events(shared, link, log, head.position, head.position).await?;
            let last = ordered_events(base, head.position, &items)?;
            if last.last().map(|(c, _)| c.head()) != Some(head) {
                return Err(Fail::Network);
            }
            proven(root, base, receipt, head)?
        };
        let batch = VerifiedBatch {
            log,
            events,
            head,
            receipt,
        };
        shared.commit_time(1).await;
        let (_, windows) = match &fence {
            Some(fence) => shared
                .owner
                .apply_remote_batch_fenced(shared.container, fence, batch),
            None => shared
                .owner
                .apply_remote_batch_queued(shared.container, batch),
        }
        .map_err(owner_fail)?;
        shared.windows.wake(windows);
    }
    if stop {
        local(
            shared
                .owner
                .record_stop(shared.container, log, StopReason::Integrity),
        )?;
        return Ok(Batch::Stopped);
    }
    if let Some(held) = held {
        return Ok(Batch::Held(held));
    }
    match reached {
        Some(head) => Ok(Batch::Committed {
            more: more || head != tail || head.position < receiver.latest,
        }),
        None => Err(Fail::Network),
    }
}

/// The account originals the account log orders from position `first`, at
/// most one read's worth, each the exact canonical wrapping its commitment
/// names; and whether the read was full. The account owner verifies them.
pub(crate) async fn read_account(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    first: u64,
) -> Result<(Vec<Vec<u8>>, bool), Fail> {
    let (items, _) = read_events(shared, link, log, first, first + BATCH - 1).await?;
    let full = items.len() as u64 == BATCH;
    let ordered = ordered_events(BaseId(log.id), first, &items)?;
    let mut originals = Vec::with_capacity(ordered.len());
    for (commitment, event) in &ordered {
        if commitment.route() != bh_sync::Route::Control {
            return Err(Fail::Network);
        }
        let (original, _) = account_log_unwrap(event).map_err(|_| Fail::Network)?;
        originals.push(original.to_vec());
    }
    Ok((originals, full))
}

/// How often the receiver passes without a wake, notice or other reason.
const POLL: Duration = Duration::from_secs(1);

/// The receiver lane: receive, follow the account and copy its changes, and
/// grant publication while its prerequisites hold. Ends at halt, closing its
/// link.
pub(crate) async fn run_receiver(
    shared: Arc<Shared>,
    mut link: Link,
    log: LogId,
    publish: watch::Receiver<PublishFacts>,
    facts: watch::Sender<ReceiveFacts>,
) {
    tokio::select! {
        _ = shared.halted() => {}
        _ = receive(&shared, &mut link, log, publish, &facts) => {}
    }
    link.shutdown().await;
}

async fn receive(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    publish: watch::Receiver<PublishFacts>,
    facts: &watch::Sender<ReceiveFacts>,
) {
    let mut receiver = Receiver::default();
    receiver.watch(shared, Some(publish));
    let mut copier = Copier::default();
    let mut ready = Readiness::new(facts);
    let mut backoff = Backoff::default();
    loop {
        let news = receiver.take_news();
        copier.follow |= news.follow;
        let mut waiting = None;
        let mut progressed = false;
        if news.unregistered {
            ready.withdraw();
            if let Err(fail) = register::reregister(shared, link).await {
                waiting = outbox::worse(waiting, fail);
            }
        }
        if copier.stopped {
            // Nothing more is applied or published once the account stopped.
            waiting = Some(Fail::Stopped);
        } else {
            grant(shared, log, &mut ready);
            match pull(shared, link, &mut receiver, log).await {
                Ok(moved) => progressed |= moved,
                Err(fail) => waiting = outbox::worse(waiting, fail),
            }
            copier.follow |= receiver.take_follow_account();
            match copier::step(shared, link, &mut copier, &mut receiver, log, &mut ready).await {
                Ok(moved) => progressed |= moved,
                Err(fail) => waiting = outbox::worse(waiting, fail),
            }
        }
        // Control work, if any, is over: grant again unless stopped.
        if copier.stopped {
            ready.withdraw();
        } else {
            grant(shared, log, &mut ready);
        }
        let wait = match waiting {
            Some(Fail::Unregistered) => {
                ready.withdraw();
                match register::reregister(shared, link).await {
                    Ok(()) => grant(shared, log, &mut ready),
                    Err(fail) => waiting = Some(fail),
                }
                Some(backoff.next())
            }
            Some(Fail::Network) => {
                link.drop_data();
                receiver.drop_subscriptions();
                Some(backoff.next())
            }
            Some(Fail::Authorization | Fail::Missing | Fail::Unsupported | Fail::Stopped) => {
                Some(backoff.next())
            }
            Some(Fail::Retry) if !progressed => Some(backoff.next()),
            _ if progressed => {
                backoff.reset();
                None
            }
            _ => {
                backoff.reset();
                Some(POLL)
            }
        };
        facts.send_modify(|f| {
            f.started = true;
            f.waiting = waiting;
            f.held = receiver.held;
            f.tail_known = receiver.tail_known;
            f.latest = receiver.latest;
            f.unsettled = copier.unsettled;
            f.control_not_accepted = copier.not_accepted;
            f.stopped = copier.stopped;
            f.revision = f.revision.wrapping_add(1);
        });
        if let Some(wait) = wait {
            receiver.wait(shared, wait, copier.stopped).await;
        }
    }
}

/// Grant publication while authority for the own base is current and the
/// base is not stopped; withdraw it otherwise.
fn grant(shared: &Shared, log: LogId, ready: &mut Readiness<'_>) {
    match shared.owner.sync_fence(shared.container, log) {
        Ok(_) => ready.grant(),
        Err(_) => ready.withdraw(),
    }
}

#[cfg(test)]
#[path = "puller_tests.rs"]
mod scheduling_tests;

#[cfg(test)]
mod held_retry_tests {
    use super::*;
    #[test]
    fn saves_do_not_retry_storm_and_other_notes_have_their_own_backoff() {
        let mut retry = HeldRetries::default();
        let now = Instant::now();
        let a = bh_storage::NoteKey {
            base: [1; 32],
            audience: [0; 32],
            note: [1; 32],
        };
        let b = bh_storage::NoteKey { note: [2; 32], ..a };
        assert!(retry.permit(a, now));
        for _ in 0..1000 {
            assert!(!retry.permit(a, now));
        }
        assert!(retry.permit(b, now));
        assert!(retry.permit(a, now + Duration::from_secs(1)));
        assert!(!retry.permit(a, now + Duration::from_secs(2)));
        assert!(retry.permit(a, now + Duration::from_secs(3)));
        // Restart has no remembered deadline: one immediate retry.
        assert!(HeldRetries::default().permit(a, now));
    }
}
