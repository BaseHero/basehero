//! The account's trust lane, in the receiver after the copier's step: it
//! orders the one trust control this device staged, rotates the personal
//! key once a removal takes effect, and accepts a rotation another device
//! ordered.
//!
//! A staged control is sent byte for byte: its body and attachment as staged,
//! a rotation's raw seal frame in its padded transport object (purpose 2).
//! Once its append may have reached the log, the service is asked whether it
//! was ordered before anything is sent again, so a lost answer never costs a
//! second entry. The service's confirmation and its accepted head are
//! verified under the hosting root for exactly these bytes, this account
//! log, a fresh challenge and the staged position; then the account is
//! followed, and verified history alone settles the stage. A stage is
//! dropped without its order only when the service refused these exact bytes
//! for good and a later follow still stands at their predecessor; a lost
//! answer, a transport error, "not ordered yet" or a moved head never drop it.
//!
//! A rotation is staged for the latest effect due at the time a fresh,
//! challenged accepted head names, never the device clock, which only says
//! when to look. Its new key exists only in its seals until verified history
//! orders it; the key that lost a race is never accepted.
use crate::{
    Shared,
    account_evidence::{self, EvidenceFailure},
    backoff::Backoff,
    copier::{Copier, match_stored_accepted, stored_time},
    outbox::{Fail, Link},
    puller::{granted, only},
    scheduler::Readiness,
};
use bh_account::{
    AccountEvent, DeviceState, RequestState,
    journal::{AccountJournal, HistoryCursor, StagedControl},
    owner::staging::{
        Settled, Settlement, device_seals_digest, published_device_digest, rotation_body_digest,
        signs_rotation_body,
    },
    storage::DeviceJournal,
};
use bh_authz_proto::{
    FromService, RecoveryAttachment, Refusal, ToService, Want, account_log_id, account_log_wrap,
    rotation_body, rotation_frame,
};
use bh_sync::{
    BodyObject, Digest, Route,
    evidence::{AcceptedHead, OrderingConfirmation, TimeBounds},
    permit::{AppendAck, LogId, LogKind},
    wire::{self, Request, Response},
};
use tokio::time::Instant;

/// The tags of the trust controls this lane reads.
const CANCEL: u8 = 7;
const REPLACE_RECOVERY: u8 = 8;
const ROTATE: u8 = 9;

/// The account position whose event publishes the signup's personal key.
const SIGNUP_PUBLICATION: u64 = 3;

/// How verified history took a trust control this device staged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ordered {
    /// Ordered, at the time its confirmation names.
    Accepted { confirmation: TimeBounds },
    /// A cancel ordered or refused only once its request's deadline had
    /// passed: the removal already took effect.
    CancelTookEffect,
    /// Another entry took its position; nothing staged was applied.
    Lost,
    /// The service refused these exact bytes for good at the head they
    /// follow; nothing staged was applied.
    Refused,
}

/// One settled trust control: its tag, the account position it was staged
/// for, and how it settled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderedControl {
    pub kind: u8,
    pub position: u64,
    pub outcome: Ordered,
    /// For an ordered removal request still waiting: when it takes effect,
    /// its confirmation's `latest_ms` plus the removal wait. `None` once it
    /// lapsed, and for every other control.
    pub deadline_ms: Option<u64>,
}

/// What the lane keeps between passes. None of it is durable: the stage and
/// history are.
#[derive(Default)]
pub(crate) struct Trust {
    /// Staged bytes whose append may have reached the log: asked about
    /// before they are submitted again.
    sent: Option<Vec<u8>>,
    /// Staged bytes the service confirmed ordered: following settles them.
    confirmed: Option<Vec<u8>>,
    /// Staged bytes the service refused for good, and why.
    refused: Option<(Vec<u8>, Refusal)>,
    order: Paced,
    /// Rotating: reset only when a rotation settles, so one the home keeps
    /// refusing is retried on a growing backoff.
    rotate: Paced,
    accept: Paced,
    /// The personal publication this device is known to hold accepted.
    accepted: Option<[u8; 32]>,
}

/// When an attempt may run again, after a failure.
#[derive(Default)]
struct Paced {
    at: Option<Instant>,
    backoff: Backoff,
}
impl Paced {
    fn ready(&self) -> bool {
        self.at.is_none_or(|at| Instant::now() >= at)
    }
    fn failed(&mut self) {
        self.at = Some(Instant::now() + self.backoff.next());
    }
    fn done(&mut self) {
        self.at = None;
        self.backoff.reset();
    }
}

fn local<T, E>(result: Result<T, E>) -> Result<T, Fail> {
    result.map_err(|_| Fail::Local)
}

fn authority<T, E>(result: Result<T, E>) -> Result<T, Fail> {
    result.map_err(|_| Fail::Authorization)
}

fn account_log(shared: &Shared) -> Result<LogId, Fail> {
    let identity = authority(shared.signer.identity())?;
    Ok(LogId {
        kind: LogKind::Account,
        id: local(account_log_id(&identity.genesis))?,
    })
}

/// One pass: settle what history took, order what is staged, accept a
/// rotation another device ordered, or rotate for an effect now due.
pub(crate) async fn step(
    shared: &Shared,
    link: &mut Link,
    trust: &mut Trust,
    copier: &mut Copier,
    ready: &mut Readiness<'_>,
) -> Result<bool, Fail> {
    if copier.stopped {
        return Ok(false);
    }
    let Some(staged) = authority(shared.signer.staged_control())? else {
        let accepted = accept_followed(shared, link, trust).await?;
        let rotated = rotate_if_due(shared, link, trust, copier, ready).await?;
        return Ok(accepted || rotated);
    };
    // The owner may be lent for a moment (the publisher signs with it):
    // settling waits for the next pass.
    match shared.signer.settle_staged() {
        Ok(Some(settlement)) => settle(shared, trust, settlement).await,
        Ok(None) => order_staged(shared, link, trust, copier, ready, &staged).await,
        Err(_) => Ok(false),
    }
}

fn publish(shared: &Shared, kind: u8, position: u64, outcome: Ordered, deadline_ms: Option<u64>) {
    shared.ordered.send_replace(Some(OrderedControl {
        kind,
        position,
        outcome,
        deadline_ms,
    }));
}

/// The stage verified history settled. This device's own ordered rotation
/// is accepted from its staged raw body; if that fails, it is accepted as
/// any followed rotation is.
async fn settle(shared: &Shared, trust: &mut Trust, settlement: Settlement) -> Result<bool, Fail> {
    trust.sent = None;
    trust.confirmed = None;
    trust.refused = None;
    trust.order.done();
    let staged = settlement.staged;
    if staged.kind == ROTATE {
        trust.rotate.done();
    }
    let event = local(AccountEvent::decode(&staged.event))?;
    let at = event.head().position;
    let (outcome, deadline) = match settlement.outcome {
        Settled::Accepted { position, bounds } => {
            // The wait a request shows is its own state, which says
            // whether it lapsed.
            let deadline = match event.change() {
                bh_account::AccountChange::RemovalRequested { .. } => {
                    authority(shared.signer.current_account())?
                        .request_state(position, bounds.latest_ms)
                        .ok()
                        .and_then(|state| match state {
                            RequestState::Pending { deadline_ms } => Some(deadline_ms),
                            _ => None,
                        })
                }
                _ => None,
            };
            if staged.kind == ROTATE
                && let Some(raw) = staged.body.clone()
                && shared.signer.accept_rotation(position, raw).await.is_err()
            {
                trust.accept.done();
            }
            let confirmation = TimeBounds {
                earliest_ms: bounds.earliest_ms,
                latest_ms: bounds.latest_ms,
            };
            (Ordered::Accepted { confirmation }, deadline)
        }
        Settled::CancelTookEffect => (Ordered::CancelTookEffect, None),
        Settled::Lost => (Ordered::Lost, None),
    };
    publish(shared, staged.kind, at, outcome, deadline);
    Ok(true)
}

/// Order the staged control while it is the account's next event.
async fn order_staged(
    shared: &Shared,
    link: &mut Link,
    trust: &mut Trust,
    copier: &mut Copier,
    ready: &mut Readiness<'_>,
    staged: &StagedControl,
) -> Result<bool, Fail> {
    let event = local(AccountEvent::decode(&staged.event))?;
    let head = authority(shared.signer.current_account())?.head();
    if event.previous_head() != head {
        // Verified history is behind the stage: only following settles it.
        copier.follow = true;
        return Ok(false);
    }
    if let Some((bytes, reason)) = &trust.refused
        && *bytes == staged.event
    {
        if copier.follow {
            return Ok(false);
        }
        // Followed since the refusal, and history still stands at these
        // bytes' predecessor: they were not ordered and never will be. An
        // owner lent for a moment discards on the next pass.
        if shared.signer.discard_staged(staged).is_err() {
            return Ok(false);
        }
        let outcome = if *reason == Refusal::Lapsed && staged.kind == CANCEL {
            Ordered::CancelTookEffect
        } else {
            Ordered::Refused
        };
        trust.refused = None;
        trust.sent = None;
        trust.order.done();
        if staged.kind == ROTATE {
            // Staged again only after a longer wait: the home may refuse
            // every rotation until something else changes.
            trust.rotate.failed();
        }
        publish(shared, staged.kind, event.head().position, outcome, None);
        // Nothing moved forward: the lane's own backoff keeps growing.
        return Ok(false);
    }
    if trust.confirmed.as_ref() == Some(&staged.event) {
        copier.follow = true;
        return Ok(false);
    }
    // A recovery replacement waits for the person to save its new kit: not
    // an attempt, so it neither withdraws readiness nor grows the backoff.
    if staged.kind == REPLACE_RECOVERY && staged.sealed_kit.is_some() {
        return Ok(false);
    }
    if !trust.order.ready() {
        return Ok(false);
    }
    ready.withdraw();
    match send(shared, link, trust, copier, staged, &event).await {
        Ok(()) => {
            trust.order.done();
            trust.confirmed = Some(staged.event.clone());
            copier.follow = true;
            Ok(true)
        }
        Err(fail) => {
            trust.order.failed();
            Err(fail)
        }
    }
}

/// The body and attachment a staged control travels with.
fn transport(
    staged: &StagedControl,
) -> Result<(Option<BodyObject>, Option<RecoveryAttachment>), Fail> {
    match staged.kind {
        ROTATE => {
            let raw = staged.body.as_ref().ok_or(Fail::Local)?;
            let recovery_seal = staged.attachment.clone().ok_or(Fail::Local)?;
            let body = local(rotation_body(raw))?;
            let commitment = body.commitment();
            Ok((
                Some(body),
                Some(RecoveryAttachment {
                    record: None,
                    recovery_seal,
                    rotation_body: Some(commitment),
                }),
            ))
        }
        // A recovery replacement goes with its record and the personal key's
        // seal to the new recovery key, and no body object; only once the
        // person saved the new kit. Until then it waits here, a local wait
        // that neither shows nor slows receiving.
        REPLACE_RECOVERY if staged.sealed_kit.is_some() => Err(Fail::Local),
        REPLACE_RECOVERY => {
            let record = staged.body.clone().ok_or(Fail::Local)?;
            let recovery_seal = staged.attachment.clone().ok_or(Fail::Local)?;
            Ok((
                None,
                Some(RecoveryAttachment {
                    record: Some(record),
                    recovery_seal,
                    rotation_body: None,
                }),
            ))
        }
        _ if staged.body.is_none()
            && staged.attachment.is_none()
            && staged.sealed_kit.is_none() =>
        {
            Ok((None, None))
        }
        // No other control's attachment is mapped here: it waits.
        _ => Err(Fail::Unsupported),
    }
}

/// Submit the staged bytes, append them and have their order confirmed. A
/// stage whose append may have landed is asked about first. A rotation's
/// body is staged before the rotation names it, so the home can read it
/// back; staging the same bytes again is harmless.
async fn send(
    shared: &Shared,
    link: &mut Link,
    trust: &mut Trust,
    copier: &mut Copier,
    staged: &StagedControl,
    event: &AccountEvent,
) -> Result<(), Fail> {
    let log = account_log(shared)?;
    let (body, attachment) = transport(staged)?;
    let commitment = body.as_ref().map(BodyObject::commitment);
    let wrapped = local(account_log_wrap(&staged.event, commitment))?;
    if trust.sent.as_ref() == Some(&staged.event) {
        match confirm(shared, log, staged, event, wrapped.digest(), commitment).await {
            // Not ordered: send the same bytes again.
            Err(Fail::Retry) => trust.sent = None,
            other => return other,
        }
    }
    if let Some(body) = &body {
        stage_body(shared, link, log, body).await?;
    }
    let answer = {
        let mut session = shared.authz.session(shared).await?;
        session
            .ask(ToService::SubmitControl {
                log,
                event: staged.event.clone(),
                delivery: None,
                attachment: attachment.map(Box::new),
            })
            .await?
    };
    let items = match answer {
        FromService::Permits { items } => items,
        // A definitive answer for these bytes, unless they were ordered
        // already: following decides which. `Unauthenticated` is the
        // session's, not the bytes': it is retried like `Unavailable`.
        FromService::Refused {
            reason: reason @ (Refusal::Invalid | Refusal::Lapsed),
        } => {
            trust.refused = Some((staged.event.clone(), reason));
            copier.follow = true;
            return Err(Fail::Retry);
        }
        other => return Err(Fail::from_answer(&other)),
    };
    let [append] = <[_; 1]>::try_from(items).map_err(|_| Fail::Network)?;
    let append = granted(append)?;
    let data = link.data(shared).await?;
    // From here an answer may be lost after the append lands.
    trust.sent = Some(staged.event.clone());
    let encoded = wrapped.encode();
    let appended = data
        .ask(|id| Request::Append {
            id,
            permit: append,
            event: encoded,
        })
        .await
        .map_err(|_| Fail::Network)?;
    match appended {
        Response::Acked { ack, .. } => {
            let ack = AppendAck::decode(&ack).map_err(|_| Fail::Network)?;
            if ack.log != log
                || ack.event != wrapped.publication_id(Route::Control)
                || ack.head.position != event.head().position
            {
                return Err(Fail::Network);
            }
        }
        // Another entry holds the position: following settles the stage.
        Response::Refused {
            reason: wire::Refusal::Predecessor | wire::Refusal::Conflict,
            ..
        } => {
            trust.sent = None;
            copier.follow = true;
            return Err(Fail::Retry);
        }
        other => return Err(Fail::from_response(&other)),
    }
    confirm(shared, log, staged, event, wrapped.digest(), commitment).await
}

/// Stage `body` on the account log under a permit asked for it alone.
async fn stage_body(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    body: &BodyObject,
) -> Result<(), Fail> {
    let answer = shared
        .authz
        .request(
            shared,
            ToService::Permits {
                items: vec![Want::Stage {
                    log,
                    body: body.commitment(),
                    len: body.bytes().len() as u32,
                }],
            },
        )
        .await?;
    let permit = only(answer)?;
    let bytes = body.bytes().to_vec();
    let data = link.data(shared).await?;
    match data
        .ask(|id| Request::Stage {
            id,
            permit,
            body: bytes,
        })
        .await
        .map_err(|_| Fail::Network)?
    {
        Response::Staged { .. } => Ok(()),
        other => Err(Fail::from_response(&other)),
    }
}

/// Ask whether the staged bytes are ordered, with a fresh challenge. `Retry`
/// for "not ordered"; an answer that does not verify settles nothing.
async fn confirm(
    shared: &Shared,
    log: LogId,
    staged: &StagedControl,
    event: &AccountEvent,
    wrapped: Digest,
    body: Option<Digest>,
) -> Result<(), Fail> {
    let challenge: [u8; 32] = bh_crypto::random();
    let answer = {
        let mut session = shared.authz.session(shared).await?;
        session
            .ask(ToService::ConfirmControl {
                log,
                event: wrapped,
                challenge,
            })
            .await?
    };
    match answer {
        FromService::Confirmed { confirmation, head } => {
            let root = shared.endpoint.hosting_root;
            if confirms(
                root,
                log,
                &challenge,
                staged,
                event,
                body,
                &confirmation,
                &head,
            ) {
                Ok(())
            } else {
                Err(Fail::Network)
            }
        }
        FromService::Refused {
            reason: Refusal::NotOrdered,
        } => Err(Fail::Retry),
        other => Err(Fail::from_answer(&other)),
    }
}

/// Whether `confirmation` and `head` say, under `root`, that exactly the
/// staged original and body are ordered at the staged position of `log`,
/// and the head answers `challenge`.
#[allow(clippy::too_many_arguments)] // One answer's independently pinned inputs.
fn confirms(
    root: [u8; 32],
    log: LogId,
    challenge: &[u8; 32],
    staged: &StagedControl,
    event: &AccountEvent,
    body: Option<Digest>,
    confirmation: &[u8],
    head: &[u8],
) -> bool {
    let Ok(proof) = OrderingConfirmation::decode(confirmation) else {
        return false;
    };
    let Ok(claim) = proof.verify_for(&root, &staged.event, body) else {
        return false;
    };
    let (at, previous) = (event.head(), event.previous_head());
    claim.log == log
        && claim.original_head.position == at.position
        && claim.original_head.hash.0 == at.hash
        && claim.original_previous.position == previous.position
        && claim.original_previous.hash.0 == previous.hash
        && AcceptedHead::verify(head, &root, log, challenge)
            .is_ok_and(|accepted| accepted.original_head.position >= at.position)
}

/// Accept the rotation verified history made current, if this device has
/// not: its raw body read by the commitment its confirmation names, checked
/// against the digest the rotation signs. Paced on failure; only a broken
/// link is the lane's.
async fn accept_followed(
    shared: &Shared,
    link: &mut Link,
    trust: &mut Trust,
) -> Result<bool, Fail> {
    let Ok(current) = shared.signer.current_account() else {
        return Ok(false);
    };
    let Ok(publication) = current.personal_publication() else {
        return Ok(false);
    };
    let digest = *publication.device_digest();
    if trust.accepted == Some(digest) || !trust.accept.ready() {
        return Ok(false);
    }
    match accept(shared, link, &current, digest).await {
        Ok(moved) => {
            trust.accepted = Some(digest);
            trust.accept.done();
            Ok(moved)
        }
        Err(fail) => {
            trust.accept.failed();
            if fail == Fail::Network {
                Err(fail)
            } else {
                Ok(false)
            }
        }
    }
}

async fn accept(
    shared: &Shared,
    link: &mut Link,
    current: &bh_account::VerifiedAccount,
    digest: [u8; 32],
) -> Result<bool, Fail> {
    let database = local(shared.owner.shared_database(shared.container))?;
    let journal = DeviceJournal::from_shared(database.clone());
    // What this device accepted, from its one row and never the keyring,
    // checked against the current publication without reading history
    // where it can be. An accepted rotation supersedes the delivery a
    // joined device began with.
    let (rotated, joined) = {
        let db = database.lock().expect("container writer lock");
        (local(db.personal_delivery())?, local(db.joined())?)
    };
    let from = match (rotated, joined) {
        (Some((position, body)), _) => {
            if device_seals_digest(&body) == digest {
                return Ok(false);
            }
            position
        }
        (None, Some(joined)) => joined.added_at.ok_or(Fail::Local)?,
        (None, None) => {
            let signup = page(&journal, current, SIGNUP_PUBLICATION, 1)?;
            if signup
                .first()
                .map(Vec::as_slice)
                .and_then(published_device_digest)
                == Some(digest)
            {
                return Ok(false);
            }
            SIGNUP_PUBLICATION
        }
    };
    let Some((position, original)) = latest_publication(&journal, current, from, digest)? else {
        // Nothing after what this device accepted publishes another key.
        return Ok(false);
    };
    let confirmation = local(
        database
            .lock()
            .expect("container writer lock")
            .confirmation(position),
    )?
    .ok_or(Fail::Missing)?;
    let commitment = OrderingConfirmation::decode(&confirmation.bytes)
        .map_err(|_| Fail::Local)?
        .claim()
        .body
        .ok_or(Fail::Local)?;
    let padded = read_body(shared, link, account_log(shared)?, commitment).await?;
    let raw = rotation_frame(&padded).map_err(|_| Fail::Missing)?;
    if !signs_rotation_body(&original, raw) {
        return Err(Fail::Missing);
    }
    authority(shared.signer.accept_rotation(position, raw.to_vec()).await)?;
    Ok(true)
}

/// `count` verified originals from `first`.
fn page(
    journal: &DeviceJournal,
    current: &bh_account::VerifiedAccount,
    first: u64,
    count: u64,
) -> Result<Vec<Vec<u8>>, Fail> {
    let page = local(journal.history_prefix(
        Some(HistoryCursor {
            anchor: current.id(),
            cut: current.head(),
            next_position: first,
        }),
        count as usize,
    ))?
    .ok_or(Fail::Local)?;
    if page.first_position != first || page.events.len() as u64 != count {
        return Err(Fail::Local);
    }
    Ok(page.events)
}

/// The latest original after `from` publishing the key `digest` names,
/// read back from the head a page at a time: a rotation is usually recent.
fn latest_publication(
    journal: &DeviceJournal,
    current: &bh_account::VerifiedAccount,
    from: u64,
    digest: [u8; 32],
) -> Result<Option<(u64, Vec<u8>)>, Fail> {
    const PAGE: u64 = 64;
    let mut end = current.head().position;
    while end > from {
        let first = end.saturating_sub(PAGE - 1).max(from + 1);
        let events = page(journal, current, first, end - first + 1)?;
        for (offset, original) in events.into_iter().enumerate().rev() {
            if rotation_body_digest(&original) == Some(digest) {
                return Ok(Some((first + offset as u64, original)));
            }
        }
        end = first - 1;
    }
    Ok(None)
}

/// One account-log body, checked against its commitment before use.
async fn read_body(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    body: Digest,
) -> Result<Vec<u8>, Fail> {
    let answer = shared
        .authz
        .request(
            shared,
            ToService::Permits {
                items: vec![Want::ReadBodies {
                    log,
                    bodies: vec![body],
                }],
            },
        )
        .await?;
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
        Response::Body { .. } | Response::Refused { .. } => Err(Fail::Missing),
        _ => Err(Fail::Network),
    }
}

/// When a removal may have taken effect (an effect verified history
/// established, or a deadline the device clock passed, a hint only), learn
/// the time from a fresh challenged accepted head and stage one rotation for
/// the latest effect due then.
async fn rotate_if_due(
    shared: &Shared,
    link: &mut Link,
    trust: &mut Trust,
    copier: &mut Copier,
    ready: &mut Readiness<'_>,
) -> Result<bool, Fail> {
    let identity = authority(shared.signer.identity())?;
    let Ok(current) = shared.signer.current_account() else {
        return Ok(false);
    };
    if current.active_device(identity.device).is_err() {
        return Ok(false);
    }
    let now = shared.endpoint.device_clock.now_ms();
    let due = current.rotation_due(0).is_some()
        || current
            .pending_removals(0)
            .iter()
            .any(|pending| pending.deadline_ms <= now);
    if !due {
        trust.rotate.done();
        return Ok(false);
    }
    if !trust.rotate.ready() {
        return Ok(false);
    }
    // Paced until a rotation settles.
    trust.rotate.failed();
    let Some(at_ms) = accepted_now(shared, link, &current).await? else {
        copier.follow = true;
        return Ok(false);
    };
    if current.rotation_reason(at_ms).is_none() {
        // The home's time has not reached the deadline the device clock
        // passed: look again no sooner than it could have.
        if let Some(deadline) = current
            .pending_removals(0)
            .iter()
            .map(|pending| pending.deadline_ms)
            .filter(|deadline| *deadline > at_ms)
            .min()
        {
            let wait = std::time::Duration::from_millis(deadline - at_ms);
            trust.rotate.at = trust.rotate.at.max(Some(Instant::now() + wait));
        }
        return Ok(false);
    }
    if !matches!(
        current.device_state(identity.device, at_ms),
        Ok(DeviceState::Active | DeviceState::RemovalPending { .. })
    ) {
        return Ok(false);
    }
    ready.withdraw();
    authority(shared.signer.stage_rotation(at_ms).await)?;
    Ok(true)
}

/// The earliest time of a fresh accepted head the service signed for a new
/// challenge at exactly this device's verified head, with its kept proof.
/// `None` if the log holds more: following comes first. Evidence that does
/// not verify is alerted.
async fn accepted_now(
    shared: &Shared,
    link: &mut Link,
    current: &bh_account::VerifiedAccount,
) -> Result<Option<u64>, Fail> {
    let identity = authority(shared.signer.identity())?;
    let log = account_log(shared)?;
    let root = shared.endpoint.hosting_root;
    let database = local(shared.owner.shared_database(shared.container))?;
    let before = local(
        database
            .lock()
            .expect("container writer lock")
            .account_outer_progress(log.id, root),
    )?
    .order;
    if before.position() != current.head().position {
        return Ok(None);
    }
    let prior = stored_time(&database, before.position())?;
    let last = before.position().checked_add(64).ok_or(Fail::Network)?;
    let page =
        match account_evidence::read_public(shared, link, &identity.genesis, before, prior, last)
            .await
        {
            Ok(page) => page,
            Err(EvidenceFailure::Unavailable(fail)) => return Err(fail),
            Err(EvidenceFailure::Invalid) => {
                local(
                    database
                        .lock()
                        .expect("container writer lock")
                        .record_refused_change(shared.endpoint.device_clock.now_ms()),
                )?;
                shared.signer.alerts_written();
                return Err(Fail::Network);
            }
        };
    if !page.events.is_empty() {
        return Ok(None);
    }
    let journal = DeviceJournal::from_shared(database.clone());
    match_stored_accepted(
        &journal,
        &database,
        current.id(),
        current.head(),
        page.accepted,
        root,
        log,
        before,
    )?;
    Ok(Some(page.accepted.bounds.earliest_ms))
}
