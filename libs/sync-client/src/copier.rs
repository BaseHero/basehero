//! Following the account and copying its changes into the own base.
//!
//! The account owner holds the account's verified history. The client reads
//! the account log after its separate durable outer checkpoint, unwraps each original exactly and
//! hands them, each with the home's ordering confirmation verified under the
//! hosting root, to the owner, which verifies and commits them. Bytes that are
//! not the next verified history are refused and read again later; an event
//! this build cannot read pauses; only authenticated history contradicting
//! the owner's stops it, and then this client.
//!
//! A device addition the person approved on this device is staged exactly
//! before anything is sent; the client orders those bytes, with their
//! delivery, while the addition is still the account's next event once the
//! account is followed. A lost answer or a refusal never stops that
//! following, which alone settles the addition.
//!
//! A base learns of an account change only from a control that copies the
//! account's next events, each with its kept confirmation, into it: a run
//! of at most 64 the control key signs within an approved action, or, for a
//! personal-key rotation that takes effect, the base's rekey, which the
//! ordinary key signs with no prompt (`runs`). Once the base's current
//! state is verified (content caught up, or, while content waits for a key
//! or a body, the control feed's scan of the pass), the client prepares
//! that copy with M alone and keeps the exact signed bytes, with a rekey's
//! seal set, before first sending them. Every retry, also after a lost
//! answer or a restart, sends those bytes: nothing is signed again because
//! an answer went missing. Only a kept copy whose seen claim fell further
//! behind the log than the services take (`SEEN_WINDOW`), which could never
//! be ordered, is replaced by a copy from the same entry prepared and
//! signed afresh from the base's current state; a rekey's with a new key
//! and seal set. Only the verified base log settles a kept copy: its exact
//! bytes ordered there with their effect, or its first entry copied by
//! another event first, whose rekey's key is then never used.
//! A refusal alone never does. Other bytes under its id, or the copy
//! ordered without effect, leave it kept, unsent and shown as not accepted.
//! The next copy is prepared only after it settles.
mod runs;

use crate::{
    AccountApplyError, Shared,
    account_evidence::{self, VerifiedEvent},
    outbox::{Fail, Link},
    puller::{Held, Receiver, granted, read_account},
    scheduler::Readiness,
};
use bh_account::{
    AccountId, ConfirmedTime, DevicePublicKeys, Head as AccountHead, VerifiedAccount,
    journal::{AccountJournal, HistoryCursor, StagedAdmission},
    storage::DeviceJournal,
};
use bh_authz_proto::{
    Delivery, FromService, MetadataKey, Refusal, ToService, Want, account_log_id, account_log_wrap,
    delivery_body,
};
use bh_storage::{
    DeviceDatabase,
    sync_state::{BaseControl, ControlOutcome},
};
use bh_sync::{
    BaseId, BodyObject, OpaqueEvent, OrderState,
    evidence::{AcceptedHead, OrderingConfirmation, TimeBounds},
    permit::{AppendAck, LogId, LogKind},
    receipt,
    wire::{self, Request, Response},
};
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;

/// How often the account log is read without a notice or a refusal.
const ACCOUNT_POLL: Duration = Duration::from_secs(300);

fn local<T, E>(result: Result<T, E>) -> Result<T, Fail> {
    result.map_err(|_| Fail::Local)
}

/// What copying keeps between rounds.
#[derive(Default)]
pub(crate) struct Copier {
    followed: Option<Instant>,
    /// Read the account log at the next step.
    pub(crate) follow: bool,
    /// A change the base lacks, or a kept copy not yet settled.
    pub(crate) unsettled: bool,
    /// The base log holds other bytes under the kept copy's id, or the copy
    /// without its effect.
    pub(crate) not_accepted: bool,
    /// The account owner stopped on contradicting history: this client
    /// stays stopped.
    pub(crate) stopped: bool,
}

/// Compare only the already committed bounded inner prefix. The journal
/// checks the pinned cut and returns exact stored originals, not just hashes.
pub(crate) fn matched_prefix(
    journal: &DeviceJournal,
    account: AccountId,
    inner: AccountHead,
    before: u64,
    originals: &[&[u8]],
) -> Result<usize, Fail> {
    let matched = originals
        .len()
        .min(inner.position.saturating_sub(before) as usize);
    if matched > 0 {
        let page = local(journal.history_prefix(
            Some(HistoryCursor {
                anchor: account,
                cut: inner,
                next_position: before + 1,
            }),
            matched,
        ))?
        .ok_or(Fail::Local)?;
        if page.events.len() != matched
            || page
                .events
                .iter()
                .zip(originals)
                .any(|(stored, ordered)| stored != ordered)
        {
            // The home confirmed other bytes where this device committed
            // history. Only the account owner judges a contradiction and
            // latches a stop, and it never sees these: the committed prefix
            // stays, the checkpoint does not move, and the log is read again.
            return Err(Fail::Network);
        }
    }
    Ok(matched)
}

/// The exact evidence the reader verified for one original, as the account
/// owner keeps it.
fn evidence(event: &VerifiedEvent) -> Option<(ConfirmedTime, Vec<u8>)> {
    Some((
        event.time.map(|time| ConfirmedTime {
            earliest_ms: time.earliest_ms,
            latest_ms: time.latest_ms,
        })?,
        event.proof.as_ref()?.encode().to_vec(),
    ))
}

/// The stored verified time of the account entry at `position`, if any.
pub(crate) fn stored_time(
    database: &Mutex<DeviceDatabase>,
    position: u64,
) -> Result<Option<TimeBounds>, Fail> {
    if position < 2 {
        return Ok(None);
    }
    Ok(local(
        database
            .lock()
            .expect("container writer lock")
            .confirmation(position),
    )?
    .map(|row| TimeBounds {
        earliest_ms: row.earliest_ms,
        latest_ms: row.latest_ms,
    }))
}

fn accepted_head(accepted: AcceptedHead) -> AccountHead {
    AccountHead {
        position: accepted.original_head.position,
        hash: accepted.original_head.hash.0,
    }
}

/// Match an empty read's challenged head to the exact durable original and
/// stored confirmation, never to the mere absence of new entries.
#[allow(clippy::too_many_arguments)] // One exact head's independently pinned history, root and opening.
pub(crate) fn match_stored_accepted(
    journal: &DeviceJournal,
    database: &Mutex<DeviceDatabase>,
    account: AccountId,
    head: AccountHead,
    accepted: AcceptedHead,
    root: [u8; 32],
    log: LogId,
    opening: OrderState,
) -> Result<(), Fail> {
    if accepted_head(accepted) != head {
        return Err(Fail::Network);
    }
    let page = local(journal.history_prefix(
        Some(HistoryCursor {
            anchor: account,
            cut: head,
            next_position: head.position,
        }),
        1,
    ))?
    .ok_or(Fail::Local)?;
    let original = page.events.first().ok_or(Fail::Local)?;
    if bh_crypto::hash(original) != head.hash {
        return Err(Fail::Network);
    }
    let proof = if head.position == 1 {
        [0; 32]
    } else {
        let row = local(
            database
                .lock()
                .expect("container writer lock")
                .confirmation(head.position),
        )?
        .ok_or(Fail::Missing)?;
        let proof = OrderingConfirmation::decode(&row.bytes).map_err(|_| Fail::Network)?;
        let claim = proof
            .verify_for(&root, original, proof.claim().body)
            .map_err(|_| Fail::Network)?;
        if claim.log != log
            || claim.original_head != accepted.original_head
            || claim.ordered != opening.head(BaseId(log.id))
            || accepted.bounds.earliest_ms < claim.bounds.earliest_ms
            || accepted.bounds.latest_ms < claim.bounds.latest_ms
        {
            return Err(Fail::Network);
        }
        proof.commitment()
    };
    if accepted.evidence != proof {
        return Err(Fail::Network);
    }
    Ok(())
}

fn observe(shared: &Shared, accepted: AcceptedHead) -> Result<(), Fail> {
    shared
        .signer
        .observe_account_accepted(
            accepted_head(accepted),
            ConfirmedTime {
                earliest_ms: accepted.bounds.earliest_ms,
                latest_ms: accepted.bounds.latest_ms,
            },
        )
        .map_err(|_| Fail::Authorization)
}

/// Follow the independently verified outer log. Signup, pairing, or an
/// interrupted prior follow may already have committed an inner prefix:
/// compare its exact journal bytes rather than applying its effects again.
/// Every original after the genesis carries its verified confirmation to
/// the account owner; a missing one leaves everything as it was.
async fn follow(shared: &Shared, link: &mut Link) -> Result<(), Fail> {
    let identity = shared.signer.identity().map_err(|_| Fail::Authorization)?;
    let log = LogId {
        kind: LogKind::Account,
        id: local(account_log_id(&identity.genesis))?,
    };
    let database = local(shared.owner.shared_database(shared.container))?;
    let journal = DeviceJournal::from_shared(database.clone());
    // A challenged head may be beyond a full page. Keep every unresolved
    // authenticated claim until its exact original and proof are checked.
    let mut pending: Vec<AcceptedHead> = Vec::new();
    loop {
        let before = local(
            database
                .lock()
                .expect("container writer lock")
                .account_outer_progress(log.id, shared.endpoint.hosting_root),
        )?
        .order;
        let prior = stored_time(&database, before.position())?;
        let (events, accepted, full, ahead) =
            read_account(shared, link, log, before, prior).await?;
        let reached = account_evidence::match_page_claims(&mut pending, &events, accepted)?;
        let inner = shared
            .signer
            .current_account()
            .map_err(|_| Fail::Authorization)?;
        if inner.id() != identity.account || before.position() > inner.head().position {
            return Err(Fail::Local);
        }
        if events.is_empty() {
            if ahead
                || inner.head().position != before.position()
                || pending
                    .iter()
                    .any(|claim| claim.original_head.position != before.position())
            {
                return Err(Fail::Missing);
            }
            for claim in pending.drain(..) {
                match_stored_accepted(
                    &journal,
                    &database,
                    identity.account,
                    inner.head(),
                    claim,
                    shared.endpoint.hosting_root,
                    log,
                    before,
                )?;
                observe(shared, claim)?;
            }
            return Ok(());
        }
        let originals: Vec<&[u8]> = events.iter().map(|e| e.original.as_slice()).collect();
        let matched = matched_prefix(
            &journal,
            identity.account,
            inner.head(),
            before.position(),
            &originals,
        )?;
        let mut current = inner.head();
        let mut next = matched;
        // Each reached head is an observation point in account-head order.
        // Check overlap against the exact kept proof, and observe a committed
        // challenged head before advancing through any uncommitted suffix.
        for (index, claim) in reached {
            let at = &events[index];
            if index < matched {
                match_stored_accepted(
                    &journal,
                    &database,
                    identity.account,
                    accepted_head(claim),
                    claim,
                    shared.endpoint.hosting_root,
                    log,
                    at.opening,
                )?;
            } else if index >= next {
                current = apply_verified(shared, current, &events[next..=index]).await?;
                next = index + 1;
            }
            if current == accepted_head(claim) {
                observe(shared, claim)?;
            }
        }
        if next < events.len() {
            apply_verified(shared, current, &events[next..]).await?;
        }
        let last = events.last().expect("nonempty account page").opening;
        local(
            database
                .lock()
                .expect("container writer lock")
                .advance_account_outer(log.id, shared.endpoint.hosting_root, before, last),
        )?;
        if !full {
            return if ahead || !pending.is_empty() {
                Err(Fail::Missing)
            } else {
                Ok(())
            };
        }
    }
}

async fn apply_verified(
    shared: &Shared,
    current: AccountHead,
    events: &[VerifiedEvent],
) -> Result<AccountHead, Fail> {
    let suffix = events
        .iter()
        .map(|event| (event.original.clone(), evidence(event)))
        .collect();
    let after = shared
        .signer
        .apply_account_timed(current, suffix)
        .await
        .map_err(|error| match error {
            AccountApplyError::Refused => Fail::Network,
            AccountApplyError::Unsupported => Fail::Unsupported,
            AccountApplyError::Stopped => Fail::Stopped,
            AccountApplyError::Unavailable => Fail::Authorization,
        })?;
    shared.removal_wake.notify_one();
    Ok(after)
}

/// One step: follow the account if it is due or an addition is kept, order
/// that addition if it is still next, then settle the kept copy, send it
/// again, or prepare the next one. Returns whether anything moved.
/// Publication is withdrawn before any control is signed or ordered; the
/// receiver grants it again once this step ends.
pub(crate) async fn step(
    shared: &Shared,
    link: &mut Link,
    copier: &mut Copier,
    receiver: &mut Receiver,
    log: LogId,
    ready: &mut Readiness<'_>,
) -> Result<bool, Fail> {
    let account_at = shared
        .signer
        .current_account()
        .map_err(|_| Fail::Authorization)?
        .head();
    // A kept addition may be ordered already, its answer lost, or another
    // event may hold its position: only following the account settles
    // either, so it is followed first, whatever its submission did.
    if next_addition(shared)?.is_some() {
        copier.follow = true;
    }
    if copier.follow
        || receiver.account_hint > account_at.position
        || copier
            .followed
            .is_none_or(|at| at.elapsed() >= ACCOUNT_POLL)
    {
        if let Err(fail) = follow(shared, link).await {
            copier.stopped = fail == Fail::Stopped;
            return Err(fail);
        }
        copier.follow = false;
        copier.followed = Some(Instant::now());
    }
    // An addition the person approved is ordered, byte for byte, while it
    // is still the account's next event after following; verified history
    // settles it.
    if let Some(staged) = next_addition(shared)? {
        copier.follow = true;
        ready.withdraw();
        order_addition(shared, link, &staged).await?;
        return Ok(true);
    }
    let database = local(shared.owner.shared_database(shared.container))?;
    let base = log.id;
    let (progress, kept) = {
        let db = database.lock().expect("container writer lock");
        let progress = local(db.log_progress(LogKind::Base as u8, base))?.ok_or(Fail::Local)?;
        (progress, local(db.pending_base_control(base))?)
    };
    if progress.stopped.is_some() {
        return Ok(false);
    }
    // The base's verified copy of the account: the control feed's while it
    // is ahead of content, so that copying needs M alone and goes on while
    // content waits for a key.
    let Some(verified) = local(shared.owner.verified_copy(shared.container, log))? else {
        // The genesis is not applied yet.
        return Ok(false);
    };
    let copied = verified.account.0;
    // Copy only from a base whose current state this device verified, so
    // the copy claims what the base holds now: content caught up, or, while
    // content waits, the control feed's scan of this pass, which reached
    // the control head the service verified.
    let current_base = receiver.caught_up(progress.position)
        || (receiver.held != Held::No && receiver.controls_current);
    copier.not_accepted = false;
    if let Some(kept) = kept {
        copier.unsettled = true;
        // Only verified history settles it: the first bytes the log ordered
        // under its id, and the base's copy of the account.
        let ordered = local(
            shared
                .owner
                .ordered_control(shared.container, log, kept.event_id),
        )?;
        let digest = local(OpaqueEvent::decode(&kept.descriptor))?.digest().0;
        let outcome = match ordered {
            Some(ordered) if ordered == digest && copied >= kept.account_position => {
                Some(ControlOutcome::Committed)
            }
            None if copied >= kept.account_position => Some(ControlOutcome::Superseded),
            // Other bytes under its id, or the copy without its effect:
            // sending it again cannot change that, and it is never resealed.
            Some(_) => {
                copier.not_accepted = true;
                return Ok(false);
            }
            None => None,
        };
        if let Some(outcome) = outcome {
            local(
                database
                    .lock()
                    .expect("container writer lock")
                    .settle_base_control(base, kept.account_position, kept.event_id, outcome),
            )?;
            return Ok(true);
        }
        if !current_base {
            return Ok(false);
        }
        ready.withdraw();
        // A copy orders after every head known now. One whose seen claim is
        // further behind that than the services take could never be
        // ordered: its bytes are never sent again. The same change is
        // prepared and signed afresh from the base's current state.
        let kept = if behind(window(shared), seen(shared, log, &kept)?, receiver.latest) {
            if behind(window(shared), verified.through, receiver.latest) {
                return Ok(false);
            }
            let current = shared
                .signer
                .current_account()
                .map_err(|_| Fail::Authorization)?;
            let Some((fresh, set)) =
                runs::prepare(shared, link, log, &current, kept.account_position).await?
            else {
                return Ok(false);
            };
            local(
                database
                    .lock()
                    .expect("container writer lock")
                    .replace_base_control(&kept, &fresh, set.as_deref()),
            )?
        } else {
            kept
        };
        return submit(shared, link, receiver, log, &kept).await;
    }
    let current = shared
        .signer
        .current_account()
        .map_err(|_| Fail::Authorization)?;
    copier.unsettled = current.head().position > copied;
    // Never prepare a copy whose seen claim would already be too old.
    if !copier.unsettled
        || !current_base
        || behind(window(shared), verified.through, receiver.latest)
    {
        return Ok(false);
    }
    ready.withdraw();
    let Some((copy, set)) = runs::prepare(shared, link, log, &current, copied + 1).await? else {
        return Ok(false);
    };
    // Kept, with a rekey's seal set, before it is first sent. A copy kept
    // already for this successor wins, and is what gets sent.
    let kept = {
        let mut db = database.lock().expect("container writer lock");
        local(match &set {
            Some(set) => db.stage_base_rekey(&copy, set),
            None => db.stage_base_control(&copy),
        })?
    };
    submit(shared, link, receiver, log, &kept).await
}

/// How far behind its own position the services take an event's seen
/// claim, controls included: a rule they will enforce.
pub(crate) const SEEN_WINDOW: u64 = 8192;

fn window(shared: &Shared) -> u64 {
    shared.tuning.seen_window.unwrap_or(SEEN_WINDOW)
}

/// Whether a seen claim at `seen` is further behind than `window` the
/// position a control would order at now: after the `latest` head known.
fn behind(window: u64, seen: u64, latest: u64) -> bool {
    latest.saturating_add(1).saturating_sub(seen) > window
}

/// The base position `kept`'s seen claim names, read back with M.
fn seen(shared: &Shared, log: LogId, kept: &BaseControl) -> Result<u64, Fail> {
    let descriptor = local(OpaqueEvent::decode(&kept.descriptor))?;
    let mut seen = None;
    shared
        .signer
        .with_metadata_key(BaseId(log.id), &mut |m| {
            seen = Some(bh_event::sealed_seen(&descriptor, m, BaseId(log.id)))
        })
        .map_err(|_| Fail::Authorization)?;
    Ok(local(seen.ok_or(Fail::Authorization)?)?.position)
}

/// The staged addition, while it is the account's next event.
fn next_addition(shared: &Shared) -> Result<Option<StagedAdmission>, Fail> {
    let head = shared
        .signer
        .current_account()
        .map_err(|_| Fail::Authorization)?
        .head();
    Ok(shared
        .signer
        .staged_addition()
        .map_err(|_| Fail::Authorization)?
        .filter(|staged| staged.position == head.position + 1 && staged.previous == head.hash))
}

/// The keys of the one device `event` adds to `current`, its predecessor.
fn added_keys(
    current: &VerifiedAccount,
    device: bh_account::DeviceId,
    event: &[u8],
) -> Result<DevicePublicKeys, Fail> {
    let decoded = local(bh_account::AccountEvent::decode(event))?;
    let keys = decoded.added_device_keys().ok_or(Fail::Local)?.clone();
    let request = local(current.add_device(device, keys.clone()))?;
    let message = request.signing_bytes();
    if event.len() != message.len() + 64 || !event.starts_with(message) {
        return Err(Fail::Local);
    }
    local(request.finish(local(event[message.len()..].try_into())?))?;
    Ok(keys)
}

/// Order a staged device addition on the account log: the exact signed
/// event, carrying the exact signed delivery as its body. The service checks
/// both against the account's current history before it permits them; a
/// lost answer or a moved log is settled by following the account.
pub(crate) async fn order_addition(
    shared: &Shared,
    link: &mut Link,
    staged: &StagedAdmission,
) -> Result<(), Fail> {
    let identity = shared.signer.identity().map_err(|_| Fail::Authorization)?;
    let log = LogId {
        kind: LogKind::Account,
        id: local(account_log_id(&identity.genesis))?,
    };
    let current = shared
        .signer
        .current_account()
        .map_err(|_| Fail::Authorization)?;
    let recipient = added_keys(&current, identity.device, &staged.event)?;
    let body = local(delivery_body(&staged.delivery))?;
    let wrapped = local(account_log_wrap(&staged.event, Some(body.commitment())))?;
    let answer = {
        let mut session = shared.authz.session(shared).await?;
        session
            .ask(ToService::SubmitControl {
                log,
                event: staged.event.clone(),
                delivery: Some(Box::new(Delivery {
                    recipient,
                    frame: staged.delivery.clone(),
                })),
                attachment: None,
            })
            .await?
    };
    let items = match answer {
        FromService::Permits { items } => items,
        // Not the next event any more: following the account decides.
        FromService::Refused {
            reason: Refusal::Invalid,
        } => return Err(Fail::Retry),
        other => return Err(Fail::from_answer(&other)),
    };
    let [stage, append] = <[_; 2]>::try_from(items).map_err(|_| Fail::Network)?;
    let (stage, append) = (granted(stage)?, granted(append)?);
    let data = link.data(shared).await?;
    let bytes = body.bytes().to_vec();
    let staged_body = data
        .ask(|id| Request::Stage {
            id,
            permit: stage,
            body: bytes,
        })
        .await
        .map_err(|_| Fail::Network)?;
    if !matches!(staged_body, Response::Staged { .. }) {
        return Err(Fail::from_response(&staged_body));
    }
    let event = wrapped.encode();
    let appended = data
        .ask(|id| Request::Append {
            id,
            permit: append,
            event,
        })
        .await
        .map_err(|_| Fail::Network)?;
    match appended {
        Response::Acked { ack, .. } => {
            let ack = AppendAck::decode(&ack).map_err(|_| Fail::Network)?;
            if ack.log != log
                || ack.event != wrapped.publication_id(bh_sync::Route::Control)
                || ack.head.position != staged.position
            {
                return Err(Fail::Network);
            }
            Ok(())
        }
        Response::Refused {
            reason: wire::Refusal::Predecessor | wire::Refusal::Conflict,
            ..
        } => Err(Fail::Retry),
        other => Err(Fail::from_response(&other)),
    }
}

/// Send a kept copy, byte for byte: permits from the service, then stage a
/// rekey's kept seal set, stage the body and append. Its outcome is learned
/// by reading the base log.
async fn submit(
    shared: &Shared,
    link: &mut Link,
    receiver: &mut Receiver,
    log: LogId,
    kept: &BaseControl,
) -> Result<bool, Fail> {
    let database = local(shared.owner.shared_database(shared.container))?;
    let seal_set = local(
        database
            .lock()
            .expect("container writer lock")
            .kept_seal_set(kept.event_id),
    )?;
    let mut metadata = None;
    shared
        .signer
        .with_metadata_key(BaseId(log.id), &mut |m| {
            metadata = Some(MetadataKey::new(m))
        })
        .map_err(|_| Fail::Authorization)?;
    let answer = {
        let mut session = shared.authz.session(shared).await?;
        session
            .ask(ToService::SubmitBaseControl {
                log,
                descriptor: kept.descriptor.clone(),
                body: kept.body.clone(),
                metadata: metadata.ok_or(Fail::Authorization)?,
            })
            .await?
    };
    let items = match answer {
        FromService::Permits { items } => items,
        // Invalid once the service has confirmed this very copy, or when it
        // cannot be ordered: the verified log decides which.
        FromService::Refused {
            reason: Refusal::Invalid | Refusal::Conflict,
        } => {
            receiver.recheck();
            return Err(Fail::Retry);
        }
        other => return Err(Fail::from_answer(&other)),
    };
    let [stage, append] = <[_; 2]>::try_from(items).map_err(|_| Fail::Network)?;
    let (stage, append) = (granted(stage)?, granted(append)?);
    // A rekey's seal set is staged first: the append names it.
    let set_stage = match &seal_set {
        Some(set) => {
            let object = BodyObject::new(set.clone()).map_err(|_| Fail::Local)?;
            let answer = shared
                .authz
                .request(
                    shared,
                    ToService::Permits {
                        items: vec![Want::Stage {
                            log,
                            body: object.commitment(),
                            len: set.len() as u32,
                        }],
                    },
                )
                .await?;
            Some((crate::puller::only(answer)?, set.clone()))
        }
        None => None,
    };
    let data = link.data(shared).await?;
    if let Some((permit, body)) = set_stage {
        let staged = data
            .ask(|id| Request::Stage { id, permit, body })
            .await
            .map_err(|_| Fail::Network)?;
        if !matches!(staged, Response::Staged { .. }) {
            return Err(Fail::from_response(&staged));
        }
    }
    let body = kept.body.clone();
    let staged = data
        .ask(|id| Request::Stage {
            id,
            permit: stage,
            body,
        })
        .await
        .map_err(|_| Fail::Network)?;
    if !matches!(staged, Response::Staged { .. }) {
        return Err(Fail::from_response(&staged));
    }
    let event = kept.descriptor.clone();
    let appended = data
        .ask(|id| Request::Append {
            id,
            permit: append,
            event,
        })
        .await
        .map_err(|_| Fail::Network)?;
    match appended {
        Response::Acked { ack, .. } => {
            let ack = AppendAck::decode(&ack).map_err(|_| Fail::Network)?;
            let proven = ack.receipt.is_some_and(|r| {
                receipt::verify(&shared.endpoint.hosting_root, BaseId(log.id), &r)
                    .is_ok_and(|r| r.head() == ack.head)
            });
            if ack.log != log || ack.event.0 != kept.event_id || !proven {
                return Err(Fail::Network);
            }
            // Settled once the receiver has verified and applied it.
            receiver.exists(ack.head.position);
            Ok(true)
        }
        // The control head moved: the log decides what became of the copy.
        Response::Refused {
            reason: wire::Refusal::Predecessor | wire::Refusal::Conflict,
            ..
        } => {
            receiver.recheck();
            Err(Fail::Retry)
        }
        other => Err(Fail::from_response(&other)),
    }
}

#[cfg(test)]
mod window_tests {
    use super::*;

    #[test]
    fn a_seen_claim_is_behind_only_past_the_window_at_the_next_position() {
        // Ordered next at 8193, a claim at 1 is exactly 8192 behind.
        assert!(!behind(SEEN_WINDOW, 1, 8192));
        assert!(behind(SEEN_WINDOW, 1, 8193));
        assert!(!behind(SEEN_WINDOW, 8193, 8193));
        assert!(!behind(3, 5, 7));
        assert!(behind(3, 4, 7));
        assert!(!behind(SEEN_WINDOW, u64::MAX, u64::MAX));
    }
}

#[cfg(test)]
mod overlap_tests {
    use super::*;
    use bh_crypto::hash;
    use bh_storage::DeviceDatabase;
    use std::sync::{Arc, Mutex};

    #[test]
    fn a_different_already_stored_original_cannot_advance_the_outer_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Mutex::new(
            DeviceDatabase::open(dir.path().join("device.sqlite")).unwrap(),
        ));
        let account = AccountId([9; 32]);
        let inner = AccountHead {
            position: 2,
            hash: hash(b"kept"),
        };
        db.lock()
            .unwrap()
            .commit_account_verified(account.0, &[b"genesis", b"kept"], 2, inner.hash, false)
            .unwrap();
        let journal = DeviceJournal::from_shared(db);
        let originals: [&[u8]; 2] = [b"genesis", b"different"];
        assert!(matches!(
            matched_prefix(&journal, account, inner, 0, &originals),
            Err(Fail::Network)
        ));
        let originals: [&[u8]; 2] = [b"genesis", b"kept"];
        assert_eq!(
            matched_prefix(&journal, account, inner, 0, &originals).unwrap(),
            2
        );
    }
}
