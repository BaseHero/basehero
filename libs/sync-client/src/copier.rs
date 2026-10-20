//! Following the account and copying its changes into the own base.
//!
//! The account owner holds the account's verified history. The client reads
//! the account log after the owner's head, unwraps each original exactly and
//! hands them to the owner, which verifies and commits them. Bytes that are
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
//! account's next event into it. Once the base is caught up, the client
//! prepares that one copy, has the control key sign it within an approved
//! action, and keeps the exact signed bytes before first sending them.
//! Every retry, also after a lost answer or a restart, sends those bytes:
//! nothing is signed again because an answer went missing. Only the
//! verified base log settles a kept copy: its exact bytes ordered there
//! with their effect, or the account change copied by another event first.
//! A refusal alone never does. Other bytes under its id, or the copy
//! ordered without effect, leave it kept, unsent and shown as not accepted.
//! The next copy is prepared only after it settles.
use crate::{
    AccountApplyError, BaseControlRequest, ControlSignError, Shared,
    outbox::{Fail, Link},
    puller::{Receiver, granted, read_account},
    scheduler::Readiness,
};
use bh_account::{
    DevicePublicKeys, VerifiedAccount,
    journal::{AccountJournal, HistoryCursor, StagedAdmission},
    storage::DeviceJournal,
};
use bh_authz_proto::{
    Delivery, FromService, MetadataKey, Refusal, ToService, account_log_id, account_log_wrap,
    delivery_body,
};
use bh_device::OwnerError;
use bh_storage::sync_state::{BaseControl, ControlOutcome};
use bh_sync::{
    BaseId, OpaqueEvent,
    permit::{AppendAck, LogId, LogKind},
    receipt,
    wire::{self, Request, Response},
};
use std::collections::BTreeSet;
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

/// Read the account log after the owner's verified head and apply what it
/// adds through the owner.
async fn follow(shared: &Shared, link: &mut Link) -> Result<(), Fail> {
    let identity = shared.signer.identity().map_err(|_| Fail::Authorization)?;
    let log = LogId {
        kind: LogKind::Account,
        id: local(account_log_id(&identity.genesis))?,
    };
    loop {
        let after = shared
            .signer
            .current_account()
            .map_err(|_| Fail::Authorization)?
            .head();
        let (originals, full) = read_account(shared, link, log, after.position + 1).await?;
        if originals.is_empty() {
            return Ok(());
        }
        shared
            .signer
            .apply_account(after, originals)
            .await
            .map_err(|error| match error {
                // Not the account's history: the log is read again.
                AccountApplyError::Refused => Fail::Network,
                AccountApplyError::Unsupported => Fail::Unsupported,
                AccountApplyError::Stopped => Fail::Stopped,
                AccountApplyError::Unavailable => Fail::Authorization,
            })?;
        if !full {
            return Ok(());
        }
    }
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
    let Some((copied, _)) = progress.account else {
        // The genesis is not applied yet.
        return Ok(false);
    };
    copier.not_accepted = false;
    if let Some(kept) = kept {
        copier.unsettled = true;
        // Only verified history settles it: the first bytes the log ordered
        // under its id, and the base's copy of the account.
        let ordered = local(
            database
                .lock()
                .expect("container writer lock")
                .log_event_digest(LogKind::Base as u8, base, kept.event_id),
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
        if !receiver.caught_up(progress.position) {
            return Ok(false);
        }
        ready.withdraw();
        return submit(shared, link, receiver, log, &kept).await;
    }
    let current = shared
        .signer
        .current_account()
        .map_err(|_| Fail::Authorization)?;
    copier.unsettled = current.head().position > copied;
    // Copy only from a base this device has caught up with, so the copy
    // claims what the base holds now.
    if !copier.unsettled || !receiver.caught_up(progress.position) {
        return Ok(false);
    }
    let position = copied + 1;
    ready.withdraw();
    let journal = DeviceJournal::from_shared(database.clone());
    let page = local(journal.history_prefix(
        Some(HistoryCursor {
            anchor: current.id(),
            cut: current.head(),
            next_position: position,
        }),
        1,
    ))?
    .ok_or(Fail::Local)?;
    let original = page.events.first().ok_or(Fail::Local)?;
    let identity = shared.signer.identity().map_err(|_| Fail::Authorization)?;
    let mut request = None;
    shared
        .signer
        .with_base_keys(BaseId(base), &mut |m, _| {
            request = Some(shared.owner.prepare_account_change_copy(
                shared.container,
                &identity.anchor,
                m,
                original,
            ));
        })
        .map_err(|_| Fail::Authorization)?;
    let request = match request.ok_or(Fail::Authorization)? {
        Ok(request) => request,
        Err(OwnerError::Stopped) => return Ok(false),
        // This device is not in the base's copy of the account, or its
        // authority is not current: another device must copy it.
        Err(OwnerError::CopyRefused | OwnerError::Unbound | OwnerError::AnchorMismatch) => {
            return Err(Fail::Authorization);
        }
        Err(_) => return Err(Fail::Local),
    };
    let signature = match shared
        .signer
        .sign_base_control(BaseControlRequest {
            expected_key: *request.expected_key(),
            message: request.signing_bytes().to_vec(),
            copies: original.clone(),
        })
        .await
    {
        Ok(signature) => signature,
        Err(ControlSignError::ConfirmationNeeded | ControlSignError::Unavailable) => {
            return Err(Fail::Authorization);
        }
    };
    let encoded = request.finish(signature).map_err(|_| Fail::Local)?;
    // Kept before it is first sent. A copy kept already for this successor
    // wins, and is what gets sent.
    let kept = local(
        database
            .lock()
            .expect("container writer lock")
            .stage_base_control(&BaseControl {
                base,
                account_position: position,
                event_id: encoded.descriptor.id().0,
                descriptor: encoded.descriptor.encode(),
                body: encoded.body,
            }),
    )?;
    submit(shared, link, receiver, log, &kept).await
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
fn added_keys(current: &VerifiedAccount, event: &[u8]) -> Result<DevicePublicKeys, Fail> {
    let before: BTreeSet<_> = local(current.active_devices())?.map(|k| k.id()).collect();
    let after = local(current.clone().applied(event))?;
    let mut added = local(after.active_devices())?.filter(|k| !before.contains(&k.id()));
    match (added.next(), added.next()) {
        (Some(keys), None) => Ok(keys.clone()),
        _ => Err(Fail::Local),
    }
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
    let recipient = added_keys(&current, &staged.event)?;
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
            if ack.log != log || ack.event != wrapped.id() || ack.head.position != staged.position {
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

/// Send a kept copy, byte for byte: permits from the service, then stage and
/// append. Its outcome is learned by reading the base log.
async fn submit(
    shared: &Shared,
    link: &mut Link,
    receiver: &mut Receiver,
    log: LogId,
    kept: &BaseControl,
) -> Result<bool, Fail> {
    let mut metadata = None;
    shared
        .signer
        .with_base_keys(BaseId(log.id), &mut |m, _| {
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
    let data = link.data(shared).await?;
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
