//! What one base control copies: the account's entries after the base's
//! copy of the account, each with its kept ordering confirmation, as a run
//! of at most `MAX_RUN`, or a personal-key rotation that takes effect as the
//! base's rekey.
//!
//! A run ends before such a rotation, and at the last change this device's
//! control key made among its entries, if any: the person approved that
//! change here, and the approval covers copying the account's
//! already-authorised history through it, never past it. The control key
//! signs a run only within such an approval (`BaseControlRequest::copies`
//! names its last entry). A confirmation this device does not keep is read
//! again from the account home and verified under the hosting root before
//! it times an entry: an entry is never copied untimed.
//!
//! A rekey needs no approval: its new content key is drawn and sealed to
//! each member inside the device, its seals and the control are signed with
//! the ordinary key, and only the key's id passes through here.
use super::local;
use crate::{
    BaseControlRequest, ControlSignError, Shared,
    outbox::{Fail, Link, usable_until},
    puller::ordered_events,
};
use bh_account::{AccountChange, AccountEvent, DeviceId, VerifiedAccount, journal::HistoryCursor};
use bh_account::{journal::AccountJournal, storage::DeviceJournal};
use bh_authz_proto::{FromService, ToService, account_log_id, account_log_unwrap};
use bh_device::{CopyPlan, OwnerError};
use bh_event::account_run::MAX_RUN;
use bh_storage::sync_state::BaseControl;
use bh_sync::{
    BaseId, Digest, Head,
    evidence::{AcceptedHead, OrderingConfirmation},
    permit::{self, LogId, LogKind, Scope},
    wire::{Request, Response},
};
use tokio::time::Instant;

/// A prepared copy: the signed control, and for a rekey the exact seal set
/// it commits to.
pub(super) type Prepared = (BaseControl, Option<Vec<u8>>);

/// The copy of the account entries from `first` (the base's copy's next)
/// into the base, prepared from its verified state and signed: a run, or
/// the rekey of a rotation that takes effect. None if the base stopped.
pub(super) async fn prepare(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    current: &VerifiedAccount,
    first: u64,
) -> Result<Option<Prepared>, Fail> {
    let identity = shared.signer.identity().map_err(|_| Fail::Authorization)?;
    let entries = missing(shared, link, current, first).await?;
    let mut plan = None;
    shared
        .signer
        .with_metadata_key(BaseId(log.id), &mut |m| {
            plan = Some(shared.owner.plan_account_copy(
                shared.container,
                &identity.anchor,
                m,
                &entries,
            ));
        })
        .map_err(|_| Fail::Authorization)?;
    let plan = match plan.ok_or(Fail::Authorization)? {
        Ok(plan) => plan,
        Err(OwnerError::Stopped) => return Ok(None),
        Err(error) => return Err(refused(error)),
    };
    let copy = match plan {
        CopyPlan::Rekey => rekey(shared, log, &identity.anchor, &entries[0]).await,
        CopyPlan::Run(n) => {
            let n = through_own_change(&entries[..n], identity.device);
            run(shared, log, &identity, &entries[..n]).await
        }
    };
    // A base that stopped meanwhile copies nothing.
    match copy {
        Err(Fail::Stopped) => Ok(None),
        other => other.map(|(control, set)| {
            Some((
                BaseControl {
                    account_position: first,
                    ..control
                },
                set,
            ))
        }),
    }
}

/// What a refused preparation means: the base stopped (`Stopped`, which
/// `prepare` turns into nothing to copy); this device not active in the
/// base's copy, or its authority not current, is another device's copy to
/// make.
fn refused(error: OwnerError) -> Fail {
    match error {
        OwnerError::Stopped => Fail::Stopped,
        OwnerError::CopyRefused | OwnerError::Unbound | OwnerError::AnchorMismatch => {
            Fail::Authorization
        }
        _ => Fail::Local,
    }
}

/// How many of `entries` a run carries: through the last change this
/// device's control key made among them, or all of them if it made none.
fn through_own_change(entries: &[(Vec<u8>, Vec<u8>)], device: DeviceId) -> usize {
    let own = |original: &[u8]| {
        let Ok(event) = AccountEvent::decode(original) else {
            return false;
        };
        match event.change() {
            AccountChange::DeviceAdded { by, .. }
            | AccountChange::RemovalRequested { by, .. }
            | AccountChange::RemovalCancelled { by, .. } => by == Some(device),
            AccountChange::RemovedNow { by, .. } | AccountChange::RecoveryReplaced { by } => {
                by == device
            }
            // Signed with the ordinary key, or by the recovery key: no
            // approval on this device names it.
            AccountChange::DeviceRemovedSelf { .. }
            | AccountChange::PersonalRotated { .. }
            | AccountChange::Setup => false,
        }
    };
    entries
        .iter()
        .rposition(|(original, _)| own(original))
        .map_or(entries.len(), |last| last + 1)
}

/// Up to `MAX_RUN` account entries from `first` of `current`'s verified
/// history, each with its confirmation: the one kept with it, or one read
/// again and verified. Ends before an entry whose confirmation cannot be
/// had now; none at all is that entry's failure.
async fn missing(
    shared: &Shared,
    link: &mut Link,
    current: &VerifiedAccount,
    first: u64,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Fail> {
    let database = local(shared.owner.shared_database(shared.container))?;
    let journal = DeviceJournal::from_shared(database.clone());
    let count = current
        .head()
        .position
        .checked_sub(first)
        .ok_or(Fail::Local)?
        .saturating_add(1)
        .min(MAX_RUN as u64) as usize;
    // The page holds the predecessor too, which a refetched confirmation
    // names.
    let from = first.checked_sub(1).filter(|p| *p > 0).ok_or(Fail::Local)?;
    let page = local(journal.history_prefix(
        Some(HistoryCursor {
            anchor: current.id(),
            cut: current.head(),
            next_position: from,
        }),
        count + 1,
    ))?
    .ok_or(Fail::Local)?;
    if page.events.len() != count + 1 {
        return Err(Fail::Local);
    }
    let mut entries = Vec::with_capacity(count);
    for (index, pair) in page.events.windows(2).enumerate() {
        let (previous, original) = (&pair[0], &pair[1]);
        let position = first + index as u64;
        let kept = local(
            database
                .lock()
                .expect("container writer lock")
                .confirmation(position),
        )?;
        let confirmation = match kept {
            Some(row) => row.bytes,
            None => match refetch(shared, link, position, previous, original).await {
                Ok(confirmation) => confirmation,
                Err(fail) if index == 0 => return Err(fail),
                Err(_) => break,
            },
        };
        entries.push((original.clone(), confirmation));
    }
    Ok(entries)
}

/// The confirmation of the account original at `position`, read again from
/// the account home with a fresh challenge: the answer's head verified
/// under the hosting root for that challenge, the read permit for exactly
/// that position, its ordered wrapper holding exactly `original`, and the
/// confirmation itself, signed under the hosting root, binding `original`,
/// its body, its predecessor `previous` and its ordered position.
async fn refetch(
    shared: &Shared,
    link: &mut Link,
    position: u64,
    previous: &[u8],
    original: &[u8],
) -> Result<Vec<u8>, Fail> {
    let identity = shared.signer.identity().map_err(|_| Fail::Authorization)?;
    let log = LogId {
        kind: LogKind::Account,
        id: local(account_log_id(&identity.genesis))?,
    };
    let root = shared.endpoint.hosting_root;
    let challenge: [u8; 32] = bh_crypto::random();
    let requested_at = Instant::now();
    let answer = shared
        .authz
        .request(
            shared,
            ToService::ReadAccountEvidence {
                genesis: identity.genesis.clone(),
                first: position,
                last: position,
                challenge,
            },
        )
        .await?;
    let FromService::AccountEvidence {
        events_permit,
        confirmations,
        head,
    } = answer
    else {
        return Err(Fail::from_answer(&answer));
    };
    let accepted =
        AcceptedHead::verify(&head, &root, log, &challenge).map_err(|_| Fail::Network)?;
    let issued = permit::issued_ms(&events_permit).map_err(|_| Fail::Network)?;
    let granted = permit::verify(root, &events_permit, issued).map_err(|_| Fail::Network)?;
    if granted.scope
        != (Scope::ReadEvents {
            log,
            first: position,
            last: position,
        })
        || accepted.original_head.position < position
    {
        return Err(Fail::Network);
    }
    usable_until(root, &events_permit, requested_at).ok_or(Fail::Network)?;
    let response = link
        .data(shared)
        .await?
        .ask(|id| Request::Read {
            id,
            permit: events_permit,
        })
        .await
        .map_err(|_| Fail::Network)?;
    let Response::Events { items, .. } = response else {
        return Err(Fail::from_response(&response));
    };
    let [(ordered, wrapper)] =
        <[_; 1]>::try_from(ordered_events(BaseId(log.id), position, &items)?)
            .map_err(|_| Fail::Missing)?;
    let (unwrapped, body) = account_log_unwrap(&wrapper).map_err(|_| Fail::Network)?;
    if unwrapped != original {
        return Err(Fail::Network);
    }
    let head = |position: u64, original: &[u8]| Head {
        position,
        hash: Digest(bh_crypto::hash(original)),
    };
    for bytes in confirmations {
        let Ok(proof) = OrderingConfirmation::decode(&bytes) else {
            return Err(Fail::Network);
        };
        if proof.claim().original_head.position != position {
            continue;
        }
        let claim = proof
            .verify_for(&root, original, body)
            .map_err(|_| Fail::Network)?;
        if claim.log != log
            || claim.original_head != head(position, original)
            || claim.original_previous != head(position - 1, previous)
            || claim.ordered != ordered.head()
        {
            return Err(Fail::Network);
        }
        return Ok(bytes);
    }
    Err(Fail::Missing)
}

/// `run` copied into the base by this device's control key, within the
/// approval of its last entry.
async fn run(
    shared: &Shared,
    log: LogId,
    identity: &crate::Identity,
    run: &[(Vec<u8>, Vec<u8>)],
) -> Result<Prepared, Fail> {
    let last = run.last().ok_or(Fail::Local)?.0.clone();
    let mut request = None;
    shared
        .signer
        .with_metadata_key(BaseId(log.id), &mut |m| {
            request = Some(shared.owner.prepare_account_run_copy(
                shared.container,
                &identity.anchor,
                m,
                run,
                bh_event::Copier::Device(identity.device),
            ));
        })
        .map_err(|_| Fail::Authorization)?;
    let request = match request.ok_or(Fail::Authorization)? {
        Ok(request) => request,
        Err(error) => return Err(refused(error)),
    };
    let signature = match shared
        .signer
        .sign_base_control(BaseControlRequest {
            expected_key: *request.expected_key(),
            message: request.signing_bytes().to_vec(),
            copies: last,
        })
        .await
    {
        Ok(signature) => signature,
        Err(ControlSignError::ConfirmationNeeded | ControlSignError::Unavailable) => {
            return Err(Fail::Authorization);
        }
    };
    let encoded = request.finish(signature).map_err(|_| Fail::Local)?;
    Ok((control(log, encoded), None))
}

/// The rekey of `rotation` (with its confirmation): its new key's seals and
/// the control signed with this device's ordinary key, with no prompt.
async fn rekey(
    shared: &Shared,
    log: LogId,
    anchor: &VerifiedAccount,
    (rotation, confirmation): &(Vec<u8>, Vec<u8>),
) -> Result<Prepared, Fail> {
    let mut sealed = None;
    shared
        .signer
        .with_metadata_key(BaseId(log.id), &mut |m| {
            sealed = Some(shared.owner.prepare_rekey_seals(
                shared.container,
                anchor,
                m,
                rotation,
                confirmation,
            ));
        })
        .map_err(|_| Fail::Authorization)?;
    let sealed = match sealed.ok_or(Fail::Authorization)? {
        Ok(sealed) => sealed,
        Err(error) => return Err(refused(error)),
    };
    let mut seals = Vec::with_capacity(sealed.seals.len());
    for seal in sealed.seals {
        let signature = shared
            .signer
            .sign_event(seal.signing_bytes().to_vec())
            .await
            .map_err(|_| Fail::Authorization)?;
        seals.push(seal.finish(signature).map_err(|_| Fail::Local)?);
    }
    let mut prepared = None;
    shared
        .signer
        .with_metadata_key(BaseId(log.id), &mut |m| {
            prepared = Some(shared.owner.prepare_rekey_for(
                shared.container,
                anchor,
                m,
                rotation,
                confirmation,
                sealed.key_id,
                std::mem::take(&mut seals),
            ));
        })
        .map_err(|_| Fail::Authorization)?;
    let prepared = match prepared.ok_or(Fail::Authorization)? {
        Ok(prepared) => prepared,
        Err(error) => return Err(refused(error)),
    };
    let signature = shared
        .signer
        .sign_event(prepared.control.signing_bytes().to_vec())
        .await
        .map_err(|_| Fail::Authorization)?;
    let encoded = prepared
        .control
        .finish(signature)
        .map_err(|_| Fail::Local)?;
    Ok((
        control(log, encoded),
        Some(prepared.seal_set.bytes().to_vec()),
    ))
}

fn control(log: LogId, encoded: bh_event::Encoded) -> BaseControl {
    BaseControl {
        base: log.id,
        account_position: 0,
        event_id: encoded.descriptor.publication_id(bh_sync::Route::Control).0,
        descriptor: encoded.descriptor.encode(),
        body: encoded.body,
    }
}
