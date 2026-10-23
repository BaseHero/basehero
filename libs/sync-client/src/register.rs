//! Registering the container's own base: the service verifies its genesis
//! with M (sent inside the attested channel, never logged or kept), the
//! genesis body is staged and the genesis ordered first on the control route,
//! and its Ack's receipt, verified under the hosting root, is recorded with
//! the registration. Every step repeats the same bytes, so a retry after a
//! crash gets the original result from the service and the log object.
//!
//! The service verifies the genesis against the account's history at the
//! head it names, which a new account's first device alone holds. Before
//! registering, the client publishes whatever of that signup history the
//! account log lacks, in order and byte for byte, verified by a read of the
//! log. Completing the first device's setup at its home is `home`'s.
use crate::{
    Identity, Shared,
    account_evidence::{self, Session, VerifiedEvent},
    authz::Authz,
    outbox::{Fail, Link},
};
use bh_account::{
    Head as AccountHead, VerifiedAccount,
    journal::{AccountJournal, HistoryCursor},
    storage::DeviceJournal,
};
use bh_authz_proto::{FromService, MetadataKey, ToService, account_log_id, account_log_wrap};
use bh_device::incoming::VerifiedBatch;
use bh_storage::own_base::OwnBaseRecord;
use bh_sync::{
    BaseId, Commitment, OpaqueEvent, OrderState, Route,
    permit::{AppendAck, LogId, LogKind},
    receipt::{self, RECEIPT_LEN},
    wire::{self, Request, Response},
};

/// The own base, once registered here and its genesis applied.
pub(crate) struct OwnBase {
    pub log: LogId,
}

fn local<T, E>(result: Result<T, E>) -> Result<T, Fail> {
    result.map_err(|_| Fail::Local)
}

/// What registration has done in this run of the client.
#[derive(Default)]
pub(crate) struct Progress {
    /// The stored writer bindings are installed.
    installed: bool,
    /// The account log holds the signup history.
    caught_up: bool,
}

/// Make sure the own base is registered with the service and here, with its
/// genesis applied, registering it if not. `None`: no own base yet.
pub(crate) async fn ensure(
    shared: &Shared,
    link: &mut Link,
    progress: &mut Progress,
) -> Result<Option<OwnBase>, Fail> {
    let database = local(shared.owner.shared_database(shared.container))?;
    let (record, registration) = {
        let db = database.lock().expect("container writer lock");
        let Some(record) = local(db.own_base())? else {
            return Ok(None);
        };
        let registration = local(db.registration(record.base))?;
        (record, registration)
    };
    let log = LogId {
        kind: LogKind::Base,
        id: record.base,
    };
    // A base this device joined has no genesis receipt of its own: the
    // receiver reads and verifies its genesis from the log.
    let receipt = match registration {
        Some(r) if r.registered => {
            if !progress.installed {
                shared.owner.install_stored_bindings(shared.container);
                progress.installed = true;
            }
            r.genesis_receipt
        }
        _ => {
            if !progress.caught_up {
                catch_up(shared, link).await?;
                progress.caught_up = true;
            }
            let receipt = register(shared, link, &record).await?;
            // This also installs the bindings reader.
            local(shared.owner.record_registration(
                shared.container,
                record.base,
                Some(receipt),
                shared.endpoint.hosting_root,
            ))?;
            progress.installed = true;
            Some(receipt)
        }
    };
    if let Some(receipt) = receipt {
        apply_genesis(shared, &record, receipt)?;
    }
    Ok(Some(OwnBase { log }))
}

/// Send `RegisterBase` again, as after the service lost the registration,
/// and order the same genesis by exact retry.
pub(crate) async fn reregister(shared: &Shared, link: &mut Link) -> Result<(), Fail> {
    let database = local(shared.owner.shared_database(shared.container))?;
    let record =
        local(database.lock().expect("container writer lock").own_base())?.ok_or(Fail::Local)?;
    register(shared, link, &record).await.map(|_| ())
}

async fn register(
    shared: &Shared,
    link: &mut Link,
    record: &OwnBaseRecord,
) -> Result<[u8; RECEIPT_LEN], Fail> {
    let identity = shared.signer.identity().map_err(|_| Fail::Authorization)?;
    let descriptor = local(OpaqueEvent::decode(&record.genesis_descriptor))?;
    let base = BaseId(record.base);
    let ordered = local(Commitment::order(
        base,
        OrderState::EMPTY,
        &descriptor,
        Route::Control,
    ))?;
    let mut metadata = None;
    shared
        .signer
        .with_metadata_key(base, &mut |m| metadata = Some(MetadataKey::new(m)))
        .map_err(|_| Fail::Authorization)?;
    let message = ToService::RegisterBase {
        descriptor: record.genesis_descriptor.clone(),
        body: record.genesis_body.clone(),
        creator_head: identity.anchor.head(),
        metadata: metadata.ok_or(Fail::Authorization)?,
    };
    let answer = {
        let mut session = shared.authz.session(shared).await?;
        session.ask(message).await?
    };
    let FromService::Permits { items } = answer else {
        return Err(Fail::from_answer(&answer));
    };
    let [Ok(stage), Ok(append)] = items.as_slice() else {
        return Err(Fail::Authorization);
    };
    let data = link.data(shared).await?;
    let body = record.genesis_body.clone();
    let staged = data
        .ask(|id| Request::Stage {
            id,
            permit: stage.clone(),
            body,
        })
        .await
        .map_err(|_| Fail::Network)?;
    if !matches!(staged, Response::Staged { .. }) {
        return Err(Fail::from_response(&staged));
    }
    let acked = data
        .ask(|id| Request::Append {
            id,
            permit: append.clone(),
            event: record.genesis_descriptor.clone(),
        })
        .await
        .map_err(|_| Fail::Network)?;
    let Response::Acked { ack, .. } = acked else {
        return Err(Fail::from_response(&acked));
    };
    // The genesis is the log's first event: its Ack must name exactly that
    // head, with a receipt for it under the pinned root.
    let ack = AppendAck::decode(&ack).map_err(|_| Fail::Network)?;
    let receipt = ack.receipt.ok_or(Fail::Network)?;
    if ack.log
        != (LogId {
            kind: LogKind::Base,
            id: base.0,
        })
        || ack.event != descriptor.publication_id(Route::Control)
        || ack.head != ordered.head()
        || receipt::verify(&shared.endpoint.hosting_root, base, &receipt).map(|r| r.head())
            != Ok(ordered.head())
    {
        return Err(Fail::Network);
    }
    Ok(receipt)
}

/// Apply the own genesis to this device's verified progress, from local
/// bytes and the recorded receipt. Nothing to do once it is applied.
fn apply_genesis(
    shared: &Shared,
    record: &OwnBaseRecord,
    receipt: [u8; RECEIPT_LEN],
) -> Result<(), Fail> {
    let database = local(shared.owner.shared_database(shared.container))?;
    let progress = local(
        database
            .lock()
            .expect("container writer lock")
            .log_progress(LogKind::Base as u8, record.base),
    )?
    .ok_or(Fail::Local)?;
    if progress.position > 0 {
        return Ok(());
    }
    let identity = shared.signer.identity().map_err(|_| Fail::Authorization)?;
    let log = LogId {
        kind: LogKind::Base,
        id: record.base,
    };
    let mut history = local(shared.owner.history(
        shared.container,
        log,
        &identity.anchor,
        shared.endpoint.hosting_root,
        1,
    ))?;
    let descriptor = local(OpaqueEvent::decode(&record.genesis_descriptor))?;
    let ordered = local(Commitment::order(
        BaseId(record.base),
        OrderState::EMPTY,
        &descriptor,
        Route::Control,
    ))?;
    let mut prepared = None;
    shared
        .signer
        .with_metadata_key(BaseId(record.base), &mut |m| {
            // The genesis is judged with M alone.
            prepared =
                Some(history.prepare(&ordered, &descriptor, Some(&record.genesis_body), m, None))
        })
        .map_err(|_| Fail::Authorization)?;
    let prepared = local(prepared.ok_or(Fail::Local)?)?;
    let applied = local(history.consume_unapplied(prepared))?;
    local(shared.owner.apply_remote_batch(
        shared.container,
        VerifiedBatch {
            log,
            events: vec![applied],
            head: ordered.head(),
            receipt,
        },
    ))?;
    Ok(())
}

/// Publish the signup history the account log lacks, until the log holds
/// it all. This does not acknowledge the three private setup objects.
async fn catch_up(shared: &Shared, link: &mut Link) -> Result<(), Fail> {
    let identity = shared.signer.identity().map_err(|_| Fail::Authorization)?;
    let originals = signup_history(shared, &identity)?;
    // A home that has not seen the account knows only its genesis: prove
    // possession at the first head this device was active at.
    let at = earliest_active(&identity, &originals)?;
    let ordered = order_prefix(shared, &shared.authz, link, &identity, &originals, at).await?;
    let read: Vec<&[u8]> = ordered.iter().map(|e| e.original.as_slice()).collect();
    replayed(&identity, &read)?;
    // Later requests authenticate at the device's current head.
    shared.authz.close().await;
    Ok(())
}

/// Make the account log's first events exactly `originals`, the start of
/// the account's history, publishing those it lacks one at a time after a
/// verified read of the log. Returns the log's verified copy, each event
/// with the home's confirmation. Events the log holds are skipped, so a lost
/// answer is settled by the next read and a missing event is sent again
/// with the same bytes.
pub(crate) async fn order_prefix(
    shared: &Shared,
    authz: &Authz,
    link: &mut Link,
    identity: &Identity,
    originals: &[Vec<u8>],
    at: Option<AccountHead>,
) -> Result<Vec<VerifiedEvent>, Fail> {
    let log = LogId {
        kind: LogKind::Account,
        id: local(account_log_id(&identity.genesis))?,
    };
    loop {
        let ordered =
            read_account_log(shared, authz, link, log, at, originals.len() as u64).await?;
        // The log is this account's: a different event at a position this
        // device holds is a fork, never overwritten.
        if ordered
            .iter()
            .zip(originals)
            .any(|(theirs, ours)| theirs.original != *ours)
        {
            return Err(Fail::Local);
        }
        let Some(missing) = originals.get(ordered.len()) else {
            return Ok(ordered);
        };
        let previous = ordered.last().map_or(OrderState::EMPTY, |e| e.opening);
        submit_account_event(shared, authz, link, log, at, previous, missing).await?;
    }
}

/// The journal's signup history, up to the head the own base's genesis
/// names, verified by replay to exactly that head.
fn signup_history(shared: &Shared, identity: &Identity) -> Result<Vec<Vec<u8>>, Fail> {
    let database = local(shared.owner.shared_database(shared.container))?;
    let journal = DeviceJournal::from_shared(database);
    let cut = identity.anchor.head();
    let mut cursor = Some(HistoryCursor {
        anchor: identity.account,
        cut,
        next_position: 1,
    });
    let mut events = Vec::new();
    while let Some(next) = cursor {
        let page = local(journal.history_prefix(Some(next), 256))?.ok_or(Fail::Local)?;
        events.extend(page.events);
        cursor = page.next;
    }
    let refs: Vec<&[u8]> = events.iter().map(Vec::as_slice).collect();
    local(VerifiedAccount::replay(identity.account, &refs, cut))?;
    Ok(events)
}

/// The account replayed from `events`, which start at its genesis.
pub(crate) fn replayed(identity: &Identity, events: &[&[u8]]) -> Result<AccountHead, Fail> {
    let (genesis, rest) = events.split_first().ok_or(Fail::Local)?;
    let mut view = local(VerifiedAccount::from_genesis(identity.account, genesis))?;
    local(view.apply_batch(rest))?;
    Ok(view.head())
}

/// The first head of the signup history at which this device was active;
/// `None` if it never was there (a later device, authenticated at its
/// current head).
pub(crate) fn earliest_active(
    identity: &Identity,
    events: &[Vec<u8>],
) -> Result<Option<AccountHead>, Fail> {
    let mut view: Option<VerifiedAccount> = None;
    for event in events {
        let next = match view.take() {
            None => local(VerifiedAccount::from_genesis(identity.account, event))?,
            Some(mut view) => {
                local(view.apply(event))?;
                view
            }
        };
        if next.active_device(identity.device).is_ok() {
            return Ok(Some(next.head()));
        }
        view = Some(next);
    }
    Ok(None)
}

/// The account log's first `last` events, each commitment chained from the
/// log's start and naming its exact event, verified with its confirmation.
async fn read_account_log(
    shared: &Shared,
    authz: &Authz,
    link: &mut Link,
    log: LogId,
    at: Option<AccountHead>,
    last: u64,
) -> Result<Vec<VerifiedEvent>, Fail> {
    let genesis = shared
        .signer
        .identity()
        .map_err(|_| Fail::Authorization)?
        .genesis;
    if account_log_id(&genesis).map_err(|_| Fail::Network)? != log.id {
        return Err(Fail::Network);
    }
    let mut ordered: Vec<VerifiedEvent> = Vec::new();
    let mut order = OrderState::EMPTY;
    while order.position() < last {
        let end = last.min(order.position() + 64);
        let prior = ordered.last().and_then(|e| e.time);
        let page = account_evidence::read(
            shared,
            link,
            &genesis,
            order,
            prior,
            end,
            Session::At(authz, at),
        )
        .await?;
        let count = page.events.len() as u64;
        for event in page.events {
            order = event.opening;
            ordered.push(event);
        }
        if count == 0 || order.position() < end {
            // An empty account log at signup is not a currentness proof.
            // The next exact original still needs the service's append grant.
            break;
        }
    }
    Ok(ordered)
}

/// Submit one signup event and append it after `previous`.
async fn submit_account_event(
    shared: &Shared,
    authz: &Authz,
    link: &mut Link,
    log: LogId,
    at: Option<AccountHead>,
    previous: OrderState,
    original: &[u8],
) -> Result<(), Fail> {
    let answer = {
        let mut session = authz.session_at(shared, at).await?;
        session
            .ask(ToService::SubmitControl {
                log,
                event: original.to_vec(),
                delivery: None,
                attachment: None,
            })
            .await?
    };
    let FromService::Permits { items } = answer else {
        return Err(Fail::from_answer(&answer));
    };
    // A signup event carries no body: one append permit.
    let [Ok(append)] = items.as_slice() else {
        return Err(Fail::Authorization);
    };
    let event = local(account_log_wrap(original, None))?;
    let expected = local(Commitment::order(
        BaseId(log.id),
        previous,
        &event,
        Route::Control,
    ))?;
    let data = link.data(shared).await?;
    let permit = append.clone();
    let encoded = event.encode();
    let response = data
        .ask(|id| Request::Append {
            id,
            permit,
            event: encoded,
        })
        .await
        .map_err(|_| Fail::Network)?;
    match response {
        Response::Acked { ack, .. } => {
            let ack = AppendAck::decode(&ack).map_err(|_| Fail::Network)?;
            if ack.log != log
                || ack.event != event.publication_id(Route::Control)
                || ack.head != expected.head()
            {
                return Err(Fail::Network);
            }
            Ok(())
        }
        // The log moved on, or holds this id otherwise: the next read decides.
        Response::Refused {
            reason: wire::Refusal::Predecessor | wire::Refusal::Conflict,
            ..
        } => Err(Fail::Retry),
        other => Err(Fail::from_response(&other)),
    }
}
