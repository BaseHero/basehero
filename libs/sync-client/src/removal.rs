//! A refused device can still read public account evidence. Never interpret
//! NotActive itself as proof: replay independently verified, exactly ordered
//! originals on a candidate, without changing the account owner.
use crate::{
    AccountApplyError, BaseControlRequest, ControlSignError, Endpoint, HomeSetup, Identity,
    RemovalVerdict, Shared, Signer, SignerError, TimedOriginal,
    account_evidence::{self, EvidenceFailure},
    copier::{match_stored_accepted, matched_prefix, stored_time},
    outbox::{Fail, Link},
    transport::Connector,
};
use bh_account::{
    ConfirmedTime, DeviceId, DeviceState, Error as AccountError, Head as AccountHead,
    PendingRemoval, VerifiedAccount, device_auth,
    device_auth::Proof,
    journal::{AccountJournal, HistoryCursor},
    storage::DeviceJournal,
};
use bh_authz_proto::account_log_id;
use bh_crypto::Secret;
use bh_device::{ContainerId, Owner};
use bh_sync::BaseId;
use bh_sync::{
    evidence::AcceptedHead,
    permit::{LogId, LogKind},
};
use futures_util::future::BoxFuture;
use std::sync::Arc;

const PAGE: u64 = 64;

// The prefix helpers distinguish local journal errors from contradicted
// authenticated evidence. An absent locally kept confirmation is unavailable,
// not a signed claim of removal.
fn classify_match(error: Fail) -> Result<(), Fail> {
    match error {
        Fail::Network => Ok(()),
        Fail::Missing | Fail::Local => Err(Fail::Local),
        other => Err(other),
    }
}

fn classify_apply(error: AccountError) -> Result<(), Fail> {
    match error {
        AccountError::Unavailable | AccountError::IncompleteMaterials => Err(Fail::Local),
        AccountError::UnsupportedVersion | AccountError::UnsupportedControl => {
            Err(Fail::Unsupported)
        }
        _ => Ok(()),
    }
}

fn account_head(accepted: AcceptedHead) -> AccountHead {
    AccountHead {
        position: accepted.original_head.position,
        hash: accepted.original_head.hash.0,
    }
}

fn refused(shared: &Shared) -> Result<(RemovalVerdict, u64), Fail> {
    let db = shared
        .owner
        .shared_database(shared.container)
        .map_err(|_| Fail::Local)?;
    db.lock()
        .expect("container writer lock")
        .record_refused_change(shared.endpoint.device_clock.now_ms())
        .map_err(|_| Fail::Local)?;
    shared.signer.alerts_written();
    // No verified time is needed: only Pending verdicts schedule a recheck.
    Ok((RemovalVerdict::Refused, 0))
}

/// A removal that took effect only because home-confirmed time reached its
/// deadline: that deadline and its requester.
type Due = Option<(u64, Option<DeviceId>)>;

/// The request whose deadline home time `at_ms` reached that a removal of
/// `device` waits for. With several, the latest: an earlier one may have
/// lapsed and a later one taken effect, so waiting for it is conservative.
fn reached(pending: Vec<PendingRemoval>, device: DeviceId, at_ms: u64) -> Option<PendingRemoval> {
    pending
        .into_iter()
        .filter(|p| p.target == device && p.deadline_ms <= at_ms)
        .max_by_key(|p| (p.deadline_ms, p.request))
}

/// Apply ordered originals one at a time. When home time alone ends this
/// device's membership, keep that request's deadline: the verdict waits for
/// the device clock as well.
fn apply_gated(
    mut candidate: VerifiedAccount,
    device: DeviceId,
    timed: &[(&[u8], Option<ConfirmedTime>)],
    due: &mut Due,
) -> Result<VerifiedAccount, AccountError> {
    for &(original, time) in timed {
        let reached = match time {
            Some(time) if candidate.active_device(device).is_ok() => {
                reached(candidate.pending_removals(0), device, time.earliest_ms)
            }
            _ => None,
        };
        candidate = candidate.applied_batch_timed(&[(original, time)])?;
        if let Some(p) = reached
            && candidate.active_device(device).is_err()
        {
            due.get_or_insert((p.deadline_ms, p.by));
        }
    }
    Ok(candidate)
}

/// Bring the last verified view up to the outer checkpoint from the journal:
/// the account follow verified and committed these originals with their
/// confirmations, and this device's authority ended with them.
fn caught_up(
    journal: &DeviceJournal,
    mut candidate: VerifiedAccount,
    to: u64,
    device: DeviceId,
    due: &mut Due,
) -> Result<VerifiedAccount, Fail> {
    let cut = journal
        .history_prefix(None, 1)
        .map_err(|_| Fail::Local)?
        .ok_or(Fail::Local)?
        .cut;
    if cut.position < to {
        return Err(Fail::Local);
    }
    while candidate.head().position < to {
        let count = (to - candidate.head().position).min(PAGE) as usize;
        let page = journal
            .history_prefix(
                Some(HistoryCursor {
                    anchor: candidate.id(),
                    cut,
                    next_position: candidate.head().position + 1,
                }),
                count,
            )
            .map_err(|_| Fail::Local)?
            .ok_or(Fail::Local)?;
        if page.events.len() != count {
            return Err(Fail::Local);
        }
        let timed: Vec<_> = page
            .events
            .iter()
            .zip(&page.times)
            .map(|(original, time)| (original.as_slice(), *time))
            .collect();
        candidate = apply_gated(candidate, device, &timed, due).map_err(|_| Fail::Local)?;
    }
    Ok(candidate)
}

/// Check against a fresh challenged accepted head and every intervening
/// ordered original. The protected outer checkpoint is only an opening, not
/// permission to invent missing history or to treat a head as completeness.
pub(crate) async fn check(shared: &Shared, link: &mut Link) -> Result<(RemovalVerdict, u64), Fail> {
    let identity = shared.signer.identity().map_err(|_| Fail::Authorization)?;
    let log = LogId {
        kind: LogKind::Account,
        id: account_log_id(&identity.genesis).map_err(|_| Fail::Local)?,
    };
    let db = shared
        .owner
        .shared_database(shared.container)
        .map_err(|_| Fail::Local)?;
    let journal = DeviceJournal::from_shared(db.clone());
    let progress = db
        .lock()
        .expect("container writer lock")
        .account_outer_progress(log.id, shared.endpoint.hosting_root)
        .map_err(|_| Fail::Local)?;
    let mut opening = progress.order;
    let mut prior = stored_time(&db, opening.position())?;
    // The owner may already have applied this device's removal, ending its
    // current view: start from the last verified one instead.
    let mut candidate = shared
        .signer
        .last_verified_account()
        .map_err(|_| Fail::Authorization)?;
    if candidate.id() != identity.account {
        return Err(Fail::Local);
    }
    let mut due = None;
    if opening.position() > candidate.head().position {
        candidate = caught_up(
            &journal,
            candidate,
            opening.position(),
            identity.device,
            &mut due,
        )?;
    }
    let mut pending = Vec::new();
    let mut verified_head = false;
    let mut accepted_bounds = None;
    loop {
        let first = opening.position().checked_add(1).ok_or(Fail::Network)?;
        let last = first.checked_add(PAGE - 1).ok_or(Fail::Network)?;
        let page = match account_evidence::read_public(
            shared,
            link,
            &identity.genesis,
            opening,
            prior,
            last,
        )
        .await
        {
            Ok(page) => page,
            Err(EvidenceFailure::Unavailable(fail)) => return Err(fail),
            Err(EvidenceFailure::Invalid) => return refused(shared),
        };
        let full = page.events.len() as u64 == PAGE;
        let reached =
            match account_evidence::match_page_claims(&mut pending, &page.events, page.accepted) {
                Ok(reached) => reached,
                Err(_) => return refused(shared),
            };
        if page.events.is_empty() {
            if opening.position() != candidate.head().position
                || pending
                    .iter()
                    .any(|claim| account_head(*claim) != candidate.head())
            {
                return refused(shared);
            }
            for claim in pending.drain(..) {
                if let Err(error) = match_stored_accepted(
                    &journal,
                    &db,
                    identity.account,
                    candidate.head(),
                    claim,
                    shared.endpoint.hosting_root,
                    log,
                    opening,
                ) {
                    classify_match(error)?;
                    return refused(shared);
                }
                accepted_bounds = Some(claim.bounds);
                verified_head = true;
            }
        } else {
            let originals: Vec<&[u8]> = page
                .events
                .iter()
                .map(|event| event.original.as_slice())
                .collect();
            let matched = match matched_prefix(
                &journal,
                identity.account,
                candidate.head(),
                opening.position(),
                &originals,
            ) {
                Ok(matched) => matched,
                Err(error) => {
                    classify_match(error)?;
                    return refused(shared);
                }
            };
            // All reached heads (including ahead claims from earlier pages)
            // have to match their original and proof. Stored prefix claims
            // need the independently kept proof as well.
            for (index, claim) in reached {
                if index < matched
                    && let Err(error) = match_stored_accepted(
                        &journal,
                        &db,
                        identity.account,
                        account_head(claim),
                        claim,
                        shared.endpoint.hosting_root,
                        log,
                        page.events[index].opening,
                    )
                {
                    classify_match(error)?;
                    return refused(shared);
                }
                if index == page.events.len() - 1
                    && account_head(claim) == account_head(page.accepted)
                {
                    accepted_bounds = Some(claim.bounds);
                    verified_head = true;
                }
            }
            let timed: Vec<_> = page.events[matched..]
                .iter()
                .map(|event| {
                    (
                        event.original.as_slice(),
                        event.time.map(|time| ConfirmedTime {
                            earliest_ms: time.earliest_ms,
                            latest_ms: time.latest_ms,
                        }),
                    )
                })
                .collect();
            candidate = match apply_gated(candidate, identity.device, &timed, &mut due) {
                Ok(next) => next,
                Err(error) => {
                    classify_apply(error)?;
                    return refused(shared);
                }
            };
            let last_event = page.events.last().expect("nonempty page");
            opening = last_event.opening;
            prior = last_event.time;
        }
        if !full {
            if !pending.is_empty()
                || !verified_head
                || account_head(page.accepted) != candidate.head()
            {
                return refused(shared);
            }
            break;
        }
    }
    let bounds = accepted_bounds.ok_or(Fail::Missing)?;
    let at_ms = bounds
        .earliest_ms
        .min(shared.endpoint.device_clock.now_ms());
    let verdict = match candidate.device_state(identity.device, at_ms) {
        Ok(DeviceState::Active) => RemovalVerdict::Active,
        Ok(DeviceState::RemovalPending {
            request,
            deadline_ms,
        }) => RemovalVerdict::Pending {
            deadline_ms,
            by: candidate
                .pending_removals(at_ms)
                .into_iter()
                .find(|pending| pending.request == request)
                .and_then(|pending| pending.by),
        },
        Ok(DeviceState::Removed) => match due {
            // Home time alone ended this membership: the device clock must
            // reach the deadline too.
            Some((deadline_ms, by)) if at_ms < deadline_ms => {
                RemovalVerdict::Pending { deadline_ms, by }
            }
            _ => {
                let unsent = db
                    .lock()
                    .expect("container writer lock")
                    .unsent_count()
                    .map_err(|_| Fail::Local)?;
                RemovalVerdict::Removed { unsent }
            }
        },
        Err(error) => {
            classify_apply(error)?;
            return refused(shared);
        }
    };
    Ok((verdict, bounds.earliest_ms))
}

/// A removed device's only standing: who it was and the last account view in
/// which it was a member. It can read public evidence and nothing else.
struct MemberView {
    device: DeviceId,
    genesis: Vec<u8>,
    last: VerifiedAccount,
}

impl Signer for MemberView {
    fn identity(&self) -> Result<Identity, SignerError> {
        Ok(Identity {
            account: self.last.id(),
            device: self.device,
            genesis: self.genesis.clone(),
            // Never used to seal: this signer has no base keys.
            anchor: self.last.clone(),
        })
    }
    fn device_proof(&self, _: device_auth::Context) -> BoxFuture<'_, Result<Proof, SignerError>> {
        Box::pin(async { Err(SignerError) })
    }
    fn device_proof_at(
        &self,
        _: AccountHead,
        _: device_auth::Context,
    ) -> BoxFuture<'_, Result<Proof, SignerError>> {
        Box::pin(async { Err(SignerError) })
    }
    fn initial_home_setup(&self) -> Result<Option<HomeSetup>, SignerError> {
        Err(SignerError)
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
        Err(SignerError)
    }
    fn last_verified_account(&self) -> Result<VerifiedAccount, SignerError> {
        Ok(self.last.clone())
    }
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

/// One check with no running client, from `last`: see `check_removal`.
pub(crate) async fn once(
    endpoint: Endpoint,
    connector: Arc<dyn Connector>,
    owner: Arc<Owner>,
    container: ContainerId,
    device: DeviceId,
    genesis: Vec<u8>,
    last: VerifiedAccount,
) -> Option<RemovalVerdict> {
    let (status, _) = tokio::sync::watch::channel(crate::SyncStatus::SavedLocal { pending: 0 });
    let signer = Arc::new(MemberView {
        device,
        genesis,
        last,
    });
    let shared = Shared::new(
        endpoint,
        connector,
        owner,
        container,
        signer,
        status,
        crate::Tuning::default(),
    );
    let mut link = Link::default();
    let checked = check(&shared, &mut link).await;
    link.shutdown().await;
    shared.authz.stop();
    shared.authz.close().await;
    checked.ok().map(|(verdict, _)| verdict)
}

fn pending_delay_ms(deadline_ms: u64, device_now_ms: u64, home_earliest_ms: u64) -> u64 {
    let remaining = if device_now_ms >= deadline_ms {
        // The device clock no longer limits erasure; wait for a fresh
        // verified home bound, not another full interval by default.
        deadline_ms
            .saturating_sub(home_earliest_ms)
            .saturating_add(1_000)
    } else {
        deadline_ms - device_now_ms
    };
    remaining.clamp(1_000, 300_000)
}

pub(crate) async fn run(shared: Arc<Shared>) {
    let mut ordinary = shared.authz.not_active();
    let mut home = shared.home_authz.not_active();
    let mut link = Link::default();
    let mut pending_recheck = None;
    loop {
        tokio::select! {
            _ = shared.halted() => break,
            _ = shared.removal_wake.notified() => {},
            answer = ordinary.changed() => if answer.is_err() { break; },
            answer = home.changed() => if answer.is_err() { break; },
            _ = async {
                if let Some(at) = pending_recheck {
                    tokio::time::sleep_until(at).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {},
        }
        let checked = loop {
            let overtaken = shared.removal_wake.notified();
            tokio::pin!(overtaken);
            overtaken.as_mut().enable();
            let checked = check(&shared, &mut link).await;
            // A wake during the check asks about newer history, such as
            // the owner applying this device's removal: answer that instead.
            if futures_util::FutureExt::now_or_never(overtaken).is_none() {
                break checked;
            }
        };
        // A superseded check reuses the link it was reading on, but nothing
        // waits for the next check: a verdict or a failure leaves no socket
        // held open, idle, between them, and no stale one to retry on.
        link.shutdown().await;
        if let Ok((verdict, home_earliest_ms)) = checked {
            if let RemovalVerdict::Pending { deadline_ms, .. } = verdict {
                // Recheck the independently moving device and home clocks,
                // even if neither a subscription nor a new request arrives.
                let now = shared.endpoint.device_clock.now_ms();
                let ms = pending_delay_ms(deadline_ms, now, home_earliest_ms);
                pending_recheck =
                    Some(tokio::time::Instant::now() + std::time::Duration::from_millis(ms));
            } else {
                pending_recheck = None;
            }
            shared.removal_verdict.send_replace(verdict);
            if matches!(verdict, RemovalVerdict::Removed { .. }) {
                break;
            }
        } else {
            // A failed read is neither Active nor removal proof. Each check
            // answers an ask, a refusal or a pending deadline: retry on the
            // bounded interval until an answer is published.
            pending_recheck =
                Some(tokio::time::Instant::now() + std::time::Duration::from_secs(300));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_account::Error;

    #[test]
    fn deadline_recheck_uses_remaining_home_time_without_clock_storm() {
        // At the device deadline, home is 1.2 seconds behind: checking in
        // 2.2 seconds is sufficient; another five-minute wait is not.
        assert_eq!(pending_delay_ms(10_000, 10_001, 8_800), 2_200);
        // A device hours ahead of home still checks at most once per five
        // minutes, not on every tick of its already-past deadline.
        assert_eq!(pending_delay_ms(1_000_000, 20_000_000, 1_000), 300_000);
        assert_eq!(pending_delay_ms(10_000, 9_000, 8_800), 1_000);
    }

    #[test]
    fn unavailable_local_evidence_is_not_a_refused_change() {
        // Storage failure or an unsupported original must not be presented
        // as a cryptographic verdict about the home.
        assert_eq!(classify_match(Fail::Local), Err(Fail::Local));
        assert_eq!(classify_match(Fail::Missing), Err(Fail::Local));
        assert_eq!(classify_apply(Error::Unavailable), Err(Fail::Local));
        assert_eq!(
            classify_apply(Error::UnsupportedVersion),
            Err(Fail::Unsupported)
        );
        assert_eq!(classify_apply(Error::BadSignature), Ok(()));
        assert_eq!(classify_match(Fail::Network), Ok(()));
    }

    #[test]
    fn several_reached_requests_wait_for_the_latest_deadline() {
        // An earlier request may lapse when its requester is removed first;
        // the one that takes effect may be the later one. Wait for it.
        let (device, other) = (DeviceId([1; 32]), DeviceId([2; 32]));
        let request = |request, target, deadline_ms| PendingRemoval {
            request,
            target,
            by: Some(DeviceId([9; 32])),
            deadline_ms,
        };
        let pending = vec![
            request(1, device, 1_000),
            request(2, device, 3_000),
            request(3, other, 4_000),
            request(4, device, 9_000),
        ];
        assert_eq!(
            reached(pending, device, 5_000).map(|p| p.deadline_ms),
            Some(3_000)
        );
    }
}
