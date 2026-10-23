//! Account runs: contiguous account events, each with the ordering
//! confirmation its account home's checker signed, copied into a base as one
//! control. The base applies each exactly as the account does, with the time
//! bounds its confirmation proves, so signers, maturity, deadlines and lapse
//! reach the account's own verdict.
//!
//! A run is copied by a key active in the base's copy of the account once
//! the run applies: a device's control key, or the current recovery key. The
//! copier only needs to be a current member; authority over each change
//! comes from that event's own signatures. So the current recovery key can
//! carry a base past a recovery-key replacement it never saw, and a removed
//! device cannot copy.
use crate::codec::{
    ACCOUNT_CHANGE_V2, Binding, CLASS_CONTROL, Error, Payload, key_id, prepare_seal,
};
use crate::control::{
    ControlChange, ControlSigningRequest, CopiedChange, Judged, Signed, SignedContext,
};
use crate::history::{Outcome, Seen};
use bh_account::{
    AccountChange, AccountEvent, ConfirmedTime, ControlOutcome, DeviceId, Error as AccountError,
    Head, VerifiedAccount,
};
use bh_crypto::{Secret, random};
use bh_sync::{
    BaseId, Digest, EventId,
    evidence::{OrderingConfirmation, original_digest},
    receipt::RECEIPT_LEN,
};
use std::sync::Arc;

/// The most account events one run carries.
pub const MAX_RUN: usize = 64;
/// A stored base-copy record that is not a single legacy account event.
const COPIES_DOMAIN: &[u8] = b"bh/base-account-copies/v1\0";
/// Every account event starts with its domain; a legacy record is exactly one.
const ACCOUNT_DOMAIN: &[u8] = b"BaseHero account event\0";

/// One account event a base copied, with the ordering confirmation that
/// timed it. Legacy single-event copies have none.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountCopy {
    pub original: Vec<u8>,
    pub confirmation: Option<Vec<u8>>,
}
// Originals name devices; diagnostics show only sizes.
impl std::fmt::Debug for AccountCopy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountCopy")
            .field("original", &self.original.len())
            .field("confirmed", &self.confirmation.is_some())
            .finish()
    }
}

/// Which key copies a run into a base.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Copier {
    /// An active device's control key.
    Device(DeviceId),
    /// The current recovery key, under its recovery author id.
    Recovery,
}

/// What one base control stores for the account events it copied: a legacy
/// copy's exact account event, or `COPIES_DOMAIN || count:u8 || count ×
/// (len:u32 || original || confirmed:u8 || confirmation)`.
pub fn encode_copies(copies: &[AccountCopy]) -> Vec<u8> {
    if let [
        AccountCopy {
            original,
            confirmation: None,
        },
    ] = copies
    {
        return original.clone();
    }
    let mut out = COPIES_DOMAIN.to_vec();
    out.push(copies.len() as u8);
    for copy in copies {
        out.extend((copy.original.len() as u32).to_be_bytes());
        out.extend(&copy.original);
        match &copy.confirmation {
            Some(confirmation) => {
                out.push(1);
                out.extend(confirmation);
            }
            None => out.push(0),
        }
    }
    out
}

/// The copies [`encode_copies`] stored.
pub fn decode_copies(record: &[u8]) -> Result<Vec<AccountCopy>, Error> {
    if record.starts_with(ACCOUNT_DOMAIN) {
        return Ok(vec![AccountCopy {
            original: record.to_vec(),
            confirmation: None,
        }]);
    }
    let mut input = record.strip_prefix(COPIES_DOMAIN).ok_or(Error::Invalid)?;
    let count = take(&mut input, 1)?[0] as usize;
    if !(1..=MAX_RUN).contains(&count) {
        return Err(Error::Invalid);
    }
    let mut copies = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u32::from_be_bytes(array(take(&mut input, 4)?)?) as usize;
        let original = take(&mut input, len)?.to_vec();
        let confirmation = match take(&mut input, 1)?[0] {
            0 => None,
            1 => Some(take(&mut input, OrderingConfirmation::LEN)?.to_vec()),
            _ => return Err(Error::Invalid),
        };
        copies.push(AccountCopy {
            original,
            confirmation,
        });
    }
    if !input.is_empty() {
        return Err(Error::Invalid);
    }
    Ok(copies)
}

/// A base's copy of the account: `anchor`, the account at the head its
/// genesis names, with each stored record ([`encode_copies`]) applied in
/// order as the base applied it. Confirmations verify under the base's
/// pinned `hosting_root`.
pub fn base_account<R: AsRef<[u8]>>(
    anchor: &VerifiedAccount,
    records: impl IntoIterator<Item = R>,
    hosting_root: &[u8; 32],
) -> Result<VerifiedAccount, Outcome> {
    let mut account = anchor.clone();
    for record in records {
        let copies = decode_copies(record.as_ref()).map_err(|_| Outcome::UnavailablePause)?;
        apply_copies(&mut account, &copies, hosting_root)?;
    }
    Ok(account)
}

/// Apply copies a base verified to its copy of the account: legacy copies
/// untimed, confirmed ones with their confirmed time.
pub fn apply_copies(
    account: &mut VerifiedAccount,
    copies: &[AccountCopy],
    hosting_root: &[u8; 32],
) -> Result<(), Outcome> {
    let mut next = account.clone();
    for copy in copies {
        match &copy.confirmation {
            None => next.apply(&copy.original).map_err(outcome)?,
            Some(confirmation) => {
                let time = confirmed(&next, &copy.original, confirmation, Some(hosting_root))?;
                next.apply_timed(&copy.original, Some(time))
                    .map_err(outcome)?;
            }
        }
    }
    *account = next;
    Ok(())
}

/// The time an ordering confirmation proves for `original` as the next event
/// of `account`. The checker signs only an original that verifies in its
/// own account's log, so the original, its predecessor and its head bind the
/// confirmation to this account without its log id. With no root (only when
/// preparing a control, never when judging one) the signature is not checked.
pub(crate) fn confirmed(
    account: &VerifiedAccount,
    original: &[u8],
    confirmation: &[u8],
    root: Option<&[u8; 32]>,
) -> Result<ConfirmedTime, Outcome> {
    let invalid = Outcome::Rejected;
    let event = AccountEvent::decode(original).map_err(outcome)?;
    let confirmation = OrderingConfirmation::decode(confirmation).map_err(|_| invalid)?;
    let claim = match root {
        Some(root) => confirmation.verify(root).map_err(|_| invalid)?,
        None => confirmation.claim(),
    };
    if claim.original != original_digest(original)
        || claim.original_previous != sync_head(account.head())
        || claim.original_head != sync_head(event.head())
    {
        return Err(invalid);
    }
    Ok(ConfirmedTime {
        earliest_ms: claim.bounds.earliest_ms,
        latest_ms: claim.bounds.latest_ms,
    })
}

fn sync_head(head: Head) -> bh_sync::Head {
    bh_sync::Head {
        position: head.position,
        hash: Digest(head.hash),
    }
}

/// How the base judges an account error: missing local evidence waits, an
/// event this build cannot read pauses, anything else is invalid.
pub(crate) fn outcome(error: AccountError) -> Outcome {
    match error {
        AccountError::Unavailable => Outcome::UnavailablePause,
        AccountError::UnsupportedVersion | AccountError::UnsupportedControl => {
            Outcome::UnsupportedPause
        }
        _ => Outcome::Rejected,
    }
}

/// `count:u8 (1..=64) || count × (len:u32 || original || confirmation)`.
fn encode_run(run: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![run.len() as u8];
    for (original, confirmation) in run {
        out.extend((original.len() as u32).to_be_bytes());
        out.extend(original);
        out.extend(confirmation);
    }
    out
}

/// One run entry: an original and its confirmation.
type Entry<'a> = (&'a [u8], &'a [u8]);

fn decode_run(mut data: &[u8]) -> Result<Vec<Entry<'_>>, Error> {
    let count = take(&mut data, 1)?[0] as usize;
    if !(1..=MAX_RUN).contains(&count) {
        return Err(Error::Invalid);
    }
    let mut run = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u32::from_be_bytes(array(take(&mut data, 4)?)?) as usize;
        let original = take(&mut data, len)?;
        let confirmation = take(&mut data, OrderingConfirmation::LEN)?;
        run.push((original, confirmation));
    }
    if !data.is_empty() {
        return Err(Error::Invalid);
    }
    Ok(run)
}

pub(crate) fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], Error> {
    let (head, rest) = input.split_at_checked(len).ok_or(Error::Invalid)?;
    *input = rest;
    Ok(head)
}
pub(crate) fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Invalid)
}

/// The account after a run: each event applied with its confirmed time as
/// the next event of `account`, and the copies to store. A run may carry the
/// account's membership and recovery-key changes. Setup is refused, and so
/// is a personal-key rotation that takes effect: it reaches a base only in
/// its rekey. A lapsed rotation changes nothing but the removal its deadline
/// made, so a run carries it.
fn apply_run(
    account: &VerifiedAccount,
    run: &[Entry<'_>],
    root: Option<&[u8; 32]>,
) -> Result<(VerifiedAccount, Vec<AccountCopy>), Outcome> {
    let mut next = account.clone();
    let mut copies = Vec::with_capacity(run.len());
    for &(original, confirmation) in run {
        let event = AccountEvent::decode(original).map_err(outcome)?;
        if matches!(event.change(), AccountChange::Setup) {
            return Err(Outcome::Rejected);
        }
        let time = confirmed(&next, original, confirmation, root)?;
        let applied = next
            .apply_timed_with_outcome(original, Some(time))
            .map_err(outcome)?;
        if applied == ControlOutcome::Applied
            && matches!(event.change(), AccountChange::PersonalRotated { .. })
        {
            return Err(Outcome::Rejected);
        }
        copies.push(AccountCopy {
            original: original.to_vec(),
            confirmation: Some(confirmation.to_vec()),
        });
    }
    Ok((next, copies))
}

/// The key that may copy into a base whose copy of the account is `account`.
fn copier_key(account: &VerifiedAccount, author: DeviceId) -> Option<[u8; 32]> {
    if account.recovery_author().ok() == Some(author) {
        return account.recovery_keys().ok().map(|keys| *keys.signing());
    }
    account
        .active_device(author)
        .ok()
        .map(|device| *device.control())
}

/// Whether a device active in `before` is not active in `after`.
pub(crate) fn removes(before: &VerifiedAccount, after: &VerifiedAccount) -> bool {
    before
        .active_devices()
        .is_ok_and(|mut devices| devices.any(|keys| after.active_device(keys.id()).is_err()))
}

/// Judge an `ACCOUNT_CHANGE_V2` control. A run that removes any device from
/// the base's copy (by RemoveSelf, RemoveNow, or a deadline a confirmation
/// in it reached) closes the content epoch, whether or not any device can
/// open its replacement yet; any other run keeps it.
pub(crate) fn judge_run(
    ctx: &impl SignedContext,
    signed: &Signed,
    data: &[u8],
) -> Result<Judged, Outcome> {
    let result = judge_run_checked(ctx, signed, data);
    // An author not active before this control is established only by the
    // run itself: what this build cannot judge is not the author's.
    match result {
        Err(Outcome::UnsupportedPause) if signed.key.is_none() => Err(Outcome::Rejected),
        other => other,
    }
}

fn judge_run_checked(
    ctx: &impl SignedContext,
    signed: &Signed,
    data: &[u8],
) -> Result<Judged, Outcome> {
    let invalid = Outcome::Rejected;
    let before = ctx.account();
    let run = decode_run(data).map_err(|_| invalid)?;
    if signed.binding.account_head != before.head() {
        return Err(invalid);
    }
    let root = ctx.hosting_root().ok_or(Outcome::UnavailablePause)?;
    let (after, copies) = apply_run(before, &run, Some(&root))?;
    match copier_key(&after, signed.binding.device) {
        Some(key) if signed.signed_by(&key) => {}
        _ => return Err(invalid),
    }
    let epoch_id = if removes(before, &after) {
        None
    } else {
        ctx.epoch_id()
    };
    Ok(Judged::Control {
        account: Some(Arc::new(after)),
        copy: Some(CopiedChange {
            change: ControlChange::AccountRun,
            copies,
            seal_set: None,
        }),
        metadata_id: ctx.metadata_id(),
        epoch_id,
    })
}

/// Prepare the base control that copies `run`, the next account events after
/// `base_account` (the base's copy of the account), each with its ordering
/// confirmation. `seen` is what the author's verified history of the base
/// had applied at its head and `receipt` the hosting receipt for that head.
/// The copier must be active once the run applies; it signs with its control
/// key, or the recovery key.
#[allow(clippy::too_many_arguments)] // One control's exact signed fields.
pub fn prepare_account_run(
    base: BaseId,
    base_account: &VerifiedAccount,
    copier: Copier,
    metadata: &Secret<32>,
    seen: Seen,
    receipt: [u8; RECEIPT_LEN],
    run: &[(Vec<u8>, Vec<u8>)],
) -> Result<ControlSigningRequest, Error> {
    if seen.head.position == 0
        || seen.account != base_account.head()
        || !(1..=MAX_RUN).contains(&run.len())
    {
        return Err(Error::Invalid);
    }
    let borrowed: Vec<Entry<'_>> = run
        .iter()
        .map(|(original, confirmation)| (original.as_slice(), confirmation.as_slice()))
        .collect();
    let (after, _) = apply_run(base_account, &borrowed, None).map_err(|_| Error::Invalid)?;
    let device = match copier {
        Copier::Device(device) => device,
        Copier::Recovery => after.recovery_author().map_err(|_| Error::Invalid)?,
    };
    let expected = copier_key(&after, device).ok_or(Error::Invalid)?;
    let data = encode_run(run);
    Ok(ControlSigningRequest::new(prepare_seal(
        Binding {
            version: 3,
            highest: 3,
            mode: 0,
            base: base.0,
            audience: [0; 32],
            epoch: key_id(metadata),
            event_id: EventId(random()),
            account: base_account.id(),
            device,
            account_head: seen.account,
            seen: seen.head,
            seen_control: seen.control,
            class: CLASS_CONTROL,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: receipt,
        },
        Payload {
            kind: ACCOUNT_CHANGE_V2,
            data: &data,
        },
        expected,
        metadata,
        None,
    )?))
}
