//! `ACCOUNT_REKEY`: a base's new content key after the account rotates its
//! personal key. The control carries the rotation (the next event of the
//! base's copy of the account) with its ordering confirmation, the new key's
//! id, and the commitment of its seal set: the new key sealed to each
//! member's current personal key. It is signed with the ordinary key of a
//! device active once the rotation applies, in binding mode 2.
//!
//! The seal set is a separate body object in the base's body store, staged
//! before the control and named by its append, so it can be deleted by its
//! commitment once its key is replaced while the control stays forever. The
//! control commits to the set, never to its bytes: judging the control,
//! including reopening the epoch under the new id, never needs the set.
//!
//! The set is encrypted under a key derived from the base's metadata key M,
//! bound to the base, the control's event id and the new key id, because
//! seal headers name the sending account and device.
//!
//! Known limit: one set is one body object, at most 4 MiB, about 2,790 seals
//! of today's 1,499 bytes. A base whose members hold more personal keys
//! than that needs the set split across objects.
use crate::account_run::{AccountCopy, array, confirmed, outcome, take};
use crate::codec::{
    ACCOUNT_REKEY, Binding, CLASS_CONTROL, Error, MODE_ORDINARY, Payload, key_id, open_binding,
    open_body, prepare_seal,
};
use crate::control::{
    ControlChange, ControlSigningRequest, CopiedChange, Judged, Signed, SignedContext,
};
use crate::history::{AppliedEvent, AppliedKind, Outcome, Seen};
use bh_account::{AccountChange, AccountEvent, ControlOutcome, DeviceId, VerifiedAccount};
use bh_crypto::{Secret, aead_open, aead_seal, derive_key, random};
use bh_sync::{
    BODY_SIZES, BaseId, BodyObject, Digest, EventId, OpaqueEvent, evidence::OrderingConfirmation,
    receipt::RECEIPT_LEN,
};
use std::sync::Arc;

const SEAL_SET_KEY: &[u8; 8] = b"bhRkSs01";
const SEAL_SET_AAD: &[u8] = b"bh/rekey-seal-set-aad/v1\0";
/// Nonce and tag around the seal set's padded plaintext.
const SEAL_SET_OVERHEAD: usize = 24 + 16;

/// A rekey's new content key id and its seals.
pub type EpochSeals = ([u8; 32], Vec<Vec<u8>>);

/// A prepared rekey: the control for the author's ordinary key to sign, and
/// the seal set to stage, by its commitment, before the control's append.
pub struct PreparedRekey {
    pub control: ControlSigningRequest,
    pub seal_set: BodyObject,
}

struct RekeyPayload<'a> {
    rotation: &'a [u8],
    confirmation: &'a [u8],
    key_id: [u8; 32],
    count: u16,
    seal_set: Digest,
}
/// `len:u32 || rotation || confirmation || key_id:32 || count:u16 ||
/// seal_set_commitment:32`.
fn encode_payload(p: &RekeyPayload<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + p.rotation.len() + p.confirmation.len() + 66);
    out.extend((p.rotation.len() as u32).to_be_bytes());
    out.extend(p.rotation);
    out.extend(p.confirmation);
    out.extend(p.key_id);
    out.extend(p.count.to_be_bytes());
    out.extend(p.seal_set.0);
    out
}
fn decode_payload(mut data: &[u8]) -> Result<RekeyPayload<'_>, Error> {
    let len = u32::from_be_bytes(array(take(&mut data, 4)?)?) as usize;
    let payload = RekeyPayload {
        rotation: take(&mut data, len)?,
        confirmation: take(&mut data, OrderingConfirmation::LEN)?,
        key_id: array(take(&mut data, 32)?)?,
        count: u16::from_be_bytes(array(take(&mut data, 2)?)?),
        seal_set: Digest(array(take(&mut data, 32)?)?),
    };
    if !data.is_empty() || payload.count == 0 {
        return Err(Error::Invalid);
    }
    Ok(payload)
}

fn seal_set_ad(base: BaseId, event_id: EventId, key_id: &[u8; 32]) -> Vec<u8> {
    [SEAL_SET_AAD, &base.0, &event_id.0, key_id].concat()
}

/// `nonce || AEAD(count:u16 || count × (len:u32 || seal) || zeros)` in the
/// smallest body size that fits.
fn seal_set(
    metadata: &Secret<32>,
    base: BaseId,
    event_id: EventId,
    key_id: &[u8; 32],
    seals: &[Vec<u8>],
) -> Result<BodyObject, Error> {
    let count = u16::try_from(seals.len()).map_err(|_| Error::Invalid)?;
    if count == 0 {
        return Err(Error::Invalid);
    }
    let mut plain = count.to_be_bytes().to_vec();
    for seal in seals {
        plain.extend((u32::try_from(seal.len()).map_err(|_| Error::Invalid)?).to_be_bytes());
        plain.extend(seal);
    }
    let size = *BODY_SIZES
        .iter()
        .find(|&&size| plain.len() + SEAL_SET_OVERHEAD <= size)
        .ok_or(Error::Invalid)?;
    plain.resize(size - SEAL_SET_OVERHEAD, 0);
    let key = derive_key(metadata, SEAL_SET_KEY, 0);
    let (nonce, cipher) = aead_seal(&key, &seal_set_ad(base, event_id, key_id), &plain)
        .map_err(|_| Error::Invalid)?;
    let mut bytes = nonce.to_vec();
    bytes.extend(cipher);
    BodyObject::new(bytes).map_err(|_| Error::Invalid)
}

fn open_seal_set(
    metadata: &Secret<32>,
    base: BaseId,
    event_id: EventId,
    key_id: &[u8; 32],
    count: u16,
    bytes: &[u8],
) -> Result<Vec<Vec<u8>>, Error> {
    let key = derive_key(metadata, SEAL_SET_KEY, 0);
    let nonce: &[u8; 24] = bytes
        .get(..24)
        .and_then(|n| n.try_into().ok())
        .ok_or(Error::Invalid)?;
    let plain = aead_open(
        &key,
        nonce,
        &seal_set_ad(base, event_id, key_id),
        &bytes[24..],
    )
    .map_err(|_| Error::Invalid)?;
    let mut input = plain.expose();
    if u16::from_be_bytes(array(take(&mut input, 2)?)?) != count {
        return Err(Error::Invalid);
    }
    let mut seals = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let len = u32::from_be_bytes(array(take(&mut input, 4)?)?) as usize;
        seals.push(take(&mut input, len)?.to_vec());
    }
    if input.iter().any(|&b| b != 0) {
        return Err(Error::Invalid);
    }
    Ok(seals)
}

/// The rotation applied with its confirmed time as the next event of
/// `account`, which must be a personal-key rotation that takes effect. A
/// lapsed one rotated no key, so no epoch follows it; a run copies it.
fn apply_rotation(
    account: &VerifiedAccount,
    rotation: &[u8],
    confirmation: &[u8],
    root: Option<&[u8; 32]>,
) -> Result<VerifiedAccount, Outcome> {
    let event = AccountEvent::decode(rotation).map_err(outcome)?;
    if !matches!(event.change(), AccountChange::PersonalRotated { .. }) {
        return Err(Outcome::Rejected);
    }
    let time = confirmed(account, rotation, confirmation, root)?;
    let mut next = account.clone();
    match next
        .apply_timed_with_outcome(rotation, Some(time))
        .map_err(outcome)?
    {
        ControlOutcome::Applied => Ok(next),
        ControlOutcome::Lapsed => Err(Outcome::Rejected),
    }
}

/// Judge an `ACCOUNT_REKEY` control: the epoch becomes the new key's id,
/// whether it was open or closed.
pub(crate) fn judge_rekey(
    ctx: &impl SignedContext,
    signed: &Signed,
    data: &[u8],
) -> Result<Judged, Outcome> {
    let invalid = Outcome::Rejected;
    let before = ctx.account();
    let payload = decode_payload(data).map_err(|_| invalid)?;
    if signed.binding.mode != MODE_ORDINARY
        || signed.binding.account_head != before.head()
        || Some(payload.key_id) == ctx.epoch_id()
    {
        return Err(invalid);
    }
    let root = ctx.hosting_root().ok_or(Outcome::UnavailablePause)?;
    let after = apply_rotation(before, payload.rotation, payload.confirmation, Some(&root))?;
    match after.active_device(signed.binding.device) {
        Ok(device) if signed.signed_by(device.signing()) => {}
        _ => return Err(invalid),
    }
    // Confirmation may establish another removal after the raw seals were
    // prepared. The rotation still advances the account, but its personal
    // key may be held by that newly removed recipient. Keep the epoch closed
    // until a later rotation fulfils all already-established effects. Zero
    // checks those effects without advancing any still-pending deadline.
    let epoch_id = after.rotation_due(0).is_none().then_some(payload.key_id);
    Ok(Judged::Control {
        account: Some(Arc::new(after)),
        copy: Some(CopiedChange {
            change: ControlChange::Rekey,
            copies: vec![AccountCopy {
                original: payload.rotation.to_vec(),
                confirmation: Some(payload.confirmation.to_vec()),
            }],
            seal_set: Some(payload.seal_set),
        }),
        metadata_id: ctx.metadata_id(),
        epoch_id,
    })
}

/// The base's copy of the account once `rotation`, its next account event
/// with `confirmation` verified under the base's pinned `hosting_root`,
/// applies: only for a personal-key rotation that takes effect. Its
/// personal key is the one a rekey seals the new content key to.
pub fn rotated_account(
    base_account: &VerifiedAccount,
    rotation: &[u8],
    confirmation: &[u8],
    hosting_root: &[u8; 32],
) -> Result<VerifiedAccount, Error> {
    apply_rotation(base_account, rotation, confirmation, Some(hosting_root))
        .map_err(|_| Error::Invalid)
}

/// Prepare the `ACCOUNT_REKEY` control installing `new_epoch` in a base whose
/// copy of the account is `base_account`. `rotation` must be that copy's next
/// account event, a personal-key rotation, and `confirmation` its ordering
/// confirmation; `seals` seal `new_epoch` to each member's current personal
/// key. `device` must be active once the rotation applies; it signs with its
/// ordinary key. `seen` and `receipt` are as for any control.
#[allow(clippy::too_many_arguments)] // One control's exact signed fields.
pub fn prepare_rekey(
    base: BaseId,
    base_account: &VerifiedAccount,
    device: DeviceId,
    metadata: &Secret<32>,
    seen: Seen,
    receipt: [u8; RECEIPT_LEN],
    rotation: &[u8],
    confirmation: &[u8],
    new_epoch: &Secret<32>,
    seals: &[Vec<u8>],
) -> Result<PreparedRekey, Error> {
    prepare_rekey_for(
        base,
        base_account,
        device,
        metadata,
        seen,
        receipt,
        rotation,
        confirmation,
        key_id(new_epoch),
        seals,
    )
}

/// As [`prepare_rekey`], naming the new content key only by its id
/// `new_id`: the key itself stays with whoever sealed `seals`.
#[allow(clippy::too_many_arguments)] // One control's exact signed fields.
pub fn prepare_rekey_for(
    base: BaseId,
    base_account: &VerifiedAccount,
    device: DeviceId,
    metadata: &Secret<32>,
    seen: Seen,
    receipt: [u8; RECEIPT_LEN],
    rotation: &[u8],
    confirmation: &[u8],
    new_id: [u8; 32],
    seals: &[Vec<u8>],
) -> Result<PreparedRekey, Error> {
    if seen.head.position == 0 || seen.account != base_account.head() {
        return Err(Error::Invalid);
    }
    let after =
        apply_rotation(base_account, rotation, confirmation, None).map_err(|_| Error::Invalid)?;
    let expected = *after
        .active_device(device)
        .map_err(|_| Error::Invalid)?
        .signing();
    let event_id = EventId(random());
    let set = seal_set(metadata, base, event_id, &new_id, seals)?;
    let data = encode_payload(&RekeyPayload {
        rotation,
        confirmation,
        key_id: new_id,
        count: seals.len() as u16,
        seal_set: set.commitment(),
    });
    let control = ControlSigningRequest::new(prepare_seal(
        Binding {
            version: 3,
            highest: 3,
            mode: MODE_ORDINARY,
            base: base.0,
            audience: [0; 32],
            epoch: key_id(metadata),
            event_id,
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
            kind: ACCOUNT_REKEY,
            data: &data,
        },
        expected,
        metadata,
        None,
    )?);
    Ok(PreparedRekey {
        control,
        seal_set: set,
    })
}

/// The new content key's id and its seals, from an accepted `ACCOUNT_REKEY`
/// and its seal set. `Ok(None)` for any other event. Without the seal set
/// the seals are `Unavailable`, to fetch and retry; bytes other than the set
/// the control committed to, or a set bound to another base, control or key,
/// are `Invalid`, never another set.
pub fn rekey_seals(
    applied: &AppliedEvent,
    metadata: &Secret<32>,
    seal_set: Option<&[u8]>,
) -> Result<Option<EpochSeals>, Error> {
    if !matches!(applied.kind(), AppliedKind::Control) {
        return Ok(None);
    }
    let base = applied.commitment().base();
    let descriptor = OpaqueEvent::decode(applied.descriptor_bytes()).map_err(|_| Error::Invalid)?;
    let signed = open_binding(&descriptor, metadata, base.0, false)?.binding;
    if signed.mode != MODE_ORDINARY {
        return Ok(None);
    }
    let body = open_body(&signed, applied.body_bytes(), metadata, None)?;
    if body.kind != ACCOUNT_REKEY {
        return Ok(None);
    }
    let payload = decode_payload(body.data())?;
    let bytes = seal_set.ok_or(Error::Unavailable)?;
    let seals = committed_seals(metadata, base, signed.event_id, &payload, bytes)?;
    Ok(Some((payload.key_id, seals)))
}

/// What a device keeps while it waits for a rekey's seal set: the control's
/// event id, the new key's id, the seal count and the set's commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealSetRef {
    pub event_id: EventId,
    pub key_id: [u8; 32],
    pub count: u16,
    pub commitment: Digest,
}
impl SealSetRef {
    /// The seals in `bytes`, only if they are exactly the set this rekey
    /// committed to, sealed for `base`, its control and its key.
    pub fn open(
        &self,
        metadata: &Secret<32>,
        base: BaseId,
        bytes: &[u8],
    ) -> Result<Vec<Vec<u8>>, Error> {
        let payload = RekeyPayload {
            rotation: &[],
            confirmation: &[],
            key_id: self.key_id,
            count: self.count,
            seal_set: self.commitment,
        };
        committed_seals(metadata, base, self.event_id, &payload, bytes)
    }
}

/// The seal set an accepted `ACCOUNT_REKEY` of `base` names, read from its
/// exact descriptor and body; `Ok(None)` for any other control. Its verdict
/// is the caller's: this reads, it does not judge.
pub fn rekey_seal_set(
    base: BaseId,
    descriptor: &OpaqueEvent,
    body: &[u8],
    metadata: &Secret<32>,
) -> Result<Option<SealSetRef>, Error> {
    let signed = open_binding(descriptor, metadata, base.0, false)?.binding;
    if signed.mode != MODE_ORDINARY || signed.class != CLASS_CONTROL {
        return Ok(None);
    }
    let opened = open_body(&signed, body, metadata, None)?;
    if opened.kind != ACCOUNT_REKEY {
        return Ok(None);
    }
    let payload = decode_payload(opened.data())?;
    Ok(Some(SealSetRef {
        event_id: signed.event_id,
        key_id: payload.key_id,
        count: payload.count,
        commitment: payload.seal_set,
    }))
}

/// The seals in `bytes`, only if they are exactly the set `payload` commits
/// to, sealed for this base, control and key.
fn committed_seals(
    metadata: &Secret<32>,
    base: BaseId,
    event_id: EventId,
    payload: &RekeyPayload<'_>,
    bytes: &[u8],
) -> Result<Vec<Vec<u8>>, Error> {
    let object = BodyObject::new(bytes.to_vec()).map_err(|_| Error::Invalid)?;
    if object.commitment() != payload.seal_set {
        return Err(Error::Invalid);
    }
    open_seal_set(
        metadata,
        base,
        event_id,
        &payload.key_id,
        payload.count,
        bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(key_id: [u8; 32], set: &BodyObject) -> RekeyPayload<'static> {
        RekeyPayload {
            rotation: &[],
            confirmation: &[],
            key_id,
            count: 2,
            seal_set: set.commitment(),
        }
    }

    #[test]
    fn seal_set_bound_to_its_base_event_and_key() {
        let metadata = Secret::<32>::random();
        let (base, event, key) = (BaseId([1; 32]), EventId([2; 32]), [3; 32]);
        let seals = vec![vec![7; 1499], vec![8; 1499]];
        let set = seal_set(&metadata, base, event, &key, &seals).unwrap();
        assert_eq!(
            committed_seals(&metadata, base, event, &payload(key, &set), set.bytes()),
            Ok(seals.clone())
        );
        // The same bytes named by another base, control or key, each
        // committing to them, are refused.
        for (base, event, key) in [
            (BaseId([9; 32]), event, key),
            (base, EventId([9; 32]), key),
            (base, event, [9; 32]),
        ] {
            assert_eq!(
                committed_seals(&metadata, base, event, &payload(key, &set), set.bytes()),
                Err(Error::Invalid)
            );
        }
        // Under another metadata key, or for another count.
        assert_eq!(
            committed_seals(
                &Secret::random(),
                base,
                event,
                &payload(key, &set),
                set.bytes()
            ),
            Err(Error::Invalid)
        );
        let mut one = payload(key, &set);
        one.count = 1;
        assert_eq!(
            committed_seals(&metadata, base, event, &one, set.bytes()),
            Err(Error::Invalid)
        );
        // Another set sealed for exactly this binding is not the committed one.
        let other = seal_set(
            &metadata,
            base,
            event,
            &key,
            &[vec![9; 1499], vec![9; 1499]],
        )
        .unwrap();
        assert_eq!(
            committed_seals(&metadata, base, event, &payload(key, &set), other.bytes()),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn a_kept_reference_opens_only_its_committed_set() {
        let metadata = Secret::<32>::random();
        let (base, event, key) = (BaseId([1; 32]), EventId([2; 32]), [3; 32]);
        let seals = vec![vec![7; 1499], vec![8; 1499]];
        let set = seal_set(&metadata, base, event, &key, &seals).unwrap();
        let kept = SealSetRef {
            event_id: event,
            key_id: key,
            count: 2,
            commitment: set.commitment(),
        };
        assert_eq!(kept.open(&metadata, base, set.bytes()), Ok(seals));
        let other = seal_set(
            &metadata,
            base,
            event,
            &key,
            &[vec![9; 1499], vec![9; 1499]],
        )
        .unwrap();
        assert_eq!(
            kept.open(&metadata, base, other.bytes()),
            Err(Error::Invalid)
        );
        assert_eq!(
            kept.open(&metadata, BaseId([9; 32]), set.bytes()),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn seal_set_takes_the_smallest_body_that_fits() {
        let metadata = Secret::<32>::random();
        let set = |count| {
            seal_set(
                &metadata,
                BaseId([1; 32]),
                EventId([2; 32]),
                &[3; 32],
                &vec![vec![0; 1499]; count],
            )
        };
        assert_eq!(set(2).unwrap().bytes().len(), 4096);
        assert_eq!(set(0).err(), Some(Error::Invalid));
        // The named limit: one 4 MiB object.
        let most = (BODY_SIZES[BODY_SIZES.len() - 1] - SEAL_SET_OVERHEAD - 2) / (4 + 1499);
        assert!(set(most).is_ok());
        assert_eq!(set(most + 1).err(), Some(Error::Invalid));
    }
}
