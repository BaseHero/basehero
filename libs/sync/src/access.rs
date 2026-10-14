//! Exact operation approvals and a pure consumption planner.
//!
//! This is not the account-authority checker. Only its authenticated signing
//! boundary may issue approvals, after serializing authority changes with access.
//! Storage adapters must atomically compare the complete input state, apply the
//! plan and durably commit before releasing bytes or an acknowledgement.

use crate::log::{BodyObject, Input, hash, referenced_body};
use crate::{BaseId, Commitment, Digest, Error, Head, OpaqueEvent, VERSION};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccessError {
    Signature,
    Stale,
    Operation,
    Time,
    Selection,
    ReplayConflict,
    History,
    Exhausted,
    Unavailable,
    Uncertain,
    /// The descriptor's referenced detached body is not durably staged.
    Body,
}

/// A read names exact immutable ciphertext commitments, not an audience handle.
/// The checker must verify authority for every selected object, not merely base
/// membership. The common-header range transport is outside this module.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Operation {
    Append(OpaqueEvent),
    Read(ReadSelection),
    /// Stage one immutable padded body by the commitment the kernel derives from
    /// its bytes. Repeating the exact bytes is idempotent in the adapter.
    StageBody(BodyObject),
    /// Read 1-64 exact immutable body commitments. This never reuses the event
    /// read approval domain.
    ReadBodies(BodySelection),
}
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReadSelection(Vec<Digest>);
impl ReadSelection {
    pub fn objects(&self) -> &[Digest] {
        &self.0
    }
}
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BodySelection(Vec<Digest>);
impl BodySelection {
    pub fn objects(&self) -> &[Digest] {
        &self.0
    }
}
fn validate_selection(objects: &[Digest]) -> Result<(), AccessError> {
    if objects.is_empty()
        || objects.len() > 64
        || objects
            .iter()
            .enumerate()
            .any(|(i, value)| objects[..i].contains(value))
    {
        return Err(AccessError::Selection);
    }
    Ok(())
}
fn read_bytes(objects: &[Digest]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + objects.len() * 32);
    bytes.extend((objects.len() as u16).to_be_bytes());
    for object in objects {
        bytes.extend(object.0);
    }
    bytes
}
impl Operation {
    pub fn read(objects: Vec<Digest>) -> Result<Self, AccessError> {
        validate_selection(&objects)?;
        Ok(Self::Read(ReadSelection(objects)))
    }
    pub fn stage_body(body: BodyObject) -> Self {
        Self::StageBody(body)
    }
    pub fn read_bodies(objects: Vec<Digest>) -> Result<Self, AccessError> {
        validate_selection(&objects)?;
        Ok(Self::ReadBodies(BodySelection(objects)))
    }
    pub fn digest(&self) -> Digest {
        match self {
            Self::Append(event) => hash(b"bh/append/v1\0", &[&event.digest().0]),
            Self::Read(selection) => hash(b"bh/read/v1\0", &[&read_bytes(&selection.0)]),
            Self::StageBody(body) => hash(b"bh/body-stage/v1\0", &[&body.commitment().0]),
            Self::ReadBodies(selection) => hash(b"bh/body-read/v1\0", &[&read_bytes(&selection.0)]),
        }
    }
}

/// Ordinary storage fields: no account/device/audience or authority-head handle.
/// `sequence` counts access operations, NOT common-log events. Read operations
/// must also consume it, so replay protection does not require a nonce ledger.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Approval {
    pub base: BaseId,
    pub expected_head: Head,
    pub incarnation: [u8; 32],
    pub sequence: u64,
    pub nonce: [u8; 32],
    pub operation: Digest,
    /// Commitment to the fresh response channel/key, never a device identity.
    pub response_binding: Digest,
    pub not_before: u64,
    pub expires: u64,
}
const APPROVAL_DOMAIN: &[u8] = b"bh/access-approval/v1\0";
impl Approval {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = APPROVAL_DOMAIN.to_vec();
        bytes.extend(self.encode());
        bytes
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(VERSION.to_be_bytes());
        bytes.extend(self.base.0);
        bytes.extend(self.expected_head.position.to_be_bytes());
        bytes.extend(self.expected_head.hash.0);
        bytes.extend(self.incarnation);
        bytes.extend(self.sequence.to_be_bytes());
        bytes.extend(self.nonce);
        bytes.extend(self.operation.0);
        bytes.extend(self.response_binding.0);
        bytes.extend(self.not_before.to_be_bytes());
        bytes.extend(self.expires.to_be_bytes());
        bytes
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignedApproval {
    pub approval: Approval,
    pub signature: [u8; 64],
}
impl SignedApproval {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.approval.encode();
        bytes.extend(self.signature);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut input = Input(bytes);
        input.version()?;
        let result = Self {
            approval: Approval {
                base: BaseId(input.array()?),
                expected_head: Head {
                    position: u64::from_be_bytes(input.array()?),
                    hash: Digest(input.array()?),
                },
                incarnation: input.array()?,
                sequence: u64::from_be_bytes(input.array()?),
                nonce: input.array()?,
                operation: Digest(input.array()?),
                response_binding: Digest(input.array()?),
                not_before: u64::from_be_bytes(input.array()?),
                expires: u64::from_be_bytes(input.array()?),
            },
            signature: input.array()?,
        };
        if !input.0.is_empty() {
            return Err(Error::Encoding);
        }
        Ok(result)
    }
    fn check(&self, state: &GateState) -> Result<(), AccessError> {
        bh_crypto::verify(
            &state.checker_key,
            &self.approval.signing_bytes(),
            &self.signature,
        )
        .map_err(|_| AccessError::Signature)?;
        let a = self.approval;
        if a.base != state.base
            || a.expected_head != state.head
            || a.incarnation != state.incarnation
            || Some(a.sequence) != state.sequence.checked_add(1)
        {
            return Err(AccessError::Stale);
        }
        Ok(())
    }
}

/// Persisted by the storage adapter. Restoring this from disk does NOT establish
/// freshness; the host must reconcile with the live protected execution lane.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GateState {
    pub base: BaseId,
    pub head: Head,
    pub incarnation: [u8; 32],
    pub sequence: u64,
    pub checker_key: [u8; 32],
}
/// Conservative bounds from the host's trusted clock, never the request.
/// Both endpoints must fall inside the approval's validity interval. The checker
/// must cap expires at the earliest possible pending authority effect.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TimeWindow {
    pub earliest: u64,
    pub latest: u64,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Consumption {
    pub next: GateState,
    /// New log row, absent for read or exact replay.
    pub append: Option<Commitment>,
    /// Original row on exact replay; never a newly assigned position.
    pub ack: Option<Commitment>,
    /// New immutable body to persist, keyed by its kernel-derived commitment.
    /// Absent for every operation except a fresh body stage.
    pub stage: Option<Digest>,
}

/// Pure, side-effect-free check. `existing` must come from the adapter's committed
/// replay index for this event id, not from the request. `staged_body` must be the
/// commitment the adapter found under the descriptor's referenced body, not a
/// caller assertion. The adapter owns index integrity and availability; a missing
/// archival lookup is NOT evidence of absence.
/// Every retry needs current authorization, including retrieval of a lost Ack.
pub fn plan_consumption(
    state: &GateState,
    signed: &SignedApproval,
    operation: &Operation,
    time: TimeWindow,
    existing: Option<Commitment>,
    staged_body: Option<Digest>,
    response_binding: Digest,
) -> Result<Consumption, AccessError> {
    signed.check(state)?;
    let approval = signed.approval;
    if approval.operation != operation.digest() || approval.response_binding != response_binding {
        return Err(AccessError::Operation);
    }
    if time.earliest > time.latest
        || approval.not_before > time.earliest
        || time.latest >= approval.expires
    {
        return Err(AccessError::Time);
    }
    let mut next = *state;
    next.sequence = next.sequence.checked_add(1).ok_or(AccessError::Exhausted)?;
    match operation {
        Operation::Read(_) | Operation::ReadBodies(_) => {
            if existing.is_some() {
                return Err(AccessError::ReplayConflict);
            }
            Ok(Consumption {
                next,
                append: None,
                ack: None,
                stage: None,
            })
        }
        Operation::StageBody(body) => Ok(Consumption {
            next,
            append: None,
            ack: None,
            stage: Some(body.commitment()),
        }),
        Operation::Append(event) => {
            // A committed descriptor must never dangle: fail closed unless the
            // adapter found exactly the body the first 32 envelope bytes name.
            let referenced = referenced_body(event).map_err(|_| AccessError::Operation)?;
            if staged_body != Some(referenced) {
                return Err(AccessError::Body);
            }
            if let Some(original) = existing {
                if original.base() != state.base
                    || original.head().position == 0
                    || original.head().position > state.head.position
                    || (original.head().position == state.head.position
                        && original.head() != state.head)
                    || original.verify_integrity().is_err()
                    || original.verify_body(event).is_err()
                {
                    return Err(AccessError::ReplayConflict);
                }
                return Ok(Consumption {
                    next,
                    append: None,
                    ack: Some(original),
                    stage: None,
                });
            }
            let committed = Commitment::order(state.base, state.head, event)
                .map_err(|_| AccessError::History)?;
            next.head = committed.head();
            Ok(Consumption {
                next,
                append: Some(committed),
                ack: Some(committed),
                stage: None,
            })
        }
    }
}

/// One protected execution lane's local bookkeeping, not a distributed lock.
/// The hosting adapter must durably record Pending BEFORE releasing an approval,
/// serialize account mutations through this lane too, and verify all receipts.
/// Cold restart creates Unavailable; there is deliberately no decode-from-disk
/// shortcut and no timeout/abort method that silently forgets an outstanding grant.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExecutionLane {
    state: Option<GateState>,
    pending: Option<SignedApproval>,
}
impl ExecutionLane {
    pub fn unavailable() -> Self {
        Self {
            state: None,
            pending: None,
        }
    }
    /// Host integration boundary: only after current authority and storage state
    /// have been established, not from an arbitrary signed historical snapshot.
    pub fn establish(&mut self, state: GateState) -> Result<(), AccessError> {
        if self.state.is_some() {
            return Err(AccessError::Uncertain);
        }
        self.state = Some(state);
        Ok(())
    }
    pub fn begin(&mut self, approval: SignedApproval) -> Result<(), AccessError> {
        let state = self.state.ok_or(AccessError::Unavailable)?;
        if self.pending.is_some() {
            return Err(AccessError::Uncertain);
        }
        approval.check(&state)?;
        self.pending = Some(approval);
        Ok(())
    }
    /// Complete only after the adapter authenticates an exact durable receipt.
    /// This method checks binding/continuity, not the receipt's transport proof.
    pub fn committed(
        &mut self,
        approval: SignedApproval,
        next: GateState,
    ) -> Result<(), AccessError> {
        let before = self.state.ok_or(AccessError::Unavailable)?;
        let pending = self.pending.ok_or(AccessError::Uncertain)?;
        if pending != approval
            || next.base != before.base
            || next.incarnation != before.incarnation
            || next.checker_key != before.checker_key
            || next.sequence != pending.approval.sequence
            || !(next.head == before.head
                || before.head.position.checked_add(1) == Some(next.head.position))
        {
            return Err(AccessError::Uncertain);
        }
        self.state = Some(next);
        self.pending = None;
        Ok(())
    }
    /// An unresolved operation can be abandoned only after storage DURABLY fences
    /// the old incarnation. Host must verify that fact and reconstruct current
    /// authority first. Fresh random incarnation alone is not a freshness proof.
    pub fn fence(&mut self, recovered: GateState) -> Result<(), AccessError> {
        let before = self.state.ok_or(AccessError::Unavailable)?;
        if recovered.base != before.base
            || recovered.incarnation == before.incarnation
            || recovered.sequence < before.sequence
            || recovered.head.position < before.head.position
            || (recovered.head.position == before.head.position && recovered.head != before.head)
        {
            return Err(AccessError::Stale);
        }
        self.state = Some(recovered);
        self.pending = None;
        Ok(())
    }
}
