use crate::codec::{
    ACCOUNT_CHANGE, Binding, CLASS_CONTENT, CLASS_CONTROL, Error, GENESIS, NOTE, OpenPayload,
    apply_note, key_id, open_binding, open_body,
};
use bh_account::{
    AccountEvent, AccountId, Error as AccountError, Head as AccountHead, VerifiedAccount,
};
use bh_core::note::{Note, NoteError};
use bh_crypto::{Secret, SecretBytes, verify};
use bh_sync::{BaseId, Commitment, Digest, Head, OpaqueEvent, referenced_body};
use std::{collections::BTreeMap, sync::Arc};

/// These results establish only historical verification, never a currently
/// authorised service operation. A caller must stop after `IntegrityStop`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Accepted,
    ContentRejected,
    IntegrityStop,
    UnsupportedPause,
    UnavailablePause,
}
/// Selected Note, checked against the authenticated ID before writing. The
/// compatibility `apply` API still stops on an externally guessed wrong target.
pub struct NoteTarget<'a> {
    pub id: [u8; 32],
    pub note: &'a mut Note,
}

/// Transfer exclusive ownership of a working Note from the store. Do not keep
/// another canonical alias while it is outside the committed projection.
pub struct OwnedNoteTarget {
    pub id: [u8; 32],
    pub note: Note,
}

/// A working Note is not a UI publication gate: the store decides when to
/// expose accepted state. Decode fails before yrs opens a transaction; Apply
/// can leave a partially changed Doc, which is discarded here.
pub enum WorkingNote {
    Accepted(Note),
    Untouched(Note),
    Poisoned,
}

pub struct Materialized {
    pub transition: Transition,
    pub note: Option<WorkingNote>,
}

pub struct MaterializeError {
    pub reason: ConsumeError,
    pub target: Option<OwnedNoteTarget>,
}
impl std::fmt::Debug for MaterializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaterializeError")
            .field("reason", &self.reason)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishError {
    StaleState,
}

/// Bounded verifier effects, not a whole-History candidate. Nothing in this
/// value becomes visible in History until the owner publishes this transition.
pub struct Transition {
    before: Prestate,
    event_id: [u8; 32],
    digest: Digest,
    seen: Seen,
    account: Option<Arc<VerifiedAccount>>,
    metadata_id: Option<[u8; 32]>,
    epoch_id: Option<[u8; 32]>,
    applied: AppliedEvent,
}
impl Transition {
    pub fn applied(&self) -> &AppliedEvent {
        &self.applied
    }
}

/// A local selection/state race, not evidence of malicious remote history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumeError {
    StaleState,
    WrongTarget,
}

// No public constructor or deserializer: only prepare() can produce this owned
// authenticated event. Note plaintext remains guarded in OpenPayload.
pub struct PreparedEvent {
    before: Prestate,
    ordered: Commitment,
    descriptor: Vec<u8>,
    body: Vec<u8>,
    body_commitment: Digest,
    head: Head,
    digest: Digest,
    event_id: [u8; 32],
    version: u16,
    kind: PreparedKind,
}
impl PreparedEvent {
    /// Only supported note events have a target. Controls return None.
    pub fn note_id(&self) -> Option<[u8; 32]> {
        match &self.kind {
            PreparedKind::Note { id, .. } => Some(*id),
            PreparedKind::Control { .. } => None,
        }
    }
}
/// An authenticated, consumed event. Its private construction binds all bytes
/// required by a store to the same verification and history transition. Neither
/// this value nor its kind implements serialization or cloning.
pub struct AppliedEvent {
    ordered: Commitment,
    ordered_bytes: Vec<u8>,
    descriptor: Vec<u8>,
    body: Vec<u8>,
    body_commitment: Digest,
    kind: AppliedKind,
    head: Head,
    floor: u16,
}
/// Only an accepted note exposes an applied delta. A rejected content event
/// advances the common history but must not change the Note.
pub enum AppliedKind {
    NoteAccepted {
        note_id: [u8; 32],
        delta: SecretBytes,
    },
    NoteRejected {
        note_id: [u8; 32],
    },
    Control,
}
impl std::fmt::Debug for AppliedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppliedEvent")
            .field("head", &self.head)
            .field("floor", &self.floor)
            .field("kind", &self.outcome())
            .finish_non_exhaustive()
    }
}
impl AppliedEvent {
    pub fn commitment(&self) -> Commitment {
        self.ordered
    }
    pub fn commitment_bytes(&self) -> &[u8] {
        &self.ordered_bytes
    }
    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.descriptor
    }
    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }
    pub fn body_commitment(&self) -> Digest {
        self.body_commitment
    }
    pub fn kind(&self) -> &AppliedKind {
        &self.kind
    }
    pub fn outcome(&self) -> Outcome {
        match self.kind {
            AppliedKind::NoteRejected { .. } => Outcome::ContentRejected,
            _ => Outcome::Accepted,
        }
    }
    pub fn head(&self) -> Head {
        self.head
    }
    pub fn floor(&self) -> u16 {
        self.floor
    }
}
enum PreparedKind {
    Note {
        id: [u8; 32],
        payload: OpenPayload,
    },
    Control {
        account: Arc<VerifiedAccount>,
        metadata_id: Option<[u8; 32]>,
        epoch_id: Option<[u8; 32]>,
    },
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Prestate {
    base: BaseId,
    head: Head,
    control: [u8; 32],
    account: AccountHead,
    metadata_id: Option<[u8; 32]>,
    epoch_id: Option<[u8; 32]>,
    floor: u16,
    entries: usize,
    ids: usize,
    stopped: bool,
}

#[derive(Clone)]
struct Seen {
    head: Head,
    control: [u8; 32],
    account: AccountHead,
}

/// In-memory candidate. The device store must atomically persist exact originals,
/// accepted deltas or rejection, and verified progress; this type is not durable authority.
#[derive(Clone)]
pub struct History {
    base: BaseId,
    // Notes and transactional clones share this immutable verified snapshot.
    // An account-changing control prepares a separate owned successor.
    account: Arc<VerifiedAccount>,
    entries: Vec<Seen>,
    ids: BTreeMap<[u8; 32], Digest>,
    metadata_id: Option<[u8; 32]>,
    epoch_id: Option<[u8; 32]>,
    floor: u16,
    stopped: bool,
}
impl History {
    /// `base` and `account_id` must come from local creation or an independent
    /// introduction, never from the untrusted log being checked.
    pub fn new(
        account_id: AccountId,
        account_genesis: &[u8],
        base: BaseId,
        remembered_floor: u16,
    ) -> Result<Self, Error> {
        let account = VerifiedAccount::from_genesis(account_id, account_genesis)
            .map_err(|_| Error::Invalid)?;
        Self::with_account(&account, base, remembered_floor)
    }
    /// Start at the creator's independently verified account head named by a
    /// base genesis, including heads after account setup or device changes.
    pub fn with_account(
        account: &VerifiedAccount,
        base: BaseId,
        remembered_floor: u16,
    ) -> Result<Self, Error> {
        if remembered_floor == 0 || account.is_stopped() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            base,
            account: Arc::new(account.clone()),
            entries: vec![],
            ids: BTreeMap::new(),
            metadata_id: None,
            epoch_id: None,
            floor: remembered_floor,
            stopped: false,
        })
    }
    pub fn head(&self) -> Head {
        self.entries.last().map_or(Head::EMPTY, |s| s.head)
    }
    pub fn floor(&self) -> u16 {
        self.floor
    }
    pub fn metadata_id(&self) -> Option<[u8; 32]> {
        self.metadata_id
    }
    pub fn epoch_id(&self) -> Option<[u8; 32]> {
        self.epoch_id
    }
    /// Restore a durable integrity stop after replaying the unchanged verified
    /// prefix. This never accepts an unverified head or lifts an existing stop.
    pub fn mark_stopped(&mut self) {
        self.stopped = true;
    }
    /// Rebuild only the verified history, not Note projections, from independently
    /// anchored introductions/roots and exact stored originals in log order.
    /// Malformed framing or any verification failure refuses the entire replay.
    pub fn replay<I, D, B>(
        account_id: AccountId,
        account_genesis: &[u8],
        base: BaseId,
        remembered_floor: u16,
        metadata: &Secret<32>,
        content: Option<&Secret<32>>,
        records: I,
    ) -> Result<Self, Outcome>
    where
        I: IntoIterator<Item = (Commitment, D, B)>,
        D: AsRef<[u8]>,
        B: AsRef<[u8]>,
    {
        let account = VerifiedAccount::from_genesis(account_id, account_genesis)
            .map_err(|_| Outcome::IntegrityStop)?;
        Self::replay_with_account(&account, base, remembered_floor, metadata, content, records)
    }
    /// Replay originals anchored to the creator's verified account projection
    /// at the genesis head; later account changes arrive in the base log.
    pub fn replay_with_account<I, D, B>(
        account: &VerifiedAccount,
        base: BaseId,
        remembered_floor: u16,
        metadata: &Secret<32>,
        content: Option<&Secret<32>>,
        records: I,
    ) -> Result<Self, Outcome>
    where
        I: IntoIterator<Item = (Commitment, D, B)>,
        D: AsRef<[u8]>,
        B: AsRef<[u8]>,
    {
        let mut history = Self::with_account(account, base, remembered_floor)
            .map_err(|_| Outcome::IntegrityStop)?;
        for (ordered, descriptor, body) in records {
            let descriptor =
                OpaqueEvent::decode(descriptor.as_ref()).map_err(|_| Outcome::IntegrityStop)?;
            let prepared = history.prepare(
                &ordered,
                &descriptor,
                Some(body.as_ref()),
                metadata,
                content,
            )?;
            // Prepare has authenticated the same original and body as live
            // consumption. No Yjs application or projection state is needed to
            // advance the common chain, account controls or version floor.
            history.advance(&prepared);
        }
        Ok(history)
    }
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }
    pub fn account_head(&self) -> AccountHead {
        self.account.head()
    }
    fn prestate(&self) -> Prestate {
        Prestate {
            base: self.base,
            head: self.head(),
            control: self.entries.last().map_or([0; 32], |s| s.control),
            account: self.account.head(),
            metadata_id: self.metadata_id,
            epoch_id: self.epoch_id,
            floor: self.floor,
            entries: self.entries.len(),
            ids: self.ids.len(),
            stopped: self.stopped,
        }
    }

    /// Verify descriptor, original signature, author-seen heads and account
    /// authority without fetching/opening a note body. This does not advance.
    pub fn inspect(
        &self,
        ordered: &Commitment,
        event: &OpaqueEvent,
        metadata: &Secret<32>,
    ) -> Result<Binding, Outcome> {
        if self.stopped {
            return Err(Outcome::IntegrityStop);
        }
        let genesis = self.entries.is_empty();
        if ordered.verify_next(self.base, self.head()).is_err()
            || ordered.verify_body(event).is_err()
            || self.ids.contains_key(&event.id().0)
        {
            return Err(Outcome::IntegrityStop);
        }
        let (signed, signature) = match open_binding(
            event,
            metadata,
            if genesis { [0; 32] } else { self.base.0 },
            genesis,
        ) {
            Ok(v) => v,
            Err(Error::Unsupported) => return Err(Outcome::UnsupportedPause),
            Err(Error::Unavailable) => return Err(Outcome::UnavailablePause),
            Err(Error::Invalid) => return Err(Outcome::IntegrityStop),
        };
        if signed.audience != [0; 32] || signed.account != self.account.id() {
            return Err(Outcome::IntegrityStop);
        }
        // AEAD success alone cannot authenticate a substituted metadata root.
        // Genesis introduces M; every later original, including content, must
        // use precisely that committed root. S's epoch remains class-specific.
        let metadata_key_id = key_id(metadata);
        if !genesis && self.metadata_id != Some(metadata_key_id) {
            return Err(Outcome::IntegrityStop);
        }
        if !genesis && signed.class == CLASS_CONTENT && Some(signed.epoch) != self.epoch_id {
            return Err(Outcome::IntegrityStop);
        }
        if signed.class == CLASS_CONTROL && signed.epoch != metadata_key_id {
            return Err(Outcome::IntegrityStop);
        }
        if genesis {
            if signed.class != CLASS_CONTROL
                || signed.seen != Head::EMPTY
                || signed.seen_control != [0; 32]
                || signed.account_head != self.account.head()
            {
                return Err(Outcome::IntegrityStop);
            }
        } else {
            if signed.seen.position == 0 {
                return Err(Outcome::IntegrityStop);
            }
            let Ok(index) = usize::try_from(signed.seen.position - 1) else {
                return Err(Outcome::IntegrityStop);
            };
            let Some(seen) = self.entries.get(index) else {
                return Err(Outcome::IntegrityStop);
            };
            if seen.head != signed.seen
                || seen.control != signed.seen_control
                || seen.account != signed.account_head
            {
                return Err(Outcome::IntegrityStop);
            }
            if signed.class == CLASS_CONTROL
                && signed.seen_control != self.entries.last().expect("nonempty history").control
            {
                return Err(Outcome::IntegrityStop);
            }
        }
        let device = match self.account.active_device(signed.device) {
            Ok(v) => v,
            Err(_) => return Err(Outcome::IntegrityStop),
        };
        let key = if genesis || signed.class == CLASS_CONTENT {
            device.signing()
        } else {
            device.control()
        };
        let mut signed_bytes = b"bh/original-envelope/v1\0".to_vec();
        signed_bytes.extend(signed.encode_for_verify());
        if verify(key, &signed_bytes, &signature).is_err()
            || signed.highest < signed.version
            || signed.version < self.floor
        {
            return Err(Outcome::IntegrityStop);
        }
        if signed.version != 1 {
            return Err(Outcome::UnsupportedPause);
        }
        Ok(signed)
    }

    /// Fully verify one ordered original and body without advancing the
    /// checkpoint or modifying a Note. Invalid history latches an integrity
    /// stop; missing input and unsupported semantics do not. This grants no
    /// current/unlock authority.
    pub fn prepare(
        &mut self,
        ordered: &Commitment,
        event: &OpaqueEvent,
        body: Option<&[u8]>,
        metadata: &Secret<32>,
        content: Option<&Secret<32>>,
    ) -> Result<PreparedEvent, Outcome> {
        let result = self.prepare_checked(ordered, event, body, metadata, content);
        if matches!(result, Err(Outcome::IntegrityStop)) {
            self.stopped = true;
        }
        result
    }

    fn prepare_checked(
        &self,
        ordered: &Commitment,
        event: &OpaqueEvent,
        body: Option<&[u8]>,
        metadata: &Secret<32>,
        content: Option<&Secret<32>>,
    ) -> Result<PreparedEvent, Outcome> {
        let signed = self.inspect(ordered, event, metadata)?;
        let body = body.ok_or(Outcome::UnavailablePause)?;
        if signed.class == CLASS_CONTENT && content.is_some_and(|root| key_id(root) != signed.epoch)
        {
            return Err(Outcome::IntegrityStop);
        }
        let payload = open_body(&signed, body, metadata, content).map_err(|e| match e {
            Error::Unavailable => Outcome::UnavailablePause,
            Error::Unsupported => Outcome::UnsupportedPause,
            Error::Invalid => Outcome::IntegrityStop,
        })?;
        let mut next_account = None;
        let mut next_metadata = self.metadata_id;
        let mut next_epoch = self.epoch_id;
        match (signed.class, payload.kind) {
            (CLASS_CONTROL, GENESIS) if self.entries.is_empty() => {
                let data = payload.data();
                if data.len() != 168
                    || data[..32] != signed.account.0
                    || data[32..40] != signed.account_head.position.to_be_bytes()
                    || data[40..72] != signed.account_head.hash
                    || data[72..104] != [0; 32]
                    || data[136..168] != signed.epoch
                {
                    return Err(Outcome::IntegrityStop);
                }
                next_metadata = Some(signed.epoch);
                next_epoch = Some(data[104..136].try_into().expect("length checked"));
            }
            (CLASS_CONTROL, ACCOUNT_CHANGE) if !self.entries.is_empty() => {
                let data = payload.data();
                // Independent allowlist; expanding the account parser cannot make
                // private recovery/seal records forwardable under metadata M.
                const TAG: usize = b"BaseHero account event\0".len() + 2 + 2 + 8 + 32 + 32 + 32;
                let Some(tag) = data.get(TAG) else {
                    return Err(Outcome::IntegrityStop);
                };
                if !matches!(tag, 1 | 2) {
                    return Err(Outcome::UnsupportedPause);
                }
                let parsed = match AccountEvent::decode(data) {
                    Ok(event) => event,
                    Err(AccountError::UnsupportedVersion | AccountError::UnsupportedControl) => {
                        return Err(Outcome::UnsupportedPause);
                    }
                    Err(_) => return Err(Outcome::IntegrityStop),
                };
                if signed.account_head != self.account.head() {
                    return Err(Outcome::IntegrityStop);
                }
                // Only a control that changes account authority needs an owned
                // candidate; note verification and genesis share the snapshot.
                let mut account = Arc::clone(&self.account);
                match Arc::make_mut(&mut account).apply(parsed.as_bytes()) {
                    Ok(()) => next_account = Some(account),
                    Err(AccountError::UnsupportedVersion | AccountError::UnsupportedControl) => {
                        return Err(Outcome::UnsupportedPause);
                    }
                    Err(_) => return Err(Outcome::IntegrityStop),
                }
                if data[TAG] == 2 {
                    next_epoch = None;
                }
            }
            (CLASS_CONTENT, NOTE) if !self.entries.is_empty() => {
                let data = payload.data();
                let id: [u8; 32] = data
                    .get(..32)
                    .ok_or(Outcome::IntegrityStop)?
                    .try_into()
                    .expect("length checked");
                return Ok(PreparedEvent {
                    before: self.prestate(),
                    ordered: *ordered,
                    descriptor: event.encode(),
                    body: body.to_vec(),
                    body_commitment: referenced_body(event).expect("inspected descriptor"),
                    head: ordered.head(),
                    digest: ordered.event_digest(),
                    event_id: event.id().0,
                    version: signed.version,
                    kind: PreparedKind::Note { id, payload },
                });
            }
            (CLASS_CONTROL, GENESIS)
            | (CLASS_CONTENT, GENESIS | ACCOUNT_CHANGE)
            | (CLASS_CONTROL, NOTE) => return Err(Outcome::IntegrityStop),
            _ => return Err(Outcome::UnsupportedPause),
        }
        Ok(PreparedEvent {
            before: self.prestate(),
            ordered: *ordered,
            descriptor: event.encode(),
            body: body.to_vec(),
            body_commitment: referenced_body(event).expect("inspected descriptor"),
            head: ordered.head(),
            digest: ordered.event_digest(),
            event_id: event.id().0,
            version: signed.version,
            kind: PreparedKind::Control {
                account: next_account.unwrap_or_else(|| Arc::clone(&self.account)),
                metadata_id: next_metadata,
                epoch_id: next_epoch,
            },
        })
    }

    /// Prepare an owned Note and bounded transition without changing live
    /// History. A rejected Decode returns the identical untouched Note; Apply
    /// errors discard the working Note and require reconstruction from committed
    /// local state. On selection failure the working Note is returned in the error.
    pub fn materialize(
        &self,
        prepared: PreparedEvent,
        target: Option<OwnedNoteTarget>,
    ) -> Result<Materialized, MaterializeError> {
        if self.prestate() != prepared.before || self.stopped {
            return Err(MaterializeError {
                reason: ConsumeError::StaleState,
                target,
            });
        }
        if matches!(&prepared.kind, PreparedKind::Control { .. }) != target.is_none()
            || target
                .as_ref()
                .is_some_and(|t| Some(t.id) != prepared.note_id())
        {
            return Err(MaterializeError {
                reason: ConsumeError::WrongTarget,
                target,
            });
        }
        let (kind, note) = match &prepared.kind {
            PreparedKind::Control { .. } => (AppliedKind::Control, None),
            PreparedKind::Note { id, payload } => {
                let mut note = target.expect("target checked").note;
                let delta = &payload.data()[32..];
                match note.apply_update(delta) {
                    Ok(()) => (
                        AppliedKind::NoteAccepted {
                            note_id: *id,
                            delta: SecretBytes::from_vec(delta.to_vec()),
                        },
                        Some(WorkingNote::Accepted(note)),
                    ),
                    Err(NoteError::Decode(_)) => (
                        AppliedKind::NoteRejected { note_id: *id },
                        Some(WorkingNote::Untouched(note)),
                    ),
                    Err(NoteError::Apply(_)) => {
                        drop(note);
                        (
                            AppliedKind::NoteRejected { note_id: *id },
                            Some(WorkingNote::Poisoned),
                        )
                    }
                }
            }
        };
        let (account, metadata_id, epoch_id, control) = match &prepared.kind {
            PreparedKind::Control {
                account,
                metadata_id,
                epoch_id,
            } => (
                Some(Arc::clone(account)),
                *metadata_id,
                *epoch_id,
                prepared.digest.0,
            ),
            PreparedKind::Note { .. } => (
                None,
                self.metadata_id,
                self.epoch_id,
                prepared.before.control,
            ),
        };
        let seen = Seen {
            head: prepared.head,
            control,
            account: account
                .as_ref()
                .map_or_else(|| self.account.head(), |a| a.head()),
        };
        let applied = AppliedEvent {
            ordered: prepared.ordered,
            ordered_bytes: prepared.ordered.encode(),
            descriptor: prepared.descriptor,
            body: prepared.body,
            body_commitment: prepared.body_commitment,
            kind,
            head: prepared.head,
            floor: self.floor.max(prepared.version),
        };
        Ok(Materialized {
            transition: Transition {
                before: prepared.before,
                event_id: prepared.event_id,
                digest: prepared.digest,
                seen,
                account,
                metadata_id,
                epoch_id,
                applied,
            },
            note,
        })
    }

    /// The trusted store owner calls this only after COMMIT of this transition's
    /// exact originals, outcome and progress, and its own revision/unlock checks.
    /// A failed COMMIT drops the transition and working Note instead. This method
    /// checks in-memory prestate and stop, not whether SQLite actually committed.
    pub fn publish_committed(
        &mut self,
        transition: Transition,
    ) -> Result<AppliedEvent, PublishError> {
        if self.prestate() != transition.before || self.stopped {
            return Err(PublishError::StaleState);
        }
        if let Some(account) = transition.account {
            self.account = account;
        }
        self.metadata_id = transition.metadata_id;
        self.epoch_id = transition.epoch_id;
        self.entries.push(transition.seen);
        self.ids.insert(transition.event_id, transition.digest);
        self.floor = transition.applied.floor;
        Ok(transition.applied)
    }

    /// Consume only against the exact verified predecessor. Selection errors do
    /// not poison history or modify a Note. The caller owns the atomic store and
    /// (for hidden bases) must separately fence its current unlock generation.
    pub fn consume(
        &mut self,
        prepared: PreparedEvent,
        target: Option<NoteTarget<'_>>,
    ) -> Result<AppliedEvent, ConsumeError> {
        if self.prestate() != prepared.before || self.stopped {
            return Err(ConsumeError::StaleState);
        }
        let is_control = matches!(&prepared.kind, PreparedKind::Control { .. });
        if is_control != target.is_none()
            || target
                .as_ref()
                .is_some_and(|t| Some(t.id) != prepared.note_id())
        {
            return Err(ConsumeError::WrongTarget);
        }
        let kind = match &prepared.kind {
            PreparedKind::Control { .. } => AppliedKind::Control,
            PreparedKind::Note { id, payload } => {
                let target = target.expect("target checked");
                match apply_note(target.note, &payload.data()[32..]) {
                    Ok(candidate) => {
                        // Take direct ownership of the copied delta in its wiped
                        // allocation; the decrypted padded payload remains guarded.
                        let delta = SecretBytes::from_vec(payload.data()[32..].to_vec());
                        *target.note = candidate;
                        AppliedKind::NoteAccepted {
                            note_id: *id,
                            delta,
                        }
                    }
                    Err(()) => AppliedKind::NoteRejected { note_id: *id },
                }
            }
        };
        self.advance(&prepared);
        Ok(AppliedEvent {
            ordered: prepared.ordered,
            ordered_bytes: prepared.ordered.encode(),
            descriptor: prepared.descriptor,
            body: prepared.body,
            body_commitment: prepared.body_commitment,
            kind,
            head: self.head(),
            floor: self.floor,
        })
    }

    // Replay calls this only after prepare; it advances the same common history
    // as consume, without needing or changing any Note projection.
    fn advance(&mut self, prepared: &PreparedEvent) {
        let previous_control = self.entries.last().map_or([0; 32], |p| p.control);
        let is_control = if let PreparedKind::Control {
            account,
            metadata_id,
            epoch_id,
        } = &prepared.kind
        {
            self.account = Arc::clone(account);
            self.metadata_id = *metadata_id;
            self.epoch_id = *epoch_id;
            true
        } else {
            false
        };
        self.entries.push(Seen {
            head: prepared.head,
            control: if is_control {
                prepared.digest.0
            } else {
                previous_control
            },
            account: self.account.head(),
        });
        self.ids.insert(prepared.event_id, prepared.digest);
        self.floor = self.floor.max(prepared.version);
    }

    /// Compatibility API for a caller with an externally known note ID. Unlike
    /// consume(), a wrong guess remains an integrity stop as before.
    pub fn apply(
        &mut self,
        ordered: &Commitment,
        event: &OpaqueEvent,
        body: Option<&[u8]>,
        metadata: &Secret<32>,
        content: Option<&Secret<32>>,
        target: NoteTarget<'_>,
    ) -> Outcome {
        let prepared = match self.prepare(ordered, event, body, metadata, content) {
            Ok(p) => p,
            Err(other) => return other,
        };
        let target = if prepared.note_id().is_some() {
            Some(target)
        } else {
            None
        };
        match self.consume(prepared, target) {
            Ok(applied) => applied.outcome(),
            Err(_) => {
                self.stopped = true;
                Outcome::IntegrityStop
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Payload, seal};
    use bh_account::{DevicePublicKeys, RecoveryPublicKeys};
    use bh_crypto::{KemKey, SigningKey};
    use bh_sync::EventId;

    #[test]
    fn notes_reuse_account_state_and_candidate_controls_are_isolated() {
        let signing = SigningKey::generate();
        let control = SigningKey::generate();
        let receiving = KemKey::generate();
        let keys =
            DevicePublicKeys::new(signing.public(), control.public(), receiving.public()).unwrap();
        let device = keys.id();
        let request = AccountEvent::genesis(
            keys,
            RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public()),
        );
        let account_genesis = request
            .finish(control.sign(request.signing_bytes()))
            .unwrap();
        let account_id = AccountId::of_genesis(&account_genesis).unwrap();
        let account =
            VerifiedAccount::from_genesis(account_id, account_genesis.as_bytes()).unwrap();
        let metadata = Secret::<32>::random();
        let content = Secret::<32>::random();
        let metadata_id = key_id(&metadata);
        let mut genesis_data = Vec::new();
        genesis_data.extend(account_id.0);
        genesis_data.extend(account.head().position.to_be_bytes());
        genesis_data.extend(account.head().hash);
        genesis_data.extend([0; 32]);
        genesis_data.extend(key_id(&content));
        genesis_data.extend(metadata_id);
        let genesis = seal(
            Binding {
                version: 1,
                highest: 1,
                mode: 1,
                base: [0; 32],
                audience: [0; 32],
                epoch: metadata_id,
                event_id: EventId(bh_crypto::random()),
                account: account_id,
                device,
                account_head: account.head(),
                seen: Head::EMPTY,
                seen_control: [0; 32],
                class: CLASS_CONTROL,
                padded: 0,
                commitment: [0; 32],
            },
            Payload {
                kind: GENESIS,
                data: &genesis_data,
            },
            &signing,
            &metadata,
            None,
        )
        .unwrap();
        let base = BaseId::from_genesis(&genesis.descriptor);
        let mut history = History::new(account_id, account_genesis.as_bytes(), base, 1).unwrap();
        let genesis_order = Commitment::order(base, Head::EMPTY, &genesis.descriptor).unwrap();
        let prepared = history
            .prepare(
                &genesis_order,
                &genesis.descriptor,
                Some(&genesis.body),
                &metadata,
                None,
            )
            .unwrap();
        history.advance(&prepared);

        let account_device = history.account.active_device(device).unwrap() as *const _;
        let mut candidate = history.clone();
        assert_eq!(
            account_device,
            candidate.account.active_device(device).unwrap() as *const _,
            "transaction candidates should share immutable verified account state"
        );

        let binding = |history: &History, class| Binding {
            version: 1,
            highest: 1,
            mode: 0,
            base: base.0,
            audience: [0; 32],
            epoch: if class == CLASS_CONTROL {
                metadata_id
            } else {
                key_id(&content)
            },
            event_id: EventId(bh_crypto::random()),
            account: account_id,
            device,
            account_head: history.account_head(),
            seen: history.head(),
            seen_control: history.entries.last().unwrap().control,
            class,
            padded: 0,
            commitment: [0; 32],
        };
        let mut note_data = vec![7; 32];
        note_data.extend(Note::new().append_paragraph("unchanged account"));
        let note = seal(
            binding(&history, CLASS_CONTENT),
            Payload {
                kind: NOTE,
                data: &note_data,
            },
            &signing,
            &metadata,
            Some(&content),
        )
        .unwrap();
        let ordered = Commitment::order(base, history.head(), &note.descriptor).unwrap();
        let account_head = history.account_head();
        let prepared = history
            .prepare(
                &ordered,
                &note.descriptor,
                Some(&note.body),
                &metadata,
                Some(&content),
            )
            .unwrap();
        assert_eq!(
            history.account.active_device(device).unwrap() as *const _,
            account_device
        );
        history.advance(&prepared);
        assert_eq!(history.account_head(), account_head);
        assert_eq!(
            history.account.active_device(device).unwrap() as *const _,
            account_device
        );
        assert_eq!(candidate.account_head(), account_head);
        assert_eq!(candidate.head(), genesis_order.head());

        let added = DevicePublicKeys::new(
            SigningKey::generate().public(),
            SigningKey::generate().public(),
            KemKey::generate().public(),
        )
        .unwrap();
        let added_id = added.id();
        let request = account.add_device(device, added).unwrap();
        let add = request
            .finish(control.sign(request.signing_bytes()))
            .unwrap();
        let changed = seal(
            binding(&candidate, CLASS_CONTROL),
            Payload {
                kind: ACCOUNT_CHANGE,
                data: add.as_bytes(),
            },
            &control,
            &metadata,
            None,
        )
        .unwrap();
        let ordered = Commitment::order(base, candidate.head(), &changed.descriptor).unwrap();
        let prepared = candidate
            .prepare(
                &ordered,
                &changed.descriptor,
                Some(&changed.body),
                &metadata,
                None,
            )
            .unwrap();
        assert_eq!(history.account_head(), account_head);
        assert!(history.account.active_device(added_id).is_err());
        candidate.advance(&prepared);
        assert_eq!(candidate.account_head(), add.head());
        assert!(candidate.account.active_device(added_id).is_ok());
        assert_eq!(history.account_head(), account_head);
        assert!(history.account.active_device(added_id).is_err());
        assert_eq!(
            history.account.active_device(device).unwrap() as *const _,
            account_device
        );
    }
}
