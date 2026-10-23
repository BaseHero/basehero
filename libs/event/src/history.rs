use crate::account_run::{base_account, encode_copies};
use crate::codec::{Binding, Error, NOTE_PREFIX, OpenPayload, apply_note};
use crate::control::{Judged, Signed, SignedContext, judge, verify_signed};
use crate::writer::DeviceWriterDeclaration;
use bh_account::{AccountId, Head as AccountHead, VerifiedAccount};
use bh_core::note::{Note, NoteError};
use bh_crypto::{Secret, SecretBytes};
use bh_sync::{BaseId, Commitment, Digest, Head, OpaqueEvent, OrderState, referenced_body};
use std::{collections::BTreeMap, sync::Arc};

/// These results establish only historical verification, never a currently
/// authorised service operation. A caller must stop after `IntegrityStop`.
///
/// An invalid submission under a known protocol (a forged or malformed
/// original, a false claim about what its author had seen, an absent or
/// invalid receipt, an inactive author) is `Rejected`: ordered, with no
/// effect, and verification continues. Only evidence against independently
/// verified history stops: a verified hosting receipt contradicting it,
/// changed bytes under an established commitment, or an invalid genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Accepted,
    ContentRejected,
    Rejected,
    IntegrityStop,
    UnsupportedPause,
    UnavailablePause,
    /// Verified and consumed, with its content retained exactly and not
    /// applied by this build: typed data, a content kind this build does not
    /// know, or a note event whose writer declaration this build cannot read.
    Retained,
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
    /// The note engine trapped or hit a local limit: nothing was judged, and
    /// the working Note is discarded.
    Unavailable,
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
    author: Option<([u8; 32], [u8; 32])>,
    kind: PreparedKind,
}
impl PreparedEvent {
    /// Only a note event this build applies has a target. Controls, retained
    /// content and unreadable declarations return None.
    pub fn note_id(&self) -> Option<[u8; 32]> {
        match &self.kind {
            PreparedKind::Note { id, .. } => Some(*id),
            PreparedKind::Control { .. }
            | PreparedKind::Typed { .. }
            | PreparedKind::UnknownContent { .. }
            | PreparedKind::NoteUnsupported { .. }
            | PreparedKind::Rejected => None,
        }
    }
    /// The producing writer a note event declares, unchecked against its
    /// author; None for controls and every retained event.
    pub fn writer(&self) -> Option<DeviceWriterDeclaration> {
        match &self.kind {
            PreparedKind::Note { writer, .. } => Some(*writer),
            PreparedKind::Control { .. }
            | PreparedKind::Typed { .. }
            | PreparedKind::UnknownContent { .. }
            | PreparedKind::NoteUnsupported { .. }
            | PreparedKind::Rejected => None,
        }
    }
    /// An invalid submission: consuming it advances history with no effect.
    pub fn is_rejected(&self) -> bool {
        matches!(self.kind, PreparedKind::Rejected)
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
    judged_floor: u16,
    author: Option<([u8; 32], [u8; 32])>,
    writer: Option<DeviceWriterDeclaration>,
    seen: Seen,
    metadata_id: Option<[u8; 32]>,
    epoch_id: Option<[u8; 32]>,
    hosting_root: Option<[u8; 32]>,
    account_change: Option<Vec<u8>>,
}
/// Authenticated history classification. A rejected content event advances
/// the common history but must not change the Note; a retained one advances
/// it with its exact bytes kept and nothing applied.
pub enum AppliedKind {
    /// With `History::consume`, the delta passed that history's Note judgment.
    /// With `History::consume_unapplied`, this is only an authenticated
    /// candidate: the device Owner must judge and commit it before it is
    /// accepted content or may retire pending work.
    NoteAccepted {
        note_id: [u8; 32],
        delta: SecretBytes,
    },
    NoteRejected {
        note_id: [u8; 32],
    },
    /// Typed data, exactly as its author sealed it. This layer does not parse
    /// it; the device owner decides whether and how to apply it.
    Typed {
        payload: SecretBytes,
    },
    /// A content kind this build does not know: retained exactly, not applied,
    /// and history continues past it.
    UnknownContent {
        kind: u16,
        payload: SecretBytes,
    },
    /// A note event whose writer declaration this build cannot read: retained
    /// exactly and not applied, so only this note waits for a newer build.
    NoteUnsupported {
        note_id: [u8; 32],
        payload: SecretBytes,
    },
    Control,
    /// An invalid submission: it holds its position and nothing else.
    Rejected,
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
    /// This history's classification, not necessarily final content acceptance.
    /// In particular, `consume_unapplied` returns `Accepted` for authenticated
    /// Note candidates whose content still awaits the Owner's judgment/commit.
    pub fn outcome(&self) -> Outcome {
        match self.kind {
            AppliedKind::NoteRejected { .. } => Outcome::ContentRejected,
            AppliedKind::Rejected => Outcome::Rejected,
            AppliedKind::Typed { .. }
            | AppliedKind::UnknownContent { .. }
            | AppliedKind::NoteUnsupported { .. } => Outcome::Retained,
            AppliedKind::NoteAccepted { .. } | AppliedKind::Control => Outcome::Accepted,
        }
    }
    pub fn head(&self) -> Head {
        self.head
    }
    pub fn floor(&self) -> u16 {
        self.floor
    }
    /// The version floor this event was judged under. Above the floor before
    /// it, the floor rose at the previous position.
    pub fn judged_floor(&self) -> u16 {
        self.judged_floor
    }
    /// What verified history had applied once this event was: the record an
    /// author's claim to have seen this position is checked against.
    pub fn seen(&self) -> Seen {
        self.seen
    }
    /// Everything judging the next event needs, once this one is applied.
    /// None only before a genesis has named the metadata root.
    pub fn continuation(&self) -> Option<Continuation> {
        Some(Continuation {
            seen: self.seen,
            order: self.ordered.after(),
            metadata_id: self.metadata_id?,
            epoch_id: self.epoch_id,
            floor: self.floor,
        })
    }
    /// The pinned hosting root this event's receipt was judged under; None
    /// only for a genesis verified without one.
    pub fn hosting_root(&self) -> Option<[u8; 32]> {
        self.hosting_root
    }
    /// What an accepted account control applied to the account projection,
    /// as one record to store: a legacy copy's exact account event, or the
    /// encoded copies of a run or rekey (`account_run::decode_copies`).
    /// [`History::resume`] takes these records back.
    pub fn account_change(&self) -> Option<&[u8]> {
        self.account_change.as_deref()
    }
    /// The verified signer: its account and active device, or the recovery
    /// author for a run the recovery key copied. None for a rejected
    /// submission, whose signer is not established.
    pub fn author(&self) -> Option<([u8; 32], [u8; 32])> {
        self.author
    }
    /// The writer a note event declares, rejected or not. Only its decoding
    /// is checked here: whether it binds [`Self::author`] is the note
    /// owner's rule. None for controls and for a declaration this build
    /// cannot read.
    pub fn writer(&self) -> Option<DeviceWriterDeclaration> {
        self.writer
    }
}
/// The exact decrypted payload an event retains, owned and wiped on drop.
fn retained(payload: &OpenPayload) -> SecretBytes {
    SecretBytes::from_vec(payload.data().to_vec())
}

enum PreparedKind {
    Note {
        id: [u8; 32],
        writer: DeviceWriterDeclaration,
        payload: OpenPayload,
    },
    /// Typed data this build carries but does not parse.
    Typed {
        payload: OpenPayload,
    },
    /// A content kind this build does not know.
    UnknownContent {
        kind: u16,
        payload: OpenPayload,
    },
    /// A note event whose writer declaration this build cannot read.
    NoteUnsupported {
        id: [u8; 32],
        payload: OpenPayload,
    },
    Control {
        account: Arc<VerifiedAccount>,
        metadata_id: Option<[u8; 32]>,
        epoch_id: Option<[u8; 32]>,
        change: Option<Vec<u8>>,
    },
    Rejected,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Prestate {
    base: BaseId,
    head: Head,
    order: OrderState,
    control: [u8; 32],
    account: AccountHead,
    metadata_id: Option<[u8; 32]>,
    epoch_id: Option<[u8; 32]>,
    floor: u16,
    position: u64,
    ids: usize,
    stopped: bool,
}

/// What verified history had applied at one position: its head, the digest
/// of the newest control event and the account head. An author's claim to
/// have seen that position is checked against exactly this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seen {
    pub head: Head,
    pub control: [u8; 32],
    pub account: AccountHead,
}

/// A durable verified continuation: what judging the next event needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Continuation {
    pub seen: Seen,
    pub order: OrderState,
    pub metadata_id: [u8; 32],
    pub epoch_id: Option<[u8; 32]>,
    pub floor: u16,
}

/// A local store could not answer. Nothing is judged; the device waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LookupError;

/// Durable verified history below a resumed continuation, read by point
/// lookups so that resuming neither replays nor loads the whole log.
/// Implementations must not take a lock a caller of `prepare` may hold.
pub trait HistoryLookup: Send + Sync {
    /// What was seen at `position` (from 1), if verified history has it.
    fn seen(&self, position: u64) -> Result<Option<Seen>, LookupError>;
    /// The digest of the first ordered event that used this ID, if any.
    fn event_digest(&self, event_id: [u8; 32]) -> Result<Option<Digest>, LookupError>;
}

#[derive(Clone)]
struct Durable {
    last: Seen,
    lookup: Arc<dyn HistoryLookup>,
}

/// In-memory candidate. The device store must atomically persist exact originals,
/// accepted deltas or rejection, and verified progress; this type is not durable authority.
#[derive(Clone)]
pub struct History {
    base: BaseId,
    order: OrderState,
    // Notes and transactional clones share this immutable verified snapshot.
    // An account-changing control prepares a separate owned successor.
    account: Arc<VerifiedAccount>,
    // Verified history below `entries` when resumed: looked up, never loaded.
    durable: Option<Durable>,
    // Positions after the durable continuation (from 1 without one).
    entries: Vec<Seen>,
    ids: BTreeMap<[u8; 32], Digest>,
    metadata_id: Option<[u8; 32]>,
    epoch_id: Option<[u8; 32]>,
    floor: u16,
    stopped: bool,
    // Pinned hosting root that certifies receipt keys. Only base genesis
    // verification runs without one; it never reaches a later event.
    hosting_root: Option<[u8; 32]>,
}
impl History {
    /// `base` and `account_id` must come from local creation or an independent
    /// introduction, never from the untrusted log being checked. `hosting_root`
    /// is the independently pinned key that certifies receipt keys for this base.
    pub fn new(
        account_id: AccountId,
        account_genesis: &[u8],
        base: BaseId,
        hosting_root: [u8; 32],
        remembered_floor: u16,
    ) -> Result<Self, Error> {
        let account = VerifiedAccount::from_genesis(account_id, account_genesis)
            .map_err(|_| Error::Invalid)?;
        Self::with_account(&account, base, hosting_root, remembered_floor)
    }
    /// Start at the creator's independently verified account head named by a
    /// base genesis, including heads after account setup or device changes.
    /// Every event after genesis must carry a receipt for its author's observed
    /// head that verifies under `hosting_root`.
    pub fn with_account(
        account: &VerifiedAccount,
        base: BaseId,
        hosting_root: [u8; 32],
        remembered_floor: u16,
    ) -> Result<Self, Error> {
        Self::anchored(account, base, Some(hosting_root), remembered_floor)
    }
    /// Genesis verification needs no receipt, so it needs no hosting root; any
    /// later event pauses as unavailable. A missing local root is this
    /// device's configuration, not evidence about the log.
    pub(crate) fn anchored(
        account: &VerifiedAccount,
        base: BaseId,
        hosting_root: Option<[u8; 32]>,
        remembered_floor: u16,
    ) -> Result<Self, Error> {
        if remembered_floor == 0 || account.is_stopped() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            base,
            order: OrderState::EMPTY,
            account: Arc::new(account.clone()),
            durable: None,
            entries: vec![],
            ids: BTreeMap::new(),
            metadata_id: None,
            epoch_id: None,
            floor: remembered_floor,
            stopped: false,
            hosting_root,
        })
    }
    /// Continue from a durable verified continuation without replaying the
    /// log. `anchor` is the creator's account at the head the base genesis
    /// names, as for [`History::with_account`]; `account_changes` are the
    /// records [`AppliedEvent::account_change`] gave for the base-log
    /// controls that changed the account after it, in position order.
    /// Earlier positions and event IDs are read through `lookup`; confirmed
    /// copies verify again under `hosting_root`, which must be the root
    /// pinned when this base was registered, taken from its authenticated
    /// hosting association; the store owner refuses any other. Local state that does not reproduce
    /// the continuation is `UnavailablePause`: nothing is judged.
    #[allow(clippy::too_many_arguments)]
    pub fn resume<C, A>(
        anchor: &VerifiedAccount,
        base: BaseId,
        hosting_root: [u8; 32],
        continuation: Continuation,
        account_changes: C,
        lookup: Arc<dyn HistoryLookup>,
        remembered_floor: u16,
    ) -> Result<Self, Outcome>
    where
        C: IntoIterator<Item = A>,
        A: AsRef<[u8]>,
    {
        let unavailable = Outcome::UnavailablePause;
        if continuation.seen.head.position == 0
            || continuation.order.head(base) != continuation.seen.head
            || continuation.floor == 0
            || remembered_floor == 0
            || anchor.is_stopped()
        {
            return Err(unavailable);
        }
        let account =
            base_account(anchor, account_changes, &hosting_root).map_err(|_| unavailable)?;
        if account.head() != continuation.seen.account
            || lookup.seen(continuation.seen.head.position) != Ok(Some(continuation.seen))
        {
            return Err(unavailable);
        }
        Ok(Self {
            base,
            order: continuation.order,
            account: Arc::new(account),
            durable: Some(Durable {
                last: continuation.seen,
                lookup,
            }),
            entries: vec![],
            ids: BTreeMap::new(),
            metadata_id: Some(continuation.metadata_id),
            epoch_id: continuation.epoch_id,
            floor: continuation.floor.max(remembered_floor),
            stopped: false,
            hosting_root: Some(hosting_root),
        })
    }
    fn durable_position(&self) -> u64 {
        self.durable.as_ref().map_or(0, |d| d.last.head.position)
    }
    fn position(&self) -> u64 {
        self.durable_position() + self.entries.len() as u64
    }
    fn last_seen(&self) -> Option<Seen> {
        self.entries
            .last()
            .copied()
            .or_else(|| self.durable.as_ref().map(|d| d.last))
    }
    fn last_control(&self) -> [u8; 32] {
        self.last_seen().map_or([0; 32], |s| s.control)
    }
    /// What was seen at a position: in memory after the continuation, or
    /// looked up below it. A store that cannot answer, or answers for
    /// another position, makes this device wait.
    fn seen_at(&self, position: u64) -> Result<Option<Seen>, Outcome> {
        let below = self.durable_position();
        if position == 0 {
            return Ok(None);
        }
        if position > below {
            return Ok(usize::try_from(position - below - 1)
                .ok()
                .and_then(|index| self.entries.get(index))
                .copied());
        }
        let durable = self
            .durable
            .as_ref()
            .expect("positions below a continuation");
        match durable.lookup.seen(position) {
            Ok(Some(seen)) if seen.head.position == position => Ok(Some(seen)),
            _ => Err(Outcome::UnavailablePause),
        }
    }
    fn id_used(&self, event_id: [u8; 32]) -> Result<bool, Outcome> {
        if self.ids.contains_key(&event_id) {
            return Ok(true);
        }
        match &self.durable {
            Some(durable) => durable
                .lookup
                .event_digest(event_id)
                .map(|digest| digest.is_some())
                .map_err(|_| Outcome::UnavailablePause),
            None => Ok(false),
        }
    }
    pub fn head(&self) -> Head {
        self.last_seen().map_or(Head::EMPTY, |s| s.head)
    }
    pub fn order_state(&self) -> OrderState {
        self.order
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
    ///
    /// `floor_rises` are `(position, floor)`: events after `position` were
    /// judged under at least `floor`, so each event is judged under the floor
    /// in force when it was ordered, never a later one.
    #[allow(clippy::too_many_arguments)]
    pub fn replay<I, D, B>(
        account_id: AccountId,
        account_genesis: &[u8],
        base: BaseId,
        hosting_root: [u8; 32],
        floor_rises: &[(u64, u16)],
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
        Self::replay_with_account(
            &account,
            base,
            hosting_root,
            floor_rises,
            metadata,
            content,
            records,
        )
    }
    /// Replay originals anchored to the creator's verified account projection
    /// at the genesis head; later account changes arrive in the base log.
    pub fn replay_with_account<I, D, B>(
        account: &VerifiedAccount,
        base: BaseId,
        hosting_root: [u8; 32],
        floor_rises: &[(u64, u16)],
        metadata: &Secret<32>,
        content: Option<&Secret<32>>,
        records: I,
    ) -> Result<Self, Outcome>
    where
        I: IntoIterator<Item = (Commitment, D, B)>,
        D: AsRef<[u8]>,
        B: AsRef<[u8]>,
    {
        let mut history = Self::with_account(account, base, hosting_root, 1)
            .map_err(|_| Outcome::IntegrityStop)?;
        let rise = |history: &mut Self| {
            let position = history.position();
            for &(after, floor) in floor_rises {
                if after <= position {
                    history.floor = history.floor.max(floor);
                }
            }
        };
        for (ordered, descriptor, body) in records {
            rise(&mut history);
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
        rise(&mut history);
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
            order: self.order,
            control: self.last_control(),
            account: self.account.head(),
            metadata_id: self.metadata_id,
            epoch_id: self.epoch_id,
            floor: self.floor,
            position: self.position(),
            ids: self.ids.len(),
            stopped: self.stopped,
        }
    }

    /// Verify descriptor, original signature, author-seen heads and account
    /// authority without fetching/opening a note body. This does not advance.
    /// An invalid submission is `Err(Rejected)`; [`History::prepare`] turns it
    /// into an event that advances history with no effect.
    ///
    /// A control whose author is not active before it (a run's copier added
    /// in that run) is authenticated only once its body is judged.
    pub fn inspect(
        &self,
        ordered: &Commitment,
        event: &OpaqueEvent,
        metadata: &Secret<32>,
    ) -> Result<Binding, Outcome> {
        self.inspect_signed(ordered, event, metadata)
            .map(|signed| signed.binding)
    }

    fn inspect_signed(
        &self,
        ordered: &Commitment,
        event: &OpaqueEvent,
        metadata: &Secret<32>,
    ) -> Result<Signed, Outcome> {
        if self.stopped {
            return Err(Outcome::IntegrityStop);
        }
        // The order must continue verified history and commit these bytes.
        if self.order.head(self.base) != self.head()
            || ordered.before() != self.order
            || ordered.verify_next(self.base, self.head()).is_err()
            || ordered.verify_body(event).is_err()
        {
            return Err(Outcome::IntegrityStop);
        }
        verify_signed(self, ordered.route(), event, metadata)
    }

    /// Fully verify one ordered original and body without advancing the
    /// checkpoint or modifying a Note. Evidence against verified history
    /// latches an integrity stop; missing input and unsupported semantics do
    /// not. An invalid submission is prepared as rejected
    /// ([`PreparedEvent::is_rejected`]): consuming it advances history with
    /// no effect. This grants no current/unlock authority.
    pub fn prepare(
        &mut self,
        ordered: &Commitment,
        event: &OpaqueEvent,
        body: Option<&[u8]>,
        metadata: &Secret<32>,
        content: Option<&Secret<32>>,
    ) -> Result<PreparedEvent, Outcome> {
        let result = match self.prepare_checked(ordered, event, body, metadata, content) {
            Err(Outcome::Rejected) => Ok(self.rejected(ordered, event, body)),
            other => other,
        };
        if matches!(result, Err(Outcome::IntegrityStop)) {
            self.stopped = true;
        }
        result
    }

    /// An ordered invalid submission: its position and bytes, nothing else.
    fn rejected(
        &self,
        ordered: &Commitment,
        event: &OpaqueEvent,
        body: Option<&[u8]>,
    ) -> PreparedEvent {
        PreparedEvent {
            before: self.prestate(),
            ordered: *ordered,
            descriptor: event.encode(),
            body: body.map(<[u8]>::to_vec).unwrap_or_default(),
            body_commitment: referenced_body(event).unwrap_or(Digest([0; 32])),
            head: ordered.head(),
            digest: ordered.event_digest(),
            event_id: ordered.event_id().0,
            version: 0,
            author: None,
            kind: PreparedKind::Rejected,
        }
    }

    fn prepare_checked(
        &self,
        ordered: &Commitment,
        event: &OpaqueEvent,
        body: Option<&[u8]>,
        metadata: &Secret<32>,
        content: Option<&Secret<32>>,
    ) -> Result<PreparedEvent, Outcome> {
        let signed = self.inspect_signed(ordered, event, metadata)?;
        let body = body.ok_or(Outcome::UnavailablePause)?;
        let kind = match judge(self, &signed, event, body, metadata, content)? {
            Judged::Note {
                id,
                writer,
                payload,
            } => PreparedKind::Note {
                id,
                writer,
                payload,
            },
            Judged::Typed { payload } => PreparedKind::Typed { payload },
            Judged::UnknownContent { kind, payload } => {
                PreparedKind::UnknownContent { kind, payload }
            }
            Judged::NoteUnsupported { id, payload } => {
                PreparedKind::NoteUnsupported { id, payload }
            }
            Judged::Control {
                account,
                copy,
                metadata_id,
                epoch_id,
            } => PreparedKind::Control {
                // Only a control that changes account authority owns a
                // candidate; note verification and genesis share the snapshot.
                account: account.unwrap_or_else(|| Arc::clone(&self.account)),
                metadata_id,
                epoch_id,
                change: copy.map(|copy| encode_copies(&copy.copies)),
            },
        };
        Ok(PreparedEvent {
            before: self.prestate(),
            ordered: *ordered,
            descriptor: event.encode(),
            body: body.to_vec(),
            body_commitment: referenced_body(event).expect("inspected descriptor"),
            head: ordered.head(),
            digest: ordered.event_digest(),
            event_id: ordered.event_id().0,
            version: signed.binding.version,
            author: Some((signed.binding.account.0, signed.binding.device.0)),
            kind,
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
        if prepared.note_id().is_none() != target.is_none()
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
            PreparedKind::Rejected => (AppliedKind::Rejected, None),
            PreparedKind::Typed { payload } => (
                AppliedKind::Typed {
                    payload: retained(payload),
                },
                None,
            ),
            PreparedKind::UnknownContent { kind, payload } => (
                AppliedKind::UnknownContent {
                    kind: *kind,
                    payload: retained(payload),
                },
                None,
            ),
            PreparedKind::NoteUnsupported { id, payload } => (
                AppliedKind::NoteUnsupported {
                    note_id: *id,
                    payload: retained(payload),
                },
                None,
            ),
            PreparedKind::Note { id, payload, .. } => {
                let mut note = target.expect("target checked").note;
                let delta = &payload.data()[NOTE_PREFIX..];
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
                    Err(NoteError::Unavailable) => {
                        return Err(MaterializeError {
                            reason: ConsumeError::Unavailable,
                            target: None,
                        });
                    }
                }
            }
        };
        let (account, metadata_id, epoch_id, control) = match &prepared.kind {
            PreparedKind::Control {
                account,
                metadata_id,
                epoch_id,
                ..
            } => (
                Some(Arc::clone(account)),
                *metadata_id,
                *epoch_id,
                prepared.digest.0,
            ),
            PreparedKind::Note { .. }
            | PreparedKind::Typed { .. }
            | PreparedKind::UnknownContent { .. }
            | PreparedKind::NoteUnsupported { .. }
            | PreparedKind::Rejected => (
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
        let writer = prepared.writer();
        let account_change = match &prepared.kind {
            PreparedKind::Control { change, .. } => change.clone(),
            _ => None,
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
            judged_floor: prepared.before.floor,
            author: prepared.author,
            writer,
            seen,
            metadata_id,
            epoch_id,
            hosting_root: self.hosting_root,
            account_change,
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
        self.order = transition.applied.ordered.after();
        // A rejected replay of an ordered ID keeps the first one's digest.
        self.ids
            .entry(transition.event_id)
            .or_insert(transition.digest);
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
        if prepared.note_id().is_none() != target.is_none()
            || target
                .as_ref()
                .is_some_and(|t| Some(t.id) != prepared.note_id())
        {
            return Err(ConsumeError::WrongTarget);
        }
        let kind = match &prepared.kind {
            PreparedKind::Control { .. } => AppliedKind::Control,
            PreparedKind::Rejected => AppliedKind::Rejected,
            PreparedKind::Typed { payload } => AppliedKind::Typed {
                payload: retained(payload),
            },
            PreparedKind::UnknownContent { kind, payload } => AppliedKind::UnknownContent {
                kind: *kind,
                payload: retained(payload),
            },
            PreparedKind::NoteUnsupported { id, payload } => AppliedKind::NoteUnsupported {
                note_id: *id,
                payload: retained(payload),
            },
            PreparedKind::Note { id, payload, .. } => {
                let target = target.expect("target checked");
                match apply_note(target.note, &payload.data()[NOTE_PREFIX..]) {
                    Ok(candidate) => {
                        // Take direct ownership of the copied delta in its wiped
                        // allocation; the decrypted padded payload remains guarded.
                        let delta = SecretBytes::from_vec(payload.data()[NOTE_PREFIX..].to_vec());
                        *target.note = candidate;
                        AppliedKind::NoteAccepted {
                            note_id: *id,
                            delta,
                        }
                    }
                    Err(NoteError::Unavailable) => return Err(ConsumeError::Unavailable),
                    Err(_) => AppliedKind::NoteRejected { note_id: *id },
                }
            }
        };
        self.advance(&prepared);
        Ok(self.advanced(prepared, kind))
    }

    /// Consume against the exact verified predecessor without applying any
    /// Note or running its engine. `NoteAccepted` carries an authenticated
    /// candidate, not a content verdict: decoding and integration belong to
    /// the note owner, independently of verified log progress.
    pub fn consume_unapplied(
        &mut self,
        prepared: PreparedEvent,
    ) -> Result<AppliedEvent, ConsumeError> {
        if self.prestate() != prepared.before || self.stopped {
            return Err(ConsumeError::StaleState);
        }
        let kind = match &prepared.kind {
            PreparedKind::Control { .. } => AppliedKind::Control,
            PreparedKind::Rejected => AppliedKind::Rejected,
            PreparedKind::Typed { payload } => AppliedKind::Typed {
                payload: retained(payload),
            },
            PreparedKind::UnknownContent { kind, payload } => AppliedKind::UnknownContent {
                kind: *kind,
                payload: retained(payload),
            },
            PreparedKind::NoteUnsupported { id, payload } => AppliedKind::NoteUnsupported {
                note_id: *id,
                payload: retained(payload),
            },
            PreparedKind::Note { id, payload, .. } => {
                let delta = &payload.data()[NOTE_PREFIX..];
                AppliedKind::NoteAccepted {
                    note_id: *id,
                    delta: SecretBytes::from_vec(delta.to_vec()),
                }
            }
        };
        self.advance(&prepared);
        Ok(self.advanced(prepared, kind))
    }

    /// The applied event for a prepared event this History just advanced by.
    fn advanced(&self, prepared: PreparedEvent, kind: AppliedKind) -> AppliedEvent {
        let writer = prepared.writer();
        let judged_floor = prepared.before.floor;
        let account_change = match prepared.kind {
            PreparedKind::Control { change, .. } => change,
            _ => None,
        };
        AppliedEvent {
            ordered: prepared.ordered,
            ordered_bytes: prepared.ordered.encode(),
            author: prepared.author,
            writer,
            descriptor: prepared.descriptor,
            body: prepared.body,
            body_commitment: prepared.body_commitment,
            kind,
            head: self.head(),
            floor: self.floor,
            judged_floor,
            seen: self.last_seen().expect("just advanced"),
            metadata_id: self.metadata_id,
            epoch_id: self.epoch_id,
            hosting_root: self.hosting_root,
            account_change,
        }
    }

    // Replay calls this only after prepare; it advances the same common history
    // as consume, without needing or changing any Note projection.
    fn advance(&mut self, prepared: &PreparedEvent) {
        let previous_control = self.last_control();
        let is_control = if let PreparedKind::Control {
            account,
            metadata_id,
            epoch_id,
            ..
        } = &prepared.kind
        {
            self.account = Arc::clone(account);
            self.metadata_id = *metadata_id;
            self.epoch_id = *epoch_id;
            true
        } else {
            false
        };
        self.order = prepared.ordered.after();
        self.entries.push(Seen {
            head: prepared.head,
            control: if is_control {
                prepared.digest.0
            } else {
                previous_control
            },
            account: self.account.head(),
        });
        self.ids.entry(prepared.event_id).or_insert(prepared.digest);
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
            // Local engine failure says nothing about the signed event. Leave
            // the verifier retryable, distinct from wrong-target compatibility.
            Err(ConsumeError::Unavailable) => Outcome::UnavailablePause,
            Err(_) => {
                self.stopped = true;
                Outcome::IntegrityStop
            }
        }
    }
}

/// History knows every verified position: below a resumed continuation by
/// lookup, after it in memory.
impl SignedContext for History {
    fn base(&self) -> BaseId {
        self.base
    }
    fn genesis(&self) -> bool {
        self.position() == 0
    }
    fn account(&self) -> &VerifiedAccount {
        &self.account
    }
    fn metadata_id(&self) -> Option<[u8; 32]> {
        self.metadata_id
    }
    fn epoch_id(&self) -> Option<[u8; 32]> {
        self.epoch_id
    }
    fn floor(&self) -> u16 {
        self.floor
    }
    fn hosting_root(&self) -> Option<[u8; 32]> {
        self.hosting_root
    }
    fn last_control(&self) -> [u8; 32] {
        History::last_control(self)
    }
    fn id_used(&self, event_id: [u8; 32]) -> Result<bool, Outcome> {
        History::id_used(self, event_id)
    }
    fn known_head(&self, position: u64) -> Result<Option<Head>, Outcome> {
        Ok(self.seen_at(position)?.map(|seen| seen.head))
    }
    fn saw(&self, claim: Seen) -> Result<bool, Outcome> {
        Ok(self.seen_at(claim.head.position)? == Some(claim))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{
        ACCOUNT_CHANGE, CLASS_CONTENT, CLASS_CONTROL, GENESIS, NOTE, Payload, key_id, seal,
    };
    use bh_account::AccountEvent;
    use bh_account::{DevicePublicKeys, RecoveryPublicKeys};
    use bh_crypto::{KemKey, SigningKey};
    use bh_sync::receipt;
    use bh_sync::{EventId, Route};

    struct Fixture {
        signing: SigningKey,
        control: SigningKey,
        device: bh_account::DeviceId,
        account_id: AccountId,
        account_genesis: AccountEvent,
        account: VerifiedAccount,
        metadata: Secret<32>,
        content: Secret<32>,
        genesis: crate::Encoded,
    }

    fn fixture() -> Fixture {
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
                version: 3,
                highest: 3,
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
                seen_receipt: [0; bh_sync::receipt::RECEIPT_LEN],
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
        Fixture {
            signing,
            control,
            device,
            account_id,
            account_genesis,
            account,
            metadata,
            content,
            genesis,
        }
    }

    #[test]
    fn notes_reuse_account_state_and_candidate_controls_are_isolated() {
        let Fixture {
            signing,
            control,
            device,
            account_id,
            account_genesis,
            account,
            metadata,
            content,
            genesis,
        } = fixture();
        let metadata_id = key_id(&metadata);
        let base = BaseId::from_genesis(&genesis.descriptor);
        let root = SigningKey::generate();
        let receipt_key = SigningKey::generate();
        let certificate = receipt::verify_certificate(
            &root.public(),
            &receipt::certify(&root, receipt_key.public()),
        )
        .unwrap();
        let mut history = History::new(
            account_id,
            account_genesis.as_bytes(),
            base,
            root.public(),
            1,
        )
        .unwrap();
        let genesis_order =
            Commitment::order(base, OrderState::EMPTY, &genesis.descriptor, Route::Control)
                .unwrap();
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
            version: 3,
            highest: 3,
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
            seen_control: history.last_control(),
            class,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: receipt::sign(&certificate, &receipt_key, base, history.head()).unwrap(),
        };
        let note_data = crate::note_payload(
            [7; 32],
            DeviceWriterDeclaration {
                account: account_id.0,
                device: device.0,
                nonce: [1; 32],
            },
            &Note::new()
                .unwrap()
                .append_paragraph("unchanged account")
                .unwrap(),
        );
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
        let ordered = Commitment::order(
            base,
            history.order_state(),
            &note.descriptor,
            Route::Content,
        )
        .unwrap();
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
        let ordered = Commitment::order(
            base,
            candidate.order_state(),
            &changed.descriptor,
            Route::Control,
        )
        .unwrap();
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

    #[test]
    fn rootless_history_pauses_on_any_event_after_genesis() {
        let f = fixture();
        let base = BaseId::from_genesis(&f.genesis.descriptor);
        let mut history = History::anchored(&f.account, base, None, 1).unwrap();
        let genesis_order = Commitment::order(
            base,
            OrderState::EMPTY,
            &f.genesis.descriptor,
            Route::Control,
        )
        .unwrap();
        let prepared = history
            .prepare(
                &genesis_order,
                &f.genesis.descriptor,
                Some(&f.genesis.body),
                &f.metadata,
                None,
            )
            .unwrap();
        history.advance(&prepared);
        let root = SigningKey::generate();
        let receipt_key = SigningKey::generate();
        let certificate = receipt::verify_certificate(
            &root.public(),
            &receipt::certify(&root, receipt_key.public()),
        )
        .unwrap();
        let data = crate::note_payload(
            [7; 32],
            DeviceWriterDeclaration {
                account: f.account_id.0,
                device: f.device.0,
                nonce: [1; 32],
            },
            &Note::new()
                .unwrap()
                .append_paragraph("past genesis")
                .unwrap(),
        );
        let note = seal(
            Binding {
                version: 3,
                highest: 3,
                mode: 0,
                base: base.0,
                audience: [0; 32],
                epoch: key_id(&f.content),
                event_id: EventId(bh_crypto::random()),
                account: f.account_id,
                device: f.device,
                account_head: history.account_head(),
                seen: history.head(),
                seen_control: history.last_control(),
                class: CLASS_CONTENT,
                padded: 0,
                commitment: [0; 32],
                seen_receipt: receipt::sign(&certificate, &receipt_key, base, history.head())
                    .unwrap(),
            },
            Payload {
                kind: NOTE,
                data: &data,
            },
            &f.signing,
            &f.metadata,
            Some(&f.content),
        )
        .unwrap();
        let ordered = Commitment::order(
            base,
            history.order_state(),
            &note.descriptor,
            Route::Content,
        )
        .unwrap();
        // Without a pinned root this device cannot check the receipt: that is
        // missing local configuration, not evidence against the log.
        assert_eq!(
            history
                .prepare(
                    &ordered,
                    &note.descriptor,
                    Some(&note.body),
                    &f.metadata,
                    Some(&f.content),
                )
                .err(),
            Some(Outcome::UnavailablePause)
        );
        assert!(!history.is_stopped());
        let _ = f.control;
    }
}
