//! Verified remote events applied in log order to each note's *accepted*
//! state, apart from this device's pending local work. A note's accepted
//! state is the log-order integration of its accepted events; its working
//! state is accepted plus pending local updates in local order. Incoming
//! rules read accepted state only. One batch's decisions, its progress, its
//! typed operations, its retained content and the working notes' remote
//! deltas commit in one SQLite transaction, and deliveries go to windows only
//! after that commit.
//!
//! A batch's effects run in log order, so a typed operation sees a Note whose
//! first accepted event is earlier and not one whose is later. Content this
//! build cannot apply is kept exactly, at its position, and never stops
//! unrelated work: a content kind it does not know, and a note event whose
//! writer declaration it cannot read. The latter waits only for its own Note:
//! later events for that Note are kept behind it in order, so the Note never
//! moves past an event this build cannot read. The scope's typed log stays
//! complete through the committed position; a Note this replica cannot show is
//! a gap in that record, which makes ordered work on it wait and a Note-family
//! listing incomplete while everything else carries on.
use crate::{
    ContainerId, ORDINARY_AUDIENCE, Owner, OwnerError, SyncFence, load_working_note,
    sync_fence::Recheck,
};
use bh_account::VerifiedAccount;
use bh_core::note::{IncomingError, IncomingRefusal, Note, NoteError};
use bh_data::{Actor, Position, Scope};
use bh_event::{
    AppliedEvent, AppliedKind, Continuation, History, HistoryLookup, LookupError, NOTE, Seen,
    note_payload,
    writer::{DeviceWriterDeclaration, WriterScope},
};
use bh_storage::held_notes::HeldEvent;
use bh_storage::{
    DeviceDatabase, NoteKey, StoreError,
    note_writers::BaseWriterPhase,
    retained::RetainedContent,
    sync_state::{
        AcceptedBinding, AcceptedNote, IncomingCommit, IncomingNote, IncomingStep, OwnOutcome,
        PackageOutcome, SeenRow, TypedPayload, VerifiedRecord,
    },
};
pub use bh_sync::permit::{LogId, LogKind};
use bh_sync::{BaseId, Digest, Head, receipt, receipt::RECEIPT_LEN};
use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, Mutex},
};

/// Storage uses the same byte that the permit signs for this log kind.
fn log_code(log: LogId) -> u8 {
    log.kind as u8
}

/// Consecutive events `History` verified under the pinned hosting root and
/// consumed with `History::consume_unapplied` (this owner alone judges note
/// content, on accepted state), the head they reach and the hosting receipt
/// the caller verified for it.
pub struct VerifiedBatch {
    pub log: LogId,
    pub events: Vec<AppliedEvent>,
    pub head: Head,
    pub receipt: [u8; RECEIPT_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoteOutcome {
    Accepted,
    Refused(RefusalReason),
    /// Held for a local resource limit or missing local key or bytes, never
    /// for a dependency gap.
    Waiting,
}

/// A refused event has no effect on accepted state, on every device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalReason {
    ForeignWriter,
    NotContinuous,
    MissingDependency,
    /// Not a Yjs v1 update.
    Undecodable,
    /// A Yjs update that yrs failed to integrate on accepted state.
    ApplyFailed,
    Duplicate,
}
impl From<IncomingRefusal> for RefusalReason {
    fn from(reason: IncomingRefusal) -> Self {
        match reason {
            IncomingRefusal::ForeignWriter => Self::ForeignWriter,
            IncomingRefusal::NotContinuous => Self::NotContinuous,
            IncomingRefusal::Duplicate => Self::Duplicate,
            IncomingRefusal::MissingDependency => Self::MissingDependency,
            IncomingRefusal::Undecodable => Self::Undecodable,
            IncomingRefusal::ApplyFailed => Self::ApplyFailed,
        }
    }
}
impl RefusalReason {
    /// The stored code of a refused package's reason.
    fn code(self) -> u8 {
        match self {
            Self::ForeignWriter => 1,
            Self::NotContinuous => 2,
            Self::MissingDependency => 3,
            Self::Undecodable => 4,
            Self::ApplyFailed => 5,
            Self::Duplicate => 6,
        }
    }
    fn from_code(code: u8) -> Result<Self, StoreError> {
        Ok(match code {
            1 => Self::ForeignWriter,
            2 => Self::NotContinuous,
            3 => Self::MissingDependency,
            4 => Self::Undecodable,
            5 => Self::ApplyFailed,
            6 => Self::Duplicate,
            _ => return Err(StoreError::CorruptSyncState),
        })
    }
}

/// Where one of this device's local updates stands while it is not
/// accepted. Its work stays in the working note in every state; nothing
/// reseals it automatically. All but `Unsent`, `Sealed` and `Acked` mean
/// "not accepted" for the person to see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unaccepted {
    /// No package is sealed yet.
    Unsent,
    /// Sealed; nothing heard about it yet.
    Sealed,
    /// The append was acknowledged; its content is not judged yet.
    Acked,
    /// Ordered and refused by the writer rule.
    Refused(RefusalReason),
    /// Ordered as an invalid submission (a receipt that does not verify,
    /// say), with no effect.
    Rejected,
    /// Another event holds its event ID, so it cannot be ordered under it.
    Conflicted,
}

/// One unaccepted local update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnacceptedUpdate {
    pub update_id: i64,
    /// The position its Ack or ordered echo named.
    pub position: Option<u64>,
    pub state: Unaccepted,
}

/// Each note event's outcome in log order, and the windows with queued
/// deliveries for the native delivery worker to wake.
pub type Applied = (Vec<(NoteKey, NoteOutcome)>, Vec<String>);

/// Why a log stopped. A stop is sticky and keeps all verified state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StopReason {
    /// `History` proved the log contradicts its verified prefix.
    Integrity = 1,
}

/// Past this many accepted updates after its compacted segments, a note's
/// accepted state is compacted (verified, within the rebuild budget) as a
/// batch commits, so loading it never replays a long history.
const ACCEPTED_TAIL_LIMIT: usize = 64;

/// A remote row's local request ID, derived from its unique event ID.
fn remote_request(event_id: [u8; 32]) -> [u8; 16] {
    let mut input = b"bh remote note update v1\0".to_vec();
    input.extend(event_id);
    bh_crypto::hash(&input)[..16]
        .try_into()
        .expect("sixteen bytes")
}

fn scope(key: NoteKey) -> WriterScope {
    WriterScope {
        base: key.base,
        audience: key.audience,
        note: key.note,
    }
}

/// A verified log's durable rows, looked up for a resumed `History`. Each
/// lookup takes the container's writer lock briefly: never call
/// `History::prepare` on a resumed History while holding that lock.
struct StoredLookup {
    database: Arc<Mutex<DeviceDatabase>>,
    kind: u8,
    id: [u8; 32],
}
impl HistoryLookup for StoredLookup {
    fn seen(&self, position: u64) -> Result<Option<Seen>, LookupError> {
        let row = self
            .database
            .lock()
            .map_err(|_| LookupError)?
            .log_seen(self.kind, self.id, position)
            .map_err(|_| LookupError)?;
        Ok(row.map(|r| Seen {
            head: Head {
                position: r.position,
                hash: Digest(r.head_hash),
            },
            control: r.control_digest,
            account: bh_account::Head {
                position: r.account_position,
                hash: r.account_hash,
            },
        }))
    }
    fn event_digest(&self, event_id: [u8; 32]) -> Result<Option<Digest>, LookupError> {
        Ok(self
            .database
            .lock()
            .map_err(|_| LookupError)?
            .log_event_digest(self.kind, self.id, event_id)
            .map_err(|_| LookupError)?
            .map(Digest))
    }
}

fn record(event: &AppliedEvent) -> VerifiedRecord {
    let seen = event.seen();
    let ordered = event.commitment();
    VerifiedRecord {
        seen: SeenRow {
            position: seen.head.position,
            head_hash: seen.head.hash.0,
            control_digest: seen.control,
            account_position: seen.account.position,
            account_hash: seen.account.hash,
        },
        event_id: ordered.event_id().0,
        digest: ordered.event_digest().0,
        account_change: event.account_change().map(<[u8]>::to_vec),
        judged_floor: event.judged_floor(),
        floor: event.floor(),
    }
}

/// How an ordered event relates to this device's own packages.
enum Own {
    Not,
    /// Its exact package: the outbox row.
    Exact(i64),
    /// Other bytes under that package's event ID; whether this device's own
    /// key signed them.
    Clash {
        update_id: i64,
        own_key: bool,
    },
}

/// One note's accepted state through this batch, and what it must commit.
struct Work {
    key: NoteKey,
    stored: AcceptedNote,
    note: Option<Note>,
    /// Updates this batch accepted, for rebuilding after a changed refusal.
    batch: Vec<Vec<u8>>,
    accepted: Vec<(u64, Vec<u8>)>,
    bindings: BTreeMap<u64, AcceptedBinding>,
    remote: Vec<([u8; 16], Vec<u8>)>,
    /// Whether any own package of this note was ordered in this batch.
    own: bool,
    /// Own packages this batch accepted, which stop being pending.
    retired: u64,
}
impl Work {
    fn rebuild(&mut self) -> Result<(), OwnerError> {
        self.note.take();
        let mut note = Note::from_ordered(&self.stored.ordered()).map_err(accepted_note)?;
        for update in &self.batch {
            note.apply_update(update).map_err(accepted_note)?;
        }
        self.note = Some(note);
        Ok(())
    }
}

// Retained encoded prepared compaction/rebuild budget, not RSS or peak
// allocation. Retry's previous successful prefix coexists with the next during
// preparation. This is not a per-retry CPU cap: optional compaction can repeat
// for each of the 64 candidates under the existing per-operation fuel limit.
const PREPARED_BYTES: usize = 512 * 1024 * 1024;

fn state_size(state: &bh_core::note::OrderedState) -> usize {
    9 + state.segments().iter().map(|s| 4 + s.len()).sum::<usize>()
}
fn prepared_size(note: &IncomingNote) -> usize {
    note.compacted.as_ref().map_or(0, state_size)
        + note.rebuild_working.as_ref().map_or(0, state_size)
}
fn bound_prepared(note: &mut IncomingNote, remaining: usize) -> Result<(), OwnerError> {
    if prepared_size(note) > remaining {
        note.compacted = None;
    }
    if prepared_size(note) > remaining {
        return Err(OwnerError::NoteUnavailable);
    }
    Ok(())
}
fn open_work(database: &Arc<Mutex<DeviceDatabase>>, key: NoteKey) -> Result<Work, OwnerError> {
    let stored = database
        .lock()
        .expect("container writer lock")
        .accepted_note(key)?;
    let note = Some(Note::from_ordered(&stored.ordered()).map_err(accepted_note)?);
    Ok(Work {
        key,
        stored,
        note,
        batch: Vec::new(),
        accepted: Vec::new(),
        bindings: BTreeMap::new(),
        remote: Vec::new(),
        own: false,
        retired: 0,
    })
}
fn judge_candidate(
    database: &Arc<Mutex<DeviceDatabase>>,
    w: &mut Work,
    event: &HeldEvent,
) -> Result<(NoteOutcome, Option<OwnOutcome>), OwnerError> {
    let outcome = match &event.delta {
        Some(delta) => admit(database, w, event, delta)?,
        None => NoteOutcome::Refused(RefusalReason::Undecodable),
    };
    if outcome == NoteOutcome::Accepted {
        let delta = event.delta.as_ref().expect("accepted");
        w.accepted
            .push((event.ordered.head().position, delta.clone()));
        w.batch.push(delta.clone());
        if event.own_update.is_none() {
            w.remote
                .push((remote_request(event.ordered.event_id().0), delta.clone()));
        }
    }
    if outcome == NoteOutcome::Accepted
        && let Some(update_id) = event.own_update
    {
        w.retired += database
            .lock()
            .expect("container writer lock")
            .package_pending_count(update_id)?;
    }
    let own = event.own_update.map(|update_id| {
        w.own = true;
        let package = match outcome {
            NoteOutcome::Accepted => PackageOutcome::Accepted,
            NoteOutcome::Refused(reason) => PackageOutcome::Refused(reason.code()),
            NoteOutcome::Waiting => PackageOutcome::Held,
        };
        OwnOutcome {
            update_id,
            ordered: event.ordered,
            outcome: package,
            publishing_stopped: false,
        }
    });
    Ok((outcome, own))
}
// Capture all guest-derived results before another apply can invalidate it.
// A retry retains the last complete capture, not state from a trapped guest.
fn prepare_note(
    database: &Arc<Mutex<DeviceDatabase>>,
    w: &Work,
) -> Result<(IncomingNote, Option<[u8; 32]>), OwnerError> {
    let pending = database
        .lock()
        .expect("container writer lock")
        .pending_count(w.key)?
        .saturating_sub(w.retired);
    let note = w.note.as_ref().expect("live note");
    let (rebuild, digest) = if w.own && pending == 0 {
        let mut state = w.stored.ordered();
        for update in &w.batch {
            state.push(update.clone());
        }
        (Some(state), Some(note.digest()?))
    } else {
        (None, None)
    };
    let compacted =
        if !w.accepted.is_empty() && w.stored.tail.len() + w.accepted.len() > ACCEPTED_TAIL_LIMIT {
            let tail: Vec<_> = w.stored.tail.iter().chain(&w.batch).cloned().collect();
            note.ordered(&w.stored.previous, &tail)?
        } else {
            None
        };
    let title = (pending == 0 && !w.accepted.is_empty())
        .then(|| note.title_preview())
        .transpose()?;
    Ok((
        IncomingNote {
            key: w.key,
            accepted: w.accepted.clone(),
            compacted,
            bindings: w.bindings.values().copied().collect(),
            remote: w.remote.clone(),
            rebuild_working: rebuild,
            title,
        },
        digest,
    ))
}
// The accepted guest has been dropped before opening the working note.
fn finish_note(
    database: &Arc<Mutex<DeviceDatabase>>,
    prepared: &mut IncomingNote,
    digest: Option<[u8; 32]>,
    remaining: usize,
) -> Result<(), OwnerError> {
    if let Some(digest) = digest {
        let (mut working, _, _) = load_working_note(database, prepared.key, false)?;
        for (_, update) in &prepared.remote {
            working.apply_update(update)?;
        }
        if working.digest()? == digest {
            prepared.rebuild_working = None;
        }
    }
    bound_prepared(prepared, remaining)
}
type Judged = (IncomingNote, Vec<NoteOutcome>, Vec<OwnOutcome>);
fn judge_note(
    database: &Arc<Mutex<DeviceDatabase>>,
    key: NoteKey,
    candidates: &[(usize, HeldEvent)],
    remaining: usize,
) -> Result<Judged, OwnerError> {
    let mut w = open_work(database, key)?;
    let mut outcomes = Vec::new();
    let mut own = Vec::new();
    for (_, candidate) in candidates {
        let (outcome, package) = judge_candidate(database, &mut w, candidate)?;
        outcomes.push(outcome);
        own.extend(package);
    }
    let (mut prepared, digest) = prepare_note(database, &w)?;
    drop(w);
    finish_note(database, &mut prepared, digest, remaining)?;
    Ok((prepared, outcomes, own))
}

/// Accepted state that does not reopen is corrupt, unless the note engine
/// was unavailable, which judges nothing.
fn accepted_note(error: NoteError) -> OwnerError {
    match error {
        NoteError::Unavailable => OwnerError::NoteUnavailable,
        _ => StoreError::CorruptSyncState.into(),
    }
}

impl Owner {
    /// The verifier for a registered log, continuing from its durable
    /// verified continuation without replaying it. `anchor` is the creator's
    /// account at the head the base genesis names. `hosting_root` must come
    /// from the base's authenticated hosting association and equal the root
    /// pinned at registration; another root is a configuration error,
    /// `Unavailable` before any event is judged.
    pub fn history(
        &self,
        id: ContainerId,
        log: LogId,
        anchor: &VerifiedAccount,
        hosting_root: [u8; 32],
        remembered_floor: u16,
    ) -> Result<History, OwnerError> {
        if log.kind != LogKind::Base {
            return Err(OwnerError::InvalidBatch);
        }
        let database = self.shared_database(id)?;
        let (progress, changes) = {
            let db = database.lock().expect("container writer lock");
            let progress = db
                .log_progress(log_code(log), log.id)?
                .ok_or(OwnerError::NotRegistered)?;
            let changes = db.log_account_changes(log_code(log), log.id)?;
            (progress, changes)
        };
        if progress.stopped.is_some() {
            return Err(OwnerError::Stopped);
        }
        if progress.hosting_root != hosting_root {
            return Err(OwnerError::Unavailable);
        }
        let base = BaseId(log.id);
        let floor = progress.floor.max(remembered_floor);
        if progress.position == 0 {
            return History::with_account(anchor, base, hosting_root, floor)
                .map_err(|_| OwnerError::Unavailable);
        }
        let (Some((account_position, account_hash)), Some(metadata_id)) =
            (progress.account, progress.metadata_id)
        else {
            return Err(StoreError::CorruptSyncState.into());
        };
        let continuation = Continuation {
            seen: Seen {
                head: Head {
                    position: progress.position,
                    hash: Digest(progress.head_hash),
                },
                control: progress.control_digest,
                account: bh_account::Head {
                    position: account_position,
                    hash: account_hash,
                },
            },
            metadata_id,
            epoch_id: progress.epoch_id,
            floor: progress.floor,
        };
        let lookup = Arc::new(StoredLookup {
            database,
            kind: log_code(log),
            id: log.id,
        });
        History::resume(
            anchor,
            base,
            hosting_root,
            continuation,
            &changes,
            lookup,
            remembered_floor,
        )
        .map_err(|_| OwnerError::Unavailable)
    }

    /// This note's local updates that are not accepted yet, oldest first
    /// (at most 256), and where each stands.
    pub fn unaccepted(
        &self,
        id: ContainerId,
        key: NoteKey,
    ) -> Result<Vec<UnacceptedUpdate>, OwnerError> {
        let database = self.shared_database(id)?;
        let rows = database
            .lock()
            .expect("container writer lock")
            .unaccepted_packages(key, 0, 256)?;
        rows.into_iter()
            .map(|p| {
                let state = match (p.packaged, p.outcome) {
                    (false, _) => Unaccepted::Unsent,
                    (true, None) => Unaccepted::Sealed,
                    (true, Some(PackageOutcome::Acked | PackageOutcome::Held)) => Unaccepted::Acked,
                    (true, Some(PackageOutcome::Refused(code))) => {
                        Unaccepted::Refused(RefusalReason::from_code(code)?)
                    }
                    (true, Some(PackageOutcome::Rejected)) => Unaccepted::Rejected,
                    (true, Some(PackageOutcome::Conflicted)) => Unaccepted::Conflicted,
                    (true, Some(PackageOutcome::Accepted)) => {
                        return Err(StoreError::CorruptSyncState.into());
                    }
                };
                Ok(UnacceptedUpdate {
                    update_id: p.update_id,
                    position: p.position,
                    state,
                })
            })
            .collect()
    }

    /// Apply one verified batch to accepted state and commit it atomically
    /// with progress. Returns each note event's outcome in log order.
    pub fn apply_remote_batch(
        &self,
        id: ContainerId,
        batch: VerifiedBatch,
    ) -> Result<Vec<(NoteKey, NoteOutcome)>, OwnerError> {
        self.apply_remote_batch_with_hook(id, batch, |_| Ok(()))
            .map(|(outcomes, _)| outcomes)
    }

    /// As `apply_remote_batch`, also naming the windows to wake.
    pub fn apply_remote_batch_queued(
        &self,
        id: ContainerId,
        batch: VerifiedBatch,
    ) -> Result<Applied, OwnerError> {
        self.apply_remote_batch_with_hook(id, batch, |_| Ok(()))
    }

    /// As `apply_remote_batch_queued`, committed only while the authority
    /// `fence` captured, before the batch was read, is still current: checked
    /// under the writer guard immediately before COMMIT. `Unbound` otherwise,
    /// with nothing applied.
    pub fn apply_remote_batch_fenced(
        &self,
        id: ContainerId,
        fence: &SyncFence,
        batch: VerifiedBatch,
    ) -> Result<Applied, OwnerError> {
        self.apply_remote_batch_inner(id, Some(fence), batch, |_| Ok(()))
    }

    /// Test seam: `between(i)` runs inside the transaction before step `i`'s
    /// writes (in log order: a note, a typed operation or retained content);
    /// an error there must leave every table unchanged.
    #[doc(hidden)]
    pub fn apply_remote_batch_with_hook(
        &self,
        id: ContainerId,
        batch: VerifiedBatch,
        between: impl FnMut(usize) -> Result<(), StoreError>,
    ) -> Result<Applied, OwnerError> {
        self.apply_remote_batch_inner(id, None, batch, between)
    }

    fn apply_remote_batch_inner(
        &self,
        id: ContainerId,
        fence: Option<&SyncFence>,
        batch: VerifiedBatch,
        between: impl FnMut(usize) -> Result<(), StoreError>,
    ) -> Result<Applied, OwnerError> {
        let VerifiedBatch {
            log,
            events,
            head,
            receipt,
        } = batch;
        // Account logs carry account controls, which the account owner applies.
        if log.kind != LogKind::Base {
            return Err(OwnerError::InvalidBatch);
        }
        let Some(last) = events.last() else {
            return Ok((Vec::new(), Vec::new()));
        };
        let base = log.id;
        // The batch proves itself here: one base, each event continuing the
        // one before, ending at the head it names.
        if last.head() != head
            || events.windows(2).any(|pair| {
                pair[1]
                    .commitment()
                    .verify_next(BaseId(base), pair[0].head())
                    .is_err()
            })
            || events[0].commitment().base() != BaseId(base)
        {
            return Err(OwnerError::InvalidBatch);
        }
        if !self.anchored(id) {
            return Err(OwnerError::Unbound);
        }
        let key = |note| NoteKey {
            base,
            audience: ORDINARY_AUDIENCE,
            note,
        };
        let database = self.shared_database(id)?;
        // Exclusive ownership of exactly this batch's notes, in a fixed order;
        // other notes and containers carry on. A Note this batch keeps behind
        // unreadable content takes its lock too, so a concurrent release of
        // that Note's held events never interleaves with it.
        let mut notes: Vec<[u8; 32]> = events
            .iter()
            .filter_map(|e| match e.kind() {
                AppliedKind::NoteAccepted { note_id, .. }
                | AppliedKind::NoteRejected { note_id }
                | AppliedKind::NoteUnsupported { note_id, .. } => Some(*note_id),
                AppliedKind::Control
                | AppliedKind::Rejected
                | AppliedKind::Typed { .. }
                | AppliedKind::UnknownContent { .. } => None,
            })
            .collect();
        notes.sort_unstable();
        notes.dedup();
        let slots: Vec<_> = notes.iter().map(|n| self.work_lock(id, key(*n))).collect();
        let guards: Vec<_> = slots
            .iter()
            .map(|s| s.lock.as_ref().unwrap().lock().expect("note work lock"))
            .collect();

        let progress = {
            let db = database.lock().expect("container writer lock");
            let progress = db
                .log_progress(log_code(log), base)?
                .ok_or(OwnerError::NotRegistered)?;
            if progress.stopped.is_some() {
                return Err(OwnerError::Stopped);
            }
            if db.own_base()?.is_none_or(|own| own.base != base) {
                return Err(OwnerError::Unbound);
            }
            if db.base_writer_phase(base)? != Some(BaseWriterPhase::Registered) {
                return Err(OwnerError::NotRegistered);
            }
            progress
        };
        let root = progress.hosting_root;
        if events.iter().any(|e| e.hosting_root() != Some(root)) {
            return Err(OwnerError::Unavailable);
        }
        if receipt::verify(&root, BaseId(base), &receipt).map(|r| r.head()) != Ok(head) {
            return Err(OwnerError::InvalidBatch);
        }
        let after = (progress.position, progress.head_hash);
        events[0]
            .commitment()
            .verify_next(
                BaseId(base),
                Head {
                    position: after.0,
                    hash: Digest(after.1),
                },
            )
            .map_err(|_| OwnerError::InvalidBatch)?;
        let continuation = last.continuation().ok_or(OwnerError::InvalidBatch)?;
        // Classify event identity exactly once in global log order, before any
        // note engine runs. A later duplicate cannot settle a held own package.
        let mut groups: BTreeMap<[u8; 32], Vec<(usize, HeldEvent)>> = BTreeMap::new();
        // The position of the first note event this build cannot read, per
        // Note: later events for that Note wait behind it.
        let mut blockers: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        // Content kept exactly at its position: an unknown kind, an unreadable
        // declaration, and any note event waiting behind either.
        let mut retained = Vec::new();
        let mut typed = Vec::new();
        let mut settled = HashSet::new();
        let mut own_outcomes = Vec::new();
        for (index, event) in events.iter().enumerate() {
            let candidate = match event.kind() {
                AppliedKind::NoteAccepted { note_id, delta } => {
                    Some((*note_id, Some(delta.expose().to_vec())))
                }
                AppliedKind::NoteRejected { note_id } => Some((*note_id, None)),
                AppliedKind::Control
                | AppliedKind::Rejected
                | AppliedKind::Typed { .. }
                | AppliedKind::UnknownContent { .. }
                | AppliedKind::NoteUnsupported { .. } => None,
            };
            let unsupported = match event.kind() {
                AppliedKind::NoteUnsupported { note_id, .. } => Some(*note_id),
                _ => None,
            };
            let own = own_event(
                &database,
                base,
                event,
                candidate
                    .as_ref()
                    .map(|(n, _)| key(*n))
                    .or_else(|| unsupported.map(key)),
                &settled,
            )?;
            let mut own_update = None;
            match own {
                Own::Not => {}
                Own::Exact(update_id) => {
                    settled.insert(update_id);
                    if candidate.is_some() {
                        own_update = Some(update_id);
                    } else if unsupported.is_some() {
                        // Retained exactly, so this package is not decided yet.
                        own_outcomes.push(OwnOutcome {
                            update_id,
                            ordered: event.commitment(),
                            outcome: PackageOutcome::Held,
                            publishing_stopped: false,
                        });
                    } else {
                        own_outcomes.push(OwnOutcome {
                            update_id,
                            ordered: event.commitment(),
                            outcome: PackageOutcome::Rejected,
                            publishing_stopped: false,
                        });
                    }
                }
                Own::Clash { update_id, own_key } => {
                    settled.insert(update_id);
                    own_outcomes.push(OwnOutcome {
                        update_id,
                        ordered: event.commitment(),
                        outcome: PackageOutcome::Conflicted,
                        publishing_stopped: own_key,
                    });
                }
            }
            let author = event.author();
            let position = event.head().position;
            let ordered = event.commitment();
            match event.kind() {
                AppliedKind::NoteUnsupported { note_id, payload } => {
                    blockers
                        .entry(*note_id)
                        .and_modify(|first| *first = (*first).min(position))
                        .or_insert(position);
                    retained.push(RetainedContent {
                        log_kind: log_code(log),
                        log_id: base,
                        audience: ORDINARY_AUDIENCE,
                        position: Position(position),
                        kind: NOTE,
                        note: Some(*note_id),
                        author,
                        payload: payload.expose().to_vec(),
                    });
                }
                AppliedKind::UnknownContent { kind, payload } => retained.push(RetainedContent {
                    log_kind: log_code(log),
                    log_id: base,
                    audience: ORDINARY_AUDIENCE,
                    position: Position(position),
                    kind: *kind,
                    note: None,
                    author,
                    payload: payload.expose().to_vec(),
                }),
                AppliedKind::Typed { payload } => typed.push((
                    position,
                    Box::new(TypedPayload {
                        scope: Scope {
                            base,
                            audience: ORDINARY_AUDIENCE,
                        },
                        position: Position(position),
                        actor: Actor::Device {
                            account: author.ok_or(StoreError::CorruptSyncState)?.0,
                            device: author.ok_or(StoreError::CorruptSyncState)?.1,
                        },
                        payload: payload.expose().to_vec(),
                        ordered,
                        descriptor: event.descriptor_bytes().to_vec(),
                        body: event.body_bytes().to_vec(),
                    }),
                )),
                _ => {}
            }
            if let Some((note, delta)) = candidate {
                groups.entry(note).or_default().push((
                    index,
                    HeldEvent {
                        ordered,
                        author,
                        writer: event.writer().map(|w| (w.account, w.device, w.nonce)),
                        delta,
                        own_update,
                    },
                ));
            }
        }
        let mut commit = IncomingCommit {
            log_kind: log_code(log),
            log_id: base,
            hosting_root: root,
            after,
            receipt,
            records: events.iter().map(record).collect(),
            metadata_id: continuation.metadata_id,
            epoch_id: continuation.epoch_id,
            notes: Vec::new(),
            steps: Vec::new(),
            own: own_outcomes,
            held: Vec::new(),
        };
        let mut outcomes = Vec::new();
        let mut reloads = Vec::new();
        let mut prepared_bytes = 0;
        let mut steps: Vec<(u64, IncomingStep)> = typed
            .into_iter()
            .map(|(position, typed)| (position, IncomingStep::Typed(typed)))
            .collect();
        steps.extend(
            retained
                .into_iter()
                .map(|row| (row.position.0, IncomingStep::Retained(row))),
        );
        // Only this note's working engine is retained, never one per batch
        // entry. Global outcomes are reassembled by their original position.
        for (note, candidates) in groups {
            let key = key(note);
            let already_retained = database
                .lock()
                .expect("container writer lock")
                .note_has_retained(key)?;
            // This batch's first unreadable declaration for the Note, or every
            // candidate when an earlier batch already retained one.
            let cut = if already_retained {
                0
            } else {
                match blockers.get(&note) {
                    Some(position) => candidates
                        .iter()
                        .position(|(_, c)| c.ordered.head().position >= *position)
                        .unwrap_or(candidates.len()),
                    None => candidates.len(),
                }
            };
            let (prefix, suffix) = candidates.split_at(cut);
            // Later events for the Note wait behind what this build cannot
            // read, in position order: it never moves past them, and no event
            // is lost.
            for (index, candidate) in suffix {
                let kept = candidate.writer.zip(candidate.delta.as_deref());
                match kept {
                    Some((writer, delta)) => {
                        let payload = note_payload(
                            note,
                            DeviceWriterDeclaration {
                                account: writer.0,
                                device: writer.1,
                                nonce: writer.2,
                            },
                            delta,
                        );
                        steps.push((
                            candidate.ordered.head().position,
                            IncomingStep::Retained(RetainedContent {
                                log_kind: log_code(log),
                                log_id: base,
                                audience: ORDINARY_AUDIENCE,
                                position: Position(candidate.ordered.head().position),
                                kind: NOTE,
                                note: Some(note),
                                author: candidate.author,
                                payload,
                            }),
                        ));
                        if let Some(update_id) = candidate.own_update {
                            commit.own.push(OwnOutcome {
                                update_id,
                                ordered: candidate.ordered,
                                outcome: PackageOutcome::Held,
                                publishing_stopped: false,
                            });
                        }
                        outcomes.push((*index, key, NoteOutcome::Waiting));
                    }
                    // A note event this layer already refused was no update at
                    // all: there are no bytes to keep, and its verdict does not
                    // depend on the unreadable declaration before it.
                    None => {
                        if let Some(update_id) = candidate.own_update {
                            commit.own.push(OwnOutcome {
                                update_id,
                                ordered: candidate.ordered,
                                outcome: PackageOutcome::Refused(RefusalReason::Undecodable.code()),
                                publishing_stopped: false,
                            });
                        }
                        outcomes.push((
                            *index,
                            key,
                            NoteOutcome::Refused(RefusalReason::Undecodable),
                        ));
                    }
                }
            }
            if prefix.is_empty() {
                continue;
            }
            let already_held = database
                .lock()
                .expect("container writer lock")
                .note_is_held(key)?;
            let judged = if already_held {
                Err(OwnerError::NoteUnavailable)
            } else {
                judge_note(
                    &database,
                    key,
                    prefix,
                    PREPARED_BYTES.saturating_sub(prepared_bytes),
                )
            };
            match judged {
                Ok((prepared, verdicts, own)) => {
                    prepared_bytes += prepared_size(&prepared);
                    if prepared.rebuild_working.is_some() {
                        reloads.push(key);
                    }
                    // Its existence shows at the position of its first accepted
                    // candidate; the title of the whole group commits with it.
                    let at = prefix
                        .iter()
                        .zip(&verdicts)
                        .find(|(_, verdict)| **verdict == NoteOutcome::Accepted)
                        .map(|((_, candidate), _)| candidate.ordered.head().position)
                        .unwrap_or(prefix[0].1.ordered.head().position);
                    outcomes.extend(prefix.iter().zip(verdicts).map(|((i, _), o)| (*i, key, o)));
                    commit.own.extend(own);
                    steps.push((at, IncomingStep::Note(commit.notes.len())));
                    commit.notes.push(prepared);
                }
                Err(OwnerError::NoteUnavailable) => {
                    let mut held = Vec::new();
                    for (index, candidate) in prefix {
                        if let Some(update_id) = candidate.own_update {
                            commit.own.push(OwnOutcome {
                                update_id,
                                ordered: candidate.ordered,
                                outcome: PackageOutcome::Held,
                                publishing_stopped: false,
                            });
                        }
                        outcomes.push((*index, key, NoteOutcome::Waiting));
                        held.push(candidate.clone());
                    }
                    // The gap begins at this Note's first held position, not
                    // at the start of the batch ahead of earlier typed work.
                    steps.push((
                        prefix[0].1.ordered.head().position,
                        IncomingStep::Hold(commit.held.len()),
                    ));
                    commit.held.push((key, held));
                }
                Err(e) => return Err(e),
            }
        }
        steps.sort_unstable_by_key(|(position, _)| *position);
        commit.steps = steps.into_iter().map(|(_, step)| step).collect();
        outcomes.sort_unstable_by_key(|(i, _, _)| *i);
        let outcomes = outcomes.into_iter().map(|(_, key, o)| (key, o)).collect();
        commit
            .own
            .sort_unstable_by_key(|o| o.ordered.head().position);
        let commit_step = |db: &mut DeviceDatabase| {
            db.commit_incoming(&commit, between).map_err(|e| match e {
                StoreError::LogStopped => OwnerError::Stopped,
                StoreError::RootConflict => OwnerError::Unavailable,
                other => OwnerError::Store(other),
            })
        };
        let committed = match fence {
            Some(fence) => self.fenced(fence, Recheck::Authority, commit_step)?,
            None => commit_step(&mut database.lock().expect("container writer lock"))?,
        };
        // Published only after COMMIT, and before the notes' leases end, so
        // no local save of these notes is delivered between their rows. The
        // batch is committed whatever happens here: a container removed
        // meanwhile simply has no windows to tell.
        let mut windows = Vec::new();
        if let Ok(session) = self.account_session(id) {
            let mut targets = Vec::new();
            {
                let mut guard = session.lock().expect("container session lock");
                for (note, done) in commit.notes.iter().zip(&committed) {
                    let reload = reloads.contains(&note.key).then_some(done.frontier);
                    let updates: Vec<(i64, Vec<u8>)> = done
                        .rows
                        .iter()
                        .copied()
                        .zip(note.remote.iter().map(|(_, u)| u.clone()))
                        .collect();
                    guard.publish_remote(note.key, &updates, reload, |d| targets.push(d));
                }
            }
            windows = self.enqueue(id, targets);
        }
        drop(guards);
        drop(slots);
        for note in &committed {
            self.compaction.schedule(id, note.key, &database);
        }
        self.compaction.schedule_maintenance(id, &database);
        self.compaction.schedule_derived_if_pending(id, &database);
        Ok((outcomes, windows))
    }

    /// Judge a bounded prefix of one note's durable held events, without
    /// re-reading the log or changing its progress. Local failure leaves the
    /// failed candidate and its successors held; completed predecessors commit.
    pub fn retry_held(&self, id: ContainerId, key: NoteKey) -> Result<Applied, OwnerError> {
        if !self.anchored(id) {
            return Err(OwnerError::Unbound);
        }
        let slot = self.work_lock(id, key);
        let _guard = slot
            .lock
            .as_ref()
            .expect("note lock")
            .lock()
            .expect("note work lock");
        let database = self.shared_database(id)?;
        let first = {
            let db = database.lock().expect("container writer lock");
            let progress = db
                .log_progress(bh_storage::sync_state::LOG_BASE, key.base)?
                .ok_or(OwnerError::NotRegistered)?;
            if progress.stopped.is_some() {
                return Err(OwnerError::Stopped);
            }
            db.next_held_event(key, 0)?
        };
        let Some(mut event) = first else {
            return Ok((Vec::new(), Vec::new()));
        };
        let mut w = match open_work(&database, key) {
            Ok(w) => w,
            Err(OwnerError::NoteUnavailable) => {
                return Ok((vec![(key, NoteOutcome::Waiting)], Vec::new()));
            }
            Err(e) => return Err(e),
        };
        let mut outcomes = Vec::new();
        let mut own = Vec::new();
        let mut prepared = None;
        let mut through = 0;
        for _ in 0..64 {
            let result = (|| {
                let (outcome, package) = judge_candidate(&database, &mut w, &event)?;
                let (mut candidate, digest) = prepare_note(&database, &w)?;
                bound_prepared(&mut candidate, PREPARED_BYTES)?;
                Ok::<_, OwnerError>((outcome, package, candidate, digest))
            })();
            match result {
                Ok((outcome, package, candidate, digest)) => {
                    outcomes.push((key, outcome));
                    own.extend(package);
                    prepared = Some((candidate, digest));
                    through = event.ordered.head().position;
                }
                Err(OwnerError::NoteUnavailable) => {
                    outcomes.push((key, NoteOutcome::Waiting));
                    break;
                }
                Err(e) => return Err(e),
            }
            let next = database
                .lock()
                .expect("container writer lock")
                .next_held_event(key, through)?;
            let Some(next) = next else {
                break;
            };
            event = next;
        }
        drop(w);
        let Some((mut prepared, digest)) = prepared else {
            return Ok((outcomes, Vec::new()));
        };
        match finish_note(&database, &mut prepared, digest, PREPARED_BYTES) {
            Ok(()) => {}
            Err(OwnerError::NoteUnavailable) => {
                return Ok((vec![(key, NoteOutcome::Waiting)], Vec::new()));
            }
            Err(e) => return Err(e),
        }
        let done = database
            .lock()
            .expect("container writer lock")
            .release_held(&prepared, through, &own)?;
        let mut windows = Vec::new();
        if let Ok(session) = self.account_session(id) {
            let mut targets = Vec::new();
            {
                let mut guard = session.lock().expect("container session lock");
                let reload = prepared.rebuild_working.is_some().then_some(done.frontier);
                let updates: Vec<_> = done
                    .rows
                    .iter()
                    .copied()
                    .zip(prepared.remote.iter().map(|(_, u)| u.clone()))
                    .collect();
                guard.publish_remote(key, &updates, reload, |d| targets.push(d));
            }
            windows = self.enqueue(id, targets);
        }
        self.compaction.schedule(id, key, &database);
        self.compaction.schedule_maintenance(id, &database);
        self.compaction.schedule_derived_if_pending(id, &database);
        Ok((outcomes, windows))
    }

    /// Latch a proven contradiction for this log. Accepted, working and
    /// pending state all stay; nothing further applies to the log.
    pub fn record_stop(
        &self,
        id: ContainerId,
        log: LogId,
        reason: StopReason,
    ) -> Result<(), OwnerError> {
        let database = self.shared_database(id)?;
        let mut db = database.lock().expect("container writer lock");
        db.record_log_stop(log_code(log), log.id, reason as u8)?;
        Ok(())
    }
}

/// How an ordered event relates to this device's packages. History has
/// authenticated it already, so other bytes under one of their event IDs
/// are never evidence against the log: another device's event (or someone's
/// invalid submission) takes that ID, or this device's own key signed them.
fn own_event(
    database: &Arc<Mutex<DeviceDatabase>>,
    base: [u8; 32],
    event: &AppliedEvent,
    key: Option<NoteKey>,
    settled: &HashSet<i64>,
) -> Result<Own, OwnerError> {
    let package = database
        .lock()
        .expect("container writer lock")
        .own_package(event.commitment().event_id().0)?;
    // Only an ID's first ordered occurrence speaks for the package; a later
    // one is a reused ID that History rejected. Another base's package can
    // never be ordered in this log, so nothing here speaks for it.
    let Some(package) =
        package.filter(|p| p.key.base == base && !p.echoed && !settled.contains(&p.update_id))
    else {
        return Ok(Own::Not);
    };
    if package.descriptor == event.descriptor_bytes()
        && package.body == event.body_bytes()
        && key.is_none_or(|k| k == package.key)
    {
        return Ok(Own::Exact(package.update_id));
    }
    Ok(Own::Clash {
        update_id: package.update_id,
        own_key: event.author().is_some() && event.author() == package.principal,
    })
}

/// The incoming writer rule: the declared writer must be the verified
/// author's, bound to it if seen before, and its update must insert only
/// as that writer, continuing exactly at its accepted end, and attach.
fn admit(
    database: &std::sync::Arc<std::sync::Mutex<bh_storage::DeviceDatabase>>,
    w: &mut Work,
    event: &HeldEvent,
    delta: &[u8],
) -> Result<NoteOutcome, OwnerError> {
    let refused = |reason| Ok(NoteOutcome::Refused(reason));
    if !w.note.as_ref().expect("live note").is_update(delta)? {
        return refused(RefusalReason::Undecodable);
    }
    let Some((account, device, nonce)) = event.writer else {
        return refused(RefusalReason::Undecodable);
    };
    let writer = DeviceWriterDeclaration {
        account,
        device,
        nonce,
    };
    if Some((account, device)) != event.author {
        return refused(RefusalReason::ForeignWriter);
    }
    let client = writer.client_id(scope(w.key));
    let bound = match w.bindings.get(&client) {
        Some(b) => Some(*b),
        None => database
            .lock()
            .expect("container writer lock")
            .accepted_binding(w.key, client)?,
    };
    if bound.is_some_and(|b| (b.account, b.device, b.nonce) != (account, device, nonce)) {
        return refused(RefusalReason::ForeignWriter);
    }
    match w
        .note
        .as_mut()
        .expect("live note")
        .apply_incoming(delta, client)
    {
        Ok(()) => {
            w.bindings.insert(
                client,
                AcceptedBinding {
                    client_id: client,
                    account,
                    device,
                    nonce,
                    accepted_end: w
                        .note
                        .as_ref()
                        .expect("live note")
                        .writer_end(client)?
                        .unwrap_or(0),
                },
            );
            Ok(NoteOutcome::Accepted)
        }
        // Local failure defers this note, never a replicated refusal.
        Err(IncomingError::Unavailable) => Err(OwnerError::NoteUnavailable),
        Err(IncomingError::Refused { reason, changed }) => {
            if changed {
                w.rebuild()?;
            }
            refused(reason.into())
        }
    }
}

#[cfg(test)]
mod prepared_tests {
    use super::*;
    #[test]
    fn budget_drops_optional_compaction_before_deferring_required_state() {
        let state = bh_core::note::OrderedState::single(vec![1; 32]);
        let mut note = IncomingNote {
            key: NoteKey {
                base: [1; 32],
                audience: [0; 32],
                note: [2; 32],
            },
            accepted: Vec::new(),
            compacted: Some(state.clone()),
            bindings: Vec::new(),
            remote: Vec::new(),
            rebuild_working: Some(state),
            title: None,
        };
        assert!(bound_prepared(&mut note, 45).is_ok());
        assert!(note.compacted.is_none());
        assert!(note.rebuild_working.is_some());
        assert!(matches!(
            bound_prepared(&mut note, 44),
            Err(OwnerError::NoteUnavailable)
        ));
    }
}
