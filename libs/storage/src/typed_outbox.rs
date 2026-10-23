//! This device's typed-work outbox: one immutable sealed event per pending
//! typed mutation, its exact bytes kept until a verified echo judges it.
//!
//! Note update ids and mutation ids stay fully separate. A typed package names
//! a `bh-data` mutation and its exact payload; it never manufactures a note
//! id, a writer declaration or a note run. The work it publishes lives in
//! `data_pending`, which is also where its own echo is recognised, so this
//! module stores only what the transport needs: the immutable bytes, the Ack
//! position, and what the echo decided.
//!
//! Publish order is one order across both kinds of local work. A note's work
//! is ordered by its first pending update id; typed work carries the highest
//! note update id at the moment it was queued, so the two are comparable and
//! a typed package never jumps ahead of work committed before it. The note
//! commits need no extra write for this: the note-update sequence is the
//! clock, and a typed entry only snapshots it once.
//!
//! One entry is queued per saved mutation, so a package publishes exactly one
//! payload: the envelope carries one content kind, and bundling several
//! mutations would need a container format of its own. If the person drops
//! the saved work before it is sealed, its entry stays idle — never offered
//! for publishing and never counted as pending.

use crate::{
    DeviceDatabase, NoteKey, StoreError,
    sync_state::{OutboxHead, PackageOutcome, package_verdict},
};
use bh_data::{
    Actor, CoreCatalogue, MutationId, Scope,
    admission::HostAdmission,
    mutation::{
        apply::Outcome,
        ops::Operation,
        pending::{self, LocalSaved, SubmitError},
    },
};
use bh_sync::{BodyObject, Commitment, EventId, OpaqueEvent, referenced_body};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;

/// v14: an unsent, undecided package may be retired to be sealed again
/// under the same entry (`publish_typed_reseal`); the table's checks keep
/// that from touching an acknowledged or judged one. Otherwise its bytes
/// stay exact.
pub(crate) fn migrate_retirement(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    tx.execute_batch(
        "DROP TRIGGER typed_outbox_exact;
        CREATE TRIGGER typed_outbox_exact BEFORE UPDATE ON typed_outbox
          WHEN NEW.mutation!=OLD.mutation OR NEW.base!=OLD.base OR NEW.audience!=OLD.audience
            OR NEW.after_note!=OLD.after_note
            OR (OLD.event_id IS NOT NULL AND NEW.event_id IS NOT NULL
              AND (NEW.event_id IS NOT OLD.event_id
                OR NEW.descriptor IS NOT OLD.descriptor OR NEW.body IS NOT OLD.body))
          BEGIN SELECT RAISE(ABORT,'exact typed package'); END;",
    )
}

pub(crate) fn migrate(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    // Additive: nothing here rewrites a note, its outbox or `data_pending`.
    // `after_note` snapshots the note-update clock at queueing so typed work
    // and note work share one publish order; `id` breaks ties between typed
    // entries queued at the same clock and is also their permit/hold key.
    tx.execute_batch(
        "CREATE TABLE typed_outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mutation BLOB NOT NULL UNIQUE CHECK(length(mutation)=16),
            base BLOB NOT NULL CHECK(length(base)=32),
            audience BLOB NOT NULL CHECK(length(audience)=32),
            after_note INTEGER NOT NULL CHECK(after_note>=0),
            event_id BLOB UNIQUE CHECK(event_id IS NULL OR length(event_id)=32),
            descriptor BLOB,
            body BLOB,
            ack BLOB,
            staged INTEGER NOT NULL DEFAULT 0 CHECK(staged IN (0,1)),
            acked_position INTEGER CHECK(acked_position IS NULL OR acked_position>0),
            ordered_position INTEGER CHECK(ordered_position IS NULL OR ordered_position>0),
            outcome INTEGER CHECK(outcome IS NULL OR outcome BETWEEN 1 AND 6),
            refusal INTEGER CHECK(refusal IS NULL OR (outcome=3 AND refusal BETWEEN 1 AND 255)),
            CHECK((event_id IS NULL)=(descriptor IS NULL)),
            CHECK((descriptor IS NULL)=(body IS NULL)),
            CHECK(event_id IS NOT NULL
              OR (ack IS NULL AND acked_position IS NULL AND ordered_position IS NULL
                  AND staged=0 AND outcome IS NULL)),
            CHECK(outcome!=3 OR refusal IS NOT NULL)
        );
        CREATE UNIQUE INDEX typed_outbox_ordered_position ON typed_outbox(base,ordered_position)
          WHERE ordered_position IS NOT NULL;
        CREATE INDEX typed_outbox_open ON typed_outbox(after_note,id)
          WHERE outcome IS NULL AND ordered_position IS NULL;
        CREATE INDEX typed_outbox_scope_open ON typed_outbox(base,audience,id)
          WHERE outcome IS NULL AND ordered_position IS NULL;
        CREATE TRIGGER typed_outbox_exact BEFORE UPDATE ON typed_outbox
          WHEN NEW.mutation!=OLD.mutation OR NEW.base!=OLD.base OR NEW.audience!=OLD.audience
            OR NEW.after_note!=OLD.after_note
            OR (OLD.event_id IS NOT NULL AND (NEW.event_id IS NOT OLD.event_id
              OR NEW.descriptor IS NOT OLD.descriptor OR NEW.body IS NOT OLD.body))
          BEGIN SELECT RAISE(ABORT,'exact typed package'); END;
        CREATE TABLE typed_alarm (
            id INTEGER PRIMARY KEY,
            kind INTEGER NOT NULL CHECK(kind IN (1,2)),
            package INTEGER NOT NULL REFERENCES typed_outbox(id),
            position INTEGER CHECK(position IS NULL OR position>0)
        );",
    )
}

/// A fresh candidate for typed entry `id`'s saved work, as it is saved now.
fn saved_candidate(conn: &Connection, id: i64) -> Result<TypedPackageCandidate, StoreError> {
    let Some((mutation, base, audience, _, _, _)) = row(conn, id)? else {
        return Err(StoreError::MissingPending);
    };
    let mutation: [u8; 16] = array(mutation)?;
    let stored: Option<SavedRow> = conn
        .query_row(
            "SELECT p.payload,p.state,s.base,s.audience FROM data_pending p
                   JOIN data_scope s ON s.id=p.scope WHERE p.mutation=?1",
            [mutation.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((payload, state, saved_base, saved_audience)) = stored else {
        return Err(StoreError::MissingPending);
    };
    if state != "pending" && state != "waiting" {
        return Err(StoreError::MissingPending);
    }
    if saved_base != base || saved_audience != audience {
        return Err(StoreError::RequestConflict);
    }
    Ok(TypedPackageCandidate {
        event_id: EventId(bh_crypto::random::<32>()),
        id,
        mutation,
        base: array(base)?,
        audience: array(audience)?,
        payload,
    })
}

/// Whether typed package `id` is undecided: no Ack, no ordered position, no
/// verdict and no alarm names it.
fn typed_undecided(conn: &Connection, id: i64) -> Result<bool, StoreError> {
    Ok(conn.query_row(
        "SELECT acked_position IS NULL AND ordered_position IS NULL AND outcome IS NULL
           AND NOT EXISTS(SELECT 1 FROM typed_alarm WHERE package=?1)
         FROM typed_outbox WHERE id=?1",
        [id],
        |r| r.get(0),
    )?)
}

fn signed(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::CorruptSyncState)
}
fn unsigned(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::CorruptSyncState)
}
fn array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::CorruptSyncState)
}

/// Why typed work could not be queued for publishing. Nothing is written.
#[derive(Debug, Error)]
pub enum SubmitTypedError {
    #[error(transparent)]
    Submit(#[from] SubmitError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// A saved typed mutation and the outbox entry that will publish it.
pub struct QueuedTyped {
    pub saved: LocalSaved,
    /// The typed outbox entry: its publish order and permit/hold key.
    pub package: i64,
}

/// Where a piece of local work sits in this device's publish order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutboxOrder {
    /// The local commit clock: a note update id, or the note clock a typed
    /// mutation was queued at.
    pub clock: i64,
    /// 0 for note work, 1 for typed work.
    pub kind: u8,
    /// Orders typed work queued at the same clock; 0 for note work.
    pub tie: i64,
}
impl OutboxOrder {
    /// Before every queued item.
    pub const START: Self = Self {
        clock: 0,
        kind: 0,
        tie: 0,
    };
}

/// One typed mutation's next package to publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypedHead {
    /// The typed outbox entry.
    pub id: i64,
    pub base: [u8; 32],
    pub audience: [u8; 32],
    /// The note-update clock this work was queued after.
    pub after_note: i64,
}
impl TypedHead {
    pub fn order(&self) -> OutboxOrder {
        OutboxOrder {
            clock: self.after_note,
            kind: 1,
            tie: self.id,
        }
    }
}

/// One piece of local work the publisher may take this round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboxCandidate {
    Note(OutboxHead),
    Typed(TypedHead),
}
impl OutboxCandidate {
    pub fn order(&self) -> OutboxOrder {
        match self {
            Self::Note(head) => OutboxOrder {
                clock: head.first,
                kind: 0,
                tie: 0,
            },
            Self::Typed(head) => head.order(),
        }
    }
}

/// Seal the pending typed payload only after releasing every owner and
/// database guard, then CAS-persist exactly these bytes.
#[derive(Debug)]
pub struct TypedPackageCandidate {
    pub event_id: EventId,
    /// The typed outbox entry the payload was read for.
    pub id: i64,
    /// The `bh-data` mutation this package publishes; never a note id.
    pub mutation: [u8; 16],
    pub base: [u8; 32],
    pub audience: [u8; 32],
    /// The exact payload bytes `data_pending` holds; never re-encoded.
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum TypedPackagePreparation {
    Existing(StoredTypedPackage),
    Candidate(TypedPackageCandidate),
}

/// Immutable typed package: its exact sealed bytes are kept after an Ack and
/// after the echo that judged it, so a retry never reseals.
#[derive(Debug)]
pub struct StoredTypedPackage {
    pub event_id: EventId,
    pub descriptor: OpaqueEvent,
    pub body: Vec<u8>,
    pub ack: Option<Commitment>,
}

/// What became of one typed package, if it has one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypedPackageProgress {
    pub package: i64,
    pub payload_position: Option<u64>,
    pub outcome: Option<PackageOutcome>,
}

/// A verified echo's verdict on one of this device's typed packages.
pub struct TypedEcho {
    pub event_id: [u8; 32],
    pub ordered: Commitment,
    /// None when the ordered payload still waits for a typed dependency.
    pub outcome: Option<PackageOutcome>,
    /// This device's own key authored other bytes under its event id.
    pub publishing_stopped: bool,
}

/// A queued entry's own columns: mutation, scope, then its sealed bytes.
type EntryRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);
/// A sealed package's columns: event id, descriptor, body, Ack.
type PackageRow = (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>);
/// The saved work a package must still match: payload, state, base, audience.
type SavedRow = (Vec<u8>, String, Vec<u8>, Vec<u8>);
/// A sealed event matching a verified ID: base, descriptor, body, pending actor.
type EchoIdentityRow = (Vec<u8>, Vec<u8>, Vec<u8>, Option<i64>);
/// A typed package an echo judged: id, base, descriptor, Ack.
type EchoRow = (i64, Vec<u8>, Vec<u8>, Option<Vec<u8>>);

fn row(conn: &Connection, id: i64) -> Result<Option<EntryRow>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT mutation,base,audience,event_id,descriptor,body FROM typed_outbox WHERE id=?1",
            [id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()?)
}

fn read_package(conn: &Connection, id: i64) -> Result<Option<StoredTypedPackage>, StoreError> {
    let stored: Option<PackageRow> = conn
        .query_row(
            "SELECT event_id,descriptor,body,ack FROM typed_outbox WHERE id=?1 AND event_id IS NOT NULL",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((id, descriptor, body, ack)) = stored else {
        return Ok(None);
    };
    let event_id = EventId(array(id)?);
    let descriptor = OpaqueEvent::decode(&descriptor).map_err(|_| StoreError::CorruptOutbox)?;
    let object = BodyObject::new(body).map_err(|_| StoreError::CorruptOutbox)?;
    if descriptor.publication_id(bh_sync::Route::Content) != event_id
        || referenced_body(&descriptor).map_err(|_| StoreError::CorruptOutbox)?
            != object.commitment()
    {
        return Err(StoreError::CorruptOutbox);
    }
    let ack = ack
        .map(|bytes| Commitment::decode(&bytes).map_err(|_| StoreError::CorruptOutbox))
        .transpose()?;
    if ack.is_some_and(|record| record.verify_body(&descriptor).is_err()) {
        return Err(StoreError::CorruptOutbox);
    }
    Ok(Some(StoredTypedPackage {
        event_id,
        descriptor,
        body: object.bytes().to_vec(),
        ack,
    }))
}

impl DeviceDatabase {
    /// Save a typed mutation and queue it for publishing in the same
    /// transaction, so the outbox never holds an entry whose work is missing.
    /// The caller supplies host admission: saving a rule change is not the
    /// person's confirmation.
    pub fn submit_typed(
        &mut self,
        core: &dyn CoreCatalogue,
        scope: Scope,
        actor: &Actor,
        op: Operation,
        admission: &dyn HostAdmission,
    ) -> Result<QueuedTyped, SubmitTypedError> {
        self.submit_typed_with_id(core, scope, actor, op, admission, None)
    }

    /// An approval has already bound the exact payload and mutation identity
    /// to this device's signature. The outbox still commits atomically.
    pub fn submit_typed_with_id(
        &mut self,
        core: &dyn CoreCatalogue,
        scope: Scope,
        actor: &Actor,
        op: Operation,
        admission: &dyn HostAdmission,
        mutation: Option<MutationId>,
    ) -> Result<QueuedTyped, SubmitTypedError> {
        self.submit_typed_checked(core, scope, actor, op, admission, mutation, None, || true)
    }

    /// A native host rechecks its generation under its session guard before
    /// the same transaction commits, after the typed outbox insert.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_typed_checked(
        &mut self,
        core: &dyn CoreCatalogue,
        scope: Scope,
        actor: &Actor,
        op: Operation,
        admission: &dyn HostAdmission,
        mutation: Option<MutationId>,
        confirmation: Option<bh_data::admission::PriorRules>,
        current: impl FnOnce() -> bool,
    ) -> Result<QueuedTyped, SubmitTypedError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StoreError::from)?;
        let saved = match mutation {
            Some(id) => pending::submit_with_confirmation(
                &tx,
                core,
                scope,
                actor,
                op,
                admission,
                id,
                confirmation,
            )?,
            None => pending::submit_with_admission(&tx, core, scope, actor, op, admission)?,
        };
        let after_note: i64 = tx
            .query_row("SELECT COALESCE(MAX(id),0) FROM note_updates", [], |r| {
                r.get(0)
            })
            .map_err(StoreError::from)?;
        tx.execute(
            "INSERT INTO typed_outbox(mutation,base,audience,after_note) VALUES(?1,?2,?3,?4)",
            params![
                saved.mutation.0.as_slice(),
                scope.base.as_slice(),
                scope.audience.as_slice(),
                after_note
            ],
        )
        .map_err(StoreError::from)?;
        let package = tx.last_insert_rowid();
        if !current() {
            return Err(StoreError::AuthorityChanged.into());
        }
        tx.commit().map_err(StoreError::from)?;
        Ok(QueuedTyped { saved, package })
    }

    /// The typed outbox entry for a saved mutation, if it was queued here.
    pub fn typed_package_id(&self, mutation: MutationId) -> Result<Option<i64>, StoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT id FROM typed_outbox WHERE mutation=?1",
                [mutation.0.as_slice()],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Phase 1: release the database guard after this call. The native issuer
    /// seals the mutation's exact payload outside all owner and database
    /// guards. Pending and waiting local saves both enter the ordered log;
    /// a package that already exists is returned, never resealed.
    pub fn prepare_typed_package(&self, id: i64) -> Result<TypedPackagePreparation, StoreError> {
        if crate::sync_state::publishing_stopped(&self.connection)? {
            return Err(StoreError::PublishingStopped);
        }
        if let Some(existing) = read_package(&self.connection, id)? {
            return Ok(TypedPackagePreparation::Existing(existing));
        }
        saved_candidate(&self.connection, id).map(TypedPackagePreparation::Candidate)
    }

    /// Phase 2: the short IMMEDIATE CAS rejects a mutation whose saved work
    /// changed or retired. Exactly the bytes handed in are persisted once.
    pub fn publish_typed_package(
        &mut self,
        candidate: TypedPackageCandidate,
        descriptor: OpaqueEvent,
        body: BodyObject,
    ) -> Result<StoredTypedPackage, StoreError> {
        if candidate.event_id.0 == [0; 32]
            || descriptor.nonce() != candidate.event_id
            || referenced_body(&descriptor).map_err(|_| StoreError::InvalidPackage)?
                != body.commitment()
        {
            return Err(StoreError::InvalidPackage);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if crate::sync_state::publishing_stopped(&tx)? {
            return Err(StoreError::PublishingStopped);
        }
        if let Some(existing) = read_package(&tx, candidate.id)? {
            return Ok(existing);
        }
        let stored: Option<SavedRow> = tx
            .query_row(
                "SELECT p.payload,p.state,s.base,s.audience FROM data_pending p
                   JOIN data_scope s ON s.id=p.scope WHERE p.mutation=?1",
                [candidate.mutation.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((payload, state, base, audience)) = stored else {
            return Err(StoreError::RequestConflict);
        };
        if (state != "pending" && state != "waiting")
            || payload != candidate.payload
            || base != candidate.base.as_slice()
            || audience != candidate.audience.as_slice()
            || row(&tx, candidate.id)?.is_none_or(|(m, b, a, _, _, _)| {
                m != candidate.mutation.as_slice() || b != candidate.base || a != candidate.audience
            })
        {
            return Err(StoreError::RequestConflict);
        }
        tx.execute(
            "UPDATE typed_outbox SET event_id=?2,descriptor=?3,body=?4 WHERE id=?1 AND event_id IS NULL",
            params![
                candidate.id,
                descriptor.publication_id(bh_sync::Route::Content).0.as_slice(),
                descriptor.encode(),
                body.bytes()
            ],
        )?;
        let stored = read_package(&tx, candidate.id)?.ok_or(StoreError::CorruptOutbox)?;
        tx.commit()?;
        Ok(stored)
    }

    /// Match the complete ordered record to the immutable package and record
    /// the position it names. An Ack is not acceptance: only the verified echo
    /// decides what became of the work. A duplicate Ack must match exactly.
    pub fn acknowledge_typed_package(
        &mut self,
        id: i64,
        ack: &Commitment,
    ) -> Result<bool, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = read_package(&tx, id)?.ok_or(StoreError::MissingPending)?;
        let base: Vec<u8> =
            tx.query_row("SELECT base FROM typed_outbox WHERE id=?1", [id], |r| {
                r.get(0)
            })?;
        if ack.base().0 != base.as_slice() || ack.verify_body(&stored.descriptor).is_err() {
            return Err(StoreError::AckConflict);
        }
        if let Some(existing) = stored.ack {
            return if existing.encode() == ack.encode() {
                Ok(false)
            } else {
                Err(StoreError::AckConflict)
            };
        }
        let position = signed(ack.head().position)?;
        tx.execute(
            "UPDATE typed_outbox SET ack=?2,staged=1,acked_position=?3,outcome=COALESCE(outcome,1)
             WHERE id=?1",
            params![id, ack.encode(), position],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Phase 1 of a reseal: a fresh candidate for typed package `id`'s saved
    /// work, while the package is kept undecided; for a package under an
    /// epoch content has left (`publish_typed_reseal` checks that).
    pub fn prepare_typed_reseal(
        &self,
        id: i64,
    ) -> Result<Option<TypedPackageCandidate>, StoreError> {
        if crate::sync_state::publishing_stopped(&self.connection)? {
            return Err(StoreError::PublishingStopped);
        }
        let Some(stored) = read_package(&self.connection, id)? else {
            return Ok(None);
        };
        if stored.ack.is_some() || !typed_undecided(&self.connection, id)? {
            return Ok(None);
        }
        saved_candidate(&self.connection, id).map(Some)
    }

    /// Phase 2 of a reseal, in one transaction: package `old` of the same
    /// entry, sealed under `sealed_epoch`, is retired and `candidate`'s exact
    /// new bytes replace it, only while it is still kept undecided as read,
    /// its saved work unchanged, and its base's verified content in another
    /// epoch: content passed the control that replaced it, so it can never
    /// be ordered and its bytes are never sent again. None otherwise.
    pub fn publish_typed_reseal(
        &mut self,
        candidate: TypedPackageCandidate,
        old: EventId,
        sealed_epoch: [u8; 32],
        descriptor: OpaqueEvent,
        body: BodyObject,
    ) -> Result<Option<StoredTypedPackage>, StoreError> {
        if candidate.event_id.0 == [0; 32]
            || descriptor.nonce() != candidate.event_id
            || referenced_body(&descriptor).map_err(|_| StoreError::InvalidPackage)?
                != body.commitment()
        {
            return Err(StoreError::InvalidPackage);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if crate::sync_state::publishing_stopped(&tx)? {
            return Err(StoreError::PublishingStopped);
        }
        let Some(stored) = read_package(&tx, candidate.id)? else {
            return Ok(None);
        };
        if stored.event_id != old
            || stored.ack.is_some()
            || !typed_undecided(&tx, candidate.id)?
            || !crate::sync_state::content_left(&tx, candidate.base, sealed_epoch)?
            || saved_candidate(&tx, candidate.id).ok().is_none_or(|saved| {
                saved.payload != candidate.payload
                    || saved.mutation != candidate.mutation
                    || saved.base != candidate.base
                    || saved.audience != candidate.audience
            })
        {
            return Ok(None);
        }
        tx.execute(
            "UPDATE typed_outbox SET event_id=NULL,descriptor=NULL,body=NULL,staged=0 WHERE id=?1",
            [candidate.id],
        )?;
        tx.execute(
            "UPDATE typed_outbox SET event_id=?2,descriptor=?3,body=?4 WHERE id=?1 AND event_id IS NULL",
            params![
                candidate.id,
                descriptor.publication_id(bh_sync::Route::Content).0.as_slice(),
                descriptor.encode(),
                body.bytes()
            ],
        )?;
        let stored = read_package(&tx, candidate.id)?.ok_or(StoreError::CorruptOutbox)?;
        tx.commit()?;
        Ok(Some(stored))
    }

    /// Record a verified echo's verdict on one of this device's typed
    /// packages in its own short transaction. A caller that applies the
    /// echo's content in the same transaction uses [`record_echo`] instead.
    pub fn record_typed_echo(
        &mut self,
        log: [u8; 32],
        echo: &TypedEcho,
    ) -> Result<Option<i64>, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let recorded = record_echo(&tx, log, echo)?;
        tx.commit()?;
        Ok(recorded)
    }

    /// What became of one typed package, if it has one yet.
    pub fn typed_package_progress(
        &self,
        id: i64,
    ) -> Result<Option<TypedPackageProgress>, StoreError> {
        let stored: Option<(Option<i64>, Option<u8>, Option<u8>)> = self
            .connection
            .query_row(
                "SELECT acked_position,outcome,refusal FROM typed_outbox WHERE id=?1 AND event_id IS NOT NULL",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        stored
            .map(|(position, outcome, refusal)| {
                Ok(TypedPackageProgress {
                    package: id,
                    payload_position: position.map(unsigned).transpose()?,
                    outcome: PackageOutcome::decode(outcome, refusal)?,
                })
            })
            .transpose()
    }

    /// Pending and waiting saves are offered in scope order: the ordered log
    /// judges even work whose local verdict is uncertain. Dropped, rejected
    /// and retired work is not offered or blocking. An acknowledged or judged
    /// package releases the next mutation in its scope.
    ///
    /// Both kinds are read as one order. The typed read seeks per open scope,
    /// not per mutation in an offline backlog or accepted history.
    pub fn outbox_candidates(
        &self,
        after: OutboxOrder,
        before: Option<OutboxOrder>,
        limit: usize,
    ) -> Result<Vec<OutboxCandidate>, StoreError> {
        let limit = limit.min(256);
        let notes = self.note_candidates(after, before, limit)?;
        let typed = self.typed_candidates(after, before, limit)?;
        let mut notes = notes.into_iter().peekable();
        let mut typed = typed.into_iter().peekable();
        let mut out = Vec::with_capacity(limit);
        while out.len() < limit {
            let next = match (notes.peek(), typed.peek()) {
                (Some(note), Some(package)) => {
                    if OutboxCandidate::Note(*note).order()
                        <= OutboxCandidate::Typed(*package).order()
                    {
                        OutboxCandidate::Note(notes.next().expect("peeked"))
                    } else {
                        OutboxCandidate::Typed(typed.next().expect("peeked"))
                    }
                }
                (Some(_), None) => OutboxCandidate::Note(notes.next().expect("peeked")),
                (None, Some(_)) => OutboxCandidate::Typed(typed.next().expect("peeked")),
                (None, None) => break,
            };
            out.push(next);
        }
        Ok(out)
    }

    /// The next package of each note to publish, at most `limit` (≤ 256)
    /// whose first uncovered update is after `after`, in that first id's
    /// order. Typed work shares that order but is not returned here.
    pub fn outbox_heads(&self, after: i64, limit: usize) -> Result<Vec<OutboxHead>, StoreError> {
        self.note_candidates(
            OutboxOrder {
                clock: after,
                kind: 0,
                tie: 0,
            },
            None,
            limit.min(256),
        )
    }

    fn note_candidates(
        &self,
        after: OutboxOrder,
        before: Option<OutboxOrder>,
        limit: usize,
    ) -> Result<Vec<OutboxHead>, StoreError> {
        // Note work has (clock, 0, 0). The wrap bound includes its
        // starting head, as it did before typed work joined the lane.
        let mut stmt = self.connection.prepare_cached(
            "SELECT MIN(CASE WHEN p.outcome IS NULL THEN w.update_id END) AS first,
               u.base,u.audience,u.note
             FROM pending_note_work w CROSS JOIN note_updates u ON u.id=w.update_id
             LEFT JOIN note_outbox_members m ON m.update_id=w.update_id
             LEFT JOIN note_outbox_progress p ON p.update_id=COALESCE(m.package_update_id,w.update_id)
             GROUP BY u.base,u.audience,u.note
             HAVING first>?1
               AND (?2 IS NULL OR first<=?2)
               AND MAX(COALESCE(p.outcome IN (3,4,5),0))=0
             ORDER BY first LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![after.clock, before.map(|b| b.clock), limit as i64],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (first, base, audience, note) = row?;
            let key = NoteKey {
                base: array(base)?,
                audience: array(audience)?,
                note: array(note)?,
            };
            let update_id = match crate::runs::covering(&self.connection, first)? {
                Some(package) => package,
                None => crate::runs::run_end(&self.connection, key, first)?,
            };
            out.push(OutboxHead {
                first,
                update_id,
                key,
            });
        }
        Ok(out)
    }

    fn typed_candidates(
        &self,
        after: OutboxOrder,
        before: Option<OutboxOrder>,
        limit: usize,
    ) -> Result<Vec<TypedHead>, StoreError> {
        // One typed mutation per scope per round trip, in local commit order:
        // the head is the scope's first entry with no outcome and no known
        // ordered position whose saved work is pending or waiting (the
        // ordered log judges waiting work). A future typed payload version
        // can carry a run of operations in one event. Walk distinct open
        // scopes with index seeks, then find the first live save in each.
        // Filtering on the cursor happens after the head lookup: a later
        // mutation must never bypass its scope's head.
        let mut stmt = self.connection.prepare_cached(
            "WITH RECURSIVE scopes(id) AS (
               SELECT (SELECT id FROM typed_outbox INDEXED BY typed_outbox_scope_open
                 WHERE outcome IS NULL AND ordered_position IS NULL
                 ORDER BY base,audience,id LIMIT 1)
               UNION ALL
               SELECT COALESCE(
                 (SELECT next.id FROM typed_outbox next INDEXED BY typed_outbox_scope_open
                  WHERE next.outcome IS NULL AND next.ordered_position IS NULL
                    AND next.base=first.base AND next.audience>first.audience
                  ORDER BY next.audience,next.id LIMIT 1),
                 (SELECT next.id FROM typed_outbox next INDEXED BY typed_outbox_scope_open
                  WHERE next.outcome IS NULL AND next.ordered_position IS NULL
                    AND next.base>first.base
                  ORDER BY next.base,next.audience,next.id LIMIT 1))
               FROM scopes s JOIN typed_outbox first ON first.id=s.id
             )
             SELECT t.after_note,t.id,t.base,t.audience
             FROM scopes s JOIN typed_outbox first ON first.id=s.id
             JOIN typed_outbox t ON t.id=(
               SELECT live.id FROM typed_outbox live INDEXED BY typed_outbox_scope_open
               JOIN data_pending d ON d.mutation=live.mutation
               WHERE live.base=first.base AND live.audience=first.audience
                 AND live.outcome IS NULL AND live.ordered_position IS NULL
                 AND d.state IN ('pending','waiting')
               ORDER BY live.id LIMIT 1)
             WHERE (t.after_note>?1 OR (t.after_note=?1
                 AND (?2<1 OR (?2=1 AND t.id>?3))))
               AND (?4 IS NULL OR t.after_note<?4
                 OR (t.after_note=?4 AND ?5=1 AND t.id<?6))
             ORDER BY t.after_note,t.id LIMIT ?7",
        )?;
        let rows = stmt.query_map(
            params![
                after.clock,
                after.kind,
                after.tie,
                before.map(|b| b.clock),
                before.map(|b| b.kind),
                before.map(|b| b.tie),
                limit as i64
            ],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (after_note, id, base, audience) = row?;
            out.push(TypedHead {
                id,
                base: array(base)?,
                audience: array(audience)?,
                after_note,
            });
        }
        Ok(out)
    }
}

/// Locate a locally sealed event by its ID, not its plaintext mutation.
/// Exactness includes the signed descriptor and encrypted body; a different
/// event under this ID is a conflict even if its typed payload happens to
/// decode to the same operation. Check authorship before applying the payload,
/// since an accepted echo may retire the pending actor row.
pub(crate) fn classify_echo(
    tx: &Transaction<'_>,
    log: [u8; 32],
    event_id: [u8; 32],
    descriptor: &[u8],
    body: &[u8],
    actor: &Actor,
) -> Result<Option<(bool, bool)>, StoreError> {
    let saved: Option<EchoIdentityRow> = tx
        .query_row(
            "SELECT t.base,t.descriptor,t.body,p.actor FROM typed_outbox t
             LEFT JOIN data_pending p ON p.mutation=t.mutation WHERE t.event_id=?1",
            [event_id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((base, sealed, encrypted, own_actor)) = saved else {
        return Ok(None);
    };
    if base != log {
        return Ok(None);
    }
    Ok(Some((
        sealed == descriptor && encrypted == body,
        bh_data::store::actor::matches(tx, own_actor, actor)?,
    )))
}

/// Record arrival of this device's verified typed event, including its exact
/// ordered position and any final verdict. A waiting verdict is `None`: it
/// leaves Acked (or unset) until replay decides the payload. A stored Ack
/// that disagrees with the verified record raises an alarm; the record wins.
/// Returns the package id when this was this device's package.
pub fn record_echo(
    tx: &Transaction<'_>,
    log: [u8; 32],
    echo: &TypedEcho,
) -> Result<Option<i64>, StoreError> {
    let stored: Option<EchoRow> = tx
        .query_row(
            "SELECT id,base,descriptor,ack FROM typed_outbox WHERE event_id=?1",
            [echo.event_id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((id, base, descriptor, ack)) = stored else {
        return Ok(None);
    };
    let position = signed(echo.ordered.head().position)?;
    if echo.publishing_stopped {
        insert_alarm(tx, 1, id, Some(echo.ordered.head().position))?;
    }
    let (outcome, refusal) = echo
        .outcome
        .map(PackageOutcome::code)
        .map_or((None, None), |(code, refusal)| (Some(code), refusal));
    if echo.outcome == Some(PackageOutcome::Conflicted) {
        tx.execute(
            "UPDATE typed_outbox SET outcome=5,refusal=NULL WHERE id=?1",
            [id],
        )?;
        return Ok(Some(id));
    }
    let descriptor = OpaqueEvent::decode(&descriptor).map_err(|_| StoreError::CorruptOutbox)?;
    if echo.ordered.base().0 != log
        || base.as_slice() != log
        || echo.ordered.verify_body(&descriptor).is_err()
    {
        return Err(StoreError::AckConflict);
    }
    match ack {
        Some(existing) if existing.as_slice() == echo.ordered.encode().as_slice() => {}
        existing => {
            if existing.is_some() {
                insert_alarm(tx, 2, id, Some(echo.ordered.head().position))?;
            }
        }
    }
    tx.execute(
        "UPDATE typed_outbox SET ack=?2,staged=1,acked_position=?3,ordered_position=?3,
            outcome=COALESCE(?4,outcome),refusal=CASE WHEN ?4 IS NULL THEN refusal ELSE ?5 END
         WHERE id=?1",
        params![id, echo.ordered.encode(), position, outcome, refusal],
    )?;
    Ok(Some(id))
}

/// Settle only packages whose exact verified echo was recorded at this
/// position. Every lookup uses the ordered-position index, so the cost is
/// proportional to the rows replay actually decided, not outbox history.
pub(crate) fn settle_decided(
    tx: &Transaction<'_>,
    scope: Scope,
    decided: &[(bh_data::Position, Outcome)],
) -> Result<(), StoreError> {
    let mut lookup =
        tx.prepare_cached("SELECT id FROM typed_outbox WHERE base=?1 AND ordered_position=?2")?;
    let mut update = tx.prepare_cached(
        "UPDATE typed_outbox SET outcome=?2,refusal=NULL WHERE id=?1 AND (outcome IS NULL OR outcome=1)",
    )?;
    for (position, outcome) in decided {
        let Some(verdict) = package_verdict(outcome) else {
            continue;
        };
        let id: Option<i64> = lookup
            .query_row(params![scope.base.as_slice(), signed(position.0)?], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(id) = id {
            update.execute(params![id, verdict.code().0])?;
        }
    }
    Ok(())
}

/// Keep one alarm per package, kind and position, so a re-delivered echo
/// does not add duplicates.
fn insert_alarm(
    tx: &Transaction<'_>,
    kind: u8,
    package: i64,
    position: Option<u64>,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO typed_alarm(kind,package,position)
         SELECT ?1,?2,?3 WHERE NOT EXISTS (
           SELECT 1 FROM typed_alarm WHERE kind=?1 AND package=?2 AND position IS ?3)",
        params![kind, package, position.map(signed).transpose()?],
    )?;
    Ok(())
}

/// Whether a typed publishing alarm stops this container's publishing.
pub(crate) fn publishing_stopped(conn: &Connection) -> Result<bool, StoreError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM typed_alarm WHERE kind=1)",
        [],
        |r| r.get(0),
    )?)
}

/// This container's typed alarms, oldest first.
pub(crate) fn alarms(conn: &Connection) -> Result<Vec<(u8, i64, Option<u64>)>, StoreError> {
    let mut stmt =
        conn.prepare_cached("SELECT kind,package,position FROM typed_alarm ORDER BY id")?;
    stmt.query_map([], |r| {
        Ok((
            r.get::<_, u8>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, Option<i64>>(2)?,
        ))
    })?
    .map(|row| {
        let (kind, package, position) = row?;
        Ok((kind, package, position.map(unsigned).transpose()?))
    })
    .collect()
}

/// Typed work counts for the status line: still pending, not yet
/// acknowledged, and ordered but not accepted.
pub(crate) fn summary(conn: &Connection) -> Result<(u64, u64, u64), StoreError> {
    let (unacknowledged, unaccepted, not_accepted): (i64, i64, i64) = conn.query_row(
        "SELECT COALESCE(SUM(d.state IN ('pending','waiting')
                    AND t.outcome IS NULL AND t.ordered_position IS NULL),0),
                COALESCE(SUM(d.state IN ('pending','waiting')),0),
                COALESCE(SUM(COALESCE(t.outcome IN (3,4,5),0)),0)
         FROM data_pending d CROSS JOIN typed_outbox t ON t.mutation=d.mutation",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    Ok((
        unsigned(unacknowledged)?,
        unsigned(unaccepted)?,
        unsigned(not_accepted)?,
    ))
}
