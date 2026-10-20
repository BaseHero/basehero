//! Incoming sync state: each log's verified continuation (its progress, the
//! pinned hosting root and what judging the next event needs), the verified
//! rows a resumed verifier looks up by position and event ID, each note's
//! accepted state (its accepted updates in log order, kept apart from this
//! device's pending work), accepted writer bindings, what became of this
//! device's packages, local alarms and base registration. The native owner
//! verifies and decides; this adapter commits one batch's decisions in one
//! transaction, or nothing. Verified rows are keyed by log and position, so
//! a later covering checkpoint can prune them by range.
use crate::{DeviceDatabase, NoteKey, StoreError, catalogue, read_package};
use bh_core::note::OrderedState;
use bh_sync::{
    BodyObject, Commitment, OpaqueEvent, permit::LogKind, receipt::RECEIPT_LEN, referenced_body,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

pub(crate) fn migrate(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    // Additive: no v10 row is rewritten. A stopped log keeps its progress row
    // exactly as it was; nothing may change it afterwards.
    tx.execute_batch(
        "CREATE TABLE log_progress (
            log_kind INTEGER NOT NULL CHECK(log_kind IN (1,2)),
            log_id BLOB NOT NULL CHECK(length(log_id)=32),
            position INTEGER NOT NULL CHECK(position>=0),
            head_hash BLOB NOT NULL CHECK(length(head_hash)=32),
            receipt BLOB CHECK(receipt IS NULL OR length(receipt)=300),
            control_digest BLOB NOT NULL CHECK(length(control_digest)=32),
            stopped_reason INTEGER CHECK(stopped_reason IS NULL OR stopped_reason BETWEEN 1 AND 255),
            hosting_root BLOB NOT NULL CHECK(length(hosting_root)=32),
            account_position INTEGER CHECK(account_position IS NULL OR account_position>0),
            account_hash BLOB CHECK(account_hash IS NULL OR length(account_hash)=32),
            metadata_id BLOB CHECK(metadata_id IS NULL OR length(metadata_id)=32),
            epoch_id BLOB CHECK(epoch_id IS NULL OR length(epoch_id)=32),
            floor INTEGER NOT NULL CHECK(floor BETWEEN 1 AND 65535),
            CHECK((account_position IS NULL)=(account_hash IS NULL)),
            CHECK(position=0 OR (account_position IS NOT NULL AND metadata_id IS NOT NULL)),
            PRIMARY KEY(log_kind,log_id)
        ) WITHOUT ROWID;
        CREATE TRIGGER log_progress_stop_sticky BEFORE UPDATE ON log_progress
          WHEN OLD.stopped_reason IS NOT NULL
          BEGIN SELECT RAISE(ABORT,'stopped log'); END;
        CREATE TRIGGER log_progress_root_pinned BEFORE UPDATE ON log_progress
          WHEN NEW.hosting_root!=OLD.hosting_root
          BEGIN SELECT RAISE(ABORT,'pinned hosting root'); END;
        CREATE TABLE log_seen (
            log_kind INTEGER NOT NULL, log_id BLOB NOT NULL,
            position INTEGER NOT NULL CHECK(position>0),
            head_hash BLOB NOT NULL CHECK(length(head_hash)=32),
            control_digest BLOB NOT NULL CHECK(length(control_digest)=32),
            account_position INTEGER NOT NULL CHECK(account_position>0),
            account_hash BLOB NOT NULL CHECK(length(account_hash)=32),
            PRIMARY KEY(log_kind,log_id,position)
        ) WITHOUT ROWID;
        CREATE TABLE log_event_id (
            log_kind INTEGER NOT NULL, log_id BLOB NOT NULL,
            event_id BLOB NOT NULL CHECK(length(event_id)=32),
            digest BLOB NOT NULL CHECK(length(digest)=32),
            position INTEGER NOT NULL CHECK(position>0),
            PRIMARY KEY(log_kind,log_id,event_id)
        ) WITHOUT ROWID;
        CREATE TABLE log_account_change (
            log_kind INTEGER NOT NULL, log_id BLOB NOT NULL,
            position INTEGER NOT NULL CHECK(position>0),
            account_event BLOB NOT NULL,
            PRIMARY KEY(log_kind,log_id,position)
        ) WITHOUT ROWID;
        CREATE TABLE log_floor (
            log_kind INTEGER NOT NULL, log_id BLOB NOT NULL,
            position INTEGER NOT NULL CHECK(position>=0),
            floor INTEGER NOT NULL CHECK(floor BETWEEN 1 AND 65535),
            PRIMARY KEY(log_kind,log_id,position)
        ) WITHOUT ROWID;
        CREATE TABLE accepted_note (
            base BLOB NOT NULL CHECK(length(base)=32),
            audience BLOB NOT NULL CHECK(length(audience)=32),
            note BLOB NOT NULL CHECK(length(note)=32),
            ordered_state BLOB NOT NULL,
            through_position INTEGER NOT NULL CHECK(through_position>0),
            PRIMARY KEY(base,audience,note)
        ) WITHOUT ROWID;
        CREATE TABLE accepted_note_tail (
            base BLOB NOT NULL, audience BLOB NOT NULL, note BLOB NOT NULL,
            position INTEGER NOT NULL CHECK(position>0),
            delta BLOB NOT NULL,
            PRIMARY KEY(base,audience,note,position),
            FOREIGN KEY(base,audience,note) REFERENCES accepted_note(base,audience,note)
        ) WITHOUT ROWID;
        CREATE TABLE writer_binding (
            base BLOB NOT NULL, audience BLOB NOT NULL, note BLOB NOT NULL,
            client_id INTEGER NOT NULL CHECK(client_id BETWEEN 0 AND 9007199254740991),
            account BLOB NOT NULL CHECK(length(account)=32),
            device BLOB NOT NULL CHECK(length(device)=32),
            nonce BLOB NOT NULL CHECK(length(nonce)=32),
            accepted_end INTEGER NOT NULL CHECK(accepted_end BETWEEN 0 AND 4294967295),
            PRIMARY KEY(base,audience,note,client_id),
            FOREIGN KEY(base,audience,note) REFERENCES accepted_note(base,audience,note)
        ) WITHOUT ROWID;
        CREATE TRIGGER writer_binding_immutable BEFORE UPDATE ON writer_binding
          WHEN NEW.account!=OLD.account OR NEW.device!=OLD.device OR NEW.nonce!=OLD.nonce
            OR NEW.accepted_end<OLD.accepted_end
          BEGIN SELECT RAISE(ABORT,'immutable writer binding'); END;
        CREATE TABLE note_outbox_progress (
            update_id INTEGER PRIMARY KEY REFERENCES note_outbox(update_id),
            staged INTEGER NOT NULL DEFAULT 0 CHECK(staged IN (0,1)),
            acked_position INTEGER CHECK(acked_position IS NULL OR acked_position>0),
            outcome INTEGER CHECK(outcome IS NULL OR outcome BETWEEN 1 AND 5),
            refusal INTEGER CHECK(refusal IS NULL OR (outcome=3 AND refusal BETWEEN 1 AND 255)),
            CHECK(outcome!=3 OR refusal IS NOT NULL)
        );
        CREATE TABLE sync_alarm (
            id INTEGER PRIMARY KEY,
            kind INTEGER NOT NULL CHECK(kind IN (1,2)),
            update_id INTEGER NOT NULL REFERENCES note_outbox(update_id),
            position INTEGER CHECK(position IS NULL OR position>0)
        );
        CREATE TABLE registration (
            base BLOB PRIMARY KEY CHECK(length(base)=32),
            state INTEGER NOT NULL CHECK(state IN (0,1)),
            genesis_receipt BLOB CHECK(genesis_receipt IS NULL OR length(genesis_receipt)=300)
        );
        CREATE TABLE base_control_outbox (
            base BLOB NOT NULL CHECK(length(base)=32),
            account_position INTEGER NOT NULL CHECK(account_position>1),
            event_id BLOB NOT NULL UNIQUE CHECK(length(event_id)=32),
            descriptor BLOB NOT NULL,
            body BLOB NOT NULL,
            outcome INTEGER CHECK(outcome IS NULL OR outcome IN (1,2)),
            PRIMARY KEY(base,account_position)
        ) WITHOUT ROWID;
        CREATE TRIGGER base_control_exact BEFORE UPDATE ON base_control_outbox
          WHEN NEW.event_id!=OLD.event_id OR NEW.descriptor!=OLD.descriptor OR NEW.body!=OLD.body
            OR OLD.outcome IS NOT NULL
          BEGIN SELECT RAISE(ABORT,'exact base control'); END;
        CREATE TABLE joined_device (
            id INTEGER PRIMARY KEY CHECK(id=1),
            account BLOB NOT NULL CHECK(length(account)=32),
            hint BLOB NOT NULL,
            delivery BLOB,
            added_at INTEGER CHECK(added_at IS NULL OR added_at>1),
            activated INTEGER NOT NULL DEFAULT 0 CHECK(activated IN (0,1)),
            CHECK((delivery IS NULL)=(added_at IS NULL)),
            CHECK(activated=0 OR delivery IS NOT NULL)
        );
        CREATE TRIGGER joined_device_admitted BEFORE UPDATE ON joined_device
          WHEN OLD.delivery IS NOT NULL AND (NEW.account!=OLD.account OR NEW.hint!=OLD.hint
            OR NEW.delivery!=OLD.delivery OR NEW.added_at!=OLD.added_at OR NEW.activated<OLD.activated)
          BEGIN SELECT RAISE(ABORT,'admitted join'); END;",
    )?;
    crate::held_notes::ensure_layout(tx)
}

/// Log kinds, as the hosted service numbers them.
pub const LOG_BASE: u8 = LogKind::Base as u8;
pub const LOG_ACCOUNT: u8 = LogKind::Account as u8;

/// A log's verified continuation: its last durably applied head and what
/// judging the next event needs. Position 0 is the registered, empty log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogProgress {
    pub position: u64,
    pub head_hash: [u8; 32],
    pub receipt: Option<[u8; RECEIPT_LEN]>,
    pub control_digest: [u8; 32],
    /// Set once by a proven contradiction; never cleared.
    pub stopped: Option<u8>,
    /// Pinned at registration from the authenticated hosting association.
    pub hosting_root: [u8; 32],
    /// The account head after the last applied event; None before genesis.
    pub account: Option<(u64, [u8; 32])>,
    pub metadata_id: Option<[u8; 32]>,
    pub epoch_id: Option<[u8; 32]>,
    pub floor: u16,
}

/// What verified history had applied at one position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeenRow {
    pub position: u64,
    pub head_hash: [u8; 32],
    pub control_digest: [u8; 32],
    pub account_position: u64,
    pub account_hash: [u8; 32],
}

/// One applied event's verified rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRecord {
    pub seen: SeenRow,
    pub event_id: [u8; 32],
    pub digest: [u8; 32],
    /// The exact verified account event an accepted account control applied.
    pub account_change: Option<Vec<u8>>,
    /// The version floor the event was judged under, and the floor after it.
    pub judged_floor: u16,
    pub floor: u16,
}

/// A note's accepted state: verified compacted segments, then the accepted
/// updates after them in log order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AcceptedNote {
    pub previous: OrderedState,
    pub tail: Vec<Vec<u8>>,
    pub through: u64,
}
impl AcceptedNote {
    pub fn ordered(&self) -> OrderedState {
        let mut ordered = self.previous.clone();
        for update in &self.tail {
            ordered.push(update.clone());
        }
        ordered
    }
}

/// A writer ID bound by its first accepted use to the author it declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedBinding {
    pub client_id: u64,
    pub account: [u8; 32],
    pub device: [u8; 32],
    pub nonce: [u8; 32],
    pub accepted_end: u32,
}

/// A base's registration record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration {
    pub registered: bool,
    pub genesis_receipt: Option<[u8; RECEIPT_LEN]>,
}

/// This device's sealed package for an event ID, with its exact bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnPackage {
    pub update_id: i64,
    pub key: NoteKey,
    pub descriptor: Vec<u8>,
    pub body: Vec<u8>,
    /// Its local update is still pending work.
    pub pending: bool,
    /// The account and device of the writer that produced it, if linked.
    pub principal: Option<([u8; 32], [u8; 32])>,
    /// A verified echo already decided what became of it: any later event
    /// with its ID reuses that ID and says nothing more about it.
    pub echoed: bool,
}

/// What this device has learned about one of its packages. Only `Accepted`
/// retires local work; every other outcome keeps it, for the person to see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageOutcome {
    /// The append was acknowledged at a position; content not yet judged.
    Acked,
    /// Exact verified echo observed; local content judgment is held.
    Held,
    Accepted,
    /// Ordered, and refused by the writer rule (the owner's reason code).
    Refused(u8),
    /// Ordered as an invalid submission, with no effect.
    Rejected,
    /// Another event holds its event ID, so it cannot be ordered under it.
    Conflicted,
}
impl PackageOutcome {
    fn code(self) -> (u8, Option<u8>) {
        match self {
            Self::Acked => (1, None),
            Self::Held => (6, None),
            Self::Accepted => (2, None),
            Self::Refused(reason) => (3, Some(reason)),
            Self::Rejected => (4, None),
            Self::Conflicted => (5, None),
        }
    }
    fn decode(code: Option<u8>, refusal: Option<u8>) -> Result<Option<Self>, StoreError> {
        Ok(match (code, refusal) {
            (None, None) => None,
            (Some(1), None) => Some(Self::Acked),
            (Some(2), None) => Some(Self::Accepted),
            (Some(3), Some(reason)) => Some(Self::Refused(reason)),
            (Some(4), None) => Some(Self::Rejected),
            (Some(5), None) => Some(Self::Conflicted),
            (Some(6), None) => Some(Self::Held),
            _ => return Err(StoreError::CorruptSyncState),
        })
    }
}

/// One of this device's pending updates and what became of its package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackageProgress {
    pub update_id: i64,
    /// It has a sealed package.
    pub packaged: bool,
    /// The position its Ack or ordered echo named.
    pub position: Option<u64>,
    pub outcome: Option<PackageOutcome>,
}

/// One note's next package to publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboxHead {
    /// Stable pagination key: the first update represented by this head.
    pub first: i64,
    pub update_id: i64,
    pub key: NoteKey,
}

/// What this device's outbox holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboxSummary {
    /// Pending updates with no Ack and no outcome yet.
    pub unacknowledged: u64,
    /// Pending updates not yet accepted, acknowledged or not.
    pub unaccepted: u64,
    /// Distinct notes with pending work, for the status line.
    pub unaccepted_notes: u64,
    /// Notes with a refused, rejected or conflicted package.
    pub not_accepted_notes: u64,
}

/// A verified echo's verdict on one of this device's packages. For
/// `Conflicted`, `ordered` is the event that holds its event ID.
pub struct OwnOutcome {
    pub update_id: i64,
    pub ordered: Commitment,
    pub outcome: PackageOutcome,
    /// This device's own key authored other bytes under its event ID.
    pub publishing_stopped: bool,
}

/// A signed base control copying one account change into a base, kept
/// before it is first sent. `account_position` names its successor: the
/// account head the base's copy of the account reaches once it is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseControl {
    pub base: [u8; 32],
    pub account_position: u64,
    pub event_id: [u8; 32],
    pub descriptor: Vec<u8>,
    pub body: Vec<u8>,
}

/// What verified history proved about a kept base control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlOutcome {
    /// Its exact event is in the verified log.
    Committed = 1,
    /// Another event copied its account change first: this one can never be
    /// ordered after that change.
    Superseded = 2,
}

/// A local alarm: something this device did, or was told, that it must
/// show rather than repair by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncAlarm {
    /// This device's key signed other bytes under one of its event IDs (a
    /// clone or a local bug): it publishes nothing more until resolved.
    PublishingStopped { update_id: i64 },
    /// A stored Ack disagreed with the verified ordered record, which won.
    AckMismatch { update_id: i64, position: u64 },
}

/// One log batch's decisions. `after` is the progress it continues from;
/// `records` are its events' verified rows in log order, the last one the
/// new head.
pub struct IncomingCommit {
    pub log_kind: u8,
    pub log_id: [u8; 32],
    pub hosting_root: [u8; 32],
    pub after: (u64, [u8; 32]),
    pub receipt: [u8; RECEIPT_LEN],
    pub records: Vec<VerifiedRecord>,
    pub metadata_id: [u8; 32],
    pub epoch_id: Option<[u8; 32]>,
    pub notes: Vec<IncomingNote>,
    pub own: Vec<OwnOutcome>,
    pub held: Vec<(NoteKey, Vec<crate::held_notes::HeldEvent>)>,
}

/// One note's share of a batch.
pub struct IncomingNote {
    pub key: NoteKey,
    /// Accepted updates and their log positions, appended to the tail.
    pub accepted: Vec<(u64, Vec<u8>)>,
    /// A verified compaction of the whole accepted state, including
    /// `accepted`; replaces the stored segments and tail.
    pub compacted: Option<OrderedState>,
    pub bindings: Vec<AcceptedBinding>,
    /// Other authors' accepted updates for the working note, in log order,
    /// each with its local request ID.
    pub remote: Vec<([u8; 16], Vec<u8>)>,
    /// Replace the working note with this accepted state after the inserts.
    pub rebuild_working: Option<OrderedState>,
    /// Catalogue title derived from the result, if known.
    pub title: Option<String>,
}

/// Rows a committed note's working state gained, and its new frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedNote {
    pub key: NoteKey,
    pub rows: Vec<i64>,
    pub frontier: i64,
}

fn key_params(key: &NoteKey) -> [&[u8]; 3] {
    [&key.base, &key.audience, &key.note]
}
fn array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::CorruptSyncState)
}
fn unsigned(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::CorruptSyncState)
}
fn signed(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::CorruptSyncState)
}

pub(crate) fn read_progress(
    conn: &rusqlite::Connection,
    kind: u8,
    id: [u8; 32],
) -> Result<Option<LogProgress>, StoreError> {
    type Row = (
        i64,
        Vec<u8>,
        Option<Vec<u8>>,
        Vec<u8>,
        Option<u8>,
        Vec<u8>,
        Option<i64>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        u16,
    );
    let row: Option<Row> = conn
        .query_row(
            "SELECT position,head_hash,receipt,control_digest,stopped_reason,hosting_root,
               account_position,account_hash,metadata_id,epoch_id,floor
             FROM log_progress WHERE log_kind=?1 AND log_id=?2",
            params![kind, id.as_slice()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(position, head, receipt, control, stopped, root, ap, ah, metadata, epoch, floor)| {
            Ok(LogProgress {
                position: unsigned(position)?,
                head_hash: array(head)?,
                receipt: receipt.map(array).transpose()?,
                control_digest: array(control)?,
                stopped,
                hosting_root: array(root)?,
                account: match (ap, ah) {
                    (Some(p), Some(h)) => Some((unsigned(p)?, array(h)?)),
                    (None, None) => None,
                    _ => return Err(StoreError::CorruptSyncState),
                },
                metadata_id: metadata.map(array).transpose()?,
                epoch_id: epoch.map(array).transpose()?,
                floor,
            })
        },
    )
    .transpose()
}

impl DeviceDatabase {
    pub fn log_progress(&self, kind: u8, id: [u8; 32]) -> Result<Option<LogProgress>, StoreError> {
        read_progress(&self.connection, kind, id)
    }

    /// What verified history had applied at `position`, if stored.
    pub fn log_seen(
        &self,
        kind: u8,
        id: [u8; 32],
        position: u64,
    ) -> Result<Option<SeenRow>, StoreError> {
        type Row = (Vec<u8>, Vec<u8>, i64, Vec<u8>);
        let row: Option<Row> = self
            .connection
            .prepare_cached(
                "SELECT head_hash,control_digest,account_position,account_hash FROM log_seen
                 WHERE log_kind=?1 AND log_id=?2 AND position=?3",
            )?
            .query_row(params![kind, id.as_slice(), signed(position)?], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .optional()?;
        row.map(|(head, control, account_position, account_hash)| {
            Ok(SeenRow {
                position,
                head_hash: array(head)?,
                control_digest: array(control)?,
                account_position: unsigned(account_position)?,
                account_hash: array(account_hash)?,
            })
        })
        .transpose()
    }

    /// The digest of the first ordered event in the log with this ID.
    pub fn log_event_digest(
        &self,
        kind: u8,
        id: [u8; 32],
        event_id: [u8; 32],
    ) -> Result<Option<[u8; 32]>, StoreError> {
        let digest: Option<Vec<u8>> = self
            .connection
            .prepare_cached(
                "SELECT digest FROM log_event_id WHERE log_kind=?1 AND log_id=?2 AND event_id=?3",
            )?
            .query_row(params![kind, id.as_slice(), event_id.as_slice()], |r| {
                r.get(0)
            })
            .optional()?;
        digest.map(array).transpose()
    }

    /// The exact verified account events the log's account controls applied,
    /// in position order.
    pub fn log_account_changes(&self, kind: u8, id: [u8; 32]) -> Result<Vec<Vec<u8>>, StoreError> {
        let mut stmt = self.connection.prepare_cached(
            "SELECT account_event FROM log_account_change WHERE log_kind=?1 AND log_id=?2 ORDER BY position",
        )?;
        Ok(stmt
            .query_map(params![kind, id.as_slice()], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// Stored floor rises `(position, floor)`: events after `position` were
    /// judged under at least `floor`.
    pub fn floor_rises(&self, kind: u8, id: [u8; 32]) -> Result<Vec<(u64, u16)>, StoreError> {
        let mut stmt = self.connection.prepare_cached(
            "SELECT position,floor FROM log_floor WHERE log_kind=?1 AND log_id=?2 ORDER BY position",
        )?;
        stmt.query_map(params![kind, id.as_slice()], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, u16>(1)?))
        })?
        .map(|row| {
            let (position, floor) = row?;
            Ok((unsigned(position)?, floor))
        })
        .collect()
    }

    pub fn accepted_note(&self, key: NoteKey) -> Result<AcceptedNote, StoreError> {
        let row: Option<(Vec<u8>, i64)> = self
            .connection
            .query_row(
                "SELECT ordered_state,through_position FROM accepted_note WHERE base=?1 AND audience=?2 AND note=?3",
                key_params(&key),
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((encoded, through)) = row else {
            return Ok(AcceptedNote::default());
        };
        let mut stmt = self.connection.prepare_cached(
            "SELECT delta FROM accepted_note_tail WHERE base=?1 AND audience=?2 AND note=?3 ORDER BY position",
        )?;
        let tail = stmt
            .query_map(key_params(&key), |r| r.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(AcceptedNote {
            previous: OrderedState::decode(&encoded).map_err(|_| StoreError::CorruptSyncState)?,
            tail,
            through: unsigned(through)?,
        })
    }

    /// The last log position that changed this note's accepted state; 0 if
    /// none has. Note-scoped, unlike the common log head.
    pub fn accepted_revision(&self, key: NoteKey) -> Result<u64, StoreError> {
        let through: Option<i64> = self
            .connection
            .query_row(
                "SELECT through_position FROM accepted_note WHERE base=?1 AND audience=?2 AND note=?3",
                key_params(&key),
                |r| r.get(0),
            )
            .optional()?;
        unsigned(through.unwrap_or(0))
    }

    pub fn accepted_binding(
        &self,
        key: NoteKey,
        client_id: u64,
    ) -> Result<Option<AcceptedBinding>, StoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT account,device,nonce,accepted_end FROM writer_binding WHERE base=?1 AND audience=?2 AND note=?3 AND client_id=?4",
                params![key.base.as_slice(), key.audience.as_slice(), key.note.as_slice(), client_id as i64],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(account, device, nonce, end)| {
            Ok(AcceptedBinding {
                client_id,
                account: array(account)?,
                device: array(device)?,
                nonce: array(nonce)?,
                accepted_end: u32::try_from(end).map_err(|_| StoreError::CorruptSyncState)?,
            })
        })
        .transpose()
    }

    /// This device's sealed package with that event ID, if any.
    pub fn own_package(&self, event_id: [u8; 32]) -> Result<Option<OwnPackage>, StoreError> {
        type Row = (
            i64,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            bool,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            bool,
        );
        let row: Option<Row> = self
            .connection
            .query_row(
                "SELECT o.update_id,u.base,u.audience,u.note,o.descriptor,o.body,
                   EXISTS(SELECT 1 FROM pending_note_work p WHERE p.update_id=o.update_id),
                   w.account,w.device,COALESCE(g.outcome,0) IN (2,3,4,5,6)
                 FROM note_outbox o JOIN note_updates u ON u.id=o.update_id
                 LEFT JOIN note_update_writer w ON w.update_id=o.update_id
                 LEFT JOIN note_outbox_progress g ON g.update_id=o.update_id
                 WHERE o.event_id=?1",
                [event_id.as_slice()],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                    ))
                },
            )
            .optional()?;
        row.map(
            |(
                update_id,
                base,
                audience,
                note,
                descriptor,
                body,
                pending,
                account,
                device,
                echoed,
            )| {
                Ok(OwnPackage {
                    update_id,
                    key: NoteKey {
                        base: array(base)?,
                        audience: array(audience)?,
                        note: array(note)?,
                    },
                    descriptor,
                    body,
                    pending,
                    principal: match (account, device) {
                        (Some(a), Some(d)) => Some((array(a)?, array(d)?)),
                        _ => None,
                    },
                    echoed,
                })
            },
        )
        .transpose()
    }

    /// Pending local updates for this note.
    pub fn pending_count(&self, key: NoteKey) -> Result<u64, StoreError> {
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM note_updates u JOIN pending_note_work p ON p.update_id=u.id
             WHERE u.base=?1 AND u.audience=?2 AND u.note=?3",
            key_params(&key),
            |r| r.get(0),
        )?;
        unsigned(count)
    }

    /// What became of one local update's package, if it has one.
    pub fn package_progress(&self, update_id: i64) -> Result<Option<PackageProgress>, StoreError> {
        let package_id = crate::runs::covering(&self.connection, update_id)?.unwrap_or(update_id);
        let row: Option<(Option<i64>, Option<u8>, Option<u8>)> = self
            .connection
            .query_row(
                "SELECT p.acked_position,p.outcome,p.refusal FROM note_outbox o
                 LEFT JOIN note_outbox_progress p USING(update_id) WHERE o.update_id=?1",
                [package_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        row.map(|(position, outcome, refusal)| {
            Ok(PackageProgress {
                update_id,
                packaged: true,
                position: position.map(unsigned).transpose()?,
                outcome: PackageOutcome::decode(outcome, refusal)?,
            })
        })
        .transpose()
    }

    /// This note's local updates that are not accepted yet, oldest first,
    /// at most `limit` (≤ 256) after update `after`: in flight, Acked,
    /// refused, rejected or conflicted. Their work stays in the working note.
    pub fn unaccepted_packages(
        &self,
        key: NoteKey,
        after: i64,
        limit: usize,
    ) -> Result<Vec<PackageProgress>, StoreError> {
        let mut stmt = self.connection.prepare_cached(
            "SELECT w.update_id,m.update_id IS NOT NULL OR o.update_id IS NOT NULL,p.acked_position,p.outcome,p.refusal
             FROM pending_note_work w CROSS JOIN note_updates u ON u.id=w.update_id
             LEFT JOIN note_outbox_members m ON m.update_id=w.update_id
             LEFT JOIN note_outbox o ON o.update_id=w.update_id
             LEFT JOIN note_outbox_progress p ON p.update_id=COALESCE(m.package_update_id,w.update_id)
             WHERE u.base=?1 AND u.audience=?2 AND u.note=?3 AND w.update_id>?4
             ORDER BY w.update_id LIMIT ?5",
        )?;
        let limit = limit.min(256) as i64;
        stmt.query_map(
            params![
                key.base.as_slice(),
                key.audience.as_slice(),
                key.note.as_slice(),
                after,
                limit
            ],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, bool>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Option<u8>>(3)?,
                    r.get::<_, Option<u8>>(4)?,
                ))
            },
        )?
        .map(|row| {
            let (update_id, packaged, position, outcome, refusal) = row?;
            Ok(PackageProgress {
                update_id,
                packaged,
                position: position.map(unsigned).transpose()?,
                outcome: PackageOutcome::decode(outcome, refusal)?,
            })
        })
        .collect()
    }

    /// The next package of each note to publish, at most `limit` (≤ 256)
    /// whose first uncovered update is after `after`, in that first id's
    /// order. The returned update id is the persisted package or the last
    /// update of the bounded run to seal; `first` is the paging cursor.
    /// A note none of whose
    /// pending updates was refused, rejected or conflicted has one; such a
    /// package holds its note back until a deliberate step resolves it.
    pub fn outbox_heads(&self, after: i64, limit: usize) -> Result<Vec<OutboxHead>, StoreError> {
        let mut stmt = self.connection.prepare_cached(
            "SELECT MIN(CASE WHEN p.outcome IS NULL THEN w.update_id END) AS first,u.base,u.audience,u.note
             FROM pending_note_work w CROSS JOIN note_updates u ON u.id=w.update_id
             LEFT JOIN note_outbox_members m ON m.update_id=w.update_id
             LEFT JOIN note_outbox_progress p ON p.update_id=COALESCE(m.package_update_id,w.update_id)
             GROUP BY u.base,u.audience,u.note
             HAVING first>?1 AND MAX(COALESCE(p.outcome IN (3,4,5),0))=0
             ORDER BY first LIMIT ?2",
        )?;
        let limit = limit.min(256) as i64;
        stmt.query_map(params![after, limit], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?
        .map(|row| {
            let (update_id, base, audience, note) = row?;
            let key = NoteKey {
                base: array(base)?,
                audience: array(audience)?,
                note: array(note)?,
            };
            let first = update_id;
            let update_id = match crate::runs::covering(&self.connection, first)? {
                Some(package) => package,
                None => crate::runs::run_end(&self.connection, key, first)?,
            };
            Ok(OutboxHead {
                first,
                update_id,
                key,
            })
        })
        .collect()
    }

    /// Pending updates with no Ack and no outcome, all pending updates, and
    /// notes held back by a refused, rejected or conflicted package.
    pub fn outbox_summary(&self) -> Result<OutboxSummary, StoreError> {
        let (unacknowledged, unaccepted, not_accepted_notes, unaccepted_notes): (i64, i64, i64, i64) =
            self.connection.query_row(
                "SELECT COALESCE(SUM(unacked),0),COALESCE(SUM(pending),0),COALESCE(SUM(held),0),COUNT(*)
                 FROM (SELECT SUM(p.outcome IS NULL) AS unacked,COUNT(*) AS pending,
                   MAX(COALESCE(p.outcome IN (3,4,5),0)) AS held
                   FROM pending_note_work w CROSS JOIN note_updates u ON u.id=w.update_id
                   LEFT JOIN note_outbox_members m ON m.update_id=w.update_id
                   LEFT JOIN note_outbox_progress p ON p.update_id=COALESCE(m.package_update_id,w.update_id)
                   GROUP BY u.base,u.audience,u.note)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
        Ok(OutboxSummary {
            unacknowledged: unsigned(unacknowledged)?,
            unaccepted: unsigned(unaccepted)?,
            unaccepted_notes: unsigned(unaccepted_notes)?,
            not_accepted_notes: unsigned(not_accepted_notes)?,
        })
    }

    /// How many still-pending local commits this package covers.
    pub fn package_pending_count(&self, update_id: i64) -> Result<u64, StoreError> {
        match crate::runs::covered(&self.connection, update_id) {
            Ok(rows) => Ok(rows.len() as u64),
            Err(StoreError::MissingPending) => Ok(0),
            Err(error) => Err(error),
        }
    }

    /// Keep a signed base control before it is first sent, unless one is
    /// kept for the same successor already: that one is returned, never
    /// replaced, so every retry sends its exact bytes.
    pub fn stage_base_control(&mut self, control: &BaseControl) -> Result<BaseControl, StoreError> {
        let descriptor =
            OpaqueEvent::decode(&control.descriptor).map_err(|_| StoreError::InvalidPackage)?;
        let body = BodyObject::new(control.body.clone()).map_err(|_| StoreError::InvalidPackage)?;
        if control.account_position < 2
            || descriptor.id().0 != control.event_id
            || referenced_body(&descriptor).ok() != Some(body.commitment())
        {
            return Err(StoreError::InvalidPackage);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO base_control_outbox(base,account_position,event_id,descriptor,body)
               VALUES (?1,?2,?3,?4,?5) ON CONFLICT(base,account_position) DO NOTHING",
            params![
                control.base.as_slice(),
                signed(control.account_position)?,
                control.event_id.as_slice(),
                control.descriptor,
                control.body
            ],
        )?;
        let stored = read_control(&tx, control.base, control.account_position)?
            .ok_or(StoreError::CorruptOutbox)?;
        tx.commit()?;
        Ok(stored.0)
    }

    /// The kept control for the base's next account successor that verified
    /// history has not settled yet.
    pub fn pending_base_control(&self, base: [u8; 32]) -> Result<Option<BaseControl>, StoreError> {
        let position: Option<i64> = self
            .connection
            .query_row(
                "SELECT MIN(account_position) FROM base_control_outbox WHERE base=?1 AND outcome IS NULL",
                [base.as_slice()],
                |r| r.get(0),
            )?;
        let Some(position) = position else {
            return Ok(None);
        };
        Ok(read_control(&self.connection, base, unsigned(position)?)?.map(|(control, _)| control))
    }

    /// What verified history settled for a kept control: None if none is
    /// kept for that successor, Some(None) while it is pending.
    pub fn base_control_outcome(
        &self,
        base: [u8; 32],
        account_position: u64,
    ) -> Result<Option<Option<ControlOutcome>>, StoreError> {
        Ok(read_control(&self.connection, base, account_position)?.map(|(_, outcome)| outcome))
    }

    /// Record what verified history proved about the kept control with this
    /// event id. The row and its bytes stay; a verdict is never changed.
    pub fn settle_base_control(
        &mut self,
        base: [u8; 32],
        account_position: u64,
        event_id: [u8; 32],
        outcome: ControlOutcome,
    ) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (stored, settled) =
            read_control(&tx, base, account_position)?.ok_or(StoreError::CorruptOutbox)?;
        if stored.event_id != event_id || settled.is_some_and(|s| s != outcome) {
            return Err(StoreError::CorruptOutbox);
        }
        if settled.is_none() {
            tx.execute(
                "UPDATE base_control_outbox SET outcome=?3 WHERE base=?1 AND account_position=?2",
                params![base.as_slice(), signed(account_position)?, outcome as u8],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Local alarms, oldest first.
    pub fn sync_alarms(&self) -> Result<Vec<SyncAlarm>, StoreError> {
        let mut stmt = self
            .connection
            .prepare_cached("SELECT kind,update_id,position FROM sync_alarm ORDER BY id")?;
        stmt.query_map([], |r| {
            Ok((
                r.get::<_, u8>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Option<i64>>(2)?,
            ))
        })?
        .map(|row| match row? {
            (1, update_id, _) => Ok(SyncAlarm::PublishingStopped { update_id }),
            (2, update_id, Some(position)) => Ok(SyncAlarm::AckMismatch {
                update_id,
                position: unsigned(position)?,
            }),
            _ => Err(StoreError::CorruptSyncState),
        })
        .collect()
    }

    /// Whether this container must publish nothing more (a publishing alarm).
    pub fn publishing_stopped(&self) -> Result<bool, StoreError> {
        publishing_stopped(&self.connection)
    }

    /// Commit one verified batch's decisions atomically: the continuation,
    /// the verified rows, accepted state, bindings, working-note deltas and
    /// what became of this device's packages. Any failure, including
    /// `between`, leaves every table unchanged.
    pub fn commit_incoming(
        &mut self,
        commit: &IncomingCommit,
        mut between: impl FnMut(usize) -> Result<(), StoreError>,
    ) -> Result<Vec<CommittedNote>, StoreError> {
        let last = commit
            .records
            .last()
            .ok_or(StoreError::CorruptSyncState)?
            .seen;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let progress = read_progress(&tx, commit.log_kind, commit.log_id)?
            .ok_or(StoreError::MissingProgress)?;
        if progress.stopped.is_some() {
            return Err(StoreError::LogStopped);
        }
        if (progress.position, progress.head_hash) != commit.after {
            return Err(StoreError::StaleProgress);
        }
        if progress.hosting_root != commit.hosting_root {
            return Err(StoreError::RootConflict);
        }
        let (kind, id) = (commit.log_kind, commit.log_id.as_slice());
        let mut floor = progress.floor;
        for record in &commit.records {
            let seen = &record.seen;
            let position = signed(seen.position)?;
            tx.prepare_cached(
                "INSERT INTO log_seen(log_kind,log_id,position,head_hash,control_digest,account_position,account_hash)
                   VALUES (?1,?2,?3,?4,?5,?6,?7)",
            )?
            .execute(params![
                kind,
                id,
                position,
                seen.head_hash.as_slice(),
                seen.control_digest.as_slice(),
                signed(seen.account_position)?,
                seen.account_hash.as_slice()
            ])?;
            // A reused ID keeps its first ordered event's digest.
            tx.prepare_cached(
                "INSERT INTO log_event_id(log_kind,log_id,event_id,digest,position) VALUES (?1,?2,?3,?4,?5)
                 ON CONFLICT DO NOTHING",
            )?
            .execute(params![
                kind,
                id,
                record.event_id.as_slice(),
                record.digest.as_slice(),
                position
            ])?;
            if let Some(change) = &record.account_change {
                tx.execute(
                    "INSERT INTO log_account_change(log_kind,log_id,position,account_event) VALUES (?1,?2,?3,?4)",
                    params![kind, id, position, change],
                )?;
            }
            for (after, raised) in [
                (seen.position - 1, record.judged_floor),
                (seen.position, record.floor),
            ] {
                if raised > floor {
                    tx.execute(
                        "INSERT INTO log_floor(log_kind,log_id,position,floor) VALUES (?1,?2,?3,?4)
                         ON CONFLICT DO UPDATE SET floor=max(floor,excluded.floor)",
                        params![kind, id, signed(after)?, raised],
                    )?;
                    floor = raised;
                }
            }
        }
        tx.execute(
            "UPDATE log_progress SET position=?3,head_hash=?4,receipt=?5,control_digest=?6,
               account_position=?7,account_hash=?8,metadata_id=?9,epoch_id=?10,floor=?11
             WHERE log_kind=?1 AND log_id=?2",
            params![
                kind,
                id,
                signed(last.position)?,
                last.head_hash.as_slice(),
                commit.receipt.as_slice(),
                last.control_digest.as_slice(),
                signed(last.account_position)?,
                last.account_hash.as_slice(),
                commit.metadata_id.as_slice(),
                commit.epoch_id.as_ref().map(|e| e.as_slice()),
                floor
            ],
        )?;
        for own in &commit.own {
            record_own(&tx, commit.log_id, own)?;
        }
        for (key, events) in &commit.held {
            crate::held_notes::insert(&tx, *key, events)?;
        }
        let mut committed = Vec::with_capacity(commit.notes.len());
        for (index, note) in commit.notes.iter().enumerate() {
            between(index)?;
            committed.push(commit_note(&tx, note)?);
        }
        tx.commit()?;
        for note in &commit.notes {
            self.forget_note(note.key);
        }
        Ok(committed)
    }

    /// Latch a proven contradiction. The log's progress and every note's
    /// accepted and working state stay as they are; a later stop keeps the
    /// first reason.
    pub fn record_log_stop(
        &mut self,
        kind: u8,
        id: [u8; 32],
        reason: u8,
    ) -> Result<(), StoreError> {
        if reason == 0 {
            return Err(StoreError::CorruptSyncState);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        match read_progress(&tx, kind, id)? {
            Some(progress) if progress.stopped.is_some() => return Ok(()),
            Some(_) => {
                tx.execute(
                    "UPDATE log_progress SET stopped_reason=?3 WHERE log_kind=?1 AND log_id=?2",
                    params![kind, id.as_slice(), reason],
                )?;
            }
            None => return Err(StoreError::MissingProgress),
        }
        tx.commit()?;
        Ok(())
    }

    pub fn registration(&self, base: [u8; 32]) -> Result<Option<Registration>, StoreError> {
        let row: Option<(u8, Option<Vec<u8>>)> = self
            .connection
            .query_row(
                "SELECT state,genesis_receipt FROM registration WHERE base=?1",
                [base.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        row.map(|(state, receipt)| {
            Ok(Registration {
                registered: state == 1,
                genesis_receipt: receipt.map(array).transpose()?,
            })
        })
        .transpose()
    }

    /// Record a verified registration (the genesis receipt for a base this
    /// device created, or the bootstrap of a joined base), pin the hosting
    /// root from its authenticated hosting association in the base log's
    /// continuation, and latch its writer phase Registered, all in one
    /// transaction. Another root than the one already pinned is refused.
    pub fn record_registration(
        &mut self,
        base: [u8; 32],
        genesis_receipt: Option<[u8; RECEIPT_LEN]>,
        hosting_root: [u8; 32],
    ) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        register(&tx, base, genesis_receipt, hosting_root)?;
        tx.commit()?;
        Ok(())
    }
}

/// `record_registration`'s writes, inside the caller's transaction.
pub(crate) fn register(
    tx: &Transaction<'_>,
    base: [u8; 32],
    genesis_receipt: Option<[u8; RECEIPT_LEN]>,
    hosting_root: [u8; 32],
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO registration(base,state,genesis_receipt) VALUES (?1,1,?2)
         ON CONFLICT(base) DO UPDATE SET state=1,
           genesis_receipt=COALESCE(registration.genesis_receipt,excluded.genesis_receipt)",
        params![
            base.as_slice(),
            genesis_receipt.as_ref().map(|r| r.as_slice())
        ],
    )?;
    tx.execute(
        "INSERT INTO log_progress(log_kind,log_id,position,head_hash,control_digest,hosting_root,floor)
           VALUES (?1,?2,0,zeroblob(32),zeroblob(32),?3,1)
         ON CONFLICT DO NOTHING",
        params![LOG_BASE, base.as_slice(), hosting_root.as_slice()],
    )?;
    let pinned = read_progress(tx, LOG_BASE, base)?.ok_or(StoreError::MissingProgress)?;
    if pinned.hosting_root != hosting_root {
        return Err(StoreError::RootConflict);
    }
    crate::note_writers::mark_registered(tx, base)?;
    Ok(())
}

fn read_control(
    conn: &rusqlite::Connection,
    base: [u8; 32],
    account_position: u64,
) -> Result<Option<(BaseControl, Option<ControlOutcome>)>, StoreError> {
    type Row = (Vec<u8>, Vec<u8>, Vec<u8>, Option<u8>);
    let row: Option<Row> = conn
        .query_row(
            "SELECT event_id,descriptor,body,outcome FROM base_control_outbox
             WHERE base=?1 AND account_position=?2",
            params![base.as_slice(), signed(account_position)?],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    row.map(|(event_id, descriptor, body, outcome)| {
        let outcome = match outcome {
            None => None,
            Some(1) => Some(ControlOutcome::Committed),
            Some(2) => Some(ControlOutcome::Superseded),
            Some(_) => return Err(StoreError::CorruptOutbox),
        };
        Ok((
            BaseControl {
                base,
                account_position,
                event_id: array(event_id)?,
                descriptor,
                body,
            },
            outcome,
        ))
    })
    .transpose()
}

pub(crate) fn publishing_stopped(conn: &rusqlite::Connection) -> Result<bool, StoreError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sync_alarm WHERE kind=1)",
        [],
        |r| r.get(0),
    )?)
}

pub(crate) fn commit_note(
    tx: &Transaction<'_>,
    note: &IncomingNote,
) -> Result<CommittedNote, StoreError> {
    let key = note.key;
    let k = key_params(&key);
    let through = note.accepted.last().map(|(position, _)| *position);
    if let Some(through) = through {
        let through = signed(through)?;
        tx.execute(
            "INSERT INTO accepted_note(base,audience,note,ordered_state,through_position) VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(base,audience,note) DO UPDATE SET through_position=excluded.through_position",
            params![k[0], k[1], k[2], OrderedState::default().encode(), through],
        )?;
        match &note.compacted {
            Some(state) => {
                tx.execute(
                    "UPDATE accepted_note SET ordered_state=?4 WHERE base=?1 AND audience=?2 AND note=?3",
                    params![k[0], k[1], k[2], state.encode()],
                )?;
                tx.execute(
                    "DELETE FROM accepted_note_tail WHERE base=?1 AND audience=?2 AND note=?3",
                    k,
                )?;
            }
            None => {
                for (position, delta) in &note.accepted {
                    tx.execute(
                        "INSERT INTO accepted_note_tail(base,audience,note,position,delta) VALUES (?1,?2,?3,?4,?5)",
                        params![k[0], k[1], k[2], signed(*position)?, delta],
                    )?;
                }
            }
        }
    } else if note.compacted.is_some() || !note.bindings.is_empty() {
        return Err(StoreError::CorruptSyncState);
    }
    for b in &note.bindings {
        tx.execute(
            "INSERT INTO writer_binding(base,audience,note,client_id,account,device,nonce,accepted_end)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(base,audience,note,client_id) DO UPDATE SET accepted_end=excluded.accepted_end,
               account=excluded.account,device=excluded.device,nonce=excluded.nonce",
            params![
                k[0],
                k[1],
                k[2],
                b.client_id as i64,
                b.account.as_slice(),
                b.device.as_slice(),
                b.nonce.as_slice(),
                b.accepted_end
            ],
        )?;
    }
    let mut rows = Vec::with_capacity(note.remote.len());
    for (request, delta) in &note.remote {
        tx.execute(
            "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
            params![k[0], k[1], k[2], request.as_slice(), delta],
        )?;
        rows.push(tx.last_insert_rowid());
    }
    let frontier: i64 = tx.query_row(
        "SELECT COALESCE(MAX(id),0) FROM note_updates WHERE base=?1 AND audience=?2 AND note=?3",
        k,
        |r| r.get(0),
    )?;
    if let Some(state) = &note.rebuild_working {
        // The working note becomes exactly the accepted state: the owner
        // rebuilds only when every own package was accepted and none is
        // pending, so every row up to the frontier is covered.
        tx.execute(
            "INSERT INTO note_checkpoints(base,audience,note,generation,local_frontier,encoded_yjs)
               VALUES (?1,?2,?3,1,?4,?5)
             ON CONFLICT(base,audience,note) DO UPDATE SET generation=generation+1,
               local_frontier=excluded.local_frontier,encoded_yjs=excluded.encoded_yjs",
            params![k[0], k[1], k[2], frontier, state.encode()],
        )?;
    }
    if through.is_some() || !note.remote.is_empty() {
        // Index a note first seen here, then set its title if known.
        catalogue::touch(tx, key, None)?;
        if let Some(title) = &note.title {
            catalogue::touch(tx, key, Some(title))?;
        }
    }
    Ok(CommittedNote {
        key,
        rows,
        frontier,
    })
}

/// Record a verified echo's verdict on one of this device's packages. Only
/// an accepted package retires its pending work. The verified ordered record
/// wins over a stored Ack that disagrees, which is kept as an alarm.
pub(crate) fn record_own(
    tx: &Transaction<'_>,
    log: [u8; 32],
    own: &OwnOutcome,
) -> Result<(), StoreError> {
    let update_id = own.update_id;
    let stored = read_package(tx, update_id)?.ok_or(StoreError::MissingPending)?;
    let position = signed(own.ordered.head().position)?;
    let (outcome, refusal) = own.outcome.code();
    if own.publishing_stopped {
        tx.execute(
            "INSERT INTO sync_alarm(kind,update_id,position) VALUES (1,?1,?2)",
            params![update_id, position],
        )?;
    }
    if own.outcome == PackageOutcome::Conflicted {
        tx.execute(
            "INSERT INTO note_outbox_progress(update_id,outcome) VALUES (?1,5)
             ON CONFLICT(update_id) DO UPDATE SET outcome=5,refusal=NULL",
            [update_id],
        )?;
        return Ok(());
    }
    let base: Vec<u8> = tx.query_row(
        "SELECT base FROM note_updates WHERE id=?1",
        [update_id],
        |r| r.get(0),
    )?;
    if own.ordered.base().0 != log
        || base.as_slice() != log
        || own.ordered.verify_body(&stored.descriptor).is_err()
    {
        return Err(StoreError::AckConflict);
    }
    match stored.ack {
        Some(existing) if existing.encode() == own.ordered.encode() => {}
        existing => {
            if existing.is_some() {
                tx.execute(
                    "INSERT INTO sync_alarm(kind,update_id,position) VALUES (2,?1,?2)",
                    params![update_id, position],
                )?;
            }
            tx.execute(
                "UPDATE note_outbox SET ack=?2 WHERE update_id=?1",
                params![update_id, own.ordered.encode()],
            )?;
        }
    }
    tx.execute(
        "INSERT INTO note_outbox_progress(update_id,staged,acked_position,outcome,refusal) VALUES (?1,1,?2,?3,?4)
         ON CONFLICT(update_id) DO UPDATE SET staged=1,acked_position=excluded.acked_position,
           outcome=excluded.outcome,refusal=excluded.refusal",
        params![update_id, position, outcome, refusal],
    )?;
    if own.outcome == PackageOutcome::Accepted {
        // Keep every original delta/request for local reads and exact
        // request replay; only the run's pending references retire.
        let covered = match crate::runs::covered(tx, update_id) {
            Ok(rows) => rows,
            Err(StoreError::MissingPending) => Vec::new(),
            Err(error) => return Err(error),
        };
        for covered in covered {
            tx.execute("DELETE FROM pending_scope WHERE update_id=?1", [covered])?;
            tx.execute(
                "DELETE FROM pending_note_work WHERE update_id=?1",
                [covered],
            )?;
        }
    }
    Ok(())
}
