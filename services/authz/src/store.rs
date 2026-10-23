//! SQLite on the service's protected disk: verified account histories (a
//! cache the edge can always rebuild), the ordering confirmations this
//! service signed for them and the base registry of verified geneses (state
//! the edge cannot rebuild), each base's control record, which a device
//! rebuilds with M when it is lost, and recovery state: each account's
//! current recovery record and recovery seal, found by the hash of the
//! code's proof alone, the tries against each record and the times each
//! account's kit was used. The connection lock is never held across an
//! await. No key is stored here but inside the recovery objects, which this
//! service cannot open.
//!
//! Account and base projections each record their order format and the
//! canonical opening they reached. A projection recorded before canonical
//! order has neither: it stays as it is, paused, and is never relabelled.
use crate::ServiceError;
use bh_account::{AccountId, Head as AccountHead};
#[cfg(test)]
use bh_event::AccountCopy;
use bh_event::{
    ControlChange, ControlEffect, ControlState, SeenReceiptConflict,
    account_run::{decode_copies, encode_copies},
};
use bh_sync::{BaseId, Commitment, Digest, Head, OrderState, receipt};
#[cfg(test)]
use bh_sync::{EventId, Route};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use std::{path::Path, sync::Mutex};

pub(crate) mod candidate;
#[cfg(test)]
mod candidate_tests;
pub(crate) mod projection;
#[cfg(test)]
mod projection_cost_tests;
#[cfg(test)]
mod projection_tests;

const SCHEMA: i64 = 7;
/// The canonical order format a projection records.
const FORMAT: i64 = 2;

pub(crate) struct Store {
    db: Mutex<Connection>,
}

#[cfg(test)]
thread_local! {
    static FULL_ACCOUNT_READ: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}
#[cfg(test)]
fn take_full_account_read() -> (usize, usize) {
    FULL_ACCOUNT_READ.with(|counter| counter.replace((0, 0)))
}

/// One verified original account event and the body its wrapper carries.
pub(crate) struct StoredEvent {
    pub original: Vec<u8>,
    pub body: Option<Digest>,
}

/// Attached objects admitted with an exact wrapped original. Only an Applied
/// confirmation can activate them; Lapsed consumes the pending row alone.
pub(crate) struct Attachment {
    pub record: Option<Vec<u8>>,
    pub recovery_seal: Vec<u8>,
    pub rotation_body: Option<Vec<u8>>,
}
pub(crate) struct ConfirmedPage<'a> {
    pub confirmations: &'a [(u64, Vec<u8>)],
    pub activations: &'a [(u64, Option<Activation>)],
}
pub(crate) enum Activation {
    Replace {
        old: [u8; 32],
        record: Vec<u8>,
        seal: Vec<u8>,
        prefix: Digest,
    },
    Rotate {
        seal: Vec<u8>,
    },
}

/// An account's verified events in order and its account-log head.
#[cfg(test)]
pub(crate) struct StoredAccount {
    #[allow(dead_code)] // Fixture verifies ordering/head and event rows.
    pub log: [u8; 32],
    pub head: Head,
    /// The canonical opening at `head`; None for a projection recorded
    /// before canonical order.
    pub opening: Option<OrderState>,
    pub events: Vec<StoredEvent>,
    /// The ordering confirmations of its confirmed events, by position, in
    /// order. An event without one is legacy or not yet confirmed.
    #[allow(dead_code)] // Read once account changes are confirmed.
    pub confirmations: Vec<(u64, Vec<u8>)>,
}

/// An account's current recovery record, as its proof check finds it.
pub(crate) struct RecoveryEntry {
    pub account: [u8; 32],
    pub record: Vec<u8>,
    pub recovery_seal: Vec<u8>,
    pub record_digest: [u8; 32],
}

/// The current durable objects that a rotation must match before issuance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryDigests {
    pub record: [u8; 32],
    pub seal: [u8; 32],
}

/// Wrong-password tries against one record, and when the next is allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TryState {
    pub failures: u32,
    pub next_ms: Option<u64>,
}

/// Kit-use notices kept per account: the latest ones.
const NOTICES_KEPT: i64 = 64;

/// What a base's verified genesis established: the creator account and the
/// content epoch (its content key's id). This is the base's state at its
/// genesis only; its control record follows the controls after it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedBase {
    pub account: [u8; 32],
    pub epoch: [u8; 32],
}

/// A base control the service permitted and has not yet seen ordered: the
/// exact event, the control head it must follow, its permits' deadline and
/// its effect, judged with M before the permits were signed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Pending {
    pub event_id: [u8; 32],
    pub after: Head,
    pub deadline_ms: u64,
    pub effect: ControlEffect,
}

/// Whether a base's genesis is known to be ordered. A provisional record
/// holds the exact verified genesis candidate and its account binding only:
/// it grants nothing but that genesis's stage and append retries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Status {
    Provisional = 1,
    Accepted = 2,
}

/// A durable projection, or one recorded before canonical order.
pub(crate) enum Record<T> {
    Legacy,
    Canonical(T),
}

/// A base's canonical projection: its status, control record and pending
/// control.
pub(crate) struct Projection {
    pub status: Status,
    pub state: ControlState,
    pub pending: Option<Pending>,
}

/// The durable base projection a conditional save expects to find
/// unchanged: its status, raw checkpoint and pending control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Prior {
    pub status: Status,
    pub order: OrderState,
    pub pending: Option<Pending>,
}

/// An encountered control fact contradicting a required durable global
/// Head (or its accepted digest/raw opening), distinct from the signed
/// endpoint that authenticates it through a complete raw path.
#[derive(Clone, Copy)]
pub(crate) struct ControlConflict {
    pub known: Head,
    pub observed: Head,
    pub known_digest: Option<Digest>,
    pub observed_digest: Option<Digest>,
    pub known_order: Option<OrderState>,
    pub observed_order: Option<OrderState>,
}
impl Prior {
    pub fn of(status: Status, state: &ControlState, pending: Option<&Pending>) -> Self {
        Self {
            status,
            order: state.order,
            pending: pending.cloned(),
        }
    }
}

/// What a conditional save did.
pub(crate) enum Saved {
    Written,
    /// The durable projection was not the expected one, or the save would
    /// move it back: nothing changed.
    Changed,
    /// The base is bound to another verified genesis owner.
    Conflict,
    /// Independently authenticated contradiction already stopped this base.
    Stopped,
}

fn storage<E>(_: E) -> ServiceError {
    ServiceError::Storage
}
fn array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], rusqlite::Error> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

/// Schema 3 to 4, in one transaction: a copied account event keeps its
/// ordering confirmation (none for an existing, legacy copy), and a pending
/// control keeps the seal set its append must also order. An account event
/// keeps the confirmation this service signed for it; events stored before
/// are legacy and have none. Recovery adds each account's current record
/// and recovery seal (`seal_digest` is the digest account events name it
/// by), found by its proof check; tries per record; kit-use notices; and
/// each submitted recovery attachment until its event is confirmed.
fn upgrade_to_four(db: &mut Connection, new: bool) -> rusqlite::Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(
        "ALTER TABLE base_account_changes ADD COLUMN confirmation BLOB;
         ALTER TABLE base_pending ADD COLUMN seal_set BLOB;
         CREATE TABLE account_confirmations(
           account BLOB NOT NULL, position INTEGER NOT NULL, confirmation BLOB NOT NULL,
           PRIMARY KEY(account, position));
         CREATE TABLE recovery_index(
           proof_check BLOB PRIMARY KEY, account BLOB NOT NULL, record_digest BLOB NOT NULL);
         CREATE TABLE recovery_records(
           account BLOB PRIMARY KEY, record BLOB NOT NULL, recovery_seal BLOB NOT NULL,
           record_digest BLOB NOT NULL, seal_digest BLOB NOT NULL);
         CREATE TABLE recovery_tries(
           record_digest BLOB PRIMARY KEY, failures INTEGER NOT NULL,
           fifth_failure_ms INTEGER, next_ms INTEGER);
         CREATE TABLE recovery_notices(
           account BLOB NOT NULL, time_ms INTEGER NOT NULL, PRIMARY KEY(account, time_ms));
         CREATE TABLE pending_attachments(
           account BLOB NOT NULL, event BLOB NOT NULL, record BLOB,
           recovery_seal BLOB NOT NULL, rotation_body BLOB,
           PRIMARY KEY(account, event));",
    )?;
    if new {
        tx.execute("INSERT INTO meta(key, value) VALUES('schema', 4)", [])?;
    } else {
        tx.execute("UPDATE meta SET value=4 WHERE key='schema' AND value=3", [])?;
    }
    tx.commit()
}

/// Schema 4 to 5, in one transaction: each account and base projection
/// records its order format and canonical opening, and a base its genesis
/// status and every raw control's first-used routed ID. Existing rows get
/// none: they predate canonical order and stay paused.
fn upgrade_to_five(db: &mut Connection) -> rusqlite::Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(
        "ALTER TABLE accounts ADD COLUMN format INTEGER;
         ALTER TABLE accounts ADD COLUMN opening BLOB;
         ALTER TABLE base_controls ADD COLUMN format INTEGER;
         ALTER TABLE base_controls ADD COLUMN status INTEGER;
         ALTER TABLE base_controls ADD COLUMN raw_order BLOB;
         CREATE TABLE base_control_ids(
           base BLOB NOT NULL, id BLOB NOT NULL, position INTEGER NOT NULL,
           PRIMARY KEY(base, id));
         UPDATE meta SET value=5 WHERE key='schema' AND value=4;",
    )?;
    tx.commit()
}

fn upgrade_to_six(db: &mut Connection) -> rusqlite::Result<()> {
    let tx = db.transaction()?;
    projection::schema(&tx)?;
    tx.execute("UPDATE meta SET value=6 WHERE key='schema' AND value=5", [])?;
    tx.commit()
}

/// Schema 6 to 7, in one transaction: BASE copy generations, their staged
/// raw controls and routed first uses, copied suffixes, and a stop's
/// reference to the staged path it pins. Existing rows are unchanged; a
/// base record without a BASE copy stays unsupported, never replayed.
fn upgrade_to_seven(db: &mut Connection) -> rusqlite::Result<()> {
    let tx = db.transaction()?;
    candidate::schema(&tx)?;
    tx.execute("UPDATE meta SET value=7 WHERE key='schema' AND value=6", [])?;
    tx.commit()
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, ServiceError> {
        let mut db = Connection::open(path).map_err(storage)?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS accounts(
               account BLOB PRIMARY KEY, log BLOB NOT NULL,
               position INTEGER NOT NULL, log_hash BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS account_events(
               account BLOB NOT NULL, position INTEGER NOT NULL, bytes BLOB NOT NULL,
               body BLOB, PRIMARY KEY(account, position));
             CREATE TABLE IF NOT EXISTS bases(
               base BLOB PRIMARY KEY, account BLOB NOT NULL, epoch BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS base_stops(
               base BLOB PRIMARY KEY, kind INTEGER NOT NULL,
               remembered BLOB, observed BLOB, receipt BLOB,
               remembered_receipt BLOB, known_position INTEGER,
               known_hash BLOB, seen_receipt BLOB, scan_controls BLOB,
               hosting_root BLOB, observed_hash BLOB,
               known_digest BLOB, observed_digest BLOB,
               conflict_order BLOB);
             CREATE TABLE IF NOT EXISTS base_controls(
               base BLOB PRIMARY KEY, creator BLOB NOT NULL, hosting_root BLOB NOT NULL,
               metadata_id BLOB NOT NULL, epoch BLOB, floor INTEGER NOT NULL,
               control_position INTEGER NOT NULL, control_hash BLOB NOT NULL,
               control_digest BLOB NOT NULL,
               head_position INTEGER NOT NULL, head_hash BLOB NOT NULL,
               account_position INTEGER NOT NULL, account_hash BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS base_account_changes(
               base BLOB NOT NULL, position INTEGER NOT NULL, bytes BLOB NOT NULL,
               PRIMARY KEY(base, position));
             CREATE TABLE IF NOT EXISTS base_pending(
               base BLOB PRIMARY KEY, event_id BLOB NOT NULL,
               after_position INTEGER NOT NULL, after_hash BLOB NOT NULL,
               deadline INTEGER NOT NULL, digest BLOB NOT NULL, epoch_after BLOB,
               account_position INTEGER NOT NULL, account_hash BLOB NOT NULL,
               change INTEGER NOT NULL, account_event BLOB NOT NULL, floor INTEGER NOT NULL,
               seen_position INTEGER NOT NULL, judged_control BLOB NOT NULL,
               judged_account_position INTEGER NOT NULL, judged_account_hash BLOB NOT NULL);",
        )
        .map_err(storage)?;
        let schema: Option<i64> = db
            .query_row("SELECT value FROM meta WHERE key='schema'", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(storage)?;
        match schema {
            // A new disk takes the schema-3 tables above, then every step.
            None | Some(3) => {
                upgrade_to_four(&mut db, schema.is_none()).map_err(storage)?;
                upgrade_to_five(&mut db).map_err(storage)?;
                upgrade_to_six(&mut db).map_err(storage)?;
                upgrade_to_seven(&mut db).map_err(storage)?;
            }
            Some(4) => {
                upgrade_to_five(&mut db).map_err(storage)?;
                upgrade_to_six(&mut db).map_err(storage)?;
                upgrade_to_seven(&mut db).map_err(storage)?;
            }
            Some(5) => {
                upgrade_to_six(&mut db).map_err(storage)?;
                upgrade_to_seven(&mut db).map_err(storage)?;
            }
            Some(6) => upgrade_to_seven(&mut db).map_err(storage)?,
            Some(SCHEMA) => {}
            Some(_) => return Err(ServiceError::Storage),
        }
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS account_time_floors(
               account BLOB PRIMARY KEY, earliest INTEGER NOT NULL, latest INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS retire_home(
               account BLOB PRIMARY KEY, prefix_digest BLOB NOT NULL);",
        )
        .map_err(storage)?;
        let rotation_column: bool = db
            .prepare("PRAGMA table_info(pending_attachments)")
            .map_err(storage)?
            .query_map([], |r| r.get::<_, String>(1))
            .map_err(storage)?
            .any(|name| name.as_deref() == Ok("rotation_body"));
        if !rotation_column {
            db.execute_batch("ALTER TABLE pending_attachments ADD COLUMN rotation_body BLOB;")
                .map_err(storage)?;
        }
        // A derived index of confirmed wrapped events. Backfill older disks
        // once; inserts thereafter share the confirmation transaction.
        let indexed: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='confirmed_events')",
                [],
                |r| r.get(0),
            )
            .map_err(storage)?;
        if !indexed {
            let tx = db.transaction().map_err(storage)?;
            tx.execute_batch(
                "CREATE TABLE confirmed_events(
                   account BLOB NOT NULL, event BLOB NOT NULL, position INTEGER NOT NULL,
                   PRIMARY KEY(account, event));",
            )
            .map_err(storage)?;
            {
                let mut rows = tx
                    .prepare(
                        "SELECT e.account, e.position, e.bytes, e.body
                              FROM account_events e JOIN account_confirmations c
                              ON e.account=c.account AND e.position=c.position",
                    )
                    .map_err(storage)?;
                let mut query = rows.query([]).map_err(storage)?;
                while let Some(row) = query.next().map_err(storage)? {
                    let account: Vec<u8> = row.get(0).map_err(storage)?;
                    let position: i64 = row.get(1).map_err(storage)?;
                    let original: Vec<u8> = row.get(2).map_err(storage)?;
                    let body: Option<Vec<u8>> = row.get(3).map_err(storage)?;
                    let wrapped = bh_authz_proto::account_log_wrap(
                        &original,
                        body.map(array::<32>)
                            .transpose()
                            .map_err(storage)?
                            .map(Digest),
                    )
                    .map_err(storage)?;
                    tx.execute(
                        "INSERT INTO confirmed_events(account, event, position) VALUES(?1,?2,?3)",
                        params![account, wrapped.digest().0.as_slice(), position],
                    )
                    .map_err(storage)?;
                }
            }
            tx.commit().map_err(storage)?;
        }
        Ok(Self { db: Mutex::new(db) })
    }

    fn with<R>(
        &self,
        run: impl FnOnce(&mut Connection) -> rusqlite::Result<R>,
    ) -> Result<R, ServiceError> {
        let mut db = self.db.lock().map_err(storage)?;
        run(&mut db).map_err(storage)
    }

    /// `with`, for candidate staging only: its commit skips its own sync.
    /// Staging is unreachable until a later FULL publication or stop commit,
    /// whose WAL sync makes these earlier frames durable too; a crash before
    /// then loses only unreachable staging. FULL is back before the lock is
    /// released; if it cannot be, the poisoned lock fails every later use.
    fn staging<R>(
        &self,
        run: impl FnOnce(&mut Connection) -> rusqlite::Result<R>,
    ) -> Result<R, ServiceError> {
        let mut db = self.db.lock().map_err(storage)?;
        db.pragma_update(None, "synchronous", "NORMAL")
            .map_err(storage)?;
        let result = run(&mut db);
        db.pragma_update(None, "synchronous", "FULL")
            .expect("restore synchronous=FULL");
        result.map_err(storage)
    }

    #[cfg(test)]
    pub fn account(&self, account: &[u8; 32]) -> Result<Option<StoredAccount>, ServiceError> {
        self.with(|db| {
            let Some((log, position, hash, opening)) = db
                .query_row(
                    "SELECT log, position, log_hash, format, opening FROM accounts
                     WHERE account=?1",
                    [account.as_slice()],
                    |r| {
                        Ok((
                            r.get::<_, Vec<u8>>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, Vec<u8>>(2)?,
                            canonical(r.get(3)?, r.get(4)?)?,
                        ))
                    },
                )
                .optional()?
            else {
                return Ok(None);
            };
            let mut statement = db.prepare(
                "SELECT bytes, body FROM account_events WHERE account=?1 ORDER BY position",
            )?;
            let events = statement
                .query_map([account.as_slice()], |r| {
                    Ok(StoredEvent {
                        original: r.get(0)?,
                        body: r
                            .get::<_, Option<Vec<u8>>>(1)?
                            .map(array)
                            .transpose()?
                            .map(Digest),
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            if events.len() as i64 != position {
                return Err(rusqlite::Error::InvalidQuery);
            }
            projection::full_read_work(events.len(), events.iter().map(|e| e.original.len()).sum());
            FULL_ACCOUNT_READ.with(|counter| {
                let (rows, bytes) = counter.get();
                counter.set((
                    rows + events.len(),
                    bytes + events.iter().map(|e| e.original.len()).sum::<usize>(),
                ));
            });
            let mut statement = db.prepare(
                "SELECT position, confirmation FROM account_confirmations WHERE account=?1
                 ORDER BY position",
            )?;
            let confirmations = statement
                .query_map([account.as_slice()], |r| {
                    Ok((r.get::<_, i64>(0)? as u64, r.get(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let log = array(log)?;
            let head = Head {
                position: position as u64,
                hash: Digest(array(hash)?),
            };
            if opening.is_some_and(|o| o.head(BaseId(log)) != head) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(Some(StoredAccount {
                log,
                head,
                opening,
                events,
                confirmations,
            }))
        })
    }

    /// Commit the exact originals, proofs, index, current checkpoint, historical
    /// grid and APPLIED body outcomes under the same writer lock and CAS.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn extend_projected(
        &self,
        account: &[u8; 32],
        log: &[u8; 32],
        previous: OrderState,
        after: OrderState,
        events: &[StoredEvent],
        page: ConfirmedPage<'_>,
        write: &projection::ProjectionWrite,
        applied: &[projection::AppliedBody],
    ) -> Result<projection::Pin, ServiceError> {
        let prepared = projection::prepare_projection(
            previous,
            events,
            ConfirmedPage {
                confirmations: page.confirmations,
                activations: page.activations,
            },
            write,
        )
        .map_err(|_| ServiceError::Storage)?;
        self.extend_inner(
            account,
            log,
            previous,
            after,
            events,
            page,
            Some((write, applied, &prepared)),
        )?
        .ok_or(ServiceError::Storage)
    }

    /// Legacy direct-write fixture only. Production callers must supply a
    /// checkpoint and its delta; they cannot commit a projectionless page.
    #[cfg(test)]
    pub(crate) fn extend(
        &self,
        account: &[u8; 32],
        log: &[u8; 32],
        previous: OrderState,
        after: OrderState,
        events: &[StoredEvent],
        page: ConfirmedPage<'_>,
    ) -> Result<(), ServiceError> {
        self.extend_inner(account, log, previous, after, events, page, None)
            .map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    fn extend_inner(
        &self,
        account: &[u8; 32],
        log: &[u8; 32],
        previous: OrderState,
        after: OrderState,
        events: &[StoredEvent],
        page: ConfirmedPage<'_>,
        projection: Option<(
            &projection::ProjectionWrite,
            &[projection::AppliedBody],
            &projection::PreparedProjection<'_>,
        )>,
    ) -> Result<Option<projection::Pin>, ServiceError> {
        let head = after.head(BaseId(*log));
        if previous.position().checked_add(events.len() as u64) != Some(after.position()) {
            return Err(ServiceError::Storage);
        }
        let previous_head = previous.head(BaseId(*log));
        self.with(|db| {
            let tx = db.transaction()?;
            let stored = tx.query_row(
                "SELECT log, position, log_hash, format, opening FROM accounts WHERE account=?1",
                [account.as_slice()],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?, canonical(r.get(3)?, r.get(4)?)?)),
            ).optional()?;
            // A projection from before canonical order, or a checkpoint
            // whose redundant log/head was replaced, is never extended.
            if stored.is_some_and(|(stored_log, position, hash, opening)|
                stored_log != log || position != previous_head.position as i64
                    || hash != previous_head.hash.0 || opening != Some(previous)) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let previous = previous_head;
            for (i, event) in events.iter().enumerate() {
                tx.execute(
                    "INSERT INTO account_events(account, position, bytes, body)
                     VALUES(?1, ?2, ?3, ?4)",
                    params![
                        account.as_slice(),
                        (previous.position as i64) + 1 + i as i64,
                        event.original,
                        event.body.map(|b| b.0.to_vec()),
                    ],
                )?;
            }
            let appended = previous.position + 1..=previous.position + events.len() as u64;
            for (position, confirmation) in page.confirmations {
                if !appended.contains(position) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                let event = &events[(*position - previous.position - 1) as usize];
                let wrapped = bh_authz_proto::account_log_wrap(&event.original, event.body)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                tx.execute(
                    "INSERT INTO account_confirmations(account, position, confirmation)
                     VALUES(?1, ?2, ?3)",
                    params![account.as_slice(), *position as i64, confirmation],
                )?;
                tx.execute(
                    "INSERT INTO confirmed_events(account, event, position) VALUES(?1, ?2, ?3)",
                    params![account.as_slice(), wrapped.digest().0.as_slice(), *position as i64],
                )?;
            }
            for (position, effect) in page.activations {
                if !appended.contains(position) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                let event = &events[(*position - previous.position - 1) as usize];
                let wrapped = bh_authz_proto::account_log_wrap(&event.original, event.body)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                if tx.execute("DELETE FROM pending_attachments WHERE account=?1 AND event=?2",
                    params![account.as_slice(), wrapped.digest().0.as_slice()])? != 1 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                match effect {
                    Some(Activation::Replace { old, record, seal, prefix }) => {
                        let checks = bh_account::recovery::record_checks(record)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?;
                        if checks.account.0 != *account {
                            return Err(rusqlite::Error::InvalidQuery);
                        }
                        let current = tx.query_row(
                            "SELECT record_digest FROM recovery_records WHERE account=?1",
                            [account.as_slice()], |r| array::<32>(r.get(0)?),
                        ).optional()?;
                        match current {
                            Some(digest) if digest == *old => {
                                tx.execute("DELETE FROM recovery_records WHERE account=?1",
                                    [account.as_slice()])?;
                                tx.execute("DELETE FROM recovery_index WHERE account=?1 AND record_digest=?2",
                                    params![account.as_slice(), old.as_slice()])?;
                                tx.execute("DELETE FROM recovery_tries WHERE record_digest=?1",
                                    [old.as_slice()])?;
                            }
                            None => {} // Signup's initial home objects were not yet stored.
                            Some(_) => return Err(rusqlite::Error::InvalidQuery),
                        }
                        tx.execute("INSERT INTO recovery_index(proof_check,account,record_digest)
                                    VALUES(?1,?2,?3)",
                            params![checks.proof_check.as_slice(),account.as_slice(),checks.digest.as_slice()])?;
                        tx.execute("INSERT INTO recovery_records(account,record,recovery_seal,record_digest,seal_digest)
                                    VALUES(?1,?2,?3,?4,?5)",
                            params![account.as_slice(),record,seal,checks.digest.as_slice(),
                                    bh_account::personal::seal_digest(seal).as_slice()])?;
                        tx.execute("INSERT OR REPLACE INTO retire_home(account,prefix_digest) VALUES(?1,?2)",
                            params![account.as_slice(),prefix.0.as_slice()])?;
                    }
                    Some(Activation::Rotate { seal }) => {
                        let updated = tx.execute("UPDATE recovery_records SET recovery_seal=?2, seal_digest=?3
                                       WHERE account=?1", params![account.as_slice(),seal,
                            bh_account::personal::seal_digest(seal).as_slice()])?;
                        if updated != 1 { return Err(rusqlite::Error::InvalidQuery); }
                    }
                    None => {}
                }
            }
            tx.execute(
                "INSERT INTO accounts(account, log, position, log_hash, format, opening)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(account) DO UPDATE SET position=?3, log_hash=?4, opening=?6",
                params![
                    account.as_slice(),
                    log.as_slice(),
                    head.position as i64,
                    head.hash.0.as_slice(),
                    FORMAT,
                    after.encode().as_slice(),
                ],
            )?;
            let committed = if let Some((write, applied, prepared)) = projection {
                let pin = write.header.pin;
                if pin.key.account.0 != *account
                    || !matches!(pin.key.source, projection::Source::Home(source) if source.kind == bh_authz_proto::LogKind::Account && source.id == *log)
                    || write.header.opening != after
                    || write.delta.expected.0 != previous.position
                    || write.delta.through.0 != after.position()
                    || applied.len() > events.len()
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                projection::write_projection(&tx, write, prepared)?;
                for body in applied {
                    if !appended.contains(&body.position)
                        || events[(body.position - previous.position - 1) as usize].body != Some(body.digest)
                        || !page.confirmations.iter().any(|(position, _)| *position == body.position)
                    {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    tx.execute("INSERT OR IGNORE INTO account_applied_bodies(account,kind,source,generation,digest,position)
                        VALUES(?1,1,?2,?3,?4,?5)",params![account.as_slice(),log.as_slice(),i64::try_from(pin.generation).map_err(|_|rusqlite::Error::InvalidQuery)?,body.digest.0.as_slice(),i64::try_from(body.position).map_err(|_|rusqlite::Error::InvalidQuery)?])?;
                }
                Some(pin)
            } else { None };
            tx.commit()?;
            Ok(committed)
        })
    }

    /// Retain the exact submitted attachment before issuing an append permit.
    /// Repeating the same event with different objects is refused.
    pub fn stage_attachment(
        &self,
        account: &[u8; 32],
        event: Digest,
        attachment: &Attachment,
    ) -> Result<bool, ServiceError> {
        self.with(|db| {
            db.execute(
                "INSERT OR IGNORE INTO pending_attachments(account,event,record,recovery_seal,rotation_body)
                 VALUES(?1,?2,?3,?4,?5)",
                params![account.as_slice(), event.0.as_slice(), attachment.record,
                        attachment.recovery_seal, attachment.rotation_body],
            )?;
            let held: (Option<Vec<u8>>, Vec<u8>, Option<Vec<u8>>) = db.query_row(
                "SELECT record,recovery_seal,rotation_body FROM pending_attachments
                 WHERE account=?1 AND event=?2",
                params![account.as_slice(), event.0.as_slice()],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
            )?;
            Ok(held == (attachment.record.clone(), attachment.recovery_seal.clone(), attachment.rotation_body.clone()))
        })
    }

    /// Current durable record and seal digests required before a rotation
    /// can be permitted; unlike replacement, rotation carries no record.
    pub fn recovery_digests(
        &self,
        account: &[u8; 32],
    ) -> Result<Option<RecoveryDigests>, ServiceError> {
        self.with(|db| {
            db.query_row(
                "SELECT record_digest, seal_digest FROM recovery_records WHERE account=?1",
                [account.as_slice()],
                |r| {
                    Ok(RecoveryDigests {
                        record: array(r.get(0)?)?,
                        seal: array(r.get(1)?)?,
                    })
                },
            )
            .optional()
        })
    }

    pub fn attachment(
        &self,
        account: &[u8; 32],
        event: Digest,
    ) -> Result<Option<Attachment>, ServiceError> {
        self.with(|db| db.query_row(
            "SELECT record,recovery_seal,rotation_body FROM pending_attachments WHERE account=?1 AND event=?2",
            params![account.as_slice(), event.0.as_slice()],
            |r| Ok(Attachment { record: r.get(0)?, recovery_seal: r.get(1)?, rotation_body: r.get(2)? }),
        ).optional())
    }

    pub fn retire_pending(&self, account: &[u8; 32]) -> Result<Option<Digest>, ServiceError> {
        self.with(|db| {
            db.query_row(
                "SELECT prefix_digest FROM retire_home WHERE account=?1",
                [account.as_slice()],
                |r| Ok(Digest(array(r.get(0)?)?)),
            )
            .optional()
        })
    }

    pub fn retire_done(&self, account: &[u8; 32], prefix: Digest) -> Result<(), ServiceError> {
        self.with(|db| {
            db.execute(
                "DELETE FROM retire_home WHERE account=?1 AND prefix_digest=?2",
                params![account.as_slice(), prefix.0.as_slice()],
            )?;
            Ok(())
        })
    }

    /// Highest bounds of an accepted-head answer already issued for this account.
    pub fn time_floor(
        &self,
        account: &[u8; 32],
    ) -> Result<Option<bh_sync::evidence::TimeBounds>, ServiceError> {
        self.with(|db| {
            db.query_row(
                "SELECT earliest, latest FROM account_time_floors WHERE account=?1",
                [account.as_slice()],
                |row| {
                    Ok(bh_sync::evidence::TimeBounds {
                        earliest_ms: row.get::<_, i64>(0)? as u64,
                        latest_ms: row.get::<_, i64>(1)? as u64,
                    })
                },
            )
            .optional()
        })
    }

    pub fn remember_time(
        &self,
        account: &[u8; 32],
        bounds: bh_sync::evidence::TimeBounds,
    ) -> Result<(), ServiceError> {
        self.with(|db| {
            db.execute("INSERT INTO account_time_floors(account, earliest, latest) VALUES(?1,?2,?3)
                ON CONFLICT(account) DO UPDATE SET earliest=MAX(earliest,excluded.earliest), latest=MAX(latest,excluded.latest)",
                params![account.as_slice(), bounds.earliest_ms as i64, bounds.latest_ms as i64])?;
            Ok(())
        })
    }

    /// The confirmation this service signed for the event at `position`.
    pub fn confirmation(
        &self,
        account: &[u8; 32],
        position: u64,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        self.with(|db| {
            db.query_row(
                "SELECT confirmation FROM account_confirmations WHERE account=?1 AND position=?2",
                params![account.as_slice(), position as i64],
                |r| r.get(0),
            )
            .optional()
        })
    }

    /// Confirmation of this exact wrapped event, in the account-local index.
    pub fn confirmed_event(
        &self,
        account: &[u8; 32],
        event: Digest,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        self.with(|db| {
            db.query_row(
                "SELECT c.confirmation FROM confirmed_events i
                 JOIN account_confirmations c ON c.account=i.account AND c.position=i.position
                 WHERE i.account=?1 AND i.event=?2",
                params![account.as_slice(), event.0.as_slice()],
                |r| r.get(0),
            )
            .optional()
        })
    }

    /// The verified original at `position` of the account's history.
    pub fn account_event(
        &self,
        account: &[u8; 32],
        position: u64,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        self.with(|db| {
            db.query_row(
                "SELECT bytes FROM account_events WHERE account=?1 AND position=?2",
                params![account.as_slice(), position as i64],
                |r| r.get(0),
            )
            .optional()
        })
    }

    pub fn base(&self, base: &[u8; 32]) -> Result<Option<VerifiedBase>, ServiceError> {
        self.with(|db| {
            db.query_row(
                "SELECT account, epoch FROM bases WHERE base=?1",
                [base.as_slice()],
                |r| {
                    Ok(VerifiedBase {
                        account: array(r.get(0)?)?,
                        epoch: array(r.get(1)?)?,
                    })
                },
            )
            .optional()
        })
    }
}

impl Store {
    /// Make `record` and `recovery_seal` the account's current recovery
    /// objects, in one transaction, and index the record by its proof check.
    /// With `retire`, they replace the account's record of that digest,
    /// whose index and tries go with it; without, they are the account's
    /// first record. The same record again replaces only its seal. Returns
    /// whether it wrote: any other current record stands.
    pub fn put_recovery(
        &self,
        account: &[u8; 32],
        record: &[u8],
        recovery_seal: &[u8],
        retire: Option<[u8; 32]>,
    ) -> Result<bool, ServiceError> {
        let checks = bh_account::recovery::record_checks(record).map_err(storage)?;
        if checks.account.0 != *account {
            return Err(ServiceError::Storage);
        }
        let seal_digest = bh_account::personal::seal_digest(recovery_seal);
        self.with(|db| {
            let tx = db.transaction()?;
            let current = tx
                .query_row(
                    "SELECT record_digest FROM recovery_records WHERE account=?1",
                    [account.as_slice()],
                    |r| array::<32>(r.get(0)?),
                )
                .optional()?;
            match current {
                Some(digest) if digest == checks.digest => {}
                Some(digest) if Some(digest) == retire => {
                    tx.execute(
                        "DELETE FROM recovery_index WHERE record_digest=?1",
                        [digest.as_slice()],
                    )?;
                    tx.execute(
                        "DELETE FROM recovery_tries WHERE record_digest=?1",
                        [digest.as_slice()],
                    )?;
                }
                Some(_) => return Ok(false),
                None => {}
            }
            if current != Some(checks.digest) {
                tx.execute(
                    "INSERT INTO recovery_index(proof_check, account, record_digest)
                     VALUES(?1, ?2, ?3)",
                    params![
                        checks.proof_check.as_slice(),
                        account.as_slice(),
                        checks.digest.as_slice()
                    ],
                )?;
            }
            tx.execute(
                "INSERT OR REPLACE INTO recovery_records(account, record, recovery_seal,
                   record_digest, seal_digest)
                 VALUES(?1, ?2, ?3, ?4, ?5)",
                params![
                    account.as_slice(),
                    record,
                    recovery_seal,
                    checks.digest.as_slice(),
                    seal_digest.as_slice()
                ],
            )?;
            tx.commit()?;
            Ok(true)
        })
    }

    /// The current recovery record whose proof check this is.
    pub fn recovery_by_proof(
        &self,
        proof_check: &[u8; 32],
    ) -> Result<Option<RecoveryEntry>, ServiceError> {
        self.with(|db| {
            db.query_row(
                "SELECT r.account, r.record, r.recovery_seal, r.record_digest
                 FROM recovery_index i JOIN recovery_records r
                   ON r.account = i.account AND r.record_digest = i.record_digest
                 WHERE i.proof_check=?1",
                [proof_check.as_slice()],
                |r| {
                    Ok(RecoveryEntry {
                        account: array(r.get(0)?)?,
                        record: r.get(1)?,
                        recovery_seal: r.get(2)?,
                        record_digest: array(r.get(3)?)?,
                    })
                },
            )
            .optional()
        })
    }

    pub fn tries(&self, record_digest: &[u8; 32]) -> Result<Option<TryState>, ServiceError> {
        self.with(|db| {
            db.query_row(
                "SELECT failures, next_ms FROM recovery_tries WHERE record_digest=?1",
                [record_digest.as_slice()],
                |r| {
                    Ok(TryState {
                        failures: r.get(0)?,
                        next_ms: r.get::<_, Option<i64>>(1)?.map(|ms| ms as u64),
                    })
                },
            )
            .optional()
        })
    }

    /// Count a wrong-password try against the record at `at_ms`, in one
    /// transaction. Its next try never moves earlier.
    pub fn record_failure(
        &self,
        record_digest: &[u8; 32],
        at_ms: u64,
    ) -> Result<TryState, ServiceError> {
        self.with(|db| {
            let tx = db.transaction()?;
            let (failures, fifth, next) = tx
                .query_row(
                    "SELECT failures, fifth_failure_ms, next_ms FROM recovery_tries
                     WHERE record_digest=?1",
                    [record_digest.as_slice()],
                    |r| {
                        Ok((
                            r.get::<_, u32>(0)?,
                            r.get::<_, Option<i64>>(1)?.map(|ms| ms as u64),
                            r.get::<_, Option<i64>>(2)?.map(|ms| ms as u64),
                        ))
                    },
                )
                .optional()?
                .unwrap_or_default();
            let failures = failures.saturating_add(1);
            let fifth = fifth.or((failures >= crate::recovery::FREE_TRIES).then_some(at_ms));
            let next = next.max(crate::recovery::next_try(failures, fifth, at_ms));
            tx.execute(
                "INSERT OR REPLACE INTO recovery_tries(record_digest, failures,
                   fifth_failure_ms, next_ms)
                 VALUES(?1, ?2, ?3, ?4)",
                params![
                    record_digest.as_slice(),
                    failures,
                    fifth.map(|ms| ms as i64),
                    next.map(|ms| ms as i64)
                ],
            )?;
            tx.commit()?;
            Ok(TryState {
                failures,
                next_ms: next,
            })
        })
    }

    pub fn clear_tries(&self, record_digest: &[u8; 32]) -> Result<(), ServiceError> {
        self.with(|db| {
            db.execute(
                "DELETE FROM recovery_tries WHERE record_digest=?1",
                [record_digest.as_slice()],
            )?;
            Ok(())
        })
    }

    /// Note that the account's kit was used at `ms`, and keep only its
    /// latest notices. Its times strictly increase, even when the clock
    /// steps back, so reading after the last one seen misses none.
    pub fn add_notice(&self, account: &[u8; 32], ms: u64) -> Result<(), ServiceError> {
        self.with(|db| {
            let tx = db.transaction()?;
            let last: Option<i64> = tx.query_row(
                "SELECT MAX(time_ms) FROM recovery_notices WHERE account=?1",
                [account.as_slice()],
                |r| r.get(0),
            )?;
            let ms = last.map_or(ms as i64, |last| (ms as i64).max(last + 1));
            tx.execute(
                "INSERT INTO recovery_notices(account, time_ms) VALUES(?1, ?2)",
                params![account.as_slice(), ms],
            )?;
            tx.execute(
                "DELETE FROM recovery_notices WHERE account=?1 AND time_ms NOT IN (
                   SELECT time_ms FROM recovery_notices WHERE account=?1
                   ORDER BY time_ms DESC LIMIT ?2)",
                params![account.as_slice(), NOTICES_KEPT],
            )?;
            tx.commit()
        })
    }

    /// The times of the account's notices after `after_ms`, oldest first.
    pub fn notices_after(
        &self,
        account: &[u8; 32],
        after_ms: u64,
        limit: usize,
    ) -> Result<Vec<u64>, ServiceError> {
        self.with(|db| {
            let mut statement = db.prepare(
                "SELECT time_ms FROM recovery_notices WHERE account=?1 AND time_ms > ?2
                 ORDER BY time_ms LIMIT ?3",
            )?;
            statement
                .query_map(
                    params![
                        account.as_slice(),
                        after_ms.min(i64::MAX as u64) as i64,
                        limit as i64
                    ],
                    |r| Ok(r.get::<_, i64>(0)? as u64),
                )?
                .collect()
        })
    }
}

fn head(position: i64, hash: Vec<u8>) -> Result<Head, rusqlite::Error> {
    Ok(Head {
        position: position as u64,
        hash: Digest(array(hash)?),
    })
}
fn account_head(position: i64, hash: Vec<u8>) -> Result<AccountHead, rusqlite::Error> {
    Ok(AccountHead {
        position: position as u64,
        hash: array(hash)?,
    })
}

impl Store {
    /// A base's control projection: its status, control record and pending
    /// control. Production reads `base_snapshot`, with its BASE copy's pin.
    #[cfg(test)]
    pub fn controls(&self, base: &[u8; 32]) -> Result<Option<Record<Projection>>, ServiceError> {
        self.with(|db| {
            let Some(found) = db
                .query_row(
                    "SELECT creator, hosting_root, metadata_id, epoch, floor,
                       control_position, control_hash, control_digest,
                       head_position, head_hash, account_position, account_hash,
                       format, status, raw_order
                     FROM base_controls WHERE base=?1",
                    [base.as_slice()],
                    |r| projection(*base, r),
                )
                .optional()?
            else {
                return Ok(None);
            };
            let Record::Canonical((status, state)) = found else {
                return Ok(Some(Record::Legacy));
            };
            let pending = db
                .query_row(
                    "SELECT event_id, after_position, after_hash, deadline, digest, epoch_after,
                       account_position, account_hash, change, account_event, floor,
                       seen_position, judged_control, judged_account_position,
                       judged_account_hash, seal_set
                     FROM base_pending WHERE base=?1",
                    [base.as_slice()],
                    pending,
                )
                .optional()?;
            Ok(Some(Record::Canonical(Projection {
                status,
                state,
                pending,
            })))
        })
    }

    /// The first authenticated contradiction is immutable evidence. It never
    /// updates the accepted projection and cannot be cleared by registration.
    pub fn stop(
        &self,
        base: &[u8; 32],
        root: [u8; 32],
        remembered: OrderState,
        observed: OrderState,
        receipt: &[u8; 300],
        remembered_receipt: Option<&[u8; 300]>,
    ) -> Result<(), ServiceError> {
        self.with(|db| {
            db.execute(
                "INSERT OR IGNORE INTO base_stops(base, kind, remembered, observed, receipt,
                    remembered_receipt, hosting_root) VALUES(?1, 1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    base.as_slice(),
                    remembered.encode().as_slice(),
                    observed.encode().as_slice(),
                    receipt.as_slice(),
                    remembered_receipt.map(|r| r.as_slice()),
                    root.as_slice(),
                ],
            )?;
            Ok(())
        })
    }

    /// Store the actual pinned-root seen receipt, the known global Head,
    /// and (only for replay) the rooted endpoint and the complete raw-control
    /// path that established a candidate-known Head: the replay candidate's
    /// staged rows, streamed and checked here, then pinned by reference. No
    /// endpoint receipt is synthesized for an unordered submission.
    pub fn stop_seen(
        &self,
        witness: SeenReceiptConflict,
        scan: Option<(OrderState, &[u8; 300], &candidate::Candidate)>,
    ) -> Result<(), ServiceError> {
        let base = witness.base;
        if witness.known.position != witness.observed.position
            || witness.known == witness.observed
            || receipt::verify(&witness.root, base, &witness.receipt)
                .map(|r| r.head() != witness.observed)
                .unwrap_or(true)
        {
            return Err(ServiceError::Storage);
        }
        let (endpoint, endpoint_receipt, staged) = match &scan {
            Some((end, proof, candidate)) => {
                if candidate.base != base
                    || receipt::verify(&witness.root, base, *proof)
                        .map(|r| r.head() != end.head(base))
                        .unwrap_or(true)
                {
                    return Err(ServiceError::Storage);
                }
                (
                    Some(end.encode().to_vec()),
                    Some(proof.to_vec()),
                    Some(**candidate),
                )
            }
            None => (None, None, None),
        };
        let end_raw = scan.as_ref().map(|(end, _, _)| end.raw_control());
        self.with(|db| {
            let tx = db.transaction()?;
            let valid = tx
                .query_row(
                    "SELECT hosting_root, format, status, control_position, control_hash,
                    head_position, head_hash FROM base_controls WHERE base=?1",
                    [base.0.as_slice()],
                    |r| {
                        let root: Vec<u8> = r.get(0)?;
                        let format: Option<i64> = r.get(1)?;
                        let status: Option<i64> = r.get(2)?;
                        let accepted = (r.get::<_, i64>(3)?, r.get::<_, Vec<u8>>(4)?);
                        let raw = (r.get::<_, i64>(5)?, r.get::<_, Vec<u8>>(6)?);
                        let known = (
                            witness.known.position as i64,
                            witness.known.hash.0.as_slice(),
                        );
                        Ok(root == witness.root
                            && format == Some(FORMAT)
                            && (if scan.is_some() {
                                matches!(status, Some(1 | 2))
                            } else {
                                status == Some(Status::Accepted as i64)
                                    && [accepted, raw]
                                        .iter()
                                        .any(|(pos, hash)| (*pos, hash.as_slice()) == known)
                            }))
                    },
                )
                .optional()?;
            if valid != Some(true) && !(scan.is_some() && valid.is_none()) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            if let Some(candidate) = &staged {
                let (raw, found) = candidate::staged_path(&tx, candidate, witness.root, |c| {
                    c.head() == witness.known
                })?;
                if Some(raw) != end_raw || !found {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            tx.execute(
                "INSERT OR IGNORE INTO base_stops(base, kind, known_position, known_hash,
                    seen_receipt, observed, receipt, scan_controls, hosting_root, path_generation)
                 VALUES(?1, 2, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    base.0.as_slice(),
                    witness.known.position as i64,
                    witness.known.hash.0.as_slice(),
                    witness.receipt.as_slice(),
                    endpoint,
                    endpoint_receipt,
                    None::<Vec<u8>>,
                    witness.root.as_slice(),
                    staged.map(|c| c.pin.generation as i64),
                ],
            )?;
            tx.commit()
        })
    }

    /// Persist a direct endpoint/global-Head contradiction or a conflicting
    /// control in the completely rooted replay path. Unlike a kind-1 stop,
    /// the endpoint may be later than the actual mismatching control.
    #[allow(clippy::too_many_arguments)] // One local witness plus its rooted scan evidence.
    pub fn stop_control(
        &self,
        base: BaseId,
        root: [u8; 32],
        remembered_raw: OrderState,
        conflict: ControlConflict,
        endpoint: OrderState,
        endpoint_receipt: &[u8; 300],
        path: Option<&candidate::Candidate>,
    ) -> Result<(), ServiceError> {
        if conflict.known.position != conflict.observed.position
            || (conflict.known == conflict.observed
                && conflict.known_digest == conflict.observed_digest
                && conflict.known_order == conflict.observed_order)
            || receipt::verify(&root, base, endpoint_receipt)
                .map(|r| r.head() != endpoint.head(base))
                .unwrap_or(true)
        {
            return Err(ServiceError::Storage);
        }
        let observed = |control: &Commitment| {
            control.head() == conflict.observed
                && conflict
                    .observed_digest
                    .is_none_or(|d| d == control.event_digest())
                && conflict.observed_order.is_none_or(|o| o == control.after())
        };
        let staged = match path {
            Some(candidate) if candidate.base == base => Some(*candidate),
            Some(_) => return Err(ServiceError::Storage),
            None if endpoint.head(base) != conflict.observed => return Err(ServiceError::Storage),
            None => None,
        };
        self.with(|db| {
            let tx = db.transaction()?;
            let valid = tx
                .query_row(
                    "SELECT hosting_root, format, status, raw_order,
                    control_position, control_hash, control_digest,
                    head_position, head_hash FROM base_controls WHERE base=?1",
                    [base.0.as_slice()],
                    |r| {
                        let persisted = canonical(r.get(1)?, r.get(3)?)?;
                        let accepted = head(r.get(4)?, r.get(5)?)?;
                        let digest: Vec<u8> = r.get(6)?;
                        let raw = head(r.get(7)?, r.get(8)?)?;
                        Ok(r.get::<_, Vec<u8>>(0)? == root
                            && r.get::<_, Option<i64>>(2)? == Some(Status::Accepted as i64)
                            && persisted == Some(remembered_raw)
                            && ((conflict.known == raw
                                && conflict.known_order == Some(remembered_raw))
                                || (conflict.known_order.is_none()
                                    && conflict.known == accepted
                                    && conflict
                                        .known_digest
                                        .is_some_and(|d| d.0.as_slice() == digest))))
                    },
                )
                .optional()?;
            if valid != Some(true) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            if let Some(candidate) = &staged {
                let (raw, found) = candidate::staged_path(&tx, candidate, root, observed)?;
                if raw != endpoint.raw_control() || !found {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            tx.execute(
                "INSERT OR IGNORE INTO base_stops(base, kind, remembered, observed, receipt,
                    hosting_root, known_position, known_hash, observed_hash, known_digest,
                    observed_digest, conflict_order, scan_controls, path_generation)
                 VALUES(?1, 3, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    base.0.as_slice(),
                    remembered_raw.encode().as_slice(),
                    endpoint.encode().as_slice(),
                    endpoint_receipt.as_slice(),
                    root.as_slice(),
                    conflict.known.position as i64,
                    conflict.known.hash.0.as_slice(),
                    conflict.observed.hash.0.as_slice(),
                    conflict.known_digest.map(|d| d.0.to_vec()),
                    conflict.observed_digest.map(|d| d.0.to_vec()),
                    conflict.observed_order.map(|o| o.encode().to_vec()),
                    None::<Vec<u8>>,
                    staged.map(|c| c.pin.generation as i64),
                ],
            )?;
            tx.commit()
        })
    }

    /// A grant's final check is serialized with stop and conditional saves
    /// on this store connection. The closure must not await or take a slot lock.
    pub fn while_running<R>(
        &self,
        bases: &[[u8; 32]],
        grant: impl FnOnce() -> R,
    ) -> Result<Option<R>, ServiceError> {
        self.with(|db| {
            for base in bases {
                if db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM base_stops WHERE base=?1)",
                    [base.as_slice()],
                    |r| r.get::<_, bool>(0),
                )? {
                    return Ok(None);
                }
            }
            Ok(Some(grant()))
        })
    }

    /// In one transaction: bind the base to `owner`'s verified genesis
    /// unless bound, then replace its projection with `state`, `status` and
    /// `pending` and write the base's copy of the account (`base`: select a
    /// verified registration candidate, or append the exact copies of the
    /// consumed effect), recording the first use of each of `ids` in that
    /// generation, only if the durable projection is still `expected` (None:
    /// none), its selected copy and the account's HOME pin unchanged. A
    /// projection recorded before canonical order, an accepted one given a
    /// provisional status, or a save behind the durable raw checkpoint
    /// changes nothing.
    #[allow(clippy::too_many_arguments)]
    pub fn save_controls_if(
        &self,
        owner: Option<VerifiedBase>,
        status: Status,
        state: &ControlState,
        pending: Option<&Pending>,
        ids: &[([u8; 32], u64)],
        expected: Option<Prior>,
        write: &candidate::BaseWrite<'_>,
    ) -> Result<Saved, ServiceError> {
        // Copies' confirmations verify before the writer lock.
        let bounds = match (write.candidate, write.previous) {
            (None, Some(previous)) => {
                candidate::prepare_copies(write.projection, write.copies, previous)
                    .map_err(storage)?
            }
            _ if write.copies.is_empty() => Vec::new(),
            _ => return Err(ServiceError::Storage),
        };
        self.with(|db| {
            let tx = db.transaction()?;
            let base = state.base.0;
            if tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM base_stops WHERE base=?1)",
                [base.as_slice()],
                |r| r.get::<_, bool>(0),
            )? {
                return Ok(Saved::Stopped);
            }
            if let Some(owner) = owner {
                tx.execute(
                    "INSERT OR IGNORE INTO bases(base, account, epoch) VALUES(?1, ?2, ?3)",
                    params![
                        base.as_slice(),
                        owner.account.as_slice(),
                        owner.epoch.as_slice()
                    ],
                )?;
                let bound: (Vec<u8>, Vec<u8>) = tx.query_row(
                    "SELECT account, epoch FROM bases WHERE base=?1",
                    [base.as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                if bound != (owner.account.to_vec(), owner.epoch.to_vec()) {
                    return Ok(Saved::Conflict);
                }
            }
            let stored = tx
                .query_row(
                    "SELECT format, status, raw_order FROM base_controls WHERE base=?1",
                    [base.as_slice()],
                    |r| {
                        let status = match r.get::<_, Option<i64>>(1)? {
                            Some(1) => Some(Status::Provisional),
                            Some(2) => Some(Status::Accepted),
                            _ => None,
                        };
                        let order = canonical(r.get(0)?, r.get(2)?)?;
                        Ok(order.zip(status))
                    },
                )
                .optional()?;
            let stored_pending = tx
                .query_row(
                    "SELECT event_id, after_position, after_hash, deadline, digest, epoch_after,
                       account_position, account_hash, change, account_event, floor,
                       seen_position, judged_control, judged_account_position,
                       judged_account_hash, seal_set
                     FROM base_pending WHERE base=?1",
                    [base.as_slice()],
                    self::pending,
                )
                .optional()?;
            let current = match stored {
                None => None,
                Some(None) => return Ok(Saved::Changed),
                Some(Some((order, status))) => Some(Prior {
                    status,
                    order,
                    pending: stored_pending,
                }),
            };
            if current != expected
                || current.as_ref().is_some_and(|c| {
                    c.status > status || c.order.position() > state.order.position()
                })
            {
                return Ok(Saved::Changed);
            }
            let Some(generation) = candidate::save_projected_base(
                &tx,
                status,
                state,
                write,
                &bounds,
                current.is_none(),
            )?
            else {
                return Ok(Saved::Changed);
            };
            save(&tx, status, state, pending)?;
            for (id, position) in ids {
                tx.execute(
                    "INSERT OR IGNORE INTO base_ids(base, generation, id, position) VALUES(?1, ?2, ?3, ?4)",
                    params![base.as_slice(), generation as i64, id.as_slice(), *position as i64],
                )?;
            }
            tx.commit()?;
            Ok(Saved::Written)
        })
    }
}

/// Replace a base's control row and its pending control, in the caller's
/// transaction. The copied account events are the BASE copy's rows.
fn save(
    tx: &Transaction,
    status: Status,
    state: &ControlState,
    pending: Option<&Pending>,
) -> rusqlite::Result<()> {
    let base = state.base.0;
    if state.order.head(state.base) != state.control_head {
        return Err(rusqlite::Error::InvalidQuery);
    }
    tx.execute(
        "INSERT OR REPLACE INTO base_controls(base, creator, hosting_root, metadata_id,
           epoch, floor, control_position, control_hash, control_digest,
           head_position, head_hash, account_position, account_hash,
           format, status, raw_order)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            base.as_slice(),
            state.creator.0.as_slice(),
            state.hosting_root.as_slice(),
            state.metadata_id.as_slice(),
            state.epoch.map(|e| e.to_vec()),
            state.floor,
            state.control.position as i64,
            state.control.hash.0.as_slice(),
            state.control_digest.as_slice(),
            state.control_head.position as i64,
            state.control_head.hash.0.as_slice(),
            state.account.position as i64,
            state.account.hash.as_slice(),
            FORMAT,
            status as i64,
            state.order.encode().as_slice(),
        ],
    )?;
    tx.execute("DELETE FROM base_pending WHERE base=?1", [base.as_slice()])?;
    if let Some(p) = pending {
        let e = &p.effect;
        tx.execute(
            "INSERT INTO base_pending(base, event_id, after_position, after_hash,
               deadline, digest, epoch_after, account_position, account_hash, change,
               account_event, floor, seen_position, judged_control,
               judged_account_position, judged_account_hash, seal_set)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
               ?17)",
            params![
                base.as_slice(),
                p.event_id.as_slice(),
                p.after.position as i64,
                p.after.hash.0.as_slice(),
                p.deadline_ms as i64,
                e.digest.0.as_slice(),
                e.epoch_after.map(|e| e.to_vec()),
                e.account_head_after.position as i64,
                e.account_head_after.hash.as_slice(),
                match e.change {
                    ControlChange::AddDevice => 1,
                    ControlChange::RemoveSelf => 2,
                    ControlChange::AccountRun => 3,
                    ControlChange::Rekey => 4,
                },
                encode_copies(&e.account_copies),
                e.floor_after,
                e.seen_position as i64,
                e.judged_control_digest.as_slice(),
                e.judged_account_head.position as i64,
                e.judged_account_head.hash.as_slice(),
                e.seal_set.map(|d| d.0.to_vec()),
            ],
        )?;
    }
    Ok(())
}

/// A stored canonical opening: None for a row recorded before canonical
/// order. Any other format is not this service's.
fn canonical(
    format: Option<i64>,
    opening: Option<Vec<u8>>,
) -> rusqlite::Result<Option<OrderState>> {
    match (format, opening) {
        (None, None) => Ok(None),
        (Some(FORMAT), Some(bytes)) => OrderState::decode(&bytes)
            .map(Some)
            .map_err(|_| rusqlite::Error::InvalidQuery),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn projection(base: [u8; 32], r: &Row) -> rusqlite::Result<Record<(Status, ControlState)>> {
    let Some(order) = canonical(r.get(12)?, r.get(14)?)? else {
        return Ok(Record::Legacy);
    };
    let status = match r.get::<_, i64>(13)? {
        1 => Status::Provisional,
        2 => Status::Accepted,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let state = state(base, order, r)?;
    if order.head(BaseId(base)) != state.control_head {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(Record::Canonical((status, state)))
}

fn state(base: [u8; 32], order: OrderState, r: &Row) -> rusqlite::Result<ControlState> {
    Ok(ControlState {
        base: BaseId(base),
        creator: AccountId(array(r.get(0)?)?),
        hosting_root: array(r.get(1)?)?,
        metadata_id: array(r.get(2)?)?,
        epoch: r.get::<_, Option<Vec<u8>>>(3)?.map(array).transpose()?,
        floor: r.get(4)?,
        control: head(r.get(5)?, r.get(6)?)?,
        control_digest: array(r.get(7)?)?,
        control_head: head(r.get(8)?, r.get(9)?)?,
        order,
        account: account_head(r.get(10)?, r.get(11)?)?,
    })
}

fn pending(r: &Row) -> rusqlite::Result<Pending> {
    Ok(Pending {
        event_id: array(r.get(0)?)?,
        after: head(r.get(1)?, r.get(2)?)?,
        deadline_ms: r.get::<_, i64>(3)? as u64,
        effect: ControlEffect {
            digest: Digest(array(r.get(4)?)?),
            epoch_after: r.get::<_, Option<Vec<u8>>>(5)?.map(array).transpose()?,
            account_head_after: account_head(r.get(6)?, r.get(7)?)?,
            change: match r.get::<_, u8>(8)? {
                1 => ControlChange::AddDevice,
                2 => ControlChange::RemoveSelf,
                3 => ControlChange::AccountRun,
                4 => ControlChange::Rekey,
                _ => return Err(rusqlite::Error::InvalidQuery),
            },
            account_copies: decode_copies(&r.get::<_, Vec<u8>>(9)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            seal_set: r
                .get::<_, Option<Vec<u8>>>(15)?
                .map(array)
                .transpose()?
                .map(Digest),
            floor_after: r.get(10)?,
            seen_position: r.get::<_, i64>(11)? as u64,
            judged_control_digest: array(r.get(12)?)?,
            judged_account_head: account_head(r.get(13)?, r.get(14)?)?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The schema-3 tables this service deployed, exactly.
    const SCHEMA_THREE: &str = "
        CREATE TABLE meta(key TEXT PRIMARY KEY, value INTEGER NOT NULL);
        CREATE TABLE accounts(
          account BLOB PRIMARY KEY, log BLOB NOT NULL,
          position INTEGER NOT NULL, log_hash BLOB NOT NULL);
        CREATE TABLE account_events(
          account BLOB NOT NULL, position INTEGER NOT NULL, bytes BLOB NOT NULL,
          body BLOB, PRIMARY KEY(account, position));
        CREATE TABLE bases(
          base BLOB PRIMARY KEY, account BLOB NOT NULL, epoch BLOB NOT NULL);
        CREATE TABLE base_controls(
          base BLOB PRIMARY KEY, creator BLOB NOT NULL, hosting_root BLOB NOT NULL,
          metadata_id BLOB NOT NULL, epoch BLOB, floor INTEGER NOT NULL,
          control_position INTEGER NOT NULL, control_hash BLOB NOT NULL,
          control_digest BLOB NOT NULL,
          head_position INTEGER NOT NULL, head_hash BLOB NOT NULL,
          account_position INTEGER NOT NULL, account_hash BLOB NOT NULL);
        CREATE TABLE base_account_changes(
          base BLOB NOT NULL, position INTEGER NOT NULL, bytes BLOB NOT NULL,
          PRIMARY KEY(base, position));
        CREATE TABLE base_pending(
          base BLOB PRIMARY KEY, event_id BLOB NOT NULL,
          after_position INTEGER NOT NULL, after_hash BLOB NOT NULL,
          deadline INTEGER NOT NULL, digest BLOB NOT NULL, epoch_after BLOB,
          account_position INTEGER NOT NULL, account_hash BLOB NOT NULL,
          change INTEGER NOT NULL, account_event BLOB NOT NULL, floor INTEGER NOT NULL,
          seen_position INTEGER NOT NULL, judged_control BLOB NOT NULL,
          judged_account_position INTEGER NOT NULL, judged_account_hash BLOB NOT NULL);";

    fn disk(schema: i64) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authz.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(SCHEMA_THREE).unwrap();
        db.execute(
            "INSERT INTO meta(key, value) VALUES('schema', ?1)",
            [schema],
        )
        .unwrap();
        let blob = |b: u8| vec![b; 32];
        db.execute(
            "INSERT INTO bases(base, account, epoch) VALUES(?1, ?2, ?3)",
            params![blob(1), blob(2), blob(3)],
        )
        .unwrap();
        db.execute(
            "INSERT INTO base_controls VALUES(?1, ?2, ?3, ?4, ?5, 2, 4, ?6, ?7, 5, ?8, 6, ?9)",
            params![
                blob(1),
                blob(2),
                blob(4),
                blob(5),
                blob(3),
                blob(6),
                blob(7),
                blob(8),
                blob(9)
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO base_account_changes(base, position, bytes) VALUES(?1, 0, ?2)",
            params![blob(1), b"BaseHero account event\0legacy".to_vec()],
        )
        .unwrap();
        db.execute(
            "INSERT INTO base_pending VALUES(?1, ?2, 4, ?3, 99, ?4, ?5, 7, ?6, 1, ?7, 2, 3,
               ?8, 6, ?9)",
            params![
                blob(1),
                blob(10),
                blob(6),
                blob(11),
                blob(3),
                blob(12),
                b"BaseHero account event\0pending".to_vec(),
                blob(7),
                blob(9)
            ],
        )
        .unwrap();
        (dir, path)
    }

    #[test]
    fn projection_schema_keeps_populated_legacy_scope_unsupported() {
        let (_dir, path) = disk(3);
        let store = Store::open(&path).unwrap();
        let schema: i64 = store
            .with(|db| {
                db.query_row("SELECT value FROM meta WHERE key='schema'", [], |r| {
                    r.get(0)
                })
            })
            .unwrap();
        assert_eq!(schema, SCHEMA);
        assert!(matches!(
            store.controls(&[1; 32]).unwrap(),
            Some(Record::Legacy)
        ));
    }

    #[test]
    fn schema_six_base_record_without_its_copy_stays_unsupported() {
        let (dir, store) = open_new();
        let base = BaseId([1; 32]);
        let state = state_at(base, genesis_order(base));
        store
            .with(|db| {
                let tx = db.transaction()?;
                save(&tx, Status::Accepted, &state, None)?;
                tx.commit()
            })
            .unwrap();
        drop(store);
        let path = dir.path().join("authz.sqlite");
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "DROP TABLE base_generations; DROP TABLE base_raw; DROP TABLE base_ids;
                 DROP TABLE projection_copies; ALTER TABLE base_stops DROP COLUMN path_generation;
                 UPDATE meta SET value=6 WHERE key='schema';",
            )
            .unwrap();
        let store = Store::open(&path).unwrap();
        let schema: i64 = store
            .with(|db| {
                db.query_row("SELECT value FROM meta WHERE key='schema'", [], |r| {
                    r.get(0)
                })
            })
            .unwrap();
        assert_eq!(schema, SCHEMA);
        let rows = projection_rows(&store, &base.0);
        // A canonical record from before BASE copies is never a new empty
        // base, and is never replayed on open.
        assert!(matches!(
            store.base_snapshot(base).unwrap(),
            Some(Record::Legacy)
        ));
        assert_eq!(projection_rows(&store, &base.0), rows);
    }

    #[test]
    fn legacy_scopes_stay_paused_beside_new_projected_home_scopes() {
        let (_dir, path) = disk(3);
        let store = std::sync::Arc::new(Store::open(&path).unwrap());
        let (key, genesis, opening, write) = super::projection_tests::seed_on();
        let projection::Source::Home(log) = key.source else {
            unreachable!()
        };
        store
            .extend_projected(
                &key.account.0,
                &log.id,
                OrderState::EMPTY,
                opening,
                &[StoredEvent {
                    original: genesis.clone(),
                    body: None,
                }],
                ConfirmedPage {
                    confirmations: &[],
                    activations: &[],
                },
                &write,
                &[],
            )
            .unwrap();
        let Record::Canonical(stored) = store.current_projection(key).unwrap().unwrap() else {
            panic!()
        };
        assert_eq!(
            store
                .restore_projection(stored, key, [7; 32], &genesis)
                .unwrap()
                .head()
                .position,
            1
        );
        assert!(matches!(
            store.controls(&[1; 32]).unwrap(),
            Some(Record::Legacy)
        ));
        assert_eq!(
            store
                .with(|db| db.query_row(
                    "SELECT COUNT(*) FROM base_account_changes WHERE base=?1",
                    [[1; 32].as_slice()],
                    |r| r.get::<_, i64>(0)
                ))
                .unwrap(),
            1
        );
    }

    #[test]
    fn schema_three_disk_upgrades_keeping_bases_as_legacy_projections() {
        let (_dir, path) = disk(3);
        let store = Store::open(&path).unwrap();
        let schema: i64 = store
            .with(|db| {
                db.query_row("SELECT value FROM meta WHERE key='schema'", [], |r| {
                    r.get(0)
                })
            })
            .unwrap();
        assert_eq!(schema, SCHEMA);
        // The base stays registered to its account under its epoch.
        let base = store.base(&[1; 32]).unwrap().unwrap();
        assert_eq!((base.account, base.epoch), ([2; 32], [3; 32]));
        // Its projection predates canonical order: it is never relabelled,
        // and no save replaces it, whatever it expects.
        assert!(matches!(
            store.controls(&[1; 32]).unwrap(),
            Some(Record::Legacy)
        ));
        let rows = projection_rows(&store, &[1; 32]);
        let state = state_at(BaseId([1; 32]), genesis_order(BaseId([1; 32])));
        let (_, _, _, write) = super::projection_tests::seed_on();
        let pin = write.header.pin;
        for expected in [None, Some(Prior::of(Status::Provisional, &state, None))] {
            assert!(matches!(
                store
                    .save_controls_if(
                        None,
                        Status::Accepted,
                        &state,
                        None,
                        &[],
                        expected,
                        &candidate::BaseWrite {
                            candidate: None,
                            previous: Some(pin),
                            projection: &write,
                            copies: &[],
                            anchor: pin,
                            expected_home: pin,
                        },
                    )
                    .unwrap(),
                Saved::Changed
            ));
        }
        assert!(matches!(
            store.base_snapshot(BaseId([1; 32])).unwrap(),
            Some(Record::Legacy)
        ));
        assert_eq!(projection_rows(&store, &[1; 32]), rows);
        // The upgraded disk takes every schema-4 table.
        let (record, seal) = recovery_objects();
        let account = record_checks(&record).unwrap().account.0;
        assert!(store.put_recovery(&account, &record, &seal, None).unwrap());
        store.add_notice(&account, 5).unwrap();
        let tables: i64 = store
            .with(|db| {
                db.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN
                       ('account_confirmations', 'recovery_index', 'recovery_records',
                        'recovery_tries', 'recovery_notices', 'pending_attachments')",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(tables, 6);
    }

    /// The account log's order after `n` entries.
    fn opening(log: &[u8; 32], n: u64) -> OrderState {
        (0..n).fold(OrderState::EMPTY, |before, i| {
            let digest = if i == 0 { *log } else { [i as u8 + 40; 32] };
            bh_sync::canonical::CanonicalCommitment::order(
                BaseId(*log),
                before,
                Digest(digest),
                bh_sync::Route::Control,
            )
            .unwrap()
            .after()
        })
    }

    /// Every durable row of one base's projection, byte for byte.
    fn projection_rows(store: &Store, base: &[u8; 32]) -> Vec<Vec<rusqlite::types::Value>> {
        store
            .with(|db| {
                let mut rows = vec![];
                for table in [
                    "bases",
                    "base_controls",
                    "base_account_changes",
                    "base_pending",
                    "base_control_ids",
                ] {
                    let mut statement = db.prepare(&format!(
                        "SELECT * FROM {table} WHERE base=?1 ORDER BY 1, 2"
                    ))?;
                    let width = statement.column_count();
                    let mut query = statement.query([base.as_slice()])?;
                    while let Some(row) = query.next()? {
                        rows.push(
                            (0..width)
                                .map(|i| row.get::<_, rusqlite::types::Value>(i))
                                .collect::<Result<_, _>>()?,
                        );
                    }
                }
                Ok(rows)
            })
            .unwrap()
    }

    fn genesis_order(base: BaseId) -> bh_sync::canonical::CanonicalCommitment {
        bh_sync::canonical::CanonicalCommitment::order(
            base,
            OrderState::EMPTY,
            Digest(base.0),
            bh_sync::Route::Control,
        )
        .unwrap()
    }

    /// A projection whose last raw control is `ordered`.
    fn state_at(base: BaseId, ordered: bh_sync::canonical::CanonicalCommitment) -> ControlState {
        ControlState {
            base,
            creator: AccountId([2; 32]),
            hosting_root: [3; 32],
            metadata_id: [4; 32],
            epoch: Some([5; 32]),
            floor: 3,
            control: ordered.head(),
            control_digest: ordered.event_digest().0,
            control_head: ordered.head(),
            order: ordered.after(),
            account: AccountHead {
                position: 1,
                hash: [7; 32],
            },
        }
    }

    #[test]
    fn an_account_projection_keeps_its_canonical_opening() {
        let (dir, store) = open_new();
        let (account, log) = ([1; 32], [2; 32]);
        let event = |b: u8| StoredEvent {
            original: vec![b; 8],
            body: None,
        };
        let first = genesis_order(BaseId(log)).after();
        let page = || ConfirmedPage {
            confirmations: &[],
            activations: &[],
        };
        // Only from the opening it holds.
        assert!(
            store
                .extend(&account, &log, first, first, &[event(1)], page())
                .is_err()
        );
        store
            .extend(
                &account,
                &log,
                OrderState::EMPTY,
                first,
                &[event(1)],
                page(),
            )
            .unwrap();
        let stored = store.account(&account).unwrap().unwrap();
        assert_eq!(stored.opening, Some(first));
        assert_eq!(stored.head, first.head(BaseId(log)));
        assert!(
            store
                .extend(
                    &account,
                    &log,
                    OrderState::EMPTY,
                    first,
                    &[event(1)],
                    page()
                )
                .is_err()
        );
        // A row from before canonical order has no opening, and nothing
        // extends it into one.
        store
            .with(|db| {
                db.execute(
                    "UPDATE accounts SET format=NULL, opening=NULL WHERE account=?1",
                    [account.as_slice()],
                )
            })
            .unwrap();
        drop(store);
        let store = Store::open(&dir.path().join("authz.sqlite")).unwrap();
        let stored = store.account(&account).unwrap().unwrap();
        assert_eq!(stored.opening, None);
        assert!(
            store
                .extend(&account, &log, first, first, &[event(2)], page())
                .is_err()
        );
        assert_eq!(store.account(&account).unwrap().unwrap().events.len(), 1);
    }

    #[test]
    fn extend_refuses_a_replaced_account_checkpoint_without_mutating_it() {
        let (_dir, store) = open_new();
        let account = [1; 32];
        let log = [2; 32];
        let first = opening(&log, 1);
        store
            .extend(
                &account,
                &log,
                OrderState::EMPTY,
                first,
                &[StoredEvent {
                    original: vec![1],
                    body: None,
                }],
                ConfirmedPage {
                    confirmations: &[],
                    activations: &[],
                },
            )
            .unwrap();
        for sql in [
            "UPDATE accounts SET log=zeroblob(32) WHERE account=?1",
            "UPDATE accounts SET log_hash=zeroblob(32) WHERE account=?1",
            "UPDATE accounts SET position=2 WHERE account=?1",
        ] {
            let original = store
                .with(|db| {
                    db.query_row(
                        "SELECT log,position,log_hash FROM accounts WHERE account=?1",
                        [account.as_slice()],
                        |r| {
                            Ok((
                                r.get::<_, Vec<u8>>(0)?,
                                r.get::<_, i64>(1)?,
                                r.get::<_, Vec<u8>>(2)?,
                            ))
                        },
                    )
                })
                .unwrap();
            store
                .with(|db| db.execute(sql, [account.as_slice()]))
                .unwrap();
            let before = store
                .with(|db| {
                    db.query_row(
                        "SELECT log,position,log_hash FROM accounts WHERE account=?1",
                        [account.as_slice()],
                        |r| {
                            Ok((
                                r.get::<_, Vec<u8>>(0)?,
                                r.get::<_, i64>(1)?,
                                r.get::<_, Vec<u8>>(2)?,
                            ))
                        },
                    )
                })
                .unwrap();
            assert!(
                store
                    .extend(
                        &account,
                        &log,
                        first,
                        opening(&log, 2),
                        &[StoredEvent {
                            original: vec![2],
                            body: None
                        }],
                        ConfirmedPage {
                            confirmations: &[],
                            activations: &[]
                        }
                    )
                    .is_err()
            );
            assert_eq!(
                store
                    .with(|db| db.query_row(
                        "SELECT log,position,log_hash FROM accounts WHERE account=?1",
                        [account.as_slice()],
                        |r| Ok((
                            r.get::<_, Vec<u8>>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, Vec<u8>>(2)?
                        ))
                    ))
                    .unwrap(),
                before
            );
            assert_eq!(
                store
                    .with(|db| db.query_row(
                        "SELECT COUNT(*) FROM account_events WHERE account=?1",
                        [account.as_slice()],
                        |r| r.get::<_, i64>(0)
                    ))
                    .unwrap(),
                1
            );
            store
                .with(|db| {
                    db.execute(
                        "UPDATE accounts SET log=?2,position=?3,log_hash=?4 WHERE account=?1",
                        params![account.as_slice(), original.0, original.1, original.2],
                    )
                })
                .unwrap();
        }
    }

    use bh_account::recovery::{self, Password, RecoveryCode, record_checks};

    /// A recovery record shaped as signup makes it, under a fresh code, and
    /// a seal.
    fn recovery_objects() -> (Vec<u8>, Vec<u8>) {
        let device = bh_crypto::SigningKey::generate();
        let keys = bh_account::DevicePublicKeys::new(
            bh_crypto::SigningKey::generate().public(),
            device.public(),
            bh_crypto::KemKey::generate().public(),
        )
        .unwrap();
        let recovery_keys = recovery::RecoveryKeys::generate();
        let draft = bh_account::AccountEvent::genesis(keys, recovery_keys.public());
        let genesis = draft.finish(device.sign(draft.signing_bytes())).unwrap();
        let id = AccountId::of_genesis(&genesis).unwrap();
        let view = bh_account::VerifiedAccount::from_genesis(id, genesis.as_bytes()).unwrap();
        let code = RecoveryCode::generate();
        let record = recovery::prepare_record(
            &view,
            &recovery_keys,
            &Password::new("store test").unwrap(),
            &code,
        )
        .unwrap();
        (record.as_bytes().to_vec(), vec![7; 1300])
    }

    fn open_new() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("authz.sqlite")).unwrap();
        (dir, store)
    }

    #[test]
    fn a_record_is_found_by_its_proof_check_only_while_current() {
        let (_dir, store) = open_new();
        let (record, seal) = recovery_objects();
        let checks = record_checks(&record).unwrap();
        let account = checks.account.0;
        assert!(
            store
                .recovery_by_proof(&checks.proof_check)
                .unwrap()
                .is_none()
        );
        assert!(store.put_recovery(&account, &record, &seal, None).unwrap());
        let found = store
            .recovery_by_proof(&checks.proof_check)
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                found.account,
                found.record_digest,
                &found.record,
                &found.recovery_seal
            ),
            (account, checks.digest, &record, &seal)
        );
        // The same record again replaces only its seal; a record for another
        // account is refused.
        assert!(
            store
                .put_recovery(&account, &record, &[8; 1300], None)
                .unwrap()
        );
        let found = store
            .recovery_by_proof(&checks.proof_check)
            .unwrap()
            .unwrap();
        assert_eq!(found.recovery_seal, vec![8; 1300]);
        assert!(store.put_recovery(&[0; 32], &record, &seal, None).is_err());
        // Without the digest it retires, another record does not replace it.
        let (other, _) = recovery_objects();
        let mut foreign = other.clone();
        foreign[10..42].copy_from_slice(&account);
        assert!(!store.put_recovery(&account, &foreign, &seal, None).unwrap());
        assert!(
            !store
                .put_recovery(&account, &foreign, &seal, Some([9; 32]))
                .unwrap()
        );
        assert_eq!(
            store
                .recovery_by_proof(&checks.proof_check)
                .unwrap()
                .unwrap()
                .record,
            record
        );
    }

    #[test]
    fn kit_replacement_retires_the_old_record_with_its_tries() {
        let (_dir, store) = open_new();
        let (record, seal) = recovery_objects();
        let old = record_checks(&record).unwrap();
        let account = old.account.0;
        store.put_recovery(&account, &record, &seal, None).unwrap();
        for _ in 0..5 {
            store.record_failure(&old.digest, 10).unwrap();
        }
        // A replacement record for the same account, under a new code.
        let (mut new, _) = recovery_objects();
        new[10..42].copy_from_slice(&account);
        let replacement = record_checks(&new).unwrap();
        assert!(
            store
                .put_recovery(&account, &new, &seal, Some(old.digest))
                .unwrap()
        );
        assert!(store.recovery_by_proof(&old.proof_check).unwrap().is_none());
        assert_eq!(store.tries(&old.digest).unwrap(), None);
        let found = store
            .recovery_by_proof(&replacement.proof_check)
            .unwrap()
            .unwrap();
        assert_eq!(found.record_digest, replacement.digest);
        assert_eq!(store.tries(&replacement.digest).unwrap(), None);
    }

    #[test]
    fn failures_follow_the_schedule_and_never_move_the_next_try_earlier() {
        let (_dir, store) = open_new();
        let digest = [1; 32];
        for failures in 1..5 {
            assert_eq!(
                store.record_failure(&digest, 100).unwrap(),
                TryState {
                    failures,
                    next_ms: None
                }
            );
        }
        let hour = 3_600_000;
        assert_eq!(
            store.record_failure(&digest, 1_000).unwrap(),
            TryState {
                failures: 5,
                next_ms: Some(1_000 + hour)
            }
        );
        // A failure counted at an earlier time keeps the later next try.
        assert_eq!(
            store.record_failure(&digest, 500).unwrap().next_ms,
            Some(1_000 + hour)
        );
        store.clear_tries(&digest).unwrap();
        assert_eq!(store.tries(&digest).unwrap(), None);
    }

    #[test]
    fn notices_strictly_increase_and_keep_the_latest() {
        let (_dir, store) = open_new();
        let (a, b) = ([1; 32], [2; 32]);
        store.add_notice(&a, 100).unwrap();
        store.add_notice(&a, 100).unwrap();
        store.add_notice(&a, 50).unwrap();
        assert_eq!(store.notices_after(&a, 0, 64).unwrap(), vec![100, 101, 102]);
        assert_eq!(store.notices_after(&a, 100, 1).unwrap(), vec![101]);
        assert_eq!(store.notices_after(&b, 0, 64).unwrap(), Vec::<u64>::new());
        for ms in 0..100 {
            store.add_notice(&b, 1_000 + ms).unwrap();
        }
        let kept = store.notices_after(&b, 0, 1_000).unwrap();
        assert_eq!(kept.len(), NOTICES_KEPT as usize);
        assert_eq!(kept[0], 1_036);
        assert_eq!(store.notices_after(&a, 0, 64).unwrap().len(), 3);
    }

    #[test]
    fn confirmation_refuses_an_existing_mismatched_record_without_consuming_attachment() {
        let (_dir, store) = open_new();
        let (record, seal) = recovery_objects();
        let checks = record_checks(&record).unwrap();
        let account = checks.account.0;
        let log = [8; 32];
        store.put_recovery(&account, &record, &seal, None).unwrap();
        let event = StoredEvent {
            original: vec![1],
            body: None,
        };
        let wrapped = bh_authz_proto::account_log_wrap(&event.original, event.body)
            .unwrap()
            .digest();
        assert!(
            store
                .stage_attachment(
                    &account,
                    wrapped,
                    &Attachment {
                        record: Some(record.clone()),
                        recovery_seal: seal.clone(),
                        rotation_body: None,
                    }
                )
                .unwrap()
        );
        let result = store.extend(
            &account,
            &log,
            OrderState::EMPTY,
            opening(&log, 1),
            &[event],
            ConfirmedPage {
                confirmations: &[],
                activations: &[(
                    1,
                    Some(Activation::Replace {
                        old: [9; 32],
                        record,
                        seal: seal.clone(),
                        prefix: Digest([4; 32]),
                    }),
                )],
            },
        );
        assert!(
            result.is_err(),
            "an existing unrelated record must not be replaced"
        );
        assert!(
            store.account(&account).unwrap().is_none(),
            "no partial confirmation"
        );
        assert!(
            store.attachment(&account, wrapped).unwrap().is_some(),
            "pending survives rollback"
        );
        assert_eq!(
            store.recovery_digests(&account).unwrap(),
            Some(RecoveryDigests {
                record: checks.digest,
                seal: bh_account::personal::seal_digest(&seal)
            })
        );
    }

    #[test]
    fn confirmations_are_stored_with_their_events_only() {
        let (dir, store) = open_new();
        let (account, log) = ([1; 32], [2; 32]);
        let event = |b: u8| StoredEvent {
            original: vec![b; 8],
            body: None,
        };
        let head = |position: u64| opening(&log, position);
        store
            .extend(
                &account,
                &log,
                OrderState::EMPTY,
                head(2),
                &[event(1), event(2)],
                ConfirmedPage {
                    confirmations: &[(2, vec![9; 40])],
                    activations: &[],
                },
            )
            .unwrap();
        // Not for an event the call does not append.
        for position in [1, 2, 4] {
            assert!(
                store
                    .extend(
                        &account,
                        &log,
                        head(2),
                        head(3),
                        &[event(3)],
                        ConfirmedPage {
                            confirmations: &[(position, vec![9; 40])],
                            activations: &[]
                        }
                    )
                    .is_err()
            );
        }
        store
            .extend(
                &account,
                &log,
                head(2),
                head(3),
                &[event(3)],
                ConfirmedPage {
                    confirmations: &[(3, vec![8; 40])],
                    activations: &[],
                },
            )
            .unwrap();
        assert_eq!(store.confirmation(&account, 1).unwrap(), None);
        let wrapped = bh_authz_proto::account_log_wrap(&[2; 8], None)
            .unwrap()
            .digest();
        assert_eq!(
            store.confirmed_event(&account, wrapped).unwrap(),
            Some(vec![9; 40])
        );
        assert_eq!(store.confirmed_event(&[8; 32], wrapped).unwrap(), None);
        assert_eq!(store.confirmation(&account, 2).unwrap(), Some(vec![9; 40]));
        drop(store);
        let store = Store::open(&dir.path().join("authz.sqlite")).unwrap();
        assert_eq!(
            store.confirmed_event(&account, wrapped).unwrap(),
            Some(vec![9; 40])
        );
        // An existing schema-four disk can be backfilled without changing
        // confirmation bytes or making unconfirmed originals confirmable.
        store
            .with(|db| db.execute_batch("DROP TABLE confirmed_events;"))
            .unwrap();
        drop(store);
        let store = Store::open(&dir.path().join("authz.sqlite")).unwrap();
        assert_eq!(
            store.confirmed_event(&account, wrapped).unwrap(),
            Some(vec![9; 40])
        );
        let stored = store.account(&account).unwrap().unwrap();
        assert_eq!(stored.events.len(), 3);
        assert_eq!(
            stored.confirmations,
            vec![(2, vec![9; 40]), (3, vec![8; 40])]
        );
    }

    #[test]
    fn schema_two_disk_is_refused() {
        let (_dir, path) = disk(2);
        assert!(Store::open(&path).is_err());
    }

    #[test]
    fn new_disk_starts_at_the_current_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authz.sqlite");
        let store = Store::open(&path).unwrap();
        let schema: i64 = store
            .with(|db| {
                db.query_row("SELECT value FROM meta WHERE key='schema'", [], |r| {
                    r.get(0)
                })
            })
            .unwrap();
        assert_eq!(schema, SCHEMA);
        drop(store);
        Store::open(&path).unwrap();
    }
}
