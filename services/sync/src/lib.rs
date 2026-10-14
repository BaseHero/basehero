//! Native SQLite consumption of exact signed operations, not a hosted access endpoint.
//! The caller is a trusted host: it must supply the *actual* one-use response-channel
//! binding, deliver the committed response only over that channel, reconcile the
//! protected execution lane and serialize current account/control authority before
//! issuing grants. Reopening disk does not establish any of those properties.
#![forbid(unsafe_code)]

use bh_sync::{
    AccessError, BaseId, BodyObject, Commitment, Digest, EventId, GateState, Head, OpaqueEvent,
    Operation, SignedApproval, TimeWindow, plan_consumption, referenced_body,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::path::Path;

#[cfg(test)]
mod commit_test;

const SCHEMA: u32 = 2;

/// No request-controlled time or callback can be used as a production clock.
/// To prove commit-before-expiry, `latest` must bound the remaining transaction
/// *including commit*, not just the instant this method samples the clock.
/// This native adapter enforces no maximum commit duration; an arbitrary disk
/// stall defeats any unproved margin. Exact hosted removal deadlines are not
/// established by this interface without a separately validated host contract.
pub trait Clock {
    fn window(&self) -> Result<TimeWindow, Refusal>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Access(AccessError),
    /// Includes SQL errors, absent/corrupt history, clock failure and unsupported schema.
    Unavailable,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Ack(Commitment),
    Read(Vec<Vec<u8>>),
    Staged(Digest),
    ReadBodies(Vec<Vec<u8>>),
}
/// Only for trusted lane reconciliation after a response was lost. This row is
/// not an attested receipt or a substitute for a host-authenticated durable outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastOutcome {
    pub approval: SignedApproval,
    pub next: GateState,
    pub ack: Option<Commitment>,
}

pub struct Database {
    connection: Connection,
    #[cfg(test)]
    fail_commit: bool,
}
impl Database {
    /// Provision exactly one new base with a gate supplied by trusted initialization.
    /// Not a way to re-establish authority after a restart.
    pub fn create(path: &Path, initial: GateState) -> Result<Self, Refusal> {
        if initial.head != Head::EMPTY || initial.sequence != 0 {
            return Err(Refusal::Unavailable);
        }
        let mut connection = connect(path)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        if version(&tx)? != 0 || table_exists(&tx, "gate")? {
            return Err(Refusal::Unavailable);
        }
        tx.execute_batch(
            "CREATE TABLE gate (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            base BLOB NOT NULL, position INTEGER NOT NULL, chain_hash BLOB NOT NULL,
            incarnation BLOB NOT NULL, sequence INTEGER NOT NULL, checker_key BLOB NOT NULL,
            last_approval BLOB, last_ack BLOB
        );
        CREATE TABLE events (
            base BLOB NOT NULL, event_id BLOB NOT NULL, position INTEGER NOT NULL UNIQUE,
            event_digest BLOB NOT NULL UNIQUE, commitment BLOB NOT NULL, body BLOB NOT NULL,
            PRIMARY KEY(base, event_id)
        );
        CREATE TABLE bodies (
            base BLOB NOT NULL, commitment BLOB NOT NULL, body BLOB NOT NULL,
            PRIMARY KEY(base, commitment)
        );",
        )
        .map_err(sql)?;
        tx.execute(
            "INSERT INTO gate VALUES (1, ?1, 0, ?2, ?3, 0, ?4, NULL, NULL)",
            params![
                initial.base.0.as_slice(),
                initial.head.hash.0.as_slice(),
                initial.incarnation.as_slice(),
                initial.checker_key.as_slice()
            ],
        )
        .map_err(sql)?;
        tx.pragma_update(None, "user_version", SCHEMA)
            .map_err(sql)?;
        tx.commit().map_err(sql)?;
        Ok(Self {
            connection,
            #[cfg(test)]
            fail_commit: false,
        })
    }

    /// Refuses newer or uninitialized schemas *before* any mutation. There is no
    /// upgrade path: a version-1 file can hold descriptors whose bodies were never
    /// written, and accepting it would create the dangling state this format forbids.
    pub fn open(path: &Path) -> Result<Self, Refusal> {
        let connection = connect(path)?;
        if version(&connection)? != SCHEMA
            || !table_exists(&connection, "gate")?
            || !table_exists(&connection, "bodies")?
        {
            return Err(Refusal::Unavailable);
        }
        let db = Self {
            connection,
            #[cfg(test)]
            fail_commit: false,
        };
        db.state()?;
        Ok(db)
    }

    pub fn state(&self) -> Result<GateState, Refusal> {
        gate(&self.connection)
    }

    pub fn last_outcome(&self) -> Result<Option<LastOutcome>, Refusal> {
        let (approval, ack): (Option<Vec<u8>>, Option<Vec<u8>>) = self
            .connection
            .query_row(
                "SELECT last_approval, last_ack FROM gate WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(sql)?;
        let Some(approval) = approval else {
            return if ack.is_none() {
                Ok(None)
            } else {
                Err(Refusal::Unavailable)
            };
        };
        let approval = SignedApproval::decode(&approval).map_err(|_| Refusal::Unavailable)?;
        let ack = ack
            .map(|bytes| Commitment::decode(&bytes).map_err(|_| Refusal::Unavailable))
            .transpose()?;
        let next = self.state()?;
        if approval.approval.base != next.base
            || approval.approval.incarnation != next.incarnation
            || approval.approval.sequence != next.sequence
            || ack.is_some_and(|c| c.base() != next.base || c.head().position > next.head.position)
        {
            return Err(Refusal::Unavailable);
        }
        Ok(Some(LastOutcome {
            approval,
            next,
            ack,
        }))
    }

    /// One IMMEDIATE transaction is the admission/ordering/response boundary.
    /// `response_binding` MUST come from the actual live one-use response channel,
    /// not a serialized field of the request. No bytes or Ack escape before commit.
    pub fn consume(
        &mut self,
        approval: &SignedApproval,
        operation: &Operation,
        response_binding: Digest,
        clock: &impl Clock,
    ) -> Result<Outcome, Refusal> {
        #[cfg(test)]
        let fail_commit = self.fail_commit;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let before = gate(&tx)?;
        check_head(&tx, before)?;
        let existing = match operation {
            Operation::Append(event) => {
                lookup(&tx, before, Some(event.id()), None)?.map(|(c, _)| c)
            }
            _ => None,
        };
        let staged_body = match operation {
            Operation::Append(event) => {
                let reference = referenced_body(event).map_err(|_| Refusal::Unavailable)?;
                stored_body(&tx, before.base, reference)?.map(|body| body.commitment())
            }
            _ => None,
        };
        let plan = plan_consumption(
            &before,
            approval,
            operation,
            clock.window()?,
            existing,
            staged_body,
            response_binding,
        )
        .map_err(Refusal::Access)?;
        let output = match operation {
            Operation::Append(event) => {
                let ack = plan.ack.ok_or(Refusal::Unavailable)?;
                if let Some(commitment) = plan.append {
                    if commitment != ack {
                        return Err(Refusal::Unavailable);
                    }
                    tx.execute("INSERT INTO events (base, event_id, position, event_digest, commitment, body)
                        VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![before.base.0.as_slice(),
                        event.id().0.as_slice(), number(commitment.head().position)?,
                        event.digest().0.as_slice(), commitment.encode(), event.encode()]).map_err(sql)?;
                }
                Outcome::Ack(ack)
            }
            Operation::Read(selection) => {
                let mut bytes = Vec::with_capacity(selection.objects().len());
                for digest in selection.objects() {
                    let (_, body) =
                        lookup(&tx, before, None, Some(*digest))?.ok_or(Refusal::Unavailable)?;
                    bytes.push(body);
                }
                Outcome::Read(bytes)
            }
            Operation::StageBody(body) => {
                let commitment = plan.stage.ok_or(Refusal::Unavailable)?;
                // Repeat staging of identical bytes keeps one row and does not fork.
                let changed = tx
                    .execute(
                        "INSERT OR IGNORE INTO bodies (base, commitment, body) VALUES (?1, ?2, ?3)",
                        params![
                            before.base.0.as_slice(),
                            commitment.0.as_slice(),
                            body.bytes()
                        ],
                    )
                    .map_err(sql)?;
                if changed == 0 {
                    // An existing row must still hash to the same commitment.
                    stored_body(&tx, before.base, commitment)?.ok_or(Refusal::Unavailable)?;
                }
                Outcome::Staged(commitment)
            }
            Operation::ReadBodies(selection) => {
                let mut bodies = Vec::with_capacity(selection.objects().len());
                for digest in selection.objects() {
                    let body =
                        stored_body(&tx, before.base, *digest)?.ok_or(Refusal::Unavailable)?;
                    bodies.push(body.bytes().to_vec());
                }
                Outcome::ReadBodies(bodies)
            }
        };
        // Compare the entire prior gate, including the pinned checker and incarnation,
        // even though IMMEDIATE serializes local writers. Never UPDATE by sequence alone.
        let changed = tx
            .execute(
                "UPDATE gate SET position=?1, chain_hash=?2, sequence=?3,
            last_approval=?4, last_ack=?5 WHERE singleton=1 AND base=?6 AND position=?7
            AND chain_hash=?8 AND incarnation=?9 AND sequence=?10 AND checker_key=?11",
                params![
                    number(plan.next.head.position)?,
                    plan.next.head.hash.0.as_slice(),
                    number(plan.next.sequence)?,
                    approval.encode(),
                    plan.ack.map(|c| c.encode()),
                    before.base.0.as_slice(),
                    number(before.head.position)?,
                    before.head.hash.0.as_slice(),
                    before.incarnation.as_slice(),
                    number(before.sequence)?,
                    before.checker_key.as_slice()
                ],
            )
            .map_err(sql)?;
        if changed != 1 {
            return Err(Refusal::Unavailable);
        }
        #[cfg(test)]
        if fail_commit {
            // Test-only deferred FK violation makes SQLite's COMMIT itself fail.
            tx.execute("INSERT INTO fail_commit (parent) VALUES (42)", [])
                .map_err(sql)?;
        }
        tx.commit().map_err(sql)?;
        Ok(output)
    }
}

fn sql(_: rusqlite::Error) -> Refusal {
    Refusal::Unavailable
}
fn number(value: u64) -> Result<i64, Refusal> {
    i64::try_from(value).map_err(|_| Refusal::Unavailable)
}
fn positive(value: i64) -> Result<u64, Refusal> {
    u64::try_from(value).map_err(|_| Refusal::Unavailable)
}
fn array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], Refusal> {
    bytes.try_into().map_err(|_| Refusal::Unavailable)
}
fn connect(path: &Path) -> Result<Connection, Refusal> {
    let conn = Connection::open(path).map_err(sql)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(sql)?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(sql)?;
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(sql)?;
    Ok(conn)
}
fn version(conn: &Connection) -> Result<u32, Refusal> {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(sql)
}
fn table_exists(conn: &Connection, name: &str) -> Result<bool, Refusal> {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
        [name],
        |_| Ok(()),
    )
    .optional()
    .map(|found| found.is_some())
    .map_err(sql)
}
fn gate(conn: &Connection) -> Result<GateState, Refusal> {
    let (base, position, hash, incarnation, sequence, key): (Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, Vec<u8>) =
        conn.query_row("SELECT base, position, chain_hash, incarnation, sequence, checker_key FROM gate WHERE singleton=1", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))).map_err(sql)?;
    Ok(GateState {
        base: BaseId(array(base)?),
        head: Head {
            position: positive(position)?,
            hash: Digest(array(hash)?),
        },
        incarnation: array(incarnation)?,
        sequence: positive(sequence)?,
        checker_key: array(key)?,
    })
}
fn check_head(tx: &Transaction<'_>, state: GateState) -> Result<(), Refusal> {
    if state.head == Head::EMPTY {
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .map_err(sql)?;
        return if count == 0 {
            Ok(())
        } else {
            Err(Refusal::Unavailable)
        };
    }
    let (commitment, _) = lookup_position(tx, state, state.head.position)?;
    if commitment.head() == state.head {
        Ok(())
    } else {
        Err(Refusal::Unavailable)
    }
}
fn lookup(
    tx: &Transaction<'_>,
    state: GateState,
    id: Option<EventId>,
    digest: Option<Digest>,
) -> Result<Option<(Commitment, Vec<u8>)>, Refusal> {
    let record: Option<Record> = if let Some(id) = id {
        tx.query_row("SELECT position, event_id, event_digest, commitment, body FROM events WHERE base=?1 AND event_id=?2",
            params![state.base.0.as_slice(), id.0.as_slice()], record).optional().map_err(sql)?
    } else if let Some(digest) = digest {
        tx.query_row("SELECT position, event_id, event_digest, commitment, body FROM events WHERE base=?1 AND event_digest=?2",
            params![state.base.0.as_slice(), digest.0.as_slice()], record).optional().map_err(sql)?
    } else {
        return Err(Refusal::Unavailable);
    };
    record.map(|record| validate(tx, state, record)).transpose()
}
/// Load one staged body, re-deriving its commitment from the stored bytes. A
/// missing row is reported as absent; an unparseable or mismatched row refuses.
fn stored_body(
    tx: &Transaction<'_>,
    base: BaseId,
    commitment: Digest,
) -> Result<Option<BodyObject>, Refusal> {
    let stored: Option<Vec<u8>> = tx
        .query_row(
            "SELECT body FROM bodies WHERE base=?1 AND commitment=?2",
            params![base.0.as_slice(), commitment.0.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql)?;
    stored
        .map(|bytes| {
            let body = BodyObject::new(bytes).map_err(|_| Refusal::Unavailable)?;
            if body.commitment() != commitment {
                return Err(Refusal::Unavailable);
            }
            Ok(body)
        })
        .transpose()
}
fn lookup_position(
    tx: &Transaction<'_>,
    state: GateState,
    position: u64,
) -> Result<(Commitment, Vec<u8>), Refusal> {
    let row = tx.query_row(
        "SELECT position, event_id, event_digest, commitment, body FROM events WHERE base=?1 AND position=?2",
        params![state.base.0.as_slice(), number(position)?], record).map_err(sql)?;
    validate(tx, state, row)
}
type Record = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
fn record(row: &rusqlite::Row<'_>) -> rusqlite::Result<Record> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}
fn validate(
    tx: &Transaction<'_>,
    state: GateState,
    row: Record,
) -> Result<(Commitment, Vec<u8>), Refusal> {
    let (position, indexed_id, indexed_digest, bytes, body) = row;
    let position = positive(position)?;
    let commitment = Commitment::decode(&bytes).map_err(|_| Refusal::Unavailable)?;
    let event = OpaqueEvent::decode(&body).map_err(|_| Refusal::Unavailable)?;
    if position == 0
        || position > state.head.position
        || commitment.base() != state.base
        || commitment.head().position != position
        || array::<32>(indexed_id)? != event.id().0
        || array::<32>(indexed_digest)? != event.digest().0
        || commitment.event_id() != event.id()
        || commitment.verify_body(&event).is_err()
    {
        return Err(Refusal::Unavailable);
    }
    let previous = if position == 1 {
        Head::EMPTY
    } else {
        let bytes: Vec<u8> = tx
            .query_row(
                "SELECT commitment FROM events WHERE base=?1 AND position=?2",
                params![state.base.0.as_slice(), number(position - 1)?],
                |r| r.get(0),
            )
            .map_err(sql)?;
        let prior = Commitment::decode(&bytes).map_err(|_| Refusal::Unavailable)?;
        if prior.base() != state.base || prior.head().position != position - 1 {
            return Err(Refusal::Unavailable);
        }
        prior.head()
    };
    let canonical =
        Commitment::order(state.base, previous, &event).map_err(|_| Refusal::Unavailable)?;
    if commitment != canonical
        || (position == state.head.position && commitment.head() != state.head)
    {
        return Err(Refusal::Unavailable);
    }
    Ok((commitment, body))
}
