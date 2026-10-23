//! A base's verified control facts, as the metadata-only control feed judged
//! them: one row per control-route event, with its route-derived ID, what the
//! last accepted control left once it was judged, and the feed's cursor with
//! the authenticated endpoint its coverage reaches. Only that feed writes
//! them, and only once a scan's coverage is established; they only grow, and
//! a server cannot lower them. Content follows its own cursor (`sync_state`)
//! and may lag behind them.
//!
//! A rekey whose seal set this device has not opened yet keeps a durable wait
//! until its key is installed.
use crate::{DeviceDatabase, StoreError};
use bh_sync::{OrderState, receipt::RECEIPT_LEN};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

pub(crate) fn migrate(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    tx.execute_batch(
        "CREATE TABLE base_control_fact (
            base BLOB NOT NULL CHECK(length(base)=32),
            position INTEGER NOT NULL CHECK(position>0),
            head_hash BLOB NOT NULL CHECK(length(head_hash)=32),
            digest BLOB NOT NULL CHECK(length(digest)=32),
            event_id BLOB NOT NULL CHECK(length(event_id)=32),
            accepted INTEGER NOT NULL CHECK(accepted IN (0,1)),
            control_position INTEGER NOT NULL CHECK(control_position>0
              AND control_position<=position),
            control_hash BLOB NOT NULL CHECK(length(control_hash)=32),
            control_digest BLOB NOT NULL CHECK(length(control_digest)=32),
            account_position INTEGER NOT NULL CHECK(account_position>0),
            account_hash BLOB NOT NULL CHECK(length(account_hash)=32),
            epoch_id BLOB CHECK(epoch_id IS NULL OR length(epoch_id)=32),
            epoch_position INTEGER NOT NULL CHECK(epoch_position>0
              AND epoch_position<=control_position),
            epoch_hash BLOB NOT NULL CHECK(length(epoch_hash)=32),
            floor INTEGER NOT NULL CHECK(floor BETWEEN 1 AND 65535),
            account_change BLOB,
            CHECK(accepted=1 OR account_change IS NULL),
            CHECK(accepted=0 OR (control_position=position AND control_digest=digest
              AND control_hash=head_hash)),
            PRIMARY KEY(base,position)
        ) WITHOUT ROWID;
        CREATE INDEX base_control_fact_id ON base_control_fact(base,event_id,position);
        CREATE TRIGGER base_control_fact_kept BEFORE UPDATE ON base_control_fact
          BEGIN SELECT RAISE(ABORT,'control facts are kept'); END;
        CREATE TABLE base_control_cursor (
            base BLOB PRIMARY KEY CHECK(length(base)=32),
            position INTEGER NOT NULL CHECK(position>0),
            head_hash BLOB NOT NULL CHECK(length(head_hash)=32),
            node_hash BLOB NOT NULL CHECK(length(node_hash)=32),
            covered_position INTEGER NOT NULL CHECK(covered_position>=position),
            covered BLOB NOT NULL CHECK(length(covered)=82),
            receipt BLOB NOT NULL CHECK(length(receipt)=300),
            metadata_id BLOB NOT NULL CHECK(length(metadata_id)=32)
        ) WITHOUT ROWID;
        CREATE TRIGGER base_control_cursor_monotone BEFORE UPDATE ON base_control_cursor
          WHEN NEW.position<OLD.position OR NEW.covered_position<OLD.covered_position
            OR NEW.metadata_id!=OLD.metadata_id
          BEGIN SELECT RAISE(ABORT,'control cursor never moves back'); END;
        CREATE TABLE base_seal_wait (
            base BLOB NOT NULL CHECK(length(base)=32),
            key_id BLOB NOT NULL CHECK(length(key_id)=32),
            position INTEGER NOT NULL CHECK(position>0),
            event_id BLOB NOT NULL CHECK(length(event_id)=32),
            count INTEGER NOT NULL CHECK(count BETWEEN 1 AND 65535),
            commitment BLOB NOT NULL CHECK(length(commitment)=32),
            PRIMARY KEY(base,key_id)
        ) WITHOUT ROWID;",
    )
}

/// One judged control-route event and the verified control state once it
/// was judged. For a rejected control, `control` and everything after it are
/// the last accepted control's, never its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlFact {
    pub position: u64,
    pub head_hash: [u8; 32],
    /// The event's own `OpaqueEvent::digest`, accepted or not.
    pub digest: [u8; 32],
    /// Its control-route publication ID. The first fact with an ID is its
    /// first use, rejected or not; a later one is a repeat.
    pub event_id: [u8; 32],
    pub accepted: bool,
    /// The last accepted control at or before this position: its head and
    /// digest.
    pub control: (u64, [u8; 32]),
    pub control_digest: [u8; 32],
    /// The base's copy of the account after it.
    pub account: (u64, [u8; 32]),
    /// The content epoch after it; None while closed.
    pub epoch: Option<[u8; 32]>,
    /// The head of the control that installed the epoch in force.
    pub epoch_installed: (u64, [u8; 32]),
    pub floor: u16,
    /// An accepted control's copied account events (`encode_copies`).
    pub account_change: Option<Vec<u8>>,
}

/// How far the control feed has judged: the last control-route event's
/// global head and raw node, the endpoint opening its coverage was verified
/// against with the hosting receipt for that endpoint's head, and the base's
/// metadata key id. Every control up to `covered` is judged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlCursor {
    pub position: u64,
    pub head_hash: [u8; 32],
    /// The raw control node after it, which the next control extends.
    pub node_hash: [u8; 32],
    /// The authenticated endpoint coverage reaches: its raw control is this
    /// cursor's, and its position is at or after it.
    pub covered: OrderState,
    pub receipt: [u8; RECEIPT_LEN],
    pub metadata_id: [u8; 32],
}

/// A rekey whose seal set is not opened yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealWait {
    pub base: [u8; 32],
    pub key_id: [u8; 32],
    pub position: u64,
    pub event_id: [u8; 32],
    pub count: u16,
    pub commitment: [u8; 32],
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

const FACT_COLUMNS: &str =
    "position,head_hash,digest,event_id,accepted,control_position,control_hash,
    control_digest,account_position,account_hash,epoch_id,epoch_position,epoch_hash,floor,
    account_change";

type FactRow = (
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    bool,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Option<Vec<u8>>,
    i64,
    Vec<u8>,
    u16,
    Option<Vec<u8>>,
);
fn fact_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<FactRow> {
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
        r.get(11)?,
        r.get(12)?,
        r.get(13)?,
        r.get(14)?,
    ))
}
fn fact(row: FactRow) -> Result<ControlFact, StoreError> {
    let (p, head, digest, id, accepted, cp, ch, cd, ap, ah, epoch, ep, eh, floor, change) = row;
    Ok(ControlFact {
        position: unsigned(p)?,
        head_hash: array(head)?,
        digest: array(digest)?,
        event_id: array(id)?,
        accepted,
        control: (unsigned(cp)?, array(ch)?),
        control_digest: array(cd)?,
        account: (unsigned(ap)?, array(ah)?),
        epoch: epoch.map(array).transpose()?,
        epoch_installed: (unsigned(ep)?, array(eh)?),
        floor,
        account_change: change,
    })
}

fn read_cursor(
    connection: &rusqlite::Connection,
    base: [u8; 32],
) -> Result<Option<ControlCursor>, StoreError> {
    type Row = (i64, Vec<u8>, Vec<u8>, i64, Vec<u8>, Vec<u8>, Vec<u8>);
    let row: Option<Row> = connection
        .prepare_cached(
            "SELECT position,head_hash,node_hash,covered_position,covered,receipt,metadata_id
             FROM base_control_cursor WHERE base=?1",
        )?
        .query_row(params![base.as_slice()], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })
        .optional()?;
    row.map(
        |(position, head, node, covered_at, covered, receipt, metadata)| {
            let covered = OrderState::decode(&covered).map_err(|_| StoreError::CorruptSyncState)?;
            if covered.position() != unsigned(covered_at)? {
                return Err(StoreError::CorruptSyncState);
            }
            Ok(ControlCursor {
                position: unsigned(position)?,
                head_hash: array(head)?,
                node_hash: array(node)?,
                covered,
                receipt: array(receipt)?,
                metadata_id: array(metadata)?,
            })
        },
    )
    .transpose()
}

impl DeviceDatabase {
    /// Where the control feed of `base` has judged to, if it has started.
    pub fn control_cursor(&self, base: [u8; 32]) -> Result<Option<ControlCursor>, StoreError> {
        read_cursor(&self.connection, base)
    }

    /// The last judged control at or before `position`.
    pub fn control_fact_at(
        &self,
        base: [u8; 32],
        position: u64,
    ) -> Result<Option<ControlFact>, StoreError> {
        let position = signed(position.min(i64::MAX as u64))?;
        self.connection
            .prepare_cached(&format!(
                "SELECT {FACT_COLUMNS} FROM base_control_fact
                 WHERE base=?1 AND position<=?2 ORDER BY position DESC LIMIT 1"
            ))?
            .query_row(params![base.as_slice(), position], fact_row)
            .optional()?
            .map(fact)
            .transpose()
    }

    /// The judged control exactly at `position`, if there is one.
    pub fn control_fact(
        &self,
        base: [u8; 32],
        position: u64,
    ) -> Result<Option<ControlFact>, StoreError> {
        self.connection
            .prepare_cached(&format!(
                "SELECT {FACT_COLUMNS} FROM base_control_fact WHERE base=?1 AND position=?2"
            ))?
            .query_row(params![base.as_slice(), signed(position)?], fact_row)
            .optional()?
            .map(fact)
            .transpose()
    }

    /// The account changes accepted controls applied at or before `through`,
    /// in position order.
    pub fn control_account_changes(
        &self,
        base: [u8; 32],
        through: u64,
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        let through = signed(through.min(i64::MAX as u64))?;
        let mut stmt = self.connection.prepare_cached(
            "SELECT account_change FROM base_control_fact
             WHERE base=?1 AND position<=?2 AND account_change IS NOT NULL ORDER BY position",
        )?;
        Ok(stmt
            .query_map(params![base.as_slice(), through], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// The digest of the first judged control of `base` that used this
    /// control-route ID, rejected or not.
    pub fn control_first_use(
        &self,
        base: [u8; 32],
        event_id: [u8; 32],
    ) -> Result<Option<[u8; 32]>, StoreError> {
        let digest: Option<Vec<u8>> = self
            .connection
            .prepare_cached(
                "SELECT digest FROM base_control_fact WHERE base=?1 AND event_id=?2
                 ORDER BY position LIMIT 1",
            )?
            .query_row(params![base.as_slice(), event_id.as_slice()], |r| r.get(0))
            .optional()?;
        digest.map(array).transpose()
    }

    /// Commit judged controls after the cursor `expected` (None before the
    /// first), with the new cursor and any seal waits they started, in one
    /// transaction. New facts may be empty only when the cursor keeps its
    /// raw control and extends its coverage. `StaleProgress` if the cursor
    /// changed meanwhile.
    pub fn commit_controls(
        &mut self,
        base: [u8; 32],
        expected: Option<&ControlCursor>,
        facts: &[ControlFact],
        cursor: &ControlCursor,
        waits: &[SealWait],
    ) -> Result<(), StoreError> {
        let covered_at = cursor.covered.position();
        let raw = cursor.covered.raw_control();
        let same_raw = expected.is_some_and(|e| {
            e.position == cursor.position
                && e.head_hash == cursor.head_hash
                && e.node_hash == cursor.node_hash
        });
        let ends = match facts.last() {
            Some(last) => last.position == cursor.position && last.head_hash == cursor.head_hash,
            None => same_raw && expected.is_some_and(|e| covered_at > e.covered.position()),
        };
        if !ends
            || covered_at < cursor.position
            || raw.position != cursor.position
            || raw.node_hash.0 != cursor.node_hash
            || expected.is_some_and(|e| {
                covered_at < e.covered.position() || e.metadata_id != cursor.metadata_id
            })
        {
            return Err(StoreError::CorruptSyncState);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = read_cursor(&tx, base)?;
        if current.as_ref() != expected {
            return Err(StoreError::StaleProgress);
        }
        let mut after = expected.map_or(0, |e| e.position);
        for f in facts {
            if f.position <= after {
                return Err(StoreError::CorruptSyncState);
            }
            after = f.position;
            tx.execute(
                "INSERT INTO base_control_fact (base,position,head_hash,digest,event_id,accepted,
                   control_position,control_hash,control_digest,account_position,account_hash,
                   epoch_id,epoch_position,epoch_hash,floor,account_change)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                params![
                    base.as_slice(),
                    signed(f.position)?,
                    f.head_hash.as_slice(),
                    f.digest.as_slice(),
                    f.event_id.as_slice(),
                    f.accepted,
                    signed(f.control.0)?,
                    f.control.1.as_slice(),
                    f.control_digest.as_slice(),
                    signed(f.account.0)?,
                    f.account.1.as_slice(),
                    f.epoch.as_ref().map(|e| e.as_slice()),
                    signed(f.epoch_installed.0)?,
                    f.epoch_installed.1.as_slice(),
                    f.floor,
                    f.account_change.as_deref(),
                ],
            )?;
        }
        if cursor.position != after {
            return Err(StoreError::CorruptSyncState);
        }
        tx.execute(
            "INSERT INTO base_control_cursor (base,position,head_hash,node_hash,covered_position,
               covered,receipt,metadata_id)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(base) DO UPDATE SET position=excluded.position,
               head_hash=excluded.head_hash, node_hash=excluded.node_hash,
               covered_position=excluded.covered_position, covered=excluded.covered,
               receipt=excluded.receipt, metadata_id=excluded.metadata_id",
            params![
                base.as_slice(),
                signed(cursor.position)?,
                cursor.head_hash.as_slice(),
                cursor.node_hash.as_slice(),
                signed(covered_at)?,
                cursor.covered.encode().as_slice(),
                cursor.receipt.as_slice(),
                cursor.metadata_id.as_slice(),
            ],
        )?;
        for w in waits {
            if w.base != base {
                return Err(StoreError::CorruptSyncState);
            }
            tx.execute(
                "INSERT OR IGNORE INTO base_seal_wait (base,key_id,position,event_id,count,commitment)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    w.base.as_slice(),
                    w.key_id.as_slice(),
                    signed(w.position)?,
                    w.event_id.as_slice(),
                    w.count,
                    w.commitment.as_slice(),
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Every rekey whose seal set is not opened yet, oldest first.
    pub fn seal_waits(&self) -> Result<Vec<SealWait>, StoreError> {
        type Row = (Vec<u8>, Vec<u8>, i64, Vec<u8>, u16, Vec<u8>);
        let mut stmt = self.connection.prepare_cached(
            "SELECT base,key_id,position,event_id,count,commitment FROM base_seal_wait
             ORDER BY position",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<Row>>>()?;
        rows.into_iter()
            .map(|(base, key_id, position, event_id, count, commitment)| {
                Ok(SealWait {
                    base: array(base)?,
                    key_id: array(key_id)?,
                    position: unsigned(position)?,
                    event_id: array(event_id)?,
                    count,
                    commitment: array(commitment)?,
                })
            })
            .collect()
    }

    /// The wait for `key_id` is over: its key is installed.
    pub fn finish_seal_wait(&mut self, base: [u8; 32], key_id: [u8; 32]) -> Result<(), StoreError> {
        self.connection.execute(
            "DELETE FROM base_seal_wait WHERE base=?1 AND key_id=?2",
            params![base.as_slice(), key_id.as_slice()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_sync::{Digest, canonical::RawControlHead};

    fn fact(position: u64, accepted: bool, control: u64) -> ControlFact {
        ControlFact {
            position,
            head_hash: [position as u8; 32],
            digest: [100 + position as u8; 32],
            event_id: [150 + position as u8; 32],
            accepted,
            control: (control, [control as u8; 32]),
            control_digest: [100 + control as u8; 32],
            account: (3, [3; 32]),
            epoch: Some([7; 32]),
            epoch_installed: (1, [1; 32]),
            floor: 1,
            account_change: accepted.then(|| vec![position as u8]),
        }
    }
    /// The cursor after the control at `position`, covered through `covered`.
    fn cursor_to(position: u64, covered: u64) -> ControlCursor {
        let raw = RawControlHead {
            position,
            node_hash: Digest([200 + position as u8; 32]),
        };
        let suffix = covered - position;
        ControlCursor {
            position,
            head_hash: [position as u8; 32],
            node_hash: raw.node_hash.0,
            covered: OrderState::new(
                raw,
                suffix,
                Digest(if suffix == 0 { [0; 32] } else { [5; 32] }),
            )
            .unwrap(),
            receipt: [9; RECEIPT_LEN],
            metadata_id: [5; 32],
        }
    }
    fn cursor(position: u64) -> ControlCursor {
        cursor_to(position, position)
    }

    #[test]
    fn a_cursor_needs_matching_new_facts_and_failed_waits_roll_back_everything() {
        let mut db = DeviceDatabase::open(":memory:").unwrap();
        let base = [1; 32];
        db.commit_controls(base, None, &[fact(1, true, 1)], &cursor(1), &[])
            .unwrap();
        let mut forged = cursor(1);
        forged.head_hash = [99; 32];
        assert!(
            db.commit_controls(base, Some(&cursor(1)), &[], &forged, &[])
                .is_err()
        );
        // No new facts and no further coverage: nothing to commit.
        assert!(
            db.commit_controls(base, Some(&cursor(1)), &[], &cursor(1), &[])
                .is_err()
        );
        forged = cursor(4);
        forged.node_hash = [98; 32];
        assert!(
            db.commit_controls(base, Some(&cursor(1)), &[fact(4, true, 4)], &forged, &[])
                .is_err()
        );
        assert_eq!(db.control_cursor(base).unwrap(), Some(cursor(1)));
        assert_eq!(db.control_fact(base, 4).unwrap(), None);
        db.connection
            .execute_batch(
                "CREATE TRIGGER fail_wait BEFORE INSERT ON base_seal_wait
             BEGIN SELECT RAISE(ABORT,'injected wait failure'); END;",
            )
            .unwrap();
        let wait = SealWait {
            base,
            key_id: [7; 32],
            position: 4,
            event_id: [4; 32],
            count: 1,
            commitment: [6; 32],
        };
        assert!(
            db.commit_controls(
                base,
                Some(&cursor(1)),
                &[fact(4, true, 4)],
                &cursor(4),
                &[wait]
            )
            .is_err()
        );
        assert_eq!(db.control_cursor(base).unwrap(), Some(cursor(1)));
        assert_eq!(db.control_fact(base, 4).unwrap(), None);
        assert!(db.seal_waits().unwrap().is_empty());
    }

    #[test]
    fn coverage_extends_without_facts_and_never_moves_back() {
        let mut db = DeviceDatabase::open(":memory:").unwrap();
        let base = [1; 32];
        db.commit_controls(base, None, &[fact(1, true, 1)], &cursor_to(1, 3), &[])
            .unwrap();
        // Trailing content: the same raw control, covered further.
        db.commit_controls(base, Some(&cursor_to(1, 3)), &[], &cursor_to(1, 9), &[])
            .unwrap();
        assert_eq!(db.control_cursor(base).unwrap(), Some(cursor_to(1, 9)));
        // An older endpoint never lowers it, with or without facts.
        assert!(
            db.commit_controls(base, Some(&cursor_to(1, 9)), &[], &cursor_to(1, 5), &[])
                .is_err()
        );
        assert!(
            db.commit_controls(
                base,
                Some(&cursor_to(1, 9)),
                &[fact(4, true, 4)],
                &cursor_to(4, 4),
                &[]
            )
            .is_err()
        );
        assert!(
            db.connection
                .execute(
                    "UPDATE base_control_cursor SET covered_position=2 WHERE base=?1",
                    params![base.as_slice()],
                )
                .is_err()
        );
        assert_eq!(db.control_cursor(base).unwrap(), Some(cursor_to(1, 9)));
    }

    #[test]
    fn a_control_ids_first_use_is_its_earliest_fact_rejected_or_not() {
        let mut db = DeviceDatabase::open(":memory:").unwrap();
        let base = [1; 32];
        let rejected = ControlFact {
            event_id: [42; 32],
            ..fact(4, false, 1)
        };
        let repeat = ControlFact {
            event_id: [42; 32],
            ..fact(6, false, 1)
        };
        db.commit_controls(
            base,
            None,
            &[fact(1, true, 1), rejected.clone(), repeat],
            &cursor(6),
            &[],
        )
        .unwrap();
        assert_eq!(
            db.control_first_use(base, [42; 32]).unwrap(),
            Some(rejected.digest)
        );
        assert_eq!(
            db.control_first_use(base, fact(1, true, 1).event_id)
                .unwrap(),
            Some(fact(1, true, 1).digest)
        );
        assert_eq!(db.control_first_use(base, [43; 32]).unwrap(), None);
        assert_eq!(db.control_first_use([2; 32], [42; 32]).unwrap(), None);
    }

    #[test]
    fn facts_answer_as_of_a_position_and_only_grow() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("facts.sqlite");
        let base = [1; 32];
        let wait = SealWait {
            base,
            key_id: [8; 32],
            position: 4,
            event_id: [4; 32],
            count: 1,
            commitment: [6; 32],
        };
        {
            let mut db = DeviceDatabase::open(&path).unwrap();
            assert_eq!(db.control_cursor(base).unwrap(), None);
            db.commit_controls(base, None, &[fact(1, true, 1)], &cursor(1), &[])
                .unwrap();
            // A rejected control keeps the accepted one before it.
            db.commit_controls(
                base,
                Some(&cursor(1)),
                &[fact(4, true, 4), fact(9, false, 4)],
                &cursor(9),
                &[wait],
            )
            .unwrap();
            // The cursor moved: a writer that read it earlier is refused.
            assert!(matches!(
                db.commit_controls(
                    base,
                    Some(&cursor(1)),
                    &[fact(12, true, 12)],
                    &cursor(12),
                    &[]
                ),
                Err(StoreError::StaleProgress)
            ));
            // Facts never go back or change.
            assert!(
                db.commit_controls(base, Some(&cursor(9)), &[fact(9, true, 9)], &cursor(9), &[])
                    .is_err()
            );
            assert!(
                db.connection
                    .execute(
                        "UPDATE base_control_cursor SET position=1 WHERE base=?1",
                        params![base.as_slice()],
                    )
                    .is_err()
            );
            assert!(
                db.connection
                    .execute("UPDATE base_control_fact SET accepted=0", [])
                    .is_err()
            );
        }
        let mut db = DeviceDatabase::open(&path).unwrap();
        assert_eq!(db.control_cursor(base).unwrap(), Some(cursor(9)));
        assert_eq!(db.control_fact_at(base, 0).unwrap(), None);
        assert_eq!(db.control_fact_at(base, 3).unwrap(), Some(fact(1, true, 1)));
        assert_eq!(db.control_fact_at(base, 8).unwrap(), Some(fact(4, true, 4)));
        let rejected = db.control_fact_at(base, 100).unwrap().unwrap();
        assert_eq!(rejected, fact(9, false, 4));
        assert_ne!(rejected.digest, rejected.control_digest);
        assert_eq!(db.control_fact(base, 5).unwrap(), None);
        assert_eq!(
            db.control_account_changes(base, 8).unwrap(),
            vec![vec![1], vec![4]]
        );
        assert_eq!(db.control_account_changes(base, 3).unwrap(), vec![vec![1]]);
        assert_eq!(
            db.control_first_use(base, fact(9, false, 4).event_id)
                .unwrap(),
            Some(fact(9, false, 4).digest)
        );
        assert_eq!(db.seal_waits().unwrap(), vec![wait]);
        db.finish_seal_wait(base, wait.key_id).unwrap();
        assert_eq!(db.seal_waits().unwrap(), vec![]);
    }
}
