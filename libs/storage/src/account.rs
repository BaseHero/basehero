//! Device-local account journal rows: typed, opaque, and free of `bh-account`
//! types. Verification and the `AccountJournal` contract live in `bh-account`;
//! this module only persists exact bytes atomically. The connection stays private.

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{DeviceDatabase, StoreError};

/// The constant-size signed-history preflight; full account verification
/// belongs to the independent admission source.
pub struct AccountHistoryEdges {
    pub count: u64,
    pub first: Vec<u8>,
    pub last: Vec<u8>,
}

/// Durable verified-account summary; never a head without stored signed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountStateRecord {
    pub anchor: [u8; 32],
    pub head_position: u64,
    pub head_hash: [u8; 32],
    pub stopped: bool,
}

mod index;
pub use index::*;
mod bootstrap;
pub use bootstrap::InitialBootstrapRecord;

/// Recorded local device identity. Public halves only, never seeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceIdentityRecord {
    pub handle: [u8; 32],
    pub signing: [u8; 32],
    pub control: [u8; 32],
    pub receiving: [u8; 1216],
    pub policy: u8,
    pub kind: u8,
}

/// Versioned, opaque, native-protected pending-setup blob plus its stage code and
/// explicit kit-save flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingSetupRow {
    pub version: u16,
    pub stage: u8,
    pub kit_saved: bool,
    pub blob: Vec<u8>,
}

/// Opaque exact signed add plus encrypted signed delivery. Single unresolved row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedAdmissionRow {
    pub position: u64,
    pub previous: [u8; 32],
    pub event: Vec<u8>,
    pub delivery: Vec<u8>,
}

fn read_staged(
    connection: &rusqlite::Connection,
) -> Result<Option<StagedAdmissionRow>, StoreError> {
    let raw = connection
        .query_row(
            "SELECT position,previous,event,delivery FROM account_staged_admission WHERE id=1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((position, previous, event, delivery)) = raw else {
        return Ok(None);
    };
    if position <= 1 || event.is_empty() || delivery.is_empty() {
        return Err(StoreError::CorruptStagedAdmission);
    }
    let previous = previous
        .try_into()
        .map_err(|_| StoreError::CorruptStagedAdmission)?;
    Ok(Some(StagedAdmissionRow {
        position: u64::try_from(position).map_err(|_| StoreError::CorruptStagedAdmission)?,
        previous,
        event,
        delivery,
    }))
}

fn fixed<const N: usize>(
    row: &rusqlite::Row<'_>,
    index: usize,
    name: &str,
) -> rusqlite::Result<[u8; N]> {
    let bytes: Vec<u8> = row.get(index)?;
    bytes.try_into().map_err(|_| {
        rusqlite::Error::InvalidColumnType(index, name.into(), rusqlite::types::Type::Blob)
    })
}

impl DeviceDatabase {
    /// One writer-connection query: no durable account/setup/identity work may
    /// be discarded when reusing an interrupted signup container.
    pub fn account_container_empty(&self) -> Result<bool, StoreError> {
        let empty: bool = self.connection.query_row(
            "SELECT NOT EXISTS (
                SELECT 1 FROM account_state UNION ALL
                SELECT 1 FROM account_events UNION ALL
                SELECT 1 FROM account_outer_progress UNION ALL
                SELECT 1 FROM account_pending_setup UNION ALL
                SELECT 1 FROM account_staged_admission UNION ALL
                SELECT 1 FROM account_device UNION ALL
                SELECT 1 FROM note_updates UNION ALL
                SELECT 1 FROM note_outbox UNION ALL
                SELECT 1 FROM note_checkpoints UNION ALL
                SELECT 1 FROM notes UNION ALL
                SELECT 1 FROM view_records
            )",
            [],
            |row| row.get(0),
        )?;
        Ok(empty)
    }

    pub fn account_state(&self) -> Result<Option<AccountStateRecord>, StoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT anchor,head_position,head_hash,stopped FROM account_state WHERE id=1",
                [],
                |row| {
                    Ok(AccountStateRecord {
                        anchor: fixed::<32>(row, 0, "anchor")?,
                        head_position: row.get::<_, i64>(1)? as u64,
                        head_hash: fixed::<32>(row, 2, "head_hash")?,
                        stopped: row.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .optional()?)
    }

    /// O(1) anchor/head continuity preflight for a caller holding independently
    /// verified account state. This is not a substitute for verification of
    /// account controls on admission or changes.
    pub fn account_history_edges(&self) -> Result<Option<AccountHistoryEdges>, StoreError> {
        // MAX on the rowid btree and two edge lookups do not scan a long log.
        // Projection repair uses separate bounded, verified history pages.
        let count: Option<i64> =
            self.connection
                .query_row("SELECT MAX(id) FROM account_events", [], |r| r.get(0))?;
        let Some(count) = count else { return Ok(None) };
        if count <= 0 {
            return Err(StoreError::CorruptAccount);
        }
        let first = self.connection.query_row(
            "SELECT bytes FROM account_events ORDER BY id LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        let last = self.connection.query_row(
            "SELECT bytes FROM account_events ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        Ok(Some(AccountHistoryEdges {
            count: count as u64,
            first,
            last,
        }))
    }
    /// Original signed events in insertion order.
    pub fn account_history(&self) -> Result<Vec<Vec<u8>>, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT bytes FROM account_events ORDER BY id")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        rows.collect::<rusqlite::Result<_>>()
            .map_err(StoreError::from)
    }

    /// Append original signed bytes and set the head and stop flag in one
    /// transaction. An empty `events` slice only updates the stop flag. The head
    /// position must match the total stored event count, so a head never outlives
    /// its bytes.
    pub fn commit_account_verified(
        &mut self,
        anchor: [u8; 32],
        events: &[&[u8]],
        head_position: u64,
        head_hash: [u8; 32],
        stopped: bool,
    ) -> Result<(), StoreError> {
        self.commit_account_verified_projected(
            anchor,
            events,
            head_position,
            head_hash,
            stopped,
            None,
        )
    }

    /// The original bytes, remembered head and locally verified projection are
    /// one SQLite commit. Empty stop writes and legacy appends retain the prior
    /// verified cut so a later activation can resume bounded reconstruction.
    pub fn commit_account_verified_projected(
        &mut self,
        anchor: [u8; 32],
        events: &[&[u8]],
        head_position: u64,
        head_hash: [u8; 32],
        stopped: bool,
        projection: Option<&AccountProjectionDelta>,
    ) -> Result<(), StoreError> {
        self.commit_account_verified_confirmed(
            anchor,
            events,
            head_position,
            head_hash,
            stopped,
            projection,
            &[],
        )
    }

    /// Commit caller-verified originals, exact confirmation evidence and the
    /// derived projection in one transaction. Evidence may name only this append.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_account_verified_confirmed(
        &mut self,
        anchor: [u8; 32],
        events: &[&[u8]],
        head_position: u64,
        head_hash: [u8; 32],
        stopped: bool,
        projection: Option<&AccountProjectionDelta>,
        confirmations: &[crate::ConfirmationRow],
    ) -> Result<(), StoreError> {
        self.commit_account_verified_with_alerts(
            anchor,
            events,
            head_position,
            head_hash,
            stopped,
            projection,
            confirmations,
            None,
        )
    }

    /// The verified alert cursor and facts share the originals' transaction.
    /// `None` preserves the older account-only API for setup and legacy callers.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_account_verified_with_alerts(
        &mut self,
        anchor: [u8; 32],
        events: &[&[u8]],
        head_position: u64,
        head_hash: [u8; 32],
        stopped: bool,
        projection: Option<&AccountProjectionDelta>,
        confirmations: &[crate::ConfirmationRow],
        alerts: Option<&[crate::NewAlert]>,
    ) -> Result<(), StoreError> {
        if projection.is_some() && events.is_empty() {
            return Err(StoreError::CorruptAccount);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction.query_row(
            "SELECT COALESCE(MAX(id),0) FROM account_events",
            [],
            |row| row.get::<_, i64>(0),
        )? as u64;
        let stored: Option<(Vec<u8>, i64, Option<i64>)> = transaction
            .query_row(
                "SELECT anchor,head_position,observed_earliest_ms FROM account_state WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        match &stored {
            Some((previous_anchor, position, _))
                if previous_anchor.as_slice() != anchor.as_slice()
                    || *position != existing as i64 =>
            {
                return Err(StoreError::CorruptAccount);
            }
            _ => {}
        }
        // A first commit must carry the genesis bytes; never a bare head 0.
        if stored.is_none() && events.is_empty() {
            return Err(StoreError::HeadWithoutBytes);
        }
        if head_position != existing + events.len() as u64 {
            return Err(StoreError::HeadWithoutBytes);
        }
        if confirmations
            .iter()
            .any(|row| row.position <= existing || row.position > head_position)
        {
            return Err(StoreError::CorruptSecurity);
        }
        // Only new originals are bound by a previously observed accepted-head
        // time. Attaching the already accepted setup prefix's evidence is not
        // a new append and must not retime that prefix against a later floor.
        if !events.is_empty()
            && let Some((_, _, Some(floor))) = stored
        {
            let floor = u64::try_from(floor).map_err(|_| StoreError::CorruptAccount)?;
            if confirmations.len() != events.len() {
                // No writes have occurred: absent evidence is a retryable
                // refusal, not an authenticated time contradiction.
                return Err(StoreError::MissingTime);
            }
            if confirmations.iter().any(|row| row.earliest_ms < floor) {
                return Err(StoreError::TimeRegressed);
            }
        }
        for event in events {
            transaction.execute("INSERT INTO account_events(bytes) VALUES (?1)", [*event])?;
        }
        crate::security::put_confirmations(&transaction, confirmations)?;
        transaction.execute(
            "INSERT INTO account_state(id,anchor,head_position,head_hash,stopped)\n             VALUES (1,?1,?2,?3,?4)\n             ON CONFLICT(id) DO UPDATE SET\n               anchor=excluded.anchor,\n               head_position=excluded.head_position,\n               head_hash=excluded.head_hash,\n               stopped=MAX(account_state.stopped,excluded.stopped)",
            params![
                anchor.as_slice(),
                head_position as i64,
                head_hash.as_slice(),
                i64::from(stopped as u8)
            ],
        )?;
        if let Some(delta) = projection {
            index::apply_delta(&transaction, anchor, delta)?;
        }
        if let Some(alerts) = alerts {
            crate::security::record_alerts_tx(&transaction, head_position, alerts)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Attach the home's confirmations of setup positions 2 and 3 to the prefix
    /// this device committed untimed before reaching its home, replacing the
    /// projection with `projection`, a fresh timed replay, in the same commit.
    /// Only while setup is pending, the head is exactly that prefix with these
    /// originals and no confirmation is stored; nothing else is ever retimed.
    pub fn attach_setup_confirmations(
        &mut self,
        anchor: [u8; 32],
        head: (u64, [u8; 32]),
        originals: [&[u8]; 2],
        confirmations: &[crate::ConfirmationRow; 2],
        projection: Option<&AccountProjectionDelta>,
    ) -> Result<(), StoreError> {
        let [record, key] = confirmations;
        if head.0 != 3
            || (record.position, key.position) != (2, 3)
            || key.earliest_ms < record.earliest_ms
            || key.latest_ms < record.latest_ms
            || projection.is_some_and(|d| {
                d.epoch.is_some() || d.expected != (0, [0; 32]) || d.through != head
            })
        {
            return Err(StoreError::CorruptSecurity);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (pending, timed, indexed, count): (bool, bool, bool, i64) = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM account_pending_setup WHERE id=1),
                    EXISTS(SELECT 1 FROM account_confirmations),
                    EXISTS(SELECT 1 FROM account_projection),
                    (SELECT COALESCE(MAX(id),0) FROM account_events)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        let state: Option<(Vec<u8>, i64, Vec<u8>, i64)> = transaction
            .query_row(
                "SELECT anchor,head_position,head_hash,stopped FROM account_state WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let stored = {
            let mut statement = transaction
                .prepare("SELECT bytes FROM account_events WHERE id IN (2,3) ORDER BY id")?;
            statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        if !pending
            || timed
            || count != 3
            || indexed != projection.is_some()
            || state != Some((anchor.to_vec(), 3, head.1.to_vec(), 0))
            || stored != originals
            || bh_crypto::hash(originals[1]) != head.1
        {
            return Err(StoreError::AuthorityChanged);
        }
        crate::security::put_confirmations(&transaction, confirmations)?;
        if let Some(delta) = projection {
            index::reset(&transaction, anchor)?;
            index::apply_delta(&transaction, anchor, delta)?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn device_identity(&self) -> Result<Option<DeviceIdentityRecord>, StoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT handle,signing,control,receiving,policy,kind FROM account_device WHERE id=1",
                [],
                |row| {
                    Ok(DeviceIdentityRecord {
                        handle: fixed::<32>(row, 0, "handle")?,
                        signing: fixed::<32>(row, 1, "signing")?,
                        control: fixed::<32>(row, 2, "control")?,
                        receiving: fixed::<1216>(row, 3, "receiving")?,
                        policy: row.get::<_, i64>(4)? as u8,
                        kind: row.get::<_, i64>(5)? as u8,
                    })
                },
            )
            .optional()?)
    }

    pub fn commit_device_identity(
        &mut self,
        record: &DeviceIdentityRecord,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO account_device(id,handle,signing,control,receiving,policy,kind)\n             VALUES (1,?1,?2,?3,?4,?5,?6)\n             ON CONFLICT(id) DO UPDATE SET\n               handle=excluded.handle,\n               signing=excluded.signing,\n               control=excluded.control,\n               receiving=excluded.receiving,\n               policy=excluded.policy,\n               kind=excluded.kind",
            params![
                record.handle.as_slice(),
                record.signing.as_slice(),
                record.control.as_slice(),
                record.receiving.as_slice(),
                i64::from(record.policy),
                i64::from(record.kind)
            ],
        )?;
        Ok(())
    }

    pub fn pending_setup(&self) -> Result<Option<PendingSetupRow>, StoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT version,stage,kit_saved,blob FROM account_pending_setup WHERE id=1",
                [],
                |row| {
                    Ok(PendingSetupRow {
                        version: row.get::<_, i64>(0)? as u16,
                        stage: row.get::<_, i64>(1)? as u8,
                        kit_saved: row.get::<_, i64>(2)? != 0,
                        blob: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn commit_pending_setup(&mut self, record: &PendingSetupRow) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO account_pending_setup(id,version,stage,kit_saved,blob)\n             VALUES (1,?1,?2,?3,?4)\n             ON CONFLICT(id) DO UPDATE SET\n               version=excluded.version,\n               stage=excluded.stage,\n               kit_saved=MAX(account_pending_setup.kit_saved,excluded.kit_saved),\n               blob=excluded.blob",
            params![
                i64::from(record.version),
                i64::from(record.stage),
                i64::from(record.kit_saved as u8),
                record.blob.as_slice()
            ],
        )?;
        Ok(())
    }

    pub fn clear_pending_setup(&mut self) -> Result<(), StoreError> {
        self.connection
            .execute("DELETE FROM account_pending_setup WHERE id=1", [])?;
        Ok(())
    }

    pub fn staged_admission(&self) -> Result<Option<StagedAdmissionRow>, StoreError> {
        read_staged(&self.connection)
    }

    /// Reserve the one staged row under an IMMEDIATE write lock; never overwrite
    /// bytes that may already have reached the account home.
    pub fn insert_staged_admission(&mut self, row: &StagedAdmissionRow) -> Result<(), StoreError> {
        let position =
            i64::try_from(row.position).map_err(|_| StoreError::CorruptStagedAdmission)?;
        if position <= 1 || row.event.is_empty() || row.delivery.is_empty() {
            return Err(StoreError::CorruptStagedAdmission);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if read_staged(&tx)?.is_some() {
            return Err(StoreError::StagedAdmissionExists);
        }
        tx.execute("INSERT INTO account_staged_admission(id,position,previous,event,delivery) VALUES (1,?1,?2,?3,?4)",
            params![position, row.previous.as_slice(), row.event.as_slice(), row.delivery.as_slice()])?;
        tx.commit()?;
        Ok(())
    }

    /// A stale completion must not erase a newer staged admission. Missing is
    /// idempotent (including a restart after an already completed clear).
    pub fn clear_staged_admission(
        &mut self,
        expected: &StagedAdmissionRow,
    ) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        match read_staged(&tx)? {
            None => return Ok(()),
            Some(current) if current != *expected => {
                return Err(StoreError::StagedAdmissionChanged);
            }
            Some(_) => {}
        }
        tx.execute("DELETE FROM account_staged_admission WHERE id=1", [])?;
        tx.commit()?;
        Ok(())
    }
}
