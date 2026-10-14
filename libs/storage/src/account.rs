//! Device-local account journal rows: typed, opaque, and free of `bh-account`
//! types. Verification and the `AccountJournal` contract live in `bh-account`;
//! this module only persists exact bytes atomically. The connection stays private.

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{DeviceDatabase, StoreError};

/// Durable verified-account summary; never a head without stored signed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountStateRecord {
    pub anchor: [u8; 32],
    pub head_position: u64,
    pub head_hash: [u8; 32],
    pub stopped: bool,
}

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
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction.query_row("SELECT COUNT(*) FROM account_events", [], |row| {
            row.get::<_, i64>(0)
        })? as u64;
        let stored_anchor: Option<Vec<u8>> = transaction
            .query_row("SELECT anchor FROM account_state WHERE id=1", [], |row| {
                row.get(0)
            })
            .optional()?;
        match stored_anchor {
            Some(existing) if existing.as_slice() != anchor.as_slice() => {
                return Err(StoreError::CorruptAccount);
            }
            _ => {}
        }
        // A first commit must carry the genesis bytes; never a bare head 0.
        if stored_anchor.is_none() && events.is_empty() {
            return Err(StoreError::HeadWithoutBytes);
        }
        if head_position != existing + events.len() as u64 {
            return Err(StoreError::HeadWithoutBytes);
        }
        for event in events {
            transaction.execute("INSERT INTO account_events(bytes) VALUES (?1)", [*event])?;
        }
        transaction.execute(
            "INSERT INTO account_state(id,anchor,head_position,head_hash,stopped)\n             VALUES (1,?1,?2,?3,?4)\n             ON CONFLICT(id) DO UPDATE SET\n               anchor=excluded.anchor,\n               head_position=excluded.head_position,\n               head_hash=excluded.head_hash,\n               stopped=MAX(account_state.stopped,excluded.stopped)",
            params![
                anchor.as_slice(),
                head_position as i64,
                head_hash.as_slice(),
                i64::from(stopped as u8)
            ],
        )?;
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
}
