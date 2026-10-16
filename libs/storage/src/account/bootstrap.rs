//! Immutable encrypted initial materials, separate from the public account log.
use super::fixed;
use crate::{DeviceDatabase, StoreError};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

#[derive(Clone, PartialEq, Eq)]
pub struct InitialBootstrapRecord {
    pub anchor: [u8; 32],
    pub head_position: u64,
    pub head_hash: [u8; 32],
    pub recovery_record: Vec<u8>,
    pub device_seal: Vec<u8>,
    pub recovery_seal: Vec<u8>,
}

fn read(connection: &rusqlite::Connection) -> Result<Option<InitialBootstrapRecord>, StoreError> {
    Ok(connection
        .query_row(
            "SELECT anchor,head_position,head_hash,recovery_record,device_seal,recovery_seal
         FROM account_initial_bootstrap WHERE id=1",
            [],
            |r| {
                Ok(InitialBootstrapRecord {
                    anchor: fixed(r, 0, "anchor")?,
                    head_position: r.get::<_, i64>(1)? as u64,
                    head_hash: fixed(r, 2, "head_hash")?,
                    recovery_record: r.get(3)?,
                    device_seal: r.get(4)?,
                    recovery_seal: r.get(5)?,
                })
            },
        )
        .optional()?)
}

impl DeviceDatabase {
    pub fn initial_bootstrap(&self) -> Result<Option<InitialBootstrapRecord>, StoreError> {
        read(&self.connection)
    }

    /// The account layer authenticates these exact ciphertexts against its
    /// signed three-event prefix. Never replace an existing copy. If requested,
    /// deleting disposable setup and checking/retaining this copy is one commit.
    pub fn retain_initial_bootstrap(
        &mut self,
        row: &InitialBootstrapRecord,
        clear_pending: bool,
    ) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let anchor: Option<Vec<u8>> = tx
            .query_row(
                "SELECT anchor FROM account_state WHERE id=1 AND head_position>=3",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if anchor.as_deref() != Some(row.anchor.as_slice()) || row.head_position != 3 {
            return Err(StoreError::CorruptAccount);
        }
        if let Some(old) = read(&tx)? {
            if old != *row {
                return Err(StoreError::CorruptAccount);
            }
        } else {
            tx.execute(
                "INSERT INTO account_initial_bootstrap
                 (id,anchor,head_position,head_hash,recovery_record,device_seal,recovery_seal)
                 VALUES(1,?1,3,?2,?3,?4,?5)",
                params![
                    &row.anchor,
                    &row.head_hash,
                    &row.recovery_record,
                    &row.device_seal,
                    &row.recovery_seal
                ],
            )?;
        }
        if clear_pending {
            tx.execute("DELETE FROM account_pending_setup WHERE id=1", [])?;
        }
        tx.commit()?;
        Ok(())
    }
}
