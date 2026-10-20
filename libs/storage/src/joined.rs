//! A container that joined an existing account by QR. The showing device's
//! hint is kept until the admission it led to is committed; the admission,
//! its own base and a registration without a genesis receipt commit in one
//! transaction; activation commits once the base is caught up. These rows
//! grant nothing: the native owners verify before writing them, and the
//! container's note authority waits for activation.
use crate::{DeviceDatabase, StoreError, own_base::OwnBaseRecord, sync_state::LOG_BASE};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinedRecord {
    pub account: [u8; 32],
    /// The showing device's opened hint, kept so an interrupted admission can
    /// be verified again without the relay.
    pub hint: Vec<u8>,
    /// The signed personal-key delivery the addition carried, once admitted.
    pub delivery: Option<Vec<u8>>,
    /// The account position of this device's addition, once admitted.
    pub added_at: Option<u64>,
    pub activated: bool,
}

type Row = (Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<i64>, i64);

fn read(connection: &rusqlite::Connection) -> Result<Option<JoinedRecord>, StoreError> {
    let row: Option<Row> = connection
        .query_row(
            "SELECT account,hint,delivery,added_at,activated FROM joined_device WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    row.map(|(account, hint, delivery, added_at, activated)| {
        Ok(JoinedRecord {
            account: account
                .try_into()
                .map_err(|_| StoreError::CorruptSyncState)?,
            hint,
            delivery,
            added_at: added_at.map(|a| a as u64),
            activated: activated == 1,
        })
    })
    .transpose()
}

fn verified_anchor(tx: &Transaction<'_>) -> Result<Option<Vec<u8>>, StoreError> {
    Ok(tx
        .query_row(
            "SELECT anchor FROM account_state WHERE id=1 AND stopped=0",
            [],
            |r| r.get(0),
        )
        .optional()?)
}

impl DeviceDatabase {
    pub fn joined(&self) -> Result<Option<JoinedRecord>, StoreError> {
        read(&self.connection)
    }

    /// Keep the showing device's hint for `account`. A later pairing's hint
    /// replaces it until an admission is committed; after that it is fixed.
    pub fn record_join_hint(&mut self, account: [u8; 32], hint: &[u8]) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "INSERT INTO joined_device(id,account,hint) VALUES (1,?1,?2)
             ON CONFLICT(id) DO UPDATE SET account=excluded.account, hint=excluded.hint
               WHERE joined_device.delivery IS NULL",
            params![account.as_slice(), hint],
        )?;
        if changed == 0 {
            return Err(StoreError::AuthorityChanged);
        }
        Ok(())
    }

    /// Commit a verified admission in one transaction: the delivery and the
    /// addition's position, the own base record and its registration
    /// without a genesis receipt (the base log is read from its start),
    /// pinning `hosting_root` and latching its writer phase Registered. The
    /// verified account must already be committed. Exactly repeatable;
    /// other bytes after a commit are refused.
    pub fn commit_joined_admission(
        &mut self,
        delivery: &[u8],
        added_at: u64,
        own_base: &OwnBaseRecord,
        hosting_root: [u8; 32],
    ) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let joined = read(&tx)?.ok_or(StoreError::AuthorityChanged)?;
        if verified_anchor(&tx)?.as_deref() != Some(joined.account.as_slice())
            || own_base.account != joined.account
        {
            return Err(StoreError::AuthorityChanged);
        }
        match (&joined.delivery, joined.added_at) {
            (Some(kept), Some(at)) if kept.as_slice() == delivery && at == added_at => {}
            (None, None) => {
                tx.execute(
                    "UPDATE joined_device SET delivery=?1, added_at=?2 WHERE id=1",
                    params![delivery, added_at as i64],
                )?;
            }
            _ => return Err(StoreError::AuthorityChanged),
        }
        match crate::own_base::read_own_base(&tx)? {
            Some(kept) if kept == *own_base => {}
            Some(_) => return Err(StoreError::AuthorityChanged),
            None => {
                tx.execute(
                    "INSERT INTO own_base(id,account,base,genesis_descriptor,genesis_body,initial_key_package) VALUES (1,?1,?2,?3,?4,?5)",
                    params![
                        own_base.account.as_slice(),
                        own_base.base.as_slice(),
                        own_base.genesis_descriptor.as_slice(),
                        own_base.genesis_body.as_slice(),
                        own_base.initial_key_package.as_slice()
                    ],
                )?;
            }
        }
        crate::sync_state::register(&tx, own_base.base, None, hosting_root)?;
        tx.commit()?;
        Ok(())
    }

    /// Make the joined container usable, once its own base's verified
    /// progress holds at least the genesis. The caller has read the base to
    /// the tail it knows of.
    pub fn activate_joined(&mut self) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let joined = read(&tx)?.ok_or(StoreError::AuthorityChanged)?;
        if joined.delivery.is_none() {
            return Err(StoreError::AuthorityChanged);
        }
        let base = crate::own_base::read_own_base(&tx)?
            .ok_or(StoreError::AuthorityChanged)?
            .base;
        let progress = crate::sync_state::read_progress(&tx, LOG_BASE, base)?
            .ok_or(StoreError::MissingProgress)?;
        if progress.stopped.is_some() {
            return Err(StoreError::LogStopped);
        }
        if progress.position == 0 {
            return Err(StoreError::MissingProgress);
        }
        tx.execute("UPDATE joined_device SET activated=1 WHERE id=1", [])?;
        // Activation changes no typed state: a bootstrap reads the log from its
        // start, so ordered decisions made during it were already fully
        // informed, and this container could not list before now either.
        tx.commit()?;
        Ok(())
    }
}
