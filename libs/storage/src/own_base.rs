//! Opaque original base bootstrap bytes. Verification and key access belong to
//! native account/device owners, never this storage adapter.
use crate::{DeviceDatabase, StoreError};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnBaseRecord {
    pub account: [u8; 32],
    pub base: [u8; 32],
    pub genesis_descriptor: Vec<u8>,
    pub genesis_body: Vec<u8>,
    pub initial_key_package: Vec<u8>,
}

pub(crate) fn read_own_base(
    connection: &rusqlite::Connection,
) -> Result<Option<OwnBaseRecord>, StoreError> {
    let row = connection.query_row(
        "SELECT account,base,genesis_descriptor,genesis_body,initial_key_package FROM own_base WHERE id=1", [],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
    ).optional()?;
    row.map(
        |(account, base, genesis_descriptor, genesis_body, initial_key_package)| {
            Ok(OwnBaseRecord {
                account: account.try_into().map_err(|_| StoreError::CorruptOwnBase)?,
                base: base.try_into().map_err(|_| StoreError::CorruptOwnBase)?,
                genesis_descriptor,
                genesis_body,
                initial_key_package,
            })
        },
    )
    .transpose()
}

impl DeviceDatabase {
    pub fn own_base(&self) -> Result<Option<OwnBaseRecord>, StoreError> {
        read_own_base(&self.connection)
    }

    /// The native caller supplies a current-generation predicate; inspect it
    /// while holding the SQLite writer transaction, including on a losing CAS.
    /// This does not verify genesis; the caller must verify its authority before use.
    pub fn create_own_base_if_absent(
        &mut self,
        record: &OwnBaseRecord,
        current: impl Fn() -> bool,
    ) -> Result<OwnBaseRecord, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let anchor: Option<Vec<u8>> = tx
            .query_row(
                "SELECT anchor FROM account_state WHERE id=1 AND stopped=0",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if !current() || anchor.as_deref() != Some(record.account.as_slice()) {
            return Err(StoreError::AuthorityChanged);
        }
        if let Some(winner) = read_own_base(&tx)? {
            if winner.account != record.account {
                return Err(StoreError::AuthorityChanged);
            }
            return Ok(winner);
        }
        tx.execute("INSERT INTO own_base(id,account,base,genesis_descriptor,genesis_body,initial_key_package) VALUES (1,?1,?2,?3,?4,?5)",
            params![record.account.as_slice(), record.base.as_slice(), record.genesis_descriptor.as_slice(), record.genesis_body.as_slice(), record.initial_key_package.as_slice()])?;
        // Only a newly created local own base gets this bypass. A legacy row
        // without a phase, including a losing CAS above, stays unavailable.
        tx.execute(
            "INSERT INTO base_writer_phase(base,phase) VALUES (?1,0)",
            [record.base],
        )?;
        // The own base's ordinary audience exists before its first Note, so an
        // empty base lists as complete-empty rather than unknown.
        crate::data::seed_scope_coverage(
            &tx,
            bh_data::Scope {
                base: record.base,
                audience: [0; 32],
            },
        )?;
        tx.commit()?;
        Ok(record.clone())
    }
}
