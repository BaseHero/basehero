//! Local window presentation saved only for the next authorized admission.
//! A record carries no authority and is never a reason to bind a page.
use crate::{DeviceDatabase, NoteKey, StoreError};
use rusqlite::{TransactionBehavior, params};

const VERSION: u32 = 1;
#[derive(Clone, Debug, PartialEq)]
pub struct ViewRecord {
    pub version: u32,
    pub key: NoteKey,
    pub anchor: Vec<u8>,
    pub head: Vec<u8>,
    pub cursor_offset: f64,
    pub frame: [f64; 4],
}

impl DeviceDatabase {
    /// Replace *all* records, including with an empty list. Call for every
    /// anchored container, not just containers with open windows.
    pub fn replace_view_records(&mut self, records: &[ViewRecord]) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM view_records", [])?;
        for record in records {
            if record.version != VERSION
                || !record.cursor_offset.is_finite()
                || !record.frame.iter().all(|value| value.is_finite())
            {
                return Err(StoreError::InvalidViewRecord);
            }
            tx.execute("INSERT INTO view_records(version,base,audience,note,anchor,head,cursor_offset,x,y,width,height)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)", params![
                record.version, record.key.base.as_slice(), record.key.audience.as_slice(),
                record.key.note.as_slice(), record.anchor, record.head, record.cursor_offset,
                record.frame[0],record.frame[1],record.frame[2],record.frame[3],
            ])?;
        }
        tx.commit()?;
        Ok(())
    }
    /// Atomic consume after verified anchoring. Unrecognized future versions
    /// are discarded rather than guessed at by an older client.
    pub fn take_view_records(&mut self) -> Result<Vec<ViewRecord>, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let records = {
            let mut query=tx.prepare("SELECT version,base,audience,note,anchor,head,cursor_offset,x,y,width,height FROM view_records ORDER BY id")?;
            let rows = query.query_map([], |row| {
                let version: u32 = row.get(0)?;
                let key = NoteKey {
                    base: fixed(row.get(1)?)?,
                    audience: fixed(row.get(2)?)?,
                    note: fixed(row.get(3)?)?,
                };
                Ok(ViewRecord {
                    version,
                    key,
                    anchor: row.get(4)?,
                    head: row.get(5)?,
                    cursor_offset: row.get(6)?,
                    frame: [row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?],
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        tx.execute("DELETE FROM view_records", [])?;
        tx.commit()?;
        Ok(records
            .into_iter()
            .filter(|record| {
                record.version == VERSION
                    && record.cursor_offset.is_finite()
                    && record.frame.iter().all(|v| v.is_finite())
            })
            .collect())
    }
    pub fn delete_view_records(&mut self) -> Result<(), StoreError> {
        self.connection.execute("DELETE FROM view_records", [])?;
        Ok(())
    }
}
fn fixed(bytes: Vec<u8>) -> rusqlite::Result<[u8; 32]> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
