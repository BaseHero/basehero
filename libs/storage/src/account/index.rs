//! Incremental local account indexes. Historical rows are epoch-keyed so reset
//! and reclamation never require rewriting lifetime history.
use super::{AccountStateRecord, fixed};
use crate::{DeviceDatabase, StoreError};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

/// The account layer's summary: fixed fields, then open membership changes.
const MIN_SUMMARY: usize = 2602;
const MAX_SUMMARY: usize = 1 << 20;
pub struct AccountProjectionRecord {
    pub anchor: [u8; 32],
    pub epoch: u64,
    pub through_position: u64,
    pub through_hash: [u8; 32],
    pub summary: Vec<u8>,
}
pub struct AccountDeviceRow {
    pub device: [u8; 32],
    pub keys: Vec<u8>,
    pub added: u64,
}
pub struct AccountProjectionDelta {
    pub epoch: Option<u64>,
    pub expected: (u64, [u8; 32]),
    pub through: (u64, [u8; 32]),
    pub summary: Vec<u8>,
    pub added: Vec<AccountDeviceRow>,
    pub removed: Vec<([u8; 32], u64)>,
    pub keys: Vec<(u8, [u8; 32], u64)>,
}
pub struct AccountProjectionView {
    pub state: AccountStateRecord,
    pub projection: Option<AccountProjectionRecord>,
    pub active: Vec<AccountDeviceRow>,
    pub first: Vec<u8>,
    pub last: Vec<u8>,
    pub through: Option<Vec<u8>>,
}
#[derive(Clone, Copy)]
pub struct AccountHistoryCursor {
    pub anchor: [u8; 32],
    pub cut: (u64, [u8; 32]),
    pub next_position: u64,
}
pub struct AccountHistoryPage {
    pub cursor: AccountHistoryCursor,
    pub events: Vec<Vec<u8>>,
    pub next_position: Option<u64>,
}
/// Distinguish malformed local projection data from transient database I/O.
pub fn is_account_corruption(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::CorruptAccount
            | StoreError::AuthorityChanged
            | StoreError::Database(
                rusqlite::Error::InvalidColumnType(..)
                    | rusqlite::Error::InvalidQuery
                    | rusqlite::Error::QueryReturnedNoRows
                    | rusqlite::Error::IntegralValueOutOfRange(..)
                    | rusqlite::Error::FromSqlConversionFailure(..)
            )
    )
}
pub(crate) fn bounded_blob(
    row: &rusqlite::Row<'_>,
    column: usize,
    max: usize,
) -> rusqlite::Result<Vec<u8>> {
    // Borrow SQLite's value; refuse before allocating/copying the payload.
    let bytes = row.get_ref(column)?.as_blob()?;
    if bytes.len() > max {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(bytes.to_vec())
}
pub(crate) fn sql(value: u64) -> Result<i64, StoreError> {
    value.try_into().map_err(|_| StoreError::CorruptAccount)
}
fn number(r: &rusqlite::Row<'_>, col: usize) -> rusqlite::Result<u64> {
    let n: i64 = r.get(col)?;
    n.try_into()
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(col, n))
}
fn event(conn: &Connection, pos: u64, max: usize) -> Result<Vec<u8>, StoreError> {
    Ok(conn.query_row(
        "SELECT bytes FROM account_events WHERE id=?1",
        [sql(pos)?],
        |r| bounded_blob(r, 0, max),
    )?)
}
fn state(conn: &Connection) -> Result<Option<AccountStateRecord>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT anchor,head_position,head_hash,stopped FROM account_state WHERE id=1",
            [],
            |r| {
                Ok(AccountStateRecord {
                    anchor: fixed(r, 0, "anchor")?,
                    head_position: number(r, 1)?,
                    head_hash: fixed(r, 2, "hash")?,
                    stopped: r.get(3)?,
                })
            },
        )
        .optional()?)
}
fn projection(conn: &Connection) -> Result<Option<AccountProjectionRecord>, StoreError> {
    Ok(conn.query_row("SELECT anchor,epoch,through_position,through_hash,summary FROM account_projection WHERE id=1", [], |r| {
        Ok(AccountProjectionRecord { anchor: fixed(r,0,"anchor")?, epoch: number(r,1)?,
            through_position: number(r,2)?, through_hash: fixed(r,3,"hash")?, summary: bounded_blob(r,4,MAX_SUMMARY)? })
    }).optional()?)
}
fn fresh_epoch(conn: &Connection) -> Result<u64, StoreError> {
    let max: u64 = conn.query_row(
        "SELECT MAX(
        COALESCE((SELECT MAX(epoch) FROM account_projection),0),
        COALESCE((SELECT MAX(epoch) FROM account_devices),0),
        COALESCE((SELECT MAX(epoch) FROM account_key_use),0))",
        [],
        |r| number(r, 0),
    )?;
    max.checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or(StoreError::CorruptAccount)
}
pub(super) fn reset(conn: &Connection, anchor: [u8; 32]) -> Result<u64, StoreError> {
    let epoch = fresh_epoch(conn)?;
    conn.execute("INSERT INTO account_projection(id,anchor,epoch,through_position,through_hash,summary)
        VALUES(1,?1,?2,0,zeroblob(32),x'') ON CONFLICT(id) DO UPDATE SET
        anchor=excluded.anchor,epoch=excluded.epoch,through_position=0,through_hash=zeroblob(32),summary=x''",
        params![anchor.as_slice(),sql(epoch)?])?;
    Ok(epoch)
}
pub(super) fn apply_delta(
    conn: &Connection,
    anchor: [u8; 32],
    d: &AccountProjectionDelta,
) -> Result<(), StoreError> {
    let current = projection(conn)?;
    let epoch = match current {
        Some(ref p)
            if p.anchor == anchor
                && (p.through_position, p.through_hash) == d.expected
                && d.epoch.is_none_or(|e| e == p.epoch) =>
        {
            p.epoch
        }
        None if d.epoch.is_none() && d.expected == (0, [0; 32]) => reset(conn, anchor)?,
        _ => return Err(StoreError::AuthorityChanged),
    };
    if d.through.0 <= d.expected.0 || !(MIN_SUMMARY..=MAX_SUMMARY).contains(&d.summary.len()) {
        return Err(StoreError::CorruptAccount);
    }
    for row in &d.added {
        conn.execute(
            "INSERT INTO account_devices(epoch,device,keys,added) VALUES(?1,?2,?3,?4)",
            params![
                sql(epoch)?,
                row.device.as_slice(),
                row.keys,
                sql(row.added)?
            ],
        )?;
    }
    for (device, position) in &d.removed {
        if conn.execute("UPDATE account_devices SET removed=?3 WHERE epoch=?1 AND device=?2 AND removed IS NULL AND added<?3",
            params![sql(epoch)?,device.as_slice(),sql(*position)?])? != 1 { return Err(StoreError::AuthorityChanged); }
    }
    for (space, key, position) in &d.keys {
        conn.execute(
            "INSERT INTO account_key_use(epoch,space,key,added) VALUES(?1,?2,?3,?4)",
            params![sql(epoch)?, space, key.as_slice(), sql(*position)?],
        )?;
    }
    conn.execute(
        "UPDATE account_projection SET through_position=?1,through_hash=?2,summary=?3 WHERE id=1",
        params![sql(d.through.0)?, d.through.1.as_slice(), d.summary],
    )?;
    Ok(())
}
impl DeviceDatabase {
    /// Coherent bounded metadata/current membership read. No historic device row
    /// or interior original is fetched except the checkpoint's exact event.
    pub fn account_projection_view(
        &self,
        max_event: usize,
    ) -> Result<Option<AccountProjectionView>, StoreError> {
        let tx = self.connection.unchecked_transaction()?;
        let Some(state) = state(&tx)? else {
            return Ok(None);
        };
        let first = event(&tx, 1, max_event)?;
        let last = event(&tx, state.head_position, max_event)?;
        let max: u64 = tx.query_row("SELECT COALESCE(MAX(id),0) FROM account_events", [], |r| {
            number(r, 0)
        })?;
        if max != state.head_position || bh_crypto::hash(&last) != state.head_hash {
            return Err(StoreError::CorruptAccount);
        }
        let projection = projection(&tx)?;
        let mut active = Vec::new();
        let mut through = None;
        if let Some(p) = &projection {
            if p.anchor != state.anchor || p.epoch == 0 || p.through_position > state.head_position
            {
                return Err(StoreError::CorruptAccount);
            }
            if p.through_position > 0 {
                through = Some(event(&tx, p.through_position, max_event)?);
                let mut stmt = tx.prepare("SELECT device,keys,added FROM account_devices WHERE epoch=?1 AND removed IS NULL ORDER BY added")?;
                let rows = stmt.query_map([sql(p.epoch)?], |r| {
                    Ok(AccountDeviceRow {
                        device: fixed(r, 0, "device")?,
                        keys: bounded_blob(r, 1, 1280)?,
                        added: number(r, 2)?,
                    })
                })?;
                active = rows.collect::<rusqlite::Result<_>>()?;
            }
        }
        tx.commit()?;
        Ok(Some(AccountProjectionView {
            state,
            projection,
            active,
            first,
            last,
            through,
        }))
    }
    pub fn account_projection(&self) -> Result<Option<AccountProjectionRecord>, StoreError> {
        projection(&self.connection)
    }
    pub fn reset_account_projection(&mut self, anchor: [u8; 32]) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if state(&tx)?.is_none_or(|s| s.anchor != anchor) {
            return Err(StoreError::AuthorityChanged);
        }
        reset(&tx, anchor)?;
        tx.commit()?;
        Ok(())
    }
    pub fn advance_account_projection(
        &mut self,
        anchor: [u8; 32],
        d: &AccountProjectionDelta,
        max_event: usize,
    ) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let s = state(&tx)?.ok_or(StoreError::AuthorityChanged)?;
        if s.anchor != anchor
            || d.through.0 > s.head_position
            || bh_crypto::hash(&event(&tx, d.through.0, max_event)?) != d.through.1
        {
            return Err(StoreError::AuthorityChanged);
        }
        apply_delta(&tx, anchor, d)?;
        tx.commit()?;
        Ok(())
    }
    /// Each maintenance pass reclaims at most 256 rows per table.
    pub fn cleanup_account_projection(&mut self) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM account_devices WHERE (epoch,device) IN
            (SELECT epoch,device FROM account_devices WHERE epoch < (SELECT epoch FROM account_projection WHERE id=1) LIMIT 256)",[])?;
        tx.execute("DELETE FROM account_key_use WHERE (epoch,space,key) IN
            (SELECT epoch,space,key FROM account_key_use WHERE epoch < (SELECT epoch FROM account_projection WHERE id=1) LIMIT 256)",[])?;
        tx.commit()?;
        Ok(())
    }
    /// Capture and guard each page in one short read transaction. The size bound
    /// is supplied by the owning protocol's codec, not duplicated here.
    pub fn account_history_page(
        &self,
        cursor: Option<AccountHistoryCursor>,
        limit: usize,
        max_event: usize,
    ) -> Result<Option<AccountHistoryPage>, StoreError> {
        if !(1..=256).contains(&limit) {
            return Err(StoreError::CorruptAccount);
        }
        let tx = self.connection.unchecked_transaction()?;
        let Some(s) = state(&tx)? else {
            return if cursor.is_some() {
                Err(StoreError::AuthorityChanged)
            } else {
                Ok(None)
            };
        };
        let c = cursor.unwrap_or(AccountHistoryCursor {
            anchor: s.anchor,
            cut: (s.head_position, s.head_hash),
            next_position: 1,
        });
        if c.anchor != s.anchor
            || c.cut.0 == 0
            || c.cut.0 > s.head_position
            || (c.cut.0 == s.head_position && c.cut.1 != s.head_hash)
            || c.next_position == 0
            || c.next_position > c.cut.0
            || bh_crypto::hash(&event(&tx, c.cut.0, max_event)?) != c.cut.1
        {
            return Err(StoreError::AuthorityChanged);
        }
        let end = c
            .cut
            .0
            .min(c.next_position.saturating_add(limit as u64 - 1));
        let mut events = Vec::with_capacity(limit);
        {
            let mut stmt = tx.prepare(
                "SELECT id,bytes FROM account_events WHERE id>=?1 AND id<=?2 ORDER BY id",
            )?;
            let mut rows = stmt.query(params![sql(c.next_position)?, sql(end)?])?;
            let mut next = c.next_position;
            while let Some(row) = rows.next()? {
                if number(row, 0)? != next {
                    return Err(StoreError::CorruptAccount);
                }
                events.push(bounded_blob(row, 1, max_event)?);
                next += 1;
            }
            if next != end + 1 {
                return Err(StoreError::CorruptAccount);
            }
        }
        tx.commit()?;
        Ok(Some(AccountHistoryPage {
            cursor: c,
            events,
            next_position: (end < c.cut.0).then_some(end + 1),
        }))
    }
}
