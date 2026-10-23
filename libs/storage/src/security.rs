//! Device-local storage for verified security changes.

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{DeviceDatabase, StoreError};

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    tx.execute_batch(
        "CREATE TABLE security_alerts (
            id INTEGER PRIMARY KEY,
            kind INTEGER NOT NULL CHECK(kind BETWEEN 1 AND 9),
            position INTEGER CHECK(position>=0),
            subject BLOB CHECK(subject IS NULL OR length(subject)=32),
            actor BLOB CHECK(actor IS NULL OR length(actor)=32),
            time_ms INTEGER CHECK(time_ms IS NULL OR time_ms>=0),
            deadline_ms INTEGER CHECK(deadline_ms IS NULL OR deadline_ms>=0),
            shown INTEGER NOT NULL DEFAULT 0 CHECK(shown IN (0,1)),
            UNIQUE(kind,position)
        );
        CREATE TABLE security_alert_cursor (
            id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
            position INTEGER NOT NULL CHECK(position>=0)
        );
        CREATE TABLE staged_account_control (
            id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
            kind INTEGER NOT NULL CHECK(kind>=0),
            event BLOB NOT NULL CHECK(length(event)>0),
            body BLOB, attachment BLOB, sealed_kit BLOB
        );
        CREATE TABLE account_confirmations (
            position INTEGER PRIMARY KEY CHECK(position>0),
            earliest_ms INTEGER NOT NULL,
            latest_ms INTEGER NOT NULL CHECK(latest_ms>=earliest_ms),
            confirmation BLOB NOT NULL CHECK(length(confirmation)>0)
        );
        CREATE TABLE account_directory_versions (
            entry BLOB PRIMARY KEY CHECK(length(entry)=32),
            version INTEGER NOT NULL CHECK(version>=0)
        ) WITHOUT ROWID;
        CREATE TABLE base_epoch_keys (
            base BLOB NOT NULL CHECK(length(base)=32),
            epoch_id BLOB NOT NULL CHECK(length(epoch_id)=32),
            purpose INTEGER NOT NULL CHECK(purpose>=0),
            seal BLOB NOT NULL CHECK(length(seal)>0),
            PRIMARY KEY(base,epoch_id,purpose)
        ) WITHOUT ROWID;
        CREATE TABLE account_personal_delivery (
            id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
            position INTEGER NOT NULL CHECK(position>0),
            frame BLOB NOT NULL CHECK(length(frame)>0)
        );
        CREATE TABLE account_directory_state (
            id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
            version INTEGER NOT NULL CHECK(version>=0),
            written INTEGER NOT NULL CHECK(written IN (0,1))
        );
        ALTER TABLE account_state ADD COLUMN observed_earliest_ms INTEGER CHECK(observed_earliest_ms IS NULL OR observed_earliest_ms>=0);
        -- Existing ordered logs deliberately remain unmarked. Only a fresh
        -- empty registration writes canonical format and opening in one txn.
        ALTER TABLE log_progress ADD COLUMN order_format INTEGER;
        ALTER TABLE log_progress ADD COLUMN opening BLOB;
        ALTER TABLE log_progress ADD COLUMN floor_opening BLOB;
        CREATE TABLE account_outer_progress (
            log_id BLOB PRIMARY KEY CHECK(length(log_id)=32),
            hosting_root BLOB NOT NULL CHECK(length(hosting_root)=32),
            order_format INTEGER NOT NULL,
            opening BLOB NOT NULL,
            position INTEGER NOT NULL CHECK(position>=0),
            head_hash BLOB NOT NULL CHECK(length(head_hash)=32)
        ) WITHOUT ROWID;",
    )?;
    crate::sync_state::migrate_kept_seal_sets(tx)?;
    crate::typed_outbox::migrate_retirement(tx)?;
    crate::control_facts::migrate(tx)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub enum AlertKind {
    DeviceAddedByQr = 1,
    DeviceAddedByKit = 2,
    KitUsed = 3,
    RemovalRequested = 4,
    RemovalCancelled = 5,
    RemovalEffective = 6,
    KitChanged = 7,
    RefusedChange = 8,
    /// This device saved a new kit whose recovery replacement history did
    /// not take: the old kit is still the account's.
    KitNotChanged = 9,
}
impl TryFrom<i64> for AlertKind {
    type Error = StoreError;
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::DeviceAddedByQr),
            2 => Ok(Self::DeviceAddedByKit),
            3 => Ok(Self::KitUsed),
            4 => Ok(Self::RemovalRequested),
            5 => Ok(Self::RemovalCancelled),
            6 => Ok(Self::RemovalEffective),
            7 => Ok(Self::KitChanged),
            8 => Ok(Self::RefusedChange),
            9 => Ok(Self::KitNotChanged),
            _ => Err(StoreError::CorruptSecurity),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewAlert {
    pub kind: AlertKind,
    pub position: Option<u64>,
    pub subject: Option<[u8; 32]>,
    pub actor: Option<[u8; 32]>,
    pub time_ms: Option<u64>,
    pub deadline_ms: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAlert {
    pub id: i64,
    pub kind: AlertKind,
    pub position: Option<u64>,
    pub subject: Option<[u8; 32]>,
    pub actor: Option<[u8; 32]>,
    pub time_ms: Option<u64>,
    pub deadline_ms: Option<u64>,
    pub shown: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedControl {
    pub kind: i64,
    pub event: Vec<u8>,
    pub body: Option<Vec<u8>>,
    pub attachment: Option<Vec<u8>>,
    pub sealed_kit: Option<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochKeyRow {
    pub base: [u8; 32],
    pub epoch_id: [u8; 32],
    pub purpose: i64,
    pub seal: Vec<u8>,
}
/// What accepting a personal key read: the account head, the accepted rotation
/// delivery and every local keyring row. Its commit compares all three.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyringSnapshot {
    pub head: (u64, [u8; 32]),
    pub delivery: Option<(u64, Vec<u8>)>,
    pub rows: Vec<EpochKeyRow>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmationRow {
    pub position: u64,
    pub earliest_ms: u64,
    pub latest_ms: u64,
    pub bytes: Vec<u8>,
}

fn integer(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::CorruptSecurity)
}
fn unsigned(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::CorruptSecurity)
}
fn fixed(bytes: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, StoreError> {
    bytes
        .map(|b| b.try_into().map_err(|_| StoreError::CorruptSecurity))
        .transpose()
}
type RawAlert = (
    i64,
    i64,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    i64,
);
fn alert(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawAlert> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}
fn decode_alert(raw: RawAlert) -> Result<StoredAlert, StoreError> {
    let (id, kind, position, subject, actor, time_ms, deadline_ms, shown) = raw;
    if id <= 0 || !matches!(shown, 0 | 1) {
        return Err(StoreError::CorruptSecurity);
    }
    Ok(StoredAlert {
        id,
        kind: kind.try_into()?,
        position: position.map(unsigned).transpose()?,
        subject: fixed(subject)?,
        actor: fixed(actor)?,
        time_ms: time_ms.map(unsigned).transpose()?,
        deadline_ms: deadline_ms.map(unsigned).transpose()?,
        shown: shown == 1,
    })
}
fn read_staged(conn: &rusqlite::Connection) -> Result<Option<StagedControl>, StoreError> {
    let raw: Option<StagedControl> = conn
        .query_row(
            "SELECT kind,event,body,attachment,sealed_kit FROM staged_account_control WHERE id=1",
            [],
            |r| {
                Ok(StagedControl {
                    kind: r.get(0)?,
                    event: r.get(1)?,
                    body: r.get(2)?,
                    attachment: r.get(3)?,
                    sealed_kit: r.get(4)?,
                })
            },
        )
        .optional()?;
    if raw
        .as_ref()
        .is_some_and(|r| r.kind < 0 || r.event.is_empty())
    {
        return Err(StoreError::CorruptSecurity);
    }
    Ok(raw)
}

fn read_delivery(conn: &rusqlite::Connection) -> Result<Option<(u64, Vec<u8>)>, StoreError> {
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT position,frame FROM account_personal_delivery WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(position, frame)| Ok((unsigned(position)?, frame)))
        .transpose()
}
fn read_keys(
    conn: &rusqlite::Connection,
    base: Option<[u8; 32]>,
) -> Result<Vec<EpochKeyRow>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT base,epoch_id,purpose,seal FROM base_epoch_keys WHERE ?1 IS NULL OR base=?1 ORDER BY base,epoch_id,purpose",
    )?;
    let rows = stmt.query_map([base.as_ref().map(|b| b.as_slice())], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, Vec<u8>>(3)?,
        ))
    })?;
    rows.map(|r| {
        let (base, epoch, purpose, seal) = r?;
        Ok(EpochKeyRow {
            base: base.try_into().map_err(|_| StoreError::CorruptSecurity)?,
            epoch_id: epoch.try_into().map_err(|_| StoreError::CorruptSecurity)?,
            purpose,
            seal,
        })
    })
    .collect()
}
fn read_snapshot(conn: &rusqlite::Connection) -> Result<Option<KeyringSnapshot>, StoreError> {
    let head: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT head_position,head_hash FROM account_state WHERE id=1 AND stopped=0",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((position, hash)) = head else {
        return Ok(None);
    };
    Ok(Some(KeyringSnapshot {
        head: (
            unsigned(position)?,
            hash.try_into().map_err(|_| StoreError::CorruptSecurity)?,
        ),
        delivery: read_delivery(conn)?,
        rows: read_keys(conn, None)?,
    }))
}
fn insert_key(
    tx: &rusqlite::Transaction<'_>,
    row: &EpochKeyRow,
    sql: &str,
) -> Result<(), StoreError> {
    if row.purpose < 0 || row.seal.is_empty() {
        return Err(StoreError::CorruptSecurity);
    }
    tx.execute(
        sql,
        params![
            row.base.as_slice(),
            row.epoch_id.as_slice(),
            row.purpose,
            row.seal
        ],
    )?;
    Ok(())
}

/// Share the caller's transaction so originals, evidence and authority never
/// become durable separately.
pub(crate) fn put_confirmations(
    tx: &rusqlite::Transaction<'_>,
    rows: &[ConfirmationRow],
) -> Result<(), StoreError> {
    for row in rows {
        if row.position == 0 || row.latest_ms < row.earliest_ms || row.bytes.is_empty() {
            return Err(StoreError::CorruptSecurity);
        }
        let position = integer(row.position)?;
        let earliest = integer(row.earliest_ms)?;
        let latest = integer(row.latest_ms)?;
        tx.execute(
                "INSERT OR IGNORE INTO account_confirmations(position,earliest_ms,latest_ms,confirmation) VALUES(?1,?2,?3,?4)",
                params![position, earliest, latest, &row.bytes],
            )?;
        let stored: (i64, i64, Vec<u8>) = tx.query_row(
                "SELECT earliest_ms,latest_ms,confirmation FROM account_confirmations WHERE position=?1",
                [position],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
        if stored != (earliest, latest, row.bytes.clone()) {
            return Err(StoreError::CorruptSecurity);
        }
    }
    Ok(())
}

/// Called inside an account commit, or by the standalone alert API. A failing
/// insert or cursor update rolls back the entire caller transaction.
pub(crate) fn record_alerts_tx(
    tx: &rusqlite::Transaction<'_>,
    through: u64,
    alerts: &[NewAlert],
) -> Result<Vec<StoredAlert>, StoreError> {
    let through = integer(through)?;
    let mut result = Vec::with_capacity(alerts.len());
    for item in alerts {
        let position = item.position.map(integer).transpose()?;
        let time = item.time_ms.map(integer).transpose()?;
        let deadline = item.deadline_ms.map(integer).transpose()?;
        tx.execute("INSERT OR IGNORE INTO security_alerts(kind,position,subject,actor,time_ms,deadline_ms) VALUES(?1,?2,?3,?4,?5,?6)", params![item.kind as i64, position, item.subject.as_ref().map(|v| v.as_slice()), item.actor.as_ref().map(|v| v.as_slice()), time, deadline])?;
        let raw = if let Some(position) = position {
            tx.query_row("SELECT id,kind,position,subject,actor,time_ms,deadline_ms,shown FROM security_alerts WHERE kind=?1 AND position=?2", params![item.kind as i64, position], alert)?
        } else {
            tx.query_row("SELECT id,kind,position,subject,actor,time_ms,deadline_ms,shown FROM security_alerts WHERE id=last_insert_rowid()", [], alert)?
        };
        result.push(decode_alert(raw)?);
    }
    tx.execute("INSERT INTO security_alert_cursor(id,position) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET position=MAX(position,excluded.position)", [through])?;
    Ok(result)
}

impl DeviceDatabase {
    /// Store a verified batch and its scan cursor together, including empty batches.
    pub fn record_alerts(
        &mut self,
        through: u64,
        alerts: &[NewAlert],
    ) -> Result<Vec<StoredAlert>, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = record_alerts_tx(&tx, through, alerts)?;
        tx.commit()?;
        Ok(result)
    }
    /// A deadline observation is valid only against this exact committed head.
    /// A concurrent account append/cancellation cannot leave a stale alert.
    pub fn record_observed_account_alerts(
        &mut self,
        anchor: [u8; 32],
        head: (u64, [u8; 32]),
        observed_earliest_ms: u64,
        alerts: &[NewAlert],
    ) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<(Vec<u8>, i64, Vec<u8>, i64)> = tx
            .query_row(
                "SELECT anchor,head_position,head_hash,stopped FROM account_state WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if stored != Some((anchor.to_vec(), integer(head.0)?, head.1.to_vec(), 0)) {
            return Err(StoreError::AuthorityChanged);
        }
        // The account head and its observation are canonical. Projection repair
        // cannot discard either, even when the projection row was deleted.
        let changed = tx.execute("UPDATE account_state SET observed_earliest_ms=MAX(COALESCE(observed_earliest_ms,0),?1) WHERE id=1 AND anchor=?2 AND head_position=?3 AND head_hash=?4 AND stopped=0", params![integer(observed_earliest_ms)?, anchor.as_slice(), integer(head.0)?, head.1.as_slice()])?;
        if changed != 1 {
            return Err(StoreError::AuthorityChanged);
        }
        record_alerts_tx(&tx, head.0, alerts)?;
        tx.commit()?;
        Ok(())
    }
    /// Durable accepted-head lower bound. Retained through projection repair
    /// and applied to the owner only after replay reaches the remembered head.
    pub fn observed_account_floor(&self) -> Result<Option<u64>, StoreError> {
        let floor: Option<Option<i64>> = self
            .connection
            .query_row(
                "SELECT observed_earliest_ms FROM account_state WHERE id=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        floor.flatten().map(unsigned).transpose()
    }
    pub fn alert_cursor(&self) -> Result<u64, StoreError> {
        let value: Option<i64> = self
            .connection
            .query_row(
                "SELECT position FROM security_alert_cursor WHERE id=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        value.map(unsigned).transpose().map(|v| v.unwrap_or(0))
    }
    fn list_alerts(&self, query: &str, limit: i64) -> Result<Vec<StoredAlert>, StoreError> {
        let mut stmt = self.connection.prepare(query)?;
        let rows = stmt.query_map([limit], alert)?;
        rows.map(|r| decode_alert(r?)).collect()
    }
    pub fn alerts(&self, limit: usize) -> Result<Vec<StoredAlert>, StoreError> {
        self.list_alerts("SELECT id,kind,position,subject,actor,time_ms,deadline_ms,shown FROM security_alerts ORDER BY id DESC LIMIT ?1", i64::try_from(limit).map_err(|_| StoreError::CorruptSecurity)?)
    }
    pub fn unshown_alerts(&self) -> Result<Vec<StoredAlert>, StoreError> {
        self.list_alerts("SELECT id,kind,position,subject,actor,time_ms,deadline_ms,shown FROM security_alerts WHERE shown=0 ORDER BY id LIMIT ?1", -1)
    }
    pub fn mark_alerts_shown(&mut self, ids: &[i64]) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for id in ids {
            tx.execute("UPDATE security_alerts SET shown=1 WHERE id=?1", [id])?;
        }
        tx.commit()?;
        Ok(())
    }
    /// Keep the home's notice that the account's kit was used at `time_ms`
    /// as an alert, once: a notice already kept for that time adds nothing.
    /// Rows are only ever added. Whether one was added.
    pub fn record_kit_used(&mut self, time_ms: u64) -> Result<bool, StoreError> {
        let time = integer(time_ms)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let kept: i64 = tx.query_row(
            "SELECT COUNT(*) FROM security_alerts WHERE kind=?1 AND time_ms=?2",
            params![AlertKind::KitUsed as i64, time],
            |r| r.get(0),
        )?;
        if kept == 0 {
            tx.execute(
                "INSERT INTO security_alerts(kind,time_ms) VALUES(?1,?2)",
                params![AlertKind::KitUsed as i64, time],
            )?;
        }
        tx.commit()?;
        Ok(kept == 0)
    }
    /// The newest kit-used notice kept: where the next notice read starts.
    pub fn newest_kit_used(&self) -> Result<Option<u64>, StoreError> {
        let newest: Option<i64> = self.connection.query_row(
            "SELECT MAX(time_ms) FROM security_alerts WHERE kind=?1",
            [AlertKind::KitUsed as i64],
            |r| r.get(0),
        )?;
        newest.map(unsigned).transpose()
    }
    pub fn record_refused_change(&mut self, time_ms: u64) -> Result<(), StoreError> {
        self.record_alerts(
            self.alert_cursor()?,
            &[NewAlert {
                kind: AlertKind::RefusedChange,
                position: None,
                subject: None,
                actor: None,
                time_ms: Some(time_ms),
                deadline_ms: None,
            }],
        )?;
        Ok(())
    }
    pub fn stage_account_control(&mut self, row: &StagedControl) -> Result<(), StoreError> {
        if row.kind < 0 || row.event.is_empty() {
            return Err(StoreError::CorruptSecurity);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if read_staged(&tx)?.is_some() {
            return Err(StoreError::StagedControlExists);
        }
        tx.execute("INSERT INTO staged_account_control(id,kind,event,body,attachment,sealed_kit) VALUES(1,?1,?2,?3,?4,?5)", params![row.kind, row.event, row.body, row.attachment, row.sealed_kit])?;
        tx.commit()?;
        Ok(())
    }
    pub fn staged_account_control(&self) -> Result<Option<StagedControl>, StoreError> {
        read_staged(&self.connection)
    }
    pub fn clear_staged_account_control(
        &mut self,
        expected: &StagedControl,
    ) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        match read_staged(&tx)? {
            None => return Ok(()),
            Some(current) if current != *expected => return Err(StoreError::StagedControlChanged),
            _ => (),
        }
        tx.execute("DELETE FROM staged_account_control WHERE id=1", [])?;
        tx.commit()?;
        Ok(())
    }
    /// The person saved the kit of `expected`, the exact staged row read
    /// before: clear its `sealed_kit` and keep the rest, in one statement, so
    /// no crash can leave the control unstaged. A different row, one with no
    /// kit, or none at all is `StagedControlChanged` and nothing changes.
    pub fn clear_staged_kit(&mut self, expected: &StagedControl) -> Result<(), StoreError> {
        let cleared = self.connection.execute(
            "UPDATE staged_account_control SET sealed_kit=NULL WHERE id=1 AND kind=?1 AND event=?2 \
             AND body IS ?3 AND attachment IS ?4 AND sealed_kit IS NOT NULL AND sealed_kit=?5",
            params![
                expected.kind,
                expected.event,
                expected.body,
                expected.attachment,
                expected.sealed_kit
            ],
        )?;
        if cleared == 0 {
            return Err(StoreError::StagedControlChanged);
        }
        Ok(())
    }
    /// Store verified confirmation bytes once per position; reject contradictory replays.
    pub fn put_confirmations(&mut self, rows: &[ConfirmationRow]) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        put_confirmations(&tx, rows)?;
        tx.commit()?;
        Ok(())
    }
    pub fn confirmation(&self, position: u64) -> Result<Option<ConfirmationRow>, StoreError> {
        let row: Option<(i64, i64, Vec<u8>)> = self.connection.query_row(
            "SELECT earliest_ms,latest_ms,confirmation FROM account_confirmations WHERE position=?1",
            [integer(position)?],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).optional()?;
        row.map(|(earliest_ms, latest_ms, bytes)| {
            let earliest_ms = unsigned(earliest_ms)?;
            let latest_ms = unsigned(latest_ms)?;
            if position == 0 || latest_ms < earliest_ms || bytes.is_empty() {
                return Err(StoreError::CorruptSecurity);
            }
            Ok(ConfirmationRow {
                position,
                earliest_ms,
                latest_ms,
                bytes,
            })
        })
        .transpose()
    }
    /// Return whether the remembered version advanced; lower/equal versions leave it unchanged.
    pub fn remember_directory_version(
        &mut self,
        entry: [u8; 32],
        version: u64,
    ) -> Result<bool, StoreError> {
        let version = integer(version)?;
        let changed = self.connection.execute(
            "INSERT INTO account_directory_versions(entry,version) VALUES(?1,?2) ON CONFLICT(entry) DO UPDATE SET version=excluded.version WHERE version<excluded.version",
            params![entry.as_slice(), version],
        )?;
        Ok(changed != 0)
    }
    pub fn directory_version(&self, entry: [u8; 32]) -> Result<Option<u64>, StoreError> {
        self.connection
            .query_row(
                "SELECT version FROM account_directory_versions WHERE entry=?1",
                [entry.as_slice()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .map(unsigned)
            .transpose()
    }
    /// Overwrites what it finds: tests only. Production adds rows with
    /// `install_epoch_keys` and switches the delivery and every row with
    /// `accept_personal_delivery`.
    #[cfg(test)]
    pub fn put_epoch_key(&mut self, row: &EpochKeyRow) -> Result<(), StoreError> {
        self.connection.execute("INSERT INTO base_epoch_keys(base,epoch_id,purpose,seal) VALUES(?1,?2,?3,?4) ON CONFLICT(base,epoch_id,purpose) DO UPDATE SET seal=excluded.seal", params![row.base.as_slice(), row.epoch_id.as_slice(), row.purpose, row.seal])?;
        Ok(())
    }
    pub fn epoch_keys(&self, base: [u8; 32]) -> Result<Vec<EpochKeyRow>, StoreError> {
        read_keys(&self.connection, Some(base))
    }
    /// Overwrites what it finds: tests only. Production adds rows with
    /// `install_epoch_keys` and switches the delivery and every row with
    /// `accept_personal_delivery`.
    #[cfg(test)]
    pub fn replace_epoch_keys(
        &mut self,
        base: [u8; 32],
        rows: &[EpochKeyRow],
    ) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM base_epoch_keys WHERE base=?1",
            [base.as_slice()],
        )?;
        for row in rows {
            if row.base != base {
                return Err(StoreError::CorruptSecurity);
            }
            tx.execute(
                "INSERT INTO base_epoch_keys(base,epoch_id,purpose,seal) VALUES(?1,?2,?3,?4)",
                params![
                    row.base.as_slice(),
                    row.epoch_id.as_slice(),
                    row.purpose,
                    row.seal
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    /// Overwrites what it finds: tests only. Production adds rows with
    /// `install_epoch_keys` and switches the delivery and every row with
    /// `accept_personal_delivery`.
    #[cfg(test)]
    pub fn put_personal_delivery(&mut self, position: u64, frame: &[u8]) -> Result<(), StoreError> {
        let position = integer(position)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT position,frame FROM account_personal_delivery WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((old_position, old_frame)) = prior {
            if old_position > position || (old_position == position && old_frame != frame) {
                return Err(StoreError::CorruptSecurity);
            }
            if old_position == position {
                return Ok(());
            }
        }
        tx.execute("INSERT INTO account_personal_delivery(id,position,frame) VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET position=excluded.position,frame=excluded.frame", params![position, frame])?;
        tx.commit()?;
        Ok(())
    }
    pub fn personal_delivery(&self) -> Result<Option<(u64, Vec<u8>)>, StoreError> {
        read_delivery(&self.connection)
    }
    /// The running account's head, accepted rotation delivery and every keyring
    /// row, read together. None without a running account.
    pub fn keyring_snapshot(&self) -> Result<Option<KeyringSnapshot>, StoreError> {
        read_snapshot(&self.connection)
    }
    /// Switch the accepted personal-key delivery and replace every keyring row
    /// with its re-sealed form, in one transaction, only if nothing changed
    /// since `expected` was read and `current` holds under the writer.
    /// Each row must be re-sealed one for one; a held base without its
    /// metadata and content rows is refused until its keyring is initialized.
    pub fn accept_personal_delivery(
        &mut self,
        expected: &KeyringSnapshot,
        position: u64,
        frame: &[u8],
        rows: &[EpochKeyRow],
        current: impl Fn() -> bool,
    ) -> Result<(), StoreError> {
        let stored = integer(position)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !current() {
            return Err(StoreError::AuthorityChanged);
        }
        if read_snapshot(&tx)?.as_ref() != Some(expected) {
            return Err(StoreError::KeyringChanged);
        }
        if let Some(own) = crate::own_base::read_own_base(&tx)? {
            for purpose in [1, 2] {
                if !expected
                    .rows
                    .iter()
                    .any(|r| r.base == own.base && r.purpose == purpose)
                {
                    return Err(StoreError::KeyringIncomplete);
                }
            }
        }
        let slots = |rows: &[EpochKeyRow]| {
            let mut slots: Vec<_> = rows
                .iter()
                .map(|r| (r.base, r.epoch_id, r.purpose))
                .collect();
            slots.sort_unstable();
            slots
        };
        if position == 0
            || frame.is_empty()
            || slots(rows) != slots(&expected.rows)
            || expected
                .delivery
                .as_ref()
                .is_some_and(|(old, _)| *old >= position)
        {
            return Err(StoreError::CorruptSecurity);
        }
        tx.execute("DELETE FROM base_epoch_keys", [])?;
        for row in rows {
            insert_key(
                &tx,
                row,
                "INSERT INTO base_epoch_keys(base,epoch_id,purpose,seal) VALUES(?1,?2,?3,?4)",
            )?;
        }
        tx.execute("INSERT INTO account_personal_delivery(id,position,frame) VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET position=excluded.position,frame=excluded.frame", params![stored, frame])?;
        tx.commit()?;
        Ok(())
    }
    /// Add rows sealed to the personal key accepted under `delivery`, keeping
    /// any row already stored. Refused if the accepted delivery changed.
    pub fn install_epoch_keys(
        &mut self,
        delivery: Option<&(u64, Vec<u8>)>,
        rows: &[EpochKeyRow],
        current: impl Fn() -> bool,
    ) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !current() {
            return Err(StoreError::AuthorityChanged);
        }
        if read_delivery(&tx)?.as_ref() != delivery {
            return Err(StoreError::KeyringChanged);
        }
        for row in rows {
            insert_key(
                &tx,
                row,
                "INSERT OR IGNORE INTO base_epoch_keys(base,epoch_id,purpose,seal) VALUES(?1,?2,?3,?4)",
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn directory_state(&self) -> Result<Option<(u64, bool)>, StoreError> {
        let row: Option<(i64, i64)> = self
            .connection
            .query_row(
                "SELECT version,written FROM account_directory_state WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        row.map(|(version, written)| {
            if !matches!(written, 0 | 1) {
                return Err(StoreError::CorruptSecurity);
            }
            Ok((unsigned(version)?, written == 1))
        })
        .transpose()
    }
    pub fn set_directory_state(&mut self, version: u64, written: bool) -> Result<(), StoreError> {
        self.connection.execute("INSERT INTO account_directory_state(id,version,written) VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET version=excluded.version,written=excluded.written", params![integer(version)?, i64::from(written)])?;
        Ok(())
    }
    /// Count saved local items with no verified ordering acknowledgment. A
    /// package's ACK covers every one of its explicit note-run members;
    /// an unpackaged update is still unsent work. Outcome (including a
    /// rejected echo) cannot substitute for the ACK.
    pub fn unsent_count(&self) -> Result<u64, StoreError> {
        let notes: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM pending_note_work w
             LEFT JOIN note_outbox_members m ON m.update_id=w.update_id
             LEFT JOIN note_outbox o ON o.update_id=COALESCE(m.package_update_id,w.update_id)
             WHERE o.ack IS NULL",
            [],
            |r| r.get(0),
        )?;
        let typed: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM data_pending d
             LEFT JOIN typed_outbox t ON t.mutation=d.mutation
             WHERE d.state IN ('pending','waiting') AND t.ack IS NULL",
            [],
            |r| r.get(0),
        )?;
        unsigned(notes)?
            .checked_add(unsigned(typed)?)
            .ok_or(StoreError::CorruptOutbox)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceDatabase;
    use rusqlite::params;

    fn db() -> DeviceDatabase {
        let db = DeviceDatabase::open(":memory:").unwrap();
        assert_eq!(db.data_version(), bh_core::LOCAL_DATA_VERSION);
        db
    }

    #[test]
    fn step_creates_every_table_and_rolls_back_whole_on_failure() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        // v3 creates account state and v11 creates log progress before the
        // v14 security extension adds the canonical opening columns.
        // v13 creates the typed outbox whose exact-bytes check v14 widens.
        conn.execute_batch("CREATE TABLE account_state(id INTEGER PRIMARY KEY); CREATE TABLE log_progress(log_kind INTEGER); CREATE TABLE typed_outbox(mutation,base,audience,after_note,event_id,descriptor,body); CREATE TRIGGER typed_outbox_exact BEFORE UPDATE ON typed_outbox BEGIN SELECT 1; END;")
            .unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute_batch("CREATE TABLE account_confirmations(position INTEGER)")
            .unwrap();
        assert!(migrate(&tx).is_err());
        tx.rollback().unwrap();
        let has_floor: i64 = conn.query_row("SELECT COUNT(*) FROM pragma_table_info('account_state') WHERE name='observed_earliest_ms'", [], |r| r.get(0)).unwrap();
        assert_eq!(has_floor, 0);
        for name in [
            "security_alerts",
            "security_alert_cursor",
            "staged_account_control",
            "account_confirmations",
            "account_directory_versions",
            "base_epoch_keys",
            "account_personal_delivery",
            "account_directory_state",
            "account_outer_progress",
            "base_control_seal_set",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [name],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{name}");
        }
        let tx = conn.transaction().unwrap();
        migrate(&tx).unwrap();
        tx.commit().unwrap();
        let has_floor: i64 = conn.query_row("SELECT COUNT(*) FROM pragma_table_info('account_state') WHERE name='observed_earliest_ms'", [], |r| r.get(0)).unwrap();
        assert_eq!(has_floor, 1);
        for name in [
            "security_alerts",
            "security_alert_cursor",
            "staged_account_control",
            "account_confirmations",
            "account_directory_versions",
            "base_epoch_keys",
            "account_personal_delivery",
            "account_directory_state",
            "account_outer_progress",
            "base_control_seal_set",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [name],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "{name}");
        }
    }

    #[test]
    fn alerts_are_idempotent_and_advance_the_cursor_atomically() {
        let mut db = db();
        let alert = NewAlert {
            kind: AlertKind::DeviceAddedByQr,
            position: Some(2),
            subject: Some([3; 32]),
            actor: None,
            time_ms: Some(123),
            deadline_ms: None,
        };
        assert_eq!(db.alert_cursor().unwrap(), 0);
        let first = db.record_alerts(2, std::slice::from_ref(&alert)).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].position, Some(2));
        assert_eq!(
            db.record_alerts(2, std::slice::from_ref(&alert)).unwrap(),
            first
        );
        db.mark_alerts_shown(&[first[0].id]).unwrap();
        assert!(db.unshown_alerts().unwrap().is_empty());
        assert!(db.alerts(5).unwrap()[0].shown);
        db.connection.execute_batch("CREATE TRIGGER block_alert BEFORE INSERT ON security_alerts BEGIN SELECT RAISE(ABORT, 'blocked'); END;").unwrap();
        let mut next = alert;
        next.position = Some(3);
        assert!(db.record_alerts(3, &[next]).is_err());
        assert_eq!(db.alert_cursor().unwrap(), 2);
        assert_eq!(db.alerts(5).unwrap().len(), 1);
        db.connection
            .execute_batch("DROP TRIGGER block_alert")
            .unwrap();
        db.record_refused_change(456).unwrap();
        assert_eq!(
            db.unshown_alerts().unwrap()[0].kind,
            AlertKind::RefusedChange
        );
    }

    #[test]
    fn a_kit_used_notice_is_kept_once_and_names_the_newest_time() {
        let mut db = db();
        assert_eq!(db.newest_kit_used().unwrap(), None);
        assert!(db.record_kit_used(500).unwrap());
        assert!(!db.record_kit_used(500).unwrap(), "the same notice again");
        assert!(db.record_kit_used(300).unwrap());
        assert_eq!(db.newest_kit_used().unwrap(), Some(500));
        let kept: Vec<_> = db
            .alerts(10)
            .unwrap()
            .into_iter()
            .filter(|alert| alert.kind == AlertKind::KitUsed)
            .map(|alert| (alert.time_ms, alert.position, alert.shown))
            .collect();
        assert_eq!(
            kept,
            vec![(Some(300), None, false), (Some(500), None, false)]
        );
        // The account-scan cursor is not a notice's.
        assert_eq!(db.alert_cursor().unwrap(), 0);
    }

    #[test]
    fn a_second_staged_control_is_refused() {
        let mut db = db();
        let first = StagedControl {
            kind: 1,
            event: vec![1],
            body: Some(vec![2]),
            attachment: None,
            sealed_kit: None,
        };
        db.stage_account_control(&first).unwrap();
        assert_eq!(db.staged_account_control().unwrap(), Some(first.clone()));
        let second = StagedControl {
            event: vec![9],
            ..first.clone()
        };
        assert!(db.stage_account_control(&second).is_err());
        assert!(db.clear_staged_account_control(&second).is_err());
        assert_eq!(db.staged_account_control().unwrap(), Some(first.clone()));
        db.clear_staged_account_control(&first).unwrap();
        db.clear_staged_account_control(&first).unwrap();
        assert_eq!(db.staged_account_control().unwrap(), None);
    }

    #[test]
    fn a_staged_kit_is_cleared_only_from_the_exact_row() {
        let mut db = db();
        let staged = StagedControl {
            kind: 8,
            event: vec![1],
            body: Some(vec![2]),
            attachment: Some(vec![3]),
            sealed_kit: Some(vec![4]),
        };
        db.stage_account_control(&staged).unwrap();
        for changed in [
            StagedControl {
                event: vec![9],
                ..staged.clone()
            },
            StagedControl {
                sealed_kit: Some(vec![5]),
                ..staged.clone()
            },
            StagedControl {
                body: None,
                ..staged.clone()
            },
        ] {
            assert!(matches!(
                db.clear_staged_kit(&changed),
                Err(StoreError::StagedControlChanged)
            ));
            assert_eq!(db.staged_account_control().unwrap(), Some(staged.clone()));
        }
        db.clear_staged_kit(&staged).unwrap();
        let saved = StagedControl {
            sealed_kit: None,
            ..staged.clone()
        };
        assert_eq!(db.staged_account_control().unwrap(), Some(saved.clone()));
        // Already cleared, or nothing staged: nothing to clear.
        assert!(db.clear_staged_kit(&staged).is_err());
        assert!(db.clear_staged_kit(&saved).is_err());
        db.clear_staged_account_control(&saved).unwrap();
        assert!(db.clear_staged_kit(&staged).is_err());
        assert_eq!(db.staged_account_control().unwrap(), None);
    }

    #[test]
    fn verified_alert_kinds_dedupe_after_database_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alerts.sqlite");
        let mut db = DeviceDatabase::open(&path).unwrap();
        let kinds = [
            AlertKind::DeviceAddedByQr,
            AlertKind::DeviceAddedByKit,
            AlertKind::RemovalRequested,
            AlertKind::RemovalCancelled,
            AlertKind::RemovalEffective,
            AlertKind::KitChanged,
        ];
        let alerts: Vec<_> = kinds
            .iter()
            .enumerate()
            .map(|(index, &kind)| NewAlert {
                kind,
                position: Some(index as u64 + 4),
                subject: None,
                actor: None,
                time_ms: Some(100),
                deadline_ms: (kind == AlertKind::RemovalRequested).then_some(200),
            })
            .collect();
        db.record_alerts(9, &alerts).unwrap();
        drop(db);
        let mut db = DeviceDatabase::open(&path).unwrap();
        db.record_alerts(9, &alerts).unwrap();
        assert_eq!(db.alert_cursor().unwrap(), 9);
        assert_eq!(db.alerts(10).unwrap().len(), kinds.len());
        for kind in kinds {
            assert_eq!(
                db.alerts(10)
                    .unwrap()
                    .iter()
                    .filter(|a| a.kind == kind)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn second_alert_insert_failure_rolls_back_first_insert_and_cursor() {
        let mut db = db();
        db.record_alerts(2, &[]).unwrap();
        db.connection.execute_batch("CREATE TRIGGER block_second_alert BEFORE INSERT ON security_alerts WHEN NEW.position=4 BEGIN SELECT RAISE(ABORT, 'blocked'); END;").unwrap();
        let make = |position| NewAlert {
            kind: AlertKind::DeviceAddedByQr,
            position: Some(position),
            subject: None,
            actor: None,
            time_ms: None,
            deadline_ms: None,
        };
        assert!(db.record_alerts(4, &[make(3), make(4)]).is_err());
        assert!(
            db.alerts(10).unwrap().is_empty(),
            "first insert rolled back"
        );
        assert_eq!(db.alert_cursor().unwrap(), 2, "cursor rolled back");
    }

    #[test]
    fn epoch_keys_replace_atomically() {
        let mut db = db();
        let old = EpochKeyRow {
            base: [1; 32],
            epoch_id: [2; 32],
            purpose: 0,
            seal: vec![7],
        };
        let next = EpochKeyRow {
            epoch_id: [3; 32],
            seal: vec![8],
            ..old.clone()
        };
        db.put_epoch_key(&old).unwrap();
        assert_eq!(db.epoch_keys([1; 32]).unwrap(), vec![old.clone()]);
        let foreign = EpochKeyRow {
            base: [9; 32],
            ..next.clone()
        };
        assert!(
            db.replace_epoch_keys([1; 32], &[next.clone(), foreign])
                .is_err()
        );
        assert_eq!(db.epoch_keys([1; 32]).unwrap(), vec![old]);
        db.replace_epoch_keys([1; 32], std::slice::from_ref(&next))
            .unwrap();
        assert_eq!(db.epoch_keys([1; 32]).unwrap(), vec![next]);
    }

    fn key(base: u8, epoch: u8, purpose: i64, seal: u8) -> EpochKeyRow {
        EpochKeyRow {
            base: [base; 32],
            epoch_id: [epoch; 32],
            purpose,
            seal: vec![seal],
        }
    }

    #[test]
    fn keyring_acceptance_commits_only_what_it_read_and_rolls_back_whole() {
        let mut db = db();
        assert_eq!(db.keyring_snapshot().unwrap(), None);
        db.connection
            .execute(
                "INSERT INTO account_state(id,anchor,head_position,head_hash,stopped) VALUES(1,?1,0,?2,0)",
                params![[1u8; 32].as_slice(), [2u8; 32].as_slice()],
            )
            .unwrap();
        db.put_epoch_key(&key(5, 6, 1, 1)).unwrap();
        db.put_epoch_key(&key(5, 7, 2, 1)).unwrap();
        let read = db.keyring_snapshot().unwrap().unwrap();
        let resealed = [key(5, 6, 1, 9), key(5, 7, 2, 9)];
        // A row stored meanwhile is a change: nothing is written.
        db.put_epoch_key(&key(8, 8, 2, 1)).unwrap();
        assert!(matches!(
            db.accept_personal_delivery(&read, 4, &[3], &resealed, || true),
            Err(StoreError::KeyringChanged)
        ));
        let read = db.keyring_snapshot().unwrap().unwrap();
        // Every row is re-sealed one for one, never dropped.
        assert!(matches!(
            db.accept_personal_delivery(&read, 4, &[3], &resealed, || true),
            Err(StoreError::CorruptSecurity)
        ));
        assert!(matches!(
            db.accept_personal_delivery(&read, 4, &[3], &[], || false),
            Err(StoreError::AuthorityChanged)
        ));
        let resealed = [key(5, 6, 1, 9), key(5, 7, 2, 9), key(8, 8, 2, 9)];
        db.connection.execute_batch("CREATE TRIGGER block_delivery BEFORE INSERT ON account_personal_delivery BEGIN SELECT RAISE(ABORT, 'blocked'); END;").unwrap();
        assert!(
            db.accept_personal_delivery(&read, 4, &[3], &resealed, || true)
                .is_err()
        );
        assert_eq!(db.keyring_snapshot().unwrap().unwrap(), read);
        db.connection
            .execute_batch("DROP TRIGGER block_delivery")
            .unwrap();
        db.accept_personal_delivery(&read, 4, &[3], &resealed, || true)
            .unwrap();
        let after = db.keyring_snapshot().unwrap().unwrap();
        assert_eq!(after.delivery, Some((4, vec![3])));
        assert_eq!(after.rows, resealed.to_vec());
        // An earlier or equal position never replaces the accepted one.
        assert!(matches!(
            db.accept_personal_delivery(&after, 4, &[4], &resealed, || true),
            Err(StoreError::CorruptSecurity)
        ));
        // A held base without its metadata and content rows waits for them.
        db.connection.execute("INSERT INTO own_base(id,account,base,genesis_descriptor,genesis_body,initial_key_package) VALUES(1,?1,?2,x'00',x'00',x'00')", params![[1u8; 32].as_slice(), [6u8; 32].as_slice()]).unwrap();
        assert!(matches!(
            db.accept_personal_delivery(&after, 9, &[5], &resealed, || true),
            Err(StoreError::KeyringIncomplete)
        ));
    }

    #[test]
    fn keyring_install_keeps_stored_rows_under_the_same_delivery() {
        let mut db = db();
        db.install_epoch_keys(None, &[key(1, 2, 1, 1)], || true)
            .unwrap();
        db.install_epoch_keys(None, &[key(1, 2, 1, 2), key(1, 3, 2, 2)], || true)
            .unwrap();
        assert_eq!(
            db.epoch_keys([1; 32]).unwrap(),
            vec![key(1, 2, 1, 1), key(1, 3, 2, 2)]
        );
        db.put_personal_delivery(4, &[1]).unwrap();
        assert!(matches!(
            db.install_epoch_keys(None, &[key(1, 4, 2, 2)], || true),
            Err(StoreError::KeyringChanged)
        ));
        assert!(matches!(
            db.install_epoch_keys(Some(&(4, vec![1])), &[key(1, 4, 2, 2)], || false),
            Err(StoreError::AuthorityChanged)
        ));
        assert_eq!(db.epoch_keys([1; 32]).unwrap().len(), 2);
    }

    #[test]
    fn confirmations_store_once_and_refuse_other_bytes() {
        let mut db = db();
        let first = ConfirmationRow {
            position: 4,
            earliest_ms: 100,
            latest_ms: 150,
            bytes: vec![1, 2],
        };
        let next = ConfirmationRow {
            position: 5,
            earliest_ms: 200,
            latest_ms: 250,
            bytes: vec![3],
        };
        assert_eq!(db.confirmation(4).unwrap(), None);
        db.put_confirmations(std::slice::from_ref(&first)).unwrap();
        db.put_confirmations(std::slice::from_ref(&first)).unwrap();
        assert_eq!(db.confirmation(4).unwrap(), Some(first.clone()));
        let changed = ConfirmationRow {
            bytes: vec![9],
            ..first.clone()
        };
        assert!(matches!(
            db.put_confirmations(&[next.clone(), changed]),
            Err(StoreError::CorruptSecurity)
        ));
        assert_eq!(db.confirmation(5).unwrap(), None, "whole batch rolled back");
        assert_eq!(db.confirmation(4).unwrap(), Some(first));
        db.put_confirmations(std::slice::from_ref(&next)).unwrap();
        assert_eq!(db.confirmation(5).unwrap(), Some(next));
        assert!(matches!(
            db.put_confirmations(&[ConfirmationRow {
                position: 0,
                earliest_ms: 1,
                latest_ms: 2,
                bytes: vec![1]
            }]),
            Err(StoreError::CorruptSecurity)
        ));
        assert!(matches!(
            db.put_confirmations(&[ConfirmationRow {
                position: 6,
                earliest_ms: 3,
                latest_ms: 2,
                bytes: vec![1]
            }]),
            Err(StoreError::CorruptSecurity)
        ));
        assert!(matches!(
            db.put_confirmations(&[ConfirmationRow {
                position: 6,
                earliest_ms: 1,
                latest_ms: 2,
                bytes: vec![]
            }]),
            Err(StoreError::CorruptSecurity)
        ));
    }

    #[test]
    fn directory_versions_never_go_down() {
        let mut db = db();
        let entry = [3; 32];
        assert_eq!(db.directory_version(entry).unwrap(), None);
        assert!(db.remember_directory_version(entry, 5).unwrap());
        assert_eq!(db.directory_version(entry).unwrap(), Some(5));
        assert!(!db.remember_directory_version(entry, 4).unwrap());
        assert_eq!(db.directory_version(entry).unwrap(), Some(5));
        assert!(!db.remember_directory_version(entry, 5).unwrap());
        assert!(db.remember_directory_version(entry, 6).unwrap());
        assert_eq!(db.directory_version(entry).unwrap(), Some(6));
        assert_eq!(db.directory_version([4; 32]).unwrap(), None);
        assert!(matches!(
            db.remember_directory_version([5; 32], u64::MAX),
            Err(StoreError::CorruptSecurity)
        ));
        assert_eq!(db.directory_version([5; 32]).unwrap(), None);
    }

    #[test]
    fn directory_state_round_trip() {
        let mut db = db();
        assert_eq!(db.directory_state().unwrap(), None);
        db.set_directory_state(3, false).unwrap();
        assert_eq!(db.directory_state().unwrap(), Some((3, false)));
        db.set_directory_state(3, true).unwrap();
        assert_eq!(db.directory_state().unwrap(), Some((3, true)));
        assert_eq!(db.unsent_count().unwrap(), 0);
    }

    #[test]
    fn sealed_delivery_does_not_replace_a_different_frame_at_the_same_position() {
        let mut db = db();
        db.put_personal_delivery(4, &[1]).unwrap();
        assert!(db.put_personal_delivery(4, &[2]).is_err());
        assert_eq!(db.personal_delivery().unwrap(), Some((4, vec![1])));
        db.put_personal_delivery(5, &[3]).unwrap();
        assert_eq!(db.personal_delivery().unwrap(), Some((5, vec![3])));
    }

    #[test]
    fn a_kit_not_changed_alert_is_kept() {
        let mut db = db();
        let alert = NewAlert {
            kind: AlertKind::KitNotChanged,
            position: Some(7),
            subject: None,
            actor: None,
            time_ms: None,
            deadline_ms: None,
        };
        db.record_alerts(db.alert_cursor().unwrap(), std::slice::from_ref(&alert))
            .unwrap();
        db.record_alerts(db.alert_cursor().unwrap(), &[alert])
            .unwrap();
        let stored = db.unshown_alerts().unwrap();
        assert_eq!(stored.len(), 1, "once per position");
        assert_eq!(stored[0].kind, AlertKind::KitNotChanged);
        assert_eq!(stored[0].position, Some(7));
        assert_eq!(db.alert_cursor().unwrap(), 0);
        assert!(
            db.connection
                .execute("INSERT INTO security_alerts(kind) VALUES(10)", [])
                .is_err()
        );
    }

    #[test]
    fn checks_refuse_bad_lengths() {
        let db = db();
        assert!(
            db.connection
                .execute(
                    "INSERT INTO security_alerts(kind,subject) VALUES(1,?1)",
                    [vec![1u8; 31]]
                )
                .is_err()
        );
        assert!(
            db.connection
                .execute(
                    "INSERT INTO base_epoch_keys(base,epoch_id,purpose,seal) VALUES(?1,?2,0,x'01')",
                    params![vec![1u8; 31], vec![2u8; 32]]
                )
                .is_err()
        );
        assert!(
            db.connection
                .execute(
                    "INSERT INTO base_epoch_keys(base,epoch_id,purpose,seal) VALUES(?1,?2,0,x'01')",
                    params![vec![1u8; 32], vec![2u8; 31]]
                )
                .is_err()
        );
        assert!(
            db.connection
                .execute("INSERT INTO security_alerts(kind,shown) VALUES(99,0)", [])
                .is_err()
        );
    }
}
