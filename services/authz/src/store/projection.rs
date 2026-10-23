//! Source-qualified, generation-pinned hosted account projection rows.
use super::{ConfirmedPage, Record, ServiceError, Store, StoredEvent, array, storage};
use bh_account::{
    AccountId, ConfirmedTime, DeviceId, Error as AccountError, Head as AccountHead,
    VerifiedAccount,
    projection::{
        self as account_projection, AccountDeviceRow, AccountProjectionDelta, Checkpoint,
        HistoryIndex, KeyUse,
    },
};
use bh_authz_proto::{LogId, LogKind};
use bh_sync::{BaseId, Digest, OrderState};
use rusqlite::{OptionalExtension, Transaction, params};
use std::sync::Arc;

pub(super) fn schema(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    tx.execute_batch(
        "CREATE TABLE projection_sources(
      account BLOB NOT NULL, kind INTEGER NOT NULL, source BLOB NOT NULL,
      generation INTEGER NOT NULL, root BLOB NOT NULL,
      prefix_account BLOB, prefix_kind INTEGER, prefix_source BLOB,
      prefix_generation INTEGER, prefix_position INTEGER, prefix_hash BLOB,
      PRIMARY KEY(account,kind,source,generation));
    CREATE TABLE projection_selected(
      account BLOB NOT NULL, kind INTEGER NOT NULL, source BLOB NOT NULL,
      generation INTEGER NOT NULL, PRIMARY KEY(account,kind,source));
    CREATE TABLE projection_current(
      account BLOB NOT NULL, kind INTEGER NOT NULL, source BLOB NOT NULL,
      generation INTEGER NOT NULL, position INTEGER NOT NULL, hash BLOB NOT NULL,
      summary BLOB NOT NULL, stopped INTEGER NOT NULL, opening BLOB NOT NULL,
      PRIMARY KEY(account,kind,source,generation));
    CREATE TABLE projection_active(
      account BLOB NOT NULL, kind INTEGER NOT NULL, source BLOB NOT NULL,
      generation INTEGER NOT NULL, device BLOB NOT NULL, keys BLOB NOT NULL,
      added INTEGER NOT NULL, PRIMARY KEY(account,kind,source,generation,device));
    CREATE TABLE projection_snapshots(
      account BLOB NOT NULL, kind INTEGER NOT NULL, source BLOB NOT NULL,
      generation INTEGER NOT NULL, position INTEGER NOT NULL, hash BLOB NOT NULL,
      summary BLOB NOT NULL, stopped INTEGER NOT NULL, opening BLOB NOT NULL,
      PRIMARY KEY(account,kind,source,generation,position));
    CREATE TABLE projection_snapshot_devices(
      account BLOB NOT NULL, kind INTEGER NOT NULL, source BLOB NOT NULL,
      generation INTEGER NOT NULL, position INTEGER NOT NULL, device BLOB NOT NULL,
      keys BLOB NOT NULL, added INTEGER NOT NULL,
      PRIMARY KEY(account,kind,source,generation,position,device));
    CREATE TABLE projection_devices(
      account BLOB NOT NULL, kind INTEGER NOT NULL, source BLOB NOT NULL,
      generation INTEGER NOT NULL, device BLOB NOT NULL, first_position INTEGER NOT NULL,
      PRIMARY KEY(account,kind,source,generation,device));
    CREATE TABLE projection_keys(
      account BLOB NOT NULL, kind INTEGER NOT NULL, source BLOB NOT NULL,
      generation INTEGER NOT NULL, key_kind INTEGER NOT NULL, key_hash BLOB NOT NULL,
      first_position INTEGER NOT NULL,
      PRIMARY KEY(account,kind,source,generation,key_kind,key_hash));
    CREATE TABLE projection_times(
      account BLOB NOT NULL, kind INTEGER NOT NULL, source BLOB NOT NULL,
      generation INTEGER NOT NULL, position INTEGER NOT NULL,
      earliest INTEGER, latest INTEGER,
      PRIMARY KEY(account,kind,source,generation,position));
    CREATE TABLE account_applied_bodies(
      account BLOB NOT NULL, kind INTEGER NOT NULL, source BLOB NOT NULL,
      generation INTEGER NOT NULL, digest BLOB NOT NULL, position INTEGER NOT NULL,
      PRIMARY KEY(account,kind,source,generation,digest));",
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    Home(LogId),
    Base(BaseId),
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceKey {
    pub account: AccountId,
    pub source: Source,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pin {
    pub key: SourceKey,
    pub generation: u64,
    pub cut: AccountHead,
}
#[derive(Clone, Copy)]
pub(crate) struct ProjectionHeader {
    pub pin: Pin,
    pub root: [u8; 32],
    pub opening: OrderState,
    pub prefix: Option<Pin>,
}
pub(crate) struct StoredProjection {
    pub header: ProjectionHeader,
    pub checkpoint: Checkpoint,
}
pub(crate) struct HistoricalSnapshot {
    pub checkpoint: Checkpoint,
    pub opening: OrderState,
}
pub(crate) struct ProjectionWrite {
    pub header: ProjectionHeader,
    pub checkpoint: Checkpoint,
    pub delta: AccountProjectionDelta,
    pub snapshots: Vec<HistoricalSnapshot>,
}
pub(crate) struct HistoricalEntry {
    pub position: u64,
    pub event: StoredEvent,
    pub confirmation: Option<Vec<u8>>,
}
#[derive(Clone, Copy)]
pub(crate) struct AppliedBody {
    pub position: u64,
    pub digest: Digest,
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct Work {
    pub transitions: usize,
    pub decoded_rows: usize,
    pub decoded_bytes: usize,
    pub fullscan_steps: i32,
    pub sorts: i32,
    pub measured_statements: usize,
    pub sources: Vec<SourceKey>,
}
#[cfg(test)]
thread_local! {
    static WORK: std::cell::RefCell<Option<Work>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(super) fn begin_work() {
    WORK.with(|slot| *slot.borrow_mut() = Some(Work::default()));
}
#[cfg(test)]
pub(super) fn end_work() -> Work {
    WORK.with(|slot| slot.borrow_mut().take().unwrap())
}
#[cfg(test)]
pub(crate) fn full_read_work(rows: usize, bytes: usize) {
    WORK.with(|slot| {
        if let Some(work) = slot.borrow_mut().as_mut() {
            work.decoded_rows += rows;
            work.decoded_bytes += bytes;
        }
    });
}
#[cfg(test)]
pub(crate) fn transition_work() {
    WORK.with(|slot| {
        if let Some(work) = slot.borrow_mut().as_mut() {
            work.transitions += 1
        }
    });
}
#[cfg(test)]
pub(super) fn source_work(key: SourceKey) {
    WORK.with(|slot| {
        if let Some(work) = slot.borrow_mut().as_mut() {
            work.sources.push(key)
        }
    });
}
#[cfg(test)]
pub(super) fn statement_work(statement: &rusqlite::Statement<'_>) {
    WORK.with(|slot| {
        if let Some(work) = slot.borrow_mut().as_mut() {
            work.measured_statements += 1;
            work.fullscan_steps += statement.get_status(rusqlite::StatementStatus::FullscanStep);
            work.sorts += statement.get_status(rusqlite::StatementStatus::Sort);
        }
    });
}
#[cfg(test)]
fn history_work(rows: &[HistoricalEntry], statement: &rusqlite::Statement<'_>) {
    statement_work(statement);
    WORK.with(|slot| {
        if let Some(work) = slot.borrow_mut().as_mut() {
            work.decoded_rows += rows.len();
            work.decoded_bytes += rows
                .iter()
                .map(|r| r.event.original.len() + r.confirmation.as_ref().map_or(0, Vec::len))
                .sum::<usize>();
        }
    });
}

pub(super) fn identity(source: Source) -> (i64, [u8; 32]) {
    match source {
        Source::Home(log) => (if log.kind == LogKind::Account { 1 } else { 3 }, log.id),
        Source::Base(base) => (2, base.0),
    }
}
pub(super) fn sql(n: u64) -> rusqlite::Result<i64> {
    i64::try_from(n).map_err(|_| rusqlite::Error::InvalidQuery)
}
pub(super) fn number(r: &rusqlite::Row<'_>, col: usize) -> rusqlite::Result<u64> {
    let n: i64 = r.get(col)?;
    u64::try_from(n).map_err(|_| rusqlite::Error::InvalidQuery)
}
fn checkpoint(
    r: &rusqlite::Row<'_>,
    account: AccountId,
    position: usize,
) -> rusqlite::Result<Checkpoint> {
    let stopped: i64 = r.get(position + 3)?;
    if !(0..=1).contains(&stopped) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(Checkpoint {
        account,
        head: AccountHead {
            position: number(r, position)?,
            hash: array(r.get(position + 1)?)?,
        },
        summary: r.get(position + 2)?,
        active: Vec::new(),
        stopped: stopped == 1,
    })
}
pub(super) fn opening(bytes: Vec<u8>) -> rusqlite::Result<OrderState> {
    OrderState::decode(&bytes).map_err(|_| rusqlite::Error::InvalidQuery)
}
pub(super) fn devices(
    db: &rusqlite::Connection,
    pin: Pin,
    snapshot: Option<u64>,
) -> rusqlite::Result<Vec<AccountDeviceRow>> {
    let (kind, source) = identity(pin.key.source);
    let query = if snapshot.is_some() {
        "SELECT device,keys,added FROM projection_snapshot_devices WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4 AND position=?5 ORDER BY device"
    } else {
        "SELECT device,keys,added FROM projection_active WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4 AND ?5 IS NULL ORDER BY device"
    };
    let mut stmt = db.prepare(query)?;
    stmt.query_map(
        params![
            pin.key.account.0.as_slice(),
            kind,
            source.as_slice(),
            sql(pin.generation)?,
            snapshot.map(sql).transpose()?
        ],
        |r| {
            Ok(AccountDeviceRow {
                device: array(r.get(0)?)?,
                keys: r.get(1)?,
                added: number(r, 2)?,
            })
        },
    )?
    .collect()
}
fn cut_original(db: &rusqlite::Connection, pin: Pin) -> rusqlite::Result<Vec<u8>> {
    let (kind, _) = identity(pin.key.source);
    if kind != 1 || pin.cut.position == 0 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    db.query_row(
        "SELECT bytes FROM account_events WHERE account=?1 AND position=?2",
        params![pin.key.account.0.as_slice(), sql(pin.cut.position)?],
        |r| r.get(0),
    )
}
fn verify_opening(
    db: &rusqlite::Connection,
    pin: Pin,
    outer: OrderState,
    root: &[u8; 32],
) -> rusqlite::Result<()> {
    let Source::Home(log) = pin.key.source else {
        return Err(rusqlite::Error::InvalidQuery);
    };
    let original = cut_original(db, pin)?;
    let wrapped = bh_authz_proto::account_log_wrap(
        &original,
        db.query_row(
            "SELECT body FROM account_events WHERE account=?1 AND position=?2",
            params![pin.key.account.0.as_slice(), sql(pin.cut.position)?],
            |r| r.get::<_, Option<Vec<u8>>>(0),
        )?
        .map(array::<32>)
        .transpose()?
        .map(Digest),
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    if pin.cut.position == 1 {
        let genesis = bh_sync::canonical::CanonicalCommitment::order(
            BaseId(log.id),
            OrderState::EMPTY,
            wrapped.digest(),
            bh_sync::Route::Control,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
        if genesis.after() != outer {
            return Err(rusqlite::Error::InvalidQuery);
        }
    } else {
        let proof: Vec<u8> = db.query_row(
            "SELECT confirmation FROM account_confirmations WHERE account=?1 AND position=?2",
            params![pin.key.account.0.as_slice(), sql(pin.cut.position)?],
            |r| r.get(0),
        )?;
        let proof = bh_sync::evidence::OrderingConfirmation::decode(&proof)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let claim = proof
            .verify_for(
                root,
                &original,
                bh_authz_proto::account_log_unwrap(&wrapped)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?
                    .1,
            )
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let previous = db.query_row(
            "SELECT bytes FROM account_events WHERE account=?1 AND position=?2",
            params![pin.key.account.0.as_slice(), sql(pin.cut.position - 1)?],
            |r| r.get::<_, Vec<u8>>(0),
        )?;
        if claim.log != log
            || claim.original_head.position != pin.cut.position
            || claim.original_head.hash.0 != pin.cut.hash
            || claim.original_previous.position != pin.cut.position - 1
            || claim.original_previous.hash.0 != bh_crypto::hash(&previous)
            || claim.ordered != outer.head(BaseId(log.id))
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    Ok(())
}

/// A source's pinned hosting root and, for a BASE copy, the one HOME prefix
/// it extends: the same account's own log, never another BASE or a chain.
pub(super) fn source_row(
    db: &rusqlite::Connection,
    key: SourceKey,
    generation: u64,
) -> rusqlite::Result<([u8; 32], Option<Pin>)> {
    let (kind, source) = identity(key.source);
    #[allow(clippy::type_complexity)] // One row's nullable prefix columns.
    let (root, prefix): (
        Vec<u8>,
        (
            Option<Vec<u8>>,
            Option<i64>,
            Option<Vec<u8>>,
            Option<i64>,
            Option<i64>,
            Option<Vec<u8>>,
        ),
    ) = db.query_row(
        "SELECT root,prefix_account,prefix_kind,prefix_source,prefix_generation,prefix_position,prefix_hash
         FROM projection_sources WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4",
        params![key.account.0.as_slice(), kind, source.as_slice(), sql(generation)?],
        |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))),
    )?;
    let prefix = match (kind, prefix) {
        (1 | 3, (None, None, None, None, None, None)) => None,
        (2, (Some(account), Some(1), Some(log), Some(generation), Some(position), Some(hash)))
            if account == key.account.0 =>
        {
            let (generation, position) = (
                u64::try_from(generation).map_err(|_| rusqlite::Error::InvalidQuery)?,
                u64::try_from(position).map_err(|_| rusqlite::Error::InvalidQuery)?,
            );
            if generation == 0 || position == 0 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Some(Pin {
                key: SourceKey {
                    account: key.account,
                    source: Source::Home(LogId {
                        kind: LogKind::Account,
                        id: array(log)?,
                    }),
                },
                generation,
                cut: AccountHead {
                    position,
                    hash: array(hash)?,
                },
            })
        }
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    Ok((array(root)?, prefix))
}

/// The original at `position` of a pin's history: the account's own HOME
/// row, or for a BASE copy its HOME prefix up to that prefix's cut and its
/// own copied suffix after it.
fn original_at(
    db: &rusqlite::Connection,
    pin: Pin,
    prefix: Option<Pin>,
    position: u64,
) -> rusqlite::Result<Vec<u8>> {
    let (kind, source) = identity(pin.key.source);
    match (kind, prefix) {
        (1, None) => cut_original(
            db,
            Pin {
                cut: AccountHead {
                    position,
                    hash: [0; 32],
                },
                ..pin
            },
        ),
        (2, Some(prefix)) if position > 0 && position <= prefix.cut.position => db.query_row(
            "SELECT bytes FROM account_events WHERE account=?1 AND position=?2",
            params![pin.key.account.0.as_slice(), sql(position)?],
            |r| r.get(0),
        ),
        (2, Some(_)) => {
            let bytes: Vec<u8> = db.query_row(
                "SELECT bytes FROM projection_copies WHERE account=?1 AND kind=2 AND source=?2
                 AND generation=?3 AND position=?4",
                params![
                    pin.key.account.0.as_slice(),
                    source.as_slice(),
                    sql(pin.generation)?,
                    sql(position)?
                ],
                |r| r.get(0),
            )?;
            #[cfg(test)]
            full_read_work(1, bytes.len());
            Ok(bytes)
        }
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

pub(super) fn validate_pin(db: &rusqlite::Connection, pin: Pin) -> rusqlite::Result<[u8; 32]> {
    validate(db, pin).map(|(root, _)| root)
}

/// A pin's root and HOME prefix, once its generation, cut original and (for
/// a BASE copy) that prefix's own exact cut are checked.
pub(super) fn validate(
    db: &rusqlite::Connection,
    pin: Pin,
) -> rusqlite::Result<([u8; 32], Option<Pin>)> {
    let (kind, source) = identity(pin.key.source);
    if kind == 2 {
        let (root, prefix) = source_row(db, pin.key, pin.generation)?;
        let prefix = prefix.ok_or(rusqlite::Error::InvalidQuery)?;
        let current: u64 = db.query_row(
            "SELECT position FROM projection_current WHERE account=?1 AND kind=2 AND source=?2 AND generation=?3",
            params![pin.key.account.0.as_slice(), source.as_slice(), sql(pin.generation)?],
            |r| number(r, 0),
        )?;
        if pin.cut.position > current
            || pin.cut.position < prefix.cut.position
            || validate_pin(db, prefix)? != root
            || bh_crypto::hash(&original_at(db, pin, Some(prefix), pin.cut.position)?)
                != pin.cut.hash
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        return Ok((root, Some(prefix)));
    }
    let (root, current): (Vec<u8>, u64) = db.query_row(
        "SELECT s.root,c.position FROM projection_sources s JOIN projection_current c
         ON (s.account,s.kind,s.source,s.generation)=(c.account,c.kind,c.source,c.generation)
         WHERE s.account=?1 AND s.kind=?2 AND s.source=?3 AND s.generation=?4",
        params![
            pin.key.account.0.as_slice(),
            kind,
            source.as_slice(),
            sql(pin.generation)?
        ],
        |r| Ok((r.get(0)?, number(r, 1)?)),
    )?;
    if pin.cut.position > current || bh_crypto::hash(&cut_original(db, pin)?) != pin.cut.hash {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok((array(root)?, None))
}

impl Store {
    pub(crate) fn current_projection(
        &self,
        key: SourceKey,
    ) -> Result<Option<Record<StoredProjection>>, ServiceError> {
        #[cfg(test)]
        source_work(key);
        self.with(|db| {
            let (kind, source) = identity(key.source);
            let mut selected = db.prepare("SELECT generation FROM projection_selected WHERE account=?1 AND kind=?2 AND source=?3")?;
            let generation: Option<u64> = selected.query_row(
                params![key.account.0.as_slice(), kind, source.as_slice()], |r| number(r, 0)).optional()?;
            #[cfg(test)]
            statement_work(&selected);
            drop(selected);
            let Some(generation) = generation else {
                let legacy: bool = match key.source {
                    Source::Home(log) if log.kind==LogKind::Account => db.query_row("SELECT EXISTS(SELECT 1 FROM accounts WHERE account=?1 AND log=?2)", params![key.account.0.as_slice(),log.id.as_slice()], |r| r.get(0))?,
                    Source::Home(_) => false,
                    Source::Base(base) => db.query_row("SELECT EXISTS(SELECT 1 FROM base_controls WHERE base=?1)", [base.0.as_slice()], |r| r.get(0))?,
                };
                return Ok(legacy.then_some(Record::Legacy));
            };
            let mut current = db.prepare(
                "SELECT s.root,c.position,c.hash,c.summary,c.stopped,c.opening
                 FROM projection_sources s JOIN projection_current c
                 ON (s.account,s.kind,s.source,s.generation)=(c.account,c.kind,c.source,c.generation)
                 WHERE s.account=?1 AND s.kind=?2 AND s.source=?3 AND s.generation=?4")?;
            let (root, checkpoint, outer): (Vec<u8>, Checkpoint, Vec<u8>) = current.query_row(
                params![key.account.0.as_slice(), kind, source.as_slice(), sql(generation)?],
                |r| Ok((r.get(0)?, checkpoint(r, key.account, 1)?, r.get(5)?)))?;
            #[cfg(test)]
            statement_work(&current);
            drop(current);
            let pin = Pin { key, generation, cut: checkpoint.head };
            let mut checkpoint = checkpoint;
            checkpoint.active = devices(db, pin, None)?;
            let prefix = source_row(db, key, generation)?.1;
            Ok(Some(Record::Canonical(StoredProjection {
                header: ProjectionHeader { pin, root: array(root)?, opening: opening(outer)?, prefix },
                checkpoint,
            })))
        })
    }

    pub(crate) fn projection_at(
        &self,
        pin: Pin,
        position: u64,
    ) -> Result<StoredProjection, ServiceError> {
        #[cfg(test)]
        source_work(pin.key);
        self.with(|db| {
            if position == 0 || position > pin.cut.position {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let root = validate_pin(db, pin)?;
            let (kind, source) = identity(pin.key.source);
            let mut snapshot = db.prepare(
                "SELECT position,hash,summary,stopped,opening FROM projection_snapshots
                 WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4 AND position<=?5
                 ORDER BY position DESC LIMIT 1",
            )?;
            let (mut checkpoint, outer): (Checkpoint, Vec<u8>) = snapshot.query_row(
                params![
                    pin.key.account.0.as_slice(),
                    kind,
                    source.as_slice(),
                    sql(pin.generation)?,
                    sql(position)?
                ],
                |r| Ok((checkpoint(r, pin.key.account, 0)?, r.get(4)?)),
            )?;
            #[cfg(test)]
            statement_work(&snapshot);
            drop(snapshot);
            let at = Pin {
                cut: checkpoint.head,
                ..pin
            };
            checkpoint.active = devices(db, pin, Some(at.cut.position))?;
            Ok(StoredProjection {
                header: ProjectionHeader {
                    pin: at,
                    root,
                    opening: opening(outer)?,
                    prefix: None,
                },
                checkpoint,
            })
        })
    }

    pub(crate) fn history_range(
        &self,
        pin: Pin,
        first: u64,
        last: u64,
    ) -> Result<Vec<HistoricalEntry>, ServiceError> {
        #[cfg(test)]
        source_work(pin.key);
        self.with(|db| {
            if first == 0 || last < first || last > pin.cut.position || last - first >= 63 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            validate_pin(db, pin)?;
            if !matches!(pin.key.source, Source::Home(_)) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let mut stmt = db.prepare(
                "SELECT e.position,e.bytes,e.body,c.confirmation FROM account_events e
               LEFT JOIN account_confirmations c ON c.account=e.account AND c.position=e.position
               WHERE e.account=?1 AND e.position>=?2 AND e.position<=?3 ORDER BY e.position",
            )?;
            let rows: Vec<_> = stmt
                .query_map(
                    params![pin.key.account.0.as_slice(), sql(first)?, sql(last)?],
                    |r| {
                        Ok(HistoricalEntry {
                            position: number(r, 0)?,
                            event: StoredEvent {
                                original: r.get(1)?,
                                body: r
                                    .get::<_, Option<Vec<u8>>>(2)?
                                    .map(array)
                                    .transpose()?
                                    .map(Digest),
                            },
                            confirmation: r.get(3)?,
                        })
                    },
                )?
                .collect::<Result<_, _>>()?;
            #[cfg(test)]
            history_work(&rows, &stmt);
            if rows.len() != (last - first + 1) as usize
                || rows
                    .iter()
                    .enumerate()
                    .any(|(i, row)| row.position != first + i as u64)
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(rows)
        })
    }

    pub(crate) fn history_index(self: &Arc<Self>, pin: Pin) -> Arc<dyn HistoryIndex> {
        Arc::new(SqlIndex {
            store: self.clone(),
            pin,
        })
    }

    pub(crate) fn restore_projection(
        self: &Arc<Self>,
        stored: StoredProjection,
        expected: SourceKey,
        root: [u8; 32],
        genesis: &[u8],
    ) -> Result<VerifiedAccount, ServiceError> {
        #[cfg(test)]
        source_work(expected);
        let header = stored.header;
        let pin = header.pin;
        if pin.key != expected
            || header.root != root
            || stored.checkpoint.account != expected.account
            || stored.checkpoint.head != pin.cut
        {
            return Err(ServiceError::Storage);
        }
        let event = bh_account::AccountEvent::decode(genesis).map_err(storage)?;
        if AccountId::of_genesis(&event).map_err(storage)? != expected.account {
            return Err(ServiceError::Storage);
        }
        if let Source::Base(base) = expected.source {
            return self.restore_base(stored, base, genesis);
        }
        let log = match expected.source {
            Source::Home(log) => log,
            Source::Base(_) => return Err(ServiceError::Storage),
        };
        if bh_authz_proto::account_log_id(genesis).map_err(storage)? != log.id {
            return Err(ServiceError::Storage);
        }
        let valid = self.with(|db| {
            let (kind, source) = identity(expected.source);
            let selected: u64 = db.query_row("SELECT generation FROM projection_selected WHERE account=?1 AND kind=?2 AND source=?3",
                params![expected.account.0.as_slice(), kind, source.as_slice()], |r| number(r,0))?;
            if selected != pin.generation || validate_pin(db,pin)? != root ||
                db.query_row("SELECT bytes FROM account_events WHERE account=?1 AND position=1", [expected.account.0.as_slice()], |r|r.get::<_,Vec<u8>>(0))? != genesis {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let actual = if let Some(current) = self.current_projection_unlocked(db, expected, pin.generation)? {
                current
            } else { return Err(rusqlite::Error::InvalidQuery) };
            let current_pin = actual.header.pin.cut;
            let current_opening = actual.header.opening;
            let at = if current_pin == pin.cut { actual } else {
                self.snapshot_unlocked(db, pin)?
            };
            verify_opening(db, pin, header.opening, &root)?;
            if at.header.opening != header.opening || at.checkpoint.head != stored.checkpoint.head
                || at.checkpoint.summary != stored.checkpoint.summary
                || at.checkpoint.stopped != stored.checkpoint.stopped
                || at.checkpoint.active.len() != stored.checkpoint.active.len()
                || at.checkpoint.active.iter().zip(&stored.checkpoint.active).any(|(a,b)|
                    a.device != b.device || a.keys != b.keys || a.added != b.added)
                || header.opening.head(BaseId(log.id)).position != pin.cut.position {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let outer: (i64,Vec<u8>,Vec<u8>) = db.query_row("SELECT position,log_hash,opening FROM accounts WHERE account=?1",
                [expected.account.0.as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            if current_pin.position != outer.0 as u64 || current_opening != opening(outer.2)?
                || current_opening.head(BaseId(log.id)).hash.0 != array::<32>(outer.1)?
                || header.opening.head(BaseId(log.id)).position != pin.cut.position {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(())
        });
        valid?;
        account_projection::restore(stored.checkpoint, pin.generation, self.history_index(pin))
            .map_err(storage)
    }

    /// A BASE copy restores only at its current checkpoint, over exactly
    /// its pinned HOME prefix, and only while the base's control record names
    /// the same creator, raw opening and account head.
    fn restore_base(
        self: &Arc<Self>,
        stored: StoredProjection,
        base: BaseId,
        genesis: &[u8],
    ) -> Result<VerifiedAccount, ServiceError> {
        let header = stored.header;
        let pin = header.pin;
        let prefix = header.prefix.ok_or(ServiceError::Storage)?;
        let Source::Home(log) = prefix.key.source else {
            return Err(ServiceError::Storage);
        };
        if bh_authz_proto::account_log_id(genesis).map_err(storage)? != log.id {
            return Err(ServiceError::Storage);
        }
        self.with(|db| {
            let selected: u64 = db.query_row(
                "SELECT generation FROM projection_selected WHERE account=?1 AND kind=2 AND source=?2",
                params![pin.key.account.0.as_slice(), base.0.as_slice()],
                |r| number(r, 0),
            )?;
            let (root, anchor) = validate(db, pin)?;
            let actual = self
                .current_projection_unlocked(db, pin.key, pin.generation)?
                .ok_or(rusqlite::Error::InvalidQuery)?;
            let control = db.query_row(
                "SELECT creator, format, raw_order, account_position, account_hash
                 FROM base_controls WHERE base=?1",
                [base.0.as_slice()],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        super::canonical(r.get(1)?, r.get(2)?)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )?;
            if selected != pin.generation
                || root != header.root
                || anchor != Some(prefix)
                || db.query_row(
                    "SELECT bytes FROM account_events WHERE account=?1 AND position=1",
                    [pin.key.account.0.as_slice()],
                    |r| r.get::<_, Vec<u8>>(0),
                )? != genesis
                || actual.header.pin.cut != pin.cut
                || actual.header.opening != header.opening
                || actual.header.prefix != Some(prefix)
                || actual.checkpoint.summary != stored.checkpoint.summary
                || actual.checkpoint.stopped != stored.checkpoint.stopped
                || actual.checkpoint.active.len() != stored.checkpoint.active.len()
                || actual
                    .checkpoint
                    .active
                    .iter()
                    .zip(&stored.checkpoint.active)
                    .any(|(a, b)| a.device != b.device || a.keys != b.keys || a.added != b.added)
                || control.0 != pin.key.account.0
                || control.1 != Some(header.opening)
                || u64::try_from(control.2).ok() != Some(pin.cut.position)
                || control.3 != pin.cut.hash
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(())
        })?;
        account_projection::restore(stored.checkpoint, pin.generation, self.history_index(pin))
            .map_err(storage)
    }

    fn current_projection_unlocked(
        &self,
        db: &rusqlite::Connection,
        key: SourceKey,
        generation: u64,
    ) -> rusqlite::Result<Option<StoredProjection>> {
        let (kind, source) = identity(key.source);
        db.query_row("SELECT s.root,c.position,c.hash,c.summary,c.stopped,c.opening FROM projection_sources s JOIN projection_current c
          ON (s.account,s.kind,s.source,s.generation)=(c.account,c.kind,c.source,c.generation)
          WHERE s.account=?1 AND s.kind=?2 AND s.source=?3 AND s.generation=?4",
          params![key.account.0.as_slice(),kind,source.as_slice(),sql(generation)?], |r| {
              let mut cp = checkpoint(r,key.account,1)?;
              cp.active = devices(db,Pin { key, generation, cut:cp.head },None)?;
              let prefix = source_row(db, key, generation)?.1;
              Ok(StoredProjection { header:ProjectionHeader { pin:Pin {key,generation,cut:cp.head},root:array(r.get(0)?)?,opening:opening(r.get(5)?)?,prefix }, checkpoint:cp })
          }).optional()
    }
    fn snapshot_unlocked(
        &self,
        db: &rusqlite::Connection,
        pin: Pin,
    ) -> rusqlite::Result<StoredProjection> {
        let (kind, source) = identity(pin.key.source);
        db.query_row(
            "SELECT position,hash,summary,stopped,opening FROM projection_snapshots
           WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4 AND position=?5",
            params![
                pin.key.account.0.as_slice(),
                kind,
                source.as_slice(),
                sql(pin.generation)?,
                sql(pin.cut.position)?
            ],
            |r| {
                let mut cp = checkpoint(r, pin.key.account, 0)?;
                cp.active = devices(db, pin, Some(pin.cut.position))?;
                Ok(StoredProjection {
                    header: ProjectionHeader {
                        pin,
                        root: validate_pin(db, pin)?,
                        opening: opening(r.get(4)?)?,
                        prefix: None,
                    },
                    checkpoint: cp,
                })
            },
        )
    }
    pub(crate) fn body_applied(&self, pin: Pin, digest: Digest) -> Result<bool, ServiceError> {
        self.with(|db| {
            validate_pin(db,pin)?;
            let (kind,source)=identity(pin.key.source);
            db.query_row("SELECT EXISTS(SELECT 1 FROM account_applied_bodies WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4 AND digest=?5 AND position<=?6)",
                params![pin.key.account.0.as_slice(),kind,source.as_slice(),sql(pin.generation)?,digest.0.as_slice(),sql(pin.cut.position)?], |r|r.get(0))
        })
    }
}

struct SqlIndex {
    store: Arc<Store>,
    pin: Pin,
}
impl SqlIndex {
    /// Validate the pin and return a BASE copy's HOME prefix: its lookups read
    /// that one prefix, clamped to its cut, and its own suffix, nothing else.
    fn check(&self, db: &rusqlite::Connection, cut: AccountHead) -> rusqlite::Result<Option<Pin>> {
        #[cfg(test)]
        source_work(self.pin.key);
        if cut != self.pin.cut {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let (_, prefix) = validate(db, self.pin)?;
        #[cfg(test)]
        if let Some(prefix) = prefix {
            source_work(prefix.key);
        }
        Ok(prefix)
    }
}
/// Whether `pin`'s own first-use rows hold `value` at or before its cut.
fn first_use(
    db: &rusqlite::Connection,
    table: &str,
    column: &str,
    pin: Pin,
    extra: Option<i64>,
    value: &[u8],
) -> rusqlite::Result<bool> {
    let (kind, source) = identity(pin.key.source);
    let space = if extra.is_some() {
        " AND key_kind=?7"
    } else {
        ""
    };
    let mut statement = db.prepare(&format!(
        "SELECT EXISTS(SELECT 1 FROM {table} WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4 AND {column}=?5 AND first_position<=?6{space})"
    ))?;
    let found = match extra {
        Some(space) => statement.query_row(
            params![
                pin.key.account.0.as_slice(),
                kind,
                source.as_slice(),
                sql(pin.generation)?,
                value,
                sql(pin.cut.position)?,
                space
            ],
            |r| r.get(0),
        )?,
        None => statement.query_row(
            params![
                pin.key.account.0.as_slice(),
                kind,
                source.as_slice(),
                sql(pin.generation)?,
                value,
                sql(pin.cut.position)?
            ],
            |r| r.get(0),
        )?,
    };
    #[cfg(test)]
    statement_work(&statement);
    Ok(found)
}
impl HistoryIndex for SqlIndex {
    fn event_matches(
        &self,
        cut: AccountHead,
        position: u64,
        bytes: &[u8],
    ) -> Result<bool, AccountError> {
        self.store
            .with(|db| {
                let prefix = self.check(db, cut)?;
                if position == 0 || position > cut.position {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok(original_at(db, self.pin, prefix, position)? == bytes)
            })
            .map_err(|_| AccountError::Unavailable)
    }
    fn device_seen(&self, cut: AccountHead, id: &DeviceId) -> Result<bool, AccountError> {
        self.store
            .with(|db| {
                let prefix = self.check(db, cut)?;
                Ok(
                    first_use(db, "projection_devices", "device", self.pin, None, &id.0)?
                        || prefix.map_or(Ok(false), |p| {
                            first_use(db, "projection_devices", "device", p, None, &id.0)
                        })?,
                )
            })
            .map_err(|_| AccountError::Unavailable)
    }
    fn key_used(&self, cut: AccountHead, key: KeyUse<'_>) -> Result<bool, AccountError> {
        let (space, key) = match key {
            KeyUse::Signing(k) => (0, *k),
            KeyUse::Receiving(k) => (1, account_projection::receiving_hash(k)),
        };
        self.store
            .with(|db| {
                let prefix = self.check(db, cut)?;
                Ok(first_use(
                    db,
                    "projection_keys",
                    "key_hash",
                    self.pin,
                    Some(space),
                    &key,
                )? || prefix.map_or(Ok(false), |p| {
                    first_use(db, "projection_keys", "key_hash", p, Some(space), &key)
                })?)
            })
            .map_err(|_| AccountError::Unavailable)
    }
    fn confirmed_time(
        &self,
        cut: AccountHead,
        position: u64,
    ) -> Result<Option<ConfirmedTime>, AccountError> {
        self.store.with(|db|{let prefix = self.check(db,cut)?;
            if position==0 || position>cut.position{return Err(rusqlite::Error::InvalidQuery)}
            // A BASE copy's positions up to its anchor are its HOME prefix's.
            let pin = prefix.filter(|p| position <= p.cut.position).unwrap_or(self.pin);
            let(kind,source)=identity(pin.key.source);
            let mut statement = db.prepare("SELECT earliest,latest FROM projection_times WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4 AND position=?5")?;
            let (earliest,latest):(Option<i64>,Option<i64>)=statement.query_row(
                params![pin.key.account.0.as_slice(),kind,source.as_slice(),sql(pin.generation)?,sql(position)?],|r|Ok((r.get(0)?,r.get(1)?)))?;
            #[cfg(test)]
            statement_work(&statement);
            // Only genesis and a BASE copy's legacy (unconfirmed) copies are untimed.
            match(earliest,latest){(None,None) if position==1 || kind==2=>Ok(None),(Some(a),Some(b)) if a>=0 && b>=a=>Ok(Some(ConfirmedTime {earliest_ms:a as u64,latest_ms:b as u64})),_=>Err(rusqlite::Error::InvalidQuery)}
        }).map_err(|_|AccountError::Unavailable)
    }
}

#[cfg(test)]
type ValidationHook = Box<dyn FnOnce() -> rusqlite::Result<()>>;
#[cfg(test)]
thread_local! {
    static VALIDATION_HOOK: std::cell::RefCell<Option<ValidationHook>> = std::cell::RefCell::new(None);
}
#[cfg(test)]
pub(super) fn validation_hook(hook: impl FnOnce() -> rusqlite::Result<()> + 'static) {
    VALIDATION_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}
#[cfg(test)]
pub(super) fn run_validation_hook() -> rusqlite::Result<()> {
    VALIDATION_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook()
        } else {
            Ok(())
        }
    })
}

// Prepared only for one bounded page. Borrowed originals and proof bytes stay
// immutable through the transaction; SQL rows must match them exactly.
pub(super) struct PreparedProjection<'a> {
    previous: OrderState,
    entries: Vec<PreparedEntry<'a>>,
}
struct PreparedEntry<'a> {
    original: &'a [u8],
    body: Option<Digest>,
    proof: Option<&'a [u8]>,
    bounds: Option<(i64, i64)>,
    after: OrderState,
}

pub(super) fn prepare_projection<'a>(
    previous: OrderState,
    events: &'a [StoredEvent],
    page: ConfirmedPage<'a>,
    write: &ProjectionWrite,
) -> rusqlite::Result<PreparedProjection<'a>> {
    let pin = write.header.pin;
    let Source::Home(log) = pin.key.source else {
        return Err(rusqlite::Error::InvalidQuery);
    };
    if log.kind != LogKind::Account
        || events.is_empty()
        || events.len() > 64
        || previous.position() != write.delta.expected.0
        || previous.position().checked_add(events.len() as u64) != Some(pin.cut.position)
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut outer = previous;
    let mut original_before = write.delta.expected.1;
    let mut entries = Vec::with_capacity(events.len());
    let mut proofs = page.confirmations.iter().peekable();
    let mut snapshots = write.snapshots.iter();
    for (i, event) in events.iter().enumerate() {
        let position = previous.position() + 1 + i as u64;
        let proof = if proofs.peek().is_some_and(|(at, _)| *at == position) {
            Some(
                proofs
                    .next()
                    .ok_or(rusqlite::Error::InvalidQuery)?
                    .1
                    .as_slice(),
            )
        } else {
            None
        };
        let wrapped = bh_authz_proto::account_log_wrap(&event.original, event.body)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        outer = bh_sync::canonical::CanonicalCommitment::order(
            BaseId(log.id),
            outer,
            wrapped.digest(),
            bh_sync::Route::Control,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?
        .after();
        let original_hash = bh_crypto::hash(&event.original);
        if position == 1 || position.is_multiple_of(64) {
            let snapshot = snapshots.next().ok_or(rusqlite::Error::InvalidQuery)?;
            if snapshot.checkpoint.head.position != position
                || snapshot.checkpoint.head.hash != original_hash
                || snapshot.opening != outer
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
        }
        let bounds = match (position, proof) {
            (1, None) => None,
            (_, Some(bytes)) => {
                let confirmation = bh_sync::evidence::OrderingConfirmation::decode(bytes)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let claim = confirmation
                    .verify_for(&write.header.root, &event.original, event.body)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                if claim.log != log
                    || claim.original_head
                        != (bh_sync::Head {
                            position,
                            hash: Digest(original_hash),
                        })
                    || claim.original_previous
                        != (bh_sync::Head {
                            position: position - 1,
                            hash: Digest(original_before),
                        })
                    || claim.ordered != outer.head(BaseId(log.id))
                    || claim.bounds.earliest_ms > claim.bounds.latest_ms
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Some((sql(claim.bounds.earliest_ms)?, sql(claim.bounds.latest_ms)?))
            }
            _ => return Err(rusqlite::Error::InvalidQuery),
        };
        entries.push(PreparedEntry {
            original: &event.original,
            body: event.body,
            proof,
            bounds,
            after: outer,
        });
        original_before = original_hash;
    }
    if proofs.next().is_some()
        || snapshots.next().is_some()
        || outer != write.header.opening
        || original_before != pin.cut.hash
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    // No callback, including test instrumentation, runs inside Store.with's
    // writer transaction. The writer still checks selection and exact rows.
    #[cfg(test)]
    run_validation_hook()?;
    Ok(PreparedProjection { previous, entries })
}

pub(super) fn write_projection(
    tx: &Transaction<'_>,
    write: &ProjectionWrite,
    prepared: &PreparedProjection<'_>,
) -> rusqlite::Result<()> {
    let pin = write.header.pin;
    let (kind, source) = identity(pin.key.source);
    let d = &write.delta;
    if write.checkpoint.account != pin.key.account
        || write.checkpoint.head != pin.cut
        || d.through != (pin.cut.position, pin.cut.hash)
        || d.summary != write.checkpoint.summary
        || pin.generation == 0
        || pin.cut.position == 0
        || d.through.0 <= d.expected.0
        || d.through.0 - d.expected.0 > 64
        || d.epoch.is_some_and(|e| e != pin.generation)
        || write.header.prefix.is_some()
        || kind != 1
        || write.header.opening.head(BaseId(source)).position != pin.cut.position
        || bh_crypto::hash(&cut_original(tx, pin)?) != pin.cut.hash
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let current:Option<(u64,u64,Vec<u8>,Vec<u8>)>=tx.query_row("SELECT s.generation,c.position,c.hash,c.opening FROM projection_selected s JOIN projection_current c
      ON(s.account,s.kind,s.source,s.generation)=(c.account,c.kind,c.source,c.generation)
      WHERE s.account=?1 AND s.kind=?2 AND s.source=?3",
      params![pin.key.account.0.as_slice(),kind,source.as_slice()],|r|Ok((number(r,0)?,number(r,1)?,r.get(2)?,r.get(3)?))).optional()?;
    let mut before = match current {
        None if d.epoch.is_none() && d.expected == (0, [0; 32]) && pin.generation == 1 => {
            tx.execute("INSERT INTO projection_sources(account,kind,source,generation,root) VALUES(?1,?2,?3,?4,?5)",params![pin.key.account.0.as_slice(),kind,source.as_slice(),sql(pin.generation)?,write.header.root.as_slice()])?;
            tx.execute("INSERT INTO projection_selected(account,kind,source,generation) VALUES(?1,?2,?3,?4)",params![pin.key.account.0.as_slice(),kind,source.as_slice(),sql(pin.generation)?])?;
            // Genesis itself is the first immutable historical grid point.
            if write.snapshots.first().map(|s| s.checkpoint.head.position) != Some(1) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            OrderState::EMPTY
        }
        Some((generation, position, hash, previous_opening))
            if generation == pin.generation
                && d.epoch == Some(generation)
                && (position, hash.as_slice()) == (d.expected.0, d.expected.1.as_slice()) =>
        {
            let root:Vec<u8>=tx.query_row("SELECT root FROM projection_sources WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4",
                params![pin.key.account.0.as_slice(),kind,source.as_slice(),sql(pin.generation)?],|r|r.get(0))?;
            if root != write.header.root {
                return Err(rusqlite::Error::InvalidQuery);
            }
            opening(previous_opening)?
        }
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    if before != prepared.previous
        || prepared.entries.len() as u64 != pin.cut.position - d.expected.0
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut original_before = d.expected.1;
    // A time row is present for every original, including proofless genesis.
    // Absence of a row is lost evidence, not an untimed original.
    for (entry, position) in prepared
        .entries
        .iter()
        .zip(d.expected.0 + 1..=pin.cut.position)
    {
        let (original, body, proof): (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>) = tx.query_row(
            "SELECT e.bytes,e.body,c.confirmation FROM account_events e LEFT JOIN account_confirmations c
             ON c.account=e.account AND c.position=e.position WHERE e.account=?1 AND e.position=?2",
            params![pin.key.account.0.as_slice(),sql(position)?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        if original != entry.original
            || body.as_deref() != entry.body.as_ref().map(|d| d.0.as_slice())
            || proof.as_deref() != entry.proof
            || (position > 1 && entry.proof.is_none())
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        before = entry.after;
        original_before = bh_crypto::hash(&original);
        let bounds = entry.bounds;
        tx.execute(
            "INSERT INTO projection_times(account,kind,source,generation,position,earliest,latest)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                pin.key.account.0.as_slice(),
                kind,
                source.as_slice(),
                sql(pin.generation)?,
                sql(position)?,
                bounds.map(|v| v.0),
                bounds.map(|v| v.1)
            ],
        )?;
    }
    if before != write.header.opening || original_before != pin.cut.hash {
        return Err(rusqlite::Error::InvalidQuery);
    }
    apply_delta(tx, write)?;
    for snap in &write.snapshots {
        let cp = &snap.checkpoint;
        let pos = cp.head.position;
        if cp.account != pin.key.account
            || pos != 1 && pos % 64 != 0
            || pos <= d.expected.0
            || pos > pin.cut.position
            || snap.opening.head(BaseId(source)).position != pos
            || bh_crypto::hash(&cut_original(
                tx,
                Pin {
                    cut: cp.head,
                    ..pin
                },
            )?) != cp.head.hash
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if prepared
            .entries
            .iter()
            .find(|entry| entry.after.head(BaseId(source)).position == pos)
            .is_none_or(|entry| {
                entry.after != snap.opening || bh_crypto::hash(entry.original) != cp.head.hash
            })
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        tx.execute("INSERT INTO projection_snapshots(account,kind,source,generation,position,hash,summary,stopped,opening) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![pin.key.account.0.as_slice(),kind,source.as_slice(),sql(pin.generation)?,sql(pos)?,cp.head.hash.as_slice(),cp.summary,i64::from(cp.stopped),snap.opening.encode().as_slice()])?;
        for member in &cp.active {
            tx.execute("INSERT INTO projection_snapshot_devices(account,kind,source,generation,position,device,keys,added) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
              params![pin.key.account.0.as_slice(),kind,source.as_slice(),sql(pin.generation)?,sql(pos)?,member.device.as_slice(),member.keys,sql(member.added)?])?;
        }
    }
    Ok(())
}

/// Apply one bounded delta's membership and first-use rows to `write`'s pin
/// and replace its current checkpoint, in the caller's transaction.
pub(super) fn apply_delta(tx: &Transaction<'_>, write: &ProjectionWrite) -> rusqlite::Result<()> {
    let pin = write.header.pin;
    let (kind, source) = identity(pin.key.source);
    let d = &write.delta;
    for row in &d.added {
        if row.added <= d.expected.0 || row.added > pin.cut.position {
            return Err(rusqlite::Error::InvalidQuery);
        }
        tx.execute("INSERT INTO projection_active(account,kind,source,generation,device,keys,added) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![pin.key.account.0.as_slice(),kind,source.as_slice(),sql(pin.generation)?,row.device.as_slice(),row.keys,sql(row.added)?])?;
        tx.execute("INSERT INTO projection_devices(account,kind,source,generation,device,first_position) VALUES(?1,?2,?3,?4,?5,?6)",
            params![pin.key.account.0.as_slice(),kind,source.as_slice(),sql(pin.generation)?,row.device.as_slice(),sql(row.added)?])?;
    }
    for (device, pos) in &d.removed {
        // A matured removal can name its earlier request position, even when
        // the transition that resolves it belongs to this later page.
        if *pos==0 || *pos>pin.cut.position || tx.execute("DELETE FROM projection_active WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4 AND device=?5 AND added<?6",
            params![pin.key.account.0.as_slice(),kind,source.as_slice(),sql(pin.generation)?,device.as_slice(),sql(*pos)?])? != 1 {return Err(rusqlite::Error::InvalidQuery)}
    }
    for (space, key, pos) in &d.keys {
        if *space > 1 || *pos <= d.expected.0 || *pos > pin.cut.position {
            return Err(rusqlite::Error::InvalidQuery);
        }
        tx.execute("INSERT INTO projection_keys(account,kind,source,generation,key_kind,key_hash,first_position) VALUES(?1,?2,?3,?4,?5,?6,?7)",
          params![pin.key.account.0.as_slice(),kind,source.as_slice(),sql(pin.generation)?,space,key.as_slice(),sql(*pos)?])?;
    }
    let active = devices(tx, pin, None)?;
    if active.len() != write.checkpoint.active.len()
        || active
            .iter()
            .zip(&write.checkpoint.active)
            .any(|(a, b)| a.device != b.device || a.keys != b.keys || a.added != b.added)
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    tx.execute("INSERT INTO projection_current(account,kind,source,generation,position,hash,summary,stopped,opening)
      VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
      ON CONFLICT(account,kind,source,generation) DO UPDATE SET position=excluded.position,hash=excluded.hash,
      summary=excluded.summary,stopped=excluded.stopped,opening=excluded.opening",
      params![pin.key.account.0.as_slice(),kind,source.as_slice(),sql(pin.generation)?,sql(pin.cut.position)?,pin.cut.hash.as_slice(),write.checkpoint.summary,i64::from(write.checkpoint.stopped),write.header.opening.encode().as_slice()])?;
    Ok(())
}
