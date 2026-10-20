use super::{count_family, entries, state};
use crate::{
    DataError, RecordId,
    store::{id, integer, records, registry, sql},
    text,
};
use rusqlite::{Transaction, params};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// Counts SQLite VM steps without interrupting a statement (which would roll
/// back its work). Each step stops between records; a single record or SQL
/// statement can exceed the bound. The caller must commit after one step and
/// yield to foreground writers before scheduling another.
pub(crate) struct WorkMeter<'a> {
    tx: &'a Transaction<'a>,
    steps: Arc<AtomicU64>,
    limit: u64,
}
impl<'a> WorkMeter<'a> {
    pub(crate) fn new(tx: &'a Transaction<'a>, limit: u64) -> Result<Self, DataError> {
        if limit == 0 {
            return Err(DataError::Limit("work limit must be positive".into()));
        }
        let steps = Arc::new(AtomicU64::new(0));
        let counter = steps.clone();
        tx.progress_handler(
            100,
            Some(move || {
                counter.fetch_add(100, Ordering::Relaxed);
                false
            }),
        )
        .map_err(sql)?;
        Ok(Self { tx, steps, limit })
    }
    pub(crate) fn exhausted(&self) -> bool {
        self.used() >= self.limit
    }
    pub(crate) fn used(&self) -> u64 {
        self.steps.load(Ordering::Relaxed)
    }
}
impl Drop for WorkMeter<'_> {
    fn drop(&mut self) {
        let _ = self.tx.progress_handler(0, None::<fn() -> bool>);
    }
}

pub const BACKFILL_BATCH: usize = 500;
/// Persisted cumulative rows scanned and the build-start estimate; concurrent
/// writes can change the total, so the reported total never falls below done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub done: u64,
    pub total: u64,
    pub ready: bool,
}

/// Backward-compatible unmetered maintenance for offline callers. Online
/// hosts must call `backfill_step_bounded` once per writer-queue turn.
pub fn backfill_step(
    tx: &Transaction<'_>,
    ix: i64,
    max_rows: usize,
) -> Result<Progress, DataError> {
    backfill_step_bounded(tx, ix, max_rows, u64::MAX)
}
/// Performs at most `max_rows` rows and stops after `max_vm_steps` SQLite VM
/// steps at the next record boundary. A single record/SQL statement can run
/// over the bound; choose the bound with measured per-record headroom. Call in
/// one short transaction, commit, then serve waiting foreground writes before
/// the next step. Never loop maintenance steps with writer priority.
pub fn backfill_step_bounded(
    tx: &Transaction<'_>,
    ix: i64,
    max_rows: usize,
    max_vm_steps: u64,
) -> Result<Progress, DataError> {
    let meter = WorkMeter::new(tx, max_vm_steps)?;
    let mut current = state(tx, ix)?;
    if current.state == "ready" {
        return Ok(Progress {
            done: current.built,
            total: current.estimate.unwrap_or(0).max(current.built),
            ready: true,
        });
    }
    let cap = max_rows.min(BACKFILL_BATCH);
    if current.state == "retiring" {
        if current.estimate.is_none() {
            let count:i64=tx.query_row("SELECT (SELECT count(*) FROM data_index_entry WHERE ix=?1)+(SELECT count(*) FROM data_unique WHERE ix=?1)",[ix],|r|r.get(0)).map_err(sql)?;
            current.estimate =
                Some(u64::try_from(count).map_err(|e| DataError::Corrupt(e.to_string()))?);
            tx.execute(
                "UPDATE data_index SET estimate=?2 WHERE id=?1",
                params![ix, count],
            )
            .map_err(sql)?;
        }
        let cap = if max_vm_steps == u64::MAX {
            cap
        } else {
            cap.min(32)
        };
        let removed=tx.execute("DELETE FROM data_index_entry WHERE rowid IN (SELECT rowid FROM data_index_entry WHERE ix=?1 LIMIT ?2)",params![ix,cap as i64]).map_err(sql)?;
        let removed_unique=tx.execute("DELETE FROM data_unique WHERE rowid IN (SELECT rowid FROM data_unique WHERE ix=?1 LIMIT ?2)",params![ix,(cap-removed) as i64]).map_err(sql)?;
        let remains:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM data_index_entry WHERE ix=?1 UNION ALL SELECT 1 FROM data_unique WHERE ix=?1)",[ix],|r|r.get(0)).map_err(sql)?;
        if !remains {
            tx.execute("DELETE FROM data_index WHERE id=?1", [ix])
                .map_err(sql)?;
        }
        let built = current
            .built
            .checked_add((removed + removed_unique) as u64)
            .ok_or_else(|| DataError::Limit("index progress overflow".into()))?;
        if remains {
            tx.execute(
                "UPDATE data_index SET built=?2 WHERE id=?1",
                params![ix, integer(built)?],
            )
            .map_err(sql)?;
        }
        return Ok(Progress {
            done: built,
            total: current.estimate.unwrap_or(0).max(built),
            ready: !remains,
        });
    }
    if current.state != "building" {
        return Err(DataError::Corrupt("invalid index state".into()));
    }
    // A reset leaves estimate NULL. Count exactly once at build start, never
    // on each batch; the following scan remains independent of family size.
    if current.estimate.is_none() {
        let estimate = count_family(tx, current.scope, current.family)?;
        tx.execute(
            "UPDATE data_index SET estimate=?2 WHERE id=?1",
            params![ix, integer(estimate)?],
        )
        .map_err(sql)?;
        current.estimate = Some(estimate);
    }
    let members = registry::family_members(tx, current.scope, current.family)?;
    let mut ordinal = members
        .iter()
        .position(|member| current.cursor_type.is_none_or(|cursor| *member >= cursor))
        .unwrap_or(members.len());
    let mut done = 0usize;
    let mut cursor_type = current.cursor_type;
    let mut cursor_id = current.cursor_id;
    while ordinal < members.len() && done < cap && (done == 0 || !meter.exhausted()) {
        let member = members[ordinal];
        let after = if cursor_type == Some(member) {
            cursor_id
        } else {
            0
        };
        let mut stmt=tx.prepare("SELECT record,id FROM data_record WHERE scope=?1 AND type=?2 AND id>?3 ORDER BY id LIMIT ?4").map_err(sql)?;
        let found = stmt
            .query_map(
                params![
                    current.scope,
                    member.0.as_slice(),
                    after,
                    (cap - done).min(32) as i64
                ],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)),
            )
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        for (record, id_) in found {
            let row = records::get(tx, current.scope, RecordId(id(record)?))?
                .ok_or_else(|| DataError::Corrupt("backfill record vanished".into()))?;
            entries::write(tx, &current, &row)?;
            cursor_type = Some(member);
            cursor_id = id_;
            done += 1;
            if meter.exhausted() {
                break;
            }
        }
        // An indexed existence probe detects exhaustion without reading another record.
        let more: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM data_record WHERE scope=?1 AND type=?2 AND id>?3)",
                params![
                    current.scope,
                    member.0.as_slice(),
                    if cursor_type == Some(member) {
                        cursor_id
                    } else {
                        0
                    }
                ],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if more {
            if done >= cap || meter.exhausted() {
                break;
            }
            continue;
        }
        // A completed member is covered even if it contained zero records.
        // The MAX marker also covers newly inserted rows of this type inline.
        cursor_type = Some(member);
        cursor_id = i64::MAX;
        ordinal += 1;
    }
    // A zero-cap step cannot claim completion without scanning.
    let ready = cap > 0 && ordinal == members.len();
    let built = current
        .built
        .checked_add(done as u64)
        .ok_or_else(|| DataError::Limit("index progress overflow".into()))?;
    tx.execute(
        "UPDATE data_index SET state=?2,cursor_type=?3,cursor_id=?4,built=?5 WHERE id=?1",
        params![
            ix,
            if ready { "ready" } else { "building" },
            cursor_type.map(|t| t.0.to_vec()),
            cursor_id,
            integer(built)?
        ],
    )
    .map_err(sql)?;
    Ok(Progress {
        done: built,
        total: current.estimate.unwrap_or(0).max(built),
        ready,
    })
}

/// Mark indexes non-ready before clearing derived rows. Returns true if the
/// index-clearing phase is pending. A later call resumes instead of resetting
/// work already in progress. Commit this marker before scheduling steps.
pub fn begin_rebuild(tx: &Transaction<'_>) -> Result<bool, DataError> {
    let clearing: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM data_index WHERE state='clearing')",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let text_pending: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM data_text_rebuild WHERE id=1)",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if !clearing && !text_pending {
        tx.execute("UPDATE data_index SET state='clearing',cursor_type=NULL,cursor_id=0,built=0,estimate=NULL WHERE state!='retiring'",[]).map_err(sql)?;
        text::begin_rebuild(tx)?;
    }
    Ok(clearing || !text_pending)
}
/// One bounded, restartable index-clearing step. Returns true once clearing is
/// over and indexes have transitioned to building. Commit and yield to queued
/// foreground writers before another clearing, text or index backfill step.
pub fn clear_step_bounded(
    tx: &Transaction<'_>,
    max_rows: usize,
    max_vm_steps: u64,
) -> Result<bool, DataError> {
    let _meter = WorkMeter::new(tx, max_vm_steps)?;
    let cap = if max_vm_steps == u64::MAX {
        max_rows.min(BACKFILL_BATCH)
    } else {
        max_rows.min(32)
    };
    let removed=tx.execute("DELETE FROM data_index_entry WHERE rowid IN (SELECT e.rowid FROM data_index_entry e JOIN data_index d ON d.id=e.ix WHERE d.state='clearing' LIMIT ?1)",[cap as i64]).map_err(sql)?;
    let removed_unique=tx.execute("DELETE FROM data_unique WHERE rowid IN (SELECT u.rowid FROM data_unique u JOIN data_index d ON d.id=u.ix WHERE d.state='clearing' LIMIT ?1)",[(cap-removed) as i64]).map_err(sql)?;
    if removed + removed_unique == 0 && cap > 0 {
        tx.execute(
            "UPDATE data_index SET state='building' WHERE state='clearing'",
            [],
        )
        .map_err(sql)?;
        return Ok(true);
    }
    Ok(false)
}
/// Offline convenience for a persistent database. It intentionally loops
/// without yielding to the host writer queue. An online host instead calls
/// `begin_rebuild`, `clear_step_bounded`, `text::rebuild_step_bounded`, then
/// `backfill_step_bounded`: one committed step per writer-queue turn.
pub fn rebuild_all<F>(mut tx_factory: F) -> Result<(), DataError>
where
    F: FnMut() -> Result<rusqlite::Connection, DataError>,
{
    let resume = {
        let mut conn = tx_factory()?;
        let tx = conn.transaction().map_err(sql)?;
        let pending = begin_rebuild(&tx)?;
        tx.commit().map_err(sql)?;
        pending
    };
    if resume {
        loop {
            let mut conn = tx_factory()?;
            let tx = conn.transaction().map_err(sql)?;
            let ready = clear_step_bounded(&tx, BACKFILL_BATCH, u64::MAX)?;
            tx.commit().map_err(sql)?;
            if ready {
                break;
            }
        }
    }
    loop {
        let mut conn = tx_factory()?;
        let tx = conn.transaction().map_err(sql)?;
        let ready = text::rebuild_step_bounded(&tx, BACKFILL_BATCH, u64::MAX)?;
        tx.commit().map_err(sql)?;
        if ready {
            return Ok(());
        }
    }
}
