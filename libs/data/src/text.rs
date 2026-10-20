//! Scoped, rebuildable FTS5 projection. Body extraction is deliberately done
//! outside write transactions. FTS rows are contentless, so the small projection
//! state table records the projected title and a body hash to avoid revising unchanged text.
//! Record rows passed to hooks must be freshly read after `records::put`: `revise`
//! updates the stored text revision, not the caller's in-memory `RecordRow`.
pub use crate::text_reproject::step as reproject_step;
use crate::{
    CompiledType, DataError, RecordId, Scope,
    catalogue::Shipped,
    store::{
        self,
        records::{self, RecordRow},
        registry,
    },
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

/// Long bodies are indexed only up to this UTF-8 byte boundary (rounded down
/// to a character boundary). Search beyond the prefix is not available.
pub const MAX_INDEXED_BODY_BYTES: usize = 262_144;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextJob {
    pub rec: i64,
    pub scope: Scope,
    pub record: RecordId,
    pub wanted: u64,
}
/// `current` is this scope's largest assigned text revision. `complete_through`
/// is comparable across scopes: the first unindexed revision minus one, or the
/// global sequence horizon if this scope has no outstanding extraction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextWatermark {
    pub current: u64,
    pub complete_through: u64,
}
/// One attempted extraction: a selected job and the body a host decoded for it
/// outside every write transaction. `None` means the body is not available on
/// this replica yet; the job stays queued for a later turn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedJob {
    pub job: TextJob,
    pub body: Option<String>,
}
/// What one stored batch covered. `attempted` may exceed `extracted` when a
/// body was unavailable or its job was superseded while decoding; a later turn
/// attempts the jobs the work limit left behind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExtractOutcome {
    pub attempted: usize,
    pub extracted: usize,
}
pub trait BodyText {
    fn body_text(&self, scope: Scope, record: RecordId) -> Result<Option<String>, DataError>;
}

fn token(scope: i64) -> String {
    format!("s{scope}x")
}
/// The scope is a single FTS token, not user-supplied MATCH syntax.
pub(crate) fn scope_token(scope: i64) -> String {
    token(scope)
}
fn indexed_prefix(body: &str) -> &str {
    let mut end = body.len().min(MAX_INDEXED_BODY_BYTES);
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    &body[..end]
}
fn projection(row: &RecordRow, ct: &CompiledType) -> (String, String) {
    let doc = if row.deleted { None } else { row.view() };
    let title = doc
        .and_then(|d| ct.search.title.as_ref().and_then(|p| p.get(d)))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let body = doc
        .map(|d| {
            ct.search
                .text
                .iter()
                .filter_map(|p| p.get(d).and_then(|v| v.as_str()))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    (title, body)
}
fn put_fts(
    tx: &Transaction<'_>,
    rec: i64,
    sid: i64,
    title: &str,
    body: &str,
) -> Result<(), DataError> {
    tx.execute("DELETE FROM data_fts WHERE rowid=?1", [rec])
        .map_err(store::sql)?;
    tx.execute(
        "INSERT INTO data_fts(rowid,scope,title,body) VALUES(?1,?2,?3,?4)",
        params![rec, token(sid), title, indexed_prefix(body)],
    )
    .map_err(store::sql)?;
    Ok(())
}
fn revise(tx: &Transaction<'_>, row: &RecordRow) -> Result<u64, DataError> {
    let rev = records::next_seq(tx)?;
    tx.execute(
        "UPDATE data_record SET text_rev=?1 WHERE id=?2 AND scope=?3",
        params![store::integer(rev)?, row.id, row.scope],
    )
    .map_err(store::sql)?;
    Ok(rev)
}
fn queue(tx: &Transaction<'_>, row: &RecordRow) -> Result<u64, DataError> {
    let rev = revise(tx, row)?;
    // Retain the earliest unindexed revision across coalesced edits. Without
    // `since`, min(wanted)-1 would claim earlier edits already searchable.
    tx.execute("INSERT INTO data_text_job(rec,scope,wanted,since) VALUES(?1,?2,?3,?3) ON CONFLICT(rec) DO UPDATE SET scope=excluded.scope,wanted=excluded.wanted",
        params![row.id,row.scope,store::integer(rev)?]).map_err(store::sql)?;
    Ok(rev)
}
/// A note-body writer calls this after changing a body without a title edit.
/// Repeated calls replace the job's wanted revision rather than accumulating work.
pub fn body_changed(tx: &Transaction<'_>, row: &RecordRow) -> Result<u64, DataError> {
    queue(tx, row)
}
/// A Note's projection changed: keeps the derived title its extracted body is
/// indexed with and asks for the body at `row.text_rev`, which the caller
/// has already stored on the row.
pub(crate) fn note_projected(
    tx: &Transaction<'_>,
    row: &RecordRow,
    title: &str,
) -> Result<(), DataError> {
    tx.prepare_cached("INSERT INTO data_text_state(rec,scope,title,body) VALUES(?1,?2,?3,NULL) ON CONFLICT(rec) DO UPDATE SET scope=excluded.scope,title=excluded.title WHERE title IS NOT excluded.title OR scope IS NOT excluded.scope")
        .map_err(store::sql)?.execute(params![row.id, row.scope, title]).map_err(store::sql)?;
    // A record id cannot change scopes: avoid rewriting the scope/since index.
    tx.prepare_cached("INSERT INTO data_text_job(rec,scope,wanted,since) VALUES(?1,?2,?3,?3) ON CONFLICT(rec) DO UPDATE SET wanted=excluded.wanted")
        .map_err(store::sql)?.execute(params![row.id, row.scope, store::integer(row.text_rev)?]).map_err(store::sql)?;
    Ok(())
}
/// Maintains generic text synchronously; built-in bodies get one latest-wanted
/// job per record, with extraction outside the writer's transaction.
pub fn on_record_changed(
    tx: &Transaction<'_>,
    row: &RecordRow,
    ct: &CompiledType,
) -> Result<(), DataError> {
    // Live hooks and reconstruction use the currently effective search map,
    // including records still permitted on an older schema revision.
    let current = registry::current(tx, row.scope, row.type_id, &Shipped)?;
    let ct = current.as_ref().unwrap_or(ct);
    let (title, body) = projection(row, ct);
    let previous: Option<(String, Option<Vec<u8>>)> = tx
        .query_row(
            "SELECT title,body FROM data_text_state WHERE rec=?1 AND scope=?2",
            params![row.id, row.scope],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(store::sql)?;
    if row.deleted {
        if previous.is_some() {
            tx.execute("DELETE FROM data_fts WHERE rowid=?1", [row.id])
                .map_err(store::sql)?;
            tx.execute(
                "DELETE FROM data_text_state WHERE rec=?1 AND scope=?2",
                params![row.id, row.scope],
            )
            .map_err(store::sql)?;
            tx.execute("DELETE FROM data_text_job WHERE rec=?1", [row.id])
                .map_err(store::sql)?;
            revise(tx, row)?;
        }
    } else if ct.search.builtin_body {
        if previous.as_ref().is_none_or(|(old, _)| old != &title) {
            tx.execute("INSERT INTO data_text_state(rec,scope,title,body) VALUES(?1,?2,?3,NULL) ON CONFLICT(rec) DO UPDATE SET title=excluded.title,body=NULL",
                params![row.id,row.scope,title]).map_err(store::sql)?;
            queue(tx, row)?;
        }
    } else {
        let body_hash = bh_crypto::hash(body.as_bytes());
        if previous.as_ref().is_none_or(|(old, old_body)| {
            old != &title || old_body.as_deref() != Some(body_hash.as_slice())
        }) {
            put_fts(tx, row.id, row.scope, &title, &body)?;
            tx.execute("INSERT INTO data_text_state(rec,scope,title,body) VALUES(?1,?2,?3,?4) ON CONFLICT(rec) DO UPDATE SET title=excluded.title,body=excluded.body",
                params![row.id,row.scope,title,body_hash.as_slice()]).map_err(store::sql)?;
            tx.execute("DELETE FROM data_text_job WHERE rec=?1", [row.id])
                .map_err(store::sql)?;
            revise(tx, row)?;
        }
    }
    Ok(())
}

pub fn next_jobs(conn: &Connection, max_jobs: usize) -> Result<Vec<TextJob>, DataError> {
    next_jobs_after(conn, max_jobs, None)
}
// Jobs are ordered across all scopes using the (wanted,rec) index, so
// successive bounded attempts do not sort or scan the pending backlog.
fn next_jobs_after(
    conn: &Connection,
    max_jobs: usize,
    after: Option<(u64, i64)>,
) -> Result<Vec<TextJob>, DataError> {
    let (wanted, rec) = after.unwrap_or((0, 0));
    let mut stmt=conn.prepare("SELECT j.rec,s.base,s.audience,r.record,j.wanted FROM data_text_job j JOIN data_record r ON r.id=j.rec AND r.scope=j.scope JOIN data_scope s ON s.id=j.scope WHERE (j.wanted,j.rec)>(?1,?2) ORDER BY j.wanted,j.rec LIMIT ?3")
        .map_err(store::sql)?;
    let jobs = stmt
        .query_map(
            params![
                store::integer(wanted)?,
                rec,
                store::integer(max_jobs.min(i64::MAX as usize) as u64)?
            ],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            },
        )
        .map_err(store::sql)?;
    jobs.map(|j| {
        let (rec, base, audience, record, wanted) = j.map_err(store::sql)?;
        Ok(TextJob {
            rec,
            scope: Scope {
                base: store::id(base)?,
                audience: store::id(audience)?,
            },
            record: RecordId(store::id(record)?),
            wanted: store::unsigned(wanted)?,
        })
    })
    .collect()
}
/// Returns false if the job was superseded or its record was deleted. The
/// current record's title is read inside the transaction, avoiding stale titles.
pub fn store_extracted(tx: &Transaction<'_>, job: &TextJob, body: &str) -> Result<bool, DataError> {
    let Some(sid) = records::lookup_scope(tx, job.scope)? else {
        return Ok(false);
    };
    let wanted: Option<i64> = tx
        .query_row(
            "SELECT wanted FROM data_text_job WHERE rec=?1 AND scope=?2",
            params![job.rec, sid],
            |r| r.get(0),
        )
        .optional()
        .map_err(store::sql)?;
    if wanted != Some(store::integer(job.wanted)?) {
        return Ok(false);
    }
    let row: Option<(Vec<u8>, i64, bool)> = tx
        .query_row(
            "SELECT record,text_rev,deleted FROM data_record WHERE id=?1 AND scope=?2",
            params![job.rec, sid],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(store::sql)?;
    if !row.is_some_and(|(record, rev, deleted)| {
        record == job.record.0 && rev == wanted.unwrap_or_default() && !deleted
    }) {
        return Ok(false);
    }
    let title: String = tx
        .query_row(
            "SELECT title FROM data_text_state WHERE rec=?1 AND scope=?2",
            params![job.rec, sid],
            |r| r.get(0),
        )
        .map_err(store::sql)?;
    put_fts(tx, job.rec, sid, &title, body)?;
    tx.execute(
        "DELETE FROM data_text_job WHERE rec=?1 AND scope=?2 AND wanted=?3",
        params![job.rec, sid, wanted],
    )
    .map_err(store::sql)?;
    Ok(true)
}
/// The jobs one bounded turn should attempt, in rotation order: at most
/// `max_jobs` starting after the persisted extraction cursor, then wrapping
/// once to the head of the queue when the tail is shorter. An unavailable body
/// therefore rotates behind later revisions across turns. The caller decodes
/// each body outside every write transaction.
pub fn next_batch(conn: &Connection, max_jobs: usize) -> Result<Vec<TextJob>, DataError> {
    if max_jobs == 0 {
        return Ok(Vec::new());
    }
    let start: (i64, i64) = conn
        .query_row(
            "SELECT wanted,rec FROM data_text_extract_cursor WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(store::sql)?;
    let start = (store::unsigned(start.0)?, start.1);
    let mut jobs = next_jobs_after(conn, max_jobs, Some(start))?;
    if jobs.len() < max_jobs && start != (0, 0) {
        for job in next_jobs_after(conn, max_jobs - jobs.len(), Some((0, 0)))? {
            if (job.wanted, job.rec) >= start {
                break; // No second attempt of the same job in this turn.
            }
            jobs.push(job);
        }
    }
    Ok(jobs)
}
/// Store one attempted job in the caller's transaction: a body only when the
/// job's revision is still current, and always the rotation cursor.
fn attempt(tx: &Transaction<'_>, job: &TextJob, body: Option<&str>) -> Result<bool, DataError> {
    let stored = match body {
        Some(body) => store_extracted(tx, job, body)?,
        None => false,
    };
    tx.execute(
        "UPDATE data_text_extract_cursor SET wanted=?1,rec=?2 WHERE id=1",
        params![store::integer(job.wanted)?, job.rec],
    )
    .map_err(store::sql)?;
    Ok(stored)
}
/// Store a batch a host decoded outside every write transaction, in the
/// caller's short transaction. Metered like `extract_step_bounded`: stops
/// between jobs when the write work cap is met, leaving the rest for a later
/// turn. A job whose revision moved while decoding stores nothing and stays
/// queued at its new revision.
pub fn store_batch_bounded(
    tx: &Transaction<'_>,
    batch: &[DecodedJob],
    max_vm_steps: u64,
) -> Result<ExtractOutcome, DataError> {
    if max_vm_steps == 0 {
        return Err(DataError::Limit("work limit must be positive".into()));
    }
    let mut work = 0u64;
    let mut outcome = ExtractOutcome::default();
    for decoded in batch {
        if outcome.attempted > 0 && work >= max_vm_steps {
            break;
        }
        let meter = crate::index::WorkMeter::new(tx, max_vm_steps.saturating_sub(work).max(1))?;
        if attempt(tx, &decoded.job, decoded.body.as_deref())? {
            outcome.extracted += 1;
        }
        work = work.saturating_add(meter.used().max(1));
        drop(meter);
        outcome.attempted += 1;
    }
    Ok(outcome)
}
/// Reads body text without a write lock; checks revisions again at commit.
pub fn extract_step(
    conn: &mut Connection,
    src: &dyn BodyText,
    max_jobs: usize,
) -> Result<usize, DataError> {
    extract_step_bounded(conn, src, max_jobs, u64::MAX)
}
/// Attempts at most `max_jobs` bodies, successful or unavailable, and stops
/// between attempts when the cumulative metered write work cap is met. Job
/// selection uses an indexed, one-row seek; provider work is bounded by the
/// attempt count, not by the SQLite meter. A persisted cursor rotates unavailable
/// jobs behind later work, including after reopen. Commit, then yield to the
/// writer queue. Returns successful extractions.
pub fn extract_step_bounded(
    conn: &mut Connection,
    src: &dyn BodyText,
    max_jobs: usize,
    max_vm_steps: u64,
) -> Result<usize, DataError> {
    if max_vm_steps == 0 {
        return Err(DataError::Limit("work limit must be positive".into()));
    }
    let mut completed = 0;
    let mut work = 0u64;
    for job in next_batch(conn, max_jobs)? {
        let body = src.body_text(job.scope, job.record)?;
        let tx = conn.transaction().map_err(store::sql)?;
        let meter = crate::index::WorkMeter::new(&tx, max_vm_steps.saturating_sub(work).max(1))?;
        if attempt(&tx, &job, body.as_deref())? {
            completed += 1;
        }
        work = work.saturating_add(meter.used().max(1));
        drop(meter);
        tx.commit().map_err(store::sql)?;
        if work >= max_vm_steps {
            break;
        }
    }
    Ok(completed)
}
/// Start in the same transaction that marks other derived indexes non-ready.
/// The durable marker makes every scope's text watermark lag until all records
/// have been projected and any built-in body extraction jobs have finished.
pub(crate) fn begin_rebuild(tx: &Transaction<'_>) -> Result<(), DataError> {
    tx.execute(
        "INSERT OR IGNORE INTO data_text_rebuild(id,phase,cursor) VALUES(1,'clearing',0)",
        [],
    )
    .map_err(store::sql)?;
    Ok(())
}

/// One committed, restartable batch of FTS clearing or record projection.
/// Returns true only after every record has been visited. Source records and
/// pending work are never cleared. Callers provide one short transaction per step.
/// Known limit: core definitions are resolved from the shipped catalogue;
/// an unpersisted custom core catalogue cannot be reconstructed here.
/// One committed writer-queue turn of restartable text reconstruction. A
/// single large FTS record can exceed the bound; yield after this step.
pub fn rebuild_step_bounded(
    tx: &Transaction<'_>,
    max_rows: usize,
    max_vm_steps: u64,
) -> Result<bool, DataError> {
    let meter = crate::index::WorkMeter::new(tx, max_vm_steps)?;
    let (phase, cursor): (String, i64) = tx
        .query_row(
            "SELECT phase,cursor FROM data_text_rebuild WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(store::sql)?;
    let cap = if max_vm_steps == u64::MAX {
        max_rows.min(500)
    } else {
        max_rows.min(32)
    } as i64;
    if phase == "clearing" {
        let fts = tx
            .execute(
                "DELETE FROM data_fts WHERE rowid IN (SELECT rowid FROM data_fts LIMIT ?1)",
                [cap],
            )
            .map_err(store::sql)?;
        let remaining = cap - fts as i64;
        let state = tx.execute("DELETE FROM data_text_state WHERE rec IN (SELECT rec FROM data_text_state LIMIT ?1)", [remaining]).map_err(store::sql)?;
        let remaining = remaining - state as i64;
        let jobs = tx
            .execute(
                "DELETE FROM data_text_job WHERE rec IN (SELECT rec FROM data_text_job LIMIT ?1)",
                [remaining],
            )
            .map_err(store::sql)?;
        if fts + state + jobs == 0 && cap > 0 {
            tx.execute(
                "UPDATE data_text_rebuild SET phase='building' WHERE id=1",
                [],
            )
            .map_err(store::sql)?;
        }
        return Ok(false);
    }
    if phase != "building" {
        return Err(DataError::Corrupt("invalid text rebuild phase".into()));
    }
    let mut st = tx
        .prepare("SELECT scope,record,id FROM data_record WHERE id>?1 ORDER BY id LIMIT ?2")
        .map_err(store::sql)?;
    let rows = st
        .query_map(params![cursor, cap], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .map_err(store::sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(store::sql)?;
    drop(st);
    let mut last = None;
    for (sid, record, id) in &rows {
        if last.is_some() && meter.exhausted() {
            break;
        }
        let row = records::get(tx, *sid, RecordId(store::id(record.clone())?))?
            .ok_or_else(|| DataError::Corrupt("text rebuild record vanished".into()))?;
        let compiled = registry::current(tx, *sid, row.type_id, &Shipped)?
            .ok_or_else(|| DataError::Corrupt("text rebuild definition missing".into()))?;
        on_record_changed(tx, &row, &compiled)?;
        last = Some(*id);
    }
    if let Some(last) = last {
        tx.execute("UPDATE data_text_rebuild SET cursor=?1 WHERE id=1", [last])
            .map_err(store::sql)?;
    }
    // Probe beyond the persisted cursor without reading the rest of the table.
    let next: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM data_record WHERE id>(SELECT cursor FROM data_text_rebuild WHERE id=1))", [], |r| r.get(0)).map_err(store::sql)?;
    if !next && cap > 0 {
        tx.execute("DELETE FROM data_text_rebuild WHERE id=1", [])
            .map_err(store::sql)?;
        return Ok(true);
    }
    Ok(false)
}

/// Cheap host probe for pending search-mapping evolution.
pub fn reprojection_pending(conn: &Connection) -> Result<bool, DataError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM data_text_mapping)",
        [],
        |row| row.get(0),
    )
    .map_err(store::sql)
}

pub fn watermark(conn: &Connection, scope: Scope) -> Result<TextWatermark, DataError> {
    watermark_for_types(conn, scope, None)
}

pub(crate) fn watermark_for_types(
    conn: &Connection,
    scope: Scope,
    types: Option<&[crate::TypeId]>,
) -> Result<TextWatermark, DataError> {
    let Some(sid) = records::lookup_scope(conn, scope)? else {
        return Ok(TextWatermark {
            current: 0,
            complete_through: 0,
        });
    };
    // The covering (scope,text_rev) index supplies max without visiting every
    // record. The global sequence is the comparable horizon across scopes:
    // an idle scope is not behind a revision issued in another scope.
    let (current,pending,global):(i64,Option<i64>,i64)=conn.query_row(
        "SELECT coalesce((SELECT max(text_rev) FROM data_record WHERE scope=?1),0), (SELECT min(since) FROM data_text_job WHERE scope=?1), (SELECT next-1 FROM data_seq WHERE id=1)",
        [sid],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(store::sql)?;
    let rebuilding: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM data_text_rebuild WHERE id=1)",
            [],
            |r| r.get(0),
        )
        .map_err(store::sql)?;
    if rebuilding {
        return Ok(TextWatermark {
            current: store::unsigned(global)?.max(store::unsigned(current)?),
            complete_through: 0,
        });
    }
    let mapping: Option<i64> = if let Some(types) = types {
        let mut first = None;
        for ty in types {
            let since: Option<i64> = conn
                .query_row(
                    "SELECT since FROM data_text_mapping WHERE scope=?1 AND type=?2",
                    params![sid, ty.0.as_slice()],
                    |r| r.get(0),
                )
                .optional()
                .map_err(store::sql)?;
            if let Some(since) = since {
                first = Some(first.map_or(since, |old: i64| old.min(since)));
            }
        }
        first
    } else {
        conn.query_row(
            "SELECT min(since) FROM data_text_mapping WHERE scope=?1",
            [sid],
            |r| r.get(0),
        )
        .map_err(store::sql)?
    };
    let pending = pending.into_iter().chain(mapping).min();
    Ok(TextWatermark {
        current: store::unsigned(current)?
            .max(mapping.map(store::unsigned).transpose()?.unwrap_or(0)),
        complete_through: pending
            .map(store::unsigned)
            .transpose()?
            .map_or(store::unsigned(global)?, |w| w.saturating_sub(1)),
    })
}
