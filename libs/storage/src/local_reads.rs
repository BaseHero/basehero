//! Bounded local pending reads and additive note checkpoints. A checkpoint is
//! merely a device-local read projection, never signed history or permission to
//! delete pending/outbox-referenced updates. Encoding runs outside SQLite locks.
use crate::{DeviceDatabase, NoteKey, PendingNoteUpdate, StoreError};
use bh_core::note::{Note, OrderedState};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

pub struct PendingPage {
    pub rows: Vec<PendingNoteUpdate>,
    pub next: Option<i64>,
}
fn note_page(
    conn: &Connection,
    key: NoteKey,
    after: i64,
    target: i64,
    limit: usize,
) -> Result<Vec<(i64, Vec<u8>)>, StoreError> {
    let mut stmt=conn.prepare_cached("SELECT id,length(delta),delta FROM note_updates WHERE base=?1 AND audience=?2 AND note=?3 AND id>?4 AND id<=?5 ORDER BY id LIMIT ?6")?;
    let mut rows = stmt.query(params![
        key.base.as_slice(),
        key.audience.as_slice(),
        key.note.as_slice(),
        after,
        target,
        limit.clamp(1, 256) as i64
    ])?;
    let (mut page, mut bytes) = (Vec::new(), 0usize);
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let size: usize = row
            .get::<_, i64>(1)?
            .try_into()
            .map_err(|_| StoreError::InvalidUpdate)?;
        if !page.is_empty() && bytes.saturating_add(size) > 256 * 1024 {
            break;
        }
        let delta: Vec<u8> = row.get(2)?;
        bytes = bytes.saturating_add(delta.len());
        page.push((id, delta));
    }
    Ok(page)
}
/// Short SQLite seed. Replay of this immutable prefix happens after releasing
/// the writer, even for an in-memory test container without a read-only pool.
pub struct NoteSeed {
    pub state: OrderedState,
    pub covered: i64,
    pub target: i64,
}
/// Captured local read projection; only bytes/metadata are read under SQLite.
/// Decoding the prior checkpoint and every delta happens after guards release.
pub struct CheckpointSeed {
    key: NoteKey,
    generation: i64,
    covered: i64,
    target: i64,
    anchor: Option<[u8; 32]>,
    encoded: Vec<u8>,
}
impl CheckpointSeed {
    pub fn start(self) -> Result<CheckpointJob, StoreError> {
        let previous =
            OrderedState::decode(&self.encoded).map_err(|_| StoreError::InvalidUpdate)?;
        let note = Note::from_ordered(&previous)?;
        Ok(CheckpointJob {
            key: self.key,
            generation: self.generation,
            covered: self.covered,
            target: self.target,
            after: self.covered,
            anchor: self.anchor,
            note,
            previous,
            tail: Vec::new(),
        })
    }
}
pub struct CheckpointJob {
    key: NoteKey,
    generation: i64,
    covered: i64,
    target: i64,
    after: i64,
    anchor: Option<[u8; 32]>,
    note: Note,
    // The updates `note` integrated, in order, for verified compaction.
    previous: OrderedState,
    tail: Vec<Vec<u8>>,
}
pub struct PreparedCheckpoint {
    key: NoteKey,
    generation: i64,
    covered: i64,
    target: i64,
    anchor: Option<[u8; 32]>,
    encoded: Vec<u8>,
}
impl PreparedCheckpoint {
    pub fn encoded_bytes(&self) -> usize {
        self.encoded.len()
    }
}
impl CheckpointJob {
    /// Applying each page happens after releasing the writer guard. The yrs
    /// state includes unknown structures and unresolved dependencies.
    pub fn apply_page(&mut self, page: &[(i64, Vec<u8>)]) -> Result<(), StoreError> {
        for (id, bytes) in page {
            if *id <= self.after || *id > self.target {
                return Err(StoreError::InvalidUpdate);
            }
            self.note.apply_update(bytes)?;
            self.tail.push(bytes.clone());
            self.after = *id;
        }
        Ok(())
    }
    pub fn after(&self) -> i64 {
        self.after
    }
    /// Compaction keeps the order the updates were integrated in wherever a
    /// merged state would reopen with a different structure. A result that
    /// does not reopen as this note publishes nothing: the prior checkpoint
    /// and its tail stay.
    pub fn finish(self) -> Result<Option<PreparedCheckpoint>, StoreError> {
        if self.after != self.target {
            return Ok(None);
        }
        let Some(state) = self.note.ordered(&self.previous, &self.tail)? else {
            return Ok(None);
        };
        Ok(Some(PreparedCheckpoint {
            key: self.key,
            generation: self.generation,
            covered: self.covered,
            target: self.target,
            anchor: self.anchor,
            encoded: state.encode(),
        }))
    }
}
impl DeviceDatabase {
    pub fn note_seed(&self, key: NoteKey) -> Result<NoteSeed, StoreError> {
        let prior:Option<(i64,Vec<u8>)>=self.connection.query_row("SELECT local_frontier,encoded_yjs FROM note_checkpoints WHERE base=?1 AND audience=?2 AND note=?3",params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (covered, encoded) = prior.unwrap_or((0, Vec::new()));
        let target: i64 = self.local_frontier(key)?.max(covered);
        Ok(NoteSeed {
            state: OrderedState::decode(&encoded).map_err(|_| StoreError::InvalidUpdate)?,
            covered,
            target,
        })
    }
    pub fn note_seed_page(
        &self,
        key: NoteKey,
        after: i64,
        target: i64,
    ) -> Result<Vec<(i64, Vec<u8>)>, StoreError> {
        note_page(&self.connection, key, after, target, 256)
    }
    /// Scope and keyset are local indexing selectors, never page authority.
    /// An update larger than the byte budget is returned alone so enumeration
    /// still progresses; callers should cap update sizes at their trust boundary.
    pub fn pending_page(
        &self,
        base: [u8; 32],
        audience: [u8; 32],
        note: Option<[u8; 32]>,
        after: i64,
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<PendingPage, StoreError> {
        let limit = max_rows.clamp(1, 256);
        let complete: bool = self.connection.query_row(
            "SELECT complete FROM pending_scope_backfill WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        if complete {
            let sql = if note.is_some() {
                "SELECT s.update_id,s.note,length(u.delta),u.delta FROM pending_scope s JOIN note_updates u ON u.id=s.update_id WHERE s.base=?1 AND s.audience=?2 AND s.note=?3 AND s.update_id>?4 ORDER BY s.update_id LIMIT ?5"
            } else {
                "SELECT s.update_id,s.note,length(u.delta),u.delta FROM pending_scope s JOIN note_updates u ON u.id=s.update_id WHERE s.base=?1 AND s.audience=?2 AND s.update_id>?3 ORDER BY s.update_id LIMIT ?4"
            };
            let mut stmt = self.connection.prepare_cached(sql)?;
            let mut rows = if let Some(note) = note {
                stmt.query(params![
                    base.as_slice(),
                    audience.as_slice(),
                    note.as_slice(),
                    after,
                    (limit + 1) as i64
                ])?
            } else {
                stmt.query(params![
                    base.as_slice(),
                    audience.as_slice(),
                    after,
                    (limit + 1) as i64
                ])?
            };
            let mut result = Vec::with_capacity(limit);
            let mut bytes = 0usize;
            let mut more = false;
            while let Some(row) = rows.next()? {
                let id: i64 = row.get(0)?;
                let note: Vec<u8> = row.get(1)?;
                let size: usize = row
                    .get::<_, i64>(2)?
                    .try_into()
                    .map_err(|_| StoreError::InvalidUpdate)?;
                if result.len() == limit
                    || (!result.is_empty() && bytes.saturating_add(size) > max_bytes)
                {
                    more = true;
                    break;
                }
                let delta: Vec<u8> = row.get(3)?;
                let note = note.try_into().map_err(|_| StoreError::InvalidUpdate)?;
                bytes += delta.len();
                result.push(PendingNoteUpdate {
                    update_id: id,
                    key: NoteKey {
                        base,
                        audience,
                        note,
                    },
                    writer: crate::note_writers::pending_writer(&self.connection, id)?,
                    bytes: delta,
                });
            }
            return Ok(PendingPage {
                next: more.then(|| result.last().expect("nonempty indexed page").update_id),
                rows: result,
            });
        }
        // Transition reader scans at most 256 old pending IDs per request,
        // including *empty* scoped pages, until the bounded backfill finishes.
        // New writes are dual-maintained but still visible through this path.
        let mut stmt=self.connection.prepare_cached("SELECT p.update_id,u.base,u.audience,u.note,length(u.delta),u.delta FROM pending_note_work p JOIN note_updates u ON u.id=p.update_id WHERE p.update_id>?1 ORDER BY p.update_id LIMIT 257")?;
        let mut rows = stmt.query([after])?;
        let mut result = Vec::with_capacity(limit);
        let mut bytes = 0usize;
        let mut scanned = 0;
        let mut cursor = after;
        let mut more = false;
        while let Some(row) = rows.next()? {
            if scanned == 256 || result.len() == limit {
                more = true;
                break;
            }
            let id: i64 = row.get(0)?;
            let row_base: Vec<u8> = row.get(1)?;
            let row_audience: Vec<u8> = row.get(2)?;
            let row_note: Vec<u8> = row.get(3)?;
            let matches = row_base == base
                && row_audience == audience
                && note.is_none_or(|note| row_note == note);
            if matches && !result.is_empty() {
                let size: usize = row
                    .get::<_, i64>(4)?
                    .try_into()
                    .map_err(|_| StoreError::InvalidUpdate)?;
                if bytes.saturating_add(size) > max_bytes {
                    more = true;
                    break;
                }
            }
            cursor = id;
            scanned += 1;
            if matches {
                let delta: Vec<u8> = row.get(5)?;
                bytes += delta.len();
                result.push(PendingNoteUpdate {
                    update_id: id,
                    key: NoteKey {
                        base,
                        audience,
                        note: row_note.try_into().map_err(|_| StoreError::InvalidUpdate)?,
                    },
                    writer: crate::note_writers::pending_writer(&self.connection, id)?,
                    bytes: delta,
                });
            }
        }
        Ok(PendingPage {
            rows: result,
            next: more.then_some(cursor),
        })
    }
    /// Convert at most `max_rows` legacy pending references per transaction.
    /// Reads use the compatible keyset fallback until the last step commits.
    pub fn backfill_pending_scope(&mut self, max_rows: usize) -> Result<bool, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (last, complete): (i64, bool) = tx.query_row(
            "SELECT last_id,complete FROM pending_scope_backfill WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if complete {
            return Ok(true);
        }
        let mut stmt=tx.prepare("SELECT p.update_id,u.base,u.audience,u.note FROM pending_note_work p JOIN note_updates u ON u.id=p.update_id WHERE p.update_id>?1 ORDER BY p.update_id LIMIT ?2")?;
        let budget = max_rows.clamp(1, 256);
        let rows = stmt
            .query_map(params![last, budget as i64], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        let mut cursor = last;
        for (id, base, audience, note) in &rows {
            tx.execute("INSERT OR IGNORE INTO pending_scope(update_id,base,audience,note) VALUES (?1,?2,?3,?4)",params![id,base,audience,note])?;
            cursor = *id;
        }
        let done = rows.len() < budget;
        tx.execute(
            "UPDATE pending_scope_backfill SET last_id=?1,complete=?2 WHERE id=1",
            params![cursor, done],
        )?;
        tx.commit()?;
        Ok(done)
    }
    /// Small indexed probe: reaching either threshold requests background
    /// compaction, never blocks a save or refuses an oversized/failing tail.
    pub fn checkpoint_due(&self, key: NoteKey) -> Result<bool, StoreError> {
        let covered:Option<i64>=self.connection.query_row("SELECT local_frontier FROM note_checkpoints WHERE base=?1 AND audience=?2 AND note=?3",params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice()],|r|r.get(0)).optional()?;
        let mut stmt=self.connection.prepare_cached("SELECT length(delta) FROM note_updates WHERE base=?1 AND audience=?2 AND note=?3 AND id>?4 ORDER BY id LIMIT 256")?;
        let rows = stmt.query_map(
            params![
                key.base.as_slice(),
                key.audience.as_slice(),
                key.note.as_slice(),
                covered.unwrap_or(0)
            ],
            |r| r.get::<_, i64>(0),
        )?;
        let mut count = 0;
        let mut bytes = 0usize;
        for row in rows {
            count += 1;
            bytes =
                bytes.saturating_add(usize::try_from(row?).map_err(|_| StoreError::InvalidUpdate)?);
            if count >= 256 || bytes >= 256 * 1024 {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// Capture an immutable local prefix and its generation; later saves never
    /// block on its reconstruction. The caller pages below while writer access
    /// is released between pages, then encodes the finished job outside guards.
    pub fn begin_checkpoint(&self, key: NoteKey) -> Result<Option<CheckpointSeed>, StoreError> {
        let prior:Option<(i64,i64,Vec<u8>)>=self.connection.query_row(
            "SELECT generation,local_frontier,encoded_yjs FROM note_checkpoints WHERE base=?1 AND audience=?2 AND note=?3",
            params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional()?;
        let (generation, covered, encoded) = prior.unwrap_or((0, 0, Vec::new()));
        let target: Option<i64> = self.connection.query_row(
            "SELECT MAX(id) FROM note_updates WHERE base=?1 AND audience=?2 AND note=?3",
            params![
                key.base.as_slice(),
                key.audience.as_slice(),
                key.note.as_slice()
            ],
            |r| r.get(0),
        )?;
        let Some(target) = target.filter(|target| *target > covered) else {
            return Ok(None);
        };
        let anchor = self
            .account_state()?
            .filter(|s| !s.stopped)
            .map(|s| s.anchor);
        Ok(Some(CheckpointSeed {
            key,
            generation,
            covered,
            target,
            anchor,
            encoded,
        }))
    }
    /// Cold open already owns the fully rebuilt Note. Capture the checkpoint
    /// generation/frontier without loading or applying any old projection rows.
    /// The caller supplies that very Note's `ordered` state, made outside locks.
    /// CAS at publication rejects a concurrent checkpoint or authority change.
    pub fn prepare_loaded_checkpoint(
        &self,
        key: NoteKey,
        frontier: i64,
        state: &OrderedState,
    ) -> Result<Option<PreparedCheckpoint>, StoreError> {
        if !self.checkpoint_due(key)? || self.local_frontier(key)? != frontier {
            return Ok(None);
        }
        let previous: Option<(i64, i64)> = self.connection.query_row(
            "SELECT generation,local_frontier FROM note_checkpoints WHERE base=?1 AND audience=?2 AND note=?3",
            params![key.base.as_slice(), key.audience.as_slice(), key.note.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).optional()?;
        let (generation, covered) = previous.unwrap_or((0, 0));
        let anchor = self
            .account_state()?
            .filter(|state| !state.stopped)
            .map(|state| state.anchor);
        Ok(Some(PreparedCheckpoint {
            key,
            generation,
            covered,
            target: frontier,
            anchor,
            encoded: state.encode(),
        }))
    }
    pub fn checkpoint_page(
        &self,
        job: &CheckpointJob,
        max_rows: usize,
    ) -> Result<Vec<(i64, Vec<u8>)>, StoreError> {
        note_page(&self.connection, job.key, job.after, job.target, max_rows)
    }
    /// CAS covers only the captured prefix and its authority, not later note
    /// revisions. Every old update stays in SQLite: receipts, pending work and
    /// retained history are not compacted away by a local read projection.
    pub fn publish_checkpoint(&mut self, job: &PreparedCheckpoint) -> Result<bool, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_anchor: Option<(Vec<u8>, bool)> = tx
            .query_row(
                "SELECT anchor,stopped FROM account_state WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0)),
            )
            .optional()?;
        if current_anchor.as_ref().is_some_and(|(_, stopped)| *stopped)
            || current_anchor.as_ref().map(|(a, _)| a.as_slice())
                != job.anchor.as_ref().map(|a| a.as_slice())
        {
            return Ok(false);
        }
        let previous:Option<(i64,i64)>=tx.query_row("SELECT generation,local_frontier FROM note_checkpoints WHERE base=?1 AND audience=?2 AND note=?3",params![job.key.base.as_slice(),job.key.audience.as_slice(),job.key.note.as_slice()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if previous.unwrap_or((0, 0)) != (job.generation, job.covered) {
            return Ok(false);
        }
        tx.execute("INSERT INTO note_checkpoints(base,audience,note,generation,local_frontier,encoded_yjs) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(base,audience,note) DO UPDATE SET generation=excluded.generation,local_frontier=excluded.local_frontier,encoded_yjs=excluded.encoded_yjs",
            params![job.key.base.as_slice(),job.key.audience.as_slice(),job.key.note.as_slice(),job.generation+1,job.target,job.encoded.as_slice()])?;
        tx.commit()?;
        Ok(true)
    }
    pub fn checkpoint_tail(&self, key: NoteKey) -> Result<(i64, i64), StoreError> {
        let covered:Option<i64>=self.connection.query_row("SELECT local_frontier FROM note_checkpoints WHERE base=?1 AND audience=?2 AND note=?3",params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice()],|r|r.get(0)).optional()?;
        Ok(self.connection.query_row("SELECT COUNT(*),COALESCE(SUM(length(delta)),0) FROM note_updates WHERE base=?1 AND audience=?2 AND note=?3 AND id>?4",params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice(),covered.unwrap_or(0)],|r|Ok((r.get(0)?,r.get(1)?)))?)
    }
}
