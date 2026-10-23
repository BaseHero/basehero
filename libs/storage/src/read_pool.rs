//! Two short-lived read-only SQLite connections per file container. Rebuild a
//! note in keyset pages without holding the writer or a long read snapshot.
use crate::{NoteEntry, NoteKey, StoreError, catalogue};
use bh_core::note::{Note, OrderedState};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::{
    fs::File,
    ops::Deref,
    path::PathBuf,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
const MAX_READERS: usize = 2;
pub struct ReadPool {
    path: PathBuf,
    idle: Mutex<(Vec<Connection>, usize)>,
    available: Condvar,
    // A borrowed read pool may outlive the writer; retain the lock until
    // its connections are closed too.
    _lock: Option<Arc<File>>,
    replayed_rows: AtomicUsize,
}
struct Lease<'a> {
    pool: &'a ReadPool,
    conn: Option<Connection>,
}
impl Deref for Lease<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("read lease")
    }
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let mut idle = self.pool.idle.lock().expect("read pool lock");
            idle.0.push(conn);
            self.pool.available.notify_one();
        }
    }
}
pub struct ReadResult {
    pub state: Vec<u8>,
    pub frontier: i64,
    pub rows: usize,
    pub bytes: usize,
}
/// Owned canonical candidate, not a second authoritative DeviceDatabase.
/// The caller owns it exclusively until a scoped durable CAS publishes it.
pub struct LoadedNote {
    pub note: Note,
    pub frontier: i64,
    pub rows: usize,
    pub bytes: usize,
}
impl ReadPool {
    pub(crate) fn new(path: PathBuf, lock: Option<Arc<File>>) -> Arc<Self> {
        Arc::new(Self {
            path,
            idle: Mutex::new((Vec::new(), 0)),
            available: Condvar::new(),
            _lock: lock,
            replayed_rows: AtomicUsize::new(0),
        })
    }
    /// One statement guards epoch/cut and the lookup, without the writer.
    pub fn account_device_seen(
        &self,
        anchor: [u8; 32],
        epoch: u64,
        cut: u64,
        device: &[u8; 32],
    ) -> Result<bool, StoreError> {
        self.account_evidence(anchor, epoch, cut, 0, device)
    }
    pub fn account_key_used(
        &self,
        anchor: [u8; 32],
        epoch: u64,
        cut: u64,
        space: u8,
        key: &[u8; 32],
    ) -> Result<bool, StoreError> {
        self.account_evidence(anchor, epoch, cut, space as u64 + 1, key)
    }
    fn account_evidence(
        &self,
        anchor: [u8; 32],
        epoch: u64,
        cut: u64,
        kind: u64,
        key: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let conn = self.lease()?;
        let (guard, found): (bool,bool) = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM account_projection WHERE id=1 AND anchor=?1 AND epoch=?2 AND through_position>=?3),
            CASE WHEN ?4=0 THEN EXISTS(SELECT 1 FROM account_devices WHERE epoch=?2 AND device=?5 AND added<=?3)
            ELSE EXISTS(SELECT 1 FROM account_key_use WHERE epoch=?2 AND space=?4-1 AND key=?5 AND added<=?3) END",
            params![anchor.as_slice(),crate::account::sql(epoch)?,crate::account::sql(cut)?,crate::account::sql(kind)?,key.as_slice()], |r| Ok((r.get(0)?,r.get(1)?)))?;
        if !guard {
            return Err(StoreError::AuthorityChanged);
        }
        Ok(found)
    }
    pub fn account_event_bytes(
        &self,
        anchor: [u8; 32],
        epoch: u64,
        cut: u64,
        position: u64,
        max_event: usize,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let conn = self.lease()?;
        let (guard, bytes) = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM account_projection WHERE id=1 AND anchor=?1 AND epoch=?2 AND through_position>=?3),
            (SELECT bytes FROM account_events WHERE id=?4 AND id<=?3)",
            params![anchor.as_slice(),crate::account::sql(epoch)?,crate::account::sql(cut)?,crate::account::sql(position)?], |r| {
                let bytes = match r.get_ref(1)? {
                    rusqlite::types::ValueRef::Null => None,
                    _ => Some(crate::account::bounded_blob(r,1,max_event)?),
                };
                Ok((r.get::<_,bool>(0)?,bytes))
            })?;
        if !guard {
            return Err(StoreError::AuthorityChanged);
        }
        if position <= cut && bytes.is_none() {
            return Err(StoreError::CorruptAccount);
        }
        Ok(bytes)
    }
    /// Confirmed bounds at the same anchor, index epoch and cut as the view.
    /// A missing row means legacy/unknown time, not permission to guess one.
    pub fn account_confirmed_time(
        &self,
        anchor: [u8; 32],
        epoch: u64,
        cut: u64,
        position: u64,
    ) -> Result<Option<(u64, u64)>, StoreError> {
        let conn = self.lease()?;
        let (guard, earliest, latest, proof_len): (bool, Option<i64>, Option<i64>, Option<i64>) = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM account_projection WHERE id=1 AND anchor=?1 AND epoch=?2 AND through_position>=?3),
             c.earliest_ms,c.latest_ms,length(c.confirmation)
             FROM (SELECT 1) LEFT JOIN account_confirmations c ON c.position=?4 AND c.position<=?3",
            params![anchor.as_slice(),crate::account::sql(epoch)?,crate::account::sql(cut)?,crate::account::sql(position)?],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        )?;
        if !guard {
            return Err(StoreError::AuthorityChanged);
        }
        match (earliest, latest, proof_len) {
            (None, None, None) => Ok(None),
            (Some(earliest), Some(latest), Some(len))
                if earliest >= 0 && latest >= earliest && len > 0 =>
            {
                Ok(Some((earliest as u64, latest as u64)))
            }
            _ => Err(StoreError::CorruptSecurity),
        }
    }

    /// Run one short typed-data query without holding the writer guard.
    pub fn read_data<T>(
        &self,
        read: impl FnOnce(&Connection) -> Result<T, bh_data::DataError>,
    ) -> Result<T, bh_data::DataError> {
        let conn = self
            .lease()
            .map_err(|e| bh_data::DataError::Sql(e.to_string()))?;
        read(&conn)
    }
    /// Run one short read-only operation without the writer guard.
    pub(crate) fn with_connection<T>(
        &self,
        read: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let conn = self.lease()?;
        read(&conn)
    }
    fn lease(&self) -> Result<Lease<'_>, StoreError> {
        let mut idle = self.idle.lock().expect("read pool lock");
        loop {
            if let Some(conn) = idle.0.pop() {
                return Ok(Lease {
                    pool: self,
                    conn: Some(conn),
                });
            }
            if idle.1 < MAX_READERS {
                idle.1 += 1;
                drop(idle);
                let conn = Connection::open_with_flags(
                    &self.path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                );
                let conn = match conn {
                    Ok(conn) => conn,
                    Err(error) => {
                        self.idle.lock().expect("read pool lock").1 -= 1;
                        self.available.notify_one();
                        return Err(StoreError::Database(error));
                    }
                };
                if let Err(error) = conn.busy_timeout(Duration::from_secs(5)) {
                    self.idle.lock().expect("read pool lock").1 -= 1;
                    self.available.notify_one();
                    return Err(StoreError::Database(error));
                }
                return Ok(Lease {
                    pool: self,
                    conn: Some(conn),
                });
            }
            idle = self.available.wait(idle).expect("read pool wait");
        }
    }
    /// Deterministic local replay-pass probe, not product telemetry. A loaded
    /// checkpoint counts as one apply; this counter counts SQLite tail rows.
    pub fn replayed_rows(&self) -> usize {
        self.replayed_rows.load(Ordering::Relaxed)
    }
    pub fn list_notes(
        &self,
        base: [u8; 32],
        audience: [u8; 32],
        after: Option<(i64, [u8; 32])>,
        limit: usize,
    ) -> Result<Vec<NoteEntry>, StoreError> {
        let conn = self.lease()?;
        catalogue::list(&conn, base, audience, after, limit)
    }
    pub fn note_state(&self, key: NoteKey) -> Result<ReadResult, StoreError> {
        self.note_state_with_progress(key, || {})
    }
    /// Progress is invoked only after a page's lease is dropped. Native
    /// callers may yield/cancel a long legacy reconstruction without holding
    /// either reader transaction or writer mutex while they do so.
    pub fn note_state_with_progress(
        &self,
        key: NoteKey,
        progress: impl FnMut(),
    ) -> Result<ReadResult, StoreError> {
        let loaded = self.load_note_with_progress(key, progress)?;
        Ok(ReadResult {
            state: loaded.note.state()?,
            frontier: loaded.frontier,
            rows: loaded.rows,
            bytes: loaded.bytes,
        })
    }
    pub fn load_note(&self, key: NoteKey) -> Result<LoadedNote, StoreError> {
        self.load_note_with_progress(key, || {})
    }
    pub fn load_note_with_progress(
        &self,
        key: NoteKey,
        progress: impl FnMut(),
    ) -> Result<LoadedNote, StoreError> {
        let mut note = Note::new()?;
        let (frontier, rows, bytes) = self.scan(key, true, progress, |update| {
            note.apply_update(&update).map_err(StoreError::from)
        })?;
        Ok(LoadedNote {
            note,
            frontier,
            rows,
            bytes,
        })
    }
    /// The checkpoint's ordered updates followed by every later row, in the
    /// order a loaded note integrates them, and the frontier they reach.
    /// Only bytes are read; it is not a replay pass.
    pub fn note_ordered(&self, key: NoteKey) -> Result<(OrderedState, i64), StoreError> {
        let mut ordered = OrderedState::default();
        let (frontier, _, _) = self.scan(
            key,
            false,
            || {},
            |update| {
                ordered.push(update);
                Ok(())
            },
        )?;
        Ok((ordered, frontier))
    }
    /// Feed the checkpoint's segments, then each later row, to `apply` in
    /// order. Rows are read in bounded pages, each under its own lease.
    fn scan(
        &self,
        key: NoteKey,
        replay: bool,
        mut progress: impl FnMut(),
        mut apply: impl FnMut(Vec<u8>) -> Result<(), StoreError>,
    ) -> Result<(i64, usize, usize), StoreError> {
        let (covered, encoded, target) = {
            let conn = self.lease()?;
            let (covered,encoded): (i64,Vec<u8>)=conn.query_row(
                "SELECT local_frontier,encoded_yjs FROM note_checkpoints WHERE base=?1 AND audience=?2 AND note=?3",
                params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice()],|r|Ok((r.get(0)?,r.get(1)?)),
            ).optional()?.unwrap_or((0,Vec::new()));
            let target: Option<i64> = conn.query_row(
                "SELECT MAX(id) FROM note_updates WHERE base=?1 AND audience=?2 AND note=?3",
                params![
                    key.base.as_slice(),
                    key.audience.as_slice(),
                    key.note.as_slice()
                ],
                |r| r.get(0),
            )?;
            (covered, encoded, target.unwrap_or(covered))
        };
        let mut bytes = encoded.len();
        let checkpoint = OrderedState::decode(&encoded).map_err(|_| StoreError::InvalidUpdate)?;
        drop(encoded);
        for segment in checkpoint.into_segments() {
            apply(segment)?;
        }
        let mut after = covered;
        let mut count = 0;
        while after < target {
            let page = {
                let conn = self.lease()?;
                let mut stmt=conn.prepare_cached("SELECT id,length(delta),delta FROM note_updates WHERE base=?1 AND audience=?2 AND note=?3 AND id>?4 AND id<=?5 ORDER BY id LIMIT 256")?;
                let mut rows = stmt.query(params![
                    key.base.as_slice(),
                    key.audience.as_slice(),
                    key.note.as_slice(),
                    after,
                    target
                ])?;
                let mut page = Vec::new();
                let mut bytes = 0usize;
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
                page
            };
            if page.is_empty() {
                return Err(StoreError::InvalidUpdate);
            }
            for (id, delta) in page {
                bytes += delta.len();
                apply(delta)?;
                if replay {
                    self.replayed_rows.fetch_add(1, Ordering::Relaxed);
                }
                after = id;
                count += 1;
            }
            progress();
        }
        Ok((target, count, bytes))
    }
}
