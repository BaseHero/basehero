//! Two short-lived read-only SQLite connections per file container. Rebuild a
//! note in keyset pages without holding the writer or a long read snapshot.
use crate::{NoteKey, StoreError};
use bh_core::note::Note;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::{
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
    pub(crate) fn new(path: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            path,
            idle: Mutex::new((Vec::new(), 0)),
            available: Condvar::new(),
            replayed_rows: AtomicUsize::new(0),
        })
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
            state: loaded.note.state(),
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
        mut progress: impl FnMut(),
    ) -> Result<LoadedNote, StoreError> {
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
        let mut note = Note::new();
        if !encoded.is_empty() {
            note.apply_update(&encoded)
                .map_err(|_| StoreError::InvalidUpdate)?;
        }
        let mut after = covered;
        let mut count = 0;
        let mut bytes = encoded.len();
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
                note.apply_update(&delta)
                    .map_err(|_| StoreError::InvalidUpdate)?;
                self.replayed_rows.fetch_add(1, Ordering::Relaxed);
                after = id;
                count += 1;
                bytes += delta.len();
            }
            progress();
        }
        Ok(LoadedNote {
            note,
            frontier: target,
            rows: count,
            bytes,
        })
    }
}
