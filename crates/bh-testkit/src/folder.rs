//! An in-memory backup folder with controlled write faults.

use bh_core::{
    Account, BackupFolder, BackupLocation, Base, DocumentFolders, FolderEntry, FolderError,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Condvar, Mutex},
};

#[derive(Default)]
struct State {
    files: BTreeMap<String, Vec<u8>>,
    reads: BTreeMap<String, usize>,
    writes: usize,
    remaining: Option<usize>,
    truncate: Option<usize>,
    away: bool,
    permission_lost: bool,
    full: bool,
    away_on_write: Option<String>,
    hanging: bool,
    hang_after: usize,
    waiting_writes: usize,
}

/// A backup folder in memory; clones share the same files and faults.
#[derive(Clone, Default)]
pub struct MemoryFolder {
    inner: Arc<(Mutex<State>, Condvar)>,
}

/// Unblocks pending writes when dropped.
pub struct HangGuard {
    inner: Arc<(Mutex<State>, Condvar)>,
}

impl Drop for HangGuard {
    fn drop(&mut self) {
        let (state, ready) = &*self.inner;
        let mut state = state.lock().unwrap();
        state.hanging = false;
        state.hang_after = 0;
        ready.notify_all();
    }
}

impl MemoryFolder {
    /// Makes writes after the next `n` successful writes fail.
    pub fn fail_writes_after(&self, n: usize) {
        self.inner.0.lock().unwrap().remaining = Some(n);
    }
    /// The next successful write stores only the first `at` bytes.
    pub fn truncate_next_write(&self, at: usize) {
        self.inner.0.lock().unwrap().truncate = Some(at);
    }
    /// Makes every folder operation return `Unreachable`.
    pub fn go_away(&self) {
        self.inner.0.lock().unwrap().away = true;
    }
    /// Makes the folder available again.
    pub fn come_back(&self) {
        self.inner.0.lock().unwrap().away = false;
    }
    /// Disconnects when a write to a path containing `fragment` is attempted.
    pub fn go_away_on_write(&self, fragment: &str) {
        self.inner.0.lock().unwrap().away_on_write = Some(fragment.into());
    }
    /// Makes folder operations fail with a lost permission error.
    pub fn lose_permission(&self) {
        self.inner.0.lock().unwrap().permission_lost = true;
    }
    /// Restores the folder's permission.
    pub fn grant_permission(&self) {
        self.inner.0.lock().unwrap().permission_lost = false;
    }
    /// Makes subsequent writes fail with `Full`.
    pub fn fill_up(&self) {
        self.inner.0.lock().unwrap().full = true;
    }
    /// Clears a simulated full-folder error.
    pub fn make_room(&self) {
        self.inner.0.lock().unwrap().full = false;
    }
    /// Pauses writes until the returned guard is dropped.
    pub fn hang_writes(&self) -> HangGuard {
        let mut state = self.inner.0.lock().unwrap();
        state.hanging = true;
        state.hang_after = 0;
        HangGuard {
            inner: self.inner.clone(),
        }
    }
    /// Pauses writes after `n` successful writes until the guard is dropped.
    pub fn hang_writes_after(&self, n: usize) -> HangGuard {
        let mut state = self.inner.0.lock().unwrap();
        state.hanging = true;
        state.hang_after = n;
        HangGuard {
            inner: self.inner.clone(),
        }
    }
    /// Waits until a writer is blocked by `hang_writes`.
    pub fn wait_for_write(&self) {
        let (state, ready) = &*self.inner;
        let mut state = state.lock().unwrap();
        while state.waiting_writes == 0 {
            state = ready.wait(state).unwrap();
        }
    }
    /// Returns a copy of all files, keyed by relative path.
    pub fn files(&self) -> BTreeMap<String, Vec<u8>> {
        self.inner.0.lock().unwrap().files.clone()
    }
    /// Number of successful file writes.
    pub fn writes(&self) -> usize {
        self.inner.0.lock().unwrap().writes
    }
    /// Number of times a file has been read.
    pub fn reads(&self, path: &str) -> usize {
        self.inner
            .0
            .lock()
            .unwrap()
            .reads
            .get(path)
            .copied()
            .unwrap_or(0)
    }
    /// Inserts a file directly, bypassing simulated write faults.
    pub fn put(&self, path: &str, bytes: &[u8]) {
        self.inner
            .0
            .lock()
            .unwrap()
            .files
            .insert(path.into(), bytes.to_vec());
    }
    /// Removes a file directly, bypassing simulated write faults.
    pub fn remove_file(&self, path: &str) {
        self.inner.0.lock().unwrap().files.remove(path);
    }
}

impl DocumentFolders for MemoryFolder {
    fn open(&self, _uri: &str) -> Result<Arc<dyn BackupFolder>, FolderError> {
        Ok(Arc::new(self.clone()))
    }
}

/// Relative paths of stored files with a given suffix, in sorted order.
pub fn record_paths(folder: &MemoryFolder, suffix: &str) -> Vec<String> {
    folder
        .files()
        .keys()
        .filter(|path| path.ends_with(suffix))
        .cloned()
        .collect()
}

/// A signed-in full device with an ordinary base and a selected in-memory backup folder.
pub async fn backup_device() -> (Account, Base, Arc<MemoryFolder>) {
    let core = crate::device("backup");
    let folder = Arc::new(MemoryFolder::default());
    core.set_document_folders(folder.clone());
    let (account, _) = core.sign_up(crate::new_signup()).await.expect("sign up");
    let base = account.create_base("Personal").await.expect("create base");
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .expect("select backup folder");
    (account, base, folder)
}

fn valid(path: &str, root: bool) -> Result<(), FolderError> {
    if (!root && path.is_empty())
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|c| c == "." || c == ".." || c.is_empty() && !path.is_empty())
    {
        Err(FolderError::Other("invalid backup path".into()))
    } else {
        Ok(())
    }
}

impl BackupFolder for MemoryFolder {
    fn list(&self, dir: &str) -> Result<Vec<FolderEntry>, FolderError> {
        let state = self.inner.0.lock().unwrap();
        if state.away {
            return Err(FolderError::Unreachable);
        }
        if state.permission_lost {
            return Err(FolderError::PermissionLost);
        }
        valid(dir, true)?;
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        let mut entries = BTreeMap::new();
        for (path, bytes) in &state.files {
            if let Some(rest) = path.strip_prefix(&prefix) {
                if let Some((child, _)) = rest.split_once('/') {
                    entries.entry(child.to_owned()).or_insert(FolderEntry {
                        name: child.into(),
                        dir: true,
                        size: 0,
                    });
                } else {
                    entries.insert(
                        rest.to_owned(),
                        FolderEntry {
                            name: rest.into(),
                            dir: false,
                            size: bytes.len() as u64,
                        },
                    );
                }
            }
        }
        Ok(entries.into_values().collect())
    }
    fn read(&self, path: &str) -> Result<Vec<u8>, FolderError> {
        let mut state = self.inner.0.lock().unwrap();
        if state.away {
            return Err(FolderError::Unreachable);
        }
        if state.permission_lost {
            return Err(FolderError::PermissionLost);
        }
        valid(path, false)?;
        let bytes = state
            .files
            .get(path)
            .cloned()
            .ok_or_else(|| FolderError::Other("file not found".into()))?;
        *state.reads.entry(path.into()).or_default() += 1;
        Ok(bytes)
    }
    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), FolderError> {
        let (lock, ready) = &*self.inner;
        let mut state = lock.lock().unwrap();
        if state.away {
            return Err(FolderError::Unreachable);
        }
        if state.permission_lost {
            return Err(FolderError::PermissionLost);
        }
        valid(path, false)?;
        if state
            .away_on_write
            .as_deref()
            .is_some_and(|fragment| path.contains(fragment))
        {
            state.away = true;
            state.away_on_write = None;
            return Err(FolderError::Unreachable);
        }
        if state.hanging && state.hang_after > 0 {
            state.hang_after -= 1;
        } else if state.hanging {
            state.waiting_writes += 1;
            ready.notify_all();
            while state.hanging {
                state = ready.wait(state).unwrap();
            }
            state.waiting_writes -= 1;
        }
        if state.away {
            return Err(FolderError::Unreachable);
        }
        if state.permission_lost {
            return Err(FolderError::PermissionLost);
        }
        if state.full {
            return Err(FolderError::Full);
        }
        if state.remaining == Some(0) {
            return Err(FolderError::Other("simulated write failure".into()));
        }
        if let Some(ref mut remaining) = state.remaining {
            *remaining -= 1;
        }
        let len = state
            .truncate
            .take()
            .unwrap_or(bytes.len())
            .min(bytes.len());
        state.files.insert(path.into(), bytes[..len].to_vec());
        state.writes += 1;
        Ok(())
    }
    fn remove(&self, path: &str) -> Result<(), FolderError> {
        let mut state = self.inner.0.lock().unwrap();
        if state.away {
            return Err(FolderError::Unreachable);
        }
        if state.permission_lost {
            return Err(FolderError::PermissionLost);
        }
        valid(path, false)?;
        state
            .files
            .retain(|key, _| key != path && !key.starts_with(&format!("{path}/")));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_limit_fails_with_other() {
        let folder = MemoryFolder::default();
        folder.fail_writes_after(1);
        folder.write("a", b"ok").unwrap();
        assert!(matches!(
            folder.write("b", b"no"),
            Err(FolderError::Other(_))
        ));
        assert_eq!(folder.read("a").unwrap(), b"ok");
        assert!(
            folder
                .list("")
                .unwrap()
                .iter()
                .all(|entry| entry.name != "b")
        );
    }

    #[test]
    fn truncated_write_reports_success_but_stores_a_prefix() {
        let folder = MemoryFolder::default();
        folder.truncate_next_write(2);
        folder.write("a", b"abc").unwrap();
        assert_eq!(folder.read("a").unwrap(), b"ab");
        folder.write("b", b"xyz").unwrap();
        assert_eq!(folder.read("b").unwrap(), b"xyz");
    }

    #[test]
    fn gone_folder_rejects_every_operation_and_can_return() {
        let folder = MemoryFolder::default();
        folder.go_away();
        assert!(matches!(folder.list(""), Err(FolderError::Unreachable)));
        assert!(matches!(folder.read("a"), Err(FolderError::Unreachable)));
        assert!(matches!(
            folder.write("a", b"x"),
            Err(FolderError::Unreachable)
        ));
        assert!(matches!(folder.remove("a"), Err(FolderError::Unreachable)));
        folder.come_back();
        folder.write("a", b"ok").unwrap();
    }

    #[test]
    fn full_folder_refuses_writes() {
        let folder = MemoryFolder::default();
        folder.fill_up();
        assert!(matches!(folder.write("a", b"x"), Err(FolderError::Full)));
    }

    #[test]
    fn hanging_writes_resume_on_guard_drop() {
        let folder = std::sync::Arc::new(MemoryFolder::default());
        let guard = folder.hang_writes();
        let (tx, rx) = std::sync::mpsc::channel();
        let second = folder.clone();
        let join = std::thread::spawn(move || {
            second.write("a", b"x").unwrap();
            tx.send(()).unwrap();
        });
        folder.wait_for_write();
        assert!(rx.try_recv().is_err());
        drop(guard);
        join.join().unwrap();
        assert_eq!(folder.read("a").unwrap(), b"x");
    }
}
