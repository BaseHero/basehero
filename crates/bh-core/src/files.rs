//! Sealed, immutable file parts and their upload and download queues.

use crate::base::Base;
use crate::client::Api;
use crate::envelope::{self, Aad, Purpose};
use crate::store::FileRow;
use crate::{BaseEvent, Error};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bh_crypto::Secret;
use bh_proto::{BaseId, ObjectId};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[cfg(feature = "test-support")]
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, watch};
use ts_rs::TS;
use zeroize::Zeroizing;

/// Maximum file size in bytes (100 MiB).
pub const FILE_MAX: u64 = 104_857_600;
/// Maximum plaintext bytes in a file part (4 MiB).
pub const FILE_PART: usize = 4_194_304;

/// File metadata supplied by the caller; the content is passed separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewFile {
    /// Parent note, folder or project; `None` for a top-level file.
    pub parent: Option<ObjectId>,
    /// Display name, sealed inside the file object.
    pub name: String,
    /// Picked media type, sealed inside the file object; never used to render content.
    pub mime: String,
}

/// Progress derived from local parts and the sealed object's `uploaded` field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum FileStatus {
    /// All parts are stored on this device.
    Here,
    /// This device is uploading its sealed parts.
    Sending {
        /// Parts acknowledged by the server.
        done: u32,
        /// Total number of parts.
        parts: u32,
    },
    /// A full device is fetching the file.
    Fetching {
        /// Parts already saved.
        done: u32,
        /// Total parts.
        parts: u32,
    },
    /// An app device has not fetched the file.
    Remote,
    /// The writer has not finished uploading the file.
    Waiting,
    /// A local part failed to authenticate or could not be fetched.
    Broken,
}

/// A file object's sealed metadata and locally derived availability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct FileInfo {
    /// File object ID.
    #[ts(type = "string")]
    pub id: ObjectId,
    /// Its parent object, if any.
    #[ts(type = "string | null")]
    pub parent: Option<ObjectId>,
    /// Display name.
    pub name: String,
    /// Picked type (not trusted for rendering).
    pub mime: String,
    /// Plaintext byte length.
    #[ts(type = "number")]
    pub size: u64,
    /// Local availability or upload state.
    pub status: FileStatus,
}

/// Raster image bytes with a media type determined only by their signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    /// Sniffed type, never the file's declared type.
    pub mime: String,
    /// Authenticated plaintext bytes.
    pub bytes: Vec<u8>,
}

/// Identify supported raster formats by magic bytes, never by name or declared MIME.
pub fn sniff_image(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

pub(crate) fn parts(size: u64) -> u32 {
    ((size.saturating_add(FILE_PART as u64 - 1) / FILE_PART as u64).max(1)) as u32
}

pub(crate) fn seal_part(
    fk: &Secret<32>,
    base: BaseId,
    id: ObjectId,
    n: u32,
    plain: &[u8],
) -> Vec<u8> {
    let key = bh_crypto::kdf(fk, b"bhfblob1", u64::from(n) + 1);
    envelope::seal(
        &key,
        &Aad {
            purpose: Purpose::FileBlob,
            base: base.0,
            object: id.0,
            epoch: 1,
        },
        plain,
    )
}

#[allow(dead_code, reason = "used by the incoming file queue")]
pub(crate) fn open_part(
    fk: &Secret<32>,
    base: BaseId,
    id: ObjectId,
    n: u32,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let key = bh_crypto::kdf(fk, b"bhfblob1", u64::from(n) + 1);
    envelope::open(
        &key,
        &Aad {
            purpose: Purpose::FileBlob,
            base: base.0,
            object: id.0,
            epoch: 1,
        },
        sealed,
    )
}

/// Known limit: the file key also lives as text among the file object's fields,
/// so ordinary JSON and Yjs copies of it, including summaries returned to callers,
/// aren't wiped from memory when a base closes; only the `Secret` copies are.
pub(crate) fn key_text(fk: &Secret<32>) -> String {
    URL_SAFE_NO_PAD.encode(fk.expose())
}

pub(crate) fn part_root(path: &Path) -> PathBuf {
    path.with_extension("files")
}

/// Remove sealed directories that cannot be reached from the committed files table.
pub(crate) fn cleanup(base: &Base, root: &Path) -> Result<(), Error> {
    if !root.exists() {
        return Ok(());
    }
    let rows = base.db()?.file_rows()?;
    let ids: std::collections::HashSet<_> = rows.into_iter().map(|r| r.id.to_string()).collect();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if !ids.contains(&entry.file_name().to_string_lossy().to_string())
            && entry.file_type()?.is_dir()
        {
            std::fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}

/// One background downloader for a full device. Retries transient failures on
/// the next catch-up; authentication failures are permanently set aside.
pub(crate) struct Downloader {
    wake: Arc<Notify>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    #[cfg(feature = "test-support")]
    pub(crate) probe: Probe,
}

impl Drop for Downloader {
    fn drop(&mut self) {
        // Waiting for a wake must not retain the API after the last base drops.
        let task = self
            .task
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(task) = task {
            task.abort();
        }
    }
}

impl Downloader {
    pub(crate) fn start(base: &Base, api: Api, runtime: &tokio::runtime::Handle) -> Self {
        let wake = Arc::new(Notify::new());
        let owner = base.downgrade();
        let task_wake = wake.clone();
        #[cfg(feature = "test-support")]
        let probe = Probe::default();
        #[cfg(feature = "test-support")]
        probe.alive.store(true, Ordering::SeqCst);
        #[cfg(feature = "test-support")]
        let (task_probe, alive) = (probe.clone(), Alive(probe.alive.clone()));
        let task = runtime.spawn(async move {
            #[cfg(feature = "test-support")]
            let _alive = alive;
            loop {
                let Some(base) = owner.upgrade() else {
                    break;
                };
                let candidates = base
                    .db()
                    .and_then(|db| db.file_candidates())
                    .unwrap_or_default();
                for id in candidates {
                    if base
                        .file(id)
                        .ok()
                        .flatten()
                        .is_some_and(|f| matches!(f.status, FileStatus::Fetching { .. }))
                    {
                        #[cfg(feature = "test-support")]
                        if task_probe.hold.load(Ordering::SeqCst) {
                            task_probe.held.store(true, Ordering::SeqCst);
                            std::future::pending::<()>().await;
                        }
                        let _ = base.download_file(id, &api).await;
                    }
                }
                drop(base);
                task_wake.notified().await;
            }
        });
        Self {
            wake,
            task: Mutex::new(Some(task)),
            #[cfg(feature = "test-support")]
            probe,
        }
    }

    pub(crate) fn changed(&self) {
        self.wake.notify_one();
    }

    pub(crate) async fn stop(&self) {
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }
}

/// One background uploader per open base; it never owns the base between attempts.
pub(crate) struct Uploader {
    wake: Arc<Notify>,
    progress: watch::Sender<Result<(), Error>>,
    stopped: std::sync::atomic::AtomicBool,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    #[cfg(feature = "test-support")]
    paused: Arc<AtomicBool>,
    #[cfg(feature = "test-support")]
    fail_after: Arc<AtomicU32>,
    #[cfg(feature = "test-support")]
    pub(crate) probe: Probe,
}

/// Test-only: holds an upload just before its request, and shows whether the
/// uploader's task still exists.
#[cfg(feature = "test-support")]
#[derive(Clone, Default)]
pub(crate) struct Probe {
    pub(crate) hold: Arc<AtomicBool>,
    pub(crate) held: Arc<AtomicBool>,
    pub(crate) alive: Arc<AtomicBool>,
    pub(crate) idle: Arc<AtomicBool>,
}

/// Clears `Probe::alive` when the task's future is dropped, even unpolled.
#[cfg(feature = "test-support")]
struct Alive(Arc<AtomicBool>);

#[cfg(feature = "test-support")]
impl Drop for Alive {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Drop for Uploader {
    fn drop(&mut self) {
        // Between uploads the task waits for a wake, so it can't notice on its
        // own that the last handle to its base has gone.
        let task = self
            .task
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(task) = task {
            task.abort();
        }
    }
}

impl Uploader {
    pub(crate) fn start(
        base: &Base,
        api: Api,
        runtime: &tokio::runtime::Handle,
        root: PathBuf,
    ) -> Self {
        let wake = Arc::new(Notify::new());
        let (progress, _) = watch::channel(Ok(()));
        let task_progress = progress.clone();
        #[cfg(feature = "test-support")]
        let paused = Arc::new(AtomicBool::new(false));
        #[cfg(feature = "test-support")]
        let fail_after = Arc::new(AtomicU32::new(u32::MAX));
        let owner = base.downgrade();
        let task_wake = wake.clone();
        #[cfg(feature = "test-support")]
        let task_paused = paused.clone();
        #[cfg(feature = "test-support")]
        let task_fail = fail_after.clone();
        #[cfg(feature = "test-support")]
        let probe = Probe::default();
        #[cfg(feature = "test-support")]
        probe.alive.store(true, Ordering::SeqCst);
        #[cfg(feature = "test-support")]
        let (task_probe, alive) = (probe.clone(), Alive(probe.alive.clone()));
        let task = runtime.spawn(async move {
            #[cfg(feature = "test-support")]
            let _alive = alive;
            let mut backoff = Duration::from_millis(500);
            loop {
                #[cfg(feature = "test-support")]
                if task_paused.load(Ordering::SeqCst) { task_wake.notified().await; continue; }
                let Some(base) = owner.upgrade() else { break; };
                let result = upload_next(&base, &api, &root,
                    #[cfg(feature = "test-support")] &task_fail,
                    #[cfg(feature = "test-support")] &task_probe).await;
                drop(base);
                let _ = task_progress.send_replace(result.as_ref().map(|_| ()).map_err(Clone::clone));
                #[cfg(feature = "test-support")]
                task_probe.idle.store(matches!(&result, Ok(false)), Ordering::SeqCst);
                match result {
                    Ok(true) => backoff = Duration::from_millis(500),
                    Ok(false) => task_wake.notified().await,
                    Err(Error::RateLimited) => {
                        // File PUTs share the server's 50-write/s device window
                        // with change POSTs. Retry at that pace rather than
                        // exponentially backing off for a full minute.
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(_) => {
                        tokio::select! { _ = tokio::time::sleep(backoff) => {}, _ = task_wake.notified() => {} }
                        backoff = (backoff * 2).min(Duration::from_secs(30));
                    }
                }
            }
        });
        Self {
            wake,
            progress,
            stopped: std::sync::atomic::AtomicBool::new(false),
            task: Mutex::new(Some(task)),
            #[cfg(feature = "test-support")]
            paused,
            #[cfg(feature = "test-support")]
            fail_after,
            #[cfg(feature = "test-support")]
            probe,
        }
    }

    pub(crate) fn changed(&self) {
        self.wake.notify_one();
    }

    pub(crate) async fn stop(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = self.progress.send_replace(Err(Error::NotFound));
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<Result<(), Error>> {
        self.progress.subscribe()
    }

    pub(crate) fn stopped(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn pause(&self, value: bool) {
        if value {
            self.probe.idle.store(false, Ordering::SeqCst);
        }
        self.paused.store(value, Ordering::SeqCst);
        self.changed();
    }
    #[cfg(feature = "test-support")]
    pub(crate) fn fail_after(&self, count: u32) {
        self.fail_after.store(count, Ordering::SeqCst);
    }
}

async fn upload_next(
    base: &Base,
    api: &Api,
    root: &Path,
    #[cfg(feature = "test-support")] fail_after: &AtomicU32,
    #[cfg(feature = "test-support")] probe: &Probe,
) -> Result<bool, Error> {
    let rows = base.db()?.file_rows()?;
    for row in &rows {
        if row.sent == Some(row.parts)
            && base
                .get(row.id)?
                .is_some_and(|object| object.fields.get("uploaded") != Some(&true.into()))
        {
            base.set_fields(
                row.id,
                serde_json::Map::from_iter([("uploaded".into(), true.into())]),
            )?;
            base.emit(BaseEvent::FilesChanged(vec![row.id]));
            return Ok(true);
        }
    }
    let Some(FileRow {
        id,
        parts,
        sent: Some(n),
        ..
    }) = rows
        .into_iter()
        .find(|row| row.sent.is_some_and(|n| n < row.parts))
    else {
        return Ok(false);
    };
    let bytes = std::fs::read(root.join(id.to_string()).join(n.to_string()))?;
    #[cfg(feature = "test-support")]
    if probe.hold.load(Ordering::SeqCst) {
        probe.held.store(true, Ordering::SeqCst);
        std::future::pending::<()>().await;
    }
    // A lost reply must resend the *same on-disk ciphertext*, including its nonce.
    #[cfg(feature = "test-support")]
    let lost = fail_after.load(Ordering::SeqCst) == 0;
    api.put_file_part(base.id(), id, n, bytes).await?;
    #[cfg(feature = "test-support")]
    if lost {
        fail_after.store(u32::MAX, Ordering::SeqCst);
        return Err(Error::Network("injected lost file reply".into()));
    }
    #[cfg(feature = "test-support")]
    if fail_after.load(Ordering::SeqCst) != u32::MAX {
        fail_after.fetch_sub(1, Ordering::SeqCst);
    }
    base.db()?.file_sent(id, n + 1)?;
    if n + 1 == parts {
        base.set_fields(
            id,
            serde_json::Map::from_iter([("uploaded".into(), true.into())]),
        )?;
    }
    base.emit(BaseEvent::FilesChanged(vec![id]));
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parts_follow_the_size() {
        assert_eq!(
            [0, 1, 4_194_304, 4_194_305, 104_857_600].map(parts),
            [1, 1, 1, 2, 25]
        );
    }
    #[test]
    fn a_part_opens_only_in_its_own_place() {
        let key = Secret::<32>::random();
        let base = BaseId([3; 16]);
        let id = ObjectId([4; 16]);
        let sealed = seal_part(&key, base, id, 0, b"private");
        assert_eq!(&*open_part(&key, base, id, 0, &sealed).unwrap(), b"private");
        for (base, id, n) in [
            (base, id, 1),
            (BaseId([5; 16]), id, 0),
            (base, ObjectId([5; 16]), 0),
        ] {
            assert_eq!(open_part(&key, base, id, n, &sealed), Err(Error::Crypto));
        }
        let other = seal_part(&key, base, id, 1, b"other");
        assert_eq!(open_part(&key, base, id, 0, &other), Err(Error::Crypto));
    }
}
