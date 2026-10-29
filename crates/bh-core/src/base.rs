//! `Base`: one base's objects, kept in its own encrypted store.

use crate::client::Api;
use crate::envelope::{self, Aad, Purpose};
use crate::files::{
    self, Downloader, FILE_MAX, FILE_PART, FileInfo, FileStatus, Image, NewFile, Uploader,
};
use crate::note::{self, Live, NoteDoc};
use crate::objects::{self, Meta, NewObject, ObjectSummary};
use crate::query::{self, Query};
use crate::search::{self, SearchHit};
use crate::store::{BaseDb, ObjectRow};
use crate::sync::{BaseEvent, Incoming, SyncState, SyncTask};
use crate::types::{self, BASE, FOLDER, NOTE, PROJECT, TYPE, TypeDef, TypeRef};
use crate::versions::VersionTicker;
use crate::{Error, SecretStore};
use bh_crypto::Secret;
use bh_proto::{BaseId, DeviceId, ObjectId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use tokio::sync::broadcast;
use ts_rs::TS;
use yrs::updates::decoder::Decode;
use yrs::{Doc, ReadTxn, StateVector, Transact, TransactionMut, Update};
use zeroize::Zeroizing;

/// The largest local update: sealed, it is the largest change the server takes.
pub(crate) const MAX_UPDATE: usize = (8 << 20) - envelope::OVERHEAD;

/// The key epoch; every base has only its first key.
pub(crate) const EPOCH: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
/// Permission granted to a device for one base. Read-only bases refuse local edits.
pub enum Mode {
    /// May read and write records.
    ReadWrite,
    /// May read records, but writes return [`Error::ReadOnly`].
    ReadOnly,
}

/// A base as `Account::bases` lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct BaseSummary {
    #[ts(type = "string")]
    /// Identifier used to open the base.
    pub id: BaseId,
    /// Name from the base's local information object.
    pub name: String,
    /// This device's access mode.
    pub mode: Mode,
    /// Whether this base is hidden and currently unlocked.
    pub hidden: bool,
    /// Where this base shows in another base, on full devices.
    pub mount: Option<crate::Mount>,
}

/// A base's key, `BK`: 32 random bytes. Never printed.
pub(crate) struct BaseKey(Secret<32>);

impl BaseKey {
    pub(crate) fn new(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(Secret::from_slice(bytes)?))
    }

    pub(crate) fn secret(&self) -> &Secret<32> {
        &self.0
    }
}

impl std::fmt::Debug for BaseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BaseKey(…)")
    }
}

/// One open base. Clones share the store and the open documents.
#[derive(Clone)]
pub struct Base {
    inner: Arc<Inner>,
}

/// A non-owning reference to an open base, used by the account and sync task.
#[derive(Clone)]
pub(crate) struct BaseWeak(Weak<Inner>);

pub(crate) struct OpenStore(Option<BaseDb>);
impl std::ops::Deref for OpenStore {
    type Target = BaseDb;
    fn deref(&self) -> &BaseDb {
        self.0.as_ref().expect("closed store")
    }
}
impl std::ops::DerefMut for OpenStore {
    fn deref_mut(&mut self) -> &mut BaseDb {
        self.0.as_mut().expect("closed store")
    }
}
struct KeyGuard<'a>(MutexGuard<'a, Option<BaseKey>>);
impl std::ops::Deref for KeyGuard<'_> {
    type Target = BaseKey;
    fn deref(&self) -> &BaseKey {
        self.0.as_ref().expect("closed key")
    }
}
fn closed_receiver<T: Clone>() -> broadcast::Receiver<T> {
    let (sender, receiver) = broadcast::channel(1);
    drop(sender);
    receiver
}

impl BaseWeak {
    pub(crate) fn upgrade(&self) -> Option<Base> {
        self.0.upgrade().map(|inner| Base { inner })
    }

    pub(crate) fn is_same(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.0, &other.0)
    }
}

struct Inner {
    id: BaseId,
    mode: Mode,
    device: Option<DeviceId>,
    full: std::sync::atomic::AtomicBool,
    key: Mutex<Option<BaseKey>>,
    /// The yrs client ID of this process's core edits, used only under the
    /// store lock against the stored state, so its clock never repeats.
    client: u64,
    db: Mutex<OpenStore>,
    parts_root: std::path::PathBuf,
    /// Absent only for standalone test-kit bases.
    removal: OnceLock<Arc<AtomicU8>>,
    /// Open documents, one per object; always lock `db` first.
    live: Mutex<HashMap<ObjectId, Weak<Live>>>,
    events: Mutex<Option<broadcast::Sender<BaseEvent>>>,
    closed: std::sync::atomic::AtomicBool,
    /// The sync task, for a base that has a server.
    sync: OnceLock<SyncTask>,
    uploader: OnceLock<Uploader>,
    versions: OnceLock<VersionTicker>,
    version_clock: OnceLock<crate::Clock>,
    version_tick_lock: tokio::sync::Mutex<()>,
    downloader: OnceLock<Downloader>,
    file_api: OnceLock<Api>,
    version_device_name: OnceLock<Arc<dyn Fn(DeviceId) -> Option<String> + Send + Sync>>,
    download_lock: tokio::sync::Mutex<()>,
    downloads_stopped: std::sync::atomic::AtomicBool,
    /// The server signed this device out: local edits stay queued, never sent.
    sync_stopped: std::sync::atomic::AtomicBool,
    download_stop: tokio::sync::watch::Sender<bool>,
    #[cfg(feature = "test-support")]
    held_on_demand_get: Mutex<Option<std::sync::Arc<std::sync::atomic::AtomicBool>>>,
    #[cfg(feature = "test-support")]
    held_upload_wait: Mutex<Option<(Arc<std::sync::atomic::AtomicBool>, Arc<tokio::sync::Notify>)>>,
    #[cfg(feature = "test-support")]
    held_version_fetch:
        Mutex<Option<(Arc<std::sync::atomic::AtomicBool>, Arc<tokio::sync::Notify>)>>,
    #[cfg(feature = "test-support")]
    fail_next_save: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for Base {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Base")
            .field("id", &self.inner.id)
            .field("mode", &self.inner.mode)
            .finish_non_exhaustive()
    }
}

fn decode_file_key(encoded: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, encoded)
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// An object that fetched changes changed, and the updates that applied.
struct Applied {
    id: ObjectId,
    live: Option<Arc<Live>>,
    updates: Vec<Vec<u8>>,
}

/// Types that the tree, `move_to` and `delete` leave alone.
pub(crate) fn structural(name: &str) -> bool {
    matches!(name, TYPE | BASE)
}

impl Base {
    /// Opens a base's store at `path` with its key `base.<id>.dbkey` from
    /// `secrets`, made on first use.
    pub(crate) fn open(
        path: &Path,
        secrets: &dyn SecretStore,
        id: BaseId,
        key: BaseKey,
        mode: Mode,
        device: Option<DeviceId>,
        removal: Option<Arc<AtomicU8>>,
    ) -> Result<Base, Error> {
        if removal
            .as_ref()
            .is_some_and(|r| r.load(Ordering::SeqCst) != 0)
        {
            return Err(Error::Revoked);
        }
        let name = format!("base.{id}.dbkey");
        let db_key = match secrets.get(&name)? {
            Some(key) => key,
            None => {
                let key = Zeroizing::new(bh_crypto::random::<32>().to_vec());
                secrets.put(&name, &key)?;
                key
            }
        };
        let base = Self::open_store(path, &db_key, id, key, mode, device)?;
        if let Some(removal) = removal {
            base.inner.removal.set(removal).ok();
        }
        Ok(base)
    }

    pub(crate) fn open_store(
        path: &Path,
        db_key: &[u8],
        id: BaseId,
        key: BaseKey,
        mode: Mode,
        device: Option<DeviceId>,
    ) -> Result<Base, Error> {
        let db = BaseDb::open(path, db_key)?;
        let base = Base {
            inner: Arc::new(Inner {
                id,
                mode,
                device,
                full: std::sync::atomic::AtomicBool::new(true),
                key: Mutex::new(Some(key)),
                client: u64::from(u32::from_le_bytes(bh_crypto::random::<4>())),
                db: Mutex::new(OpenStore(Some(db))),
                parts_root: files::part_root(path),
                removal: OnceLock::new(),
                live: Mutex::new(HashMap::new()),
                events: Mutex::new(Some(broadcast::channel(256).0)),
                closed: std::sync::atomic::AtomicBool::new(false),
                sync: OnceLock::new(),
                uploader: OnceLock::new(),
                versions: OnceLock::new(),
                version_clock: OnceLock::new(),
                version_tick_lock: tokio::sync::Mutex::new(()),
                downloader: OnceLock::new(),
                file_api: OnceLock::new(),
                version_device_name: OnceLock::new(),
                download_lock: tokio::sync::Mutex::new(()),
                downloads_stopped: std::sync::atomic::AtomicBool::new(false),
                sync_stopped: std::sync::atomic::AtomicBool::new(false),
                download_stop: tokio::sync::watch::channel(false).0,
                #[cfg(feature = "test-support")]
                held_on_demand_get: Mutex::new(None),
                #[cfg(feature = "test-support")]
                held_upload_wait: Mutex::new(None),
                #[cfg(feature = "test-support")]
                held_version_fetch: Mutex::new(None),
                #[cfg(feature = "test-support")]
                fail_next_save: Default::default(),
            }),
        };
        if base.db()?.needs_search_backfill() {
            let mut db = base.db()?;
            db.migrate_search(|db| {
                for (id, state) in db.objects_for_backfill()? {
                    let doc = base.load(&state)?;
                    let txn = doc.transact();
                    let meta = objects::read_meta(&txn)?;
                    let fields = objects::read_fields(&txn);
                    let title = base.title(db, &meta.ty, &txn, &fields);
                    let body = base.search_text(db, &meta.ty, &txn, &fields);
                    db.put_search(id, &title, &body)?;
                }
                Ok(())
            })?;
        }
        files::cleanup(&base, &base.inner.parts_root)?;
        Ok(base)
    }

    /// Test kit only: a read-write base with a store in `dir` and no server.
    /// `key` is the base key; the base's ID and store key derive from it, so
    /// the same directory and key open the same base again.
    #[cfg(feature = "test-support")]
    pub fn open_local(dir: &Path, key: [u8; 32]) -> Result<Base, Error> {
        let key = BaseKey::new(&key)?;
        let hash = bh_crypto::generichash(Some(key.secret().expose()), &[b"bh.test.local-base"]);
        let id = BaseId(hash[..16].try_into().expect("16 bytes"));
        let db_key = bh_crypto::kdf(key.secret(), b"bhtestdb", 1);
        let path = dir.join(format!("{id}.sqlite"));
        Self::open_store(&path, db_key.expose(), id, key, Mode::ReadWrite, None)
    }

    pub(crate) fn set_full(&self, full: bool) {
        self.inner.full.store(full, Ordering::SeqCst);
    }

    pub(crate) fn set_removal(&self, removal: Arc<AtomicU8>) {
        self.inner.removal.set(removal).ok();
    }

    /// Ends background work, closes the encrypted store, and wipes the base key
    /// even if callers still hold cloned handles.
    pub(crate) async fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        self.stop_sync().await;
        let _downloads = self.inner.download_lock.lock().await;
        let mut db = crate::store::in_use(&self.inner.db);
        for weak in lock(&self.inner.live).drain().map(|(_, weak)| weak) {
            if let Some(live) = weak.upgrade() {
                live.close();
            }
        }
        self.inner.events.lock().unwrap().take();
        self.inner.key.lock().unwrap().take();
        db.0.take();
    }

    fn key(&self) -> KeyGuard<'_> {
        KeyGuard(lock(&self.inner.key))
    }

    pub(crate) fn downgrade(&self) -> BaseWeak {
        BaseWeak(Arc::downgrade(&self.inner))
    }

    /// This base's stable identifier.
    pub fn id(&self) -> BaseId {
        self.inner.id
    }

    /// The name in the base's `core.base` object, empty until it arrives.
    pub fn name(&self) -> String {
        self.get(ObjectId(self.inner.id.0))
            .ok()
            .flatten()
            .map(|s| s.title)
            .unwrap_or_default()
    }

    /// Access mode granted to this device.
    pub fn mode(&self) -> Mode {
        self.inner.mode
    }

    pub(crate) fn db(&self) -> Result<crate::store::InUse<'_, OpenStore>, Error> {
        let db = crate::store::in_use(&self.inner.db);
        if db.0.is_none() {
            Err(Error::NotFound)
        } else {
            Ok(db)
        }
    }

    /// Adds a file locally, sealing each part with its own positional key and
    /// persisting every sealed byte before queuing upload. No network is needed.
    ///
    /// # Errors
    /// Returns [`Error::TooLarge`] before writing for content over 100 MiB,
    /// [`Error::ReadOnly`] or [`Error::Revoked`] when writes are blocked,
    /// [`Error::NotFound`] for a missing parent, [`Error::Invalid`] for an
    /// invalid parent, or [`Error::Storage`] if local persistence fails.
    pub fn add_file(&self, new: NewFile, content: &[u8]) -> Result<ObjectId, Error> {
        if content.len() as u64 > FILE_MAX {
            return Err(Error::TooLarge);
        }
        self.writable()?;
        let mut db = self.db()?;
        if let Some(parent) = new.parent {
            let s = db.summary(parent)?.ok_or(Error::NotFound)?;
            if s.deleted || !matches!(s.ty.name.as_str(), NOTE | FOLDER | PROJECT) {
                return Err(Error::invalid(
                    "file parent must be a note, folder or project",
                ));
            }
        }
        let id = ObjectId::random();
        let fk = Secret::<32>::random();
        let count = self.write_parts(id, &fk, content)?;
        let result = (|| -> Result<(), Error> {
            let fields = Map::from_iter([
                ("name".into(), Value::from(new.name)),
                ("mime".into(), Value::from(new.mime)),
                ("size".into(), Value::from(content.len() as u64)),
                ("key".into(), Value::from(files::key_text(&fk))),
            ]);
            let position = self.place(&db, None, new.parent, None, true)?;
            db.batch(|db| {
                self.insert(
                    db,
                    id,
                    &TypeRef::new(types::FILE, 1),
                    new.parent,
                    &position,
                    &fields,
                )?;
                db.put_file(id, count, false)
            })?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_dir_all(self.inner.parts_root.join(id.to_string()));
        }
        drop(db);
        result?;
        self.emit(BaseEvent::FilesChanged(vec![id]));
        if let Some(uploader) = self.inner.uploader.get() {
            uploader.changed();
        }
        Ok(id)
    }

    /// Seals `content`'s parts for this base under the file key `fk` and puts
    /// them in place for `id`, replacing any there. Returns how many there are.
    fn write_parts(&self, id: ObjectId, fk: &Secret<32>, content: &[u8]) -> Result<u32, Error> {
        let count = files::parts(content.len() as u64);
        let root = &self.inner.parts_root;
        std::fs::create_dir_all(root)?;
        let tmp = root.join(format!("{id}.tmp"));
        let dir = root.join(id.to_string());
        std::fs::create_dir(&tmp)?;
        let result = (|| -> Result<(), Error> {
            for n in 0..count {
                let start = n as usize * FILE_PART;
                let end = content.len().min(start + FILE_PART);
                std::fs::write(
                    tmp.join(n.to_string()),
                    files::seal_part(fk, self.id(), id, n, &content[start..end]),
                )?;
            }
            if dir.exists() {
                std::fs::remove_dir_all(&dir)?;
            }
            std::fs::rename(&tmp, &dir)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_dir_all(&tmp);
        }
        result.map(|()| count)
    }

    /// Seals a moved file's content for this base, with its own file key, and
    /// records its parts: to be sent, unless this base's earlier copy says the
    /// server already has them. Parts already here whole are kept.
    pub(crate) fn add_file_parts(
        &self,
        id: ObjectId,
        key: &Secret<32>,
        content: &[u8],
    ) -> Result<(), Error> {
        if content.len() as u64 > FILE_MAX {
            return Err(Error::TooLarge);
        }
        self.writable()?;
        let db = self.db()?;
        if db
            .file_row(id)?
            .is_some_and(|row| row.have == row.parts && row.broken.is_none())
        {
            return Ok(());
        }
        let uploaded = db
            .summary(id)?
            .is_some_and(|s| s.fields.get("uploaded") == Some(&Value::Bool(true)));
        let count = self.write_parts(id, key, content)?;
        db.put_file(id, count, uploaded)?;
        drop(db);
        self.emit(BaseEvent::FilesChanged(vec![id]));
        if let Some(uploader) = self.inner.uploader.get() {
            uploader.changed();
        }
        Ok(())
    }

    /// The key a file's parts are sealed with, from its object.
    pub(crate) fn file_key(&self, id: ObjectId) -> Result<Secret<32>, Error> {
        let object = self.get(id)?.ok_or(Error::NotFound)?;
        let encoded = object
            .fields
            .get("key")
            .and_then(Value::as_str)
            .ok_or(Error::NeedsUpdate)?;
        Secret::<32>::from_slice(&decode_file_key(encoded)?).map_err(|_| Error::Crypto)
    }

    /// The local metadata and availability of a file, or `None` for another
    /// type or an unknown ID. No network is needed.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] for a closed base, [`Error::NeedsUpdate`]
    /// for a newer format, or [`Error::Storage`] for unreadable local data.
    pub fn file(&self, id: ObjectId) -> Result<Option<FileInfo>, Error> {
        let Some(summary) = self.get(id)? else {
            return Ok(None);
        };
        if summary.ty.name != types::FILE {
            return Ok(None);
        }
        let fields = &summary.fields;
        let size = fields
            .get("size")
            .and_then(Value::as_u64)
            .ok_or(Error::NeedsUpdate)?;
        let name = fields
            .get("name")
            .and_then(Value::as_str)
            .ok_or(Error::NeedsUpdate)?
            .to_owned();
        let mime = fields
            .get("mime")
            .and_then(Value::as_str)
            .ok_or(Error::NeedsUpdate)?
            .to_owned();
        if size > FILE_MAX {
            return Err(Error::Crypto);
        }
        let count = files::parts(size);
        let row = self.db()?.file_row(id)?;
        let status = match row {
            Some(ref row) if row.sent.is_some_and(|sent| sent < count) => FileStatus::Sending {
                done: row.sent.unwrap(),
                parts: count,
            },
            Some(ref row) if row.have == count => FileStatus::Here,
            Some(ref row) if row.broken.is_some() => FileStatus::Broken,
            _ if fields.get("uploaded") != Some(&Value::Bool(true)) => FileStatus::Waiting,
            _ if self.inner.full.load(Ordering::SeqCst) => FileStatus::Fetching {
                done: row.map_or(0, |r| r.have),
                parts: count,
            },
            _ => FileStatus::Remote,
        };
        Ok(Some(FileInfo {
            id,
            parent: summary.parent,
            name,
            mime,
            size,
            status,
        }))
    }

    pub(crate) fn version_now(&self) -> i64 {
        // Before start_sync installs the injected clock, edits use wall time.
        // Tests using ManualClock should start sync before making local edits.
        self.inner
            .version_clock
            .get()
            .map_or_else(now_ms, crate::Clock::edit_time_ms)
    }

    pub(crate) fn version_tick_lock(&self) -> &tokio::sync::Mutex<()> {
        &self.inner.version_tick_lock
    }

    pub(crate) fn version_sync(&self) -> Option<&SyncTask> {
        self.inner.sync.get()
    }

    pub(crate) fn version_api(&self) -> Result<&Api, Error> {
        self.check_removal()?;
        self.inner
            .file_api
            .get()
            .ok_or_else(|| Error::Network("base is offline".into()))
    }

    pub(crate) fn set_version_device_name(
        &self,
        lookup: impl Fn(DeviceId) -> Option<String> + Send + Sync + 'static,
    ) {
        self.inner.version_device_name.set(Arc::new(lookup)).ok();
    }

    pub(crate) fn version_device_name(&self, device: DeviceId) -> Option<String> {
        self.inner.version_device_name.get()?.as_ref()(device)
    }

    pub(crate) fn version_writable(&self, id: ObjectId) -> Result<(), Error> {
        self.writable()?;
        let db = self.db()?;
        if db.needs_update(id)? {
            return Err(Error::NeedsUpdate);
        }
        let (ty, _) = db.state(id)?.ok_or(Error::NotFound)?;
        self.editable(&db, &ty)?;
        if !matches!(ty.name.as_str(), NOTE | FOLDER | PROJECT) {
            return Err(Error::invalid("not a note, folder or project"));
        }
        Ok(())
    }

    pub(crate) fn restore_content(&self, id: ObjectId, version: &Doc) -> Result<(), Error> {
        self.edit_with_origin(id, u64::MAX, |_, _, _, txn| {
            crate::versions::copy_content(txn, version)
        })
    }

    pub(crate) fn current_version_content_matches(
        &self,
        id: ObjectId,
        version: &Doc,
    ) -> Result<bool, Error> {
        let db = self.db()?;
        let (_, state) = db.state(id)?.ok_or(Error::NotFound)?;
        let current = self.load(&state)?;
        Ok(crate::versions::same_content(&current, version))
    }

    pub(crate) fn open_version_body(&self, id: ObjectId, body: &[u8]) -> Result<Doc, Error> {
        let _db = self.db()?;
        let opened = self.open_change(id, true, body)?;
        self.load(&opened).map_err(|_| Error::Crypto)
    }

    /// In tests, holds a fetched version before it is opened or the current content is kept.
    #[cfg(feature = "test-support")]
    pub fn test_hold_version_fetch(&self) -> Arc<std::sync::atomic::AtomicBool> {
        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *lock(&self.inner.held_version_fetch) =
            Some((entered.clone(), Arc::new(tokio::sync::Notify::new())));
        entered
    }

    /// Releases a version held by `test_hold_version_fetch`.
    #[cfg(feature = "test-support")]
    pub fn test_resume_version_fetch(&self) {
        if let Some((_, notify)) = lock(&self.inner.held_version_fetch).take() {
            notify.notify_one();
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) async fn test_wait_version_fetch(&self) {
        let held = lock(&self.inner.held_version_fetch).clone();
        if let Some((entered, notify)) = held {
            let notified = notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            entered.store(true, Ordering::SeqCst);
            notified.await;
        }
    }

    /// Opens a kept state's sealed body for tests of content and object binding.
    #[cfg(feature = "test-support")]
    pub fn test_open_kept_state(&self, id: ObjectId, body: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.open_change(id, true, body)?.to_vec())
    }

    /// Holds the next background version check until the base stops it.
    #[cfg(feature = "test-support")]
    pub fn test_hold_version_tick(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.inner.versions.get().expect("version task").hold_next()
    }

    /// Download missing parts, authenticating each and checking the expected
    /// plaintext length before it becomes part of the local sealed copy.
    pub(crate) async fn download_file(&self, id: ObjectId, api: &Api) -> Result<(), Error> {
        let mut stop = self.inner.download_stop.subscribe();
        let _guard = self.inner.download_lock.lock().await;
        if *stop.borrow() {
            return Err(Error::NotFound);
        }
        let info = self.file(id)?.ok_or(Error::NotFound)?;
        match info.status {
            FileStatus::Here => return Ok(()),
            FileStatus::Broken => return Err(Error::Crypto),
            FileStatus::Waiting | FileStatus::Sending { .. } => return Err(Error::NotFound),
            _ => {}
        }
        let object = self.get(id)?.ok_or(Error::NotFound)?;
        let encoded = object
            .fields
            .get("key")
            .and_then(Value::as_str)
            .ok_or(Error::NeedsUpdate)?;
        let decoded = decode_file_key(encoded)?;
        let fk = Secret::<32>::from_slice(&decoded).map_err(|_| Error::Crypto)?;
        let count = files::parts(info.size);
        if info.size > FILE_MAX {
            return Err(Error::Crypto);
        }
        let root = self.inner.parts_root.join(id.to_string());
        std::fs::create_dir_all(&root)?;
        let have = self.db()?.file_row(id)?.map_or(0, |row| row.have);
        // A crash can leave bytes ahead of the SQL progress record. Never trust
        // either: authenticate persisted parts again on every read or resume.
        for n in 0..count {
            let expected =
                (info.size - u64::from(n) * FILE_PART as u64).min(FILE_PART as u64) as usize;
            if n < have {
                let plain = std::fs::read(root.join(n.to_string()))
                    .map_err(|_| Error::Crypto)
                    .and_then(|bytes| files::open_part(&fk, self.id(), id, n, &bytes));
                if !plain.as_ref().is_ok_and(|part| part.len() == expected) {
                    self.db()?.file_broken(id, count)?;
                    self.emit(BaseEvent::FilesChanged(vec![id]));
                    return Err(Error::Crypto);
                }
                continue;
            }
            let get = async {
                #[cfg(feature = "test-support")]
                {
                    let held = { lock(&self.inner.held_on_demand_get).take() };
                    if let Some(held) = held {
                        held.store(true, Ordering::SeqCst);
                        std::future::pending::<()>().await;
                    }
                }
                api.get_file_part(self.id(), id, n).await
            };
            let sealed = tokio::select! {
                biased;
                _ = stop.changed() => return Err(Error::NotFound),
                result = get => result?,
            };
            let plain = match files::open_part(&fk, self.id(), id, n, &sealed) {
                Ok(plain) if plain.len() == expected => plain,
                _ => {
                    self.db()?.file_broken(id, count)?;
                    self.emit(BaseEvent::FilesChanged(vec![id]));
                    return Err(Error::Crypto);
                }
            };
            drop(plain);
            let tmp = root.join(format!("{n}.tmp"));
            std::fs::write(&tmp, sealed)?;
            std::fs::rename(tmp, root.join(n.to_string()))?;
            self.db()?.file_received(id, count, n + 1)?;
            self.emit(BaseEvent::FilesChanged(vec![id]));
        }
        Ok(())
    }

    /// Return a file's plaintext only after all its sealed parts authenticate.
    /// Missing parts are fetched and retained on both full and app devices.
    /// The returned buffer belongs to the caller, who must wipe it when finished.
    pub async fn file_bytes(&self, id: ObjectId) -> Result<Vec<u8>, Error> {
        let mut bytes = self.file_bytes_owned(id).await?;
        Ok(std::mem::take(&mut *bytes))
    }

    async fn file_bytes_owned(&self, id: ObjectId) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.inner.downloads_stopped.load(Ordering::SeqCst) {
            return Err(Error::NotFound);
        }
        let info = self.file(id)?.ok_or(Error::NotFound)?;
        match info.status {
            FileStatus::Broken => return Err(Error::Crypto),
            FileStatus::Waiting => return Err(Error::NotFound),
            FileStatus::Sending { .. }
                if self
                    .db()?
                    .file_row(id)?
                    .is_none_or(|row| row.have != row.parts) =>
            {
                return Err(Error::NotFound);
            }
            FileStatus::Here | FileStatus::Sending { .. } => {}
            _ => {
                self.download_file(id, self.inner.file_api.get().ok_or(Error::NotFound)?)
                    .await?
            }
        }
        let _guard = self.inner.download_lock.lock().await;
        if self.inner.downloads_stopped.load(Ordering::SeqCst) {
            return Err(Error::NotFound);
        }
        let object = self.get(id)?.ok_or(Error::NotFound)?;
        let encoded = object
            .fields
            .get("key")
            .and_then(Value::as_str)
            .ok_or(Error::NeedsUpdate)?;
        let decoded = decode_file_key(encoded)?;
        let fk = Secret::<32>::from_slice(&decoded).map_err(|_| Error::Crypto)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(info.size as usize));
        for n in 0..files::parts(info.size) {
            let expected =
                (info.size - u64::from(n) * FILE_PART as u64).min(FILE_PART as u64) as usize;
            let part = std::fs::read(
                self.inner
                    .parts_root
                    .join(id.to_string())
                    .join(n.to_string()),
            )
            .map_err(|_| Error::Crypto)
            .and_then(|sealed| files::open_part(&fk, self.id(), id, n, &sealed));
            if !part.as_ref().is_ok_and(|part| part.len() == expected) {
                self.db()?.file_broken(id, files::parts(info.size))?;
                self.emit(BaseEvent::FilesChanged(vec![id]));
                return Err(Error::Crypto);
            }
            bytes.extend_from_slice(&part.expect("checked above"));
        }
        Ok(bytes)
    }

    /// Read an authenticated file as an image only when its magic bytes name a supported raster type.
    /// The returned image bytes belong to the caller, who must wipe them when finished.
    pub async fn image(&self, id: ObjectId) -> Result<Image, Error> {
        let mut bytes = self.file_bytes_owned(id).await?;
        let mime = files::sniff_image(&bytes).ok_or_else(|| Error::invalid("not an image"))?;
        Ok(Image {
            mime: mime.into(),
            bytes: std::mem::take(&mut *bytes),
        })
    }

    /// Atomically write an authenticated file to the requested path.
    /// Callers opening hidden-base copies must remove those copies on lock.
    pub async fn save_file(&self, id: ObjectId, dest: &Path) -> Result<(), Error> {
        let bytes = self.file_bytes_owned(id).await?;
        let parent = dest
            .parent()
            .ok_or_else(|| Error::invalid("destination has no parent"))?;
        let tmp = parent.join(format!(".{}.tmp", ObjectId::random()));
        let result = (|| -> Result<(), Error> {
            std::fs::write(&tmp, &bytes)?;
            std::fs::rename(&tmp, dest)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    pub(crate) fn files_caught_up(&self) {
        if let Some(downloader) = self.inner.downloader.get() {
            downloader.changed();
        }
    }

    /// After the server signed this device out: a base opened since has no sync
    /// task, but isn't local-only, so it must not report its outbox as sent.
    pub(crate) fn set_sync_stopped(&self) {
        self.inner.sync_stopped.store(true, Ordering::SeqCst);
    }

    fn check_sync_stopped(&self) -> Result<(), Error> {
        if self.inner.sync_stopped.load(Ordering::SeqCst) {
            Err(Error::Network("sync has stopped".into()))
        } else {
            Ok(())
        }
    }

    /// Stops sync, upload and download tasks before account erasure or base close.
    pub(crate) async fn stop_sync(&self) {
        self.inner.downloads_stopped.store(true, Ordering::SeqCst);
        self.inner.download_stop.send_replace(true);
        if let Some(versions) = self.inner.versions.get() {
            versions.stop().await;
        }
        if let Some(sync) = self.inner.sync.get() {
            sync.stop().await;
        }
        if let Some(uploader) = self.inner.uploader.get() {
            uploader.stop().await;
        }
        if let Some(downloader) = self.inner.downloader.get() {
            downloader.stop().await;
        }
        let _downloads = self.inner.download_lock.lock().await;
    }

    /// Starts the base's sync task with the account's client.
    pub(crate) fn start_sync(
        &self,
        api: Api,
        runtime: &tokio::runtime::Handle,
        clock: crate::Clock,
    ) {
        self.inner.file_api.get_or_init(|| api.clone());
        if self.inner.full.load(Ordering::SeqCst) {
            self.inner
                .downloader
                .get_or_init(|| Downloader::start(self, api.clone(), runtime));
        }
        self.inner.uploader.get_or_init(|| {
            Uploader::start(self, api.clone(), runtime, self.inner.parts_root.clone())
        });
        self.inner.version_clock.get_or_init(|| clock.clone());
        self.inner
            .sync
            .get_or_init(|| SyncTask::start(self.clone(), api, runtime, clock.clone()));
        self.inner
            .versions
            .get_or_init(|| VersionTicker::start(self.downgrade(), clock, runtime));
    }

    /// Current local outbox size and last successful catch-up, without a network call.
    pub fn sync_state(&self) -> SyncState {
        if self.check_removal().is_err() {
            return SyncState {
                pending: 0,
                online: false,
                last_synced_at: None,
            };
        }
        let (online, last_synced_at) = self
            .inner
            .sync
            .get()
            .map_or((false, None), SyncTask::status);
        SyncState {
            pending: self.db().ok().and_then(|db| db.pending().ok()).unwrap_or(0),
            online,
            last_synced_at,
        }
    }

    /// Subscribes to object and sync changes. Keep the receiver alive while
    /// refreshing a view; a lagged receiver must reload from the base.
    /// No network call is made by subscribing.
    ///
    /// ```no_run
    /// use bh_core::{Base, BaseEvent};
    /// async fn watch(base: &Base) {
    ///     let mut events = base.events();
    ///     while let Ok(event) = events.recv().await {
    ///         if let BaseEvent::ObjectsChanged(ids) = event {
    ///             for id in ids { let _ = base.get(id); }
    ///         }
    ///     }
    /// }
    /// ```
    pub fn events(&self) -> broadcast::Receiver<BaseEvent> {
        self.inner
            .events
            .lock()
            .unwrap()
            .as_ref()
            .map_or_else(closed_receiver, |events| events.subscribe())
    }

    pub(crate) fn emit(&self, event: BaseEvent) {
        // No subscribers is fine.
        if let Some(events) = self.inner.events.lock().unwrap().as_ref() {
            let _ = events.send(event);
        }
    }

    /// Sends the outbox now and waits until the server has it. A base
    /// without a server has nothing to send. Needs the network when online.
    ///
    /// # Errors
    /// Returns [`Error::Network`] if sending fails, [`Error::Revoked`] if the
    /// device was removed, or server errors such as [`Error::TooLarge`].
    pub async fn flush(&self) -> Result<(), Error> {
        self.check_removal()?;
        self.check_sync_stopped()?;
        match self.inner.sync.get() {
            Some(sync) => sync.flush().await,
            None => Ok(()),
        }
    }

    /// Waits for every queued part in this base to reach the server. An upload
    /// failure leaves the queue in place for a later attempt.
    pub(crate) async fn wait_for_file_uploads(&self) -> Result<(), Error> {
        self.check_removal()?;
        let uploader = self.inner.uploader.get();
        let mut progress = uploader.map(Uploader::subscribe);
        loop {
            // Mark progress seen before inspecting the queue. Any completion after
            // this point remains visible to changed() if the snapshot was pending.
            if let Some(receiver) = progress.as_mut() {
                receiver.borrow_and_update().clone()?;
            }
            let rows = self.db()?.file_rows()?;
            let mut pending = false;
            for row in rows {
                if row.sent.is_some_and(|sent| sent < row.parts)
                    || (row.sent == Some(row.parts)
                        && self.get(row.id)?.is_some_and(|object| {
                            object.fields.get("uploaded") != Some(&Value::Bool(true))
                        }))
                {
                    pending = true;
                    break;
                }
            }
            if !pending {
                return Ok(());
            }
            let Some(uploader) = uploader else {
                return Err(Error::Network("base is offline".into()));
            };
            if uploader.stopped() {
                return Err(Error::NotFound);
            }
            #[cfg(feature = "test-support")]
            let held = { lock(&self.inner.held_upload_wait).clone() };
            #[cfg(feature = "test-support")]
            if let Some((entered, notify)) = held {
                let notified = notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                entered.store(true, Ordering::SeqCst);
                notified.await;
            }
            let receiver = progress.as_mut().expect("uploader has a receiver");
            receiver.changed().await.map_err(|_| Error::NotFound)?;
            self.check_removal()?;
        }
    }

    /// Sends pending edits and catches up with the server once before returning.
    /// A local-only base has nothing to synchronize.
    ///
    /// # Errors
    /// Returns [`Error::Network`] when unreachable, or [`Error::Revoked`] when removed.
    pub async fn sync_now(&self) -> Result<(), Error> {
        self.check_removal()?;
        self.check_sync_stopped()?;
        match self.inner.sync.get() {
            Some(sync) => sync.sync_now().await,
            None => Ok(()),
        }
    }

    /// After a local edit is stored: tells listeners and the sync task.
    fn edited(&self, id: ObjectId) {
        self.emit(BaseEvent::ObjectsChanged(vec![id]));
        if let Some(sync) = self.inner.sync.get() {
            sync.changed();
        }
    }

    /// Asks the sync task to catch up with the server.
    pub(crate) fn catch_up(&self) {
        if let Some(sync) = self.inner.sync.get() {
            sync.catch_up();
        }
    }

    /// The associated data of a change to `id`: an update or a whole state.
    fn change_aad(&self, id: ObjectId, state: bool) -> Aad {
        Aad {
            purpose: if state {
                Purpose::ObjectState
            } else {
                Purpose::ObjectUpdate
            },
            base: self.inner.id.0,
            object: id.0,
            epoch: EPOCH,
        }
    }

    /// `CK = kdf(BK, "bhcntnt1", epoch)`, which seals changes.
    fn content_key(&self) -> Secret<32> {
        bh_crypto::kdf(self.key().secret(), b"bhcntnt1", EPOCH.into())
    }

    pub(crate) fn seal_change(&self, id: ObjectId, state: bool, update: &[u8]) -> Vec<u8> {
        envelope::seal(&self.content_key(), &self.change_aad(id, state), update)
    }

    fn open_change(
        &self,
        id: ObjectId,
        state: bool,
        body: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        envelope::open(&self.content_key(), &self.change_aad(id, state), body)
    }

    fn writable(&self) -> Result<(), Error> {
        self.check_removal()?;
        match self.inner.mode {
            Mode::ReadWrite => Ok(()),
            Mode::ReadOnly => Err(Error::ReadOnly),
        }
    }

    /// The definition objects of `ty` are checked against, if this device has it.
    fn def(&self, db: &BaseDb, ty: &TypeRef) -> Result<Option<TypeDef>, Error> {
        if types::is_core(&ty.name) {
            return Ok(types::core_def(ty));
        }
        let id = types::type_object_id(&self.key(), &ty.name, ty.version);
        Ok(db
            .summary(id)?
            .and_then(|s| serde_json::from_value::<TypeDef>(s.fields.get("def")?.clone()).ok())
            .filter(|d| d.name == ty.name && d.version == ty.version))
    }

    /// Local edits require a definition; fetched records may precede theirs.
    fn editable(&self, db: &BaseDb, ty: &TypeRef) -> Result<TypeDef, Error> {
        self.def(db, ty)?.ok_or(Error::NeedsUpdate)
    }

    /// An unknown app type can arrive before its definition. Only a version
    /// beyond a definition already held by this device needs a newer core.
    fn newer_type(&self, db: &BaseDb, ty: &TypeRef) -> Result<bool, Error> {
        if self.def(db, ty)?.is_some() {
            return Ok(false);
        }
        if types::is_core(&ty.name) {
            return Ok(true);
        }
        Ok(db.of_type(TYPE)?.iter().filter(|s| !s.deleted).any(|s| {
            s.fields
                .get("def")
                .and_then(|d| serde_json::from_value::<TypeDef>(d.clone()).ok())
                .is_some_and(|d| d.name == ty.name && d.version < ty.version)
        }))
    }

    /// A newer or undecodable type must not be rewritten by compaction.
    pub(crate) fn newer_type_for_compaction(
        &self,
        db: &BaseDb,
        ty: &TypeRef,
    ) -> Result<bool, Error> {
        self.newer_type(db, ty)
    }

    fn load(&self, state: &[u8]) -> Result<Doc, Error> {
        let unreadable = |_| Error::Storage("unreadable object state".into());
        let doc = Doc::with_client_id(self.inner.client);
        let update = Update::decode_v1(state).map_err(unreadable)?;
        doc.transact_mut()
            .apply_update(update)
            .map_err(|_| Error::Storage("unreadable object state".into()))?;
        Ok(doc)
    }

    fn title<T: ReadTxn>(
        &self,
        db: &BaseDb,
        ty: &TypeRef,
        txn: &T,
        fields: &Map<String, Value>,
    ) -> String {
        match ty.name.as_str() {
            NOTE => note::body_title(txn),
            TYPE => note::name_title(fields.get("def").and_then(|d| d.get("name"))),
            _ => self
                .def(db, ty)
                .ok()
                .flatten()
                .and_then(|d| d.title_field)
                .map(|f| note::name_title(fields.get(&f)))
                .unwrap_or_default(),
        }
    }

    fn search_text<T: ReadTxn>(
        &self,
        db: &BaseDb,
        ty: &TypeRef,
        txn: &T,
        fields: &Map<String, Value>,
    ) -> String {
        let mut text = if matches!(ty.name.as_str(), NOTE | FOLDER | PROJECT) {
            note::body_text(txn)
        } else {
            String::new()
        };
        if let Ok(Some(def)) = self.def(db, ty) {
            for field in def
                .fields
                .iter()
                .filter(|f| f.kind == types::FieldKind::Text)
            {
                if let Some(value) = fields.get(&field.name).and_then(Value::as_str) {
                    text.push('\n');
                    text.push_str(value);
                }
            }
        }
        text
    }

    fn check_closed(&self) -> Result<(), Error> {
        if self.inner.closed.load(Ordering::SeqCst) {
            Err(Error::NotFound)
        } else {
            Ok(())
        }
    }

    fn check_removal(&self) -> Result<(), Error> {
        if self
            .inner
            .removal
            .get()
            .is_some_and(|r| r.load(Ordering::SeqCst) != 0)
        {
            return Err(Error::Revoked);
        }
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Stores `doc` and its summary and, for local edits, their updates in
    /// the outbox, in one transaction.
    fn save(
        &self,
        db: &mut BaseDb,
        id: ObjectId,
        doc: &Doc,
        outbox: &[&[u8]],
        by: Option<DeviceId>,
        confirmed: Option<u64>,
    ) -> Result<(), Error> {
        self.check_removal()?;
        #[cfg(feature = "test-support")]
        if self
            .inner
            .fail_next_save
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(Error::Storage("injected save failure".into()));
        }
        let txn = doc.transact();
        let Meta {
            ty,
            parent,
            position,
            deleted,
            moved,
        } = objects::read_meta(&txn)?;
        let fields = objects::read_fields(&txn);
        let title = self.title(db, &ty, &txn, &fields);
        let search_text = self.search_text(db, &ty, &txn, &fields);
        let mut reindex = false;
        if ty.name == TYPE {
            let def: TypeDef = serde_json::from_value(
                fields
                    .get("def")
                    .cloned()
                    .ok_or_else(|| Error::invalid("missing definition"))?,
            )
            .map_err(|_| Error::invalid("invalid definition"))?;
            types::check_def(&def)?;
            if types::type_object_id(&self.key(), &def.name, def.version) != id {
                return Err(Error::invalid("definition ID does not match"));
            }
            if let Some(old) = db.summary(id)? {
                let old_def: TypeDef = serde_json::from_value(
                    old.fields.get("def").cloned().ok_or(Error::NeedsUpdate)?,
                )
                .map_err(|_| Error::NeedsUpdate)?;
                types::check_redefinition(&old_def, &def)?;
                reindex = old_def.title_field != def.title_field
                    || old_def
                        .fields
                        .iter()
                        .map(|f| (&f.name, f.kind))
                        .collect::<Vec<_>>()
                        != def
                            .fields
                            .iter()
                            .map(|f| (&f.name, f.kind))
                            .collect::<Vec<_>>();
            } else {
                reindex = true;
            }
        }
        let state = txn.encode_state_as_update_v1(&StateVector::default());
        drop(txn);
        let summary = ObjectSummary {
            id,
            ty,
            parent,
            position,
            deleted,
            title,
            fields,
            updated_at: now_ms(),
            updated_by: by,
        };
        let row = ObjectRow {
            summary,
            state,
            moved: moved.is_some(),
        };
        db.batch(|db| {
            db.put(&row, outbox, confirmed)?;
            if !outbox.is_empty() {
                db.record_local_edit(id, self.version_now())?;
            }
            db.put_search(id, &row.summary.title, &search_text)?;
            if reindex {
                let def: TypeDef = serde_json::from_value(row.summary.fields["def"].clone())
                    .expect("validated definition");
                // Records may arrive before their definition. Recompute both
                // their titles and searchable Text fields when it arrives.
                for record in db.of_type(&def.name)? {
                    if record.ty.version != def.version {
                        continue;
                    }
                    let Some((_, state)) = db.state(record.id)? else {
                        continue;
                    };
                    let doc = self.load(&state)?;
                    let txn = doc.transact();
                    let title = self.title(db, &record.ty, &txn, &record.fields);
                    let body = self.search_text(db, &record.ty, &txn, &record.fields);
                    db.put_title(record.id, &title)?;
                    db.put_search(record.id, &title, &body)?;
                }
            }
            Ok(())
        })
    }

    fn live(&self, id: ObjectId) -> Option<Arc<Live>> {
        lock(&self.inner.live).get(&id).and_then(Weak::upgrade)
    }

    /// Gives a stored update to the object's open document, if any.
    fn share_with_origin(&self, id: ObjectId, origin: u64, update: &[u8]) {
        if let Some(live) = self.live(id) {
            if let Ok(decoded) = Update::decode_v1(update) {
                let _ = live
                    .doc
                    .lock()
                    .unwrap()
                    .transact_mut()
                    .apply_update(decoded);
            }
            live.publish(origin, update);
        }
    }

    /// A core edit of an existing object: on a copy of its stored state, then
    /// stored with its update in the outbox and given to its open document.
    fn edit_in(
        &self,
        db: &mut BaseDb,
        id: ObjectId,
        origin: u64,
        edit: impl FnOnce(&BaseDb, &Meta, &TypeDef, &mut TransactionMut) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.writable()?;
        if db.needs_update(id)? {
            return Err(Error::NeedsUpdate);
        }
        let (ty, state) = db.state(id)?.ok_or(Error::NotFound)?;
        let def = self.editable(db, &ty)?;
        let doc = self.load(&state)?;
        let update = {
            let mut txn = doc.transact_mut();
            let meta = objects::read_meta(&txn)?;
            edit(db, &meta, &def, &mut txn)?;
            txn.encode_update_v1()
        };
        if update.len() > MAX_UPDATE {
            return Err(Error::TooLarge);
        }
        self.save(db, id, &doc, &[&update], self.inner.device, None)?;
        self.share_with_origin(id, origin, &update);
        self.edited(id);
        Ok(())
    }

    fn edit(
        &self,
        id: ObjectId,
        edit: impl FnOnce(&BaseDb, &Meta, &TypeDef, &mut TransactionMut) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.edit_with_origin(id, 0, edit)
    }

    fn edit_with_origin(
        &self,
        id: ObjectId,
        origin: u64,
        edit: impl FnOnce(&BaseDb, &Meta, &TypeDef, &mut TransactionMut) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.edit_in(&mut **self.db()?, id, origin, edit)
    }

    /// Writes a new object.
    fn insert(
        &self,
        db: &mut BaseDb,
        id: ObjectId,
        ty: &TypeRef,
        parent: Option<ObjectId>,
        position: &str,
        fields: &Map<String, Value>,
    ) -> Result<(), Error> {
        let doc = Doc::with_client_id(self.inner.client);
        let update = {
            let mut txn = doc.transact_mut();
            objects::write_type(&mut txn, ty);
            objects::write_place(&mut txn, parent, position);
            objects::write_deleted(&mut txn, false);
            objects::write_fields(&mut txn, fields)?;
            txn.encode_update_v1()
        };
        if update.len() > MAX_UPDATE {
            return Err(Error::TooLarge);
        }
        self.save(db, id, &doc, &[&update], self.inner.device, None)?;
        self.edited(id);
        Ok(())
    }

    /// Writes the base's own `core.base` object, which holds its name.
    pub(crate) fn write_info(&self, name: &str) -> Result<(), Error> {
        let fields = Map::from_iter([("name".to_string(), Value::from(name))]);
        let position = objects::position_between(None, None);
        self.insert(
            &mut **self.db()?,
            ObjectId(self.inner.id.0),
            &TypeRef::new(BASE, 1),
            None,
            &position,
            &fields,
        )
    }

    /// Sets the name in the base's `core.base` object, writing the object if
    /// it hasn't arrived here.
    pub(crate) fn set_name(&self, name: &str) -> Result<(), Error> {
        let fields = Map::from_iter([("name".to_string(), Value::from(name))]);
        match self.edit(ObjectId(self.inner.id.0), |_, _, _, txn| {
            objects::write_fields(txn, &fields)
        }) {
            Err(Error::NotFound) => self.write_info(name),
            result => result,
        }
    }

    /// A position under `parent` for `moving` (if it's already there): after
    /// `after`, or else last or first.
    fn place(
        &self,
        db: &BaseDb,
        moving: Option<ObjectId>,
        parent: Option<ObjectId>,
        after: Option<ObjectId>,
        last: bool,
    ) -> Result<String, Error> {
        let siblings: Vec<_> = db
            .siblings(parent)?
            .into_iter()
            .filter(|(id, _)| Some(*id) != moving)
            .collect();
        let at = |i: usize| siblings.get(i).map(|(_, p)| p.as_str());
        Ok(match after {
            Some(after) => {
                let i = siblings
                    .iter()
                    .position(|(id, _)| *id == after)
                    .ok_or_else(|| Error::invalid("`after` must be another child of the parent"))?;
                objects::position_between(at(i), at(i + 1))
            }
            None if last => {
                objects::position_between(siblings.last().map(|(_, p)| p.as_str()), None)
            }
            None => objects::position_between(None, at(0)),
        })
    }

    fn shown_parent(&self, db: &BaseDb, id: ObjectId) -> Result<Option<ObjectId>, Error> {
        objects::effective_parent(id, |n| db.parent_of(n))
    }

    /// Writes a readable, unencrypted copy to a new or empty directory.
    /// Files that are unavailable are reported in the summary; other failures
    /// remove the partial copy before returning.
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] for an unsafe or nonempty directory, or
    /// [`Error::Storage`] when the local store cannot be read.
    pub async fn export(&self, dir: &Path) -> Result<crate::ExportSummary, Error> {
        crate::export::run(&[(self.clone(), None)], dir).await
    }

    pub(crate) fn export_objects(&self) -> Result<Vec<ObjectSummary>, Error> {
        self.check_closed()?;
        let ids: Vec<ObjectId> = {
            let db = self.db()?;
            db.summaries(
                &format!(
                    "SELECT {} FROM objects WHERE deleted < 2 ORDER BY position, object_id",
                    crate::store::SUMMARY
                ),
                [],
            )?
            .into_iter()
            .map(|row| row.id)
            .collect()
        };
        ids.into_iter()
            .map(|id| self.get(id)?.ok_or(Error::NotFound))
            .collect()
    }

    /// An object, deleted or not, with the parent it shows under.
    ///
    /// # Errors
    /// Returns [`Error::NeedsUpdate`] for an unsupported version or
    /// [`Error::Storage`] if local data cannot be read.
    pub fn get(&self, id: ObjectId) -> Result<Option<ObjectSummary>, Error> {
        self.check_closed()?;
        let db = self.db()?;
        if db.needs_update(id)? {
            return Err(Error::NeedsUpdate);
        }
        let Some(mut summary) = db.summary(id)? else {
            return Ok(None);
        };
        if self.newer_type(&db, &summary.ty)? {
            return Err(Error::NeedsUpdate);
        }
        summary.parent = self.shown_parent(&db, id)?;
        Ok(Some(summary))
    }

    /// The objects shown under `parent` (`None` for the top level), in order,
    /// without deleted objects or type definitions.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] for an unknown parent or [`Error::Storage`]
    /// if the local store cannot be read.
    pub fn children(&self, parent: Option<ObjectId>) -> Result<Vec<ObjectSummary>, Error> {
        self.check_closed()?;
        let db = self.db()?;
        let Some(folder) = parent else {
            let mut out = db.top_level()?;
            for id in objects::cycle_minimums(&db.parents()?) {
                if let Some(s) = db.summary(id)?
                    && !s.deleted
                    && !structural(&s.ty.name)
                {
                    out.push(s);
                }
            }
            for s in &mut out {
                s.parent = None;
            }
            out.sort_by(|a, b| (&a.position, a.id).cmp(&(&b.position, b.id)));
            return Ok(out);
        };
        if db.parent_of(folder)?.is_none() {
            return Err(Error::NotFound);
        }
        // Only an ancestor of the folder can be in a cycle with it.
        let mut ancestors = HashSet::new();
        let mut node = db.parent_of(folder)?.flatten();
        while let Some(n) = node
            && ancestors.insert(n)
        {
            node = db.parent_of(n)?.flatten();
        }
        let mut out = Vec::new();
        for child in db.children(folder)? {
            if !ancestors.contains(&child.id) || self.shown_parent(&db, child.id)? == parent {
                out.push(child);
            }
        }
        Ok(out)
    }

    /// Creates an object, checking its fields against its type. Without
    /// `after`, it goes last under its parent.
    ///
    /// # Errors
    /// Returns [`Error::ReadOnly`] or [`Error::Revoked`] when writes are blocked,
    /// [`Error::Invalid`] for unknown types or invalid fields, [`Error::NotFound`]
    /// for an unknown parent/sibling, [`Error::NeedsUpdate`] for an unknown
    /// version, [`Error::TooLarge`] for an oversized update, or [`Error::Storage`]
    /// if writing the local store fails.
    pub fn create(&self, new: NewObject) -> Result<ObjectId, Error> {
        self.writable()?;
        if structural(&new.ty.name) {
            return Err(Error::invalid("type definitions are made with define_type"));
        }
        let mut db = self.db()?;
        let def = self
            .def(&db, &new.ty)?
            .ok_or_else(|| Error::invalid("unknown type"))?;
        let fields: Map<String, Value> = new
            .fields
            .into_iter()
            .filter(|(_, v)| !v.is_null())
            .collect();
        types::validate(&def, &fields)?;
        if let Some(parent) = new.parent
            && db.parent_of(parent)?.is_none()
        {
            return Err(Error::NotFound);
        }
        let position = self.place(&db, None, new.parent, new.after, true)?;
        let id = ObjectId::random();
        self.insert(&mut db, id, &new.ty, new.parent, &position, &fields)?;
        Ok(id)
    }

    /// Sets each field, checked against the object's type; `null` removes one.
    ///
    /// # Errors
    /// Returns [`Error::ReadOnly`], [`Error::Revoked`], [`Error::NotFound`],
    /// [`Error::NeedsUpdate`], [`Error::Invalid`], [`Error::TooLarge`] or
    /// [`Error::Storage`] for a blocked, missing, unsupported, invalid, oversized
    /// or unwritable local edit respectively.
    pub fn set_fields(&self, id: ObjectId, fields: Map<String, Value>) -> Result<(), Error> {
        self.edit(id, |_, meta, def, txn| {
            if meta.ty.name == TYPE {
                return Err(Error::invalid("type definitions change with define_type"));
            }
            let mut merged = objects::read_fields(txn);
            for (key, value) in &fields {
                match value {
                    Value::Null => merged.remove(key),
                    value => merged.insert(key.clone(), value.clone()),
                };
            }
            types::validate(def, &merged)?;
            objects::write_fields(txn, &fields)
        })
    }

    /// Moves an object under `parent` (`None` for the top level), after the
    /// sibling `after`, or first without it. A move into the object itself or
    /// one of its descendants is refused.
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] for an invalid move, [`Error::NotFound`] for
    /// missing objects, and [`Error::ReadOnly`], [`Error::Revoked`],
    /// [`Error::NeedsUpdate`], [`Error::TooLarge`] or [`Error::Storage`] when
    /// editing cannot be completed.
    pub fn move_to(
        &self,
        id: ObjectId,
        parent: Option<ObjectId>,
        after: Option<ObjectId>,
    ) -> Result<(), Error> {
        self.edit(id, |db, meta, _, txn| {
            if structural(&meta.ty.name) {
                return Err(Error::invalid("this object has no place in the tree"));
            }
            if let Some(parent) = parent {
                db.parent_of(parent)?.ok_or(Error::NotFound)?;
                let (mut seen, mut node) = (HashSet::new(), Some(parent));
                while let Some(n) = node
                    && seen.insert(n)
                {
                    if n == id {
                        return Err(Error::invalid("an object can't move into itself"));
                    }
                    node = db.parent_of(n)?.flatten();
                }
            }
            let position = self.place(db, Some(id), parent, after, false)?;
            objects::write_place(txn, parent, &position);
            Ok(())
        })
    }

    fn set_deleted(&self, id: ObjectId, deleted: bool) -> Result<(), Error> {
        self.edit(id, |_, meta, _, txn| {
            if structural(&meta.ty.name) {
                return Err(Error::invalid("this object can't be deleted"));
            }
            objects::write_deleted(txn, deleted);
            Ok(())
        })
    }

    /// Moves an object to the trash: it leaves `children` and shows in `trash`.
    ///
    /// # Errors
    /// Returns [`Error::ReadOnly`], [`Error::Revoked`], [`Error::NotFound`],
    /// [`Error::Invalid`], [`Error::NeedsUpdate`], [`Error::TooLarge`] or
    /// [`Error::Storage`] if the local edit cannot be completed.
    pub fn delete(&self, id: ObjectId) -> Result<(), Error> {
        self.set_deleted(id, true)
    }

    /// Restores an object from the trash.
    ///
    /// # Errors
    /// Returns the same variants as [`Self::delete`].
    pub fn undelete(&self, id: ObjectId) -> Result<(), Error> {
        self.set_deleted(id, false)
    }

    /// `root`, then its descendants, parents before children, deleted ones
    /// included and type definitions and the base's own object left out.
    pub(crate) fn subtree(&self, root: ObjectId) -> Result<Vec<ObjectId>, Error> {
        let db = self.db()?;
        let ty = db.type_of(root)?.ok_or(Error::NotFound)?;
        if structural(&ty.name) {
            return Ok(Vec::new());
        }
        let (mut out, mut seen, mut next) = (vec![root], HashSet::from([root]), 0);
        while let Some(&id) = out.get(next) {
            for (child, _) in db.siblings(Some(id))? {
                if seen.insert(child) {
                    out.push(child);
                }
            }
            next += 1;
        }
        Ok(out)
    }

    /// The base this copy of `id` moved to, if it's a marker left behind.
    pub(crate) fn moved_to(&self, id: ObjectId) -> Result<Option<BaseId>, Error> {
        let db = self.db()?;
        let Some((_, state)) = db.state(id)? else {
            return Ok(None);
        };
        Ok(objects::read_meta(&self.load(&state)?.transact())?.moved)
    }

    /// A position after the last of `parent`'s children.
    pub(crate) fn last_position(&self, parent: Option<ObjectId>) -> Result<String, Error> {
        self.place(&**self.db()?, None, parent, None, true)
    }

    /// Writes an object moved here from another base: `state` applied to this
    /// base's copy (new, or the marker it left here before), at `place` (a
    /// parent and position) or else where `state` puts it, deleted as `state`
    /// says, no longer a marker. A file's `uploaded` is this base's earlier
    /// copy's, as it tells whether the server has this base's parts. Returns
    /// `false`, writing nothing, when this base already has it otherwise.
    pub(crate) fn import(
        &self,
        id: ObjectId,
        state: &[u8],
        place: Option<(Option<ObjectId>, &str)>,
    ) -> Result<bool, Error> {
        self.writable()?;
        let unreadable = || Error::invalid("not an object state");
        let incoming = Update::decode_v1(state).map_err(|_| unreadable())?;
        let deleted = objects::read_meta(&self.load(state)?.transact())?.deleted;
        let mut db = self.db()?;
        let (doc, uploaded) = match db.state(id)? {
            Some((_, stored)) => {
                let doc = self.load(&stored)?;
                if objects::read_meta(&doc.transact())?.moved.is_none() {
                    return Ok(false);
                }
                let uploaded = objects::read_fields(&doc.transact()).remove("uploaded");
                (doc, uploaded)
            }
            None => (Doc::with_client_id(self.inner.client), None),
        };
        let before = doc.transact().state_vector();
        let file = {
            let mut txn = doc.transact_mut();
            txn.apply_update(incoming).map_err(|_| unreadable())?;
            let file = objects::read_meta(&txn)?.ty.name == types::FILE;
            if let Some((parent, position)) = place {
                objects::write_place(&mut txn, parent, position);
            }
            objects::write_deleted(&mut txn, deleted);
            objects::write_moved(&mut txn, None);
            if file {
                let uploaded = uploaded.unwrap_or(Value::Null);
                objects::write_fields(&mut txn, &Map::from_iter([("uploaded".into(), uploaded)]))?;
            }
            file
        };
        let update = doc.transact().encode_state_as_update_v1(&before);
        if update.len() > MAX_UPDATE {
            return Err(Error::TooLarge);
        }
        self.save(&mut db, id, &doc, &[&update], self.inner.device, None)?;
        drop(db);
        self.share_with_origin(id, 0, &update);
        self.edited(id);
        if file {
            // Parts sent before the object arrived still need it marked uploaded.
            self.emit(BaseEvent::FilesChanged(vec![id]));
            if let Some(uploader) = self.inner.uploader.get() {
                uploader.changed();
            }
        }
        Ok(true)
    }

    /// Leaves a deleted marker of `id` naming the base it moved to.
    pub(crate) fn mark_moved(&self, id: ObjectId, to: BaseId) -> Result<(), Error> {
        self.edit(id, |_, meta, _, txn| {
            if structural(&meta.ty.name) {
                return Err(Error::invalid("this object can't move"));
            }
            objects::write_deleted(txn, true);
            objects::write_moved(txn, Some(to));
            Ok(())
        })
    }

    /// Deleted objects, the most recently changed first.
    ///
    /// # Errors
    /// Returns [`Error::Storage`] if the local store cannot be read.
    pub fn trash(&self) -> Result<Vec<ObjectSummary>, Error> {
        self.check_closed()?;
        let db = self.db()?;
        let mut out = db.trash()?;
        for s in &mut out {
            s.parent = self.shown_parent(&db, s.id)?;
        }
        Ok(out)
    }

    /// The document of a note, folder or project: one per object in this
    /// process, shared by every caller.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] for a missing object, [`Error::Invalid`]
    /// for a non-document, [`Error::NeedsUpdate`] for an unsupported type, or
    /// [`Error::Storage`] for unreadable local data.
    pub fn note(&self, id: ObjectId) -> Result<NoteDoc, Error> {
        self.check_closed()?;
        let db = self.db()?;
        if db.needs_update(id)? {
            return Err(Error::NeedsUpdate);
        }
        let mut live = lock(&self.inner.live);
        if let Some(open) = live.get(&id).and_then(Weak::upgrade) {
            return Ok(NoteDoc::new(self.clone(), open));
        }
        let (ty, state) = db.state(id)?.ok_or(Error::NotFound)?;
        self.editable(&db, &ty)?;
        if !matches!(ty.name.as_str(), NOTE | FOLDER | PROJECT) {
            return Err(Error::invalid("not a note, folder or project"));
        }
        let open = Arc::new(Live::new(id, ty.name, self.load(&state)?));
        live.retain(|_, w| w.strong_count() > 0);
        live.insert(id, Arc::downgrade(&open));
        Ok(NoteDoc::new(self.clone(), open))
    }

    /// `NoteDoc::apply`: a local edit to an open document.
    pub(crate) fn apply_local(&self, live: &Live, origin: u64, update: &[u8]) -> Result<(), Error> {
        self.writable()?;
        if update.len() > MAX_UPDATE {
            return Err(Error::TooLarge);
        }
        let decoded = Update::decode_v1(update).map_err(|_| Error::invalid("not a Yjs update"))?;
        let mut db = self.db()?;
        if db.needs_update(live.id)? {
            return Err(Error::NeedsUpdate);
        }
        let ty = db.type_of(live.id)?.ok_or(Error::NotFound)?;
        self.editable(&db, &ty)?;
        live.doc
            .lock()
            .unwrap()
            .transact_mut()
            .apply_update(decoded)
            .map_err(|_| Error::invalid("the update doesn't apply"))?;
        let mut unsaved = lock(&live.unsaved);
        unsaved.push(update.to_vec());
        let outbox: Vec<&[u8]> = unsaved.iter().map(Vec::as_slice).collect();
        self.save(
            &mut db,
            live.id,
            &live.doc.lock().unwrap(),
            &outbox,
            self.inner.device,
            None,
        )?;
        unsaved.clear();
        drop((unsaved, db));
        live.publish(origin, update);
        self.edited(live.id);
        Ok(())
    }

    /// Applies another device's update: whatever the object's version,
    /// without the outbox.
    #[cfg(feature = "test-support")]
    fn apply_remote(&self, id: ObjectId, update: &[u8], by: Option<DeviceId>) -> Result<(), Error> {
        let decoded = Update::decode_v1(update).map_err(|_| Error::invalid("not a Yjs update"))?;
        let mut db = self.db()?;
        let live = self.live(id);
        let doc = match (&live, db.state(id)?) {
            (Some(live), _) => live.doc.lock().unwrap().clone(),
            (None, Some((_, state))) => self.load(&state)?,
            (None, None) => Doc::with_client_id(self.inner.client),
        };
        doc.transact_mut()
            .apply_update(decoded)
            .map_err(|_| Error::invalid("the update doesn't apply"))?;
        // Saving an open document also stores its unsaved local edits, so
        // they go to the outbox too.
        let mut unsaved = live.as_ref().map(|l| lock(&l.unsaved));
        let outbox: Vec<&[u8]> = unsaved
            .iter()
            .flat_map(|u| u.iter())
            .map(Vec::as_slice)
            .collect();
        self.save(&mut db, id, &doc, &outbox, by, None)?;
        if let Some(unsaved) = &mut unsaved {
            unsaved.clear();
        }
        drop((unsaved, db));
        if let Some(live) = live {
            live.publish(0, update);
        }
        self.emit(BaseEvent::ObjectsChanged(vec![id]));
        Ok(())
    }

    /// Applies fetched objects in one transaction, returning changed IDs and
    /// whether any object needs an update. Newer objects keep their raw
    /// envelopes without changing their local state; other objects apply.
    /// Changes already confirmed are skipped. Decrypt, decode and apply
    /// failures (including panics) are set aside while later changes apply.
    pub(crate) fn apply_fetched(
        &self,
        objects: &[(ObjectId, u64, Vec<Incoming>)],
    ) -> Result<(Vec<ObjectId>, bool), Error> {
        self.check_removal()?;
        let mut db = self.db()?;
        let (applied, needs_update) = db.batch(|db| {
            let mut out = Vec::new();
            let mut needs_update = false;
            for (id, head, changes) in objects {
                let (changed, newer) = self.apply_one(db, *id, *head, changes)?;
                out.extend(changed);
                needs_update |= newer;
            }
            Ok((out, needs_update))
        })?;
        // Only after the batch commits do open documents receive remote edits.
        // Hold the store lock until their updates and unsaved edits agree with it.
        for applied in &applied {
            if let Some(live) = &applied.live {
                for update in &applied.updates {
                    let decoded = Update::decode_v1(update).expect("already decoded");
                    live.doc
                        .lock()
                        .unwrap()
                        .transact_mut()
                        .apply_update(decoded)
                        .expect("already applied");
                }
                lock(&live.unsaved).clear();
            }
        }
        drop(db);
        for applied in &applied {
            if let Some(live) = &applied.live {
                for update in &applied.updates {
                    live.publish(0, update);
                }
            }
        }
        Ok((applied.into_iter().map(|a| a.id).collect(), needs_update))
    }

    fn apply_one(
        &self,
        db: &mut BaseDb,
        id: ObjectId,
        head: u64,
        changes: &[Incoming],
    ) -> Result<(Option<Applied>, bool), Error> {
        let stored = db.state(id)?;
        let confirmed = db.confirmed(id)?.unwrap_or(0);
        let newer = db.needs_update(id)?
            || match &stored {
                Some((ty, _)) => self.newer_type(db, ty)?,
                None => false,
            }
            || changes.iter().any(|c| {
                c.seq > confirmed && c.body.first().is_some_and(|f| *f > envelope::FORMAT)
            });
        if newer {
            self.keep_future(db, id, changes)?;
            return Ok((None, true));
        }
        if head <= confirmed {
            return Ok((None, false));
        }
        // Each change is tried on a copy of the stored state first, so one
        // that fails leaves the open document as it was.
        let copy = match &stored {
            Some((_, state)) => self.load(state)?,
            None => Doc::with_client_id(self.inner.client),
        };
        let mut applied = Vec::new();
        let mut failed = Vec::new();
        let mut by = None;
        for change in changes.iter().filter(|c| c.seq > confirmed) {
            let result = catch_unwind(AssertUnwindSafe(|| {
                let update = self
                    .open_change(id, change.state, &change.body)
                    .map_err(|e| e.to_string())?;
                let decoded =
                    Update::decode_v1(&update).map_err(|_| "not a Yjs update".to_string())?;
                copy.transact_mut()
                    .apply_update(decoded)
                    .map_err(|_| "the update doesn't apply".to_string())?;
                Ok::<_, String>(update.to_vec())
            }));
            match result {
                Ok(Ok(update)) => {
                    applied.push((change, update));
                    by = Some(change.device);
                }
                Ok(Err(error)) => failed.push((change, error)),
                Err(_) => failed.push((change, "applying it panicked".into())),
            }
        }
        if applied.is_empty() {
            for (change, error) in failed {
                db.set_aside(id, change.seq, &change.body, &error)?;
            }
            if stored.is_some() {
                db.set_confirmed(id, head)?;
            }
            return Ok((None, false));
        }
        // Set aside known types at a newer version, including a type that
        // arrived in this batch. Unknown app types can precede their definition.
        let live = self.live(id);
        // Saving an open document also stores its unsaved local edits, so
        // they go to the outbox too. Apply them to the copy, not to `live`.
        let unsaved = live.as_ref().map(|l| lock(&l.unsaved));
        let outbox: Vec<&[u8]> = unsaved
            .iter()
            .flat_map(|u| u.iter())
            .map(Vec::as_slice)
            .collect();
        for update in &outbox {
            let decoded = Update::decode_v1(update)
                .map_err(|_| Error::Storage("unreadable unsaved update".into()))?;
            copy.transact_mut()
                .apply_update(decoded)
                .map_err(|_| Error::Storage("unreadable unsaved update".into()))?;
        }
        let saved = (|| {
            let ty = objects::read_meta(&copy.transact())?.ty;
            if self.newer_type(db, &ty)? {
                return Err(Error::NeedsUpdate);
            }
            self.save(db, id, &copy, &outbox, by, Some(head))
        })();
        drop(unsaved);
        match saved {
            Ok(()) => {
                for (change, error) in failed {
                    db.set_aside(id, change.seq, &change.body, &error)?;
                }
                Ok((
                    Some(Applied {
                        id,
                        live,
                        updates: applied.into_iter().map(|(_, u)| u).collect(),
                    }),
                    false,
                ))
            }
            Err(Error::NeedsUpdate) => {
                self.keep_future(db, id, changes)?;
                Ok((None, true))
            }
            // The changes don't make an object (it has no type): keep them aside.
            Err(Error::Invalid(error)) => {
                for (change, reason) in failed {
                    db.set_aside(id, change.seq, &change.body, &reason)?;
                }
                for (change, _) in &applied {
                    db.set_aside(id, change.seq, &change.body, &error)?;
                }
                if stored.is_some() {
                    db.set_confirmed(id, head)?;
                }
                Ok((None, false))
            }
            Err(e) => Err(e),
        }
    }

    fn keep_future(&self, db: &BaseDb, id: ObjectId, changes: &[Incoming]) -> Result<(), Error> {
        for change in changes {
            db.keep_future(id, change.seq, change.state, change.device, &change.body)?;
        }
        Ok(())
    }

    /// Stores a record type's definition as a `core.type` object whose ID is
    /// keyed by the base. An existing definition may only gain optional
    /// fields or change `doc` text. Call this when opening a base, before writing.
    ///
    /// ```no_run
    /// use bh_core::{Base, FieldDef, FieldKind, TypeDef, Error};
    /// fn define(base: &Base) -> Result<(), Error> {
    ///     base.define_type(TypeDef { name: "sample.reading".into(), version: 1,
    ///         doc: "One reading".into(), title_field: Some("day".into()),
    ///         fields: vec![FieldDef { name: "day".into(), kind: FieldKind::Date,
    ///             required: true, unit: None, doc: "Calendar day".into() }] })
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] for an invalid definition or incompatible
    /// change, [`Error::ReadOnly`] or [`Error::Revoked`] if writes are blocked,
    /// [`Error::NeedsUpdate`] for an unknown version, [`Error::TooLarge`] for
    /// an oversized edit, or [`Error::Storage`] if writing locally fails.
    pub fn define_type(&self, def: TypeDef) -> Result<(), Error> {
        self.writable()?;
        types::check_def(&def)?;
        let mut db = self.db()?;
        let id = types::type_object_id(&self.key(), &def.name, def.version);
        let fields =
            Map::from_iter([("def".to_string(), serde_json::to_value(&def).expect("JSON"))]);
        if db.needs_update(id)? {
            return Err(Error::NeedsUpdate);
        }
        let Some(existing) = db.summary(id)? else {
            let position = objects::position_between(None, None);
            return self.insert(
                &mut db,
                id,
                &TypeRef::new(TYPE, 1),
                None,
                &position,
                &fields,
            );
        };
        let old = existing
            .fields
            .get("def")
            .and_then(|d| serde_json::from_value::<TypeDef>(d.clone()).ok())
            .ok_or(Error::NeedsUpdate)?;
        if old == def {
            return Ok(());
        }
        types::check_redefinition(&old, &def)?;
        self.edit_in(&mut db, id, 0, |_, _, _, txn| {
            objects::write_fields(txn, &fields)
        })
    }

    /// Finds live objects of a type matching JSON-field filters and ordering.
    /// Versions of a type are queried together; querying reads local data only.
    ///
    /// ```no_run
    /// use bh_core::{Base, Error, Filter, Op, Order, Query};
    /// use serde_json::json;
    /// fn readings(base: &Base) -> Result<(), Error> {
    ///     let found = base.query(&Query { ty: "sample.reading".into(),
    ///         filters: vec![Filter { field: "day".into(), op: Op::Eq,
    ///             value: json!("2026-11-01") }],
    ///         order_by: Some(("day".into(), Order::Desc)), limit: Some(20) })?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] for an unrepresentable field name or
    /// [`Error::Storage`] for a local query failure.
    pub fn query(&self, q: &Query) -> Result<Vec<ObjectSummary>, Error> {
        self.check_closed()?;
        query::run(&**self.db()?, q)
    }

    /// Searches locally indexed titles, note bodies and Text fields.
    ///
    /// # Errors
    /// Returns [`Error::Storage`] if the local search fails.
    pub fn search(&self, text: &str, limit: usize) -> Result<Vec<SearchHit>, Error> {
        self.check_closed()?;
        search::search(&**self.db()?, text, limit)
    }

    /// The record types defined in this base, by name and version.
    ///
    /// # Errors
    /// Returns [`Error::Storage`] if the local store cannot be read.
    pub fn types(&self) -> Result<Vec<TypeDef>, Error> {
        self.check_closed()?;
        let db = self.db()?;
        let mut defs: Vec<TypeDef> = db
            .of_type(TYPE)?
            .into_iter()
            .filter(|s| !s.deleted)
            .filter_map(|s| {
                let def: TypeDef = serde_json::from_value(s.fields.get("def")?.clone()).ok()?;
                (types::type_object_id(&self.key(), &def.name, def.version) == s.id).then_some(def)
            })
            .collect();
        defs.sort_by(|a, b| (&a.name, a.version).cmp(&(&b.name, b.version)));
        Ok(defs)
    }
}

/// Hooks for tests.
#[cfg(feature = "test-support")]
impl Base {
    /// Test-only bulk writer: the same validation, Yjs state, summaries, FTS and
    /// outbox as `create`, but one outer store transaction and no sibling scan
    /// per inserted object. Intended for scale fixtures, never an app API.
    pub fn test_bulk_create(
        &self,
        objects: impl IntoIterator<Item = (NewObject, Option<Vec<u8>>)>,
    ) -> Result<Vec<ObjectId>, Error> {
        self.writable()?;
        let mut db = self.db()?;
        let mut positions: HashMap<Option<ObjectId>, String> = HashMap::new();
        let mut ids = Vec::new();
        db.batch(|db| {
            for (new, note_update) in objects {
                if structural(&new.ty.name) {
                    return Err(Error::invalid("type definitions are made with define_type"));
                }
                let def = self
                    .def(db, &new.ty)?
                    .ok_or_else(|| Error::invalid("unknown type"))?;
                let fields: Map<String, Value> = new
                    .fields
                    .into_iter()
                    .filter(|(_, v)| !v.is_null())
                    .collect();
                types::validate(&def, &fields)?;
                if let Some(parent) = new.parent
                    && db.parent_of(parent)?.is_none()
                {
                    return Err(Error::NotFound);
                }
                let last = match positions.entry(new.parent) {
                    std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        let last = db
                            .siblings(new.parent)?
                            .last()
                            .map(|(_, p)| p.clone())
                            .unwrap_or_default();
                        entry.insert(last)
                    }
                };
                let position = objects::position_between(
                    if last.is_empty() {
                        None
                    } else {
                        Some(last.as_str())
                    },
                    None,
                );
                *last = position.clone();
                let id = ObjectId::random();
                if let Some(update) = note_update {
                    if new.ty.name != NOTE {
                        return Err(Error::invalid("text requires a note"));
                    }
                    let doc = Doc::with_client_id(self.inner.client);
                    let metadata = {
                        let mut txn = doc.transact_mut();
                        objects::write_type(&mut txn, &new.ty);
                        objects::write_place(&mut txn, new.parent, &position);
                        objects::write_deleted(&mut txn, false);
                        objects::write_fields(&mut txn, &fields)?;
                        txn.encode_update_v1()
                    };
                    doc.transact_mut()
                        .apply_update(
                            Update::decode_v1(&update)
                                .map_err(|_| Error::invalid("not a Yjs update"))?,
                        )
                        .map_err(|_| Error::invalid("not a Yjs update"))?;
                    self.save(db, id, &doc, &[&metadata, &update], self.inner.device, None)?;
                    self.edited(id);
                } else {
                    self.insert(db, id, &new.ty, new.parent, &position, &fields)?;
                }
                ids.push(id);
            }
            Ok(())
        })?;
        Ok(ids)
    }

    /// Test-only year fixture: apply one chronological chunk of distinct Yjs
    /// sessions, save each touched note once, and queue every original update
    /// in one transaction. Sync must finish before writing the next chunk.
    pub fn test_bulk_apply(&self, updates: &[(ObjectId, Vec<u8>)]) -> Result<(), Error> {
        self.writable()?;
        let mut db = self.db()?;
        let mut docs = HashMap::new();
        for (id, update) in updates {
            if update.len() > MAX_UPDATE {
                return Err(Error::TooLarge);
            }
            if !docs.contains_key(id) {
                let (ty, state) = db.state(*id)?.ok_or(Error::NotFound)?;
                if ty.name != NOTE {
                    return Err(Error::invalid("not a note"));
                }
                docs.insert(*id, self.load(&state)?);
            }
            docs.get(id)
                .expect("loaded note")
                .transact_mut()
                .apply_update(
                    Update::decode_v1(update).map_err(|_| Error::invalid("not a Yjs update"))?,
                )
                .map_err(|_| Error::invalid("not a Yjs update"))?;
        }
        db.batch(|db| {
            for (id, doc) in &docs {
                self.save(db, *id, doc, &[], self.inner.device, None)?;
            }
            db.test_append_outbox(updates)
        })?;
        drop(db);
        for id in docs.keys() {
            self.edited(*id);
        }
        Ok(())
    }

    /// In tests, holds a foreground download inside the part-fetch loop.
    #[cfg(feature = "test-support")]
    pub fn test_hold_on_demand_file_get(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        let held = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        *lock(&self.inner.held_on_demand_get) = Some(held.clone());
        held
    }

    /// In tests, reports whether close has dropped the in-memory base key.
    #[cfg(feature = "test-support")]
    pub fn test_has_key(&self) -> bool {
        lock(&self.inner.key).is_some()
    }

    /// In tests, holds a full device's next file part download before its GET
    /// until the downloader stops. The returned flag is set when it is held.
    #[cfg(feature = "test-support")]
    pub fn test_hold_file_gets(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        let probe = &self
            .inner
            .downloader
            .get()
            .expect("the base's sync has started")
            .probe;
        probe.hold.store(true, Ordering::SeqCst);
        probe.held.clone()
    }

    /// In tests, a flag that stays set while the downloader task exists.
    #[cfg(feature = "test-support")]
    pub fn test_downloader_alive(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.inner
            .downloader
            .get()
            .expect("the base's sync has started")
            .probe
            .alive
            .clone()
    }

    /// Holds the next upload waiter after it finds pending work, before it waits.
    #[cfg(feature = "test-support")]
    pub fn test_hold_next_upload_wait(&self) -> Arc<std::sync::atomic::AtomicBool> {
        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *lock(&self.inner.held_upload_wait) =
            Some((entered.clone(), Arc::new(tokio::sync::Notify::new())));
        entered
    }

    /// Releases the upload waiter held by `test_hold_next_upload_wait`.
    #[cfg(feature = "test-support")]
    pub fn test_resume_upload_wait(&self) {
        if let Some((_, notify)) = lock(&self.inner.held_upload_wait).take() {
            notify.notify_one();
        }
    }

    /// Pauses only the file uploader in tests.
    #[cfg(feature = "test-support")]
    pub fn pause_files(&self) {
        if let Some(task) = self.inner.uploader.get() {
            task.pause(true);
        }
    }

    /// Resumes the file uploader in tests.
    #[cfg(feature = "test-support")]
    pub fn resume_files(&self) {
        if let Some(task) = self.inner.uploader.get() {
            task.pause(false);
        }
    }

    /// In tests, holds this base's next file part upload just before its request
    /// until the uploader stops. The returned flag is set once one is held.
    #[cfg(feature = "test-support")]
    pub fn test_hold_file_puts(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        let probe = &self
            .inner
            .uploader
            .get()
            .expect("the base's sync has started")
            .probe;
        probe.hold.store(true, Ordering::SeqCst);
        probe.held.clone()
    }

    /// In tests, reports when the uploader has found the queue empty and published progress.
    #[cfg(feature = "test-support")]
    pub fn test_uploader_idle(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.inner
            .uploader
            .get()
            .expect("the base's sync has started")
            .probe
            .idle
            .clone()
    }

    /// In tests, a flag that stays set while this base's uploader task exists.
    #[cfg(feature = "test-support")]
    pub fn test_uploader_alive(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.inner
            .uploader
            .get()
            .expect("the base's sync has started")
            .probe
            .alive
            .clone()
    }

    /// Injects a lost reply after `n` successful part uploads in tests.
    #[cfg(feature = "test-support")]
    pub fn fail_file_put_after(&self, n: u32) {
        if let Some(task) = self.inner.uploader.get() {
            task.fail_after(n);
        }
    }

    /// Holds the next kept-state response after the server replies, for clock tests.
    pub fn test_hold_kept_reply(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.inner.sync.get().unwrap().hold_next_kept_reply()
    }

    /// Releases a kept-state response held by `test_hold_kept_reply`.
    pub fn test_resume_kept_reply(&self) {
        self.inner.sync.get().unwrap().resume_kept_reply();
    }

    /// Test-only: retain one server change per queued session instead of the
    /// normal sync engine's per-object merging. Only valid with test fixtures.
    pub fn test_preserve_sync_updates(&self) {
        if let Some(sync) = self.inner.sync.get() {
            sync.preserve_updates();
        }
    }

    /// Stops the sync task sending or fetching until `test_resume_sync`.
    pub fn test_pause_sync(&self) {
        if let Some(sync) = self.inner.sync.get() {
            sync.pause(true);
        }
    }

    /// Resumes a sync task paused by [`Self::test_pause_sync`].
    pub fn test_resume_sync(&self) {
        if let Some(sync) = self.inner.sync.get() {
            sync.pause(false);
        }
    }

    /// The seq up to which this device has applied every change to `id`.
    pub fn test_confirmed_seq(&self, id: ObjectId) -> u64 {
        self.db()
            .unwrap()
            .confirmed(id)
            .expect("readable store")
            .unwrap_or(0)
    }

    /// The changes set aside: their objects, seqs and errors.
    pub fn test_set_aside(&self) -> Vec<(ObjectId, u64, String)> {
        self.db().unwrap().set_aside_rows().expect("readable store")
    }

    /// Raw future envelopes retained for a newer version of the core.
    pub fn test_future_bodies(&self, id: ObjectId) -> Vec<Vec<u8>> {
        self.db()
            .unwrap()
            .future_bodies(id)
            .expect("readable store")
    }

    /// An update to `id` sealed as this base's changes are.
    pub fn test_seal_update(&self, id: ObjectId, update: &[u8]) -> Vec<u8> {
        self.seal_change(id, false, update)
    }

    /// A whole state to `id` sealed with the state purpose for raw protocol tests.
    pub fn test_seal_state(&self, id: ObjectId, state: &[u8]) -> Vec<u8> {
        self.seal_change(id, true, state)
    }

    /// Applies an update as if it came from another device.
    pub fn test_apply_remote(&self, id: ObjectId, update: &[u8]) -> Result<(), Error> {
        self.apply_remote(id, update, None)
    }

    /// The outbox's object IDs and updates, oldest first.
    pub fn test_outbox(&self) -> Vec<(ObjectId, Vec<u8>)> {
        self.db().unwrap().outbox().expect("readable outbox")
    }

    /// Test kit only: create a moved marker as an app could in base content.
    pub fn test_mark_moved(&self, id: ObjectId, to: BaseId) -> Result<(), Error> {
        self.mark_moved(id, to)
    }

    /// Makes the next store write fail, as a full disk would.
    pub fn test_fail_next_save(&self) {
        self.inner
            .fail_next_save
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// The object ID of a type definition in this base.
    pub fn test_type_id(&self, name: &str, version: u32) -> ObjectId {
        types::type_object_id(&self.key(), name, version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FileSecretStore;

    #[tokio::test]
    async fn file_scratch_buffers_are_zeroizing_until_returned_to_the_caller() {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [3u8; 32]);
        let decoded: Zeroizing<Vec<u8>> = decode_file_key(&encoded).unwrap();
        assert_eq!(decoded.as_slice(), &[3u8; 32]);
        let tmp = tempfile::tempdir().unwrap();
        let base = Base::open_local(tmp.path(), [7; 32]).unwrap();
        let id = base
            .add_file(
                crate::NewFile {
                    parent: None,
                    name: "scratch".into(),
                    mime: "image/png".into(),
                },
                b"private bytes",
            )
            .unwrap();
        let assembled: Zeroizing<Vec<u8>> = base.file_bytes_owned(id).await.unwrap();
        assert_eq!(assembled.as_slice(), b"private bytes");
    }

    fn folder(name: &str) -> NewObject {
        NewObject {
            ty: TypeRef::new(FOLDER, 1),
            parent: None,
            after: None,
            fields: Map::from_iter([("name".into(), Value::from(name))]),
        }
    }

    #[test]
    fn documentation_only_definition_edits_do_not_reindex_records() {
        let tmp = tempfile::tempdir().unwrap();
        let base = Base::open_local(tmp.path(), [7; 32]).unwrap();
        let mut def = TypeDef {
            name: "demo.sleep".into(),
            version: 1,
            doc: String::new(),
            title_field: Some("memo".into()),
            fields: vec![types::FieldDef {
                name: "memo".into(),
                kind: types::FieldKind::Text,
                required: false,
                unit: None,
                doc: String::new(),
            }],
        };
        base.define_type(def.clone()).unwrap();
        let id = base
            .create(NewObject {
                ty: TypeRef::new("demo.sleep", 1),
                parent: None,
                after: None,
                fields: Map::from_iter([("memo".into(), Value::from("ferry"))]),
            })
            .unwrap();
        base.db()
            .unwrap()
            .connection()
            .execute_batch(&format!(
                "CREATE TABLE reindexes (id INTEGER); \
             CREATE TRIGGER record_title_update AFTER UPDATE OF title ON objects \
             WHEN NEW.object_id = '{id}' BEGIN INSERT INTO reindexes VALUES (1); END;"
            ))
            .unwrap();
        def.doc = "Updated description".into();
        base.define_type(def.clone()).unwrap();
        let count = || {
            base.db()
                .unwrap()
                .connection()
                .query_row("SELECT count(*) FROM reindexes", [], |r| r.get::<_, i64>(0))
                .unwrap()
        };
        assert_eq!(count(), 0);
        def.fields.push(types::FieldDef {
            name: "source".into(),
            kind: types::FieldKind::Text,
            required: false,
            unit: None,
            doc: String::new(),
        });
        base.define_type(def).unwrap();
        assert_eq!(count(), 1);
    }

    #[test]
    fn bases_and_notes_can_be_shared_across_threads() {
        fn shareable<T: Send + Sync + 'static>() {}
        shareable::<Base>();
        shareable::<NoteDoc>();
    }

    #[test]
    fn a_base_keeps_its_store_key_in_the_secret_store() {
        let tmp = tempfile::tempdir().unwrap();
        let secrets = FileSecretStore::new(tmp.path().join("secrets")).unwrap();
        let id = BaseId([4; 16]);
        let path = tmp.path().join("bases").join(format!("{id}.sqlite"));
        let open = || {
            Base::open(
                &path,
                &secrets,
                id,
                BaseKey::new(&[1; 32]).unwrap(),
                Mode::ReadWrite,
                Some(DeviceId([9; 16])),
                None,
            )
        };
        let base = open().unwrap();
        let f = base.create(folder("Trips")).unwrap();
        assert_eq!(
            base.get(f).unwrap().unwrap().updated_by,
            Some(DeviceId([9; 16]))
        );
        let key = secrets.get(&format!("base.{id}.dbkey")).unwrap().unwrap();
        assert_eq!(key.len(), 32);
        drop(base);
        assert_eq!(open().unwrap().get(f).unwrap().unwrap().title, "Trips");
        assert_eq!(
            format!("{:?}", BaseKey::new(&[1; 32]).unwrap()),
            "BaseKey(…)"
        );
    }

    #[test]
    fn a_read_only_base_refuses_local_writes_at_once() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("base.sqlite");
        let open = |mode| {
            Base::open_store(
                &path,
                &[1; 32],
                BaseId([4; 16]),
                BaseKey::new(&[1; 32]).unwrap(),
                mode,
                None,
            )
            .unwrap()
        };
        let f = open(Mode::ReadWrite)
            .create(NewObject {
                ty: TypeRef::new(NOTE, 1),
                ..folder("")
            })
            .unwrap();
        let base = open(Mode::ReadOnly);
        assert_eq!(base.mode(), Mode::ReadOnly);
        assert_eq!(base.create(folder("x")), Err(Error::ReadOnly));
        assert_eq!(base.set_fields(f, Map::new()), Err(Error::ReadOnly));
        assert_eq!(base.move_to(f, None, None), Err(Error::ReadOnly));
        assert_eq!(base.delete(f), Err(Error::ReadOnly));
        assert_eq!(base.undelete(f), Err(Error::ReadOnly));
        let def = TypeDef {
            name: "demo.x".into(),
            version: 1,
            doc: String::new(),
            title_field: None,
            fields: vec![],
        };
        assert_eq!(base.define_type(def), Err(Error::ReadOnly));
        assert_eq!(
            base.note(f).unwrap().apply(5, &[0, 0]),
            Err(Error::ReadOnly)
        );
        assert!(format!("{base:?}").starts_with("Base {"));
    }

    #[test]
    fn fetched_changes_that_fail_are_set_aside_and_the_rest_apply() {
        let tmp = tempfile::tempdir().unwrap();
        let base = Base::open_store(
            &tmp.path().join("b.sqlite"),
            &[1; 32],
            BaseId([4; 16]),
            BaseKey::new(&[1; 32]).unwrap(),
            Mode::ReadWrite,
            None,
        )
        .unwrap();
        let source = Doc::new();
        let update = {
            let mut txn = source.transact_mut();
            objects::write_type(&mut txn, &TypeRef::new(FOLDER, 1));
            objects::write_place(&mut txn, None, "V");
            objects::write_fields(
                &mut txn,
                &Map::from_iter([("name".into(), Value::from("Trips"))]),
            )
            .unwrap();
            txn.encode_update_v1()
        };
        let id = ObjectId([6; 16]);
        let change = |seq, body: Vec<u8>| Incoming {
            seq,
            state: false,
            device: DeviceId([3; 16]),
            body,
        };
        let changes = vec![
            change(1, vec![1; 60]),
            change(2, base.seal_change(id, false, b"not a Yjs update")),
            change(3, base.seal_change(id, false, &update)),
            // Sealed as a state, so it doesn't open as an update.
            change(4, base.seal_change(id, true, &update)),
        ];
        let fetched = [(id, 4, changes)];
        assert_eq!(base.apply_fetched(&fetched).unwrap(), (vec![id], false));
        let summary = base.get(id).unwrap().unwrap();
        assert_eq!(
            (summary.title.as_str(), summary.updated_by),
            ("Trips", Some(DeviceId([3; 16])))
        );
        assert_eq!(base.db().unwrap().confirmed(id).unwrap(), Some(4));
        let aside: Vec<u64> = base
            .db()
            .unwrap()
            .set_aside_rows()
            .unwrap()
            .iter()
            .map(|(_, seq, _)| *seq)
            .collect();
        assert_eq!(aside, [1, 2, 4]);
        // Changes up to `confirmed_seq` are never applied or set aside again.
        assert!(base.apply_fetched(&fetched).unwrap().0.is_empty());
        assert_eq!(base.db().unwrap().set_aside_rows().unwrap().len(), 3);
        assert!(base.db().unwrap().outbox().unwrap().is_empty());
    }

    #[test]
    fn newer_changes_and_types_leave_the_object_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let base = Base::open_store(
            &tmp.path().join("b.sqlite"),
            &[1; 32],
            BaseId([4; 16]),
            BaseKey::new(&[1; 32]).unwrap(),
            Mode::ReadWrite,
            None,
        )
        .unwrap();
        let id = base.create(folder("Original")).unwrap();
        let before = base.get(id).unwrap().unwrap();
        let mut body = base.seal_change(id, false, b"not a Yjs update");
        body[0] = 2;
        let raw = body.clone();
        let incoming = |seq, body| Incoming {
            seq,
            state: false,
            device: DeviceId([3; 16]),
            body,
        };
        assert_eq!(
            base.apply_fetched(&[(id, 1, vec![incoming(1, body)])]),
            Ok((vec![], true))
        );
        assert!(matches!(base.get(id), Err(Error::NeedsUpdate)));
        assert_eq!(base.db().unwrap().summary(id).unwrap().unwrap(), before);
        assert!(base.db().unwrap().set_aside_rows().unwrap().is_empty());
        assert_eq!(base.db().unwrap().confirmed(id).unwrap(), Some(0));
        let reopened = BaseDb::open(&tmp.path().join("b.sqlite"), &[1; 32]).unwrap();
        assert_eq!(reopened.future_bodies(id).unwrap(), [raw]);
        drop(reopened);

        let source = Doc::new();
        let update = {
            let mut txn = source.transact_mut();
            objects::write_type(&mut txn, &TypeRef::new(FOLDER, 2));
            objects::write_place(&mut txn, None, "V");
            txn.encode_update_v1()
        };
        let other = ObjectId([8; 16]);
        assert_eq!(
            base.apply_fetched(&[(
                other,
                2,
                vec![incoming(2, base.seal_change(other, false, &update))]
            )]),
            Ok((vec![], true))
        );
        assert!(matches!(base.get(other), Err(Error::NeedsUpdate)));
        assert!(base.db().unwrap().set_aside_rows().unwrap().is_empty());
        assert_eq!(base.db().unwrap().confirmed(other).unwrap(), None);

        base.define_type(TypeDef {
            name: "demo.sleep".into(),
            version: 1,
            doc: String::new(),
            title_field: None,
            fields: vec![],
        })
        .unwrap();
        let source = Doc::new();
        let update = {
            let mut txn = source.transact_mut();
            objects::write_type(&mut txn, &TypeRef::new("demo.sleep", 2));
            objects::write_place(&mut txn, None, "V");
            txn.encode_update_v1()
        };
        let newer_app_record = ObjectId([9; 16]);
        let envelope = base.seal_change(newer_app_record, false, &update);
        assert_eq!(
            base.apply_fetched(&[(newer_app_record, 3, vec![incoming(3, envelope.clone())])]),
            Ok((vec![], true))
        );
        assert_eq!(
            base.db().unwrap().future_bodies(newer_app_record).unwrap(),
            [envelope]
        );
        assert!(matches!(
            base.get(newer_app_record),
            Err(Error::NeedsUpdate)
        ));

        // Even a fetched change that cannot decode cannot advance a stored
        // object whose type is already newer than this build's definition.
        let state = base.db().unwrap().state(id).unwrap().unwrap().1;
        let mut future = base.db().unwrap().summary(id).unwrap().unwrap();
        future.ty.version = 2;
        base.db()
            .unwrap()
            .put(
                &ObjectRow {
                    summary: future.clone(),
                    state,
                    moved: false,
                },
                &[],
                None,
            )
            .unwrap();
        let bad = base.seal_change(id, false, b"bad update");
        assert_eq!(
            base.apply_fetched(&[(id, 3, vec![incoming(3, bad)])]),
            Ok((vec![], true))
        );
        assert!(matches!(base.get(id), Err(Error::NeedsUpdate)));
        assert_eq!(base.db().unwrap().summary(id).unwrap().unwrap(), future);
        assert!(base.db().unwrap().set_aside_rows().unwrap().is_empty());
        assert_eq!(base.db().unwrap().confirmed(id).unwrap(), Some(0));
    }

    #[test]
    fn a_failed_fetch_batch_does_not_change_an_open_document() {
        let tmp = tempfile::tempdir().unwrap();
        let base = Base::open_store(
            &tmp.path().join("b.sqlite"),
            &[1; 32],
            BaseId([4; 16]),
            BaseKey::new(&[1; 32]).unwrap(),
            Mode::ReadWrite,
            None,
        )
        .unwrap();
        let id = base.create(folder("Original")).unwrap();
        let doc = base.note(id).unwrap();
        let source = Doc::new();
        let update = {
            let mut txn = source.transact_mut();
            objects::write_type(&mut txn, &TypeRef::new(FOLDER, 1));
            objects::write_place(&mut txn, None, "V");
            objects::write_fields(
                &mut txn,
                &Map::from_iter([("name".into(), Value::from("New"))]),
            )
            .unwrap();
            txn.encode_update_v1()
        };
        let remote = Incoming {
            seq: 1,
            state: false,
            device: DeviceId([3; 16]),
            body: base.seal_change(id, false, &update),
        };
        let before = doc.state();
        base.test_fail_next_save();
        assert!(base.apply_fetched(&[(id, 1, vec![remote])]).is_err());
        assert_eq!(doc.state(), before);
        assert_eq!(base.db().unwrap().confirmed(id).unwrap(), Some(0));

        // A failure on a later object rolls the first one's write back too.
        let remote = Incoming {
            seq: 1,
            state: false,
            device: DeviceId([3; 16]),
            body: base.seal_change(id, false, &update),
        };
        let mut newer = base.seal_change(ObjectId([9; 16]), false, &update);
        newer[0] = 2;
        assert_eq!(
            base.apply_fetched(&[
                (id, 1, vec![remote]),
                (
                    ObjectId([9; 16]),
                    2,
                    vec![Incoming {
                        seq: 2,
                        state: false,
                        device: DeviceId([3; 16]),
                        body: newer
                    }]
                ),
            ]),
            Ok((vec![id], true))
        );
        assert_ne!(doc.state(), before);
        assert_eq!(base.db().unwrap().confirmed(id).unwrap(), Some(1));
    }

    #[test]
    fn the_base_name_comes_from_its_own_object() {
        let tmp = tempfile::tempdir().unwrap();
        let id = BaseId([4; 16]);
        let base = Base::open_store(
            &tmp.path().join("b.sqlite"),
            &[1; 32],
            id,
            BaseKey::new(&[1; 32]).unwrap(),
            Mode::ReadWrite,
            None,
        )
        .unwrap();
        assert_eq!(base.name(), "");
        let mut db = base.db().unwrap();
        let fields = Map::from_iter([("name".into(), Value::from("Travel"))]);
        base.insert(
            &mut db,
            ObjectId(id.0),
            &TypeRef::new(BASE, 1),
            None,
            "V",
            &fields,
        )
        .unwrap();
        drop(db);
        assert_eq!(base.name(), "Travel");
        assert!(base.children(None).unwrap().is_empty());
        assert!(matches!(
            base.delete(ObjectId(id.0)),
            Err(Error::Invalid(_))
        ));
    }
}
