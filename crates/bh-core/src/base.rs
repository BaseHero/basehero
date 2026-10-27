//! `Base`: one base's objects, kept in its own encrypted store.

use crate::client::Api;
use crate::envelope::{self, Aad, Purpose};
use crate::note::{self, Live, NoteDoc};
use crate::objects::{self, Meta, NewObject, ObjectSummary};
use crate::query::{self, Query};
use crate::search::{self, SearchHit};
use crate::store::{BaseDb, ObjectRow};
use crate::sync::{BaseEvent, Incoming, SyncState, SyncTask};
use crate::types::{self, BASE, FOLDER, NOTE, PROJECT, TYPE, TypeDef, TypeRef};
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
pub enum Mode {
    ReadWrite,
    ReadOnly,
}

/// A base as `Account::bases` lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct BaseSummary {
    #[ts(type = "string")]
    pub id: BaseId,
    pub name: String,
    pub mode: Mode,
    /// Always false in this version.
    pub hidden: bool,
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

impl BaseWeak {
    pub(crate) fn upgrade(&self) -> Option<Base> {
        self.0.upgrade().map(|inner| Base { inner })
    }
}

struct Inner {
    id: BaseId,
    mode: Mode,
    device: Option<DeviceId>,
    key: BaseKey,
    /// The yrs client ID of this process's core edits, used only under the
    /// store lock against the stored state, so its clock never repeats.
    client: u64,
    db: Mutex<BaseDb>,
    /// Absent only for standalone test-kit bases.
    removal: OnceLock<Arc<AtomicU8>>,
    /// Open documents, one per object; always lock `db` first.
    live: Mutex<HashMap<ObjectId, Weak<Live>>>,
    events: broadcast::Sender<BaseEvent>,
    /// The sync task, for a base that has a server.
    sync: OnceLock<SyncTask>,
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
fn structural(name: &str) -> bool {
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

    fn open_store(
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
                key,
                client: u64::from(u32::from_le_bytes(bh_crypto::random::<4>())),
                db: Mutex::new(db),
                removal: OnceLock::new(),
                live: Mutex::new(HashMap::new()),
                events: broadcast::channel(256).0,
                sync: OnceLock::new(),
                #[cfg(feature = "test-support")]
                fail_next_save: Default::default(),
            }),
        };
        if base.db().needs_search_backfill() {
            let mut db = base.db();
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

    pub(crate) fn downgrade(&self) -> BaseWeak {
        BaseWeak(Arc::downgrade(&self.inner))
    }

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

    pub fn mode(&self) -> Mode {
        self.inner.mode
    }

    pub(crate) fn db(&self) -> crate::store::InUse<'_, BaseDb> {
        crate::store::in_use(&self.inner.db)
    }

    /// Stops background sync before the account's local stores are erased.
    pub(crate) async fn stop_sync(&self) {
        if let Some(sync) = self.inner.sync.get() {
            sync.stop().await;
        }
    }

    /// Starts the base's sync task with the account's client.
    pub(crate) fn start_sync(
        &self,
        api: Api,
        runtime: &tokio::runtime::Handle,
        clock: crate::Clock,
    ) {
        self.inner
            .sync
            .get_or_init(|| SyncTask::start(self.clone(), api, runtime, clock));
    }

    pub fn sync_state(&self) -> SyncState {
        let (online, last_synced_at) = self
            .inner
            .sync
            .get()
            .map_or((false, None), SyncTask::status);
        SyncState {
            pending: self.db().pending().unwrap_or(0),
            online,
            last_synced_at,
        }
    }

    pub fn events(&self) -> broadcast::Receiver<BaseEvent> {
        self.inner.events.subscribe()
    }

    pub(crate) fn emit(&self, event: BaseEvent) {
        // No subscribers is fine.
        let _ = self.inner.events.send(event);
    }

    /// Sends the outbox now and waits until the server has it. A base
    /// without a server has nothing to send.
    pub async fn flush(&self) -> Result<(), Error> {
        match self.inner.sync.get() {
            Some(sync) => sync.flush().await,
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
        bh_crypto::kdf(self.inner.key.secret(), b"bhcntnt1", EPOCH.into())
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
        let id = types::type_object_id(&self.inner.key, &ty.name, ty.version);
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

    fn check_removal(&self) -> Result<(), Error> {
        if self
            .inner
            .removal
            .get()
            .is_some_and(|r| r.load(Ordering::SeqCst) != 0)
        {
            Err(Error::Revoked)
        } else {
            Ok(())
        }
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
            if types::type_object_id(&self.inner.key, &def.name, def.version) != id {
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
        let row = ObjectRow { summary, state };
        db.batch(|db| {
            db.put(&row, outbox, confirmed)?;
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
    fn share(&self, id: ObjectId, update: &[u8]) {
        if let Some(live) = self.live(id) {
            if let Ok(decoded) = Update::decode_v1(update) {
                let _ = live.doc.transact_mut().apply_update(decoded);
            }
            live.publish(0, update);
        }
    }

    /// A core edit of an existing object: on a copy of its stored state, then
    /// stored with its update in the outbox and given to its open document.
    fn edit_in(
        &self,
        db: &mut BaseDb,
        id: ObjectId,
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
        self.share(id, &update);
        self.edited(id);
        Ok(())
    }

    fn edit(
        &self,
        id: ObjectId,
        edit: impl FnOnce(&BaseDb, &Meta, &TypeDef, &mut TransactionMut) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.edit_in(&mut self.db(), id, edit)
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
            &mut self.db(),
            ObjectId(self.inner.id.0),
            &TypeRef::new(BASE, 1),
            None,
            &position,
            &fields,
        )
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

    /// An object, deleted or not, with the parent it shows under.
    pub fn get(&self, id: ObjectId) -> Result<Option<ObjectSummary>, Error> {
        let db = self.db();
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
    pub fn children(&self, parent: Option<ObjectId>) -> Result<Vec<ObjectSummary>, Error> {
        let db = self.db();
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
    pub fn create(&self, new: NewObject) -> Result<ObjectId, Error> {
        self.writable()?;
        if structural(&new.ty.name) {
            return Err(Error::invalid("type definitions are made with define_type"));
        }
        let mut db = self.db();
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
    pub fn delete(&self, id: ObjectId) -> Result<(), Error> {
        self.set_deleted(id, true)
    }

    pub fn undelete(&self, id: ObjectId) -> Result<(), Error> {
        self.set_deleted(id, false)
    }

    /// Deleted objects, the most recently changed first.
    pub fn trash(&self) -> Result<Vec<ObjectSummary>, Error> {
        let db = self.db();
        let mut out = db.trash()?;
        for s in &mut out {
            s.parent = self.shown_parent(&db, s.id)?;
        }
        Ok(out)
    }

    /// The document of a note, folder or project: one per object in this
    /// process, shared by every caller. A newer object returns `NeedsUpdate`.
    pub fn note(&self, id: ObjectId) -> Result<NoteDoc, Error> {
        let db = self.db();
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
        let mut db = self.db();
        if db.needs_update(live.id)? {
            return Err(Error::NeedsUpdate);
        }
        let ty = db.type_of(live.id)?.ok_or(Error::NotFound)?;
        self.editable(&db, &ty)?;
        live.doc
            .transact_mut()
            .apply_update(decoded)
            .map_err(|_| Error::invalid("the update doesn't apply"))?;
        let mut unsaved = lock(&live.unsaved);
        unsaved.push(update.to_vec());
        let outbox: Vec<&[u8]> = unsaved.iter().map(Vec::as_slice).collect();
        self.save(
            &mut db,
            live.id,
            &live.doc,
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
        let mut db = self.db();
        let live = self.live(id);
        let doc = match (&live, db.state(id)?) {
            (Some(live), _) => live.doc.clone(),
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
        let mut db = self.db();
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
    /// fields or change `doc` text.
    pub fn define_type(&self, def: TypeDef) -> Result<(), Error> {
        self.writable()?;
        types::check_def(&def)?;
        let id = types::type_object_id(&self.inner.key, &def.name, def.version);
        let fields =
            Map::from_iter([("def".to_string(), serde_json::to_value(&def).expect("JSON"))]);
        let mut db = self.db();
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
        self.edit_in(&mut db, id, |_, _, _, txn| {
            objects::write_fields(txn, &fields)
        })
    }

    /// Finds live objects of a type matching JSON-field filters and ordering.
    pub fn query(&self, q: &Query) -> Result<Vec<ObjectSummary>, Error> {
        query::run(&self.db(), q)
    }

    /// Searches locally indexed titles, note bodies and Text fields.
    pub fn search(&self, text: &str, limit: usize) -> Result<Vec<SearchHit>, Error> {
        search::search(&self.db(), text, limit)
    }

    /// The record types defined in this base, by name and version.
    pub fn types(&self) -> Result<Vec<TypeDef>, Error> {
        let db = self.db();
        let mut defs: Vec<TypeDef> = db
            .of_type(TYPE)?
            .into_iter()
            .filter(|s| !s.deleted)
            .filter_map(|s| {
                let def: TypeDef = serde_json::from_value(s.fields.get("def")?.clone()).ok()?;
                (types::type_object_id(&self.inner.key, &def.name, def.version) == s.id)
                    .then_some(def)
            })
            .collect();
        defs.sort_by(|a, b| (&a.name, a.version).cmp(&(&b.name, b.version)));
        Ok(defs)
    }
}

/// Hooks for tests.
#[cfg(feature = "test-support")]
impl Base {
    /// Stops the sync task sending or fetching until `test_resume_sync`.
    pub fn test_pause_sync(&self) {
        if let Some(sync) = self.inner.sync.get() {
            sync.pause(true);
        }
    }

    pub fn test_resume_sync(&self) {
        if let Some(sync) = self.inner.sync.get() {
            sync.pause(false);
        }
    }

    /// The seq up to which this device has applied every change to `id`.
    pub fn test_confirmed_seq(&self, id: ObjectId) -> u64 {
        self.db()
            .confirmed(id)
            .expect("readable store")
            .unwrap_or(0)
    }

    /// The changes set aside: their objects, seqs and errors.
    pub fn test_set_aside(&self) -> Vec<(ObjectId, u64, String)> {
        self.db().set_aside_rows().expect("readable store")
    }

    /// Raw future envelopes retained for a newer version of the core.
    pub fn test_future_bodies(&self, id: ObjectId) -> Vec<Vec<u8>> {
        self.db().future_bodies(id).expect("readable store")
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
        self.db().outbox().expect("readable outbox")
    }

    /// Makes the next store write fail, as a full disk would.
    pub fn test_fail_next_save(&self) {
        self.inner
            .fail_next_save
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// The object ID of a type definition in this base.
    pub fn test_type_id(&self, name: &str, version: u32) -> ObjectId {
        types::type_object_id(&self.inner.key, name, version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FileSecretStore;

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
        assert_eq!(base.db().confirmed(id).unwrap(), Some(4));
        let aside: Vec<u64> = base
            .db()
            .set_aside_rows()
            .unwrap()
            .iter()
            .map(|(_, seq, _)| *seq)
            .collect();
        assert_eq!(aside, [1, 2, 4]);
        // Changes up to `confirmed_seq` are never applied or set aside again.
        assert!(base.apply_fetched(&fetched).unwrap().0.is_empty());
        assert_eq!(base.db().set_aside_rows().unwrap().len(), 3);
        assert!(base.db().outbox().unwrap().is_empty());
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
        assert_eq!(base.db().summary(id).unwrap().unwrap(), before);
        assert!(base.db().set_aside_rows().unwrap().is_empty());
        assert_eq!(base.db().confirmed(id).unwrap(), Some(0));
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
        assert!(base.db().set_aside_rows().unwrap().is_empty());
        assert_eq!(base.db().confirmed(other).unwrap(), None);

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
            base.db().future_bodies(newer_app_record).unwrap(),
            [envelope]
        );
        assert!(matches!(
            base.get(newer_app_record),
            Err(Error::NeedsUpdate)
        ));

        // Even a fetched change that cannot decode cannot advance a stored
        // object whose type is already newer than this build's definition.
        let state = base.db().state(id).unwrap().unwrap().1;
        let mut future = base.db().summary(id).unwrap().unwrap();
        future.ty.version = 2;
        base.db()
            .put(
                &ObjectRow {
                    summary: future.clone(),
                    state,
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
        assert_eq!(base.db().summary(id).unwrap().unwrap(), future);
        assert!(base.db().set_aside_rows().unwrap().is_empty());
        assert_eq!(base.db().confirmed(id).unwrap(), Some(0));
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
        assert_eq!(base.db().confirmed(id).unwrap(), Some(0));

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
        assert_eq!(base.db().confirmed(id).unwrap(), Some(1));
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
        let mut db = base.db();
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
