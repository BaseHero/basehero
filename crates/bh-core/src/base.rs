//! `Base`: one base's objects, kept in its own encrypted store.

use crate::note::{self, Live, NoteDoc};
use crate::objects::{self, Meta, NewObject, ObjectSummary};
use crate::store::{BaseDb, ObjectRow};
use crate::types::{self, BASE, FOLDER, NOTE, PROJECT, TYPE, TypeDef, TypeRef};
use crate::{Error, SecretStore};
use bh_crypto::Secret;
use bh_proto::{BaseId, DeviceId, ObjectId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use ts_rs::TS;
use yrs::updates::decoder::Decode;
use yrs::{Doc, ReadTxn, StateVector, Transact, TransactionMut, Update};
use zeroize::Zeroizing;

/// The largest local update, as the largest change the server takes.
pub(crate) const MAX_UPDATE: usize = 8 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum Mode {
    ReadWrite,
    ReadOnly,
}

/// A base's key, `BK`: 32 random bytes. Never printed.
pub(crate) struct BaseKey(Secret<32>);

impl BaseKey {
    #[allow(dead_code, reason = "accounts will unwrap base keys")]
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

struct Inner {
    id: BaseId,
    mode: Mode,
    device: Option<DeviceId>,
    key: BaseKey,
    /// The yrs client ID of this process's core edits, used only under the
    /// store lock against the stored state, so its clock never repeats.
    client: u64,
    db: Mutex<BaseDb>,
    /// Open documents, one per object; always lock `db` first.
    live: Mutex<HashMap<ObjectId, Weak<Live>>>,
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

/// Types that the tree, `move_to` and `delete` leave alone.
fn structural(name: &str) -> bool {
    matches!(name, TYPE | BASE)
}

impl Base {
    /// Opens a base's store at `path` with its key `base.<id>.dbkey` from
    /// `secrets`, made on first use.
    #[allow(dead_code, reason = "accounts will open bases")]
    pub(crate) fn open(
        path: &Path,
        secrets: &dyn SecretStore,
        id: BaseId,
        key: BaseKey,
        mode: Mode,
        device: Option<DeviceId>,
    ) -> Result<Base, Error> {
        let name = format!("base.{id}.dbkey");
        let db_key = match secrets.get(&name)? {
            Some(key) => key,
            None => {
                let key = Zeroizing::new(bh_crypto::random::<32>().to_vec());
                secrets.put(&name, &key)?;
                key
            }
        };
        Self::open_store(path, &db_key, id, key, mode, device)
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
        Ok(Base {
            inner: Arc::new(Inner {
                id,
                mode,
                device,
                key,
                client: u64::from(u32::from_le_bytes(bh_crypto::random::<4>())),
                db: Mutex::new(db),
                live: Mutex::new(HashMap::new()),
                #[cfg(feature = "test-support")]
                fail_next_save: Default::default(),
            }),
        })
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

    fn db(&self) -> MutexGuard<'_, BaseDb> {
        lock(&self.inner.db)
    }

    fn writable(&self) -> Result<(), Error> {
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

    /// The definition an existing object is edited under. Without one the
    /// object is of a newer version, and is left untouched.
    fn editable(&self, db: &BaseDb, ty: &TypeRef) -> Result<TypeDef, Error> {
        self.def(db, ty)?.ok_or(Error::NeedsUpdate)
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

    /// Stores `doc` and its summary and, for local edits, their updates in
    /// the outbox, in one transaction.
    fn save(
        &self,
        db: &mut BaseDb,
        id: ObjectId,
        doc: &Doc,
        outbox: &[&[u8]],
        by: Option<DeviceId>,
    ) -> Result<(), Error> {
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
        db.put(&ObjectRow { summary, state }, outbox)
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
        self.save(db, id, &doc, &[&update], self.inner.device)?;
        self.share(id, &update);
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
        self.save(db, id, &doc, &[&update], self.inner.device)
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
        let Some(mut summary) = db.summary(id)? else {
            return Ok(None);
        };
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
    /// process, shared by every caller. An object of a newer version opens to
    /// be read, but refuses edits.
    pub fn note(&self, id: ObjectId) -> Result<NoteDoc, Error> {
        let db = self.db();
        let mut live = lock(&self.inner.live);
        if let Some(open) = live.get(&id).and_then(Weak::upgrade) {
            return Ok(NoteDoc::new(self.clone(), open));
        }
        let (ty, state) = db.state(id)?.ok_or(Error::NotFound)?;
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
        let ty = db.type_of(live.id)?.ok_or(Error::NotFound)?;
        self.editable(&db, &ty)?;
        live.doc
            .transact_mut()
            .apply_update(decoded)
            .map_err(|_| Error::invalid("the update doesn't apply"))?;
        let mut unsaved = lock(&live.unsaved);
        unsaved.push(update.to_vec());
        let outbox: Vec<&[u8]> = unsaved.iter().map(Vec::as_slice).collect();
        self.save(&mut db, live.id, &live.doc, &outbox, self.inner.device)?;
        unsaved.clear();
        drop((unsaved, db));
        live.publish(origin, update);
        Ok(())
    }

    /// Applies another device's update, as sync does: whatever the object's
    /// version, without the outbox.
    #[allow(dead_code, reason = "sync will apply remote changes")]
    pub(crate) fn apply_remote(
        &self,
        id: ObjectId,
        update: &[u8],
        by: Option<DeviceId>,
    ) -> Result<(), Error> {
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
        self.save(&mut db, id, &doc, &outbox, by)?;
        if let Some(unsaved) = &mut unsaved {
            unsaved.clear();
        }
        drop((unsaved, db));
        if let Some(live) = live {
            live.publish(0, update);
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

/// Hooks for tests without a server.
#[cfg(feature = "test-support")]
impl Base {
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
