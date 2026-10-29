//! Moves between bases. An item, its descendants and the record types they use
//! are written into the other base with their IDs and current content, and the
//! old copies become deleted markers naming where they went. A move is recorded
//! in account data first, so the device that started it finishes it on a later
//! `refresh` if it stopped midway. A folder's first grant is such a move, of
//! its contents into a new base that the folder then shows.

use crate::account::{Account, DeviceKind, entry};
use crate::base::{self, Mode};
use crate::{BaseId, Error, Mount, ObjectId, grants, types};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// One move between bases, kept under account data's `moves` with the
/// `device` that runs it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Move {
    pub from: BaseId,
    pub to: BaseId,
    /// The item that moves, or, with `contents`, whose children move.
    pub item: ObjectId,
    pub contents: bool,
    /// Where in `to` it goes; `None` is the top level.
    pub parent: Option<ObjectId>,
    /// `to`'s name, when the move must create it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Account {
    /// Moves an item, with everything in it, from base `from` to base `to`,
    /// last under `parent` (`None` for the top level). It keeps its ID, its
    /// current content and the record types it uses; files are sealed again
    /// for `to` and uploaded, after fetching any this device hasn't
    /// downloaded. The old copies stay in `from` as deleted markers, out of its
    /// tree, trash and search, with their earlier versions. Full devices only.
    /// Needs the network for files; if the move stops midway, a later
    /// [`Self::refresh`] on this device finishes it.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on an app device or when a granted folder
    /// would move into a hidden base, [`Error::Invalid`] when `from` is `to`,
    /// the item is a type definition or a base's own object, or `to` shows
    /// inside the item, [`Error::NotFound`] for an unknown base, item or parent
    /// or an item that already moved, [`Error::ReadOnly`] when `to` is
    /// read-only, or network and storage errors.
    pub async fn move_between(
        &self,
        from: BaseId,
        id: ObjectId,
        to: BaseId,
        parent: Option<ObjectId>,
    ) -> Result<(), Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        // Mounts can have changed on another device since this one last refreshed.
        self.refresh_account_data().await?;
        if from == to {
            return Err(Error::invalid("the item is already in that base"));
        }
        let (source, target) = (self.base(from)?, self.base(to)?);
        if target.mode() != Mode::ReadWrite {
            return Err(Error::ReadOnly);
        }
        let item = source.get(id)?.ok_or(Error::NotFound)?;
        if source.moved_to(id)?.is_some() {
            return Err(Error::NotFound);
        }
        if base::structural(&item.ty.name) {
            return Err(Error::invalid("this object can't move"));
        }
        if let Some(parent) = parent
            && (target.get(parent)?.is_none() || target.moved_to(parent)?.is_some())
        {
            return Err(Error::NotFound);
        }
        // Granted folders in what moves go with it.
        let mounts = self
            .cached_data()
            .map(|data| grants::mounts(&data))
            .unwrap_or_default();
        let moving: HashSet<ObjectId> = source.subtree(id)?.into_iter().collect();
        let carried = |m: &Mount| m.parent == from && moving.contains(&m.folder);
        if self.is_hidden(to)? && mounts.values().any(carried) {
            return Err(Error::Forbidden);
        }
        let (mut seen, mut shown) = (HashSet::new(), to);
        while let Some(mount) = mounts.get(&shown).filter(|_| seen.insert(shown)) {
            if carried(mount) {
                return Err(Error::invalid("a granted folder can't move into itself"));
            }
            shown = mount.parent;
        }
        self.start_move(Move {
            from,
            to,
            item: id,
            contents: false,
            parent,
            name: None,
        })
        .await
    }

    /// The base that folder `folder` in base `base` shows. A folder's first
    /// grant makes it: a new base named as the folder, the folder's contents
    /// moved in, and a mount in account data. Granting it again finishes a
    /// first grant that stopped midway, so nothing is copied twice.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] for a hidden base, [`Error::NotFound`] for
    /// an unknown base or a missing or deleted folder, [`Error::Invalid`] for
    /// anything but a folder or project, or the errors of a move.
    pub(crate) async fn grant_folder(
        &self,
        base: BaseId,
        folder: ObjectId,
    ) -> Result<BaseId, Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        self.check_grantable(base)?;
        let item = self
            .base(base)?
            .get(folder)?
            .filter(|item| !item.deleted)
            .ok_or(Error::NotFound)?;
        if ![types::FOLDER, types::PROJECT].contains(&item.ty.name.as_str()) {
            return Err(Error::invalid("only a folder or project can be granted"));
        }
        let shows = move |m: &Mount| (m.parent, m.folder) == (base, folder);
        if let Some(mount) = self.mounts().into_iter().find(shows) {
            self.finish_first_grant(mount).await?;
            return Ok(mount.base);
        }
        let name = match item.title.trim() {
            "" => "Untitled".to_owned(),
            title => title.to_owned(),
        };
        let mv = Move {
            from: base,
            to: BaseId::random(),
            item: folder,
            contents: true,
            parent: None,
            name: Some(name),
        };
        let key = ObjectId::random().to_string();
        let (record, recorded) = (self.move_record(&mv), key.clone());
        let to = mv.to;
        // Another device may have granted it first; then its mount is used.
        let found = Arc::new(Mutex::new(None));
        let earlier = found.clone();
        self.update_data_with_envelope(move |data, _| {
            let mount = grants::mounts(data).into_values().find(shows);
            *earlier.lock().unwrap() = mount;
            if mount.is_some() {
                return false;
            }
            grants::edit(data, |data| {
                let place = json!({ "parent": base.to_string(), "folder": folder.to_string() });
                entry(data, "mounts").insert(to.to_string(), place);
                entry(data, "moves").insert(recorded.clone(), record.clone());
            });
            true
        })
        .await?;
        let earlier = *found.lock().unwrap();
        match earlier {
            Some(mount) => {
                self.finish_first_grant(mount).await?;
                Ok(mount.base)
            }
            None => {
                self.run_move(&key, &mv).await?;
                Ok(to)
            }
        }
    }

    /// Runs the move this device recorded for `mount`'s first grant, if any.
    async fn finish_first_grant(&self, mount: Mount) -> Result<(), Error> {
        for (key, mv) in self.my_moves() {
            if (mv.from, mv.to, mv.item) == (mount.parent, mount.base, mount.folder) {
                self.run_move(&key, &mv).await?;
            }
        }
        Ok(())
    }

    /// `mv` as kept in account data, run by this device.
    fn move_record(&self, mv: &Move) -> Value {
        let mut value = serde_json::to_value(mv).expect("JSON");
        value["device"] = Value::from(self.device_id().to_string());
        value
    }

    /// Records `mv` in account data under a new key, for this device, then runs it.
    pub(crate) async fn start_move(&self, mv: Move) -> Result<(), Error> {
        let this = self.clone();
        self.run(async move {
            let key = ObjectId::random().to_string();
            let value = this.move_record(&mv);
            let recorded = key.clone();
            this.update_data(move |data| {
                entry(data, "moves").insert(recorded.clone(), value.clone());
            })
            .await?;
            this.run_move(&key, &mv).await
        })
        .await
    }

    /// Carries out the move recorded under `key`. Each step is safe to repeat:
    /// an item `to` already has is left as it is, and one already marked isn't
    /// marked again.
    pub(crate) async fn run_move(&self, key: &str, mv: &Move) -> Result<(), Error> {
        let _one = self.move_lock().lock().await;
        if let Some(name) = &mv.name
            && matches!(self.base(mv.to), Err(Error::NotFound))
        {
            self.create_base_at(mv.to, name).await?;
        }
        self.settle_grants().await?;
        let (from, to) = (self.base(mv.from)?, self.base(mv.to)?);
        let mut ids = from.subtree(mv.item)?;
        let roots: HashSet<ObjectId> = if mv.contents {
            ids.retain(|id| *id != mv.item);
            let children = from.db()?.siblings(Some(mv.item))?;
            children.into_iter().map(|(id, _)| id).collect()
        } else {
            HashSet::from([mv.item])
        };
        let defs = from.types()?;
        let mut defined: HashSet<_> = to
            .types()?
            .into_iter()
            .map(|def| (def.name, def.version))
            .collect();
        for &id in &ids {
            // A marker of an earlier move stays where it is.
            if from.moved_to(id)?.is_some() {
                continue;
            }
            let Some(summary) = from.get(id)? else {
                continue;
            };
            let ty = (summary.ty.name.clone(), summary.ty.version);
            if !types::is_core(&ty.0)
                && defined.insert(ty.clone())
                && let Some(def) = defs.iter().find(|d| (&d.name, d.version) == (&ty.0, ty.1))
            {
                to.define_type(def.clone())?;
            }
            let arrived = to.get(id)?.is_some() && to.moved_to(id)?.is_none();
            if ty.0 == types::FILE && !arrived {
                // A file that can't be read moves without its content.
                match from.file_bytes(id).await {
                    Ok(bytes) => {
                        let bytes = Zeroizing::new(bytes);
                        to.add_file_parts(id, &from.file_key(id)?, &bytes)?;
                    }
                    Err(Error::NotFound | Error::Crypto) => {}
                    Err(error) => return Err(error),
                }
            }
            let (_, state) = from.db()?.state(id)?.ok_or(Error::NotFound)?;
            let position = match roots.contains(&id) {
                true => Some(to.last_position(mv.parent)?),
                false => None,
            };
            to.import(id, &state, position.as_deref().map(|p| (mv.parent, p)))?;
        }
        for &id in &ids {
            if from.moved_to(id)?.is_none() {
                from.mark_moved(id, mv.to)?;
            }
        }
        // Nothing may keep either base open afterwards: send both bases'
        // changes and all moved file parts before the move counts as done.
        to.flush().await?;
        from.flush().await?;
        to.wait_for_file_uploads().await?;
        // The uploader marks files uploaded in the object's sealed fields.
        to.flush().await?;
        // Granted folders that moved show in `to` now.
        let key = key.to_owned();
        let mut moved = HashSet::new();
        for id in ids {
            if to.get(id)?.is_some() && to.moved_to(id)?.is_none() {
                moved.insert(id.to_string());
            }
        }
        let (from_id, to_id) = (mv.from.to_string(), mv.to.to_string());
        self.update_data(move |data| {
            grants::edit(data, |data| {
                entry(data, "moves").remove(&key);
                for mount in entry(data, "mounts").values_mut() {
                    let carried = mount.get("parent").and_then(Value::as_str) == Some(&from_id)
                        && mount
                            .get("folder")
                            .and_then(Value::as_str)
                            .is_some_and(|folder| moved.contains(folder));
                    if carried {
                        mount["parent"] = Value::from(to_id.clone());
                    }
                }
            })
        })
        .await?;
        self.settle_grants().await
    }

    /// Runs every move recorded for this device, as after a crash. Each runs on
    /// its own, so one that fails doesn't hold up the rest.
    pub(crate) async fn resume_moves(&self) -> Result<(), Error> {
        let mut first = None;
        for (key, mv) in self.my_moves() {
            if let Err(error) = self.run_move(&key, &mv).await {
                first.get_or_insert(error);
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// The moves recorded for this device in cached account data, by key.
    fn my_moves(&self) -> Vec<(String, Move)> {
        let device = self.device_id().to_string();
        self.cached_data()
            .and_then(|data| data.get("moves")?.as_object().cloned())
            .into_iter()
            .flatten()
            .filter(|(_, mv)| mv.get("device").and_then(Value::as_str) == Some(&device))
            .filter_map(|(key, mv)| Some((key, serde_json::from_value(mv).ok()?)))
            .collect()
    }
}
