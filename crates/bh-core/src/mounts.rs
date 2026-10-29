//! Bases shown in a folder of another base. Full devices show a mounted base's
//! contents in place: in the folder's tree, its base's trash and export, and
//! by following links to where an item moved.

use crate::account::{Account, Data};
use crate::export::ExportSummary;
use crate::objects::ObjectSummary;
use crate::{Base, BaseId, Error, ObjectId, grants};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use ts_rs::TS;

/// Base `base` shows in base `parent`'s folder `folder`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct Mount {
    /// The mounted base.
    #[ts(type = "string")]
    pub base: BaseId,
    /// The base whose folder shows it.
    #[ts(type = "string")]
    pub parent: BaseId,
    /// The folder in `parent` that shows it.
    #[ts(type = "string")]
    pub folder: ObjectId,
}

/// One row of a full device's tree: an object, the base it lives in, and,
/// for a granted folder, the base it shows and who else can read it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct TreeItem {
    /// The object.
    #[serde(flatten)]
    pub summary: ObjectSummary,
    /// The base the object lives in.
    #[ts(type = "string")]
    pub base: BaseId,
    /// For a granted folder, the base it shows.
    #[ts(type = "string | null")]
    pub mounted: Option<BaseId>,
    /// The names of the apps that can read a granted folder, sorted; empty
    /// unless `mounted`.
    pub readers: Vec<String>,
}

/// The mounts below `base`, transitively, each once.
fn below(mounts: &BTreeMap<BaseId, Mount>, base: BaseId) -> Vec<Mount> {
    let (mut out, mut seen, mut queue) = (Vec::new(), HashSet::from([base]), vec![base]);
    while let Some(parent) = queue.pop() {
        for mount in mounts.values() {
            if mount.parent == parent && seen.insert(mount.base) {
                out.push(*mount);
                queue.push(mount.base);
            }
        }
    }
    out
}

impl Account {
    /// Cached account data and its mounts; both empty on app devices.
    fn mount_view(&self) -> (Option<Data>, BTreeMap<BaseId, Mount>) {
        let data = self.cached_data();
        let mounts = data.as_ref().map(grants::mounts).unwrap_or_default();
        (data, mounts)
    }

    /// A mounted base, or `None` when this device doesn't have it yet.
    fn open_mounted(&self, id: BaseId) -> Result<Option<Base>, Error> {
        match self.base(id) {
            Ok(base) => Ok(Some(base)),
            Err(Error::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn tree_items(
        &self,
        (data, mounts): &(Option<Data>, BTreeMap<BaseId, Mount>),
        base: BaseId,
        list: Vec<ObjectSummary>,
    ) -> Vec<TreeItem> {
        list.into_iter()
            .map(|summary| {
                let mounted = mounts
                    .values()
                    .find(|m| (m.parent, m.folder) == (base, summary.id))
                    .map(|m| m.base);
                let mut readers: Vec<String> = match (mounted, data) {
                    (Some(mounted), Some(data)) => grants::readers(data, mounted)
                        .into_iter()
                        .map(|device| self.app_reader_name(device))
                        .collect(),
                    _ => Vec::new(),
                };
                readers.sort();
                TreeItem {
                    summary,
                    base,
                    mounted,
                    readers,
                }
            })
            .collect()
    }

    /// The objects shown under `parent` in `base` (`None` for the top level),
    /// as [`Base::children`] lists them. Under a granted folder, the contents
    /// of the base it shows follow the folder's own. Never contacts the server.
    ///
    /// # Errors
    /// Returns the errors of [`Self::base`] and [`Base::children`].
    pub fn tree_children(
        &self,
        base: BaseId,
        parent: Option<ObjectId>,
    ) -> Result<Vec<TreeItem>, Error> {
        let view = self.mount_view();
        let mut out = self.tree_items(&view, base, self.base(base)?.children(parent)?);
        let shown = view
            .1
            .values()
            .find(|m| Some((m.parent, m.folder)) == parent.map(|p| (base, p)))
            .map(|m| m.base);
        if let Some(mounted) = shown
            && let Some(open) = self.open_mounted(mounted)?
        {
            let items = self.tree_items(&view, mounted, open.children(None)?);
            out.extend(items);
        }
        Ok(out)
    }

    /// The trash of `base` and of every base shown in its folders, the most
    /// recently changed first. Never contacts the server.
    ///
    /// # Errors
    /// Returns the errors of [`Self::base`] and [`Base::trash`].
    pub fn trash(&self, base: BaseId) -> Result<Vec<TreeItem>, Error> {
        let view = self.mount_view();
        let mut out = self.tree_items(&view, base, self.base(base)?.trash()?);
        for mount in below(&view.1, base) {
            if let Some(open) = self.open_mounted(mount.base)? {
                let items = self.tree_items(&view, mount.base, open.trash()?);
                out.extend(items);
            }
        }
        out.sort_by_key(|item| std::cmp::Reverse(item.summary.updated_at));
        Ok(out)
    }

    /// Writes a readable, unencrypted copy of `base` to a new or empty
    /// directory, with the contents of each granted folder in it in place.
    /// See [`Base::export`].
    ///
    /// # Errors
    /// Returns the errors of [`Self::base`] and [`Base::export`].
    pub async fn export(&self, base: BaseId, dir: &Path) -> Result<ExportSummary, Error> {
        let (_, mounts) = self.mount_view();
        let mut bases = vec![(self.base(base)?, None)];
        for mount in below(&mounts, base) {
            if let Some(open) = self.open_mounted(mount.base)? {
                bases.push((open, Some(mount.folder)));
            }
        }
        crate::export::run(&bases, dir).await
    }

    /// The base where object `id`, as named in `base`, lives now: `base`
    /// itself, or where its copy there moved, following each later move.
    /// Never contacts the server.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] when no base open here has a live copy,
    /// or the errors of [`Self::base`].
    pub fn locate(&self, base: BaseId, id: ObjectId) -> Result<BaseId, Error> {
        let (mut at, mut seen) = (base, HashSet::new());
        while seen.insert(at) {
            let open = self.base(at)?;
            match open.moved_to(id)? {
                Some(next) => at = next,
                None => return open.get(id)?.map(|_| at).ok_or(Error::NotFound),
            }
        }
        Err(Error::NotFound)
    }

    /// The ordinary base whose copy of object `id` is a marker of its move to
    /// `base`, where its earlier versions stay; `None` if it didn't move or
    /// that base isn't here. Reads local stores only.
    pub fn moved_from(&self, base: BaseId, id: ObjectId) -> Option<BaseId> {
        self.bases()
            .into_iter()
            .filter(|summary| !summary.hidden && summary.id != base)
            .map(|summary| summary.id)
            .find(|&other| {
                self.base(other)
                    .and_then(|open| open.moved_to(id))
                    .is_ok_and(|to| to == Some(base))
            })
    }
}
