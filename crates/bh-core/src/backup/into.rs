//! Rebuilding an offline backup into fresh account bases.

use super::restore::OpenedBackup;
use crate::account::{Account, DeviceKind};
use crate::grants;
use crate::types::{BASE, FILE, TYPE, TypeDef};
use crate::{BaseId, Error, ObjectId};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeSet, HashMap};
use ts_rs::TS;
use zeroize::Zeroizing;

/// Bases created from an offline backup and files unavailable at that point.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct RestoreSummary {
    /// Original and newly created base IDs, in creation order.
    #[ts(type = "[string, string][]")]
    pub restored: Vec<(BaseId, BaseId)>,
    /// Wrappers that could not be opened at this point.
    pub locked: usize,
    /// Bases without a snapshot at this point.
    pub missing: usize,
    /// File IDs whose content was unavailable or unreadable in the backup.
    #[ts(type = "string[]")]
    pub missing_files: Vec<ObjectId>,
    /// Records that could not be opened or applied at this point.
    pub unreadable: usize,
    /// Record files whose closing record or contents were invalid.
    pub ignored_files: Vec<String>,
}

impl OpenedBackup {
    /// Restores selected bases and their mounted descendants into new bases of a full account.
    /// Each new base has its own ID and key; the source account and backup are unchanged.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] for an app device, [`Error::NotFound`] for
    /// a base not open at this point, or a storage/network error while rebuilding.
    pub async fn restore_into(
        &self,
        account: &Account,
        at: i64,
        bases: &[BaseId],
        label: &str,
    ) -> Result<RestoreSummary, Error> {
        if account.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let rebuilt = self.rebuild(at).await?;
        let mut chosen = BTreeSet::new();
        for id in bases {
            if !rebuilt.bases.contains_key(id) {
                return Err(Error::NotFound);
            }
            chosen.insert(*id);
        }
        loop {
            let previous = chosen.len();
            for (id, mount) in &rebuilt.mounts {
                if chosen.contains(&mount.parent) && rebuilt.bases.contains_key(id) {
                    chosen.insert(*id);
                }
            }
            if chosen.len() == previous {
                break;
            }
        }
        // Resolve the entire mapping before writing any object, so move markers
        // can point to the new target even when it is created later.
        let mut mapping = HashMap::new();
        let mut created = Vec::new();
        for id in chosen {
            let source = rebuilt.bases.get(&id).expect("chosen base exists");
            let name = format!("{} ({label})", source.name());
            let destination = if rebuilt.hidden.contains(&id) {
                let password = self.hidden_passwords.get(&id).ok_or(Error::NotFound)?;
                account
                    .create_hidden_base(&name, Zeroizing::new((**password).clone()))
                    .await?
            } else {
                account.create_base(&name).await?
            };
            mapping.insert(id, destination.id());
            created.push((id, destination));
        }
        let mut missing = BTreeSet::new();
        for (old, destination) in &created {
            let source = rebuilt.bases.get(old).expect("chosen base exists");
            let states = source.db()?.objects_for_backfill()?;
            // Definitions are base-keyed, and records need their definitions
            // before their states are indexed in the destination store.
            for (id, _) in &states {
                let Some(summary) = source.get(*id)? else {
                    continue;
                };
                if summary.ty.name == TYPE {
                    let def: TypeDef = serde_json::from_value(
                        summary
                            .fields
                            .get("def")
                            .cloned()
                            .ok_or(Error::NeedsUpdate)?,
                    )
                    .map_err(|_| Error::NeedsUpdate)?;
                    destination.define_type(def)?;
                }
            }
            for (id, state) in states {
                let ty = source.db()?.type_of(id)?.ok_or(Error::NotFound)?;
                if ty.name == BASE || ty.name == TYPE {
                    continue;
                }
                let moved_to = source.moved_to(id)?;
                if moved_to.is_some_and(|target| !mapping.contains_key(&target)) {
                    continue;
                }
                destination.restore_object(id, &state, &mapping)?;
                if ty.name == FILE && moved_to.is_none() {
                    match source.file_bytes(id).await {
                        Ok(content) => {
                            let content = Zeroizing::new(content);
                            let key = destination.file_key(id)?;
                            destination.add_file_parts(id, &key, &content)?;
                        }
                        Err(Error::NotFound | Error::Crypto | Error::Storage(_)) => {
                            missing.insert(id);
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        let mounts: Vec<_> = rebuilt
            .mounts
            .values()
            .filter_map(|mount| {
                let (&child, &parent) = (mapping.get(&mount.base)?, mapping.get(&mount.parent)?);
                Some((child, parent, mount.folder))
            })
            .collect();
        if !mounts.is_empty() {
            account
                .update_data(move |data| {
                    grants::edit(data, |data| {
                        let entry = data.entry("mounts").or_insert_with(|| json!({}));
                        let map = entry.as_object_mut().expect("mounts are an object");
                        for (child, parent, folder) in &mounts {
                            map.insert(
                                child.to_string(),
                                json!({ "parent": parent, "folder": folder }),
                            );
                        }
                    });
                })
                .await?;
        }
        // A caller may close this device immediately after restoring. Finish
        // uploading the rebuilt content before reporting that it is ready.
        for (_, base) in &created {
            base.wait_for_file_uploads().await?;
            base.flush().await?;
        }
        Ok(RestoreSummary {
            restored: created
                .into_iter()
                .map(|(old, base)| (old, base.id()))
                .collect(),
            locked: rebuilt.report.locked,
            missing: rebuilt.report.missing,
            missing_files: missing.into_iter().collect(),
            unreadable: rebuilt
                .report
                .bases
                .iter()
                .map(|base| base.unreadable)
                .sum(),
            ignored_files: rebuilt.report.ignored_files,
        })
    }
}
