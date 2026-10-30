//! Daily consolidation and retention of device-local backup records.
use super::format::{self, ChangeRecord, FileKind};
use super::restore::{valid_keys_file, valid_snapshot};
use super::{BackupFolder, FolderError};
use crate::BaseId;
use crate::account::Account;
use crate::store::BackupRow;
use std::collections::{BTreeMap, BTreeSet, HashSet};

const THIRTY_DAYS: i64 = 30 * 86_400_000;

fn error(error: crate::Error) -> FolderError {
    FolderError::Other(format!("backup progress: {error}"))
}

fn entries(folder: &dyn BackupFolder, dir: &str) -> Result<Vec<super::FolderEntry>, FolderError> {
    folder.list(dir)
}

fn delete(
    account: &Account,
    folder: &dyn BackupFolder,
    path: &str,
    size: u64,
    row: &mut BackupRow,
    generation: u64,
) -> Result<(), FolderError> {
    if account.backup_stopped(generation) {
        return Err(FolderError::Other("backup stopped".into()));
    }
    folder.remove(path)?;
    row.bytes = row.bytes.saturating_sub(size);
    Ok(())
}

pub(super) fn tree_size(folder: &dyn BackupFolder, path: &str) -> Result<u64, FolderError> {
    let mut size: u64 = 0;
    for entry in entries(folder, path)? {
        let child = format!("{path}/{}", entry.name);
        size = size.saturating_add(if entry.dir {
            tree_size(folder, &child)?
        } else {
            entry.size
        });
    }
    Ok(size)
}

fn run_from_file(name: &str, suffix: &str) -> Option<i64> {
    name.strip_suffix(suffix).and_then(format::parse_run)
}

fn log_day(name: &str) -> Option<(&str, i64)> {
    let stem = name.strip_suffix(".bhl")?;
    if let Some((day, run)) = stem.split_once('-') {
        if day.len() != 8 {
            return None;
        }
        let at = format::parse_run(run)?;
        let valid_day = format::parse_run(&format!("{day}T000000000Z"))?;
        (format::run_name(valid_day).get(..8)? == day).then_some((day, at))
    } else {
        let at = format::parse_run(stem)?;
        Some((stem.get(..8)?, at))
    }
}

impl Account {
    /// Consolidates older UTC days and discards records no longer needed for retained points.
    /// A failed maintenance pass leaves the completed run intact and is retried on a later run.
    pub(crate) async fn merge_and_prune(
        &self,
        folder: &dyn BackupFolder,
        run: i64,
        mut row: BackupRow,
        location: &super::BackupLocation,
        generation: u64,
    ) -> Result<(), FolderError> {
        let day = format::run_name(run)[..8].to_string();
        if row
            .merged_day
            .as_deref()
            .is_some_and(|last| last >= day.as_str())
        {
            return Ok(());
        }
        let dir = format::device_dir(self.id(), self.device_id());
        let result = maintain(self, folder, &dir, &day, run, &mut row, generation)
            .and_then(|()| tree_size(folder, &dir).map(|size| row.bytes = size));
        if result.is_ok() {
            row.merged_day = Some(day);
        }
        // Store even partial deletion accounting. A failed pass is not marked done.
        self.update_backup_progress(&row, row.generation, location)
            .map_err(error)?;
        result
    }
}

fn maintain(
    account_handle: &Account,
    folder: &dyn BackupFolder,
    dir: &str,
    today: &str,
    run: i64,
    row: &mut BackupRow,
    generation: u64,
) -> Result<(), FolderError> {
    let logs_dir = format!("{dir}/log");
    let mut days: BTreeMap<&str, Vec<super::FolderEntry>> = BTreeMap::new();
    let listed = entries(folder, &logs_dir)?;
    for entry in &listed {
        if !entry.dir
            && let Some((day, _)) = log_day(&entry.name)
            && day < today
        {
            days.entry(day).or_default().push(entry.clone());
        }
    }
    for (day, inputs) in days {
        if inputs.len() < 2 {
            continue;
        }
        let mut valid = Vec::new();
        let mut bodies = Vec::new();
        let mut seen = HashSet::new();
        for entry in inputs {
            let path = format!("{logs_dir}/{}", entry.name);
            let bytes = folder.read(&path)?;
            if let Ok(records) = format::decode(FileKind::Log, &bytes) {
                if records.is_empty() {
                    continue;
                }
                for record in records {
                    if seen.insert(record.to_vec()) {
                        bodies.push(record.to_vec());
                    }
                }
                valid.push((path, entry.size));
            }
        }
        if valid.is_empty() {
            continue;
        }
        let output = format!("{dir}/{}", format::merged_path(day, &format::run_name(run)));
        let bytes = format::encode(FileKind::Log, &bodies);
        // A new name is used for every attempt. Verify the closing record before removing inputs.
        if entries(folder, &logs_dir)?
            .iter()
            .any(|entry| output.rsplit('/').next() == Some(entry.name.as_str()))
        {
            return Err(FolderError::Other("merged log name already exists".into()));
        }
        if account_handle.backup_stopped(generation) {
            return Err(FolderError::Other("backup stopped".into()));
        }
        folder.write(&output, &bytes)?;
        if folder.read(&output)? != bytes {
            return Err(FolderError::Other("incomplete merged log".into()));
        }
        row.bytes = row.bytes.saturating_add(bytes.len() as u64);
        for (path, size) in valid {
            delete(account_handle, folder, &path, size, row, generation)?;
        }
    }

    let cutoff = run.saturating_sub(THIRTY_DAYS);
    let keys_dir = format!("{dir}/keys");
    let keys: Vec<_> = entries(folder, &keys_dir)?
        .into_iter()
        .filter_map(|entry| {
            (!entry.dir)
                .then(|| run_from_file(&entry.name, ".bhk").map(|at| (entry, at)))
                .flatten()
        })
        .collect();
    let mut valid_keys = BTreeMap::new();
    for (entry, at) in &keys {
        let path = format!("{keys_dir}/{}", entry.name);
        let bytes = folder.read(&path)?;
        if let Some(file) =
            valid_keys_file(&bytes, account_handle.id(), account_handle.device_id(), *at)
        {
            valid_keys.insert(*at, file);
        }
    }
    // With no usable keys, no snapshot or part is known to be orphaned.
    if valid_keys.is_empty() {
        return Ok(());
    }
    let newest_old = valid_keys.keys().filter(|at| **at < cutoff).max().copied();
    let mut wrappers = BTreeSet::new();
    for (entry, at) in keys {
        let path = format!("{keys_dir}/{}", entry.name);
        if at < cutoff && Some(at) != newest_old {
            delete(account_handle, folder, &path, entry.size, row, generation)?;
        } else if let Some(file) = valid_keys.remove(&at) {
            wrappers.extend(file.wrappers.into_iter().map(|w| w.base));
        }
    }
    let snapshots_dir = format!("{dir}/snapshots");
    let mut oldest = BTreeMap::new();
    for base_entry in entries(folder, &snapshots_dir)? {
        if !base_entry.dir {
            continue;
        }
        let Ok(base) = base_entry.name.parse::<BaseId>() else {
            continue;
        };
        let base_dir = format!("{snapshots_dir}/{base}");
        let snapshots: Vec<_> = entries(folder, &base_dir)?
            .into_iter()
            .filter_map(|entry| {
                (!entry.dir)
                    .then(|| run_from_file(&entry.name, ".bhs").map(|at| (entry, at)))
                    .flatten()
            })
            .collect();
        let mut populated_snapshots = BTreeSet::new();
        let mut empty_snapshots = BTreeSet::new();
        for (entry, at) in &snapshots {
            let path = format!("{base_dir}/{}", entry.name);
            if let Ok(records) = format::decode(FileKind::Snapshot, &folder.read(&path)?)
                && valid_snapshot(&records, base, *at)
            {
                if records.is_empty() {
                    empty_snapshots.insert(*at);
                } else {
                    populated_snapshots.insert(*at);
                }
            }
        }
        // Empty snapshots restore an actually empty base, but cannot replace an
        // older snapshot carrying content as the pruning anchor.
        let newest_old = populated_snapshots
            .iter()
            .filter(|at| **at < cutoff)
            .max()
            .or_else(|| empty_snapshots.iter().filter(|at| **at < cutoff).max())
            .copied();
        for (entry, at) in snapshots {
            let path = format!("{base_dir}/{}", entry.name);
            if at < cutoff && (Some(at) != newest_old || !wrappers.contains(&base)) {
                delete(account_handle, folder, &path, entry.size, row, generation)?;
            } else {
                oldest
                    .entry(base)
                    .and_modify(|current: &mut i64| *current = (*current).min(at))
                    .or_insert(at);
            }
        }
    }
    for entry in entries(folder, &logs_dir)? {
        if entry.dir {
            continue;
        }
        let Some((log_day, at)) = log_day(&entry.name) else {
            continue;
        };
        let path = format!("{logs_dir}/{}", entry.name);
        let bytes = folder.read(&path)?;
        let removable = match format::decode(FileKind::Log, &bytes) {
            // Empty per-run logs are the only record of parts-only runs.
            Ok(records) if records.is_empty() => log_day != today && at < cutoff,
            Ok(records) => records.iter().all(|body| {
                ChangeRecord::decode(body).is_ok_and(|record| {
                    oldest
                        .get(&record.base)
                        .map_or(record.run < cutoff, |snapshot| record.run <= *snapshot)
                })
            }),
            Err(_) => at < cutoff,
        };
        if removable {
            delete(account_handle, folder, &path, entry.size, row, generation)?;
        }
    }
    let parts_dir = format!("{dir}/files");
    for entry in entries(folder, &parts_dir)? {
        if !entry.dir {
            continue;
        }
        let Ok(base) = entry.name.parse::<BaseId>() else {
            continue;
        };
        if !oldest.contains_key(&base) {
            let path = format!("{parts_dir}/{base}");
            let size = tree_size(folder, &path)?;
            delete(account_handle, folder, &path, size, row, generation)?;
        }
    }
    Ok(())
}
