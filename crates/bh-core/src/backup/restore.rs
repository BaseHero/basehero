//! Reading encrypted backup records and rebuilding local, serverless bases.

use super::format::{self, ChangeRecord, FileKind, KeysFile};
use super::{BackupFolder, FolderError};
use crate::base::{Base, BaseKey, Mode};
use crate::basekeys::BaseKeys;
use crate::core::{Core, derive};
use crate::envelope;
use crate::files;
use crate::grants;
use crate::hidden::HiddenKey;
use crate::keys::{self, RecoveryKit};
use crate::{AccountId, BaseId, DeviceId, Error, ExportSummary, Mount, ObjectId};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bh_crypto::Secret;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use ts_rs::TS;
use yrs::{ReadTxn, Transact};
use zeroize::Zeroizing;

/// A device's newest complete, readable keys record in a backup folder.
#[derive(Clone, Debug)]
pub struct BackupListing {
    /// The backed-up account.
    pub account: AccountId,
    /// The device that wrote these files.
    pub device: DeviceId,
    /// The account email displayed when this file was written.
    pub email: String,
    /// The account server, shown for identification but not contacted.
    pub server: url::Url,
    /// The time of the newest valid keys record, in Unix milliseconds.
    pub written_at: i64,
}

/// A base available at one backup point.
#[derive(Clone, Debug)]
pub struct RestorableBase {
    /// The original base ID.
    pub id: BaseId,
    /// The original name.
    pub name: String,
    /// Whether this base requires an additional password.
    pub hidden: bool,
    /// Where this base appears in another base.
    pub mount: Option<Mount>,
    /// Number of notes.
    pub notes: usize,
    /// Number of non-note records.
    pub records: usize,
    /// Number of files.
    pub files: usize,
}

/// Objects checked in one restored base.
#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
#[ts(rename_all = "camelCase")]
pub struct BaseCheck {
    /// Original base ID.
    #[ts(type = "string")]
    pub id: BaseId,
    /// Original base name.
    pub name: String,
    /// Number of objects restored.
    pub objects: usize,
    /// Number of records that could not be opened or decoded, or whose edits could not be applied.
    pub unreadable: usize,
    /// Files with unavailable or unauthenticated parts.
    #[ts(type = "string[]")]
    pub missing_files: Vec<ObjectId>,
}

/// Result of checking a point before exporting it.
#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
#[ts(rename_all = "camelCase")]
pub struct CheckReport {
    /// Bases whose snapshots and wrappers could be opened.
    pub bases: Vec<BaseCheck>,
    /// Wrappers that could not be opened at this point.
    pub locked: usize,
    /// Bases without a snapshot at this point.
    pub missing: usize,
    /// Damaged record files ignored while scanning the folder.
    pub ignored_files: Vec<String>,
}

struct RecordedKeys {
    at: i64,
    file: KeysFile,
}
struct RecordedChange {
    at: i64,
    base: BaseId,
    object: ObjectId,
    state: bool,
    sealed: Vec<u8>,
}
struct Snapshot {
    at: i64,
    records: Vec<Vec<u8>>,
}
struct InvalidChange {
    at: i64,
    base: Option<BaseId>,
}

/// An offline backup opened using only a password and a recovery kit.
/// Temporary encrypted stores are removed when the last handle is dropped.
pub struct OpenedBackup {
    folder: Arc<dyn BackupFolder>,
    dir: String,
    account: AccountId,
    account_keys: BTreeMap<u32, Secret<32>>,
    opened_epoch: u32,
    hidden: BTreeMap<BaseId, HiddenKey>,
    pub(super) hidden_passwords: BTreeMap<BaseId, Zeroizing<String>>,
    keys: Vec<RecordedKeys>,
    snapshots: BTreeMap<BaseId, Vec<Snapshot>>,
    logs: Vec<RecordedChange>,
    invalid: Vec<InvalidChange>,
    points: Vec<i64>,
    ignored: Vec<String>,
    temporary: PathBuf,
    rebuilt: tokio::sync::Mutex<Option<(i64, Rebuilt)>>,
}

impl Drop for OpenedBackup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.temporary);
    }
}

fn folder_error(error: FolderError) -> Error {
    Error::Storage(format!("backup folder: {error:?}"))
}

// Both retention and restore must agree on which anchors can be used.
pub(super) fn valid_keys_file(
    bytes: &[u8],
    account: AccountId,
    device: DeviceId,
    at: i64,
) -> Option<KeysFile> {
    let records = format::decode(FileKind::Keys, bytes).ok()?;
    let [record] = records.as_slice() else {
        return None;
    };
    let file: KeysFile = serde_json::from_slice(record).ok()?;
    (file.v == 1 && file.account == account && file.device == device && file.written_at == at)
        .then_some(file)
}

pub(super) fn valid_snapshot(records: &[&[u8]], base: BaseId, at: i64) -> bool {
    records.iter().all(|body| {
        ChangeRecord::decode(body)
            .is_ok_and(|record| record.state && record.base == base && record.run == at)
    })
}

fn keys_in(
    folder: &dyn BackupFolder,
    dir: &str,
    account: AccountId,
    device: DeviceId,
) -> Result<Vec<RecordedKeys>, Error> {
    let mut found = Vec::new();
    for entry in folder.list(&format!("{dir}/keys")).map_err(folder_error)? {
        let Some(at) = entry.name.strip_suffix(".bhk").and_then(format::parse_run) else {
            continue;
        };
        if entry.dir {
            continue;
        }
        let bytes = folder
            .read(&format!("{dir}/keys/{}", entry.name))
            .map_err(folder_error)?;
        if let Some(file) = valid_keys_file(&bytes, account, device, at) {
            found.push(RecordedKeys { at, file });
        }
    }
    found.sort_by_key(|item| std::cmp::Reverse(item.at));
    Ok(found)
}

/// Lists each account/device directory with a valid keys file, without a password.
///
/// # Errors
/// Returns [`Error::Storage`] when the folder cannot be read.
pub fn list_backups(folder: &dyn BackupFolder) -> Result<Vec<BackupListing>, Error> {
    let mut listings = Vec::new();
    for account in folder
        .list("")
        .map_err(folder_error)?
        .into_iter()
        .filter(|e| e.dir)
    {
        let Ok(account_id) = account.name.parse::<AccountId>() else {
            continue;
        };
        for device in folder
            .list(&account.name)
            .map_err(folder_error)?
            .into_iter()
            .filter(|e| e.dir)
        {
            let Ok(device_id) = device.name.parse::<DeviceId>() else {
                continue;
            };
            let dir = format::device_dir(account_id, device_id);
            for keys in keys_in(folder, &dir, account_id, device_id)? {
                if let Ok(server) = keys.file.server.parse() {
                    let mut written_at = keys.at;
                    for entry in folder.list(&format!("{dir}/log")).map_err(folder_error)? {
                        if !entry.dir
                            && let Some(run) = entry
                                .name
                                .strip_suffix(".bhl")
                                .map(|name| name.rsplit_once('-').map_or(name, |(_, run)| run))
                                .and_then(format::parse_run)
                        {
                            written_at = written_at.max(run);
                        }
                    }
                    for base in folder
                        .list(&format!("{dir}/snapshots"))
                        .map_err(folder_error)?
                    {
                        if !base.dir {
                            continue;
                        }
                        for entry in folder
                            .list(&format!("{dir}/snapshots/{}", base.name))
                            .map_err(folder_error)?
                        {
                            if !entry.dir
                                && let Some(run) =
                                    entry.name.strip_suffix(".bhs").and_then(format::parse_run)
                            {
                                written_at = written_at.max(run);
                            }
                        }
                    }
                    listings.push(BackupListing {
                        account: account_id,
                        device: device_id,
                        email: keys.file.email,
                        server,
                        written_at,
                    });
                    break;
                }
            }
        }
    }
    listings.sort_by_key(|item| std::cmp::Reverse(item.written_at));
    Ok(listings)
}

impl Core {
    /// Opens a listed device's backup without contacting the account server.
    ///
    /// # Errors
    /// Returns [`Error::BadKit`] if no saved envelope opens with this password
    /// and recovery kit, or [`Error::Storage`] if the folder cannot be read.
    pub async fn open_backup(
        &self,
        folder: Arc<dyn BackupFolder>,
        listing: &BackupListing,
        password: Zeroizing<String>,
        kit: &str,
    ) -> Result<OpenedBackup, Error> {
        let shared = self.shared.clone();
        let account = listing.account;
        let device = listing.device;
        let kit = Zeroizing::new(kit.to_string());
        shared
            .clone()
            .run(async move {
                let dir = format::device_dir(account, device);
                let keys = keys_in(folder.as_ref(), &dir, account, device)?;
                let kit = RecoveryKit::parse(&kit)?;
                let mut attempted = HashSet::new();
                let mut opened = None;
                for item in &keys {
                    let file = &item.file;
                    if !attempted.insert((file.salt.clone(), file.envelope.clone())) {
                        continue;
                    }
                    let Ok(salt) = <[u8; 16]>::try_from(file.salt.as_slice()) else {
                        continue;
                    };
                    let password = match derive(password.clone(), salt, file.kdf.clone()).await {
                        Ok(password) => password,
                        Err(Error::NeedsUpdate) => continue,
                        Err(error) => return Err(error),
                    };
                    if let Ok(plain) = envelope::open(
                        &password.wrap_key(&kit),
                        &keys::account_key_aad(
                            &account,
                            envelope::epoch(&file.envelope).unwrap_or(0),
                        ),
                        &file.envelope,
                    ) && let Ok(secret) = Secret::<32>::from_slice(&plain)
                    {
                        opened = Some((
                            Arc::new(secret),
                            item.at,
                            envelope::epoch(&file.envelope).ok_or(Error::Crypto)?,
                        ));
                        break;
                    }
                }
                let (key, opened_at, opened_epoch) = opened.ok_or(Error::BadKit)?;
                let mut account_keys = BTreeMap::new();
                if let Some(data) = keys
                    .iter()
                    .find(|item| item.at == opened_at)
                    .and_then(|item| item.file.account_data.as_ref())
                {
                    let data_epoch = u32::try_from(data.version).map_err(|_| Error::Crypto)?;
                    let plain = envelope::open(
                        &keys::account_data_key(&key),
                        &keys::account_data_aad(&account, data_epoch),
                        &data.sealed,
                    )?;
                    let json: serde_json::Value =
                        serde_json::from_slice(&plain).map_err(|_| Error::Crypto)?;
                    if let Some(older) = json.get("keys").and_then(serde_json::Value::as_object) {
                        for (epoch, encoded) in older {
                            let epoch: u32 = epoch.parse().map_err(|_| Error::Crypto)?;
                            let encoded = encoded.as_str().ok_or(Error::Crypto)?;
                            let bytes =
                                URL_SAFE_NO_PAD.decode(encoded).map_err(|_| Error::Crypto)?;
                            account_keys.insert(epoch, Secret::<32>::from_slice(&bytes)?);
                        }
                    }
                }
                account_keys.insert(opened_epoch, Secret::from_slice(key.expose())?);
                let mut snapshots: BTreeMap<BaseId, Vec<Snapshot>> = BTreeMap::new();
                let mut logs = Vec::new();
                let mut invalid = Vec::new();
                let mut points = BTreeSet::new();
                let mut ignored = Vec::new();
                points.extend(keys.iter().map(|item| item.at));
                let snapshot_root = format!("{dir}/snapshots");
                for entry in folder
                    .list(&snapshot_root)
                    .map_err(folder_error)?
                    .into_iter()
                    .filter(|e| e.dir)
                {
                    let Ok(base) = entry.name.parse::<BaseId>() else {
                        continue;
                    };
                    for file in folder
                        .list(&format!("{snapshot_root}/{base}"))
                        .map_err(folder_error)?
                    {
                        let Some(at) = file.name.strip_suffix(".bhs").and_then(format::parse_run)
                        else {
                            continue;
                        };
                        if file.dir {
                            continue;
                        }
                        let path = format!("{snapshot_root}/{base}/{}", file.name);
                        let bytes = folder.read(&path).map_err(folder_error)?;
                        match format::decode(FileKind::Snapshot, &bytes) {
                            Ok(records) if valid_snapshot(&records, base, at) => {
                                points.insert(at);
                                snapshots.entry(base).or_default().push(Snapshot {
                                    at,
                                    records: records.into_iter().map(ToOwned::to_owned).collect(),
                                });
                            }
                            _ => ignored.push(path),
                        }
                    }
                }
                for records in snapshots.values_mut() {
                    records.sort_by_key(|s| s.at);
                }
                for file in folder.list(&format!("{dir}/log")).map_err(folder_error)? {
                    if file.dir || !file.name.ends_with(".bhl") {
                        continue;
                    }
                    let path = format!("{dir}/log/{}", file.name);
                    let filename_time = file.name.strip_suffix(".bhl").and_then(|name| {
                        (!name.contains('-'))
                            .then(|| format::parse_run(name))
                            .flatten()
                    });
                    // A merged name bounds errors but is never itself a user point.
                    let merged_time = file
                        .name
                        .strip_suffix(".bhl")
                        .and_then(|name| name.split_once('-'))
                        .and_then(|(_, run)| format::parse_run(run));
                    let bytes = folder.read(&path).map_err(folder_error)?;
                    match format::decode(FileKind::Log, &bytes) {
                        Ok(records) => {
                            if records.is_empty()
                                && let Some(at) = filename_time
                            {
                                points.insert(at);
                            }
                            for body in records {
                                if let Ok(record) = ChangeRecord::decode(body) {
                                    points.insert(record.run);
                                    logs.push(RecordedChange {
                                        at: record.run,
                                        base: record.base,
                                        object: record.object,
                                        state: record.state,
                                        sealed: record.sealed.to_vec(),
                                    });
                                } else {
                                    let base = body
                                        .get(1..17)
                                        .and_then(|id| id.try_into().ok())
                                        .map(BaseId);
                                    let at = body
                                        .get(33..41)
                                        .and_then(|at| at.try_into().ok())
                                        .map(i64::from_be_bytes)
                                        .or(filename_time)
                                        .or(merged_time)
                                        .unwrap_or(i64::MIN);
                                    invalid.push(InvalidChange { at, base });
                                }
                            }
                        }
                        Err(_) => ignored.push(path),
                    }
                }
                logs.sort_by_key(|record| record.at);
                // The oldest keys file may predate every retained snapshot; it
                // unlocks later points but is not itself a restorable point.
                if let Some(earliest) = snapshots
                    .values()
                    .flat_map(|all| all.iter().map(|s| s.at))
                    .min()
                {
                    let first_keys = keys.iter().map(|item| item.at).min().unwrap_or(i64::MAX);
                    points.retain(|at| *at >= earliest.max(first_keys));
                }
                let temporary = shared
                    .data_dir
                    .join("restore")
                    .join(BaseId::random().to_string());
                std::fs::create_dir_all(&temporary)?;
                Ok(OpenedBackup {
                    folder,
                    dir,
                    account,
                    account_keys,
                    opened_epoch,
                    hidden: BTreeMap::new(),
                    hidden_passwords: BTreeMap::new(),
                    keys,
                    snapshots,
                    logs,
                    invalid,
                    points: points.into_iter().rev().collect(),
                    ignored,
                    temporary,
                    rebuilt: tokio::sync::Mutex::new(None),
                })
            })
            .await
    }
}

fn ordinary_key(
    account_key: &Secret<32>,
    base: BaseId,
    epoch: u32,
    wrapper: &[u8],
) -> Option<BaseKey> {
    let key = bh_crypto::kdf(account_key, b"bhbasew1", 1);
    let plain = envelope::open(&key, &keys::account_wrapper_aad(&base, epoch), wrapper).ok()?;
    BaseKey::new(&plain).ok()
}

#[derive(Clone)]
pub(super) struct Rebuilt {
    root: PathBuf,
    pub(super) bases: BTreeMap<BaseId, Base>,
    pub(super) hidden: BTreeSet<BaseId>,
    pub(super) mounts: BTreeMap<BaseId, Mount>,
    pub(super) report: CheckReport,
}

impl OpenedBackup {
    /// Valid run times, newest first, in Unix milliseconds.
    pub fn points(&self) -> Vec<i64> {
        self.points.clone()
    }

    /// Opens all as-yet-locked wrappers matching an extra password.
    ///
    /// # Errors
    /// Returns [`Error::NothingUnlocked`] when no new base opens, or an error
    /// if the password is empty or its key cannot be derived.
    pub async fn unlock(&mut self, extra_password: Zeroizing<String>) -> Result<usize, Error> {
        let account_key = self.account_keys.get(&1).ok_or(Error::Crypto)?;
        let account_key = Secret::<32>::from_slice(account_key.expose())?;
        let password = extra_password.clone();
        let key = tokio::task::spawn_blocking(move || HiddenKey::derive(&account_key, &password))
            .await
            .map_err(|_| Error::Storage("hidden key derivation failed".into()))??;
        let mut count = 0;
        for item in &self.keys {
            for wrapper in &item.file.wrappers {
                if self.hidden.contains_key(&wrapper.base)
                    || !self.snapshots.contains_key(&wrapper.base)
                {
                    continue;
                }
                let Ok(epoch) = u32::try_from(wrapper.epoch) else {
                    continue;
                };
                if self.account_keys.values().rev().any(|account_key| {
                    ordinary_key(account_key, wrapper.base, epoch, &wrapper.wrapper).is_some()
                }) {
                    continue;
                }
                let account_keys: Vec<_> = self.account_keys.values().rev().collect();
                if key
                    .open_any(
                        &account_keys,
                        self.account,
                        wrapper.base,
                        epoch,
                        &wrapper.wrapper,
                    )
                    .is_some()
                {
                    self.hidden.insert(wrapper.base, key.duplicate());
                    self.hidden_passwords
                        .insert(wrapper.base, extra_password.clone());
                    count += 1;
                }
            }
        }
        if count == 0 {
            return Err(Error::NothingUnlocked);
        }
        if let Some((_, previous)) = self.rebuilt.get_mut().take() {
            let root = previous.root.clone();
            drop(previous);
            std::fs::remove_dir_all(root)?;
        }
        Ok(count)
    }

    fn selected(&self, at: i64) -> Result<&KeysFile, Error> {
        if !self.points.contains(&at) {
            return Err(Error::NotFound);
        }
        let file = &self
            .keys
            .iter()
            .find(|item| item.at <= at)
            .ok_or(Error::NotFound)?
            .file;
        if envelope::epoch(&file.envelope).is_some_and(|epoch| epoch > self.opened_epoch) {
            return Err(Error::BadKit);
        }
        Ok(file)
    }

    pub(super) async fn rebuild(&self, at: i64) -> Result<Rebuilt, Error> {
        let mut cached = self.rebuilt.lock().await;
        if let Some((point, rebuilt)) = &*cached
            && *point == at
        {
            return Ok(rebuilt.clone());
        }
        if let Some((_, previous)) = cached.take() {
            let root = previous.root.clone();
            drop(previous);
            std::fs::remove_dir_all(root)?;
        }
        let rebuilt = self.build_point(at).await?;
        *cached = Some((at, rebuilt.clone()));
        Ok(rebuilt)
    }

    async fn build_point(&self, at: i64) -> Result<Rebuilt, Error> {
        let selected = self.selected(at)?;
        let data = selected
            .account_data
            .as_ref()
            .map(|data| {
                let epoch = u32::try_from(data.version).map_err(|_| Error::Crypto)?;
                if envelope::epoch(&data.sealed) != Some(epoch) {
                    return Err(Error::Crypto);
                }
                let plain = self
                    .account_keys
                    .values()
                    .rev()
                    .find_map(|key| {
                        envelope::open(
                            &keys::account_data_key(key),
                            &keys::account_data_aad(&self.account, epoch),
                            &data.sealed,
                        )
                        .ok()
                    })
                    .ok_or(Error::Crypto)?;
                serde_json::from_slice::<crate::account::Data>(&plain).map_err(|_| Error::Crypto)
            })
            .transpose()?;
        let mounts = data.as_ref().map(grants::mounts).unwrap_or_default();
        let mut bases = BTreeMap::new();
        let mut hidden_bases = BTreeSet::new();
        let mut report = CheckReport {
            bases: Vec::new(),
            locked: 0,
            missing: 0,
            ignored_files: self.ignored.clone(),
        };
        let root = self.temporary.join(BaseId::random().to_string());
        std::fs::create_dir_all(&root)?;
        for wrapper in &selected.wrappers {
            if bases.contains_key(&wrapper.base) {
                continue;
            }
            let Some(snapshot) = self
                .snapshots
                .get(&wrapper.base)
                .and_then(|all| all.iter().rev().find(|s| s.at <= at))
            else {
                report.missing += 1;
                continue;
            };
            let Ok(epoch) = u32::try_from(wrapper.epoch) else {
                report.locked += 1;
                continue;
            };
            let ordinary = self
                .account_keys
                .values()
                .rev()
                .find_map(|key| ordinary_key(key, wrapper.base, epoch, &wrapper.wrapper));
            let hidden = ordinary.is_none();
            let key = ordinary.or_else(|| {
                let account_keys: Vec<_> = self.account_keys.values().rev().collect();
                self.hidden.get(&wrapper.base).and_then(|hidden| {
                    hidden
                        .open_any(
                            &account_keys,
                            self.account,
                            wrapper.base,
                            epoch,
                            &wrapper.wrapper,
                        )
                        .map(|(key, _)| key)
                })
            });
            let Some(key) = key else {
                report.locked += 1;
                continue;
            };
            let previous: Vec<_> = wrapper
                .chain
                .iter()
                .map(|link| (link.epoch, link.sealed.clone()))
                .collect();
            let keys = BaseKeys::from_chain(epoch, key, &previous, &wrapper.base)?;
            let base = Base::open_store(
                &root.join(format!("{}.sqlite", wrapper.base)),
                &bh_crypto::random::<32>(),
                wrapper.base,
                BaseKey::new(keys.current().1.secret().expose())?,
                Mode::ReadOnly,
                None,
            )?;
            base.install_keys(keys);
            let mut changes = Vec::new();
            let mut malformed = 0;
            for body in &snapshot.records {
                match ChangeRecord::decode(body) {
                    Ok(record) if record.base == wrapper.base && record.run == snapshot.at => {
                        changes.push((record.object, record.state, record.sealed.to_vec()))
                    }
                    _ => malformed += 1,
                }
            }
            for record in self
                .logs
                .iter()
                .filter(|r| r.base == wrapper.base && r.at > snapshot.at && r.at <= at)
            {
                changes.push((record.object, record.state, record.sealed.clone()));
            }
            let mut unreadable = malformed
                + base.apply_backup(&changes)?.len()
                + self
                    .invalid
                    .iter()
                    .filter(|r| r.base == Some(wrapper.base) && r.at > snapshot.at && r.at <= at)
                    .count();
            let mut missing_files = Vec::new();
            let candidates = { base.db()?.file_candidates()? };
            for id in candidates {
                let Some(file) = base.file(id)? else {
                    continue;
                };
                let count = files::parts(file.size);
                let mut all = true;
                for n in 0..count {
                    let path = format!("{}/{}", self.dir, format::part_path(wrapper.base, id, n));
                    let bytes = match self.folder.read(&path) {
                        Ok(bytes) => bytes,
                        Err(FolderError::Other(_)) => {
                            all = false;
                            break;
                        }
                        Err(error) => return Err(folder_error(error)),
                    };
                    let target = base.part_file(id, n);
                    std::fs::create_dir_all(target.parent().expect("part parent"))?;
                    std::fs::write(target, bytes)?;
                }
                if all {
                    base.db()?.file_received(id, count, count)?;
                }
                if !all || base.file_bytes(id).await.map(Zeroizing::new).is_err() {
                    base.db()?.file_broken(id, count)?;
                    missing_files.push(id);
                }
            }
            let objects = base.export_objects()?;
            for (_, state) in base.db()?.objects_for_backfill()? {
                unreadable += usize::from(base.load(&state)?.transact().has_missing_updates());
            }
            report.bases.push(BaseCheck {
                id: wrapper.base,
                name: base.name(),
                objects: objects.len(),
                unreadable,
                missing_files,
            });
            bases.insert(wrapper.base, base);
            if hidden {
                hidden_bases.insert(wrapper.base);
            }
        }
        // A log header can name a base that has no wrapper at this point. Its
        // original base cannot be inferred after tampering; count it once so a
        // damaged record is not silently omitted from the integrity report.
        if let Some(first) = report.bases.first_mut() {
            first.unreadable += self
                .logs
                .iter()
                .filter(|record| {
                    record.at <= at && !selected.wrappers.iter().any(|w| w.base == record.base)
                })
                .count();
            first.unreadable += self
                .invalid
                .iter()
                .filter(|record| {
                    record.at <= at
                        && record
                            .base
                            .is_none_or(|base| !selected.wrappers.iter().any(|w| w.base == base))
                })
                .count();
        }
        Ok(Rebuilt {
            root,
            bases,
            hidden: hidden_bases,
            mounts,
            report,
        })
    }

    /// Lists the bases available at a point, with their readable object counts.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] for an unknown point, or [`Error::Storage`] for an unreadable folder/store.
    pub async fn bases(&self, at: i64) -> Result<Vec<RestorableBase>, Error> {
        let rebuilt = self.rebuild(at).await?;
        let mut result = Vec::new();
        for (id, base) in &rebuilt.bases {
            let rows = base.export_objects()?;
            result.push(RestorableBase {
                id: *id,
                name: base.name(),
                hidden: rebuilt.hidden.contains(id),
                mount: rebuilt.mounts.get(id).cloned(),
                notes: rows.iter().filter(|row| row.ty.name == "core.note").count(),
                files: rows.iter().filter(|row| row.ty.name == "core.file").count(),
                records: rows
                    .iter()
                    .filter(|row| {
                        !matches!(
                            row.ty.name.as_str(),
                            "core.note" | "core.file" | "core.base"
                        )
                    })
                    .count(),
            });
        }
        Ok(result)
    }

    /// Reopens every record and file part at a point, reporting unreadable content.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] for an unknown point, or [`Error::Storage`] for an unreadable folder/store.
    pub async fn check(&self, at: i64) -> Result<CheckReport, Error> {
        Ok(self.rebuild(at).await?.report)
    }

    /// Exports the chosen base and its mounted descendants as a readable folder.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] if this base is not available, or an export or folder error.
    pub async fn export(&self, at: i64, base: BaseId, out: &Path) -> Result<ExportSummary, Error> {
        let rebuilt = self.rebuild(at).await?;
        let main = rebuilt.bases.get(&base).ok_or(Error::NotFound)?;
        let mut selected = vec![(main.clone(), None)];
        let mut included = BTreeSet::from([base]);
        loop {
            let mut next = Vec::new();
            for (id, mount) in &rebuilt.mounts {
                if included.contains(&mount.parent)
                    && !included.contains(id)
                    && let Some(base) = rebuilt.bases.get(id)
                {
                    next.push((*id, base.clone(), mount.folder));
                }
            }
            if next.is_empty() {
                break;
            }
            for (id, base, folder) in next {
                included.insert(id);
                selected.push((base, Some(folder)));
            }
        }
        crate::export::run(&selected, out).await
    }
}

#[cfg(test)]
mod serialization_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn check_report_uses_camel_case_json_and_round_trips() {
        let id = BaseId::random();
        let file = ObjectId::random();
        let report = CheckReport {
            bases: vec![BaseCheck {
                id,
                name: "Personal".into(),
                objects: 2,
                unreadable: 1,
                missing_files: vec![file],
            }],
            locked: 0,
            missing: 1,
            ignored_files: vec!["bad".into()],
        };
        let expected = json!({
            "bases": [{"id": id, "name": "Personal", "objects": 2,
                       "unreadable": 1, "missingFiles": [file]}],
            "locked": 0, "missing": 1, "ignoredFiles": ["bad"]
        });
        assert_eq!(serde_json::to_value(&report).unwrap(), expected);
        let decoded: CheckReport = serde_json::from_value(expected).unwrap();
        assert_eq!(decoded.bases[0].missing_files, vec![file]);
        assert_eq!(decoded.ignored_files, vec!["bad"]);
    }
}
