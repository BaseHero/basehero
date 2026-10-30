//! Device-local backup writer. Folder operations never hold a base store lock.

use super::format::{self, ChangeRecord, FileKind, KeysFile, PreviousKey, Wrapper};
use super::{BackupFolder, BackupLocation, BackupProblem, BackupRun, FolderError, LocalFolder};
use crate::account::Account;
use crate::base::BaseKey;
use crate::basekeys::BaseKeys;
use crate::core::Shared;
use crate::hidden::HiddenKey;
use crate::keys;
use crate::store::BackupRow;
use crate::{Base, Error};
use bh_crypto::Secret;
use bh_proto::ObjectId;
use std::collections::HashSet;
#[cfg(any(target_os = "macos", test))]
use std::path::Path;
use std::sync::Arc;

/// Makes the Mac's default folder again if the person deleted it, while the
/// folder it sits in is still there. It's recognised by its path, so the core
/// never reads the home folder itself.
#[cfg(any(target_os = "macos", test))]
fn recreate_mac_default(path: &Path) {
    let default = path.ends_with("Library/Mobile Documents/com~apple~CloudDocs/BaseHero")
        || path.ends_with("Documents/BaseHero Backup");
    if default
        && path.parent().is_some_and(Path::is_dir)
        && std::fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        let _ = std::fs::create_dir(path);
    }
}
use yrs::updates::{decoder::Decode, encoder::Encode};
use yrs::{Doc, ReadTxn, StateVector, Transact, Update};

impl Shared {
    pub(crate) fn open_folder(
        &self,
        location: &BackupLocation,
    ) -> Result<Arc<dyn BackupFolder>, Error> {
        self.open_backup_folder(location)
            .map_err(|error| error.map_or(Error::NotFound, folder_error))
    }

    fn open_backup_folder(
        &self,
        location: &BackupLocation,
    ) -> Result<Arc<dyn BackupFolder>, Option<FolderError>> {
        match location {
            BackupLocation::Path { path, .. } => Ok(Arc::new(LocalFolder::new(path.clone()))),
            BackupLocation::Document { uri, .. } => self
                .document_folders
                .lock()
                .unwrap()
                .as_ref()
                .ok_or(None)?
                .open(uri)
                .map_err(Some),
        }
    }
}

fn folder_error(error: FolderError) -> Error {
    Error::Storage(format!("backup folder: {error:?}"))
}
fn problem(error: &FolderError) -> BackupProblem {
    match error {
        FolderError::PermissionLost => BackupProblem::PermissionLost,
        FolderError::Full => BackupProblem::Full,
        _ => BackupProblem::Unreachable,
    }
}
fn write_record(
    account: &Account,
    folder: &dyn BackupFolder,
    path: &str,
    kind: FileKind,
    records: &[Vec<u8>],
    generation: u64,
) -> Result<u64, WriteError> {
    check_running(account, generation)?;
    let bytes = format::encode(kind, records);
    folder.write(path, &bytes)?;
    check_running(account, generation)?;
    let stored = folder.read(path)?;
    if stored != bytes || format::decode(kind, &stored).is_err() {
        return Err(FolderError::Other("incomplete backup write".into()).into());
    }
    Ok(bytes.len() as u64)
}

struct Batch {
    base: Base,
    snapshot: bool,
    epoch: u32,
    records: Vec<Vec<u8>>,
    committed: Vec<(ObjectId, i64, Vec<u8>)>,
    hidden: bool,
}

fn prepare(
    base: &Base,
    generation: i64,
    snapshot: bool,
    at: i64,
    hidden: bool,
) -> Result<Batch, Error> {
    let mut records = Vec::new();
    let mut committed = Vec::new();
    let mut epoch = None;
    for (id, seq, state, previous) in base.db()?.dirty_since(generation, snapshot)? {
        let doc = Doc::new();
        doc.transact_mut()
            .apply_update(Update::decode_v1(&state).map_err(|_| Error::Crypto)?)
            .map_err(|_| Error::Crypto)?;
        let txn = doc.transact();
        let sv = txn.state_vector().encode_v1();
        let previous = previous
            .as_deref()
            .map(StateVector::decode_v1)
            .transpose()
            .map_err(|_| Error::Crypto)?;
        // An edit can change Yrs' delete set without advancing its state vector.
        // The dirty trigger is authoritative; even that edit needs its delta.
        let body = if snapshot {
            state
        } else {
            txn.encode_state_as_update_v1(previous.as_ref().unwrap_or(&StateVector::default()))
        };
        let sealed = base.seal_change(id, snapshot, &body);
        epoch.get_or_insert(crate::envelope::epoch(&sealed).ok_or(Error::Crypto)?);
        records.push(
            ChangeRecord {
                state: snapshot,
                base: base.id(),
                object: id,
                run: at,
                sealed: &sealed,
            }
            .encode(),
        );
        committed.push((id, seq, sv));
    }
    Ok(Batch {
        base: base.clone(),
        snapshot,
        epoch: epoch.unwrap_or_else(|| base.newest_epoch()),
        records,
        committed,
        hidden,
    })
}

fn wrapper_covers(
    keys_file: &KeysFile,
    base: crate::BaseId,
    sealed_epoch: u32,
    account_keys: &[&Secret<32>],
    hidden_key: Option<&HiddenKey>,
) -> bool {
    keys_file.wrappers.iter().any(|wrapper| {
        wrapper.base == base
            && wrapper_opens(
                keys_file.account,
                wrapper,
                sealed_epoch,
                account_keys,
                hidden_key,
            )
    })
}

fn wrapper_opens(
    account: crate::AccountId,
    wrapper: &Wrapper,
    sealed_epoch: u32,
    account_keys: &[&Secret<32>],
    hidden_key: Option<&HiddenKey>,
) -> bool {
    let base = wrapper.base;
    let Ok(epoch) = u32::try_from(wrapper.epoch) else {
        return false;
    };
    let current = if let Some(hidden_key) = hidden_key {
        hidden_key
            .open_any(account_keys, account, base, epoch, &wrapper.wrapper)
            .map(|(key, _)| key)
    } else {
        account_keys.iter().find_map(|account_key| {
            let wrap_key = bh_crypto::kdf(account_key, b"bhbasew1", 1);
            let plain = crate::envelope::open(
                &wrap_key,
                &keys::account_wrapper_aad(&base, epoch),
                &wrapper.wrapper,
            )
            .ok()?;
            BaseKey::new(&plain).ok()
        })
    };
    let Some(current) = current else { return false };
    let chain: Vec<_> = wrapper
        .chain
        .iter()
        .map(|link| (link.epoch, link.sealed.clone()))
        .collect();
    BaseKeys::from_chain(epoch, current, &chain, &base)
        .is_ok_and(|keys| keys.get(sealed_epoch).is_some())
}

// One transient race is silent. A second run with the same broken wrapper
// shows the existing backup warning without inventing a new UI state.
fn stale_wrapper_problem(previous: Option<&str>) -> &'static str {
    if matches!(previous, Some("keyMismatch" | "usingLastChecked")) {
        BackupProblem::UsingLastChecked.text()
    } else {
        "keyMismatch"
    }
}

fn keys(account: &Account, at: i64) -> Result<(KeysFile, String, bool), Error> {
    let credentials = account
        .backup_credentials()?
        .ok_or_else(|| Error::Storage("missing local sign-in details".into()))?;
    let (ordinary, hidden) = account.backup_wrappers()?;
    let ordinary_ids: HashSet<_> = ordinary.iter().map(|row| row.id).collect();
    let mut wrappers: Vec<_> = ordinary
        .into_iter()
        .map(|row| Wrapper {
            base: row.id,
            epoch: row.epoch as u64,
            wrapper: row.wrapper,
            chain: row
                .chain
                .into_iter()
                .map(|(epoch, sealed)| PreviousKey { epoch, sealed })
                .collect(),
        })
        .collect();
    for row in hidden {
        if !wrappers.iter().any(|w| w.base == row.id) {
            wrappers.push(Wrapper {
                base: row.id,
                epoch: row.epoch as u64,
                wrapper: row.wrapper,
                chain: row
                    .chain
                    .into_iter()
                    .map(|(epoch, sealed)| PreviousKey { epoch, sealed })
                    .collect(),
            });
        }
    }
    wrappers.sort_by_key(|w| w.base);
    let data = account.backup_sealed_data()?;
    let mut file = KeysFile {
        v: 1,
        account: account.id(),
        device: account.device_id(),
        server: account.backup_server(),
        email: account.email(),
        written_at: at,
        salt: credentials.salt.to_vec(),
        kdf: crate::keys::DEFAULT_KDF,
        envelope: credentials.envelope,
        envelope_checked: credentials.checked,
        wrappers,
        account_data: data,
    };
    // An unopenable ordinary wrapper cannot be included in a new keys file:
    // it would turn an otherwise sound backup point into an unrestorable one.
    // Locked hidden wrappers cannot be verified without their extra password.
    let ring = account.backup_account_keys()?;
    let account_keys: Vec<_> = ring.iter_newest_first().map(|(_, key)| key).collect();
    let mut skipped = false;
    file.wrappers.retain(|wrapper| {
        let valid = !ordinary_ids.contains(&wrapper.base)
            || wrapper_opens(file.account, wrapper, 1, &account_keys, None);
        skipped |= !valid;
        valid
    });
    // Random AEAD nonces and the run timestamp must not force a new keys file.
    let mut stable = file.clone();
    stable.written_at = 0;
    if let Some(data) = &mut stable.account_data {
        data.sealed.clear();
    }
    let digest = bh_crypto::sha256(&serde_json::to_vec(&stable).expect("keys JSON"));
    let hash = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok((file, hash, skipped))
}

fn path(dir: &str, relative: &str) -> String {
    format!("{dir}/{relative}")
}

fn exists(folder: &dyn BackupFolder, name: &str) -> Result<bool, FolderError> {
    let (parent, filename) = name.rsplit_once('/').unwrap_or(("", name));
    Ok(folder
        .list(parent)?
        .iter()
        .any(|entry| entry.name == filename && !entry.dir))
}

fn unique_run(
    folder: &dyn BackupFolder,
    dir: &str,
    bases: &[Base],
    start: i64,
) -> Result<(String, i64), FolderError> {
    let mut at = start;
    loop {
        let run = format::run_name(at);
        let mut used = exists(folder, &path(dir, &format::keys_path(&run)))?
            || exists(folder, &path(dir, &format::log_path(&run)))?;
        for base in bases {
            used |= exists(folder, &path(dir, &format::snapshot_path(base.id(), &run)))?;
        }
        if !used {
            return Ok((run, at));
        }
        at = at
            .checked_add(1)
            .ok_or(FolderError::Other("backup time overflow".into()))?;
    }
}

pub(crate) async fn run(account: &Account, generation: u64) -> Result<BackupRun, Error> {
    account.check_active()?;
    let mut row = account.backup_row()?;
    let Some(location) = row.location.clone().filter(|_| row.enabled) else {
        return Ok(BackupRun::default());
    };
    #[cfg(target_os = "macos")]
    if let BackupLocation::Path { path, .. } = &location {
        recreate_mac_default(path);
    }
    let folder = match account.backup_shared().open_backup_folder(&location) {
        Ok(folder) => folder,
        Err(None) => return Err(Error::NotFound),
        Err(Some(error)) => {
            row.problem = Some(problem(&error).text().into());
            account.update_backup_progress(&row, row.generation, &location)?;
            return Ok(BackupRun::default());
        }
    };
    let dir = format::device_dir(account.id(), account.device_id());
    let outcome = write_run(
        account,
        folder.as_ref(),
        &dir,
        &location,
        &mut row,
        generation,
    )
    .await;
    match outcome {
        Ok(result) => {
            account.update_backup_progress(&row, row.generation, &location)?;
            let at = result
                .run
                .as_deref()
                .and_then(format::parse_run)
                .unwrap_or_else(|| account.clock().edit_time_ms());
            // Maintenance is best effort: a completed run must remain completed.
            if !account.backup_stopped(generation) {
                let _ = account
                    .merge_and_prune(folder.as_ref(), at, row, &location, generation)
                    .await;
            }
            Ok(result)
        }
        Err(WriteError::Stopped) => Ok(BackupRun::default()),
        Err(WriteError::Credentials(problem)) => {
            row.problem = Some(problem.text().into());
            account.update_backup_progress(&row, row.generation, &location)?;
            Ok(BackupRun::default())
        }
        Err(WriteError::Folder(error)) => {
            row.problem = Some(problem(&error).text().into());
            account.update_backup_progress(&row, row.generation, &location)?;
            Ok(BackupRun::default())
        }
        // Notice-triggered erasure can remove secrets while a run is reading
        // them. Report the revocation, not the incidental storage failure.
        Err(WriteError::Core(_)) if account.check_active().is_err() => Err(Error::Revoked),
        Err(WriteError::Core(error)) => Err(error),
    }
}

enum WriteError {
    Stopped,
    Folder(FolderError),
    Credentials(BackupProblem),
    Core(Error),
}
fn check_running(account: &Account, generation: u64) -> Result<(), WriteError> {
    account.check_active()?;
    if account.backup_stopped(generation) {
        Err(WriteError::Stopped)
    } else {
        Ok(())
    }
}
impl From<FolderError> for WriteError {
    fn from(e: FolderError) -> Self {
        Self::Folder(e)
    }
}
impl From<Error> for WriteError {
    fn from(e: Error) -> Self {
        Self::Core(e)
    }
}

async fn write_run(
    account: &Account,
    folder: &dyn BackupFolder,
    dir: &str,
    location: &BackupLocation,
    row: &mut BackupRow,
    generation: u64,
) -> Result<BackupRun, WriteError> {
    let current_epoch = account.backup_account_epoch()?;
    let credentials = account
        .backup_credentials()?
        .ok_or(WriteError::Credentials(BackupProblem::NoKitRecord))?;
    if crate::envelope::epoch(&credentials.envelope) != Some(current_epoch) {
        return Err(WriteError::Credentials(BackupProblem::UsingLastChecked));
    }
    let (ordinary, _) = account.backup_wrappers()?;
    let hidden = account.unlocked_backup_bases();
    let hidden_ids: HashSet<_> = hidden.iter().map(Base::id).collect();
    let mut bases = Vec::new();
    for entry in ordinary {
        // A full-device removal commits before its ordinary bases finish re-keying.
        // The removed device still holds their old keys; leave dirty rows untouched.
        if entry.account_epoch < current_epoch {
            continue;
        }
        match account.base(entry.id) {
            Ok(base) => bases.push(base),
            Err(error) => eprintln!("warning: skipping backup of base {}: {error}", entry.id),
        }
    }
    bases.extend(hidden);
    let (run, at) = unique_run(
        folder,
        dir,
        &bases,
        account.clock().edit_time_ms().max(
            row.last_run
                .as_deref()
                .and_then(format::parse_run)
                .unwrap_or(i64::MIN)
                .saturating_add(1),
        ),
    )?;

    // A missing or size-mismatched snapshot means the saved cursor cannot be trusted.
    for base in &bases {
        let (snapshot, snapshot_bytes, _, _) = {
            let _guard = base.backup_guard().await;
            if hidden_ids.contains(&base.id()) && !base.backup_open() {
                continue;
            }
            base.db()?.backup_state(row.generation)?
        };
        if let Some(snapshot) = snapshot {
            let name = path(dir, &format::snapshot_path(base.id(), &snapshot));
            let (parent, filename) = name.rsplit_once('/').expect("snapshot has parent");
            let valid = folder
                .list(parent)?
                .iter()
                .any(|entry| entry.name == filename && !entry.dir && entry.size == snapshot_bytes);
            if !valid {
                let old_generation = row.generation;
                row.generation += 1;
                row.last_run = None;
                row.keys_hash = None;
                row.keys_name = None;
                row.bytes = super::prune::tree_size(folder, dir)?;
                if !account.update_backup_progress(row, old_generation, location)? {
                    return Ok(BackupRun::default());
                }
                break;
            }
        }
    }
    let mut batches = Vec::new();
    for base in &bases {
        let _guard = base.backup_guard().await;
        if hidden_ids.contains(&base.id()) && !base.backup_open() {
            continue;
        }
        let (snapshot, snapshot_bytes, log_bytes, snapshot_epoch) =
            base.db()?.backup_state(row.generation)?;
        let due = snapshot.is_none_or(|name| {
            snapshot_epoch != Some(base.newest_epoch())
                || log_bytes > snapshot_bytes / 2
                || at.saturating_sub(format::parse_run(&name).unwrap_or(0)) >= 7 * 86_400_000
        });
        batches.push(prepare(
            base,
            row.generation,
            due,
            at,
            hidden_ids.contains(&base.id()),
        )?);
    }
    // Re-read wrappers *after* sealing. A newer wrapper carries the predecessor
    // chain and opens old records; an older wrapper must never accompany new ones.
    let (key_file, hash, skipped_wrapper) = keys(account, at)?;
    let current_epoch = account.backup_account_epoch()?;
    let (current_rows, _) = account.backup_wrappers()?;
    let eligible: HashSet<_> = current_rows
        .into_iter()
        .filter(|row| row.account_epoch >= current_epoch)
        .map(|row| row.id)
        .collect();
    batches.retain(|batch| {
        hidden_ids.contains(&batch.base.id())
            || (eligible.contains(&batch.base.id())
                && key_file
                    .wrappers
                    .iter()
                    .any(|w| w.base == batch.base.id() && w.epoch == u64::from(batch.epoch)))
    });
    // A discarded batch must not copy file parts from that same stale base either.
    bases.retain(|base| batches.iter().any(|batch| batch.base.id() == base.id()));
    if crate::envelope::epoch(&key_file.envelope) != Some(current_epoch) {
        // The new key was adopted, but its usable envelope has not reached the cache yet.
        return Err(WriteError::Credentials(BackupProblem::UsingLastChecked));
    }
    let ring = account.backup_account_keys()?;
    let account_keys: Vec<_> = ring.iter_newest_first().map(|(_, key)| key).collect();
    let stale_batch = batches.iter().any(|batch| {
        let hidden = hidden_ids.contains(&batch.base.id());
        let hidden_key = hidden
            .then(|| account.backup_hidden_key(batch.base.id()))
            .flatten();
        !wrapper_covers(
            &key_file,
            batch.base.id(),
            batch.epoch,
            &account_keys,
            hidden_key.as_ref(),
        )
    });
    let previous_problem = row.problem.clone();
    row.problem = if stale_batch || skipped_wrapper {
        Some(stale_wrapper_problem(previous_problem.as_deref()).into())
    } else {
        None
    };
    if stale_batch {
        // Keep every dirty cursor and write no unusable keys file or snapshot.
        return Ok(BackupRun::default());
    }
    let keys_valid = match row.keys_name.as_deref() {
        Some(name) => {
            let name = path(dir, &format::keys_path(name));
            exists(folder, &name)?
                && format::decode(FileKind::Keys, &folder.read(&name)?).is_ok_and(|records| {
                    records.len() == 1 && serde_json::from_slice::<KeysFile>(records[0]).is_ok()
                })
        }
        None => false,
    };
    let write_keys = row.keys_hash.as_deref() != Some(&hash) || !keys_valid;
    let mut result = BackupRun::default();
    let mut work = write_keys || batches.iter().any(|b| b.snapshot || !b.records.is_empty());
    for base in &bases {
        let _guard = base.backup_guard().await;
        if hidden_ids.contains(&base.id()) && !base.backup_open() {
            continue;
        }
        work |= !base.db()?.parts_to_copy(row.generation)?.is_empty();
    }
    if !work {
        return Ok(result);
    }
    result.run = Some(run.clone());
    if !exists(folder, "README.txt")? {
        check_running(account, generation)?;
        folder.write("README.txt", b"BaseHero encrypted backup. Keep your password and recovery kit to restore your data.\n")?;
        check_running(account, generation)?;
    }
    if write_keys {
        check_running(account, generation)?;
        let name = path(dir, &format::keys_path(&run));
        let bytes = write_record(
            account,
            folder,
            &name,
            FileKind::Keys,
            &[serde_json::to_vec(&key_file).expect("keys JSON")],
            generation,
        )?;
        row.keys_hash = Some(hash);
        row.keys_name = Some(run.clone());
        row.bytes = row.bytes.saturating_add(bytes);
        account.update_backup_progress(row, row.generation, location)?;
    }
    for batch in batches.iter().filter(|batch| batch.snapshot) {
        check_running(account, generation)?;
        let name = path(dir, &format::snapshot_path(batch.base.id(), &run));
        let bytes = write_record(
            account,
            folder,
            &name,
            FileKind::Snapshot,
            &batch.records,
            generation,
        )?;
        {
            let _guard = batch.base.backup_guard().await;
            if !batch.hidden || batch.base.backup_open() {
                let mut db = batch.base.db()?;
                db.set_snapshot(row.generation, &run, bytes, batch.epoch)?;
                db.commit_backup(row.generation, &batch.committed, 0)?;
            }
        }
        row.bytes = row.bytes.saturating_add(bytes);
        result.snapshots += 1;
        result.objects += batch.records.len();
    }
    let log: Vec<Vec<u8>> = batches
        .iter()
        .filter(|batch| !batch.snapshot)
        .flat_map(|batch| batch.records.iter().cloned())
        .collect();
    check_running(account, generation)?;
    let size = write_record(
        account,
        folder,
        &path(dir, &format::log_path(&run)),
        FileKind::Log,
        &log,
        generation,
    )?;
    row.bytes = row.bytes.saturating_add(size);
    result.objects += log.len();
    for batch in batches.iter().filter(|batch| !batch.snapshot) {
        let _guard = batch.base.backup_guard().await;
        if !batch.hidden || batch.base.backup_open() {
            let bytes = batch
                .records
                .iter()
                .map(|record| record.len() as u64 + 4)
                .sum();
            batch
                .base
                .db()?
                .commit_backup(row.generation, &batch.committed, bytes)?;
        }
    }
    for base in &bases {
        let parts = {
            let _guard = base.backup_guard().await;
            if hidden_ids.contains(&base.id()) && !base.backup_open() {
                continue;
            }
            base.db()?.parts_to_copy(row.generation)?
        };
        for (id, count, copied) in parts {
            for n in copied..count {
                check_running(account, generation)?;
                let bytes = {
                    let _guard = base.backup_guard().await;
                    if hidden_ids.contains(&base.id()) && !base.backup_open() {
                        break;
                    }
                    std::fs::read(base.part_file(id, n)).map_err(Error::from)?
                };
                let destination = path(dir, &format::part_path(base.id(), id, n));
                check_running(account, generation)?;
                folder.write(&destination, &bytes)?;
                check_running(account, generation)?;
                if folder.read(&destination)? != bytes {
                    return Err(FolderError::Other("incomplete file part".into()).into());
                }
                {
                    let _guard = base.backup_guard().await;
                    if !hidden_ids.contains(&base.id()) || base.backup_open() {
                        base.db()?.part_copied(row.generation, id, n + 1)?;
                    }
                }
                row.bytes = row.bytes.saturating_add(bytes.len() as u64);
                result.parts += 1;
            }
        }
    }
    check_running(account, generation)?;
    row.last_run = Some(run);
    Ok(result)
}

#[cfg(test)]
mod mac_folder_tests {
    use super::*;

    #[test]
    fn a_keys_file_must_open_the_epoch_actually_sealed_in_a_batch() {
        use bh_proto::{AccountId, DeviceId};
        let base = crate::BaseId([3; 16]);
        let account_key = Secret::<32>::from_slice(&[7; 32]).unwrap();
        let first = BaseKey::new(&[1; 32]).unwrap();
        let second = BaseKey::new(&[2; 32]).unwrap();
        let account = AccountId([1; 16]);
        let mut keys = KeysFile {
            v: 1,
            account,
            device: DeviceId([2; 16]),
            server: String::new(),
            email: String::new(),
            written_at: 0,
            salt: vec![],
            kdf: crate::keys::DEFAULT_KDF,
            envelope: vec![],
            envelope_checked: false,
            account_data: None,
            wrappers: vec![Wrapper {
                base,
                epoch: 1,
                wrapper: crate::envelope::seal(
                    &bh_crypto::kdf(&account_key, b"bhbasew1", 1),
                    &keys::account_wrapper_aad(&base, 1),
                    first.secret().expose(),
                ),
                chain: vec![],
            }],
        };
        let account_keys = [&account_key];
        assert!(!wrapper_covers(&keys, base, 2, &account_keys, None));
        keys.wrappers[0].epoch = 2;
        keys.wrappers[0].wrapper = crate::envelope::seal(
            &bh_crypto::kdf(&account_key, b"bhbasew1", 1),
            &keys::account_wrapper_aad(&base, 2),
            second.secret().expose(),
        );
        assert!(!wrapper_covers(&keys, base, 1, &account_keys, None));
        keys.wrappers[0].chain.push(PreviousKey {
            epoch: 1,
            sealed: crate::rotation::seal_previous(&second, &base, 1, &first),
        });
        assert!(wrapper_covers(&keys, base, 1, &account_keys, None));
        assert!(wrapper_covers(&keys, base, 2, &account_keys, None));
    }

    #[test]
    fn a_corrupt_previous_key_link_does_not_cover_an_older_sealed_epoch() {
        use crate::{base::BaseKey, envelope, keys, rotation::seal_previous};
        use bh_crypto::Secret;
        use bh_proto::{AccountId, DeviceId};
        let account = AccountId([4; 16]);
        let base = crate::BaseId([3; 16]);
        let account_key = Secret::<32>::from_slice(&[7; 32]).unwrap();
        let first = BaseKey::new(&[1; 32]).unwrap();
        let current = BaseKey::new(&[2; 32]).unwrap();
        let wrapper = envelope::seal(
            &bh_crypto::kdf(&account_key, b"bhbasew1", 1),
            &keys::account_wrapper_aad(&base, 2),
            current.secret().expose(),
        );
        let mut sealed = seal_previous(&current, &base, 1, &first);
        *sealed.last_mut().unwrap() ^= 1;
        let file = KeysFile {
            v: 1,
            account,
            device: DeviceId([5; 16]),
            server: String::new(),
            email: String::new(),
            written_at: 0,
            salt: vec![],
            kdf: crate::keys::DEFAULT_KDF,
            envelope: vec![],
            envelope_checked: true,
            wrappers: vec![Wrapper {
                base,
                epoch: 2,
                wrapper,
                chain: vec![PreviousKey { epoch: 1, sealed }],
            }],
            account_data: None,
        };
        assert!(
            !wrapper_covers(&file, base, 1, &[&account_key], None),
            "corrupt link was accepted"
        );
    }

    #[test]
    fn a_transient_key_mismatch_is_silent_and_a_repeated_one_warns() {
        assert_eq!(stale_wrapper_problem(None), "keyMismatch");
        assert_eq!(
            stale_wrapper_problem(Some("keyMismatch")),
            "usingLastChecked"
        );
        assert_eq!(
            stale_wrapper_problem(Some("usingLastChecked")),
            "usingLastChecked"
        );
    }

    #[test]
    fn a_missing_default_folder_is_recreated_only_when_its_parent_exists() {
        let home = tempfile::tempdir().unwrap();
        let parent = home.path().join("Documents");
        std::fs::create_dir(&parent).unwrap();
        let default = parent.join("BaseHero Backup");
        recreate_mac_default(&default);
        assert!(default.is_dir());
        std::fs::remove_dir(&default).unwrap();
        let custom = parent.join("Custom");
        recreate_mac_default(&custom);
        assert!(!custom.exists());
        std::fs::remove_dir(&parent).unwrap();
        recreate_mac_default(&default);
        assert!(!default.exists());
        let cloud = home
            .path()
            .join("Library/Mobile Documents/com~apple~CloudDocs");
        std::fs::create_dir_all(&cloud).unwrap();
        recreate_mac_default(&cloud.join("BaseHero"));
        assert!(cloud.join("BaseHero").is_dir());
    }
}
