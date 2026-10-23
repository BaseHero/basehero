//! The account directory at the account's home: this device's entry for its
//! own base, carrying only the key package of the base's current epoch, and
//! reading the directory back.
//!
//! A device reads the directory only when it knows of no entry of its own
//! (its first start, or an upgrade from a build without one), when its write
//! was refused, or when the base's entry is ahead of the epoch this device
//! verified; such an entry is read again after the account and base are
//! followed. An entry behind that epoch is written over, as a missing one
//! is: versions rise with the epoch. The device whose rekey installed the
//! base's current epoch writes the entry for it, at a version that rises
//! with the epoch: the installing control's base position. Every opened
//! entry raises the version this device remembers for it, across restarts,
//! and a lower one is refused. Writing is tracked durably, so a restart does
//! not write again.
//!
//! The same step writes this device's own entries once each, its name and a
//! password check it holds unpublished, and reads the whole directory back
//! only when the host asks (its devices view opened, or a password change
//! needs the account's check) or once an addition was followed: never on
//! every pass. What a read finds goes to the host: each active device's name
//! as that device signed it, and the current record's password check.
use crate::{
    DirectoryRead, Shared,
    backoff::Backoff,
    copier::Copier,
    outbox::{Fail, Link},
    puller::only,
};
use bh_account::{
    DeviceId,
    directory::DirectoryEntry,
    owner::staging::{EntryRefused, directory_entry_id},
};
use bh_authz_proto::{ToService, Want, account_log_id};
use bh_storage::sync_state::ControlOutcome;
use bh_sync::{
    Digest,
    permit::{LogId, LogKind},
    wire::{Request, Response},
};
use std::collections::BTreeSet;
use tokio::time::Instant;

/// Pages of one read, at most: 64 entries each.
const MAX_PAGES: usize = 1024;

/// What the directory step keeps between passes.
#[derive(Default)]
pub(crate) struct Directory {
    /// Read again once the account and base were followed.
    after_follow: bool,
    /// The own base's entry, this device's own entries and reads of names
    /// each wait their own backoff after a failure.
    base: Paced,
    own: Paced,
    read: Paced,
    /// The active devices when names were last read, or when this client
    /// started: one added since is read once.
    devices: Option<BTreeSet<DeviceId>>,
    /// The host asked for a read that has not succeeded yet.
    wanted: bool,
}

/// When an attempt may run again, after a failure.
#[derive(Default)]
struct Paced {
    at: Option<Instant>,
    backoff: Backoff,
}
impl Paced {
    fn ready(&self) -> bool {
        self.at.is_none_or(|at| Instant::now() >= at)
    }
    /// Settle one attempt: a failure waits this backoff, and only a broken
    /// link is the lane's.
    fn settle(&mut self, attempt: Result<bool, Fail>) -> Result<bool, Fail> {
        match attempt {
            Ok(moved) => {
                self.at = None;
                self.backoff.reset();
                Ok(moved)
            }
            Err(fail) => {
                self.at = Some(Instant::now() + self.backoff.next());
                if fail == Fail::Network {
                    Err(fail)
                } else {
                    Ok(false)
                }
            }
        }
    }
}

/// The base's current epoch as this device verified it, and the version its
/// entry carries: the base position of the control that installed it.
#[derive(Clone, Copy)]
struct Target {
    epoch: [u8; 32],
    version: u64,
}

/// What a read found for the own base.
enum Found {
    Current(u64),
    Missing,
    /// Another epoch's entry below this device's version, or one refused as
    /// older than a version this device remembers below it.
    Behind,
    /// Another epoch's entry at or above this device's version, or one
    /// refused as older than a version this device remembers at or above it.
    Ahead,
}

fn local<T, E>(result: Result<T, E>) -> Result<T, Fail> {
    result.map_err(|_| Fail::Local)
}

fn authority<T, E>(result: Result<T, E>) -> Result<T, Fail> {
    result.map_err(|_| Fail::Authorization)
}

/// One step for the own base `log`. Runs only when no account change waits
/// to be copied. The own base's entry, this device's own entries and a read
/// of names each wait their own backoff after a failure, so one failing
/// holds back neither other; only a broken link is the lane's.
pub(crate) async fn step(
    shared: &Shared,
    link: &mut Link,
    directory: &mut Directory,
    copier: &mut Copier,
    log: LogId,
) -> Result<bool, Fail> {
    if copier.stopped || copier.unsettled {
        return Ok(false);
    }
    let mut moved = false;
    if directory.base.ready() && !(directory.after_follow && copier.follow) {
        let attempt = pass(shared, link, directory, copier, log).await;
        moved |= directory.base.settle(attempt)?;
    }
    if directory.own.ready() {
        let attempt = own(shared, link).await;
        moved |= directory.own.settle(attempt)?;
    }
    if directory.read.ready() {
        let attempt = names(shared, link, directory).await;
        if attempt.is_err() {
            shared.signer.directory_unread();
        }
        moved |= directory.read.settle(attempt)?;
    }
    Ok(moved)
}

async fn pass(
    shared: &Shared,
    link: &mut Link,
    directory: &mut Directory,
    copier: &mut Copier,
    log: LogId,
) -> Result<bool, Fail> {
    let Some(target) = target(shared, log)? else {
        return Ok(false);
    };
    let state = authority(shared.signer.directory_state())?;
    let reread = std::mem::take(&mut directory.after_follow);
    match state {
        Some((version, true)) if version >= target.version && !reread => return Ok(false),
        // A write at this version was started and not confirmed.
        Some((version, false)) if version >= target.version && !reread => {
            return write(shared, link, directory, copier, log, target, version).await;
        }
        Some(_) if !reread => {
            if !producer(shared, log, target)? {
                return Ok(false);
            }
            return write(shared, link, directory, copier, log, target, target.version).await;
        }
        _ => {}
    }
    // No entry of its own known, or one to read again: read first.
    let found = read_own(shared, link, log, target).await?;
    settle(shared, link, directory, copier, log, target, found).await
}

#[allow(clippy::too_many_arguments)] // One step's independently pinned inputs.
async fn settle(
    shared: &Shared,
    link: &mut Link,
    directory: &mut Directory,
    copier: &mut Copier,
    log: LogId,
    target: Target,
    found: Found,
) -> Result<bool, Fail> {
    match found {
        Found::Current(_) => {
            authority(shared.signer.set_directory_state(target.version, true))?;
            Ok(true)
        }
        Found::Missing | Found::Behind => {
            write(shared, link, directory, copier, log, target, target.version).await
        }
        // Read again after the next follow, paced like any failure.
        Found::Ahead => {
            directory.after_follow = true;
            copier.follow = true;
            Err(Fail::Retry)
        }
    }
}

/// The base's current epoch, from content's verified state and the control
/// feed's facts. `None` while the epoch is closed or the facts lag it.
fn target(shared: &Shared, log: LogId) -> Result<Option<Target>, Fail> {
    let database = local(shared.owner.shared_database(shared.container))?;
    let db = database.lock().expect("container writer lock");
    let Some(progress) = local(db.log_progress(LogKind::Base as u8, log.id))? else {
        return Ok(None);
    };
    let Some(epoch) = progress.epoch_id else {
        return Ok(None);
    };
    let version = match local(db.control_fact_at(log.id, progress.position))? {
        Some(fact) if fact.epoch == Some(epoch) => fact.epoch_installed.0,
        Some(_) => return Ok(None),
        // No control after the genesis: its epoch is the genesis's.
        None => 1,
    };
    Ok(Some(Target { epoch, version }))
}

/// Whether this device's rekey installed the target epoch: its kept control
/// for the account change that rekey copied was committed.
fn producer(shared: &Shared, log: LogId, target: Target) -> Result<bool, Fail> {
    if target.version < 2 {
        return Ok(false);
    }
    let database = local(shared.owner.shared_database(shared.container))?;
    let db = database.lock().expect("container writer lock");
    let Some(fact) = local(db.control_fact(log.id, target.version))? else {
        return Ok(false);
    };
    Ok(local(db.base_control_outcome(log.id, fact.account.0))?
        == Some(Some(ControlOutcome::Committed)))
}

fn account_log(shared: &Shared) -> Result<LogId, Fail> {
    let identity = authority(shared.signer.identity())?;
    Ok(LogId {
        kind: LogKind::Account,
        id: local(account_log_id(&identity.genesis))?,
    })
}

/// Write the own base's entry at `version`, recording the attempt first.
#[allow(clippy::too_many_arguments)] // One step's independently pinned inputs.
async fn write(
    shared: &Shared,
    link: &mut Link,
    directory: &mut Directory,
    copier: &mut Copier,
    log: LogId,
    target: Target,
    version: u64,
) -> Result<bool, Fail> {
    authority(shared.signer.set_directory_state(version, false))?;
    let bytes = authority(
        shared
            .signer
            .prepare_base_entry(
                bh_sync::BaseId(log.id),
                target.epoch,
                shared.endpoint.edge_url.clone(),
                version,
            )
            .await,
    )?;
    let entry = directory_entry_id(&bytes).ok_or(Fail::Local)?;
    match store(shared, link, entry, version, bytes).await? {
        Stored::Stored => {
            authority(shared.signer.set_directory_state(version, true))?;
            Ok(true)
        }
        // The home holds this entry at this version or later already: an
        // earlier attempt of this device's, or another device's. Read it.
        Stored::Conflict => {
            let found = read_own(shared, link, log, target).await?;
            match found {
                Found::Current(held) if held >= version => {
                    authority(shared.signer.set_directory_state(version, true))?;
                    Ok(true)
                }
                _ => {
                    directory.after_follow = true;
                    copier.follow = true;
                    Err(Fail::Retry)
                }
            }
        }
    }
}

/// How the home took one entry write.
enum Stored {
    Stored,
    /// It holds `entry` at this version or later already.
    Conflict,
}

/// Store `bytes` as directory entry `entry` at `version`.
async fn store(
    shared: &Shared,
    link: &mut Link,
    entry: [u8; 32],
    version: u64,
    bytes: Vec<u8>,
) -> Result<Stored, Fail> {
    let len = u32::try_from(bytes.len()).map_err(|_| Fail::Local)?;
    let answer = shared
        .authz
        .request(
            shared,
            ToService::Permits {
                items: vec![Want::StoreDirectoryEntry {
                    log: account_log(shared)?,
                    entry,
                    version,
                    body: Digest(bh_crypto::hash(&bytes)),
                    len,
                }],
            },
        )
        .await?;
    let permit = only(answer)?;
    let data = link.data(shared).await?;
    match data
        .ask(|id| Request::StoreDirectoryEntry {
            id,
            permit,
            body: bytes,
        })
        .await
        .map_err(|_| Fail::Network)?
    {
        Response::DirectoryEntryStored { .. } => Ok(Stored::Stored),
        Response::Refused {
            reason: bh_sync::wire::Refusal::Conflict,
            ..
        } => Ok(Stored::Conflict),
        other => Err(Fail::from_response(&other)),
    }
}

/// Write each of this device's own entries the home is not known to hold.
/// One the home already holds at that version or later (a conflict) counts
/// as held: only this device writes its own entries.
async fn own(shared: &Shared, link: &mut Link) -> Result<bool, Fail> {
    let entries = authority(shared.signer.own_entries().await)?;
    let mut moved = false;
    for (version, bytes) in entries {
        let entry = directory_entry_id(&bytes).ok_or(Fail::Local)?;
        // Stored now, or already held at this version or later.
        store(shared, link, entry, version, bytes).await?;
        authority(shared.signer.own_entry_held(entry, version))?;
        moved = true;
    }
    Ok(moved)
}

/// Read the directory for the host, when it asked or a device was added
/// since the last read, and tell it what the read found.
async fn names(shared: &Shared, link: &mut Link, directory: &mut Directory) -> Result<bool, Fail> {
    directory.wanted |= shared.signer.directory_wanted();
    let account = authority(shared.signer.current_account())?;
    let active: BTreeSet<DeviceId> = local(account.active_devices())?
        .map(|keys| keys.id())
        .collect();
    let added = directory
        .devices
        .as_ref()
        .is_some_and(|known| !active.is_subset(known));
    if !directory.wanted && !added {
        directory.devices.get_or_insert(active);
        return Ok(false);
    }
    let entries = read(shared, link).await?;
    let opened = authority(shared.signer.open_directory_entries(entries).await)?;
    let mut found = DirectoryRead {
        names: Vec::new(),
        password_check: None,
    };
    for entry in opened.into_iter().flatten() {
        match entry.entry {
            // A device names only itself.
            DirectoryEntry::DeviceName { device, name }
                if entry.signer == device && active.contains(&device) =>
            {
                found.names.push((device, name));
            }
            DirectoryEntry::PasswordCheck { check, .. } if found.password_check.is_none() => {
                found.password_check = Some(check);
            }
            _ => {}
        }
    }
    shared.signer.directory_read(found);
    directory.devices = Some(active);
    directory.wanted = false;
    Ok(true)
}

/// Read the whole directory, open it and find the own base's entry.
async fn read_own(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    target: Target,
) -> Result<Found, Fail> {
    // A device that cannot open the directory reads nothing.
    authority(shared.signer.open_directory_entries(Vec::new()).await)?;
    let entries = read(shared, link).await?;
    let opened = authority(shared.signer.open_directory_entries(entries).await)?;
    let mut found = Found::Missing;
    let mut stale = |version: u64| {
        if version < target.version {
            if matches!(found, Found::Missing) {
                found = Found::Behind;
            }
        } else {
            found = Found::Ahead;
        }
    };
    for entry in &opened {
        match entry {
            Ok(opened) => {
                if let DirectoryEntry::Base { base, epoch_id, .. } = &opened.entry
                    && *base == log.id
                {
                    if *epoch_id == target.epoch {
                        return Ok(Found::Current(opened.version));
                    }
                    stale(opened.version);
                }
            }
            Err(EntryRefused::LowerVersion { remembered }) => stale(*remembered),
            Err(EntryRefused::Invalid(_)) => {}
        }
    }
    Ok(found)
}

/// Every entry the home holds, page by page.
pub(crate) async fn read(shared: &Shared, link: &mut Link) -> Result<Vec<Vec<u8>>, Fail> {
    let log = account_log(shared)?;
    let mut entries = Vec::new();
    let mut after = None;
    for _ in 0..MAX_PAGES {
        let answer = shared
            .authz
            .request(
                shared,
                ToService::Permits {
                    items: vec![Want::ReadDirectory { log }],
                },
            )
            .await?;
        let permit = only(answer)?;
        let data = link.data(shared).await?;
        let (page, more) = match data
            .ask(|id| Request::ReadDirectory { id, permit, after })
            .await
            .map_err(|_| Fail::Network)?
        {
            Response::Directory { entries, more, .. } => (entries, more),
            other => return Err(Fail::from_response(&other)),
        };
        let last = page.last().map(|entry| directory_entry_id(entry));
        entries.extend(page);
        if !more {
            return Ok(entries);
        }
        after = Some(last.flatten().ok_or(Fail::Network)?);
    }
    Err(Fail::Network)
}
