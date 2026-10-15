//! Device-wide signed policy owner. The directory must be durable app data,
//! outside account storage and evictable caches. One owner per provider/process.
use basehero_models::provider_policy::{
    self, Install, MAX_ENVELOPE_BYTES, Reject, RouteEvidence, Snapshot, State, Trust,
};
use bh_confidential_attestation::Time;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    sync::RwLock,
};

#[derive(Debug)]
pub enum Error {
    Storage(io::Error),
    Busy,
    Configuration,
    Shipped(Reject),
    Quarantined,
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Storage(error)
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    Installed { usable_now: bool },
    Same { usable_now: bool },
    Rejected(Reject),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Write,
    FileSync,
    Rename,
    DirectorySync,
}

pub struct Owner {
    directory: PathBuf,
    path: PathBuf,
    // Never remove the lock inode: another process may hold it while waiting.
    _lock: File,
    state: State,
    reader: Reader,
    quarantined: bool,
    trust: OwnedTrust,
}
struct OwnedTrust {
    root: [u8; 32],
    key_id: [u8; 8],
    provider: String,
    models: Vec<String>,
    app_build_date: u64,
    max_lifetime_secs: u64,
}
impl OwnedTrust {
    fn new(trust: &Trust<'_>) -> Self {
        Self {
            root: trust.root,
            key_id: trust.key_id,
            provider: trust.provider.to_owned(),
            models: trust.models.iter().map(|m| (*m).to_owned()).collect(),
            app_build_date: trust.app_build_date,
            max_lifetime_secs: trust.max_lifetime_secs,
        }
    }
    fn with_trust<R>(&self, f: impl FnOnce(&Trust<'_>) -> R) -> R {
        let names: Vec<&str> = self.models.iter().map(String::as_str).collect();
        f(&Trust {
            root: self.root,
            key_id: self.key_id,
            provider: &self.provider,
            models: &names,
            app_build_date: self.app_build_date,
            max_lifetime_secs: self.max_lifetime_secs,
        })
    }
}
fn read_bounded(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_ENVELOPE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok((bytes.len() <= MAX_ENVELOPE_BYTES).then_some(bytes))
}
fn atomic_write(
    directory: &Path,
    path: &Path,
    bytes: &[u8],
    fault: Option<Stage>,
) -> io::Result<()> {
    let mut temp = tempfile::NamedTempFile::new_in(directory)?;
    if fault == Some(Stage::Write) {
        return Err(io::Error::other("injected write"));
    }
    temp.write_all(bytes)?;
    temp.flush()?;
    if fault == Some(Stage::FileSync) {
        return Err(io::Error::other("injected file sync"));
    }
    temp.as_file().sync_all()?;
    if fault == Some(Stage::Rename) {
        return Err(io::Error::other("injected rename"));
    }
    temp.persist(path).map_err(|e| e.error)?;
    if fault == Some(Stage::DirectorySync) {
        return Err(io::Error::other("injected directory sync"));
    }
    File::open(directory)?.sync_all()?;
    Ok(())
}
impl Owner {
    /// Holds the OS lock for this provider for the whole ownership lifetime.
    /// Shipped bytes and trust must come from one authenticated app release.
    /// After dropping an owner, `Busy` can be transient if this process is
    /// concurrently spawning a child that briefly inherited its lock fd.
    pub fn open(
        directory: &Path,
        trust: &Trust<'_>,
        shipped: &[u8],
        time: Option<Time>,
    ) -> Result<Self, Error> {
        if trust.provider.is_empty()
            || !trust
                .provider
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        {
            return Err(Error::Configuration);
        }
        if shipped.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::Shipped(Reject::TooLarge));
        }
        let owned = OwnedTrust::new(trust);
        let initial = provider_policy::restore(shipped, trust).map_err(Error::Shipped)?;
        fs::create_dir_all(directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join(format!("{}.lock", trust.provider)))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| Error::Busy)?;
        let path = directory.join(format!("{}.policy", trust.provider));
        let restored = match read_bounded(&path) {
            Ok(Some(bytes)) => provider_policy::restore(&bytes, trust).ok(),
            Ok(None) => None,
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::Storage(e)),
        };
        let needs_seed = restored.is_none();
        let state = restored.unwrap_or(initial);
        let reader = Reader(Arc::new(RwLock::new(Some(Arc::new(
            state.snapshot().clone(),
        )))));
        let mut owner = Self {
            directory: directory.to_owned(),
            path,
            _lock: lock,
            state,
            reader,
            quarantined: false,
            trust: owned,
        };
        // A missing or corrupt file is seeded durably before its snapshot escapes.
        if needs_seed {
            atomic_write(
                &owner.directory,
                &owner.path,
                owner.state.signed_bytes(),
                None,
            )?;
        }
        owner.install_inner(shipped, time, None)?;
        Ok(owner)
    }
    /// Obtain a reader that does not hold the installer gate across disk sync.
    pub fn reader(&self) -> Reader {
        self.reader.clone()
    }
    /// None during an ambiguous write: no route may use the old snapshot.
    pub fn snapshot(&self) -> Option<Arc<Snapshot>> {
        self.reader.snapshot()
    }
    pub fn signed_bytes(&self) -> &[u8] {
        self.state.signed_bytes()
    }
    pub fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    pub fn install(&mut self, bytes: &[u8], time: Option<Time>) -> Result<Change, Error> {
        self.install_inner(bytes, time, None)
    }
    fn install_inner(
        &mut self,
        bytes: &[u8],
        time: Option<Time>,
        fault: Option<Stage>,
    ) -> Result<Change, Error> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Ok(Change::Rejected(Reject::TooLarge));
        }
        if self.quarantined {
            // A prior rename may have succeeded despite an ambiguous sync error.
            // Reconcile from disk before allowing another transition.
            let disk = read_bounded(&self.path)?.ok_or_else(|| {
                Error::Storage(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stored policy too large",
                ))
            })?;
            self.state = self
                .trust
                .with_trust(|trust| provider_policy::restore(&disk, trust))
                .map_err(|e| {
                    Error::Storage(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("stored policy: {e:?}"),
                    ))
                })?;
        }
        let result = self
            .trust
            .with_trust(|trust| provider_policy::install(Some(&self.state), bytes, trust, time));
        match result {
            Install::Reject(_) if self.quarantined => Err(Error::Quarantined),
            Install::Reject(e) => Ok(Change::Rejected(e)),
            Install::Same { .. } if self.quarantined => Err(Error::Quarantined),
            Install::Same { usable_now } => Ok(Change::Same { usable_now }),
            Install::Installed { state, usable_now } => {
                if let Err(e) =
                    atomic_write(&self.directory, &self.path, state.signed_bytes(), fault)
                {
                    self.quarantined = true;
                    *self.reader.0.write().unwrap() = None;
                    return Err(Error::Storage(e));
                }
                self.state = state;
                *self.reader.0.write().unwrap() = Some(Arc::new(self.state.snapshot().clone()));
                self.quarantined = false;
                Ok(Change::Installed { usable_now })
            }
        }
    }
    #[cfg(test)]
    fn install_with_fault(
        &mut self,
        bytes: &[u8],
        time: Option<Time>,
        fault: Option<Stage>,
    ) -> Result<Change, Error> {
        self.install_inner(bytes, time, fault)
    }
}
/// Cloneable handoff reader. The short lock only clones an immutable snapshot;
/// it is never held while the installer persists a policy.
#[derive(Clone)]
pub struct Reader(Arc<RwLock<Option<Arc<Snapshot>>>>);
impl Reader {
    pub fn snapshot(&self) -> Option<Arc<Snapshot>> {
        self.0.read().unwrap().clone()
    }
    /// Load at this handoff, never from an admission-time cached Arc. A
    /// quarantined write exposes no snapshot and cannot authorize dispatch.
    pub fn check_current(
        &self,
        evidence: RouteEvidence<'_>,
        time: Option<Time>,
    ) -> Result<(), Reject> {
        let snapshot = self.snapshot().ok_or(Reject::Denied)?;
        provider_policy::check_current(&snapshot, evidence, time)
    }
}

/// One device/provider refresh lane. `begin` records the attempt durably before
/// a fetch; invoke it on startup, resume and timer wakeups. Always call `finish`
/// on completion *and cancellation*, or subsequent attempts remain coalesced.
/// Wall seconds come from the device clock; a backwards jump is due.
pub struct Schedule {
    path: PathBuf,
    last: Option<(u64, u64, u64)>, // attempt, routine deadline, unknown deadline
    active: bool,
    seed: u64,
}
impl Schedule {
    pub fn new(owner: &Owner) -> Result<Self, Error> {
        let path = owner
            .directory
            .join(format!("{}.attempt", owner.trust.provider));
        let last = match File::open(&path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(129).read_to_end(&mut bytes)?;
                (bytes.len() <= 128)
                    .then(|| std::str::from_utf8(&bytes).ok())
                    .flatten()
                    .and_then(|s| {
                        let fields = s
                            .trim()
                            .split(':')
                            .map(str::parse::<u64>)
                            .collect::<Result<Vec<_>, _>>();
                        fields
                            .ok()
                            .and_then(|v| (v.len() == 3).then(|| (v[0], v[1], v[2])))
                    })
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::Storage(e)),
        };
        use rand::TryRngCore;
        let seed = rand::rngs::OsRng
            .try_next_u64()
            .map_err(|e| Error::Storage(io::Error::other(format!("OS randomness: {e:?}"))))?;
        Ok(Self {
            path,
            last,
            active: false,
            seed: if seed == 0 { 1 } else { seed },
        })
    }
    pub fn begin(&mut self, now: u64, unknown_deployment: bool) -> Result<bool, Error> {
        if self.active {
            return Ok(false);
        }
        if let Some((attempt, routine, unknown)) = self.last
            && now >= attempt
            && now < routine
            && (!unknown_deployment || now < unknown)
        {
            return Ok(false);
        }
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        let routine = now.saturating_add(6 * 3600 + self.seed % 3600);
        let unknown = now.saturating_add(1800 + (self.seed / 3600) % 1800);
        let record = format!("{now}:{routine}:{unknown}\n");
        atomic_write(
            self.path.parent().unwrap(),
            &self.path,
            record.as_bytes(),
            None,
        )?;
        self.last = Some((now, routine, unknown));
        self.active = true;
        Ok(true)
    }
    pub fn finish(&mut self) {
        self.active = false;
    }
}

pub mod fetch;
#[cfg(test)]
mod tests;
