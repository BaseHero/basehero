//! Native per-account files. Filenames are independent random identifiers;
//! stored account rows are never registration or routing authority.
use super::{AccountAuthority, ContainerId, Owner, OwnerError};
use bh_crypto::random;
use bh_storage::{DeviceDatabase, OpenError};
use std::{fs, path::Path};

fn open_error(error: OpenError) -> OwnerError {
    match error {
        OpenError::Busy => OwnerError::Busy,
        other => OwnerError::Open(other),
    }
}

fn accounts(dir: &Path) -> std::path::PathBuf {
    dir.join("accounts")
}

fn container_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".sqlite") else {
        return false;
    };
    stem.len() == 32
        && stem
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Owner {
    /// Create a new random account container, locking its sibling before SQLite
    /// opens. Neither the filename nor the unverified account row is authority.
    /// A crash after SQLite initialization can leave an empty unanchored file;
    /// callers may reuse it only after `is_empty` confirms it is still empty.
    pub fn create_container(&self, dir: &Path) -> Result<ContainerId, OwnerError> {
        let directory = accounts(dir);
        fs::create_dir_all(&directory).map_err(OwnerError::Io)?;
        let db = loop {
            let name: String = random::<16>()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let candidate = directory.join(format!("{name}.sqlite"));
            match DeviceDatabase::create_container(&candidate).map_err(open_error)? {
                Some(db) => break db,
                None => continue,
            }
        };
        self.install(db, None, AccountAuthority::Unbound)
    }

    /// Call once per Owner. Each random-named file has its own result: a busy,
    /// newer or damaged account cannot hide another account's opened ID. Only
    /// failure to enumerate the directory returns an outer error. A second call
    /// reports this Owner's already-open files as Busy too.
    #[expect(
        clippy::type_complexity,
        reason = "per-file results are the public caller contract"
    )]
    pub fn open_containers(
        &self,
        dir: &Path,
    ) -> Result<Vec<(String, Result<ContainerId, OwnerError>)>, OwnerError> {
        let entries = match fs::read_dir(accounts(dir)) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(OwnerError::Io(e)),
        };
        // Finish enumeration before installing anything: an iterator error is
        // the only remaining outer failure and must not strand opened IDs.
        let entries = entries
            .collect::<Result<Vec<_>, _>>()
            .map_err(OwnerError::Io)?;
        let mut files = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            let Some(stem) = name
                .to_str()
                .filter(|n| container_name(n))
                .and_then(|n| n.strip_suffix(".sqlite"))
            else {
                continue;
            };
            let result = (|| {
                if !entry.file_type().map_err(OwnerError::Io)?.is_file() {
                    return Ok(None);
                }
                let db = DeviceDatabase::open_container(&entry.path()).map_err(open_error)?;
                self.install(db, None, AccountAuthority::Unbound).map(Some)
            })();
            if let Some(result) = match result {
                Ok(None) => None,
                Ok(Some(id)) => Some(Ok(id)),
                Err(error) => Some(Err(error)),
            } {
                files.push((stem.to_owned(), result));
            }
        }
        Ok(files)
    }
}
