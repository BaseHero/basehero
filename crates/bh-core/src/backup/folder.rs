use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
};
use ts_rs::TS;

/// A folder the backup reads and writes through. Paths are relative, `/`-separated,
/// without `.` or `..`; `""` is the folder itself.
pub trait BackupFolder: Send + Sync {
    /// Lists immediate children of a directory, or returns an empty list if it is missing.
    fn list(&self, dir: &str) -> Result<Vec<FolderEntry>, FolderError>;
    /// Reads the bytes of a file. A missing file returns [`FolderError::Other`],
    /// not [`FolderError::Unreachable`] (which means the folder itself is unavailable).
    fn read(&self, path: &str) -> Result<Vec<u8>, FolderError>;
    /// Writes a file, creating parent directories and replacing an existing file.
    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), FolderError>;
    /// Removes a file or entire directory; missing paths are ignored.
    fn remove(&self, path: &str) -> Result<(), FolderError>;
}

/// One immediate child in a backup folder listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderEntry {
    /// The child's name (not its relative path).
    pub name: String,
    /// Whether this child is a directory.
    pub dir: bool,
    /// The file's byte length, or zero for a directory.
    pub size: u64,
}

/// A failure while accessing a backup folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FolderError {
    /// The folder is disconnected, missing or inaccessible.
    Unreachable,
    /// Access previously granted to the folder has been revoked.
    PermissionLost,
    /// The destination cannot accept more bytes.
    Full,
    /// Another filesystem error.
    Other(String),
}

/// A backup folder on the local filesystem.
pub struct LocalFolder {
    root: PathBuf,
}

impl LocalFolder {
    /// Uses an existing local folder as the backup root; does not create it.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn path(&self, relative: &str, allow_root: bool) -> Result<PathBuf, FolderError> {
        if (!allow_root && relative.is_empty())
            || relative.starts_with('/')
            || relative.contains('\\')
            || relative
                .split('/')
                .any(|c| c == "." || c == ".." || c.is_empty() && !relative.is_empty())
        {
            return Err(FolderError::Other("invalid backup path".into()));
        }
        let root = fs::symlink_metadata(&self.root).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                FolderError::Unreachable
            } else {
                error(e)
            }
        })?;
        if !root.is_dir() || root.file_type().is_symlink() {
            return Err(FolderError::Unreachable);
        }
        let mut path = self.root.clone();
        if !relative.is_empty() {
            for segment in relative.split('/') {
                path.push(segment);
                match fs::symlink_metadata(&path) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        return Err(FolderError::Other("symbolic link in backup path".into()));
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(error(e)),
                    _ => {}
                }
            }
        }
        Ok(path)
    }
}

fn error(e: io::Error) -> FolderError {
    match e.kind() {
        io::ErrorKind::StorageFull => FolderError::Full,
        io::ErrorKind::PermissionDenied => FolderError::PermissionLost,
        _ => FolderError::Other(e.to_string()),
    }
}

impl BackupFolder for LocalFolder {
    fn list(&self, dir: &str) -> Result<Vec<FolderEntry>, FolderError> {
        let path = self.path(dir, true)?;
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound && !dir.is_empty() => return Ok(vec![]),
            Err(e) => return Err(error(e)),
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(error)?;
            let meta = fs::symlink_metadata(entry.path()).map_err(error)?;
            if meta.file_type().is_symlink() {
                continue;
            }
            out.push(FolderEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                dir: meta.is_dir(),
                size: if meta.is_dir() { 0 } else { meta.len() },
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, FolderError> {
        fs::read(self.path(path, false)?).map_err(error)
    }

    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), FolderError> {
        let path = self.path(path, false)?;
        let parent = path.parent().expect("file has a parent");
        let created_dirs = parent.ancestors().take_while(|dir| !dir.exists()).count();
        fs::create_dir_all(parent).map_err(error)?;
        let is_new = !path.exists();
        let mut file = fs::File::create(&path).map_err(error)?;
        file.write_all(bytes).map_err(error)?;
        if let Err(e) = file.sync_all()
            && e.kind() != io::ErrorKind::Unsupported
        {
            return Err(error(e));
        }
        if is_new {
            // Sync the new file's parent, each newly created directory, and
            // the existing ancestor holding the topmost new directory.
            for dir in parent.ancestors().take(created_dirs + 1) {
                let _ = fs::File::open(dir).and_then(|dir| dir.sync_all());
            }
        }
        Ok(())
    }

    fn remove(&self, path: &str) -> Result<(), FolderError> {
        let path = self.path(path, false)?;
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(error(e)),
        };
        let result = if meta.is_dir() {
            fs::remove_dir_all(path)
        } else {
            fs::remove_file(path)
        };
        match result {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other.map_err(error),
        }
    }
}

/// Opens document-tree URIs provided by the host platform.
pub trait DocumentFolders: Send + Sync {
    /// Resolves a document URI to a readable and writable folder.
    fn open(&self, uri: &str) -> Result<Arc<dyn BackupFolder>, FolderError>;
}

/// A saved backup destination and its human-readable label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum BackupLocation {
    /// A filesystem path such as a folder in iCloud Drive.
    Path {
        /// Local filesystem path.
        path: PathBuf,
        /// Name shown to the person.
        label: String,
    },
    /// A folder selected through a document provider.
    Document {
        /// Document-tree URI.
        uri: String,
        /// Name shown to the person.
        label: String,
    },
}

impl BackupLocation {
    pub(crate) fn same_destination(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Path { path: a, .. }, Self::Path { path: b, .. }) => a == b,
            (Self::Document { uri: a, .. }, Self::Document { uri: b, .. }) => a == b,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_folder_refuses_paths_that_leave_it() {
        let root = tempfile::tempdir().unwrap();
        let folder = LocalFolder::new(root.path().to_path_buf());
        for bad in ["../x", "/etc/x", "a/../../x", "a/./b", "a\\b"] {
            assert!(folder.write(bad, b"x").is_err(), "{bad}");
        }
    }

    #[test]
    fn a_local_folder_writes_lists_reads_replaces_and_removes() {
        let root = tempfile::tempdir().unwrap();
        let folder = LocalFolder::new(root.path().to_path_buf());
        folder.write("a/b/c", b"abc").unwrap();
        let entries = folder.list("a/b").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            (&*entries[0].name, entries[0].dir, entries[0].size),
            ("c", false, 3)
        );
        assert_eq!(folder.read("a/b/c").unwrap(), b"abc");
        folder.write("a/b/c", b"q").unwrap();
        assert_eq!(folder.read("a/b/c").unwrap(), b"q");
        folder.remove("a").unwrap();
        assert!(folder.list("a").unwrap().is_empty());
        folder.remove("a").unwrap();
    }

    #[test]
    fn a_local_folder_write_round_trips_new_and_replaced_files() {
        let root = tempfile::tempdir().unwrap();
        let folder = LocalFolder::new(root.path().to_path_buf());
        folder.write("nested/record", b"first").unwrap();
        assert_eq!(folder.read("nested/record").unwrap(), b"first");
        folder.write("nested/record", b"second").unwrap();
        assert_eq!(folder.read("nested/record").unwrap(), b"second");
    }

    #[test]
    fn a_local_folder_writes_into_new_nested_directories() {
        let root = tempfile::tempdir().unwrap();
        let folder = LocalFolder::new(root.path().to_path_buf());
        folder
            .write("snapshots/base/run/record", b"sealed")
            .unwrap();
        assert_eq!(folder.read("snapshots/base/run/record").unwrap(), b"sealed");
        assert_eq!(folder.list("snapshots/base/run").unwrap()[0].size, 6);
    }

    #[test]
    fn a_missing_root_is_unreachable() {
        let root = tempfile::tempdir().unwrap();
        let folder = LocalFolder::new(root.path().join("absent"));
        assert!(matches!(folder.list(""), Err(FolderError::Unreachable)));
        assert!(matches!(
            folder.write("a", b"x"),
            Err(FolderError::Unreachable)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn listing_ignores_dangling_links() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("real"), b"ok").unwrap();
        std::os::unix::fs::symlink("missing", root.path().join("dangling")).unwrap();
        let folder = LocalFolder::new(root.path().to_path_buf());
        assert_eq!(
            folder.list("").unwrap(),
            vec![FolderEntry {
                name: "real".into(),
                dir: false,
                size: 2,
            }]
        );
    }

    #[cfg(unix)]
    #[test]
    fn listing_ignores_links_to_outside_targets() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), b"outside").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret"),
            root.path().join("linked-secret"),
        )
        .unwrap();
        let folder = LocalFolder::new(root.path().to_path_buf());
        assert!(folder.list("").unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn links_cannot_escape_the_folder() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("outside")).unwrap();
        let folder = LocalFolder::new(root.path().to_path_buf());
        assert!(folder.write("outside/x", b"x").is_err());
        assert!(!outside.path().join("x").exists());
    }
}
