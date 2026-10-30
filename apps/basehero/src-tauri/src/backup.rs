#[cfg(target_os = "android")]
pub mod android;

use bh_core::BackupLocation;
#[cfg(any(target_os = "android", test))]
use bh_core::FolderError;
use std::path::{Path, PathBuf};

/// A Finder-like name that identifies a folder without exposing the whole home path.
pub fn label_for(path: &Path) -> String {
    label_for_home(path, &home_dir())
}

/// Finder-like label with a supplied home directory for deterministic callers.
pub fn label_for_home(path: &Path, home: &Path) -> String {
    let cloud = home.join("Library/Mobile Documents/com~apple~CloudDocs");
    let (prefix, relative) = if let Ok(relative) = path.strip_prefix(&cloud) {
        (Some("iCloud Drive".to_owned()), relative)
    } else if let Ok(relative) = path.strip_prefix("/Volumes") {
        (None, relative)
    } else if let Ok(relative) = path.strip_prefix(home) {
        (None, relative)
    } else {
        (None, path)
    };
    prefix
        .into_iter()
        .chain(
            relative
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned()),
        )
        .filter(|part| part != "/")
        .collect::<Vec<_>>()
        .join(" › ")
}

/// Default destination chosen from a supplied home directory (also usable in tests).
pub fn default_location_for(home: &Path) -> BackupLocation {
    let cloud = home.join("Library/Mobile Documents/com~apple~CloudDocs");
    let path = if cloud.is_dir() {
        cloud.join("BaseHero")
    } else {
        home.join("Documents/BaseHero Backup")
    };
    BackupLocation::Path {
        label: label_for_home(&path, home),
        path,
    }
}

/// Install the default only for a full device that has never selected a folder.
pub fn prepare_mac_account(account: &bh_core::Account, home: &Path) -> Result<(), bh_core::Error> {
    if account.kind() != bh_core::DeviceKind::Full || account.backup_status()?.location.is_some() {
        return Ok(());
    }
    let location = default_location_for(home);
    if let BackupLocation::Path { path, .. } = &location {
        // A disconnected or read-only destination must not prevent account load;
        // the scheduled run will report the folder problem in backup status.
        let _ = std::fs::create_dir_all(path);
    }
    account.set_backup(Some(location))
}

/// The person's home folder: for picker labels, and the Mac default in the app.
/// Tests pass their own home to `AppState::open` instead.
pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Maps folder bridge exceptions independently of the JNI transport.
#[cfg(any(target_os = "android", test))]
pub(crate) fn android_folder_error(message: String) -> FolderError {
    if message.contains("NotFound") {
        FolderError::Other(message)
    } else if message.contains("PermissionLost") {
        FolderError::PermissionLost
    } else if message.contains("Unreachable") {
        FolderError::Unreachable
    } else if message.contains("Full") {
        FolderError::Full
    } else {
        FolderError::Other(message)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn missing_android_document_is_a_missing_file_not_a_lost_folder() {
        assert!(matches!(
            super::android_folder_error("java.lang.IllegalStateException: NotFound".into()),
            bh_core::FolderError::Other(_)
        ));
    }
}
