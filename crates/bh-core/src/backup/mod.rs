mod folder;
mod into;
mod prune;
mod restore;
pub(crate) mod schedule;
pub(crate) mod writer;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// This device's saved destination and most recent complete backup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct BackupStatus {
    /// Saved destination, if one has ever been chosen.
    pub location: Option<BackupLocation>,
    /// Whether new runs are enabled.
    pub enabled: bool,
    /// Whether the backup explanation was acknowledged.
    pub acknowledged: bool,
    /// Time of the most recent complete run, in Unix milliseconds.
    pub last_run_at: Option<i64>,
    /// Bytes this device wrote into its backup folder.
    pub bytes: u64,
    /// Reason this backup is paused.
    pub problem: Option<BackupProblem>,
    /// Whether a backup has not completed in seven days.
    pub stale: bool,
}

/// Why a backup run has paused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum BackupProblem {
    /// The folder cannot currently be reached.
    Unreachable,
    /// The folder grant has been lost.
    PermissionLost,
    /// The folder has no remaining space.
    Full,
    /// Only sign-in details last confirmed on this device are available.
    UsingLastChecked,
    /// There is no saved recovery-kit record.
    NoKitRecord,
}
impl BackupProblem {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "unreachable" => Some(Self::Unreachable),
            "permissionLost" => Some(Self::PermissionLost),
            "full" => Some(Self::Full),
            "usingLastChecked" => Some(Self::UsingLastChecked),
            "noKitRecord" => Some(Self::NoKitRecord),
            _ => None,
        }
    }
    pub(crate) fn text(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::PermissionLost => "permissionLost",
            Self::Full => "full",
            Self::UsingLastChecked => "usingLastChecked",
            Self::NoKitRecord => "noKitRecord",
        }
    }
}

/// How long to wait after a change, and the shortest interval between runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct BackupSchedule {
    /// Delay from the first change after the previous run.
    #[ts(type = "{ secs: number, nanos: number }")]
    pub delay: std::time::Duration,
    /// Minimum time between completed runs.
    #[ts(type = "{ secs: number, nanos: number }")]
    pub min_interval: std::time::Duration,
}

impl BackupSchedule {
    /// Five minutes after the first change, with no other rate limit.
    pub const MAC: Self = Self {
        delay: std::time::Duration::from_secs(5 * 60),
        min_interval: std::time::Duration::ZERO,
    };
    /// Run immediately after a change, at most once every fifteen minutes.
    pub const PHONE: Self = Self {
        delay: std::time::Duration::ZERO,
        min_interval: std::time::Duration::from_secs(15 * 60),
    };
}

/// Work completed by one backup request; `run` is absent when there was nothing to write.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BackupRun {
    /// Timestamp name of the run, if files were written.
    pub run: Option<String>,
    /// Number of objects recorded.
    pub objects: usize,
    /// Number of sealed file parts copied.
    pub parts: usize,
    /// Number of base snapshots written.
    pub snapshots: usize,
}

pub(crate) mod format;

pub use folder::{
    BackupFolder, BackupLocation, DocumentFolders, FolderEntry, FolderError, LocalFolder,
};
pub use into::RestoreSummary;
pub use restore::{
    BackupListing, BaseCheck, CheckReport, OpenedBackup, RestorableBase, list_backups,
};
