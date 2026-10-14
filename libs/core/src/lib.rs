//! Portable product rules, independent of storage and platform frameworks.

pub mod note;
pub mod note_schema;

/// Local SQLite layout version. This is not an event, protocol or release version.
pub const LOCAL_DATA_VERSION: u32 = 4;

/// An older client must never downgrade or reset newer local data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewerDataVersion {
    pub found: u32,
    pub supported: u32,
}

impl std::fmt::Display for NewerDataVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "local data version {} requires a newer client (supports {})",
            self.found, self.supported
        )
    }
}

impl std::error::Error for NewerDataVersion {}

/// Check compatibility before changing a database or starting a migration.
/// Version zero is SQLite's empty/unversioned starting point.
pub fn check_local_data_version(found: u32) -> Result<(), NewerDataVersion> {
    if found > LOCAL_DATA_VERSION {
        Err(NewerDataVersion {
            found,
            supported: LOCAL_DATA_VERSION,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_initial_and_current_layouts_but_not_newer_data() {
        assert_eq!(check_local_data_version(0), Ok(()));
        assert_eq!(check_local_data_version(LOCAL_DATA_VERSION), Ok(()));
        assert_eq!(
            check_local_data_version(LOCAL_DATA_VERSION + 1),
            Err(NewerDataVersion {
                found: LOCAL_DATA_VERSION + 1,
                supported: LOCAL_DATA_VERSION
            })
        );
    }
}
