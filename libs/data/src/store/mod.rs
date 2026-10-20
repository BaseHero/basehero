//! SQLite layout and scope-local typed-record primitives.

pub mod actor;
pub mod coverage;
mod ddl;
pub mod records;
pub mod registry;

use crate::DataError;

pub const LAYOUT_VERSION: u32 = 1;

pub fn migrate(tx: &rusqlite::Transaction<'_>) -> Result<(), DataError> {
    ddl::migrate(tx)
}

pub(crate) fn sql(error: rusqlite::Error) -> DataError {
    DataError::Sql(error.to_string())
}

pub(crate) fn corrupt(error: impl std::fmt::Display) -> DataError {
    DataError::Corrupt(error.to_string())
}

pub(crate) fn integer(value: u64) -> Result<i64, DataError> {
    i64::try_from(value).map_err(corrupt)
}

pub(crate) fn unsigned(value: i64) -> Result<u64, DataError> {
    u64::try_from(value).map_err(corrupt)
}

pub(crate) fn id<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], DataError> {
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| DataError::Corrupt(format!("expected {N}-byte identifier")))
}
