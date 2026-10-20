use serde::{Deserialize, Serialize};

use crate::{FieldPath, RecordId, RevisionId, Scope};

#[derive(Debug, thiserror::Error)]
pub enum DataError {
    #[error("SQL error: {0}")]
    Sql(String),
    #[error("corrupt data: {0}")]
    Corrupt(String),
    #[error("limit exceeded: {0}")]
    Limit(String),
    #[error("unsupported profile keyword {keyword} at {pointer}")]
    Profile { keyword: String, pointer: String },
    #[error("invalid definition: {0}")]
    Definition(String),
    #[error("unique conflict")]
    UniqueConflict,
    #[error("not found")]
    NotFound,
    #[error("unauthorized")]
    Unauthorized,
    #[error("invalid field path: {0}")]
    Path(String),
    #[error("invalid value: {0}")]
    Value(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Rejection {
    pub code: RejectCode,
    pub path: Option<FieldPath>,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectCode {
    Schema,
    UnknownField,
    DerivedField,
    ActionOnly,
    Overlap,
    Unique,
    RevisionNotPermitted,
    DeviceOnly,
    AppInactive,
    ReservedType,
    ConcreteTypeChange,
    TooLarge,
    NotFound,
    Deleted,
    NothingToUndo,
    Exists,
    NeedsCoreTransition,
    Unauthorized,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Wait {
    MissingDefinition(RevisionId),
    MissingRecord(RecordId),
    UniquenessUnknown(Scope),
    Coverage(Scope),
    Unsupported,
    Queued,
}
