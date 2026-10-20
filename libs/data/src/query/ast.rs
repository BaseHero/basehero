use crate::{FieldPath, KeyRef, RecordId, RecordRef, RevisionId, TypeId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TypeSelect {
    Exact(TypeId),
    Family(TypeId),
}
impl TypeSelect {
    pub(crate) fn id(&self) -> TypeId {
        match self {
            Self::Exact(id) | Self::Family(id) => *id,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Expr {
    Cmp {
        path: FieldPath,
        op: CmpOp,
        value: Value,
    },
    In {
        path: FieldPath,
        values: Vec<Value>,
    },
    IsNull(FieldPath),
    RefersTo {
        path: FieldPath,
        target: RecordRef,
    },
    Via {
        path: FieldPath,
        filter: Box<Expr>,
    },
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SortKey {
    pub key: KeyRef,
    pub desc: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Follow {
    pub path: FieldPath,
    pub fields: Vec<FieldPath>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextMatch {
    pub terms: String,
    pub on: Option<FieldPath>,
    pub require_revision: Option<u64>,
}
fn default_limit() -> u32 {
    50
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Query {
    pub select: TypeSelect,
    #[serde(default)]
    pub filter: Option<Expr>,
    #[serde(default)]
    pub sort: Vec<SortKey>,
    #[serde(default)]
    pub fields: Vec<FieldPath>,
    #[serde(default)]
    pub follow: Vec<Follow>,
    #[serde(default)]
    pub text: Option<TextMatch>,
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub after: Option<Cursor>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Cursor(pub String);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Gap {
    NotCovered,
    /// A Note in the scope cannot show its content here yet: a held body, Note
    /// content kept for a newer executable, or a missing first projection. A
    /// Note-family result may be missing that record; other types are
    /// unaffected.
    NoteUnavailable,
    UnsupportedType(TypeId),
    WaitingRecord(RecordId),
    WaitingType(TypeId),
    WaitingScope,
    IndexBuilding {
        index: String,
        done: u64,
        total: u64,
    },
    TextBehind {
        watermark: u64,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Completeness {
    Complete,
    Incomplete(Vec<Gap>),
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FollowRow {
    pub record: RecordId,
    pub type_id: TypeId,
    pub values: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Row {
    pub record: RecordId,
    /// The query's `$changed` sort key, when requested. This is a replica-local
    /// recency sequence, not an ordered-log position or wall-clock time.
    #[serde(skip)]
    pub changed: Option<i64>,
    pub type_id: TypeId,
    pub revision: RevisionId,
    pub values: BTreeMap<String, Value>,
    pub follows: BTreeMap<String, Option<FollowRow>>,
    pub pending: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Page {
    pub rows: Vec<Row>,
    pub next: Option<Cursor>,
    pub completeness: Completeness,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Measure {
    Count,
    Sum(FieldPath),
}
fn default_groups() -> u32 {
    1000
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Aggregate {
    pub select: TypeSelect,
    #[serde(default)]
    pub filter: Option<Expr>,
    #[serde(default)]
    pub group_by: Option<FieldPath>,
    pub measures: Vec<Measure>,
    #[serde(default = "default_groups")]
    pub max_groups: u32,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AggregateGroup {
    pub key: Option<Value>,
    pub values: Vec<Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AggregateResult {
    pub groups: Vec<AggregateGroup>,
    pub completeness: Completeness,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub vm_steps: u64,
}
impl Budget {
    pub const INTERACTIVE: Self = Self {
        // Measured, see scale example: indexed 50-row page ≤1,000 VM steps
        // at 100k records (1,000-step resolution); this allows ≥5× that
        // work and accommodates measured indexed Via (≤40,000 steps).
        vm_steps: 1_000_000,
    };
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryError {
    Unauthorized,
    UnknownType,
    UnknownField(FieldPath),
    TypeMismatch(FieldPath),
    NotQueryable {
        path: Option<FieldPath>,
        detail: String,
    },
    TooCostly {
        work: u64,
    },
    IndexBuilding {
        index: String,
        done: u64,
        total: u64,
    },
    TextBehind {
        watermark: u64,
        required: u64,
    },
    Storage(String),
}
// Human-facing diagnostics currently use the Debug shape; tools supply stable codes separately.
impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl QueryError {
    pub(crate) fn not_queryable(path: Option<FieldPath>, detail: impl Into<String>) -> Self {
        Self::NotQueryable {
            path,
            detail: detail.into(),
        }
    }
}
impl From<crate::DataError> for QueryError {
    fn from(err: crate::DataError) -> Self {
        match err {
            crate::DataError::Unauthorized => Self::Unauthorized,
            other => Self::Storage(other.to_string()),
        }
    }
}
