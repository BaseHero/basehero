use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::Value;

use crate::{AppId, FieldPath, RevisionId, TypeId};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Actor {
    Device {
        account: [u8; 32],
        device: [u8; 32],
    },
    Job {
        account: [u8; 32],
        delegation: [u8; 32],
        action: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TypeKind {
    Record,
    Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum FieldKind {
    String,
    Integer,
    Number,
    Boolean,
    /// Integer milliseconds since the Unix epoch, UTC.
    Timestamp,
    Enum(Vec<String>),
    Reference(RefSpec),
    Atomic,
    /// Object path whose children are separately declared fields; not directly writable.
    Container,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RefSpec {
    pub targets: Vec<TypeId>,
    pub family: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum WritePolicy {
    Direct,
    ActionOnly,
    Derived,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FieldSpec {
    pub path: FieldPath,
    pub kind: FieldKind,
    pub write: WritePolicy,
    pub required: bool,
    pub nullable: bool,
    pub declared_by: TypeId,
    pub meaning: String,
    pub unit: Option<String>,
    pub absent: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyRef {
    Field(FieldPath),
    Changed,
}

impl Serialize for KeyRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Field(path) => serializer.serialize_str(&path.as_pointer()),
            Self::Changed => serializer.serialize_str("$changed"),
        }
    }
}

impl<'de> Deserialize<'de> for KeyRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == "$changed" {
            Ok(Self::Changed)
        } else {
            FieldPath::parse(&value)
                .map(Self::Field)
                .map_err(D::Error::custom)
        }
    }
}

/// Index keys are validated by definition compilation (one to four keys).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IndexDecl {
    pub name: String,
    pub keys: Vec<KeyRef>,
    /// The type whose definition declares this index; the indexed family is this type and its specialisations.
    pub declared_by: TypeId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UniqueDecl {
    pub name: String,
    pub keys: Vec<KeyRef>,
    /// The type whose definition declares this index; the indexed family is this type and its specialisations.
    pub declared_by: TypeId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueryDecl {
    pub name: String,
    pub query: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SearchMap {
    pub title: Option<FieldPath>,
    pub text: Vec<FieldPath>,
    pub builtin_body: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionDecl {
    pub name: String,
    /// The declared leaf fields the action may change, matched exactly: naming
    /// a container does not cover its children.
    pub effects: Vec<FieldPath>,
    pub source: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Builtin {
    Note,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TypeDocs {
    pub description: String,
    pub rationale: Vec<String>,
    pub examples_valid: Vec<Value>,
    pub examples_invalid: Vec<Value>,
    pub migration: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompiledType {
    pub type_id: TypeId,
    pub revision: RevisionId,
    pub kind: TypeKind,
    pub app: Option<AppId>,
    pub name: String,
    /// Self first, followed by ancestors.
    pub lineage: Vec<(TypeId, RevisionId)>,
    pub effective_schema: Value,
    pub resources: Vec<(String, Value)>,
    pub fields: Vec<FieldSpec>,
    pub indexes: Vec<IndexDecl>,
    pub uniques: Vec<UniqueDecl>,
    pub queries: Vec<QueryDecl>,
    pub search: SearchMap,
    pub actions: Vec<ActionDecl>,
    pub builtin: Option<Builtin>,
    pub previous: Option<RevisionId>,
    pub docs: TypeDocs,
}

pub trait CoreCatalogue {
    fn core_type(&self, id: TypeId) -> Option<CompiledType>;
}

impl CompiledType {
    pub fn field(&self, path: &FieldPath) -> Option<&FieldSpec> {
        self.fields.iter().find(|field| &field.path == path)
    }

    pub fn is_family_member_of(&self, id: TypeId) -> bool {
        self.lineage.iter().any(|(ancestor, _)| *ancestor == id)
    }
}
