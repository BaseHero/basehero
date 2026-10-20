//! Shared typed-record identities, field paths, definitions and value limits.

pub mod admission;
pub mod catalogue;
pub mod compat;
pub mod compose;
pub mod definition;
pub mod error;
pub mod evolve;
pub mod ids;
pub mod index;
pub mod model;
pub mod mutation;
pub mod note;
pub mod path;
pub mod payload;
pub mod profile;
pub mod query;
mod schema_work;
pub mod session;
pub mod store;
#[cfg(feature = "testkit")]
pub mod testkit;
pub mod text;
mod text_reproject;
pub mod tools;
pub mod validate;
pub mod validate_cache;
pub mod value;

pub use error::{DataError, RejectCode, Rejection, Wait};
pub use ids::{AppId, MutationId, Position, RecordId, RecordRef, RevisionId, Scope, TypeId};
pub use model::{
    ActionDecl, Actor, Builtin, CompiledType, CoreCatalogue, FieldKind, FieldSpec, IndexDecl,
    KeyRef, QueryDecl, RefSpec, SearchMap, TypeDocs, TypeKind, UniqueDecl, WritePolicy,
};
pub use path::{FieldPath, MAX_PATH_DEPTH};
pub use value::{MAX_RECORD_BYTES, MAX_SAFE_INTEGER, MAX_VALUE_DEPTH};
