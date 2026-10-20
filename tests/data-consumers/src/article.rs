//! Consumer A: an article list. All state belongs to the supplied session.
use bh_data::{
    AppId, FieldPath, KeyRef, RecordId, RecordRef, RevisionId, Scope, TypeId,
    mutation::{
        ops::{FieldChange, Operation},
        pending::LocalSaved,
    },
    query::{Follow, Page, Query, QueryError, SortKey, TypeSelect},
    session::{Authority, DataSession, SessionError, Store},
};
use serde_json::json;

pub const DEFINITION: &[u8] = include_bytes!("../types/Article.json");
pub const APP: AppId = AppId([2; 32]);
pub fn type_id() -> TypeId {
    TypeId::for_app(APP, [1; 16])
}
fn path(s: &str) -> FieldPath {
    FieldPath::parse(s).unwrap()
}

pub fn define<S: Store, A: Authority>(s: &DataSession<S, A>) -> Result<LocalSaved, SessionError> {
    s.submit(Operation::DefineType {
        bytes: DEFINITION.to_vec(),
    })
}
pub fn save<S: Store, A: Authority>(
    s: &DataSession<S, A>,
    record: RecordId,
    title: &str,
    url: &str,
    published: i64,
    content: RecordRef,
) -> Result<LocalSaved, SessionError> {
    s.submit(Operation::Create {
        record,
        type_id: type_id(),
        revision: RevisionId::of(DEFINITION),
        doc: json!({"title":title,"url":url,"published":published,"content":content,"state":"new"}),
    })
}
pub fn edit<S: Store, A: Authority>(
    s: &DataSession<S, A>,
    record: RecordId,
    revision: RevisionId,
    changes: Vec<FieldChange>,
) -> Result<LocalSaved, SessionError> {
    s.submit(Operation::Edit {
        record,
        revision,
        changes,
    })
}
pub fn recent<S: Store, A: Authority>(
    s: &DataSession<S, A>,
    scope: Scope,
) -> Result<Page, QueryError> {
    s.query(
        scope,
        &Query {
            select: TypeSelect::Exact(type_id()),
            filter: None,
            sort: vec![SortKey {
                key: KeyRef::Field(path("/published")),
                desc: true,
            }],
            fields: vec![path("/title"), path("/state")],
            follow: vec![Follow {
                path: path("/content"),
                fields: vec![path("/title")],
            }],
            text: None,
            limit: 50,
            after: None,
        },
    )
}
/// A view's index is a local request, not an app mutation.
pub fn prepare_view<S: Store, A: Authority>(
    s: &DataSession<S, A>,
    scope: Scope,
) -> Result<(), bh_data::DataError> {
    s.ensure_index(scope, type_id(), vec![KeyRef::Field(path("/published"))])?;
    Ok(())
}
