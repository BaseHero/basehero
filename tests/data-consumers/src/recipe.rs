//! Composition: an Address value and a reference to canonical instructions.
use bh_data::{
    AppId, FieldPath, RecordId, RecordRef, RevisionId, Scope, TypeId,
    mutation::{ops::Operation, pending::LocalSaved},
    query::{Follow, Page, Query, QueryError, TypeSelect},
    session::{Authority, DataSession, SessionError, Store},
};
use serde_json::json;
pub const DEFINITION: &[u8] = include_bytes!("../types/Recipe.json");
pub const ADDRESS: &[u8] = include_bytes!("../types/Address.json");
pub fn type_id() -> TypeId {
    TypeId::for_app(AppId([2; 32]), [9; 16])
}
pub fn define<S: Store, A: Authority>(s: &DataSession<S, A>) -> Result<LocalSaved, SessionError> {
    s.submit(Operation::DefineType {
        bytes: DEFINITION.to_vec(),
    })
}
pub fn save<S: Store, A: Authority>(
    s: &DataSession<S, A>,
    record: RecordId,
    instructions: RecordRef,
) -> Result<LocalSaved, SessionError> {
    s.submit(Operation::Create { record, type_id: type_id(), revision: RevisionId::of(DEFINITION),
        doc: json!({"name":"Solar oven bread","location":{"city":"Example City","street":"12 Garden Lane"},
                    "instructions":instructions}) })
}
pub fn view<S: Store, A: Authority>(
    s: &DataSession<S, A>,
    scope: Scope,
) -> Result<Page, QueryError> {
    let p = |s| FieldPath::parse(s).unwrap();
    s.query(
        scope,
        &Query {
            select: TypeSelect::Exact(type_id()),
            filter: None,
            sort: vec![],
            fields: vec![p("/name"), p("/location")],
            follow: vec![Follow {
                path: p("/instructions"),
                fields: vec![p("/title")],
            }],
            text: None,
            limit: 50,
            after: None,
        },
    )
}
