//! Consumer B: evidence selected for a context. It discovers Article by contract,
//! not by calling the article consumer or opening its installation.
use bh_data::{
    AppId, FieldPath, KeyRef, RecordId, RecordRef, RevisionId, Scope, TypeId,
    mutation::{ops::Operation, pending::LocalSaved},
    query::{CmpOp, Expr, Follow, Page, Query, QueryError, TextMatch, TypeSelect},
    session::{Authority, DataSession, SessionError, Store},
};
use serde_json::json;

pub const DEFINITION: &[u8] = include_bytes!("../types/SourceSelection.json");
pub const APP: AppId = AppId([3; 32]);
pub fn type_id() -> TypeId {
    TypeId::for_app(APP, [7; 16])
}
fn p(s: &str) -> FieldPath {
    FieldPath::parse(s).unwrap()
}
pub fn define<S: Store, A: Authority>(
    session: &DataSession<S, A>,
) -> Result<LocalSaved, SessionError> {
    session.submit(Operation::DefineType {
        bytes: DEFINITION.to_vec(),
    })
}
pub fn select<S: Store, A: Authority>(
    session: &DataSession<S, A>,
    id: RecordId,
    article: RecordRef,
    context: RecordRef,
    reason: &str,
    note: RecordRef,
) -> Result<LocalSaved, SessionError> {
    session.submit(Operation::Create {
        record: id,
        type_id: type_id(),
        revision: RevisionId::of(DEFINITION),
        doc: json!({"article":article,"context":context,"reason":reason,"note":note}),
    })
}
pub fn context_query(context: RecordRef, from: i64, until: i64) -> Query {
    Query {
        select: TypeSelect::Exact(type_id()),
        filter: Some(Expr::And(vec![
            Expr::RefersTo {
                path: p("/context"),
                target: context,
            },
            Expr::Via {
                path: p("/article"),
                filter: Box::new(Expr::And(vec![
                    Expr::Cmp {
                        path: p("/published"),
                        op: CmpOp::Ge,
                        value: json!(from),
                    },
                    Expr::Cmp {
                        path: p("/published"),
                        op: CmpOp::Lt,
                        value: json!(until),
                    },
                ])),
            },
        ])),
        fields: vec![p("/reason")],
        sort: vec![],
        follow: vec![
            Follow {
                path: p("/article"),
                fields: vec![p("/title")],
            },
            Follow {
                path: p("/note"),
                fields: vec![p("/title")],
            },
        ],
        text: Some(TextMatch {
            terms: "solar".into(),
            on: Some(p("/article")),
            require_revision: None,
        }),
        limit: 50,
        after: None,
    }
}
pub fn for_context<S: Store, A: Authority>(
    session: &DataSession<S, A>,
    scope: Scope,
    context: RecordRef,
    from: i64,
    until: i64,
) -> Result<Page, QueryError> {
    session.query(scope, &context_query(context, from, until))
}
pub fn prepare_view<S: Store, A: Authority>(
    session: &DataSession<S, A>,
    scope: Scope,
) -> Result<(), bh_data::DataError> {
    session.ensure_index(scope, type_id(), vec![KeyRef::Field(p("/reason"))])?;
    Ok(())
}
