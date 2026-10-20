//! A dated Note: the note writer owns title and body; only date and mood are added.
use bh_data::{
    AppId, RecordId, RevisionId, TypeId,
    mutation::{ops::Operation, pending::LocalSaved},
    session::{Authority, DataSession, SessionError, Store},
};
use serde_json::json;
pub const DEFINITION: &[u8] = include_bytes!("../types/JournalEntry.json");
pub fn type_id() -> TypeId {
    TypeId::for_app(AppId([2; 32]), [8; 16])
}
pub fn define<S: Store, A: Authority>(s: &DataSession<S, A>) -> Result<LocalSaved, SessionError> {
    s.submit(Operation::DefineType {
        bytes: DEFINITION.to_vec(),
    })
}
pub fn bind<S: Store, A: Authority>(
    s: &DataSession<S, A>,
    note: RecordId,
    date: i64,
    mood: &str,
) -> Result<LocalSaved, SessionError> {
    s.submit(Operation::BindNote {
        note,
        type_id: type_id(),
        revision: RevisionId::of(DEFINITION),
        doc: json!({"date":date,"mood":mood}),
    })
}
