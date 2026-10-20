//! Shipped, revision-pinned core content contracts.
use std::sync::LazyLock;

use crate::{CompiledType, CoreCatalogue, RevisionId, TypeId, compose, definition};

const NOTE_V1: &[u8] = include_bytes!("../core/note.v1.json");
static CORE: LazyLock<Vec<CompiledType>> = LazyLock::new(|| {
    let definition =
        definition::parse_core_note(NOTE_V1).expect("shipped Note definition must parse");
    vec![
        compose::compile(&definition, RevisionId::of(NOTE_V1), &|_, _| None)
            .expect("shipped Note definition must compile"),
    ]
});

pub struct Shipped;
impl CoreCatalogue for Shipped {
    fn core_type(&self, id: TypeId) -> Option<CompiledType> {
        core_types()
            .iter()
            .find(|contract| contract.type_id == id)
            .cloned()
    }
}
pub fn core_types() -> &'static [CompiledType] {
    &CORE
}
pub fn baseline_note() -> (TypeId, RevisionId) {
    let note = &core_types()[0];
    (note.type_id, note.revision)
}
