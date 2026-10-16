use bh_core::note::{EDITING_POSITIONS, Note, WriterError};

#[test]
fn positions_match_the_editors_count_for_the_shared_fixture() {
    let mut note = Note::new();
    note.apply_update(include_bytes!(
        "../../../apps/client/editor/test/positions.bin"
    ))
    .unwrap();
    // ProseMirror's nodeSize, checked by the editor's own test of this file.
    assert_eq!(note.document_positions(), 28);
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../../../note-schema/v1.json")).unwrap();
    assert_eq!(
        inventory["editingPositions"].as_u64(),
        Some(EDITING_POSITIONS as u64)
    );
}

#[test]
fn checked_authoring_accepts_up_to_the_limit_and_refuses_beyond_it_unchanged() {
    let mut note = Note::with_writer(7).unwrap();
    // 2 (document) + 2 (paragraph) + 999,992 units = 999,996 positions.
    note.append_paragraph(&"a".repeat(999_992));
    assert_eq!(note.document_positions(), 999_996);
    // An emoji is two UTF-16 units: 999,996 + 2 + 2 = exactly 1,000,000.
    note.try_append_paragraph("\u{1F600}").unwrap();
    assert_eq!(note.document_positions(), 1_000_000);
    let before = note.state();
    assert!(matches!(
        note.try_append_paragraph(""),
        Err(WriterError::TooLarge)
    ));
    assert_eq!(note.state(), before, "a refused operation writes nothing");
}

#[test]
fn an_existing_over_limit_note_is_kept_and_counted_without_truncation() {
    let mut note = Note::with_writer(9).unwrap();
    note.append_paragraph(&"b".repeat(1_000_000));
    let mut received = Note::new();
    received.apply_update(&note.state()).unwrap();
    assert_eq!(received.document_positions(), 1_000_004);
    assert_eq!(received.state(), note.state());
}
