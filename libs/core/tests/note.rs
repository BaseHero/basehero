use bh_core::note::Note;
use bh_core::note_schema::classify_note;
use yrs::updates::decoder::Decode;
use yrs::{
    Doc, GetString, ReadTxn, Transact, Update, WriteTxn, Xml, XmlElementPrelim, XmlFragment,
};

fn paragraph(text: &str) -> Vec<u8> {
    let doc = Doc::new();
    let mut txn = doc.transact_mut();
    let frag = txn.get_or_insert_xml_fragment("default");
    let p = frag.insert(&mut txn, 0, XmlElementPrelim::empty("paragraph"));
    p.insert(&mut txn, 0, yrs::XmlTextPrelim::new(text));
    txn.encode_update_v1()
}

#[test]
fn core_accepts_yjs_update_and_can_edit_without_ui() {
    let base = paragraph("hello");
    let mut note = Note::new().unwrap();
    note.apply_update(&base).unwrap();
    let delta = note.append_paragraph("from core").unwrap();
    let mut replay = Note::new().unwrap();
    replay.apply_update(&base).unwrap();
    replay.apply_update(&delta).unwrap();
    assert_eq!(replay.state().unwrap(), note.state().unwrap());
}

#[test]
fn bad_bytes_leave_note_unchanged() {
    let mut note = Note::new().unwrap();
    note.apply_update(&paragraph("before")).unwrap();
    let state = note.state().unwrap();
    assert!(note.apply_update(&[1, 2, 3]).is_err());
    assert_eq!(note.state().unwrap(), state);
}

#[test]
fn concurrent_updates_merge() {
    let first = paragraph("one");
    let second = paragraph("two");
    let mut a = Note::new().unwrap();
    let mut b = Note::new().unwrap();
    a.apply_update(&first).unwrap();
    a.apply_update(&second).unwrap();
    b.apply_update(&second).unwrap();
    b.apply_update(&first).unwrap();
    assert_eq!(a.state().unwrap(), b.state().unwrap());
}

#[test]
fn actual_tiptap_yjs_nested_list_marks_are_readable_by_yrs() {
    let bytes = include_bytes!("../../../tests/interop/known.bin");
    let mut note = Note::new().unwrap();
    note.apply_update(bytes).unwrap();
    note.append_paragraph("core-authored").unwrap();
    let restored = Doc::new();
    restored
        .transact_mut()
        .apply_update(Update::decode_v1(&note.state().unwrap()).unwrap())
        .unwrap();
    let txn = restored.transact();
    let xml = txn.get_xml_fragment("default").unwrap().get_string(&txn);
    assert_eq!(
        xml,
        "<paragraph>intro</paragraph><bulletList><listItem><paragraph><bold>parent </bold>item</paragraph><bulletList><listItem><paragraph><italic>nested </italic>item</paragraph></listItem></bulletList></listItem></bulletList><paragraph>core-authored</paragraph>"
    );
}

#[test]
fn yrs_preserves_unknown_elements_when_editing_known_neighbor() {
    let source = Doc::new();
    let mut txn = source.transact_mut();
    let frag = txn.get_or_insert_xml_fragment("default");
    frag.insert(&mut txn, 0, XmlElementPrelim::empty("paragraph"));
    let unknown = frag.insert(&mut txn, 1, XmlElementPrelim::empty("futureWidget"));
    unknown.insert_attribute(&mut txn, "payload", "keep");
    unknown.insert(&mut txn, 0, yrs::XmlTextPrelim::new("future content"));
    let bytes = txn.encode_update_v1();
    drop(txn);
    let mut note = Note::new().unwrap();
    note.apply_update(&bytes).unwrap();
    note.append_paragraph("known neighbor").unwrap();
    let restored = Doc::new();
    restored
        .transact_mut()
        .apply_update(Update::decode_v1(&note.state().unwrap()).unwrap())
        .unwrap();
    let txn = restored.transact();
    let xml = txn.get_xml_fragment("default").unwrap().get_string(&txn);
    assert!(
        xml.contains("futureWidget") && xml.contains("future content") && xml.contains("keep"),
        "{xml}"
    );
}

#[test]
fn shared_inventory_classifies_yrs_content_without_modifying_note() {
    let mut note = Note::new().unwrap();
    note.apply_update(include_bytes!("../../../tests/interop/known.bin"))
        .unwrap();
    let original = note.state().unwrap();
    assert!(classify_note(&original).unwrap());
    assert!(
        classify_note(include_bytes!(
            "../../../apps/client/editor/test/code-italic.bin"
        ))
        .unwrap(),
        "shared code+italic fixture is editable on both sides"
    );
    let rich = include_bytes!("../../../apps/client/editor/test/rich.bin");
    assert!(
        classify_note(rich).unwrap(),
        "Rust must agree with the actual bundled rich schema"
    );
    for unsupported in [
        include_bytes!("../../../apps/client/editor/test/mark.bin").as_slice(),
        include_bytes!("../../../apps/client/editor/test/attr.bin").as_slice(),
        include_bytes!("../../../apps/client/editor/test/value.bin").as_slice(),
        include_bytes!("../../../apps/client/editor/test/textAttr.bin").as_slice(),
    ] {
        assert!(
            !classify_note(unsupported).unwrap(),
            "Rust must agree with the editor's unsupported classification"
        );
        let mut opaque = Note::new().unwrap();
        opaque.apply_update(unsupported).unwrap();
        opaque.append_paragraph("neighbor").unwrap();
        assert!(
            !classify_note(&opaque.state().unwrap()).unwrap(),
            "core must keep opaque content while editing beside it"
        );
    }
    assert_eq!(note.state().unwrap(), original);

    let doc = Doc::new();
    let mut txn = doc.transact_mut();
    let frag = txn.get_or_insert_xml_fragment("default");
    let heading = frag.insert(&mut txn, 0, XmlElementPrelim::empty("heading"));
    heading.insert_attribute(&mut txn, "level", 4);
    let future = frag.insert(&mut txn, 1, XmlElementPrelim::empty("futureWidget"));
    future.insert_attribute(&mut txn, "payload", "keep");
    future.insert(&mut txn, 0, yrs::XmlTextPrelim::new("future content"));
    let bytes = txn.encode_update_v1();
    drop(txn);
    assert!(!classify_note(&bytes).unwrap());
    let mut retained = Note::new().unwrap();
    retained.apply_update(&bytes).unwrap();
    retained.append_paragraph("known neighbor").unwrap();
    assert!(!classify_note(&retained.state().unwrap()).unwrap());
    let xml = {
        let restored = Doc::new();
        restored
            .transact_mut()
            .apply_update(Update::decode_v1(&retained.state().unwrap()).unwrap())
            .unwrap();
        let txn = restored.transact();
        txn.get_xml_fragment("default").unwrap().get_string(&txn)
    };
    assert!(xml.contains("futureWidget") && xml.contains("payload=\"keep\""));
}

#[test]
fn primitive_after_valid_xml_block_is_unsupported() {
    // Yjs allows a primitive XML child. yrs children() stops on that child;
    // classification must inspect every array slot instead.
    let bytes = include_bytes!("../../../apps/client/editor/test/primitive-after-valid.bin");
    assert!(!classify_note(bytes).unwrap());
}

#[test]
#[ignore = "manual measurement; warm per-edit cost on 300-block working note"]
fn measure_ordinary_note_edit_cost() {
    let mut note = Note::new().unwrap();
    for i in 0..300 {
        note.append_paragraph(&format!("block {i}: ordinary note text"))
            .unwrap();
    }
    let t = std::time::Instant::now();
    for i in 0..100 {
        note.append_paragraph(&format!("new line {i}")).unwrap();
    }
    eprintln!(
        "100 edits/300 initial blocks: {:?}, final state {} bytes",
        t.elapsed(),
        note.state().unwrap().len()
    );
}
