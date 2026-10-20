//! Plain body text is literal document text, bounded before it reaches search.
use bh_core::note::Note;
use yrs::Text;
use yrs::types::Attrs;
use yrs::{
    Any, Doc, Transact, TransactionMut, WriteTxn, XmlElementPrelim, XmlFragment, XmlFragmentRef,
    XmlTextPrelim,
};

fn note_from(build: impl FnOnce(&mut TransactionMut, &XmlFragmentRef)) -> Note {
    let doc = Doc::new();
    let mut tx = doc.transact_mut();
    let frag = tx.get_or_insert_xml_fragment("default");
    build(&mut tx, &frag);
    let mut note = Note::new().unwrap();
    note.apply_update(&tx.encode_update_v1()).unwrap();
    note
}

fn paragraph(tx: &mut TransactionMut, parent: &impl XmlFragment, text: &str) {
    let p = parent.push_back(tx, XmlElementPrelim::empty("paragraph"));
    if !text.is_empty() {
        p.push_back(tx, XmlTextPrelim::new(text));
    }
}

#[test]
fn body_text_is_literal_document_text() {
    let note = note_from(|tx, frag| {
        let first = frag.push_back(tx, XmlElementPrelim::empty("paragraph"));
        let text = first.push_back(tx, XmlTextPrelim::new("hello "));
        text.format(
            tx,
            0,
            5,
            Attrs::from([("bold".into(), Any::Map(Default::default()))]),
        );
        first.push_back(tx, XmlTextPrelim::new("world"));
        first.push_back(tx, XmlElementPrelim::empty("hardBreak"));
        first.push_back(tx, XmlTextPrelim::new("next"));
        paragraph(tx, frag, "second");
    });
    assert_eq!(
        note.body_text(1_024).unwrap(),
        "hello world\nnext\nsecond\n"
    );
}

#[test]
fn body_text_truncates_on_a_character_boundary() {
    let note = note_from(|tx, frag| paragraph(tx, frag, "ééééé"));
    assert_eq!(note.body_text(5).unwrap(), "éé");
    assert_eq!(note.body_text(0).unwrap(), "");
}
