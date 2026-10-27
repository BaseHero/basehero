use crate::{Error, NoteDoc};
use yrs::{Doc, Transact, WriteTxn, XmlElementPrelim, XmlFragment, XmlTextPrelim};

/// Writes a heading and nonempty paragraph lines using note schema v1, with Hero's origin 1.
pub(crate) fn write_note_body(note: &NoteDoc, title: &str, text: &str) -> Result<(), Error> {
    let doc = Doc::new();
    let mut txn = doc.transact_mut();
    let body = txn.get_or_insert_xml_fragment("default");
    body.push_back(
        &mut txn,
        XmlElementPrelim::new("heading", [XmlTextPrelim::new(title).into()]),
    );
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        body.push_back(
            &mut txn,
            XmlElementPrelim::new("paragraph", [XmlTextPrelim::new(line).into()]),
        );
    }
    note.apply(1, &txn.encode_update_v1())
}
