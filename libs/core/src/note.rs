//! Portable yrs document operations. Neither this document nor its snapshots are
//! a storage acknowledgement: the device store serializes mutation with commit.

use yrs::updates::decoder::Decode;
use yrs::{Doc, ReadTxn, StateVector, Transact, Update, WriteTxn, XmlElementPrelim, XmlFragment};

pub const FRAGMENT: &str = "default";

/// The document is private: callers cannot take a mutable yrs transaction and
/// bypass device-store commit/rollback. A Note outside storage is only a working
/// copy, not durable or authorized state.
pub struct Note {
    doc: Doc,
}

#[derive(Debug)]
pub enum NoteError {
    Decode(yrs::encoding::read::Error),
    Apply(yrs::error::UpdateError),
}

impl std::fmt::Display for NoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid note update: {self:?}")
    }
}
impl std::error::Error for NoteError {}

impl Default for Note {
    fn default() -> Self {
        Self::new()
    }
}

impl Note {
    pub fn new() -> Self {
        Self { doc: Doc::new() }
    }

    /// Apply a Yjs v1 update. On any error, discard this working Note rather
    /// than assuming yrs rolled back a partially applied transaction.
    pub fn apply_update(&mut self, bytes: &[u8]) -> Result<(), NoteError> {
        let update = Update::decode_v1(bytes).map_err(NoteError::Decode)?;
        self.doc
            .transact_mut()
            .apply_update(update)
            .map_err(NoteError::Apply)
    }

    pub fn state(&self) -> Vec<u8> {
        self.doc
            .transact()
            .encode_state_as_update_v1(&StateVector::default())
    }

    /// Small core-authored operation in the same Y.XmlFragment used by Yjs
    /// collaboration. Unknown Yjs elements are never converted to markup here.
    /// The caller must commit the returned delta before accepting this edit.
    pub fn append_paragraph(&mut self, text: &str) -> Vec<u8> {
        let mut txn = self.doc.transact_mut();
        let fragment = txn.get_or_insert_xml_fragment(FRAGMENT);
        let len = fragment.len(&txn);
        let element = fragment.insert(&mut txn, len, XmlElementPrelim::empty("paragraph"));
        if !text.is_empty() {
            element.insert(&mut txn, 0, yrs::XmlTextPrelim::new(text));
        }
        txn.encode_update_v1()
    }
}
