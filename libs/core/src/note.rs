//! Portable yrs document operations. Neither this document nor its snapshots are
//! a storage acknowledgement: the device store serializes mutation with commit.

use yrs::types::xml::XmlOut;
use yrs::updates::decoder::Decode;
use yrs::{
    Doc, ReadTxn, StateVector, Text, Transact, Update, WriteTxn, XmlElementPrelim, XmlFragment,
};

pub const FRAGMENT: &str = "default";
/// Local editing policy shared with the editor (`editingPositions` in the note
/// inventory): checked authoring may grow a note to this many ProseMirror
/// positions, about a million characters. Larger notes are kept and readable;
/// this never rejects stored, received or already accepted content.
pub const EDITING_POSITIONS: usize = 1_000_000;

/// The document is private: callers cannot take a mutable yrs transaction and
/// bypass device-store commit/rollback. A Note outside storage is only a working
/// copy, not durable or authorized state.
pub struct Note {
    doc: Doc,
    // Derived from decoded Item+GC input, including pending structs. Never a
    // persisted clock; Skip gaps remain visible until real input fills them.
    coverage: yrs::IdSet,
}

#[derive(Debug)]
pub enum NoteError {
    Decode(yrs::encoding::read::Error),
    Apply(yrs::error::UpdateError),
}

#[derive(Debug)]
pub enum WriterError {
    InvalidWriter,
    /// Too few clocks remain for this operation: reacquire, never wrap.
    Exhausted,
    /// The operation would take the note past [`EDITING_POSITIONS`].
    TooLarge,
    Update(NoteError),
}

/// One writer's clocks: received Item+GC input checked against the integrated
/// store. Only Ready proves the next clock an author would allocate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterPrefix {
    /// Complete, integrated 0..end.
    Ready(u32),
    /// Complete input still waiting on another writer's missing struct.
    Pending,
    /// A Skip gap or other missing input: no prefix proof.
    Incomplete,
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
        Self {
            doc: Doc::new(),
            coverage: yrs::IdSet::default(),
        }
    }

    /// Native authoring copy. The ID alone grants no authority: the device
    /// owner requires its current lease at commit. Random fixture authors must
    /// never bypass that fence. UTF16 clocks agree with Yjs, without cleanup.
    pub fn with_writer(client_id: u64) -> Result<Self, WriterError> {
        if client_id >= (1u64 << 53) {
            return Err(WriterError::InvalidWriter);
        }
        Ok(Self {
            doc: Doc::with_options(yrs::Options {
                client_id: yrs::ClientID::new(client_id),
                offset_kind: yrs::OffsetKind::Utf16,
                cleanup_formatting: false,
                ..yrs::Options::default()
            }),
            coverage: yrs::IdSet::default(),
        })
    }

    pub fn has_writer(&self, client_id: u64) -> bool {
        self.coverage.get(&yrs::ClientID::new(client_id)).is_some()
    }

    /// Pending input still counts as covered (screening), but yrs and Yjs
    /// allocate from integrated structs, so both must agree on the end.
    pub fn writer_prefix(&self, client_id: u64) -> WriterPrefix {
        let id = yrs::ClientID::new(client_id);
        let end = match self.coverage.get(&id) {
            None => 0,
            Some(ranges) => {
                let mut ranges = ranges.iter();
                match (ranges.next(), ranges.next()) {
                    (Some((range, _)), None) if range.start == 0 => range.end,
                    _ => return WriterPrefix::Incomplete,
                }
            }
        };
        if self.doc.transact().state_vector().get(&id) == end {
            WriterPrefix::Ready(end)
        } else {
            WriterPrefix::Pending
        }
    }

    /// None is no proven next clock, not permission to start at zero.
    pub fn writer_end(&self, client_id: u64) -> Option<u32> {
        match self.writer_prefix(client_id) {
            WriterPrefix::Ready(end) => Some(end),
            _ => None,
        }
    }

    /// Validate the new local insertion run before applying the decoded update.
    /// Delete-only/reference-only work is allowed; existing request retries are
    /// handled by storage before reaching this method.
    pub fn apply_writer_update(&mut self, bytes: &[u8], client_id: u64) -> Result<(), WriterError> {
        let update =
            Update::decode_v1(bytes).map_err(|e| WriterError::Update(NoteError::Decode(e)))?;
        let inserts = update.insertions(true);
        let end = self
            .writer_end(client_id)
            .ok_or(WriterError::InvalidWriter)?;
        for (id, ranges) in inserts.iter() {
            let mut ranges = ranges.iter();
            let range = ranges.next().ok_or(WriterError::InvalidWriter)?;
            // A run may end exactly at u32::MAX (last clock MAX-1): valid
            // terminal progress. The owner retires that writer afterwards.
            if id.get() != client_id
                || range.start != end
                || range.end <= range.start
                || ranges.next().is_some()
            {
                return Err(WriterError::InvalidWriter);
            }
        }
        self.apply_decoded(update, inserts)
            .map_err(WriterError::Update)?;
        // A successful apply can still leave the new run pending on a missing
        // origin; that is not a durable next-clock continuation.
        self.writer_end(client_id)
            .map(|_| ())
            .ok_or(WriterError::InvalidWriter)
    }

    fn apply_decoded(&mut self, update: Update, inserts: yrs::IdSet) -> Result<(), NoteError> {
        self.doc
            .transact_mut()
            .apply_update(update)
            .map_err(NoteError::Apply)?;
        self.coverage.merge_with(inserts);
        Ok(())
    }

    /// Apply a Yjs v1 update. Decode fails before a transaction opens; on
    /// Apply errors, discard this working Note rather than assume rollback.
    pub fn apply_update(&mut self, bytes: &[u8]) -> Result<(), NoteError> {
        let update = Update::decode_v1(bytes).map_err(NoteError::Decode)?;
        let inserts = update.insertions(true);
        self.apply_decoded(update, inserts)
    }

    /// Identity of this working yrs replica. Useful to verify an update was
    /// applied in place; not an authentication token or a durable Note ID.
    pub fn replica_id(&self) -> u64 {
        self.doc.client_id().get()
    }

    pub fn state(&self) -> Vec<u8> {
        self.doc
            .transact()
            .encode_state_as_update_v1(&StateVector::default())
    }

    /// Catalogue title: literal text of the first nonempty paragraph/heading,
    /// in document order through known list/quote containers. Hard breaks are
    /// spaces; marks, attributes, embeds and unknown elements never become
    /// text. Read-only and bounded: 256 source items in total (deleted and
    /// formatting items included), 1024 UTF-8 bytes, 80 scalars, 16 levels.
    /// An exhausted budget, or 80 scalars of only whitespace that cannot prove
    /// the block empty, is untitled rather than a later block's text.
    /// Call only for a note already open for its commit, never to list notes.
    pub fn title_preview(&self) -> String {
        const DEPTH: usize = 16;
        const CHARS: usize = 80;
        let txn = self.doc.transact();
        let Some(root) = txn.get_xml_fragment(FRAGMENT) else {
            return String::new();
        };
        let (mut items, mut bytes) = (256, 1024);
        let mut stack = vec![root.source_children(&txn)];
        while let Some(cursor) = stack.last_mut() {
            let Ok(next) = cursor.next(&mut items) else {
                return String::new();
            };
            let Some(XmlOut::Element(el)) = next else {
                if next.is_none() {
                    stack.pop();
                }
                continue;
            };
            match el.tag().as_ref() {
                "paragraph" | "heading" => {
                    let (mut title, mut count) = (String::new(), 0);
                    let mut children = el.source_children(&txn);
                    while count < CHARS {
                        let Ok(child) = children.next(&mut items) else {
                            return String::new();
                        };
                        match child {
                            None => break,
                            Some(XmlOut::Text(text)) => {
                                let Ok(prefix) =
                                    text.plain_prefix(&txn, &mut items, &mut bytes, CHARS - count)
                                else {
                                    return String::new();
                                };
                                count += prefix.chars().count();
                                title.push_str(&prefix);
                            }
                            Some(XmlOut::Element(inline))
                                if inline.tag().as_ref() == "hardBreak" =>
                            {
                                let Some(left) = bytes.checked_sub(1) else {
                                    return String::new();
                                };
                                bytes = left;
                                count += 1;
                                title.push(' ');
                            }
                            Some(_) => {}
                        }
                    }
                    let trimmed = title.trim();
                    if !trimmed.is_empty() {
                        return trimmed.to_owned();
                    }
                    if count == CHARS {
                        return String::new();
                    }
                }
                "bulletList" | "orderedList" | "taskList" | "listItem" | "taskItem"
                | "blockquote" => {
                    if stack.len() >= DEPTH {
                        return String::new();
                    }
                    stack.push(el.source_children(&txn));
                }
                _ => {} // Opaque/unsupported structures are never a title.
            }
        }
        String::new()
    }

    /// The editor's ProseMirror `nodeSize` for this note: UTF-16 units of text,
    /// one per leaf node, two per other element, plus two for the document.
    /// Visits each live child item once; for checked authoring, not keystrokes.
    pub fn document_positions(&self) -> usize {
        let txn = self.doc.transact();
        let Some(root) = txn.get_xml_fragment(FRAGMENT) else {
            return 2;
        };
        let mut items = usize::MAX;
        let mut positions = 2usize;
        let mut stack = vec![root.source_children(&txn)];
        while let Some(cursor) = stack.last_mut() {
            match cursor.next(&mut items) {
                Ok(Some(XmlOut::Element(el))) => {
                    if crate::note_schema::is_leaf(el.tag()) {
                        positions += 1;
                    } else {
                        positions += 2;
                        stack.push(el.source_children(&txn));
                    }
                }
                Ok(Some(XmlOut::Text(text))) => {
                    for piece in text.diff(&txn, |_| ()) {
                        positions += match piece.insert {
                            yrs::Out::Any(yrs::Any::String(s)) => s.encode_utf16().count(),
                            _ => 1,
                        };
                    }
                }
                Ok(Some(XmlOut::Fragment(_))) => {}
                Ok(None) | Err(()) => {
                    stack.pop();
                }
            }
        }
        positions
    }

    /// Leased core authoring: refuses before mutating unless this writer has a
    /// proven next clock and room for the whole operation (the element, then
    /// one text item and its UTF16 units), and the note stays within the
    /// shared editing size.
    pub fn try_append_paragraph(&mut self, text: &str) -> Result<Vec<u8>, WriterError> {
        let end = self
            .writer_end(self.replica_id())
            .ok_or(WriterError::InvalidWriter)?;
        let units = text.encode_utf16().count() as u64;
        let need = if units == 0 { 1 } else { 2 + units };
        if u64::from(end) + need > u64::from(u32::MAX) {
            return Err(WriterError::Exhausted);
        }
        // A paragraph adds two positions plus its UTF-16 units.
        let grown = (units as usize).saturating_add(2);
        if self.document_positions().saturating_add(grown) > EDITING_POSITIONS {
            return Err(WriterError::TooLarge);
        }
        Ok(self.append_paragraph(text))
    }

    /// Small core-authored operation in the same Y.XmlFragment used by Yjs
    /// collaboration. Unknown Yjs elements are never converted to markup here.
    /// The caller must commit the returned delta before accepting this edit.
    /// Unchecked fixture form; leased authoring uses `try_append_paragraph`.
    pub fn append_paragraph(&mut self, text: &str) -> Vec<u8> {
        let mut txn = self.doc.transact_mut();
        let fragment = txn.get_or_insert_xml_fragment(FRAGMENT);
        let len = fragment.len(&txn);
        let element = fragment.insert(&mut txn, len, XmlElementPrelim::empty("paragraph"));
        if !text.is_empty() {
            element.insert(&mut txn, 0, yrs::XmlTextPrelim::new(text));
        }
        let bytes = txn.encode_update_v1();
        drop(txn);
        // This small core operation encodes only its delta, never the document.
        let update = Update::decode_v1(&bytes).expect("locally encoded update");
        self.coverage.merge_with(update.insertions(true));
        bytes
    }
}
