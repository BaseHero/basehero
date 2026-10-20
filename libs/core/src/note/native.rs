//! The yrs note engine itself. Inside the bundled note engine, and on Wasm,
//! this is [`super::Note`]; on devices and services the host runs it only
//! contained, and calls it directly only to compare the two.

use super::{
    EDITING_POSITIONS, FRAGMENT, IncomingRefusal, NoteError, ORDERED_REBUILD_BUDGET, OrderedState,
    WriterError, WriterPrefix, count_rebuilds,
};
use yrs::types::xml::XmlOut;
use yrs::updates::decoder::Decode;
use yrs::{
    Doc, ReadTxn, StateVector, Text, Transact, Update, WriteTxn, XmlElementPrelim, XmlFragment,
};

/// The document is private: callers cannot take a mutable yrs transaction and
/// bypass device-store commit/rollback. A Note outside storage is only a working
/// copy, not durable or authorized state.
pub struct Note {
    doc: Doc,
    // Derived from decoded Item+GC input, including pending structs. Never a
    // persisted clock; Skip gaps remain visible until real input fills them.
    coverage: yrs::IdSet,
}

/// One separator between visible body text, never a leading or doubled one.
fn boundary(out: &mut String, mark: char) {
    if !out.is_empty() && !out.ends_with(mark) {
        out.push(mark);
    }
}

fn is_block(tag: &str) -> bool {
    matches!(
        tag,
        "paragraph" | "heading" | "listItem" | "taskItem" | "blockquote" | "codeBlock" | "tableRow"
    )
}

fn truncate_utf8(mut out: String, max_bytes: usize) -> String {
    if out.len() > max_bytes {
        let mut end = max_bytes;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }
    out
}

/// Whether these updates, applied in order to a new note, give this digest.
fn reproduces<'a>(segments: impl Iterator<Item = &'a [u8]>, target: [u8; 32]) -> bool {
    count_rebuilds(1);
    let mut note = Note::with_replica(READER_REPLICA);
    segments.into_iter().all(|s| note.apply_update(s).is_ok()) && note.digest() == target
}

/// `run` merged, if `head`, that run and then `rest` reproduce `target`.
fn verified_run(
    head: &[&[u8]],
    run: &[&[u8]],
    rest: &[&[u8]],
    target: [u8; 32],
    spare: &mut usize,
) -> Option<Vec<u8>> {
    let merged = yrs::merge_updates_v1(run).ok()?;
    *spare -= 1;
    let candidate = head
        .iter()
        .copied()
        .chain([merged.as_slice()])
        .chain(rest.iter().copied());
    reproduces(candidate, target).then_some(merged)
}

/// A merged run if there is one, otherwise the pieces it would replace.
fn run_or<'a>(merged: &'a Option<Vec<u8>>, raw: &[&'a [u8]]) -> Vec<&'a [u8]> {
    match merged {
        Some(run) => vec![run.as_slice()],
        None => raw.to_vec(),
    }
}

/// One update holding every change in `updates`, in the order given. Only
/// one writer's consecutive updates merge into the same structure; several
/// writers' concurrent text can integrate in another order (see
/// [`OrderedState`]).
pub fn merge_updates(updates: &[&[u8]]) -> Result<Vec<u8>, NoteError> {
    let decoded = updates
        .iter()
        .map(|bytes| decode(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(yrs::updates::encoder::Encode::encode_v1(
        &Update::merge_updates(decoded),
    ))
}

/// A rebuild only reads, so its replica ID never appears in what it builds.
pub(crate) const READER_REPLICA: u64 = (1 << 53) - 1;

/// Whether these bytes are a Yjs v1 update at all, without integrating them.
pub fn is_update(bytes: &[u8]) -> bool {
    decode(bytes).is_ok()
}

/// Decode, keeping a failed allocation a local limit rather than a verdict.
pub(crate) fn decode(bytes: &[u8]) -> Result<Update, NoteError> {
    Update::decode_v1(bytes).map_err(|e| match e {
        // Inside the sandbox allocation failure is a trap, not a verdict.
        // The native oracle retains its original decode-error behavior.
        #[cfg(target_family = "wasm")]
        yrs::encoding::read::Error::NotEnoughMemory(_) => panic!("note allocation failed"),
        e => NoteError::Decode(e),
    })
}

/// Options for this client, without the random source `Options::default`
/// draws on: the ID is explicit and the GUID, unused by notes, derives from it.
fn options(client_id: u64) -> yrs::Options {
    yrs::Options::with_guid_and_client_id(
        client_id.to_string().into(),
        yrs::ClientID::new(client_id),
    )
}

impl Default for Note {
    fn default() -> Self {
        Self::new()
    }
}

impl Note {
    /// A reader with a random replica ID, as `Doc::new` would choose.
    pub fn new() -> Self {
        Self::with_replica(yrs::ClientID::random().get())
    }

    /// [`Note::new`] with this replica ID.
    pub fn with_replica(client_id: u64) -> Self {
        Self {
            doc: Doc::with_options(options(client_id)),
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
                offset_kind: yrs::OffsetKind::Utf16,
                cleanup_formatting: false,
                ..options(client_id)
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
        let update = decode(bytes).map_err(WriterError::Update)?;
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

    /// The incoming writer rule, on accepted state: insert only under
    /// `client_id`, in one run starting exactly at its accepted end, and
    /// attach completely. Deletes and references to other writers' items are
    /// allowed. On `Err((_, true))` this Note was changed and must be
    /// discarded and rebuilt; with `false` it is untouched.
    pub fn apply_incoming(
        &mut self,
        bytes: &[u8],
        client_id: u64,
    ) -> Result<(), (IncomingRefusal, bool)> {
        let update = decode(bytes).map_err(|_| (IncomingRefusal::Undecodable, false))?;
        let inserts = update.insertions(true);
        for (id, ranges) in inserts.iter() {
            if id.get() != client_id {
                return Err((IncomingRefusal::ForeignWriter, false));
            }
            let end = self
                .writer_end(client_id)
                .ok_or((IncomingRefusal::NotContinuous, false))?;
            let mut ranges = ranges.iter();
            let range = ranges
                .next()
                .ok_or((IncomingRefusal::NotContinuous, false))?;
            let single = ranges.next().is_none();
            if single && range.end <= end {
                return Err((IncomingRefusal::Duplicate, false));
            }
            if !single || range.start != end || range.end <= range.start {
                return Err((IncomingRefusal::NotContinuous, false));
            }
        }
        self.apply_decoded(update, inserts)
            .map_err(|_| (IncomingRefusal::ApplyFailed, true))?;
        if self.has_pending() {
            return Err((IncomingRefusal::MissingDependency, true));
        }
        Ok(())
    }

    /// Whether any struct or deletion waits on a missing item.
    pub fn has_pending(&self) -> bool {
        let txn = self.doc.transact();
        let store = txn.store();
        store.pending_update().is_some() || store.pending_ds().is_some()
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
        let update = decode(bytes)?;
        let inserts = update.insertions(true);
        self.apply_decoded(update, inserts)
    }

    /// Identity of this working yrs replica. Useful to verify an update was
    /// applied in place; not an authentication token or a durable Note ID.
    pub fn replica_id(&self) -> u64 {
        self.doc.client_id().get()
    }

    /// One merged full state. Reopening it can order concurrent text
    /// differently from this note; persist [`Note::ordered`] instead.
    pub fn state(&self) -> Vec<u8> {
        self.doc
            .transact()
            .encode_state_as_update_v1(&StateVector::default())
    }

    pub fn from_ordered(state: &OrderedState) -> Result<Note, NoteError> {
        let mut note = Note::new();
        note.apply_ordered(state)?;
        Ok(note)
    }

    /// Apply each segment in order, as [`Note::apply_update`] does.
    pub fn apply_ordered(&mut self, state: &OrderedState) -> Result<(), NoteError> {
        state
            .segments()
            .iter()
            .try_for_each(|s| self.apply_update(s))
    }

    /// Structure of the integrated document: item order, deletions, content
    /// kinds and lengths, map entries, delete set and pending structs, but not
    /// how yrs happens to split its blocks.
    pub fn digest(&self) -> [u8; 32] {
        yrs::structure_digest(&self.doc.transact())
    }

    /// This note as one full state, if that reopens with the same structure.
    /// One rebuild: opening tries only this and leaves [`Note::ordered`]'s
    /// search to the background checkpoint.
    pub fn merged(&self) -> Option<OrderedState> {
        merged(self.state(), self.digest())
    }

    /// Compact the updates this note was built from, `previous` then `tail`
    /// in order, keeping its structure, in at most [`ORDERED_REBUILD_BUDGET`]
    /// rebuilds. Usually that is one full state. Otherwise `previous`'s
    /// segments, verified when they were written, stay as they are; the tail
    /// merges into the last of them, or alone, if that verifies. Failing
    /// both, bisection from each end finds a merged prefix and suffix of the
    /// tail that still reproduce this note, and whatever lies between when
    /// the budget is spent stays as given. None if the result does not
    /// reopen as this note, as when the note was not built from these updates.
    pub fn ordered(&self, previous: &OrderedState, tail: &[Vec<u8>]) -> Option<OrderedState> {
        ordered(self.state(), self.digest(), previous, tail)
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

    /// Plain literal text of the current body in document order, at most
    /// `max_bytes` UTF-8 bytes: text items' visible characters, one newline for
    /// each hard break and block boundary, never marks, attributes or embeds.
    /// Read-only and bounded: at most `max_bytes` scalars and about
    /// `4 * max_bytes` source items are visited. A shorter prefix is returned
    /// when a budget is exhausted, never a fabricated or malformed string.
    pub fn body_text(&self, max_bytes: usize) -> String {
        const DEPTH: usize = 16;
        let txn = self.doc.transact();
        let Some(root) = txn.get_xml_fragment(FRAGMENT) else {
            return String::new();
        };
        let mut out = String::new();
        if max_bytes == 0 {
            return out;
        }
        let mut chars_left = max_bytes;
        let mut items = max_bytes.saturating_mul(4).saturating_add(4_096);
        let mut bytes = items;
        let mut stack = vec![(String::new(), root.source_children(&txn))];
        while let Some((_, cursor)) = stack.last_mut() {
            let next = cursor.next(&mut items);
            match next {
                Ok(Some(XmlOut::Text(text))) => {
                    if chars_left == 0 {
                        break;
                    }
                    let Ok(prefix) = text.plain_prefix(&txn, &mut items, &mut bytes, chars_left)
                    else {
                        break;
                    };
                    chars_left -= prefix.chars().count();
                    out.push_str(&prefix);
                }
                Ok(Some(XmlOut::Element(el))) => {
                    let tag = el.tag();
                    if tag.as_ref() == "hardBreak" {
                        boundary(&mut out, '\n');
                    } else if stack.len() < DEPTH {
                        stack.push((tag.to_string(), el.source_children(&txn)));
                    }
                }
                Ok(Some(XmlOut::Fragment(_))) => {}
                Ok(None) => {
                    let (tag, _) = stack.pop().expect("open cursor");
                    if is_block(&tag) {
                        boundary(&mut out, '\n');
                    }
                }
                Err(()) => break,
            }
            if out.len() >= max_bytes {
                break;
            }
        }
        truncate_utf8(out, max_bytes)
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

/// [`Note::merged`] for a note with this full state and digest.
pub fn merged(state: Vec<u8>, target: [u8; 32]) -> Option<OrderedState> {
    let single = OrderedState::single(state);
    reproduces(single.segments().iter().map(Vec::as_slice), target).then_some(single)
}

/// [`Note::ordered`] for a note with this full state and digest.
pub fn ordered(
    state: Vec<u8>,
    target: [u8; 32],
    previous: &OrderedState,
    tail: &[Vec<u8>],
) -> Option<OrderedState> {
    if let Some(single) = merged(state, target) {
        return Some(single);
    }
    let kept: Vec<&[u8]> = previous.segments().iter().map(Vec::as_slice).collect();
    let tail: Vec<&[u8]> = tail.iter().map(Vec::as_slice).collect();
    let n = tail.len();
    let owned = |parts: &[&[u8]]| OrderedState {
        segments: parts.iter().map(|s| s.to_vec()).collect(),
    };
    // One rebuild went on the full state; one is kept for the final check.
    let mut spare = ORDERED_REBUILD_BUDGET - 2;
    if let Some((last, head)) = kept.split_last()
        && n > 0
    {
        // With nothing before it, the last segment and tail are the full state.
        let run: Vec<&[u8]> = [*last].into_iter().chain(tail.iter().copied()).collect();
        if !head.is_empty()
            && let Some(run) = verified_run(head, &run, &[], target, &mut spare)
        {
            return Some(owned(&[head, &[run.as_slice()]].concat()));
        }
        if n > 1
            && let Some(run) = verified_run(&kept, &tail, &[], target, &mut spare)
        {
            return Some(owned(&[&kept, &[run.as_slice()][..]].concat()));
        }
    }
    // tail[..p] and tail[s..] each merge into one segment, or are at most
    // one piece as given; tail[p..s] stays as given. Each verified step
    // leaves exactly the candidate it checked. The whole tail merged has
    // already failed (with nothing kept, it is the full state).
    let (mut p, mut s) = (n.min(1), n.saturating_sub(1).max(n.min(1)));
    let (mut p_fail, mut s_fail) = (n, 0);
    let (mut prefix, mut suffix) = (None, None);
    let (mut verified, mut front_next) = (false, true);
    while spare > 0 {
        let front = (p, p_fail.min(s + 1));
        let back = (s_fail.max(p.saturating_sub(1)), s);
        let open = |(lo, hi): (usize, usize)| hi > lo + 1;
        let front_now = match (open(front), open(back)) {
            (false, false) => break,
            (true, true) => front_next,
            (front_open, _) => front_open,
        };
        front_next = !front_now;
        if front_now {
            let m = p + (front.1 - p) / 2;
            let rest = [&tail[m..s], &run_or(&suffix, &tail[s..])[..]].concat();
            match verified_run(&kept, &tail[..m], &rest, target, &mut spare) {
                Some(run) => (p, prefix, verified) = (m, Some(run), true),
                None => p_fail = m,
            }
        } else {
            let t = back.0 + (s - back.0) / 2;
            let head = [&kept, &run_or(&prefix, &tail[..p])[..], &tail[p..t]].concat();
            match verified_run(&head, &tail[t..], &[], target, &mut spare) {
                Some(run) => (s, suffix, verified) = (t, Some(run), true),
                None => s_fail = t,
            }
        }
    }
    let out = owned(
        &[
            &kept,
            &run_or(&prefix, &tail[..p])[..],
            &tail[p..s],
            &run_or(&suffix, &tail[s..])[..],
        ]
        .concat(),
    );
    (verified || reproduces(out.segments().iter().map(Vec::as_slice), target)).then_some(out)
}
