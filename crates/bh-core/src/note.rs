//! `NoteDoc`, and a note body's title and text, read through the editor's
//! schema (`note-schema/v1.json`).

use crate::base::Base;
use crate::objects::{self, BODY};
use crate::types::NOTE;
use crate::{Error, ObjectId};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::broadcast;
use yrs::types::text::YChange;
use yrs::{
    Any, Doc, Out, ReadTxn, StateVector, Text, Transact, XmlElementRef, XmlFragment, XmlOut,
};

/// Titles are at most this many characters.
pub(crate) const TITLE_CHARS: usize = 200;
/// Containers deeper than this are not read.
const DEPTH: usize = 16;
/// A title reads at most this many nodes before giving up.
const TITLE_NODES: usize = 256;

/// One applied update, local or remote. Origin 0 is sync and the core's own
/// edits, 1 is Hero; editors pick other values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteUpdate {
    pub origin: u64,
    pub update: Vec<u8>,
}

/// The one open document of an object in this process.
pub(crate) struct Live {
    pub id: ObjectId,
    pub ty: String,
    pub doc: Doc,
    pub events: broadcast::Sender<NoteUpdate>,
    /// Local updates in `doc` that a failed save didn't store; the next save
    /// puts them in the outbox with its own.
    pub unsaved: Mutex<Vec<Vec<u8>>>,
}

impl Live {
    pub(crate) fn new(id: ObjectId, ty: String, doc: Doc) -> Self {
        Self {
            id,
            ty,
            doc,
            events: broadcast::channel(256).0,
            unsaved: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn publish(&self, origin: u64, update: &[u8]) {
        // No subscribers is fine.
        let _ = self.events.send(NoteUpdate {
            origin,
            update: update.to_vec(),
        });
    }
}

/// A note's (or a folder's or project's) document, shared by every window
/// that opens it in this process.
#[derive(Clone)]
pub struct NoteDoc {
    base: Base,
    live: Arc<Live>,
}

impl std::fmt::Debug for NoteDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoteDoc")
            .field("id", &self.live.id)
            .finish_non_exhaustive()
    }
}

impl NoteDoc {
    pub(crate) fn new(base: Base, live: Arc<Live>) -> Self {
        Self { base, live }
    }

    pub fn id(&self) -> ObjectId {
        self.live.id
    }

    /// The whole document as one Yjs v1 update.
    pub fn state(&self) -> Vec<u8> {
        self.live
            .doc
            .transact()
            .encode_state_as_update_v1(&StateVector::default())
    }

    /// Applies a local edit and stores it, with its update in the outbox. If
    /// storing fails, the edit stays in this document and is stored with the
    /// next one.
    pub fn apply(&self, origin: u64, update: &[u8]) -> Result<(), Error> {
        self.base.apply_local(&self.live, origin, update)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<NoteUpdate> {
        self.live.events.subscribe()
    }

    /// A note's first nonempty paragraph or heading; a folder's or project's name.
    pub fn title(&self) -> String {
        let txn = self.live.doc.transact();
        if self.live.ty == NOTE {
            body_title(&txn)
        } else {
            name_title(objects::read_fields(&txn).get("name"))
        }
    }

    /// The body's plain text, a line for each paragraph or heading.
    pub fn text(&self) -> String {
        body_text(&self.live.doc.transact())
    }
}

/// A `name` or title field as a title.
pub(crate) fn name_title(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .map(|s| s.trim().chars().take(TITLE_CHARS).collect::<String>())
        .unwrap_or_default()
}

/// The schema's node kinds: blocks hold text; containers hold blocks or
/// other containers; leaves (hard breaks) hold nothing.
struct Schema {
    blocks: HashSet<String>,
    containers: HashSet<String>,
    leaves: HashSet<String>,
}

fn schema() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let spec: Value = serde_json::from_str(include_str!("../../../note-schema/v1.json"))
            .expect("the note schema is JSON");
        let mut schema = Schema {
            blocks: HashSet::new(),
            containers: HashSet::new(),
            leaves: HashSet::new(),
        };
        for node in spec["nodes"].as_object().expect("nodes").keys() {
            if spec["children"].get(node).is_none() {
                schema.leaves.insert(node.clone());
            }
        }
        for (node, children) in spec["children"].as_object().expect("children") {
            if Some(node.as_str()) == spec["fragment"].as_str() {
                continue;
            }
            let holds_text = children
                .as_array()
                .expect("child list")
                .iter()
                .any(|c| c == "text");
            let set = if holds_text {
                &mut schema.blocks
            } else {
                &mut schema.containers
            };
            set.insert(node.clone());
        }
        schema
    })
}

/// A block's literal text: text items' characters, `space` for each leaf
/// such as a hard break, never marks, attributes or embeds. Stops after
/// `limit` characters, and says whether it did.
fn block_text<T: ReadTxn>(
    txn: &T,
    block: &XmlElementRef,
    space: char,
    limit: usize,
) -> (String, bool) {
    let (mut out, mut count) = (String::new(), 0);
    for child in block.children(txn) {
        match child {
            XmlOut::Text(text) => {
                for chunk in text.diff(txn, |_: YChange| ()) {
                    if let Out::Any(Any::String(s)) = chunk.insert {
                        for c in s.chars() {
                            if count == limit {
                                return (out, true);
                            }
                            out.push(c);
                            count += 1;
                        }
                    }
                }
            }
            XmlOut::Element(el) if schema().leaves.contains(el.tag().as_ref()) => {
                if count == limit {
                    return (out, true);
                }
                out.push(space);
                count += 1;
            }
            _ => {}
        }
    }
    (out, false)
}

/// The text of the first nonempty paragraph or heading, in document order
/// through known containers, at most 200 characters, with hard breaks as
/// spaces. Unknown elements never become a title. A budget runs out as
/// untitled rather than a later block's text.
pub(crate) fn body_title<T: ReadTxn>(txn: &T) -> String {
    let Some(body) = txn.get_xml_fragment(BODY) else {
        return String::new();
    };
    let schema = schema();
    let mut nodes = TITLE_NODES;
    let mut stack = vec![body.children(txn)];
    while let Some(cursor) = stack.last_mut() {
        let Some(node) = cursor.next() else {
            stack.pop();
            continue;
        };
        let Some(left) = nodes.checked_sub(1) else {
            return String::new();
        };
        nodes = left;
        let XmlOut::Element(el) = node else {
            continue;
        };
        let tag = el.tag();
        if schema.blocks.contains(tag.as_ref()) {
            let (title, full) = block_text(txn, &el, ' ', TITLE_CHARS);
            let trimmed = title.trim();
            if !trimmed.is_empty() {
                return trimmed.to_owned();
            }
            if full {
                return String::new();
            }
        } else if schema.containers.contains(tag.as_ref()) && stack.len() < DEPTH {
            stack.push(el.children(txn));
        }
    }
    String::new()
}

/// The body's plain text: a line for each block that isn't blank, hard
/// breaks as new lines.
pub(crate) fn body_text<T: ReadTxn>(txn: &T) -> String {
    let Some(body) = txn.get_xml_fragment(BODY) else {
        return String::new();
    };
    let schema = schema();
    let mut out = String::new();
    let mut stack = vec![body.children(txn)];
    while let Some(cursor) = stack.last_mut() {
        let Some(node) = cursor.next() else {
            stack.pop();
            continue;
        };
        match node {
            XmlOut::Element(el) if schema.blocks.contains(el.tag().as_ref()) => {
                let (text, _) = block_text(txn, &el, '\n', usize::MAX);
                if !text.trim().is_empty() {
                    if !out.is_empty() {
                        out.push('\n');
                    }
                    out.push_str(&text);
                }
            }
            XmlOut::Element(el) if stack.len() < DEPTH => stack.push(el.children(txn)),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use yrs::{WriteTxn, XmlElementPrelim, XmlTextPrelim};

    fn doc_with(build: impl FnOnce(&mut yrs::TransactionMut, yrs::XmlFragmentRef)) -> Doc {
        let doc = Doc::new();
        {
            let mut txn = doc.transact_mut();
            let body = txn.get_or_insert_xml_fragment(BODY);
            build(&mut txn, body);
        }
        doc
    }

    fn paragraph(text: &str) -> XmlElementPrelim {
        XmlElementPrelim::new("paragraph", [XmlTextPrelim::new(text).into()])
    }

    #[test]
    fn the_schema_names_blocks_and_containers() {
        let s = schema();
        assert!(s.blocks.contains("paragraph") && s.blocks.contains("heading"));
        for c in [
            "bulletList",
            "listItem",
            "taskItem",
            "blockquote",
            "orderedList",
            "taskList",
        ] {
            assert!(s.containers.contains(c), "{c}");
        }
        assert_eq!(s.leaves, HashSet::from(["hardBreak".to_string()]));
    }

    #[test]
    fn titles_descend_through_lists_and_skip_unknown_elements() {
        let doc = doc_with(|txn, body| {
            body.push_back(
                txn,
                XmlElementPrelim::new("mystery", [paragraph("Hidden").into()]),
            );
            body.push_back(
                txn,
                XmlElementPrelim::new(
                    "bulletList",
                    [XmlElementPrelim::new("listItem", [paragraph("  ").into()]).into()],
                ),
            );
            body.push_back(
                txn,
                XmlElementPrelim::new(
                    "blockquote",
                    [XmlElementPrelim::new(
                        "paragraph",
                        [
                            XmlTextPrelim::new("Ferry").into(),
                            XmlElementPrelim::empty("hardBreak").into(),
                            XmlTextPrelim::new("times").into(),
                        ],
                    )
                    .into()],
                ),
            );
        });
        let txn = doc.transact();
        assert_eq!(body_title(&txn), "Ferry times");
        assert_eq!(body_text(&txn), "Hidden\nFerry\ntimes");
    }

    #[test]
    fn titles_are_at_most_200_characters() {
        let long = "é".repeat(500);
        let doc = doc_with(|txn, body| {
            body.push_back(txn, paragraph(&long));
        });
        assert_eq!(body_title(&doc.transact()).chars().count(), TITLE_CHARS);
        let blank = doc_with(|txn, body| {
            body.push_back(txn, paragraph(&" ".repeat(300)));
            body.push_back(txn, paragraph("Later"));
        });
        assert_eq!(body_title(&blank.transact()), "");
        assert_eq!(body_title(&Doc::new().transact()), "");
    }

    #[test]
    fn marks_do_not_become_text() {
        let doc = doc_with(|txn, body| {
            let p = body.push_back(txn, XmlElementPrelim::empty("paragraph"));
            let text = p.push_back(txn, XmlTextPrelim::new("plain "));
            let bold: yrs::types::Attrs = [("bold".into(), Any::Map(Default::default()))].into();
            text.insert_with_attributes(txn, 6, "bold", bold);
        });
        assert_eq!(body_title(&doc.transact()), "plain bold");
    }
}
