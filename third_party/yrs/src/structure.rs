//! Read-only structural digest of a document's integrated item graph.
//!
//! Two documents have the same digest when their roots and nested branches
//! hold the same items in the same order, with the same deletion state,
//! content kinds and lengths and map entries, the same delete set and the same
//! pending structs. Block splitting and merging do not change it: each item
//! is hashed as the run of clock units it covers, and adjacent units with
//! contiguous IDs, equal deletion state and equal kind form one run however
//! they are stored. Deleted items count as deleted units, whatever content
//! garbage collection left behind. Item pointers are never exposed and the
//! document is not changed. Work is one visit per item, map entry and range,
//! with an explicit stack rather than recursion.

use crate::block::{ItemContent, ItemPtr, ID};
use crate::branch::BranchPtr;
use crate::id_set::{DeleteSet, IdSet};
use crate::types::TypeRef;
use crate::{ReadTxn, StateVector};
use sha2::{Digest, Sha256};
use std::ops::Range;
use std::sync::Arc;

const DOMAIN: &[u8] = b"yrs structure digest v1\0";

// Unit kinds. Deleted units share one kind; a nested type is never merged
// into a run because its branch follows it in the stream.
const DELETED: u8 = 0;
const ANY: u8 = 1;
const BINARY: u8 = 2;
const DOC: u8 = 3;
const JSON: u8 = 4;
const EMBED: u8 = 5;
const FORMAT: u8 = 6;
const STRING: u8 = 7;
const TYPE: u8 = 8;

/// SHA-256 over a canonical, length-prefixed stream of the structure above.
pub fn structure_digest<T: ReadTxn>(txn: &T) -> [u8; 32] {
    let store = txn.store();
    let mut h = Sha256::new();
    h.update(DOMAIN);
    state_vector(&mut h, b'V', &store.blocks.get_state_vector());
    id_set(&mut h, b'D', &IdSet::from_store(&store.blocks));
    match &store.pending {
        None => h.update([b'p']),
        Some(pending) => {
            h.update([b'P']);
            state_vector(&mut h, b'M', &pending.missing);
            id_set(&mut h, b'I', &pending.update.insertions(true));
            id_set(&mut h, b'D', &pending.update.delete_set);
        }
    }
    match &store.pending_ds {
        None => h.update([b'q']),
        Some(ds) => id_set(&mut h, b'Q', ds),
    }
    let mut roots: Vec<_> = store
        .types
        .iter()
        .filter(|(_, b)| b.start.is_some() || !b.map.is_empty())
        .collect();
    roots.sort_by(|a, b| a.0.cmp(b.0));
    h.update(len(roots.len()));
    for (name, branch) in roots {
        h.update([b'R']);
        bytes(&mut h, name.as_bytes());
        walk(&mut h, BranchPtr::from(branch));
    }
    h.finalize().into()
}

enum Work {
    Branch(BranchPtr),
    List(Option<ItemPtr>),
    Entries(Vec<(Arc<str>, ItemPtr)>),
    End,
}

fn walk(h: &mut Sha256, root: BranchPtr) {
    let mut stack = vec![Work::Branch(root)];
    while let Some(work) = stack.pop() {
        match work {
            Work::Branch(branch) => {
                h.update([b'B']);
                let mut entries: Vec<_> = branch.map.iter().map(|(k, v)| (k.clone(), *v)).collect();
                entries.sort_by(|a, b| b.0.cmp(&a.0)); // popped in ascending order
                stack.push(Work::End);
                stack.push(Work::Entries(entries));
                stack.push(Work::List(branch.start));
            }
            Work::List(mut next) => {
                let mut run: Option<(ID, u32, u8)> = None;
                let mut nested = false;
                while let Some(item) = next {
                    next = item.right;
                    let kind = unit_kind(&item);
                    if let (TYPE, ItemContent::Type(inner)) = (kind, &item.content) {
                        flush(h, run.take());
                        h.update([b'T']);
                        id(h, &item.id);
                        type_ref(h, &inner.type_ref);
                        stack.push(Work::List(next));
                        stack.push(Work::Branch(BranchPtr::from(inner)));
                        nested = true;
                        break;
                    }
                    match &mut run {
                        Some((start, n, k))
                            if *k == kind
                                && start.client == item.id.client
                                && start.clock.checked_add(*n) == Some(item.id.clock) =>
                        {
                            *n += item.len;
                        }
                        _ => {
                            flush(h, run.take());
                            run = Some((item.id, item.len, kind));
                        }
                    }
                }
                flush(h, run);
                if !nested {
                    h.update([b'l']);
                }
            }
            Work::Entries(mut entries) => {
                let Some((key, current)) = entries.pop() else {
                    h.update([b'm']);
                    continue;
                };
                h.update([b'K']);
                bytes(h, key.as_bytes());
                // The current item, then each overwritten value to its left.
                let mut item = Some(current);
                while let Some(value) = item {
                    unit(h, &value.id, value.len, unit_kind(&value));
                    item = value.left;
                }
                h.update([b'k']);
                stack.push(Work::Entries(entries));
                if let (false, ItemContent::Type(inner)) = (current.is_deleted(), &current.content) {
                    h.update([b'T']);
                    type_ref(h, &inner.type_ref);
                    stack.push(Work::Branch(BranchPtr::from(inner)));
                }
            }
            Work::End => h.update([b'E']),
        }
    }
}

fn unit_kind(item: &ItemPtr) -> u8 {
    if item.is_deleted() {
        return DELETED;
    }
    match &item.content {
        ItemContent::Any(_) => ANY,
        ItemContent::Binary(_) => BINARY,
        ItemContent::Deleted(_) => DELETED,
        ItemContent::Doc(_, _) => DOC,
        ItemContent::JSON(_) => JSON,
        ItemContent::Embed(_) => EMBED,
        ItemContent::Format(_, _) => FORMAT,
        ItemContent::String(_) => STRING,
        ItemContent::Type(_) => TYPE,
    }
}

fn flush(h: &mut Sha256, run: Option<(ID, u32, u8)>) {
    if let Some((start, n, kind)) = run {
        unit(h, &start, n, kind);
    }
}

fn unit(h: &mut Sha256, start: &ID, n: u32, kind: u8) {
    h.update([b'U', kind]);
    id(h, start);
    h.update(n.to_be_bytes());
}

fn id(h: &mut Sha256, id: &ID) {
    h.update(id.client.get().to_be_bytes());
    h.update(id.clock.to_be_bytes());
}

fn type_ref(h: &mut Sha256, type_ref: &TypeRef) {
    h.update([type_ref.kind()]);
    if let TypeRef::XmlElement(tag) = type_ref {
        bytes(h, tag.as_bytes());
    }
}

fn state_vector(h: &mut Sha256, tag: u8, sv: &StateVector) {
    let mut clients: Vec<_> = sv.iter().map(|(c, clock)| (c.get(), *clock)).collect();
    clients.sort_unstable();
    h.update([tag]);
    h.update(len(clients.len()));
    for (client, clock) in clients {
        h.update(client.to_be_bytes());
        h.update(clock.to_be_bytes());
    }
}

/// Ranges per client, sorted and merged where they overlap or touch.
fn id_set(h: &mut Sha256, tag: u8, set: &IdSet) {
    let mut clients = Vec::with_capacity(set.len());
    for (client, ranges) in set.iter() {
        let mut ranges: Vec<Range<u32>> = ranges.iter().cloned().collect();
        ranges.sort_unstable_by_key(|r| (r.start, r.end));
        let mut merged: Vec<Range<u32>> = Vec::with_capacity(ranges.len());
        for range in ranges.into_iter().filter(|r| r.start < r.end) {
            match merged.last_mut() {
                Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
                _ => merged.push(range),
            }
        }
        if !merged.is_empty() {
            clients.push((client.get(), merged));
        }
    }
    h.update([tag]);
    h.update(len(clients.len()));
    for (client, merged) in clients {
        h.update(client.to_be_bytes());
        h.update(len(merged.len()));
        for range in merged {
            h.update(range.start.to_be_bytes());
            h.update(range.end.to_be_bytes());
        }
    }
}

fn bytes(h: &mut Sha256, value: &[u8]) {
    h.update(len(value.len()));
    h.update(value);
}

fn len(n: usize) -> [u8; 8] {
    (n as u64).to_be_bytes()
}
