//! Deterministic bounds before handing schemas or instances to the validator.
use crate::{DataError, value};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

pub const MAX_EXPANDED: u64 = 8_192;
pub const MAX_RECORD_WORK: u64 = 16_777_216;
const MAX_GRAPH_DEPTH: usize = 128;

/// Count evaluation branches with multiplicity, memoising each source node.
/// All supplied definitions are checked, including unused ones: compilation
/// must not depend on the validator's eager/lazy resource strategy.
pub fn expansion(root: &Value, resources: &[(&str, &Value)]) -> Result<u64, DataError> {
    let docs: Vec<&Value> = std::iter::once(root)
        .chain(resources.iter().map(|(_, v)| *v))
        .collect();
    let mut uris = HashMap::new();
    for (i, (uri, _)) in resources.iter().enumerate() {
        if uris.insert(*uri, i + 1).is_some() {
            return Err(DataError::Definition("duplicate schema resource".into()));
        }
    }
    let mut graph = Graph {
        docs,
        uris,
        memo: HashMap::new(),
        active: HashSet::new(),
    };
    let mut total = 0u64;
    for i in 0..graph.docs.len() {
        total = total.saturating_add(graph.cost(i, "", 0)?.cost);
        bounded(total)?;
    }
    Ok(total)
}
fn escape(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}
fn bounded(cost: u64) -> Result<u64, DataError> {
    if cost > MAX_EXPANDED {
        Err(DataError::Limit("expanded schema work exceeds 8192".into()))
    } else {
        Ok(cost)
    }
}
#[derive(Clone, Copy)]
struct Work {
    cost: u64,
    // Longest descendant path in edges, independent of the first visit's depth.
    height: usize,
}
impl Work {
    fn include(&mut self, child: Self) {
        self.cost = self.cost.saturating_add(child.cost);
        self.height = self.height.max(1 + child.height);
    }
}

struct Graph<'a> {
    docs: Vec<&'a Value>,
    uris: HashMap<&'a str, usize>,
    memo: HashMap<(usize, String), Work>,
    active: HashSet<(usize, String)>,
}
impl Graph<'_> {
    fn cost(&mut self, doc: usize, pointer: &str, depth: usize) -> Result<Work, DataError> {
        let key = (doc, pointer.to_owned());
        if let Some(work) = self.memo.get(&key) {
            // A shallow first visit must not hide a longer path through this
            // subtree later. Both values are bounded by the early depth guard.
            if depth + work.height > MAX_GRAPH_DEPTH {
                return Err(DataError::Limit(
                    "cyclic or excessively deep schema graph".into(),
                ));
            }
            return Ok(*work);
        }
        if depth > MAX_GRAPH_DEPTH || !self.active.insert(key.clone()) {
            return Err(DataError::Limit(
                "cyclic or excessively deep schema graph".into(),
            ));
        }
        let node = self.docs[doc]
            .pointer(pointer)
            .ok_or_else(|| DataError::Definition("unresolved schema reference".into()))?;
        let mut work = Work { cost: 1, height: 0 };
        if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
            let (uri, fragment) = reference.split_once('#').unwrap_or((reference, ""));
            let target = if uri.is_empty() {
                doc
            } else {
                *self
                    .uris
                    .get(uri)
                    .ok_or_else(|| DataError::Definition("unregistered schema resource".into()))?
            };
            work.include(self.cost(target, fragment, depth + 1)?);
        }
        for keyword in ["properties", "$defs"] {
            for name in node
                .get(keyword)
                .and_then(Value::as_object)
                .into_iter()
                .flat_map(|m| m.keys())
            {
                work.include(self.cost(
                    doc,
                    &format!("{pointer}/{keyword}/{}", escape(name)),
                    depth + 1,
                )?);
            }
        }
        if node.get("items").is_some() {
            work.include(self.cost(doc, &format!("{pointer}/items"), depth + 1)?);
        }
        for keyword in ["prefixItems", "allOf", "anyOf", "oneOf"] {
            for n in 0..node
                .get(keyword)
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
            {
                work.include(self.cost(doc, &format!("{pointer}/{keyword}/{n}"), depth + 1)?);
            }
        }
        // Enum/const comparisons inspect their literal operands too.
        for keyword in ["enum", "const"] {
            if let Some(v) = node.get(keyword) {
                work.cost = work.cost.saturating_add(value::canonical(v).len() as u64);
            }
        }
        bounded(work.cost)?;
        self.active.remove(&key);
        self.memo.insert(key, work);
        Ok(work)
    }
}

/// Includes bytes (string/comparison work), all descendant visits and a
/// conservative pairwise array-comparison allowance for uniqueItems. Nested
/// arrays are counted independently, in one bounded-depth walk.
pub fn record_shape(doc: &Value) -> u64 {
    fn walk(v: &Value) -> (u64, u64) {
        match v {
            Value::Array(items) => {
                let mut bytes = 2u64;
                let mut extra = 0u64;
                for item in items {
                    let (b, e) = walk(item);
                    bytes = bytes.saturating_add(b + 1);
                    extra = extra.saturating_add(e);
                }
                (
                    bytes,
                    extra.saturating_add(bytes.saturating_mul(items.len() as u64)),
                )
            }
            Value::Object(items) => {
                let mut bytes = 2u64;
                let mut extra = 0u64;
                for (key, v) in items {
                    let (b, e) = walk(v);
                    bytes = bytes.saturating_add(b + key.len() as u64 * 6 + 4);
                    extra = extra.saturating_add(e);
                }
                (bytes, extra)
            }
            _ => (value::canonical(v).len() as u64 + 1, 0),
        }
    }
    let (bytes, extra) = walk(doc);
    bytes.saturating_add(extra)
}
