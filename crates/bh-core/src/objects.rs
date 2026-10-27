//! The object document layout, summaries, positions and the folder tree.
//!
//! Every object is one yrs document: `Map "meta"` holds `type`, `v`, `parent`
//! (hex, null or absent at the top level), `pos` and `deleted`; `Map "fields"` holds
//! the fields as JSON values; `XmlFragment "default"` holds a note's body.

use crate::Error;
use crate::types::TypeRef;
use bh_proto::{DeviceId, ObjectId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use ts_rs::TS;
use yrs::{Any, Map as _, MapRef, Out, ReadTxn, TransactionMut, WriteTxn};

pub(crate) const META: &str = "meta";
pub(crate) const FIELDS: &str = "fields";
pub(crate) const BODY: &str = "default";

/// A new object. `after` places it after that sibling; without it, the object
/// goes last among `parent`'s children.
#[derive(Clone, Debug, PartialEq)]
pub struct NewObject {
    pub ty: TypeRef,
    pub parent: Option<ObjectId>,
    pub after: Option<ObjectId>,
    pub fields: Map<String, Value>,
}

/// An object as lists show it. `parent` is where the object shows in the tree:
/// its own parent, or the top level when that parent isn't here (yet) or the
/// object has the lowest ID in a cycle of moves.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct ObjectSummary {
    #[ts(type = "string")]
    pub id: ObjectId,
    pub ty: TypeRef,
    #[ts(type = "string | null")]
    pub parent: Option<ObjectId>,
    pub position: String,
    pub deleted: bool,
    pub title: String,
    #[ts(as = "HashMap<String, TsJsonValue>")]
    pub fields: Map<String, Value>,
    #[ts(type = "number")]
    pub updated_at: i64,
    #[ts(type = "string | null")]
    pub updated_by: Option<DeviceId>,
}

/// TypeScript's view of a `serde_json::Value`.
#[derive(TS)]
#[ts(
    export,
    export_to = "apps/basehero/src/lib/generated/",
    rename = "JsonValue",
    untagged
)]
#[allow(dead_code, reason = "describes JSON to TypeScript only")]
pub(crate) enum TsJsonValue {
    Number(f64),
    String(String),
    Boolean(bool),
    Array(Vec<TsJsonValue>),
    Object(HashMap<String, TsJsonValue>),
    Null(()),
}

/// What an object's `meta` map says.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Meta {
    pub ty: TypeRef,
    pub parent: Option<ObjectId>,
    pub position: String,
    pub deleted: bool,
}

fn meta_map<T: ReadTxn>(txn: &T) -> Option<MapRef> {
    txn.get_map(META)
}

/// The object's `meta`. A document without a type isn't an object.
pub(crate) fn read_meta<T: ReadTxn>(txn: &T) -> Result<Meta, Error> {
    let invalid = || Error::invalid("not an object document");
    let meta = meta_map(txn).ok_or_else(invalid)?;
    let get = |key: &str| match meta.get(txn, key) {
        Some(Out::Any(any)) => Some(any),
        _ => None,
    };
    let Some(Any::String(name)) = get("type") else {
        return Err(invalid());
    };
    let version = match get("v") {
        Some(Any::Number(n)) => n
            .as_i64()
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| *v > 0)
            .ok_or_else(invalid)?,
        _ => return Err(invalid()),
    };
    let parent = match get("parent") {
        Some(Any::String(hex)) => hex.parse().ok(),
        _ => None,
    };
    let position = match get("pos") {
        Some(Any::String(pos)) => pos.to_string(),
        _ => String::new(),
    };
    Ok(Meta {
        ty: TypeRef::new(&*name, version),
        parent,
        position,
        deleted: matches!(get("deleted"), Some(Any::Bool(true))),
    })
}

pub(crate) fn write_type(txn: &mut TransactionMut, ty: &TypeRef) {
    let meta = txn.get_or_insert_map(META);
    meta.insert(txn, "type", ty.name.as_str());
    meta.insert(txn, "v", Any::from(ty.version));
}

/// Writes `parent` (null at the top level, never removed) and `pos`
/// together, so concurrent moves resolve both from the same move.
pub(crate) fn write_place(txn: &mut TransactionMut, parent: Option<ObjectId>, position: &str) {
    let meta = txn.get_or_insert_map(META);
    let parent = parent.map_or(Any::Null, |p| Any::from(p.to_string()));
    meta.insert(txn, "parent", parent);
    meta.insert(txn, "pos", position);
}

pub(crate) fn write_deleted(txn: &mut TransactionMut, deleted: bool) {
    let meta = txn.get_or_insert_map(META);
    meta.insert(txn, "deleted", deleted);
}

/// The object's fields as JSON. Nested yrs types read as their JSON value.
pub(crate) fn read_fields<T: ReadTxn>(txn: &T) -> Map<String, Value> {
    let Some(fields) = txn.get_map(FIELDS) else {
        return Map::new();
    };
    let mut out = Map::new();
    for (key, value) in fields.iter(txn) {
        let any = yrs::types::ToJson::to_json(&value, txn);
        if let Ok(value) = serde_json::to_value(&any)
            && !value.is_null()
        {
            out.insert(key.to_string(), value);
        }
    }
    out
}

/// Sets each field; a `null` removes it.
pub(crate) fn write_fields(
    txn: &mut TransactionMut,
    fields: &Map<String, Value>,
) -> Result<(), Error> {
    let map = txn.get_or_insert_map(FIELDS);
    for (key, value) in fields {
        if value.is_null() {
            map.remove(txn, key);
        } else {
            let any: Any = serde_json::from_value(value.clone())
                .map_err(|_| Error::invalid("a field value isn't JSON"))?;
            map.insert(txn, key.as_str(), any);
        }
    }
    Ok(())
}

const DIGITS: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const ZERO: u8 = DIGITS[0];
const LAST: u8 = DIGITS[61];
/// The smallest integer part, which no key may be on its own.
const SMALLEST: &str = "A00000000000000000000000000";
/// Random digits ending each new key, so devices that place objects in the
/// same spot at once practically never make the same key.
const JITTER: usize = 3;

fn digit(c: u8) -> usize {
    DIGITS.iter().position(|&d| d == c).expect("checked digit")
}

/// The length of a key's integer part from its head: `a`–`z` give 2–27
/// characters, `Z`–`A` give 2–27 for keys below them.
fn integer_len(head: u8) -> Option<usize> {
    match head {
        b'a'..=b'z' => Some(usize::from(head - b'a') + 2),
        b'A'..=b'Z' => Some(usize::from(b'Z' - head) + 2),
        _ => None,
    }
}

fn split(key: &str) -> (&str, &str) {
    let len = integer_len(key.as_bytes()[0]).expect("checked key");
    key.split_at(len)
}

/// A position key, as rocicorp's fractional indexing makes them: an integer
/// part (a head letter giving its length, then base-62 digits) and a fraction
/// that doesn't end in `0`.
fn is_position(key: &str) -> bool {
    let bytes = key.as_bytes();
    let Some(len) = bytes.first().copied().and_then(integer_len) else {
        return false;
    };
    bytes.len() >= len
        && bytes.iter().all(u8::is_ascii_alphanumeric)
        && (bytes.len() == len || bytes.last() != Some(&ZERO))
        && key != SMALLEST
}

/// The next integer part, or `None` after the largest.
fn increment(int: &str) -> Option<String> {
    let (head, mut digits) = (int.as_bytes()[0], int.as_bytes()[1..].to_vec());
    for d in digits.iter_mut().rev() {
        if *d != LAST {
            *d = DIGITS[digit(*d) + 1];
            return Some(join(head, &digits));
        }
        *d = ZERO;
    }
    match head {
        b'Z' => Some("a0".into()),
        b'z' => None,
        _ => {
            let head = head + 1;
            if head > b'a' {
                digits.push(ZERO);
            } else {
                digits.pop();
            }
            Some(join(head, &digits))
        }
    }
}

/// The previous integer part, or `None` before the smallest.
fn decrement(int: &str) -> Option<String> {
    let (head, mut digits) = (int.as_bytes()[0], int.as_bytes()[1..].to_vec());
    for d in digits.iter_mut().rev() {
        if *d != ZERO {
            *d = DIGITS[digit(*d) - 1];
            return Some(join(head, &digits));
        }
        *d = LAST;
    }
    match head {
        b'a' => Some(join(b'Z', &[LAST])),
        b'A' => None,
        _ => {
            let head = head - 1;
            if head < b'Z' {
                digits.push(LAST);
            } else {
                digits.pop();
            }
            Some(join(head, &digits))
        }
    }
}

fn join(head: u8, digits: &[u8]) -> String {
    String::from_utf8([&[head], digits].concat()).expect("ASCII")
}

/// A fraction strictly between `a` and `b` (`None` meaning past the end).
fn midpoint(a: &str, b: Option<&str>) -> String {
    let (a, b) = (a.as_bytes(), b.map(str::as_bytes));
    if let Some(b) = b {
        let shared = b
            .iter()
            .enumerate()
            .take_while(|(i, c)| a.get(*i).copied().unwrap_or(ZERO) == **c)
            .count();
        if shared > 0 {
            let rest = midpoint(
                std::str::from_utf8(a.get(shared..).unwrap_or(&[])).expect("ASCII"),
                Some(std::str::from_utf8(&b[shared..]).expect("ASCII")),
            );
            return std::str::from_utf8(&b[..shared]).expect("ASCII").to_owned() + &rest;
        }
    }
    let low = a.first().map_or(0, |&c| digit(c));
    let high = b.map_or(DIGITS.len(), |b| digit(b[0]));
    if high - low > 1 {
        return (DIGITS[(low + high).div_ceil(2)] as char).to_string();
    }
    match b {
        Some(b) if b.len() > 1 => (b[0] as char).to_string(),
        _ => {
            let rest = std::str::from_utf8(a.get(1..).unwrap_or(&[])).expect("ASCII");
            (DIGITS[low] as char).to_string() + &midpoint(rest, None)
        }
    }
}

/// rocicorp's `generateKeyBetween` for valid keys `a < b`, `None` meaning the
/// start or the end. Appends and prepends step the integer part, so keys
/// grow with the logarithm of the count; the integer parts run out only after
/// 62^26 keys at either end.
fn key_between(a: Option<&str>, b: Option<&str>) -> String {
    match (a, b) {
        (None, None) => "a0".into(),
        (None, Some(b)) => {
            let (int, fraction) = split(b);
            if int == SMALLEST {
                return format!("{int}{}", midpoint("", Some(fraction)));
            }
            // Unlike rocicorp's, this never returns `b`'s own integer part:
            // every key ends in random digits, so that would put each prepend
            // inside the fraction of the one before, and keys would grow.
            let int = decrement(int).expect("only the smallest integer has none before it");
            if int == SMALLEST {
                return format!("{int}{}", midpoint("", None));
            }
            int
        }
        (Some(a), None) => {
            let (int, fraction) = split(a);
            increment(int).unwrap_or_else(|| format!("{int}{}", midpoint(fraction, None)))
        }
        (Some(a), Some(b)) => {
            let ((int_a, fraction_a), (int_b, fraction_b)) = (split(a), split(b));
            if int_a == int_b {
                return format!("{int_a}{}", midpoint(fraction_a, Some(fraction_b)));
            }
            match increment(int_a) {
                Some(int) if int.as_str() < b => int,
                _ => format!("{int_a}{}", midpoint(fraction_a, None)),
            }
        }
    }
}

fn jitter() -> String {
    let random = bh_crypto::random::<JITTER>();
    let mut out: String = random[..JITTER - 1]
        .iter()
        .map(|b| DIGITS[usize::from(*b) % 62] as char)
        .collect();
    out.push(DIGITS[1 + usize::from(random[JITTER - 1]) % 61] as char);
    out
}

/// A position key strictly between `before` and `after`, where `None` is the
/// start or the end, ending in random digits. A bound that isn't a valid key,
/// or bounds out of order (as after concurrent edits), counts as open.
pub(crate) fn position_between(before: Option<&str>, after: Option<&str>) -> String {
    let before = before.filter(|b| is_position(b));
    let after = after.filter(|a| is_position(a) && before.is_none_or(|b| b < *a));
    let mut key = key_between(before, after);
    loop {
        let jittered = key.clone() + &jitter();
        if after.is_none_or(|a| jittered.as_str() < a) {
            return jittered;
        }
        // `key` is a prefix of `after`: move closer to it and try again.
        key = key_between(Some(&key), after);
    }
}

/// Where an object shows in the tree. `parent_of` gives an object's own
/// parent, or `None` for an object this device doesn't have. An object shows
/// at the top level when its parent is missing, or when it has the lowest ID
/// in a cycle of concurrent moves; otherwise under its own parent.
pub(crate) fn effective_parent<E>(
    id: ObjectId,
    mut parent_of: impl FnMut(ObjectId) -> Result<Option<Option<ObjectId>>, E>,
) -> Result<Option<ObjectId>, E> {
    let Some(Some(parent)) = parent_of(id)? else {
        return Ok(None);
    };
    if parent_of(parent)?.is_none() {
        return Ok(None);
    }
    let (mut seen, mut lowest, mut node) = (HashSet::from([id]), id, parent);
    loop {
        if node == id {
            return Ok((lowest != id).then_some(parent));
        }
        if !seen.insert(node) {
            return Ok(Some(parent));
        }
        lowest = lowest.min(node);
        match parent_of(node)? {
            Some(Some(next)) => node = next,
            _ => return Ok(Some(parent)),
        }
    }
}

/// The objects with the lowest ID in each cycle of `parents`, which show at
/// the top level.
pub(crate) fn cycle_minimums(parents: &HashMap<ObjectId, Option<ObjectId>>) -> HashSet<ObjectId> {
    let (mut done, mut out) = (HashSet::new(), HashSet::new());
    for &start in parents.keys() {
        let mut path: Vec<ObjectId> = Vec::new();
        let mut node = Some(start);
        while let Some(n) = node {
            if done.contains(&n) {
                break;
            }
            if let Some(i) = path.iter().position(|&p| p == n) {
                out.insert(*path[i..].iter().min().expect("non-empty cycle"));
                break;
            }
            path.push(n);
            node = parents.get(&n).copied().flatten();
        }
        done.extend(path);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use yrs::updates::decoder::Decode;
    use yrs::{Doc, Transact};

    #[test]
    fn keys_match_rocicorps_fractional_indexing() {
        let z27 = "z".repeat(27);
        let (z27v, one) = (format!("{z27}V"), format!("{}1", &SMALLEST[..26]));
        let (smallest_v, smallest_1, smallest_0v) = (
            format!("{SMALLEST}V"),
            format!("{SMALLEST}1"),
            format!("{SMALLEST}0V"),
        );
        let cases = [
            (None, None, "a0"),
            (None, Some("a0"), "Zz"),
            (None, Some("Zz"), "Zy"),
            (Some("a0"), None, "a1"),
            (Some("a1"), None, "a2"),
            (Some("a0"), Some("a1"), "a0V"),
            (Some("a1"), Some("a2"), "a1V"),
            (Some("a0V"), Some("a1"), "a0l"),
            (Some("Zz"), Some("a0"), "ZzV"),
            (Some("Zz"), Some("a1"), "a0"),
            (None, Some("Y00"), "Xzzz"),
            (Some("bzz"), None, "c000"),
            (Some("a0"), Some("a0V"), "a0G"),
            (Some("a0"), Some("a0G"), "a08"),
            (Some("b125"), Some("b129"), "b127"),
            (Some("a0"), Some("a1V"), "a1"),
            (Some("Zz"), Some("a01"), "a0"),
            (Some(z27.as_str()), None, z27v.as_str()),
            // rocicorp gives "a0" and "b99" here; prepends step the integer.
            (None, Some("a0V"), "Zz"),
            (None, Some("b999"), "b98"),
            (None, Some(one.as_str()), smallest_v.as_str()),
            (None, Some(smallest_1.as_str()), smallest_0v.as_str()),
        ];
        for (a, b, want) in cases {
            assert!(a.is_none_or(is_position) && b.is_none_or(is_position));
            assert_eq!(key_between(a, b), want, "{a:?} {b:?}");
        }
        assert_eq!(increment("Zz").as_deref(), Some("a0"));
        assert_eq!(decrement("a0").as_deref(), Some("Zz"));
        assert_eq!(increment(&z27), None);
        assert_eq!(decrement(SMALLEST), None);
    }

    #[test]
    fn only_well_formed_keys_are_positions() {
        for key in ["a0", "a0V", "Zz", "b125", "zzzzzzzzzzzzzzzzzzzzzzzzzzz"] {
            assert!(is_position(key), "{key}");
        }
        for key in ["", "0", "a", "a00", "a0V0", "b1", "a-b", "a0é", SMALLEST] {
            assert!(!is_position(key), "{key}");
        }
    }

    #[test]
    fn positions_sort_between_their_bounds() {
        let cases: &[(Option<&str>, Option<&str>)] = &[
            (None, None),
            (Some("a0"), None),
            (None, Some("a0")),
            (Some("a0"), Some("a1")),
            (Some("a0"), Some("a01")),
            (Some("a0"), Some("a0001")),
            (Some("Zz"), Some("a0")),
            (Some("a1"), Some("a1V")),
            (Some("a1"), Some("a11")),
            (None, Some("A000000000000000000000000001")),
            (None, Some("A0000000000000000000000000001")),
        ];
        for &(before, after) in cases {
            for _ in 0..50 {
                let key = position_between(before, after);
                assert!(is_position(&key), "{key}");
                assert!(before.is_none_or(|b| b < key.as_str()), "{before:?} {key}");
                assert!(after.is_none_or(|a| key.as_str() < a), "{key} {after:?}");
            }
        }
    }

    #[test]
    fn the_same_spot_gives_different_keys() {
        let keys: HashSet<_> = (0..20)
            .map(|_| position_between(Some("a0"), Some("a1")))
            .collect();
        assert!(keys.len() > 1);
    }

    #[test]
    fn appends_and_prepends_keep_keys_short() {
        let (mut first, mut last) = (position_between(None, None), position_between(None, None));
        for _ in 0..10_000 {
            let key = position_between(Some(&last), None);
            assert!(last < key && key.len() < 20, "{last} {key}");
            last = key;
            let key = position_between(None, Some(&first));
            assert!(key < first && key.len() < 20, "{key} {first}");
            first = key;
        }
    }

    #[test]
    fn repeated_inserts_stay_ordered() {
        let mut keys = vec![position_between(None, None)];
        for i in 0..200 {
            let (before, after) = match i % 3 {
                0 => (keys.last().cloned(), None),
                1 => (None, keys.first().cloned()),
                _ => (Some(keys[0].clone()), keys.get(1).cloned()),
            };
            let key = position_between(before.as_deref(), after.as_deref());
            assert!(before.is_none_or(|b| b < key) && after.is_none_or(|a| key < a));
            keys.push(key);
            keys.sort();
            keys.dedup();
        }
        assert_eq!(keys.len(), 201);
        assert!(keys.iter().all(|k| k.len() < 40), "{:?}", keys.last());
    }

    #[test]
    fn bad_or_reversed_bounds_are_open() {
        assert!(position_between(Some("b00"), Some("a0")).as_str() > "b00");
        assert!(position_between(Some("a0"), Some("a0")).as_str() > "a0");
        assert!(is_position(&position_between(Some("a-b"), Some("é"))));
    }

    fn id(n: u8) -> ObjectId {
        ObjectId([n; 16])
    }

    #[test]
    fn effective_parents_break_cycles_at_the_lowest_id() {
        // 1 → 2 → 3 → 1 is a cycle; 4 hangs off 2; 5's parent is missing.
        let parents: HashMap<_, _> = [
            (id(1), Some(id(2))),
            (id(2), Some(id(3))),
            (id(3), Some(id(1))),
            (id(4), Some(id(2))),
            (id(5), Some(id(9))),
            (id(6), None),
        ]
        .into();
        let of = |n| Ok::<_, ()>(parents.get(&n).copied());
        assert_eq!(effective_parent(id(1), of), Ok(None));
        assert_eq!(effective_parent(id(2), of), Ok(Some(id(3))));
        assert_eq!(effective_parent(id(3), of), Ok(Some(id(1))));
        assert_eq!(effective_parent(id(4), of), Ok(Some(id(2))));
        assert_eq!(effective_parent(id(5), of), Ok(None));
        assert_eq!(effective_parent(id(6), of), Ok(None));
        assert_eq!(effective_parent(id(7), of), Ok(None));
        assert_eq!(cycle_minimums(&parents), HashSet::from([id(1)]));
    }

    #[test]
    fn meta_and_fields_round_trip_through_a_document() {
        let doc = Doc::new();
        let mut txn = doc.transact_mut();
        write_type(&mut txn, &TypeRef::new("demo.trip", 3));
        write_place(&mut txn, Some(id(1)), "V");
        write_deleted(&mut txn, true);
        let fields = serde_json::json!({ "n": 1, "x": 1.5, "s": "a", "o": { "k": [true] } });
        write_fields(&mut txn, fields.as_object().unwrap()).unwrap();
        let meta = read_meta(&txn).unwrap();
        assert_eq!(meta.ty, TypeRef::new("demo.trip", 3));
        assert_eq!(
            (meta.parent, meta.position.as_str(), meta.deleted),
            (Some(id(1)), "V", true)
        );
        assert_eq!(Value::Object(read_fields(&txn)), fields);
        write_place(&mut txn, None, "W");
        write_fields(
            &mut txn,
            serde_json::json!({ "n": null }).as_object().unwrap(),
        )
        .unwrap();
        assert_eq!(read_meta(&txn).unwrap().parent, None);
        let meta = txn.get_map(META).unwrap();
        assert_eq!(meta.get(&txn, "parent"), Some(Out::Any(Any::Null)));
        meta.remove(&mut txn, "parent");
        assert_eq!(read_meta(&txn).unwrap().parent, None);
        assert!(!read_fields(&txn).contains_key("n"));
    }

    #[test]
    fn a_concurrent_move_to_the_top_level_keeps_its_parent_and_position_together() {
        let start = Doc::with_client_id(1);
        {
            let mut txn = start.transact_mut();
            write_type(&mut txn, &TypeRef::new("core.note", 1));
            write_place(&mut txn, Some(id(1)), "a0");
        }
        let state = start
            .transact()
            .encode_state_as_update_v1(&Default::default());
        // The higher client ID wins concurrent writes to a key; it moves to
        // the top level, which once removed `parent` and so lost that key.
        let copies = [Doc::with_client_id(3), Doc::with_client_id(2)];
        for (doc, parent, pos) in [(&copies[0], None, "a1"), (&copies[1], Some(id(2)), "a2")] {
            let mut txn = doc.transact_mut();
            txn.apply_update(yrs::Update::decode_v1(&state).unwrap())
                .unwrap();
            write_place(&mut txn, parent, pos);
        }
        let updates = copies
            .each_ref()
            .map(|d| d.transact().encode_state_as_update_v1(&Default::default()));
        for (doc, update) in copies.iter().zip(updates.iter().rev()) {
            doc.transact_mut()
                .apply_update(yrs::Update::decode_v1(update).unwrap())
                .unwrap();
        }
        let metas = copies.each_ref().map(|d| read_meta(&d.transact()).unwrap());
        assert_eq!(metas[0], metas[1]);
        let place = (metas[0].parent, metas[0].position.as_str());
        assert!(
            place == (None, "a1") || place == (Some(id(2)), "a2"),
            "{place:?}"
        );
    }
}
