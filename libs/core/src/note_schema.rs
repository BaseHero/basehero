//! Classification for the versioned note inventory shared with the bundled
//! editor. Never use this to reject storage of an unknown canonical Yjs update.
use serde_json::Value;
use yrs::types::xml::XmlOut;
use yrs::updates::decoder::Decode;
use yrs::{Doc, Out, ReadTxn, Text, Transact, Update, Xml, XmlFragment};

fn inventory() -> Value {
    serde_json::from_str(include_str!("../../../note-schema/v1.json"))
        .expect("checked static note schema")
}

fn value_matches(rule: &Value, value: &Value) -> bool {
    if let Some(choices) = rule.get("enum").and_then(Value::as_array) {
        return choices.contains(value);
    }
    if let Some(bounds) = rule.get("integer").and_then(Value::as_array) {
        return value
            .as_i64()
            .is_some_and(|n| n >= bounds[0].as_i64().unwrap() && n <= bounds[1].as_i64().unwrap());
    }
    if let Some(protocols) = rule.get("url").and_then(Value::as_array) {
        return value.as_str().is_some_and(|s| {
            !s.chars().any(char::is_control)
                && url::Url::parse(s).is_ok_and(|url| {
                    url.host_str().is_some()
                        && protocols
                            .iter()
                            .any(|p| p.as_str() == Some(&format!("{}:", url.scheme())))
                })
        });
    }
    false
}
fn attribute_matches(rules: &Value, name: &str, value: &yrs::Any) -> bool {
    rules.get(name).is_some_and(|rule| {
        serde_json::to_value(value).is_ok_and(|value| value_matches(rule, &value))
    })
}
fn permits(parent: &str, child: &str, spec: &Value) -> bool {
    spec["children"][parent]
        .as_array()
        .is_some_and(|children| children.iter().any(|name| name.as_str() == Some(child)))
}
fn supported<T: ReadTxn>(node: XmlOut, parent: &str, txn: &T, spec: &Value) -> bool {
    match node {
        XmlOut::Text(text) => {
            if !permits(parent, "text", spec) || text.attributes(txn).next().is_some() {
                return false;
            }
            text.diff(txn, |_| ()).into_iter().all(|piece| {
                matches!(piece.insert, Out::Any(yrs::Any::String(_)))
                    && piece.attributes.is_none_or(|attrs| {
                        attrs.iter().all(|(name, value)| {
                            spec["marks"]
                                .get(name.as_ref())
                                .is_some_and(|rules| match value {
                                    yrs::Any::Map(map) => map
                                        .iter()
                                        .all(|(key, val)| attribute_matches(rules, key, val)),
                                    _ => false,
                                })
                        })
                    })
            })
        }
        XmlOut::Element(el) => {
            let name = el.tag().as_ref();
            if !permits(parent, name, spec) {
                return false;
            }
            let Some(rules) = spec["nodes"].get(name) else {
                return false;
            };
            let first_ok = spec["requiredFirst"][name].as_array().is_none_or(|required| {
                matches!(el.get(txn, 0), Some(XmlOut::Element(first)) if required.iter().any(|candidate| candidate.as_str() == Some(first.tag())))
            });
            first_ok
                && el.attributes(txn).all(|(key, value)| match value {
                    Out::Any(any) => attribute_matches(rules, key, &any),
                    _ => false,
                })
                && (0..el.len(txn)).all(|index| {
                    el.get(txn, index)
                        .is_some_and(|child| supported(child, name, txn, spec))
                })
        }
        XmlOut::Fragment(_) => false,
    }
}

/// This is a UI compatibility check, never a condition for keeping a note in
/// storage. An unsupported note remains intact and must not be editor-bound.
pub fn classify_note(bytes: &[u8]) -> Result<bool, crate::note::NoteError> {
    let update = Update::decode_v1(bytes).map_err(crate::note::NoteError::Decode)?;
    let doc = Doc::new();
    doc.transact_mut()
        .apply_update(update)
        .map_err(crate::note::NoteError::Apply)?;
    let txn = doc.transact();
    let Some(fragment) = txn.get_xml_fragment("default") else {
        return Ok(true);
    };
    let spec = inventory();
    // children() stops at the first primitive in an XML sequence; get()
    // returns None there. Visit every array position so later content cannot
    // conceal an unsupported child from the editor compatibility gate.
    Ok((0..fragment.len(&txn)).all(|index| {
        fragment
            .get(&txn, index)
            .is_some_and(|child| supported(child, "default", &txn, &spec))
    }))
}
