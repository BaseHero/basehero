//! The typed payload: the bytes an ordered event carries for one operation.
//!
//! Layout: `u16` big-endian version ‖ `u32` big-endian header length ‖ UTF-8
//! JSON header ‖ raw tail. The header is RFC 8785 canonical JSON:
//!
//! ```json
//! { "mutation": "<hex32>", "affects": { "type": "<hex>"?, "record": "<hex>"? },
//!   "op": { "kind": "...", ... }, "confirmation": { ... }? }
//! ```
//!
//! `confirmation` is the exact prior rules explicitly approved by the person's
//! device. The signed event covers it. Ordinary submissions omit the field;
//! only the trusted approval path may encode it. Ordered evaluation checks it
//! against the prior rules at that position, not against a sender's claim.
//!
//! `DefineType` and `Adopt` carry the exact definition bytes as the tail
//! (`"definition": "tail"` in the header); every other operation has an empty
//! tail. Every version keeps the version and header-length prefix and the
//! header's `affects`, so a replica that cannot run an operation can still
//! tell what it may change. An unknown version or operation kind is
//! *unsupported* (it waits for a newer executable); an unknown field inside a
//! known kind is *malformed* on every client, because extensions use a new
//! kind or version. So is a version-1 header whose bytes are not exactly the
//! canonical form of what they parse to (duplicate keys, other spacing or key
//! order), so no two decoders can read one header differently.
//!
//! Known limit: an unsupported payload waits under whatever its `affects`
//! names, and unreadable `affects` (or none) means the whole typed scope. Any
//! member who may write to a scope can therefore stall all of its typed work
//! on every executable that cannot read the payload, for as long as it cannot
//! (`[0xff, 0xff]` is never readable). This is the same class as an operation
//! naming an unknown core revision, and it needs the same member authority.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    DataError, MutationId, RecordId, RevisionId, TypeId, admission::PriorRules, definition,
    mutation::ops::Operation, value,
};

pub const PAYLOAD_VERSION: u16 = 1;
/// A maximum-size definition (57,344 bytes) fits with its header.
pub const MAX_PAYLOAD_BYTES: usize = 61_440;

const PREFIX: usize = 6;
const TAIL: &str = "tail";
/// Every [`Operation::kind`]; any other kind is unsupported here.
const KNOWN: &[&str] = &[
    "define_app",
    "define_type",
    "adopt",
    "create",
    "edit",
    "delete",
    "undo",
    "undo_remove",
    "action",
    "set_app_state",
    "bind_core",
    "transition",
    "migrate",
    "bind_note",
];

/// What an operation may change, readable without understanding it. Neither
/// field set means the whole typed scope.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Affects {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_id: Option<TypeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<RecordId>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Decoded {
    Op(MutationId, Operation),
    Confirmed(MutationId, Operation, PriorRules),
    /// A version or operation kind this executable does not know.
    Unsupported {
        version: u16,
        affects: Affects,
        reason: String,
    },
    Malformed(String),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    mutation: MutationId,
    affects: Affects,
    op: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confirmation: Option<PriorRules>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefineTypeHeader {
    kind: String,
    definition: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptHeader {
    kind: String,
    #[serde(
        serialize_with = "crate::ids::serialize_hex",
        deserialize_with = "crate::ids::deserialize_hex"
    )]
    from_audience: [u8; 32],
    revision: RevisionId,
    definition: String,
}

/// What `op` may change, as its header states it.
pub fn affects_of(op: &Operation) -> Affects {
    match op {
        // An app's state is read by every operation on its types.
        Operation::DefineApp { .. } | Operation::SetAppState { .. } => Affects::default(),
        Operation::DefineType { bytes } | Operation::Adopt { bytes, .. } => Affects {
            type_id: definition::parse(bytes).ok().map(|def| def.type_id),
            record: None,
        },
        Operation::BindCore { type_id, .. } | Operation::Transition { type_id, .. } => Affects {
            type_id: Some(*type_id),
            record: None,
        },
        Operation::Create {
            record, type_id, ..
        }
        | Operation::BindNote {
            note: record,
            type_id,
            ..
        } => Affects {
            type_id: Some(*type_id),
            record: Some(*record),
        },
        op => Affects {
            type_id: None,
            record: op.record(),
        },
    }
}

/// Encodes one operation; a payload over [`MAX_PAYLOAD_BYTES`] is refused
/// with `DataError::Limit`.
pub fn encode(mutation: MutationId, op: &Operation) -> Result<Vec<u8>, DataError> {
    encode_with_confirmation(mutation, op, None)
}

/// Trusted approval callers use this only after checking the exact prior
/// rules with the submission evaluator. Other callers must use [`encode`].
pub fn encode_with_confirmation(
    mutation: MutationId,
    op: &Operation,
    confirmation: Option<PriorRules>,
) -> Result<Vec<u8>, DataError> {
    debug_assert!(
        KNOWN.contains(&op.kind()),
        "{} is not a known kind",
        op.kind()
    );
    let invalid = |e: serde_json::Error| DataError::Value(e.to_string());
    let (header_op, tail) = match op {
        Operation::DefineType { bytes } => (
            serde_json::to_value(DefineTypeHeader {
                kind: "define_type".into(),
                definition: TAIL.into(),
            })
            .map_err(invalid)?,
            bytes.as_slice(),
        ),
        Operation::Adopt {
            from_audience,
            revision,
            bytes,
        } => (
            serde_json::to_value(AdoptHeader {
                kind: "adopt".into(),
                from_audience: *from_audience,
                revision: *revision,
                definition: TAIL.into(),
            })
            .map_err(invalid)?,
            bytes.as_slice(),
        ),
        op => (serde_json::to_value(op).map_err(invalid)?, &[][..]),
    };
    let header = serde_json::to_value(Header {
        mutation,
        affects: affects_of(op),
        op: header_op,
        confirmation,
    })
    .map_err(invalid)?;
    let header = value::canonical(&header);
    let total = PREFIX + header.len() + tail.len();
    if total > MAX_PAYLOAD_BYTES {
        return Err(DataError::Limit(format!(
            "payload of {total} bytes exceeds {MAX_PAYLOAD_BYTES}"
        )));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
    out.extend_from_slice(
        &u32::try_from(header.len())
            .expect("bounded by MAX_PAYLOAD_BYTES")
            .to_be_bytes(),
    );
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(tail);
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Decoded {
    let Some(version) = bytes.get(..2).map(|v| u16::from_be_bytes([v[0], v[1]])) else {
        return Decoded::Malformed("payload shorter than its version".into());
    };
    if version != PAYLOAD_VERSION {
        return Decoded::Unsupported {
            version,
            affects: lenient_affects(bytes),
            reason: format!("payload version {version}"),
        };
    }
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Decoded::Malformed(format!("payload exceeds {MAX_PAYLOAD_BYTES} bytes"));
    }
    let Some((header, tail)) = frame(bytes) else {
        return Decoded::Malformed("header length exceeds the payload".into());
    };
    let parsed: Value = match serde_json::from_slice(header) {
        Ok(parsed) => parsed,
        Err(e) => return Decoded::Malformed(format!("header: {e}")),
    };
    if value::canonical(&parsed).as_bytes() != header {
        return Decoded::Malformed("header is not canonical JSON".into());
    }
    if parsed.get("confirmation") == Some(&Value::Null) {
        return Decoded::Malformed("confirmation must be omitted rather than null".into());
    }
    let header: Header = match serde_json::from_value(parsed) {
        Ok(header) => header,
        Err(e) => return Decoded::Malformed(format!("header: {e}")),
    };
    let Some(kind) = header.op.get("kind").and_then(Value::as_str) else {
        return Decoded::Malformed("operation without a kind".into());
    };
    if !KNOWN.contains(&kind) {
        return Decoded::Unsupported {
            version,
            affects: header.affects,
            reason: format!("operation kind {kind}"),
        };
    }
    let op = match operation(header.op, tail) {
        Ok(op) => op,
        Err(e) => return Decoded::Malformed(e),
    };
    if affects_of(&op) != header.affects {
        return Decoded::Malformed("affects does not match the operation".into());
    }
    match header.confirmation {
        Some(prior) => Decoded::Confirmed(header.mutation, op, prior),
        None => Decoded::Op(header.mutation, op),
    }
}

/// The header and tail of a payload in this layout.
fn frame(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = bytes.get(2..PREFIX)?;
    let len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
    let end = PREFIX.checked_add(len)?;
    Some((bytes.get(PREFIX..end)?, &bytes[end..]))
}

/// `affects` from any version's header, or the whole scope when it cannot be read.
fn lenient_affects(bytes: &[u8]) -> Affects {
    frame(bytes)
        .and_then(|(header, _)| serde_json::from_slice::<Map<String, Value>>(header).ok())
        .and_then(|mut header| header.remove("affects"))
        .and_then(|affects| serde_json::from_value(affects).ok())
        .unwrap_or_default()
}

fn operation(op: Value, tail: &[u8]) -> Result<Operation, String> {
    let kind = op
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let carries_tail = matches!(kind.as_str(), "define_type" | "adopt");
    if !carries_tail && !tail.is_empty() {
        return Err(format!("{kind} carries no tail"));
    }
    let tailed = |definition: &str| {
        if definition == TAIL {
            Ok(tail.to_vec())
        } else {
            Err(format!("{kind} definition must be \"{TAIL}\""))
        }
    };
    match kind.as_str() {
        "define_type" => {
            let h: DefineTypeHeader = serde_json::from_value(op).map_err(|e| e.to_string())?;
            Ok(Operation::DefineType {
                bytes: tailed(&h.definition)?,
            })
        }
        "adopt" => {
            let h: AdoptHeader = serde_json::from_value(op).map_err(|e| e.to_string())?;
            Ok(Operation::Adopt {
                from_audience: h.from_audience,
                revision: h.revision,
                bytes: tailed(&h.definition)?,
            })
        }
        _ => serde_json::from_value(op).map_err(|e| e.to_string()),
    }
}
