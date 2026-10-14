//! Pure Worker-side validation/planning over an ordinary DO's transaction snapshot.
//! No account authority, host freshness, channel authentication or trusted clock is
//! established here. The DO adapter supplies persisted rows, never caller rows.
use bh_sync::{
    BaseId, BodyObject, Commitment, Digest, GateState, Head, OpaqueEvent, Operation,
    SignedApproval, TimeWindow, plan_consumption,
};
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, OnceLock};

const MAX_INPUT: usize = 10 * 1024 * 1024;
const MAX_OUTPUT: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Gate {
    base: String,
    position: u64,
    hash: String,
    incarnation: String,
    sequence: u64,
    checker_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    position: u64,
    event_id: String,
    event_digest: String,
    commitment: String,
    event: String,
    previous: Option<String>,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum RequestOperation {
    Append { event: String },
    Read { objects: Vec<String> },
    Stage { body: String },
    Readbodies { objects: Vec<String> },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyRow {
    commitment: String,
    body: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u16,
    gate: Gate,
    approval: String,
    operation: RequestOperation,
    binding: String,
    earliest: u64,
    latest: u64,
    head: Option<Row>,
    selected: Vec<Row>,
    /// Stored bytes the adapter found under an append's referenced body. Rust
    /// re-derives the commitment from these bytes; a caller value is ignored.
    #[serde(default)]
    staged_body: Option<String>,
    /// Stored bodies selected for a body read, in request order.
    #[serde(default)]
    bodies: Vec<BodyRow>,
}
#[derive(Serialize)]
struct ResultPlan {
    position: u64,
    hash: String,
    sequence: u64,
    append: Option<String>,
    ack: Option<String>,
    stage: Option<String>,
}

fn canonical_hex(value: &str) -> bool {
    value
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}
fn unhex<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    if value.len() != N * 2 || !canonical_hex(value) {
        return Err(());
    }
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(out)
}
fn unhex_bytes(value: &str, max: usize) -> Result<Vec<u8>, ()> {
    if value.len() > max * 2 || !value.len().is_multiple_of(2) || !canonical_hex(value) {
        return Err(());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| {
            u8::from_str_radix(std::str::from_utf8(chunk).map_err(|_| ())?, 16).map_err(|_| ())
        })
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(CHARS[(byte >> 4) as usize] as char);
        out.push(CHARS[(byte & 15) as usize] as char);
    }
    out
}
fn gate(value: Gate) -> Result<GateState, ()> {
    Ok(GateState {
        base: BaseId(unhex(&value.base)?),
        head: Head {
            position: value.position,
            hash: Digest(unhex(&value.hash)?),
        },
        incarnation: unhex(&value.incarnation)?,
        sequence: value.sequence,
        checker_key: unhex(&value.checker_key)?,
    })
}
fn row(value: &Row, state: GateState) -> Result<(Commitment, OpaqueEvent), ()> {
    let commitment = Commitment::decode(&unhex_bytes(&value.commitment, 178)?).map_err(|_| ())?;
    let event = OpaqueEvent::decode(&unhex_bytes(&value.event, 65574)?).map_err(|_| ())?;
    let previous = if value.position == 1 {
        if value.previous.is_some() {
            return Err(());
        }
        Head::EMPTY
    } else {
        let prior = Commitment::decode(&unhex_bytes(value.previous.as_ref().ok_or(())?, 178)?)
            .map_err(|_| ())?;
        if prior.base() != state.base || prior.head().position != value.position - 1 {
            return Err(());
        }
        prior.head()
    };
    if value.position == 0
        || value.position > state.head.position
        || commitment.base() != state.base
        || commitment.head().position != value.position
        || commitment.event_id() != event.id()
        || commitment.event_digest() != event.digest()
        || unhex::<32>(&value.event_id)? != event.id().0
        || unhex::<32>(&value.event_digest)? != event.digest().0
        || commitment.verify_next(state.base, previous).is_err()
        || commitment.verify_body(&event).is_err()
        || (value.position == state.head.position && commitment.head() != state.head)
    {
        return Err(());
    }
    Ok((commitment, event))
}

/// Returned bytes are a plan, not permission to expose data before a durable
/// transaction; only the DO storage adapter can apply them atomically.
fn plan(bytes: &[u8]) -> Result<Vec<u8>, ()> {
    if bytes.len() > MAX_INPUT {
        return Err(());
    }
    let request: Request = serde_json::from_slice(bytes).map_err(|_| ())?;
    if request.version != 1 {
        return Err(());
    }
    let state = gate(request.gate)?;
    if state.head == Head::EMPTY {
        if request.head.is_some() {
            return Err(());
        }
    } else {
        let (commitment, _) = row(request.head.as_ref().ok_or(())?, state)?;
        if commitment.head() != state.head {
            return Err(());
        }
    }
    let approval = SignedApproval::decode(&unhex_bytes(&request.approval, 290)?).map_err(|_| ())?;
    let binding = Digest(unhex(&request.binding)?);
    let staged_body = request
        .staged_body
        .as_deref()
        .map(|body| {
            let bytes = unhex_bytes(body, 65536)?;
            Ok::<_, ()>(BodyObject::new(bytes).map_err(|_| ())?.commitment())
        })
        .transpose()?;
    let operation = match request.operation {
        RequestOperation::Append { event } => {
            Operation::Append(OpaqueEvent::decode(&unhex_bytes(&event, 65574)?).map_err(|_| ())?)
        }
        RequestOperation::Read { objects } => Operation::read(
            objects
                .iter()
                .map(|s| unhex(s).map(Digest))
                .collect::<Result<_, _>>()?,
        )
        .map_err(|_| ())?,
        RequestOperation::Stage { body } => {
            let bytes = unhex_bytes(&body, 65536)?;
            Operation::stage_body(BodyObject::new(bytes).map_err(|_| ())?)
        }
        RequestOperation::Readbodies { objects } => {
            let objects = objects
                .iter()
                .map(|s| unhex(s).map(Digest))
                .collect::<Result<_, _>>()?;
            Operation::read_bodies(objects).map_err(|_| ())?
        }
    };
    let existing = match &operation {
        Operation::Append(event) => {
            if request.selected.len() > 1 {
                return Err(());
            }
            if let Some(found) = request.selected.first() {
                let (commitment, stored) = row(found, state)?;
                if stored.id() != event.id() {
                    return Err(());
                }
                Some(commitment)
            } else {
                None
            }
        }
        Operation::Read(selection) => {
            if request.selected.len() != selection.objects().len() {
                return Err(());
            }
            for (record, digest) in request.selected.iter().zip(selection.objects()) {
                let (_, stored) = row(record, state)?;
                if stored.digest() != *digest {
                    return Err(());
                }
            }
            None
        }
        Operation::ReadBodies(selection) => {
            // The adapter supplies stored bytes; the kernel re-derives each
            // commitment from those bytes rather than trusting the request.
            if request.bodies.len() != selection.objects().len() {
                return Err(());
            }
            for (record, digest) in request.bodies.iter().zip(selection.objects()) {
                let bytes = unhex_bytes(&record.body, 65536)?;
                let body = BodyObject::new(bytes).map_err(|_| ())?;
                if body.commitment() != *digest || unhex::<32>(&record.commitment)? != digest.0 {
                    return Err(());
                }
            }
            None
        }
        Operation::StageBody(_) => None,
    };
    let result = plan_consumption(
        &state,
        &approval,
        &operation,
        TimeWindow {
            earliest: request.earliest,
            latest: request.latest,
        },
        existing,
        staged_body,
        binding,
    )
    .map_err(|_| ())?;
    let output = ResultPlan {
        position: result.next.head.position,
        hash: hex(&result.next.head.hash.0),
        sequence: result.next.sequence,
        append: result.append.map(|c| hex(&c.encode())),
        ack: result.ack.map(|c| hex(&c.encode())),
        stage: result.stage.map(|d| hex(&d.0)),
    };
    let bytes = serde_json::to_vec(&output).map_err(|_| ())?;
    if bytes.len() > MAX_OUTPUT {
        return Err(());
    }
    Ok(bytes)
}

static INPUT: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
static OUTPUT: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
fn input() -> &'static Mutex<Vec<u8>> {
    INPUT.get_or_init(|| Mutex::new(Vec::new()))
}
fn output() -> &'static Mutex<Vec<u8>> {
    OUTPUT.get_or_init(|| Mutex::new(Vec::new()))
}

/// `reserve_input` pins a Rust-owned buffer until `execute` returns. Calls into
/// this ABI must be synchronous and non-reentrant. JS checks actual memory spans.
#[unsafe(no_mangle)]
pub extern "C" fn reserve_input(len: u32) -> u32 {
    if len as usize > MAX_INPUT || len == 0 {
        return 0;
    }
    let Ok(mut bytes) = input().lock() else {
        return 0;
    };
    bytes.resize(len as usize, 0);
    bytes.as_mut_ptr() as u32
}
#[unsafe(no_mangle)]
pub extern "C" fn execute(len: u32) -> u32 {
    let Ok(mut received) = input().lock() else {
        return 1;
    };
    let Ok(mut response) = output().lock() else {
        return 1;
    };
    response.clear();
    if len == 0 || len as usize != received.len() {
        received.fill(0);
        return 1;
    }
    let result = plan(&received);
    received.fill(0);
    if let Ok(bytes) = result {
        *response = bytes;
        0
    } else {
        1
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn result_ptr() -> u32 {
    output().lock().map_or(0, |bytes| bytes.as_ptr() as u32)
}
#[unsafe(no_mangle)]
pub extern "C" fn result_len() -> u32 {
    output().lock().map_or(0, |bytes| bytes.len() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_inputs_refuse_without_panicking() {
        for bytes in [
            b"{}".as_slice(),
            b"{} {}",
            b"\xff",
            b"{\"version\":1,\"version\":1}",
        ] {
            assert!(plan(bytes).is_err());
        }
        assert!(plan(&vec![b' '; MAX_INPUT + 1]).is_err());
    }
}
