//! Pure Worker-side validation/planning over an ordinary DO's transaction snapshot.
//! No account authority, host freshness, channel authentication or trusted clock is
//! established here. The DO adapter supplies persisted rows, never caller rows.
use bh_crypto::{Secret, SigningKey};
use bh_sync::permit::{self, AppendAck, LogId, LogKind, PermitError, Scope};
use bh_sync::wire::{self, Refusal};
use bh_sync::{BODY_SIZES, ENVELOPE_SIZES};
use bh_sync::{
    BaseId, BodyObject, Commitment, Digest, EventId, GateState, Head, OpaqueEvent, Operation,
    OrderState, Route, SignedApproval, TimeWindow, plan_consumption, receipt, referenced_body,
};
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, OnceLock};

const MAX_INPUT: usize = 10 * 1024 * 1024;
const MAX_BODY: usize = BODY_SIZES[BODY_SIZES.len() - 1];
// An encoded event has a 2-byte version, 32-byte ID and 4-byte length.
const MAX_EVENT: usize = 38 + ENVELOPE_SIZES[ENVELOPE_SIZES.len() - 1];
const MAX_OUTPUT: usize = 1024;
/// Largest JSON a log-object helper returns: 64 body commitments in hex.
const MAX_HELPER_OUTPUT: usize = 16 * 1024;
/// JS numbers are exact only up to 2^53 - 1; larger values refuse, never round.
const MAX_SAFE: u64 = (1 << 53) - 1;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Gate {
    base: String,
    order_format: u16,
    order: String,
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
    order: String,
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
    if value.order_format != 2 {
        return Err(());
    }
    let order = OrderState::decode(&unhex::<82>(&value.order)?).map_err(|_| ())?;
    Ok(GateState {
        base: BaseId(unhex(&value.base)?),
        order,
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
    let commitment =
        Commitment::decode(&unhex_bytes(&value.commitment, Commitment::LEN)?).map_err(|_| ())?;
    let event = OpaqueEvent::decode(&unhex_bytes(&value.event, MAX_EVENT)?).map_err(|_| ())?;
    let previous = if value.position == 1 {
        if value.previous.is_some() {
            return Err(());
        }
        Head::EMPTY
    } else {
        let prior = Commitment::decode(&unhex_bytes(
            value.previous.as_ref().ok_or(())?,
            Commitment::LEN,
        )?)
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
        || commitment.event_id() != event.publication_id(commitment.route())
        || commitment.event_digest() != event.digest()
        || unhex::<32>(&value.event_id)? != commitment.event_id().0
        || unhex::<32>(&value.event_digest)? != event.digest().0
        || commitment.verify_next(state.base, previous).is_err()
        || (value.position == 1 && commitment.before() != OrderState::EMPTY)
        || (value.position > 1 && {
            let prior = Commitment::decode(&unhex_bytes(
                value.previous.as_deref().ok_or(())?,
                Commitment::LEN,
            )?)
            .map_err(|_| ())?;
            commitment.before() != prior.after()
        })
        || commitment.verify_body(&event).is_err()
        || (value.position == state.head.position && commitment.after() != state.order)
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
            let bytes = unhex_bytes(body, MAX_BODY)?;
            Ok::<_, ()>(BodyObject::new(bytes).map_err(|_| ())?.commitment())
        })
        .transpose()?;
    let operation = match request.operation {
        RequestOperation::Append { event } => Operation::Append(
            OpaqueEvent::decode(&unhex_bytes(&event, MAX_EVENT)?).map_err(|_| ())?,
        ),
        RequestOperation::Read { objects } => Operation::read(
            objects
                .iter()
                .map(|s| unhex(s).map(Digest))
                .collect::<Result<_, _>>()?,
        )
        .map_err(|_| ())?,
        RequestOperation::Stage { body } => {
            let bytes = unhex_bytes(&body, MAX_BODY)?;
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
                if stored.digest() != event.digest() {
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
                let bytes = unhex_bytes(&record.body, MAX_BODY)?;
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
        order: hex(&result.next.order.encode()),
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

#[derive(Serialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
enum ScopeOut {
    StoreHomeObjects {
        prefix_digest: String,
        bundle_digest: String,
    },
    ReadDirectory,
    StoreDirectoryEntry {
        entry: String,
        version: u64,
        body: String,
        len: u32,
    },
    RetireHomeObjects {
        prefix_digest: String,
    },
    ReadEvents {
        first: u64,
        last: u64,
    },
    ReadBodies {
        bodies: Vec<String>,
    },
    Stage {
        body: String,
        len: u32,
    },
    Append {
        event_id: String,
        digest: String,
        body: Option<String>,
        epoch: String,
        after: Option<HeadOut>,
        /// A second staged body ordered with a control's own.
        attached: Option<String>,
    },
    Subscribe,
    ReadControls {
        after: u64,
    },
    ReadControlRange {
        after: u64,
        through: u64,
    },
    Presence {
        epoch: String,
    },
}
#[derive(Serialize)]
struct HeadOut {
    position: u64,
    hash: String,
}
#[derive(Serialize)]
struct VerifiedPermit {
    /// `kind:u8 || id:32` in hex: the log object's name and R2 key prefix.
    log: String,
    issued_ms: u64,
    deadline_ms: u64,
    #[serde(flatten)]
    scope: ScopeOut,
}
#[derive(Serialize)]
struct Ordered {
    commitment: String,
    order: String,
    position: u64,
    hash: String,
    event_id: String,
    digest: String,
}
#[derive(Serialize)]
struct DecodedRequest {
    kind: &'static str,
    id: u32,
    /// `[offset, length]` into the decoded frame; absent for a credit grant.
    permit: Option<[usize; 2]>,
    payload: Option<[usize; 2]>,
    stage_permit: Option<[usize; 2]>,
    append_permit: Option<[usize; 2]>,
    event: Option<[usize; 2]>,
    body: Option<[usize; 2]>,
    after: Option<u64>,
    cursor: Option<String>,
    credit: Option<u32>,
}

fn safe(value: u64) -> Result<u64, Refusal> {
    if value > MAX_SAFE {
        return Err(Refusal::Malformed);
    }
    Ok(value)
}
fn json<T: Serialize>(value: &T) -> Result<Vec<u8>, Refusal> {
    serde_json::to_vec(value).map_err(|_| Refusal::Unavailable)
}
fn split<const N: usize>(bytes: &[u8]) -> Result<([u8; N], &[u8]), Refusal> {
    let (head, rest) = bytes.split_at_checked(N).ok_or(Refusal::Malformed)?;
    Ok((head.try_into().map_err(|_| Refusal::Malformed)?, rest))
}
fn head_out(head: Head) -> Result<HeadOut, Refusal> {
    Ok(HeadOut {
        position: safe(head.position)?,
        hash: hex(&head.hash.0),
    })
}

/// Input `root:32 || now_ms:u64 || permit_len:u32 || permit || payload`.
/// A stage permit binds the exact body bytes and an append permit the exact
/// event bytes in `payload`; other scopes require an empty payload.
fn verify_permit_at(bytes: &[u8]) -> Result<Vec<u8>, Refusal> {
    let (root, rest) = split::<32>(bytes)?;
    let (now, rest) = split::<8>(rest)?;
    let (len, rest) = split::<4>(rest)?;
    let (signed, payload) = rest
        .split_at_checked(u32::from_be_bytes(len) as usize)
        .ok_or(Refusal::Malformed)?;
    let verified =
        permit::verify(root, signed, u64::from_be_bytes(now)).map_err(|error| match error {
            PermitError::Encoding | PermitError::Version | PermitError::Bounds => {
                Refusal::Malformed
            }
            PermitError::Certificate | PermitError::Signature => Refusal::Scope,
            PermitError::Expired | PermitError::Window => Refusal::Expired,
        })?;
    let (log, scope) = match verified.scope {
        Scope::ReadEvents { log, first, last } if payload.is_empty() => (
            log,
            ScopeOut::ReadEvents {
                first: safe(first)?,
                last: safe(last)?,
            },
        ),
        Scope::ReadBodies { log, bodies } if payload.is_empty() => (
            log,
            ScopeOut::ReadBodies {
                bodies: bodies.iter().map(|d| hex(&d.0)).collect(),
            },
        ),
        Scope::Stage { log, body, len } => {
            if payload.len() != len as usize {
                return Err(Refusal::Scope);
            }
            let object = BodyObject::new(payload.to_vec()).map_err(|_| Refusal::Malformed)?;
            if object.commitment() != body {
                return Err(Refusal::Scope);
            }
            (
                log,
                ScopeOut::Stage {
                    body: hex(&body.0),
                    len,
                },
            )
        }
        Scope::Append {
            log,
            event,
            body,
            epoch,
            after,
            attached,
        } => {
            let decoded = OpaqueEvent::decode(payload).map_err(|_| Refusal::Malformed)?;
            if decoded.digest() != event {
                return Err(Refusal::Scope);
            }
            if let Some(body) = body
                && referenced_body(&decoded).map_err(|_| Refusal::Malformed)? != body
            {
                return Err(Refusal::Scope);
            }
            (
                log,
                ScopeOut::Append {
                    event_id: hex(&decoded
                        .publication_id(if after.is_some() {
                            Route::Control
                        } else {
                            Route::Content
                        })
                        .0),
                    digest: hex(&event.0),
                    body: body.map(|d| hex(&d.0)),
                    epoch: hex(&epoch),
                    after: after.map(head_out).transpose()?,
                    attached: attached.map(|d| hex(&d.0)),
                },
            )
        }
        Scope::StoreHomeObjects {
            log,
            prefix_digest,
            bundle_digest,
        } => {
            let digest = bh_sync::home_objects::digest(payload).map_err(|_| Refusal::Malformed)?;
            if digest != bundle_digest {
                return Err(Refusal::Scope);
            }
            (
                log,
                ScopeOut::StoreHomeObjects {
                    prefix_digest: hex(&prefix_digest.0),
                    bundle_digest: hex(&bundle_digest.0),
                },
            )
        }
        Scope::ReadDirectory { log } if payload.is_empty() => (log, ScopeOut::ReadDirectory),
        Scope::StoreDirectoryEntry {
            log,
            entry,
            version,
            body,
            len,
        } => {
            if payload.len() != len as usize || payload.is_empty() || payload.len() > 65536 {
                return Err(Refusal::Malformed);
            }
            if bh_crypto::hash(payload) != body.0 {
                return Err(Refusal::Scope);
            }
            (
                log,
                ScopeOut::StoreDirectoryEntry {
                    entry: hex(&entry),
                    version: safe(version)?,
                    body: hex(&body.0),
                    len,
                },
            )
        }
        Scope::RetireHomeObjects { log, prefix_digest } if payload.is_empty() => (
            log,
            ScopeOut::RetireHomeObjects {
                prefix_digest: hex(&prefix_digest.0),
            },
        ),
        Scope::Subscribe { log } if payload.is_empty() => (log, ScopeOut::Subscribe),
        Scope::ReadControls { log, after } if payload.is_empty() => (
            log,
            ScopeOut::ReadControls {
                after: safe(after)?,
            },
        ),
        Scope::ReadControlRange {
            log,
            after,
            through,
        } if payload.is_empty() => (
            log,
            ScopeOut::ReadControlRange {
                after: safe(after)?,
                through: safe(through)?,
            },
        ),
        Scope::Presence { log, epoch } if payload.is_empty() => {
            (log, ScopeOut::Presence { epoch: hex(&epoch) })
        }
        _ => return Err(Refusal::Malformed),
    };
    let mut name = vec![log.kind as u8];
    name.extend(log.id);
    json(&VerifiedPermit {
        log: hex(&name),
        issued_ms: safe(verified.issued_ms)?,
        deadline_ms: safe(verified.deadline_ms)?,
        scope,
    })
}

/// Input `log_id:32 || before:82 || route:u8 || event`, with route 0 for
/// content and 1 for a control. The first event of a
/// log must be the genesis its id names, on the control route.
fn order_commitment_at(bytes: &[u8]) -> Result<Vec<u8>, Refusal> {
    let (log, rest) = split::<32>(bytes)?;
    let (opening, rest) = split::<82>(rest)?;
    let before = OrderState::decode(&opening).map_err(|_| Refusal::Malformed)?;
    let (route, rest) = split::<1>(rest)?;
    let route = match route {
        [0] => Route::Content,
        [1] => Route::Control,
        _ => return Err(Refusal::Malformed),
    };
    let event = OpaqueEvent::decode(rest).map_err(|_| Refusal::Malformed)?;
    let commitment =
        Commitment::order(BaseId(log), before, &event, route).map_err(|error| match error {
            bh_sync::Error::GenesisMismatch => Refusal::Scope,
            _ => Refusal::Unavailable,
        })?;
    json(&Ordered {
        commitment: hex(&commitment.encode()),
        order: hex(&commitment.after().encode()),
        position: safe(commitment.head().position).map_err(|_| Refusal::Unavailable)?,
        hash: hex(&commitment.head().hash.0),
        event_id: hex(&commitment.event_id().0),
        digest: hex(&event.digest().0),
    })
}

/// Derive an append lookup identity from exact original bytes and its named
/// log; retrying genesis after content still has the control route.
fn routed_id_at(bytes: &[u8]) -> Result<Vec<u8>, Refusal> {
    let (base, event) = split::<32>(bytes)?;
    let event = OpaqueEvent::decode(event).map_err(|_| Refusal::Malformed)?;
    let route = if event.digest().0 == base {
        Route::Control
    } else {
        Route::Content
    };
    json(&serde_json::json!({ "event_id": hex(&event.publication_id(route).0) }))
}

/// Body-free verified state of a retained immutable commitment. Used by
/// endpoint reads and lost-Ack retries, never as an author acceptance proof.
/// Input `base:32 || commitment:149`.
fn commitment_state_at(bytes: &[u8]) -> Result<Vec<u8>, Refusal> {
    let (base, record) = split::<32>(bytes)?;
    let commitment = Commitment::decode(record).map_err(|_| Refusal::Unavailable)?;
    if commitment.base() != BaseId(base) {
        return Err(Refusal::Unavailable);
    }
    let head = commitment.head();
    json(&Ordered {
        commitment: hex(record),
        order: hex(&commitment.after().encode()),
        position: safe(head.position).map_err(|_| Refusal::Unavailable)?,
        hash: hex(&head.hash.0),
        event_id: hex(&commitment.event_id().0),
        digest: hex(&commitment.event_digest().0),
    })
}

/// Input `base:32 || stored_commitment:149 || stored_descriptor`.
/// Decode the immutable tail returned by a durable read, checking its base,
/// self-consistency and exact descriptor commitment before signing its head.
/// This proves ordering bytes only, never the encrypted author's authority.
fn read_tail_at(bytes: &[u8]) -> Result<Vec<u8>, Refusal> {
    checked_tail_at(bytes, None)
}
/// Publication proofs must bind a content-route commitment, never a control.
fn publish_tail_at(bytes: &[u8]) -> Result<Vec<u8>, Refusal> {
    checked_tail_at(bytes, Some(Route::Content))
}
fn checked_tail_at(bytes: &[u8], route: Option<Route>) -> Result<Vec<u8>, Refusal> {
    let (base, rest) = split::<32>(bytes)?;
    let (stored, descriptor) = rest
        .split_at_checked(Commitment::LEN)
        .ok_or(Refusal::Unavailable)?;
    let ordered = Commitment::decode(stored).map_err(|_| Refusal::Unavailable)?;
    let descriptor = OpaqueEvent::decode(descriptor).map_err(|_| Refusal::Unavailable)?;
    if route.is_some_and(|route| ordered.route() != route) {
        return Err(Refusal::Unavailable);
    }
    let head = ordered
        .verify_next(BaseId(base), ordered.previous())
        .map_err(|_| Refusal::Unavailable)?;
    ordered
        .verify_body(&descriptor)
        .map_err(|_| Refusal::Unavailable)?;
    json(&head_out(head)?)
}

#[derive(Serialize)]
struct SignedHead {
    receipt: Option<String>,
    ack: Option<String>,
}

/// Input `root:32 || receipt_seed:32 || receipt_certificate:130 || log:33 ||
/// position:u64 || hash:32 || optional event_id:32`. The caller passes only a
/// log object's durable head. A base log's head gets an observed-head receipt
/// from the configured key, whose certificate must verify under the pinned
/// root; an account-home log gets none. With an event id, also returns the
/// encoded append Ack carrying that receipt.
fn sign_head_at(bytes: &[u8]) -> Result<Vec<u8>, Refusal> {
    let (root, rest) = split::<32>(bytes)?;
    // The seed is copied only into the wiped `Secret`.
    let (seed, rest) = rest.split_at_checked(32).ok_or(Refusal::Malformed)?;
    let (certificate, rest) = rest
        .split_at_checked(receipt::CERTIFICATE_LEN)
        .ok_or(Refusal::Malformed)?;
    let (log, rest) = split::<33>(rest)?;
    let (position, rest) = split::<8>(rest)?;
    let (hash, rest) = split::<32>(rest)?;
    let event = match rest.len() {
        0 => None,
        32 => Some(EventId(rest.try_into().map_err(|_| Refusal::Malformed)?)),
        _ => return Err(Refusal::Malformed),
    };
    let kind = match log[0] {
        1 => LogKind::Base,
        2 => LogKind::Account,
        _ => return Err(Refusal::Malformed),
    };
    let id: [u8; 32] = log[1..].try_into().map_err(|_| Refusal::Malformed)?;
    let head = Head {
        position: safe(u64::from_be_bytes(position))?,
        hash: Digest(hash),
    };
    // A misconfigured key or certificate is the service's fault, not the caller's.
    let certificate =
        receipt::verify_certificate(&root, certificate).map_err(|_| Refusal::Unavailable)?;
    let signer = SigningKey::from_seed(&Secret::from_slice(seed).map_err(|_| Refusal::Malformed)?);
    let receipt = match kind {
        LogKind::Base => Some(
            receipt::sign(&certificate, &signer, BaseId(id), head)
                .map_err(|_| Refusal::Unavailable)?,
        ),
        LogKind::Account => None,
    };
    let ack = event.map(|event| {
        AppendAck {
            log: LogId { kind, id },
            event,
            head,
            receipt,
        }
        .encode()
    });
    json(&SignedHead {
        receipt: receipt.map(|r| hex(&r)),
        ack: ack.map(|a| hex(&a)),
    })
}

/// Input one data-wire request frame. Returns its fields with byte ranges into
/// that same frame, so the caller slices exactly what the strict decoder read.
fn decode_request_at(bytes: &[u8]) -> Result<Vec<u8>, Refusal> {
    const PERMIT_AT: usize = 2 + 1 + 4 + 4;
    let request = wire::Request::decode(bytes).map_err(|_| Refusal::Malformed)?;
    if let wire::Request::Publish {
        id,
        stage_permit,
        append_permit,
        event,
        body,
    } = &request
    {
        let mut at = 7;
        let mut next = |len: usize| {
            at += 4;
            let result = [at, len];
            at += len;
            result
        };
        let fields = [stage_permit, append_permit, event, body].map(|part| next(part.len()));
        return json(&DecodedRequest {
            kind: "publish",
            id: *id,
            permit: None,
            payload: None,
            stage_permit: Some(fields[0]),
            append_permit: Some(fields[1]),
            event: Some(fields[2]),
            body: Some(fields[3]),
            after: None,
            cursor: None,
            credit: None,
        });
    }
    let (kind, id, permit, payload, after) = match &request {
        wire::Request::Read { id, permit } => ("read", *id, permit, None, None),
        wire::Request::ReadDirectory {
            id,
            permit,
            after: _,
        } => ("read_directory", *id, permit, None, None),
        wire::Request::StoreDirectoryEntry { id, permit, body } => {
            ("store_directory_entry", *id, permit, Some(body), None)
        }
        wire::Request::RetireHomeObjects { id, permit } => {
            ("retire_home_objects", *id, permit, None, None)
        }
        wire::Request::StoreHomeObjects { id, permit, bundle } => {
            ("store_home_objects", *id, permit, Some(bundle), None)
        }
        wire::Request::Stage { id, permit, body } => ("stage", *id, permit, Some(body), None),
        wire::Request::Append { id, permit, event } => ("append", *id, permit, Some(event), None),
        wire::Request::Subscribe { id, permit, after } => {
            ("subscribe", *id, permit, None, Some(safe(*after)?))
        }
        wire::Request::Publish { .. } => unreachable!("handled above"),
        wire::Request::PresenceJoin { id, permit } => ("presence_join", *id, permit, None, None),
        // Fire and forget under the join's id: no permit of its own. The
        // sealed bytes are opaque to the Worker.
        wire::Request::Presence { id, sealed } => {
            return json(&DecodedRequest {
                kind: "presence",
                id: *id,
                permit: None,
                payload: Some([PERMIT_AT, sealed.len()]),
                stage_permit: None,
                append_permit: None,
                event: None,
                body: None,
                after: None,
                cursor: None,
                credit: None,
            });
        }
        wire::Request::Credit { bytes } => {
            return json(&DecodedRequest {
                kind: "credit",
                id: 0,
                permit: None,
                payload: None,
                stage_permit: None,
                append_permit: None,
                event: None,
                body: None,
                after: None,
                cursor: None,
                credit: Some(*bytes),
            });
        }
    };
    json(&DecodedRequest {
        kind,
        id,
        permit: Some([PERMIT_AT, permit.len()]),
        payload: payload.map(|p| [PERMIT_AT + permit.len() + 4, p.len()]),
        stage_permit: None,
        append_permit: None,
        event: None,
        body: None,
        after,
        cursor: match &request {
            wire::Request::ReadDirectory { after, .. } => after.map(|entry| hex(&entry)),
            _ => None,
        },
        credit: None,
    })
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
/// Run a log-object helper over the reserved input. Returns 0 with JSON in the
/// result buffer, or a data-wire refusal code (1-10) with an empty result.
fn helper(run: fn(&[u8]) -> Result<Vec<u8>, Refusal>, len: u32) -> u32 {
    let Ok(mut received) = input().lock() else {
        return Refusal::Unavailable as u32;
    };
    let Ok(mut response) = output().lock() else {
        return Refusal::Unavailable as u32;
    };
    response.clear();
    if len == 0 || len as usize != received.len() {
        received.fill(0);
        return Refusal::Malformed as u32;
    }
    let result = run(&received);
    received.fill(0);
    match result {
        Ok(bytes) if bytes.len() <= MAX_HELPER_OUTPUT => {
            *response = bytes;
            0
        }
        Ok(_) => Refusal::Unavailable as u32,
        Err(refusal) => refusal as u32,
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn verify_permit(len: u32) -> u32 {
    helper(verify_permit_at, len)
}
#[unsafe(no_mangle)]
pub extern "C" fn order_commitment(len: u32) -> u32 {
    helper(order_commitment_at, len)
}
#[unsafe(no_mangle)]
pub extern "C" fn commitment_state(len: u32) -> u32 {
    helper(commitment_state_at, len)
}
#[unsafe(no_mangle)]
pub extern "C" fn routed_id(len: u32) -> u32 {
    helper(routed_id_at, len)
}
#[unsafe(no_mangle)]
pub extern "C" fn decode_request(len: u32) -> u32 {
    helper(decode_request_at, len)
}
#[unsafe(no_mangle)]
pub extern "C" fn read_tail(len: u32) -> u32 {
    helper(read_tail_at, len)
}
#[unsafe(no_mangle)]
pub extern "C" fn publish_tail(len: u32) -> u32 {
    helper(publish_tail_at, len)
}
#[unsafe(no_mangle)]
pub extern "C" fn sign_head(len: u32) -> u32 {
    helper(sign_head_at, len)
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
    fn plan_stages_appends_and_reads_a_one_mib_body() {
        use bh_sync::{Approval, SignedApproval};
        let signer = key(42);
        let body = BodyObject::new(vec![0xb4; 1024 * 1024]).unwrap();
        let mut envelope = body.commitment().0.to_vec();
        envelope.resize(1024, 0);
        let event = OpaqueEvent::new(EventId([3; 32]), envelope).unwrap();
        let operation = Operation::stage_body(body.clone());
        let gate = GateState {
            base: BaseId(event.digest().0),
            order: OrderState::EMPTY,
            head: Head::EMPTY,
            incarnation: [5; 32],
            sequence: 0,
            checker_key: signer.public(),
        };
        let approval = Approval {
            base: gate.base,
            expected_head: gate.head,
            incarnation: gate.incarnation,
            sequence: 1,
            nonce: [1; 32],
            operation: operation.digest(),
            response_binding: Digest([7; 32]),
            not_before: 10,
            expires: 20,
        };
        let signed = SignedApproval {
            approval,
            signature: signer.sign(&approval.signing_bytes()),
        };
        let request = serde_json::json!({
            "version": 1,
            "gate": { "base": hex(&gate.base.0), "position": 0,
                "order_format": 2, "order": hex(&gate.order.encode()),
                "hash": hex(&gate.head.hash.0), "incarnation": hex(&gate.incarnation),
                "sequence": 0, "checker_key": hex(&gate.checker_key) },
            "approval": hex(&signed.encode()),
            "operation": { "kind": "stage", "body": hex(body.bytes()) },
            "binding": hex(&[7; 32]), "earliest": 10, "latest": 11,
            "head": null, "selected": []
        });
        let result = parsed(plan(&serde_json::to_vec(&request).unwrap()).unwrap());
        assert_eq!(result["stage"], hex(&body.commitment().0));

        let mut request = request;
        let sign = |operation: Operation, sequence| {
            let approval = Approval {
                operation: operation.digest(),
                sequence,
                nonce: [sequence as u8; 32],
                ..approval
            };
            hex(&SignedApproval {
                approval,
                signature: signer.sign(&approval.signing_bytes()),
            }
            .encode())
        };
        let read = Operation::read_bodies(vec![body.commitment()]).unwrap();
        request["approval"] = sign(read, 1).into();
        request["operation"] =
            serde_json::json!({"kind":"readbodies", "objects":[hex(&body.commitment().0)]});
        request["bodies"] = serde_json::json!([{
            "commitment":hex(&body.commitment().0), "body":hex(body.bytes())
        }]);
        assert!(plan(&serde_json::to_vec(&request).unwrap()).is_ok());

        request["approval"] = sign(Operation::Append(event.clone()), 1).into();
        request["operation"] = serde_json::json!({"kind":"append", "event":hex(&event.encode())});
        request["bodies"] = serde_json::json!([]);
        request["staged_body"] = hex(body.bytes()).into();
        let result = parsed(plan(&serde_json::to_vec(&request).unwrap()).unwrap());
        assert!(result["append"].as_str().is_some());
    }

    #[test]
    fn envelope_over_64_kib_remains_refused() {
        let mut event = vec![0u8; 38 + 65537];
        event[..2].copy_from_slice(&1u16.to_be_bytes());
        event[34..38].copy_from_slice(&65537u32.to_be_bytes());
        assert!(unhex_bytes(&hex(&event), MAX_EVENT).is_err());
        let mut input = vec![0; 32 + 82 + 1];
        input.extend(event);
        assert_eq!(order_commitment_at(&input), Err(Refusal::Malformed));
    }

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

    use bh_sync::permit::Permit;

    const NOW: u64 = 1_000_000;
    fn key(seed: u8) -> SigningKey {
        SigningKey::from_seed(&Secret::from_slice(&[seed; 32]).unwrap())
    }
    fn signed(root: &SigningKey, scope: Scope, issued_ms: u64) -> Vec<u8> {
        let signer = key(9);
        let certificate = permit::certify(root, signer.public());
        let permit = Permit {
            scope,
            issued_ms,
            deadline_ms: issued_ms + 30_000,
            batch: [1; 16],
        };
        permit::sign(&signer, &certificate, &permit)
    }
    fn verify_input(root: [u8; 32], now: u64, permit: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut input = root.to_vec();
        input.extend(now.to_be_bytes());
        input.extend((permit.len() as u32).to_be_bytes());
        input.extend(permit);
        input.extend(payload);
        input
    }
    fn parsed(bytes: Vec<u8>) -> serde_json::Value {
        serde_json::from_slice(&bytes).unwrap()
    }

    // Replaces the formats task's refusal of presence permits: the edge now
    // serves presence joins, so a valid permit verifies to its base and epoch.
    #[test]
    fn presence_permit_verifies_to_its_base_log_and_epoch() {
        let root = key(1);
        let log = LogId {
            kind: LogKind::Base,
            id: [5; 32],
        };
        let permit = signed(
            &root,
            Scope::Presence {
                log,
                epoch: [6; 32],
            },
            NOW,
        );
        let check = |p: &[u8], payload: &[u8], now| {
            verify_permit_at(&verify_input(root.public(), now, p, payload))
        };
        let value = parsed(check(&permit, &[], NOW).unwrap());
        assert_eq!(value["scope"], "presence");
        assert_eq!(value["log"], format!("01{}", "05".repeat(32)));
        assert_eq!(value["epoch"], "06".repeat(32));
        assert_eq!(value["deadline_ms"], NOW + 30_000);
        // A presence permit binds no payload, and has the usual window.
        assert_eq!(check(&permit, &[1], NOW), Err(Refusal::Malformed));
        assert_eq!(check(&permit, &[], NOW + 30_000), Err(Refusal::Expired));
        let mut forged = permit.clone();
        forged[40] ^= 1;
        assert_eq!(check(&forged, &[], NOW), Err(Refusal::Scope));
        // Under another root it is not ours.
        let stranger = signed(
            &key(2),
            Scope::Presence {
                log,
                epoch: [6; 32],
            },
            NOW,
        );
        assert_eq!(check(&stranger, &[], NOW), Err(Refusal::Scope));
        // A subscribe permit stays a subscribe permit: the edge refuses it for a join.
        let subscribe = signed(&root, Scope::Subscribe { log }, NOW);
        assert_eq!(
            parsed(check(&subscribe, &[], NOW).unwrap())["scope"],
            "subscribe"
        );
        // Presence is only ever for a base log.
        let account = LogId {
            kind: LogKind::Account,
            id: [5; 32],
        };
        let account = signed(
            &root,
            Scope::Presence {
                log: account,
                epoch: [6; 32],
            },
            NOW,
        );
        assert_eq!(check(&account, &[], NOW), Err(Refusal::Malformed));
    }

    #[test]
    fn bounded_control_scope_verifies_for_worker() {
        let root = key(1);
        let log = LogId {
            kind: LogKind::Base,
            id: [5; 32],
        };
        let signed = signed(
            &root,
            Scope::ReadControlRange {
                log,
                after: 2,
                through: MAX_SAFE,
            },
            NOW,
        );
        let result =
            parsed(verify_permit_at(&verify_input(root.public(), NOW, &signed, &[])).unwrap());
        assert_eq!(result["scope"], "read_control_range");
        assert_eq!(result["after"], 2);
        assert_eq!(result["through"], MAX_SAFE);
        assert_eq!(result["log"], format!("01{}", "05".repeat(32)));
        assert_eq!(
            verify_permit_at(&verify_input(root.public(), NOW, &signed, &[0])),
            Err(Refusal::Malformed)
        );
    }

    #[test]
    fn home_objects_verify_exact_bundle_account_scope_prefix_and_deadline() {
        use bh_sync::home_objects;
        let root = key(1);
        let bundle = home_objects::encode(&[1; 242], &[2; 1299], &[3; 1299]).unwrap();
        let log = LogId {
            kind: LogKind::Account,
            id: [5; 32],
        };
        let scope = Scope::StoreHomeObjects {
            log,
            prefix_digest: Digest([6; 32]),
            bundle_digest: home_objects::digest(&bundle).unwrap(),
        };
        let permit = signed(&root, scope, NOW);
        let check = |p: &[u8], body: &[u8], now| {
            verify_permit_at(&verify_input(root.public(), now, p, body))
        };
        let value = parsed(check(&permit, &bundle, NOW).unwrap());
        assert_eq!(value["scope"], "store_home_objects");
        assert_eq!(value["log"], format!("02{}", "05".repeat(32)));
        assert_eq!(value["prefix_digest"], "06".repeat(32));
        assert_eq!(
            value["bundle_digest"],
            hex(&home_objects::digest(&bundle).unwrap().0)
        );
        let mut different = bundle.clone();
        different[100] ^= 1;
        assert_eq!(check(&permit, &different, NOW), Err(Refusal::Scope));
        assert_eq!(
            check(&permit, &bundle[..bundle.len() - 1], NOW),
            Err(Refusal::Malformed)
        );
        assert_eq!(check(&permit, &bundle, NOW + 30000), Err(Refusal::Expired));
        let mut forged = permit.clone();
        forged[170] ^= 1;
        assert_eq!(check(&forged, &bundle, NOW), Err(Refusal::Scope));
        let frame = wire::Request::StoreHomeObjects {
            id: 17,
            permit,
            bundle: bundle.clone(),
        }
        .encode()
        .unwrap();
        let request = parsed(decode_request_at(&frame).unwrap());
        assert_eq!(request["kind"], "store_home_objects");
        assert_eq!(request["id"], 17);
        assert_eq!(request["payload"][1], bundle.len());
    }

    #[test]
    fn verify_permit_binds_root_time_and_exact_payload() {
        let root = key(1);
        let log = LogId {
            kind: LogKind::Base,
            id: [5; 32],
        };
        let body = BodyObject::new(vec![3; 1024]).unwrap();
        let stage = signed(
            &root,
            Scope::Stage {
                log,
                body: body.commitment(),
                len: 1024,
            },
            NOW,
        );
        let ok = parsed(
            verify_permit_at(&verify_input(root.public(), NOW, &stage, body.bytes())).unwrap(),
        );
        assert_eq!(ok["scope"], "stage");
        assert_eq!(ok["log"], format!("01{}", "05".repeat(32)));
        assert_eq!(ok["deadline_ms"], NOW + 30_000);
        let check = |root: [u8; 32], now: u64, permit: &[u8], payload: &[u8]| {
            verify_permit_at(&verify_input(root, now, permit, payload)).err()
        };
        assert_eq!(
            check(key(2).public(), NOW, &stage, body.bytes()),
            Some(Refusal::Scope)
        );
        assert_eq!(
            check(root.public(), NOW + 30_000, &stage, body.bytes()),
            Some(Refusal::Expired)
        );
        assert_eq!(
            check(root.public(), NOW - 1, &stage, body.bytes()),
            Some(Refusal::Expired)
        );
        assert_eq!(
            check(root.public(), NOW, &stage, &[4; 1024]),
            Some(Refusal::Scope)
        );
        assert_eq!(
            check(root.public(), NOW, &stage, &[3; 1000]),
            Some(Refusal::Scope)
        );
        let mut forged = stage.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(
            check(root.public(), NOW, &forged, body.bytes()),
            Some(Refusal::Scope)
        );

        let mut envelope = body.commitment().0.to_vec();
        envelope.extend([7; 1024 - 32]);
        let event = OpaqueEvent::new(EventId([8; 32]), envelope).unwrap();
        let append = signed(
            &root,
            Scope::Append {
                log,
                event: event.digest(),
                body: Some(body.commitment()),
                epoch: [6; 32],
                after: Some(Head::EMPTY),
                attached: None,
            },
            NOW,
        );
        let ok = parsed(
            verify_permit_at(&verify_input(root.public(), NOW, &append, &event.encode())).unwrap(),
        );
        assert_eq!(ok["event_id"], hex(&event.publication_id(Route::Control).0));
        assert_eq!(ok["body"], hex(&body.commitment().0));
        assert_eq!(ok["after"]["position"], 0);
        let other = OpaqueEvent::new(EventId([8; 32]), vec![7; 1024]).unwrap();
        assert_eq!(
            check(root.public(), NOW, &append, &other.encode()),
            Some(Refusal::Scope)
        );
        assert_eq!(
            check(root.public(), NOW, &append, &[1, 2]),
            Some(Refusal::Malformed)
        );
        let read = signed(
            &root,
            Scope::ReadEvents {
                log,
                first: 1,
                last: 64,
            },
            NOW,
        );
        assert!(check(root.public(), NOW, &read, &[]).is_none());
        assert_eq!(
            check(root.public(), NOW, &read, &[0]),
            Some(Refusal::Malformed)
        );
        let controls = signed(&root, Scope::ReadControls { log, after: 3 }, NOW);
        let ok =
            parsed(verify_permit_at(&verify_input(root.public(), NOW, &controls, &[])).unwrap());
        assert_eq!(ok["scope"], "read_controls");
        assert_eq!(ok["after"], 3);
        assert_eq!(ok["log"], format!("01{}", "05".repeat(32)));
        assert_eq!(
            check(root.public(), NOW, &controls, &[0]),
            Some(Refusal::Malformed)
        );
        let empty = signed(&root, Scope::ReadControls { log, after: 0 }, NOW);
        let ok = parsed(verify_permit_at(&verify_input(root.public(), NOW, &empty, &[])).unwrap());
        assert_eq!(ok["scope"], "read_controls");
        assert_eq!(ok["after"], 0);
        let far = signed(
            &root,
            Scope::ReadControls {
                log,
                after: MAX_SAFE + 1,
            },
            NOW,
        );
        assert_eq!(
            check(root.public(), NOW, &far, &[]),
            Some(Refusal::Malformed)
        );
        assert_eq!(
            check(root.public(), NOW, &[0; 10], &[]),
            Some(Refusal::Malformed)
        );
    }

    #[test]
    fn read_tail_uses_stored_commitment_and_refuses_other_log_or_bytes() {
        let genesis = OpaqueEvent::new(EventId([1; 32]), vec![2; 1024]).unwrap();
        let base = BaseId(genesis.digest().0);
        let ordered = Commitment::order(base, OrderState::EMPTY, &genesis, Route::Control).unwrap();
        let mut input = base.0.to_vec();
        input.extend(ordered.encode());
        input.extend(genesis.encode());
        let out = parsed(read_tail_at(&input).unwrap());
        assert_eq!(out["position"], 1);
        assert_eq!(out["hash"], hex(&ordered.head().hash.0));
        let mut wrong = input.clone();
        wrong[0] ^= 1;
        assert_eq!(read_tail_at(&wrong).err(), Some(Refusal::Unavailable));
        let mut changed = input.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(read_tail_at(&changed).err(), Some(Refusal::Unavailable));
        let mut forged = input.clone();
        forged[32 + Commitment::LEN - 1] ^= 1;
        assert_eq!(read_tail_at(&forged).err(), Some(Refusal::Unavailable));
        assert_eq!(
            read_tail_at(&input[..32 + Commitment::LEN]).err(),
            Some(Refusal::Unavailable)
        );
        input.push(0);
        assert_eq!(read_tail_at(&input).err(), Some(Refusal::Unavailable));
    }

    #[test]
    fn publish_tail_refuses_control_commitment_and_changed_descriptor() {
        let genesis = OpaqueEvent::new(EventId([1; 32]), vec![2; 1024]).unwrap();
        let base = BaseId(genesis.digest().0);
        let control = Commitment::order(base, OrderState::EMPTY, &genesis, Route::Control).unwrap();
        let content = OpaqueEvent::new(EventId([2; 32]), vec![3; 1024]).unwrap();
        let ordered = Commitment::order(base, control.after(), &content, Route::Content).unwrap();
        let mut input = base.0.to_vec();
        input.extend(ordered.encode());
        input.extend(content.encode());
        assert_eq!(
            parsed(publish_tail_at(&input).unwrap())["hash"],
            hex(&ordered.head().hash.0)
        );
        let mut wrong = base.0.to_vec();
        wrong.extend(control.encode());
        wrong.extend(genesis.encode());
        assert_eq!(publish_tail_at(&wrong), Err(Refusal::Unavailable));
        input.push(0);
        assert_eq!(publish_tail_at(&input), Err(Refusal::Unavailable));
    }

    fn sign_input(
        root: [u8; 32],
        seed: u8,
        certificate: &[u8],
        log: &[u8],
        event: Option<[u8; 32]>,
    ) -> Vec<u8> {
        let mut input = root.to_vec();
        input.extend([seed; 32]);
        input.extend(certificate);
        input.extend(log);
        input.extend(7u64.to_be_bytes());
        input.extend([4; 32]);
        input.extend(event.into_iter().flatten());
        input
    }

    #[test]
    fn sign_head_signs_base_receipts_and_acks_under_the_pinned_root() {
        use bh_sync::permit::AppendAck;
        let root = key(1);
        let certificate = receipt::certify(&root, key(3).public());
        let head = Head {
            position: 7,
            hash: Digest([4; 32]),
        };
        let mut base = vec![1];
        base.extend([5; 32]);
        let out = parsed(
            sign_head_at(&sign_input(
                root.public(),
                3,
                &certificate,
                &base,
                Some([8; 32]),
            ))
            .unwrap(),
        );
        let signed = unhex_bytes(out["receipt"].as_str().unwrap(), 300).unwrap();
        let verified = receipt::verify(&root.public(), BaseId([5; 32]), &signed).unwrap();
        assert_eq!(verified.head(), head);
        let ack =
            AppendAck::decode(&unhex_bytes(out["ack"].as_str().unwrap(), 1024).unwrap()).unwrap();
        assert_eq!(
            (ack.log.kind, ack.log.id, ack.event, ack.head),
            (LogKind::Base, [5; 32], EventId([8; 32]), head)
        );
        assert_eq!(ack.receipt.unwrap()[..], signed[..]);
        // A head notice has no event and so no Ack.
        let notice =
            parsed(sign_head_at(&sign_input(root.public(), 3, &certificate, &base, None)).unwrap());
        assert!(notice["ack"].is_null());
        assert_eq!(notice["receipt"], out["receipt"]);

        // An account-home log gets no receipt.
        let mut account = vec![2];
        account.extend([5; 32]);
        let out = parsed(
            sign_head_at(&sign_input(
                root.public(),
                3,
                &certificate,
                &account,
                Some([8; 32]),
            ))
            .unwrap(),
        );
        assert!(out["receipt"].is_null());
        let ack =
            AppendAck::decode(&unhex_bytes(out["ack"].as_str().unwrap(), 1024).unwrap()).unwrap();
        assert_eq!((ack.log.kind, ack.receipt), (LogKind::Account, None));

        let check = |root: [u8; 32], seed: u8, certificate: &[u8], log: &[u8], extra: &[u8]| {
            let mut input = sign_input(root, seed, certificate, log, None);
            input.extend(extra);
            sign_head_at(&input).err()
        };
        // A certificate from another root, or a key it does not certify.
        assert_eq!(
            check(key(2).public(), 3, &certificate, &base, &[]),
            Some(Refusal::Unavailable)
        );
        assert_eq!(
            check(root.public(), 4, &certificate, &base, &[]),
            Some(Refusal::Unavailable)
        );
        let mut unknown = base.clone();
        unknown[0] = 3;
        assert_eq!(
            check(root.public(), 3, &certificate, &unknown, &[]),
            Some(Refusal::Malformed)
        );
        assert_eq!(
            check(root.public(), 3, &certificate, &base, &[0]),
            Some(Refusal::Malformed)
        );
        assert_eq!(sign_head_at(&[0; 40]).err(), Some(Refusal::Malformed));
    }

    fn order_input(log: [u8; 32], before: OrderState, route: u8, event: &OpaqueEvent) -> Vec<u8> {
        let mut input = log.to_vec();
        input.extend(before.encode());
        input.push(route);
        input.extend(event.encode());
        input
    }

    #[test]
    fn event_routing_uses_genesis_digest_even_after_content() {
        let genesis = OpaqueEvent::new(EventId([1; 32]), vec![2; 1024]).unwrap();
        let base = BaseId::from_genesis(&genesis);
        let content = OpaqueEvent::new(EventId([1; 32]), vec![3; 1024]).unwrap();
        let input = |event: &OpaqueEvent| [base.0.as_slice(), &event.encode()].concat();
        assert_eq!(
            parsed(routed_id_at(&input(&genesis)).unwrap())["event_id"],
            hex(&genesis.publication_id(Route::Control).0)
        );
        assert_eq!(
            parsed(routed_id_at(&input(&content)).unwrap())["event_id"],
            hex(&content.publication_id(Route::Content).0)
        );
    }

    #[test]
    fn body_free_commitment_state_derives_opening_head_and_routed_identity() {
        let event = OpaqueEvent::new(EventId([1; 32]), vec![2; 1024]).unwrap();
        let base = BaseId::from_genesis(&event);
        let commitment =
            Commitment::order(base, bh_sync::OrderState::EMPTY, &event, Route::Control).unwrap();
        let mut input = base.0.to_vec();
        input.extend(commitment.encode());
        let state = parsed(commitment_state_at(&input).unwrap());
        assert_eq!(state["order"], hex(&commitment.after().encode()));
        assert_eq!(state["position"], 1);
        assert_eq!(state["hash"], hex(&commitment.head().hash.0));
        assert_eq!(
            state["event_id"],
            hex(&event.publication_id(Route::Control).0)
        );
        let mut wrong = input;
        wrong[0] ^= 1;
        assert_eq!(commitment_state_at(&wrong), Err(Refusal::Unavailable));
    }

    #[test]
    fn order_commitment_requires_the_named_genesis() {
        let genesis = OpaqueEvent::new(EventId([1; 32]), vec![2; 1024]).unwrap();
        let base = BaseId(genesis.digest().0);
        let ok = parsed(
            order_commitment_at(&order_input(base.0, OrderState::EMPTY, 1, &genesis)).unwrap(),
        );
        let expected =
            Commitment::order(base, OrderState::EMPTY, &genesis, Route::Control).unwrap();
        assert_eq!(ok["commitment"], hex(&expected.encode()));
        assert_eq!(ok["position"], 1);
        assert_eq!(
            order_commitment_at(&order_input([9; 32], OrderState::EMPTY, 1, &genesis)).err(),
            Some(Refusal::Scope)
        );
        // A genesis is always a control.
        assert_eq!(
            order_commitment_at(&order_input(base.0, OrderState::EMPTY, 0, &genesis)).err(),
            Some(Refusal::Scope)
        );
        assert_eq!(
            order_commitment_at(&[0; 115]).err(),
            Some(Refusal::Malformed)
        );
    }

    #[test]
    fn order_commitment_commits_the_route() {
        let genesis = OpaqueEvent::new(EventId([1; 32]), vec![2; 1024]).unwrap();
        let base = BaseId(genesis.digest().0);
        let before = Commitment::order(base, OrderState::EMPTY, &genesis, Route::Control)
            .unwrap()
            .after();
        let next = OpaqueEvent::new(EventId([3; 32]), vec![4; 1024]).unwrap();
        for (byte, route) in [(0, Route::Content), (1, Route::Control)] {
            let ok =
                parsed(order_commitment_at(&order_input(base.0, before, byte, &next)).unwrap());
            let expected = Commitment::order(base, before, &next, route).unwrap();
            assert_eq!(ok["commitment"], hex(&expected.encode()));
            assert_eq!(ok["hash"], hex(&expected.head().hash.0));
        }
        for unknown in [2, 0xff] {
            assert_eq!(
                order_commitment_at(&order_input(base.0, before, unknown, &next)).err(),
                Some(Refusal::Malformed)
            );
        }
    }

    #[test]
    fn decode_request_ranges_select_the_decoded_fields() {
        let frame = wire::Request::Append {
            id: 7,
            permit: vec![1; 300],
            event: vec![2; 1062],
        }
        .encode()
        .unwrap();
        let out = parsed(decode_request_at(&frame).unwrap());
        assert_eq!(out["kind"], "append");
        assert_eq!(out["id"], 7);
        let range = |v: &serde_json::Value| {
            let start = v[0].as_u64().unwrap() as usize;
            start..start + v[1].as_u64().unwrap() as usize
        };
        assert_eq!(frame[range(&out["permit"])], [1; 300]);
        assert_eq!(frame[range(&out["payload"])], [2; 1062]);
        assert_eq!(range(&out["payload"]).end, frame.len());
        let compound = wire::Request::Publish {
            id: 8,
            stage_permit: vec![3; 20],
            append_permit: vec![4; 30],
            event: vec![5; 50],
            body: vec![6; 1024],
        }
        .encode()
        .unwrap();
        let fields = parsed(decode_request_at(&compound).unwrap());
        assert_eq!(fields["kind"], "publish");
        for (field, byte, size) in [
            ("stage_permit", 3, 20),
            ("append_permit", 4, 30),
            ("event", 5, 50),
            ("body", 6, 1024),
        ] {
            assert_eq!(compound[range(&fields[field])], vec![byte; size]);
        }
        let subscribe = wire::Request::Subscribe {
            id: 1,
            permit: vec![3; 10],
            after: 42,
        }
        .encode()
        .unwrap();
        let out = parsed(decode_request_at(&subscribe).unwrap());
        assert_eq!(
            (out["after"].as_u64(), out["payload"].is_null()),
            (Some(42), true)
        );
        let mut trailing = frame.clone();
        trailing.push(0);
        assert_eq!(decode_request_at(&trailing).err(), Some(Refusal::Malformed));
        let too_far = wire::Request::Subscribe {
            id: 1,
            permit: vec![3; 10],
            after: MAX_SAFE + 1,
        }
        .encode()
        .unwrap();
        assert_eq!(decode_request_at(&too_far).err(), Some(Refusal::Malformed));
        let join = wire::Request::PresenceJoin {
            id: 11,
            permit: vec![7; 294],
        }
        .encode()
        .unwrap();
        let out = parsed(decode_request_at(&join).unwrap());
        assert_eq!(
            (&out["kind"], &out["id"]),
            (&"presence_join".into(), &11.into())
        );
        assert_eq!(join[range(&out["permit"])], [7; 294]);
        assert_eq!(range(&out["permit"]).end, join.len());
        assert!(out["payload"].is_null());
        let presence = wire::Request::Presence {
            id: 11,
            sealed: vec![8; 393],
        }
        .encode()
        .unwrap();
        let out = parsed(decode_request_at(&presence).unwrap());
        assert_eq!((&out["kind"], &out["id"]), (&"presence".into(), &11.into()));
        assert!(out["permit"].is_null());
        assert_eq!(presence[range(&out["payload"])], [8; 393]);
        assert_eq!(range(&out["payload"]).end, presence.len());
        // Over 512 sealed bytes refuses at the length prefix.
        let mut over = presence.clone();
        over[7..11].copy_from_slice(&513u32.to_be_bytes());
        over.resize(11 + 513, 8);
        assert_eq!(decode_request_at(&over).err(), Some(Refusal::Malformed));
        let credit = wire::Request::Credit { bytes: 65_549 }.encode().unwrap();
        let out = parsed(decode_request_at(&credit).unwrap());
        assert_eq!(
            (&out["kind"], &out["id"], &out["credit"], &out["permit"]),
            (
                &serde_json::json!("credit"),
                &serde_json::json!(0),
                &serde_json::json!(65_549),
                &serde_json::Value::Null
            )
        );
        let mut zero = credit.clone();
        zero[7..].fill(0);
        assert_eq!(decode_request_at(&zero).err(), Some(Refusal::Malformed));
    }
}
