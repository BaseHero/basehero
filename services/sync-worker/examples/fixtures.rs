//! Native-only deterministic signing material, never included in the Worker module.
use bh_crypto::{Secret, SigningKey};
use bh_sync::{
    Approval, BaseId, BodyObject, Commitment, Digest, EventId, GateState, Head, OpaqueEvent,
    Operation, OrderState, Route, SignedApproval,
};
use serde_json::json;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn grant(key: &SigningKey, gate: GateState, operation: &Operation, sequence: u64) -> String {
    let approval = Approval {
        base: gate.base,
        expected_head: gate.head,
        incarnation: gate.incarnation,
        sequence,
        nonce: [sequence as u8; 32],
        operation: operation.digest(),
        response_binding: Digest([7; 32]),
        not_before: 10,
        expires: 20,
    };
    hex(&SignedApproval {
        approval,
        signature: key.sign(&approval.signing_bytes()),
    }
    .encode())
}
/// A descriptor whose first 32 envelope bytes are `commitment`, matching the real
/// codec's detached-body reference.
fn descriptor(id: [u8; 32], commitment: [u8; 32], seed: u8) -> OpaqueEvent {
    let mut envelope = commitment.to_vec();
    envelope.extend(vec![seed; 1024 - 32]);
    OpaqueEvent::new(EventId(id), envelope).unwrap()
}
fn body(seed: u8) -> BodyObject {
    BodyObject::new(vec![seed; 1024]).unwrap()
}
fn main() {
    let key = SigningKey::from_seed(&Secret::from_slice(&[42; 32]).unwrap());
    let body_a = body(0xb1);
    let body_b = body(0xb2);
    let body_c = body(0xb3);
    let event = descriptor([3; 32], body_a.commitment().0, 0xa5);
    let base = BaseId::from_genesis(&event);
    let gate = GateState {
        base,
        order: OrderState::EMPTY,
        head: Head::EMPTY,
        incarnation: [5; 32],
        sequence: 0,
        checker_key: key.public(),
    };
    let commitment = Commitment::order(base, OrderState::EMPTY, &event, Route::Control).unwrap();
    let append = Operation::Append(event.clone());
    let read = Operation::read(vec![event.digest()]).unwrap();
    let after = GateState {
        head: commitment.head(),
        order: commitment.after(),
        sequence: 1,
        ..gate
    };
    let conflicting = descriptor(event.nonce().0, body_a.commitment().0, 0x3c);
    let second = descriptor([4; 32], body_b.commitment().0, 0x4c);
    let second_commitment =
        Commitment::order(base, commitment.after(), &second, Route::Content).unwrap();
    let third = descriptor([6; 32], body_c.commitment().0, 0x6d);
    let third_commitment =
        Commitment::order(base, second_commitment.after(), &third, Route::Content).unwrap();
    let after_second = GateState {
        head: second_commitment.head(),
        order: second_commitment.after(),
        sequence: 2,
        ..after
    };
    let after_third = GateState {
        head: third_commitment.head(),
        order: third_commitment.after(),
        sequence: 3,
        ..after
    };
    let after_clean_retry = GateState {
        sequence: 4,
        ..after_third
    };
    let other_key = SigningKey::from_seed(&Secret::from_slice(&[43; 32]).unwrap());
    let wrong_key = Approval {
        base,
        expected_head: after.head,
        incarnation: after.incarnation,
        sequence: 2,
        nonce: [9; 32],
        operation: append.digest(),
        response_binding: Digest([7; 32]),
        not_before: 10,
        expires: 20,
    };
    // Detached-body fixtures. `staged` is seeded and exercised through the real
    // stage/append/read operations; `missing` is deliberately never staged. The
    // main body fixture appends the genesis first, then stages, then appends.
    let staged = body(0xb4);
    let staged_event = descriptor([8; 32], staged.commitment().0, 0x8e);
    let staged_commitment =
        Commitment::order(base, commitment.after(), &staged_event, Route::Content).unwrap();
    let missing = body(0xb5);
    let missing_event = descriptor([9; 32], missing.commitment().0, 0x9f);
    let stage_op = Operation::stage_body(staged.clone());
    let read_bodies_op = Operation::read_bodies(vec![staged.commitment()]).unwrap();
    let after_stage = GateState {
        sequence: 2,
        ..after
    };
    let after_body_append = GateState {
        head: staged_commitment.head(),
        order: staged_commitment.after(),
        sequence: 3,
        ..after
    };
    let stage_twice_gate = GateState {
        sequence: 1,
        ..gate
    };
    let stage_thrice_gate = GateState {
        sequence: 2,
        ..gate
    };
    let printed = json!({
        "gate": { "base":hex(&base.0),"order_format":2,"order":hex(&gate.order.encode()),"position":0,"hash":hex(&Head::EMPTY.hash.0),
            "incarnation":hex(&gate.incarnation),"sequence":0,"checker_key":hex(&key.public()) },
        "event":hex(&event.encode()), "digest":hex(&event.digest().0), "commitment":hex(&commitment.encode()),
        "append":grant(&key, gate, &append, 1),
        "replay":grant(&key, after, &append, 2),
        "read":grant(&key, GateState { sequence:2,..after }, &read, 3),
        "conflict":grant(&key, after, &Operation::Append(conflicting.clone()), 2),
        "conflicting_event":hex(&conflicting.encode()),
        "second":hex(&second.encode()),
        "second_append":grant(&key, after, &Operation::Append(second.clone()), 2),
        "second_commitment":hex(&second_commitment.encode()),
        "third":hex(&third.encode()),
        "third_append":grant(&key, after_second, &Operation::Append(third.clone()), 3),
        "third_commitment":hex(&third_commitment.encode()),
        "replay_first_after_third":grant(&key, after_third, &append, 4),
        "replay_first_after_clean":grant(&key, after_clean_retry, &append, 5),
        "read_first_after_third":grant(&key, after_clean_retry, &read, 5),
        "wrong_key":hex(&SignedApproval { approval:wrong_key,signature:other_key.sign(&wrong_key.signing_bytes()) }.encode()),
        "bodies": [
            {"commitment":hex(&body_a.commitment().0),"body":hex(body_a.bytes())},
            {"commitment":hex(&body_b.commitment().0),"body":hex(body_b.bytes())},
            {"commitment":hex(&body_c.commitment().0),"body":hex(body_c.bytes())},
        ],
        "stage":grant(&key, gate, &stage_op, 1),
        "stage_after_genesis":grant(&key, after, &stage_op, 2),
        "stage_twice":grant(&key, stage_twice_gate, &stage_op, 2),
        "stage_thrice":grant(&key, stage_thrice_gate, &stage_op, 3),
        "read_bodies_after_stage":grant(&key, stage_twice_gate, &read_bodies_op, 2),
        "stage_body":hex(staged.bytes()),
        "stage_body_commitment":hex(&staged.commitment().0),
        "mismatched_body":hex(body_b.bytes()),
        "append_body":grant(&key, after_stage, &Operation::Append(staged_event.clone()), 3),
        "body_event":hex(&staged_event.encode()),
        "body_commitment":hex(&staged_commitment.encode()),
        "read_bodies":grant(&key, after_body_append, &read_bodies_op, 4),
        "read_body_object":hex(&staged.commitment().0),
        "missing_body_event":hex(&missing_event.encode()),
        "append_missing_body":grant(&key, after, &Operation::Append(missing_event.clone()), 2),
        "time":{"earliest":10,"latest":11},
        "binding":hex(&[7;32]),
    });
    println!("{printed}");
}
