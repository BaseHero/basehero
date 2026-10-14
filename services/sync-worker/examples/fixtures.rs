//! Native-only deterministic signing material, never included in the Worker module.
use bh_crypto::{Secret, SigningKey};
use bh_sync::{
    Approval, BaseId, Commitment, Digest, GateState, Head, OpaqueEvent, Operation, SignedApproval,
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
fn main() {
    let key = SigningKey::from_seed(&Secret::from_slice(&[42; 32]).unwrap());
    let event = OpaqueEvent::new(bh_sync::EventId([3; 32]), vec![0xa5; 1024]).unwrap();
    let base = BaseId::from_genesis(&event);
    let gate = GateState {
        base,
        head: Head::EMPTY,
        incarnation: [5; 32],
        sequence: 0,
        checker_key: key.public(),
    };
    let commitment = Commitment::order(base, Head::EMPTY, &event).unwrap();
    let append = Operation::Append(event.clone());
    let read = Operation::read(vec![event.digest()]).unwrap();
    let after = GateState {
        head: commitment.head(),
        sequence: 1,
        ..gate
    };
    let conflicting = OpaqueEvent::new(event.id(), vec![0x3c; 1024]).unwrap();
    let second = OpaqueEvent::new(bh_sync::EventId([4; 32]), vec![0x4c; 1024]).unwrap();
    let second_commitment = Commitment::order(base, commitment.head(), &second).unwrap();
    let third = OpaqueEvent::new(bh_sync::EventId([6; 32]), vec![0x6d; 1024]).unwrap();
    let third_commitment = Commitment::order(base, second_commitment.head(), &third).unwrap();
    let after_second = GateState {
        head: second_commitment.head(),
        sequence: 2,
        ..after
    };
    let after_third = GateState {
        head: third_commitment.head(),
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
    let printed = json!({
        "gate": { "base":hex(&base.0),"position":0,"hash":hex(&Head::EMPTY.hash.0),
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
        "time":{"earliest":10,"latest":11},
        "binding":hex(&[7;32]),
    });
    println!("{printed}");
}
