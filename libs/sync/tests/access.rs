use bh_sync::*;

fn body(n: u8) -> BodyObject {
    BodyObject::new(vec![n; 1024]).unwrap()
}
fn event_with_body(id: u8, seed: u8) -> OpaqueEvent {
    // A real descriptor's first 32 envelope bytes are its body commitment. These
    // fixtures keep that invariant so the kernel's referenced-body check passes.
    let body = body(seed);
    let mut envelope = body.commitment().0.to_vec();
    envelope.extend(vec![seed; 1024 - 32]);
    OpaqueEvent::new(EventId([id; 32]), envelope).unwrap()
}
fn event(n: u8) -> OpaqueEvent {
    event_with_body(n, n)
}
fn fixture() -> (GateState, bh_crypto::SigningKey) {
    let seed = bh_crypto::Secret::from_slice(&[7; 32]).unwrap();
    let key = bh_crypto::SigningKey::from_seed(&seed);
    let genesis = event(1);
    let base = BaseId::from_genesis(&genesis);
    let head = Commitment::order(base, Head::EMPTY, &genesis)
        .unwrap()
        .head();
    (
        GateState {
            base,
            head,
            incarnation: [4; 32],
            sequence: 0,
            checker_key: key.public(),
        },
        key,
    )
}
fn approval(
    state: &GateState,
    operation: &Operation,
    key: &bh_crypto::SigningKey,
) -> SignedApproval {
    let approval = Approval {
        base: state.base,
        expected_head: state.head,
        incarnation: state.incarnation,
        sequence: state.sequence + 1,
        nonce: [8; 32],
        operation: operation.digest(),
        response_binding: Digest([6; 32]),
        not_before: 100,
        expires: 200,
    };
    let signature = key.sign(&approval.signing_bytes());
    SignedApproval {
        approval,
        signature,
    }
}
fn time() -> TimeWindow {
    TimeWindow {
        earliest: 110,
        latest: 120,
    }
}

fn body_ref(operation: &Operation) -> Option<Digest> {
    match operation {
        Operation::Append(event) => referenced_body(event).ok(),
        Operation::StageBody(body) => Some(body.commitment()),
        Operation::Read(_) | Operation::ReadBodies(_) => None,
    }
}
fn plan_consumption(
    state: &GateState,
    approval: &SignedApproval,
    operation: &Operation,
    time: TimeWindow,
    existing: Option<Commitment>,
) -> Result<Consumption, AccessError> {
    bh_sync::plan_consumption(
        state,
        approval,
        operation,
        time,
        existing,
        body_ref(operation),
        Digest([6; 32]),
    )
}

#[test]
fn response_cannot_be_redirected_by_a_copied_approval() {
    let (state, key) = fixture();
    let op = Operation::read(vec![event(1).digest()]).unwrap();
    let grant = approval(&state, &op, &key);
    assert_eq!(
        bh_sync::plan_consumption(&state, &grant, &op, time(), None, None, Digest([9; 32])),
        Err(AccessError::Operation)
    );
}

#[test]
fn append_and_read_each_consume_one_sequence() {
    let (state, key) = fixture();
    let operation = Operation::Append(event(2));
    let grant = approval(&state, &operation, &key);
    let plan = plan_consumption(&state, &grant, &operation, time(), None).unwrap();
    assert_eq!(plan.next.sequence, 1);
    assert_eq!(plan.next.head.position, 2);
    assert_eq!(plan.append.unwrap().event_id(), event(2).id());
    assert_eq!(
        plan_consumption(&plan.next, &grant, &operation, time(), None),
        Err(AccessError::Stale)
    );
    let read = Operation::read(vec![event(2).digest()]).unwrap();
    let read_grant = approval(&plan.next, &read, &key);
    let read_plan = plan_consumption(&plan.next, &read_grant, &read, time(), None).unwrap();
    assert_eq!(read_plan.next.sequence, 2);
    assert_eq!(read_plan.next.head, plan.next.head);
    assert_eq!(read_plan.append, None);
}

#[test]
fn every_approval_field_and_signature_are_authenticated() {
    let (state, key) = fixture();
    let op = Operation::Append(event(2));
    let grant = approval(&state, &op, &key);
    let bytes = grant.encode();
    assert_eq!(SignedApproval::decode(&bytes), Ok(grant));
    for i in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[i] ^= 1;
        if let Ok(changed) = SignedApproval::decode(&changed) {
            assert!(
                plan_consumption(&state, &changed, &op, time(), None).is_err(),
                "byte {i}"
            );
        }
    }
    assert!(SignedApproval::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(SignedApproval::decode(&trailing).is_err());
}

#[test]
fn altered_operations_head_base_and_incarnation_refuse() {
    let (state, key) = fixture();
    let op = Operation::Append(event(2));
    let grant = approval(&state, &op, &key);
    assert_eq!(
        plan_consumption(&state, &grant, &Operation::Append(event(3)), time(), None),
        Err(AccessError::Operation)
    );
    let mut altered = state;
    altered.base = BaseId([9; 32]);
    assert_eq!(
        plan_consumption(&altered, &grant, &op, time(), None),
        Err(AccessError::Stale)
    );
    altered = state;
    altered.head.hash = Digest([9; 32]);
    assert_eq!(
        plan_consumption(&altered, &grant, &op, time(), None),
        Err(AccessError::Stale)
    );
    altered = state;
    altered.incarnation = [9; 32];
    assert_eq!(
        plan_consumption(&altered, &grant, &op, time(), None),
        Err(AccessError::Stale)
    );
}

#[test]
fn deadline_bounds_are_conservative_and_invalid_time_refuses() {
    let (state, key) = fixture();
    let op = Operation::Append(event(2));
    let grant = approval(&state, &op, &key);
    for t in [
        TimeWindow {
            earliest: 99,
            latest: 110,
        },
        TimeWindow {
            earliest: 190,
            latest: 200,
        },
        TimeWindow {
            earliest: 200,
            latest: 201,
        },
        TimeWindow {
            earliest: 120,
            latest: 110,
        },
    ] {
        assert_eq!(
            plan_consumption(&state, &grant, &op, t, None),
            Err(AccessError::Time)
        );
    }
    assert!(
        plan_consumption(
            &state,
            &grant,
            &op,
            TimeWindow {
                earliest: 100,
                latest: 199
            },
            None
        )
        .is_ok()
    );
}

#[test]
fn fresh_authorization_of_lost_ack_returns_original_commitment() {
    let (state, key) = fixture();
    let op = Operation::Append(event(2));
    let first = plan_consumption(&state, &approval(&state, &op, &key), &op, time(), None).unwrap();
    let original = first.append.unwrap();
    let fresh = approval(&first.next, &op, &key);
    let retry = plan_consumption(&first.next, &fresh, &op, time(), Some(original)).unwrap();
    assert_eq!(retry.next.head, first.next.head);
    assert_eq!(retry.next.sequence, 2);
    assert_eq!(retry.append, None);
    assert_eq!(retry.ack, Some(original));
    let changed = Operation::Append(OpaqueEvent::new(event(2).id(), vec![3; 1024]).unwrap());
    assert_eq!(
        plan_consumption(
            &first.next,
            &approval(&first.next, &changed, &key),
            &changed,
            time(),
            Some(original)
        ),
        Err(AccessError::ReplayConflict)
    );
}

#[test]
fn read_selection_is_bounded_and_committed() {
    assert_eq!(Operation::read(vec![]), Err(AccessError::Selection));
    assert_eq!(
        Operation::read(vec![Digest([1; 32]); 65]),
        Err(AccessError::Selection)
    );
    assert_eq!(
        Operation::read(vec![Digest([1; 32]); 2]),
        Err(AccessError::Selection)
    );
    assert_ne!(
        Operation::read(vec![Digest([1; 32])]).unwrap().digest(),
        Operation::read(vec![Digest([2; 32])]).unwrap().digest()
    );
}

#[test]
fn body_operations_have_distinct_bounded_domains() {
    assert_eq!(Operation::read_bodies(vec![]), Err(AccessError::Selection));
    assert_eq!(
        Operation::read_bodies(vec![Digest([1; 32]); 65]),
        Err(AccessError::Selection)
    );
    assert_eq!(
        Operation::read_bodies(vec![Digest([1; 32]); 2]),
        Err(AccessError::Selection)
    );
    let one = Operation::read_bodies(vec![body(1).commitment()]).unwrap();
    let two = Operation::read_bodies(vec![body(2).commitment()]).unwrap();
    assert_ne!(one.digest(), two.digest());
    // Same underlying object, different operation domain: an event-read approval
    // cannot authorise a body read, and staging is distinct from reading.
    let commitment = body(1).commitment();
    let event_read_same_object = Operation::read(vec![commitment]).unwrap();
    assert_ne!(one.digest(), event_read_same_object.digest());
    assert_ne!(Operation::stage_body(body(1)).digest(), one.digest());
}

#[test]
fn append_fails_closed_unless_the_referenced_body_is_staged() {
    let (state, key) = fixture();
    let op = Operation::Append(event(2));
    let grant = approval(&state, &op, &key);
    let referenced = referenced_body(&event(2)).unwrap();
    assert_eq!(
        bh_sync::plan_consumption(&state, &grant, &op, time(), None, None, Digest([6; 32])),
        Err(AccessError::Body)
    );
    assert_eq!(
        bh_sync::plan_consumption(
            &state,
            &grant,
            &op,
            time(),
            None,
            Some(Digest([9; 32])),
            Digest([6; 32])
        ),
        Err(AccessError::Body)
    );
    let plan = bh_sync::plan_consumption(
        &state,
        &grant,
        &op,
        time(),
        None,
        Some(referenced),
        Digest([6; 32]),
    )
    .unwrap();
    assert_eq!(plan.append.unwrap().event_id(), event(2).id());
}

#[test]
fn body_stage_and_read_consume_sequence_without_moving_head() {
    let (state, key) = fixture();
    let stage = Operation::stage_body(body(5));
    let plan = plan_consumption(
        &state,
        &approval(&state, &stage, &key),
        &stage,
        time(),
        None,
    )
    .unwrap();
    assert_eq!(plan.next.sequence, state.sequence + 1);
    assert_eq!(plan.next.head, state.head);
    assert_eq!(plan.stage, Some(body(5).commitment()));
    assert_eq!(plan.append, None);
    let read = Operation::read_bodies(vec![body(5).commitment()]).unwrap();
    let read_plan = plan_consumption(
        &plan.next,
        &approval(&plan.next, &read, &key),
        &read,
        time(),
        None,
    )
    .unwrap();
    assert_eq!(read_plan.next.sequence, state.sequence + 2);
    assert_eq!(read_plan.next.head, state.head);
    assert_eq!(read_plan.append, None);
    assert_eq!(read_plan.ack, None);
    assert_eq!(read_plan.stage, None);
    // A copied event-read approval does not bind this body read.
    let event_read = Operation::read(vec![body(5).commitment()]).unwrap();
    assert_eq!(
        plan_consumption(
            &plan.next,
            &approval(&plan.next, &event_read, &key),
            &read,
            time(),
            None
        ),
        Err(AccessError::Operation)
    );
}

#[test]
fn stale_or_misbound_body_approvals_never_consume() {
    let (state, key) = fixture();
    let stage = Operation::stage_body(body(6));
    let grant = approval(&state, &stage, &key);
    let mut later = state;
    later.sequence += 1;
    assert_eq!(
        plan_consumption(&later, &grant, &stage, time(), None),
        Err(AccessError::Stale)
    );
    let other = Operation::stage_body(body(7));
    assert_eq!(
        plan_consumption(&state, &grant, &other, time(), None),
        Err(AccessError::Operation)
    );
}

#[test]
fn execution_lane_starts_unavailable_and_never_clears_uncertainty_on_timeout() {
    let (state, key) = fixture();
    let op = Operation::Append(event(2));
    let grant = approval(&state, &op, &key);
    let mut lane = ExecutionLane::unavailable();
    assert_eq!(lane.begin(grant), Err(AccessError::Unavailable));
    lane.establish(state).unwrap();
    lane.begin(grant).unwrap();
    assert_eq!(lane.begin(grant), Err(AccessError::Uncertain));
    assert_eq!(lane.establish(state), Err(AccessError::Uncertain));
    assert_eq!(lane.fence(state), Err(AccessError::Stale));
    let mut fenced = state;
    fenced.incarnation = [5; 32];
    lane.fence(fenced).unwrap();
    assert_eq!(lane.begin(grant), Err(AccessError::Stale));
}

#[test]
fn lane_reconciles_exact_committed_outcome_or_stays_blocked() {
    let (state, key) = fixture();
    let op = Operation::Append(event(2));
    let grant = approval(&state, &op, &key);
    let plan = plan_consumption(&state, &grant, &op, time(), None).unwrap();
    let mut lane = ExecutionLane::unavailable();
    lane.establish(state).unwrap();
    lane.begin(grant).unwrap();
    let mut wrong = plan.next;
    wrong.sequence += 1;
    assert_eq!(lane.committed(grant, wrong), Err(AccessError::Uncertain));
    lane.committed(grant, plan.next).unwrap();
    let next_op = Operation::Append(event(3));
    lane.begin(approval(&plan.next, &next_op, &key)).unwrap();
}
