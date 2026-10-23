//! Public account evidence is challenge bound and discloses no bodies.
#![cfg(feature = "synthetic-attestation")]
mod support;
use bh_authz::proto::{FromService, Refusal, ToService, Want};
use bh_sync::{
    evidence::{AcceptedHead, OrderingConfirmation},
    permit::Scope,
};
use support::*;

#[tokio::test]
async fn anyone_reads_account_evidence_with_a_challenge_bound_head() {
    let h = Harness::new();
    let a = Device::new();
    let account = Account::create_full(&a);
    h.publish(&account);
    let service = h.service();
    let (mut c, _, _) = connect(&service);
    let answer = c
        .handle(ToService::ReadAccountEvidence {
            genesis: account.genesis.clone(),
            first: 1,
            last: 3,
            challenge: [8; 32],
        })
        .await;
    let FromService::AccountEvidence {
        events_permit,
        confirmations,
        head,
    } = answer
    else {
        panic!("evidence: {answer:?}")
    };
    assert_eq!(
        h.permit(&events_permit).scope,
        Scope::ReadEvents {
            log: account.log,
            first: 1,
            last: 3
        }
    );
    assert_eq!(confirmations.len(), 2, "genesis must never be timed");
    for (i, bytes) in confirmations.iter().enumerate() {
        let evidence = OrderingConfirmation::decode(bytes).unwrap();
        let claim = evidence
            .verify_for(&h.root.public(), &account.originals[i + 1], None)
            .unwrap();
        assert_eq!(claim.ordered.position, i as u64 + 2);
    }
    let accepted = AcceptedHead::verify(&head, &h.root.public(), account.log, &[8; 32]).unwrap();
    assert_eq!(accepted.original_head.position, 3);
    assert_eq!(accepted.evidence, bh_crypto::hash(&confirmations[1]));
    assert!(AcceptedHead::verify(&head, &h.root.public(), account.log, &[9; 32]).is_err());
    assert!(matches!(
        c.handle(ToService::Permits {
            items: vec![Want::ReadBodies {
                log: account.log,
                bodies: vec![]
            }]
        })
        .await,
        FromService::Refused {
            reason: Refusal::Unauthenticated
        }
    ));
}

#[tokio::test]
async fn directory_permits_only_for_active_devices_of_the_account() {
    let h = Harness::new();
    let a = Device::new();
    let account = Account::create_full(&a);
    h.publish(&account);
    let service = h.service();
    let mut c = session(&service, &account, &a).await;
    let want = Want::ReadDirectory { log: account.log };
    assert_eq!(
        h.permit(&single_permit(
            c.handle(ToService::Permits { items: vec![want] }).await
        ))
        .scope,
        Scope::ReadDirectory { log: account.log }
    );
    let foreign = Account::create_full(&Device::new());
    let result = c
        .handle(ToService::Permits {
            items: vec![Want::ReadDirectory { log: foreign.log }],
        })
        .await;
    assert!(
        matches!(result, FromService::Permits { items } if matches!(items[0],Err(Refusal::Unknown)))
    );
}

#[tokio::test]
async fn accepted_head_time_is_a_durable_floor_for_later_confirmations() {
    let h = Harness::new();
    h.clock.set(100);
    let a = Device::new();
    let mut account = Account::create_full(&a);
    h.publish(&account);
    let service = h.service();
    let (mut c, _, _) = connect(&service);
    h.clock.set(500);
    let answer = c
        .handle(ToService::ReadAccountEvidence {
            genesis: account.genesis.clone(),
            first: 1,
            last: 3,
            challenge: [8; 32],
        })
        .await;
    let FromService::AccountEvidence { head, .. } = answer else {
        panic!("evidence: {answer:?}")
    };
    assert_eq!(
        AcceptedHead::verify(&head, &h.root.public(), account.log, &[8; 32])
            .unwrap()
            .bounds
            .latest_ms,
        500
    );
    drop(c);
    drop(service);
    h.clock.set(200);
    let event = account.add_device(&a, &Device::new());
    h.order_account_event(&account, &event);
    let service = h.service();
    let (mut c, _, _) = connect(&service);
    let answer = c
        .handle(ToService::ReadAccountEvidence {
            genesis: account.genesis.clone(),
            first: 4,
            last: 4,
            challenge: [8; 32],
        })
        .await;
    let FromService::AccountEvidence { confirmations, .. } = answer else {
        panic!("evidence: {answer:?}")
    };
    let bounds = OrderingConfirmation::decode(&confirmations[0])
        .unwrap()
        .claim()
        .bounds;
    assert_eq!((bounds.earliest_ms, bounds.latest_ms), (500, 500));
}
