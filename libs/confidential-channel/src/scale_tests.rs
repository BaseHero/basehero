use super::*;
use crate::{
    appraisal::{Clock, PolicyContext, PolicyStore, Sample, StoredState},
    attestation::{Expected, Time, VerifiedEvidence},
    handshake::{ClientHello, ServerPending},
    record::{Opened, Session},
};
use bh_confidential_policy::{Limits, Policy, Role, Snapshot};
use bh_crypto::{Secret, SecretBytes, SigningKey};
use std::sync::{
    Arc, Barrier, OnceLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

const T: u64 = 1_751_328_000;
#[derive(Clone)]
struct TestClock {
    wall: Arc<AtomicU64>,
    mono: Arc<AtomicU64>,
}
impl TestClock {
    fn new() -> Self {
        Self {
            wall: Arc::new(AtomicU64::new(T)),
            mono: Arc::new(AtomicU64::new(100)),
        }
    }
}
impl Clock for TestClock {
    fn sample(&self) -> Sample {
        Sample {
            system_seconds: Some(self.wall.load(Ordering::SeqCst)),
            monotonic_ms: self.mono.load(Ordering::SeqCst),
        }
    }
}
struct Store(Arc<AtomicBool>);
impl PolicyStore for Store {
    type Error = ();
    fn load(&mut self) -> Result<StoredState, ()> {
        Ok(StoredState::Fresh)
    }
    fn save(&mut self, _: &Snapshot) -> Result<(), ()> {
        if self.0.load(Ordering::SeqCst) {
            Err(())
        } else {
            Ok(())
        }
    }
}
fn root() -> SigningKey {
    SigningKey::from_seed(&Secret::from_slice(&[7; 32]).unwrap())
}
fn synthetic(
    expected: &Expected,
    time: Option<Time>,
) -> Result<VerifiedEvidence, attestation::Error> {
    attestation::synthetic_evidence(expected, time.unwrap(), None)
}
fn fixture_evidence() -> VerifiedEvidence {
    synthetic(
        &Expected {
            signing: [1; 32],
            receiving: [2; 1216],
            nonce: [3; 32],
            role: Role::Checker,
        },
        Some(Time {
            earliest: T,
            latest: T,
            max_uncertainty_secs: 0,
        }),
    )
    .unwrap()
}
fn policy(generation: u64, withdraw: bool) -> (Vec<u8>, [u8; 64]) {
    let evidence = fixture_evidence();
    let p = Policy {
        version: 1,
        generation,
        issued_at: T,
        expires_at: evidence.validity().1 + 1000,
        builds: if withdraw {
            vec![]
        } else {
            vec![evidence.measured().build().clone()]
        },
        machines: vec![*evidence.measured().machine()],
    };
    let bytes = serde_json::to_vec(&p).unwrap();
    let sig = root().sign(&[b"basehero.confidential-policy.v1\0".as_slice(), &bytes].concat());
    (bytes, sig)
}
fn context() -> (PolicyContext<Store>, TestClock, Arc<AtomicBool>) {
    let clock = TestClock::new();
    let fail = Arc::new(AtomicBool::new(false));
    let ctx = PolicyContext::new(
        root().public(),
        Limits {
            max_lifetime_secs: u64::MAX,
            max_uncertainty_secs: 0,
        },
        T,
        Store(fail.clone()),
        clock.clone(),
    )
    .unwrap();
    (ctx, clock, fail)
}
fn pending(
    ctx: PolicyContext<Store>,
) -> (
    ClientHello<Store>,
    Vec<u8>,
    handshake::ServerAwaitEncapsulation<Store>,
) {
    let client = ClientHello::new(ctx).unwrap();
    let server = ServerPending::accept_hello(client.frame(), root().public(), 100).unwrap();
    let (p, sig) = policy(1, false);
    // Explicitly not an Intel-signed fresh proof. Private substitution below
    // runs real archived QVL then synthetic expected binding and full log assembly.
    let (proof, server) = server
        .attach_evidence(&p, &sig, b"synthetic", b"synthetic", b"synthetic", 100)
        .unwrap();
    (client, proof, server)
}
fn sessions(ctx: PolicyContext<Store>) -> (Session<Store>, Session<Store>) {
    let (client, proof, server) = pending(ctx);
    attestation::QVL_CALLS.with(|n| n.set(0));
    let checked = client
        .checked_with_test(&proof, |_, expected, time| synthetic(expected, time))
        .unwrap();
    assert_eq!(attestation::QVL_CALLS.with(|n| n.get()), 1);
    let (enc, client) = checked.encapsulate().unwrap();
    let (finish, server) = server.accept_encapsulation(&enc, 100).unwrap();
    let (finish, client) = client.accept_finish(&finish).unwrap();
    let server = server.accept_finish(&finish, TestClock::new()).unwrap();
    assert_eq!(attestation::QVL_CALLS.with(|n| n.get()), 1); // neither KEM nor Finish re-QVL
    (client, server)
}
#[test]
fn common_client_clock_latches_real_wall_and_monotonic_rollback() {
    for backwards_wall in [false, true] {
        let (ctx, clock, _) = context();
        ClientHello::new(ctx.clone()).unwrap();
        clock.wall.store(T + 1, Ordering::SeqCst);
        clock.mono.store(101, Ordering::SeqCst);
        ClientHello::new(ctx.clone()).unwrap();
        if backwards_wall {
            clock.wall.store(T, Ordering::SeqCst);
        } else {
            clock.mono.store(100, Ordering::SeqCst);
        }
        assert!(matches!(ClientHello::new(ctx.clone()), Err(Error::Clock)));
        clock.wall.store(T + 2, Ordering::SeqCst);
        clock.mono.store(102, Ordering::SeqCst);
        assert!(matches!(ClientHello::new(ctx), Err(Error::Clock)));
    }
}
#[test]
fn client_entry_paths_sample_while_holding_context_lock() {
    let observed = Arc::new(OnceLock::<std::sync::Weak<PolicyContext<Store>>>::new());
    let samples = Arc::new(AtomicU64::new(0));
    let clock = {
        let observed = observed.clone();
        let samples = samples.clone();
        move || {
            let ctx = observed
                .get()
                .expect("context installed before first sample")
                .upgrade()
                .expect("context still alive during sample");
            assert!(
                ctx.lock_held_for_test(),
                "clock sampled before context lock"
            );
            samples.fetch_add(1, Ordering::SeqCst);
            Sample {
                system_seconds: Some(T),
                monotonic_ms: 100,
            }
        }
    };
    let ctx = Arc::new(
        PolicyContext::new(
            root().public(),
            Limits {
                max_lifetime_secs: u64::MAX,
                max_uncertainty_secs: 0,
            },
            T,
            Store(Arc::new(AtomicBool::new(false))),
            clock,
        )
        .unwrap(),
    );
    assert!(observed.set(Arc::downgrade(&ctx)).is_ok());

    ctx.with_clock(|_| Ok(())).unwrap();
    assert_eq!(samples.load(Ordering::SeqCst), 1, "with_clock must sample");
    let (p, sig) = policy(1, false);
    ctx.deliver_policy(&p, &sig).unwrap();
    ctx.with_current(&fixture_evidence(), |_| Ok(())).unwrap();
    assert_eq!(
        samples.load(Ordering::SeqCst),
        2,
        "with_current must sample"
    );
}
#[test]
fn blocked_heavy_verification_rechecks_current_policy_clock_and_persistence() {
    for case in 0..5 {
        let (ctx, clock, fail) = context();
        let (client, proof, _) = pending(ctx.clone());
        let verified = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let done = verified.clone();
        let release = resume.clone();
        let handle = std::thread::spawn(move || {
            attestation::QVL_CALLS.with(|n| n.set(0));
            let result = client.checked_with_test(&proof, |_, expected, time| {
                let evidence = synthetic(expected, time)?;
                done.wait();
                release.wait();
                Ok(evidence)
            });
            assert_eq!(attestation::QVL_CALLS.with(|n| n.get()), 1);
            result.err()
        });
        verified.wait(); // Taking policy lock here would deadlock if QVL held it.
        let expected = match case {
            0 => {
                let (p, s) = policy(2, true);
                ctx.deliver_policy(&p, &s).unwrap();
                Error::Policy(bh_confidential_policy::Error::BuildDenied)
            }
            1 => {
                ctx.mark_unavailable().unwrap();
                Error::Policy(bh_confidential_policy::Error::PolicyUnavailable)
            }
            2 => {
                let (p, s) = policy(2, false);
                fail.store(true, Ordering::SeqCst);
                assert_eq!(
                    ctx.deliver_policy(&p, &s),
                    Err(Error::PersistenceUnavailable)
                );
                Error::PersistenceUnavailable
            }
            3 => {
                clock
                    .wall
                    .store(fixture_evidence().validity().1, Ordering::SeqCst);
                Error::Attestation(attestation::Error::Quote)
            }
            _ => {
                clock.mono.store(99, Ordering::SeqCst);
                Error::Clock
            }
        };
        resume.wait();
        assert_eq!(handle.join().unwrap(), Some(expected));
    }
}
#[test]
fn records_recheck_horizon_and_withdrawal_before_both_actions() {
    for withdrawal in [false, true] {
        for opening in [false, true] {
            let (ctx, clock, _) = context();
            let (mut client, mut server) = sessions(ctx.clone());
            let frame = server.seal(SecretBytes::from_vec(vec![9])).unwrap();
            if withdrawal {
                let (p, s) = policy(2, true);
                ctx.deliver_policy(&p, &s).unwrap();
            } else {
                clock
                    .wall
                    .store(fixture_evidence().validity().1, Ordering::SeqCst);
            }
            let result = if opening {
                client.open(&frame).map(|_| ())
            } else {
                client.seal(SecretBytes::from_vec(vec![1])).map(|_| ())
            };
            assert_eq!(
                result,
                Err(if withdrawal {
                    Error::Policy(bh_confidential_policy::Error::BuildDenied)
                } else {
                    Error::Attestation(attestation::Error::Quote)
                })
            );
            assert!(client.is_closed());
            assert_eq!(client.binding(), Err(Error::Order));
            // Other guards are deliberately valid: with this specific guard
            // deleted the action succeeds, rather than failing for another reason.
        }
    }
}
#[test]
fn many_records_keep_one_heavy_verification_and_no_raw_evidence() {
    let (ctx, _, _) = context();
    let (mut client, mut server) = sessions(ctx);
    for _ in 0..128 {
        let ct = client.seal(SecretBytes::from_vec(vec![7])).unwrap();
        assert!(matches!(server.open(&ct).unwrap(), Opened::Data(_)));
        let ct = server.seal(SecretBytes::from_vec(vec![8])).unwrap();
        match client.open(&ct).unwrap() {
            Opened::Data(p) => assert_eq!(p.expose(), [8]),
            Opened::Closed => panic!(),
        }
    }
    assert_eq!(attestation::QVL_CALLS.with(|n| n.get()), 1);
    // The actual retained variant has an opaque fixed measurement value, not
    // quote/collateral/log Vecs; no raw evidence survives transcript derivation.
    let record::Appraisal::Client(_, e) = &client.appraisal_for_test() else {
        panic!()
    };
    assert_eq!(
        e.measured()
            .build()
            .boot
            .iter()
            .map(Vec::len)
            .sum::<usize>(),
        192
    );
}

#[cfg(test)]
#[path = "scale_measurements.rs"]
mod measurements;
