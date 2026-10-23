use crate::appraisal::Sample;
use crate::test_clock::At;
use bh_confidential_channel::{
    Error,
    appraisal::{PolicyContext, PolicyStore, StoredState},
};
use bh_confidential_policy::{Build, Limits, Policy, Role, Snapshot};
use bh_crypto::{Secret, SigningKey};
use std::sync::{Arc, Mutex};

// Private legacy fixture adapter; the checked action still uses the production
// immutable horizon and current gate path, never a second authorization method.
impl<S: PolicyStore> PolicyContext<S> {
    fn check_synthetic_for_test(
        &self,
        build: &Build,
        machine: &[u8; 32],
        sample: Sample,
    ) -> Result<(), Error> {
        crate::test_clock::set(sample);
        let expected = crate::attestation::Expected {
            signing: [1; 32],
            receiving: [2; 1216],
            nonce: [3; 32],
            role: Role::Checker,
        };
        let evidence = crate::attestation::synthetic_evidence(
            &expected,
            crate::attestation::Time {
                earliest: 100,
                latest: 100,
                max_uncertainty_secs: 0,
            },
            Some((build.clone(), *machine)),
        )?;
        self.with_current(&evidence, |_| Ok(()))
    }
}
struct Memory(Arc<Mutex<(StoredState, usize, bool)>>);
impl PolicyStore for Memory {
    type Error = ();
    fn load(&mut self) -> Result<StoredState, Self::Error> {
        Ok(self.0.lock().unwrap().0.clone())
    }
    fn save(&mut self, snap: &Snapshot) -> Result<(), Self::Error> {
        let mut s = self.0.lock().unwrap();
        s.1 += 1;
        if s.2 {
            Err(())
        } else {
            s.0 = StoredState::Committed(snap.clone());
            Ok(())
        }
    }
}
fn signed(n: u64) -> (Vec<u8>, [u8; 64], Build) {
    let build = Build {
        role: Role::Checker,
        compose_sha256: [1; 32],
        boot: std::array::from_fn(|_| vec![1; 48]),
    };
    let bytes = serde_json::to_vec(&Policy {
        version: 1,
        generation: n,
        issued_at: 100,
        expires_at: 200,
        builds: vec![build.clone()],
        machines: vec![[2; 32]],
    })
    .unwrap();
    let signing = SigningKey::from_seed(&Secret::from_slice(&[7; 32]).unwrap());
    let sig = signing.sign(&[b"basehero.confidential-policy.v1\0".as_slice(), &bytes].concat());
    (bytes, sig, build)
}
fn context(mem: &Arc<Mutex<(StoredState, usize, bool)>>) -> PolicyContext<Memory> {
    crate::test_clock::clock_at(0);
    PolicyContext::new(
        SigningKey::from_seed(&Secret::from_slice(&[7; 32]).unwrap()).public(),
        Limits {
            max_lifetime_secs: 100,
            max_uncertainty_secs: 0,
        },
        100,
        Memory(mem.clone()),
        crate::test_clock::read,
    )
    .unwrap()
}
#[test]
fn impossible_or_prebuild_system_samples_refuse_before_use() {
    let mem = Arc::new(Mutex::new((StoredState::Fresh, 0, false)));
    let ctx = context(&mem);
    let (p, sig, build) = signed(1);
    ctx.deliver_policy(&p, &sig).unwrap();
    for system_seconds in [None, Some(0), Some(99), Some(u64::MAX)] {
        assert_eq!(
            ctx.check_synthetic_for_test(
                &build,
                &[2; 32],
                Sample {
                    system_seconds,
                    monotonic_ms: 1
                }
            ),
            Err(Error::Clock)
        );
    }
}

#[test]
fn backward_system_or_monotonic_time_latches_across_redelivery() {
    for sample in [
        Sample {
            system_seconds: Some(99),
            monotonic_ms: 2,
        },
        Sample {
            system_seconds: None,
            monotonic_ms: 0,
        },
        Sample {
            system_seconds: Some(119),
            monotonic_ms: 2,
        },
        Sample {
            system_seconds: Some(120),
            monotonic_ms: 0,
        },
    ] {
        let mem = Arc::new(Mutex::new((StoredState::Fresh, 0, false)));
        let ctx = context(&mem);
        let (p, sig, build) = signed(1);
        ctx.deliver_policy(&p, &sig).unwrap();
        ctx.check_synthetic_for_test(
            &build,
            &[2; 32],
            Sample {
                system_seconds: Some(120),
                monotonic_ms: 1,
            },
        )
        .unwrap();
        assert_eq!(
            ctx.check_synthetic_for_test(&build, &[2; 32], sample),
            Err(Error::Clock)
        );
        ctx.deliver_policy(&p, &sig).unwrap();
        assert_eq!(
            ctx.check_synthetic_for_test(
                &build,
                &[2; 32],
                Sample {
                    system_seconds: Some(130),
                    monotonic_ms: 3
                }
            ),
            Err(Error::Clock)
        );
    }
}

#[test]
fn invalid_and_conflicting_deliveries_do_not_write_or_mutate_floor() {
    let mem = Arc::new(Mutex::new((StoredState::Fresh, 0, false)));
    let ctx = context(&mem);
    let (first, sig, build) = signed(2);
    assert_eq!(
        ctx.deliver_policy(&first, &[0; 64]),
        Err(Error::Policy(bh_confidential_policy::Error::Signature))
    );
    assert_eq!(mem.lock().unwrap().1, 0);
    ctx.deliver_policy(&first, &sig).unwrap();
    let (lower, lower_sig, _) = signed(1);
    assert_eq!(
        ctx.deliver_policy(&lower, &lower_sig),
        Err(Error::Policy(bh_confidential_policy::Error::PolicyRollback))
    );
    let changed = [first.as_slice(), b" "].concat();
    let changed_sig = SigningKey::from_seed(&Secret::from_slice(&[7; 32]).unwrap())
        .sign(&[b"basehero.confidential-policy.v1\0".as_slice(), &changed].concat());
    assert_eq!(
        ctx.deliver_policy(&changed, &changed_sig),
        Err(Error::Policy(
            bh_confidential_policy::Error::GenerationConflict
        ))
    );
    assert_eq!(mem.lock().unwrap().1, 1);
    ctx.check_synthetic_for_test(
        &build,
        &[2; 32],
        Sample {
            system_seconds: Some(120),
            monotonic_ms: 1,
        },
    )
    .unwrap();
}

#[test]
fn unusable_committed_successor_and_restart_before_after_commit() {
    let mem = Arc::new(Mutex::new((StoredState::Fresh, 0, false)));
    let ctx = context(&mem);
    let (p, sig, build) = signed(1);
    ctx.deliver_policy(&p, &sig).unwrap();
    let before = context(&mem);
    assert_eq!(
        before.check_synthetic_for_test(
            &build,
            &[2; 32],
            Sample {
                system_seconds: Some(120),
                monotonic_ms: 1
            }
        ),
        Err(Error::Policy(
            bh_confidential_policy::Error::PolicyUnavailable
        ))
    );
    let (mut successor, _, _) = signed(2);
    let mut policy: Policy = serde_json::from_slice(&successor).unwrap();
    policy.builds.clear();
    successor = serde_json::to_vec(&policy).unwrap();
    let successor_sig = SigningKey::from_seed(&Secret::from_slice(&[7; 32]).unwrap())
        .sign(&[b"basehero.confidential-policy.v1\0".as_slice(), &successor].concat());
    ctx.deliver_policy(&successor, &successor_sig).unwrap();
    assert_eq!(mem.lock().unwrap().1, 2);
    assert_eq!(
        ctx.check_synthetic_for_test(
            &build,
            &[2; 32],
            Sample {
                system_seconds: Some(120),
                monotonic_ms: 1
            }
        ),
        Err(Error::Policy(bh_confidential_policy::Error::BuildDenied))
    );
    assert_eq!(
        ctx.deliver_policy(&p, &sig),
        Err(Error::Policy(bh_confidential_policy::Error::PolicyRollback))
    );
    let after = context(&mem);
    assert_eq!(
        after.check_synthetic_for_test(
            &build,
            &[2; 32],
            Sample {
                system_seconds: Some(120),
                monotonic_ms: 1
            }
        ),
        Err(Error::Policy(
            bh_confidential_policy::Error::PolicyUnavailable
        ))
    );
    assert_eq!(
        after.deliver_policy(&p, &sig),
        Err(Error::Policy(bh_confidential_policy::Error::PolicyRollback))
    );
    after.deliver_policy(&successor, &successor_sig).unwrap();
    assert_eq!(mem.lock().unwrap().1, 2); // identical durable redelivery is no-write
    assert_eq!(
        after.check_synthetic_for_test(
            &build,
            &[2; 32],
            Sample {
                system_seconds: Some(120),
                monotonic_ms: 1
            }
        ),
        Err(Error::Policy(bh_confidential_policy::Error::BuildDenied))
    );
    let missing = Arc::new(Mutex::new((StoredState::Missing, 0, false)));
    assert!(matches!(
        PolicyContext::new(
            SigningKey::from_seed(&Secret::from_slice(&[7; 32]).unwrap()).public(),
            Limits {
                max_lifetime_secs: 100,
                max_uncertainty_secs: 0
            },
            100,
            Memory(missing),
            crate::test_clock::read
        ),
        Err(Error::PersistenceUnavailable)
    ));
}

#[test]
fn hello_root_role_and_nonce_are_exact_and_each_server_hello_has_new_keys() {
    use crate::handshake::{ClientHello, ServerPending};
    let mem = Arc::new(Mutex::new((StoredState::Fresh, 0, false)));
    let root = SigningKey::from_seed(&Secret::from_slice(&[7; 32]).unwrap()).public();
    let ctx = context(&mem);
    let first = ClientHello::new({
        crate::test_clock::clock_at(1);
        ctx.clone()
    })
    .unwrap();
    let second = ClientHello::new({
        crate::test_clock::clock_at(1);
        ctx
    })
    .unwrap();
    assert_ne!(first.frame(), second.frame());
    assert!(matches!(
        ServerPending::<Memory>::accept_hello(first.frame(), [9; 32], 1),
        Err(Error::Authentication)
    ));
    let mut wrong_role = first.frame().to_vec();
    wrong_role[43] = 2;
    assert!(matches!(
        ServerPending::<Memory>::accept_hello(&wrong_role, root, 1),
        Err(Error::Frame)
    ));
    let s1 = ServerPending::<Memory>::accept_hello(first.frame(), root, 1).unwrap();
    let s2 = ServerPending::<Memory>::accept_hello(first.frame(), root, 1).unwrap();
    assert_ne!(s1.report_data(), s2.report_data());
    let mut changed_nonce = first.frame().to_vec();
    changed_nonce[11] ^= 1;
    let s3 = ServerPending::<Memory>::accept_hello(&changed_nonce, root, 1).unwrap();
    assert_ne!(s1.report_data(), s3.report_data());
}

#[test]
fn hello_authenticates_only_peers_built_in_the_same_flag_mode() {
    use crate::handshake::{ClientHello, ServerPending};
    let mem = Arc::new(Mutex::new((StoredState::Fresh, 0, false)));
    let root = SigningKey::from_seed(&Secret::from_slice(&[7; 32]).unwrap()).public();
    crate::test_clock::clock_at(1);
    let hello = ClientHello::new(context(&mem)).unwrap();
    assert!(ServerPending::<Memory>::accept_hello(hello.frame(), root, 1).is_ok());
    let mut other_mode = hello.frame().to_vec();
    let flagged_root = bh_crypto::hash(
        &[
            b"bh flags root v1\0".as_slice(),
            &root,
            &bh_crypto::hash(b"removal wait\x005 minutes\0"),
        ]
        .concat(),
    );
    let opposite = if bh_flags::off_default().is_empty() {
        flagged_root
    } else {
        root
    };
    other_mode[44..76].copy_from_slice(&bh_crypto::hash(&opposite));
    assert!(matches!(
        ServerPending::<Memory>::accept_hello(&other_mode, root, 1),
        Err(Error::Authentication)
    ));
    if bh_flags::off_default().is_empty() {
        assert_eq!(&hello.frame()[44..76], &bh_crypto::hash(&root));
    } else {
        assert_eq!(&hello.frame()[44..76], &bh_crypto::hash(&flagged_root));
    }
}

#[test]
fn synthetic_five_messages_and_bidirectional_records() {
    use crate::{
        handshake::{ClientHello, ServerPending},
        record::Opened,
    };
    use bh_crypto::SecretBytes;
    let mem = Arc::new(Mutex::new((StoredState::Fresh, 0, false)));
    let ctx = context(&mem);
    let root = SigningKey::from_seed(&Secret::from_slice(&[7; 32]).unwrap()).public();
    let client = ClientHello::new({
        crate::test_clock::clock_at(100);
        ctx.clone()
    })
    .unwrap();
    let hello = client.frame().to_vec();
    let server = ServerPending::<Memory>::accept_hello(&hello, root, 100).unwrap();
    assert_ne!(server.report_data(), [0; 64]);
    let (policy, sig, build) = signed(1);
    let (proof, server) = server
        .attach_evidence(&policy, &sig, b"quote", b"collateral", b"log", 101)
        .unwrap();
    let checked = client
        .at(Sample {
            system_seconds: Some(120),
            monotonic_ms: 102,
        })
        .synthetic_checked(&proof, build, [2; 32])
        .unwrap();
    let (encapsulation, pending) = checked
        .at(Sample {
            system_seconds: Some(120),
            monotonic_ms: 103,
        })
        .encapsulate()
        .unwrap();
    let (server_finish, pending_server) = server.accept_encapsulation(&encapsulation, 104).unwrap();
    let (client_finish, mut c) = pending
        .at(Sample {
            system_seconds: Some(120),
            monotonic_ms: 105,
        })
        .accept_finish(&server_finish)
        .unwrap();
    let mut s = pending_server
        .accept_finish(&client_finish, crate::test_clock::clock_at(106))
        .unwrap();
    // Reconstruct both hashes without calling the channel's transcript/binding helpers.
    let expected_t = bh_crypto::hash(
        &[
            b"basehero.checker-channel.v1\0".as_slice(),
            b"transcript\0",
            &hello,
            &proof,
            &encapsulation,
        ]
        .concat(),
    );
    let expected_signature_input = [
        b"basehero.checker-channel.v1\0".as_slice(),
        b"server-signature\0",
        &expected_t,
    ]
    .concat();
    let (_, proof_body) = crate::wire::parse(&proof).unwrap();
    let signing = crate::wire::proof(proof_body).unwrap().signing;
    bh_crypto::verify(
        &signing,
        &expected_signature_input,
        &server_finish[11..75].try_into().unwrap(),
    )
    .unwrap();
    let expected_b = bh_crypto::hash(
        &[
            b"basehero.checker-channel.v1\0".as_slice(),
            b"binding\0",
            &expected_t,
            &server_finish,
            &client_finish,
        ]
        .concat(),
    );
    assert_eq!(c.binding().unwrap(), expected_b);
    assert_eq!(s.binding().unwrap(), expected_b);
    let outbound = c
        .at(Sample {
            system_seconds: Some(120),
            monotonic_ms: 107,
        })
        .seal(SecretBytes::from_vec(b"hello".to_vec()))
        .unwrap();
    match s
        .at(Sample {
            system_seconds: None,
            monotonic_ms: 107,
        })
        .open(&outbound)
        .unwrap()
    {
        Opened::Data(bytes) => assert_eq!(bytes.expose(), b"hello"),
        Opened::Closed => panic!("unexpected close"),
    }
    let reply = s
        .at(Sample {
            system_seconds: None,
            monotonic_ms: 108,
        })
        .seal(SecretBytes::from_vec(b"world".to_vec()))
        .unwrap();
    match c
        .at(Sample {
            system_seconds: Some(120),
            monotonic_ms: 108,
        })
        .open(&reply)
        .unwrap()
    {
        Opened::Data(bytes) => assert_eq!(bytes.expose(), b"world"),
        Opened::Closed => panic!("unexpected close"),
    }
    assert!(matches!(
        s.at(Sample {
            system_seconds: None,
            monotonic_ms: 109
        })
        .open(&outbound),
        Err(Error::Sequence)
    ));
    assert!(s.is_closed());
    assert_eq!(s.binding(), Err(Error::Order));
    assert_eq!(
        c.at(Sample {
            system_seconds: Some(120),
            monotonic_ms: 107
        })
        .seal(SecretBytes::from_vec(b"rollback".to_vec()))
        .err(),
        Some(Error::Clock)
    );
    assert!(c.is_closed());
    assert_eq!(c.binding(), Err(Error::Order));
    ctx.deliver_policy(&policy, &sig).unwrap();
    // Hello now takes the same qualified locked clock, so the shared latch
    // refuses earlier than the old proof-only sample entry point.
    assert!(matches!(
        ClientHello::new({
            crate::test_clock::clock_at(110);
            ctx.clone()
        }),
        Err(Error::Clock)
    ));
    assert_eq!(
        ctx.check_synthetic_for_test(
            &signed(1).2,
            &[2; 32],
            Sample {
                system_seconds: Some(120),
                monotonic_ms: 112
            }
        ),
        Err(Error::Clock)
    );
}

#[test]
fn handshake_local_rollback_latches_shared_context() {
    use crate::handshake::{ClientHello, ServerPending};
    let mem = Arc::new(Mutex::new((StoredState::Fresh, 0, false)));
    let ctx = context(&mem);
    let (policy, sig, build) = signed(1);
    ctx.deliver_policy(&policy, &sig).unwrap();
    ctx.check_synthetic_for_test(
        &build,
        &[2; 32],
        Sample {
            system_seconds: Some(120),
            monotonic_ms: 101,
        },
    )
    .unwrap();
    let root = SigningKey::from_seed(&Secret::from_slice(&[7; 32]).unwrap()).public();
    let hello = ClientHello::new({
        crate::test_clock::clock_at(102);
        ctx.clone()
    })
    .unwrap();
    let server = ServerPending::<Memory>::accept_hello(hello.frame(), root, 102).unwrap();
    let (proof, _) = server
        .attach_evidence(&policy, &sig, b"q", b"c", b"l", 102)
        .unwrap();
    assert!(matches!(
        hello
            .at(Sample {
                system_seconds: Some(120),
                monotonic_ms: 101
            })
            .synthetic_checked(&proof, build.clone(), [2; 32]),
        Err(Error::Clock)
    ));
    ctx.deliver_policy(&policy, &sig).unwrap();
    assert_eq!(
        ctx.check_synthetic_for_test(
            &build,
            &[2; 32],
            Sample {
                system_seconds: Some(120),
                monotonic_ms: 103
            }
        ),
        Err(Error::Clock)
    );
}

#[test]
fn different_valid_kem_ciphertext_reaches_signature_gate() {
    use crate::handshake::{ClientHello, ServerPending};
    let mem = Arc::new(Mutex::new((StoredState::Fresh, 0, false)));
    let ctx = context(&mem);
    let root = SigningKey::from_seed(&Secret::from_slice(&[7; 32]).unwrap()).public();
    let client = ClientHello::new({
        crate::test_clock::clock_at(100);
        ctx
    })
    .unwrap();
    let server = ServerPending::<Memory>::accept_hello(client.frame(), root, 100).unwrap();
    let (policy, sig, build) = signed(1);
    let (proof, server) = server
        .attach_evidence(&policy, &sig, b"q", b"c", b"l", 101)
        .unwrap();
    let checked = client
        .at(Sample {
            system_seconds: Some(120),
            monotonic_ms: 102,
        })
        .synthetic_checked(&proof, build, [2; 32])
        .unwrap();
    let (original, pending) = checked
        .at(Sample {
            system_seconds: Some(120),
            monotonic_ms: 103,
        })
        .encapsulate()
        .unwrap();
    let (_, body) = crate::wire::parse(&proof).unwrap();
    let receiving = crate::wire::proof(body).unwrap().receiving;
    let (alternate, _) = bh_crypto::encapsulate(&receiving).unwrap();
    let alternate = crate::wire::frame(3, &alternate).unwrap();
    assert_ne!(original, alternate);
    // This is a valid KEM ciphertext: decapsulation and server Finish succeed.
    // But it is not the ciphertext committed by the client's actual transition.
    let (finish, _) = server.accept_encapsulation(&alternate, 104).unwrap();
    assert!(matches!(
        pending
            .at(Sample {
                system_seconds: Some(120),
                monotonic_ms: 105
            })
            .accept_finish(&finish),
        Err(Error::Authentication)
    ));
}

#[test]
fn pending_outage_between_records_closes_without_plaintext() {
    use crate::{
        handshake::{ClientHello, ServerPending},
        record::Opened,
    };
    use bh_crypto::SecretBytes;
    let mem = Arc::new(Mutex::new((StoredState::Fresh, 0, false)));
    let ctx = context(&mem);
    let root = SigningKey::from_seed(&Secret::from_slice(&[7; 32]).unwrap()).public();
    let client = ClientHello::new({
        crate::test_clock::clock_at(100);
        ctx.clone()
    })
    .unwrap();
    let server = ServerPending::<Memory>::accept_hello(client.frame(), root, 100).unwrap();
    let (p, sig, build) = signed(1);
    let (proof, server) = server
        .attach_evidence(&p, &sig, b"q", b"c", b"l", 100)
        .unwrap();
    let checked = client
        .at(Sample {
            system_seconds: Some(120),
            monotonic_ms: 101,
        })
        .synthetic_checked(&proof, build, [2; 32])
        .unwrap();
    let (enc, pending) = checked
        .at(Sample {
            system_seconds: Some(120),
            monotonic_ms: 102,
        })
        .encapsulate()
        .unwrap();
    let (finish, server) = server.accept_encapsulation(&enc, 103).unwrap();
    let (finish_c, mut client) = pending
        .at(Sample {
            system_seconds: Some(120),
            monotonic_ms: 104,
        })
        .accept_finish(&finish)
        .unwrap();
    let mut server = server
        .accept_finish(&finish_c, crate::test_clock::clock_at(104))
        .unwrap();
    let first = server
        .at(Sample {
            system_seconds: None,
            monotonic_ms: 105,
        })
        .seal(SecretBytes::from_vec(b"first".to_vec()))
        .unwrap();
    assert!(matches!(
        client
            .at(Sample {
                system_seconds: Some(120),
                monotonic_ms: 105
            })
            .open(&first),
        Ok(Opened::Data(_))
    ));
    let second = server
        .at(Sample {
            system_seconds: None,
            monotonic_ms: 106,
        })
        .seal(SecretBytes::from_vec(b"secret".to_vec()))
        .unwrap();
    let (next, next_sig, _) = signed(2);
    mem.lock().unwrap().2 = true;
    assert_eq!(
        ctx.deliver_policy(&next, &next_sig),
        Err(Error::PersistenceUnavailable)
    );
    assert_eq!(ctx.mark_unavailable(), Err(Error::PersistenceUnavailable));
    mem.lock().unwrap().2 = false;
    ctx.resolve_pending().unwrap();
    assert!(matches!(
        client
            .at(Sample {
                system_seconds: Some(120),
                monotonic_ms: 106
            })
            .open(&second),
        Err(Error::Policy(
            bh_confidential_policy::Error::PolicyUnavailable
        ))
    ));
    assert!(client.is_closed());
    assert_eq!(client.binding(), Err(Error::Order));
}

#[test]
fn saved_archived_quote_is_not_a_fresh_matching_checker_proof() {
    use crate::handshake::{ClientHello, ServerPending};
    let quote = include_bytes!("../../confidential-attestation/tests/fixtures/tdx_quote");
    let collateral =
        include_bytes!("../../confidential-attestation/tests/fixtures/tdx_quote_collateral.json");
    let log = b"[]";
    let mem = Arc::new(Mutex::new((StoredState::Fresh, 0, false)));
    let ctx = context(&mem);
    let root = SigningKey::from_seed(&Secret::from_slice(&[7; 32]).unwrap()).public();
    let client = ClientHello::new({
        crate::test_clock::clock_at(100);
        ctx
    })
    .unwrap();
    let server = ServerPending::<Memory>::accept_hello(client.frame(), root, 100).unwrap();
    let (p, sig, _) = signed(1);
    let (proof, _) = server
        .attach_evidence(&p, &sig, quote, collateral, log, 100)
        .unwrap();
    assert_eq!(
        client
            .at(Sample {
                system_seconds: Some(1_751_328_000),
                monotonic_ms: 101
            })
            .accept_proof(&proof)
            .err(),
        Some(Error::Attestation(crate::attestation::Error::Binding))
    );
    assert_eq!(mem.lock().unwrap().1, 1); // persisted despite subsequent hardware refusal
}

#[test]
#[ignore = "local cost probe, not a hardware or deployed throughput test"]
fn local_crypto_and_archived_qvl_cost_probe() {
    use bh_crypto::{KemKey, SecretBytes};
    use std::time::Instant;
    let rounds = 50;
    let start = Instant::now();
    for _ in 0..rounds {
        let signing = SigningKey::generate();
        let receiving = KemKey::generate();
        let (ct, shared) = bh_crypto::encapsulate(&receiving.public()).unwrap();
        assert_eq!(
            bh_crypto::decapsulate(&receiving, &ct).unwrap().expose(),
            shared.expose()
        );
        let message = signing.sign(b"handshake");
        bh_crypto::verify(&signing.public(), b"handshake", &message).unwrap();
    }
    println!(
        "synthetic local Ed25519 + X-Wing keygen/encap/decap per handshake: {:.1} us",
        start.elapsed().as_micros() as f64 / rounds as f64
    );
    let key = Secret::random();
    for len in [1, 65_536] {
        let message = SecretBytes::from_vec(vec![7; len]);
        let start = Instant::now();
        for _ in 0..rounds {
            let (nonce, ct) = bh_crypto::aead_seal(&key, b"record", message.expose()).unwrap();
            let opened = bh_crypto::aead_open(&key, &nonce, b"record", &ct).unwrap();
            assert_eq!(opened.expose(), message.expose());
        }
        println!(
            "synthetic local {len}-byte AEAD seal/open per pair: {:.1} us",
            start.elapsed().as_micros() as f64 / rounds as f64
        );
    }
    let quote = include_bytes!("../../confidential-attestation/tests/fixtures/tdx_quote");
    let collateral =
        include_bytes!("../../confidential-attestation/tests/fixtures/tdx_quote_collateral.json");
    let time = bh_confidential_attestation::Time {
        earliest: 1_751_328_000,
        latest: 1_751_328_000,
        max_uncertainty_secs: 0,
    };
    let start = Instant::now();
    for _ in 0..rounds {
        bh_confidential_attestation::quote_claims_with_policy(quote, collateral, time, |now| {
            dcap_qvl::QuotePolicy::strict(now)
                .allow_smt(true)
                .allow_dynamic_platform(true)
                .allow_cached_keys(true)
        })
        .unwrap();
    }
    println!(
        "archived 2025 standalone valid QVL quote/collateral only (unmatched keys/log), per check: {:.1} us",
        start.elapsed().as_micros() as f64 / rounds as f64
    );
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../confidential-attestation/tests/fixtures/tdx-lite-getquote.json"
    ))
    .unwrap();
    let log = fixture["event_log"].as_str().unwrap();
    let start = Instant::now();
    for _ in 0..rounds {
        let events: serde_json::Value = serde_json::from_str(log).unwrap();
        assert!(events.as_array().is_some());
    }
    println!(
        "separate archived dstack event-log JSON parser only ({size} bytes, unmatched to QVL quote), per parse: {:.1} us",
        start.elapsed().as_micros() as f64 / rounds as f64,
        size = log.len()
    );
}

#[test]
fn save_precedes_use_and_failed_save_poison_is_shared() {
    let mem = Arc::new(Mutex::new((StoredState::Fresh, 0, false)));
    let ctx = context(&mem);
    let other = ctx.clone();
    let (p, sig, b) = signed(1);
    ctx.deliver_policy(&p, &sig).unwrap();
    assert_eq!(mem.lock().unwrap().1, 1);
    ctx.check_synthetic_for_test(
        &b,
        &[2; 32],
        Sample {
            system_seconds: Some(120),
            monotonic_ms: 100,
        },
    )
    .unwrap();
    let (p2, sig2, _) = signed(2);
    mem.lock().unwrap().2 = true;
    assert_eq!(
        ctx.deliver_policy(&p2, &sig2),
        Err(Error::PersistenceUnavailable)
    );
    assert_eq!(ctx.mark_unavailable(), Err(Error::PersistenceUnavailable));
    assert_eq!(
        other.check_synthetic_for_test(
            &b,
            &[2; 32],
            Sample {
                system_seconds: Some(120),
                monotonic_ms: 101
            }
        ),
        Err(Error::PersistenceUnavailable)
    );
    mem.lock().unwrap().2 = false;
    ctx.resolve_pending().unwrap();
    {
        let state = mem.lock().unwrap();
        assert_eq!(state.1, 3); // N save, failed N+1 save, resolved N+1 save
        let StoredState::Committed(snapshot) = &state.0 else {
            panic!("pending candidate not committed")
        };
        assert_eq!(snapshot.payload(), p2);
    }
    assert_eq!(
        ctx.check_synthetic_for_test(
            &b,
            &[2; 32],
            Sample {
                system_seconds: Some(120),
                monotonic_ms: 102
            }
        ),
        Err(Error::Policy(
            bh_confidential_policy::Error::PolicyUnavailable
        ))
    ); // the outage persists after successful storage resolution
    assert_eq!(
        ctx.deliver_policy(&p, &sig),
        Err(Error::Policy(bh_confidential_policy::Error::PolicyRollback))
    );
    ctx.deliver_policy(&p2, &sig2).unwrap(); // fresh authenticated redelivery
    ctx.check_synthetic_for_test(
        &b,
        &[2; 32],
        Sample {
            system_seconds: Some(120),
            monotonic_ms: 103,
        },
    )
    .unwrap();
    assert_eq!(mem.lock().unwrap().1, 3); // identical durable redelivery does not save
    let restored = context(&mem);
    assert_eq!(
        restored.check_synthetic_for_test(
            &b,
            &[2; 32],
            Sample {
                system_seconds: Some(120),
                monotonic_ms: 102
            }
        ),
        Err(Error::Policy(
            bh_confidential_policy::Error::PolicyUnavailable
        ))
    );
    restored.deliver_policy(&p2, &sig2).unwrap();
    assert_eq!(mem.lock().unwrap().1, 3);
}
