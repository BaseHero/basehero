use bh_crypto::{Secret, SigningKey, verify as verify_signature};
use bh_sync::permit::verify_published_ordering;
use bh_sync::permit::{self, AppendAck, LogId, LogKind, Permit, PermitError, Scope};
use bh_sync::receipt;
use bh_sync::{Digest, EventId, Head};

#[test]
fn published_ordering_proof_requires_root_route_descriptor_receipt_and_exact_head() {
    use bh_sync::{BaseId, Commitment, OpaqueEvent, OrderState, Route};
    let genesis = OpaqueEvent::new(EventId([1; 32]), vec![2; 1024]).unwrap();
    let base = BaseId(genesis.digest().0);
    let genesis_order =
        Commitment::order(base, OrderState::EMPTY, &genesis, Route::Control).unwrap();
    let event = OpaqueEvent::new(EventId([2; 32]), vec![3; 1024]).unwrap();
    let commitment =
        Commitment::order(base, genesis_order.after(), &event, Route::Content).unwrap();
    let cert = receipt::verify_certificate(
        &key(1).public(),
        &receipt::certify(&key(1), key(2).public()),
    )
    .unwrap();
    let signed = receipt::sign(&cert, &key(2), base, commitment.head()).unwrap();
    let log = LogId {
        kind: LogKind::Base,
        id: base.0,
    };
    let ack = AppendAck {
        log,
        event: event.publication_id(Route::Content),
        head: commitment.head(),
        receipt: Some(signed),
    };
    let check = |ack: &AppendAck, event: &OpaqueEvent, bytes: &[u8]| {
        verify_published_ordering(&key(1).public(), log, event, &ack.encode(), bytes)
    };
    assert_eq!(check(&ack, &event, &commitment.encode()), Ok(commitment));
    assert!(
        verify_published_ordering(
            &key(9).public(),
            log,
            &event,
            &ack.encode(),
            &commitment.encode()
        )
        .is_err()
    );
    assert!(
        verify_published_ordering(
            &key(1).public(),
            LogId { id: [9; 32], ..log },
            &event,
            &ack.encode(),
            &commitment.encode()
        )
        .is_err()
    );
    assert!(
        verify_published_ordering(
            &key(1).public(),
            LogId {
                kind: LogKind::Account,
                ..log
            },
            &event,
            &ack.encode(),
            &commitment.encode()
        )
        .is_err()
    );
    let mut missing = ack.clone();
    missing.receipt = None;
    assert!(check(&missing, &event, &commitment.encode()).is_err());
    let mut wrong_head = ack.clone();
    wrong_head.head.hash.0[0] ^= 1;
    assert!(check(&wrong_head, &event, &commitment.encode()).is_err());
    let mut wrong_event = ack.clone();
    wrong_event.event.0[0] ^= 1;
    assert!(check(&wrong_event, &event, &commitment.encode()).is_err());
    let other = OpaqueEvent::new(EventId([3; 32]), vec![4; 1024]).unwrap();
    assert!(check(&ack, &other, &commitment.encode()).is_err());
    let mut bad_receipt = ack.clone();
    bad_receipt.receipt.as_mut().unwrap()[299] ^= 1;
    assert!(check(&bad_receipt, &event, &commitment.encode()).is_err());
    let mut changed = commitment.encode();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(check(&ack, &event, &changed).is_err());
    let mut wrong_previous = commitment.encode();
    wrong_previous[45] ^= 1;
    assert!(check(&ack, &event, &wrong_previous).is_err());
    assert!(check(&ack, &event, &genesis_order.encode()).is_err());
    let mut noncanonical = commitment.encode();
    noncanonical.push(0);
    assert!(check(&ack, &event, &noncanonical).is_err());
}

#[test]
fn directory_and_retire_scopes_round_trip_and_refuse_base_logs() {
    let account = LogId {
        kind: LogKind::Account,
        id: [3; 32],
    };
    for scope in [
        Scope::ReadDirectory { log: account },
        Scope::StoreDirectoryEntry {
            log: account,
            entry: [4; 32],
            version: 7,
            body: Digest([5; 32]),
            len: 1024,
        },
        Scope::RetireHomeObjects {
            log: account,
            prefix_digest: Digest([6; 32]),
        },
    ] {
        let p = permit(scope.clone());
        assert_eq!(permit::verify(key(1).public(), &signed(&p), 1000), Ok(p));
        let base_scope = match scope {
            Scope::ReadDirectory { .. } => Scope::ReadDirectory { log: log() },
            Scope::StoreDirectoryEntry {
                entry,
                version,
                body,
                len,
                ..
            } => Scope::StoreDirectoryEntry {
                log: log(),
                entry,
                version,
                body,
                len,
            },
            Scope::RetireHomeObjects { prefix_digest, .. } => Scope::RetireHomeObjects {
                log: log(),
                prefix_digest,
            },
            _ => unreachable!(),
        };
        assert_eq!(
            permit::verify(key(1).public(), &signed(&permit(base_scope)), 1000),
            Err(PermitError::Bounds)
        );
    }
}

#[test]
fn bounded_control_scope_roundtrip_and_strict_decoding() {
    let p = permit(Scope::ReadControlRange {
        log: log(),
        after: 1,
        through: (1 << 53) - 1,
    });
    let bytes = signed(&p);
    assert_eq!(bytes[132], 14);
    assert_eq!(permit::verify(key(1).public(), &bytes, 1000), Ok(p));
    let internal = permit(Scope::ReadControls {
        log: log(),
        after: 1,
    });
    assert_eq!(signed(&internal)[132], 6);
    for invalid in [
        Scope::ReadControlRange {
            log: log(),
            after: 2,
            through: 1,
        },
        Scope::ReadControlRange {
            log: log(),
            after: 0,
            through: 1 << 53,
        },
        Scope::ReadControlRange {
            log: log(),
            after: 1 << 53,
            through: 1 << 53,
        },
    ] {
        assert_eq!(
            permit::verify(key(1).public(), &signed(&permit(invalid)), 1000),
            Err(PermitError::Bounds)
        );
    }
    let body_end = bytes.len() - 64;
    let mut trailing = bytes.clone();
    trailing.insert(body_end, 0);
    assert_eq!(
        permit::verify(key(1).public(), &trailing, 1000),
        Err(PermitError::Encoding)
    );
    let mut truncated = bytes.clone();
    truncated.remove(body_end - 1);
    assert_eq!(
        permit::verify(key(1).public(), &truncated, 1000),
        Err(PermitError::Encoding)
    );
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_seed(&Secret::from_slice(&[byte; 32]).unwrap())
}
fn log() -> LogId {
    LogId {
        kind: LogKind::Base,
        id: [3; 32],
    }
}
fn permit(scope: Scope) -> Permit {
    Permit {
        scope,
        issued_ms: 1000,
        deadline_ms: 31_000,
        batch: [4; 16],
    }
}
fn signed(permit: &Permit) -> Vec<u8> {
    permit::sign(&key(2), &permit::certify(&key(1), key(2).public()), permit)
}

#[test]
fn permit_certificate_verifier_is_role_specific() {
    let root = key(1).public();
    let leaf = key(2).public();
    let cert = permit::certify(&key(1), leaf);
    let verified = permit::verify_certificate(&root, &cert).unwrap();
    assert_eq!(verified.as_bytes(), &cert);
    assert_eq!(verified.public_key(), leaf);
    assert_eq!(format!("{verified:?}"), "CertifiedPermitKey");
    assert!(matches!(
        permit::verify_certificate(&key(3).public(), &cert),
        Err(PermitError::Certificate)
    ));
    for offset in [2, 34, 66] {
        let mut bad = cert;
        bad[offset] ^= 1;
        assert!(
            permit::verify_certificate(&root, &bad).is_err(),
            "byte {offset}"
        );
    }
    let mut bad_version = cert;
    bad_version[1] = 2;
    assert!(matches!(
        permit::verify_certificate(&root, &bad_version),
        Err(PermitError::Version)
    ));
    assert!(matches!(
        permit::verify_certificate(&root, &cert[..129]),
        Err(PermitError::Encoding)
    ));
    assert!(matches!(
        permit::verify_certificate(&root, &[cert.as_slice(), &[0]].concat()),
        Err(PermitError::Encoding)
    ));
    assert!(matches!(
        permit::verify_certificate(&root, &receipt::certify(&key(1), leaf)),
        Err(PermitError::Certificate)
    ));
}

#[test]
fn permit_roundtrip_and_verify() {
    let p = permit(Scope::Append {
        log: log(),
        event: Digest([5; 32]),
        body: Some(Digest([6; 32])),
        epoch: [7; 32],
        after: Some(Head {
            position: 8,
            hash: Digest([9; 32]),
        }),
        attached: None,
    });
    let bytes = signed(&p);
    assert_eq!(permit::verify(key(1).public(), &bytes, p.issued_ms), Ok(p));
    assert_eq!(
        bytes.len(),
        130 + 2 + 1 + 33 + 32 + 1 + 32 + 32 + 1 + 40 + 1 + 8 + 8 + 16 + 64
    );
    let cert = permit::certify(&key(1), key(2).public());
    assert_eq!(&bytes[..130], &cert);
    assert_eq!(&cert[..2], &[0, 1]);
    verify_signature(
        &key(1).public(),
        &[b"bh/permit-key/v1\0".as_slice(), &cert[..66]].concat(),
        &cert[66..130].try_into().unwrap(),
    )
    .unwrap();
    verify_signature(
        &key(2).public(),
        &[b"bh/permit/v1\0".as_slice(), &bytes[130..bytes.len() - 64]].concat(),
        &bytes[bytes.len() - 64..].try_into().unwrap(),
    )
    .unwrap();
}

#[test]
fn permit_rejects_expired() {
    let p = permit(Scope::Subscribe { log: log() });
    assert_eq!(
        permit::verify(key(1).public(), &signed(&p), p.deadline_ms),
        Err(PermitError::Expired)
    );
}
#[test]
fn permit_rejects_window_over_30s() {
    let mut p = permit(Scope::Subscribe { log: log() });
    p.deadline_ms += 1;
    assert_eq!(
        permit::verify(key(1).public(), &signed(&p), p.issued_ms),
        Err(PermitError::Window)
    );
}
#[test]
fn permit_rejects_other_root() {
    let p = permit(Scope::Subscribe { log: log() });
    assert_eq!(
        permit::verify(key(3).public(), &signed(&p), p.issued_ms),
        Err(PermitError::Certificate)
    );
}
#[test]
fn permit_read_bounds() {
    for scope in [
        Scope::ReadEvents {
            log: log(),
            first: 1,
            last: 65,
        },
        Scope::ReadEvents {
            log: log(),
            first: 0,
            last: 0,
        },
        Scope::ReadEvents {
            log: log(),
            first: 3,
            last: 2,
        },
        Scope::ReadBodies {
            log: log(),
            bodies: vec![],
        },
        Scope::ReadBodies {
            log: log(),
            bodies: vec![Digest([1; 32]); 65],
        },
    ] {
        let p = permit(scope);
        assert_eq!(
            permit::verify(key(1).public(), &signed(&p), p.issued_ms),
            Err(PermitError::Bounds)
        );
    }
    for scope in [
        Scope::ReadEvents {
            log: log(),
            first: 1,
            last: 64,
        },
        Scope::ReadBodies {
            log: log(),
            bodies: vec![Digest([2; 32]); 64],
        },
    ] {
        let p = permit(scope);
        assert_eq!(
            permit::verify(key(1).public(), &signed(&p), p.issued_ms),
            Ok(p)
        );
    }
}
#[test]
fn permit_read_controls_roundtrip_and_bounds() {
    // A control read starts after a control head; `after = 0` is the empty
    // head, so the first read includes the genesis at position 1.
    let account = LogId {
        kind: LogKind::Account,
        id: [6; 32],
    };
    for (log, after) in [(log(), 0), (log(), 1), (log(), 64), (account, u64::MAX)] {
        let p = permit(Scope::ReadControls { log, after });
        let bytes = signed(&p);
        // certificate || version || tag 6 || log || after || times || batch || signature
        assert_eq!(bytes.len(), 130 + 2 + 1 + 33 + 8 + 16 + 16 + 64);
        assert_eq!(bytes[132], 6);
        assert_eq!(bytes[133], log.kind as u8);
        assert_eq!(bytes[134..166], log.id);
        assert_eq!(bytes[166..174], after.to_be_bytes());
        let verified = permit::verify(key(1).public(), &bytes, p.issued_ms).unwrap();
        assert_eq!(verified, p);
        for n in 0..bytes.len() {
            assert!(permit::verify(key(1).public(), &bytes[..n], p.issued_ms).is_err());
        }
    }
    assert_eq!(
        format!(
            "{:?}",
            Scope::ReadControls {
                log: log(),
                after: 7
            }
        ),
        "ReadControls"
    );
}
#[test]
fn receipt_cert_not_permit_cert() {
    let p = permit(Scope::Subscribe { log: log() });
    let mut bytes = signed(&p);
    bytes[..130].copy_from_slice(&receipt::certify(&key(1), key(2).public()));
    assert_eq!(
        permit::verify(key(1).public(), &bytes, p.issued_ms),
        Err(PermitError::Certificate)
    );
}
#[test]
fn permit_rejects_mutations_and_extra_bytes() {
    let p = permit(Scope::Stage {
        log: log(),
        body: Digest([5; 32]),
        len: 1024,
    });
    let bytes = signed(&p);
    for n in 0..bytes.len() {
        assert!(
            permit::verify(key(1).public(), &bytes[..n], p.issued_ms).is_err(),
            "truncated at {n}"
        );
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(
        permit::verify(key(1).public(), &extra, p.issued_ms),
        Err(PermitError::Encoding)
    );
    let mut corrupt = bytes.clone();
    corrupt[140] ^= 1;
    assert_eq!(
        permit::verify(key(1).public(), &corrupt, p.issued_ms),
        Err(PermitError::Signature)
    );
    let mut version = bytes;
    version[131] = 2;
    assert_eq!(
        permit::verify(key(1).public(), &version, p.issued_ms),
        Err(PermitError::Version)
    );
}
#[test]
fn debug_redacts_log_id_batch_and_digests() {
    let log = LogId {
        kind: LogKind::Account,
        id: [0xab; 32],
    };
    let scopes = [
        Scope::ReadEvents {
            log,
            first: 1,
            last: 1,
        },
        Scope::ReadBodies {
            log,
            bodies: vec![Digest([0xef; 32])],
        },
        Scope::Stage {
            log,
            body: Digest([0xef; 32]),
            len: 1024,
        },
        Scope::Append {
            log,
            event: Digest([0xef; 32]),
            body: Some(Digest([0xef; 32])),
            epoch: [0xef; 32],
            after: Some(Head {
                position: 1,
                hash: Digest([0xef; 32]),
            }),
            attached: None,
        },
        Scope::Subscribe { log },
    ];
    let mut output = format!("{log:?}");
    for scope in &scopes {
        output.push_str(&format!("{scope:?}"));
    }
    let p = Permit {
        scope: scopes[3].clone(),
        issued_ms: 1,
        deadline_ms: 2,
        batch: [0xcd; 16],
    };
    output.push_str(&format!("{p:?}"));
    let ack = AppendAck {
        log,
        event: EventId([0xef; 32]),
        head: Head {
            position: 1,
            hash: Digest([0xef; 32]),
        },
        receipt: None,
    };
    output.push_str(&format!("{ack:?}"));
    for secret in [
        "ab, ab", "cd, cd", "ef, ef", "171, 171", "205, 205", "239, 239", "0xab", "0xcd", "0xef",
    ] {
        assert!(!output.contains(secret), "leaked {secret}: {output}");
    }
}

#[test]
fn append_ack_roundtrip() {
    let ack = AppendAck {
        log: log(),
        event: EventId([8; 32]),
        head: Head {
            position: 17,
            hash: Digest([9; 32]),
        },
        receipt: Some([2; receipt::RECEIPT_LEN]),
    };
    let bytes = ack.encode();
    assert_eq!(AppendAck::decode(&bytes), Ok(ack.clone()));
    assert_eq!(
        AppendAck::decode(&bytes[..bytes.len() - 1]),
        Err(PermitError::Encoding)
    );
    let mut extra = bytes;
    extra.push(0);
    assert_eq!(AppendAck::decode(&extra), Err(PermitError::Encoding));
    let account_ack = AppendAck {
        log: LogId {
            kind: LogKind::Account,
            id: [3; 32],
        },
        receipt: None,
        ..ack
    };
    assert_eq!(AppendAck::decode(&account_ack.encode()), Ok(account_ack));
}

#[test]
fn issued_time_is_read_without_trusting_it() {
    let p = permit(Scope::Stage {
        log: log(),
        body: Digest([5; 32]),
        len: 64,
    });
    let bytes = signed(&p);
    assert_eq!(permit::issued_ms(&bytes), Ok(1000));
    assert_eq!(permit::issued_ms(&bytes[..100]), Err(PermitError::Encoding));
    let mut longer = bytes.clone();
    longer.insert(140, 0);
    assert!(permit::issued_ms(&longer).is_err());
}

#[test]
fn attached_body_only_on_a_control_with_another_body() {
    let append = |body, after, attached| Scope::Append {
        log: log(),
        event: Digest([5; 32]),
        body,
        epoch: [7; 32],
        after,
        attached,
    };
    let head = Some(Head {
        position: 8,
        hash: Digest([9; 32]),
    });
    let (own, set) = (Some(Digest([6; 32])), Some(Digest([10; 32])));
    let p = permit(append(own, head, set));
    let bytes = signed(&p);
    assert_eq!(permit::verify(key(1).public(), &bytes, p.issued_ms), Ok(p));
    assert_eq!(
        bytes.len(),
        130 + 2 + 1 + 33 + 32 + 1 + 32 + 32 + 1 + 40 + 1 + 32 + 8 + 8 + 16 + 64
    );
    for (name, scope) in [
        ("content", append(own, None, set)),
        ("no body of its own", append(None, head, set)),
        ("its own body again", append(own, head, own)),
    ] {
        let p = permit(scope);
        assert_eq!(
            permit::verify(key(1).public(), &signed(&p), p.issued_ms),
            Err(PermitError::Bounds),
            "{name}"
        );
    }
}
