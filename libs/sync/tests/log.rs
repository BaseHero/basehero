use bh_sync::*;

fn event(n: u8) -> OpaqueEvent {
    OpaqueEvent::new(EventId([n; 32]), vec![n; 1024]).unwrap()
}

#[test]
fn genesis_then_tail_and_body_free_verification() {
    let first = event(1);
    let base = BaseId::from_genesis(&first);
    let a = Commitment::order(base, Head::EMPTY, &first, Route::Control).unwrap();
    let b = Commitment::order(base, a.head(), &event(2), Route::Content).unwrap();
    assert_eq!(a.verify_next(base, Head::EMPTY), Ok(a.head()));
    assert_eq!(b.verify_next(base, a.head()), Ok(b.head()));
    assert!(b.verify_body(&event(2)).is_ok());
    assert_eq!(b.verify_body(&event(3)), Err(Error::BodyMismatch));
    assert_eq!(
        b.verify_next(base, Head::EMPTY),
        Err(Error::HistoryMismatch)
    );
    assert!(a.verify_next(BaseId([9; 32]), Head::EMPTY).is_err());
}

#[test]
fn invalid_genesis_and_exhausted_position_refuse() {
    assert_eq!(
        Commitment::order(BaseId([9; 32]), Head::EMPTY, &event(1), Route::Control),
        Err(Error::GenesisMismatch)
    );
    assert_eq!(
        Commitment::order(
            BaseId([9; 32]),
            Head {
                position: u64::MAX,
                hash: Digest([8; 32])
            },
            &event(1),
            Route::Content
        ),
        Err(Error::Exhausted)
    );
}

#[test]
fn canonical_event_roundtrip_and_strict_decoder() {
    let e = event(4);
    let bytes = e.encode();
    assert_eq!(OpaqueEvent::decode(&bytes), Ok(e.clone()));
    for len in 0..bytes.len() {
        assert!(OpaqueEvent::decode(&bytes[..len]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(OpaqueEvent::decode(&trailing), Err(Error::Encoding));
    let mut version = bytes.clone();
    version[1] = 2;
    assert_eq!(OpaqueEvent::decode(&version), Err(Error::Version));
    let mut size = bytes.clone();
    size[34..38].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(OpaqueEvent::decode(&size).is_err());
    for size in [0, 1, 1023, 1025, 65537] {
        assert_eq!(
            OpaqueEvent::new(EventId([1; 32]), vec![0; size]),
            Err(Error::Size)
        );
    }
    for size in [1024, 4096, 16384, 65536] {
        assert!(OpaqueEvent::new(EventId([1; 32]), vec![0; size]).is_ok());
    }
    // Only detached bodies use the classes above 64 KiB.
    for size in [262144, 1048576, 4194304] {
        assert_eq!(
            OpaqueEvent::new(EventId([1; 32]), vec![0; size]),
            Err(Error::Size)
        );
        assert!(BodyObject::new(vec![0; size]).is_ok());
    }
    for size in [0, 1023, 65537, 262143, 4194305] {
        assert_eq!(BodyObject::new(vec![0; size]), Err(Error::Size));
    }
}

#[test]
fn commitment_codec_detects_every_mutated_byte() {
    let e = event(1);
    let base = BaseId::from_genesis(&e);
    let c = Commitment::order(base, Head::EMPTY, &e, Route::Control).unwrap();
    let bytes = c.encode();
    assert_eq!(Commitment::decode(&bytes), Ok(c));
    for i in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[i] ^= 1;
        if let Ok(decoded) = Commitment::decode(&bad) {
            assert!(
                decoded.verify_next(base, Head::EMPTY).is_err(),
                "mutation at {i}"
            );
        }
    }
    assert!(Commitment::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut extra = bytes;
    extra.push(0);
    assert!(Commitment::decode(&extra).is_err());
}

#[test]
fn fixed_blake2b_256_wire_vector() {
    // Independently computed from the documented bytes, not by this codec.
    let e = event(1);
    assert_eq!(e.encode().len(), 1062);
    assert_eq!(
        e.digest(),
        Digest([
            9, 205, 254, 47, 52, 227, 111, 140, 152, 141, 91, 14, 83, 55, 23, 161, 175, 146, 91, 6,
            81, 163, 87, 65, 99, 60, 233, 241, 231, 11, 16, 240
        ])
    );
    let c = Commitment::order(BaseId::from_genesis(&e), Head::EMPTY, &e, Route::Control).unwrap();
    assert_eq!(c.encode().len(), 179);
    assert_eq!(
        c.head().hash,
        Digest([
            16, 30, 25, 203, 155, 237, 200, 13, 17, 197, 30, 72, 22, 250, 183, 65, 227, 252, 76,
            213, 168, 68, 236, 250, 215, 1, 43, 164, 112, 91, 248, 10
        ])
    );
}

/// Offset of the route byte: version, base, previous head, event id, digest.
const ROUTE_AT: usize = 2 + 32 + 8 + 32 + 32 + 32;

/// Re-hash a commitment's preceding bytes, as a sequencer that lies would.
fn rehash(bytes: &mut [u8]) {
    let mut input = b"bh/chain/v1\0".to_vec();
    input.extend_from_slice(&bytes[..ROUTE_AT + 1 + 8]);
    let hash = bh_crypto::hash(&input);
    bytes[ROUTE_AT + 1 + 8..].copy_from_slice(&hash);
}

#[test]
fn commitment_commits_route() {
    let first = event(1);
    let base = BaseId::from_genesis(&first);
    let genesis = Commitment::order(base, Head::EMPTY, &first, Route::Control).unwrap();
    let content = Commitment::order(base, genesis.head(), &event(2), Route::Content).unwrap();
    let control = Commitment::order(base, genesis.head(), &event(2), Route::Control).unwrap();
    assert_eq!(content.route(), Route::Content);
    assert_eq!(control.route(), Route::Control);
    assert_eq!(content.head().position, control.head().position);
    assert_ne!(content.head().hash, control.head().hash);
    for c in [genesis, content, control] {
        let bytes = c.encode();
        assert_eq!(bytes[ROUTE_AT], c.route() as u8);
        assert_eq!(Commitment::decode(&bytes), Ok(c));
    }
    // Relabelling an ordered event breaks its chain hash.
    let mut relabelled = content.encode();
    relabelled[ROUTE_AT] = Route::Control as u8;
    let decoded = Commitment::decode(&relabelled).unwrap();
    assert_eq!(decoded.route(), Route::Control);
    assert_eq!(
        decoded.verify_next(base, genesis.head()),
        Err(Error::HistoryMismatch)
    );
    for unknown in [2, 0x80, 0xff] {
        let mut bad = content.encode();
        bad[ROUTE_AT] = unknown;
        rehash(&mut bad);
        assert_eq!(Commitment::decode(&bad), Err(Error::Encoding));
    }
}

#[test]
fn genesis_requires_control_route() {
    let first = event(1);
    let base = BaseId::from_genesis(&first);
    assert_eq!(
        Commitment::order(base, Head::EMPTY, &first, Route::Content),
        Err(Error::GenesisMismatch)
    );
    // A content-route genesis with a consistent chain hash still refuses.
    let mut bytes = Commitment::order(base, Head::EMPTY, &first, Route::Control)
        .unwrap()
        .encode();
    bytes[ROUTE_AT] = Route::Content as u8;
    rehash(&mut bytes);
    let forged = Commitment::decode(&bytes).unwrap();
    assert_eq!(forged.route(), Route::Content);
    assert_eq!(
        forged.verify_next(base, Head::EMPTY),
        Err(Error::GenesisMismatch)
    );
}

#[test]
fn replay_identity_is_committed_and_debug_hides_body() {
    let a = event(1);
    let b = OpaqueEvent::new(EventId([2; 32]), a.envelope().to_vec()).unwrap();
    assert_ne!(a.digest(), b.digest());
    let c = OpaqueEvent::new(a.id(), vec![2; 1024]).unwrap();
    assert_ne!(a.digest(), c.digest());
    assert!(!format!("{a:?}").contains("1, 1, 1"));
}
