use bh_sync::*;

fn event(n: u8) -> OpaqueEvent {
    OpaqueEvent::new(EventId([n; 32]), vec![n; 1024]).unwrap()
}

#[test]
fn genesis_then_tail_and_body_free_verification() {
    let first = event(1);
    let base = BaseId::from_genesis(&first);
    let a = Commitment::order(base, Head::EMPTY, &first).unwrap();
    let b = Commitment::order(base, a.head(), &event(2)).unwrap();
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
        Commitment::order(BaseId([9; 32]), Head::EMPTY, &event(1)),
        Err(Error::GenesisMismatch)
    );
    assert_eq!(
        Commitment::order(
            BaseId([9; 32]),
            Head {
                position: u64::MAX,
                hash: Digest([8; 32])
            },
            &event(1)
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
}

#[test]
fn commitment_codec_detects_every_mutated_byte() {
    let e = event(1);
    let base = BaseId::from_genesis(&e);
    let c = Commitment::order(base, Head::EMPTY, &e).unwrap();
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
    let c = Commitment::order(BaseId::from_genesis(&e), Head::EMPTY, &e).unwrap();
    assert_eq!(c.encode().len(), 178);
    assert_eq!(
        c.head().hash,
        Digest([
            31, 116, 251, 92, 105, 95, 50, 46, 198, 68, 10, 141, 191, 121, 98, 172, 75, 204, 110,
            109, 2, 0, 220, 240, 150, 156, 209, 214, 9, 61, 197, 72
        ])
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
