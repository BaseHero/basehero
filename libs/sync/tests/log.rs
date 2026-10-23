use bh_sync::*;

fn event(n: u8) -> OpaqueEvent {
    OpaqueEvent::new(EventId([n; 32]), vec![n; 1024]).unwrap()
}

#[test]
fn genesis_then_tail_and_body_free_verification() {
    let first = event(1);
    let base = BaseId::from_genesis(&first);
    let a = Commitment::order(base, OrderState::EMPTY, &first, Route::Control).unwrap();
    let b = Commitment::order(base, a.after(), &event(2), Route::Content).unwrap();
    assert_eq!(a.verify_next(base, Head::EMPTY), Ok(a.head()));
    assert_eq!(b.verify_next(base, a.head()), Ok(b.head()));
    assert_eq!(b.before(), a.after());
    assert_eq!(b.after().head(base), b.head());
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
        Commitment::order(
            BaseId([9; 32]),
            OrderState::EMPTY,
            &event(1),
            Route::Control
        ),
        Err(Error::GenesisMismatch)
    );
    let full = OrderState::new(
        RawControlHead {
            position: u64::MAX,
            node_hash: Digest([8; 32]),
        },
        0,
        Digest([0; 32]),
    )
    .unwrap();
    assert_eq!(
        Commitment::order(BaseId([9; 32]), full, &event(1), Route::Content),
        Err(Error::Exhausted)
    );
}

#[test]
fn opaque_event_roundtrip_and_strict_decoder() {
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
fn commitment_codec_detects_changed_openings_and_exact_lengths() {
    let e = event(1);
    let base = BaseId::from_genesis(&e);
    let c = Commitment::order(base, OrderState::EMPTY, &e, Route::Control).unwrap();
    let bytes = c.encode();
    assert_eq!(Commitment::decode(&bytes), Ok(c));
    for i in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[i] ^= 1;
        if let Ok(decoded) = Commitment::decode(&bad) {
            assert_ne!(decoded, c, "mutation at {i}");
            assert!(
                decoded.head() != c.head() || decoded.base() != c.base(),
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
    // Independently computed with hashlib.blake2b(digest_size=32) from the
    // documented domain strings and exact event/opening fields.
    let e = event(1);
    assert_eq!(e.encode().len(), 1062);
    assert_eq!(
        e.digest(),
        Digest([
            9, 205, 254, 47, 52, 227, 111, 140, 152, 141, 91, 14, 83, 55, 23, 161, 175, 146, 91, 6,
            81, 163, 87, 65, 99, 60, 233, 241, 231, 11, 16, 240,
        ])
    );
    let c = Commitment::order(
        BaseId::from_genesis(&e),
        OrderState::EMPTY,
        &e,
        Route::Control,
    )
    .unwrap();
    assert_eq!(c.encode().len(), 149);
    assert_eq!(
        c.head().hash,
        Digest([
            94, 49, 97, 47, 150, 141, 68, 49, 153, 239, 95, 44, 232, 43, 199, 181, 91, 203, 99,
            114, 15, 200, 144, 45, 186, 143, 217, 59, 140, 237, 117, 27,
        ])
    );
}

#[test]
fn commitment_commits_route_and_routed_identity() {
    const ROUTE_AT: usize = 2 + 32;
    let first = event(1);
    let base = BaseId::from_genesis(&first);
    let genesis = Commitment::order(base, OrderState::EMPTY, &first, Route::Control).unwrap();
    let content = Commitment::order(base, genesis.after(), &event(2), Route::Content).unwrap();
    let control = Commitment::order(base, genesis.after(), &event(2), Route::Control).unwrap();
    assert_eq!(content.route(), Route::Content);
    assert_eq!(control.route(), Route::Control);
    assert_eq!(content.head().position, control.head().position);
    assert_ne!(content.head().hash, control.head().hash);
    assert_ne!(content.event_id(), control.event_id());
    for c in [genesis, content, control] {
        let bytes = c.encode();
        assert_eq!(bytes[ROUTE_AT], c.route() as u8);
        assert_eq!(Commitment::decode(&bytes), Ok(c));
    }
    let mut relabelled = content.encode();
    relabelled[ROUTE_AT] = Route::Control as u8;
    let decoded = Commitment::decode(&relabelled).unwrap();
    assert_ne!(decoded.head(), content.head());
    assert_ne!(decoded.event_id(), content.event_id());
    for unknown in [2, 0x80, 0xff] {
        let mut bad = content.encode();
        bad[ROUTE_AT] = unknown;
        assert_eq!(Commitment::decode(&bad), Err(Error::Encoding));
    }
}

#[test]
fn genesis_requires_control_route_even_in_decoded_bytes() {
    let first = event(1);
    let base = BaseId::from_genesis(&first);
    assert_eq!(
        Commitment::order(base, OrderState::EMPTY, &first, Route::Content),
        Err(Error::GenesisMismatch)
    );
    let mut bytes = Commitment::order(base, OrderState::EMPTY, &first, Route::Control)
        .unwrap()
        .encode();
    bytes[34] = Route::Content as u8;
    assert_eq!(Commitment::decode(&bytes), Err(Error::GenesisMismatch));
}

#[test]
fn nonce_is_signed_input_not_publication_identity_and_debug_hides_body() {
    let a = event(1);
    let b = OpaqueEvent::new(EventId([2; 32]), a.envelope().to_vec()).unwrap();
    assert_ne!(a.digest(), b.digest());
    let c = OpaqueEvent::new(a.nonce(), vec![2; 1024]).unwrap();
    assert_ne!(a.digest(), c.digest());
    assert_ne!(a.publication_id(Route::Content), a.nonce());
    assert!(!format!("{a:?}").contains("1, 1, 1"));
}
