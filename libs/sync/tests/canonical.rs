use bh_sync::canonical::{
    CanonicalCommitment, CoverageError, OrderState, RawControlChain, RawControlHead, publication_id,
};
use bh_sync::{BaseId, Digest, Error, EventId, Head, OpaqueEvent, Route};

fn hex(bytes: &str) -> Vec<u8> {
    bytes
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn base() -> BaseId {
    BaseId([0x11; 32])
}
fn digest(n: u8) -> Digest {
    Digest([n; 32])
}
fn genesis() -> CanonicalCommitment {
    CanonicalCommitment::order(base(), OrderState::EMPTY, digest(0x11), Route::Control).unwrap()
}
fn next(before: OrderState, n: u8, route: Route) -> CanonicalCommitment {
    CanonicalCommitment::order(base(), before, digest(n), route).unwrap()
}

#[test]
fn exact_wire_and_hash_vectors() {
    let first = genesis();
    let state = first.after();
    assert_eq!(OrderState::LEN, 82);
    assert_eq!(CanonicalCommitment::LEN, 149);
    let mut empty_bytes = [0; 82];
    empty_bytes[1] = 2;
    assert_eq!(OrderState::EMPTY.encode(), empty_bytes);
    assert_eq!(state.encode().to_vec(), {
        let mut expected = [0; 82];
        expected[1] = 2;
        expected[9] = 1;
        expected[10..42].copy_from_slice(&hex(
            "df57b22fd25a9577398b53eb9efa973f7d1f3b8d185993ecedda76554d2bdd95",
        ));
        expected.to_vec()
    });
    assert_eq!(first.encode().to_vec(), {
        let mut expected = [0; 149];
        expected[1] = 2;
        expected[2..34].fill(0x11);
        expected[34] = 1;
        expected[36] = 2;
        expected[117..149].fill(0x11);
        expected.to_vec()
    });
    assert_eq!(
        state.head(base()).hash.0.to_vec(),
        hex("c714fd6bf0cd0d53cbde573da4c5ad2b1052c66015fc1d0daf3a4ca74c91a1f1")
    );
    assert_ne!(state.raw_control().node_hash, state.head(base()).hash);
    assert_eq!(state.position(), 1);
    assert_eq!(OrderState::decode(&state.encode()), Ok(state));
    assert_eq!(CanonicalCommitment::decode(&first.encode()), Ok(first));
    let content = next(state, 0x22, Route::Content);
    assert_eq!(
        content.after().suffix_hash().0.to_vec(),
        hex("2141f5d61261f4685de838019bb3b24981f0a2a260f85847046e91ab8519de5d")
    );
    assert_eq!(content.previous(), first.head());
    assert_eq!(content.after().raw_control(), state.raw_control());
    assert_eq!(content.after().suffix_count(), 1);
    assert_eq!(
        publication_id(Route::Control, digest(0x11)).0.to_vec(),
        hex("42012442fbf57d669e44cfce297a25f6b2143e2472acafaac18da8bc1ea0321f")
    );
    assert_eq!(
        publication_id(Route::Content, digest(0x11)).0.to_vec(),
        hex("d59b0f33fb4446ea900ff1875431ec5e1663bc975bf12dd9ac4e115848433147")
    );
    assert_ne!(
        publication_id(Route::Control, digest(0x11)),
        publication_id(Route::Content, digest(0x11))
    );
    assert_eq!(
        content.event_id(),
        publication_id(Route::Content, digest(0x22))
    );
}

#[test]
fn strict_state_and_commitment_decoding() {
    let first = genesis();
    let mut state = first.after().encode();
    assert_eq!(OrderState::decode(&state[..81]), Err(Error::Encoding));
    assert_eq!(
        OrderState::decode(&[state.as_slice(), &[0]].concat()),
        Err(Error::Encoding)
    );
    state[1] = 1;
    assert_eq!(OrderState::decode(&state), Err(Error::Version));
    state[1] = 3;
    assert_eq!(OrderState::decode(&state), Err(Error::Version));
    let mut empty = OrderState::EMPTY.encode();
    empty[41] = 1;
    assert_eq!(OrderState::decode(&empty), Err(Error::Encoding));
    empty = OrderState::EMPTY.encode();
    empty[49] = 1;
    assert_eq!(OrderState::decode(&empty), Err(Error::Encoding));
    empty = OrderState::EMPTY.encode();
    empty[81] = 1;
    assert_eq!(OrderState::decode(&empty), Err(Error::Encoding));
    let mut no_suffix = first.after().encode();
    no_suffix[81] = 1;
    assert_eq!(OrderState::decode(&no_suffix), Err(Error::Encoding));
    let mut max = first.after().encode();
    max[2..10].copy_from_slice(&u64::MAX.to_be_bytes());
    max[42..50].copy_from_slice(&1u64.to_be_bytes());
    max[81] = 1;
    assert_eq!(OrderState::decode(&max), Err(Error::Exhausted));
    assert_eq!(
        OrderState::new(RawControlHead::EMPTY, 1, digest(1)),
        Err(Error::Encoding)
    );
    assert!(
        OrderState::new(
            RawControlHead {
                position: 1,
                node_hash: digest(1)
            },
            1,
            digest(0)
        )
        .is_ok()
    );
    assert_eq!(
        OrderState::new(
            RawControlHead {
                position: u64::MAX,
                node_hash: digest(1)
            },
            1,
            digest(1)
        ),
        Err(Error::Exhausted)
    );

    let mut bytes = first.encode();
    assert_eq!(
        CanonicalCommitment::decode(&bytes[..148]),
        Err(Error::Encoding)
    );
    assert_eq!(
        CanonicalCommitment::decode(&[bytes.as_slice(), &[0]].concat()),
        Err(Error::Encoding)
    );
    bytes[1] = 1;
    assert_eq!(CanonicalCommitment::decode(&bytes), Err(Error::Version));
    bytes[1] = 3;
    assert_eq!(CanonicalCommitment::decode(&bytes), Err(Error::Version));
    bytes[1] = 2;
    bytes[34] = 2;
    assert_eq!(CanonicalCommitment::decode(&bytes), Err(Error::Encoding));
    bytes[34] = 0;
    assert_eq!(
        CanonicalCommitment::decode(&bytes),
        Err(Error::GenesisMismatch)
    );
    bytes[34] = 1;
    bytes[148] = 3;
    assert_eq!(
        CanonicalCommitment::decode(&bytes),
        Err(Error::GenesisMismatch)
    );
    bytes[148] = 0x11;
    bytes[35 + 49] = 1; // content before genesis
    assert_eq!(CanonicalCommitment::decode(&bytes), Err(Error::Encoding));
}

#[test]
fn overflow_and_body_matching() {
    let raw = RawControlHead {
        position: u64::MAX,
        node_hash: digest(4),
    };
    let state = OrderState::new(raw, 0, digest(0)).unwrap();
    assert_eq!(
        CanonicalCommitment::order(base(), state, digest(2), Route::Control),
        Err(Error::Exhausted)
    );
    let state = OrderState::new(
        RawControlHead {
            position: 1,
            node_hash: digest(4),
        },
        u64::MAX - 1,
        digest(3),
    )
    .unwrap();
    assert_eq!(
        CanonicalCommitment::order(base(), state, digest(2), Route::Content),
        Err(Error::Exhausted)
    );
    let event = OpaqueEvent::new(EventId([5; 32]), vec![6; 1024]).unwrap();
    let first = CanonicalCommitment::order(
        BaseId::from_genesis(&event),
        OrderState::EMPTY,
        event.digest(),
        Route::Control,
    )
    .unwrap();
    assert_eq!(first.verify_body(&event), Ok(()));
    let other = OpaqueEvent::new(event.nonce(), vec![7; 1024]).unwrap();
    assert_eq!(first.verify_body(&other), Err(Error::BodyMismatch));
}

#[test]
fn mixed_full_and_sparse_coverage_bind_identical_endpoint() {
    let first = genesis();
    let edit = next(first.after(), 2, Route::Content);
    let removal = next(edit.after(), 3, Route::Control);
    let rejected_control = next(removal.after(), 4, Route::Control);
    let trailing = next(rejected_control.after(), 5, Route::Content);
    let steps = [first, edit, removal, rejected_control, trailing];
    let mut full_head = Head::EMPTY;
    for step in steps {
        full_head = step.verify_next(base(), full_head).unwrap();
    }
    let endpoint = trailing.after();
    let mut sparse = RawControlChain::new(base());
    for control in [first, removal, rejected_control] {
        sparse.advance(&control).unwrap();
    }
    let coverage = sparse.finish(endpoint, full_head).unwrap();
    assert_eq!(coverage.through(), full_head);
    assert_eq!(endpoint.head(base()), full_head);
    assert_eq!(
        coverage.raw_control(),
        rejected_control.after().raw_control()
    );
    assert_eq!(
        RawControlChain::new(base())
            .finish(OrderState::EMPTY, Head::EMPTY)
            .unwrap()
            .through(),
        Head::EMPTY
    );
    assert_eq!(
        sparse.finish(endpoint, Head::EMPTY),
        Err(CoverageError::EndpointMismatch)
    );
    assert_eq!(sparse.advance(&edit), Err(CoverageError::NotControl));
    assert_eq!(
        RawControlChain::new(BaseId([8; 32])).advance(&first),
        Err(CoverageError::WrongBase)
    );
}

#[test]
fn omitted_control_and_trailing_gap_never_expose_coverage() {
    let first = genesis();
    let edit = next(first.after(), 2, Route::Content);
    let removal = next(edit.after(), 3, Route::Control);
    let later = next(removal.after(), 4, Route::Control);
    let mut sparse = RawControlChain::new(base());
    sparse.advance(&first).unwrap();
    assert_eq!(sparse.advance(&later), Err(CoverageError::MissingControl));
    assert_eq!(
        sparse
            .finish(first.after(), first.head())
            .unwrap()
            .through(),
        first.head()
    ); // failure did not advance
    assert_eq!(
        sparse.finish(later.after(), later.head()),
        Err(CoverageError::MissingControl)
    );
    let endpoint = next(later.after(), 5, Route::Content);
    assert!(sparse.finish(endpoint.after(), endpoint.head()).is_err());
    let forged_content = next(edit.after(), 5, Route::Content);
    assert_ne!(forged_content.previous(), removal.head());
    assert_eq!(
        forged_content.verify_next(base(), removal.head()),
        Err(Error::HistoryMismatch)
    );
    assert_ne!(forged_content.head(), endpoint.head());
    assert_eq!(
        sparse.finish(forged_content.after(), endpoint.head()),
        Err(CoverageError::EndpointMismatch)
    );
}

#[test]
fn missing_entire_control_segment_and_large_content_span_are_constant_work() {
    let first = genesis();
    let mut controls = vec![first];
    for i in 0..129 {
        controls.push(next(
            controls.last().unwrap().after(),
            (i % 251 + 2) as u8,
            Route::Control,
        ));
    }
    let mut chain = RawControlChain::new(base());
    chain.advance(&controls[0]).unwrap();
    assert_eq!(
        chain.advance(&controls[129]),
        Err(CoverageError::MissingControl)
    );
    for control in &controls[1..] {
        chain.advance(control).unwrap();
    }
    assert_eq!(
        chain
            .finish(controls[129].after(), controls[129].head())
            .unwrap()
            .through(),
        controls[129].head()
    );

    let synthetic_opening =
        OrderState::new(first.after().raw_control(), 50_000_001, digest(6)).unwrap();
    let distant = next(synthetic_opening, 7, Route::Control);
    let mut sparse = RawControlChain::new(base());
    sparse.advance(&first).unwrap();
    sparse.advance(&distant).unwrap();
    assert_eq!(
        sparse
            .finish(distant.after(), distant.head())
            .unwrap()
            .through(),
        distant.head()
    );
    assert_eq!(distant.previous(), synthetic_opening.head(base()));
}

#[test]
fn resumed_chain_continues_only_from_its_durable_raw_head() {
    let first = genesis();
    let edit = next(first.after(), 2, Route::Content);
    let removal = next(edit.after(), 3, Route::Control);
    let later = next(removal.after(), 4, Route::Control);
    let trailing = next(later.after(), 5, Route::Content);
    // A durable checkpoint at the removal resumes where a scan from genesis
    // would be, and reaches the same endpoint.
    let mut resumed = RawControlChain::resume(base(), removal.after().raw_control());
    assert_eq!(
        resumed.finish(edit.after(), edit.head()),
        Err(CoverageError::MissingControl)
    );
    resumed.advance(&later).unwrap();
    assert_eq!(
        resumed
            .finish(trailing.after(), trailing.head())
            .unwrap()
            .raw_control(),
        later.after().raw_control()
    );
    // From the checkpoint before the removal, the later control does not link.
    let mut stale = RawControlChain::resume(base(), first.after().raw_control());
    assert_eq!(stale.advance(&later), Err(CoverageError::MissingControl));
    assert_eq!(
        RawControlChain::resume(BaseId([8; 32]), removal.after().raw_control()).advance(&later),
        Err(CoverageError::WrongBase)
    );
}
