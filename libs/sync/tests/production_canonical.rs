use bh_sync::canonical::CanonicalCommitment;
use bh_sync::{BaseId, Commitment, EventId, OpaqueEvent, OrderState, Route};

#[test]
fn production_commitment_is_the_canonical_opening_and_routed_identity() {
    let event = OpaqueEvent::new(EventId([7; 32]), vec![9; 1024]).unwrap();
    let base = BaseId::from_genesis(&event);
    let ordered = Commitment::order(base, OrderState::EMPTY, &event, Route::Control).unwrap();
    let canonical =
        CanonicalCommitment::order(base, OrderState::EMPTY, event.digest(), Route::Control)
            .unwrap();
    assert_eq!(ordered.encode(), canonical.encode());
    assert_eq!(ordered.encode().len(), 149);
    assert_eq!(ordered.before(), OrderState::EMPTY);
    assert_eq!(ordered.after(), canonical.after());
    assert_eq!(ordered.event_id(), event.publication_id(Route::Control));
    assert_ne!(ordered.event_id(), event.nonce());
    assert_ne!(event.publication_id(Route::Content), ordered.event_id());
    let next = Commitment::order(base, ordered.after(), &event, Route::Content).unwrap();
    assert_eq!(next.previous(), ordered.head());
    assert_eq!(next.verify_next(base, ordered.head()), Ok(next.head()));
    assert_ne!(next.event_id(), ordered.event_id());
    assert_eq!(Commitment::decode(&next.encode()), Ok(next));
}
