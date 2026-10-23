#![cfg(feature = "synthetic-attestation")]
#[path = "../examples/support/forged_account_change.rs"]
mod forged;
use bh_account::{
    AccountEvent, AccountId, ConfirmedTime, DevicePublicKeys, Error, VerifiedAccount,
    crypto::KemKey, personal::PersonalKey, recovery::RecoveryKeys,
};
use bh_crypto::SigningKey;
use forged::{Kind, forge};

#[test]
fn each_forged_entry_is_refused_by_the_account_verifier() {
    let control = SigningKey::generate();
    let ordinary = SigningKey::generate();
    let device = DevicePublicKeys::new(
        ordinary.public(),
        control.public(),
        KemKey::generate().public(),
    )
    .unwrap();
    let recovery = RecoveryKeys::generate();
    let draft = AccountEvent::genesis(device.clone(), recovery.public());
    let genesis = draft.finish(control.sign(draft.signing_bytes())).unwrap();
    let anchor = AccountId::of_genesis(&genesis).unwrap();
    let mut view = VerifiedAccount::from_genesis(anchor, genesis.as_bytes()).unwrap();
    let record = view.prepare_recovery_record(device.id(), [5; 32]).unwrap();
    view.apply(
        record
            .finish(control.sign(record.signing_bytes()))
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let publication = view
        .publish_personal_key(
            device.id(),
            PersonalKey::generate().public(),
            [6; 32],
            [7; 32],
        )
        .unwrap();
    view.apply(
        publication
            .finish(control.sign(publication.signing_bytes()))
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    assert!(Kind::parse("bad-signature").is_some());
    assert!(Kind::parse("wrong-signer").is_some());
    assert!(Kind::parse("early-rotation").is_none());
    for (kind, expected) in [
        (Kind::BadSignature, Error::BadSignature),
        (Kind::WrongSigner, Error::BadSignature),
    ] {
        let entry = forge(kind, &view, device.id()).unwrap();
        assert_eq!(view.clone().apply(&entry), Err(expected));
    }
    // Establish a real future-dated removal so the rotation is premature,
    // rather than an unrelated rotation with a nonexistent reason.
    let second_control = SigningKey::generate();
    let second = DevicePublicKeys::new(
        SigningKey::generate().public(),
        second_control.public(),
        KemKey::generate().public(),
    )
    .unwrap();
    let add = view.add_device(device.id(), second.clone()).unwrap();
    view.apply(
        add.finish(control.sign(add.signing_bytes()))
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let request = view.request_removal(device.id(), second.id()).unwrap();
    view.apply_timed(
        request
            .finish(control.sign(request.signing_bytes()))
            .unwrap()
            .as_bytes(),
        Some(ConfirmedTime {
            earliest_ms: 1000,
            latest_ms: 1000,
        }),
    )
    .unwrap();
    let reason = view.head().position;
    let next = PersonalKey::generate();
    let request = view
        .rotate_personal(device.id(), reason, next.public(), [8; 32], [9; 32])
        .unwrap();
    let entry = request
        .finish(ordinary.sign(request.signing_bytes()))
        .unwrap();
    assert_eq!(
        view.clone().apply_timed(
            entry.as_bytes(),
            Some(ConfirmedTime {
                earliest_ms: 1001,
                latest_ms: 1001
            })
        ),
        Err(Error::TooEarly)
    );
}
