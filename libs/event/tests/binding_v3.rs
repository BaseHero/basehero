//! Replay-safe signed binding nonces in canonical production originals.
#[path = "support/runs.rs"]
mod runs;

use bh_crypto::{AeadSealNonce, Secret, SigningKey, aead_open, aead_seal, derive_key};
use bh_event::{
    Binding, CLASS_CONTENT, Encoded, Outcome, Payload, TYPED_DATA, seal, verify_genesis,
};
use bh_sync::{
    BaseId, BodyObject, EventId, OpaqueEvent, Route, canonical::publication_id,
    receipt::RECEIPT_LEN,
};
use runs::Base;

const FIELDS: usize = 346 + RECEIPT_LEN;
const SIGNED: usize = FIELDS + 24;
const DOMAIN: &[u8] = b"bh/original-envelope/v1\0";

fn binding_ad(version: u16, mode: u8, base: [u8; 32], event: &OpaqueEvent) -> Vec<u8> {
    let mut ad = b"bh/author-binding-aad/v1\0".to_vec();
    ad.extend(version.to_be_bytes());
    ad.push(mode);
    ad.extend(base);
    ad.extend(event.nonce().0);
    ad.extend(&event.envelope()[..32]);
    ad
}

/// Independent wire fixture: open and re-sign a production original, including
/// the body AD. This does not rely on the codec producer for the new seal.
fn upgrade(f: &Base, legacy: &Encoded, signer: &SigningKey, mode: u8) -> Encoded {
    let version = 3;
    let base = if mode == 1 { [0; 32] } else { f.base.0 };
    let env = legacy.descriptor.envelope();
    let key = derive_key(&f.metadata, b"bhBind01", 0);
    let plain = aead_open(
        &key,
        env[32..56].try_into().unwrap(),
        &binding_ad(version, mode, base, &legacy.descriptor),
        &env[56..],
    )
    .unwrap();
    let mut fields = plain.expose()[..FIELDS].to_vec();
    fields.resize(FIELDS, 0);
    let body_ad = |fields: &[u8]| {
        let mut ad = b"bh/payload-aad/v1\0".to_vec();
        ad.extend(&fields[..2]);
        ad.push(mode);
        ad.extend(&fields[5..133]); // base, audience, epoch, event nonce
        ad.extend(&fields[310..314]); // padded size
        ad
    };
    let body_key = if fields[309] == CLASS_CONTENT {
        derive_key(&f.epoch, b"bhNote01", 0)
    } else {
        derive_key(&f.metadata, b"bhCtrl01", 0)
    };
    let body_plain = aead_open(
        &body_key,
        legacy.body[..24].try_into().unwrap(),
        &body_ad(&fields),
        &legacy.body[24..],
    )
    .unwrap();
    fields[..4].copy_from_slice(&[0, 3, 0, 3]);
    let (nonce, cipher) = aead_seal(&body_key, &body_ad(&fields), body_plain.expose()).unwrap();
    let mut body = nonce.to_vec();
    body.extend(cipher);
    let digest = BodyObject::new(body.clone()).unwrap().commitment().0;
    fields[314..346].copy_from_slice(&digest);
    let nonce = AeadSealNonce::new();
    fields.extend(nonce.bytes());
    let mut signed = DOMAIN.to_vec();
    signed.extend(&fields);
    fields.extend(signer.sign(&signed));
    fields.resize(952, 0);
    let shell = OpaqueEvent::new(legacy.descriptor.nonce(), {
        let mut env = vec![0; 1024];
        env[..32].copy_from_slice(&digest);
        env
    })
    .unwrap();
    let mut envelope = digest.to_vec();
    envelope.extend(nonce.bytes());
    envelope.extend(
        nonce
            .seal(&key, &binding_ad(3, mode, base, &shell), &fields)
            .unwrap(),
    );
    Encoded {
        descriptor: OpaqueEvent::new(shell.nonce(), envelope).unwrap(),
        body,
    }
}

/// An M-holder can decrypt/re-encrypt but does not possess the author's key.
/// Optionally align the signed nonce with the new external nonce: the unchanged
/// signature must then fail even though the equality check succeeds.
fn reencrypt(f: &Base, event: &Encoded, align_nonce: bool, padding: bool) -> Encoded {
    let env = event.descriptor.envelope();
    let key = derive_key(&f.metadata, b"bhBind01", 0);
    let ad = binding_ad(3, 0, f.base.0, &event.descriptor);
    let plain = aead_open(&key, env[32..56].try_into().unwrap(), &ad, &env[56..]).unwrap();
    let mut bytes = plain.expose().to_vec();
    let nonce = AeadSealNonce::new();
    assert_ne!(nonce.bytes().as_slice(), &env[32..56]);
    if align_nonce || padding {
        bytes[FIELDS..SIGNED].copy_from_slice(nonce.bytes());
    }
    if padding {
        // Author-signed nonce and otherwise valid encryption: only padding is bad.
        let mut signed = DOMAIN.to_vec();
        signed.extend(&bytes[..SIGNED]);
        bytes[SIGNED..SIGNED + 64].copy_from_slice(&f.first.signing.sign(&signed));
        bytes[SIGNED + 64] = 1;
    }
    let mut envelope = env[..32].to_vec();
    envelope.extend(nonce.bytes());
    envelope.extend(nonce.seal(&key, &ad, &bytes).unwrap());
    Encoded {
        descriptor: OpaqueEvent::new(event.descriptor.nonce(), envelope).unwrap(),
        body: event.body.clone(),
    }
}

#[test]
fn v3_genesis_and_content_verify_with_independent_resigning() {
    let f = Base::new();
    let genesis = upgrade(&f, &f.genesis, &f.first.signing, 1);
    let verified = verify_genesis(
        &f.anchor,
        &genesis.descriptor,
        &genesis.body,
        &f.metadata,
        3,
    )
    .unwrap();
    assert_eq!(verified.base, BaseId::from_genesis(&genesis.descriptor));
    let note = f.note(&f.first, "canonical producer");
    assert_eq!(f.history_verdict(&note, Route::Content), Outcome::Accepted);
    let original = upgrade(&f, &note, &f.first.signing, 0);
    assert_eq!(
        f.history_verdict(&original, Route::Content),
        Outcome::Accepted
    );
    assert_eq!(original.descriptor.envelope().len(), 1024);
}

#[test]
fn metadata_holder_cannot_mint_another_publication_by_reencrypting_a_signature() {
    let f = Base::new();
    let original = upgrade(
        &f,
        &f.note(&f.first, "one publication"),
        &f.first.signing,
        0,
    );
    let replay = reencrypt(&f, &original, false, false);
    let id = publication_id(Route::Content, original.descriptor.digest());
    assert_ne!(
        id,
        publication_id(Route::Content, replay.descriptor.digest())
    );
    assert_eq!(original.descriptor.nonce(), replay.descriptor.nonce());
    // Neither original has been inserted into this verifier's ID index. Each
    // verdict clones the genesis-only history, so old dedup cannot hide replay.
    assert_eq!(
        f.history_verdict(&original, Route::Content),
        Outcome::Accepted
    );
    assert_eq!(
        f.history_verdict(&replay, Route::Content),
        Outcome::Rejected
    );
    let retry = OpaqueEvent::decode(&original.descriptor.encode()).unwrap();
    assert_eq!(id, publication_id(Route::Content, retry.digest()));
    assert_ne!(id, publication_id(Route::Control, retry.digest()));
    assert_eq!(
        f.history_verdict(&original, Route::Control),
        Outcome::Rejected
    );
}

#[test]
fn reencrypted_control_is_rejected_by_a_fresh_verifier_without_any_duplicate_index() {
    let mut f = Base::new();
    let added = f.order_at(&f.add(&f.first, &f.second), 1_000_000);
    let original = upgrade(&f, &f.run(&f.first, &[added]), &f.first.control, 0);
    let replay = reencrypt(&f, &original, false, false);
    assert_ne!(
        publication_id(Route::Control, original.descriptor.digest()),
        publication_id(Route::Control, replay.descriptor.digest())
    );
    // ControlSpine has no duplicate index at all (id_used always false).
    // Neither check changes its state, so rejection can only be verification.
    assert!(f.spine_verdict(&original).is_ok());
    assert_eq!(f.spine_verdict(&replay).err(), Some(Outcome::Rejected));
}

#[test]
fn changing_signed_nonce_without_resigning_is_rejected() {
    let f = Base::new();
    let original = upgrade(
        &f,
        &f.note(&f.first, "authenticated nonce"),
        &f.first.signing,
        0,
    );
    assert_eq!(
        f.history_verdict(&original, Route::Content),
        Outcome::Accepted
    );
    assert_eq!(
        f.history_verdict(&reencrypt(&f, &original, true, false), Route::Content),
        Outcome::Rejected
    );
}

#[test]
fn nonzero_binding_padding_is_rejected_even_with_valid_signature_and_nonce() {
    let f = Base::new();
    let original = upgrade(
        &f,
        &f.note(&f.first, "canonical padding"),
        &f.first.signing,
        0,
    );
    assert_eq!(
        f.history_verdict(&original, Route::Content),
        Outcome::Accepted
    );
    assert_eq!(
        f.history_verdict(&reencrypt(&f, &original, false, true), Route::Content),
        Outcome::Rejected
    );
}

#[test]
fn external_event_nonce_ad_and_ciphertext_tampering_are_rejected() {
    let f = Base::new();
    let original = upgrade(&f, &f.note(&f.first, "bound bytes"), &f.first.signing, 0);
    assert_eq!(
        f.history_verdict(&original, Route::Content),
        Outcome::Accepted
    );
    let renamed = Encoded {
        descriptor: OpaqueEvent::new(EventId([0xee; 32]), original.descriptor.envelope().to_vec())
            .unwrap(),
        body: original.body.clone(),
    };
    assert_eq!(
        f.history_verdict(&renamed, Route::Content),
        Outcome::Rejected
    );
    for offset in [0, 32, 56] {
        // commitment AD, external AEAD nonce, ciphertext
        let mut envelope = original.descriptor.envelope().to_vec();
        envelope[offset] ^= 1;
        let bad = Encoded {
            descriptor: OpaqueEvent::new(original.descriptor.nonce(), envelope).unwrap(),
            body: original.body.clone(),
        };
        assert_eq!(f.history_verdict(&bad, Route::Content), Outcome::Rejected);
    }
}

#[test]
fn v3_ordinary_key_rekey_and_deferred_device_author_are_verified() {
    let mut f = Base::new();
    let added = f.order_at(&f.add(&f.first, &f.second), 1_000_000);
    // Second is absent before this run: signature checking must be deferred
    // until the copied account events establish the author's control key.
    let legacy = f.run_signed(f.second.id(), &f.second.control, &[added]);
    let run = upgrade(&f, &legacy, &f.second.control, 0);
    assert_eq!(
        f.history_verdict(&reencrypt(&f, &run, true, false), Route::Control),
        Outcome::Rejected
    );
    assert_eq!(
        f.spine_verdict(&reencrypt(&f, &run, true, false)).err(),
        Some(Outcome::Rejected)
    );
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    let removal = f.remove_self(&f.second);
    let reason = removal.head().position;
    let removed = f.order_at(&removal, 1_000_001);
    let removal_run = upgrade(&f, &f.run(&f.first, &[removed]), &f.first.control, 0);
    assert_eq!(f.step(&removal_run, Route::Control), Outcome::Accepted);
    let rotated = f.order_at(&f.rotate(&f.first, reason), 1_000_002);
    let next = Secret::random();
    let rekey = Base::sign_rekey(
        f.rekey(&f.first, &rotated, &next, &[vec![0; 1499]]),
        &f.first,
    );
    let wrong_key = upgrade(&f, &rekey, &f.first.control, 2);
    let rekey = upgrade(&f, &rekey, &f.first.signing, 2);
    assert_eq!(
        f.history_verdict(&wrong_key, Route::Control),
        Outcome::Rejected
    );
    assert_eq!(f.spine_verdict(&wrong_key).err(), Some(Outcome::Rejected));
    assert_eq!(f.step(&rekey, Route::Control), Outcome::Accepted);
    assert_eq!(f.history.epoch_id(), Some(bh_event::key_id(&next)));
}

#[test]
fn v3_recovery_author_established_by_the_run_authenticates_the_nonce() {
    let mut f = Base::new();
    let next = runs::Recovery::new();
    let replaced = f.order_at(&f.replace_recovery(&f.first, &next), 1_000_000);
    let legacy = f.run_by_recovery(&next, &[replaced]);
    let original = upgrade(&f, &legacy, &next.signing, 0);
    let tampered = reencrypt(&f, &original, true, false);
    assert_eq!(
        f.history_verdict(&tampered, Route::Control),
        Outcome::Rejected
    );
    assert_eq!(f.spine_verdict(&tampered).err(), Some(Outcome::Rejected));
    assert_eq!(f.step(&original, Route::Control), Outcome::Accepted);
    assert!(f.account.recovery_author() == f.ordered.recovery_author());
}

#[test]
fn v3_public_seal_and_version_floor() {
    let mut f = Base::new();
    let binding = Binding {
        version: 3,
        highest: 3,
        ..f.binding(f.first.id(), CLASS_CONTENT)
    };
    let original = seal(
        binding,
        Payload {
            kind: TYPED_DATA,
            data: b"typed",
        },
        &f.first.signing,
        &f.metadata,
        Some(&f.epoch),
    )
    .unwrap();
    // Typed payloads are verified and retained for their own consumer.
    assert_eq!(f.step(&original, Route::Content), Outcome::Retained);
    assert_eq!(f.history.floor(), 3);
    let mut legacy = f.binding(f.first.id(), CLASS_CONTENT);
    legacy.version = 2;
    legacy.highest = 2;
    let legacy = seal(
        legacy,
        Payload {
            kind: TYPED_DATA,
            data: b"legacy",
        },
        &f.first.signing,
        &f.metadata,
        Some(&f.epoch),
    )
    .unwrap();
    assert_eq!(
        f.history_verdict(&legacy, Route::Content),
        Outcome::Rejected
    );
}
