use bh_account::{
    AccountEvent, AccountId, DevicePublicKeys, VerifiedAccount,
    crypto::{self, KemKey, Secret, SigningKey},
    pairing::{PairError, QrCode, Reply, ShowingSession, verify_showing},
};

fn fixture() -> (VerifiedAccount, Vec<u8>, DevicePublicKeys, SigningKey) {
    let ordinary = SigningKey::generate();
    let control = SigningKey::generate();
    let receiver = KemKey::generate();
    let keys =
        DevicePublicKeys::new(ordinary.public(), control.public(), receiver.public()).unwrap();
    let recovery = bh_account::recovery::RecoveryKeys::generate();
    let draft = AccountEvent::genesis(keys.clone(), recovery.public());
    let event = draft.finish(control.sign(draft.signing_bytes())).unwrap();
    let anchor = AccountId::of_genesis(&event).unwrap();
    (
        VerifiedAccount::from_genesis(anchor, event.as_bytes()).unwrap(),
        event.as_bytes().to_vec(),
        keys,
        control,
    )
}
fn keys() -> DevicePublicKeys {
    DevicePublicKeys::new(
        SigningKey::generate().public(),
        SigningKey::generate().public(),
        KemKey::generate().public(),
    )
    .unwrap()
}

#[test]
fn qr_is_canonical_and_requires_active_showing_history_from_anchor() {
    let (account, genesis, showing, control) = fixture();
    let session = ShowingSession::new(account.id(), showing.id());
    let encoded = session.qr().unwrap().encode();
    assert_eq!(encoded.len(), 122);
    let qr = QrCode::decode(&encoded).unwrap();
    assert_eq!(qr.encode(), encoded);
    assert!(
        verify_showing(&qr, &[genesis.as_slice()], account.head())
            .unwrap()
            .id()
            == showing.id()
    );
    for index in [0, 8, 10, 42] {
        let mut changed = encoded.to_vec();
        changed[index] ^= 1;
        assert!(
            QrCode::decode(&changed).is_err()
                || verify_showing(
                    &QrCode::decode(&changed).unwrap(),
                    &[genesis.as_slice()],
                    account.head()
                )
                .is_err()
        );
    }
    assert!(QrCode::decode(&encoded[..121]).is_err());
    assert!(QrCode::decode(&[encoded.as_slice(), &[0]].concat()).is_err());
    // Session/secret aren't part of history. A changed QR can still decode,
    // but cannot authenticate a scanner reply to the original live session.
    let mut removed = account.clone();
    let request = removed.remove_self(showing.id()).unwrap();
    let event = request
        .finish(control.sign(request.signing_bytes()))
        .unwrap();
    removed.apply(event.as_bytes()).unwrap();
    assert!(verify_showing(&qr, &[genesis.as_slice(), event.as_bytes()], removed.head()).is_err());
    for index in [74, 90] {
        let mut changed = encoded.to_vec();
        changed[index] ^= 1;
        let forged = Reply::make(&QrCode::decode(&changed).unwrap(), keys(), b"Fold").unwrap();
        assert_eq!(session.receive(&forged), Err(PairError::InvalidReply));
    }
}

#[test]
fn transcript_field_changes_and_reply_races_are_rejected() {
    let (account, _, showing, _) = fixture();
    let session = ShowingSession::new(account.id(), showing.id());
    let qr = session.qr().unwrap();
    let scanner = keys();
    assert!(matches!(
        Reply::make(&qr, scanner.clone(), &[0; 65]),
        Err(PairError::Malformed)
    ));
    let reply = Reply::make(&qr, scanner.clone(), b"Fold").unwrap();
    // Independently build the fixed transcript, so a field removed from BOTH
    // create and verify is caught (including label and version).
    let mut expected = b"BaseHero QR proof v1\0".to_vec();
    expected.extend_from_slice(&1u16.to_be_bytes());
    expected.extend_from_slice(&qr.account.0);
    expected.extend_from_slice(&qr.showing.0);
    expected.extend_from_slice(&qr.session);
    expected.extend_from_slice(scanner.signing());
    expected.extend_from_slice(scanner.control());
    expected.extend_from_slice(scanner.receiving());
    expected.extend_from_slice(&4u16.to_be_bytes());
    expected.extend_from_slice(b"Fold");
    let raw = qr.encode();
    let secret = Secret::<32>::from_slice(&raw[90..]).unwrap();
    let key = crypto::derive_key(&secret, b"BHPAIR01", 1);
    let nonce: [u8; 24] = reply.proof[..24].try_into().unwrap();
    assert!(crypto::aead_open(&key, &nonce, &expected, &reply.proof[24..]).is_ok());
    let header = b"BaseHero QR proof v1\0".len();
    for at in [
        0,
        header,
        header + 2,
        header + 34,
        header + 66,
        header + 82,
        header + 114,
        header + 146,
        header + 1300,
        header + 1362,
        expected.len() - 1,
    ] {
        let mut altered = expected.clone();
        altered[at] ^= 1;
        assert!(
            crypto::aead_open(&key, &nonce, &altered, &reply.proof[24..]).is_err(),
            "transcript byte {at}"
        );
    }
    assert_eq!(session.receive(&reply).unwrap(), scanner);
    assert_eq!(
        session.receive(&reply).unwrap(),
        scanner,
        "same reply is idempotent"
    );
    let mut changed = reply.clone();
    changed.session[0] ^= 1;
    assert_eq!(session.receive(&changed), Err(PairError::InvalidReply));
    let mut changed = reply.clone();
    changed.label.push(b'!');
    assert_eq!(session.receive(&changed), Err(PairError::InvalidReply));
    let mut changed = reply.clone();
    changed.keys = keys();
    assert_eq!(session.receive(&changed), Err(PairError::InvalidReply));
    let mut changed = reply.clone();
    changed.keys = DevicePublicKeys::new(
        keys().signing().to_owned(),
        reply.keys.control().to_owned(),
        reply.keys.receiving().to_owned(),
    )
    .unwrap();
    assert_eq!(session.receive(&changed), Err(PairError::InvalidReply));
    let mut changed = reply.clone();
    changed.keys = DevicePublicKeys::new(
        reply.keys.signing().to_owned(),
        keys().control().to_owned(),
        reply.keys.receiving().to_owned(),
    )
    .unwrap();
    assert_eq!(session.receive(&changed), Err(PairError::InvalidReply));
    let mut changed = reply.clone();
    changed.keys = DevicePublicKeys::new(
        reply.keys.signing().to_owned(),
        reply.keys.control().to_owned(),
        keys().receiving().to_owned(),
    )
    .unwrap();
    assert_eq!(session.receive(&changed), Err(PairError::InvalidReply));
    let mut changed = reply.clone();
    changed.proof[39] ^= 1;
    assert_eq!(session.receive(&changed), Err(PairError::InvalidReply));
    let second = Reply::make(&qr, keys(), b"Fold").unwrap();
    assert_eq!(session.receive(&second), Err(PairError::CompetingReply));
    assert_eq!(session.receive(&reply), Err(PairError::Ended));
}

#[test]
fn cancelled_session_never_accepts_late_signature() {
    let (account, _, showing, _) = fixture();
    let session = ShowingSession::new(account.id(), showing.id());
    let reply = Reply::make(&session.qr().unwrap(), keys(), b"").unwrap();
    session.receive(&reply).unwrap();
    let _draft = account
        .add_device(showing.id(), reply.keys.clone())
        .unwrap();
    session.cancel();
    assert!(
        matches!(session.qr(), Err(PairError::Ended)),
        "cancelled QR cannot be re-shown"
    );
    // A late native signature is never passed to durable staging.
    let mut persisted = false;
    assert_eq!(
        session.stage::<()>(&[0; 64], &[1], |_, _| {
            persisted = true;
            Ok(())
        }),
        Err(PairError::Ended)
    );
    assert!(!persisted);
}

#[test]
fn reply_encoding_is_exact_and_strict() {
    let (account, _, showing, _) = fixture();
    let session = ShowingSession::new(account.id(), showing.id());
    let reply = Reply::make(&session.qr().unwrap(), keys(), b"Fold").unwrap();
    let encoded = reply.encode();
    assert_eq!(encoded.len(), 8 + 16 + 1280 + 2 + 4 + 40);
    assert!(Reply::decode(&encoded).unwrap() == reply);
    assert!(session.receive(&Reply::decode(&encoded).unwrap()).is_ok());
    assert_eq!(
        Reply::decode(&encoded[..encoded.len() - 1]).err(),
        Some(PairError::Malformed)
    );
    assert_eq!(
        Reply::decode(&[encoded.as_slice(), &[0]].concat()).err(),
        Some(PairError::Malformed)
    );
    let mut magic = encoded.clone();
    magic[0] ^= 1;
    assert_eq!(Reply::decode(&magic).err(), Some(PairError::Malformed));
    // An over-long label never decodes.
    let mut long = encoded[..8 + 16 + 1280].to_vec();
    long.extend(65u16.to_be_bytes());
    long.extend([b'x'; 65]);
    long.extend([0; 40]);
    assert_eq!(Reply::decode(&long).err(), Some(PairError::Malformed));
    // A changed byte decodes but no longer authenticates.
    let mut changed = encoded.clone();
    changed[30] ^= 1;
    if let Ok(decoded) = Reply::decode(&changed) {
        assert_eq!(session.receive(&decoded), Err(PairError::InvalidReply));
    }
}

#[test]
fn relay_keys_agree_hide_the_secret_and_end_with_the_session() {
    let (account, _, showing, _) = fixture();
    let session = ShowingSession::new(account.id(), showing.id());
    let qr = session.qr().unwrap();
    let shown = session.relay().unwrap();
    let scanned = qr.relay();
    assert_eq!(shown.name(), scanned.name());
    let raw = qr.encode();
    assert_ne!(&shown.name()[..], &raw[90..], "the name is not the secret");
    let other = ShowingSession::new(account.id(), showing.id());
    assert_ne!(other.relay().unwrap().name(), shown.name());

    let sealed = shown.seal_show(b"ordered at 4").unwrap();
    assert_eq!(
        scanned.open_show(&sealed).unwrap().expose(),
        b"ordered at 4"
    );
    // Each side's messages open only as that side's.
    assert!(scanned.open_join(&sealed).is_err());
    let reply = scanned.seal_join(b"a reply").unwrap();
    assert_eq!(shown.open_join(&reply).unwrap().expose(), b"a reply");
    assert!(shown.open_show(&reply).is_err());
    assert!(other.relay().unwrap().open_show(&sealed).is_err());
    let mut changed = sealed.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(scanned.open_show(&changed).is_err());
    assert!(scanned.open_show(&sealed[..10]).is_err());

    session.cancel();
    assert!(matches!(session.relay(), Err(PairError::Ended)));
    let _ = Secret::<32>::random();
    let _ = crypto::hash(b"");
}
