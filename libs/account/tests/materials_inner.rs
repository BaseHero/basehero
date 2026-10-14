//! Independently constructed committed private bytes reach the *inner* checks.
//! This is a fixture encoder, not an alternative production recovery protocol.
#[path = "support/native.rs"]
mod native;
use native::open_for_receiver;

use bh_account::{
    AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount,
    crypto::{self, KemKey, Secret, SigningKey},
    personal::SealPurpose,
    recovery::{Password, RecoveryCode, open_record},
};

struct Inputs {
    state: VerifiedAccount,
    first: DevicePublicKeys,
    control: SigningKey,
    device: KemKey,
    recovery_sign: [u8; 32],
    recovery_recv: [u8; 32],
    personal_seed: [u8; 32],
}
impl Inputs {
    fn new() -> Self {
        let ordinary = SigningKey::generate();
        let control = SigningKey::generate();
        let device = KemKey::generate();
        let first =
            DevicePublicKeys::new(ordinary.public(), control.public(), device.public()).unwrap();
        let recovery_sign = [0x11; 32];
        let recovery_recv = [0x22; 32];
        let recovery = RecoveryPublicKeys::new(
            SigningKey::from_seed(&Secret::from_slice(&recovery_sign).unwrap()).public(),
            KemKey::from_seed(&Secret::from_slice(&recovery_recv).unwrap()).public(),
        );
        let draft = AccountEvent::genesis(first.clone(), recovery);
        let genesis = draft.finish(control.sign(draft.signing_bytes())).unwrap();
        let state = VerifiedAccount::from_genesis(
            AccountId::of_genesis(&genesis).unwrap(),
            genesis.as_bytes(),
        )
        .unwrap();
        Self {
            state,
            first,
            control,
            device,
            recovery_sign,
            recovery_recv,
            personal_seed: [0x33; 32],
        }
    }
    fn signing(&self, tag: u8, body: &[u8], state: &VerifiedAccount) -> Vec<u8> {
        // Do not use production control builders; sign the independently packed bytes.
        let mut bytes = b"BaseHero account event\0".to_vec();
        bytes.extend(1u16.to_be_bytes());
        bytes.extend(1u16.to_be_bytes());
        bytes.extend((state.head().position + 1).to_be_bytes());
        bytes.extend(state.head().hash);
        bytes.extend(state.id().0);
        bytes.extend(self.first.id().0);
        bytes.push(tag);
        bytes.extend(body);
        bytes.extend(self.control.sign(&bytes));
        bytes
    }
    fn personal_public(&self) -> [u8; 1216] {
        KemKey::from_seed(&Secret::from_slice(&self.personal_seed).unwrap()).public()
    }
    fn record(&self, sign_seed: &[u8; 32], recv_seed: &[u8; 32], ad_account: AccountId) -> Vec<u8> {
        const CODE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let public = self.state.recovery_keys().unwrap();
        let key_id = crypto::hash(
            &[
                b"BH recovery key id v1\0".as_slice(),
                public.signing(),
                public.receiving(),
            ]
            .concat(),
        );
        let pw = b"pa\0ss\xc3\xa9";
        let framed = [
            b"BH ordinary recovery v1\0".as_slice(),
            &(pw.len() as u16).to_be_bytes(),
            pw,
            &CODE,
        ]
        .concat();
        let root =
            crypto::pwhash_argon2id13(&framed, b"BaseHeroRecovV01", 2, 64 * 1024 * 1024).unwrap();
        let wrap = crypto::derive_key(&root, b"BHRWRA01", 1);
        let ad = [
            b"BH recovery wrap v1\0".as_slice(),
            &1u16.to_be_bytes(),
            &ad_account.0,
            &key_id,
        ]
        .concat();
        let (nonce, ciphertext) =
            crypto::aead_seal(&wrap, &ad, &[sign_seed.as_slice(), recv_seed].concat()).unwrap();
        let token = crypto::derive_key(&root, b"BHRTOK01", 1);
        let token_hash =
            crypto::hash(&[b"BH recovery token check v1\0".as_slice(), token.expose()].concat());
        let proof = crypto::hash(&[b"BH ordinary code proof v1\0".as_slice(), &CODE].concat());
        let proof_hash =
            crypto::hash(&[b"BH recovery proof check v1\0".as_slice(), &proof].concat());
        let record = [
            b"BHREC01\0".as_slice(),
            &1u16.to_be_bytes(),
            &self.state.id().0,
            &key_id,
            &nonce,
            ciphertext.as_slice(),
            &token_hash,
            &proof_hash,
        ]
        .concat();
        assert_eq!(record.len(), 242);
        record
    }
    fn seal(
        &self,
        purpose: u8,
        recipient: &[u8; 1216],
        seed: &[u8; 32],
        ad_purpose: u8,
    ) -> Vec<u8> {
        let public = self.personal_public();
        let key_id = crypto::hash(&[b"BH personal key id v1\0".as_slice(), &public].concat());
        let recipient_id =
            crypto::hash(&[b"BH personal recipient v1\0".as_slice(), recipient].concat());
        let (kem, shared) = crypto::encapsulate(recipient).unwrap();
        let key = crypto::derive_key(&shared, b"BHPSEA01", 1);
        let ad = [
            b"BH personal seed seal v1\0".as_slice(),
            &1u16.to_be_bytes(),
            &[ad_purpose],
            &self.state.id().0,
            &key_id,
            &recipient_id,
        ]
        .concat();
        let (nonce, ciphertext) = crypto::aead_seal(&key, &ad, seed).unwrap();
        let seal = [
            b"BHPERS01".as_slice(),
            &1u16.to_be_bytes(),
            &[purpose],
            &self.state.id().0,
            &key_id,
            &recipient_id,
            &kem,
            &nonce,
            ciphertext.as_slice(),
        ]
        .concat();
        assert_eq!(seal.len(), 1299);
        seal
    }
    fn committed(
        &self,
        record: &[u8],
        device_seal: &[u8],
        recovery_seal: &[u8],
    ) -> VerifiedAccount {
        let record_digest =
            crypto::hash(&[b"BH recovery record commit v1\0".as_slice(), record].concat());
        let mut state = self.state.clone();
        state
            .apply(&self.signing(3, &record_digest, &state))
            .unwrap();
        let public = self.personal_public();
        let seal_digest = |seal: &[u8]| {
            crypto::hash(&[b"BH personal seal commit v1\0".as_slice(), seal].concat())
        };
        let body = [
            &public[..],
            &seal_digest(device_seal),
            &seal_digest(recovery_seal),
        ]
        .concat();
        state.apply(&self.signing(4, &body, &state)).unwrap();
        assert!(state.materials_ready().unwrap());
        state
    }
    fn baseline(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let record = self.record(&self.recovery_sign, &self.recovery_recv, self.state.id());
        let first = self.seal(1, self.first.receiving(), &self.personal_seed, 1);
        let recovery = self.seal(
            2,
            self.state.recovery_keys().unwrap().receiving(),
            &self.personal_seed,
            2,
        );
        (record, first, recovery)
    }
}
fn credentials() -> (Password, RecoveryCode) {
    (
        Password::new("pa\0ssé").unwrap(),
        RecoveryCode::from_raw(&std::array::from_fn(|i| i as u8)),
    )
}

#[test]
fn independently_signed_record_and_both_private_envelopes_open() {
    let input = Inputs::new();
    let (record, first, recovery) = input.baseline();
    let state = input.committed(&record, &first, &recovery);
    let (password, code) = credentials();
    let restored = open_record(&state, &record, &password, &code).unwrap();
    assert_eq!(
        restored.public().signing(),
        input.state.recovery_keys().unwrap().signing()
    );
    assert_eq!(
        restored.public().receiving(),
        input.state.recovery_keys().unwrap().receiving()
    );
    assert_eq!(
        open_for_receiver(&state, &first, SealPurpose::FirstDevice, &input.device)
            .unwrap()
            .public(),
        input.personal_public()
    );
    assert_eq!(
        open_for_receiver(
            &state,
            &recovery,
            SealPurpose::Recovery,
            restored.receiver()
        )
        .unwrap()
        .public(),
        input.personal_public()
    );
}

#[test]
fn matching_signed_record_commitment_reaches_token_proof_and_reconstructed_halves() {
    let input = Inputs::new();
    let (baseline, first, recovery) = input.baseline();
    let (password, code) = credentials();
    for offset in [178, 210] {
        // token hash; separately, proof hash
        let mut record = baseline.clone();
        record[offset] ^= 1;
        let state = input.committed(&record, &first, &recovery);
        assert!(
            open_record(&state, &record, &password, &code).is_err(),
            "inner check at offset {offset}"
        );
    }
    for (sign, recv) in [
        ([0x41; 32], input.recovery_recv),
        (input.recovery_sign, [0x42; 32]),
    ] {
        let record = input.record(&sign, &recv, input.state.id()); // authentic AEAD, public half differs
        let state = input.committed(&record, &first, &recovery);
        assert!(open_record(&state, &record, &password, &code).is_err());
    }
    for offset in [74, 98] {
        // fresh commitment on corrupt nonce/ciphertext, not merely outer digest
        let mut record = baseline.clone();
        record[offset] ^= 1;
        let state = input.committed(&record, &first, &recovery);
        assert!(open_record(&state, &record, &password, &code).is_err());
    }
    let record = input.record(
        &input.recovery_sign,
        &input.recovery_recv,
        AccountId([0xa5; 32]),
    );
    let state = input.committed(&record, &first, &recovery);
    assert!(
        open_record(&state, &record, &password, &code).is_err(),
        "signed metadata correct but encryption used wrong account AD"
    );
}

#[test]
fn matching_signed_envelope_commitment_reaches_personal_public_and_aead_checks() {
    let input = Inputs::new();
    let (record, baseline, recovery) = input.baseline();
    let wrong_seed = [0x44; 32];
    let wrong = input.seal(1, input.first.receiving(), &wrong_seed, 1);
    let state = input.committed(&record, &wrong, &recovery); // signed expected metadata/public, authenticated wrong seed
    assert!(open_for_receiver(&state, &wrong, SealPurpose::FirstDevice, &input.device).is_err());
    for offset in [107, 1227, 1251] {
        // KEM, nonce, ciphertext; each digest is re-signed
        let mut seal = baseline.clone();
        seal[offset] ^= 1;
        let state = input.committed(&record, &seal, &recovery);
        assert!(open_for_receiver(&state, &seal, SealPurpose::FirstDevice, &input.device).is_err());
    }
    let wrong_ad = input.seal(1, input.first.receiving(), &input.personal_seed, 2);
    let state = input.committed(&record, &wrong_ad, &recovery);
    assert!(
        open_for_receiver(&state, &wrong_ad, SealPurpose::FirstDevice, &input.device).is_err(),
        "signed header purpose correct but AEAD bound another purpose"
    );
}
