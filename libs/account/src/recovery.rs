//! Initial ordinary recovery materials; no home release check or kit persistence.
use crate::crypto::{self, KemKey, Secret, SecretBytes, SigningKey};
use crate::{AccountId, Error, RecoveryPublicKeys, VerifiedAccount};

const PREFIX: &[u8; 8] = b"BHREC01\0";
const SALT: &[u8; 16] = b"BaseHeroRecovV01";
const SIZE: usize = 242;

pub struct Password(SecretBytes);
impl Password {
    pub fn new(utf8: &str) -> Result<Self, Error> {
        if !(1..=1024).contains(&utf8.len()) {
            return Err(Error::Malformed);
        }
        Ok(Self(
            SecretBytes::from_parts(&[utf8.as_bytes()]).map_err(|_| Error::CryptoFailure)?,
        ))
    }
}

pub struct RecoveryCode(Secret<16>);
impl RecoveryCode {
    pub fn generate() -> Self {
        Self(Secret::random())
    }
    pub fn from_raw(bytes: &[u8; 16]) -> Self {
        Self(Secret::from_slice(bytes).expect("fixed size"))
    }
    /// Only a trusted kit exporter or explicitly gated checker may read these raw bytes.
    pub fn expose(&self) -> &[u8; 16] {
        self.0.expose()
    }
}

pub struct RecoveryKeys {
    signing: SigningKey,
    receiver: KemKey,
}
impl RecoveryKeys {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(),
            receiver: KemKey::generate(),
        }
    }
    pub fn public(&self) -> RecoveryPublicKeys {
        RecoveryPublicKeys::new(self.signing.public(), self.receiver.public())
    }
    pub fn receiver(&self) -> &KemKey {
        &self.receiver
    }
    fn from_plaintext(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 64 {
            return Err(Error::Malformed);
        }
        let signing = Secret::<32>::from_slice(&bytes[..32]).map_err(|_| Error::Malformed)?;
        let receiving = Secret::<32>::from_slice(&bytes[32..]).map_err(|_| Error::Malformed)?;
        Ok(Self {
            signing: SigningKey::from_seed(&signing),
            receiver: KemKey::from_seed(&receiving),
        })
    }
}

pub struct PreparedRecoveryRecord {
    bytes: SecretBytes,
    digest: [u8; 32],
}
impl PreparedRecoveryRecord {
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.expose()
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

fn key_id(public: &RecoveryPublicKeys) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(27 + 32 + 1216);
    bytes.extend_from_slice(b"BH recovery key id v1\0");
    bytes.extend_from_slice(public.signing());
    bytes.extend_from_slice(public.receiving());
    crypto::hash(&bytes)
}
fn commitment(bytes: &[u8]) -> Result<[u8; 32], Error> {
    let encoded = SecretBytes::from_parts(&[b"BH recovery record commit v1\0", bytes])
        .map_err(|_| Error::CryptoFailure)?;
    Ok(crypto::hash(encoded.expose()))
}
fn associated(account: AccountId, id: &[u8; 32]) -> Vec<u8> {
    [
        b"BH recovery wrap v1\0".as_slice(),
        &1u16.to_be_bytes(),
        &account.0,
        id,
    ]
    .concat()
}
fn root(password: &Password, code: &RecoveryCode) -> Result<Secret<32>, Error> {
    let framed = SecretBytes::from_parts(&[
        b"BH ordinary recovery v1\0",
        &(password.0.expose().len() as u16).to_be_bytes(),
        password.0.expose(),
        code.expose(),
    ])
    .map_err(|_| Error::CryptoFailure)?;
    crypto::pwhash_argon2id13(framed.expose(), SALT, 2, 64 * 1024 * 1024)
        .map_err(|_| Error::CryptoFailure)
}
fn token_hash(root: &Secret<32>) -> Result<Secret<32>, Error> {
    let token = crypto::derive_key(root, b"BHRTOK01", 1);
    let framed = SecretBytes::from_parts(&[b"BH recovery token check v1\0", token.expose()])
        .map_err(|_| Error::CryptoFailure)?;
    Ok(crypto::hash_secret(framed.expose()))
}
fn proof_hash(code: &RecoveryCode) -> Result<Secret<32>, Error> {
    let input = SecretBytes::from_parts(&[b"BH ordinary code proof v1\0", code.expose()])
        .map_err(|_| Error::CryptoFailure)?;
    let proof = crypto::hash_secret(input.expose());
    let check = SecretBytes::from_parts(&[b"BH recovery proof check v1\0", proof.expose()])
        .map_err(|_| Error::CryptoFailure)?;
    Ok(crypto::hash_secret(check.expose()))
}

pub fn prepare_record(
    state: &VerifiedAccount,
    keys: &RecoveryKeys,
    password: &Password,
    code: &RecoveryCode,
) -> Result<PreparedRecoveryRecord, Error> {
    state.preparing_record()?;
    let public = state.recovery_keys()?;
    if public.signing() != keys.public().signing()
        || public.receiving() != keys.public().receiving()
    {
        return Err(Error::InvalidSetup);
    }
    let id = key_id(public);
    let root = root(password, code)?;
    let wrap = crypto::derive_key(&root, b"BHRWRA01", 1);
    let signing = keys.signing.export_seed();
    let receiving = keys.receiver.export_seed();
    let plaintext = SecretBytes::from_parts(&[signing.expose(), receiving.expose()])
        .map_err(|_| Error::CryptoFailure)?;
    let (nonce, ciphertext) =
        crypto::aead_seal(&wrap, &associated(state.id(), &id), plaintext.expose())
            .map_err(|_| Error::CryptoFailure)?;
    let token = token_hash(&root)?;
    let proof = proof_hash(code)?;
    let bytes = SecretBytes::from_parts(&[
        PREFIX,
        &1u16.to_be_bytes(),
        &state.id().0,
        &id,
        &nonce,
        &ciphertext,
        token.expose(),
        proof.expose(),
    ])
    .map_err(|_| Error::CryptoFailure)?;
    debug_assert_eq!(bytes.expose().len(), SIZE);
    let digest = commitment(bytes.expose())?;
    Ok(PreparedRecoveryRecord { bytes, digest })
}

pub fn open_record(
    state: &VerifiedAccount,
    bytes: &[u8],
    password: &Password,
    code: &RecoveryCode,
) -> Result<RecoveryKeys, Error> {
    let (signed_digest, _) = state.initial_materials()?;
    if bytes.len() != SIZE
        || &bytes[..8] != PREFIX
        || &bytes[8..10] != 1u16.to_be_bytes().as_slice()
    {
        return Err(Error::Malformed);
    }
    if !crypto::constant_time_eq(&commitment(bytes)?, signed_digest) {
        return Err(Error::InvalidCredentials);
    }
    let public = state.recovery_keys()?;
    let id = key_id(public);
    if bytes[10..42] != state.id().0 || bytes[42..74] != id {
        return Err(Error::InvalidCredentials);
    }
    let nonce: &[u8; 24] = bytes[74..98].try_into().map_err(|_| Error::Malformed)?;
    let root = root(password, code)?;
    let wrap = crypto::derive_key(&root, b"BHRWRA01", 1);
    let plaintext = crypto::aead_open(&wrap, nonce, &associated(state.id(), &id), &bytes[98..178])
        .map_err(|_| Error::InvalidCredentials)?;
    if !crypto::constant_time_eq(&bytes[178..210], token_hash(&root)?.expose())
        || !crypto::constant_time_eq(&bytes[210..242], proof_hash(code)?.expose())
    {
        return Err(Error::InvalidCredentials);
    }
    let restored = RecoveryKeys::from_plaintext(plaintext.expose())?;
    if restored.public().signing() != public.signing()
        || restored.public().receiving() != public.receiving()
    {
        return Err(Error::InvalidCredentials);
    }
    Ok(restored)
}

// Fixed reference answers from independent direct libsodium 1.0.22 ctypes calls.
#[cfg(test)]
mod vectors {
    use super::*;
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    #[test]
    fn framed_argon_and_separate_kdf_domains() {
        let password = Password::new("pa\0ssé").unwrap();
        let code = RecoveryCode::from_raw(&std::array::from_fn(|i| i as u8));
        let root = root(&password, &code).unwrap();
        assert_eq!(
            hex(root.expose()),
            "f7a8de2f5943f150b2757fdf3eac2f0f3c8241b7fbcd87264df2ef59a3bf1361"
        );
        assert_eq!(
            hex(crypto::derive_key(&root, b"BHRWRA01", 1).expose()),
            "3e53b3e5bee5886d6884d8b2b53aa42f32b310fe686e0048c62a2edd1a723175"
        );
        assert_eq!(
            hex(crypto::derive_key(&root, b"BHRTOK01", 1).expose()),
            "fb203fcdc2eeeedf31339c4dc8e86b4208acba77b0e8095471a63fc06eec70ed"
        );
        // Final home-private values, independently calculated by direct libsodium
        // ctypes crypto_generichash over the framed token/proof domains.
        assert_eq!(
            hex(token_hash(&root).unwrap().expose()),
            "198f9fcf849a71e99ccc02bc860e9f948eb2f9fac9e7db0f0412bda6afac4fd5"
        );
        let expected_proof = "c1186ed09939eb6ee5502e739bf774a7478b5249ec5f46c20b9fabd3827ca6b3";
        assert_eq!(hex(proof_hash(&code).unwrap().expose()), expected_proof);
        let other_root = super::root(&Password::new("other-password").unwrap(), &code).unwrap();
        assert_eq!(hex(proof_hash(&code).unwrap().expose()), expected_proof);
        assert_eq!(
            hex(token_hash(&other_root).unwrap().expose()),
            "5fd2a24a045f4cc3deb8a1b350c50bec6d0a719fafc4b7ffbed8e470ceaef749"
        );
        let mut changed_code = std::array::from_fn(|i| i as u8);
        changed_code[0] = 1;
        let changed_code = RecoveryCode::from_raw(&changed_code);
        assert_eq!(
            hex(proof_hash(&changed_code).unwrap().expose()),
            "301f2c8953e08a4d4c9604d1304b508a55c4e944230371221047fccbc5c4f2ee"
        );
        assert_ne!(
            token_hash(&root).unwrap().expose(),
            token_hash(&super::root(&password, &changed_code).unwrap())
                .unwrap()
                .expose()
        );
    }
}
