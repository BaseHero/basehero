//! Ordinary recovery materials: the record, its replacement, the sealed claim
//! a recovering device sends its home, and the local password check. No kit
//! persistence.
use crate::crypto::{self, KemKey, Secret, SecretBytes, SigningKey};
use crate::{AccountId, Error, RecoveryPublicKeys, VerifiedAccount};

const PREFIX: &[u8; 8] = b"BHREC01\0";
const SALT: &[u8; 16] = b"BaseHeroRecovV01";
const SIZE: usize = 242;
const OPS: u64 = 2;
const MEMORY: usize = 64 * 1024 * 1024;
const CLAIM_PREFIX: &[u8; 8] = b"BHRCLM01";
const CLAIM_SIZE: usize = 8 + 2 + 1 + 1120 + 24 + 64 + 16;
const CHECK_PREFIX: &[u8; 8] = b"BHPWCK01";
/// Every base original's signing bytes start with this domain, then its
/// binding: versions and mode, base, audience, epoch and event id, then the
/// account and the author.
const BASE_ORIGINAL: &[u8] = b"bh/original-envelope/v1\0";
const MODE_AT: usize = BASE_ORIGINAL.len() + 2 + 2;
const ACCOUNT_AT: usize = MODE_AT + 1 + 4 * 32;
const AUTHOR_AT: usize = ACCOUNT_AT + 32;
pub(crate) const PASSWORD_CHECK_SIZE: usize = 8 + 16 + 32;

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

#[cfg(test)]
mod kit_format_tests {
    use super::*;
    #[test]
    fn kit_code_has_34_readable_characters_and_checks_a_typo() {
        let code = RecoveryCode::from_raw(&std::array::from_fn(|i| i as u8));
        let printed = code.to_kit_text();
        assert_eq!(printed.len(), 34);
        assert_eq!(
            RecoveryCode::from_kit_text(&printed).unwrap().expose(),
            code.expose()
        );
        let mut altered = printed.into_bytes();
        altered[0] = if altered[0] == b'A' { b'B' } else { b'A' };
        assert!(RecoveryCode::from_kit_text(&String::from_utf8(altered).unwrap()).is_err());
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

    /// 128 random bits as 26 base32 characters plus two checksum characters;
    /// seven groups of four separated by dashes (34 printable characters).
    pub fn to_kit_text(&self) -> String {
        const LETTERS: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut symbols = [0u8; 28];
        for (index, symbol) in symbols.iter_mut().enumerate().take(26) {
            let bit = index * 5;
            let source = bit / 8;
            let shift = bit % 8;
            let high = u16::from(self.expose()[source]) << 8;
            let low = u16::from(*self.expose().get(source + 1).unwrap_or(&0));
            *symbol = LETTERS[usize::from(((high | low) >> (11 - shift)) & 31)];
        }
        let digest = crate::crypto::hash(self.expose());
        symbols[26] = LETTERS[usize::from(digest[0] >> 3)];
        symbols[27] = LETTERS
            [usize::from(((u16::from(digest[0]) << 2) | (u16::from(digest[1]) >> 6)) as u8 & 31)];
        let mut text = String::with_capacity(34);
        for (index, letter) in symbols.iter().enumerate() {
            if index > 0 && index % 4 == 0 {
                text.push('-');
            }
            text.push(char::from(*letter));
        }
        text
    }

    pub fn from_kit_text(text: &str) -> Result<Self, Error> {
        if text.len() > 64 {
            return Err(Error::Malformed);
        }
        let raw: Vec<u8> = text.bytes().filter(|b| *b != b'-' && *b != b' ').collect();
        if raw.len() != 28 {
            return Err(Error::Malformed);
        }
        let mut symbols = [0u8; 28];
        for (index, letter) in raw.iter().enumerate() {
            let upper = letter.to_ascii_uppercase();
            symbols[index] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
                .iter()
                .position(|candidate| *candidate == upper)
                .ok_or(Error::Malformed)? as u8;
        }
        if symbols[25] & 3 != 0 {
            return Err(Error::Malformed);
        }
        let mut code = [0u8; 16];
        for (index, symbol) in symbols[..26].iter().enumerate() {
            for shift in 0..5 {
                let bit = index * 5 + shift;
                if bit < 128 && (symbol >> (4 - shift)) & 1 == 1 {
                    code[bit / 8] |= 1 << (7 - bit % 8);
                }
            }
        }
        let digest = crate::crypto::hash(&code);
        if symbols[26] != digest[0] >> 3
            || symbols[27] != ((u16::from(digest[0]) << 2 | u16::from(digest[1]) >> 6) & 31) as u8
        {
            return Err(Error::InvalidCredentials);
        }
        Ok(Self::from_raw(&code))
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
    /// Callers sign through the purpose-bound request methods instead.
    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message)
    }
    /// Sign a base control as `state`'s current recovery key, which copies
    /// account entries into a base for a device that recovered the account:
    /// only an ordinary (not genesis) base original's signing bytes naming
    /// `state`'s account and its recovery author, for `expected`, which must be this key and the one
    /// `state` holds current. A replaced kit's key signs nothing.
    pub fn sign_base_control(
        &self,
        state: &VerifiedAccount,
        expected: &[u8; 32],
        message: &[u8],
    ) -> Result<[u8; 64], Error> {
        let current = state.recovery_keys()?;
        let public = self.public();
        if current.signing() != public.signing()
            || current.receiving() != public.receiving()
            || expected != public.signing()
        {
            return Err(Error::InvalidCredentials);
        }
        if !message.starts_with(BASE_ORIGINAL)
            || message.len() < AUTHOR_AT + 32
            || message[MODE_AT] != 0
            || message[ACCOUNT_AT..AUTHOR_AT] != state.id().0
            || message[AUTHOR_AT..AUTHOR_AT + 32] != state.recovery_author()?.0
        {
            return Err(Error::NotPermitted);
        }
        Ok(self.sign(message))
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
pub(crate) fn commitment(bytes: &[u8]) -> Result<[u8; 32], Error> {
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
    crypto::pwhash_argon2id13(framed.expose(), SALT, OPS, MEMORY).map_err(|_| Error::CryptoFailure)
}
fn token(root: &Secret<32>) -> Secret<32> {
    crypto::derive_key(root, b"BHRTOK01", 1)
}
fn token_check(token: &Secret<32>) -> Result<Secret<32>, Error> {
    let framed = SecretBytes::from_parts(&[b"BH recovery token check v1\0", token.expose()])
        .map_err(|_| Error::CryptoFailure)?;
    Ok(crypto::hash_secret(framed.expose()))
}
fn token_hash(root: &Secret<32>) -> Result<Secret<32>, Error> {
    token_check(&token(root))
}
fn proof(code: &RecoveryCode) -> Result<Secret<32>, Error> {
    let input = SecretBytes::from_parts(&[b"BH ordinary code proof v1\0", code.expose()])
        .map_err(|_| Error::CryptoFailure)?;
    Ok(crypto::hash_secret(input.expose()))
}
fn proof_check(proof: &Secret<32>) -> Result<Secret<32>, Error> {
    let check = SecretBytes::from_parts(&[b"BH recovery proof check v1\0", proof.expose()])
        .map_err(|_| Error::CryptoFailure)?;
    Ok(crypto::hash_secret(check.expose()))
}
fn proof_hash(code: &RecoveryCode) -> Result<Secret<32>, Error> {
    proof_check(&proof(code)?)
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
    encode_record(state.id(), keys, password, code)
}

/// A record for a new recovery key replacing the current one, under a new
/// code and the current or a new password. The ReplaceRecovery event that
/// signs its digest makes it current.
pub fn prepare_replacement(
    state: &VerifiedAccount,
    keys: &RecoveryKeys,
    password: &Password,
    code: &RecoveryCode,
) -> Result<PreparedRecoveryRecord, Error> {
    state.initial_materials()?;
    state.check_new_recovery(&keys.public())?;
    encode_record(state.id(), keys, password, code)
}

fn encode_record(
    account: AccountId,
    keys: &RecoveryKeys,
    password: &Password,
    code: &RecoveryCode,
) -> Result<PreparedRecoveryRecord, Error> {
    let id = key_id(&keys.public());
    let root = root(password, code)?;
    let wrap = crypto::derive_key(&root, b"BHRWRA01", 1);
    let signing = keys.signing.export_seed();
    let receiving = keys.receiver.export_seed();
    let plaintext = SecretBytes::from_parts(&[signing.expose(), receiving.expose()])
        .map_err(|_| Error::CryptoFailure)?;
    let (nonce, ciphertext) =
        crypto::aead_seal(&wrap, &associated(account, &id), plaintext.expose())
            .map_err(|_| Error::CryptoFailure)?;
    let token = token_hash(&root)?;
    let proof = proof_hash(code)?;
    let bytes = SecretBytes::from_parts(&[
        PREFIX,
        &1u16.to_be_bytes(),
        &account.0,
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

fn shape(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() != SIZE
        || &bytes[..8] != PREFIX
        || &bytes[8..10] != 1u16.to_be_bytes().as_slice()
    {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Open a well-shaped record naming `account` and recovery key `id`; the
/// caller compares the restored keys with what it expects.
fn unwrap_record(
    bytes: &[u8],
    account: AccountId,
    id: &[u8; 32],
    password: &Password,
    code: &RecoveryCode,
) -> Result<RecoveryKeys, Error> {
    if bytes[10..42] != account.0 || bytes[42..74] != *id {
        return Err(Error::InvalidCredentials);
    }
    let nonce: &[u8; 24] = bytes[74..98].try_into().map_err(|_| Error::Malformed)?;
    let root = root(password, code)?;
    let wrap = crypto::derive_key(&root, b"BHRWRA01", 1);
    let plaintext = crypto::aead_open(&wrap, nonce, &associated(account, id), &bytes[98..178])
        .map_err(|_| Error::InvalidCredentials)?;
    if !crypto::constant_time_eq(&bytes[178..210], token_hash(&root)?.expose())
        || !crypto::constant_time_eq(&bytes[210..242], proof_hash(code)?.expose())
    {
        return Err(Error::InvalidCredentials);
    }
    RecoveryKeys::from_plaintext(plaintext.expose())
}

/// The initial record, once the account's setup materials are complete.
pub fn open_record(
    state: &VerifiedAccount,
    bytes: &[u8],
    password: &Password,
    code: &RecoveryCode,
) -> Result<RecoveryKeys, Error> {
    state.initial_materials()?;
    open_current_record(state, bytes, password, code)
}

/// Open the record whose digest the log names as current (the initial one or
/// the latest replacement's) and check its keys are the current recovery key.
pub fn open_current_record(
    state: &VerifiedAccount,
    bytes: &[u8],
    password: &Password,
    code: &RecoveryCode,
) -> Result<RecoveryKeys, Error> {
    let signed_digest = state.record_digest()?;
    shape(bytes)?;
    if !crypto::constant_time_eq(&commitment(bytes)?, &signed_digest) {
        return Err(Error::InvalidCredentials);
    }
    let public = state.recovery_keys()?;
    let restored = unwrap_record(bytes, state.id(), &key_id(public), password, code)?;
    if restored.public().signing() != public.signing()
        || restored.public().receiving() != public.receiving()
    {
        return Err(Error::InvalidCredentials);
    }
    Ok(restored)
}

/// The account a released record belongs to, authenticated by the record's
/// encryption under this password and code: a recovering device's anchor,
/// before it has any history. A home cannot relabel a record for another
/// account.
pub fn account_of_record(
    bytes: &[u8],
    password: &Password,
    code: &RecoveryCode,
) -> Result<AccountId, Error> {
    shape(bytes)?;
    let account = AccountId(bytes[10..42].try_into().map_err(|_| Error::Malformed)?);
    let id: [u8; 32] = bytes[42..74].try_into().map_err(|_| Error::Malformed)?;
    let restored = unwrap_record(bytes, account, &id, password, code)?;
    if key_id(&restored.public()) != id {
        return Err(Error::InvalidCredentials);
    }
    Ok(account)
}

/// What a home indexes and compares for a record. Shape only: nothing here
/// is authenticated until the account's log names `digest`.
pub struct RecordChecks {
    pub account: AccountId,
    pub token_check: [u8; 32],
    pub proof_check: [u8; 32],
    pub digest: [u8; 32],
}
pub fn record_checks(record: &[u8]) -> Result<RecordChecks, Error> {
    shape(record)?;
    let field = |range: std::ops::Range<usize>| -> Result<[u8; 32], Error> {
        record[range].try_into().map_err(|_| Error::Malformed)
    };
    Ok(RecordChecks {
        account: AccountId(field(10..42)?),
        token_check: field(178..210)?,
        proof_check: field(210..242)?,
        digest: commitment(record)?,
    })
}

/// The code's proof and the password-and-code check token, as a recovering
/// device sends them to its home. The home keeps only their checks.
pub struct RecoveryClaim {
    proof: Secret<32>,
    token: Secret<32>,
    proof_check: [u8; 32],
    token_check: [u8; 32],
}
impl RecoveryClaim {
    fn new(proof: Secret<32>, token: Secret<32>) -> Result<Self, Error> {
        Ok(Self {
            proof_check: *proof_check(&proof)?.expose(),
            token_check: *token_check(&token)?.expose(),
            proof,
            token,
        })
    }
    /// Equals the record's proof check, whatever the password.
    pub fn proof_check(&self) -> [u8; 32] {
        self.proof_check
    }
    /// Equals the record's token check only with the right password too.
    pub fn token_check(&self) -> [u8; 32] {
        self.token_check
    }
}

pub fn claim(password: &Password, code: &RecoveryCode) -> Result<RecoveryClaim, Error> {
    RecoveryClaim::new(proof(code)?, token(&root(password, code)?))
}

fn claim_associated(home: &[u8; 1216], nonce: &[u8; 32], purpose: u8) -> Vec<u8> {
    [
        b"BH recovery claim v1\0".as_slice(),
        &1u16.to_be_bytes(),
        &[purpose],
        nonce,
        &crypto::hash(&[b"BH recovery claim home v1\0".as_slice(), home].concat()),
    ]
    .concat()
}

/// Seal a claim to the home's X-Wing key for one fresh home nonce and
/// purpose; it opens for no other nonce or purpose.
pub fn seal_claim(
    home_key: &[u8; 1216],
    claim: &RecoveryClaim,
    nonce: &[u8; 32],
    purpose: u8,
) -> Result<Vec<u8>, Error> {
    let (ct, shared) = crypto::encapsulate(home_key).map_err(|_| Error::CryptoFailure)?;
    let key = crypto::derive_key(&shared, b"BHRCLK01", 1);
    let plaintext = SecretBytes::from_parts(&[claim.proof.expose(), claim.token.expose()])
        .map_err(|_| Error::CryptoFailure)?;
    let (aead_nonce, ciphertext) = crypto::aead_seal(
        &key,
        &claim_associated(home_key, nonce, purpose),
        plaintext.expose(),
    )
    .map_err(|_| Error::CryptoFailure)?;
    let mut sealed = Vec::with_capacity(CLAIM_SIZE);
    sealed.extend_from_slice(CLAIM_PREFIX);
    sealed.extend_from_slice(&1u16.to_be_bytes());
    sealed.push(purpose);
    sealed.extend_from_slice(&ct);
    sealed.extend_from_slice(&aead_nonce);
    sealed.extend_from_slice(&ciphertext);
    debug_assert_eq!(sealed.len(), CLAIM_SIZE);
    Ok(sealed)
}

/// The home opens a claim with its private key and the nonce it issued;
/// returns the claim and its purpose.
pub fn open_claim(
    home: &KemKey,
    sealed: &[u8],
    nonce: &[u8; 32],
) -> Result<(RecoveryClaim, u8), Error> {
    if sealed.len() != CLAIM_SIZE
        || &sealed[..8] != CLAIM_PREFIX
        || &sealed[8..10] != 1u16.to_be_bytes().as_slice()
    {
        return Err(Error::Malformed);
    }
    let purpose = sealed[10];
    let ct: &[u8; 1120] = sealed[11..1131].try_into().map_err(|_| Error::Malformed)?;
    let aead_nonce: &[u8; 24] = sealed[1131..1155]
        .try_into()
        .map_err(|_| Error::Malformed)?;
    let shared = crypto::decapsulate(home, ct).map_err(|_| Error::InvalidCredentials)?;
    let key = crypto::derive_key(&shared, b"BHRCLK01", 1);
    let plaintext = crypto::aead_open(
        &key,
        aead_nonce,
        &claim_associated(&home.public(), nonce, purpose),
        &sealed[1155..],
    )
    .map_err(|_| Error::InvalidCredentials)?;
    let proof = Secret::from_slice(&plaintext.expose()[..32]).map_err(|_| Error::Malformed)?;
    let token = Secret::from_slice(&plaintext.expose()[32..]).map_err(|_| Error::Malformed)?;
    Ok((RecoveryClaim::new(proof, token)?, purpose))
}

/// A device-local check of the password alone, for changing it: Argon2id
/// with a random salt. It never leaves the account's devices unencrypted.
pub struct PasswordCheck {
    salt: [u8; 16],
    verifier: Secret<32>,
}
impl PasswordCheck {
    pub fn encode(&self) -> SecretBytes {
        SecretBytes::from_vec(
            [CHECK_PREFIX.as_slice(), &self.salt, self.verifier.expose()].concat(),
        )
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PASSWORD_CHECK_SIZE || &bytes[..8] != CHECK_PREFIX {
            return Err(Error::Malformed);
        }
        Ok(Self {
            salt: bytes[8..24].try_into().map_err(|_| Error::Malformed)?,
            verifier: Secret::from_slice(&bytes[24..]).map_err(|_| Error::Malformed)?,
        })
    }
}
fn password_verifier(password: &Password, salt: &[u8; 16]) -> Result<Secret<32>, Error> {
    let framed = SecretBytes::from_parts(&[
        b"BH password check v1\0",
        &(password.0.expose().len() as u16).to_be_bytes(),
        password.0.expose(),
    ])
    .map_err(|_| Error::CryptoFailure)?;
    crypto::pwhash_argon2id13(framed.expose(), salt, OPS, MEMORY).map_err(|_| Error::CryptoFailure)
}
pub fn make_password_check(password: &Password) -> Result<PasswordCheck, Error> {
    let salt = crypto::random::<16>();
    Ok(PasswordCheck {
        verifier: password_verifier(password, &salt)?,
        salt,
    })
}
pub fn verify_password(check: &PasswordCheck, password: &Password) -> Result<(), Error> {
    let verifier = password_verifier(password, &check.salt)?;
    if !crypto::constant_time_eq(verifier.expose(), check.verifier.expose()) {
        return Err(Error::InvalidCredentials);
    }
    Ok(())
}

#[cfg(test)]
mod base_control_tests {
    use super::*;
    use crate::{AccountEvent, AccountId, DevicePublicKeys};

    /// A one-device account whose recovery key is `keys`.
    fn account(keys: &RecoveryKeys) -> VerifiedAccount {
        let control = SigningKey::generate();
        let first = DevicePublicKeys::new(
            SigningKey::generate().public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        let draft = AccountEvent::genesis(first, keys.public());
        let genesis = draft.finish(control.sign(draft.signing_bytes())).unwrap();
        let id = AccountId::of_genesis(&genesis).unwrap();
        VerifiedAccount::from_genesis(id, genesis.as_bytes()).unwrap()
    }

    /// A base original's signing bytes naming `account` and `author`.
    fn original(account: AccountId, author: crate::DeviceId) -> Vec<u8> {
        let mut bytes = BASE_ORIGINAL.to_vec();
        bytes.extend([0, 3, 0, 3, 0]);
        bytes.extend([7; 32 * 4]);
        bytes.extend(account.0);
        bytes.extend(author.0);
        bytes.extend([9; 200]);
        bytes
    }

    #[test]
    fn the_current_recovery_key_signs_only_this_accounts_base_originals_as_itself() {
        let keys = RecoveryKeys::generate();
        let state = account(&keys);
        let expected = *state.recovery_keys().unwrap().signing();
        let author = state.recovery_author().unwrap();
        let message = original(state.id(), author);
        let signature = keys.sign_base_control(&state, &expected, &message).unwrap();
        crypto::verify(&expected, &message, &signature).unwrap();
        // Not a base original: an account event's or any other bytes.
        let mut account_event = message.clone();
        account_event[..BASE_ORIGINAL.len()].copy_from_slice(b"BaseHero account event\0\0");
        let mut another_account = message.clone();
        another_account[ACCOUNT_AT] ^= 1;
        let mut another_author = message.clone();
        another_author[AUTHOR_AT] ^= 1;
        // A genesis's mode, not an ordinary control's.
        let mut genesis_mode = message.clone();
        genesis_mode[MODE_AT] = 1;
        for refused in [
            account_event,
            another_account,
            another_author,
            genesis_mode,
            message[..AUTHOR_AT + 31].to_vec(),
            b"anything".to_vec(),
        ] {
            assert!(keys.sign_base_control(&state, &expected, &refused).is_err());
        }
        // A key the request does not name, or one the account no longer
        // holds current (another kit's), signs nothing.
        assert!(keys.sign_base_control(&state, &[1; 32], &message).is_err());
        let replaced = RecoveryKeys::generate();
        let replaced_key = replaced.public().signing().to_owned();
        assert!(
            replaced
                .sign_base_control(&state, &replaced_key, &message)
                .is_err()
        );
    }
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
