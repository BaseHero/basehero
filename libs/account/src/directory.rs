//! The account directory at the account's home: entries sealed to the
//! personal key and signed by an active device, under ids derived from the
//! personal key so the home cannot test which bases they name.
//!
//! A reader that remembers an entry's version must refuse a lower one. A
//! fresh device remembers none, so the home can show it an older entry.
use crate::crypto::{self, Secret, SecretBytes};
use crate::personal::{self, PersonalKey};
use crate::recovery::{PASSWORD_CHECK_SIZE, PasswordCheck};
use crate::{AccountId, DeviceId, Error, VerifiedAccount};

const DOMAIN: &[u8] = b"bh/directory-entry/v1\0";
const HEADER: usize = DOMAIN.len() + 32 + 32 + 32 + 8 + 8 + 32 + 32;
const SEAL_OVERHEAD: usize = 1120 + 24 + 16;
/// Longest server address or device name, in UTF-8 bytes.
pub const MAX_TEXT: usize = 255;
/// Longest current key package in a base entry.
pub const MAX_KEY_PACKAGE: usize = 32 * 1024;
/// Longest metadata-key seal in a base entry.
pub const MAX_METADATA_SEAL: usize = 2048;
const MAX_PLAINTEXT: usize =
    1 + 32 + 32 + 1 + 1 + MAX_TEXT + 4 + MAX_KEY_PACKAGE + 4 + MAX_METADATA_SEAL;
pub const MAX_ENTRY: usize = HEADER + SEAL_OVERHEAD + MAX_PLAINTEXT + 64;

/// The key entry ids are derived from; only holders of the personal key have it.
pub fn directory_key(personal: &PersonalKey) -> Secret<32> {
    crypto::derive_key(&personal.seed(), b"BHADIR01", 1)
}

pub enum EntrySubject {
    Base([u8; 32]),
    DeviceName(DeviceId),
    PasswordCheck,
}
impl EntrySubject {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Base(base) => {
                out.push(1);
                out.extend_from_slice(base);
            }
            Self::DeviceName(device) => {
                out.push(2);
                out.extend_from_slice(&device.0);
            }
            Self::PasswordCheck => out.push(3),
        }
    }
}

pub fn entry_id(key: &Secret<32>, subject: &EntrySubject) -> [u8; 32] {
    const ID_DOMAIN: &[u8] = b"BH directory entry id v1\0";
    let mut input = Vec::with_capacity(ID_DOMAIN.len() + 32 + 33);
    input.extend_from_slice(ID_DOMAIN);
    input.extend_from_slice(key.expose());
    subject.encode(&mut input);
    let input = SecretBytes::from_vec(input);
    crypto::hash(input.expose())
}

/// A base entry carries only the base's current key package and its
/// metadata key M, each sealed to the current personal key; keys for its
/// earlier epochs are never listed. M is kept across a base's epochs, so a
/// device that recovers the account can verify the base's genesis and
/// controls. `own` marks the account's own base, which its own device
/// writes; every other base the account belongs to is not.
pub enum DirectoryEntry {
    Base {
        base: [u8; 32],
        server: String,
        epoch_id: [u8; 32],
        current_key_seal: Vec<u8>,
        metadata_seal: Vec<u8>,
        own: bool,
    },
    DeviceName {
        device: DeviceId,
        name: String,
    },
    PasswordCheck {
        check: PasswordCheck,
        record_digest: [u8; 32],
    },
}
impl DirectoryEntry {
    fn subject(&self) -> EntrySubject {
        match self {
            Self::Base { base, .. } => EntrySubject::Base(*base),
            Self::DeviceName { device, .. } => EntrySubject::DeviceName(*device),
            Self::PasswordCheck { .. } => EntrySubject::PasswordCheck,
        }
    }
    fn encode(&self) -> Result<SecretBytes, Error> {
        let mut out = Vec::with_capacity(MAX_PLAINTEXT);
        match self {
            Self::Base {
                base,
                server,
                epoch_id,
                current_key_seal,
                metadata_seal,
                own,
            } => {
                if server.len() > MAX_TEXT
                    || current_key_seal.len() > MAX_KEY_PACKAGE
                    || metadata_seal.len() > MAX_METADATA_SEAL
                {
                    return Err(Error::Malformed);
                }
                out.push(1);
                out.extend_from_slice(base);
                out.extend_from_slice(epoch_id);
                out.push(u8::from(*own));
                out.push(server.len() as u8);
                out.extend_from_slice(server.as_bytes());
                out.extend_from_slice(&(current_key_seal.len() as u32).to_be_bytes());
                out.extend_from_slice(current_key_seal);
                out.extend_from_slice(&(metadata_seal.len() as u32).to_be_bytes());
                out.extend_from_slice(metadata_seal);
            }
            Self::DeviceName { device, name } => {
                if name.len() > MAX_TEXT {
                    return Err(Error::Malformed);
                }
                out.push(2);
                out.extend_from_slice(&device.0);
                out.push(name.len() as u8);
                out.extend_from_slice(name.as_bytes());
            }
            Self::PasswordCheck {
                check,
                record_digest,
            } => {
                out.push(3);
                out.extend_from_slice(record_digest);
                out.extend_from_slice(check.encode().expose());
            }
        }
        Ok(SecretBytes::from_vec(out))
    }
    /// Strict: known kinds, bounded lengths, UTF-8 text, no trailing bytes.
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut input = Input(bytes);
        let entry = match input.take(1)?[0] {
            1 => {
                let base = input.array()?;
                let epoch_id = input.array()?;
                let own = match input.take(1)?[0] {
                    0 => false,
                    1 => true,
                    _ => return Err(Error::Malformed),
                };
                let server = input.text()?;
                let len = u32::from_be_bytes(input.array()?) as usize;
                if len > MAX_KEY_PACKAGE {
                    return Err(Error::Malformed);
                }
                let current_key_seal = input.take(len)?.to_vec();
                let len = u32::from_be_bytes(input.array()?) as usize;
                if len > MAX_METADATA_SEAL {
                    return Err(Error::Malformed);
                }
                Self::Base {
                    base,
                    server,
                    epoch_id,
                    current_key_seal,
                    metadata_seal: input.take(len)?.to_vec(),
                    own,
                }
            }
            2 => Self::DeviceName {
                device: DeviceId(input.array()?),
                name: input.text()?,
            },
            3 => Self::PasswordCheck {
                record_digest: input.array()?,
                check: PasswordCheck::decode(input.take(PASSWORD_CHECK_SIZE)?)?,
            },
            _ => return Err(Error::Malformed),
        };
        if !input.0.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(entry)
    }
}

struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < len {
            return Err(Error::Malformed);
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Malformed)
    }
    fn text(&mut self) -> Result<String, Error> {
        let len = usize::from(self.take(1)?[0]);
        String::from_utf8(self.take(len)?.to_vec()).map_err(|_| Error::Malformed)
    }
}

fn associated(account: AccountId, key_id: &[u8; 32]) -> Vec<u8> {
    [
        b"BH directory entry seal v1\0".as_slice(),
        &account.0,
        key_id,
    ]
    .concat()
}

/// Exact bytes for the signer's ordinary key. Completing it checks the
/// signature; it does not store the entry.
pub struct EntrySigningRequest {
    bytes: Vec<u8>,
    expected_key: [u8; 32],
}
impl EntrySigningRequest {
    pub fn signing_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn expected_key(&self) -> &[u8; 32] {
        &self.expected_key
    }
    pub fn finish(&self, signature: [u8; 64]) -> Result<Vec<u8>, Error> {
        crypto::verify(&self.expected_key, &self.bytes, &signature)
            .map_err(|_| Error::BadSignature)?;
        let mut entry = self.bytes.clone();
        entry.extend_from_slice(&signature);
        Ok(entry)
    }
}

/// Seal `entry` to the current personal key, for `signer`, an active device,
/// to sign at this view's head. A password check must name the current
/// recovery record.
pub fn prepare_entry(
    state: &VerifiedAccount,
    personal: &PersonalKey,
    signer: DeviceId,
    entry: &DirectoryEntry,
    version: u64,
) -> Result<EntrySigningRequest, Error> {
    let public = state.personal_public()?;
    if *public != personal.public() {
        return Err(Error::InvalidCredentials);
    }
    let expected_key = *state.active_device(signer)?.signing();
    if matches!(entry, DirectoryEntry::PasswordCheck { record_digest, .. }
        if *record_digest != state.record_digest()?)
    {
        return Err(Error::InvalidCredentials);
    }
    let plaintext = entry.encode()?;
    let key_id = personal::id(public);
    let id = entry_id(&directory_key(personal), &entry.subject());
    let (ct, shared) = crypto::encapsulate(public).map_err(|_| Error::CryptoFailure)?;
    let key = crypto::derive_key(&shared, b"BHADSE01", 1);
    let (nonce, sealed) =
        crypto::aead_seal(&key, &associated(state.id(), &key_id), plaintext.expose())
            .map_err(|_| Error::CryptoFailure)?;
    let head = state.head();
    let mut bytes = Vec::with_capacity(HEADER + SEAL_OVERHEAD + plaintext.expose().len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&state.id().0);
    bytes.extend_from_slice(&key_id);
    bytes.extend_from_slice(&id);
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(&head.position.to_be_bytes());
    bytes.extend_from_slice(&head.hash);
    bytes.extend_from_slice(&signer.0);
    bytes.extend_from_slice(&ct);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&sealed);
    Ok(EntrySigningRequest {
        bytes,
        expected_key,
    })
}

pub struct OpenedEntry {
    pub entry: DirectoryEntry,
    pub entry_id: [u8; 32],
    pub version: u64,
    pub signer: DeviceId,
}

/// Open an entry under the current personal key. Refused: another account,
/// another personal key (entries under a rotated-away key are ignored), a head
/// beyond this view's, a signer no longer active or not active at that head, a
/// bad signature, a signed head hash other than this history's at that
/// position (`Fork`), an id not derived from the sealed subject, or a password
/// check for an earlier recovery record. Judges the signer by the head's
/// position in this view's history. The hash is compared where the view holds
/// it, since its index cut; an earlier head is judged by position only.
pub fn open_entry(
    state: &VerifiedAccount,
    personal: &PersonalKey,
    bytes: &[u8],
) -> Result<OpenedEntry, Error> {
    if bytes.len() < HEADER + SEAL_OVERHEAD + 64
        || bytes.len() > MAX_ENTRY
        || &bytes[..DOMAIN.len()] != DOMAIN
    {
        return Err(Error::Malformed);
    }
    let mut input = Input(&bytes[DOMAIN.len()..bytes.len() - 64]);
    let account = AccountId(input.array()?);
    let key_id: [u8; 32] = input.array()?;
    let id: [u8; 32] = input.array()?;
    let version = u64::from_be_bytes(input.array()?);
    let position = u64::from_be_bytes(input.array()?);
    let head_hash: [u8; 32] = input.array()?;
    let signer = DeviceId(input.array()?);
    let ct: [u8; 1120] = input.array()?;
    let nonce: [u8; 24] = input.array()?;
    let sealed = input.0;
    if account != state.id() {
        return Err(Error::WrongAccount);
    }
    let public = state.personal_public()?;
    if *public != personal.public() || key_id != personal::id(public) {
        return Err(Error::InvalidCredentials);
    }
    if position > state.head().position {
        return Err(Error::TruncatedHistory);
    }
    // A removed signer is refused before older membership is consulted,
    // which the index may not answer.
    let signing = *state.active_device(signer)?.signing();
    let signature: [u8; 64] = bytes[bytes.len() - 64..]
        .try_into()
        .map_err(|_| Error::Malformed)?;
    crypto::verify(&signing, &bytes[..bytes.len() - 64], &signature)
        .map_err(|_| Error::BadSignature)?;
    if state
        .verified_head_at(position)
        .is_some_and(|hash| hash != head_hash)
    {
        return Err(Error::Fork);
    }
    if !state.active_at(signer, position)? {
        return Err(Error::NotActive);
    }
    let shared = personal.decapsulate(&ct)?;
    let key = crypto::derive_key(&shared, b"BHADSE01", 1);
    let plaintext = crypto::aead_open(&key, &nonce, &associated(account, &key_id), sealed)
        .map_err(|_| Error::InvalidCredentials)?;
    let entry = DirectoryEntry::decode(plaintext.expose())?;
    if entry_id(&directory_key(personal), &entry.subject()) != id {
        return Err(Error::InvalidCredentials);
    }
    if matches!(&entry, DirectoryEntry::PasswordCheck { record_digest, .. }
        if *record_digest != state.record_digest()?)
    {
        return Err(Error::InvalidCredentials);
    }
    Ok(OpenedEntry {
        entry,
        entry_id: id,
        version,
        signer,
    })
}
