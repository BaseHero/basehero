//! Native-only signed base-root envelopes. Identity-bearing headers and packages
//! are protected objects, never service routing headers or WebView output.
use bh_account::{AccountId, DeviceId, Head, VerifiedAccount, personal::PersonalKey};
use bh_crypto::{Secret, aead_open, aead_seal, derive_key, encapsulate, hash, verify};
use bh_event::key_id;
use bh_sync::BaseId;

pub const HEADER_LEN: usize = 243;
pub const SEAL_LEN: usize = HEADER_LEN + 1120 + 24 + 48 + 64;
pub const PACKAGE_LEN: usize = 8 + 2 + 4 + SEAL_LEN + 4 + SEAL_LEN;
const SIGNATURE_DOMAIN: &[u8] = b"BH base key seal signature v1\0";
const PACKAGE_DOMAIN: &[u8] = b"BH initial base key package v1\0";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum BaseKeyPurpose {
    Metadata = 1,
    Content = 2,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SealError {
    Encoding,
    Context,
    Signature,
    Crypto,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SealHeader {
    pub purpose: BaseKeyPurpose,
    pub base: BaseId,
    pub audience: [u8; 32],
    pub key_id: [u8; 32],
    /// Hash of the exact authenticated personal-public bytes.
    pub recipient: [u8; 32],
    pub sender: AccountId,
    pub device: DeviceId,
    pub head: Head,
}
impl SealHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend(b"BHBKSL01");
        out.extend(1u16.to_be_bytes());
        out.push(self.purpose as u8);
        out.extend(self.base.0);
        out.extend(self.audience);
        out.extend(self.key_id);
        out.extend(self.recipient);
        out.extend(self.sender.0);
        out.extend(self.device.0);
        out.extend(self.head.position.to_be_bytes());
        out.extend(self.head.hash);
        debug_assert_eq!(out.len(), HEADER_LEN);
        out
    }
    /// Parse only a complete v1 frame. Parsing alone confers no authority.
    pub fn decode(seal: &[u8]) -> Result<Self, SealError> {
        if seal.len() != SEAL_LEN || &seal[..8] != b"BHBKSL01" || seal[8..10] != 1u16.to_be_bytes()
        {
            return Err(SealError::Encoding);
        }
        let purpose = match seal[10] {
            1 => BaseKeyPurpose::Metadata,
            2 => BaseKeyPurpose::Content,
            _ => return Err(SealError::Encoding),
        };
        // Exact frame size was checked before any offset/slice.
        Ok(Self {
            purpose,
            base: BaseId(array(&seal[11..43])?),
            audience: array(&seal[43..75])?,
            key_id: array(&seal[75..107])?,
            recipient: array(&seal[107..139])?,
            sender: AccountId(array(&seal[139..171])?),
            device: DeviceId(array(&seal[171..203])?),
            head: Head {
                position: u64::from_be_bytes(array(&seal[203..211])?),
                hash: array(&seal[211..243])?,
            },
        })
    }
    fn signer(
        &self,
        history: &VerifiedAccount,
        recipient: &[u8; 1216],
    ) -> Result<[u8; 32], SealError> {
        if self.sender != history.id()
            || self.head != history.head()
            || self.recipient != hash(recipient)
            || history.personal_public().map_err(|_| SealError::Context)? != recipient
        {
            return Err(SealError::Context);
        }
        Ok(*history
            .active_device(self.device)
            .map_err(|_| SealError::Context)?
            .signing())
    }
}
fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], SealError> {
    bytes.try_into().map_err(|_| SealError::Encoding)
}
fn signing_bytes(frame: &[u8]) -> Vec<u8> {
    [SIGNATURE_DOMAIN, frame].concat()
}

pub struct PreparedBaseKeySeal {
    unsigned: Vec<u8>,
    signing: Vec<u8>,
    expected_key: [u8; 32],
}
impl PreparedBaseKeySeal {
    pub fn signing_bytes(&self) -> &[u8] {
        &self.signing
    }
    pub fn expected_key(&self) -> &[u8; 32] {
        &self.expected_key
    }
    pub fn finish(mut self, signature: [u8; 64]) -> Result<Vec<u8>, SealError> {
        verify(&self.expected_key, &self.signing, &signature).map_err(|_| SealError::Signature)?;
        self.unsigned.extend(signature);
        Ok(self.unsigned)
    }
}

pub fn prepare_seal(
    history: &VerifiedAccount,
    header: SealHeader,
    recipient: &[u8; 1216],
    root: &Secret<32>,
) -> Result<PreparedBaseKeySeal, SealError> {
    let expected_key = header.signer(history, recipient)?;
    if header.key_id != key_id(root) {
        return Err(SealError::Context);
    }
    let (kem, shared) = encapsulate(recipient).map_err(|_| SealError::Crypto)?;
    let encryption = derive_key(&shared, b"BHBKEY01", header.purpose as u64);
    let mut unsigned = header.encode();
    let (nonce, ciphertext) =
        aead_seal(&encryption, &unsigned, root.expose()).map_err(|_| SealError::Crypto)?;
    unsigned.extend(kem);
    unsigned.extend(nonce);
    unsigned.extend(ciphertext);
    Ok(PreparedBaseKeySeal {
        signing: signing_bytes(&unsigned),
        unsigned,
        expected_key,
    })
}

/// Authenticate a seal without any private key: every expected context field,
/// then the historical account/head, the personal key that history published
/// as recipient, and the signature of a device active there. A key already
/// rotated away can still be checked this way; nothing is opened.
pub fn verify_seal(
    history: &VerifiedAccount,
    expected: &SealHeader,
    seal: &[u8],
) -> Result<(), SealError> {
    let header = SealHeader::decode(seal)?;
    if header != *expected {
        return Err(SealError::Context);
    }
    let recipient = history.personal_public().map_err(|_| SealError::Context)?;
    let signer = header.signer(history, recipient)?;
    verify(
        &signer,
        &signing_bytes(&seal[..SEAL_LEN - 64]),
        &array(&seal[SEAL_LEN - 64..])?,
    )
    .map_err(|_| SealError::Signature)
}

/// Check historical account/head/signer and every expected context field before
/// touching the receiver. A matching seal key id is still provisional until the
/// caller verifies the exact genesis that commits that id.
pub fn open_seal(
    history: &VerifiedAccount,
    expected: &SealHeader,
    seal: &[u8],
    personal: &PersonalKey,
) -> Result<Secret<32>, SealError> {
    verify_seal(history, expected, seal)?;
    if history.personal_public().map_err(|_| SealError::Context)? != &personal.public() {
        return Err(SealError::Context);
    }
    let header = *expected;
    let shared = personal
        .decapsulate(&array(&seal[243..1363])?)
        .map_err(|_| SealError::Crypto)?;
    decrypt_root(&header, seal, &shared)
}

fn decrypt_root(
    header: &SealHeader,
    seal: &[u8],
    shared: &Secret<32>,
) -> Result<Secret<32>, SealError> {
    let encryption = derive_key(shared, b"BHBKEY01", header.purpose as u64);
    let plaintext = aead_open(
        &encryption,
        &array(&seal[1363..1387])?,
        &seal[..HEADER_LEN],
        &seal[1387..1435],
    )
    .map_err(|_| SealError::Crypto)?;
    let root = Secret::from_slice(plaintext.expose()).map_err(|_| SealError::Crypto)?;
    if key_id(&root) != header.key_id {
        return Err(SealError::Context);
    }
    Ok(root)
}

/// Exact immutable M/K frames in canonical order. This container verifies shape
/// and shared context, not historical signatures or authority.
pub struct InitialBaseKeyPackage {
    bytes: Vec<u8>,
}
impl InitialBaseKeyPackage {
    pub fn new(metadata: &[u8], content: &[u8]) -> Result<Self, SealError> {
        check_pair(metadata, content)?;
        let mut bytes = Vec::with_capacity(PACKAGE_LEN);
        bytes.extend(b"BHBKPK01");
        bytes.extend(1u16.to_be_bytes());
        bytes.extend((SEAL_LEN as u32).to_be_bytes());
        bytes.extend(metadata);
        bytes.extend((SEAL_LEN as u32).to_be_bytes());
        bytes.extend(content);
        Ok(Self { bytes })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, SealError> {
        if bytes.len() != PACKAGE_LEN
            || &bytes[..8] != b"BHBKPK01"
            || bytes[8..10] != 1u16.to_be_bytes()
            || bytes[10..14] != (SEAL_LEN as u32).to_be_bytes()
            || bytes[14 + SEAL_LEN..18 + SEAL_LEN] != (SEAL_LEN as u32).to_be_bytes()
        {
            return Err(SealError::Encoding);
        }
        check_pair(&bytes[14..14 + SEAL_LEN], &bytes[18 + SEAL_LEN..])?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn metadata_seal(&self) -> &[u8] {
        &self.bytes[14..14 + SEAL_LEN]
    }
    pub fn content_seal(&self) -> &[u8] {
        &self.bytes[18 + SEAL_LEN..]
    }
    pub fn digest(&self) -> [u8; 32] {
        hash(&[PACKAGE_DOMAIN, self.as_bytes()].concat())
    }
}
fn check_pair(metadata: &[u8], content: &[u8]) -> Result<(), SealError> {
    let m = SealHeader::decode(metadata)?;
    let k = SealHeader::decode(content)?;
    if m.purpose != BaseKeyPurpose::Metadata
        || k.purpose != BaseKeyPurpose::Content
        || m != (SealHeader {
            purpose: m.purpose,
            key_id: m.key_id,
            ..k
        })
    {
        return Err(SealError::Context);
    }
    Ok(())
}

#[cfg(test)]
mod vectors {
    use super::*;
    use bh_crypto::{KemKey, SigningKey, decapsulate};
    fn unhex(text: &str) -> Vec<u8> {
        text.trim()
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn independent_complete_package_vector_pins_header_domains_and_root_derivation() {
        let bytes = unhex(include_str!("../tests/fixtures/base-key-package-v1.hex"));
        let package = InitialBaseKeyPackage::decode(&bytes).unwrap();
        assert_eq!(bytes.len(), 3016);
        assert_eq!(
            package.digest().as_slice(),
            unhex("173e71dd4c05db092c3cb666735393ded283e9020a621c9a3e5b62a355982bcf")
        );
        let recipient = KemKey::from_seed(&Secret::from_slice(&[0x22; 32]).unwrap());
        let signer = SigningKey::from_seed(&Secret::from_slice(&[0x11; 32]).unwrap());
        for (purpose, root, seal) in [
            (
                BaseKeyPurpose::Metadata,
                [0x33; 32],
                package.metadata_seal(),
            ),
            (BaseKeyPurpose::Content, [0x44; 32], package.content_seal()),
        ] {
            let expected = SealHeader {
                purpose,
                base: BaseId([0xa1; 32]),
                audience: [0; 32],
                key_id: key_id(&Secret::from_slice(&root).unwrap()),
                recipient: hash(&recipient.public()),
                sender: AccountId([0xa2; 32]),
                device: DeviceId([0xa3; 32]),
                head: Head {
                    position: 3,
                    hash: [0xa4; 32],
                },
            };
            assert_eq!(seal.len(), 1499);
            assert_eq!(expected.encode(), seal[..243]);
            assert!(SealHeader::decode(seal).unwrap() == expected);
            verify(
                &signer.public(),
                &signing_bytes(&seal[..1435]),
                &array(&seal[1435..]).unwrap(),
            )
            .unwrap();
            let shared = decapsulate(&recipient, &array(&seal[243..1363]).unwrap()).unwrap();
            assert_eq!(
                decrypt_root(&expected, seal, &shared).unwrap().expose(),
                &root
            );
            let mut altered = seal.to_vec();
            altered[1387] ^= 1;
            assert!(decrypt_root(&expected, &altered, &shared).is_err());
        }
        assert_eq!(
            InitialBaseKeyPackage::new(package.metadata_seal(), package.content_seal())
                .unwrap()
                .as_bytes(),
            bytes
        );
    }
}
