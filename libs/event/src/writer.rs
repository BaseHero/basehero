//! Compact device-writer declarations. Decoding and derivation are not author
//! authentication: compare the principal with the authenticated original.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WriterScope {
    pub base: [u8; 32],
    pub audience: [u8; 32],
    pub note: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceWriterDeclaration {
    pub account: [u8; 32],
    pub device: [u8; 32],
    pub nonce: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterDecodeError {
    Malformed,
    TrailingData,
    UnsupportedVersion(u16),
    UnsupportedAuthor(u8),
}

impl DeviceWriterDeclaration {
    pub fn encode(self) -> [u8; 99] {
        let mut bytes = [0; 99];
        bytes[..3].copy_from_slice(&[0, 1, 1]);
        bytes[3..35].copy_from_slice(&self.account);
        bytes[35..67].copy_from_slice(&self.device);
        bytes[67..].copy_from_slice(&self.nonce);
        bytes
    }

    /// Decoding must stay canonical: a reader that keeps this build's exact
    /// payload recomposes it with [`Self::encode`], so an accepted declaration
    /// must re-encode to exactly the bytes it was decoded from.
    pub fn decode(bytes: &[u8]) -> Result<Self, WriterDecodeError> {
        match bytes.len().cmp(&99) {
            std::cmp::Ordering::Less => return Err(WriterDecodeError::Malformed),
            std::cmp::Ordering::Greater => return Err(WriterDecodeError::TrailingData),
            std::cmp::Ordering::Equal => {}
        }
        let version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if version != 1 {
            return Err(WriterDecodeError::UnsupportedVersion(version));
        }
        if bytes[2] != 1 {
            return Err(WriterDecodeError::UnsupportedAuthor(bytes[2]));
        }
        Ok(Self {
            account: bytes[3..35].try_into().unwrap(),
            device: bytes[35..67].try_into().unwrap(),
            nonce: bytes[67..].try_into().unwrap(),
        })
    }

    pub fn digest(self, scope: WriterScope) -> [u8; 32] {
        let mut input = [0; 213];
        input[..18].copy_from_slice(b"BH note writer v1\0");
        input[18..20].copy_from_slice(&1u16.to_be_bytes());
        input[20..52].copy_from_slice(&scope.base);
        input[52..84].copy_from_slice(&scope.audience);
        input[84..116].copy_from_slice(&scope.note);
        input[116..].copy_from_slice(&self.encode()[2..]);
        bh_crypto::hash(&input)
    }

    pub fn client_id(self, scope: WriterScope) -> u64 {
        u64::from_be_bytes(self.digest(scope)[..8].try_into().unwrap()) & ((1u64 << 53) - 1)
    }
}
