use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Scope {
    pub base: [u8; 32],
    pub audience: [u8; 32],
}

impl Scope {
    /// Whether `audience` is the one every member of a base reads; any other
    /// audience is a smaller group of the base's members. This is the only
    /// place that is decided, from bh-device's all-zero ordinary audience; if
    /// audiences gain a richer readership model, the host should supply it.
    pub fn is_base_wide(audience: &[u8; 32]) -> bool {
        *audience == [0; 32]
    }
}

pub(crate) fn serialize_hex<const N: usize, S: Serializer>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use std::fmt::Write;
    let mut hex = String::with_capacity(N * 2);
    for byte in bytes {
        write!(hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    serializer.serialize_str(&hex)
}

pub(crate) fn deserialize_hex<'de, const N: usize, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let text = String::deserialize(deserializer)?;
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(D::Error::custom("expected fixed-length lowercase hex"));
    }
    let mut bytes = [0; N];
    for (i, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        bytes[i] = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(bytes)
}

macro_rules! hex_id {
    ($name:ident, $len:expr) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; $len]);

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serialize_hex(&self.0, serializer)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserialize_hex(deserializer).map(Self)
            }
        }
    };
}

hex_id!(RecordId, 32);
hex_id!(TypeId, 32);
hex_id!(AppId, 32);
hex_id!(RevisionId, 32);
hex_id!(MutationId, 16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RecordRef {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_hex_32",
        deserialize_with = "deserialize_optional_hex_32"
    )]
    pub audience: Option<[u8; 32]>,
    pub record: RecordId,
}

fn serialize_optional_hex_32<S: Serializer>(
    audience: &Option<[u8; 32]>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match audience {
        Some(bytes) => serialize_hex(bytes, serializer),
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_hex_32<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<[u8; 32]>, D::Error> {
    deserialize_hex(deserializer).map(Some)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Position(pub u64);

impl RecordId {
    pub fn random() -> Self {
        Self(bh_crypto::random())
    }
}

impl TypeId {
    pub fn for_app(app: AppId, local: [u8; 16]) -> Self {
        let mut input = b"bh/app-type/v1\0".to_vec();
        input.extend_from_slice(&app.0);
        input.extend_from_slice(&local);
        Self(bh_crypto::hash(&input))
    }

    pub fn core(name: &str) -> Self {
        let mut input = b"bh/core-type/v1\0".to_vec();
        input.extend_from_slice(name.as_bytes());
        Self(bh_crypto::hash(&input))
    }

    pub fn is_reserved_core(&self) -> bool {
        crate::catalogue::core_types()
            .iter()
            .any(|contract| contract.type_id == *self)
    }
}

impl AppId {
    pub fn random() -> Self {
        Self(bh_crypto::random())
    }
}

impl MutationId {
    pub fn random() -> Self {
        Self(bh_crypto::random())
    }
}

impl RevisionId {
    pub fn of(bytes: &[u8]) -> Self {
        let mut input = b"bh/type-revision/v1\0".to_vec();
        input.extend_from_slice(bytes);
        Self(bh_crypto::hash(&input))
    }
}
