use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};
use ts_rs::TS;

/// The v1 protocol's client-generated, 16-byte IDs. Their JSON and TypeScript
/// representations are hex strings, not arrays of numbers.
macro_rules! id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, TS)]
        #[ts(export, export_to = "server/src/proto/gen/", type = "string")]
        /// A 16-byte client-generated protocol identifier. JSON serializes it
        /// as exactly 32 lowercase hexadecimal characters; parsing text also
        /// accepts uppercase hex.
        pub struct $name(
            /// The raw 16-byte identifier.
            pub [u8; 16],
        );

        impl $name {
            /// Creates a new identifier using the operating system's random source.
            pub fn random() -> Self {
                let mut bytes = [0; 16];
                getrandom::fill(&mut bytes).expect("operating system random source unavailable");
                Self(bytes)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl FromStr for $name {
            type Err = ParseIdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                if s.len() != 32 || !s.is_ascii() {
                    return Err(ParseIdError);
                }
                let mut bytes = [0u8; 16];
                for (index, pair) in s.as_bytes().chunks_exact(2).enumerate() {
                    let digit = |c: u8| (c as char).to_digit(16).ok_or(ParseIdError);
                    bytes[index] = ((digit(pair[0])? << 4) | digit(pair[1])?) as u8;
                }
                Ok(Self(bytes))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                // The wire format is exactly 32 lowercase hex characters. `FromStr`
                // stays case-insensitive for CLI input, so validate separately here.
                let value = String::deserialize(deserializer)?;
                if value.len() != 32
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(serde::de::Error::custom(
                        "expected a 32-character lowercase hexadecimal ID",
                    ));
                }
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

/// An identifier was not exactly 32 hexadecimal characters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseIdError;

impl fmt::Display for ParseIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a 32-character hexadecimal ID")
    }
}

impl std::error::Error for ParseIdError {}

id!(AccountId);
id!(DeviceId);
id!(BaseId);
id!(ObjectId);
id!(ChangeId);
id!(ApprovalId);
