use bh_core::hero::HeroEvent;
use bh_core::{AccountEvent, AccountId, AccountSummary, BaseEvent, BaseId, SearchHit};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ts_rs::TS;
use zeroize::Zeroizing;

/// A secret at the native command boundary, wiped on every return path.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn into_inner(self) -> Zeroizing<String> {
        self.0
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::from(value.to_owned())
    }
}

impl std::ops::Deref for SecretString {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum Platform {
    Macos,
    Android,
    Linux,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct AppInfo {
    pub version: String,
    pub server: String,
    pub platform: Platform,
}

#[derive(Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct SignUpForm {
    pub invite: String,
    pub email: String,
    #[ts(type = "string")]
    pub password: SecretString,
    pub device_name: String,
}

#[derive(Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct SignInForm {
    pub email: String,
    #[ts(type = "string")]
    pub password: SecretString,
    pub device_name: String,
}

#[derive(Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct SignedUp {
    pub account: AccountSummary,
    #[ts(type = "string")]
    pub kit: SecretString,
}

#[cfg(test)]
mod secret_tests {
    use super::{SecretString, SignInForm};

    #[test]
    fn secret_form_stays_wire_compatible_and_is_owned_by_zeroizing_boundary() {
        let form: SignInForm = serde_json::from_str(
            r#"{"email":"user@example.test","password":"sensitive","deviceName":"Mac"}"#,
        )
        .unwrap();
        assert_eq!(&*form.password, "sensitive");
        assert_eq!(
            serde_json::to_value(&form).unwrap()["password"],
            "sensitive"
        );
        let secret: SecretString = "kit".into();
        assert_eq!(serde_json::to_string(&secret).unwrap(), "\"kit\"");
    }
}

/// Sent to every window as `bh:event`. Bases and Hero add their variants.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum AppEvent {
    Account {
        #[ts(type = "string")]
        account: AccountId,
        event: AccountEvent,
    },
    Base {
        #[ts(type = "string")]
        account: AccountId,
        #[ts(type = "string")]
        base: BaseId,
        event: BaseEvent,
    },
    Hero {
        #[ts(type = "string")]
        account: AccountId,
        #[ts(type = "string")]
        base: BaseId,
        #[ts(type = "string")]
        chat: bh_core::ObjectId,
        event: HeroEvent,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct BaseRef {
    #[ts(type = "string")]
    pub account: AccountId,
    #[ts(type = "string")]
    pub base: BaseId,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct SearchResult {
    #[ts(type = "string")]
    pub base: BaseId,
    pub base_name: String,
    pub hit: SearchHit,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct UpdateInfo {
    pub version: String,
    pub notes: String,
}
