//! The build's fixed sync endpoint: one compact JSON file named at build time
//! by `BH_SYNC_ENDPOINT`. Shared by `build.rs`, which refuses to build with a
//! file that does not parse, and by the app, which reads the copy built in.
//! No page, setting or runtime input supplies any of it.
//!
//! Every field is required and none has a default: an absent file means a
//! local-only build, and anything partial or malformed is refused rather than
//! completed. Synthetic appraisal (and plain `http://`) is accepted only by a
//! build with the local `synthetic-attestation` feature.

/// The parsed endpoint, independent of the client crate's types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fields {
    pub edge_url: String,
    pub hosting_root: [u8; 32],
    pub app_root: [u8; 32],
    pub policy: Vec<u8>,
    pub policy_signature: Vec<u8>,
    pub max_lifetime_secs: u64,
    pub max_uncertainty_secs: u64,
    pub build_floor: u64,
    pub synthetic: bool,
    /// The home's recovery-key certificate, exactly, naming `hosting_root`.
    /// The host verifies its signature before using it.
    pub recovery_key: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    Invalid,
}

const KEYS: [&str; 10] = [
    "edge_url",
    "hosting_root",
    "app_root",
    "policy",
    "policy_signature",
    "max_lifetime_secs",
    "max_uncertainty_secs",
    "build_floor",
    "appraisal",
    "recovery_key",
];

/// A recovery-key certificate: version 1, the root that signed it, the
/// X-Wing public key and the signature.
const RECOVERY_KEY_LEN: usize = 2 + 32 + 1216 + 64;

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

fn root(value: &serde_json::Value) -> Option<[u8; 32]> {
    let root: [u8; 32] = hex(value.as_str()?)?.try_into().ok()?;
    (root != [0; 32]).then_some(root)
}

fn edge(url: &str, synthetic: bool) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://").filter(|_| synthetic))?;
    let host = rest.split('/').next()?;
    let printable = url.bytes().all(|b| b.is_ascii_graphic());
    (!host.is_empty() && printable).then(|| url.to_owned())
}

/// `Ok(None)` for no file (a local-only build); `Invalid` for anything that is
/// not one complete, well-formed endpoint this build may use.
pub fn parse(text: &str, synthetic_allowed: bool) -> Result<Option<Fields>, ConfigError> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    let invalid = ConfigError::Invalid;
    let value: serde_json::Value = serde_json::from_str(text).map_err(|_| invalid)?;
    let object = value.as_object().ok_or(invalid)?;
    if object.len() != KEYS.len() || KEYS.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid);
    }
    let synthetic = match object["appraisal"].as_str() {
        Some("hardware") => false,
        Some("synthetic") if synthetic_allowed => true,
        _ => return Err(invalid),
    };
    let number = |key: &str| object[key].as_u64().ok_or(invalid);
    let bytes = |key: &str| object[key].as_str().and_then(hex).ok_or(invalid);
    let fields = Fields {
        edge_url: object["edge_url"]
            .as_str()
            .and_then(|url| edge(url, synthetic))
            .ok_or(invalid)?,
        hosting_root: root(&object["hosting_root"]).ok_or(invalid)?,
        app_root: root(&object["app_root"]).ok_or(invalid)?,
        policy: bytes("policy")?,
        policy_signature: bytes("policy_signature")?,
        max_lifetime_secs: number("max_lifetime_secs")?,
        max_uncertainty_secs: number("max_uncertainty_secs")?,
        build_floor: number("build_floor")?,
        synthetic,
        recovery_key: bytes("recovery_key")?,
    };
    if fields.max_lifetime_secs == 0
        || fields.build_floor == 0
        || fields.policy.is_empty() != fields.policy_signature.is_empty()
        || fields.recovery_key.len() != RECOVERY_KEY_LEN
        || fields.recovery_key[..2] != 1u16.to_be_bytes()
        || fields.recovery_key[2..34] != fields.hosting_root
    {
        return Err(invalid);
    }
    Ok(Some(fields))
}

/// The endpoint a build carries: no file named is a local-only build; a file
/// that is named must hold one complete endpoint, so an empty one is refused.
pub fn built(named: Option<&str>, synthetic_allowed: bool) -> Result<Option<Fields>, ConfigError> {
    match named {
        None => Ok(None),
        Some(text) => parse(text, synthetic_allowed)?
            .map(Some)
            .ok_or(ConfigError::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_A: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const ROOT_B: &str = "0202020202020202020202020202020202020202020202020202020202020202";

    /// A recovery-key certificate's shape under `root`: version, root, the
    /// X-Wing public key and the root's signature. Only its shape is checked
    /// here; the host checks the signature.
    fn recovery_key(root: &str) -> String {
        format!("0001{root}{}{}", "a7".repeat(1216), "5c".repeat(64))
    }

    fn complete() -> serde_json::Value {
        serde_json::json!({
            "edge_url": "https://edge.example",
            "hosting_root": ROOT_A,
            "app_root": ROOT_B,
            "policy": "a1b2",
            "policy_signature": "c3d4",
            "max_lifetime_secs": 86400,
            "max_uncertainty_secs": 30,
            "build_floor": 1760000000,
            "appraisal": "hardware",
            "recovery_key": recovery_key(ROOT_A)
        })
    }

    #[test]
    fn no_file_means_no_endpoint() {
        assert_eq!(parse("", false), Ok(None));
        assert_eq!(parse("  \n", false), Ok(None));
    }

    #[test]
    fn a_named_file_must_hold_an_endpoint_and_only_no_file_is_local_only() {
        assert_eq!(built(None, false), Ok(None));
        // A named file left empty is a release that would never sync.
        for empty in ["", " ", "\n\t "] {
            assert_eq!(
                built(Some(empty), false),
                Err(ConfigError::Invalid),
                "{empty:?}"
            );
        }
        assert_eq!(built(Some("{"), false), Err(ConfigError::Invalid));
        let text = complete().to_string();
        assert_eq!(built(Some(&text), false), parse(&text, false));
        assert!(built(Some(&text), false).unwrap().is_some());
    }

    #[test]
    fn a_complete_file_gives_every_field_exactly() {
        let fields = parse(&complete().to_string(), false).unwrap().unwrap();
        assert_eq!(fields.edge_url, "https://edge.example");
        assert_eq!(fields.hosting_root, [1; 32]);
        assert_eq!(fields.app_root, [2; 32]);
        assert_eq!(fields.policy, vec![0xa1, 0xb2]);
        assert_eq!(fields.policy_signature, vec![0xc3, 0xd4]);
        assert_eq!(fields.max_lifetime_secs, 86400);
        assert_eq!(fields.max_uncertainty_secs, 30);
        assert_eq!(fields.build_floor, 1_760_000_000);
        assert!(!fields.synthetic);
        assert_eq!(fields.recovery_key.len(), 1314);
        assert_eq!(fields.recovery_key[2..34], [1; 32]);
        // No delivered policy at all is allowed: both empty.
        let mut none = complete();
        none["policy"] = "".into();
        none["policy_signature"] = "".into();
        let fields = parse(&none.to_string(), false).unwrap().unwrap();
        assert!(fields.policy.is_empty() && fields.policy_signature.is_empty());
    }

    #[test]
    fn partial_or_invented_values_never_enable_sync() {
        // Every field is required: none has a default.
        for key in complete().as_object().unwrap().keys() {
            let mut partial = complete();
            partial.as_object_mut().unwrap().remove(key);
            assert_eq!(
                parse(&partial.to_string(), false),
                Err(ConfigError::Invalid),
                "{key}"
            );
        }
        let bad: &[(&str, serde_json::Value)] = &[
            ("edge_url", "edge.example".into()),
            ("edge_url", "ftp://edge.example".into()),
            ("edge_url", "https://".into()),
            ("edge_url", "https://edge.example/path with space".into()),
            ("hosting_root", "00".repeat(32).into()),
            ("hosting_root", "01".repeat(31).into()),
            ("hosting_root", "zz".repeat(32).into()),
            ("app_root", "00".repeat(32).into()),
            ("policy", "abc".into()),
            ("policy_signature", "".into()),
            ("max_lifetime_secs", 0.into()),
            ("max_lifetime_secs", (-1).into()),
            ("max_lifetime_secs", "86400".into()),
            ("build_floor", 0.into()),
            ("recovery_key", "".into()),
            ("recovery_key", recovery_key(ROOT_A)[..2626].into()),
            ("recovery_key", format!("{}00", recovery_key(ROOT_A)).into()),
            ("recovery_key", recovery_key(ROOT_B).into()),
            (
                "recovery_key",
                format!("0002{}", &recovery_key(ROOT_A)[4..]).into(),
            ),
            ("appraisal", "".into()),
            ("appraisal", "any".into()),
            ("unknown", true.into()),
        ];
        for (key, value) in bad {
            let mut invalid = complete();
            invalid[*key] = value.clone();
            assert_eq!(
                parse(&invalid.to_string(), false),
                Err(ConfigError::Invalid),
                "{key} = {value}"
            );
        }
        assert_eq!(parse("{", false), Err(ConfigError::Invalid));
        assert_eq!(parse("[]", false), Err(ConfigError::Invalid));
    }

    #[test]
    fn synthetic_appraisal_needs_the_local_build() {
        let mut local = complete();
        local["appraisal"] = "synthetic".into();
        local["edge_url"] = "http://127.0.0.1:8787".into();
        assert_eq!(
            parse(&local.to_string(), false),
            Err(ConfigError::Invalid),
            "a release build never accepts synthetic appraisal"
        );
        let fields = parse(&local.to_string(), true).unwrap().unwrap();
        assert!(fields.synthetic);
        // Plain HTTP is only for a local synthetic stack.
        let mut plain = complete();
        plain["edge_url"] = "http://edge.example".into();
        assert_eq!(parse(&plain.to_string(), true), Err(ConfigError::Invalid));
    }
}
