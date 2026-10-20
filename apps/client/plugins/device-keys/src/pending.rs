//! Framing for pending first-device setup blobs, shared by JNI and host tests.
//!
//! Each blob names its own Keystore wrapping key, so a code-bearing blob and
//! its no-code replacement never share a key, and retiring the code-bearing key
//! leaves an old WAL or copied database ciphertext unopenable:
//! `kind || key handle || [retired kit key handle] || Keystore GCM blob`.
use bh_account::journal::ProtectorError;

pub(crate) const KIT: u8 = 1;
pub(crate) const HOME: u8 = 2;
// The Kotlin store's own framing: version byte, 12-byte IV, 16-byte GCM tag.
const SEALED_MIN: usize = 1 + 12 + 16;

pub(crate) struct Pending<'a> {
    pub kind: u8,
    pub key: [u8; 32],
    pub retired: Option<[u8; 32]>,
    pub sealed: &'a [u8],
}

pub(crate) fn frame(
    kind: u8,
    key: &[u8; 32],
    retired: Option<&[u8; 32]>,
    sealed: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + retired.map_or(0, |_| 32) + sealed.len());
    out.push(kind);
    out.extend_from_slice(key);
    if let Some(retired) = retired {
        out.extend_from_slice(retired);
    }
    out.extend_from_slice(sealed);
    out
}

pub(crate) fn parse(blob: &[u8]) -> Result<Pending<'_>, ProtectorError> {
    let kind = *blob.first().ok_or(ProtectorError::Failed)?;
    let start = match kind {
        KIT => 33,
        HOME => 65,
        _ => return Err(ProtectorError::Failed),
    };
    let sealed = blob
        .get(start..)
        .filter(|sealed| sealed.len() >= SEALED_MIN)
        .ok_or(ProtectorError::Failed)?;
    let handle = |range: std::ops::Range<usize>| -> Result<[u8; 32], ProtectorError> {
        blob[range].try_into().map_err(|_| ProtectorError::Failed)
    };
    Ok(Pending {
        kind,
        key: handle(1..33)?,
        retired: (kind == HOME).then(|| handle(33..65)).transpose()?,
        sealed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kit_and_home_blobs_name_distinct_keys_and_the_retired_kit_key() {
        let sealed = [9; SEALED_MIN];
        let kit = frame(KIT, &[1; 32], None, &sealed);
        let parsed = parse(&kit).unwrap();
        assert_eq!(
            (parsed.kind, parsed.key, parsed.retired),
            (KIT, [1; 32], None)
        );
        assert_eq!(parsed.sealed, sealed);
        let home = frame(HOME, &[2; 32], Some(&[1; 32]), &sealed);
        let parsed = parse(&home).unwrap();
        assert_eq!(
            (parsed.kind, parsed.key, parsed.retired),
            (HOME, [2; 32], Some([1; 32]))
        );
        assert_eq!(parsed.sealed, sealed);
    }

    #[test]
    fn malformed_blobs_fail_before_any_keystore_call() {
        let sealed = [9; SEALED_MIN];
        let kit = frame(KIT, &[1; 32], None, &sealed);
        let home = frame(HOME, &[2; 32], Some(&[1; 32]), &sealed);
        for malformed in [
            Vec::new(),
            kit[..kit.len() - 1].to_vec(),
            home[..home.len() - 1].to_vec(),
            [&[3][..], &kit[1..]].concat(),
            [&[0][..], &kit[1..]].concat(),
        ] {
            assert!(matches!(parse(&malformed), Err(ProtectorError::Failed)));
        }
    }
}
