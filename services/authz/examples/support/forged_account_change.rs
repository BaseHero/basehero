//! Synthetic-only canonical account entries with invalid author signatures.
use bh_account::{DeviceId, VerifiedAccount};
use bh_crypto::SigningKey;

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    BadSignature,
    WrongSigner,
}
impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "bad-signature" => Some(Self::BadSignature),
            "wrong-signer" => Some(Self::WrongSigner),
            _ => None,
        }
    }
}

/// The production encoder fixes the account, author and predecessor. No
/// device private key is needed: the first forgery is an invalid signature,
/// the second is a *valid* signature from an unrelated generated key.
pub fn forge(kind: Kind, view: &VerifiedAccount, author: DeviceId) -> Result<Vec<u8>, String> {
    let request = view
        .remove_self(author)
        .map_err(|e| format!("cannot draft removal: {e:?}"))?;
    let mut original = request.signing_bytes().to_vec();
    let mut signature = match kind {
        Kind::BadSignature => [0; 64],
        Kind::WrongSigner => {
            let outsider = SigningKey::generate();
            if outsider.public() == *request.expected_key() {
                return Err("unexpected matching signer".into());
            }
            outsider.sign(request.signing_bytes())
        }
    };
    // An all-zero signature does not authenticate under any ordinary key.
    original.extend_from_slice(&signature);
    signature.fill(0);
    Ok(original)
}
