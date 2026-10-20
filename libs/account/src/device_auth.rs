//! Native ordinary-device-key possession at one supplied verified account head.
//!
//! The caller supplies a binding to an established protected session and a fresh
//! server challenge. Neither preparing nor verifying a proof establishes that
//! this head is current, that the challenge has not been consumed, or that the
//! device has hosted access. Those checks belong to the protected protocol.

use crate::{AccountId, DeviceId, DevicePublicKeys, Error, Head, VerifiedAccount, crypto::verify};

const DOMAIN: &[u8] = b"bh/sync-device-possession/v1\0";
const UNSIGNED_LEN: usize = 170;
pub const PROOF_LEN: usize = UNSIGNED_LEN + 64;

/// Session-local input from the protected protocol, not a WebView credential.
#[derive(Clone, Copy)]
pub struct Context {
    pub channel_binding: [u8; 32],
    pub challenge: [u8; 32],
}

/// Exact domain-prefixed message for the active device's ordinary signing key.
pub struct SigningRequest {
    message: [u8; DOMAIN.len() + UNSIGNED_LEN],
    key: [u8; 32],
}

impl std::fmt::Debug for SigningRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningRequest(..)")
    }
}

/// Fixed-width signed proof. Not an authorization or a reusable credential.
pub struct Proof([u8; PROOF_LEN]);

impl std::fmt::Debug for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Proof(..)")
    }
}

/// Ordinary-key possession relative only to the supplied account projection.
pub struct PossessionAtHead {
    account: AccountId,
    device: DeviceId,
    head: Head,
}

impl std::fmt::Debug for PossessionAtHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PossessionAtHead(..)")
    }
}

impl PossessionAtHead {
    pub fn account(&self) -> AccountId {
        self.account
    }
    pub fn device(&self) -> DeviceId {
        self.device
    }
    pub fn head(&self) -> Head {
        self.head
    }
}

/// Choose identity, head and public key from the verified projection, not the caller.
pub fn prepare(
    account: &VerifiedAccount,
    device: DeviceId,
    context: Context,
) -> Result<SigningRequest, Error> {
    let key = *account.active_device(device)?.signing();
    Ok(request(account.id(), device, key, account.head(), context))
}

/// A device joining by QR has no verified history yet: it names its own
/// journaled keys and the head the showing device reported. The verifier
/// checks that head against its own history; this proves nothing locally.
pub(crate) fn prepare_joining(
    account: AccountId,
    keys: &DevicePublicKeys,
    head: Head,
    context: Context,
) -> SigningRequest {
    request(account, keys.id(), *keys.signing(), head, context)
}

fn request(
    account: AccountId,
    device: DeviceId,
    key: [u8; 32],
    head: Head,
    context: Context,
) -> SigningRequest {
    let mut message = [0; DOMAIN.len() + UNSIGNED_LEN];
    message[..DOMAIN.len()].copy_from_slice(DOMAIN);
    let unsigned = &mut message[DOMAIN.len()..];
    unsigned[..2].copy_from_slice(&1u16.to_be_bytes());
    unsigned[2..34].copy_from_slice(&account.0);
    unsigned[34..66].copy_from_slice(&device.0);
    unsigned[66..74].copy_from_slice(&head.position.to_be_bytes());
    unsigned[74..106].copy_from_slice(&head.hash);
    unsigned[106..138].copy_from_slice(&context.channel_binding);
    unsigned[138..170].copy_from_slice(&context.challenge);
    SigningRequest { message, key }
}

impl SigningRequest {
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Reject a native result that was not made with the projected ordinary key.
    pub fn finish(self, signature: [u8; 64]) -> Result<Proof, Error> {
        verify(&self.key, &self.message, &signature).map_err(|_| Error::BadSignature)?;
        let mut bytes = [0; PROOF_LEN];
        bytes[..UNSIGNED_LEN].copy_from_slice(&self.message[DOMAIN.len()..]);
        bytes[UNSIGNED_LEN..].copy_from_slice(&signature);
        Ok(Proof(bytes))
    }
}

impl Proof {
    pub fn as_bytes(&self) -> &[u8; PROOF_LEN] {
        &self.0
    }
}

/// Check exact context and ordinary-key possession at this supplied head only.
/// No mutation, replay consumption, currentness or hosted authority is implied.
pub fn verify_at(
    account: &VerifiedAccount,
    expected: Context,
    encoded: &[u8],
) -> Result<PossessionAtHead, Error> {
    if encoded.len() != PROOF_LEN {
        return Err(Error::Malformed);
    }
    if encoded[..2] != 1u16.to_be_bytes() {
        return Err(Error::UnsupportedVersion);
    }
    if encoded[2..34] != account.id().0 {
        return Err(Error::WrongAccount);
    }
    let head = account.head();
    if encoded[66..74] != head.position.to_be_bytes()
        || encoded[74..106] != head.hash
        || encoded[106..138] != expected.channel_binding
        || encoded[138..170] != expected.challenge
    {
        return Err(Error::InvalidCredentials);
    }
    let device = DeviceId(encoded[34..66].try_into().expect("checked fixed width"));
    let key = account.active_device(device)?.signing();
    let mut message = [0; DOMAIN.len() + UNSIGNED_LEN];
    message[..DOMAIN.len()].copy_from_slice(DOMAIN);
    message[DOMAIN.len()..].copy_from_slice(&encoded[..UNSIGNED_LEN]);
    let signature: &[u8; 64] = encoded[UNSIGNED_LEN..]
        .try_into()
        .expect("checked fixed width");
    verify(key, &message, signature).map_err(|_| Error::BadSignature)?;
    Ok(PossessionAtHead {
        account: account.id(),
        device,
        head,
    })
}
