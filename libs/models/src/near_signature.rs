//! Exact-byte NEAR completion signatures. Only the verified model key or
//! quote-bound gateway signer may authenticate a result; signature metadata is
//! never a trust root. Call only after the encrypted wire response is complete.

use crate::{
    near_model::{MODEL, VerifiedModelKey},
    near_route::GatewaySigner,
};
use bh_crypto::Sha256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Kind,
    Signer,
    Payload,
    Signature,
}

/// Untrusted response from the separate completion-signature endpoint. Fetching
/// it through the authenticated route belongs to the transport increment.
pub struct Signature<'a> {
    pub kind: &'a str,
    pub signing_algo: &'a str,
    pub signing_address: &'a str,
    pub signed_text: &'a str,
    pub signature: &'a str,
}

/// SHA-256 of the *encrypted* response wire bytes; update before parsing,
/// decrypting, changing SSE newlines or stripping any trailing data. A final
/// chunk alone never implies success: the caller must also validate EOF/[DONE].
pub struct WireHash(Sha256);
impl WireHash {
    pub fn new() -> Self {
        Self(Sha256::new())
    }
    pub fn update(&mut self, chunk: &[u8]) {
        self.0.update(chunk);
    }
    pub fn finalize(self) -> [u8; 32] {
        self.0.finalize()
    }
}
impl Default for WireHash {
    fn default() -> Self {
        Self::new()
    }
}

pub fn verify_model(
    key: &VerifiedModelKey,
    request: &[u8],
    response_hash: [u8; 32],
    signature: &Signature<'_>,
) -> Result<(), Error> {
    verify_model_key(key.public_key(), request, response_hash, signature)
}

fn verify_model_key(
    key: &[u8; 32],
    request: &[u8],
    response_hash: [u8; 32],
    signature: &Signature<'_>,
) -> Result<(), Error> {
    // Model is fixed by the prepared request builder, but check again at the
    // signature boundary to avoid accidentally verifying a different model.
    let body: serde_json::Value = serde_json::from_slice(request).map_err(|_| Error::Payload)?;
    if body.get("model").and_then(serde_json::Value::as_str) != Some(MODEL) {
        return Err(Error::Payload);
    }
    verify(
        "provider_tee",
        key,
        Some(MODEL),
        request,
        response_hash,
        signature,
    )
}

// Reserved for a session that explicitly selected the gateway signer; this
// fixed-model route must not accept a caller-chosen gateway kind instead.
#[allow(dead_code)]
pub(crate) fn verify_gateway(
    signer: &GatewaySigner,
    request: &[u8],
    response_hash: [u8; 32],
    signature: &Signature<'_>,
) -> Result<(), Error> {
    verify(
        "gateway",
        signer.public_key(),
        None,
        request,
        response_hash,
        signature,
    )
}

fn verify(
    kind: &str,
    trusted_key: &[u8; 32],
    model: Option<&str>,
    request: &[u8],
    response_hash: [u8; 32],
    signature: &Signature<'_>,
) -> Result<(), Error> {
    if signature.kind != kind {
        return Err(Error::Kind);
    }
    if signature.signing_address.len() != 64 {
        return Err(Error::Signer);
    }
    let signer = hex::decode(signature.signing_address).map_err(|_| Error::Signer)?;
    if signature.signing_algo != "ed25519" || signer.as_slice() != trusted_key {
        return Err(Error::Signer);
    }
    let mut text = String::new();
    if let Some(model) = model {
        text.push_str(model);
        text.push(':');
    }
    text.push_str(&hex::encode(bh_crypto::sha256(request)));
    text.push(':');
    text.push_str(&hex::encode(response_hash));
    if signature.signed_text != text {
        return Err(Error::Payload);
    }
    if signature.signature.len() != 128 {
        return Err(Error::Signature);
    }
    let bytes = hex::decode(signature.signature).map_err(|_| Error::Signature)?;
    let signature_bytes: [u8; 64] = bytes.try_into().map_err(|_| Error::Signature)?;
    bh_crypto::verify(trusted_key, text.as_bytes(), &signature_bytes).map_err(|_| Error::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_010_signed_exact_wire_fixture() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/near_sdk_v2.json")).unwrap();
        let request = hex::decode(fixture["request_wire_hex"].as_str().unwrap()).unwrap();
        let wire = hex::decode(fixture["response_wire_hex"].as_str().unwrap()).unwrap();
        let mut hash = WireHash::new();
        for byte in wire.chunks(7) {
            hash.update(byte);
        }
        let meta = &fixture["signature"];
        let signature = Signature {
            kind: meta["signature_kind"].as_str().unwrap(),
            signing_algo: meta["signing_algo"].as_str().unwrap(),
            signing_address: meta["signing_address"].as_str().unwrap(),
            signed_text: meta["text"].as_str().unwrap(),
            signature: meta["signature"].as_str().unwrap(),
        };
        let model_key: [u8; 32] = hex::decode(fixture["model_public_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            verify_model_key(&model_key, &request, hash.finalize(), &signature),
            Ok(())
        );
        let normalized = String::from_utf8(wire).unwrap().replace("\r\n", "\n");
        assert_eq!(
            verify_model_key(
                &model_key,
                &request,
                bh_crypto::sha256(normalized.as_bytes()),
                &signature
            ),
            Err(Error::Payload)
        );
        let mut changed = request;
        changed.push(b' ');
        assert_eq!(
            verify_model_key(
                &model_key,
                &changed,
                bh_crypto::sha256(normalized.as_bytes()),
                &signature
            ),
            Err(Error::Payload)
        );
    }

    #[test]
    fn rust_public_vector_exact_wire_signature_stays_replayable() {
        // This fixture is additionally replayed against the independent SDK
        // signature verifier by the offline interop check, not just this code.
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/near_rust_v2.json")).unwrap();
        let request = hex::decode(f["request_wire_hex"].as_str().unwrap()).unwrap();
        let response = hex::decode(f["response_wire_hex"].as_str().unwrap()).unwrap();
        let key: [u8; 32] = hex::decode(f["rust_signature"]["signing_address"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let sig = &f["rust_signature"];
        let signature = Signature {
            kind: sig["signature_kind"].as_str().unwrap(),
            signing_algo: sig["signing_algo"].as_str().unwrap(),
            signing_address: sig["signing_address"].as_str().unwrap(),
            signed_text: sig["text"].as_str().unwrap(),
            signature: sig["signature"].as_str().unwrap(),
        };
        assert_eq!(
            verify_model_key(&key, &request, bh_crypto::sha256(&response), &signature),
            Ok(())
        );
        let mut changed = request;
        changed.push(b' ');
        assert_eq!(
            verify_model_key(&key, &changed, bh_crypto::sha256(&response), &signature),
            Err(Error::Payload)
        );
    }

    #[test]
    fn exact_encrypted_bytes_kind_signer_and_text() {
        let key = bh_crypto::SigningKey::generate();
        let request = format!(r#"{{"model":"{MODEL}","messages":[]}}"#);
        let wire = b"data: {\"encrypted\":\"00\"}\r\n\r\ndata: [DONE]\n\n";
        let mut hash = WireHash::new();
        for byte in wire {
            hash.update(&[*byte]);
        }
        let digest = hash.finalize();
        assert_eq!(digest, bh_crypto::sha256(wire));
        let text = format!(
            "{MODEL}:{}:{}",
            hex::encode(bh_crypto::sha256(request.as_bytes())),
            hex::encode(digest)
        );
        let sig = hex::encode(key.sign(text.as_bytes()));
        let signer = hex::encode(key.public());
        fn signature<'a>(
            kind: &'a str,
            signer: &'a str,
            signed_text: &'a str,
            signature: &'a str,
        ) -> Signature<'a> {
            Signature {
                kind,
                signing_algo: "ed25519",
                signing_address: signer,
                signed_text,
                signature,
            }
        }
        assert_eq!(
            verify_model_key(
                &key.public(),
                request.as_bytes(),
                digest,
                &signature("provider_tee", &signer, &text, &sig)
            ),
            Ok(())
        );
        assert_eq!(
            verify_model_key(
                &key.public(),
                request.as_bytes(),
                digest,
                &signature("gateway", &signer, &text, &sig)
            ),
            Err(Error::Kind)
        );
        let oversized = "f".repeat(1 << 20);
        let oversized_signer = signature("provider_tee", &oversized, &text, &sig);
        assert_eq!(
            verify_model_key(&key.public(), request.as_bytes(), digest, &oversized_signer),
            Err(Error::Signer)
        );
        let oversized_signature = signature("provider_tee", &signer, &text, &oversized);
        assert_eq!(
            verify_model_key(
                &key.public(),
                request.as_bytes(),
                digest,
                &oversized_signature
            ),
            Err(Error::Signature)
        );
        let wrong_algo = Signature {
            signing_algo: "ecdsa",
            ..signature("provider_tee", &signer, &text, &sig)
        };
        assert_eq!(
            verify_model_key(&key.public(), request.as_bytes(), digest, &wrong_algo),
            Err(Error::Signer)
        );
        assert_eq!(
            verify_model_key(
                &key.public(),
                request.as_bytes(),
                digest,
                &signature(
                    "provider_tee",
                    &hex::encode(bh_crypto::SigningKey::generate().public()),
                    &text,
                    &sig
                )
            ),
            Err(Error::Signer)
        );
        assert_eq!(
            verify_model_key(
                &key.public(),
                request.as_bytes(),
                digest,
                &signature("provider_tee", &signer, "bad", &sig)
            ),
            Err(Error::Payload)
        );
        assert_eq!(
            verify_model_key(
                &key.public(),
                request.as_bytes(),
                bh_crypto::sha256(b"different"),
                &signature("provider_tee", &signer, &text, &sig)
            ),
            Err(Error::Payload)
        );
        assert_eq!(
            verify_model_key(
                &key.public(),
                b"different request",
                digest,
                &signature("provider_tee", &signer, &text, &sig)
            ),
            Err(Error::Payload)
        );
        assert_eq!(
            verify_model_key(
                &key.public(),
                request.as_bytes(),
                digest,
                &signature("provider_tee", &signer, &text, &hex::encode([0u8; 64]))
            ),
            Err(Error::Signature)
        );
    }
}
