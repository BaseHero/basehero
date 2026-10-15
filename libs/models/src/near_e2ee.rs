//! Offline fixed-model NEAR Ed25519-v2 request/reply protocol. Network I/O,
//! attestation fetch, signature fetch and metering belong to later increments.
//! The outer OHTTP reply is still buffered by `near_route` (16 MiB); the SSE
//! transform is incremental over its decrypted BHTTP body, not network streaming.
use crate::{
    near_fields,
    near_model::VerifiedModelKey,
    near_route::{self, GatewayKeyConfig, InnerRequest},
    near_stream::{self, Stream},
    response::{Completion, Delta, Limits},
};
use bh_crypto::{Secret, SigningKey, provider_compat as compat};
use rand::{CryptoRng, RngCore};

pub use crate::near_signature::Signature;

type FieldOpener = Box<dyn FnMut(&str) -> Result<String, near_stream::Error>>;
const INNER_PATH: &str = "/v1/chat/completions";
const MAX_FIELD_BYTES: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Request,
    Crypto,
    Route,
    Response,
    Signature,
    Limit,
}

/// Only a quote-verified model key can prepare an encrypted request. Fresh
/// response signing key per request, retained only inside this ownership chain.
/// The inner HTTP contains no caller-supplied headers, credentials or cache/body
/// metadata: all mandatory flags live inside the authenticated OHTTP envelope.
pub struct Prepared<'a> {
    model: &'a VerifiedModelKey,
    response_key: Secret<32>,
    response_public: [u8; 32],
    body: Vec<u8>,
}
pub fn prepare<'a>(
    model: &'a VerifiedModelKey,
    request_json: &[u8],
) -> Result<Prepared<'a>, Error> {
    let response_sign = SigningKey::generate();
    let response_public = response_sign.public();
    let response_key =
        compat::ed25519_secret_to_curve25519(&response_sign).map_err(|_| Error::Crypto)?;
    let recipient =
        compat::ed25519_public_to_curve25519(model.public_key()).map_err(|_| Error::Crypto)?;
    let encrypted = near_fields::transform(request_json, |text| {
        encrypt(text, &recipient).map_err(|_| near_fields::Error::Encrypt)
    })
    .map_err(|e| match e {
        near_fields::Error::Limit => Error::Limit,
        near_fields::Error::Shape => Error::Request,
        near_fields::Error::Encrypt => Error::Crypto,
    })?;
    let body = serde_json::to_vec(&encrypted).map_err(|_| Error::Request)?;
    Ok(Prepared {
        model,
        response_key,
        response_public,
        body,
    })
}

impl<'a> Prepared<'a> {
    /// Encapsulate the exact serialized encrypted request. The ordinary relay
    /// gets only an outer credential; neither client nor model key headers escape.
    pub fn encapsulate<R: CryptoRng + RngCore>(
        self,
        key_config: &GatewayKeyConfig,
        relay_credential: &str,
        rng: &mut R,
    ) -> Result<Exchange<'a>, Error> {
        let client = hex::encode(self.response_public);
        let model = hex::encode(self.model.public_key());
        let headers = [
            ("content-type", "application/json"),
            ("accept", "text/event-stream"),
            ("x-signing-algo", "ed25519"),
            ("x-client-pub-key", client.as_str()),
            ("x-model-pub-key", model.as_str()),
            ("x-encryption-version", "2"),
            ("x-no-aliasing", "true"),
            ("x-encrypt-all-fields", "true"),
        ];
        let request = InnerRequest {
            method: "POST",
            path: INNER_PATH,
            headers: &headers,
            body: &self.body,
        };
        let outer = near_route::encapsulate(key_config, &request, relay_credential, rng)
            .map_err(|_| Error::Route)?;
        Ok(Exchange {
            outer,
            prepared: self,
        })
    }
}

/// Opaque OHTTP request. Transport must dispatch at most once after its durable
/// reservation; this type neither performs I/O nor claims cancellation/settlement.
pub struct Exchange<'a> {
    outer: near_route::Encapsulated,
    prepared: Prepared<'a>,
}
impl<'a> Exchange<'a> {
    pub fn outer_headers(&self) -> &[(String, String)] {
        &self.outer.outer_headers
    }
    pub fn outer_body(&self) -> &[u8] {
        &self.outer.outer_body
    }
    /// The current OHTTP decoder buffers and authenticates the entire response
    /// before providing its BHTTP body. Never present this as wire-level streaming.
    pub fn decapsulate(self, outer_body: &[u8]) -> Result<BufferedReply<'a>, Error> {
        self.decapsulate_with_limits(outer_body, Limits::default())
    }
    pub(crate) fn decapsulate_with_limits(
        self,
        outer_body: &[u8],
        limits: Limits,
    ) -> Result<BufferedReply<'a>, Error> {
        let response = self
            .outer
            .decapsulate(outer_body)
            .map_err(|_| Error::Route)?;
        if response.status != 200
            || !response.headers.iter().any(|(name, value)| {
                name == b"content-type" && value.starts_with(b"text/event-stream")
            })
        {
            return Err(Error::Response);
        }
        let request = self.prepared.body;
        let key = self.prepared.response_key;
        let opener = move |field: &str| decrypt(field, &key).map_err(|_| near_stream::Error::Field);
        let stream = Stream::new(Box::new(opener) as FieldOpener, limits);
        Ok(BufferedReply {
            model: self.prepared.model,
            request,
            body: response.body,
            offset: 0,
            exhausted: false,
            failed: false,
            stream,
        })
    }
}

/// SSE read with bounded event/field memory and explicitly provisional text.
/// `finish` consumes this handle and releases a completion only after EOF,
/// `[DONE]`, a supported finish marker, and the exact encrypted-wire signature.
pub struct BufferedReply<'a> {
    model: &'a VerifiedModelKey,
    request: Vec<u8>,
    body: Vec<u8>,
    offset: usize,
    exhausted: bool,
    failed: bool,
    stream: Stream<FieldOpener>,
}
impl BufferedReply<'_> {
    pub fn next_provisional(&mut self) -> Result<Option<Vec<Delta>>, Error> {
        if self.exhausted || self.failed {
            self.failed = true;
            return Err(Error::Response);
        }
        if self.offset == self.body.len() {
            self.exhausted = true;
            return Ok(None);
        }
        let end = (self.offset + 1024).min(self.body.len());
        let deltas = self
            .stream
            .push(&self.body[self.offset..end])
            .map_err(|e| {
                self.failed = true;
                map_stream(e)
            })?;
        self.offset = end;
        Ok(Some(deltas))
    }
    /// Caller must fetch signature separately; a missing/late signature leaves
    /// the response provisional. Signature metadata cannot nominate another key.
    pub fn finish(self, signature: &Signature<'_>) -> Result<Completion, Error> {
        if self.failed || self.offset != self.body.len() {
            return Err(Error::Response);
        }
        self.stream
            .finish(self.model, &self.request, signature)
            .map_err(map_stream)
    }
}
fn map_stream(e: near_stream::Error) -> Error {
    match e {
        near_stream::Error::Signature => Error::Signature,
        near_stream::Error::Limit => Error::Limit,
        _ => Error::Response,
    }
}

fn encrypt(text: &str, recipient: &[u8; 32]) -> Result<String, Error> {
    if text.len() > MAX_FIELD_BYTES {
        return Err(Error::Limit);
    }
    let ephemeral = Secret::<32>::random();
    let public = compat::x25519_base(&ephemeral).map_err(|_| Error::Crypto)?;
    let shared = compat::x25519(&ephemeral, recipient).map_err(|_| Error::Crypto)?;
    let key =
        compat::hkdf_sha256_no_salt(&shared, b"ed25519_encryption").map_err(|_| Error::Crypto)?;
    let (nonce, ciphertext) =
        bh_crypto::aead_seal(&key, &[], text.as_bytes()).map_err(|_| Error::Crypto)?;
    let mut wire = Vec::with_capacity(32 + 24 + ciphertext.len());
    wire.extend_from_slice(&public);
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&ciphertext);
    Ok(hex::encode(wire))
}
fn decrypt(field: &str, key: &Secret<32>) -> Result<String, Error> {
    if field.is_empty() {
        return Ok(String::new());
    } // SDK's empty response-field convention
    if field.len() > 2 * (MAX_FIELD_BYTES + 72) {
        return Err(Error::Limit);
    }
    let wire = hex::decode(field).map_err(|_| Error::Response)?;
    if wire.len() < 72 {
        return Err(Error::Response);
    }
    let public: [u8; 32] = wire[..32].try_into().map_err(|_| Error::Response)?;
    let nonce: [u8; 24] = wire[32..56].try_into().map_err(|_| Error::Response)?;
    let shared = compat::x25519(key, &public).map_err(|_| Error::Response)?;
    let derived =
        compat::hkdf_sha256_no_salt(&shared, b"ed25519_encryption").map_err(|_| Error::Crypto)?;
    let plaintext =
        bh_crypto::aead_open(&derived, &nonce, &[], &wire[56..]).map_err(|_| Error::Response)?;
    let text = std::str::from_utf8(plaintext.expose()).map_err(|_| Error::Response)?;
    Ok(text.to_owned())
}

#[cfg(test)]
#[path = "near_e2ee_tests.rs"]
mod tests;
