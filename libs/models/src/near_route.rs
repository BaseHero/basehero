//! Fixed NEAR Cloud Gateway trust and OHTTP/BHTTP framing.
//!
//! This module verifies an Ed25519-signed OHTTP key configuration against a
//! quote-verified gateway signer and encapsulates/decapsulates the draft
//! `chunked-ohttp` exchange the pinned NEAR Python SDK and Cloud Gateway both
//! use. It performs no network I/O, issues no nonce and verifies no hardware:
//! the caller owns attestation, authority, accounting and the single dispatch.
//! Test keys are synthetic and prove protocol/ordering, never hardware.

use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead as _, KeyInit, Payload},
};
use hkdf::Hkdf;
use hpke::{
    Deserializable as _, OpModeS, Serializable as _, aead::AesGcm128, kdf::HkdfSha256,
    kem::X25519HkdfSha256, setup_sender,
};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use std::fmt;

type NearKem = X25519HkdfSha256;
type NearKdf = HkdfSha256;
type NearAead = AesGcm128;

/// Fixed recipient. The route never sends to another scheme or authority.
pub const NEAR_SCHEME: &str = "https";
pub const NEAR_AUTHORITY: &str = "cloud-api.near.ai";
pub const OHTTP_PATH: &str = "/ohttp";
const REQUEST_LABEL: &[u8] = b"message/bhttp chunked request";
const RESPONSE_LABEL: &[u8] = b"message/bhttp chunked response";
const CHUNK_SIZE: usize = 16_384;
const TAG_SIZE: usize = 16;
pub const OHTTP_REQUEST_CONTENT_TYPE: &str = "message/ohttp-chunked-req";
pub const OHTTP_RESPONSE_CONTENT_TYPE: &str = "message/ohttp-chunked-res";
/// Lower-cased name/value response fields.
type HeaderFields = Vec<(Vec<u8>, Vec<u8>)>;
/// Bound on the unpadded inner request.
pub const MAX_REQUEST_BYTES: usize = 1 << 20;
/// Bound on the buffered outer response this increment decrypts in one pass.
pub const MAX_RESPONSE_BYTES: usize = 1 << 24;

/// All failures are fixed, content-free kinds; never include key material,
/// decrypted bytes, provider text or caller input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NearError {
    InvalidSigner,
    InvalidKeyConfig,
    InvalidRequest,
    Encryption,
    Decryption,
    Response,
    TooLarge,
    Unsupported,
}
impl fmt::Display for NearError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "near route: {self:?}")
    }
}
impl std::error::Error for NearError {}

/// A quote-bound gateway signing key (Ed25519, 32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewaySigner(pub [u8; 32]);

/// Parsed OHTTP key configuration restricted to X25519 + HKDF-SHA256 +
/// AES128-GCM. Only `verify_key_config` constructs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewayKeyConfig {
    key_id: u8,
    public_key: [u8; 32],
}

/// One inner HTTP request. Only the origin-form path is caller-chosen; scheme
/// and authority are fixed above.
pub struct InnerRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
}

/// A prepared outer request plus the sender context that can open its reply.
pub struct Encapsulated {
    /// Outer headers the relay may forward: only the provider credential,
    /// the chunked content type and the incremental hint.
    pub outer_headers: Vec<(String, String)>,
    /// Exact outer request bytes to POST to `OHTTP_PATH`.
    pub outer_body: Vec<u8>,
    response: ResponseContext,
}

struct ResponseContext {
    context: hpke::aead::AeadCtxS<NearAead, NearKdf, NearKem>,
    enc: Vec<u8>,
}

/// A decoded BHTTP response. Body is bounded by `MAX_RESPONSE_BYTES`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BhttpResponse {
    pub status: u16,
    pub headers: HeaderFields,
    pub body: Vec<u8>,
}

/// Verify the Ed25519 signature over the raw key-config bytes against a
/// gateway signer, then parse with strict suite checks.
pub fn verify_key_config(
    raw: &[u8],
    signature: &[u8],
    signer: &GatewaySigner,
) -> Result<GatewayKeyConfig, NearError> {
    let signature: &[u8; 64] = signature.try_into().map_err(|_| NearError::InvalidSigner)?;
    bh_crypto::verify(&signer.0, raw, signature).map_err(|_| NearError::InvalidSigner)?;
    parse_key_config(raw)
}

fn parse_key_config(raw: &[u8]) -> Result<GatewayKeyConfig, NearError> {
    if raw.len() < 41 {
        return Err(NearError::InvalidKeyConfig);
    }
    // HPKE KEM id must be DHKEM(X25519, HKDF-SHA256).
    if raw[1] != 0x00 || raw[2] != 0x20 {
        return Err(NearError::InvalidKeyConfig);
    }
    let size = usize::from(u16::from_be_bytes([raw[35], raw[36]]));
    if size == 0 || size % 4 != 0 || raw.len() != 37 + size {
        return Err(NearError::InvalidKeyConfig);
    }
    let mut supported = false;
    for offset in (37..raw.len()).step_by(4) {
        if raw[offset..offset + 4] == [0x00, 0x01, 0x00, 0x01] {
            supported = true;
        }
    }
    if !supported {
        return Err(NearError::Unsupported);
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&raw[3..35]);
    Ok(GatewayKeyConfig {
        key_id: raw[0],
        public_key,
    })
}

/// Encapsulate one fixed-origin inner request as chunked OHTTP. `relay_credential`
/// is the ordinary-relay credential; it is the only caller value placed in the
/// outer headers, and no inner content or field-encryption header escapes.
pub fn encapsulate<R: CryptoRng + RngCore>(
    config: &GatewayKeyConfig,
    request: &InnerRequest<'_>,
    relay_credential: &str,
    rng: &mut R,
) -> Result<Encapsulated, NearError> {
    validate_path(request.path)?;
    if relay_credential.is_empty()
        || relay_credential
            .bytes()
            .any(|byte| byte == 0 || byte == b'\r' || byte == b'\n')
    {
        return Err(NearError::InvalidRequest);
    }
    let plaintext = encode_bhttp_request(request)?;
    let header = ohttp_header(config.key_id);
    let mut info = Vec::with_capacity(REQUEST_LABEL.len() + 1 + header.len());
    info.extend_from_slice(REQUEST_LABEL);
    info.push(0);
    info.extend_from_slice(&header);

    let public = <NearKem as hpke::Kem>::PublicKey::from_bytes(&config.public_key)
        .map_err(|_| NearError::InvalidKeyConfig)?;
    let (enc, mut context) =
        setup_sender::<NearAead, NearKdf, NearKem, _>(&OpModeS::Base, &public, &info, rng)
            .map_err(|_| NearError::Encryption)?;
    let enc = enc.to_bytes().as_slice().to_vec();

    let mut outer_body = Vec::with_capacity(header.len() + enc.len() + plaintext.len());
    outer_body.extend_from_slice(&header);
    outer_body.extend_from_slice(&enc);
    let chunks = plaintext.len().div_ceil(CHUNK_SIZE);
    for (index, chunk) in plaintext.chunks(CHUNK_SIZE).enumerate() {
        let last = index + 1 == chunks;
        let aad: &[u8] = if last { b"final" } else { b"" };
        let ciphertext = context
            .seal(chunk, aad)
            .map_err(|_| NearError::Encryption)?;
        if last {
            write_varint(&mut outer_body, 0);
        } else {
            write_varint(&mut outer_body, ciphertext.len());
        }
        outer_body.extend_from_slice(&ciphertext);
    }

    Ok(Encapsulated {
        outer_headers: vec![
            (
                "content-type".to_string(),
                OHTTP_REQUEST_CONTENT_TYPE.to_string(),
            ),
            (
                "authorization".to_string(),
                format!("Bearer {relay_credential}"),
            ),
            ("incremental".to_string(), "?1".to_string()),
        ],
        outer_body,
        response: ResponseContext { context, enc },
    })
}

impl Encapsulated {
    /// Consume the sender context and open the outer response body. This
    /// increment buffers the whole bounded reply; streaming is a later increment.
    pub fn decapsulate(self, outer_body: &[u8]) -> Result<BhttpResponse, NearError> {
        self.response.decapsulate(outer_body)
    }
}

impl ResponseContext {
    fn decapsulate(self, outer_body: &[u8]) -> Result<BhttpResponse, NearError> {
        if outer_body.len() > MAX_RESPONSE_BYTES {
            return Err(NearError::TooLarge);
        }
        let mut reader = Reader::new(outer_body);
        let response_nonce = reader.exact(16)?.to_vec();
        let mut secret = [0u8; 16];
        self.context
            .export(RESPONSE_LABEL, &mut secret)
            .map_err(|_| NearError::Decryption)?;
        let mut salt = self.enc;
        salt.extend_from_slice(&response_nonce);
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &secret);
        let mut key = [0u8; 16];
        let mut base_nonce = [0u8; 12];
        hkdf.expand(b"key", &mut key)
            .map_err(|_| NearError::Decryption)?;
        hkdf.expand(b"nonce", &mut base_nonce)
            .map_err(|_| NearError::Decryption)?;
        let cipher = Aes128Gcm::new_from_slice(&key).map_err(|_| NearError::Decryption)?;

        let mut plaintext = Vec::new();
        let mut counter: u64 = 0;
        loop {
            let size = reader.varint(false)?;
            let last = size == 0;
            let take = if last {
                let remaining = reader.remaining();
                if remaining > CHUNK_SIZE + TAG_SIZE {
                    return Err(NearError::Decryption);
                }
                remaining
            } else {
                if size > CHUNK_SIZE + TAG_SIZE {
                    return Err(NearError::Decryption);
                }
                size
            };
            let ciphertext = reader.exact(take)?;
            if ciphertext.len() < TAG_SIZE || (!last && ciphertext.len() == TAG_SIZE) {
                return Err(NearError::Decryption);
            }
            let mut nonce = base_nonce;
            xor_counter(&mut nonce, counter);
            let aad: &[u8] = if last { b"final" } else { b"" };
            let chunk = cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| NearError::Decryption)?;
            plaintext.extend_from_slice(&chunk);
            if plaintext.len() > MAX_RESPONSE_BYTES {
                return Err(NearError::TooLarge);
            }
            counter = counter.checked_add(1).ok_or(NearError::Decryption)?;
            if last {
                break;
            }
        }
        parse_bhttp_response(&plaintext)
    }
}

fn ohttp_header(key_id: u8) -> [u8; 7] {
    [key_id, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01]
}

fn xor_counter(nonce: &mut [u8; 12], counter: u64) {
    // The chunked-OHTTP draft XORs the big-endian counter into the last 8 nonce
    // bytes, as ohttp 0.7.2 and the pinned Python SDK do.
    let bytes = counter.to_be_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        nonce[4 + index] ^= byte;
    }
}

fn is_token(byte: u8) -> bool {
    matches!(byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~'
        | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

fn validate_path(path: &str) -> Result<(), NearError> {
    if !path.starts_with('/') || path.starts_with("//") {
        return Err(NearError::InvalidRequest);
    }
    if path
        .bytes()
        .any(|byte| byte == 0 || byte == b'\r' || byte == b'\n' || byte == b' ' || byte == b'#')
    {
        return Err(NearError::InvalidRequest);
    }
    Ok(())
}

fn write_varint(out: &mut Vec<u8>, value: usize) {
    if value < (1 << 6) {
        out.push(value as u8);
    } else if value < (1 << 14) {
        out.extend_from_slice(&((value as u16) | (1 << 14)).to_be_bytes());
    } else if value < (1 << 30) {
        out.extend_from_slice(&((value as u32) | (2 << 30)).to_be_bytes());
    } else {
        out.extend_from_slice(&((value as u64) | (3 << 62)).to_be_bytes());
    }
}

fn write_vector(out: &mut Vec<u8>, value: &[u8]) {
    write_varint(out, value.len());
    out.extend_from_slice(value);
}

fn hop_by_hop(lower: &str) -> bool {
    matches!(
        lower,
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "te"
            | "trailer"
    )
}

fn encode_bhttp_request(request: &InnerRequest<'_>) -> Result<Vec<u8>, NearError> {
    let method = request.method.as_bytes();
    if method.is_empty() || !method.iter().all(|byte| is_token(*byte)) {
        return Err(NearError::InvalidRequest);
    }
    let connection: Vec<&str> = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .map(|(_, value)| value.split(',').map(str::trim).collect())
        .unwrap_or_default();

    let mut fields = Vec::new();
    for (name, value) in request.headers {
        let lower = name.to_ascii_lowercase();
        if hop_by_hop(&lower)
            || connection
                .iter()
                .any(|item| item.eq_ignore_ascii_case(&lower))
        {
            continue;
        }
        if lower.is_empty()
            || !lower.as_bytes().iter().all(|byte| is_token(*byte))
            || value
                .bytes()
                .any(|byte| byte == 0 || byte == b'\r' || byte == b'\n')
        {
            return Err(NearError::InvalidRequest);
        }
        write_vector(&mut fields, lower.as_bytes());
        write_vector(&mut fields, value.as_bytes());
    }
    if fields.len() + request.body.len() > MAX_REQUEST_BYTES {
        return Err(NearError::TooLarge);
    }

    let mut out = Vec::new();
    out.push(0); // known-length request framing
    write_vector(&mut out, method);
    write_vector(&mut out, NEAR_SCHEME.as_bytes());
    write_vector(&mut out, NEAR_AUTHORITY.as_bytes());
    write_vector(&mut out, request.path.as_bytes());
    write_vector(&mut out, &fields);
    write_vector(&mut out, request.body);
    out.push(0); // empty trailer section
    if out.len() > MAX_REQUEST_BYTES {
        return Err(NearError::TooLarge);
    }
    let padding = (CHUNK_SIZE - out.len() % CHUNK_SIZE) % CHUNK_SIZE;
    out.resize(out.len() + padding, 0);
    Ok(out)
}

struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }
    fn remaining(&self) -> usize {
        self.data.len() - self.position
    }
    fn exact(&mut self, size: usize) -> Result<&'a [u8], NearError> {
        let end = self.position.checked_add(size).ok_or(NearError::Response)?;
        let value = self
            .data
            .get(self.position..end)
            .ok_or(NearError::Response)?;
        self.position = end;
        Ok(value)
    }
    fn varint(&mut self, eof_zero: bool) -> Result<usize, NearError> {
        let Some(first) = self.data.get(self.position).copied() else {
            return if eof_zero {
                Ok(0)
            } else {
                Err(NearError::Response)
            };
        };
        self.position += 1;
        let width = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for _ in 1..width {
            value =
                (value << 8) | u64::from(*self.data.get(self.position).ok_or(NearError::Response)?);
            self.position += 1;
        }
        usize::try_from(value).map_err(|_| NearError::TooLarge)
    }
    fn vector(&mut self) -> Result<&'a [u8], NearError> {
        let size = self.varint(false)?;
        self.exact(size)
    }
}

fn parse_fields(reader: &mut Reader<'_>, known_length: bool) -> Result<HeaderFields, NearError> {
    if known_length {
        let size = reader.varint(true)?;
        let bytes = reader.exact(size)?;
        let mut section = Reader::new(bytes);
        parse_field_list(&mut section, Some(size))
    } else {
        parse_field_list(reader, None)
    }
}

fn parse_field_list(
    reader: &mut Reader<'_>,
    limit: Option<usize>,
) -> Result<HeaderFields, NearError> {
    let mut fields = Vec::new();
    let mut total = 0usize;
    loop {
        if let Some(limit) = limit
            && reader.position == limit
        {
            return Ok(fields);
        }
        let name_size = reader.varint(limit.is_none() && fields.is_empty())?;
        if name_size == 0 {
            if limit.is_some() {
                return Err(NearError::Response);
            }
            return Ok(fields);
        }
        total += name_size;
        if total > MAX_RESPONSE_BYTES {
            return Err(NearError::TooLarge);
        }
        let name = reader.exact(name_size)?;
        let value = reader.vector()?;
        total += value.len();
        if total > MAX_RESPONSE_BYTES {
            return Err(NearError::TooLarge);
        }
        if !name.iter().all(|byte| is_token(byte.to_ascii_lowercase()))
            || value
                .iter()
                .any(|byte| *byte == 0 || *byte == b'\r' || *byte == b'\n')
        {
            return Err(NearError::Response);
        }
        fields.push((name.to_ascii_lowercase(), value.to_vec()));
    }
}

fn content_length(headers: &HeaderFields, status: u16) -> Result<Option<usize>, NearError> {
    let mut lengths = std::collections::BTreeSet::new();
    for (name, value) in headers {
        if name != b"content-length" {
            continue;
        }
        for item in value.split(|byte| *byte == b',') {
            let item = item
                .iter()
                .copied()
                .filter(|byte| *byte != b' ' && *byte != b'\t')
                .collect::<Vec<_>>();
            let text = std::str::from_utf8(&item).map_err(|_| NearError::Response)?;
            let number = text.parse::<usize>().map_err(|_| NearError::Response)?;
            lengths.insert(number);
        }
    }
    if lengths.len() > 1 {
        return Err(NearError::Response);
    }
    let length = lengths.into_iter().next();
    if length.is_some() && (status < 200 || status == 204) {
        return Err(NearError::Response);
    }
    if status == 205 && length.is_some_and(|value| value != 0) {
        return Err(NearError::Response);
    }
    if status == 204 || status == 304 {
        return Ok(Some(0));
    }
    Ok(length)
}

fn parse_bhttp_response(plaintext: &[u8]) -> Result<BhttpResponse, NearError> {
    let mut reader = Reader::new(plaintext);
    let framing = reader.varint(false)?;
    if framing != 1 && framing != 3 {
        return Err(NearError::Response);
    }
    let known_length = framing == 1;
    let status = reader.varint(false)?;
    // RFC 9292 informational responses precede the final response; the gateway's
    // reqwest loopback consumes them, so only a final 2xx..5xx is accepted.
    if !(200..=599).contains(&status) {
        return Err(NearError::Response);
    }
    let status = status as u16;
    let headers = parse_fields(&mut reader, known_length)?;
    let expected = content_length(&headers, status)?;

    let mut body = Vec::new();
    if known_length {
        let size = reader.varint(true)?;
        if size > 0 {
            body.extend_from_slice(reader.exact(size)?);
        }
    } else {
        let mut first = true;
        loop {
            let size = reader.varint(first)?;
            first = false;
            if size == 0 {
                break;
            }
            body.extend_from_slice(reader.exact(size)?);
            if body.len() > MAX_RESPONSE_BYTES {
                return Err(NearError::TooLarge);
            }
        }
    }
    if let Some(expected) = expected
        && body.len() != expected
    {
        return Err(NearError::Response);
    }
    parse_fields(&mut reader, known_length)?;
    while let Some(byte) = plaintext.get(reader.position) {
        if *byte != 0 {
            return Err(NearError::Response);
        }
        reader.position += 1;
    }
    Ok(BhttpResponse {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
#[path = "near_route_tests.rs"]
mod tests;
