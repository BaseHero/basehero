//! Offline NEAR gateway-trust tests. Every key here is synthetic and
//! UNATTESTED. Real HPKE and Ed25519 run, but nothing proves hardware validity
//! or that a live gateway issued the key configuration.
//!
//! The fixture deliberately does not reuse the production chunk labels, nonce
//! arithmetic, varint code or chunk size, so a defect shared by both sides
//! cannot hide. `interop_with_gateway_ohttp_072_server` is the source of truth:
//! it runs the pinned gateway's exact ohttp/bhttp 0.7.2 server code.

use super::*;
use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{KeyInit, Payload},
};
use bh_crypto::SigningKey;
use hkdf::Hkdf;
use hpke::{
    Kem as _, OpModeR, aead::AesGcm128, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver,
};
use rand::{SeedableRng, rngs::StdRng};
use sha2::Sha256;

type Kem = X25519HkdfSha256;
type Aead = AesGcm128;
type Kdf = HkdfSha256;
type Receiver = hpke::aead::AeadCtxR<Aead, Kdf, Kem>;

/// The pinned gateway and SDK chunk plaintext at 16 KiB. Spelled out here so a
/// change in the module cannot silently move both sides together.
const TEST_CHUNK: usize = 16_384;

/// Minimal QUIC varint writer, independent of the module's framing code.
fn iv_varint(value: usize) -> Vec<u8> {
    if value < (1 << 6) {
        vec![value as u8]
    } else if value < (1 << 14) {
        ((value as u16) | (1 << 14)).to_be_bytes().to_vec()
    } else if value < (1 << 30) {
        ((value as u32) | (2 << 30)).to_be_bytes().to_vec()
    } else {
        ((value as u64) | (3u64 << 62)).to_be_bytes().to_vec()
    }
}

/// Independent reader for the framing bytes these tests produce and consume.
struct IvReader<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> IvReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn varint(&mut self) -> usize {
        let first = self.data[self.pos];
        let width = 1usize << (first >> 6);
        let mut value = usize::from(first & 0x3f);
        for offset in 1..width {
            value = (value << 8) | usize::from(self.data[self.pos + offset]);
        }
        self.pos += width;
        value
    }
    fn vector(&mut self) -> &'a [u8] {
        let size = self.varint();
        let value = &self.data[self.pos..self.pos + size];
        self.pos += size;
        value
    }
}

struct Fixture {
    signing: SigningKey,
    signer: GatewaySigner,
    config: GatewayKeyConfig,
    config_bytes: Vec<u8>,
    signature: Vec<u8>,
    recipient: <Kem as hpke::Kem>::PrivateKey,
}

fn sign_config(signing: &SigningKey, raw: &[u8]) -> Vec<u8> {
    signing.sign(raw).to_vec()
}

/// Build a synthetic recipient keypair and a signed configuration with a
/// chosen symmetric suite list (AES128-GCM first by default).
fn fixture_with_suites(suites: &[(u16, u16)]) -> Fixture {
    let mut rng = StdRng::from_os_rng();
    let (recipient, public) = Kem::gen_keypair(&mut rng);
    let mut config_bytes = vec![1u8];
    config_bytes.extend_from_slice(&0x0020u16.to_be_bytes());
    config_bytes.extend_from_slice(public.to_bytes().as_ref());
    config_bytes.extend_from_slice(&((suites.len() * 4) as u16).to_be_bytes());
    for (kdf, aead) in suites {
        config_bytes.extend_from_slice(&kdf.to_be_bytes());
        config_bytes.extend_from_slice(&aead.to_be_bytes());
    }
    let signing = SigningKey::generate();
    let signer = GatewaySigner::for_tests(signing.public());
    let signature = sign_config(&signing, &config_bytes);
    let config = verify_key_config(&config_bytes, &signature, &signer).unwrap();
    Fixture {
        signing,
        signer,
        config,
        config_bytes,
        signature,
        recipient,
    }
}

fn fixture() -> Fixture {
    fixture_with_suites(&[(0x0001, 0x0001), (0x0001, 0x0003)])
}

struct Decoded {
    method: String,
    path: String,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
}

/// Open the outer request with the fixture recipient, independently of the
/// module's reader, labels and chunk arithmetic. Asserts the exact fixed
/// 7-byte header the client must send.
fn open_request(outer_body: &[u8], secret: &<Kem as hpke::Kem>::PrivateKey) -> (Receiver, Decoded) {
    assert_eq!(
        &outer_body[..7],
        &[0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01],
        "outer header must be key 1, DHKEM(X25519), HKDF-SHA256/AES128-GCM"
    );
    let enc = &outer_body[7..39];
    let mut info = b"message/bhttp chunked request".to_vec();
    info.push(0);
    info.extend_from_slice(&outer_body[..7]);
    let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc).unwrap();
    let mut receiver =
        setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, secret, &encapped, &info).unwrap();
    let mut reader = IvReader::new(&outer_body[39..]);
    let mut plaintext = Vec::new();
    loop {
        let size = reader.varint();
        let last = size == 0;
        let take = if last {
            reader.data.len() - reader.pos
        } else {
            size
        };
        let start = reader.pos;
        reader.pos += take;
        let aad: &[u8] = if last { b"final" } else { b"" };
        plaintext.extend_from_slice(
            &receiver
                .open(&reader.data[start..start + take], aad)
                .unwrap(),
        );
        if last {
            break;
        }
    }
    let mut outer = IvReader::new(&plaintext);
    assert_eq!(outer.varint(), 0, "known-length request");
    let method = String::from_utf8(outer.vector().to_vec()).unwrap();
    let _scheme = outer.vector();
    let _authority = outer.vector();
    let path = String::from_utf8(outer.vector().to_vec()).unwrap();
    let fields = outer.vector();
    let mut field_reader = IvReader::new(fields);
    let mut headers = Vec::new();
    while field_reader.pos < fields.len() {
        let name = field_reader.vector().to_vec();
        let value = field_reader.vector().to_vec();
        headers.push((name, value));
    }
    let body = outer.vector().to_vec();
    (
        receiver,
        Decoded {
            method,
            path,
            headers,
            body,
        },
    )
}

/// Derive the response AEAD and base nonce exactly as the pinned SDK's
/// exported-secret HKDF scheme does.
fn response_cipher(receiver: &Receiver, enc: &[u8], nonce: &[u8; 16]) -> (Aes128Gcm, [u8; 12]) {
    let mut secret = [0u8; 16];
    receiver
        .export(b"message/bhttp chunked response", &mut secret)
        .unwrap();
    let mut salt = enc.to_vec();
    salt.extend_from_slice(nonce);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &secret);
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    hkdf.expand(b"key", &mut key).unwrap();
    hkdf.expand(b"nonce", &mut iv).unwrap();
    (Aes128Gcm::new_from_slice(&key).unwrap(), iv)
}

/// The chunked-OHTTP draft XORs the big-endian counter into the last 8 nonce
/// bytes; written out here so a shared bug cannot pass both sides.
fn seal_counter(
    cipher: &Aes128Gcm,
    iv: &[u8; 12],
    counter: u64,
    msg: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let mut wide = [0u8; 16];
    wide[4..].copy_from_slice(iv);
    let folded = u128::from_be_bytes(wide) ^ u128::from(counter);
    cipher
        .encrypt(
            Nonce::from_slice(&folded.to_be_bytes()[4..]),
            Payload { msg, aad },
        )
        .unwrap()
}

/// One chunk frame: a length varint (0 when final) followed by ciphertext.
fn seal_frame(
    cipher: &Aes128Gcm,
    iv: &[u8; 12],
    counter: u64,
    plaintext: &[u8],
    final_chunk: bool,
) -> Vec<u8> {
    let aad: &[u8] = if final_chunk { b"final" } else { b"" };
    let ciphertext = seal_counter(cipher, iv, counter, plaintext, aad);
    let mut frame = if final_chunk {
        iv_varint(0)
    } else {
        iv_varint(ciphertext.len())
    };
    frame.extend_from_slice(&ciphertext);
    frame
}

/// Seal one non-final chunk per `write_all`, then an empty final chunk on
/// close, as ohttp 0.7.2's `ChunkWriter` does.
fn seal_writes(
    receiver: &Receiver,
    enc: &[u8],
    nonce: &[u8; 16],
    writes: &[Vec<u8>],
    drop_final: bool,
    reorder: bool,
) -> Vec<u8> {
    let (cipher, iv) = response_cipher(receiver, enc, nonce);
    let mut frames = Vec::new();
    let mut counter = 0u64;
    for write in writes {
        if write.is_empty() {
            // ChunkWriter seals an empty write as an empty non-final chunk.
            frames.push(seal_frame(&cipher, &iv, counter, b"", false));
            counter += 1;
            continue;
        }
        // ChunkWriter caps each chunk at 16 KiB even for a larger write.
        for piece in write.chunks(TEST_CHUNK) {
            frames.push(seal_frame(&cipher, &iv, counter, piece, false));
            counter += 1;
        }
    }
    if reorder && frames.len() > 1 {
        frames.swap(0, 1);
    }
    let mut out = nonce.to_vec();
    for frame in frames {
        out.extend_from_slice(&frame);
    }
    if !drop_final {
        out.extend_from_slice(&seal_frame(&cipher, &iv, counter, b"", true));
    }
    out
}

/// Build a reply from explicit `(counter, plaintext, final)` frames, including
/// hostile shapes the real `ChunkWriter` would never emit.
fn seal_frames(
    receiver: &Receiver,
    enc: &[u8],
    nonce: &[u8; 16],
    frames: &[(u64, Vec<u8>, bool)],
) -> Vec<u8> {
    let (cipher, iv) = response_cipher(receiver, enc, nonce);
    let mut out = nonce.to_vec();
    for (counter, plaintext, final_chunk) in frames {
        out.extend_from_slice(&seal_frame(&cipher, &iv, *counter, plaintext, *final_chunk));
    }
    out
}

/// Seal a whole BHTTP message split into `TEST_CHUNK` non-final chunks plus an
/// empty final chunk.
fn seal_message(receiver: &Receiver, enc: &[u8], nonce: &[u8; 16], bhttp: &[u8]) -> Vec<u8> {
    let writes: Vec<Vec<u8>> = bhttp.chunks(TEST_CHUNK).map(<[u8]>::to_vec).collect();
    seal_writes(receiver, enc, nonce, &writes, false, false)
}

/// Write a BHTTP request/response with independent framing code.
fn iv_bhttp_response(
    framing: usize,
    status: u16,
    headers: &[(&[u8], &[u8])],
    body: &[u8],
) -> Vec<u8> {
    assert!(
        framing == 1 || framing == 3,
        "only known length and indeterminate"
    );
    let mut fields = Vec::new();
    for (name, value) in headers {
        fields.extend_from_slice(&iv_varint(name.len()));
        fields.extend_from_slice(name);
        fields.extend_from_slice(&iv_varint(value.len()));
        fields.extend_from_slice(value);
    }
    let mut out = Vec::new();
    out.push(framing as u8);
    out.extend_from_slice(&iv_varint(usize::from(status)));
    if framing == 1 {
        out.extend_from_slice(&iv_varint(fields.len()));
        out.extend_from_slice(&fields);
    } else {
        out.extend_from_slice(&fields);
        out.extend_from_slice(&iv_varint(0));
    }
    out.extend_from_slice(&iv_varint(body.len()));
    out.extend_from_slice(body);
    out.extend_from_slice(&iv_varint(0));
    out.extend_from_slice(&iv_varint(0));
    out
}

/// Writes the pinned gateway's `write_indeterminate_response_header` plus body
/// pieces the way `routes/ohttp.rs::ohttp_relay_chunked` does: each varint and
/// each field on its own `write_all`.
fn gateway_writes(body_pieces: &[&[u8]]) -> Vec<Vec<u8>> {
    let mut writes = vec![iv_varint(3), iv_varint(200)];
    for (name, value) in [
        (&b"content-type"[..], &b"text/event-stream"[..]),
        (b"inference-id", b"abc"),
    ] {
        writes.push(iv_varint(name.len()));
        writes.push(name.to_vec());
        writes.push(iv_varint(value.len()));
        writes.push(value.to_vec());
    }
    writes.push(iv_varint(0));
    for piece in body_pieces {
        writes.push(iv_varint(piece.len()));
        writes.push(piece.to_vec());
    }
    writes.push(iv_varint(0));
    writes.push(iv_varint(0));
    writes
}

fn sample_request<'a>(headers: &'a [(&'a str, &'a str)], body: &'a [u8]) -> InnerRequest<'a> {
    InnerRequest {
        method: "POST",
        path: "/v1/chat/completions",
        headers,
        body,
    }
}

fn encapsulate_request<'a>(
    fixture: &Fixture,
    headers: &'a [(&'a str, &'a str)],
    body: &'a [u8],
) -> Encapsulated {
    let mut rng = StdRng::from_os_rng();
    encapsulate(
        &fixture.config,
        &sample_request(headers, body),
        "relay-key",
        &mut rng,
    )
    .unwrap()
}

#[test]
fn key_config_rejects_signature_signer_and_format_substitutions() {
    let fixture = fixture();
    assert_eq!(
        verify_key_config(&fixture.config_bytes, &fixture.signature, &fixture.signer).unwrap(),
        fixture.config
    );

    let mut bad_signature = fixture.signature.clone();
    bad_signature[0] ^= 1;
    assert_eq!(
        verify_key_config(&fixture.config_bytes, &bad_signature, &fixture.signer),
        Err(NearError::InvalidSigner)
    );

    let other = GatewaySigner::for_tests(SigningKey::generate().public());
    assert_eq!(
        verify_key_config(&fixture.config_bytes, &fixture.signature, &other),
        Err(NearError::InvalidSigner)
    );

    assert_eq!(
        verify_key_config(&fixture.config_bytes, &[0u8; 8], &fixture.signer),
        Err(NearError::InvalidSigner)
    );

    // A re-signed but malformed configuration must still fail on format.
    let mut bad_kem = fixture.config_bytes.clone();
    bad_kem[2] = 0x21;
    let signature = sign_config(&fixture.signing, &bad_kem);
    assert_eq!(
        verify_key_config(&bad_kem, &signature, &fixture.signer),
        Err(NearError::InvalidKeyConfig)
    );

    let mut extra = fixture.config_bytes.clone();
    extra.push(0);
    let signature = sign_config(&fixture.signing, &extra);
    assert_eq!(
        verify_key_config(&extra, &signature, &fixture.signer),
        Err(NearError::InvalidKeyConfig)
    );

    // No AES128-GCM suite: unsupported, not silently accepted.
    let mut no_aes = fixture.config_bytes.clone();
    no_aes[37..41].copy_from_slice(&[0x00, 0x02, 0x00, 0x01]);
    let signature = sign_config(&fixture.signing, &no_aes);
    assert_eq!(
        verify_key_config(&no_aes, &signature, &fixture.signer),
        Err(NearError::Unsupported)
    );
}

#[test]
fn aes_suite_is_selected_and_header_is_fixed() {
    // The real gateway lists AES128-GCM first, then ChaCha20-Poly1305. The
    // client always selects AES128-GCM and advertises it in the header,
    // regardless of list order.
    let fixture = fixture_with_suites(&[(0x0001, 0x0003), (0x0001, 0x0001)]);
    let headers = [("authorization", "Bearer inner-token")];
    let encapsulated = encapsulate_request(&fixture, &headers, b"body");
    assert_eq!(
        &encapsulated.outer_body[..7],
        &[0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01],
        "the client must advertise X25519/HKDF-SHA256/AES128-GCM"
    );
    let (receiver, decoded) = open_request(&encapsulated.outer_body, &fixture.recipient);
    assert_eq!(decoded.body, b"body");
    let bhttp = iv_bhttp_response(3, 200, &[(b"content-type", b"text/event-stream")], b"ok");
    let reply = seal_message(
        &receiver,
        &encapsulated.outer_body[7..39],
        &[0x5au8; 16],
        &bhttp,
    );
    let response = encapsulated.decapsulate(&reply).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok");
}

#[test]
fn opaque_round_trip_and_canaries() {
    let fixture = fixture();
    let headers = [
        ("content-type", "application/json"),
        ("authorization", "Bearer inner-proxy-token"),
        ("x-signing-algo", "ed25519"),
        ("x-encrypt-all-fields", "true"),
        ("connection", "keep-alive"),
        ("transfer-encoding", "chunked"),
    ];
    let body = b"{\"messages\":[{\"role\":\"user\",\"content\":\"PROMPT_SECRET\"}]}";
    let encapsulated = encapsulate_request(&fixture, &headers, body);

    assert!(
        encapsulated
            .outer_headers
            .iter()
            .any(|(name, value)| name == "authorization" && value == "Bearer relay-key")
    );
    assert!(
        encapsulated
            .outer_headers
            .iter()
            .any(|(name, value)| name == "content-type" && value == OHTTP_REQUEST_CONTENT_TYPE)
    );
    assert!(
        encapsulated
            .outer_headers
            .iter()
            .any(|(name, value)| name == "incremental" && value == "?1")
    );

    for canary in [
        b"PROMPT_SECRET".as_slice(),
        b"inner-proxy-token".as_slice(),
        b"x-signing-algo".as_slice(),
    ] {
        assert!(
            !encapsulated
                .outer_body
                .windows(canary.len())
                .any(|window| window == canary)
        );
    }

    let (receiver, decoded) = open_request(&encapsulated.outer_body, &fixture.recipient);
    assert_eq!(decoded.method, "POST");
    assert_eq!(decoded.path, "/v1/chat/completions");
    assert_eq!(decoded.body, body);
    // Field-encryption headers belong inside OHTTP.
    assert!(
        decoded
            .headers
            .iter()
            .any(|(name, value)| name == b"authorization" && value == b"Bearer inner-proxy-token")
    );
    assert!(
        decoded
            .headers
            .iter()
            .any(|(name, value)| name == b"x-signing-algo" && value == b"ed25519")
    );
    assert!(
        decoded
            .headers
            .iter()
            .any(|(name, value)| name == b"x-encrypt-all-fields" && value == b"true")
    );
    // Hop-by-hop and connection-listed fields must never reach the inner request.
    assert!(
        !decoded
            .headers
            .iter()
            .any(|(name, _)| name == b"connection" || name == b"transfer-encoding")
    );
    assert!(
        !encapsulated
            .outer_headers
            .iter()
            .any(|(name, _)| name == "connection" || name == "transfer-encoding")
    );

    let bhttp = iv_bhttp_response(
        3,
        200,
        &[
            (b"content-type", b"text/event-stream"),
            (b"inference-id", b"00000000-0000-4000-8000-000000000065"),
        ],
        b"RESPONSE_SECRET",
    );
    let reply = seal_message(
        &receiver,
        &encapsulated.outer_body[7..39],
        &[0x11u8; 16],
        &bhttp,
    );
    assert!(
        reply
            .windows(b"RESPONSE_SECRET".len())
            .all(|window| window != b"RESPONSE_SECRET")
    );
    let response = encapsulated.decapsulate(&reply).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"RESPONSE_SECRET");
    assert!(
        response
            .headers
            .iter()
            .any(|(name, value)| name == b"inference-id"
                && value == b"00000000-0000-4000-8000-000000000065")
    );
}

#[test]
fn gateway_shaped_multichunk_request_and_reply() {
    let fixture = fixture();
    let headers: [(&str, &str); 0] = [];
    let body = vec![b'a'; 40_000]; // three request chunks
    let encapsulated = encapsulate_request(&fixture, &headers, &body);
    let (receiver, decoded) = open_request(&encapsulated.outer_body, &fixture.recipient);
    assert_eq!(decoded.body, body);

    // Count the outer request chunks independently.
    let mut reader = IvReader::new(&encapsulated.outer_body[39..]);
    let mut chunks = 0;
    loop {
        let size = reader.varint();
        chunks += 1;
        if size == 0 {
            break;
        }
        reader.pos += size;
    }
    assert!(
        chunks >= 3,
        "a 40 KiB body must span several chunks, got {chunks}"
    );

    // The gateway writes one non-final chunk per write, then closes with an
    // empty final chunk. The reply body is larger than one chunk.
    let piece = vec![b'z'; 20_000];
    let writes = gateway_writes(&[b"data: 1\n\n", &piece, b"data: [DONE]\n\n"]);
    let reply = seal_writes(
        &receiver,
        &encapsulated.outer_body[7..39],
        &[0x33u8; 16],
        &writes,
        false,
        false,
    );
    let response = encapsulated.decapsulate(&reply).unwrap();
    assert_eq!(response.status, 200);
    assert!(response.body.ends_with(b"data: [DONE]\n\n"));
    assert_eq!(response.body.len(), 9 + 20_000 + 14);
}

#[test]
fn dropped_final_chunk_and_reordered_chunks_fail() {
    let fixture = fixture();
    let headers: [(&str, &str); 0] = [];
    let piece = vec![b'z'; TEST_CHUNK];
    let writes = gateway_writes(&[b"data: 1\n\n", &piece, b"data: [DONE]\n\n"]);
    for (label, drop_final, reorder) in [
        ("dropped final chunk", true, false),
        ("reordered chunks", false, true),
    ] {
        let encapsulated = encapsulate_request(&fixture, &headers, b"x");
        let (receiver, _) = open_request(&encapsulated.outer_body, &fixture.recipient);
        let reply = seal_writes(
            &receiver,
            &encapsulated.outer_body[7..39],
            &[0x77u8; 16],
            &writes,
            drop_final,
            reorder,
        );
        assert!(
            encapsulated.decapsulate(&reply).is_err(),
            "{label} must fail closed"
        );
    }
}

#[test]
fn empty_non_final_chunk_is_rejected() {
    let fixture = fixture();
    let headers: [(&str, &str); 0] = [];
    let encapsulated = encapsulate_request(&fixture, &headers, b"x");
    let (receiver, _) = open_request(&encapsulated.outer_body, &fixture.recipient);
    // A non-final chunk of exactly the tag length would carry no plaintext.
    let writes = vec![vec![1u8], Vec::new()];
    let reply = seal_writes(
        &receiver,
        &encapsulated.outer_body[7..39],
        &[0x22u8; 16],
        &writes,
        false,
        false,
    );
    assert_eq!(encapsulated.decapsulate(&reply), Err(NearError::Decryption));
}

#[test]
fn corrupted_or_truncated_response_fails_closed() {
    let fixture = fixture();
    let headers: [(&str, &str); 0] = [];

    let encapsulated = encapsulate_request(&fixture, &headers, b"x");
    let (receiver, _) = open_request(&encapsulated.outer_body, &fixture.recipient);
    let bhttp = iv_bhttp_response(1, 200, &[], b"ok");
    let mut corrupted = seal_message(
        &receiver,
        &encapsulated.outer_body[7..39],
        &[0x44u8; 16],
        &bhttp,
    );
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert_eq!(
        encapsulated.decapsulate(&corrupted),
        Err(NearError::Decryption)
    );

    // A frame truncated at a chunk boundary fails closed.
    let encapsulated = encapsulate_request(&fixture, &headers, b"x");
    let (receiver, _) = open_request(&encapsulated.outer_body, &fixture.recipient);
    let bhttp = iv_bhttp_response(3, 200, &[], &vec![b'k'; TEST_CHUNK * 2]);
    let mut truncated = seal_message(
        &receiver,
        &encapsulated.outer_body[7..39],
        &[0x55u8; 16],
        &bhttp,
    );
    truncated.truncate(truncated.len() - 1);
    assert!(encapsulated.decapsulate(&truncated).is_err());
}

#[test]
fn non_zero_trailing_padding_is_rejected() {
    let fixture = fixture();
    let headers: [(&str, &str); 0] = [];
    let encapsulated = encapsulate_request(&fixture, &headers, b"x");
    let (receiver, _) = open_request(&encapsulated.outer_body, &fixture.recipient);
    let mut bhttp = iv_bhttp_response(1, 200, &[], b"ok");
    bhttp.push(1);
    let reply = seal_message(
        &receiver,
        &encapsulated.outer_body[7..39],
        &[0x66u8; 16],
        &bhttp,
    );
    assert_eq!(encapsulated.decapsulate(&reply), Err(NearError::Response));
}

#[test]
fn content_length_mismatch_is_rejected() {
    let fixture = fixture();
    let headers: [(&str, &str); 0] = [];
    let encapsulated = encapsulate_request(&fixture, &headers, b"x");
    let (receiver, _) = open_request(&encapsulated.outer_body, &fixture.recipient);
    let bhttp = iv_bhttp_response(3, 200, &[(b"content-length", b"5")], b"ok");
    let reply = seal_message(
        &receiver,
        &encapsulated.outer_body[7..39],
        &[0x77u8; 16],
        &bhttp,
    );
    assert_eq!(encapsulated.decapsulate(&reply), Err(NearError::Response));
}

#[test]
fn informational_status_is_rejected() {
    let fixture = fixture();
    let headers: [(&str, &str); 0] = [];
    for status in [100u16, 101, 199] {
        let encapsulated = encapsulate_request(&fixture, &headers, b"x");
        let (receiver, _) = open_request(&encapsulated.outer_body, &fixture.recipient);
        let bhttp = iv_bhttp_response(3, status, &[], b"");
        let reply = seal_message(
            &receiver,
            &encapsulated.outer_body[7..39],
            &[0x88u8; 16],
            &bhttp,
        );
        assert_eq!(
            encapsulated.decapsulate(&reply),
            Err(NearError::Response),
            "status {status} must not be the final response"
        );
    }
}

#[test]
fn header_value_with_crlf_is_refused() {
    let fixture = fixture();
    let mut rng = StdRng::from_os_rng();
    let headers = [("x-bad", "value\r\nInjected: yes")];
    assert_eq!(
        encapsulate(
            &fixture.config,
            &sample_request(&headers, b""),
            "key",
            &mut rng
        )
        .err(),
        Some(NearError::InvalidRequest)
    );
}

#[test]
fn fixed_recipient_refuses_other_origin_and_oversize() {
    let fixture = fixture();
    let mut rng = StdRng::from_os_rng();
    let headers: [(&str, &str); 0] = [];

    for path in [
        "http://evil.example/v1/chat/completions",
        "//evil.example/v1/chat/completions",
        "/v1/chat/completions#fragment",
        "/v1/chat/completions with space",
    ] {
        let request = InnerRequest {
            method: "POST",
            path,
            headers: &headers,
            body: b"",
        };
        assert_eq!(
            encapsulate(&fixture.config, &request, "key", &mut rng).err(),
            Some(NearError::InvalidRequest),
            "path {path} must be refused"
        );
    }

    let body = vec![0u8; MAX_REQUEST_BYTES + 1];
    assert_eq!(
        encapsulate(
            &fixture.config,
            &sample_request(&headers, &body),
            "key",
            &mut rng
        )
        .err(),
        Some(NearError::TooLarge)
    );

    assert_eq!(
        encapsulate(
            &fixture.config,
            &sample_request(&headers, b""),
            "bad\r\ncredential",
            &mut rng
        )
        .err(),
        Some(NearError::InvalidRequest)
    );
}

#[test]
fn response_bounds_are_enforced() {
    let fixture = fixture();
    let headers: [(&str, &str); 0] = [];

    // Just over the 16 MiB buffered outer bound.
    let encapsulated = encapsulate_request(&fixture, &headers, b"x");
    let oversize = vec![0u8; (16 * 1024 * 1024) + 1];
    assert_eq!(
        encapsulated.decapsulate(&oversize),
        Err(NearError::TooLarge)
    );

    // A valid final chunk one byte over the plaintext bound must be refused
    // before decryption; without the bound it would decrypt and parse.
    let encapsulated = encapsulate_request(&fixture, &headers, b"x");
    let (receiver, _) = open_request(&encapsulated.outer_body, &fixture.recipient);
    let reply = seal_frames(
        &receiver,
        &encapsulated.outer_body[7..39],
        &[0x99u8; 16],
        &[(0, vec![0u8; TEST_CHUNK + 1], true)],
    );
    assert_eq!(encapsulated.decapsulate(&reply), Err(NearError::Decryption));

    // A valid non-final chunk one byte over the plaintext bound must be refused
    // before decryption.
    let encapsulated = encapsulate_request(&fixture, &headers, b"x");
    let (receiver, _) = open_request(&encapsulated.outer_body, &fixture.recipient);
    let reply = seal_frames(
        &receiver,
        &encapsulated.outer_body[7..39],
        &[0xaau8; 16],
        &[(0, vec![0u8; TEST_CHUNK + 1], false), (1, Vec::new(), true)],
    );
    assert_eq!(encapsulated.decapsulate(&reply), Err(NearError::Decryption));
}

// ---- interop with the pinned gateway's own ohttp/bhttp 0.7.2 server ----

struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl futures::io::AsyncWrite for Shared {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        std::task::Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[test]
fn interop_with_gateway_ohttp_072_server() {
    use futures::io::{AsyncReadExt, AsyncWriteExt};
    use ohttp::hpke::{Aead as OhttpAead, Kdf as OhttpKdf, Kem as OhttpKem};

    futures::executor::block_on(async {
        let config = ohttp::KeyConfig::new(
            1,
            OhttpKem::X25519Sha256,
            vec![
                ohttp::SymmetricSuite::new(OhttpKdf::HkdfSha256, OhttpAead::Aes128Gcm),
                ohttp::SymmetricSuite::new(OhttpKdf::HkdfSha256, OhttpAead::ChaCha20Poly1305),
            ],
        )
        .unwrap();
        let raw = config.encode().unwrap();
        let signing = SigningKey::generate();
        let signer = GatewaySigner::for_tests(signing.public());
        let ours = verify_key_config(&raw, &signing.sign(&raw), &signer).unwrap();

        let server = ohttp::Server::new(config).unwrap();
        let headers = [
            ("content-type", "application/json"),
            ("authorization", "Bearer inner"),
        ];
        let big = vec![b'q'; 40_000];
        let mut rng = StdRng::from_os_rng();
        let request =
            encapsulate(&ours, &sample_request(&headers, &big), "relay", &mut rng).unwrap();
        assert_eq!(
            &request.outer_body[..7],
            &[0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01]
        );

        let mut server_request =
            server.decapsulate_stream(futures::io::Cursor::new(request.outer_body.clone()));
        let mut bhttp_request = Vec::new();
        server_request
            .read_to_end(&mut bhttp_request)
            .await
            .unwrap();
        let message =
            bhttp::Message::read_bhttp(&mut std::io::Cursor::new(&bhttp_request[..])).unwrap();
        assert_eq!(message.control().method(), Some(&b"POST"[..]));
        assert_eq!(message.control().path(), Some(&b"/v1/chat/completions"[..]));
        assert_eq!(message.content(), &big[..]);
        assert_eq!(
            message.header().get(b"authorization"),
            Some(&b"Bearer inner"[..])
        );

        // Drive the response exactly as `routes/ohttp.rs::ohttp_relay_chunked`:
        // each varint and field is a separate write, each body piece flushes,
        // and close adds the empty final chunk.
        let buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut writer = server_request.response(Shared(buffer.clone())).unwrap();
        async fn write_field_varint<W: futures::io::AsyncWrite + Unpin>(
            writer: &mut W,
            value: usize,
        ) {
            writer.write_all(&iv_varint(value)).await.unwrap();
        }
        write_field_varint(&mut writer, 3).await;
        write_field_varint(&mut writer, 200).await;
        for (name, value) in [
            (&b"content-type"[..], &b"text/event-stream"[..]),
            (b"inference-id", b"abc"),
        ] {
            write_field_varint(&mut writer, name.len()).await;
            writer.write_all(name).await.unwrap();
            write_field_varint(&mut writer, value.len()).await;
            writer.write_all(value).await.unwrap();
        }
        write_field_varint(&mut writer, 0).await;
        let piece = vec![b'z'; 20_000];
        for part in [&b"data: 1\n\n"[..], &piece[..], b"data: [DONE]\n\n"] {
            write_field_varint(&mut writer, part.len()).await;
            writer.write_all(part).await.unwrap();
            writer.flush().await.unwrap();
        }
        write_field_varint(&mut writer, 0).await;
        write_field_varint(&mut writer, 0).await;
        writer.close().await.unwrap();

        let reply = buffer.lock().unwrap().clone();
        let response = request.decapsulate(&reply).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body.len(), 9 + 20_000 + 14);
        assert!(response.body.ends_with(b"data: [DONE]\n\n"));
        assert!(
            response
                .headers
                .iter()
                .any(|(name, value)| name == b"inference-id" && value == b"abc")
        );
    });
}
