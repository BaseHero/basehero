use super::*;
use bh_crypto::SigningKey;
use serde_json::{Value, json};

fn model() -> VerifiedModelKey {
    VerifiedModelKey::for_tests(SigningKey::generate().public())
}
fn request() -> Value {
    json!({"model":"z-ai/glm-5.3-flash","stream":true,"messages":[{"role":"user","content":"confidential"}]})
}
fn schema() -> Value {
    json!({"type":"object","description":"schema-canary","properties":{"private-canary":{"type":"array","items":{"type":"object","properties":{"kind":{"enum":["ok"]},"count":{"type":"integer"}},"required":["kind","count"],"additionalProperties":false}}},"required":["private-canary"],"additionalProperties":false})
}
#[test]
fn validates_real_nested_schema_and_rejects_incompatible_values() {
    let model = model();
    let prepared = prepare_structured(
        &model,
        request().to_string().as_bytes(),
        schema().to_string().as_bytes(),
    )
    .unwrap();
    assert!(prepared.accepts(&json!({"private-canary":[{"kind":"ok","count":3}]})));
    for bad in [
        json!({}),
        json!({"private-canary":[{"kind":"no","count":3}]}),
        json!({"private-canary":[{"kind":"ok","count":"3"}]}),
        json!({"private-canary":[{"kind":"ok","count":3,"extra":1}]}),
        json!({"private-canary":[],"extra":1}),
    ] {
        assert!(!prepared.accepts(&bad));
    }
}
#[test]
fn refuses_collisions_refs_and_bounds_without_exposing_canaries() {
    let model = model();
    for field in [
        "tools",
        "tool_choice",
        "function_call",
        "response_format",
        "parallel_tool_calls",
    ] {
        let mut request = request();
        request[field] = json!(null);
        assert_eq!(
            prepare_structured(
                &model,
                request.to_string().as_bytes(),
                schema().to_string().as_bytes()
            )
            .err(),
            Some(Error::Request)
        );
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let file = std::env::temp_dir().join(format!(
        "bh-schema-{}",
        hex::encode(SigningKey::generate().public())
    ));
    std::fs::write(&file, br#"{"type":"object"}"#).unwrap();
    for schema in [
        json!({"$ref":format!("http://{}/private-canary", listener.local_addr().unwrap())}),
        json!({"$ref":format!("file://{}", file.display())}),
        json!({"type":"object","properties":{"nested":{"$ref":format!("file://{}",file.display())}}}),
        json!({"type":"object","properties":{"nested":{"$ref":format!("http://{}/private-canary", listener.local_addr().unwrap())}}}),
        json!({"$ref":"#/$defs/local"}),
        json!({"type":"object","properties":{"a":{"pattern":".*"}}}),
        json!({"type":"object","properties":{"a":{"format":"uri"}}}),
    ] {
        assert_eq!(
            prepare_structured(
                &model,
                request().to_string().as_bytes(),
                schema.to_string().as_bytes()
            )
            .err(),
            Some(Error::Request)
        );
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    std::fs::remove_file(file).unwrap();
    let mut too_deep = json!({"type":"string"});
    for _ in 0..35 {
        too_deep = json!({"type":"object","properties":{"a":too_deep}});
    }
    assert_eq!(
        prepare_structured(
            &model,
            request().to_string().as_bytes(),
            too_deep.to_string().as_bytes()
        )
        .err(),
        Some(Error::Limit)
    );
    let too_big = json!({"type":"object","description":"x".repeat(65536)});
    assert_eq!(
        prepare_structured(
            &model,
            request().to_string().as_bytes(),
            too_big.to_string().as_bytes()
        )
        .err(),
        Some(Error::Limit)
    );
    let err = prepare_structured(
        &model,
        request().to_string().as_bytes(),
        br#"{"type":"private-canary"}"#,
    )
    .err()
    .unwrap();
    assert!(!format!("{err:?}").contains("private-canary"));
}

// Independent gateway server and recipient cryptography: exercises the actual
// structured ownership chain, not a duplicate completion collector.
#[test]
fn signed_gateway_result_is_data_only_and_failures_release_nothing() {
    use bh_crypto::{Secret, provider_compat as compat};
    use futures::io::{AsyncReadExt, AsyncWriteExt};
    use ohttp::hpke::{Aead, Kdf, Kem};
    use rand::{SeedableRng, rngs::StdRng};
    use std::sync::{Arc, Mutex};
    fn varint(n: usize) -> Vec<u8> {
        if n < 64 {
            vec![n as u8]
        } else if n < 16384 {
            ((n as u16) | 0x4000).to_be_bytes().to_vec()
        } else {
            ((n as u32) | 0x8000_0000).to_be_bytes().to_vec()
        }
    }
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl futures::io::AsyncWrite for Sink {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.0.lock().unwrap().extend_from_slice(data);
            std::task::Poll::Ready(Ok(data.len()))
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
    fn seal(text: &str, key: &[u8; 32]) -> String {
        let secret = Secret::<32>::random();
        let public = compat::x25519_base(&secret).unwrap();
        let shared = compat::x25519(&secret, key).unwrap();
        let derived = compat::hkdf_sha256_no_salt(&shared, b"ed25519_encryption").unwrap();
        let (nonce, ciphertext) = bh_crypto::aead_seal(&derived, &[], text.as_bytes()).unwrap();
        hex::encode([public.as_slice(), nonce.as_slice(), ciphertext.as_slice()].concat())
    }
    fn open(field: &str, key: &Secret<32>) -> String {
        let raw = hex::decode(field).unwrap();
        let public: [u8; 32] = raw[..32].try_into().unwrap();
        let nonce: [u8; 24] = raw[32..56].try_into().unwrap();
        let shared = compat::x25519(key, &public).unwrap();
        let derived = compat::hkdf_sha256_no_salt(&shared, b"ed25519_encryption").unwrap();
        let value = bh_crypto::aead_open(&derived, &nonce, &[], &raw[56..]).unwrap();
        String::from_utf8(value.expose().to_vec()).unwrap()
    }
    futures::executor::block_on(async {
        let model_sign = SigningKey::generate();
        let model = VerifiedModelKey::for_tests(model_sign.public());
        let model_secret = compat::ed25519_secret_to_curve25519(&model_sign).unwrap();
        let config = ohttp::KeyConfig::new(
            1,
            Kem::X25519Sha256,
            vec![ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm)],
        )
        .unwrap();
        let raw = config.encode().unwrap();
        let gateway_sign = SigningKey::generate();
        let gateway = crate::near_route::GatewaySigner::for_tests(gateway_sign.public());
        let key_config =
            crate::near_route::verify_key_config(&raw, &gateway_sign.sign(&raw), &gateway).unwrap();
        let valid = json!({"private-canary":[{"kind":"ok","count":3}]});
        // 1 root + 1 array + 700 × (object + 2 values) = 2,102 nodes.
        // The whole JSON and each encrypted SSE event fit below their byte caps.
        let oversized_nodes = json!({"private-canary": (0..700).map(|_| json!({"kind":"ok","count":3})).collect::<Vec<_>>()});
        let mut nested = json!(true);
        for _ in 0..34 {
            nested = json!({"n": nested});
        }
        let too_deep = json!({"nested": nested});
        for (tools, done, good_sig, success) in [
            (vec![(NAME, valid.clone())], true, true, true),
            (
                vec![(NAME, json!({"private-canary":[{"kind":"bad","count":3}]}))],
                true,
                true,
                false,
            ),
            (vec![("wrong", valid.clone())], true, true, false),
            (vec![("text_plus_tool", valid.clone())], true, true, false),
            (vec![("malformed", valid.clone())], true, true, false),
            (vec![("truncated_outer", valid.clone())], true, true, false),
            (
                vec![("oversized_nodes", oversized_nodes)],
                true,
                true,
                false,
            ),
            (vec![("aggregate_bytes", valid.clone())], true, true, false),
            (vec![("deep_result", too_deep)], true, true, false),
            (
                vec![(NAME, valid.clone()), (NAME, valid.clone())],
                true,
                true,
                false,
            ),
            (vec![], true, true, false),
            (vec![(NAME, valid.clone())], true, false, false),
            (vec![(NAME, valid.clone())], false, true, false),
        ] {
            let active_schema = if tools
                .first()
                .is_some_and(|(name, _)| *name == "deep_result")
            {
                json!({"type":"object","properties":{"nested":{"type":"object"}},"required":["nested"]})
            } else {
                schema()
            };
            let prepared = prepare_structured(
                &model,
                request().to_string().as_bytes(),
                active_schema.to_string().as_bytes(),
            )
            .unwrap();
            let mut rng = StdRng::from_os_rng();
            let exchange = prepared
                .encapsulate(&key_config, "relay-key", &mut rng)
                .unwrap();
            let headers = exchange.outer_headers();
            assert!(!format!("{headers:?}").contains("schema-canary"));
            assert!(
                !exchange
                    .outer_body()
                    .windows(b"private-canary".len())
                    .any(|v| v == b"private-canary")
            );
            let server = ohttp::Server::new(config.clone()).unwrap();
            let mut recipient =
                server.decapsulate_stream(futures::io::Cursor::new(exchange.outer_body().to_vec()));
            let mut bhttp = Vec::new();
            recipient.read_to_end(&mut bhttp).await.unwrap();
            let message =
                bhttp::Message::read_bhttp(&mut std::io::Cursor::new(&bhttp[..])).unwrap();
            let body = message.content();
            assert!(
                !body
                    .windows(b"schema-canary".len())
                    .any(|v| v == b"schema-canary")
            );
            let encrypted: Value = serde_json::from_slice(body).unwrap();
            let tool = &encrypted["tools"][0]["function"];
            assert_eq!(open(tool["name"].as_str().unwrap(), &model_secret), NAME);
            assert_eq!(
                open(tool["description"].as_str().unwrap(), &model_secret),
                "Return structured data only; this is not an action."
            );
            assert_eq!(
                serde_json::from_str::<Value>(&open(
                    tool["parameters"].as_str().unwrap(),
                    &model_secret
                ))
                .unwrap(),
                active_schema
            );
            assert_eq!(
                open(
                    encrypted["tool_choice"]["function"]["name"]
                        .as_str()
                        .unwrap(),
                    &model_secret
                ),
                NAME
            );
            assert_eq!(encrypted["parallel_tool_calls"], false);
            let client_ed: [u8; 32] =
                hex::decode(message.header().get(b"x-client-pub-key").unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
            let client_key = compat::ed25519_public_to_curve25519(&client_ed).unwrap();
            let mut events = Vec::new();
            if tools
                .first()
                .is_some_and(|(name, _)| *name == "text_plus_tool")
            {
                events.extend_from_slice(format!("data: {}\n\n", json!({"choices":[{"index":0,"delta":{"content":seal("untrusted text", &client_key)}}]})).as_bytes());
            }
            for (index, (name, arguments)) in tools.iter().enumerate() {
                let mut argument_text = if *name == "malformed" {
                    "{".to_owned()
                } else {
                    arguments.to_string()
                };
                if *name == "aggregate_bytes" {
                    // Valid small JSON followed by >256 KiB of legal trailing
                    // whitespace. Its parsed/re-serialized value stays small;
                    // only the pre-parse accumulated argument cap can reject it.
                    argument_text.push_str(&" ".repeat(256 * 1024));
                    assert!(argument_text.len() > MAX_RESULT_BYTES);
                    assert!(arguments.to_string().len() < MAX_RESULT_BYTES);
                }
                for (part, bytes) in argument_text.as_bytes().chunks(8000).enumerate() {
                    let named = if *name == "malformed"
                        || *name == "truncated_outer"
                        || *name == "text_plus_tool"
                        || *name == "oversized_nodes"
                        || *name == "aggregate_bytes"
                        || *name == "deep_result"
                    {
                        NAME
                    } else {
                        name
                    };
                    let chunk = json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":index,"id":(part == 0).then(||format!("id{index}")),"type":"function","function":{"name":(part == 0).then(||seal(named, &client_key)),"arguments":seal(std::str::from_utf8(bytes).unwrap(), &client_key)}}]},"finish_reason":null}]});
                    let event = format!("data: {chunk}\n\n");
                    assert!(event.len() < 256 * 1024);
                    events.extend_from_slice(event.as_bytes());
                }
            }
            let reason = if tools.is_empty() {
                "stop"
            } else {
                "tool_calls"
            };
            events.extend_from_slice(format!("data: {{\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"{reason}\"}}]}}\n\n").as_bytes());
            if done {
                events.extend_from_slice(b"data: [DONE]\n\n");
            }
            assert!(events.len() < 8 * 1024 * 1024);
            let hash = bh_crypto::sha256(body);
            let response_hash = bh_crypto::sha256(&events);
            let signed_text = format!(
                "z-ai/glm-5.3-flash:{}:{}",
                hex::encode(hash),
                hex::encode(response_hash)
            );
            let signature = hex::encode(model_sign.sign(signed_text.as_bytes()));
            let signer = hex::encode(model_sign.public());
            let wrong_signer = hex::encode(SigningKey::generate().public());
            let sig = Signature {
                kind: "provider_tee",
                signing_algo: "ed25519",
                signing_address: if good_sig { &signer } else { &wrong_signer },
                signed_text: &signed_text,
                signature: &signature,
            };
            let output = Arc::new(Mutex::new(Vec::new()));
            let mut writer = recipient.response(Sink(output.clone())).unwrap();
            for part in [
                varint(3),
                varint(200),
                varint(12),
                b"content-type".to_vec(),
                varint(17),
                b"text/event-stream".to_vec(),
                varint(0),
                varint(events.len()),
                events,
                varint(0),
                varint(0),
            ] {
                writer.write_all(&part).await.unwrap();
            }
            writer.close().await.unwrap();
            let mut ciphertext = output.lock().unwrap().clone();
            if tools
                .first()
                .is_some_and(|(name, _)| *name == "truncated_outer")
            {
                ciphertext.pop();
                assert!(matches!(
                    exchange.decapsulate(&ciphertext),
                    Err(Error::Route)
                ));
                continue;
            }
            let reply = exchange.decapsulate(&ciphertext).unwrap();
            let result = reply.finish(&sig);
            if success {
                assert_eq!(result.unwrap().value, valid);
            } else if tools.first().is_some_and(|(name, _)| {
                ["oversized_nodes", "aggregate_bytes", "deep_result"].contains(name)
            }) {
                let expected = if tools[0].0 == "aggregate_bytes" {
                    Error::Response
                } else {
                    Error::Limit
                };
                assert_eq!(result.err(), Some(expected), "limit case: {:?}", tools[0].0);
            } else {
                assert!(result.is_err());
            }
        }
    });
}
