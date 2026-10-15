use super::*;
use serde_json::{Value, json};

#[test]
fn prepared_inner_request_reaches_pinned_gateway_server_opaque_and_returns_verified_completion() {
    use futures::io::{AsyncReadExt, AsyncWriteExt};
    use ohttp::hpke::{Aead, Kdf, Kem};
    use rand::{SeedableRng, rngs::StdRng};
    fn varint(n: usize) -> Vec<u8> {
        if n < 64 {
            vec![n as u8]
        } else {
            ((n as u16) | 0x4000).to_be_bytes().to_vec()
        }
    }
    futures::executor::block_on(async {
        let config = ohttp::KeyConfig::new(
            1,
            Kem::X25519Sha256,
            vec![ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm)],
        )
        .unwrap();
        let raw = config.encode().unwrap();
        let signing = SigningKey::generate();
        let signer = near_route::GatewaySigner::for_tests(signing.public());
        let key_config = near_route::verify_key_config(&raw, &signing.sign(&raw), &signer).unwrap();
        let server = ohttp::Server::new(config).unwrap();
        let model_sign = SigningKey::generate();
        let model = VerifiedModelKey::for_tests(model_sign.public());
        let input = json!({"model":"z-ai/glm-5.3-flash","stream":true,"messages":[{"role":"user","content":"private 🪐"}],"tools":[{"type":"function","function":{"name":"lookup","description":"secret","parameters":{"type":"object","properties":{"q":{"type":"string","description":"secret"}}}}}]}).to_string();
        let mut rng = StdRng::from_os_rng();
        let prepared = prepare(&model, input.as_bytes()).unwrap();
        let exchange = prepared
            .encapsulate(&key_config, "relay-key", &mut rng)
            .unwrap();
        assert_eq!(exchange.outer_headers().len(), 3);
        assert!(
            !exchange
                .outer_body()
                .windows(7)
                .any(|part| part == b"private")
        );
        let mut recipient =
            server.decapsulate_stream(futures::io::Cursor::new(exchange.outer_body().to_vec()));
        let mut bhttp = Vec::new();
        recipient.read_to_end(&mut bhttp).await.unwrap();
        let message = bhttp::Message::read_bhttp(&mut std::io::Cursor::new(&bhttp[..])).unwrap();
        assert_eq!(message.control().path(), Some(&b"/v1/chat/completions"[..]));
        for (name, value) in [
            (&b"x-signing-algo"[..], &b"ed25519"[..]),
            (b"x-encryption-version", b"2"),
            (b"x-no-aliasing", b"true"),
            (b"x-encrypt-all-fields", b"true"),
        ] {
            assert_eq!(message.header().get(name), Some(value));
        }
        assert!(message.header().get(b"authorization").is_none());
        assert!(message.header().get(b"content-length").is_none());
        let body = message.content();
        assert!(!body.windows(7).any(|part| part == b"private"));
        let value: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(
            decrypt(
                value["messages"][0]["content"].as_str().unwrap(),
                &compat::ed25519_secret_to_curve25519(&model_sign).unwrap()
            )
            .unwrap(),
            "private 🪐"
        );
        let client_ed: [u8; 32] = hex::decode(message.header().get(b"x-client-pub-key").unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let client_curve = compat::ed25519_public_to_curve25519(&client_ed).unwrap();
        let content = encrypt("hello 🪐", &client_curve).unwrap();
        let response = format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{content}\"}},\"finish_reason\":\"stop\"}}]}}\r\n\r\ndata: [DONE]\r\n\r\n"
        );
        let collector = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl futures::io::AsyncWrite for Shared {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                self.0.lock().unwrap().extend_from_slice(buf);
                std::task::Poll::Ready(Ok(buf.len()))
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
        let mut writer = recipient.response(Shared(collector.clone())).unwrap();
        for bytes in [
            varint(3),
            varint(200),
            varint(12),
            b"content-type".to_vec(),
            varint(17),
            b"text/event-stream".to_vec(),
            varint(0),
            varint(response.len()),
            response.as_bytes().to_vec(),
            varint(0),
            varint(0),
        ] {
            writer.write_all(&bytes).await.unwrap();
        }
        writer.close().await.unwrap();
        let ciphertext = collector.lock().unwrap().clone();
        let mut opened = exchange.decapsulate(&ciphertext).unwrap();
        let mut provisional = String::new();
        while let Some(deltas) = opened.next_provisional().unwrap() {
            for Delta::Text(t) in deltas {
                provisional.push_str(&t);
            }
        }
        assert_eq!(provisional, "hello 🪐");
        let request_hash = bh_crypto::sha256(body);
        let response_hash = bh_crypto::sha256(response.as_bytes());
        let text = format!(
            "z-ai/glm-5.3-flash:{}:{}",
            hex::encode(request_hash),
            hex::encode(response_hash)
        );
        let signature = hex::encode(model_sign.sign(text.as_bytes()));
        let signer = hex::encode(model_sign.public());
        let sig = Signature {
            kind: "provider_tee",
            signing_algo: "ed25519",
            signing_address: &signer,
            signed_text: &text,
            signature: &signature,
        };
        let completion = opened.finish(&sig).unwrap();
        assert_eq!(completion.text, "hello 🪐");
    });
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("../tests/fixtures/near_sdk_v2.json")).unwrap()
}
fn client(seed: &str) -> Secret<32> {
    let raw = hex::decode(seed).unwrap();
    compat::ed25519_secret_to_curve25519(&SigningKey::from_seed(&Secret::from_slice(&raw).unwrap()))
        .unwrap()
}
#[test]
fn decrypt_python_sdk_v2_fields_and_unicode() {
    let f = fixture();
    let model_key = client(f["model_seed_hex"].as_str().unwrap());
    let encrypted = &f["request_encrypted"];
    let plain = &f["request_plain"];
    for pointer in [
        "/messages/0/content",
        "/messages/2/content",
        "/messages/2/reasoning",
        "/messages/2/reasoning_content",
        "/messages/2/refusal",
        "/messages/2/audio/data",
        "/messages/2/tool_calls/0/function/name",
        "/messages/2/tool_calls/0/function/arguments",
        "/messages/2/function_call/name",
        "/messages/2/function_call/arguments",
        "/messages/3/content",
        "/tools/0/function/name",
        "/tools/0/function/description",
        "/tool_choice/function/name",
        "/function_call/name",
    ] {
        assert_eq!(
            decrypt(
                encrypted.pointer(pointer).unwrap().as_str().unwrap(),
                &model_key
            )
            .unwrap(),
            plain.pointer(pointer).unwrap().as_str().unwrap(),
            "{pointer}"
        );
    }
    for pointer in ["/messages/1/content", "/tools/0/function/parameters"] {
        let opened = decrypt(
            encrypted.pointer(pointer).unwrap().as_str().unwrap(),
            &model_key,
        )
        .unwrap();
        let value: Value = serde_json::from_str(&opened).unwrap();
        assert_eq!(value, *plain.pointer(pointer).unwrap(), "{pointer}");
    }
    assert!(decrypt("00", &model_key).is_err());
    let mut changed = encrypted["messages"][0]["content"]
        .as_str()
        .unwrap()
        .to_owned();
    changed.replace_range(120..122, "aa");
    assert!(decrypt(&changed, &model_key).is_err());
    assert!(decrypt(&"00".repeat(32), &model_key).is_err());
}
#[test]
fn encrypt_rust_fields_to_sdk_model_key_and_fresh_response_keys() {
    let f = fixture();
    let key = VerifiedModelKey::for_tests(
        hex::decode(f["model_public_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let input = serde_json::to_vec(&f["request_plain"]).unwrap();
    let first = prepare(&key, &input).unwrap();
    let second = prepare(&key, &input).unwrap();
    assert_ne!(first.response_public, second.response_public);
    assert_ne!(first.body, second.body);
    let recipient = client(f["model_seed_hex"].as_str().unwrap());
    let encrypted: Value = serde_json::from_slice(&first.body).unwrap();
    assert_eq!(encrypted["model"], "z-ai/glm-5.3-flash");
    let content = encrypted["messages"][1]["content"].as_str().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&decrypt(content, &recipient).unwrap()).unwrap(),
        f["request_plain"]["messages"][1]["content"]
    );
    assert_eq!(
        decrypt(
            encrypted["messages"][2]["reasoning_content"]
                .as_str()
                .unwrap(),
            &recipient
        )
        .unwrap(),
        "a thought"
    );
    assert_eq!(
        decrypt(
            encrypted["tools"][0]["function"]["parameters"]
                .as_str()
                .unwrap(),
            &recipient
        )
        .map(|s| serde_json::from_str::<Value>(&s).unwrap())
        .unwrap(),
        f["request_plain"]["tools"][0]["function"]["parameters"]
    );
    if let Ok(path) = std::env::var("NEAR4_WRITE_VECTOR") {
        // Optional explicit offline interop artifact for the SDK's independent
        // recipient; never written in ordinary test runs or shipped in product.
        let client_ed: [u8; 32] = hex::decode(f["client_public_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let response_field = encrypt(
            "hello 🪐",
            &compat::ed25519_public_to_curve25519(&client_ed).unwrap(),
        )
        .unwrap();
        let model_seed = hex::decode(f["model_seed_hex"].as_str().unwrap()).unwrap();
        let model_sign = SigningKey::from_seed(&Secret::from_slice(&model_seed).unwrap());
        let reply_recipient = compat::ed25519_public_to_curve25519(&first.response_public).unwrap();
        let reply_field = encrypt("hello 🪐", &reply_recipient).unwrap();
        assert_eq!(
            decrypt(&reply_field, &first.response_key).unwrap(),
            "hello 🪐"
        );
        let reply_wire = format!("data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{reply_field}\"}},\"finish_reason\":\"stop\"}}]}}\r\n\r\ndata: [DONE]\r\n\r\n").into_bytes();
        let signed_text = format!(
            "z-ai/glm-5.3-flash:{}:{}",
            hex::encode(bh_crypto::sha256(&first.body)),
            hex::encode(bh_crypto::sha256(&reply_wire))
        );
        let rust_signature = json!({ "signature_kind":"provider_tee", "signing_algo":"ed25519", "signing_address":hex::encode(model_sign.public()), "text":signed_text, "signature":hex::encode(model_sign.sign(signed_text.as_bytes())) });
        let record = json!({ "model_seed_hex":f["model_seed_hex"], "client_seed_hex":f["client_seed_hex"], "encrypted_request":encrypted, "request_wire_hex":hex::encode(&first.body), "response_wire_hex":hex::encode(&reply_wire), "rust_signature":rust_signature, "client_public_hex":hex::encode(first.response_public), "rust_response_field":response_field });
        std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
    }
    let wrong = Secret::<32>::random();
    assert!(decrypt(content, &wrong).is_err());
    for invalid in [
        json!({"model":"different","stream":true,"messages":[{"role":"user","content":"secret"}]}),
        json!({"model":"z-ai/glm-5.3-flash","stream":true,"messages":[{"role":"user","content":"secret"}],"stop":"private"}),
        json!({"model":"z-ai/glm-5.3-flash","stream":true,"messages":[{"role":"user","content":"secret"}],"response_format":{"type":"json_schema","json_schema":{"name":"private","schema":{"type":"object"}}}}),
    ] {
        assert!(matches!(
            prepare(&key, invalid.to_string().as_bytes()),
            Err(Error::Request)
        ));
    }
}
#[test]
fn buffered_reply_refuses_repeat_eof_and_completion_after_reuse() {
    let f = fixture();
    let body = hex::decode(f["response_wire_hex"].as_str().unwrap()).unwrap();
    let request = hex::decode(f["request_wire_hex"].as_str().unwrap()).unwrap();
    let model = VerifiedModelKey::for_tests(
        hex::decode(f["model_public_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let client_key = client(f["client_seed_hex"].as_str().unwrap());
    let stream = Stream::new(
        Box::new(move |field: &str| {
            decrypt(field, &client_key).map_err(|_| near_stream::Error::Field)
        }) as super::FieldOpener,
        Limits::default(),
    );
    let mut reply = BufferedReply {
        model: &model,
        request,
        body,
        offset: 0,
        exhausted: false,
        failed: false,
        stream,
    };
    while reply.next_provisional().unwrap().is_some() {}
    assert!(matches!(reply.next_provisional(), Err(Error::Response)));
    let sig = &f["signature"];
    let signature = Signature {
        kind: sig["signature_kind"].as_str().unwrap(),
        signing_algo: sig["signing_algo"].as_str().unwrap(),
        signing_address: sig["signing_address"].as_str().unwrap(),
        signed_text: sig["text"].as_str().unwrap(),
        signature: sig["signature"].as_str().unwrap(),
    };
    assert!(matches!(reply.finish(&signature), Err(Error::Response)));
}
#[test]
fn sdk_nullable_text_and_tool_streams_finish_with_exact_wire_signature() {
    for source in [
        include_str!("../tests/fixtures/near_sdk_v2_nullable_text.json"),
        include_str!("../tests/fixtures/near_sdk_v2_nullable_tool.json"),
    ] {
        let fixture: Value = serde_json::from_str(source).unwrap();
        let request = hex::decode(fixture["request_wire_hex"].as_str().unwrap()).unwrap();
        let wire = hex::decode(fixture["response_wire_hex"].as_str().unwrap()).unwrap();
        let model = VerifiedModelKey::for_tests(
            hex::decode(fixture["model_public_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let client_key = client(fixture["client_seed_hex"].as_str().unwrap());
        let mut stream = Stream::new(
            Box::new(move |field: &str| {
                decrypt(field, &client_key).map_err(|_| near_stream::Error::Field)
            }) as super::FieldOpener,
            Limits::default(),
        );
        let mut provisional = String::new();
        for fragment in wire.chunks(7) {
            for Delta::Text(text) in stream.push(fragment).unwrap() {
                provisional.push_str(&text);
            }
        }
        let signature = &fixture["signature"];
        let sig = Signature {
            kind: signature["signature_kind"].as_str().unwrap(),
            signing_algo: signature["signing_algo"].as_str().unwrap(),
            signing_address: signature["signing_address"].as_str().unwrap(),
            signed_text: signature["text"].as_str().unwrap(),
            signature: signature["signature"].as_str().unwrap(),
        };
        let completed = stream.finish(&model, &request, &sig).unwrap();
        assert_eq!(provisional, fixture["expected_text"].as_str().unwrap());
        assert_eq!(completed.text, provisional);
        if fixture["expected_tool"].is_null() {
            assert!(completed.tools.is_empty());
        } else {
            assert_eq!(completed.tools.len(), 1);
            assert_eq!(completed.tools[0].name, fixture["expected_tool"]["name"]);
            assert_eq!(
                completed.tools[0].arguments,
                fixture["expected_tool"]["arguments"]
            );
        }
    }
}

#[test]
fn sdk_encrypted_sse_needs_done_and_real_signature() {
    let f = fixture();
    let request = hex::decode(f["request_wire_hex"].as_str().unwrap()).unwrap();
    let wire = hex::decode(f["response_wire_hex"].as_str().unwrap()).unwrap();
    let model = VerifiedModelKey::for_tests(
        hex::decode(f["model_public_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let client_key = client(f["client_seed_hex"].as_str().unwrap());
    let mut stream = Stream::new(
        Box::new(move |field: &str| {
            decrypt(field, &client_key).map_err(|_| near_stream::Error::Field)
        }) as Box<dyn FnMut(&str) -> Result<String, near_stream::Error>>,
        Limits::default(),
    );
    let mut displayed = String::new();
    for chunk in wire.chunks(3) {
        for delta in stream.push(chunk).unwrap() {
            let Delta::Text(text) = delta;
            displayed.push_str(&text);
        }
    }
    assert_eq!(displayed, "hé🪐");
    let signature = &f["signature"];
    let sig = Signature {
        kind: signature["signature_kind"].as_str().unwrap(),
        signing_algo: signature["signing_algo"].as_str().unwrap(),
        signing_address: signature["signing_address"].as_str().unwrap(),
        signed_text: signature["text"].as_str().unwrap(),
        signature: signature["signature"].as_str().unwrap(),
    };
    let completion = stream.finish(&model, &request, &sig).unwrap();
    assert_eq!(completion.tools[0].arguments, json!({"q":"東京"}));
    let mut bad = wire;
    bad[85] ^= 1;
    let client = client(f["client_seed_hex"].as_str().unwrap());
    let mut stream = Stream::new(
        Box::new(move |field: &str| decrypt(field, &client).map_err(|_| near_stream::Error::Field))
            as Box<dyn FnMut(&str) -> Result<String, near_stream::Error>>,
        Limits::default(),
    );
    assert!(stream.push(&bad).is_err() || stream.finish(&model, &request, &sig).is_err());
}
