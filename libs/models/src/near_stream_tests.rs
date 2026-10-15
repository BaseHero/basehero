use super::*;
use serde_json::{Value, json};
use std::collections::HashMap;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../tests/fixtures/near_sdk_v2.json")).unwrap()
}
fn mapping(wire: &[u8], fixture: &Value) -> HashMap<String, String> {
    fn walk(cipher: &Value, plain: &Value, map: &mut HashMap<String, String>) {
        match (cipher, plain) {
            (Value::String(c), Value::String(p)) if c != p => {
                map.insert(c.to_owned(), p.to_owned());
            }
            (Value::Array(c), Value::Array(p)) => {
                for (c, p) in c.iter().zip(p) {
                    walk(c, p, map);
                }
            }
            (Value::Object(c), Value::Object(p)) => {
                for (k, c) in c {
                    if let Some(p) = p.get(k) {
                        walk(c, p, map);
                    }
                }
            }
            _ => {}
        }
    }
    let source = std::str::from_utf8(wire).unwrap();
    let mut map = HashMap::new();
    for (index, line) in source
        .lines()
        .filter(|s| s.starts_with("data: {"))
        .enumerate()
    {
        let value: Value = serde_json::from_str(line.strip_prefix("data: ").unwrap()).unwrap();
        walk(&value, &fixture["response_plain"][index], &mut map);
    }
    map
}
fn signed(fixture: &Value) -> Signature<'_> {
    let sig = &fixture["signature"];
    Signature {
        kind: sig["signature_kind"].as_str().unwrap(),
        signing_algo: sig["signing_algo"].as_str().unwrap(),
        signing_address: sig["signing_address"].as_str().unwrap(),
        signed_text: sig["text"].as_str().unwrap(),
        signature: sig["signature"].as_str().unwrap(),
    }
}
fn setup() -> (
    Vec<u8>,
    Vec<u8>,
    VerifiedModelKey,
    Value,
    HashMap<String, String>,
) {
    let fixture = fixture();
    let request = hex::decode(fixture["request_wire_hex"].as_str().unwrap()).unwrap();
    let wire = hex::decode(fixture["response_wire_hex"].as_str().unwrap()).unwrap();
    let key = VerifiedModelKey::for_tests(
        hex::decode(fixture["model_public_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let map = mapping(&wire, &fixture);
    (request, wire, key, fixture, map)
}
#[test]
fn sdk_010_fragmented_sse_is_provisional_until_exact_wire_signature() {
    let (request, wire, key, fixture, map) = setup();
    let mut stream = Stream::new(
        move |cipher| map.get(cipher).cloned().ok_or(Error::Field),
        Limits::default(),
    );
    let mut displayed = String::new();
    for fragment in wire.chunks(1) {
        for delta in stream.push(fragment).unwrap() {
            let Delta::Text(s) = delta;
            displayed.push_str(&s);
        }
    }
    assert_eq!(displayed, "hé🪐");
    // No completion or tools can be obtained from the provisional deltas.
    let completion = stream.finish(&key, &request, &signed(&fixture)).unwrap();
    assert_eq!(completion.text, "hé🪐");
    assert_eq!(completion.tools.len(), 1);
    assert_eq!(completion.tools[0].name, "lookup");
    assert_eq!(completion.tools[0].arguments, json!({"q":"東京"}));
}
#[test]
fn truncation_tamper_missing_done_and_signature_reject_completion() {
    let (request, wire, key, fixture, map) = setup();
    let end = wire.windows(12).position(|w| w == b"data: [DONE]").unwrap();
    for fragment in [&wire[..end], &wire[..wire.len() - 1], wire.as_slice()] {
        let map = map.clone();
        let mut stream = Stream::new(
            move |cipher| map.get(cipher).cloned().ok_or(Error::Field),
            Limits::default(),
        );
        stream.push(fragment).unwrap();
        if fragment.len() == wire.len() {
            let mut changed = request.clone();
            changed.push(b' ');
            assert!(matches!(
                stream.finish(&key, &changed, &signed(&fixture)),
                Err(Error::Signature)
            ));
        } else {
            assert!(matches!(
                stream.finish(&key, &request, &signed(&fixture)),
                Err(Error::Frame | Error::Signature)
            ));
        }
    }
    let mut changed = wire.clone();
    changed[0] ^= 1;
    let mut stream = Stream::new(
        move |cipher| map.get(cipher).cloned().ok_or(Error::Field),
        Limits::default(),
    );
    stream.push(&changed).unwrap();
    assert!(matches!(
        stream.finish(&key, &request, &signed(&fixture)),
        Err(Error::Signature)
    ));
}
#[test]
fn nullable_optional_fields_do_not_permit_malformed_nonnull_values_or_bad_ciphertext() {
    for invalid in [
        json!({"choices":[{"delta":{"audio":42}}]}),
        json!({"choices":[{"delta":{"tool_calls":{}}}]}),
        json!({"choices":[{"delta":{"function_call":[]}}]}),
        json!({"choices":[{"delta":{"nearai_tool_result":true}}]}),
        json!({"choices":[{"delta":{"tool_calls":[{"function":12}]}}]}),
        json!({"choices":[{"delta":{},"logprobs":false}]}),
        json!({"choices":[{"delta":{},"logprobs":{"content":{}}}]}),
        json!({"choices":[{"delta":{},"logprobs":{"content":[{"top_logprobs":{}}]}}]}),
    ] {
        let mut invalid = invalid;
        assert_eq!(
            decrypt_event(&mut invalid, &mut |s| Ok(s.to_owned())),
            Err(Error::Frame)
        );
    }
    let mut invalid_bytes =
        json!({"choices":[{"delta":{},"logprobs":{"content":[{"bytes":123}]}}]});
    assert_eq!(
        decrypt_event(&mut invalid_bytes, &mut |s| Ok(s.to_owned())),
        Err(Error::Field)
    );
    let mut bad_ciphertext = json!({"choices":[{"delta":{"audio":{"data":"malformed"}}}]});
    assert_eq!(
        decrypt_event(&mut bad_ciphertext, &mut |_| Err(Error::Field)),
        Err(Error::Field)
    );
    let mut absent = json!({"choices":[{"delta":{"audio":null,"function_call":null,"tool_calls":[{"function":null}],"nearai_tool_result":null},"logprobs":{"content":[null,{"bytes":null,"top_logprobs":null}],"refusal":null}}]});
    assert_eq!(
        decrypt_event(&mut absent, &mut |_| Err(Error::Field)),
        Ok(())
    );
}

#[test]
fn poisoned_state_and_encrypted_event_limits() {
    let mut done = Stream::new(|s| Ok(s.to_owned()), Limits::default());
    done.push(b"data: [DONE]\n\n").unwrap();
    assert!(matches!(done.push(b"data: [DONE]\n\n"), Err(Error::Frame)));
    assert!(matches!(done.push(b""), Err(Error::Frame)));
    let mut stream = Stream::new(|_| Err(Error::Field), Limits::default());
    assert!(matches!(
        stream.push(b"data: {\"choices\":[{\"delta\":{\"content\":\"invalid\"}}]}\n\n"),
        Err(Error::Field)
    ));
    assert!(matches!(
        stream.push(b"data: [DONE]\n\n"),
        Err(Error::Frame)
    ));
    let mut stream = Stream::new(|s| Ok(s.to_owned()), Limits::default());
    assert!(matches!(
        stream.push(&vec![b'a'; MAX_ENCRYPTED_EVENT + 1]),
        Err(Error::Limit)
    ));
    assert!(matches!(
        stream.push(b"data: [DONE]\n\n"),
        Err(Error::Frame)
    ));
}
