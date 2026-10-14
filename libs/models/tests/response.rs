use basehero_models::response::{DecodeError, Delta, Limits, ResponseDecoder};
use serde_json::json;

fn event(value: serde_json::Value) -> String {
    format!("data: {value}\n\n")
}
fn text(value: &str) -> String {
    event(json!({"choices":[{"index":0,"delta":{"content":value},"finish_reason":null}]}))
}
fn end(reason: &str) -> String {
    event(json!({"choices":[{"index":0,"delta":{},"finish_reason":reason}]}))
}
fn decode(
    bytes: &[u8],
    chunk: usize,
) -> Result<basehero_models::response::Completion, DecodeError> {
    let mut d = ResponseDecoder::new(Limits::default());
    for part in bytes.chunks(chunk) {
        d.push(part)?;
    }
    d.finish()
}

#[test]
fn utf8_and_sse_framing_survive_every_chunk_boundary() {
    let wire = format!(
        ": keepalive\n\n{}{}data: [DONE]\n\n",
        text("hello 🌍"),
        end("stop")
    );
    for chunk in 1..=wire.len() {
        assert_eq!(decode(wire.as_bytes(), chunk).unwrap().text, "hello 🌍");
    }
    for ending in ["\r\n", "\r"] {
        assert_eq!(
            decode(wire.replace('\n', ending).as_bytes(), 1)
                .unwrap()
                .text,
            "hello 🌍"
        );
    }
}

#[test]
fn exactly_one_initial_bom_is_framing_not_content() {
    let wire = format!(
        "\u{feff}{}{}{}data: [DONE]\n\n",
        text("first"),
        text("\u{feff}later"),
        end("stop")
    );
    for chunk in 1..=wire.len() {
        let mut d = ResponseDecoder::new(Limits::default());
        let mut streamed = String::new();
        for part in wire.as_bytes().chunks(chunk) {
            for Delta::Text(t) in d.push(part).unwrap() {
                streamed.push_str(&t);
            }
        }
        assert_eq!(streamed, "first\u{feff}later");
        assert_eq!(d.finish().unwrap().text, "first\u{feff}later");
    }
    // A later line's leading BOM is part of its field name, not framing.
    let later = format!(
        "{}\u{feff}{}{}data: [DONE]\n\n",
        text("first"),
        text("ignored"),
        end("stop")
    );
    assert_eq!(decode(later.as_bytes(), 1).unwrap().text, "first");
    // Strip one, not every initial BOM: this remains an unknown SSE field.
    let double = format!(
        "\u{feff}\u{feff}{}{}data: [DONE]\n\n",
        text("ignored"),
        end("stop")
    );
    assert_eq!(decode(double.as_bytes(), 1).unwrap().text, "");
}

#[test]
fn streams_text_but_only_releases_complete_json_tools_at_finish() {
    let mut d = ResponseDecoder::new(Limits::default());
    let deltas = d.push(text("Working").as_bytes()).unwrap();
    assert!(matches!(&deltas[..], [Delta::Text(t)] if t == "Working"));
    let a = event(json!({"choices":[{"index":0,"delta":{"tool_calls":[
        {"index":1,"id":"b","type":"function","function":{"name":"read","arguments":"{\"id\":"}},
        {"index":0,"id":"a","type":"function","function":{"name":"search","arguments":"{\"q\":"}}
    ]}}]}));
    assert!(d.push(a.as_bytes()).unwrap().is_empty());
    let b = event(json!({"choices":[{"index":0,"delta":{"tool_calls":[
        {"index":0,"function":{"arguments":"\"snow\"}"}},
        {"index":1,"function":{"arguments":"1}"}}
    ]}}]}));
    d.push(b.as_bytes()).unwrap();
    d.push(end("tool_calls").as_bytes()).unwrap();
    d.push(b"data: [DONE]\n\n").unwrap();
    let result = d.finish().unwrap();
    assert_eq!(result.tools.len(), 2);
    assert_eq!(result.tools[0].id, "a");
    assert_eq!(result.tools[0].name, "search");
    assert_eq!(result.tools[0].arguments, json!({"q":"snow"}));
    assert_eq!(result.tools[1].arguments, json!({"id":1}));
}

#[test]
fn usage_after_finish_is_preserved_not_required_or_promoted_to_billing() {
    let usage = event(
        json!({"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":7,"prompt_tokens_details":{"cached_tokens":60}}}),
    );
    let wire = format!("{}{}{}data: [DONE]\n\n", text("{}"), end("stop"), usage);
    let result = decode(wire.as_bytes(), 3).unwrap();
    assert_eq!(result.json().unwrap(), json!({}));
    let tokens = result.reported_usage.unwrap();
    assert_eq!((tokens.input, tokens.cached, tokens.output), (100, 60, 7));
    assert!(
        decode(format!("{}data: [DONE]\n\n", end("stop")).as_bytes(), 1)
            .unwrap()
            .reported_usage
            .is_none()
    );
}

#[test]
fn missing_terminal_markers_and_invalid_completions_fail_closed() {
    for wire in [
        text("partial"),
        format!("{}data: [DONE]\n\n", text("partial")),
        end("stop"),
    ] {
        assert_eq!(
            decode(wire.as_bytes(), 1).unwrap_err(),
            DecodeError::Incomplete
        );
    }
    for reason in ["length", "content_filter", "unknown"] {
        assert_eq!(
            decode(format!("{}data: [DONE]\n\n", end(reason)).as_bytes(), 1).unwrap_err(),
            DecodeError::Unusable
        );
    }
    let wire = format!("{}{}data: [DONE]\n\n", text("not JSON"), end("stop"));
    assert_eq!(
        decode(wire.as_bytes(), 1).unwrap().json().unwrap_err(),
        DecodeError::InvalidJson
    );
}

#[test]
fn malformed_provider_data_and_errors_are_content_free_and_poison_decoder() {
    for value in [
        json!({"error":{"message":"PRIVATE_CANARY"}}),
        json!({"choices":[{"index":1,"delta":{"content":"PRIVATE_CANARY"}}]}),
        json!({"choices":[{"index":0,"delta":{"refusal":"PRIVATE_CANARY"}}]}),
    ] {
        let mut d = ResponseDecoder::new(Limits::default());
        let err = d.push(event(value).as_bytes()).unwrap_err();
        assert!(!format!("{err:?} {err}").contains("PRIVATE_CANARY"));
        assert_eq!(d.push(b"data: [DONE]\n\n").unwrap_err(), err);
        assert_eq!(d.finish().unwrap_err(), err);
    }
    assert_eq!(
        decode(b"data: {broken\n\n", 1).unwrap_err(),
        DecodeError::Malformed
    );
    assert_eq!(
        decode(b"data: \xff\n\n", 1).unwrap_err(),
        DecodeError::Malformed
    );
}

#[test]
fn bounds_apply_to_whole_stream_lines_content_and_tool_indexes() {
    let wire = format!("{}{}data: [DONE]\n\n", text("12345"), end("stop"));
    for limits in [
        Limits {
            max_wire_bytes: 5,
            ..Limits::default()
        },
        Limits {
            max_event_bytes: 5,
            ..Limits::default()
        },
        Limits {
            max_content_bytes: 4,
            ..Limits::default()
        },
    ] {
        let mut d = ResponseDecoder::new(limits);
        assert_eq!(d.push(wire.as_bytes()).unwrap_err(), DecodeError::Limit);
    }
    let wire = event(json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":1000000}]}}]}));
    assert_eq!(decode(wire.as_bytes(), 1).unwrap_err(), DecodeError::Limit);
}

#[test]
fn tool_arguments_identity_and_finish_reason_must_agree() {
    for tool in [
        json!({"index":0,"id":"a","function":{"name":"read","arguments":"{"}}),
        json!({"index":0,"function":{"name":"read","arguments":"{}"}}),
        json!({"index":0,"id":"a","function":{"name":"read","arguments":"[]"}}),
    ] {
        let wire = format!(
            "{}{}data: [DONE]\n\n",
            event(json!({"choices":[{"index":0,"delta":{"tool_calls":[tool]}}]})),
            end("tool_calls")
        );
        assert!(decode(wire.as_bytes(), 2).is_err());
    }
    assert!(
        decode(
            format!("{}data: [DONE]\n\n", end("tool_calls")).as_bytes(),
            1
        )
        .is_err()
    );
}

#[test]
fn data_after_finish_or_done_and_invalid_usage_are_rejected() {
    let late = format!("{}{}data: [DONE]\n\n", end("stop"), text("late"));
    assert!(decode(late.as_bytes(), 1).is_err());
    let late = format!("{}data: [DONE]\n\n{}", end("stop"), text("late"));
    assert!(decode(late.as_bytes(), 1).is_err());
    let usage = event(
        json!({"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":2,"prompt_tokens_details":{"cached_tokens":3}}}),
    );
    let complete = format!("{}{}{}data: [DONE]\n\n", text("answer"), end("stop"), usage);
    assert_eq!(
        decode(complete.as_bytes(), 1).unwrap_err(),
        DecodeError::Malformed
    );
}
