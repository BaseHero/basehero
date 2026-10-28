#![cfg(all(feature = "testing", debug_assertions))]
use bh_models::{testing::*, *};
use serde_json::{Value, json};
use zeroize::Zeroizing;

fn model(e: &TestEnclave) -> Tinfoil {
    Tinfoil::unverified_for_tests(
        Gateway::new(e.url().as_str()).unwrap(),
        Zeroizing::new("device-token".into()),
        e.key_hex(),
    )
}
fn ask(text: &str) -> ChatRequest {
    ChatRequest {
        messages: vec![Message {
            role: Role::User,
            content: Some(text.into()),
            tool_calls: vec![],
            tool_call_id: None,
        }],
        tools: vec![],
        tool_choice: None,
        max_tokens: 64,
    }
}
fn reply() -> Value {
    json!({"choices":[{"message":{"role":"assistant","content":"ferry"},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":9,"completion_tokens":1,"total_tokens":10},"model":"deepseek-v4-1-flash"})
}
#[tokio::test]
async fn a_reply_arrives_whole_and_decrypts() {
    let e = TestEnclave::start();
    e.reply(EnclaveReply::Completion(reply()));
    let c = model(&e)
        .complete(ask("Reply with one word"))
        .await
        .unwrap();
    assert_eq!(c.text.as_deref(), Some("ferry"));
    assert_eq!(c.finish, Finish::Stop);
    assert_eq!(
        c.usage,
        Some(Usage {
            prompt: 9,
            completion: 1
        })
    );
    let seen = &e.requests()[0];
    let p = seen.plaintext.as_ref().unwrap();
    assert_eq!(p["model"], "deepseek-v4-1-flash");
    assert_eq!(p["stream"], true);
    assert_eq!(p["stream_options"]["include_usage"], true);
    assert_eq!(p["user_cache_secret"], "cache-secret-for-tests");
    assert!(!String::from_utf8_lossy(&seen.body).contains("Reply with one word"));
    assert_eq!(seen.headers["authorization"], "Bearer device-token");
    assert_eq!(seen.headers["x-tinfoil-model"], "deepseek-v4-1-flash");
    assert_eq!(seen.headers["bh-protocol"], "1");
    assert_eq!(seen.headers["accept"], "text/event-stream");
}
fn stream(gated: bool, cut: bool) -> EnclaveReply {
    EnclaveReply::Stream {
        events: vec![
            json!({"choices":[{"index":0,"delta":{"role":"assistant","content":"It"}}]}),
            json!({"choices":[{"index":0,"delta":{"content":" leaves"}}]}),
            json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
            json!({"choices":[],"usage":{"prompt_tokens":9,"completion_tokens":2,"total_tokens":11}}),
        ],
        trailer: None,
        gated,
        cut,
        hold_trailer: false,
    }
}
#[tokio::test]
async fn text_arrives_in_pieces_and_the_completion_is_whole() {
    let e = TestEnclave::start();
    e.reply(stream(true, false));
    let m = model(&e);
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let mut call = m.complete_streaming(ask("When does it leave?"), send);
    let deadline = std::time::Duration::from_secs(30);
    // The first piece arrives while the enclave holds back the rest.
    let first = tokio::time::timeout(deadline, async {
        tokio::select! {
            result = &mut call => panic!("the call ended before its first piece: {result:?}"),
            piece = receive.recv() => piece.unwrap(),
        }
    })
    .await
    .unwrap();
    assert_eq!(first, "It");
    e.release();
    let c = call.await.unwrap();
    let mut pieces = vec![first];
    while let Ok(piece) = receive.try_recv() {
        pieces.push(piece);
    }
    assert_eq!(pieces, ["It", " leaves"]);
    assert_eq!(c.text.as_deref(), Some("It leaves"));
    assert_eq!(c.finish, Finish::Stop);
    assert!(c.tool_calls.is_empty());
    assert_eq!(
        c.usage,
        Some(Usage {
            prompt: 9,
            completion: 2
        })
    );
    let seen = &e.requests()[0];
    let p = seen.plaintext.as_ref().unwrap();
    assert_eq!(p["stream"], true);
    assert_eq!(p["stream_options"]["include_usage"], true);
    assert_eq!(seen.headers["accept"], "text/event-stream");
    assert_eq!(seen.headers["x-tinfoil-max-output-tokens"], "64");
}
#[tokio::test]
async fn complete_still_returns_the_whole_reply() {
    let e = TestEnclave::start();
    e.reply(stream(false, false));
    let c = model(&e).complete(ask("When?")).await.unwrap();
    assert_eq!(c.text.as_deref(), Some("It leaves"));
    assert_eq!(c.finish, Finish::Stop);
}
#[tokio::test]
async fn done_finishes_before_the_trailer_or_connection_close() {
    let e = TestEnclave::start();
    let EnclaveReply::Stream {
        events,
        trailer,
        gated,
        cut,
        ..
    } = stream(false, false)
    else {
        unreachable!()
    };
    e.reply(EnclaveReply::Stream {
        events,
        trailer,
        gated,
        cut,
        hold_trailer: true,
    });
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        model(&e).complete(ask("When?")),
    )
    .await;
    // The connection remains open at the trailer gate; waiting for EOF would time out.
    assert_eq!(
        result
            .expect("[DONE] arrives before the trailer")
            .unwrap()
            .text
            .as_deref(),
        Some("It leaves")
    );
    e.release();
}
#[tokio::test]
async fn a_cut_stream_fails() {
    let e = TestEnclave::start();
    e.reply(stream(false, true));
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    assert_eq!(
        model(&e)
            .complete_streaming(ask("When?"), send)
            .await
            .unwrap_err(),
        ModelError::Response
    );
    // The text that arrived was still shown.
    assert_eq!(receive.recv().await.as_deref(), Some("It"));
}
#[tokio::test]
async fn a_whole_reply_is_sent_as_one_piece() {
    let e = TestEnclave::start();
    e.reply(EnclaveReply::Completion(reply()));
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let c = model(&e)
        .complete_streaming(ask("One word"), send)
        .await
        .unwrap();
    assert_eq!(c.text.as_deref(), Some("ferry"));
    assert_eq!(receive.recv().await.as_deref(), Some("ferry"));
    assert!(receive.recv().await.is_none());
}
#[tokio::test]
async fn tool_calls_come_back_with_their_arguments() {
    let e = TestEnclave::start();
    e.reply(EnclaveReply::Completion(json!({"choices":[{"message":{"role":"assistant","content":null,
        "tool_calls":[{"id":"call-1","type":"function","function":{"name":"search","arguments":"{\"text\":\"ferry\"}"}}]},
        "finish_reason":"tool_calls"}]})));
    let mut req = ask("Search");
    req.tools.push(ToolSpec {
        name: "search".into(),
        description: "Find".into(),
        parameters: json!({"type":"object"}),
    });
    req.tool_choice = Some(ToolChoice::Function("search".into()));
    req.messages.push(Message {
        role: Role::Assistant,
        content: None,
        tool_calls: vec![ToolCall {
            id: "old".into(),
            name: "search".into(),
            arguments: "{}".into(),
        }],
        tool_call_id: None,
    });
    req.messages.push(Message {
        role: Role::Tool,
        content: Some("old result".into()),
        tool_calls: vec![],
        tool_call_id: Some("old".into()),
    });
    let c = model(&e).complete(req).await.unwrap();
    assert_eq!(c.finish, Finish::ToolCalls);
    assert_eq!(c.tool_calls[0].name, "search");
    assert_eq!(c.tool_calls[0].arguments, "{\"text\":\"ferry\"}");
    let p = e.requests()[0].plaintext.clone().unwrap();
    assert_eq!(
        p["tool_choice"],
        json!({"type":"function","function":{"name":"search"}})
    );
    assert_eq!(p["tools"][0]["function"]["name"], "search");
    assert_eq!(
        p["messages"][1]["tool_calls"][0]["function"]["arguments"],
        "{}"
    );
    assert_eq!(p["messages"][2]["tool_call_id"], "old");
}
#[tokio::test]
async fn a_key_mismatch_reverifies_once_and_resends_once() {
    for succeeds in [true, false] {
        let e = TestEnclave::start();
        e.reply(EnclaveReply::KeyMismatch);
        e.reply(if succeeds {
            EnclaveReply::Completion(reply())
        } else {
            EnclaveReply::KeyMismatch
        });
        let result = model(&e).complete(ask("ferry")).await;
        if succeeds {
            assert_eq!(result.unwrap().text.as_deref(), Some("ferry"));
        } else {
            assert_eq!(result.unwrap_err(), ModelError::Encryption);
        }
        let seen = e.requests();
        assert_eq!(seen.len(), 2);
        assert_ne!(
            seen[0].headers["ehbp-encapsulated-key"],
            seen[1].headers["ehbp-encapsulated-key"]
        );
    }
}
#[tokio::test]
async fn gateway_statuses_map_to_errors() {
    for (status, error) in [
        (401, ModelError::Unauthorized),
        (403, ModelError::Forbidden),
        (413, ModelError::TooLarge),
        (426, ModelError::NeedsUpdate),
        (429, ModelError::RateLimited),
        (502, ModelError::HttpStatus(502)),
    ] {
        let e = TestEnclave::start();
        e.reply(EnclaveReply::Status(status));
        assert_eq!(model(&e).complete(ask("ferry")).await.unwrap_err(), error);
        assert_eq!(e.requests().len(), 1);
    }
}
#[tokio::test]
async fn redirects_are_not_followed() {
    let e = TestEnclave::start();
    e.reply(EnclaveReply::Redirect("http://127.0.0.1:9/".into()));
    assert_eq!(
        model(&e).complete(ask("ferry")).await.unwrap_err(),
        ModelError::HttpStatus(307)
    );
    assert_eq!(e.requests().len(), 1);
}
#[tokio::test]
async fn a_corrupted_reply_fails_without_revealing_it() {
    let e = TestEnclave::start();
    e.reply(EnclaveReply::Corrupted(reply()));
    let err = model(&e).complete(ask("ferry")).await.unwrap_err();
    assert!(matches!(err, ModelError::Encryption | ModelError::Response));
    assert!(!format!("{err:?}").contains("ferry"));
}
#[test]
fn gateway_urls_are_https_or_loopback_http() {
    for url in [
        "https://dev-api.basehero.com/v1/models/tinfoil/",
        "http://127.0.0.1:8787/v1/models/tinfoil/",
        "http://localhost:8787/",
        "http://[::1]:8787/",
    ] {
        assert!(Gateway::new(url).is_ok(), "{url}");
    }
    for bad in [
        "http://example.com/",
        "https://u:p@x.com/",
        "https://x.com/?q=1",
        "ftp://x.com/",
        "https://x.com/#x",
        "https://x.com:0/",
    ] {
        assert!(Gateway::new(bad).is_err(), "{bad}");
    }
}
#[tokio::test]
async fn requests_over_1_mib_or_without_messages_are_refused() {
    let e = TestEnclave::start();
    let mut empty = ask("x");
    empty.messages.clear();
    for req in [empty, ask(&"x".repeat(1024 * 1024))] {
        assert_eq!(
            model(&e).complete(req).await.unwrap_err(),
            ModelError::InvalidRequest
        );
    }
    assert!(e.requests().is_empty());
}
#[tokio::test]
async fn responses_over_8_mib_and_malformed_messages_are_refused() {
    for value in [
        json!({"choices":[{"message":{"role":"user","content":"private"},"finish_reason":"stop"}]}),
        json!({"choices":[{"message":{"role":"assistant","content":"x".repeat(8*1024*1024)},"finish_reason":"stop"}]}),
    ] {
        let e = TestEnclave::start();
        e.reply(EnclaveReply::Completion(value));
        assert_eq!(
            model(&e).complete(ask("x")).await.unwrap_err(),
            ModelError::Response
        );
    }
}
#[tokio::test]
async fn dropping_a_hung_call_does_not_block_the_next_completion() {
    let e = TestEnclave::start();
    let m = model(&e);
    e.reply(EnclaveReply::Hang);
    let mut hung = m.complete(ask("cancel me"));
    while e.requests().is_empty() {
        tokio::select! {
            result = &mut hung => panic!("hung call unexpectedly completed: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }
    }
    drop(hung);
    e.reply(EnclaveReply::Completion(reply()));
    assert_eq!(
        m.complete(ask("next")).await.unwrap().text.as_deref(),
        Some("ferry")
    );
    assert_eq!(e.requests().len(), 2);
}

#[tokio::test]
async fn a_hung_call_times_out_without_retrying() {
    let e = TestEnclave::start();
    let m = model(&e);
    e.reply(EnclaveReply::Hang);
    let mut hung = m.complete(ask("timeout"));
    while e.requests().is_empty() {
        tokio::select! {
            result = &mut hung => panic!("hung call unexpectedly completed: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }
    }
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(120)).await;
    assert_eq!(hung.await.unwrap_err(), ModelError::Transport);
    assert_eq!(e.requests().len(), 1);
}

#[tokio::test]
async fn scripted_model_records_requests_and_returns_in_order() {
    let m = ScriptedModel::new(vec![
        Scripted::Reply(Completion {
            text: Some("first".into()),
            tool_calls: vec![],
            finish: Finish::Stop,
            usage: None,
        }),
        Scripted::Fail(ModelError::Forbidden),
        Scripted::Hang,
    ]);
    assert_eq!(
        m.complete(ask("one")).await.unwrap().text.as_deref(),
        Some("first")
    );
    assert_eq!(
        m.complete(ask("two")).await.unwrap_err(),
        ModelError::Forbidden
    );
    let mut pending = m.complete(ask("three"));
    assert!(futures_util::poll!(&mut pending).is_pending());
    drop(pending);
    assert_eq!(m.requests().len(), 3);
}

#[tokio::test]
async fn a_scripted_stream_sends_text_as_it_is_pushed() {
    let whole = Completion {
        text: Some("It leaves".into()),
        tool_calls: vec![],
        finish: Finish::Stop,
        usage: None,
    };
    let (script, control) = StreamScript::new();
    let (dropped, _) = StreamScript::new();
    let m = ScriptedModel::new(vec![
        Scripted::Stream(script),
        Scripted::Reply(whole.clone()),
        Scripted::Stream(dropped),
    ]);
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let mut call = m.complete_streaming(ask("one"), send);
    control.text("It");
    assert!(futures_util::poll!(&mut call).is_pending());
    assert_eq!(receive.try_recv().unwrap(), "It");
    control.text(" leaves");
    control.finish(whole.clone());
    assert_eq!(call.await.unwrap(), whole);
    assert_eq!(receive.try_recv().unwrap(), " leaves");

    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    assert_eq!(m.complete_streaming(ask("two"), send).await.unwrap(), whole);
    assert_eq!(receive.try_recv().unwrap(), "It leaves");

    let mut hung = m.complete(ask("three"));
    assert!(futures_util::poll!(&mut hung).is_pending());
}
