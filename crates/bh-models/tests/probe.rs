#![cfg(all(feature = "testing", debug_assertions))]
use bh_models::{testing::*, *};
use serde_json::json;

fn reply(text: Option<&str>, tool_calls: Vec<ToolCall>) -> Scripted {
    Scripted::Reply(Completion {
        text: text.map(Into::into),
        tool_calls,
        finish: Finish::Stop,
        usage: None,
    })
}
fn title(arguments: &str) -> Vec<ToolCall> {
    vec![ToolCall {
        id: "call-1".into(),
        name: "note_title".into(),
        arguments: arguments.into(),
    }]
}

#[tokio::test]
async fn the_probe_asks_for_a_word_then_forces_the_title_tool() {
    let model = ScriptedModel::new(vec![
        reply(Some("ferry"), vec![]),
        reply(None, title(r#"{"title":"Ferry times"}"#)),
    ]);
    let result = probe(model.as_ref()).await.unwrap();
    assert_eq!(
        (result.ok, result.verified, result.text.as_deref()),
        (true, true, Some("ferry"))
    );
    assert_eq!(
        (result.tool.as_str(), &result.tool_args, result.ms.len()),
        ("note_title", &json!({"title":"Ferry times"}), 2)
    );
    let [word, tool] = model.requests().try_into().unwrap();
    assert_eq!(
        word.messages[0].content.as_deref(),
        Some("Reply with exactly the word: ferry")
    );
    assert_eq!((word.max_tokens, tool.max_tokens), (64, 64));
    assert_eq!(
        tool.tool_choice,
        Some(ToolChoice::Function("note_title".into()))
    );
}

#[tokio::test]
async fn the_probe_names_the_step_that_failed() {
    let model = ScriptedModel::new(vec![reply(Some("boat"), vec![])]);
    assert_eq!(
        probe(model.as_ref()).await,
        Err(ProbeFailure {
            step: 1,
            error: ModelError::Response
        })
    );
    let model = ScriptedModel::new(vec![
        reply(Some("ferry"), vec![]),
        Scripted::Fail(ModelError::Verification),
    ]);
    assert_eq!(
        probe(model.as_ref()).await,
        Err(ProbeFailure {
            step: 2,
            error: ModelError::Verification
        })
    );
    let model = ScriptedModel::new(vec![
        reply(Some("ferry"), vec![]),
        reply(None, title(r#"{"title":"Bus times"}"#)),
    ]);
    assert_eq!(probe(model.as_ref()).await.unwrap_err().step, 2);
}
