//! The live probe's two tiny synthetic completions, shared by the example and
//! the app's debug probe. Only the probe's caller sees the content.
use crate::{ChatModel, ChatRequest, Message, ModelError, Role, ToolChoice, ToolSpec};
use serde::Serialize;
use serde_json::{Value, json};
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ProbeResult {
    pub ok: bool,
    /// A Tinfoil model completes only after attestation verification.
    pub verified: bool,
    pub text: Option<String>,
    pub tool: String,
    pub tool_args: Value,
    pub ms: Vec<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeFailure {
    pub step: u8,
    pub error: ModelError,
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

pub async fn probe(model: &dyn ChatModel) -> Result<ProbeResult, ProbeFailure> {
    let fail = |step, error| ProbeFailure { step, error };
    let start = Instant::now();
    let first = model
        .complete(ask("Reply with exactly the word: ferry"))
        .await
        .map_err(|e| fail(1, e))?;
    let ms1 = start.elapsed().as_millis() as u64;
    if first.text.as_deref() != Some("ferry") {
        return Err(fail(1, ModelError::Response));
    }
    let mut tool = ask("Call note_title with the title Ferry times");
    tool.tools.push(ToolSpec { name:"note_title".into(), description:"Provide a note title".into(),
        parameters:json!({"type":"object","properties":{"title":{"type":"string"}},"required":["title"],"additionalProperties":false}) });
    tool.tool_choice = Some(ToolChoice::Function("note_title".into()));
    let start = Instant::now();
    let second = model.complete(tool).await.map_err(|e| fail(2, e))?;
    let ms2 = start.elapsed().as_millis() as u64;
    let [tool] = second.tool_calls.as_slice() else {
        return Err(fail(2, ModelError::Response));
    };
    let tool_args: Value =
        serde_json::from_str(&tool.arguments).map_err(|_| fail(2, ModelError::Response))?;
    if tool.name != "note_title" || tool_args != json!({"title":"Ferry times"}) {
        return Err(fail(2, ModelError::Response));
    }
    Ok(ProbeResult {
        ok: true,
        verified: true,
        text: first.text,
        tool: tool.name.clone(),
        tool_args,
        ms: vec![ms1, ms2],
    })
}
