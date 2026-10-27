use crate::ModelError;
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion {
    pub text: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub finish: Finish,
    pub usage: Option<Usage>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finish {
    Stop,
    ToolCalls,
    Length,
    Other,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage {
    pub prompt: u64,
    pub completion: u64,
}

pub(crate) fn decode(bytes: &[u8]) -> Result<Completion, ModelError> {
    let raw: Value = serde_json::from_slice(bytes).map_err(|_| ModelError::Response)?;
    let choice = raw.pointer("/choices/0").ok_or(ModelError::Response)?;
    let message = choice.get("message").ok_or(ModelError::Response)?;
    if message["role"] != "assistant" {
        return Err(ModelError::Response);
    }
    let text = match message.get("content") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        _ => return Err(ModelError::Response),
    };
    let mut tool_calls = vec![];
    if let Some(calls) = message.get("tool_calls") {
        for call in calls.as_array().ok_or(ModelError::Response)? {
            let string = |path| {
                call.pointer(path)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or(ModelError::Response)
            };
            if call["type"] != "function" {
                return Err(ModelError::Response);
            }
            tool_calls.push(ToolCall {
                id: string("/id")?,
                name: string("/function/name")?,
                arguments: string("/function/arguments")?,
            });
        }
    }
    let finish = match choice["finish_reason"]
        .as_str()
        .ok_or(ModelError::Response)?
    {
        "stop" => Finish::Stop,
        "tool_calls" => Finish::ToolCalls,
        "length" => Finish::Length,
        _ => Finish::Other,
    };
    let usage = match raw.get("usage") {
        None | Some(Value::Null) => None,
        Some(u) => Some(Usage {
            prompt: u["prompt_tokens"].as_u64().ok_or(ModelError::Response)?,
            completion: u["completion_tokens"]
                .as_u64()
                .ok_or(ModelError::Response)?,
        }),
    };
    Ok(Completion {
        text,
        tool_calls,
        finish,
        usage,
    })
}
