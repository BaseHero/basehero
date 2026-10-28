use crate::{ModelError, TINFOIL_MODEL, ToolCall};
use serde::Serialize;
use serde_json::{Value, json};

/// One bounded chat completion request. Messages are sent in conversation
/// order and the maximum output must be between 1 and 32,768 tokens.
#[derive(Clone, Debug, PartialEq)]
pub struct ChatRequest {
    /// Conversation in order.
    pub messages: Vec<Message>,
    /// Tools the model may call.
    pub tools: Vec<ToolSpec>,
    /// Optional constraint on tool calling.
    pub tool_choice: Option<ToolChoice>,
    /// Upper bound on generated tokens.
    pub max_tokens: u32,
}
/// One conversation message, optionally carrying a tool call or result.
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    /// Sender role.
    pub role: Role,
    /// Text, when provided.
    pub content: Option<String>,
    /// Assistant's requested tool calls.
    pub tool_calls: Vec<ToolCall>,
    /// Tool call this message answers, if any.
    pub tool_call_id: Option<String>,
}
/// Sender role serialized in lowercase for model requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// System instructions.
    System,
    /// The person's message.
    User,
    /// Model's reply or tool request.
    Assistant,
    /// Result of a model-requested tool call.
    Tool,
}
/// Callable tool's name, purpose and JSON parameter schema.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolSpec {
    /// Name used in the model's tool call.
    pub name: String,
    /// Description shown to the model.
    pub description: String,
    /// JSON Schema for arguments.
    pub parameters: Value,
}
/// Whether the model may call tools or must call one named function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolChoice {
    /// The model chooses whether to call a tool.
    Auto,
    /// No tools may be called.
    None,
    /// Require a call to the named function.
    Function(String),
}

impl ChatRequest {
    pub(crate) fn encode(&self, cache_secret: &str) -> Result<Vec<u8>, ModelError> {
        if self.messages.is_empty()
            || self.max_tokens == 0
            || self.max_tokens > 32768
            || cache_secret.is_empty()
        {
            return Err(ModelError::InvalidRequest);
        }
        let messages: Vec<_> = self.messages.iter().map(|m| {
            let mut value = json!({"role":m.role,"content":m.content});
            if !m.tool_calls.is_empty() {
                value["tool_calls"] = json!(m.tool_calls.iter().map(|c|
                    json!({"id":c.id,"type":"function","function":{"name":c.name,"arguments":c.arguments}})
                ).collect::<Vec<_>>());
            }
            if let Some(id) = &m.tool_call_id { value["tool_call_id"] = json!(id); }
            value
        }).collect();
        let mut value = json!({"model":TINFOIL_MODEL,"stream":true,
            "stream_options":{"include_usage":true},"messages":messages,
            "max_tokens":self.max_tokens,"user_cache_secret":cache_secret});
        if !self.tools.is_empty() {
            value["tools"] = json!(
                self.tools
                    .iter()
                    .map(|t| json!({"type":"function",
                "function":{"name":t.name,"description":t.description,"parameters":t.parameters}}))
                    .collect::<Vec<_>>()
            );
        }
        if let Some(choice) = &self.tool_choice {
            value["tool_choice"] = match choice {
                ToolChoice::Auto => json!("auto"),
                ToolChoice::None => json!("none"),
                ToolChoice::Function(name) => json!({"type":"function","function":{"name":name}}),
            };
        }
        let bytes = serde_json::to_vec(&value).map_err(|_| ModelError::InvalidRequest)?;
        // EHBP adds a four-byte length and a 16-byte authentication tag.
        if bytes.len() > 1024 * 1024 - 20 {
            return Err(ModelError::InvalidRequest);
        }
        Ok(bytes)
    }
}
