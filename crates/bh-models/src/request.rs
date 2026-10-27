use crate::{ModelError, TINFOIL_MODEL, ToolCall};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq)]
pub struct ChatRequest {
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSpec>,
    pub tool_choice: Option<ToolChoice>,
    pub max_tokens: u32,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub role: Role,
    pub content: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub tool_call_id: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}
#[derive(Clone, Debug, PartialEq)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolChoice {
    Auto,
    None,
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
        let mut value = json!({"model":TINFOIL_MODEL,"stream":false,"messages":messages,
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
