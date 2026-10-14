//! Bounded decoding of decrypted chat-completion SSE bodies.
//!
//! This module does not authenticate a provider or its usage. Only pass plaintext
//! here after the transport has authenticated and decrypted it. Tool calls are
//! proposals, never authorization to execute a tool.

use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Malformed,
    Incomplete,
    Unusable,
    Limit,
    InvalidJson,
}
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "model response: {self:?}")
    }
}
impl std::error::Error for DecodeError {}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_wire_bytes: usize,
    pub max_event_bytes: usize,
    pub max_content_bytes: usize,
    pub max_tools: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_wire_bytes: 8 * 1024 * 1024,
            max_event_bytes: 256 * 1024,
            max_content_bytes: 2 * 1024 * 1024,
            max_tools: 32,
        }
    }
}

/// Input tokens include the cached subset, not an additional token category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
pub struct Tokens {
    pub input: u64,
    pub cached: u64,
    pub output: u64,
}
impl Tokens {
    pub fn is_valid(self) -> bool {
        self.cached <= self.input
    }
}

#[derive(PartialEq, Eq)]
pub enum Delta {
    /// Provisional display text. It is not a completed answer.
    Text(String),
}
impl fmt::Debug for Delta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Delta([redacted])")
    }
}

pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}
pub struct Completion {
    pub text: String,
    pub tools: Vec<ToolCall>,
    /// Provider-body observation; NOT an authenticated accounting receipt.
    pub reported_usage: Option<Tokens>,
}
impl fmt::Debug for Completion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Completion([redacted])")
    }
}
impl Completion {
    /// Parse an ordinary structured response. The caller must additionally
    /// validate its requested schema; parsing JSON alone is not schema validation.
    pub fn json(&self) -> Result<Value, DecodeError> {
        if !self.tools.is_empty() {
            return Err(DecodeError::InvalidJson);
        }
        serde_json::from_str(&self.text).map_err(|_| DecodeError::InvalidJson)
    }
}

#[derive(Default)]
struct ToolParts {
    id: String,
    name: String,
    arguments: String,
}

/// One decoder per attempt. Any error poisons it; success requires both a
/// supported finish reason and a complete `[DONE]` event. No partial tool escapes.
pub struct ResponseDecoder {
    limits: Limits,
    wire_bytes: usize,
    content_bytes: usize,
    line: Vec<u8>,
    event: Vec<u8>,
    after_cr: bool,
    first_line: bool,
    done: bool,
    reason: Option<String>,
    error: Option<DecodeError>,
    text: String,
    tools: BTreeMap<usize, ToolParts>,
    usage: Option<Tokens>,
}
impl ResponseDecoder {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            wire_bytes: 0,
            content_bytes: 0,
            line: Vec::new(),
            event: Vec::new(),
            after_cr: false,
            first_line: true,
            done: false,
            reason: None,
            error: None,
            text: String::new(),
            tools: BTreeMap::new(),
            usage: None,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Delta>, DecodeError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let result = self.push_inner(bytes);
        if let Err(error) = result {
            self.error = Some(error);
        }
        result
    }

    fn push_inner(&mut self, bytes: &[u8]) -> Result<Vec<Delta>, DecodeError> {
        self.wire_bytes = self
            .wire_bytes
            .checked_add(bytes.len())
            .ok_or(DecodeError::Limit)?;
        if self.wire_bytes > self.limits.max_wire_bytes {
            return Err(DecodeError::Limit);
        }
        let mut deltas = Vec::new();
        for &byte in bytes {
            if self.after_cr && byte == b'\n' {
                self.after_cr = false;
                continue;
            }
            self.after_cr = byte == b'\r';
            if byte == b'\r' || byte == b'\n' {
                self.consume_line(&mut deltas)?;
            } else {
                if self.line.len() >= self.limits.max_event_bytes {
                    return Err(DecodeError::Limit);
                }
                self.line.push(byte);
            }
        }
        Ok(deltas)
    }

    fn consume_line(&mut self, deltas: &mut Vec<Delta>) -> Result<(), DecodeError> {
        let line = std::mem::take(&mut self.line);
        // SSE permits exactly one BOM at the start of the stream. Waiting for
        // the first complete line also handles a BOM split across input chunks.
        let line = if std::mem::take(&mut self.first_line) {
            line.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&line)
        } else {
            &line
        };
        // Even ignored fields/comments must be valid UTF-8.
        std::str::from_utf8(line).map_err(|_| DecodeError::Malformed)?;
        if line.is_empty() {
            if !self.event.is_empty() {
                let mut event = std::mem::take(&mut self.event);
                event.pop(); // final newline added for SSE multi-line data
                self.consume_event(&event, deltas)?;
            }
        } else if let Some(data) = line.strip_prefix(b"data:") {
            let data = data.strip_prefix(b" ").unwrap_or(data);
            let size = self
                .event
                .len()
                .checked_add(data.len())
                .and_then(|n| n.checked_add(1))
                .ok_or(DecodeError::Limit)?;
            if size > self.limits.max_event_bytes {
                return Err(DecodeError::Limit);
            }
            self.event.extend_from_slice(data);
            self.event.push(b'\n');
        } else if line == b"data" {
            if self.event.len() >= self.limits.max_event_bytes {
                return Err(DecodeError::Limit);
            }
            self.event.push(b'\n');
        }
        Ok(())
    }

    fn consume_event(&mut self, bytes: &[u8], deltas: &mut Vec<Delta>) -> Result<(), DecodeError> {
        if self.done {
            return Err(DecodeError::Malformed);
        }
        if bytes == b"[DONE]" {
            self.done = true;
            return Ok(());
        }
        let chunk: Chunk = serde_json::from_slice(bytes).map_err(|_| DecodeError::Malformed)?;
        if chunk.error.is_some() {
            return Err(DecodeError::Unusable);
        }
        if let Some(usage) = chunk.usage {
            let tokens = Tokens {
                input: usage.prompt_tokens,
                cached: usage.prompt_tokens_details.map_or(0, |d| d.cached_tokens),
                output: usage.completion_tokens,
            };
            if !tokens.is_valid() || self.usage.is_some_and(|old| old != tokens) {
                return Err(DecodeError::Malformed);
            }
            self.usage = Some(tokens);
        }
        if chunk.choices.len() > 1 {
            return Err(DecodeError::Malformed);
        }
        for choice in chunk.choices {
            if choice.index != 0 || self.reason.is_some() {
                return Err(DecodeError::Malformed);
            }
            if choice.delta.refusal.as_ref().is_some_and(|s| !s.is_empty()) {
                return Err(DecodeError::Unusable);
            }
            if let Some(text) = choice.delta.content {
                self.add_content(text.len())?;
                self.text.push_str(&text);
                if !text.is_empty() {
                    deltas.push(Delta::Text(text));
                }
            }
            for part in choice.delta.tool_calls.unwrap_or_default() {
                if part.index >= self.limits.max_tools {
                    return Err(DecodeError::Limit);
                }
                if part.kind.as_deref().is_some_and(|k| k != "function") {
                    return Err(DecodeError::Malformed);
                }
                let func = part.function.unwrap_or_default();
                self.add_content(part.id.as_ref().map_or(0, String::len))?;
                self.add_content(func.name.as_ref().map_or(0, String::len))?;
                self.add_content(func.arguments.as_ref().map_or(0, String::len))?;
                let tool = self.tools.entry(part.index).or_default();
                if let Some(id) = part.id {
                    tool.id.push_str(&id);
                }
                if let Some(name) = func.name {
                    tool.name.push_str(&name);
                }
                if let Some(args) = func.arguments {
                    tool.arguments.push_str(&args);
                }
            }
            if let Some(reason) = choice.finish_reason {
                if reason != "stop" && reason != "tool_calls" {
                    return Err(DecodeError::Unusable);
                }
                self.reason = Some(reason);
            }
        }
        Ok(())
    }

    fn add_content(&mut self, len: usize) -> Result<(), DecodeError> {
        self.content_bytes = self
            .content_bytes
            .checked_add(len)
            .ok_or(DecodeError::Limit)?;
        if self.content_bytes > self.limits.max_content_bytes {
            return Err(DecodeError::Limit);
        }
        Ok(())
    }

    pub fn finish(self) -> Result<Completion, DecodeError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if !self.done || self.reason.is_none() || !self.line.is_empty() || !self.event.is_empty() {
            return Err(DecodeError::Incomplete);
        }
        if (self.reason.as_deref() == Some("tool_calls")) != !self.tools.is_empty() {
            return Err(DecodeError::Malformed);
        }
        let mut tools = Vec::new();
        for (expected, (index, tool)) in self.tools.into_iter().enumerate() {
            if index != expected
                || tool.id.is_empty()
                || tool.name.is_empty()
                || tools.iter().any(|t: &ToolCall| t.id == tool.id)
            {
                return Err(DecodeError::Malformed);
            }
            let arguments: Value =
                serde_json::from_str(&tool.arguments).map_err(|_| DecodeError::InvalidJson)?;
            if !arguments.is_object() {
                return Err(DecodeError::InvalidJson);
            }
            tools.push(ToolCall {
                id: tool.id,
                name: tool.name,
                arguments,
            });
        }
        Ok(Completion {
            text: self.text,
            tools,
            reported_usage: self.usage,
        })
    }
}

#[derive(Deserialize)]
struct Chunk {
    #[serde(default)]
    choices: Vec<Choice>,
    usage: Option<Usage>,
    error: Option<Value>,
}
#[derive(Deserialize)]
struct Choice {
    index: usize,
    #[serde(default)]
    delta: WireDelta,
    finish_reason: Option<String>,
}
#[derive(Default, Deserialize)]
struct WireDelta {
    content: Option<String>,
    refusal: Option<String>,
    tool_calls: Option<Vec<ToolDelta>>,
}
#[derive(Deserialize)]
struct ToolDelta {
    index: usize,
    id: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    function: Option<FunctionDelta>,
}
#[derive(Default, Deserialize)]
struct FunctionDelta {
    name: Option<String>,
    arguments: Option<String>,
}
#[derive(Deserialize)]
struct Usage {
    prompt_tokens: u64,
    completion_tokens: u64,
    prompt_tokens_details: Option<Cached>,
}
#[derive(Deserialize)]
struct Cached {
    #[serde(default)]
    cached_tokens: u64,
}
