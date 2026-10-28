//! Bounded decoding of a decrypted chat-completion event stream. A stream is
//! finished only by a finish reason and then `data: [DONE]`.
use crate::{Completion, Finish, ModelError, ToolCall, Usage};
use serde::Deserialize;
use std::collections::BTreeMap;

const MAX_TOTAL: usize = 8 * 1024 * 1024;
const MAX_EVENT: usize = 1024 * 1024;
const MAX_TOOLS: usize = 16;
const MAX_ARGUMENTS: usize = 64 * 1024;

/// Any error poisons the decoder, so a broken stream never finishes.
pub(crate) struct Decoder {
    total: usize,
    line: Vec<u8>,
    event: Vec<u8>,
    failed: bool,
    done: bool,
    text: String,
    tools: BTreeMap<usize, ToolCall>,
    finish: Option<Finish>,
    usage: Option<Usage>,
}

impl Decoder {
    pub(crate) fn new() -> Self {
        Self {
            total: 0,
            line: Vec::new(),
            event: Vec::new(),
            failed: false,
            done: false,
            text: String::new(),
            tools: BTreeMap::new(),
            finish: None,
            usage: None,
        }
    }

    /// Reads more of the stream and returns the reply text it completes.
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<Vec<String>, ModelError> {
        if self.failed {
            return Err(ModelError::Response);
        }
        let result = self.read(bytes);
        self.failed = result.is_err();
        result
    }

    pub(crate) fn done(&self) -> bool {
        self.done
    }

    /// Ends the stream; one without a finish reason and `[DONE]` is an error.
    pub(crate) fn finish(self) -> Result<Completion, ModelError> {
        if self.failed || !self.done {
            return Err(ModelError::Response);
        }
        let finish = self.finish.ok_or(ModelError::Response)?;
        let tool_calls: Vec<_> = self.tools.into_values().collect();
        if tool_calls
            .iter()
            .any(|c| c.id.is_empty() || c.name.is_empty())
        {
            return Err(ModelError::Response);
        }
        Ok(Completion {
            text: Some(self.text).filter(|t| !t.is_empty()),
            tool_calls,
            finish,
            usage: self.usage,
        })
    }

    fn read(&mut self, bytes: &[u8]) -> Result<Vec<String>, ModelError> {
        self.total += bytes.len();
        if self.total > MAX_TOTAL {
            return Err(ModelError::Response);
        }
        let mut text = Vec::new();
        for piece in bytes.split_inclusive(|&b| b == b'\n') {
            if self.done {
                return Err(ModelError::Response);
            }
            let (part, ended) = match piece.strip_suffix(b"\n") {
                Some(part) => (part, true),
                None => (piece, false),
            };
            if self.line.len() + part.len() > MAX_EVENT {
                return Err(ModelError::Response);
            }
            self.line.extend_from_slice(part);
            if ended {
                let line = std::mem::take(&mut self.line);
                self.read_line(line.strip_suffix(b"\r").unwrap_or(&line), &mut text)?;
            }
        }
        Ok(text)
    }

    /// Keeps `data:` fields; other fields and comments are ignored.
    fn read_line(&mut self, line: &[u8], text: &mut Vec<String>) -> Result<(), ModelError> {
        if line.is_empty() {
            let mut event = std::mem::take(&mut self.event);
            if event.pop().is_some() && !event.is_empty() {
                self.read_event(&event, text)?;
            }
        } else if let Some(data) = line.strip_prefix(b"data:") {
            let data = data.strip_prefix(b" ").unwrap_or(data);
            if self.event.len() + data.len() + 1 > MAX_EVENT {
                return Err(ModelError::Response);
            }
            self.event.extend_from_slice(data);
            self.event.push(b'\n');
        }
        Ok(())
    }

    fn read_event(&mut self, data: &[u8], text: &mut Vec<String>) -> Result<(), ModelError> {
        // Nothing follows `[DONE]`.
        if self.done {
            return Err(ModelError::Response);
        }
        if data == b"[DONE]" {
            self.done = true;
            return Ok(());
        }
        let chunk: Chunk = serde_json::from_slice(data).map_err(|_| ModelError::Response)?;
        if chunk.error.is_some() {
            return Err(ModelError::Response);
        }
        if let Some(usage) = chunk.usage {
            self.usage = Some(Usage {
                prompt: usage.prompt_tokens,
                completion: usage.completion_tokens,
            });
        }
        let Some(choice) = chunk.choices.into_iter().next() else {
            return Ok(());
        };
        if let Some(content) = choice.delta.content.filter(|c| !c.is_empty()) {
            self.text.push_str(&content);
            text.push(content);
        }
        for part in choice.delta.tool_calls.unwrap_or_default() {
            if part.index >= MAX_TOOLS || part.kind.is_some_and(|k| k != "function") {
                return Err(ModelError::Response);
            }
            let call = self.tools.entry(part.index).or_insert_with(|| ToolCall {
                id: String::new(),
                name: String::new(),
                arguments: String::new(),
            });
            if let Some(id) = part.id.filter(|s| !s.is_empty()) {
                call.id = id;
            }
            let function = part.function.unwrap_or_default();
            if let Some(name) = function.name.filter(|s| !s.is_empty()) {
                call.name = name;
            }
            if let Some(arguments) = function.arguments {
                if call.arguments.len() + arguments.len() > MAX_ARGUMENTS {
                    return Err(ModelError::Response);
                }
                call.arguments.push_str(&arguments);
            }
        }
        if let Some(reason) = choice.finish_reason {
            self.finish = Some(match reason.as_str() {
                "stop" => Finish::Stop,
                "tool_calls" => Finish::ToolCalls,
                "length" => Finish::Length,
                _ => Finish::Other,
            });
        }
        Ok(())
    }
}

// Unknown fields, such as `reasoning_content`, are ignored.
#[derive(Deserialize)]
struct Chunk {
    #[serde(default)]
    choices: Vec<Choice>,
    usage: Option<WireUsage>,
    error: Option<serde::de::IgnoredAny>,
}
#[derive(Deserialize)]
struct Choice {
    #[serde(default)]
    delta: Delta,
    finish_reason: Option<String>,
}
#[derive(Default, Deserialize)]
struct Delta {
    content: Option<String>,
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
struct WireUsage {
    prompt_tokens: u64,
    completion_tokens: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Finish, ToolCall, Usage};

    const BODY: &str = concat!(
        ": keep-alive\n\n",
        r#"data: {"id":"c1","choices":[{"index":0,"delta":{"role":"assistant","content":"","reasoning_content":"Hmm"}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"index":0,"delta":{"content":"Let me "},"logprobs":null}]}"#,
        "\r\n\r\n",
        r#"data: {"choices":[{"index":0,"delta":{"content":"look."}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call-1","type":"function","function":{"name":"search","arguments":""}}]}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call-2","type":"function","function":{"name":"search","arguments":"{\"text\":"}}]}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"text\":"}}]}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"ferry\"}"}},{"index":1,"function":{"arguments":"\"café\"}"}}]}}]}"#,
        "\n\n",
        r#"data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":null}"#,
        "\n\n",
        r#"data: {"choices":[],"usage":{"prompt_tokens":9,"completion_tokens":2,"total_tokens":11}}"#,
        "\n\n",
        "data: [DONE]\n\n",
    );

    fn decode(pieces: &[&[u8]]) -> Result<(Completion, String), ModelError> {
        let mut decoder = Decoder::new();
        let mut text = String::new();
        for piece in pieces {
            text.extend(decoder.push(piece)?);
        }
        Ok((decoder.finish()?, text))
    }
    fn events(events: &[&str]) -> String {
        events.iter().map(|e| format!("data: {e}\n\n")).collect()
    }

    #[test]
    fn splitting_anywhere_decodes_the_same() {
        let body = BODY.as_bytes();
        let whole = decode(&[body]).unwrap();
        assert_eq!(
            whole.0,
            Completion {
                text: Some("Let me look.".into()),
                tool_calls: vec![
                    ToolCall {
                        id: "call-1".into(),
                        name: "search".into(),
                        arguments: r#"{"text":"ferry"}"#.into(),
                    },
                    ToolCall {
                        id: "call-2".into(),
                        name: "search".into(),
                        arguments: r#"{"text":"café"}"#.into(),
                    },
                ],
                finish: Finish::ToolCalls,
                usage: Some(Usage {
                    prompt: 9,
                    completion: 2
                }),
            }
        );
        let accent = BODY.find('é').unwrap() + 1;
        assert!(!BODY.is_char_boundary(accent));
        for at in 0..=body.len() {
            assert_eq!(decode(&[&body[..at], &body[at..]]).unwrap(), whole, "{at}");
        }
        let bytes: Vec<&[u8]> = body.chunks(1).collect();
        assert_eq!(decode(&bytes).unwrap(), whole);
    }

    #[test]
    fn tool_arguments_never_appear_as_text() {
        let (completion, text) = decode(&[BODY.as_bytes()]).unwrap();
        assert_eq!(text, "Let me look.");
        assert_eq!(completion.tool_calls[0].arguments, r#"{"text":"ferry"}"#);
    }

    #[test]
    fn a_stream_without_done_is_an_error() {
        let text = r#"{"choices":[{"index":0,"delta":{"content":"It"}}]}"#;
        let stop = r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#;
        let cut = events(&[text]);
        assert_eq!(decode(&[cut.as_bytes()]).unwrap_err(), ModelError::Response);
        let unfinished = events(&[text, stop]);
        assert_eq!(
            decode(&[unfinished.as_bytes()]).unwrap_err(),
            ModelError::Response
        );
        let no_reason = events(&[text, "[DONE]"]);
        assert_eq!(
            decode(&[no_reason.as_bytes()]).unwrap_err(),
            ModelError::Response
        );
        let undelimited = format!("{}data: [DONE]", events(&[text, stop]));
        assert_eq!(
            decode(&[undelimited.as_bytes()]).unwrap_err(),
            ModelError::Response
        );
        let whole = events(&[text, stop, "[DONE]"]);
        assert_eq!(
            decode(&[whole.as_bytes()]).unwrap().0.text.as_deref(),
            Some("It")
        );
    }

    #[test]
    fn no_bytes_follow_done_in_the_same_decrypted_chunk() {
        let stop = r#"{"choices":[{"delta":{},"finish_reason":"stop"}]}"#;
        for suffix in ["data: {}\n\n", ": comment\n\n", "\n"] {
            let body = format!("{}{}", events(&[stop, "[DONE]"]), suffix);
            assert_eq!(
                decode(&[body.as_bytes()]).unwrap_err(),
                ModelError::Response
            );
        }
    }

    #[test]
    fn an_error_event_is_an_error() {
        let body = events(&[
            r#"{"choices":[{"index":0,"delta":{"content":"It"}}]}"#,
            r#"{"error":{"message":"x"}}"#,
        ]);
        let mut decoder = Decoder::new();
        let err = decoder.push(body.as_bytes()).unwrap_err();
        assert_eq!(err, ModelError::Response);
        assert!(!format!("{err:?}").contains('x'));
        // A failed decoder stays failed.
        let rest = events(&[
            r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
            "[DONE]",
        ]);
        assert_eq!(
            decoder.push(rest.as_bytes()).unwrap_err(),
            ModelError::Response
        );
        assert_eq!(decoder.finish().unwrap_err(), ModelError::Response);
    }

    #[test]
    fn oversized_events_are_refused() {
        let big = format!("data: {}", "x".repeat(1024 * 1024 + 1));
        let mut decoder = Decoder::new();
        // Refused before the event ends, so it is never held whole.
        assert_eq!(
            decoder.push(big.as_bytes()).unwrap_err(),
            ModelError::Response
        );
        let lines: String = (0..1024)
            .map(|_| format!("data: {}\n", "x".repeat(1024)))
            .collect();
        assert_eq!(
            Decoder::new().push(lines.as_bytes()).unwrap_err(),
            ModelError::Response
        );
    }

    #[test]
    fn streams_and_tool_calls_are_bounded() {
        let delta = |d: &str| format!(r#"{{"choices":[{{"index":0,"delta":{d}}}]}}"#);
        let line = events(&[&delta(&format!(
            r#"{{"content":"{}"}}"#,
            "x".repeat(512 * 1024)
        ))]);
        let mut decoder = Decoder::new();
        let mut result = Ok(vec![]);
        for _ in 0..17 {
            result = decoder.push(line.as_bytes());
        }
        assert_eq!(result.unwrap_err(), ModelError::Response);

        let call = |i: usize| {
            delta(&format!(
                r#"{{"tool_calls":[{{"index":{i},"id":"c","function":{{"name":"n","arguments":"{{}}"}}}}]}}"#
            ))
        };
        assert!(Decoder::new().push(events(&[&call(15)]).as_bytes()).is_ok());
        assert_eq!(
            Decoder::new()
                .push(events(&[&call(16)]).as_bytes())
                .unwrap_err(),
            ModelError::Response
        );

        let args = delta(&format!(
            r#"{{"tool_calls":[{{"index":0,"function":{{"arguments":"{}"}}}}]}}"#,
            "x".repeat(32 * 1024)
        ));
        let mut decoder = Decoder::new();
        assert!(decoder.push(events(&[&args, &args]).as_bytes()).is_ok());
        assert_eq!(decoder.push(events(&["{}"]).as_bytes()).map(|_| ()), Ok(()));
        assert_eq!(
            decoder
                .push(
                    events(&[&delta(
                        r#"{"tool_calls":[{"index":0,"function":{"arguments":"x"}}]}"#
                    )])
                    .as_bytes()
                )
                .unwrap_err(),
            ModelError::Response
        );
    }
}
