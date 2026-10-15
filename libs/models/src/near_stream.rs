//! Bounded encrypted-wire SSE framing. The field opener is supplied only by
//! the private v2 request context, once the provider crypto gate is approved.
//! No completion escapes before an authenticated final signature.
use crate::{
    near_model::VerifiedModelKey,
    near_signature::{self, Signature, WireHash},
    response::{Completion, DecodeError, Delta, Limits, ResponseDecoder},
};
use serde_json::Value;

const MAX_ENCRYPTED_WIRE: usize = 16 << 20;
const MAX_ENCRYPTED_EVENT: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Frame,
    Field,
    Limit,
    Decode,
    Signature,
}

/// One attempt. EOF consumes this handle; error poisons it and cannot return a
/// final result. The caller may show `Delta::Text` only as provisional.
pub(crate) struct Stream<F: FnMut(&str) -> Result<String, Error>> {
    open: F,
    response: ResponseDecoder,
    wire: WireHash,
    wire_size: usize,
    event_bytes: usize,
    pending: Vec<u8>,
    data: Vec<String>,
    event_error: bool,
    after_cr: bool,
    done: bool,
    failed: bool,
}
impl<F: FnMut(&str) -> Result<String, Error>> Stream<F> {
    pub(crate) fn new(open: F, limits: Limits) -> Self {
        Self {
            open,
            response: ResponseDecoder::new(limits),
            wire: WireHash::new(),
            wire_size: 0,
            event_bytes: 0,
            pending: Vec::new(),
            data: Vec::new(),
            event_error: false,
            after_cr: false,
            done: false,
            failed: false,
        }
    }
    pub(crate) fn push(&mut self, raw: &[u8]) -> Result<Vec<Delta>, Error> {
        if self.failed || (self.done && !(self.after_cr && raw == b"\n")) {
            self.failed = true;
            return Err(Error::Frame);
        }
        let result = self.push_inner(raw);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn push_inner(&mut self, raw: &[u8]) -> Result<Vec<Delta>, Error> {
        self.wire_size = self.wire_size.checked_add(raw.len()).ok_or(Error::Limit)?;
        if self.wire_size > MAX_ENCRYPTED_WIRE {
            return Err(Error::Limit);
        }
        // Preserve exact encrypted bytes, including CRLF, whitespace, comments
        // and tail; never hash a parsed/decrypted representation.
        self.wire.update(raw);
        let mut emitted = Vec::new();
        for &byte in raw {
            if self.after_cr {
                self.after_cr = false;
                if byte == b'\n' {
                    continue;
                }
            }
            if self.done {
                return Err(Error::Frame);
            }
            if byte == b'\r' || byte == b'\n' {
                self.line(&mut emitted)?;
                self.after_cr = byte == b'\r';
            } else {
                if self.pending.len() >= MAX_ENCRYPTED_EVENT {
                    return Err(Error::Limit);
                }
                self.pending.push(byte);
            }
        }
        Ok(emitted)
    }
    fn line(&mut self, emitted: &mut Vec<Delta>) -> Result<(), Error> {
        self.event_bytes = self
            .event_bytes
            .checked_add(self.pending.len() + 1)
            .ok_or(Error::Limit)?;
        if self.event_bytes > MAX_ENCRYPTED_EVENT {
            return Err(Error::Limit);
        }
        let line = std::str::from_utf8(&self.pending).map_err(|_| Error::Frame)?;
        if self.done && !line.is_empty() {
            return Err(Error::Frame);
        }
        if line.is_empty() {
            self.event_bytes = 0;
            if self.event_error {
                return Err(Error::Frame);
            }
            if !self.data.is_empty() {
                let data = self.data.join("\n");
                self.data.clear();
                if data == "[DONE]" {
                    if self.done {
                        return Err(Error::Frame);
                    }
                    self.response
                        .push(b"data: [DONE]\n\n")
                        .map_err(map_decode)?;
                    self.done = true;
                } else if !data.is_empty() {
                    let mut event: Value = serde_json::from_str(&data).map_err(|_| Error::Frame)?;
                    decrypt_event(&mut event, &mut self.open)?;
                    let bytes = serde_json::to_vec(&event).map_err(|_| Error::Frame)?;
                    let mut normalized = b"data: ".to_vec();
                    normalized.extend_from_slice(&bytes);
                    normalized.extend_from_slice(b"\n\n");
                    emitted.extend(self.response.push(&normalized).map_err(map_decode)?);
                }
            }
        } else if line == "event: error" || line == "event:error" || line == "event:  error" {
            self.event_error = true;
        } else if line == "data" || line.starts_with("data:") {
            let data = line
                .strip_prefix("data:")
                .unwrap_or("")
                .strip_prefix(' ')
                .unwrap_or(line.strip_prefix("data:").unwrap_or(""));
            self.data.push(data.to_owned());
        }
        self.pending.clear();
        Ok(())
    }
    pub(crate) fn finish(
        self,
        key: &VerifiedModelKey,
        request: &[u8],
        signature: &Signature<'_>,
    ) -> Result<Completion, Error> {
        if self.failed
            || !self.done
            || !self.pending.is_empty()
            || !self.data.is_empty()
            || self.event_error
        {
            return Err(Error::Frame);
        }
        let completion = self.response.finish().map_err(map_decode)?;
        near_signature::verify_model(key, request, self.wire.finalize(), signature)
            .map_err(|_| Error::Signature)?;
        Ok(completion)
    }
}
fn map_decode(_: DecodeError) -> Error {
    Error::Decode
}

fn decrypt_event(
    event: &mut Value,
    open: &mut impl FnMut(&str) -> Result<String, Error>,
) -> Result<(), Error> {
    let root = event.as_object_mut().ok_or(Error::Frame)?;
    let Some(choices) = root.get_mut("choices") else {
        return Ok(());
    };
    let choices = choices.as_array_mut().ok_or(Error::Frame)?;
    if choices.len() > 1 {
        return Err(Error::Frame);
    }
    for choice in choices {
        let choice = choice.as_object_mut().ok_or(Error::Frame)?;
        if let Some(delta) = choice.get_mut("delta") {
            let message = delta.as_object_mut().ok_or(Error::Frame)?;
            fields(
                message,
                &["content", "reasoning_content", "reasoning", "refusal"],
                open,
            )?;
            if let Some(parts) = message.get_mut("content")
                && parts.is_array()
            {
                // SDK supports encrypted text parts but the current response
                // decoder only accepts string deltas. Refuse, don't drop them.
                return Err(Error::Field);
            }
            if let Some(audio) = message.get_mut("audio")
                && !audio.is_null()
            {
                fields(audio.as_object_mut().ok_or(Error::Frame)?, &["data"], open)?;
            }
            if let Some(calls) = message.get_mut("tool_calls")
                && !calls.is_null()
            {
                for call in calls.as_array_mut().ok_or(Error::Frame)? {
                    if let Some(function) = call
                        .as_object_mut()
                        .ok_or(Error::Frame)?
                        .get_mut("function")
                        && !function.is_null()
                    {
                        fields(
                            function.as_object_mut().ok_or(Error::Frame)?,
                            &["name", "arguments"],
                            open,
                        )?;
                    }
                }
            }
            if let Some(function) = message.get_mut("function_call")
                && !function.is_null()
            {
                fields(
                    function.as_object_mut().ok_or(Error::Frame)?,
                    &["name", "arguments"],
                    open,
                )?;
            }
            if let Some(result) = message.get_mut("nearai_tool_result")
                && !result.is_null()
            {
                fields(
                    result.as_object_mut().ok_or(Error::Frame)?,
                    &["output"],
                    open,
                )?;
            }
        }
        if let Some(logprobs) = choice.get_mut("logprobs")
            && !logprobs.is_null()
        {
            let logprobs = logprobs.as_object_mut().ok_or(Error::Frame)?;
            for key in ["content", "refusal"] {
                if let Some(entries) = logprobs.get_mut(key)
                    && !entries.is_null()
                {
                    decrypt_logprobs(entries, open, 0)?;
                }
            }
        }
    }
    Ok(())
}
fn decrypt_logprobs(
    entries: &mut Value,
    open: &mut impl FnMut(&str) -> Result<String, Error>,
    depth: u8,
) -> Result<(), Error> {
    if depth > 2 {
        return Err(Error::Limit);
    }
    for entry in entries.as_array_mut().ok_or(Error::Frame)? {
        if entry.is_null() {
            continue;
        }
        let entry = entry.as_object_mut().ok_or(Error::Frame)?;
        fields(entry, &["token"], open)?;
        if let Some(v) = entry.get_mut("bytes")
            && !v.is_null()
        {
            let raw = v.as_str().ok_or(Error::Field)?;
            *v = serde_json::from_str(&open(raw)?).map_err(|_| Error::Field)?;
        }
        if let Some(top) = entry.get_mut("top_logprobs")
            && !top.is_null()
        {
            decrypt_logprobs(top, open, depth + 1)?;
        }
    }
    Ok(())
}
fn fields(
    target: &mut serde_json::Map<String, Value>,
    names: &[&str],
    open: &mut impl FnMut(&str) -> Result<String, Error>,
) -> Result<(), Error> {
    for name in names {
        if let Some(v) = target.get_mut(*name) {
            if v.is_null() {
                continue;
            }
            let raw = v.as_str().ok_or(Error::Field)?;
            *v = Value::String(if raw.is_empty() {
                String::new()
            } else {
                open(raw)?
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "near_stream_tests.rs"]
mod tests;
