//! Strict subset of NEAR Chat Completions requests. The SDK transforms a
//! selective list of fields and silently leaves unknown ones alone; this
//! boundary refuses unsupported shapes rather than leaking a new content field.
// Only the verified-model preparation path may call this private transform.
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Shape,
    Limit,
    Encrypt,
}

const MAX_INPUT: usize = 1 << 20;

/// Invoked only with content-bearing strings. `encrypt` must be the pinned
/// model's v2 field encryption, never a plaintext identity function in product.
/// Kept crate-private so callers cannot obtain a falsely "prepared" request.
pub(crate) fn transform(
    input: &[u8],
    mut encrypt: impl FnMut(&str) -> Result<String, Error>,
) -> Result<Value, Error> {
    if input.len() > MAX_INPUT {
        return Err(Error::Limit);
    }
    let mut body: Value = serde_json::from_slice(input).map_err(|_| Error::Shape)?;
    let object = body.as_object_mut().ok_or(Error::Shape)?;
    allowed(
        object,
        &[
            "model",
            "messages",
            "tools",
            "tool_choice",
            "function_call",
            "stream",
            "stream_options",
            "temperature",
            "top_p",
            "max_tokens",
            "max_completion_tokens",
            "response_format",
            "parallel_tool_calls",
            "seed",
            "frequency_penalty",
            "presence_penalty",
        ],
    )?;
    if object.get("model").and_then(Value::as_str) != Some(crate::near_model::MODEL)
        || object.get("stream") != Some(&Value::Bool(true))
    {
        return Err(Error::Shape);
    }
    for (field, max) in [
        ("max_tokens", 1_000_000),
        ("max_completion_tokens", 1_000_000),
    ] {
        if let Some(v) = object.get(field)
            && v.as_u64().is_none_or(|n| n == 0 || n > max)
        {
            return Err(Error::Shape);
        }
    }
    for field in [
        "temperature",
        "top_p",
        "frequency_penalty",
        "presence_penalty",
    ] {
        if let Some(v) = object.get(field)
            && !v.is_number()
        {
            return Err(Error::Shape);
        }
    }
    if let Some(v) = object.get("seed")
        && v.as_i64().is_none()
    {
        return Err(Error::Shape);
    }
    if let Some(v) = object.get("parallel_tool_calls")
        && !v.is_boolean()
    {
        return Err(Error::Shape);
    }
    if let Some(v) = object.get("stream_options") {
        let options = v.as_object().ok_or(Error::Shape)?;
        allowed(options, &["include_usage"])?;
        if options
            .get("include_usage")
            .is_some_and(|v| !v.is_boolean())
        {
            return Err(Error::Shape);
        }
    }
    if let Some(v) = object.get("response_format") {
        let format = v.as_object().ok_or(Error::Shape)?;
        allowed(format, &["type", "json_schema"])?;
        match format.get("type").and_then(Value::as_str) {
            Some("text" | "json_object") if format.len() == 1 => {}
            Some("json_schema") => {
                let schema = format
                    .get("json_schema")
                    .and_then(Value::as_object)
                    .ok_or(Error::Shape)?;
                allowed(schema, &["name", "description", "schema", "strict"])?;
                if schema.get("name").and_then(Value::as_str).is_none()
                    || !schema.get("schema").is_some_and(Value::is_object)
                    || schema.get("strict").is_some_and(|v| !v.is_boolean())
                {
                    return Err(Error::Shape);
                }
                // Schema contains descriptions, examples and constants. The SDK
                // does not encrypt response_format: refuse it rather than leak.
                return Err(Error::Shape);
            }
            _ => return Err(Error::Shape),
        }
    }
    let messages = object
        .get_mut("messages")
        .and_then(Value::as_array_mut)
        .ok_or(Error::Shape)?;
    if messages.is_empty() || messages.len() > 128 {
        return Err(Error::Shape);
    }
    for message in messages {
        let msg = message.as_object_mut().ok_or(Error::Shape)?;
        allowed(
            msg,
            &[
                "role",
                "content",
                "reasoning_content",
                "reasoning",
                "name",
                "refusal",
                "audio",
                "tool_calls",
                "function_call",
                "tool_call_id",
            ],
        )?;
        if !matches!(
            msg.get("role").and_then(Value::as_str),
            Some("system" | "developer" | "user" | "assistant" | "tool" | "function")
        ) {
            return Err(Error::Shape);
        }
        if !msg.contains_key("content") && !msg.contains_key("tool_calls") {
            return Err(Error::Shape);
        }
        if let Some(content) = msg.get_mut("content") {
            if let Some(s) = content.as_str() {
                *content = Value::String(encrypt(s)?);
            } else if content.is_array() {
                // SDK dumps the entire array as compact, UTF-8-preserving JSON.
                // serde_json may sort object keys; encryption semantics match,
                // but exact ciphertext intentionally differs across fresh nonces.
                let json = serde_json::to_string(content).map_err(|_| Error::Shape)?;
                *content = Value::String(encrypt(&json)?);
            } else if !content.is_null() {
                return Err(Error::Shape);
            }
        }
        strings(
            msg,
            &["reasoning_content", "reasoning", "name", "refusal"],
            &mut encrypt,
        )?;
        if let Some(audio) = msg.get_mut("audio") {
            let audio = audio.as_object_mut().ok_or(Error::Shape)?;
            allowed(audio, &["data"])?;
            strings(audio, &["data"], &mut encrypt)?;
        }
        if let Some(id) = msg.get("tool_call_id")
            && !identifier(id)
        {
            return Err(Error::Shape);
        }
        if let Some(calls) = msg.get_mut("tool_calls") {
            let calls = calls.as_array_mut().ok_or(Error::Shape)?;
            if calls.len() > 32 {
                return Err(Error::Shape);
            }
            for call in calls {
                let call = call.as_object_mut().ok_or(Error::Shape)?;
                allowed(call, &["id", "type", "function"])?;
                if call.get("id").is_some_and(|v| !identifier(v))
                    || call.get("type").and_then(Value::as_str) != Some("function")
                {
                    return Err(Error::Shape);
                }
                function(
                    call.get_mut("function").ok_or(Error::Shape)?,
                    &mut encrypt,
                    false,
                )?;
            }
        }
        if let Some(f) = msg.get_mut("function_call") {
            function(f, &mut encrypt, false)?;
        }
    }
    if let Some(tools) = object.get_mut("tools") {
        let tools = tools.as_array_mut().ok_or(Error::Shape)?;
        if tools.len() > 32 {
            return Err(Error::Shape);
        }
        for tool in tools {
            let tool = tool.as_object_mut().ok_or(Error::Shape)?;
            allowed(tool, &["type", "function"])?;
            if tool.get("type").and_then(Value::as_str) != Some("function") {
                return Err(Error::Shape);
            }
            function(
                tool.get_mut("function").ok_or(Error::Shape)?,
                &mut encrypt,
                true,
            )?;
        }
    }
    for choice in ["tool_choice", "function_call"] {
        if let Some(v) = object.get_mut(choice) {
            if choice == "tool_choice" && matches!(v.as_str(), Some("none" | "auto" | "required")) {
                continue;
            }
            if choice == "function_call" && matches!(v.as_str(), Some("none" | "auto")) {
                continue;
            }
            let obj = v.as_object_mut().ok_or(Error::Shape)?;
            if choice == "tool_choice" {
                allowed(obj, &["type", "function"])?;
                if obj.get("type").and_then(Value::as_str) != Some("function") {
                    return Err(Error::Shape);
                }
                let named = obj
                    .get_mut("function")
                    .and_then(Value::as_object_mut)
                    .ok_or(Error::Shape)?;
                allowed(named, &["name"])?;
                if !named.contains_key("name") {
                    return Err(Error::Shape);
                }
                strings(named, &["name"], &mut encrypt)?;
            } else {
                allowed(obj, &["name"])?;
                if !obj.contains_key("name") {
                    return Err(Error::Shape);
                }
                strings(obj, &["name"], &mut encrypt)?;
            }
        }
    }
    if serde_json::to_vec(&body).map_err(|_| Error::Shape)?.len() > MAX_INPUT {
        return Err(Error::Limit);
    }
    Ok(body)
}

fn identifier(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        !s.is_empty()
            && s.len() <= 64
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    })
}
fn allowed(obj: &Map<String, Value>, fields: &[&str]) -> Result<(), Error> {
    if obj.keys().any(|k| !fields.contains(&k.as_str())) {
        Err(Error::Shape)
    } else {
        Ok(())
    }
}
fn strings(
    obj: &mut Map<String, Value>,
    names: &[&str],
    encrypt: &mut impl FnMut(&str) -> Result<String, Error>,
) -> Result<(), Error> {
    for name in names {
        if let Some(v) = obj.get_mut(*name) {
            let s = v.as_str().ok_or(Error::Shape)?;
            *v = Value::String(encrypt(s)?);
        }
    }
    Ok(())
}
fn function(
    v: &mut Value,
    encrypt: &mut impl FnMut(&str) -> Result<String, Error>,
    tool: bool,
) -> Result<(), Error> {
    let obj = v.as_object_mut().ok_or(Error::Shape)?;
    allowed(
        obj,
        if tool {
            &["name", "description", "parameters", "strict"]
        } else {
            &["name", "arguments"]
        },
    )?;
    if !obj.contains_key("name") {
        return Err(Error::Shape);
    }
    strings(
        obj,
        if tool {
            &["name", "description"]
        } else {
            &["name", "arguments"]
        },
        encrypt,
    )?;
    if tool {
        if let Some(v) = obj.get("strict")
            && !v.is_boolean()
        {
            return Err(Error::Shape);
        }
        if let Some(p) = obj.get_mut("parameters") {
            if !p.is_object() {
                return Err(Error::Shape);
            }
            let json = serde_json::to_string(p).map_err(|_| Error::Shape)?;
            *p = Value::String(encrypt(&json)?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sdk_010_request_field_fixture() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/near_sdk_v2.json")).unwrap();
        let plain = serde_json::to_vec(&fixture["request_plain"]).unwrap();
        let mut seen = Vec::new();
        let transformed = transform(&plain, |s| {
            seen.push(s.to_owned());
            Ok(format!("sealed:{s}"))
        })
        .unwrap();
        assert_eq!(transformed["model"], crate::near_model::MODEL);
        assert!(seen.iter().any(|s| s == "Résumé 🪐"));
        assert!(seen.iter().any(|s| s.contains("日本語 café")));
        assert!(
            seen.iter()
                .any(|s| s.contains("\"description\":\"日本語\""))
        );
        assert!(seen.iter().any(String::is_empty));
        // The SDK request fixture encrypts the same fields, not the structural
        // role, tool ID, model ID or streaming control.
        let sdk = &fixture["request_encrypted"];
        for pointer in [
            "/messages/0/content",
            "/messages/1/content",
            "/messages/2/content",
            "/messages/2/reasoning_content",
            "/messages/2/reasoning",
            "/messages/2/name",
            "/messages/2/refusal",
            "/messages/2/audio/data",
            "/messages/2/tool_calls/0/function/name",
            "/messages/2/tool_calls/0/function/arguments",
            "/messages/2/function_call/name",
            "/messages/2/function_call/arguments",
            "/messages/3/content",
            "/tools/0/function/name",
            "/tools/0/function/description",
            "/tools/0/function/parameters",
            "/tool_choice/function/name",
            "/function_call/name",
        ] {
            assert!(
                transformed
                    .pointer(pointer)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .starts_with("sealed:"),
                "{pointer}"
            );
            assert!(
                sdk.pointer(pointer)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .chars()
                    .all(|c| c.is_ascii_hexdigit()),
                "SDK: {pointer}"
            );
        }
    }

    #[test]
    fn encrypt_every_documented_field_and_refuse_unknowns() {
        let json = format!(
            r#"{{"model":"{}","stream":true,"messages":[{{"role":"user","content":[{{"type":"text","text":"é"}}],"reasoning":"private","name":"x","refusal":"no","audio":{{"data":"sound"}},"tool_calls":[{{"id":"id","type":"function","function":{{"name":"tool","arguments":"{{}}"}}}}],"function_call":{{"name":"old","arguments":"{}"}}}}],"tools":[{{"type":"function","function":{{"name":"tool","description":"secret","parameters":{{"type":"object","description":"secret"}}}}}}],"tool_choice":{{"type":"function","function":{{"name":"tool"}}}},"function_call":{{"name":"old"}}}}"#,
            crate::near_model::MODEL,
            "{}"
        );
        let transformed = transform(json.as_bytes(), |s| Ok(format!("sealed:{s}"))).unwrap();
        assert!(
            transformed["messages"][0]["content"]
                .as_str()
                .unwrap()
                .starts_with("sealed:[")
        );
        for pointer in [
            "/messages/0/reasoning",
            "/messages/0/name",
            "/messages/0/refusal",
            "/messages/0/audio/data",
            "/messages/0/tool_calls/0/function/name",
            "/messages/0/tool_calls/0/function/arguments",
            "/messages/0/function_call/name",
            "/messages/0/function_call/arguments",
            "/tools/0/function/name",
            "/tools/0/function/description",
            "/tools/0/function/parameters",
            "/tool_choice/function/name",
            "/function_call/name",
        ] {
            assert!(
                transformed
                    .pointer(pointer)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .starts_with("sealed:"),
                "{pointer}"
            );
        }
        for leak in [
            r#""metadata":"secret""#,
            r#""response_format":{"type":"json_schema","json_schema":{"name":"x","schema":{"description":"secret"}}}"#,
        ] {
            let changed = json.replacen("\"stream\":true", &format!("\"stream\":true,{leak}"), 1);
            assert_eq!(
                transform(changed.as_bytes(), |_| Ok(String::new())),
                Err(Error::Shape)
            );
        }
        assert_eq!(
            transform(
                json.replace("\"stream\":true", "\"stream\":false")
                    .as_bytes(),
                |_| Ok(String::new())
            ),
            Err(Error::Shape)
        );
    }
}
