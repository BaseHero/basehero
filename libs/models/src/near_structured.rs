//! Data-only NEAR structured results. The schema and the sole inert result tool
//! travel encrypted to the verified model; no returned tool is executable.
use crate::{
    near_e2ee,
    near_model::VerifiedModelKey,
    near_route::GatewayKeyConfig,
    response::{Limits, Tokens},
};
use jsonschema::{Draft, Validator};
use rand::{CryptoRng, RngCore};
use serde_json::{Value, json};

pub use near_e2ee::{Error, Signature};
const NAME: &str = "basehero_structured_result";
const MAX_SCHEMA_BYTES: usize = 64 * 1024;
const MAX_RESULT_BYTES: usize = 256 * 1024;
const MAX_NODES: usize = 2048;
const MAX_DEPTH: usize = 32;

/// Prepared owns the compiled local validator until the final signed result.
/// No plaintext schema is added to ordinary request fields or outer headers.
pub struct Prepared<'a> {
    inner: near_e2ee::Prepared<'a>,
    validator: Validator,
}
pub fn prepare_structured<'a>(
    model: &'a VerifiedModelKey,
    request_json: &[u8],
    schema_json: &[u8],
) -> Result<Prepared<'a>, Error> {
    if schema_json.len() > MAX_SCHEMA_BYTES || request_json.len() > (1 << 20) {
        return Err(Error::Limit);
    }
    let schema: Value = serde_json::from_slice(schema_json).map_err(|_| Error::Request)?;
    let mut nodes = 0;
    check_schema(&schema, 0, &mut nodes)?;
    // Explicit draft; no default features (HTTP/file/async resolution). Every
    // reference/identifier keyword is rejected above, including nested schemas.
    let validator = jsonschema::options()
        .with_draft(Draft::Draft202012)
        .build(&schema)
        .map_err(|_| Error::Request)?;
    let mut request: Value = serde_json::from_slice(request_json).map_err(|_| Error::Request)?;
    let object = request.as_object_mut().ok_or(Error::Request)?;
    if [
        "tools",
        "tool_choice",
        "function_call",
        "response_format",
        "parallel_tool_calls",
    ]
    .iter()
    .any(|name| object.contains_key(*name))
    {
        return Err(Error::Request);
    }
    object.insert(
        "tools".into(),
        json!([{"type":"function","function":{
            "name": NAME,
            "description": "Return structured data only; this is not an action.",
            "parameters": schema
        }}]),
    );
    object.insert(
        "tool_choice".into(),
        json!({"type":"function","function":{"name":NAME}}),
    );
    object.insert("parallel_tool_calls".into(), Value::Bool(false));
    let body = serde_json::to_vec(&request).map_err(|_| Error::Request)?;
    let inner = near_e2ee::prepare(model, &body)?;
    Ok(Prepared { inner, validator })
}

impl<'a> Prepared<'a> {
    pub fn encapsulate<R: CryptoRng + RngCore>(
        self,
        key: &GatewayKeyConfig,
        relay_credential: &str,
        rng: &mut R,
    ) -> Result<Exchange<'a>, Error> {
        Ok(Exchange {
            inner: self.inner.encapsulate(key, relay_credential, rng)?,
            validator: self.validator,
        })
    }
    #[cfg(test)]
    fn accepts(&self, value: &Value) -> bool {
        self.validator.is_valid(value)
    }
}
pub struct Exchange<'a> {
    inner: near_e2ee::Exchange<'a>,
    validator: Validator,
}
impl<'a> Exchange<'a> {
    pub fn outer_headers(&self) -> &[(String, String)] {
        self.inner.outer_headers()
    }
    pub fn outer_body(&self) -> &[u8] {
        self.inner.outer_body()
    }
    pub fn decapsulate(self, body: &[u8]) -> Result<BufferedReply<'a>, Error> {
        Ok(BufferedReply {
            inner: self.inner.decapsulate_with_limits(
                body,
                Limits {
                    max_content_bytes: MAX_RESULT_BYTES,
                    ..Limits::default()
                },
            )?,
            validator: self.validator,
        })
    }
}
/// No provisional output or tool proposals are available through this API.
pub struct BufferedReply<'a> {
    inner: near_e2ee::BufferedReply<'a>,
    validator: Validator,
}
pub struct StructuredResult {
    pub value: Value,
    /// Observation only; never a billing receipt or retry authorization.
    pub reported_usage: Option<Tokens>,
}
impl BufferedReply<'_> {
    pub fn finish(mut self, signature: &Signature<'_>) -> Result<StructuredResult, Error> {
        while self.inner.next_provisional()?.is_some() {}
        let completion = self.inner.finish(signature)?;
        if !completion.text.is_empty() || completion.tools.len() != 1 {
            return Err(Error::Response);
        }
        let tool = completion.tools.into_iter().next().ok_or(Error::Response)?;
        if tool.name != NAME {
            return Err(Error::Response);
        }
        let value = tool.arguments;
        // Decoder has already parsed object arguments. Bound tree traversal and
        // encoded size before handing it to the schema engine.
        let mut nodes = 0;
        check_value(&value, 0, &mut nodes)?;
        if serde_json::to_vec(&value)
            .map_err(|_| Error::Response)?
            .len()
            > MAX_RESULT_BYTES
        {
            return Err(Error::Limit);
        }
        if !self.validator.is_valid(&value) {
            return Err(Error::Response);
        }
        Ok(StructuredResult {
            value,
            reported_usage: completion.reported_usage,
        })
    }
}
fn check_value(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), Error> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_NODES {
        return Err(Error::Limit);
    }
    match value {
        Value::Array(values) => {
            for v in values {
                check_value(v, depth + 1, nodes)?;
            }
        }
        Value::Object(values) => {
            for v in values.values() {
                check_value(v, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}
// Deliberately limited Draft 2020-12 vocabulary: no references, identifiers,
// regex, remote formats, combinators, conditional evaluation or unknown keywords.
fn check_schema(schema: &Value, depth: usize, nodes: &mut usize) -> Result<(), Error> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_NODES {
        return Err(Error::Limit);
    }
    let obj = schema.as_object().ok_or(Error::Request)?;
    for (key, value) in obj {
        match key.as_str() {
            "type" | "required" | "enum" | "const" | "description" | "title" | "minItems"
            | "maxItems" | "minLength" | "maxLength" | "minimum" | "maximum" => {
                check_value(value, depth + 1, nodes)?;
            }
            "properties" => {
                for sub in value.as_object().ok_or(Error::Request)?.values() {
                    check_schema(sub, depth + 1, nodes)?;
                }
            }
            "items" => check_schema(value, depth + 1, nodes)?,
            "additionalProperties" => {
                if !value.is_boolean() {
                    check_schema(value, depth + 1, nodes)?;
                }
            }
            _ => return Err(Error::Request),
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "near_structured_tests.rs"]
mod tests;
