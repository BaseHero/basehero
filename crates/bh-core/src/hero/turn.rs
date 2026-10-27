//! One bounded, cancellable model/tool turn.
use super::{
    Step,
    tools::{ToolResult, Tools},
};
use crate::{BaseId, ObjectId};
use bh_models::{ChatModel, ChatRequest, Message, ModelError, Role, ToolCall, ToolChoice};
use tokio::sync::watch;

pub(crate) struct TurnLimits {
    pub max_calls: usize,
    pub max_tokens: u32,
    pub max_request_bytes: usize,
}
impl Default for TurnLimits {
    fn default() -> Self {
        Self {
            max_calls: 8,
            max_tokens: 2048,
            max_request_bytes: 512 * 1024,
        }
    }
}
pub(crate) enum ResultKind {
    Answer(String),
    Ask(BaseId),
    Failed(&'static str),
    Stopped,
}
pub(crate) struct TurnOutcome {
    pub kind: ResultKind,
    pub steps: Vec<Step>,
    pub created: Vec<ObjectId>,
}
fn code(error: ModelError) -> &'static str {
    match error {
        ModelError::RateLimited => "rate_limited",
        ModelError::Verification => "verification",
        ModelError::NeedsUpdate => "needs_update",
        ModelError::Transport | ModelError::HttpStatus(500..=599) => "unavailable",
        _ => "failed",
    }
}
fn message(role: Role, content: Option<String>) -> Message {
    Message {
        role,
        content,
        tool_calls: vec![],
        tool_call_id: None,
    }
}
/// Runs calls in sequence and returns the first permission request without making another model call.
pub(crate) async fn run(
    model: &dyn ChatModel,
    tools: &mut Tools,
    mut request: Vec<Message>,
    limits: TurnLimits,
    mut cancel: watch::Receiver<bool>,
    mut progress: impl FnMut(&Step, &[ObjectId]),
    mut guarded_call: impl FnMut(&mut Tools, &ToolCall) -> Option<ToolResult>,
) -> TurnOutcome {
    let mut steps = vec![];
    let mut created = vec![];
    let kind = 'turn: {
        for i in 0..limits.max_calls {
            if *cancel.borrow() {
                break 'turn ResultKind::Stopped;
            }
            let mut req = ChatRequest {
                messages: request.clone(),
                tools: Tools::specs(),
                tool_choice: Some(if i + 1 == limits.max_calls {
                    ToolChoice::None
                } else {
                    ToolChoice::Auto
                }),
                max_tokens: limits.max_tokens,
            };
            // The oldest history is discarded before a request can exceed the cap.
            while super::prompt::request_size(&req.messages)
                > limits.max_request_bytes.saturating_sub(32 * 1024)
                && req.messages.len() > 2
            {
                req.messages.remove(1);
            }
            let completion = tokio::select! {
                biased;
                _ = cancel.changed() => break 'turn ResultKind::Stopped,
                result = model.complete(req.clone()) => result,
            };
            if *cancel.borrow() {
                break 'turn ResultKind::Stopped;
            }
            let completion = match completion {
                Ok(value) => value,
                Err(err) => break 'turn ResultKind::Failed(code(err)),
            };
            if completion.tool_calls.is_empty() {
                break 'turn ResultKind::Answer(completion.text.unwrap_or_default());
            }
            // Keep the exact tool-call envelope alongside results for the next request.
            request = req.messages;
            request.push(Message {
                role: Role::Assistant,
                content: completion.text,
                tool_calls: completion.tool_calls.clone(),
                tool_call_id: None,
            });
            for call in completion.tool_calls {
                if *cancel.borrow() {
                    break 'turn ResultKind::Stopped;
                }
                let Some(result) = guarded_call(tools, &call) else {
                    break 'turn ResultKind::Stopped;
                };
                if let Some(id) = result.created {
                    created.push(id);
                }
                steps.push(result.step);
                progress(steps.last().unwrap(), &created);
                if let Some(base) = result.ask {
                    break 'turn ResultKind::Ask(base);
                }
                request.push(Message {
                    tool_call_id: Some(call.id),
                    ..message(Role::Tool, Some(result.content))
                });
            }
        }
        ResultKind::Failed("failed")
    };
    TurnOutcome {
        kind,
        steps,
        created,
    }
}
