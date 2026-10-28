//! One bounded, cancellable model/tool turn.
use super::{
    Step,
    tools::{ToolResult, Tools},
};
use crate::{BaseId, ObjectId};
use bh_models::{ChatModel, ChatRequest, Message, ModelError, Role, ToolCall, ToolChoice};
use tokio::sync::{mpsc, watch};

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
    Answer,
    Ask(BaseId),
    Failed(&'static str),
    Stopped,
}
pub(crate) struct TurnOutcome {
    pub kind: ResultKind,
    /// The text of all model calls, joined by a blank line.
    pub text: String,
    pub steps: Vec<Step>,
    pub created: Vec<ObjectId>,
}
impl TurnOutcome {
    pub fn failed() -> Self {
        Self {
            kind: ResultKind::Failed("failed"),
            text: String::new(),
            steps: vec![],
            created: vec![],
        }
    }
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
/// `on_text` gets the turn's text so far after each piece, and `true` once a model call ends.
#[allow(
    clippy::too_many_arguments,
    reason = "the model, tools, request, limits, cancellation and callbacks are distinct"
)]
pub(crate) async fn run(
    model: &dyn ChatModel,
    tools: &mut Tools,
    mut request: Vec<Message>,
    limits: TurnLimits,
    mut cancel: watch::Receiver<bool>,
    mut on_text: impl FnMut(&str, bool),
    mut progress: impl FnMut(&Step, &[ObjectId]),
    mut guarded_call: impl FnMut(&mut Tools, &ToolCall) -> Option<ToolResult>,
) -> TurnOutcome {
    let mut text = String::new();
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
            // Pieces of this call follow a blank line after an earlier call's text.
            let start = text.len();
            let add = |text: &mut String, piece: String| {
                if piece.is_empty() {
                    return false;
                }
                if text.len() == start && start > 0 {
                    text.push_str("\n\n");
                }
                text.push_str(&piece);
                true
            };
            let (sender, mut pieces) = mpsc::unbounded_channel();
            let call = model.complete_streaming(req.clone(), sender);
            tokio::pin!(call);
            let completion = loop {
                tokio::select! {
                    biased;
                    _ = cancel.changed() => break 'turn ResultKind::Stopped,
                    Some(piece) = pieces.recv() => {
                        if add(&mut text, piece) && !*cancel.borrow() {
                            on_text(&text, false);
                        }
                    }
                    result = &mut call => break result,
                }
            };
            // The call may send its last pieces just before it resolves.
            while let Ok(piece) = pieces.try_recv() {
                add(&mut text, piece);
            }
            if *cancel.borrow() {
                break 'turn ResultKind::Stopped;
            }
            on_text(&text, true);
            let completion = match completion {
                Ok(value) => value,
                Err(err) => break 'turn ResultKind::Failed(code(err)),
            };
            if completion.tool_calls.is_empty() {
                break 'turn ResultKind::Answer;
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
        text,
        steps,
        created,
    }
}
