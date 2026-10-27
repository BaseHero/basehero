//! CLI access to the core's persisted Hero chats and turns.
use bh_core::{
    Account, BaseId, ObjectId,
    hero::{ChatRole, Hero},
};
use clap::Subcommand;
use serde_json::{Value, json};

use crate::{Result, invalid, object_id, selected_base};

/// Hero actions exposed by the CLI.
#[derive(Subcommand)]
pub(crate) enum HeroCommand {
    /// List chats in a base.
    Chats {
        /// Base ID or name; optional when there is exactly one base.
        #[arg(long)]
        base: Option<String>,
    },
    /// Send a prompt and wait for the reply or permission request.
    #[command(after_help = "Press Ctrl-C to stop.")]
    Ask {
        /// Base ID or name; optional when there is exactly one base.
        #[arg(long)]
        base: Option<String>,
        /// Continue an existing chat; otherwise use the newest top-level chat.
        #[arg(long)]
        chat: Option<String>,
        /// Object to focus on.
        #[arg(long)]
        focus: Option<String>,
        /// The prompt to send.
        text: String,
    },
    /// Allow a requested cross-base read and resume the turn.
    Allow {
        /// Chat base ID or name.
        #[arg(long)]
        base: Option<String>,
        /// Chat ID.
        #[arg(long)]
        chat: String,
    },
    /// Deny a requested cross-base read and resume the turn.
    Deny {
        /// Chat base ID or name.
        #[arg(long)]
        base: Option<String>,
        /// Chat ID.
        #[arg(long)]
        chat: String,
    },
}

fn chat_base(account: &Account, requested: Option<&str>, chat: ObjectId) -> Result<BaseId> {
    if let Some(requested) = requested {
        let base = selected_base(account, Some(requested))?;
        if base
            .get(chat)?
            .is_some_and(|s| !s.deleted && s.ty.name == "core.chat")
        {
            return Ok(base.id());
        }
        return Err(Box::new(bh_core::Error::NotFound));
    }
    for summary in account.bases() {
        let base = account.base(summary.id)?;
        if base
            .get(chat)?
            .is_some_and(|s| !s.deleted && s.ty.name == "core.chat")
        {
            return Ok(base.id());
        }
    }
    Err(Box::new(bh_core::Error::NotFound))
}

#[cfg(all(debug_assertions, feature = "test-support"))]
fn scripted(account: &Account) -> Result<Option<Hero>> {
    use bh_core::DeviceId;
    use bh_models::{
        Completion, Finish, ToolCall,
        testing::{Scripted, ScriptedModel},
    };
    use std::collections::{BTreeMap, BTreeSet};
    let Some(path) = std::env::var_os("BH_TEST_MODEL_SCRIPT") else {
        return Ok(None);
    };
    // Debug-only fixture: supply synthetic app readers to the real core access rule.
    if let Some(readers) = std::env::var_os("BH_TEST_APP_READERS") {
        let readers = readers
            .into_string()
            .map_err(|_| invalid("test app readers must be UTF-8"))?;
        let readers: BTreeMap<BaseId, BTreeSet<DeviceId>> = serde_json::from_str(&readers)?;
        for (base, readers) in readers {
            account.test_set_app_readers(base, readers);
        }
    }
    let steps: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let steps = steps
        .as_array()
        .ok_or_else(|| invalid("model script must be an array"))?;
    let mut replies = Vec::with_capacity(steps.len());
    for (index, step) in steps.iter().enumerate() {
        if let Some(name) = step.get("tool").and_then(Value::as_str) {
            let args = step
                .get("arguments")
                .ok_or_else(|| invalid("script tool needs arguments"))?;
            replies.push(Scripted::Reply(Completion {
                text: None,
                tool_calls: vec![ToolCall {
                    id: format!("script-{index}"),
                    name: name.to_owned(),
                    arguments: args.to_string(),
                }],
                finish: Finish::ToolCalls,
                usage: None,
            }));
        } else {
            let text = step
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("script reply needs text"))?;
            replies.push(Scripted::Reply(Completion {
                text: Some(text.to_owned()),
                tool_calls: vec![],
                finish: Finish::Stop,
                usage: None,
            }));
        }
    }
    Ok(Some(account.hero_with_model(ScriptedModel::new(replies))))
}

fn controller(account: &Account) -> Result<Hero> {
    #[cfg(all(debug_assertions, feature = "test-support"))]
    if let Some(model) = scripted(account)? {
        return Ok(model);
    }
    Ok(account.hero())
}

/// Execute a Hero action using only the core's Hero API.
pub(crate) async fn execute(account: &Account, command: &HeroCommand) -> Result<Value> {
    let hero = controller(account)?;
    match command {
        HeroCommand::Chats { base } => {
            let base = selected_base(account, base.as_deref())?;
            Ok(serde_json::to_value(hero.chats(base.id())?)?)
        }
        HeroCommand::Ask {
            base,
            chat,
            focus,
            text,
        } => {
            let base = if let Some(chat) = chat {
                chat_base(account, base.as_deref(), object_id(chat)?)?
            } else {
                selected_base(account, base.as_deref())?.id()
            };
            let chat = match chat {
                Some(chat) => object_id(chat)?,
                None => hero.chat_for(base, None)?,
            };
            let user = hero.send(
                base,
                chat,
                text,
                focus.as_deref().map(object_id).transpose()?,
            )?;
            hero.wait_idle(chat).await;
            let message = hero
                .messages(base, chat)?
                .into_iter()
                .rev()
                .find(|m| m.role == ChatRole::Hero)
                .ok_or_else(|| invalid("Hero reply missing"))?;
            let mut value = serde_json::to_value(message)?;
            value["chat"] = json!(chat);
            value["user"] = json!(user);
            Ok(value)
        }
        HeroCommand::Allow { base, chat } | HeroCommand::Deny { base, chat } => {
            let id = object_id(chat)?;
            let base = chat_base(account, base.as_deref(), id)?;
            hero.answer(base, id, matches!(command, HeroCommand::Allow { .. }))?;
            hero.wait_idle(id).await;
            let message = hero
                .messages(base, id)?
                .into_iter()
                .rev()
                .find(|m| m.role == ChatRole::Hero)
                .ok_or_else(|| invalid("Hero reply missing"))?;
            Ok(serde_json::to_value(message)?)
        }
    }
}
