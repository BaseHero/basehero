use crate::{error::CommandError, state::AppState};
use bh_core::hero::{ChatMessage, ChatSummary};
use bh_core::{AccountId, BaseId, ObjectId};

pub fn chats(
    state: &AppState,
    account: AccountId,
    base: BaseId,
) -> Result<Vec<ChatSummary>, CommandError> {
    Ok(state.hero(account)?.chats(base)?)
}
pub fn chat_for(
    state: &AppState,
    account: AccountId,
    base: BaseId,
    project: Option<ObjectId>,
) -> Result<ObjectId, CommandError> {
    Ok(state.hero(account)?.chat_for(base, project)?)
}
pub fn new_chat(
    state: &AppState,
    account: AccountId,
    base: BaseId,
) -> Result<ObjectId, CommandError> {
    Ok(state.hero(account)?.new_chat(base)?)
}
pub fn messages(
    state: &AppState,
    account: AccountId,
    base: BaseId,
    chat: ObjectId,
) -> Result<Vec<ChatMessage>, CommandError> {
    Ok(state.hero(account)?.messages(base, chat)?)
}
pub fn send(
    state: &AppState,
    account: AccountId,
    base: BaseId,
    chat: ObjectId,
    text: &str,
    focus: Option<ObjectId>,
) -> Result<ObjectId, CommandError> {
    Ok(state.hero(account)?.send(base, chat, text, focus)?)
}
pub fn stop(
    state: &AppState,
    account: AccountId,
    base: BaseId,
    chat: ObjectId,
) -> Result<(), CommandError> {
    Ok(state.hero(account)?.stop(base, chat)?)
}
pub fn answer(
    state: &AppState,
    account: AccountId,
    base: BaseId,
    chat: ObjectId,
    allow: bool,
) -> Result<(), CommandError> {
    Ok(state.hero(account)?.answer(base, chat, allow)?)
}
pub fn retry(
    state: &AppState,
    account: AccountId,
    base: BaseId,
    chat: ObjectId,
) -> Result<(), CommandError> {
    Ok(state.hero(account)?.retry(base, chat)?)
}

pub mod ipc {
    use super::*;
    use crate::state::Startup;
    #[tauri::command]
    pub fn hero_chats(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
        base: BaseId,
    ) -> Result<Vec<ChatSummary>, CommandError> {
        chats(startup.state()?, account, base)
    }
    #[tauri::command]
    pub fn hero_chat_for(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
        base: BaseId,
        project: Option<ObjectId>,
    ) -> Result<ObjectId, CommandError> {
        chat_for(startup.state()?, account, base, project)
    }
    #[tauri::command]
    pub fn hero_new_chat(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
        base: BaseId,
    ) -> Result<ObjectId, CommandError> {
        new_chat(startup.state()?, account, base)
    }
    #[tauri::command]
    pub fn hero_messages(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
        base: BaseId,
        chat: ObjectId,
    ) -> Result<Vec<ChatMessage>, CommandError> {
        messages(startup.state()?, account, base, chat)
    }
    #[tauri::command]
    pub fn hero_send(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
        base: BaseId,
        chat: ObjectId,
        text: String,
        focus: Option<ObjectId>,
    ) -> Result<ObjectId, CommandError> {
        send(startup.state()?, account, base, chat, &text, focus)
    }
    #[tauri::command]
    pub fn hero_stop(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
        base: BaseId,
        chat: ObjectId,
    ) -> Result<(), CommandError> {
        stop(startup.state()?, account, base, chat)
    }
    #[tauri::command]
    pub fn hero_answer(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
        base: BaseId,
        chat: ObjectId,
        allow: bool,
    ) -> Result<(), CommandError> {
        answer(startup.state()?, account, base, chat, allow)
    }
    #[tauri::command]
    pub fn hero_retry(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
        base: BaseId,
        chat: ObjectId,
    ) -> Result<(), CommandError> {
        retry(startup.state()?, account, base, chat)
    }
}
