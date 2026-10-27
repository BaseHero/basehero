use crate::error::CommandError;
use crate::state::AppState;
use crate::views::{BaseRef, SearchResult};
use bh_core::{
    AccountId, BaseId, BaseSummary, NewObject, ObjectId, ObjectSummary, SyncState, TypeRef,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum ItemKind {
    Note,
    Folder,
    Project,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct NewItem {
    pub kind: ItemKind,
    #[ts(type = "string | null")]
    pub parent: Option<ObjectId>,
    #[ts(type = "string | null")]
    pub after: Option<ObjectId>,
    pub name: Option<String>,
}

pub fn bases(state: &AppState, account: AccountId) -> Result<Vec<BaseSummary>, CommandError> {
    Ok(state.core.account(account)?.bases())
}

pub async fn create_base(
    state: &AppState,
    account: AccountId,
    name: &str,
) -> Result<BaseSummary, CommandError> {
    let base = state.core.account(account)?.create_base(name).await?;
    let r = BaseRef {
        account,
        base: base.id(),
    };
    // Install the forwarder while the new base is still open.
    state.base(&r)?;
    Ok(BaseSummary {
        id: base.id(),
        name: base.name(),
        mode: base.mode(),
        hidden: false,
    })
}

pub fn children(
    state: &AppState,
    r: &BaseRef,
    parent: Option<ObjectId>,
) -> Result<Vec<ObjectSummary>, CommandError> {
    Ok(state.base(r)?.children(parent)?)
}

pub fn get_object(
    state: &AppState,
    r: &BaseRef,
    id: ObjectId,
) -> Result<Option<ObjectSummary>, CommandError> {
    Ok(state.base(r)?.get(id)?)
}

pub fn create_object(
    state: &AppState,
    r: &BaseRef,
    item: NewItem,
) -> Result<ObjectId, CommandError> {
    let ty = match item.kind {
        ItemKind::Note => "core.note",
        ItemKind::Folder => "core.folder",
        ItemKind::Project => "core.project",
    };
    let mut fields = Map::new();
    if ty != "core.note"
        && let Some(name) = item.name
    {
        fields.insert("name".into(), Value::String(name));
    }
    Ok(state.base(r)?.create(NewObject {
        ty: TypeRef::new(ty, 1),
        parent: item.parent,
        after: item.after,
        fields,
    })?)
}

pub fn rename_object(
    state: &AppState,
    r: &BaseRef,
    id: ObjectId,
    name: &str,
) -> Result<(), CommandError> {
    let base = state.base(r)?;
    let object = base.get(id)?.ok_or(bh_core::Error::NotFound)?;
    if object.ty.name == "core.note" {
        return Err(bh_core::Error::Invalid("a note's title comes from its body".into()).into());
    }
    let mut fields = Map::new();
    fields.insert("name".into(), Value::String(name.to_owned()));
    Ok(base.set_fields(id, fields)?)
}

pub fn move_object(
    state: &AppState,
    r: &BaseRef,
    id: ObjectId,
    parent: Option<ObjectId>,
    after: Option<ObjectId>,
) -> Result<(), CommandError> {
    Ok(state.base(r)?.move_to(id, parent, after)?)
}

pub fn delete_object(state: &AppState, r: &BaseRef, id: ObjectId) -> Result<(), CommandError> {
    Ok(state.base(r)?.delete(id)?)
}

pub fn restore_object(state: &AppState, r: &BaseRef, id: ObjectId) -> Result<(), CommandError> {
    Ok(state.base(r)?.undelete(id)?)
}

pub fn trash(state: &AppState, r: &BaseRef) -> Result<Vec<ObjectSummary>, CommandError> {
    Ok(state.base(r)?.trash()?)
}

pub fn search(
    state: &AppState,
    account: AccountId,
    base: Option<BaseId>,
    text: &str,
    limit: usize,
) -> Result<Vec<SearchResult>, CommandError> {
    let account_handle = state.core.account(account)?;
    let listed = account_handle.bases();
    let mut results = Vec::new();
    let mut ordered = Vec::new();
    if let Some(id) = base {
        // An explicit base must belong to this account, even when the limit is zero.
        state.base(&BaseRef { account, base: id })?;
        ordered.push(id);
    }
    ordered.extend(listed.iter().map(|s| s.id).filter(|id| Some(*id) != base));
    for id in ordered {
        if results.len() == limit {
            break;
        }
        let r = BaseRef { account, base: id };
        let opened = state.base(&r)?;
        let base_name = opened.name();
        for hit in opened.search(text, limit - results.len())? {
            results.push(SearchResult {
                base: id,
                base_name: base_name.clone(),
                hit,
            });
        }
    }
    Ok(results)
}

pub fn sync_state(state: &AppState, r: &BaseRef) -> Result<SyncState, CommandError> {
    Ok(state.base(r)?.sync_state())
}

/// Thin Tauri adapters; plain functions above remain callable without a window.
pub mod ipc {
    use super::*;
    use tauri::State;

    #[tauri::command]
    pub fn bases(
        state: State<'_, crate::state::Startup>,
        account: AccountId,
    ) -> Result<Vec<BaseSummary>, CommandError> {
        super::bases(state.state()?, account)
    }
    #[tauri::command]
    pub async fn create_base(
        state: State<'_, crate::state::Startup>,
        account: AccountId,
        name: String,
    ) -> Result<BaseSummary, CommandError> {
        super::create_base(state.state()?, account, &name).await
    }
    #[tauri::command]
    pub fn children(
        state: State<'_, crate::state::Startup>,
        r: BaseRef,
        parent: Option<ObjectId>,
    ) -> Result<Vec<ObjectSummary>, CommandError> {
        super::children(state.state()?, &r, parent)
    }
    #[tauri::command]
    pub fn get_object(
        state: State<'_, crate::state::Startup>,
        r: BaseRef,
        id: ObjectId,
    ) -> Result<Option<ObjectSummary>, CommandError> {
        super::get_object(state.state()?, &r, id)
    }
    #[tauri::command]
    pub fn create_object(
        state: State<'_, crate::state::Startup>,
        r: BaseRef,
        item: NewItem,
    ) -> Result<ObjectId, CommandError> {
        super::create_object(state.state()?, &r, item)
    }
    #[tauri::command]
    pub fn rename_object(
        state: State<'_, crate::state::Startup>,
        r: BaseRef,
        id: ObjectId,
        name: String,
    ) -> Result<(), CommandError> {
        super::rename_object(state.state()?, &r, id, &name)
    }
    #[tauri::command]
    pub fn move_object(
        state: State<'_, crate::state::Startup>,
        r: BaseRef,
        id: ObjectId,
        parent: Option<ObjectId>,
        after: Option<ObjectId>,
    ) -> Result<(), CommandError> {
        super::move_object(state.state()?, &r, id, parent, after)
    }
    #[tauri::command]
    pub fn delete_object(
        state: State<'_, crate::state::Startup>,
        r: BaseRef,
        id: ObjectId,
    ) -> Result<(), CommandError> {
        super::delete_object(state.state()?, &r, id)
    }
    #[tauri::command]
    pub fn restore_object(
        state: State<'_, crate::state::Startup>,
        r: BaseRef,
        id: ObjectId,
    ) -> Result<(), CommandError> {
        super::restore_object(state.state()?, &r, id)
    }
    #[tauri::command]
    pub fn trash(
        state: State<'_, crate::state::Startup>,
        r: BaseRef,
    ) -> Result<Vec<ObjectSummary>, CommandError> {
        super::trash(state.state()?, &r)
    }
    #[tauri::command]
    pub fn search(
        state: State<'_, crate::state::Startup>,
        account: AccountId,
        base: Option<BaseId>,
        text: String,
        limit: usize,
    ) -> Result<Vec<SearchResult>, CommandError> {
        super::search(state.state()?, account, base, &text, limit)
    }
    #[tauri::command]
    pub fn sync_state(
        state: State<'_, crate::state::Startup>,
        r: BaseRef,
    ) -> Result<SyncState, CommandError> {
        super::sync_state(state.state()?, &r)
    }
}
