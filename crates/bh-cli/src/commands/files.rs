use crate::{Result, account, containing_base, invalid, object_id, selected_base};
use bh_core::{Core, NewFile};
use clap::Subcommand;
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Subcommand)]
pub(crate) enum FileCommand {
    /// Add a plain file to a note, folder or project in a base.
    Add {
        #[arg(long)]
        base: Option<String>,
        #[arg(long)]
        parent: Option<String>,
        #[arg(long, default_value = "application/octet-stream")]
        mime: String,
        path: PathBuf,
    },
}

pub(crate) fn execute(core: &Core, command: &FileCommand) -> Result<Value> {
    match command {
        FileCommand::Add {
            base,
            parent,
            mime,
            path,
        } => {
            let parent = parent.as_deref().map(object_id).transpose()?;
            let account = account(core)?;
            let base = if let Some(requested) = base {
                selected_base(&account, Some(requested))?
            } else if let Some(id) = parent {
                containing_base(&account, id)?
            } else {
                selected_base(&account, None)?
            };
            if let Some(id) = parent {
                let summary = base.get(id)?.ok_or(bh_core::Error::NotFound)?;
                if !matches!(
                    summary.ty.name.as_str(),
                    "core.note" | "core.folder" | "core.project"
                ) {
                    return Err(invalid("file parent must be a note, folder or project"));
                }
            }
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| invalid("file name must be UTF-8"))?;
            let bytes = std::fs::read(path)?;
            let id = base.add_file(
                NewFile {
                    parent,
                    name: name.into(),
                    mime: mime.clone(),
                },
                &bytes,
            )?;
            Ok(json!({ "id": id, "baseId": base.id(), "name": name }))
        }
    }
}
