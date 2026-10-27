use crate::{Result, account, selected_base};
use bh_core::Core;
use serde_json::{Value, to_value};
use std::path::Path;

pub(crate) async fn execute(core: &Core, base: &str, out: &Path) -> Result<Value> {
    let base = selected_base(&account(core)?, Some(base))?;
    let summary = base.export(out).await?;
    if !summary.missing_files.is_empty() {
        let names = summary
            .missing_files
            .iter()
            .map(|id| {
                base.file(*id)
                    .ok()
                    .flatten()
                    .map_or_else(|| id.to_string(), |file| format!("{} ({id})", file.name))
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "exported available content to {}; missing files: {names}",
            out.display()
        )
        .into());
    }
    Ok(to_value(summary)?)
}
