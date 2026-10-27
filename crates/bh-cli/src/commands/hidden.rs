//! CLI operations for hidden bases. Passwords are never included in results or errors.
use bh_core::{Account, BaseSummary, password_strength};
use clap::Subcommand;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{Result, approve::terminal_device_name, hidden_password, invalid};

#[derive(Subcommand)]
pub(crate) enum HiddenCommand {
    Create { name: String },
    Unlock,
    Strength,
}

pub(crate) fn rendered_summary(mut summary: Value) -> Value {
    if let Some(name) = summary.get_mut("name")
        && let Some(raw) = name.as_str()
    {
        *name = Value::String(terminal_device_name(raw));
    }
    summary
}

pub(crate) fn summaries(summaries: Vec<BaseSummary>) -> Result<Value> {
    Ok(Value::Array(
        summaries
            .into_iter()
            .map(|summary| serde_json::to_value(summary).map(rendered_summary))
            .collect::<std::result::Result<Vec<_>, _>>()?,
    ))
}

pub(crate) async fn execute(account: &Account, command: &HiddenCommand) -> Result<Value> {
    match command {
        HiddenCommand::Create { name } => {
            let password = hidden_password()?;
            if std::env::var_os("BH_HIDDEN_PASSWORD").is_none() {
                let confirmation = Zeroizing::new(rpassword::prompt_password("Type it again: ")?);
                if *password != *confirmation {
                    return Err(invalid("passwords do not match"));
                }
            }
            let base = account.create_hidden_base(name, password).await?;
            Ok(json!({ "id": base.id(), "name": terminal_device_name(&base.name()) }))
        }
        HiddenCommand::Unlock => summaries(account.unlock_hidden(hidden_password()?).await?),
        HiddenCommand::Strength => {
            let password = hidden_password()?;
            Ok(serde_json::to_value(password_strength(&password, &[]))?)
        }
    }
}
