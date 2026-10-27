use bh_core::{Account, Error, ObjectId};
use serde_json::{Value, json};

use crate::{Result, object_id, selected_base};

pub(super) async fn list(
    account: &Account,
    base: &str,
    id: &str,
    before: Option<u64>,
) -> Result<Value> {
    let base = selected_base(account, Some(base))?;
    let id = object_id(id)?;
    if base.get(id)?.is_none() {
        return Err(Box::new(Error::NotFound));
    }
    let (versions, more) = base.versions(id, before, 50).await?;
    Ok(json!({ "versions": versions, "more": more }))
}

pub(super) async fn restore(account: &Account, base: &str, id: &str, seq: u64) -> Result<Value> {
    let base = selected_base(account, Some(base))?;
    let id: ObjectId = object_id(id)?;
    base.restore_version(id, seq).await?;
    Ok(json!({ "id": id, "seq": seq }))
}
