//! A small native sample: all credentials and records stay out of the WebView.
use bh_core::{
    Account, AccountId, Base, BaseId, Core, CoreConfig, DeviceId, Error, FieldDef, FieldKind,
    Filter, Mode, NewObject, ObjectId, Op, Order, Query, SecretStore, TypeDef, TypeRef,
    models::{ChatRequest, Message, Role},
};
use serde_json::{Map, json};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

pub const READING: &str = "sample.reading";
pub const CREDENTIALS_FILE: &str = "app-credentials.json";

// snippet:install
mod install_example {
    use bh_core::{Account, AppCredentials, BaseId, Core, Error, Mode, TypeDef};
    use std::{path::Path, time::Duration};

    pub async fn install_file(
        core: &Core,
        path: &Path,
        ty: TypeDef,
    ) -> Result<(Account, BaseId), Error> {
        // This file is private app storage, never passed to the WebView.
        let bytes = std::fs::read(path)?;
        let credentials: AppCredentials =
            serde_json::from_slice(&bytes).map_err(|e| Error::Invalid(e.to_string()))?;
        let base_id = *credentials
            .bases
            .first()
            .ok_or_else(|| Error::Invalid("no base grant".into()))?;
        let account = core.install_app(credentials).await?;
        let base = account.base(base_id)?;
        // A second installation must fetch existing records before query-and-create.
        tokio::time::timeout(Duration::from_secs(30), base.sync_now())
            .await
            .map_err(|_| Error::Network("first catch-up timed out".into()))??;
        if base.mode() == Mode::ReadWrite {
            base.define_type(ty)?;
        }
        std::fs::remove_file(path)?;
        Ok((account, base_id))
    }
}
// end-snippet

pub fn reading_type() -> TypeDef {
    TypeDef {
        name: READING.into(),
        version: 1,
        doc: "One sample measurement per calendar day; use day to find a reading".into(),
        title_field: None,
        fields: vec![
            FieldDef {
                name: "day".into(),
                kind: FieldKind::Date,
                required: true,
                unit: None,
                doc: "Local calendar day of measurement, YYYY-MM-DD".into(),
            },
            FieldDef {
                name: "value".into(),
                kind: FieldKind::Number,
                required: true,
                unit: Some("count".into()),
                doc: "Measured count for this day".into(),
            },
            FieldDef {
                name: "note".into(),
                kind: FieldKind::Text,
                required: false,
                unit: None,
                doc: "Optional explanation of the measurement".into(),
            },
        ],
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connected {
    pub account: AccountId,
    pub device: DeviceId,
    pub base: BaseId,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Reading {
    pub day: String,
    pub value: f64,
}
pub struct Sample {
    core: Core,
}

impl Sample {
    pub fn open(data_dir: PathBuf, secrets: Arc<dyn SecretStore>) -> Result<Self, Error> {
        Ok(Self {
            core: Core::open(CoreConfig { data_dir, secrets })?,
        })
    }

    fn account(&self) -> Result<Account, Error> {
        let id = self.core.accounts().first().ok_or(Error::NotFound)?.id;
        self.core.account(id)
    }
    fn base(&self) -> Result<Base, Error> {
        let account = self.account()?;
        let id = account.bases().first().ok_or(Error::NotFound)?.id;
        account.base(id)
    }
    pub fn connected(&self) -> Option<Connected> {
        let account = self.account().ok()?;
        let base = account.bases().first()?.id;
        Some(Connected {
            account: account.id(),
            device: account.device_id(),
            base,
        })
    }

    pub async fn install_file(&self, path: &Path) -> Result<Connected, Error> {
        let (account, base) =
            install_example::install_file(&self.core, path, reading_type()).await?;
        Ok(Connected {
            account: account.id(),
            device: account.device_id(),
            base,
        })
    }

    pub async fn write_reading(&self, day: &str, value: f64) -> Result<ObjectId, Error> {
        let base = self.base()?;
        if base.mode() == Mode::ReadOnly {
            return Err(Error::ReadOnly);
        }
        // Restarted installations must also catch up before creating a new day.
        if base.sync_state().last_synced_at.is_none() {
            tokio::time::timeout(Duration::from_secs(30), base.sync_now())
                .await
                .map_err(|_| Error::Network("first catch-up timed out".into()))??;
        }
        let query = Query {
            ty: READING.into(),
            filters: vec![Filter {
                field: "day".into(),
                op: Op::Eq,
                value: json!(day),
            }],
            order_by: Some(("day".into(), Order::Desc)),
            limit: Some(1),
        };
        let mut fields = Map::from_iter([("value".into(), json!(value))]);
        if let Some(found) = base.query(&query)?.first() {
            base.set_fields(found.id, fields)?;
            Ok(found.id)
        } else {
            fields.insert("day".into(), json!(day));
            base.create(NewObject {
                ty: TypeRef::new(READING, 1),
                parent: None,
                after: None,
                fields,
            })
        }
    }

    pub fn readings(&self) -> Result<Vec<Reading>, Error> {
        let base = self.base()?;
        let records = base.query(&Query {
            ty: READING.into(),
            filters: vec![],
            order_by: Some(("day".into(), Order::Desc)),
            limit: None,
        })?;
        records
            .into_iter()
            .map(|record| {
                Ok(Reading {
                    day: record
                        .fields
                        .get("day")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| Error::Invalid("reading day".into()))?
                        .into(),
                    value: record
                        .fields
                        .get("value")
                        .and_then(|v| v.as_f64())
                        .ok_or_else(|| Error::Invalid("reading value".into()))?,
                })
            })
            .collect()
    }

    pub async fn flush(&self) -> Result<(), Error> {
        self.base()?.flush().await
    }

    pub async fn ask_model(&self, question: &str) -> Result<String, Error> {
        let model = self.account()?.model()?;
        let reply = model
            .complete(ChatRequest {
                messages: vec![Message {
                    role: Role::User,
                    content: Some(question.into()),
                    tool_calls: vec![],
                    tool_call_id: None,
                }],
                tools: vec![],
                tool_choice: None,
                max_tokens: 64,
            })
            .await
            .map_err(|e| Error::Network(e.to_string()))?;
        Ok(reply.text.unwrap_or_default())
    }
}
