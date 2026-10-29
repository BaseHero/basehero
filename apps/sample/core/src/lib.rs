//! A small native sample: all credentials and records stay out of the WebView.
use bh_core::{
    Account, AccountId, AppIdentity, Base, BaseId, Core, CoreConfig, DeviceId, Digits, Error,
    FieldDef, FieldKind, Filter, Mode, NewObject, ObjectId, Op, Order, PendingConnection, Query,
    SecretStore, TypeDef, TypeRef, Url,
    models::{ChatRequest, Message, Role},
};
use serde_json::{Map, json};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::{Mutex, watch};

pub const READING: &str = "sample.reading";

// snippet:connect
mod connect_example {
    use bh_core::{Account, BaseId, Error, Mode, PendingConnection, TypeDef};
    use std::time::Duration;

    pub async fn finish(
        pending: &mut PendingConnection,
        ty: TypeDef,
    ) -> Result<(Account, BaseId), Error> {
        let account = pending.wait().await?;
        let base_id = account
            .bases()
            .first()
            .ok_or_else(|| Error::Invalid("no base grant".into()))?
            .id;
        let base = account.base(base_id)?;
        // A reinstalled app catches up before querying or creating a daily record.
        tokio::time::timeout(Duration::from_secs(30), base.sync_now())
            .await
            .map_err(|_| Error::Network("first catch-up timed out".into()))??;
        if base.mode() == Mode::ReadWrite {
            base.define_type(ty)?;
        }
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
    pub bases: Vec<String>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Reading {
    pub day: String,
    pub value: f64,
}
pub struct Sample {
    core: Core,
    server: Url,
    pending: Mutex<Option<PendingConnection>>,
    cancelled: watch::Sender<bool>,
}

impl Sample {
    pub fn open(data_dir: PathBuf, secrets: Arc<dyn SecretStore>) -> Result<Self, Error> {
        Self::open_with_server(
            data_dir,
            secrets,
            "https://dev-api.basehero.com/".parse().unwrap(),
        )
    }

    pub fn open_with_server(
        data_dir: PathBuf,
        secrets: Arc<dyn SecretStore>,
        server: Url,
    ) -> Result<Self, Error> {
        Ok(Self {
            core: Core::open(CoreConfig { data_dir, secrets })?,
            server,
            pending: Mutex::new(None),
            cancelled: watch::channel(false).0,
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
        let bases = account.bases();
        let base = bases.first()?.id;
        Some(Connected {
            account: account.id(),
            device: account.device_id(),
            base,
            bases: bases.into_iter().map(|summary| summary.name).collect(),
        })
    }

    /// Checks the server before presenting a saved connection; a revoked app erases its copy.
    pub async fn check_connection(&self) -> Result<Option<Connected>, Error> {
        if let Ok(account) = self.account()
            && matches!(account.refresh().await, Err(Error::Revoked))
        {
            account.sign_out().await?;
        }
        Ok(self.connected())
    }

    pub async fn connect_digits(&self, email: &str) -> Result<Digits, Error> {
        self.cancelled.send_replace(false);
        let mut cancelled = self.cancelled.subscribe();
        let mut pending = self
            .core
            .start_connection(
                self.server.clone(),
                email,
                AppIdentity {
                    name: "BaseHero Sample".into(),
                    app_id: "app.basehero.sample".into(),
                },
            )
            .await?;
        let digits = tokio::select! {
            result = pending.digits() => result,
            _ = cancelled.changed() => {
                pending.cancel().await?;
                return Err(Error::ApprovalEnded(bh_core::EndReason::Cancelled));
            }
        }?;
        *self.pending.lock().await = Some(pending);
        if *self.cancelled.borrow() {
            self.connect_cancel().await?;
            return Err(Error::ApprovalEnded(bh_core::EndReason::Cancelled));
        }
        Ok(digits)
    }

    pub async fn connect_finish(&self) -> Result<Connected, Error> {
        let mut pending = self.pending.lock().await.take().ok_or(Error::NotFound)?;
        let mut cancelled = self.cancelled.subscribe();
        let result = tokio::select! {
            result = connect_example::finish(&mut pending, reading_type()) => result,
            _ = cancelled.changed() => {
                pending.cancel().await?;
                return Err(Error::ApprovalEnded(bh_core::EndReason::Cancelled));
            }
        };
        let (account, base) = result?;
        Ok(Connected {
            account: account.id(),
            device: account.device_id(),
            base,
            bases: account
                .bases()
                .into_iter()
                .map(|summary| summary.name)
                .collect(),
        })
    }

    pub async fn connect_cancel(&self) -> Result<(), Error> {
        self.cancelled.send_replace(true);
        if let Some(mut pending) = self.pending.lock().await.take() {
            pending.cancel().await?;
        }
        Ok(())
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
