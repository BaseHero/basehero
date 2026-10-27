//! Hero's persisted chats and bounded private assistant turns.
pub(crate) mod access;
pub(crate) mod chat;
mod prompt;
#[cfg(all(test, feature = "test-support"))]
mod synthetic_tests;
pub(crate) mod tools;
mod turn;

use crate::{Account, AccountEvent, Base, BaseId, Error, NewObject, ObjectId, TypeRef};
use bh_models::ChatModel;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::{Notify, broadcast, watch};
use ts_rs::TS;
use turn::{ResultKind, TurnLimits};

/// Chat list item, newest first.
#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct ChatSummary {
    /// Chat object ID.
    #[ts(type = "string")]
    pub id: ObjectId,
    /// Display title.
    pub title: String,
    /// Optional project parent.
    #[ts(type = "string | null")]
    pub project: Option<ObjectId>,
    /// Last update time in milliseconds.
    #[ts(type = "number")]
    pub updated_at: i64,
}
/// Message author.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum ChatRole {
    /// The person.
    User,
    /// Hero.
    Hero,
}
/// Current state of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum MessageState {
    /// Finished.
    Done,
    /// Generating.
    Working,
    /// Cancelled.
    Stopped,
    /// Failed.
    Failed,
    /// Waiting for permission.
    Asking,
}
/// An action Hero took in a turn.
#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct Step {
    /// Tool name.
    pub tool: String,
    /// Base selected by the tool.
    #[ts(type = "string | null")]
    pub base: Option<BaseId>,
    /// Object involved, if any.
    #[ts(type = "string | null")]
    pub object: Option<ObjectId>,
    /// Safe display title.
    pub title: Option<String>,
}
/// Permission requested before Hero reads another base.
#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct Ask {
    /// Base awaiting permission.
    #[ts(type = "string")]
    pub base: BaseId,
    /// Human-readable name of the base.
    pub base_name: String,
    /// Apps with access to the chat base but not the requested base.
    pub readers_without: Vec<String>,
}
/// One persisted user or Hero message.
#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct ChatMessage {
    /// Message ID.
    #[ts(type = "string")]
    pub id: ObjectId,
    /// Author.
    pub role: ChatRole,
    /// Plain text body.
    pub text: String,
    /// RFC3339 creation timestamp.
    pub at: String,
    /// Lifecycle state.
    pub state: MessageState,
    /// Fixed, non-content error code.
    pub error: Option<String>,
    /// Completed tool actions.
    pub steps: Vec<Step>,
    /// Notes made in this turn.
    #[ts(type = "Array<string>")]
    pub created: Vec<ObjectId>,
    /// Permission prompt, if waiting.
    pub ask: Option<Ask>,
}
/// A chat was changed locally or by sync.
#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum HeroEvent {
    /// A chat's list or messages changed.
    Changed {
        /// Base containing the chat.
        #[ts(type = "string")]
        base: BaseId,
        /// Chat ID.
        #[ts(type = "string")]
        chat: ObjectId,
    },
}

struct Active {
    base: BaseId,
    message: ObjectId,
    cancel: watch::Sender<bool>,
}
struct Inner {
    account: Account,
    model: Arc<dyn ChatModel>,
    turns: Mutex<HashMap<ObjectId, Active>>,
    watched: Mutex<HashSet<BaseId>>,
    idle: Notify,
    running: Arc<Running>,
    events: broadcast::Sender<HeroEvent>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        for active in self.turns.lock().unwrap().values() {
            let _ = active.cancel.send(true);
        }
    }
}
/// An account's Hero controller; clones share active turns.
#[derive(Clone)]
pub struct Hero {
    inner: Arc<Inner>,
}
type Controllers = Mutex<HashMap<(crate::AccountId, crate::DeviceId), Weak<Inner>>>;
static HEROES: OnceLock<Controllers> = OnceLock::new();
static ALL_HEROES: OnceLock<Mutex<Vec<Weak<Inner>>>> = OnceLock::new();

pub(crate) async fn stop_account_turns(account: &Account) {
    let heroes: Vec<_> = ALL_HEROES
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|h| h.account.id() == account.id() && h.account.device_id() == account.device_id())
        .collect();
    for hero in &heroes {
        for active in hero.turns.lock().unwrap().values() {
            let _ = active.cancel.send(true);
        }
    }
    for hero in heroes {
        loop {
            let notified = hero.running.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if hero.running.count.load(Ordering::SeqCst) == 0 {
                break;
            }
            notified.await;
        }
    }
}

#[derive(Default)]
struct Running {
    count: AtomicUsize,
    idle: Notify,
}
struct RunningTurn(Arc<Running>);
impl Drop for RunningTurn {
    fn drop(&mut self) {
        self.0.count.fetch_sub(1, Ordering::SeqCst);
        self.0.idle.notify_waiters();
    }
}
impl Account {
    /// The process-wide Hero controller for this account and device.
    pub fn hero(&self) -> Hero {
        let map = HEROES.get_or_init(Default::default);
        let mut map = map.lock().unwrap();
        if let Some(inner) = map
            .get(&(self.id(), self.device_id()))
            .and_then(Weak::upgrade)
        {
            return Hero { inner };
        }
        let hero = Hero::new(self.clone(), self.model().expect("model configuration"));
        map.insert((self.id(), self.device_id()), Arc::downgrade(&hero.inner));
        hero
    }
    /// The account's configured, attested cloud model (also used by connected apps).
    pub fn model(&self) -> Result<Arc<dyn ChatModel>, Error> {
        crate::models::for_account(self)
    }
    /// A controller using a synthetic model; no live model calls in tests.
    #[cfg(feature = "test-support")]
    pub fn hero_with_model(&self, model: Arc<dyn ChatModel>) -> Hero {
        Hero::new(self.clone(), model)
    }
}
impl Hero {
    fn new(account: Account, model: Arc<dyn ChatModel>) -> Self {
        let (events, _) = broadcast::channel(128);
        let hero = Self {
            inner: Arc::new(Inner {
                account: account.clone(),
                model,
                turns: Mutex::new(HashMap::new()),
                watched: Mutex::new(HashSet::new()),
                idle: Notify::new(),
                running: Arc::new(Running::default()),
                events,
            }),
        };
        let weak = Arc::downgrade(&hero.inner);
        {
            let mut heroes = ALL_HEROES.get_or_init(Default::default).lock().unwrap();
            heroes.retain(|controller| controller.strong_count() > 0);
            heroes.push(weak.clone());
        }
        let mut changes = account.events();
        account.runtime().spawn(async move {
            while let Ok(event) = changes.recv().await {
                if let Some(inner) = weak.upgrade() {
                    if matches!(event, AccountEvent::BasesChanged | AccountEvent::Removed) {
                        let available: HashSet<_> =
                            inner.account.bases().into_iter().map(|b| b.id).collect();
                        let active: Vec<_> = inner
                            .turns
                            .lock()
                            .unwrap()
                            .iter()
                            .filter(|(_, a)| {
                                matches!(event, AccountEvent::Removed)
                                    || !available.contains(&a.base)
                            })
                            .map(|(id, a)| (*id, a.base))
                            .collect();
                        for (chat, base) in active {
                            let _ = (Hero {
                                inner: inner.clone(),
                            })
                            .stop(base, chat);
                        }
                    }
                } else {
                    break;
                }
            }
        });
        hero
    }
    fn base(&self, id: BaseId) -> Result<Base, Error> {
        let base = self.inner.account.base(id)?;
        if self.inner.watched.lock().unwrap().insert(id) {
            let weak = Arc::downgrade(&self.inner);
            let mut updates = base.events();
            self.inner.account.runtime().spawn(async move {
                while let Ok(event) = updates.recv().await {
                    let Some(inner) = weak.upgrade() else { break };
                    if let crate::BaseEvent::ObjectsChanged(ids) = event
                        && let Ok(base) = inner.account.base(id)
                    {
                        for changed in ids {
                            let chat = base.get(changed).ok().flatten().and_then(|s| {
                                if s.ty.name == "core.chat" {
                                    Some(changed)
                                } else if s.ty.name == "core.message" {
                                    s.parent
                                } else {
                                    None
                                }
                            });
                            if let Some(chat) = chat {
                                let _ = inner.events.send(HeroEvent::Changed { base: id, chat });
                            }
                        }
                    }
                }
            });
        }
        Ok(base)
    }
    /// Lists chats in this base, newest first.
    pub fn chats(&self, id: BaseId) -> Result<Vec<ChatSummary>, Error> {
        let base = self.base(id)?;
        let mut chats: Vec<_> = base
            .query(&crate::Query {
                ty: "core.chat".into(),
                filters: vec![],
                order_by: None,
                limit: None,
            })?
            .into_iter()
            .filter(|s| s.ty.name == "core.chat" && !s.deleted)
            .map(|s| {
                let messages = base.children(Some(s.id))?;
                let count = messages
                    .iter()
                    .filter(|m| m.ty.name == "core.message" && !m.deleted)
                    .count();
                let updated_at = messages
                    .iter()
                    .map(|m| m.updated_at)
                    .max()
                    .unwrap_or(s.updated_at)
                    .max(s.updated_at);
                Ok((
                    ChatSummary {
                        id: s.id,
                        title: s.title,
                        project: s
                            .fields
                            .get("project")
                            .and_then(Value::as_str)
                            .and_then(|s| s.parse().ok()),
                        updated_at,
                    },
                    count,
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        chats.sort_by_key(|(chat, count)| std::cmp::Reverse((chat.updated_at, *count, chat.id)));
        Ok(chats.into_iter().map(|(chat, _)| chat).collect())
    }
    /// Gets or creates the chat for a project, or the newest top-level chat.
    pub fn chat_for(&self, base: BaseId, project: Option<ObjectId>) -> Result<ObjectId, Error> {
        if let Some(chat) = self.chats(base)?.into_iter().find(|s| s.project == project) {
            return Ok(chat.id);
        }
        self.make_chat(base, project)
    }
    /// Starts a fresh top-level chat.
    pub fn new_chat(&self, base: BaseId) -> Result<ObjectId, Error> {
        self.make_chat(base, None)
    }
    fn make_chat(&self, id: BaseId, project: Option<ObjectId>) -> Result<ObjectId, Error> {
        let base = self.base(id)?;
        if let Some(p) = project
            && base
                .get(p)?
                .filter(|s| s.ty.name == "core.project" && !s.deleted)
                .is_none()
        {
            return Err(Error::NotFound);
        }
        let mut fields = Map::new();
        fields.insert("title".into(), json!("New chat"));
        if let Some(p) = project {
            fields.insert("project".into(), json!(p));
        }
        let chat = base.create(NewObject {
            ty: TypeRef::new("core.chat", 1),
            parent: project,
            after: None,
            fields,
        })?;
        self.changed(id, chat);
        Ok(chat)
    }
    fn changed(&self, base: BaseId, chat: ObjectId) {
        let _ = self.inner.events.send(HeroEvent::Changed { base, chat });
    }
    fn ensure_chat(&self, base: &Base, chat: ObjectId) -> Result<crate::ObjectSummary, Error> {
        base.get(chat)?
            .filter(|s| !s.deleted && s.ty.name == "core.chat")
            .ok_or(Error::NotFound)
    }
    /// Lists a chat's messages, marking interrupted local work after a restart.
    pub fn messages(&self, id: BaseId, chat: ObjectId) -> Result<Vec<ChatMessage>, Error> {
        let base = self.base(id)?;
        self.ensure_chat(&base, chat)?;
        let mut result = vec![];
        for entry in base
            .children(Some(chat))?
            .into_iter()
            .filter(|s| !s.deleted && s.ty.name == "core.message")
        {
            let mut message = parse_message(&entry)?;
            if message.state == MessageState::Working
                && entry.fields.get("device").and_then(Value::as_str)
                    == Some(self.inner.account.device_id().to_string().as_str())
                && !self.inner.turns.lock().unwrap().contains_key(&chat)
            {
                let mut fields = entry.fields.clone();
                fields.insert("state".into(), json!("failed"));
                fields.insert("error".into(), json!("interrupted"));
                base.set_fields(entry.id, fields)?;
                message.state = MessageState::Failed;
                message.error = Some("interrupted".into());
                self.changed(id, chat);
            }
            result.push(message);
        }
        Ok(result)
    }
    /// Appends a user message and starts a turn. A concurrent send returns `busy`.
    pub fn send(
        &self,
        id: BaseId,
        chat: ObjectId,
        text: &str,
        focus: Option<ObjectId>,
    ) -> Result<ObjectId, Error> {
        let base = self.base(id)?;
        let summary = self.ensure_chat(&base, chat)?;
        if base.mode() == crate::Mode::ReadOnly {
            return Err(Error::ReadOnly);
        }
        let history = self.messages(id, chat)?;
        let mut turns = self.inner.turns.lock().unwrap();
        self.inner.account.check_active()?;
        if turns.contains_key(&chat) {
            return Err(Error::Conflict("busy".into()));
        }
        let mut fields = message_fields("user", "done", text, self.inner.account.device_id());
        if let Some(focus) = focus {
            fields.insert("focus".into(), json!(focus));
        }
        let user = base.create(NewObject {
            ty: TypeRef::new("core.message", 1),
            parent: Some(chat),
            after: None,
            fields,
        })?;
        let working = base.create(NewObject {
            ty: TypeRef::new("core.message", 1),
            parent: Some(chat),
            after: None,
            fields: message_fields("hero", "working", "", self.inner.account.device_id()),
        })?;
        let (cancel, receiver) = watch::channel(false);
        turns.insert(
            chat,
            Active {
                base: id,
                message: working,
                cancel,
            },
        );
        self.changed(id, chat);
        let mut all = history;
        all.push(parse_message(&base.get(user)?.ok_or(Error::NotFound)?)?);
        self.launch(
            id,
            chat,
            working,
            focus,
            summary
                .fields
                .get("project")
                .and_then(Value::as_str)
                .and_then(|s| s.parse().ok()),
            all,
            receiver,
        );
        drop(turns);
        Ok(user)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "the turn's persisted identity, context and cancellation are distinct"
    )]
    fn launch(
        &self,
        id: BaseId,
        chat: ObjectId,
        message: ObjectId,
        focus: Option<ObjectId>,
        project: Option<ObjectId>,
        history: Vec<ChatMessage>,
        cancel: watch::Receiver<bool>,
    ) {
        let weak = Arc::downgrade(&self.inner);
        self.inner.running.count.fetch_add(1, Ordering::SeqCst);
        let running = RunningTurn(self.inner.running.clone());
        self.inner.account.runtime().spawn(async move {
            let _running = running;
            let Some(inner) = weak.upgrade() else { return };
            let hero = Hero { inner };
            let base = match hero.base(id) {
                Ok(b) => b,
                Err(_) => {
                    hero.finish(
                        id,
                        chat,
                        message,
                        ResultKind::Failed("failed"),
                        vec![],
                        vec![],
                    );
                    return;
                }
            };
            let request = match prompt::build(&base, focus, project, &history) {
                Ok(r) => r,
                Err(_) => {
                    hero.finish(
                        id,
                        chat,
                        message,
                        ResultKind::Failed("failed"),
                        vec![],
                        vec![],
                    );
                    return;
                }
            };
            let chat_info = match hero.ensure_chat(&base, chat) {
                Ok(c) => c,
                Err(_) => {
                    hero.finish(
                        id,
                        chat,
                        message,
                        ResultKind::Failed("failed"),
                        vec![],
                        vec![],
                    );
                    return;
                }
            };
            let clock = hero.inner.account.clock();
            let readers_fresh = tokio::select! {
                result = hero.inner.account.refresh_account_data() => result.is_ok(),
                _ = clock.sleep_until(clock.now_ms().saturating_add(10_000)) => false,
            };
            let mut tools = hero.tools(id, project, &chat_info, readers_fresh);
            let model = hero.inner.model.clone();
            drop(base);
            drop(hero);
            let outcome = turn::run(
                model.as_ref(),
                &mut tools,
                request,
                TurnLimits::default(),
                cancel,
                |step, created| {
                    let Some(inner) = weak.upgrade() else { return };
                    let hero = Hero { inner };
                    let turns = hero.inner.turns.lock().unwrap();
                    if turns
                        .get(&chat)
                        .is_some_and(|a| a.message == message && !*a.cancel.borrow())
                        && let Ok(base) = hero.base(id)
                        && let Ok(Some(entry)) = base.get(message)
                    {
                        let mut fields = entry.fields;
                        let mut steps: Vec<Step> = serde_json::from_value(
                            fields.get("steps").cloned().unwrap_or(json!([])),
                        )
                        .unwrap_or_default();
                        steps.push(step.clone());
                        fields.insert("steps".into(), json!(steps));
                        fields.insert("created".into(), json!(created));
                        let _ = base.set_fields(message, fields);
                        hero.changed(id, chat);
                    }
                },
                |tools, call| {
                    let inner = weak.upgrade()?;
                    let turns = inner.turns.lock().unwrap();
                    if turns
                        .get(&chat)
                        .is_some_and(|a| a.message == message && !*a.cancel.borrow())
                    {
                        Some(tools.call(call))
                    } else {
                        None
                    }
                },
            )
            .await;
            if let Some(inner) = weak.upgrade() {
                (Hero { inner }).finish(
                    id,
                    chat,
                    message,
                    outcome.kind,
                    outcome.steps,
                    outcome.created,
                );
            }
        });
    }
    fn tools(
        &self,
        id: BaseId,
        project: Option<ObjectId>,
        chat: &crate::ObjectSummary,
        readers_fresh: bool,
    ) -> tools::Tools {
        let summaries = self.inner.account.bases();
        let current = summaries.iter().find(|b| b.id == id);
        let allowed: Vec<BaseId> =
            serde_json::from_value(chat.fields.get("allowed").cloned().unwrap_or(json!([])))
                .unwrap_or_default();
        let denied: Vec<BaseId> =
            serde_json::from_value(chat.fields.get("denied").cloned().unwrap_or(json!([])))
                .unwrap_or_default();
        let others = summaries
            .iter()
            .filter(|s| s.id != id)
            .filter_map(|s| {
                let current = current?;
                let permission = if !readers_fresh && !s.hidden && !denied.contains(&s.id) {
                    access::Access::Ask
                } else {
                    access::access(
                        current,
                        s,
                        &self.inner.account.app_readers(id),
                        &self.inner.account.app_readers(s.id),
                        &allowed,
                        &denied,
                    )
                };
                self.inner.account.base(s.id).ok().map(|b| (b, permission))
            })
            .collect();
        tools::Tools::new(
            self.inner.account.base(id).expect("open chat base"),
            others,
            project,
        )
    }
    fn finish(
        &self,
        id: BaseId,
        chat: ObjectId,
        message: ObjectId,
        kind: ResultKind,
        steps: Vec<Step>,
        created: Vec<ObjectId>,
    ) {
        let mut turns = self.inner.turns.lock().unwrap();
        if turns
            .get(&chat)
            .is_none_or(|a| a.message != message || *a.cancel.borrow())
        {
            return;
        }
        if let Ok(base) = self.base(id)
            && let Ok(Some(entry)) = base.get(message)
        {
            let mut fields = entry.fields;
            let (state, text, error, ask) = match kind {
                ResultKind::Answer(t) => ("done", t, None, None),
                ResultKind::Failed(c) => ("failed", String::new(), Some(c), None),
                ResultKind::Stopped => ("stopped", String::new(), None, None),
                ResultKind::Ask(requested) => {
                    let readers = self.inner.account.app_readers(id);
                    let other = self.inner.account.app_readers(requested);
                    let names = readers
                        .difference(&other)
                        .map(|r| self.inner.account.app_reader_name(*r))
                        .collect();
                    let name = self
                        .inner
                        .account
                        .bases()
                        .into_iter()
                        .find(|b| b.id == requested)
                        .map_or(String::new(), |b| b.name);
                    (
                        "asking",
                        String::new(),
                        None,
                        Some(Ask {
                            base: requested,
                            base_name: name,
                            readers_without: names,
                        }),
                    )
                }
            };
            fields.insert("state".into(), json!(state));
            fields.insert("text".into(), json!(text));
            fields.insert("steps".into(), json!(steps));
            fields.insert("created".into(), json!(created));
            if let Some(e) = error {
                fields.insert("error".into(), json!(e));
            } else {
                fields.remove("error");
            }
            if let Some(a) = ask {
                fields.insert("ask".into(), json!(a));
            } else {
                fields.remove("ask");
            }
            let _ = base.set_fields(message, fields);
        }
        turns.remove(&chat);
        self.inner.idle.notify_waiters();
        self.changed(id, chat);
    }
    /// Cancels the in-flight call and atomically persists Stopped.
    pub fn stop(&self, id: BaseId, chat: ObjectId) -> Result<(), Error> {
        let mut turns = self.inner.turns.lock().unwrap();
        if let Some(active) = turns.get(&chat) {
            if active.base != id {
                return Err(Error::NotFound);
            }
            let _ = active.cancel.send(true);
            // The base may already be gone. Cancellation still wins over a late reply.
            if let Ok(base) = self.base(id)
                && let Ok(Some(entry)) = base.get(active.message)
            {
                let mut fields = entry.fields;
                fields.insert("state".into(), json!("stopped"));
                let _ = base.set_fields(active.message, fields);
            }
            turns.remove(&chat);
            self.inner.idle.notify_waiters();
            self.changed(id, chat);
            return Ok(());
        }
        drop(turns);
        let base = self.base(id)?;
        self.ensure_chat(&base, chat)?;
        Ok(())
    }
    /// Answers a permission request and reruns the last user message.
    pub fn answer(&self, id: BaseId, chat: ObjectId, allow: bool) -> Result<(), Error> {
        let messages = self.messages(id, chat)?;
        let ask = messages
            .iter()
            .rev()
            .find(|m| m.role == ChatRole::Hero)
            .and_then(|m| m.ask.as_ref())
            .ok_or(Error::NotFound)?;
        let base = self.base(id)?;
        let summary = self.ensure_chat(&base, chat)?;
        let mut fields = summary.fields;
        let key = if allow { "allowed" } else { "denied" };
        let mut ids: Vec<BaseId> =
            serde_json::from_value(fields.get(key).cloned().unwrap_or(json!([])))
                .unwrap_or_default();
        if !ids.contains(&ask.base) {
            ids.push(ask.base)
        }
        fields.insert(key.into(), json!(ids));
        base.set_fields(chat, fields)?;
        self.retry(id, chat)
    }
    /// Reruns the last user message without changing chat permissions.
    pub fn retry(&self, id: BaseId, chat: ObjectId) -> Result<(), Error> {
        let base = self.base(id)?;
        let summary = self.ensure_chat(&base, chat)?;
        let messages = self.messages(id, chat)?;
        let mut turns = self.inner.turns.lock().unwrap();
        self.inner.account.check_active()?;
        if turns.contains_key(&chat) {
            return Err(Error::Conflict("busy".into()));
        }
        let user = messages
            .iter()
            .rev()
            .find(|m| m.role == ChatRole::User)
            .ok_or(Error::NotFound)?;
        let focus = base.get(user.id)?.and_then(|s| {
            s.fields
                .get("focus")
                .and_then(Value::as_str)
                .and_then(|s| s.parse().ok())
        });
        let existing = messages
            .iter()
            .rev()
            .find(|m| m.role == ChatRole::Hero)
            .ok_or(Error::NotFound)?
            .id;
        let mut fields = base.get(existing)?.ok_or(Error::NotFound)?.fields;
        fields.insert("state".into(), json!("working"));
        fields.insert("text".into(), json!(""));
        fields.remove("error");
        fields.remove("ask");
        fields.insert("steps".into(), json!([]));
        base.set_fields(existing, fields)?;
        let (cancel, receiver) = watch::channel(false);
        turns.insert(
            chat,
            Active {
                base: id,
                message: existing,
                cancel,
            },
        );
        self.launch(
            id,
            chat,
            existing,
            focus,
            summary
                .fields
                .get("project")
                .and_then(Value::as_str)
                .and_then(|s| s.parse().ok()),
            messages.into_iter().filter(|m| m.id != existing).collect(),
            receiver,
        );
        drop(turns);
        Ok(())
    }
    /// Subscribes to changed chats, including changes received by sync.
    pub fn events(&self) -> broadcast::Receiver<HeroEvent> {
        self.inner.events.subscribe()
    }
    /// Waits until this process has no active turn for the chat.
    pub async fn wait_idle(&self, chat: ObjectId) {
        loop {
            let notified = self.inner.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.inner.turns.lock().unwrap().contains_key(&chat) {
                return;
            }
            notified.await;
        }
    }
}
fn message_fields(
    role: &str,
    state: &str,
    text: &str,
    device: crate::DeviceId,
) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("role".into(), json!(role));
    map.insert("state".into(), json!(state));
    map.insert("text".into(), json!(text));
    map.insert("at".into(), json!(format!("{}T00:00:00Z", prompt_date())));
    map.insert("device".into(), json!(device.to_string()));
    map
}
fn prompt_date() -> String {
    // RFC3339 date from the same civil-day calculation used by the prompt.
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() / 86400) as i64;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    y += i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}
fn parse_message(s: &crate::ObjectSummary) -> Result<ChatMessage, Error> {
    let value = |key: &str| {
        s.fields
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let role = match value("role").as_str() {
        "user" => ChatRole::User,
        "hero" => ChatRole::Hero,
        _ => return Err(Error::invalid("invalid message")),
    };
    let state = match value("state").as_str() {
        "done" => MessageState::Done,
        "working" => MessageState::Working,
        "stopped" => MessageState::Stopped,
        "failed" => MessageState::Failed,
        "asking" => MessageState::Asking,
        _ => return Err(Error::invalid("invalid message")),
    };
    Ok(ChatMessage {
        id: s.id,
        role,
        text: value("text"),
        at: value("at"),
        state,
        error: s
            .fields
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_owned),
        steps: serde_json::from_value(s.fields.get("steps").cloned().unwrap_or(json!([])))
            .unwrap_or_default(),
        created: serde_json::from_value(s.fields.get("created").cloned().unwrap_or(json!([])))
            .unwrap_or_default(),
        ask: s
            .fields
            .get("ask")
            .and_then(|v| serde_json::from_value(v.clone()).ok()),
    })
}
