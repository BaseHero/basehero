//! Hero's persisted chats and bounded private assistant turns.
pub(crate) mod access;
pub(crate) mod chat;
mod prompt;
#[cfg(all(test, feature = "test-support"))]
mod synthetic_tests;
pub(crate) mod tools;
mod turn;

use crate::base::BaseWeak;
use crate::{Account, AccountEvent, Base, BaseId, DeviceKind, Error, NewObject, ObjectId, TypeRef};
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
use turn::{ResultKind, TurnLimits, TurnOutcome};

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
/// A chat was changed locally or by sync, or Hero's reply grew.
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
    /// The working message's text so far, at most every 100 ms; not yet saved.
    Text {
        /// Base containing the chat.
        #[ts(type = "string")]
        base: BaseId,
        /// Chat ID.
        #[ts(type = "string")]
        chat: ObjectId,
        /// The working Hero message.
        #[ts(type = "string")]
        message: ObjectId,
        /// The reply so far.
        text: String,
    },
}

struct Active {
    base: BaseId,
    message: ObjectId,
    cancel: watch::Sender<bool>,
    /// The reply so far, saved at most every two seconds.
    text: String,
}
/// Whether a turn task still owns its chat's running turn; the caller holds the turns lock.
/// The task's own `cancel` also rules out a later turn that reuses the message.
fn owns_turn(
    turns: &HashMap<ObjectId, Active>,
    chat: ObjectId,
    message: ObjectId,
    cancel: &watch::Receiver<bool>,
) -> bool {
    !*cancel.borrow()
        && turns
            .get(&chat)
            .is_some_and(|a| a.message == message && !*a.cancel.borrow())
}
/// How often a running turn shows and saves its reply.
const SHOW_MS: u64 = 100;
const SAVE_MS: u64 = 2_000;
struct Inner {
    account: Account,
    model: Option<Arc<dyn ChatModel>>,
    turns: Mutex<HashMap<ObjectId, Active>>,
    tasks: Mutex<HashMap<BaseId, Vec<tokio::task::JoinHandle<()>>>>,
    watched: Mutex<HashMap<BaseId, BaseWeak>>,
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

pub(crate) async fn cancel_account_base(account: &Account, base: &Base) {
    let heroes: Vec<_> = ALL_HEROES
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|h| h.account.id() == account.id() && h.account.device_id() == account.device_id())
        .map(|inner| Hero { inner })
        .collect();
    for hero in heroes {
        hero.cancel_base(base).await;
    }
}

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
        let hero = Hero::new(self.clone(), None);
        map.insert((self.id(), self.device_id()), Arc::downgrade(&hero.inner));
        hero
    }
    /// The account's configured cloud model (also used by connected apps).
    /// Constructing the handle is local; completing a request needs the network.
    ///
    /// ```no_run
    /// use bh_core::{Account, Error, models::{ChatModel, ChatRequest, Message, Role}};
    /// async fn ask(account: &Account) -> Result<(), Error> {
    ///     let model = account.model()?;
    ///     let answer = model.complete(ChatRequest {
    ///         messages: vec![Message { role: Role::User,
    ///             content: Some("Reply briefly.".into()), tool_calls: vec![],
    ///             tool_call_id: None }],
    ///         tools: vec![], tool_choice: None, max_tokens: 64,
    ///     }).await;
    ///     let _text = answer.map_err(|e| Error::Network(e.to_string()))?.text;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] for a malformed gateway URL,
    /// [`Error::Storage`] for missing local credentials, or [`Error::Crypto`]
    /// for a local key failure. Completion errors are [`crate::models::ModelError`].
    pub fn model(&self) -> Result<Arc<dyn ChatModel>, Error> {
        crate::models::for_account(self, None)
    }
    /// The cloud model attributed to a base this device can open. Handle creation
    /// is local; completion needs the network and the server rechecks the grant.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] if the base cannot be opened, or local
    /// configuration, storage or key errors from [`Self::model`].
    pub fn model_for(&self, base: BaseId) -> Result<Arc<dyn ChatModel>, Error> {
        self.base(base).map_err(|error| {
            if error == Error::NotFound {
                Error::Forbidden
            } else {
                error
            }
        })?;
        crate::models::for_account(self, Some(base))
    }
    /// A controller using a synthetic model; no live model calls in tests.
    #[cfg(feature = "test-support")]
    pub fn hero_with_model(&self, model: Arc<dyn ChatModel>) -> Hero {
        Hero::new(self.clone(), Some(model))
    }
}
impl Hero {
    fn new(account: Account, model: Option<Arc<dyn ChatModel>>) -> Self {
        let (events, _) = broadcast::channel(128);
        let hero = Self {
            inner: Arc::new(Inner {
                account: account.clone(),
                model,
                turns: Mutex::new(HashMap::new()),
                tasks: Mutex::new(HashMap::new()),
                watched: Mutex::new(HashMap::new()),
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
        let watch = base.downgrade();
        let needs_watch = {
            let mut watched = self.inner.watched.lock().unwrap();
            if watched.get(&id).is_some_and(|old| old.is_same(&watch)) {
                false
            } else {
                watched.insert(id, watch.clone());
                true
            }
        };
        if needs_watch {
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
                if let Some(inner) = weak.upgrade() {
                    let mut watched = inner.watched.lock().unwrap();
                    if watched.get(&id).is_some_and(|old| old.is_same(&watch)) {
                        watched.remove(&id);
                    }
                }
            });
        }
        Ok(base)
    }
    /// Lists chats in this base, newest first.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] for an ungranted base,
    /// [`Error::NeedsUpdate`] for unknown data, or [`Error::Storage`] for a
    /// local read failure.
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
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] for an unknown project/base, or local edit
    /// errors from [`Base::create`] including [`Error::ReadOnly`],
    /// [`Error::NeedsUpdate`], [`Error::Invalid`] and [`Error::Storage`].
    pub fn chat_for(&self, base: BaseId, project: Option<ObjectId>) -> Result<ObjectId, Error> {
        if let Some(chat) = self.chats(base)?.into_iter().find(|s| s.project == project) {
            return Ok(chat.id);
        }
        self.make_chat(base, project)
    }
    /// Starts a fresh top-level chat.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] for an ungranted base, or edit errors
    /// from [`Base::create`] including [`Error::ReadOnly`], [`Error::Invalid`]
    /// and [`Error::Storage`].
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
    /// Hero's request to read `requested` from a chat in `id`, as this device sees
    /// it: its name and the readers who'd gain it come from this device's own
    /// records. None for the chat's own base, a hidden base or an unknown one.
    fn ask_for(&self, id: BaseId, requested: BaseId) -> Option<Ask> {
        if requested == id {
            return None;
        }
        let summary = self
            .inner
            .account
            .bases()
            .into_iter()
            .find(|b| b.id == requested && !b.hidden)?;
        let readers = self.inner.account.app_readers(id);
        let other = self.inner.account.app_readers(requested);
        Some(Ask {
            base: requested,
            base_name: summary.name,
            readers_without: readers
                .difference(&other)
                .map(|r| self.inner.account.app_reader_name(*r))
                .collect(),
        })
    }
    /// Lists a chat's messages, marking interrupted local work after a restart.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] for an unknown chat/base, or local read or
    /// edit errors such as [`Error::NeedsUpdate`], [`Error::ReadOnly`] or
    /// [`Error::Storage`].
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
            // An app with this base can write a message: trust only the base ID,
            // and only on a message that is asking.
            let asking = message.state == MessageState::Asking;
            message.ask = message
                .ask
                .take()
                .filter(|_| asking)
                .and_then(|ask| self.ask_for(id, ask.base));
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
            if let Some(active) = self
                .inner
                .turns
                .lock()
                .unwrap()
                .get(&chat)
                .filter(|a| a.message == entry.id)
            {
                message.text.clone_from(&active.text);
            }
            result.push(message);
        }
        Ok(result)
    }
    /// Appends a user message and starts a turn. A concurrent send returns `busy`.
    /// The turn runs asynchronously and needs the network for a live model;
    /// sending the local message itself does not.
    ///
    /// # Errors
    /// Returns [`Error::Conflict`] for a turn already running,
    /// [`Error::ReadOnly`] for a read-only base, [`Error::NotFound`] for an
    /// unknown chat/base, or local errors such as [`Error::Revoked`],
    /// [`Error::Invalid`], [`Error::NeedsUpdate`] and [`Error::Storage`].
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
                text: String::new(),
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
        mut cancel: watch::Receiver<bool>,
    ) {
        let weak = Arc::downgrade(&self.inner);
        self.inner.running.count.fetch_add(1, Ordering::SeqCst);
        let running = RunningTurn(self.inner.running.clone());
        let task = self.inner.account.runtime().spawn(async move {
            let _running = running;
            let Some(inner) = weak.upgrade() else { return };
            let hero = Hero { inner };
            let base = match hero.base(id) {
                Ok(b) => b,
                Err(_) => {
                    hero.finish(id, chat, message, TurnOutcome::failed());
                    return;
                }
            };
            let request = match prompt::build(&base, focus, project, &history) {
                Ok(r) => r,
                Err(_) => {
                    hero.finish(id, chat, message, TurnOutcome::failed());
                    return;
                }
            };
            let chat_info = match hero.ensure_chat(&base, chat) {
                Ok(c) => c,
                Err(_) => {
                    hero.finish(id, chat, message, TurnOutcome::failed());
                    return;
                }
            };
            let clock = hero.inner.account.clock();
            let readers_fresh = tokio::select! {
                biased;
                _ = cancel.changed() => return,
                result = hero.inner.account.refresh_account_data() => result.is_ok(),
                _ = clock.sleep_until(clock.now_ms().saturating_add(10_000)) => false,
            };
            if *cancel.borrow() {
                return;
            }
            let mut tools = hero.tools(base.clone(), project, chat_info.id, readers_fresh);
            let model = match &hero.inner.model {
                Some(model) => model.clone(),
                None => match hero.inner.account.model_for(id) {
                    Ok(model) => model,
                    Err(_) => {
                        hero.finish(id, chat, message, TurnOutcome::failed());
                        return;
                    }
                },
            };
            drop(hero);
            let own = cancel.clone();
            // Text shows at most every SHOW_MS and at the end of each call, and is
            // saved at most every SAVE_MS; the turn's end saves the whole reply.
            let (mut shown, mut shown_at) = (0, None::<u64>);
            let (mut saved, mut saved_at) = (0, clock.now_ms());
            let outcome = turn::run(
                model.as_ref(),
                &mut tools,
                request,
                TurnLimits::default(),
                cancel,
                |text, ended| {
                    let Some(inner) = weak.upgrade() else { return };
                    let mut turns = inner.turns.lock().unwrap();
                    if !owns_turn(&turns, chat, message, &own) {
                        return;
                    }
                    if let Some(active) = turns.get_mut(&chat) {
                        text.clone_into(&mut active.text);
                    }
                    let now = clock.now_ms();
                    if text.len() != shown
                        && (ended || shown_at.is_none_or(|at| now >= at.saturating_add(SHOW_MS)))
                    {
                        (shown, shown_at) = (text.len(), Some(now));
                        let _ = inner.events.send(HeroEvent::Text {
                            base: id,
                            chat,
                            message,
                            text: text.to_owned(),
                        });
                    }
                    if text.len() != saved
                        && now >= saved_at.saturating_add(SAVE_MS)
                        && let Ok(Some(entry)) = base.get(message)
                    {
                        (saved, saved_at) = (text.len(), now);
                        let mut fields = entry.fields;
                        fields.insert("text".into(), json!(text));
                        let _ = base.set_fields(message, fields);
                    }
                },
                |step, created| {
                    let Some(inner) = weak.upgrade() else { return };
                    let hero = Hero { inner };
                    let turns = hero.inner.turns.lock().unwrap();
                    if owns_turn(&turns, chat, message, &own)
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
                    if owns_turn(&turns, chat, message, &own) {
                        Some(tools.call(call))
                    } else {
                        None
                    }
                },
            )
            .await;
            if let Some(inner) = weak.upgrade() {
                (Hero { inner }).finish(id, chat, message, outcome);
            }
        });
        let mut tasks = self.inner.tasks.lock().unwrap();
        let group = tasks.entry(id).or_default();
        group.retain(|task| !task.is_finished());
        group.push(task);
    }
    fn tools(
        &self,
        chat_base: Base,
        project: Option<ObjectId>,
        chat: ObjectId,
        readers_fresh: bool,
    ) -> tools::Tools {
        let id = chat_base.id();
        let summaries = self.inner.account.bases();
        let current = summaries.iter().find(|b| b.id == id);
        let (allowed, denied) = self.inner.account.hero_permissions(id, chat);
        // An app device can't know who else reads a base, nor answer a prompt.
        let app_device = self.inner.account.kind() == DeviceKind::App;
        let others = summaries
            .iter()
            .filter(|s| s.id != id)
            .filter_map(|s| {
                let current = current?;
                let permission = if app_device {
                    access::Access::Never
                } else if !readers_fresh && !s.hidden && !denied.contains(&s.id) {
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
        let mounts = self
            .inner
            .account
            .mounts()
            .into_iter()
            .map(|mount| (mount.folder, mount.parent, mount.base))
            .collect();
        tools::Tools::new(chat_base, others, project).with_mounts(mounts)
    }
    fn finish(&self, id: BaseId, chat: ObjectId, message: ObjectId, outcome: TurnOutcome) {
        let TurnOutcome {
            kind,
            text,
            steps,
            created,
        } = outcome;
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
                ResultKind::Answer => ("done", text, None, None),
                ResultKind::Failed(c) => ("failed", text, Some(c), None),
                ResultKind::Stopped => ("stopped", text, None, None),
                ResultKind::Ask(requested) => match self.ask_for(id, requested) {
                    Some(ask) => ("asking", String::new(), None, Some(ask)),
                    None => ("failed", text, Some("failed"), None),
                },
            };
            fields.insert("state".into(), json!(state));
            fields.insert("text".into(), json!(text));
            fields.insert("steps".into(), json!(steps));
            fields.insert("created".into(), json!(created));
            if let Some(e) = error {
                fields.insert("error".into(), json!(e));
            } else {
                fields.insert("error".into(), json!(null));
            }
            if let Some(a) = ask {
                fields.insert("ask".into(), json!(a));
            } else {
                fields.insert("ask".into(), json!(null));
            }
            let _ = base.set_fields(message, fields);
        }
        turns.remove(&chat);
        self.inner.idle.notify_waiters();
        self.changed(id, chat);
    }
    /// Cancels the in-flight call and persists Stopped locally; no separate
    /// network request is made.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] for a chat in another base, or local
    /// errors such as [`Error::Storage`] and [`Error::NeedsUpdate`] if no
    /// active turn exists and the chat cannot be opened.
    pub fn stop(&self, id: BaseId, chat: ObjectId) -> Result<(), Error> {
        self.stop_in(id, chat, None)
    }
    /// Stops a turn, saving through `open` when the account no longer lists the base.
    fn stop_in(&self, id: BaseId, chat: ObjectId, open: Option<&Base>) -> Result<(), Error> {
        let mut turns = self.inner.turns.lock().unwrap();
        if let Some(active) = turns.get(&chat) {
            if active.base != id {
                return Err(Error::NotFound);
            }
            let _ = active.cancel.send(true);
            // The base may already be gone. Cancellation still wins over a late reply.
            if let Ok(base) = open.map_or_else(|| self.base(id), |base| Ok(base.clone()))
                && let Ok(Some(entry)) = base.get(active.message)
            {
                let mut fields = entry.fields;
                fields.insert("state".into(), json!("stopped"));
                fields.insert("text".into(), json!(active.text));
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
    /// Answers the pending permission request for `requested`, the base the
    /// person was shown, and reruns the last user message. The resulting live turn
    /// needs the network; this method edits locally.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] unless the chat's last Hero message is still
    /// asking for `requested`,
    /// [`Error::Conflict`] if another turn is active, or local edit errors
    /// including [`Error::Forbidden`], [`Error::ReadOnly`], [`Error::Revoked`],
    /// [`Error::NeedsUpdate`] and [`Error::Storage`], or network errors while
    /// saving the permission in encrypted account data.
    pub async fn answer(
        &self,
        id: BaseId,
        chat: ObjectId,
        requested: BaseId,
        allow: bool,
    ) -> Result<(), Error> {
        let messages = self.messages(id, chat)?;
        // Act only on the prompt the person saw: the last Hero message, still
        // asking, for the base they were shown.
        let ask = messages
            .iter()
            .rev()
            .find(|m| m.role == ChatRole::Hero)
            .filter(|m| m.state == MessageState::Asking)
            .and_then(|m| m.ask.as_ref())
            .filter(|ask| ask.base == requested)
            .ok_or(Error::NotFound)?;
        let base = self.base(id)?;
        self.ensure_chat(&base, chat)?;
        self.inner
            .account
            .set_hero_permission(id, chat, ask.base, allow)
            .await?;
        self.retry(id, chat)
    }
    /// Reruns the last user message without changing chat permissions. The
    /// resulting live turn needs the network; this method edits locally.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] if the chat or its messages are absent,
    /// [`Error::Conflict`] for a running turn, or local edit errors including
    /// [`Error::ReadOnly`], [`Error::Revoked`], [`Error::NeedsUpdate`] and
    /// [`Error::Storage`].
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
        // set_fields keeps a field it isn't given; only null removes one.
        fields.insert("error".into(), json!(null));
        fields.insert("ask".into(), json!(null));
        fields.insert("steps".into(), json!([]));
        base.set_fields(existing, fields)?;
        let (cancel, receiver) = watch::channel(false);
        turns.insert(
            chat,
            Active {
                base: id,
                message: existing,
                cancel,
                text: String::new(),
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
    /// Cancels every turn in `open` and awaits the turn tasks, even if the
    /// account has already hidden the base, saving each reply so far as Stopped
    /// through the still-open handle. Clears Hero's cached base watcher.
    /// Infallible: a cancelled task cannot make another model request or write
    /// a late reply.
    pub(crate) async fn cancel_base(&self, open: &Base) {
        let base = open.id();
        let chats: Vec<_> = self
            .inner
            .turns
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, active)| active.base == base)
            .map(|(chat, _)| *chat)
            .collect();
        for chat in chats {
            let _ = self.stop_in(base, chat, Some(open));
        }
        let tasks = self
            .inner
            .tasks
            .lock()
            .unwrap()
            .remove(&base)
            .unwrap_or_default();
        for task in tasks {
            let _ = task.await;
        }
        self.inner.watched.lock().unwrap().remove(&base);
    }
    /// Subscribes to changed chats, including changes received by sync.
    pub fn events(&self) -> broadcast::Receiver<HeroEvent> {
        self.inner.events.subscribe()
    }
    /// Waits until this process has no active turn for the chat. A live turn may need
    /// the network, but this method does not make a separate request.
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
