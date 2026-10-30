//! The sync task: one per open base. It sends the outbox, catches up on
//! start and after a failure, and applies remote changes by the client
//! invariant: an object's `confirmed_seq` advances to a change's seq only
//! when that change's `prevHead` equals it; otherwise the object is fetched,
//! which sets `confirmed_seq` to the fetched head.
//!
//! Live changes go through the same invariant ([`Engine::apply_results`]
//! decides for a device's own results), and compaction is to run after each
//! send ([`Engine::after_send`]).

use crate::base::{Base, BaseWeak};
use crate::client::Api;
use crate::envelope::OVERHEAD;
use crate::store::{BaseDb, SendingRow};
use crate::{Clock, Error};
use bh_proto::{
    Bytes, Change, ChangeId, ChangeKind, ChangeResult, ChangesRequest, DeviceId, FetchObject,
    FetchRequest, ObjectId,
};
use futures_util::{FutureExt, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, sleep_until};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Message};
use ts_rs::TS;

/// At most one change per object goes out in this long, unless flushed.
const SEND_INTERVAL: Duration = Duration::from_millis(500);
const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// A `changes` request's limits.
const BATCH_CHANGES: usize = 1000;
const BATCH_BYTES: usize = 8 << 20;
/// A `fetch` request's limit.
const FETCH_OBJECTS: usize = 200;
const COMPACT_TAIL: u64 = 100;
const COMPACT_PENDING_BYTES: usize = 256 << 10;
const COMPACT_APPLIED_BYTES: usize = 4 << 20;
const MAX_STATE_BYTES: usize = 8 << 20;
/// The `sync` table's key for the base head caught up to.
const HEAD: &str = "head";

/// What a base's sync is doing. `pending` counts objects with changes not yet
/// on the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct SyncState {
    #[ts(type = "number")]
    /// Number of objects with unsent changes.
    pub pending: u64,
    /// Whether the sync task currently has a connection.
    pub online: bool,
    /// Millisecond timestamp of the last completed catch-up, if any.
    #[ts(type = "number | null")]
    pub last_synced_at: Option<i64>,
}

/// Notifications for local edits, fetched changes and sync status. On receiver
/// lag, read fresh summaries from the base rather than relying on every event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum BaseEvent {
    /// Object summaries or documents changed.
    ObjectsChanged(#[ts(type = "Array<string>")] Vec<ObjectId>),
    /// Local file upload progress or availability changed.
    FilesChanged(#[ts(type = "Array<string>")] Vec<ObjectId>),
    /// The base's sync status changed.
    Sync(SyncState),
    /// A fetched object requires a newer version; other objects continue syncing.
    NeedsUpdate,
}

/// One change from the server, as `fetch` returns it.
pub(crate) struct Incoming {
    pub seq: u64,
    /// A whole state rather than an update.
    pub state: bool,
    pub device: DeviceId,
    pub body: Vec<u8>,
}

impl Incoming {
    fn of(object: FetchObject) -> Vec<Incoming> {
        let state = object.state.map(|s| Incoming {
            seq: s.seq,
            state: true,
            device: s.device_id,
            body: s.body.0,
        });
        let updates = object.updates.into_iter().map(|u| Incoming {
            seq: u.seq,
            state: false,
            device: u.device_id,
            body: u.body.0,
        });
        state.into_iter().chain(updates).collect()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveChange {
    t: String,
    seq: u64,
    object_id: ObjectId,
    prev_head: u64,
    kind: ChangeKind,
    change_id: ChangeId,
    device_id: DeviceId,
    body: Option<Bytes>,
}

enum Command {
    Changed,
    CatchUp,
    Flush(oneshot::Sender<Result<(), Error>>),
    PostState(ObjectId, bool, oneshot::Sender<Result<PostedState, Error>>),
    SyncNow(oneshot::Sender<Result<(), Error>>),
    #[cfg(feature = "test-support")]
    Resume,
}

#[derive(Clone, Copy, Default)]
struct Status {
    online: bool,
    last_synced_at: Option<i64>,
}

/// Result of attempting to post one kept state.
pub(crate) enum PostedState {
    Stored,
    Stale,
    Skipped,
}

/// A base's handle on its sync task.
pub(crate) struct SyncTask {
    commands: mpsc::UnboundedSender<Command>,
    status: Arc<Mutex<Status>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    #[cfg(feature = "test-support")]
    paused: Arc<AtomicBool>,
    #[cfg(feature = "test-support")]
    unmerged: Arc<AtomicBool>,
    #[cfg(feature = "test-support")]
    hold_sends: Arc<AtomicBool>,
    #[cfg(feature = "test-support")]
    hold_kept_reply: Arc<AtomicBool>,
    #[cfg(feature = "test-support")]
    kept_reply_entered: Arc<AtomicBool>,
    #[cfg(feature = "test-support")]
    release_kept_reply: Arc<tokio::sync::Notify>,
}

impl SyncTask {
    pub(crate) fn start(
        base: Base,
        api: Api,
        runtime: &tokio::runtime::Handle,
        clock: Clock,
    ) -> SyncTask {
        let (commands, receiver) = mpsc::unbounded_channel();
        let status = Arc::new(Mutex::new(Status::default()));
        let paused = Arc::new(AtomicBool::new(false));
        #[cfg(feature = "test-support")]
        let unmerged = Arc::new(AtomicBool::new(false));
        #[cfg(feature = "test-support")]
        let hold_sends = Arc::new(AtomicBool::new(false));
        #[cfg(feature = "test-support")]
        let hold_kept_reply = Arc::new(AtomicBool::new(false));
        #[cfg(feature = "test-support")]
        let kept_reply_entered = Arc::new(AtomicBool::new(false));
        #[cfg(feature = "test-support")]
        let release_kept_reply = Arc::new(tokio::sync::Notify::new());
        let engine = Engine {
            owner: base.downgrade(),
            base: None,
            api,
            clock,
            commands: receiver,
            status: status.clone(),
            paused: paused.clone(),
            #[cfg(feature = "test-support")]
            unmerged: unmerged.clone(),
            #[cfg(feature = "test-support")]
            hold_sends: hold_sends.clone(),
            #[cfg(feature = "test-support")]
            hold_kept_reply: hold_kept_reply.clone(),
            #[cfg(feature = "test-support")]
            kept_reply_entered: kept_reply_entered.clone(),
            #[cfg(feature = "test-support")]
            release_kept_reply: release_kept_reply.clone(),
            flushes: Vec::new(),
            dirty: true,
            caught_up: false,
            last_sent: HashMap::new(),
            send_at: None,
            socket: None,
            retry_at: None,
            backoff: BACKOFF_MIN,
            reported: None,
            needs_update_reported: false,
            applied_bytes: HashMap::new(),
            pending_tail_bytes: HashMap::new(),
            too_large_warned: HashSet::new(),
            posted: HashMap::new(),
            pending_posts: Vec::new(),
        };
        let task = runtime.spawn(engine.run());
        SyncTask {
            commands,
            status,
            task: Mutex::new(Some(task)),
            #[cfg(feature = "test-support")]
            paused,
            #[cfg(feature = "test-support")]
            unmerged,
            #[cfg(feature = "test-support")]
            hold_sends,
            #[cfg(feature = "test-support")]
            hold_kept_reply,
            #[cfg(feature = "test-support")]
            kept_reply_entered,
            #[cfg(feature = "test-support")]
            release_kept_reply,
        }
    }

    /// Cancels sync and waits until it no longer uses the local store.
    pub(crate) async fn stop(&self) {
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        // An aborted task can't report it went offline.
        self.status.lock().unwrap_or_else(|p| p.into_inner()).online = false;
    }

    /// `(online, last_synced_at)`.
    pub(crate) fn status(&self) -> (bool, Option<i64>) {
        let status = *self.status.lock().unwrap_or_else(|p| p.into_inner());
        (status.online, status.last_synced_at)
    }

    /// A local edit is in the outbox.
    pub(crate) fn changed(&self) {
        let _ = self.commands.send(Command::Changed);
    }

    pub(crate) fn catch_up(&self) {
        let _ = self.commands.send(Command::CatchUp);
    }

    pub(crate) async fn flush(&self) -> Result<(), Error> {
        let stopped = || Error::Network("sync has stopped".into());
        let (reply, done) = oneshot::channel();
        self.commands
            .send(Command::Flush(reply))
            .map_err(|_| stopped())?;
        done.await.map_err(|_| stopped())?
    }

    pub(crate) async fn post_state(&self, id: ObjectId) -> Result<PostedState, Error> {
        self.enqueue_state(id, true).await
    }

    /// An explicit restore keeps the current state regardless of the hourly
    /// version policy, while retaining all send/catch-up safety checks.
    pub(crate) async fn post_state_for_restore(&self, id: ObjectId) -> Result<PostedState, Error> {
        self.enqueue_state(id, false).await
    }

    async fn enqueue_state(
        &self,
        id: ObjectId,
        check_candidate: bool,
    ) -> Result<PostedState, Error> {
        let (reply, done) = oneshot::channel();
        self.commands
            .send(Command::PostState(id, check_candidate, reply))
            .map_err(|_| Error::Network("sync has stopped".into()))?;
        done.await
            .map_err(|_| Error::Network("sync has stopped".into()))?
    }

    pub(crate) async fn sync_now(&self) -> Result<(), Error> {
        let (reply, done) = oneshot::channel();
        self.commands
            .send(Command::SyncNow(reply))
            .map_err(|_| Error::Network("sync has stopped".into()))?;
        done.await
            .map_err(|_| Error::Network("sync has stopped".into()))?
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn hold_next_kept_reply(&self) -> Arc<AtomicBool> {
        self.kept_reply_entered.store(false, Ordering::SeqCst);
        self.hold_kept_reply.store(true, Ordering::SeqCst);
        self.kept_reply_entered.clone()
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn resume_kept_reply(&self) {
        self.release_kept_reply.notify_one();
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn preserve_updates(&self) {
        self.unmerged.store(true, Ordering::SeqCst);
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn hold_sends(&self, held: bool) {
        self.hold_sends.store(held, Ordering::SeqCst);
        if !held {
            self.changed();
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn pause(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
        if !paused {
            let _ = self.commands.send(Command::Resume);
        }
    }
}

struct PendingPost {
    id: ObjectId,
    check_candidate: bool,
    reply: oneshot::Sender<Result<PostedState, Error>>,
}

struct Engine {
    /// The task never owns the base between rounds: the last caller can drop it.
    owner: BaseWeak,
    base: Option<Base>,
    api: Api,
    clock: Clock,
    commands: mpsc::UnboundedReceiver<Command>,
    status: Arc<Mutex<Status>>,
    paused: Arc<AtomicBool>,
    #[cfg(feature = "test-support")]
    unmerged: Arc<AtomicBool>,
    #[cfg(feature = "test-support")]
    hold_sends: Arc<AtomicBool>,
    #[cfg(feature = "test-support")]
    hold_kept_reply: Arc<AtomicBool>,
    #[cfg(feature = "test-support")]
    kept_reply_entered: Arc<AtomicBool>,
    #[cfg(feature = "test-support")]
    release_kept_reply: Arc<tokio::sync::Notify>,
    /// Callers waiting for the outbox to be sent.
    flushes: Vec<oneshot::Sender<Result<(), Error>>>,
    /// The outbox may hold changes.
    dirty: bool,
    /// Caught up since starting or the last failure.
    caught_up: bool,
    /// Per-object send deadlines in the monotonic device clock.
    last_sent: HashMap<ObjectId, u64>,
    /// The earliest postponed object, or none if new work may send now.
    send_at: Option<u64>,
    socket: Option<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    /// After a failure, when to try again.
    retry_at: Option<Instant>,
    backoff: Duration,
    reported: Option<(u64, bool)>,
    needs_update_reported: bool,
    /// Sealed bytes applied after the last observed state, for the size triggers.
    applied_bytes: HashMap<ObjectId, usize>,
    /// This device's posted updates after the latest observed state.
    pending_tail_bytes: HashMap<ObjectId, usize>,
    too_large_warned: HashSet<ObjectId>,
    posted: HashMap<ChangeId, bool>,
    pending_posts: Vec<PendingPost>,
}

impl Engine {
    async fn run(mut self) {
        let mut ping = tokio::time::interval(Duration::from_secs(30));
        loop {
            let wake = self.next_wake();
            tokio::select! {
                command = self.commands.recv() => match command {
                    Some(command) => self.take(command),
                    None => return,
                },
                () = sleep_until(wake.unwrap_or_else(far_future)), if wake.is_some() => {}
                () = self.clock.sleep_until(self.send_at.unwrap_or(u64::MAX)), if self.send_at.is_some() => {
                    self.send_at = None;
                }
                message = async { self.socket.as_mut().expect("connected").next().await }, if self.socket.is_some() && !self.paused() => {
                    self.receive(message).await;
                }
                _ = ping.tick() => {
                    if let Some(socket) = &mut self.socket
                        && socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                        self.disconnect();
                    }
                }
            }
            while let Ok(command) = self.commands.try_recv() {
                self.take(command);
            }
            if let Some(PendingPost {
                id,
                check_candidate,
                reply,
            }) = self.pending_posts.pop()
            {
                let result = self.post_kept_state(id, check_candidate).await;
                let _ = reply.send(result);
                continue;
            }
            if self.paused() {
                for flush in self.flushes.drain(..) {
                    let _ = flush.send(Err(Error::Network("sync is paused".into())));
                }
                continue;
            }
            let Some(base) = self.owner.upgrade() else {
                return;
            };
            self.base = Some(base);
            self.step().await;
            self.base = None;
        }
    }

    /// Use the ordinary durable sending queue, including its retry and fetch path.
    async fn post_kept_state(
        &mut self,
        id: ObjectId,
        check_candidate: bool,
    ) -> Result<PostedState, Error> {
        if self.paused() {
            return Err(Error::Network("sync is paused".into()));
        }
        // Only step() owns reconnecting and catch-up; a post must not mark
        // caught_up without a live socket during reconnect backoff.
        if self.socket.is_none() || !self.caught_up {
            return Err(Error::Network("sync is not connected".into()));
        }
        let base = self.owner.upgrade().ok_or(Error::NotFound)?;
        self.base = Some(base);
        let result = async {
            let mut worked = false;
            // A kept state must cover the edits this device has already sent.
            let (force, _reply) = oneshot::channel();
            self.flushes.push(force);
            let sent = self.send(&mut worked).await;
            self.flushes.pop();
            sent?;
            let row = {
                let base = self.base();
                let db = base.db()?;
                // The flush may have retried a kept row and recorded its version.
                if check_candidate
                    && !db
                        .version_candidates(base.version_now(), 0, 0)?
                        .contains(&id)
                {
                    return Ok(PostedState::Skipped);
                }
                let Some((ty, state)) = db.state(id)? else {
                    return Ok(PostedState::Skipped);
                };
                // A local edit could land during the network send above. Never
                // seal a state that includes edits beyond its covers sequence.
                if db.outbox_objects(db.outbox_end()?)?.contains(&id)
                    || db.needs_update(id)?
                    || base.newer_type_for_compaction(&db, &ty)?
                    || state.len() + OVERHEAD > MAX_STATE_BYTES
                {
                    return Ok(PostedState::Skipped);
                }
                let Some(covers) = db.confirmed(id)?.filter(|n| *n > 0) else {
                    return Ok(PostedState::Skipped);
                };
                SendingRow {
                    change_id: ChangeId::random(),
                    object_id: id,
                    state: true,
                    keep: true,
                    body: base.seal_change(id, true, &state),
                    covers: Some(covers),
                    outbox_max_id: 0,
                }
            };
            self.base()
                .db()?
                .start_sending(std::slice::from_ref(&row))?;
            // A caller deliberately asked for this kept state now. Do not
            // throttle it behind the just-flushed edits for this object.
            let (force, _reply) = oneshot::channel();
            self.flushes.push(force);
            let sent = self.send(&mut worked).await;
            self.flushes.pop();
            sent?;
            match self.posted.remove(&row.change_id) {
                Some(true) => Ok(PostedState::Stored),
                Some(false) => {
                    self.fetch(vec![id], &mut worked).await?;
                    Ok(PostedState::Stale)
                }
                None => Err(Error::Network("kept state awaits retry".into())),
            }
        }
        .await;
        self.posted.clear();
        self.base = None;
        result
    }

    fn disconnect(&mut self) {
        self.socket = None;
        self.caught_up = false;
        self.retry_at = Some(Instant::now() + self.backoff);
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
        self.status.lock().unwrap_or_else(|p| p.into_inner()).online = false;
    }

    async fn receive(
        &mut self,
        message: Option<Result<Message, tokio_tungstenite::tungstenite::Error>>,
    ) {
        if self.paused() {
            self.caught_up = false;
            return;
        }
        let Some(base) = self.owner.upgrade() else {
            return;
        };
        self.base = Some(base);
        let mut worked = false;
        let result = match message {
            Some(Ok(Message::Text(text))) => {
                let mut messages = vec![text];
                // Coalesce a burst into one store transaction, rather than
                // opening a transaction for each object in a posted batch.
                let mut closed = false;
                while messages.len() < 200 {
                    match self
                        .socket
                        .as_mut()
                        .expect("connected")
                        .next()
                        .now_or_never()
                    {
                        Some(Some(Ok(Message::Text(text)))) => messages.push(text),
                        Some(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
                        Some(_) => {
                            closed = true;
                            break;
                        }
                        None => break,
                    }
                }
                let result = self.apply_lives(messages, &mut worked).await;
                if closed && result.is_ok() {
                    Err(Error::Network("live connection closed".into()))
                } else {
                    result
                }
            }
            // A grant can also close a socket with 4001; only an explicit
            // revocation message or a 401 revoked answer erases the account.
            Some(Ok(Message::Close(Some(frame)))) if u16::from(frame.code) == 4001 => {
                Err(Error::Network("live connection closed".into()))
            }
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => Ok(()),
            _ => Err(Error::Network("live connection closed".into())),
        };
        if result.is_err() {
            self.disconnect();
        }
        self.report(worked);
        self.base = None;
    }

    async fn apply_lives(
        &mut self,
        messages: Vec<tokio_tungstenite::tungstenite::Utf8Bytes>,
        worked: &mut bool,
    ) -> Result<(), Error> {
        let mut batch: Vec<(ObjectId, u64, Vec<Incoming>)> = Vec::new();
        let mut by_id = HashMap::<ObjectId, usize>::new();
        if let Some(revoked) = messages.iter().find_map(|message| {
            serde_json::from_str::<serde_json::Value>(message)
                .ok()
                .filter(|value| value["t"] == "revoked")
        }) {
            self.api.revoked(revoked["notice"].as_str());
            return Err(Error::Revoked);
        }
        let sending: HashSet<_> = self
            .base()
            .db()?
            .sending()?
            .into_iter()
            .map(|row| row.change_id)
            .collect();
        for message in messages {
            if let Ok(bh_proto::LiveMessage::Epoch { epoch }) = serde_json::from_str(&message) {
                self.apply_batch(&mut batch, worked).await?;
                by_id.clear();
                if epoch > self.base().newest_epoch() {
                    self.base().reload_keys().await?;
                }
                self.caught_up = false;
                continue;
            }
            let change: LiveChange = serde_json::from_str(&message)
                .map_err(|_| Error::Network("malformed live message".into()))?;
            if change.t != "change" {
                return Err(Error::Network("malformed live message".into()));
            }
            // The locally applied edit is still in `sending` until its HTTP
            // reply arrives. Its broadcast must not apply or confirm it first.
            if sending.contains(&change.change_id) {
                continue;
            }
            let index = by_id.get(&change.object_id).copied();
            let confirmed = if let Some(index) = index {
                batch[index].1
            } else {
                self.base().db()?.confirmed(change.object_id)?.unwrap_or(0)
            };
            if change.seq <= confirmed {
                continue;
            }
            let Some(body) = change
                .body
                .clone()
                .filter(|_| change.prev_head == confirmed)
            else {
                self.apply_batch(&mut batch, worked).await?;
                by_id.clear();
                self.apply_live(change, worked).await?;
                continue;
            };
            let incoming = Incoming {
                seq: change.seq,
                state: change.kind == ChangeKind::State,
                device: change.device_id,
                body: body.0,
            };
            if let Some(index) = index {
                batch[index].1 = change.seq;
                batch[index].2.push(incoming);
            } else {
                by_id.insert(change.object_id, batch.len());
                batch.push((change.object_id, change.seq, vec![incoming]));
            }
        }
        self.apply_batch(&mut batch, worked).await
    }

    async fn apply_batch(
        &mut self,
        batch: &mut Vec<(ObjectId, u64, Vec<Incoming>)>,
        worked: &mut bool,
    ) -> Result<(), Error> {
        if batch.is_empty() {
            return Ok(());
        }
        if self.base().missing_epoch(batch) {
            self.base().reload_keys().await?;
            if self.base().missing_epoch(batch) {
                return Err(Error::Network("waiting for base key".into()));
            }
        }
        let (changed, needs_update) = self.base().apply_fetched(batch)?;
        self.observe_incoming(batch, &changed);
        batch.clear();
        if needs_update && !self.needs_update_reported {
            self.needs_update_reported = true;
            self.base().emit(BaseEvent::NeedsUpdate);
        }
        if !changed.is_empty() {
            *worked = true;
            self.base().emit(BaseEvent::ObjectsChanged(changed));
            self.base().files_caught_up();
        }
        Ok(())
    }

    async fn apply_live(&mut self, change: LiveChange, worked: &mut bool) -> Result<(), Error> {
        let confirmed = self.base().db()?.confirmed(change.object_id)?.unwrap_or(0);
        if change.seq <= confirmed {
            return Ok(());
        }
        let Some(body) = change.body.filter(|_| change.prev_head == confirmed) else {
            if !self.fetch(vec![change.object_id], worked).await? {
                return Err(Error::Network("live body not available".into()));
            }
            return Ok(());
        };
        let incoming = Incoming {
            seq: change.seq,
            state: change.kind == ChangeKind::State,
            device: change.device_id,
            body: body.0,
        };
        self.apply_batch(
            &mut vec![(change.object_id, change.seq, vec![incoming])],
            worked,
        )
        .await
    }

    fn base(&self) -> &Base {
        self.base.as_ref().expect("base held for the sync round")
    }

    fn take(&mut self, command: Command) {
        match command {
            Command::Changed => {
                self.dirty = true;
                self.send_at = None;
            }
            #[cfg(feature = "test-support")]
            Command::Resume => {
                self.dirty = true;
                self.send_at = None;
                self.caught_up = false;
            }
            Command::CatchUp => self.caught_up = false,
            Command::Flush(reply) => self.flushes.push(reply),
            Command::PostState(id, check_candidate, reply) => {
                self.pending_posts.push(PendingPost {
                    id,
                    check_candidate,
                    reply,
                })
            }
            Command::SyncNow(reply) => {
                self.caught_up = false;
                self.flushes.push(reply);
            }
        }
    }

    fn paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    fn next_wake(&self) -> Option<Instant> {
        if self.paused() {
            return None;
        }
        if !self.caught_up && self.retry_at.is_none() {
            return Some(Instant::now());
        }
        if let Some(at) = self.retry_at {
            return Some(at);
        }
        if self.socket.is_none() || !self.caught_up || self.dirty && self.send_at.is_none() {
            Some(Instant::now())
        } else {
            None
        }
    }

    /// Does whatever is due: catching up, then sending.
    async fn step(&mut self) {
        let now = Instant::now();
        let flushing = !self.flushes.is_empty();
        if self.retry_at.is_some_and(|at| now < at) && !flushing {
            return;
        }
        if !self.needs_update_reported
            && self
                .base()
                .db()
                .ok()
                .is_some_and(|db| db.has_future().unwrap_or(false))
        {
            self.needs_update_reported = true;
            self.base().emit(BaseEvent::NeedsUpdate);
        }
        let reconnecting = self.socket.is_none();
        let catch_up = !self.caught_up;
        let send = flushing || self.retry_at.is_some() || (self.dirty && self.send_at.is_none());
        if !catch_up && !send {
            return;
        }
        let mut worked = false;
        let result = async {
            if reconnecting {
                self.socket = Some(self.api.base_live(self.base().id()).await?);
            }
            self.round(catch_up, send, &mut worked).await
        }
        .await;
        let mut status = *self.status.lock().unwrap_or_else(|p| p.into_inner());
        match result {
            Ok(()) => {
                self.retry_at = None;
                self.backoff = BACKOFF_MIN;
                status.online = true;
                status.last_synced_at = Some(now_ms());
                for flush in self.flushes.drain(..) {
                    let _ = flush.send(Ok(()));
                }
            }
            Err(e) => {
                self.retry_at = Some(Instant::now() + self.backoff);
                self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
                self.caught_up = false;
                if matches!(e, Error::Network(_)) {
                    self.socket = None;
                }
                status.online = self.socket.is_some();
                // Waiting out a rate limit is part of sending; anything else
                // is the caller's to know.
                if e != Error::RateLimited {
                    for flush in self.flushes.drain(..) {
                        let _ = flush.send(Err(e.clone()));
                    }
                }
            }
        }
        *self.status.lock().unwrap_or_else(|p| p.into_inner()) = status;
        self.report(worked);
    }

    async fn round(&mut self, catch_up: bool, send: bool, worked: &mut bool) -> Result<(), Error> {
        if catch_up {
            self.catch_up(worked).await?;
            self.caught_up = true;
            self.base().files_caught_up();
        }
        if send {
            self.send(worked).await?;
        }
        Ok(())
    }

    /// Emits the sync state when it changed, or after the task sent or applied changes.
    fn report(&mut self, worked: bool) {
        let state = self.base().sync_state();
        let now = (state.pending, state.online);
        if worked || self.reported != Some(now) {
            self.reported = Some(now);
            self.base().emit(BaseEvent::Sync(state));
        }
    }

    /// Fetches every object whose head is past what this device has applied,
    /// from the base head caught up to.
    async fn catch_up(&mut self, worked: &mut bool) -> Result<(), Error> {
        let id = self.base().id();
        let mut after = self.base().db()?.sync_value(HEAD)?.unwrap_or(0);
        loop {
            if self.paused() {
                return Ok(());
            }
            let page = self.api.since(id, after).await?;
            let wanted = {
                let db = self.base().db()?;
                let mut wanted = Vec::new();
                for object in &page.objects {
                    if object.head > db.confirmed(object.object_id)?.unwrap_or(0) {
                        wanted.push(object.object_id);
                    }
                }
                wanted
            };
            if !self.fetch(wanted, worked).await? {
                return Err(Error::Network("catch-up body not available".into()));
            }
            after = match (page.more, page.objects.last()) {
                (true, Some(last)) => last.head,
                _ => page.head,
            };
            self.base().db()?.set_sync_value(HEAD, after)?;
            if !page.more {
                return Ok(());
            }
        }
    }

    /// Fetches and applies objects, following `more`. Returns false when a
    /// reply holds no objects, as when their bodies are missing for now.
    async fn fetch(&mut self, ids: Vec<ObjectId>, worked: &mut bool) -> Result<bool, Error> {
        for chunk in ids.chunks(FETCH_OBJECTS) {
            let mut ask = chunk.to_vec();
            while !ask.is_empty() {
                let reply = self
                    .api
                    .fetch(
                        self.base().id(),
                        &FetchRequest {
                            object_ids: ask.clone(),
                        },
                    )
                    .await?;
                if reply.objects.is_empty() {
                    return Ok(false);
                }
                // A truncated reply must account for every requested object,
                // either in `objects` or in `more`. Otherwise catch-up must retry.
                let accounted: HashSet<_> = reply
                    .objects
                    .iter()
                    .map(|o| o.object_id)
                    .chain(reply.more.iter().copied())
                    .collect();
                if ask.iter().any(|id| !accounted.contains(id)) {
                    return Ok(false);
                }
                let fetched: Vec<_> = reply
                    .objects
                    .into_iter()
                    .map(|o| (o.object_id, o.head, Incoming::of(o)))
                    .collect();
                if self.base().missing_epoch(&fetched) {
                    self.base().reload_keys().await?;
                    if self.base().missing_epoch(&fetched) {
                        return Err(Error::Network("waiting for base key".into()));
                    }
                }
                let (changed, needs_update) = self.base().apply_fetched(&fetched)?;
                self.observe_incoming(&fetched, &changed);
                if needs_update && !self.needs_update_reported {
                    self.needs_update_reported = true;
                    self.base().emit(BaseEvent::NeedsUpdate);
                }
                if !changed.is_empty() {
                    *worked = true;
                    self.base().emit(BaseEvent::ObjectsChanged(changed));
                    self.base().files_caught_up();
                }
                ask = reply.more;
            }
        }
        Ok(true)
    }

    /// Sends the outbox in batches. A batch is recorded in `sending` before
    /// it's posted, and after a failure the same batch is posted again,
    /// unchanged, before any other. Edits made meanwhile wait for the next
    /// send, so an object goes out at most once a send.
    async fn send(&mut self, worked: &mut bool) -> Result<(), Error> {
        #[cfg(feature = "test-support")]
        if self.hold_sends.load(Ordering::SeqCst) {
            self.dirty = false;
            return Ok(());
        }
        let end = self.base().db()?.outbox_end()?;
        loop {
            let batch = {
                let base = self.base().clone();
                let mut db = base.db()?;
                // Checked under the store lock, so an edit made after pausing
                // is never in a batch.
                if self.paused() {
                    return Ok(());
                }
                let sending = db.sending()?;
                let mut bytes = 0;
                let sending: Vec<_> = sending
                    .into_iter()
                    .filter(|row| !db.needs_update(row.object_id).unwrap_or(false))
                    .take_while(|row| {
                        if bytes > 0 && bytes + row.body.len() > BATCH_BYTES {
                            return false;
                        }
                        bytes += row.body.len();
                        true
                    })
                    .collect();
                if sending.is_empty() {
                    let batch = self.next_batch(&db, end, !self.flushes.is_empty())?;
                    if batch.is_empty() {
                        let waiting: Vec<_> = db
                            .outbox_objects(end)?
                            .into_iter()
                            .filter(|id| !db.needs_update(*id).unwrap_or(false))
                            .collect();
                        self.dirty = !waiting.is_empty();
                        if self.dirty {
                            self.send_at = waiting
                                .iter()
                                .filter_map(|id| self.last_sent.get(id))
                                .map(|at| at.saturating_add(SEND_INTERVAL.as_millis() as u64))
                                .min();
                        }
                        return Ok(());
                    }
                    db.start_sending(&batch)?;
                    batch
                } else {
                    sending
                }
            };
            // A queued state is a change too: only an explicit flush may
            // bypass the per-object background interval.
            if self.flushes.is_empty() {
                let wait = batch
                    .iter()
                    .filter(|row| row.state)
                    .filter_map(|row| {
                        self.last_sent
                            .get(&row.object_id)
                            .map(|at| at.saturating_add(SEND_INTERVAL.as_millis() as u64))
                    })
                    .filter(|at| *at > self.clock.now_ms())
                    .min();
                if let Some(at) = wait {
                    self.dirty = true;
                    self.send_at = Some(at);
                    return Ok(());
                }
            }
            let request = ChangesRequest {
                changes: batch.iter().map(change).collect(),
            };
            let reply = self.api.changes(self.base().id(), &request).await;
            let sent_at = self.clock.now_ms();
            for row in &batch {
                self.last_sent.insert(row.object_id, sent_at);
            }
            let reply = match reply {
                Err(Error::Conflict(code)) if code == "stale_epoch" || code == "rekey_needed" => {
                    self.base().reload_keys().await?;
                    if !self.base().reseal_sending()? {
                        return Err(Error::Network("waiting for base re-key".into()));
                    }
                    continue;
                }
                other => other?,
            };
            #[cfg(feature = "test-support")]
            if batch.iter().any(|row| row.keep)
                && self.hold_kept_reply.swap(false, Ordering::SeqCst)
            {
                let released = self.release_kept_reply.notified();
                self.kept_reply_entered.store(true, Ordering::SeqCst);
                released.await;
            }
            for row in &batch {
                if row.keep {
                    let result = reply
                        .results
                        .iter()
                        .find(|r| r.change_id == row.change_id)
                        .ok_or_else(|| Error::Network("malformed response".into()))?;
                    let stored = result.seq.is_some() && !result.stale;
                    // A retried kept send whose first reply was lost records this
                    // reply's time, so the edit since waits for the next version.
                    // Known limit: nothing is lost, it's in the current state.
                    if stored {
                        self.base()
                            .db()?
                            .version_stored(row.object_id, self.base().version_now())?;
                    }
                    self.posted.insert(row.change_id, stored);
                }
            }
            *worked = true;
            let fetch = self.apply_results(&batch, &reply.results)?;
            if !fetch.is_empty() {
                self.fetch(fetch, worked).await?;
            }
            self.after_send(&batch, &reply.results)?;
        }
    }

    /// Forgets the changes the server stored, and keeps the client
    /// invariant: returns the objects that must be fetched because another
    /// change landed before this device's.
    fn apply_results(
        &self,
        batch: &[SendingRow],
        results: &[ChangeResult],
    ) -> Result<Vec<ObjectId>, Error> {
        let mut db = self.base().db()?;
        let (mut done, mut fetch) = (Vec::new(), Vec::new());
        #[cfg(feature = "test-support")]
        let mut sequence = HashMap::new();
        for row in batch {
            let result = results
                .iter()
                .find(|r| r.change_id == row.change_id)
                .ok_or_else(|| Error::Network("malformed response".into()))?;
            let confirmed = db.confirmed(row.object_id)?.unwrap_or(0);
            #[cfg(feature = "test-support")]
            let confirmed = *sequence.get(&row.object_id).unwrap_or(&confirmed);
            let confirm = match result.seq {
                Some(seq) if result.prev_head == confirmed => Some(seq),
                Some(seq) => {
                    if seq > confirmed {
                        fetch.push(row.object_id);
                    }
                    None
                }
                None => None,
            };
            #[cfg(feature = "test-support")]
            if let Some(seq) = confirm {
                sequence.insert(row.object_id, seq);
            }
            done.push((row, confirm));
        }
        db.sent(&done)?;
        Ok(fetch)
    }

    /// Count successfully applied encrypted changes since the most recent state.
    fn observe_incoming(&mut self, batch: &[(ObjectId, u64, Vec<Incoming>)], changed: &[ObjectId]) {
        for (id, _, changes) in batch {
            if !changed.contains(id) {
                continue;
            }
            for change in changes {
                if change.state {
                    self.applied_bytes.insert(*id, 0);
                    self.pending_tail_bytes.insert(*id, 0);
                    self.too_large_warned.remove(id);
                } else {
                    *self.applied_bytes.entry(*id).or_default() += change.body.len();
                }
            }
        }
    }

    /// Queue one sealed state after a confirmed update, never over a newer object.
    /// It goes through `sending` so a lost reply retries the identical change.
    fn after_send(&mut self, sent: &[SendingRow], results: &[ChangeResult]) -> Result<(), Error> {
        let mut candidates = Vec::new();
        for row in sent {
            let result = results
                .iter()
                .find(|r| r.change_id == row.change_id)
                .ok_or_else(|| Error::Network("malformed response".into()))?;
            if row.state {
                if !result.stale {
                    self.applied_bytes.insert(row.object_id, 0);
                    self.pending_tail_bytes.insert(row.object_id, 0);
                    self.too_large_warned.remove(&row.object_id);
                }
                continue;
            }
            if result.seq.is_some() {
                *self.applied_bytes.entry(row.object_id).or_default() += row.body.len();
                *self.pending_tail_bytes.entry(row.object_id).or_default() += row.body.len();
                if result.tail >= COMPACT_TAIL
                    || self.pending_tail_bytes[&row.object_id] > COMPACT_PENDING_BYTES
                    || self.applied_bytes[&row.object_id] > COMPACT_APPLIED_BYTES
                {
                    candidates.push(row.object_id);
                }
            }
        }
        let base = self.base().clone();
        let mut db = base.db()?;
        let mut states = Vec::new();
        let mut unique = HashSet::new();
        for id in candidates {
            if !unique.insert(id) {
                continue;
            }
            if db.needs_update(id)? {
                continue;
            }
            let Some((ty, state)) = db.state(id)? else {
                continue;
            };
            if base.newer_type_for_compaction(&db, &ty)? {
                continue;
            }
            let Some(covers) = db.confirmed(id)?.filter(|seq| *seq > 0) else {
                continue;
            };
            if state.len() + OVERHEAD > MAX_STATE_BYTES {
                if self.too_large_warned.insert(id) {
                    eprintln!("warning: object {id} state exceeds 8 MiB; keeping its update tail");
                }
                continue;
            }
            states.push(SendingRow {
                change_id: ChangeId::random(),
                object_id: id,
                state: true,
                keep: false,
                body: base.seal_change(id, true, &state),
                covers: Some(covers),
                outbox_max_id: 0,
            });
        }
        if !states.is_empty() {
            db.start_sending(&states)?;
        }
        Ok(())
    }

    /// The next batch from the outbox up to row `end`: one change per object,
    /// merging its waiting updates, within a request's limits.
    fn next_batch(&self, db: &BaseDb, end: i64, flushing: bool) -> Result<Vec<SendingRow>, Error> {
        #[cfg(feature = "test-support")]
        if self.unmerged.load(Ordering::SeqCst) {
            return db
                .test_outbox_batch(end, BATCH_CHANGES, BATCH_BYTES)?
                .into_iter()
                .map(|(row_id, id, update)| {
                    Ok(SendingRow {
                        change_id: ChangeId::random(),
                        object_id: id,
                        state: false,
                        keep: false,
                        body: self.base().seal_change(id, false, &update),
                        covers: None,
                        outbox_max_id: row_id,
                    })
                })
                .collect();
        }
        let mut batch = Vec::new();
        let mut total = 0;
        for id in db.outbox_objects(end)? {
            if db.needs_update(id)? {
                continue;
            }
            if !flushing
                && self.last_sent.get(&id).is_some_and(|at| {
                    self.clock.now_ms() < at.saturating_add(SEND_INTERVAL.as_millis() as u64)
                })
            {
                continue;
            }
            if batch.len() == BATCH_CHANGES {
                break;
            }
            let room = BATCH_BYTES.saturating_sub(total + OVERHEAD);
            let mut rows = db.outbox_rows(id, end, room)?;
            let merged = loop {
                let merged = match rows.as_slice() {
                    [(_, only)] => only.clone(),
                    _ => yrs::merge_updates_v1(rows.iter().map(|(_, u)| u.as_slice()))
                        .unwrap_or_default(),
                };
                if (merged.is_empty() || merged.len() > room) && rows.len() > 1 {
                    rows.truncate(rows.len() / 2);
                    continue;
                }
                break merged;
            };
            if merged.len() > room && !batch.is_empty() {
                break;
            }
            let body = self.base().seal_change(id, false, &merged);
            total += body.len();
            batch.push(SendingRow {
                change_id: ChangeId::random(),
                object_id: id,
                state: false,
                keep: false,
                body,
                covers: None,
                outbox_max_id: rows.last().expect("an outbox row").0,
            });
        }
        Ok(batch)
    }
}

fn change(row: &SendingRow) -> Change {
    Change {
        change_id: row.change_id,
        object_id: row.object_id,
        kind: if row.state {
            ChangeKind::State
        } else {
            ChangeKind::Update
        },
        body: Bytes(row.body.clone()),
        covers: row.covers,
        keep: row.keep.then_some(true),
    }
}

fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(86_400)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}
