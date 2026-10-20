//! Own-device presence: ephemeral carets between this account's devices. It
//! never appends, never persists and never enters note sync status.
//!
//! **Sending.** The host reports each window's selection. The most recently
//! active window per open note wins, at most [`MAX_LOCAL_NOTES`] notes are
//! held, and the least recently active is evicted as `cleared`. One frame is
//! sent at most every [`SEND_INTERVAL`] per device, with the latest value
//! always trailing; nothing is sent while the roster has no other device.
//! Each frame is sealed with `bh_event::presence` under the own base's current
//! content key, and only when every writer its positions name has an accepted
//! binding for the note. A withheld value stays latest and is rechecked when
//! accepted history wakes a window, without polling.
//!
//! **Receiving.** A frame opens only under this session's epoch, with valid
//! authentication, version, kind and bounded positions, and is kept in memory
//! keyed by handle and note. An older or equal sequence is ignored within one
//! slot; a frame from a new slot replaces the entry (a relaunch, even with a
//! wall clock that went backwards), and a later `left` for the old slot cannot
//! remove it. The whole bounded state is published through a `watch` channel,
//! so a slow host can miss an intermediate value but never a removal.
//!
//! **The task.** It owns its own data socket and join, opened only while the
//! app is foreground, a note window is open and presence is configured. It
//! asks the shared authz session for one presence permit at a time, renewing
//! before the permit's usable end. The content key never leaves
//! `with_base_keys`, and each send and delivery rechecks the owner authority
//! and epoch under the short sync fence. Leaving sends `cleared` best effort
//! and closes the join; a reconnect keeps this device's own selections so the
//! next roster snapshot resends them.

use crate::{
    Shared,
    backoff::Backoff,
    data::{Answers, DataSocket},
    outbox::usable_until,
};
use bh_authz_proto::{FromService, ToService, Want};
use bh_crypto::{Secret, random};
use bh_device::{OwnerError, SyncFence};
use bh_event::presence::{self, PresenceRecord, SEALED_LEN};
use bh_storage::NoteKey;
use bh_sync::{
    BaseId,
    permit::{LogId, LogKind},
    wire::{Refusal, Request, Response},
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::watch, time::Instant};
use yrs::{Assoc, ID, IndexScope, StickyIndex, updates::decoder::Decode};

/// The most local notes whose carets presence keeps and sends.
pub const MAX_LOCAL_NOTES: usize = 8;
/// The most remote carets one device keeps in memory.
pub const MAX_REMOTE: usize = 64;
/// The longest device label sent or kept, in bytes (the record's limit).
pub const MAX_LABEL: usize = 64;
/// One frame per device at most this often while values keep changing.
pub const SEND_INTERVAL: Duration = Duration::from_millis(100);
/// A rejoin after an epoch refusal is delayed by 0..2 s, as the relay contract
/// asks, so many devices do not all return at once.
const REJOIN_JITTER_MS: u64 = 2_000;
/// How soon to look again when this container has no usable own-base epoch yet.
const NOT_READY_RETRY: Duration = Duration::from_millis(500);
/// How long a leaving join lets its best-effort `cleared` frames be written
/// before the socket closes. Bounded: the socket close alone removes them.
const CLEAR_FLUSH: Duration = Duration::from_millis(20);
/// Yjs relative positions this side accepts and sends.
const MAX_POSITION: usize = 96;
/// The ordinary audience of this base's own notes: `NoteKey.audience` for a
/// personal base, where the format's audience is the base itself.
const OWN_AUDIENCE: [u8; 32] = [0; 32];

/// One other device's caret in one note, as received.
#[derive(Clone, PartialEq, Eq)]
pub struct RemotePresence {
    /// Stable per device and epoch; not its device or writer id.
    pub handle: [u8; 16],
    pub note: [u8; 32],
    pub label: String,
    /// Index of one of six preset colours.
    pub colour: u8,
    /// Yjs v1 relative positions, as sent.
    pub anchor: Vec<u8>,
    pub head: Vec<u8>,
}

impl std::fmt::Debug for RemotePresence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RemotePresence(..)")
    }
}

/// Every remote caret this device currently shows, bounded by [`MAX_REMOTE`].
///
/// Each published value is the whole state, so a host that reads only the
/// latest value still sees every removal.
#[derive(Clone, Default)]
pub struct RemoteState(Arc<Vec<RemotePresence>>);

impl RemoteState {
    pub fn entries(&self) -> &[RemotePresence] {
        &self.0
    }
}

impl std::fmt::Debug for RemoteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RemoteState(..)")
    }
}

/// This device's own-device presence, as the native host uses it.
///
/// All methods are nonblocking and safe from any thread. Presence stays
/// dormant (no socket, no permits) until [`Presence::configure`] and
/// [`Presence::foreground`] have both been used.
///
/// Windows are the host's own window names (the same ones it gives
/// `note_selection` and the local peer relay). A host:
/// - calls [`Presence::configure`] once with the pairing label and colour;
/// - calls [`Presence::set`] on selection change and when a note window gains
///   focus (a window must call `set` at least once before it can receive
///   other devices' carets for that note);
/// - calls [`Presence::clear`] when a window closes or navigates away;
/// - calls [`Presence::foreground`] with the app's foreground state, and
///   [`Presence::leave`] when it pauses or quits: `leave` announces nothing
///   to show and keeps each window's selection, so a resume resends it
///   without a new `set` (an Android page keeps its focus across a pause);
/// - reads [`Presence::subscribe`] and diffs it against what is already shown.
#[derive(Clone)]
pub struct Presence {
    state: Arc<State>,
}

impl Presence {
    pub(crate) fn new() -> Self {
        Self {
            state: State::new(),
        }
    }

    /// The label and colour this device's caret is shown with elsewhere. The
    /// label is truncated to [`MAX_LABEL`] bytes on a character boundary;
    /// `colour` is clamped to one of six preset colours (0..=5). The host
    /// picks the colour, bumping it if another device already uses it.
    pub fn configure(&self, label: &str, colour: u8) {
        let mut config = self.state.config.lock().expect("presence config");
        config.label = truncate(label);
        config.colour = colour.min(5);
        config.configured = true;
        drop(config);
        self.state.wake();
    }

    /// Report `window`'s selection in `note` as Yjs v1 relative positions. The
    /// most recent window to call wins for the note. Returns false, sending
    /// nothing, for an empty or over-long position, a position that is not a
    /// decodable Yjs v1 sticky index, or an all-zero note id.
    pub fn set(&self, window: &str, note: [u8; 32], anchor: Vec<u8>, head: Vec<u8>) -> bool {
        if note.iter().all(|byte| *byte == 0) || !valid_position(&anchor) || !valid_position(&head)
        {
            return false;
        }
        let mut local = self.state.local.lock().expect("presence local");
        // A window may have navigated: its old note falls back or clears.
        local.remove_window(window);
        local.tick += 1;
        let tick = local.tick;
        local.windows.insert(
            window.to_owned(),
            Window {
                note,
                selection: Selection { anchor, head },
                tick,
            },
        );
        if !local.notes.contains_key(&note) {
            while local.notes.len() >= MAX_LOCAL_NOTES {
                let Some(evicted) = local
                    .notes
                    .iter()
                    .min_by_key(|(_, held)| held.tick)
                    .map(|(id, _)| *id)
                else {
                    break;
                };
                local.evict(evicted, tick);
            }
        }
        local.clears.remove(&note);
        let selection = local.windows[window].selection.clone();
        match local.notes.get_mut(&note) {
            Some(held) => {
                held.selection = Some(selection);
                held.tick = tick;
                held.pending = true;
            }
            None => {
                local.notes.insert(
                    note,
                    Note {
                        selection: Some(selection),
                        tick,
                        pending: true,
                    },
                );
            }
        }
        drop(local);
        self.state.wake();
        true
    }

    /// `window` closed or left its note: the note's next most recently active
    /// window on that note takes over, or its caret is cleared.
    pub fn clear(&self, window: &str) {
        let Some(closed) = self
            .state
            .local
            .lock()
            .expect("presence local")
            .remove_window(window)
        else {
            return;
        };
        let note = closed.note;
        let open = self.state.is_open(note);
        self.state.remote_retain_note(note, open);
        self.state.wake();
    }

    /// The app is foreground. Turning it off sends `cleared` best effort and
    /// closes the join; this device's own selections are kept and resent when
    /// it returns.
    pub fn foreground(&self, on: bool) {
        let mut config = self.state.config.lock().expect("presence config");
        config.foreground = on;
        drop(config);
        self.state.wake();
    }

    /// Pause or quit: announce there is nothing to show and close the join.
    /// Each window's selection is kept, so a resume rejoins, resends it and
    /// shows the other devices' carets again before anyone moves; a window
    /// that closed meanwhile has called [`Presence::clear`]. Best effort;
    /// returns at once.
    pub fn leave(&self) {
        self.foreground(false);
    }

    /// The current remote carets. Every value is the whole bounded state, so a
    /// slow reader can miss an intermediate value but never a removal.
    pub fn subscribe(&self) -> watch::Receiver<RemoteState> {
        self.state.remote_state.subscribe()
    }
}

impl std::fmt::Debug for Presence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Presence(..)")
    }
}

/// A label cut to [`MAX_LABEL`] bytes without splitting a character.
fn truncate(label: &str) -> String {
    let mut end = label.len().min(MAX_LABEL);
    while !label.is_char_boundary(end) {
        end -= 1;
    }
    label[..end].to_owned()
}

/// A Yjs v1 sticky index of bounded size, or false.
fn valid_position(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.len() <= MAX_POSITION && writer_of(bytes).is_ok()
}

/// The writer a position names, or `None` for a position on the root, after
/// decoding and bounding it. Malformed bytes are refused.
fn writer_of(bytes: &[u8]) -> Result<Option<u64>, ()> {
    if bytes.is_empty() || bytes.len() > MAX_POSITION {
        return Err(());
    }
    let index = StickyIndex::decode_v1(bytes).map_err(|_| ())?;
    if index.assoc != Assoc::Before && index.assoc != Assoc::After {
        return Err(());
    }
    Ok(match index.scope() {
        IndexScope::Relative(ID { client, .. }) | IndexScope::Nested(ID { client, .. }) => {
            Some(client.get())
        }
        IndexScope::Root(_) => None,
    })
}

#[derive(Clone)]
struct Selection {
    anchor: Vec<u8>,
    head: Vec<u8>,
}

struct Window {
    note: [u8; 32],
    selection: Selection,
    tick: u64,
}

struct Note {
    selection: Option<Selection>,
    tick: u64,
    pending: bool,
}

#[derive(Default)]
struct Local {
    windows: HashMap<String, Window>,
    notes: BTreeMap<[u8; 32], Note>,
    /// Notes evicted while held, to be sent `cleared`.
    clears: BTreeMap<[u8; 32], u64>,
    tick: u64,
    last_seq: u64,
}

impl Local {
    /// Forget `window`, falling back to that note's next window or clearing
    /// it. Only the note's active window changes the shown value.
    fn remove_window(&mut self, window: &str) -> Option<Window> {
        let closed = self.windows.remove(window)?;
        let note = closed.note;
        let active = self
            .notes
            .get(&note)
            .is_some_and(|held| held.tick == closed.tick);
        self.tick += 1;
        let tick = self.tick;
        let fallback = self
            .windows
            .values()
            .filter(|window| window.note == note)
            .max_by_key(|window| window.tick)
            .map(|window| window.selection.clone());
        if fallback.is_some() {
            if active && let Some(held) = self.notes.get_mut(&note) {
                held.selection = fallback;
                held.tick = tick;
                held.pending = true;
            }
        } else if let Some(held) = self.notes.get_mut(&note) {
            held.selection = None;
            held.tick = tick;
            held.pending = true;
        }
        Some(closed)
    }

    /// Drop a note and its windows, remembering to send `cleared` for it.
    fn evict(&mut self, note: [u8; 32], tick: u64) {
        self.notes.remove(&note);
        self.windows.retain(|_, window| window.note != note);
        self.clears.insert(note, tick);
        while self.clears.len() > MAX_LOCAL_NOTES {
            let Some(oldest) = self
                .clears
                .iter()
                .min_by_key(|(_, tick)| **tick)
                .map(|(note, _)| *note)
            else {
                break;
            };
            self.clears.remove(&oldest);
        }
    }
}

#[derive(Default)]
struct Config {
    label: String,
    colour: u8,
    configured: bool,
    foreground: bool,
}

struct Entry {
    slot: u32,
    seq: u64,
    label: String,
    colour: u8,
    anchor: Vec<u8>,
    head: Vec<u8>,
}

#[derive(Default)]
struct Remote {
    entries: BTreeMap<([u8; 16], [u8; 32]), Entry>,
}

struct State {
    config: Mutex<Config>,
    local: Mutex<Local>,
    remote: Mutex<Remote>,
    wake: watch::Sender<u64>,
    remote_state: watch::Sender<RemoteState>,
}

impl State {
    fn new() -> Arc<Self> {
        let (remote_state, _) = watch::channel(RemoteState::default());
        Arc::new(Self {
            config: Mutex::default(),
            local: Mutex::default(),
            remote: Mutex::default(),
            wake: watch::Sender::new(0),
            remote_state,
        })
    }

    fn wake(&self) {
        self.wake
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    /// Configured and foreground: a session may run.
    fn ready(&self) -> bool {
        let config = self.config.lock().expect("presence config");
        config.configured && config.foreground
    }

    /// Ready and with something that needs this device's join: an open note
    /// window, or a pending `cleared` for the last one that closed.
    fn should_run(&self) -> bool {
        if !self.ready() {
            return false;
        }
        let local = self.local.lock().expect("presence local");
        !local.windows.is_empty()
            || local.notes.values().any(|note| note.pending)
            || !local.clears.is_empty()
    }

    /// Whether this device currently shows `note` in some window.
    fn is_open(&self, note: [u8; 32]) -> bool {
        self.local
            .lock()
            .expect("presence local")
            .windows
            .values()
            .any(|window| window.note == note)
    }

    /// (label, colour) once configured.
    fn config(&self) -> Option<(String, u8)> {
        let config = self.config.lock().expect("presence config");
        config
            .configured
            .then(|| (config.label.clone(), config.colour))
    }

    fn pending(&self) -> bool {
        let local = self.local.lock().expect("presence local");
        local.notes.values().any(|note| note.pending) || !local.clears.is_empty()
    }

    /// The next value to send: an evicted note's clear, or the most recently
    /// active pending selection. The tick identifies the exact value, so a
    /// later change stays pending.
    fn next_send(&self) -> Option<([u8; 32], Option<Selection>, u64)> {
        let local = self.local.lock().expect("presence local");
        if let Some((note, tick)) = local
            .clears
            .iter()
            .max_by_key(|(_, tick)| **tick)
            .map(|(note, tick)| (*note, *tick))
        {
            return Some((note, None, tick));
        }
        local
            .notes
            .iter()
            .filter(|(_, note)| note.pending)
            .max_by_key(|(_, note)| note.tick)
            .map(|(id, note)| (*id, note.selection.clone(), note.tick))
    }

    /// The notes a leaving join should clear.
    fn held_notes(&self) -> Vec<[u8; 32]> {
        let local = self.local.lock().expect("presence local");
        let mut notes: Vec<[u8; 32]> = local.notes.keys().copied().collect();
        notes.extend(local.clears.keys().copied());
        notes
    }

    fn sent(&self, note: [u8; 32], tick: u64, cleared: bool, seq: u64) {
        let mut local = self.local.lock().expect("presence local");
        local.last_seq = local.last_seq.max(seq);
        if cleared {
            if local.clears.get(&note) == Some(&tick) {
                local.clears.remove(&note);
            }
            if local
                .notes
                .get(&note)
                .is_some_and(|held| held.selection.is_none())
            {
                local.notes.remove(&note);
            }
        } else if let Some(held) = local.notes.get_mut(&note)
            && held.tick == tick
        {
            held.pending = false;
        }
    }

    /// Abandon a value that cannot be sent now (no other device, malformed
    /// position): it is sent again on the next roster `joined` or snapshot.
    fn deferred(&self, note: [u8; 32], tick: u64, cleared: bool) {
        let mut local = self.local.lock().expect("presence local");
        if cleared {
            if local.clears.get(&note) == Some(&tick) {
                local.clears.remove(&note);
            }
            if local
                .notes
                .get(&note)
                .is_some_and(|held| held.selection.is_none())
            {
                local.notes.remove(&note);
            }
        } else if let Some(held) = local.notes.get_mut(&note)
            && held.tick == tick
        {
            held.pending = false;
        }
    }

    /// `max(previous + 1, unix_ms)`, so a sender's frames order within one
    /// run. Across a relaunch only the slot identifies the new incarnation;
    /// a wall clock that went backwards can lower it.
    fn next_sequence(&self) -> u64 {
        let last = self.local.lock().expect("presence local").last_seq;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        now.max(last + 1)
    }

    fn mark_all_pending(&self) {
        let mut local = self.local.lock().expect("presence local");
        for note in local.notes.values_mut() {
            note.pending = true;
        }
    }

    /// A roster change: `event` 2 removes that slot's carets.
    fn peers(&self, others: u16, event: u8, slot: u32) {
        if event == 2 {
            self.left(slot);
        }
        if others == 0 {
            self.clear_remote();
        }
    }

    fn left(&self, slot: u32) {
        let removed = {
            let mut remote = self.remote.lock().expect("presence remote");
            let before = remote.entries.len();
            remote.entries.retain(|_, entry| entry.slot != slot);
            remote.entries.len() != before
        };
        if removed {
            self.publish();
        }
    }

    fn clear_remote(&self) {
        let changed = {
            let mut remote = self.remote.lock().expect("presence remote");
            let changed = !remote.entries.is_empty();
            remote.entries.clear();
            changed
        };
        if changed {
            self.publish();
        }
    }

    /// Closing `note`'s last window drops its remote entries; another open
    /// window on it keeps them.
    fn remote_retain_note(&self, note: [u8; 32], keep: bool) {
        let changed = {
            let mut remote = self.remote.lock().expect("presence remote");
            let before = remote.entries.len();
            remote
                .entries
                .retain(|(_, held), _| (*held == note) == keep);
            remote.entries.len() != before
        };
        if changed {
            self.publish();
        }
    }

    fn publish(&self) {
        let remote = self.remote.lock().expect("presence remote");
        let state = RemoteState(Arc::new(
            remote
                .entries
                .iter()
                .map(|((handle, note), entry)| RemotePresence {
                    handle: *handle,
                    note: *note,
                    label: entry.label.clone(),
                    colour: entry.colour,
                    anchor: entry.anchor.clone(),
                    head: entry.head.clone(),
                })
                .collect(),
        ));
        drop(remote);
        self.remote_state.send_replace(state);
    }

    /// Apply one authenticated record from `slot`.
    fn received(&self, from: u32, record: PresenceRecord) {
        let key = (record.handle, record.note);
        let changed = {
            let mut remote = self.remote.lock().expect("presence remote");
            if record.kind == 2 {
                // Only a clear from the caret's own incarnation removes it; an
                // old slot's late clear cannot delete a relaunched caret.
                let present = remote
                    .entries
                    .get(&key)
                    .is_some_and(|entry| entry.slot == from);
                if present {
                    remote.entries.remove(&key);
                }
                present
            } else if remote
                .entries
                .get(&key)
                .is_some_and(|entry| entry.slot == from && record.seq <= entry.seq)
                || (!remote.entries.contains_key(&key) && remote.entries.len() >= MAX_REMOTE)
            {
                false
            } else {
                remote.entries.insert(
                    key,
                    Entry {
                        slot: from,
                        seq: record.seq,
                        label: record.label,
                        colour: record.colour,
                        anchor: record.anchor,
                        head: record.head,
                    },
                );
                true
            }
        };
        if changed {
            self.publish();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fail {
    Halt,
    /// No usable own-base epoch yet; look again shortly.
    NotReady,
    /// The epoch is closed, the base stopped or this device's authority is
    /// gone: only accepted history (a control) can change that.
    Closed,
    Auth,
    Network,
}

enum Outcome {
    Halt,
    Dormant,
    Rejoin { epoch: bool },
}

enum Sent {
    /// The frame was written to the socket.
    Written,
    /// Nothing needed sending.
    Done,
    /// A position names a writer without an accepted binding here yet.
    Withheld,
    /// No room in the socket's outgoing queue; keep it pending.
    Busy,
}

struct Session {
    socket: DataSocket,
    answers: Answers,
    join_id: u32,
    renew_at: Instant,
    epoch: [u8; 32],
    base: [u8; 32],
    log: LogId,
    fence: SyncFence,
    /// Other devices in the roster, as the last `Peers` said.
    others: u16,
    /// The earliest instant another frame may be sent.
    next_send_at: Option<Instant>,
    /// Waiting for a writer's accepted echo; do not poll for it.
    withheld: bool,
}

/// The presence task: dormant until configured and foreground with a window.
pub(crate) async fn run(shared: Arc<Shared>) {
    let hub = shared.presence.state.clone();
    let mut local = hub.wake.subscribe();
    let mut client = shared.wake.subscribe();
    let mut windows = shared.windows.generation();
    let mut backoff = Backoff::default();
    loop {
        if shared.is_halted() {
            return;
        }
        if !hub.should_run() {
            hub.clear_remote();
            if idle(&shared, &hub, None, &mut local, &mut client, &mut windows).await {
                return;
            }
            continue;
        }
        match open_session(&shared, &hub).await {
            Ok(session) => {
                match run_session(
                    &shared,
                    &hub,
                    session,
                    &mut local,
                    &mut client,
                    &mut windows,
                    &mut backoff,
                )
                .await
                {
                    Outcome::Halt => return,
                    Outcome::Dormant => continue,
                    Outcome::Rejoin { epoch } => {
                        hub.clear_remote();
                        // An epoch refusal keeps its 0-2 s spread, but a
                        // repeated one must also grow the wait: a server that
                        // refuses every join must not cost a permit each time.
                        let wait = if epoch {
                            backoff.next() + jitter()
                        } else {
                            backoff.next()
                        };
                        if idle(
                            &shared,
                            &hub,
                            Some(wait),
                            &mut local,
                            &mut client,
                            &mut windows,
                        )
                        .await
                        {
                            return;
                        }
                    }
                }
            }
            Err(Fail::Halt) => return,
            Err(fail) => {
                hub.clear_remote();
                let wait = match fail {
                    Fail::NotReady => Some(NOT_READY_RETRY),
                    Fail::Closed => None,
                    _ => Some(backoff.next()),
                };
                if idle(&shared, &hub, wait, &mut local, &mut client, &mut windows).await {
                    return;
                }
            }
        }
    }
}

/// Wait for a local change, a host or window wake, or `wait`. True when the
/// client has halted.
async fn idle(
    shared: &Shared,
    hub: &State,
    wait: Option<Duration>,
    local: &mut watch::Receiver<u64>,
    client: &mut watch::Receiver<u64>,
    windows: &mut watch::Receiver<u64>,
) -> bool {
    let deadline = async move {
        match wait {
            Some(wait) => tokio::time::sleep(wait).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(deadline);
    // A pending retry deadline is the rejoin policy. An active device reports
    // selections every few tens of milliseconds, accepted history wakes
    // windows while content flows, and every local note commit calls
    // `Client::wake()` (the host's "look for new local work now"); those only
    // change what will be sent. If any of them ended the wait, each would cost
    // a fresh permit and join. Only the deadline, a halt, or the host
    // leaving/backgrounding ends the wait.
    let retry = wait.is_some();
    loop {
        tokio::select! {
            biased;
            _ = shared.halted() => return true,
            result = local.changed() => {
                if result.is_err() || !retry || !hub.should_run() {
                    return result.is_err();
                }
            }
            result = client.changed() => {
                if result.is_err() || !retry || !hub.should_run() {
                    return result.is_err();
                }
            }
            result = windows.changed() => {
                if result.is_err() || !retry {
                    return result.is_err();
                }
            }
            _ = &mut deadline => return false,
        }
    }
}

fn jitter() -> Duration {
    let bytes = random::<2>();
    Duration::from_millis(u64::from(u16::from_be_bytes(bytes)) % REJOIN_JITTER_MS)
}

/// This container's own base, its current epoch, and whether it is usable.
fn target(shared: &Shared) -> Result<(LogId, [u8; 32], [u8; 32]), Fail> {
    let database = shared
        .owner
        .shared_database(shared.container)
        .map_err(|_| Fail::Closed)?;
    let db = database.lock().map_err(|_| Fail::Closed)?;
    let Some(own) = db.own_base().map_err(|_| Fail::Closed)? else {
        return Err(Fail::NotReady);
    };
    let log = LogId {
        kind: LogKind::Base,
        id: own.base,
    };
    let Some(progress) = db
        .log_progress(LogKind::Base as u8, own.base)
        .map_err(|_| Fail::Closed)?
    else {
        return Err(Fail::NotReady);
    };
    if progress.stopped.is_some() {
        return Err(Fail::Closed);
    }
    let Some(epoch) = progress.epoch_id else {
        return Err(Fail::Closed);
    };
    Ok((log, epoch, own.base))
}

async fn acquire(
    shared: &Arc<Shared>,
    log: LogId,
    epoch: [u8; 32],
) -> Result<(Vec<u8>, Instant), Fail> {
    // Conservative: the permit's life started when it was asked for, not when
    // the answer reached us.
    let requested_at = Instant::now();
    let message = ToService::Permits {
        items: vec![Want::Presence { log, epoch }],
    };
    let answer = tokio::select! {
        biased;
        _ = shared.halted() => return Err(Fail::Halt),
        answer = shared.authz.request(shared, message) => answer.map_err(|_| Fail::Auth)?,
    };
    let FromService::Permits { items } = answer else {
        return Err(Fail::Auth);
    };
    let Some(Ok(signed)) = items.into_iter().next() else {
        return Err(Fail::Auth);
    };
    let until =
        usable_until(shared.endpoint.hosting_root, &signed, requested_at).ok_or(Fail::Auth)?;
    Ok((signed, until))
}

async fn open_session(shared: &Arc<Shared>, hub: &Arc<State>) -> Result<Session, Fail> {
    if !hub.should_run() {
        return Err(Fail::NotReady);
    }
    let (log, epoch, base) = target(shared)?;
    let fence = shared
        .owner
        .sync_fence(shared.container, log)
        .map_err(|error| match error {
            OwnerError::Stopped | OwnerError::Unbound | OwnerError::NotRegistered => Fail::Closed,
            _ => Fail::NotReady,
        })?;
    let (permit, until) = acquire(shared, log, epoch).await?;
    if !hub.should_run() {
        return Err(Fail::NotReady);
    }
    let socket = tokio::select! {
        biased;
        _ = shared.halted() => return Err(Fail::Halt),
        socket = DataSocket::open(shared.connector.as_ref()) => socket.map_err(|_| Fail::Network)?,
    };
    let answers = socket
        .send(|id| Request::PresenceJoin { id, permit })
        .map_err(|_| Fail::Network)?;
    let join_id = answers.id();
    Ok(Session {
        socket,
        answers,
        join_id,
        renew_at: until,
        epoch,
        base,
        log,
        fence,
        others: 0,
        next_send_at: None,
        withheld: false,
    })
}

async fn run_session(
    shared: &Arc<Shared>,
    hub: &Arc<State>,
    mut session: Session,
    local: &mut watch::Receiver<u64>,
    client: &mut watch::Receiver<u64>,
    windows: &mut watch::Receiver<u64>,
    backoff: &mut Backoff,
) -> Outcome {
    loop {
        if shared.is_halted() {
            end_session(shared, hub, &mut session, true).await;
            return Outcome::Halt;
        }
        if !hub.should_run() {
            end_session(shared, hub, &mut session, true).await;
            return Outcome::Dormant;
        }
        let mut timer = session.renew_at;
        if session.others > 0 && hub.pending() && !session.withheld {
            timer = timer.min(session.next_send_at.unwrap_or_else(Instant::now));
        }
        let sleep = tokio::time::sleep_until(timer);
        tokio::pin!(sleep);
        tokio::select! {
            biased;
            _ = shared.halted() => {
                end_session(shared, hub, &mut session, true).await;
                return Outcome::Halt;
            }
            result = local.changed() => {
                if result.is_err() {
                    end_session(shared, hub, &mut session, true).await;
                    return Outcome::Halt;
                }
                // A selection reports often; the send itself rechecks the
                // epoch under the fence, so do not take the container's
                // database lock on every `set`.
                session.retry(hub);
            }
            result = client.changed() => {
                if result.is_err() {
                    end_session(shared, hub, &mut session, true).await;
                    return Outcome::Halt;
                }
                if !session.epoch_current(shared) {
                    end_session(shared, hub, &mut session, false).await;
                    return Outcome::Rejoin { epoch: false };
                }
                session.retry(hub);
            }
            result = windows.changed() => {
                if result.is_err() {
                    end_session(shared, hub, &mut session, true).await;
                    return Outcome::Halt;
                }
                if !session.epoch_current(shared) {
                    end_session(shared, hub, &mut session, false).await;
                    return Outcome::Rejoin { epoch: false };
                }
                session.retry(hub);
            }
            next = session.answers.next() => match next {
                None => {
                    end_session(shared, hub, &mut session, false).await;
                    return Outcome::Rejoin { epoch: false };
                }
                Some(Response::Peers { others, event, slot, .. }) => {
                    // Any roster answer proves this join was admitted, so the
                    // next failure starts the backoff from the beginning.
                    backoff.reset();
                    session.others = others;
                    hub.peers(others, event, slot);
                    if others > 0 && event <= 1 {
                        hub.mark_all_pending();
                        session.withheld = false;
                        // Still at most one frame per SEND_INTERVAL.
                        session.next_send_at.get_or_insert_with(Instant::now);
                    }
                }
                Some(Response::Presence { from, sealed, .. }) => {
                    receive(shared, hub, &session.fence, session.epoch, session.base, from, &sealed);
                }
                Some(Response::Refused { reason, .. }) => {
                    end_session(shared, hub, &mut session, false).await;
                    return Outcome::Rejoin { epoch: reason == Refusal::Epoch };
                }
                Some(_) => {}
            },
            _ = &mut sleep => {
                if Instant::now() >= session.renew_at {
                    match renew(shared, &mut session).await {
                        Ok(until) => session.renew_at = until,
                        Err(Fail::Halt) => {
                            end_session(shared, hub, &mut session, true).await;
                            return Outcome::Halt;
                        }
                        Err(_) => {
                            end_session(shared, hub, &mut session, false).await;
                            return Outcome::Rejoin { epoch: false };
                        }
                    }
                } else {
                    match send_pending(shared, hub, &mut session).await {
                        Ok(Sent::Written) => {
                            session.withheld = false;
                            session.next_send_at = Some(Instant::now() + SEND_INTERVAL);
                        }
                        Ok(Sent::Done) => {
                            session.withheld = false;
                            session.next_send_at = None;
                        }
                        Ok(Sent::Withheld) => {
                            session.withheld = true;
                            session.next_send_at = None;
                        }
                        Ok(Sent::Busy) => {
                            session.withheld = false;
                            session.next_send_at = Some(Instant::now() + SEND_INTERVAL);
                        }
                        Err(Fail::Halt) => {
                            end_session(shared, hub, &mut session, true).await;
                            return Outcome::Halt;
                        }
                        Err(_) => {
                            end_session(shared, hub, &mut session, false).await;
                            return Outcome::Rejoin { epoch: false };
                        }
                    }
                }
            }
        }
    }
}

impl Session {
    /// This container's own base still has this session's epoch under current
    /// authority: a control, a stop or a closure ends the session at once.
    fn epoch_current(&self, shared: &Shared) -> bool {
        target(shared).is_ok_and(|(log, epoch, _)| log == self.log && epoch == self.epoch)
    }

    /// Another frame may go now (a local change, a host wake or accepted
    /// history): a withheld value is rechecked, an unsent one can start.
    fn retry(&mut self, hub: &State) {
        if self.others == 0 || !hub.pending() {
            return;
        }
        if self.withheld {
            self.withheld = false;
            self.next_send_at = Some(Instant::now());
        }
    }
}

async fn renew(shared: &Arc<Shared>, session: &mut Session) -> Result<Instant, Fail> {
    let (permit, until) = acquire(shared, session.log, session.epoch).await?;
    let answers = session
        .socket
        .send(|id| Request::PresenceJoin { id, permit })
        .map_err(|_| Fail::Network)?;
    // Same epoch: the edge keeps this socket's upstream and slot; only the id
    // and deadline move. Remote state stays as it was.
    session.join_id = answers.id();
    session.answers = answers;
    Ok(until)
}

/// The bound writers for these positions have accepted history here, under
/// this session's epoch and the current owner authority.
fn bindings_ok(
    db: &mut bh_storage::DeviceDatabase,
    anchor: &[u8],
    head: &[u8],
    key: NoteKey,
    base: [u8; 32],
    epoch: [u8; 32],
) -> Result<bool, OwnerError> {
    let progress = db
        .log_progress(LogKind::Base as u8, base)?
        .ok_or(OwnerError::NotRegistered)?;
    if progress.stopped.is_some() {
        return Err(OwnerError::Stopped);
    }
    if progress.epoch_id != Some(epoch) {
        return Err(OwnerError::Changed);
    }
    // A clear names no writer; a selection names up to two.
    let (anchor, head) = match (anchor.is_empty(), head.is_empty()) {
        (true, true) => (None, None),
        (false, false) => (
            writer_of(anchor).map_err(|_| OwnerError::InvalidBatch)?,
            writer_of(head).map_err(|_| OwnerError::InvalidBatch)?,
        ),
        _ => return Err(OwnerError::InvalidBatch),
    };
    let mut checked = [None, None];
    for writer in [anchor, head].into_iter().flatten() {
        if checked.contains(&Some(writer)) {
            continue;
        }
        if db
            .accepted_binding(key, writer)
            .map_err(OwnerError::Store)?
            .is_none()
        {
            return Ok(false);
        }
        let slot = checked
            .iter()
            .position(Option::is_none)
            .expect("two writers");
        checked[slot] = Some(writer);
    }
    Ok(true)
}

async fn send_pending(
    shared: &Arc<Shared>,
    hub: &Arc<State>,
    session: &mut Session,
) -> Result<Sent, Fail> {
    let Some((note, selection, tick)) = hub.next_send() else {
        return Ok(Sent::Done);
    };
    let cleared = selection.is_none();
    if session.others == 0 {
        // Nothing to show it to; the next roster snapshot resends it.
        hub.deferred(note, tick, cleared);
        return Ok(Sent::Done);
    }
    let Some((label, colour)) = hub.config() else {
        return Ok(Sent::Done);
    };
    let (anchor, head) = match &selection {
        Some(selection) => (selection.anchor.as_slice(), selection.head.as_slice()),
        None => (&[][..], &[][..]),
    };
    if !cleared && (!valid_position(anchor) || !valid_position(head)) {
        hub.deferred(note, tick, false);
        return Ok(Sent::Done);
    }
    let key = NoteKey {
        base: session.base,
        audience: OWN_AUDIENCE,
        note,
    };
    let base = session.base;
    let epoch = session.epoch;
    match shared.owner.with_sync_fence(&session.fence, |db| {
        bindings_ok(db, anchor, head, key, base, epoch)
    }) {
        Ok(true) => {}
        Ok(false) => return Ok(Sent::Withheld),
        Err(_) => {
            return Err(Fail::Auth);
        }
    }
    let identity = shared.signer.identity().map_err(|_| Fail::Auth)?;
    let seq = hub.next_sequence();
    let mut sealed = None;
    shared
        .signer
        .with_base_keys(BaseId(base), &mut |_, content: &Secret<32>| {
            // The key stays inside this closure: only the sealed frame leaves.
            // It must be the stored epoch's key, or a removed device could
            // still hold the root a labelled frame is sealed under.
            if bh_event::key_id(content) != epoch {
                return;
            }
            let record = PresenceRecord {
                kind: if cleared { 2 } else { 1 },
                handle: presence::handle(content, identity.device),
                seq,
                colour,
                note,
                anchor: anchor.to_vec(),
                head: head.to_vec(),
                label: if cleared {
                    String::new()
                } else {
                    label.clone()
                },
            };
            sealed = presence::seal(content, base, base, epoch, &record).ok();
        })
        .map_err(|_| Fail::Auth)?;
    let Some(sealed) = sealed.filter(|sealed| sealed.len() == SEALED_LEN) else {
        hub.deferred(note, tick, cleared);
        return Ok(Sent::Done);
    };
    let id = session.join_id;
    let step = shared.owner.with_sync_fence(&session.fence, |db| {
        if !bindings_ok(db, anchor, head, key, base, epoch)? {
            return Ok(Sent::Withheld);
        }
        Ok(
            match session.socket.send_quiet(Request::Presence { id, sealed }) {
                Ok(()) => Sent::Written,
                Err(_) => Sent::Busy,
            },
        )
    });
    match step {
        Ok(Sent::Written) => {
            hub.sent(note, tick, cleared, seq);
            Ok(Sent::Written)
        }
        Ok(step) => Ok(step),
        Err(_) => Err(Fail::Auth),
    }
}

fn receive(
    shared: &Arc<Shared>,
    hub: &Arc<State>,
    fence: &SyncFence,
    epoch: [u8; 32],
    base: [u8; 32],
    from: u32,
    sealed: &[u8],
) {
    if sealed.len() != SEALED_LEN || sealed[1..33] != epoch {
        return;
    }
    let mut opened = None;
    if shared
        .signer
        .with_base_keys(BaseId(base), &mut |_, content: &Secret<32>| {
            if bh_event::key_id(content) != epoch {
                return;
            }
            opened = presence::open(content, base, base, epoch, sealed).ok();
        })
        .is_err()
    {
        return;
    }
    let Some(record) = opened else {
        return;
    };
    match record.kind {
        1 => {
            if record.note.iter().all(|byte| *byte == 0)
                || !valid_position(&record.anchor)
                || !valid_position(&record.head)
            {
                return;
            }
        }
        2 => {
            if !record.anchor.is_empty() || !record.head.is_empty() {
                return;
            }
        }
        _ => return,
    }
    if !hub.is_open(record.note) {
        return;
    }
    let valid = shared
        .owner
        .with_sync_fence(fence, |db: &mut bh_storage::DeviceDatabase| {
            let progress = db
                .log_progress(LogKind::Base as u8, base)?
                .ok_or(OwnerError::NotRegistered)?;
            if progress.stopped.is_some() {
                return Err(OwnerError::Stopped);
            }
            if progress.epoch_id != Some(epoch) {
                return Err(OwnerError::Changed);
            }
            Ok(())
        })
        .is_ok();
    if !valid {
        return;
    }
    hub.received(from, record);
}

/// End this session: best-effort `cleared` frames when we are leaving while
/// the join is still live, then close it and forget every remote caret. This
/// device's own selections stay, so a rejoin resends them or a resume keeps
/// whatever the host has reported since.
async fn end_session(shared: &Arc<Shared>, hub: &Arc<State>, session: &mut Session, clears: bool) {
    if clears && session.others > 0 {
        send_clears(shared, hub, session).await;
        // Give the writer task a bounded moment to put them on the wire; the
        // socket close alone also removes this device's carets.
        tokio::time::sleep(CLEAR_FLUSH).await;
    }
    session.socket.shutdown().await;
    hub.clear_remote();
}

/// Seal and enqueue a `cleared` for each held note on the current join. No
/// wait for delivery and no new permit.
async fn send_clears(shared: &Arc<Shared>, hub: &Arc<State>, session: &mut Session) {
    let Some((_, colour)) = hub.config() else {
        return;
    };
    let Ok(identity) = shared.signer.identity() else {
        return;
    };
    let notes = hub.held_notes();
    let base = session.base;
    let epoch = session.epoch;
    for note in notes {
        let seq = hub.next_sequence();
        let mut sealed = None;
        let _ = shared
            .signer
            .with_base_keys(BaseId(base), &mut |_, content: &Secret<32>| {
                if bh_event::key_id(content) != epoch {
                    return;
                }
                let record = PresenceRecord {
                    kind: 2,
                    handle: presence::handle(content, identity.device),
                    seq,
                    colour,
                    note,
                    anchor: Vec::new(),
                    head: Vec::new(),
                    label: String::new(),
                };
                sealed = presence::seal(content, base, base, epoch, &record).ok();
            });
        if let Some(sealed) = sealed {
            let id = session.join_id;
            let _ = session.socket.send_quiet(Request::Presence { id, sealed });
        }
    }
}
