//! Native-only adapter. No store is opened and no note is bound until a real
//! verified account session supplies native authority. Setup has no note IPC.
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use bh_account::VerifiedAccount;
use bh_device::{ContainerId, Owner, OwnerError, coordinator::AuthoritySource};
use bh_storage::{DeviceDatabase, MAX_NOTE_PAGE, NoteKey};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, Runtime, WebviewWindow};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::lifecycle::{
    self, CapturedView, Lifecycle, MAX_CURSOR_OFFSET, Poster, Reason, Refusal, Scope as DrainScope,
    Target,
};

const MAX_STORAGE_TASKS: usize = 8;
const MAX_CONTAINER_TASKS: usize = 2;
const DELIVERY_WORKERS: usize = 2;
type Surface = (String, Box<WebviewWindow<tauri::Wry>>);
enum DeliveryTask {
    Surface(Surface, u64),
    Stop,
}
// PM positions are ephemeral and are refreshed on selection/document change.
// No cursor enters storage, sync or a cross-device presence path.
#[derive(Clone, Serialize)]
struct Peer {
    id: String,
    anchor: u32,
    head: u32,
}
struct CursorState {
    container: ContainerId,
    note: NoteKey,
    generation: u64,
    page: u64,
    peer: Peer,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct PeerTarget {
    label: String,
    container: ContainerId,
    note: NoteKey,
    generation: u64,
    page: u64,
}
impl CursorState {
    fn target(&self, label: &str) -> PeerTarget {
        PeerTarget {
            label: label.into(),
            container: self.container,
            note: self.note,
            generation: self.generation,
            page: self.page,
        }
    }
}
#[derive(Default)]
struct PeerCursors {
    // Publication and removal visit only windows of this note, not every
    // window open in another note or account on this device.
    groups: HashMap<(ContainerId, NoteKey), HashMap<String, CursorState>>,
    windows: HashMap<String, (ContainerId, NoteKey)>,
}
impl PeerCursors {
    /// Record this window's selection and say what its peers must draw. The
    /// third value is true when the window has just joined this note (opened
    /// it, or came from another one), so it also needs the remote carets the
    /// note already shows.
    fn publish(&mut self, window: &str, cursor: CursorState) -> (Vec<PeerTarget>, Vec<Peer>, bool) {
        let (container, note) = (cursor.container, cursor.note);
        let joined = match self.windows.get(window) {
            Some(previous) if *previous == (container, note) => false,
            Some(_) => {
                self.remove(window);
                true
            }
            None => true,
        };
        self.windows.insert(window.into(), (container, note));
        let group = self.groups.entry((container, note)).or_default();
        group.insert(window.into(), cursor);
        let mut targets = Vec::new();
        let mut visible = Vec::new();
        for (name, cursor) in group.iter() {
            if name != window && cursor.container == container && cursor.note == note {
                targets.push(cursor.target(name));
                visible.push(cursor.peer.clone());
            }
        }
        targets.sort_by(|a, b| a.label.cmp(&b.label));
        visible.sort_by(|a, b| a.id.cmp(&b.id));
        (targets, visible, joined)
    }
    fn remove(&mut self, window: &str) -> Vec<PeerTarget> {
        let Some(key) = self.windows.remove(window) else {
            return Vec::new();
        };
        let Some(group) = self.groups.get_mut(&key) else {
            return Vec::new();
        };
        group.remove(window);
        let targets = group.iter().map(|(name, peer)| peer.target(name)).collect();
        if group.is_empty() {
            self.groups.remove(&key);
        }
        targets
    }
    /// Every window bound to `note` in `container`, for one remote caret.
    /// A container holds one own base; its note id is enough to find them.
    fn targets_for(&self, container: ContainerId, note: [u8; 32]) -> Vec<PeerTarget> {
        let mut targets: Vec<PeerTarget> = self
            .groups
            .iter()
            .filter(|((id, key), _)| *id == container && key.note == note)
            .flat_map(|(_, group)| {
                group
                    .iter()
                    .map(|(name, cursor)| cursor.target(name))
                    .collect::<Vec<_>>()
            })
            .collect();
        targets.sort_by(|a, b| a.label.cmp(&b.label));
        targets
    }
    /// One bound window's delivery target. A window that has just opened the
    /// note uses it to draw the remote carets the note already shows; the
    /// lease and authority checks in `send_peers` still apply.
    fn target_for(&self, window: &str) -> Option<PeerTarget> {
        let key = self.windows.get(window)?;
        self.groups
            .get(key)?
            .get(window)
            .map(|cursor| cursor.target(window))
    }
}

/// The other devices' carets this device shows, keyed by account. Memory
/// only: never storage, a restart record, sync state or a note's saved bytes.
#[derive(Default)]
struct RemoteCarets {
    shown: HashMap<ContainerId, Vec<(RemoteKey, ShownRemote)>>,
    own: HashMap<ContainerId, u8>,
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RemoteKey {
    handle: [u8; 16],
    note: [u8; 32],
}
#[derive(Clone, PartialEq, Eq)]
struct ShownRemote {
    label: String,
    colour: u8,
    anchor: Vec<u8>,
    head: Vec<u8>,
}
fn remote_id(handle: &[u8; 16]) -> String {
    handle.iter().map(|byte| format!("{byte:02x}")).collect()
}
impl RemoteCarets {
    /// The carets this device currently shows for one note, so a window that
    /// opens the note now draws them without waiting for the other device to
    /// move. Hues are already the ones shown (collision-bumped).
    fn shown_for(&self, container: ContainerId, note: [u8; 32]) -> Vec<PeerMessage> {
        self.shown
            .get(&container)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter(|(key, _)| key.note == note)
            .map(|(key, shown)| PeerMessage::Remote {
                id: remote_id(&key.handle),
                label: shown.label.clone(),
                colour: shown.colour,
                anchor: shown.anchor.clone(),
                head: shown.head.clone(),
            })
            .collect()
    }
    /// This device's own hue in `container`, so a remote caret never borrows it.
    fn own_colour(&mut self, container: ContainerId, colour: u8) {
        self.own.insert(container, colour.min(5));
    }
    /// Replace one account's remote state and say what its windows must draw
    /// or remove. A hue that collides with this device's or another shown
    /// caret is bumped to the next free preset, in handle order.
    fn update(
        &mut self,
        container: ContainerId,
        state: &[bh_host::sync::RemotePresence],
    ) -> Vec<([u8; 32], PeerMessage)> {
        let mut by_note: BTreeMap<[u8; 32], Vec<&bh_host::sync::RemotePresence>> = BTreeMap::new();
        for presence in state {
            by_note.entry(presence.note).or_default().push(presence);
        }
        let own = self.own.get(&container).copied();
        let previous = self.shown.get(&container).map(Vec::as_slice).unwrap_or(&[]);
        let mut next = Vec::new();
        let mut messages = Vec::new();
        for (note, mut entries) in by_note {
            entries.sort_by_key(|presence| presence.handle);
            let mut used = BTreeSet::new();
            used.extend(own);
            for presence in entries {
                let mut colour = presence.colour.min(5);
                for _ in 0..6 {
                    if used.insert(colour) {
                        break;
                    }
                    colour = (colour + 1) % 6;
                }
                let key = RemoteKey {
                    handle: presence.handle,
                    note,
                };
                let shown = ShownRemote {
                    label: presence.label.clone(),
                    colour,
                    anchor: presence.anchor.clone(),
                    head: presence.head.clone(),
                };
                let changed = !previous
                    .iter()
                    .any(|(old, value)| *old == key && *value == shown);
                if changed {
                    messages.push((
                        note,
                        PeerMessage::Remote {
                            id: remote_id(&presence.handle),
                            label: shown.label.clone(),
                            colour,
                            anchor: shown.anchor.clone(),
                            head: shown.head.clone(),
                        },
                    ));
                }
                next.push((key, shown));
            }
        }
        for (key, _) in previous {
            if !next.iter().any(|(shown, _)| shown == key) {
                messages.push((
                    key.note,
                    PeerMessage::Remove {
                        id: remote_id(&key.handle),
                    },
                ));
            }
        }
        self.shown.insert(container, next);
        messages
    }
    /// Forget every caret this account is shown with, and say which windows
    /// remove them. Used when the client that reported them has gone.
    fn clear(&mut self, container: ContainerId) -> Vec<([u8; 32], PeerMessage)> {
        self.shown
            .remove(&container)
            .unwrap_or_default()
            .into_iter()
            .map(|(key, _)| {
                (
                    key.note,
                    PeerMessage::Remove {
                        id: remote_id(&key.handle),
                    },
                )
            })
            .collect()
    }
}
/// A callback can arrive after navigation/reopen. Only its exact lease can
/// release this surface; no worker waits for the WebView's main thread.
#[derive(Default)]
struct DeliveryState {
    active: HashMap<String, u64>,
    pages: HashMap<String, u64>,
}
#[derive(Default)]
struct DeliveryLeases {
    state: Mutex<DeliveryState>,
    next: AtomicU64,
}
impl DeliveryLeases {
    #[cfg(test)]
    fn start(&self, label: &str) -> Option<u64> {
        self.start_in(self.state.lock().expect("delivery lease lock"), label)
    }
    fn start_if_page(&self, label: &str, page: u64) -> Option<u64> {
        let state = self.state.lock().expect("delivery lease lock");
        if state.pages.get(label) != Some(&page) {
            return None;
        }
        self.start_in(state, label)
    }
    fn start_in(
        &self,
        mut state: std::sync::MutexGuard<'_, DeliveryState>,
        label: &str,
    ) -> Option<u64> {
        if state.active.contains_key(label) {
            return None;
        }
        let token = self
            .next
            .fetch_add(1, Ordering::Relaxed)
            .checked_add(1)
            .expect("delivery token exhausted");
        state.active.insert(label.into(), token);
        Some(token)
    }
    fn current(&self, label: &str, token: u64) -> bool {
        self.state
            .lock()
            .expect("delivery lease lock")
            .active
            .get(label)
            == Some(&token)
    }
    fn finish(&self, label: &str, token: u64) -> bool {
        let mut state = self.state.lock().expect("delivery lease lock");
        if state.active.get(label) != Some(&token) {
            return false;
        }
        state.active.remove(label);
        true
    }
    fn cancel(&self, label: &str) {
        let mut state = self.state.lock().expect("delivery lease lock");
        state.active.remove(label);
        state.pages.remove(label);
    }
    fn page(&self, label: &str) -> Option<u64> {
        self.state
            .lock()
            .expect("delivery lease lock")
            .pages
            .get(label)
            .copied()
    }
    fn bind_page(&self, label: &str) -> u64 {
        let mut state = self.state.lock().expect("delivery lease lock");
        let page = self
            .next
            .fetch_add(1, Ordering::Relaxed)
            .checked_add(1)
            .expect("page token exhausted");
        state.pages.insert(label.into(), page);
        page
    }
}
fn wake_delivery(
    sender: &mpsc::Sender<DeliveryTask>,
    leases: &DeliveryLeases,
    stopping: &AtomicBool,
    app: AppHandle<tauri::Wry>,
    label: String,
) {
    if stopping.load(Ordering::Acquire) {
        return;
    }
    // Capture wry's webview_id and its page incarnation at scheduling.
    // A lifecycle callback between lookup and admission cannot turn an old
    // handle into a lease for the new page.
    for _ in 0..2 {
        let Some(page) = leases.page(&label) else {
            return;
        };
        let Some(target) = app.get_webview_window(&label) else {
            return;
        };
        if let Some(token) = leases.start_if_page(&label, page) {
            if sender
                .send(DeliveryTask::Surface(
                    (label.clone(), Box::new(target)),
                    token,
                ))
                .is_err()
            {
                leases.finish(&label, token);
            }
            return;
        }
        if leases.page(&label) == Some(page) {
            return;
        } // existing lease
    }
}

/// Actual dispatcher seam: the native poster pins a WebviewWindow and posts
/// on its UI thread; tests use a bounded poster but exercise this same drain,
/// completion and retry path. A callback is not an acknowledgement if the
/// bridge reports stale/failed or if it is missing.
fn dispatch_surface(
    owner: &Arc<Owner>,
    leases: &Arc<DeliveryLeases>,
    label: &str,
    token: u64,
    mut post: impl FnMut(bh_device::coordinator::Delivery, Box<dyn Fn(String) + Send>) -> bool,
    on_next: Arc<dyn Fn() + Send + Sync>,
) -> (bool, bool) {
    if !leases.current(label, token) {
        return (true, false);
    }
    let page = leases.page(label);
    let mut wake_after_drain = false;
    let mut submitted = false;
    let delivered = owner.drain_surface_once(label, &mut |item| {
        submitted = true;
        let retry = bh_device::coordinator::Delivery {
            window: item.window.clone(),
            generation: item.generation,
            sequence: item.sequence,
            through_update_id: item.through_update_id,
            update: Vec::new(),
            resync: true,
            segments: Vec::new(),
            reload: item.reload,
        };
        if !owner.delivery_current(&retry) || !leases.current(label, token) {
            wake_after_drain = leases.finish(label, token) && owner.has_queued_delivery(label);
            return;
        }
        let callback_owner = Arc::clone(owner);
        let callback_leases = Arc::clone(leases);
        let callback_label = label.to_owned();
        let callback_retry = retry.clone();
        let next = Arc::clone(&on_next);
        let accepted = post(
            item,
            Box::new(move |value| {
                if !callback_leases.current(&callback_label, token) {
                    return;
                }
                let consumed = matches!(value.trim(), "\"accepted\"" | "\"buffered\"");
                let obsolete = callback_leases.page(&callback_label) != page
                    || !callback_owner.delivery_current(&callback_retry);
                if !consumed && !obsolete {
                    callback_owner.retry_delivery(&callback_retry);
                }
                if callback_leases.finish(&callback_label, token)
                    && (consumed
                        || callback_leases.page(&callback_label) != page
                        || !callback_owner.delivery_current(&callback_retry))
                    && callback_owner.has_queued_delivery(&callback_label)
                {
                    next();
                }
            }),
        );
        if !accepted && leases.current(label, token) {
            let obsolete = leases.page(label) != page || !owner.delivery_current(&retry);
            if !obsolete {
                owner.retry_delivery(&retry);
            }
            wake_after_drain = leases.finish(label, token)
                && (leases.page(label) != page || !owner.delivery_current(&retry))
                && owner.has_queued_delivery(label);
        }
    });
    if wake_after_drain {
        on_next();
    }
    (delivered, submitted)
}

// On desktop, final validation and pinned-handle eval posting are ordered with
// page-load/destruction callbacks on the main thread. Android queues eval on
// its Java UI thread: the JS page-token check fences later navigation there.
// Runtime-wry routes the pinned eval by webview_id, not a reusable label.
fn post_if_current(
    owner: &Owner,
    leases: &DeliveryLeases,
    label: &str,
    token: u64,
    page: u64,
    item: &bh_device::coordinator::Delivery,
    post: impl FnOnce() -> bool,
) -> bool {
    leases.current(label, token)
        && leases.page(label) == Some(page)
        && owner.delivery_current(item)
        && post()
}

/// Fixed worker count independent of the number of commits/windows. Only
/// window labels are queued (once per surface), never note bytes. The owner
/// keeps bounded ordered bytes or one retryable resnapshot marker per surface.
struct DeliveryDispatcher {
    sender: mpsc::Sender<DeliveryTask>,
    leases: Arc<DeliveryLeases>,
    stopping: Arc<AtomicBool>,
}
impl DeliveryDispatcher {
    fn new(owner: Arc<Owner>) -> Self {
        let (sender, receiver) = mpsc::channel::<DeliveryTask>();
        let receiver = Arc::new(Mutex::new(receiver));
        let leases = Arc::new(DeliveryLeases::default());
        let stopping = Arc::new(AtomicBool::new(false));
        for index in 0..DELIVERY_WORKERS {
            let owner = Arc::clone(&owner);
            let rx = Arc::clone(&receiver);
            let leases = Arc::clone(&leases);
            let again = sender.clone();
            let stopping = Arc::clone(&stopping);
            thread::Builder::new()
                .name(format!("bh-note-delivery-{index}"))
                .spawn(move || {
                    loop {
                        let next = rx.lock().expect("delivery receiver lock").recv();
                        if stopping.load(Ordering::Acquire) {
                            break;
                        }
                        let Ok(DeliveryTask::Surface((label, target), token)) = next else { break; };
                        if !leases.current(&label, token) { continue; }
                        let app = target.app_handle().clone();
                        let on_next: Arc<dyn Fn() + Send + Sync> = Arc::new({
                            let owner = Arc::clone(&owner);
                            let leases = Arc::clone(&leases);
                            let again = again.clone();
                            let stopping = Arc::clone(&stopping);
                            let app = app.clone();
                            let label = label.clone();
                            move || {
                                if owner.has_queued_delivery(&label) {
                                    wake_delivery(&again, &leases, &stopping, app.clone(), label.clone());
                                }
                            }
                        });
                        let (delivered, submitted) = dispatch_surface(&owner, &leases, &label, token, |item, callback| {
                            let payload = Incoming { generation:item.generation, sequence:item.sequence,
                                update:item.update, resync:item.resync, updates:item.segments, reload:item.reload };
                            let Some(page) = leases.page(&label) else { return false; };
                            let Ok(json) = serde_json::to_string(&payload) else { return false; };
                            // The captured handle carries wry's webview_id, not a
                            // reusable label. Desktop orders validation/posting
                            // with lifecycle; Android relies on the JS page token.
                            let owner = Arc::clone(&owner);
                            let leases = Arc::clone(&leases);
                            let label = label.clone();
                            let pinned = target.clone();
                            let again = again.clone();
                            let stopping = Arc::clone(&stopping);
                            let app = app.clone();
                            target.run_on_main_thread(move || {
                                let retry = bh_device::coordinator::Delivery {
                                    window:label.clone(), generation:payload.generation,
                                    sequence:payload.sequence, through_update_id:item.through_update_id,
                                    update:Vec::new(), resync:true, segments:Vec::new(), reload:payload.reload,
                                };
                                // A queued eval after navigation must not construct
                                // or dispatch a plaintext event in the new document.
                                let script = format!("(()=>{{if(window.__bhNotePage!==\"{page}\")return 'stale';return window.__bhNoteDelivery?.({json})??'stale'}})()");
                                if !post_if_current(&owner, &leases, &label, token, page, &retry,
                                    || pinned.eval_with_callback(script, callback).is_ok()) {
                                    if leases.page(&label) == Some(page) && owner.delivery_current(&retry) {
                                        owner.retry_delivery(&retry);
                                    }
                                    if leases.finish(&label, token)
                                        && (leases.page(&label) != Some(page) || !owner.delivery_current(&retry))
                                        && owner.has_queued_delivery(&label) {
                                        wake_delivery(&again, &leases, &stopping, app, label);
                                    }
                                }
                            }).is_ok()
                        }, on_next);
                        if !delivered {
                            // Transient snapshot failure: yield behind other surfaces.
                            thread::sleep(Duration::from_millis(100));
                            if leases.finish(&label, token) && owner.has_queued_delivery(&label) {
                                wake_delivery(&again, &leases, &stopping, app, label);
                            }
                        } else if !submitted && leases.finish(&label, token)
                            && owner.has_queued_delivery(&label) {
                            wake_delivery(&again, &leases, &stopping, app, label);
                        }
                    }
                })
                .expect("delivery worker");
        }
        Self {
            sender,
            leases,
            stopping,
        }
    }
    fn wake(&self, app: AppHandle<tauri::Wry>, label: String) {
        wake_delivery(&self.sender, &self.leases, &self.stopping, app, label);
    }
    fn cancel(&self, label: &str) {
        self.leases.cancel(label);
    }
}
impl Drop for DeliveryDispatcher {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        for _ in 0..DELIVERY_WORKERS {
            let _ = self.sender.send(DeliveryTask::Stop);
        }
    }
}

/// Async FIFO admission precedes spawn_blocking, so queued windows occupy no
/// blocking threads. The owner itself serializes same-note commits; opens do
/// not lock out saves. The per-container cap leaves slots for other accounts.
#[derive(Default)]
struct Admission {
    containers: Mutex<HashMap<ContainerId, Weak<Semaphore>>>,
}
impl Admission {
    fn for_container(&self, id: ContainerId) -> Arc<Semaphore> {
        let mut slots = self.containers.lock().expect("container admission lock");
        if let Some(slot) = slots.get(&id).and_then(Weak::upgrade) {
            return slot;
        }
        let slot = Arc::new(Semaphore::new(MAX_CONTAINER_TASKS));
        slots.insert(id, Arc::downgrade(&slot));
        slot
    }
    async fn enter(self: &Arc<Self>, id: ContainerId, tasks: Arc<Semaphore>) -> StoragePermit {
        let container = self.for_container(id);
        let container_permit = Arc::clone(&container)
            .acquire_owned()
            .await
            .expect("container semaphore open");
        let task_permit = tasks.acquire_owned().await.expect("process semaphore open");
        StoragePermit {
            admission: Arc::clone(self),
            id,
            container,
            container_permit: Some(container_permit),
            task_permit: Some(task_permit),
        }
    }
    fn forget_container(&self, id: ContainerId, slot: &Arc<Semaphore>) {
        let mut slots = self.containers.lock().expect("container admission lock");
        if Arc::strong_count(slot) == 1
            && slots
                .get(&id)
                .is_some_and(|old| old.as_ptr() == Arc::as_ptr(slot))
        {
            slots.remove(&id);
        }
    }
}
struct StoragePermit {
    admission: Arc<Admission>,
    id: ContainerId,
    container: Arc<Semaphore>,
    container_permit: Option<OwnedSemaphorePermit>,
    task_permit: Option<OwnedSemaphorePermit>,
}
impl Drop for StoragePermit {
    fn drop(&mut self) {
        self.task_permit.take();
        self.container_permit.take();
        self.admission.forget_container(self.id, &self.container);
    }
}

pub struct NoteHost {
    owner: Arc<Owner>,
    tasks: Arc<Semaphore>,
    admissions: Arc<Admission>,
    delivery: Arc<DeliveryDispatcher>,
    peers: Mutex<PeerCursors>,
    // Other devices' carets, and the presence settings this host chose.
    remotes: Mutex<RemoteCarets>,
    configured: Mutex<HashMap<ContainerId, u8>>,
    watching: Mutex<HashMap<ContainerId, u64>>,
    next_watch: AtomicU64,
    // A new window's note, chosen natively before its page exists. Its first
    // note_binding rechecks authority through show_note; never a page value.
    intents: Mutex<HashMap<String, (ContainerId, [u8; 32])>>,
    // Close/Quit/update drains and their bounded lifecycle evaluations.
    lifecycle: Arc<Lifecycle>,
    // Restored selection/reading position for a window's first binding of
    // that note: presentation only, never authority.
    hints: Mutex<HashMap<String, ([u8; 32], CapturedView)>>,
    // Scripts handed to a window, so tests can see the command's fan-out
    // without a display or main thread.
    #[cfg(test)]
    sent: Mutex<Vec<(String, String)>>,
    #[cfg(desktop)]
    next_window: AtomicU64,
}
impl Default for NoteHost {
    fn default() -> Self {
        Self::with_owner(Arc::new(Owner::default()))
    }
}
impl NoteHost {
    pub fn with_owner(owner: Arc<Owner>) -> Self {
        let delivery = Arc::new(DeliveryDispatcher::new(Arc::clone(&owner)));
        Self {
            owner,
            tasks: Arc::new(Semaphore::new(MAX_STORAGE_TASKS)),
            admissions: Arc::new(Admission::default()),
            delivery,
            peers: Mutex::new(PeerCursors::default()),
            remotes: Mutex::new(RemoteCarets::default()),
            configured: Mutex::new(HashMap::new()),
            watching: Mutex::new(HashMap::new()),
            next_watch: AtomicU64::new(0),
            intents: Mutex::new(HashMap::new()),
            lifecycle: Arc::new(Lifecycle::default()),
            hints: Mutex::new(HashMap::new()),
            #[cfg(test)]
            sent: Mutex::new(Vec::new()),
            #[cfg(desktop)]
            next_window: AtomicU64::new(0),
        }
    }
    /// A restored window shows `note` at this selection and reading position.
    pub(crate) fn remember_hint(&self, label: &str, note: [u8; 32], view: CapturedView) {
        self.hints
            .lock()
            .expect("view hint lock")
            .insert(label.to_owned(), (note, view));
    }
    fn take_hint(&self, label: &str, note: [u8; 32]) -> Option<CapturedView> {
        let hint = self.hints.lock().expect("view hint lock").remove(label)?;
        (hint.0 == note).then_some(hint.1)
    }
    pub(crate) fn owner(&self) -> &Arc<Owner> {
        &self.owner
    }
    #[cfg(any(desktop, test))]
    pub(crate) fn remember_window(&self, label: &str, id: ContainerId, note: [u8; 32]) {
        self.intents
            .lock()
            .expect("window intent lock")
            .insert(label.to_owned(), (id, note));
    }
    pub(crate) fn forget_window_intent(&self, label: &str) {
        self.intents
            .lock()
            .expect("window intent lock")
            .remove(label);
    }
    /// Bind an unbound new window to its natively chosen note, once. While a
    /// close, Quit or update holds the window, the intent stays for a later
    /// binding (`Err`), which rechecks it like the first.
    pub(crate) fn bind_window_intent(&self, label: &str) -> Result<bool, ()> {
        if self.owner.bound_note(label).is_some() {
            return Ok(false);
        }
        let intent = self
            .intents
            .lock()
            .expect("window intent lock")
            .remove(label);
        let Some((id, note)) = intent else {
            return Ok(false);
        };
        match self.owner.show_note(label, id, note) {
            Ok(()) => Ok(true),
            Err(OwnerError::Busy) => {
                self.intents
                    .lock()
                    .expect("window intent lock")
                    .entry(label.to_owned())
                    .or_insert((id, note));
                Err(())
            }
            Err(_) => Ok(false),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct NoteRow {
    pub note: Vec<u8>,
    pub title: String,
    pub touched: i64,
}
/// Keyset cursor from a previous page's last row; not authority.
#[derive(Deserialize)]
pub(crate) struct After {
    pub touched: i64,
    pub note: Vec<u8>,
}
fn note_id(note: Vec<u8>) -> Result<[u8; 32], &'static str> {
    note.try_into().map_err(|_| "note unavailable")
}
fn bound_container(owner: &Owner, window: &str) -> Result<ContainerId, &'static str> {
    owner.bound_container(window).ok_or("note unavailable")
}
/// This device's position among the account's active devices, which is the
/// preset hue every screen shows it with. `None` while no verified session
/// names this container's device; presence then stays unavailable.
fn presence_colour<R: Runtime>(app: &AppHandle<R>, container: ContainerId) -> Option<u8> {
    app.try_state::<bh_host::sync::SyncHost>()?
        .presence_colour(container)
}
/// The calling window's own container; the page names no account or base.
pub(crate) fn list_bound(
    owner: &Owner,
    window: &str,
    after: Option<After>,
) -> Result<Vec<NoteRow>, &'static str> {
    let id = bound_container(owner, window)?;
    let after = match after {
        Some(After { touched, note }) => Some((touched, note_id(note)?)),
        None => None,
    };
    let page = owner
        .list_notes_page(id, after, MAX_NOTE_PAGE)
        .map_err(|_| "note unavailable")?;
    Ok(page
        .rows
        .into_iter()
        .map(|entry| NoteRow {
            note: entry.note.to_vec(),
            title: entry.title,
            touched: entry.touched,
        })
        .collect())
}
pub(crate) fn create_bound(owner: &Owner, window: &str) -> Result<Vec<u8>, &'static str> {
    let id = bound_container(owner, window)?;
    owner
        .create_note(id)
        .map(|note| note.to_vec())
        .map_err(|_| "note unavailable")
}
pub(crate) fn show_bound(owner: &Owner, window: &str, note: Vec<u8>) -> Result<(), &'static str> {
    let id = bound_container(owner, window)?;
    owner
        .show_note(window, id, note_id(note)?)
        .map_err(|_| "note unavailable")
}
/// A new window may open only a note in the caller's authorized own base.
pub(crate) fn new_window_note(
    owner: &Owner,
    window: &str,
    note: Vec<u8>,
) -> Result<(ContainerId, [u8; 32]), &'static str> {
    let id = bound_container(owner, window)?;
    let note = note_id(note)?;
    match owner.has_note(id, note) {
        Ok(true) => Ok((id, note)),
        _ => Err("note unavailable"),
    }
}
impl NoteHost {
    /// Called only by a native account admission source after verifying the
    /// exact signed account history. A second account adds another container;
    /// it never replaces other windows' session or account.
    #[allow(dead_code)]
    pub fn install(
        &self,
        database: DeviceDatabase,
        verified: Option<&VerifiedAccount>,
        authority: Box<dyn AuthoritySource + Send>,
    ) -> Result<ContainerId, &'static str> {
        self.owner
            .register(database, verified, authority)
            .map_err(|_| "container unavailable")
    }
    #[allow(dead_code)]
    pub fn bind(&self, window: &WebviewWindow, id: ContainerId) -> Result<(), &'static str> {
        // Rebinding authority in the same WebView does not complete a posted
        // evaluation. Only page replacement/destruction cancels its lease.
        // A prior note's cursor is gone immediately, not at the next page load.
        self.clear_peer(window.app_handle(), window.label());
        self.owner
            .bind(window.label(), id)
            .map_err(|_| "container unavailable")
    }
    pub fn has_binding(&self, window: &str) -> bool {
        self.owner.bound_note(window).is_some()
    }
    /// The calling window's current note page, if it has one.
    pub(crate) fn page(&self, window: &str) -> Option<u64> {
        self.delivery.leases.page(window)
    }
    fn clear_peer(&self, app: &AppHandle, window: &str) {
        let (id, targets) = {
            let mut peers = self.peers.lock().expect("peer lock");
            let id = peers
                .windows
                .get(window)
                .and_then(|key| peers.groups.get(key)?.get(window))
                .map(|entry| entry.peer.id.clone());
            (id, peers.remove(window))
        };
        if let Some(id) = id {
            self.send_peers(app, targets, &PeerMessage::Remove { id });
        }
        // The note's presence caret belongs to this window: navigation,
        // close and page replacement all leave it behind. The next note's
        // first selection reports a new one.
        if let Some(container) = self.owner.bound_container(window)
            && let Some(presence) = app
                .try_state::<bh_host::sync::SyncHost>()
                .and_then(|sync| sync.presence(container))
        {
            presence.clear(window);
        }
    }
    fn send_peers<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        targets: Vec<PeerTarget>,
        message: &PeerMessage,
    ) {
        let Ok(json) = serde_json::to_string(message) else {
            return;
        };
        for PeerTarget {
            label,
            container,
            note,
            generation,
            page,
        } in targets
        {
            let Some(target) = app.get_webview_window(&label) else {
                continue;
            };
            let owner = Arc::clone(&self.owner);
            let leases = Arc::clone(&self.delivery.leases);
            let script = format!(
                "(()=>{{if(window.__bhNotePage!==\"{page}\")return;window.__bhNotePeers?.({json})}})()"
            );
            #[cfg(test)]
            self.sent
                .lock()
                .expect("sent lock")
                .push((label.clone(), script.clone()));
            let pinned = target.clone();
            let _ = target.run_on_main_thread(move || {
                if leases.page(&label) == Some(page)
                    && owner.bound_work_key(&label, generation) == Some((container, note))
                {
                    let _ = pinned.eval(script);
                }
            });
        }
    }
    /// This device's own presence for `container`, configured once with the
    /// pairing label and this device's hue among the account's active
    /// devices. Dormant (nothing shown, no error) until the account and its
    /// device order are known.
    fn ensure_presence<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        container: ContainerId,
    ) -> Option<bh_host::sync::Presence> {
        let sync = app.try_state::<bh_host::sync::SyncHost>()?;
        let presence = sync.presence(container)?;
        let colour = {
            let configured = self.configured.lock().expect("presence config");
            configured.get(&container).copied()
        };
        if colour.is_none() {
            let colour = presence_colour(app, container)?;
            let raw = crate::pairing_host::device_label();
            let label = String::from_utf8_lossy(&raw);
            presence.configure(&label, colour);
            presence.foreground(true);
            self.remotes
                .lock()
                .expect("remote carets")
                .own_colour(container, colour);
            self.configured
                .lock()
                .expect("presence config")
                .insert(container, colour);
        }
        self.watch_presence(app, container, &presence);
        Some(presence)
    }
    /// Subscribe once per running client. The task ends when the client's
    /// presence does (account stop or replacement) and frees the slot for the
    /// next client.
    fn watch_presence<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        container: ContainerId,
        presence: &bh_host::sync::Presence,
    ) {
        let token = {
            let mut watching = self.watching.lock().expect("presence watch");
            if watching.contains_key(&container) {
                return;
            }
            let token = self.next_watch.fetch_add(1, Ordering::Relaxed) + 1;
            watching.insert(container, token);
            token
        };
        let mut changes = presence.subscribe();
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            loop {
                let state = changes.borrow_and_update().clone();
                app.state::<NoteHost>()
                    .deliver_remote(&app, container, state.entries());
                if changes.changed().await.is_err() {
                    break;
                }
            }
            app.state::<NoteHost>().end_watch(&app, container, token);
        });
    }
    /// The client that configured presence is gone: nothing it showed stays,
    /// so a window that opens the note later draws nothing, and windows that
    /// drew its carets remove them. Its replacement must configure its own
    /// label and hue before a caret is sent. No replacement watch starts until
    /// the entry is gone, so this cannot clear a newer client's carets.
    fn end_watch<R: Runtime>(&self, app: &AppHandle<R>, container: ContainerId, token: u64) {
        let messages = {
            let mut watching = self.watching.lock().expect("presence watch");
            if watching.get(&container) != Some(&token) {
                return;
            }
            watching.remove(&container);
            self.configured
                .lock()
                .expect("presence config")
                .remove(&container);
            self.remotes.lock().expect("remote carets").clear(container)
        };
        for (note, message) in messages {
            let targets = self
                .peers
                .lock()
                .expect("peer lock")
                .targets_for(container, note);
            self.send_peers(app, targets, &message);
        }
    }
    /// Send the windows bound to each changed note the other devices' carets
    /// through the same page leases and authority checks as local carets.
    fn deliver_remote<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        container: ContainerId,
        state: &[bh_host::sync::RemotePresence],
    ) {
        let messages = self
            .remotes
            .lock()
            .expect("remote carets")
            .update(container, state);
        for (note, message) in messages {
            let targets = self
                .peers
                .lock()
                .expect("peer lock")
                .targets_for(container, note);
            self.send_peers(app, targets, &message);
        }
    }
    /// A script handed to a window in this test, in scheduling order.
    #[cfg(test)]
    fn sent(&self) -> Vec<(String, String)> {
        self.sent.lock().expect("sent lock").clone()
    }
    fn invalidate(&self, app: &AppHandle, window: &str) {
        // A page's pairing code ends with the page.
        if let Some(pairing) = app.try_state::<bh_host::pairing::PairingHost>() {
            pairing.window_gone(window);
        }
        self.clear_peer(app, window);
        self.delivery.cancel(window);
        // The old page's lifecycle eval and any drain waiting on it are void.
        self.lifecycle.leases.cancel(window);
        self.lifecycle.drains.page_gone(window);
        self.owner.invalidate(window);
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum PeerMessage {
    Set {
        id: String,
        anchor: u32,
        head: u32,
    },
    Remote {
        id: String,
        label: String,
        colour: u8,
        anchor: Vec<u8>,
        head: Vec<u8>,
    },
    Remove {
        id: String,
    },
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Opened {
    /// The note's Yjs updates, which the page applies in this order.
    updates: Vec<Vec<u8>>,
    generation: u64,
    sequence: u64,
    client_id: u64,
    writer_token: Vec<u8>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Acknowledged {
    request_id: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Incoming {
    generation: u64,
    sequence: u64,
    update: Vec<u8>,
    resync: bool,
    /// A resync's note as ordered updates, applied in turn.
    updates: Vec<Vec<u8>>,
    /// Replace the copy with `updates` once it has no unsaved writing.
    reload: bool,
}

/// Call once per document. A second binding call rotates the page token and
/// silently ends delivery to that document until it reloads.
#[tauri::command]
fn note_binding(
    window: WebviewWindow,
    host: tauri::State<'_, NoteHost>,
) -> Result<Option<Binding>, &'static str> {
    host.clear_peer(window.app_handle(), window.label());
    // A held new window keeps its note; the page offers to try again.
    host.bind_window_intent(window.label())
        .map_err(|()| "note busy")?;
    Ok(host.owner.bound_note(window.label()).map(|note| Binding {
        note: note.to_vec(),
        surface: host.delivery.leases.bind_page(window.label()).to_string(),
        view: host.take_hint(window.label(), note),
    }))
}
#[derive(Serialize)]
struct Binding {
    note: Vec<u8>,
    surface: String,
    // Restart presentation for this note's first binding in a restored window.
    view: Option<CapturedView>,
}
/// The account's current sync status for the calling window's page, which
/// asks once it has installed `surface`: a status published before then
/// never reached it. Later ones arrive as `sync://status`; the page keeps
/// the newer revision of the two. Nothing for another page or an unbound
/// window, and `None` before the account's first status.
#[tauri::command]
fn sync_status(
    window: WebviewWindow,
    host: tauri::State<'_, NoteHost>,
    surface: String,
) -> Result<Option<bh_host::sync::StatusView>, &'static str> {
    let sync = window.app_handle().try_state::<bh_host::sync::SyncHost>();
    page_status(
        &host.delivery.leases,
        &host.owner,
        window.label(),
        &surface,
        |id| sync?.view(id),
    )
}
fn page_status<V>(
    leases: &DeliveryLeases,
    owner: &Owner,
    label: &str,
    surface: &str,
    view: impl FnOnce(ContainerId) -> Option<V>,
) -> Result<Option<V>, &'static str> {
    let page = surface.parse::<u64>().map_err(|_| "status unavailable")?;
    if leases.page(label) != Some(page) {
        return Err("status unavailable");
    }
    let id = owner.bound_container(label).ok_or("status unavailable")?;
    Ok(view(id))
}
#[tauri::command]
async fn note_open(
    window: WebviewWindow,
    host: tauri::State<'_, NoteHost>,
    note: Vec<u8>,
    retire_writer: Option<Vec<u8>>,
) -> Result<Opened, &'static str> {
    let note: [u8; 32] = note.try_into().map_err(|_| "note unavailable")?;
    // Capacity rollover only: the page's current writer token, never a slot.
    let retire: Option<[u8; 32]> = retire_writer
        .map(|t| t.try_into().map_err(|_| "invalid writer token"))
        .transpose()?;
    let label = window.label().to_owned();
    let owner = Arc::clone(&host.owner);
    let (id, _) = owner
        .bound_open_key(&label, note)
        .ok_or("note unavailable")?;
    let permit = host.admissions.enter(id, Arc::clone(&host.tasks)).await;
    let open_label = label.clone();
    let opened = tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        match retire {
            Some(token) => owner.open_leased_retiring(&open_label, note, token),
            None => owner.open_leased(&open_label, note),
        }
    })
    .await
    .map_err(|_| "note unavailable")?;
    let opened = opened.map_err(|err| match err {
        OwnerError::Changed => "note changed; retry open",
        _ => "note unavailable",
    })?;
    host.clear_peer(window.app_handle(), &label);
    Ok(Opened {
        updates: opened.state.into_segments(),
        generation: opened.generation,
        sequence: opened.sequence,
        client_id: opened.writer.ok_or("writer unavailable")?.client_id,
        writer_token: opened.writer.ok_or("writer unavailable")?.token.to_vec(),
    })
}
#[tauri::command]
async fn note_commit(
    window: WebviewWindow,
    host: tauri::State<'_, NoteHost>,
    generation: u64,
    request_id: String,
    writer_token: Vec<u8>,
    update: Vec<u8>,
) -> Result<Acknowledged, &'static str> {
    let request: [u8; 16] = decode_request(&request_id).ok_or("invalid request")?;
    let writer_token: [u8; 32] = writer_token
        .try_into()
        .map_err(|_| "invalid writer token")?;
    let label = window.label().to_owned();
    let (id, _) = host
        .owner
        .bound_work_key(&label, generation)
        .ok_or("note unavailable")?;
    // Local writing, unlike a peer's delivery, keeps an update waiting.
    host.lifecycle.typed();
    let task_permit = host.admissions.enter(id, Arc::clone(&host.tasks)).await;
    let owner = Arc::clone(&host.owner);
    let delivery = Arc::clone(&host.delivery);
    let app = window.app_handle().clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let _task_permit = task_permit;
        let committed = owner.commit_leased(&label, generation, writer_token, request, &update);
        if let Ok((_, targets)) = &committed {
            for target in targets {
                delivery.wake(app.clone(), target.clone());
            }
            // Durable local work: the account's sync looks for it now.
            if let Some(sync) = app.try_state::<bh_host::sync::SyncHost>() {
                sync.wake(id);
            }
        }
        committed
    })
    .await
    .map_err(|_| "note commit failed")?;
    result.map_err(|err| match err {
        OwnerError::Changed => "note changed; retry",
        _ => "note commit failed",
    })?;
    Ok(Acknowledged { request_id })
}
#[tauri::command]
#[allow(clippy::too_many_arguments)] // The page's selection contract, one field per value.
fn note_selection<R: Runtime>(
    window: WebviewWindow<R>,
    host: tauri::State<'_, NoteHost>,
    generation: u64,
    surface: String,
    anchor: u32,
    head: u32,
    anchor_rel: Option<Vec<u8>>,
    head_rel: Option<Vec<u8>>,
) -> Vec<Peer> {
    let label = window.label();
    let Ok(page) = surface.parse::<u64>() else {
        return Vec::new();
    };
    if host.delivery.leases.page(label) != Some(page) {
        return Vec::new();
    }
    let Some((container, note)) = host.owner.bound_work_key(label, generation) else {
        return Vec::new();
    };
    let (targets, visible, joined) = host.peers.lock().expect("peer lock").publish(
        label,
        CursorState {
            container,
            note,
            generation,
            page,
            peer: Peer {
                id: surface.clone(),
                anchor,
                head,
            },
        },
    );
    host.send_peers(
        window.app_handle(),
        targets,
        &PeerMessage::Set {
            id: surface,
            anchor,
            head,
        },
    );
    // A window that has just opened this note draws the other devices' carets
    // where they already are, not only after the next move. Only this window
    // gets them, and only through the same lease and authority checks.
    if joined {
        let target = host.peers.lock().expect("peer lock").target_for(label);
        let shown = host
            .remotes
            .lock()
            .expect("remote carets")
            .shown_for(container, note.note);
        if let Some(target) = target {
            for message in shown {
                host.send_peers(window.app_handle(), vec![target.clone()], &message);
            }
        }
    }
    // Cross-device presence is separate from the same-device relay above:
    // relative bytes go to the client's own task, and nothing is retained.
    if let (Some(anchor_rel), Some(head_rel)) = (anchor_rel, head_rel)
        && let Some(presence) = host.ensure_presence(window.app_handle(), container)
    {
        presence.set(label, note.note, anchor_rel, head_rel);
    }
    visible
}
#[tauri::command]
fn note_close(window: WebviewWindow, host: tauri::State<'_, NoteHost>, generation: u64) {
    // Closing an editor does not destroy its WebView or acknowledge a posted
    // eval. Preserve its lease until the callback or native page replacement.
    if host
        .owner
        .bound_work_key(window.label(), generation)
        .is_some()
    {
        host.clear_peer(window.app_handle(), window.label());
    }
    host.owner.close_generation(window.label(), generation);
}
/// The page drained under native drain `fence`: its accepted writing is saved
/// and it holds new input. Tauri supplies the calling WebView; only that
/// window's current page token counts, and the owner then refuses its writes.
/// False tells the page to resume its own editing.
#[tauri::command]
async fn note_drained(
    window: WebviewWindow,
    host: tauri::State<'_, NoteHost>,
    surface: String,
    fence: String,
    view: Option<CapturedView>,
) -> Result<bool, ()> {
    let label = window.label().to_owned();
    let page = host.delivery.leases.page(&label);
    Ok(lifecycle::accept_drained(
        &host.owner,
        &host.lifecycle,
        &label,
        page,
        lifecycle::Drained {
            surface: &surface,
            fence: &fence,
            view,
            frame: frame(&window),
        },
    )
    .await)
}
/// The page could not save its writing in time (or at all).
#[tauri::command]
fn note_drain_failed(
    window: WebviewWindow,
    host: tauri::State<'_, NoteHost>,
    surface: String,
    fence: String,
) -> bool {
    let page = host.delivery.leases.page(window.label());
    lifecycle::drain_failed(&host.lifecycle, window.label(), page, &surface, &fence)
}
/// Outer position and inner size in logical points, as restore applies them.
fn frame(window: &WebviewWindow) -> Option<[f64; 4]> {
    let scale = window.scale_factor().ok()?;
    let position = window.outer_position().ok()?.to_logical::<f64>(scale);
    let size = window.inner_size().ok()?.to_logical::<f64>(scale);
    Some([position.x, position.y, size.width, size.height])
}

/// The app's windows as the sync host reaches them: status only to windows
/// bound to that account, each on its current page; deliveries through the
/// one bounded dispatcher; reloads when an account's authority ends.
pub(crate) struct AppWindows {
    pub app: AppHandle,
}
impl bh_host::sync::StatusWindows for AppWindows {
    fn post_status(&self, container: ContainerId, view: &bh_host::sync::StatusView) {
        let Ok(json) = serde_json::to_string(view) else {
            return;
        };
        let host = self.app.state::<NoteHost>();
        for (label, window) in self.app.webview_windows() {
            let Some(page) = host.delivery.leases.page(&label) else {
                continue;
            };
            if host.owner.bound_container(&label) != Some(container) {
                continue;
            }
            let owner = Arc::clone(&host.owner);
            let leases = Arc::clone(&host.delivery.leases);
            let pinned = window.clone();
            let script = format!(
                "(()=>{{if(window.__bhNotePage!==\"{page}\")return;window.dispatchEvent(new CustomEvent('sync://status',{{detail:{json}}}))}})()"
            );
            // Rechecked on the window's own thread, ordered with page loads.
            let _ = window.run_on_main_thread(move || {
                if leases.page(&label) == Some(page)
                    && owner.bound_container(&label) == Some(container)
                {
                    let _ = pinned.eval(script);
                }
            });
        }
    }
    fn wake_delivery(&self, window: String) {
        let host = self.app.state::<NoteHost>();
        host.delivery.wake(self.app.clone(), window);
    }
    fn authority_ended(&self, _: ContainerId, windows: Vec<String>) {
        let host = self.app.state::<NoteHost>();
        for label in windows {
            host.invalidate(&self.app, &label);
            if let Some(window) = self.app.get_webview_window(&label) {
                let _ = window.reload();
            }
        }
    }
}

/// Upper bound for one close, Quit or update drain; normally milliseconds.
const DRAIN_LIMIT: Duration = Duration::from_secs(10);
/// An update waits until no window has typed for this long.
const UPDATE_TYPING_IDLE: Duration = Duration::from_secs(2);

/// Posts a lifecycle script to the pinned WebView of a window, on its UI
/// thread and only while `page` is still its note page; that check is
/// ordered with page-load callbacks on the same thread.
struct WebviewPoster {
    app: AppHandle,
    pages: Arc<DeliveryLeases>,
}
type EvalDone = Mutex<Option<Box<dyn FnOnce(String) + Send>>>;
fn finish_eval(done: &EvalDone, value: String) {
    if let Some(done) = done.lock().expect("eval callback lock").take() {
        done(value);
    }
}
impl Poster for WebviewPoster {
    fn post(
        &self,
        label: &str,
        page: u64,
        script: String,
        done: Box<dyn FnOnce(String) + Send>,
    ) -> bool {
        let Some(window) = self.app.get_webview_window(label) else {
            return false;
        };
        let pages = Arc::clone(&self.pages);
        let label = label.to_owned();
        let pinned = window.clone();
        let done: Arc<EvalDone> = Arc::new(Mutex::new(Some(done)));
        window
            .run_on_main_thread(move || {
                if pages.page(&label) != Some(page) {
                    finish_eval(&done, "\"stale\"".into());
                    return;
                }
                let callback = Arc::clone(&done);
                if pinned
                    .eval_with_callback(script, move |value| finish_eval(&callback, value))
                    .is_err()
                {
                    finish_eval(&done, "\"stale\"".into());
                }
            })
            .is_ok()
    }
}

/// Exit and relaunch readiness for a verified update: every window drained
/// through a real local commit, and restart records written for every
/// account. Held until exit; dropping it resumes editing and removes the
/// records it wrote. Never sent to a page.
pub struct RestartReady {
    held: lifecycle::Held,
}
impl RestartReady {
    /// Start the verified replacement, then exit keeping every window held
    /// and the records in place. If `relaunch` fails, this guard drops.
    ///
    /// Containers hold an exclusive lock until this process exits, so
    /// `relaunch` must only arrange for the new app to start after this PID
    /// has gone (the Mac updater's waiter polls it); starting it directly
    /// would find every account busy. `app.exit` stops the run loop without
    /// `terminate:`, so it does not re-enter the Quit hook.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn exit(
        self,
        app: &AppHandle,
        relaunch: impl FnOnce() -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        relaunch()?;
        self.held.keep();
        app.exit(0);
        Ok(())
    }
}

impl NoteHost {
    fn poster(&self, app: &AppHandle) -> Arc<dyn Poster> {
        Arc::new(WebviewPoster {
            app: app.clone(),
            pages: Arc::clone(&self.delivery.leases),
        })
    }
    fn targets(&self, app: &AppHandle) -> Vec<Target> {
        app.webview_windows()
            .into_keys()
            .map(|label| Target {
                page: self.delivery.leases.page(&label),
                label,
            })
            .collect()
    }
    /// Update readiness: wait for two seconds without local typing,
    /// then drain every window (at most ten seconds, within `deadline`) and
    /// write restart records. A failed save, missing reply or record write
    /// refuses; there is no discard path. Editing resumes on refusal.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub async fn prepare_restart(
        &self,
        app: &AppHandle,
        deadline: Instant,
    ) -> Result<RestartReady, Refusal> {
        lifecycle::typing_idle(&self.lifecycle, UPDATE_TYPING_IDLE, deadline).await?;
        let mut held = lifecycle::drain(
            &self.owner,
            &self.lifecycle,
            &self.poster(app),
            DrainScope::All,
            self.targets(app),
            Reason::Update,
            deadline.min(Instant::now() + DRAIN_LIMIT),
        )
        .await
        .map_err(|failure| failure.refusal)?;
        lifecycle::write_records(&self.owner, &mut held).await?;
        Ok(RestartReady { held })
    }
    /// Ordinary Quit: drain every window, record them for the next launch,
    /// and exit. A window that cannot save asks first, Keep open by default.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    async fn quit(&self, app: &AppHandle) -> bool {
        let drained = lifecycle::drain(
            &self.owner,
            &self.lifecycle,
            &self.poster(app),
            DrainScope::All,
            self.targets(app),
            Reason::Quit,
            Instant::now() + DRAIN_LIMIT,
        )
        .await;
        match drained {
            Ok(mut held) => {
                // Writing is saved; a failed record only means these windows
                // do not reopen next launch.
                if lifecycle::write_records(&self.owner, &mut held)
                    .await
                    .is_err()
                {
                    eprintln!("BaseHero: windows will not reopen; their records were not saved");
                }
                held.keep();
                // Sync stops with the app; its exact bytes are already kept.
                // Presence says nothing remains on screen before the socket
                // closes, so the other device's caret goes at once.
                if let Some(sync) = app.try_state::<bh_host::sync::SyncHost>() {
                    sync.leave_presence();
                    sync.shutdown_all().await;
                }
                true
            }
            Err(failure) if failure.refusal == Refusal::Busy => false,
            // The approved sheet on each window that could not save, in turn.
            Err(failure) => {
                lifecycle::confirm_each(failure, |label| async move {
                    let Some(window) = app.get_webview_window(&label) else {
                        return false;
                    };
                    let _ = window.set_focus();
                    confirm_discard(&window).await
                })
                .await
            }
        }
    }
}

/// Close one window after its writing is saved; a failed save asks first.
#[cfg(desktop)]
async fn close_window(app: AppHandle, window: WebviewWindow) {
    let host = app.state::<NoteHost>();
    let label = window.label().to_owned();
    let targets = vec![Target {
        page: host.delivery.leases.page(&label),
        label: label.clone(),
    }];
    let drained = lifecycle::drain(
        &host.owner,
        &host.lifecycle,
        &host.poster(&app),
        DrainScope::Window(label),
        targets,
        Reason::Close,
        Instant::now() + DRAIN_LIMIT,
    )
    .await;
    match drained {
        // destroy, not close: close would ask CloseRequested again.
        Ok(held) => {
            let _ = window.destroy();
            drop(held);
        }
        // A drain of this window (or Quit) is already deciding.
        Err(failure) if failure.refusal == Refusal::Busy => {}
        Err(failure) => {
            if confirm_discard(&window).await {
                let _ = window.destroy();
            }
            drop(failure);
        }
    }
}

/// Native sheet: Keep open is the default; true only for Close without saving.
#[cfg(target_os = "macos")]
async fn confirm_discard(window: &WebviewWindow) -> bool {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let pinned = window.clone();
    let shown = window.run_on_main_thread(move || {
        bh_mac_lifecycle::ask_discard(&pinned, move |discard| {
            let _ = sender.send(discard);
        });
    });
    shown.is_ok() && receiver.await.unwrap_or(false)
}
#[cfg(not(target_os = "macos"))]
#[cfg_attr(mobile, allow(dead_code))]
async fn confirm_discard(_window: &WebviewWindow) -> bool {
    false
}

/// Bring ordinary Quit (menu, Dock, logout, AppleScript) to the same drain.
#[cfg(target_os = "macos")]
fn intercept_quit(app: &AppHandle) -> Result<(), bh_mac_lifecycle::InstallError> {
    let handle = app.clone();
    bh_mac_lifecycle::intercept_terminate(move |reply| {
        let app = handle.clone();
        tauri::async_runtime::spawn(async move {
            // A panicking drain must cancel Quit rather than leave AppKit
            // waiting forever for the dropped reply.
            let draining = app.clone();
            let quit = tauri::async_runtime::spawn(async move {
                draining.state::<NoteHost>().quit(&draining).await
            })
            .await
            .unwrap_or(false);
            let _ = app.run_on_main_thread(move || {
                let _ = reply.reply(quit);
            });
        });
    })
}

/// Run a short catalogue operation off the main thread behind this container's
/// admission, so a busy account cannot occupy every blocking thread.
async fn admitted<R: Send + 'static>(
    host: &NoteHost,
    window: &WebviewWindow,
    work: impl FnOnce(&Owner, &str) -> Result<R, &'static str> + Send + 'static,
) -> Result<R, &'static str> {
    let label = window.label().to_owned();
    let id = bound_container(&host.owner, &label)?;
    let permit = host.admissions.enter(id, Arc::clone(&host.tasks)).await;
    let owner = Arc::clone(&host.owner);
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        work(&owner, &label)
    })
    .await
    .map_err(|_| "note unavailable")?
}
/// The first page of this window's own-base notes, most recent first.
#[tauri::command]
async fn note_list(
    window: WebviewWindow,
    host: tauri::State<'_, NoteHost>,
    after: Option<After>,
) -> Result<Vec<NoteRow>, &'static str> {
    admitted(&host, &window, move |owner, label| {
        list_bound(owner, label, after)
    })
    .await
}
#[tauri::command]
async fn note_create(
    window: WebviewWindow,
    host: tauri::State<'_, NoteHost>,
) -> Result<Vec<u8>, &'static str> {
    admitted(&host, &window, create_bound).await
}
/// Route this window to another note of its own base. The page then calls
/// note_binding and note_open for the new load; the old generation is refused.
#[tauri::command]
async fn note_show(
    window: WebviewWindow,
    host: tauri::State<'_, NoteHost>,
    note: Vec<u8>,
) -> Result<(), &'static str> {
    host.clear_peer(window.app_handle(), window.label());
    admitted(&host, &window, move |owner, label| {
        show_bound(owner, label, note)
    })
    .await
}
/// Open the caller's note in another window that shares the same core note.
#[tauri::command]
async fn note_new_window(
    window: WebviewWindow,
    host: tauri::State<'_, NoteHost>,
    note: Vec<u8>,
) -> Result<(), &'static str> {
    let caller = window.label().to_owned();
    let owner = Arc::clone(&host.owner);
    let (id, note) =
        tauri::async_runtime::spawn_blocking(move || new_window_note(&owner, &caller, note))
            .await
            .map_err(|_| "note unavailable")??;
    open_window(&host, window.app_handle(), id, note)
}
fn open_window(
    host: &NoteHost,
    app: &AppHandle,
    id: ContainerId,
    note: [u8; 32],
) -> Result<(), &'static str> {
    open_window_at(host, app, id, note, None)
}
/// Where the Mac window buttons sit in the page's location bar; the main
/// window's `trafficLightPosition` in tauri.conf.json is the same.
#[cfg(desktop)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const TRAFFIC_LIGHTS: [f64; 2] = [14.0, 19.0];
#[cfg(desktop)]
fn open_window_at(
    host: &NoteHost,
    app: &AppHandle,
    id: ContainerId,
    note: [u8; 32],
    restore: Option<(Option<[f64; 4]>, CapturedView)>,
) -> Result<(), &'static str> {
    let index = host
        .next_window
        .fetch_add(1, Ordering::Relaxed)
        .checked_add(1)
        .ok_or("window unavailable")?;
    let label = format!("note-{index}");
    // Record the intent before the page can ask for its binding.
    host.remember_window(&label, id, note);
    let builder =
        tauri::WebviewWindowBuilder::new(app, &label, tauri::WebviewUrl::App("index.html".into()))
            .title("BaseHero")
            .inner_size(1000.0, 760.0)
            .min_inner_size(320.0, 400.0);
    // The page's location bar is the title bar, as for the main window.
    #[cfg(target_os = "macos")]
    let builder = builder
        .title_bar_style(tauri::TitleBarStyle::Overlay)
        .hidden_title(true)
        .traffic_light_position(tauri::LogicalPosition::new(
            TRAFFIC_LIGHTS[0],
            TRAFFIC_LIGHTS[1],
        ));
    let mut builder = builder;
    if let Some((frame, view)) = restore {
        host.remember_hint(&label, note, view);
        if let Some([x, y, width, height]) = frame {
            builder = builder.inner_size(width, height);
            if on_screen([x, y, width, height], &screens(app.available_monitors())) {
                builder = builder.position(x, y);
            }
        }
    }
    if builder.build().is_err() {
        host.forget_window_intent(&label);
        host.hints.lock().expect("view hint lock").remove(&label);
        return Err("window unavailable");
    }
    Ok(())
}
#[cfg(mobile)]
fn open_window_at(
    _host: &NoteHost,
    _app: &AppHandle,
    _id: ContainerId,
    _note: [u8; 32],
    _restore: Option<(Option<[f64; 4]>, CapturedView)>,
) -> Result<(), &'static str> {
    Err("window unavailable")
}

/// One window to reopen after Quit or update. Presentation only: its note is
/// shown again through the full native authority check, in a new load.
pub(crate) struct Restore {
    pub note: [u8; 32],
    pub view: CapturedView,
    pub frame: Option<[f64; 4]>,
}
const MAX_RESTORED_WINDOWS: usize = 32;
/// Records already passed native authority; bound and clamp what they hint.
pub(crate) fn plan_restore(records: Vec<bh_storage::ViewRecord>) -> Vec<Restore> {
    records
        .into_iter()
        .take(MAX_RESTORED_WINDOWS)
        .map(|record| Restore {
            note: record.key.note,
            view: CapturedView {
                version: 1,
                anchor: record.anchor,
                head: record.head,
                cursor_offset: if record.cursor_offset.is_finite() {
                    record
                        .cursor_offset
                        .clamp(-MAX_CURSOR_OFFSET, MAX_CURSOR_OFFSET)
                } else {
                    0.0
                },
            },
            frame: restore_frame(record.frame),
        })
        .collect()
}
/// A logical [x, y, width, height]: finite, with a usable size.
pub(crate) fn restore_frame(frame: [f64; 4]) -> Option<[f64; 4]> {
    let [x, y, width, height] = frame;
    frame.iter().all(|value| value.is_finite()).then_some([
        x,
        y,
        width.clamp(320.0, 8000.0),
        height.clamp(400.0, 8000.0),
    ])
}
/// The window's title bar would sit on one of these logical screens.
#[cfg_attr(mobile, allow(dead_code))]
pub(crate) fn on_screen(frame: [f64; 4], screens: &[[f64; 4]]) -> bool {
    let (x, y) = (frame[0] + 40.0, frame[1] + 10.0);
    screens
        .iter()
        .any(|[sx, sy, sw, sh]| x >= *sx && x < sx + sw && y >= *sy && y < sy + sh)
}
#[cfg(desktop)]
fn screens(monitors: tauri::Result<Vec<tauri::Monitor>>) -> Vec<[f64; 4]> {
    monitors
        .unwrap_or_default()
        .iter()
        .map(|monitor| {
            let scale = monitor.scale_factor();
            let position = monitor.position().to_logical::<f64>(scale);
            let size = monitor.size().to_logical::<f64>(scale);
            [position.x, position.y, size.width, size.height]
        })
        .collect()
}
/// Put back the main window's restored note view and frame, and open one
/// window per other record through the ordinary native intent path.
pub(crate) fn restore_windows(
    host: &NoteHost,
    window: &WebviewWindow,
    id: ContainerId,
    main: Option<Restore>,
    others: Vec<Restore>,
) {
    if let Some(main) = main {
        host.remember_hint(window.label(), main.note, main.view);
        #[cfg(desktop)]
        if let Some([x, y, width, height]) = main.frame {
            let _ = window.set_size(tauri::LogicalSize::new(width, height));
            if on_screen([x, y, width, height], &screens(window.available_monitors())) {
                let _ = window.set_position(tauri::LogicalPosition::new(x, y));
            }
        }
    }
    for other in others {
        let _ = open_window_at(
            host,
            window.app_handle(),
            id,
            other.note,
            Some((other.frame, other.view)),
        );
    }
}
fn decode_request(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(bytes)
}

pub fn builder() -> tauri::Builder<tauri::Wry> {
    let owner = Arc::new(Owner::default());
    let sync = bh_host::sync::SyncHost::new(crate::sync_host::configured(), Arc::clone(&owner));
    let accounts = crate::account_host::account_host(Arc::clone(&owner)).into_state();
    accounts.set_device_model(String::from_utf8_lossy(&crate::pairing_host::device_label()));
    // A verified removal stops its client, then erases this account on this
    // device. The registry keeps the final screen for `screen()`; the other
    // accounts keep their owners and routes.
    sync.set_erase({
        let accounts = accounts.clone();
        std::sync::Arc::new(move |id| {
            let accounts = accounts.clone();
            Box::pin(async move {
                let _ = accounts.erase_removed(id).await;
            })
        })
    });
    let builder = tauri::Builder::default()
        .manage(NoteHost::with_owner(owner))
        .manage(sync)
        .manage(accounts)
        .manage(bh_host::pairing::PairingHost::default())
        .invoke_handler(tauri::generate_handler![
            note_binding,
            note_open,
            note_commit,
            note_selection,
            note_close,
            note_list,
            note_create,
            note_show,
            note_new_window,
            note_drained,
            note_drain_failed,
            sync_status,
            crate::account_host::account_screen,
            crate::account_host::account_retry,
            crate::account_host::account_suggest_password,
            crate::account_host::account_create,
            crate::account_host::account_confirm_kit,
            crate::account_host::account_return,
            crate::account_host::account_print_kit,
            crate::account_host::account_email_kit,
            crate::account_host::account_save_kit_file,
            crate::account_host::account_open_note,
            crate::pairing_host::pairing_show,
            crate::pairing_host::pairing_status,
            crate::pairing_host::pairing_approve,
            crate::pairing_host::pairing_cancel,
            crate::pairing_host::pairing_reconfirm,
            crate::pairing_host::pairing_join,
            crate::pairing_host::pairing_join_status,
            crate::mac_update::commands::update_status,
            crate::mac_update::commands::update_not_now,
            crate::mac_update::commands::update_install,
            crate::window_layout::window_sidebar,
            crate::about::app_about,
            crate::devices_host::devices_kit_screen,
            crate::devices_host::devices_view,
            crate::devices_host::devices_request_removal,
            crate::devices_host::devices_cancel_removal,
            crate::devices_host::devices_remove_now,
            crate::devices_host::devices_remove_self,
            crate::devices_host::account_change_password,
            crate::devices_host::account_confirm_new_kit,
            crate::devices_host::alerts_list,
            crate::devices_host::account_recover,
            crate::devices_host::account_check_code,
            crate::devices_host::account_recovery_status,
        ])
        .on_page_load(|webview, payload| {
            if payload.event() == tauri::webview::PageLoadEvent::Started {
                webview
                    .app_handle()
                    .state::<NoteHost>()
                    .invalidate(webview.app_handle(), webview.label());
            }
        })
        .on_window_event(|window, event| match event {
            #[cfg(desktop)]
            tauri::WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                let app = window.app_handle().clone();
                if let Some(target) = app.get_webview_window(window.label()) {
                    tauri::async_runtime::spawn(close_window(app, target));
                }
            }
            tauri::WindowEvent::Destroyed => {
                let host = window.app_handle().state::<NoteHost>();
                host.forget_window_intent(window.label());
                host.invalidate(window.app_handle(), window.label());
            }
            // Android's onPause/onResume. Presence must never outlive the
            // app being on screen, and may rejoin only once it returns.
            #[cfg(target_os = "android")]
            tauri::WindowEvent::Suspended => {
                if let Some(sync) = window.app_handle().try_state::<bh_host::sync::SyncHost>() {
                    lifecycle::paused(&sync);
                }
            }
            #[cfg(target_os = "android")]
            tauri::WindowEvent::Resumed => {
                if let Some(sync) = window.app_handle().try_state::<bh_host::sync::SyncHost>() {
                    lifecycle::resumed(&sync);
                }
            }
            _ => {}
        })
        .setup(|app| {
            // Never run where ordinary Quit would skip saving.
            #[cfg(target_os = "macos")]
            {
                intercept_quit(app.handle())
                    .map_err(|error| format!("Quit cannot wait for saving ({error:?})"))?;
                crate::mac_update::install(app);
            }
            #[cfg(target_os = "macos")]
            crate::native::notify::enable();
            crate::alerts_host::start(
                app.handle().clone(),
                &app.state::<crate::account_host::SharedAccountHost>(),
            );
            Ok(())
        });
    // A crashed page's writing is gone; its drain fails at once.
    #[cfg(target_os = "macos")]
    let builder = builder
        .on_web_content_process_terminate(|webview| {
            let app = webview.app_handle();
            app.state::<NoteHost>().invalidate(app, webview.label());
        })
        .menu(crate::window_layout::menu)
        .on_menu_event(crate::window_layout::menu_event);
    builder
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(desktop)]
    #[test]
    fn note_windows_put_the_mac_buttons_where_the_main_window_does() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let main = &config["app"]["windows"][0];
        assert_eq!(main["titleBarStyle"], "Overlay");
        assert_eq!(main["hiddenTitle"], true);
        let at = &main["trafficLightPosition"];
        assert_eq!(
            [at["x"].as_f64().unwrap(), at["y"].as_f64().unwrap()],
            TRAFFIC_LIGHTS
        );
    }
    use bh_account::{
        AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount,
        crypto::{KemKey, SigningKey},
    };
    use bh_device::coordinator::Scope;
    use bh_host::sync::RemotePresence;
    use bh_storage::NoteKey;
    use std::collections::HashMap;

    #[test]
    fn peer_cursors_relay_only_within_same_container_and_note() {
        let mut peers = PeerCursors::default();
        let key = NoteKey {
            base: [1; 32],
            audience: [2; 32],
            note: [3; 32],
        };
        let other = NoteKey {
            note: [4; 32],
            ..key
        };
        for (name, container, note) in [
            ("left", ContainerId([1; 16]), key),
            ("right", ContainerId([1; 16]), key),
            ("other-note", ContainerId([1; 16]), other),
            ("other-container", ContainerId([2; 16]), key),
        ] {
            peers.publish(
                name,
                CursorState {
                    container,
                    note,
                    generation: 7,
                    page: 11,
                    peer: Peer {
                        id: "11".into(),
                        anchor: 1,
                        head: 2,
                    },
                },
            );
        }
        let (targets, visible, _) = peers.publish(
            "left",
            CursorState {
                container: ContainerId([1; 16]),
                note: key,
                generation: 7,
                page: 11,
                peer: Peer {
                    id: "11".into(),
                    anchor: 3,
                    head: 5,
                },
            },
        );
        assert_eq!(
            targets,
            vec![PeerTarget {
                label: "right".into(),
                container: ContainerId([1; 16]),
                note: key,
                generation: 7,
                page: 11
            }]
        );
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, "11");
        assert_eq!(visible[0].anchor, 1);
        assert_eq!(
            peers.remove("right"),
            vec![PeerTarget {
                label: "left".into(),
                container: ContainerId([1; 16]),
                note: key,
                generation: 7,
                page: 11
            }]
        );
        assert!(peers.remove("right").is_empty());
    }

    fn remote(handle: u8, note: [u8; 32], label: &str, colour: u8) -> RemotePresence {
        RemotePresence {
            handle: [handle; 16],
            note,
            label: label.into(),
            colour,
            anchor: vec![handle, 1],
            head: vec![handle, 2],
        }
    }
    fn remote_names(peers: &PeerCursors, container: ContainerId, note: [u8; 32]) -> Vec<String> {
        let mut names: Vec<String> = peers
            .targets_for(container, note)
            .into_iter()
            .map(|target| target.label)
            .collect();
        names.sort();
        names
    }

    /// Test 1c: a remote device's caret reaches every window bound to that
    /// note, and no window on another note or account. The pure fan-out picks
    /// only windows in that note's group; `send_peers` then re-applies the page
    /// lease and the note authority check before any window draws it.
    #[test]
    fn remote_caret_reaches_every_window_of_the_note() {
        let container = ContainerId([1; 16]);
        let key = NoteKey {
            base: [1; 32],
            audience: [2; 32],
            note: [3; 32],
        };
        let other = NoteKey {
            note: [4; 32],
            ..key
        };
        let mut peers = PeerCursors::default();
        for (name, id, note) in [
            ("left", container, key),
            ("right", container, key),
            ("other-note", container, other),
            ("other-container", ContainerId([2; 16]), key),
        ] {
            peers.publish(
                name,
                CursorState {
                    container: id,
                    note,
                    generation: 7,
                    page: 11,
                    peer: Peer {
                        id: "11".into(),
                        anchor: 1,
                        head: 2,
                    },
                },
            );
        }
        let mut remotes = RemoteCarets::default();
        remotes.own_colour(container, 0);
        let changes = remotes.update(container, &[remote(9, key.note, "Pixel 10 Pro Fold", 1)]);
        let [(note, message)] = changes.as_slice() else {
            panic!("one note changed, got {changes:?}");
        };
        assert_eq!(*note, key.note);
        let PeerMessage::Remote {
            id,
            label,
            colour,
            anchor,
            head,
        } = message
        else {
            panic!("not a remote caret");
        };
        assert_eq!(id, &"09".repeat(16));
        assert_eq!(label, "Pixel 10 Pro Fold");
        assert_eq!(*colour, 1);
        assert_eq!(anchor, &vec![9, 1]);
        assert_eq!(head, &vec![9, 2]);
        assert_eq!(remote_names(&peers, container, key.note), ["left", "right"]);
        assert_eq!(remote_names(&peers, container, other.note), ["other-note"]);
        assert_eq!(
            remote_names(&peers, ContainerId([2; 16]), key.note),
            ["other-container"]
        );

        // Two senders whose own hues collide with this device's are bumped to
        // the next free preset, in handle order.
        let changes = remotes.update(
            container,
            &[
                remote(8, key.note, "Mac", 0),
                remote(9, key.note, "Pixel 10 Pro Fold", 1),
            ],
        );
        let colours: Vec<u8> = changes
            .iter()
            .filter_map(|(_, message)| match message {
                PeerMessage::Remote { colour, .. } => Some(*colour),
                _ => None,
            })
            .collect();
        assert_eq!(colours, [1, 2]);

        // A departure reaches the same windows as the caret did.
        let changes = remotes.update(container, &[]);
        assert_eq!(changes.len(), 2);
        for (note, message) in &changes {
            assert_eq!(*note, key.note);
            assert!(matches!(message, PeerMessage::Remove { .. }));
        }
    }

    /// Test 1c, late join: a window that opens the note after a remote caret
    /// already arrived is told to draw it now, through the same window target
    /// `send_peers` re-checks the lease and authority for.
    #[test]
    fn window_that_opens_the_note_later_draws_the_shown_remote_caret() {
        let container = ContainerId([1; 16]);
        let key = NoteKey {
            base: [1; 32],
            audience: [2; 32],
            note: [3; 32],
        };
        let other = NoteKey {
            note: [4; 32],
            ..key
        };
        let cursor = |note| CursorState {
            container,
            note,
            generation: 7,
            page: 11,
            peer: Peer {
                id: "11".into(),
                anchor: 1,
                head: 2,
            },
        };
        let mut peers = PeerCursors::default();
        let (_, _, joined) = peers.publish("first", cursor(key));
        assert!(joined, "the note's first window joins it");
        let mut remotes = RemoteCarets::default();
        remotes.own_colour(container, 2);
        remotes.update(
            container,
            &[
                remote(8, other.note, "Mac", 0),
                remote(9, key.note, "Pixel 10 Pro Fold", 1),
            ],
        );

        // A second window on the same note draws what is already shown there.
        let (_, _, joined) = peers.publish("second", cursor(key));
        assert!(joined, "opening the note is a join");
        let shown = remotes.shown_for(container, key.note);
        assert_eq!(shown.len(), 1, "only this note's carets");
        let PeerMessage::Remote {
            id,
            label,
            colour,
            anchor,
            head,
        } = &shown[0]
        else {
            panic!("not a remote caret");
        };
        assert_eq!(id, &"09".repeat(16));
        assert_eq!(label, "Pixel 10 Pro Fold");
        assert_eq!(*colour, 1, "the hue shown after the collision bump");
        assert_eq!(anchor, &vec![9, 1]);
        assert_eq!(head, &vec![9, 2]);
        assert_eq!(remotes.shown_for(container, other.note).len(), 1);
        assert!(
            remotes.shown_for(ContainerId([2; 16]), key.note).is_empty(),
            "another account shows nothing"
        );
        let target = peers.target_for("second").expect("a bound window");
        assert_eq!(target.label, "second");
        assert_eq!(target.note, key);
        assert_eq!(target.generation, 7);
        assert_eq!(target.page, 11);

        // A later selection from the same window is not a join: it already has
        // the carets, and nothing is sent again.
        let (_, _, joined) = peers.publish("second", cursor(key));
        assert!(!joined);
        // Moving to another note is a join for that note.
        let (_, _, joined) = peers.publish("second", cursor(other));
        assert!(joined);
        assert_eq!(remotes.shown_for(container, other.note).len(), 1);
        assert!(peers.target_for("second").is_some());
    }

    type MockApp = tauri::App<tauri::test::MockRuntime>;
    fn mock_app(owner: Arc<Owner>) -> MockApp {
        tauri::test::mock_builder()
            .manage(NoteHost::with_owner(owner))
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("mock app")
    }
    fn mock_window(app: &MockApp, label: &str) {
        tauri::WebviewWindowBuilder::new(app, label, tauri::WebviewUrl::App("index.html".into()))
            .build()
            .expect("mock window");
    }
    /// A page binds its lease and reports a first selection, as the editor does.
    fn select(app: &MockApp, label: &str, generation: u64) {
        let page = app.state::<NoteHost>().delivery.leases.bind_page(label);
        note_selection(
            app.get_webview_window(label).expect("window"),
            app.state::<NoteHost>(),
            generation,
            page.to_string(),
            1,
            2,
            None,
            None,
        );
    }

    /// Test 1c through the command itself: the window that publishes second on
    /// the note is told to draw the remote caret already shown there, while a
    /// window on another note or base is not. Deleting the join branch in
    /// `note_selection` fails this; the pure helpers stay green.
    #[test]
    fn note_selection_draws_shown_remote_caret_only_in_the_window_that_joins() {
        let (owner, id, writer, _dir, scopes) = delivery_fixture_with_scopes();
        let key = NoteKey {
            base: [1; 32],
            audience: [3; 32],
            note: [4; 32],
        };
        let base_scope = scopes.lock().unwrap()["writer"];
        let other_note = NoteKey {
            note: [5; 32],
            ..key
        };
        let other_base = NoteKey {
            base: [9; 32],
            note: [6; 32],
            ..key
        };
        for (label, note) in [("other-note", other_note), ("other-base", other_base)] {
            scopes.lock().unwrap().insert(
                label.into(),
                Scope {
                    key: note,
                    ..base_scope
                },
            );
            owner.bind(label, id).unwrap();
        }
        let reader = owner.open("reader", key.note).unwrap().generation;
        let other_note_generation = owner
            .open("other-note", other_note.note)
            .unwrap()
            .generation;
        let other_base_generation = owner
            .open("other-base", other_base.note)
            .unwrap()
            .generation;
        let app = mock_app(Arc::clone(&owner));
        for label in ["writer", "reader", "other-note", "other-base"] {
            mock_window(&app, label);
        }
        let host = app.state::<NoteHost>();
        select(&app, "writer", writer);
        host.deliver_remote(
            app.handle(),
            id,
            &[remote(9, key.note, "Pixel 10 Pro Fold", 1)],
        );
        assert_eq!(host.sent().len(), 1, "the writer draws the late remote");

        let before = host.sent().len();
        select(&app, "reader", reader);
        let sent = host.sent();
        let joined: Vec<&(String, String)> = sent[before..]
            .iter()
            .filter(|(label, _)| label == "reader")
            .collect();
        let [(_, script)] = joined.as_slice() else {
            panic!("the joining window gets one remote caret, got {joined:?}");
        };
        assert!(script.contains("\"type\":\"remote\""), "{script}");
        assert!(script.contains(&"09".repeat(16)), "{script}");
        assert!(script.contains("Pixel 10 Pro Fold"), "{script}");

        // A window that joins another note, and one in another base, gets no
        // remote caret: `shown_for` is keyed by this note.
        let before = host.sent().len();
        select(&app, "other-note", other_note_generation);
        select(&app, "other-base", other_base_generation);
        assert!(
            host.sent()[before..]
                .iter()
                .all(|(_, script)| !script.contains("\"type\":\"remote\"")),
            "another note or base shows nothing"
        );
        assert!(
            host.sent()[before..]
                .iter()
                .all(|(label, _)| label != "other-note" && label != "other-base"),
            "nothing at all is delivered to the other windows"
        );
    }

    /// A stopped client's last carets are forgotten with its watch: open
    /// windows remove them, and a window that opens the note later draws none.
    #[test]
    fn ending_a_presence_watch_removes_its_carets_everywhere() {
        let (owner, id, writer, _dir, scopes) = delivery_fixture_with_scopes();
        let key = NoteKey {
            base: [1; 32],
            audience: [3; 32],
            note: [4; 32],
        };
        let base_scope = scopes.lock().unwrap()["writer"];
        let app = mock_app(Arc::clone(&owner));
        mock_window(&app, "writer");
        let host = app.state::<NoteHost>();
        select(&app, "writer", writer);
        host.deliver_remote(app.handle(), id, &[remote(8, key.note, "Mac", 1)]);
        assert_eq!(
            host.remotes.lock().unwrap().shown_for(id, key.note).len(),
            1
        );
        host.watching.lock().unwrap().insert(id, 42);
        host.configured.lock().unwrap().insert(id, 1);

        // A stale watcher's token changes nothing.
        host.end_watch(app.handle(), id, 41);
        assert_eq!(
            host.remotes.lock().unwrap().shown_for(id, key.note).len(),
            1
        );

        let before = host.sent().len();
        host.end_watch(app.handle(), id, 42);
        assert!(
            host.remotes
                .lock()
                .unwrap()
                .shown_for(id, key.note)
                .is_empty(),
            "the stopped client's shown carets are gone"
        );
        assert!(!host.watching.lock().unwrap().contains_key(&id));
        assert!(!host.configured.lock().unwrap().contains_key(&id));
        let sent = host.sent();
        let removed = &sent[before..];
        assert!(
            removed.iter().any(|(label, script)| label == "writer"
                && script.contains("\"type\":\"remove\"")
                && script.contains(&"08".repeat(16))),
            "the open window removes the caret: {removed:?}"
        );

        // The note opens fresh later: nothing is replayed.
        scopes.lock().unwrap().insert("later".into(), base_scope);
        owner.bind("later", id).unwrap();
        let later = owner.open("later", key.note).unwrap().generation;
        mock_window(&app, "later");
        let before = host.sent().len();
        select(&app, "later", later);
        assert!(
            host.sent()[before..]
                .iter()
                .all(|(_, script)| !script.contains("\"type\":\"remote\"")),
            "a window opening the note later draws nothing"
        );
    }

    type ScopeRoutes = Arc<Mutex<HashMap<String, Scope>>>;
    struct Issuer(ScopeRoutes);
    impl AuthoritySource for Issuer {
        fn bound_scope(&self, window: &str) -> Option<Scope> {
            self.0.lock().unwrap().get(window).copied()
        }
    }
    fn delivery_fixture_with_scopes() -> (
        Arc<Owner>,
        ContainerId,
        u64,
        std::path::PathBuf,
        ScopeRoutes,
    ) {
        let dir = std::env::temp_dir().join(format!(
            "bh-native-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let signing = SigningKey::generate();
        let control = SigningKey::generate();
        let keys = DevicePublicKeys::new(
            signing.public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        let recovery =
            RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public());
        let draft = AccountEvent::genesis(keys, recovery);
        let signed = draft.finish(control.sign(draft.signing_bytes())).unwrap();
        let proof = VerifiedAccount::from_genesis(
            AccountId::of_genesis(&signed).unwrap(),
            signed.as_bytes(),
        )
        .unwrap();
        let mut db = DeviceDatabase::open(dir.join("native.db")).unwrap();
        db.commit_account_verified(
            proof.id().0,
            &[signed.as_bytes()],
            proof.head().position,
            proof.head().hash,
            false,
        )
        .unwrap();
        let scope = Scope {
            account: proof.id().0,
            key: NoteKey {
                base: [1; 32],
                audience: [3; 32],
                note: [4; 32],
            },
        };
        let scopes = Arc::new(Mutex::new(HashMap::from([
            ("writer".into(), scope),
            ("reader".into(), scope),
        ])));
        let owner = Arc::new(Owner::default());
        let id = owner
            .register(db, Some(&proof), Box::new(Issuer(Arc::clone(&scopes))))
            .unwrap();
        owner.bind("writer", id).unwrap();
        owner.bind("reader", id).unwrap();
        let writer = owner.open("writer", [4; 32]).unwrap();
        owner.open("reader", [4; 32]).unwrap();
        (owner, id, writer.generation, dir, scopes)
    }
    fn delivery_fixture() -> (Arc<Owner>, ContainerId, u64, std::path::PathBuf) {
        let (owner, id, generation, dir, _) = delivery_fixture_with_scopes();
        (owner, id, generation, dir)
    }
    type Callback = Box<dyn Fn(String) + Send>;
    #[test]
    fn obsolete_eval_releases_old_lease_and_delivers_new_note_without_another_commit() {
        let (owner, id, writer, _dir, scopes) = delivery_fixture_with_scopes();
        let leases = Arc::new(DeliveryLeases::default());
        leases.bind_page("reader");
        owner
            .commit_queued("writer", writer, [1; 16], &[0, 0])
            .unwrap();
        let old = leases.start("reader").unwrap();
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let delivered_next = Arc::clone(&delivered);
        let owner_next = Arc::clone(&owner);
        let leases_next = Arc::clone(&leases);
        let next: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            let token = leases_next
                .start("reader")
                .expect("obsolete lease must be released");
            let (ok, submitted) = dispatch_surface(
                &owner_next,
                &leases_next,
                "reader",
                token,
                |item, callback| {
                    delivered_next.lock().unwrap().push(item.generation);
                    callback("\"accepted\"".into());
                    true
                },
                Arc::new(|| {}),
            );
            assert!(ok && submitted);
        });
        let mut old_callback = None;
        let (ok, submitted) = dispatch_surface(
            &owner,
            &leases,
            "reader",
            old,
            |_, callback| {
                old_callback = Some(callback);
                true
            },
            Arc::clone(&next),
        );
        assert!(ok && submitted);
        // Same WebView: note switch rotates its page, not the outstanding lease.
        let new_note = [5; 32];
        let old_scope = scopes.lock().unwrap()["reader"];
        let new_scope = Scope {
            key: NoteKey {
                note: new_note,
                ..old_scope.key
            },
            ..old_scope
        };
        {
            let mut routes = scopes.lock().unwrap();
            routes.insert("reader".into(), new_scope);
            routes.insert("new-writer".into(), new_scope);
        }
        owner.bind("reader", id).unwrap();
        let new_reader = owner.open("reader", new_note).unwrap().generation;
        leases.bind_page("reader");
        owner.bind("new-writer", id).unwrap();
        let new_generation = owner.open("new-writer", new_note).unwrap().generation;
        owner
            .commit_queued("new-writer", new_generation, [2; 16], &[0, 0])
            .unwrap();
        assert!(
            leases.start("reader").is_none(),
            "new work waits behind old eval"
        );
        old_callback.unwrap()("\"stale\"".into());
        assert_eq!(*delivered.lock().unwrap(), vec![new_reader]);
        assert!(!owner.has_queued_delivery("reader"));
    }
    #[test]
    fn obsolete_pre_post_failure_wakes_newly_queued_generation() {
        let (owner, id, writer, _dir) = delivery_fixture();
        let leases = Arc::new(DeliveryLeases::default());
        leases.bind_page("reader");
        owner
            .commit_queued("writer", writer, [1; 16], &[0, 0])
            .unwrap();
        let old = leases.start("reader").unwrap();
        let wakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = Arc::clone(&wakes);
        let next: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            count.fetch_add(1, Ordering::Relaxed);
        });
        dispatch_surface(
            &owner,
            &leases,
            "reader",
            old,
            |_, _| {
                owner.bind("reader", id).unwrap();
                owner.open("reader", [4; 32]).unwrap();
                leases.bind_page("reader");
                owner
                    .commit_queued("writer", writer, [2; 16], &[0, 0])
                    .unwrap();
                false // The old scheduled post fails after navigation.
            },
            next,
        );
        assert_eq!(wakes.load(Ordering::Relaxed), 1);
        assert!(owner.has_queued_delivery("reader"));
        assert!(leases.start("reader").is_some());
    }
    #[test]
    fn dispatcher_posts_one_eval_and_handles_lifecycle_completion_and_failure() {
        let (owner, id, writer, _dir) = delivery_fixture();
        let leases = Arc::new(DeliveryLeases::default());
        leases.bind_page("reader");
        let wakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let next: Arc<dyn Fn() + Send + Sync> = Arc::new({
            let wakes = Arc::clone(&wakes);
            move || {
                wakes.fetch_add(1, Ordering::Relaxed);
            }
        });
        let bytes = [0, 0];
        owner
            .commit_queued("writer", writer, [1; 16], &bytes)
            .unwrap();
        owner
            .commit_queued("writer", writer, [2; 16], &bytes)
            .unwrap();
        let token = leases.start("reader").unwrap();
        let mut callbacks: Vec<Callback> = Vec::new();
        let (ok, submitted) = dispatch_surface(
            &owner,
            &leases,
            "reader",
            token,
            |_, callback| {
                callbacks.push(callback);
                true
            },
            Arc::clone(&next),
        );
        assert!(ok && submitted);
        assert_eq!(
            callbacks.len(),
            1,
            "a mutant unbounded drain posts multiple accepted evals"
        );
        assert!(leases.start("reader").is_none());
        callbacks.pop().unwrap()("\"accepted\"".into());
        assert_eq!(wakes.load(Ordering::Relaxed), 1);
        assert!(leases.start("reader").is_some());
        // An error payload retains a bounded resync but never reposts in its callback.
        let token = leases.start("other").unwrap();
        leases.finish("other", token);
        let token = leases.start("reader");
        assert!(token.is_none(), "the prior test wake must own the lease");
        let current = leases.state.lock().unwrap().active["reader"];
        let mut pending = Vec::new();
        dispatch_surface(
            &owner,
            &leases,
            "reader",
            current,
            |_, callback| {
                pending.push(callback);
                true
            },
            Arc::clone(&next),
        );
        assert_eq!(pending.len(), 1);
        pending.pop().unwrap()("{\"error\":\"renderer\"}".into());
        assert_eq!(owner.queued_delivery_budget("reader"), (1, 0, true));
        assert_eq!(
            wakes.load(Ordering::Relaxed),
            1,
            "failed eval must not spin"
        );
        assert!(!leases.current("reader", current));
        let stalled = leases.start("reader").unwrap();
        dispatch_surface(
            &owner,
            &leases,
            "reader",
            stalled,
            |_, callback| {
                pending.push(callback);
                true
            },
            Arc::clone(&next),
        );
        for _ in 0..100 {
            assert!(leases.start("reader").is_none());
        }
        owner.close_generation("reader", owner.open("reader", [4; 32]).unwrap().generation);
        owner.bind("reader", id).unwrap();
        owner.open("reader", [4; 32]).unwrap();
        assert!(
            leases.start("reader").is_none(),
            "close/open/rebind is not native replacement"
        );
        leases.cancel("reader"); // page Started or window Destroyed
        leases.bind_page("reader");
        let replacement = leases.start("reader").unwrap();
        pending.pop().unwrap()("\"accepted\"".into());
        assert_eq!(
            wakes.load(Ordering::Relaxed),
            1,
            "replaced lease cannot wake"
        );
        assert!(
            leases.current("reader", replacement),
            "late callback cannot release replacement"
        );
        leases.finish("reader", replacement);
        owner
            .commit_queued("writer", writer, [3; 16], &bytes)
            .unwrap();
        let rejected = leases.start("reader").unwrap();
        let (ok, submitted) = dispatch_surface(
            &owner,
            &leases,
            "reader",
            rejected,
            |_, _| false,
            Arc::clone(&next),
        );
        assert!(ok && submitted);
        assert_eq!(owner.queued_delivery_budget("reader"), (1, 0, true));
        assert!(!leases.current("reader", rejected));
        let no_listener = leases.start("reader").unwrap();
        let mut failed = Vec::new();
        dispatch_surface(
            &owner,
            &leases,
            "reader",
            no_listener,
            |_, callback| {
                failed.push(callback);
                true
            },
            Arc::clone(&next),
        );
        failed.pop().unwrap()("\"stale\"".into());
        assert_eq!(owner.queued_delivery_budget("reader"), (1, 0, true));
        assert_eq!(wakes.load(Ordering::Relaxed), 1);
        let buffered = leases.start("reader").unwrap();
        dispatch_surface(
            &owner,
            &leases,
            "reader",
            buffered,
            |_, callback| {
                failed.push(callback);
                true
            },
            Arc::clone(&next),
        );
        failed.pop().unwrap()("\"buffered\"".into());
        assert!(!leases.current("reader", buffered));
    }
    #[test]
    fn scheduled_dispatch_after_label_reuse_never_posts_old_bytes() {
        let (owner, id, writer, _dir) = delivery_fixture();
        let leases = Arc::new(DeliveryLeases::default());
        leases.bind_page("reader");
        owner
            .commit_queued("writer", writer, [1; 16], &[0, 0])
            .unwrap();
        let old = leases.start("reader").unwrap();
        let (scheduled, ready) = mpsc::channel();
        let (resume, continued) = mpsc::channel();
        let worker_owner = Arc::clone(&owner);
        let worker_leases = Arc::clone(&leases);
        let worker = thread::spawn(move || {
            scheduled.send(()).unwrap();
            continued.recv().unwrap();
            let mut calls = 0;
            dispatch_surface(
                &worker_owner,
                &worker_leases,
                "reader",
                old,
                |_, _| {
                    calls += 1;
                    true
                },
                Arc::new(|| {}),
            );
            calls
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        // Native destruction + new window, or PageLoad::Started + replacement
        // in the same WebView, invalidates the scheduled surface first.
        leases.cancel("reader");
        owner.invalidate("reader");
        owner.bind("reader", id).unwrap();
        owner.open("reader", [4; 32]).unwrap();
        leases.bind_page("reader");
        let fresh = leases.start("reader").unwrap();
        resume.send(()).unwrap();
        assert_eq!(worker.join().unwrap(), 0);
        assert!(leases.current("reader", fresh));
    }
    #[test]
    fn scheduled_pinned_post_rejects_cancelled_lease() {
        let (owner, id, writer, _dir) = delivery_fixture();
        let leases = Arc::new(DeliveryLeases::default());
        let page = leases.bind_page("reader");
        owner
            .commit_queued("writer", writer, [1; 16], &[0, 0])
            .unwrap();
        let mut items = Vec::new();
        owner.drain_surface_once("reader", &mut |item| items.push(item));
        let item = items.pop().unwrap();
        let old = leases.start("reader").unwrap();
        let (ready, scheduled) = mpsc::channel();
        let (resume, continued) = mpsc::channel();
        let worker_owner = Arc::clone(&owner);
        let worker_leases = Arc::clone(&leases);
        let worker = thread::spawn(move || {
            ready.send(()).unwrap();
            continued.recv().unwrap();
            let mut posts = 0;
            let accepted = post_if_current(
                &worker_owner,
                &worker_leases,
                "reader",
                old,
                page,
                &item,
                || {
                    posts += 1;
                    true
                },
            );
            (accepted, posts)
        });
        scheduled.recv_timeout(Duration::from_secs(2)).unwrap();
        leases.cancel("reader"); // PageLoad::Started, before next document
        owner.invalidate("reader");
        owner.bind("reader", id).unwrap();
        owner.open("reader", [4; 32]).unwrap();
        leases.bind_page("reader");
        resume.send(()).unwrap();
        assert_eq!(worker.join().unwrap(), (false, 0));
    }
    #[test]
    fn repeated_note_binding_rotates_page_token_and_rejects_old_eval() {
        let leases = DeliveryLeases::default();
        let first = leases.bind_page("reader"); // first note_binding
        let second = leases.bind_page("reader"); // new document, before PageLoad::Started
        assert_ne!(first, second);
        assert!(leases.start_if_page("reader", first).is_none());
        assert!(leases.start_if_page("reader", second).is_some());
        // The browser test exercises the actual bridge's old-token eval guard:
        // this old token returns 'stale' before calling __bhNoteDelivery.
    }
    #[test]
    fn sync_status_answers_only_the_calling_windows_current_page() {
        let (owner, id, _, _dir) = delivery_fixture();
        let leases = DeliveryLeases::default();
        let old = leases.bind_page("reader").to_string();
        let page = leases.bind_page("reader").to_string();
        let view = |container: ContainerId| (container == id).then_some("current");
        assert_eq!(
            page_status(&leases, &owner, "reader", &page, view),
            Ok(Some("current"))
        );
        // The window's earlier page, a bad token, or another window's page.
        assert!(page_status(&leases, &owner, "reader", &old, view).is_err());
        assert!(page_status(&leases, &owner, "reader", "current", view).is_err());
        assert!(page_status(&leases, &owner, "writer", &page, view).is_err());
        let writer = leases.bind_page("writer").to_string();
        assert_eq!(
            page_status(&leases, &owner, "writer", &writer, view),
            Ok(Some("current"))
        );
        // A page in a window bound to no account, and a page that has gone.
        let unbound = leases.bind_page("unbound").to_string();
        assert!(page_status(&leases, &owner, "unbound", &unbound, view).is_err());
        leases.cancel("reader");
        assert!(page_status(&leases, &owner, "reader", &page, view).is_err());
        // Its account's status before any was published: nothing yet.
        assert_eq!(
            page_status(&leases, &owner, "writer", &writer, |_| None::<()>),
            Ok(None)
        );
    }
    #[test]
    fn delayed_eval_callback_owns_only_its_window_lease() {
        let leases = DeliveryLeases::default();
        let old_page = leases.bind_page("stalled");
        let first = leases.start_if_page("stalled", old_page).unwrap();
        assert!(leases.start("stalled").is_none());
        let other = leases.start("other").unwrap();
        assert!(leases.finish("other", other));
        assert!(
            leases.start("other").is_some(),
            "second worker can serve other surface"
        );
        leases.cancel("stalled");
        let new_page = leases.bind_page("stalled");
        assert_ne!(old_page, new_page);
        assert!(leases.start_if_page("stalled", old_page).is_none());
        let reopened = leases.start_if_page("stalled", new_page).unwrap();
        assert!(
            !leases.finish("stalled", first),
            "late old eval must not release new lease"
        );
        assert!(leases.start("stalled").is_none());
        assert!(leases.finish("stalled", reopened));
        assert!(leases.start("stalled").is_some());
    }

    #[test]
    fn a_missing_callback_cannot_admit_a_second_eval_until_surface_replacement() {
        // Native scheduling fake: each queued wake attempts the same lease the
        // dispatcher uses. No timing assumption or real WebView is involved.
        let leases = DeliveryLeases::default();
        let waiting = leases.start("busy").unwrap();
        for _ in 0..10_000 {
            assert!(
                leases.start("busy").is_none(),
                "live WebView still owns its eval"
            );
        }
        let other = leases.start("idle").unwrap();
        assert!(leases.finish("idle", other));
        assert!(
            leases.start("idle").is_some(),
            "other surfaces keep progressing"
        );
        // A completed callback releases exactly one slot, allowing a bounded
        // queue's latest delta/resync to become the next evaluation.
        assert!(leases.finish("busy", waiting));
        let next = leases.start("busy").unwrap();
        for _ in 0..10_000 {
            assert!(leases.start("busy").is_none());
        }
        leases.cancel("busy"); // real native destruction/replacement
        let replaced = leases.start("busy").unwrap();
        assert!(
            !leases.finish("busy", next),
            "late callback cannot release replacement"
        );
        assert!(leases.finish("busy", replaced));
    }

    #[tokio::test]
    async fn saves_wait_behind_open_and_save_then_succeed() {
        let admission = Arc::new(Admission::default());
        let tasks = Arc::new(Semaphore::new(MAX_STORAGE_TASKS));
        let account = ContainerId([1; 16]);
        // Open and save occupy the account's two lanes. A third save waits
        // asynchronously, rather than reporting a failed save to the editor.
        let open = admission.enter(account, Arc::clone(&tasks)).await;
        let saving = admission.enter(account, Arc::clone(&tasks)).await;
        let waiting = {
            let admission = Arc::clone(&admission);
            let tasks = Arc::clone(&tasks);
            tokio::spawn(async move { admission.enter(account, tasks).await })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished(), "save must wait, not reject");
        let other = admission
            .enter(ContainerId([2; 16]), Arc::clone(&tasks))
            .await;
        drop(open);
        let finished = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
        drop(saving);
        drop(finished);
        drop(other);
        assert!(admission.containers.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn ten_bases_await_admission_without_refusing_saves() {
        let admission = Arc::new(Admission::default());
        let tasks = Arc::new(Semaphore::new(MAX_STORAGE_TASKS));
        let id = ContainerId([9; 16]);
        let began = std::time::Instant::now();
        let mut saves = Vec::new();
        for _base in 0..10 {
            let admission = Arc::clone(&admission);
            let tasks = Arc::clone(&tasks);
            saves.push(tokio::spawn(async move {
                let _permit = admission.enter(id, tasks).await;
                tauri::async_runtime::spawn_blocking(|| {
                    std::thread::sleep(Duration::from_millis(5))
                })
                .await
                .unwrap();
            }));
        }
        for save in saves {
            save.await.unwrap();
        }
        eprintln!(
            "ten synthetic base saves: native admission + blocking thread wall {:?} (no Owner/SQLite/WebView)",
            began.elapsed()
        );
        assert!(admission.containers.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn three_windows_reopen_in_one_account_without_rejection() {
        let admission = Arc::new(Admission::default());
        let tasks = Arc::new(Semaphore::new(MAX_STORAGE_TASKS));
        let id = ContainerId([3; 16]);
        let first = admission.enter(id, Arc::clone(&tasks)).await;
        let second = admission.enter(id, Arc::clone(&tasks)).await;
        let third = {
            let admission = Arc::clone(&admission);
            let tasks = Arc::clone(&tasks);
            tokio::spawn(async move { admission.enter(id, tasks).await })
        };
        tokio::task::yield_now().await;
        assert!(!third.is_finished());
        drop(second);
        let third = tokio::time::timeout(Duration::from_secs(1), third)
            .await
            .unwrap()
            .unwrap();
        drop(first);
        drop(third);
        assert!(admission.containers.lock().unwrap().is_empty());
    }
}
