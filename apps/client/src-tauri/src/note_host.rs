//! Native-only adapter. No store is opened and no note is bound until a real
//! verified account session supplies native authority. Setup has no note IPC.
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use bh_account::VerifiedAccount;
use bh_device::{ContainerId, Owner, OwnerError, coordinator::AuthoritySource};
use bh_storage::{DeviceDatabase, NoteKey};
use serde::Serialize;
use tauri::{AppHandle, Manager, WebviewWindow};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

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
#[derive(Debug, PartialEq, Eq)]
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
    fn publish(&mut self, window: &str, cursor: CursorState) -> (Vec<PeerTarget>, Vec<Peer>) {
        let (container, note) = (cursor.container, cursor.note);
        if self
            .windows
            .get(window)
            .is_some_and(|previous| *previous != (container, note))
        {
            self.remove(window);
        }
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
        (targets, visible)
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
        };
        if !owner.delivery_current(&retry) || !leases.current(label, token) {
            leases.finish(label, token);
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
                if !consumed {
                    callback_owner.retry_delivery(&callback_retry);
                }
                if callback_leases.finish(&callback_label, token)
                    && consumed
                    && callback_owner.has_queued_delivery(&callback_label)
                {
                    next();
                }
            }),
        );
        if !accepted && leases.current(label, token) {
            owner.retry_delivery(&retry);
            leases.finish(label, token);
        }
    });
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
                                update:item.update, resync:item.resync };
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
                                    update:Vec::new(), resync:true,
                                };
                                // A queued eval after navigation must not construct
                                // or dispatch a plaintext event in the new document.
                                let script = format!("(()=>{{if(window.__bhNotePage!==\"{page}\")return 'stale';return window.__bhNoteDelivery?.({json})??'stale'}})()");
                                if !post_if_current(&owner, &leases, &label, token, page, &retry,
                                    || pinned.eval_with_callback(script, callback).is_ok()) {
                                    owner.retry_delivery(&retry);
                                    if leases.finish(&label, token) && owner.has_queued_delivery(&label) {
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
}
impl Default for NoteHost {
    fn default() -> Self {
        let owner = Arc::new(Owner::default());
        let delivery = Arc::new(DeliveryDispatcher::new(Arc::clone(&owner)));
        Self {
            owner,
            tasks: Arc::new(Semaphore::new(MAX_STORAGE_TASKS)),
            admissions: Arc::new(Admission::default()),
            delivery,
            peers: Mutex::new(PeerCursors::default()),
        }
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
    }
    fn send_peers(&self, app: &AppHandle, targets: Vec<PeerTarget>, message: &PeerMessage) {
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
    fn invalidate(&self, app: &AppHandle, window: &str) {
        self.clear_peer(app, window);
        self.delivery.cancel(window);
        self.owner.invalidate(window);
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum PeerMessage {
    Set { id: String, anchor: u32, head: u32 },
    Remove { id: String },
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Opened {
    state: Vec<u8>,
    generation: u64,
    sequence: u64,
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
}

/// Call once per document. A second binding call rotates the page token and
/// silently ends delivery to that document until it reloads.
#[tauri::command]
fn note_binding(window: WebviewWindow, host: tauri::State<'_, NoteHost>) -> Option<Binding> {
    host.clear_peer(window.app_handle(), window.label());
    host.owner.bound_note(window.label()).map(|note| Binding {
        note: note.to_vec(),
        surface: host.delivery.leases.bind_page(window.label()).to_string(),
    })
}
#[derive(Serialize)]
struct Binding {
    note: Vec<u8>,
    surface: String,
}
#[tauri::command]
async fn note_open(
    window: WebviewWindow,
    host: tauri::State<'_, NoteHost>,
    note: Vec<u8>,
) -> Result<Opened, &'static str> {
    let note: [u8; 32] = note.try_into().map_err(|_| "note unavailable")?;
    let label = window.label().to_owned();
    let owner = Arc::clone(&host.owner);
    let (id, _) = owner
        .bound_open_key(&label, note)
        .ok_or("note unavailable")?;
    let permit = host.admissions.enter(id, Arc::clone(&host.tasks)).await;
    let open_label = label.clone();
    let opened = tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        owner.open(&open_label, note)
    })
    .await
    .map_err(|_| "note unavailable")?;
    let opened = opened.map_err(|err| match err {
        OwnerError::Changed => "note changed; retry open",
        _ => "note unavailable",
    })?;
    host.clear_peer(window.app_handle(), &label);
    Ok(Opened {
        state: opened.state,
        generation: opened.generation,
        sequence: opened.sequence,
    })
}
#[tauri::command]
async fn note_commit(
    window: WebviewWindow,
    host: tauri::State<'_, NoteHost>,
    generation: u64,
    request_id: String,
    update: Vec<u8>,
) -> Result<Acknowledged, &'static str> {
    let request: [u8; 16] = decode_request(&request_id).ok_or("invalid request")?;
    let label = window.label().to_owned();
    let (id, _) = host
        .owner
        .bound_work_key(&label, generation)
        .ok_or("note unavailable")?;
    let task_permit = host.admissions.enter(id, Arc::clone(&host.tasks)).await;
    let owner = Arc::clone(&host.owner);
    let delivery = Arc::clone(&host.delivery);
    let app = window.app_handle().clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let _task_permit = task_permit;
        let committed = owner.commit_queued(&label, generation, request, &update);
        if let Ok((_, targets)) = &committed {
            for target in targets {
                delivery.wake(app.clone(), target.clone());
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
fn note_selection(
    window: WebviewWindow,
    host: tauri::State<'_, NoteHost>,
    generation: u64,
    surface: String,
    anchor: u32,
    head: u32,
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
    let (targets, visible) = host.peers.lock().expect("peer lock").publish(
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
    tauri::Builder::default()
        .manage(NoteHost::default())
        .invoke_handler(tauri::generate_handler![
            note_binding,
            note_open,
            note_commit,
            note_selection,
            note_close
        ])
        .on_page_load(|webview, payload| {
            if payload.event() == tauri::webview::PageLoadEvent::Started {
                webview
                    .app_handle()
                    .state::<NoteHost>()
                    .invalidate(webview.app_handle(), webview.label());
            }
        })
        .on_window_event(|window, event| {
            if matches!(event, tauri::WindowEvent::Destroyed) {
                window
                    .app_handle()
                    .state::<NoteHost>()
                    .invalidate(window.app_handle(), window.label());
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_account::{
        AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount,
        crypto::{KemKey, SigningKey},
    };
    use bh_device::coordinator::Scope;
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
        let (targets, visible) = peers.publish(
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

    struct Issuer(HashMap<String, Scope>);
    impl AuthoritySource for Issuer {
        fn bound_scope(&self, window: &str) -> Option<Scope> {
            self.0.get(window).copied()
        }
    }
    fn delivery_fixture() -> (Arc<Owner>, ContainerId, u64, std::path::PathBuf) {
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
        let owner = Arc::new(Owner::default());
        let id = owner
            .register(
                db,
                Some(&proof),
                Box::new(Issuer(HashMap::from([
                    ("writer".into(), scope),
                    ("reader".into(), scope),
                ]))),
            )
            .unwrap();
        owner.bind("writer", id).unwrap();
        owner.bind("reader", id).unwrap();
        let writer = owner.open("writer", [4; 32]).unwrap();
        owner.open("reader", [4; 32]).unwrap();
        (owner, id, writer.generation, dir)
    }
    type Callback = Box<dyn Fn(String) + Send>;
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
