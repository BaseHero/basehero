//! The one native owner of the close, Quit and update barrier.
//!
//! Each entry point holds its windows under an owner drain fence, asks every
//! held page to finish composition and save its accepted writing, and counts
//! only replies from the current page token and fence. The owner marks each
//! reply under the note lease that also fences COMMIT, so nothing is written
//! after a window says it is drained. Quit and update then replace every
//! anchored container's restart records. Dropping the hold resumes exactly
//! its own pages and removes only the records it wrote; a discard is never
//! readiness for an update.
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bh_device::{ContainerId, DrainFence, MAX_SELECTION_BYTES, Owner};
use bh_storage::{DeviceDatabase, NoteKey, ViewRecord};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

/// Why a close, Quit or update drain did not finish. Deliberately names no
/// account, base, note or window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Another lifecycle drain already holds these windows.
    Busy,
    /// A window could not save its writing (or its restart records failed).
    NotSaved,
    /// A window did not reply before the deadline.
    TimedOut,
}

/// Why the pages are held; the page shows "Saving before update…" for Update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    Close,
    Quit,
    Update,
}
impl Reason {
    fn page(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::Close | Self::Quit => "close",
        }
    }
}
/// Which windows the owner holds while they drain.
pub(crate) enum Scope {
    All,
    #[cfg_attr(mobile, allow(dead_code))]
    Window(String),
}
/// A window to drain and its current note page token, if its page bound one.
pub(crate) struct Target {
    pub label: String,
    pub page: Option<u64>,
}

/// The page's restart view: encoded Yjs relative selection, and how far the
/// selection head sat below the top of its visible scroll area, in CSS
/// pixels (negative above it). Presentation only, bounded before storage.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CapturedView {
    pub version: u32,
    pub anchor: Vec<u8>,
    pub head: Vec<u8>,
    pub cursor_offset: f64,
}
pub(crate) const MAX_CURSOR_OFFSET: f64 = 10_000_000.0;
impl CapturedView {
    fn valid(&self) -> bool {
        self.version == 1
            && self.anchor.len() <= MAX_SELECTION_BYTES
            && self.head.len() <= MAX_SELECTION_BYTES
            && self.cursor_offset.abs() <= MAX_CURSOR_OFFSET
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Saved,
    Failed,
    /// Its earlier eval is still outstanding; nothing new was posted.
    Stalled,
}
struct Waiting {
    page: u64,
    outcome: Option<Outcome>,
}
struct Operation {
    fence: DrainFence,
    reason: Reason,
    waiting: HashMap<String, Waiting>,
    views: Vec<(String, ContainerId, ViewRecord)>,
    notify: Arc<Notify>,
}
/// A drain's windows by outcome so far, each list sorted by label.
struct Status {
    waiting: bool,
    failed: Vec<String>,
    /// Stalled, or still waiting at the deadline.
    unanswered: Vec<String>,
}

/// Lifecycle drains in progress, keyed by an id only native code and the
/// held pages see. Owner fences decide which drains may coexist.
#[derive(Default)]
pub(crate) struct Drains {
    ops: Mutex<HashMap<String, Operation>>,
    next: AtomicU64,
}
impl Drains {
    fn begin(
        &self,
        fence: DrainFence,
        reason: Reason,
        pages: &[(String, u64)],
    ) -> (String, Arc<Notify>) {
        let id = self
            .next
            .fetch_add(1, Ordering::Relaxed)
            .checked_add(1)
            .expect("drain id exhausted")
            .to_string();
        let notify = Arc::new(Notify::new());
        let waiting = pages
            .iter()
            .map(|(label, page)| {
                (
                    label.clone(),
                    Waiting {
                        page: *page,
                        outcome: None,
                    },
                )
            })
            .collect();
        self.ops.lock().expect("drain lock").insert(
            id.clone(),
            Operation {
                fence,
                reason,
                waiting,
                views: Vec::new(),
                notify: Arc::clone(&notify),
            },
        );
        (id, notify)
    }
    /// The owner fence for a reply from this exact page of a current drain.
    pub(crate) fn accepts(&self, label: &str, page: u64, id: &str) -> Option<(DrainFence, Reason)> {
        let ops = self.ops.lock().expect("drain lock");
        let op = ops.get(id)?;
        let waiting = op.waiting.get(label)?;
        (waiting.page == page && waiting.outcome.is_none()).then_some((op.fence, op.reason))
    }
    /// Record a reply once; a stale page, fence or repeated reply is refused.
    fn reply(
        &self,
        label: &str,
        page: u64,
        id: &str,
        outcome: Outcome,
        view: Option<(ContainerId, ViewRecord)>,
    ) -> bool {
        let mut ops = self.ops.lock().expect("drain lock");
        let Some(op) = ops.get_mut(id) else {
            return false;
        };
        let Some(waiting) = op
            .waiting
            .get_mut(label)
            .filter(|w| w.page == page && w.outcome.is_none())
        else {
            return false;
        };
        waiting.outcome = Some(outcome);
        if let Some((container, record)) = view {
            op.views.push((label.to_owned(), container, record));
        }
        op.notify.notify_one();
        true
    }
    fn status(&self, id: &str) -> Option<Status> {
        let ops = self.ops.lock().expect("drain lock");
        let op = ops.get(id)?;
        let mut status = Status {
            waiting: false,
            failed: Vec::new(),
            unanswered: Vec::new(),
        };
        let mut labels: Vec<_> = op.waiting.iter().collect();
        labels.sort_by(|a, b| a.0.cmp(b.0));
        for (label, waiting) in labels {
            match waiting.outcome {
                None => {
                    status.waiting = true;
                    status.unanswered.push(label.clone());
                }
                Some(Outcome::Failed) => status.failed.push(label.clone()),
                Some(Outcome::Stalled) => status.unanswered.push(label.clone()),
                Some(Outcome::Saved) => {}
            }
        }
        Some(status)
    }
    /// The main window's record first, then others by label: restore uses the
    /// main window for the first record and opens one window per other.
    fn views(&self, id: &str) -> Vec<(ContainerId, ViewRecord)> {
        let ops = self.ops.lock().expect("drain lock");
        let Some(op) = ops.get(id) else {
            return Vec::new();
        };
        let mut views = op.views.clone();
        views.sort_by(|a, b| (a.0 != "main", &a.0).cmp(&(b.0 != "main", &b.0)));
        views.into_iter().map(|(_, c, r)| (c, r)).collect()
    }
    fn end(&self, id: &str) {
        self.ops.lock().expect("drain lock").remove(id);
    }
    /// The page is gone (destroyed or its web content process ended): any
    /// drain waiting on it fails rather than waiting out its deadline.
    pub(crate) fn page_gone(&self, label: &str) {
        let mut ops = self.ops.lock().expect("drain lock");
        for op in ops.values_mut() {
            if let Some(waiting) = op.waiting.get_mut(label)
                && waiting.outcome.is_none()
            {
                waiting.outcome = Some(Outcome::Failed);
                op.notify.notify_one();
            }
        }
    }
}

/// At most one lifecycle evaluation outstanding per WebView, across drains,
/// retries and deadlines: a timeout cannot retract a posted eval, so the
/// next attempt waits for its callback (or page replacement) instead of
/// adding another. A resume that cannot post yet is posted on that callback.
#[derive(Default)]
pub(crate) struct ControlLeases {
    slots: Mutex<HashMap<String, Slot>>,
    next: AtomicU64,
}
struct Slot {
    token: u64,
    resume: Option<(u64, String)>,
}
impl ControlLeases {
    pub(crate) fn start(&self, label: &str) -> Option<u64> {
        let mut slots = self.slots.lock().expect("control lease lock");
        if slots.contains_key(label) {
            return None;
        }
        let token = self
            .next
            .fetch_add(1, Ordering::Relaxed)
            .checked_add(1)
            .expect("control token exhausted");
        slots.insert(
            label.to_owned(),
            Slot {
                token,
                resume: None,
            },
        );
        Some(token)
    }
    /// Release this lease; returns a resume (page, drain id) to post next.
    pub(crate) fn finish(&self, label: &str, token: u64) -> Option<(u64, String)> {
        let mut slots = self.slots.lock().expect("control lease lock");
        if slots.get(label).is_none_or(|slot| slot.token != token) {
            return None;
        }
        slots.remove(label).and_then(|slot| slot.resume)
    }
    /// Remember a resume for the outstanding eval's callback; false if none.
    fn defer_resume(&self, label: &str, page: u64, id: &str) -> bool {
        let mut slots = self.slots.lock().expect("control lease lock");
        match slots.get_mut(label) {
            Some(slot) => {
                slot.resume = Some((page, id.to_owned()));
                true
            }
            None => false,
        }
    }
    /// Page replaced or WebView destroyed: its eval and callback are void.
    pub(crate) fn cancel(&self, label: &str) {
        self.slots.lock().expect("control lease lock").remove(label);
    }
    #[cfg(test)]
    fn outstanding(&self, label: &str) -> bool {
        self.slots
            .lock()
            .expect("control lease lock")
            .contains_key(label)
    }
}

/// Posts one script to a window's current page, on its UI thread. `done`
/// runs with the script's JSON result, or never (a stalled WebView).
pub(crate) trait Poster: Send + Sync {
    fn post(
        &self,
        label: &str,
        page: u64,
        script: String,
        done: Box<dyn FnOnce(String) + Send>,
    ) -> bool;
}

/// Native lifecycle state shared by close, Quit and update.
#[derive(Default)]
pub(crate) struct Lifecycle {
    pub drains: Drains,
    pub leases: ControlLeases,
    typed: Mutex<Option<Instant>>,
}
impl Lifecycle {
    /// A page asked to save local writing (typing, paste, Undo, formatting).
    pub(crate) fn typed(&self) {
        *self.typed.lock().expect("typing lock") = Some(Instant::now());
    }
    fn last_typed(&self) -> Option<Instant> {
        *self.typed.lock().expect("typing lock")
    }
}

fn resume_script(page: u64, id: &str) -> String {
    format!(
        "(()=>{{if(window.__bhNotePage!==\"{page}\")return 'stale';return window.__bhResumeEditing?.(\"{id}\")??'stale'}})()"
    )
}
fn drain_script(page: u64, id: &str, timeout: Duration, reason: Reason) -> String {
    format!(
        "(()=>{{if(window.__bhNotePage!==\"{page}\")return 'stale';return window.__bhDrain?.({{page:\"{page}\",fence:\"{id}\",timeoutMs:{},reason:\"{}\"}})??'stale'}})()",
        timeout.as_millis().max(1),
        reason.page()
    )
}
fn post_resume(
    lifecycle: &Arc<Lifecycle>,
    poster: &Arc<dyn Poster>,
    label: &str,
    page: u64,
    id: &str,
) {
    let Some(token) = lifecycle.leases.start(label) else {
        lifecycle.leases.defer_resume(label, page, id);
        return;
    };
    let done_lifecycle = Arc::clone(lifecycle);
    let done_poster = Arc::clone(poster);
    let done_label = label.to_owned();
    let posted = poster.post(
        label,
        page,
        resume_script(page, id),
        Box::new(move |_| {
            if let Some((page, id)) = done_lifecycle.leases.finish(&done_label, token) {
                post_resume(&done_lifecycle, &done_poster, &done_label, page, &id);
            }
        }),
    );
    if !posted {
        lifecycle.leases.finish(label, token);
    }
}

/// Holds windows for one drain until it is dropped or kept for exit.
pub(crate) struct Held {
    owner: Arc<Owner>,
    lifecycle: Arc<Lifecycle>,
    poster: Arc<dyn Poster>,
    id: String,
    fence: DrainFence,
    pages: Vec<(String, u64)>,
    written: Vec<Arc<Mutex<DeviceDatabase>>>,
    kept: bool,
}
impl Held {
    /// Exit or relaunch follows: keep every window held and the records.
    pub(crate) fn keep(mut self) {
        self.kept = true;
    }
}
impl Drop for Held {
    fn drop(&mut self) {
        if self.kept {
            return;
        }
        let owner = Arc::clone(&self.owner);
        let lifecycle = Arc::clone(&self.lifecycle);
        let poster = Arc::clone(&self.poster);
        let id = std::mem::take(&mut self.id);
        let fence = self.fence;
        let pages = std::mem::take(&mut self.pages);
        let written = std::mem::take(&mut self.written);
        let wrote = !written.is_empty();
        // Remove the records this drain wrote before another drain may start;
        // SQLite never runs on the UI thread that may drop this guard.
        let release = move || {
            for database in written {
                let _ = database
                    .lock()
                    .expect("container writer lock")
                    .delete_view_records();
            }
            lifecycle.drains.end(&id);
            owner.end_drain(fence);
            for (label, page) in pages {
                post_resume(&lifecycle, &poster, &label, page, &id);
            }
        };
        if wrote {
            tauri::async_runtime::spawn_blocking(release);
        } else {
            release();
        }
    }
}

pub(crate) struct Failure {
    pub refusal: Refusal,
    /// Kept held while native sheets ask; dropping it resumes.
    pub held: Option<Held>,
    /// Every window that failed or did not reply, by label.
    pub windows: Vec<String>,
}

/// Ordinary Quit after a failed drain: ask on each failed or timed-out window
/// in turn. Only an explicit discard on every one keeps the hold for exit; a
/// Keep open, missing window or failed prompt drops it, resuming them all.
pub(crate) async fn confirm_each<F, Asked>(failure: Box<Failure>, mut ask: F) -> bool
where
    F: FnMut(String) -> Asked,
    Asked: std::future::Future<Output = bool>,
{
    let Failure { held, windows, .. } = *failure;
    if windows.is_empty() {
        return false;
    }
    for label in windows {
        if !ask(label).await {
            return false;
        }
    }
    held.map(Held::keep).is_some()
}

/// Drain `targets` under one owner fence; see the module documentation.
pub(crate) async fn drain(
    owner: &Arc<Owner>,
    lifecycle: &Arc<Lifecycle>,
    poster: &Arc<dyn Poster>,
    scope: Scope,
    targets: Vec<Target>,
    reason: Reason,
    deadline: Instant,
) -> Result<Held, Box<Failure>> {
    let fence = match &scope {
        Scope::All => owner.begin_drain(),
        Scope::Window(label) => owner.begin_window_drain(label),
    }
    .map_err(|_| {
        Box::new(Failure {
            refusal: Refusal::Busy,
            held: None,
            windows: Vec::new(),
        })
    })?;
    let pages: Vec<_> = targets
        .iter()
        .filter_map(|t| t.page.map(|page| (t.label.clone(), page)))
        .collect();
    let (id, notify) = lifecycle.drains.begin(fence, reason, &pages);
    let held = Held {
        owner: Arc::clone(owner),
        lifecycle: Arc::clone(lifecycle),
        poster: Arc::clone(poster),
        id: id.clone(),
        fence,
        pages: pages.clone(),
        written: Vec::new(),
        kept: false,
    };
    // A surface with no bound note page (setup, loading, a dead page) has no
    // editor writing; fence it so it cannot start any while held. A failure
    // must not skip saving the other windows before Quit offers discard.
    let mut failed_surfaces = Vec::new();
    for target in targets.iter().filter(|t| t.page.is_none()) {
        let marked = {
            let owner = Arc::clone(owner);
            let label = target.label.clone();
            tauri::async_runtime::spawn_blocking(move || owner.mark_drained(&label, fence)).await
        };
        if !matches!(marked, Ok(Ok(_))) {
            failed_surfaces.push(target.label.clone());
        }
    }
    for (label, page) in &pages {
        let Some(token) = lifecycle.leases.start(label) else {
            // Its earlier eval is still outstanding: never stack another.
            lifecycle
                .drains
                .reply(label, *page, &id, Outcome::Stalled, None);
            continue;
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        let done_lifecycle = Arc::clone(lifecycle);
        let done_poster = Arc::clone(poster);
        let done_label = label.clone();
        let done_id = id.clone();
        let done_page = *page;
        let posted = poster.post(
            label,
            *page,
            drain_script(*page, &id, remaining, reason),
            Box::new(move |result| {
                if result.trim() != "\"accepted\"" {
                    done_lifecycle.drains.reply(
                        &done_label,
                        done_page,
                        &done_id,
                        Outcome::Failed,
                        None,
                    );
                }
                if let Some((page, id)) = done_lifecycle.leases.finish(&done_label, token) {
                    post_resume(&done_lifecycle, &done_poster, &done_label, page, &id);
                }
            }),
        );
        if !posted {
            lifecycle.leases.finish(label, token);
            lifecycle
                .drains
                .reply(label, *page, &id, Outcome::Failed, None);
        }
    }
    // A failure is reported only once no other window is still saving, so a
    // discard can never cut short writing that is about to be saved.
    loop {
        let notified = notify.notified();
        if lifecycle.drains.status(&id).is_none_or(|s| !s.waiting) {
            break;
        }
        if tokio::time::timeout_at(deadline.into(), notified)
            .await
            .is_err()
        {
            break; // still-waiting windows refuse as timed out
        }
    }
    let refused = match lifecycle.drains.status(&id) {
        None => Some((Refusal::NotSaved, failed_surfaces)),
        Some(status) if !failed_surfaces.is_empty() || !status.failed.is_empty() => {
            let mut windows = [failed_surfaces, status.failed, status.unanswered].concat();
            windows.sort();
            Some((Refusal::NotSaved, windows))
        }
        Some(status) if !status.unanswered.is_empty() => {
            Some((Refusal::TimedOut, status.unanswered))
        }
        Some(_) => None,
    };
    if let Some((refusal, windows)) = refused {
        return Err(Box::new(Failure {
            refusal,
            held: Some(held),
            windows,
        }));
    }
    Ok(held)
}

/// A page's drained reply. Only the current page token of a window this
/// drain waits on counts; the owner then fences that window's writing under
/// the note lease. Returns whether the reply was accepted (a refused page
/// resumes its own editing).
/// A page's drained reply as the command received it, with the window frame.
pub(crate) struct Drained<'a> {
    pub surface: &'a str,
    pub fence: &'a str,
    pub view: Option<CapturedView>,
    pub frame: Option<[f64; 4]>,
}
pub(crate) async fn accept_drained(
    owner: &Arc<Owner>,
    lifecycle: &Arc<Lifecycle>,
    label: &str,
    current_page: Option<u64>,
    reply: Drained<'_>,
) -> bool {
    let Drained {
        surface,
        fence: id,
        view,
        frame,
    } = reply;
    let Ok(page) = surface.parse::<u64>() else {
        return false;
    };
    if current_page != Some(page) {
        return false;
    }
    let Some((fence, reason)) = lifecycle.drains.accepts(label, page, id) else {
        return false;
    };
    let marked = {
        let owner = Arc::clone(owner);
        let label = label.to_owned();
        tauri::async_runtime::spawn_blocking(move || owner.mark_drained(&label, fence)).await
    };
    let Ok(Ok(key)) = marked else {
        lifecycle
            .drains
            .reply(label, page, id, Outcome::Failed, None);
        return false;
    };
    let record = restart_record(reason, key, view, frame);
    lifecycle
        .drains
        .reply(label, page, id, Outcome::Saved, record)
}
fn restart_record(
    reason: Reason,
    key: Option<(ContainerId, NoteKey)>,
    view: Option<CapturedView>,
    frame: Option<[f64; 4]>,
) -> Option<(ContainerId, ViewRecord)> {
    let (container, key) = key?;
    let view = view.filter(CapturedView::valid)?;
    let frame = frame.filter(|f| f.iter().all(|v| v.is_finite()))?;
    (reason != Reason::Close).then_some((
        container,
        ViewRecord {
            version: 1,
            key,
            anchor: view.anchor,
            head: view.head,
            cursor_offset: view.cursor_offset,
            frame,
        },
    ))
}
/// A page could not drain (save failed or its deadline passed).
pub(crate) fn drain_failed(
    lifecycle: &Lifecycle,
    label: &str,
    current_page: Option<u64>,
    surface: &str,
    id: &str,
) -> bool {
    let Ok(page) = surface.parse::<u64>() else {
        return false;
    };
    current_page == Some(page)
        && lifecycle
            .drains
            .reply(label, page, id, Outcome::Failed, None)
}

/// Replace every anchored container's restart records with this drain's
/// views (empty for a container with no window). On failure the hold drops:
/// windows resume and records already written by it are removed.
pub(crate) async fn write_records(owner: &Arc<Owner>, held: &mut Held) -> Result<(), Refusal> {
    let views = held.lifecycle.drains.views(&held.id);
    let databases = owner.anchored_databases();
    let written = tauri::async_runtime::spawn_blocking(move || {
        let mut written = Vec::new();
        for (id, database) in databases {
            let records: Vec<_> = views
                .iter()
                .filter(|(container, _)| *container == id)
                .map(|(_, record)| record.clone())
                .collect();
            let result = database
                .lock()
                .expect("container writer lock")
                .replace_view_records(&records);
            if result.is_err() {
                return Err(written);
            }
            written.push(database);
        }
        Ok(written)
    })
    .await
    .map_err(|_| Refusal::NotSaved)?;
    match written {
        Ok(written) => {
            held.written = written;
            Ok(())
        }
        Err(written) => {
            held.written = written;
            Err(Refusal::NotSaved)
        }
    }
}

/// Before an update drain: wait until no window has typed for `idle`. Only
/// local saves count, so peers' updates cannot hold it off.
pub(crate) async fn typing_idle(
    lifecycle: &Lifecycle,
    idle: Duration,
    deadline: Instant,
) -> Result<(), Refusal> {
    loop {
        let Some(quiet) = lifecycle.last_typed().map(|at| at + idle) else {
            return Ok(());
        };
        let now = Instant::now();
        if quiet <= now {
            return Ok(());
        }
        if quiet > deadline {
            tokio::time::sleep_until(deadline.into()).await;
            return Err(Refusal::TimedOut);
        }
        tokio::time::sleep_until(quiet.into()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_account::{
        AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount,
        crypto::{KemKey, SigningKey},
    };
    use bh_device::coordinator::{AuthoritySource, Scope as NoteScope};
    use tokio::sync::mpsc;

    struct Issuer(HashMap<String, NoteScope>);
    impl AuthoritySource for Issuer {
        fn bound_scope(&self, window: &str) -> Option<NoteScope> {
            self.0.get(window).copied()
        }
    }
    /// One verified test container with `windows` bound to and opening one note.
    fn container(
        owner: &Owner,
        dir: &std::path::Path,
        windows: &[&str],
    ) -> (ContainerId, std::path::PathBuf) {
        let control = SigningKey::generate();
        let keys = DevicePublicKeys::new(
            SigningKey::generate().public(),
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
        let path = dir.join(format!("{}.db", windows[0]));
        let mut db = DeviceDatabase::open(&path).unwrap();
        db.commit_account_verified(
            proof.id().0,
            &[signed.as_bytes()],
            proof.head().position,
            proof.head().hash,
            false,
        )
        .unwrap();
        let scope = NoteScope {
            account: proof.id().0,
            key: NoteKey {
                base: [1; 32],
                audience: [3; 32],
                note: [4; 32],
            },
        };
        let routes = windows.iter().map(|w| ((*w).to_owned(), scope)).collect();
        let id = owner
            .register(db, Some(&proof), Box::new(Issuer(routes)))
            .unwrap();
        for window in windows {
            owner.bind(window, id).unwrap();
            owner.open(window, [4; 32]).unwrap();
        }
        (id, path)
    }
    fn generation(owner: &Owner, window: &str) -> u64 {
        (1..10_000)
            .rev()
            .find(|g| owner.bound_work_key(window, *g).is_some())
            .expect("open generation")
    }
    fn commit(owner: &Owner, window: &str, request: u8) -> bool {
        owner
            .commit_queued(window, generation(owner, window), [request; 16], &[0, 0])
            .is_ok()
    }

    type Done = Box<dyn FnOnce(String) + Send>;
    /// Stands in for the real WebView poster: a drain request goes to the
    /// test as (label, page, drain id); the test plays the page's reply.
    #[derive(Default)]
    struct Pages {
        stall: Mutex<Vec<String>>,
        held_callbacks: Mutex<Vec<(String, Done)>>,
        posts: Mutex<Vec<(String, String)>>,
        requests: Mutex<Option<mpsc::UnboundedSender<(String, u64, String)>>>,
    }
    impl Poster for Pages {
        fn post(&self, label: &str, page: u64, script: String, done: Done) -> bool {
            self.posts
                .lock()
                .unwrap()
                .push((label.to_owned(), script.clone()));
            if self.stall.lock().unwrap().iter().any(|l| l == label) {
                self.held_callbacks
                    .lock()
                    .unwrap()
                    .push((label.to_owned(), done));
                return true;
            }
            done("\"accepted\"".into());
            if let Some(start) = script.find("fence:\"") {
                let id = script[start + 7..].split('"').next().unwrap().to_owned();
                if let Some(tx) = self.requests.lock().unwrap().as_ref() {
                    let _ = tx.send((label.to_owned(), page, id));
                }
            }
            true
        }
    }
    impl Pages {
        fn drains(&self, label: &str) -> usize {
            self.posts
                .lock()
                .unwrap()
                .iter()
                .filter(|(l, s)| l == label && s.contains("__bhDrain"))
                .count()
        }
        fn resumes(&self, label: &str) -> usize {
            self.posts
                .lock()
                .unwrap()
                .iter()
                .filter(|(l, s)| l == label && s.contains("__bhResumeEditing"))
                .count()
        }
    }
    struct Fixture {
        owner: Arc<Owner>,
        lifecycle: Arc<Lifecycle>,
        pages: Arc<Pages>,
        poster: Arc<dyn Poster>,
        _dir: tempfile::TempDir,
    }
    fn fixture(windows: &[&str]) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(Owner::default());
        container(&owner, dir.path(), windows);
        let pages = Arc::new(Pages::default());
        Fixture {
            owner,
            lifecycle: Arc::new(Lifecycle::default()),
            poster: Arc::clone(&pages) as Arc<dyn Poster>,
            pages,
            _dir: dir,
        }
    }
    fn targets(labels: &[&str]) -> Vec<Target> {
        labels
            .iter()
            .enumerate()
            .map(|(i, l)| Target {
                label: (*l).to_owned(),
                page: Some(10 + i as u64),
            })
            .collect()
    }
    /// The page side: every drain request is answered by `reply`.
    fn answer(f: &Fixture, reply: impl Fn(&str) -> Option<bool> + Send + 'static) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        *f.pages.requests.lock().unwrap() = Some(tx);
        let owner = Arc::clone(&f.owner);
        let lifecycle = Arc::clone(&f.lifecycle);
        tokio::spawn(async move {
            while let Some((label, page, id)) = rx.recv().await {
                match reply(&label) {
                    Some(true) => {
                        accept_drained(
                            &owner,
                            &lifecycle,
                            &label,
                            Some(page),
                            Drained {
                                surface: &page.to_string(),
                                fence: &id,
                                view: None,
                                frame: None,
                            },
                        )
                        .await;
                    }
                    Some(false) => {
                        drain_failed(&lifecycle, &label, Some(page), &page.to_string(), &id);
                    }
                    None => {}
                }
            }
        });
    }
    fn soon(ms: u64) -> Instant {
        Instant::now() + Duration::from_millis(ms)
    }

    #[test]
    fn replies_count_once_for_the_current_page_and_drain_and_name_no_window() {
        let owner = Owner::default();
        let fence = owner.begin_drain().unwrap();
        let drains = Drains::default();
        let (id, _) = drains.begin(fence, Reason::Quit, &[("secret-window".into(), 11)]);
        assert!(
            !drains.reply("secret-window", 12, &id, Outcome::Saved, None),
            "old page"
        );
        assert!(
            !drains.reply("secret-window", 11, "0", Outcome::Saved, None),
            "old drain"
        );
        assert!(drains.accepts("secret-window", 11, &id).is_some());
        assert!(drains.reply("secret-window", 11, &id, Outcome::Saved, None));
        assert!(
            !drains.reply("secret-window", 11, &id, Outcome::Failed, None),
            "once"
        );
        assert!(drains.accepts("secret-window", 11, &id).is_none());
        for refusal in [Refusal::Busy, Refusal::NotSaved, Refusal::TimedOut] {
            assert!(!format!("{refusal:?}").contains("secret"));
        }
    }

    #[tokio::test]
    async fn quit_drain_waits_for_every_window_then_fences_their_writing_until_dropped() {
        let f = fixture(&["writer", "reader"]);
        answer(&f, |_| Some(true));
        let held = drain(
            &f.owner,
            &f.lifecycle,
            &f.poster,
            Scope::All,
            targets(&["writer", "reader"]),
            Reason::Quit,
            soon(2000),
        )
        .await
        .ok()
        .expect("both drained");
        assert!(
            !commit(&f.owner, "writer", 1),
            "no native write after the reply"
        );
        assert!(
            f.owner.open("reader", [4; 32]).is_err(),
            "no new load while held"
        );
        drop(held);
        assert_eq!(
            (f.pages.resumes("writer"), f.pages.resumes("reader")),
            (1, 1)
        );
        assert!(commit(&f.owner, "writer", 1), "resumed windows write again");
    }

    #[tokio::test]
    async fn a_stalled_window_times_out_without_another_eval_and_resumes_once_on_its_callback() {
        let f = fixture(&["writer", "stalled"]);
        f.pages.stall.lock().unwrap().push("stalled".into());
        answer(&f, |_| Some(true));
        let failed = drain(
            &f.owner,
            &f.lifecycle,
            &f.poster,
            Scope::All,
            targets(&["writer", "stalled"]),
            Reason::Update,
            soon(500),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(failed.refusal, Refusal::TimedOut);
        assert_eq!(failed.windows, ["stalled"]);
        drop(failed);
        assert!(
            commit(&f.owner, "writer", 1),
            "a refusal never keeps others frozen"
        );
        // A retry waits for the outstanding eval instead of stacking another.
        for _ in 0..3 {
            let again = drain(
                &f.owner,
                &f.lifecycle,
                &f.poster,
                Scope::All,
                targets(&["writer", "stalled"]),
                Reason::Update,
                soon(2000),
            )
            .await
            .err()
            .unwrap();
            assert_eq!(again.refusal, Refusal::TimedOut);
        }
        assert_eq!(f.pages.drains("stalled"), 1);
        assert_eq!(f.pages.resumes("stalled"), 0);
        // Its late callback releases the lease and posts one deferred resume.
        let (_, done) = f.pages.held_callbacks.lock().unwrap().pop().unwrap();
        f.pages.stall.lock().unwrap().clear();
        done("\"accepted\"".into());
        assert_eq!(f.pages.resumes("stalled"), 1);
        assert!(!f.lifecycle.leases.outstanding("stalled"));
    }

    #[tokio::test]
    async fn a_late_reply_cannot_mark_or_answer_a_newer_drain() {
        let f = fixture(&["writer"]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        *f.pages.requests.lock().unwrap() = Some(tx);
        let first = drain(
            &f.owner,
            &f.lifecycle,
            &f.poster,
            Scope::All,
            targets(&["writer"]),
            Reason::Quit,
            soon(50),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(first.refusal, Refusal::TimedOut);
        drop(first);
        let (_, page, old) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a drain request")
            .unwrap();
        let next = {
            let (owner, lifecycle, poster) = (
                Arc::clone(&f.owner),
                Arc::clone(&f.lifecycle),
                Arc::clone(&f.poster),
            );
            tokio::spawn(async move {
                drain(
                    &owner,
                    &lifecycle,
                    &poster,
                    Scope::All,
                    targets(&["writer"]),
                    Reason::Quit,
                    soon(2000),
                )
                .await
                .ok()
            })
        };
        let (_, _, current) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a drain request")
            .unwrap();
        assert!(
            !accept_drained(
                &f.owner,
                &f.lifecycle,
                "writer",
                Some(page),
                Drained {
                    surface: &page.to_string(),
                    fence: &old,
                    view: None,
                    frame: None
                }
            )
            .await
        );
        assert!(
            commit(&f.owner, "writer", 1),
            "the stale reply fenced nothing"
        );
        assert!(
            !accept_drained(
                &f.owner,
                &f.lifecycle,
                "writer",
                Some(page + 1),
                Drained {
                    surface: &page.to_string(),
                    fence: &current,
                    view: None,
                    frame: None
                }
            )
            .await,
            "another page"
        );
        assert!(
            accept_drained(
                &f.owner,
                &f.lifecycle,
                "writer",
                Some(page),
                Drained {
                    surface: &page.to_string(),
                    fence: &current,
                    view: None,
                    frame: None
                }
            )
            .await
        );
        let held = next
            .await
            .unwrap()
            .expect("current reply completes the drain");
        assert!(!commit(&f.owner, "writer", 2));
        drop(held);
    }

    #[tokio::test]
    async fn a_failed_save_keeps_its_window_held_for_the_sheet_until_dropped() {
        let f = fixture(&["writer", "reader"]);
        answer(&f, |label| Some(label != "reader"));
        let failed = drain(
            &f.owner,
            &f.lifecycle,
            &f.poster,
            Scope::All,
            targets(&["writer", "reader"]),
            Reason::Quit,
            soon(2000),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(failed.refusal, Refusal::NotSaved);
        assert_eq!(failed.windows, ["reader"]);
        assert!(
            f.owner.open("reader", [4; 32]).is_err(),
            "held while the sheet asks"
        );
        let busy = drain(
            &f.owner,
            &f.lifecycle,
            &f.poster,
            Scope::Window("reader".into()),
            targets(&["reader"]),
            Reason::Close,
            soon(100),
        )
        .await
        .err()
        .unwrap();
        assert!(busy.refusal == Refusal::Busy && busy.held.is_none());
        drop(failed);
        f.owner.open("reader", [4; 32]).unwrap();
    }

    #[tokio::test]
    async fn a_failure_waits_for_every_other_window_before_anyone_is_asked_to_discard() {
        let f = fixture(&["failing", "slow"]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        *f.pages.requests.lock().unwrap() = Some(tx);
        let (owner, lifecycle) = (Arc::clone(&f.owner), Arc::clone(&f.lifecycle));
        tokio::spawn(async move {
            while let Some((label, page, id)) = rx.recv().await {
                let surface = page.to_string();
                if label == "failing" {
                    drain_failed(&lifecycle, &label, Some(page), &surface, &id);
                } else {
                    // The other window is still saving when the first fails.
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    let reply = Drained {
                        surface: &surface,
                        fence: &id,
                        view: None,
                        frame: None,
                    };
                    accept_drained(&owner, &lifecycle, &label, Some(page), reply).await;
                }
            }
        });
        let started = Instant::now();
        let failed = drain(
            &f.owner,
            &f.lifecycle,
            &f.poster,
            Scope::All,
            targets(&["failing", "slow"]),
            Reason::Quit,
            soon(3000),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(failed.refusal, Refusal::NotSaved);
        assert_eq!(failed.windows, ["failing"]);
        assert!(
            started.elapsed() >= Duration::from_millis(140),
            "the other window finished saving first"
        );
        assert!(!commit(&f.owner, "slow", 1), "and was fenced as drained");
        drop(failed);
    }

    /// Two windows fail to save while a third is still saving.
    async fn two_failures(f: &Fixture) -> Box<Failure> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        *f.pages.requests.lock().unwrap() = Some(tx);
        let (owner, lifecycle) = (Arc::clone(&f.owner), Arc::clone(&f.lifecycle));
        tokio::spawn(async move {
            while let Some((label, page, id)) = rx.recv().await {
                let surface = page.to_string();
                if label == "slow" {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let reply = Drained {
                        surface: &surface,
                        fence: &id,
                        view: None,
                        frame: None,
                    };
                    accept_drained(&owner, &lifecycle, &label, Some(page), reply).await;
                } else {
                    drain_failed(&lifecycle, &label, Some(page), &surface, &id);
                }
            }
        });
        drain(
            &f.owner,
            &f.lifecycle,
            &f.poster,
            Scope::All,
            targets(&["a", "b", "slow"]),
            Reason::Quit,
            soon(3000),
        )
        .await
        .err()
        .unwrap()
    }

    #[tokio::test]
    async fn quit_asks_on_every_failed_window_and_one_keep_open_resumes_them_all() {
        let f = fixture(&["a", "b", "slow"]);
        let failed = two_failures(&f).await;
        assert_eq!(failed.refusal, Refusal::NotSaved);
        assert_eq!(failed.windows, ["a", "b"]);
        let asked = Arc::new(Mutex::new(Vec::new()));
        let quit = {
            let (owner, asked) = (Arc::clone(&f.owner), Arc::clone(&asked));
            confirm_each(failed, move |label: String| {
                // The saving window finished before anyone was asked.
                assert!(!commit(&owner, "slow", 1));
                asked.lock().unwrap().push(label.clone());
                async move { label == "a" }
            })
            .await
        };
        assert!(!quit, "Keep open on b cancels the whole Quit");
        assert_eq!(*asked.lock().unwrap(), ["a", "b"]);
        for window in ["a", "b", "slow"] {
            assert_eq!(f.pages.resumes(window), 1, "{window} resumed");
            assert!(commit(&f.owner, window, 2), "{window} writes again");
        }
        // Only a discard on every affected window lets Quit go ahead.
        let failed = two_failures(&f).await;
        assert!(confirm_each(failed, |_| async { true }).await);
        for window in ["a", "b", "slow"] {
            assert_eq!(f.pages.resumes(window), 1, "{window} still held for exit");
        }
        assert!(!commit(&f.owner, "slow", 3), "its drained fence is kept");
        assert!(f.owner.begin_drain().is_err(), "and so is the hold");
    }

    #[tokio::test]
    async fn a_failure_names_every_failed_and_timed_out_window() {
        let f = fixture(&["failing", "saved", "stalled"]);
        f.pages.stall.lock().unwrap().push("stalled".into());
        answer(&f, |label| Some(label != "failing"));
        let failed = drain(
            &f.owner,
            &f.lifecycle,
            &f.poster,
            Scope::All,
            targets(&["stalled", "saved", "failing"]),
            Reason::Quit,
            soon(1000),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(failed.refusal, Refusal::NotSaved);
        assert_eq!(failed.windows, ["failing", "stalled"]);
    }

    #[tokio::test]
    async fn a_missing_window_or_failed_prompt_is_never_consent() {
        let f = fixture(&["a", "b", "slow"]);
        let failed = two_failures(&f).await;
        let asked = Arc::new(Mutex::new(0));
        let counted = Arc::clone(&asked);
        let quit = confirm_each(failed, move |_| {
            *counted.lock().unwrap() += 1;
            async { false }
        })
        .await;
        assert!(!quit);
        assert_eq!(*asked.lock().unwrap(), 1, "stops at the first refusal");
        assert!(commit(&f.owner, "b", 1), "all resumed");
        let none = Box::new(Failure {
            refusal: Refusal::NotSaved,
            held: None,
            windows: Vec::new(),
        });
        assert!(
            !confirm_each(none, |_| async { true }).await,
            "no one asked"
        );
    }

    #[tokio::test]
    async fn a_vanished_page_fails_its_drain_at_once() {
        let f = fixture(&["writer"]);
        f.pages.stall.lock().unwrap().push("writer".into());
        let lifecycle = Arc::clone(&f.lifecycle);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            lifecycle.drains.page_gone("writer");
        });
        let started = Instant::now();
        let failed = drain(
            &f.owner,
            &f.lifecycle,
            &f.poster,
            Scope::All,
            targets(&["writer"]),
            Reason::Quit,
            soon(5000),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(failed.refusal, Refusal::NotSaved);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn a_pageless_mark_failure_waits_for_other_windows_to_save_before_quit_refuses() {
        let f = fixture(&["writer"]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        *f.pages.requests.lock().unwrap() = Some(tx);
        let (owner, lifecycle) = (Arc::clone(&f.owner), Arc::clone(&f.lifecycle));
        tokio::spawn(async move {
            let (label, page, id) = rx.recv().await.expect("writer drain requested");
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert!(
                accept_drained(
                    &owner,
                    &lifecycle,
                    &label,
                    Some(page),
                    Drained {
                        surface: &page.to_string(),
                        fence: &id,
                        view: None,
                        frame: None,
                    },
                )
                .await
            );
        });
        let started = Instant::now();
        let failed = drain(
            &f.owner,
            &f.lifecycle,
            &f.poster,
            Scope::Window("writer".into()),
            vec![
                Target {
                    label: "missing".into(),
                    page: None,
                },
                Target {
                    label: "writer".into(),
                    page: Some(11),
                },
            ],
            Reason::Quit,
            soon(3000),
        )
        .await
        .err()
        .expect("missing surface refused");
        assert_eq!(failed.refusal, Refusal::NotSaved);
        assert_eq!(failed.windows, ["missing"]);
        assert!(started.elapsed() >= Duration::from_millis(140));
        assert_eq!(f.pages.drains("writer"), 1);
        assert!(
            !commit(&f.owner, "writer", 1),
            "other window saved and is fenced"
        );
        drop(failed);
        assert!(commit(&f.owner, "writer", 2), "refusal releases the hold");
    }

    #[tokio::test]
    async fn a_surface_without_a_note_page_is_fenced_without_an_eval() {
        let f = fixture(&["writer"]);
        let held = drain(
            &f.owner,
            &f.lifecycle,
            &f.poster,
            Scope::All,
            vec![Target {
                label: "writer".into(),
                page: None,
            }],
            Reason::Quit,
            soon(1000),
        )
        .await
        .ok()
        .unwrap();
        assert_eq!(f.pages.drains("writer"), 0);
        assert!(!commit(&f.owner, "writer", 1));
        drop(held);
        assert!(commit(&f.owner, "writer", 1));
    }

    #[tokio::test]
    async fn failing_restart_records_refuse_and_remove_only_what_this_drain_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(Owner::default());
        let paths: HashMap<_, _> = [
            container(&owner, dir.path(), &["a"]),
            container(&owner, dir.path(), &["b"]),
        ]
        .into_iter()
        .collect();
        let databases = owner.anchored_databases();
        let (first, second) = (databases[0].0, databases[1].0);
        let count = |id: ContainerId| -> i64 {
            rusqlite::Connection::open(&paths[&id])
                .unwrap()
                .query_row("SELECT count(*) FROM view_records", [], |row| row.get(0))
                .unwrap()
        };
        let pages = Arc::new(Pages::default());
        let poster: Arc<dyn Poster> = Arc::clone(&pages) as _;
        let lifecycle = Arc::new(Lifecycle::default());
        let mut held = drain(
            &owner,
            &lifecycle,
            &poster,
            Scope::All,
            Vec::new(),
            Reason::Update,
            soon(1000),
        )
        .await
        .ok()
        .unwrap();
        let record = ViewRecord {
            version: 1,
            key: NoteKey {
                base: [1; 32],
                audience: [0; 32],
                note: [4; 32],
            },
            anchor: vec![1, 2],
            head: vec![3],
            cursor_offset: 0.0,
            frame: [0.0, 0.0, 800.0, 600.0],
        };
        lifecycle
            .drains
            .ops
            .lock()
            .unwrap()
            .get_mut(&held.id)
            .unwrap()
            .views
            .push(("main".into(), first, record));
        // The second container's write fails after the first one's succeeded.
        rusqlite::Connection::open(&paths[&second])
            .unwrap()
            .execute_batch("DROP TABLE view_records")
            .unwrap();
        assert_eq!(
            write_records(&owner, &mut held).await,
            Err(Refusal::NotSaved)
        );
        assert_eq!(count(first), 1, "written before the failure");
        drop(held);
        for _ in 0..200 {
            if let Ok(fence) = owner.begin_drain() {
                owner.end_drain(fence);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(count(first), 0, "its own record is removed with the hold");
    }

    #[tokio::test]
    async fn an_update_waits_for_typing_to_pause_but_not_forever() {
        let lifecycle = Arc::new(Lifecycle::default());
        typing_idle(&lifecycle, Duration::from_millis(50), soon(1000))
            .await
            .unwrap();
        lifecycle.typed();
        let started = Instant::now();
        typing_idle(&lifecycle, Duration::from_millis(50), soon(1000))
            .await
            .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(45));
        let typing = Arc::clone(&lifecycle);
        let typist = tokio::spawn(async move {
            for _ in 0..40 {
                typing.typed();
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert_eq!(
            typing_idle(&lifecycle, Duration::from_millis(50), soon(150)).await,
            Err(Refusal::TimedOut)
        );
        typist.abort();
    }

    #[test]
    fn restart_records_need_an_ordinary_key_a_valid_view_and_quit_or_update() {
        let key = Some((
            ContainerId([1; 16]),
            NoteKey {
                base: [1; 32],
                audience: [0; 32],
                note: [2; 32],
            },
        ));
        let view = CapturedView {
            version: 1,
            anchor: vec![1; 1024],
            head: vec![2],
            cursor_offset: 33.0,
        };
        let frame = Some([1.0, 2.0, 800.0, 600.0]);
        let record = restart_record(Reason::Quit, key, Some(view.clone()), frame)
            .unwrap()
            .1;
        assert_eq!(
            (record.anchor.len(), record.cursor_offset, record.frame),
            (1024, 33.0, [1.0, 2.0, 800.0, 600.0])
        );
        assert!(restart_record(Reason::Close, key, Some(view.clone()), frame).is_none());
        assert!(
            restart_record(Reason::Update, None, Some(view.clone()), frame).is_none(),
            "hidden or fixture scope"
        );
        let oversized = CapturedView {
            anchor: vec![0; 1025],
            ..view.clone()
        };
        assert!(restart_record(Reason::Update, key, Some(oversized), frame).is_none());
        // The cursor may sit above the visible area; only an unbounded or
        // non-finite offset is refused.
        let above = CapturedView {
            cursor_offset: -120.5,
            ..view.clone()
        };
        let record = restart_record(Reason::Update, key, Some(above), frame).unwrap();
        assert_eq!(record.1.cursor_offset, -120.5);
        for bad in [f64::NAN, f64::INFINITY, -2e7, 2e7] {
            let bad = CapturedView {
                cursor_offset: bad,
                ..view.clone()
            };
            assert!(restart_record(Reason::Update, key, Some(bad), frame).is_none());
        }
        assert!(
            restart_record(
                Reason::Update,
                key,
                Some(view),
                Some([f64::NAN, 0.0, 1.0, 1.0])
            )
            .is_none()
        );
    }
}
