//! Your devices: the account's active devices as this device verified them,
//! what each may do to them now, the security alerts kept here, and what the
//! host remembers of the account directory.
//!
//! Every time a choice depends on is the latest home time this device
//! verified (its accepted-head floor and its newest stored confirmation's
//! `earliest_ms`), never the device clock: a clock set ahead cannot make a
//! device look mature or a removal look due.
//!
//! Names come from directory `DeviceName` entries each device signs for
//! itself; this device's is the model name the app gives the host. They are
//! read when the view opens and after an addition is followed, and kept in
//! memory only.
use std::collections::{BTreeMap, HashMap, HashSet};

use bh_account::{
    AccountChange, AccountEvent, DeviceId, DeviceState, REMOVAL_WAIT_MS, VerifiedAccount,
    recovery::{Password, PasswordCheck, RecoveryCode, RecoveryKeys},
};
use bh_device::ContainerId;
use bh_storage::{AlertKind, DeviceDatabase, StoredAlert};
use serde::Serialize;

use crate::{
    accounts::{AccountOperation, HostKeyStore, Screen, SharedAccountHost},
    sync::{StageRefused, SyncHandle, SyncHost, TrustControl},
};
use bh_account::journal::PendingSetupProtector;
use bh_sync_client::{Ordered, OrderedControl, RecoverError, RemovalVerdict};
use tokio::sync::watch;

/// What Your devices shows. No key, account id or container id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DevicesView {
    /// This build's removal wait; every duration in the copy uses it.
    pub wait_ms: u64,
    pub devices: Vec<DeviceItem>,
    /// Every alert kept on this device, newest first.
    pub alerts: Vec<AlertItem>,
    /// Changing the password needs the recovery kit too: no password check
    /// for the current recovery record was found.
    pub password_change_needs_kit: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceItem {
    pub id_hex: String,
    /// The name the device gave itself; `None` until one is read, when the
    /// app shows its kind and added date.
    pub name: Option<String>,
    pub this_device: bool,
    /// When it was added, by home time; `None` for history kept untimed.
    pub added_ms: Option<u64>,
    pub pending: Option<PendingItem>,
    /// This device staged its removal and history has not ordered it yet:
    /// submitting, across restarts too.
    pub submitting: bool,
    /// Remove it (this device: remove this device).
    pub can_remove: bool,
    /// Remove it at once with the recovery kit: this device has been in the
    /// account for the removal wait, by home time.
    pub can_remove_now: bool,
    /// Cancel its pending removal: this device is mature and not its target.
    pub can_cancel: bool,
}

/// A pending removal: when it takes effect and who asked for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PendingItem {
    pub request: u64,
    pub deadline_ms: u64,
    /// The requesting device's name; `None` for one with no name read yet,
    /// or a request signed with the recovery key.
    pub requested_by: Option<String>,
}

/// One security alert, with the names of the devices it is about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AlertItem {
    /// Stable within this container: tells a delivered alert from a new one.
    pub id: i64,
    pub kind: &'static str,
    pub subject_name: Option<String>,
    pub actor_name: Option<String>,
    pub time_ms: Option<u64>,
    pub deadline_ms: Option<u64>,
}

/// Native-only delivery context; the DevicesView alert JSON stays account-local.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveredAlert {
    pub container: ContainerId,
    pub alert: AlertItem,
}

impl std::ops::Deref for DeliveredAlert {
    type Target = AlertItem;

    fn deref(&self) -> &Self::Target {
        &self.alert
    }
}

fn kind_name(kind: AlertKind) -> &'static str {
    match kind {
        AlertKind::DeviceAddedByQr => "device_added_by_qr",
        AlertKind::DeviceAddedByKit => "device_added_by_kit",
        AlertKind::KitUsed => "kit_used",
        AlertKind::RemovalRequested => "removal_requested",
        AlertKind::RemovalCancelled => "removal_cancelled",
        AlertKind::RemovalEffective => "removal_effective",
        AlertKind::KitChanged => "kit_changed",
        AlertKind::RefusedChange => "refused_change",
        AlertKind::KitNotChanged => "kit_not_changed",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A password check and the recovery record it belongs with.
pub(crate) struct HeldCheck {
    pub check: PasswordCheck,
    pub record_digest: [u8; 32],
    /// A new password's check is never written under the personal key the
    /// old kit could open: only under the key rotated in after it.
    pub not_under: Option<[u8; 32]>,
}

/// What the host remembers of one account's directory, in memory only.
#[derive(Default)]
pub(crate) struct Known {
    /// Each active device's name, as the last read found it.
    pub names: BTreeMap<DeviceId, String>,
    pub check: Option<HeldCheck>,
    /// A read finished since this account opened.
    pub read: bool,
    /// The host asked for a read that the client has not taken yet.
    pub wanted: bool,
    /// Own entries the home is known to hold, by (subject, personal key):
    /// `NAME` or `CHECK`, and the hash of the key they are sealed to.
    pub written: HashSet<(u8, [u8; 32])>,
    /// Reads finished since this account opened.
    pub reads: u64,
    /// Own entries handed to the client to write, by entry id.
    pub writing: HashMap<[u8; 32], (u8, [u8; 32])>,
    /// Alerts wait for a read of the names they need.
    pub naming: Naming,
    /// A recovery replacement was lost or refused while its new kit
    /// showed: saving that kit reports it unchanged.
    pub kit_not_changed: bool,
}

/// Where alerts naming a device with no name read this run stand.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Naming {
    #[default]
    Idle,
    /// A read was asked for them; they wait for it.
    Asked,
    /// It finished or failed: they go out with whatever names it found.
    Answered,
}

pub(crate) const NAME: u8 = 0;
pub(crate) const CHECK: u8 = 1;

impl Known {
    /// The check for `record`, if this device holds it.
    pub fn check_for(&self, record: [u8; 32]) -> Option<&PasswordCheck> {
        self.check
            .as_ref()
            .filter(|held| held.record_digest == record)
            .map(|held| &held.check)
    }
}

/// A copy of `check` (it is not `Clone`: it is secret).
pub(crate) fn copy_check(check: &PasswordCheck) -> PasswordCheck {
    PasswordCheck::decode(check.encode().expose()).expect("an encoded check decodes")
}

/// Whether `password` matches `check`, on this device alone.
pub(crate) fn password_matches(check: &PasswordCheck, password: &str) -> bool {
    Password::new(password)
        .ok()
        .is_some_and(|password| bh_account::recovery::verify_password(check, &password).is_ok())
}

/// The latest home time this device verified: its accepted-head floor and
/// the confirmation of its verified head. Never the device clock.
pub(crate) fn home_time(database: &DeviceDatabase, account: &VerifiedAccount) -> u64 {
    let floor = database
        .observed_account_floor()
        .ok()
        .flatten()
        .unwrap_or(0);
    let confirmed = database
        .confirmation(account.head().position)
        .ok()
        .flatten()
        .map_or(0, |row| row.earliest_ms);
    floor.max(confirmed)
}

/// The device a staged removal control removes: its target, or this
/// device for its own.
pub(crate) fn submitting(staged: &[u8]) -> Option<DeviceId> {
    match AccountEvent::decode(staged).ok()?.change() {
        AccountChange::RemovalRequested { target, .. } => Some(target),
        AccountChange::DeviceRemovedSelf { device } => Some(device),
        AccountChange::RemovedNow { target, .. } => Some(target),
        _ => None,
    }
}

/// The view of `account` for device `this` at home time `home_ms`, with
/// the removal this device staged, if any, `submitting`.
pub(crate) fn build(
    account: &VerifiedAccount,
    this: DeviceId,
    home_ms: u64,
    names: &BTreeMap<DeviceId, String>,
    alerts: &[StoredAlert],
    password_change_needs_kit: bool,
    submitting: Option<DeviceId>,
) -> DevicesView {
    let mature = account.is_mature(this, home_ms);
    let pending = account.pending_removals(home_ms);
    let named = |id: DeviceId| names.get(&id).cloned();
    let mut devices: Vec<DeviceItem> = account
        .active_devices()
        .map(|devices| devices.map(|keys| keys.id()).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|id| {
            let state = account.device_state(id, home_ms).ok()?;
            let pending = match state {
                DeviceState::Removed => return None,
                DeviceState::Active => None,
                DeviceState::RemovalPending {
                    request,
                    deadline_ms,
                } => Some(PendingItem {
                    request,
                    deadline_ms,
                    requested_by: pending
                        .iter()
                        .find(|p| p.request == request)
                        .and_then(|p| p.by)
                        .and_then(named),
                }),
            };
            let this_device = id == this;
            let submitting = submitting == Some(id);
            Some(DeviceItem {
                id_hex: hex(&id.0),
                name: named(id),
                this_device,
                added_ms: account.added_at(id),
                submitting,
                can_remove: !submitting && (this_device || pending.is_none()),
                can_remove_now: !this_device && mature,
                can_cancel: !this_device && mature && pending.is_some(),
                pending,
            })
        })
        .collect();
    // This device first, then the others as they were added.
    devices.sort_by_key(|item| (!item.this_device, item.added_ms));
    DevicesView {
        wait_ms: REMOVAL_WAIT_MS,
        devices,
        alerts: alerts
            .iter()
            .map(|alert| alert_item(alert, names, this))
            .collect(),
        password_change_needs_kit,
    }
}

fn alert_item(
    alert: &StoredAlert,
    names: &BTreeMap<DeviceId, String>,
    this: DeviceId,
) -> AlertItem {
    let named = |id: Option<[u8; 32]>| id.and_then(|id| names.get(&DeviceId(id)).cloned());
    AlertItem {
        id: alert.id,
        kind: kind_name(alert.kind),
        subject_name: named(alert.subject),
        // Before our directory name arrives, use the same fallback that Your
        // devices shows for its own unnamed row, not "another device".
        actor_name: named(alert.actor)
            .or_else(|| (alert.actor == Some(this.0)).then(|| "Device".into())),
        time_ms: alert.time_ms,
        deadline_ms: alert.deadline_ms,
    }
}

fn delivered_alert(
    container: ContainerId,
    alert: &StoredAlert,
    names: &BTreeMap<DeviceId, String>,
    this: DeviceId,
) -> DeliveredAlert {
    DeliveredAlert {
        container,
        alert: alert_item(alert, names, this),
    }
}

/// How many kept alerts the list shows.
const LISTED_ALERTS: usize = 200;

/// Errors `run` gives, beside `not permitted`, `sync unavailable` and
/// `account unavailable`: a confirmation refused or failed; another control
/// staged and not settled yet (nothing was asked); history did not take the
/// control; a new password this build cannot take; a changed kit's
/// replacement lost or refused, so the kit in use did not change; what the
/// home released for a password and kit does not verify.
const NOT_SIGNED: &str = "not signed";
const BUSY: &str = "busy";
const NOT_ACCEPTED: &str = "not accepted";
const INVALID_PASSWORD: &str = "invalid password";
const KIT_NOT_CHANGED: &str = "kit not changed";
/// What the home released for a password and kit does not verify.
const NOT_VERIFIED: &str = "not verified";

/// What a recovery or a kit check shows for the home's answer. Until an
/// admission snapshot can be read, a base whose key changed since its
/// genesis waits as unreachable, its progress kept. What the home released
/// and does not verify is an error, never asked again unseen.
pub(crate) fn recover_refused(error: RecoverError) -> Result<Screen, &'static str> {
    let refused = |reason, tries_left, next_try_ms| {
        Ok(Screen::RecoverRefused {
            reason,
            tries_left,
            next_try_ms,
        })
    };
    match error {
        RecoverError::NotRecognised => refused("not_recognised", None, None),
        RecoverError::PasswordMismatch {
            tries_left,
            next_try_ms,
        } => refused("password", Some(tries_left), next_try_ms),
        RecoverError::Wait { next_try_ms } => refused("wait", None, Some(next_try_ms)),
        RecoverError::Unreachable | RecoverError::AwaitingAdmission => {
            refused("unreachable", None, None)
        }
        RecoverError::Invalid => Err(NOT_VERIFIED),
    }
}

fn refused(refusal: StageRefused) -> &'static str {
    match refusal {
        StageRefused::Busy => BUSY,
        StageRefused::NotSigned => NOT_SIGNED,
    }
}

/// The trust lane's settlements, from now on: subscribed before a control
/// is staged, so its own is not missed.
fn settlements(handle: &SyncHandle) -> watch::Receiver<Option<OrderedControl>> {
    let mut settled = handle.client.trust();
    settled.borrow_and_update();
    settled
}

/// How verified history settles the control of `kind` staged for account
/// position `position`; an error once the account's sync stops.
async fn settled(
    handle: &SyncHandle,
    settled: &mut watch::Receiver<Option<OrderedControl>>,
    kind: u8,
    position: u64,
) -> Result<Ordered, &'static str> {
    let mut stopping = handle.stopping.clone();
    loop {
        tokio::select! {
            changed = settled.changed() => changed.map_err(|_| "sync unavailable")?,
            _ = stopping.wait_for(|stopped| *stopped) => return Err("sync unavailable"),
        }
        let Some(ordered) = *settled.borrow_and_update() else {
            continue;
        };
        if ordered.position == position && ordered.kind == kind {
            return Ok(ordered.outcome);
        }
    }
}

/// Run `operation` on Your devices for the routed ready account. Each one
/// is checked against verified history at home time before any prompt or
/// request; a control is then signed with the second key (one confirmation
/// covers it and its copy into the own base), staged, and followed until
/// the account's history settles it. While another control is staged,
/// none is asked for (`busy`).
///
/// - `RequestRemoval`: `Ready` once ordered; its deadline is the order's
///   confirmed `latest_ms` plus the wait, unchanged by a lost answer.
/// - `CancelRemoval`: `Ready` once ordered in time, `CancelTookEffect` when
///   the removal had already taken effect, never a success.
/// - `RemoveNow`: only from a device in the account for the wait; the home
///   checks the password and kit first (its refusal is `RecoverRefused`, as
///   recovery shows it, and nothing is asked of the person), then one
///   confirmation; `Ready` once ordered, the device removed at once.
/// - `RemoveSelf`: sends unsent work first unless `without_sync`, then the
///   verified removal erases the account here: `Erased` or
///   `EraseIncomplete`. Lost or refused, `not accepted`.
/// - `ChangePassword`: with no password check for the current record, the
///   kit too (`needs kit` without it), checked by the home as `RemoveNow`'s
///   is; then `NewKit`, its replacement kept until `ConfirmNewKit`
///   says the kit is saved; then `Ready` once history takes the
///   replacement (at once while no sync runs: it sends it when it starts),
///   and `kit not changed` when it is lost or refused.
pub async fn run<S, P>(
    accounts: &SharedAccountHost<S, P>,
    sync: &SyncHost,
    operation: AccountOperation,
) -> Result<Screen, &'static str>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    if matches!(operation, AccountOperation::ConfirmNewKit) {
        return confirm_new_kit(accounts, sync).await;
    }
    let (id, this, account) = routed(accounts, sync).ok_or("account unavailable")?;
    let home_ms = {
        let database = accounts.database(id).ok_or("account unavailable")?;
        let database = database.lock().map_err(|_| "account unavailable")?;
        home_time(&database, &account)
    };
    let control = match operation {
        AccountOperation::RequestRemoval { device } => {
            let target = DeviceId(device);
            if target == this || account.device_state(target, home_ms) != Ok(DeviceState::Active) {
                return Err("not permitted");
            }
            TrustControl::RequestRemoval(target)
        }
        AccountOperation::CancelRemoval { request } => {
            // No device cancels its own removal, and only a mature one may.
            let pending = account
                .pending_removals(home_ms)
                .into_iter()
                .find(|p| p.request == request)
                .ok_or("not permitted")?;
            if pending.target == this || !account.is_mature(this, home_ms) {
                return Err("not permitted");
            }
            TrustControl::Cancel(request)
        }
        AccountOperation::RemoveNow {
            device,
            password,
            code,
        } => {
            // Only a device in the account for the wait, by home time,
            // removes another at once: checked before the kit or a prompt.
            let target = DeviceId(device);
            let removable = matches!(
                account.device_state(target, home_ms),
                Ok(DeviceState::Active | DeviceState::RemovalPending { .. })
            );
            if target == this || !removable || !account.is_mature(this, home_ms) {
                return Err("not permitted");
            }
            return remove_now(accounts, sync, id, target, &password, &code).await;
        }
        AccountOperation::RemoveSelf { without_sync } => {
            return remove_self(accounts, sync, id, without_sync).await;
        }
        AccountOperation::ChangePassword { current, new, code } => {
            return change_password(accounts, sync, id, &account, current, new, code).await;
        }
        _ => return Err("not a devices operation"),
    };
    let handle = sync.handle(id).ok_or("sync unavailable")?;
    let mut following = settlements(&handle);
    let position = handle.ops.stage_control(control).await.map_err(refused)?;
    handle.client.wake();
    match settled(&handle, &mut following, control.kind(), position).await? {
        Ordered::Accepted { .. } => Ok(Screen::Ready),
        Ordered::CancelTookEffect => Ok(Screen::CancelTookEffect),
        Ordered::Lost | Ordered::Refused => Err(NOT_ACCEPTED),
    }
}

/// Remove `target` at once with the password and kit: the home checks them
/// and releases the recovery keys, which sign their half; this device's
/// second key signs its own; history then removes `target` at once.
async fn remove_now<S, P>(
    accounts: &SharedAccountHost<S, P>,
    sync: &SyncHost,
    id: ContainerId,
    target: DeviceId,
    password: &str,
    code: &str,
) -> Result<Screen, &'static str>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    let handle = sync.handle(id).ok_or("sync unavailable")?;
    let keys = match kit_keys(accounts, &handle, id, password, code).await? {
        Ok(keys) => keys,
        Err(refused) => return Ok(refused),
    };
    let mut following = settlements(&handle);
    let position = handle.ops.remove_now(target, keys).await.map_err(refused)?;
    handle.client.wake();
    match settled(&handle, &mut following, REMOVE_NOW, position).await? {
        Ordered::Accepted { .. } => Ok(Screen::Ready),
        _ => Err(NOT_ACCEPTED),
    }
}

/// The account's current recovery keys for `password` and kit `code`, from
/// the home's check (a wrong password uses a try), or the screen of its
/// refusal. An invalid password, or another control staged, asks nothing.
async fn kit_keys<S, P>(
    accounts: &SharedAccountHost<S, P>,
    handle: &SyncHandle,
    id: ContainerId,
    password: &str,
    code: &str,
) -> Result<Result<RecoveryKeys, Screen>, &'static str>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone,
{
    let password = Password::new(password).map_err(|_| INVALID_PASSWORD)?;
    let Ok(code) = RecoveryCode::from_kit_text(code) else {
        return recover_refused(RecoverError::NotRecognised).map(Err);
    };
    let staged = {
        let database = accounts.database(id).ok_or("account unavailable")?;
        let database = database.lock().map_err(|_| "account unavailable")?;
        database
            .staged_account_control()
            .map_err(|_| "account unavailable")?
    };
    if staged.is_some() {
        return Err(BUSY);
    }
    match handle.client.recovery_keys(&password, &code).await {
        Ok(keys) => Ok(Ok(keys)),
        Err(error) => recover_refused(error).map(Err),
    }
}

/// Remove this device: send unsent work first unless `without_sync`, then
/// stage the removal and wait for the erasure its verified order brings.
/// Lost or refused, it fails at once rather than waiting.
async fn remove_self<S, P>(
    accounts: &SharedAccountHost<S, P>,
    sync: &SyncHost,
    id: ContainerId,
    without_sync: bool,
) -> Result<Screen, &'static str>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    let handle = sync.handle(id).ok_or("sync unavailable")?;
    if !without_sync {
        let mut stopping = handle.stopping.clone();
        tokio::select! {
            sent = sync.sent(id) => if !sent { return Err("sync unavailable") },
            _ = stopping.wait_for(|stopped| *stopped) => return Err("sync unavailable"),
        }
    }
    let mut following = settlements(&handle);
    let verdict = handle.client.removal_verdict();
    let position = handle
        .ops
        .stage_control(TrustControl::RemoveSelf)
        .await
        .map_err(refused)?;
    handle.client.wake();
    tokio::select! {
        screen = accounts.erased() => Ok(screen),
        outcome = settled(&handle, &mut following, TrustControl::RemoveSelf.kind(), position) => {
            match outcome {
                Ok(Ordered::Accepted { .. }) => Ok(accounts.erased().await),
                Ok(_) => Err(NOT_ACCEPTED),
                // Sync stops for the verified removal, before it erases.
                Err(_) if matches!(*verdict.borrow(), RemovalVerdict::Removed { .. }) => {
                    Ok(accounts.erased().await)
                }
                Err(error) => Err(error),
            }
        }
    }
}

/// The person saved the new kit `NewKit` showed. Its kit is cleared from
/// the stage on the owner alone, so it needs no sync: after a restart the
/// account shows its new kit before any sync starts. While sync runs, the
/// replacement is followed until history settles it.
async fn confirm_new_kit<S, P>(
    accounts: &SharedAccountHost<S, P>,
    sync: &SyncHost,
) -> Result<Screen, &'static str>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    let Some((id, capability)) = accounts.showing_new_kit() else {
        let lost = accounts
            .routed()
            .and_then(|id| {
                accounts.with_known(id, |known, _| std::mem::take(&mut known.kit_not_changed))
            })
            .unwrap_or(false);
        return Err(if lost {
            KIT_NOT_CHANGED
        } else {
            "not permitted"
        });
    };
    let running = sync.handle(id).map(|handle| {
        let following = settlements(&handle);
        (handle, following)
    });
    let staged = accounts
        .run_lent(id, &capability, |owner, _| {
            Box::pin(async move { owner.confirm_staged_kit() })
        })
        .await
        .map_err(|_| "account unavailable")?
        .map_err(|_| "account unavailable")?;
    let not_changed = || {
        let _ = accounts.kit_not_changed(id);
        accounts.with_known(id, |known, _| known.kit_not_changed = false);
        Err(KIT_NOT_CHANGED)
    };
    let Some(position) = staged else {
        // Lost while its kit showed.
        return not_changed();
    };
    let Some((handle, mut following)) = running else {
        accounts.show(id, Screen::Ready);
        return Ok(Screen::Ready);
    };
    handle.client.wake();
    let outcome = settled(&handle, &mut following, REPLACE_RECOVERY, position).await;
    match outcome {
        Ok(Ordered::Accepted { .. }) => {
            accounts.with_known(id, |known, _| known.kit_not_changed = false);
            accounts.show(id, Screen::Ready);
            Ok(Screen::Ready)
        }
        Ok(_) => not_changed(),
        Err(error) => follow_stopped(accounts, id, error),
    }
}

/// Sync stopped while a saved kit's replacement was followed: shown Ready,
/// it is sent when sync runs again. If history settled it lost or refused
/// in the same poll, the hook left the flag: the kit did not change.
/// (A dropped save followed by such a settlement is a known limit: the
/// flag waits for a save the person can no longer press.)
fn follow_stopped<S, P>(
    accounts: &SharedAccountHost<S, P>,
    id: ContainerId,
    error: &'static str,
) -> Result<Screen, &'static str>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone,
{
    accounts.show(id, Screen::Ready);
    let lost = accounts
        .with_known(id, |known, _| std::mem::take(&mut known.kit_not_changed))
        .unwrap_or(false);
    Err(if lost { KIT_NOT_CHANGED } else { error })
}

/// The tags of a removal now and a recovery replacement in `event`.
const REMOVE_NOW: u8 = 6;
const REPLACE_RECOVERY: u8 = 8;

/// The routed ready account, this device and the history it verified: its
/// client's view while one runs (the owner may be lent to a prompt), else
/// its owner's.
fn routed<S, P>(
    accounts: &SharedAccountHost<S, P>,
    sync: &SyncHost,
) -> Option<(ContainerId, DeviceId, VerifiedAccount)>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone,
{
    let (id, capability) = accounts.ready_authority()?;
    let account = match sync.handle(id) {
        Some(handle) => handle.ops.verified()?,
        None => accounts.routed_account()?.2,
    };
    Some((id, capability.device_id(), account))
}

/// Your devices for the routed ready account, and a directory read of its
/// names asked for: its client takes it on its next pass, woken here.
/// `None` while no account is ready.
pub fn view<S, P>(accounts: &SharedAccountHost<S, P>, sync: &SyncHost) -> Option<DevicesView>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone,
{
    let (id, this, account) = routed(accounts, sync)?;
    let view = accounts.devices_view(id, this, &account);
    sync.wake(id);
    view
}

/// Change the password and kit. With a known password check, `current` is
/// checked here first, so a wrong one prompts and sends nothing; the
/// account's check is read from its directory when none is held. With none
/// for the current record, the kit `code` is needed too, and the home
/// checks both (`password_change_needs_kit`); its refusal is shown as
/// recovery shows it, and nothing is asked of the person. The new
/// kit is shown at once and kept until saved; its replacement is sent only
/// then. The new password's check is published after the rotation that
/// follows, under the new key.
async fn change_password<S, P>(
    accounts: &SharedAccountHost<S, P>,
    sync: &SyncHost,
    id: ContainerId,
    account: &VerifiedAccount,
    current: String,
    new: Option<String>,
    code: Option<String>,
) -> Result<Screen, &'static str>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    if new
        .as_deref()
        .is_some_and(|new| Password::new(new).is_err())
    {
        return Err(INVALID_PASSWORD);
    }
    let record = account.record_digest().map_err(|_| "account unavailable")?;
    let held = |accounts: &SharedAccountHost<S, P>| {
        accounts
            .with_known(id, |known, _| known.check_for(record).map(copy_check))
            .flatten()
    };
    let check = match held(accounts) {
        Some(check) => Some(check),
        None => {
            let reads = accounts
                .with_known(id, |known, _| {
                    known.wanted = true;
                    known.reads
                })
                .ok_or("account unavailable")?;
            let handle = sync.handle(id).ok_or("sync unavailable")?;
            handle.client.wake();
            let mut stopping = handle.stopping.clone();
            tokio::select! {
                () = accounts.read_after(id, reads) => {}
                _ = stopping.wait_for(|stopped| *stopped) => return Err("sync unavailable"),
            }
            held(accounts)
        }
    };
    match check {
        Some(check) => {
            let candidate = current.clone();
            let matches = tokio::task::spawn_blocking(move || password_matches(&check, &candidate))
                .await
                .map_err(|_| "account unavailable")?;
            if !matches {
                return Err("wrong password");
            }
        }
        // No check for this record: the kit and the home's check instead.
        None => {
            let code = code.ok_or("needs kit")?;
            let handle = sync.handle(id).ok_or("sync unavailable")?;
            match kit_keys(accounts, &handle, id, &current, &code).await? {
                Ok(keys) => drop(keys),
                Err(refused) => return Ok(refused),
            }
        }
    }
    let password = new.unwrap_or(current);
    let handle = sync.handle(id).ok_or("sync unavailable")?;
    let kit = handle
        .ops
        .replace_recovery(password)
        .await
        .map_err(refused)?;
    let old_key = account
        .personal_public()
        .map(|key| bh_crypto::hash(key))
        .map_err(|_| "account unavailable")?;
    accounts.with_known(id, |known, _| {
        known.check = Some(HeldCheck {
            check: kit.check,
            record_digest: kit.record_digest,
            not_under: Some(old_key),
        });
    });
    let screen = Screen::NewKit { code: kit.code };
    accounts.with_known(id, |known, _| known.kit_not_changed = false);
    accounts.show(id, screen.clone());
    Ok(screen)
}

impl<S, P> SharedAccountHost<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone,
{
    fn devices_view(
        &self,
        id: ContainerId,
        this: DeviceId,
        account: &VerifiedAccount,
    ) -> Option<DevicesView> {
        let database = self.database(id)?;
        let (home_ms, alerts, staged) = {
            let database = database.lock().ok()?;
            (
                home_time(&database, account),
                database.alerts(LISTED_ALERTS).ok()?,
                database.staged_account_control().ok()?,
            )
        };
        let submitting = staged.and_then(|staged| submitting(&staged.event));
        let (names, needs_kit) = self.with_known(id, |known, model| {
            known.wanted = true;
            let mut names = known.names.clone();
            if let Some(model) = model {
                names.insert(this, model.to_owned());
            }
            let held = account
                .record_digest()
                .ok()
                .is_some_and(|record| known.check_for(record).is_some());
            (names, known.read && !held)
        })?;
        self.deliver_alerts(id);
        Some(build(
            account, this, home_ms, &names, &alerts, needs_kit, submitting,
        ))
    }

    /// New alerts of account `id`, with names, to whoever watches `alerts()`;
    /// each is marked shown once handed over, so it is delivered once, across
    /// restarts. Nothing is marked while nobody watches. Alerts naming a
    /// device with no name read this run first wait for one read of the
    /// names, asked for here, and then go out with what it found, or with
    /// no name if it failed.
    pub(crate) fn deliver_alerts(&self, id: ContainerId) {
        if !self.alerts_watched() {
            return;
        }
        // The registry lock is never taken under a database lock.
        let Some(this) = self
            .ready_parts(id)
            .map(|parts| parts.capability.device_id())
        else {
            return;
        };
        let (names, naming) = self
            .with_known(id, |known, model| {
                let mut names = known.names.clone();
                if let Some(model) = model {
                    names.insert(this, model.to_owned());
                }
                (names, known.naming)
            })
            .unwrap_or_default();
        let Some(database) = self.database(id) else {
            return;
        };
        let Ok(mut database) = database.lock() else {
            return;
        };
        let Ok(new) = database.unshown_alerts() else {
            return;
        };
        if new.is_empty() {
            return;
        }
        let unnamed = new.iter().any(|alert| {
            [alert.subject, alert.actor]
                .into_iter()
                .flatten()
                .any(|device| !names.contains_key(&DeviceId(device)))
        });
        match naming {
            Naming::Idle if unnamed => {
                drop(database);
                self.with_known(id, |known, _| {
                    known.naming = Naming::Asked;
                    known.wanted = true;
                });
                return;
            }
            Naming::Asked => return,
            _ => {}
        }
        let items: Vec<_> = new
            .iter()
            .map(|alert| delivered_alert(id, alert, &names, this))
            .collect();
        let ids: Vec<_> = new.iter().map(|alert| alert.id).collect();
        if database.mark_alerts_shown(&ids).is_ok() {
            drop(database);
            self.with_known(id, |known, _| known.naming = Naming::Idle);
            self.publish_alerts(items);
        }
    }

    /// The names read account `id`'s alerts waited for finished or failed:
    /// deliver them now.
    pub(crate) fn names_answered(&self, id: ContainerId) {
        self.with_known(id, |known, _| {
            if known.naming == Naming::Asked {
                known.naming = Naming::Answered;
            }
        });
        self.deliver_alerts(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_account::{
        AccountEvent, AccountId, ConfirmedTime, DevicePublicKeys, SigningRequest,
        crypto::{KemKey, SigningKey},
        recovery::RecoveryKeys,
    };

    const DAY: u64 = 86_400_000;

    struct Member {
        ordinary: SigningKey,
        control: SigningKey,
        keys: DevicePublicKeys,
    }
    impl Member {
        fn new() -> Self {
            let (ordinary, control) = (SigningKey::generate(), SigningKey::generate());
            let keys = DevicePublicKeys::new(
                ordinary.public(),
                control.public(),
                KemKey::generate().public(),
            )
            .unwrap();
            Self {
                ordinary,
                control,
                keys,
            }
        }
        fn id(&self) -> DeviceId {
            self.keys.id()
        }
    }

    fn signed(request: SigningRequest, key: &SigningKey) -> Vec<u8> {
        request
            .finish(key.sign(request.signing_bytes()))
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn at(ms: u64) -> Option<ConfirmedTime> {
        Some(ConfirmedTime {
            earliest_ms: ms,
            latest_ms: ms,
        })
    }

    /// The Mac signs up at `start`; the Fold is added `fold_after` later.
    fn account(start: u64, fold_after: u64) -> (Member, Member, VerifiedAccount) {
        let mac = Member::new();
        let draft = AccountEvent::genesis(mac.keys.clone(), RecoveryKeys::generate().public());
        let genesis = draft
            .finish(mac.control.sign(draft.signing_bytes()))
            .unwrap();
        let mut account = VerifiedAccount::from_genesis(
            AccountId::of_genesis(&genesis).unwrap(),
            genesis.as_bytes(),
        )
        .unwrap();
        let record = account.prepare_recovery_record(mac.id(), [3; 32]).unwrap();
        account
            .apply_timed(&signed(record, &mac.control), at(start))
            .unwrap();
        let personal = account
            .publish_personal_key(mac.id(), KemKey::generate().public(), [4; 32], [5; 32])
            .unwrap();
        account
            .apply_timed(&signed(personal, &mac.control), at(start))
            .unwrap();
        let fold = Member::new();
        let added = account.add_device(mac.id(), fold.keys.clone()).unwrap();
        account
            .apply_timed(&signed(added, &mac.control), at(start + fold_after))
            .unwrap();
        let _ = &fold.ordinary;
        (mac, fold, account)
    }

    fn names(pairs: &[(DeviceId, &str)]) -> BTreeMap<DeviceId, String> {
        pairs
            .iter()
            .map(|(id, name)| (*id, (*name).to_owned()))
            .collect()
    }

    #[test]
    fn devices_view_marks_this_device_and_eligibility() {
        let start = 1_900_000_000_000;
        let (mac, fold, account) = account(start, DAY);
        let known = names(&[(mac.id(), "MacBook Pro"), (fold.id(), "Pixel 10 Pro Fold")]);
        let home = start + 5 * DAY;
        let view = build(&account, mac.id(), home, &known, &[], false, None);
        assert_eq!(view.devices.len(), 2);
        let this = &view.devices[0];
        assert!(this.this_device);
        assert_eq!(this.name.as_deref(), Some("MacBook Pro"));
        assert_eq!(this.id_hex, hex(&mac.id().0));
        assert_eq!(this.added_ms, Some(start));
        assert!(this.can_remove && !this.can_remove_now && !this.can_cancel);
        let other = &view.devices[1];
        assert!(!other.this_device);
        assert_eq!(other.name.as_deref(), Some("Pixel 10 Pro Fold"));
        assert_eq!(other.added_ms, Some(start + DAY));
        assert!(other.can_remove && other.can_remove_now && !other.can_cancel);
        assert_eq!(other.pending, None);
        // No name read for it yet: the app shows its kind and added date.
        let view = build(&account, mac.id(), home, &BTreeMap::new(), &[], false, None);
        assert_eq!(view.devices[1].name, None);
    }

    #[test]
    fn own_alert_actor_uses_the_name_shown_for_this_device_without_a_directory_read() {
        let start = 1_900_000_000_000;
        let (mac, fold, account) = account(start, DAY);
        let alerts = [AlertKind::KitChanged, AlertKind::RemovalRequested]
            .into_iter()
            .enumerate()
            .map(|(index, kind)| StoredAlert {
                id: index as i64 + 1,
                kind,
                position: None,
                subject: None,
                actor: Some(mac.id().0),
                time_ms: None,
                deadline_ms: None,
                shown: false,
            })
            .collect::<Vec<_>>();
        let view = build(
            &account,
            mac.id(),
            start + DAY,
            &BTreeMap::new(),
            &alerts,
            false,
            None,
        );
        assert_eq!(view.devices[0].name, None);
        for alert in &view.alerts {
            assert_eq!(alert.actor_name.as_deref(), Some("Device"));
        }
        let own_name = names(&[(mac.id(), "Pixel 6")]);
        let named_view = build(
            &account,
            mac.id(),
            start + DAY,
            &own_name,
            &alerts,
            false,
            None,
        );
        assert_eq!(named_view.devices[0].name.as_deref(), Some("Pixel 6"));
        assert!(
            named_view
                .alerts
                .iter()
                .all(|alert| alert.actor_name.as_deref() == Some("Pixel 6"))
        );
        let other = StoredAlert {
            actor: Some(fold.id().0),
            ..alerts[0].clone()
        };
        assert_eq!(
            alert_item(&other, &BTreeMap::new(), mac.id()).actor_name,
            None
        );
    }

    #[test]
    fn delivered_alerts_keep_their_container_when_local_row_ids_overlap() {
        let (mac, _, _) = account(1_900_000_000_000, 0);
        // Two independent account databases each allocate local row 1.
        let mut first_db = DeviceDatabase::open(":memory:").unwrap();
        let mut second_db = DeviceDatabase::open(":memory:").unwrap();
        for db in [&mut first_db, &mut second_db] {
            assert!(db.record_kit_used(1_900_000_000_000).unwrap());
        }
        let first_row = first_db.unshown_alerts().unwrap();
        let second_row = second_db.unshown_alerts().unwrap();
        assert_eq!(first_row[0].id, 1);
        assert_eq!(second_row[0].id, 1);
        let first = delivered_alert(
            ContainerId([1; 16]),
            &first_row[0],
            &BTreeMap::new(),
            mac.id(),
        );
        let second = delivered_alert(
            ContainerId([2; 16]),
            &second_row[0],
            &BTreeMap::new(),
            mac.id(),
        );
        assert_eq!(
            first.alert, second.alert,
            "local alert rows may be identical"
        );
        assert_eq!(first.container, ContainerId([1; 16]));
        assert_eq!(second.container, ContainerId([2; 16]));
    }

    #[test]
    fn remove_now_hidden_for_an_immature_device() {
        let start = 1_900_000_000_000;
        let (mac, fold, account) = account(start, DAY);
        // The Fold, added a day after the Mac, three days after signup:
        // two days in, not mature.
        let view = build(
            &account,
            fold.id(),
            start + 3 * DAY,
            &BTreeMap::new(),
            &[],
            false,
            None,
        );
        let mac_item = view.devices.iter().find(|d| !d.this_device).unwrap();
        assert!(mac_item.can_remove, "any device may ask");
        assert!(!mac_item.can_remove_now);
        // Mature exactly at the wait, by home time.
        let view = build(
            &account,
            fold.id(),
            start + DAY + REMOVAL_WAIT_MS,
            &BTreeMap::new(),
            &[],
            false,
            None,
        );
        let mac_item = view.devices.iter().find(|d| !d.this_device).unwrap();
        assert!(mac_item.can_remove_now);
        assert_eq!(hex(&mac.id().0), mac_item.id_hex);
    }

    /// A device clock a week ahead of the home's time changes nothing: only
    /// verified home time is used.
    #[test]
    fn a_device_clock_ahead_of_home_time_does_not_make_a_device_mature() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        // The home's latest time is a moment before the Fold is mature; this
        // machine's clock reads a week past that.
        let home = now - 7 * DAY;
        let added = home + 1 - REMOVAL_WAIT_MS;
        let (_, fold, account) = account(added - DAY, DAY);
        let view = build(
            &account,
            fold.id(),
            home,
            &BTreeMap::new(),
            &[],
            false,
            None,
        );
        let other = view.devices.iter().find(|d| !d.this_device).unwrap();
        assert!(!other.can_remove_now);
    }

    #[test]
    fn target_sees_its_pending_removal_and_no_cancel() {
        let start = 1_900_000_000_000;
        let (mac, fold, mut account) = account(start, 0);
        let names = names(&[(mac.id(), "MacBook Pro"), (fold.id(), "Pixel 10 Pro Fold")]);
        let requested = start + 4 * DAY;
        let request = account.request_removal(mac.id(), fold.id()).unwrap();
        account
            .apply_timed(&signed(request, &mac.control), at(requested))
            .unwrap();
        let position = account.head().position;
        let deadline = requested + REMOVAL_WAIT_MS;
        // On the Fold, the target.
        let view = build(&account, fold.id(), requested + 1, &names, &[], false, None);
        let this = view.devices.iter().find(|d| d.this_device).unwrap();
        assert_eq!(
            this.pending,
            Some(PendingItem {
                request: position,
                deadline_ms: deadline,
                requested_by: Some("MacBook Pro".into()),
            })
        );
        assert!(!this.can_cancel, "no device cancels its own removal");
        // On the Mac, the requester: mature, so it may cancel.
        let view = build(&account, mac.id(), requested + 1, &names, &[], false, None);
        let other = view.devices.iter().find(|d| !d.this_device).unwrap();
        assert!(other.pending.is_some() && other.can_cancel);
        assert!(!other.can_remove, "already pending");
        // Past the deadline by home time it is gone.
        let view = build(&account, mac.id(), deadline, &names, &[], false, None);
        assert_eq!(view.devices.len(), 1);
    }

    #[test]
    fn view_reports_this_builds_wait() {
        let (mac, _, account) = account(1_900_000_000_000, 0);
        let view = build(&account, mac.id(), 0, &BTreeMap::new(), &[], true, None);
        assert_eq!(view.wait_ms, bh_account::REMOVAL_WAIT_MS);
        assert!(view.password_change_needs_kit);
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["wait_ms"], bh_account::REMOVAL_WAIT_MS);
    }

    /// Every recovery answer shows as the home gave it; a base waiting for
    /// an admission snapshot shows as unreachable, and what does not verify
    /// is an error, not a refusal to try again.
    #[test]
    fn recovery_answers_map_to_screens() {
        let refused = |reason, tries_left, next_try_ms| {
            Ok(Screen::RecoverRefused {
                reason,
                tries_left,
                next_try_ms,
            })
        };
        let cases = [
            (
                RecoverError::NotRecognised,
                refused("not_recognised", None, None),
            ),
            (
                RecoverError::PasswordMismatch {
                    tries_left: 0,
                    next_try_ms: Some(9),
                },
                refused("password", Some(0), Some(9)),
            ),
            (
                RecoverError::Wait { next_try_ms: 9 },
                refused("wait", None, Some(9)),
            ),
            (
                RecoverError::Unreachable,
                refused("unreachable", None, None),
            ),
            (
                RecoverError::AwaitingAdmission,
                refused("unreachable", None, None),
            ),
            (RecoverError::Invalid, Err(NOT_VERIFIED)),
        ];
        for (error, screen) in cases {
            assert_eq!(recover_refused(error), screen, "{error:?}");
        }
        let json =
            serde_json::to_value(recover_refused(RecoverError::Wait { next_try_ms: 9 }).unwrap())
                .unwrap();
        assert_eq!(
            json,
            serde_json::json!({"screen": "recover_refused", "reason": "wait", "tries_left": null, "next_try_ms": 9})
        );
    }

    /// Sync stops in the poll the saved kit's replacement settles lost: the
    /// hook has already shown Ready and left the flag, so the person is told
    /// the kit did not change, once.
    #[test]
    fn a_follow_stopped_after_the_replacement_was_lost_says_kit_not_changed() {
        use crate::{
            accounts::AccountHost,
            test_support::{FakeStore, PlainProtector},
        };
        let dir = tempfile::tempdir().unwrap();
        let accounts = AccountHost::<FakeStore, PlainProtector>::new(
            std::sync::Arc::new(bh_device::Owner::default()),
            Some(dir.path().to_path_buf()),
        )
        .into_state();
        let id = ContainerId([7; 16]);
        accounts.with_known(id, |known, _| known.kit_not_changed = true);
        assert_eq!(
            follow_stopped(&accounts, id, "sync unavailable"),
            Err(KIT_NOT_CHANGED)
        );
        assert_eq!(
            accounts.with_known(id, |known, _| known.kit_not_changed),
            Some(false)
        );
        // Not lost: saved, and sent when sync runs again.
        assert_eq!(
            follow_stopped(&accounts, id, "sync unavailable"),
            Err("sync unavailable")
        );
    }
}
