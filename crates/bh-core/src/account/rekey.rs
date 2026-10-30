//! Full-device key rotation and finishing bases left behind by a removal.

use super::*;
use crate::rotation::seal_for_device;
use bh_proto::{DeviceKeyEntry, RotationRequest};

struct BackgroundRekeyGuard(Weak<Inner>);

impl Drop for BackgroundRekeyGuard {
    fn drop(&mut self) {
        if let Some(inner) = self.0.upgrade() {
            inner.rekey_running.store(false, Ordering::Release);
        }
    }
}

/// Persist the removed reader and its former bases before any re-key starts.
pub(super) fn pending_removal(
    data: &mut Data,
    device: DeviceId,
    bases: BTreeSet<BaseId>,
    version: u64,
) {
    let name = device_name(data, device);
    let pending = entry(data, "pendingRemovals");
    let previous = pending
        .get(&device.to_string())
        .and_then(|item| item.get("bases"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|id| id.as_str()?.parse::<BaseId>().ok());
    let all: BTreeSet<_> = bases.into_iter().chain(previous).collect();
    pending.insert(
        device.to_string(),
        json!({"name": name, "bases": all, "version": version}),
    );
}

fn pending_bases(data: &Data) -> BTreeMap<BaseId, u64> {
    let mut bases: BTreeMap<BaseId, u64> = BTreeMap::new();
    for item in data
        .get("pendingRemovals")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(_, item)| item)
    {
        let Some(version) = item.get("version").and_then(Value::as_u64) else {
            continue;
        };
        for id in item
            .get("bases")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(base) = id.as_str().and_then(|id| id.parse::<BaseId>().ok()) {
                bases
                    .entry(base)
                    .and_modify(|existing| *existing = (*existing).max(version))
                    .or_insert(version);
            }
        }
    }
    bases
}

/// How a device is being removed.
pub enum Removal {
    /// Disconnect an app, or erase this device.
    Plain,
    /// Remove another full device with the account password.
    Full {
        /// The account password, zeroized after use.
        password: Zeroizing<String>,
        /// Whether the device is lost or stolen (and the recovery kit must change).
        lost: bool,
    },
}

/// The result of a removal after its revocation has been confirmed.
#[derive(Debug, PartialEq, Eq)]
pub struct RemovalOutcome {
    /// A replacement kit, if the current kit could not be kept.
    pub new_kit: Option<RecoveryKit>,
    /// Ordinary bases still need re-keying; refresh on any full device will finish them.
    pub pending: bool,
}

impl Account {
    pub(super) async fn remove_full(
        &self,
        id: DeviceId,
        password: Zeroizing<String>,
        lost: bool,
    ) -> Result<RemovalOutcome, Error> {
        // A new full rotation advances every base again and satisfies earlier
        // app/folder floors; a stuck pending re-key must not block revocation.
        let _ = self.finish_rekeys().await;
        let params = self.inner.api.login_params(&self.inner.email).await?;
        let salt = login_salt(&params)?;
        let password = derive(password, salt, params.kdf).await?;
        for attempt in 0..3 {
            self.refresh_account_data().await?;
            let record = self
                .inner
                .api
                .account_after(self.verified_keys()?.newest().0)
                .await?;
            self.adopt_keys(record.epoch, &record.device_keys)?;
            let target = record
                .devices
                .iter()
                .find(|d| d.device_id == id && d.status == "active")
                .ok_or(Error::NotFound)?;
            if target.kind != bh_proto::DeviceKind::Full {
                return Err(Error::invalid("device kind"));
            }
            let old = self.account_key()?;
            let next = Secret::<32>::random();
            let next_epoch = self
                .verified_keys()?
                .newest()
                .0
                .checked_add(1)
                .ok_or(Error::Crypto)?;
            let (version, mut data, _) = self.accept_data(record.data.as_ref())?;
            let pins = self.pin_publics(&data)?;
            let previous_kit = self.recovery_kit()?;
            let new_kit = if lost || previous_kit.is_none() {
                Some(RecoveryKit::generate())
            } else {
                None
            };
            let kit = new_kit
                .as_ref()
                .or(previous_kit.as_ref())
                .ok_or(Error::BadKit)?;
            let envelope = envelope::seal(
                &password.wrap_key(kit),
                &keys::account_key_aad(&self.id(), next_epoch),
                next.expose(),
            );
            let hash = envelope_hash(&envelope);
            let saved = if new_kit.is_some() {
                false
            } else {
                data.get("kit")
                    .and_then(|v| v.get("saved"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            };
            let made_at = data.get("kit").and_then(|v| v.get("at")).cloned();
            set_kit(&mut data, kit, saved, &hash, &salt);
            if new_kit.is_none()
                && let Some(at) = made_at
            {
                data.get_mut("kit")
                    .and_then(Value::as_object_mut)
                    .ok_or(Error::Crypto)?
                    .insert("at".into(), at);
            }
            // The removal and its pending marker commit in the same DELETE.
            // Full removals use the account epoch, not the account-data version
            // used by app and folder removals.
            let name = device_name(&data, id);
            entry(&mut data, "pendingRemovals").insert(
                id.to_string(),
                json!({"name": name, "kind": "full", "epoch": next_epoch}),
            );
            entry(&mut data, "keys").insert(
                (next_epoch - 1).to_string(),
                json!(URL_SAFE_NO_PAD.encode(old.expose())),
            );
            let mut deliveries = Vec::new();
            for device in record
                .devices
                .iter()
                .filter(|d| d.status == "active" && d.device_id != id)
            {
                let (previous, next_key) = match device.kind {
                    bh_proto::DeviceKind::Full => (
                        Secret::from_slice(old.expose())?,
                        Secret::from_slice(next.expose())?,
                    ),
                    bh_proto::DeviceKind::App => {
                        // Registration can commit before the connect writes account data.
                        // An app without its key never completed that connection.
                        let Some(app) = data
                            .get_mut("apps")
                            .and_then(|v| v.get_mut(device.device_id.to_string()))
                        else {
                            continue;
                        };
                        let previous = Secret::from_slice(
                            &URL_SAFE_NO_PAD
                                .decode(
                                    app.get("key")
                                        .and_then(Value::as_str)
                                        .ok_or(Error::Crypto)?,
                                )
                                .map_err(|_| Error::Crypto)?,
                        )?;
                        let fresh = Secret::<32>::random();
                        app["key"] = json!(URL_SAFE_NO_PAD.encode(fresh.expose()));
                        (previous, fresh)
                    }
                };
                // Old devices without published keys cannot receive delivery.
                // They keep only old keys, are fenced from writing and must sign in again.
                let Some(public) = pins.get(&device.device_id) else {
                    continue;
                };
                let public: [u8; XWING_PUBLIC_BYTES] =
                    public.as_slice().try_into().map_err(|_| Error::Crypto)?;
                deliveries.push(DeviceKeyEntry {
                    device_id: device.device_id,
                    sealed: Bytes(seal_for_device(
                        &public,
                        &DeliveryContext {
                            account: self.id(),
                            device: device.device_id,
                            kind: device.kind.clone(),
                            from_epoch: next_epoch - 1,
                        },
                        &previous,
                        &next_key,
                    )?),
                });
            }
            if !deliveries.iter().any(|d| d.device_id == self.device_id()) {
                return Err(Error::Crypto);
            }
            let json = Zeroizing::new(serde_json::to_vec(&data).map_err(|_| Error::Crypto)?);
            let ciphertext = envelope::seal(
                &keys::account_data_key(&next),
                &keys::account_data_aad(&self.id(), data_epoch(version + 1)?),
                &json,
            );
            let request = DeleteDeviceRequest {
                notice: Some(Bytes(self.removal_notice_for(id).await?.to_vec())),
                data: Some(AccountDataRequest {
                    ciphertext: Bytes(ciphertext.clone()),
                    expected_version: version,
                    account_epoch: next_epoch,
                }),
                rotation: Some(RotationRequest {
                    epoch: next_epoch,
                    login_key: Bytes(password.login_key().to_vec()),
                    account_key_envelope: Bytes(envelope.clone()),
                    activation_hash: Bytes(
                        bh_crypto::sha256(keys::activation(&next).expose()).to_vec(),
                    ),
                    device_keys: deliveries,
                }),
            };
            match self.inner.api.delete_device(id, &request).await {
                Ok(()) => {}
                Err(Error::Conflict(code))
                    if (code == "epoch_conflict" || code == "version_conflict") && attempt < 2 =>
                {
                    continue;
                }
                Err(error) if matches!(error, Error::Network(_)) => {
                    // A network failure may be a lost response to a committed DELETE.
                    // Later kit changes, account-data writes or another rotation
                    // need not preserve our envelope. Our own authenticated
                    // delivery to the attempted key proves this DELETE committed.
                    let committed = self.inner.api.account_after(next_epoch - 1).await?;
                    if committed.epoch < next_epoch
                        || !committed
                            .devices
                            .iter()
                            .any(|d| d.device_id == id && d.status == "revoked")
                    {
                        return Err(error);
                    }
                    let Some(delivery) = committed
                        .device_keys
                        .iter()
                        .find(|item| item.epoch == next_epoch)
                    else {
                        return Err(error);
                    };
                    let seed = self
                        .inner
                        .shared
                        .secret(&format!("acct.{}.kem", self.id()))?;
                    let kem = KemKey::from_seed(&Secret::<32>::from_slice(&seed)?);
                    let opened = crate::rotation::open_for_device(
                        &kem,
                        &DeliveryContext {
                            account: self.id(),
                            device: self.device_id(),
                            kind: bh_proto::DeviceKind::Full,
                            from_epoch: next_epoch - 1,
                        },
                        &old,
                        &delivery.sealed.0,
                    )
                    .map_err(|_| error.clone())?;
                    if !bh_crypto::constant_time_eq(opened.expose(), next.expose()) {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
            // The DELETE committed: later local write failures must not hide
            // the new kit or turn a successful revocation into an error.
            // Install our committed key and data locally. No
            // second network read (or base re-key) belongs on the return path.
            // If local persistence fails, never suppress a committed new kit:
            // the next refresh can repeat adoption from the server.
            if let Ok(mut ring) = self.verified_keys()
                && ring
                    .insert(next_epoch, Secret::from_slice(next.expose())?)
                    .is_ok()
            {
                let _ = self
                    .inner
                    .shared
                    .secrets
                    .put(&format!("acct.{}.key", self.id()), &ring.to_bytes());
            }
            let _ = self.cache_envelope(&envelope);
            let _ = self.cache(version + 1, &data, true);
            let _ = self.remember_backup_credentials(envelope.clone(), salt);
            self.start_background_rekeys();
            let _ = self.inner.events.send(AccountEvent::DevicesChanged);
            return Ok(RemovalOutcome {
                new_kit,
                pending: true,
            });
        }
        Err(Error::Conflict("epoch_conflict".into()))
    }

    fn start_background_rekeys(&self) {
        let mut task = self.inner.rekey_task.lock().unwrap();
        if self.inner.removal.load(Ordering::SeqCst) != 0 {
            return;
        }
        self.inner.rekey_requested.fetch_add(1, Ordering::AcqRel);
        if self
            .inner
            .rekey_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let account = self.clone();
        let guard = BackgroundRekeyGuard(Arc::downgrade(&self.inner));
        *task = Some(self.inner.shared.handle.spawn(async move {
            let last = loop {
                let requested = account.inner.rekey_requested.load(Ordering::Acquire);
                let _ = account.finish_rekeys().await;
                // Open hidden bases have their own cancellation guard. Locked
                // ones are fenced and do not delay the pending marker.
                let open: Vec<_> = account
                    .inner
                    .hidden
                    .lock()
                    .unwrap()
                    .keys()
                    .copied()
                    .collect();
                for id in open {
                    let _ = account.rekey_hidden(id).await;
                }
                if account.inner.rekey_requested.load(Ordering::Acquire) == requested {
                    break requested;
                }
            };
            drop(guard);
            // A request between the last check and dropping the marker was
            // unable to spawn its own task. Restart it here instead.
            if account.inner.rekey_requested.load(Ordering::Acquire) != last {
                account.start_background_rekeys();
            }
        }));
    }

    /// Finish all pending removals for a CLI caller that will exit afterward.
    /// Retries transient failures three times with short backoff; an unfinished
    /// removal or a permanent failure is returned rather than waiting forever.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on an app device, or the final re-key,
    /// network, or account-data error if the work cannot be completed.
    pub async fn wait_for_removals(&self) -> Result<(), Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let mut last = None;
        for attempt in 0..3 {
            let result = async {
                self.refresh_account_data().await?;
                if self.cached_data().is_some_and(|data| {
                    data.get("pendingRemovals")
                        .and_then(Value::as_object)
                        .is_none_or(Map::is_empty)
                }) {
                    return Ok(());
                }
                self.finish_rekeys().await?;
                self.refresh_account_data().await?;
                if self.cached_data().is_some_and(|data| {
                    data.get("pendingRemovals")
                        .and_then(Value::as_object)
                        .is_none_or(Map::is_empty)
                }) {
                    Ok(())
                } else {
                    Err(Error::Conflict("pending_removal".into()))
                }
            }
            .await;
            match result {
                Ok(()) => return Ok(()),
                Err(
                    error
                    @ (Error::Forbidden | Error::Revoked | Error::Crypto | Error::NeedsUpdate),
                ) => {
                    return Err(error);
                }
                Err(error) => last = Some(error),
            }
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(50 * (1 << attempt))).await;
            }
        }
        Err(last.expect("at least one failed attempt"))
    }

    /// Re-key ordinary bases behind the account epoch or a pending app/folder
    /// removal. A pending app/folder removal needs every affected base's data
    /// floor; a full removal needs every listed ordinary base's account epoch.
    pub async fn finish_rekeys(&self) -> Result<(), Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let _one = self.inner.rekeys.lock().await;
        let record = self
            .inner
            .api
            .account_after(self.verified_keys()?.newest().0)
            .await?;
        self.adopt_keys(record.epoch, &record.device_keys)?;
        let epoch = self.verified_keys()?.newest().0;
        let known_ordinary: HashSet<_> = self.db().bases()?.into_iter().map(|row| row.id).collect();
        // For a folder removal, revoke the old server grant before declaring
        // its re-key complete. A failed revoke leaves the removal pending.
        let mut first_error = None;
        let grants_settled = if self.cached_data().is_some_and(|data| {
            data.get("pendingRemovals")
                .and_then(Value::as_object)
                .is_some_and(|entries| !entries.is_empty())
                && !grants::pending(&data).is_empty()
        }) {
            match self.settle_grants().await {
                Ok(()) => true,
                Err(error) => {
                    first_error = Some(error);
                    false
                }
            }
        } else {
            true
        };
        let pending = self
            .cached_data()
            .map(|data| pending_bases(&data))
            .unwrap_or_default();
        let mut ordinary_epochs = BTreeMap::new();
        let mut completed_floors = BTreeMap::new();
        let mut failed_ordinary = false;
        let mut failed_bases = HashSet::new();
        let full_pending = self.cached_data().is_some_and(|data| {
            data.get("pendingRemovals")
                .and_then(Value::as_object)
                .is_some_and(|entries| entries.values().any(|entry| entry["kind"] == "full"))
        });
        for id in record.bases {
            let required = pending.get(&id).copied().unwrap_or(0);
            let result: Result<Option<_>, Error> = async {
                let mut key = self.inner.api.base_key(id).await?;
                for _ in 0..3 {
                    if key.account_epoch >= epoch && key.data_floor >= required {
                        break;
                    }
                    let row = Self::base_row(id, key.clone());
                    match self.base_key(&row) {
                        Ok(_) => {}
                        // Unknown wrappers may be locked hidden bases; their old writes are fenced.
                        Err(Error::Crypto) if !known_ordinary.contains(&id) => return Ok(None),
                        Err(error) => return Err(error),
                    }
                    match self.rekey_base_to(id, Some((epoch, required))).await {
                        Ok(()) => {}
                        Err(Error::Conflict(code))
                            if code == "epoch_conflict" || code == "stale_grant" =>
                        {
                            self.refresh_account_data().await?;
                            key = self.inner.api.base_key(id).await?;
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                    key = self.inner.api.base_key(id).await?;
                }
                if key.account_epoch < epoch || key.data_floor < required {
                    match self.base_key(&Self::base_row(id, key.clone())) {
                        Ok(_) => return Err(Error::Conflict("epoch_conflict".into())),
                        Err(Error::Crypto) if !known_ordinary.contains(&id) => return Ok(None),
                        Err(error) => return Err(error),
                    }
                }
                // Include ordinary bases first seen on the server, not only locally opened ones.
                if full_pending {
                    match self.base_key(&Self::base_row(id, key.clone())) {
                        Ok(_) => {}
                        Err(Error::Crypto) if !known_ordinary.contains(&id) => return Ok(None),
                        Err(error) => return Err(error),
                    }
                }
                Ok(Some((key.account_epoch, key.data_floor)))
            }
            .await;
            match result {
                Ok(Some((reached, floor))) => {
                    ordinary_epochs.insert(id, reached);
                    completed_floors.insert(id, floor);
                }
                Ok(None) => {}
                Err(error) => {
                    // An unopenable known base must not clear any full removal.
                    failed_ordinary = true;
                    failed_bases.insert(id);
                    first_error.get_or_insert(error);
                }
            }
        }
        // A base omitted from inventory must not silently finish a pending list.
        for (id, required) in &pending {
            if failed_bases.contains(id) {
                continue;
            }
            match self.inner.api.base_key(*id).await {
                Ok(key) if key.data_floor >= *required => {
                    completed_floors.insert(*id, key.data_floor);
                }
                Ok(_) => {
                    first_error.get_or_insert(Error::Conflict("stale_grant".into()));
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if self.cached_data().is_some_and(|data| {
            data.get("pendingRemovals")
                .and_then(Value::as_object)
                .is_some_and(|entries| !entries.is_empty())
        }) {
            let cleared = Arc::new(AtomicBool::new(false));
            let signal = cleared.clone();
            self.update_data_at(move |data, _| {
                let done: Vec<String> = data
                    .get("pendingRemovals")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flatten()
                    .filter(|(_, item)| {
                        if item.get("kind").and_then(Value::as_str) == Some("full") {
                            let Some(required) = item.get("epoch").and_then(Value::as_u64) else {
                                return false;
                            };
                            return !failed_ordinary
                                && ordinary_epochs
                                    .values()
                                    .all(|epoch| u64::from(*epoch) >= required);
                        }
                        let Some(required) = item.get("version").and_then(Value::as_u64) else {
                            return false;
                        };
                        grants_settled
                            && item
                                .get("bases")
                                .and_then(Value::as_array)
                                .is_some_and(|bases| {
                                    bases.iter().all(|id| {
                                        id.as_str()
                                            .and_then(|id| id.parse::<BaseId>().ok())
                                            .and_then(|id| completed_floors.get(&id).copied())
                                            .is_some_and(|floor| floor >= required)
                                    })
                                })
                    })
                    .map(|(id, _)| id.clone())
                    .collect();
                let entries = entry(data, "pendingRemovals");
                for id in done {
                    signal.store(true, Ordering::Relaxed);
                    entries.remove(&id);
                }
            })
            .await?;
            if cleared.load(Ordering::Relaxed) {
                let _ = self.inner.events.send(AccountEvent::DevicesChanged);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(super) async fn remove_app(&self, id: DeviceId) -> Result<RemovalOutcome, Error> {
        // Each retry calculates the next version from the snapshot it actually
        // attempts to commit. The notice and sealed data travel in one DELETE.
        for attempt in 0..3 {
            let record = self
                .inner
                .api
                .account_after(self.verified_keys()?.newest().0)
                .await?;
            self.adopt_keys(record.epoch, &record.device_keys)?;
            if !record.devices.iter().any(|d| {
                d.device_id == id && d.kind == bh_proto::DeviceKind::App && d.status == "active"
            }) {
                return Err(Error::NotFound);
            }
            let (version, mut data, _) = self.accept_data(record.data.as_ref())?;
            let next_version = version.checked_add(1).ok_or(Error::Crypto)?;
            let Some(app_key) = data
                .get("apps")
                .and_then(|apps| apps.get(id.to_string()))
                .and_then(|app| app.get("key"))
                .and_then(Value::as_str)
            else {
                // Registration preceded the interrupted account-data write.
                // There is no app key or grant to rotate; revoke server access.
                self.inner
                    .api
                    .delete_device(id, &notice_request(self.removal_notice_for(id).await?))
                    .await?;
                return Ok(RemovalOutcome {
                    new_kit: None,
                    pending: false,
                });
            };
            let app_key = Secret::<32>::from_slice(
                &URL_SAFE_NO_PAD.decode(app_key).map_err(|_| Error::Crypto)?,
            )?;
            let notice =
                keys::removal_notice(&bh_crypto::kdf(&app_key, keys::REMOVAL, 1), &self.id(), &id);
            let mounts = grants::mounts(&data);
            let mut bases: BTreeSet<_> = grants::effective(&grants::direct(&data, id), &mounts)
                .into_keys()
                .collect();
            if let Some(was) = grants::was(&data, id) {
                bases.extend(was.into_keys());
            }
            pending_removal(&mut data, id, bases.clone(), next_version);
            entry(&mut data, "apps").remove(&id.to_string());
            let account_epoch = self.verified_keys()?.newest().0;
            let json = Zeroizing::new(serde_json::to_vec(&data).map_err(|_| Error::Crypto)?);
            let ciphertext = envelope::seal(
                &keys::account_data_key(&self.account_key()?),
                &keys::account_data_aad(&self.id(), data_epoch(next_version)?),
                &json,
            );
            let request = DeleteDeviceRequest {
                notice: Some(Bytes(notice.to_vec())),
                data: Some(AccountDataRequest {
                    ciphertext: Bytes(ciphertext),
                    expected_version: version,
                    account_epoch,
                }),
                rotation: None,
            };
            match self.inner.api.delete_device(id, &request).await {
                Ok(()) => {}
                Err(Error::Conflict(code))
                    if (code == "version_conflict" || code == "epoch_conflict") && attempt < 2 =>
                {
                    continue;
                }
                Err(error) if matches!(error, Error::Network(_)) => {
                    let committed = self.inner.api.account_after(account_epoch).await?;
                    self.adopt_keys(committed.epoch, &committed.device_keys)?;
                    if !committed
                        .devices
                        .iter()
                        .any(|d| d.device_id == id && d.status == "revoked")
                    {
                        return Err(error);
                    }
                    let (seen_version, latest, _) = self.accept_data(committed.data.as_ref())?;
                    if seen_version < next_version
                        || latest
                            .get("apps")
                            .and_then(|apps| apps.get(id.to_string()))
                            .is_some()
                    {
                        return Err(error);
                    }
                    // Another full device can finish the list and replace the
                    // ciphertext while our DELETE reply is in flight. A retained
                    // pending entry must still cover every former base. If it has
                    // already been cleared, prove completion from the base floors.
                    let covers = latest
                        .get("pendingRemovals")
                        .and_then(|entries| entries.get(id.to_string()))
                        .and_then(|item| {
                            let version = item.get("version")?.as_u64()?;
                            let listed: BTreeSet<BaseId> = item
                                .get("bases")?
                                .as_array()?
                                .iter()
                                .filter_map(|base| base.as_str()?.parse().ok())
                                .collect();
                            Some(version >= next_version && bases.is_subset(&listed))
                        })
                        .unwrap_or(false);
                    if !covers {
                        for base in &bases {
                            if self.inner.api.base_key(*base).await?.data_floor < next_version {
                                return Err(error);
                            }
                        }
                    }
                }
                Err(error) => return Err(error),
            }
            let pending = match self.refresh_account_data().await {
                Ok(()) => self.finish_rekeys().await.is_err(),
                Err(_) => true,
            };
            let _ = self.inner.events.send(AccountEvent::DevicesChanged);
            return Ok(RemovalOutcome {
                new_kit: None,
                pending,
            });
        }
        Err(Error::Conflict("version_conflict".into()))
    }
}
