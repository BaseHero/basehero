//! Create-once signup base. Historical introduction proof and current native
//! authority are separate: neither an anchor nor an unregistered genesis is an
//! ordered base head, a server receipt, or permission to sign a successor.
use crate::base_keys::{
    BaseKeyPurpose, InitialBaseKeyPackage, SealError, SealHeader, open_seal, prepare_seal,
    verify_seal,
};
use crate::keyring;
use bh_account::{
    VerifiedAccount,
    journal::{AccountJournal, PendingSetupProtector},
    local_seal::LocalKeyPurpose,
    owner::{
        AccountCapability, AccountOwner, InitialAccountPrefix, OwnerError, PendingHomeObjects,
    },
    personal::PersonalKey,
    platform::DeviceKeyStore,
};
use bh_crypto::{Secret, hash};
use bh_event::{VerifiedGenesis, key_id, prepare_genesis, verify_genesis};
use bh_storage::{
    DeviceDatabase, EpochKeyRow, StoreError,
    own_base::OwnBaseRecord,
    sync_state::{LOG_BASE, LogProgress},
};
use bh_sync::{BaseId, OpaqueEvent};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, RwLock},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnBaseError {
    Stale,
    Account(OwnerError),
    Storage,
    Invalid,
    Seal(SealError),
    /// The verified current epoch's key is not held: no current writes.
    KeyPending,
}
impl From<OwnerError> for OwnBaseError {
    fn from(e: OwnerError) -> Self {
        Self::Account(e)
    }
}
impl From<SealError> for OwnBaseError {
    fn from(e: SealError) -> Self {
        Self::Seal(e)
    }
}

/// Public account originals are deliberately separate from protected objects.
/// No Serialize implementation: transport consumers must select their channel.
#[derive(Clone, PartialEq, Eq)]
pub struct BootstrapExport {
    pub account: InitialAccountPrefix,
    pub protected: ProtectedBootstrap,
}
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedBootstrap {
    pub home: PendingHomeObjects,
    pub own_base: OwnBaseRecord,
}

/// Non-cloneable roots with generation-bound synchronous access. Secret drops
/// wipe M and every K; this is not a note writer and grants no authority
/// without the later writer fence.
///
/// Every key is opened when the base opens, or installed later: using one
/// never needs the personal key or any other native key, so no lock is ever
/// held across native key work.
pub struct OwnBase {
    genesis: VerifiedGenesis,
    record: OwnBaseRecord,
    package: InitialBaseKeyPackage,
    metadata: Secret<32>,
    /// The epoch verified history named current when the base opened; None
    /// while that epoch is closed.
    current: Option<[u8; 32]>,
    /// Every content key this device holds for the base, by key id: those
    /// in its keyring when it opened, and each installed since.
    epochs: RwLock<BTreeMap<[u8; 32], Secret<32>>>,
    capability: Arc<AccountCapability>,
}
impl OwnBase {
    pub fn id(&self) -> BaseId {
        self.genesis.base
    }
    /// M and the content key of the epoch verified current when the base
    /// opened. A verified epoch whose key is not held, or a closed one, is
    /// `KeyPending`: no other key, genesis included, stands in for it.
    pub fn with_keys<R>(
        &self,
        use_keys: impl FnOnce(&Secret<32>, &Secret<32>) -> R,
    ) -> Result<R, OwnBaseError> {
        let current = self.current.ok_or(OwnBaseError::KeyPending)?;
        self.with_epoch_key(Some(current), |metadata, content| {
            content.map(|content| use_keys(metadata, content))
        })?
        .ok_or(OwnBaseError::KeyPending)
    }
    /// M alone. Never `KeyPending`: controls, copies and every other
    /// metadata-only use go on while an epoch's key is missing or closed.
    pub fn with_metadata_key<R>(
        &self,
        use_key: impl FnOnce(&Secret<32>) -> R,
    ) -> Result<R, OwnBaseError> {
        self.current()?;
        let result = use_key(&self.metadata);
        self.current()?;
        Ok(result)
    }
    /// M and the content key of `epoch`, if this device holds it: None for a
    /// closed epoch (`None`) or one whose key is not held. Never another
    /// epoch's key.
    pub fn with_epoch_key<R>(
        &self,
        epoch: Option<[u8; 32]>,
        use_keys: impl FnOnce(&Secret<32>, Option<&Secret<32>>) -> R,
    ) -> Result<R, OwnBaseError> {
        self.current()?;
        // Copied out so that no lock of ours is held while the caller's
        // closure takes its own; the copy is wiped when it drops.
        let content = match epoch {
            Some(epoch) => self
                .epochs
                .read()
                .map_err(|_| OwnBaseError::Storage)?
                .get(&epoch)
                .map(|key| Secret::from_slice(key.expose()))
                .transpose()
                .map_err(|_| OwnBaseError::Storage)?,
            None => None,
        };
        let result = use_keys(&self.metadata, content.as_ref());
        self.current()?;
        Ok(result)
    }
    /// Keep `content`, an epoch key this device installed, for use from now
    /// on, under its committed id.
    pub fn remember_epoch(&self, content: Secret<32>) -> Result<(), OwnBaseError> {
        self.current()?;
        self.epochs
            .write()
            .map_err(|_| OwnBaseError::Storage)?
            .entry(key_id(&content))
            .or_insert(content);
        Ok(())
    }
    fn current(&self) -> Result<(), OwnBaseError> {
        if self.capability.is_current() {
            Ok(())
        } else {
            Err(OwnBaseError::Stale)
        }
    }
    /// Exact package, not re-sealed or re-signed. Native/protected consumers only.
    pub fn initial_key_package(&self) -> Result<&InitialBaseKeyPackage, OwnBaseError> {
        self.current()?;
        Ok(&self.package)
    }
    pub fn bootstrap_export<J: AccountJournal, S: DeviceKeyStore, P: PendingSetupProtector>(
        &self,
        account: &AccountOwner<J, S, P>,
    ) -> Result<BootstrapExport, OwnBaseError> {
        self.current()?;
        let (prefix, home) = account.initial_bootstrap(&self.capability)?;
        if prefix.anchor != self.genesis.creator || prefix.head != self.genesis.account_head {
            return Err(OwnBaseError::Invalid);
        }
        let result = BootstrapExport {
            account: prefix,
            protected: ProtectedBootstrap {
                home,
                own_base: self.record.clone(),
            },
        };
        self.current()?;
        Ok(result)
    }
}

fn historical(prefix: &InitialAccountPrefix) -> Result<VerifiedAccount, OwnBaseError> {
    if prefix.events.len() != 3 || prefix.head.position != 3 {
        return Err(OwnBaseError::Invalid);
    }
    VerifiedAccount::replay(
        prefix.anchor,
        &prefix.events.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        prefix.head,
    )
    .map_err(|_| OwnBaseError::Invalid)
}

/// The exact original package, authenticated against the account history at
/// its head without any private key: context, recipient and signatures of
/// both seals. Its key ids stay provisional until the genesis verifies.
struct Authenticated {
    descriptor: OpaqueEvent,
    package: InitialBaseKeyPackage,
    metadata: SealHeader,
    content: SealHeader,
}
fn authenticate(
    record: &OwnBaseRecord,
    history: &VerifiedAccount,
    capability: &AccountCapability,
) -> Result<Authenticated, OwnBaseError> {
    if !capability.is_current() {
        return Err(OwnBaseError::Stale);
    }
    if record.account != history.id().0 || record.account != capability.account_id().0 {
        return Err(OwnBaseError::Invalid);
    }
    let descriptor =
        OpaqueEvent::decode(&record.genesis_descriptor).map_err(|_| OwnBaseError::Invalid)?;
    let base = BaseId::from_genesis(&descriptor);
    if record.base != base.0 {
        return Err(OwnBaseError::Invalid);
    }
    let package = InitialBaseKeyPackage::decode(&record.initial_key_package)?;
    let m = SealHeader::decode(package.metadata_seal())?;
    if m.base != base
        || m.audience != [0; 32]
        || m.sender != history.id()
        || m.head != history.head()
    {
        return Err(OwnBaseError::Invalid);
    }
    let k = SealHeader::decode(package.content_seal())?;
    verify_seal(history, &m, package.metadata_seal())?;
    verify_seal(history, &k, package.content_seal())?;
    Ok(Authenticated {
        descriptor,
        package,
        metadata: m,
        content: k,
    })
}

/// Verify the exact original genesis under M and that it commits both
/// package key ids. No OwnBase (and hence no scoped key access) escapes before
/// all checks, including current requester authority, have succeeded.
fn finish(
    record: OwnBaseRecord,
    history: &VerifiedAccount,
    checked: Authenticated,
    metadata: Secret<32>,
    keys: impl FnOnce(&VerifiedGenesis) -> Result<HeldKeys, OwnBaseError>,
    capability: Arc<AccountCapability>,
) -> Result<OwnBase, OwnBaseError> {
    let (m, k) = (checked.metadata, checked.content);
    let genesis = verify_genesis(
        history,
        &checked.descriptor,
        &record.genesis_body,
        &metadata,
        1,
    )
    .map_err(|_| OwnBaseError::Invalid)?;
    if genesis.creator != history.id()
        || genesis.account_head != history.head()
        || genesis.device != m.device
        || genesis.base != m.base
        || genesis.metadata_key_id != m.key_id
        || genesis.content_key_id != k.key_id
    {
        return Err(OwnBaseError::Invalid);
    }
    let (current, epochs) = keys(&genesis)?;
    if !capability.is_current() {
        return Err(OwnBaseError::Stale);
    }
    Ok(OwnBase {
        genesis,
        record,
        package: checked.package,
        metadata,
        current,
        epochs: RwLock::new(epochs),
        capability,
    })
}

/// The epoch current when a base opens, and every content key held for it.
type HeldKeys = (Option<[u8; 32]>, BTreeMap<[u8; 32], Secret<32>>);

/// Open both roots from the original package with the personal key it was
/// sealed to, then verify the exact original genesis and both committed key
/// ids. Its content key is the genesis epoch's.
pub(crate) fn open_record(
    record: OwnBaseRecord,
    history: &VerifiedAccount,
    personal: &PersonalKey,
    capability: Arc<AccountCapability>,
) -> Result<OwnBase, OwnBaseError> {
    let checked = authenticate(&record, history, &capability)?;
    let metadata = open_seal(
        history,
        &checked.metadata,
        checked.package.metadata_seal(),
        personal,
    )?;
    let content = open_seal(
        history,
        &checked.content,
        checked.package.content_seal(),
        personal,
    )?;
    // open_seal re-derives ids from decrypted roots, not merely from the headers.
    finish(
        record,
        history,
        checked,
        metadata,
        |genesis| {
            let id = genesis.content_key_id;
            Ok((Some(id), BTreeMap::from([(id, content)])))
        },
        capability,
    )
}

/// Open the held roots from the local keyring with the accepted personal key:
/// M and every epoch's content key the keyring holds for the base, each
/// opening to its committed id; a row that does not is refused. The original
/// package is still authenticated in full, and its genesis verified under
/// the held M; the current epoch is the verified one.
fn open_held(
    record: OwnBaseRecord,
    history: &VerifiedAccount,
    personal: &PersonalKey,
    rows: &[EpochKeyRow],
    progress: Option<LogProgress>,
    capability: Arc<AccountCapability>,
) -> Result<OwnBase, OwnBaseError> {
    let checked = authenticate(&record, history, &capability)?;
    let (account, base) = (history.id(), record.base);
    let held = |purpose, key_id| keyring::held(rows, account, base, purpose, key_id, personal);
    let metadata =
        held(LocalKeyPurpose::Metadata, checked.metadata.key_id)?.ok_or(OwnBaseError::Invalid)?;
    let ordered = progress.filter(|p| p.position > 0);
    if ordered.is_some_and(|p| p.metadata_id != Some(checked.metadata.key_id)) {
        return Err(OwnBaseError::Invalid);
    }
    finish(
        record,
        history,
        checked,
        metadata,
        |genesis| {
            let current = match ordered {
                // Before its genesis is ordered, the base's epoch is the
                // genesis one.
                None => Some(genesis.content_key_id),
                // A closed epoch (None) has no write key: verified state
                // refuses every content seal (EpochClosed).
                Some(progress) => progress.epoch_id,
            };
            let mut epochs = BTreeMap::new();
            for row in rows
                .iter()
                .filter(|r| r.base == base && r.purpose == LocalKeyPurpose::Content as i64)
            {
                let key =
                    held(LocalKeyPurpose::Content, row.epoch_id)?.ok_or(OwnBaseError::Invalid)?;
                epochs.insert(row.epoch_id, key);
            }
            Ok((current, epochs))
        },
        capability,
    )
}

fn storage(error: StoreError) -> OwnBaseError {
    match error {
        StoreError::KeyringChanged | StoreError::AuthorityChanged => OwnBaseError::Stale,
        _ => OwnBaseError::Storage,
    }
}

/// The account at the head the record's package was sealed at: the retained
/// signup prefix for this device's own signup, never a replay of later
/// history; for a container that joined, its verified history at that head.
fn package_history<J, S, P>(
    account: &AccountOwner<J, S, P>,
    capability: &AccountCapability,
    database: &Mutex<DeviceDatabase>,
    record: &OwnBaseRecord,
) -> Result<VerifiedAccount, OwnBaseError>
where
    J: AccountJournal,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    let joined = database
        .lock()
        .map_err(|_| OwnBaseError::Storage)?
        .joined()
        .map_err(storage)?
        .is_some();
    if !joined {
        return historical(&account.initial_prefix(capability)?);
    }
    let position = crate::join::package_head(&record.initial_key_package)?;
    Ok(account.verified_at(capability, position)?)
}

/// Keep the record's metadata and genesis content roots in the keyring,
/// sealed to `personal`, the key accepted under `delivery`. Only the
/// package's own recipient opens them; a changed delivery refuses the insert.
#[allow(clippy::too_many_arguments)] // One install's exact inputs.
fn install<J, S, P>(
    account: &AccountOwner<J, S, P>,
    capability: &Arc<AccountCapability>,
    database: &Mutex<DeviceDatabase>,
    record: &OwnBaseRecord,
    history: &VerifiedAccount,
    personal: &PersonalKey,
    delivery: Option<&(u64, Vec<u8>)>,
) -> Result<(), OwnBaseError>
where
    J: AccountJournal,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    let opened = open_record(record.clone(), history, personal, capability.clone())?;
    let rows = opened.with_keys(|metadata, content| {
        Ok::<_, OwnBaseError>([
            keyring::sealed(
                history.id(),
                record.base,
                LocalKeyPurpose::Metadata,
                metadata,
                personal,
            )?,
            keyring::sealed(
                history.id(),
                record.base,
                LocalKeyPurpose::Content,
                content,
                personal,
            )?,
        ])
    })??;
    account.verified(capability)?;
    database
        .lock()
        .map_err(|_| OwnBaseError::Storage)?
        .install_epoch_keys(delivery, &rows, || capability.is_current())
        .map_err(storage)
}

/// Initialize the keyring for the held own base, if any, from its verified
/// original package. Never creates a base and opens no UI; runs on own-base
/// open and before accepting a personal-key rotation.
pub async fn ensure_keyring<J, S, P>(
    account: &mut AccountOwner<J, S, P>,
    capability: Arc<AccountCapability>,
    database: Arc<Mutex<DeviceDatabase>>,
) -> Result<(), OwnBaseError>
where
    J: AccountJournal,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    account.verified(&capability)?;
    let (record, rows, delivery) = {
        let db = database.lock().map_err(|_| OwnBaseError::Storage)?;
        let Some(record) = db.own_base().map_err(storage)? else {
            return Ok(());
        };
        let rows = db.epoch_keys(record.base).map_err(storage)?;
        (record, rows, db.personal_delivery().map_err(storage)?)
    };
    if keyring::complete(&rows, record.base) {
        return Ok(());
    }
    // All native key I/O is outside the database writer guard.
    let personal = account.open_current_personal(&capability).await?;
    let history = package_history(account, &capability, &database, &record)?;
    install(
        account,
        &capability,
        &database,
        &record,
        &history,
        &personal,
        delivery.as_ref(),
    )
}

/// Open a held own base: initialize its keyring if needed, then open from it.
async fn open_existing<J, S, P>(
    account: &mut AccountOwner<J, S, P>,
    capability: Arc<AccountCapability>,
    database: Arc<Mutex<DeviceDatabase>>,
    record: OwnBaseRecord,
) -> Result<OwnBase, OwnBaseError>
where
    J: AccountJournal,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    let delivery = database
        .lock()
        .map_err(|_| OwnBaseError::Storage)?
        .personal_delivery()
        .map_err(storage)?;
    // All native key I/O is outside the database writer guard.
    let personal = account.open_current_personal(&capability).await?;
    let history = package_history(account, &capability, &database, &record)?;
    let rows = database
        .lock()
        .map_err(|_| OwnBaseError::Storage)?
        .epoch_keys(record.base)
        .map_err(storage)?;
    if !keyring::complete(&rows, record.base) {
        install(
            account,
            &capability,
            &database,
            &record,
            &history,
            &personal,
            delivery.as_ref(),
        )?;
    }
    let (rows, progress) = {
        let db = database.lock().map_err(|_| OwnBaseError::Storage)?;
        // The rows are sealed to the key accepted under the delivery read
        // with them. Another process accepting a rotation since `personal`
        // was opened re-sealed them: that is a retry, not a bad row.
        if db.personal_delivery().map_err(storage)? != delivery {
            return Err(OwnBaseError::Stale);
        }
        (
            db.epoch_keys(record.base).map_err(storage)?,
            db.log_progress(LOG_BASE, record.base).map_err(storage)?,
        )
    };
    account.verified(&capability)?;
    open_held(record, &history, &personal, &rows, progress, capability)
}

pub async fn create_or_open<J, S, P>(
    account: &mut AccountOwner<J, S, P>,
    capability: Arc<AccountCapability>,
    database: Arc<Mutex<DeviceDatabase>>,
) -> Result<OwnBase, OwnBaseError>
where
    J: AccountJournal,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    account.verified(&capability)?;
    let (existing, joined) = {
        let db = database.lock().map_err(|_| OwnBaseError::Storage)?;
        (
            db.own_base().map_err(|_| OwnBaseError::Storage)?,
            db.joined().map_err(|_| OwnBaseError::Storage)?,
        )
    };
    if let Some(record) = existing {
        return open_existing(account, capability, database, record).await;
    }
    // A container that joined by pairing opens the base its admission kept;
    // it never creates one.
    if joined.is_some() {
        return Err(OwnBaseError::Invalid);
    }
    let prefix = account.initial_prefix(&capability)?;
    let history = historical(&prefix)?;
    // All native key I/O is outside the database writer guard.
    let personal = account.open_personal(&capability).await?;
    account.verified(&capability)?;
    // Signup must finish before later control activation. A missing row after
    // that point is not permission to invent a replacement base.
    if account.verified(&capability)?.head() != history.head() {
        return Err(OwnBaseError::Invalid);
    }
    let metadata = Secret::random();
    let content = Secret::random();
    let request = prepare_genesis(&history, capability.device_id(), &metadata, &content)
        .map_err(|_| OwnBaseError::Invalid)?;
    let signature = account
        .sign_content(&capability, request.signing_bytes())
        .await?;
    let (encoded, base) = request
        .finish(signature)
        .map_err(|_| OwnBaseError::Invalid)?;
    let genesis = verify_genesis(&history, &encoded.descriptor, &encoded.body, &metadata, 1)
        .map_err(|_| OwnBaseError::Invalid)?;
    let context = SealHeader {
        purpose: BaseKeyPurpose::Metadata,
        base,
        audience: [0; 32],
        key_id: genesis.metadata_key_id,
        recipient: hash(&personal.public()),
        sender: history.id(),
        device: capability.device_id(),
        head: history.head(),
    };
    let m = prepare_seal(&history, context, &personal.public(), &metadata)?;
    let signature = account.sign_content(&capability, m.signing_bytes()).await?;
    let m = m.finish(signature)?;
    let k = prepare_seal(
        &history,
        SealHeader {
            purpose: BaseKeyPurpose::Content,
            key_id: genesis.content_key_id,
            ..context
        },
        &personal.public(),
        &content,
    )?;
    let signature = account.sign_content(&capability, k.signing_bytes()).await?;
    let k = k.finish(signature)?;
    let package = InitialBaseKeyPackage::new(&m, &k)?;
    let candidate = OwnBaseRecord {
        account: history.id().0,
        base: base.0,
        genesis_descriptor: encoded.descriptor.encode(),
        genesis_body: encoded.body,
        initial_key_package: package.as_bytes().to_vec(),
    };
    // Verify the producer's complete candidate before durable publication.
    let checked = open_record(candidate, &history, &personal, capability.clone())?;
    account.verified(&capability)?;
    let winner = {
        let mut db = database.lock().map_err(|_| OwnBaseError::Storage)?;
        if db.own_base().map_err(|_| OwnBaseError::Storage)?.is_none() {
            let state = db
                .account_state()
                .map_err(|_| OwnBaseError::Storage)?
                .ok_or(OwnBaseError::Invalid)?;
            if state.anchor != history.id().0
                || state.head_position != history.head().position
                || state.head_hash != history.head().hash
                || state.stopped
            {
                return Err(OwnBaseError::Invalid);
            }
        }
        db.create_own_base_if_absent(&checked.record, || capability.is_current())
            .map_err(|_| OwnBaseError::Storage)?
    };
    // A concurrent creator's persisted winner is the only identity we expose.
    // Losing candidate roots and provisional receiver material wipe on drop.
    drop(checked);
    account.verified(&capability)?;
    open_existing(account, capability, database, winner).await
}
