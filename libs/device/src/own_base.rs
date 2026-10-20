//! Create-once signup base. Historical introduction proof and current native
//! authority are separate: neither an anchor nor an unregistered genesis is an
//! ordered base head, a server receipt, or permission to sign a successor.
use crate::base_keys::{
    BaseKeyPurpose, InitialBaseKeyPackage, SealError, SealHeader, open_seal, prepare_seal,
};
use bh_account::{
    VerifiedAccount,
    journal::{AccountJournal, PendingSetupProtector},
    owner::{
        AccountCapability, AccountOwner, InitialAccountPrefix, OwnerError, PendingHomeObjects,
    },
    personal::PersonalKey,
    platform::DeviceKeyStore,
};
use bh_crypto::{Secret, hash};
use bh_event::{VerifiedGenesis, prepare_genesis, verify_genesis};
use bh_storage::{DeviceDatabase, own_base::OwnBaseRecord};
use bh_sync::{BaseId, OpaqueEvent};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnBaseError {
    Stale,
    Account(OwnerError),
    Storage,
    Invalid,
    Seal(SealError),
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
/// wipe M and K; this is not a note writer and grants no authority without the
/// later writer fence.
pub struct OwnBase {
    genesis: VerifiedGenesis,
    record: OwnBaseRecord,
    package: InitialBaseKeyPackage,
    metadata: Secret<32>,
    content: Secret<32>,
    capability: Arc<AccountCapability>,
}
impl OwnBase {
    pub fn id(&self) -> BaseId {
        self.genesis.base
    }
    pub fn with_keys<R>(
        &self,
        use_keys: impl FnOnce(&Secret<32>, &Secret<32>) -> R,
    ) -> Result<R, OwnBaseError> {
        self.current()?;
        let result = use_keys(&self.metadata, &self.content);
        self.current()?;
        Ok(result)
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

/// Reopen both seals provisionally, then verify the exact original genesis and
/// both committed key ids. No OwnBase (and hence no scoped key access) escapes
/// before all checks, including current requester authority, have succeeded.
pub(crate) fn open_record(
    record: OwnBaseRecord,
    history: &VerifiedAccount,
    personal: &PersonalKey,
    capability: Arc<AccountCapability>,
) -> Result<OwnBase, OwnBaseError> {
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
    let metadata = open_seal(history, &m, package.metadata_seal(), personal)?;
    let genesis = verify_genesis(history, &descriptor, &record.genesis_body, &metadata, 1)
        .map_err(|_| OwnBaseError::Invalid)?;
    let k = SealHeader::decode(package.content_seal())?;
    if genesis.creator != history.id()
        || genesis.account_head != history.head()
        || genesis.device != m.device
        || genesis.base != base
        || genesis.metadata_key_id != m.key_id
        || genesis.content_key_id != k.key_id
    {
        return Err(OwnBaseError::Invalid);
    }
    let content = open_seal(history, &k, package.content_seal(), personal)?;
    // open_seal re-derives ids from decrypted roots, not merely from the headers.
    if !capability.is_current() {
        return Err(OwnBaseError::Stale);
    }
    Ok(OwnBase {
        genesis,
        record,
        package,
        metadata,
        content,
        capability,
    })
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
    // A container that joined by pairing opens its base with the personal
    // key its addition delivered; it never creates one.
    let joined = database
        .lock()
        .map_err(|_| OwnBaseError::Storage)?
        .joined()
        .map_err(|_| OwnBaseError::Storage)?;
    if let Some(joined) = joined {
        let (Some(delivery), Some(added_at)) = (joined.delivery, joined.added_at) else {
            return Err(OwnBaseError::Invalid);
        };
        let record = database
            .lock()
            .map_err(|_| OwnBaseError::Storage)?
            .own_base()
            .map_err(|_| OwnBaseError::Storage)?
            .ok_or(OwnBaseError::Invalid)?;
        let personal = account
            .open_delivered_personal(&capability, &delivery, added_at)
            .await?;
        let history = account.verified_at(
            &capability,
            crate::join::package_head(&record.initial_key_package)?,
        )?;
        return open_record(record, &history, &personal, capability);
    }
    let prefix = account.initial_prefix(&capability)?;
    let history = historical(&prefix)?;
    let existing = database
        .lock()
        .map_err(|_| OwnBaseError::Storage)?
        .own_base()
        .map_err(|_| OwnBaseError::Storage)?;
    // All native key I/O is outside the database writer guard.
    let personal = account.open_personal(&capability).await?;
    account.verified(&capability)?;
    if let Some(record) = existing {
        return open_record(record, &history, &personal, capability);
    }
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
    account.verified(&capability)?;
    open_record(winner, &history, &personal, capability)
}
