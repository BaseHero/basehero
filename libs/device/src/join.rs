//! A container joining an existing account by QR. Pairing verifies the
//! account log from genesis and this device's admission in it, and reads the
//! own base's genesis; `admit` commits that verified result here: the
//! account history with its confirmations through the account owner, then,
//! once the own base's record opens with the personal key the addition
//! delivered, the delivery, own base and registration in one transaction. The container stays
//! unusable (`authorize` refuses it) until its bootstrap reads the base and
//! `activate_joined` commits.
//!
//! A container that recovered the account, with no device left to pair
//! with, is admitted the same way from what recovery verified
//! (`admit_current`): the own base's key package is the one the account's
//! directory entry for the base carries, while that entry is the base's
//! genesis epoch under the current personal key. A base whose epoch has
//! changed since is admitted only from an admission snapshot; until then
//! its admission waits, with the account history kept.
use crate::{
    ContainerId, Owner, OwnerError,
    base_keys::{BaseKeyPurpose, InitialBaseKeyPackage, SealHeader, open_seal},
    own_base::{OwnBaseError, open_record},
};
use bh_account::{
    AccountId, ConfirmedTime,
    journal::{AccountJournal, PendingSetupProtector},
    owner::{AccountCapability, AccountLoad, AccountOwner, OwnerError as AccountError},
    personal::PersonalKey,
    platform::DeviceKeyStore,
};
use bh_storage::{joined::JoinedRecord, own_base::OwnBaseRecord};
use bh_sync::{BaseId, OpaqueEvent};
use std::sync::Arc;

/// One original with its confirmed time and exact confirmation bytes, as
/// pairing verified them under the hosting root; `None` only for genesis.
pub type TimedOriginal = (Vec<u8>, Option<(ConfirmedTime, Vec<u8>)>);

/// What pairing verified: the account's original history from genesis
/// (under the code's anchor), each event with its confirmation, the
/// position of this device's addition and the exact signed delivery it
/// carried, and the own base's genesis as its log orders it with the key
/// package the showing device sent.
pub struct Admission {
    pub account: AccountId,
    pub history: Vec<TimedOriginal>,
    pub added_at: u64,
    pub delivery: Vec<u8>,
    pub base: [u8; 32],
    pub genesis_descriptor: Vec<u8>,
    pub genesis_body: Vec<u8>,
    pub package: Vec<u8>,
    /// The hosting root pinned for the base's log.
    pub hosting_root: [u8; 32],
}

/// What recovery verified: as `Admission`, with the own base's directory
/// entry in place of a key package: its epoch and the seals of its metadata
/// key and of that epoch's content key.
pub struct CurrentAdmission {
    pub account: AccountId,
    pub history: Vec<TimedOriginal>,
    pub added_at: u64,
    pub delivery: Vec<u8>,
    pub base: [u8; 32],
    pub genesis_descriptor: Vec<u8>,
    pub genesis_body: Vec<u8>,
    pub epoch_id: [u8; 32],
    pub metadata_seal: Vec<u8>,
    pub content_seal: Vec<u8>,
    pub hosting_root: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinError {
    /// The account owner refused the history or could not act.
    Account(AccountError),
    /// The account is not active on this device after the commit.
    NotActive,
    /// The own base's record does not open or verify.
    OwnBase(OwnBaseError),
    Owner,
    /// The own base's epoch changed since its genesis: only an admission
    /// snapshot admits it. The account history is kept; nothing of the base.
    AwaitingAdmission,
}
impl From<AccountError> for JoinError {
    fn from(error: AccountError) -> Self {
        Self::Account(error)
    }
}
impl From<OwnBaseError> for JoinError {
    fn from(error: OwnBaseError) -> Self {
        Self::OwnBase(error)
    }
}

/// The account head an own base's key package was sealed at: its genesis's.
pub(crate) fn package_head(package: &[u8]) -> Result<u64, OwnBaseError> {
    let package = InitialBaseKeyPackage::decode(package)?;
    Ok(SealHeader::decode(package.metadata_seal())?.head.position)
}

/// Commit a verified admission. Repeatable after an interruption: an
/// account already committed is kept, and the one transaction repeats.
pub async fn admit<J, S, P>(
    account: &mut AccountOwner<J, S, P>,
    owner: &Owner,
    id: ContainerId,
    admission: &Admission,
) -> Result<Arc<AccountCapability>, JoinError>
where
    J: AccountJournal,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    let (capability, personal) = adopt(
        account,
        owner,
        id,
        admission.account,
        &admission.history,
        &admission.delivery,
        admission.added_at,
    )
    .await?;
    let record = OwnBaseRecord {
        account: admission.account.0,
        base: admission.base,
        genesis_descriptor: admission.genesis_descriptor.clone(),
        genesis_body: admission.genesis_body.clone(),
        initial_key_package: admission.package.clone(),
    };
    keep(
        account,
        owner,
        id,
        &capability,
        &personal,
        record,
        &admission.delivery,
        admission.added_at,
        admission.hosting_root,
    )?;
    Ok(capability)
}

/// Commit what recovery verified, as `admit` does, once the own base's
/// directory entry gives its genesis epoch's package under the current
/// personal key: `AwaitingAdmission` (history kept, nothing of the base) if
/// the base's epoch or the personal key changed since, which its seals
/// show. An entry naming another base or whose content seal is another
/// epoch's, or a seal under another key or by a device not active where it
/// was made, is refused and keeps nothing of the base. Repeatable as
/// `admit` is.
pub async fn admit_current<J, S, P>(
    account: &mut AccountOwner<J, S, P>,
    owner: &Owner,
    id: ContainerId,
    admission: &CurrentAdmission,
) -> Result<Arc<AccountCapability>, JoinError>
where
    J: AccountJournal,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    // A recovered container joins with no pairing hint to keep.
    match owner.joined(id).map_err(|_| JoinError::Owner)? {
        Some(joined) if joined.account == admission.account.0 => {}
        _ => owner
            .record_join_hint(id, admission.account, &[])
            .map_err(|_| JoinError::Owner)?,
    }
    let (capability, personal) = adopt(
        account,
        owner,
        id,
        admission.account,
        &admission.history,
        &admission.delivery,
        admission.added_at,
    )
    .await?;
    let package = current_package(account, &capability, &personal, admission)?;
    let record = OwnBaseRecord {
        account: admission.account.0,
        base: admission.base,
        genesis_descriptor: admission.genesis_descriptor.clone(),
        genesis_body: admission.genesis_body.clone(),
        initial_key_package: package,
    };
    keep(
        account,
        owner,
        id,
        &capability,
        &personal,
        record,
        &admission.delivery,
        admission.added_at,
        admission.hosting_root,
    )?;
    Ok(capability)
}

/// The account history committed and active here, and the personal key its
/// addition of this device delivered.
async fn adopt<J, S, P>(
    account: &mut AccountOwner<J, S, P>,
    owner: &Owner,
    id: ContainerId,
    anchor: AccountId,
    history: &[TimedOriginal],
    delivery: &[u8],
    added_at: u64,
) -> Result<(Arc<AccountCapability>, PersonalKey), JoinError>
where
    J: AccountJournal,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    let history: Vec<_> = history
        .iter()
        .map(|(original, evidence)| (original.as_slice(), evidence.clone()))
        .collect();
    account.adopt_joined_timed(anchor, &history)?;
    let AccountLoad::Active(capability) = account.activate().await? else {
        return Err(JoinError::NotActive);
    };
    let capability = Arc::new(capability);
    let verified = account.verified(&capability)?.clone();
    owner.anchor(id, &verified).map_err(|_| JoinError::Owner)?;
    let personal = account
        .open_delivered_personal(&capability, delivery, added_at)
        .await?;
    Ok((capability, personal))
}

/// Open both roots of `record` before anything about the base is kept, then
/// keep the delivery, own base and registration in one transaction.
#[allow(clippy::too_many_arguments)] // One admission's exact verified parts.
fn keep<J, S, P>(
    account: &AccountOwner<J, S, P>,
    owner: &Owner,
    id: ContainerId,
    capability: &Arc<AccountCapability>,
    personal: &PersonalKey,
    record: OwnBaseRecord,
    delivery: &[u8],
    added_at: u64,
    hosting_root: [u8; 32],
) -> Result<(), JoinError>
where
    J: AccountJournal,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    let historical = account.verified_at(capability, package_head(&record.initial_key_package)?)?;
    drop(open_record(
        record.clone(),
        &historical,
        personal,
        capability.clone(),
    )?);
    let database = owner.shared_database(id).map_err(|_| JoinError::Owner)?;
    database
        .lock()
        .expect("container writer lock")
        .commit_joined_admission(delivery, added_at, &record, hosting_root)
        .map_err(|_| JoinError::Owner)?;
    owner.install_stored_bindings(id);
    Ok(())
}

/// The own base's original key package, from its directory entry's seals,
/// while they are the genesis epoch's under the current personal key.
fn current_package<J, S, P>(
    account: &AccountOwner<J, S, P>,
    capability: &AccountCapability,
    personal: &PersonalKey,
    admission: &CurrentAdmission,
) -> Result<Vec<u8>, JoinError>
where
    J: AccountJournal,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    let refused = JoinError::OwnBase(OwnBaseError::Invalid);
    let descriptor = OpaqueEvent::decode(&admission.genesis_descriptor).map_err(|_| refused)?;
    let metadata = SealHeader::decode(&admission.metadata_seal).map_err(OwnBaseError::from)?;
    if BaseId::from_genesis(&descriptor).0 != admission.base
        || metadata.purpose != BaseKeyPurpose::Metadata
        || metadata.base.0 != admission.base
        || metadata.audience != [0; 32]
        || metadata.sender != admission.account
    {
        return Err(refused);
    }
    let sealed_at = account
        .verified_at(capability, metadata.head.position)
        .map_err(|_| refused)?;
    // Sealed to the current personal key by a device active where it was
    // made: a seal to a replaced key is refused here.
    let root = open_seal(&sealed_at, &metadata, &admission.metadata_seal, personal)
        .map_err(OwnBaseError::from)?;
    if SealHeader::decode(&admission.content_seal)
        .map_err(OwnBaseError::from)?
        .key_id
        != admission.epoch_id
    {
        return Err(refused);
    }
    // The original pair was sealed at the head the genesis names, under
    // this M, for its epoch. Seals of the base's M made later come only
    // after its epoch or the personal key changed: that base is admitted
    // from a snapshot.
    match bh_event::verify_genesis(&sealed_at, &descriptor, &admission.genesis_body, &root, 1) {
        Ok(genesis)
            if genesis.account_head == sealed_at.head()
                && genesis.content_key_id == admission.epoch_id => {}
        _ => return Err(JoinError::AwaitingAdmission),
    }
    // The pair must be the base's original one: `open_record` checks it
    // against the genesis, at the genesis's head, by its creator.
    Ok(
        InitialBaseKeyPackage::new(&admission.metadata_seal, &admission.content_seal)
            .map_err(OwnBaseError::from)?
            .as_bytes()
            .to_vec(),
    )
}

impl Owner {
    /// The joined-container state, if this container joined by pairing.
    pub fn joined(&self, id: ContainerId) -> Result<Option<JoinedRecord>, OwnerError> {
        let database = self.shared_database(id)?;
        Ok(database.lock().expect("container writer lock").joined()?)
    }
    /// Keep the showing device's opened hint while the admission it leads to
    /// is verified.
    pub fn record_join_hint(
        &self,
        id: ContainerId,
        account: AccountId,
        hint: &[u8],
    ) -> Result<(), OwnerError> {
        let database = self.shared_database(id)?;
        Ok(database
            .lock()
            .expect("container writer lock")
            .record_join_hint(account.0, hint)?)
    }
    /// Make a joined container usable, in one commit, once its bootstrap has
    /// read the own base to its known tail.
    pub fn activate_joined(&self, id: ContainerId) -> Result<(), OwnerError> {
        let database = self.shared_database(id)?;
        Ok(database
            .lock()
            .expect("container writer lock")
            .activate_joined()?)
    }
}
