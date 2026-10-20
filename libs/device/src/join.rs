//! A container joining an existing account by QR. Pairing verifies the
//! account log from genesis and this device's admission in it, and reads the
//! own base's genesis; `admit` commits that verified result here: the
//! account history through the account owner, then, once the own base's
//! record opens with the personal key the addition delivered, the delivery,
//! own base and registration in one transaction. The container stays
//! unusable (`authorize` refuses it) until its bootstrap reads the base and
//! `activate_joined` commits.
use crate::{
    ContainerId, Owner, OwnerError,
    base_keys::{InitialBaseKeyPackage, SealHeader},
    own_base::{OwnBaseError, open_record},
};
use bh_account::{
    AccountId,
    journal::{AccountJournal, PendingSetupProtector},
    owner::{AccountCapability, AccountLoad, AccountOwner, OwnerError as AccountError},
    platform::DeviceKeyStore,
};
use bh_storage::{joined::JoinedRecord, own_base::OwnBaseRecord};
use std::sync::Arc;

/// What pairing verified: the account's original history from genesis
/// (under the code's anchor), the position of this device's addition and the
/// exact signed delivery it carried, and the own base's genesis as its log
/// orders it with the key package the showing device sent.
pub struct Admission {
    pub account: AccountId,
    pub history: Vec<Vec<u8>>,
    pub added_at: u64,
    pub delivery: Vec<u8>,
    pub base: [u8; 32],
    pub genesis_descriptor: Vec<u8>,
    pub genesis_body: Vec<u8>,
    pub package: Vec<u8>,
    /// The hosting root pinned for the base's log.
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
    let history: Vec<&[u8]> = admission.history.iter().map(Vec::as_slice).collect();
    account.adopt_joined(admission.account, &history)?;
    let AccountLoad::Active(capability) = account.activate().await? else {
        return Err(JoinError::NotActive);
    };
    let capability = Arc::new(capability);
    let verified = account.verified(&capability)?.clone();
    owner.anchor(id, &verified).map_err(|_| JoinError::Owner)?;
    let record = OwnBaseRecord {
        account: admission.account.0,
        base: admission.base,
        genesis_descriptor: admission.genesis_descriptor.clone(),
        genesis_body: admission.genesis_body.clone(),
        initial_key_package: admission.package.clone(),
    };
    // Open both roots before anything about the base is kept.
    let personal = account
        .open_delivered_personal(&capability, &admission.delivery, admission.added_at)
        .await?;
    let historical = account.verified_at(&capability, package_head(&admission.package)?)?;
    drop(open_record(
        record.clone(),
        &historical,
        &personal,
        capability.clone(),
    )?);
    let database = owner.shared_database(id).map_err(|_| JoinError::Owner)?;
    database
        .lock()
        .expect("container writer lock")
        .commit_joined_admission(
            &admission.delivery,
            admission.added_at,
            &record,
            admission.hosting_root,
        )
        .map_err(|_| JoinError::Owner)?;
    owner.install_stored_bindings(id);
    Ok(capability)
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
