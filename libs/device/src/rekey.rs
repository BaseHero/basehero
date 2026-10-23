//! The rekey of this container's own base after the account rotates its
//! personal key: the new content key sealed to each member, installed by an
//! `ACCOUNT_REKEY` this device's ordinary key signs, with no prompt.
//!
//! The new key is drawn here and sealed at once; only its seals and its id
//! leave this module, so no caller ever holds it. This device gets it back,
//! like every member, from its own seal once the base orders the rekey.
use crate::{
    ContainerId, Owner, OwnerError,
    base_keys::{BaseKeyPurpose, PreparedBaseKeySeal, SealHeader, prepare_seal},
};
use bh_account::VerifiedAccount;
use bh_crypto::{Secret, hash};
use bh_event::{
    key_id,
    rekey::{PreparedRekey, prepare_rekey_for, rotated_account},
};

/// A new content key for the own base, by its id, and its seals for each
/// member's current personal key, each still to be signed with this
/// device's ordinary key. The key itself is gone.
pub struct RekeySeals {
    pub key_id: [u8; 32],
    pub seals: Vec<PreparedBaseKeySeal>,
}

impl Owner {
    /// Prepare the `ACCOUNT_REKEY` installing `new_epoch` in this container's
    /// own base. `rotation` must be the next event of the base's copy of the
    /// account, with `confirmation` its ordering confirmation; `seals` seal
    /// `new_epoch` to each member's current personal key. The returned seal
    /// set is staged, by its commitment, before the control is appended.
    #[allow(clippy::too_many_arguments)] // One rekey's exact inputs.
    pub fn prepare_rekey(
        &self,
        id: ContainerId,
        anchor: &VerifiedAccount,
        metadata: &Secret<32>,
        rotation: &[u8],
        confirmation: &[u8],
        new_epoch: &Secret<32>,
        seals: Vec<Vec<u8>>,
    ) -> Result<PreparedRekey, OwnerError> {
        self.prepare_rekey_for(
            id,
            anchor,
            metadata,
            rotation,
            confirmation,
            key_id(new_epoch),
            seals,
        )
    }

    /// As `prepare_rekey`, naming the new key only by `new_id`, its id, as
    /// [`Owner::prepare_rekey_seals`] returns it with its signed seals.
    #[allow(clippy::too_many_arguments)] // One rekey's exact inputs.
    pub fn prepare_rekey_for(
        &self,
        id: ContainerId,
        anchor: &VerifiedAccount,
        metadata: &Secret<32>,
        rotation: &[u8],
        confirmation: &[u8],
        new_id: [u8; 32],
        seals: Vec<Vec<u8>>,
    ) -> Result<PreparedRekey, OwnerError> {
        let c = self.copy_context(id, anchor, metadata)?;
        prepare_rekey_for(
            c.base,
            &c.account,
            c.capability.device_id(),
            metadata,
            c.seen,
            c.receipt,
            rotation,
            confirmation,
            new_id,
            &seals,
        )
        .map_err(|_| OwnerError::CopyRefused)
    }

    /// Draw a new content key for this container's own base, whose copy of
    /// the account `rotation` (with its ordering `confirmation`) rotates
    /// next, and seal it to each member's personal key once the rotation
    /// applies: today the account's own, the new one. Each seal is sent by
    /// this device at that head, for its ordinary key to sign. The key is
    /// dropped before this returns; `CopyRefused` if `rotation` is not a
    /// rotation that takes effect there.
    pub fn prepare_rekey_seals(
        &self,
        id: ContainerId,
        anchor: &VerifiedAccount,
        metadata: &Secret<32>,
        rotation: &[u8],
        confirmation: &[u8],
    ) -> Result<RekeySeals, OwnerError> {
        let c = self.copy_context(id, anchor, metadata)?;
        let after = rotated_account(&c.account, rotation, confirmation, &c.root)
            .map_err(|_| OwnerError::CopyRefused)?;
        let recipient = *after
            .personal_public()
            .map_err(|_| OwnerError::CopyRefused)?;
        let content = Secret::<32>::random();
        let header = SealHeader {
            purpose: BaseKeyPurpose::Content,
            base: c.base,
            audience: [0; 32],
            key_id: key_id(&content),
            recipient: hash(&recipient),
            sender: after.id(),
            device: c.capability.device_id(),
            head: after.head(),
        };
        let seal = prepare_seal(&after, header, &recipient, &content)
            .map_err(|_| OwnerError::CopyRefused)?;
        Ok(RekeySeals {
            key_id: header.key_id,
            seals: vec![seal],
        })
    }
}
