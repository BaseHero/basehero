//! Base introduction: the descriptor digest is the base ID. The account
//! projection must be independently verified at exactly the named head.
use crate::codec::{
    Binding, CLASS_CONTROL, Encoded, Error, EventSigningRequest, GENESIS, Payload, key_id,
    open_body, prepare_seal,
};
use crate::history::{History, Outcome};
use bh_account::{AccountId, DeviceId, Head as AccountHead, VerifiedAccount};
use bh_crypto::{Secret, random};
use bh_sync::{BaseId, Commitment, EventId, Head, OpaqueEvent, Route, receipt::RECEIPT_LEN};

pub struct GenesisSigningRequest(EventSigningRequest);
impl GenesisSigningRequest {
    pub fn signing_bytes(&self) -> &[u8] {
        self.0.signing_bytes()
    }
    pub fn expected_key(&self) -> &[u8; 32] {
        self.0.expected_key()
    }
    pub fn finish(self, signature: [u8; 64]) -> Result<(Encoded, BaseId), Error> {
        let encoded = self.0.finish(signature)?;
        let base = BaseId::from_genesis(&encoded.descriptor);
        Ok((encoded, base))
    }
}

/// Prepare an ordinary device signature without holding the device private key.
/// `metadata` is M; `content` is K_e. Both are independently provisioned roots.
pub fn prepare_genesis(
    creator: &VerifiedAccount,
    device: DeviceId,
    metadata: &Secret<32>,
    content: &Secret<32>,
) -> Result<GenesisSigningRequest, Error> {
    let expected = *creator
        .active_device(device)
        .map_err(|_| Error::Invalid)?
        .signing();
    let metadata_id = key_id(metadata);
    let mut data = Vec::with_capacity(168);
    data.extend(creator.id().0);
    data.extend(creator.head().position.to_be_bytes());
    data.extend(creator.head().hash);
    data.extend([0; 32]);
    data.extend(key_id(content));
    data.extend(metadata_id);
    Ok(GenesisSigningRequest(prepare_seal(
        Binding {
            version: 1,
            highest: 1,
            mode: 1,
            base: [0; 32],
            audience: [0; 32],
            epoch: metadata_id,
            event_id: EventId(random()),
            account: creator.id(),
            device,
            account_head: creator.head(),
            seen: Head::EMPTY,
            seen_control: [0; 32],
            class: CLASS_CONTROL,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: [0; RECEIPT_LEN],
        },
        Payload {
            kind: GENESIS,
            data: &data,
        },
        expected,
        metadata,
        None,
    )?))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifiedGenesis {
    pub base: BaseId,
    pub creator: AccountId,
    pub device: DeviceId,
    pub account_head: AccountHead,
    pub metadata_key_id: [u8; 32],
    pub content_key_id: [u8; 32],
}

/// Verify the original introduction using History's shared genesis checks.
/// A digest is a base ID only after the creator account and original pass.
/// This is historical verification, not a current membership credential.
pub fn verify_genesis(
    creator: &VerifiedAccount,
    descriptor: &OpaqueEvent,
    body: &[u8],
    metadata: &Secret<32>,
    remembered_floor: u16,
) -> Result<VerifiedGenesis, Outcome> {
    let base = BaseId::from_genesis(descriptor);
    let mut history = History::anchored(creator, base, None, remembered_floor)
        .map_err(|_| Outcome::IntegrityStop)?;
    let ordered = Commitment::order(base, Head::EMPTY, descriptor, Route::Control)
        .map_err(|_| Outcome::IntegrityStop)?;
    judge_genesis(&mut history, &ordered, descriptor, body, metadata)
}

/// Judge an ordered genesis with History's checks and return its IDs.
pub(crate) fn judge_genesis(
    history: &mut History,
    ordered: &Commitment,
    descriptor: &OpaqueEvent,
    body: &[u8],
    metadata: &Secret<32>,
) -> Result<VerifiedGenesis, Outcome> {
    history.prepare(ordered, descriptor, Some(body), metadata, None)?;
    // The checked binding and body are read again solely to return their IDs;
    // no independent validation path may accept a genesis History rejects.
    let signed = history.inspect(ordered, descriptor, metadata)?;
    let payload = open_body(&signed, body, metadata, None).map_err(|_| Outcome::IntegrityStop)?;
    Ok(VerifiedGenesis {
        base: ordered.base(),
        creator: signed.account,
        device: signed.device,
        account_head: signed.account_head,
        metadata_key_id: signed.epoch,
        content_key_id: payload.data()[104..136]
            .try_into()
            .expect("validated genesis length"),
    })
}
