//! Current authority plus immutable historical evidence at a verified cut.
use super::*;
use bh_storage::account::{AccountDeviceRow, AccountProjectionDelta};

pub(crate) trait HistoryIndex: Send + Sync {
    fn event_matches(&self, cut: Head, position: u64, bytes: &[u8]) -> Result<bool, Error>;
    fn device_seen(&self, cut: Head, id: &DeviceId) -> Result<bool, Error>;
    fn key_used(&self, cut: Head, key: KeyUse<'_>) -> Result<bool, Error>;
}
pub(crate) enum KeyUse<'a> {
    Signing(&'a [u8; 32]),
    Receiving(&'a [u8; 1216]),
}
pub(crate) fn receiving_hash(key: &[u8; 1216]) -> [u8; 32] {
    let mut bytes = b"BaseHero receiving key\0".to_vec();
    bytes.extend_from_slice(key);
    hash(&bytes)
}
#[derive(Clone)]
pub(super) struct Indexed {
    pub cut: Head,
    pub epoch: u64,
    pub index: Arc<dyn HistoryIndex>,
}
#[derive(Clone, Default)]
pub(super) struct Recent {
    pub heads: BTreeMap<u64, [u8; 32]>,
    pub added: BTreeMap<DeviceId, (DevicePublicKeys, u64)>,
    pub removed: BTreeMap<DeviceId, u64>,
    pub used_signing: BTreeMap<[u8; 32], u64>,
    pub used_receiving: BTreeMap<[u8; 1216], u64>,
}
impl VerifiedAccount {
    pub(super) fn key_used(&self, key: KeyUse<'_>) -> Result<bool, Error> {
        let recent = match key {
            KeyUse::Signing(k) => self.recent.used_signing.contains_key(k),
            KeyUse::Receiving(k) => self.recent.used_receiving.contains_key(k),
        };
        if recent {
            return Ok(true);
        }
        self.indexed
            .as_ref()
            .map_or(Ok(false), |i| i.index.key_used(i.cut, key))
    }
    /// Owned candidate: any error discards all partial work, without changing
    /// the accepted view or latching an integrity stop on evidence unavailability.
    pub fn applied_batch(mut self, events: &[&[u8]]) -> Result<Self, Error> {
        self.running()?;
        for bytes in events {
            self.apply_one(bytes)?;
        }
        Ok(self)
    }
    pub(crate) fn summary(&self) -> Vec<u8> {
        let mut out = b"BHACSM01".to_vec();
        out.extend(self.recovery.signing);
        out.extend(self.recovery.receiving);
        out.extend(self.first.0);
        out.push(u8::from(self.record_digest.is_some()));
        out.extend(self.record_digest.unwrap_or([0; 32]));
        out.push(u8::from(self.personal.is_some()));
        if let Some(p) = &self.personal {
            out.extend(p.public);
            out.extend(p.device_digest);
            out.extend(p.recovery_digest);
        } else {
            out.resize(out.len() + 1280, 0);
        }
        out
    }
    pub(crate) fn from_index(
        id: AccountId,
        head: Head,
        summary: &[u8],
        rows: Vec<AccountDeviceRow>,
        epoch: u64,
        index: Arc<dyn HistoryIndex>,
    ) -> Result<Self, Error> {
        let mut r = Reader(summary);
        if r.take(8)? != b"BHACSM01" || head.position == 0 {
            return Err(Error::Malformed);
        }
        let recovery = RecoveryPublicKeys::new(r.array()?, r.array()?);
        let first = DeviceId(r.array()?);
        let has_record = r.array::<1>()?[0];
        let digest = r.array()?;
        let has_personal = r.array::<1>()?[0];
        let publication = PersonalPublication {
            public: r.array()?,
            device_digest: r.array()?,
            recovery_digest: r.array()?,
        };
        if !r.0.is_empty()
            || has_record > 1
            || has_personal > 1
            || (has_record == 1 && head.position < 2)
            || (has_personal == 1 && (head.position < 3 || has_record == 0))
        {
            return Err(Error::Malformed);
        }
        let mut active = BTreeMap::new();
        let mut signing = std::collections::BTreeSet::from([recovery.signing]);
        let mut receiving = std::collections::BTreeSet::from([recovery.receiving]);
        for row in rows {
            let mut input = Reader(&row.keys);
            let keys = DevicePublicKeys::decode(&mut input)?;
            if !input.0.is_empty()
                || keys.id().0 != row.device
                || row.added == 0
                || row.added > head.position
                || !signing.insert(keys.signing)
                || !signing.insert(keys.control)
                || !receiving.insert(keys.receiving)
                || active.insert(keys.id(), keys).is_some()
            {
                return Err(Error::Malformed);
            }
        }
        Ok(Self {
            id,
            head,
            active,
            recovery,
            first,
            record_digest: (has_record == 1).then_some(digest),
            personal: (has_personal == 1).then_some(publication),
            stopped: false,
            recent: Recent::default(),
            indexed: Some(Indexed {
                cut: head,
                epoch,
                index,
            }),
        })
    }
    pub(crate) fn pin_empty(mut self, epoch: u64, index: Arc<dyn HistoryIndex>) -> Self {
        self.indexed = Some(Indexed {
            cut: Head {
                position: 0,
                hash: [0; 32],
            },
            epoch,
            index,
        });
        self
    }
    pub(crate) fn rebase(mut self, epoch: u64, index: Arc<dyn HistoryIndex>) -> Self {
        self.indexed = Some(Indexed {
            cut: self.head,
            epoch,
            index,
        });
        self.recent = Recent::default();
        self
    }
    pub(crate) fn delta(&self) -> AccountProjectionDelta {
        let added = self
            .recent
            .added
            .iter()
            .map(|(id, (keys, position))| {
                let mut bytes = Vec::with_capacity(1280);
                keys.encode(&mut bytes);
                AccountDeviceRow {
                    device: id.0,
                    keys: bytes,
                    added: *position,
                }
            })
            .collect();
        let mut keys: Vec<_> = self
            .recent
            .used_signing
            .iter()
            .map(|(key, pos)| (0, *key, *pos))
            .collect();
        keys.extend(
            self.recent
                .used_receiving
                .iter()
                .map(|(key, pos)| (1, receiving_hash(key), *pos)),
        );
        AccountProjectionDelta {
            epoch: self.indexed.as_ref().map(|i| i.epoch),
            expected: self
                .indexed
                .as_ref()
                .map_or((0, [0; 32]), |i| (i.cut.position, i.cut.hash)),
            through: (self.head.position, self.head.hash),
            summary: self.summary(),
            added,
            removed: self
                .recent
                .removed
                .iter()
                .map(|(id, p)| (id.0, *p))
                .collect(),
            keys,
        }
    }
}
