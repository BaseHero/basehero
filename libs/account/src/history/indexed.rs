//! Current authority plus immutable historical evidence at a verified cut.
use super::*;
use crate::trust::{Effect, PendingRemoval};
use bh_storage::account::{AccountDeviceRow, AccountProjectionDelta};

pub trait HistoryIndex: Send + Sync {
    fn event_matches(&self, cut: Head, position: u64, bytes: &[u8]) -> Result<bool, Error>;
    fn device_seen(&self, cut: Head, id: &DeviceId) -> Result<bool, Error>;
    fn key_used(&self, cut: Head, key: KeyUse<'_>) -> Result<bool, Error>;
    /// The stored confirmed time of an entry, if any.
    fn confirmed_time(&self, cut: Head, position: u64) -> Result<Option<ConfirmedTime>, Error>;
}
pub enum KeyUse<'a> {
    Signing(&'a [u8; 32]),
    Receiving(&'a [u8; 1216]),
}
pub fn receiving_hash(key: &[u8; 1216]) -> [u8; 32] {
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
    /// Confirmed times of entries applied since the cut.
    pub times: BTreeMap<u64, ConfirmedTime>,
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
    pub fn applied_batch(self, events: &[&[u8]]) -> Result<Self, Error> {
        let timed: Vec<_> = events.iter().map(|bytes| (*bytes, None)).collect();
        self.applied_batch_timed(&timed)
    }
    /// `applied_batch` with each event's confirmed time, if any.
    pub fn applied_batch_timed(
        mut self,
        events: &[(&[u8], Option<ConfirmedTime>)],
    ) -> Result<Self, Error> {
        self.running()?;
        for (bytes, time) in events {
            self.apply_one(bytes, *time)?;
        }
        Ok(self)
    }
    /// Version 2 is version 1's fields followed by confirmed time, pending
    /// requests and unfulfilled effects: bounded by membership and the
    /// changes since the last rotation, not by history. How resolved
    /// requests ended is not kept.
    pub(crate) fn summary(&self) -> Vec<u8> {
        let mut out = b"BHACSM02".to_vec();
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
        let t = &self.timeline;
        let (first, last) = (
            t.first.unwrap_or((0, 0)),
            t.last.unwrap_or(ConfirmedTime {
                earliest_ms: 0,
                latest_ms: 0,
            }),
        );
        out.push(u8::from(t.first.is_some()));
        for value in [first.0, first.1, last.earliest_ms, last.latest_ms] {
            out.extend(value.to_be_bytes());
        }
        out.extend((t.pending.len() as u32).to_be_bytes());
        for p in t.pending.values() {
            out.extend(p.request.to_be_bytes());
            out.extend(p.target.0);
            out.push(u8::from(p.by.is_some()));
            out.extend(p.by.map_or([0; 32], |by| by.0));
            out.extend(p.deadline_ms.to_be_bytes());
        }
        out.extend((t.effects.len() as u32).to_be_bytes());
        for (position, effect) in &t.effects {
            let (kind, device) = match effect.reason {
                RotationReason::Removal { target, .. } => (0, target.0),
                RotationReason::RemovedNow { target, .. } => (1, target.0),
                RotationReason::RemovedSelf { device, .. } => (2, device.0),
                RotationReason::RecoveryReplaced { .. } => (3, [0; 32]),
            };
            out.extend(position.to_be_bytes());
            out.push(kind);
            out.extend(device);
            out.extend(effect.established_ms.to_be_bytes());
        }
        out
    }
    pub(crate) fn checkpoint_rows(&self) -> Vec<AccountDeviceRow> {
        self.active
            .values()
            .map(|member| {
                let mut keys = Vec::with_capacity(1280);
                member.keys.encode(&mut keys);
                AccountDeviceRow {
                    device: member.keys.id().0,
                    keys,
                    added: member.added,
                }
            })
            .collect()
    }
    pub(crate) fn from_checkpoint(
        id: AccountId,
        head: Head,
        summary: &[u8],
        rows: Vec<AccountDeviceRow>,
        stopped: bool,
        epoch: u64,
        index: Arc<dyn HistoryIndex>,
    ) -> Result<Self, Error> {
        let mut account = Self::from_index(id, head, summary, rows, epoch, index)?;
        account.stopped = stopped;
        Ok(account)
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
        let version = r.take(8)?;
        if !(version == b"BHACSM01" || version == b"BHACSM02") || head.position == 0 {
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
        if has_record > 1
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
                || active
                    .insert(
                        keys.id(),
                        Member {
                            keys,
                            added: row.added,
                        },
                    )
                    .is_some()
            {
                return Err(Error::Malformed);
            }
        }
        let timeline = if version == b"BHACSM02" {
            read_timeline(&mut r, head, &active)?
        } else {
            Timeline::default()
        };
        if !r.0.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            id,
            head,
            active,
            recovery,
            first,
            record_digest: (has_record == 1).then_some(digest),
            personal: (has_personal == 1).then_some(publication),
            timeline,
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

/// Strict and canonical: positions increase and lie within the verified cut;
/// a pending request's requester and target are active; effects were
/// established by the last confirmed time; nothing open without a confirmed
/// entry.
fn read_timeline(
    r: &mut Reader<'_>,
    head: Head,
    active: &BTreeMap<DeviceId, Member>,
) -> Result<Timeline, Error> {
    let u64_at = |r: &mut Reader<'_>| Ok::<_, Error>(u64::from_be_bytes(r.array()?));
    let count = |r: &mut Reader<'_>| Ok::<_, Error>(u32::from_be_bytes(r.array()?));
    let timed = r.array::<1>()?[0];
    let (first, first_latest) = (u64_at(r)?, u64_at(r)?);
    let last = ConfirmedTime {
        earliest_ms: u64_at(r)?,
        latest_ms: u64_at(r)?,
    };
    let mut t = Timeline::default();
    match timed {
        0 if [first, first_latest, last.earliest_ms, last.latest_ms] == [0; 4] => {}
        1 if (1..=head.position).contains(&first)
            && last.earliest_ms <= last.latest_ms
            && first_latest <= last.latest_ms =>
        {
            t.first = Some((first, first_latest));
            t.last = Some(last);
        }
        _ => return Err(Error::Malformed),
    }
    let in_order = |previous: Option<u64>, position: u64| {
        previous.is_none_or(|p| p < position) && (1..=head.position).contains(&position)
    };
    for _ in 0..count(r)? {
        let request = u64_at(r)?;
        let target = DeviceId(r.array()?);
        let has_by = r.array::<1>()?[0];
        let by = DeviceId(r.array()?);
        let deadline_ms = u64_at(r)?;
        let by = match has_by {
            0 if by.0 == [0; 32] => None,
            1 if active.contains_key(&by) => Some(by),
            _ => return Err(Error::Malformed),
        };
        if !in_order(t.pending.keys().next_back().copied(), request)
            || !active.contains_key(&target)
        {
            return Err(Error::Malformed);
        }
        t.pending.insert(
            request,
            PendingRemoval {
                request,
                target,
                by,
                deadline_ms,
            },
        );
    }
    for _ in 0..count(r)? {
        let position = u64_at(r)?;
        let kind = r.array::<1>()?[0];
        let device = DeviceId(r.array()?);
        let established_ms = u64_at(r)?;
        let reason = match kind {
            0 => RotationReason::Removal {
                request: position,
                target: device,
            },
            1 => RotationReason::RemovedNow {
                position,
                target: device,
            },
            2 => RotationReason::RemovedSelf { position, device },
            3 if device.0 == [0; 32] => RotationReason::RecoveryReplaced { position },
            _ => return Err(Error::Malformed),
        };
        if !in_order(t.effects.keys().next_back().copied(), position)
            || t.pending.contains_key(&position)
            || t.last.is_none_or(|l| established_ms > l.latest_ms)
        {
            return Err(Error::Malformed);
        }
        t.effects.insert(
            position,
            Effect {
                reason,
                established_ms,
            },
        );
    }
    if t.first.is_none() && !(t.pending.is_empty() && t.effects.is_empty()) {
        return Err(Error::Malformed);
    }
    Ok(t)
}
