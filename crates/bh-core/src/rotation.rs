//! Key rings and keys sealed for device delivery or for a base's previous epoch.

use crate::Error;
use crate::base::BaseKey;
use crate::envelope::{self, Aad, Purpose};
use bh_crypto::{KemKey, Secret, XWING_CIPHERTEXT_BYTES, XWING_PUBLIC_BYTES};
use bh_proto::{AccountId, BaseId, DeviceId, DeviceKeyDelivery, DeviceKind};
use zeroize::Zeroizing;

/// Account or app keys, ordered from oldest to newest epoch.
pub(crate) struct KeyRing(Vec<(u32, Secret<32>)>);

impl KeyRing {
    pub(crate) fn from_key(epoch: u32, key: Secret<32>) -> Result<Self, Error> {
        if epoch == 0 {
            return Err(Error::Crypto);
        }
        Ok(Self(vec![(epoch, key)]))
    }

    /// The original secret format was exactly one 32-byte key at epoch 1.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() == 32 {
            return Ok(Self(vec![(1, Secret::from_slice(bytes)?)]));
        }
        if bytes.is_empty() || !bytes.len().is_multiple_of(36) {
            return Err(Error::Crypto);
        }
        let mut entries = Vec::with_capacity(bytes.len() / 36);
        for entry in bytes.as_chunks::<36>().0 {
            let epoch = u32::from_be_bytes(entry[..4].try_into().expect("four bytes"));
            if epoch == 0
                || entries
                    .last()
                    .is_some_and(|(previous, _)| *previous >= epoch)
            {
                return Err(Error::Crypto);
            }
            entries.push((epoch, Secret::from_slice(&entry[4..])?));
        }
        Ok(Self(entries))
    }

    pub(crate) fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(self.0.len() * 36));
        for (epoch, key) in &self.0 {
            bytes.extend_from_slice(&epoch.to_be_bytes());
            bytes.extend_from_slice(key.expose());
        }
        bytes
    }

    pub(crate) fn newest(&self) -> (u32, &Secret<32>) {
        let (epoch, key) = self.0.last().expect("key ring is never empty");
        (*epoch, key)
    }

    pub(crate) fn get(&self, epoch: u32) -> Option<&Secret<32>> {
        self.0
            .binary_search_by_key(&epoch, |(e, _)| *e)
            .ok()
            .map(|index| &self.0[index].1)
    }

    pub(crate) fn iter_newest_first(&self) -> impl Iterator<Item = (u32, &Secret<32>)> {
        self.0.iter().rev().map(|(epoch, key)| (*epoch, key))
    }

    /// Adopts only an unbroken, authenticated chain; a bad batch changes nothing.
    pub(crate) fn adopt(
        &mut self,
        kem: &KemKey,
        context: &DeliveryContext,
        reported_epoch: u32,
        deliveries: &[DeviceKeyDelivery],
    ) -> Result<(), Error> {
        let mut pending = Self::parse(&self.to_bytes())?;
        if reported_epoch < pending.newest().0 {
            return Err(Error::Crypto);
        }
        for delivery in deliveries {
            let (from_epoch, previous) = pending.newest();
            let target = from_epoch.checked_add(1).ok_or(Error::Crypto)?;
            if delivery.epoch != target || target > reported_epoch {
                return Err(Error::Crypto);
            }
            let next = open_for_device(
                kem,
                &DeliveryContext {
                    from_epoch,
                    ..context.clone()
                },
                previous,
                &delivery.sealed.0,
            )?;
            pending.insert(target, next)?;
        }
        if pending.newest().0 != reported_epoch {
            return Err(Error::Crypto);
        }
        *self = pending;
        Ok(())
    }

    pub(crate) fn insert(&mut self, epoch: u32, key: Secret<32>) -> Result<(), Error> {
        if epoch == 0 {
            return Err(Error::Crypto);
        }
        match self.0.binary_search_by_key(&epoch, |(e, _)| *e) {
            Ok(index) if bh_crypto::constant_time_eq(self.0[index].1.expose(), key.expose()) => {
                Ok(())
            }
            Ok(_) => Err(Error::Crypto),
            Err(index) => {
                self.0.insert(index, (epoch, key));
                Ok(())
            }
        }
    }
}

/// Authenticated transition from one device key epoch to the next.
#[derive(Clone)]
pub(crate) struct DeliveryContext {
    pub(crate) account: AccountId,
    pub(crate) device: DeviceId,
    pub(crate) kind: DeviceKind,
    pub(crate) from_epoch: u32,
}

impl DeliveryContext {
    fn target_epoch(&self) -> Result<u32, Error> {
        if self.from_epoch == 0 {
            return Err(Error::Crypto);
        }
        self.from_epoch.checked_add(1).ok_or(Error::Crypto)
    }

    fn tag(
        &self,
        previous: &Secret<32>,
        encapsulation: &[u8],
        wrapped: &[u8],
    ) -> Result<[u8; 32], Error> {
        let target = self.target_epoch()?;
        let key = bh_crypto::kdf(previous, b"bhrotat1", 1);
        let kind = [match self.kind {
            DeviceKind::Full => 0,
            DeviceKind::App => 1,
        }];
        Ok(bh_crypto::generichash(
            Some(key.expose()),
            &[
                b"bh.v1.rotation",
                &self.account.0,
                &self.device.0,
                &kind,
                &self.from_epoch.to_be_bytes(),
                &target.to_be_bytes(),
                encapsulation,
                wrapped,
            ],
        ))
    }
}

/// Delivers the next key authenticated under this recipient's preceding key.
pub(crate) fn seal_for_device(
    public: &[u8; XWING_PUBLIC_BYTES],
    context: &DeliveryContext,
    previous: &Secret<32>,
    next: &Secret<32>,
) -> Result<Vec<u8>, Error> {
    let target = context.target_epoch()?;
    let (encapsulation, shared) = bh_crypto::encapsulate(public)?;
    let wrapped = envelope::seal(
        &bh_crypto::kdf(&shared, b"bhdevky1", 1),
        &Aad {
            purpose: Purpose::DeviceKey,
            base: context.account.0,
            object: context.device.0,
            epoch: target,
        },
        next.expose(),
    );
    let tag = context.tag(previous, &encapsulation, &wrapped)?;
    let mut out = Vec::with_capacity(encapsulation.len() + wrapped.len() + tag.len());
    out.extend_from_slice(&encapsulation);
    out.extend_from_slice(&wrapped);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Checks the predecessor's tag before any X-Wing decapsulation.
pub(crate) fn open_for_device(
    kem: &KemKey,
    context: &DeliveryContext,
    previous: &Secret<32>,
    sealed: &[u8],
) -> Result<Secret<32>, Error> {
    let target = context.target_epoch()?;
    // X-Wing ciphertext, a complete 32-byte key envelope, and the 32-byte tag.
    if sealed.len() < XWING_CIPHERTEXT_BYTES + 77 + 32 {
        return Err(Error::Crypto);
    }
    let (body, tag) = sealed.split_at(sealed.len() - 32);
    let (encapsulation, wrapped) = body.split_at(XWING_CIPHERTEXT_BYTES);
    let expected = context.tag(previous, encapsulation, wrapped)?;
    if !bh_crypto::constant_time_eq(&expected, tag) {
        return Err(Error::Crypto);
    }
    let encapsulation: &[u8; XWING_CIPHERTEXT_BYTES] =
        encapsulation.try_into().expect("X-Wing ciphertext length");
    let shared = bh_crypto::decapsulate(kem, encapsulation)?;
    let bytes = envelope::open(
        &bh_crypto::kdf(&shared, b"bhdevky1", 1),
        &Aad {
            purpose: Purpose::DeviceKey,
            base: context.account.0,
            object: context.device.0,
            epoch: target,
        },
        wrapped,
    )?;
    Ok(Secret::from_slice(&bytes)?)
}

/// Seals an earlier base key under the key of the next epoch.
pub(crate) fn seal_previous(
    new: &BaseKey,
    base: &BaseId,
    old_epoch: u32,
    old: &BaseKey,
) -> Vec<u8> {
    envelope::seal(
        &bh_crypto::kdf(new.secret(), b"bhprevk1", 1),
        &Aad {
            purpose: Purpose::PreviousBaseKey,
            base: base.0,
            object: [0; 16],
            epoch: old_epoch,
        },
        old.secret().expose(),
    )
}

/// Opens an earlier base key only with the next epoch's base key.
pub(crate) fn open_previous(
    new: &BaseKey,
    base: &BaseId,
    old_epoch: u32,
    sealed: &[u8],
) -> Result<BaseKey, Error> {
    let bytes = envelope::open(
        &bh_crypto::kdf(new.secret(), b"bhprevk1", 1),
        &Aad {
            purpose: Purpose::PreviousBaseKey,
            base: base.0,
            object: [0; 16],
            epoch: old_epoch,
        },
        sealed,
    )?;
    BaseKey::new(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::BaseKey;
    use bh_crypto::{KemKey, Secret, XWING_CIPHERTEXT_BYTES};
    use bh_proto::{AccountId, BaseId, DeviceId};

    fn key(byte: u8) -> Secret<32> {
        Secret::from_slice(&[byte; 32]).unwrap()
    }

    #[test]
    fn key_ring_round_trips_and_finds_epochs() {
        let mut ring = KeyRing::parse(&[1; 32]).unwrap();
        assert_eq!(ring.newest().0, 1);
        assert_eq!(ring.get(1).unwrap().expose(), &[1; 32]);
        ring.insert(2, key(2)).unwrap();
        ring.insert(3, key(3)).unwrap();
        let ordered: Vec<_> = ring.iter_newest_first().map(|(epoch, _)| epoch).collect();
        assert_eq!(ordered, vec![3, 2, 1]);
        assert_eq!(ring.newest().1.expose(), &[3; 32]);
        assert!(ring.get(4).is_none());
        let bytes = ring.to_bytes();
        assert_eq!(&bytes[..4], &1u32.to_be_bytes());
        assert_eq!(&bytes[36..40], &2u32.to_be_bytes());
        assert_eq!(&bytes[72..76], &3u32.to_be_bytes());
        let restored = KeyRing::parse(&bytes).unwrap();
        assert_eq!(restored.get(1).unwrap().expose(), &[1; 32]);
        assert_eq!(restored.get(3).unwrap().expose(), &[3; 32]);
    }

    #[test]
    fn inserting_a_conflicting_key_preserves_the_original() {
        let mut ring = KeyRing::parse(&[1; 32]).unwrap();
        assert_eq!(ring.insert(1, key(9)), Err(Error::Crypto));
        assert_eq!(ring.get(1).unwrap().expose(), &[1; 32]);
        assert_eq!(ring.to_bytes().len(), 36);
    }

    #[test]
    fn inserting_an_identical_key_is_idempotent() {
        let mut ring = KeyRing::parse(&[1; 32]).unwrap();
        assert_eq!(ring.insert(1, key(1)), Ok(()));
        assert_eq!(ring.get(1).unwrap().expose(), &[1; 32]);
        assert_eq!(ring.to_bytes().len(), 36);
    }

    #[test]
    fn inserting_epoch_zero_is_rejected_without_changing_the_ring() {
        let mut ring = KeyRing::parse(&[1; 32]).unwrap();
        assert_eq!(ring.insert(0, key(0)), Err(Error::Crypto));
        assert_eq!(ring.newest().0, 1);
        assert_eq!(ring.get(1).unwrap().expose(), &[1; 32]);
    }

    #[test]
    fn key_ring_refuses_malformed_lengths_and_epochs() {
        for bad in [&[][..], &[0; 31][..], &[0; 35][..], &[0; 37][..]] {
            assert!(KeyRing::parse(bad).is_err());
        }
        let mut repeated = [0; 72];
        repeated[..4].copy_from_slice(&1u32.to_be_bytes());
        repeated[36..40].copy_from_slice(&1u32.to_be_bytes());
        assert!(KeyRing::parse(&repeated).is_err());
        let mut zero = [0; 36];
        assert!(KeyRing::parse(&zero).is_err());
        zero[..4].copy_from_slice(&2u32.to_be_bytes());
        let mut descending = [0; 72];
        descending[..36].copy_from_slice(&zero);
        descending[36..40].copy_from_slice(&1u32.to_be_bytes());
        assert!(KeyRing::parse(&descending).is_err());
    }

    #[test]
    fn a_device_key_opens_only_for_its_device_account_and_epoch() {
        let kem = KemKey::generate();
        let other = KemKey::generate();
        let account = AccountId([1; 16]);
        let device = DeviceId([2; 16]);
        let context = DeliveryContext {
            account,
            device,
            kind: bh_proto::DeviceKind::Full,
            from_epoch: 1,
        };
        let sealed = seal_for_device(&kem.public(), &context, &key(6), &key(7)).unwrap();
        assert_eq!(sealed.len(), XWING_CIPHERTEXT_BYTES + 77 + 32);
        assert_eq!(
            open_for_device(&kem, &context, &key(6), &sealed)
                .unwrap()
                .expose(),
            &[7; 32]
        );
        assert!(open_for_device(&other, &context, &key(6), &sealed).is_err());
        assert!(open_for_device(&kem, &context, &key(8), &sealed).is_err());
        for altered in [
            DeliveryContext {
                account: AccountId([3; 16]),
                ..context.clone()
            },
            DeliveryContext {
                device: DeviceId([3; 16]),
                ..context.clone()
            },
            DeliveryContext {
                kind: bh_proto::DeviceKind::App,
                ..context.clone()
            },
            DeliveryContext {
                from_epoch: 2,
                ..context.clone()
            },
        ] {
            assert!(open_for_device(&kem, &altered, &key(6), &sealed).is_err());
        }
        for offset in [0, XWING_CIPHERTEXT_BYTES, sealed.len() - 1] {
            let mut changed = sealed.clone();
            changed[offset] ^= 1;
            assert!(open_for_device(&kem, &context, &key(6), &changed).is_err());
        }
        assert!(open_for_device(&kem, &context, &key(6), &sealed[..sealed.len() - 32]).is_err());
        assert!(open_for_device(&kem, &context, &key(6), &sealed[..15]).is_err());
        assert!(
            seal_for_device(
                &kem.public(),
                &DeliveryContext {
                    from_epoch: 0,
                    ..context.clone()
                },
                &key(6),
                &key(7)
            )
            .is_err()
        );
        assert!(
            seal_for_device(
                &kem.public(),
                &DeliveryContext {
                    from_epoch: u32::MAX,
                    ..context.clone()
                },
                &key(6),
                &key(7)
            )
            .is_err()
        );
        assert!(
            open_for_device(
                &kem,
                &DeliveryContext {
                    from_epoch: 0,
                    ..context.clone()
                },
                &key(6),
                &sealed
            )
            .is_err()
        );
        assert!(
            open_for_device(
                &kem,
                &DeliveryContext {
                    from_epoch: u32::MAX,
                    ..context
                },
                &key(6),
                &sealed
            )
            .is_err()
        );
    }

    #[test]
    fn a_server_encapsulation_without_a_previous_key_mac_is_rejected() {
        let kem = KemKey::generate();
        let context = DeliveryContext {
            account: AccountId([1; 16]),
            device: DeviceId([2; 16]),
            kind: bh_proto::DeviceKind::Full,
            from_epoch: 1,
        };
        let (encapsulation, shared) = bh_crypto::encapsulate(&kem.public()).unwrap();
        let wrapped = envelope::seal(
            &bh_crypto::kdf(&shared, b"bhdevky1", 1),
            &Aad {
                purpose: Purpose::DeviceKey,
                base: context.account.0,
                object: context.device.0,
                epoch: 2,
            },
            key(9).expose(),
        );
        let mut forged = encapsulation.to_vec();
        forged.extend_from_slice(&wrapped);
        assert!(open_for_device(&kem, &context, &key(6), &forged).is_err());
        forged.extend_from_slice(&[0; 32]);
        assert!(open_for_device(&kem, &context, &key(6), &forged).is_err());
    }

    #[test]
    fn a_forged_delivery_is_refused_and_the_ring_is_unchanged() {
        let kem = KemKey::generate();
        let context = DeliveryContext {
            account: AccountId([1; 16]),
            device: DeviceId([2; 16]),
            kind: bh_proto::DeviceKind::Full,
            from_epoch: 1,
        };
        let two = bh_proto::DeviceKeyDelivery {
            epoch: 2,
            sealed: bh_proto::Bytes(
                seal_for_device(&kem.public(), &context, &key(1), &key(2)).unwrap(),
            ),
        };
        let three = bh_proto::DeviceKeyDelivery {
            epoch: 3,
            sealed: bh_proto::Bytes(
                seal_for_device(
                    &kem.public(),
                    &DeliveryContext {
                        from_epoch: 2,
                        ..context.clone()
                    },
                    &key(2),
                    &key(3),
                )
                .unwrap(),
            ),
        };
        let mut ring = KeyRing::parse(&[1; 32]).unwrap();
        let mut forged = three.clone();
        forged.sealed.0[0] ^= 1;
        assert_eq!(
            ring.adopt(&kem, &context, 3, &[two.clone(), forged]),
            Err(Error::Crypto)
        );
        assert_eq!(ring.newest().0, 1);
        assert_eq!(
            ring.adopt(&kem, &context, 3, std::slice::from_ref(&three)),
            Err(Error::Crypto)
        );
        assert_eq!(ring.newest().0, 1);
        ring.adopt(&kem, &context, 3, &[two, three]).unwrap();
        assert_eq!(ring.newest().0, 3);
        assert_eq!(ring.get(2).unwrap().expose(), &[2; 32]);
        assert_eq!(ring.adopt(&kem, &context, 2, &[]), Err(Error::Crypto));
        assert_eq!(ring.newest().0, 3);
    }

    #[test]
    fn a_gap_is_refused() {
        let kem = KemKey::generate();
        let context = DeliveryContext {
            account: AccountId([1; 16]),
            device: DeviceId([2; 16]),
            kind: bh_proto::DeviceKind::Full,
            from_epoch: 1,
        };
        let three = bh_proto::DeviceKeyDelivery {
            epoch: 3,
            sealed: bh_proto::Bytes(
                seal_for_device(
                    &kem.public(),
                    &DeliveryContext {
                        from_epoch: 2,
                        ..context.clone()
                    },
                    &key(2),
                    &key(3),
                )
                .unwrap(),
            ),
        };
        let mut ring = KeyRing::parse(&[1; 32]).unwrap();
        assert_eq!(ring.adopt(&kem, &context, 3, &[three]), Err(Error::Crypto));
        assert_eq!(ring.to_bytes().len(), 36);
        assert_eq!(ring.newest().0, 1);
    }

    #[test]
    fn a_previous_key_opens_only_under_the_next_key() {
        let base = BaseId([5; 16]);
        let next = BaseKey::new(&[2; 32]).unwrap();
        let old = BaseKey::new(&[1; 32]).unwrap();
        let sealed = seal_previous(&next, &base, 1, &old);
        assert_eq!(
            open_previous(&next, &base, 1, &sealed)
                .unwrap()
                .secret()
                .expose(),
            &[1; 32]
        );
        assert!(open_previous(&old, &base, 1, &sealed).is_err());
        assert!(open_previous(&next, &BaseId([6; 16]), 1, &sealed).is_err());
        assert!(open_previous(&next, &base, 2, &sealed).is_err());
    }
}
