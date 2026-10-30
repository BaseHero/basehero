//! A base's newest key and its authenticated chain of predecessors.

use crate::Error;
use crate::base::BaseKey;
use crate::rotation::open_previous;
use bh_proto::BaseId;

/// Base keys ordered by epoch, oldest first.
pub(crate) struct BaseKeys(Vec<(u32, BaseKey)>);

impl BaseKeys {
    pub(crate) fn from_chain(
        current_epoch: u32,
        current: BaseKey,
        previous: &[(u32, Vec<u8>)],
        base: &BaseId,
    ) -> Result<Self, Error> {
        if current_epoch == 0 || previous.len() != (current_epoch - 1) as usize {
            return Err(Error::Crypto);
        }
        let mut keys = vec![(current_epoch, current)];
        for epoch in (1..current_epoch).rev() {
            let sealed = previous
                .iter()
                .find(|(e, _)| *e == epoch)
                .ok_or(Error::Crypto)?;
            let old = open_previous(&keys.last().expect("current key").1, base, epoch, &sealed.1)?;
            keys.push((epoch, old));
        }
        keys.reverse();
        Ok(Self(keys))
    }

    pub(crate) fn current(&self) -> (u32, &BaseKey) {
        let (epoch, key) = self.0.last().expect("nonempty base keys");
        (*epoch, key)
    }

    pub(crate) fn get(&self, epoch: u32) -> Option<&BaseKey> {
        self.0
            .get(epoch.checked_sub(1)? as usize)
            .and_then(|(found, key)| (*found == epoch).then_some(key))
    }

    pub(crate) fn first(&self) -> &BaseKey {
        &self.0[0].1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotation::seal_previous;

    #[test]
    fn walks_three_epochs_and_rejects_a_broken_link() {
        let id = BaseId::random();
        let one = BaseKey::new(&[1; 32]).unwrap();
        let two = BaseKey::new(&[2; 32]).unwrap();
        let three = BaseKey::new(&[3; 32]).unwrap();
        let chain = vec![
            (1, seal_previous(&two, &id, 1, &one)),
            (2, seal_previous(&three, &id, 2, &two)),
        ];
        let keys = BaseKeys::from_chain(3, three, &chain, &id).unwrap();
        assert_eq!(keys.current().0, 3);
        assert_eq!(keys.first().secret().expose(), &[1; 32]);
        assert_eq!(keys.get(2).unwrap().secret().expose(), &[2; 32]);
        let bad = vec![(1, chain[0].1.clone()), (2, chain[0].1.clone())];
        assert!(matches!(
            BaseKeys::from_chain(3, BaseKey::new(&[3; 32]).unwrap(), &bad, &id),
            Err(Error::Crypto)
        ));
    }
}
