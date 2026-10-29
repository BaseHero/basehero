use crate::{BaseId, BaseSummary, DeviceId};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    Free,
    Ask,
    Never,
}

pub(crate) fn access(
    chat_base: &BaseSummary,
    other: &BaseSummary,
    chat_readers: &BTreeSet<DeviceId>,
    other_readers: &BTreeSet<DeviceId>,
    allowed: &[BaseId],
    denied: &[BaseId],
) -> Access {
    if chat_base.id == other.id {
        Access::Free
    } else if other.hidden || denied.contains(&other.id) {
        Access::Never
    } else if chat_readers.is_subset(other_readers) || allowed.contains(&other.id) {
        Access::Free
    } else {
        Access::Ask
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mode;
    fn summary(id: BaseId, hidden: bool) -> BaseSummary {
        BaseSummary {
            id,
            name: "base".into(),
            mode: Mode::ReadWrite,
            hidden,
            mount: None,
        }
    }
    fn readers() -> (BTreeSet<DeviceId>, BTreeSet<DeviceId>) {
        (BTreeSet::new(), BTreeSet::from([DeviceId::random()]))
    }
    #[test]
    fn a_chat_in_your_own_base_uses_health_freely() {
        let (personal, health) = (
            summary(BaseId::random(), false),
            summary(BaseId::random(), false),
        );
        let (empty, raring) = readers();
        assert_eq!(
            access(&personal, &health, &empty, &raring, &[], &[]),
            Access::Free
        );
        assert_eq!(
            access(&personal, &personal, &empty, &empty, &[], &[personal.id]),
            Access::Free
        );
    }
    #[test]
    fn a_chat_in_health_asks_before_using_personal() {
        let (personal, health) = (
            summary(BaseId::random(), false),
            summary(BaseId::random(), false),
        );
        let (empty, raring) = readers();
        assert_eq!(
            access(&health, &personal, &raring, &empty, &[], &[]),
            Access::Ask
        );
    }
    #[test]
    fn hidden_bases_are_never_used_from_outside() {
        let (personal, hidden) = (
            summary(BaseId::random(), false),
            summary(BaseId::random(), true),
        );
        let empty = BTreeSet::new();
        assert_eq!(
            access(&personal, &hidden, &empty, &empty, &[hidden.id], &[]),
            Access::Never
        );
    }
    #[test]
    fn a_chat_inside_a_hidden_base_uses_ordinary_bases() {
        let (personal, hidden) = (
            summary(BaseId::random(), false),
            summary(BaseId::random(), true),
        );
        let empty = BTreeSet::new();
        assert_eq!(
            access(&hidden, &personal, &empty, &empty, &[], &[]),
            Access::Free
        );
        assert_eq!(
            access(&hidden, &hidden, &empty, &empty, &[], &[]),
            Access::Free
        );
    }
    #[test]
    fn answers_are_remembered_per_chat() {
        let (personal, health) = (
            summary(BaseId::random(), false),
            summary(BaseId::random(), false),
        );
        let (empty, raring) = readers();
        assert_eq!(
            access(&health, &personal, &raring, &empty, &[personal.id], &[]),
            Access::Free
        );
        assert_eq!(
            access(
                &health,
                &personal,
                &raring,
                &empty,
                &[personal.id],
                &[personal.id]
            ),
            Access::Never
        );
    }
}
