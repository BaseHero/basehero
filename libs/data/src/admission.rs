//! Trusted-host confirmation, not caller-provided claims or a signature format.
use crate::{Actor, AppId, DataError, Position, RevisionId, Scope, mutation::ops::Operation};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PriorRules {
    Type {
        revision: Option<RevisionId>,
        permitted: Vec<RevisionId>,
    },
    App {
        app: AppId,
        since: Option<Position>,
        active: Option<bool>,
    },
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Confirmation {
    pub scope: Scope,
    pub actor: Actor,
    /// Includes exact definition bytes, not just a caller's claimed hash.
    pub operation: Operation,
    pub prior: PriorRules,
}
/// Implement only at the verified host boundary. For local saves, confirm
/// the person's exact proposal and current authority. For ordered calls the
/// evaluator checks the signed payload's prior rules itself; the host only
/// attests that the authenticated author and position are a device allowed to
/// confirm. A device identity alone is never confirmation.
pub trait HostAdmission {
    fn confirms(&self, _request: &Confirmation, _at: Option<Position>) -> Result<bool, DataError> {
        Ok(false)
    }
    /// The host has verified this actor may read the adoption's source.
    fn may_read_source(
        &self,
        _actor: &Actor,
        _source: Scope,
        _at: Option<Position>,
    ) -> Result<bool, DataError> {
        Ok(false)
    }
}
pub struct Unavailable;
impl HostAdmission for Unavailable {}
