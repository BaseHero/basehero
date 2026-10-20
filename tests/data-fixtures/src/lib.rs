//! Synthetic authority for isolated, headless typed-data tests.
//! Never use this crate for a production account or tool boundary.
use bh_data::{Actor, Scope, session::Authority};

#[derive(Clone, Debug)]
pub struct FixtureAuthority {
    pub actor: Actor,
    pub reads: Vec<Scope>,
    pub write: Option<Scope>,
}

impl Authority for FixtureAuthority {
    fn actor(&self) -> Actor {
        self.actor.clone()
    }
    fn reads(&self) -> Vec<Scope> {
        self.reads.clone()
    }
    // Fixture assumption only: tests using this authority supply already-confirmed
    // device operations. Negative admission tests use an exact evidence fixture.
    fn confirm_rule_change(
        &self,
        request: &bh_data::admission::Confirmation,
        _at: Option<bh_data::Position>,
    ) -> Result<bool, bh_data::DataError> {
        Ok(matches!(request.actor, Actor::Device { .. }))
    }
    fn write(&self) -> Option<Scope> {
        self.write
    }
}

pub fn member(account_seed: u8) -> Actor {
    Actor::Device {
        account: [account_seed; 32],
        device: [account_seed.wrapping_add(1); 32],
    }
}

pub fn job(account_seed: u8, action: Option<&str>) -> Actor {
    Actor::Job {
        account: [account_seed; 32],
        delegation: [account_seed.wrapping_add(2); 32],
        action: action.map(str::to_owned),
    }
}

pub fn scopes(base_seed: u8) -> (Scope, Scope) {
    let base = [base_seed; 32];
    (
        Scope {
            base,
            audience: [0; 32],
        },
        Scope {
            base,
            audience: [base_seed.wrapping_add(1); 32],
        },
    )
}
