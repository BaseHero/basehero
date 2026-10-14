//! Per-attempt accounting and local delivery state, not a billing authority.
//!
//! The owning service must durably reserve before dispatch, atomically associate
//! trusted provider-facing receipts with that attempt, and persist transitions.
//! Never construct settlement from untrusted client or decrypted-body assertions.
//! This module does not implement an allowance policy or automatic retries.

use crate::response::Tokens;
use serde::Serialize;
use std::{collections::BTreeMap, fmt};

/// Shipped route identifiers, not an endpoint supplied by the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    Near,
    Tinfoil,
}
/// Protected activity attribution. Do not attach this to ordinary billing logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkKind {
    AskedTurn,
    WakeUp,
    Legwork,
    NightlyReflection,
    FirstLook,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountingError {
    InvalidTokens,
    Overflow,
    InvalidTransition,
    InvalidSettlement,
    ConflictingSettlement,
    ConflictingUsage,
}
impl fmt::Display for AccountingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "model accounting: {self:?}")
    }
}
impl std::error::Error for AccountingError {}

/// Nano-USD per million tokens. A cost computed here is an estimate, not a
/// provider invoice. The caller pins rates to its recorded price version.
#[derive(Clone, Copy, Debug)]
pub struct Rates {
    pub input_per_million: u64,
    pub cached_per_million: u64,
    pub output_per_million: u64,
}
impl Rates {
    pub fn cost(self, tokens: Tokens) -> Result<u64, AccountingError> {
        if !tokens.is_valid() {
            return Err(AccountingError::InvalidTokens);
        }
        let input = u128::from(tokens.input - tokens.cached) * u128::from(self.input_per_million);
        let cached = u128::from(tokens.cached) * u128::from(self.cached_per_million);
        let output = u128::from(tokens.output) * u128::from(self.output_per_million);
        let total = input
            .checked_add(cached)
            .and_then(|n| n.checked_add(output))
            .ok_or(AccountingError::Overflow)?;
        u64::try_from(total.div_ceil(1_000_000)).map_err(|_| AccountingError::Overflow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Ready,
    Running,
    Completed,
    Failed,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Settlement {
    NotDispatched,
    Pending,
    /// Trusted reconciliation confirms no charge, not merely a transport error.
    NotCharged,
    Charged {
        tokens: Tokens,
        nano_usd: u64,
    },
}

/// Contains no content, work kind, actor, conversation or private task identifier.
/// The trusted gateway supplies its permitted funding/base scope separately.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct BillingRecord {
    pub route: Route,
    pub settlement: Settlement,
}

pub struct Attempt {
    route: Route,
    kind: WorkKind,
    delivery: Delivery,
    settlement: Settlement,
    observed: Option<Tokens>,
}
impl fmt::Debug for Attempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Attempt([protected])")
    }
}
impl Attempt {
    pub fn new(route: Route, kind: WorkKind) -> Self {
        Self {
            route,
            kind,
            delivery: Delivery::Ready,
            settlement: Settlement::NotDispatched,
            observed: None,
        }
    }
    /// Call immediately BEFORE allowing the first request byte out. A subsequent
    /// transport error is uncertain unless trusted reconciliation says otherwise.
    pub fn mark_dispatched(&mut self) -> Result<(), AccountingError> {
        if self.delivery != Delivery::Ready {
            return Err(AccountingError::InvalidTransition);
        }
        self.delivery = Delivery::Running;
        self.settlement = Settlement::Pending;
        Ok(())
    }
    pub fn delivery(&self) -> Delivery {
        self.delivery
    }
    /// Check under the same synchronization as Stop before publishing text/tools.
    /// This library performs no I/O and cannot stop remote inference or charges.
    pub fn may_deliver(&self) -> bool {
        self.delivery == Delivery::Running
    }
    pub fn stop(&mut self) {
        if matches!(
            self.delivery,
            Delivery::Ready | Delivery::Running | Delivery::Failed
        ) {
            self.delivery = Delivery::Stopped;
        }
    }
    /// Only call after a complete, validated response. Settlement is independent.
    pub fn complete(&mut self) -> Result<(), AccountingError> {
        if self.delivery != Delivery::Running {
            return Err(AccountingError::InvalidTransition);
        }
        self.delivery = Delivery::Completed;
        Ok(())
    }
    pub fn fail(&mut self) -> Result<(), AccountingError> {
        if !matches!(self.delivery, Delivery::Ready | Delivery::Running) {
            return Err(AccountingError::InvalidTransition);
        }
        self.delivery = Delivery::Failed;
        Ok(())
    }
    /// This permits considering a NEW attempt, not redispatching this one.
    /// The caller still needs current authority and a fresh budget reservation.
    pub fn may_retry(&self) -> bool {
        self.delivery == Delivery::Failed && self.settlement != Settlement::Pending
    }
    /// Preserve an observation for protected activity; it never settles billing.
    pub fn record_usage(&mut self, tokens: Tokens) -> Result<(), AccountingError> {
        if self.settlement == Settlement::NotDispatched {
            return Err(AccountingError::InvalidTransition);
        }
        if !tokens.is_valid() {
            return Err(AccountingError::InvalidTokens);
        }
        if self.observed.is_some_and(|old| old != tokens) {
            return Err(AccountingError::ConflictingUsage);
        }
        self.observed = Some(tokens);
        Ok(())
    }
    /// Trusted accounting boundary, NOT a deserialization endpoint. The service
    /// must authenticate the receipt and bind it to this exact dispatch first.
    /// Identical replay is idempotent; conflicting evidence requires investigation.
    pub fn reconcile(&mut self, settlement: Settlement) -> Result<(), AccountingError> {
        if self.settlement == Settlement::NotDispatched {
            return Err(AccountingError::InvalidTransition);
        }
        match settlement {
            Settlement::NotCharged => {}
            Settlement::Charged { tokens, .. } if tokens.is_valid() => {}
            Settlement::Charged { .. } => return Err(AccountingError::InvalidTokens),
            _ => return Err(AccountingError::InvalidSettlement),
        }
        if self.settlement != Settlement::Pending && self.settlement != settlement {
            return Err(AccountingError::ConflictingSettlement);
        }
        self.settlement = settlement;
        Ok(())
    }
    pub fn billing(&self) -> BillingRecord {
        BillingRecord {
            route: self.route,
            settlement: self.settlement,
        }
    }
    /// Only for authorized, encrypted activity/report storage.
    pub fn observed_usage(&self) -> Option<Tokens> {
        self.observed
    }
}

/// A protected aggregate; not an ordinary diagnostics payload. Pending costs
/// must remain visibly pending instead of being folded into a misleading zero.
#[derive(Debug, PartialEq, Eq)]
pub struct UsageSummary {
    pub attempts: u64,
    pub pending: u64,
    pub settled_nano_usd: u64,
    pub tokens: Tokens,
}
/// Supply distinct attempts from the caller's durable ledger. Do not insert the
/// same attempt twice; receipt replay is handled on the attempt, not by this sum.
pub fn summarize(
    attempts: &[Attempt],
) -> Result<BTreeMap<WorkKind, UsageSummary>, AccountingError> {
    let mut summaries = BTreeMap::new();
    for a in attempts {
        let s = summaries.entry(a.kind).or_insert(UsageSummary {
            attempts: 0,
            pending: 0,
            settled_nano_usd: 0,
            tokens: Tokens {
                input: 0,
                cached: 0,
                output: 0,
            },
        });
        s.attempts = add(s.attempts, 1)?;
        match a.settlement {
            Settlement::Pending => s.pending = add(s.pending, 1)?,
            Settlement::Charged { tokens, nano_usd } => {
                s.settled_nano_usd = add(s.settled_nano_usd, nano_usd)?;
                s.tokens.input = add(s.tokens.input, tokens.input)?;
                s.tokens.cached = add(s.tokens.cached, tokens.cached)?;
                s.tokens.output = add(s.tokens.output, tokens.output)?;
            }
            _ => {}
        }
    }
    Ok(summaries)
}
fn add(a: u64, b: u64) -> Result<u64, AccountingError> {
    a.checked_add(b).ok_or(AccountingError::Overflow)
}
