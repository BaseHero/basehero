//! The home's recovery check. A recovering device seals the code's proof and
//! the password-and-code check token to the home's recovery key, for one
//! nonce the home issued. The home finds the record by the hash of the proof
//! alone: an unknown proof is not recognised and costs nothing. A known
//! proof with the wrong token is a try against that record: five are free,
//! then one an hour for a day from the fifth, then one a day. Both right
//! release the record and the personal key's recovery seal, clear the
//! record's tries and leave the account's devices a notice. Tries are
//! counted per record and notices per account: one account's recovery never
//! waits for another's.
use crate::{
    Bounds, ServiceError,
    store::{RecoveryEntry, Store},
};
use bh_account::{
    AccountId,
    recovery::{RecoveryClaim, record_checks},
};
use bh_authz_proto::RecoveryAnswer;

/// Wrong-password tries against a record before any wait.
pub const FREE_TRIES: u32 = 5;
const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 86_400_000;

/// When the next try is allowed after the `failures`th failure, at
/// `failure_ms`, against a record whose fifth failure was at
/// `fifth_failure_ms`: none to wait for before the fifth, then an hour
/// until a day after the fifth, then a day.
pub fn next_try(failures: u32, fifth_failure_ms: Option<u64>, failure_ms: u64) -> Option<u64> {
    if failures < FREE_TRIES {
        return None;
    }
    let fifth = fifth_failure_ms.unwrap_or(failure_ms);
    let wait = if failure_ms < fifth.saturating_add(DAY_MS) {
        HOUR_MS
    } else {
        DAY_MS
    };
    Some(failure_ms.saturating_add(wait))
}

/// Judge an opened claim at `bounds`: a try is allowed only once the whole
/// interval has reached the record's next try, and a failure counts from
/// its latest bound, so a clock that steps back never reopens tries.
/// `None` for a proof that names no current record. Call with the
/// account's lock held, so its tries are judged one at a time.
pub(crate) fn check(
    store: &Store,
    claim: &RecoveryClaim,
    bounds: Bounds,
) -> Result<Option<(AccountId, RecoveryAnswer)>, ServiceError> {
    let Some(RecoveryEntry {
        account,
        record,
        recovery_seal,
        record_digest,
    }) = store.recovery_by_proof(&claim.proof_check())?
    else {
        return Ok(None);
    };
    let account = AccountId(account);
    if let Some(next_try_ms) = store.tries(&record_digest)?.and_then(|t| t.next_ms)
        && bounds.earliest_ms < next_try_ms
    {
        return Ok(Some((account, RecoveryAnswer::Wait { next_try_ms })));
    }
    let checks = record_checks(&record).map_err(|_| ServiceError::Storage)?;
    if !bh_crypto::constant_time_eq(&claim.token_check(), &checks.token_check) {
        let state = store.record_failure(&record_digest, bounds.latest_ms)?;
        return Ok(Some((
            account,
            RecoveryAnswer::PasswordMismatch {
                tries_left: FREE_TRIES.saturating_sub(state.failures) as u8,
                next_try_ms: state.next_ms,
            },
        )));
    }
    let genesis = store
        .account_event(&account.0, 1)?
        .ok_or(ServiceError::Storage)?;
    // The devices are told before the tries reset.
    store.add_notice(&account.0, bounds.latest_ms)?;
    store.clear_tries(&record_digest)?;
    Ok(Some((
        account,
        RecoveryAnswer::Released {
            genesis,
            record,
            recovery_seal,
        },
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_free_then_hourly_for_a_day_then_daily() {
        for failures in 0..FREE_TRIES {
            assert_eq!(next_try(failures, None, 10), None);
        }
        let fifth = 1_000;
        assert_eq!(next_try(5, Some(fifth), fifth), Some(fifth + HOUR_MS));
        let last_hourly = fifth + DAY_MS - 1;
        assert_eq!(
            next_try(28, Some(fifth), last_hourly),
            Some(last_hourly + HOUR_MS)
        );
        assert_eq!(
            next_try(29, Some(fifth), fifth + DAY_MS),
            Some(fifth + 2 * DAY_MS)
        );
        assert_eq!(next_try(u32::MAX, Some(0), u64::MAX), Some(u64::MAX));
    }
}
