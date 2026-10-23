//! Completing a first device's setup at its account home. Signup retained
//! the original three-event prefix and three private objects (recovery
//! record, device seal, recovery seal). Setup completes only after a
//! verified read of the account log holds exactly that prefix, with the
//! home's confirmations of positions 2 and 3 the device keeps with it, and the
//! service answers that the home durably stored exactly those objects, and
//! then only if the native authority that read them is still current.
//!
//! Anything less leaves setup pending, and the next attempt sends the same
//! retained bytes again: the home stores them once and answers an exact
//! retry the same way. Nothing is resealed or regenerated. This is checked
//! once per client start, so a setup an earlier client cleared on public
//! ordering alone is still stored. Storage acknowledges only these objects,
//! never a base head or note content.
use crate::{
    HomeRetryReason, HomeSetup, HomeStatus, Shared, backoff::Backoff, outbox::Fail, outbox::Link,
    register,
};
use bh_account::{ConfirmedTime, Head as AccountHead, VerifiedAccount};
use bh_authz_proto::{FromService, ToService};
use bh_sync::home_objects;
use std::sync::Arc;

/// Retry independently of note publication, with a separate authenticated
/// session and data link. A wake can retry sooner after an unavailable home.
/// This task ends after one successful recheck for this client start.
pub(crate) async fn run(shared: Arc<Shared>) {
    let mut link = Link::default();
    let mut backoff = Backoff::default();
    loop {
        match complete(&shared, &mut link).await {
            Ok(Some(())) => {
                shared.home_status.send_replace(HomeStatus::Done);
                break;
            }
            Ok(None) => {
                shared.home_status.send_replace(HomeStatus::NotNeeded);
                break;
            }
            Err(failure) => {
                if failure.fail == Fail::Network {
                    link.drop_data();
                }
                shared
                    .home_status
                    .send_replace(HomeStatus::Retrying(failure.reason));
                let _ = tokio::time::timeout(backoff.next(), shared.home_wake.notified()).await;
            }
        }
    }
    shared.home_authz.close().await;
}

/// One attempt's content-free reason plus its transport classification.
struct HomeFailure {
    fail: Fail,
    reason: HomeRetryReason,
}
impl HomeFailure {
    fn step(fail: Fail) -> Self {
        let reason = match fail {
            Fail::Network | Fail::Retry | Fail::Missing => HomeRetryReason::Unavailable,
            Fail::Authorization | Fail::Unregistered => HomeRetryReason::Refused,
            Fail::Local | Fail::Unsupported | Fail::Stopped => HomeRetryReason::Other,
        };
        Self { fail, reason }
    }
    fn retained() -> Self {
        Self {
            fail: Fail::Local,
            reason: HomeRetryReason::SetupNotReady,
        }
    }
}

/// Complete this device's setup at its home, or learn it has none to
/// complete (`None`).
async fn complete(shared: &Shared, link: &mut Link) -> Result<Option<()>, HomeFailure> {
    let Some(setup) = shared
        .signer
        .initial_home_setup()
        .map_err(|_| HomeFailure::retained())?
    else {
        return Ok(None);
    };
    let identity = shared
        .signer
        .identity()
        .map_err(|_| HomeFailure::step(Fail::Authorization))?;
    let digest = checked_digest(&setup, &identity).map_err(|_| HomeFailure::retained())?;
    let prefix = &setup.prefix;
    let at = register::earliest_active(&identity, &prefix.events).map_err(HomeFailure::step)?;
    let ordered = register::order_prefix(
        shared,
        &shared.home_authz,
        link,
        &identity,
        &prefix.events,
        at,
    )
    .await
    .map_err(|fail| HomeFailure::step(home_fail(fail)))?;
    let read: Vec<&[u8]> = ordered.iter().map(|e| e.original.as_slice()).collect();
    if read != prefix.events
        || register::replayed(&identity, &read).map_err(HomeFailure::step)? != prefix.head
    {
        return Err(HomeFailure::retained());
    }
    // The home's confirmations of positions 2 and 3, verified with them.
    let evidence = match ordered.as_slice() {
        [_, record, key] => [record, key].map(|e| {
            Some((
                ConfirmedTime {
                    earliest_ms: e.time?.earliest_ms,
                    latest_ms: e.time?.latest_ms,
                },
                e.proof.as_ref()?.encode().to_vec(),
            ))
        }),
        _ => return Err(HomeFailure::retained()),
    };
    let [Some(record), Some(key)] = evidence else {
        return Err(HomeFailure::step(Fail::Missing));
    };
    // A prior authorization retry may have preceded this store attempt;
    // while its answer is outstanding the home check is pending, not refused.
    shared.home_status.send_replace(HomeStatus::Pending);
    let answer = {
        let mut session = shared
            .home_authz
            .session_at(shared, at)
            .await
            .map_err(|e| HomeFailure::step(home_fail(e.into())))?;
        session
            .ask(ToService::StoreHomeObjects {
                prefix: prefix.head,
                record: setup.objects.record.clone(),
                device_seal: setup.objects.device_seal.clone(),
                recovery_seal: setup.objects.recovery_seal.clone(),
            })
            .await
            .map_err(|e| HomeFailure::step(home_fail(e.into())))?
    };
    if !stored(&answer, prefix.head, digest) {
        let reason = match answer {
            FromService::Unavailable => HomeRetryReason::Unavailable,
            FromService::Refused { .. } => HomeRetryReason::Refused,
            _ => HomeRetryReason::Other,
        };
        return Err(HomeFailure {
            fail: home_fail(Fail::from_answer(&answer)),
            reason,
        });
    }
    shared
        .signer
        .confirm_home_ordered(&setup, [record, key])
        .map_err(|_| HomeFailure::step(Fail::Authorization))?;
    Ok(Some(()))
}

/// The retained prefix must be this account's signup, replaying to exactly
/// its head, and the objects those its signed events commit to. Returns
/// their canonical bundle's digest.
fn checked_digest(setup: &HomeSetup, identity: &crate::Identity) -> Result<[u8; 32], Fail> {
    let HomeSetup {
        prefix, objects, ..
    } = setup;
    let events: Vec<&[u8]> = prefix.events.iter().map(Vec::as_slice).collect();
    if prefix.anchor != identity.account {
        return Err(Fail::Local);
    }
    let view =
        VerifiedAccount::replay(prefix.anchor, &events, prefix.head).map_err(|_| Fail::Local)?;
    view.verify_initial_objects(
        &objects.record,
        &objects.device_seal,
        &objects.recovery_seal,
    )
    .map_err(|_| Fail::Local)?;
    let bundle = home_objects::encode(
        &objects.record,
        &objects.device_seal,
        &objects.recovery_seal,
    )
    .map_err(|_| Fail::Local)?;
    Ok(home_objects::digest(&bundle).map_err(|_| Fail::Local)?.0)
}

/// Whether `answer` says the home stored exactly the bundle with `digest`
/// at the signup prefix `prefix`. Nothing else is storage.
fn stored(answer: &FromService, prefix: AccountHead, digest: [u8; 32]) -> bool {
    matches!(
        answer,
        FromService::HomeObjectsStored { prefix: p, digest: d } if *p == prefix && *d == digest
    )
}

/// A home step never re-registers the own base: waiting for authority is
/// the most it implies.
fn home_fail(fail: Fail) -> Fail {
    match fail {
        Fail::Unregistered => Fail::Authorization,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_authz_proto::Refusal;

    #[test]
    fn only_the_exact_storage_answer_is_storage() {
        let prefix = AccountHead {
            position: 3,
            hash: [7; 32],
        };
        let digest = [9; 32];
        assert!(stored(
            &FromService::HomeObjectsStored { prefix, digest },
            prefix,
            digest
        ));
        let other_head = AccountHead {
            position: 3,
            hash: [8; 32],
        };
        let other_position = AccountHead {
            position: 4,
            hash: [7; 32],
        };
        for answer in [
            FromService::HomeObjectsStored {
                prefix: other_head,
                digest,
            },
            FromService::HomeObjectsStored {
                prefix: other_position,
                digest,
            },
            FromService::HomeObjectsStored {
                prefix,
                digest: [10; 32],
            },
            FromService::Permits { items: vec![] },
            FromService::Authenticated {
                account_head: prefix,
            },
            FromService::Refused {
                reason: Refusal::Invalid,
            },
            FromService::Unavailable,
        ] {
            assert!(!stored(&answer, prefix, digest), "{answer:?}");
        }
    }
}
