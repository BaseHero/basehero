use basehero_models::accounting::*;
use basehero_models::response::Tokens;

fn tokens() -> Tokens {
    Tokens {
        input: 100,
        cached: 60,
        output: 7,
    }
}
fn charged() -> Settlement {
    Settlement::Charged {
        tokens: tokens(),
        nano_usd: 1234,
    }
}

#[test]
fn cached_tokens_are_a_subset_and_integer_cost_rounds_up_once() {
    let rates = Rates {
        input_per_million: 150_000_000,
        cached_per_million: 15_000_000,
        output_per_million: 500_000_000,
    };
    assert_eq!(rates.cost(tokens()).unwrap(), 10400); // 40*150 + 60*15 + 7*500
    let tiny = Rates {
        input_per_million: 1,
        cached_per_million: 1,
        output_per_million: 1,
    };
    assert_eq!(
        tiny.cost(Tokens {
            input: 1,
            cached: 0,
            output: 1
        })
        .unwrap(),
        1
    );
    assert_eq!(
        rates.cost(Tokens {
            input: 1,
            cached: 2,
            output: 0
        }),
        Err(AccountingError::InvalidTokens)
    );
    let huge = Rates {
        input_per_million: u64::MAX,
        cached_per_million: u64::MAX,
        output_per_million: u64::MAX,
    };
    assert_eq!(
        huge.cost(Tokens {
            input: u64::MAX,
            cached: 0,
            output: u64::MAX
        }),
        Err(AccountingError::Overflow)
    );
}

#[test]
fn stop_before_dispatch_does_not_charge_and_cannot_dispatch_later() {
    let mut attempt = Attempt::new(Route::Near, WorkKind::AskedTurn);
    attempt.stop();
    assert_eq!(attempt.delivery(), Delivery::Stopped);
    assert_eq!(attempt.billing().settlement, Settlement::NotDispatched);
    assert!(!attempt.may_deliver());
    assert!(!attempt.may_retry());
    assert_eq!(
        attempt.mark_dispatched(),
        Err(AccountingError::InvalidTransition)
    );
    assert_eq!(
        attempt.reconcile(charged()),
        Err(AccountingError::InvalidTransition)
    );
}

#[test]
fn inflight_stop_is_immediate_but_billing_stays_uncertain() {
    let mut attempt = Attempt::new(Route::Tinfoil, WorkKind::Legwork);
    attempt.mark_dispatched().unwrap();
    assert!(attempt.may_deliver());
    attempt.stop();
    assert!(!attempt.may_deliver());
    assert!(!attempt.may_retry());
    assert_eq!(attempt.billing().settlement, Settlement::Pending);
    // Late observations/reconciliation must not revive output or tools.
    attempt.record_usage(tokens()).unwrap();
    assert_eq!(attempt.billing().settlement, Settlement::Pending);
    attempt.reconcile(charged()).unwrap();
    assert_eq!(attempt.delivery(), Delivery::Stopped);
    assert!(!attempt.may_deliver());
    assert_eq!(attempt.complete(), Err(AccountingError::InvalidTransition));
    assert_eq!(attempt.billing().settlement, charged());
}

#[test]
fn stop_after_failure_blocks_retry_before_and_after_reconciliation() {
    for settlement in [Settlement::NotCharged, charged()] {
        for stop_before_receipt in [true, false] {
            let mut attempt = Attempt::new(Route::Near, WorkKind::AskedTurn);
            attempt.mark_dispatched().unwrap();
            attempt.fail().unwrap();
            if stop_before_receipt {
                attempt.stop();
                assert_eq!(attempt.billing().settlement, Settlement::Pending);
                assert!(!attempt.may_retry());
            }
            attempt.reconcile(settlement).unwrap();
            if !stop_before_receipt {
                assert!(attempt.may_retry());
                attempt.stop();
            }
            assert_eq!(attempt.delivery(), Delivery::Stopped);
            assert_eq!(attempt.billing().settlement, settlement);
            assert!(!attempt.may_deliver());
            assert!(!attempt.may_retry());
            attempt.reconcile(settlement).unwrap();
            assert!(!attempt.may_retry());
        }
    }
}

#[test]
fn uncertain_failures_cannot_retry_until_trusted_reconciliation() {
    let mut attempt = Attempt::new(Route::Near, WorkKind::WakeUp);
    attempt.mark_dispatched().unwrap();
    attempt.fail().unwrap();
    assert!(!attempt.may_retry());
    attempt.record_usage(tokens()).unwrap(); // Body usage is not trusted settlement.
    assert!(!attempt.may_retry());
    attempt.reconcile(charged()).unwrap();
    assert!(attempt.may_retry());
    assert_eq!(
        attempt.mark_dispatched(),
        Err(AccountingError::InvalidTransition)
    ); // New attempt required.
    let mut refused = Attempt::new(Route::Near, WorkKind::AskedTurn);
    refused.fail().unwrap(); // verification or local admission failed before dispatch
    assert!(refused.may_retry());
}

#[test]
fn receipts_are_idempotent_but_conflicts_do_not_rewrite_charges() {
    let mut attempt = Attempt::new(Route::Near, WorkKind::NightlyReflection);
    attempt.mark_dispatched().unwrap();
    assert_eq!(
        attempt.reconcile(Settlement::Pending),
        Err(AccountingError::InvalidSettlement)
    );
    assert_eq!(
        attempt.reconcile(Settlement::NotDispatched),
        Err(AccountingError::InvalidSettlement)
    );
    attempt.reconcile(charged()).unwrap();
    attempt.reconcile(charged()).unwrap();
    assert_eq!(
        attempt.reconcile(Settlement::NotCharged),
        Err(AccountingError::ConflictingSettlement)
    );
    assert_eq!(attempt.billing().settlement, charged());
    attempt.complete().unwrap();
    attempt.stop();
    assert_eq!(attempt.delivery(), Delivery::Completed);
    assert!(!attempt.may_retry());
}

#[test]
fn usage_observations_are_validated_and_cannot_silently_change() {
    let mut attempt = Attempt::new(Route::Tinfoil, WorkKind::FirstLook);
    assert_eq!(
        attempt.record_usage(tokens()),
        Err(AccountingError::InvalidTransition)
    );
    attempt.mark_dispatched().unwrap();
    assert_eq!(
        attempt.record_usage(Tokens {
            input: 1,
            cached: 2,
            output: 0
        }),
        Err(AccountingError::InvalidTokens)
    );
    attempt.record_usage(tokens()).unwrap();
    attempt.record_usage(tokens()).unwrap();
    assert_eq!(
        attempt.record_usage(Tokens {
            input: 50,
            cached: 0,
            output: 1
        }),
        Err(AccountingError::ConflictingUsage)
    );
    assert_eq!(
        attempt.reconcile(Settlement::Charged {
            tokens: Tokens {
                input: 1,
                cached: 2,
                output: 0
            },
            nano_usd: 1
        }),
        Err(AccountingError::InvalidTokens)
    );
    assert_eq!(attempt.billing().settlement, Settlement::Pending);
}

#[test]
fn protected_summaries_count_retries_and_pending_separately() {
    let mut first = Attempt::new(Route::Near, WorkKind::AskedTurn);
    first.mark_dispatched().unwrap();
    first.fail().unwrap();
    first.reconcile(charged()).unwrap();
    let mut retry = Attempt::new(Route::Tinfoil, WorkKind::AskedTurn);
    retry.mark_dispatched().unwrap();
    retry.complete().unwrap();
    let second_charge = Settlement::Charged {
        tokens: Tokens {
            input: 200,
            cached: 30,
            output: 11,
        },
        nano_usd: 4321,
    };
    retry.reconcile(second_charge).unwrap();
    retry.reconcile(second_charge).unwrap(); // replay must not add another charge
    let mut pending = Attempt::new(Route::Near, WorkKind::AskedTurn);
    pending.mark_dispatched().unwrap();
    pending.complete().unwrap(); // missing receipt remains unknown, not zero cost
    let mut stopped = Attempt::new(Route::Near, WorkKind::FirstLook);
    stopped.stop();
    let summary = summarize(&[first, retry, pending, stopped]).unwrap();
    let asked = summary.get(&WorkKind::AskedTurn).unwrap();
    assert_eq!(asked.attempts, 3);
    assert_eq!(asked.settled_nano_usd, 5555);
    assert_eq!(asked.pending, 1);
    assert_eq!(
        asked.tokens,
        Tokens {
            input: 300,
            cached: 90,
            output: 18
        }
    );
    assert_eq!(summary.get(&WorkKind::FirstLook).unwrap().pending, 0);
}

#[test]
fn ordinary_projection_never_serializes_protected_work_kind_or_observations() {
    let mut a = Attempt::new(Route::Near, WorkKind::NightlyReflection);
    a.mark_dispatched().unwrap();
    a.record_usage(tokens()).unwrap();
    let value = serde_json::to_value(a.billing()).unwrap();
    assert_eq!(
        value,
        serde_json::json!({"route":"near","settlement":{"state":"pending"}})
    );
    assert!(!format!("{a:?}").contains("NightlyReflection"));
}
