mod common;

use basehero_app_lib::commands::account::accounts;
use basehero_app_lib::views::AppEvent;
use common::{open_at, state_at};

fn server() -> bh_core::Url {
    "http://127.0.0.1:9".parse().unwrap()
}

#[test]
fn a_new_install_opens_with_no_accounts_and_reopens() {
    let (state, events) = state_at(server());
    assert!(accounts(&state).unwrap().is_empty());
    drop(state);
    let again = open_at(events.data_dir(), server(), &events);
    assert!(accounts(&again).unwrap().is_empty());
}

#[test]
fn events_reach_the_capturing_sink() {
    let (state, events) = state_at(server());
    let event = AppEvent::Account {
        account: bh_core::AccountId([7; 16]),
        event: bh_core::AccountEvent::Removed,
    };
    (state.sink)(event);
    let seen = events.wait_for(|e| matches!(e, AppEvent::Account { .. }));
    assert!(matches!(
        seen,
        AppEvent::Account {
            event: bh_core::AccountEvent::Removed,
            ..
        }
    ));
}
