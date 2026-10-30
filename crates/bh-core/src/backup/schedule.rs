//! One non-owning, clock-driven backup worker per account.

use crate::account::AccountWeak;
use crate::{BackupSchedule, Clock};
use std::sync::Arc;
use tokio::sync::Notify;

pub(crate) async fn run(
    weak: AccountWeak,
    signal: Arc<Notify>,
    clock: Clock,
    schedule: BackupSchedule,
) {
    loop {
        signal.notified().await;
        let Some(account) = weak.upgrade() else { break };
        if account.check_active().is_err() {
            break;
        }
        let Ok(row) = account.backup_row() else {
            continue;
        };
        if !row.enabled {
            continue;
        }
        let first_change = clock.now_ms();
        let last_run = row.last_run.as_deref().and_then(super::format::parse_run);
        let min_wait = last_run.map_or(0, |at| {
            at.saturating_add(schedule.min_interval.as_millis().min(i64::MAX as u128) as i64)
                .saturating_sub(clock.edit_time_ms())
                .max(0) as u64
        });
        let due = first_change
            .saturating_add(schedule.delay.as_millis().min(u64::MAX as u128) as u64)
            .max(clock.now_ms().saturating_add(min_wait));
        drop(account);
        loop {
            tokio::select! {
                () = clock.sleep_until(due) => break,
                () = signal.notified() => {
                    if weak.upgrade().is_none_or(|account| account.check_active().is_err()) {
                        return;
                    }
                    // Later changes in this window do not postpone its first deadline.
                }
            }
        }
        let Some(account) = weak.upgrade() else { break };
        if account.check_active().is_err() {
            break;
        }
        if account.backup_row().is_ok_and(|row| row.enabled) {
            let _ = account.backup_now().await;
        }
    }
}
