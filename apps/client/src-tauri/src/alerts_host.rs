//! The host delivers alert kinds from verified history. Turn those kinds
//! into fixed notification text here, never server-supplied prose.
use bh_host::devices::{AlertItem, DeliveredAlert};

fn body(item: &AlertItem) -> String {
    let subject = item.subject_name.as_deref().unwrap_or("A device");
    let actor = item.actor_name.as_deref().unwrap_or("another device");
    match item.kind {
        "device_added_by_qr" => format!("{subject} was added"),
        "device_added_by_kit" => {
            "Your account was opened on a new device with your password and recovery kit".into()
        }
        "kit_used" => "Your recovery kit was used".into(),
        "removal_requested" => format!("Removal of {subject} requested from {actor}"),
        "removal_cancelled" => format!("Removal of {subject} was cancelled"),
        "removal_effective" => format!("{subject} was removed"),
        "kit_changed" => format!("Password and recovery kit changed from {actor}"),
        "kit_not_changed" => "Your recovery kit wasn’t changed. Your old kit still works.".into(),
        "refused_change" => "BaseHero refused an invalid change to your account".into(),
        _ => "Security alert".into(),
    }
}

/// The full local container identity and its local row ID form one native key.
fn identity(delivered: &DeliveredAlert) -> String {
    let mut key = String::from("basehero-alert-");
    for byte in delivered.container.0 {
        use std::fmt::Write;
        write!(key, "{byte:02x}").expect("writing to a String");
    }
    use std::fmt::Write;
    write!(key, "-{}", delivered.alert.id).expect("writing to a String");
    key
}

fn unseen<'a>(
    seen: &mut std::collections::HashSet<String>,
    rows: &'a [DeliveredAlert],
) -> Vec<(String, &'a DeliveredAlert)> {
    rows.iter()
        .rev()
        .filter_map(|alert| {
            let key = identity(alert);
            seen.insert(key.clone()).then_some((key, alert))
        })
        .collect()
}

pub(crate) fn start(app: tauri::AppHandle, accounts: &crate::account_host::SharedAccountHost) {
    let mut alerts = accounts.alerts();
    tauri::async_runtime::spawn(async move {
        #[cfg(target_os = "macos")]
        let _ = &app;
        let mut seen = std::collections::HashSet::new();
        loop {
            let rows = alerts.borrow_and_update().clone();
            for (key, alert) in unseen(&mut seen, &rows) {
                let message = body(alert);
                #[cfg(target_os = "macos")]
                crate::native::notify::send(&key, &message);
                #[cfg(target_os = "android")]
                crate::notify_android::send(&app, &key, &message);
                #[cfg(not(any(target_os = "macos", target_os = "android")))]
                {
                    let _ = (&app, &key, &message);
                }
            }
            if alerts.changed().await.is_err() {
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_device::ContainerId;

    #[test]
    fn native_identity_scopes_equal_rows_and_retains_full_ids() {
        let alert = AlertItem {
            id: i64::MAX,
            kind: "kit_used",
            subject_name: None,
            actor_name: None,
            time_ms: Some(123),
            deadline_ms: None,
        };
        let first = DeliveredAlert {
            container: ContainerId([0x11; 16]),
            alert: alert.clone(),
        };
        let second = DeliveredAlert {
            container: ContainerId([0x22; 16]),
            alert: alert.clone(),
        };
        let later_id = DeliveredAlert {
            container: first.container,
            alert: AlertItem {
                id: i64::MAX - (1_i64 << 32),
                ..alert
            },
        };
        let first_key = identity(&first);
        assert_eq!(
            first_key,
            format!("basehero-alert-{}-{}", "11".repeat(16), i64::MAX)
        );
        assert_ne!(first_key, identity(&second));
        assert_ne!(
            first_key,
            identity(&later_id),
            "Android must not truncate an i64 row ID"
        );
        let mut seen = std::collections::HashSet::new();
        let rows = [first.clone(), second, first, later_id];
        let delivered = unseen(&mut seen, &rows);
        assert_eq!(
            delivered.len(),
            3,
            "both containers and both large IDs reach native delivery"
        );
        assert!(delivered.iter().any(|(key, _)| key == &first_key));
        assert_eq!(unseen(&mut seen, &rows).len(), 0, "the same alert dedupes");
    }
}
