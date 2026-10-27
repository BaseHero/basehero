use crate::approve::terminal_device_name;
use bh_core::{AccountUsage, UsageRow};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Default)]
struct Total {
    calls: u64,
    missing: u64,
    cost: u64,
    price: u64,
    stored_bytes: u64,
}
impl Total {
    fn add(&mut self, row: &UsageRow) {
        self.calls += row.requests;
        self.missing += row.unreported;
        self.cost += row.cost_micro_usd;
        self.price += row.price_micro_usd;
        self.stored_bytes += row.stored_bytes;
    }
    fn display(&self) -> String {
        format!(
            "{} calls, {} calls with no reported cost, ${:.4} cost, ${:.4} price{}",
            self.calls,
            self.missing,
            self.cost as f64 / 1e6,
            self.price as f64 / 1e6,
            if self.stored_bytes > 0 {
                format!(", {} bytes stored", self.stored_bytes)
            } else {
                String::new()
            }
        )
    }
}
fn grouped(rows: &[UsageRow], key: impl Fn(&UsageRow) -> String) -> BTreeMap<String, Total> {
    let mut totals = BTreeMap::<String, Total>::new();
    for row in rows {
        totals.entry(key(row)).or_default().add(row);
    }
    totals
}
fn base_name(usage: &AccountUsage, row: &UsageRow) -> String {
    // Known hidden-bases limit: someone holding an unlocked device can see
    // how many hidden bases exist. Unnamed storage stays in Other so totals add up.
    match row.base {
        Some(base) => usage
            .base_names
            .get(&base)
            .cloned()
            .unwrap_or_else(|| "Other".into()),
        None if row.device.is_none() => "not broken down".into(),
        None => "Other".into(),
    }
}
fn app_name(usage: &AccountUsage, row: &UsageRow) -> String {
    match row.device {
        Some(device) => usage
            .device_names
            .get(&device)
            .cloned()
            .unwrap_or_else(|| "a removed device".into()),
        None => "not broken down".into(),
    }
}
fn print_group(out: &mut String, title: &str, totals: BTreeMap<String, Total>) {
    out.push_str(title);
    out.push('\n');
    let mut ordered: Vec<_> = totals.into_iter().collect();
    ordered.sort_by(|(name_a, a), (name_b, b)| b.price.cmp(&a.price).then(name_a.cmp(name_b)));
    for (name, total) in ordered {
        out.push_str(&format!(
            "  {}: {}\n",
            terminal_device_name(&name),
            total.display()
        ));
    }
}

pub fn format(usage: &AccountUsage, month: &str) -> String {
    let mut out = format!("Usage (UTC) — {month}\n");
    let current: Vec<_> = usage
        .months
        .iter()
        .filter(|r| r.period == month)
        .cloned()
        .collect();
    let summed = grouped(&current, |_| "total".into());
    print_group(&mut out, "Month total", summed);
    print_group(
        &mut out,
        "By service",
        grouped(&current, |r| r.service.clone()),
    );
    print_group(
        &mut out,
        "By base",
        grouped(&current, |r| base_name(usage, r)),
    );
    print_group(
        &mut out,
        "By app",
        grouped(
            &current
                .iter()
                .filter(|r| r.service != "storage")
                .cloned()
                .collect::<Vec<_>>(),
            |r| app_name(usage, r),
        ),
    );
    print_group(
        &mut out,
        "Months",
        grouped(&usage.months, |r| r.period.clone()),
    );
    print_group(&mut out, "Days", grouped(&usage.days, |r| r.period.clone()));
    if current.iter().any(|row| row.service == "storage") {
        out.push_str("Storage is a month at today's size.\n");
    }
    out
}

fn json_totals(totals: BTreeMap<String, Total>) -> Vec<Value> {
    let mut ordered: Vec<_> = totals.into_iter().collect();
    ordered.sort_by(|(name_a, a), (name_b, b)| b.price.cmp(&a.price).then(name_a.cmp(name_b)));
    ordered
        .into_iter()
        .map(|(name, total)| {
            json!({
                "name": name, "requests": total.calls, "unreported": total.missing,
                "costMicroUsd": total.cost, "priceMicroUsd": total.price, "storedBytes": total.stored_bytes,
            })
        })
        .collect()
}

/// JSON output contains named summaries, never the server's random base IDs.
pub fn json(usage: &AccountUsage, month: &str) -> Value {
    let current: Vec<_> = usage
        .months
        .iter()
        .filter(|row| row.period == month)
        .cloned()
        .collect();
    // Unnamed bases fold into Other. Known limit: someone holding an unlocked
    // device can see how many hidden bases exist, including through storage.
    json!({
        "months": json_totals(grouped(&usage.months, |r| r.period.clone())),
        "days": json_totals(grouped(&usage.days, |r| r.period.clone())),
        "byService": json_totals(grouped(&current, |r| r.service.clone())),
        "byBase": json_totals(grouped(&current, |r| base_name(usage, r))),
        "byApp": json_totals(grouped(&current.iter().filter(|r| r.service != "storage").cloned().collect::<Vec<_>>(), |r| app_name(usage, r))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_core::{BaseId, DeviceId};

    #[test]
    fn bh_usage_prints_totals_by_service_base_and_app() {
        let base = BaseId::random();
        let device = DeviceId::random();
        let row = UsageRow {
            period: "2026-10".into(),
            service: "model".into(),
            base: Some(base),
            device: Some(device),
            requests: 2,
            unreported: 1,
            prompt_tokens: 4,
            completion_tokens: 5,
            cost_micro_usd: 12345,
            price_micro_usd: 18518,
            stored_bytes: 0,
        };
        let usage = AccountUsage {
            months: vec![row.clone()],
            days: vec![UsageRow {
                period: "2026-10-27".into(),
                ..row
            }],
            base_names: [(base, "Personal".into())].into(),
            device_names: [(device, "My app".into())].into(),
        };
        let printed = format(&usage, "2026-10");
        for expected in [
            "By service\n  model:",
            "By base\n  Personal:",
            "By app\n  My app:",
            "Months\n  2026-10:",
            "Days\n  2026-10-27:",
            "2 calls, 1 calls with no reported cost",
            "$0.0123 cost",
            "$0.0185 price",
        ] {
            assert!(printed.contains(expected), "missing {expected}: {printed}");
        }
    }

    #[test]
    fn storage_shows_base_share_without_an_app_or_fake_calls() {
        let base = BaseId::random();
        let storage = UsageRow {
            period: "2026-10".into(),
            service: "storage".into(),
            base: Some(base),
            device: None,
            requests: 0,
            unreported: 0,
            prompt_tokens: 0,
            completion_tokens: 0,
            cost_micro_usd: 273,
            price_micro_usd: 410,
            stored_bytes: 5_242_880,
        };
        let usage = AccountUsage {
            months: vec![storage],
            days: vec![],
            base_names: [(base, "Personal".into())].into(),
            device_names: Default::default(),
        };
        let printed = format(&usage, "2026-10");
        assert!(printed.contains("storage:"), "{printed}");
        assert!(printed.contains("Personal:"), "{printed}");
        assert!(printed.contains("5242880 bytes"), "{printed}");
        assert!(!printed.contains("By app\n  not broken down"), "{printed}");
        assert!(
            printed.contains("Storage is a month at today's size."),
            "{printed}"
        );
        let summary = json(&usage, "2026-10");
        assert_eq!(summary["byBase"][0]["storedBytes"], 5_242_880);
        assert_eq!(summary["byApp"], serde_json::json!([]));
    }

    #[test]
    fn unnamed_base_is_other_in_text_and_json_without_exposing_ids() {
        let hidden = BaseId::random();
        let device = DeviceId::random();
        let row = |base, requests, price| UsageRow {
            period: "2026-10".into(),
            service: "model".into(),
            base,
            device: Some(device),
            requests,
            unreported: 0,
            prompt_tokens: 0,
            completion_tokens: 0,
            cost_micro_usd: price / 2,
            price_micro_usd: price,
            stored_bytes: 0,
        };
        let usage = AccountUsage {
            months: vec![row(Some(hidden), 2, 12000), row(None, 1, 6000)],
            days: vec![],
            base_names: Default::default(),
            device_names: [(device, "Writer".into())].into(),
        };
        let printed = format(&usage, "2026-10");
        assert!(printed.contains("By base\n  Other: 3 calls"), "{printed}");
        assert!(!printed.contains(&hidden.to_string()));
        assert!(!printed.contains("a base you no longer have"));
        let json = json(&usage, "2026-10").to_string();
        assert!(!json.contains(&hidden.to_string()), "{json}");
        assert!(json.contains("Other"), "{json}");
        assert!(json.contains("\"requests\":3"), "{json}");
    }
}
