//! App grants in account data: each app's own grants, the grants mounted bases
//! get from the bases they're mounted in, and a pending change's grants before.

use crate::account::Data;
use crate::{BaseId, DeviceId, Mode, Mount};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) type Grants = BTreeMap<BaseId, Mode>;

pub(crate) fn mode_text(mode: Mode) -> &'static str {
    match mode {
        Mode::ReadWrite => "rw",
        Mode::ReadOnly => "ro",
    }
}

fn wider(a: Mode, b: Mode) -> Mode {
    if a == Mode::ReadWrite || b == Mode::ReadWrite {
        Mode::ReadWrite
    } else {
        Mode::ReadOnly
    }
}

fn parse(value: Option<&Value>) -> Grants {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(id, mode)| {
            let mode = match mode.as_str()? {
                "rw" => Mode::ReadWrite,
                "ro" => Mode::ReadOnly,
                _ => return None,
            };
            Some((id.parse().ok()?, mode))
        })
        .collect()
}

pub(crate) fn to_value(grants: &Grants) -> Value {
    Value::Object(
        grants
            .iter()
            .map(|(id, mode)| (id.to_string(), Value::from(mode_text(*mode))))
            .collect(),
    )
}

fn apps(data: &Data) -> impl Iterator<Item = (DeviceId, &Map<String, Value>)> {
    data.get("apps")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(id, app)| Some((id.parse().ok()?, app.as_object()?)))
}

fn app(data: &Data, device: DeviceId) -> Option<&Map<String, Value>> {
    data.get("apps")?.get(device.to_string())?.as_object()
}

/// Every mount in account data, by mounted base.
pub(crate) fn mounts(data: &Data) -> BTreeMap<BaseId, Mount> {
    data.get("mounts")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(base, mount)| {
            let base = base.parse().ok()?;
            let parent = mount.get("parent")?.as_str()?.parse().ok()?;
            let folder = mount.get("folder")?.as_str()?.parse().ok()?;
            Some((
                base,
                Mount {
                    base,
                    parent,
                    folder,
                },
            ))
        })
        .collect()
}

/// The app's own grants.
pub(crate) fn direct(data: &Data, device: DeviceId) -> Grants {
    parse(app(data, device).and_then(|app| app.get("bases")))
}

/// The app's grants before a pending change, if one is pending.
pub(crate) fn was(data: &Data, device: DeviceId) -> Option<Grants> {
    let was = app(data, device)?.get("was")?;
    Some(parse(Some(was)))
}

/// Own grants, and for each mounted base the widest grant on it or on a base
/// above it.
pub(crate) fn effective(direct: &Grants, mounts: &BTreeMap<BaseId, Mount>) -> Grants {
    let mut out = Grants::new();
    for &start in direct.keys().chain(mounts.keys()) {
        let mut seen = BTreeSet::new();
        let mut base = Some(start);
        let mut mode = None;
        while let Some(id) = base.filter(|id| seen.insert(*id)) {
            if let Some(&own) = direct.get(&id) {
                mode = Some(mode.map_or(own, |m| wider(m, own)));
            }
            base = mounts.get(&id).map(|m| m.parent);
        }
        if let Some(mode) = mode {
            out.insert(start, mode);
        }
    }
    out
}

fn all_effective(data: &Data) -> BTreeMap<DeviceId, Grants> {
    let mounts = mounts(data);
    apps(data)
        .map(|(device, _)| (device, effective(&direct(data, device), &mounts)))
        .collect()
}

/// Applies `change`, then marks each app whose effective grants changed as
/// pending, keeping its grants before in `was`, widened with any `was` it had.
pub(crate) fn edit(data: &mut Data, change: impl FnOnce(&mut Data)) {
    let before = all_effective(data);
    change(data);
    for (device, after) in all_effective(data) {
        let old = before.get(&device).cloned().unwrap_or_default();
        if old == after {
            continue;
        }
        let mut was = was(data, device).unwrap_or_default();
        for (base, mode) in old {
            let wide = was.get(&base).map_or(mode, |m| wider(*m, mode));
            was.insert(base, wide);
        }
        if let Some(app) = data
            .get_mut("apps")
            .and_then(|apps| apps.get_mut(device.to_string()))
            .and_then(Value::as_object_mut)
        {
            app.insert("was".into(), to_value(&was));
        }
    }
}

/// Apps that can read `base` now, or could before a pending change.
pub(crate) fn readers(data: &Data, base: BaseId) -> BTreeSet<DeviceId> {
    let mounts = mounts(data);
    apps(data)
        .map(|(device, _)| device)
        .filter(|&device| {
            effective(&direct(data, device), &mounts).contains_key(&base)
                || was(data, device).is_some_and(|was| was.contains_key(&base))
        })
        .collect()
}

/// Apps with a grant change the server hasn't confirmed yet.
pub(crate) fn pending(data: &Data) -> Vec<DeviceId> {
    apps(data)
        .filter(|(_, app)| app.contains_key("was"))
        .map(|(device, _)| device)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ObjectId;
    use serde_json::json;

    fn grants<const N: usize>(list: [(BaseId, Mode); N]) -> Grants {
        list.into()
    }

    fn mounts<const N: usize>(list: [(BaseId, BaseId); N]) -> BTreeMap<BaseId, Mount> {
        list.into_iter()
            .map(|(base, parent)| {
                let folder = ObjectId::random();
                (
                    base,
                    Mount {
                        base,
                        parent,
                        folder,
                    },
                )
            })
            .collect()
    }

    fn set_app_bases<const N: usize>(data: &mut Data, app: DeviceId, list: [(BaseId, &str); N]) {
        let bases: Map<String, Value> = list
            .into_iter()
            .map(|(id, mode)| (id.to_string(), json!(mode)))
            .collect();
        data["apps"][app.to_string()]["bases"] = Value::Object(bases);
    }

    fn data_with_app<const N: usize>(app: DeviceId, list: [(BaseId, &str); N]) -> Data {
        let Value::Object(mut data) =
            json!({ "v": 1, "apps": { app.to_string(): { "name": "X" } } })
        else {
            unreachable!()
        };
        set_app_bases(&mut data, app, list);
        data
    }

    fn ids() -> (BaseId, BaseId, BaseId) {
        (BaseId::random(), BaseId::random(), BaseId::random())
    }

    #[test]
    fn a_mounted_base_gets_every_grant_above_it() {
        let (p, b, c) = ids();
        let eff = effective(
            &grants([(p, Mode::ReadOnly), (c, Mode::ReadWrite)]),
            &mounts([(b, p), (c, b)]),
        );
        assert_eq!(
            eff,
            grants([
                (p, Mode::ReadOnly),
                (b, Mode::ReadOnly),
                (c, Mode::ReadWrite)
            ])
        );
    }

    #[test]
    fn the_wider_mode_wins_inside() {
        let (p, b, _) = ids();
        let eff = effective(
            &grants([(p, Mode::ReadWrite), (b, Mode::ReadOnly)]),
            &mounts([(b, p)]),
        );
        assert_eq!(eff[&b], Mode::ReadWrite);
    }

    #[test]
    fn a_pending_change_counts_old_and_new_readers() {
        let (p, q, _) = ids();
        let x = DeviceId::random();
        let mut data = data_with_app(x, [(p, "rw")]);
        edit(&mut data, |d| set_app_bases(d, x, [(q, "rw")]));
        assert_eq!(readers(&data, p), BTreeSet::from([x]));
        assert_eq!(readers(&data, q), BTreeSet::from([x]));
        assert_eq!(pending(&data), vec![x]);
    }

    #[test]
    fn a_second_change_while_pending_widens_was() {
        let (p, q, r) = ids();
        let x = DeviceId::random();
        let mut data = data_with_app(x, [(p, "ro")]);
        edit(&mut data, |d| set_app_bases(d, x, [(q, "rw")]));
        edit(&mut data, |d| set_app_bases(d, x, [(r, "rw"), (p, "rw")]));
        assert_eq!(
            was(&data, x),
            Some(grants([(p, Mode::ReadOnly), (q, Mode::ReadWrite)]))
        );
        edit(&mut data, |d| set_app_bases(d, x, [(r, "rw")]));
        assert_eq!(
            was(&data, x),
            Some(grants([
                (p, Mode::ReadWrite),
                (q, Mode::ReadWrite),
                (r, Mode::ReadWrite)
            ]))
        );
        assert!(readers(&data, p).contains(&x));
        assert!(readers(&data, q).contains(&x));
        assert!(readers(&data, r).contains(&x));
    }

    #[test]
    fn an_edit_that_changes_nothing_leaves_no_change_pending() {
        let (p, _, _) = ids();
        let x = DeviceId::random();
        let mut data = data_with_app(x, [(p, "rw")]);
        edit(&mut data, |d| set_app_bases(d, x, [(p, "rw")]));
        assert!(pending(&data).is_empty());
    }

    #[test]
    fn mount_cycles_end() {
        let (b, c, _) = ids();
        let eff = effective(&grants([(b, Mode::ReadOnly)]), &mounts([(b, c), (c, b)]));
        assert_eq!(eff, grants([(b, Mode::ReadOnly), (c, Mode::ReadOnly)]));
    }

    #[test]
    fn mounts_read_from_account_data() {
        let (b, p, _) = ids();
        let folder = ObjectId::random();
        let Value::Object(data) = json!({
            "v": 1,
            "mounts": { b.to_string(): { "parent": p.to_string(), "folder": folder.to_string() } }
        }) else {
            unreachable!()
        };
        assert_eq!(
            super::mounts(&data),
            BTreeMap::from([(
                b,
                Mount {
                    base: b,
                    parent: p,
                    folder
                }
            )])
        );
    }
}
