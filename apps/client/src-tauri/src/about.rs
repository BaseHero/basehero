use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct About {
    version: String,
    build: String,
    commit: String,
    test_settings: Vec<Setting>,
}

#[derive(Serialize)]
struct Setting {
    name: String,
    value: String,
}

#[tauri::command]
pub(crate) fn app_about() -> About {
    let info = bh_flags::build_info();
    About {
        version: env!("CARGO_PKG_VERSION").into(),
        build: info.build.into(),
        commit: info.commit.into(),
        test_settings: bh_flags::off_default()
            .iter()
            .map(|flag| Setting {
                name: flag.name.into(),
                value: flag.value.into(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn about_reports_no_test_settings_in_a_default_build() {
        if option_env!("BH_FLAG_REMOVAL_WAIT") != Some("5m") {
            assert!(super::app_about().test_settings.is_empty());
        }
    }
}
