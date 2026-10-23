#[test]
fn default_wait_is_three_days() {
    if option_env!("BH_FLAG_REMOVAL_WAIT") != Some("5m") {
        assert_eq!(bh_flags::REMOVAL_WAIT_MS, 259_200_000);
    }
}
#[test]
fn default_build_lists_no_test_settings() {
    if option_env!("BH_FLAG_REMOVAL_WAIT") != Some("5m") {
        assert!(bh_flags::off_default().is_empty());
    }
}
#[test]
fn bind_root_is_identity_by_default() {
    if option_env!("BH_FLAG_REMOVAL_WAIT") != Some("5m") {
        assert_eq!(bh_flags::bind_root([7; 32]), [7; 32]);
    }
}
#[test]
fn flagged_build_waits_five_minutes_and_binds_another_root() {
    if option_env!("BH_FLAG_REMOVAL_WAIT") == Some("5m") {
        assert_eq!(bh_flags::REMOVAL_WAIT_MS, 300_000);
        assert_eq!(
            bh_flags::off_default(),
            &[bh_flags::Flag {
                name: "removal wait",
                value: "5 minutes"
            }]
        );
        assert_ne!(bh_flags::bind_root([7; 32]), [7; 32]);
    }
}
#[test]
fn build_metadata_defaults_when_unset() {
    if option_env!("BH_BUILD_NUMBER").is_none() && option_env!("BH_SOURCE_COMMIT").is_none() {
        let info = bh_flags::build_info();
        assert_eq!((info.build, info.commit), ("unknown", "unknown"));
    }
}
