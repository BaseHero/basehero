fn main() {
    for key in [
        "BH_FLAG_REMOVAL_WAIT",
        "BH_RELEASE",
        "BH_BUILD_NUMBER",
        "BH_SOURCE_COMMIT",
    ] {
        println!("cargo:rerun-if-env-changed={key}");
    }
    println!("cargo:rustc-check-cfg=cfg(bh_flag_removal_wait_5m)");
    let wait = std::env::var("BH_FLAG_REMOVAL_WAIT").ok();
    assert!(
        wait.as_deref().is_none_or(|value| value == "5m"),
        "BH_FLAG_REMOVAL_WAIT must be 5m or unset"
    );
    assert!(
        !(std::env::var("BH_RELEASE").as_deref() == Ok("1") && wait.is_some()),
        "release builds refuse off-default flags"
    );
    if wait.is_some() {
        println!("cargo:rustc-cfg=bh_flag_removal_wait_5m");
    }
    for (source, target) in [
        ("BH_BUILD_NUMBER", "BH_FLAGS_BUILD_NUMBER"),
        ("BH_SOURCE_COMMIT", "BH_FLAGS_SOURCE_COMMIT"),
    ] {
        println!(
            "cargo:rustc-env={target}={}",
            std::env::var(source).unwrap_or_else(|_| "unknown".into())
        );
    }
}
