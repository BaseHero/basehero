fn main() {
    // Releases set their version in tauri.conf.json, not Cargo.toml, so report that one.
    let conf: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string("tauri.conf.json").expect("read tauri.conf.json"),
    )
    .expect("tauri.conf.json is JSON");
    let version = conf["version"]
        .as_str()
        .expect("tauri.conf.json has a version");
    println!("cargo:rustc-env=BH_APP_VERSION={version}");
    println!("cargo:rerun-if-changed=tauri.conf.json");
    tauri_build::build()
}
