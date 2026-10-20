//! Builds the note engine for wasm32-unknown-unknown from this workspace and
//! its lockfile, then compiles it to Pulley bytecode, so apps ship it ready
//! to load and never compile Wasm at run time.

use std::{env, fs, path::PathBuf, process::Command};

include!("src/config.rs");

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let engine = manifest.parent().expect("note-engine");
    let workspace = engine.join("../..");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("out dir"));
    for input in [
        engine.join("src"),
        engine.join("Cargo.toml"),
        manifest.join("src/config.rs"),
        workspace.join("libs/core/src"),
        workspace.join("libs/core/Cargo.toml"),
        workspace.join("note-schema"),
        workspace.join("third_party/yrs/src"),
        workspace.join("third_party/yrs/Cargo.toml"),
        workspace.join("Cargo.toml"),
        workspace.join("Cargo.lock"),
    ] {
        println!("cargo:rerun-if-changed={}", input.display());
    }

    let target_dir = out.join("engine");
    let mut cargo = Command::new(env::var_os("CARGO").expect("cargo"));
    cargo
        .args(["build", "--locked", "--profile", "note-engine"])
        .args(["--target", "wasm32-unknown-unknown", "-p", "bh-note-engine"])
        .arg("--manifest-path")
        .arg(workspace.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target_dir);
    // Nothing the outer build set for its own target, wrappers or lints.
    for key in [
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET",
        "CARGO_BUILD_TARGET_DIR",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CLIPPY_ARGS",
    ] {
        cargo.env_remove(key);
    }
    let status = cargo.status().expect("run cargo for the note engine");
    assert!(
        status.success(),
        "building the note engine failed: {status}"
    );

    let wasm = fs::read(target_dir.join("wasm32-unknown-unknown/note-engine/bh_note_engine.wasm"))
        .expect("note engine module");
    let target = pulley_target(
        &env::var("CARGO_CFG_TARGET_POINTER_WIDTH").expect("pointer width"),
        &env::var("CARGO_CFG_TARGET_ENDIAN").expect("endian"),
    );
    let config = note_engine_config(&target).expect("Pulley configuration");
    let compiled = wasmtime::Engine::new(&config)
        .and_then(|engine| engine.precompile_module(&wasm))
        .expect("compile the note engine to Pulley");
    fs::write(out.join("note-engine.cwasm"), compiled).expect("write the compiled engine");
}
