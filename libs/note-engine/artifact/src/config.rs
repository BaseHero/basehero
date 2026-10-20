/// The configuration the note engine is compiled for and run with. A
/// precompiled module loads only into an engine configured exactly so, by
/// the same Wasmtime release.
fn note_engine_config(target: &str) -> wasmtime::Result<wasmtime::Config> {
    let mut config = wasmtime::Config::new();
    config.target(target)?.consume_fuel(true);
    Ok(config)
}

/// Pulley for a target with this pointer width and byte order.
fn pulley_target(pointer_width: &str, endian: &str) -> String {
    let be = if endian == "big" { "be" } else { "" };
    format!("pulley{pointer_width}{be}")
}
