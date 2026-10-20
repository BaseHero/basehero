//! The bundled note engine, compiled to Pulley bytecode by this package's
//! build from this workspace's sources. Nothing else is ever loaded as it:
//! not a file, and nothing from the network.

use std::sync::OnceLock;
use wasmtime::{Engine, Module};

include!("config.rs");

static COMPILED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/note-engine.cwasm"));

/// The engine and the note engine module, loaded once per process.
pub fn module() -> Result<&'static (Engine, Module), &'static str> {
    static LOADED: OnceLock<Result<(Engine, Module), String>> = OnceLock::new();
    LOADED
        .get_or_init(|| {
            let target = pulley_target(
                &usize::BITS.to_string(),
                if cfg!(target_endian = "big") {
                    "big"
                } else {
                    "little"
                },
            );
            let engine = Engine::new(&note_engine_config(&target).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            #[allow(unsafe_code)]
            // SAFETY: COMPILED is this build's own `precompile_module` output
            // for this Wasmtime release and configuration, embedded at build
            // time; it is never read from anywhere else.
            let module = unsafe { Module::deserialize(&engine, COMPILED) };
            Ok((engine, module.map_err(|e| e.to_string())?))
        })
        .as_ref()
        .map_err(String::as_str)
}
