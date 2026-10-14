use std::{fs, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let sodium = pkg_config::Config::new()
        .atleast_version("1.0.22")
        .probe("libsodium")
        .expect("bh-crypto requires libsodium >= 1.0.22 with X-Wing and its development headers");

    // No host executable is run: cross builds use the target's pkg-config data.
    // The linked library's size functions are checked before any crypto call.
    // Missing symbols fail at link time; there is no classical-only fallback.
    for header in [
        "sodium.h",
        "sodium/core.h",
        "sodium/utils.h",
        "sodium/randombytes.h",
        "sodium/crypto_generichash.h",
        "sodium/crypto_hash_sha256.h",
        "sodium/crypto_sign_ed25519.h",
        "sodium/crypto_kdf.h",
        "sodium/crypto_aead_xchacha20poly1305.h",
        "sodium/crypto_pwhash.h",
        "sodium/crypto_kem_xwing.h",
    ] {
        let path = sodium
            .include_paths
            .iter()
            .map(|dir| dir.join(header))
            .find(|path| path.is_file())
            .unwrap_or_else(|| panic!("required libsodium header missing: {header}"));
        println!("cargo:rerun-if-changed={}", path.display());
        if header == "sodium/crypto_kem_xwing.h" {
            check_xwing_header(&path);
        }
        if header == "sodium/crypto_hash_sha256.h" {
            check_sha256_header(&path);
        }
    }
}

fn check_sha256_header(path: &Path) {
    let header = fs::read_to_string(path).expect("read SHA-256 header");
    // Check the literal C layout used by the repr(C) state in lib.rs. This
    // deliberately rejects a changed declaration; the linked library's size
    // functions independently detect a header/library mismatch at runtime.
    let declaration = header
        .split_once("typedef struct crypto_hash_sha256_state {")
        .and_then(|(_, rest)| rest.split_once("} crypto_hash_sha256_state;"))
        .map(|(fields, _)| {
            fields
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        });
    assert_eq!(
        declaration,
        Some(vec![
            "uint32_t state[8];",
            "uint64_t count;",
            "uint8_t  buf[64];"
        ]),
        "unsupported libsodium SHA-256 state layout"
    );
    assert!(
        header
            .lines()
            .any(|line| line.split_whitespace().collect::<Vec<_>>()
                == ["#define", "crypto_hash_sha256_BYTES", "32U"]),
        "unsupported libsodium SHA-256 output size"
    );
}

fn check_xwing_header(path: &Path) {
    let header = fs::read_to_string(path).expect("read X-Wing header");
    // Deliberately narrow, fail-closed check of libsodium's published literal
    // constants, not a C preprocessor. New header forms require review; runtime
    // checks independently guard against mismatched headers/shared libraries.
    for (name, expected) in [
        ("crypto_kem_xwing_PUBLICKEYBYTES", 1216),
        ("crypto_kem_xwing_SECRETKEYBYTES", 32),
        ("crypto_kem_xwing_CIPHERTEXTBYTES", 1120),
        ("crypto_kem_xwing_SHAREDSECRETBYTES", 32),
        ("crypto_kem_xwing_SEEDBYTES", 32),
    ] {
        let value = header.lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next() != Some("#define") || fields.next() != Some(name) {
                return None;
            }
            fields.next()?.trim_end_matches('U').parse::<usize>().ok()
        });
        assert_eq!(value, Some(expected), "unsupported libsodium {name}");
    }
}
