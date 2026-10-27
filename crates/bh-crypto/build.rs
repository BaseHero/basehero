use std::{fs, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target = std::env::var("TARGET").expect("Cargo provides TARGET");
    // Apple apps and Android binaries must not depend on a runtime libsodium dylib.
    let static_link = target == "aarch64-apple-darwin" || target.contains("-android");
    let sodium = pkg_config::Config::new()
        .atleast_version("1.0.22")
        .statik(static_link)
        .probe("libsodium")
        .expect("bh-crypto requires libsodium >= 1.0.22 with X-Wing and its development headers");
    // pkg-config silently falls back to a dylib when an archive is absent.
    // Fail closed on app targets instead of shipping a runtime libsodium dependency.
    if static_link {
        assert!(
            sodium
                .link_paths
                .iter()
                .any(|dir| dir.join("libsodium.a").is_file()),
            "static libsodium.a required on Apple ARM64 and Android"
        );
    }

    for header in [
        "sodium.h",
        "sodium/core.h",
        "sodium/utils.h",
        "sodium/randombytes.h",
        "sodium/crypto_generichash.h",
        "sodium/crypto_hash_sha256.h",
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
    }
}

fn check_xwing_header(path: &Path) {
    let header = fs::read_to_string(path).expect("read X-Wing header");
    // Reject a changed declaration; runtime size queries independently guard
    // against mismatched headers and libraries.
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
