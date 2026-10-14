{
  description = "BaseHero development tools";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/c59305bab2065cfecc4944690d9eedbb56f3a9fa";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, rust-overlay, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
    in
    {
      devShells = nixpkgs.lib.genAttrs systems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          cryptoWorkerSodium = pkgs.callPackage ./libs/crypto/wasm.nix { };
          # Cargo's target directory is mutable: sharing it between worktrees can
          # break concurrent doctests and block one check behind another.
          # sccache shares compiler output without sharing Cargo's build lock.
          cargoCacheHook = abi: ''
            bh_repo="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
            if [ -f "$bh_repo/basehero/Cargo.toml" ]; then bh_repo="$bh_repo/basehero"; fi
            bh_target="$bh_repo/target${if abi == "native" then "" else "/${system}-${abi}"}"
            if [ -z "''${CARGO_TARGET_DIR:-}" ] || [ "''${CARGO_TARGET_DIR}" = "''${BH_CARGO_DEFAULT_TARGET:-__none__}" ]; then
              # Cargo's own per-workspace target default keeps absolute worktree
              # paths out of rustc's environment, so sccache can reuse Rust crates.
              ${if abi == "native" then "unset CARGO_TARGET_DIR" else "export CARGO_TARGET_DIR=\"$bh_target\""}
            fi
            export BH_CARGO_DEFAULT_TARGET="$bh_target"
            if [ -z "''${RUSTC_WRAPPER+x}" ]; then export RUSTC_WRAPPER=${pkgs.sccache}/bin/sccache; fi
            if [ -z "''${CARGO_INCREMENTAL+x}" ]; then export CARGO_INCREMENTAL=0; fi
          '';
          linuxDeps =
            with pkgs;
            lib.optionals stdenv.hostPlatform.isLinux [
              webkitgtk_4_1
              gtk3
              libsoup_3
              glib
              glib-networking
              cairo
              pango
              gdk-pixbuf
              atk
              librsvg
              openssl
              dbus
            ];
          androidPkgs = import nixpkgs {
            inherit system;
            config = {
              allowUnfree = true;
              android_sdk.accept_license = true;
            };
          };
          android = androidPkgs.androidenv.composeAndroidPackages {
            # Tauri 2.12's Android library compiles against API 36.
            platformVersions = [ "36" ];
            buildToolsVersions = [ "35.0.0" ];
            includeNDK = true;
            ndkVersions = [ "29.0.14206865" ];
            includeEmulator = false;
            includeSystemImages = false;
          };
          # A second SDK view for the real-app WebDriver tests: the emulator and
          # one x86_64 Google APIs system image, kept out of the ordinary
          # `android` shell so an ABI-specific download is opt-in.
          androidEmulatorPackages = androidPkgs.androidenv.composeAndroidPackages {
            platformVersions = [ "36" ];
            buildToolsVersions = [ "35.0.0" ];
            includeNDK = true;
            ndkVersions = [ "29.0.14206865" ];
            includeEmulator = true;
            includeSystemImages = true;
            systemImageTypes = [ "google_apis" ];
            abiVersions = [ "x86_64" ];
          };
          sdk = "${android.androidsdk}/libexec/android-sdk";
          ndk = "${sdk}/ndk/29.0.14206865";
          llvm = "${ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin";
          # Use the native package's pinned upstream source, but compile against
          # the same NDK/API as Rust. Never expose the native .pc to Cargo.
          androidSodium = pkgs.stdenv.mkDerivation {
            pname = "libsodium-android";
            inherit (pkgs.libsodium) version src;
            nativeBuildInputs = [ pkgs.autoreconfHook ];
            preConfigure = ''
              export CC=${llvm}/aarch64-linux-android24-clang
              export AR=${llvm}/llvm-ar
              export RANLIB=${llvm}/llvm-ranlib
              export CFLAGS='-O2 -fPIC'
            '';
            configureFlags = [
              "--host=aarch64-linux-android"
              "--disable-shared"
              "--enable-static"
            ];
            makeFlags = [ "V=1" ]; # Show the actual NDK compiler and optimization flags.
            doCheck = false; # Target binaries cannot run on the build host.
          };
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs =
              with pkgs;
              [
                rust
                pkg-config
                cargo-tauri
                nodejs_22
              ]
              ++ lib.optionals stdenv.hostPlatform.isLinux [
                xvfb
                xdotool
                util-linux
                iproute2
              ];
            buildInputs = linuxDeps ++ [ pkgs.libsodium ];
            shellHook = cargoCacheHook "native" + pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
              export GIO_MODULE_DIR=${pkgs.glib-networking}/lib/gio/modules
              export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath (linuxDeps ++ [ pkgs.libsodium ])}:''${LD_LIBRARY_PATH:-}
            '';
          };
        }
        // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
          cryptoWorker = pkgs.mkShell {
            nativeBuildInputs = [ rust pkgs.pkg-config pkgs.nodejs_22 ];
            buildInputs = [ cryptoWorkerSodium ];
            shellHook = cargoCacheHook "crypto-worker" + ''
              export PKG_CONFIG_LIBDIR=${cryptoWorkerSodium}/lib/pkgconfig
              export PKG_CONFIG_ALLOW_CROSS=1
              export LIBSODIUM_STATIC=1
            '';
          };
          android = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              rust
              pkg-config
              cargo-tauri
              nodejs_22
              jdk17
              android.androidsdk
            ];
            ANDROID_HOME = sdk;
            ANDROID_SDK_ROOT = sdk;
            NDK_HOME = ndk;
            JAVA_HOME = pkgs.jdk17.home;
            CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = "${llvm}/aarch64-linux-android24-clang";
            CC_aarch64_linux_android = "${llvm}/aarch64-linux-android24-clang";
            AR_aarch64_linux_android = "${llvm}/llvm-ar";
            PKG_CONFIG_LIBDIR_aarch64_linux_android = "${androidSodium}/lib/pkgconfig";
            # An inherited native PKG_CONFIG_PATH otherwise wins over LIBDIR.
            PKG_CONFIG_PATH_aarch64_linux_android = "";
            PKG_CONFIG_ALLOW_CROSS_aarch64_linux_android = "1";
            LIBSODIUM_STATIC = "1";
            shellHook = cargoCacheHook "android";
            GRADLE_OPTS = "-Dorg.gradle.project.android.aapt2FromMavenOverride=${sdk}/build-tools/35.0.0/aapt2";
          };
          # x86_64 emulator builds and the real-app WebDriver tests. The Rust
          # target lives in rust-toolchain.toml; this shell adds the ABI's
          # linker and the emulator system image.
          androidEmulator = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              rust
              pkg-config
              cargo-tauri
              nodejs_22
              jdk17
              androidEmulatorPackages.androidsdk
            ];
            ANDROID_HOME = "${androidEmulatorPackages.androidsdk}/libexec/android-sdk";
            ANDROID_SDK_ROOT = "${androidEmulatorPackages.androidsdk}/libexec/android-sdk";
            NDK_HOME = "${androidEmulatorPackages.androidsdk}/libexec/android-sdk/ndk/29.0.14206865";
            JAVA_HOME = pkgs.jdk17.home;
            CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER = "${androidEmulatorPackages.androidsdk}/libexec/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android24-clang";
            CC_x86_64_linux_android = "${androidEmulatorPackages.androidsdk}/libexec/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android24-clang";
            AR_x86_64_linux_android = "${androidEmulatorPackages.androidsdk}/libexec/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar";
            GRADLE_OPTS = "-Dorg.gradle.project.android.aapt2FromMavenOverride=${androidEmulatorPackages.androidsdk}/libexec/android-sdk/build-tools/35.0.0/aapt2";
          };
        }
      );
    };
}
