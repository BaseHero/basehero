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

      # Static libsodium for the two ABIs the app builds: the Fold's release
      # APK and the x86_64 emulator build. Cross only: it never runs here.
      androidSodium =
        system: target:
        let
          cross = import nixpkgs {
            inherit system;
            crossSystem = {
              config = "${target}-unknown-linux-android";
              androidSdkVersion = "35";
              androidNdkVersion = "27";
              useLLVM = true;
            };
          };
        in
        cross.libsodium.overrideAttrs (old: {
          pname = "libsodium-android";
          configureFlags = (old.configureFlags or [ ]) ++ [
            "--disable-shared"
            "--enable-static"
          ];
          doCheck = false; # Target binaries cannot run on the build host.
        });

      # The Android SDK and NDK are unfree and need their licence accepted.
      androidPackages =
        system: systemImage:
        let
          pkgs = import nixpkgs {
            inherit system;
            config = {
              allowUnfree = true;
              android_sdk.accept_license = true;
            };
          };
        in
        pkgs.androidenv.composeAndroidPackages (
          {
            # Tauri 2.12's Android library compiles against API 36.
            platformVersions = [ "36" ];
            buildToolsVersions = [ "35.0.0" ];
            includeNDK = true;
            ndkVersions = [ "29.0.14206865" ];
          }
          // (
            if systemImage then
              {
                includeEmulator = true;
                includeSystemImages = true;
                systemImageTypes = [ "google_apis" ];
                abiVersions = [ "x86_64" ];
              }
            else
              {
                includeEmulator = false;
                includeSystemImages = false;
              }
          )
        );

      # `nix develop .#android` builds the aarch64 release APK. The emulator
      # image and its x86_64 build are opt-in through `.#androidEmulator`.
      androidShell =
        system: systemImage:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          android = androidPackages system systemImage;
          sdk = "${android.androidsdk}/libexec/android-sdk";
          ndkVersion = "29.0.14206865";
          ndk = "${sdk}/ndk/${ndkVersion}";
          llvm = "${ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin";
          abi = if systemImage then "x86_64" else "aarch64";
          linker = "${llvm}/${abi}-linux-android24-clang";
          # Compile the native package's pinned source with the *same* NDK/API
          # as Rust, rather than importing a separate cross toolchain.
          mkAndroidSodium = target: pkgs.stdenv.mkDerivation {
            pname = "libsodium-android";
            inherit (pkgs.libsodium) version src;
            nativeBuildInputs = [ pkgs.autoreconfHook ];
            preConfigure = ''
              export CC=${llvm}/${target}24-clang
              export AR=${llvm}/llvm-ar
              export RANLIB=${llvm}/llvm-ranlib
              export CFLAGS='-O2 -fPIC'
            '';
            configureFlags = [
              "--host=${target}"
              "--disable-shared"
              "--enable-static"
            ];
            doCheck = false;
          };
          sodium = mkAndroidSodium "${abi}-linux-android";
          pkgConfigPrefix = builtins.replaceStrings [ "-" ] [ "_" ] abi;
        in
        pkgs.mkShell {
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
          "CARGO_TARGET_${pkgs.lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] abi)}_LINUX_ANDROID_LINKER" =
            linker;
          "CC_${pkgConfigPrefix}_linux_android" = linker;
          "AR_${pkgConfigPrefix}_linux_android" = "${llvm}/llvm-ar";
          "PKG_CONFIG_LIBDIR_${pkgConfigPrefix}_linux_android" = "${sodium}/lib/pkgconfig";
          # Keep an inherited native lookup out of the Android target paths.
          "PKG_CONFIG_PATH_${pkgConfigPrefix}_linux_android" = "";
          "PKG_CONFIG_ALLOW_CROSS_${pkgConfigPrefix}_linux_android" = "1";
          LIBSODIUM_STATIC = "1";
          # Gradle downloads a dynamically linked aapt2; use the SDK's patched one.
          GRADLE_OPTS = "-Dorg.gradle.project.android.aapt2FromMavenOverride=${sdk}/build-tools/35.0.0/aapt2";
          shellHook = ''
            # Every checkout keeps its own emulator state, independent of the
            # directory the shell was entered from.
            bh_root="$PWD"
            while [ ! -f "$bh_root/flake.nix" ] || [ ! -d "$bh_root/apps/basehero/src-tauri" ]; do
              if [ "$bh_root" = / ]; then
                echo "Enter the BaseHero dev shell from within its checkout." >&2
                exit 1
              fi
              bh_root="$(dirname "$bh_root")"
            done
            export ANDROID_AVD_HOME="$bh_root/.android-avd"
            export ANDROID_USER_HOME="$bh_root/.android-user"
            # Raring's agents run their emulator on 5560; ours is 5580.
            export ANDROID_SERIAL=''${ANDROID_SERIAL:-emulator-5580}
            unset bh_root
          '';
        };
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
          # bh-crypto links libsodium statically on the Mac, so the app loads only system libraries.
          sodium =
            if pkgs.stdenv.hostPlatform.isDarwin then
              pkgs.libsodium.overrideAttrs { dontDisableStatic = true; }
            else
              pkgs.libsodium;
        in
        {
          default = pkgs.mkShell {
            # perl builds the OpenSSL that SQLCipher vendors.
            nativeBuildInputs = with pkgs; [ rust pkg-config perl nodejs_22 cargo-tauri playwright-driver.browsers ];
            buildInputs = [ sodium ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux (with pkgs; [
              webkitgtk_4_1 gtk3 libsoup_3 glib glib-networking cairo pango
              gdk-pixbuf atk librsvg openssl dbus
            ]);
            shellHook = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
              export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath [ pkgs.libsodium pkgs.webkitgtk_4_1 pkgs.gtk3 pkgs.libsoup_3 pkgs.glib pkgs.glib-networking pkgs.cairo pkgs.pango pkgs.gdk-pixbuf pkgs.atk pkgs.librsvg pkgs.openssl pkgs.dbus ]}:''${LD_LIBRARY_PATH:-}
              export PLAYWRIGHT_BROWSERS_PATH=${pkgs.playwright-driver.browsers}
              export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
            '';
          };
        }
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          android = androidShell system false;
          androidEmulator = androidShell system true;
        }
      );

      # Android static libraries are opt-in; app tooling will add the SDK and NDK.
      packages = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (system: {
        libsodiumAndroidAarch64 = androidSodium system "aarch64";
        libsodiumAndroidX86_64 = androidSodium system "x86_64";
      });
    };
}
