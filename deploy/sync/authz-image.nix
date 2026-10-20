{ pkgs, rust, src }:
let
  rustPlatform = pkgs.makeRustPlatform { cargo = rust; rustc = rust; };
  authz = rustPlatform.buildRustPackage {
    pname = "bh-authz";
    version = "0.1.0";
    inherit src;
    cargoLock = {
      lockFile = src + /Cargo.lock;
      allowBuiltinFetchGit = true;
    };
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [ pkgs.libsodium ];
    cargoBuildFlags = [ "-p" "bh-authz" "--bin" "bh-authz" ];
    # The pinned toolchain includes wasm32-unknown-unknown. The artifact build
    # script builds that guest with the vendored lock, then precompiles Pulley.
    doCheck = false; # Package smoke checks run on the emitted artifact below.
    postInstall = ''
      if "$out/bin/bh-authz" --synthetic-attestation >smoke.out 2>smoke.err; then
        echo 'release accepted synthetic mode' >&2; exit 1
      fi
      grep -F 'unknown flag --synthetic-attestation' smoke.err
      if "$out/bin/bh-authz" >smoke.out 2>smoke.err; then
        echo 'release accepted absent hardware configuration' >&2; exit 1
      fi
      grep -F -- '--permit-key is required' smoke.err
    '';
  };
  authz-image = pkgs.dockerTools.buildLayeredImage {
    name = "bh-authz";
    tag = builtins.substring 0 32 (builtins.hashString "sha256" (toString authz));
    contents = [ authz pkgs.cacert ];
    config = {
      Entrypoint = [ "${authz}/bin/bh-authz" ];
      # The renderer requires an explicit non-root host-compatible UID/GID;
      # no socket permission or protected-volume ownership is assumed here.
      User = "65532:65532";
      Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
      WorkingDir = "/data";
    };
  };
in
{ inherit authz authz-image; }
