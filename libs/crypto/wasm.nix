{ stdenv, libsodium, emscripten, gnumake }:

# The same pinned C source as the native pkg-config binding. This archive is
# linked only into the narrow Worker hash/verify fixture; no alternate crypto.
stdenv.mkDerivation {
  pname = "bh-libsodium-worker";
  inherit (libsodium) version src;
  nativeBuildInputs = [ emscripten gnumake ];
  dontConfigure = true;
  buildPhase = ''
    runHook preBuild
    emconfigure ./configure --disable-shared --disable-ssp --disable-asm \
      --disable-pie --without-pthreads --prefix=$out
    emmake make -j''${NIX_BUILD_CORES:-4}
    runHook postBuild
  '';
  installPhase = ''
    runHook preInstall
    emmake make install
    runHook postInstall
  '';
}
