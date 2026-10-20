#!/usr/bin/env bash
# Build two ephemeral-test APK inputs before generating any short-lived QR.
# Run from basehero/ in .#androidEmulator. The caller owns the live local stack.
# With SYNC_LIVE_ENDPOINT, build against that deployed hardware endpoint instead,
# without synthetic attestation.
set -euo pipefail
: "${SYNC_ARTIFACTS:?absolute output directory}" "${CARGO_TARGET_DIR:?private target}"
if [[ -n ${SYNC_LIVE_ENDPOINT:-} ]]; then
  node apps/client/tests/android/sync-live.mjs check-endpoint "$SYNC_LIVE_ENDPOINT"
  BH_SYNC_ENDPOINT=$(realpath "$SYNC_LIVE_ENDPOINT") features=webdriver
else
  : "${LOCAL_STACK_DIR:?owned live stack}"
  BH_SYNC_ENDPOINT="$LOCAL_STACK_DIR/emulator-endpoint.json" features=webdriver,synthetic-attestation
  bash scripts/local-stack.sh status
fi
export BH_SYNC_ENDPOINT
mkdir -p "$SYNC_ARTIFACTS"
# The native peer is built separately in the default Nix shell (host libsodium).
for version in 0.1.0 0.1.1; do
  (cd apps/client && cargo tauri android build --target x86_64 --apk --ci \
    --features "$features" --config "{\"version\":\"$version\"}")
  apk="$SYNC_ARTIFACTS/$version.apk"
  cp apps/client/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk "$apk"
  python3 scripts/android_no_models.py "$apk" --expect-scanner
  python3 scripts/webdriver_android_manifest.py "$apk" "$ANDROID_HOME/build-tools/35.0.0/aapt"
  python3 - "$apk" "$BH_SYNC_ENDPOINT" "$version" "$features" <<'PY'
import hashlib,json,pathlib,subprocess,sys,zipfile,datetime,os,re
apk,ep,version,features=pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]),sys.argv[3],sys.argv[4].split(',')
with zipfile.ZipFile(apk) as z:
    assert ep.read_bytes() in z.read('lib/x86_64/libbh_client_lib.so'), 'exact endpoint not embedded'
    for n in z.namelist():
        b=z.read(n)
        assert b'EMULATOR FIXTURE' not in b and b'Create emulator test account' not in b, n
badging=subprocess.check_output([os.environ['ANDROID_HOME']+'/build-tools/35.0.0/aapt','dump','badging',str(apk)],text=True)
code=int(re.search(r"versionCode='(\d+)'",badging)[1]); assert code=={'0.1.0':1000,'0.1.1':1001}[version]
stamp={'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'source_diff_sha256':hashlib.sha256(subprocess.check_output(['git','diff','HEAD','--','.'])).hexdigest(),'apk_sha256':hashlib.sha256(apk.read_bytes()).hexdigest(),'endpoint_sha256':hashlib.sha256(ep.read_bytes()).hexdigest(),'features':features,'version':version,'versionCode':code,'built_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
apk.with_suffix('.json').write_text(json.dumps(stamp,indent=2)+'\n'); print(json.dumps(stamp))
PY
done
