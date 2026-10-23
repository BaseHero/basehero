#!/usr/bin/env bash
# Local synthetic stack + real Android camera/Keystore sync acceptance.
# From basehero/, with private absolute LOCAL_STACK_DIR, SYNC_ARTIFACTS and target:
# nix develop --command bash apps/client/tests/android/run-sync.sh prepare
# nix develop .#androidEmulator --command bash apps/client/tests/android/build-sync.sh
# nix develop .#androidEmulator --command bash apps/client/tests/android/run-sync.sh run
# nix develop --command bash scripts/local-stack.sh down
# A run owns a fresh private SYNC_RUN directory and disposable AVD. Nothing
# deploys; the peer is production bh-host/Owner with software test keys.
# Live variant, against an already deployed hardware-attested endpoint instead of
# the local stack (no synthetic attestation anywhere; emulator only):
# SYNC_LIVE_ENDPOINT=FILE SYNC_ARTIFACTS=DIR nix develop --command bash apps/client/tests/android/run-sync.sh prepare-live
# SYNC_LIVE_ENDPOINT=FILE nix develop .#androidEmulator --command bash apps/client/tests/android/build-sync.sh
# SYNC_LIVE_ENDPOINT=FILE nix develop .#androidEmulator --command bash apps/client/tests/android/run-sync.sh run
set -euo pipefail
umask 077
: "${CARGO_TARGET_DIR:?private target}"
[[ -n ${SYNC_LIVE_ENDPOINT:-} ]] || : "${LOCAL_STACK_DIR:?private stack directory}"
case "${1:-}" in
  prepare-live)
    : "${SYNC_LIVE_ENDPOINT:?deployed hardware endpoint file}" "${SYNC_ARTIFACTS:?private artifact directory}"
    node apps/client/tests/android/sync-live.mjs check-endpoint "$SYNC_LIVE_ENDPOINT"
    # The same production peer, built without synthetic attestation, kept apart
    # from any synthetic build in the shared target directory.
    cargo build --locked --offline -p bh-local-sync-tests --example local_sync_device
    mkdir -p "$SYNC_ARTIFACTS"
    cp "$CARGO_TARGET_DIR/debug/examples/local_sync_device" "$SYNC_ARTIFACTS/peer-live"
    ;;
  prepare)
    cargo build --locked --offline -p bh-local-sync-tests --features synthetic-attestation --example local_sync_device
    bash scripts/local-stack.sh up
    python3 - "$LOCAL_STACK_DIR" <<'PY'
import json,pathlib,sys
s=pathlib.Path(sys.argv[1]); k=s/'keys'
e={'edge_url':(s/'edge-url').read_text().strip(),'hosting_root':(k/'hosting-root.pub').read_text().strip(),'app_root':(k/'app-root.pub').read_text().strip(),'policy':(k/'policy.json').read_bytes().hex(),'policy_signature':(k/'policy.sig').read_text().strip(),'recovery_key':(k/'recovery.cert').read_text().strip(),'max_lifetime_secs':86400,'max_uncertainty_secs':0,'build_floor':1,'appraisal':'synthetic'}
(s/'host-endpoint.json').write_text(json.dumps(e,separators=(',',':')))
e['edge_url']=e['edge_url'].replace('127.0.0.1','10.0.2.2')
(s/'emulator-endpoint.json').write_text(json.dumps(e,separators=(',',':')))
PY
    ;;
  run)
    : "${SYNC_ARTIFACTS:?directory holding both APK inputs and stamps}"
    source apps/client/tests/webdriver/lib.sh
    refuse_occupied_port
    if [[ -n ${SYNC_LIVE_ENDPOINT:-} ]]; then
      node apps/client/tests/android/sync-live.mjs check-endpoint "$SYNC_LIVE_ENDPOINT"
      [[ -x $SYNC_ARTIFACTS/peer-live ]] || { echo 'run prepare-live first' >&2; exit 2; }
      # Host peer and emulator reach the same public endpoint.
      export SYNC_LIVE=1 SYNC_HOST_ENDPOINT=$SYNC_LIVE_ENDPOINT SYNC_PEER_BIN=$SYNC_ARTIFACTS/peer-live
      emulator_endpoint=$SYNC_LIVE_ENDPOINT features=webdriver stack=''
    else
      bash scripts/local-stack.sh status
      export SYNC_HOST_ENDPOINT="$LOCAL_STACK_DIR/host-endpoint.json"
      emulator_endpoint=$LOCAL_STACK_DIR/emulator-endpoint.json features=webdriver,synthetic-attestation stack=$LOCAL_STACK_DIR
    fi
    export SYNC_RUN=${SYNC_RUN:-$(mktemp -d /tmp/bh-android-sync.XXXXXX)}
    [[ -d $SYNC_RUN && ! -e $SYNC_RUN/peer ]] || { echo 'SYNC_RUN must be fresh' >&2; exit 2; }
    export SCAN_UNSIGNED_APK="$SYNC_ARTIFACTS/0.1.0.apk" SYNC_UPDATE_UNSIGNED_APK="$SYNC_ARTIFACTS/0.1.1.apk"
    python3 - "$emulator_endpoint" "$SYNC_ARTIFACTS" "$SYNC_RUN" "$features" "$stack" <<'PY'
import hashlib,json,pathlib,sys,zipfile
endpoint,art,out=map(pathlib.Path,sys.argv[1:4]); features,stack=sys.argv[4].split(','),sys.argv[5]
ep=endpoint.read_bytes(); e=json.loads(ep)
if stack:
    s=pathlib.Path(stack)
    assert e['edge_url']==(s/'edge-url').read_text().strip().replace('127.0.0.1','10.0.2.2')
    for f,k in [('hosting-root.pub','hosting_root'),('app-root.pub','app_root'),('policy.sig','policy_signature'),('recovery.cert','recovery_key')]:
        assert e[k]==(s/'keys'/f).read_text().strip()
    assert e['policy']==(s/'keys/policy.json').read_bytes().hex()
stamps=[]
for version in ['0.1.0','0.1.1']:
    a=art/(version+'.apk'); stamp=json.loads((art/(version+'.json')).read_text())
    assert hashlib.sha256(a.read_bytes()).hexdigest()==stamp['apk_sha256'], 'APK differs from its stamp'
    assert hashlib.sha256(ep).hexdigest()==stamp['endpoint_sha256'], 'APK stamp is for another endpoint'
    assert stamp['features']==features, 'APK stamp has other features'
    with zipfile.ZipFile(a) as z: assert ep in z.read('lib/x86_64/libbh_client_lib.so')
    stamps.append(stamp)
(out/'endpoint-and-apks.json').write_text(json.dumps({'exact_live_endpoint':True,'stamps':stamps},indent=2)+'\n')
print('PASS exact live endpoint URL, roots, signed policy and both APK hashes; '+str(out))
PY
    node apps/client/tests/android/sync-peer.mjs
    ;;
  *) echo 'usage: run-sync.sh prepare|prepare-live|run' >&2; exit 2 ;;
esac
