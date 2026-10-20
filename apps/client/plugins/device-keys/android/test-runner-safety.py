#!/usr/bin/env python3
"""Fake Android commands: launch races and cleanup, without connecting to a device."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

module = Path(__file__).resolve().parent
client = module.parents[2]


def executable(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('#!/usr/bin/env bash\nset -e\n' + body)
    path.chmod(0o755)


with tempfile.TemporaryDirectory(prefix='bh-devicekeys-runner-test.') as tmp:
    root = Path(tmp)
    target = root / 'basehero/apps/client/plugins/device-keys/android'
    target.mkdir(parents=True)
    shutil.copy2(module / 'run-emulator.sh', target / 'run-emulator.sh')
    lib = root / 'basehero/apps/client/tests/webdriver/lib.sh'
    lib.parent.mkdir(parents=True)
    (root / 'basehero/apps/client/tests/android').mkdir(parents=True)
    shutil.copy2(client / 'tests/webdriver/lib.sh', lib)
    shutil.copy2(client / 'tests/android/emulator.sh', root / 'basehero/apps/client/tests/android/emulator.sh')
    apk = target / 'build/outputs/apk/androidTest/debug/bh-device-keys-android-debug-androidTest.apk'
    apk.parent.mkdir(parents=True)
    apk.touch()
    executable(root / 'basehero/apps/client/src-tauri/gen/android/gradlew', 'exit 0\n')
    sdk = root / 'sdk'
    executable(sdk / 'ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android24-clang', 'exit 0\n')
    executable(sdk / 'cmdline-tools/latest/bin/avdmanager',
               'while [ "$#" -gt 0 ]; do if [ "$1" = -n ]; then printf "%s" "$2" > "$PROBE_NAME"; break; fi; shift; done\n')
    executable(sdk / 'emulator/emulator',
               'printf "%s" "$$" > "$PROBE_PID"\n'
               'if [ "$PROBE_CASE" = failed ]; then exit 1; fi\nexec sleep 30\n')
    executable(root / 'bin/ss', 'printf "State Recv-Q Send-Q Local Address:Port Peer Address:Port\\n"\n')
    executable(root / 'bin/adb', '''printf '%s\\n' "$*" >> "$PROBE_LOG"
case "$*" in
  devices) printf 'List of devices attached\\n\\n' ;;
  '-s emulator-5554 emu avd name')
    if [ "$PROBE_CASE" = failed ]; then exit 1; fi
    if [ "$PROBE_CASE" = foreign ]; then echo another_tasks_avd; else echo "$(cat "$PROBE_NAME")"; fi ;;
  '-s emulator-5554 shell getprop sys.boot_completed') echo 1 ;;
  '-s emulator-5554 shell getprop ro.kernel.qemu') echo 1 ;;
  '-s emulator-5554 shell setprop debug.checkjni 1') exit 1 ;;
esac
''')
    for case in ('failed', 'foreign', 'ordinary'):
        log = root / f'{case}.log'
        pidfile = root / f'{case}.pid'
        env = dict(os.environ, ANDROID_HOME=str(sdk), JAVA_HOME=str(root),
                   PROBE_LOG=str(log), PROBE_NAME=str(root / f'{case}.name'),
                   PROBE_PID=str(pidfile), PROBE_CASE=case,
                   PATH=str(root / 'bin') + ':' + os.environ['PATH'])
        run = subprocess.run(['bash', str(target / 'run-emulator.sh')], env=env,
                             text=True, capture_output=True, timeout=15)
        commands = log.read_text().splitlines()
        assert run.returncode != 0, (case, run.stdout, run.stderr)
        assert 'shell setprop debug.checkjni 1' not in '\n'.join(commands) or case == 'ordinary', commands
        assert ('-s emulator-5554 emu kill' in commands) == (case == 'ordinary'), commands
        if case == 'failed':
            assert 'emulator died before boot' in run.stderr, run.stderr
        if case == 'foreign':
            assert 'foreign emulator occupies serial' in run.stderr, run.stderr
        if case == 'ordinary':
            assert '-s emulator-5554 shell setprop debug.checkjni 1' in commands, commands
        pid = int(pidfile.read_text())
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError(f'{case}: emulator child {pid} still alive')
        print(f'{case}: refused unsafe actions; cleaned up child')
