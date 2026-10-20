// Execute the runner's actual privileged block with shell/device boundaries stubbed.
// A missing ownership branch must fail here before any real emulator is started.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const dir = path.dirname(fileURLToPath(import.meta.url));
const runner = readFileSync(path.join(dir, 'run-scan.sh'), 'utf8');
const ownership = runner.match(/^own_pid\(\).*$/m)[0];
const block = runner.slice(runner.indexOf('\nif [[ $mode == sync ]]; then', runner.indexOf('\nwait_for_boot\n')), runner.indexOf('\nadb() {'));
for (const scenario of ['dead-pid','wrong-pid','wrong-birth','wrong-avd','lost-pid-after-root','lost-avd-after-root','offline-after-root','valid']) {
  test(`privileged runner fails closed: ${scenario}`, () => {
    const work = mkdtempSync(path.join(tmpdir(), 'adb-root-guard-'));
    try {
      writeFileSync(path.join(work, 'calls'), '');
      writeFileSync(path.join(work, 'adb'), `#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> "$STUB_WORK/calls"
case "$*" in
  '-s emulator-5554 emu avd name')
    if [[ $CASE == wrong-avd || ( $CASE == lost-avd-after-root && -f $STUB_WORK/rooted ) ]]; then echo foreign
    elif [[ $CASE == offline-after-root && -f $STUB_WORK/rooted && ! -f $STUB_WORK/offline ]]; then touch "$STUB_WORK/offline"; exit 1
    else echo owned; fi ;;
  '-s emulator-5554 root') touch "$STUB_WORK/rooted" ;;
  '-s emulator-5554 shell getprop sys.boot_completed') echo 1 ;;
  '-s emulator-5554 shell id -u') echo 0 ;;
  '-s emulator-5554 exec-out tar') : ;;
  *) exit 93 ;;
esac
`, { mode: 0o700 });
      writeFileSync(path.join(work, 'sleep'), '#!/usr/bin/env bash\nexit 0\n', { mode: 0o700 });
      const result = spawnSync('bash', ['-c', `set -euo pipefail
source "$HELPERS"
mode=sync; serial=emulator-5554; avd_name=owned; pid=$$; born=123
start_time() {
  [[ $CASE != dead-pid && $CASE != wrong-pid ]] || return 1
  [[ $CASE != lost-pid-after-root || ! -f $STUB_WORK/rooted ]] || return 1
  if [[ $CASE == wrong-birth ]]; then printf 124; else printf 123; fi
}
${ownership}
${block}
command adb -s "$serial" exec-out tar
`], { encoding: 'utf8', env: { ...process.env, PATH: `${work}:${process.env.PATH}`, HELPERS: path.join(dir, 'emulator.sh'), STUB_WORK: work, CASE: scenario } });
      const calls = readFileSync(path.join(work, 'calls'), 'utf8');
      if (['valid','offline-after-root'].includes(scenario)) {
        assert.equal(result.status, 0, result.stderr);
        assert.match(calls, /shell id -u/); assert.match(calls, /exec-out tar/);
      } else {
        assert.notEqual(result.status, 0, `unsafe success: ${calls}`);
        assert(!calls.includes('shell id -u') && !calls.includes('exec-out tar'), calls);
        if (!scenario.includes('after-root')) assert(!calls.includes('emulator-5554 root'), calls);
      }
    } finally { rmSync(work, { recursive: true, force: true }); }
  });
}
