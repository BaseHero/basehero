import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,existsSync,rmSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const source=readFileSync(new URL('./android-emulator-update.sh',import.meta.url),'utf8');
const start=source.indexOf('credential_focus() {');
const end=source.indexOf('\n[ "$(adb -s "$serial" shell getprop',start);
assert.ok(start>=0 && end>start);
const reopen=source.slice(start,end);

function attempt({focus,launcher='',keyguard=false,afterMenuFocus=focus,afterWindowFocus,activities='ok'}) {
  const dir=mkdtempSync(join(tmpdir(),'bh-reopen-mock-'));
  try {
    const calls=join(dir,'calls');
    const screen=(name)=>name==='credential'
      ? 'com.android.settings/com.android.settings.password.ConfirmLockPassword$InternalActivity'
      : name==='bouncer' ? 'com.android.systemui/.KeyguardBouncer' : name==='shade' ? 'NotificationShade' : 'app.basehero.client/.MainActivity';
    const script=`set -euo pipefail
serial=emulator-5554; instrument_host_pid=''; webdriver_port=9999; webdriver_activity=app.basehero.client/.MainActivity
adb() {
  if [[ "$*" == *'shell dumpsys window'* ]]; then
    if [ -f '${dir}/menu' ]; then foreground='${screen(afterMenuFocus)}';
    elif [ -f '${dir}/window-seen' ]; then foreground='${screen(afterWindowFocus??focus)}';
    else foreground='${screen(focus)}'; fi
    touch '${dir}/window-seen'
    printf 'mCurrentFocus=Window{0 u0 %s}\\nisKeyguardShowing=${keyguard}\\n' "$foreground"
  elif [[ "$*" == *'shell dumpsys activity activities'* ]]; then
    ${activities==='fail' ? `echo activity-dumpsys-failed >&2; return 1` : ':'}
    ${activities==='other' ? `printf '%s\\n' '  * Hist #0: ActivityRecord{def u0 app.basehero.client/.MainActivity t42}'; return 0` : ':'}
    printf '%s\\n' '  * Hist #0: ActivityRecord{abc u0 com.android.settings/.password.ConfirmLockPassword$InternalActivity t42}'
    ${launcher ? `printf '%s\\n' '    launchedFromUid=10216 launchedFromPackage=${launcher} userId=0'` : ':'}
    printf '%s\\n' '  * Hist #1: ActivityRecord{def u0 app.basehero.client/.MainActivity t42}'
  elif [[ "$*" == *'shell input keyevent 82'* ]]; then touch '${dir}/menu';
  elif [[ "$*" == *'shell input text'* ]]; then printf '%s\\n' "$*" >>'${calls}';
  elif [[ "$*" == *'shell pidof'* ]]; then printf '4567\\n'; fi
}
curl(){ [ -f '${calls}' ]; }
sleep(){ :; }
reopen_diagnostics(){ :; }
${reopen}
reopen_after_instrumentation`;
    const result=spawnSync('bash',['-c',script],{encoding:'utf8'});
    return {status:result.status,stderr:result.stderr,stdout:result.stdout,typed:existsSync(calls)?readFileSync(calls,'utf8'):''};
  } finally {rmSync(dir,{recursive:true,force:true});}
}

test('Settings credential launched by app types disposable PIN without showing keyguard',()=>{
  const result=attempt({focus:'credential',launcher:'app.basehero.client'});
  assert.equal(result.status,0,result.stderr);
  assert.equal(result.typed,'-s emulator-5554 shell input text 1234\n');
});

for (const launcher of ['another.app','com.android.settings']) {
  test(`Settings credential launched by ${launcher} refuses the PIN`,()=>{
    const result=attempt({focus:'credential',launcher});
    assert.notEqual(result.status,0);
    assert.equal(result.typed,'');
    assert.match(result.stderr,new RegExp(launcher.replaceAll('.','\\.')));
  });
}

const refusals={
  'failing activities query':{launcher:'app.basehero.client',activities:'fail'},
  'credential record without launchedFromPackage':{},
  'null launchedFromPackage':{launcher:'null'},
  'no credential ActivityRecord':{launcher:'app.basehero.client',activities:'other'},
};
for (const [name,options] of Object.entries(refusals)) {
  test(`Settings credential with ${name} refuses the PIN`,()=>{
    const result=attempt({focus:'credential',...options});
    assert.notEqual(result.status,0);
    assert.equal(result.typed,'');
    assert.match(result.stderr,/PIN destination not verified: .*ConfirmLock.*keyguard: .*launcher: /);
  });
}

test('bouncer types PIN only when keyguard is showing',()=>{
  const result=attempt({focus:'bouncer',keyguard:true});
  assert.equal(result.status,0,result.stderr);
  assert.equal(result.typed,'-s emulator-5554 shell input text 1234\n');
  const unlocked=attempt({focus:'bouncer'});
  assert.notEqual(unlocked.status,0);
  assert.equal(unlocked.typed,'');
});

test('focus moving to app after opening shade refuses the PIN',()=>{
  const result=attempt({focus:'shade',keyguard:true,afterMenuFocus:'app'});
  assert.notEqual(result.status,0);
  assert.equal(result.typed,'');
});

test('NotificationShade alone refuses the PIN',()=>{
  const result=attempt({focus:'shade',keyguard:true,afterMenuFocus:'shade'});
  assert.notEqual(result.status,0);
  assert.equal(result.typed,'');
});

test('credential focus moving to app before final verification refuses the PIN',()=>{
  const result=attempt({focus:'credential',launcher:'app.basehero.client',afterWindowFocus:'app'});
  assert.notEqual(result.status,0);
  assert.equal(result.typed,'');
});
