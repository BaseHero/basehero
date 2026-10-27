import { test } from 'node:test';
import assert from 'node:assert/strict';
import { adb, launch, webview } from './lib.mjs';

const app = 'app.basehero';
const inApp = script => adb('shell', 'run-as', app, 'sh', '-c', `'${script}'`);
const keyError = "BaseHero can't reach its key on this device.";

async function screen() {
  const page = await webview();
  try {
    return await page.locator('h1').first().textContent();
  } finally {
    await page.context().browser()?.close();
  }
}

async function restart() {
  adb('shell', 'am', 'force-stop', app);
  await launch();
  return screen();
}

test('the master key is kept wrapped outside backup, and a damaged one is refused, not replaced', async () => {
  assert.equal(await restart(), 'BaseHero');
  assert.equal(inApp('wc -c < no_backup/master.key.v1'), '61');
  assert.equal(inApp('test -f secrets/app.canary && echo yes'), 'yes');
  // Change the tag's last byte.
  inApp('cd no_backup && cp master.key.v1 kept || exit 1; c=x; [ "$(tail -c 1 kept)" = x ] && c=y; head -c 60 kept > master.key.v1 && printf $c >> master.key.v1');
  const damaged = inApp('od -An -tx1 no_backup/master.key.v1');
  try {
    assert.equal(await restart(), keyError);
    assert.equal(inApp('od -An -tx1 no_backup/master.key.v1'), damaged, 'the damaged file was left in place');
  } finally {
    inApp('mv no_backup/kept no_backup/master.key.v1');
  }
  assert.equal(await restart(), 'BaseHero');
});
