import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { adb, launch, webview } from './lib.mjs';

const required = ['BH_APPROVER_CLI', 'BH_APPROVER_HOME', 'BH_TEST_EMAIL', 'BH_TEST_PASSWORD', 'BH_TEST_KIT'];
function setup() {
  for (const name of required) assert(process.env[name], `${name} is required for the dev approval emulator check`);
  const cli = process.env.BH_APPROVER_CLI;
  const env = { PATH: process.env.PATH, HOME: process.env.BH_APPROVER_HOME,
    XDG_CONFIG_HOME: process.env.BH_APPROVER_HOME, GH_CONFIG_DIR: process.env.BH_APPROVER_HOME };
  const help = spawnSync(cli, ['approve', '--help'], { env, encoding: 'utf8', timeout: 10_000 });
  assert.equal(help.status, 0, 'the host CLI does not support device approval');
  return { cli, env };
}
async function signIn(page) {
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByLabel('Email').fill(process.env.BH_TEST_EMAIL);
  await page.getByLabel('Password').fill(process.env.BH_TEST_PASSWORD);
  await page.getByLabel('Device name').fill('Fold approval check');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('heading', { name: 'Open this device' }).waitFor({ timeout: 30_000 });
}

test('the dev relay approves an emulator sign-in and the kit also opens a fresh sign-in', { timeout: 180_000 }, async () => {
  const { cli, env } = setup();
  // This is the disposable AVD only. Reset between runs so both follow the new-device path.
  adb('shell', 'pm', 'clear', 'app.basehero');
  await launch();
  let page = await webview();
  let approver;
  try {
    await signIn(page);
    // Opening the request on the approver is what makes the digits appear.
    approver = spawn(cli, ['--home', process.env.BH_APPROVER_HOME, 'approve', '--json'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    approver.stderr.resume(); // Never print CLI diagnostics that could include its private home.
    const digits = (await page.getByTestId('approval-digits').textContent({ timeout: 60_000 })).trim();
    assert.match(digits, /^\d{3} \d{3}$/);
    approver.stdin.end(`${digits}\n`);
    let deadline;
    const exit = await Promise.race([
      new Promise((resolve, reject) => { approver.once('error', reject); approver.once('close', resolve); }),
      new Promise((_, reject) => { deadline = setTimeout(() => { approver.kill(); reject(new Error('host approval exceeded 60 seconds')); }, 60_000); }),
    ]).finally(() => clearTimeout(deadline));
    assert.equal(exit, 0, 'host approval failed');
    await page.getByRole('link', { name: 'Personal' }).waitFor({ timeout: 30_000 });
  } finally {
    if (approver?.exitCode === null) approver.kill();
    await page.context().browser()?.close();
  }
  adb('shell', 'pm', 'clear', 'app.basehero');
  await launch();
  page = await webview();
  try {
    await signIn(page);
    await page.getByRole('button', { name: 'Use your recovery kit instead' }).click();
    await page.getByLabel('Recovery kit').fill(process.env.BH_TEST_KIT);
    await page.getByRole('button', { name: 'Use kit' }).click();
    await page.getByRole('link', { name: 'Personal' }).waitFor({ timeout: 30_000 });
  } finally { await page.context().browser()?.close(); }
});
