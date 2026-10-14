import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

// Never use the real public/ notice or production environment to exercise activation.
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'basehero-website-build-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, 'scripts'));
  mkdirSync(join(root, 'public'));
  cpSync(new URL('../scripts/build.mjs', import.meta.url), join(root, 'scripts/build.mjs'));
  cpSync(new URL('../public/index.html', import.meta.url), join(root, 'public/index.html'));
  const run = (vars = {}) => spawnSync(process.execPath, [join(root, 'scripts/build.mjs')], {
    cwd: root, encoding: 'utf8', env: { PATH: process.env.PATH, ...vars }
  });
  const config = () => JSON.parse(readFileSync(join(root, 'dist/wrangler.jsonc'), 'utf8'));
  const page = () => readFileSync(join(root, 'dist/assets/index.html'), 'utf8');
  const notice = () => writeFileSync(join(root, 'public/beta-list.html'), '<!doctype html><title>Local fixture, not a notice</title>');
  return { root, run, config, page, notice };
}

test('default production build remains disabled without a notice, D1 or live mail', t => {
  const f = fixture(t);
  assert.equal(f.run().status, 0);
  assert.equal(f.config().vars.SIGNUP_ENABLED, 'false');
  assert.equal(f.config().vars.MAIL_MODE, 'disabled');
  assert.equal(f.config().d1_databases, undefined);
  assert.equal(existsSync(join(f.root, 'dist/assets/beta-list.html')), false);
  assert.match(f.page(), /Beta signup opening soon\. No addresses are collected yet/);
  assert.match(f.page(), /name="email"[^>]*\bdisabled\b/);
  assert.match(f.page(), /type="submit" disabled/);
  assert.doesNotMatch(f.page(), /href="beta-list\.html"/);
  // Provisioning D1 or marking the site launched alone cannot expose collection.
  assert.equal(f.run({ WEBSITE_LAUNCHED: 'true', D1_DATABASE_ID: '00000000-0000-4000-8000-000000000001' }).status, 0);
  assert.equal(f.config().vars.SIGNUP_ENABLED, 'false');
  assert.equal(f.config().vars.MAIL_MODE, 'disabled');
  assert.match(f.page(), /name="email"[^>]*\bdisabled\b/);
});

test('published notice has approved operator/postal contact, no review rail, and does not activate signup alone', t => {
  const notice = readFileSync(new URL('../public/beta-list.html', import.meta.url), 'utf8');
  assert.match(notice, /MotiveSite Inc\./);
  assert.match(notice, /133 Knudson Dr\., Ottawa, ON K2K 2L8, Canada\./);
  assert.match(notice, /beta invitation.*subscription to occasional BaseHero news/s);
  assert.match(notice, /Cloudflare stores the signup list; Lettermint delivers the emails/);
  assert.match(notice, /unsubscribe link.*stops both kinds of email/s);
  assert.doesNotMatch(notice, /\[Verified|review-note|support-preview|Design study|\.\.\/dispatch|beta-flow|\/home\/dan\//i);
  const f = fixture(t);
  cpSync(new URL('../public/beta-list.html', import.meta.url), join(f.root, 'public/beta-list.html'));
  assert.equal(f.run({ WEBSITE_LAUNCHED: 'true', D1_DATABASE_ID: '00000000-0000-4000-8000-000000000001' }).status, 0);
  assert.equal(f.config().vars.SIGNUP_ENABLED, 'false');
  assert.equal(existsSync(join(f.root, 'dist/assets/beta-list.html')), false);
  assert.match(f.page(), /name="email"[^>]*\bdisabled\b/);
  assert.equal(f.run({ WEBSITE_LAUNCHED: 'true', D1_DATABASE_ID: '00000000-0000-4000-8000-000000000001', SIGNUP_ENABLED: 'true' }).status, 0);
  assert.equal(existsSync(join(f.root, 'dist/assets/beta-list.html')), true);
  assert.match(f.page(), /href="beta-list\.html"/);
});

test('enabled build requires a notice, launched website and D1, and emits both-purpose consent', t => {
  const f = fixture(t);
  const enabled = { SIGNUP_ENABLED: 'true', WEBSITE_LAUNCHED: 'true', D1_DATABASE_ID: '00000000-0000-4000-8000-000000000001' };
  assert.notEqual(f.run(enabled).status, 0, 'a missing notice must refuse activation');
  f.notice();
  assert.notEqual(f.run({ ...enabled, WEBSITE_LAUNCHED: 'false' }).status, 0);
  assert.notEqual(f.run({ ...enabled, D1_DATABASE_ID: '' }).status, 0);
  assert.equal(f.run(enabled).status, 0);
  assert.equal(f.config().vars.SIGNUP_ENABLED, 'true');
  assert.equal(f.config().vars.MAIL_MODE, 'live');
  assert.deepEqual(f.config().d1_databases, [{ binding: 'DB', database_name: 'basehero-website', database_id: enabled.D1_DATABASE_ID }]);
  assert.equal(existsSync(join(f.root, 'dist/assets/beta-list.html')), true);
  assert.match(f.page(), /Request a beta invitation and subscribe to the BaseHero newsletter/);
  assert.match(f.page(), /Beta access isn’t guaranteed/);
  assert.match(f.page(), /Confirm your email to activate both/);
  assert.match(f.page(), /No account is created\. Unsubscribe anytime/);
  assert.match(f.page(), /href="beta-list\.html"/);
  assert.doesNotMatch(f.page(), /name="email"[^>]*\bdisabled\b/);
  assert.doesNotMatch(f.page(), /type="submit" disabled/);
  assert.equal(f.config().assets.run_worker_first, true);
});
