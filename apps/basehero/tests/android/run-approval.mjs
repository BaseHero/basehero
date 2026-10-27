import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { bh, createDevInvite, temporaryHome } from './lib.mjs';

const { home, remove } = temporaryHome();
try {
  const email = `android-approval-${Date.now()}-${randomUUID()}@example.com`;
  const password = `Test-${randomUUID()}-long`;
  const invite = createDevInvite();
  let kit;
  try {
    kit = bh(['--home', home, 'signup', '--server', 'https://dev-api.basehero.com',
      '--invite', invite, '--email', email, '--name', 'Approval check'], { home, password }).kit;
  } catch {
    throw new Error('could not sign up the dev approver');
  }
  assert(kit && /\S/.test(kit), 'dev signup must return a recovery kit');
  const root = resolve(import.meta.dirname, '../../../..');
  const result = spawnSync(process.execPath, ['--test', 'apps/basehero/tests/android/approval.test.mjs'], {
    cwd: root,
    env: {
      PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: home, GH_CONFIG_DIR: home,
      BH_APPROVER_CLI: resolve(root, 'target/debug/bh'), BH_APPROVER_HOME: home,
      BH_TEST_EMAIL: email, BH_TEST_PASSWORD: password, BH_TEST_KIT: kit,
    },
    stdio: 'inherit',
    timeout: 240_000,
  });
  if (result.error) throw new Error(`approval suite could not finish: ${result.error.code}`);
  process.exitCode = result.status ?? 1;
} finally {
  remove();
}
