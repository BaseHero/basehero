import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';

const lib = fileURLToPath(new URL('./lib.sh', import.meta.url));
test('runner refuses an occupied port before launching an app', async t => {
  const server = spawn('node', ['-e', 'require("node:net").createServer().listen(4445,"127.0.0.1"); console.log("ready")'], { stdio: ['ignore', 'pipe', 'inherit'] });
  t.after(() => { server.kill(); });
  await Promise.race([once(server.stdout, 'data'), once(server, 'exit').then(() => { throw Error('listener exited'); })]);
  const result = spawnSync('bash', ['-c', `source "$1"; refuse_occupied_port`, 'bash', lib], { encoding: 'utf8' });
  assert.notEqual(result.status, 0, result.stderr);
  assert.match(result.stderr, /already listening/);
});

test('emulator preflight refuses even an offline attached device', t => {
  const dir = mkdtempSync(join(tmpdir(), 'bh-adb-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'adb'), '#!/bin/sh\nprintf "List of devices attached\\nemulator-5556\\toffline\\n"\n', { mode: 0o755 });
  const result = spawnSync('bash', ['-c', 'PATH="$2:$PATH"; source "$1"; refuse_attached_android', 'bash', lib, dir], {
    encoding: 'utf8',
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /already attached/);
});
