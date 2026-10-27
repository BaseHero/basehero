import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAdb } from './lib.mjs';

test('every ADB action refuses a different AVD before touching it', () => {
  const calls = [];
  const adb = createAdb((_command, args) => {
    calls.push(args);
    return 'someone-elses-avd\nOK\n';
  });
  for (const args of [['shell', 'input', 'keyevent', '4'], ['emu', 'fold'], ['emu', 'unfold'], ['forward', 'tcp:0', 'localabstract:fake']]) {
    assert.throws(() => adb(...args), /refusing another AVD/);
  }
  assert.deepEqual(calls, Array.from({ length: 4 }, () => ['-s', 'emulator-5580', 'emu', 'avd', 'name']));
});

test('a verified AVD permits the intended action with an explicit serial', () => {
  const calls = [];
  const adb = createAdb((_command, args) => {
    calls.push(args);
    return args[2] === 'emu' ? 'bh-fold-36\nOK\n' : 'done\n';
  });
  assert.equal(adb('shell', 'getprop', 'sys.boot_completed'), 'done');
  assert.deepEqual(calls, [
    ['-s', 'emulator-5580', 'emu', 'avd', 'name'],
    ['-s', 'emulator-5580', 'shell', 'getprop', 'sys.boot_completed'],
  ]);
});
