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
  assert.deepEqual(calls, Array.from({ length: 4 }, () => ['-s', 'emulator-5580', 'shell', 'getprop', 'ro.boot.qemu.avd_name']));
});

test('an isolated HOME can identify the AVD without emulator-console credentials', () => {
  const calls = [];
  const adb = createAdb((_command, args) => {
    calls.push(args);
    if (args.includes('avd') && args.includes('name')) return ''; // console denies a fresh HOME
    if (args.includes('ro.boot.qemu.avd_name')) return 'bh-fold-36\n';
    if (args.includes('ro.kernel.qemu')) return '1\n';
    return 'done\n';
  });
  assert.equal(adb('shell', 'getprop', 'sys.boot_completed'), 'done');
  assert(calls.every(args => args[0] === '-s' && args[1] === 'emulator-5580'));
});

test('a verified AVD permits the intended action with an explicit serial', () => {
  const calls = [];
  const adb = createAdb((_command, args) => {
    calls.push(args);
    if (args.includes('ro.boot.qemu.avd_name')) return 'bh-fold-36\n';
    if (args.includes('ro.kernel.qemu')) return '1\n';
    return 'done\n';
  });
  assert.equal(adb('shell', 'getprop', 'sys.boot_completed'), 'done');
  assert.deepEqual(calls, [
    ['-s', 'emulator-5580', 'shell', 'getprop', 'ro.boot.qemu.avd_name'],
    ['-s', 'emulator-5580', 'shell', 'getprop', 'ro.kernel.qemu'],
    ['-s', 'emulator-5580', 'shell', 'getprop', 'sys.boot_completed'],
  ]);
});
