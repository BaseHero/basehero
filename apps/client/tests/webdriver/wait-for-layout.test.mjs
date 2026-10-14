import test from 'node:test';
import assert from 'node:assert/strict';
import { laidOutAndVisible } from './viewport.mjs';

test('a hidden or zero-size WebView cannot be screenshot acceptance', () => {
  assert.equal(laidOutAndVisible([412, 915, 'hidden', 'complete']), false);
  assert.equal(laidOutAndVisible([0, 0, 'visible', 'complete']), false);
  assert.equal(laidOutAndVisible([412, 915, 'visible', 'loading']), true);
});
