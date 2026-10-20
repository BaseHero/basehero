import assert from 'node:assert/strict';
import { test } from 'node:test';
import { cloudText } from '../ui/pairing.js';

test('sync status counts notes, not keystrokes, and ends at Synced', () => {
  assert.equal(cloudText['saved-local']({ pending: 1, network: 'on' }), 'Saved on this device · 1 not yet synced');
  assert.equal(cloudText.syncing({ pending: 0 }), 'Syncing');
  assert.equal(cloudText.syncing({ pending: 1 }), 'Syncing 1 note');
  assert.equal(cloudText.syncing({ pending: 2 }), 'Syncing 2 notes');
  assert.equal(cloudText.synced({ pending: 0 }), 'Synced');
});
