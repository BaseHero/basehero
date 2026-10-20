import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fixture from './fold-state.mjs';

// Independent measured CSS / physical geometry, including fractional DPR.
const target = () => ({ x: 289, y: 130.72, dpr: 2.625, width: 842, height: 701,
  scale: 1, top: 0, left: 0, page: 123, hit: true, inside: true, paragraph: 'Peer live incoming' });
const geometry = { width: 2208, height: 1840, density: 420 };
test('native tap uses physical coordinates inside measured non-title text', () => {
  assert.deepEqual(fixture.editorTapPoint(target(), geometry, 123, 'Peer live incoming'), [759, 343]);
});
for (const [label, change] of [
  ['overlaid target', t => { t.hit = false; }],
  ['off-pane target', t => { t.inside = false; }],
  ['different paragraph', t => { t.paragraph = 'Title'; }],
  ['replaced page', t => { t.page++; }],
  ['stale geometry', t => { t.width = 411; }],
  ['wrong density', t => { t.dpr = 1; }],
  ['zoom', t => { t.scale = 2; }],
  ['panned viewport', t => { t.left = 4; }],
  ['invalid point', t => { t.y = NaN; }],
  ['point outside screen', t => { t.x = 900; }],
]) test(`native tap refuses ${label}`, () => {
  const t = target(); change(t);
  assert.throws(() => fixture.editorTapPoint(t, geometry, 123, 'Peer live incoming'), { name: 'AssertionError' });
});
test('Back eligibility requires explicit shown IME; unknown is not hidden', () => {
  assert.equal(fixture.imeShown('mInputShown=true'), true);
  assert.equal(fixture.imeShown('mInputShown=false'), false);
  assert.throws(() => fixture.imeShown(''), { name: 'AssertionError' });
});
