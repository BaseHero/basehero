import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertSettledFold, settledFold, verifiedPinPrompt } from './fold-state.mjs';
// API36 dumpsys fragments: independent literal coordinates, no expected value
// computed with the parser under test. Unrelated windows cannot satisfy the gate.
const sample = () => ({
  ime: 'mInputShown=false',
  posture: 'Committed state: CLOSED',
  display: `  DisplayDeviceInfo{"Built-in Screen": uniqueId="local:4619827259835644672", 2208 x 1840, state OFF, committedState OFF}
    mCurrentLayerStack=1
    mCurrentLayerStackRect=Rect(0, 0 - 2208, 1840)
    mCurrentDisplayRect=Rect(0, 0 - 2208, 1840)
  DisplayDeviceInfo{"Built-in Screen": uniqueId="local:4619827551948147201", 1080 x 2092, state ON, committedState ON}
    mCurrentLayerStack=0
    mCurrentLayerStackRect=Rect(0, 0 - 1080, 2092)
    mCurrentDisplayRect=Rect(0, 0 - 1080, 2092)
  Display 0:
    mDisplayId=0
    mPrimaryDisplayDevice=Built-in Screen(local:4619827551948147201)
    mIsEnabled=true
    mIsInTransition=false
    mLayerStack=0
    mOverrideDisplayInfo=DisplayInfo{real 1080 x 2092, density 420 (420.0 x 420.0)}
  Display 1:
    mDisplayId=1
    mPrimaryDisplayDevice=Built-in Screen(local:4619827259835644672)
    mIsEnabled=false
`,
  window: `  mCurrentFocus=Window{abc u0 app.basehero.client/app.basehero.client.MainActivity}
  mScreenOnFully=true mWindowManagerDrawComplete=true
  Window #0 Window{abc u0 app.basehero.client/app.basehero.client.MainActivity}:
    mDisplayId=0
    Requested w=1080 h=2092 mLayoutSeq=412
    Frames: parent=[0,0][1080,2092] display=[0,0][1080,2092] frame=[0,0][1080,2092] last=[0,0][2208,1840] insetsChanged=false
    mHasSurface=true isReadyForDisplay()=true mWindowRemovalAllowed=false
    WindowStateAnimator{af1765c app.basehero.client/app.basehero.client.MainActivity}:
      Surface: shown=true
    isOnScreen=true
    isVisible=true
  Window #1 Window{def u0 NotificationShade}:
    mDisplayId=0 mHasSurface=true mDrawState=HAS_DRAWN isOnScreen=true isVisible=true
    Frames: parent=[0,0][1080,2092] display=[0,0][1080,2092] frame=[0,0][1080,2092] last=[0,0][1080,2092] insetsChanged=false
`,
  activities: '  topResumedActivity=ActivityRecord{abc u0 app.basehero.client/.MainActivity t1}',
  web: { visibility: 'visible', focused: true, editorFocused: true, selected: true,
    width: 1080 / 2.625, height: 2092 / 2.625, screenWidth: 1080 / 2.625, screenHeight: 2092 / 2.625, dpr: 2.625,
    visual: { width: 1080 / 2.625, height: 2092 / 2.625, scale: 1, top: 0, left: 0 },
    pane: { left: 0, top: 60, right: 400, bottom: 730, width: 400, height: 670 },
    caret: { left: 25, top: 180, right: 65, bottom: 200, height: 20 } },
});
test('settled outer app keeps physical IDs exact, maps logical display and viewport', () => {
  const s = assertSettledFold(sample(), 'CLOSED');
  assert.equal(s.physical, '4619827551948147201');
  assert.equal(s.logical, 0); assert.equal(s.width, 1080); assert.equal(s.height, 2092);
});
// Real WebView observation from final R1 fold-incoming/01.json, with the
// existing CLOSED native fixture. The original zero-offset observation passes.
const incomingWeb = {
  visibility: 'visible', focused: true, editorFocused: true, selected: true,
  width: 412, height: 797, screenWidth: 412, screenHeight: 797, dpr: 2.625, page: 1792290245058,
  visual: { width: 412.19049072265625, height: 797.3333129882812, scale: 1, top: 0, left: 0 },
  pane: { left: 0, top: 80, right: 412.19049072265625, bottom: 771.3333740234375,
    width: 412.19049072265625, height: 691.3333740234375 },
  caret: { left: 24, top: 173.7857208251953, right: 56.82143020629883,
    bottom: 194.73809814453125, width: 32.82143020629883, height: 20.952377319335938 },
};
for (const [offset, value] of [['top', 250], ['left', 60]]) test(`reject real incoming caret panned out of visual viewport (${offset})`, () => {
  const s = sample(); s.web = structuredClone(incomingWeb);
  assert.equal(assertSettledFold(s, 'CLOSED').width, 1080);
  s.web.visual[offset] = value;
  assert.throws(() => assertSettledFold(s, 'CLOSED'), /visual viewport/);
});
test('settling diagnoses foreground during pending draw but requires two render-complete samples', async () => {
  let nativeReads = 0, webReads = 0;
  const observations = [];
  const result = await settledFold({ posture: 'CLOSED', attempts: 4,
    native: () => { const s = sample(); if (++nativeReads === 1) s.window = s.window.replace('mScreenOnFully=true', 'mScreenOnFully=false'); return s; },
    web: () => { webReads++; return sample().web; }, wait: async () => {}, record: s => observations.push(s),
  });
  assert.equal(nativeReads, 3); assert.equal(webReads, 3); assert.equal(observations.length, 3);
  assert(observations[0].web); assert.match(observations[0].error, /screen not fully on/);
  assert.equal(result.geometry.width, 1080);
});
test('background DOM never satisfies a bounded settle', async () => {
  let webReads = 0;
  await assert.rejects(settledFold({ posture: 'CLOSED', attempts: 3,
    native: () => ({ ...sample(), activities: '' }), web: () => { webReads++; return sample().web; },
    wait: async () => {}, record: () => {},
  }), /not top resumed/);
  assert.equal(webReads, 0);
});
test('actual frame and viewport pass despite stale requested and screen metadata', () => {
  const s = sample();
  s.window = s.window.replace('Requested w=1080 h=2092', 'Requested w=2208 h=1840');
  s.web.screenWidth = 842; s.web.screenHeight = 701;
  assert.equal(assertSettledFold(s, 'CLOSED').width, 1080);
});
test('foreground geometry failure retains read-only WebView diagnosis, never PASS', async () => {
  const observations = [];
  await assert.rejects(settledFold({ posture: 'CLOSED', attempts: 1,
    native: () => { const s = sample(); s.window = s.window.replace('frame=[0,0][1080,2092]', 'frame=[0,0][2208,1840]'); return s; },
    web: () => sample().web, wait: async () => {}, record: s => observations.push(s),
  }), /actual app frame/);
  assert.deepEqual(observations[0].web, sample().web);
});
const withKeyboard = () => {
  const s = sample(); s.ime = 'mInputShown=true';
  s.window = `  Display: mDisplayId=0 (organized)
        InsetsSource id=3 type=ime frame=[0,1220][1080,2092] visibleFrame=[0,1220][1080,2092] visible=true flags= sideHint=BOTTOM
WINDOW MANAGER WINDOWS
${s.window}`;
  s.web.height = 465; s.web.visual.height = 465.1428527832031;
  s.web.pane.bottom = 439; s.web.pane.height = 379;
  return s;
};
test('shown bottom IME accounts for the real smaller viewport without losing visible caret', () => {
  assert.equal(assertSettledFold(withKeyboard(), 'CLOSED').height, 2092);
});
for (const [label, change] of [
  ['hidden IME', s => { s.ime = 'mInputShown=false'; }],
  ['unknown IME visibility', s => { s.ime = ''; }],
  ['foreign display inset', s => { s.window = s.window.replace('Display: mDisplayId=0', 'Display: mDisplayId=1'); }],
  ['invisible inset', s => { s.window = s.window.replace('visible=true flags=', 'visible=false flags='); }],
  ['wrong inset geometry', s => { s.window = s.window.replace('frame=[0,1220][1080,2092]', 'frame=[0,900][1080,2092]'); }],
  ['caret occluded by keyboard', s => { s.web.caret.top = 470; s.web.caret.bottom = 490; }],
]) test(`IME cannot excuse ${label}`, () => {
  const s = withKeyboard(); change(s); assert.throws(() => assertSettledFold(s, 'CLOSED'));
});
test('PIN requires observed system keyguard AND its credential entry', () => {
  const window = 'mCurrentFocus=Window{def u0 NotificationShade}\nmShowingLockscreen=true';
  const xml = '<node package="com.android.systemui" resource-id="com.android.systemui:id/pinEntry" enabled="true" />';
  assert(verifiedPinPrompt(window, xml));
  assert(!verifiedPinPrompt(window.replace('NotificationShade', 'app.basehero.client'), xml));
  assert(!verifiedPinPrompt(window.replace('true', 'false'), xml));
  assert(!verifiedPinPrompt(window, xml.replace('pinEntry', 'message')));
  assert(!verifiedPinPrompt(window, xml.replace('enabled="true"', 'enabled="false"')));
});
for (const [label, change] of [
  ['background focus', s => { s.window = s.window.replace('mCurrentFocus=Window{abc u0 app.basehero.client/app.basehero.client.MainActivity}', 'mCurrentFocus=Window{def u0 NotificationShade}'); }],
  ['not resumed', s => { s.activities = s.activities.replace('app.basehero.client/.MainActivity', 'com.android.settings/.Settings'); }],
  ['wrong logical display', s => { s.window = s.window.replace('mDisplayId=0', 'mDisplayId=1'); }],
  ['hidden app with visible other window', s => { s.window = s.window.replace('isVisible=true', 'isVisible=false'); }],
  ['app surface not shown', s => { s.window = s.window.replace('Surface: shown=true', 'Surface: shown=false'); }],
  ['app not ready for display', s => { s.window = s.window.replace('isReadyForDisplay()=true', 'isReadyForDisplay()=false'); }],
  ['correct request but stale actual frame', s => { s.window = s.window.replace('frame=[0,0][1080,2092]', 'frame=[0,0][2208,1840]'); }],
  ['missing actual app frame despite other window frame', s => { s.window = s.window.replace('frame=[0,0][1080,2092]', 'missingFrame'); }],
  ['offset actual frame', s => { s.window = s.window.replace('frame=[0,0][1080,2092]', 'frame=[20,0][1100,2092]'); }],
  ['screen not fully on', s => { s.window = s.window.replace('mScreenOnFully=true', 'mScreenOnFully=false'); }],
  ['window draw pending', s => { s.window = s.window.replace('mWindowManagerDrawComplete=true', 'mWindowManagerDrawComplete=false'); }],
  ['inner-sized outer frame', s => { s.display = s.display.replace('Rect(0, 0 - 1080, 2092)', 'Rect(0, 0 - 2208, 1840)'); }],
  ['display transition pending', s => { s.display = s.display.replace('mIsInTransition=false', 'mIsInTransition=true'); }],
  ['physical outer off', s => { s.display = s.display.replace('state ON, committedState ON', 'state OFF, committedState OFF'); }],
  ['stale inner viewport', s => { s.web.width = 2208 / 2.625; }],
  ['hidden WebView', s => { s.web.visibility = 'hidden'; }],
  ['unfocused WebView', s => { s.web.focused = false; }],
  ['zero pane', s => { s.web.pane.height = 0; }],
  ['caret below pane', s => { s.web.caret.bottom = 780; }],
  ['wrong DPR', s => { s.web.dpr = 1; }],
]) test(`reject CLOSED+DOM without ${label}`, () => {
  const s = sample(); change(s); assert.throws(() => assertSettledFold(s, 'CLOSED'));
});
