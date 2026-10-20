import assert from 'node:assert/strict';
// Read-only observations in the actual WebView, not a synthetic layout or focus.
export const foldViewportScript = `const e=document.querySelector('.ProseMirror'),s=window.getSelection();
  const rect=r=>r?{left:r.left,top:r.top,right:r.right,bottom:r.bottom,width:r.width,height:r.height}:null;
  return {visibility:document.visibilityState,focused:document.hasFocus(),editorFocused:document.activeElement===e,
    selected:!!e&&e.contains(s?.anchorNode),width:innerWidth,height:innerHeight,
    screenWidth:screen.width,screenHeight:screen.height,dpr:devicePixelRatio,
    visual:visualViewport?{width:visualViewport.width,height:visualViewport.height,scale:visualViewport.scale,
      top:visualViewport.offsetTop,left:visualViewport.offsetLeft}:null,
    pane:rect(e?.closest('.note-pane')?.getBoundingClientRect()),
    caret:rect(s?.rangeCount?s.getRangeAt(0).getBoundingClientRect():null),page:performance.timeOrigin};`;

// Convert only an observed, unobscured non-title paragraph hit to native pixels.
// Called before the transition, never to restore focus after a fold.
export function editorTapPoint(target, geometry, page, paragraph) {
  assert(target.hit && target.inside && target.paragraph === paragraph, 'unsafe editor tap target');
  assert.equal(target.page, page, 'tap page replaced');
  assert.equal(target.scale, 1); assert.equal(target.top, 0); assert.equal(target.left, 0);
  assert(Number.isFinite(target.dpr) && target.dpr > 0);
  assert(Math.abs(target.dpr * 160 - geometry.density) <= 2 * target.dpr);
  assert(Math.abs(target.width * target.dpr - geometry.width) <= 2 * target.dpr);
  assert(Math.abs(target.height * target.dpr - geometry.height) <= 2 * target.dpr);
  assert(Number.isFinite(target.x) && Number.isFinite(target.y) &&
    target.x > 0 && target.x < target.width && target.y > 0 && target.y < target.height);
  return [Math.round(target.x * target.dpr), Math.round(target.y * target.dpr)];
}

export function imeShown(dump) {
  const shown = dump.match(/\bmInputShown=(true|false)\b/);
  assert(shown, 'IME visibility unknown; do not send Back');
  return shown[1] === 'true';
}

export function verifiedPinPrompt(window, xml) {
  return /mCurrentFocus=Window\{[^\n}]*\bNotificationShade\}/.test(window) &&
    /mShowingLockscreen=true\b/.test(window) && [...xml.matchAll(/<node\b[^>]*>/g)].some(([node]) =>
      node.includes('package="com.android.systemui"') && node.includes('resource-id="com.android.systemui:id/pinEntry"') && node.includes('enabled="true"'));
}

// Ownership/PID are checked by the caller before each native observation.
// This gate permits read-only foreground WebView diagnosis even while layout
// is pending; it does not declare rendering settled.
export function assertForeground({ window, activities }) {
  const focus = window.match(/mCurrentFocus=Window\{([^\n}]+)\}/)?.[1];
  assert(focus?.includes('app.basehero.client/app.basehero.client.MainActivity'), 'app not focused');
  const appWindow = [...window.matchAll(/^  Window #\d+ Window\{([^\n}]+)\}:\n([\s\S]*?)(?=^  Window #|$(?![\s\S]))/gm)].find(m => m[1] === focus)?.[2];
  assert(appWindow, 'focused window absent');
  for (const flag of ['mDisplayId=0', 'mHasSurface=true', 'isReadyForDisplay()=true', 'Surface: shown=true', 'isOnScreen=true', 'isVisible=true']) {
    assert(appWindow.includes(flag), `app window lacks ${flag}`);
  }
  assert.match(activities, /topResumedActivity=ActivityRecord\{[^\n}]*app\.basehero\.client\/\.MainActivity\b/, 'app not top resumed');
  return appWindow;
}

// Two consecutive matching native + WebView observations. Never drive the
// background WebView to make a foreground assertion pass.
export async function settledFold({ posture, native, web, wait, record, attempts = 30 }) {
  let previous, last;
  for (let i = 0; i < attempts; i++) {
    const sample = await native();
    try {
      assertForeground(sample);
      sample.web = await web();
      const geometry = assertSettledFold(sample, posture);
      const key = JSON.stringify([geometry, sample.web]);
      record({ ...sample, geometry });
      if (previous === key) return { ...sample, geometry };
      previous = key;
    } catch (error) {
      last = String(error); previous = undefined; record({ ...sample, error: last });
    }
    await wait();
  }
  throw Error(`fold did not settle: ${last ?? 'geometry kept changing'}`);
}

// API36 Fold dumpsys. Fail closed on missing/ambiguous observations. IDs stay
// strings: physical display IDs exceed Number's exact-integer range.
export function assertSettledFold(sample, posture, withWeb = true) {
  const { display, window, web } = sample;
  const appWindow = assertForeground(sample);
  assert(sample.posture.includes(posture), `not ${posture}`);
  const devices = [...display.matchAll(/^  DisplayDeviceInfo\{[^\n]+[\s\S]*?(?=^  DisplayDeviceInfo\{|^LogicalDisplayMapper:|$(?![\s\S]))/gm)]
    .map(([block]) => {
      const m = block.match(/uniqueId="local:(\d+)", (\d+) x (\d+)/);
      return m && { physical: m[1], width: +m[2], height: +m[3], block };
    }).filter(Boolean).sort((a, b) => b.width * b.height - a.width * a.height);
  assert.equal(devices.length, 2, 'expected exactly two physical Fold displays');
  const [active, inactive] = posture === 'CLOSED' ? [devices[1], devices[0]] : devices;
  assert.match(active.block.split('\n')[0], /state ON, committedState ON\b/, 'active physical display not on');
  assert.match(inactive.block.split('\n')[0], /state OFF, committedState OFF\b/, 'inactive physical display not off');
  const { physical, width, height } = active;
  for (const key of ['mCurrentLayerStackRect', 'mCurrentDisplayRect']) {
    assert(active.block.includes(`${key}=Rect(0, 0 - ${width}, ${height})`), `${key} not settled physical geometry`);
  }
  const logicalBlocks = [...display.matchAll(/^  Display (\d+):\n([\s\S]*?)(?=^  Display \d+:|^  Display Groups:|$(?![\s\S]))/gm)];
  const logicalBlock = logicalBlocks.find(m => m[2].includes(`mPrimaryDisplayDevice=Built-in Screen(local:${physical})`));
  assert(logicalBlock, 'physical display has no logical route');
  const logical = +logicalBlock[1], block = logicalBlock[2];
  assert.equal(logical, 0, 'app must be on active default logical display');
  assert.match(block, /mIsEnabled=true\b/); assert.match(block, /mIsInTransition=false\b/);
  assert(block.includes(`mLayerStack=${logical}\n`) && active.block.includes(`mCurrentLayerStack=${logical}\n`));
  const info = block.match(/mOverrideDisplayInfo=(DisplayInfo\{[^\n]+)/)?.[1] ?? block.match(/mBaseDisplayInfo=(DisplayInfo\{[^\n]+)/)?.[1];
  assert(info?.includes(`real ${width} x ${height},`), 'logical geometry not settled');
  const density = +info.match(/density (\d+)/)?.[1];
  assert(density > 0, 'missing logical display density');
  // Android 16 WindowFrames.mFrame is the actual app frame in display
  // coordinates. Requested is the application's request, not layout output.
  // Obtain this from dumpsys window -a, scoped to the exact focused window.
  const frame = appWindow.match(/^\s*Frames:[^\n]*\bframe=(\[[-\d]+,[-\d]+\]\[[-\d]+,[-\d]+\])/m)?.[1];
  assert.equal(frame, `[0,0][${width},${height}]`, 'actual app frame not settled');
  assert.match(window, /mScreenOnFully=true\b/, 'screen not fully on');
  assert.match(window, /mWindowManagerDrawComplete=true\b/, 'window manager draw incomplete');
  let viewportHeight = height;
  if (withWeb) {
    if (imeShown(sample.ime)) {
      // adjustResize leaves the app window full-sized but removes the shown
      // bottom IME from the WebView. Use the active display's real inset, not
      // screen.* or a keyboard-height guess. Unknown/floating geometry fails.
      const displayWindow = window.match(/^  Display: mDisplayId=0\b[^\n]*\n([\s\S]*?)(?=^  Display: |^WINDOW MANAGER |$(?![\s\S]))/m)?.[1];
      const inset = displayWindow?.match(/^\s+InsetsSource\b[^\n]*type=ime frame=\[0,(\d+)\]\[(\d+),(\d+)\][^\n]*\bvisible=true\b/m);
      assert(inset && +inset[2] === width && +inset[3] === height && +inset[1] > 0 && +inset[1] < height,
        'shown IME lacks active-display bottom inset');
      viewportHeight = +inset[1];
    }
    assert.equal(web.visibility, 'visible'); assert(web.focused && web.editorFocused && web.selected, 'live editor not focused');
    const close = (a, b) => Number.isFinite(a) && Math.abs(a - b) <= 2 * web.dpr;
    assert(close(web.dpr * 160, density), 'WebView density mismatch');
    assert(close(web.width * web.dpr, width) && close(web.height * web.dpr, viewportHeight), 'WebView not reflowed to visible native geometry');
    // screen.* describes screen metadata, not this WebView's render viewport.
    // Keep it in observations; require the actual layout + visual viewport.
    assert(web.visual?.scale === 1 && close(web.visual.width, web.width) && close(web.visual.height, web.height), 'visual viewport mismatch');
    assert(web.visual.top === 0 && web.visual.left === 0, 'visual viewport panned; layout caret bounds are not visible bounds');
    const { pane: p, caret: c } = web;
    assert(p?.width > 0 && p.height > 0 && c?.height > 0, 'empty pane/caret');
    assert(c.top >= Math.max(p.top, 0) && c.bottom <= Math.min(p.bottom, web.height) &&
      c.left >= Math.max(p.left, 0) && c.right <= Math.min(p.right, web.width), 'caret outside visible pane');
  }
  return { physical, logical, width, height, density, viewportHeight };
}
