// Plain W3C HTTP wait for the Android WebView to have a non-zero viewport.
// The plugin's Android screenshot draws the WebView to a bitmap and fails with
// "width and height must be > 0" if layout has not happened yet, so the Android
// runner waits here before running the shared spec. No dependencies.
//
//   node wait-for-layout.mjs
import { laidOutAndVisible } from './viewport.mjs';
const base = 'http://127.0.0.1:4445';

const created = await (await fetch(base + "/session", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ capabilities: {} }),
})).json();
const sessionId = created?.value?.sessionId;
if (!sessionId) {
  console.error("no session id: " + JSON.stringify(created));
  process.exit(1);
}

let last = null;
let ok = false;
try {
  for (let i = 0; i < 60; i += 1) {
    const body = await (await fetch(`${base}/session/${sessionId}/execute/sync`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        script: "return [window.innerWidth, window.innerHeight, document.visibilityState, document.readyState];",
        args: [],
      }),
    })).json();
    last = body?.value;
    if (laidOutAndVisible(last)) {
      ok = true;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  console.log("viewport [width, height, visibility, readyState] = " + JSON.stringify(last));
} finally {
  await fetch(`${base}/session/${sessionId}`, { method: "DELETE" });
}
process.exit(ok ? 0 : 1);
