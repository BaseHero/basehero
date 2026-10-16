// Assert that a built artifact does or does not contain the WebDriver plugin.
// Works on a linked binary or on an Android APK (native libs, dex classes and
// the merged manifest are all scanned), so an accidental feature or Gradle
// module leak fails a release build.
//
//   node scripts/check-webdriver-markers.mjs <artifact> --expect absent|present
//
// Tests use synthetic files for both directions; real release artifacts are
// checked without the feature, and `--expect present` is the positive control.
import { readFileSync, realpathSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

export const MARKERS = [
  "tauri-plugin-webdriver",
  "tauri_plugin_webdriver",
  "TAURI_WEBDRIVER_PORT",
  "session/{session_id}",
  "com/plugin/webdriver",
  "com.plugin.webdriver",
];

/** Markers present in `bytes`, in MARKERS order. */
export function markersIn(bytes) {
  const text = bytes.toString("latin1");
  return MARKERS.filter((marker) => text.includes(marker));
}

function artifactBytes(path) {
  const bytes = readFileSync(path);
  if (bytes.subarray(0, 4).toString("latin1") === "PK\u0003\u0004") {
    // An APK: concatenate every stored entry (dex, jni libs, manifest, resources).
    const unzip = spawnSync("unzip", ["-p", path], { maxBuffer: 512 * 1024 * 1024 });
    if (unzip.status !== 0) {
      throw new Error(`unzip -p ${path} failed: ${unzip.stderr}`);
    }
    return unzip.stdout;
  }
  return bytes;
}

export function check(path, expectation) {
  const present = markersIn(artifactBytes(path));
  if (expectation === "absent" && present.length > 0) {
    return [`${path} contains ${present.join(", ")}`];
  }
  if (expectation === "present" && present.length !== MARKERS.length) {
    return [`${path} is missing markers: ${MARKERS.filter((m) => !present.includes(m)).join(", ")}`];
  }
  return [];
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  const [path, flag, expectation] = process.argv.slice(2);
  if (!path || flag !== "--expect" || !["absent", "present"].includes(expectation)) {
    console.error("usage: node scripts/check-webdriver-markers.mjs <artifact> --expect absent|present");
    process.exit(2);
  }
  const failures = check(path, expectation);
  if (failures.length > 0) {
    for (const failure of failures) console.error(`webdriver markers FAIL: expected ${expectation}, ${failure}`);
    process.exit(1);
  }
  console.log(`ok: ${path} matches --expect ${expectation}`);
}
