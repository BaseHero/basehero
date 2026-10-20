// Fast, platform-independent proof that no release build input enables the
// client's test-only `emulator-fixture` feature. `check.sh android` scans a
// default-feature library; this covers the routes a Tauri release build takes
// instead: its config, the Gradle project and its buildSrc, the client's Cargo
// features, Cargo config rustflags and the release scripts.
//
//   node scripts/android-fixture-exclusion.mjs
//
// Only the feature's own declaration and the fixture's runner and check
// scripts may name it; the runner lives under apps/client/tests and is not scanned.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FEATURE = "emulator-fixture";
const TAURI = "apps/client/src-tauri";
const ANDROID = `${TAURI}/gen/android`;
const GENERATED_JNI_LIBS = `${ANDROID}/app/src/main/jniLibs`;
// The check scripts that build or scan the fixture on purpose.
const ALLOWED_SCRIPTS = new Set([
  "scripts/check.sh",
  "scripts/android-release-check.sh",
  "scripts/android-fixture-exclusion.mjs",
  "scripts/android-emulator-update.sh", // opt-in disposable emulator, never a release build input
]);
// Gradle caches and outputs; a fixture build leaves its libraries in build/.
const SKIPPED_DIRS = new Set([".kotlin", ".gradle", "build", ".cxx", ".externalNativeBuild", ".idea"]);
const DECLARATION = /^\s*emulator-fixture\s*=\s*\[\s*\]\s*$/;

function files(root, dir) {
  const full = path.join(root, dir);
  if (!existsSync(full)) return [];
  return readdirSync(full).flatMap((name) => {
    const rel = `${dir}/${name}`;
    if (rel === GENERATED_JNI_LIBS) return [];
    if (statSync(path.join(root, rel)).isDirectory()) return SKIPPED_DIRS.has(name) ? [] : files(root, rel);
    return [rel];
  });
}

const isGradle = (rel) => /(\.gradle|\.gradle\.kts|\.properties)$/.test(rel) || rel.startsWith(`${ANDROID}/buildSrc/src/`);
const isTauriConfig = (rel) => /^(tauri(\..+)?\.conf\.json5?|Tauri(\..+)?\.toml)$/.test(path.basename(rel));

/** Every file through which a release build could enable the feature. */
export function releaseInputs(root) {
  const tauri = files(root, TAURI).filter((rel) => path.dirname(rel) === TAURI);
  const cargoConfig = [".cargo", "apps/client/.cargo", `${TAURI}/.cargo`].flatMap((dir) => files(root, dir));
  const scripts = files(root, "scripts").filter((rel) => path.dirname(rel) === "scripts" && !ALLOWED_SCRIPTS.has(rel));
  return [
    ...tauri.filter((rel) => isTauriConfig(rel) || path.basename(rel) === "Cargo.toml"),
    ...files(root, ANDROID).filter(isGradle),
    ...cargoConfig,
    ...scripts,
  ];
}

export function check(root) {
  const failures = [];
  for (const rel of releaseInputs(root)) {
    readFileSync(path.join(root, rel), "utf8").split("\n").forEach((line, index) => {
      if (!line.includes(FEATURE)) return;
      if (rel === `${TAURI}/Cargo.toml` && DECLARATION.test(line)) return;
      failures.push(`${rel}:${index + 1}: ${line.trim()}`);
    });
  }
  return failures;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const failures = check(root);
  if (failures.length > 0) {
    for (const failure of failures) console.error(`android fixture exclusion FAIL: ${failure}`);
    process.exit(1);
  }
  console.log(`ok: no ${FEATURE} in ${releaseInputs(root).length} release build inputs (Tauri config, Gradle, Cargo features, release scripts)`);
}
