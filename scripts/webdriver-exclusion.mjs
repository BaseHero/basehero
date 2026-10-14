// Fast, platform-independent proof that the WebDriver plugin is not in the
// default feature graph of the client for any target. Release builds must not
// link it; real-app tests enable it through the non-default `webdriver` feature.
//
//   node scripts/webdriver-exclusion.mjs
//
// The check also runs the positive control (the feature enabled must pull the
// plugin) so a passing result cannot be vacuous.
import { spawnSync } from "node:child_process";

const PACKAGE = "tauri-plugin-webdriver";
const CRATE = "tauri_plugin_webdriver";
const FEATURE = "webdriver";

/** Lines that mention the plugin, i.e. it reached the resolved feature graph. */
export function pluginLines(treeOutput) {
  return treeOutput
    .split("\n")
    .filter((line) => line.includes(PACKAGE) || line.includes(CRATE));
}

function tree(features) {
  const args = ["tree", "--locked", "-e", "features", "--target", "all", "-p", "bh-client"];
  if (features) {
    args.push("--features", features);
  }
  const result = spawnSync("cargo", args, { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`cargo ${args.join(" ")} failed: ${result.stderr || result.stdout}`);
  }
  return result.stdout;
}

export function check({ trees = tree } = {}) {
  const failures = [];

  const defaults = pluginLines(trees(undefined));
  if (defaults.length > 0) {
    failures.push(`default features pull the plugin:\n  ${defaults.join("\n  ")}`);
  }

  const enabled = pluginLines(trees(FEATURE));
  if (enabled.length === 0) {
    failures.push(`the ${FEATURE} feature did not pull the plugin; the check is not meaningful`);
  }

  return failures;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const failures = check();
  if (failures.length > 0) {
    for (const failure of failures) console.error(`webdriver exclusion FAIL: ${failure}`);
    process.exit(1);
  }
  console.log("ok: no tauri-plugin-webdriver in the default feature graph for any target; positive control found it with --features webdriver");
}
