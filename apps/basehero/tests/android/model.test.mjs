import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { launch, webview } from './lib.mjs';

// Two tiny paid calls through the dev gateway, so only on request.
const live = process.env.BH_LIVE === '1';
const gateway = process.env.BH_LIVE_GATEWAY ?? 'https://dev-api.basehero.com/v1/models/tinfoil/';
const tokenFile = process.env.BH_LIVE_TOKEN_FILE ?? `${homedir()}/.config/basehero/dev-operator-token`;

test('the app verifies Tinfoil and completes a live call', { skip: !live && 'set BH_LIVE=1' }, async () => {
  await launch();
  const page = await webview();
  try {
    // The token stays an invoke argument: never written to the device or printed.
    const result = await page.evaluate(
      args => window.__TAURI_INTERNALS__.invoke('dev_model_probe', args)
        .then(value => ({ value }), error => ({ error: JSON.stringify(error) })),
      { gateway, token: readFileSync(tokenFile, 'utf8').trim() },
    );
    assert.equal(result.error, undefined, `dev_model_probe failed: ${result.error}`);
    console.log(JSON.stringify(result.value));
    const probe = result.value;
    assert.equal(probe.ok, true);
    assert.equal(probe.verified, true);
    assert.equal(probe.text, 'ferry');
    assert.equal(probe.tool, 'note_title');
    assert.equal(probe.tool_args.title, 'Ferry times');
  } finally {
    await page.context().browser()?.close();
  }
});
