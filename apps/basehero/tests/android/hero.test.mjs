import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { launch, webview, openBase, newNote } from './lib.mjs';

// A screenshot of the panel with a real reply, for people checking a build.
const screenshot = process.env.BH_HERO_SCREENSHOT ?? resolve(import.meta.dirname, '../../test-results/hero-panel.png');
const prompt = 'Create a note titled Packing list with three items for a ferry trip.';

test('Hero on dev replies, creates a note, and its button opens the editor', { timeout: 150_000 }, async () => {
  await launch(); const page = await webview();
  try {
    await newNote(page, 'Hero check');
    if (await page.locator('.hero-toggle').isVisible()) await page.locator('.hero-toggle').click();
    const panel = page.getByRole('region', { name: 'Hero' });
    await panel.getByLabel('Ask Hero').waitFor();
    // On a rerun, use the already completed turn rather than spending on another call.
    if (!await panel.getByText(prompt, { exact: true }).count()) {
      await panel.getByLabel('Ask Hero').fill(prompt);
      await panel.getByRole('button', { name: 'Send' }).click();
    }
    const created = panel.locator('button.created', { hasText: 'Packing list' });
    await created.waitFor({ timeout: 90_000 });
    await panel.getByText('Hero is working…').waitFor({ state: 'hidden', timeout: 90_000 });
    const heroReply = await panel.locator('article:not(.user)').last().locator('p').first().textContent();
    assert(heroReply?.trim() && !heroReply.includes('working') && !heroReply.includes('couldn’t'),
      `Hero reply is missing: ${heroReply}`);
    console.log('Hero reply:', heroReply);
    await panel.screenshot({ path: screenshot });
    await created.click();
    await page.locator('[aria-label="Note editor"] .ProseMirror').getByRole('heading', { name: 'Packing list', exact: true }).waitFor();
  } finally { await page.context().browser()?.close(); }
});
