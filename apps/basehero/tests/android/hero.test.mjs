import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { launch, webview, newNote } from './lib.mjs';

// A screenshot of the panel with a real reply, for people checking a build.
const screenshot = process.env.BH_HERO_SCREENSHOT ?? resolve(import.meta.dirname, '../../test-results/hero-panel.png');
const streamingScreenshot = resolve(import.meta.dirname, '../../test-results/hero-panel-streaming.png');
const prompt = 'Create a note titled Packing list with three items for a ferry trip.';

test('Hero on dev replies, creates a note, and its button opens the editor', { timeout: 150_000 }, async () => {
  await launch(); const page = await webview();
  try {
    await newNote(page, 'Hero check');
    const panel = page.getByRole('region', { name: 'Hero' });
    // The app remembers an open panel; the toggle would close it.
    if (!await panel.getByLabel('Ask Hero').isVisible() && await page.locator('.hero-toggle').isVisible()) {
      await page.locator('.hero-toggle').click();
    }
    await panel.getByLabel('Ask Hero').waitFor();
    await panel.getByLabel('Ask Hero').fill(prompt);
    await panel.getByRole('button', { name: 'Send' }).click();
    // Both the reply and Stop must be visible at the same instant, before completion.
    await page.waitForFunction(() => {
      const panel = document.querySelector('[aria-label="Hero"]');
      const reply = panel?.querySelector('article:not(.user):last-of-type p')?.textContent?.trim();
      return !!reply && reply !== 'Hero is working…' &&
        [...(panel?.querySelectorAll('button') ?? [])].some(button => button.textContent?.trim() === 'Stop');
    }, null, { timeout: 30_000 });
    const streamingText = await panel.locator('article:not(.user)').last().locator('p').first().textContent();
    assert(streamingText?.trim(), 'no Hero text while Stop was available');
    console.log('Hero streaming text:', streamingText);
    await panel.screenshot({ path: streamingScreenshot });
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
