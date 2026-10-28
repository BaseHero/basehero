import { expect, test } from '@playwright/test';

test('Hero reply shows a created note that opens in the editor', async ({ page }) => {
  await page.goto('/');
  const ref = await page.evaluate(async () => {
    const { account, kit } = await window.__fake.signUp({ invite: 'DEMO', email: 'hero@example.test', password: 'password', deviceName: 'Mac' });
    await window.__fake.setKitSaved(account.id, kit);
    const base = await window.__fake.createBase(account.id, 'Personal');
    const focus = await window.__fake.createObject({ account: account.id, base: base.id }, { kind: 'note', name: 'Kyoto in March', parent: null, after: null });
    const note = await window.__fake.createObject({ account: account.id, base: base.id }, { kind: 'note', name: 'Kyoto checklist', parent: null, after: null });
    window.__fake.seedHeroChat(account.id, base.id, null, 'chat');
    window.__fake.seedHeroMessages(account.id, base.id, 'chat', [
      { id: 'user', role: 'user', text: 'Create a note named Kyoto checklist containing: Bring a train ticket. Then briefly reply.', at: '2026-10-30T00:00:00Z', state: 'done', error: null, steps: [], created: [], ask: null },
      { id: 'reply', role: 'hero', text: 'Done — I created the note "Kyoto checklist" with the item "Bring a train ticket."', at: '2026-10-30T00:00:01Z', state: 'done', error: null, steps: [], created: [note], ask: null },
    ]);
    return { account: account.id, base: base.id, focus, note };
  });
  await page.evaluate(ref => { location.hash = `#/a/${ref.account}/b/${ref.base}/n/${ref.focus}`; }, ref);
  const panel = page.getByRole('region', { name: 'Hero' });
  await expect(panel.getByText('Done — I created the note', { exact: false })).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Kyoto checklist' })).toBeVisible();
  if (process.env.BH_HERO_SCREENSHOT) await page.screenshot({ path: process.env.BH_HERO_SCREENSHOT, fullPage: true });
  await panel.getByRole('button', { name: 'Kyoto checklist' }).click();
  await expect(page).toHaveURL(new RegExp(`/n/${ref.note}$`));
  await expect(page.getByRole('region', { name: 'Note editor' })).toBeVisible();
});

async function noteWithHero(page) {
  await page.goto('/');
  const ref = await page.evaluate(async () => {
    const { account, kit } = await window.__fake.signUp({ invite: 'DEMO', email: 'width@example.test', password: 'password', deviceName: 'Fold' });
    await window.__fake.setKitSaved(account.id, kit);
    const base = await window.__fake.createBase(account.id, 'Personal');
    const note = await window.__fake.createObject({ account: account.id, base: base.id }, { kind: 'note', name: 'Ferry', parent: null, after: null });
    return { account: account.id, base: base.id, note };
  });
  await page.evaluate(ref => { location.hash = `#/a/${ref.account}/b/${ref.base}/n/${ref.note}`; }, ref);
  await expect(page.locator('.ProseMirror')).toBeVisible();
}

test('the conversation follows a growing reply unless scrolled up', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 600 });
  await page.goto('/');
  const ref = await page.evaluate(async () => {
    const { account, kit } = await window.__fake.signUp({ invite: 'DEMO', email: 'scroll@example.test', password: 'password', deviceName: 'Mac' });
    await window.__fake.setKitSaved(account.id, kit);
    const base = await window.__fake.createBase(account.id, 'Personal');
    const note = await window.__fake.createObject({ account: account.id, base: base.id }, { kind: 'note', name: 'Ferry', parent: null, after: null });
    window.__fake.seedHeroChat(account.id, base.id, null, 'scroll-chat');
    window.__fake.seedHeroMessages(account.id, base.id, 'scroll-chat', [
      ...Array.from({ length: 15 }, (_, index) => ({ id: `user-${index}`, role: 'user' as const, text: `Earlier question ${index}`, at: '2026-10-30T00:00:00Z', state: 'done' as const, error: null, steps: [], created: [], ask: null })),
      { id: 'working-reply', role: 'hero', text: '', at: '2026-10-30T00:00:01Z', state: 'working', error: null, steps: [], created: [], ask: null },
    ]);
    return { account: account.id, base: base.id, note };
  });
  await page.evaluate(ref => { location.hash = `#/a/${ref.account}/b/${ref.base}/n/${ref.note}`; }, ref);
  const panel = page.getByRole('region', { name: 'Hero' });
  await expect(panel.getByText('Hero is working…')).toBeVisible();
  const conversation = panel.locator('.conversation');
  await conversation.evaluate(el => { el.scrollTop = el.scrollHeight; });
  const stream = async (text: string) => page.evaluate(({ ref, text }) => {
    window.__fake.heroText(ref.account, ref.base, 'scroll-chat', 'working-reply', text);
  }, { ref, text });
  await stream('The answer starts.');
  await expect(panel.getByText('The answer starts.')).toBeVisible();
  await expect.poll(() => conversation.evaluate(el => el.scrollHeight - el.scrollTop - el.clientHeight)).toBeLessThan(3);
  await conversation.evaluate(el => { el.scrollTop = 0; });
  await stream('The answer starts.\n'.repeat(30));
  await expect(panel.getByText('The answer starts.', { exact: false }).last()).toBeVisible();
  expect(await conversation.evaluate(el => el.scrollTop)).toBe(0);
});

test('on an unfolded Fold Hero opens as a sheet wide enough to read', async ({ page }) => {
  await page.setViewportSize({ width: 852, height: 880 });
  await noteWithHero(page);
  const panel = page.getByRole('region', { name: 'Hero' });
  await expect(panel).toBeHidden();
  await page.getByRole('button', { name: 'Hero', exact: true }).click();
  await expect(panel).toBeVisible();
  const box = (await panel.boundingBox())!;
  expect(box.width).toBeGreaterThanOrEqual(320);
  expect(box.height).toBeGreaterThanOrEqual(880 * 0.6);
  await page.getByRole('button', { name: 'Close Hero' }).click();
  await expect(panel).toBeHidden();
});

test('on a wide window Hero sits beside the note at a readable width', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await noteWithHero(page);
  const panel = page.getByRole('region', { name: 'Hero' });
  await expect(panel).toBeVisible();
  await expect(page.getByRole('button', { name: 'Hero', exact: true })).toBeHidden();
  expect((await panel.boundingBox())!.width).toBeGreaterThanOrEqual(260);
});
