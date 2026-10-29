import { test, expect } from '@playwright/test';

test('a refusal between account snapshot and event subscription is not lost', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(window, '__fake', { configurable: true, set(fake: typeof window.__fake) {
      Object.defineProperty(window, '__fake', { configurable: true, value: fake });
      // signUp populates the fake synchronously, just as a native core already has an account.
      void fake.signUp({ invite: 'WELCOME', email: 'known@example.com', password: 'correct horse battery staple', deviceName: 'Mac' });
      const accounts = fake.accounts.bind(fake);
      let snapshotTaken = false;
      let id = '';
      fake.accounts = async () => {
        const snapshot = await accounts();
        snapshotTaken = true;
        id = snapshot[0].id;
        return snapshot;
      };
      const onEvent = fake.onEvent.bind(fake);
      let first = true;
      fake.onEvent = async handler => {
        if (first) {
          first = false;
          // Native listen() is asynchronous. Let the old account snapshot finish,
          // then deliver a refusal before this window's event listener is registered.
          await Promise.resolve();
          if (!snapshotTaken) throw new Error('harness expected the snapshot first');
          fake.emit({ kind: 'account', account: id, event: 'SignedOutByServer' });
        }
        return onEvent(handler);
      };
    } });
  });
  await page.goto('/');
  await expect.poll(() => page.evaluate(async () => (await window.__fake.accounts())[0]?.signedOutByServer)).toBe(true);
  await expect(page.getByRole('alert').filter({ hasText: 'The server signed this device out' })).toBeVisible();
});
