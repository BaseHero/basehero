import { test, expect, type Page } from '@playwright/test';

const kit = '7KQ2-M9XD-4F8P-2L6R-V3TN-H5YA-ZC';
async function pending(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: 'Open this device' })).toBeVisible();
}
async function signed(page: Page, beforeContinue?: () => Promise<void>): Promise<string> {
  await page.goto('/');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByLabel('Device name').fill('Mac');
  await page.getByRole('button', { name: 'Create account' }).click();
  await beforeContinue?.();
  await page.getByRole('button', { name: 'Later' }).click();
  return (await page.evaluate(() => window.__fake.accounts()))[0].id;
}

test('a new device sees digits, then can use its kit instead without another password', async ({ page }) => {
  await pending(page);
  await page.evaluate(() => window.__fake.setApprovalDigits('dan@example.com', '482 913'));
  await expect(page.getByText('482 913')).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__fake.calls.filter(c => c.startsWith('approvalStart')).length)).toBe(1);
  await page.getByRole('button', { name: 'Use your recovery kit instead' }).click();
  await page.getByLabel('Recovery kit').fill('AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA');
  await page.getByRole('button', { name: 'Use kit' }).click();
  await expect(page.getByText("That kit doesn't match this account.")).toBeVisible();
  await page.getByLabel('Recovery kit').fill(kit);
  await page.getByRole('button', { name: 'Use kit' }).click();
  await expect(page.getByRole('link', { name: 'Personal' })).toBeVisible();
  expect(await page.evaluate(() => window.__fake.calls.filter(c => c.startsWith('signInStart')))).toHaveLength(1);
});

test('approval wait opens the account after the approving side completes', async ({ page }) => {
  await pending(page);
  await page.evaluate(() => window.__fake.setApprovalDigits('dan@example.com', '482 913'));
  await expect(page.getByText('482 913')).toBeVisible();
  await page.evaluate(() => window.__fake.completeApproval('dan@example.com'));
  await expect(page.getByRole('link', { name: 'Personal' })).toBeVisible();
});

test('the approving device opens a request and types digits shown on the other device', async ({ page }) => {
  const account = await signed(page);
  await page.evaluate(id => {
    window.__fake.addApprovalRequest(id, { id: '11111111111111111111111111111111', deviceId: '22222222222222222222222222222222', createdAt: 0, expiresAt: 120000 });
    window.__fake.emit({ kind: 'account', account: id, event: { ApprovalRequested: { id: '11111111111111111111111111111111', deviceId: '22222222222222222222222222222222', createdAt: 0, expiresAt: 120000 } } });
  }, account);
  await page.getByRole('button', { name: 'Open request' }).click();
  await expect(page.getByText('Type the six digits shown on the new device.')).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__fake.calls.some(c => c.startsWith('approvalOpen')))).toBe(true);
  await page.getByLabel('Digits shown on the new device').fill('482913');
  await page.getByRole('button', { name: 'Approve device' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.calls.filter(c => c.startsWith('approvalApprove')).length)).toBe(1);
  await page.evaluate(id => window.__fake.emit({ kind: 'account', account: id, event: { ApprovalClosed: '11111111111111111111111111111111' } }), account);
  await expect(page.getByRole('button', { name: 'Open request' })).toHaveCount(0);
});

test('ApprovalClosed removes a still-listed request without a local action', async ({ page }) => {
  const account = await signed(page);
  const request = { id: '11111111111111111111111111111111', deviceId: '22222222222222222222222222222222', createdAt: 0, expiresAt: 120000 };
  await page.evaluate(({ account, request }) => window.__fake.addApprovalRequest(account, request), { account, request });
  await page.evaluate(({ account, request }) => window.__fake.emit({ kind: 'account', account, event: { ApprovalRequested: request } }), { account, request });
  await expect(page.getByRole('button', { name: 'Open request' })).toBeVisible();
  await page.evaluate(id => window.__fake.emit({ kind: 'account', account: id, event: { ApprovalClosed: '11111111111111111111111111111111' } }), account);
  await expect(page.getByRole('button', { name: 'Open request' })).toHaveCount(0);
});

for (const [reason, copy] of [
  ['WrongDigits', "The digits didn't match. Run the sign-in again to start over."],
  ['Declined', 'The request was declined.'],
  ['Cancelled', 'The request was cancelled.'],
  ['Expired', 'The request expired after two minutes. Run the sign-in again to start over.'],
  ['AlreadyAnswered', 'Another device is already answering this request.'],
  ['BadMessage', 'The exchange failed. Run the sign-in again to start over.'],
] as const) {
  test(`terminal ${reason} removes waiting digits and offers recovery`, async ({ page }) => {
    await pending(page);
    await page.evaluate(() => window.__fake.setApprovalDigits('dan@example.com', '482 913'));
    await expect(page.getByText('Waiting for approval…')).toBeVisible();
    await page.evaluate(reason => window.__fake.endApproval('dan@example.com', reason), reason);
    await expect(page.getByRole('alert')).toContainText(copy);
    await expect(page.getByText('Waiting for approval…')).toHaveCount(0);
    await expect(page.getByTestId('approval-digits')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Start again' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Use your recovery kit instead' })).toBeVisible();
  });
}

test('a close during the list fetch cannot resurrect the request', async ({ page }) => {
  const request = { id: '11111111111111111111111111111111', deviceId: '22222222222222222222222222222222', createdAt: 0, expiresAt: 120000 };
  const account = await signed(page, async () => {
    await page.evaluate(async request => {
      const fake = window.__fake;
      fake.addApprovalRequest((await fake.accounts())[0].id, request);
      const original = fake.approvalRequests.bind(fake);
      fake.approvalRequests = async id => {
        const snapshot = await original(id);
        await new Promise<void>(resolve => { (window as typeof window & { releaseApprovalList: () => void }).releaseApprovalList = resolve; });
        return snapshot;
      };
    }, request);
  });
  await expect.poll(() => page.evaluate(() => typeof (window as typeof window & { releaseApprovalList?: () => void }).releaseApprovalList)).toBe('function');
  await page.evaluate(({ account, request }) => {
    window.__fake.emit({ kind: 'account', account, event: { ApprovalClosed: request.id } });
    (window as typeof window & { releaseApprovalList: () => void }).releaseApprovalList();
  }, { account, request });
  await expect(page.getByRole('button', { name: 'Open request' })).toHaveCount(0);
});

test('a request arriving while the list fetch is pending remains visible', async ({ page }) => {
  const account = await signed(page, async () => {
    await page.evaluate(() => {
      const fake = window.__fake;
      const original = fake.approvalRequests.bind(fake);
      fake.approvalRequests = async id => {
        const snapshot = await original(id);
        await new Promise<void>(resolve => { (window as typeof window & { releaseApprovalList: () => void }).releaseApprovalList = resolve; });
        return snapshot;
      };
    });
  });
  const request = { id: '11111111111111111111111111111111', deviceId: '22222222222222222222222222222222', createdAt: 0, expiresAt: 120000 };
  await expect.poll(() => page.evaluate(() => typeof (window as typeof window & { releaseApprovalList?: () => void }).releaseApprovalList)).toBe('function');
  await page.evaluate(({ account, request }) => {
    window.__fake.addApprovalRequest(account, request);
    window.__fake.emit({ kind: 'account', account, event: { ApprovalRequested: request } });
    (window as typeof window & { releaseApprovalList: () => void }).releaseApprovalList();
  }, { account, request });
  await expect(page.getByRole('button', { name: 'Open request' })).toBeVisible();
});

test('cancel and decline end the corresponding exchange', async ({ page }) => {
  await pending(page);
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.calls.some(c => c.startsWith('approvalCancel')))).toBe(true);
  const account = await signed(page);
  await page.evaluate(id => {
    const request = { id: '11111111111111111111111111111111', deviceId: '22222222222222222222222222222222', createdAt: 0, expiresAt: 120000 };
    window.__fake.addApprovalRequest(id, request);
    window.__fake.emit({ kind: 'account', account: id, event: { ApprovalRequested: request } });
  }, account);
  await expect(page.getByRole('button', { name: 'Decline request' })).toBeVisible();
  await page.getByRole('button', { name: 'Decline request' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.calls.some(c => c.startsWith('approvalDecline')))).toBe(true);
  await expect(page.getByRole('button', { name: 'Decline request' })).toHaveCount(0);
});
