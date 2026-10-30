import { expect, test, type Page } from '@playwright/test';

const folder = { kind: 'path' as const, path: '/backups', label: 'USB Drive › BaseHero' };
const phoneFolder = { kind: 'document' as const, uri: 'content://drive', label: 'Google Drive' };

async function account(page: Page, platform = 'macos') {
  await page.goto(`/?platform=${platform}`);
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Create account' }).click();
  const kit = await page.evaluate(() => window.__fake.accounts().then(() => '7KQ2-M9XD-4F8P-2L6R-V3TN-H5YA-ZC'));
  await page.getByRole('button', { name: 'Later' }).click();
  return { id: await page.evaluate(() => window.__fake.accounts().then(rows => rows[0].id)), kit };
}

test('a new Mac account shows the backup card until OK', async ({ page }) => {
  const { id } = await account(page);
  await expect(page.getByText("BaseHero keeps an encrypted backup in iCloud Drive › BaseHero. It opens with your password and recovery kit, even without BaseHero's servers.")).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save your kit' })).toBeVisible();
  await page.getByRole('button', { name: 'OK', exact: true }).click();
  await expect(page.getByText(/BaseHero keeps an encrypted backup/)).toHaveCount(0);
  expect((await page.evaluate(id => window.__fake.backupStatus(id), id)).acknowledged).toBe(true);
});

test('change folder schedules a fresh backup and dismisses the Mac card', async ({ page }) => {
  const { id } = await account(page);
  await page.evaluate(folder => window.__fake.setPickedBackupFolder(folder), folder);
  await page.getByRole('button', { name: 'Change folder…' }).first().click();
  await expect.poll(() => page.evaluate(() => window.__fake.calls.some(call => call.startsWith('setBackup')))).toBe(true);
  expect(await page.evaluate(() => window.__fake.calls.some(call => call.startsWith('backupNow')))).toBe(false);
  await expect(page.getByText(/BaseHero keeps an encrypted backup/)).toHaveCount(0);
  const status = await page.evaluate(id => window.__fake.backupStatus(id), id);
  expect(status.location?.label).toBe(folder.label);
  expect(status.acknowledged).toBe(true);
});

test('an unacknowledged Mac backup card is shown even when backup is off', async ({ page }) => {
  const { id } = await account(page);
  await page.evaluate(id => {
    const status = window.__fake['backupStatuses'].get(id)!;
    window.__fake['backupStatuses'].set(id, { ...status, enabled: false, acknowledged: false });
  }, id);
  await page.getByRole('link', { name: 'Backup' }).click();
  await page.getByRole('link', { name: 'BaseHero' }).click();
  await expect(page.getByRole('region', { name: 'Your backup' })).toBeVisible();
});

test('the status line names each problem and its action', async ({ page }) => {
  const { id } = await account(page);
  await page.getByRole('button', { name: 'OK', exact: true }).click();
  for (const [kind, message] of [
    ['unreachable', "Backup paused: can't reach USB Drive › BaseHero. Last backup 3 days ago."],
    ['permissionLost', 'Choose the backup folder again.'],
    ['full', 'Backup paused: USB Drive is full.'],
    ['usingLastChecked', 'Backup is using the sign-in details it last confirmed.'],
    ['noKitRecord', 'Make a new recovery kit so your backup can be checked.'],
  ] as const) {
    await page.evaluate(({ id, kind, folder }) => {
      window.__fake['backupStatuses'].set(id, { enabled: true, acknowledged: true, location: folder, lastRunAt: Date.now() - 3 * 86400000, bytes: 1400000000, problem: { kind }, stale: false });
    }, { id, kind, folder });
    await page.getByRole('link', { name: 'Backup' }).click();
    await expect(page.locator('main')).toContainText(message);
    if (kind === 'noKitRecord') {
      await page.locator('main').getByRole('button', { name: 'Make a new kit' }).click();
      await expect(page.getByRole('heading', { name: 'Devices' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Make kit', exact: true })).toBeVisible();
    } else if (kind === 'permissionLost') await expect(page.getByRole('button', { name: 'Change folder…' })).toBeVisible();
    else if (kind === 'usingLastChecked') await expect(page.locator('main').getByRole('button', { name: 'Make a new kit' })).toHaveCount(0);
    await page.getByRole('link', { name: 'Devices' }).click();
  }
});

test('a stale backup shows under the sidebar', async ({ page }) => {
  const { id } = await account(page);
  await page.getByRole('button', { name: 'OK', exact: true }).click();
  await page.evaluate(({ id, folder }) => window.__fake['backupStatuses'].set(id, { enabled: true, acknowledged: true, location: folder, lastRunAt: Date.now() - 8 * 86400000, bytes: 1400000000, problem: null, stale: true }), { id, folder });
  await page.getByRole('link', { name: 'Backup' }).click();
  await page.getByRole('link', { name: 'Personal' }).click();
  await expect(page.locator('nav').getByText(/Backed up 8 days ago/)).toBeVisible();
});

test('a small phone backup estimate uses the status line units', async ({ page }) => {
  await account(page, 'android');
  await page.evaluate(folder => {
    window.__fake.setPickedBackupFolder(folder);
    window.__fake.backupEstimate = async () => 512;
  }, phoneFolder);
  await page.getByRole('link', { name: 'Backup' }).click();
  await page.getByRole('button', { name: 'Back up to a folder…' }).click();
  await expect(page.getByText('This will write about 512 bytes to Google Drive')).toBeVisible();
});

test('the phone folder hint sits inside the backup panel', async ({ page }) => {
  await account(page, 'android');
  await page.getByRole('link', { name: 'Backup' }).click();
  const panel = page.locator('main section.panel');
  await expect(panel.getByText('Choose a folder, perhaps one named BaseHero, on your phone or drive.')).toBeVisible();
});

test('a phone turns backup on after seeing how much it will write', async ({ page }) => {
  const { id } = await account(page, 'android');
  await page.evaluate(folder => window.__fake.setPickedBackupFolder(folder), phoneFolder);
  await page.getByRole('link', { name: 'Backup' }).click();
  await page.getByRole('button', { name: 'Back up to a folder…' }).click();
  await expect(page.getByText('This will write about 1.4 GB to Google Drive')).toBeVisible();
  expect((await page.evaluate(id => window.__fake.backupStatus(id), id)).enabled).toBe(false);
  await page.getByRole('button', { name: 'Start' }).click();
  await expect(page.locator('main')).toContainText('Google Drive');
  expect((await page.evaluate(id => window.__fake.backupStatus(id), id)).enabled).toBe(true);
  await page.evaluate(folder => window.__fake.setPickedBackupFolder(folder), { ...phoneFolder, label: 'New Drive' });
  await page.getByRole('button', { name: 'Change folder…' }).click();
  await expect(page.getByText('This will write about 1.4 GB to New Drive')).toBeVisible();
  expect((await page.evaluate(id => window.__fake.backupStatus(id), id)).location?.label).toBe('Google Drive');
  await page.getByRole('button', { name: 'Cancel' }).click();
  await page.getByRole('button', { name: 'Off' }).click();
  const off = await page.evaluate(id => window.__fake.backupStatus(id), id);
  expect(off.enabled).toBe(false);
  expect(off.location?.label).toBe('Google Drive');
});

async function createBackup(page: Page) {
  const { id, kit } = await account(page);
  await page.evaluate(async ({ id, folder }) => { await window.__fake.createBase(id, 'Personal'); await window.__fake.setBackup(id, folder); await window.__fake.backupNow(id); await window.__fake.backupNow(id); }, { id, folder });
  await page.getByRole('link', { name: 'Backup' }).click();
  await page.getByRole('button', { name: 'Restore…' }).click();
  await page.evaluate(folder => window.__fake.setPickedBackupFolder(folder), folder);
  await page.getByRole('button', { name: 'Pick folder…' }).click();
  await page.getByRole('button', { name: /dan@example.com/ }).click();
  return { id, kit };
}

test('backup listings and points in time show the date and time without seconds', async ({ page }) => {
  const { id, kit } = await account(page);
  await page.evaluate(async ({ id, folder }) => {
    await window.__fake.createBase(id, 'Personal');
    await window.__fake.setBackup(id, folder);
    await window.__fake.backupNow(id);
    const original = window.__fake.restoreList.bind(window.__fake);
    window.__fake.restoreList = async (...args) => (await original(...args)).map(item => ({ ...item, writtenAt: new Date(2026, 9, 29, 22, 24, 23).getTime() }));
  }, { id, folder });
  await page.getByRole('link', { name: 'Backup' }).click();
  await page.getByRole('button', { name: 'Restore…' }).click();
  await page.evaluate(folder => window.__fake.setPickedBackupFolder(folder), folder);
  await page.getByRole('button', { name: 'Pick folder…' }).click();
  await expect(page.getByRole('button', { name: /dan@example.com/ })).toContainText(/Oct 29, 2026,? (at )?10:24\s?PM/);
  await page.getByRole('button', { name: /dan@example.com/ }).click();
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByLabel('Recovery kit').fill(kit);
  await page.getByRole('button', { name: 'Open backup' }).click();
  await expect(page.getByLabel('Point in time').locator('option')).toHaveText([/^[A-Z][a-z]{2} [0-9]{1,2}, [0-9]{4},? (at )?[0-9]{1,2}:[0-9]{2}\s?[AP]M$/]);
});

test('restore base counts use singular for one and plural for two', async ({ page }) => {
  const { kit } = await createBackup(page);
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByLabel('Recovery kit').fill(kit);
  await page.getByRole('button', { name: 'Open backup' }).click();
  await expect(page.getByText('1 note · 0 records · 0 files')).toBeVisible();
  await expect(page.getByText("1 record couldn't be opened or applied")).toBeVisible();
  await page.evaluate(() => {
    const original = window.__fake.restoreBases.bind(window.__fake);
    window.__fake.restoreBases = async (...args) => (await original(...args)).map(base => ({ ...base, notes: 2, records: 2, files: 2 }));
  });
  await page.getByLabel('Point in time').selectOption({ index: 1 });
  await expect(page.getByText('2 notes · 2 records · 2 files')).toBeVisible();
  await page.getByLabel('Extra password').fill('hidden password');
  await page.getByRole('button', { name: 'Open bases' }).click();
  await expect(page.getByText('1 missing file.')).toBeVisible();
});

test('restore into this account picks a point, opens a hidden base and reports a missing file', async ({ page }) => {
  const { kit } = await createBackup(page);
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByLabel('Recovery kit').fill(kit);
  await page.getByRole('button', { name: 'Open backup' }).click();
  await expect(page.getByLabel('Point in time').locator('option')).toHaveCount(2);
  await page.getByLabel('Point in time').selectOption({ index: 1 });
  await expect(page.getByText('1 base needs its extra password')).toBeVisible();
  await expect(page.getByText("1 record couldn't be opened or applied")).toBeVisible();
  await expect(page.getByText('Private')).toHaveCount(0);
  await page.getByLabel('Extra password').fill('hidden password');
  await page.getByRole('button', { name: 'Open bases' }).click();
  await expect(page.getByText('Private', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Restore selected' }).click();
  await expect(page.getByText("1 record couldn't be opened or applied")).toBeVisible();
  await expect(page.getByText('1 missing file.')).toBeVisible();
  await expect(page.getByText(/skipped/)).toHaveCount(0);
  await expect(page.getByText(/Private \(restored/)).toBeVisible();
});

test('restore from the sign-in screen signs up and restores every base', async ({ page }) => {
  const { kit } = await createBackup(page);
  await page.evaluate(() => {
    const original = window.__fake.restoreList.bind(window.__fake);
    window.__fake.restoreList = async (...args) => (await original(...args)).map(item => ({ ...item, server: 'https://old.example.test/' }));
  });
  await page.getByRole('button', { name: 'Cancel restore' }).click();
  await page.getByRole('link', { name: 'Devices' }).click();
  page.once('dialog', dialog => void dialog.accept());
  await page.getByRole('button', { name: 'Remove' }).click();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('button', { name: 'Restore from a backup' }).click();
  await page.getByRole('button', { name: 'Pick folder…' }).click();
  await page.getByRole('button', { name: /dan@example.com/ }).click();
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByLabel('Recovery kit').fill(kit);
  await page.getByRole('button', { name: 'Open backup' }).click();
  await page.getByLabel('Extra password').fill('hidden password');
  await page.getByRole('button', { name: 'Open bases' }).click();
  await page.getByRole('button', { name: 'Continue to sign up' }).click();
  await expect(page.getByLabel('Server')).toHaveValue('https://dev-api.basehero.com');
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('new@example.com');
  await page.getByLabel('New password').fill('new correct horse battery staple');
  await page.getByRole('button', { name: 'Sign up and restore' }).click();
  await expect(page.getByText(/Restored Personal \(restored \d{1,2} [A-Z][a-z]{2}\), Private \(restored \d{1,2} [A-Z][a-z]{2}\)\./)).toBeVisible();
  expect(await page.evaluate(() => window.__fake.calls.includes('restoreSignUp'))).toBe(true);
  await page.getByRole('button', { name: 'Done' }).click();
  await expect(page.getByRole('heading', { name: 'Your recovery kit' })).toBeVisible();
  expect(await page.evaluate(async () => {
    const accounts = await window.__fake.accounts();
    return (await window.__fake.bases(accounts[0].id)).map(base => base.name);
  })).toEqual(expect.arrayContaining([expect.stringMatching(/^Personal \(restored \d{1,2} [A-Z][a-z]{2}\)$/), expect.stringMatching(/^Private \(restored \d{1,2} [A-Z][a-z]{2}\)$/)]));
});

test('a failed new-account restore shows the kit and offers a retry from Backup', async ({ page }) => {
  const { kit } = await createBackup(page);
  await page.getByRole('button', { name: 'Cancel restore' }).click();
  await page.getByRole('link', { name: 'Devices' }).click();
  page.once('dialog', dialog => void dialog.accept());
  await page.getByRole('button', { name: 'Remove' }).click();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('button', { name: 'Restore from a backup' }).click();
  await page.getByRole('button', { name: 'Pick folder…' }).click();
  await page.getByRole('button', { name: /dan@example.com/ }).click();
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByLabel('Recovery kit').fill(kit);
  await page.getByRole('button', { name: 'Open backup' }).click();
  await page.getByRole('button', { name: 'Continue to sign up' }).click();
  await page.evaluate(() => { window.__fake.restoreInto = async () => { throw new Error('Storage full'); }; });
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('new@example.com');
  await page.getByLabel('New password').fill('new correct horse battery staple');
  await page.getByRole('button', { name: 'Sign up and restore' }).click();
  await expect(page.getByRole('alert')).toContainText("The restore didn't finish: Storage full. You can restore again from Backup.");
  await expect(page.getByText('Your recovery kit:')).toContainText('7KQ2-M9XD');
  await page.getByRole('button', { name: 'Done' }).click();
  await expect(page.getByRole('heading', { name: 'Your recovery kit' })).toBeVisible();
});

test('cancel during backup open closes the late handle', async ({ page }) => {
  const { kit } = await createBackup(page);
  await page.evaluate(() => {
    const original = window.__fake.restoreOpen.bind(window.__fake);
    window.__fake.restoreOpen = async (...args) => {
      const handle = await original(...args);
      await new Promise<void>(resolve => { (window as Window & { releaseRestoreOpen: () => void }).releaseRestoreOpen = resolve; });
      return handle;
    };
  });
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByLabel('Recovery kit').fill(kit);
  await page.getByRole('button', { name: 'Open backup' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.openRestoreCount())).toBe(1);
  await page.getByRole('button', { name: 'Cancel restore' }).click();
  await page.evaluate(() => (window as Window & { releaseRestoreOpen: () => void }).releaseRestoreOpen());
  await expect.poll(() => page.evaluate(() => window.__fake.openRestoreCount())).toBe(0);
});

test('a failed point load can be retried without leaving an old handle open', async ({ page }) => {
  const { kit } = await createBackup(page);
  await page.evaluate(() => {
    const original = window.__fake.restorePoints.bind(window.__fake);
    let fail = true;
    window.__fake.restorePoints = async (...args) => {
      if (fail) { fail = false; throw new Error('Cannot load points'); }
      return original(...args);
    };
  });
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByLabel('Recovery kit').fill(kit);
  await page.getByRole('button', { name: 'Open backup' }).click();
  await expect(page.getByRole('alert')).toHaveText("Can't reach BaseHero. Check your connection.");
  await page.getByRole('button', { name: 'Open backup' }).click();
  await expect(page.getByLabel('Point in time')).toBeVisible();
  expect(await page.evaluate(() => window.__fake.openRestoreCount())).toBe(1);
  await page.getByRole('button', { name: 'Cancel restore' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.openRestoreCount())).toBe(0);
});

test('a failed base load can be retried without leaving an old handle open', async ({ page }) => {
  const { kit } = await createBackup(page);
  await page.evaluate(() => {
    const original = window.__fake.restoreBases.bind(window.__fake);
    let fail = true;
    window.__fake.restoreBases = async (...args) => {
      if (fail) { fail = false; throw new Error('Cannot load bases'); }
      return original(...args);
    };
  });
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByLabel('Recovery kit').fill(kit);
  await page.getByRole('button', { name: 'Open backup' }).click();
  await expect(page.getByRole('alert')).toHaveText("Can't reach BaseHero. Check your connection.");
  await page.getByRole('button', { name: 'Open backup' }).click();
  await expect(page.getByLabel('Point in time')).toBeVisible();
  expect(await page.evaluate(() => window.__fake.openRestoreCount())).toBe(1);
  await page.getByRole('button', { name: 'Cancel restore' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.openRestoreCount())).toBe(0);
});

test('a wrong password or kit says so and keeps the form', async ({ page }) => {
  await createBackup(page);
  await page.getByLabel('Password').fill('wrong');
  await page.getByLabel('Recovery kit').fill('wrong kit');
  await page.getByRole('button', { name: 'Open backup' }).click();
  await expect(page.getByRole('alert')).toHaveText('Wrong password or recovery kit');
  await expect(page.getByLabel('Password')).toBeVisible();
});
