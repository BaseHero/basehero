import { defineConfig, devices } from '@playwright/test';
import { assertPatchedYjs } from './scripts/patch-yjs.mjs';

assertPatchedYjs();

const port = process.env.BH_TEST_PORT ?? process.env.BH_PLAYWRIGHT_PORT ?? '5173';
const url = `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: './tests/ui',
  use: { baseURL: url },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
  webServer: { command: `node scripts/patch-yjs.mjs && npx vite --mode fake --host 127.0.0.1 --port ${port} --strictPort`, url, reuseExistingServer: false },
});
