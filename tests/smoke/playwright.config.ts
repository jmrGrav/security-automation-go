import { defineConfig, devices } from '@playwright/test';

// Hard gate: refuse to run without explicit opt-in.
if (!process.env.SECURITY_AUTOMATION_SMOKE_LIVE) {
  console.error('\n[SMOKE] SECURITY_AUTOMATION_SMOKE_LIVE=1 is required to run smoke tests.');
  console.error('[SMOKE] These tests connect to a running local instance with real credentials.');
  console.error('[SMOKE] Set the variable explicitly to confirm you intend to run live tests.\n');
  process.exit(1);
}

const BASE_URL = process.env.SMOKE_UI_URL || 'http://127.0.0.1:9091';
const SCREENSHOT_DIR = process.env.SMOKE_SCREENSHOT_DIR || '/tmp/security-automation-smoke';

export default defineConfig({
  testDir: './specs',
  globalSetup: './global-setup',
  timeout: 30_000,
  retries: 0,
  workers: 1,

  use: {
    baseURL: BASE_URL,
    // Re-use the session saved by globalSetup to avoid hitting the login rate limiter.
    storageState: process.env.SMOKE_ADMIN_PASSWORD ? '.auth/user.json' : undefined,
    // Screenshots only on failure — stored locally, never committed.
    screenshot: 'only-on-failure',
    screenshotPath: SCREENSHOT_DIR,
    video: 'off',
    trace: 'off',
    // Ignore certificate errors for local self-signed certs.
    ignoreHTTPSErrors: true,
  },

  reporter: [
    ['list'],
    ['json', { outputFile: '/tmp/security-automation-smoke/results.json' }],
  ],

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], channel: 'chromium' },
    },
  ],
});
