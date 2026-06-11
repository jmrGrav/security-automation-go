import { chromium } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Global setup: logs in once and saves the session to .auth/user.json.
 * All tests then start with storageState pre-loaded, so login() in beforeEach
 * hits the redirect branch (already authenticated) and makes no POST /login.
 * This keeps the total login POSTs to 1 per test run, staying well under the
 * server-side rate limit of 20/min.
 */
async function globalSetup(): Promise<void> {
  const password = process.env.SMOKE_ADMIN_PASSWORD;
  if (!password) return;

  const baseURL = process.env.SMOKE_UI_URL ?? 'http://127.0.0.1:9091';
  const authDir = path.join(__dirname, '.auth');
  fs.mkdirSync(authDir, { recursive: true });

  const browser = await chromium.launch();
  const page = await browser.newPage();
  page.setDefaultTimeout(15_000);

  await page.goto(`${baseURL}/login`);
  await page.fill('#password', password);
  await page.click('button[type="submit"]');
  await page.waitForURL(`${baseURL}/`);

  await page.context().storageState({ path: path.join(authDir, 'user.json') });
  await browser.close();
}

export default globalSetup;
