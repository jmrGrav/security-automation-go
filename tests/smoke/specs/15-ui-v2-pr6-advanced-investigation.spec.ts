import { test, expect, Page } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';
import { login } from '../helpers/session';

const SCREENSHOT_DIR = process.env.SMOKE_SCREENSHOT_DIR || '/tmp/security-automation-smoke';

async function cap(page: Page, name: string): Promise<void> {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
  await page.screenshot({
    path: path.join(SCREENSHOT_DIR, name),
    fullPage: true,
  });
}

test.describe('UI v2 PR6 Advanced Investigation', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await login(page);
  });

  test('Correlated Timeline page renders', async ({ page }) => {
    await page.goto('/v2/timeline/correlated');
    await expect(page.getByRole('heading', { name: /Correlated Timeline/i })).toBeVisible();
    await cap(page, 'ui-v2-pr6-correlated-timeline.png');
  });

  test('Focus Incident page renders for IP', async ({ page }) => {
    await page.goto('/v2/incident?ip=127.0.0.1');
    await expect(page.getByRole('heading', { name: /Focus Incident/i })).toBeVisible();
    await expect(page.locator('a[href*="abuseipdb.com"]')).toBeVisible();
    await cap(page, 'ui-v2-pr6-focus-incident.png');
  });

  test('Notes page renders', async ({ page }) => {
    await page.goto('/v2/notes');
    await expect(page.getByRole('heading', { name: /Operator Notes/i })).toBeVisible();
    await cap(page, 'ui-v2-pr6-notes.png');
  });

  test('Focus Incident has no mutation buttons', async ({ page }) => {
    await page.goto('/v2/incident?ip=127.0.0.1');
    const banBtn = page.getByRole('button', { name: /ban/i });
    await expect(banBtn).not.toBeVisible();
    await cap(page, 'ui-v2-pr6-incident-no-mutations.png');
  });
});
