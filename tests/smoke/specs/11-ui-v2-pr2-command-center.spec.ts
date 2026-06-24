import { test, expect, Page } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';
import { login } from '../helpers/session';

const SCREENSHOT_DIR = process.env.SMOKE_SCREENSHOT_DIR || '/tmp/security-automation-smoke';

async function referenceCapture(page: Page, name: string): Promise<void> {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
  await page.screenshot({
    path: path.join(SCREENSHOT_DIR, name),
    fullPage: true,
  });
}

test.describe('UI v2 PR2 SOC Command Center', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await login(page);
  });

  test('Dashboard renders SOC command center and command palette', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText('Security Command Center')).toBeVisible();
    await expect(page.getByText('Health Score')).toBeVisible();
    await expect(page.getByText('Universal Search')).toBeVisible();
    await expect(page.getByText('Live Activity Feed')).toBeVisible();
    await referenceCapture(page, 'ui-v2-pr2-dashboard-command-center-default.png');

    await page.keyboard.press(process.platform === 'darwin' ? 'Meta+K' : 'Control+K');
    await expect(page.locator('[data-command-palette-root="true"]')).toHaveClass(/open/);
    await referenceCapture(page, 'ui-v2-pr2-command-palette-open.png');
  });

  test('Dashboard compact mode remains usable', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: /Compact mode/i }).click();
    await expect(page.locator('body')).toHaveAttribute('data-density', 'compact');
    await expect(page.getByText('Security Command Center')).toBeVisible();
    await referenceCapture(page, 'ui-v2-pr2-dashboard-command-center-compact.png');
  });
});
