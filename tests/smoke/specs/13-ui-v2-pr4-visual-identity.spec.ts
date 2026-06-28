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

test.describe('UI v2 PR4 Visual Identity and Design System', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await login(page);
  });

  test('Dashboard supports light comfort, dark operations, and compact visual profiles', async ({ page }) => {
    await page.goto('/');

    await expect(page.getByRole('heading', { name: 'Security Command Center', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: /Dark operations/i })).toBeVisible();
    await referenceCapture(page, 'ui-v2-pr4-dashboard-light-comfort.png');

    await page.getByRole('button', { name: /Dark operations/i }).click();
    await expect(page.locator('body')).toHaveAttribute('data-theme', 'operations-dark');
    await expect(page.getByRole('button', { name: /Comfort light/i })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Threat Visualization' })).toBeVisible();
    await referenceCapture(page, 'ui-v2-pr4-dashboard-dark-operations.png');

    await page.getByRole('button', { name: /Compact mode/i }).click();
    await expect(page.locator('body')).toHaveAttribute('data-density', 'compact');
    await expect(page.getByRole('heading', { name: 'Security Command Center', exact: true })).toBeVisible();
    await referenceCapture(page, 'ui-v2-pr4-compact-mode.png');
  });

  test('Timeline and Attack Map retain readable dark operations treatment', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: /Dark operations/i }).click();
    await expect(page.locator('body')).toHaveAttribute('data-theme', 'operations-dark');
    await expect(page.getByRole('region', { name: 'Threat Visualization' })).toBeVisible();
    await referenceCapture(page, 'ui-v2-pr4-attack-map-dark-operations.png');

    await page.goto('/v2/timeline');
    await expect(page.locator('body')).toHaveAttribute('data-theme', 'operations-dark');
    await expect(page.getByRole('heading', { name: /Timeline/i })).toBeVisible();
    await referenceCapture(page, 'ui-v2-pr4-timeline-dark-operations.png');

    await page.getByRole('button', { name: /Compact mode/i }).click();
    await expect(page.locator('body')).toHaveAttribute('data-density', 'compact');
    await referenceCapture(page, 'ui-v2-pr4-timeline-dark-compact.png');
  });

  test('Empty and degraded states remain explicit in the visual system', async ({ page }) => {
    await page.goto('/v2/timeline?q=__ui_v2_pr4_empty_state_fixture__');
    await expect(page.getByText(/No matching timeline events/i)).toBeVisible();
    await referenceCapture(page, 'ui-v2-pr4-empty-degraded-state.png');
  });
});
