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

test.describe('UI v2 PR1 performance and ergonomics baseline', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await login(page);
  });

  test('Timeline supports compact mode and persistent collapsible panels', async ({ page }) => {
    await page.goto('/v2/timeline');

    const firstRow = page.locator('tbody tr').first();
    const hasRows = await firstRow.count() > 0;
    const defaultBox = hasRows ? await firstRow.boundingBox() : null;
    await referenceCapture(page, 'ui-v2-pr1-timeline-default.png');

    await page.getByRole('button', { name: /Compact mode/i }).click();
    await expect(page.locator('body')).toHaveAttribute('data-density', 'compact');
    await referenceCapture(page, 'ui-v2-pr1-timeline-compact.png');

    if (defaultBox) {
      const compactBox = await firstRow.boundingBox();
      expect(compactBox?.height ?? defaultBox.height, 'compact row height should allow at least 25% more visible rows').toBeLessThanOrEqual(defaultBox.height * 0.8);
    }

    const panel = page.locator('[data-collapsible-key="timeline-read-model"]').first();
    await expect(panel).toBeVisible();
    await panel.locator('[data-collapsible-toggle="true"]').click();
    await expect(panel).toHaveAttribute('data-collapsed', 'true');
    await referenceCapture(page, 'ui-v2-pr1-timeline-collapsed.png');

    await page.goto('/v2/health');
    await page.goto('/v2/timeline');
    await expect(page.locator('[data-collapsible-key="timeline-read-model"]').first()).toHaveAttribute('data-collapsed', 'true');
  });
});
