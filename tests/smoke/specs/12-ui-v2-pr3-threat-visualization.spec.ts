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

test.describe('UI v2 PR3 Threat Visualization', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await login(page);
  });

  test('Dashboard renders read-only Attack Map widget', async ({ page }) => {
    await page.goto('/');
    const threat = page.getByRole('region', { name: 'Threat Visualization' });

    await expect(threat).toBeVisible();
    await expect(threat.getByRole('heading', { name: /Attack Map/i })).toBeVisible();
    await expect(threat.locator('form')).toHaveCount(0);

    const forbidden = [
      'data-dashboard-mutation',
      'data-cloudflare-mutation',
      'data-crowdsec-mutation',
      'cloudflare-delete',
      'crowdsec-delete',
    ];
    const html = await threat.evaluate(el => el.outerHTML);
    for (const token of forbidden) {
      expect(html, `Threat widget must not expose ${token}`).not.toContain(token);
    }
    const hasData = await threat.locator('svg[aria-label="Attack Map country distribution"]').count();
    if (hasData > 0) {
      await expect(threat.getByText('Top Campaigns')).toBeVisible();
    } else {
      await expect(threat.getByText(/No threat visualization data|unavailable/i)).toBeVisible();
    }

    await referenceCapture(page, 'ui-v2-pr3-dashboard-attack-map-widget.png');
  });

  test('Dashboard compact mode keeps Attack Map readable', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: /Compact mode/i }).click();
    await expect(page.locator('body')).toHaveAttribute('data-density', 'compact');
    await expect(page.getByRole('region', { name: 'Threat Visualization' })).toBeVisible();
    await referenceCapture(page, 'ui-v2-pr3-dashboard-attack-map-compact.png');
  });
});
