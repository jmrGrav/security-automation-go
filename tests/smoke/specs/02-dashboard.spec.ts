import { test, expect } from '@playwright/test';
import { login } from '../helpers/session';
import { assertNoSecretLeakage } from '../helpers/redact';

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('dashboard renders with runtime status panel', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('h2, h1').first()).toBeVisible();
    const body = await page.content();
    assertNoSecretLeakage(body, 'dashboard');
    // Must show some runtime status — not a blank page.
    expect(body).toContain('CrowdSec');
    expect(body).toContain('Cloudflare');
  });

  test('dashboard contains sidebar navigation', async ({ page }) => {
    await page.goto('/');
    const body = await page.content();
    // Core nav items must be present.
    for (const item of ['Health', 'Providers', 'Forensic', 'Trusted Networks']) {
      expect(body, `sidebar must contain "${item}"`).toContain(item);
    }
  });

  test('dashboard does not show any JS console errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') errors.push(msg.text());
    });
    page.on('pageerror', err => errors.push(err.message));
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    expect(errors, `JS errors on dashboard: ${errors.join(', ')}`).toHaveLength(0);
  });

  test('dashboard does not show raw error stack traces', async ({ page }) => {
    await page.goto('/');
    const body = await page.content();
    const forbidden = ['panic:', 'goroutine', 'runtime error', 'UNKNOWN_ERROR'];
    for (const pattern of forbidden) {
      expect(body, `dashboard must not contain "${pattern}"`).not.toContain(pattern);
    }
  });
});
