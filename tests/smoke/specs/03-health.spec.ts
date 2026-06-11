import { test, expect } from '@playwright/test';
import { login } from '../helpers/session';
import { assertNoSecretLeakage } from '../helpers/redact';

test.describe('Health Center', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('GET /health returns 200 and renders a health page', async ({ page }) => {
    const response = await page.goto('/health');
    expect(response?.status()).toBe(200);
    const body = await page.content();
    assertNoSecretLeakage(body, '/health');
    expect(body).not.toContain('panic:');
  });

  test('GET /health/json returns valid JSON', async ({ page }) => {
    const response = await page.goto('/health/json');
    expect(response?.status()).toBe(200);
    const body = await response!.text();
    // Must be parseable JSON.
    const parsed = JSON.parse(body);
    expect(parsed).toBeDefined();
    // Must contain some health keys — not just an empty object.
    const keys = Object.keys(parsed);
    expect(keys.length, 'health JSON must contain status entries').toBeGreaterThan(0);
  });

  test('health page does not leak any API token or key', async ({ page }) => {
    await page.goto('/health');
    const body = await page.content();
    assertNoSecretLeakage(body, '/health');
  });

  test('health shows Cloudflare status — not contradicted by Dashboard', async ({ page }) => {
    const healthResp = await page.goto('/health/json').then(r => r?.text());
    const dashboardResp = await page.goto('/').then(() => page.content());

    const health = JSON.parse(healthResp ?? '{}');
    const cfHealthConfigured = JSON.stringify(health).toLowerCase().includes('cloudflare');

    // If health says Cloudflare is mentioned at all, dashboard must also show it.
    if (cfHealthConfigured) {
      expect(dashboardResp ?? '', 'Dashboard must mention Cloudflare if Health does').toContain('Cloudflare');
    }
  });
});
