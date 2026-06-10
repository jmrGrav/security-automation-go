import { test, expect } from '@playwright/test';
import { login } from '../helpers/session';
import { assertNoSecretLeakage } from '../helpers/redact';

test.describe('Providers', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('GET /providers returns 200', async ({ page }) => {
    const response = await page.goto('/providers');
    expect(response?.status()).toBe(200);
  });

  test('providers page does not leak any API key', async ({ page }) => {
    await page.goto('/providers');
    const body = await page.content();
    assertNoSecretLeakage(body, '/providers');
    // Keys must be masked — the word "masked" or "•" indicates redaction.
    // If any provider is configured we should see configured/enabled status, not raw tokens.
    const dangerPatterns = [/cfut_/, /sk-/, /AIza/, /cs_/];
    for (const pattern of dangerPatterns) {
      expect(body, `provider page must not contain raw key matching ${pattern}`).not.toMatch(pattern);
    }
  });

  test('provider status values are meaningful (not blank)', async ({ page }) => {
    await page.goto('/providers');
    const body = await page.content();
    // At minimum, the page should tell us something about provider state.
    const meaningfulStrings = ['configured', 'missing', 'enabled', 'disabled', 'not configured'];
    const hasMeaning = meaningfulStrings.some(s => body.toLowerCase().includes(s));
    expect(hasMeaning, 'providers page must show at least one status value').toBe(true);
  });
});
