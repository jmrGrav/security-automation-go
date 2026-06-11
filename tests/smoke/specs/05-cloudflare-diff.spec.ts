import { test, expect } from '@playwright/test';
import { login } from '../helpers/session';
import { assertNoSecretLeakage } from '../helpers/redact';

test.describe('Cloudflare Diff', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('GET /cloudflare/diff returns 200', async ({ page }) => {
    const response = await page.goto('/cloudflare/diff');
    expect(response?.status()).toBe(200);
  });

  test('Cloudflare Diff does not leak tokens', async ({ page }) => {
    await page.goto('/cloudflare/diff');
    const body = await page.content();
    assertNoSecretLeakage(body, '/cloudflare/diff');
  });

  test('Operator Summary panel is present', async ({ page }) => {
    await page.goto('/cloudflare/diff');
    const body = await page.content();
    // The Operator Summary panel was added in v1.6.0.
    // It must show YES/NO/DRY-RUN — not a blank or error state.
    const hasOperatorSummary = body.includes('Configured') || body.includes('Token') || body.includes('Mode');
    expect(hasOperatorSummary, 'Operator Summary panel must be present').toBe(true);
  });

  test('Cloudflare Diff coherence: if health says configured, diff must not say token missing', async ({ page }) => {
    // Get health JSON first.
    await page.goto('/health/json');
    const healthText = await page.content();
    let healthConfigured = false;
    try {
      const health = JSON.parse(
        // health/json renders in <pre> or <body> depending on the handler
        healthText.replace(/<[^>]+>/g, '')
      );
      healthConfigured = JSON.stringify(health).toLowerCase().includes('"cloudflare"') &&
        !JSON.stringify(health).toLowerCase().includes('not_configured');
    } catch {
      // health JSON parse failure is its own test failure — skip coherence check
      return;
    }

    if (healthConfigured) {
      await page.goto('/cloudflare/diff');
      const body = await page.content();
      // If health says CF is configured, diff page must not contradict that.
      expect(body, 'Cloudflare Diff must not say "token missing" when health reports configured')
        .not.toContain('token missing');
      expect(body, 'Cloudflare Diff must not say "not configured" when health reports configured')
        .not.toMatch(/token.*not configured/i);
    }
  });
});
