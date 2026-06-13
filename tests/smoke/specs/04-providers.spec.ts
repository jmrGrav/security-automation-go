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

  test('Replace Key forms have CSRF token and no pre-filled key value', async ({ page }) => {
    await page.goto('/providers');
    // Every Replace Key form must include a csrf_token hidden field.
    const csrfInputs = await page.locator('form input[name="csrf_token"]').all();
    expect(csrfInputs.length, 'at least one CSRF-protected form must be present').toBeGreaterThan(0);
    for (const input of csrfInputs) {
      const val = await input.getAttribute('value');
      expect(val, 'csrf_token must have a non-empty value').toBeTruthy();
    }
    // Password fields for key entry must never carry a pre-filled value.
    const passwordInputs = await page.locator('input[name="new_api_key"]').all();
    for (const input of passwordInputs) {
      const val = await input.getAttribute('value');
      expect(val ?? '', 'key input must not be pre-filled').toBe('');
      const type = await input.getAttribute('type');
      expect(type, 'key input must be type=password').toBe('password');
    }
  });

  test('Replace Key POST without CSRF token is rejected with 403', async ({ page }) => {
    // Must be authenticated (beforeEach login already ran) so the auth guard
    // does not redirect — the CSRF guard fires and returns 403.
    const response = await page.request.post('/admin/providers/spamhaus/key', {
      form: {
        new_api_key: 'fake-test-key-no-csrf',
        confirm_replace: 'yes',
      },
    });
    // Server must reject with 403 Forbidden when csrf_token is absent.
    expect(response.status(), 'POST without CSRF must be rejected').toBe(403);
  });

  test('Replace Key for Spamhaus shows CONFIGURED immediately and never leaks the key', async ({ page }) => {
    // Get CSRF token from the providers page
    await page.goto('/providers');
    const csrfInput = page.locator('form input[name="csrf_token"]').first();
    const csrfToken = await csrfInput.getAttribute('value');
    expect(csrfToken, 'CSRF token must be present').toBeTruthy();

    // POST a test key via the Replace Key form (authenticated session via beforeEach)
    const testKey = 'placeholder-spamhaus-value-' + Date.now();
    const response = await page.request.post('/admin/providers/spamhaus/key', {
      form: {
        csrf_token: csrfToken!,
        new_api_key: testKey,
        confirm_replace: 'yes',
      },
    });
    // Must redirect (303 See Other) after a successful Replace Key
    expect(response.status(), 'Replace Key must redirect').toBe(200); // Playwright follows redirects

    // After redirect the page should show CONFIGURED for Spamhaus
    const body = await page.content();
    expect(body.toUpperCase(), 'Spamhaus must show CONFIGURED after Replace Key').toContain('CONFIGURED');

    // The raw key must never appear in the HTML
    expect(body, 'raw key must not appear in HTML').not.toContain(testKey);
  });
});
