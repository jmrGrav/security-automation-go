import { test, expect } from '@playwright/test';
import { login } from '../helpers/session';
import { assertNoSecretLeakage } from '../helpers/redact';

// Gate for specs that mutate provider credentials. SECURITY_AUTOMATION_SMOKE_LIVE=1
// only confirms "this is a reachable live server" — on an operator box that's
// frequently the real production instance at :9091, and a mutating spec run there
// would silently overwrite a real provider key with a disposable placeholder with
// no way to recover it. SMOKE_ALLOW_MUTATIONS=1 is a separate, explicit opt-in that
// the operator must set only when pointed at a disposable/isolated instance.
const ALLOW_MUTATIONS = process.env.SMOKE_ALLOW_MUTATIONS === '1';

test.describe('Providers', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('GET /providers returns 200', async ({ page }) => {
    const response = await page.goto('/v2/providers');
    expect(response?.status()).toBe(200);
  });

  test('providers page does not leak any API key', async ({ page }) => {
    await page.goto('/v2/providers');
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
    await page.goto('/v2/providers');
    const body = await page.content();
    // At minimum, the page should tell us something about provider state.
    const meaningfulStrings = ['configured', 'missing', 'enabled', 'disabled', 'not configured'];
    const hasMeaning = meaningfulStrings.some(s => body.toLowerCase().includes(s));
    expect(hasMeaning, 'providers page must show at least one status value').toBe(true);
  });

  test('provider action rail stays readable and buttons stay large', async ({ page }) => {
    await page.goto('/v2/providers');
    const actionRail = page.locator('.provider-actions').first();
    await expect(actionRail).toBeVisible();

    const updateKey = page.getByRole('button', { name: /Update Key/i }).first();
    await expect(updateKey).toBeVisible();

    const testButton = page.getByRole('button', { name: /Test Now/i }).first();
    await expect(testButton).toBeVisible();

    const minHeight = await testButton.evaluate(el => {
      const value = getComputedStyle(el).minHeight;
      return Number.parseFloat(value || '0');
    });
    expect(minHeight, 'provider action buttons should be visibly larger').toBeGreaterThanOrEqual(40);
  });

  test('Replace Key forms have CSRF token and no pre-filled key value', async ({ page }) => {
    await page.goto('/v2/providers');
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
    // Use the browser session so the auth cookie is present. The request still
    // omits csrf_token, so the server must reject it with 403.
    const status = await page.evaluate(async () => {
      const response = await fetch('/admin/providers/spamhaus/key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'new_api_key=fake-test-key-no-csrf&confirm_replace=yes',
      });
      return response.status;
    });
    expect(status, 'POST without CSRF must be rejected').toBe(403);
  });

  test('Replace Key for Spamhaus shows CONFIGURED immediately and never leaks the key', async ({ page }) => {
    if (!ALLOW_MUTATIONS) {
      test.skip(true, 'Set SMOKE_ALLOW_MUTATIONS=1 to run this mutating spec against a disposable instance — it overwrites the live Spamhaus key with a placeholder and the original cannot be recovered');
      return;
    }
    // Get CSRF token from the providers page
    await page.goto('/v2/providers');
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
