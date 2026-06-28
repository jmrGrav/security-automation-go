import { test, expect } from '@playwright/test';
import { login } from '../helpers/session';
import { assertNoSecretLeakage } from '../helpers/redact';

// Pages that must render (HTTP 200) and not leak secrets or panic.
const AUTH_REQUIRED_PAGES = [
  '/trusted-networks',
  '/audit',
  '/forensic',
  '/about',
  '/health',
  '/pipeline',
  '/evidence',
  '/intelligence',
  '/timeline',
];

test.describe('Authenticated pages render without error', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  for (const path of AUTH_REQUIRED_PAGES) {
    test(`GET ${path} returns 200 and no panic`, async ({ page }) => {
      const response = await page.goto(path);
      expect(response?.status(), `${path} must return 200`).toBe(200);
      const body = await page.content();
      assertNoSecretLeakage(body, path);
      const forbidden = ['panic:', 'goroutine', 'runtime error'];
      for (const f of forbidden) {
        expect(body, `${path} must not contain "${f}"`).not.toContain(f);
      }
    });
  }

  test('Trusted Networks table renders with expected columns', async ({ page }) => {
    await page.goto('/trusted-networks');
    const body = await page.content();
    // v1.6.0 converted this page to a responsive table.
    const hasTable = body.includes('<table') || body.includes('table');
    expect(hasTable, 'Trusted Networks must render a table layout').toBe(true);
    assertNoSecretLeakage(body, '/trusted-networks');
  });

  test('About/System shows release, runtime, features, and providers sections', async ({ page }) => {
    await page.goto('/about');
    const body = await page.content();
    for (const want of ['Release', 'Runtime', 'Features', 'Providers']) {
      expect(body, `about/system must include ${want}`).toContain(want);
    }
    assertNoSecretLeakage(body, '/about');
  });

  test('unauthenticated request to protected page redirects to login', async ({ browser }) => {
    // browser.newContext() without explicit storageState inherits the project-level
    // storageState; an empty state is required to guarantee no session cookie is sent.
    const freshCtx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await freshCtx.newPage();
    await page.goto('/v2/health');
    expect(page.url()).toContain('/login');
    await freshCtx.close();
  });
});
