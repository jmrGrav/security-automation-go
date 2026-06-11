import { Page, BrowserContext, expect } from '@playwright/test';

/**
 * Logs in using the admin password from SMOKE_ADMIN_PASSWORD env var.
 * The password is never printed, logged, or included in screenshots.
 * If the page already has a valid session (via storageState), the /login
 * redirect to / is detected and the function returns without POSTing again.
 */
export async function login(page: Page): Promise<void> {
  const password = process.env.SMOKE_ADMIN_PASSWORD;
  if (!password) {
    throw new Error(
      '[SMOKE] SMOKE_ADMIN_PASSWORD is required. Set it without logging: ' +
      'read -rs SMOKE_ADMIN_PASSWORD && export SMOKE_ADMIN_PASSWORD'
    );
  }

  await page.goto('/login');

  // If storageState provided a valid session, /login redirects to /.
  if (!page.url().includes('/login')) {
    return;
  }

  await page.fill('#password', password);
  await page.click('button[type="submit"]');

  // Successful login redirects to dashboard.
  await expect(page).toHaveURL('/');
}

/**
 * Returns session cookie attributes. Password is never present.
 * Used to assert HttpOnly, SameSite, Secure without exposing the value.
 */
export async function getSessionCookieAttrs(ctx: BrowserContext) {
  const cookies = await ctx.cookies();
  const session = cookies.find(c => c.name === 'ui_session');
  return session ?? null;
}

/**
 * Logs out by extracting the CSRF token from the providers page and
 * submitting a POST /logout request. Requires a valid session.
 */
export async function logout(page: Page): Promise<void> {
  // Extract a CSRF token from a page that embeds one.
  await page.goto('/providers');
  const csrf = await page.inputValue('input[name="csrf_token"]').catch(() => '');

  // POST /logout with the CSRF token via fetch (same-origin, updates cookie jar).
  await page.evaluate(async (token: string) => {
    await fetch('/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `csrf_token=${encodeURIComponent(token)}`,
    });
  }, csrf);

  // After logout the session cookie is cleared; navigating to / redirects to /login.
  await page.goto('/');
  await expect(page).toHaveURL('/login');
}
