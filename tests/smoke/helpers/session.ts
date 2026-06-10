import { Page, BrowserContext, expect } from '@playwright/test';

/**
 * Logs in using the admin password from SMOKE_ADMIN_PASSWORD env var.
 * The password is never printed, logged, or included in screenshots.
 * Returns the session cookie value for reference checks.
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
  const session = cookies.find(c => c.name === 'session' || c.name === 'session_id');
  return session ?? null;
}

/**
 * Logs out via the UI logout form. Requires a valid session.
 */
export async function logout(page: Page): Promise<void> {
  await page.goto('/');
  // Click the Logout button inside the nav form.
  await page.click('form[action="/logout"] button[type="submit"]');
  await expect(page).toHaveURL('/login');
}
