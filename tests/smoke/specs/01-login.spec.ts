import { test, expect } from '@playwright/test';
import { login, logout, getSessionCookieAttrs } from '../helpers/session';
import { assertNoSecretLeakage } from '../helpers/redact';

test.describe('Login / session', () => {
  // Auth flow tests must start without a pre-loaded session.
  test.use({ storageState: undefined });

  test('login page renders without error', async ({ page }) => {
    await page.goto('/login');
    expect(page.url()).toContain('/login');
    const body = await page.content();
    assertNoSecretLeakage(body, '/login page');
    await expect(page.locator('#password')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('valid password logs in and redirects to dashboard', async ({ page }) => {
    await login(page);
    expect(page.url()).not.toContain('/login');
    const body = await page.content();
    assertNoSecretLeakage(body, 'dashboard after login');
  });

  test('session cookie is HttpOnly and SameSite=Strict', async ({ page, context }) => {
    await login(page);
    const cookie = await getSessionCookieAttrs(context);
    expect(cookie, 'session cookie must be set').not.toBeNull();
    expect(cookie!.httpOnly, 'cookie must be HttpOnly').toBe(true);
    expect(cookie!.sameSite, 'cookie must be SameSite=Strict').toBe('Strict');
    // Secure=true is set unconditionally (W3C Secure Contexts §3.2:
    // 127.0.0.0/8 is "potentially trustworthy" — browsers accept it on http).
    expect(cookie!.secure, 'cookie must have Secure flag').toBe(true);
  });

  test('unauthenticated request redirects to /login', async ({ page }) => {
    // Fresh context — no session cookie.
    await page.goto('/');
    expect(page.url()).toContain('/login');
  });

  test('logout clears session and redirects to /login', async ({ page }) => {
    await login(page);
    await logout(page);
    // After logout, dashboard must redirect to login.
    await page.goto('/');
    expect(page.url()).toContain('/login');
  });

  test('invalid password returns error, no session created', async ({ page }) => {
    await page.goto('/login');
    await page.fill('#password', 'definitely-wrong-password-xyzzy-12345');
    await page.click('button[type="submit"]');
    // Must stay on login or show an error — must NOT redirect to dashboard.
    await page.waitForURL(/\/login|\/setup/);
    expect(page.url()).not.toBe('/');
  });
});
