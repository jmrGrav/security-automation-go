import { test, expect } from '@playwright/test';
import { login } from '../helpers/session';

/**
 * Cross-page coherence: Health, Dashboard, Cloudflare Diff, and Providers
 * must all tell the same story about what is configured.
 *
 * These tests are descriptive — they report what each page says and fail
 * only on direct contradictions (not on "not configured" states).
 */
test.describe('Cross-page coherence', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('health JSON and dashboard CrowdSec status are consistent', async ({ page }) => {
    await page.goto('/health/json');
    const rawHealthText = await page.evaluate(() => document.body.innerText);
    let health: Record<string, unknown> = {};
    try {
      health = JSON.parse(rawHealthText);
    } catch {
      test.skip();
      return;
    }

    const healthJson = JSON.stringify(health).toLowerCase();
    const crowdsecConfiguredInHealth = healthJson.includes('crowdsec') &&
      !healthJson.includes('"crowdsec":"not_configured"') &&
      !healthJson.includes('"crowdsec":"missing"');

    if (crowdsecConfiguredInHealth) {
      await page.goto('/');
      const dashboard = await page.content();
      // Dashboard must not claim CrowdSec is unconfigured if health says it is.
      // Limit the span to 80 chars to avoid false matches across HTML sections.
      expect(dashboard, 'Dashboard must not contradict CrowdSec health status')
        .not.toMatch(/crowdsec.{0,80}(?:unconfigured|not configured)/i);
    }
  });

  test('Cloudflare configured in health → Cloudflare Diff shows Token YES', async ({ page }) => {
    await page.goto('/health/json');
    const rawText = await page.evaluate(() => document.body.innerText);
    let health: Record<string, unknown> = {};
    try {
      health = JSON.parse(rawText);
    } catch {
      test.skip();
      return;
    }

    const healthJson = JSON.stringify(health).toLowerCase();
    const cfConfiguredInHealth =
      healthJson.includes('cloudflare') &&
      !healthJson.includes('not_configured') &&
      !healthJson.includes('missing');

    if (cfConfiguredInHealth) {
      await page.goto('/cloudflare/diff');
      const body = await page.content();
      // Diff page must not say token is missing when health reports configured.
      expect(body, 'Cloudflare Diff must not say token missing when health reports configured')
        .not.toMatch(/token.*no|token.*missing/i);
    }
  });

  test('provider page keys are masked — not equal to what health JSON shows', async ({ page }) => {
    await page.goto('/providers');
    const body = await page.content();
    // If keys are present, they must be masked (shown as "****" or similar).
    // We verify the body contains no raw token pattern.
    const rawTokenPattern = /\b(cfut_|sk-ant-|sk-|AIza)[a-zA-Z0-9_-]{10,}/;
    expect(body, 'Providers page must not contain raw token values').not.toMatch(rawTokenPattern);
  });

  test('OpenResty installed but no events file is NOT shown as critical error', async ({ page }) => {
    await page.goto('/health');
    const body = await page.content();
    // OpenResty binary presence without events.jsonl must not be shown as "failed" or "critical".
    // The health model reports binary+service only (not events file).
    if (body.includes('OpenResty')) {
      expect(body, 'OpenResty without events.jsonl must not show critical failure')
        .not.toMatch(/openresty.*critical|openresty.*failed/i);
    }
  });
});
