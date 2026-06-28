import { test, expect, Page } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';
import { login } from '../helpers/session';

const SCREENSHOT_DIR = process.env.SMOKE_SCREENSHOT_DIR || '/tmp/security-automation-smoke';

async function referenceCapture(page: Page, name: string): Promise<void> {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
  await page.screenshot({
    path: path.join(SCREENSHOT_DIR, name),
    fullPage: true,
  });
}

test.describe('UI v2 PR5 Operator Productivity', () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await login(page);
    // Clear localStorage state so each test starts clean.
    await page.goto('/');
    await page.evaluate(() => {
      localStorage.removeItem('security-automation:watchlist');
      localStorage.removeItem('security-automation:watchlist-open');
      localStorage.removeItem('security-automation:recents');
    });
  });

  test('Watchlist: add item, persist across navigation, then remove', async ({ page }) => {
    // Navigate to timeline where watchlist-add buttons exist.
    await page.goto('/v2/timeline');
    await expect(page.getByRole('heading', { name: /Timeline/i })).toBeVisible();

    // Locate the first watchlist-add button and click it.
    const addBtn = page.locator('[data-watchlist-add="true"]').first();
    await expect(addBtn).toBeVisible();
    await addBtn.click();

    // Verify the button flipped to ★ (item added).
    await expect(addBtn).toHaveText('★');

    // Verify the item is present in localStorage.
    const stored = await page.evaluate(() => localStorage.getItem('security-automation:watchlist'));
    expect(stored).not.toBeNull();
    const parsed = JSON.parse(stored!);
    expect(Array.isArray(parsed) && parsed.length).toBeGreaterThan(0);

    // Expand the watchlist panel (collapsed by default) so the item is visible.
    const showToggle = page.locator('[data-watchlist-collapse-toggle="true"]');
    await showToggle.click();
    await expect(page.locator('[data-watchlist-body]')).toBeVisible();

    // Assert the watchlist list contains an item (remove button present).
    await expect(page.locator('[data-watchlist-remove]').first()).toBeVisible();

    // Screenshot before removal.
    await referenceCapture(page, 'ui-v2-pr5-watchlist-populated.png');

    // Navigate away and back to verify persistence.
    await page.goto('/');
    await page.goto('/v2/timeline');

    // Re-expand after navigation.
    const showToggleAfter = page.locator('[data-watchlist-collapse-toggle="true"]');
    await showToggleAfter.click();
    await expect(page.locator('[data-watchlist-body]')).toBeVisible();

    // Item should still be present.
    await expect(page.locator('[data-watchlist-remove]').first()).toBeVisible();

    // Remove the item.
    await page.locator('[data-watchlist-remove]').first().click();

    // Assert the list now shows the empty state.
    await expect(page.locator('[data-watchlist-list] p.muted')).toBeVisible();
    const storedAfter = await page.evaluate(() => localStorage.getItem('security-automation:watchlist'));
    const parsedAfter = storedAfter ? JSON.parse(storedAfter) : [];
    expect(parsedAfter.length).toBe(0);
  });

  test('Recently viewed: navigation creates entries in recents widget', async ({ page }) => {
    // Navigate through a few pages to generate recents.
    await page.goto('/');
    await page.goto('/v2/timeline');
    await page.goto('/v2/health');
    // Return to dashboard where the sidebar recents widget is rendered.
    await page.goto('/');

    // The recents widget should contain at least one anchor link.
    const recentsWidget = page.locator('[data-recents-widget="true"]');
    await expect(recentsWidget).toBeVisible();
    await expect(recentsWidget.locator('[data-recents-list] a').first()).toBeVisible();

    // Screenshot showing recents populated.
    await referenceCapture(page, 'ui-v2-pr5-recents-visible.png');
  });

  test('Keyboard navigation: g+d goes to dashboard, g+t goes to timeline', async ({ page }) => {
    await page.goto('/v2/timeline');
    await expect(page.getByRole('heading', { name: /Timeline/i })).toBeVisible();

    // Press g then d — should navigate to dashboard.
    await page.keyboard.press('g');
    await page.waitForTimeout(200);
    await page.keyboard.press('d');
    await expect(page).toHaveURL('/');

    // Press g then t — should navigate to timeline.
    await page.keyboard.press('g');
    await page.waitForTimeout(200);
    await page.keyboard.press('t');
    await expect(page).toHaveURL('/timeline');

    // Screenshot showing timeline reached via keyboard.
    await referenceCapture(page, 'ui-v2-pr5-keyboard-nav.png');
  });

  test('Dark + compact regression: widgets remain visible under both modes', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Security Command Center', exact: true })).toBeVisible();

    // Toggle dark operations mode.
    await page.getByRole('button', { name: /Dark operations/i }).click();
    await expect(page.locator('body')).toHaveAttribute('data-theme', 'operations-dark');

    // Toggle compact density.
    await page.getByRole('button', { name: /Compact mode/i }).click();
    await expect(page.locator('body')).toHaveAttribute('data-density', 'compact');

    // Watchlist widget still present in the sidebar.
    await expect(page.locator('[data-watchlist-widget="true"]')).toBeVisible();

    // Recents widget still present in the sidebar.
    await expect(page.locator('[data-recents-widget="true"]')).toBeVisible();

    // Screenshot confirming both widgets visible under dark + compact.
    await referenceCapture(page, 'ui-v2-pr5-dark-compact-regression.png');
  });
});
