import { test, expect } from '@playwright/test';
import { execFileSync } from 'child_process';
import { resolve } from 'path';
import { login } from '../helpers/session';

/**
 * Runtime Integrity Tests
 *
 * Two-layer verification:
 *   Layer 1 (DB truth)      — smoke-backend-status.sh reads credential_secrets
 *                              directly via sqlite3, no decryption, presence only.
 *   Layer 2 (server truth)  — /health/json is the running server's assessment
 *                              of its own credential store (reads + decrypts).
 *   Layer 3 (UI truth)      — what the browser actually renders.
 *
 * Integrity rule: all three layers must agree on configured/missing for each provider.
 *
 *   DB: present  + Health: GREEN/YELLOW-with-token  + UI: configured  → PASS
 *   DB: present  + Health: RED "not configured"                        → FAIL (server bug)
 *   DB: present  + UI says "missing"                                   → FAIL (UI bug)
 *   DB: missing  + Health: GREEN "not configured (optional)"           → PASS
 *   DB: missing  + UI: "configured"                                    → FAIL (phantom config)
 */

const ROOT_DIR = resolve(__dirname, '../../..');
const STATE_DIR = process.env.SMOKE_STATE_DIR || '/var/lib/security-automation-go';

interface DBStatus {
  db_path: string;
  credentials: Record<string, { present: boolean; enabled: boolean }>;
  ui_settings: Record<string, string>;
  error: string | null;
}

interface HealthCheck {
  name: string;
  status: 'GREEN' | 'YELLOW' | 'RED';
  reason: string;
}

interface HealthResponse {
  generated_at: string;
  health: HealthCheck[];
  detection: unknown[];
}

function runBackendStatus(): DBStatus | null {
  try {
    const output = execFileSync(
      `${ROOT_DIR}/scripts/smoke-backend-status.sh`,
      [STATE_DIR],
      {
        encoding: 'utf8',
        timeout: 15_000,
        env: { ...process.env, SECURITY_AUTOMATION_SMOKE_LIVE: '1', SMOKE_STATE_DIR: STATE_DIR },
      }
    );
    return JSON.parse(output.trim());
  } catch (err: any) {
    console.warn('[integrity] smoke-backend-status.sh failed:', err.message);
    return null;
  }
}

function findHealthCheck(checks: HealthCheck[], name: string): HealthCheck | undefined {
  return checks.find(c => c.name === name);
}

// Maps credential key → health check name
const CREDENTIAL_TO_HEALTH: Record<string, string> = {
  'cloudflare.api_token': 'cloudflare',
  'abuseipdb.api_key':    'abuseipdb',
  'betterstack.source_token': 'betterstack',
  'crowdsec.lapi_key':    'crowdsec',
  'ai.openai.api_key':    'ai-providers',
  'ai.anthropic.api_key': 'ai-providers',
  'ai.gemini.api_key':    'ai-providers',
};

// Reasons that clearly indicate "token present" in health JSON
const TOKEN_PRESENT_REASONS = [
  'configured',
  'api token',
  'api key',
  'source token',
  'lapi key',
  'zone id',
];

function healthIndicatesPresent(check: HealthCheck | undefined): boolean {
  if (!check) return false;
  const reason = check.reason.toLowerCase();
  return TOKEN_PRESENT_REASONS.some(r => reason.includes(r)) &&
    !reason.includes('not configured') &&
    !reason.includes('missing');
}

function healthIndicatesMissing(check: HealthCheck | undefined): boolean {
  if (!check) return true;
  const reason = check.reason.toLowerCase();
  return reason.includes('not configured') || reason.includes('missing') ||
    check.status === 'RED';
}

test.describe('Runtime integrity', () => {
  let dbStatus: DBStatus | null = null;
  let healthData: HealthResponse | null = null;

  test.beforeAll(async () => {
    dbStatus = runBackendStatus();
    if (dbStatus?.error) {
      console.warn('[integrity] DB probe error:', dbStatus.error);
      dbStatus = null;
    }
  });

  test.beforeEach(async ({ page }) => {
    await login(page);
    if (!healthData) {
      await page.goto('/v2/health/json');
      const text = (await page.evaluate(() => document.body.innerText)).trim();
      try {
        healthData = JSON.parse(text);
      } catch {
        console.warn('[integrity] Could not parse /health/json');
      }
    }
  });

  // ── Layer 1 ↔ Layer 2: DB truth vs server health JSON ───────────────────

  test('DB probe is reachable and returns valid manifest', async () => {
    if (!dbStatus) {
      test.skip(true, 'smoke-backend-status.sh not reachable — check SMOKE_STATE_DIR and sqlite3');
      return;
    }
    expect(dbStatus.error).toBeNull();
    expect(dbStatus.credentials).toBeDefined();
    expect(dbStatus.db_path).toContain('runtime.db');
    console.log('[integrity] DB path:', dbStatus.db_path);
    console.log('[integrity] Credential presence:',
      Object.entries(dbStatus.credentials)
        .map(([k, v]) => `${k}=${v.present ? 'present' : 'missing'}(enabled:${v.enabled})`)
        .join(', ')
    );
  });

  for (const [credKey, healthName] of Object.entries(CREDENTIAL_TO_HEALTH)) {
    // Skip duplicates for ai-providers (multiple keys map to one health check)
    if (credKey === 'ai.anthropic.api_key' || credKey === 'ai.gemini.api_key') continue;

    test(`integrity: DB[${credKey}] ↔ health[${healthName}]`, async () => {
      if (!dbStatus || !healthData) {
        test.skip(true, 'DB probe or health JSON not available');
        return;
      }

      const cred = dbStatus.credentials[credKey];
      const healthCheck = findHealthCheck(healthData.health, healthName);
      const dbPresent = cred?.present ?? false;

      const serverSaysPresent = healthIndicatesPresent(healthCheck);
      const serverSaysMissing = healthIndicatesMissing(healthCheck);

      console.log(
        `[integrity] ${credKey}: DB=${dbPresent ? 'PRESENT' : 'MISSING'}, ` +
        `health=${healthCheck?.status ?? 'N/A'} "${healthCheck?.reason ?? ''}"`
      );

      // FAIL case: DB has credential but server reports it as not configured
      if (dbPresent && serverSaysMissing && healthCheck?.status === 'RED') {
        throw new Error(
          `[INTEGRITY FAIL] DB has "${credKey}" present but health "${healthName}" ` +
          `reports RED "${healthCheck.reason}". ` +
          `The server is not reading the credential store correctly.`
        );
      }

      // FAIL case: DB does NOT have credential but server claims it's configured
      if (!dbPresent && serverSaysPresent) {
        throw new Error(
          `[INTEGRITY FAIL] DB has NO "${credKey}" but health "${healthName}" ` +
          `reports it as configured: "${healthCheck?.reason}". ` +
          `Phantom configuration — verify credential store.`
        );
      }

      // PASS: DB and server agree
      console.log(`[integrity] ✓ ${credKey}: DB and health are consistent`);
    });
  }

  // ── AI providers: all three keys together ────────────────────────────────

  test('integrity: AI providers DB ↔ health[ai-providers]', async () => {
    if (!dbStatus || !healthData) {
      test.skip(true, 'DB probe or health JSON not available');
      return;
    }

    const aiHealthCheck = findHealthCheck(healthData.health, 'ai-providers');
    const openai = dbStatus.credentials['ai.openai.api_key']?.present ?? false;
    const anthropic = dbStatus.credentials['ai.anthropic.api_key']?.present ?? false;
    const gemini = dbStatus.credentials['ai.gemini.api_key']?.present ?? false;
    const anyAIPresent = openai || anthropic || gemini;

    const configuredCount = [openai, anthropic, gemini].filter(Boolean).length;
    console.log(
      `[integrity] AI providers: ${configuredCount}/3 configured in DB, ` +
      `health=${aiHealthCheck?.status ?? 'N/A'} "${aiHealthCheck?.reason ?? ''}"`
    );

    if (anyAIPresent && aiHealthCheck?.status === 'RED') {
      throw new Error(
        `[INTEGRITY FAIL] At least one AI key present in DB but health reports RED: ` +
        `"${aiHealthCheck.reason}"`
      );
    }
    console.log('[integrity] ✓ AI providers: DB and health are consistent');
  });

  // ── Cloudflare zone ID: ui_settings ↔ health ────────────────────────────

  test('integrity: cf_zone_id in ui_settings ↔ health cloudflare check', async () => {
    if (!dbStatus || !healthData) {
      test.skip(true, 'DB probe or health JSON not available');
      return;
    }

    const zoneConfigured = dbStatus.ui_settings['cf_zone_id'] === 'configured';
    const cfHealthCheck = findHealthCheck(healthData.health, 'cloudflare');
    const cfPresent = dbStatus.credentials['cloudflare.api_token']?.present ?? false;

    console.log(
      `[integrity] Cloudflare: token=${cfPresent ? 'PRESENT' : 'MISSING'}, ` +
      `zone=${zoneConfigured ? 'CONFIGURED' : 'MISSING'}, ` +
      `health=${cfHealthCheck?.status} "${cfHealthCheck?.reason}"`
    );

    if (cfPresent && zoneConfigured) {
      // Both present → health must be GREEN
      if (cfHealthCheck?.status !== 'GREEN') {
        throw new Error(
          `[INTEGRITY FAIL] CF token AND zone are in DB but health is not GREEN: ` +
          `${cfHealthCheck?.status} "${cfHealthCheck?.reason}"`
        );
      }
    }

    if (cfPresent && !zoneConfigured) {
      // Token present but no zone → health should be YELLOW (token present but zone missing)
      const reason = cfHealthCheck?.reason.toLowerCase() ?? '';
      if (cfHealthCheck?.status === 'RED' && reason.includes('not configured')) {
        throw new Error(
          `[INTEGRITY FAIL] CF token is in DB but health reports RED "not configured". ` +
          `Expected YELLOW (zone missing).`
        );
      }
    }

    console.log('[integrity] ✓ Cloudflare zone: DB and health are consistent');
  });

  // ── Layer 2 ↔ Layer 3: health JSON vs UI page display ────────────────────

  test('integrity: UI dashboard does not claim CrowdSec configured if health says missing', async ({ page }) => {
    if (!healthData) {
      test.skip(true, 'health JSON not available');
      return;
    }

    const csCheck = findHealthCheck(healthData.health, 'crowdsec');
    await page.goto('/');
    const body = await page.content();

    const healthSaysMissing = csCheck?.status === 'RED' ||
      (csCheck?.reason.toLowerCase().includes('not configured') ?? false);

    if (healthSaysMissing) {
      // Dashboard must not claim CrowdSec is configured/working
      expect(body.toLowerCase(), 'Dashboard must not contradict health JSON on CrowdSec')
        .not.toMatch(/crowdsec.*configured.*yes|crowdsec.*running/i);
    }
    console.log(
      `[integrity] ✓ CrowdSec: health=${csCheck?.status} "${csCheck?.reason}" ↔ dashboard consistent`
    );
  });

  test('integrity: Cloudflare Diff does not claim configured if health/DB says missing', async ({ page }) => {
    if (!healthData || !dbStatus) {
      test.skip(true, 'health JSON or DB probe not available');
      return;
    }

    const cfCheck = findHealthCheck(healthData.health, 'cloudflare');
    const dbHasToken = dbStatus.credentials['cloudflare.api_token']?.present ?? false;
    const healthSaysMissing = cfCheck?.status === 'RED' &&
      (cfCheck.reason.toLowerCase().includes('not configured'));

    await page.goto('/v2/cloudflare');
    const body = await page.content();

    if (!dbHasToken && healthSaysMissing) {
      // If both DB and health agree CF is not configured, diff page must not say "Configured YES"
      expect(body, 'Cloudflare Diff must not say "Configured YES" when DB and health both say missing')
        .not.toMatch(/configured.*yes/i);
    }

    if (dbHasToken && !healthSaysMissing) {
      // If DB has token and health says configured, diff must not say token missing.
      // Use a span-pair regex to avoid false positives from unrelated "no" words in
      // the same single-line HTML (e.g. "no live mutation path" in a badge further down).
      expect(body, 'Cloudflare Diff must not say "token missing" when DB has token')
        .not.toMatch(/>\s*token\s*<\/span>\s*<span[^>]*>\s*(?:NO|missing)/i);
    }

    console.log(
      `[integrity] ✓ Cloudflare Diff: DB=${dbHasToken ? 'PRESENT' : 'MISSING'}, ` +
      `health=${cfCheck?.status} → diff page consistent`
    );
  });

  test('integrity: providers page does not claim configured if DB credential is missing', async ({ page }) => {
    if (!dbStatus) {
      test.skip(true, 'DB probe not available');
      return;
    }

    await page.goto('/v2/providers');
    const body = await page.content();

    // For each provider that is absent from the DB, the providers page must not
    // show a configured/enabled badge for it.
    const providerMap: Record<string, string> = {
      'abuseipdb.api_key':       'AbuseIPDB',
      'betterstack.source_token': 'BetterStack',
      'ai.openai.api_key':       'OpenAI',
      'ai.anthropic.api_key':    'Anthropic',
      'ai.gemini.api_key':       'Gemini',
    };

    for (const [credKey, providerLabel] of Object.entries(providerMap)) {
      const dbPresent = dbStatus.credentials[credKey]?.present ?? false;
      if (!dbPresent) {
        // Provider page must not claim this provider is "enabled" or "configured"
        const providerSection = extractProviderSection(body, providerLabel);
        if (providerSection) {
          expect(providerSection, `${providerLabel} must not show "enabled" when DB credential is absent`)
            .not.toMatch(/\benabled\b/i);
        }
      }
      console.log(
        `[integrity] ✓ ${providerLabel}: DB=${dbPresent ? 'PRESENT' : 'MISSING'} ↔ providers page consistent`
      );
    }
  });
});

// Extract the HTML section around a provider label (rough heuristic)
function extractProviderSection(html: string, label: string): string | null {
  const idx = html.indexOf(label);
  if (idx === -1) return null;
  return html.slice(Math.max(0, idx - 50), idx + 200);
}
