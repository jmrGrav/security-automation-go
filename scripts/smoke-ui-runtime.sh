#!/usr/bin/env bash
# smoke-ui-runtime.sh — pre-release v1.6.0 live smoke test runner
#
# NEVER run in CI. This script connects to a running local instance with
# real credentials. It is opt-in only.
#
# Usage:
#   SECURITY_AUTOMATION_SMOKE_LIVE=1 \
#   SMOKE_ADMIN_PASSWORD="$(read -rs p && echo "$p")" \
#   ./scripts/smoke-ui-runtime.sh
#
# Optional vars:
#   SMOKE_UI_URL            — default: http://127.0.0.1:9091
#   SMOKE_STATE_DIR         — default: /var/lib/security-automation-go
#   SMOKE_BIN               — default: /usr/bin/cf-sync
#   SMOKE_ADMIN_RESET_CONFIRM=1  — enable destructive admin CLI tests
#   SMOKE_SCREENSHOT_DIR    — default: /tmp/security-automation-smoke

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SMOKE_DIR="$ROOT_DIR/tests/smoke"
REPORT_DIR="/tmp/security-automation-smoke"
REPORT_FILE="$ROOT_DIR/SMOKE_TEST_REPORT.md"

# ── Gate ────────────────────────────────────────────────────────────────────
if [[ "${SECURITY_AUTOMATION_SMOKE_LIVE:-}" != "1" ]]; then
  echo ""
  echo "ERROR: SECURITY_AUTOMATION_SMOKE_LIVE=1 is required to run smoke tests."
  echo ""
  echo "These tests connect to a running local instance using real credentials."
  echo "Set the variable explicitly to confirm intent:"
  echo ""
  echo "  SECURITY_AUTOMATION_SMOKE_LIVE=1 \\"
  echo "  SMOKE_ADMIN_PASSWORD=... \\"
  echo "  ./scripts/smoke-ui-runtime.sh"
  echo ""
  exit 1
fi

if [[ -z "${SMOKE_ADMIN_PASSWORD:-}" ]]; then
  echo ""
  echo "ERROR: SMOKE_ADMIN_PASSWORD is required."
  echo ""
  echo "Read it without logging:"
  echo '  read -rsp "Admin password: " SMOKE_ADMIN_PASSWORD && export SMOKE_ADMIN_PASSWORD'
  echo '  SECURITY_AUTOMATION_SMOKE_LIVE=1 ./scripts/smoke-ui-runtime.sh'
  echo ""
  exit 1
fi

UI_URL="${SMOKE_UI_URL:-http://127.0.0.1:9091}"
STATE_DIR="${SMOKE_STATE_DIR:-/var/lib/security-automation-go}"
BIN="${SMOKE_BIN:-/usr/bin/cf-sync}"

# ── Pre-flight checks ────────────────────────────────────────────────────────
echo "[SMOKE] Pre-flight checks..."

# 1. Standard test suite must pass first.
echo "[SMOKE] Running go test ./... (must be green before live smoke)..."
cd "$ROOT_DIR"
GOTOOLCHAIN=go1.25.0 go test ./... -count=1 2>&1 | grep -E "^(ok|FAIL|---)" | tail -10
echo "[SMOKE] ✓ Unit tests passed."

# 2. Backend status probe (pre-flight only — full check is in spec 09)
echo "[SMOKE] Probing backend DB status..."
BACKEND_JSON=$(SECURITY_AUTOMATION_SMOKE_LIVE=1 SMOKE_STATE_DIR="$STATE_DIR" \
  "$ROOT_DIR/scripts/smoke-backend-status.sh" "$STATE_DIR" 2>/dev/null || echo '{"error":"probe failed"}')
if echo "$BACKEND_JSON" | grep -q '"error":null'; then
  echo "[SMOKE] ✓ DB probe: credentials present in $(echo "$BACKEND_JSON" | grep -o '"db_path":"[^"]*"' | head -1)"
  # Print presence manifest (no values, no decryption)
  echo "$BACKEND_JSON" | python3 -c "
import sys,json
d=json.load(sys.stdin)
creds=d.get('credentials',{})
for k,v in creds.items():
    status='PRESENT' if v['present'] else 'MISSING'
    enabled=' (disabled)' if v['present'] and not v['enabled'] else ''
    print(f'  [{status}]{enabled} {k}')
" 2>/dev/null || true
else
  echo "[SMOKE] WARNING: DB probe failed or DB not accessible: $BACKEND_JSON"
  echo "[SMOKE]          Integrity tests will be skipped (spec 09)."
fi

# 2. Binary must be built.
echo "[SMOKE] Building cf-sync binary..."
GOTOOLCHAIN=go1.25.0 go build -o /tmp/cf-sync-smoke ./cmd/cf-sync/
SMOKE_BIN_BUILT="/tmp/cf-sync-smoke"
echo "[SMOKE] ✓ Binary built at $SMOKE_BIN_BUILT."

# 3. UI must be reachable.
echo "[SMOKE] Checking UI reachability at $UI_URL..."
if ! curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$UI_URL/login" | grep -qE "^(200|302)$"; then
  echo "[SMOKE] ERROR: UI at $UI_URL is not responding."
  echo "[SMOKE] Start cf-sync with UI_ENABLED=1 before running smoke tests."
  exit 1
fi
echo "[SMOKE] ✓ UI is reachable."

# ── Node dependencies ────────────────────────────────────────────────────────
echo "[SMOKE] Installing Playwright dependencies..."
cd "$SMOKE_DIR"
npm install --silent
npx playwright install chromium
echo "[SMOKE] ✓ Playwright ready."

# ── Screenshot directory ─────────────────────────────────────────────────────
SCREENSHOT_DIR="${SMOKE_SCREENSHOT_DIR:-$REPORT_DIR}"
mkdir -p "$SCREENSHOT_DIR"

# ── Run Playwright tests ─────────────────────────────────────────────────────
echo ""
echo "[SMOKE] Running browser smoke tests..."
echo "[SMOKE] Target: $UI_URL"
echo "[SMOKE] Screenshots on failure: $SCREENSHOT_DIR"
echo ""

set +e
SECURITY_AUTOMATION_SMOKE_LIVE=1 \
SMOKE_ADMIN_PASSWORD="$SMOKE_ADMIN_PASSWORD" \
SMOKE_UI_URL="$UI_URL" \
SMOKE_STATE_DIR="$STATE_DIR" \
SMOKE_BIN="$SMOKE_BIN_BUILT" \
SMOKE_SCREENSHOT_DIR="$SCREENSHOT_DIR" \
  npx playwright test 2>&1 | tee /tmp/smoke-playwright.log
PLAYWRIGHT_EXIT=$?
set -e

# ── Generate report ──────────────────────────────────────────────────────────
echo ""
echo "[SMOKE] Generating report..."

COMMIT=$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(date -u '+%Y-%m-%d %H:%M UTC')
RESULT=$( [[ $PLAYWRIGHT_EXIT -eq 0 ]] && echo "PASS" || echo "FAIL" )

cat > "$REPORT_FILE" << REPORT
# Smoke Test Report

| Field | Value |
|-------|-------|
| Date | $DATE |
| Commit | $COMMIT |
| Branch | $(git -C "$ROOT_DIR" branch --show-current 2>/dev/null || echo "unknown") |
| Target | $UI_URL |
| State dir | $STATE_DIR (path only — no content) |
| Result | **$RESULT** |

## Environment

- UI reachable: YES
- Unit tests: PASS (pre-flight)
- Browser: Chromium via Playwright

## Pages Tested

| Page | Description |
|------|-------------|
| /login | Authentication form |
| / | Dashboard |
| /health | Health Center |
| /health/json | Health JSON endpoint |
| /providers | Provider configuration (masked) |
| /cloudflare/diff | Cloudflare Diff + Operator Summary |
| /trusted-networks | Trusted Networks table |
| /audit | Audit trail |
| /forensic | Forensic lookup |
| /about | About/System |
| /intelligence | Security Intelligence |
| /timeline | Timeline |
| /replay | Replay (stub) |
| /deban | Deban (stub) |
| /recovery | Recovery (stub) |
| /drift | Drift (stub) |

## Coherence Checks

- Health ↔ Dashboard CrowdSec status
- Health ↔ Cloudflare Diff token status
- Provider page key masking
- OpenResty without events.jsonl ≠ critical failure

## Runtime Integrity Checks (spec 09)

Three-layer verification — DB truth ↔ /health/json ↔ UI:

| Provider | Credential Key | DB Probe |
|----------|---------------|----------|
| Cloudflare | cloudflare.api_token | $(echo "$BACKEND_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); c=d.get('credentials',{}); v=c.get('cloudflare.api_token',{}); print('PRESENT' if v.get('present') else 'MISSING')" 2>/dev/null || echo "N/A") |
| CrowdSec | crowdsec.lapi_key | $(echo "$BACKEND_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); c=d.get('credentials',{}); v=c.get('crowdsec.lapi_key',{}); print('PRESENT' if v.get('present') else 'MISSING')" 2>/dev/null || echo "N/A") |
| AbuseIPDB | abuseipdb.api_key | $(echo "$BACKEND_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); c=d.get('credentials',{}); v=c.get('abuseipdb.api_key',{}); print('PRESENT' if v.get('present') else 'MISSING')" 2>/dev/null || echo "N/A") |
| BetterStack | betterstack.source_token | $(echo "$BACKEND_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); c=d.get('credentials',{}); v=c.get('betterstack.source_token',{}); print('PRESENT' if v.get('present') else 'MISSING')" 2>/dev/null || echo "N/A") |
| OpenAI | ai.openai.api_key | $(echo "$BACKEND_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); c=d.get('credentials',{}); v=c.get('ai.openai.api_key',{}); print('PRESENT' if v.get('present') else 'MISSING')" 2>/dev/null || echo "N/A") |
| Anthropic | ai.anthropic.api_key | $(echo "$BACKEND_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); c=d.get('credentials',{}); v=c.get('ai.anthropic.api_key',{}); print('PRESENT' if v.get('present') else 'MISSING')" 2>/dev/null || echo "N/A") |
| Gemini | ai.gemini.api_key | $(echo "$BACKEND_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); c=d.get('credentials',{}); v=c.get('ai.gemini.api_key',{}); print('PRESENT' if v.get('present') else 'MISSING')" 2>/dev/null || echo "N/A") |

## Security Checks

- Session cookie: HttpOnly, SameSite=Strict, Secure
- No raw API tokens in any rendered page
- No panic/goroutine traces in any page
- No JS console errors on dashboard

## Playwright Results

\`\`\`
$(tail -30 /tmp/smoke-playwright.log 2>/dev/null || echo "(log not available)")
\`\`\`

## Screenshots on Failure

$(ls -1 "$SCREENSHOT_DIR"/*.png 2>/dev/null | sed 's/^/- /' || echo "None (all tests passed)")

---

*This report was generated by \`scripts/smoke-ui-runtime.sh\`. It must never be committed with secrets.*
*Screenshots stored at: $SCREENSHOT_DIR (local only — never committed)*
REPORT

echo "[SMOKE] Report written to: $REPORT_FILE"
echo ""

if [[ $PLAYWRIGHT_EXIT -eq 0 ]]; then
  echo "[SMOKE] ✅ ALL SMOKE TESTS PASSED — GO for v1.6.0"
else
  echo "[SMOKE] ❌ SMOKE TESTS FAILED — NO-GO until failures are resolved"
  echo "[SMOKE] See: $REPORT_FILE"
  echo "[SMOKE] Screenshots: $SCREENSHOT_DIR"
  exit 1
fi
