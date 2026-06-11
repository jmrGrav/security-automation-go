#!/usr/bin/env bash
# smoke-backend-status.sh — read SQLite DB and output a JSON presence manifest.
#
# This script reads credential presence DIRECTLY from the SQLite database,
# independently of the running UI server. No decryption is performed —
# only row existence is checked. Secret values are NEVER read or printed.
#
# Output format (JSON):
#   {
#     "db_path": "/var/lib/security-automation-go/runtime.db",
#     "credentials": {
#       "cloudflare.api_token":     { "present": true,  "enabled": true  },
#       "crowdsec.lapi_key":        { "present": false, "enabled": false },
#       ...
#     },
#     "ui_settings": {
#       "cf_zone_id": "configured",
#       "setup_complete": "true",
#       ...
#     },
#     "error": null
#   }
#
# Usage:
#   SECURITY_AUTOMATION_SMOKE_LIVE=1 ./scripts/smoke-backend-status.sh [state-dir]
#
# Requires: sqlite3, SECURITY_AUTOMATION_SMOKE_LIVE=1

set -euo pipefail

# ── Gate ────────────────────────────────────────────────────────────────────
if [[ "${SECURITY_AUTOMATION_SMOKE_LIVE:-}" != "1" ]]; then
  echo '{"error":"SECURITY_AUTOMATION_SMOKE_LIVE=1 required"}'
  exit 1
fi

STATE_DIR="${1:-${SMOKE_STATE_DIR:-/var/lib/security-automation-go}}"
DB_PATH="$STATE_DIR/runtime.db"

# The state dir is 0750 owned by security-automation; the calling user (e.g. jm)
# cannot traverse it, so -f returns false even when the file exists.
# Check existence via the service account first, then fall back to direct access.
if sudo -n -u security-automation test -f "$DB_PATH" 2>/dev/null; then
  # File exists — use sudo sqlite3 (service account owns the DB at 0600).
  if sudo -n -u security-automation sqlite3 "$DB_PATH" ".tables" &>/dev/null 2>&1; then
    SQLITE="sudo -n -u security-automation sqlite3"
  else
    echo "{\"error\":\"cannot read $DB_PATH — add NOPASSWD rule: ALL=(security-automation) NOPASSWD: /usr/bin/sqlite3\"}"
    exit 1
  fi
elif [[ -f "$DB_PATH" ]]; then
  # Accessible directly (e.g. running as root or matching user).
  SQLITE="sqlite3"
else
  echo "{\"error\":\"database not found at $DB_PATH\"}"
  exit 1
fi

# ── Known credential keys ────────────────────────────────────────────────────
CREDENTIAL_KEYS=(
  "cloudflare.api_token"
  "abuseipdb.api_key"
  "betterstack.source_token"
  "crowdsec.lapi_key"
  "ai.openai.api_key"
  "ai.anthropic.api_key"
  "ai.gemini.api_key"
)

# ── Known ui_settings keys ───────────────────────────────────────────────────
SETTINGS_KEYS=(
  "cf_zone_id"
  "setup_complete"
  "mutations_enabled"
  "dry_run"
)

# ── Query credential presence (no decryption) ────────────────────────────────
creds_json=""
for key in "${CREDENTIAL_KEYS[@]}"; do
  # Returns "1|1" (present|enabled) or empty (absent)
  result=$($SQLITE "$DB_PATH" \
    "SELECT '1', enabled FROM credential_secrets WHERE name='$key' LIMIT 1;" \
    2>/dev/null || echo "")

  if [[ -n "$result" ]]; then
    present="true"
    enabled_val="${result#*|}"
    enabled=$( [[ "$enabled_val" == "1" ]] && echo "true" || echo "false" )
  else
    present="false"
    enabled="false"
  fi

  # JSON-encode the key (replace . with safe chars in JSON key name)
  if [[ -n "$creds_json" ]]; then
    creds_json="${creds_json},"
  fi
  creds_json="${creds_json}\"${key}\":{\"present\":${present},\"enabled\":${enabled}}"
done

# ── Query ui_settings ────────────────────────────────────────────────────────
settings_json=""
for key in "${SETTINGS_KEYS[@]}"; do
  value=$($SQLITE "$DB_PATH" \
    "SELECT value FROM ui_settings WHERE key='$key' LIMIT 1;" \
    2>/dev/null || echo "")

  if [[ -n "$value" ]]; then
    status="configured"
  else
    status="missing"
  fi

  if [[ -n "$settings_json" ]]; then
    settings_json="${settings_json},"
  fi
  settings_json="${settings_json}\"${key}\":\"${status}\""
done

# ── Output JSON manifest ─────────────────────────────────────────────────────
cat <<JSON
{
  "db_path": "${DB_PATH}",
  "credentials": {${creds_json}},
  "ui_settings": {${settings_json}},
  "error": null
}
JSON
