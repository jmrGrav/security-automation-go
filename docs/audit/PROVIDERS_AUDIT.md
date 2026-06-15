# Providers Audit — v1.6.x

**Date:** 2026-06-12  
**Scope:** All integration providers — configuration state, UI availability, missing capabilities  
**Status legend:** ✅ Configured · ⚠ Partial · ❌ Missing · 🔒 Key in SQLite · 🔧 Env-var only

---

## Executive Summary

9 providers are referenced in the codebase. 5 have credentials stored. None have a unified management UI — providers can only be configured through the first-run wizard (limited) or YAML config / env vars (not operator-friendly). There is no way to add, edit, disable, test, or diagnose a provider through the web UI.

---

## Provider Status Matrix

| Provider | Key in Store | Enabled | Model/Zone | Test | Disable | Notes |
|----------|-------------|---------|------------|------|---------|-------|
| Cloudflare | ✅ 🔒 | ✅ | ✅ zone set | ❌ | ❌ | mutations_enabled=true |
| CrowdSec | ✅ 🔒 | ✅ | N/A | ❌ | ❌ | decisions log + nginx |
| AbuseIPDB | ✅ 🔒 | ✅ | N/A | ❌ | ❌ | 7 reports sent |
| BetterStack | ✅ 🔒 | ✅ | N/A | ❌ | ❌ | token present |
| Anthropic | ✅ 🔒 | ❌ | ❌ no model | ❌ | ❌ | key stored, not enabled |
| Gemini | ✅ 🔒 | ❌ | ❌ no model | ❌ | ❌ | key stored, not enabled |
| OpenAI | ❌ | ❌ | ❌ | ❌ | ❌ | key missing |
| Spamhaus | ❌ | ❌ | N/A | ❌ | ❌ | no UI, env-var only |
| VirusTotal | ❌ | ❌ | N/A | ❌ | ❌ | no UI, env-var only |

---

## Provider Details

### Cloudflare

**Role:** IP access rule sync (CrowdSec bans → CF rules), WAF event ingestion  
**Config source:** Credential store (api_token) + ui_settings (cf_zone_id) + setup wizard  
**Status:** ✅ Fully operational

```
api_token:     ✅ in credential_secrets (enabled=true)
cf_zone_id:    ✅ in ui_settings
mutations_enabled: true
cloudflare_mutations_enabled: true
```

**What works:** WAF event fetch (every 60s), ban sync (orchestrator), Cloudflare Diff page  
**What's missing:** No way to test CF API connectivity from UI. No way to temporarily disable mutations from UI without editing SQLite.  
**UI coverage:** Diff page, setup wizard step 4

---

### CrowdSec

**Role:** Source of active bans (sync to Cloudflare), decision log for event correlation  
**Config source:** Credential store (lapi_key) + YAML config  
**Status:** ✅ Configured

```
crowdsec.lapi_key: ✅ in credential_secrets (enabled=true)
cs_poller_enabled: true (ui_settings)
decisions_log:     configured (/var/log/crowdsec/decisions.log or similar)
nginx_log_dir:     /var/log/nginx
```

**What works:** LAPI key loaded, poller enabled flag set in SQLite  
**What's missing:** No way to test LAPI connectivity from UI. No way to see how many active bans CrowdSec has. Silent event drop when nginx logs have no matching URI (see DATA_PIPELINE_AUDIT.md).  
**UI coverage:** Health page shows status, setup wizard step

---

### AbuseIPDB

**Role:** Outbound threat reporting  
**Config source:** Credential store (api_key)  
**Status:** ✅ Configured and active

```
abuseipdb.api_key: ✅ in credential_secrets (enabled=true)
abuseipdb_enabled: true (ui_settings)
reporting_enabled: not explicitly set (defaults to enabled)
```

**What works:** 7 IPs reported on 2026-06-11. Outbox worker processes retries.  
**What's missing:** No way to see reporting rate / quota usage from UI. No way to disable reporting from UI without editing SQLite. Confidence gap causes 17% of real threats to be suppressed (see DATA_PIPELINE_AUDIT.md).  
**UI coverage:** Providers page (read-only badge)

---

### BetterStack

**Role:** Telemetry sink — security events forwarded to BetterStack Logs  
**Config source:** Credential store (source_token)  
**Status:** ✅ Configured

```
betterstack.source_token: ✅ in credential_secrets (enabled=true)
ingesting_host:            configured (BETTERSTACK_INGESTING_HOST env var or YAML)
```

**What works:** Source token loaded; telemetry sink configured (`sinks.NewBetterStack()`) when both token and host are set.  
**What's missing:** No diagnostic page for BetterStack. No way to verify log ingestion is working. No toggle in UI.  
**UI coverage:** Health page shows YELLOW/GREEN based on token presence

---

### Anthropic AI

**Role:** AI explain gateway — natural language security event analysis  
**Config source:** Credential store (api_key) + env vars (model, enabled flag)  
**Status:** ⚠ Key stored, provider disabled

```
ai.anthropic.api_key: ✅ in credential_secrets (enabled=true)
AI_PROVIDER_ANTHROPIC_ENABLED: not set → false
AI_PROVIDER_ANTHROPIC_MODEL:   not set → "" (empty)
```

**What works:** Key is loaded at startup into `aiCfg.Anthropic.APIKey`  
**What's missing:** Provider disabled; no model name; no UI to configure  
**UI coverage:** None

---

### Gemini AI

**Role:** AI explain gateway — alternative to Anthropic  
**Config source:** Credential store (api_key) + env vars  
**Status:** ⚠ Key stored, provider disabled

```
ai.gemini.api_key: ✅ in credential_secrets (enabled=true)
AI_PROVIDER_GEMINI_ENABLED: not set → false
AI_PROVIDER_GEMINI_MODEL:   not set → "" (empty)
```

**What works:** Key loaded at startup  
**What's missing:** Provider disabled; no model name; no UI  
**UI coverage:** None

---

### OpenAI

**Role:** AI explain gateway — primary provider in many deployments  
**Config source:** Credential store (api_key) + env vars  
**Status:** ❌ Key not stored

```
ai.openai.api_key: ❌ NOT in credential_secrets
AI_PROVIDER_OPENAI_ENABLED: not set → false
```

**UI coverage:** None

---

### Spamhaus

**Role:** DNS blacklist / reputation lookup for threat enrichment  
**Config source:** YAML config / env var only (`SPAMHAUS_API_KEY`)  
**Status:** ❌ Not configured

```
spamhaus.api_key:  not set
spamhaus.enabled:  false
```

**No UI.** No setup wizard step. No credential store entry. Key must be set in YAML or env var.  
**UI coverage:** None

---

### VirusTotal

**Role:** File/URL/IP reputation lookup  
**Config source:** YAML config / env var only (`VIRUSTOTAL_API_KEY`)  
**Status:** ❌ Not configured

```
virustotal.api_key: not set
virustotal.enabled: false
```

**No UI.** No setup wizard step. No credential store entry.  
**UI coverage:** None

---

## Missing: Unified Provider Management UI

The user cannot currently:
- See all providers in one place with their status
- Add a new credential via the web UI (only the setup wizard covers a subset)
- Edit an existing credential (e.g., rotate AbuseIPDB key)
- Disable a provider temporarily
- Test a provider's connectivity
- Set model names for AI providers
- Enable/disable AI providers

The `/providers` page exists but appears to be a static status display, not an interactive management console.

---

## Problems Identified

| # | Severity | Problem |
|---|----------|---------|
| P1 | **Critique** | AI providers (Anthropic, Gemini) have keys but are disabled — AI explain feature non-functional. |
| P2 | **Important** | No unified provider management UI — no add/edit/test/disable capability. |
| P3 | **Important** | AI model names not configurable via UI or credential store — env vars only. |
| P4 | **Important** | Spamhaus and VirusTotal have no UI, no credential store support — can only be enabled via YAML/env. |
| P5 | **Important** | OpenAI key missing. |
| P6 | **Cosmétique** | No connectivity test for any provider — no way to validate a newly entered key before saving. |
