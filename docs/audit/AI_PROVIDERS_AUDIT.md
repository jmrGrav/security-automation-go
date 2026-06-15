# AI Providers Audit — v1.6.x

**Date:** 2026-06-12  
**Scope:** AI explain gateway configuration, model wiring, key management, UI availability  
**Status legend:** ✅ OK · ⚠ PARTIAL · ❌ MISSING/BROKEN

---

## Executive Summary

The AI gateway code is complete and architecturally sound. Three providers are supported (OpenAI, Anthropic, Gemini). Two API keys are stored in the credential store (Anthropic, Gemini). However:

1. **No model names configured** — `AI_PROVIDER_*_MODEL` env vars are not set; models default to `""`.
2. **All providers disabled by default** — `AI_PROVIDER_*_ENABLED` env vars not set; default is `false`.
3. **No UI to configure models or enable providers** — configuration is env-var-only with no runtime override path.
4. **OpenAI key missing** — only Anthropic and Gemini keys are in the credential store.

---

## Credential Store Status

Queried from `/var/lib/security-automation-go/runtime.db` (main DB):

| Credential key         | Present | Enabled |
|------------------------|---------|---------|
| `ai.openai.api_key`    | ❌       | N/A     |
| `ai.anthropic.api_key` | ✅       | ✅       |
| `ai.gemini.api_key`    | ✅       | ✅       |

---

## Configuration Architecture

### Key loading path (`cmd/cf-sync/ui_runtime.go:134–142`)

```go
aiCfg := ai.FromEnv()  // reads AI_PROVIDER_* env vars
if v, ok, _ := credentialStore.Lookup(ctx, "ai.openai.api_key"); ok {
    aiCfg.OpenAI.APIKey = v
}
if v, ok, _ := credentialStore.Lookup(ctx, "ai.anthropic.api_key"); ok {
    aiCfg.Anthropic.APIKey = v
}
if v, ok, _ := credentialStore.Lookup(ctx, "ai.gemini.api_key"); ok {
    aiCfg.Gemini.APIKey = v
}
```

**API keys** are loaded from SQLite credential store at startup. ✅

**Model names** are NOT loaded from the credential store. They come only from env vars:
- `AI_PROVIDER_OPENAI_MODEL`
- `AI_PROVIDER_ANTHROPIC_MODEL`
- `AI_PROVIDER_GEMINI_MODEL`

These env vars are not set → models default to `""` (empty string).

**Enabled flags** are NOT loaded from the credential store or SQLite ui_settings:
- `AI_PROVIDER_OPENAI_ENABLED` (default: false)
- `AI_PROVIDER_ANTHROPIC_ENABLED` (default: false)
- `AI_PROVIDER_GEMINI_ENABLED` (default: false)

With `Enabled=false`, the provider is not registered in the gateway even if the API key is present.

### AI gateway (`internal/ai/gateway/`)

The gateway is an "explain-only" service, used to generate natural-language explanations of security events. It supports:
- Provider strategy: `auto` (try in order), or specific provider
- Rate limiting: 10/min (configurable)
- Cache TTL: 15min
- Strict no-tools mode: true
- Max context: 12,000 bytes
- Max output: 800 tokens

### Provider factories (`cmd/cf-sync/ui_runtime.go:153–157`)

```go
ProviderFactories: map[string]ui.ProviderFactory{
    "openai":    func(pc ai.ProviderConfig) providers.Provider { return aiopenai.New(pc) },
    "anthropic": func(pc ai.ProviderConfig) providers.Provider { return aianthropic.New(pc) },
    "gemini":    func(pc ai.ProviderConfig) providers.Provider { return aigemini.New(pc) },
},
```

Factories are wired. The issue is that `pc.Enabled = false` for all providers, so `buildAIProviders()` returns an empty slice.

### Provider state file (`internal/config/config.go:264`)

```go
c.UI.ProviderStateFile = filepath.Join(c.StateDir, "runtime", "ai-providers.env")
```

Path: `/var/lib/security-automation-go/runtime/ai-providers.env`

This file is referenced in config but there is no code that reads or writes model configuration to/from this file. It appears to be a legacy placeholder for a feature not yet implemented.

---

## Provider Status Matrix

| Provider  | Key Present | Enabled | Model | Usable |
|-----------|-------------|---------|-------|--------|
| OpenAI    | ❌          | ❌      | ❌    | ❌     |
| Anthropic | ✅          | ❌      | ❌    | ❌     |
| Gemini    | ✅          | ❌      | ❌    | ❌     |

---

## Health Check

`internal/health/checks.go` — `ai-providers` check:

The health check for `ai-providers` reports GREEN when at least one API key is present and configured, RED when all are missing. Since Anthropic and Gemini keys are present, the health check shows GREEN or YELLOW, but this is misleading — the providers are disabled at runtime despite keys being configured.

---

## UI Audit

**Current UI pages related to AI:**
- `/intelligence` — uses AI explain gateway for event analysis
- `/about` — shows version info, may list configured providers

**Missing UI:**
- No page to enable/disable individual AI providers
- No page to configure model name per provider
- No page to test connectivity (send ping request to provider)
- The `ProviderStateFile` (`ai-providers.env`) is not used by any UI handler

---

## Problems Identified

| # | Severity | Problem |
|---|----------|---------|
| P1 | **Critique** | All AI providers disabled (`Enabled=false`). AI explain feature is non-functional despite 2 API keys being stored. |
| P2 | **Important** | Model names not configurable — no env var set, no UI, `ai-providers.env` not implemented. |
| P3 | **Important** | No UI to enable/disable AI providers or configure model. Changes require env var edits + service restart. |
| P4 | **Important** | OpenAI key missing from credential store. |
| P5 | **Cosmétique** | `ai-providers.env` path declared in config but file is never read or written. |
