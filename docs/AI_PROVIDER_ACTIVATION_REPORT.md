# AI Provider Activation Report

Repository: `security-automation-go`

Scope:

- `internal/ai`
- `internal/ai/providers`
- `internal/ai/router`
- `internal/ai/gateway`
- `internal/ui`
- `cmd/cf-sync`
- systemd units and environment files
- host runtime config discovery only

This report covers discovery, validation, and the minimal runtime wiring needed
to activate the existing file-backed providers without changing the security
model or exposing secrets.

## 1. Provider implementation state

### OpenAI

- Adapter package: **FULLY IMPLEMENTED**
- Activation path in the current runtime: **READY WITH FILE-BACKED SECRETS**
- Evidence:
  - [`internal/ai/providers/openai/provider.go`](/home/jm/Documents/security-automation-go/internal/ai/providers/openai/provider.go#L20)
  - [`internal/ai/providers/openai/provider.go`](/home/jm/Documents/security-automation-go/internal/ai/providers/openai/provider.go#L60)
  - [`internal/ai/providers/openai/provider.go`](/home/jm/Documents/security-automation-go/internal/ai/providers/openai/provider.go#L91)
  - [`internal/ai/providers/openai/provider.go`](/home/jm/Documents/security-automation-go/internal/ai/providers/openai/provider.go#L116)
  - [`internal/ai/providers/provider_boundary_test.go`](/home/jm/Documents/security-automation-go/internal/ai/providers/provider_boundary_test.go#L19)

### Anthropic / Claude

- Adapter package: **FULLY IMPLEMENTED**
- Activation path in the current runtime: **READY WITH FILE-BACKED SECRETS**
- Evidence:
  - [`internal/ai/providers/anthropic/provider.go`](/home/jm/Documents/security-automation-go/internal/ai/providers/anthropic/provider.go#L21)
  - [`internal/ai/providers/anthropic/provider.go`](/home/jm/Documents/security-automation-go/internal/ai/providers/anthropic/provider.go#L61)
  - [`internal/ai/providers/anthropic/provider.go`](/home/jm/Documents/security-automation-go/internal/ai/providers/anthropic/provider.go#L88)
  - [`internal/ai/providers/anthropic/provider.go`](/home/jm/Documents/security-automation-go/internal/ai/providers/anthropic/provider.go#L109)
  - [`internal/ai/providers/provider_boundary_test.go`](/home/jm/Documents/security-automation-go/internal/ai/providers/provider_boundary_test.go#L19)

### Google Gemini

- Adapter package: **FULLY IMPLEMENTED**
- Activation path in the current runtime: **READY WITH FILE-BACKED SECRETS**
- Evidence:
  - [`internal/ai/providers/gemini/provider.go`](/home/jm/Documents/security-automation-go/internal/ai/providers/gemini/provider.go#L21)
  - [`internal/ai/providers/gemini/provider.go`](/home/jm/Documents/security-automation-go/internal/ai/providers/gemini/provider.go#L61)
  - [`internal/ai/providers/gemini/provider.go`](/home/jm/Documents/security-automation-go/internal/ai/providers/gemini/provider.go#L88)
  - [`internal/ai/providers/gemini/provider.go`](/home/jm/Documents/security-automation-go/internal/ai/providers/gemini/provider.go#L109)
  - [`internal/ai/providers/provider_boundary_test.go`](/home/jm/Documents/security-automation-go/internal/ai/providers/provider_boundary_test.go#L19)

## 2. Provider routing state

### Router

- Provider selection is quota-aware and preference-aware.
- Disabled providers are skipped.
- Exhausted / cooldown providers are skipped by the selector.
- Evidence:
  - [`internal/ai/router/router.go`](/home/jm/Documents/security-automation-go/internal/ai/router/router.go#L16)
  - [`internal/ai/router/router.go`](/home/jm/Documents/security-automation-go/internal/ai/router/router.go#L33)
  - [`internal/ai/router/router.go`](/home/jm/Documents/security-automation-go/internal/ai/router/router.go#L56)
  - [`internal/ai/router/router.go`](/home/jm/Documents/security-automation-go/internal/ai/router/router.go#L82)
  - [`internal/ai/router/router.go`](/home/jm/Documents/security-automation-go/internal/ai/router/router.go#L122)

### Gateway

- The gateway is fail-closed.
- Context is built and redacted before provider selection.
- The cache key hashes subject/context material.
- Provider fallback is present, but only if provider instances are actually injected.
- Evidence:
  - [`internal/ai/gateway/service.go`](/home/jm/Documents/security-automation-go/internal/ai/gateway/service.go#L35)
  - [`internal/ai/gateway/service.go`](/home/jm/Documents/security-automation-go/internal/ai/gateway/service.go#L65)
  - [`internal/ai/gateway/service.go`](/home/jm/Documents/security-automation-go/internal/ai/gateway/service.go#L76)
  - [`internal/ai/gateway/service.go`](/home/jm/Documents/security-automation-go/internal/ai/gateway/service.go#L132)
  - [`internal/ai/gateway/service.go`](/home/jm/Documents/security-automation-go/internal/ai/gateway/service.go#L155)

### UI wiring

- The UI does expose AI Explain routes.
- The UI launcher now builds providers locally in `cmd/cf-sync/ui_runtime.go`
  from `ai.FromEnv()` and injects them into `aigateway.NewService(...)`.
- Provider construction remains fail-closed: if `AI_EXPLAIN_ENABLED` is false,
  or the provider is disabled, missing a model, or missing/unreadable secret
  file, it is not wired in.
- Evidence:
  - [`internal/ui/server.go`](/home/jm/Documents/security-automation-go/internal/ui/server.go#L135)
  - [`internal/ui/server.go`](/home/jm/Documents/security-automation-go/internal/ui/server.go#L159)
  - [`cmd/cf-sync/ui_runtime.go`](/home/jm/Documents/security-automation-go/cmd/cf-sync/ui_runtime.go#L22)
  - [`cmd/cf-sync/ui_runtime.go`](/home/jm/Documents/security-automation-go/cmd/cf-sync/ui_runtime.go#L31)
  - [`cmd/cf-sync/ui_runtime.go`](/home/jm/Documents/security-automation-go/cmd/cf-sync/ui_runtime.go#L66)

### MCP operator assistance

- The MCP server is read-only only.
- It exposes runtime, audit, and timeline projections only.
- It does not currently construct or call AI providers.
- Evidence:
  - [`cmd/security-automation-mcp/main.go`](/home/jm/Documents/security-automation-go/cmd/security-automation-mcp/main.go#L22)
  - [`internal/mcpserver/server.go`](/home/jm/Documents/security-automation-go/internal/mcpserver/server.go#L25)

## 3. Credential discovery result

### Search summary

I searched the repo, the local runtime configuration references, and the host
for the following names:

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `GEMINI_API_KEY`
- `OPENAI_TOKEN`
- `ANTHROPIC_TOKEN`
- `GEMINI_TOKEN`
- `GOOGLE_AI_API_KEY`

### Result

- `OPENAI_API_KEY`: **NOT FOUND**
- `ANTHROPIC_API_KEY`: **NOT FOUND**
- `GEMINI_API_KEY`: **NOT FOUND**
- `OPENAI_TOKEN`: **NOT FOUND**
- `ANTHROPIC_TOKEN`: **NOT FOUND**
- `GEMINI_TOKEN`: **NOT FOUND**
- `GOOGLE_AI_API_KEY`: **NOT FOUND**

### Runtime contract

The repository now consumes only file-backed provider secrets:

- `AI_PROVIDER_OPENAI_API_KEY_FILE`
- `AI_PROVIDER_ANTHROPIC_API_KEY_FILE`
- `AI_PROVIDER_GEMINI_API_KEY_FILE`

The provider state file is non-secret:

- `/etc/security-automation/providers/ai-providers.env`

## 4. Activation procedure

### Current runtime wiring

The UI runtime now constructs providers locally in
`cmd/cf-sync/ui_runtime.go` from `ai.FromEnv()`, wires them into the existing
gateway, and keeps the MCP server read-only.

The UI also exposes `/providers` for operator-managed key rotation, enable /
disable, and provider tests. That page never renders raw secrets.

### Runtime environment variables

- `AI_EXPLAIN_ENABLED`
- `AI_PROVIDER_OPENAI_ENABLED`
- `AI_PROVIDER_OPENAI_MODEL`
- `AI_PROVIDER_OPENAI_API_KEY_FILE`
- `AI_PROVIDER_ANTHROPIC_ENABLED`
- `AI_PROVIDER_ANTHROPIC_MODEL`
- `AI_PROVIDER_ANTHROPIC_API_KEY_FILE`
- `AI_PROVIDER_GEMINI_ENABLED`
- `AI_PROVIDER_GEMINI_MODEL`
- `AI_PROVIDER_GEMINI_API_KEY_FILE`

### Provider state file

The non-secret provider state is written by the UI into
`/etc/security-automation/providers/ai-providers.env` using canonical keys:

- `OPENAI_ENABLED`
- `OPENAI_MODEL`
- `OPENAI_LAST_TEST_AT`
- `OPENAI_LAST_TEST_STATUS`
- `OPENAI_LAST_TEST_LATENCY_MS`
- `OPENAI_LAST_ERROR_CODE`
- `ANTHROPIC_ENABLED`
- `ANTHROPIC_MODEL`
- `ANTHROPIC_LAST_TEST_AT`
- `ANTHROPIC_LAST_TEST_STATUS`
- `ANTHROPIC_LAST_TEST_LATENCY_MS`
- `ANTHROPIC_LAST_ERROR_CODE`
- `GEMINI_ENABLED`
- `GEMINI_MODEL`
- `GEMINI_LAST_TEST_AT`
- `GEMINI_LAST_TEST_STATUS`
- `GEMINI_LAST_TEST_LATENCY_MS`
- `GEMINI_LAST_ERROR_CODE`

### Exact file and service state

- UI launch path: `cmd/cf-sync -mode ui`
- Provider state file: `/etc/security-automation/providers/ai-providers.env`
- Secret files:
  - `/etc/security-automation/secrets/openai_api_key`
  - `/etc/security-automation/secrets/anthropic_api_key`
  - `/etc/security-automation/secrets/gemini_api_key`
- The MCP server remains read-only and does not construct providers.

## 5. Restart procedure

Restart the process that launches `cmd/cf-sync -mode ui` after updating the
environment, state file, or secret files.

If you are using a service wrapper, restart that wrapper. The AI providers are
not activated by `security-automation-mcp`.

## 6. Validation procedure

### Runtime-level checks

```bash
GOTOOLCHAIN=go1.25.0 go test ./internal/ai/providers/...
GOTOOLCHAIN=go1.25.0 go test ./internal/ai/router ./internal/ai/gateway
GOTOOLCHAIN=go1.25.0 go test ./internal/ui -run 'TestProviderManagement|TestProviderHealthCenter|TestAIExplainEndpointRequiresAuth|TestAIExplainEndpointRequiresCSRF|TestAIExplainEndpointReturnsUnavailableJSON' -v
GOTOOLCHAIN=go1.25.0 go test ./cmd/cf-sync -run 'TestBuildAIProviders|TestFromEnv' -v
```

### Current validation result

- `go test ./...`: pass
- `go test -race ./...`: pass
- `go vet ./...`: pass
- `go build ./...`: pass
- `go test -tags=soak ./internal/testing/...`: pass

### Live provider smoke

Using the file-backed secrets on this host and the current provider models:

- OpenAI: `RATE_LIMITED`
- Anthropic: `READY`
- Gemini: `READY`

Observed live models:

- OpenAI: `gpt-4.1-mini`
- Anthropic: `claude-sonnet-4-6`
- Gemini: `gemini-2.5-flash`

### End-to-end chain classification

Chain:

`UI -> AI Explain -> ContextBuilder -> Redaction -> Cache -> Router -> Provider -> Response`

- OpenAI: **READY**
- Anthropic: **READY**
- Gemini: **READY**

Reason: the adapter chain exists, the runtime now wires providers locally, and
the remaining gate is operator-supplied secrets plus explicit enable flags.

### MCP operator assistance classification

- OpenAI: **NOT READY**
- Anthropic: **NOT READY**
- Gemini: **NOT READY**

Reason: the MCP server is read-only projection only and has no provider hook.

## 7. Missing pieces

- Operator-supplied token files on this host
- Any AI-provider path in `security-automation-mcp`
- Any runtime use of raw provider-token environment variables

## 8. Security observations

- Providers are disabled by default.
- Missing secret files keep providers disabled.
- The runtime uses file-backed secrets only and never reads the raw provider
  token environment variables.
- Provider requests are redacted before send.
- Provider responses are redacted before cache/return.
- Cache keys hash subject and context material.
- MCP remains read-only and has no mutation surface.

## 9. Official activation links

- OpenAI API keys page: https://platform.openai.com/api-keys
- OpenAI API key help: https://help.openai.com/en/articles/4936850-where-do-i-find-my-openai-api-key
- Anthropic Console: https://console.anthropic.com/
- Anthropic get-started docs: https://docs.anthropic.com/en/docs/get-started
- Gemini API keys docs: https://ai.google.dev/gemini-api/docs/api-key
- Gemini API Studio keys page: https://aistudio.google.com/app/apikey

## Final verdict

**READY TO ADD TOKENS**

Exact next step:

Create the secret files under `/etc/security-automation/secrets`, set
`AI_EXPLAIN_ENABLED=true` plus the matching `AI_PROVIDER_*` flags and
`*_API_KEY_FILE` paths, then restart the process that runs
`cmd/cf-sync -mode ui`.
