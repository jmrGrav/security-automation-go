# AI Explain + MCP Read-Only Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a local read-only MCP surface and an operator-only AI explain endpoint without introducing any mutation path.

**Architecture:** Phase 1 builds a stdio-first MCP server that reads existing runtime, audit, timeline, trusted-network, provider-health, replay, recovery, drift, and security-intelligence projections and returns redacted JSON only. Phase 2 adds a CSRF-protected `/ui/ai/explain` endpoint that reuses the existing AI scaffolding for context-building, redaction, cache, quota, and policy, but falls back to a local synthetic explanation until external providers are explicitly enabled. Phase 3 adds disabled-by-default provider routing for OpenAI, Anthropic Claude, and Gemini with quota-aware selection and text-only responses. Phase 4 wires UI buttons and status affordances into the existing read-only operator shell.

**Tech Stack:** Go 1.22, `github.com/modelcontextprotocol/go-sdk/mcp`, existing `internal/ai/*` scaffolding, existing runtime/status/audit/timeline/security projection packages, stdlib `net/http`, existing `templ` UI shell.

---

### Task 1: Add the local MCP server package and CLI entrypoint

**Files:**
- Create: `cmd/security-automation-mcp/main.go`
- Create: `internal/mcpserver/server.go`
- Create: `internal/mcpserver/auth.go`
- Create: `internal/mcpserver/audit.go`
- Create: `internal/mcpserver/redaction.go`
- Create: `internal/mcpserver/tools_runtime.go`
- Create: `internal/mcpserver/tools_health.go`
- Create: `internal/mcpserver/tools_audit.go`
- Create: `internal/mcpserver/tools_timeline.go`
- Create: `internal/mcpserver/tools_security.go`
- Create: `internal/mcpserver/tools_trusted_networks.go`
- Create: `internal/mcpserver/tools_replay.go`
- Create: `internal/mcpserver/tools_recovery.go`
- Create: `internal/mcpserver/tools_drift.go`
- Create: `internal/mcpserver/server_test.go`
- Create: `internal/mcpserver/static_guard_test.go`

- [ ] **Step 1: Write failing tests for the server contract**

```go
func TestServerExposesReadOnlyTools(t *testing.T) {}
func TestServerRejectsForbiddenImports(t *testing.T) {}
func TestServerRedactsSecrets(t *testing.T) {}
```

- [ ] **Step 2: Run the focused tests and confirm failure**

Run: `GOTOOLCHAIN=local go test ./internal/mcpserver -run 'TestServerExposesReadOnlyTools|TestServerRejectsForbiddenImports|TestServerRedactsSecrets' -v`

- [ ] **Step 3: Implement the MCP server and minimal tool handlers**

```go
server := mcp.NewServer(&mcp.Implementation{Name: "security-automation-mcp", Version: version}, nil)
mcp.AddTool(server, &mcp.Tool{Name: "get_runtime_status", Description: "Read-only runtime status"}, handleGetRuntimeStatus)
```

- [ ] **Step 4: Re-run the focused tests**

Run: `GOTOOLCHAIN=local go test ./internal/mcpserver -run 'TestServerExposesReadOnlyTools|TestServerRejectsForbiddenImports|TestServerRedactsSecrets' -v`

- [ ] **Step 5: Wire the CLI to stdio by default and loopback HTTP only when explicitly requested**

```go
if opts.Transport == "stdio" { _ = server.Run(ctx, &mcp.StdioTransport{}) }
```

- [ ] **Step 6: Commit the phase-1 MCP slice**

```bash
git add cmd/security-automation-mcp internal/mcpserver
git commit -m "feat: add local read-only mcp server"
```

### Task 2: Add the operator-only AI explain endpoint

**Files:**
- Create: `internal/ai/gateway/server.go`
- Create: `internal/ai/gateway/server_test.go`
- Create: `internal/ai/contextbuilder/local.go`
- Create: `internal/ai/contextbuilder/local_test.go`
- Create: `internal/ai/cache/memory.go`
- Create: `internal/ai/cache/memory_test.go`
- Create: `internal/ai/policy/default.go`
- Create: `internal/ai/policy/default_test.go`
- Modify: `internal/ui/server.go`
- Modify: `internal/ui/helpers.go`
- Modify: `internal/ui/audit.go`

- [ ] **Step 1: Write failing tests for `/ui/ai/explain`**

```go
func TestAIExplainRequiresAuthAndCSRF(t *testing.T) {}
func TestAIExplainReturnsLocalSyntheticResponse(t *testing.T) {}
func TestAIExplainAuditsAndRedacts(t *testing.T) {}
```

- [ ] **Step 2: Run the focused tests and confirm failure**

Run: `GOTOOLCHAIN=local go test ./internal/ui ./internal/ai/... -run 'TestAIExplainRequiresAuthAndCSRF|TestAIExplainReturnsLocalSyntheticResponse|TestAIExplainAuditsAndRedacts' -v`

- [ ] **Step 3: Implement the gateway server and local fallback**

```go
func (g *Gateway) Explain(ctx context.Context, req ai.ExplainRequest) (ai.ExplainResponse, error)
```

- [ ] **Step 4: Add the POST route with auth, CSRF, rate limit, cache, and audit**

```go
s.mux.HandleFunc("POST /ui/ai/explain", s.requireAuth(s.handleAIExplain))
```

- [ ] **Step 5: Re-run the focused tests**

Run: `GOTOOLCHAIN=local go test ./internal/ui ./internal/ai/... -run 'TestAIExplainRequiresAuthAndCSRF|TestAIExplainReturnsLocalSyntheticResponse|TestAIExplainAuditsAndRedacts' -v`

- [ ] **Step 6: Commit the AI endpoint slice**

```bash
git add internal/ai internal/ui
git commit -m "feat: add read-only ai explain endpoint"
```

### Task 3: Add disabled-by-default provider routing

**Files:**
- Create: `internal/ai/providers/openai/provider.go`
- Create: `internal/ai/providers/anthropic/provider.go`
- Create: `internal/ai/providers/gemini/provider.go`
- Create: `internal/ai/gateway/router.go`
- Create: `internal/ai/gateway/router_test.go`
- Create: `internal/ai/providers/provider_test.go`

- [ ] **Step 1: Write failing tests for provider selection and cooldown**

```go
func TestRouterSkipsDisabledProviders(t *testing.T) {}
func TestRouterFallsBackOn429(t *testing.T) {}
func TestRouterSkipsExhaustedQuota(t *testing.T) {}
```

- [ ] **Step 2: Run the focused tests and confirm failure**

Run: `GOTOOLCHAIN=local go test ./internal/ai/... -run 'TestRouterSkipsDisabledProviders|TestRouterFallsBackOn429|TestRouterSkipsExhaustedQuota' -v`

- [ ] **Step 3: Implement the provider adapters and router**

```go
type Provider struct { enabled bool; timeout time.Duration }
```

- [ ] **Step 4: Re-run the focused tests**

Run: `GOTOOLCHAIN=local go test ./internal/ai/... -run 'TestRouterSkipsDisabledProviders|TestRouterFallsBackOn429|TestRouterSkipsExhaustedQuota' -v`

- [ ] **Step 5: Commit the routing slice**

```bash
git add internal/ai
git commit -m "feat: add ai provider routing"
```

### Task 4: Wire the UI explain button and result surface

**Files:**
- Modify: `internal/ui/timeline.go`
- Modify: `internal/ui/audit.go`
- Modify: `internal/ui/provider_health.go`
- Modify: `internal/ui/security_intelligence.go`
- Modify: `internal/ui/trusted_networks.go`
- Modify: `internal/ui/workflows.go`
- Modify: `internal/ui/server.go`
- Modify: `internal/ui/views.templ`
- Modify: `internal/ui/views_templ.go`
- Create: `internal/ui/ai_explain_test.go`

- [ ] **Step 1: Write failing tests for the button and result summary**

```go
func TestExplainWithAIButtonAppearsOnReadOnlyPages(t *testing.T) {}
func TestAIExplainResultNeverPrintsPrompt(t *testing.T) {}
```

- [ ] **Step 2: Run the focused tests and confirm failure**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run 'TestExplainWithAIButtonAppearsOnReadOnlyPages|TestAIExplainResultNeverPrintsPrompt' -v`

- [ ] **Step 3: Add the button and the result summary fields**

```templ
<button type="button">Explain with AI</button>
```

- [ ] **Step 4: Re-run the focused tests**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run 'TestExplainWithAIButtonAppearsOnReadOnlyPages|TestAIExplainResultNeverPrintsPrompt' -v`

- [ ] **Step 5: Commit the UI wiring**

```bash
git add internal/ui
git commit -m "feat: add ai explain ui affordances"
```

### Task 5: Add docs, captures, and full validation

**Files:**
- Create: `docs/security/AI_EXPLAIN_GATEWAY_MCP.md`
- Modify: `docs/security/AI_EXPLAIN_GATEWAY.md`
- Modify: `docs/AI_ASSISTANCE.md`

- [ ] **Step 1: Add the security and usage docs**
- [ ] **Step 2: Capture the browser evidence for the new UI states**
- [ ] **Step 3: Run the full validation suite**

Run:
```bash
GOTOOLCHAIN=local gofmt -w $(find . -type f -name '*.go' -not -path './vendor/*')
GOTOOLCHAIN=local go test ./...
GOTOOLCHAIN=local go test -race ./...
GOTOOLCHAIN=local go vet ./...
GOTOOLCHAIN=local go build ./...
GOTOOLCHAIN=local go test -tags=soak ./internal/testing/...
```

- [ ] **Step 4: Commit the tranche docs and evidence**

```bash
git add docs/security docs/AI_ASSISTANCE.md
git commit -m "docs: record ai explain and mcp read-only tranche"
```
