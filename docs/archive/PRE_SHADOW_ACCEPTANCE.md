# Pre-Shadow Acceptance

## Scope

Acceptance review for the current `security-automation-go` tranche before
entering real shadow mode. No new feature work was added.

## Commands executed

- `GOTOOLCHAIN=go1.25.0 gofmt -w $(find . -type f -name '*.go' -not -path './vendor/*')`
- `GOTOOLCHAIN=go1.25.0 go test ./...`
- `GOTOOLCHAIN=go1.25.0 go test -race ./...`
- `GOTOOLCHAIN=go1.25.0 go vet ./...`
- `GOTOOLCHAIN=go1.25.0 go build ./...`
- `GOTOOLCHAIN=go1.25.0 go test -tags=soak ./internal/testing/...`
- `go run ./cmd/cf-sync -mode doctor`
- `go run ./cmd/cf-sync -mode status`
- `timeout 3s go run ./cmd/security-automation-mcp`

## Results

- Baseline validation: green.
- `cf-sync -mode doctor`: failed cleanly because configuration was missing
  `CF_API_TOKEN`.
- `cf-sync -mode status`: failed cleanly because configuration was missing
  `CF_API_TOKEN`.
- `security-automation-mcp`: started on stdio and remained in read-only
  transport mode until terminated by timeout; no crash was observed.
- `brooks-audit` and `brooks-test` binaries were not installed in this
  environment, so the Brooks review was performed manually against the Brooks
  guides and the live code tree.

## Wiring matrix

| Component | Status | Evidence |
|---|---|---|
| Quota refresh orchestrator | WIRED | `cmd/cf-sync/daemon_runtime.go`, `cmd/cf-sync/quota_refresh.go` |
| Provider quota state UI | WIRED | `internal/ui/server.go`, `internal/ui/provider_health.go` |
| AI Explain endpoint | WIRED | `internal/ui/server.go`, `internal/ui/ai_explain_test.go` |
| OpenAI adapter | WIRED | `internal/ai/providers/openai/provider.go` |
| Anthropic adapter | WIRED | `internal/ai/providers/anthropic/provider.go` |
| Gemini adapter | WIRED | `internal/ai/providers/gemini/provider.go` |
| AI provider routing | WIRED | `internal/ai/router/router.go` |
| AI cache | WIRED | `internal/ai/cache/memory.go` |
| AI redaction | WIRED | `internal/ai/gateway/service.go`, `internal/ai/redaction/default.go` |
| MCP stdio server | WIRED | `cmd/security-automation-mcp/main.go`, `internal/mcpserver/server.go` |
| MCP tools | WIRED | `internal/mcpserver/server.go` |
| MCP audit sink | WIRED | `cmd/security-automation-mcp/main.go`, `internal/mcpserver/server.go` |
| MCP redaction | WIRED | `internal/mcpserver/redaction.go` |
| Scheduler bounded queue | WIRED | `internal/runtime/scheduler/queue/work_queue.go` |
| Journal retention / rotation | WIRED | `internal/runtime/journal/journal.go` |
| Timeline cap | WIRED | `internal/runtime/timeline/collector.go` |
| Reporting evidence retention | WIRED | `internal/services/reporting/evidence_recorder.go`, `internal/storage/sqlite/reporting_evidence.go` |
| Report outbox retention | WIRED | `internal/services/reporting/outbox.go`, `internal/storage/sqlite/report_outbox.go` |
| Decision gate pruning | WIRED | `internal/services/reporting/decision_gate.go` |
| Raw event archive compaction | WIRED | `internal/runtime/checkpoint/checkpoint.go`, `internal/storage/sqlite/events.go` |
| Checkpoint-aware replay after compaction | WIRED | `internal/runtime/events/events_test.go`, `internal/runtime/checkpoint/checkpoint.go` |

## Security invariant matrix

| Invariant | Status | Evidence |
|---|---|---|
| No new Cloudflare writer | PASS | no new writer imported into AI/MCP/UI; Cloudflare mutation remains behind existing runtime path |
| No new CrowdSec writer | PASS | no new writer imported into AI/MCP/UI; write boundary remains in the existing CrowdSec client path |
| No shell / `os/exec` in AI/MCP/UI | PASS | `internal/ai/guard_test.go`, `internal/mcpserver/static_guard_test.go` |
| No SQLite write in AI/MCP | PASS | no `ensureWritable` / sqlite writer usage inside AI or MCP packages |
| No recovery restore from UI/MCP/AI | PASS | recovery remains in runtime/control-plane packages, not UI/MCP/AI |
| No active replay from UI/MCP/AI | PASS | replay logic remains in runtime packages and the UI/MCP layers are read-only projections |
| No secrets in logs / audit / cache | PASS | `internal/security/redaction`, `internal/ui/audit_redaction.go`, `internal/ai/gateway/service.go` |
| No provider tokens displayed | PASS | provider health pages mask keys; tests assert no raw secrets are rendered |
| No dependency on the unrelated Hugo MCP runtime | PASS | repository search returned no hits; static guards also cover the path |
| CSP self-only | PASS | `internal/ui/server.go` security headers set `Content-Security-Policy` to self-only scripts |
| UI auth required | PASS | protected routes go through `requireAuth` |
| CSRF required on POST | PASS | mutation route checks `validCSRF` |
| MCP read-only only | PASS | only `get_runtime_status`, `get_audit_logs`, `get_timeline` are registered |
| AI disabled by default without secret | PASS | `internal/ai/config.go`, `internal/ai/providers/provider_boundary_test.go` |
| Missing secret = no network call | PASS | provider boundary tests assert zero hits |

## Brooks findings

- No blocking architecture finding.
- No blocking test-quality finding.
- The main architectural hub remains `cmd/cf-sync` as composition root, but it is
  an acceptable wiring boundary rather than an abuse of business logic.

## Fixes applied in this pass

- No code changes were required during the acceptance review itself.
- The review only verified the existing hardening tranche and updated the
  status/decision docs.

## Residuals

- `shadow-status` is not implemented as a `cf-sync` mode.
- `brooks-audit` / `brooks-test` binaries are not installed locally, so the
  Brooks review was manual rather than tool-driven.

## Verdict

GO SHADOW
