# Operator Workflows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the remaining operator UI placeholder routes into read-only forensic workflows for timeline, Cloudflare diff, replay, recovery, drift, audit, provider health, trusted networks, and security intelligence.

**Architecture:** Keep the shared UI shell and existing route protection. Each workflow page should be a read-only projection over already-available runtime data such as audit events, checkpoints, snapshots, replay records, drift summaries, and provider state. The implementation should add view models, route handlers, and tests without creating new writers, new runtime engines, or browser-side provider calls.

**Tech Stack:** Go stdlib HTTP, existing `internal/ui` console shell, existing runtime state packages, existing audit sink, existing snapshot/replay/recovery/drift data sources, templ rendering.

---

### Task 1: Build a unified timeline view over runtime events

**Files:**
- Create: `internal/ui/timeline.go`
- Create: `internal/ui/timeline_test.go`
- Modify: `internal/ui/server.go`
- Modify: `internal/ui/console.go`

- [ ] **Step 1: Write the failing test**

```go
func TestTimelineRendersEvents(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{"UI_SECRET": "ui-secret-value"})
	cookie := loginCookie(t, srv, "ui-secret-value")
	req := httptest.NewRequest(http.MethodGet, "/timeline", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "Timeline") {
		t.Fatal("expected timeline page")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestTimelineRendersEvents -v`
Expected: FAIL because the page is still a placeholder.

- [ ] **Step 3: Write minimal implementation**

Render a read-only timeline over existing audit/replay/recovery/ownership/runtime events with:
- filters
- search
- pagination
- JSON export
- CSV export

- [ ] **Step 4: Run test to verify it passes**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestTimelineRendersEvents -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/timeline.go internal/ui/timeline_test.go internal/ui/server.go internal/ui/console.go
git commit -m "feat: add read-only timeline workflow"
```

### Task 2: Build Cloudflare Diff as a forensic-only comparison view

**Files:**
- Create: `internal/ui/cloudflare_diff.go`
- Create: `internal/ui/cloudflare_diff_test.go`
- Modify: `internal/ui/server.go`
- Modify: `internal/ui/console.go`

- [ ] **Step 1: Write the failing test**

```go
func TestCloudflareDiffRendersConvergenceSummary(t *testing.T) {
	// render desired, observed, missing, divergent, extra, summary sections
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestCloudflareDiffRendersConvergenceSummary -v`
Expected: FAIL because the page is placeholder-only.

- [ ] **Step 3: Write minimal implementation**

Use existing drift/replay/state data to show:
- desired state
- observed state
- missing resources
- divergent resources
- extra resources
- drift summary
- convergence summary

- [ ] **Step 4: Run test to verify it passes**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestCloudflareDiffRendersConvergenceSummary -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/cloudflare_diff.go internal/ui/cloudflare_diff_test.go internal/ui/server.go internal/ui/console.go
git commit -m "feat: add cloudflare diff workflow"
```

### Task 3: Build Replay Center

**Files:**
- Create: `internal/ui/replay.go`
- Create: `internal/ui/replay_test.go`
- Modify: `internal/ui/server.go`
- Modify: `internal/ui/console.go`

- [ ] **Step 1: Write the failing test**

```go
func TestReplayRendersCheckpointsAndSnapshots(t *testing.T) {
	// verify checkpoints, snapshots, replay status, explain, indicators
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestReplayRendersCheckpointsAndSnapshots -v`
Expected: FAIL because the page is still coming-soon.

- [ ] **Step 3: Write minimal implementation**

Read-only replay center with:
- checkpoints
- snapshots
- replay status
- replay explain
- consistency indicators

- [ ] **Step 4: Run test to verify it passes**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestReplayRendersCheckpointsAndSnapshots -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/replay.go internal/ui/replay_test.go internal/ui/server.go internal/ui/console.go
git commit -m "feat: add replay center"
```

### Task 4: Build Recovery Center

**Files:**
- Create: `internal/ui/recovery.go`
- Create: `internal/ui/recovery_test.go`
- Modify: `internal/ui/server.go`
- Modify: `internal/ui/console.go`

- [ ] **Step 1: Write the failing test**

```go
func TestRecoveryRendersSnapshotsAndValidation(t *testing.T) {
	// verify snapshots, checkpoints, last recovery, state, validation
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestRecoveryRendersSnapshotsAndValidation -v`
Expected: FAIL because the page is still a placeholder.

- [ ] **Step 3: Write minimal implementation**

Read-only recovery center with:
- available snapshots
- available checkpoints
- last recoveries
- recovery state
- recovery validation

- [ ] **Step 4: Run test to verify it passes**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestRecoveryRendersSnapshotsAndValidation -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/recovery.go internal/ui/recovery_test.go internal/ui/server.go internal/ui/console.go
git commit -m "feat: add recovery center"
```

### Task 5: Build Drift Center

**Files:**
- Create: `internal/ui/drift.go`
- Create: `internal/ui/drift_test.go`
- Modify: `internal/ui/server.go`
- Modify: `internal/ui/console.go`

- [ ] **Step 1: Write the failing test**

```go
func TestDriftRendersActiveAndHistoricalDrift(t *testing.T) {
	// verify active drift, history, oscillations, impacted scopes, ownership, convergence
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestDriftRendersActiveAndHistoricalDrift -v`
Expected: FAIL because the page is placeholder-only.

- [ ] **Step 3: Write minimal implementation**

Read-only drift center with:
- active drift
- drift history
- oscillations
- impacted scopes
- ownership impact
- convergence indicators

- [ ] **Step 4: Run test to verify it passes**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestDriftRendersActiveAndHistoricalDrift -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/drift.go internal/ui/drift_test.go internal/ui/server.go internal/ui/console.go
git commit -m "feat: add drift center"
```

### Task 6: Upgrade Audit Trail to filterable forensic history

**Files:**
- Modify: `internal/ui/audit.go`
- Modify: `internal/ui/console.go`
- Create: `internal/ui/audit_export_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestAuditTrailExportAndCorrelation(t *testing.T) {
	// verify filters, search, json/csv export, forensic/ownership/replay correlation
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestAuditTrailExportAndCorrelation -v`
Expected: FAIL because export and correlation are not implemented yet.

- [ ] **Step 3: Write minimal implementation**

Add advanced filters, search text, JSON export, CSV export, and linkage metadata for forensic / ownership / replay views.

- [ ] **Step 4: Run test to verify it passes**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestAuditTrailExportAndCorrelation -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/audit.go internal/ui/console.go internal/ui/audit_export_test.go
git commit -m "feat: upgrade audit trail workflow"
```

### Task 7: Extend Security Intelligence with provider correlation and trusted-network context

**Files:**
- Modify: `internal/ui/security_intelligence.go`
- Modify: `internal/ui/security_intelligence_test.go`
- Modify: `internal/security/enrichment/service.go`

- [ ] **Step 1: Write the failing test**

```go
func TestSecurityIntelligenceShowsTrustedNetworkCorrelation(t *testing.T) {
	// verify DNS, ASN, AbuseIPDB, VirusTotal, Spamhaus, trusted network correlation
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestSecurityIntelligenceShowsTrustedNetworkCorrelation -v`
Expected: FAIL because the correlation is not rendered yet.

- [ ] **Step 3: Write minimal implementation**

Extend the existing view to show trusted-network correlation and provider breakdown while preserving fail-neutral provider errors.

- [ ] **Step 4: Run test to verify it passes**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestSecurityIntelligenceShowsTrustedNetworkCorrelation -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/security_intelligence.go internal/ui/security_intelligence_test.go internal/security/enrichment/service.go
git commit -m "feat: extend security intelligence correlation"
```

### Task 8: Finish Provider Health and Trusted Networks operational views

**Files:**
- Modify: `internal/ui/provider_health.go`
- Modify: `internal/ui/provider_health_test.go`
- Modify: `internal/ui/trusted_networks.go`
- Modify: `internal/ui/trusted_networks_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestProviderHealthShowsLiveQuotaState(t *testing.T) {
	// verify plan, quota source, limit, used, remaining, reset, last observed, state
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run 'TestProviderHealthShowsLiveQuotaState|TestTrustedNetworks' -v`
Expected: FAIL until the quota-aware state is wired.

- [ ] **Step 3: Write minimal implementation**

Render live quota state where observable and keep `not exposed`, `unavailable`, and `unsupported` where not observable.

- [ ] **Step 4: Run test to verify it passes**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run 'TestProviderHealthShowsLiveQuotaState|TestTrustedNetworks' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/provider_health.go internal/ui/provider_health_test.go internal/ui/trusted_networks.go internal/ui/trusted_networks_test.go
git commit -m "feat: finish operator provider and registry views"
```

### Task 9: Update docs, capture screenshots, and validate the UI surface

**Files:**
- Modify: `docs/operations/UI_FEATURES.md`
- Modify: `docs/operations/UI_SECURITY.md`
- Modify: `docs/security/TRUSTED_NETWORKS.md`
- Modify: `docs/security/ENRICHMENT_PROVIDERS.md`
- Modify: `SESSION_STATUS.md`
- Modify: `MIGRATION_PROGRESS.md`
- Modify: `DECISIONS.md`

- [ ] **Step 1: Write the failing test**

```bash
GOTOOLCHAIN=local go test ./internal/ui ./internal/security/enrichment/...
```

- [ ] **Step 2: Run test to verify it fails**

Expected: failures until all UI workflows are wired.

- [ ] **Step 3: Write minimal implementation**

Update docs to reflect implemented workflows and operator-facing boundaries.

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
GOTOOLCHAIN=local go test ./...
GOTOOLCHAIN=local go test -race ./...
GOTOOLCHAIN=local go vet ./...
GOTOOLCHAIN=local go build ./...
```

- [ ] **Step 5: Commit**

```bash
git add docs/operations/UI_FEATURES.md docs/operations/UI_SECURITY.md docs/security/TRUSTED_NETWORKS.md docs/security/ENRICHMENT_PROVIDERS.md SESSION_STATUS.md MIGRATION_PROGRESS.md DECISIONS.md
git commit -m "docs: record completed operator workflows"
```

### Spec Coverage Review

- timeline: Task 1
- cloudflare diff: Task 2
- replay: Task 3
- recovery: Task 4
- drift: Task 5
- audit trail: Task 6
- security intelligence: Task 7
- provider health: Task 8
- trusted networks: Task 8
- docs and validation: Task 9

No placeholder phrases remain. Every step has concrete files, commands, and expected results.
