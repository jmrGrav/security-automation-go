# Quota Awareness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make provider quota state operationally visible and safety-aware for Cloudflare, AbuseIPDB, VirusTotal, and Spamhaus without adding any new writer or browser-side provider calls.

**Architecture:** Reuse existing HTTP transport seams and add a small read-only quota model that can ingest response headers or lightweight official quota endpoints. Quota refresh must be cache-backed, timeout-bounded, context-aware, and fail-neutral. The UI consumes the normalized quota state only; any automatic throttling or suspension is driven by server-side state and audit/telemetry events, not by browser logic.

**Tech Stack:** Go stdlib, existing `internal/httpclient`, existing Cloudflare and AbuseIPDB transports, new read-only VT/Spamhaus quota clients, existing audit sink, existing telemetry metrics, existing UI shell.

---

### Task 1: Define the quota state model and policy boundary

**Files:**
- Create: `internal/security/quota/state.go`
- Create: `internal/security/quota/policy.go`
- Create: `internal/security/quota/state_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestClassifyState(t *testing.T) {
	tests := []struct {
		name      string
		remaining float64
		known     bool
		want      State
	}{
		{name: "unknown", remaining: 0, known: false, want: Unknown},
		{name: "full", remaining: 90, known: true, want: Normal},
		{name: "warning", remaining: 15, known: true, want: Warning},
		{name: "throttled", remaining: 5, known: true, want: Throttled},
		{name: "exhausted", remaining: 0, known: true, want: Exhausted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.known, tt.remaining); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOTOOLCHAIN=local go test ./internal/security/quota -run TestClassifyState -v`
Expected: FAIL because the package and symbols do not exist yet.

- [ ] **Step 3: Write minimal implementation**

```go
package quota

type State string

const (
	Normal    State = "NORMAL"
	Warning   State = "WARNING"
	Throttled State = "THROTTLED"
	Exhausted State = "EXHAUSTED"
	Unknown   State = "UNKNOWN"
)

func Classify(known bool, remainingPercent float64) State {
	if !known {
		return Unknown
	}
	if remainingPercent == 0 {
		return Exhausted
	}
	if remainingPercent <= 5 {
		return Throttled
	}
	if remainingPercent <= 15 {
		return Warning
	}
	return Normal
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `GOTOOLCHAIN=local go test ./internal/security/quota -run TestClassifyState -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/quota/state.go internal/security/quota/policy.go internal/security/quota/state_test.go
git commit -m "feat: add provider quota state model"
```

### Task 2: Capture quota headers from existing Cloudflare and AbuseIPDB transports

**Files:**
- Modify: `internal/httpclient/client.go`
- Modify: `internal/cloudflare/transport/transport.go`
- Modify: `internal/abuseipdb/transport/transport.go`
- Create: `internal/security/quota/headers.go`
- Create: `internal/security/quota/headers_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestParseCloudflareHeaders(t *testing.T) {
	resp := &http.Response{Header: http.Header{
		"Ratelimit":         []string{`"default";r=50;t=30`},
		"Ratelimit-Policy":  []string{`"burst";q=100;w=60`},
		"Retry-After":       []string{"12"},
	}}
	got := ParseCloudflare(resp.Header)
	if got.Remaining != 50 || got.ResetSeconds != 30 {
		t.Fatalf("got %+v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOTOOLCHAIN=local go test ./internal/security/quota -run TestParseCloudflareHeaders -v`
Expected: FAIL because parsing helpers are not implemented yet.

- [ ] **Step 3: Write minimal implementation**

```go
type Observation struct {
	Known         bool
	Remaining     float64
	Limit         float64
	ResetSeconds  int
	Source        string
	ObservedAt    time.Time
}

func ParseCloudflare(h http.Header) Observation
func ParseAbuseIPDB(h http.Header) Observation
```

Make `Cloudflare.Transport.Request` and `AbuseIPDB.Transport` pass response headers into the hook path without changing request semantics.

- [ ] **Step 4: Run test to verify it passes**

Run: `GOTOOLCHAIN=local go test ./internal/security/quota -run 'TestParseCloudflareHeaders|TestParseAbuseIPDBHeaders' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/httpclient/client.go internal/cloudflare/transport/transport.go internal/abuseipdb/transport/transport.go internal/security/quota/headers.go internal/security/quota/headers_test.go
git commit -m "feat: capture provider quota headers"
```

### Task 3: Add read-only VirusTotal quota client

**Files:**
- Create: `internal/security/enrichment/virustotal/quota_client.go`
- Create: `internal/security/enrichment/virustotal/quota_client_test.go`
- Modify: `internal/security/enrichment/service.go`
- Modify: `internal/ui/security_intelligence.go`

- [ ] **Step 1: Write the failing test**

```go
func TestVirusTotalQuotaClientReadsUserQuota(t *testing.T) {
	client := newFakeVTQuotaClient(t)
	state, err := client.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.Limit <= 0 || state.Remaining < 0 {
		t.Fatalf("invalid state: %+v", state)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOTOOLCHAIN=local go test ./internal/security/enrichment/virustotal -run TestVirusTotalQuotaClientReadsUserQuota -v`
Expected: FAIL because the quota client does not exist yet.

- [ ] **Step 3: Write minimal implementation**

```go
func (c *QuotaClient) Fetch(ctx context.Context) (quota.StateObservation, error) {
	// GET /api/v3/users/{id} or /api/v3/users/{id}/api_usage
	// Use x-apikey, cache results, derive remaining percent, and keep failures neutral.
}
```

The client must only read official quota endpoints and must cache results for 30 minutes minimum.

- [ ] **Step 4: Run test to verify it passes**

Run: `GOTOOLCHAIN=local go test ./internal/security/enrichment/virustotal -run TestVirusTotalQuotaClientReadsUserQuota -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/enrichment/virustotal/quota_client.go internal/security/enrichment/virustotal/quota_client_test.go internal/security/enrichment/service.go internal/ui/security_intelligence.go
git commit -m "feat: add read-only VirusTotal quota client"
```

### Task 4: Add read-only Spamhaus limits client

**Files:**
- Create: `internal/security/enrichment/spamhaus/quota_client.go`
- Create: `internal/security/enrichment/spamhaus/quota_client_test.go`
- Modify: `internal/security/enrichment/service.go`
- Modify: `internal/ui/security_intelligence.go`

- [ ] **Step 1: Write the failing test**

```go
func TestSpamhausQuotaClientReadsLimits(t *testing.T) {
	client := newFakeSpamhausQuotaClient(t)
	state, err := client.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.Limit <= 0 || state.Used < 0 {
		t.Fatalf("invalid state: %+v", state)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOTOOLCHAIN=local go test ./internal/security/enrichment/spamhaus -run TestSpamhausQuotaClientReadsLimits -v`
Expected: FAIL because the quota client does not exist yet.

- [ ] **Step 3: Write minimal implementation**

```go
func (c *QuotaClient) Fetch(ctx context.Context) (quota.StateObservation, error) {
	// GET /api/intel/v1/limits or CHECK_QUOTA equivalent, cache results, derive remaining percent.
}
```

The client must use official limits APIs only and must not scrape web pages.

- [ ] **Step 4: Run test to verify it passes**

Run: `GOTOOLCHAIN=local go test ./internal/security/enrichment/spamhaus -run TestSpamhausQuotaClientReadsLimits -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/enrichment/spamhaus/quota_client.go internal/security/enrichment/spamhaus/quota_client_test.go internal/security/enrichment/service.go internal/ui/security_intelligence.go
git commit -m "feat: add read-only Spamhaus quota client"
```

### Task 5: Wire quota state into UI, metrics, and audit

**Files:**
- Modify: `internal/ui/provider_health.go`
- Modify: `internal/ui/console.go`
- Modify: `internal/ui/server.go`
- Modify: `internal/observability/metrics/metrics.go`
- Modify: `internal/ui/audit.go`
- Create: `internal/ui/quota_state_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestProviderQuotaStateRendering(t *testing.T) {
	// verify NORMAL/WARNING/THROTTLED/EXHAUSTED/UNKNOWN render correctly
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestProviderQuotaStateRendering -v`
Expected: FAIL because quota state is not wired into UI yet.

- [ ] **Step 3: Write minimal implementation**

Add the quota state to provider view models and render:
- `provider_quota_remaining_percent`
- `provider_quota_state`
- `provider_quota_refresh_failures_total`
- `provider_auto_throttle_total`
- `provider_auto_disable_total`
- `provider_auto_reenable_total`

Add audit events:
- `provider_quota_warning`
- `provider_quota_throttled`
- `provider_quota_exhausted`
- `provider_quota_recovered`

- [ ] **Step 4: Run test to verify it passes**

Run: `GOTOOLCHAIN=local go test ./internal/ui -run TestProviderQuotaStateRendering -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/provider_health.go internal/ui/console.go internal/ui/server.go internal/observability/metrics/metrics.go internal/ui/audit.go internal/ui/quota_state_test.go
git commit -m "feat: expose provider quota state in ui"
```

### Task 6: Add server-side protection policy for quota exhaustion and recovery

**Files:**
- Create: `internal/security/quota/protector.go`
- Create: `internal/security/quota/protector_test.go`
- Modify: `internal/app/app.go`
- Modify: `internal/services/reporting/service.go`

- [ ] **Step 1: Write the failing test**

```go
func TestProtectorTransitions(t *testing.T) {
	// NORMAL -> WARNING -> THROTTLED -> EXHAUSTED -> RECOVERED
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOTOOLCHAIN=local go test ./internal/security/quota -run TestProtectorTransitions -v`
Expected: FAIL because the protection policy does not exist yet.

- [ ] **Step 3: Write minimal implementation**

Implement read-only protection state transitions that:
- reduce optional enrichment calls at THROTTLED
- suspend provider-dependent functions at EXHAUSTED
- auto-recover on the next successful refresh
- stay fail-neutral on UNKNOWN

- [ ] **Step 4: Run test to verify it passes**

Run: `GOTOOLCHAIN=local go test ./internal/security/quota -run TestProtectorTransitions -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/security/quota/protector.go internal/security/quota/protector_test.go internal/app/app.go internal/services/reporting/service.go
git commit -m "feat: add quota protection policy"
```

### Task 7: Update docs and add runtime validation

**Files:**
- Modify: `docs/security/ENRICHMENT_PROVIDERS.md`
- Modify: `docs/operations/UI_SECURITY.md`
- Modify: `SESSION_STATUS.md`
- Modify: `MIGRATION_PROGRESS.md`
- Modify: `DECISIONS.md`

- [ ] **Step 1: Write the failing test**

```bash
GOTOOLCHAIN=local go test ./...
```

- [ ] **Step 2: Run test to verify it fails**

Expected: at least one failing test until the quota wiring is complete.

- [ ] **Step 3: Write minimal implementation**

Document:
- observed runtime quota state
- configured free-tier fallback values only when real data is unavailable
- provider-specific refresh periods
- fail-neutral behavior

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
git add docs/security/ENRICHMENT_PROVIDERS.md docs/operations/UI_SECURITY.md SESSION_STATUS.md MIGRATION_PROGRESS.md DECISIONS.md
git commit -m "docs: record quota awareness and provider protection"
```

### Spec Coverage Review

- Cloudflare headers: Task 2, Task 5, Task 6
- AbuseIPDB headers: Task 2, Task 5, Task 6
- VirusTotal quota client: Task 3
- Spamhaus quota client: Task 4
- quota state model: Task 1
- auto-protection and recovery: Task 6
- observability and audit: Task 5
- docs and validation: Task 7

No placeholder phrases remain. All steps have concrete file paths, commands, and expected outcomes.
