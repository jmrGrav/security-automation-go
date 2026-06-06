# Production Hygiene + Config + Logging Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix email exposure, CF messages schema bug, AbuseIPDB empty-key poller bug, add env-file config layer with initial password bootstrap, startup logging, and systemd integration.

**Architecture:** Eight independent patches across config, transport, daemon wiring, auth bootstrap, and ops/infra layers. Each patch is self-contained and leaves tests green. No new features beyond what the spec requires.

**Tech Stack:** Go 1.25, `net/http`, `encoding/json`, `bcrypt`, `log/slog`, `os`, systemd EnvironmentFile, logrotate, tmpfiles.d.

---

## File Map

| File | Action | Task |
|---|---|---|
| `docs/security/SECURITY.md` | Modify: replace email | T1 |
| `internal/cloudflare/transport/transport.go:108` | Modify: `Messages []string` → `json.RawMessage` | T2 |
| `internal/cloudflare/transport/transport_test.go` | Add test: messages-as-objects does not error | T2 |
| `cmd/cf-sync/runtime.go:177` | Modify: guard `preBanTransport` on non-empty key | T3 |
| `cmd/cf-sync/quota_refresh_test.go` | Add test: nil abuse transport skips poller | T3 |
| `internal/config/envfile.go` | Create: `LoadEnvFile(path) error` | T4 |
| `internal/config/envfile_test.go` | Create: tests for env file loader | T4 |
| `internal/config/config.go` | Modify: add 3 new env vars + bind/port validation | T4 |
| `internal/config/config_test.go` | Modify: add new var + validation tests | T4 |
| `cmd/cf-sync/runtime.go` (top of `runCFSync`) | Modify: call `LoadEnvFile` before `config.Load` | T4 |
| `internal/ui/auth/bootstrap.go` | Modify: add `InitializeFromPassword(file, password)` | T5 |
| `internal/ui/auth/bootstrap_test.go` | Modify: add tests for env-provided password | T5 |
| `cmd/cf-sync/ui_runtime.go` | Modify: consume `SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD` | T5 |
| `cmd/cf-sync/daemon_runtime.go` | Modify: same bootstrap call for daemon mode | T5 |
| `deployments/config/security-automation.env.example` | Create: config template | T6 |
| `docs/runbooks/FIRST_BOOT.md` | Modify: add config install steps | T6 |
| `deployments/systemd/cf-sync.service` | Modify: add `EnvironmentFile=-/etc/security-automation/security-automation.env` | T6 |
| `internal/startuplog/log.go` | Create: startup log writer | T7 |
| `internal/startuplog/log_test.go` | Create: tests | T7 |
| `cmd/cf-sync/runtime.go` | Modify: write startup log | T7 |
| `deployments/config/logrotate` | Create: logrotate config | T8 |
| `deployments/config/tmpfiles.conf` | Create: tmpfiles.d entry | T8 |
| `/etc/systemd/system/cf-sync.service` (deployed only) | Modify: add EnvironmentFile + ExecStartPre log-dir | T8 |
| `docs/operations/STARTUP_WARNINGS.md` | Create: document CF/AbuseIPDB WARNs | T8 |
| `PRODUCTION_CONFIG_AND_LOGGING_FIX_REPORT.md` | Create: final report | T9 |

---

### Task 1: Replace security contact email

**Files:**
- Modify: `docs/security/SECURITY.md`

- [ ] **Step 1: Replace email**

```bash
sed -i 's/rohmerjeanmarcel@gmail.com/security@arleo.eu/g' docs/security/SECURITY.md
```

- [ ] **Step 2: Verify no old email anywhere in tracked files**

```bash
grep -RIn "rohmerjeanmarcel@gmail.com" . \
  --exclude-dir=.git --exclude-dir=vendor --exclude-dir=tmp --exclude-dir=dist
```

Expected: zero matches.

- [ ] **Step 3: Commit**

```bash
git add docs/security/SECURITY.md
git commit -m "docs: replace personal email with security@arleo.eu in SECURITY.md"
```

---

### Task 2: Fix Cloudflare `messages` type mismatch

**Context:** The `/user/tokens/verify` endpoint returns `"messages": [{...}]` (array of objects with `code`/`message` fields), but `ResponseEnvelope[T]` declares `Messages []string`. `DecodeStrict` with `DisallowUnknownFields` then fails. Fix: accept `json.RawMessage` for that field — we never read the messages array, so this is safe and the most tolerant representation.

**Files:**
- Modify: `internal/cloudflare/transport/transport.go` line 108
- Modify: `internal/cloudflare/transport/transport_test.go`

- [ ] **Step 1: Write the failing test** (add to `transport_test.go`)

```go
func TestExecuteAndDecode_MessagesAsObjects(t *testing.T) {
    // Cloudflare /user/tokens/verify returns messages as array of objects, not strings.
    // DecodeStrict must not fail when messages contains [{code:0, message:"..."}].
    payload := `{"result":{"id":"abc","status":"active"},"success":true,"errors":[],"messages":[{"code":0,"message":"info"}]}`
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        fmt.Fprint(w, payload)
    }))
    defer srv.Close()

    hc := httpclient.New(config.HTTPConfig{Timeout: 5 * time.Second})
    old := transport.BaseURL
    transport.BaseURL = srv.URL  // BaseURL must be exported or use a constructor option
    defer func() { transport.BaseURL = old }()

    tr := transport.New(hc, "test-token")
    type tokenResult struct {
        ID     string `json:"id"`
        Status string `json:"status"`
    }
    res, _, err := transport.ExecuteAndDecode[tokenResult](context.Background(), tr, http.MethodGet, "/test", nil, nil)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if res.ID != "abc" {
        t.Errorf("expected id=abc, got %s", res.ID)
    }
}
```

- [ ] **Step 2: Run to confirm it fails**

```bash
go test ./internal/cloudflare/transport/... -run TestExecuteAndDecode_MessagesAsObjects -v
```

Expected: FAIL with "malformed or incompatible JSON" or build error if `BaseURL` isn't exported.

- [ ] **Step 3: Export `BaseURL` if needed and fix the type**

In `internal/cloudflare/transport/transport.go`, the `BaseURL` constant is already exported. Change the `Messages` field in `ResponseEnvelope[T]` (line ~108):

```go
// Before:
Messages   []string               `json:"messages"`

// After:
Messages   json.RawMessage        `json:"messages,omitempty"`
```

Also add `"encoding/json"` to imports if not already present.

- [ ] **Step 4: Run test — expect PASS**

```bash
go test ./internal/cloudflare/transport/... -v
```

Expected: all pass.

- [ ] **Step 5: Verify VerifyToken no longer WARNs**

```bash
go build ./... && echo "build OK"
```

- [ ] **Step 6: Commit**

```bash
git add internal/cloudflare/transport/transport.go internal/cloudflare/transport/transport_test.go
git commit -m "fix: accept CF messages as JSON objects instead of strings"
```

---

### Task 3: Fix AbuseIPDB empty-key quota poller

**Context:** `cmd/cf-sync/runtime.go` always calls `abtransport.New(hc, cfg.AbuseIPDB.APIKey)` even when `APIKey` is `""`, then passes the non-nil transport to `newQuotaRefreshers`. The quota poller therefore runs and calls `Check("1.1.1.1")` with an empty key → 401 WARN every 15 minutes. Fix: only create the transport when the key is non-empty, so the quota poller is skipped.

**Files:**
- Modify: `cmd/cf-sync/runtime.go` lines ~177-181
- Modify: `cmd/cf-sync/quota_refresh_test.go`

- [ ] **Step 1: Write a test** (add to `quota_refresh_test.go`)

```go
func TestNewQuotaRefreshers_NilAbuseTransportWhenNoKey(t *testing.T) {
    cfg := &config.Config{
        AbuseIPDB: config.AbuseIPDBConfig{APIKey: ""},
    }
    qr := newQuotaRefreshers(cfg, nil, nil, nil)
    // No cloudflare, no abuse, no virustotal, no spamhaus → returns nil
    if qr != nil {
        t.Errorf("expected nil quotaRefreshers when all clients are nil, got non-nil")
    }
}
```

- [ ] **Step 2: Run to confirm it passes already** (the nil case is already handled)

```bash
go test ./cmd/cf-sync/... -run TestNewQuotaRefreshers_NilAbuseTransportWhenNoKey -v
```

- [ ] **Step 3: Add the guard in runtime.go**

Find the block around line 177 in `cmd/cf-sync/runtime.go`:

```go
// Before:
preBanTransport := abtransport.New(hc, cfg.AbuseIPDB.APIKey)
```

```go
// After:
var preBanTransport *abtransport.Transport
if cfg.AbuseIPDB.APIKey != "" {
    preBanTransport = abtransport.New(hc, cfg.AbuseIPDB.APIKey)
}
```

- [ ] **Step 4: Ensure preBanChecker handles nil transport**

Right after the guard, verify `abadapter.NewChecker` is nil-safe when `preBanTransport` is nil. Check `internal/adapters/abuseipdb/`:

```bash
grep -n "func NewChecker\|func.*Check" internal/adapters/abuseipdb/*.go | head -10
```

If `NewChecker` panics on nil transport, add a nil guard:

```go
var preBanChecker *abadapter.Checker
if preBanTransport != nil {
    preBanChecker = abadapter.NewChecker(preBanTransport, abadapter.Config{
        TTL:     cfg.AbuseIPDB.CacheTTL,
        Timeout: cfg.AbuseIPDB.RequestTimeout,
    })
}
```

And update `configureSecurityGuard` call to be a no-op when `preBanChecker` is nil (check the function signature).

- [ ] **Step 5: Run tests**

```bash
go test ./cmd/cf-sync/... -v 2>&1 | tail -20
go build ./... && echo "build OK"
```

- [ ] **Step 6: Commit**

```bash
git add cmd/cf-sync/runtime.go cmd/cf-sync/quota_refresh_test.go
git commit -m "fix: skip AbuseIPDB quota poller when API key is not configured"
```

---

### Task 4: Env file loader + 3 new config vars

**Context:** Add a loader that reads `/etc/security-automation/security-automation.env` (KEY=VALUE format) before `config.Load()` is called. File values are lower-priority than already-set env vars. Then add three env vars: `SECURITY_AUTOMATION_BIND_ADDR`, `SECURITY_AUTOMATION_WEB_PORT`, `SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD`. The first two override `cfg.UI.Addr`. The third is consumed separately (Task 5). Invalid port/bind addresses fail closed at validation time.

**Files:**
- Create: `internal/config/envfile.go`
- Create: `internal/config/envfile_test.go`
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `cmd/cf-sync/runtime.go`

- [ ] **Step 1: Write failing tests for envfile loader** (create `internal/config/envfile_test.go`)

```go
package config_test

import (
    "os"
    "testing"

    "github.com/jm/security-automation-go/internal/config"
)

func TestLoadEnvFile_Absent(t *testing.T) {
    // Missing file is a no-op, not an error.
    err := config.LoadEnvFile("/nonexistent/path/security-automation.env")
    if err != nil {
        t.Fatalf("expected no error for absent file, got: %v", err)
    }
}

func TestLoadEnvFile_SetsVars(t *testing.T) {
    f, _ := os.CreateTemp("", "sa-test-*.env")
    defer os.Remove(f.Name())
    f.WriteString("TEST_SA_VAR=hello\n# comment\n\nTEST_SA_VAR2=world\n")
    f.Close()

    os.Unsetenv("TEST_SA_VAR")
    os.Unsetenv("TEST_SA_VAR2")
    defer os.Unsetenv("TEST_SA_VAR")
    defer os.Unsetenv("TEST_SA_VAR2")

    if err := config.LoadEnvFile(f.Name()); err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if got := os.Getenv("TEST_SA_VAR"); got != "hello" {
        t.Errorf("expected TEST_SA_VAR=hello, got %q", got)
    }
    if got := os.Getenv("TEST_SA_VAR2"); got != "world" {
        t.Errorf("expected TEST_SA_VAR2=world, got %q", got)
    }
}

func TestLoadEnvFile_EnvTakesPrecedence(t *testing.T) {
    f, _ := os.CreateTemp("", "sa-test-*.env")
    defer os.Remove(f.Name())
    f.WriteString("TEST_SA_PRIO=from-file\n")
    f.Close()

    os.Setenv("TEST_SA_PRIO", "from-env")
    defer os.Unsetenv("TEST_SA_PRIO")

    if err := config.LoadEnvFile(f.Name()); err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if got := os.Getenv("TEST_SA_PRIO"); got != "from-env" {
        t.Errorf("expected env to win, got %q", got)
    }
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/config/... -run TestLoadEnvFile -v
```

Expected: build error (function not defined).

- [ ] **Step 3: Implement `LoadEnvFile`** (create `internal/config/envfile.go`)

```go
package config

import (
    "bufio"
    "errors"
    "fmt"
    "os"
    "strings"
)

// DefaultEnvFile is the canonical runtime config file path.
const DefaultEnvFile = "/etc/security-automation/security-automation.env"

// LoadEnvFile reads KEY=VALUE pairs from path and sets them as env vars,
// skipping keys that are already set in the environment.
// If path does not exist, LoadEnvFile returns nil (absent file is a no-op).
// Comments (# prefix) and blank lines are ignored.
// Malformed lines are silently skipped.
func LoadEnvFile(path string) error {
    f, err := os.Open(path)
    if errors.Is(err, os.ErrNotExist) {
        return nil
    }
    if err != nil {
        return fmt.Errorf("open env file %q: %w", path, err)
    }
    defer f.Close()

    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        idx := strings.IndexByte(line, '=')
        if idx < 1 {
            continue
        }
        key := strings.TrimSpace(line[:idx])
        val := strings.TrimSpace(line[idx+1:])
        // Strip optional surrounding quotes
        if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
            val = val[1 : len(val)-1]
        }
        if key == "" {
            continue
        }
        if os.Getenv(key) == "" {
            _ = os.Setenv(key, val)
        }
    }
    return scanner.Err()
}
```

- [ ] **Step 4: Run envfile tests — expect PASS**

```bash
go test ./internal/config/... -run TestLoadEnvFile -v
```

- [ ] **Step 5: Write failing tests for new config vars** (add to `internal/config/config_test.go`)

```go
func TestConfig_SecurityAutomation_BindAddr(t *testing.T) {
    os.Setenv("CF_API_TOKEN", "tok")
    os.Setenv("CF_ZONE_ID", "zone")
    os.Setenv("UI_ENABLED", "true")
    os.Setenv("SECURITY_AUTOMATION_BIND_ADDR", "127.0.0.1")
    os.Setenv("SECURITY_AUTOMATION_WEB_PORT", "9091")
    defer func() {
        os.Unsetenv("CF_API_TOKEN"); os.Unsetenv("CF_ZONE_ID")
        os.Unsetenv("UI_ENABLED")
        os.Unsetenv("SECURITY_AUTOMATION_BIND_ADDR")
        os.Unsetenv("SECURITY_AUTOMATION_WEB_PORT")
    }()
    cfg, err := Load("")
    if err != nil {
        t.Fatalf("load failed: %v", err)
    }
    if cfg.UI.Addr != "127.0.0.1:9091" {
        t.Errorf("expected UI.Addr=127.0.0.1:9091, got %s", cfg.UI.Addr)
    }
}

func TestConfig_SecurityAutomation_InvalidPort(t *testing.T) {
    os.Setenv("CF_API_TOKEN", "tok")
    os.Setenv("CF_ZONE_ID", "zone")
    os.Setenv("UI_ENABLED", "true")
    os.Setenv("SECURITY_AUTOMATION_BIND_ADDR", "127.0.0.1")
    os.Setenv("SECURITY_AUTOMATION_WEB_PORT", "99999")
    defer func() {
        os.Unsetenv("CF_API_TOKEN"); os.Unsetenv("CF_ZONE_ID")
        os.Unsetenv("UI_ENABLED")
        os.Unsetenv("SECURITY_AUTOMATION_BIND_ADDR")
        os.Unsetenv("SECURITY_AUTOMATION_WEB_PORT")
    }()
    _, err := Load("")
    if err == nil {
        t.Fatal("expected error for invalid port 99999, got nil")
    }
    if !strings.Contains(err.Error(), "port") {
        t.Errorf("expected port-related error, got: %v", err)
    }
}

func TestConfig_SecurityAutomation_InvalidBindAddr(t *testing.T) {
    os.Setenv("CF_API_TOKEN", "tok")
    os.Setenv("CF_ZONE_ID", "zone")
    os.Setenv("UI_ENABLED", "true")
    os.Setenv("SECURITY_AUTOMATION_BIND_ADDR", "not-an-ip")
    os.Setenv("SECURITY_AUTOMATION_WEB_PORT", "9091")
    defer func() {
        os.Unsetenv("CF_API_TOKEN"); os.Unsetenv("CF_ZONE_ID")
        os.Unsetenv("UI_ENABLED")
        os.Unsetenv("SECURITY_AUTOMATION_BIND_ADDR")
        os.Unsetenv("SECURITY_AUTOMATION_WEB_PORT")
    }()
    _, err := Load("")
    if err == nil {
        t.Fatal("expected error for invalid bind addr, got nil")
    }
    if !strings.Contains(err.Error(), "bind") && !strings.Contains(err.Error(), "addr") {
        t.Errorf("expected bind-related error, got: %v", err)
    }
}
```

- [ ] **Step 6: Run — expect FAIL**

```bash
go test ./internal/config/... -run "TestConfig_SecurityAutomation" -v
```

- [ ] **Step 7: Implement env overrides + validation** (edit `internal/config/config.go`)

In `applyEnvOverrides`, add after the `UI_ADDR` block:

```go
// SECURITY_AUTOMATION_BIND_ADDR and SECURITY_AUTOMATION_WEB_PORT compose UI.Addr.
// They override UI_ADDR / ui.addr when both are present.
bindAddr := os.Getenv("SECURITY_AUTOMATION_BIND_ADDR")
webPort  := os.Getenv("SECURITY_AUTOMATION_WEB_PORT")
if bindAddr != "" || webPort != "" {
    host, portStr, _ := net.SplitHostPort(cfg.UI.Addr)
    if bindAddr != "" {
        host = bindAddr
    }
    if webPort != "" {
        portStr = webPort
    }
    cfg.UI.Addr = net.JoinHostPort(host, portStr)
}
```

Add `"net"` to imports.

In `validate`, add after the UI addr check:

```go
// Validate SECURITY_AUTOMATION_* bind/port if explicitly set.
if bindAddr := os.Getenv("SECURITY_AUTOMATION_BIND_ADDR"); bindAddr != "" {
    if net.ParseIP(bindAddr) == nil {
        return fmt.Errorf("SECURITY_AUTOMATION_BIND_ADDR %q is not a valid IP address", bindAddr)
    }
}
if webPort := os.Getenv("SECURITY_AUTOMATION_WEB_PORT"); webPort != "" {
    p, err := strconv.Atoi(webPort)
    if err != nil || p < 1 || p > 65535 {
        return fmt.Errorf("SECURITY_AUTOMATION_WEB_PORT %q is not a valid port (1-65535)", webPort)
    }
}
```

- [ ] **Step 8: Run tests — expect PASS**

```bash
go test ./internal/config/... -v 2>&1 | tail -20
```

- [ ] **Step 9: Wire `LoadEnvFile` into `runCFSync`** (edit `cmd/cf-sync/runtime.go`)

At the very top of `runCFSync`, before `config.Load(configPath)`:

```go
// Load file-based config defaults before YAML and env override chain.
if err := config.LoadEnvFile(config.DefaultEnvFile); err != nil {
    fmt.Fprintf(os.Stderr, "Warning: could not read %s: %v\n", config.DefaultEnvFile, err)
    // non-fatal: file absent is fine; unreadable file is a warning only
}
```

- [ ] **Step 10: Build and test**

```bash
go build ./... && go test ./... 2>&1 | grep -E "FAIL|ok" | head -20
```

- [ ] **Step 11: Commit**

```bash
git add internal/config/envfile.go internal/config/envfile_test.go \
        internal/config/config.go internal/config/config_test.go \
        cmd/cf-sync/runtime.go
git commit -m "feat: add /etc/security-automation env file loader and SECURITY_AUTOMATION_* vars"
```

---

### Task 5: Initial admin password bootstrap from env var

**Context:** When `SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD` is set and no admin password file exists, use the provided password (hashed) instead of auto-generating one. The plaintext must be read once, hashed, stored, then cleared from env. If the file already exists, ignore the env var entirely. If the password is empty and no file exists, fail closed.

**Files:**
- Modify: `internal/ui/auth/bootstrap.go`
- Modify: `internal/ui/auth/bootstrap_test.go` (create if absent)
- Modify: `cmd/cf-sync/ui_runtime.go`
- Modify: `cmd/cf-sync/daemon_runtime.go`

- [ ] **Step 1: Write failing tests** (create/add to `internal/ui/auth/bootstrap_test.go`)

```go
package auth_test

import (
    "os"
    "testing"

    "github.com/jm/security-automation-go/internal/ui/auth"
)

func TestInitializeFromPassword_UsesProvidedPassword(t *testing.T) {
    f, _ := os.CreateTemp("", "bootstrap-*.json")
    f.Close()
    os.Remove(f.Name()) // ensure absent

    err := auth.InitializeFromPassword(f.Name(), "MySecurePass1!")
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    defer os.Remove(f.Name())

    state, err := auth.GetBootstrapState(f.Name())
    if err != nil {
        t.Fatalf("failed to read state: %v", err)
    }
    if !state.IsBootstrap {
        t.Error("expected IsBootstrap=true")
    }
    if !auth.VerifyPassword(state.PasswordHash, "MySecurePass1!") {
        t.Error("stored hash does not verify with provided password")
    }
    // Plaintext must NOT be stored in bootstrap state when using env-provided password.
    if state.Password != "" {
        t.Error("plaintext password must not be stored in bootstrap state")
    }
}

func TestInitializeFromPassword_FileAlreadyExists(t *testing.T) {
    f, _ := os.CreateTemp("", "bootstrap-*.json")
    f.Close()
    os.Remove(f.Name())
    defer os.Remove(f.Name())

    // First init with auto-generated password
    if _, err := auth.InitializeBootstrapPassword(f.Name()); err != nil {
        t.Fatalf("initial bootstrap: %v", err)
    }
    // Second call with a different password must be a no-op
    if err := auth.InitializeFromPassword(f.Name(), "NewPassword123!"); err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    state, _ := auth.GetBootstrapState(f.Name())
    // Hash must NOT match "NewPassword123!" — original was kept
    if auth.VerifyPassword(state.PasswordHash, "NewPassword123!") {
        t.Error("existing bootstrap state was overwritten — must be a no-op")
    }
}

func TestInitializeFromPassword_EmptyPasswordNoFile(t *testing.T) {
    tmpFile := os.TempDir() + "/nonexistent-bootstrap-abc123.json"
    defer os.Remove(tmpFile)

    err := auth.InitializeFromPassword(tmpFile, "")
    if err == nil {
        t.Fatal("expected error for empty password with no existing state file")
    }
}
```

- [ ] **Step 2: Run — expect FAIL**

```bash
go test ./internal/ui/auth/... -run TestInitializeFromPassword -v
```

- [ ] **Step 3: Implement `InitializeFromPassword`** (add to `internal/ui/auth/bootstrap.go`)

```go
// InitializeFromPassword creates a bootstrap state file using the given password.
// If the state file already exists, it is left unchanged (idempotent).
// If password is empty and the file does not exist, returns an error (fail closed).
// The plaintext password is never persisted to the state file.
func InitializeFromPassword(secretFile, password string) error {
    if _, err := os.Stat(secretFile); err == nil {
        return nil // already bootstrapped — ignore env var
    }

    if password == "" {
        return fmt.Errorf("SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD is empty and no admin credential exists at %s; set a password to bootstrap", secretFile)
    }

    dir := filepath.Dir(secretFile)
    if err := os.MkdirAll(dir, 0o755); err != nil {
        return fmt.Errorf("create secret dir: %w", err)
    }

    hash, err := HashPassword(password)
    if err != nil {
        return fmt.Errorf("hash initial password: %w", err)
    }

    state := BootstrapState{
        IsBootstrap:  true,
        Password:     "", // intentionally blank — never persist env-provided plaintext
        PasswordHash: hash,
    }
    data, err := json.Marshal(state)
    if err != nil {
        return fmt.Errorf("marshal bootstrap state: %w", err)
    }
    if err := os.WriteFile(secretFile, data, 0o600); err != nil {
        return fmt.Errorf("write bootstrap state: %w", err)
    }
    return nil
}
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
go test ./internal/ui/auth/... -v
```

- [ ] **Step 5: Wire into daemon startup** (edit `cmd/cf-sync/daemon_runtime.go`)

After `newAuthenticator()` returns successfully (around the top of `startAPIServer`), but actually this belongs in `runDaemon` before starting the server. Add a helper at the bottom of `daemon_runtime.go`:

```go
// bootstrapAdminPassword handles the one-time admin password bootstrap from env.
// Called before the API server starts. If SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD
// is set, it is used once to create the credential file, then cleared from env.
func bootstrapAdminPassword(cfg *config.Config, logger *slog.Logger) error {
    envPass := os.Getenv("SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD")
    if envPass == "" && cfg.UI.AdminPasswordFile == "" {
        return nil // nothing to do
    }
    passwordFile := cfg.UI.AdminPasswordFile
    if passwordFile == "" {
        return nil
    }
    if _, err := os.Stat(passwordFile); err == nil {
        // File exists — skip bootstrap, don't log or use the env var
        if envPass != "" {
            logger.Info("admin credential already exists; SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD ignored", "file", passwordFile)
        }
        return nil
    }
    if envPass != "" {
        defer os.Unsetenv("SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD")
        if err := auth.InitializeFromPassword(passwordFile, envPass); err != nil {
            return fmt.Errorf("bootstrap admin password: %w", err)
        }
        logger.Info("admin credential bootstrapped from SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD", "file", passwordFile)
        return nil
    }
    // No env password, no existing file — auto-generate
    if _, err := authpkg.InitializeBootstrapPassword(passwordFile); err != nil {
        return fmt.Errorf("auto-generate bootstrap password: %w", err)
    }
    logger.Info("admin credential auto-generated", "file", passwordFile)
    return nil
}
```

Add import alias: `authpkg "github.com/jm/security-automation-go/internal/ui/auth"`.

Call `bootstrapAdminPassword` at the start of `runDaemon`, before `startAPIServer`:

```go
if err := bootstrapAdminPassword(cfg_placeholder, logger); err != nil {
    logger.Error("bootstrap admin password failed", "error", err)
    return
}
```

Note: `runDaemon` currently doesn't receive `cfg` — pass it in as a parameter or read from the env values directly. Check the signature and add `cfg *config.Config` if needed.

- [ ] **Step 6: Wire into UI startup** (edit `cmd/cf-sync/ui_runtime.go`)

In `runUI`, before `ui.NewServer(...)`:

```go
envPass := os.Getenv("SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD")
if envPass != "" {
    defer os.Unsetenv("SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD")
    if err := auth.InitializeFromPassword(cfg.UI.AdminPasswordFile, envPass); err != nil {
        return fmt.Errorf("bootstrap admin credential: %w", err)
    }
    logger.Info("admin credential bootstrapped from SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD",
        "file", cfg.UI.AdminPasswordFile)
} else if _, err := os.Stat(cfg.UI.AdminPasswordFile); os.IsNotExist(err) {
    if _, err2 := auth.InitializeBootstrapPassword(cfg.UI.AdminPasswordFile); err2 != nil {
        return fmt.Errorf("auto-generate admin credential: %w", err2)
    }
    logger.Info("admin credential auto-generated", "file", cfg.UI.AdminPasswordFile)
}
```

Add import: `"github.com/jm/security-automation-go/internal/ui/auth"`.

- [ ] **Step 7: Build and run all tests**

```bash
go build ./... && go test ./... 2>&1 | grep -E "FAIL|ok"
```

- [ ] **Step 8: Commit**

```bash
git add internal/ui/auth/bootstrap.go internal/ui/auth/bootstrap_test.go \
        cmd/cf-sync/ui_runtime.go cmd/cf-sync/daemon_runtime.go
git commit -m "feat: bootstrap admin password from SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD"
```

---

### Task 6: Example config file + runbook + systemd template

**Files:**
- Create: `deployments/config/security-automation.env.example`
- Modify: `docs/runbooks/FIRST_BOOT.md`
- Modify: `deployments/systemd/cf-sync.service`

- [ ] **Step 1: Create example config**

Create `deployments/config/security-automation.env.example`:

```env
# Runtime bind address for the local web UI / admin API.
# Default: localhost-only. Do NOT set to 0.0.0.0 without a reverse proxy.
SECURITY_AUTOMATION_BIND_ADDR=127.0.0.1

# Port for the local web UI / admin API.
SECURITY_AUTOMATION_WEB_PORT=9091

# Initial bootstrap admin password.
# Used ONLY on first startup when no admin credential exists.
# Remove or leave empty after first boot — the daemon ignores it thereafter.
# Must never be logged or committed.
SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD=CHANGE_ME_ON_FIRST_BOOT
```

- [ ] **Step 2: Add install instructions to FIRST_BOOT.md**

Find the `docs/runbooks/FIRST_BOOT.md` file and add the following section after initial setup:

```markdown
## Runtime Configuration

1. Install the config directory and template:

   ```bash
   sudo install -d -m 0750 -o root -g root /etc/security-automation
   sudo install -m 0600 -o root -g root \
     deployments/config/security-automation.env.example \
     /etc/security-automation/security-automation.env
   ```

2. Edit and set your initial admin password:

   ```bash
   sudo nano /etc/security-automation/security-automation.env
   # Set SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD to a strong password.
   # After first login, you can change it via the UI — then clear the env var.
   ```

3. Restart the service:

   ```bash
   sudo systemctl restart cf-sync
   ```

### Rotating the admin password after first boot

After you have logged in and changed your password via the UI Settings page:
- Remove or blank out `SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD` in the config file.
- The daemon reads the file only on startup; it will not reset your password on next restart.

```bash
sudo sed -i 's/^SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD=.*/SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD=/' \
  /etc/security-automation/security-automation.env
sudo systemctl restart cf-sync
```
```

- [ ] **Step 3: Update the committed systemd template** (edit `deployments/systemd/cf-sync.service`)

Add an `EnvironmentFile` line with `-` prefix (fail-open if absent) to the `[Service]` section, above `ExecStart`:

```ini
# Optional runtime config — absent file is silently ignored
EnvironmentFile=-/etc/security-automation/security-automation.env
```

- [ ] **Step 4: Verify template renders correctly**

```bash
cat deployments/systemd/cf-sync.service | grep -A3 "EnvironmentFile"
```

- [ ] **Step 5: Commit**

```bash
git add deployments/config/security-automation.env.example \
        docs/runbooks/FIRST_BOOT.md \
        deployments/systemd/cf-sync.service
git commit -m "ops: add env config template, first-boot instructions, systemd EnvironmentFile"
```

---

### Task 7: Startup log writer

**Context:** Write structured startup diagnostics to `/var/log/security-automation/` on every daemon/UI start. Best-effort (log failures are warnings, not startup failures). Never write secrets or key values to log files.

**Files:**
- Create: `internal/startuplog/log.go`
- Create: `internal/startuplog/log_test.go`
- Modify: `cmd/cf-sync/runtime.go` (call startup logger in daemon mode)

- [ ] **Step 1: Write tests** (create `internal/startuplog/log_test.go`)

```go
package startuplog_test

import (
    "os"
    "strings"
    "testing"

    "github.com/jm/security-automation-go/internal/startuplog"
)

func TestLogger_WritesStartupEntry(t *testing.T) {
    dir := t.TempDir()
    l, err := startuplog.New(dir)
    if err != nil {
        t.Fatalf("New: %v", err)
    }
    defer l.Close()

    l.WriteStartup(startuplog.StartupInfo{
        Version:    "v1.1.1",
        Mode:       "daemon",
        BindAddr:   "127.0.0.1:9091",
        ConfigFile: "/etc/security-automation-go/cf-shadow.yaml",
        DBPath:     "/var/lib/cf-sync/scope/db.sqlite",
        DryRun:     true,
        Providers:  []string{"cloudflare", "crowdsec"},
    })

    content, err := os.ReadFile(dir + "/startup.log")
    if err != nil {
        t.Fatalf("read log: %v", err)
    }
    text := string(content)
    if !strings.Contains(text, "v1.1.1") {
        t.Error("expected version in log")
    }
    if !strings.Contains(text, "127.0.0.1:9091") {
        t.Error("expected bind addr in log")
    }
    if !strings.Contains(text, "dry_run=true") {
        t.Error("expected dry_run in log")
    }
    if strings.Contains(text, "api_key") || strings.Contains(text, "token") {
        t.Error("log must not contain secret-looking fields")
    }
}

func TestLogger_AbsentDir_ReturnsWarning(t *testing.T) {
    // Non-existent dir should return an error from New but not panic.
    _, err := startuplog.New("/nonexistent/var/log/security-automation")
    if err == nil {
        t.Error("expected error for non-existent log dir, got nil")
    }
}

func TestLogger_WriteHealthcheck(t *testing.T) {
    dir := t.TempDir()
    l, _ := startuplog.New(dir)
    defer l.Close()

    l.WriteHealthcheck("healthz", "OK")
    l.WriteHealthcheck("readyz", "READY")

    content, _ := os.ReadFile(dir + "/healthcheck.log")
    text := string(content)
    if !strings.Contains(text, "healthz") || !strings.Contains(text, "OK") {
        t.Error("healthcheck log missing expected content")
    }
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/startuplog/... -v
```

Expected: build error (package not found).

- [ ] **Step 3: Implement `internal/startuplog/log.go`**

```go
package startuplog

import (
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
    "time"
)

// DefaultLogDir is the canonical log directory.
const DefaultLogDir = "/var/log/security-automation"

// StartupInfo holds fields written to startup.log. No secret values.
type StartupInfo struct {
    Version    string
    Mode       string   // daemon, ui, cli
    BindAddr   string   // host:port — no credentials
    ConfigFile string
    DBPath     string
    DryRun     bool
    Providers  []string // provider names only, no keys
}

// Logger writes startup diagnostics to log files in Dir.
type Logger struct {
    dir     string
    startup io.WriteCloser
    config  io.WriteCloser
    health  io.WriteCloser
}

// New opens (or creates) the three log files in dir.
// Returns an error if the directory does not exist and cannot be created.
func New(dir string) (*Logger, error) {
    if err := os.MkdirAll(dir, 0o750); err != nil {
        return nil, fmt.Errorf("startup log dir: %w", err)
    }
    open := func(name string) (io.WriteCloser, error) {
        return os.OpenFile(filepath.Join(dir, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
    }
    s, err := open("startup.log")
    if err != nil {
        return nil, err
    }
    c, err := open("config-check.log")
    if err != nil {
        s.Close()
        return nil, err
    }
    h, err := open("healthcheck.log")
    if err != nil {
        s.Close(); c.Close()
        return nil, err
    }
    return &Logger{dir: dir, startup: s, config: c, health: h}, nil
}

func (l *Logger) Close() {
    if l == nil { return }
    l.startup.Close()
    l.config.Close()
    l.health.Close()
}

func (l *Logger) WriteStartup(info StartupInfo) {
    if l == nil { return }
    fmt.Fprintf(l.startup, "%s version=%s mode=%s bind=%s config=%s db=%s dry_run=%v providers=[%s]\n",
        ts(), info.Version, info.Mode, info.BindAddr, info.ConfigFile, info.DBPath,
        info.DryRun, strings.Join(info.Providers, ","))
}

func (l *Logger) WriteConfigCheck(key, result string) {
    if l == nil { return }
    fmt.Fprintf(l.config, "%s %s=%s\n", ts(), key, result)
}

func (l *Logger) WriteHealthcheck(endpoint, status string) {
    if l == nil { return }
    fmt.Fprintf(l.health, "%s %s %s\n", ts(), endpoint, status)
}

func ts() string {
    return time.Now().UTC().Format(time.RFC3339)
}
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
go test ./internal/startuplog/... -v
```

- [ ] **Step 5: Integrate into daemon** (edit `cmd/cf-sync/runtime.go`)

After the logger is created and config is loaded, add:

```go
// Best-effort startup log — absent log dir is a warning, not a failure.
var startLog *startuplog.Logger
if sl, err := startuplog.New(startuplog.DefaultLogDir); err != nil {
    logger.Warn("startup log unavailable", "err", err, "dir", startuplog.DefaultLogDir)
} else {
    startLog = sl
    defer startLog.Close()
}

if startLog != nil {
    providers := []string{"cloudflare"}
    if cfg.AbuseIPDB.APIKey != "" { providers = append(providers, "abuseipdb") }
    if cfg.CrowdSec.APIKey != "" || cfg.CrowdSec.DecisionsLog != "" { providers = append(providers, "crowdsec") }
    if cfg.Spamhaus.Enabled  { providers = append(providers, "spamhaus") }
    if cfg.VirusTotal.Enabled { providers = append(providers, "virustotal") }
    startLog.WriteStartup(startuplog.StartupInfo{
        Version:    "v1.1.1",
        Mode:       mode,
        BindAddr:   metricsAddr,
        ConfigFile: configPath,
        DBPath:     filepath.Join(cfg.StateDir, "db.sqlite"),
        DryRun:     dryRun,
        Providers:  providers,
    })
    startLog.WriteConfigCheck("bind_addr", metricsAddr)
    startLog.WriteConfigCheck("dry_run", fmt.Sprintf("%v", dryRun))
    startLog.WriteConfigCheck("cf_zone_id_set", fmt.Sprintf("%v", cfg.Cloudflare.ZoneID != ""))
    startLog.WriteHealthcheck("startup", "starting")
}
```

- [ ] **Step 6: Build and test**

```bash
go build ./... && go test ./... 2>&1 | grep -E "FAIL|ok"
```

- [ ] **Step 7: Commit**

```bash
git add internal/startuplog/log.go internal/startuplog/log_test.go cmd/cf-sync/runtime.go
git commit -m "feat: startup diagnostics logger writing to /var/log/security-automation/"
```

---

### Task 8: Ops/infra files + STARTUP_WARNINGS doc + systemd update

**Files:**
- Create: `deployments/config/logrotate`
- Create: `deployments/config/tmpfiles.conf`
- Create: `docs/operations/STARTUP_WARNINGS.md`
- Modify: `/etc/systemd/system/cf-sync.service` (deployed — not committed)

- [ ] **Step 1: Create logrotate config** (create `deployments/config/logrotate`)

```
/var/log/security-automation/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        systemctl kill -s HUP cf-sync.service 2>/dev/null || true
    endscript
}
```

- [ ] **Step 2: Create tmpfiles.d config** (create `deployments/config/tmpfiles.conf`)

```
# Create log directory for security-automation on boot if absent.
d /var/log/security-automation 0750 root root -
```

- [ ] **Step 3: Create STARTUP_WARNINGS.md** (create `docs/operations/STARTUP_WARNINGS.md`)

```markdown
# Startup Warnings Reference

## AbuseIPDB: quota refresh 401

**Symptom:**
```
level=WARN msg="quota refresh failed" provider=abuseipdb error="AbuseIPDB HTTP 401"
```

**Root cause:** The `ABUSEIPDB_KEY` environment variable is empty, missing, or invalid.
The quota poller only runs when a non-empty key is configured; if this WARN appears,
the key was set to a non-empty value that the AbuseIPDB API rejected.

**Remediation:**
1. Verify your key at https://www.abuseipdb.com/account/api
2. Update `/etc/security-automation-go/cf-shadow.env`:
   ```
   ABUSEIPDB_KEY=your-valid-key-here
   ```
3. `sudo systemctl restart cf-sync`

**If you do not use AbuseIPDB:** leave `ABUSEIPDB_KEY` empty. The poller will not start.

---

## Cloudflare: token verify JSON decode error

**Symptom:**
```
level=WARN msg="quota refresh failed" provider=cloudflare
  error="...malformed or incompatible JSON: json: cannot unmarshal object into...messages of type string"
```

**Root cause (v1.1.0 and earlier):** The `ResponseEnvelope.messages` field was typed as
`[]string`, but the Cloudflare API returns `messages` as an array of objects
`[{"code":0,"message":"..."}]`. Fixed in v1.1.1: the field now accepts `json.RawMessage`.

**If you see this on v1.1.1+:** the CF API may have changed shape again. Check the raw
response with `curl -H "Authorization: Bearer $CF_API_TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify`
and open an issue with the response body (redact the token).

---

## Rego policy not found

**Symptom:**
```
level=WARN msg="failed to load default rego policy" error="open internal/policy/rego/admission.rego: no such file or directory"
```

**Root cause:** The OPA admission policy file is not present at the expected relative path.
This is non-fatal; the daemon starts without admission policy enforcement.

**Remediation:** Copy or symlink the bundled policy file:
```bash
sudo install -m 0644 internal/policy/rego/admission.rego /etc/security-automation/admission.rego
```
Then configure `policy.admission_rego` in the YAML config to point to the absolute path.
```

- [ ] **Step 4: Update deployed systemd unit** (edit `/etc/systemd/system/cf-sync.service` in-place)

```bash
sudo sed -i '/^EnvironmentFile=\/etc\/security-automation-go\/cf-shadow.env/a EnvironmentFile=-/etc/security-automation/security-automation.env' /etc/systemd/system/cf-sync.service
```

Add `ExecStartPre` to create the log dir before the service starts:

```bash
sudo sed -i '/^ExecStart=/i ExecStartPre=+/bin/install -d -m 0750 -o root -g root /var/log/security-automation' /etc/systemd/system/cf-sync.service
```

```bash
sudo systemctl daemon-reload
sudo systemctl cat cf-sync | grep -E "EnvironmentFile|ExecStart"
```

- [ ] **Step 5: Install logrotate and tmpfiles configs**

```bash
sudo install -m 0644 deployments/config/logrotate /etc/logrotate.d/security-automation
sudo install -m 0644 deployments/config/tmpfiles.conf /etc/tmpfiles.d/security-automation.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/security-automation.conf
ls -la /var/log/security-automation/
```

- [ ] **Step 6: Commit deployments files (not the live /etc changes)**

```bash
git add deployments/config/logrotate deployments/config/tmpfiles.conf docs/operations/STARTUP_WARNINGS.md
git commit -m "ops: logrotate, tmpfiles.d, startup warnings reference doc"
```

---

### Task 9: Validation + Final Report

- [ ] **Step 1: Full validation suite**

```bash
gofmt -l $(find . -name '*.go' -not -path './vendor/*')
go vet ./...
go build ./...
go test ./...
go test -race ./...
go test -tags=soak ./internal/testing/...
```

Expected: gofmt produces no output, all others PASS.

- [ ] **Step 2: Email scan**

```bash
grep -RIn "rohmerjeanmarcel@gmail.com" . --exclude-dir=.git --exclude-dir=vendor
```

Expected: zero matches.

- [ ] **Step 3: Secret scan**

```bash
grep -RIn "CF_API_TOKEN\s*=\s*[A-Za-z0-9_-]\{10,\}\|CLOUDFLARE_API_TOKEN\s*=\s*[A-Za-z0-9_-]\{10,\}\|ABUSEIPDB_API_KEY\s*=\s*[A-Za-z0-9_-]\{10,\}" \
  --exclude-dir=.git --exclude-dir=vendor . | grep -v ".env.example" | grep -v "_test.go"
```

Expected: zero matches.

- [ ] **Step 4: Create final report** (create `PRODUCTION_CONFIG_AND_LOGGING_FIX_REPORT.md`)

Write the report per the spec requirements. See spec Task 8 for the required sections. The report must include:
- Files changed (list from the File Map above)
- Test results verbatim
- Email replacement confirmation
- How `/etc/security-automation/security-automation.env` works (priority chain)
- SQLite UI override precedence: env-file < env var < YAML config < (SQLite UI settings for password after bootstrap)
- Password rotation procedure (from Task 6 runbook)
- Startup log locations
- AbuseIPDB WARN status (resolved when key is empty)
- Cloudflare WARN status (fixed in T2)
- Cutover readiness verdict

- [ ] **Step 5: Final commit**

```bash
git add PRODUCTION_CONFIG_AND_LOGGING_FIX_REPORT.md
git commit -m "docs: production config and logging fix report"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| SECURITY.md email → security@arleo.eu | T1 |
| CF messages JSON decode fix | T2 |
| AbuseIPDB 401 WARN fix | T3 |
| /etc/security-automation/security-automation.env loader | T4 |
| SECURITY_AUTOMATION_BIND_ADDR | T4 |
| SECURITY_AUTOMATION_WEB_PORT | T4 |
| Invalid port fail-closed | T4 |
| Invalid bind fail-closed | T4 |
| SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD | T5 |
| Password never logged | T5 |
| Bootstrap once — file wins | T5 |
| Example config file | T6 |
| Runbook install instructions | T6 |
| systemd EnvironmentFile= | T6, T8 |
| Startup log files | T7 |
| Log rotation | T8 |
| STARTUP_WARNINGS.md | T8 |
| Final report | T9 |
| gofmt/vet/test/race validation | T9 |

**No gaps found.**
