# Security Backlog

Audit source: Gemini CLI red-team + Claude independent validation — 2026-06-08

## OPEN

### [SEC-004] Rate limiter O(n) cleanup on every request

Source: Gemini CLI (HIGH) / Claude validation (CONFIRMED LOW in current deployment)
Status: OPEN
Severity: LOW
Decision: FIX LATER
GitHub: https://github.com/jmrGrav/security-automation-go/issues/7
Owner: @jmrGrav
Target: v1.6.0 or when UI is exposed beyond localhost
Evidence: `internal/ui/server.go:1143` — full map scan on every `Allow()` call. With 100k unique IPs, each request iterates 100k entries under mutex lock.
Notes: Not urgent. UI is designed for local operator access. A background cleanup goroutine or TTL-eviction map would resolve this.

---

### [SEC-005] Setup wizard path disclosure post-setup

Source: Gemini CLI (HIGH) / Claude validation (PARTIAL LOW)
Status: OPEN
Severity: LOW
Decision: FIX LATER
GitHub: https://github.com/jmrGrav/security-automation-go/issues/8
Owner: @jmrGrav
Target: v1.6.0
Evidence: `internal/ui/setup_wizard.go:112` — `/setup/step/1` is accessible post-setup to unauthenticated users and reveals `s.cfg.UI.SecretFile` path. The file path ≠ file content. Requires separate filesystem access to exploit.
Notes: Add `setupStore.IsComplete()` check in `handleSetupStep1`, redirect to `/login` if complete.

---

### [SEC-006] crypto/rand panic in login handler

Source: Gemini CLI (MEDIUM) / Claude validation (CONFIRMED LOW)
Status: OPEN
Severity: LOW
Decision: DOCUMENT ONLY
GitHub: https://github.com/jmrGrav/security-automation-go/issues/9
Owner: @jmrGrav
Target: —
Evidence: `internal/ui/login.go:120` — `generateSessionToken()` panics on `crypto/rand` failure. On Linux 3.17+ and modern macOS/Windows, `crypto/rand` never returns an error. `net/http` recovers panics in handlers, so the daemon would not crash. Bootstrap panic in `auth/password.go:21` is acceptable (fail-fast at startup).
Notes: Technically incorrect pattern (panic in handler) but zero practical risk on supported platforms. If changed, use `return "", fmt.Errorf(...)` and propagate 503.

---

### [SEC-007] Audit remaining UI auth/session/CSRF surfaces

Source: Post-audit recommendation (Claude)
Status: OPEN
Severity: INFO
Decision: FUTURE REVIEW
GitHub: https://github.com/jmrGrav/security-automation-go/issues/10
Owner: @jmrGrav
Target: —
Evidence: Gemini found no auth bypass, no CSRF bypass, no session fixation. Independent audit recommended as ongoing hygiene.
Notes: Focus on cookie attributes (Secure/SameSite), session invalidation on password change, CSRF token rotation.

---

### [SEC-008] OpenResty/Lua ingestion hardening review

Source: Post-audit recommendation (Claude)
Status: OPEN
Severity: INFO
Decision: FUTURE REVIEW
GitHub: https://github.com/jmrGrav/security-automation-go/issues/11
Owner: @jmrGrav
Target: —
Evidence: Gemini audit did not cover the OpenResty/Lua layer. Input parsing and trust boundary between Nginx and Go daemon not reviewed.
Notes: Review Lua input validation, shared memory access, and injection vectors in the OpenResty integration.

---

### [SEC-009] SQLite recovery and corruption resilience review

Source: Post-audit recommendation (Claude)
Status: OPEN
Severity: INFO
Decision: FUTURE REVIEW
GitHub: https://github.com/jmrGrav/security-automation-go/issues/12
Owner: @jmrGrav
Target: —
Evidence: Gemini found no corruption or injection in the WAL/recovery paths. Independent review of the recovery manager, quarantine logic, and replay consistency recommended.
Notes: Focus on the recovery/manager.go, replay/consistency, and WAL checkpoint interactions.

---

## CLOSED

### [SEC-001] ExportHotSnapshot path sanitization

Source: Gemini CLI (CRITICAL) / Claude validation (PARTIAL — dead code)
Status: CLOSED
Resolution: Added `strings.ContainsAny(clean, "'\"")` guard in `ExportHotSnapshot` before VACUUM INTO. Prevents future SQL injection if function is ever exposed to user input.
PR: —
Commit: 6c5c78c
Date: 2026-06-08

---

### [SEC-002] API internal error leakage in V3 handlers

Source: Gemini CLI (MEDIUM) / Claude validation (CONFIRMED)
Status: CLOSED
Resolution: 8 call sites in `internal/api/handlers/v3/handlers.go` updated. `err.Error()` replaced with `"internal error"` in responses; original errors logged via `slog.ErrorContext`.
PR: —
Commit: 6c5c78c
Date: 2026-06-08

---

### [SEC-003] Custom constant-time comparison (subtleConstantTime)

Source: Gemini CLI (LOW) / Claude validation (CONFIRMED LOW)
Status: CLOSED
Resolution: `subtleConstantTime` function removed from `server.go`. All 3 call sites (server.go CSRF header, server.go CSRF form value, login.go setup secret) replaced with `crypto/subtle.ConstantTimeCompare`.
PR: —
Commit: 6c5c78c
Date: 2026-06-08

---

### [SEC-P07] CreateTemp + Chmod race condition

Source: Gemini CLI
Status: CLOSED
Resolution: FALSE POSITIVE — Gemini assumed `os.CreateTemp`; actual code uses `os.OpenFile` with explicit `0o600` mode. The `.tmp` file is created at 0600 from the start; `os.Rename` is atomic; the subsequent `os.Chmod` is redundant but harmless.
PR: —
Commit: —
Date: 2026-06-08

---

### [SEC-P08] BufferAuditSink unbounded memory growth

Source: Gemini CLI
Status: CLOSED
Resolution: FALSE POSITIVE — `BufferAuditSink` / `NewBufferAuditSink` are test doubles only. No production code instantiates this type. Production uses `FileAuditSink`.
PR: —
Commit: —
Date: 2026-06-08
