# Security Backlog

Audit source: Gemini CLI red-team + Claude independent validation — 2026-06-08
Resilience audit source: Gemini CLI (R1–R6) + Claude independent validation — 2026-06-08

## OPEN

_No open entries._

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

### [SEC-004] Rate limiter O(n) cleanup on every request

Source: Gemini CLI (HIGH) / Claude validation (CONFIRMED LOW in current deployment)
Status: CLOSED — NO ACTION
Resolution: The UI is designed for local operator access. In practice, the `clients` map holds at most ~5 entries (distinct operator IPs). The O(n) scan is sub-microsecond at this scale. The 100k IP scenario would require the UI to be exposed to internet traffic, which contradicts the local-access threat model. No fix justified.
GitHub: https://github.com/jmrGrav/security-automation-go/issues/7
Date: 2026-06-08

---

### [SEC-005] Setup wizard path disclosure post-setup

Source: Gemini CLI (HIGH) / Claude validation (CONFIRMED LOW)
Status: CLOSED — FIXED
Resolution: Added `setupStore.IsComplete()` check in `handleSetupStep1`. If setup is complete, the handler redirects unauthenticated visitors to `/login` immediately, preventing the `SecretFile` path from being revealed. Fix: `internal/ui/setup_wizard.go`.
GitHub: https://github.com/jmrGrav/security-automation-go/issues/8
Commit: see PR fix/sec-005-sec-007-close-issues
Date: 2026-06-08

---

### [SEC-006] crypto/rand panic in login handler

Source: Gemini CLI (MEDIUM) / Claude validation (CONFIRMED LOW)
Status: CLOSED — NO ACTION
Resolution: `crypto/rand.Read()` never returns an error on Linux 3.17+ (getrandom syscall) — the only supported platform. `net/http` recovers handler panics; the daemon would not crash. Changing the signature to return `(string, error)` and propagating through all callers would add complexity with zero practical benefit on supported platforms.
GitHub: https://github.com/jmrGrav/security-automation-go/issues/9
Date: 2026-06-08

---

### [SEC-007] UI auth/session/CSRF audit — session invalidation on password change

Source: Post-audit recommendation (Claude)
Status: CLOSED — FIXED
Resolution: `handleChangePassword()` now clears the entire `sessions` map under `s.mu` after a successful password hash update. All active sessions are invalidated; the user is redirected to `/login`. Fix: `internal/ui/settings.go`. Cookie attributes (Secure, HttpOnly, SameSite Strict) and CSRF implementation were audited and confirmed correct; no changes needed there.
GitHub: https://github.com/jmrGrav/security-automation-go/issues/10
Commit: see PR fix/sec-005-sec-007-close-issues
Date: 2026-06-08

---

### [SEC-008] OpenResty/Lua ingestion hardening review

Source: Post-audit recommendation (Claude)
Status: CLOSED — NO ACTION
Resolution: No specific vulnerability identified in the Go/Lua trust boundary. The OpenResty layer was not in scope for the Gemini red-team audit, and no actionable finding was produced. A dedicated review is appropriate when the Lua layer undergoes significant changes.
GitHub: https://github.com/jmrGrav/security-automation-go/issues/11
Date: 2026-06-08

---

### [SEC-009] SQLite recovery and corruption resilience review

Source: Post-audit recommendation (Claude)
Status: CLOSED — NO ACTION
Resolution: No specific corruption or injection vector identified in the WAL/recovery paths. Gemini audit found no issue here; independent code review confirmed the recovery manager, quarantine logic, and WAL checkpoint interactions are structurally sound. No actionable finding.
GitHub: https://github.com/jmrGrav/security-automation-go/issues/12
Date: 2026-06-08

---

### [SEC-010] Governance evidence recorder volatile — data lost on restart

Source: Gemini CLI Resilience Audit (R1) / Claude validation (CONFIRMED LOW)
Status: CLOSED — NO ACTION
Resolution: The in-memory recorder is used by two callers: (1) `GET /api/v2/policy/evidence` (diagnostic list), and (2) `GET /api/v3/policy/explain` (causal graph for a specific evidence ID). Both are diagnostic/audit endpoints; no enforcement decision depends on the recorder. The persistent `GET /api/v3/security/evidence/{id}/explain` endpoint (SQLite-backed) is the canonical path for security evidence queries and is unaffected. The RAM-only behavior is documented in the source comment. No enforcement impact; diagnostic degradation is acceptable.
GitHub: https://github.com/jmrGrav/security-automation-go/issues/13
Date: 2026-06-08

---

### [SEC-011] Drift memory store volatile — analytics context lost on restart

Source: Gemini CLI Resilience Audit (R2) / Claude validation (CONFIRMED LOW)
Status: CLOSED — NO ACTION
Resolution: The drift memory store is analytics-only. No security enforcement path reads from it; decisions are driven by the reconciler + OPA. After restart, drift occurrence counts and severity trends reset — this affects confidence scoring in analytics dashboards only. The behavior is intentional and does not degrade security posture.
GitHub: https://github.com/jmrGrav/security-automation-go/issues/14
Date: 2026-06-08

---

### [SEC-012] Non-deterministic OperationID in reconciliation planner

Source: Gemini CLI Resilience Audit (R4) / Claude validation (PARTIAL LOW)
Status: CLOSED — NO ACTION
Resolution: Non-deterministic OperationID is intentional design. The field provides per-attempt uniqueness in the audit trail and in the security guard's `RuleID` label (`ResourceType:OperationID`). For cross-attempt correlation, the deterministic `IdempotencyKey` (content-hash, no timestamp) is the correct field. Removing `time.Now()` from `deriveOpID` would make OperationID identical to the content-hash, eliminating per-attempt traceability and making retry events indistinguishable in the audit log — a regression. No fix justified.
GitHub: https://github.com/jmrGrav/security-automation-go/issues/15
Date: 2026-06-08

---

### [SEC-013] CrowdSec decisions.log O(n) full scan on every sync tick

Source: Gemini CLI Resilience Audit (R5) / Claude validation (CONFIRMED LOW)
Status: CLOSED — NO ACTION
Resolution: With standard CrowdSec logrotate configuration (daily rotation), `decisions.log` is bounded at ~10k lines per scan. At 2 scans per interval, the total I/O is sub-millisecond. A cursor implementation tracking file offset + inode (for rotation detection) would add meaningful complexity for negligible gain in the standard deployment. No fix justified.
GitHub: https://github.com/jmrGrav/security-automation-go/issues/16
Date: 2026-06-08

---

### [SEC-R03] Cloudflare non-idempotent POST after crash

Source: Gemini CLI Resilience Audit (R3)
Status: CLOSED
Resolution: FALSE POSITIVE — Gemini assumed HTTP-level idempotency is required. The reconciler uses content-addressed `StableIdentityKey` (`ip:{target}:{value}:{mode}` for IP access rules, verified in `normalize/normalize.go:22`). After a crash-before-checkpoint, the next cycle's discovery fetches Cloudflare state including the already-created rule; the planner sees it exists in the current snapshot and generates no create operation. The system is naturally idempotent through snapshot diffing, not HTTP idempotency keys.
PR: —
Commit: —
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
