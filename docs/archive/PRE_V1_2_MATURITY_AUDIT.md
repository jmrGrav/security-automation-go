# PRE-V1.2 MATURITY AUDIT: SECURITY-AUTOMATION-GO

**Auditor:** Gemini CLI (Senior Go/Security/Operations Reviewer)
**Date:** Friday, June 5, 2026
**Scope:** Repository Root (v1.1.1+)
**Status:** Pre-v1.2 Readiness Assessment

---

## EXECUTIVE SUMMARY

The `security-automation-go` project has evolved into a sophisticated security control plane. The transition from Phase-0 stubs to a formal event-sourced runtime with HA fencing, multi-domain ownership, and OPA policy integration is a significant achievement. The codebase demonstrates high technical rigor in its core state management and reconciliation logic.

However, the project currently faces **Operational and Installability "Last Mile"** challenges that prevent it from being a "plug-and-play" production platform. Specifically, interactions between systemd hardening (`DynamicUser`), logging subsystems, and signal handling create risks for production stability.

**Overall Maturity Score: 84/100**
**Verdict: PRODUCTION READY WITH CONDITIONS**

---

## PHASE 1 — ARCHITECTURE REVIEW

| Component | Score | Justification |
|-----------|-------|---------------|
| **runtime FSM** | **A+** | Formal state machine with strict transition rules, event sourcing, and checkpointing. Excellent epoch management. |
| **scheduler** | **A** | Stateful, pool-based scheduler. Handles interval-based execution with proper concurrency controls. |
| **replay engine** | **A-** | WAF replay poller is well-structured with cursor persistence. Some "reserved" routes in UI indicate work-in-progress. |
| **recovery engine** | **A** | Durable rollback checkpoints and a dedicated rollback planner provide strong reliability guarantees. |
| **SQLite WAL persistence** | **A+** | Sophisticated use of SQLite. Correct pragmas (WAL, synchronous=NORMAL), migration management, and integrity checks. |
| **ownership lineage** | **A** | Clear separation of authoritative (Terraform) vs managed (cf-sync) domains. Append-only lineage recording. |
| **HA fencing** | **A** | LeaseManager with monotonic fencing tokens effectively prevents split-brain mutations. |
| **policy engine** | **A** | Multi-tiered evaluation: simple built-in rules + OPA (Rego) + conflict resolution (Deny wins). |
| **UI architecture** | **B+** | Clean separation using `views.templ`. Server-side logic in `server.go` is becoming dense; consider further modularization. |
| **provider architecture** | **A** | High-quality transport and adapter patterns. Strong validation at boundaries (e.g., `cscli` duration regex). |
| **startup config** | **A-** | Robust environment-driven config with validation. Minimal "magic" defaults. |

---

## PHASE 2 — SECURITY REVIEW

### FINDINGS

| ID | Severity | Category | Finding | Evidence |
|----|----------|----------|---------|----------|
| **SEC-01** | **MEDIUM** | Secret Leakage | `CF_SYNC_API_TOKEN` is environment-only. | `cmd/cf-sync/daemon_runtime.go:49`. Risks leakage via `/proc` or debug dumps. |
| **SEC-02** | **MEDIUM** | Auth Bypass | `localhost-only` assumption. | UI defaults to `127.0.0.1`. If bound to `0.0.0.0` without TLS, session cookies are vulnerable. |
| **SEC-03** | **LOW** | CSRF | Pending remediation for some routes. | `TODO.md` Task 2: "CSRF remediation (settings.go, logout, forensic, intelligence)". |
| **SEC-04** | **INFO** | Permissions | Secret file permissions are `0600`. | Correctly implemented in `internal/ui/auth/bootstrap.go`. |

### ASSESSMENT
The security posture is strong. The use of bcrypt for UI passwords, HMAC-SHA256 for CSRF tokens, and the "Fail-Closed" design for Cloudflare/CrowdSec mutations demonstrate a "Security by Design" mindset. The primary risk is secret leakage through the environment and the pending CSRF work.

---

## PHASE 3 — OPERATIONS REVIEW

### FINDINGS

| ID | Severity | Finding | Consequence |
|----|----------|---------|-------------|
| **OPS-01** | **HIGH** | `DynamicUser=yes` vs Log Perms | The `tmpfiles.conf` creates `/var/log/security-automation` as `root:root`. The service (running as a random UID) will fail to write startup/health logs. |
| **OPS-02** | **HIGH** | Missing `SIGUSR1` Handler | `logrotate` sends `SIGUSR1` to trigger log reopening. The app does not handle this signal, leading to potential crash or failed rotation. |
| **OPS-03** | **MEDIUM** | Startup Log Lifecycle | `startuplog` directory creation at runtime might fail if the parent `/var/log` is restricted (common in hardened systems). |

### ASSESSMENT
Operational readiness is the weakest link. The project uses advanced systemd hardening (`DynamicUser`, `ProtectSystem=strict`), but the supporting infrastructure (logging/rotation) is not fully aligned with these features.

---

## PHASE 4 — INSTALLABILITY REVIEW

### BLOCKERS (Ranked)

1. **Manual Env Setup:** Operator must manually construct `/etc/security-automation/security-automation.env` with 4+ secrets before the service can even start. (High)
2. **Bootstrap Friction:** The bootstrap password process is secure but adds cognitive load. A `cf-sync init` command is missing. (Medium)
3. **Documentation Sync:** `README.md` claims no tests for transport/adapter, which is false. This discourages contributors/auditors. (Low)

**"Install to Operational in 15 mins" Target:** **NOT MET.**
Current estimate: 30-45 minutes due to manual configuration and environment preparation.

---

## PHASE 5 — TEST REVIEW

### ASSESSMENT
- **Unit Tests:** Excellent coverage on critical paths (`runtime/engine`, `storage/sqlite`).
- **Race Tests:** Clean (verified).
- **Integration Tests:** Strong UI integration tests (`internal/ui/auth_integration_test.go`).
- **Gaps:** 
    - End-to-end "First Boot" tests are missing.
    - `SIGUSR1` handling tests are missing (because handler is missing).
    - `DynamicUser` permission simulation tests are missing.

---

## PHASE 6 — RED TEAM REVIEW

### REPRODUCIBLE FINDINGS
1. **Log Failure:** In a standard systemd environment with the provided unit, the app will log `Error: startuplog: open startup.log: permission denied` and fail to provide diagnostics.
2. **Rotation Crash:** Sending `kill -USR1 <pid>` to the daemon causes it to exit (default Go behavior for unhandled USR1).

### THEORETICAL FINDINGS
1. **Token Exhaustion:** A malicious internal user could trigger thousands of "AI Explain" requests to exhaust the provider quota, although the rate limiter (`10/min`) mitigates this significantly.

---

## PHASE 7 — V1.2 READINESS SCORE

| Category | Score |
|----------|-------|
| Architecture | 95/100 |
| Security | 85/100 |
| Reliability | 90/100 |
| Operations | 70/100 |
| Installability | 75/100 |
| Maintainability | 90/100 |

**Overall Maturity Score: 84/100**
**Classification: PRODUCTION READY WITH CONDITIONS**

---

## PHASE 8 — TOP 10 IMPROVEMENTS (PRE-V1.2)

1. **Systemd Alignment:** Replace `tmpfiles.conf` log creation with `LogsDirectory=security-automation` in the `.service` file to let systemd handle `DynamicUser` permissions.
2. **Signal Handling:** Implement `SIGUSR1` handler to reopen `startuplog` file handles.
3. **Secret Security:** Add `CF_SYNC_API_TOKEN_FILE` support to allow loading the admin token from a `0600` file instead of the environment.
4. **Onboarding CLI:** Add `cf-sync init` to interactively generate the environment file and secrets.
5. **CSRF Completion:** Finish the `TODO.md` Task 2 remediation for settings and forensic pages.
6. **Documentation Audit:** Update `README.md` to reflect current (passing) test status and actual coverage.
7. **Health Observability:** Expose the `startuplog` healthcheck results directly in the "System" page of the UI.
8. **Binary Hardening:** Ensure `Makefile` uses `-trimpath` and `-buildmode=pie` for production builds.
9. **Logrotate Refinement:** Update logrotate to use `copytruncate` if `SIGUSR1` handling is delayed, to avoid service interruption.
10. **Schema Validation:** Add `PRAGMA integrity_check` to the UI "System" page to allow operators to verify the SQLite state.
