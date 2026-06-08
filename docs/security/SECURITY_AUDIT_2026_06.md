# Security Audit — June 2026

**Date:** 2026-06-08  
**Auditor:** Gemini CLI (offensive red-team) + Claude (independent counter-expertise)  
**Scope:** Full codebase — security, robustness, performance, architecture

## Context

Audit conducted on project at v1.5.0 release state:

- 0 open GitHub Security alerts
- 0 open Dependabot alerts
- 0 open CodeQL alerts
- git history purged of known secrets
- CI green, branch protection active

## Methodology

1. Gemini CLI performed an aggressive red-team scan across all security categories
2. Claude independently validated each finding by reading source code and tracing call graphs
3. No assumption that Gemini was correct or incorrect — all findings verified from first principles

## Counter-Expertise Results

### Confirmed Findings (Fixed)

| ID | Gemini Severity | Real Severity | Status |
|----|-----------------|---------------|--------|
| SEC-001 | CRITICAL | LOW (dead code) | Fixed — commit 6c5c78c |
| SEC-002 | MEDIUM | MEDIUM | Fixed — commit 6c5c78c |
| SEC-003 | LOW | LOW | Fixed — commit 6c5c78c |

### Confirmed Findings (Deferred)

| ID | Severity | Decision |
|----|----------|----------|
| SEC-004 Rate limiter O(n) | LOW | FIX LATER (v1.6.0) |
| SEC-005 Setup wizard path | LOW | FIX LATER (v1.6.0) |
| SEC-006 crypto/rand panic | LOW | DOCUMENT ONLY |

### False Positives

| ID | Gemini Claim | Why Wrong |
|----|-------------|-----------|
| SEC-P07 CreateTemp + Chmod | Race condition on secret file creation | Code uses `os.OpenFile` with `0o600` from the start, not `os.CreateTemp`. The `Chmod` post-rename is redundant but harmless. |
| SEC-P08 BufferAuditSink memory | Unbounded growth in production | `BufferAuditSink` is a test double only. Production uses `FileAuditSink`. Gemini didn't trace instantiation sites. |

**False positive rate: 2/8 (25%)** — Gemini applied heuristic pattern matching without verifying code paths.

## What Gemini Did NOT Find

This is the more significant result of the audit:

- No authentication bypass
- No CSRF bypass or token weakness exploitable in practice
- No session fixation or hijacking vector
- No AES-GCM encryption weakness in the CredentialStore
- No secret leakage from logs or error messages (pre-existing)
- No injection in the CrowdSec or Cloudflare integration layers
- No SQLite WAL corruption or race condition
- No OPA policy bypass
- No replay event forgery

This validates the security architecture at v1.5.0 level.

## Residual Risk

| Risk | Assessment |
|------|-----------|
| SQL injection | Eliminated for existing code. `ExportHotSnapshot` was dead code; guard added. |
| Error disclosure | Eliminated in V3 API handlers. |
| Timing attacks on CSRF | Eliminated. Using `crypto/subtle.ConstantTimeCompare`. |
| Rate limiter DoS | Acceptable for local UI threat model. Tracked as SEC-004. |
| Path disclosure post-setup | Low impact. Tracked as SEC-005. |
| crypto/rand panic | Non-issue on modern Linux. Tracked as SEC-006. |

**Overall residual risk: LOW.** The project is suitable for continued production operation.

## Backlog

Full findings tracked in [docs/issues/SECURITY_BACKLOG.md](../issues/SECURITY_BACKLOG.md).

GitHub issues: #4 (closed), #5 (closed), #6 (closed), #7, #8, #9, #10, #11, #12
