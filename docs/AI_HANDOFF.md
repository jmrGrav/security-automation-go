# AI Handoff — security-automation-go

Rapid context for AI assistants and future contributors. Read this before proposing changes, running audits, or refactoring.

**Table of Contents**

1. [Project Overview](#1-project-overview)
2. [Active Components](#2-active-components)
3. [Retired Components](#3-retired-components)
4. [Non-Negotiable Decisions](#4-non-negotiable-decisions)
5. [Environment Assumptions](#5-environment-assumptions)
6. [First-Time User Philosophy](#6-first-time-user-philosophy)
7. [Detection First](#7-detection-first)
8. [Security Rules](#8-security-rules)
9. [Legacy Component Registry](#9-legacy-component-registry)
10. [CrowdSec Philosophy](#10-crowdsec-philosophy)
11. [Configuration Philosophy](#11-configuration-philosophy)
12. [Before Any Refactor](#12-before-any-refactor)
13. [AI Assistant Rules](#13-ai-assistant-rules)
14. [Lessons Learned](#14-lessons-learned)

---

## 1. Project Overview

`security-automation-go` is the Go successor to a historical Python-based CrowdSec → Cloudflare automation runtime. It automates threat response for a self-hosted homelab: bans are ingested from CrowdSec, enriched, and enforced on Cloudflare IP access rules. The system also provides a local WAF layer, a health UI, a first-boot wizard, AI-assisted threat explanation, and packaging for Debian/Ubuntu.

**Current version:** v1.5.0 (released 2026-06-08). First-run wizard validated. Encrypted CredentialStore production-ready. CrowdSec Go integration complete. Python retired from critical path.

**Current maturity:** production on a single-node Ubuntu homelab. Active development. Python retirement complete on critical path; stub entrypoints retained for rollback.

**High-level architecture:**

```
CrowdSec LAPI / cscli
       │
       ▼
Go crowdsec-sync daemon  ──▶  Cloudflare WAF rules
       │
       ├──▶ SQLite WAL (state, credentials, events)
       ├──▶ decisions.log  ──▶  Vector ──▶  BetterStack
       ├──▶ OpenResty Lua bouncer (bans.json)
       └──▶ Health Center / UI (port 9091)
```

**Deployment:** single Ubuntu host, systemd-managed daemons, `.deb` packaging for distribution.

---

## 2. Active Components

| Component | Package / Path | Role |
|---|---|---|
| Go Runtime | `internal/app`, `cmd/` | Core sync daemon and command entrypoints |
| SQLite WAL | `internal/storage/sqlite` | Primary state backend; WAL mode; single writer |
| CredentialStore | `internal/storage/sqlite/credential_store.go` | Encrypted secret storage; AES-GCM per-secret |
| CrowdSec sync | `internal/crowdsec`, `internal/app` | Reads decisions/bans, enforces on Cloudflare |
| CrowdSec AppSec | WAF layer via CrowdSec | Handles application-layer attack detection |
| CrowdSec Poller | `internal/crowdsec/poller` | Go replacement for `crowdsec-poller.py`; writes `decisions.log` |
| Cloudflare | `internal/cloudflare` | IP access rule management |
| OpenResty + Lua | `internal/openresty` | Local bouncer: publishes `bans.json` for Lua module |
| Health Center | `internal/health` | System health checks; RED/YELLOW/GREEN per subsystem |
| Detection Engine | `internal/detect` | Auto-discovers CrowdSec, OpenResty, Nginx, paths, services |
| Wizard | `internal/ui` (setup flow) | First-boot guided setup; skip-friendly for all optional components |
| Recovery Engine | `internal/rollback` | Checkpoint and rollback for enforcement actions |
| Replay Engine | `internal/runtime` (replay) | Cloudflare WAF event replay for AbuseIPDB reporting |
| AI Explain | `internal/ai`, `internal/ai/providers` | Optional threat explanation via OpenAI/Anthropic/Gemini |
| Packaging | `deployments/` | `.deb` packaging for Ubuntu/Debian homelab install |
| recidive | `internal/recidive` | Escalates repeat offenders to longer bans |
| cidrban | `internal/cidrban` | Auto-bans /24 CIDRs when threshold exceeded |
| AbuseIPDB | `internal/abuseipdb` | Enrichment + reporting for observed threats |

---

## 3. Retired Components

| Component | Status | Replacement |
|---|---|---|
| **ModSecurity** | **RETIRED** | OpenResty + CrowdSec AppSec are active. `internal/modsecurity` exists but is legacy — do not extend, port, or wire. |
| `crowdsec-notifier.py` | **REPLACED** | Go `crowdsec-sync` daemon handles CF push and AbuseIPDB. |
| Python runtime | **RETIREMENT IN PROGRESS** | `crowdsec-poller.py` is the last active Python script (pending cutover to Go poller). |
| Historical CF push path | **LEGACY** | Pre-Go Cloudflare push logic; superseded by `internal/cloudflare`. |

**Rule:** the existence of code in the repository does not imply it is used in production. Always check `cmd/` entrypoints and systemd units before classifying a feature as active.

---

## 4. Non-Negotiable Decisions

> **DO NOT CHANGE WITHOUT STRONG JUSTIFICATION**

### SQLite WAL

SQLite WAL is the primary storage backend. Do **not** propose PostgreSQL as a replacement. PostgreSQL remains an optional future backend only. The single-writer constraint is deliberate — do not introduce concurrent mutation paths.

### OpenResty + Lua

Preserve OpenResty + Lua as the local mitigation layer. Do not propose replacing it.

### CrowdSec AppSec

CrowdSec AppSec is the WAF layer. Do not propose reintroducing ModSecurity.

### Credential Storage

All secrets belong in the encrypted CredentialStore. Do **not** recommend:
- plaintext `.env` files for operator secrets
- hardcoded values in code or YAML
- real tokens in markdown, examples, reports, or screenshots
- new `SECRET_NAME=value` patterns in env docs

---

## 5. Environment Assumptions

**Reserved ports:**

| Port | Service | Rule |
|---|---|---|
| 9090 | Cockpit | Never use — conflicts with Cockpit |
| 9091 | Security Automation UI | Current wizard/UI port |

**Primary platform:** Ubuntu, systemd, OpenResty, CrowdSec, Cloudflare.

**CrowdSec is recommended, not mandatory.** The application must function without it.

---

## 6. First-Time User Philosophy

The project must remain **homelab friendly**. A user should be able to install the `.deb`, open the wizard, and click Next — the software discovers everything it can automatically.

**Wizard principles:**
- Detect automatically via `internal/detect`
- Pre-fill detected values (LAPI URL, paths, services, log dirs)
- Allow Skip on every optional component
- Allow later configuration from UI Settings

**Never force** during first setup: CrowdSec, Cloudflare, AbuseIPDB, AI providers. All are opt-in.

---

## 7. Detection First

`internal/detect` is a core subsystem. Before introducing a new manual configuration field, determine whether the value can be auto-detected.

**Items that should be detected, not hardcoded:**
- CrowdSec installed / service active / LAPI reachable
- LAPI URL and port
- OpenResty / Nginx presence and paths
- `cscli` binary location
- State directories, log directories

Detection priority: **auto-detect → saved config → manual entry**. Detection is continuous, not first-boot only — re-run on Health Center open and detect configuration drift.

---

## 8. Security Rules

### Secret Handling

Never place real secrets in:
- README, docs, markdown reports
- code examples or test fixtures
- screenshots or commit messages
- code comments

### Secret Storage

All operator secrets belong in the encrypted CredentialStore (`internal/storage/sqlite/credential_store.go`). The store uses per-secret AES-GCM encryption with a master key derived from the host's machine-specific entropy.

The UI operator flow for secrets: **set / replace / delete / test — never redisplay the value**.

### Fail Closed

Security modules fail closed when misconfigured. However, a failure in one subsystem (e.g., CrowdSec LAPI key absent) must not bring down:
- Dashboard
- Wizard
- Health Center
- UI
- the entire runtime

Errors are isolated to the affected subsystem. The poller logs a clear error and exits its goroutine; the rest of `crowdsec-sync` continues.

---

## 9. Legacy Component Registry

| Component | Status | Notes |
|---|---|---|
| ModSecurity | RETIRED | `internal/modsecurity` exists but is not wired. CrowdSec AppSec + OpenResty are active. Do not reintroduce. |
| `crowdsec-notifier.py` | REPLACED | Go daemon handles CF push. Python service stopped and disabled at cutover. |
| `crowdsec-poller.py` | PENDING CUTOVER | Go replacement (`internal/crowdsec/poller`) is complete. Python service still running until cutover confirmed. |
| Python runtime | RETIREMENT PHASE | Last active Python script is `crowdsec-poller.py`. All other Python components replaced. |
| Historical CF push path | LEGACY | Pre-Go Cloudflare enforcement; not in current `cmd/` entrypoints. |

---

## 10. CrowdSec Philosophy

CrowdSec is **RECOMMENDED**, not **REQUIRED**.

If CrowdSec is absent or misconfigured:
- UI, Dashboard, SQLite, Recovery, Replay, Packaging continue to function
- CrowdSec-related features degrade gracefully with Health CENTER showing RED for the affected subsystem
- The wizard allows skipping CrowdSec entirely

This applies equally to: Cloudflare, AbuseIPDB, AI providers. All integrate cleanly but none are mandatory for the application to start.

---

## 11. Configuration Philosophy

Avoid creating new hidden environment variables. The operator should not need to edit `.env` to manage the system in steady state.

**For future modules, prefer this hierarchy:**

1. Wizard (first-boot, skip-friendly)
2. Settings UI (post-setup, any time)
3. Health Center (observe and reconfigure)
4. CredentialStore (for secrets)

Over: manual `.env` editing, YAML secret fields, hardcoded defaults.

Non-secret tunables (URLs, intervals, feature flags) may remain in env/YAML. Secrets never do.

---

## 12. Before Any Refactor

Before proposing major changes, check:

- `docs/AI_HANDOFF.md` (this file) — architectural memory
- `docs/architecture/` — design decisions
- `docs/migration/` — Python retirement progress
- `docs/runbooks/` — operational procedures

**If documentation and code disagree:** do not immediately modify the code. First determine whether the component is ACTIVE, LEGACY, or RETIRED by checking `cmd/` entrypoints, systemd units, and git log.

---

## 13. AI Assistant Rules

Before recommending changes to any component:

1. Classify it: **ACTIVE / LEGACY / RETIRED**
2. Check whether it is wired in a `cmd/` entrypoint and a systemd unit
3. The existence of a package does not imply production use

**Example:** `internal/modsecurity` exists. ModSecurity is RETIRED. Do not recommend extending, porting, or wiring it.

**Credential rule:** Never suggest storing a real token in a markdown doc, config example, test, or env file — even temporarily. Always route through CredentialStore.

**Port rule:** Never suggest port 9090. It conflicts with Cockpit.

**SQLite rule:** Do not propose replacing SQLite with PostgreSQL unless there is explicit evidence that the single-node constraint has been lifted.

---

## 14. Lessons Learned

### Code present ≠ Feature active

Always verify runtime wiring before classifying a feature as a blocker or a dependency. Check `cmd/` and systemd units, not just `internal/`.

### Detection first, manual configuration second

If a value can be auto-detected (path, port, service state, URL), prefer detection over requiring the user to configure it manually.

### Secrets belong in CredentialStore, not in docs or .env

Never expose real tokens in markdown, examples, reports, commits, or screenshots — even in redacted form that reveals structure. If a key appears in an AI context, recommend rotation.

### Recommended does not mean required

CrowdSec, Cloudflare, AbuseIPDB, and AI providers must integrate cleanly but must not prevent a fresh installation from functioning. Fail-closed scoped to the subsystem; fail-open at the application level.

### Operational simplicity beats architectural purity

Prefer solutions that are understandable, maintainable, observable, and deployable by homelab users. A working single-node SQLite system beats a theoretically superior distributed backend that requires infrastructure knowledge to operate.
