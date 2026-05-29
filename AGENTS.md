# AGENTS

## Mission Focus

This repository is no longer a simple sync daemon. It is evolving into a distributed, forensic-grade security governance control-plane with:

- formal runtime FSM
- partitioned multi-worker scheduler
- HA coordination with fencing tokens
- scoped SQLite WAL persistence
- versioned migrations
- checkpoint-aware replay
- recovery engine
- deterministic evidence replay
- explainability and policy layers

Agents must preserve that foundation while continuing the migration from the historical Python 3.6.0 implementation.

## Hard Rules

1. Do not rewrite the healthy Go runtime unnecessarily.
2. Do not break existing public APIs unless explicitly requested.
3. Do not remove existing tests.
4. Do not replace SQLite/WAL persistence.
5. Do not couple OpenResty, Lua, or CrowdSec directly into the FSM core.
6. Add new behavior through isolated adapters, contracts, and compatibility layers.
7. Every new feature must come with unit or integration tests.
8. Every meaningful step must leave the repository green:
   - `gofmt -w .`
   - `go vet ./...`
   - `go test ./...`
   - `go test -race ./...`
   - `go build ./...`

## Python 3.6.0 Migration Strategy

Treat the Python 3.6.0 codebase as the historical source of truth for missing behavior, not as the target runtime architecture.

Migration order:

1. Audit the Python 3.6.0 gap against current Go.
2. Define versioned contracts under `contracts/`.
3. Implement isolated adapters under `internal/adapters/`.
4. Add temporary compatibility readers under `internal/compat/python36`.
5. Validate through replay, dry-run, and production-hardening checks.

## Priority Order

1. OpenResty + Lua config
2. CrowdSec integration
3. Cloudflare/API Shield hardening
4. Better Stack / observability
5. Python legacy cleanup

## Target Architecture

```text
Python 3.6.0 legacy
        ↓
compat/parser
        ↓
contracts/*.schema.json
        ↓
Go adapters
        ↓
event bus / FSM / scheduler
        ↓
SQLite WAL / replay / forensic timeline
```

Core Go runtime responsibilities:

- orchestration
- state
- persistence
- replay
- recovery
- auditability

Adapter responsibilities:

- OpenResty
- Lua
- CrowdSec
- Cloudflare
- Better Stack
- external parsing and validation

## Implementation Expectations

- Prefer incremental, low-risk patches over broad rewrites.
- Never add hidden goroutines.
- Never add silent mutations or side effects outside the event pipeline.
- Keep repositories free of business logic.
- Preserve deterministic replay, rollback semantics, scope isolation, and append-only audit integrity.

## Current Working Style

When resuming work on Python 3.6.0 migration:

1. Identify the current legacy Python artifact(s).
2. Produce or update `docs/migration/python36-gap-analysis.md`.
3. Implement only the next safe slice.
4. Validate fully before stopping.

## Reference

Read `ACCURACY_POLICY.md`, `SESSION_STATUS.md`, `MIGRATION_PROGRESS.md`, and `DECISIONS.md` before making substantial changes.
