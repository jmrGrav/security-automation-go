# Python 3.6.0 vs Go Gap Analysis

Updated: 2026-05-27 UTC

## Scope

This audit compares the production Python 3.6.0 implementation in `/home/jm/Documents/crowdsec-cf-sync/` against the current Go control-plane in `/home/jm/Documents/security-automation-go/`.

The Python code remains the operational source of truth for legacy behavior. This document is intentionally conservative: if parity could not be verified from repository code, the item is marked as partial or missing rather than assumed complete.

## Python 3.6.0 features already present in Go

- Cloudflare typed transport, discovery, pagination, normalization, and dry-run mutation scaffolding
  - Relevant Go paths:
    - `internal/cloudflare/transport`
    - `internal/cloudflare/discovery`
    - `internal/cloudflare/normalize`
    - `internal/cloudflare/mutate`
- CrowdSec integration boundary with translators and dry-run scaffolding
  - Relevant Go paths:
    - `internal/crowdsec/adapter`
    - `internal/crowdsec/translator`
    - `internal/crowdsec/validation`
- Append-only runtime event log, replay, checkpointing, and initial recovery
  - Relevant Go paths:
    - `internal/runtime/events`
    - `internal/runtime/checkpoint`
    - `internal/runtime/recovery`
    - `internal/runtime/replay/consistency`
- SQLite WAL persistence, migrations, scoped state, hot snapshots, and maintenance hooks
  - Relevant Go paths:
    - `internal/storage/manager`
    - `internal/storage/migrations`
    - `internal/storage/sqlite`
    - `internal/storage/snapshot`
- Governance and forensic substrate beyond the original Python scope
  - Relevant Go paths:
    - `internal/policy/*`
    - `internal/runtime/timeline`
    - `internal/runtime/ownership`
    - `internal/runtime/ha`
    - `internal/runtime/governor`

## Python 3.6.0 features partially migrated in Go

- Better Stack integration
  - Python has ingest behavior and operational usage.
  - Go has a boundary but `Send` is still not implemented.
  - Relevant Go paths:
    - `internal/betterstack/client.go`
- ModSecurity / nginx error-log correlation
  - Python performs ModSecurity-based security actions.
  - Go only has a placeholder service and TODO for nginx error log parsing.
  - Relevant Go paths:
    - `internal/modsecurity/service.go`
    - `internal/modsecurity/doc.go`
- Cloudflare reconciliation execution semantics
  - Go has typed planning and mutation scaffolding.
  - Python still carries mature production behavior for recidivist escalation, CIDR blocks, WAF polling, and safety heuristics.
  - Relevant Go paths:
    - `internal/reconciliation`
    - `internal/execution`
    - `internal/cloudflare/mutate`
- CrowdSec execution semantics
  - Go has boundaries, models, and translators.
  - Python remains the verified implementation for live operational behavior and scenario mapping.
  - Relevant Go paths:
    - `internal/crowdsec/*`

## Python 3.6.0 features missing in Go

- Versioned external contracts for the Python/OpenResty/Lua/CrowdSec/Better Stack ecosystem
  - No `contracts/` directory existed before this phase.
- OpenResty adapter boundary
  - Python ships generated nginx/OpenResty config and deployment assumptions.
  - Go had no isolated adapter to represent or validate that contract.
- Lua adapter boundary
  - Python and Lua coordinate through `bans.json`, `events.jsonl`, shared dict sizing, mitigation tuning, and sync freshness.
  - Go had no isolated contract-aware parser/validator for this configuration domain.
- Python 3.6.0 compatibility bridge
  - No `internal/compat/python36` package existed.
- Production-grade parity for:
  - OpenResty config generation/validation
  - Lua sync contract validation
  - CrowdSec acquisition/parser compatibility
  - Better Stack ingest semantics
  - Cloudflare/API Shield hardening logic proven against Python behavior

## High-risk regression areas

- OpenResty fail-open/fail-safe semantics
  - Python 3.6.0 and the Lua layer explicitly preserve request-path safety behavior under stale or missing sync data.
  - Recreating this incorrectly in Go would be operationally risky.
- Lua IPC contract
  - `bans.json` monotonic versioning, entry-count integrity, stale-file rejection, and `events.jsonl` rotation are part of the production design.
- Better Stack and observability expectations
  - Python emits operationally meaningful logs and metrics already used in production.
- Config compatibility
  - Python currently derives many behaviors from environment variables and generated files.
  - Moving too quickly to Go-native config without a compatibility layer risks silent drift.

## Recommended integration order

1. Introduce versioned contracts.
   - Purpose: decouple Go from direct dependence on legacy Python runtime structures.
2. Add parse/validate-only OpenResty and Lua adapters.
   - Purpose: make the external boundary explicit without touching FSM or mutation logic.
3. Add Python 3.6 compatibility readers.
   - Purpose: ingest legacy Python/OpenResty/Lua configuration and map it to Go contracts.
4. Implement Better Stack ingest behavior.
5. Implement OpenResty/Lua config validation and dry-run rendering.
6. Extend CrowdSec and Cloudflare parity using replay fixtures and compatibility tests.
7. Retire Python-owned behavior only after contract-level parity is proven.

## Minimal safe patch for this phase

This phase should remain intentionally narrow:

- Add `contracts/*.schema.json`.
- Add `internal/adapters/openresty` as a parse/validate/event-emission boundary.
- Add `internal/adapters/lua` as a parse/validate/event-emission boundary.
- Add `make verify`.

This phase should not:

- rewire the central FSM
- add live OpenResty side effects
- change SQLite schema
- change Cloudflare mutation execution
- replace Python production behavior

## Files expected to be touched next

- `contracts/events.schema.json`
- `contracts/openresty.schema.json`
- `contracts/crowdsec.schema.json`
- `contracts/cloudflare.schema.json`
- `contracts/betterstack.schema.json`
- `internal/adapters/openresty/*`
- `internal/adapters/lua/*`
- `Makefile`

## Remaining unknowns to resolve later

- Exact Python 3.6.0 compatibility inputs to support first:
  - generated nginx snippets
  - Lua runtime constants
  - environment-file projections
  - CrowdSec parser/acquis mappings
- Which Cloudflare/API Shield fields from Python must become explicit contracts in Go
- Which Better Stack payload shape should be considered canonical for parity
