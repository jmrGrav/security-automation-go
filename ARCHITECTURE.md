# Architecture

## Goals

The Go implementation is designed to replace the production Python stack progressively, not by in-place modification. The migration keeps the current Python services untouched while a parallel Go stack is developed, tested, and shadow-validated.

Primary goals:

- lower memory usage
- more predictable long-running behavior
- explicit dependency injection
- better observability
- safer concurrency and shutdown behavior
- simpler unit and integration testing

## High-level layout

### `cmd/`

Each command maps to one current Python entrypoint and stays narrowly focused:

- `cmd/crowdsec-sync`
- `cmd/cf-allowlist-sync`
- `cmd/cf-cleanup`

Each command only wires config, logging, signals, dependency injection, and the top-level scheduler. Business logic lives under `internal/`.

### `internal/`

`internal/config`

- environment-driven configuration loading
- typed config structs
- validation and defaults
- service-specific settings without global mutable state

`internal/logging`

- central `slog` logger creation
- consistent JSON or text structured output
- shared service metadata fields

`internal/cloudflare`

- typed Cloudflare client models and interfaces
- future home for access-rule APIs, list APIs, and GraphQL WAF polling

`internal/crowdsec`

- typed interface for `cscli`/future API access
- active decisions, allowlists, and escalation commands

`internal/abuseipdb`

- typed reporter client
- category mapping and future rate-limit handling

`internal/betterstack`

- Better Stack ingest client abstraction

`internal/modsecurity`

- future log parser and temporary-ban decision logic

`internal/recidive`

- recidivist tracking, escalation policy, and retention logic

`internal/cidrban`

- `/24` aggregation logic and future IPv6-compatible network policy extensions

`internal/state`

- JSON-backed persistence for migration phase one
- swappable storage boundary for future SQLite adoption

`internal/utils`

- reusable helpers for retry, HTTP client creation, timing, and network parsing

`internal/scheduler`

- interval runner with context cancellation
- safe goroutine ownership and graceful shutdown boundaries

`internal/app`

- service bootstrap
- dependency graph assembly
- runner implementations that connect command wiring to internal service interfaces

## Dependency direction

The architecture intentionally points inward:

- `cmd/*` depends on `internal/app`, `internal/config`, and `internal/logging`
- `internal/app` depends on service packages through interfaces
- service packages depend on common helpers in `internal/state` and `internal/utils`
- no package depends on `cmd/*`

This keeps the business logic unit-testable without process-level wiring.

## Concurrency model

This scaffold assumes:

- one owning context per process
- one scheduler loop per binary
- bounded goroutines with explicit context cancellation
- no background goroutine without a clear owner
- shared state only behind interfaces and synchronization primitives

The goal is to avoid the hidden race risks that often appear when a single Python script is split into concurrent workers without clarifying ownership first.

## Service mapping

### `crowdsec-cf-sync.py` -> `cmd/crowdsec-sync`

Planned internal sub-services:

- `crowdsec.ActiveBanSource`
- `cloudflare.AccessRuleClient`
- `abuseipdb.Reporter`
- `modsecurity.Service`
- `recidive.Service`
- `cidrban.Service`
- `betterstack.IngestClient`
- `state.Store`

This command is intentionally decomposed because the current Python daemon couples multiple concerns in one loop. The Go design separates those concerns without changing the externally observed behavior.

### `cloudflare-allowlist-update.py` -> `cmd/cf-allowlist-sync`

Planned internal sub-services:

- `cloudflare.ListClient`
- `crowdsec.AllowlistManager`
- `utils.HTTPFetcher`

### `cloudflare-cleanup-ip-rules.py` -> `cmd/cf-cleanup`

Planned internal sub-services:

- `cloudflare.AccessRuleClient`
- cleanup policy component to preserve selected notes/comments

## State model

JSON persistence is kept first for compatibility and rollout simplicity.

Initial JSON state files mirror the Python responsibilities:

- AbuseIPDB reported state
- recidivist counters
- ModSecurity temporary-ban state
- CIDR-ban state
- Cloudflare WAF cursor state

Future migration to SQLite should happen behind the `internal/state` interfaces so command code and business rules do not need to change.

## Compatibility concerns

- IPv6 values must be normalized consistently to avoid duplicate add/remove loops.
- CrowdSec allowlist matching must continue to support both individual IPs and CIDR entries.
- `cloudflare-allowlist-update.py` currently performs additive sync only for CrowdSec allowlists and does not remove existing entries.
- cleanup logic currently keeps rules whose note contains `easycron`, case-insensitively.
- `crowdsec-cf-sync.py` relies on local log files and `cscli`, not only remote APIs.
- several current Python behaviors depend on JSON state retention windows and deduplication keys; those must be kept exactly during migration.

## Extensibility

The package split is intentionally more granular than the current Python scripts because the migration needs stable seams:

- interfaces permit mock-driven tests before production cutover
- the JSON store can later be replaced by SQLite
- typed clients make rate limits, retries, and pagination easier to centralize
- service-specific runners allow progressive enablement and shadow mode
