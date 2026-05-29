# Risk Analysis

## Highest-risk areas

### 1. Hidden coupling inside `crowdsec-cf-sync.py`

The current Python daemon mixes multiple domains in one loop. Splitting it into Go packages improves maintainability but risks changing sequencing, deduplication, and state timing.

Mitigation:

- preserve current responsibility boundaries in documentation first
- use golden tests for each sub-feature
- cut over sub-features progressively

### 2. State compatibility drift

Several behaviors depend on JSON files storing timestamps and deduplication markers.

Mitigation:

- document current state purposes now
- keep JSON schemas simple and explicit
- add compatibility tests with fixture files

### 3. IPv6 normalization

The Python sync explicitly normalizes IPv6 access-rule values to avoid duplicate add/remove cycles.

Mitigation:

- centralize normalization in one helper
- test compressed and expanded forms

### 4. External dependency rate limits

Cloudflare and AbuseIPDB calls are rate-limited.

Mitigation:

- typed clients with retry policy and pagination
- bounded concurrency only where ordering does not matter
- structured logs for retries and throttling

### 5. Local environment assumptions

The Python scripts assume:

- `cscli` exists
- specific log paths exist
- writable state paths exist

Mitigation:

- validate environment at startup
- fail clearly
- isolate path configuration in env-driven config

### 6. Unsafe cleanup semantics

The cleanup script is intentionally destructive except for rules containing `easycron`.

Mitigation:

- keep a dry-run mode in Go before enabling deletes
- test case-insensitive keep matching

## Medium-risk areas

- log parsing drift for ModSecurity
- behavior changes caused by different time parsing
- accidental change from additive sync to full reconciliation for allowlists
- scheduler timing differences after restart

## Low-risk areas

- systemd scaffolding
- structured logger initialization
- config loading
- dependency injection layout
