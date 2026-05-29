# Migration Plan

## Principles

- Do not modify the Python scripts.
- Keep Python as the production source of truth until parity is proven.
- Replace behavior progressively, not all at once.
- Validate each responsibility independently before cutover.

## Phase 0: This step

- analyze all three production Python scripts
- extract responsibilities and compatibility-sensitive behavior
- build a separate Go module
- define interfaces, models, config, logging, and state boundaries
- create deployment and testing documentation

## Phase 1: Read-only parity

- implement typed Cloudflare, CrowdSec, AbuseIPDB, and Better Stack clients
- implement log readers and parsers
- implement JSON state store behavior compatible with current files
- add golden tests from captured Python inputs and outputs
- run Go binaries in shadow mode with no write actions

Success criteria:

- Go logs and computed decisions match Python expectations on captured fixtures
- no unbounded goroutines
- stable memory profile under long-running tests

## Phase 2: Controlled write capability

- enable one write path at a time behind config flags
- start with lowest-risk service first:
  1. `cf-cleanup`
  2. `cf-allowlist-sync`
  3. `crowdsec-sync` sub-features individually

Success criteria:

- Go and Python outputs match on dry-run comparisons
- retries and timeouts are observable
- no state corruption across restarts

## Phase 3: Dual-run validation

- run Python and Go in parallel where safe
- keep Go write-disabled for features still owned by Python
- compare resulting Cloudflare/CrowdSec state snapshots
- document every difference before enabling write mode

## Phase 4: Incremental cutover

- move one service at a time to Go-managed systemd units
- preserve original Python unit/service definitions for rollback
- keep rollback path to Python immediate and documented

## Phase 5: Post-cutover hardening

- replace JSON storage with SQLite behind interfaces
- add metrics if needed
- tighten security posture and secret delivery

## Feature work order recommendation

1. Common HTTP client, retries, and config
2. Cloudflare typed client and pagination
3. CrowdSec `cscli` wrapper and decision models
4. Allowlist sync behavior
5. Cleanup behavior
6. CrowdSec active-ban sync
7. AbuseIPDB reporting
8. Recidive escalation
9. ModSecurity parsing
10. CIDR auto-ban
11. Better Stack ingest
12. Cloudflare WAF polling

## Rollback strategy

- keep Python binaries and units unchanged
- deploy Go binaries with separate names and unit files first
- use dry-run or read-only mode where possible
- cut over only after side-by-side state comparison
- revert by stopping Go units and restarting Python units
