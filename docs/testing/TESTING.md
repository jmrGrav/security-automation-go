# Testing Strategy

## Goals

The migration needs confidence in behavior parity, not just code coverage.

## Test layers

### Unit tests

Target:

- config parsing and validation
- retry behavior
- state store read/write semantics
- allowlist matching
- IPv4 and IPv6 normalization
- pagination logic
- deduplication keys and retention windows

### Golden tests

Capture representative production-like fixtures from:

- `decisions.log`
- nginx access logs
- nginx error logs with ModSecurity entries
- Cloudflare access-rule API payloads
- Cloudflare list item payloads
- Cloudflare WAF GraphQL payloads

Golden tests should assert that Go produces the same derived actions and state transitions as Python for those fixtures.

### Integration tests

Use fake HTTP servers and temporary directories to validate:

- Cloudflare client pagination and retries
- AbuseIPDB request formatting
- Better Stack ingest payload shape
- JSON state persistence across restarts

### Command tests

Exercise `cmd/*` wiring with injected fake clients and stores to validate:

- graceful shutdown
- scheduler cancellation
- dry-run behavior
- startup validation failures

## Shadow validation

Before production cutover:

- run the Go services in read-only mode
- compare computed decisions against Python outputs
- store diffs for investigation

## Non-functional checks

- long-running leak checks
- restart safety checks
- timeout and retry behavior under induced failures
- race checks with `go test -race` once Go is installed

## Minimum acceptance gate

Do not replace a Python service until:

- unit tests pass
- golden tests pass
- integration tests pass
- shadow diffs are understood
- rollback instructions are verified
