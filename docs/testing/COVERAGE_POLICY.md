# Coverage Policy

**Date:** 2026-05-30

---

## Why 100% global coverage is NOT the objective

A high global coverage percentage is easy to fake with decorative tests that call every
function without asserting anything meaningful. Such tests pass, inflate the metric, but
provide no protection against regressions.

This project targets **meaningful coverage of real behaviour** — particularly on security
and correctness-critical paths. A test that does not assert is worse than no test, because
it creates false confidence while adding maintenance cost.

**100% global coverage is not achievable or desirable** because:
- Main packages (`cmd/`) are mostly wiring code that requires live infrastructure to test.
- Adapters to external systems (Cloudflare, CrowdSec LAPI, AbuseIPDB) require mock infra
  or real credentials — both options either add fragility or can't run in CI.
- Purely compositional packages (models, types, constants) have no testable behaviour.
- Some code paths (catastrophic errors, filesystem corruption) require conditions that
  can't be reliably injected without system-level privileges.

---

## Critical paths requiring 100% coverage (or written justification if not achievable)

These paths are where bugs cause **incorrect security decisions, data loss, or
production lockouts**. They receive priority test coverage.

| Path | Package | Target | Rationale |
|---|---|---|---|
| FSM lifecycle transitions | `runtime/engine` | 100% reachable transitions | Wrong state = wrong enforcement decisions |
| Lease acquire/release/fencing | `runtime/coordination` | 100% core paths | Fencing token corruption = split-brain |
| CrowdSec decision validation | `crowdsec/validation` | 100% | Invalid ops reach cscli without validation |
| Policy engine allow/deny/escalation | `policy/engine` | 100% named rules | Wrong decision = unauthorized mutation or lock-out |
| OPA policy allow/deny/error | `policy/opa` | 100% reachable paths | Eval errors must return deny (fail-closed) |
| Anti-self-ban shield | `security/protected` | 100% | Protected IP → accidental lockout |
| Config validation fail-closed | `config` | 95%+ | Missing credentials must prevent startup |
| Circuit breaker transitions | `runtime/breaker` | 100% ✓ (already achieved) | Breaker state affects all downstream decisions |
| CrowdSec adapter idempotence | `crowdsec/adapter` | 80%+ | cscli executor handles edge cases |
| Retry/cooldown policy | `runtime/scheduler/stateful` | 80%+ | Wrong backoff = thundering herd |

---

## Minimum thresholds by package group

| Group | Packages | Target |
|---|---|---|
| Security decision core | `policy/engine`, `policy/opa`, `execution`, `crowdsec/validation` | ≥ 85% |
| Runtime safety | `runtime/engine`, `runtime/coordination`, `runtime/breaker` | ≥ 80% |
| Storage | `storage/sqlite`, `runtime/state`, `state` | ≥ 70% |
| Signal ingestion | `crowdsec/source`, `adapters/*event` | ≥ 60% |
| Configuration | `config` | ≥ 85% |
| Enforcement logic | `cidrban`, `recidive`, `openresty/state` | ≥ 75% |
| Infrastructure | `httpclient`, `logging`, `scheduler` | ≥ 65% |
| Composites/models | `*/models`, `*/types` | Exempt (no testable behaviour) |
| External API adapters | `cloudflare/transport`, `abuseipdb/transport` | Exempt (require live credentials) |
| Main entrypoints | `cmd/*` | Exempt (require live infra) |

---

## How to run the tests

```bash
# Full suite (recommended)
./scripts/test-all.sh

# Tests only (no race, fast)
go test ./...

# With race detector (mandatory before any commit to main)
go test -race ./...

# Coverage report
go test ./... -coverprofile=coverage.out -covermode=atomic
go tool cover -func=coverage.out | grep total:

# View HTML coverage (identify untested branches)
go tool cover -html=coverage.out -o coverage.html
```

---

## What constitutes a real test

**Required:**
- Every test must assert the return value, error state, or observable side effect.
- Table-driven tests must cover both happy and error paths.
- Concurrency tests must use `-race` to detect data races.
- Tests touching persistent state (files, SQLite) must use `t.TempDir()`.

**Forbidden:**
- Tests that call a function and ignore all outputs.
- Tests that only verify "no panic" without business-logic assertions.
- Tests that override production behaviour to make coverage easier.
- Removing or weakening assertions to make a test pass.

---

## Adding new code

Any new package or function on a critical path (see table above) must include
tests before the PR is merged. Test coverage for the new code must not drop
any critical-path package below its threshold.
