# Test Coverage Audit

**Date:** 2026-05-29  
**Scope:** Factual inventory only — no new tests written.  
**Method:** Package enumeration via `go list ./...` cross-referenced with `find *_test.go`.

Legend: ✓ = test file present | ✗ = no test file | ⚠ = test file present but package is a placeholder (ErrNotImplemented)

---

## CRITICAL — Packages in the live execution hot path

Bugs here cause production mutations, data loss, or silent failures.

| Package | Go files | Test files | Tested? | Notes |
|---|---|---|---|---|
| `internal/cloudflare/mutate` | 3 | 1 | ✓ | IP rule mutations (create/delete). Test covers mutator registration. **No integration/negative-path tests.** |
| `internal/cloudflare/transport` | 1 | 0 | ✗ | HTTP transport to CF API. Zero tests. Wraps real API calls. |
| `internal/cloudflare/client` | 1 | 0 | ✗ | CF client constructor. |
| `internal/cloudflare` (root) | 3 | 2 | ✓ | WAF event listing, top-level client. Partial coverage. |
| `internal/cloudflare/discovery` | 1 | 0 | ✗ | Discovers CF IP access rules. Zero tests. |
| `internal/cloudflare/normalize` | 2 | 0 | ✗ | Normalizes CF API responses. Zero tests. |
| `internal/execution` | 6 | 4 | ✓ | GovernedExecutor, fencing, security guard, validators. Well tested. |
| `internal/orchestrator/pipeline` | 13 | 2 | ✓ | 13-stage pipeline. **Only admission and orchestrator top-level tested.** 11 stages untested. |
| `internal/reconciliation` | 2 | 1 | ✓ | Generic planner — tested. |
| `internal/rollback/executor` | 1 | 1 | ✓ | Rollback execution — tested. |
| `internal/rollback/planner` | 1 | 0 | ✗ | Rollback planning — zero tests. |
| `internal/rollback/validator` | 1 | 0 | ✗ | Rollback validation — zero tests. |
| `internal/storage/sqlite` | 13 | 8 | ✓ | Strongest coverage area. Events, leases, ownership, outbox, dedup, rollback checkpoint — all tested. |
| `internal/services/reporting` | 13 | 7 | ✓ | AbuseIPDB reporting pipeline. Chaos, dedup, evidence, policy, telemetry tested. |
| `internal/runtime/recovery` | 4 | 2 | ✓ | Recovery engine and manager tested. |
| `internal/runtime/scheduler/stateful` | 4 | 1 | ✓ | Only scheduler logic tested; budget, pool, queue untested. |
| `internal/runtime/scheduler/budget` | 1 | 0 | ✗ | Rate budget manager — zero tests. |
| `internal/runtime/scheduler/pool` | 1 | 0 | ✗ | Worker pool — zero tests. |
| `internal/runtime/scheduler/queue` | 1 | 0 | ✗ | Work queue — zero tests. |

---

## HIGH — Core safety, reliability, and data integrity

Bugs here degrade reliability silently or corrupt state over time.

| Package | Go files | Test files | Tested? | Notes |
|---|---|---|---|---|
| `internal/runtime/drift` | 4 | 0 | ✗ | Drift detection engine — **zero tests.** Critical for convergence guarantees. |
| `internal/runtime/drift/memory` | 2 | 0 | ✗ | Drift memory store — zero tests. |
| `internal/runtime/engine` | 1 | 0 | ✗ | State machine — zero tests. Core lifecycle component. |
| `internal/runtime/breaker` | 1 | 1 | ✓ | Circuit breaker — tested. |
| `internal/runtime/checkpoint` | 1 | 1 | ✓ | Checkpoint manager — tested. |
| `internal/runtime/coordination` | 2 | 1 | ✓ | Lease management — tested. |
| `internal/runtime/lock` | 1 | 1 | ✓ | File lock — tested. |
| `internal/runtime/ownership` | 4 | 2 | ✓ | Lineage and resolver — tested. |
| `internal/runtime/reducer` | 1 | 1 | ✓ | Event reducer — tested. |
| `internal/runtime/events` | 4 | 1 | ✓ | Event bus — tested. |
| `internal/runtime/replay/consistency` | 1 | 1 | ✓ | Replay consistency verifier — tested. |
| `internal/runtime/status` | 2 | 1 | ✓ | Status collector — tested. |
| `internal/runtime/state` | 1 | 1 | ✓ | State store — tested (previously excluded from repo). |
| `internal/state` | 2 | 1 | ✓ | JSON state store — tested (previously excluded from repo). |
| `internal/policy/engine` | 1 | 1 | ✓ | Policy evaluation — tested. |
| `internal/policy/opa` | 2 | 0 | ✗ | OPA engine and bundle loader — zero tests. |
| `internal/policy/admission` | 1 | 0 | ✗ | Admission controller — zero tests. |
| `internal/snapshot` | 2 | 1 | ✓ | Snapshot top-level — tested. |
| `internal/snapshot/builder` | 1 | 1 | ✓ | Assembler — tested. |
| `internal/snapshot/builder/multi` | 1 | 2 | ✓ | Multi-zone assembler — tested. |
| `internal/crowdsec/translator` | 1 | 1 | ✓ | Decision translator — tested. |
| `internal/crowdsec` (client root) | 2 | 0 | ⚠ | All methods return `ErrNotImplemented`. Untestable until implemented. |
| `internal/crowdsec/adapter` | 3 | 0 | ✗ | CSCLIExecutor — zero tests. Runs `cscli` shell commands. |
| `internal/crowdsec/validation` | 1 | 0 | ✗ | Batch validation — zero tests. |

---

## MEDIUM — Supporting infrastructure

| Package | Go files | Test files | Tested? | Notes |
|---|---|---|---|---|
| `internal/adapters/cloudflareevent` | 2 | 2 | ✓ | WAF replay adapter — tested. |
| `internal/adapters/crowdsecevent` | 3 | 3 | ✓ | CrowdSec event adapter — tested. |
| `internal/adapters/openrestyevent` | 3 | 3 | ✓ | OpenResty event adapter — tested. |
| `internal/adapters/abuseipdb` | 1 | 1 | ✓ | AbuseIPDB pre-ban checker — tested. |
| `internal/adapters/lua` | 1 | 1 | ✓ | Lua adapter — tested. |
| `internal/adapters/openresty` | 1 | 1 | ✓ | OpenResty adapter — tested. |
| `internal/abuseipdb` | 3 | 1 | ✓ | Top-level client — tested. |
| `internal/abuseipdb/executor` | 1 | 0 | ✗ | Real executor sending HTTP reports — zero tests. |
| `internal/abuseipdb/transport` | 1 | 0 | ✗ | HTTP transport — zero tests. |
| `internal/config` | 2 | 1 | ✓ | Config loading — tested. |
| `internal/httpclient` | 3 | 1 | ✓ | Backoff HTTP client — tested. |
| `internal/logging` | 2 | 1 | ✓ | Structured logger — tested. |
| `internal/betterstack` | 3 | 1 | ✓ | BetterStack client — tested. |
| `internal/compat/python36` | 4 | 1 | ✓ | Python 3.6 compat layer — tested. |
| `internal/runtime/convergence` | 1 | 0 | ✗ | Convergence validator — zero tests. |
| `internal/runtime/oscillation` | 1 | 0 | ✗ | Oscillation detector — zero tests. |
| `internal/runtime/ha` | 1 | 0 | ✗ | HA manager — zero tests. |
| `internal/runtime/ha/backends/file` | 1 | 0 | ✗ | File backend for HA — zero tests. |
| `internal/runtime/governor` | 2 | 0 | ✗ | Rate governor — zero tests. |
| `internal/runtime/invariants` | 1 | 0 | ✗ | Invariant engine — zero tests. |
| `internal/runtime/cooldown` | 1 | 0 | ✗ | Cooldown manager — zero tests. |
| `internal/telemetry/sinks` | 3 | 2 | ✓ | Prometheus + BetterStack sinks — tested. |
| `internal/observability/metrics` | 1 | 1 | ✓ | Metrics — tested. |
| `internal/services/reporting/replay` | 1 | 1 | ✓ | Replay verifier — tested. |
| `internal/storage/fs` | 1 | 0 | ✗ | FS runtime storage — zero tests. |
| `internal/storage/manager` | 1 | 0 | ✗ | Migration manager — zero tests. |
| `internal/scheduler` | 2 | 1 | ✓ | Interval runner — tested. |

---

## LOW — Models, helpers, doc packages

| Package | Go files | Test files | Tested? |
|---|---|---|---|
| `internal/security/abuseformat` | 1 | 1 | ✓ |
| `internal/security/baseline` | 1 | 1 | ✓ |
| `internal/security/blastradius` | 1 | 1 | ✓ |
| `internal/security/classifier` | 1 | 1 | ✓ |
| `internal/security/confidence` | 1 | 1 | ✓ |
| `internal/security/fp_memory` | 1 | 1 | ✓ |
| `internal/security/risk` | 1 | 1 | ✓ |
| `internal/security/trust` | 1 | 1 | ✓ |
| `internal/security/postmortem` | 0 | 1 | ✓ |
| `internal/security/safety` | 0 | 1 | ✓ |
| `internal/security/reportdedup` | 1 | 0 | ✗ |
| `internal/security/reputation` | 1 | 0 | ✗ |
| `internal/cloudflare/models` | 2 | 0 | ✗ |
| `internal/cloudflare/decode` | 1 | 0 | ✗ |
| `internal/cloudflare/pagination` | 1 | 0 | ✗ |
| `internal/cloudflare/resources` | 1 | 0 | ✗ |
| `internal/cloudflare/rulesets` | 1 | 0 | ✗ |
| `internal/policy/*` (models/explain/federation/intent) | multiple | 0 | ✗ |
| `internal/runtime/models` | 5 | 0 | ✗ |
| `internal/runtime/bus` | 1 | 0 | ✗ |
| `internal/runtime/journal` | 1 | 0 | ✗ |
| `internal/runtime/coalesce` | 1 | 0 | ✗ |
| `internal/runtime/simulation` | 1 | 0 | ✗ |
| `internal/runtime/quarantine` | 1 | 0 | ✗ |
| `internal/runtime/scope` | 1 | 0 | ✗ |
| `internal/runtime/timeline` | 1 | 0 | ✗ |
| `internal/runtime/limiter` | 1 | 0 | ✗ |
| `internal/runtime/diagnostics` | 1 | 0 | ✗ |
| `internal/runtime/replay` | 1 | 0 | ✗ |
| `internal/runtime/wiring` | 1 | 0 | ✗ |
| `internal/testing/chaos` | 3 | 0 | ✗ |
| `internal/fixtures` | 7 | 1 | ✓ |
| `internal/utils` | 2 | 0 | ✗ |

---

## Summary

| Criticality | Packages | With tests | Coverage ratio |
|---|---|---|---|
| CRITICAL | 19 | 11 | 58% |
| HIGH | 22 | 15 | 68% |
| MEDIUM | 27 | 15 | 56% |
| LOW | ~32 | 10 | ~31% |
| **Total** | **~100** | **~51** | **~51%** |

---

## Priority Gaps

### Must address before any live traffic (CRITICAL, untested)

1. `internal/cloudflare/transport` — every CF mutation goes through here
2. `internal/cloudflare/discovery` — discovery stage of every pipeline run
3. `internal/cloudflare/normalize` — normalize stage output feeds the planner
4. `internal/orchestrator/pipeline` stages: normalization, planning, execution, rollback — only 2/13 stages tested
5. `internal/crowdsec/adapter` (CSCLIExecutor) — runs `cscli` shell commands, no test coverage
6. `internal/rollback/planner` and `/validator` — rollback logic untested

### Must address before reducing Python as safety net (HIGH, untested)

7. `internal/runtime/drift` — convergence guarantee relies on untested drift engine
8. `internal/runtime/engine` — state machine is zero-tested
9. `internal/policy/opa` — OPA admission engine untested
10. `internal/policy/admission` — admission controller untested
