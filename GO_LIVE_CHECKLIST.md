# Go-Live Checklist

Mandatory gate before transferring **any** production authority from Python to Go.
Each item needs concrete, reproducible evidence (a command that passes / a test
that exercises the path). An item with no backing test is a **NO-GO** contributor.

Status legend: ✅ done · ⚠️ partial · ❌ blocking · n/a.

## A. Build & static checks
- [x] `go build ./...` — ✅ (2026-05-29)
- [x] `go vet ./...` — ✅
- [x] `gofmt -l .` clean — ✅
- [x] `go test ./...` 0 failures — ✅ (but 92/148 pkgs have no tests)
- [x] `go test -race ./...` clean — ✅ (bounded by coverage)

## B. Repository hygiene
- [x] Git initialised, private remote `security-automation-go`
- [x] CI runs build/vet/gofmt/test/race on push & PR
- [x] LICENSE, SECURITY.md, CONTRIBUTING.md, CODEOWNERS, .gitignore present
- [x] No secrets committed (`*.env.example` only, empty values)
- [x] README reflects real state (not Phase-0 scaffolding)

## C. Correctness of external-effect boundaries (BLOCKING)
- [ ] ❌ `internal/cloudflare/transport` has tests (POST/DELETE/GraphQL, retries, errors)
- [ ] ❌ `internal/crowdsec/adapter` (cscli) has tests (arg building, parsing, failures)
- [ ] ⚠️ `internal/cloudflare/mutate` coverage beyond 1 test file (complex mutators, list-item, ListID extraction TODO resolved)
- [ ] ❌ Rollback `planner.go:82` "PREVIOUS state" TODO resolved + tested

## D. Runtime safety validations (BLOCKING — named requirements)
- [ ] ❌ **Replay validation** — deterministic replay equivalence test exercising `internal/runtime/replay` (consistency pkg tested; replay pkg has 0 tests)
- [x]/⚠️ **Recovery validation** — `internal/runtime/recovery` has tests; confirm checkpoint-aware recovery end-to-end
- [ ] ❌ **Rollback validation** — governed rollback restores prior state on a live drill
- [ ] ❌ **Lost-lease validation** — `internal/runtime/ha` lease loss → fencing rejection (0 tests today)
- [ ] ❌ **Strict-HA validation** — strict HA startup refuses to run without valid lease
- [ ] ❌ **Journal/invariants** — `internal/runtime/journal` & `invariants` have tests

## E. Integration validations
- [ ] ❌ **AbuseIPDB validation** — report path verified against sandbox/dry-run, dedup keys preserved
- [ ] ❌ **Cloudflare validation** — access-rule add/remove + list-item + cleanup (keep `easycron`) verified against a test zone or recorded fixtures
- [ ] ⚠️ **WAF GraphQL discovery** — `client.go:87` TODO resolved

## F. Functional parity (from TEST_GAP_REPORT §3) (BLOCKING)
- [ ] ❌ Recidivist escalation ported (or descoped with sign-off)
- [ ] ❌ `/24` auto-ban ported (or descoped with sign-off)
- [ ] ❌ ModSecurity-log-based ban ported / decision recorded vs WAF-replay
- [ ] ❌ Allowlist additive sync wired in `cf-sync` (exclusion `immuniweb`)
- [ ] ⚠️ Cleanup flow wired in `cf-sync` (delete primitives exist)
- [ ] ⚠️ State migration: SQLite vs Python JSON documented (migrate or clean-start)

## G. Operational readiness
- [ ] Prometheus metrics scraped; dashboards for mutation counts by origin
- [ ] Alerts: mutation-while-dry-run, parity divergence, lease lost, rollback executed
- [ ] Systemd units: separate names/state from Python; restart + env secrets verified
- [ ] Rollback drill executed (stop Go → start Python) within RTO < 5 min
- [ ] Legacy stub cmds (`crowdsec-sync`, `cf-allowlist-sync`, `cf-cleanup`) removed or guarded

## H. Sign-off
- [ ] Dry-run parity ≥ threshold for ≥7 days (DEPLOYMENT_PLAN Phase 1)
- [ ] GO/NO-GO decision recorded in DECISIONS.md with evidence links
- [ ] Named approver + date

---

### Current aggregate verdict (2026-05-29): **NO-GO for authority transfer.**
Sections A & B pass. Sections C–F have blocking items (untested mutation/cscli
boundaries; replay/lost-lease/strict-HA unvalidated; unported Python features).
**GO** only for: private repo + CI + **observe-only / dry-run** deployment with
Python authoritative and Go mutations disabled.
