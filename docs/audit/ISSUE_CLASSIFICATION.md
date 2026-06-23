# Issue burn-down: classification (excl. v1.7.5 milestone)

Audit covers all open issues outside the v1.7.5 milestone at the time of
this pass. Each issue's body was re-verified against current code (not
just trusted as written) before disposition.

## Fixed this pass

- **#102** — `statusLevelFromText` had no "available" branch, so "SQLite WAL
  available" fell through to `warning`. Added the branch (after the
  existing "unavailable" check, since order matters) and a regression
  test (`TestStatusLevelFromText` in `internal/ui/server_test.go`).
- **#73** — `tests/smoke/specs/04-providers.spec.ts`'s "Replace Key for
  Spamhaus" spec overwrites a real provider key with no way to recover it,
  and only required `SECURITY_AUTOMATION_SMOKE_LIVE=1` (which just means
  "reachable," often the live prod instance). Added a separate
  `SMOKE_ALLOW_MUTATIONS=1` opt-in gate, modeled on the existing
  `SMOKE_ADMIN_RESET_CONFIRM` precedent, and documented it in
  `docs/operations/RUNBOOK.md`.
- **#86** — `docs/operations/SHADOW_MODE.md` read as if the legacy Python
  daemon were still the live authority. Added a status banner noting this
  is historical/pre-cutover content, pointing to `CUTOVER.md` for the
  current authority model, without rewriting the re-runnable steps.
- **#87** — staticcheck flagged 10+ unused UI helpers (superseded
  `requireAuth`, `providerViews`, masking/value helpers, a duplicate
  `isSensitiveAuditField` wrapper, etc.) in `internal/ui/server.go`,
  `provider_admin.go`, `provider_admin_handlers.go`, `audit.go`. Removed
  all; reverified with a fresh staticcheck run plus full build/vet/test.
- **#105** — `cmd/cf-sync/runtime.go` constructed `intentComp` (policy
  compiler) and `simEng` (simulation engine) and immediately discarded
  them via `_ = `. Removed both constructions and their imports, which
  also orphaned `internal/policy/compiler` and `internal/runtime/simulation`
  (deleted below).

## Already fixed — close without further action

- **#88** — Trusted Networks/CrowdSec allowlist staleness was resolved by
  an earlier-merged PR (#118), which wired `CrowdSecStatusStore` into the
  UI. No remaining gap.

## Dead code — deleted (per standing rule: prefer deletion over keeping dead code)

Each package was independently verified to have zero external import
references (grep across the whole repo for its import path, excluding its
own directory) before deletion:

- **#106** `internal/runtime/recovery` (+ `internal/storage/snapshot`, its
  only consumer, now also dead)
- **#107** `internal/runtime/replay` (+ `internal/runtime/replay/consistency`)
- **#108** `internal/runtime/ha` (+ `internal/runtime/ha/backends/file`)
- **#109** `internal/runtime/coalesce`
- **#110** `internal/runtime/oscillation`
- **#111** `internal/runtime/scheduler/scheduler.go` only — the legacy
  root file. Note: the parent directory `internal/runtime/scheduler/`
  also contains four live subpackages (`pool`, `queue`, `budget`,
  `stateful`), actively imported by `internal/api/handlers/v2`,
  `internal/api/server`, `internal/orchestrator/pipeline`, and
  `cmd/cf-sync` — those were verified live and kept.
- **#112** `internal/policy/replay/verifier`
- **#113** `internal/services/reporting/replay`
- **#114** `internal/modsecurity`
- **#115** `internal/cloudflare/rulesets`
- **#116** `internal/storage/fs`
- **#117** `internal/compat/python36` (+ `internal/adapters/lua`,
  `internal/adapters/openresty`, whose only consumers were
  `python36`'s `lua.go`/`nginx.go`, now also dead)
- Newly orphaned by the #105 fix: `internal/policy/compiler`,
  `internal/runtime/simulation`

Validation after the full sweep: `go build ./...`, `go vet ./...`, and
`go test ./...` all pass with zero failures.

## Deferred — needs dedicated implementation (not a dead-code/delete fix)

These describe real feature gaps requiring schema/store/UI changes, not
something resolvable by deleting or one-lining a fix. Tracked as
follow-up work, not closed:

- **#83** — CF rule inventory backfill (`cf_ban_lifecycle` only tracks
  ~5 of ~131 live Cloudflare rules). Descriptive backfill proposal.
- **#84** — `/sync` reads legacy shadow JSONL instead of the scoped
  runtime.db.
- **#85** — replay/recovery/drift/deban routes are shell placeholders
  without backing data.
- **#89** — dashboard hardcodes HA/fencing as disabled (consistent with
  #108's HA subsystem being dead code — the UI gap is now arguably moot,
  but a real "no HA" UI state, rather than a hardcoded one, is still
  worth a small follow-up).
- **#103** — Cloudflare delete-cleanup failures are log-only and never
  persisted; needs a persisted failure status in `cf_ban_lifecycle` plus
  a UI render path. Confirmed accurate against current
  `internal/cloudflare/banlifecycle/cleanup/cleanup.go`.
- **#104** — Timeline drops runtime lineage and hardcodes "replay
  sequence unavailable." Needs real wiring of `tlCollector`
  (`cmd/cf-sync/runtime.go`), not deletion — this is the reason
  `tlCollector` was deliberately left in place during the #105 fix.

## Not yet examined this pass

- **#46** — pipeline health matrix observability columns. Per prior
  analysis: explicitly does not block release.
- **#67** — smoke coverage for first-run wizard / production enable
  flows. Smoke-coverage gap, not a defect.
