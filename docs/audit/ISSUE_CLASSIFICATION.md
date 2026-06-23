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
- **#84** — `/sync` read the legacy shadow-mode JSONL log
  (`internal/shadow.Store`), which the live `cmd/cf-sync` daemon never
  writes to (only `cmd/crowdsec-sync`/`cmd/cf-shadow`, in shadow mode, do).
  Rewrote `internal/ui/cfsync_page.go` to read `banlifecycle.Store`
  (runtime.db's `cf_ban_lifecycle` table) instead — the same store
  `/ban-lifecycle` and the daemon's reactive ban/cleanup path already use.
  `CFSyncView` (`internal/ui/types.go`) was rebuilt around this single
  source of truth; no dual-source logic remains. Tests:
  `internal/ui/cfsync_page_test.go` (rewritten).
- **#103** — Cloudflare delete-cleanup failures were log-only. Added
  `cleanup_attempts`, `last_cleanup_error`, `last_cleanup_attempt_at`
  columns to `cf_ban_lifecycle` (migration v21,
  `internal/storage/sqlite/db.go`), a `RecordCleanupFailure` method on
  `banlifecycle.Store` (implemented in `internal/storage/sqlite/ban_lifecycle.go`
  and `internal/cloudflare/banlifecycle/memstore`), wired
  `internal/cloudflare/banlifecycle/cleanup/cleanup.go`'s
  `deleteRuleAndFinish` to persist failures instead of only logging them
  (entry stays active so the next pass retries), and added a "retrying
  cleanup" render state to `/ban-lifecycle`
  (`internal/ui/ban_lifecycle_page.go`) showing attempt count and last
  error. Tests: `TestWorker_DeleteFailure_PersistsCleanupFailure`
  (`cleanup_test.go`), `TestBanLifecycleView_RetryingEntry_SurfacesCleanupFailure`
  (`internal/ui/ban_lifecycle_page_test.go`).
- **#104** — `/timeline` never read the runtime event journal at all,
  hardcoding `ReplaySequence: "unavailable"` for every audit-derived row.
  `tlCollector` (`internal/runtime/timeline.Collector`) was constructed in
  `cmd/cf-sync/runtime.go` and immediately discarded — real lineage data
  (sequence numbers, correlation ids from the daemon's lifecycle-transition
  event journal) existed but was unreachable from the UI. Added
  `lazyEventStore` (`cmd/cf-sync/event_store_holder.go`, same
  populated-after-startup indirection as `lazyBanLifecycleStore`), wired it
  through `ui.Options.EventStore`/`Server.eventStore`, and added a
  `runtimeEntryToTimelineEvent` projection in `internal/ui/timeline.go` that
  merges `timeline.Collector.Assemble(...)` entries into the unified
  timeline as their own `scope=runtime` rows with real `ReplaySequence`
  values (never a placeholder) — filterable via a new "Runtime Lineage"
  source option. Standalone `-mode ui` (no daemon) falls back to
  `sqlite.NewEventRepository(setupDB)`, mirroring the ban-lifecycle
  fallback. Removed the now-redundant `tlCollector` construction in
  `runtime.go` (the UI builds its own collector from the same event store).
  Tests: `TestTimelineIncludesRuntimeLineage`
  (`internal/ui/timeline_test.go`).
- **#89** — the dashboard's "HA / fencing" row hardcoded
  `Level: "disabled"` with a misleading detail ("read-only UI shell") that
  didn't reflect reality. The dedicated HA subsystem (`internal/runtime/ha`)
  was deleted as dead code in this pass (#108, zero importers), and no HA or
  fencing config flag exists anywhere in `internal/config` — so "disabled"
  wrongly implied an operator could enable it. Replaced with
  `haFencingLevel()`/`haFencingDetail()` (`internal/ui/server.go`) reporting
  `Level: "unavailable"` and a detail explaining the HA subsystem is not
  present in this build (single-instance fencing tokens/leases are internal
  scheduler plumbing, not multi-node HA failover). Test:
  `TestDashboard_HAFencingReportsRealUnavailableState`
  (`internal/ui/dashboard_helpers_test.go`).
- **#85** — `/replay`, `/recovery`, `/drift`, `/deban` were shell-only pages
  presenting elaborate future-state copy ("Checkpoints", "Convergence
  indicators", etc.) with zero backing data, and none were reachable from
  navigation (`consoleNav()` never linked them — only directly-typed URLs
  reached them). Replay's and Recovery's backing subsystems were already
  deleted as dead code in this same pass (#107, #106). Drift's engine
  (`internal/runtime/drift`) does run live in the daemon, but is never
  threaded into `ui.Options` and its memory store
  (`internal/runtime/drift/memory.Store`) has no list/summary method to
  back a real overview page without new plumbing — i.e. just as unreachable
  from the UI as the deleted subsystems today. Deban's "coming soon" copy
  was actively misleading, since a fully real per-IP deban action already
  ships at `/ban-lifecycle`. Per the issue's own recommended fix ("remove
  the route and navigation entry until the workflow is implemented") and the
  standing no-fake-state rule, removed all four routes outright: handlers
  (`handleReplayPage`/`handleDebanPage`/`handleRecoveryPage`/`handleDriftPage`),
  route registrations, view builders (`replayView`/`recoveryView`/`driftView`
  in `internal/ui/workflows.go`), and the now-unused `ComingSoonPage`/
  `ComingSoonView`. The issue also named `/trusted-networks/diff` and
  `/trusted-networks/refresh` — both reachable from the real
  `/trusted-networks` page and already self-labeled "read-only placeholder",
  but `internal/trustednetworks` has no `Diff`/`Refresh` function of any
  kind to wire to (verified by grep), so building either for real would mean
  designing a brand-new feature (fetching an external source and diffing
  against the local registry snapshot), not a wiring fix. Applied the same
  disposition for consistency: removed both routes, their handlers, the
  placeholder renderer (`trustedNetworksPlaceholderPage`), and the dead-end
  links from the `/trusted-networks` page body — the page still renders its
  real, wired registry table and the working `/trusted-networks/export`
  link. Tests: `TestRemovedShellPlaceholderRoutesAreGone`
  (`internal/ui/workflows_test.go`); updated `TestWorkflowPagesRenderReadOnlySections`,
  `TestWorkflowPagesDoNotLeakSecrets`, `TestServer_WorkflowRoutesRequireAuth`,
  `TestServer_PagesAreSelfContained`, `TestDashboard_StubPanelsAreDisabled`
  to drop the removed routes; deleted `TestServer_ReservedRoutesRequireAuth`
  and `TestWorkflowPages_StubBadgesAreDisabled` (asserted behavior of code
  that no longer exists). Removed the four dead routes from the Playwright
  smoke suite (`tests/smoke/specs/06-other-pages.spec.ts`).
- **#83** — `cf_ban_lifecycle` only tracks ~5 of ~131 live Cloudflare rules
  (rules created outside this tool, or before the lifecycle store existed,
  are invisible to the UI). The issue itself is descriptive-only and
  explicitly does not propose writing synthetic backfill rows (open policy
  questions: expiration, origin-disambiguation) — doing so would fabricate
  provenance data and create a second, conflicting source of truth for
  `cf_ban_lifecycle`, violating the no-fake-state rule. Instead added a
  read-only inventory cross-reference to `/sync`
  (`internal/ui/cfsync_page.go`): `fetchCFRuleInventory` calls the existing
  read-only `discovery.ListIPAccessRules` primitive (already used
  unauthenticated-write-free by the setup wizard's token validation,
  `setup_wizard.go:795`) to count the zone's total live rules, and reports
  live/tracked/untracked counts — no writes, no mutation, no synthetic
  entries. Cached 60s (`cfRuleInventoryCacheTTL`) to bound Cloudflare API
  call volume. The live API call is injectable via `Server.cfRuleLister`
  (same test-seam pattern as `validateCloudflare`) so tests never hit the
  real Cloudflare API. Tests: `TestFetchCFRuleInventory_*`,
  `TestCFRuleInventorySnapshot_Caches`, `TestRenderCFRuleInventory_*`
  (`internal/ui/cfsync_page_test.go`).

## Already fixed — close without further action

- **#88** — Trusted Networks/CrowdSec allowlist staleness was resolved by
  an earlier-merged PR (#118), which wired `CrowdSecStatusStore` into the
  UI. No remaining gap.
- **#67** — re-verified against current code rather than trusted as
  written. The issue's core complaint (0% test coverage on setup-wizard
  step handlers) predates this session's analysis: PR #71
  (`6f0fbb5 test(ui): cover setup wizard steps 2/8/9 and full first-run
  journey`) already added `TestSetupWizard_FullFirstRunJourney_SkipOptionalSteps`,
  `TestSetupWizard_Step2PersistsBindAddress`, and
  `TestSetupWizard_Step9RequiresExplicitOptIn` — these assert persisted
  state (`store.settings["ui_addr"]`, `mutations_enabled`, `dry_run`), not
  just HTTP status codes, which is exactly what the issue asked for.
  `go tool cover -func` confirms every step handler the issue names by
  name (`handleSetupStep2`/`4`/`5`/`6`/`8`/`9` and their Post variants) is
  now in the 56.8%-100% coverage range, up from the issue's claimed 0%.
  The remaining 0%-coverage functions (`validateCFToken`,
  `validateAbuseIPDB`, `ValidateAbuseIPDB`, `validateBetterStack`) are
  exercised indirectly via the existing injectable test-seam fields
  (`s.validateCloudflare`, etc.) rather than called directly — consistent
  with this codebase's established pattern, not a gap.
  The issue also asked for a Playwright-level full-journey smoke test;
  confirmed via grep that none exists (`tests/smoke/specs/*.ts` has zero
  `setup/step` references). Did not add one: the existing smoke suite
  (`tests/smoke/helpers/session.ts`) assumes an already-provisioned,
  already-logged-in instance reached via password login — the first-run
  wizard by definition only appears on a fresh, unprovisioned instance, so
  a real browser-level test would need its own fresh-state harness
  (separate state dir, separate server bootstrap, no login helper reuse),
  which is new test infrastructure, not a wiring fix, and the Go-level
  tests already exercise the real HTTP handlers end-to-end (cookies, CSRF,
  redirects, persisted state) with equivalent rigor. No remaining gap that
  justifies new infrastructure under the standing no-new-architecture rule.

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

## Deferred to v1.7.5

- **#46** — pipeline health matrix observability columns (Fetched,
  Duplicates, Last successful run, Last error, Last report timestamp).
  Re-verified: the issue is labeled `enhancement`, not a defect, and its
  own body states "Priority: Post-1.6.0 roadmap — Post-3 item. Do not
  block release on this." Wiring real per-source data for every named
  column is a multi-source plumbing change (each column needs its own
  source-of-truth field threaded through to the pipeline health view),
  not a small fix-in-place — exactly the kind of work the issue itself
  says should wait. Deferred to v1.7.5 with no partial/speculative wiring
  added now, consistent with the standing no-fake-state and
  no-speculative-future-wiring rules.
