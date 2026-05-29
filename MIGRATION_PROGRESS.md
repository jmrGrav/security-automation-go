# MIGRATION_PROGRESS

## 2026-05-29T15:20:00+02:00

### Completed

- Added optional lease-bound mode for AbuseIPDB outbox worker without changing retry semantics:
  - new `OutboxLeaseGuard` boundary
  - `ProcessOnce` checks lease guard before processing each outbox item
  - guard refusal emits telemetry/evidence and prevents upstream call
- Closed ownership claim persistence/high-risk drift gap:
  - runtime ownership resolver now supports persistent claim authority via `ClaimStore`
  - `Resolve` now reads from store when configured
  - `Claim` persists first to store, then updates memory cache
  - `ListClaims` now favors persistent store snapshots
  - cf-sync wiring now sets ownership claim store to SQLite repository
- Added tests:
  - ownership claim store survives resolver restart and remains authoritative
  - in-memory drift cannot bypass persistent ownership authority
  - outbox lease guard refusal prevents upstream report call

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-29T14:10:00+02:00

### Completed

- Hardened fencing propagation semantics in production wiring:
  - added strict fencing mode in `LeaseStoreFencingValidator` (`RequireFencing(true)`)
  - enabled strict fencing in `cmd/cf-sync` for:
    - governed Cloudflare mutation execution
    - rollback execution
- Added regression coverage for stale leadership races:
  - governed executor rejects missing fencing metadata when strict fencing is enabled
  - governed executor stops remaining operations when active lease/fencing changes mid-batch
  - rollback executor stops remaining compensation operations on stale fencing mid-batch and persists failed checkpoint progress

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-29T13:05:00+02:00

### Completed

- Implemented durable rollback checkpoint persistence and resume:
  - new SQLite table `rollback_checkpoints` (migration v14)
  - new `RollbackCheckpointStore` in `internal/storage/sqlite/rollback_checkpoint.go`
  - rollback executor checkpoint wiring (`SetCheckpointStore`) in cf-sync runtime composition
  - checkpoint writes at rollback start, per-op progress, failure, and completion
  - checkpoint reload/resume by `batch_id`, with completed-batch short-circuit
- Added tests:
  - rollback executor resume from persisted progress after failure
  - completed checkpoint no-op protection
  - SQLite rollback checkpoint store save/load/update behavior

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-29T10:55:00+02:00

### Completed

- Added cursor-based forensic pagination for ownership lineage API without changing current list payload semantics.
- Added corresponding cursor support in ownership CLI list/search mode.
- Added SQLite cursor query path for ownership lineage (`ListLineageCursor`) with deterministic descending ordering.
- Added tests:
  - SQL cursor pagination correctness for ownership lineage
  - API cursor header emission
  - multi-scope/restart ownership divergence determinism remains stable

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-29T10:25:00+02:00

### Completed

- Added forensic ownership lineage query surfaces:
  - CLI ownership mode with list/show/explain commands
  - API v3 ownership lineage list/get/explain endpoints
- Added direct lineage get-by-id in SQLite ownership repository (`GetLineage`).
- Added ownership divergence replay/restart tests:
  - scope-aware divergence isolation
  - deterministic repeated divergence detection after restart

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-29T09:40:00+02:00

### Completed

- PR1 completed: durable ownership lineage
  - added `ownership_lineage` append-only table (SQLite migration v13)
  - added lineage append/list APIs in SQLite ownership repository
  - connected `runtime/ownership.Resolver` to durable lineage recording in `cmd/cf-sync`
- PR2 completed: ownership restore/replay tests
  - added ownership lineage replay helper and tests in `internal/runtime/ownership`
  - added SQLite test proving lineage replay reconstructs latest effective claim
- PR3 completed: recovery invariant checks for ownership
  - recovery now validates ownership claim/lineage coherence
  - recovery fails closed if ownership invariants are violated
  - recovery report now includes ownership invariant fields

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-28T20:25:00+02:00

### Completed

- Documented the final hardening state and remaining roadmap in `docs/hardening/final-status-and-roadmap.md`.
- Completed a post-review safe auto-fix for AbuseIPDB outbox reservation lifecycle:
  - same idempotency key is treated as idempotent
  - active pending same-IP reservation blocks duplicate upstream calls
  - expired pending reservations are failed before accepting a new one
  - `MarkStatus` now reports missing outbox rows instead of silently succeeding
- Revalidated the repository after the auto-fix.

### Still desirable, but not auto-applied

- Per-mutation fencing token enforcement.
- Async AbuseIPDB outbox retry worker.
- Forward execution lease-bound context for any future live provider write path.
- Further decomposition of `internal/services/reporting`.

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-28T18:10:00+02:00

### Completed

- Added typed commit ambiguity handling for runtime event append:
  - `sqlite.ErrCommitAmbiguous`
  - post-commit lookup by `(scope_id, event_uid)`
  - no blind retry when durable commit state cannot be proven
- Connected lost-lease cancellation to execution:
  - context-aware Cloudflare mutators
  - rollback heartbeat cancellation through `context.WithCancelCause`
  - `lost_lease_mutation_aborted` audit/telemetry events
- Added strict AbuseIPDB reservation/outbox semantics:
  - durable pending reservation before upstream report
  - `report_pending`, success and failed evidence lineage
  - same-IP pending reservation serialization
  - no upstream call when reservation or pending evidence persistence fails
- Optimized forensic evidence search:
  - projected `decision` and `abuse_type`
  - SQL-backed decision/source/IP/reason/date filters
  - stable `timestamp DESC, evidence_id DESC` pagination

### Remaining

- The strict AbuseIPDB outbox is still synchronous; a future worker can retry pending/failed rows, but this tranche intentionally avoids a larger async dispatcher.
- Forward non-rollback execution paths should use the same lease-bound context once live mutation execution expands beyond rollback/governed executor entrypoints.

### Validation snapshot

- Targeted tests for sqlite/reporting/execution/orchestrator are green before full repository validation.

## 2026-05-28T06:13:30+02:00

### Completed

- Added durable runtime event idempotency:
  - `event_uid` on runtime events
  - scoped SQLite uniqueness on `(scope_id, event_uid)`
  - duplicate append resolution to the existing event id/sequence
  - no naive full append retry after ambiguous commit failure
- Unified live lease authority with the recovery-visible scoped SQLite lease store when configured:
  - `LeaseManager.WithLeaseStore`
  - persistent acquire/release/renew
  - `cmd/cf-sync` wiring to `sqlite.NewLeaseRepository`
- Added context-bound HA lease heartbeat support:
  - periodic persisted `Renew`
  - clean stop on context cancel
  - bounded failure threshold
  - lost-lease signal for safe-stop wiring
- Tightened approval evidence lineage:
  - removed duplicate op-level blocked transition evidence
  - kept separate `approval_required` and `awaiting_approval` events
- Persisted minimal evidence for malformed Cloudflare WAF events observed through telemetry
- Fixed app-level WAF reporting runtime SQLite lifetime so configured dedup/evidence stores remain usable

### In progress

- The remaining high-value hardening is strict durable reporting semantics: decide whether production should require evidence and 24h dedup marking before any AbuseIPDB upstream report leaves the process.

### Next milestones

1. Add strict report mode or a transactional outbox for AbuseIPDB reports
2. Connect lost-lease heartbeat signals to mutation cancellation in longer-running execution paths
3. Project reporting evidence `decision` into SQLite columns for stable indexed forensic search

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded

## 2026-05-28T00:05:00+02:00

### Completed

- Removed the remaining legacy lease fallback risk:
  - SQLite lease repository now normalizes `scope_id=''` rows to the active scoped runtime DB on access
  - reads/writes/releases are strict on `scope_id` after normalization
- Added explicit persisted lease renewal semantics:
  - `LeaseStore.RenewLease`
  - SQLite-backed `RenewLease`
- Hardened Cloudflare WAF cursor lifecycle:
  - overlap query window
  - high-watermark-driven cursor progression
  - no cursor advance on processing failure
  - no cursor advance on cursor-save failure
  - safe fallback on corrupted cursor load
- Added poller tests for restart/overlap safety and save/load failure handling
- Tightened local live WAF runtime wiring so CrowdSec/OpenResty keep stable processor instances over the same shared reporting service
- Added approval-workflow primitives to governed execution:
  - batch/operation approval flags
  - approval identity/status/expiry fields
  - `awaiting_approval` operation state
  - execution refusal for approval-required work until approved
- Added tests for:
  - lease renewal
  - approval-required execution blocking

### In progress

- The runtime/recovery/storage slice is now materially harder to challenge on lease scope, replay, cursor restart, and approval-foundation grounds; the next work can move back to deeper chaos/replay and broader operational proof

### Next milestones

1. Add broader restart chaos around delayed Cloudflare events and overlapping replay windows across multiple poll iterations
2. Thread approval evidence/lineage into persisted forensic records if approval-gated mutations become active in runtime policy
3. Extend chaos harness coverage for stale fencing, orphan leases, and replay interruption once those scenarios are prioritized again

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-27T18:05:00+02:00

### Completed

- Added a shared runtime reducer under `internal/runtime/reducer` and wired both:
  - live runtime lifecycle transitions
  - replay/recovery event application
- Fixed live vs replay lease semantics:
  - terminal transitions now clear both reconcile and rollback leases
  - rollback transitions now populate `ActiveRollbackLease`
  - replay no longer reconstructs leases differently from the live state machine
- Made lease persistence scope-aware:
  - `LeaseStore` interface now requires `scope_id`
  - SQLite `leases` gained `scope_id`
  - recovery orphan-lease detection is now scoped
- Replaced `MAX(sequence)+1` event allocation with atomic per-scope `event_sequences`
- Added bounded busy retry plus single-writer SQLite pooling to keep concurrent append valid under load
- Expanded checkpoint checksum validation to cover canonical full checkpoint content:
  - `name`
  - `scope_id`
  - `sequence`
  - `event_id`
  - `state`
  - `metadata`
  - `schema_version`
  - canonical `created_at`
- Added tests for:
  - live transition == replay reduction
  - rollback lease semantics
  - scoped lease isolation
  - scoped recovery orphan-lease checks
  - concurrent same-scope and multi-scope append
  - full checkpoint tamper detection

### In progress

- Brooks runtime/recovery/storage invariants are now corrected; the next meaningful work can return to higher-level forensic/runtime hardening instead of basic state-consistency repair

### Next milestones

1. Extend runtime recovery tests further if more event types begin mutating `RuntimeState`
2. Consider adding explicit renewal semantics to the scoped lease store if HA coordination starts persisting lease heartbeats there
3. Resume broader replay/recovery/chaos work now that live/replay and scoped lease invariants are defensible again

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-27T17:03:00+02:00

### Completed

- Exposed reporting evidence over API v3:
  - `GET /api/v3/security/evidence`
  - `GET /api/v3/security/evidence/{evidence_id}`
  - `GET /api/v3/security/evidence/{evidence_id}/explain`
- Reused the same reporting evidence model and explanation rendering as the CLI path so query/explain semantics stay aligned
- Extended the reporting replay verifier with version-drift detection against stored:
  - classifier version
  - formatter version
  - reporting policy version
- Added live-pipeline chaos-style coverage for mixed Cloudflare WAF batches containing malformed and valid events together

### In progress

- Evidence query/explain is now available from both CLI and HTTP API; the next value step would be broader replay/chaos depth rather than another access path

### Next milestones

1. Add deeper replay mismatch coverage when classifier/formatter/policy semantics evolve materially
2. Add more targeted live chaos around cursor overlap/restart behavior if that proves operationally relevant
3. Resume broader forensic/runtime recovery work once reporting evidence access and replay integrity are stable enough

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w internal/api/handlers/v3 internal/api/server internal/services/reporting internal/adapters/cloudflareevent cmd/cf-sync` succeeded
- `GOTOOLCHAIN=local go test ./internal/api/... ./internal/services/reporting/... ./internal/adapters/cloudflareevent ./cmd/cf-sync` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-27T16:48:00+02:00

### Completed

- Added forensic evidence query/explain support through `cmd/cf-sync -mode evidence`:
  - `list`
  - `search`
  - `show`
  - `explain`
- Enriched persisted AbuseIPDB reporting evidence with:
  - `decision`
  - `uri_list`
  - `categories`
  - `idempotency_key`
  - `dedup_key`
  - `last_reported_at`
  - `next_allowed_at`
  - `input_hash`
  - `decision_hash`
  - `normalized_event`
- Extended `internal/storage/sqlite/reporting_evidence.go` with:
  - point lookup by `evidence_id`
  - filtered search by source/IP/decision/reason/date
  - pagination through `limit` and `offset`
- Added a deterministic replay verifier in:
  - `internal/services/reporting/replay`
  - verifies canonical comment, decision, and stored hashes
  - reports `missing_context`, `mismatch_comment`, `mismatch_decision`, and `mismatch_hash`
- Added targeted chaos-style coverage around the live reporting pipeline:
  - evidence store write failure stays fail-open for the decision path
  - duplicate same IP across sources within 24h still emits only one upstream report

### In progress

- Evidence query/explain is available from the CLI, but not yet exposed through HTTP API endpoints

### Next milestones

1. Expose the same reporting evidence query/explain capability through API if still useful operationally
2. Deepen replay verification once more decision-policy versions or source-specific normalizers need drift detection
3. Add more live-pipeline chaos around cursor overlap/restart and malformed mixed-source batches when operational value justifies it

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w internal/services/reporting internal/storage/sqlite cmd/cf-sync` succeeded
- `GOTOOLCHAIN=local go test ./internal/services/reporting/... ./internal/storage/sqlite ./cmd/cf-sync` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-27T16:31:00+02:00

### Completed

- Continued the preventive refactor without changing behavior
- Added explicit orchestrator leaf stages for:
  - normalization
  - execution
  - telemetry
- `DryRun` now calls a dedicated normalization stage before planning and a telemetry stage through completion handling
- `Rollback` now calls a dedicated execution stage instead of executing rollback inline
- Added daemon/runtime helpers in `cmd/cf-sync/daemon_runtime.go` for:
  - API/auth/metrics server startup
  - daemon shutdown context wiring
  - Cloudflare WAF replay poller startup
- Reduced `cmd/cf-sync/main.go` further by moving daemon bootstrap concerns out of the main file

### In progress

- `internal/orchestrator/pipeline` is now much thinner, but the central file still coordinates the stage chain and can be reduced further over time

### Next milestones

1. Continue thinning the central orchestrator entrypoints once there is a clear structural win, not just file churn
2. Keep reducing top-level runtime wiring in `cmd/cf-sync/main.go` and `internal/app/app.go`
3. Resume evidence query/explain, replay verifier, and targeted chaos once the orchestration/composition surfaces are stable enough

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w internal/orchestrator/pipeline cmd/cf-sync` succeeded
- `GOTOOLCHAIN=local go test ./internal/orchestrator/pipeline ./cmd/cf-sync` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-27T16:18:00+02:00

### Completed

- Continued the preventive refactor without changing behavior
- Added an explicit orchestrator reporting stage in:
  - `internal/orchestrator/pipeline/stage_reporting.go`
  - `DryRun` now calls a dedicated reporting step for AbuseIPDB-side translation/reporting orchestration
- Added a small local WAF reporting runtime helper in:
  - `internal/app/reporting_runtime.go`
  - `CrowdSecSyncApp.Run` no longer wires reporting service, live sources, and per-source loops inline
- Added small `cmd/cf-sync` runtime wiring helpers in:
  - `cmd/cf-sync/runtime_wiring.go`
  - security telemetry sink construction
  - propagation guard configuration
  - Cloudflare WAF replay service construction

### In progress

- `internal/orchestrator/pipeline` is still being thinned incrementally; normalization, execution, and telemetry are not yet fully extracted as explicit stages

### Next milestones

1. Continue orchestrator decomposition with explicit normalization, execution, and telemetry stages
2. Keep shrinking `cmd/cf-sync/main.go` and `internal/app/app.go` through slice-specific builders/helpers instead of inline wiring
3. Resume evidence query/explain, replay verifier, and targeted chaos once the orchestration surface is thinner

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w internal/orchestrator/pipeline internal/app cmd/cf-sync` succeeded
- `GOTOOLCHAIN=local go test ./internal/orchestrator/pipeline ./internal/app ./cmd/cf-sync` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-27T16:02:00+02:00

### Completed

- Continued the preventive refactor without changing behavior
- Added `internal/storage/sqlite/reporting_runtime.go`:
  - small `ReportingStores` facade for the reporting/security slice
  - groups SQLite-backed dedup, evidence, and cursor stores
  - reduces composition-root wiring in `internal/app` and `cmd/cf-sync`
- Rewired `internal/app/app.go` and `cmd/cf-sync/main.go` to use the new reporting/security store facade instead of constructing those stores piecemeal
- Continued orchestrator decomposition with explicit:
  - validation stage
  - completion stage
- Kept the refactor behavioral surface stable while shrinking the inline `DryRun` flow further

### In progress

- `internal/orchestrator/pipeline` is thinner, but normalization/reporting/execution/telemetry are still not fully extracted into explicit stages

### Next milestones

1. Continue orchestrator decomposition with explicit normalization, reporting, execution, and telemetry stages
2. Consider adding a clearer SQLite facade for other growing slices beyond reporting/security if complexity keeps concentrating there
3. Resume forensic query/explain, replay verification, and targeted chaos only after the current structural cleanup is complete

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w internal/orchestrator/pipeline internal/storage/sqlite internal/app cmd/cf-sync` succeeded
- `GOTOOLCHAIN=local go test ./internal/orchestrator/pipeline ./internal/storage/sqlite ./internal/app ./cmd/cf-sync` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-27T07:21:12+02:00

### Completed

- Added durable 24-hour per-IP AbuseIPDB report deduplication:
  - `internal/security/reportdedup`
  - SQLite-backed persistence in `internal/storage/sqlite/report_dedup.go`
  - transactional mark-after-success behavior only
  - injectable clock and configurable fail-closed store error handling
- Added durable runtime cursor persistence in `internal/storage/sqlite/cursor_store.go`
- Wired the shared reporting service to enforce the new per-IP 24h AbuseIPDB rule across all WAF sources
- Added live CrowdSec ingestion through:
  - real `decisions.log` parsing
  - safe nginx URI correlation
  - `internal/adapters/crowdsecevent/live.go`
- Added live OpenResty ingestion through:
  - real Lua JSONL handoff file parsing
  - `internal/adapters/openrestyevent/live.go`
- Wired `internal/app/app.go` so live CrowdSec/OpenResty detections now enter the same shared reporting service as Cloudflare replay
- Persisted the Cloudflare WAF poller `since` cursor durably in `cmd/cf-sync`
- Began thinning `internal/orchestrator/pipeline` with explicit:
  - discovery stage
  - snapshot stage
  - planning stage
- Fixed a real race in `internal/telemetry/sinks.RecorderSink` found by `go test -race`
- Added replayable append-only evidence persistence for AbuseIPDB report/suppress decisions:
  - `internal/services/reporting/evidence.go`
  - SQLite-backed `internal/storage/sqlite/reporting_evidence.go`
  - telemetry now carries evidence IDs for both reported and suppressed decisions when persisted
- Strengthened live-source coverage with safer malformed/sparse-input tests for:
  - CrowdSec decisions.log ingestion
  - OpenResty Lua JSONL ingestion
  - Cloudflare WAF sparse GraphQL events
- Continued orchestrator decomposition with explicit:
  - admission stage
  - translation stage
  - AbuseIPDB translation stage
- Performed a preventive refactor of `internal/services/reporting`:
  - extracted policy helpers
  - extracted dedup gate logic
  - extracted evidence recorder logic
  - extracted telemetry publisher logic
- Split the oversized reporting test suite into smaller thematic files

### In progress

- The shared WAF reporting pipeline is now real for Cloudflare replay plus live CrowdSec/OpenResty inputs, but replayable evidence persistence for successful/suppressed AbuseIPDB decisions is still partial.

### Next milestones

1. Add direct query/forensic retrieval paths for persisted reporting evidence
2. Continue orchestrator decomposition with explicit normalization, reporting, execution, and telemetry stages
3. Harden Cloudflare WAF cursor crash/restart semantics further if needed
4. Add broader chaos/replay coverage around the live-source + evidence pipeline

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-27T15:05:00+02:00

### Completed

- Added `internal/services/reporting` as the unified outer-layer WAF reporting pipeline
- Routed Cloudflare replay events through:
  - normalization
  - pure classifier
  - canonical AbuseIPDB formatter
  - report/suppress decision logic
  - telemetry emission
- Added explicit local-event entry services for:
  - `internal/adapters/crowdsecevent`
  - `internal/adapters/openrestyevent`
- Implemented a real Better Stack HTTP sink behind `internal/telemetry/sinks`
- Added sink/reporting tests for:
  - exact canonical cross-source comments
  - benign telemetry-only events
  - duplicate-report suppression
  - telemetry fail-open behavior
  - Better Stack payload stability and timeout handling
  - Prometheus sink emission
- Fixed outer-layer suppression metrics to key off explicit suppression reasons instead of the propagation flag alone

### In progress

- The shared reporting pipeline is now real for Cloudflare replay and structurally available for CrowdSec/OpenResty, but the live local detection sources are not yet wired into it end-to-end.

### Next milestones

1. Wire live CrowdSec/OpenResty detections into `internal/services/reporting`
2. Persist the Cloudflare WAF replay cursor durably
3. Continue thinning `internal/orchestrator/pipeline` with explicit stages
4. Add richer Better Stack delivery policy only if operationally needed

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-27T14:05:00+02:00

### Completed

- Implemented Cloudflare GraphQL WAF event discovery through `firewallEventsAdaptive`
- Added typed WAF event fetch support to `internal/cloudflare`
- Added `internal/adapters/cloudflareevent.Service` to:
  - normalize fetched Cloudflare events
  - classify them through the shared local classifier
  - generate canonical AbuseIPDB comments
  - map category labels to AbuseIPDB numeric category IDs
  - emit telemetry for both suppressed and reported outcomes
  - deduplicate replay reports within a TTL window
- Wired Cloudflare WAF replay/reporting into `cmd/cf-sync` daemon mode
- Added tests for:
  - GraphQL WAF event replay fetch
  - benign/bootstrap suppression
  - high-confidence report emission
- Tightened `internal/abuseipdb/executor` so report failures are surfaced to callers

### In progress

- The Cloudflare WAF replay chain is now real, but Better Stack still uses only the generic sink boundary and does not yet have a concrete HTTP implementation or config.

### Next milestones

1. Route local CrowdSec/OpenResty detections through the same classifier + canonical formatter + reporting chain
2. Persist the Cloudflare WAF poller cursor (`since`) durably across daemon restarts
3. Add concrete Better Stack HTTP ingest and configuration
4. Fold the replay/reporting stage more cleanly out of the large orchestrator over time

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-27T13:10:00+02:00

### Completed

- Added `internal/security/reputation` as a provider-agnostic pre-ban boundary
- Refactored `internal/adapters/abuseipdb` into a pure reputation adapter:
  - HTTP translation
  - TTL cache
  - timeout-bounded lookup
  - no governance policy
- Purified domain-side security packages:
  - `internal/security/risk` no longer emits metrics
  - `internal/security/classifier` no longer knows Cloudflare comments or metrics
  - `internal/security/abuseformat` is now pure formatting only
- Added `internal/telemetry/events` and `internal/telemetry/sinks`:
  - passive security telemetry event model
  - recorder sink
  - Prometheus sink
  - Better Stack sink boundary
- Rewired enforcement through the real executor path:
  - `GovernedExecutor`
  - `CloudflarePropagationGuard`
  - audit journal
  - telemetry sink emission
- Added integration proof tests in `internal/execution/executor_integration_test.go`
- Added permanent regression coverage in `internal/security/postmortem`
- Added exact golden tests for canonical AbuseIPDB comments

### In progress

- The security slice is now architecturally purer and the Cloudflare guard is exercised in the real executor path, but live Cloudflare WAF ingestion and concrete Better Stack HTTP ingest are still pending.

### Next milestones

1. Feed live/replayed Cloudflare WAF events into the shared classifier chain before AbuseIPDB reporting
2. Route local CrowdSec/OpenResty detections through the same classifier + canonical formatter chain
3. Replace the Better Stack stub with a concrete HTTP sink behind `internal/telemetry/sinks`
4. Continue orchestrator decomposition so classification/reporting stages are thinner and more explicit

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-27T01:02:00+02:00

### Completed

- Added `internal/compat/python36`:
  - legacy env parsing
  - generated nginx/OpenResty contract projection
  - Lua constant projection
- Extended adapters:
  - `internal/adapters/openresty` now supports deterministic dry-run rendering
  - `internal/adapters/lua` now supports deterministic dry-run rendering
- Added `internal/security/fp_memory`
- Added `internal/security/classifier`
- Added `internal/adapters/abuseipdb`:
  - pre-ban `check` gating
  - TTL cache
  - short timeout
  - configurable fail-open / suppress behavior
  - replayable pre-ban evidence
- Extended `internal/abuseipdb/transport` with `/check`
- Extended Prometheus metrics with:
  - AbuseIPDB pre-ban metrics
  - Cloudflare local replay metrics
  - category/source metrics
- Added optional execution security guarding for Cloudflare mutation propagation

### In progress

- The new pre-ban guard and local replay classifier exist, but they are not yet fully wired into the live app/orchestrator mutation path and Cloudflare WAF event ingestion path.

### Next milestones

1. Inject the propagation guard into real executor wiring
2. Feed Cloudflare WAF events into the local classifier before AbuseIPDB reporting
3. Add Better Stack emission for suppressed and replay-classified events
4. Add operator approval/shadow propagation gates on top of the current pre-ban model

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-27T00:37:00+02:00

### Completed

- Added `internal/security/confidence`:
  - evidence-weighted decision scoring
  - review gating
  - explicit hard-deny/global-action thresholds
- Added `internal/security/trust`:
  - protected resource registry
  - defaults for RFC1918, loopback, management-plane, monitoring, control-plane
  - critical service defaults for Sonarr and Radarr
- Added `internal/security/blastradius`:
  - low-confidence cross-scope protection
  - protected target blocking
  - per-minute and propagation limit evaluation
- Updated `SECURITY_NOTES.md` with the new false-positive-resilience posture

### In progress

- The false-positive safety substrate now exists, but it is not yet enforced by the execution pipeline or Cloudflare propagation flow.

### Next milestones

1. Wire confidence/trust/blast-radius checks into mutation planning and propagation
2. Add `internal/security/fp_memory`
3. Add replayable decision explanation and approval gates
4. Resume `internal/compat/python36` and OpenResty/Lua dry-run rendering

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-27T00:21:00+02:00

### Completed

- Audited the Python 3.6.0 codebase in `/home/jm/Documents/crowdsec-cf-sync`
- Added `docs/migration/python36-gap-analysis.md`
- Added versioned contract schemas:
  - `contracts/events.schema.json`
  - `contracts/openresty.schema.json`
  - `contracts/crowdsec.schema.json`
  - `contracts/cloudflare.schema.json`
  - `contracts/betterstack.schema.json`
- Added `internal/adapters/openresty`:
  - strict JSON parsing
  - validation of shared dict declarations, init modules, and status endpoint
  - deterministic internal event projection
- Added `internal/adapters/lua`:
  - strict JSON parsing
  - validation of Lua IPC paths and mitigation timing parameters
  - deterministic internal event projection
- Added `make verify`

### In progress

- The new contracts and adapters define stable integration boundaries, but the legacy Python 3.6.0 config and generated-file compatibility bridge does not exist yet.

### Next milestones

1. Add `internal/compat/python36` to project legacy Python/OpenResty/Lua inputs into these contracts
2. Extend OpenResty and Lua adapters with dry-run rendering and offline compatibility fixtures
3. Implement Better Stack ingest parity
4. Continue Cloudflare/CrowdSec parity using replay-driven integration tests

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local make verify` succeeded

## 2026-05-27T00:02:36+02:00

### Completed

- Completed the typed runtime event catalog in `internal/runtime/events/typed.go`
- Added causality-friendly event context and lineage metadata propagation helpers
- Extended `internal/runtime/events/replay.go` with bounded replay by:
  - target sequence
  - target timestamp
- Extended `internal/runtime/recovery/event_recovery.go` with:
  - recovery plans
  - recovery manifests
  - bounded event recovery modes (`latest`, `sequence`, `time`)
- Added `internal/runtime/replay/consistency`:
  - ordering verification
  - sequence continuity verification
  - checkpoint continuity verification
  - divergence detection

### In progress

- Recovery is bounded and deterministic at the event/state level, but it is not yet orchestrating full scoped SQLite snapshot restore/reopen flows.

### Next milestones

1. Build full SQLite point-in-time restore orchestration
2. Add checksum-chain and evidence/policy lineage verification
3. Add corruption, chaos, and HA recovery drills
4. Add soak and goroutine-leak validation

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w .` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-26T23:43:38+02:00

### Completed

- Added typed runtime event helpers in `internal/runtime/events/typed.go`
- Added `internal/runtime/checkpoint`:
  - automatic runtime-state checkpoint persistence
  - checksum validation
  - retention compaction
  - stale checkpoint invalidation
- Wired `internal/runtime/engine.StateMachine` to:
  - emit lifecycle transition events
  - record automatic runtime checkpoints
  - persist rollback-before, rollback-after, and post-convergence checkpoints
- Added event-sourced runtime recovery in `internal/runtime/recovery/event_recovery.go`
- Hardened SQLite runtime durability helpers:
  - schema verification at startup
  - WAL auto-checkpoint configuration
  - manual WAL checkpoint helper
  - hot snapshot export helper
  - backup rotation helper
  - corruption quarantine helper
  - read-only degraded mode guards on mutable repositories

### In progress

- Recovery is now deterministic from checkpoint + event log for runtime state, but full point-in-time DB restore orchestration and replay-consistency verification are still pending.

### Next milestones

1. Add the remaining typed runtime events: policy, mutation, rollback, scheduler, worker, HA
2. Add replay consistency verification and checksum-chain validation
3. Add hot-snapshot + event-log point-in-time restore orchestration
4. Add corruption and degraded-mode recovery drills

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w .` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-26T23:19:49+02:00

### Completed

- Hardened `internal/runtime/events` for the first production-hardening slice:
  - added explicit publish request and checkpoint models
  - removed hidden subscriber goroutines from the event bus
  - made event replay checkpoint-aware
- Hardened `internal/storage/sqlite` event persistence:
  - transactional per-scope sequence assignment
  - durable event checkpoint persistence via migration version 3
- Hardened `internal/runtime/scheduler/pool` shutdown:
  - removed hidden submit goroutine
  - added explicit worker-pool close/wait behavior
- Fixed the pre-existing `go vet` failure in `internal/observability/metrics/metrics_test.go`

### In progress

- Event sourcing exists as a real append-only substrate, but automatic runtime-state checkpoint emission and higher-level recovery orchestration are still pending.

### Next milestones

1. Add typed event helper constructors and stricter event vocabularies
2. Persist runtime-state checkpoints from lifecycle transitions
3. Build point-in-time recovery and dry-run recovery validation on top of checkpoints
4. Add integrity/corruption tests around the event/checkpoint path

### Validation snapshot

- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-19T23:05:06+02:00

### Completed

- Production Python scripts analyzed:
  - `/usr/local/bin/crowdsec-cf-sync.py`
  - `/usr/local/bin/cloudflare-allowlist-update.py`
  - `/usr/local/bin/cloudflare-cleanup-ip-rules.py`
- Responsibility mapping captured in architecture documentation
- Go scaffold created in a separate directory
- Go baseline changed from `1.24` to `1.22.2`
- Compile-safe placeholders added for all requested interface areas
- Unit-test skeletons added for config, logging, scheduler, and JSON state
- Validation completed successfully on Go 1.22.2

### In progress

- No partial refactor is open
- No package is left half-implemented
- Deferred production behavior remains behind explicit TODO markers

### Next milestones

1. Implement `internal/cloudflare` HTTP client and tests
2. Implement `internal/crowdsec` execution layer and typed parsing
3. Complete `cf-allowlist-sync` first as the parity target

### Validation snapshot

- `GOTOOLCHAIN=local gofmt -w .` succeeded
- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-19T23:15:08+02:00

### Completed

- Added `internal/apperr` for structured error wrapping
- Added `internal/httpclient` for pooled HTTP access, retry policy, backoff, and rate-limit hooks
- Added trace ID propagation in `internal/logging`
- Added scheduler timeout support, explicit lifecycle logging, non-overlap protection, and snapshot metrics
- Updated JSON state persistence to avoid holding locks during file I/O by using atomic temp-file writes
- Added race-focused tests for scheduler and state
- Added project-wide verification rules in `ACCURACY_POLICY.md`

### Validation snapshot

- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-19T23:30:28+02:00

### Completed

- Added Cloudflare-specific migration rules and fixture-capture constraints.
- Locked in irreversible sanitization, corruption detection, checksum validation, and replay metadata requirements.

## 2026-05-19T23:46:32+02:00

### Completed

- Added operational safety, reconciliation durability, and mutation execution rules.
- Locked in kill-switch, emergency mode, mutation limits, and circuit breaker requirements.

## 2026-05-20T10:15:00+02:00

### Completed

- Deep dive analysis of production Python scripts.
- Mapped all 8+ sub-features to Go package boundaries.
- Updated `COMPATIBILITY_CHECKLIST.md` with categories, tags, and thresholds from source.
- Updated `internal/cloudflare/models.go` with JSON tags and structure.
- Added comprehensive `TODO` markers across `internal/` packages.

## 2026-05-20T10:30:00+02:00

### Completed

- Finalized `internal/snapshot` package:
  - Deterministic normalization, ordering stability, and stable checksums.
  - Rejection of trailing JSON content.
- Verified Go 1.22.2 compatibility.

## 2026-05-20T10:45:00+02:00

### Completed

- Implemented `internal/reconciliation` package:
  - Serializable `Plan` and `Operation` models.
  - `GenericPlanner` for deterministic diffing between snapshots.
  - Idempotent operation keys and stable sorting.
  - Dry-run summary generation.
- Exported `snapshot.CanonicalJSON` for reuse in planner.
- Verified compilation and added unit tests for the planner.

## 2026-05-20T11:00:00+02:00

### Completed

- Implemented `internal/fixtures` package:
  - Deterministic sanitization of sensitive data.
  - Offline `ReplayEngine` with support for sequence ordering and integrity validation.
  - Failure injection capabilities for simulating 429s, timeouts, and transient errors.
- Verified 100% offline test coverage.

## 2026-05-20T11:30:00+02:00

### Completed

- Refined `internal/snapshot` package:
  - Transitioned to domain-driven model (business state, not API dump).
  - Implemented `StableIdentityKey` (SIK) for domain-controlled identity.
  - Added sanitized `ScopeMetadata` with hashed IDs.
- Verified 100% green build and tests.

## 2026-05-20T12:00:00+02:00

### Completed

- Implemented `internal/cloudflare` discovery layer (read-only):
  - Robust `transport` with retry logic and strict decoding.
  - Deterministic `pagination` traversal.
  - Integrated with `fixtures` replay engine.

## 2026-05-20T12:30:00+02:00

### Completed

- Refactored `internal/cloudflare` to strictly separate discovery from normalization.
- Updated `internal/cloudflare/client` to orchestrate discovery and normalization.

## 2026-05-20T13:00:00+02:00

### Completed

- Implemented `internal/snapshot/builder` specialized assemblers for multi-page and multi-resource assembly.
- Added duplicate detection based on `StableIdentityKey`.

## 2026-05-20T13:30:00+02:00

### Completed

- Implemented `internal/crowdsec` execution adapter layer with deterministic translation and dry-run rendering.

## 2026-05-20T14:00:00+02:00

### Completed

- Implemented `internal/orchestrator` end-to-end dry-run pipeline.
- Implemented `cmd/cf-sync` CLI command supporting `diff --dry-run`.

## 2026-05-20T14:30:00+02:00

### Completed

- Implemented `internal/crowdsec/adapter` real executor with safe shell execution and mandatory timeouts.

## 2026-05-20T15:00:00+02:00

### Completed

- Implemented `internal/runtime` package for transactional persistence, circuit breaker protection, and manual kill-switch.

## 2026-05-20T15:30:00+02:00

### Completed

- Implemented `internal/observability` full Prometheus metrics layer.

## 2026-05-20T16:00:00+02:00

### Completed

- Implemented `internal/abuseipdb` governed execution provider for IP reporting.

## 2026-05-20T16:30:00+02:00

### Completed

- Implemented `internal/snapshot/builder/multi` for multi-resource dependency orchestration.

## 2026-05-20T17:00:00+02:00

### Completed

- Implemented `internal/cloudflare/rulesets` phase-aware reconciliation for WAF and ruleset pipelines.

## 2026-05-20T17:30:00+02:00

### Completed

- Refactored `internal/config` to implement a robust, versioned YAML configuration system.

## 2026-05-20T18:00:00+02:00

### Completed

- Implemented `internal/observability/tracing` for full reconciliation lifecycle visibility with OTEL.

## 2026-05-20T18:30:00+02:00

### Completed

- Implemented `internal/testing/chaos` package for runtime resilience validation.

## 2026-05-20T19:00:00+02:00

### Completed

- Implemented the "Safe Cloudflare Write-Path" architecture for governed execution with optimistic concurrency.

## 2026-05-20T20:00:00+02:00

### Completed

- Implemented the "Governed Rollback and Compensation Engine".

## 2026-05-21T15:00:00+02:00

### Completed

- Hardened the persistence layer with Production-Grade Database Evolution:
  - Implemented `internal/storage/manager` for versioned SQL migrations.
  - Transitioned to idempotent schema management using the `schema_migrations` table.
  - Added SQLite durability features: manual WAL checkpointing (`PRAGMA wal_checkpoint`) and controlled `VACUUM`.
  - Implemented transactional database snapshots using `VACUUM INTO` for atomic, consistent state exports.
  - Integrated the migration runner into the scoped SQLite connection lifecycle.
- Verified 100% green build and tests.

### Next milestones

1. Implement "Event Sourcing & Unified Timeline" for forensic auditing.
2. Design and implement the "Policy Bundles Versioning" with cryptographic signing.
3. Design and implement "Distributed Coordination" with etcd/Consul.

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-21T14:00:00+02:00

### Completed

- Implemented `internal/policy/intent` for autonomous governance:
  - Created high-level `Intent` models (Paranoid, Availability-First, Terraform-Friendly).
  - Implemented `IntentCompiler` to translate business objectives into technical constraints (budgets, drift tolerance, cooldowns).
  - Built a `Predictive Simulation Engine` (`internal/runtime/simulation`) to forecast reconciliation risks without state mutation.
  - Implemented `TimelineCollector` (`internal/runtime/timeline`) to assemble forensic views of lifecycle events and policy decisions.
  - Integrated intent-based signals into the platform lifecycle.
- Verified 100% green build and tests.

### Next milestones

1. Design and implement the "Policy Bundles Versioning" with cryptographic signing.
2. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).
3. Implement "Self-Healing Governance" with autonomous adaptive policies.

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-21T13:00:00+02:00

### Completed

- Implemented `internal/storage` transactional persistence layer:
  - Defined clean repository interfaces for `RuntimeState`, `Leases`, `OwnershipClaims`, and `GovernanceEvidence`.
  - Created a scoped SQLite backend (`state/<scope_id>/runtime.db`) with **WAL mode** for ACID guarantees and crash-safe commits.
  - Implemented `RuntimeRepository`, `LeaseRepository`, and `OwnershipRepository` using explicit SQL queries.
  - Provided a legacy `fs` provider for non-breaking backward compatibility.
  - Optimized database performance with mandatory pragmas (`busy_timeout`, `foreign_keys`, `synchronous=NORMAL`).
  - Refactored `main.go` to support scoped database initialization per runtime scope.
- Verified 100% green build and tests.

### Next milestones

1. Design and implement "Policy Bundles Versioning" with cryptographic signing.
2. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).
3. Implement "Intent-Based Governance" compiler.

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-21T12:00:00+02:00

### Completed

- Implemented `internal/policy/explain` for governance transparency:
  - Created `DecisionGraph` model to represent causal DAGs of policy decisions.
  - Implemented `Builder` to reconstruct decision paths from `FederatedDecision` and `GovernanceEvidence`.
  - Added Mermaid export functionality for visual rendering of decision logic.
  - Implemented API v3 with `GET /api/v3/policy/explain` endpoint.
  - Integrated explainability into the `AdmissionController`.
- Verified 100% green build and tests.

### Next milestones

1. Design and implement "Intent-Based Governance" compiler.
2. Implement "Policy Bundles Versioning" with cryptographic signing.
3. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-21T11:00:00+02:00

### Completed

- Implemented `internal/policy/federation` for hierarchical governance:
  - Created a `Resolver` to manage multiple policy scopes (Global, Tenant, Zone).
  - Implemented `MergeDecisions` with a strict severity-based priority (DENY > QUARANTINE > REQUIRE_APPROVAL > COOLDOWN > ALLOW).
  - Added support for `FederatedBundle` representing policies at different levels of authority.
  - Integrated the federation resolver into the `AdmissionController` to evaluate hierarchical policy chains.
  - Updated the audit and evidence recording to track contributors to federated decisions.
- Verified 100% green build and tests, ensuring deterministic decision merging.

### Next milestones

1. Design and implement the "Policy Explainability Graph" for visual decision debugging.
2. Implement "Intent-Based Governance" to translate high-level security goals into Rego rules.
3. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-21T10:00:00+02:00

### Completed

- Implemented `internal/policy/replay` for Deterministic Governance:
  - Created `GovernanceEvidence` model to record the complete context of every policy decision (inputs, runtime state, ownership claims, budget pressure).
  - Implemented `canonical.Checksum` to ensure hash stability for reproduction.
  - Added `EvidenceRecorder` to persist decision context in memory (and trace in audit logs).
  - Implemented `Verifier` to re-evaluate past decisions using the same input and policy bundle.
  - Integrated evidence recording into the `AdmissionController` during OPA evaluation.
  - Extended API v2 with `GET /api/v2/policy/evidence` to explore decision history.
- Verified 100% green build and tests, including regression-free orchestrator pipeline.

### Next milestones

1. Implement "Policy Bundles Versioning" with cryptographic signing.
2. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).
3. Design and implement "Intent-Based Security Layer" for high-level security orchestration.

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-21T09:00:00+02:00

### Completed

- Implemented `internal/policy/opa` (Policy-as-Code Phase 1):
  - Integrated Open Policy Agent (OPA) Go SDK for declarative governance.
  - Created a canonical `PolicyInput` model representing the complete runtime state.
  - Implemented `BundleLoader` to manage Rego policies on disk.
  - Added default `admission.rego` policy covering breaker status, hostile drift, large batches, and destructive operations.
  - Integrated OPA evaluation into the `AdmissionController` alongside legacy rules.
  - Updated `MutationBatch` to include derived metrics (`DestructiveCount`) for easy policy consumption.
- Verified 100% green build and tests, including OPA-backed decision validation.

### Next milestones

1. Design and implement "Policy Bundles Versioning" with cryptographic signing.
2. Implement "Deterministic Governance Replay" for post-mortem audit.
3. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-21T08:00:00+02:00

### Completed

- Implemented `internal/runtime/ha` for Real HA Coordination:
  - Created a `CoordinationBackend` interface to support distributed leader election and fencing tokens.
  - Implemented `FencingToken` logic (monotonic epochs) to prevent "zombie" mutations during network partitions.
  - Added a `FileBackend` implementation for local HA simulation.
  - Integrated fencing tokens into `Lease` acquisition and `RuntimeContext`.
  - Refactored `main.go` and `Orchestrator` to support HA-aware execution.
  - Ensured mutation serialization per scope remains guaranteed in multi-node scenarios.
- Verified 100% green build and tests, including fencing token propagation.

### Next milestones

1. Implement "Drift Intelligence v2" with temporal memory and structural fingerprints.
2. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).
3. Design and implement "Policy-as-Code" (OPA/Rego integration).

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-21T07:00:00+02:00

### Completed

- Implemented `internal/api/v2` multi-tenant interface:
  - Added scoped endpoints for platform visibility: `GET /api/v2/ownership/claims`, `GET /api/v2/governor/budgets`, and `GET /api/v2/workers`.
  - Implemented runtime control endpoints: `POST /api/v2/runtime/pause` and `POST /api/v2/runtime/resume`, integrated with the formal `StateMachine`.
  - Added visibility into worker pool saturation and tenant budget usage.
  - Registered Standard Domains (Terraform, cf-sync) in the ownership federation layer.
  - Refactored `Orchestrator` and `Scheduler` to expose component getters for the API server.
- Verified 100% green build and tests, including API route registration and transition safety.

### Next milestones

1. Design and implement "Real HA Coordination" with a distributed lock backend (etcd/Consul).
2. Implement "Drift Intelligence v2" with temporal memory and structural fingerprints.
3. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-21T06:00:00+02:00

### Completed

- Implemented `internal/runtime/ownership` federation layer:
  - Created an `OwnershipResolver` to adjudicate sovereignty between domains (Terraform, cf-sync, Dashboard, etc.).
  - Implemented priority-based resolution and capability checks (Create, Update, Delete, Rollback, Override).
  - Added support for `OwnershipClaims` to track current sovereignty over specific resources (SIKs).
  - Integrated the ownership resolver into the `AdmissionController` to gate all mutation attempts.
  - Added formal `TrustLevels` (Immutable, Authoritative, Managed) to prevent accidental mutation of Cloudflare-managed or Terraform-managed resources.
  - Updated `main.go` to register standard domains and initialize the federation layer.
- Verified 100% green build and tests, including priority override and denial scenarios.

### Next milestones

1. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).
2. Implement "Multi-Tenant API" to expose scoped status and control.
3. Design and implement "HA Leader Election" using a distributed lock backend.

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-21T05:00:00+02:00

### Completed

- Implemented `internal/runtime/governor` (Budget v2):
  - Created a `ResourceGovernor` to manage systemic pressure on providers (Cloudflare, etc.).
  - Implemented hierarchical `TokenBuckets` in `internal/runtime/limiter` (Global -> Tenant -> Scope).
  - Separated budget dimensions: `ResourceRequest` (discovery), `ResourceMutation` (POST/PUT/PATCH), and `ResourceDestructive` (DELETE).
  - Added support for systemic saturation scoring (`Pressure`) per provider.
  - Implemented a `Coalescer` in `internal/runtime/coalesce` to optimize mutation batches and reduce API churn.
  - Integrated the governor into the `Orchestrator` to gate discovery and mutation phases.
- Verified 100% green build and tests, including hierarchical limit enforcement.

### Next milestones

1. Implement "Ownership Federation" to handle multi-operator precedence (Terraform vs cf-sync).
2. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).
3. Implement "Multi-Tenant API" to expose scoped status and control.

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-21T04:00:00+02:00

### Completed

- Implemented `internal/runtime/scheduler` partition-aware multi-worker orchestration:
  - Created a `WorkerPool` in `internal/runtime/scheduler/pool` to manage bounded execution across multiple scopes.
  - Implemented a `WorkQueue` in `internal/runtime/scheduler/queue` with priority support (high priority for rollbacks).
  - Added a `BudgetManager` in `internal/runtime/scheduler/budget` to enforce tenant-level concurrency quotas and prevent starvation.
  - Refactored the `Stateful Scheduler` to orchestrate units of work via the pool and queue, respecting the formal state machine and isolated scope boundaries.
  - Introduced immutable `RuntimeContext` for safe, context-bound task execution.
  - Integrated Prometheus metrics for tracking worker pool saturation and tenant budget usage.
- Verified 100% green build and tests, including concurrent tick safety and priority handling.

### Next milestones

1. Implement "Tenant Budgets" v2 with mutation rates and API quotas.
2. Implement "Ownership Federation" to handle multi-operator precedence (Terraform vs cf-sync).
3. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-21T03:00:00+02:00

### Completed

- Implemented `internal/runtime/scope` for runtime isolation and multi-tenant partitioning:
  - Created a canonical `RuntimeScope` identity based on Tenant, Account, Zone, and Environment.
  - Implemented logic to derive stable `scope_id` for filesystem partitioning.
  - Partitioned all core stateful components: `StateStore`, `JournalStore`, `QuarantineStore`, and `LeaseManager` now operate within isolated subdirectories.
  - Updated `main.go` to initialize a scoped runtime environment, preventing state contamination between different zones or environments.
  - Refactored `JournalStore` and `StateStore` to automatically ensure parent directory existence for better reliability.
  - Integrated scoped logic into the `Orchestrator` and `Scheduler` initialization.
- Verified 100% green build and tests, confirming that isolation does not break existing correctness guarantees.

### Next milestones

1. Design and implement the "Partition-Aware Multi-Worker Scheduler".
2. Implement "Tenant Budgets" and scoped security policies.
3. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-21T02:00:00+02:00

### Completed

- Implemented `internal/runtime/drift` intelligence layer:
  - Created a deterministic `Classifier` for drift events (benign, operator, hostile, provider, oscillation, stale, ownership, convergence).
  - Implemented `Scorer` for risk assessment based on classification and severity.
  - Added `EscalationEngine` to determine automated reactions (quarantine, rollback, require approval, etc.) integrated with the `StateMachine`.
  - Integrated the `DriftEngine` into the `Orchestrator` to govern responses to detected divergences.
  - Added structured metadata and identifiers for correlation and auditability of drift events.
- Verified 100% green build and tests, including drift classification and escalation scenarios.

### Next milestones

1. Implement "Multi-Tenant / Multi-Zone" runtime partitioning and zone sharding.
2. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).
3. Finalize Cloudflare WAF and Ruleset phase-aware reconciliation.

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-21T01:00:00+02:00

### Completed

- Implemented `internal/runtime/scheduler/stateful`:
  - Created a lifecycle-aware `Scheduler` that respects formal runtime states and execution leases.
  - Implemented `RetryPolicy` with exponential backoff, capped delays, and randomized jitter.
  - Added `CooldownManager` in `internal/runtime/cooldown` to stabilize the system after failures or oscillations.
  - Integrated the scheduler with the `StateMachine` to ensure sequential, non-overlapping runs.
  - Added comprehensive Prometheus metrics for scheduler runs, retries, cooldowns, and pauses.
  - Updated `main.go` to initialize and run the stateful scheduler in daemon mode with robust locking.
- Verified 100% green build and tests, including lifecycle safety and retry logic.

### Next milestones

1. Implement "Drift Intelligence" classification and escalation policies.
2. Design and implement "Multi-Tenant / Multi-Zone" runtime partitioning.
3. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-21T00:00:00+02:00

### Completed

- Implemented `internal/runtime/engine` formal state machine:
  - Defined explicit runtime states: `Idle`, `Discovering`, `Planning`, `AwaitingApproval`, `Executing`, `Validating`, `Converged`, `RollbackRequired`, `RollingBack`, `Quarantined`, `Failed`.
  - Implemented strict transition validation rules to prevent inconsistent lifecycle moves.
  - Integrated the state machine into the `Orchestrator` to govern every reconciliation and rollback run.
  - Added support for state persistence and lifecycle tracking in `RuntimeState`.
  - Ensured that recovery and retry semantics follow the formal state boundaries.
- Verified 100% green build and tests, including lifecycle transition validation.

### Next milestones

1. Design and implement the "Stateful Autonomous Scheduler" with backoff, jitter, and cooldown.
2. Implement "Drift Intelligence" classification and escalation policies.
3. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-20T23:00:00+02:00

### Completed

- Implemented `internal/runtime/convergence` correctness layer:
  - Added `InvariantEngine` for validating system-wide constraints (uniqueness, graph integrity).
  - Implemented `ConvergenceValidator` for post-apply verification by re-fetching remote state.
  - Added `OscillationDetector` to identify and prevent infinite reconciliation cycles.
  - Integrated convergence validation into the `Orchestrator` lifecycle.
  - Added structured audit events for invariant violations and non-converged states.
  - Ensured automated quarantine for unstable or ambiguous states.
- Verified 100% green build and tests, including invariant violation scenarios.

### Next milestones

1. Implement the "Safe Cloudflare Write-path" live execution.
2. Design and implement the stateful daemon/scheduler for automated reconciliation.
3. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-20T22:00:00+02:00

### Completed

- Implemented `internal/runtime/coordination` safety layer:
  - Added `LeaseManager` for exclusive execution ownership of reconciliation and rollback.
  - Implemented `Lease` model with expiration and owner identity.
  - Introduced `Epoch` model with generation counters and parent lineage tracking.
  - Integrated lease acquisition into the `Orchestrator` for rollback.
  - Added support for lease and epoch persistence in `RuntimeState`.
  - Added targeted tests for overlapping runs, expiration, and epoch generation.
- Verified 100% green build and tests, including coordination safety scenarios.

### Next milestones

1. Implement the "Safe Cloudflare Write-path" live execution.
2. Design and implement the stateful daemon/scheduler for automated reconciliation.
3. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded

## 2026-05-20T21:00:00+02:00

### Completed

- Implemented `internal/policy` governance layer with `PolicyEngine` and `AdmissionController`.
- Extended `internal/api` with audit exploration and quarantine management endpoints.
- Verified 100% green build and tests.

### Next milestones

1. Implement the "Safe Cloudflare Write-path" live execution.
2. Design and implement the stateful daemon/scheduler for automated reconciliation.
3. Complete the transition of remaining Python logic (Recidive, ModSec, CIDR ban).

### Validation snapshot

- `GOTOOLCHAIN=local go build ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
## 2026-05-27T00:52:34+02:00

### Completed

- Added `internal/security/baseline` for benign browser bootstrap learning.
- Hardened `internal/security/risk` to keep baseline-only traffic in `observe_only`.
- Added AbuseIPDB config support and used it in `cmd/cf-sync`.
- Wired `CloudflarePropagationGuard` into the real `GovernedExecutor` path used by `cf-sync`.
- Extended the guard to cover Cloudflare mutation resource types beyond only `ip_access_rules`.
- Enforced canonical AbuseIPDB comment generation through `internal/security/abuseformat` in the translator path.
- Added `internal/security/safety` test coverage for favicon/robots/baseline/low-score/high-score replay cases.

### Remaining

- Live Cloudflare WAF event ingestion and normalization before AbuseIPDB reporting.
- Shared classifier/reporting flow for CrowdSec and OpenResty local detections.
- Better Stack complete security event emission.
- Replayable persisted evidence for suppression decisions.

### Validation snapshot

- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded

## 2026-05-28T-current+02:00

### Completed

- Added runtime fencing metadata to mutation and rollback operation models.
- Validated active scoped lease ID and fencing token before destructive execution paths.
- Added audit/telemetry status `stale_fencing_token_mutation_refused`.
- Added retryable AbuseIPDB report outbox rows with durable report payloads and bounded retry metadata.
- Added a context-bound outbox worker and wired it into the local WAF runtime scheduler tick.
- Continued reducing `internal/services/reporting` by extracting decision preparation.

### Validation snapshot

- Targeted package tests passed for reporting, SQLite, execution, rollback executor, and app before full-suite validation.

## 2026-05-29T-current+02:00

### Completed

- Tightened SQLite error handling by using typed modernc SQLite codes in centralized helpers.
- Shifted legacy lease scope normalization to a dedicated migration (`v12`) to keep lease runtime paths free of migration debt.
- Strengthened lease renewal semantics with epoch lineage checks in addition to owner/scope/fencing checks.
- Added rollback fencing regression test and additional lease renewal mismatch coverage.

### Validation snapshot

- `GOTOOLCHAIN=local go test ./...` succeeded
- `GOTOOLCHAIN=local go test -race ./...` succeeded
- `GOTOOLCHAIN=local go vet ./...` succeeded
- `GOTOOLCHAIN=local go build ./...` succeeded
