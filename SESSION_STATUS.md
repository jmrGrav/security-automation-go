# SESSION_STATUS

Last updated: 2026-05-29T15:20:00+02:00

## Latest hardening update

- AbuseIPDB outbox worker now supports an optional lease-bound safety gate:
  - new `OutboxLeaseGuard` hook in `OutboxWorkerConfig`
  - if guard refuses, no upstream AbuseIPDB call is attempted for that item
  - retry semantics are unchanged when the guard is not configured
- Ownership claims are now persistent-authority aware in the runtime resolver:
  - resolver now supports `ClaimStore`
  - `Resolve` reads current ownership claim from store when configured (store is authority)
  - `Claim` persists to store first, then updates in-memory cache
  - `ListClaims` returns persistent claims when store is configured
  - cf-sync wiring now binds resolver claim store to SQLite ownership repository
- Added restart/drift regression tests for ownership claims:
  - persisted claim remains authoritative after resolver restart
  - in-memory drift does not override persisted store authority
- Added outbox lease-bound regression test:
  - lease guard refusal blocks upstream reporter execution

- Priority 4 (fencing propagation) hardened in production wiring:
  - `LeaseStoreFencingValidator` now supports strict mode (`RequireFencing(true)`)
  - cf-sync now enables strict fencing for both governed execution and rollback execution
  - missing fencing metadata now fails closed for scoped mutation paths in prod wiring
- Added stale leadership race regressions:
  - governed executor: leader change mid-batch stops remaining mutations (second op refused)
  - rollback executor: stale fencing on second op stops remaining compensation ops and persists failed checkpoint

- High #2 closed with durable rollback checkpoints (no big rewrite):
  - added SQLite `rollback_checkpoints` store (migration v14)
  - rollback executor now persists checkpoint on start, after each completed compensation op, on failure, and on completion
  - rollback executor now reloads persisted checkpoint by `batch_id` and resumes from `last_completed_op_idx`
  - completed persisted rollback batches short-circuit safely (no duplicate provider mutations)
  - cf-sync wiring now injects the durable checkpoint store into rollback executor
- Added rollback durability tests:
  - resume after mid-batch failure executes only remaining ops
  - failed run persists resumable checkpoint
  - completed checkpoint prevents duplicate replay of compensation operations
  - SQLite store save/load/update coverage for rollback checkpoints

- Ownership lineage API now supports cursor-based pagination for high-volume forensic browsing:
  - query params:
    - `before_created_at` (RFC3339Nano)
    - `before_id`
    - `limit`
  - ordering remains stable: `created_at DESC, id DESC`
  - response semantics unchanged (list payload), with next cursor emitted in headers:
    - `X-Ownership-Lineage-Next-Created-At`
    - `X-Ownership-Lineage-Next-ID`
- Ownership CLI now supports cursor navigation:
  - `--before_created_at`
  - `--before_id`
- SQLite ownership lineage now has cursor-aware query support (`ListLineageCursor`) while preserving existing list semantics.
- Added regression tests for cursor paging and ownership replay divergence determinism under multi-scope restart.

- Forensic ownership lineage query is now exposed in CLI and API:
  - CLI mode: `cf-sync -mode ownership [list|show|explain]`
  - API v3:
    - `GET /api/v3/security/ownership/lineage`
    - `GET /api/v3/security/ownership/lineage/{event_id}`
    - `GET /api/v3/security/ownership/lineage/{event_id}/explain`
- Ownership lineage storage now supports direct read by event ID (`GetLineage`) in addition to filtered list.
- Recovery ownership divergence tests were expanded for multi-scope + restart consistency:
  - scope-isolated divergence detection
  - deterministic violation signature across restart/replay runs

- PR1 (ownership durable lineage) implemented with append-only SQLite storage:
  - new `ownership_lineage` table + indexes (migration v13)
  - lineage append/list repository methods
  - runtime ownership resolver now emits lineage events for `resolve` and `claim`
  - cf-sync wiring now connects resolver to durable SQLite lineage recorder
- PR2 (restore/replay ownership tests) implemented:
  - ownership lineage replay helper (`RebuildClaimsFromLineage`)
  - tests proving latest claim reconstruction by `(scope,resource)`
  - SQLite lineage replay test proving persisted lineage reconstructs expected owner
- PR3 (recovery ownership invariants) implemented:
  - recovery now checks ownership claim/lineage coherence per scope
  - violation cases: missing lineage, non-claim latest lineage, epoch/domain mismatch, invalid claim fields
  - recovery fails closed on ownership invariant violations and returns detailed invariant issue list in report

## Previous hardening update

- SQLite correctness hardening (Priority 1) is now implemented: string-based error checks are replaced by typed `sqlite.Error` and native codes in `internal/storage/sqlite/errors.go`.
- Migration debt removed from hot paths (Priority 2): `normalizeLegacyScope` moved to `DB.New` bootstrap.
- Lease ownership and fencing lineage hardened (Priority 3): `RenewLease` and `ReleaseLease` now strictly verify `owner` and `fencing_token`.
- SQLite point-in-time restore orchestration (Priority 5) exists in `recovery.Manager` with atomic snapshot restore and quarantine-backup support.
- Replay integrity extended (Priority 6) with sequence continuity and gap detection.
- Final hardening status and roadmap are documented in `docs/hardening/final-status-and-roadmap.md`.
- The post-review safe auto-fix tightened AbuseIPDB outbox reservation semantics:
  - same `idempotency_key` reservation is idempotent
  - different pending same-IP reservation is blocked while fresh
  - expired pending reservation is marked failed before a new reservation is accepted
  - `MarkStatus` now errors if no outbox row was updated
- Runtime event append now returns a typed `sqlite.ErrCommitAmbiguous` when a commit acknowledgement is ambiguous and the `(scope_id, event_uid)` row cannot be found post-facto.
- Cloudflare mutators now implement context-aware execution so lost-lease cancellation can abort long provider calls instead of waiting for background work to finish.
- Rollback execution now binds its mutation context to the HA lease heartbeat; lost heartbeat signals cancel the rollback context with a `lost lease` cause.
- `GovernedExecutor` emits `lost_lease_mutation_aborted` audit and telemetry events when cancellation stops a batch or in-flight mutation.
- AbuseIPDB reporting now uses a strict durable reservation path when configured: reserve outbox row, persist `report_pending` evidence, then call upstream, then mark success/failure and 24h dedup.
- Reporting evidence search now projects `decision` and `abuse_type` into SQLite columns and uses SQL filtering/pagination instead of decision filtering in memory.

## Current architecture state

- Separate Go module created at `/home/jm/Documents/security-automation-go`
- Go baseline retargeted to `go 1.22.2`
- Three command entrypoints exist under `cmd/`
- Dependency injection wiring exists in `internal/app`
- Config loading is environment-driven in `internal/config`
- Structured logging uses the Go standard library `log/slog`
- Trace IDs are propagated through logging context
- Structured error wrapping exists in `internal/apperr`
- Dedicated HTTP client abstraction exists in `internal/httpclient`
- Interval scheduling now includes timeout support, explicit lifecycle logging, non-overlap protection, and execution metrics
- Typed interfaces and placeholder clients exist for Cloudflare, CrowdSec, AbuseIPDB, Better Stack, and state storage
- JSON-backed state store is implemented for phase 1 compatibility with atomic temp-file writes and no locks held during file I/O
- Cloudflare implementation constraints are documented: fixture capture tooling first, separated raw and sanitized fixtures plus replay metadata, deterministic replay, replay integrity checks, schema drift checks, read-only first, dry-run before mutations, explicit pagination, strict decoding, sanitized fixtures, and fully mockable boundaries
- Reconciliation constraints are documented: idempotent plans, discovery/planning/execution separation, dry-run outputs, deterministic decisions, and no direct coupling to transport responses
- Reconciliation durability constraints are documented: serializable plans, persistable discovery snapshots, resumable execution progress, operation IDs, and replay-safe journaling
- Mutation execution constraints are documented: transactional grouping semantics, resumable batches, state-machine tracking, stale-plan detection, confirmation gates, and audit snapshots
- Operational safety constraints are documented: kill switch, emergency read-only mode, mutation limits, circuit breaker, degraded/quarantine modes, and structured audit logging
- Pure snapshot normalization exists in `internal/snapshot` with deterministic checksum generation and no transport or reconciliation coupling
- Generic fixture capture exists in `internal/snapshot` with separate raw/sanitized artifacts and replay metadata, still without transport or provider coupling
- Generic offline replay exists in `internal/snapshot` with deterministic ordering, integrity validation, latency hooks, and failure-mode simulation over sanitized fixtures only
- Runtime event sourcing now has a stricter append-only core in `internal/runtime/events` with explicit publish requests, synchronous subscriber delivery, no hidden goroutines in the event bus, typed checkpoint models, and replay that can resume from persisted checkpoints
- Scoped SQLite event storage now assigns event sequences transactionally per scope and persists event checkpoints through a versioned schema migration
- Stateful worker-pool shutdown is now explicit, and scheduler tests no longer leave background workers running past test cleanup
- Typed runtime event helpers now cover lifecycle, policy, mutation planned/applied, rollback started/completed/failed, drift, lease, fencing, scheduler, worker, governor pressure, breaker state, HA leader, recovery, and replay divergence events
- Automatic runtime checkpointing exists in `internal/runtime/checkpoint` with checksum validation, retention compaction, and stale-checkpoint invalidation
- The runtime state machine now emits lifecycle events and persists runtime checkpoints automatically on transitions when wired with an event bus and checkpoint manager
- Event-sourced recovery now exists in `internal/runtime/recovery/event_recovery.go` with checkpoint-aware replay, dry-run support, divergence detection, and basic orphan-lease/zombie-epoch detection
- Event replay now supports bounded recovery by target sequence or target timestamp
- Replay consistency verification now exists in `internal/runtime/replay/consistency` with ordering, continuity, checkpoint continuity, and divergence detection
- SQLite production hardening now includes schema verification at startup, WAL auto-checkpoint configuration, manual WAL checkpoints, hot snapshot export helpers, backup rotation, corruption quarantine helpers, and read-only degraded mode guards on mutable repositories
- A Python 3.6.0 differential audit now exists in `docs/migration/python36-gap-analysis.md`
- Versioned external contracts now exist under `contracts/` for events, OpenResty, CrowdSec, Cloudflare, and Better Stack
- Parse/validate-only adapters now exist for OpenResty and Lua under `internal/adapters/` and emit runtime-compatible internal event envelopes without modifying the FSM
- `make verify` now provides a repository verification target using recursive `gofmt`, `go vet`, `go test`, and static binary builds
- A first false-positive resilience foundation now exists under `internal/security/`:
  - `confidence` for scoring evidence-driven security decisions
  - `trust` for protected resources and anti-self-ban defaults
  - `blastradius` for scoped propagation limits and review gates
- Python 3.6.0 compatibility now exists in `internal/compat/python36` for legacy env, generated nginx/OpenResty config, and Lua constant projection into explicit contracts
- OpenResty and Lua adapters now support deterministic dry-run rendering in addition to parse/validate/event projection
- AbuseIPDB pre-ban gating now exists as a separate adapter under `internal/adapters/abuseipdb` with TTL caching, short timeout handling, configurable failure mode, replayable evidence, and protected-target suppression
- Local replay classification for Cloudflare-style events now exists in `internal/security/classifier`
- False-positive memory with temporal decay now exists in `internal/security/fp_memory`
- Execution now supports an optional security guard before mutation execution; Cloudflare propagation can be gated before mutation side effects
- `internal/security/reputation` now provides a provider-agnostic reputation boundary for pre-ban checks
- `internal/adapters/abuseipdb` is now reduced to HTTP/cache/serialization concerns behind the reputation boundary
- `internal/security/risk`, `internal/security/classifier`, and `internal/security/abuseformat` are now side-effect-free domain packages and no longer import metrics or provider packages
- `internal/telemetry/events` and `internal/telemetry/sinks` now provide a passive telemetry boundary for Prometheus and Better Stack style emission
- `cmd/cf-sync` now wires the Cloudflare propagation guard through the real governed executor path using the new reputation checker boundary
- Cloudflare WAF event ingestion now has a real typed fetch path through `firewallEventsAdaptive` GraphQL discovery and a reporting chain through `internal/adapters/cloudflareevent`
- The daemon mode now runs an explicit context-bound Cloudflare WAF replay/reporting poller using the same local classifier and canonical AbuseIPDB formatter as the safety tests
- A unified outer-layer reporting service now exists in `internal/services/reporting` and drives:
  - pure normalized event classification
  - canonical AbuseIPDB comment generation
  - report/suppress decisions
  - telemetry publication
  - metrics emission
  - deduplication
- CrowdSec and OpenResty local WAF detections now have explicit adapters that enter the same shared reporting pipeline as Cloudflare replay events
- Better Stack now has a real HTTP sink behind `internal/telemetry/sinks` using the passive telemetry event model
- Prometheus emission for the unified security pipeline now remains in the outer telemetry/reporting layers only; domain packages remain metrics-free
- AbuseIPDB report deduplication is now enforced durably per IP over a sliding 24-hour window through `internal/security/reportdedup` plus SQLite-backed persistence in `internal/storage/sqlite`
- The common reporting service now persists successful AbuseIPDB report timestamps transactionally after successful upstream reports only, with an injectable clock and fail-closed store error handling by default
- CrowdSec live detections now enter the shared reporting pipeline from real `decisions.log` ingestion plus nginx URI correlation instead of tests/services only
- OpenResty live detections now enter the shared reporting pipeline from the real Lua JSONL event handoff file instead of tests/services only
- The Cloudflare WAF daemon poller now persists its `since` cursor durably in SQLite through `runtime_cursors`
- `internal/orchestrator/pipeline` has started decomposition into explicit discovery, snapshot, and planning stages while preserving orchestration behavior
- AbuseIPDB report and suppression decisions now persist replayable append-only evidence records through `internal/services/reporting` plus SQLite-backed `abuseipdb_reporting_evidence`
- The shared reporting pipeline now assigns evidence IDs to both sent and suppressed AbuseIPDB decisions and includes them in telemetry metadata
- Live-source fixture coverage is stronger for CrowdSec/OpenResty/Cloudflare sparse or malformed inputs, with safe skip behavior instead of guessed context
- `internal/orchestrator/pipeline` now also has explicit admission and translation stages, continuing the move toward orchestration-only flow control
- `internal/services/reporting` has now been split structurally into policy, dedup, evidence-recorder, and telemetry helper files without changing behavior
- The large `internal/services/reporting/service_test.go` suite has been decomposed into smaller thematic test files for policy, dedup, evidence, and telemetry behavior
- SQLite-backed reporting/security persistence is now grouped behind a small `ReportingStores` facade in `internal/storage/sqlite`, reducing composition-root wiring for dedup, evidence, and cursor stores
- `internal/orchestrator/pipeline` now also has explicit validation and completion stages, further shrinking the inline `DryRun` flow without changing behavior
- `internal/orchestrator/pipeline` now also has an explicit reporting stage for AbuseIPDB translation/reporting-side orchestration, keeping translation and reporting concerns distinct
- `internal/orchestrator/pipeline` now also has explicit normalization, execution, and telemetry leaf stages, further reducing the amount of inline flow control left in `DryRun` and `Rollback`
- `internal/app` now uses a small local WAF reporting runtime helper instead of wiring reporting service, sources, and per-tick processing inline inside `CrowdSecSyncApp.Run`
- `cmd/cf-sync` now uses small security/runtime wiring helpers for:
  - security telemetry sink construction
  - Cloudflare propagation guard configuration
  - Cloudflare WAF replay service construction
- `cmd/cf-sync` daemon mode now also uses dedicated helpers for:
  - API/auth/metrics server startup
  - daemon shutdown context wiring
  - Cloudflare WAF replay poller startup
- AbuseIPDB reporting evidence now carries richer forensic fields:
  - canonical decision
  - URI list
  - categories
  - idempotency/dedup keys
  - last/next report window timestamps
  - input hash
  - decision hash
  - normalized event payload
- `internal/storage/sqlite/reporting_evidence.go` now supports:
  - `Get`
  - filtered `Search`
  - paginated evidence retrieval for forensic workflows
- `cmd/cf-sync` now exposes evidence-oriented CLI flows through `-mode evidence`:
  - `list`
  - `search`
  - `show`
  - `explain`
- API v3 now exposes reporting evidence through:
  - `GET /api/v3/security/evidence`
  - `GET /api/v3/security/evidence/{evidence_id}`
  - `GET /api/v3/security/evidence/{evidence_id}/explain`
- A deterministic reporting replay verifier now exists in `internal/services/reporting/replay`
- The reporting replay verifier now also detects stored-version drift for:
  - classifier version
  - formatter version
  - reporting policy version
- The reporting pipeline now has targeted chaos-style coverage for:
  - evidence store write failure
  - cross-source recent-report suppression under the 24h rule
  - mixed Cloudflare WAF batches with malformed + valid events in the same replay window
- Runtime lifecycle reduction is now shared between live transitions and replay recovery through `internal/runtime/reducer`
- Live and replay state reconstruction now clear reconcile and rollback leases consistently on terminal transitions and distinguish `ActiveLease` from `ActiveRollbackLease`
- Lease persistence and anomaly detection are now scope-aware:
  - `LeaseStore` methods take `scope_id`
  - SQLite `leases` now carry `scope_id`
  - recovery orphan-lease detection is isolated per scope
- Event sequence allocation is now atomic and scope-local through SQLite-backed `event_sequences` instead of `MAX(sequence)+1`
- Scoped SQLite runtime DBs now force a single local writer connection and use bounded retry on `SQLITE_BUSY` during concurrent event append
- Runtime checkpoint checksums now cover the full canonical proof line:
  - `name`
  - `scope_id`
  - `sequence`
  - `event_id`
  - `state`
  - `metadata`
  - `schema_version`
  - canonical `created_at`
- Legacy leases with empty `scope_id` are now normalized transactionally to the active scoped runtime DB on first repository access instead of relying on a permanent fallback read path
- Lease persistence now has an explicit renew/heartbeat primitive through `LeaseStore.RenewLease` and the SQLite lease repository
- Cloudflare WAF replay cursor handling is now restart-safer:
  - overlap replay window
  - commit only after successful batch processing
  - no cursor advance on processing error
  - no cursor advance on save failure
  - corrupted cursor load falls back safely
- Cloudflare WAF processing now returns a high-watermark timestamp so cursor commits track processed event time instead of blind wall clock
- Local live CrowdSec and OpenResty reporting runtimes now keep stable source-specific processor instances over the same shared reporting service instead of recreating wrappers each loop
- Execution now has approval-workflow foundation primitives for high-impact mutations:
  - `approval_required`
  - `approval_id`
  - `approval_status`
  - `approval_expires_at`
  - `approved_by`
  - `approval_reason`
  - `awaiting_approval` operation state
- Governed execution now refuses batches or operations marked approval-required unless explicitly approved; the behavior is inert unless those flags are set
- Runtime events now carry durable `event_uid` idempotency keys with a scoped SQLite uniqueness constraint, so ambiguous append retries can resolve to an already-persisted event instead of allocating a new sequence
- SQLite event append no longer blindly retries after an ambiguous commit error; it first checks the scoped event UID and only treats the append as successful if the event is found
- The runtime `LeaseManager` can now use the scoped SQLite `LeaseStore` as the live lease authority for acquire/release/renew, with JSON runtime state acting as the state mirror when the store is wired
- `cmd/cf-sync` now wires the live `LeaseManager` to the scoped SQLite lease repository used by recovery/anomaly detection
- A context-bound HA lease heartbeat exists in `internal/runtime/coordination`, renewing active leases through the same persistent lease path and emitting a lost-lease signal after bounded renewal failures
- Cloudflare malformed WAF events observed through telemetry now also persist minimal reporting evidence when an evidence store is configured
- Approval evidence emission no longer duplicates the same op-level blocked transition in the append-only lineage
- The legacy app-level WAF reporting runtime now keeps its SQLite reporting DB open for the lifetime of the runtime instead of closing it immediately after configuring stores
- Runtime-path enforcement proof now exists in `internal/execution/executor_integration_test.go` with:
  - real `GovernedExecutor`
  - real `CloudflarePropagationGuard`
  - fake reputation checker
  - spy mutator
  - in-memory journal
  - fake Better Stack sink
- A permanent regression suite now exists in `internal/security/postmortem` for benign/bootstrap and exploit-pattern cases inspired by real false-positive risk
- Canonical AbuseIPDB comment formatting is now locked with exact golden tests in `internal/security/abuseformat`
- Deferred features remain stubbed intentionally behind TODO markers

## Completed tasks

- 2026-05-28T06:13:30+02:00 completed the priority hardening pass from the advanced review:
    - added durable scoped event idempotency through `event_uid`
    - added SQLite migration and schema verification for event idempotency keys
    - hardened event append so ambiguous commit errors resolve through existing event lookup instead of naive sequence reallocation
    - wired `cmd/cf-sync` live lease coordination to the scoped SQLite lease repository
    - extended `LeaseManager` with persistent acquire/release/renew support while preserving legacy JSON-only behavior when no lease store is configured
    - added context-bound lease heartbeat with cancellation and lost-lease signaling
    - persisted evidence for malformed Cloudflare WAF observations through the reporting evidence path
    - removed duplicate approval evidence emission on op-level blocked approval paths
    - fixed app-level WAF reporting store lifetime so dedup/evidence stores are not backed by a closed SQLite handle
    - added tests for event UID deduplication, persistent lease authority, heartbeat renewal/cancel, lost-lease signaling, and malformed-event evidence
    - revalidated `gofmt` and `go test ./...`

- 2026-05-28T00:05:00+02:00 completed the next runtime recovery correctness and operational hardening tranche:
    - removed the permanent legacy `scope_id=''` lease fallback by normalizing legacy rows to the active scoped DB on repository access
    - added explicit persisted lease renew/heartbeat semantics to the lease store and SQLite repository
    - hardened the Cloudflare WAF cursor lifecycle with overlap replay, high-watermark commits, and no-advance-on-error/save-failure behavior
    - added poller-focused tests for:
      - overlap cursor derivation
      - high-watermark cursor advancement
      - corrupted cursor fallback
      - no cursor advance on reporting failure
      - no cursor advance on cursor-save failure
    - finalized local live WAF wiring by keeping CrowdSec/OpenResty source processors bound to the same shared reporting service instance
    - added approval-workflow primitives to mutation batches/operations and blocked execution for approval-required work that is still pending or expired
    - added tests for lease renewal and approval-required execution blocking
    - revalidated `gofmt`, `go test`, `go test -race`, `go vet`, and `go build`

- 2026-05-27T18:05:00+02:00 completed the Brooks runtime recovery/storage/checkpoint hardening tranche:
    - added `internal/runtime/reducer` and rewired live `StateMachine` plus replay recovery to use the same lifecycle/event reduction rules
    - fixed terminal lease cleanup and rollback lease handling so live and replay produce the same `RuntimeState`
    - made `LeaseStore` scope-aware and migrated SQLite `leases` with `scope_id`
    - updated recovery orphan-lease detection to query by `(scope_id, action)` instead of global action only
    - replaced per-scope `MAX(sequence)+1` with atomic `event_sequences` allocation under transaction
    - added bounded retry for concurrent append `SQLITE_BUSY` and enforced a single writer connection per scoped SQLite runtime DB
    - expanded checkpoint checksums to canonical full-record coverage including event id, metadata, schema version, and timestamp
    - added tests proving:
      - live lifecycle transition equals replay-applied transition
      - terminal transitions clear reconcile and rollback leases
      - rollback transitions use `ActiveRollbackLease`
      - two scopes can hold the same action lease independently
      - orphan-lease detection ignores other scopes
      - concurrent append keeps continuous per-scope sequences without duplicates
      - checkpoint tampering on event id, metadata, schema version, or state is detected
    - revalidated `gofmt`, `go test`, `go test -race`, `go vet`, and `go build`

- 2026-05-27T15:05:00+02:00 completed the unified WAF event pipeline and real telemetry sink tranche:
    - added `internal/services/reporting` as the shared outer-layer reporting pipeline for normalized WAF events
    - wired Cloudflare WAF replay through `normalize -> classifier -> canonical formatter -> report decision -> telemetry`
    - added explicit CrowdSec and OpenResty event services so local detections can enter the same reporting chain
    - implemented a real Better Stack HTTP sink behind `internal/telemetry/sinks`
    - kept Prometheus emission in outer layers only and fixed suppression metrics to key off suppression reasons rather than raw propagation flags
    - added tests for:
      - Cloudflare malformed-event telemetry-only behavior
      - canonical cross-source AbuseIPDB comments
      - deduplicated report suppression
      - telemetry fail-open behavior
      - Better Stack sink JSON payload and timeout handling
      - Prometheus sink metrics emission
    - revalidated `gofmt`, `go test`, `go test -race`, `go vet`, and `go build`

- 2026-05-27T14:05:00+02:00 completed the Cloudflare WAF event branch into the local security pipeline:
    - implemented typed GraphQL `firewallEventsAdaptive` discovery in `internal/cloudflare`
    - added `internal/adapters/cloudflareevent.Service` to run `normalize -> classifier -> canonical AbuseIPDB comment -> reporting`
    - added trust-aware suppression, low-confidence suppression, deduplication, telemetry emission, and category-ID mapping for Cloudflare replay reports
    - wired the new service into `cmd/cf-sync` daemon mode as an explicit polling loop
    - added replay-driven tests for GraphQL WAF event fetching and Cloudflare replay reporting
    - revalidated `gofmt`, `go test`, `go test -race`, `go vet`, and `go build`

- 2026-05-27T13:10:00+02:00 completed the safety-enforcement-proof and security-slice-purification tranche:
    - introduced `internal/security/reputation` as the provider-agnostic pre-ban boundary
    - refactored `internal/adapters/abuseipdb` into a pure reputation adapter with TTL cache and timeout handling
    - removed metrics/provider coupling from `internal/security/risk`, `internal/security/classifier`, and `internal/security/abuseformat`
    - added `internal/telemetry/events` and `internal/telemetry/sinks` to move Prometheus/Better Stack emission out of the security domain
    - rewired `cmd/cf-sync` and `internal/execution` so Cloudflare propagation suppression is exercised through the real `GovernedExecutor -> SecurityGuard -> audit/telemetry` path
    - added executor integration tests proving suppression/allow behavior, audit persistence, telemetry emission, cache behavior, and mutator non-execution on denied mutations
    - added `internal/security/postmortem` regression coverage for Sonarr-like benign requests, bootstrap assets, WordPress probing, traversal, `.env`, and SQLi-style payloads
    - converted `internal/security/abuseformat` tests to exact-string golden coverage
    - revalidated `gofmt`, `go test`, `go test -race`, `go vet`, and `go build`

- 2026-05-21T15:00:00+02:00 implemented internal/storage/manager: Versioned SQL migration system and SQLite durability features (WAL checkpoints, Vacuum, VACUUM INTO for atomic snapshots)
- 2026-05-26T23:19:49+02:00 hardened `internal/runtime/events` and `internal/storage/sqlite` for the first production-hardening slice:
    - added explicit `PublishRequest` and checkpoint domain models
    - removed asynchronous hidden subscriber goroutines from the event bus
    - made SQLite event append assign scope-local sequences transactionally
    - added replay resume support from named checkpoints
    - added event/checkpoint tests and fixed the pre-existing `go vet` failure in metrics tests
    - fixed stateful scheduler pool shutdown so global tests complete cleanly
- 2026-05-26T23:43:38+02:00 completed the next logical runtime hardening tranche:
    - added typed runtime event constructors for lifecycle, lease, and fencing flows
    - added `internal/runtime/checkpoint` for automatic runtime-state checkpointing with checksum validation and retention
    - wired `engine.StateMachine` to publish lifecycle events and persist checkpoints on transitions
    - added checkpoint-aware recovery in `internal/runtime/recovery`
    - added SQLite degraded read-only guards and durability helpers (`VerifySchema`, `WALCheckpoint`, `ExportHotSnapshot`, `RotateBackups`, `QuarantineCorruption`)
    - validated `gofmt`, `go test`, `go test -race`, `go vet`, and `go build`
- 2026-05-27T00:02:36+02:00 extended the runtime forensic-consistency slice:
    - completed the missing typed runtime event catalog
    - added lineage-aware event metadata helpers and explicit causality-friendly event context
    - extended event replay with target sequence and target timestamp bounds
    - added recovery plans/manifests for bounded event recovery
    - added `internal/runtime/replay/consistency` verifier with deterministic continuity and divergence checks
    - revalidated `gofmt`, `go test`, `go test -race`, `go vet`, and `go build`
- 2026-05-27T00:21:00+02:00 completed the first safe Python 3.6.0 migration slice:
    - audited the live Python 3.6.0 codebase at `/home/jm/Documents/crowdsec-cf-sync`
    - created `docs/migration/python36-gap-analysis.md`
    - added versioned JSON contract schemas under `contracts/`
    - added parse/validate/event-emission adapters for OpenResty and Lua in `internal/adapters/`
    - added `make verify`
    - validated `gofmt`, `go test`, `go test -race`, `go vet`, `go build`, and `make verify`
- 2026-05-27T00:37:00+02:00 added the first false-positive resilience and safe-governance slice:
    - added `internal/security/confidence` for evidence-weighted decision scoring and review gating
    - added `internal/security/trust` with protected defaults for RFC1918, loopback, management-plane, monitoring, control-plane, and critical services such as Sonarr/Radarr
    - added `internal/security/blastradius` to block low-confidence cross-scope propagation and protected-target actions
    - updated `SECURITY_NOTES.md` to record the new safety-critical governance direction
    - validated `gofmt`, `go test`, `go test -race`, `go vet`, and `go build`
- 2026-05-27T01:02:00+02:00 completed the next migration-and-safety slice:
    - added `internal/compat/python36` to project legacy Python/OpenResty/Lua artifacts into Go contracts
    - extended `internal/adapters/openresty` and `internal/adapters/lua` with deterministic dry-run rendering and offline fixtures
    - added `internal/security/fp_memory` for temporal false-positive penalties
    - added `internal/security/classifier` for local replay classification of Cloudflare-style events and AbuseIPDB category mapping/comments
    - added `internal/adapters/abuseipdb` for pre-ban `check` gating with cache, metrics, evidence, and protected-target suppression
    - extended AbuseIPDB transport/models with `/check`
    - added optional mutation-time execution security guarding via `internal/execution/security_guard.go`
    - extended `internal/security/trust` with Cloudflare edge ranges to prevent absurd self-propagation paths
    - validated `gofmt`, `go test`, `go test -race`, `go vet`, and `go build`
- 2026-05-21T15:00:00+02:00 implemented internal/storage/manager: Versioned SQL migration system and SQLite durability features (WAL checkpoints, Vacuum, VACUUM INTO for atomic snapshots)
- 2026-05-21T14:00:00+02:00 implemented internal/policy/intent: Intent-Based Governance layer for declarative objectives (e.g. ModeParanoid, ModeAvailabilityFirst) and a predictive Simulation Engine to forecast mutation risks and budget pressure
- 2026-05-21T13:00:00+02:00 implemented internal/storage: Transactional persistence layer with scoped SQLite WAL backends (state/<scope_id>/runtime.db) and legacy FS compatibility
- 2026-05-21T04:00:00+02:00 implemented internal/runtime/scheduler: partition-aware multi-worker scheduler with bounded worker pool, priority queuing for rollbacks, and tenant-level budget management (concurrency quotas)
- 2026-05-20T23:00:00+02:00 implemented internal/runtime/convergence: state convergence correctness layer with post-apply verification, invariant checking (uniqueness, integrity), and oscillation detection
- 2026-05-20T22:00:00+02:00 implemented internal/runtime/coordination: execution leases and epochs for safe multi-owner orchestration, preventing overlapping runs and stale recovery validated with tests- 2026-05-20T21:00:00+02:00 implemented internal/policy: central governance engine with deterministic rule evaluation, admission control for mutation batches, and integrated approval workflow stubs
- 2026-05-20T21:00:00+02:00 extended internal/api: added audit exploration and quarantine management endpoints with scoped authentication (audit.read, quarantine.manage)
- 2026-05-20T20:00:00+02:00 implemented internal/rollback: governed rollback engine with compensation planning (Create -> Delete, Delete -> Restore), reverse execution order, and safety validation validated with tests
- 2026-05-20T19:00:00+02:00 implemented internal/execution: governed mutation engine with transactional batches, drift validation, ownership enforcement, and optimistic concurrency (ETags) support validated with tests
- 2026-05-20T10:45:00+02:00 implemented internal/reconciliation: serializable plans, deterministic diffing, and idempotent operation keys validated with tests- 2026-05-20T10:30:00+02:00 confirmed Go 1.22.2 compatibility and clean build/test status
- 2026-05-20T10:00:00+02:00 analyzed production Python scripts and mapped all responsibilities:
    - `crowdsec-cf-sync.py`: Main sync daemon (CF sync, AbuseIPDB, Recidivist, ModSec, CIDR ban, WAF poll)
    - `cloudflare-allowlist-update.py`: Allowlist sync (BetterStack, CF IPs)
    - `cloudflare-cleanup-ip-rules.py`: Cleanup (EasyCron preservation)
- 2026-05-19T23:05:06+02:00 created the Go module, Makefile, command layout, internal packages, env examples, and systemd examples
- 2026-05-19T23:05:06+02:00 added config loader, logger package, scheduler skeleton, app lifecycle wiring, and JSON state store
- 2026-05-19T23:05:06+02:00 added compile-safe placeholder implementations and initial unit-test skeletons
- 2026-05-19T23:05:06+02:00 validated `gofmt`, `go test`, `go vet`, and `go build` on Go 1.22.2
- 2026-05-19T23:15:08+02:00 added structured error wrapping, trace IDs, HTTP retry/backoff abstraction, scheduler timeout/non-overlap metrics, and race-focused state tests
- 2026-05-19T23:15:08+02:00 validated `gofmt`, `go test -race`, `go vet`, and `go build` on Go 1.22.2
- 2026-05-19T23:20:04+02:00 recorded Cloudflare-specific implementation rules: read-only first, dry-run before writes, isolated schemas, explicit pagination, rate-limit handling, and fixture-based testing
- 2026-05-19T23:24:54+02:00 tightened Cloudflare constraints: fixture capture tooling first, automatic sanitization, strict JSON decoding, debug-gated request/response logs, and small resource-specific models
- 2026-05-19T23:27:43+02:00 added fixture-tooling requirements: raw and sanitized storage, metadata capture, pagination sequence capture, deterministic replay, schema drift tests, and fixture expiration tracking
- 2026-05-19T23:30:28+02:00 added fixture architecture rules: separated raw/sanitized/replay metadata, irreversible sanitization, corruption checks, checksum validation, latency hooks, and parallel-safe replay
- 2026-05-19T23:31:11+02:00 elevated replay failure simulation priority for Cloudflare: 429s, timeouts, incomplete pagination, and transient upstream errors
- 2026-05-19T23:32:09+02:00 enforced layering rule: no business reconciliation logic inside API transport layers
- 2026-05-19T23:36:39+02:00 added reconciliation safety rules: idempotent behavior, explicit planning, dry-run diffs, replayable reconciliation fixtures, and duplicate-mutation protection
- 2026-05-19T23:41:13+02:00 added reconciliation durability rules: serializable plans, persistable snapshots, restart-safe progress, operation IDs, execution journaling, and mutation provenance metadata
- 2026-05-19T23:43:56+02:00 added mutation execution safety rules: transactional grouping, resumable batches, mutation state machine, stale-plan checks, confirmation gates, and audit snapshots
- 2026-05-19T23:46:32+02:00 added operational safety rules: global kill switch, emergency read-only mode, mutation-count/rate limits, circuit breaker, degraded/quarantine modes, and mandatory structured audit logging
- 2026-05-19T23:58:45+02:00 implemented `internal/snapshot`: versioned immutable snapshots, deterministic normalization from raw JSON, stable checksums, and ordering-stability tests
- 2026-05-19T23:58:45+02:00 implemented generic fixture capture in `internal/snapshot`: raw/sanitized artifact separation, deterministic fixture IDs, stable hashes, and offline tests
- 2026-05-19T23:58:45+02:00 implemented generic replay engine in `internal/snapshot`: deterministic replay ordering, artifact integrity checks, latency hooks, timeout simulation, and sanitized-only replay responses

## Pending tasks

- Implement typed Cloudflare HTTP client logic with retries, pagination, and timeouts
- Implement Cloudflare client in read-only mode before any mutation path
- Implement Cloudflare fixture capture and sanitization tooling before live API usage
- Implement deterministic fixture replay and schema drift detection before live API usage
- Implement replay metadata, integrity validation, and corruption checks before live API usage
- Design reconciliation planning and execution as separate phases before any write path exists
- Design reconciliation persistence, resume-after-failure behavior, and execution journaling before any write path exists
- Design mutation executor state machine and batch recovery behavior before any write path exists
- Design execution governance controls before any write path exists
- Implement typed CrowdSec integration layer around `cscli` and log readers
- Implement allowlist sync behavior from the Python source of truth
- Implement cleanup behavior with keep-note compatibility
- Implement CrowdSec-to-Cloudflare sync behavior
- Implement AbuseIPDB reporting behavior and deduplication
- Implement recidivist escalation logic and state transitions
- Implement ModSecurity parsing and temporary-ban workflow
- Implement CIDR auto-ban logic
- Add `internal/compat/python36` readers to project legacy Python/OpenResty/Lua inputs into the new versioned contracts
- Continue thinning `internal/orchestrator/pipeline` with explicit normalization, reporting, execution, and telemetry stages
- Continue reducing composition-root wiring in `cmd/cf-sync` and `internal/app` through small, slice-specific facades/builders
- Extend adapters beyond parse/validate into dry-run rendering and compatibility testing for OpenResty/Lua
- Integrate false-positive resilience decisions into enforcement planning, Cloudflare propagation, and operator review flows
- Add explicit false-positive memory and replayable security explanation APIs
- Wire the new execution security guard into real app/orchestrator construction paths so Cloudflare mutations are actually gated at runtime
- Route local CrowdSec/OpenResty detections through the same classifier/comment/reporting chain before AbuseIPDB reporting
- Integrate local CrowdSec/OpenResty adapters into live detection sources, not only shared services/tests
- Persist the Cloudflare WAF poller cursor (`since`) durably across daemon restarts
- Expand the live-source path with stronger fixture coverage and replayable evidence persistence for successful/suppressed AbuseIPDB decisions
- Continue thinning `internal/orchestrator/pipeline` into explicit stages beyond discovery/snapshot/planning
- Persist or expose query/read paths for the new `abuseipdb_reporting_evidence` records if operator forensic workflows need direct retrieval
- Continue decomposing `internal/orchestrator/pipeline` with explicit execution/reporting/telemetry stages
- Expand tests beyond skeleton coverage into parity and fixture-driven validation

## Current blockers

- No functional blocker for the next replay-consistency or recovery-expansion slice
- The main remaining work is implementation depth and integration, not environment failure
- Production parity still requires fixture capture and side-by-side validation before enabling writes
- External integrations must be verified against official documentation before implementation
- Point-in-time recovery still lacks full SQLite snapshot restore orchestration tied to the scoped DB lifecycle
- Replay consistency checks do not yet validate policy bundle lineage, evidence cryptographic chains, or rollback ancestry
- Chaos, soak, corruption, and HA recovery drills are still mostly unimplemented
- Python 3.6.0 compatibility is now audited, but no compatibility reader exists yet for generated nginx snippets, Lua runtime constants, or Python env projections
- False-positive resilience is now wired into the governed Cloudflare execution path, but approval workflows and quarantine/shadow modes are still pending
- Cloudflare WAF events now enter the local classifier through a real GraphQL discovery path, but the poller state (`since`) is not yet durably persisted across restarts
- Better Stack now has a concrete HTTP sink and test coverage, but the broader operator dashboards and richer sink retry/batching policies remain minimal
- CrowdSec/OpenResty now share the same reporting pipeline structurally, but the live upstream source wiring for those local detections is still incomplete
- Cloudflare mutation paths must stay disabled or dry-run until parity validation is complete
- Live Cloudflare API usage should follow fixture replay tests, not precede them
- Replay tests must remain fully offline and must never mix in live API calls
- Replay architecture must support deterministic ordering and parallel-safe execution
- Replay coverage must explicitly include Cloudflare’s common operational failure modes
- Reconciliation must remain idempotent across retries, scheduler reruns, and transient failures
- Reconciliation retries must not regenerate materially different plans unexpectedly
- Overlapping reconciliation plans must not execute concurrently
- Execution must fail closed under kill-switch, excessive drift, or quarantine conditions

## Important technical decisions

- Python scripts remain untouched and remain the production source of truth
- Go baseline is `1.22.2` for compatibility with standard Ubuntu server environments
- Standard library is preferred; no third-party framework has been introduced
- JSON state files are retained for phase 1 compatibility; SQLite is deferred
- SQLite is now active for scoped runtime/event persistence while JSON compatibility remains in the codebase for earlier migration layers
- Long-running behavior is mediated through `context.Context` and a scheduler abstraction
- External API models must be verified from official docs and kept isolated inside their integration packages
- Cloudflare transport, schemas, business logic, and reconciliation logic must remain separated
- API transport layers must remain free of business reconciliation behavior
- Reconciliation state must not be coupled directly to transport response shapes
- Reconciliation runs need durable operation IDs and traceable execution history
- Mutation execution requires deterministic identity keys, stale-plan checks, and before/after audit snapshots
- Operational execution requires kill-switch control, safety thresholds, circuit breaking, and operator-visible health summaries
- Cloudflare logging must never expose tokens, account IDs, or zone secrets
- Sanitized fixtures must be immutable and versioned by endpoint/resource type
- Raw fixtures must remain distinct from replayable sanitized fixtures
- Placeholder services compile but do not implement write-side production behavior yet
- Lifecycle transitions now produce runtime checkpoints automatically when the state machine is wired with an event bus and checkpoint manager
- OpenResty and Lua were introduced first as contract adapters rather than runtime extensions to preserve the rule that edge-specific logic stays out of the FSM
- The control-plane now explicitly treats false positives as a safety-critical distributed-governance problem, with a design bias toward under-blocking instead of catastrophic over-blocking
- AbuseIPDB pre-ban checks are now modeled as a separate safety gate, not as part of direct reporting logic
- Legacy Python/OpenResty/Lua formats are now projected through compat readers into contracts instead of being pulled directly into runtime layers

## Files created

- `go.mod`
- `Makefile`
- `README.md`
- `ACCURACY_POLICY.md`
- `ARCHITECTURE.md`
- `MIGRATION_PLAN.md`
- `SECURITY_NOTES.md`
- `TESTING.md`
- `COMPATIBILITY_CHECKLIST.md`
- `RISK_ANALYSIS.md`
- `cmd/crowdsec-sync/main.go`
- `cmd/cf-allowlist-sync/main.go`
- `cmd/cf-cleanup/main.go`
- `internal/apperr/*`
- `internal/config/*`
- `internal/httpclient/*`
- `internal/logging/*`
- `internal/scheduler/*`
- `internal/state/*`
- `internal/cloudflare/*`
- `internal/crowdsec/*`
- `internal/abuseipdb/*`
- `internal/betterstack/*`
- `internal/modsecurity/*`
- `internal/recidive/*`
- `internal/cidrban/*`
- `internal/app/*`
- `internal/snapshot/*`
- `pkg/configs/*.env.example`
- `deployments/systemd/*`
- `scripts/build-static.sh`
- `docs/migration/python36-gap-analysis.md`
- `contracts/*.schema.json`
- `internal/adapters/openresty/*`
- `internal/adapters/lua/*`
- `internal/security/confidence/*`
- `internal/security/trust/*`
- `internal/security/blastradius/*`
- `internal/compat/python36/*`
- `internal/adapters/abuseipdb/*`
- `internal/security/fp_memory/*`
- `internal/security/classifier/*`

## Files modified

- `go.mod`
- `README.md`
- `internal/app/app.go`
- `internal/logging/logger.go`
- `internal/scheduler/scheduler.go`
- `internal/scheduler/scheduler_test.go`
- `internal/state/json_store.go`
- `internal/state/json_store_test.go`
- `internal/cloudflare/client.go`
- `internal/abuseipdb/client.go`
- `internal/betterstack/client.go`
- `internal/snapshot/snapshot.go`
- `internal/snapshot/builder.go`
- `internal/snapshot/snapshot_test.go`
- `internal/snapshot/fixture.go`
- `internal/snapshot/fixture_test.go`
- `internal/snapshot/replay.go`
- `internal/snapshot/replay_test.go`
- `Makefile`
- `SECURITY_NOTES.md`
- `internal/abuseipdb/models/models.go`
- `internal/abuseipdb/transport/transport.go`
- `internal/observability/metrics/metrics.go`
- `internal/execution/executor.go`
- `internal/execution/security_guard.go`

## Remaining migration steps

1. Inject `CloudflarePropagationGuard` into the real governed executor wiring in app/orchestrator construction.
2. Route Cloudflare WAF discovery/replay events through `internal/security/classifier` before AbuseIPDB report generation.
3. Add Better Stack emission and API explain surfaces for suppressed pre-ban events and replay classifications.
4. Add operator approval gates, shadow propagation, and canary-scope handling on top of the current guard.
5. Add full SQLite point-in-time recovery orchestration that combines hot snapshot selection with bounded event replay and scoped DB reopen semantics.
6. Extend replay consistency into checksum chains, evidence integrity checks, policy bundle lineage, and rollback ancestry verification.
7. Add corruption drills, degraded-mode recovery scenarios, stale-fencing cleanup tests, and false-positive chaos scenarios.
8. Add chaos and soak harnesses for replay interruption, WAL contention, split-brain recovery, and goroutine leak detection.
5. Continue Cloudflare/CrowdSec parity work only through replay-safe, deterministic slices.

## Known risks

- Behavioral drift from the monolithic Python daemon when decomposed into Go services
- State compatibility drift for JSON timestamp and deduplication semantics
- IPv6 normalization differences causing duplicate Cloudflare rule churn
- Cleanup logic becoming broader than the current `easycron` preservation rule
- Local environment assumptions around `cscli`, log paths, and permissions

## Next recommended actions

- Start with `internal/cloudflare` implementation and tests
- Keep API schemas isolated per integration package; do not leak Cloudflare JSON models outside `internal/cloudflare`
- Keep reconciliation logic above transport clients; transport should only handle HTTP, auth, pagination, headers, and schema decoding
- Introduce explicit reconciliation plan types before any mutation execution code
- Define serializable plan, snapshot, progress, and journal formats before execution logic
- Define mutation batch state machine, confirmation gate, drift threshold, and rollback handling before execution logic
- Define kill-switch, emergency mode, circuit breaker, rate limit, and quarantine behavior before execution logic
- Implement Cloudflare fixture capture tooling first, then sanitized fixture replay tests, then read-only endpoints
- Capture raw plus sanitized fixtures with metadata, pagination sequence, and expiration markers
- Add replay integrity hashes, corruption detection, schema versions, and latency simulation hooks
- Model 429s, timeouts, incomplete pagination, and transient failure sequences early in fixture replay design
- Prefer small resource-specific Cloudflare models; avoid giant shared response structs
- Implement `cf-allowlist-sync` end-to-end first behind exact parity tests
- Add dry-run flags before any destructive or write-side implementation
- Verify official docs before implementing any external endpoint or field

## Compilation status

- Status: clean on Go 1.22.2 after the runtime event-sourcing hardening slice
- Status: clean on Go 1.22.2 after runtime typed events, automatic checkpointing, event-sourced recovery, and SQLite hardening tranche
- Status: clean on Go 1.22.2 after bounded event recovery and replay consistency verification tranche
- `gofmt -w .`: success
- `go test ./...`: success
- `go test -race ./...`: success
- `go vet ./...`: success
- `go build ./...`: success

## Latest successful commands

- `GOTOOLCHAIN=local gofmt -w .`
- `GOTOOLCHAIN=local go test ./...`
- `GOTOOLCHAIN=local go test -race ./...`
- `GOTOOLCHAIN=local go vet ./...`
- `GOTOOLCHAIN=local go build ./...`

## Current project tree summary

- root docs: `README.md`, `ACCURACY_POLICY.md`, `ARCHITECTURE.md`, `MIGRATION_PLAN.md`, `SECURITY_NOTES.md`, `TESTING.md`, `COMPATIBILITY_CHECKLIST.md`, `RISK_ANALYSIS.md`
- commands: `cmd/crowdsec-sync`, `cmd/cf-allowlist-sync`, `cmd/cf-cleanup`
- internal packages: `abuseipdb`, `app`, `apperr`, `betterstack`, `cidrban`, `cloudflare`, `config`, `crowdsec`, `httpclient`, `logging`, `modsecurity`, `recidive`, `scheduler`, `snapshot`, `state`, `utils`
- deployment assets: `deployments/systemd/*`
- environment examples: `pkg/configs/*.env.example`
- helper script: `scripts/build-static.sh`

## Context and handoff note

- Estimated context budget remaining: moderate and safe for checkpointing, not for a large new integration implementation.
- This checkpoint is documentation-only; compilation status remains the same as the last validated Go milestone.
- The newest validated code addition is the pure `internal/snapshot` package; validation remained clean after its introduction.
- Next Cloudflare implementation session should begin with verified docs plus fixture capture tooling, not transport mutation code.
- Next Cloudflare implementation session should define the fixture format and sanitization contract before writing live transport code.
- Next Cloudflare implementation session should also define replay metadata, checksum strategy, and parallel-safe replay semantics.
- Next Cloudflare implementation session should explicitly encode 429, timeout, and incomplete-pagination replay scenarios.
- Next write-capable design session should define reconciliation plan objects, dry-run output format, and duplicate-mutation protections before execution logic.
- Next write-capable design session should also define persisted snapshot format, plan serialization, operation IDs, resume semantics, and execution journal schema.
- Next write-capable design session should also define mutation identity keys, executor state machine transitions, stale-plan detection, and batch audit snapshot format.
- Next execution-governance design session should define kill-switch controls, mutation-rate/count limits, degraded/quarantine modes, and structured audit event schema.
- Do not begin a large refactor in the next session before updating this file after each validated step.
## 2026-05-27T00:52:34+02:00

### Current architecture state

- Anti-false-positive protections are now partially wired into the real Cloudflare mutation path.
- `cmd/cf-sync` now builds a real AbuseIPDB pre-ban checker and injects `CloudflarePropagationGuard` into `GovernedExecutor`.
- Browser bootstrap baseline learning exists in `internal/security/baseline` and is consumed by the progressive risk engine.
- Canonical AbuseIPDB comment generation is shared through `internal/security/abuseformat`.
- Local safety coverage now includes baseline bootstrap, guarded propagation, and canonical comment generation tests.

### Completed tasks

- Added `internal/security/baseline` for benign browser bootstrap detection.
- Extended `internal/security/risk` with:
  - `benign_bootstrap`
  - baseline-aware observe-only handling
  - stronger `.env` / sensitive extension scoring
  - progressive safety metrics
- Wired AbuseIPDB-specific config into `internal/config`.
- Wired real pre-ban guard construction into `cmd/cf-sync`.
- Extended `CloudflarePropagationGuard` to protect:
  - `ip_access_rules`
  - `list_items`
  - `ruleset_rules`
  - `rulesets`
- Switched AbuseIPDB translation comments to the canonical formatter.
- Added `internal/security/safety` regression tests.

### Pending tasks

- Feed real Cloudflare WAF events from the Cloudflare client into the local classifier before reporting.
- Route local CrowdSec/OpenResty detections through the same classifier path before AbuseIPDB reporting.
- Add Better Stack event builder/wiring for suppressed, benign, and propagated decisions.
- Persist replayable evidence objects for guard suppressions and classifier suppressions beyond current metrics/journal coverage.
- Add explicit approval-gate and shadow-propagation layers above the now-guarded write path.

### Current blockers

- Better Stack now has a real sink, but event shaping and retention policy are still evolving and not yet backed by durable replay evidence storage.
- CrowdSec live correlation currently depends on nginx log availability and may skip otherwise reportable bans when no safe URI context can be reconstructed.
- Cloudflare WAF live discovery/replay remains partially modeled; provider models still need richer WAF event fields for production replay.

### Important technical decisions

- Baseline-only browser bootstrap traffic must always stay `observe_only`.
- No Cloudflare mutation path should bypass trust checks plus AbuseIPDB pre-ban evaluation once it reaches `GovernedExecutor`.
- Canonical AbuseIPDB comments must be generated through one formatter module, even when local translation data is sparse.
- Guarded ruleset/rules mutations without derivable target IPs are suppressed instead of guessed.

### Files created

- `internal/adapters/crowdsecevent/live.go`
- `internal/adapters/crowdsecevent/live_test.go`
- `internal/adapters/openrestyevent/live.go`
- `internal/adapters/openrestyevent/live_test.go`
- `internal/security/reportdedup/store.go`
- `internal/storage/sqlite/cursor_store.go`
- `internal/storage/sqlite/report_dedup.go`
- `internal/storage/sqlite/report_dedup_test.go`
- `internal/storage/sqlite/reporting_evidence.go`
- `internal/storage/sqlite/reporting_evidence_test.go`
- `internal/orchestrator/pipeline/stage_discovery.go`
- `internal/orchestrator/pipeline/stage_snapshot.go`
- `internal/orchestrator/pipeline/stage_planning.go`
- `internal/orchestrator/pipeline/stage_admission.go`
- `internal/orchestrator/pipeline/stage_translation.go`
- `internal/services/reporting/evidence.go`

### Files modified

- `cmd/cf-sync/main.go`
- `internal/app/app.go`
- `internal/config/config.go`
- `internal/observability/metrics/metrics.go`
- `internal/services/reporting/service.go`
- `internal/services/reporting/service_test.go`
- `internal/storage/sqlite/db.go`
- `internal/cloudflare/waf_events_test.go`
- `internal/adapters/crowdsecevent/live_test.go`
- `internal/adapters/openrestyevent/live_test.go`
- `internal/telemetry/sinks/prometheus.go`
- `internal/telemetry/sinks/sinks.go`
- `internal/orchestrator/pipeline/orchestrator.go`

### Remaining migration steps

1. Add direct read/query support and higher-level forensic consumption for `abuseipdb_reporting_evidence`.
2. Continue decomposing `internal/orchestrator/pipeline` with explicit normalization, reporting, execution, and telemetry stages.
3. Add broader chaos and soak coverage for the guarded mutation path.
4. Harden cursor lifecycle semantics for Cloudflare WAF polling under crash/restart scenarios.

### Known risks

- Ruleset-based Cloudflare mutations are now fail-safe if target IP extraction is impossible; this is safe but can suppress valid broad rules until explicit handling is added.
- The 24-hour AbuseIPDB per-IP dedup rule is now durable and cross-source, but incorrect clock assumptions or store outages default to suppression and can reduce reporting during degraded periods.
- CrowdSec live detection quality depends on reconstructable nginx URI context; missing logs intentionally bias toward under-reporting rather than guessed context.
- AbuseIPDB canonical comments for translator-driven local detections still rely on heuristic URI/source reconstruction when raw request context is unavailable.

### Next recommended actions

1. Persist replay evidence for report/suppress decisions alongside the new durable AbuseIPDB dedup state.
2. Extend live CrowdSec/OpenResty ingestion with more source-specific fixtures and malformed-input coverage.
3. Continue thinning `internal/orchestrator/pipeline` into explicit normalization/reporting/execution stages.

### Compilation status

- Clean on Go 1.22.2 after durable 24-hour AbuseIPDB report deduplication, live CrowdSec/OpenResty wiring, Cloudflare WAF cursor persistence, and initial orchestrator stage extraction.

### Latest successful commands

- `GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')`
- `GOTOOLCHAIN=local go test ./...`
- `GOTOOLCHAIN=local go test -race ./...`
- `GOTOOLCHAIN=local go vet ./...`
- `GOTOOLCHAIN=local go build ./...`

### Current project tree summary

- `cmd/cf-sync`: now constructs the real pre-ban guard
- `internal/services/reporting`: shared WAF report/suppress orchestration plus durable 24h per-IP AbuseIPDB dedup
- `internal/security/reportdedup`: provider-agnostic dedup store boundary
- `internal/storage/sqlite/report_dedup.go`: persistent 24h per-IP AbuseIPDB dedup store
- `internal/storage/sqlite/cursor_store.go`: durable runtime cursor persistence
- `internal/adapters/crowdsecevent/live.go`: live CrowdSec decisions.log ingestion with nginx URI correlation
- `internal/adapters/openrestyevent/live.go`: live OpenResty Lua JSONL event ingestion
- `internal/services/reporting/evidence.go`: replayable evidence model and store boundary for report/suppress decisions
- `internal/storage/sqlite/reporting_evidence.go`: durable append-only reporting evidence store
- `internal/security/baseline`: benign asset learning
- `internal/security/risk`: progressive scoring and bootstrap suppression
- `internal/security/abuseformat`: canonical AbuseIPDB comment formatting
- `internal/security/safety`: focused anti-false-positive regression tests
- `internal/adapters/abuseipdb`: pre-ban checker with TTL cache and failure policy

## 2026-05-28T-current+02:00

### Completed

- Enforced per-operation fencing tokens before guarded provider mutations in `GovernedExecutor`.
- Extended rollback compensation execution with the same fencing validator so stale rollback leases cannot mutate Cloudflare.
- Added lease/fencing metadata propagation from rollback planning into compensation operations.
- Added a bounded, context-bound AbuseIPDB report outbox worker with retry metadata and no hidden goroutine requirement.
- Persisted retryable AbuseIPDB report payloads in the SQLite outbox (`report_json`, attempts, last error, next attempt).
- Wired the local app WAF runtime to process eligible outbox retries once per scheduler tick.
- Extracted reporting decision preparation from `Service.Process` into a smaller classification/comment/telemetry stage.

### Remaining

- Forward live reconciliation writes should use the same lease-bound context pattern when that path starts executing real provider writes.
- The outbox worker is explicitly tick-driven; long-running deployments may later choose a supervised `Run(ctx)` loop, but the current integration avoids hidden goroutines.
- Reporting decomposition can continue by extracting reservation/dedup and evidence/telemetry collaborators.

### Follow-up hardening completed

- Added `internal/rollback/executor/executor_test.go` to prove stale fencing tokens in rollback path refuse compensation mutations and skip mutators.
- Extracted orchestrator lease heartbeat/cancel logic into `internal/orchestrator/pipeline/lease_bound.go` and rewired rollback through it, preparing the same pattern for forward write-path activation.
- Continued reporting refactor by extracting strict reporting attempt flow into `internal/services/reporting/report_attempt.go` (`prepare`, `reserve+pending`, `upstream execute`).

### Runtime correctness hardening (new)

- Reworked SQLite error classification to rely on typed SQLite driver codes only (no runtime `string.Contains` checks in critical paths).
- Moved legacy lease scope normalization into migration/bootstrap phase (`migration v12`), removing it from DB initialization hot-path logic.
- Hardened lease renewal contract with epoch lineage validation (`scope + owner + epoch + fencing token` must all match).
- Added lease renewal test coverage for epoch mismatch rejection.
