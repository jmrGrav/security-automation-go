# DECISIONS

## 2026-05-29T15:20:00+02:00 - Ownership claim store should be runtime authority when configured

Decision:

- Add an optional `ClaimStore` boundary to `runtime/ownership.Resolver`.
- When configured, `Resolve` reads the current claim from store and treats it as authority.
- `Claim` persists to store first, then updates in-memory cache.
- cf-sync runtime wiring configures resolver claim store to SQLite `OwnershipRepository`.

Reason:

- Memory-only claims can drift after restart and break ownership consistency guarantees.
- Durable store authority closes restart drift risk without a broad rewrite.

Impact:

- Ownership decisions remain consistent across process restarts.
- In-memory claim cache is now a mirror/optimization, not the source of truth.

## 2026-05-29T15:20:00+02:00 - AbuseIPDB outbox worker may be lease-bound optionally

Decision:

- Add optional `OutboxLeaseGuard` to `services/reporting.OutboxWorker`.
- If configured and guard refuses an item, the worker skips upstream reporting for that item and emits evidence/telemetry.
- Default behavior remains unchanged when no guard is configured.

Reason:

- Reporting paths may need leadership/lease coupling in HA deployments, but this must be opt-in to avoid changing existing retry behavior.

Impact:

- Enables safe lease-bound execution for outbox retries where required.
- Preserves current retry semantics for existing deployments.

## 2026-05-29T14:10:00+02:00 - Production mutation paths should require explicit fencing metadata

Decision:

- Extend `LeaseStoreFencingValidator` with strict mode (`RequireFencing(true)`).
- Enable strict fencing in cf-sync wiring for governed mutation execution and rollback execution.
- In strict mode, scoped mutations must include `scope_id`, `lease_id`, and `fencing_token`; missing metadata is rejected before mutator calls.

Reason:

- Without strict metadata requirements, stale or unbound mutation paths can accidentally bypass leadership/fencing guarantees.
- The no-big-rewrite fix is to tighten validator semantics and production wiring, not redesign the orchestration model.

Impact:

- Fencing propagation is fail-closed on production write paths.
- Leader races where active lease changes mid-batch are now explicitly tested and stop remaining mutations.

## 2026-05-29T13:05:00+02:00 - Rollback execution progress must be durable and resumable

Decision:

- Add a dedicated durable rollback checkpoint store in SQLite (`rollback_checkpoints`).
- Persist rollback batch progress at:
  - start
  - each completed compensation operation
  - failure
  - completion
- Reload rollback checkpoints by `batch_id` before execution and resume from persisted `last_completed_op_idx`.
- If persisted checkpoint is already `completed` with all operations done, short-circuit without re-executing provider mutations.

Reason:

- In-memory rollback progress is insufficient after crash/restart and leaves compensation safety dependent on process continuity.
- The minimum safe change is durable progress persistence with idempotent resume, not a full rollback orchestration rewrite.

Impact:

- Recovery/restart can resume rollback batches deterministically from persisted progress.
- Duplicate compensation calls are reduced because completed batches are recognized and skipped.
- Existing rollback runtime semantics remain unchanged except for added durability and restart behavior.

## 2026-05-29T10:55:00+02:00 - Ownership lineage pagination should be cursor-based for forensic scale

Decision:

- Keep ownership lineage API response payload as a list (no envelope change), and add cursor pagination via request query params plus response headers.
- Use deterministic cursor ordering on `(created_at DESC, id DESC)`.
- Support CLI cursor navigation with `before_created_at` + `before_id`.

Reason:

- Offset-based pagination becomes unstable and expensive under sustained append volume.
- Cursor pagination preserves chronological forensic browsing without breaking existing clients expecting list payloads.

Impact:

- Existing semantics remain backward-compatible.
- High-volume ownership lineage browsing is more stable and predictable.

## 2026-05-29T10:25:00+02:00 - Ownership lineage must be queryable and explainable as first-class forensic evidence

Decision:

- Expose ownership lineage through CLI and API v3 list/get/explain surfaces.
- Keep lineage read paths directly backed by durable SQLite append-only records.
- Validate ownership divergence behavior under multi-scope restart/replay via deterministic tests.

Reason:

- Durable lineage without a direct query/explain path leaves forensic triage incomplete.
- Multi-scope replay/restart tests are required to prove scope isolation and deterministic divergence signaling.

Impact:

- Operators can inspect ownership governance history by scope/resource/event id without touching raw tables.
- Recovery divergence diagnostics now have stronger regression coverage for restart scenarios.

## 2026-05-29T09:40:00+02:00 - Ownership authority must have durable lineage and recovery invariants

Decision:

- Persist ownership lineage as append-only records in SQLite (`ownership_lineage`).
- Emit lineage events from ownership resolution and claim paths.
- Validate ownership claim/lineage coherence during recovery and fail closed on violations.

Reason:

- Ownership decisions are part of governance evidence; claim-only snapshots are insufficient for forensic replay and anomaly triage.
- Recovery must reject ambiguous ownership states to keep deterministic safety guarantees.

Impact:

- Durable, queryable ownership ancestry now exists.
- Recovery reports now include ownership invariant violations and issue details.
- Runtime wiring in `cmd/cf-sync` records lineage without introducing a broad refactor.

## 2026-05-28T20:25:00+02:00 - AbuseIPDB outbox reservations must be idempotent and expirable

Decision:

- A pending AbuseIPDB reservation with the same `idempotency_key` is treated as idempotent.
- A fresh pending reservation for the same IP blocks a different report attempt.
- An expired pending reservation is marked `failed` before a new reservation for the same IP can be accepted.
- Updating an outbox row status must fail if no row is actually updated.

Reason:

- A durable reservation prevents duplicate upstream reports, but a crash or abandoned pending row must not become a permanent unexplained suppression.

Impact:

- The outbox now preserves at-most-one active same-IP report path while still allowing deterministic recovery from stale pending rows.
- Operators can distinguish active suppression, expired pending recovery, and missing outbox lineage.

## 2026-05-28T18:10:00+02:00 - Ambiguous runtime event commits must be explicit

Decision:

- Runtime event append returns `sqlite.ErrCommitAmbiguous` if `Commit()` fails and the event cannot be found by `(scope_id, event_uid)`.

Reason:

- Treating an ambiguous commit as a transient retry risks duplicate logical events or replay divergence. The safe behavior is idempotent success only when the durable row exists, otherwise an explicit critical error.

Impact:

- Callers and tests can distinguish commit ambiguity from duplicate idempotent append and normal transient failures.

## 2026-05-28T18:10:00+02:00 - Lost lease must cancel mutation context

Decision:

- Provider mutators may implement context-aware execution.
- Rollback execution binds its context to the HA heartbeat and cancels with a lost-lease cause when renewal fails.
- Execution records `lost_lease_mutation_aborted` when a batch or operation stops because the context was cancelled.

Reason:

- A heartbeat signal alone does not prevent zombie provider mutations. Cancellation must reach the execution path and provider call boundary.

Impact:

- Long Cloudflare mutations can now observe cancellation.
- Partial execution is auditable and flagged for recovery.

## 2026-05-28T18:10:00+02:00 - AbuseIPDB reports require durable reservation before upstream call

Decision:

- When the SQLite reporting stores are configured, AbuseIPDB reporting reserves a durable outbox row and persists `report_pending` evidence before calling the upstream API.
- Reservation failure or pending-evidence failure suppresses the upstream report.

Reason:

- A successful upstream report without durable evidence or anti-flood state breaks forensic guarantees and can lead to duplicate reports after restart.

Impact:

- The operational guarantee is at-least-once source ingest with at-most-one pending/upstream AbuseIPDB report path per IP reservation, plus durable 24h report dedup after success.

## 2026-05-28T18:10:00+02:00 - Reporting evidence search must use SQL-projected fields

Decision:

- Project `decision` and `abuse_type` into `abuseipdb_reporting_evidence` and index common forensic filters.

Reason:

- Filtering large evidence sets in memory makes CLI/API forensic queries unstable under append volume.

Impact:

- IP/source/decision/suppression/date searches can remain stable as evidence volume grows.

## 2026-05-28T06:13:30+02:00 - Runtime event append should use scoped idempotency keys for commit ambiguity

Decision:

- Add `event_uid` to runtime events and enforce scoped uniqueness in SQLite.
- Resolve duplicate or ambiguous appends by looking up the existing `(scope_id, event_uid)` row instead of allocating a new sequence.

Reason:

- Retrying a full append after a commit error assumes the commit definitely failed. That assumption is too weak for an event-sourced runtime where sequence identity is forensic evidence.

Impact:

- Event append is safer under ambiguous commit outcomes.
- Legitimate duplicate append attempts converge on the original event id/sequence.
- Callers can provide a stable UID explicitly, while legacy callers receive an automatically derived UID.

## 2026-05-28T06:13:30+02:00 - Live lease coordination should use the same scoped lease store seen by recovery

Decision:

- Wire `LeaseManager` to the scoped SQLite `LeaseStore` in `cmd/cf-sync`.
- Keep JSON runtime state as the live state mirror, but use the persistent scoped lease store as the lease authority when configured.

Reason:

- Recovery and anomaly detection already inspect SQLite leases. Live coordination using only JSON state creates two competing lease truths.

Impact:

- Live acquire/release/renew and recovery now observe the same persisted lease authority in the main runtime wiring.
- Existing tests and JSON-only uses remain supported when no lease store is configured.

## 2026-05-28T06:13:30+02:00 - HA heartbeat should be context-bound and explicit

Decision:

- Add an opt-in heartbeat handle that periodically renews active leases through the persistent lease authority, stops on context cancellation, and reports lost lease after bounded renewal failures.

Reason:

- A persisted `RenewLease` primitive is useful only if runtime code can exercise it with clear cancellation and failure semantics.

Impact:

- Longer-running HA paths can now bind mutation work to a lease heartbeat lifecycle.
- Lost-lease handling can be wired without hidden goroutines or implicit global state.

## 2026-05-28T00:05:00+02:00 - Legacy scoped-lease compatibility should be normalized away, not carried forever as a read fallback

Decision:

- Normalize legacy `leases.scope_id=''` rows to the active scoped runtime DB on first repository access, then use strict scoped reads/writes afterward.

Reason:

- The fallback bridge protected upgrades, but leaving it in place permanently would keep an avoidable ambiguity in recovery and HA semantics.

Impact:

- The upgrade path remains safe for existing rows.
- New and existing lease behavior converge on strict `(scope_id, action)` semantics.
- The residual Brooks risk on legacy leases is reduced from permanent design debt to transient migration normalization.

## 2026-05-28T00:05:00+02:00 - Persisted lease stores need an explicit renew primitive even before distributed heartbeat semantics are fully built out

Decision:

- Add `RenewLease` to the lease store boundary and SQLite implementation now, instead of leaving renewal as an implicit future concern.

Reason:

- Recovery/HA correctness is weaker when the only persisted lease semantics are acquire/release and expiry is effectively write-once.

Impact:

- The storage layer now has a clear heartbeat/renew hook.
- Future HA coordination can extend expiry explicitly without redesigning the storage boundary.
- Operational semantics are clearer even before a full heartbeat loop is persisted.

## 2026-05-28T00:05:00+02:00 - Cloudflare replay cursors should advance from processed event time and only on successful critical-path completion

Decision:

- Drive cursor progression from the processed high watermark, replay with a fixed overlap window, and never commit the cursor after a failed reporting batch or failed cursor save.

Reason:

- Advancing cursors by wall clock or on partial failure makes restart safety and delayed-event correctness harder to defend. Overlap plus dedup is cheaper than missed evidence.

Impact:

- Restart/overlap behavior is safer.
- Duplicate windows are absorbed by existing dedup semantics instead of losing events.
- Corrupted cursor loads now fall back safely instead of poisoning the poller lifecycle.

## 2026-05-28T00:05:00+02:00 - Approval workflow should exist as execution primitives before any UI or operator workflow is added

Decision:

- Add approval-required fields and `awaiting_approval` execution semantics to mutation batches/operations now, but keep the behavior inert until those flags are set by policy.

Reason:

- High-impact mutations need replay-safe primitives and audit semantics before any operator-facing approval experience is layered on top.

Impact:

- Execution can now refuse approval-required work deterministically.
- The runtime gains a stable approval foundation without adding UI or new policy features.
- Future approval evidence/lineage can build on existing execution semantics instead of retrofitting them.

## 2026-05-27T18:05:00+02:00 - Live runtime and replay recovery must share one reducer, not duplicate lifecycle logic

Decision:

- Introduce `internal/runtime/reducer` and route both the live state machine and replay recovery through the same transition/event reduction rules.

Reason:

- The Brooks audit found that live and replay were reconstructing leases and rollback state differently. As long as those paths diverge, deterministic recovery and HA claims are not defensible.

Impact:

- Live transition and replay now produce the same `RuntimeState` for the same lifecycle/event inputs.
- Lease cleanup and rollback-lease semantics are centralized.
- Future state mutations now have one obvious place to be made replay-safe.

## 2026-05-27T18:05:00+02:00 - Lease persistence must be scoped by runtime partition, not globally by action

Decision:

- Make `LeaseStore` scope-aware and persist `scope_id` in SQLite `leases`, with anomaly detection querying active leases by `(scope_id, action)`.

Reason:

- The runtime is scoped. Global leases by action allow one scope to contaminate recovery, anomaly detection, and HA semantics of another.

Impact:

- Two scopes can now hold the same action lease independently.
- Recovery no longer reports orphan leases from unrelated scopes.
- Lease semantics are aligned with the scoped runtime/storage model already used elsewhere.

## 2026-05-27T18:05:00+02:00 - Event sequence allocation must be atomic per scope, not derived from `MAX(sequence)+1`

Decision:

- Allocate sequences through a dedicated SQLite `event_sequences` table using transactional upsert/returning semantics, plus bounded retry on `SQLITE_BUSY`.

Reason:

- `MAX(sequence)+1` is not concurrency-safe and breaks the append-only guarantees under legitimate concurrent writers.

Impact:

- Event sequences remain continuous and monotonic per scope under concurrent append.
- The runtime no longer relies on race-prone derived allocation.
- SQLite remains compatible with the single-writer scoped durability model.

## 2026-05-27T18:05:00+02:00 - Checkpoint checksums must cover the full canonical checkpoint proof line

Decision:

- Compute runtime checkpoint checksums from a canonical representation containing name, scope, sequence, event id, state, metadata, schema version, and canonical timestamp.

Reason:

- A checksum that ignores event id, metadata, schema version, or timestamp is not a full integrity proof and can miss forensic-significant tampering.

Impact:

- Checkpoint tampering is now detected across more of the persisted proof surface.
- Recovery/checkpoint validation is more defensible for forensic and replay scenarios.
- Future schema evolution remains part of the integrity contract instead of out-of-band metadata.

## 2026-05-27T17:03:00+02:00 - CLI and API evidence access should share the same reporting evidence model and explanation semantics

Decision:

- Expose reporting evidence over API v3 by reusing the same persisted model and explanation rendering already used by the CLI.

Reason:

- Separate query/explain implementations would quickly drift and weaken operator trust in forensic tooling. The system already had a stable evidence model, so the API should consume it directly instead of inventing a parallel read path.

Impact:

- CLI and API now expose the same forensic evidence semantics.
- Search/show/explain stay aligned across operator interfaces.
- Future tooling can extend one model instead of maintaining multiple incompatible views.

## 2026-05-27T17:03:00+02:00 - Replay verification should treat stored classifier/formatter/policy versions as first-class integrity signals

Decision:

- Extend the reporting replay verifier so stored component versions participate in replay integrity, not just comments, decisions, and hashes.

Reason:

- Once historical evidence is replayed across evolving classifier/formatter/policy code, version drift is itself important forensic information even if hashes or comments still happen to match.

Impact:

- Replay verification now reports version drift explicitly.
- Investigations can distinguish semantic drift from raw data corruption or hash mismatch.
- The evidence model is better prepared for future policy/classifier evolution.

## 2026-05-27T17:03:00+02:00 - Live reporting chaos should prioritize mixed-batch safety over abstract restart theater first

Decision:

- Add targeted mixed-batch live chaos coverage before deeper restart/cursor chaos, focusing on batches that contain both malformed and valid Cloudflare WAF events.

Reason:

- The most immediate operational risk in the current reporting path is incorrect handling of partially malformed real-world batches, not synthetic restart complexity for its own sake.

Impact:

- The Cloudflare replay/reporting path is now regression-tested against mixed malformed/valid batches.
- The chaos slice stays tied to concrete reporting-safety semantics.

## 2026-05-27T16:48:00+02:00 - AbuseIPDB reporting evidence must be queryable directly, not reconstructed from logs

Decision:

- Expose the append-only AbuseIPDB reporting evidence stream through direct CLI query/explain flows backed by the SQLite evidence store.

Reason:

- Once report/suppress evidence became durable, operators needed a first-class way to inspect it without reconstructing decisions from logs, telemetry, or generic audit trails.

Impact:

- `cf-sync -mode evidence` now provides direct forensic access to reporting evidence.
- Query/search/show/explain flows rely on the persisted evidence model rather than ad hoc log parsing.
- The same evidence model can later be surfaced over HTTP without redesigning the storage layer.

## 2026-05-27T16:48:00+02:00 - Reporting evidence should persist hashes and normalized input so replay verification is possible later

Decision:

- Persist canonical hashes and normalized event context alongside each AbuseIPDB report/suppression evidence record.

Reason:

- A replay verifier cannot detect formatter/classifier/policy drift unless the stored evidence carries enough stable context to recompute the decision.

Impact:

- Evidence now stores `input_hash`, `decision_hash`, URI list, categories, canonical decision, and the normalized event payload.
- `internal/services/reporting/replay` can re-evaluate canonical comment and decision integrity deterministically.
- Future forensic tooling can compare historical evidence against newer classifier/formatter/policy versions.

## 2026-05-27T16:48:00+02:00 - Chaos for the reporting pipeline should target failure semantics, not synthetic infrastructure theater

Decision:

- Add targeted failure-path tests around the shared reporting pipeline before adding broader chaos scenarios.

Reason:

- The highest-value operational questions at this stage are whether evidence write failures, telemetry failures, and cross-source duplicate suppression preserve safe behavior without panic or upstream flooding.

Impact:

- The reporting path now has explicit coverage for evidence-store failure and recent-report cross-source suppression behavior.
- The chaos slice stays focused on real failure semantics rather than generic infrastructure simulation.

## 2026-05-27T16:31:00+02:00 - Leaf-stage extraction is still worth doing when it removes real inline orchestration, even without adding new behavior

Decision:

- Extract normalization, execution, and telemetry into explicit orchestrator leaf stages where the control-plane already had stable behavior.

Reason:

- The goal of this slice is structural clarity, not feature delivery. Pulling these leaves out of `DryRun` and `Rollback` reduces hidden flow inside the orchestrator without forcing a risky rewrite of the pipeline contract.

Impact:

- `DryRun` and `Rollback` are easier to read and reason about.
- Validation, reporting, execution, and telemetry now follow a more consistent stage pattern.
- Replay/runtime semantics remain unchanged.

## 2026-05-27T16:31:00+02:00 - Daemon bootstrap concerns should move out of cmd/cf-sync/main.go before the composition root becomes the next monolith

Decision:

- Move API server startup, daemon shutdown-context wiring, and Cloudflare WAF replay poller startup into dedicated daemon/runtime helper files under `cmd/cf-sync`.

Reason:

- `cmd/cf-sync/main.go` was still correct, but it was continuing to accumulate unrelated operational concerns in one place. The control-plane now has enough moving parts that this would become the next readability bottleneck if left alone.

Impact:

- The main composition path is thinner and easier to scan.
- Daemon-specific lifecycle concerns are easier to evolve independently.
- The refactor changes structure only; runtime behavior is preserved.

## 2026-05-27T16:18:00+02:00 - Reporting-side translation belongs in an explicit pipeline stage, not inline in DryRun

Decision:

- Extract AbuseIPDB/reporting-side translation from the inline `DryRun` flow into a dedicated orchestrator reporting stage.

Reason:

- The central orchestrator had already been split into discovery, snapshot, planning, admission, translation, validation, and completion steps. Leaving reporting-side translation inline kept a small but unnecessary mixing of concerns inside `DryRun`.

Impact:

- Translation and reporting are now structurally separate in the pipeline.
- The next execution/telemetry extractions have a cleaner pattern to follow.
- No runtime behavior changed.

## 2026-05-27T16:18:00+02:00 - Composition roots should hide repetitive reporting/security wiring behind small local helpers before they become unreadable

Decision:

- Move repetitive reporting/security runtime construction out of `internal/app/app.go` and `cmd/cf-sync/main.go` into small, package-local helper files.

Reason:

- The wiring was still correct, but the composition roots were again becoming the natural place where operational complexity reconcentrated.

Impact:

- `internal/app` now has a dedicated local WAF reporting runtime helper.
- `cmd/cf-sync` now has explicit helper functions for security telemetry, propagation-guard setup, and WAF replay service construction.
- The refactor keeps behavior identical while lowering the scan cost of the top-level wiring paths.

## 2026-05-27T16:02:00+02:00 - SQLite reporting/security stores should be grouped behind a small facade before composition roots sprawl further

Decision:

- Introduce a small `ReportingStores` facade in `internal/storage/sqlite` that groups the SQLite-backed dedup, evidence, and cursor stores used by the reporting/security slice.

Reason:

- `cmd/cf-sync` and `internal/app` had started wiring several reporting/security stores separately. The behavior was still correct, but the composition roots were becoming harder to scan and easier to drift.

Impact:

- Reporting/security persistence wiring is now thinner and more explicit at the edge.
- The reporting service can be configured from one slice-specific facade instead of several unrelated constructors.
- This is a structural cleanup only; no runtime behavior or persistence semantics changed.

## 2026-05-27T16:02:00+02:00 - Orchestrator decomposition should continue by extracting safe leaf stages, not by rewriting the pipeline

Decision:

- Extract validation and completion into explicit pipeline stages while keeping the existing `DryRun` behavior intact.

Reason:

- The central orchestrator was already improving, but the remaining inline tail of `DryRun` still mixed validation, audit completion, bus emission, health updates, and final state-machine transitions.

Impact:

- `internal/orchestrator/pipeline` is easier to read incrementally.
- Future normalization/reporting/execution/telemetry extraction has a clearer pattern to follow.
- The refactor remains low-risk because it changes structure, not control-plane semantics.

## 2026-05-27T07:21:12+02:00 - AbuseIPDB report deduplication is a durable cross-source rule, not an in-memory optimization

Decision:

- Enforce a strict sliding 24-hour `1 IP = 1 AbuseIPDB report max` rule in the shared reporting layer through a provider-agnostic store boundary (`internal/security/reportdedup`) backed by SQLite durability.

Reason:

- Event-level or in-memory TTL deduplication is not sufficient to prevent flood across process restarts, multiple WAF sources, or repeated local reclassification. The rule must survive restarts and remain source-agnostic.

Impact:

- Cloudflare WAF, CrowdSec, OpenResty, and future classifiers now share the same durable per-IP AbuseIPDB suppression rule.
- Successful reports mark the IP only after upstream success; failed reports do not poison future attempts.
- Store failures fail closed by default to avoid accidental AbuseIPDB flooding during degraded operation.

## 2026-05-27T07:21:12+02:00 - Live local WAF sources must enter the same reporting service as replayed Cloudflare events

Decision:

- Feed real CrowdSec `decisions.log` events and OpenResty Lua JSONL events into `internal/services/reporting` instead of leaving the common pipeline as a Cloudflare-only path.

Reason:

- Safety and format guarantees only hold if all sources share the same normalize -> classify -> canonical comment -> report/suppress -> telemetry flow.

Impact:

- Cross-source AbuseIPDB reporting behavior is now structurally unified.
- Canonical comment generation and deduplication no longer depend on source-specific side paths.
- CrowdSec/OpenResty now benefit from the same suppression, telemetry, and future replay evidence semantics as Cloudflare replay.

## 2026-05-27T07:21:12+02:00 - Cloudflare WAF poll progress is runtime state and must be persisted durably

Decision:

- Persist the Cloudflare WAF replay poller `since` cursor in SQLite (`runtime_cursors`) instead of keeping it process-local only.

Reason:

- A process-local cursor breaks restart continuity and can cause duplicate replay windows or missed operator expectations around bounded replay progress.

Impact:

- Daemon restarts resume from the last saved WAF replay cursor.
- Cursor lifecycle remains explicit and storage-backed without pushing this concern into transport logic.
- Future recovery work can treat poll cursors as durable runtime coordination state.

## 2026-05-27T07:21:12+02:00 - Orchestrator decomposition starts with explicit stages, not a big rewrite

Decision:

- Begin thinning `internal/orchestrator/pipeline` by extracting explicit discovery, snapshot, and planning stages while preserving the current orchestration semantics.

Reason:

- The pipeline had become too wide, but a full rewrite would be risky. Stage extraction gives clearer boundaries without destabilizing the runtime.

Impact:

- The central orchestrator is now easier to read and extend incrementally.
- Future normalization, reporting, execution, and telemetry stages can follow the same pattern.
- Runtime behavior remains stable while structure improves.

## 2026-05-27T07:21:12+02:00 - AbuseIPDB reporting evidence is persisted as append-only service-layer forensic state

Decision:

- Persist successful and suppressed AbuseIPDB reporting decisions in a dedicated append-only SQLite store (`abuseipdb_reporting_evidence`) owned by the shared reporting layer.

Reason:

- Telemetry and counters alone are not sufficient for deterministic forensic replay of why an AbuseIPDB report was sent or suppressed. The service layer already owns the orchestration context and can persist report/suppress evidence without polluting pure domain packages.

Impact:

- Report and suppression decisions now receive durable evidence IDs.
- Telemetry metadata can point back to persisted evidence for later replay or operator review.
- Future forensic/query APIs can consume a stable append-only evidence stream instead of reconstructing decisions from logs alone.

## 2026-05-27T07:21:12+02:00 - Live source parsing must fail safe on sparse or malformed context

Decision:

- Keep live CrowdSec/OpenResty/Cloudflare ingestion biased toward skipping malformed or uncorrelated events instead of inventing request context.

Reason:

- False-positive resilience is more important than squeezing every possible signal out of incomplete input. Guessed URI/rule context would weaken replay integrity and operator trust.

Impact:

- Sparse or malformed live inputs remain observable only when enough safe context exists.
- Reportable events are more likely to be slightly under-reported than misreported.
- Fixture coverage now locks this bias in as a regression-tested behavior.

## 2026-05-27T07:21:12+02:00 - Reporting orchestration is being split before it turns into a hidden control-plane brain

Decision:

- Refactor `internal/services/reporting` into smaller responsibility-focused files without changing its public behavior or role.

Reason:

- The shared reporting service had become the next natural concentration point for control-plane complexity. Splitting policy, dedup, evidence, and telemetry concerns early keeps the service understandable while preserving the current architecture.

Impact:

- The package remains the outer orchestration point for WAF reporting decisions.
- Internal responsibilities are easier to review, test, and extract further later.
- The test suite now mirrors those responsibilities more clearly instead of hiding everything in one oversized file.

## 2026-05-27T15:05:00+02:00 - Unified WAF reporting is an outer-layer service, not a domain concern

Decision:

- Introduce `internal/services/reporting` as the single orchestration point for normalized WAF events from Cloudflare, CrowdSec, and OpenResty.

Reason:

- The classifier and formatter must stay pure and reusable, while reporting decisions, deduplication, telemetry emission, and provider calls belong in an application/service layer.

Impact:

- All three WAF sources can converge on the same pipeline without duplicating policy or comment generation logic.
- Domain packages remain provider-agnostic and side-effect free.
- Reporting, telemetry, and AbuseIPDB integration can evolve without re-polluting the security domain.

## 2026-05-27T15:05:00+02:00 - Better Stack delivery stays behind the passive telemetry sink boundary

Decision:

- Implement Better Stack as a concrete HTTP sink behind `internal/telemetry/sinks` instead of letting business or domain packages call it directly.

Reason:

- Operator visibility is required, but the control-plane must preserve fail-open telemetry semantics and keep provider-specific HTTP concerns out of the domain.

Impact:

- Telemetry events can be sent to Better Stack and Prometheus from the same passive event model.
- Sink failures do not break reporting or enforcement decisions.
- Structured JSON payloads stay stable and testable.

## 2026-05-27T15:05:00+02:00 - Suppression metrics must reflect explicit suppression, not lack of propagation

Decision:

- Count false-positive/low-signal suppression metrics only when a telemetry event carries an explicit `SuppressionReason`.

Reason:

- A successful AbuseIPDB report or other telemetry-only event may legitimately have `Propagated=false` without being a suppression. Using the propagation flag alone inflated suppression metrics.

Impact:

- Prometheus counters now better reflect operator-relevant suppressions.
- Metrics semantics align with the replayable decision model.

## 2026-05-27T14:05:00+02:00 - Cloudflare WAF replay uses GraphQL discovery but keeps classification/reporting outside transport

Decision:

- Fetch Cloudflare WAF/security events from the `firewallEventsAdaptive` GraphQL dataset in `internal/cloudflare`, then pass them through `internal/adapters/cloudflareevent` for normalization, local classification, canonical comment generation, and AbuseIPDB reporting.

Reason:

- Cloudflare’s official Analytics documentation positions `firewallEventsAdaptive` as the dataset behind Security Events, which is the closest typed read path for real WAF/security event replay. Keeping that fetch in `internal/cloudflare` preserves transport/discovery boundaries, while classification and reporting stay outside the transport layer.

Impact:

- The transport layer remains read-only and provider-specific.
- The shared local classifier remains the only place where abuse semantics are decided.
- Cloudflare replay and future CrowdSec/OpenResty reporting can converge on the same formatter/reporting chain instead of duplicating logic.

## 2026-05-27T14:05:00+02:00 - The daemon poller is explicit, context-bound, and sequential

Decision:

- Run Cloudflare WAF replay/reporting in daemon mode through an explicit ticker loop tied to the daemon context instead of burying the behavior in hidden background routines inside the domain or transport layers.

Reason:

- This preserves the no-hidden-goroutines discipline and keeps lifecycle/shutdown semantics visible at the composition root.

Impact:

- The poller stops cleanly on daemon shutdown.
- Replay/reporting remains sequential and non-overlapping per process.
- Durable cursor persistence is still pending and can be added later without moving the pipeline into the transport layer.

## 2026-05-27T13:10:00+02:00 - Security domain packages must stay provider-agnostic and side-effect free

Decision:

- Remove metrics, provider formatting, and adapter coupling from `internal/security/risk`, `internal/security/classifier`, and `internal/security/abuseformat`.

Reason:

- The anti-false-positive slice had started to mix domain logic with Prometheus, Better Stack, Cloudflare, and AbuseIPDB concerns. That weakened replay purity and made the architecture drift away from hexagonal boundaries.

Impact:

- Security domain packages now only score, classify, format deterministically, and return pure structures.
- Telemetry and provider-specific rendering moved outward to `internal/telemetry/*` and execution/orchestration layers.
- Future providers or telemetry sinks can be added without re-polluting the core security domain.

## 2026-05-27T13:10:00+02:00 - Reputation lookup is a domain boundary, not an AbuseIPDB policy object

Decision:

- Introduce `internal/security/reputation` and make AbuseIPDB implement that boundary as a concrete adapter.

Reason:

- Execution safety policy should depend on “reputation exists / score / availability”, not on AbuseIPDB-specific types or decisions.

Impact:

- `internal/execution` now depends on a narrow reputation interface instead of a provider-named adapter API.
- `internal/adapters/abuseipdb` is constrained to transport/cache/serialization behavior.
- Failure-mode policy remains in execution-side governance instead of the provider adapter.

## 2026-05-27T13:10:00+02:00 - Enforcement proof must exist in the real executor path

Decision:

- Add integration tests around `GovernedExecutor -> CloudflarePropagationGuard -> mutator -> audit/telemetry` instead of relying only on guard unit tests.

Reason:

- Safety claims about suppression are not credible unless the real mutation path proves that denied operations do not reach the mutator and still remain observable.

Impact:

- The repository now has executor-path tests proving suppression, propagation allow, audit persistence, telemetry emission, and mutator non-execution.
- Future wiring regressions are more likely to be caught before reaching production.

## 2026-05-27T01:02:00+02:00 - AbuseIPDB pre-ban verification is a safety gate, not a reporting side effect

Decision:

- Implement the AbuseIPDB `check` flow as a separate adapter and execution-time safety gate instead of mixing it into direct reporting or Cloudflare mutators.

Reason:

- The requirement is to stop false-positive amplification before global propagation. That is an execution-governance concern, not a reporting concern.

Impact:

- Cloudflare propagation can now be blocked before the mutator runs.
- Protected targets and low-score AbuseIPDB results bias toward suppression and review.
- Reporting remains a separate concern and is not implicitly triggered by safety checks.

## 2026-05-27T01:02:00+02:00 - Cloudflare event normalization should reuse a local classifier, not duplicate heuristics

Decision:

- Introduce a dedicated `internal/security/classifier` for replaying Cloudflare-style events into local abuse semantics.

Reason:

- The system needs category consistency between local catches and Cloudflare-originated events, and duplicating mapping logic across adapters would drift quickly.

Impact:

- Cloudflare replay classification can evolve independently of transport details.
- AbuseIPDB comments and category mappings now have a common local interpretation layer.
- The next ingestion step can feed replayed Cloudflare events into this classifier without coupling transport to reporting.

## 2026-05-27T00:37:00+02:00 - False-positive resilience starts outside the runtime core

Decision:

- Introduce false-positive resilience first as dedicated `internal/security/*` packages instead of immediately wiring new logic into the FSM, scheduler, or repositories.

Reason:

- The production incident risk is real, but the fastest safe move is to establish explicit scoring, trust, and blast-radius policies without destabilizing the healthy runtime core.

Impact:

- The repository now has reusable safety primitives for confidence scoring, protected resource matching, and propagation gating.
- Future enforcement, Cloudflare propagation, and operator-approval steps can depend on these primitives rather than hardcoding safety logic inside execution paths.

## 2026-05-27T00:21:00+02:00 - Python 3.6.0 parity resumes through contracts and adapters, not by expanding the runtime core

Decision:

- Start the Python 3.6.0 parity catch-up by adding versioned contracts and parse/validate-only OpenResty/Lua adapters before introducing any compatibility reader or runtime-side orchestration changes.

Reason:

- The Go repository already has a healthy runtime/event/persistence core. The highest-value missing boundary is the external contract with the Python/OpenResty/Lua ecosystem, not a rewrite of the FSM or scheduler.

Impact:

- The new adapters stay outside the central runtime lifecycle logic.
- The next migration step can add `internal/compat/python36` to translate legacy Python artifacts into explicit contracts instead of coupling the runtime to legacy file formats.
- OpenResty and Lua can now evolve behind stable versioned schemas and offline tests.

## 2026-05-27T00:02:36+02:00 - Bounded event replay is the first point-in-time recovery primitive

Decision:

- Implement point-in-time recovery first as bounded replay by target sequence or target timestamp on top of checkpoint-aware event replay.

Reason:

- This delivers deterministic temporal recovery semantics immediately without forcing a risky scoped SQLite reopen/restore refactor in the same slice.

Impact:

- Recovery manifests and plans now express `latest`, `sequence`, and `time` recovery modes.
- The next recovery slice can layer SQLite snapshot restore orchestration underneath these same recovery plans instead of replacing them.

## 2026-05-27T00:02:36+02:00 - Replay consistency verification starts above the event store, not inside repositories

Decision:

- Add replay consistency checks in a dedicated runtime package rather than embedding verification logic in SQLite repositories.

Reason:

- Deterministic replay, divergence detection, and forensic continuity are runtime concerns that should remain portable across future backends.

Impact:

- `internal/runtime/replay/consistency` can verify ordering, continuity, and checkpoint continuity independently of the storage backend.
- Future PostgreSQL or streaming backends can reuse the same verification layer without rewriting repository code.

## 2026-05-26T23:43:38+02:00 - Automatic checkpoints are emitted from lifecycle transitions, not from repositories

Decision:

- Attach runtime checkpoint production to `engine.StateMachine` transitions instead of embedding that logic inside SQLite repositories or lower storage layers.

Reason:

- This preserves the architectural rule that repositories stay free of business/runtime lifecycle semantics and keeps event production/checkpoint intent visible in the runtime layer.

Impact:

- SQLite remains a persistence boundary only.
- Lifecycle transitions now produce append-only events and runtime checkpoints through explicit runtime wiring.
- Recovery can reconstruct runtime state from checkpoints plus events without hidden repository logic.

## 2026-05-26T23:43:38+02:00 - SQLite degraded mode fails closed on mutable repositories

Decision:

- Introduce a read-only degraded mode on `storage/sqlite.DB` and enforce it on mutable repositories.

Reason:

- Under corruption suspicion or operational degradation, the control-plane must stop mutating durable state before it risks compounding damage.

Impact:

- Event append, checkpoint persistence, runtime state writes, lease writes, and ownership writes now refuse to proceed in degraded read-only mode.
- Recovery and diagnostics can still inspect the database while mutating paths fail closed.

## 2026-05-26T23:19:49+02:00 - First production-hardening slice targets event sourcing before broader recovery work

Decision:

- Strengthen `internal/runtime/events` and SQLite-backed event persistence before opening wider recovery, chaos, or distributed-coordination work.

Reason:

- The repository already had a broad control-plane skeleton, but the event layer still had hidden subscriber goroutines, weak replay semantics, and no durable replay checkpoints.

Impact:

- Event append is now the append-only source of truth for timeline reconstruction.
- Event subscribers now run synchronously under caller context, which removes hidden lifecycle behavior and simplifies shutdown semantics.
- Event replay can resume from named persisted checkpoints, but checkpoint production still needs to be wired into lifecycle transitions and runtime-state snapshots.

## 2026-05-26T23:19:49+02:00 - Worker pools must shut down explicitly and must not hide submission goroutines

Decision:

- Remove the hidden goroutine in the stateful scheduler pool submit path and add explicit close/wait semantics.

Reason:

- Background workers leaking past test teardown are the same class of lifecycle bug that would become dangerous in a long-running daemon.

Impact:

- Scheduler tests now terminate cleanly.
- Pool submission respects caller cancellation directly.
- Future daemon shutdown paths have a clearer basis for graceful worker termination.

## 2026-05-19T23:05:06+02:00 - Keep Python as source of truth

Decision:

- Do not modify, rename, move, delete, or overwrite the production Python scripts.

Reason:

- They are currently running in production and define the exact behavior the Go migration must match.

Impact:

- The Go project is developed in parallel and must prove parity before cutover.

## 2026-05-19T23:05:06+02:00 - Use Go 1.22.2 baseline

Decision:

- Retarget the module to `go 1.22.2`.

Reason:

- The local environment provides Go 1.22.2 and the project must remain compatible with standard Ubuntu server environments without requiring newer toolchains or experimental features.

Impact:

- Avoid APIs and language features introduced after Go 1.22.
- Keep validation runnable locally with `gofmt`, `go test`, `go vet`, and `go build`.

## 2026-05-19T23:05:06+02:00 - Prefer standard library and explicit interfaces

Decision:

- Use standard library primitives first and model integrations through narrow interfaces.

Reason:

- This keeps the migration easier to audit, easier to deploy, and easier to test.

Impact:

- Logging uses `log/slog`
- HTTP clients use `net/http`
- Scheduling uses a small internal runner
- External integrations remain replaceable behind interfaces

## 2026-05-19T23:05:06+02:00 - Keep JSON state for phase 1

Decision:

- Preserve JSON-backed local state first and defer SQLite.

Reason:

- Current Python behavior already relies on JSON persistence for deduplication and retention semantics.

Impact:

- `internal/state` provides JSON storage now
- SQLite can be introduced later behind the same storage boundary

## 2026-05-19T23:05:06+02:00 - Decompose the monolithic sync daemon by domain

Decision:

- Represent the large Python `crowdsec-cf-sync.py` daemon as a composition of domain services instead of a single giant Go file.

Reason:

- The Python daemon currently mixes Cloudflare sync, AbuseIPDB, recidive, ModSecurity, CIDR banning, Better Stack, and Cloudflare WAF polling.

Impact:

- `internal/app` wires the composition
- domain packages own future implementation details
- parity validation must also preserve sequencing and shared-state behavior

## 2026-05-19T23:05:06+02:00 - Checkpoint often and never leave a broken build

Decision:

- Every major step must end in a compiling, documented, resumable state.

Reason:

- This migration is session-based engineering work, not one-shot generation.

Impact:

- Update `SESSION_STATUS.md`, `MIGRATION_PROGRESS.md`, and `DECISIONS.md` regularly
- Avoid starting large refactors unless there is enough session budget to finish and validate them

## 2026-05-19T23:15:08+02:00 - Enforce trust-but-verify for external integrations

Decision:

- Do not implement external integrations from memory or guesses.

Reason:

- This project targets production security automation, where invented API schemas or undocumented assumptions would create silent operational risk.

Impact:

- Verify Cloudflare, CrowdSec, AbuseIPDB, Better Stack, and Go standard library behavior against official documentation before implementation
- If verification is incomplete, leave a TODO and document the uncertainty instead of guessing
- Keep request and response translation isolated inside the integration package, especially `internal/cloudflare`

## 2026-05-19T23:15:08+02:00 - Concurrency safety before service parallelism

Decision:

- Establish cancellation, trace propagation, retry boundaries, non-overlapping scheduler runs, and race-safe state access before implementing concurrent service logic.

Reason:

- Shared state and goroutine lifecycle are the highest-risk areas for the future daemon.

Impact:

- Scheduler runs now have timeout support, explicit lifecycle logs, and overlap prevention
- `go test -race ./...` becomes a milestone gate
- State persistence avoids holding locks during file I/O

## 2026-05-19T23:20:04+02:00 - Cloudflare implementation must be read-only first

Decision:

- Implement Cloudflare integration in read-only mode before any write or delete path.

Reason:

- Early parity phases must observe and validate behavior before mutating security controls in production-adjacent workflows.

Impact:

- Mutation paths require dry-run support first
- Intended mutations must be logged before execution
- Destructive actions remain disabled during early parity work

## 2026-05-19T23:20:04+02:00 - Keep Cloudflare concerns separated and fully mockable

Decision:

- Separate Cloudflare transport, typed schemas, business logic, and reconciliation logic, and keep all Cloudflare-specific schemas inside `internal/cloudflare`.

Reason:

- This prevents Cloudflare API details from leaking into the rest of the codebase and makes tests fixture-driven and fully mockable.

Impact:

- Cloudflare pagination and rate-limit handling will be implemented explicitly inside `internal/cloudflare`
- Sanitized real-response fixtures become part of the test strategy before write support is added

## 2026-05-28T22:30:00+02:00 - SQLite correctness and recovery orchestration

Decision:

- Centralize SQLite error classification in `internal/storage/sqlite/errors.go` using typed `sqlite.Error` and native codes to eliminate fragile string matching.
- Move one-time migration tasks (like legacy scope normalization) to the `DB.New` bootstrap phase to reduce runtime contention and write amplification.
- Require `owner` and `fencing_token` verification on all lease renewals and releases to prevent stale/ambiguous coordination.
- Implement point-in-time restore in `recovery.Manager` by combining database file snapshots with bounded event replay.
- Enforce sequence continuity and gap detection during event replay to ensure reconstruction integrity.

Reason:

- Eliminating string-based error handling prevents regressions during driver updates or locale changes.
- Moving migration logic out of hot paths improves performance and reduces WAL lock contention.
- Stronger lease ownership checks prevent "zombie" workers from extending leases after leadership loss.
- Point-in-time restore is essential for autonomous recovery from corruption or operator error.

Impact:

- Integration tests should replay sanitized fixtures before live API usage
- Cloudflare implementation starts with auth validation, connectivity checks, read-only list operations, and pagination traversal only
- Mutation support remains deferred

## 2026-05-19T23:24:54+02:00 - Prefer strict decoding and small Cloudflare models

Decision:

- Use strict JSON decoding and small resource-specific response models for Cloudflare integration.

Reason:

- Giant shared response structs hide schema drift and make testing and maintenance harder.

Impact:

- Unknown critical schema mismatches should be rejected explicitly
- Cloudflare-specific schemas stay local to `internal/cloudflare`
- Debug request and response logs must stay behind a debug flag and must not expose sensitive identifiers

## 2026-05-19T23:27:43+02:00 - Fixture replay is an offline, deterministic boundary

Decision:

- Treat fixture replay as a deterministic offline test boundary with no live API mixing.

Reason:

- Replay tests need to be stable, comparable across sessions, and safe to run without network access.

Impact:

- Fixture replay tests must not make internet calls
- Raw capture, sanitization, replay, and schema drift detection become distinct responsibilities
- Fixture versioning and expiration metadata are required to monitor API drift over time

## 2026-05-19T23:27:43+02:00 - Preserve both raw and sanitized Cloudflare fixtures

Decision:

- Capture both raw and sanitized fixture forms with explicit metadata and pagination sequence data.

Reason:

- Raw captures preserve auditability, while sanitized fixtures support safe repository-based replay tests.

Impact:

- Fixture tooling must store status, headers, body, pagination metadata, and timestamps
- Sanitization must remove tokens, emails, account IDs, zone IDs, and sensitive IPs when flagged
- Sanitized fixtures should be treated as immutable after generation

## 2026-05-19T23:30:28+02:00 - Replay uses sanitized fixtures plus explicit replay metadata

Decision:

- Replay must operate on sanitized fixtures and dedicated replay metadata, never directly on raw captures.

Reason:

- Raw captures are not safe or stable as direct replay artifacts, while replay metadata needs its own deterministic control surface.

Impact:

- Raw capture, sanitized storage, and replay metadata become separate fixture layers
- Replay ordering, pagination sequencing, rate-limit cases, and transient failure cases must be expressible without live calls

## 2026-05-19T23:30:28+02:00 - Fixture replay integrity must be validated explicitly

Decision:

- Add corruption detection, checksum validation, schema versioning, and parallel-safe replay guarantees to the fixture architecture.

Reason:

- Offline replay only helps if fixture integrity and ordering are trustworthy across sessions and concurrent test runs.

Impact:

- Sanitized fixtures need explicit integrity validation
- Replay tests must support deterministic ordering and optional latency simulation without introducing nondeterminism

## 2026-05-19T23:31:11+02:00 - Replay must simulate real Cloudflare failure modes early

Decision:

- Treat rate limits, timeouts, incomplete pagination, and transient failures as first-class replay scenarios.

Reason:

- Those are the operational failure modes most likely to affect the future Cloudflare daemon in production.

Impact:

- Replay design must include explicit support for HTTP 429 responses, timeout paths, partial pagination chains, and transient upstream errors
- These cases should be modeled before live API usage or mutation logic

## 2026-05-19T23:32:09+02:00 - Keep reconciliation out of transport layers

Decision:

- API transport layers must not contain business reconciliation logic.

Reason:

- Mixing HTTP transport with reconciliation behavior makes testing, replay, and future change isolation much harder.

Impact:

- Transport packages should stop at authentication, request execution, pagination traversal, header handling, and strict schema decoding
- Reconciliation decisions belong in higher-level business layers

## 2026-05-19T23:36:39+02:00 - Reconciliation must be plan-driven and idempotent

Decision:

- Reconciliation must be idempotent and must flow through explicit discovery, planning, and execution phases.

Reason:

- Retries, scheduler reruns, network failures, and replay must not cause duplicate bans, repeated deletes, or state drift.

Impact:

- Dry-run output becomes a first-class reconciliation feature
- Mutation planning must be separate from mutation execution
- Duplicate-mutation protection is required before any write path is enabled

## 2026-05-19T23:36:39+02:00 - Reconciliation state must not depend directly on transport payloads

Decision:

- Do not couple reconciliation state directly to transport response objects.

Reason:

- Transport payloads can drift independently and should not define durable reconciliation behavior.

Impact:

- Reconciliation should operate on normalized domain snapshots and explicit plans
- Transport changes should not silently alter mutation decisions

## 2026-05-19T23:41:13+02:00 - Reconciliation must be durable across restarts

Decision:

- Reconciliation plans, snapshots, progress, and execution journals must support restart-safe durability.

Reason:

- Long-running daemons must recover from process restarts and partial failures without losing mutation provenance or re-planning unpredictably.

Impact:

- Plans must be serializable
- Discovery snapshots must be persistable
- Execution progress must be resumable
- Operation IDs and execution journals are required

## 2026-05-19T23:41:13+02:00 - Mutation provenance must be explainable

Decision:

- Persist enough metadata to explain why a mutation happened, which snapshot produced it, and which reconciliation run executed it.

Reason:

- Security automation requires post-incident auditability, especially around bans, deletes, and retries.

Impact:

- Reconciliation journaling must be replay-safe and traceable end-to-end
- Retries must not silently generate materially different plans without explicit detection

## 2026-05-19T23:43:56+02:00 - Mutation execution needs explicit state and confirmation boundaries

Decision:

- Mutation execution must use explicit state-machine tracking, confirmation gates, and audit snapshots.

Reason:

- Security mutations need strong protections against accidental execution, partial failures, and nondeterministic retries.

Impact:

- Mutation batches need deterministic identity keys and resumable state
- Execution outside dry-run mode requires explicit confirmation gates
- Before and after audit snapshots become mandatory execution metadata

## 2026-05-19T23:43:56+02:00 - Refuse unsafe execution when plans go stale

Decision:

- Execution must detect stale plans and refuse mutation if snapshot drift exceeds safety thresholds.

Reason:

- A daemon must not apply outdated mutation plans against a changed remote state.

Impact:

- Drift thresholds and stale-plan checks are required before execution
- Overlapping reconciliation plans must not run concurrently

## 2026-05-19T23:46:32+02:00 - Execution must support operator safety controls

Decision:

- Mutation execution must be governed by kill-switches, emergency read-only mode, rate and count limits, and circuit-breaker protections.

Reason:

- Security automation needs fast operator override paths and automatic fail-safe behavior under abnormal conditions.

Impact:

- Write-path design must include global execution disablement, safety thresholds, and failure escalation behavior
- Suspicious or unstable execution paths must degrade safely instead of continuing blindly

## 2026-05-19T23:46:32+02:00 - Mutation lifecycle events require structured auditability

Decision:

- Every mutation lifecycle event must emit structured audit logs and operator-visible execution summaries.

Reason:

- Operators need immediate visibility into what the daemon planned, executed, blocked, quarantined, or failed.

Impact:

- Audit event schemas and execution summary outputs become part of the write-path design contract
- Degraded and quarantine modes must be visible to operators
## 2026-05-27T00:52:34+02:00 - Baseline browser bootstrap must never trigger aggressive enforcement

Decision:

- Requests matching the learned benign browser bootstrap baseline are classified as `benign_bootstrap` and remain `observe_only`.

Reason:

- Normal homepage and asset loading must remain fully visible without creating false positives or escalating to Cloudflare propagation or AbuseIPDB reporting.

Impact:

- `internal/security/baseline` becomes part of the progressive risk path
- baseline-only events stay replayable and observable but never hard-banned

## 2026-05-27T00:52:34+02:00 - Real Cloudflare mutation execution must be guarded before provider calls

Decision:

- `cmd/cf-sync` now injects `CloudflarePropagationGuard` into the live `GovernedExecutor` path.

Reason:

- Anti-false-positive modules are not enough if production execution paths can still bypass them.

Impact:

- Cloudflare mutations now hit trust checks and AbuseIPDB pre-ban checks before provider execution
- guarded resource types currently include `ip_access_rules`, `list_items`, `ruleset_rules`, and `rulesets`

## 2026-05-27T00:52:34+02:00 - Canonical AbuseIPDB comments must come from one formatter

Decision:

- AbuseIPDB comment generation is centralized in `internal/security/abuseformat`, including translator-driven reports.

Reason:

- Source-specific string assembly creates drift, makes replay comparison harder, and weakens operator trust in forensic artifacts.

Impact:

- comment format is stable across CrowdSec/OpenResty/Cloudflare sources
- truncation, URI deduplication, and missing-field accounting are enforced in one place

## 2026-05-28T-current+02:00 - Cloudflare mutations require scoped fencing validation

Decision:

- A mutation carrying lease metadata must validate `(scope_id, lease_id, fencing_token, lease_action)` against the active scoped lease before the provider call.

Reason:

- Heartbeat cancellation prevents many zombie mutations, but stale workers also need an explicit per-operation fencing check at the execution boundary.

Impact:

- `GovernedExecutor` and rollback compensation execution reject stale tokens with `stale_fencing_token_mutation_refused`.
- Existing callers that do not yet provide lease metadata retain previous behavior until they opt into fenced execution.

## 2026-05-28T-current+02:00 - AbuseIPDB outbox retries are explicit and context-bound

Decision:

- Failed or pending AbuseIPDB report reservations are retried by an explicit worker invoked by the runtime scheduler, not by an implicit background goroutine.

Reason:

- The reporting path must be recoverable without hiding lifecycle or shutdown semantics from operators.

Impact:

- Outbox rows persist the canonical report payload, attempt count, last error, and next eligible attempt.
- The local WAF runtime processes bounded retries once per scheduler tick and remains context-cancellable.

## 2026-05-29T-current+02:00 - SQLite error handling must be code-based, not message-based

Decision:

- Runtime-critical SQLite retries and classification use typed driver error codes only.

Reason:

- Message-text matching is brittle across driver versions and can silently misclassify critical storage failures.

Impact:

- `internal/storage/sqlite/errors.go` now classifies BUSY/LOCKED/CONSTRAINT/IOERR/CORRUPT strictly via modernc SQLite error codes.
- Retry and failure paths remain deterministic and robust to message-format changes.

## 2026-05-29T-current+02:00 - Legacy lease scope normalization is bootstrap-only

Decision:

- Legacy empty `scope_id` normalization is executed by migration (`v12`), not in DB runtime startup logic.

Reason:

- Migration debt in hot paths increases WAL contention and hides non-deterministic boot-time side effects.

Impact:

- Lease runtime operations are cleaner and no longer coupled to legacy data rewrite logic.
- `NormalizeLeases` remains available as explicit admin/bootstrap utility, but is not invoked automatically by runtime hot paths.

## 2026-05-29T-current+02:00 - Lease renewal validates epoch lineage

Decision:

- `RenewLease` requires matching `scope_id + owner + epoch_id + fencing_token` to extend lease TTL.

Reason:

- Owner/fencing-only renewals can still allow ambiguous stale renewals after leadership/epoch changes.

Impact:

- Stale renewal windows are reduced.
- Heartbeat renewal now fails closed on epoch mismatch, triggering lost-lease handling instead of silently extending stale ownership.
