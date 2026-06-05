# Runtime hardening status and remaining roadmap

Last updated: 2026-05-28T20:25:00+02:00

## What was completed

### Runtime event idempotency

- Runtime events now carry `event_uid`.
- SQLite enforces scoped uniqueness on `(scope_id, event_uid)`.
- Duplicate logical appends resolve to the existing event id/sequence.
- Ambiguous commit handling no longer retries blindly.
- `sqlite.ErrCommitAmbiguous` is returned when `Commit()` fails and the row cannot be proven durable by `(scope_id, event_uid)`.

### Lease authority and heartbeat

- `LeaseManager` can use the scoped SQLite `LeaseStore` as the live lease authority.
- `cmd/cf-sync` wires the runtime lease manager to `sqlite.NewLeaseRepository`.
- Lease acquire/release/renew are now visible to recovery.
- HA heartbeat is context-bound, renews leases persistently, stops cleanly on cancellation, and emits a lost-lease signal after bounded failures.
- Rollback execution binds provider mutations to the heartbeat context.
- Cloudflare mutators support context-aware execution through `ExecuteContext`.
- Lost lease cancellation emits `lost_lease_mutation_aborted` audit/telemetry.

### AbuseIPDB strict reporting

- Reporting uses a durable outbox/reservation path when SQLite reporting stores are configured.
- A reportable event is reserved before any upstream AbuseIPDB call.
- `report_pending` evidence is persisted before the upstream call.
- Upstream success records reported evidence, marks the 24h per-IP dedup store, and marks the outbox row `reported`.
- Upstream failure marks the outbox row `failed` and does not mark the 24h dedup store.
- Reservation/evidence failure suppresses the upstream call.
- Pending reservations are idempotent for the same idempotency key.
- Expired pending reservations are failed before allowing a new reservation.

### Forensic evidence search

- `abuseipdb_reporting_evidence` now projects strong query fields:
  - `decision`
  - `abuse_type`
  - `source`
  - `ip`
  - `suppression_reason`
  - `timestamp`
  - `evidence_id`
- SQL handles filtering and pagination for common forensic queries.
- Existing JSON evidence payload remains the canonical detailed record.

### False-positive resilience

- Cloudflare, CrowdSec, and OpenResty WAF events enter a shared normalize -> classifier -> canonical formatter -> reporting -> telemetry path.
- Benign/bootstrap/low-confidence events stay observable without aggressive enforcement.
- AbuseIPDB reports are canonicalized and deduplicated across sources.
- Protected targets and low reputation confidence suppress propagation/reporting.

## Current guarantees

- SQLite WAL remains the primary backend.
- Runtime event append is idempotent by scoped `event_uid`.
- Event sequence allocation is monotonic per scope.
- Commit ambiguity is explicit instead of silently retried.
- Leases are scope-aware and recovery-visible.
- Heartbeat loss can cancel rollback/provider mutation context.
- AbuseIPDB reporting cannot call upstream in strict configured mode unless reservation and pending evidence are durable.
- AbuseIPDB 24h per-IP dedup is durable and cross-source.
- Reporting evidence search is SQL-backed for core filters.
- Telemetry failure remains fail-open for the critical path.

## What is still desirable

### 1. Per-mutation fencing token enforcement

Status: implemented.

Summary:

1. `MutationBatch`, `MutationOperation`, `RollbackBatch`, and `CompensationOperation` now carry lease/fencing metadata.
2. `execution.LeaseStoreFencingValidator` checks the active scoped lease before provider calls.
3. `GovernedExecutor` emits `stale_fencing_token_mutation_refused` audit/telemetry and skips the mutator on mismatch.
4. Rollback compensation execution uses the same validator.

### 2. Async AbuseIPDB outbox worker

Status: implemented as an explicit, context-bound worker.

Summary:

1. The SQLite outbox persists `report_json`, `attempt_count`, `last_error`, and `next_attempt_at`.
2. `reporting.OutboxWorker` processes bounded retry batches through the canonical AbuseIPDB report payload.
3. Failed retries record backoff state and do not mark the 24h dedup store.
4. Successful retries mark the durable dedup store, emit evidence/telemetry, and mark the reservation `reported`.
5. The app runtime calls `ProcessOnce(ctx)` once per scheduler tick, avoiding hidden goroutine lifecycle risk.

### 3. Forward execution lease-bound context

Status: partially complete.

Reason:

- Rollback execution is heartbeat-bound. Any future forward live mutation path should use the same pattern when it starts executing provider writes.

Recommended patch plan:

1. Acquire reconcile lease before forward mutation execution.
2. Start heartbeat with `context.WithCancelCause`.
3. Pass the lease-bound context into `GovernedExecutor.ExecuteBatch`.
4. Verify no operation proceeds after lost lease.

### 4. Reporting service decomposition

Status: started.

Reason:

- `internal/services/reporting` remains the most likely place for future complexity concentration.

Recommended patch plan:

1. Decision preparation is now extracted from `Service.Process`.
2. Next useful steps are extracting the reservation/dedup gate and evidence/telemetry collaborators.
3. Keep `Service.Process` as orchestration-only.

## Validation status

Last full validation completed successfully:

```bash
GOTOOLCHAIN=local gofmt -w $(find /home/jm/Documents/security-automation-go -type f -name '*.go' -not -path '*/vendor/*')
GOTOOLCHAIN=local go test ./...
GOTOOLCHAIN=local go test -race ./...
GOTOOLCHAIN=local go vet ./...
GOTOOLCHAIN=local go build ./...
```
