# Accuracy Policy

Last updated: 2026-05-19T23:46:32+02:00

## Verification rules

- Never invent APIs, endpoints, fields, methods, or configuration formats.
- Never assume undocumented behavior.
- If uncertain, stop and verify against official documentation before implementation.
- Prefer official documentation over memory for:
  - Cloudflare APIs
  - CrowdSec APIs
  - AbuseIPDB
  - Better Stack
  - Go standard library behavior
- If a detail cannot be verified, mark it as uncertain and leave a TODO instead of guessing.

## External integration implementation rules

Before implementing any external integration:

- validate request models
- validate response models
- validate pagination behavior
- validate authentication format
- validate documented rate-limit behavior

Keep all API translation isolated inside the corresponding integration package. For Cloudflare specifically, request and response schemas must stay inside `internal/cloudflare`.

## Cloudflare implementation rules

- Start with:
  - authentication validation
  - connectivity checks
  - read-only list operations
  - pagination traversal
- Implement read-only operations first.
- Add fixture capture tooling first.
- Sanitize all fixture data automatically.
- Add dry-run support before any write or delete operation.
- Separate:
  - API transport
  - request and response models
  - business logic
  - reconciliation logic
- Do not place business reconciliation logic inside API transport layers.
- Prefer small resource-specific response models instead of giant shared Cloudflare response structs.
- Do not perform destructive actions automatically during early parity phases.
- Log intended mutations before executing them.
- Never log API tokens, account IDs, or zone secrets.
- Add explicit request and response debug logging behind a debug flag only.
- Use fixture-based tests with real sanitized API responses.
- Add integration tests using fixture replay before live API usage.
- Support Cloudflare pagination explicitly.
- Respect Cloudflare rate limits and `Retry-After` headers.
- Support context cancellation during pagination loops.
- Validate JSON decoding strictly.
- Reject unknown critical schema mismatches explicitly.
- Keep Cloudflare APIs fully mockable behind integration boundaries.
- Keep all Cloudflare-specific schemas inside `internal/cloudflare` only.

## Reconciliation rules

- Reconciliation must be idempotent.
- Reconciliation plans must be serializable.
- Discovery snapshots must be persistable.
- Execution progress must survive process restarts.
- Partial execution state must be recoverable.
- Reconciliation operations must support resume-after-failure.
- Add operation IDs for reconciliation runs.
- Mutation execution must be traceable end-to-end.
- Add replay-safe execution journaling.
- Ensure retries do not regenerate different plans unexpectedly.
- Persist enough metadata to explain:
  - why a mutation happened
  - which snapshot produced it
  - which reconciliation run executed it
- Separate:
  - read-side discovery
  - mutation planning
  - mutation execution
- Generate explicit reconciliation plans before any action.
- Support dry-run reconciliation output.
- Log planned diffs before execution.
- Add replayable reconciliation fixtures.
- Prevent duplicate mutations across retries.
- Reconciliation decisions must be deterministic.
- Never couple reconciliation state directly to transport responses.

## Mutation execution rules

- Mutations must support transactional grouping semantics.
- Partial mutation failures must be recoverable.
- Mutation batches must be resumable independently.
- Add explicit mutation state machine tracking:
  - planned
  - executing
  - completed
  - failed
  - rolled_back
- Every mutation must have deterministic identity keys.
- Prevent concurrent execution of overlapping reconciliation plans.
- Add stale-plan detection before execution.
- Refuse execution if snapshot drift exceeds safety thresholds.
- Require explicit execution confirmation gates outside dry-run mode.
- Add execution audit snapshots before and after mutation batches.

## Operational safety rules

- Add global execution kill-switch support.
- Support read-only emergency mode.
- Add maximum mutation-count safety limits.
- Require mutation-rate limiting.
- Add circuit-breaker behavior for repeated failures.
- Refuse execution under excessive drift conditions.
- Add operator-visible execution summaries.
- Add explicit degraded-mode handling.
- Add execution quarantine mode for suspicious plans.
- Add mandatory structured audit logging for every mutation lifecycle event.

## Fixture tooling rules

- Separate:
  - raw captured fixtures
  - sanitized fixtures
  - replay metadata
- Never replay raw fixtures directly.
- Sanitization must be irreversible.
- Fixture capture must support:
  - raw response storage
  - sanitized response storage
  - metadata capture
  - pagination sequence capture
- Fixture records must store:
  - HTTP status
  - headers
  - body
  - pagination metadata
  - timestamps
- Sanitization must remove:
  - API tokens
  - emails
  - account IDs
  - zone IDs
  - IPs when marked sensitive
- Fixture replay must be deterministic.
- Fixture replay should support:
  - single page responses
  - paginated sequences
  - rate-limit responses
  - transient failures
  - malformed responses
- Prioritize real-world failure simulation for:
  - HTTP 429 responses
  - timeouts
  - incomplete pagination sequences
  - transient upstream failures
- Replay tests must run without internet access.
- Fixtures must be versioned by endpoint and resource type.
- Store fixture schema versions explicitly.
- Add schema drift detection tests.
- Add corruption-detection checks for fixtures.
- Add checksum or hash validation for replay integrity.
- Keep sanitized fixtures immutable after sanitization.
- Never mix live API calls into replay tests.
- Add replay latency simulation hooks.
- Support deterministic replay ordering.
- Ensure replay tests are parallel-safe.
- Add fixture expiration metadata to track API drift over time.

## Concurrency safety rules

- Never share mutable maps directly across goroutines.
- Protect shared mutable state explicitly.
- Prefer immutable snapshots when possible.
- Avoid package-level mutable variables.
- Prefer ownership patterns over broad mutex usage.
- Minimize lock duration.
- Never hold locks during HTTP calls, subprocess execution, or file I/O.
- Every stateful component must gain race-focused tests.
- All long-running operations must accept `context.Context`.
- Scheduler jobs must not overlap unintentionally.

## Scheduler rules

- Jobs must support cancellation.
- Jobs must support execution timeouts.
- Jobs must log start, completion, failure, and cancellation explicitly.
- Jobs must expose duration and failure counters.

## Migration implication

Correctness takes priority over implementation speed. If a future feature depends on undocumented behavior, keep it behind an interface and document the uncertainty before continuing.
