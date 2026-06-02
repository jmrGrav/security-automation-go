# Release / Cutover Checklist

Use this checklist for the final Python to Go authority decision. Local green status proves the artifact is ready to evaluate; it does not by itself prove the live cutover is complete.

## Status Model

- **Release readiness**: repository docs, tests, local drills, and operator commands are coherent.
- **Cutover readiness**: release readiness plus completed external shadow soak and controlled-authority rehearsal.
- **Production cutover**: the live host is running the Go authority path and rollback to Python remains available.

## Preconditions

- Ubuntu host has OpenResty installed and configured.
- CrowdSec is installed, healthy, and producing the expected decisions/events.
- CrowdSec writes are routed only through `crowdsec.Client`; no auxiliary UI,
  replay, deban, or orchestration code may shell out to `cscli` directly.
- Cloudflare token and zone/account IDs are present and scoped to the expected resources.
- `STATE_DIR` points to persistent storage owned by the service user.
- SQLite runtime DB uses WAL mode and has readable `runtime.db`, `runtime.db-wal`, and `runtime.db-shm` state where applicable.
- systemd unit, environment file, working directory, and permissions match the selected deployment.
- journald logs are available for the Go service.

## Local Release Gate

- `GOTOOLCHAIN=local gofmt -w $(find . -type f -name '*.go' -not -path './vendor/*')`
- `GOTOOLCHAIN=local go test ./...`
- `GOTOOLCHAIN=local go test -race ./...`
- `GOTOOLCHAIN=local go vet ./...`
- `GOTOOLCHAIN=local go build ./...`
- `GOTOOLCHAIN=local go test -tags=soak ./internal/testing/...`

## Operator Dry Runs

- `cf-sync -config /path/to/config.yaml -mode doctor`
- `cf-sync -config /path/to/config.yaml -mode status`
- `cf-sync -config /path/to/config.yaml -dry-run=true`
- `cf-cleanup --dry-run`

Expected result:

- Config errors are actionable.
- Dry-run output is explainable.
- Cleanup dry-run lists stale rules without calling deletion.
- No Cloudflare mutation is performed during dry-run.

## Backup and Recovery Gate

- Stop or pause live mutation authority before backup.
- Copy SQLite DB plus WAL/SHM files, or use the documented hot snapshot path.
- Verify backup artifact exists and is readable.
- Rehearse restore on a non-live copy.
- Confirm quarantine/degraded-mode procedure is understood.

## Shadow Soak Gate

- External shadow soak completed for the agreed duration.
- Agreement rate is within the accepted threshold.
- Any drift has an explanation and recorded evidence.
- Go shadow mode produced evidence/telemetry without external mutation.
- Python remains authority until this gate is accepted.

## Controlled Authority Gate

- Enable Go authority for the smallest safe scope.
- Confirm stale fencing is refused.
- Confirm lost lease aborts mutations.
- Confirm AbuseIPDB outbox and Cloudflare cursor state remain explainable.
- Confirm journald logs and metrics show the expected authority path.
- Keep Python rollback ready during the observation window.

## Rollback to Python

- Stop the Go authority unit.
- Re-enable the Python authority unit/env.
- Confirm Python logs show active sync.
- Confirm Go is no longer mutating Cloudflare.
- Preserve Go evidence, SQLite state, and journald logs for postmortem.

## GO Criteria

- All local validation commands pass.
- `doctor` and `status` are clean.
- Shadow soak is complete and explainable.
- Dry-run and cleanup dry-run are reviewed.
- SQLite backup/restore rehearsal is complete.
- Monitoring covers lease, cursor, outbox, evidence, replay divergence, and SQLite quarantine/degraded mode.
- Rollback to Python is rehearsed.
- Operator explicitly approves controlled authority.

## NO-GO Criteria

- Shadow soak still in progress or unexplained drift exists.
- Cloudflare token/zone scope is unclear.
- SQLite backup/restore is not rehearsed.
- systemd permissions or state path are uncertain.
- Dry-run output is not explainable.
- Cleanup dry-run shows unexpected deletion candidates.
- Lost lease, stale fencing, outbox, cursor, or evidence signals are missing.
- Rollback to Python is not ready.

## Final Decision

- Release readiness can be `GREEN` before production cutover.
- Cutover readiness is `GREEN` only after the shadow soak and controlled-authority gates are complete.
- Production cutover is `GO` only when the live host confirms Go authority and Python rollback remains available.
