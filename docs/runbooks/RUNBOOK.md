# Operational Runbook

## Startup checks

1. Confirm Ubuntu host prerequisites are installed and enabled:
   - OpenResty
   - CrowdSec
   - systemd unit for the selected runtime
2. Validate config load and scope selection:
   - `cf-sync -config /path/to/config.yaml -mode doctor`
   - `CF_API_TOKEN`
   - `CF_ZONE_ID`
   - `STATE_DIR`
3. Confirm the Cloudflare token has the expected zone/account permissions before live authority.
4. Confirm SQLite opens and `VerifySchema` passes.
5. Confirm WAL mode and checkpoint helpers are available.
6. Confirm the state directory, SQLite DB, WAL/SHM files, logs, and backup directory are writable by the systemd service user.
7. Confirm lease state is empty or owned by the expected scope.
8. Confirm cursor state exists and is sane for the Cloudflare WAF replay poller.
9. Confirm outbox pending count is bounded and explainable.
10. Confirm evidence store reads succeed.

## Local operator UI

1. Confirm UI mode is explicitly enabled before starting it:
   - `UI_ENABLED=1`
   - `UI_ADDR=127.0.0.1:9090`
   - `UI_MUTATIONS_ENABLED=0` unless the operator has explicitly enabled
     mutations
   - `UI_SECRET_FILE=/var/lib/cf-sync/secrets.local`
2. Confirm the local secret file exists or can be created by the service user
   and is `0600`.
3. Confirm provider keys are configured only through env or the local secret
   file; do not paste them into logs, docs, or evidence.
4. Start the UI in local mode:
   - `cf-sync -mode ui`
5. Expected status strings on the dashboard:
   - `CrowdSec unavailable / read-only fallback` when CrowdSec inputs are not
     present
   - `OpenResty unavailable / nginx log mode` when OpenResty inputs are not
     present
   - `Cloudflare configured dry-run` when Cloudflare is configured but live
     mutations are still disabled
   - `Cloudflare live mutations enabled` only when the operator explicitly
     enabled them

## Incident responses

### Lost lease

- Stop or pause write-path execution.
- Inspect the active lease and fencing token.
- Wait for the next epoch or restart the worker that owns the lease.

### Stale fencing

- Treat the mutation as refused.
- Check the lease epoch and fencing token lineage.
- Verify no later mutation was accepted under the stale token.

### AbuseIPDB outbox stuck

- List pending and failed reservations.
- Check the last error and `next_attempt_at`.
- Verify the lease guard is still valid before retrying.

### Cloudflare cursor corruption

- Compare the stored cursor with the last successfully processed high watermark.
- Reset only if the replay overlap window can absorb duplicates safely.

### SQLite corruption/quarantine

- Run integrity verification.
- Quarantine the database artifact.
- Stop mutation paths until the store is rebuilt or restored.

### Better Stack failure

- Continue local persistence and evidence capture.
- Do not block the control plane on telemetry sink failure.

### Cloudflare API timeout or rate limit

- Keep the run idempotent.
- Retry only through the existing bounded retry path.
- Confirm that cursor advancement did not happen on failure.

### Config load failure

- Check the config file path passed with `-config`.
- Verify `CF_API_TOKEN` and `CF_ZONE_ID` are present if the config file does not set them.
- Validate `STATE_DIR` points to a writable location for the service user.

### Replay divergence

- Compare checkpoint sequence, event sequence, and recovered state.
- Rebuild the timeline from evidence and lineage.

### Ownership conflict

- Inspect lineage, claim, and epoch state together.
- Fail closed until the authoritative owner is unambiguous.

## Useful commands

- `cf-sync -config /path/to/config.yaml -mode doctor`
- `cf-sync -config /path/to/config.yaml -mode status`
- `cf-sync -mode evidence list`
- `cf-sync -mode evidence search`
- `cf-sync -mode evidence show`
- `cf-sync -mode evidence explain`
- `cf-sync -mode ownership list`
- `cf-sync -mode ownership show`
- `cf-sync -mode ownership explain`
- `cf-sync -mode daemon`
- `cf-sync -dry-run=true`
- `journalctl -u cf-sync.service -n 200 --no-pager`

### Cleanup

- `cf-cleanup --dry-run`
- `cf-cleanup`

Run `cf-cleanup --dry-run` first. Dry-run lists the stale Cloudflare rules that would be deleted and does not call `DeleteIPAccessRule`. Only run the live command after reviewing the plan.

If a live cleanup run is interrupted, the process stops before the next destructive delete and returns a cancellation error. Re-run `cf-cleanup --dry-run` before resuming live cleanup.

`cf-allowlist-sync` is list-only and does not mutate Cloudflare.

## Release and cutover checklist

Use [RELEASE_CUTOVER_CHECKLIST.md](RELEASE_CUTOVER_CHECKLIST.md) for the final operator gate.

## GO/NO-GO checklist

- Python remains source of truth and rollback authority until the release/cutover checklist is explicitly complete.
- Local tests and local production proof are green.
- Dry-run runs are stable and explainable.
- `cf-cleanup --dry-run` has been reviewed before any live cleanup.
- Shadow mode is stable for the agreed duration and has no unexplained drift.
- Controlled authority is enabled only after validation and operator approval.
- Rollback to Python is rehearsed and documented.
- Emergency disable path is confirmed.
- SQLite backup and restore are rehearsed.
- Monitoring is confirmed for lease, cursor, outbox, evidence, and divergence events.
- Production cutover is not considered complete until the live host unit, env files, logs, and Cloudflare state confirm Go authority.
