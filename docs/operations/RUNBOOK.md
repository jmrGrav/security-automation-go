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
   - `UI_ADDR=127.0.0.1:9091`
   - `UI_MUTATIONS_ENABLED=0` unless the operator has explicitly enabled
     mutations
   - `UI_SECRET_FILE=/var/lib/security-automation-go/secrets.local`
2. Confirm the local secret file exists or can be created by the service user
   and is `0600`.
3. Confirm provider keys are configured only through the UI and are stored in
   encrypted SQLite; do not paste them into logs, docs, or evidence.
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

## Service restart after first-run wizard

When `cf-sync -mode ui` starts **before** the first-run wizard is complete, the
service enters a wizard-wait loop and does not initialise background
orchestration (scheduler, Cloudflare sync). The UI is still served on port 9091
and the wizard can be completed normally, but the orchestration does not start
automatically once setup is marked done.

**Action required after completing the wizard for the first time:**

```bash
sudo systemctl restart cf-sync
```

After the restart, the service detects the completed setup state, loads all
credentials from the encrypted store, and starts the full orchestration
alongside the operator console.

This behaviour is by design: the service reads setup state once at startup to
decide which code path to execute. The wizard completion handler logs the
following message to journald as a reminder:

```
level=INFO msg="setup complete — restart cf-sync to enable background orchestration"
```

You can confirm orchestration is running by checking that port 9092 (metrics /
API server) is listening:

```bash
ss -tlnp | grep 9092
```

## /run/crowdsec-lua permissions — restart required after group changes

`cf-sync` (running as the unprivileged `security-automation` user) exchanges
files with the OpenResty/Lua CrowdSec bouncer (running as `www-data`) via the
shared runtime directory `/run/crowdsec-lua` — `bans.json` (written by
cf-sync, read by Lua) and `events.jsonl` / `waf_refs.jsonl` (written by Lua,
read and atomically renamed by cf-sync's `openrestyevent.LiveSource`). That
directory is `root:www-data 0775` — group `www-data` has read/write,
everyone else has read-only. The package's `postinst` adds
`security-automation` to the `www-data` group (`usermod -aG www-data
security-automation`) specifically so the rename in `LiveSource` is
permitted, without granting `cf-sync` any broader access than that one
shared directory.

**Linux does not re-evaluate a running process's supplementary groups.** A
process keeps the group list it had at `exec()` time for its entire
lifetime — `usermod -aG` only affects *new* processes/sessions started after
it runs. If `cf-sync` was already running when the `www-data` group
membership was added or changed (e.g. across an upgrade, or because the
service was started before `postinst` ran on a fresh install), the running
process keeps stale credentials and `LiveSource` fails with `permission
denied` on every rename — even though `id security-automation` correctly
shows `www-data` as a supplementary group.

**Action required after any change to `security-automation`'s group
membership** (fresh install, upgrade, or manual `usermod`):

```bash
sudo systemctl restart cf-sync
```

**Verify the fix took effect** — group membership of the actual running
process must include `www-data` (gid 33), not just the user account:

```bash
sudo cat /proc/$(systemctl show cf-sync -p MainPID --value)/status | grep ^Groups
journalctl -u cf-sync --since "2 min ago" | grep "openresty live source read failed" # should be empty after restart
```

## Admin password reset and account recovery

All admin commands require local root access (`sudo`).

### Reset the admin password (without recovery key)

Use when you know root access is available and want to force a password change:

```bash
sudo cf-sync -mode admin reset-password
```

This generates a temporary password, prints it to stdout once, sets
`password_change_required=true`, and invalidates all active UI sessions by
incrementing the auth epoch. The next UI login must use the temporary password;
the UI will immediately require setting a new permanent password.

The temporary password is **never** written to journald, SQLite, or log files.

### Create a recovery key

Run once, immediately after initial setup, and store the key in a password
manager or physical safe:

```bash
sudo cf-sync -mode admin recovery-key create
```

The key (43-character base64) is printed to stdout once. Only its bcrypt hash
(cost 12) is stored in the database. If the key is lost, rotate it (see below).

### Rotate the recovery key

Replaces the current recovery key with a new one. The old key is immediately
invalidated:

```bash
sudo cf-sync -mode admin recovery-key rotate
```

### Recover access using the recovery key

When the admin password is lost and you have the recovery key:

```bash
sudo cf-sync -mode admin recover
```

You will be prompted for the recovery key (input is masked). On success, a new
temporary password is printed to stdout once and `password_change_required` is
set. Log in with the temporary password and change it immediately.

### Security invariants

- Admin passwords are stored as bcrypt (cost 12). Never in plaintext.
- Recovery key: only bcrypt hash (cost 12) stored in SQLite. Plaintext shown once, never again.
- `show-password`, `export-password`, and `decrypt-password` are not implemented and must not be added.
- All admin CLI operations require root (`os.Getuid() == 0`).
- Session invalidation via `auth_epoch`: the running UI server detects the epoch
  change on the next session check (no restart required).

## Pre-release smoke tests (v1.6.0+)

These tests run on your local machine against a live instance. They are **never run in CI**.

### What they verify

- Browser login, session cookie attributes, logout
- All authenticated pages render (200, no panic, no JS errors)
- No raw API tokens leak into any page
- Cross-page coherence: Health ↔ Dashboard ↔ Cloudflare Diff ↔ Providers
- Admin recovery CLI (with explicit confirmation flag)

### How to run

```bash
# 1. Read admin password without logging it
read -rsp "Admin password: " SMOKE_ADMIN_PASSWORD && export SMOKE_ADMIN_PASSWORD

# 2. Run (requires a live cf-sync with UI_ENABLED=1 on 127.0.0.1:9091)
SECURITY_AUTOMATION_SMOKE_LIVE=1 ./scripts/smoke-ui-runtime.sh
```

The script:
1. Runs `go test ./...` as a pre-flight gate
2. Builds the binary
3. Checks UI reachability
4. Installs Playwright + Chromium (first run only)
5. Runs all browser smoke tests
6. Writes `SMOKE_TEST_REPORT.md` (gitignored)

### Admin CLI smoke (destructive — explicit opt-in required)

```bash
SECURITY_AUTOMATION_SMOKE_LIVE=1 \
SMOKE_ADMIN_RESET_CONFIRM=1 \
SMOKE_ADMIN_PASSWORD=... \
./scripts/smoke-ui-runtime.sh
```

`SMOKE_ADMIN_RESET_CONFIRM=1` enables tests that rotate the recovery key and reset
the admin password. These modify the database. Only run if you know the current
admin password and can re-login after the test.

### Security constraints

- The admin password is read from `SMOKE_ADMIN_PASSWORD` — never logged or printed
- Screenshots on failure go to `/tmp/security-automation-smoke/` — **never committed**
- `SMOKE_TEST_REPORT.md` is gitignored — **never committed**
- No provider tokens, credentials, or DB content are included in the report
- Tests are read-only for all providers except the login/logout session

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
