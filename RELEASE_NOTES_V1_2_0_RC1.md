## v1.2.0-rc1 — Production hardening and operational stability

Security and operational hardening release candidate.

### Security improvements

- **CF_SYNC_API_TOKEN_FILE**: file-backed admin token with fail-closed semantics. File path takes precedence over the env-var value; a missing or empty file is a startup error, not a fallback.
- **Bootstrap password E2E test**: `TestFirstBootEndToEnd` proves the initial admin password is stored as a bcrypt hash — no plaintext in the database at any point, idempotent across restarts.
- **CSRF coverage confirmed**: all 10 POST mutation handlers verified to carry CSRF protection (verification pass, not a new fix).

### Operational improvements

- **logrotate strategy**: replaced SIGUSR1 rotation with `copytruncate`. Go does not reopen file descriptors on SIGUSR1, making the previous strategy a no-op.
- **DynamicUser logging fix**: `LogsDirectory=security-automation` added to the systemd unit template. Without it, `DynamicUser=yes` causes permission failures on the log directory at startup.
- **Startup logging subsystem**: `internal/startuplog` writes structured startup diagnostics before journald buffering begins, making early-boot failures visible.
- **Environment file support**: `EnvironmentFile=-/etc/security-automation/security-automation.env` added to the systemd unit. The `-` prefix makes the file optional so the unit starts cleanly when the file is absent.

### Configuration additions

| Variable | Purpose |
|---|---|
| `CF_SYNC_API_TOKEN_FILE` | Path to file containing the admin API token (takes precedence over `CF_SYNC_API_TOKEN`) |
| `SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD` | First-boot bootstrap password; hashed and stored; ignored on subsequent starts |
| `SECURITY_AUTOMATION_BIND_ADDR` | Override the API bind address (default `127.0.0.1`) |
| `SECURITY_AUTOMATION_WEB_PORT` | Override the API port (default `9090`) |

### Tests added

- `TestResolveAdminToken` — 5 subtests covering file token precedence, env-var fallback, missing file, empty file, and whitespace trimming.
- `TestNewAuthenticator/with_file_token` — daemon authenticator correctly loads token from file at startup.
- `TestNewAuthenticator/file_missing_fails_startup` — daemon authenticator returns an error (not a default) when the file path is set but the file is absent.
- `TestFirstBootEndToEnd` — full lifecycle: set env var, start daemon, confirm bcrypt hash in DB, confirm no plaintext, confirm idempotency, confirm restart safety.
- `TestConfigPrecedenceLayerOrdering` — 3-layer override chain: defaults < YAML file < env vars, verified in order.

### Documentation

- `docs/runbooks/FIRST_BOOT.md`: `CF_SYNC_API_TOKEN_FILE` added to the pre-boot environment variable list.
- `SECURITY.md`: file-backed token documented in the secret handling section; contact address updated.
- `docs/runbooks/CUTOVER_RUNBOOK.md`: service name corrected from `crowdsec-sync-go.service` to `cf-sync.service`; inline unit block updated to match the deployed template.
- `TODO.md`: all tracked items from v1.1.1 and v1.2 resolved.

### Validation

All five gates pass:

- `gofmt` — clean
- `go vet ./...` — clean
- `go build ./...` — clean
- `go test ./...` — PASS
- `go test -race ./...` — PASS

### Known limitations (pre-existing)

- `internal/cloudflare/transport` and `internal/crowdsec/adapter` have no unit tests.
- ModSecurity CF ban and recidive escalation are not yet ported from Python.
- Lua `bans.json` push remains in Python (nginx enforcement layer).

### Upgrade notes

1. Ensure `LogsDirectory=security-automation` is present in the systemd unit. It is included in `deployments/systemd/cf-sync.service` as of this release.
2. Optionally migrate from `CF_SYNC_API_TOKEN` to `CF_SYNC_API_TOKEN_FILE` for improved secret hygiene (env var remains supported).
3. Set `SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD` in the env file for first-boot bootstrap on new deployments.

---

**Operational note:**
CF_SYNC_API_TOKEN or CF_SYNC_API_TOKEN_FILE is required before daemon startup. Shadow soak must be complete (≥99.9% agreement) before production cutover. Follow `docs/runbooks/CUTOVER_RUNBOOK.md`.
