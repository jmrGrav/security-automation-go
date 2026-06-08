# First Boot Procedure

## Bootstrap files

Create the minimal non-secret bootstrap env file before starting the service:

```bash
install -d -m 755 -o root -g root /etc/security-automation-go
install -m 644 -o root -g root /dev/null /etc/security-automation-go/security-automation.env
```

Use it only for bootstrap values such as bind address, port, and `state_dir`.
Do not place operator tokens here.

## Startup sequence

1. **Instance lock check**: the process acquires a PID lock file at
   `/run/security-automation-go.pid`.
2. **Bootstrap config load**: the service reads
   `/etc/security-automation-go/security-automation.env`.
3. **SQLite startup**: the runtime database is created or opened in
   `/var/lib/security-automation-go/runtime.db`.
4. **Master key check**: the local key at
   `/var/lib/security-automation-go/secret.key` is generated if needed.
5. **UI secret initialization**: the one-time UI setup secret is created at
   `/var/lib/security-automation-go/runtime/ui_secret` on first boot, and the
   separate setup password file is created at
   `/var/lib/security-automation-go/runtime/initial-admin-password`.
6. **UI server starts**: the operator UI listens on the configured address.

## First login

1. Operator navigates to `/login`.
2. Enters the one-time UI setup secret.
3. System verifies the setup secret.
4. Operator is redirected to the setup wizard.
5. Operator completes setup and sets a permanent password.

## Wizard behavior

- Provider credentials are optional.
- If a token is entered, it is stored in encrypted SQLite.
- If a token is skipped, setup continues.
- Production mode remains disabled until Cloudflare token and Zone ID exist in
  the credential store.

## Subsequent startups

1. Instance lock check.
2. Bootstrap config load.
3. SQLite startup and migrations.
4. If `setup_complete=true`, the wizard is not forced again.
5. UI starts with existing settings and credentials.

## Failure modes

- Instance lock held: startup fails until the other process stops.
- Port in use: startup fails until the operator changes the port or stops the
  conflicting process.
- Master key missing while encrypted credentials exist: fail closed with a clear
  operator error.

## Migration and reset

- Legacy `/etc/security-automation-go/secrets/` files are import-only.
- Existing SQLite state is preserved on upgrade.
- To reset the whole installation, remove the runtime DB and bootstrap password
  file, then restart.
