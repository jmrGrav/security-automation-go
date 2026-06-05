# First Boot Procedure

## Pre-Boot: Environment File

Copy the example env file and fill in secrets before starting the service:

```bash
install -m 600 -o root -g root \
  /usr/share/doc/cf-sync/security-automation.env.example \
  /etc/security-automation/security-automation.env
# Or from the repo:
# cp deployments/config/security-automation.env.example \
#    /etc/security-automation/security-automation.env
chmod 600 /etc/security-automation/security-automation.env
```

Set at minimum:
- `CF_API_TOKEN` — Cloudflare API token
- `CF_ZONE_ID` — Cloudflare zone ID
- `CF_SYNC_API_TOKEN` — cf-sync admin API token
- `SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD` — plaintext password used **once**
  to create the bcrypt credential file; ignored on subsequent startups

Bind address and port can be overridden with `SECURITY_AUTOMATION_BIND_ADDR` and
`SECURITY_AUTOMATION_WEB_PORT` (both optional; default: `127.0.0.1:9091`).

## Startup Sequence

1. **Instance Lock Check**: System acquires a PID lock file at `/run/security-automation-go.pid`
   - If another instance is running, startup fails with the running process's PID
   - Prevents multiple instances from running simultaneously

2. **Port Availability Check**: System verifies the UI port (default 6969) is available
   - If port is in use, startup fails with the occupying process's PID and name
   - Operator must resolve the port conflict or change the UI port

3. **Bootstrap Password Initialization**: On first startup, the value of
   `SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD` is bcrypt-hashed and stored at
   `cfg.UI.AdminPasswordFile` (default `/etc/security-automation/secrets/admin_password`).
   If the credential file already exists this step is skipped.

4. **UI Server Starts**: The operator UI is now available at the configured address

## First Login

1. Operator navigates to the UI login page
2. Enters the bootstrap password
3. System verifies the password
4. Operator is redirected to **Settings → Security → Change Password**
5. Operator must change the password before accessing other pages
6. After successful password change:
   - Bootstrap flag is cleared
   - Operator gains full access to the UI
   - Old bootstrap password is no longer valid

## Subsequent Startups

1. Instance lock check (same as first boot)
2. Port availability check (same as first boot)
3. No password generation (already exists)
4. UI server starts with existing password configuration

## Failure Modes (Fail-Closed)

- **Instance lock held**: Startup fails, operator must stop the other instance manually
- **Port in use**: Startup fails, operator must change the port or resolve the conflict
- **Password file missing and env var empty**: Startup fails; set
  `SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD` in the env file and restart
- **No operator action taken**: System remains offline until operator intervenes

## No Automatic Recovery

The system does **not**:
- Automatically kill other processes
- Automatically restart
- Use default passwords
- Bypass authentication

All recovery requires explicit operator action.
