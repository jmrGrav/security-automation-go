# UI Configuration

## Configuration File

UI settings are specified in the YAML configuration file:

```yaml
ui:
  enabled: true
  addr: "127.0.0.1:6969"
  mutations_enabled: false
  secret_file: "/var/lib/security-automation-go/runtime/ui_secret"
  initial_password_file: "/var/lib/security-automation-go/runtime/initial-admin-password"
  provider_state_file: "/var/lib/security-automation-go/runtime/ai-providers.env"
```

## Environment Variables

All settings can be overridden via environment variables:

| Variable | Type | Default |
|----------|------|---------|
| `UI_ENABLED` | bool | false |
| `UI_ADDR` | string | `127.0.0.1:6969` |
| `UI_MUTATIONS_ENABLED` | bool | false |
| `UI_SECRET_FILE` | string | `/var/lib/security-automation-go/runtime/ui_secret` |
| `UI_INITIAL_PASSWORD_FILE` | string | `/var/lib/security-automation-go/runtime/initial-admin-password` |
| `UI_PROVIDER_STATE_FILE` | string | `/var/lib/security-automation-go/runtime/ai-providers.env` |

## Port Configuration

### Default Port

The default UI port is `6969`.

### Custom Port

To use a different port, set the `UI_ADDR` variable:

```bash
export UI_ADDR=127.0.0.1:8080
```

Or in the config file:

```yaml
ui:
  addr: "127.0.0.1:8080"
```

### Port Binding Warnings

If the UI server binds to a non-loopback address (e.g., `0.0.0.0:6969`), a warning is logged:

```
ui server binding to non-loopback address — restrict access at the network level
```

This is intentional; the operator is responsible for network-level access control.

## Single-Instance Guarantee

The system uses a PID lock file to ensure only one instance runs at a time.

**Lock file location:** `/run/security-automation-go.pid`

If you attempt to start a second instance:

```
another instance (PID 12345) is running
```

To start a new instance:

1. Stop the running instance: `kill 12345`
2. Wait a few seconds (if needed)
3. Start the new instance

The lock file is automatically cleaned up on graceful shutdown.

## Troubleshooting

### "Port already in use"

```
UI port 6969 already in use.

PID: 5432
Process: python
```

**Resolution:**
- Change the UI port: `export UI_ADDR=127.0.0.1:7000`
- Or stop the conflicting process: `kill 5432`

### "Another instance is running"

```
another instance (PID 12345) is running
```

**Resolution:**
- Stop the other instance: `kill 12345`
- Wait a few seconds
- Restart this instance

### Bootstrap password not working

Verify the password file exists and is readable:

```bash
ls -l /var/lib/security-automation-go/runtime/initial-admin-password
cat /var/lib/security-automation-go/runtime/initial-admin-password
```

The file contains the initial one-time bootstrap password used during first
boot.

## UI routes

- `/` Dashboard
- `/providers` Provider Management
- `/forensic` Forensic lookup
- `/audit` Audit Trail
- `/intelligence` Security Intelligence (read-only)
- `/trusted-networks` Trusted Networks Explorer (read-only)
