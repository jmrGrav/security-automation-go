# Startup Warnings Reference

This document lists warnings that cf-sync emits at startup and what to do about them.

## Warning: could not read /etc/security-automation/security-automation.env

```
Warning: could not read /etc/security-automation/security-automation.env: open ...: permission denied
```

**Cause:** The env file exists but is not readable by the process user.

**Action:** Fix permissions:
```bash
chmod 600 /etc/security-automation/security-automation.env
chown root:root /etc/security-automation/security-automation.env
```

The env file not existing is silently ignored (it is optional).

---

## Warning: startup logging unavailable

```
Warning: startup logging unavailable: startuplog: create log dir "/var/log/security-automation": ...
```

**Cause:** The log directory cannot be created or written to.

**Action (User=root deployment):** Create the directory or deploy the tmpfiles.d config:
```bash
install -d -m 0750 -o root -g root /var/log/security-automation
# Or:
systemd-tmpfiles --create /etc/tmpfiles.d/security-automation.conf
```

**Action (DynamicUser=yes deployment):** Ensure the unit file contains `LogsDirectory=security-automation`. systemd creates and chowns `/var/log/security-automation` to the dynamic user before ExecStart runs. No manual directory creation is required.

Startup logging is best-effort; the daemon runs regardless.

---

## Log rotation strategy (copytruncate)

cf-sync holds file handles to the startup log files open for the lifetime of the process. Standard logrotate rotation (rename + create) would leave the daemon writing to the renamed inode.

The deployed logrotate config uses `copytruncate` instead of a `postrotate` SIGUSR1 signal. Under `copytruncate`, logrotate copies the log content to the rotated file, then truncates the original to zero in place. The daemon's open `O_APPEND` file descriptors remain valid — the next write goes to position 0 of the now-empty original file. No SIGUSR1 handler is needed.

**Why not SIGUSR1?** Go programs that do not call `signal.Notify(ch, syscall.SIGUSR1)` receive the OS default action for SIGUSR1, which is **process termination** (POSIX `Term` disposition). Sending SIGUSR1 to cf-sync without a handler would kill the daemon on every logrotate run.

---

## Warning: Failed to initialize tracing

```
Warning: Failed to initialize tracing: ...
```

**Cause:** Tracing was enabled in the config but the OTLP exporter endpoint is
unreachable or misconfigured.

**Action:** Check `global.tracing.endpoint` in your config file, or disable tracing
with `global.tracing.enabled: false`.

---

## Error: bootstrap admin password

```
Error: bootstrap admin password: SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD is empty and no admin credential exists at ...
```

**Cause:** UI mode was started for the first time without setting an initial password.

**Action:** Set `SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD` in the env file and restart:
```ini
SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD=<your-secure-password>
```

After first boot, this variable is ignored — change the password via the UI.
