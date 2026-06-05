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

**Action:** Create the directory and grant write access, or deploy the tmpfiles.d config:
```bash
install -d -m 0750 -o root -g root /var/log/security-automation
# Or:
systemd-tmpfiles --create /etc/tmpfiles.d/security-automation.conf
```

Startup logging is best-effort; the daemon runs regardless.

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
