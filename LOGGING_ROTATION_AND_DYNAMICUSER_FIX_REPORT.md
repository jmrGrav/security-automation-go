# Logging Rotation and DynamicUser Fix Report

**Date:** 2026-06-06  
**Branch:** main  
**Status:** COMPLETE — two pre-cutover bugs fixed, both empirically verified

---

## Summary

Two bugs were found in the T7/T8 startup logging integration before production cutover.
Neither affected the currently running shadow service (which uses `User=root`), but both
would have caused failures on a fresh install using the committed systemd template
(`DynamicUser=yes`) or on every logrotate run on any deployment.

---

## Bug 1: logrotate postrotate sends SIGUSR1 — kills the daemon

### Problem

`deployments/config/logrotate` (installed to `/etc/logrotate.d/security-automation`)
contained:

```
sharedscripts
postrotate
    systemctl kill --kill-who=main --signal=SIGUSR1 cf-sync.service 2>/dev/null || true
endscript
```

**cf-sync does not register a SIGUSR1 handler.** Grep confirms:

```
$ grep -r "SIGUSR1\|USR1" cmd/cf-sync/ internal/
(no matches)
```

`cmd/cf-sync/daemon_runtime.go` and `cmd/cf-sync/ui_runtime.go` call `signal.Notify`
only for `SIGINT` and `SIGTERM`.

**POSIX default action for SIGUSR1 is `Term` (terminate the process).** In Go, signals
that are not registered via `signal.Notify` receive the OS default disposition. Sending
SIGUSR1 to cf-sync would terminate the daemon on every logrotate run. The `|| true`
suppresses the exit code of `systemctl kill`, not the effect on the running process.

Additionally, even if a SIGUSR1 handler and `Logger.Reopen()` were implemented, the
standard rotate-rename-create strategy would conflict with `DynamicUser=yes`: the new
file created by logrotate's `create 0640 root root` directive would be root-owned, and
the dynamic user could not write to it.

### Fix

Replace `postrotate`+SIGUSR1 with `copytruncate`. Under this strategy:

1. logrotate copies the log content to the rotated file (e.g., `startup.log.1`)
2. logrotate truncates the original `startup.log` to zero bytes **in place** — same inode, same fd
3. The daemon's open `O_APPEND` file descriptors remain valid
4. The next `Fprintf` write atomically seeks to end (position 0 after truncation) and writes there

No signal, no file reopen, no handler needed.

Also removed: `create 0640 root root` (copytruncate does not create new files) and
`sharedscripts` (irrelevant without a postrotate block).

### Regression test

`internal/startuplog/log_test.go::TestLogger_CopyTruncate_WritesAfterTruncate` proves
the O_APPEND + copytruncate invariant:

```
=== RUN   TestLogger_CopyTruncate_WritesAfterTruncate
--- PASS: TestLogger_CopyTruncate_WritesAfterTruncate (0.00s)
```

The test:
1. Opens a Logger and writes a startup record (`mode=before-rotate`)
2. Truncates `startup.log` to zero (simulating logrotate copytruncate)
3. Writes another record (`mode=after-rotate`) without reopening
4. Asserts the file contains only the post-truncate write

### Deployed logrotate updated

`/etc/logrotate.d/security-automation` was updated to the fixed config.
Dry-run verification:

```
$ sudo logrotate -d /etc/logrotate.d/security-automation
rotating pattern: /var/log/security-automation/*.log  after 1 days (14 rotations)
empty log files are not rotated, old logs are removed
considering log /var/log/security-automation/startup.log
  ...
  log does not need rotating (log has been rotated at 2026-06-06 00:00, …)
```

No errors; no postrotate script; no SIGUSR1.

---

## Bug 2: DynamicUser=yes cannot write to root:root 0750 log directory

### Problem

`deployments/systemd/cf-sync.service` (the committed template) uses `DynamicUser=yes`
and `ProtectSystem=strict` but has no `LogsDirectory=` directive. The log directory
`/var/log/security-automation` was created by `tmpfiles.conf` as `root:root 0750` and
by `ExecStartPre=+/bin/install … -o root -g root` in the deployed unit.

A DynamicUser (transient UID in range ~60000-65535) cannot write to a `root:root 0750`
directory. `startuplog.New()` would return an error at `os.MkdirAll` or file open,
and the daemon would print:

```
Warning: startup logging unavailable: startuplog: create log dir "/var/log/security-automation": ...
```

**The deployed unit (`/etc/systemd/system/cf-sync.service`) uses `User=root`** and is
unaffected — it runs correctly and was not changed.

### Fix

Add `LogsDirectory=security-automation` and `LogsDirectoryMode=0750` to the committed
template. This is systemd's native mechanism for DynamicUser log directories:

- systemd creates `/var/log/private/security-automation` owned by the dynamic UID
- `/var/log/security-automation` is created as a symlink → `private/security-automation`
- The dynamic user has `rwx` on the private directory and can write log files
- This access is granted even under `ProtectSystem=strict` — no `ReadWritePaths=` needed

### Empirical proof

Throwaway unit `logtest-dynamicuser.service` with identical settings (`DynamicUser=yes`,
`LogsDirectory=logtest-dynamicuser`, `LogsDirectoryMode=0750`) was started and verified:

```
$ sudo stat /var/log/private/logtest-dynamicuser
  Accès : (0750/drwxr-x---)  UID : (64249/ UNKNOWN)  GID : (64249/ UNKNOWN)

$ sudo cat /var/log/private/logtest-dynamicuser/proof.log
uid=64249(logtest-dynamicuser) gid=64249(logtest-dynamicuser) groupes=64249(logtest-dynamicuser) wrote this
```

Dynamic UID 64249 successfully created and wrote to the log file. The throwaway unit
and its artifacts were removed after verification.

### Interaction with tmpfiles.conf

`deployments/config/tmpfiles.conf` creates `/var/log/security-automation` on boot as a
real directory (`root:root 0750`). When the service with `LogsDirectory=` starts,
systemd chowns the existing directory to the dynamic user — so both mechanisms are
compatible. The tmpfiles.conf entry remains as a safety net for systems running the
`User=root` variant or where the service has never been started.

---

## Files Changed

| File | Change |
|------|--------|
| `deployments/config/logrotate` | Removed `create`, `sharedscripts`, `postrotate`/SIGUSR1 block; added `copytruncate` |
| `deployments/systemd/cf-sync.service` | Added `LogsDirectory=security-automation` and `LogsDirectoryMode=0750` under `# Paths` |
| `internal/startuplog/log_test.go` | Added `TestLogger_CopyTruncate_WritesAfterTruncate` |
| `docs/operations/STARTUP_WARNINGS.md` | Added copytruncate strategy section; clarified DynamicUser action for startup logging warning |
| `/etc/logrotate.d/security-automation` | Deployed: same as template fix |

---

## Validation

```
go test ./internal/startuplog/... -v -run TestLogger_CopyTruncate
=== RUN   TestLogger_CopyTruncate_WritesAfterTruncate
--- PASS: TestLogger_CopyTruncate_WritesAfterTruncate (0.00s)
ok  	github.com/jm/security-automation-go/internal/startuplog	0.007s

go test ./...
(all packages PASS, zero FAIL)

sudo logrotate -d /etc/logrotate.d/security-automation
(reads config cleanly, no SIGUSR1 entry, no errors)

sudo cat /var/log/security-automation/startup.log
2026-06-05T21:04:11Z startup version= mode=daemon bind= config=/etc/security-automation-go/cf-shadow.yaml db=/var/lib/cf-sync dry_run=true providers=[]
(live service unaffected, writing normally as User=root)
```

---

## Strict Rules Compliance

- No real secrets, tokens, Zone IDs, or personal emails committed ✓
- Python service not stopped ✓
- Go daemon remains in dry-run mode ✓
- No release tag created ✓
- SQLite WAL persistence untouched ✓
- Deployed unit (`User=root`) not migrated to DynamicUser ✓
- All existing tests still pass ✓
