# First Boot Guide

## Prerequisites

- Binary installed: `/usr/local/bin/cf-sync`
- Systemd unit enabled: `sudo systemctl enable cf-sync`
- State directory writable by the service user

## Starting the Service

```bash
sudo systemctl start cf-sync
sudo systemctl status cf-sync
```

On first start, the service:
1. Creates `/var/lib/security-automation-go/runtime/ui_secret` (mode 0600)
2. Creates `/var/lib/security-automation-go/runtime/initial-admin-password` (mode 0600)
3. Writes a random one-time UI setup secret to `ui_secret` and a separate one-time setup password to `initial-admin-password` — **neither is logged**
4. Starts the UI on `127.0.0.1:9091` (default) in setup-required mode
5. Blocks all normal routes until setup is complete

## Starting the UI

The setup wizard runs in UI mode, which is separate from the background daemon:

```bash
sudo /usr/local/bin/cf-sync -mode ui -config /etc/security-automation-go/cf-sync.yaml
```

Or if using the systemd UI unit:

```bash
sudo systemctl start cf-sync-ui
```

**Note:** The standard `cf-sync.service` runs the background daemon (`-mode daemon`). The setup wizard requires a separate invocation of `-mode ui` on the same binary. Both share the same SQLite state directory.

## Reading the Setup Secrets

```bash
sudo cat /var/lib/security-automation-go/runtime/ui_secret
sudo cat /var/lib/security-automation-go/runtime/initial-admin-password
```

Copy the UI secret for step 1 of the setup wizard. The initial password is used in step 2 to set the permanent admin password.

The initial password is invalidated (file truncated) automatically after you set a new admin password in step 2.

## Opening the Setup Wizard

Open a browser (or SSH tunnel) to: http://127.0.0.1:9091/

You will be redirected to `/setup/step/1`.

## Resetting First Boot

If you need to start the wizard over:

```bash
sudo systemctl stop cf-sync
sudo rm /var/lib/security-automation-go/runtime/initial-admin-password
# Remove the SQLite DB to reset setup state:
sudo rm -f /var/lib/security-automation-go/<scope-dir>/runtime.db
sudo systemctl start cf-sync
```

## SSH Tunneling

If the server has no graphical browser:

```bash
ssh -L 9091:127.0.0.1:9091 user@server
```

Then open http://localhost:9091/ on your local machine.
