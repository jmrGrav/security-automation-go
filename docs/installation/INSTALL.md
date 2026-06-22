# Installation

## Install layout

```
/etc/security-automation-go/
  security-automation.env       # non-secret bootstrap config
  providers/
    ai-providers.env            # non-secret provider state

/var/lib/security-automation-go/
  runtime.db                    # encrypted SQLite (credentials + state)
  secret.key                    # local master key (mode 0600)
  runtime/
    ui_secret                   # one-time UI setup secret (mode 0600)
    initial-admin-password      # first-run wizard password (mode 0600)

/usr/local/bin/
  cf-sync                       # main orchestrator
  crowdsec-sync
  cf-allowlist-sync
  cf-cleanup
```

## Debian package

```bash
sudo dpkg -i security-automation-go_<version>_amd64.deb
```

Installs binaries, systemd units, and the package triggers `systemctl daemon-reload`.

## Manual install

```bash
# Install binaries
sudo install -m 755 -o root -g root bin/cf-sync /usr/local/bin/
# ... other binaries

# Bootstrap config
sudo install -d -m 755 -o root -g root /etc/security-automation-go
sudo install -m 644 -o root -g root /dev/null /etc/security-automation-go/security-automation.env

# State directory
sudo install -d -m 750 -o security-automation -g security-automation /var/lib/security-automation-go
```

## First boot

See [FIRST_BOOT.md](FIRST_BOOT.md) for the initial setup procedure and wizard walkthrough.

## Packaging

See [PACKAGING.md](PACKAGING.md) for build-time packaging details.
