# Python Legacy Summary

## What Python did

The original Python 3.6 implementation (`crowdsec-cf-sync`) was a monolithic script that:

- Polled CrowdSec decisions and synced bans to Cloudflare Access Rules
- Managed an allowlist of trusted networks
- Sent metrics and audit events to BetterStack
- Provided basic reporting via cron-driven scripts

## What Go replaced

The Go rewrite (this repository) replaced all Python functionality and added:

- Encrypted credential storage (SQLite, not flat files)
- Local operator UI with wizard, audit trail, and provider management
- Shadow mode for safe migration (reads decisions, writes nothing to Cloudflare)
- MCP server for AI-assisted forensic lookup
- CrowdSec integration via the LAPI client
- AbuseIPDB enrichment
- Full systemd integration with multiple service units

## Python script location

The original Python scripts are in a separate repository (`crowdsec-cf-sync`). They are no longer the operational source of truth. The Go runtime (`cf-sync`) runs in their place.

## Remaining backlog items

None blocking production use. The Go runtime achieves full feature parity with the Python implementation.

## Migration

If running a legacy Python installation, switch to Go:

1. Stop the Python cron jobs or service.
2. Install the Go package (`dpkg -i security-automation-go_*.deb`).
3. Run the first-boot wizard.
4. Import any legacy credentials via `/admin/providers/import-legacy` in the UI.
5. Enable production mode once Cloudflare token and Zone ID are in the credential store.
