# security-automation-go

![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)
![CI](https://github.com/jmrGrav/security-automation-go/actions/workflows/ci.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/jmrGrav/security-automation-go)
![License](https://img.shields.io/github/license/jmrGrav/security-automation-go)

Go control-plane that synchronises [CrowdSec](https://crowdsec.net/) decisions to
[Cloudflare](https://www.cloudflare.com/), reports abusive IPs to
[AbuseIPDB](https://www.abuseipdb.com/), and drives WAF follow-up actions.

**Status: v1.7.6** — Complete UI v2 operator console (PR1–PR6 + SOC sprint + v1.7.6 polish): performance baseline, SOC command center, threat visualization, visual identity, operator productivity (watchlist, keyboard nav, recently viewed), and advanced investigation (correlated timeline, operator notes, focus incident). Full v2 dark shell at `/v2/` with animated login loader, sidebar workflow navigation (Observe / Investigate / Infrastructure / Operations), Timeline Live Tail, Providers integrations page, Focus Incident, Notes, Audit trail. Ctrl+K command palette with IP/ASN/provider routing + recent-IPs. Timeline histogram clickable time-range filters, contextual "why it matters" hints, ✦ AI explain trigger, live relative timestamps (freshness.js), skeleton loading states, cross-page back-navigation. Reputation-gated Cloudflare ban lifecycle, hub-and-spoke Trusted Networks registry. Production-ready.

## Architecture

```
cmd/cf-sync            orchestrator daemon + operator UI
  └── internal/orchestrator/pipeline   admission → discovery → planning → execution → reporting
  └── internal/cloudflare/             Cloudflare REST + GraphQL
  └── internal/crowdsec/               CrowdSec LAPI + detection
  └── internal/abuseipdb               AbuseIPDB reporting
  └── internal/storage/sqlite          WAL-scoped SQLite + encrypted CredentialStore (AES-GCM)
  └── internal/ui                      operator web UI, first-run wizard, health center
  └── internal/health, internal/detect health checks + auto-discovery
```

## Build & verify

```bash
go build ./...
go vet ./...
gofmt -l .
go test ./...
go test -race ./...
make package         # dist/security-automation-go_1.7.6_amd64.deb
```

## Quick install

Download the latest `.deb` from [Releases](https://github.com/jmrGrav/security-automation-go/releases):

```bash
curl -LO https://github.com/jmrGrav/security-automation-go/releases/download/v1.7.6/security-automation-go_1.7.6_amd64.deb
curl -LO https://github.com/jmrGrav/security-automation-go/releases/download/v1.7.6/SHA256SUMS
sha256sum -c SHA256SUMS
sudo dpkg -i security-automation-go_1.7.6_amd64.deb
sudo systemctl start cf-sync
```

1. Open your browser: `http://127.0.0.1:9091/setup/step/1`
2. Create your administrator password (step 1 — stored as bcrypt in SQLite, no plaintext).
3. Follow the 9-step wizard to configure Cloudflare, CrowdSec, and AI providers.
4. Credentials are encrypted and stored in SQLite.

**Ports:** UI listens on `127.0.0.1:9091`, metrics on `127.0.0.1:9092`.

## Security

All credentials are stored in the encrypted CredentialStore (SQLite AES-GCM). Nothing sensitive is in flat files or environment variables at runtime.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Documentation

→ [docs/README.md](docs/README.md)

## License

[Apache-2.0](LICENSE).
