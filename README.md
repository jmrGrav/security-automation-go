# security-automation-go

![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)
![CI](https://github.com/jmrGrav/security-automation-go/actions/workflows/ci.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/jmrGrav/security-automation-go)
![License](https://img.shields.io/github/license/jmrGrav/security-automation-go)

Go control-plane that synchronises [CrowdSec](https://crowdsec.net/) decisions to
[Cloudflare](https://www.cloudflare.com/), reports abusive IPs to
[AbuseIPDB](https://www.abuseipdb.com/), and drives WAF follow-up actions.

**Status: v1.7.7** — Unified v2 shell with collapsible sidebar (BetterStack-style 218px/66px, localStorage persist, smooth CSS transition), SVG nav icons replacing colored dots, full design system token set (`.v2-card`, `.v2-kpi`, `.v2-pill`, `.v2-banner`, `.v2-table`). Dashboard and Trusted Networks migrated to the single `v2Page()` shell — no more split identity between pages. Fixed ✦ Ask AI button in Timeline row details (JS click handler, inline result panel, CSRF threading). Built on v1.7.7: complete UI v2 operator console (PR1–PR6 + SOC sprint): SOC command center, threat visualization, Timeline Live Tail, Providers, Focus Incident, Notes, Audit trail, Ctrl+K command palette, Timeline histogram filters, contextual hints, live relative timestamps, skeleton loading, cross-page back-navigation. Reputation-gated Cloudflare ban lifecycle, hub-and-spoke Trusted Networks registry. Production-ready.

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
make package         # dist/security-automation-go_1.7.7_amd64.deb
```

## Quick install

Download the latest `.deb` from [Releases](https://github.com/jmrGrav/security-automation-go/releases):

```bash
curl -LO https://github.com/jmrGrav/security-automation-go/releases/download/v1.7.7/security-automation-go_1.7.6_amd64.deb
curl -LO https://github.com/jmrGrav/security-automation-go/releases/download/v1.7.7/SHA256SUMS
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
