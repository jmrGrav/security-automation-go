# security-automation-go

![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)
![CI](https://github.com/jmrGrav/security-automation-go/actions/workflows/ci.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/jmrGrav/security-automation-go)
![License](https://img.shields.io/github/license/jmrGrav/security-automation-go)

Go control-plane that synchronises [CrowdSec](https://crowdsec.net/) decisions to
[Cloudflare](https://www.cloudflare.com/), reports abusive IPs to
[AbuseIPDB](https://www.abuseipdb.com/), and drives WAF follow-up actions.

**Status: v1.5.0** — first-run wizard, encrypted CredentialStore, CrowdSec Go integration. Production-ready.

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
make package         # dist/security-automation-go_1.5.0_amd64.deb
```

## Quick install

```bash
sudo dpkg -i security-automation-go_1.5.0_amd64.deb
sudo systemctl start cf-sync
# First-run wizard opens automatically on first browser access
```

## Security

All credentials are stored in the encrypted CredentialStore (SQLite AES-GCM). Nothing sensitive is in flat files or environment variables at runtime.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Documentation

→ [docs/README.md](docs/README.md)

## License

[Apache-2.0](LICENSE).
