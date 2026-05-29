# Security Policy

`security-automation-go` is the Go successor to the production Python security
automation stack that synchronises CrowdSec decisions to Cloudflare, reports to
AbuseIPDB, and manages WAF follow-up actions. It runs with privileged access to:

- a Cloudflare API token (firewall access rules, rules lists, GraphQL analytics);
- the local `cscli` CrowdSec control binary;
- an AbuseIPDB reporting key;
- local CrowdSec / nginx / ModSecurity logs and runtime state.

Because a compromise of this component can disable defences or ban arbitrary
traffic, treat it as a control-plane asset.

## Reporting a vulnerability

Report privately. Do **not** open a public issue for a security defect.

- Email: rohmerjeanmarcel@gmail.com
- Use GitHub private security advisories on this repository.

Expect an acknowledgement within 72 hours.

## Secret handling

- No secrets are committed. All credentials are delivered via environment
  variables / systemd `EnvironmentFile=` at runtime (see `pkg/configs/*.env.example`).
- `.env` files are git-ignored; only `*.env.example` templates (empty values) are tracked.
- Rotate `CF_API_TOKEN`, `ABUSEIPDB_KEY`, and `CS_API_KEY` if a leak is suspected.
- The Cloudflare token must be scoped to the minimum required permissions
  (firewall access rules + rules lists + zone analytics read).

## Operational safety invariants

- The service must default to **observe-only / dry-run**; mutations are opt-in.
- Every mutating path must be reversible (see `internal/rollback/`).
- Destructive cleanup preserves rules whose note contains `easycron` (case-insensitive).
- The CrowdSec allowlist sync is **additive only** — it must never remove entries.

See [docs/hardening/](docs/hardening/) and [SECURITY_NOTES.md](SECURITY_NOTES.md)
for additional posture notes.
