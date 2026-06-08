# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| v1.5.x | ✅ Active |
| < v1.5.0 | ❌ No longer supported |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately:

1. **Email**: security@arleo.eu — include `[SECURITY]` in the subject.
2. **GitHub private advisory**: use the [Security Advisories](https://github.com/jmrGrav/security-automation-go/security/advisories/new) feature.

Expected response: acknowledgement within 72 hours; fix timeline communicated within 7 days.

## Scope

This project is a **local-only homelab control-plane**. It is not a SaaS product. The threat model assumes:

- The operator controls the host.
- The operator UI listens on `127.0.0.1:9091` by default and is not exposed to the internet.
- The encrypted CredentialStore (SQLite AES-GCM, per-secret) is the only authorised secret storage path.
- No secrets in environment files, YAML config, logs, or generated documentation.

## What counts as a vulnerability

- CSRF bypass on admin routes.
- Secret leakage in HTTP responses, logs, or audit trail.
- SQLite CredentialStore encryption bypass.
- Authentication bypass on the operator UI.
- Command injection via config or user-controlled inputs.

## What does NOT count

- The operator UI is accessible while logged in (by design).
- Secrets visible to the root user on the local machine (out of scope — physical access).
- Theoretical attacks requiring an already-compromised host account with write access to the state directory.

## No Secrets in Issues

Do not paste API tokens, LAPI keys, Cloudflare tokens, or any credential values in GitHub issues, pull requests, or comments. Rotate any credential you accidentally expose immediately.

## Responsible Disclosure

We follow responsible disclosure. We will credit reporters in the release notes unless they request anonymity.
