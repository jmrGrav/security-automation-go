## v1.1.1 — Production hardening

Security and reliability hardening release.

Highlights:
- CSRF enforced on all audited mutation routes.
- Hardcoded admin token removed.
- Admin token now loaded from CF_SYNC_API_TOKEN or CF_SYNC_API_TOKEN_FILE.
- Default API bind narrowed to 127.0.0.1:9090.
- SQLite validation hardened.
- Allowlist comment validation added.
- Session cookies upgraded to SameSite=Strict.
- Rollback planner OpUpdate now fails explicitly instead of silently applying wrong state.
- Sensitive audit redaction extended for bearer tokens.
- Backup rotation now surfaces delete errors.
- Additional runtime, HA, governor, invariant, health, storage and UI tests added.

Validation:
- gofmt clean
- go vet ./...
- go build ./...
- go test ./...
- go test -race ./...
- go test -tags=soak ./internal/testing/...

Operational note:
CF_SYNC_API_TOKEN or CF_SYNC_API_TOKEN_FILE is required before daemon startup.
