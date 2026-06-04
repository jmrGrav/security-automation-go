# Admin Token Final Verdict

**Finding ID:** Phase 4  
**Status:** CONFIRMED VULNERABILITY — FIXED in v1.1.1  
**Date:** 2026-06-04

## Summary

`cmd/cf-sync/daemon_runtime.go:newAuthenticator()` hardcoded the string `"admin-token"`
as the authentication token for the internal API server. The server bound to `:9090`
(all network interfaces) by default.

## Evidence

```go
// daemon_runtime.go (before fix)
authTokens := map[string]auth.Identity{
    "admin-token": { /* full admin scopes */ },
}
```

The `middleware.Auth` middleware validates Bearer tokens from the Authorization header.
Any actor reaching port 9090 could authenticate with `Authorization: Bearer admin-token`
and obtain `runtime.execute`, `runtime.rollback`, `quarantine.manage`, `audit.read`.

## Risk Assessment

- **Exposure:** Any host that could reach port 9090 on the daemon machine
- **Impact:** Full runtime control — execute mutations, trigger rollbacks, manage quarantine
- **Exploitability:** Trivial — token value was in source code

## Fix Applied (v1.1.1)

1. Default bind changed from `:9090` to `127.0.0.1:9090` (loopback only)
2. `newAuthenticator()` now loads the token from env var `CF_SYNC_API_TOKEN`
3. Daemon mode fails startup with a clear error if `CF_SYNC_API_TOKEN` is not set

## Related TODO Classifications

Other TODOs reviewed during this audit:

| File | TODO | Classification |
|---|---|---|
| `rollback/validator/validator.go:43` | Integrate resources.Registry | FUTURE WORK |
| `runtime/invariants/engine.go:71` | Integrate graph package | FUTURE WORK |
| `policy/bundles/activation/manager.go:36,38,50` | Bundle signing, compat, registry | FUTURE WORK |
| `cloudflare/models.go:29-31` | GraphQL, pagination stubs | FUTURE WORK |
| `rollback/planner/planner.go` | OpUpdate PreviousPayload | BUG — fixed separately in L-2 |
