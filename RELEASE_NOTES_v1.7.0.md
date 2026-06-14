# v1.7.0

## Highlights
- Stable `cf-sync` shutdown path and restart behavior.
- Provider runtime toggles for non-AI providers with live health refresh.
- AI explain gateway auto-activation from persisted credential state.
- Live operator console polish: dashboard hub, live panels, AJAX refresh, and compact forensic views.
- Security Intelligence, Forensic, Evidence, Timeline, and Pipeline Health coherence fixes.

## Release Blockers Resolved
- Dashboard hero contrast and hierarchy.
- Evidence / Timeline side panel fallback and recovery path.
- SQLite `interrupted` symptom from heavy last-event lookup.
- AI explain disabled state when a valid provider exists in CredentialStore.
- Provider diagnostics and status contradictions.

## Validation
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `go build ./...`
- `NO_RPM=1 make package`
- Live smoke: `59 passed, 2 skipped`
