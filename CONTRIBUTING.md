# Contributing

This is a production control-plane component. Stability, observability,
reversibility, and operational safety take priority over new features.

## Ground rules

1. **Do not change business behaviour** without a corresponding entry in
   [docs/archive/DECISIONS.md](docs/archive/DECISIONS.md) and an update to
   [docs/archive/COMPATIBILITY_CHECKLIST.md](docs/archive/COMPATIBILITY_CHECKLIST.md).
2. **Python remains the production source of truth** until parity is proven and a
   formal GO is recorded. Do not enable Go mutations by default.
3. **No secrets in commits.** Use `*.env.example` templates only.
4. Every outbound HTTP path needs a timeout and a retry policy.
5. Every long-running loop must be cancellable via `context.Context`.
6. No package may depend on global mutable state.

## Required local checks (must pass before pushing)

```bash
gofmt -l .          # must print nothing
go vet ./...
go build ./...
go test ./...
go test -race ./...
```

CI (`.github/workflows/ci.yml`) runs the same set on every push and pull request.

## Commits

- Sign commits and tags with GPG.
- Use the GitHub no-reply email for authorship.
- Keep commits scoped and message-clear; reference the affected package.

## Tests

New or changed logic at an external-effect boundary (Cloudflare mutate/transport,
cscli adapter, rollback, state/journal) must ship with tests. See
[docs/archive/TEST_GAP_REPORT.md](docs/archive/TEST_GAP_REPORT.md) for the current coverage debt and the
packages that most need tests before go-live.
