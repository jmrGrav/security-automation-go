# Repository Integrity Report

**Date:** 2026-05-29  
**Commit:** `3929072e12e0e54e93b540ae9cea7d15872a5486`  
**CI:** https://github.com/jmrGrav/security-automation-go/actions/runs/26656167679 — **PASS**

---

## Incident Summary

The initial CI push failed because two `.gitignore` patterns excluded source packages from the repository.

### Root Cause 1 — `state/` (bare pattern, no leading slash)

```
# Before fix
state/
```

Git's path-matching semantics: a pattern with no leading slash and a trailing slash matches **any directory with that name at any depth** in the tree. The pattern intended to ignore a hypothetical runtime `state/` directory at the repo root, but silently excluded:

| Excluded source file | Effect |
|---|---|
| `internal/state/doc.go` | `go build ./...` failure |
| `internal/state/json_store.go` | `go build ./...` failure |
| `internal/state/json_store_test.go` | `go build ./...` failure |
| `internal/runtime/state/state.go` | `go build ./...` failure |
| `internal/runtime/state/state_test.go` | `go build ./...` failure |

The real runtime state directory is `/var/lib/cf-sync` (configured in `internal/config/config.go:149`), which is outside the repository entirely and already covered by the `/var/` pattern.

### Root Cause 2 — `*.env` (test fixture)

```
# Before fix
*.env
```

The glob excluded `internal/compat/python36/testdata/python36.env`, which `internal/compat/python36/compat_test.go` reads via `os.ReadFile`. The file contains only placeholder values (`test-token`, `test-zone`) — no real secrets. Excluding it caused `go test ./...` to fail on the compat package.

---

## Fix Applied

```
# .gitignore diff
-state/
+# Generated runtime state dir at repo root only — anchored so it never
+# matches Go source packages such as internal/state or internal/runtime/state
+/state/

+# Test fixtures use placeholder-only .env files and must be tracked
+!internal/compat/python36/testdata/python36.env
```

- `state/` → `/state/` anchors the pattern to the repository root. It can no longer match `internal/state/` or `internal/runtime/state/`.
- The negation re-includes the placeholder testdata `.env` while keeping `*.env` active for real secrets everywhere else. This is safe because the *parent directory* (`testdata/`) is not itself ignored — standard git negation precondition met.

---

## Post-Fix Verification

```
git check-ignore -v internal/state/doc.go
git check-ignore -v internal/state/json_store.go
git check-ignore -v internal/state/json_store_test.go
git check-ignore -v internal/runtime/state/state.go
git check-ignore -v internal/runtime/state/state_test.go
git check-ignore -v internal/compat/python36/testdata/python36.env
```
All six: **no output** — no longer ignored. ✓

```
git check-ignore -v var/foo.db    → .gitignore:20:/var/   (still caught) ✓
git check-ignore -v state/x.json  → .gitignore:23:/state/ (still caught) ✓
git check-ignore -v secrets.env   → .gitignore:8:*.env    (still caught) ✓
```

---

## Repository State (Post-Fix)

| Metric | Value |
|---|---|
| Total tracked files | 402 |
| Tracked Go source files | 351 |
| Tracked non-Go files | 51 |
| Go packages | 141 |
| Ignored (intentional) | `bin/`, `.claude/` |
| Previously ignored (error) | 5 Go files + 1 testdata env — **restored** |

---

## Packages Present Locally and on GitHub (Post-Fix)

All 141 Go packages are now tracked. The five packages previously missing from GitHub:

| Package | Status before | Status after |
|---|---|---|
| `internal/state` | ABSENT from GitHub | PRESENT ✓ |
| `internal/runtime/state` | ABSENT from GitHub | PRESENT ✓ |
| `internal/compat/python36/testdata` | Partial (env missing) | COMPLETE ✓ |

No other source files are ignored. Confirmed with `git status --ignored --short`: only `bin/` and `.claude/` appear.

---

## Final .gitignore — Rule-by-Rule Justification

| Pattern | Scope | Justification |
|---|---|---|
| `/bin/` | Root `/bin` only | Build output from `go build -o bin/...` |
| `*.exe`, `*.test`, `*.out` | Global | Go build/test artifacts |
| `*.env` | Global | Real environment files with secrets |
| `!*.env.example` | Global negation | Example templates are safe to commit |
| `.env.*` | Global | All `.env.staging`, `.env.prod` variants |
| `!internal/compat/python36/testdata/*.env` | Scoped negation | Placeholder-only fixtures required by tests |
| `*.db`, `*.sqlite`, `*.sqlite-shm`, `*.sqlite-wal` | Global | SQLite runtime databases |
| `/var/` | Root `/var` only | Would only apply if repo had a `var/` subdir |
| `/state/` | Root `/state` only | Hypothetical runtime state dir at root — **never matches internal packages** |
| `*.state.json` | Global | Runtime JSON state snapshots |
| `coverage.txt`, `coverage.html`, `*.prof`, `cpu.out`, `mem.out` | Global | Test coverage and profiling output |
| `.idea/`, `.vscode/`, `*.swp`, `.DS_Store` | Global | Editor and OS metadata |
| `go.work`, `go.work.sum` | Global | Local workspace files not used in CI |

---

## CI Checklist

| Step | Result |
|---|---|
| `gofmt -l .` | ✓ Clean |
| `go vet ./...` | ✓ Pass |
| `go build ./...` | ✓ Pass |
| `go test ./...` | ✓ Pass |
| `go test -race ./...` | ✓ Pass |
