# Aggressive Unused / Unserved Wiring Audit

## Classification

This report is retained as historical audit evidence for runtime wiring, dead-code,
and legacy/shadow cleanup. It is not a UI v2 product roadmap document.

Current issue state at classification time:

- `#125`: closed
- `#126`: closed
- `#127`: closed
- `#128`: closed
- `#131`: open

## 1. Executive Summary

- I confirmed 6 production-side dead/unwired items in this pass.
- I created 4 new GitHub issues in this pass: `#125`, `#126`, `#127`, `#128`.
- I also relied on 2 earlier audit issues already created in this audit thread: `#116`, `#117`.
- Confirmed dead code: `internal/utils`, `internal/ai/policy`, `internal/crowdsec/adapter`, `internal/ai/providers/common.go`, plus the earlier `internal/storage/fs` and `internal/compat/python36` findings.
- Confirmed unserved UI remains covered by existing issues `#84` and `#85`; I did not duplicate them.
- No uncertain high-risk item remained after manual tracing and static validation.

## 2. Methodology

Commands run:

```text
go list ./...
go vet ./...
go test ./...
staticcheck ./...
govulncheck ./...
rg -n "HandleFunc\\(|Handle\\(|http\\.Handle|mux\\.Handle|Route\\(|router\\.Handle|New[A-Z].*Page|template\\.Must|template\\.New|Register\\(|http\\.Method" cmd internal/ui internal/api -g '!**/*_test.go'
rg -n "cf-sync|crowdsec-sync|cf-cleanup|cf-allowlist-sync|cf-shadow" packaging docs .github cmd internal -g '!**/*_test.go'
comm -23 <(go list ./... | sort) <(go list -deps ./cmd/... | sort)
rg -n "NewHTTPClient\\(|Retry\\(" internal cmd docs -g '!**/*_test.go'
rg -n "internal/ai/policy|ProviderPolicy|AllowProvider\\(|Allow\\(ctx context.Context, req ai.ExplainRequest" internal cmd docs -g '!**/*_test.go'
rg -n "internal/crowdsec/adapter|NewCSCLIExecutor|NewDryRunExecutor|CSCLIExecutor" internal cmd docs -g '!**/*_test.go'
rg -n "quotaState|newQuotaState|set\\(|get\\(" internal/ai/providers internal cmd docs -g '!**/*_test.go'
```

Limitations:

- `deadcode` and `unused` were not installed.
- `staticcheck` reported many `U1000` and style findings, but most were test-only or tiny helper leftovers; I only turned production-relevant cases into issues.
- `govulncheck` reported 0 vulnerabilities in called code; imported module vulnerabilities were not in the executed code paths.
- At original audit time, the UI v2 planning docs were also untracked and were
  classified separately as UI roadmap references.

## 3. Findings Table

| ID | Classification | Component | File(s) | Evidence | Risk | Recommendation | GitHub issue URL |
|---|---|---|---|---|---|---|---|
| F-01 | WRONG_SOURCE_OF_TRUTH | `/sync` page | `internal/ui/cfsync_page.go` | `handleCFSyncPage()` reads `shadow.NewStore(s.cfg.StateDir)` instead of the scoped runtime DB | High | Wire the page to the runtime/scoped source of truth or keep it clearly legacy-only | `#84` already exists |
| F-02 | PLACEHOLDER | Trusted Networks diff / replay / recovery / deban routes | `internal/ui/trusted_networks.go`, `internal/ui/server.go` | Routes render `trustedNetworksPlaceholderPage(...)` or `ComingSoonPage(...)` | Medium | Hide placeholder routes or wire them to real runtime data/actions | `#85` already exists |
| F-03 | DEAD_CODE | `internal/storage/fs` runtime state JSON store | `internal/storage/fs/runtime.go` | Production bootstrap uses `internal/runtime/state.NewStateStore(scopeDir)`; `go list -deps ./cmd/...` does not include `internal/storage/fs` | Medium | Delete or move behind tooling/test boundary | `#116` |
| F-04 | DEAD_CODE | Python 3.6 compatibility helper | `internal/compat/python36/doc.go`, `env.go`, `lua.go`, `nginx.go` | Only tests reference the package; no production import was found | Low | Move to migration/tooling or retire | `#117` |
| F-05 | DEAD_CODE | Shared HTTP/retry helper package | `internal/utils/doc.go`, `internal/utils/http.go` | No production import; `internal/httpclient` implements its own retry logic | Medium | Delete or wire to a real consumer | `#126` |
| F-06 | DEAD_CODE | AI explain-policy contract | `internal/ai/policy/policy.go` | No production import or implementation; outside production dependency closure | Low | Move to a future boundary or remove | `#125` |
| F-07 | DEAD_CODE | CrowdSec adapter package | `internal/crowdsec/adapter/cscli.go`, `dryrun.go` | No production import; only tests/docs reference the package | Medium | Wire into a live command or retire the package | `#127` |
| F-08 | DEAD_CODE | Unused provider quota cache helper | `internal/ai/providers/common.go` | `quotaState`, `set`, and `get` are unused and flagged by `staticcheck` | Low | Remove the helper or document deferred use | `#128` |

## 4. UI Route Matrix

| Route | Handler | Data source | Classification | Notes |
|---|---|---|---|---|
| `/` | `handleDashboard` | Runtime health, detection, provider state | WIRED_PARTIAL_DATA | Real data, but some cards still surface `unavailable`/placeholder states. |
| `/providers` | `handleProviders` | Provider runtime/config stores | WIRED_PARTIAL_DATA | Real state, but many quota/latency fields are intentionally unavailable. |
| `/forensic` | `handleForensicPage` | Evidence/search stores | WIRED_REAL_DATA | Active operator readout. |
| `/evidence` | `handleEvidencePage` | Scoped SQLite evidence store | WIRED_REAL_DATA | Exposes the main evidence read model. |
| `/pipeline` | `handlePipelineHealthPage` | Evidence store + detection config | WIRED_PARTIAL_DATA | Real counters, but some source states remain `no events yet`/`unavailable`. |
| `/sync` | `handleCFSyncPage` | `internal/shadow.Store` | WRONG_SOURCE_OF_TRUTH | Still reads the shadow store; this is already tracked in `#84`. |
| `/ban-lifecycle` | `handleBanLifecyclePage` | Ban lifecycle store | WIRED_REAL_DATA | Live lifecycle readout, with live deban actions gated by config. |
| `/trusted-networks` | `handleTrustedNetworksPage` | ASN registry + sync status holder | WIRED_PARTIAL_DATA | Real registry rendering, but some sync status values still reflect legacy/placeholder semantics. |
| `/trusted-networks/diff` | `handleTrustedNetworksDiff` | None | PLACEHOLDER | Explicit read-only placeholder. Covered by `#85`. |
| `/replay` | `handleReplayPage` | Replay projection | WIRED_PARTIAL_DATA | Route exists, but replay subsystem is still tracked separately as orphaned runtime code. |
| `/recovery` | `handleRecoveryPage` | Recovery projection | WIRED_PARTIAL_DATA | Route exists, but recovery subsystem remains a separate dead/orphaned runtime concern. |
| `/deban` | `handleDebanPage` | None | PLACEHOLDER | Coming-soon route. Covered by `#85`. |
| `/drift` | `handleDriftPage` | Drift projection | WIRED_REAL_DATA | Active read-only view. |
| `/health` | `handleHealthPage` | Health checks + detectors | WIRED_PARTIAL_DATA | Real data, but health and detection can disagree. |
| `/status/runtime` | `handleRuntimeStatus` | Runtime state | WIRED_REAL_DATA | Live runtime status view. |
| `/settings/runtime` | `handleRuntimeSettings` | Runtime settings store | WIRED_REAL_DATA | Live config/state view. |

## 5. Runtime Service Matrix

| Service | Constructor | Production entrypoint | Scheduler/worker | Store/API dependency | Classification | Notes |
|---|---|---|---|---|---|---|
| `cmd/cf-sync` | `main.go` -> `runtime.go` / `daemon_runtime.go` | `cmd/cf-sync/main.go` | Daemon loop, WAF replay, enforcement, UI/API | SQLite scoped DB, runtime state, ban lifecycle, evidence store | ACTIVE_RUNTIME | Main live control plane. |
| `cmd/crowdsec-sync` | `main.go` | `cmd/crowdsec-sync/main.go` | One-shot / service loop | CrowdSec state and SQLite | ACTIVE_RUNTIME | Separate live helper/service. |
| `cmd/cf-cleanup` | `main.go` | `cmd/cf-cleanup/main.go` | Cleanup worker | Cloudflare client + lifecycle read model | ACTIVE_RUNTIME | Live helper, but cleanup failure persistence remains a separate issue. |
| `cmd/cf-allowlist-sync` | `main.go` | `cmd/cf-allowlist-sync/main.go` | One-shot helper / timer | CrowdSec allowlist status store | ACTIVE_RUNTIME | Root-owned helper. |
| `cmd/cf-shadow` | `main.go` | `cmd/cf-shadow/main.go` | Shadow validator | Shadow store / legacy state | LEGACY_SHADOW | Retained for shadow validation, not source of truth. |
| `internal/services/autoban` | `New...` constructors in `internal/services/autoban/*` | Wired from `cmd/cf-sync` | Enforcement worker path | Reputation / confidence / ban executor | ACTIVE_RUNTIME | Live enforcement service. |
| `internal/services/reporting` | `New...` constructors in `internal/services/reporting/*` | Wired from `cmd/cf-sync` | Outbox worker / reporting pipeline | Evidence store / AbuseIPDB / dedup | ACTIVE_RUNTIME | Live reporting pipeline. |
| `internal/crowdsec/adapter` | `NewCSCLIExecutor`, `NewDryRunExecutor` | None found | None found | CrowdSec decision manager | DEAD_CODE | Real code, but not consumed by production. |
| `internal/ai/gateway` | `NewService` | UI/API wiring | Read-only explain gateway | Evidence reader, quota registry, providers | ACTIVE_RUNTIME | Live read-only gateway. |
| `internal/ai/policy` | interface-only package | None found | None found | AI provider policy boundary | DEAD_CODE | Contract exists, but no live consumer. |
| `internal/utils` | `NewHTTPClient`, `Retry` | None found | None found | HTTP client and retry helper | DEAD_CODE | Helper package has no prod consumer. |

## 6. Storage / Read-Model Matrix

| Store / table | Writer | Reader | UI/API exposure | Classification | Notes |
|---|---|---|---|---|---|
| `runtime_state.json` via `internal/runtime/state` | `cmd/cf-sync`, runtime workers | runtime state readers | UI/runtime status pages | WRITE_AND_READ | Current live runtime state path. |
| `runtime_state.json` via `internal/storage/fs` | none in production | none in production | none | LEGACY_FILE_AUTHORITY | Duplicate legacy store, already tracked in `#116`. |
| `cf_ban_lifecycle` | `cf-sync` ban lifecycle writer | `ban-lifecycle` UI and cleanup logic | yes | WRITE_AND_READ | Live lifecycle source. |
| `crowdsec_allowlist_status` | `cf-allowlist-sync` helper | Trusted Networks UI and daemon | yes | WRITE_AND_READ | Root-owned helper status. |
| `abuseipdb_reporting_evidence` | reporting pipeline | evidence/timeline/UI/API | yes | WRITE_AND_READ | Active evidence store. |
| `events` / `event_checkpoints` | runtime event pipelines | replay/recovery/status | partial | WRITE_AND_READ | Used by live runtime, not dead. |
| `shadow` store under `internal/shadow` | shadow validator | `/sync` UI | yes | STORE_IGNORES_RUNTIME | Legacy source still powering `/sync` (#84). |
| `internal/ai/providers/common.go` quota cache | none | none | none | MIGRATED_BUT_UNUSED | Unused helper cache; dead code. |

## 7. Legacy / Shadow Matrix

| Path / keyword | Current use | Authority status | Classification | Recommendation |
|---|---|---|---|---|
| `shadow` | Still appears in `internal/shadow` and `/sync` | Legacy / not authoritative | LEGACY_SHADOW | Keep only if explicitly retained; otherwise remove wiring. |
| `cf-shadow` | Separate shadow validator binary/service | Intentional shadow mode | KEEP | Do not let it become source of truth. |
| `runtime_state.json` | Live in `internal/runtime/state`; duplicate in `internal/storage/fs` | Mixed | LEGACY_FILE_AUTHORITY | Remove the unused JSON store path. |
| `python36` | Legacy compatibility conversion helpers | Test-only / offline | LEGACY_SHADOW | Move to tooling or retire. |
| `jsonl` legacy event paths | `events.jsonl`, `waf_refs.jsonl` documented and used by live runtime paths | Mixed | KEEP / DOC | Keep only where live runtime still needs them; do not treat docs as runtime proof. |
| `internal/utils` | Shared helper package with no prod consumer | None | DEAD_CODE | Delete or wire to a live consumer. |

## 8. Uncertain High-Risk Items

- None remained after manual tracing, search-based reachability checks, and `staticcheck` review.

## 9. GitHub Issues Created

| Issue | Classification | Title | URL | Root cause |
|---|---|---|---|---|
| `#125` | DEAD_CODE | `ai/policy: explain-policy contract has no production consumer` | https://github.com/jmrGrav/security-automation-go/issues/125 | Contract package with no live consumer. |
| `#126` | DEAD_CODE | `utils: shared HTTP/retry helpers are not used by production` | https://github.com/jmrGrav/security-automation-go/issues/126 | Helper package with no live consumer. |
| `#127` | DEAD_CODE | `crowdsec/adapter: cscli executor is not consumed by production` | https://github.com/jmrGrav/security-automation-go/issues/127 | Adapter package present in runtime tree but not wired. |
| `#128` | DEAD_CODE | `ai/providers: unused quotaState helper is dead code` | https://github.com/jmrGrav/security-automation-go/issues/128 | Unused quota cache helper in production package. |

Previously created in this audit chain and still relevant:

| Issue | Classification | Title |
|---|---|---|
| `#116` | DEAD_CODE | `storage: runtime_state.json JSON store is duplicated and unwired` |
| `#117` | DEAD_CODE | `compat/python36: legacy compatibility helpers are test-only` |

## 10. No-Fix Confirmation

- No code was changed.
- No refactor was done.
- No behavior was changed.

## Addendum: Targeted `internal/crowdsec/adapter` Audit

### Production chain

```text
cmd/cf-sync
  -> internal/services/autoban
  -> internal/crowdsec/models
  -> no import of internal/crowdsec/adapter

cmd/crowdsec-sync
  -> no import of internal/crowdsec/adapter

tests/docs
  -> internal/crowdsec/adapter
```

### Public surface

- `internal/crowdsec/adapter.Executor`
- `NewCSCLIExecutor`
- `NewCSCLIExecutorWithWriter`
- `(*CSCLIExecutor).Execute`
- `NewDryRunExecutor`
- `(*DryRunExecutor).Execute`

### Conclusion

- No production caller exists.
- All observed references are tests or docs.
- The package is therefore vestigial in the live runtime tree.
- I did not create a second duplicate issue because `#127` already covers this root cause.

## Addendum: Second Full Scan

- I reran an aggressive full scan after the earlier suppressions.
- The only new production-side dead helper I confirmed was `cmd/cf-sync/quota_observability.go:75` (`quotaTransitionSummary`).
- That became issue `#131`.
- No new serious hidden runtime pocket emerged from the second pass.

## Commands Executed

```text
go list ./...
go vet ./...
go test ./...
staticcheck ./...
govulncheck ./...
rg searches over cmd/, internal/, docs/, packaging/, .github/
comm -23 <(go list ./... | sort) <(go list -deps ./cmd/... | sort)
rg -n "quotaTransitionSummary\\(" . -g '!**/*_test.go'
gh issue list
gh issue create
```

## Tool Availability

- Available: `go`, `rg`, `gh`, `staticcheck`, `govulncheck`
- Not available: `deadcode`, `unused`

## Git Status

At original audit time this report was untracked. It has since been classified
as a retained audit reference under `docs/audit/`.
