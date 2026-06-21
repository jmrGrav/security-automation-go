# Changelog

All notable changes to this project will be documented in this file.

## [v1.7.3] — 2026-06-16

### Summary

Hotfix: Spamhaus Submit was never wired into the reporting pipeline — the `spamhaus.Client` interface existed but had no concrete implementation. This release adds `SubmitClient` (POST `/portal/api/v1/submissions/add/ip`, Bearer token) and wires it into `reporting.Service` independently of AbuseIPDB: own 24h per-IP in-memory dedup, fail-open on error, independent metrics. AbuseIPDB behaviour is unchanged.

### Fixes

- **FIX-SPAMHAUS-SUBMIT — Spamhaus Submit wired into reporting pipeline** — `internal/security/enrichment/spamhaus.SubmitClient` implements `Client.Report()` via `POST https://submit.spamhaus.org/portal/api/v1/submissions/add/ip` with Bearer token auth. Error handling: HTTP 401/403 → auth error (logged WARN), HTTP 429 → rate-limit error (logged WARN), HTTP 5xx → server error retryable (logged WARN). All errors are fail-open: Spamhaus failure does not affect the AbuseIPDB result or `Process()` return value.

- **FIX-SPAMHAUS-DEDUP — Per-IP 24h dedup for Spamhaus** — `spamhausIPDedup` tracks submitted IPs with a 24h TTL (in-memory, resets on restart). Second event for the same IP within the window skips the Spamhaus call entirely. Dedup is independent from AbuseIPDB's `enforceRecentReportWindow`.

- **FIX-SPAMHAUS-WIRE — Startup wiring in `newWAFBundle`** — reads `spamhaus.api_key` from the credential store at startup and calls `svc.SetSpamhausClient(spamhaus.NewSubmitClient(hc, shKey))` when the key is present and the provider state is enabled. Missing key → no-op (fail-open), matching the AbuseIPDB pattern.

### Metrics Added

- `spamhaus_submit_total` — successful Spamhaus submissions
- `spamhaus_submit_failures_total` — failed submissions (error logged WARN, execution continues)
- `spamhaus_submit_dedup_total` — submissions skipped by 24h per-IP dedup

## [v1.7.2] — 2026-06-15

### Summary

Operability sprint. Fixes two root causes that had silenced AbuseIPDB reporting since June 13: an orchestrator checkpoint UNIQUE constraint crash loop and an unconditional LeaseGuard that blocked single-node outbox processing. Improves provider diagnostic clarity so HTTP 401/403/429 errors surface their specific status code instead of the generic "provider returned empty error" message. Adds Nginx 4xx/5xx access log view at `/nginx-access`. Introduces live IP auto-banning via Cloudflare IP access rules, gated on local evidence corroboration and AbuseIPDB confidence=100.

### Fixes

- **FIX-ABUSEIPDB-SILENCE — LeaseGuard gated on strict-HA profile** — `OutboxWorkerConfig.LeaseGuard` was unconditionally set to the `outboxLeaseGuard`, requiring an active reconcile lease before dispatching any reports. In `single-node` mode no orchestrator lease exists, so all outbox processing was blocked. The guard is now only attached when `cfg.Runtime.Profile == config.RuntimeProfileStrictHA`.
- **FIX-CHECKPOINT — Idempotent event checkpoint saves** — `SaveCheckpoint` used a plain `INSERT INTO event_checkpoints`, which crashed with `UNIQUE constraint failed` on every restart when the same `(name, scope_id, sequence)` was re-attempted during startup recovery. Changed to `INSERT OR IGNORE` so duplicate saves are silently skipped.
- **FIX-PROVIDER-DIAGNOSTIC — HTTP status codes in plain-text errors now classified** — `providerDiagnosticTextFromText` now matches `"http 401"` and `"http 403"` as `AUTH_FAILED`, and `"http 429"` as `RATE_LIMITED`. Previously, errors like `"spamhaus HTTP 401"` (returned by the Spamhaus quota client) fell through to `TEST_FAILED` / "provider returned empty error", giving operators no actionable information. Test coverage added for all three new patterns.

### Features

- **FEAT-NGINX-ACCESS — Nginx 4xx/5xx access log view** — New read-only page at `/nginx-access` parses the nginx combined-format access log from `CrowdSec.NginxLogDir`, filters for 4xx/5xx responses, and groups by IP + status code. Columns: IP, status badge, count, method, last URI, user agent, first/last seen, Forensic link. Fail-open: absent log directory or empty files render a "no data" message. No AbuseIPDB reporting from this view.

- **FEAT-EVIDENCE-CF-FIELDS — Evidence Detail shows Cloudflare named fields** — The Evidence Detail page (`/evidence/:id`) now renders a "Cloudflare event fields" kv-panel before the full normalized event JSON. The panel shows up to 7 fields when present: `ray_id`, `ruleset_id`, `rule_id`, `http_method`, `edge_response_status`, `country_name`, `asn_description`. All values are HTML-escaped. Panel is suppressed when no CF fields are set (non-CF events, CrowdSec, OpenResty).

- **FEAT-ABUSEIPDB-ENRICHMENT — AbuseIPDB IP enrichment in Forensic + Security Intelligence** — New `internal/security/enrichment/abuseipdb.LookupClient` wraps the existing `abuseipdb/transport.Check()` call and implements `enrichment.LookupProvider`. Mode is `Manual` (fires only when `ManualForensics=true` on Forensic and Security Intelligence pages, never on the per-event classification hot path). Returns a `ProviderVerdict` with `score`, ISP, usage type, and country. Fail-open: HTTP 429, timeouts, and network errors return an error that the enrichment service treats as a skip — the Forensic page renders without AbuseIPDB data rather than blocking. Wired at startup in `cmd/cf-sync/ui_runtime.go` using the same AbuseIPDB credential as reporting.

- **FEAT-AUTOBAN — Auto-ban evaluator with live CF enforcement** — New package `internal/services/autoban` implements two IP ban rules evaluated after each CF WAF replay batch:
  - **Confidence-100 rule**: requires both a locally observed malicious event (burst counter ≥ 1 for that IP within the last 15 minutes) AND `abuseConfidenceScore == 100` from AbuseIPDB `/check` (via 6h in-memory cache). Score 100 alone (without local evidence) is rejected — guard prevents banning IPs that carry a high external reputation score but have never appeared in local CF WAF traffic. Only public, non-protected IPs are eligible.
  - **Burst rule**: counts malicious events per IP in a sliding 30s sub-window. If any 30s interval contains >30 distinct events (deduplicated by `ray_id`), a ban decision is emitted. Sub-window detection operates on event timestamps so historical replayed events are detected correctly.
  - **Safety guards**: only public/global-unicast IPs are eligible; `trust.DefaultRegistry()` (includes RFC1918, loopback, link-local, all Cloudflare CIDR ranges, operator-configured protected hosts) exempts matched IPs before any external call; 24h in-process dedup prevents repeated decisions for the same IP; AbuseIPDB quota guard skips `/check` when the registry reports EXHAUSTED or THROTTLED state.
  - **CF enforcement path**: `cfBanExecutor` calls `AddIPAccessRule` (zone-level IP access rule, mode=block, notes=`cf-sync:autoban:<reason>`) on confirmed live-mode decisions. `RecordBan` (24h dedup) is only called after a successful CF API call — transient failures are retried on the next poll. Shadow mode (`auto_ban_enabled: false`) logs decisions without mutating Cloudflare.
  - Config: `cloudflare.auto_ban_enabled` (bool, default `false`). Live enforcement requires both `mutations_enabled: true` and `auto_ban_enabled: true`. Test coverage: 22 unit tests covering all 7 decision scenarios.

### Known Debt (not fixed in v1.7.2)

- **VirusTotal/Spamhaus enrichment not wired**: `enrichment.NewService` is called with `nil` lookup providers in production. VirusTotal defines a `Client` interface but has no concrete IP-lookup implementation. Spamhaus only has a reporter client (outbound). The Security Intelligence and Forensic enrichment pages only perform DNS + ASN lookups. This is structural work for a future sprint.
- **Confidence gap (score 5–9)**: Scanner signatures like `nikto`, `sqlmap`, and `curl` produce confidence 0.65, below the 0.70 reporting threshold. These IPs are suppressed even though they represent real malicious activity.
- **5.255.111.197 dual-result**: One entry received both `reported` and `failed|HTTP 400` statuses. Root cause is a dedup race between the evidence check and the executor call. No duplicate reports sent.
- **Auto-ban burst rule covers CF WAF only**: CrowdSec and OpenResty events feed the same reporting service but their events are not currently wired into the burst counter. Only CF WAF replay events contribute to the burst evaluation.
- **AbuseIPDB Check and Report share a daily quota**: The `/check` calls from the confidence-100 rule and the `/report` calls from the reporting pipeline use the same AbuseIPDB API key and daily limit. A quota guard (`quota.DefaultRegistry().State("abuseipdb")`) skips Check calls when THROTTLED or EXHAUSTED, but the budget must be monitored after enabling the evaluator at higher event rates.

## [v1.7.1] — 2026-06-15

### Summary

UI audit corrections. Fixes three operator-visible defects introduced in v1.7.0: broken evidence links on audit timeline rows, forensic enrichment not running in production, and table column truncation across four data tables. Also removes three developer-artifact status entries from the dashboard counter.

### Fixes

- **FIX-TIMELINE-LINKS — Audit timeline rows no longer generate broken evidence links** — Audit entries carry no evidence record; their `EvidenceID` field was being sourced from a random hex event ID via `resolvedAuditEventID`, producing clickable links that opened to "Evidence not found" live panels. Two-site fix: clear `EvidenceID` at the converter level and pass the raw empty string to `evidenceDetailLinkHTML` so it renders "unavailable" rather than routing through `auditDisplayValue → "unknown" → /evidence/unknown`. WAF evidence rows (real `EvidenceID`) are unaffected.
- **FIX-FORENSIC-ENRICHMENT — Forensic enrichment now runs in production** — `handleForensicPage` and `handleForensicLookup` called `s.enrichment` directly, which is nil in production (not passed via `ui.Options`). Both handlers now use `securityIntelligenceService()`, the same factory already used by the Security Intelligence page, which falls back to initialising the service from config when `s.enrichment` is nil.
- **FIX-TABLE-WIDTHS — Table column truncation resolved on four data tables** — All four main data tables (Timeline, WAF Events, Pipeline Health, Forensic Local Evidence) used `table-layout: fixed` with no column hints, giving equal width to every column and truncating source names and ID columns. Added `<colgroup>` with explicit `rem` widths per table so short numeric columns stay compact and ID/IP columns get adequate space.
- **FIX-DASHBOARD-COUNTER — Dashboard disabled count no longer inflated by developer TODOs** — Replay, Recovery, and Shadow/cutover entries were listed in the dashboard status panel as `disabled: not wired`, inflating `DisabledCount` from 1 (HA/fencing — a real architectural boundary) to 4 and surfacing developer TODOs as operator-visible entries. The three entries are removed; HA/fencing remains.

### Tests

- Updated three timeline tests that asserted the old broken behaviour (audit entry `EvidenceID == correlation hex`). New assertions verify audit rows emit empty `EvidenceID`, correlation lands in `CorrelationID`, and no `/evidence/` links are generated for audit-only timelines.

## [v1.6.4] — 2026-06-13

### Summary

Provider credential-store hotfix release. Fixes non-AI provider read paths so Spamhaus, VirusTotal, and AbuseIPDB now render their configured state directly from the encrypted CredentialStore. Also normalizes old uppercase credential keys to dotted keys, lazily initializes quota clients from stored credentials, and adds smoke coverage for the provider Replace Key flow.

### Fixes

- **FIX-PROVIDERS — Non-AI provider read path** — `providerConfiguredValue()` usage removed from the provider views. `nonAIProviderEntries()`, `providerHealthViews()`, and `providerViews()` now read the encrypted CredentialStore directly, so Replace Key updates are visible in the UI immediately.
- **FIX-MIGRATION — Uppercase credential key migration** — One-time startup migration copies `SPAMHAUS_API_KEY`, `VIRUSTOTAL_API_KEY`, and `ABUSEIPDB_KEY` into dotted keys (`spamhaus.api_key`, `virustotal.api_key`, `abuseipdb.api_key`) without deleting the old entries.
- **FIX-QUOTA — Lazy quota client init** — Spamhaus and VirusTotal quota refreshers now initialize from CredentialStore on first refresh when the provider is enabled, so quota monitoring does not require a daemon restart after Replace Key.

### Tests

- `TestNonAIProviderReplaceKeyUpdatesDisplay` — Replace Key immediately updates the provider status view for Spamhaus, VirusTotal, and AbuseIPDB.
- `TestNonAIProviderKeyNeverLeaksInHTML` — seeded non-AI credential values are never rendered raw in `/providers`.
- `04-providers.spec.ts` — smoke coverage for Spamhaus Replace Key, configured badge, and redaction.

## [v1.6.3] — 2026-06-13

### Summary

Security hardening and observability improvements. Adds an operator-protected IP guard to prevent the operator's own IPs from ever being reported to AbuseIPDB or propagated to Cloudflare. Restores safe AI model defaults after credential-store migration. Improves the CF ban sync page with actionable dry-run and no-data messaging. Adds Replace Key form CSRF smoke tests.

### Fixes

- **FIX-GUARD — Operator-protected IP guard** — Add `global.protected_hosts` YAML field and `SECURITY_AUTOMATION_PROTECTED_HOSTS` env var to register operator-controlled IPs/CIDRs in the trust registry at startup. The existing `reporting.Service.isProtected()` chokepoint suppresses these IPs with reason `protected_target` before any AbuseIPDB report or Cloudflare propagation. The `CloudflarePropagationGuard` (Cloudflare mutation path) also consults the same registry. Added 3 unit tests: env-var parsing, YAML parsing, and end-to-end suppression through `reporting.Service`.
- **FIX-AI-DEFAULTS — Restore safe AI model defaults** — Added `DefaultOpenAIModel`/`DefaultAnthropicModel`/`DefaultGeminiModel` constants. `normalizeAIConfig` now applies them when a provider is enabled but the model field is empty (e.g. after credential-store migration that stored the key but not the model).
- **FIX-CFSYNC-PAGE — CF ban sync page clarity** — When no sync cycles are recorded: dry-run mode shows `DRY-RUN` badge with instructions; missing CrowdSec decisions source shows config guidance; otherwise shows "Waiting for first enforcement cycle". When cycles exist, a `MUTATIONS ON`/`DRY-RUN` mode badge appears alongside the `IN SYNC`/`DRIFT DETECTED` status badge.

### Tests

- `TestOperatorProtectedIPIsNeverReported` — end-to-end suppression
- `TestProtectedHostsFromEnvVar` / `TestProtectedHostsFromYAML` — config parsing
- `TestNormalizeAIConfigRestoresDefaultModels` — model defaulting
- `04-providers.spec.ts` — Replace Key form: CSRF token present, no pre-filled value, POST without CSRF rejected with 403

---

## [v1.6.2] — 2026-06-13

### Summary

Runtime wiring repair: CrowdSec and OpenResty events were never processed by the `cf-sync` daemon. Two root causes fixed: (1) `processCrowdSec`/`processOpenResty` were dead code in the running service; (2) `acceptDecision` silently dropped 94% of CrowdSec decisions (CAPI origin). Also fixes hardcoded `v1.0.0` version string in status/UI.

### Fixes

- **FIX-CS-WIRE — CrowdSec + OpenResty wired into cf-sync daemon** — `processCrowdSec` and `processOpenResty` were only called by `CrowdSecSyncApp` (the `crowdsec-sync` binary, not running as a service). The `cf-sync` daemon polled Cloudflare WAF only. Added `wafBundle` struct in `runtime_wiring.go` that holds CF WAF + CrowdSec + OpenResty services sharing a single `reporting.Service` (unified dedup store and evidence store). `startCrowdSecOpenRestyPoller` goroutine added to `daemon_runtime.go` and wired into `runDaemonWithLocker`.
- **FIX-CAPI — Accept CAPI origin in CrowdSec decisions** — `acceptDecision` rejected `origin="CAPI"` (CrowdSec Community API blocklist), representing 94% of decisions.log entries (9406/9972 on host). Only 12 local-origin decisions were eligible, all older than 24h. Now accepts `"capi"` alongside `"crowdsec"` and `"cscli"`. CAPI bans are executed locally; downstream reporting policy (confidence threshold, dedup TTL) handles AbuseIPDB submission.
- **FIX-VERSION — Fix hardcoded v1.0.0 version** — `status.NewCollector` had `"v1.0.0"` hardcoded. Added `version`/`commit`/`buildDate` ldflags vars in `main.go`; Makefile now injects them at build time (`-X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT) -X main.buildDate=$(BUILD_DATE)`).

---

## [v1.6.1] — 2026-06-12

### Summary

Post-release hardening sprint. Seven reliability and security fixes identified by post-v1.6.0 audit: DB split-brain elimination, SQL-level pagination replacing in-memory capping, OpenResty crash-safe event recovery, health check false-positive fix, scanner buffer increase, explicit Cloudflare 429 error propagation, and json_extract filters for evidence queries.

### Fixes

- **FIX-1 — DB split-brain** — Share `sqlite.DB` handle between daemon and UI goroutine in `-mode ui` to eliminate concurrent schema migrations against `runtime.db`.
- **FIX-2 — Evidence pagination** — Replace 10k/100k in-memory evidence fetches with SQL `COUNT(*)` + `LIMIT`/`OFFSET` pagination. Add `AbuseIPDBReported` and `Suppressed` filter fields to `EvidenceSearchOptions`. Add `Count()` method to `EvidenceStore` interface; implemented via `json_extract()` in SQLite.
- **FIX-3 — OpenResty crash recovery** — `LiveSource.Read()` recovers stale `.processing` files left by a prior crash before checking for new events. Prevents silent event loss when `os.Rename` would overwrite an unconsumed batch.
- **FIX-4 — Health check false Yellow** — `CheckOpenResty` checks directory existence (not file) — the events file is legitimately absent between pipeline cycles after `Read()` consumes it.
- **FIX-5 — Shadow store buffer** — Increase `bufio.Scanner` buffer from 64 KB to 1 MB in `shadow.Store` to prevent `/sync` page breakage on large sync cycles.
- **FIX-6 — Cloudflare 429 propagation** — Transport layer now returns an explicit `HTTP 429 rate-limited` error (with `Retry-After` value when present) instead of passing the 429 body to callers as a successful response.
- **FIX-7 — Evidence json_extract filters** — `Search()` and `Count()` apply `json_extract(data, '$.abuseipdb_reported') = 1` / `json_extract(data, '$.suppressed') = 1` directly in SQLite rather than relying on in-memory post-filtering.

---

## [v1.6.0] — 2026-06-12

### Summary

Major operator console sprint (P1–P13). SQLite as sole source of truth for runtime feature flags. Full WAF evidence pipeline wired into the UI: evidence store, `/evidence` page, Pipeline Health Matrix, Timeline enrichment, and CF ban sync view. Confidence scorer fixed for scanner user-agents. CrowdSec no-URI events preserved. OpenResty dashboard accuracy + diagnostics runbook. AI provider state persisted to SQLite (enable, model, test). `GET /forensic?ip=X` deep-links from evidence and timeline rows. Plus admin recovery system, CWE-614 elimination, env-elimination, and operator console UX cleanup from earlier milestone work.

### Features (fiabilisation sprint P1–P13)

- **P1 — Confidence scoring** — Scanner user-agents (`sqlmap`, `nikto`, Shodan, Censys, etc.) now contribute positive confidence. Previously scored 0; now bumps to `Low` threshold correctly.
- **P2 — Evidence store UI** — `/evidence` page with pagination, reported/suppressed filters. `EvidenceStore` wired from daemon into UI server via `Options.EvidenceStore`.
- **P3 — CrowdSec no-URI events** — Events where `URI` is empty are no longer silently dropped; they are preserved with an empty URI.
- **P4 — OpenResty dashboard WAF badge** — Dashboard badge now uses `os.Stat` for accurate file-existence detection instead of the old string-check path.
- **P5 — Logout button** — Logout button always visible in the sidebar of the operator console.
- **P6 — Unified Providers page** — `/providers` page consolidates all AI and non-AI providers (add, edit, test, enable/disable).
- **P7 — AI provider state in SQLite** — AI provider enabled/model settings persisted to `ui_settings` (SQLite) via the `/providers` UI. State survives daemon restarts.
- **P8 — Pipeline Health Matrix** — `/pipeline` page: per-source rows (cloudflare_waf, crowdsec_waf, openresty_waf) × columns (Classified, Reported, Suppressed, Pending) from evidence store (100k cap).
- **P9 — Timeline enriched** — `/timeline` merges audit events and WAF evidence events (sorted by wall time). Source filter (All / WAF Events / Audit Trail). Evidence events include severity and decision classification.
- **P10 — Dashboard reported total** — Dashboard shows historical AbuseIPDB-reported count from evidence store (persists across daemon restarts), not a Prometheus counter that resets.
- **P11 — OpenResty diagnostics + runbook** — `DetectOpenResty()` reports `events_age`, `events_size_bytes`, `stuck_processing`. Health page `/health` shows an OpenResty Runbook panel explaining missing-file, stale-file, and stuck-processing conditions including the silent-drop root cause (empty `ip`/`detail` fields).
- **P12 — CF Ban Sync view** — `/sync` page reads `shadow-cycles.jsonl` and displays the latest sync plan: ToAdd/ToDelete IP lists, agreement %, in-sync/drift status, active ban and CF rule counts.
- **P13 — Explain This IP** — `GET /forensic?ip=X` performs inline lookup (no POST form required). IP cells in `/evidence` and IP targets in `/timeline` link to `/forensic?ip=X` for one-click enrichment context.

### Features

- **Trusted Networks UX v2** — Registry page replaced card grid with a responsive `<table>` layout: Name, Kind, CIDRs (2 visible + `<details>` expand), Protection badge, Allowlist (CF/CS sync), Status. Wrapped in `overflow-x:auto` for narrow viewports.
- **Cloudflare Diff operator summary** — New Operator Summary panel at the top of the Cloudflare Diff page: Configured YES/NO, Token YES/NO, Zone YES/NO, Mode (DRY-RUN/LIVE), Quota, Next action. Uses `cfSentinelToken()`/`cfZoneIDFromSetup()` — the same credential-store-aware source of truth as Health and Dashboard.

### Security

- **CWE-614 eliminated structurally** — `Secure: true` is now a compile-time constant in the single pair of cookie-emitting methods (`setSessionCookie` / `clearSessionCookie`). Future call sites cannot accidentally omit it; CodeQL can no longer rediscover the pattern on new files. `secureCookie(r)` and `sessionCookie(r, token)` removed.

### Bug Fixes

- **Wizard step 8 source of truth** — Runtime Summary in setup step 8 previously used a raw `credentialStore.Lookup` call (diverging from the Dashboard) and hardcoded `"true (default)"` and `"disabled (default)"` for dry-run and mutations. Now uses `cfSentinelToken()` and reads actual `dry_run`/`mutations_enabled` values from `setupStore`, matching what the operator console shows.
- **CrowdSec LAPI key not loaded (G5)** — `runUIWithLocker` did not look up `crowdsec.lapi_key` from the credential store. Added after the existing `betterstack.source_token` lookup.
- **Data race G1** — `runtime.go` passed the `cfg` pointer to the UI goroutine while also writing credential fields. Fixed by snapshotting `uiCfg := *cfg` before launching the goroutine.
- **Wizard-wait restart guidance (G8)** — Wizard completion handler now logs a journald `INFO` message reminding the operator to run `systemctl restart cf-sync`. Documented in `docs/operations/RUNBOOK.md`.

### Testing

- **Flaky test eliminated** — `TestUIFreshInstallWizardAndConservativeRestart` intermittently timed out (~34–50 s) under `-race` because bcrypt cost-12 under CPU contention exceeded the HTTP client timeout. Fix: `cmd/cf-sync/testmain_test.go` overrides bcrypt to `MinCost` before all tests in the package. Test now runs in 1–6 s, 5/5 passes with `-race -count=5`.
- Updated `TestTrustedNetworks_RenderRegistryEntries` assertions to match the new table layout (protection/allowlist labels).

### Cleanup

- **Dead code removed (G6)** — Removed unused `runtimeStatus()` method and `openRestyStatus()` function from `internal/ui/server.go`.
- **Stub badges corrected (G7)** — Replay and Drift workflow pages: "Execution" / "Convergence" badges changed from `warning` to `disabled`. Dashboard stub panels (HA/fencing, Replay, Recovery) confirmed non-warning.
- **Sidebar Soon labels** — Replay, Deban, Recovery, Drift nav items marked `Soon: true`.

### Security

- **Admin Password Reset CLI** — `sudo cf-sync -mode admin reset-password` generates a cryptographically random temporary password (bcrypt stored, never logged), sets `password_change_required=true` in SQLite, and increments `auth_epoch` to invalidate all active UI sessions without requiring a server restart. Requires local root.
- **Admin Recovery Key** — `sudo cf-sync -mode admin recovery-key create/rotate` generates a 256-bit random recovery key, shows it once to stdout, and stores only its bcrypt hash (cost 12) in the new `admin_recovery_keys` SQLite table (migration 17). `sudo cf-sync -mode admin recover` reads the key with masked terminal input, verifies via bcrypt, then resets the password. Root required. The plaintext key and temporary password are never written to logs, journald, or the database. Five audit events are emitted to `<stateDir>/ui-audit.log`: `admin_password_reset`, `admin_sessions_invalidated`, `admin_recovery_key_created`, `admin_recovery_key_rotated`, `admin_recovery_used`.
- **Cross-process session invalidation** — UI server tracks `auth_epoch` (atomic int64 + SQLite `ui_settings`). On each `getSession` call the server reads the DB epoch; if it has advanced since the last cached value, all in-memory sessions are flushed immediately. CLI resets take effect on the next request to the running server without a restart.
- **Forced password change gate** — `forcePasswordChangeMiddleware` now checks `password_change_required` in addition to bootstrap-active, ensuring CLI-initiated resets force a UI password change regardless of whether a hash already exists.

### Documentation

- `docs/operations/RUNBOOK.md` — Added "Service restart after first-run wizard" section explaining the wizard-wait design gap and the required `systemctl restart cf-sync` step.
- `docs/operations/RUNBOOK.md` — Added "Admin password reset and account recovery" section covering all CLI commands, security invariants, and the never-implemented list.

### Env-Elimination (feature flags → SQLite)

- **SQLite single source of truth** — Feature flags (`cs_poller_enabled`, `cloudflare_mutations_enabled`, `abuseipdb_enabled`) are now stored in `ui_settings` (SQLite) and managed via the operator UI at `/settings/runtime`. The env vars `CLOUDFLARE_MUTATIONS_ENABLED`, `CS_POLLER_ENABLED`, `ABUSEIPDB_ENABLED`, and `ABUSEIPDB_REPORTING_ENABLED` are no longer read by `applyEnvOverrides`; they can be removed from `.env` files.
- **`SetupStore.GetRuntimeFlags` / `SetRuntimeFlag`** — New methods on `SetupStore` for reading and writing the four runtime booleans. Unknown key returns error.
- **Runtime Settings UI** — New page at `/settings/runtime` with CSRF-protected POST: four checkboxes, saved-banner, audit record.
- **Runtime Status UI** — New page at `/status/runtime` with per-component status badges (enabled/disabled/unconfigured) and 30-second auto-refresh.
- **Admin API token non-fatal** — `startAPIServer` failure (e.g., `CF_SYNC_API_TOKEN` absent) is now a `WARN` instead of a fatal `return`. The scheduler, WAF replay poller, and AbuseIPDB outbox start regardless.
- **Legacy secrets path removed** — `internal/health/checks.go` no longer falls back to `/etc/security-automation/secrets` (the path without `-go`) when `LegacySecretsDir` is empty.

---

## [v1.5.5] — 2026-06-10

### Summary

Hotfix release. Two wizard bugs fixed: Cloudflare token validation no longer fails on unknown JSON fields added by the Cloudflare API; completing setup via the "Finish without enabling production mode" link now correctly marks setup complete. Runtime Summary display corrected: OpenResty and SQLite no longer shown as failed when correctly installed.

### Bug Fixes

- **Cloudflare JSON tolerance** — `ExecuteAndDecode`, `MutateAndDecode`, `DecodeEnvelope`, and `ExecuteGraphQL` now use permissive JSON decoding for Cloudflare API responses. Unknown fields such as `development_mode` in Zone objects are silently ignored. `DecodeStrict` (strict schema enforcement) is preserved for internal payloads. Fix: `internal/cloudflare/decode/decode.go`, `internal/cloudflare/transport/transport.go`.
- **Dry-run wizard completion** — `handleSetupComplete` now calls `MarkComplete` before rendering the completion page. Previously, navigating directly to `/setup/complete` (the "Finish without enabling production mode" link from steps 8 and 9) did not persist the completion state, causing the wizard guard to loop. Fix: `internal/ui/setup_wizard.go`.
- **SQLite detection path** — `DetectSQLite` checked for `state.db`; the actual database is `runtime.db`. Corrected. Fix: `internal/detect/detectors.go`.
- **OpenResty health** — `DetectOpenResty` marked healthy only when the WAF events file was configured. The events file is optional pipeline config, not a health signal. Health is now: binary installed + service running. Fix: `internal/detect/detectors.go`.
- **Runtime Summary UX** — Step 8 wizard summary: nginx absence is shown as informational (not an error) when OpenResty is detected; Cloudflare not configured is shown as optional (not a failure). Fix: `internal/ui/setup_wizard.go`.
- **Step 3 error message** — CF token validation errors strip the internal Go error chain from the user-facing message, showing only the final meaningful segment.

### Testing

- `internal/cloudflare/decode/decode_test.go` (new): `Decode` accepts unknown fields; `DecodeStrict` rejects them; malformed JSON is rejected by both.
- `internal/detect/detect_test.go`: `TestDetectSQLite_UsesRuntimeDB`, `TestDetectOpenResty_InstalledAndRunning`, `TestDetectOpenResty_InstalledNoEventsFile_StillHealthy`.
- `internal/ui/setup_wizard_test.go`: `TestSetupComplete_MarksCompleteOnDirectGET`, `TestSetupComplete_DryRunDoesNotSetMutations`.

---

## [v1.5.4] — 2026-06-10

### Summary

Operational and First-Run UI finalization. Unified management mode introduced. Generic/temporary passwords removed in favor of mandatory wizard-based creation. Default ports standardized (UI: 9091, Metrics: 9092). Debian packaging lifecycle hardened (stop on remove, full cleanup on purge). SQLite concurrency hardened. Dead code from auth migration removed.

### Features

- **Unified Management Mode** — The `-mode ui` flag now acts as a complete management service. On fresh installations, it provides the setup wizard. Once setup is complete, it automatically starts the full security orchestration in the background alongside the Web UI.
- **Mandatory Password Creation** — Removed all generic passwords (`CHANGE_ME_ON_FIRST_BOOT`) and automatically generated setup secrets. Operators must now explicitly create their administrator password during the first-run wizard.
- **Port Standardization** — Default UI port set to `9091` and Metrics/API port to `9092`. Both listen on `127.0.0.1` (localhost only).

### Security / Reliability

- **SQLite PRAGMA ordering** — `PRAGMA busy_timeout=5000` is now set before `PRAGMA journal_mode=WAL` in both `New()` and `Reopen()`. This ensures the retry timeout is active during WAL mode negotiation, preventing `SQLITE_BUSY` errors on concurrent first-open in UI mode (`internal/storage/sqlite/db.go`).
- **Migration TOCTOU** — Each schema migration now runs inside a `BEGIN IMMEDIATE` transaction with an in-transaction `EXISTS` check before applying. Prevents duplicate-migration errors when two goroutines open the same database simultaneously on fresh install (`internal/storage/manager/migrator.go`).
- **Smoke test correctness** — Fixed two bugs in `smoke_test.go` (build tag `smoke`): `TestSmoke_SetupWizardAccessible` now uses an incomplete-setup server; `TestSmoke_WrongPasswordRejected` uses the correct `password=` form field and asserts 401.

### Packaging

- **Lifecycle Hardening** — Added `prerm` script to ensure the `cf-sync` service is stopped before package removal.
- **Improved Purge** — `apt purge` now cleans up all canonical directories (`/etc`, `/var/lib`, `/var/log` for `security-automation-go`) and safely removes empty legacy paths used during migration.
- **Path Normalization** — All internal paths and defaults updated to the canonical `/var/log/security-automation-go` directory.
- **Version injection** — `make package` now injects `$(VERSION)` into `DEBIAN/control` via `sed` before `dpkg-deb --build`, ensuring `dpkg --info` reports the correct version.
- **Legacy service cleanup** — `postinst` removes any `/etc/systemd/system/cf-sync.service` left over from pre-package installs so the package-owned unit in `/lib/systemd/system/` takes precedence.

### Cleanup

- Removed `GenerateInitialPassword`, `VerifyInitialPassword`, and `InvalidateInitialPassword` (dead code — no production callers after auth migration).
- Removed `InitialPasswordFile` config field (set but never read in production).
- Removed `func runDaemon` wrapper (replaced by `runDaemonWithLocker` which is called directly).
- Removed dead `"UI_SECRET"` env map entries from test helpers (env var not read by config).
- Corrected `.env.example` paths to canonical `/var/lib/security-automation-go`.

### Documentation

- Updated `README.md`, `FIRST_BOOT.md`, and `PACKAGING.md` with new ports and setup procedures.

---

## [v1.5.3] — 2026-06-08

### Summary

Hardening sprint. Brooks Phase 2 review findings addressed. VACUUM INTO SQL construction hardened (parameterized query), API/auth boundary test coverage added, smoke test suite introduced. No API or behavioral changes.

### Security

- **VACUUM INTO hardened** — `ExportHotSnapshot` now uses a parameterized query (`VACUUM INTO ?`) instead of string concatenation. Path validation extended to reject semicolons, null bytes, and newlines in addition to the existing absolute-path, traversal, and quote checks. Fix: `internal/storage/sqlite/db.go`.

### Testing

- **API/auth boundary coverage** — Added targeted tests for `internal/api/auth`, `internal/api/middleware`, `internal/api/handlers`, and `internal/api/handlers/v2`. Coverage: auth=100%, handlers=90.5%, v2=92.6%, middleware=84.4%. Tests verify: auth required, unauthorized rejected, scope enforcement, malformed JSON → 400, state machine transitions via API.
- **Smoke test suite** — Added `internal/ui/smoke_test.go` (`//go:build smoke`). Scenarios: server boots, anonymous access rejected, wizard accessible before setup, login succeeds, wrong password rejected, authenticated dashboard/health reachable, mutation endpoint requires CSRF. Run with `go test -tags=smoke ./internal/ui/...`.

### Documentation

- `docs/issues/SECURITY_BACKLOG.md`: updated with hardening sprint entries.
- `docs/COVERAGE_POLICY.md`: added coverage targets and guidance.

---

## [v1.5.2] — 2026-06-08

### Summary

Resilience patch release. Two findings from the June 2026 Gemini adversarial chaos audit fixed (C1, C5). Three remaining findings closed with technical justification. No API or behavioral changes.

### Security / Reliability

- **C1 fixed** — Daemon liveness: `Scheduler.Start()` now calls `recoverStaleState()` on startup. If the state file shows a non-terminal status (Discovering, Planning, AwaitingApproval, Executing, Validating, RollbackRequired, RollingBack) — left by a previous crash between `store.Save()` and `PublishEvent()` — it is immediately reset to `StatusFailed` via the state machine. The scheduler can then retry on the next tick via `StatusFailed → StatusDiscovering`. Intentional operator states (Paused, Quarantined) are preserved (`internal/runtime/scheduler/stateful/scheduler.go`).
- **C5 fixed** — Pagination partial delivery: `TraverseAll()` now compares total items collected against `ResultInfo.TotalCount` after all pages are fetched. If fewer items were received than the API reported, the function fails closed with an error rather than returning a partial snapshot. Note: does not detect zeroed-metadata false-empty responses (TotalCount=0 on a non-empty resource) — documented limitation (`internal/cloudflare/pagination/pagination.go`).

### Closed (no action)

| ID | Finding | Rationale |
|----|---------|-----------|
| C2 | Non-deterministic OperationID | Duplicate of SEC-012 — intentional per-attempt uniqueness |
| C3 | Cloudflare POST idempotency | Snapshot diffing (StableIdentityKey) already prevents duplicates; confirmed via reconciliation planner code path |
| C4 | Recorder unbounded RAM growth | `AuthorizeFederated` has no production callers; recorder never accumulates entries during normal daemon operation |

---

## [v1.5.1] — 2026-06-08

### Summary

Security patch release. Two low-severity UI findings fixed following the June 2026 Gemini red-team audit. All remaining audit findings closed with technical justification. No API or behavioral changes.

### Security

- **SEC-005 fixed** — `handleSetupStep1` now redirects to `/login` when setup is complete, preventing the `SecretFile` path from being revealed to unauthenticated visitors post-setup (`internal/ui/setup_wizard.go`).
- **SEC-007 fixed** — `handleChangePassword` now invalidates all active sessions immediately after a successful password update. Users must re-authenticate; the response redirects to `/login` (`internal/ui/settings.go`).

### Closed (no action)

Following independent code revalidation, the remaining 8 open audit findings are closed:

| ID | Finding | Rationale |
|----|---------|-----------|
| SEC-004 | Rate limiter O(n) | Local UI; ≤5 clients in practice; sub-µs scan |
| SEC-006 | crypto/rand panic | Never fails on Linux 3.17+; net/http recovers panics |
| SEC-008 | OpenResty/Lua review | No actionable finding; process recommendation only |
| SEC-009 | SQLite recovery review | No actionable finding; process recommendation only |
| SEC-010 | Evidence recorder volatile | Diagnostic only; enforcement unaffected; V3 SQLite path is the system of record |
| SEC-011 | Drift memory volatile | Analytics only; enforcement unaffected |
| SEC-012 | Non-deterministic OperationID | Intentional — per-attempt uniqueness; `IdempotencyKey` handles correlation |
| SEC-013 | decisions.log O(n) scan | Bounded at ~10k lines/day with standard logrotate; sub-ms |

---

## [v1.5.0] — 2026-06-08

### Summary

First release with a validated first-run wizard, encrypted credential store, and complete CrowdSec Go integration. The historical Python runtime is retired from the critical path; remaining Python scripts are kept only for rollback/archival reference.

### Added

- **First-run setup wizard** — 10-step guided install: password, admin setup, Cloudflare token, optional enrichment keys (AbuseIPDB, BetterStack, AI providers), CrowdSec LAPI key, runtime summary, production enable. Tested end-to-end via `TestUIFreshInstallWizardAndConservativeRestart`.
- **Encrypted CredentialStore** — AES-GCM per-secret SQLite store (`internal/storage/sqlite/credential_store.go`). All operator secrets (Cloudflare, AbuseIPDB, BetterStack, AI keys, CrowdSec LAPI) flow exclusively through this store at runtime. No plaintext secrets in env files after first boot.
- **CrowdSec poller — Go replacement** (`internal/crowdsec/poller/`) — complete port of `crowdsec-poller.py`. Reads LAPI key from encrypted CredentialStore; fail-closed (returns error) if key absent.
- **CrowdSec UI/UX sprint**:
  - Auto-discovery: HTTP probe (8080/8088), AppSec port 7422, `cscli` binary — `internal/detect/detectors.go`
  - Health center: three new checks — `crowdsec`, `crowdsec-poller`, `crowdsec-appsec` with GREEN/YELLOW/RED states
  - Admin panel: set/replace/delete/test LAPI key via encrypted CredentialStore — `internal/ui/crowdsec_admin.go`
  - Wizard step 8: CrowdSec LAPI key (optional, skippable, stored in CredentialStore)
- **`docs/AI_HANDOFF.md`** — rapid context document for AI assistants and future contributors.
- **Secret path canonicalization** — legacy layout detector; secret loading refuses to silently fallback once canonical directory exists.
- **First-boot URL log** — prints the UI URL to stdout/journal on first start; gated behind production enable flag.

### Changed

- Wizard stepped from 9 to 10 steps (CrowdSec step 8 inserted; runtime summary → step 9; production enable → step 10).
- `internal/config/config.go`: `PollerLAPIKey` is runtime-only; `CS_POLLER_LAPI_KEY` env loading removed.
- `cmd/crowdsec-sync/main.go`: opens SQLite CredentialStore at startup to inject LAPI key; no env/YAML fallback.
- Health page no longer exposes `state.db` path in environment detection panel.
- SQLite `db_path` detail removed from `DetectSQLite` output (internal path not surfaced to UI).

### Retired / removed

- **ModSecurity** — retired, replaced by CrowdSec AppSec. Stubs return `ErrNotImplemented`.
- `CS_POLLER_LAPI_KEY` env variable — never set; key comes from CredentialStore only.
- `internal/ui/ai_key_contract_test.go` — superseded by `provider_boundary_test.go`.

### Security

- Confirmed: no real LAPI keys or API tokens in git history or working tree.
- `crowdsec.lapi_key` redacted automatically by `isSensitiveAuditKey` (substring `"api_key"`).
- CSRF protection on all admin routes.
- Key never displayed in UI response, log, or audit trail after initial set.

### Known limitations

- `internal/cloudflare/transport` (Cloudflare mutations) and `internal/crowdsec/adapter` (cscli bans): no unit tests yet — these boundaries are integration-tested via the running daemon.
- Recidivist escalation, `/24` auto-ban, and allowlist-sync flows remain in Python stubs (v1.5.1 backlog).
- RPM package skipped — `rpmbuild` not available in CI; `.deb` only.

---

## [v1.1.1] and earlier

Pre-release development. Python remains the source of truth for all prior versions.

[v1.5.0]: https://github.com/jmrGrav/security-automation-go/releases/tag/v1.5.0
