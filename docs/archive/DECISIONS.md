# DECISIONS

## 2026-06-02 - AI provider activation stays file-backed and UI-local

Decision:

- Keep the AI provider contract file-backed only: `AI_PROVIDER_*_API_KEY_FILE`
  is the supported secret path, and raw `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`
  / `GEMINI_API_KEY` values are not consumed by the runtime.
- Activate providers only through the UI runtime path in
  `cmd/cf-sync/ui_runtime.go` by constructing them from `ai.FromEnv()` and
  injecting them into the existing gateway.
- Keep the provider adapters disabled by default and fail closed when the
  provider flag, model, or secret file is missing or unreadable.
- Preserve the read-only MCP boundary; AI provider wiring is only for AI Explain.
- Manage operator enable/disable and last-test metadata in the non-secret state
  file `/etc/security-automation/providers/ai-providers.env`; keep raw key
  material only in `/etc/security-automation/secrets/*_api_key`.

Reason:

- The repository already has a safe adapter/gateway boundary; the remaining gap
  was runtime wiring, not a new security model.
- File-backed secrets reduce accidental logging and keep the activation path
  explicit for operators.

Impact:

- OpenAI, Anthropic, and Gemini are ready to activate once operator-supplied
  secret files and enable flags are present.
- No new raw-secret environment variables are introduced.
- The MCP server remains read-only and unchanged.
- The `/providers` UI can rotate keys, toggle providers, and record redacted
  test metadata without ever exposing a secret value.

## 2026-06-02 - Pre-shadow acceptance relies on existing read-only boundaries

Decision:

- Treat the current AI Explain, MCP read-only, UI auth/CSRF, quota refresh,
  scheduler bounding, retention cleanup, and checkpoint-aware archive
  compaction as the accepted pre-shadow boundary.
- Do not expand scope or add new features during acceptance review; only fix
  broken wiring, missing guards, or incorrect documentation if they appear.

Reason:

- Acceptance review is a verification pass, not a product-tranche pass.
- The current control-plane shape is intended to be exercised in shadow mode as
  is, provided no new mutator surface appears.

Impact:

- The remaining shadow decision can be made on operational readiness rather
  than on unresolved wiring uncertainty.

## 2026-06-02 - Shadow hardening must use opportunistic cleanup, not hidden janitors

Decision:

- Keep long-run retention cleanup in existing hot paths rather than introducing
  background janitor goroutines for the shadow-hardening loop.
- Bound the scheduler queue, journal, timeline projection, reporting evidence,
  report outbox, AI cache, UI sessions, and decision-gate lock map with
  finite caps and retention-based cleanup.
- Keep raw replay event-history pruning conservative until a separate
  checkpoint-aware retention policy is defined.
- Do not introduce aggressive purge of the canonical raw event archive until
  replay and checkpoint logic can prove the deletion is safe for deterministic
  restoration.
- When purging raw events, the cutoff must be the oldest retained valid runtime
  checkpoint for the scope/name pair, and the compactor must refuse to run if
  that checkpoint boundary cannot be validated.

Reason:

- The repo already treats hidden goroutines as a risk.
- Opportunistic cleanup keeps the lifetime changes explicit and testable while
  avoiding an extra lifecycle manager just for retention.
- Deterministic replay semantics should not be weakened by accidental event
  history deletion.

Impact:

- Shadow-mode long-run memory and storage growth are now bounded on the hot
  path.
- The retention policy remains visible in code and tests rather than hidden in
  a daemon.
- Replay/archive pruning can be revisited later with an explicit
  checkpoint-aware policy, and the canonical raw archive stays conservative
  until then.
- Raw archive compaction is now checkpoint-aware and replay-safe, so the
  remaining 90-day risk is operationally bounded rather than open-ended.

## 2026-06-01 - Security Intelligence and Trusted Networks remain read-only operator views

Decision:

- `/intelligence` is a read-only enrichment lookup surface. It validates IP
  input with `netip.ParseAddr`, records `security_intelligence_lookup`, and
  stays neutral when providers fail or are disabled.
- `/trusted-networks` is a read-only registry explorer. It renders official
  registry sources, exposes dry-run or read-only refresh/diff/export actions,
  and does not auto-allowlist into CrowdSec or Cloudflare.
- External provider failure or partial coverage must not be interpreted as a
  hard-ban signal by itself.

Reason:

- Operator review needs visibility without creating a second mutation path.
- Trusted registry data is useful for evidence and review, but allowlisting
  remains a separate manual decision.

Impact:

- Security intelligence and trusted networks can be used safely in the UI.
- The pages stay compatible with the existing fail-closed runtime and audit
  model.

## 2026-06-01 — Protected Networks Registry: two-layer model, no auto-allowlist

Decision:

- ASN classification (KindProtected/SearchBot/AIAgent/Monitoring) sets `NoHardBan=true` and
  `HardBanAllowed=false` in `Assessment`. This is a pure signal — no code path in the
  enrichment package contacts CrowdSec or Cloudflare.
- All known protected-network entries live in `DefaultRegistry()` in
  `internal/security/enrichment/asn/registry.go`. Every loaded CIDR must reference a
  `SourceURL` fetched in the same session as the commit.
- Propagating a protected ASN to a CrowdSec allowlist or Cloudflare whitelist is always:
  manual, audited, and preceded by a dry-run.
- Anthropic IP ranges added (160.79.104.0/21, 2607:6bc0::/48) from
  https://platform.claude.com/docs/en/api/ip-addresses (verified 2026-06-01).

Reason:

- Automatic allowlisting based on ASN would silently whitelist any traffic originating
  from a cloud provider that also hosts the protected organisation.
- The registry gives operators a single auditable list of all protected ranges and their
  official sources, without coupling classification to allowlist mutation.

Roadmap — Protected Networks Management UI (future):

  A future operator screen will display the registry in the UI with:
  * organisation, ASN (if known), CIDRs, source URL, last-verified date, status badge
  * badge states: Up to date / Update available / Source unavailable / Manual review required
  * Actions: Refresh (re-fetch source), View diff, Approve update, Export
  * Explicit opt-in buttons to propagate to CrowdSec allowlist or Cloudflare whitelist
  * All mutations: manual, audited, dry-run first
  Sources that need periodic refresh:
  - GitHub Copilot: https://api.github.com/meta (weekly)
  - OpenAI ChatGPT-User: https://openai.com/chatgpt-user.json (weekly, 237 /28 blocks)
  - Microsoft Azure: https://www.microsoft.com/en-us/download/details.aspx?id=56519 (weekly)
  - Google Googlebot: https://developers.google.com/search/apis/ipranges/googlebot.json

## 2026-06-01T20:30:00+02:00 - The operator UI must be self-contained and share one rendering shell

Decision:

- Remove the external HTMX CDN dependency from the local operator UI shell.
- Render the forensic page through the same shared `templ` layout as the rest of
  the UI instead of keeping a separate raw HTML renderer.
- Keep the current slice self-contained and network-independent at runtime.

Reason:

- A local operator console should not need a third-party script origin to render
  or function.
- A single rendering shell keeps navigation, styling, and future page additions
  coherent and reduces drift between pages.

Impact:

- The UI remains fully functional without external network access.
- Future operator workflows can extend one shared shell instead of duplicating
  page chrome.
- HTMX can be reintroduced later from a local asset if and when the partial
  update flows are actually needed.

## 2026-06-01T20:30:00+02:00 - UI console socle must reserve future operator routes up front

Decision:

- Keep the dashboard, providers, forensic, about/system, audit, and the future
  operator routes on one shared shell with a persistent sidebar.
- Reserve authenticated coming-soon routes now for timeline, security
  intelligence, trusted networks, cloudflare diff, replay, deban, recovery, and
  drift even before the workflow implementations land.
- Render provider-health and audit-trail foundation pages now so the shell can
  expand without relayout work later.

Reason:

- The operator console will otherwise fragment into one-off layouts once the
  forensic and replay/deban workflows arrive.
- Reserved routes keep the navigation and security model stable while the
  workflow internals are still intentionally disabled.

Impact:

- The shell can grow into the later operator phases without another chrome
  rewrite.
- Auth and security headers already cover the future routes today.

## 2026-06-01T18:00:00+02:00 - GreyNoise permanently removed from scope

Decision: GreyNoise will never be integrated. All references removed.

Reason: Operator direction — will never use it.

Impact: Previous session entry (2026-06-01T16:00) noted GreyNoise was "left out
per operator direction for this slice." This entry supersedes it: the exclusion
is permanent, not slice-scoped.

## 2026-06-01T16:00:00+02:00 - Enrichment must stay fail-neutral and keep GreyNoise out of this slice

Decision:

- Add a local `internal/security/enrichment` engine with DNS/rDNS, ASN, and
  provider scoring scaffolding.
- Treat external providers as contributory only. A timeout, lookup error, or
  missing key must stay neutral.
- Keep VirusTotal manual-forensics only in this slice and keep Spamhaus report
  mode separate from Spamhaus lookup mode.
- Omit GreyNoise from this slice per operator direction.

Reason:

- The UI and runtime need local forensic visibility without creating a second
  hard-ban authority.
- Fail-neutral behavior preserves the existing escalation boundaries and keeps
  the new engine safe to wire into operator workflows later.

Impact:

- Enrichment lookups can improve operator context and scoring.
- Hard-ban decisions still require local signal plus the existing policy path.
- No GreyNoise integration is introduced in this tranche.

## 2026-06-01T16:00:00+02:00 - Local operator UI is read-only by default and keeps secrets local

Decision:

- Add a dedicated local operator UI mode built on Go stdlib `net/http`, `templ`, and HTMX.
- Bind the UI to `127.0.0.1` by default and keep it disabled unless `UI_ENABLED=1` or `ui.enabled=true` is set.
- Require local authentication backed by `UI_SECRET` and/or `UI_SECRET_FILE`; session cookies must be `HttpOnly`, `SameSite=Lax`, and `Secure` when the request is HTTPS.
- Keep mutations disabled by default. `UI_MUTATIONS_ENABLED=1` is required before any destructive UI action can proceed.
- Keep Cloudflare mutations disabled by default. `CLOUDFLARE_MUTATIONS_ENABLED=1` is required before the UI can even preview a live Cloudflare mutation.
- Keep provider API keys out of logs and evidence; show only masked values in the UI and store any local secret file with `0600` permissions.

Reason:

- The operator UI is a local control surface, not a public API. It needs browser ergonomics without weakening the existing fail-closed runtime.
- The repo already has high-risk mutating paths; the UI must not become a second writer or a secret leak.

Impact:

- The new UI mode can be used locally and behind OpenResty without changing the core runtime mutation boundaries.
- The UI can show provider and runtime status while remaining read-only by default.
- Secret handling remains local and audit-friendly.

## 2026-06-01T15:30:00+02:00 - CrowdSec writer boundary is enforced in code

Decision:

- The single CrowdSec write authority is `crowdsec.Client` (cscli subprocess
  through one injectable `cscliRunner`).
- `crowdsec.Client` now owns the full intended write surface:
  add/delete IP decisions, add/delete range decisions, add/remove allowlist
  entries, list allowlists, and list active decisions.
- Narrow future-facing interfaces are defined at the boundary:
  `DecisionWriter`, `DecisionRemover`, `AllowlistWriter`, `AllowlistReader`,
  and `CrowdSecAdminWriter`.
- `adapter.CSCLIExecutor` is no longer a second subprocess writer. It preserves
  batch semantics only and delegates every mutation to a supplied
  `crowdsec.DecisionManager`; the default constructor injects
  `crowdsec.Client`.
- Future UI, replay Cloudflare to CrowdSec, manual deban, manual allowlist, and
  orchestrator forward-write flows MUST depend on those interfaces and MUST NOT
  shell out to `cscli` directly.

Reason:

- Two independent subprocess writers would risk dual-write / split-authority,
  diverging validation, and inconsistent timeout/audit behavior.
- The prior dormant `CSCLIExecutor` still had its own `os/exec` path. Even if it
  was not wired live, that was an attractive nuisance for future UI/replay/deban
  work. Delegation removes the second writer while preserving the batch adapter
  shape.

Impact:

- Tests prove `crowdsec.Client` satisfies the narrow interfaces.
- Tests prove `CSCLIExecutor` delegates to an injected writer and does not expose
  or execute raw `cscli` commands itself.
- A static regression test fails if CrowdSec write command fragments
  (`decisions add/delete`, `allowlists add/remove`) appear outside
  `internal/crowdsec/client.go`.
- Behavior remains compatible for current runtime callers; the hardening affects
  future/deferred writer paths and validation at the single boundary.

## 2026-06-01T15:00:00+02:00 - CrowdSec has exactly ONE write boundary (historical pre-enforcement decision)

Decision:

- This decision recorded the intended single-boundary rule before enforcement.
- It is superseded by the 2026-06-01T15:30 decision above, which transformed
  `adapter.CSCLIExecutor` into a delegating adapter and removed its direct
  subprocess writer role.

## 2026-06-01T14:00:00+02:00 - CrowdSec cscli batch executor stays DORMANT (not wired live)

Status:

- Historical. Superseded by the 2026-06-01T15:30 enforcement decision: the
  executor no longer owns a direct subprocess writer and now delegates to the
  `crowdsec.Client` write boundary.

Decision:

- Keep `internal/crowdsec/adapter.CSCLIExecutor` dormant. Do NOT wire it into any
  live runtime path. Verdict: **KEEP DORMANT** (not INTEGRATE LIVE, not REMOVE).

Reason:

- The live cscli decision-writing path already exists and is wired:
  `crowdsec.Client.AddIPDecision` / `AddRangeDecision` (`cscli decisions add
  --ip|--range`), injected as `Escalator` / `CSRangeBanner` into the `recidive`
  and `cidrban` services in `internal/app/app.go`. Inputs are validated upstream
  (recidive rejects non-`net.ParseIP` IPs before escalating).
- `adapter.CSCLIExecutor` is a separate, **redundant** implementation of the same
  `cscli decisions add/delete` semantics, intended as the execution backend for
  the orchestrator pipeline. But `internal/orchestrator/pipeline` runs **DryRun
  only** — it imports `translator`+`validation`, never `adapter`, and never
  executes translated actions. Nothing constructs `CSCLIExecutor`.
- Wiring it live would create a second, competing, ungoverned cscli write path
  (dual-write / split-authority risk) and would NOT improve correctness,
  observability, recovery, security, or operability.
- The orchestrator translate→execute chain is also not cscli-ready end to end:
  the translator emits Cloudflare target names as scope (`ip`, `ip_range`, ...)
  and, for deletes, sets `Value` to a stable-identity-key string rather than a
  bare IP, with explicit TODOs. So INTEGRATE LIVE is premature regardless.
- REMOVE was considered and rejected: the executor is the deferred forward-write
  seam for the orchestrator; the project intentionally retains deferred scaffolding
  and keeps Python as source of authority. Revisit removal only if the orchestrator
  forward-write path is formally abandoned.

Hardening applied (because it builds raw cscli arguments if ever wired):

- Fail-closed input validation added at the executor boundary
  (`validateExecOperation` in `internal/crowdsec/adapter/cscli.go`), applied to
  BOTH add and delete before any args are built or any process is spawned:
  action allowlist (`add_decision`/`delete_decision`), scope allowlist
  (`ip`/`range`), `net.ParseIP` for scope `ip`, `net.ParseCIDR` for scope
  `range`, rejection of empty value, rejection of any field starting with `-`
  (flag injection), and a strict duration format for adds.
- The shared `internal/crowdsec/validation` package was deliberately NOT
  tightened: it is load-bearing for the wired orchestrator DryRun stage, and the
  translator output is not cscli-conformant, so stricter rules there would break
  the live dry-run. This is an intentional deviation from the literal "harden the
  validation" instruction, justified by primary-source evidence in the code.

Impact:

- No runtime behavior change: the executor remains uncalled in production.
- Risk closed: if the executor is ever wired, malformed/injection-prone cscli
  arguments now fail closed instead of reaching the binary.

## 2026-06-01T06:10:00+02:00 - Release readiness is separate from final production cutover

Decision:

- Treat the local Go repository as release-ready only after documentation, operator checklist, and local validation evidence are coherent.
- Keep final production cutover gated by external shadow soak completion, controlled-authority rehearsal, rollback confirmation, and operator approval.
- Keep Python as the rollback/source-of-authority path until that final gate is executed.

Reason:

- Local green tests and audits prove artifact readiness, not that the live host has already switched authority.
- The cutover is an operational state transition and must remain explicit.

Impact:

- Documentation now distinguishes release readiness, cutover readiness, and completed production cutover.
- Operators get a concrete checklist instead of inferring cutover state from audit verdicts.

## 2026-06-01T05:45:00+02:00 - Convergence and hostile drift must fail closed instead of panicking or staying active

Decision:

- Treat a missing current snapshot during convergence validation as non-converged with an invariant violation.
- Allow emergency transition to `Quarantined` from stable and active FSM states when hostile drift is detected.

Reason:

- Provider/discovery failures can leave convergence without a current snapshot; panicking would bypass controlled runtime handling.
- The drift engine already classified hostile remote deletion as requiring quarantine, but the FSM transition table could reject that fail-closed action from several states.

Impact:

- Normal convergence success and mismatch behavior are unchanged.
- Hostile drift now reaches the intended fail-closed state instead of depending on the current lifecycle phase.

## 2026-06-01T05:10:00+02:00 - AbuseIPDB outbox retry claims must be lease-checked at update time

Decision:

- Keep the AbuseIPDB outbox retry worker offline and SQLite-backed, but require `ClaimRetryable` to return only rows whose claim lease update succeeds.
- Re-check retry eligibility in the `UPDATE` predicate so stale selections do not become duplicate upstream reports.

Reason:

- Selecting retryable rows and then updating by `evidence_id/status` alone leaves a race window under concurrent workers.
- The outbox is an external reporting path, so duplicate claims are a runtime correctness and operator trust risk.

Impact:

- Concurrent workers converge on one active lease per retryable row.
- Retry semantics remain unchanged after the claim lease expires.

## 2026-06-01T05:10:00+02:00 - Destructive cleanup throttling should respect cancellation

Decision:

- Keep cleanup deletion semantics unchanged, but make the post-delete throttle observe `context.Context`.
- Return cancellation instead of continuing to the next Cloudflare deletion after the operator or service manager cancels the run.

Reason:

- Cleanup is a destructive path. Once cancellation is requested, continuing to delete additional rules is worse than stopping early with an explicit error.

Impact:

- Normal cleanup runs are unchanged.
- Interrupted cleanup runs are safer and easier to reason about.

## 2026-06-01T04:30:00+02:00 - `cf-cleanup` should expose a dry-run mode

Decision:

- Keep `cmd/cf-cleanup` as an operational mutator, but require a `--dry-run` mode that plans deletions without mutating Cloudflare.
- Preserve fail-closed behavior on Cloudflare list/delete failures.

Reason:

- `cf-cleanup` is a destructive path and needs an operator-safe planning mode.
- Dry-run gives reproducibility and confidence without changing the live mutation semantics.

Impact:

- Cleanup is safer to run during homelab operations and incident response.
- The command remains a live mutator when dry-run is not set.

## 2026-06-01T04:22:00+02:00 - `cmd/cf-cleanup` is an active destructive path and must remain covered

Decision:

- Treat `cmd/cf-cleanup` as a critical operational path, not a dead wrapper.
- Keep cleanup regressions in the test suite.
- Fail the cleanup run if any Cloudflare deletion fails, so partial failure is not reported as a full success.

Reason:

- The command deletes Cloudflare IP access rules and therefore has direct mutation risk.
- Returning success after a partial delete failure would hide an operational incident.

Impact:

- Cleanup stays visible, testable, and operator-safe.
- The command remains a live control path that must be audited like any other mutating entrypoint.

## 2026-06-01T04:08:42+02:00 - Test hardening should prioritize invariants over coverage vanity

Decision:

- Add tests only where they protect invariants, determinism, error behavior, storage contracts, or operator-visible outcomes.
- Treat standalone hash helpers, constructor wrappers, and wiring seams as optional unless they influence a critical contract.

Reason:

- The useful coverage gaps left in the codebase are now mostly second-order proof gaps, not architecture gaps.
- Coverage that does not protect a contract should remain deferred rather than forcing noise into the suite.

Impact:

- Test hardening stays focused on behavior that matters operationally.
- Remaining low-value coverage gaps can be documented explicitly instead of chased mechanically.

## 2026-06-01T02:40:00+02:00 - The reporting gate extraction is behaviorally neutral and should stay

Decision:

- Keep `internal/services/reporting/decisionGate` as the internal home for duplicate-fingerprint tracking, IP lock serialization, and clock control.
- Treat the extraction as a permanent structural improvement, not as provisional scaffolding.

Reason:

- Dedicated tests now prove the extraction is neutral and that the service behavior remains unchanged.
- Reintroducing this state into `Service` would re-concentrate accidental coordination without adding value.

Impact:

- Reporting remains coherent while being less entangled.
- The remaining hotspots are intentional coordination boundaries, not accidental debt.

## 2026-06-01T02:25:00+02:00 - `decisionGate` extraction must be kept and covered by direct tests

Decision:

- Keep `internal/services/reporting/decisionGate` as the home for duplicate fingerprint tracking, IP lock serialization, and injected clock control.
- Add direct tests for the gate instead of reintroducing the state into `Service`.

Reason:

- The gate was a real accidental coupling point, not just a naming change.
- Direct tests prove the extraction is behaviorally neutral and keep the seam honest.

Impact:

- The reporting package is easier to maintain without fragmenting the actual reporting workflow.
- The extracted state now has explicit regression coverage.

## 2026-06-01T02:10:00+02:00 - Reporting dedup and IP locking should live behind an internal decision gate

Decision:

- Move duplicate-fingerprint tracking and IP lock serialization out of `internal/services/reporting.Service` and into a dedicated internal gate.
- Preserve the existing reporting API and decision semantics.

Reason:

- The mutable concurrency state in `Service` was still a maintainability hotspot.
- A dedicated gate makes the responsibility explicit without changing runtime behavior.

Impact:

- Reporting is a little less entangled and easier to audit.
- The package remains central by responsibility, but the state boundary is cleaner.

## 2026-06-01T02:10:00+02:00 - `cmd/cf-sync` bootstrap/runtime should be split by execution mode

Decision:

- Keep `cmd/cf-sync/main.go` as a thin CLI wrapper.
- Keep shared config/bootstrap and dependency assembly in `cmd/cf-sync/runtime.go`.
- Keep `cli`, `status`, and `doctor` rendering in `cmd/cf-sync/mode_runtime.go`.
- Keep daemon server/bootstrap/signal handling in `cmd/cf-sync/daemon_runtime.go`.
- Preserve flags, defaults, startup order, and failure semantics.

Reason:

- The previous monolithic runtime file was still a composition hotspot even after earlier helper extraction.
- Splitting by execution mode reduces cognitive load without changing the runtime model.

Impact:

- `cmd/cf-sync` is materially easier to navigate.
- The split is behavior-neutral and remains within the current architecture.

## 2026-06-01T01:45:00+02:00 - Bootstrap composition should live outside `main.go`

Decision:

- Keep `cmd/cf-sync/main.go` as a thin CLI wrapper.
- Keep runtime composition and mode dispatch in `cmd/cf-sync/runtime.go`.
- Keep scope/state/bootstrap and external client setup in dedicated helper files.
- Preserve flags, defaults, startup order, and error semantics.

Reason:

- This reduces the main entrypoint to a clear wrapper without changing runtime invariants.
- The change improves readability and testability of startup code while keeping the same operational behavior.

Impact:

- The composition root is now structurally clearer.
- The remaining Brooks hotspot is concentrated in reporting, not in startup glue.

## 2026-06-01T01:30:00+02:00 - Brooks cleanup has reached the reasonable maximum without a larger architectural split

Decision:

- Stop pursuing further small Brooks-driven extractions in the current pass.
- Treat `cmd/cf-sync` and `internal/services/reporting` as the remaining structural hubs.
- Do not attempt a larger refactor unless the team explicitly accepts a broader architectural change.

Reason:

- The remaining hotspots are not simple file-level density anymore.
- Any further meaningful reduction would require splitting the composition root or reworking the reporting coordination model more deeply.
- That crosses the line from Brooks cleanup into architectural change.

Impact:

- The campaign can now be described honestly as `BROOKS MAXIMUM REACHED`.
- The code remains behaviorally neutral and validated.
- This was an interim decision; the later proof pass extracted the real accidental state and superseded the maximum-reached claim.

## 2026-06-01T01:00:00+02:00 - Mechanical bootstrap extraction can continue when it reduces file-level density only

Decision:

- Keep splitting the `cmd/cf-sync` composition root into narrow helpers when the extraction is purely mechanical.
- Keep policy conversion and external client assembly outside `main.go`.
- Keep startup ordering, flags, and defaults unchanged.

Reason:

- The remaining Brooks issues are maintainability and readability, not semantic correctness.
- Mechanical glue extraction lowers the cost of change without changing runtime behavior.

Impact:

- `cmd/cf-sync/main.go` is thinner again.
- Behavior remains neutral and validation-driven.

## 2026-06-01T00:45:00+02:00 - Main bootstrap glue can be split into small helpers when the extraction is mechanical

Decision:

- Move HTTP client initialization into `cmd/cf-sync/bootstrap.go`.
- Move external client assembly and policy conversion into `cmd/cf-sync/setup.go`.
- Keep the startup sequence, flags, defaults, and runtime semantics unchanged.

Reason:

- The remaining Brooks concern is maintainability density in the composition root, not runtime correctness.
- Mechanical extraction reduces file-level noise without changing policy or execution order.

Impact:

- `cmd/cf-sync/main.go` is narrower and easier to scan.
- The runtime remains behaviorally neutral.

## 2026-06-01T00:30:00+02:00 - Bootstrap error messages should be operator-actionable without changing startup semantics

Decision:

- Keep config validation fail-closed, but include the config path, required environment variables, and allowed runtime profiles in the error text.
- Keep `cmd/cf-sync` startup failures on `stderr` and include scope/path context for SQLite and OPA initialization errors.
- Move only mechanical bootstrap setup into `cmd/cf-sync/bootstrap.go` so the composition root becomes easier to scan without changing ordering or runtime behavior.

Reason:

- The main complaint from the Brooks pass was maintainability and operator clarity, not runtime correctness.
- These changes improve diagnosis while preserving execution order and failure semantics.

Impact:

- Startup errors are more actionable for Ubuntu/systemd operators.
- `cmd/cf-sync/main.go` is less dense, but the runtime surface is unchanged.

## 2026-06-01T00:00:00+02:00 - Scheduler startup should enumerate persisted scopes rather than invent a placeholder scope

Decision:

- Let `internal/runtime/state.StateStore` expose persisted scope enumeration.
- Have `internal/runtime/scheduler/stateful.Scheduler` discover runtime scopes from persisted state and enqueue one work item per scope.
- Fall back to the caller-provided zone only when no persisted scopes are available or listing fails.

Reason:

- The scheduler should reflect persisted control-plane partitions instead of deriving a synthetic current scope.
- The change stays local to startup wiring and does not alter scheduling policy or the worker model.

Impact:

- Scheduler partitioning is now grounded in runtime state rather than placeholder derivation.
- The remaining limitation is still the shared worker pool, so the architecture audit keeps hard worker isolation as `PARTIAL`.

## 2026-06-01T00:00:00+02:00 - `internal/app` helper logic should live outside the main composition file when the behavior is unchanged

Decision:

- Move allowlist filtering, Lua state projection, and CIDR/recidive adapter helpers into `internal/app/runtime_helpers.go`.
- Keep the runtime wiring and main run loop in `app.go`.

Reason:

- The app package was still carrying too many support helpers in one file, which made maintenance harder without adding architectural value.

Impact:

- `app.go` is smaller and easier to scan.
- Behavioral scope did not change; the refactor only reduced file-level coordination density.

## 2026-06-01T00:00:00+02:00 - CrowdSec sync and shadow-mode execution should live outside the main app composition file

Decision:

- Move the CrowdSec sync, Cloudflare diffing, and shadow-mode reporting flow into `internal/app/crowdsec_sync_runtime.go`.
- Keep `app.go` focused on type definitions and constructors.

Reason:

- The `CrowdSecSyncApp` execution path was still the densest coordination hotspot in the package.

Impact:

- The app package is less file-concentrated and easier to maintain.
- The execution behavior is unchanged; only the file layout changed.

## 2026-05-31T18:10:00+02:00 - Runtime recovery and rollback resume must validate plan and checkpoint identity before reuse

Decision:

- Make lease acquisition atomic at the SQLite boundary for `(scope_id, action)` and let the lease store reject conflicting active owners under a single transaction.
- Remove timestamp dependence from fallback event UID generation so the same logical event maps to the same idempotency key across replay/restart.
- Validate checkpoint scope/name/sequence/event_id/canonical state before replaying from it, and allow fallback to an earlier valid checkpoint or genesis only when explicitly permitted.
- Persist rollback plan identity (`plan_hash`, `operation_ids`, `operation_count`) and refuse resume when the persisted checkpoint does not match the current plan.
- Restore/quarantine must verify restored SQLite content before swap, keep the current DB recoverable on validation failure, and only clear degraded mode after successful integrity verification.

Reason:

- These are the remaining semantics that matter for deterministic recovery and safe operational restart; they should fail closed instead of drifting silently.

Impact:

- Lease authority is now atomic at the storage layer.
- Event idempotency becomes restart-stable.
- Checkpoint replay and rollback resume now reject stale or mismatched state instead of silently proceeding.
- Restore/quarantine is more defensible under WAL and corrupt snapshot scenarios.

## 2026-05-31T17:15:00+02:00 - Operational signals should be observable without blocking runtime paths

Decision:

- Add fail-open counters for evidence write failures, telemetry publish failures, outbox pending/failed/reported, malformed Cloudflare WAF events, Cloudflare replay cursor load/save failures, runtime recovery divergence, ownership invariant violations, SQLite degraded mode, and SQLite quarantine creation.
- Keep the counters local to the existing runtime/reporting/storage paths.

Reason:

- These states are operationally important, but telemetry must not become a new failure mode or change runtime policy.

Impact:

- The control plane now exposes more of its recovery and reporting state without blocking mutations or replay.

## 2026-05-31T17:15:00+02:00 - Reporting service may be split into smaller helpers when the extraction is behavior-preserving

Decision:

- Keep the `internal/services/reporting.Service` behavior unchanged while extracting small helper methods for suppressed decision handling and report finalization.

Reason:

- The service was still carrying too much flow logic in one method, but a narrow extraction is safe and does not change policy.

Impact:

- `Service.Process` is slightly easier to read and audit without affecting the runtime decision model.

## 2026-05-31T17:45:00+02:00 - Outbox retries should be atomically claimed before upstream AbuseIPDB calls

Decision:

- Add a claim lease to `OutboxWorker` and let the SQLite reservation store claim retryable rows before reporting.
- Start the outbox worker in `cmd/cf-sync` daemon mode under the daemon context.
- Short-circuit pending same-idempotency reservations instead of sending them upstream again.

Reason:

- Retryable outbox rows were still vulnerable to duplicate processing across workers, and same-idempotency pending reservations were not being reused.

Impact:

- AbuseIPDB outbox retries are now more durable under concurrency without changing the external reporting policy.

## 2026-05-31T16:00:00+02:00 - Cosmetic test coverage should be removed when it does not protect behavior

Decision:

- Remove reporting-runtime constructor/wiring smoke tests when they only prove `New...` returns non-nil dependencies.
- Remove propagation-only state machine tests when they do not protect a runtime invariant or persistence contract.
- Keep tests that prove real behavior:
  - recovery restore and checksum validation
  - heartbeat renew then lost-lease behavior
  - SQLite event append idempotency and commit ambiguity handling

Reason:

- Coverage that only exercises constructors or setters creates confidence without protecting regressions that matter.

Impact:

- The suite becomes smaller and more meaningful without changing runtime semantics.

## 2026-05-31T16:00:00+02:00 - Recovery snapshot enumeration should carry checksum metadata

Decision:

- Compute checksum metadata when enumerating recovery snapshots so restore can validate the snapshot content path through the same metadata structure used by the engine.

Reason:

- Restore tests need a durable checksum path, not just a file copy assertion, and the existing snapshot listing already owns the directory scan.

Impact:

- Restore validation can now assert checksum-aware behavior without changing the recovery control flow.

## 2026-05-31T16:00:00+02:00 - SQLite corruption/quarantine tests may use a narrow integrity seam

Decision:

- Allow a test-only integrity-check override path in `internal/storage/sqlite.DB`.
- Use that seam to force `QuarantineCorruption` through the failure path deterministically.

Reason:

- A healthy database pretending to be corrupt is a coverage illusion.
- A narrow seam is cheaper and safer than a flaky on-disk corruption fixture.

Impact:

- Quarantine behavior is now testable without changing the runtime policy or the storage backend.

## 2026-05-31T16:00:00+02:00 - Operational drills should stay deterministic and offline

Decision:

- Add replay/restart, outbox retry, and split-brain lease drills under `internal/testing/chaos`.
- Keep long soak coverage behind a build tag so normal CI stays fast and deterministic.
- Document the operator runbook separately instead of folding it into code comments.

Reason:

- Operational proof needs failure-mode scenarios, but those scenarios must not make the main test suite flaky or slow.

Impact:

- The repository gains repeatable operational drills without turning the baseline suite into a soak job.

## 2026-05-29T15:20:00+02:00 - Ownership claim store should be runtime authority when configured

Decision:

- Add an optional `ClaimStore` boundary to `runtime/ownership.Resolver`.
- When configured, `Resolve` reads the current claim from store and treats it as authority.
- `Claim` persists to store first, then updates in-memory cache.
- cf-sync runtime wiring configures resolver claim store to SQLite `OwnershipRepository`.

Reason:

- Memory-only claims can drift after restart and break ownership consistency guarantees.
- Durable store authority closes restart drift risk without a broad rewrite.

Impact:

- Ownership decisions remain consistent across process restarts.
- In-memory claim cache is now a mirror/optimization, not the source of truth.

## 2026-05-29T15:20:00+02:00 - AbuseIPDB outbox worker may be lease-bound optionally

Decision:

- Add optional `OutboxLeaseGuard` to `services/reporting.OutboxWorker`.
- If configured and guard refuses an item, the worker skips upstream reporting for that item and emits evidence/telemetry.
- Default behavior remains unchanged when no guard is configured.

Reason:

- Reporting paths may need leadership/lease coupling in HA deployments, but this must be opt-in to avoid changing existing retry behavior.

Impact:

- Enables safe lease-bound execution for outbox retries where required.
- Preserves current retry semantics for existing deployments.

## 2026-05-29T14:10:00+02:00 - Production mutation paths should require explicit fencing metadata

Decision:

- Extend `LeaseStoreFencingValidator` with strict mode (`RequireFencing(true)`).
- Enable strict fencing in cf-sync wiring for governed mutation execution and rollback execution.
- In strict mode, scoped mutations must include `scope_id`, `lease_id`, and `fencing_token`; missing metadata is rejected before mutator calls.

Reason:

- Without strict metadata requirements, stale or unbound mutation paths can accidentally bypass leadership/fencing guarantees.
- The no-big-rewrite fix is to tighten validator semantics and production wiring, not redesign the orchestration model.

Impact:

- Fencing propagation is fail-closed on production write paths.
- Leader races where active lease changes mid-batch are now explicitly tested and stop remaining mutations.

## 2026-05-29T13:05:00+02:00 - Rollback execution progress must be durable and resumable

Decision:

- Add a dedicated durable rollback checkpoint store in SQLite (`rollback_checkpoints`).
- Persist rollback batch progress at:
  - start
  - each completed compensation operation
  - failure
  - completion
- Reload rollback checkpoints by `batch_id` before execution and resume from persisted `last_completed_op_idx`.
- If persisted checkpoint is already `completed` with all operations done, short-circuit without re-executing provider mutations.

Reason:

- In-memory rollback progress is insufficient after crash/restart and leaves compensation safety dependent on process continuity.
- The minimum safe change is durable progress persistence with idempotent resume, not a full rollback orchestration rewrite.

Impact:

- Recovery/restart can resume rollback batches deterministically from persisted progress.
- Duplicate compensation calls are reduced because completed batches are recognized and skipped.
- Existing rollback runtime semantics remain unchanged except for added durability and restart behavior.

## 2026-05-29T10:55:00+02:00 - Ownership lineage pagination should be cursor-based for forensic scale

Decision:

- Keep ownership lineage API response payload as a list (no envelope change), and add cursor pagination via request query params plus response headers.
- Use deterministic cursor ordering on `(created_at DESC, id DESC)`.
- Support CLI cursor navigation with `before_created_at` + `before_id`.

Reason:

- Offset-based pagination becomes unstable and expensive under sustained append volume.
- Cursor pagination preserves chronological forensic browsing without breaking existing clients expecting list payloads.

Impact:

- Existing semantics remain backward-compatible.
- High-volume ownership lineage browsing is more stable and predictable.

## 2026-05-29T10:25:00+02:00 - Ownership lineage must be queryable and explainable as first-class forensic evidence

Decision:

- Expose ownership lineage through CLI and API v3 list/get/explain surfaces.
- Keep lineage read paths directly backed by durable SQLite append-only records.
- Validate ownership divergence behavior under multi-scope restart/replay via deterministic tests.

Reason:

- Durable lineage without a direct query/explain path leaves forensic triage incomplete.
- Multi-scope replay/restart tests are required to prove scope isolation and deterministic divergence signaling.

Impact:

- Operators can inspect ownership governance history by scope/resource/event id without touching raw tables.
- Recovery divergence diagnostics now have stronger regression coverage for restart scenarios.

## 2026-05-29T09:40:00+02:00 - Ownership authority must have durable lineage and recovery invariants

Decision:

- Persist ownership lineage as append-only records in SQLite (`ownership_lineage`).
- Emit lineage events from ownership resolution and claim paths.
- Validate ownership claim/lineage coherence during recovery and fail closed on violations.

Reason:

- Ownership decisions are part of governance evidence; claim-only snapshots are insufficient for forensic replay and anomaly triage.
- Recovery must reject ambiguous ownership states to keep deterministic safety guarantees.

Impact:

- Durable, queryable ownership ancestry now exists.
- Recovery reports now include ownership invariant violations and issue details.
- Runtime wiring in `cmd/cf-sync` records lineage without introducing a broad refactor.

## 2026-05-28T20:25:00+02:00 - AbuseIPDB outbox reservations must be idempotent and expirable

Decision:

- A pending AbuseIPDB reservation with the same `idempotency_key` is treated as idempotent.
- A fresh pending reservation for the same IP blocks a different report attempt.
- An expired pending reservation is marked `failed` before a new reservation for the same IP can be accepted.
- Updating an outbox row status must fail if no row is actually updated.

Reason:

- A durable reservation prevents duplicate upstream reports, but a crash or abandoned pending row must not become a permanent unexplained suppression.

Impact:

- The outbox now preserves at-most-one active same-IP report path while still allowing deterministic recovery from stale pending rows.
- Operators can distinguish active suppression, expired pending recovery, and missing outbox lineage.

## 2026-05-28T18:10:00+02:00 - Ambiguous runtime event commits must be explicit

Decision:

- Runtime event append returns `sqlite.ErrCommitAmbiguous` if `Commit()` fails and the event cannot be found by `(scope_id, event_uid)`.

Reason:

- Treating an ambiguous commit as a transient retry risks duplicate logical events or replay divergence. The safe behavior is idempotent success only when the durable row exists, otherwise an explicit critical error.

Impact:

- Callers and tests can distinguish commit ambiguity from duplicate idempotent append and normal transient failures.

## 2026-05-28T18:10:00+02:00 - Lost lease must cancel mutation context

Decision:

- Provider mutators may implement context-aware execution.
- Rollback execution binds its context to the HA heartbeat and cancels with a lost-lease cause when renewal fails.
- Execution records `lost_lease_mutation_aborted` when a batch or operation stops because the context was cancelled.

Reason:

- A heartbeat signal alone does not prevent zombie provider mutations. Cancellation must reach the execution path and provider call boundary.

Impact:

- Long Cloudflare mutations can now observe cancellation.
- Partial execution is auditable and flagged for recovery.

## 2026-05-28T18:10:00+02:00 - AbuseIPDB reports require durable reservation before upstream call

Decision:

- When the SQLite reporting stores are configured, AbuseIPDB reporting reserves a durable outbox row and persists `report_pending` evidence before calling the upstream API.
- Reservation failure or pending-evidence failure suppresses the upstream report.

Reason:

- A successful upstream report without durable evidence or anti-flood state breaks forensic guarantees and can lead to duplicate reports after restart.

Impact:

- The operational guarantee is at-least-once source ingest with at-most-one pending/upstream AbuseIPDB report path per IP reservation, plus durable 24h report dedup after success.

## 2026-05-28T18:10:00+02:00 - Reporting evidence search must use SQL-projected fields

Decision:

- Project `decision` and `abuse_type` into `abuseipdb_reporting_evidence` and index common forensic filters.

Reason:

- Filtering large evidence sets in memory makes CLI/API forensic queries unstable under append volume.

Impact:

- IP/source/decision/suppression/date searches can remain stable as evidence volume grows.

## 2026-05-28T06:13:30+02:00 - Runtime event append should use scoped idempotency keys for commit ambiguity

Decision:

- Add `event_uid` to runtime events and enforce scoped uniqueness in SQLite.
- Resolve duplicate or ambiguous appends by looking up the existing `(scope_id, event_uid)` row instead of allocating a new sequence.

Reason:

- Retrying a full append after a commit error assumes the commit definitely failed. That assumption is too weak for an event-sourced runtime where sequence identity is forensic evidence.

Impact:

- Event append is safer under ambiguous commit outcomes.
- Legitimate duplicate append attempts converge on the original event id/sequence.
- Callers can provide a stable UID explicitly, while legacy callers receive an automatically derived UID.

## 2026-05-28T06:13:30+02:00 - Live lease coordination should use the same scoped lease store seen by recovery

Decision:

- Wire `LeaseManager` to the scoped SQLite `LeaseStore` in `cmd/cf-sync`.
- Keep JSON runtime state as the live state mirror, but use the persistent scoped lease store as the lease authority when configured.

Reason:

- Recovery and anomaly detection already inspect SQLite leases. Live coordination using only JSON state creates two competing lease truths.

Impact:

- Live acquire/release/renew and recovery now observe the same persisted lease authority in the main runtime wiring.
- Existing tests and JSON-only uses remain supported when no lease store is configured.

## 2026-05-28T06:13:30+02:00 - HA heartbeat should be context-bound and explicit

Decision:

- Add an opt-in heartbeat handle that periodically renews active leases through the persistent lease authority, stops on context cancellation, and reports lost lease after bounded renewal failures.

Reason:

- A persisted `RenewLease` primitive is useful only if runtime code can exercise it with clear cancellation and failure semantics.

Impact:

- Longer-running HA paths can now bind mutation work to a lease heartbeat lifecycle.
- Lost-lease handling can be wired without hidden goroutines or implicit global state.

## 2026-05-28T00:05:00+02:00 - Legacy scoped-lease compatibility should be normalized away, not carried forever as a read fallback

Decision:

- Normalize legacy `leases.scope_id=''` rows to the active scoped runtime DB on first repository access, then use strict scoped reads/writes afterward.

Reason:

- The fallback bridge protected upgrades, but leaving it in place permanently would keep an avoidable ambiguity in recovery and HA semantics.

Impact:

- The upgrade path remains safe for existing rows.
- New and existing lease behavior converge on strict `(scope_id, action)` semantics.
- The residual Brooks risk on legacy leases is reduced from permanent design debt to transient migration normalization.

## 2026-05-28T00:05:00+02:00 - Persisted lease stores need an explicit renew primitive even before distributed heartbeat semantics are fully built out

Decision:

- Add `RenewLease` to the lease store boundary and SQLite implementation now, instead of leaving renewal as an implicit future concern.

Reason:

- Recovery/HA correctness is weaker when the only persisted lease semantics are acquire/release and expiry is effectively write-once.

Impact:

- The storage layer now has a clear heartbeat/renew hook.
- Future HA coordination can extend expiry explicitly without redesigning the storage boundary.
- Operational semantics are clearer even before a full heartbeat loop is persisted.

## 2026-05-28T00:05:00+02:00 - Cloudflare replay cursors should advance from processed event time and only on successful critical-path completion

Decision:

- Drive cursor progression from the processed high watermark, replay with a fixed overlap window, and never commit the cursor after a failed reporting batch or failed cursor save.

Reason:

- Advancing cursors by wall clock or on partial failure makes restart safety and delayed-event correctness harder to defend. Overlap plus dedup is cheaper than missed evidence.

Impact:

- Restart/overlap behavior is safer.
- Duplicate windows are absorbed by existing dedup semantics instead of losing events.
- Corrupted cursor loads now fall back safely instead of poisoning the poller lifecycle.

## 2026-05-28T00:05:00+02:00 - Approval workflow should exist as execution primitives before any UI or operator workflow is added

Decision:

- Add approval-required fields and `awaiting_approval` execution semantics to mutation batches/operations now, but keep the behavior inert until those flags are set by policy.

Reason:

- High-impact mutations need replay-safe primitives and audit semantics before any operator-facing approval experience is layered on top.

Impact:

- Execution can now refuse approval-required work deterministically.
- The runtime gains a stable approval foundation without adding UI or new policy features.
- Future approval evidence/lineage can build on existing execution semantics instead of retrofitting them.

## 2026-05-27T18:05:00+02:00 - Live runtime and replay recovery must share one reducer, not duplicate lifecycle logic

Decision:

- Introduce `internal/runtime/reducer` and route both the live state machine and replay recovery through the same transition/event reduction rules.

Reason:

- The Brooks audit found that live and replay were reconstructing leases and rollback state differently. As long as those paths diverge, deterministic recovery and HA claims are not defensible.

Impact:

- Live transition and replay now produce the same `RuntimeState` for the same lifecycle/event inputs.
- Lease cleanup and rollback-lease semantics are centralized.
- Future state mutations now have one obvious place to be made replay-safe.

## 2026-05-27T18:05:00+02:00 - Lease persistence must be scoped by runtime partition, not globally by action

Decision:

- Make `LeaseStore` scope-aware and persist `scope_id` in SQLite `leases`, with anomaly detection querying active leases by `(scope_id, action)`.

Reason:

- The runtime is scoped. Global leases by action allow one scope to contaminate recovery, anomaly detection, and HA semantics of another.

Impact:

- Two scopes can now hold the same action lease independently.
- Recovery no longer reports orphan leases from unrelated scopes.
- Lease semantics are aligned with the scoped runtime/storage model already used elsewhere.

## 2026-05-27T18:05:00+02:00 - Event sequence allocation must be atomic per scope, not derived from `MAX(sequence)+1`

Decision:

- Allocate sequences through a dedicated SQLite `event_sequences` table using transactional upsert/returning semantics, plus bounded retry on `SQLITE_BUSY`.

Reason:

- `MAX(sequence)+1` is not concurrency-safe and breaks the append-only guarantees under legitimate concurrent writers.

Impact:

- Event sequences remain continuous and monotonic per scope under concurrent append.
- The runtime no longer relies on race-prone derived allocation.
- SQLite remains compatible with the single-writer scoped durability model.

## 2026-05-27T18:05:00+02:00 - Checkpoint checksums must cover the full canonical checkpoint proof line

Decision:

- Compute runtime checkpoint checksums from a canonical representation containing name, scope, sequence, event id, state, metadata, schema version, and canonical timestamp.

Reason:

- A checksum that ignores event id, metadata, schema version, or timestamp is not a full integrity proof and can miss forensic-significant tampering.

Impact:

- Checkpoint tampering is now detected across more of the persisted proof surface.
- Recovery/checkpoint validation is more defensible for forensic and replay scenarios.
- Future schema evolution remains part of the integrity contract instead of out-of-band metadata.

## 2026-05-27T17:03:00+02:00 - CLI and API evidence access should share the same reporting evidence model and explanation semantics

Decision:

- Expose reporting evidence over API v3 by reusing the same persisted model and explanation rendering already used by the CLI.

Reason:

- Separate query/explain implementations would quickly drift and weaken operator trust in forensic tooling. The system already had a stable evidence model, so the API should consume it directly instead of inventing a parallel read path.

Impact:

- CLI and API now expose the same forensic evidence semantics.
- Search/show/explain stay aligned across operator interfaces.
- Future tooling can extend one model instead of maintaining multiple incompatible views.

## 2026-05-27T17:03:00+02:00 - Replay verification should treat stored classifier/formatter/policy versions as first-class integrity signals

Decision:

- Extend the reporting replay verifier so stored component versions participate in replay integrity, not just comments, decisions, and hashes.

Reason:

- Once historical evidence is replayed across evolving classifier/formatter/policy code, version drift is itself important forensic information even if hashes or comments still happen to match.

Impact:

- Replay verification now reports version drift explicitly.
- Investigations can distinguish semantic drift from raw data corruption or hash mismatch.
- The evidence model is better prepared for future policy/classifier evolution.

## 2026-05-27T17:03:00+02:00 - Live reporting chaos should prioritize mixed-batch safety over abstract restart theater first

Decision:

- Add targeted mixed-batch live chaos coverage before deeper restart/cursor chaos, focusing on batches that contain both malformed and valid Cloudflare WAF events.

Reason:

- The most immediate operational risk in the current reporting path is incorrect handling of partially malformed real-world batches, not synthetic restart complexity for its own sake.

Impact:

- The Cloudflare replay/reporting path is now regression-tested against mixed malformed/valid batches.
- The chaos slice stays tied to concrete reporting-safety semantics.

## 2026-05-27T16:48:00+02:00 - AbuseIPDB reporting evidence must be queryable directly, not reconstructed from logs

Decision:

- Expose the append-only AbuseIPDB reporting evidence stream through direct CLI query/explain flows backed by the SQLite evidence store.

Reason:

- Once report/suppress evidence became durable, operators needed a first-class way to inspect it without reconstructing decisions from logs, telemetry, or generic audit trails.

Impact:

- `cf-sync -mode evidence` now provides direct forensic access to reporting evidence.
- Query/search/show/explain flows rely on the persisted evidence model rather than ad hoc log parsing.
- The same evidence model can later be surfaced over HTTP without redesigning the storage layer.

## 2026-05-27T16:48:00+02:00 - Reporting evidence should persist hashes and normalized input so replay verification is possible later

Decision:

- Persist canonical hashes and normalized event context alongside each AbuseIPDB report/suppression evidence record.

Reason:

- A replay verifier cannot detect formatter/classifier/policy drift unless the stored evidence carries enough stable context to recompute the decision.

Impact:

- Evidence now stores `input_hash`, `decision_hash`, URI list, categories, canonical decision, and the normalized event payload.
- `internal/services/reporting/replay` can re-evaluate canonical comment and decision integrity deterministically.
- Future forensic tooling can compare historical evidence against newer classifier/formatter/policy versions.

## 2026-05-27T16:48:00+02:00 - Chaos for the reporting pipeline should target failure semantics, not synthetic infrastructure theater

Decision:

- Add targeted failure-path tests around the shared reporting pipeline before adding broader chaos scenarios.

Reason:

- The highest-value operational questions at this stage are whether evidence write failures, telemetry failures, and cross-source duplicate suppression preserve safe behavior without panic or upstream flooding.

Impact:

- The reporting path now has explicit coverage for evidence-store failure and recent-report cross-source suppression behavior.
- The chaos slice stays focused on real failure semantics rather than generic infrastructure simulation.

## 2026-05-27T16:31:00+02:00 - Leaf-stage extraction is still worth doing when it removes real inline orchestration, even without adding new behavior

Decision:

- Extract normalization, execution, and telemetry into explicit orchestrator leaf stages where the control-plane already had stable behavior.

Reason:

- The goal of this slice is structural clarity, not feature delivery. Pulling these leaves out of `DryRun` and `Rollback` reduces hidden flow inside the orchestrator without forcing a risky rewrite of the pipeline contract.

Impact:

- `DryRun` and `Rollback` are easier to read and reason about.
- Validation, reporting, execution, and telemetry now follow a more consistent stage pattern.
- Replay/runtime semantics remain unchanged.

## 2026-05-27T16:31:00+02:00 - Daemon bootstrap concerns should move out of cmd/cf-sync/main.go before the composition root becomes the next monolith

Decision:

- Move API server startup, daemon shutdown-context wiring, and Cloudflare WAF replay poller startup into dedicated daemon/runtime helper files under `cmd/cf-sync`.

Reason:

- `cmd/cf-sync/main.go` was still correct, but it was continuing to accumulate unrelated operational concerns in one place. The control-plane now has enough moving parts that this would become the next readability bottleneck if left alone.

Impact:

- The main composition path is thinner and easier to scan.
- Daemon-specific lifecycle concerns are easier to evolve independently.
- The refactor changes structure only; runtime behavior is preserved.

## 2026-05-27T16:18:00+02:00 - Reporting-side translation belongs in an explicit pipeline stage, not inline in DryRun

Decision:

- Extract AbuseIPDB/reporting-side translation from the inline `DryRun` flow into a dedicated orchestrator reporting stage.

Reason:

- The central orchestrator had already been split into discovery, snapshot, planning, admission, translation, validation, and completion steps. Leaving reporting-side translation inline kept a small but unnecessary mixing of concerns inside `DryRun`.

Impact:

- Translation and reporting are now structurally separate in the pipeline.
- The next execution/telemetry extractions have a cleaner pattern to follow.
- No runtime behavior changed.

## 2026-05-27T16:18:00+02:00 - Composition roots should hide repetitive reporting/security wiring behind small local helpers before they become unreadable

Decision:

- Move repetitive reporting/security runtime construction out of `internal/app/app.go` and `cmd/cf-sync/main.go` into small, package-local helper files.

Reason:

- The wiring was still correct, but the composition roots were again becoming the natural place where operational complexity reconcentrated.

Impact:

- `internal/app` now has a dedicated local WAF reporting runtime helper.
- `cmd/cf-sync` now has explicit helper functions for security telemetry, propagation-guard setup, and WAF replay service construction.
- The refactor keeps behavior identical while lowering the scan cost of the top-level wiring paths.

## 2026-05-27T16:02:00+02:00 - SQLite reporting/security stores should be grouped behind a small facade before composition roots sprawl further

Decision:

- Introduce a small `ReportingStores` facade in `internal/storage/sqlite` that groups the SQLite-backed dedup, evidence, and cursor stores used by the reporting/security slice.

Reason:

- `cmd/cf-sync` and `internal/app` had started wiring several reporting/security stores separately. The behavior was still correct, but the composition roots were becoming harder to scan and easier to drift.

Impact:

- Reporting/security persistence wiring is now thinner and more explicit at the edge.
- The reporting service can be configured from one slice-specific facade instead of several unrelated constructors.
- This is a structural cleanup only; no runtime behavior or persistence semantics changed.

## 2026-05-27T16:02:00+02:00 - Orchestrator decomposition should continue by extracting safe leaf stages, not by rewriting the pipeline

Decision:

- Extract validation and completion into explicit pipeline stages while keeping the existing `DryRun` behavior intact.

Reason:

- The central orchestrator was already improving, but the remaining inline tail of `DryRun` still mixed validation, audit completion, bus emission, health updates, and final state-machine transitions.

Impact:

- `internal/orchestrator/pipeline` is easier to read incrementally.
- Future normalization/reporting/execution/telemetry extraction has a clearer pattern to follow.
- The refactor remains low-risk because it changes structure, not control-plane semantics.

## 2026-05-27T07:21:12+02:00 - AbuseIPDB report deduplication is a durable cross-source rule, not an in-memory optimization

Decision:

- Enforce a strict sliding 24-hour `1 IP = 1 AbuseIPDB report max` rule in the shared reporting layer through a provider-agnostic store boundary (`internal/security/reportdedup`) backed by SQLite durability.

Reason:

- Event-level or in-memory TTL deduplication is not sufficient to prevent flood across process restarts, multiple WAF sources, or repeated local reclassification. The rule must survive restarts and remain source-agnostic.

Impact:

- Cloudflare WAF, CrowdSec, OpenResty, and future classifiers now share the same durable per-IP AbuseIPDB suppression rule.
- Successful reports mark the IP only after upstream success; failed reports do not poison future attempts.
- Store failures fail closed by default to avoid accidental AbuseIPDB flooding during degraded operation.

## 2026-05-27T07:21:12+02:00 - Live local WAF sources must enter the same reporting service as replayed Cloudflare events

Decision:

- Feed real CrowdSec `decisions.log` events and OpenResty Lua JSONL events into `internal/services/reporting` instead of leaving the common pipeline as a Cloudflare-only path.

Reason:

- Safety and format guarantees only hold if all sources share the same normalize -> classify -> canonical comment -> report/suppress -> telemetry flow.

Impact:

- Cross-source AbuseIPDB reporting behavior is now structurally unified.
- Canonical comment generation and deduplication no longer depend on source-specific side paths.
- CrowdSec/OpenResty now benefit from the same suppression, telemetry, and future replay evidence semantics as Cloudflare replay.

## 2026-05-27T07:21:12+02:00 - Cloudflare WAF poll progress is runtime state and must be persisted durably

Decision:

- Persist the Cloudflare WAF replay poller `since` cursor in SQLite (`runtime_cursors`) instead of keeping it process-local only.

Reason:

- A process-local cursor breaks restart continuity and can cause duplicate replay windows or missed operator expectations around bounded replay progress.

Impact:

- Daemon restarts resume from the last saved WAF replay cursor.
- Cursor lifecycle remains explicit and storage-backed without pushing this concern into transport logic.
- Future recovery work can treat poll cursors as durable runtime coordination state.

## 2026-05-27T07:21:12+02:00 - Orchestrator decomposition starts with explicit stages, not a big rewrite

Decision:

- Begin thinning `internal/orchestrator/pipeline` by extracting explicit discovery, snapshot, and planning stages while preserving the current orchestration semantics.

Reason:

- The pipeline had become too wide, but a full rewrite would be risky. Stage extraction gives clearer boundaries without destabilizing the runtime.

Impact:

- The central orchestrator is now easier to read and extend incrementally.
- Future normalization, reporting, execution, and telemetry stages can follow the same pattern.
- Runtime behavior remains stable while structure improves.

## 2026-05-27T07:21:12+02:00 - AbuseIPDB reporting evidence is persisted as append-only service-layer forensic state

Decision:

- Persist successful and suppressed AbuseIPDB reporting decisions in a dedicated append-only SQLite store (`abuseipdb_reporting_evidence`) owned by the shared reporting layer.

Reason:

- Telemetry and counters alone are not sufficient for deterministic forensic replay of why an AbuseIPDB report was sent or suppressed. The service layer already owns the orchestration context and can persist report/suppress evidence without polluting pure domain packages.

Impact:

- Report and suppression decisions now receive durable evidence IDs.
- Telemetry metadata can point back to persisted evidence for later replay or operator review.
- Future forensic/query APIs can consume a stable append-only evidence stream instead of reconstructing decisions from logs alone.

## 2026-05-27T07:21:12+02:00 - Live source parsing must fail safe on sparse or malformed context

Decision:

- Keep live CrowdSec/OpenResty/Cloudflare ingestion biased toward skipping malformed or uncorrelated events instead of inventing request context.

Reason:

- False-positive resilience is more important than squeezing every possible signal out of incomplete input. Guessed URI/rule context would weaken replay integrity and operator trust.

Impact:

- Sparse or malformed live inputs remain observable only when enough safe context exists.
- Reportable events are more likely to be slightly under-reported than misreported.
- Fixture coverage now locks this bias in as a regression-tested behavior.

## 2026-05-27T07:21:12+02:00 - Reporting orchestration is being split before it turns into a hidden control-plane brain

Decision:

- Refactor `internal/services/reporting` into smaller responsibility-focused files without changing its public behavior or role.

Reason:

- The shared reporting service had become the next natural concentration point for control-plane complexity. Splitting policy, dedup, evidence, and telemetry concerns early keeps the service understandable while preserving the current architecture.

Impact:

- The package remains the outer orchestration point for WAF reporting decisions.
- Internal responsibilities are easier to review, test, and extract further later.
- The test suite now mirrors those responsibilities more clearly instead of hiding everything in one oversized file.

## 2026-05-27T15:05:00+02:00 - Unified WAF reporting is an outer-layer service, not a domain concern

Decision:

- Introduce `internal/services/reporting` as the single orchestration point for normalized WAF events from Cloudflare, CrowdSec, and OpenResty.

Reason:

- The classifier and formatter must stay pure and reusable, while reporting decisions, deduplication, telemetry emission, and provider calls belong in an application/service layer.

Impact:

- All three WAF sources can converge on the same pipeline without duplicating policy or comment generation logic.
- Domain packages remain provider-agnostic and side-effect free.
- Reporting, telemetry, and AbuseIPDB integration can evolve without re-polluting the security domain.

## 2026-05-27T15:05:00+02:00 - Better Stack delivery stays behind the passive telemetry sink boundary

Decision:

- Implement Better Stack as a concrete HTTP sink behind `internal/telemetry/sinks` instead of letting business or domain packages call it directly.

Reason:

- Operator visibility is required, but the control-plane must preserve fail-open telemetry semantics and keep provider-specific HTTP concerns out of the domain.

Impact:

- Telemetry events can be sent to Better Stack and Prometheus from the same passive event model.
- Sink failures do not break reporting or enforcement decisions.
- Structured JSON payloads stay stable and testable.

## 2026-05-27T15:05:00+02:00 - Suppression metrics must reflect explicit suppression, not lack of propagation

Decision:

- Count false-positive/low-signal suppression metrics only when a telemetry event carries an explicit `SuppressionReason`.

Reason:

- A successful AbuseIPDB report or other telemetry-only event may legitimately have `Propagated=false` without being a suppression. Using the propagation flag alone inflated suppression metrics.

Impact:

- Prometheus counters now better reflect operator-relevant suppressions.
- Metrics semantics align with the replayable decision model.

## 2026-05-27T14:05:00+02:00 - Cloudflare WAF replay uses GraphQL discovery but keeps classification/reporting outside transport

Decision:

- Fetch Cloudflare WAF/security events from the `firewallEventsAdaptive` GraphQL dataset in `internal/cloudflare`, then pass them through `internal/adapters/cloudflareevent` for normalization, local classification, canonical comment generation, and AbuseIPDB reporting.

Reason:

- Cloudflare’s official Analytics documentation positions `firewallEventsAdaptive` as the dataset behind Security Events, which is the closest typed read path for real WAF/security event replay. Keeping that fetch in `internal/cloudflare` preserves transport/discovery boundaries, while classification and reporting stay outside the transport layer.

Impact:

- The transport layer remains read-only and provider-specific.
- The shared local classifier remains the only place where abuse semantics are decided.
- Cloudflare replay and future CrowdSec/OpenResty reporting can converge on the same formatter/reporting chain instead of duplicating logic.

## 2026-05-27T14:05:00+02:00 - The daemon poller is explicit, context-bound, and sequential

Decision:

- Run Cloudflare WAF replay/reporting in daemon mode through an explicit ticker loop tied to the daemon context instead of burying the behavior in hidden background routines inside the domain or transport layers.

Reason:

- This preserves the no-hidden-goroutines discipline and keeps lifecycle/shutdown semantics visible at the composition root.

Impact:

- The poller stops cleanly on daemon shutdown.
- Replay/reporting remains sequential and non-overlapping per process.
- Durable cursor persistence is still pending and can be added later without moving the pipeline into the transport layer.

## 2026-05-27T13:10:00+02:00 - Security domain packages must stay provider-agnostic and side-effect free

Decision:

- Remove metrics, provider formatting, and adapter coupling from `internal/security/risk`, `internal/security/classifier`, and `internal/security/abuseformat`.

Reason:

- The anti-false-positive slice had started to mix domain logic with Prometheus, Better Stack, Cloudflare, and AbuseIPDB concerns. That weakened replay purity and made the architecture drift away from hexagonal boundaries.

Impact:

- Security domain packages now only score, classify, format deterministically, and return pure structures.
- Telemetry and provider-specific rendering moved outward to `internal/telemetry/*` and execution/orchestration layers.
- Future providers or telemetry sinks can be added without re-polluting the core security domain.

## 2026-05-27T13:10:00+02:00 - Reputation lookup is a domain boundary, not an AbuseIPDB policy object

Decision:

- Introduce `internal/security/reputation` and make AbuseIPDB implement that boundary as a concrete adapter.

Reason:

- Execution safety policy should depend on “reputation exists / score / availability”, not on AbuseIPDB-specific types or decisions.

Impact:

- `internal/execution` now depends on a narrow reputation interface instead of a provider-named adapter API.
- `internal/adapters/abuseipdb` is constrained to transport/cache/serialization behavior.
- Failure-mode policy remains in execution-side governance instead of the provider adapter.

## 2026-05-27T13:10:00+02:00 - Enforcement proof must exist in the real executor path

Decision:

- Add integration tests around `GovernedExecutor -> CloudflarePropagationGuard -> mutator -> audit/telemetry` instead of relying only on guard unit tests.

Reason:

- Safety claims about suppression are not credible unless the real mutation path proves that denied operations do not reach the mutator and still remain observable.

Impact:

- The repository now has executor-path tests proving suppression, propagation allow, audit persistence, telemetry emission, and mutator non-execution.
- Future wiring regressions are more likely to be caught before reaching production.

## 2026-05-27T01:02:00+02:00 - AbuseIPDB pre-ban verification is a safety gate, not a reporting side effect

Decision:

- Implement the AbuseIPDB `check` flow as a separate adapter and execution-time safety gate instead of mixing it into direct reporting or Cloudflare mutators.

Reason:

- The requirement is to stop false-positive amplification before global propagation. That is an execution-governance concern, not a reporting concern.

Impact:

- Cloudflare propagation can now be blocked before the mutator runs.
- Protected targets and low-score AbuseIPDB results bias toward suppression and review.
- Reporting remains a separate concern and is not implicitly triggered by safety checks.

## 2026-05-27T01:02:00+02:00 - Cloudflare event normalization should reuse a local classifier, not duplicate heuristics

Decision:

- Introduce a dedicated `internal/security/classifier` for replaying Cloudflare-style events into local abuse semantics.

Reason:

- The system needs category consistency between local catches and Cloudflare-originated events, and duplicating mapping logic across adapters would drift quickly.

Impact:

- Cloudflare replay classification can evolve independently of transport details.
- AbuseIPDB comments and category mappings now have a common local interpretation layer.
- The next ingestion step can feed replayed Cloudflare events into this classifier without coupling transport to reporting.

## 2026-05-27T00:37:00+02:00 - False-positive resilience starts outside the runtime core

Decision:

- Introduce false-positive resilience first as dedicated `internal/security/*` packages instead of immediately wiring new logic into the FSM, scheduler, or repositories.

Reason:

- The production incident risk is real, but the fastest safe move is to establish explicit scoring, trust, and blast-radius policies without destabilizing the healthy runtime core.

Impact:

- The repository now has reusable safety primitives for confidence scoring, protected resource matching, and propagation gating.
- Future enforcement, Cloudflare propagation, and operator-approval steps can depend on these primitives rather than hardcoding safety logic inside execution paths.

## 2026-05-27T00:21:00+02:00 - Python 3.6.0 parity resumes through contracts and adapters, not by expanding the runtime core

Decision:

- Start the Python 3.6.0 parity catch-up by adding versioned contracts and parse/validate-only OpenResty/Lua adapters before introducing any compatibility reader or runtime-side orchestration changes.

Reason:

- The Go repository already has a healthy runtime/event/persistence core. The highest-value missing boundary is the external contract with the Python/OpenResty/Lua ecosystem, not a rewrite of the FSM or scheduler.

Impact:

- The new adapters stay outside the central runtime lifecycle logic.
- The next migration step can add `internal/compat/python36` to translate legacy Python artifacts into explicit contracts instead of coupling the runtime to legacy file formats.
- OpenResty and Lua can now evolve behind stable versioned schemas and offline tests.

## 2026-05-27T00:02:36+02:00 - Bounded event replay is the first point-in-time recovery primitive

Decision:

- Implement point-in-time recovery first as bounded replay by target sequence or target timestamp on top of checkpoint-aware event replay.

Reason:

- This delivers deterministic temporal recovery semantics immediately without forcing a risky scoped SQLite reopen/restore refactor in the same slice.

Impact:

- Recovery manifests and plans now express `latest`, `sequence`, and `time` recovery modes.
- The next recovery slice can layer SQLite snapshot restore orchestration underneath these same recovery plans instead of replacing them.

## 2026-05-27T00:02:36+02:00 - Replay consistency verification starts above the event store, not inside repositories

Decision:

- Add replay consistency checks in a dedicated runtime package rather than embedding verification logic in SQLite repositories.

Reason:

- Deterministic replay, divergence detection, and forensic continuity are runtime concerns that should remain portable across future backends.

Impact:

- `internal/runtime/replay/consistency` can verify ordering, continuity, and checkpoint continuity independently of the storage backend.
- Future PostgreSQL or streaming backends can reuse the same verification layer without rewriting repository code.

## 2026-05-26T23:43:38+02:00 - Automatic checkpoints are emitted from lifecycle transitions, not from repositories

Decision:

- Attach runtime checkpoint production to `engine.StateMachine` transitions instead of embedding that logic inside SQLite repositories or lower storage layers.

Reason:

- This preserves the architectural rule that repositories stay free of business/runtime lifecycle semantics and keeps event production/checkpoint intent visible in the runtime layer.

Impact:

- SQLite remains a persistence boundary only.
- Lifecycle transitions now produce append-only events and runtime checkpoints through explicit runtime wiring.
- Recovery can reconstruct runtime state from checkpoints plus events without hidden repository logic.

## 2026-05-26T23:43:38+02:00 - SQLite degraded mode fails closed on mutable repositories

Decision:

- Introduce a read-only degraded mode on `storage/sqlite.DB` and enforce it on mutable repositories.

Reason:

- Under corruption suspicion or operational degradation, the control-plane must stop mutating durable state before it risks compounding damage.

Impact:

- Event append, checkpoint persistence, runtime state writes, lease writes, and ownership writes now refuse to proceed in degraded read-only mode.
- Recovery and diagnostics can still inspect the database while mutating paths fail closed.

## 2026-05-26T23:19:49+02:00 - First production-hardening slice targets event sourcing before broader recovery work

Decision:

- Strengthen `internal/runtime/events` and SQLite-backed event persistence before opening wider recovery, chaos, or distributed-coordination work.

Reason:

- The repository already had a broad control-plane skeleton, but the event layer still had hidden subscriber goroutines, weak replay semantics, and no durable replay checkpoints.

Impact:

- Event append is now the append-only source of truth for timeline reconstruction.
- Event subscribers now run synchronously under caller context, which removes hidden lifecycle behavior and simplifies shutdown semantics.
- Event replay can resume from named persisted checkpoints, but checkpoint production still needs to be wired into lifecycle transitions and runtime-state snapshots.

## 2026-05-26T23:19:49+02:00 - Worker pools must shut down explicitly and must not hide submission goroutines

Decision:

- Remove the hidden goroutine in the stateful scheduler pool submit path and add explicit close/wait semantics.

Reason:

- Background workers leaking past test teardown are the same class of lifecycle bug that would become dangerous in a long-running daemon.

Impact:

- Scheduler tests now terminate cleanly.
- Pool submission respects caller cancellation directly.
- Future daemon shutdown paths have a clearer basis for graceful worker termination.

## 2026-05-19T23:05:06+02:00 - Keep Python as source of truth

Decision:

- Do not modify, rename, move, delete, or overwrite the production Python scripts.

Reason:

- They are currently running in production and define the exact behavior the Go migration must match.

Impact:

- The Go project is developed in parallel and must prove parity before cutover.

## 2026-05-19T23:05:06+02:00 - Use Go 1.22.2 baseline

Decision:

- Retarget the module to `go 1.22.2`.

Reason:

- The local environment provides Go 1.22.2 and the project must remain compatible with standard Ubuntu server environments without requiring newer toolchains or experimental features.

Impact:

- Avoid APIs and language features introduced after Go 1.22.
- Keep validation runnable locally with `gofmt`, `go test`, `go vet`, and `go build`.

## 2026-05-19T23:05:06+02:00 - Prefer standard library and explicit interfaces

Decision:

- Use standard library primitives first and model integrations through narrow interfaces.

Reason:

- This keeps the migration easier to audit, easier to deploy, and easier to test.

Impact:

- Logging uses `log/slog`
- HTTP clients use `net/http`
- Scheduling uses a small internal runner
- External integrations remain replaceable behind interfaces

## 2026-05-19T23:05:06+02:00 - Keep JSON state for phase 1

Decision:

- Preserve JSON-backed local state first and defer SQLite.

Reason:

- Current Python behavior already relies on JSON persistence for deduplication and retention semantics.

Impact:

- `internal/state` provides JSON storage now
- SQLite can be introduced later behind the same storage boundary

## 2026-05-19T23:05:06+02:00 - Decompose the monolithic sync daemon by domain

Decision:

- Represent the large Python `crowdsec-cf-sync.py` daemon as a composition of domain services instead of a single giant Go file.

Reason:

- The Python daemon currently mixes Cloudflare sync, AbuseIPDB, recidive, ModSecurity, CIDR banning, Better Stack, and Cloudflare WAF polling.

Impact:

- `internal/app` wires the composition
- domain packages own future implementation details
- parity validation must also preserve sequencing and shared-state behavior

## 2026-05-19T23:05:06+02:00 - Checkpoint often and never leave a broken build

Decision:

- Every major step must end in a compiling, documented, resumable state.

Reason:

- This migration is session-based engineering work, not one-shot generation.

Impact:

- Update `SESSION_STATUS.md`, `MIGRATION_PROGRESS.md`, and `DECISIONS.md` regularly
- Avoid starting large refactors unless there is enough session budget to finish and validate them

## 2026-05-19T23:15:08+02:00 - Enforce trust-but-verify for external integrations

Decision:

- Do not implement external integrations from memory or guesses.

Reason:

- This project targets production security automation, where invented API schemas or undocumented assumptions would create silent operational risk.

Impact:

- Verify Cloudflare, CrowdSec, AbuseIPDB, Better Stack, and Go standard library behavior against official documentation before implementation
- If verification is incomplete, leave a TODO and document the uncertainty instead of guessing
- Keep request and response translation isolated inside the integration package, especially `internal/cloudflare`

## 2026-05-19T23:15:08+02:00 - Concurrency safety before service parallelism

Decision:

- Establish cancellation, trace propagation, retry boundaries, non-overlapping scheduler runs, and race-safe state access before implementing concurrent service logic.

Reason:

- Shared state and goroutine lifecycle are the highest-risk areas for the future daemon.

Impact:

- Scheduler runs now have timeout support, explicit lifecycle logs, and overlap prevention
- `go test -race ./...` becomes a milestone gate
- State persistence avoids holding locks during file I/O

## 2026-05-19T23:20:04+02:00 - Cloudflare implementation must be read-only first

Decision:

- Implement Cloudflare integration in read-only mode before any write or delete path.

Reason:

- Early parity phases must observe and validate behavior before mutating security controls in production-adjacent workflows.

Impact:

- Mutation paths require dry-run support first
- Intended mutations must be logged before execution
- Destructive actions remain disabled during early parity work

## 2026-05-19T23:20:04+02:00 - Keep Cloudflare concerns separated and fully mockable

Decision:

- Separate Cloudflare transport, typed schemas, business logic, and reconciliation logic, and keep all Cloudflare-specific schemas inside `internal/cloudflare`.

Reason:

- This prevents Cloudflare API details from leaking into the rest of the codebase and makes tests fixture-driven and fully mockable.

Impact:

- Cloudflare pagination and rate-limit handling will be implemented explicitly inside `internal/cloudflare`
- Sanitized real-response fixtures become part of the test strategy before write support is added

## 2026-05-28T22:30:00+02:00 - SQLite correctness and recovery orchestration

Decision:

- Centralize SQLite error classification in `internal/storage/sqlite/errors.go` using typed `sqlite.Error` and native codes to eliminate fragile string matching.
- Move one-time migration tasks (like legacy scope normalization) to the `DB.New` bootstrap phase to reduce runtime contention and write amplification.
- Require `owner` and `fencing_token` verification on all lease renewals and releases to prevent stale/ambiguous coordination.
- Implement point-in-time restore in `recovery.Manager` by combining database file snapshots with bounded event replay.
- Enforce sequence continuity and gap detection during event replay to ensure reconstruction integrity.

Reason:

- Eliminating string-based error handling prevents regressions during driver updates or locale changes.
- Moving migration logic out of hot paths improves performance and reduces WAL lock contention.
- Stronger lease ownership checks prevent "zombie" workers from extending leases after leadership loss.
- Point-in-time restore is essential for autonomous recovery from corruption or operator error.

Impact:

- Integration tests should replay sanitized fixtures before live API usage
- Cloudflare implementation starts with auth validation, connectivity checks, read-only list operations, and pagination traversal only
- Mutation support remains deferred

## 2026-05-19T23:24:54+02:00 - Prefer strict decoding and small Cloudflare models

Decision:

- Use strict JSON decoding and small resource-specific response models for Cloudflare integration.

Reason:

- Giant shared response structs hide schema drift and make testing and maintenance harder.

Impact:

- Unknown critical schema mismatches should be rejected explicitly
- Cloudflare-specific schemas stay local to `internal/cloudflare`
- Debug request and response logs must stay behind a debug flag and must not expose sensitive identifiers

## 2026-05-19T23:27:43+02:00 - Fixture replay is an offline, deterministic boundary

Decision:

- Treat fixture replay as a deterministic offline test boundary with no live API mixing.

Reason:

- Replay tests need to be stable, comparable across sessions, and safe to run without network access.

Impact:

- Fixture replay tests must not make internet calls
- Raw capture, sanitization, replay, and schema drift detection become distinct responsibilities
- Fixture versioning and expiration metadata are required to monitor API drift over time

## 2026-05-19T23:27:43+02:00 - Preserve both raw and sanitized Cloudflare fixtures

Decision:

- Capture both raw and sanitized fixture forms with explicit metadata and pagination sequence data.

Reason:

- Raw captures preserve auditability, while sanitized fixtures support safe repository-based replay tests.

Impact:

- Fixture tooling must store status, headers, body, pagination metadata, and timestamps
- Sanitization must remove tokens, emails, account IDs, zone IDs, and sensitive IPs when flagged
- Sanitized fixtures should be treated as immutable after generation

## 2026-05-19T23:30:28+02:00 - Replay uses sanitized fixtures plus explicit replay metadata

Decision:

- Replay must operate on sanitized fixtures and dedicated replay metadata, never directly on raw captures.

Reason:

- Raw captures are not safe or stable as direct replay artifacts, while replay metadata needs its own deterministic control surface.

Impact:

- Raw capture, sanitized storage, and replay metadata become separate fixture layers
- Replay ordering, pagination sequencing, rate-limit cases, and transient failure cases must be expressible without live calls

## 2026-05-19T23:30:28+02:00 - Fixture replay integrity must be validated explicitly

Decision:

- Add corruption detection, checksum validation, schema versioning, and parallel-safe replay guarantees to the fixture architecture.

Reason:

- Offline replay only helps if fixture integrity and ordering are trustworthy across sessions and concurrent test runs.

Impact:

- Sanitized fixtures need explicit integrity validation
- Replay tests must support deterministic ordering and optional latency simulation without introducing nondeterminism

## 2026-05-19T23:31:11+02:00 - Replay must simulate real Cloudflare failure modes early

Decision:

- Treat rate limits, timeouts, incomplete pagination, and transient failures as first-class replay scenarios.

Reason:

- Those are the operational failure modes most likely to affect the future Cloudflare daemon in production.

Impact:

- Replay design must include explicit support for HTTP 429 responses, timeout paths, partial pagination chains, and transient upstream errors
- These cases should be modeled before live API usage or mutation logic

## 2026-05-19T23:32:09+02:00 - Keep reconciliation out of transport layers

Decision:

- API transport layers must not contain business reconciliation logic.

Reason:

- Mixing HTTP transport with reconciliation behavior makes testing, replay, and future change isolation much harder.

Impact:

- Transport packages should stop at authentication, request execution, pagination traversal, header handling, and strict schema decoding
- Reconciliation decisions belong in higher-level business layers

## 2026-05-19T23:36:39+02:00 - Reconciliation must be plan-driven and idempotent

Decision:

- Reconciliation must be idempotent and must flow through explicit discovery, planning, and execution phases.

Reason:

- Retries, scheduler reruns, network failures, and replay must not cause duplicate bans, repeated deletes, or state drift.

Impact:

- Dry-run output becomes a first-class reconciliation feature
- Mutation planning must be separate from mutation execution
- Duplicate-mutation protection is required before any write path is enabled

## 2026-05-19T23:36:39+02:00 - Reconciliation state must not depend directly on transport payloads

Decision:

- Do not couple reconciliation state directly to transport response objects.

Reason:

- Transport payloads can drift independently and should not define durable reconciliation behavior.

Impact:

- Reconciliation should operate on normalized domain snapshots and explicit plans
- Transport changes should not silently alter mutation decisions

## 2026-05-19T23:41:13+02:00 - Reconciliation must be durable across restarts

Decision:

- Reconciliation plans, snapshots, progress, and execution journals must support restart-safe durability.

Reason:

- Long-running daemons must recover from process restarts and partial failures without losing mutation provenance or re-planning unpredictably.

Impact:

- Plans must be serializable
- Discovery snapshots must be persistable
- Execution progress must be resumable
- Operation IDs and execution journals are required

## 2026-05-19T23:41:13+02:00 - Mutation provenance must be explainable

Decision:

- Persist enough metadata to explain why a mutation happened, which snapshot produced it, and which reconciliation run executed it.

Reason:

- Security automation requires post-incident auditability, especially around bans, deletes, and retries.

Impact:

- Reconciliation journaling must be replay-safe and traceable end-to-end
- Retries must not silently generate materially different plans without explicit detection

## 2026-05-19T23:43:56+02:00 - Mutation execution needs explicit state and confirmation boundaries

Decision:

- Mutation execution must use explicit state-machine tracking, confirmation gates, and audit snapshots.

Reason:

- Security mutations need strong protections against accidental execution, partial failures, and nondeterministic retries.

Impact:

- Mutation batches need deterministic identity keys and resumable state
- Execution outside dry-run mode requires explicit confirmation gates
- Before and after audit snapshots become mandatory execution metadata

## 2026-05-19T23:43:56+02:00 - Refuse unsafe execution when plans go stale

Decision:

- Execution must detect stale plans and refuse mutation if snapshot drift exceeds safety thresholds.

Reason:

- A daemon must not apply outdated mutation plans against a changed remote state.

Impact:

- Drift thresholds and stale-plan checks are required before execution
- Overlapping reconciliation plans must not run concurrently

## 2026-05-19T23:46:32+02:00 - Execution must support operator safety controls

Decision:

- Mutation execution must be governed by kill-switches, emergency read-only mode, rate and count limits, and circuit-breaker protections.

Reason:

- Security automation needs fast operator override paths and automatic fail-safe behavior under abnormal conditions.

Impact:

- Write-path design must include global execution disablement, safety thresholds, and failure escalation behavior
- Suspicious or unstable execution paths must degrade safely instead of continuing blindly

## 2026-05-19T23:46:32+02:00 - Mutation lifecycle events require structured auditability

Decision:

- Every mutation lifecycle event must emit structured audit logs and operator-visible execution summaries.

Reason:

- Operators need immediate visibility into what the daemon planned, executed, blocked, quarantined, or failed.

Impact:

- Audit event schemas and execution summary outputs become part of the write-path design contract
- Degraded and quarantine modes must be visible to operators
## 2026-05-27T00:52:34+02:00 - Baseline browser bootstrap must never trigger aggressive enforcement

Decision:

- Requests matching the learned benign browser bootstrap baseline are classified as `benign_bootstrap` and remain `observe_only`.

Reason:

- Normal homepage and asset loading must remain fully visible without creating false positives or escalating to Cloudflare propagation or AbuseIPDB reporting.

Impact:

- `internal/security/baseline` becomes part of the progressive risk path
- baseline-only events stay replayable and observable but never hard-banned

## 2026-05-27T00:52:34+02:00 - Real Cloudflare mutation execution must be guarded before provider calls

Decision:

- `cmd/cf-sync` now injects `CloudflarePropagationGuard` into the live `GovernedExecutor` path.

Reason:

- Anti-false-positive modules are not enough if production execution paths can still bypass them.

Impact:

- Cloudflare mutations now hit trust checks and AbuseIPDB pre-ban checks before provider execution
- guarded resource types currently include `ip_access_rules`, `list_items`, `ruleset_rules`, and `rulesets`

## 2026-05-27T00:52:34+02:00 - Canonical AbuseIPDB comments must come from one formatter

Decision:

- AbuseIPDB comment generation is centralized in `internal/security/abuseformat`, including translator-driven reports.

Reason:

- Source-specific string assembly creates drift, makes replay comparison harder, and weakens operator trust in forensic artifacts.

Impact:

- comment format is stable across CrowdSec/OpenResty/Cloudflare sources
- truncation, URI deduplication, and missing-field accounting are enforced in one place

## 2026-05-28T-current+02:00 - Cloudflare mutations require scoped fencing validation

Decision:

- A mutation carrying lease metadata must validate `(scope_id, lease_id, fencing_token, lease_action)` against the active scoped lease before the provider call.

Reason:

- Heartbeat cancellation prevents many zombie mutations, but stale workers also need an explicit per-operation fencing check at the execution boundary.

Impact:

- `GovernedExecutor` and rollback compensation execution reject stale tokens with `stale_fencing_token_mutation_refused`.
- Existing callers that do not yet provide lease metadata retain previous behavior until they opt into fenced execution.

## 2026-05-28T-current+02:00 - AbuseIPDB outbox retries are explicit and context-bound

Decision:

- Failed or pending AbuseIPDB report reservations are retried by an explicit worker invoked by the runtime scheduler, not by an implicit background goroutine.

Reason:

- The reporting path must be recoverable without hiding lifecycle or shutdown semantics from operators.

Impact:

- Outbox rows persist the canonical report payload, attempt count, last error, and next eligible attempt.
- The local WAF runtime processes bounded retries once per scheduler tick and remains context-cancellable.

## 2026-05-29T-current+02:00 - SQLite error handling must be code-based, not message-based

Decision:

- Runtime-critical SQLite retries and classification use typed driver error codes only.

Reason:

- Message-text matching is brittle across driver versions and can silently misclassify critical storage failures.

Impact:

- `internal/storage/sqlite/errors.go` now classifies BUSY/LOCKED/CONSTRAINT/IOERR/CORRUPT strictly via modernc SQLite error codes.
- Retry and failure paths remain deterministic and robust to message-format changes.

## 2026-05-29T-current+02:00 - Legacy lease scope normalization is bootstrap-only

Decision:

- Legacy empty `scope_id` normalization is executed by migration (`v12`), not in DB runtime startup logic.

Reason:

- Migration debt in hot paths increases WAL contention and hides non-deterministic boot-time side effects.

Impact:

- Lease runtime operations are cleaner and no longer coupled to legacy data rewrite logic.
- `NormalizeLeases` remains available as explicit admin/bootstrap utility, but is not invoked automatically by runtime hot paths.

## 2026-05-29T-current+02:00 - Lease renewal validates epoch lineage

Decision:

- `RenewLease` requires matching `scope_id + owner + epoch_id + fencing_token` to extend lease TTL.

Reason:

- Owner/fencing-only renewals can still allow ambiguous stale renewals after leadership/epoch changes.

Impact:

- Stale renewal windows are reduced.
- Heartbeat renewal now fails closed on epoch mismatch, triggering lost-lease handling instead of silently extending stale ownership.
