# Architectural Decisions

This document records significant design decisions that are not obvious from the code structure alone. Each entry explains **what** was decided, **why**, and **what alternatives were rejected**.

---

## AbuseIPDB: dual role (enrichment + reporting)

**Decision**: AbuseIPDB plays two independent roles in the system. The reporting pipeline (`internal/services/reporting`) submits suspicious IPs to AbuseIPDB via the `/report` endpoint using the `abuseipdb/executor` path. The enrichment service (`internal/security/enrichment/abuseipdb`) queries the `/check` endpoint to retrieve the current abuse confidence score for an IP. These are separate code paths that both use the same API key and contribute to the same daily quota.

**Why**: Reporting is a fire-and-forget outbound operation (evidence → outbox → submit). Enrichment is an on-demand lookup triggered by operator action (Forensic / Security Intelligence pages). Conflating them would require coupling the enrichment TTL cache to the reporting dedup logic.

**Quota implication**: Both paths consume the same AbuseIPDB daily limit. The Check path is guarded by `quota.DefaultRegistry().State("abuseipdb")` — if the registry reports THROTTLED or EXHAUSTED (populated from response headers by the reporting path), new Check calls are skipped. Monitor the shared budget when operating at high event rates.

---

## Spamhaus: report-only (no enrichment)

**Decision**: Spamhaus is wired only to the reporting pipeline (outbound submission). There is no Spamhaus IP enrichment lookup in the UI or the classification hot path.

**Why**: Spamhaus does not offer a publicly available IP reputation query API equivalent to AbuseIPDB's `/check`. Their data products (DBL, ZEN) are DNS-based bulk lookups, not REST API calls. A future sprint could add DNS-based Spamhaus enrichment if needed.

---

## Auto-ban evaluator: shadow-only for v1.7.2

**Decision**: The `internal/services/autoban` evaluator runs in shadow mode permanently for v1.7.2. Enabling `cloudflare.auto_ban_enabled: true` changes log output only — no Cloudflare mutation is performed. `RecordBan()` marks an in-process dedup map; nothing calls the Cloudflare firewall rule API.

**Why**: The evaluation logic must be validated in production (correct IP guard behaviour, rate of false-positive decisions, AbuseIPDB quota consumption, burst window detection with real replay data) before any mutation path is wired. Shadow mode gives a full week of signal without risk.

**What's wired vs. not**:
- Wired: event ingestion → burst counter (with ray_id dedup) → sub-window detection → structured log
- Wired: IP guard chain (invalid IP, non-public, trust registry, already-banned dedup)
- Wired: AbuseIPDB confidence-100 rule (with 6h cache, quota guard)
- **Not wired**: Cloudflare firewall rule creation, IP block mutation, or any network call to the CF API

**What a future sprint must add**: A governed `CloudflareExecutor` that wraps the existing CF client with the same admission/propagation guard pattern used by the CF ban-sync feature. It must also be gated behind the existing `MutationsEnabled` safety flag and the new `AutoBanEnabled` flag.

---

## Burst window: event-time sub-window, not wall clock

**Decision**: The burst counter (`BurstCounter.DetectBurst`) searches for the densest 30-second sub-window within stored event timestamps. It does not compare timestamps against `time.Now()`.

**Why**: The CF WAF replay poller fetches events from up to `cloudflareReplayOverlap = 10min` in the past on every poll. If burst detection compared event timestamps against `now()`, all replayed events would be older than 30 seconds by the time they are evaluated and would never trigger the rule. Sub-window detection finds real attack bursts (e.g. 40 requests in 2 seconds) regardless of when the poller processed them.

**Stale event pruning**: Events older than `burstPruneLookback = 15 minutes` are pruned inline on each `DetectBurst` call. This is longer than the replay window, ensuring all valid replayed events are considered exactly once per unique ray_id.

---

## Ray-ID dedup in burst counter

**Decision**: `BurstCounter.Record(ip, key, ts)` deduplicates by `ip:key` where `key` is the Cloudflare ray ID. If `key == ""`, no dedup is performed (non-CF sources).

**Why**: The replay overlap means the same Cloudflare WAF event (same ray_id) is re-fetched on approximately `cloudflareReplayOverlap / pollInterval` consecutive polls. Without dedup, a single burst attack at T=0 would be counted again on polls at T+60s, T+120s, etc., potentially triggering repeated ban decisions for the same original event.

---

## Enrichment: Manual mode only for AbuseIPDB

**Decision**: `LookupClient` (AbuseIPDB enrichment) reports `Mode() == LookupModeManual`. The enrichment service only invokes manual providers when `LookupOptions.ManualForensics == true`.

**Why**: AbuseIPDB `/check` consumes daily quota. Running it on every classified event in the WAF replay pipeline (which processes hundreds of events per poll) would exhaust the quota immediately. Manual-only mode gates the check behind explicit operator actions (Forensic page, Security Intelligence page).

**Auto-ban path uses a separate cache**: The auto-ban evaluator has its own `cachedEnricher` (6h TTL cache) backed by the same AbuseIPDB transport. This is intentional: the evaluator runs in the daemon context and must not depend on the UI enrichment service, which has a different lifecycle.

---

## Trust registry as the single IP safety gate

**Decision**: All IP-eligibility checks (CF propagation guard, auto-ban evaluator, reporting suppression) use `trust.DefaultRegistry()` as the authoritative gate. The default registry includes RFC1918, loopback, link-local, all Cloudflare IP CIDR ranges (published at `https://www.cloudflare.com/ips/`), and operator-configured `global.protected_hosts`.

**Why**: Centralising the guard prevents drift. The CF CIDR ranges in the default registry mean that Cloudflare itself (edge IPs, health check IPs, etc.) cannot be reported or banned — a critical safety property since all origin traffic passes through Cloudflare.

**Maintenance**: When Cloudflare publishes new CIDR ranges, the `trust.DefaultRegistry()` seed data must be updated. See `docs/architecture/TRUSTED_NETWORKS.md`.

---

## One Name Per Concept (Product Language ADR — v1.8.0+)

**Decision**: Every user-facing concept has exactly one canonical name across the UI, documentation, and tests. Synonyms, legacy names, and version-flavoured terms ("Classic", "V1", "V2", "Old", "Forensic" as a page alias) are prohibited in any string visible to an operator.

**Canonical glossary** (authoritative from v1.8.0):

| Concept | Canonical name |
|---|---|
| IP investigation page | Investigate |
| Chronological event stream | Timeline |
| Per-IP campaign view | Focus Incident |
| Enrichment data for an IP | IP Enrichment |
| Raw recorded events (business concept) | Evidence |
| Observed security activity | Activity |
| Platform health dashboard | Health |
| Cloudflare projected state | Cloudflare Overview |
| Live diff vs Cloudflare API | Cloudflare Rule Diff |
| Operator annotations | Operator Notes |

**Why**: Labels are product contracts. When two names exist for the same thing ("Forensic" / "Investigate", "Evidence" / "Activity", "Classic" / "Rule Diff"), operators build a mental model on ambiguous ground. Renaming after that is harder than getting it right at the start of a release. The v1.7.9 migration was the right moment to lock this down.

**Enforcement — Product Language Review**: Before merging any UI milestone, a Product Language Review must pass:

- same term for the same concept everywhere (UI, docs, Playwright tests);
- no competing synonyms in operator-visible strings;
- no references to retired features or pages;
- no "legacy", "classic", "old", "new", "v1", "v2" visible to the operator;
- same terminology in the UI, documentation, and test assertions.

**Alternatives rejected**: Keeping multiple informal names ("Forensic" as shorthand in card titles while the nav says "Investigate") — rejected because informal shortcuts propagate into documentation, copy-paste suggestions, and eventually operator speech. One name is the only durable choice.
