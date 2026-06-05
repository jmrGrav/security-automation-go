# Deployment Plan — Python → Go Migration

**Principle:** reversible, measurable, no interruption. Python stays
authoritative until a formal GO is recorded. Go advances one capability at a time,
always with an immediate rollback to Python.

Authority transfer is **gated** by [GO_LIVE_CHECKLIST.md](GO_LIVE_CHECKLIST.md)
and the open items in [TEST_GAP_REPORT.md](TEST_GAP_REPORT.md).

---

## Prerequisites

- Go 1.22.2 toolchain on the build host.
- Deployed Python reference is `/usr/local/bin/{crowdsec-cf-sync,cloudflare-allowlist-update,cloudflare-cleanup-ip-rules}.py` — this, not the working tree, is the parity baseline.
- Cloudflare API token scoped to: firewall access rules (edit), rules lists (edit), zone analytics (read).
- `cscli` present and runnable by the service user.
- Dedicated state dir `/var/lib/security-automation-go/` (separate from Python state).
- Secrets delivered via systemd `EnvironmentFile=`; never committed.
- Prometheus scrape + log sink reachable before any deployment phase.
- Deploy **`cmd/cf-sync` only.** The legacy `crowdsec-sync` / `cf-allowlist-sync` / `cf-cleanup` binaries are stub-backed no-ops — do not install them.

---

## Phases

Each phase has: goal · actions · what stays with Python · monitoring · **exit criteria**.

### Phase 0 — Observe-only (this week)
- **Goal:** Go runs, reads, computes, emits metrics; performs **zero** mutations.
- **Actions:** deploy `cf-sync` with mutations disabled (dry-run flag/config); wire Prometheus + logs; confirm it reads CrowdSec/CF/logs without writing.
- **Python:** fully authoritative, unchanged.
- **Monitor:** process up, no error storms, no outbound mutating calls (verify via CF audit log = no new rules from Go token), stable memory over 48h.
- **Exit:** 48–72h clean run; metrics flowing; zero mutating calls observed.

### Phase 1 — Dry-run parity
- **Goal:** Go computes the decisions it *would* make and they match Python.
- **Actions:** log intended actions (would-ban / would-report / would-allowlist) with stable keys; build an automated diff of Go-intended vs Python-actual over the same window.
- **Python:** authoritative.
- **Monitor:** parity diff report; divergences triaged and explained before proceeding.
- **Exit:** ≥7 days with parity ≥ agreed threshold (target: 0 unexplained divergences); every divergence class documented.

### Phase 2 — Shadow mode
- **Goal:** Go exercises the full pipeline incl. rollback/journal/replay against real reads, still no external mutations.
- **Actions:** enable event sourcing, journal, replay, HA lease acquisition (single node), AbuseIPDB in dry-run.
- **Python:** authoritative.
- **Monitor:** journal integrity, replay determinism, lease/fencing behaviour, recovery after forced restart.
- **Exit:** replay/recovery/lost-lease validations green (see checklist); no invariant violations over the window.

### Phase 3 — Controlled mutations (one capability at a time)
- **Goal:** enable real writes for the **lowest-risk** capability first, behind a flag.
- **Order:** (1) cleanup (keep-`easycron`) → (2) allowlist additive sync → (3) CrowdSec→CF ban sync → (4) AbuseIPDB reporting → (5) WAF replay actions. Only enable a capability that is ported **and** tested.
- **Python:** keeps every capability not yet handed to Go (disable the matching Python sub-feature only when its Go counterpart is enabled, to avoid double-action).
- **Monitor:** per-capability action counts Go vs Python; CF audit log; error/retry rates; rollback drills.
- **Exit per capability:** dry-run parity held, mutation matches expectation on a canary set, rollback verified live.

### Phase 4 — Go authority
- **Goal:** Go owns all enabled capabilities; Python runs in **shadow** (read/compute only, mutations disabled) as a safety net.
- **Exit:** ≥2 weeks of Go authority with no Sev1; Python-shadow shows no decisions Go missed.

### Phase 5 — Python retirement
- **Goal:** stop and archive Python units after the shadow window is clean.
- **Actions:** disable Python timers/units, keep them installed + documented for one more cycle, then archive.

---

## Rollback

- **Always available:** stop Go unit, re-enable Python unit. Target RTO < 5 min.
- Go and Python use **separate** unit names, binaries, and state dirs — no shared mutable state.
- Capability flags are independently revertible: disabling a Go flag and re-enabling the Python sub-feature restores prior behaviour.
- Keep the previous Go binary for one version back for fast in-place rollback.
- Rollback triggers: any unexplained mutation divergence, invariant violation, lease/fencing anomaly, or CF/cscli error storm.

## Monitoring & alerting

- **Metrics (Prometheus):** mutation counts by capability & origin (Go/Python), cscli command duration, CF API error/retry counts, journal append/replay status, lease state, recovery events.
- **Logs:** structured JSON; intended-vs-actual action lines in dry-run/shadow.
- **Alerts:** Go performs a mutation while in observe/dry-run (must never happen); parity divergence > threshold; lease lost / fencing rejection; rollback executed; AbuseIPDB/CF error rate spike.
- **Convergence validation:** automated periodic diff of CF/CrowdSec state snapshots produced by Go-intended vs Python-actual; report archived per phase.

## Phase exit-criteria summary

| Phase | Hard exit gate |
|---|---|
| 0 Observe | 48–72h clean, 0 mutating calls |
| 1 Dry-run | ≥7d, 0 unexplained divergences |
| 2 Shadow | replay/recovery/lost-lease green, 0 invariant violations |
| 3 Mutations | per-capability parity + live rollback verified |
| 4 Authority | ≥2 weeks, no Sev1, Python-shadow agrees |
| 5 Retirement | clean shadow window, Python archived |
