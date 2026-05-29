# Shadow Mode Validation Report

**Status:** PENDING — awaiting deployment on production host

This file will be overwritten by `cf-shadow` after each cycle once deployed.
The live version is written to `$STATE_DIR/shadow/SHADOW_MODE_REPORT.md`.

---

## Deployment Checklist

| Step | Command | Status |
|---|---|---|
| Build binary | `go build -o bin/cf-shadow ./cmd/cf-shadow/` | ☐ |
| Install on host | `sudo ./deployments/shadow/install-shadow.sh` | ☐ |
| Configure env | Edit `/etc/security-automation-go/cf-shadow.env` | ☐ |
| Start service | `systemctl enable --now cf-shadow` | ☐ |
| Verify first cycle | `journalctl -u cf-shadow -n 50` | ☐ |
| Monitor reports | `watch -n 60 cat /var/lib/cf-sync/shadow/SHADOW_MODE_REPORT.md` | ☐ |
| 7-day baseline | Wait for `SevenDayEligible: true` in report | ☐ |

---

## Success Criterion

≥ 99.9% average agreement over 7 consecutive days of shadow execution.

Once met, the report will display:

> **GO — Ready for controlled authority.**

---

## Reports Generated Per Cycle

| File | Purpose |
|---|---|
| `SHADOW_MODE_REPORT.md` | Per-cycle Jaccard agreement, false pos/neg, migration readiness |
| `SHADOW_DRIFT_ANALYSIS.md` | Each divergent IP classified + remediation list by risk |
| `PYTHON_GO_PARITY_REPORT.md` | Feature gap cross-reference with observed drift quantification |

---

## Known Expected Drift (Before Fixes)

| Class | Expected Count | Reason |
|---|---|---|
| Allowlist filter | Some | Go enforcement loop doesn't check CS allowlist yet |
| Confidence gate | Some | CF_MIN_CONFIDENCE gate not ported to Go |
| ModSec/CIDR rules | Some | Python adds via separate tags (modsec-ban, crowdsec-cidr-ban) |
| Timing | Some | 60s cycle offset between Python and Go |
| Protected IP | **0** | Anti-self-ban wired — any occurrence is a P0 bug |
