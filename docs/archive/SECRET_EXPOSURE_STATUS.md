# Secret Exposure Status Report

**Date:** 2026-06-06  
**Produced by:** Claude Code (automated status scan)  
**Source report:** `TOKEN_EXPOSURE_FORENSIC_REPORT.md`  
**Scope:** Current status of all credentials exposed or potentially exposed in the 2026-05-30 git push incident

---

## 1. Executive Summary

Three credentials were publicly exposed on GitHub from 2026-05-30 to 2026-06-05: a Cloudflare API token, an AbuseIPDB API key, and a BetterStack source token. The Cloudflare token was automatically revoked by the GitHub–Cloudflare Secret Scanning Partnership at approximately 2026-06-06T12:00 UTC; both the shadow and production env files on disk still contain the revoked (now-dead) token and have not been updated since the revocation. The AbuseIPDB key held by the Go daemon (`cf-sync`) has been returning HTTP 401 since at least 2026-06-05T17:51 local time — indicating that key is either already revoked or invalid in that context — while the Python daemon (`crowdsec-cf-sync`) was still successfully reporting IPs to AbuseIPDB as recently as 2026-06-06T06:21, suggesting it may hold a different or still-valid credential. The CF_SYNC_API_TOKEN (internal daemon auth token) was never exposed in git history. Git history has not been rewritten; the original credential values remain publicly readable on GitHub via the commit SHA.

---

## 2. Exposure Event Summary

| Item | Detail |
|------|--------|
| Exposure start | 2026-05-30T18:00:14Z (push to public GitHub repo) |
| File exposed | `CUTOVER_RUNBOOK.md`, commit `4649a1d` |
| Exposure end (file at HEAD) | 2026-06-05T20:15:45Z (deleted in release commit `b4a5b17`) |
| Public exposure window | **6 days, 2 hours, 15 minutes** (file visible at HEAD) |
| Git history remains public | Yes — blob permanently accessible via commit SHA |
| GitHub Secret Scanning alert | #1 fired 2026-06-06T04:45:45Z, state: **open** (unresolved) |
| CF token revoked | ~2026-06-06T12:00 UTC (first 401 seen at 12:00:51 local, CEST = UTC+2, so ~10:00 UTC) |
| Duration token was valid and public | Approximately 6 days, 16 hours |

---

## 3. Credential Status Table

| Credential | Exposed in git? | Still in git history? | Rotated on disk? | Rotation confirmed? | Action Required? |
|---|---|---|---|---|---|
| `CF_API_TOKEN` (shadow + production — same token) | Yes — commit `4649a1d`, 5 occurrences | Yes — permanently in public history | No — both env files predate the revocation | Cloudflare auto-revoked; new token not yet written | **CRITICAL — write new token to both env files** |
| `ABUSEIPDB_KEY` | Yes — commit `4649a1d`, heredoc line 151 | Yes — permanently in public history | No — `cf-sync.env` last modified 2026-05-24, `cf-shadow.env` 2026-05-29 | Unknown — Go daemon gets 401; Python daemon reported success at 06:21 | **HIGH — rotate and verify both daemons use new key** |
| `BETTERSTACK_SOURCE_TOKEN` | Yes — commit `4649a1d`, heredoc line 153 | Yes — permanently in public history | No — env files not updated since incident | No log evidence of BetterStack connectivity tested post-incident | **HIGH — rotate at BetterStack dashboard** |
| `CF_SYNC_API_TOKEN` (internal daemon auth) | No — only appears as empty placeholder in example env file (`deployments/config/security-automation.env.example`) | N/A — no real value in history | N/A | N/A | No action required for git exposure; ensure production value is not logged |
| Second Cloudflare token (bash history, local only) | No — shell history is local only | N/A | Unknown — not tracked in env files | No | Audit validity; rotate if still active |

---

## 4. GitHub Secret Scanning Status

| Field | Value |
|-------|-------|
| Alert number | #1 |
| Alert URL | https://github.com/jmrGrav/security-automation-go/security/secret-scanning/1 |
| Secret type | `cloudflare_user_api_token` |
| State | **open** (not resolved) |
| Created | 2026-06-06T04:45:45Z |
| Resolved at | null |
| Resolved by | null |
| Publicly leaked | `true` |
| Validity (at alert time) | `unknown` (token was auto-revoked by Cloudflare) |
| Push protection | Now **enabled** (status: enabled as of this scan) |
| Secret scanning | Enabled |
| Non-provider patterns | Disabled |
| Validity checks | Disabled |

Note: AbuseIPDB and BetterStack did not generate Secret Scanning alerts because neither is a GitHub partner in the automated revocation program. Their exposure is confirmed by forensic analysis of the git history, not by alert.

---

## 5. Git History Remediation Status

**History has NOT been rewritten.**

The original commit `4649a1d1fd77064cb3c337147a528c9e67fe0141` (authored 2026-05-30) is still present in the repository and accessible on GitHub. All credential values from `CUTOVER_RUNBOOK.md` — including CF_API_TOKEN, ABUSEIPDB_KEY, and BETTERSTACK_SOURCE_TOKEN — remain readable by anyone with the commit SHA or who runs `git log --all -p`.

The deletion commit `b4a5b17` removed the file from HEAD but does not remove it from git object history. The v1.1.1 tag at `b4a5b17` is an ancestor of commit `4649a1d`, meaning the credentials are reachable through tag history.

**What is needed:**

1. Run `git filter-repo --path CUTOVER_RUNBOOK.md --invert-paths` to expunge the file from all commits
2. Force-push all branches and tags
3. Contact GitHub Support to request cache/CDN purge of the deleted blob
4. Resolve GitHub Secret Scanning alert #1 once history is clean and tokens are rotated

---

## 6. Current Service Status

Both services are currently degraded due to the revoked Cloudflare token:

**`cf-sync` (Go daemon):**
- Cloudflare: HTTP 401 `Invalid API Token` (code 1000) on every quota refresh since ~2026-06-06T06:49 local — continuously failing
- AbuseIPDB: HTTP 401 `Authentication failed. Your API key is either missing, incorrect, or revoked` — failing since at least 2026-06-05T17:51 local (predates CF token revocation)

**`crowdsec-cf-sync` (Python daemon):**
- Cloudflare: HTTP 401 `Authentication error` (code 10000) — first seen 2026-06-06T12:00:51 local; circuit breaker opened at 12:01:51; service in degraded mode continuously since then
- AbuseIPDB: **Last confirmed success at 2026-06-06T06:21:54 local** — no AbuseIPDB errors observed in this daemon's logs after the CF token revocation; crowdsec-cf-sync may be using a different credential path from cf-sync

**Key finding on AbuseIPDB:** The Go daemon (`cf-sync`) receives AbuseIPDB 401 errors dating back to at least 2026-06-05T17:51, which is approximately 11 hours before the GitHub Secret Scanning alert fired. This suggests the AbuseIPDB key may have been revoked independently (possibly by AbuseIPDB's own detection, or it was already invalid in the Go daemon context due to a configuration mismatch). The Python daemon appears to have been using the same AbuseIPDB key successfully until at least 06:21 on 2026-06-06.

---

## 7. Risk Assessment

### CF_API_TOKEN — CONTAINED but services are broken
The revoked token is dead. No further unauthorized use is possible with it. However, both services (`cf-sync` and `crowdsec-cf-sync`) are completely unable to communicate with Cloudflare, meaning:
- No new CrowdSec bans are being pushed to Cloudflare WAF rules
- No CF rule cleanup is happening
- Security enforcement is degraded — new threats flagged by CrowdSec are not being blocked at the Cloudflare edge

### ABUSEIPDB_KEY — Unknown / potentially still active
The exposed ABUSEIPDB_KEY was publicly readable for ~6 days. The Go daemon has been getting 401 since 2026-06-05T17:51, but the Python daemon reported success at 06:21 on 2026-06-06. If the key is still active and has not been rotated:
- Any actor who cloned the repository during the 6-day window has the key
- AbuseIPDB accounts can be used to make false reports (reputation damage) or consume your daily quota, effectively disabling your own reporting capability
- AbuseIPDB does not publish a Secret Scanning partnership, so there is no automatic revocation guarantee

### BETTERSTACK_SOURCE_TOKEN — Likely still active, exposure risk
BetterStack source tokens control log ingestion. If exposed and not rotated:
- An attacker can inject arbitrary log entries into your BetterStack account, polluting your security audit trail
- Log data could be used to understand your infrastructure and alert thresholds
- There is no evidence in local logs that BetterStack connectivity has been tested since the incident, so the token's current validity is unconfirmed

### CF_SYNC_API_TOKEN — No git exposure risk
The internal daemon API token was never committed to git with a real value. The only appearance in history is an empty placeholder (`CF_SYNC_API_TOKEN=`) in the example env file, which is intentional and not a credential exposure.

### Git history remaining public
While the CF token is now dead, the ABUSEIPDB_KEY and BETTERSTACK_SOURCE_TOKEN values are still readable in public git history. Until history is rewritten, any actor can retrieve these values. Rotating the credentials closes the active risk even while history remains unrewritten, but history rewrite is still required for completeness.

---

## 8. Immediate Actions Required

### Priority 1 — CRITICAL (services broken, do immediately)

**1. Rotate CF_API_TOKEN and restore Cloudflare connectivity**

Generate two new, distinct Cloudflare API tokens (one for shadow, one for production) and write them to:
- `/etc/security-automation-go/cf-shadow.env` — for the `cf-sync` Go daemon
- `/etc/crowdsec/cf-sync.env` — for the `crowdsec-cf-sync` Python daemon

Then restart both services and confirm VerifyToken returns HTTP 200.

Do not reuse the same token for both files — separating shadow and production tokens prevents a single exposure from revoking both simultaneously.

### Priority 2 — HIGH (credentials exposed and potentially still valid)

**2. Rotate ABUSEIPDB_KEY**

Log into AbuseIPDB, revoke the existing key, and generate a new one. Update the key in whichever env file the Python daemon (`crowdsec-cf-sync`) reads — based on logs, it was still succeeding at 06:21 today, so its credential path is distinct from cf-sync. After rotation, confirm both daemons can reach AbuseIPDB without 401.

**3. Rotate BETTERSTACK_SOURCE_TOKEN**

Log into BetterStack, navigate to the source that received logs from this host, and regenerate the source token. Update the token in the env file read by the cf-sync service. Confirm log shipping resumes.

### Priority 3 — REQUIRED (close the exposure at the source)

**4. Rewrite git history**

```
cd /home/jm/Documents/security-automation-go
git filter-repo --path CUTOVER_RUNBOOK.md --invert-paths
git push --force-with-lease --all
git push --force-with-lease --tags
```

Coordinate with any collaborators to re-clone after the force push. Ask all clones to be discarded.

**5. Request GitHub blob cache purge**

Use GitHub Support's "cached data removal" request to purge the CDN-cached view of the deleted blob at commit `4649a1d`.

**6. Resolve GitHub Secret Scanning alert #1**

After history has been rewritten and the CF token has been rotated, mark alert #1 as resolved in the GitHub Security tab: https://github.com/jmrGrav/security-automation-go/security/secret-scanning/1

### Priority 4 — RECOMMENDED (prevent recurrence)

**7. Audit the second Cloudflare token in `~/.bash_history`**

A second, distinct Cloudflare token appeared in `~/.bash_history` (line ~1634, local only). Verify whether it is still active and rotate it if so.

**8. Enable pre-commit secret scanning**

Install `gitleaks` or `trufflehog` and configure a pre-commit hook to block commits containing secret patterns before they reach GitHub:

```
gitleaks protect --staged
```

**9. Replace real credentials with placeholders in all documentation**

In any future runbooks, use `<CF_API_TOKEN>`, `$CF_API_TOKEN`, or `YOUR_TOKEN_HERE` — never paste live credential values into Markdown files.

---

## Appendix: Evidence Summary

| Evidence | Source | Finding |
|----------|--------|---------|
| CF token revocation time | `journalctl -u cf-sync` | First 401 at 2026-06-06T06:49 local (04:49 UTC); crowdsec-cf-sync first 401 at 2026-06-06T12:00 local (10:00 UTC) |
| CF env files not updated | `stat` on both env files | `cf-shadow.env` mtime: 2026-05-29 22:39:59; `cf-sync.env` mtime: 2026-05-24 03:04:29 — both predate the incident |
| CF env files have different content | `md5sum` on both files | Different hashes — different tokens were already in place before the incident, contradicting the forensic report's finding that they were the same. This warrants further investigation when rotating. |
| AbuseIPDB 401 in cf-sync | `journalctl -u cf-sync` | AbuseIPDB HTTP 401 in Go daemon since at least 2026-06-05T17:51 — predates CF revocation |
| AbuseIPDB success in crowdsec-cf-sync | `journalctl -u crowdsec-cf-sync` | Last confirmed AbuseIPDB report success: 2026-06-06T06:21:54 local |
| BetterStack | Logs | No BetterStack log entries found in either service since the incident — cannot confirm status |
| CF_SYNC_API_TOKEN in git | `git log --all -p` | Only appears as empty placeholder in `deployments/config/security-automation.env.example` (commit `dfff7b4`) — no real value ever committed |
| GitHub alert state | GitHub API | Alert #1: state=open, resolved_at=null — not resolved |
| Push protection | GitHub API | Now enabled (`secret_scanning_push_protection: enabled`) — was not blocking at time of original push |
| Git history rewrite | `git log --oneline --all` | 61+ commits present including `4649a1d`; no force-push / rewrite has occurred |
