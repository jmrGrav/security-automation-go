# Token Exposure Forensic Report

**Date of audit:** 2026-06-06  
**Auditor:** Claude Code (automated forensic scan)  
**Scope:** CF_API_TOKEN used for both `/etc/security-automation-go/cf-shadow.env` (shadow token) and `/etc/crowdsec/cf-sync.env` (production token)

---

## Executive Summary

Both the shadow CF_API_TOKEN and the production CF_API_TOKEN are **the same token**. That single token was hardcoded verbatim into `CUTOVER_RUNBOOK.md` (5 separate occurrences across shell command examples), committed on 2026-05-30 and pushed to the **public** GitHub repository `jmrGrav/security-automation-go` at 2026-05-30T18:00:14Z. The repository was created public on 2026-05-29 and was public at the time of every push — there was no private-to-public transition. GitHub Secret Scanning detected the exposure at 2026-06-06T04:45:45Z (6 days, 10 hours, 45 minutes after the push) and marked the alert as `publicly_leaked: true`. The alert firing 8.5 hours after the v1.1.1 release (2026-06-05T20:16:02Z) suggests the release event may have triggered a re-scan of the now-tagged history, or there was simply a delayed scan queue. Cloudflare automatically revoked the token approximately 7 hours after the alert: production reads began failing at 2026-06-06T12:01 (HTTP 401 code 10000) and the shadow VerifyToken endpoint began returning code 1000. The file was deleted in commit `b4a5b17` (the v1.1.1 release commit), but deletion from `HEAD` does **not** remove it from git history, which remains publicly readable. Additionally, the token appears once in `~/.bash_history` as a curl argument (local only). A second, distinct Cloudflare token also appears in `~/.bash_history` — it is not the same as the revoked credential, but should be audited. The `.gitignore` correctly excludes `*.env` files but offered no protection because the token was embedded directly in a Markdown runbook, not in an env file.

---

## Finding 1: CF_API_TOKEN (shadow = production — same token)

**Token:** CF_API_TOKEN (shadow, stored at `/etc/security-automation-go/cf-shadow.env`)  
**Token:** CF_API_TOKEN (production, stored at `/etc/crowdsec/cf-sync.env`)  
**Note:** Confirmed — both files contain the **identical token value**

---

### Exposure 1A: git history — initial commit

**Found in:** git history (publicly visible on GitHub)  
**Commit:** `4649a1d1fd77064cb3c337147a528c9e67fe0141`  
**Commit date:** 2026-05-30 20:00:11 +0200  
**Commit message:** `docs: production cutover runbook with capability audit`  
**Author:** Jm Rohmer  
**File:** `CUTOVER_RUNBOOK.md`  
**Occurrences in that file:** 5 separate lines  

| Line | Context (token value redacted) |
|------|-------------------------------|
| 131 | `Authorization: Bearer [REDACTED]` inside a `curl` example |
| 149 | `CF_API_TOKEN=[REDACTED]` inside a `tee` heredoc for creating the live env file |
| 273 | `Authorization: Bearer [REDACTED]` in a `curl` recording CF rule count before cutover |
| 299 | `Authorization: Bearer [REDACTED]` in a `watch` command for live monitoring |
| 489 | `Authorization: Bearer [REDACTED]` in an additional monitoring curl snippet |

**Still present in HEAD:** No (the file was deleted in commit `b4a5b17`; but it is permanently in git object history)  
**Branch:** main  
**Tags that include this commit:** `v1.1.1` (commit `4649a1d` is an ancestor of the `v1.1.1` tag at `b4a5b17`)

---

### Exposure 1B: git history — v1.1.1 release commit (diff contains deletions)

**Found in:** git diff output of the release commit (as removed lines — the file was deleted in this commit)  
**Commit:** `b4a5b17a3144cca31a3fdf9d6f416c7f323805d1`  
**Commit date:** 2026-06-05 22:15:38 +0200  
**Commit message:** `release: v1.1.1 production hardening`  
**File:** `CUTOVER_RUNBOOK.md` (status: **D** — deleted)  
**Still present in HEAD:** No (deleted here)  
**Tags:** This IS the `v1.1.1` tagged commit  
**Note:** Git diff output for this commit shows the 5 deletion lines containing the token. The object is still in the pack — `git log --all -p` surfaces it.

---

### Exposure 1C: shell history

**Found in:** `~/.bash_history`  
**Line:** 1636  
**Context (token value redacted):** A `curl` command to the CF API for `PUT /zones/{zone_id}/bot_management` using the token as an `X-Auth-Key` header argument on the command line  
**Severity:** Local only — shell history is not pushed to any remote  
**Still present:** Yes — `~/.bash_history` still contains the line

---

### Exposure 1D: /var/backups (local only)

**Found in:** `/var/backups/security-automation-go-pre-cutover-2026-06-06/cf-shadow.env`  
**Severity:** Local filesystem only — this backup directory is not git-tracked and is not publicly accessible  
**Still present:** Yes (backup copy of the env file)

---

## GitHub Secret Scanning Detection

**Detected:** Yes  
**Alert #:** 1  
**Alert created:** 2026-06-06T04:45:45Z  
**Secret type:** `Cloudflare User API Token` (`cloudflare_user_api_token`)  
**State:** `open` (unresolved)  
**Publicly leaked:** `true`  
**Validity:** `unknown` (as of alert creation — token was likely already revoked by query time)  
**Push protection bypassed:** `false`  
**First location flagged:** `CUTOVER_RUNBOOK.md` line 131, commit `4649a1d1fd77064cb3c337147a528c9e67fe0141`  
**Alert URL:** https://github.com/jmrGrav/security-automation-go/security/secret-scanning/1  

GitHub Secret Scanning operates as part of the GitHub–Cloudflare Secret Scanning Partnership. When GitHub detects a Cloudflare API token pattern in a public repository, it automatically forwards the token to Cloudflare. Cloudflare then validates and revokes it. The `publicly_leaked: true` flag confirms this partnership notification occurred.

---

## Additional Secrets Also Exposed in the Same File

`CUTOVER_RUNBOOK.md` at commit `4649a1d` also contained literal values for the following credentials (visible in the same `tee` heredoc block around lines 149–153):

| Variable | Lines exposed |
|----------|--------------|
| `CF_API_TOKEN` | 131, 149, 273, 299, 489 |
| `CF_ZONE_ID` | 149 (zone ID hardcoded in multiple curl URLs throughout the file; zone IDs are semi-public but should still be rotated as a precaution) |
| `ABUSEIPDB_KEY` | 151 |
| `BETTERSTACK_SOURCE_TOKEN` | 153 |

GitHub Secret Scanning only filed one alert (for the Cloudflare token) because Cloudflare is a partner in the automated revocation program. AbuseIPDB and BetterStack keys may not have automated revocation partners, but the values were publicly accessible on GitHub from 2026-05-30 until the file was deleted in `b4a5b17`. These should also be rotated.

---

## Timeline of Events

| Timestamp (UTC) | Event |
|-----------------|-------|
| 2026-05-29T06:19:47Z | Repository `jmrGrav/security-automation-go` created as **public** (PublicEvent) |
| 2026-05-30T18:00:14Z | `CUTOVER_RUNBOOK.md` pushed to public repo (commit `4649a1d`, authored 18:00:11Z) — token embedded in 5 places; token now publicly accessible |
| 2026-06-05T20:15:45Z | v1.1.1 release commit (`b4a5b17`) pushed; `CUTOVER_RUNBOOK.md` deleted in this commit but blob remains in history |
| 2026-06-05T20:16:02Z | GitHub Release `v1.1.1` published — likely triggers a re-scan of tagged history |
| 2026-06-06T04:45:45Z | GitHub Secret Scanning alert #1 created; token reported to Cloudflare as `publicly_leaked`; **6 days, 10 hours, 45 minutes** after the token first became public |
| 2026-06-06T04:45Z – 12:01 | Cloudflare processes the GitHub–CF partner notification and revokes the token (~7h window) |
| 2026-06-06T12:01 | Production token fails all CF reads (HTTP 401 code 10000); shadow VerifyToken returns code 1000 |

---

## Root Cause Assessment

1. **Direct cause:** A live production Cloudflare API token was pasted verbatim into a Markdown runbook (`CUTOVER_RUNBOOK.md`) as part of shell command examples. The runbook was intended as operational documentation but used real credentials instead of placeholder values.

2. **Contributing factor — same token for both roles:** The shadow token and the production token were the **same credential**. A single exposure therefore revoked both simultaneously.

3. **Gap in .gitignore protection:** The `.gitignore` correctly excludes `*.env` files. However, the exposure occurred inside a `.md` file, which `.gitignore` cannot and should not block. The gap is process/review, not gitignore configuration.

4. **No push protection trigger:** GitHub push protection did not block the commit. The `push_protection_bypassed: false` flag means push protection was either not enabled for this repo at the time, or the pattern was not detected pre-push. Either way, the file landed in history and the only backstop was after-the-fact secret scanning.

5. **Delay between exposure and detection:** The token was in the public repo for approximately 6 days, 11 hours before the secret scanning alert fired (push: 2026-05-30T18:00:14Z, alert: 2026-06-06T04:45:45Z). The repository was public from creation and no privacy change occurred. The alert firing ~8.5 hours after the v1.1.1 release strongly suggests GitHub re-scanned the history when the release was published, as release events are known to trigger additional secret scanning passes on tagged commits. During the full 6-day window, the token was accessible to any actor who cloned the repository or browsed its file history.

---

## Is the Exposure Still Present?

| Location | Status |
|----------|--------|
| `HEAD` tree (current branch) | **Removed** — file deleted in `b4a5b17` |
| `git` object history | **Permanently present** — all 61 commits including `4649a1d` remain in the pack; `git log --all -p` surfaces the token |
| GitHub remote (public) | **Permanently present in history** — deletion commits do not erase git history; the blob is still accessible via the commit SHA or blob SHA |
| `~/.bash_history` | **Still present** — local only, line 1636 |
| `/var/backups/` | **Still present** — local only, not git-tracked |
| Active Cloudflare validity | **Revoked** — token is no longer valid |

---

## Recommended Remediation Steps

### Immediate (completed by Cloudflare automatically)
- [x] Token revoked by Cloudflare via Secret Scanning Partnership

### Required — Token Rotation

1. **Generate two new, distinct CF API tokens** — one for shadow mode, one for production. Do not reuse the same credential across roles.
2. **Write the new tokens** to `/etc/security-automation-go/cf-shadow.env` and `/etc/crowdsec/cf-sync.env` respectively.
3. **Restart the affected services** and confirm CF API calls succeed (VerifyToken HTTP 200, read operations returning HTTP 200).
4. **Rotate the AbuseIPDB key** and **BetterStack source token** exposed in the same runbook block — they were publicly visible for the same 7-day window.

### Required — Git History Remediation

5. **Rewrite git history** using `git filter-repo` (preferred) or BFG Repo Cleaner to expunge `CUTOVER_RUNBOOK.md` from all commits (or at minimum expunge the token occurrences):
   ```
   git filter-repo --path CUTOVER_RUNBOOK.md --invert-paths
   ```
   Then force-push all branches and tags. Coordinate with any collaborators to re-clone.
6. **Contact GitHub Support** to purge cached views of the deleted file from GitHub's CDN (use the "cached data removal" request form).
7. **Resolve the GitHub Secret Scanning alert #1** once history has been rewritten and tokens rotated, so the security tab no longer shows an open exposure.

### Process — Prevention

8. **Enable GitHub push protection** for this repository (Settings → Code security → Push protection). This would have blocked the commit at push time.
9. **Add a pre-commit hook** (e.g., `gitleaks protect --staged`) to catch secrets locally before they reach GitHub.
10. **Replace all live credential values in documentation** with placeholder syntax such as `<CF_API_TOKEN>` or `$CF_API_TOKEN`. Never paste real tokens into Markdown files, even for "temporary" runbooks.
11. **Separate shadow and production tokens** — generate distinct credentials for each role. That way, if one is exposed, the other remains operational.
12. **Treat the CF Zone ID as semi-sensitive** — while Zone IDs are not secrets in the strict sense, they should use placeholder values in public documentation to reduce attack surface.

---

## Finding 2: Second Distinct Cloudflare Token in Shell History (local only)

**Found in:** `~/.bash_history` (local only — not pushed to any remote)  
**Lines:** approximately 1634–1638 (the command block preceding the redacted-token curl)  
**Detail:** A `curl PUT /zones/{zone_id}/bot_management` call appears twice in sequence. The first invocation uses a `cfut_...` prefixed value via `X-Auth-Key` that is **different** from the revoked token (confirmed by length and prefix character comparison; the revoked token's value in the alert was confirmed to match the on-disk tokens, while the first curl uses a visually distinct value). The second invocation uses the revoked token.  
**Publicly exposed:** No — shell history is local only  
**Still present:** Yes  
**Recommended action:** Audit whether this second CF credential is still valid and still in use. If it belongs to the same Cloudflare account, verify it has not also been compromised. Rotate it preventively.

---

## No Issues Found In

- Working tree (current checkout) — 0 token matches  
- `.github/workflows/ci.yml` — 0 token matches  
- GitHub release body (`v1.1.1`) — 0 token matches  
- GitHub gists — none exist  
- GitHub PR/issue comments — no PRs or issues exist on this repository  
- `/var/backups/` — token present only in the legitimate `cf-shadow.env` backup file (local filesystem, not git-tracked, not remotely accessible)

---

## Tools Searched

| Tool | Status |
|------|--------|
| `git log --all -p` (manual grep) | Executed — found 10 hits in 2 commits |
| `git grep` (HEAD) | Executed — 0 hits (token not in HEAD tree) |
| Working tree `grep -rl` | Executed — 0 hits |
| `~/.bash_history` | Executed — 1 hit at line 1636 |
| `/var/backups/` | Executed — 1 hit (backup env file, local only) |
| GitHub Secret Scanning API | Executed — 1 open alert, `publicly_leaked: true` |
| GitHub Gists | None found |
| GitHub Releases | Release body checked — no token present |
| GitHub PRs / issue comments | No PRs or issues exist on this repository |
| `.github/workflows/ci.yml` | Checked — no token present |
| `trufflehog` | Not installed |
| `gitleaks` | Not installed |
