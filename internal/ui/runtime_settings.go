package ui

import (
	"context"
	"fmt"
	"net/http"

	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

// runtimeFlagStore is the narrow capability needed by the runtime-settings handlers.
// *sqlite.SetupStore satisfies it; in-memory test stores do not need to.
type runtimeFlagStore interface {
	GetRuntimeFlags(ctx context.Context) (sqlite.RuntimeFlags, error)
	SetRuntimeFlag(ctx context.Context, key string, enabled bool) error
}

func (s *Server) handleRuntimeSettings(w http.ResponseWriter, r *http.Request) {
	store, ok := s.setupStore.(runtimeFlagStore)
	if !ok {
		http.Error(w, "setup store not available", http.StatusServiceUnavailable)
		return
	}

	flags, err := store.GetRuntimeFlags(r.Context())
	if err != nil {
		if s.logger != nil {
			s.logger.Error("get runtime flags", "err", err)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	flash := ""
	if r.URL.Query().Get("saved") == "1" {
		flash = "saved"
	}

	csrfToken := s.csrfTokenFromRequest(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, runtimeSettingsPage(csrfToken, flags, flash))
}

func (s *Server) handleRuntimeSettingsPost(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}

	store, ok := s.setupStore.(runtimeFlagStore)
	if !ok {
		http.Error(w, "setup store not available", http.StatusServiceUnavailable)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	flagValues := map[string]bool{
		"cs_poller_enabled":            r.FormValue("cs_poller_enabled") == "true",
		"cloudflare_mutations_enabled": r.FormValue("cloudflare_mutations_enabled") == "true",
		"abuseipdb_enabled":            r.FormValue("abuseipdb_enabled") == "true",
		"betterstack_enabled":          r.FormValue("betterstack_enabled") == "true",
	}
	for key, enabled := range flagValues {
		if err := store.SetRuntimeFlag(r.Context(), key, enabled); err != nil {
			if s.logger != nil {
				s.logger.Error("set runtime flag", "key", key, "err", err)
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	if s.audit != nil {
		s.audit.Record("runtime_flags_updated", map[string]string{
			"cs_poller_enabled":            fmt.Sprintf("%t", flagValues["cs_poller_enabled"]),
			"cloudflare_mutations_enabled": fmt.Sprintf("%t", flagValues["cloudflare_mutations_enabled"]),
			"abuseipdb_enabled":            fmt.Sprintf("%t", flagValues["abuseipdb_enabled"]),
			"betterstack_enabled":          fmt.Sprintf("%t", flagValues["betterstack_enabled"]),
		})
	}

	http.Redirect(w, r, "/settings/runtime?saved=1", http.StatusSeeOther)
}

func runtimeSettingsPage(csrfToken string, flags sqlite.RuntimeFlags, flash string) string {
	checked := func(b bool) string {
		if b {
			return " checked"
		}
		return ""
	}

	savedBanner := ""
	if flash == "saved" {
		savedBanner = `<div class="ok">Settings saved. Changes take effect at the next scheduler cycle (≤60 seconds).</div>`
	}

	return fmt.Sprintf(`<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Settings — Runtime</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;background:#f5f7fb;color:#10243e}
header{padding:1rem 1.25rem;background:#10243e;color:white}
.nav{display:flex;gap:1rem;flex-wrap:wrap;margin-top:.75rem}
.nav a{color:#dce8ff;text-decoration:none}
main{max-width:36rem;margin:2rem auto;background:#fff;border:1px solid #d8e1ef;border-radius:8px;padding:1.5rem}
h2{margin-top:0}
.flag{display:flex;align-items:center;gap:.75rem;padding:.65rem 0;border-bottom:1px solid #eef1f6}
.flag:last-child{border-bottom:0}
.flag label{flex:1;cursor:pointer}
.flag .desc{color:#5f6b7a;font-size:.85rem;display:block;margin-top:.2rem}
.ok{color:#065f46;background:#ecfdf5;border:1px solid #a7f3d0;border-radius:6px;padding:.75rem;margin-bottom:1rem}
.warn{color:#92400e;background:#fffbeb;border:1px solid #fde68a;border-radius:6px;padding:.75rem;margin:.75rem 0}
button{margin-top:1.25rem;padding:.65rem 1.1rem;border:0;border-radius:6px;background:#185adb;color:#fff;cursor:pointer}
</style></head><body>
<header><strong>Operator UI</strong>
<div class="nav">
  <a href="/">Dashboard</a>
  <a href="/providers">Providers</a>
  <a href="/settings/runtime">Settings</a>
  <a href="/status/runtime">Runtime Status</a>
  <form action="/logout" method="post" style="display:inline">
    <input type="hidden" name="csrf_token" value="%s"/>
    <button type="submit" style="background:transparent;color:#dce8ff;border:1px solid #dce8ff;padding:.35rem .75rem;border-radius:4px;cursor:pointer">Logout</button>
  </form>
</div></header>
<main>
<h2>Runtime Settings</h2>
%s
<div class="warn">Changes take effect at the next scheduler cycle (≤ 60 seconds). Secrets require a process restart.</div>
<form method="post" action="/settings/runtime">
  <input type="hidden" name="csrf_token" value="%s"/>
  <div class="flag">
    <input type="checkbox" id="cs_poller_enabled" name="cs_poller_enabled" value="true"%s>
    <label for="cs_poller_enabled">CrowdSec Poller
      <span class="desc">Poll CrowdSec LAPI and push active bans to Cloudflare.</span>
    </label>
  </div>
  <div class="flag">
    <input type="checkbox" id="cloudflare_mutations_enabled" name="cloudflare_mutations_enabled" value="true"%s>
    <label for="cloudflare_mutations_enabled">Cloudflare Mutations
      <span class="desc">Allow the daemon to create/delete firewall rules in Cloudflare.</span>
    </label>
  </div>
  <div class="flag">
    <input type="checkbox" id="abuseipdb_enabled" name="abuseipdb_enabled" value="true"%s>
    <label for="abuseipdb_enabled">AbuseIPDB Reporter
      <span class="desc">Report confirmed malicious IPs to AbuseIPDB.</span>
    </label>
  </div>
  <div class="flag">
    <input type="checkbox" id="betterstack_enabled" name="betterstack_enabled" value="true"%s>
    <label for="betterstack_enabled">BetterStack Telemetry
      <span class="desc">Forward security telemetry to BetterStack.</span>
    </label>
  </div>
  <button type="submit">Save Settings</button>
</form>
</main></body></html>`,
		csrfToken,
		savedBanner,
		csrfToken,
		checked(flags.CSPollerEnabled),
		checked(flags.CloudflareMutationsEnabled),
		checked(flags.AbuseIPDBEnabled),
		checked(flags.BetterStackEnabled),
	)
}
