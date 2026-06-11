package ui

import (
	"fmt"
	"net/http"
	"time"
)

type componentStatus struct {
	Name   string
	Status string // "enabled", "disabled", "unconfigured"
}

func (s *Server) handleRuntimeStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Resolve runtime flags (best-effort; default to all-false if store not available)
	var flags struct {
		CSPollerEnabled            bool
		CloudflareMutationsEnabled bool
		AbuseIPDBEnabled           bool
		BetterStackEnabled         bool
	}
	if store, ok := s.setupStore.(runtimeFlagStore); ok {
		if f, err := store.GetRuntimeFlags(ctx); err == nil {
			flags.CSPollerEnabled = f.CSPollerEnabled
			flags.CloudflareMutationsEnabled = f.CloudflareMutationsEnabled
			flags.AbuseIPDBEnabled = f.AbuseIPDBEnabled
			flags.BetterStackEnabled = f.BetterStackEnabled
		}
	}

	// Resolve credential presence
	credPresent := func(key string) bool {
		return credentialConfigured(ctx, s.credentialStore, key)
	}

	resolveStatus := func(credKey string, flagEnabled bool) string {
		if !credPresent(credKey) {
			return "unconfigured"
		}
		if !flagEnabled {
			return "disabled"
		}
		return "enabled"
	}

	components := []componentStatus{
		{
			Name:   "CrowdSec Poller",
			Status: resolveStatus("crowdsec.lapi_key", flags.CSPollerEnabled),
		},
		{
			Name:   "Cloudflare Mutations",
			Status: resolveStatus("cloudflare.api_token", flags.CloudflareMutationsEnabled),
		},
		{
			Name:   "AbuseIPDB Reporter",
			Status: resolveStatus("abuseipdb.api_key", flags.AbuseIPDBEnabled),
		},
		{
			Name:   "BetterStack Telemetry",
			Status: resolveStatus("betterstack.source_token", flags.BetterStackEnabled),
		},
	}

	csrfToken := s.csrfTokenFromRequest(r)
	reportTime := time.Now().UTC().Format(time.RFC3339)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, runtimeStatusPage(csrfToken, components, reportTime))
}

func runtimeStatusPage(csrfToken string, components []componentStatus, reportTime string) string {
	rows := ""
	for _, c := range components {
		badgeClass := "badge-ok"
		label := "enabled"
		switch c.Status {
		case "disabled":
			badgeClass = "badge-warn"
			label = "disabled"
		case "unconfigured":
			badgeClass = "badge-warn"
			label = "unconfigured"
		}
		rows += fmt.Sprintf(`<tr><td>%s</td><td><span class="%s">%s</span></td></tr>`, c.Name, badgeClass, label)
	}

	return fmt.Sprintf(`<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>Runtime Status</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;background:#f5f7fb;color:#10243e}
header{padding:1rem 1.25rem;background:#10243e;color:white}
.nav{display:flex;gap:1rem;flex-wrap:wrap;margin-top:.75rem}
.nav a{color:#dce8ff;text-decoration:none}
main{max-width:40rem;margin:2rem auto;background:#fff;border:1px solid #d8e1ef;border-radius:8px;padding:1.5rem}
h2{margin-top:0}
table{width:100%%;border-collapse:collapse}
th,td{text-align:left;padding:.6rem .75rem;border-bottom:1px solid #eef1f6}
th{background:#f8fafc;font-weight:600;font-size:.875rem;color:#5f6b7a}
.badge-ok{display:inline-block;padding:.2rem .6rem;border-radius:9999px;background:#ecfdf5;color:#065f46;font-size:.8rem;font-weight:600}
.badge-warn{display:inline-block;padding:.2rem .6rem;border-radius:9999px;background:#fffbeb;color:#92400e;font-size:.8rem;font-weight:600}
.report-time{color:#5f6b7a;font-size:.8rem;margin-top:1rem}
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
<h2>Runtime Status</h2>
<table>
  <thead><tr><th>Component</th><th>Status</th></tr></thead>
  <tbody>%s</tbody>
</table>
<div class="report-time">Last updated: %s &mdash; page auto-refreshes every 30 seconds.</div>
</main></body></html>`,
		csrfToken,
		rows,
		reportTime,
	)
}
