package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/detect"
	"github.com/jm/security-automation-go/internal/health"
)

type healthPageView struct {
	Checks     []health.Check
	Detectors  []detect.Result
	ReportTime string
}

func (s *Server) buildHealthConfig() health.Config {
	runtimeDir := "/var/lib/security-automation-go/runtime"
	setupComplete := false
	if s.setupStore != nil {
		if ok, err := s.setupStore.IsComplete(context.Background()); err == nil {
			setupComplete = ok
		}
	}
	cloudflareConfigured := false
	abuseConfigured := false
	betterstackConfigured := false
	openAIConfigured := false
	anthropicConfigured := false
	geminiConfigured := false
	crowdSecLAPIConfigured := false
	if s.credentialStore != nil {
		cloudflareConfigured = credentialConfigured(context.Background(), s.credentialStore, "cloudflare.api_token")
		abuseConfigured = credentialConfigured(context.Background(), s.credentialStore, "abuseipdb.api_key")
		betterstackConfigured = credentialConfigured(context.Background(), s.credentialStore, "betterstack.source_token")
		openAIConfigured = credentialConfigured(context.Background(), s.credentialStore, "ai.openai.api_key")
		anthropicConfigured = credentialConfigured(context.Background(), s.credentialStore, "ai.anthropic.api_key")
		geminiConfigured = credentialConfigured(context.Background(), s.credentialStore, "ai.gemini.api_key")
		crowdSecLAPIConfigured = credentialConfigured(context.Background(), s.credentialStore, "crowdsec.lapi_key")
	}
	return health.Config{
		CloudflareTokenConfigured: cloudflareConfigured,
		CloudflareZoneID:          s.cfZoneIDFromSetup(context.Background()),
		AbuseIPDBConfigured:       abuseConfigured,
		AbuseIPDBEnabled:          providerRuntimeEnabled(context.Background(), s.setupStore, "abuseipdb", s.cfg.AbuseIPDB.Enabled),
		BetterStackConfigured:     betterstackConfigured,
		CrowdSecLAPIKeyConfigured: crowdSecLAPIConfigured,
		StateDir:                  s.cfg.StateDir,
		LogDir:                    "/var/log/security-automation-go",
		SecretDir:                 runtimeDir,
		CanonicalSecretsDir:       runtimeDir,
		LegacySecretsDir:          "",
		DecisionsLog:              s.cfg.CrowdSec.DecisionsLog,
		NginxLogDir:               s.cfg.CrowdSec.NginxLogDir,
		OpenRestyEventsFile:       s.cfg.OpenResty.EventsFile,
		OpenAIEnabled:             s.aiConfig.OpenAI.Enabled,
		OpenAIConfigured:          openAIConfigured,
		AnthropicEnabled:          s.aiConfig.Anthropic.Enabled,
		AnthropicConfigured:       anthropicConfigured,
		GeminiEnabled:             s.aiConfig.Gemini.Enabled,
		GeminiConfigured:          geminiConfigured,
		SetupComplete:             setupComplete,
	}
}

func (s *Server) buildDetectConfig() detect.Config {
	return detect.Config{
		StateDir:            s.cfg.StateDir,
		LogDir:              "/var/log/security-automation-go",
		SecretDir:           "/var/lib/security-automation-go/runtime",
		DecisionsLog:        s.cfg.CrowdSec.DecisionsLog,
		NginxLogDir:         s.cfg.CrowdSec.NginxLogDir,
		OpenRestyEventsFile: s.cfg.OpenResty.EventsFile,
		CloudflareToken:     s.cfSentinelToken(),
		CloudflareZoneID:    s.cfZoneIDFromSetup(context.Background()),
	}
}

func (s *Server) handleHealthPage(w http.ResponseWriter, r *http.Request) {
	view := healthPageView{
		Checks:     health.RunAll(s.buildHealthConfig()),
		Detectors:  detect.RunAll(s.buildDetectConfig()),
		ReportTime: time.Now().UTC().Format(time.RFC3339),
	}
	_ = HealthPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
}

func credentialConfigured(ctx context.Context, store CredentialStorer, key string) bool {
	if store == nil {
		return false
	}
	_, ok, err := store.Lookup(ctx, key)
	return err == nil && ok
}

func (s *Server) cfZoneIDFromSetup(ctx context.Context) string {
	if s.setupStore == nil {
		return s.cfg.Cloudflare.ZoneID
	}
	if v, ok, err := s.setupStore.GetSetting(ctx, "cf_zone_id"); err == nil && ok && strings.TrimSpace(v) != "" {
		return v
	}
	return s.cfg.Cloudflare.ZoneID
}

func (s *Server) handleHealthJSON(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"health":       health.RunAll(s.buildHealthConfig()),
		"detection":    detect.RunAll(s.buildDetectConfig()),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// HealthPage renders the /health page.
func HealthPage(view healthPageView, csrfToken string) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Health Center",
		Headline: "Health Center",
		Subtitle: "System health, environment detection, and diagnostic tools.",
		Active:   "/health",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			return renderHealthBody(w, view, csrfToken)
		}),
	})
}

func renderHealthBody(w io.Writer, view healthPageView, csrfToken string) error {
	green, yellow, red := 0, 0, 0
	for _, c := range view.Checks {
		switch c.Status {
		case health.Green:
			green++
		case health.Yellow:
			yellow++
		case health.Red:
			red++
		}
	}
	if _, err := fmt.Fprintf(w,
		`<div class="panel"><h2>Summary</h2><p class="muted">As of %s</p>`+
			`<div class="badges">`+
			`<span class="badge healthy">%d GREEN</span>`+
			`<span class="badge warning">%d YELLOW</span>`+
			`<span class="badge error">%d RED</span>`+
			`</div>`+
			`<div style="margin-top:1rem;display:flex;gap:.75rem">`+
			`<form method="POST" action="/health/diagnostic">`+
			`<input type="hidden" name="csrf_token" value="%s">`+
			`<button type="submit">Run Full Diagnostic</button>`+
			`</form>`+
			`<a href="/health/support-bundle" style="display:inline-block;padding:.5rem 1rem;background:#0f8b4c;color:white;border-radius:6px;text-decoration:none">Download Support Bundle</a>`+
			`</div></div>`,
		html.EscapeString(view.ReportTime), green, yellow, red, html.EscapeString(csrfToken),
	); err != nil {
		return err
	}

	if _, err := fmt.Fprint(w, `<div class="panel"><h2>Health Checks</h2><div class="kv">`); err != nil {
		return err
	}
	for _, c := range view.Checks {
		cls := healthLevelClass(c.Status)
		detail := c.Reason
		if c.Remediation != "" {
			detail += " → " + c.Remediation
		}
		if _, err := fmt.Fprintf(w,
			`<div class="row"><span>%s</span><span class="badge %s">%s: %s</span></div>`,
			html.EscapeString(c.Name), cls, html.EscapeString(string(c.Status)), html.EscapeString(detail),
		); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(w, `</div></div>`); err != nil {
		return err
	}

	if _, err := fmt.Fprint(w, `<div class="panel"><h2>Environment Detection</h2><section class="grid">`); err != nil {
		return err
	}
	for _, d := range view.Detectors {
		if err := renderDetectCard(w, d); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(w, `</section></div>`); err != nil {
		return err
	}

	// OpenResty runbook panel — only shown when configured but not collecting events.
	for _, d := range view.Detectors {
		if d.Name == "openresty" && d.Configured {
			if err := renderOpenRestyRunbook(w, d); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

func healthLevelClass(lvl health.Level) string {
	switch lvl {
	case health.Green:
		return "healthy"
	case health.Yellow:
		return "warning"
	case health.Red:
		return "error"
	default:
		return "badge"
	}
}

func renderOpenRestyRunbook(w io.Writer, d detect.Result) error {
	eventsExist := d.Details["events_exist"] == "present"
	stuckProcessing := d.Details["stuck_processing"] != ""
	eventsAge := d.Details["events_age"]
	eventsFile := d.Details["events_file"]

	staleThreshold := 30 * time.Minute
	isStale := false
	if eventsExist && eventsAge != "" {
		// Parse "Xh Ym Zs ago" by stripping " ago" suffix and using time.ParseDuration.
		ageStr := strings.TrimSuffix(eventsAge, " ago")
		if dur, err := time.ParseDuration(ageStr); err == nil {
			isStale = dur > staleThreshold
		}
	}

	if eventsExist && !stuckProcessing && !isStale {
		return nil // everything looks fine — skip runbook
	}

	if _, err := fmt.Fprint(w, `<div class="panel"><h2>OpenResty Runbook</h2>`); err != nil {
		return err
	}

	if stuckProcessing {
		if _, err := fmt.Fprintf(w,
			`<div class="badge error" style="margin-bottom:.75rem">Stuck processing file detected</div>`+
				`<p>A <code>%s.processing</code> file exists. This means a prior ingestion cycle was interrupted before it could finish. `+
				`Events in that file were not processed. Delete the file to unblock the pipeline:</p>`+
				`<pre>rm %s.processing</pre>`,
			html.EscapeString(strings.TrimSuffix(eventsFile, ".jsonl")),
			html.EscapeString(strings.TrimSuffix(eventsFile, ".jsonl")),
		); err != nil {
			return err
		}
	}

	if !eventsExist {
		if _, err := fmt.Fprintf(w,
			`<div class="badge warning" style="margin-bottom:.75rem">Events file missing</div>`+
				`<p>The configured events file <code>%s</code> does not exist. Possible causes:</p>`+
				`<ul>`+
				`<li>The Lua WAF hook in OpenResty is not writing events (check nginx error log: <code>journalctl -u openresty -n 50</code>)</li>`+
				`<li>The directory does not exist or has wrong permissions</li>`+
				`<li>No WAF events have been triggered yet (file is created on first hit)</li>`+
				`</ul>`,
			html.EscapeString(eventsFile),
		); err != nil {
			return err
		}
	} else if isStale {
		if _, err := fmt.Fprintf(w,
			`<div class="badge warning" style="margin-bottom:.75rem">Events file is stale (%s)</div>`+
				`<p>The events file has not been updated in over 30 minutes. Possible causes:</p>`+
				`<ul>`+
				`<li>No WAF traffic in this period (normal during quiet periods)</li>`+
				`<li>The Lua hook is writing events but all are being dropped — check that each event has a non-empty <code>ip</code> and <code>detail</code> field</li>`+
				`<li>OpenResty was restarted and the hook is no longer loaded (check <code>nginx -t</code>)</li>`+
				`</ul>`,
			html.EscapeString(eventsAge),
		); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprint(w,
		`<details style="margin-top:1rem"><summary>Event format requirements</summary>`+
			`<p>Each line in the events file must be valid JSON with these fields:</p>`+
			`<pre>{"ts": 1700000000.0, "type": "block", "ip": "1.2.3.4", "score": 10, "detail": "/login"}</pre>`+
			`<p><strong>Silent drop conditions:</strong> events where <code>ip</code> or <code>detail</code> is empty are silently discarded by the ingestion pipeline. `+
			`Verify your Lua script always sets both fields before writing.</p>`+
			`</details>`,
	); err != nil {
		return err
	}

	_, err := fmt.Fprint(w, `</div>`)
	return err
}

func renderDetectCard(w io.Writer, r detect.Result) error {
	installed := "missing"
	if r.Installed {
		installed = "present"
	}
	configured := "unconfigured"
	if r.Configured {
		configured = "configured"
	}
	healthyLabel, healthyClass := "unhealthy", "error"
	if r.Healthy {
		healthyLabel, healthyClass = "healthy", "healthy"
	}
	if _, err := fmt.Fprintf(w,
		`<div class="panel"><h3>%s</h3><div class="badges">`+
			`<span class="badge">%s</span>`+
			`<span class="badge">%s</span>`+
			`<span class="badge %s">%s</span>`+
			`</div><div class="kv">`,
		html.EscapeString(r.Name),
		html.EscapeString(installed),
		html.EscapeString(configured),
		healthyClass, html.EscapeString(healthyLabel),
	); err != nil {
		return err
	}
	for k, v := range r.Details {
		if _, err := fmt.Fprintf(w,
			`<div class="row"><span>%s</span><span>%s</span></div>`,
			html.EscapeString(k), html.EscapeString(v),
		); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</div></div>`)
	return err
}
