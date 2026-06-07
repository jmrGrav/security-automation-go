package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
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
	abuseKey := ""
	if s.secretProvider != nil {
		abuseKey, _ = s.secretProvider.Lookup("ABUSEIPDB_KEY")
	}
	if abuseKey == "" {
		abuseKey = s.cfg.AbuseIPDB.APIKey
	}
	return health.Config{
		CloudflareToken:     s.cfg.Cloudflare.APIToken,
		CloudflareZoneID:    s.cfg.Cloudflare.ZoneID,
		AbuseIPDBKey:        abuseKey,
		AbuseIPDBEnabled:    s.cfg.AbuseIPDB.Enabled,
		BetterStackToken:    s.cfg.BetterStack.SourceToken,
		StateDir:            s.cfg.StateDir,
		LogDir:              "/var/log/security-automation",
		SecretDir:           "/etc/security-automation-go/secrets",
		DecisionsLog:        s.cfg.CrowdSec.DecisionsLog,
		NginxLogDir:         s.cfg.CrowdSec.NginxLogDir,
		OpenRestyEventsFile: s.cfg.OpenResty.EventsFile,
	}
}

func (s *Server) buildDetectConfig() detect.Config {
	return detect.Config{
		StateDir:            s.cfg.StateDir,
		LogDir:              "/var/log/security-automation",
		SecretDir:           "/etc/security-automation-go/secrets",
		DecisionsLog:        s.cfg.CrowdSec.DecisionsLog,
		NginxLogDir:         s.cfg.CrowdSec.NginxLogDir,
		OpenRestyEventsFile: s.cfg.OpenResty.EventsFile,
		CloudflareToken:     s.cfg.Cloudflare.APIToken,
		CloudflareZoneID:    s.cfg.Cloudflare.ZoneID,
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
	_, err := fmt.Fprint(w, `</section></div>`)
	return err
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
