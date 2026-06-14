package ui

import (
	"context"
	"fmt"
	"html"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/discovery"
	"github.com/jm/security-automation-go/internal/cloudflare/transport"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/detect"
	"github.com/jm/security-automation-go/internal/health"
	"github.com/jm/security-automation-go/internal/httpclient"
	uiauth "github.com/jm/security-automation-go/internal/ui/auth"
)

// setupGuardMiddleware intercepts every request when setup is incomplete,
// redirecting to the current wizard step. It is a no-op when setupStore is nil.
func (s *Server) setupGuardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.setupStore == nil {
			next.ServeHTTP(w, r)
			return
		}
		// Always let setup routes through to avoid redirect loops.
		// Setup routes are protected by binding to localhost by default.
		if strings.HasPrefix(r.URL.Path, "/setup") {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := stableUIReadContext(r.Context())
		defer cancel()
		complete, err := s.setupStore.IsComplete(ctx)
		if err != nil || !complete {
			step := 1
			if st, e := s.setupStore.GetCurrentStep(ctx); e == nil {
				step = st
			}
			http.Redirect(w, r, fmt.Sprintf("/setup/step/%d", step), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// registerSetupRoutes registers /setup/* routes. Must be called before existing routes.
func (s *Server) registerSetupRoutes() {
	s.mux.HandleFunc("GET /setup/step/1", s.handleSetupStep1)
	s.mux.HandleFunc("POST /setup/step/1", s.handleSetupStep1Post)
	s.mux.HandleFunc("GET /setup/step/2", s.handleSetupStep2)
	s.mux.HandleFunc("POST /setup/step/2", s.handleSetupStep2Post)
	s.mux.HandleFunc("GET /setup/step/3", s.handleSetupStep3)
	s.mux.HandleFunc("POST /setup/step/3", s.handleSetupStep3Post)
	s.mux.HandleFunc("GET /setup/step/4", s.handleSetupStep4)
	s.mux.HandleFunc("POST /setup/step/4", s.handleSetupStep4Post)
	s.mux.HandleFunc("GET /setup/step/5", s.handleSetupStep5)
	s.mux.HandleFunc("POST /setup/step/5", s.handleSetupStep5Post)
	s.mux.HandleFunc("GET /setup/step/6", s.handleSetupStep6)
	s.mux.HandleFunc("POST /setup/step/6", s.handleSetupStep6Post)
	s.mux.HandleFunc("GET /setup/step/7", s.handleSetupStep7)
	s.mux.HandleFunc("POST /setup/step/7", s.handleSetupStep7Post)
	s.mux.HandleFunc("GET /setup/step/8", s.handleSetupStep8)
	s.mux.HandleFunc("GET /setup/step/9", s.handleSetupStep9)
	s.mux.HandleFunc("POST /setup/step/9", s.handleSetupStep9Post)
	s.mux.HandleFunc("GET /setup/complete", s.handleSetupComplete)
}

// renderSetupPage writes a full-page HTML response for a wizard step.
func renderSetupPage(w http.ResponseWriter, step int, title, bodyHTML, errorMsg string) {
	progressPct := (step * 100) / 9
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Setup — Step %d of 9: %s</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;background:#f5f7fb;color:#10243e}
header{padding:1rem 1.25rem;background:#10243e;color:white}
.prog{height:4px;background:#2563eb;width:%d%%}
main{max-width:36rem;margin:2rem auto;background:#fff;border:1px solid #d8e1ef;border-radius:8px;padding:1.5rem;box-shadow:0 1px 4px rgba(16,36,62,.08)}
h2{margin-top:0}
label{display:block;margin:.5rem 0 .25rem}
input[type=text],input[type=password],input[type=number]{width:100%%;box-sizing:border-box;padding:.65rem .8rem;border:1px solid #c9d5e5;border-radius:6px}
button{margin-top:1rem;padding:.65rem 1.1rem;border:0;border-radius:6px;background:#185adb;color:#fff;cursor:pointer}
button.secondary{background:#e8edf6;color:#10243e}
.error{color:#9b1c1c;background:#fef2f2;border:1px solid #fecaca;border-radius:6px;padding:.75rem;margin-bottom:1rem}
.note{color:#5f6b7a;font-size:.9rem}
.warn{color:#92400e;background:#fffbeb;border:1px solid #fde68a;border-radius:6px;padding:.75rem;margin:.75rem 0}
.ok{color:#065f46;background:#ecfdf5;border:1px solid #a7f3d0;border-radius:6px;padding:.75rem;margin:.75rem 0}
</style>
</head><body>
<header><strong>Security Automation — First-Run Setup</strong><div style="margin-top:.35rem;font-size:.85rem">Step %d of 9</div></header>
<div class="prog"></div>
<main>
<h2>%s</h2>
`, step, title, progressPct, step, title)
	if errorMsg != "" {
		fmt.Fprintf(w, `<div class="error">%s</div>`, html.EscapeString(errorMsg))
	}
	fmt.Fprint(w, bodyHTML)
	fmt.Fprint(w, `</main></body></html>`)
}

// Step 1: Create admin password.
func (s *Server) handleSetupStep1(w http.ResponseWriter, r *http.Request) {
	if s.setupStore != nil {
		if complete, _ := s.setupStore.IsComplete(r.Context()); complete {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
	}
	body := `
<p>Welcome to Security Automation. Create your administrator password to begin.</p>
<p>Choose a strong password (min 16 chars). It will be stored as a bcrypt hash in SQLite.</p>
<form action="/setup/step/1" method="post">
  <label for="new">Administrator password</label>
  <input id="new" name="new_password" type="password" required autocomplete="new-password">
  <label for="confirm">Confirm password</label>
  <input id="confirm" name="confirm_password" type="password" required autocomplete="new-password">
  <button type="submit">Create password &amp; continue</button>
</form>`
	renderSetupPage(w, 1, "Create administrator password", body, "")
}

// Step 1 POST: verify complexity, hash and store new password, grant session.
func (s *Server) handleSetupStep1Post(w http.ResponseWriter, r *http.Request) {
	newPwd := r.FormValue("new_password")
	confirmPwd := r.FormValue("confirm_password")

	rerender := func(errMsg string) {
		body := `
<p>Welcome to Security Automation. Create your administrator password to begin.</p>
<form action="/setup/step/1" method="post">
  <label>Administrator password</label><input name="new_password" type="password" required>
  <label>Confirm password</label><input name="confirm_password" type="password" required>
  <button type="submit">Create password &amp; continue</button>
</form>`
		renderSetupPage(w, 1, "Create administrator password", body, errMsg)
	}

	if newPwd != confirmPwd {
		rerender("Passwords do not match.")
		return
	}
	if len(newPwd) < minPasswordLength || !hasPasswordComplexity(newPwd) {
		rerender(fmt.Sprintf("Password must be at least %d characters and include uppercase, lowercase, digits, and symbols.", minPasswordLength))
		return
	}

	hash, err := uiauth.HashPassword(newPwd)
	if err != nil {
		rerender("Internal error hashing password.")
		return
	}
	if s.setupStore == nil {
		rerender("Setup store not available — cannot save password.")
		return
	}
	if err := s.setupStore.SetSetting(r.Context(), "admin_password_hash", hash); err != nil {
		rerender("Failed to save password.")
		return
	}

	// Grant initial session so they can complete the rest of the wizard.
	sessionToken := generateSessionToken()
	s.mu.Lock()
	s.sessions[sessionToken] = time.Now().Add(sessionTTL)
	s.mu.Unlock()
	s.setSessionCookie(w, sessionToken)

	_ = s.setupStore.SetCurrentStep(r.Context(), 2)
	http.Redirect(w, r, "/setup/step/2", http.StatusFound)
}

// Step 2: UI bind addr.
func (s *Server) handleSetupStep2(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	currentAddr := s.cfg.UI.Addr
	if s.setupStore != nil {
		if v, ok, _ := s.setupStore.GetSetting(r.Context(), "ui_addr"); ok {
			currentAddr = v
		}
	}
	currentHost := s.cfg.UI.Addr
	currentPort := fmt.Sprintf("%d", s.cfg.UI.Port)
	if h, p, err := net.SplitHostPort(currentAddr); err == nil {
		currentHost = h
		currentPort = p
	}
	csrfTok := ""
	if tok, ok := s.getSession(r); ok {
		csrfTok = s.csrfTokenFor(tok)
	}
	body := fmt.Sprintf(`
<p>The UI is currently configured to listen on <code>%s</code>.</p>
<p class="note">Default: 127.0.0.1:9091 (localhost only).</p>
<form action="/setup/step/2" method="post">
  <input type="hidden" name="csrf_token" value="%s">
  <label for="bind_addr">Bind address</label>
  <input id="bind_addr" name="bind_addr" type="text" value="%s">
  <p class="note">Use 127.0.0.1 for localhost-only (recommended).</p>
  <label for="port">Port</label>
  <input id="port" name="port" type="number" min="1024" max="65535" value="%s">
  <button type="submit">Confirm &amp; continue</button>
  <button type="submit" name="skip" value="1" class="secondary">Skip (keep default)</button>
</form>`, html.EscapeString(currentAddr), csrfTok, html.EscapeString(currentHost), html.EscapeString(currentPort))
	renderSetupPage(w, 2, "UI bind address and port", body, "")
}

func (s *Server) handleSetupStep2Post(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if r.FormValue("skip") == "1" {
		if s.setupStore != nil {
			_ = s.setupStore.SetCurrentStep(r.Context(), 3)
		}
		http.Redirect(w, r, "/setup/step/3", http.StatusFound)
		return
	}
	bindAddr := strings.TrimSpace(r.FormValue("bind_addr"))
	port := strings.TrimSpace(r.FormValue("port"))
	if bindAddr == "" || port == "" {
		renderSetupPage(w, 2, "UI bind address and port", "", "Bind address and port are required.")
		return
	}
	addr := bindAddr + ":" + port

	if s.setupStore != nil {
		_ = s.setupStore.SetSetting(r.Context(), "ui_addr", addr)
		_ = s.setupStore.SetCurrentStep(r.Context(), 3)
	}

	// Notify if address changed (requires restart).
	if addr != s.cfg.UI.Addr {
		body := fmt.Sprintf(`<div class="ok">Port/address saved. The change takes effect after a service restart.</div>
<p>Configured address: <code>%s</code></p>
<a href="/setup/step/3"><button>Continue</button></a>`, html.EscapeString(addr))
		renderSetupPage(w, 2, "UI bind address and port", body, "")
		return
	}
	http.Redirect(w, r, "/setup/step/3", http.StatusFound)
}

// Step 3: Cloudflare API token.
func (s *Server) handleSetupStep3(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	csrfTok := ""
	if tok, ok := s.getSession(r); ok {
		csrfTok = s.csrfTokenFor(tok)
	}
	body := fmt.Sprintf(`
<p>Paste your Cloudflare API token below. It will be stored at:</p>
<pre style="background:#f4f7fb;padding:.75rem;border-radius:6px">SQLite credential store</pre>
<p class="note">Stored encrypted in SQLite. The token will not be displayed again.</p>
<p class="note">Required permissions: Zone / Firewall Services / Edit</p>
<form action="/setup/step/3" method="post">
  <input type="hidden" name="csrf_token" value="%s">
  <label for="cf_token">Cloudflare API token</label>
  <input id="cf_token" name="cf_token" type="password" autocomplete="off" required placeholder="cfut_...">
  <label for="zone_id">Zone ID (optional — used to verify zone access)</label>
  <input id="zone_id" name="zone_id" type="text" placeholder="d2f7807c2c5b7c9737da45f538072423" value="%s">
  <button type="submit">Validate &amp; save</button>
  <button type="submit" name="skip" value="1" class="secondary">Skip (configure later)</button>
</form>`, csrfTok, s.cfg.Cloudflare.ZoneID)
	renderSetupPage(w, 3, "Cloudflare API token", body, "")
}

func (s *Server) handleSetupStep3Post(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if r.FormValue("skip") == "1" {
		if s.setupStore != nil {
			_ = s.setupStore.SetCurrentStep(r.Context(), 4)
		}
		http.Redirect(w, r, "/setup/step/4", http.StatusFound)
		return
	}

	cfToken := strings.TrimSpace(r.FormValue("cf_token"))
	zoneID := strings.TrimSpace(r.FormValue("zone_id"))
	if cfToken == "" {
		renderSetupPage(w, 3, "Cloudflare API token", "", "Token is required.")
		return
	}

	validateCF := s.validateCloudflare
	if validateCF == nil {
		validateCF = s.validateCFToken
	}
	if err := validateCF(r.Context(), cfToken, zoneID); err != nil {
		// Strip internal Go error chain; show only the last meaningful segment.
		msg := err.Error()
		if idx := strings.LastIndex(msg, ": "); idx != -1 {
			msg = msg[idx+2:]
		}
		renderSetupPage(w, 3, "Cloudflare API token", "", "Token validation failed: "+msg)
		return
	}

	if s.credentialStore == nil {
		renderSetupPage(w, 3, "Cloudflare API token", "", "Credential store unavailable — cannot save token.")
		return
	}
	if err := s.credentialStore.Set(r.Context(), "cloudflare.api_token", cfToken, true); err != nil {
		renderSetupPage(w, 3, "Cloudflare API token", "", "Failed to store token: "+err.Error())
		return
	}

	if s.setupStore != nil {
		if zoneID != "" {
			_ = s.setupStore.SetSetting(r.Context(), "cf_zone_id", zoneID)
		}
		_ = s.setupStore.SetCurrentStep(r.Context(), 4)
	}

	body := `<div class="ok">✓ Token validated and stored. It will not be displayed again.</div>
<a href="/setup/step/4"><button>Continue</button></a>`
	renderSetupPage(w, 3, "Cloudflare API token", body, "")
}

// Step 4: AbuseIPDB API key (optional).
func (s *Server) handleSetupStep4(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	csrfTok := ""
	if tok, ok := s.getSession(r); ok {
		csrfTok = s.csrfTokenFor(tok)
	}
	body := fmt.Sprintf(`
<p class="note">Optional. Used to report confirmed attacker IPs to AbuseIPDB.</p>
<form action="/setup/step/4" method="post">
  <input type="hidden" name="csrf_token" value="%s">
  <label for="abuseipdb_key">AbuseIPDB API key</label>
  <input id="abuseipdb_key" name="abuseipdb_key" type="password" autocomplete="off" placeholder="paste key here">
  <p class="note">Leave blank to skip. Stored encrypted in SQLite.</p>
  <button type="submit">Validate &amp; save</button>
  <button type="submit" name="skip" value="1" class="secondary">Skip</button>
</form>`, csrfTok)
	renderSetupPage(w, 4, "AbuseIPDB API key (optional)", body, "")
}

func (s *Server) handleSetupStep4Post(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	key := strings.TrimSpace(r.FormValue("abuseipdb_key"))
	if r.FormValue("skip") == "1" || key == "" {
		if s.setupStore != nil {
			_ = s.setupStore.SetCurrentStep(r.Context(), 5)
		}
		http.Redirect(w, r, "/setup/step/5", http.StatusFound)
		return
	}
	validateAbuse := s.validateAbuseIPDB
	if validateAbuse == nil {
		validateAbuse = validateAbuseIPDB
	}
	if err := validateAbuse(r.Context(), key); err != nil {
		renderSetupPage(w, 4, "AbuseIPDB API key (optional)", "", "Validation failed: "+err.Error())
		return
	}
	if s.credentialStore == nil {
		renderSetupPage(w, 4, "AbuseIPDB API key (optional)", "", "Credential store unavailable — cannot save key.")
		return
	}
	if err := s.credentialStore.Set(r.Context(), "abuseipdb.api_key", key, true); err != nil {
		renderSetupPage(w, 4, "AbuseIPDB API key (optional)", "", "Failed to store key: "+err.Error())
		return
	}
	if s.setupStore != nil {
		_ = s.setupStore.SetCurrentStep(r.Context(), 5)
	}
	http.Redirect(w, r, "/setup/step/5", http.StatusFound)
}

// Step 5: BetterStack source token (optional).
func (s *Server) handleSetupStep5(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	csrfTok := ""
	if tok, ok := s.getSession(r); ok {
		csrfTok = s.csrfTokenFor(tok)
	}
	body := fmt.Sprintf(`
<p class="note">Optional. Used to forward structured logs to BetterStack Logs.</p>
<form action="/setup/step/5" method="post">
  <input type="hidden" name="csrf_token" value="%s">
  <label for="bs_token">BetterStack source token</label>
  <input id="bs_token" name="bs_token" type="password" autocomplete="off" placeholder="paste token here">
  <p class="note">Leave blank to skip. Stored encrypted in SQLite.</p>
  <button type="submit">Validate &amp; save</button>
  <button type="submit" name="skip" value="1" class="secondary">Skip</button>
</form>`, csrfTok)
	renderSetupPage(w, 5, "BetterStack source token (optional)", body, "")
}

func (s *Server) handleSetupStep5Post(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	token := strings.TrimSpace(r.FormValue("bs_token"))
	if r.FormValue("skip") == "1" || token == "" {
		if s.setupStore != nil {
			_ = s.setupStore.SetCurrentStep(r.Context(), 6)
		}
		http.Redirect(w, r, "/setup/step/6", http.StatusFound)
		return
	}
	validateBetter := s.validateBetterStack
	if validateBetter == nil {
		validateBetter = validateBetterStack
	}
	if err := validateBetter(r.Context(), token); err != nil {
		renderSetupPage(w, 5, "BetterStack source token (optional)", "", "Validation failed: "+err.Error())
		return
	}
	if s.credentialStore == nil {
		renderSetupPage(w, 5, "BetterStack source token (optional)", "", "Credential store unavailable — cannot save token.")
		return
	}
	if err := s.credentialStore.Set(r.Context(), "betterstack.source_token", token, true); err != nil {
		renderSetupPage(w, 5, "BetterStack source token (optional)", "", "Failed to store token: "+err.Error())
		return
	}
	if s.setupStore != nil {
		_ = s.setupStore.SetCurrentStep(r.Context(), 6)
	}
	http.Redirect(w, r, "/setup/step/6", http.StatusFound)
}

// Step 6: AI provider keys (optional).
func (s *Server) handleSetupStep6(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	csrfTok := ""
	if tok, ok := s.getSession(r); ok {
		csrfTok = s.csrfTokenFor(tok)
	}
	body := fmt.Sprintf(`
<p class="note">Optional. Enable AI-powered explanations for security events.</p>
<form action="/setup/step/6" method="post">
  <input type="hidden" name="csrf_token" value="%s">
  <label for="openai_key">OpenAI API key</label>
  <input id="openai_key" name="openai_key" type="password" autocomplete="off" placeholder="sk-...">
  <label for="anthropic_key">Anthropic API key</label>
  <input id="anthropic_key" name="anthropic_key" type="password" autocomplete="off" placeholder="sk-ant-...">
  <label for="gemini_key">Gemini API key</label>
  <input id="gemini_key" name="gemini_key" type="password" autocomplete="off" placeholder="AIza...">
  <p class="note">Leave all blank to skip. Keys are stored encrypted in SQLite.</p>
  <button type="submit">Save &amp; continue</button>
  <button type="submit" name="skip" value="1" class="secondary">Skip all</button>
</form>`, csrfTok)
	renderSetupPage(w, 6, "AI provider keys (optional)", body, "")
}

func (s *Server) handleSetupStep6Post(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if r.FormValue("skip") == "1" {
		if s.setupStore != nil {
			_ = s.setupStore.SetCurrentStep(r.Context(), 7)
		}
		http.Redirect(w, r, "/setup/step/7", http.StatusFound)
		return
	}
	type aiSecret struct{ field, key, name string }
	secrets := []aiSecret{
		{"openai_key", "ai.openai.api_key", "OPENAI_API_KEY"},
		{"anthropic_key", "ai.anthropic.api_key", "ANTHROPIC_API_KEY"},
		{"gemini_key", "ai.gemini.api_key", "GEMINI_API_KEY"},
	}
	var errs []string
	for _, sec := range secrets {
		val := strings.TrimSpace(r.FormValue(sec.field))
		if val == "" {
			continue
		}
		if s.credentialStore == nil {
			errs = append(errs, fmt.Sprintf("%s: credential store unavailable", sec.name))
			continue
		}
		if err := s.credentialStore.Set(r.Context(), sec.key, val, true); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", sec.name, err))
		}
	}
	if len(errs) > 0 {
		renderSetupPage(w, 6, "AI provider keys (optional)", "", strings.Join(errs, "; "))
		return
	}
	if s.setupStore != nil {
		_ = s.setupStore.SetCurrentStep(r.Context(), 7)
	}
	http.Redirect(w, r, "/setup/step/7", http.StatusFound)
}

// Step 7: CrowdSec LAPI key (optional).
func (s *Server) handleSetupStep7(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	csrfTok := ""
	if tok, ok := s.getSession(r); ok {
		csrfTok = s.csrfTokenFor(tok)
	}

	keyConfigured := false
	if s.credentialStore != nil {
		if _, ok, _ := s.credentialStore.Lookup(r.Context(), crowdSecLAPIKey); ok {
			keyConfigured = true
		}
	}

	det := detect.DetectCrowdSec(s.buildDetectConfig())
	detectedLAPIURL := det.Details["lapi_url"]
	if detectedLAPIURL == string(detect.Missing) {
		detectedLAPIURL = ""
	}
	savedLAPIURL := ""
	if s.setupStore != nil {
		if v, ok, _ := s.setupStore.GetSetting(r.Context(), "crowdsec_lapi_url"); ok {
			savedLAPIURL = v
		}
	}
	lapiURL := savedLAPIURL
	if lapiURL == "" {
		lapiURL = detectedLAPIURL
	}

	var detectionBanner string
	if det.Installed {
		detectionBanner = `<div class="ok">CrowdSec detected on this host.</div>`
	} else {
		detectionBanner = `<div class="note">CrowdSec not detected on this host. You can still configure the LAPI key if CrowdSec is installed elsewhere.</div>`
	}

	var alreadyConfiguredMsg string
	if keyConfigured {
		alreadyConfiguredMsg = `<div class="ok">CrowdSec LAPI key already configured. You can overwrite it below or skip to continue.</div>`
	}

	body := fmt.Sprintf(`
%s
%s
<p class="note">Optional. Provide the CrowdSec LAPI key so the daemon can query blocked IPs from CrowdSec.</p>
<form action="/setup/step/7" method="post">
  <input type="hidden" name="csrf_token" value="%s">
  <label for="lapi_url">CrowdSec LAPI URL</label>
  <input id="lapi_url" name="lapi_url" type="text" value="%s" placeholder="http://127.0.0.1:8080">
  <label for="lapi_key">CrowdSec LAPI key</label>
  <input id="lapi_key" name="lapi_key" type="password" autocomplete="off" placeholder="paste key here">
  <p class="note">Leave blank to skip. Key stored in the encrypted credential store — never displayed again.</p>
  <button type="submit">Save &amp; continue</button>
  <button type="submit" name="skip" value="1" class="secondary">Skip</button>
</form>`, detectionBanner, alreadyConfiguredMsg, csrfTok, html.EscapeString(lapiURL))
	renderSetupPage(w, 7, "CrowdSec LAPI (optional)", body, "")
}

func (s *Server) handleSetupStep7Post(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if r.FormValue("skip") == "1" {
		if s.setupStore != nil {
			_ = s.setupStore.SetCurrentStep(r.Context(), 8)
		}
		http.Redirect(w, r, "/setup/step/8", http.StatusFound)
		return
	}
	lapiKey := strings.TrimSpace(r.FormValue("lapi_key"))
	if lapiKey == "" {
		if s.setupStore != nil {
			_ = s.setupStore.SetCurrentStep(r.Context(), 8)
		}
		http.Redirect(w, r, "/setup/step/8", http.StatusFound)
		return
	}
	if s.credentialStore == nil {
		renderSetupPage(w, 7, "CrowdSec LAPI (optional)", "", "Credential store unavailable — cannot save key.")
		return
	}
	if err := s.credentialStore.Set(r.Context(), crowdSecLAPIKey, lapiKey, true); err != nil {
		renderSetupPage(w, 7, "CrowdSec LAPI (optional)", "", "Failed to store LAPI key: "+err.Error())
		return
	}
	if s.setupStore != nil {
		lapiURL := strings.TrimSpace(r.FormValue("lapi_url"))
		if lapiURL != "" {
			_ = s.setupStore.SetSetting(r.Context(), "crowdsec_lapi_url", lapiURL)
		}
		_ = s.setupStore.SetCurrentStep(r.Context(), 8)
	}
	http.Redirect(w, r, "/setup/step/8", http.StatusFound)
}

// Step 8: Runtime summary.
func (s *Server) handleSetupStep8(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	uiAddr := s.cfg.UI.Addr
	if s.setupStore != nil {
		if v, ok, _ := s.setupStore.GetSetting(r.Context(), "ui_addr"); ok {
			uiAddr = v
		}
	}
	cfState := "(not configured)"
	if s.cfSentinelToken() != "" {
		cfState = "configured (encrypted)"
	}
	dryRun := "true"
	mutationsState := "disabled"
	if s.setupStore != nil {
		if v, ok, _ := s.setupStore.GetSetting(r.Context(), "dry_run"); ok && v == "false" {
			dryRun = "false"
		}
		if v, ok, _ := s.setupStore.GetSetting(r.Context(), "mutations_enabled"); ok && v == "true" {
			mutationsState = "enabled"
		}
	}
	body := fmt.Sprintf(`
<p>Review your configuration before proceeding.</p>
<table style="width:100%%;border-collapse:collapse">
<tr><td style="padding:.4rem .2rem;color:#5f6b7a">UI address</td><td><code>%s</code></td></tr>
<tr><td style="padding:.4rem .2rem;color:#5f6b7a">State directory</td><td><code>%s</code></td></tr>
<tr><td style="padding:.4rem .2rem;color:#5f6b7a">SQLite</td><td><code>%s/runtime.db</code></td></tr>
<tr><td style="padding:.4rem .2rem;color:#5f6b7a">CF token</td><td><code>%s</code></td></tr>
<tr><td style="padding:.4rem .2rem;color:#5f6b7a">Dry-run</td><td><code>%s</code></td></tr>
<tr><td style="padding:.4rem .2rem;color:#5f6b7a">Mutations</td><td><code>%s</code></td></tr>
</table>
<br>
<a href="/setup/step/9"><button>Continue to production mode</button></a>
<a href="/setup/complete" style="margin-left:.5rem"><button class="secondary">Finish without enabling production mode</button></a>
`, uiAddr, s.cfg.StateDir, s.cfg.StateDir, cfState, dryRun, mutationsState)
	results := detect.RunAll(s.buildDetectConfig())
	var sb strings.Builder
	sb.WriteString(`<h3>Detected Environment</h3><div class="kv">`)
	openrestyInstalled := false
	for _, d := range results {
		if d.Name == "openresty" && d.Installed {
			openrestyInstalled = true
		}
	}
	for _, d := range results {
		switch d.Name {
		case "nginx":
			if !d.Installed && openrestyInstalled {
				fmt.Fprintf(&sb, `<div class="row"><span>%s</span><span style="color:#5f6b7a">&#x2139; not installed (OpenResty in use)</span></div>`,
					html.EscapeString(d.Name))
				continue
			}
		case "cloudflare":
			if !d.Configured {
				fmt.Fprintf(&sb, `<div class="row"><span>%s</span><span style="color:#5f6b7a">(not configured — optional)</span></div>`,
					html.EscapeString(d.Name))
				continue
			}
		}
		icon := "&#x2717;"
		if d.Healthy {
			icon = "&#x2713;"
		}
		fmt.Fprintf(&sb, `<div class="row"><span>%s</span><span>%s installed=%v configured=%v</span></div>`,
			html.EscapeString(d.Name), icon, d.Installed, d.Configured)
	}
	sb.WriteString(`</div>`)
	body += sb.String()
	renderSetupPage(w, 8, "Runtime summary", body, "")
}

// Step 9: Enable production mode.
func (s *Server) handleSetupStep9(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	csrfTok := ""
	if tok, ok := s.getSession(r); ok {
		csrfTok = s.csrfTokenFor(tok)
	}
	body := fmt.Sprintf(`
<div class="warn">⚠ Enabling production mode will allow the daemon to write firewall rules to Cloudflare.</div>
<p>By default the service runs in <strong>dry-run mode</strong> with mutations disabled.</p>
<form action="/setup/step/9" method="post">
  <input type="hidden" name="csrf_token" value="%s">
  <label style="display:flex;gap:.5rem;align-items:center;margin:.75rem 0">
    <input type="checkbox" name="enable_production" value="1" style="width:auto">
    I understand this will enable live Cloudflare mutations. Enable production mode now.
  </label>
  <button type="submit">Finish setup</button>
</form>
<p class="note">Or: <a href="/setup/complete">Finish without enabling production mode</a></p>`, csrfTok)
	renderSetupPage(w, 9, "Enable production mode", body, "")
}

func (s *Server) handleSetupStep9Post(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	enableProd := r.FormValue("enable_production") == "1"
	if enableProd {
		if err := checkProductionEnableReady(s.setupStore, s.credentialStore, r.Context()); err != nil {
			renderSetupPage(w, 9, "Enable production mode", "", err.Error())
			return
		}
	}
	if s.setupStore != nil {
		if enableProd {
			_ = s.setupStore.SetSetting(r.Context(), "dry_run", "false")
			_ = s.setupStore.SetSetting(r.Context(), "mutations_enabled", "true")
		}
		_ = s.setupStore.MarkComplete(r.Context())
		s.logger.Info("setup complete — restart cf-sync to enable background orchestration",
			"action", "systemctl restart cf-sync")
	}
	http.Redirect(w, r, "/setup/complete", http.StatusFound)
}

// checkProductionEnableReady validates the minimum prerequisites before the
// operator can enable production mode (live Cloudflare mutations):
//   - CF token must exist in the encrypted credential store
//   - Zone ID must have been configured during step 4
func checkProductionEnableReady(store SetupStorer, credentials CredentialStorer, ctx context.Context) error {
	zoneID := ""
	if store != nil {
		if v, ok, _ := store.GetSetting(ctx, "cf_zone_id"); ok {
			zoneID = strings.TrimSpace(v)
		}
	}
	check := health.CheckProductionReady(health.Config{
		CloudflareTokenConfigured: credentialConfigured(ctx, credentials, "cloudflare.api_token"),
		CloudflareZoneID:          zoneID,
	})
	if check.Status != health.Green {
		return fmt.Errorf("%s", check.Reason)
	}
	return nil
}

// validateCFToken verifies the token is active and can list zones.
func (s *Server) validateCFToken(ctx context.Context, token, zoneID string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	httpCfg := config.HTTPConfig{Timeout: 10 * time.Second}
	t := transport.New(httpclient.New(httpCfg), token)
	d := discovery.New(t)

	tv, err := d.VerifyToken(ctx)
	if err != nil {
		return fmt.Errorf("token verification failed: %w", err)
	}
	if tv.Status != "active" {
		return fmt.Errorf("token status is %q — must be active", tv.Status)
	}
	if zoneID == "" {
		return nil
	}
	zones, err := d.ListZones(ctx)
	if err != nil {
		return fmt.Errorf("cannot list zones (check Zone:Read permission): %w", err)
	}
	for _, z := range zones {
		if z.ID == zoneID {
			return nil
		}
	}
	return fmt.Errorf("zone %q not accessible with this token", zoneID)
}

// validateAbuseIPDB sends a minimal check request. Returns nil on HTTP 200 or 429.
func validateAbuseIPDB(ctx context.Context, key string) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.abuseipdb.com/api/v2/check?ipAddress=127.0.0.1&maxAgeInDays=90", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("API key rejected (HTTP %d)", resp.StatusCode)
	}
	return nil
}

// ValidateAbuseIPDB exposes the setup-wizard AbuseIPDB check for runtime health refreshers.
func ValidateAbuseIPDB(ctx context.Context, key string) error {
	return validateAbuseIPDB(ctx, key)
}

// validateBetterStack sends a test log event. Returns nil on HTTP 202.
func validateBetterStack(ctx context.Context, token string) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	payload := `{"message":"security-automation setup validation","dt":"` + time.Now().UTC().Format(time.RFC3339) + `"}`
	req, err := http.NewRequestWithContext(ctx, "POST", "https://in.logs.betterstack.com", strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("source token rejected (HTTP %d)", resp.StatusCode)
	}
	return nil
}

func (s *Server) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	// Mark setup complete regardless of how the operator reached this page
	// (direct GET link "Finish without enabling production mode" or POST redirect).
	if s.setupStore != nil {
		_ = s.setupStore.MarkComplete(r.Context())
	}
	body := `
<div class="ok">✓ Setup complete. The service is now configured.</div>
<p>Next steps:</p>
<ul>
  <li>Restart the service to apply any port/address changes: <code>sudo systemctl restart cf-sync</code></li>
  <li>To enable production mode later: Settings → Runtime → Enable mutations</li>
  <li>Check service health: <code>curl http://127.0.0.1:9092/healthz</code></li>
</ul>
<a href="/"><button>Go to dashboard</button></a>`
	renderSetupPage(w, 9, "Setup complete", body, "")
}
