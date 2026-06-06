package ui

import (
	"fmt"
	"net/http"
	"strings"

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
		if strings.HasPrefix(r.URL.Path, "/setup") {
			next.ServeHTTP(w, r)
			return
		}
		complete, err := s.setupStore.IsComplete(r.Context())
		if err != nil || !complete {
			step := 1
			if st, e := s.setupStore.GetCurrentStep(r.Context()); e == nil {
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
		fmt.Fprintf(w, `<div class="error">%s</div>`, errorMsg)
	}
	fmt.Fprint(w, bodyHTML)
	fmt.Fprint(w, `</main></body></html>`)
}

// Step 1: Show the initial setup password location and redirect to /login.
func (s *Server) handleSetupStep1(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); ok {
		http.Redirect(w, r, "/setup/step/2", http.StatusFound)
		return
	}
	body := fmt.Sprintf(`
<p class="note">A one-time setup password was written to:</p>
<pre style="background:#f4f7fb;padding:.75rem;border-radius:6px;overflow:auto">%s</pre>
<p class="note">Read it with: <code>cat %s</code></p>
<form action="/login" method="post">
  <label for="secret">Setup password</label>
  <input id="secret" name="secret" type="password" autocomplete="current-password" required>
  <button type="submit">Continue</button>
</form>`, s.cfg.UI.InitialPasswordFile, s.cfg.UI.InitialPasswordFile)
	renderSetupPage(w, 1, "Login with setup password", body, "")
}

// Step 2 GET: force password change form.
func (s *Server) handleSetupStep2(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	csrfToken := ""
	if tok, ok := s.getSession(r); ok {
		csrfToken = s.csrfTokenFor(tok)
	}
	body := fmt.Sprintf(`
<p>Choose a strong admin password. It will be stored as a bcrypt hash.</p>
<form action="/setup/step/2" method="post">
  <input type="hidden" name="csrf_token" value="%s">
  <label for="current">Current setup password</label>
  <input id="current" name="current_password" type="password" required>
  <label for="new">New password (min 16 chars, upper+lower+digit+symbol)</label>
  <input id="new" name="new_password" type="password" required>
  <label for="confirm">Confirm new password</label>
  <input id="confirm" name="confirm_password" type="password" required>
  <button type="submit">Set password &amp; continue</button>
</form>`, csrfToken)
	renderSetupPage(w, 2, "Set admin password", body, "")
}

// Step 2 POST: verify current password, hash and store new password, invalidate initial password.
func (s *Server) handleSetupStep2Post(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Redirect(w, r, "/setup/step/1", http.StatusFound)
		return
	}
	if !s.validCSRF(r) {
		renderSetupPage(w, 2, "Set admin password", "", "CSRF token invalid — refresh and try again.")
		return
	}

	currentPwd := r.FormValue("current_password")
	newPwd := r.FormValue("new_password")
	confirmPwd := r.FormValue("confirm_password")

	csrfToken := ""
	if tok, ok := s.getSession(r); ok {
		csrfToken = s.csrfTokenFor(tok)
	}
	rerender := func(errMsg string) {
		body := fmt.Sprintf(`<form action="/setup/step/2" method="post">
  <input type="hidden" name="csrf_token" value="%s">
  <label>Current setup password</label><input name="current_password" type="password" required>
  <label>New password</label><input name="new_password" type="password" required>
  <label>Confirm</label><input name="confirm_password" type="password" required>
  <button type="submit">Set password &amp; continue</button>
</form>`, csrfToken)
		renderSetupPage(w, 2, "Set admin password", body, errMsg)
	}

	if newPwd != confirmPwd {
		rerender("Passwords do not match.")
		return
	}
	if len(newPwd) < minPasswordLength || !hasPasswordComplexity(newPwd) {
		rerender(fmt.Sprintf("Password must be at least %d characters and include uppercase, lowercase, digits, and symbols.", minPasswordLength))
		return
	}

	// Verify current password — accept either the initial file password or existing bcrypt hash.
	currentOK := uiauth.VerifyInitialPassword(s.cfg.UI.InitialPasswordFile, currentPwd)
	if !currentOK {
		state, _ := uiauth.GetBootstrapState(s.cfg.UI.AdminPasswordFile)
		currentOK = uiauth.VerifyPassword(state.PasswordHash, currentPwd)
	}
	if !currentOK {
		rerender("Current password is incorrect.")
		return
	}

	hash, err := uiauth.HashPassword(newPwd)
	if err != nil {
		rerender("Internal error hashing password.")
		return
	}
	newState := uiauth.BootstrapState{IsBootstrap: false, PasswordHash: hash}
	if err := uiauth.SaveBootstrapState(s.cfg.UI.AdminPasswordFile, newState); err != nil {
		rerender("Failed to save password.")
		return
	}

	_ = uiauth.InvalidateInitialPassword(s.cfg.UI.InitialPasswordFile)

	if s.setupStore != nil {
		_ = s.setupStore.SetCurrentStep(r.Context(), 3)
	}
	http.Redirect(w, r, "/setup/step/3", http.StatusFound)
}

// Steps 3-9 and complete are implemented in subsequent tasks.
// Placeholder handlers so the build passes.

func (s *Server) handleSetupStep3(w http.ResponseWriter, r *http.Request) {
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
	csrfTok := ""
	if tok, ok := s.getSession(r); ok {
		csrfTok = s.csrfTokenFor(tok)
	}
	body := fmt.Sprintf(`
<p>The UI is currently configured to listen on <code>%s</code>.</p>
<p class="note">Default: 127.0.0.1:9091 (localhost only).</p>
<form action="/setup/step/3" method="post">
  <input type="hidden" name="csrf_token" value="%s">
  <label for="bind_addr">Bind address</label>
  <input id="bind_addr" name="bind_addr" type="text" value="%s">
  <p class="note">Use 127.0.0.1 for localhost-only (recommended).</p>
  <label for="port">Port</label>
  <input id="port" name="port" type="number" min="1024" max="65535" value="%d">
  <button type="submit">Confirm &amp; continue</button>
  <button type="submit" name="skip" value="1" class="secondary">Skip (keep default)</button>
</form>`, currentAddr, csrfTok, s.cfg.UI.Addr, s.cfg.UI.Port)
	renderSetupPage(w, 3, "UI bind address and port", body, "")
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
	bindAddr := strings.TrimSpace(r.FormValue("bind_addr"))
	port := strings.TrimSpace(r.FormValue("port"))
	if bindAddr == "" || port == "" {
		renderSetupPage(w, 3, "UI bind address and port", "", "Bind address and port are required.")
		return
	}
	addr := bindAddr + ":" + port

	if s.setupStore != nil {
		_ = s.setupStore.SetSetting(r.Context(), "ui_addr", addr)
		_ = s.setupStore.SetCurrentStep(r.Context(), 4)
	}

	// Notify if address changed (requires restart).
	if addr != s.cfg.UI.Addr {
		body := fmt.Sprintf(`<div class="ok">Port/address saved. The change takes effect after a service restart.</div>
<p>Configured address: <code>%s</code></p>
<a href="/setup/step/4"><button>Continue</button></a>`, addr)
		renderSetupPage(w, 3, "UI bind address and port", body, "")
		return
	}
	http.Redirect(w, r, "/setup/step/4", http.StatusFound)
}
func (s *Server) handleSetupStep4(w http.ResponseWriter, r *http.Request) {
	renderSetupPage(w, 4, "Cloudflare API token", "<p>Coming soon.</p>", "")
}
func (s *Server) handleSetupStep4Post(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/setup/step/5", http.StatusFound)
}
func (s *Server) handleSetupStep5(w http.ResponseWriter, r *http.Request) {
	renderSetupPage(w, 5, "AbuseIPDB API key (optional)", "<p>Coming soon.</p>", "")
}
func (s *Server) handleSetupStep5Post(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/setup/step/6", http.StatusFound)
}
func (s *Server) handleSetupStep6(w http.ResponseWriter, r *http.Request) {
	renderSetupPage(w, 6, "BetterStack source token (optional)", "<p>Coming soon.</p>", "")
}
func (s *Server) handleSetupStep6Post(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/setup/step/7", http.StatusFound)
}
func (s *Server) handleSetupStep7(w http.ResponseWriter, r *http.Request) {
	renderSetupPage(w, 7, "AI provider keys (optional)", "<p>Coming soon.</p>", "")
}
func (s *Server) handleSetupStep7Post(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/setup/step/8", http.StatusFound)
}
func (s *Server) handleSetupStep8(w http.ResponseWriter, r *http.Request) {
	renderSetupPage(w, 8, "Runtime summary", "<p>Coming soon.</p>", "")
}
func (s *Server) handleSetupStep9(w http.ResponseWriter, r *http.Request) {
	renderSetupPage(w, 9, "Enable production mode", "<p>Coming soon.</p>", "")
}
func (s *Server) handleSetupStep9Post(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/setup/complete", http.StatusFound)
}
func (s *Server) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	renderSetupPage(w, 9, "Setup complete", `<div class="ok">Setup complete.</div><a href="/"><button>Go to dashboard</button></a>`, "")
}
