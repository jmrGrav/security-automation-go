package ui

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jm/security-automation-go/internal/ui/auth"
)

// handleV2LoginPage serves GET /v2/login.
// If the user already has a valid session, redirects to /v2/.
func (s *Server) handleV2LoginPage(w http.ResponseWriter, r *http.Request) {
	if s.isAuthed(r) {
		http.Redirect(w, r, "/v2/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, v2LoginPage(""))
}

// handleV2Login processes POST /v2/login.
func (s *Server) handleV2Login(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.Allow(clientKey(r)) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	password := r.PostForm.Get("password")
	if password == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, v2LoginPage("Password required."))
		return
	}
	if s.setupStore == nil {
		http.Error(w, "not configured", http.StatusServiceUnavailable)
		return
	}
	hash, ok, err := s.setupStore.GetSetting(r.Context(), "admin_password_hash")
	if err != nil || !ok || hash == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, v2LoginPage("Setup not complete."))
		return
	}
	if !auth.VerifyPassword(hash, password) {
		eventID := newUIEventID()
		s.auditRecord("login_failed", map[string]string{
			"actor":          "local",
			"source":         "ui_v2",
			"target":         "ui_session",
			"result":         "invalid_password",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, v2LoginPage("Invalid password."))
		return
	}

	sessionToken := generateSessionToken()
	s.mu.Lock()
	s.sessions[sessionToken] = time.Now().Add(sessionTTL)
	s.pruneSessionsLocked(time.Now().UTC())
	s.mu.Unlock()
	s.setSessionCookie(w, sessionToken)

	eventID := newUIEventID()
	s.auditRecord("login_success", map[string]string{
		"actor":          "local",
		"source":         "ui_v2",
		"target":         "ui_session",
		"result":         "success",
		"correlation_id": eventID,
		"event_id":       eventID,
	})
	http.Redirect(w, r, "/v2/", http.StatusFound)
}

func v2LoginPage(errMsg string) string {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div style="color:#f08591;font:500 13px 'JetBrains Mono',monospace;margin-bottom:16px;padding:10px 14px;border:1px solid rgba(239,95,107,0.24);border-radius:8px;background:rgba(239,95,107,0.08)">` + errMsg + `</div>`
	}
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Operator Console</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Hanken+Grotesk:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box}
body{margin:0;background:#0d0f14;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:'Hanken Grotesk',system-ui,sans-serif}
.card{background:#13151c;border:1px solid #242838;border-radius:14px;padding:40px 36px;width:100%;max-width:380px;box-shadow:0 16px 48px rgba(0,0,0,.4)}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:32px}
.logo-dot{width:10px;height:10px;border-radius:50%;background:#7c6cf2;box-shadow:0 0 12px #7c6cf2}
.logo-text{font:700 15px 'JetBrains Mono',monospace;color:#c5cad8;letter-spacing:.04em}
h1{font:700 22px 'Hanken Grotesk',sans-serif;color:#eef0f6;margin:0 0 6px}
.subtitle{font:400 13px 'Hanken Grotesk',sans-serif;color:#6b7184;margin:0 0 28px}
label{display:block;font:600 11px 'JetBrains Mono',monospace;color:#7b8196;letter-spacing:.06em;text-transform:uppercase;margin-bottom:7px}
input[type=password]{width:100%;background:#10121a;border:1px solid #20242f;border-radius:8px;padding:11px 14px;color:#eef0f6;font:500 14px 'JetBrains Mono',monospace;outline:none;transition:border-color .15s}
input[type=password]:focus{border-color:#7c6cf2}
button{width:100%;margin-top:16px;background:#7c6cf2;border:none;border-radius:8px;padding:12px;color:#fff;font:700 14px 'Hanken Grotesk',sans-serif;cursor:pointer;transition:background .15s}
button:hover{background:#8e81f5}
.v1-link{margin-top:20px;text-align:center;font:500 12px 'Hanken Grotesk',sans-serif;color:#5b6070}
.v1-link a{color:#7c6cf2;text-decoration:none}
.v1-link a:hover{text-decoration:underline}
.badge{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:5px;background:rgba(124,108,242,.12);border:1px solid rgba(124,108,242,.22);font:500 11px 'JetBrains Mono',monospace;color:#9b8cff;margin-bottom:24px}
.badge-dot{width:6px;height:6px;border-radius:50%;background:#4cc79a;animation:livepulse 1.8s infinite}
@keyframes livepulse{0%,100%{opacity:1}50%{opacity:.35}}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <span class="logo-dot"></span>
    <span class="logo-text">OPERATOR CONSOLE</span>
  </div>
  <span class="badge"><span class="badge-dot"></span>v2 preview</span>
  <h1>Sign in</h1>
  <p class="subtitle">Security automation dashboard</p>
  ` + errHTML + `
  <form method="POST" action="/v2/login">
    <label>Password</label>
    <input type="password" name="password" autofocus autocomplete="current-password" placeholder="Admin password">
    <button type="submit">Continue →</button>
  </form>
  <div class="v1-link">Looking for <a href="/login">the classic UI?</a></div>
</div>
</body>
</html>`
}
