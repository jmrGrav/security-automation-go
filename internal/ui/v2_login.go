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
		// id="v2-login-error" is read by the fetch handler to extract error text without a page reload.
		errHTML = `<div id="v2-login-error" style="color:#f08591;font:500 13px 'JetBrains Mono',monospace;margin-bottom:16px;padding:10px 14px;border:1px solid rgba(239,95,107,0.24);border-radius:8px;background:rgba(239,95,107,0.08)">` + errMsg + `</div>`
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
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes spinrev{to{transform:rotate(-360deg)}}
@keyframes halo{0%{transform:scale(.6);opacity:.5}100%{transform:scale(2.6);opacity:0}}
@keyframes beat{0%,100%{transform:scale(.82);opacity:.65}50%{transform:scale(1.12);opacity:1}}
@keyframes shimmer{0%{transform:translateX(-120%)}100%{transform:translateX(420%)}}
@keyframes floaty{0%,100%{transform:rotate(45deg) scale(1)}50%{transform:rotate(45deg) scale(1.12)}}
#v2-loader{display:none;position:fixed;inset:0;z-index:999;align-items:center;justify-content:center;background:radial-gradient(120% 120% at 50% 38%,#14161f 0%,#0c0e15 55%,#090a10 100%)}
</style>
</head>
<body>

<!-- Loader overlay (shown on form submit) -->
<div id="v2-loader">
  <div style="display:flex;flex-direction:column;align-items:center">
    <!-- animated mark -->
    <div style="position:relative;width:220px;height:190px">
      <div style="position:absolute;left:30px;top:20px;width:160px;height:160px;border-radius:50%;border:1px solid rgba(255,255,255,.06)"></div>
      <div style="position:absolute;left:24px;top:14px;width:172px;height:172px;border-radius:50%;border:1.5px solid transparent;border-top-color:#7c6cf2;opacity:.85;animation:spin 1.6s linear infinite"></div>
      <div style="position:absolute;left:34px;top:24px;width:152px;height:152px;border-radius:50%;border:1.5px solid transparent;border-bottom-color:rgba(245,146,30,.7);animation:spinrev 2.4s linear infinite"></div>
      <!-- center diamond -->
      <div style="position:absolute;left:101px;top:91px;width:18px;height:18px;background:linear-gradient(135deg,#aa9cff,#7c6cf2);border-radius:4px;animation:floaty 2s ease-in-out infinite;box-shadow:0 0 18px rgba(124,108,242,.6)"></div>
      <!-- Cloudflare node (top, orange) -->
      <div style="position:absolute;left:97px;top:7px;width:26px;height:26px">
        <div style="position:absolute;inset:0;border-radius:50%;background:#f5921e;animation:halo 1.8s ease-out infinite"></div>
        <div style="position:absolute;inset:0;border-radius:50%;background:radial-gradient(circle at 35% 30%,#ffb45a,#f5921e);box-shadow:0 0 14px rgba(245,146,30,.7);animation:beat 1.8s ease-in-out infinite"></div>
      </div>
      <!-- CrowdSec node (bottom-right, indigo) -->
      <div style="position:absolute;left:166px;top:127px;width:26px;height:26px">
        <div style="position:absolute;inset:0;border-radius:50%;background:#7c6cf2;animation:halo 1.8s ease-out infinite .6s"></div>
        <div style="position:absolute;inset:0;border-radius:50%;background:radial-gradient(circle at 35% 30%,#a99cff,#7c6cf2);box-shadow:0 0 14px rgba(124,108,242,.7);animation:beat 1.8s ease-in-out infinite .6s"></div>
      </div>
      <!-- OpenResty node (bottom-left, green) -->
      <div style="position:absolute;left:27px;top:127px;width:26px;height:26px">
        <div style="position:absolute;inset:0;border-radius:50%;background:#4cc79a;animation:halo 1.8s ease-out infinite 1.2s"></div>
        <div style="position:absolute;inset:0;border-radius:50%;background:radial-gradient(circle at 35% 30%,#7fe0bd,#4cc79a);box-shadow:0 0 14px rgba(76,199,154,.7);animation:beat 1.8s ease-in-out infinite 1.2s"></div>
      </div>
    </div>
    <!-- wordmark -->
    <div style="display:flex;align-items:center;gap:9px;margin-top:18px">
      <span style="width:9px;height:9px;border-radius:50%;background:#7c6cf2;box-shadow:0 0 10px #7c6cf2"></span>
      <span style="font:800 17px 'Hanken Grotesk',sans-serif;letter-spacing:.18em;color:#eef0f6">OPERATOR</span>
    </div>
    <!-- status line -->
    <div id="v2-loader-status" style="height:18px;margin-top:12px;font:500 12px 'JetBrains Mono',monospace;color:#9aa0b2;letter-spacing:.02em"></div>
    <!-- shimmer progress bar -->
    <div style="position:relative;width:240px;height:3px;border-radius:3px;background:rgba(255,255,255,.07);overflow:hidden;margin-top:14px">
      <div style="position:absolute;top:0;left:0;height:100%;width:40%;border-radius:3px;background:linear-gradient(90deg,transparent,#7c6cf2,#a99cff,transparent);animation:shimmer 1.4s ease-in-out infinite"></div>
    </div>
    <!-- provider legend -->
    <div style="display:flex;gap:18px;margin-top:22px">
      <span style="display:inline-flex;align-items:center;gap:7px;font:500 11px 'Hanken Grotesk',sans-serif;color:#7b8196"><span style="width:7px;height:7px;border-radius:50%;background:#f5921e"></span>Cloudflare</span>
      <span style="display:inline-flex;align-items:center;gap:7px;font:500 11px 'Hanken Grotesk',sans-serif;color:#7b8196"><span style="width:7px;height:7px;border-radius:50%;background:#7c6cf2"></span>CrowdSec</span>
      <span style="display:inline-flex;align-items:center;gap:7px;font:500 11px 'Hanken Grotesk',sans-serif;color:#7b8196"><span style="width:7px;height:7px;border-radius:50%;background:#4cc79a"></span>OpenResty · Lua</span>
    </div>
  </div>
</div>

<div class="card">
  <div class="logo">
    <span class="logo-dot"></span>
    <span class="logo-text">OPERATOR CONSOLE</span>
  </div>
  <span class="badge"><span class="badge-dot"></span>v2 preview</span>
  <h1>Sign in</h1>
  <p class="subtitle">Security automation dashboard</p>
  ` + errHTML + `
  <!-- JS error box (shown inline without reload on failed fetch) -->
  <div id="v2-err-box" style="display:none;color:#f08591;font:500 13px 'JetBrains Mono',monospace;margin-bottom:16px;padding:10px 14px;border:1px solid rgba(239,95,107,0.24);border-radius:8px;background:rgba(239,95,107,0.08)"></div>
  <form id="v2-login-form" method="POST" action="/v2/login">
    <label>Password</label>
    <input type="password" name="password" autofocus autocomplete="current-password" placeholder="Admin password">
    <button type="submit">Continue →</button>
  </form>
  <div class="v1-link">Looking for <a href="/login">the classic UI?</a></div>
</div>

<script>
(function(){
  'use strict';
  var msgs=[
    'connecting cloudflare edge…',
    'loading crowdsec decisions…',
    'starting openresty \xb7 lua…',
    'verifying event pipeline…',
    'loading dashboard…'
  ];
  var loader=document.getElementById('v2-loader');
  var statusEl=document.getElementById('v2-loader-status');
  var errBox=document.getElementById('v2-err-box');
  var form=document.getElementById('v2-login-form');
  var timer;

  function startCycle(){
    var step=0;
    statusEl.textContent=msgs[step];
    timer=setInterval(function(){step=(step+1)%(msgs.length-1);statusEl.textContent=msgs[step];},1100);
  }
  function stopCycle(msg){ clearInterval(timer); if(msg) statusEl.textContent=msg; }
  function showErr(msg){ loader.style.display='none'; errBox.textContent=msg; errBox.style.display='block'; }

  form.addEventListener('submit',function(e){
    e.preventDefault();
    errBox.style.display='none';
    loader.style.display='flex';
    startCycle();

    var body=new URLSearchParams(new FormData(form)).toString();
    fetch('/v2/login',{
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:body,
      credentials:'same-origin',
      redirect:'follow'
    }).then(function(r){
      if(r.ok){
        // Auth succeeded — prefetch JS bundles the dashboard needs so first paint is instant
        stopCycle(msgs[msgs.length-1]);
        return Promise.all([
          fetch('/v2/static/attack-map.js',{credentials:'same-origin'}),
          fetch('/v2/static/palette.js',{credentials:'same-origin'})
        ]).catch(function(){}).then(function(){ window.location.href='/v2/'; });
      }
      // Auth failed — parse error from server response without a full reload
      return r.text().then(function(html){
        var doc=new DOMParser().parseFromString(html,'text/html');
        var el=doc.getElementById('v2-login-error');
        showErr(el?el.textContent.trim():'Invalid password.');
      }).catch(function(){ showErr('Authentication failed.'); });
    }).catch(function(){ showErr('Connection error. Please try again.'); });
  });
})();
</script>
</body>
</html>`
}
