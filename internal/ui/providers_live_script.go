package ui

func providersLiveScript() string {
	return `(function(){'use strict';
function shell(){
  return document.querySelector('[data-live-shell="providers"]');
}
function csrfFrom(form){
  var field = form.querySelector('[name="csrf_token"]');
  if(field && field.value){ return field.value; }
  var meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? (meta.getAttribute('content') || '') : '';
}
function setBusy(form, busy){
  var button = form.querySelector('button[type="submit"]');
  if(button){
    button.dataset.liveLabel = button.dataset.liveLabel || button.textContent || '';
    button.disabled = !!busy;
    button.textContent = busy ? 'Working...' : button.dataset.liveLabel;
  }
}
function replaceShellFromHTML(html){
  var doc = new DOMParser().parseFromString(html, 'text/html');
  var fresh = doc.querySelector('[data-live-shell="providers"]');
  var current = shell();
  if(fresh && current){
    current.innerHTML = fresh.innerHTML;
  }
}
function refreshURL(){
  var current = shell();
  if(current && current.dataset && current.dataset.refreshUrl){
    return current.dataset.refreshUrl;
  }
  return '/providers';
}
function refreshProviders(){
  if(refreshProviders.inFlight){ return Promise.resolve(); }
  refreshProviders.inFlight = true;
  var current = shell();
  if(!current){
    refreshProviders.inFlight = false;
    return Promise.resolve();
  }
  current.classList.add('is-refreshing');
  return fetch(refreshURL(), {
    credentials: 'same-origin',
    headers: {
      'X-Live-Refresh': 'providers'
    }
  }).then(function(resp){
    if(!resp.ok){ throw new Error('refresh failed'); }
    return resp.text();
  }).then(replaceShellFromHTML).catch(function(){}).finally(function(){
    var after = shell();
    if(after){ after.classList.remove('is-refreshing'); }
    refreshProviders.inFlight = false;
  });
}
refreshProviders.inFlight = false;
function toast(message, kind){
  var el = document.createElement('div');
  el.className = 'v2-toast';
  el.textContent = message;
  if(kind === 'error'){ el.style.borderColor = 'rgba(239,95,107,.4)'; }
  document.body.appendChild(el);
  window.setTimeout(function(){ el.remove(); }, 2200);
}
document.addEventListener('submit', function(ev){
  var form = ev.target;
  if(!form || !form.matches || !form.matches('[data-live-provider-form="true"]')){ return; }
  ev.preventDefault();
  setBusy(form, true);
  var body = new URLSearchParams();
  new FormData(form).forEach(function(value, key){
    body.set(key, value);
  });
  fetch(form.action || '/providers', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
      'X-CSRF-Token': csrfFrom(form)
    },
    body: body.toString()
  }).then(function(resp){
    return resp.text().then(function(text){ return {ok: resp.ok, text: text}; }, function(){ return {ok: resp.ok, text: ''}; });
  }).then(function(result){
    if(!result.ok){
      throw new Error('request failed');
    }
    return refreshProviders();
  }).then(function(){
    if(window.__securityAutomationLive && window.__securityAutomationLive.toast){
      window.__securityAutomationLive.toast('Provider action saved', 'success');
    } else {
      toast('Provider action saved', 'success');
    }
  }).catch(function(){
    if(window.__securityAutomationLive && window.__securityAutomationLive.toast){
      window.__securityAutomationLive.toast('Provider action failed', 'error');
    } else {
      toast('Provider action failed', 'error');
    }
  }).finally(function(){
    setBusy(form, false);
  });
});
document.addEventListener('click', function(ev){
  var button = ev.target && ev.target.closest ? ev.target.closest('[data-copy-diagnostic]') : null;
  if(!button){ return; }
  var payload = button.getAttribute('data-copy-diagnostic') || '{}';
  function copied(){
    button.dataset.liveLabel = button.dataset.liveLabel || button.textContent || 'Copy diagnostic JSON';
    button.textContent = 'Copied';
    window.setTimeout(function(){ button.textContent = button.dataset.liveLabel; }, 1400);
    toast('Diagnostic JSON copied', 'success');
  }
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(payload).then(copied, function(){ toast('Copy failed', 'error'); });
  } else {
    var text = document.createElement('textarea');
    text.value = payload;
    text.style.position = 'fixed';
    text.style.left = '-9999px';
    document.body.appendChild(text);
    text.select();
    try {
      document.execCommand('copy');
      copied();
    } catch(e) {
      toast('Copy failed', 'error');
    }
    text.remove();
  }
});
refreshProviders();
var timer = window.setInterval(function(){
  if(document.visibilityState === 'visible'){
    refreshProviders();
  }
}, 10000);
window.addEventListener('focus', refreshProviders);
document.addEventListener('visibilitychange', function(){
  if(document.visibilityState === 'visible'){
    refreshProviders();
  }
});
window.addEventListener('beforeunload', function(){
  window.clearInterval(timer);
});
})();`
}
