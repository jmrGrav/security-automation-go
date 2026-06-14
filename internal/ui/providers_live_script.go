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
function refreshProviders(){
  if(refreshProviders.inFlight){ return Promise.resolve(); }
  refreshProviders.inFlight = true;
  var current = shell();
  if(!current){
    refreshProviders.inFlight = false;
    return Promise.resolve();
  }
  return fetch('/providers', {
    credentials: 'same-origin',
    headers: {
      'X-Live-Refresh': 'providers'
    }
  }).then(function(resp){
    if(!resp.ok){ throw new Error('refresh failed'); }
    return resp.text();
  }).then(replaceShellFromHTML).catch(function(){}).finally(function(){
    refreshProviders.inFlight = false;
  });
}
refreshProviders.inFlight = false;
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
    replaceShellFromHTML(result.text);
    if(window.__securityAutomationLive && window.__securityAutomationLive.toast){
      window.__securityAutomationLive.toast('Provider action saved', 'success');
    }
  }).catch(function(){
    if(window.__securityAutomationLive && window.__securityAutomationLive.toast){
      window.__securityAutomationLive.toast('Provider action failed', 'error');
    }
  }).finally(function(){
    setBusy(form, false);
  });
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
