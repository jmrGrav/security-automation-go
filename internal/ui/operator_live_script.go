package ui

func operatorLiveScript() string {
	return `(function(){'use strict';
var state = window.__securityAutomationLive || (window.__securityAutomationLive = {});
function shell(){ return document.querySelector('[data-live-shell]'); }
function panelRoot(){ return document.querySelector('[data-live-panel-root]'); }
function panelTitle(){ return panelRoot() ? panelRoot().querySelector('[data-live-panel-title]') : null; }
function panelBody(){ return panelRoot() ? panelRoot().querySelector('[data-live-panel-body]') : null; }
function panelError(message, url){
  var box = document.createElement('div');
  box.className = 'empty';
  var text = document.createElement('p');
  text.textContent = message || 'Unable to load live details.';
  box.appendChild(text);
  if(url){
    var link = document.createElement('a');
    link.className = 'badge live';
    link.href = url;
    link.textContent = 'Open full page';
    box.appendChild(link);
  }
  return box;
}
function shellSelector(node){
  if(!node){ return '[data-live-shell]'; }
  var name = node.getAttribute('data-live-shell');
  return name ? '[data-live-shell="' + name + '"]' : '[data-live-shell]';
}
function toastRegion(){
  var region = document.querySelector('[data-live-toast-region]');
  if(region){ return region; }
  region = document.createElement('div');
  region.setAttribute('data-live-toast-region', 'true');
  region.className = 'live-toast-region';
  document.body.appendChild(region);
  return region;
}
function showToast(message, level){
  if(!message){ return; }
  var region = toastRegion();
  var item = document.createElement('div');
  item.className = 'toast ' + (level || 'info');
  item.textContent = message;
  region.appendChild(item);
  window.setTimeout(function(){
    item.classList.add('dismissed');
    window.setTimeout(function(){ if(item.parentNode){ item.parentNode.removeChild(item); } }, 200);
  }, 2200);
}
function storageGet(key){
  try { return window.localStorage ? window.localStorage.getItem(key) : ''; } catch(e){ return ''; }
}
function storageSet(key, value){
  try {
    if(window.localStorage){ window.localStorage.setItem(key, value); }
  } catch(e){}
}
function applyDensityPreference(){
  var compact = storageGet('security-automation:density') === 'compact';
  if(document.body){
    if(compact){ document.body.setAttribute('data-density', 'compact'); }
    else { document.body.removeAttribute('data-density'); }
  }
  document.querySelectorAll('[data-density-toggle="true"]').forEach(function(button){
    button.setAttribute('aria-pressed', compact ? 'true' : 'false');
    button.textContent = compact ? 'Comfort mode' : 'Compact mode';
  });
}
function bindDensityToggle(){
  if(state.densityToggleBound === 'true'){ return; }
  state.densityToggleBound = 'true';
  document.addEventListener('click', function(ev){
    var button = ev.target && ev.target.closest ? ev.target.closest('[data-density-toggle="true"]') : null;
    if(!button){ return; }
    ev.preventDefault();
    var compact = document.body && document.body.getAttribute('data-density') === 'compact';
    storageSet('security-automation:density', compact ? 'comfort' : 'compact');
    applyDensityPreference();
  });
}
function setCollapsiblePanel(panel, collapsed){
  if(!panel){ return; }
  panel.setAttribute('data-collapsed', collapsed ? 'true' : 'false');
  var button = panel.querySelector('[data-collapsible-toggle="true"]');
  if(button){
    button.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    button.textContent = collapsed ? 'Expand' : 'Collapse';
  }
}
function applyCollapsiblePanels(){
  document.querySelectorAll('[data-collapsible-panel="true"]').forEach(function(panel){
    var key = panel.getAttribute('data-collapsible-key');
    var stored = key ? storageGet('security-automation:collapsed:' + key) : '';
    setCollapsiblePanel(panel, stored ? stored === 'true' : panel.getAttribute('data-collapsed') === 'true');
  });
}
function bindCollapsiblePanels(){
  applyCollapsiblePanels();
  if(state.collapsiblePanelsBound === 'true'){ return; }
  state.collapsiblePanelsBound = 'true';
  document.addEventListener('click', function(ev){
    var button = ev.target && ev.target.closest ? ev.target.closest('[data-collapsible-toggle="true"]') : null;
    if(!button){ return; }
    var panel = button.closest('[data-collapsible-panel="true"]');
    if(!panel){ return; }
    ev.preventDefault();
    var collapsed = panel.getAttribute('data-collapsed') !== 'true';
    var key = panel.getAttribute('data-collapsible-key');
    if(key){ storageSet('security-automation:collapsed:' + key, collapsed ? 'true' : 'false'); }
    setCollapsiblePanel(panel, collapsed);
  });
}
function escapeHTML(text){
  return String(text || '').replace(/[&<>"']/g, function(ch){
    return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]);
  });
}
function panelSkeleton(title){
  return '<div class="live-panel-skeleton">' +
    '<div class="skeleton-line wide"></div>' +
    '<div class="skeleton-line"></div>' +
    '<div class="skeleton-line"></div>' +
    '<div class="skeleton-line narrow"></div>' +
    (title ? '<p class="muted" style="margin-top:.85rem">' + escapeHTML(title) + '</p>' : '') +
    '</div>';
}
function flashNode(node){
  if(!node){ return; }
  node.classList.remove('shell-updated');
  window.requestAnimationFrame(function(){
    node.classList.add('shell-updated');
    window.setTimeout(function(){ node.classList.remove('shell-updated'); }, 280);
  });
}
function updateRelativeTimes(){
  document.querySelectorAll('[data-live-relative-time]').forEach(function(node){
    var iso = node.getAttribute('data-live-relative-time');
    if(!iso){ return; }
    var then = new Date(iso);
    if(isNaN(then.getTime())){ return; }
    var diff = Math.max(0, Math.floor((Date.now() - then.getTime()) / 1000));
    var text;
    if(diff < 5){
      text = 'just now';
    } else if(diff < 60){
      text = diff + 's ago';
    } else if(diff < 3600){
      text = Math.floor(diff / 60) + 'm ago';
    } else {
      text = Math.floor(diff / 3600) + 'h ago';
    }
    node.textContent = text;
  });
}
function pulseKPIs(node){
  if(!node){ return; }
  var targets = node.querySelectorAll('[data-live-kpi]');
  if(!targets.length){ return; }
  targets.forEach(function(el){
    el.classList.remove('kpi-pop');
    window.requestAnimationFrame(function(){
      el.classList.add('kpi-pop');
      window.setTimeout(function(){ el.classList.remove('kpi-pop'); }, 300);
    });
  });
}
function refreshShellNode(node){
  if(!node || node.dataset.liveRefreshing === 'true'){ return Promise.resolve(false); }
  var url = node.getAttribute('data-live-refresh-url');
  if(!url){ return Promise.resolve(false); }
  node.dataset.liveRefreshing = 'true';
  node.classList.add('shell-refreshing');
  return fetch(url, {
    credentials: 'same-origin',
    headers: { 'X-Live-Refresh': node.getAttribute('data-live-shell') || 'shell' }
  }).then(function(resp){
    if(!resp.ok){ throw new Error('refresh failed'); }
    return resp.text();
  }).then(function(html){
    var doc = new DOMParser().parseFromString(html, 'text/html');
    var fresh = doc.querySelector(shellSelector(node));
    if(fresh){
      node.innerHTML = fresh.innerHTML;
      initPanelShell();
      bindCopyButtons();
      bindSearchForms();
      applyDensityPreference();
      bindCollapsiblePanels();
      updateRelativeTimes();
      pulseKPIs(node);
      flashNode(node);
      return true;
    }
    return false;
  }).catch(function(){
    return false;
  }).finally(function(){
    node.dataset.liveRefreshing = 'false';
    node.classList.remove('shell-refreshing');
  });
}
function openPanel(url, title){
  var root = panelRoot();
  var body = panelBody();
  if(!root || !body || !url){ return Promise.resolve(); }
  root.classList.add('open');
  document.body.classList.add('panel-open');
  if(panelTitle()){
    panelTitle().textContent = title || 'Details';
  }
  body.innerHTML = panelSkeleton('Loading live details...');
  return fetch(url, {
    credentials: 'same-origin',
    headers: {
      'X-Live-Panel': '1'
    }
  }).then(function(resp){
    if(!resp.ok){ throw new Error('live details unavailable (HTTP ' + resp.status + ')'); }
    return resp.text();
  }).then(function(html){
    var doc = new DOMParser().parseFromString(html, 'text/html');
    var fragment = doc.querySelector('[data-live-panel-content]');
    if(fragment){
      body.innerHTML = fragment.innerHTML;
      var fragmentTitle = fragment.getAttribute('data-live-panel-title') || '';
      if(panelTitle() && fragmentTitle){ panelTitle().textContent = fragmentTitle; }
      return;
    }
    if(doc.body){
      body.innerHTML = doc.body.innerHTML;
      if(panelTitle() && doc.title){ panelTitle().textContent = doc.title; }
    }
  }).catch(function(err){
    var message = 'Live details unavailable';
    if(err && err.message){ message += ': ' + err.message; }
    body.innerHTML = '';
    body.appendChild(panelError(message, url));
    showToast('Unable to load details', 'error');
  });
}
function closePanel(){
  var root = panelRoot();
  var body = panelBody();
  if(root){ root.classList.remove('open'); }
  document.body.classList.remove('panel-open');
  if(body && !body.dataset.keepOpen){
    body.innerHTML = panelSkeleton('Select an item to inspect live details.');
  }
}
function submitSearchForm(form){
  if(!form){ return Promise.resolve(false); }
  var method = (form.method || 'get').toLowerCase();
  if(method !== 'get'){
    return Promise.resolve(false);
  }
  var action = form.getAttribute('action') || window.location.pathname;
  var params = new URLSearchParams();
  new FormData(form).forEach(function(value, key){
    if(value !== null && value !== undefined){ params.set(key, value); }
  });
  var target = new URL(action, window.location.href);
  target.search = params.toString();
  var node = form.closest('[data-live-shell]') || shell();
  if(node){
    if(window.history && window.history.replaceState){
      window.history.replaceState({}, document.title, target.toString());
    }
    return refreshShell(target.toString(), shellSelector(node));
  }
  window.location.assign(target.toString());
  return Promise.resolve(true);
}
function bindSearchForms(){
  document.querySelectorAll('form[data-live-search-form="true"]').forEach(function(form){
    if(form.dataset.liveBound === 'true'){ return; }
    form.dataset.liveBound = 'true';
    var timer = null;
    var trigger = function(){
      if(timer){ window.clearTimeout(timer); }
      timer = window.setTimeout(function(){
        submitSearchForm(form);
      }, 180);
    };
    form.addEventListener('submit', function(ev){
      ev.preventDefault();
      submitSearchForm(form);
    });
    form.querySelectorAll('input, select, textarea').forEach(function(field){
      field.addEventListener('input', trigger);
      field.addEventListener('change', trigger);
    });
  });
}
function bindCopyButtons(){
  document.querySelectorAll('[data-copy-target], [data-copy-text]').forEach(function(button){
    if(button.dataset.copyBound === 'true'){ return; }
    button.dataset.copyBound = 'true';
    var copyHandler = function(ev){
      ev.preventDefault();
      var text = '';
      var selector = button.getAttribute('data-copy-target');
      if(selector){
        var target = document.querySelector(selector);
        text = target ? (target.textContent || '') : '';
      }
      if(!text){
        text = button.getAttribute('data-copy-text') || '';
      }
      if(!text){ return; }
      var done = function(){
        showToast(button.getAttribute('data-copy-label') || 'Copied', 'success');
      };
      if(navigator.clipboard && navigator.clipboard.writeText){
        navigator.clipboard.writeText(text).then(done).catch(function(){
          showToast('Copy failed', 'error');
        });
      } else {
        showToast('Copy not supported', 'warning');
      }
    };
    button.addEventListener('click', copyHandler);
    button.addEventListener('keydown', function(ev){
      if(ev.key === 'Enter' || ev.key === ' '){
        copyHandler(ev);
      }
    });
  });
}
function bindLiveRefreshers(){
  document.querySelectorAll('[data-live-refresh-url]').forEach(function(node){
    if(node.dataset.liveRefreshBound === 'true'){ return; }
    node.dataset.liveRefreshBound = 'true';
    var interval = parseInt(node.getAttribute('data-live-refresh-interval') || '10000', 10);
    if(!interval || interval < 2000){ interval = 10000; }
    refreshShellNode(node);
    window.setInterval(function(){
      if(document.visibilityState === 'visible'){
        refreshShellNode(node);
      }
    }, interval);
  });
}
function bindPanelLinks(){
  document.addEventListener('click', function(ev){
    var link = ev.target && ev.target.closest ? ev.target.closest('a[data-live-panel-link="true"]') : null;
    if(!link){ return; }
    var href = link.getAttribute('href');
    if(!href || href.charAt(0) !== '/' && href.indexOf(window.location.origin) !== 0){ return; }
    ev.preventDefault();
    openPanel(link.href, link.getAttribute('data-live-panel-title') || link.getAttribute('title') || link.textContent.trim());
  });
  document.addEventListener('click', function(ev){
    var closer = ev.target && ev.target.closest ? ev.target.closest('[data-live-panel-close="true"]') : null;
    if(closer){
      ev.preventDefault();
      closePanel();
    }
    var backdrop = ev.target && ev.target.matches ? ev.target.matches('[data-live-panel-backdrop="true"]') : false;
    if(backdrop){
      ev.preventDefault();
      closePanel();
    }
  });
  document.addEventListener('keydown', function(ev){
    if(ev.key === 'Escape'){
      closePanel();
      return;
    }
    if(ev.key === '/' && !ev.ctrlKey && !ev.metaKey && !ev.altKey){
      var activeTag = document.activeElement && document.activeElement.tagName ? document.activeElement.tagName.toLowerCase() : '';
      if(activeTag === 'input' || activeTag === 'textarea' || activeTag === 'select'){
        return;
      }
      var search = document.querySelector('input[type="search"], input[data-live-search-focus="true"]');
      if(search){
        ev.preventDefault();
        search.focus();
        if(search.select){ search.select(); }
      }
    }
  });
}
function initPanelShell(){
  var root = panelRoot();
  if(!root){ return; }
  if(root.dataset.liveReady === 'true'){ return; }
  root.dataset.liveReady = 'true';
  var close = root.querySelector('[data-live-panel-close="true"]');
  if(close){
    close.addEventListener('click', function(ev){
      ev.preventDefault();
      closePanel();
    });
  }
}
function refreshShell(url, selector){
  var current = selector ? document.querySelector(selector) : shell();
  if(!current || !url){ return Promise.resolve(false); }
  current.classList.add('shell-refreshing');
  return fetch(url, { credentials: 'same-origin' }).then(function(resp){
    if(!resp.ok){ throw new Error('refresh failed'); }
    return resp.text();
  }).then(function(html){
    var doc = new DOMParser().parseFromString(html, 'text/html');
    var fresh = selector ? doc.querySelector(selector) : doc.querySelector('[data-live-shell]');
    if(fresh && current){
      current.innerHTML = fresh.innerHTML;
      initPanelShell();
      bindCopyButtons();
      bindSearchForms();
      applyDensityPreference();
      bindCollapsiblePanels();
      updateRelativeTimes();
      pulseKPIs(current);
      flashNode(current);
      return true;
    }
    return false;
  }).catch(function(){
    return false;
  }).finally(function(){
    current.classList.remove('shell-refreshing');
  });
}
bindPanelLinks();
bindDensityToggle();
bindCopyButtons();
bindSearchForms();
bindLiveRefreshers();
initPanelShell();
applyDensityPreference();
bindCollapsiblePanels();
updateRelativeTimes();
window.setInterval(updateRelativeTimes, 1000);
state.toast = showToast;
state.openPanel = openPanel;
state.closePanel = closePanel;
state.refreshShell = refreshShell;
state.refreshShellNode = refreshShellNode;
})();`
}
