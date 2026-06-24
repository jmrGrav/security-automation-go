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
function applyThemePreference(){
  var dark = storageGet('security-automation:theme') === 'operations-dark';
  if(document.body){
    if(dark){ document.body.setAttribute('data-theme', 'operations-dark'); }
    else { document.body.removeAttribute('data-theme'); }
  }
  document.querySelectorAll('[data-theme-toggle="true"]').forEach(function(button){
    button.setAttribute('aria-pressed', dark ? 'true' : 'false');
    button.textContent = dark ? 'Comfort light' : 'Dark operations';
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
function bindThemeToggle(){
  if(state.themeToggleBound === 'true'){ return; }
  state.themeToggleBound = 'true';
  document.addEventListener('click', function(ev){
    var button = ev.target && ev.target.closest ? ev.target.closest('[data-theme-toggle="true"]') : null;
    if(!button){ return; }
    ev.preventDefault();
    var dark = document.body && document.body.getAttribute('data-theme') === 'operations-dark';
    storageSet('security-automation:theme', dark ? 'comfort-light' : 'operations-dark');
    applyThemePreference();
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
var watchlistKey = 'security-automation:watchlist';
function loadWatchlist(){
  try{
    var raw = storageGet(watchlistKey);
    if(!raw){ return []; }
    var parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  }catch(e){ return []; }
}
function saveWatchlist(items){
  try{ storageSet(watchlistKey, JSON.stringify(items)); }catch(e){}
}
function renderWatchlist(){
  var widget = document.querySelector('[data-watchlist-widget="true"]');
  if(!widget){ return; }
  var list = widget.querySelector('[data-watchlist-list]');
  if(!list){ return; }
  var items = loadWatchlist();
  var capped = items.slice(0, 10);
  list.innerHTML = '';
  if(capped.length === 0){
    var empty = document.createElement('p');
    empty.className = 'muted';
    empty.style.cssText = 'font-size:.82rem;margin:.35rem 0 0;padding:0 .1rem';
    empty.textContent = 'No items watched.';
    list.appendChild(empty);
  } else {
    capped.forEach(function(item, idx){
      var row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:.45rem;padding:.28rem .1rem;border-top:1px solid var(--sidebar-border);font-size:.82rem';
      var label = document.createElement('span');
      label.style.cssText = 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--sidebar-text)';
      label.textContent = item.label || item.value || '';
      label.title = item.value || '';
      var rm = document.createElement('button');
      rm.type = 'button';
      rm.setAttribute('data-watchlist-remove', String(idx));
      rm.style.cssText = 'flex:0 0 auto;min-height:auto;padding:.1rem .35rem;font-size:.78rem;border-radius:6px;background:var(--state-error-bg);border-color:var(--state-error);color:var(--state-error);box-shadow:none';
      rm.textContent = '×';
      rm.title = 'Remove from watchlist';
      row.appendChild(label);
      row.appendChild(rm);
      list.appendChild(row);
    });
  }
  document.querySelectorAll('[data-watchlist-add="true"]').forEach(function(btn){
    var type = btn.getAttribute('data-watchlist-type') || '';
    var value = btn.getAttribute('data-watchlist-value') || '';
    var watched = items.some(function(it){ return it.type === type && it.value === value; });
    btn.textContent = watched ? '★' : '☆';
    btn.setAttribute('aria-pressed', watched ? 'true' : 'false');
    btn.title = watched ? 'Remove from watchlist' : 'Add to watchlist';
  });
}
function bindWatchlistAdd(){
  if(state.watchlistAddBound === 'true'){ return; }
  state.watchlistAddBound = 'true';
  document.addEventListener('click', function(ev){
    var btn = ev.target && ev.target.closest ? ev.target.closest('[data-watchlist-add="true"]') : null;
    if(!btn){ return; }
    ev.preventDefault();
    var type = btn.getAttribute('data-watchlist-type') || 'ip';
    var value = btn.getAttribute('data-watchlist-value') || '';
    var label = btn.getAttribute('data-watchlist-label') || value;
    if(!value){ return; }
    var items = loadWatchlist();
    var existingIdx = -1;
    items.forEach(function(it, i){ if(it.type === type && it.value === value){ existingIdx = i; } });
    if(existingIdx >= 0){
      items.splice(existingIdx, 1);
    } else {
      items.unshift({type: type, value: value, label: label, addedAt: new Date().toISOString()});
      if(items.length > 10){ items = items.slice(0, 10); }
    }
    saveWatchlist(items);
    renderWatchlist();
  });
}
function bindWatchlistRemove(){
  if(state.watchlistRemoveBound === 'true'){ return; }
  state.watchlistRemoveBound = 'true';
  document.addEventListener('click', function(ev){
    var btn = ev.target && ev.target.closest ? ev.target.closest('[data-watchlist-remove]') : null;
    if(!btn){ return; }
    var widget = btn.closest('[data-watchlist-widget="true"]');
    if(!widget){ return; }
    ev.preventDefault();
    var idx = parseInt(btn.getAttribute('data-watchlist-remove'), 10);
    if(isNaN(idx)){ return; }
    var items = loadWatchlist().slice(0, 10);
    items.splice(idx, 1);
    saveWatchlist(loadWatchlist().filter(function(it, i){
      return items.some(function(kept){ return kept.type === it.type && kept.value === it.value && kept.addedAt === it.addedAt; });
    }));
    renderWatchlist();
  });
}
var recentsKey = 'security-automation:recents';
function loadRecents(){
  try{
    var raw = storageGet(recentsKey);
    if(!raw){ return []; }
    var parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  }catch(e){ return []; }
}
function saveRecents(items){
  try{ storageSet(recentsKey, JSON.stringify(items)); }catch(e){}
}
function relativeTime(iso){
  try{
    var then = new Date(iso);
    if(isNaN(then.getTime())){ return ''; }
    var diff = Math.max(0, Math.floor((Date.now() - then.getTime()) / 1000));
    if(diff < 60){ return 'just now'; }
    if(diff < 3600){ return Math.floor(diff / 60) + 'm ago'; }
    if(diff < 86400){ return Math.floor(diff / 3600) + 'h ago'; }
    return then.toLocaleDateString();
  }catch(e){ return ''; }
}
function pushRecent(url, title){
  if(!url){ return; }
  var items = loadRecents();
  items = items.filter(function(it){ return it.url !== url; });
  items.unshift({url: url, title: title || url, ts: new Date().toISOString()});
  if(items.length > 10){ items = items.slice(0, 10); }
  saveRecents(items);
}
function renderRecents(){
  var widget = document.querySelector('[data-recents-widget="true"]');
  if(!widget){ return; }
  var list = widget.querySelector('[data-recents-list]');
  if(!list){ return; }
  var items = loadRecents().slice(0, 5);
  list.innerHTML = '';
  if(items.length === 0){
    var empty = document.createElement('p');
    empty.className = 'muted';
    empty.style.cssText = 'font-size:.82rem;margin:.35rem 0 0;padding:0 .1rem';
    empty.textContent = 'No recent pages.';
    list.appendChild(empty);
    return;
  }
  items.forEach(function(item){
    var row = document.createElement('div');
    row.style.cssText = 'border-top:1px solid var(--sidebar-border);padding:.28rem .1rem';
    var link = document.createElement('a');
    link.href = item.url || '#';
    link.style.cssText = 'display:block;text-decoration:none;color:var(--sidebar-text);font-size:.82rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
    link.textContent = item.title || item.url || '';
    link.title = item.title || item.url || '';
    var hint = document.createElement('span');
    hint.style.cssText = 'display:block;font-size:.75rem;color:var(--sidebar-text);opacity:.55';
    hint.textContent = relativeTime(item.ts);
    row.appendChild(link);
    row.appendChild(hint);
    list.appendChild(row);
  });
}
var watchlistOpenKey = 'security-automation:watchlist-open';
function applyWatchlistCollapse(){
  var widget = document.querySelector('[data-watchlist-widget="true"]');
  if(!widget){ return; }
  var body = widget.querySelector('[data-watchlist-body]');
  var toggle = widget.querySelector('[data-watchlist-collapse-toggle="true"]');
  if(!body || !toggle){ return; }
  var open = storageGet(watchlistOpenKey) === 'true';
  body.style.display = open ? 'grid' : 'none';
  toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  toggle.textContent = open ? 'Hide' : 'Show';
}
function bindKeyboardNav(){
  if(state.keyboardNavBound === 'true'){ return; }
  state.keyboardNavBound = 'true';
  var pending = null;
  var pendingTimer = null;
  var routes = { d: '/', t: '/timeline', f: '/forensic', e: '/evidence', h: '/health' };
  document.addEventListener('keydown', function(ev){
    if(ev.ctrlKey || ev.altKey || ev.metaKey){ return; }
    var activeTag = document.activeElement && document.activeElement.tagName ? document.activeElement.tagName.toLowerCase() : '';
    if(activeTag === 'input' || activeTag === 'textarea' || activeTag === 'select'){ return; }
    if(document.querySelector('.command-palette.open')){ return; }
    var key = ev.key || '';
    if(key === '/'){
      var candidates = document.querySelectorAll('input[type="search"], input[name="q"], input[name="search"]');
      var visibleSearch = null;
      for(var si=0; si<candidates.length; si++){
        if(candidates[si].offsetParent !== null){ visibleSearch = candidates[si]; break; }
      }
      if(visibleSearch){
        ev.preventDefault();
        visibleSearch.focus();
        if(visibleSearch.select){ visibleSearch.select(); }
      }
      return;
    }
    if(pending){
      var route = routes[key.toLowerCase()];
      if(route){
        ev.preventDefault();
        if(pendingTimer){ window.clearTimeout(pendingTimer); }
        pending = null;
        pendingTimer = null;
        window.location.assign(route);
      } else {
        if(pendingTimer){ window.clearTimeout(pendingTimer); }
        pending = null;
        pendingTimer = null;
      }
      return;
    }
    if(key.toLowerCase() === 'g'){
      pending = 'g';
      if(pendingTimer){ window.clearTimeout(pendingTimer); }
      pendingTimer = window.setTimeout(function(){
        pending = null;
        pendingTimer = null;
      }, 1000);
    }
  });
}
function bindWatchlistCollapse(){
  if(state.watchlistCollapseBound === 'true'){ return; }
  state.watchlistCollapseBound = 'true';
  applyWatchlistCollapse();
  document.addEventListener('click', function(ev){
    var toggle = ev.target && ev.target.closest ? ev.target.closest('[data-watchlist-collapse-toggle="true"]') : null;
    if(!toggle){ return; }
    ev.preventDefault();
    var open = storageGet(watchlistOpenKey) === 'true';
    storageSet(watchlistOpenKey, open ? 'false' : 'true');
    applyWatchlistCollapse();
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
      bindCommandPalette();
      applyDensityPreference();
      applyThemePreference();
      bindCollapsiblePanels();
      updateRelativeTimes();
      renderWatchlist();
      renderRecents();
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
function commandPaletteRoot(){ return document.querySelector('[data-command-palette-root="true"]'); }
function commandPaletteInput(){
  var root = commandPaletteRoot();
  return root ? root.querySelector('input[name="q"]') : null;
}
function openCommandPalette(){
  var root = commandPaletteRoot();
  var input = commandPaletteInput();
  if(!root || !input){ return; }
  root.classList.add('open');
  root.setAttribute('aria-hidden', 'false');
  window.setTimeout(function(){ input.focus(); input.select(); }, 0);
}
function closeCommandPalette(){
  var root = commandPaletteRoot();
  if(!root){ return; }
  root.classList.remove('open');
  root.setAttribute('aria-hidden', 'true');
}
function bindCommandPalette(){
  if(state.commandPaletteBound === 'true'){ return; }
  state.commandPaletteBound = 'true';
  document.addEventListener('keydown', function(ev){
    var key = (ev.key || '').toLowerCase();
    if((ev.ctrlKey || ev.metaKey) && key === 'k'){
      ev.preventDefault();
      openCommandPalette();
      return;
    }
    if(key === 'escape'){
      closeCommandPalette();
    }
  });
  document.addEventListener('click', function(ev){
    var trigger = ev.target && ev.target.closest ? ev.target.closest('[data-command-palette-trigger="true"]') : null;
    if(trigger){
      ev.preventDefault();
      openCommandPalette();
      return;
    }
    var root = commandPaletteRoot();
    if(root && ev.target === root){
      closeCommandPalette();
    }
  });
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
      var panelCandidates = document.querySelectorAll('input[type="search"], input[data-live-search-focus="true"]');
      var visiblePanelSearch = null;
      for(var pi=0; pi<panelCandidates.length; pi++){
        if(panelCandidates[pi].offsetParent !== null){ visiblePanelSearch = panelCandidates[pi]; break; }
      }
      if(visiblePanelSearch){
        ev.preventDefault();
        visiblePanelSearch.focus();
        if(visiblePanelSearch.select){ visiblePanelSearch.select(); }
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
      var h1 = doc.querySelector('h1');
      var pageTitle = (h1 && h1.textContent.trim()) || doc.title || url;
      pushRecent(url, pageTitle);
      current.innerHTML = fresh.innerHTML;
      initPanelShell();
      bindCopyButtons();
      bindSearchForms();
      bindCommandPalette();
      applyDensityPreference();
      applyThemePreference();
      bindCollapsiblePanels();
      updateRelativeTimes();
      renderWatchlist();
      renderRecents();
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
bindThemeToggle();
bindDensityToggle();
bindKeyboardNav();
bindCopyButtons();
bindSearchForms();
bindCommandPalette();
bindLiveRefreshers();
initPanelShell();
applyThemePreference();
applyDensityPreference();
bindCollapsiblePanels();
updateRelativeTimes();
renderWatchlist();
renderRecents();
bindWatchlistAdd();
bindWatchlistRemove();
bindWatchlistCollapse();
window.setInterval(updateRelativeTimes, 1000);
state.toast = showToast;
state.openPanel = openPanel;
state.closePanel = closePanel;
state.refreshShell = refreshShell;
state.refreshShellNode = refreshShellNode;
})();`
}
