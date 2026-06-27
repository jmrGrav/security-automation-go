package ui

func aiExplainScript() string {
	return `(function(){'use strict';
function text(node, value){ if(node){ node.textContent = value; } }
function csrfToken(){
  var el = document.getElementById('v2-csrf-token');
  if(el && el.dataset.token){ return el.dataset.token; }
  var meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? (meta.getAttribute('content') || '') : '';
}
function csrfFrom(form){
  var field = form.querySelector('[name="csrf_token"]');
  if(field && field.value){ return field.value; }
  return csrfToken();
}
function renderResult(node, payload){
  if(!node){ return; }
  var bits = [];
  if(payload.cached !== undefined){ bits.push('cached=' + (payload.cached ? 'yes' : 'no')); }
  if(payload.provider){ bits.push('provider=' + payload.provider); }
  if(payload.model){ bits.push('model=' + payload.model); }
  if(payload.quota_state){ bits.push('quota=' + payload.quota_state); }
  if(payload.audit_id){ bits.push('audit_id=' + payload.audit_id); }
  if(payload.explanation){ bits.push('', payload.explanation); }
  text(node, bits.join('\n'));
  node.dataset.aiExplainState = payload.quota_state || 'UNKNOWN';
  node.style.display = '';
}
function aiExplainFetch(subjectType, subjectId, resultNode, triggerEl){
  if(triggerEl){ triggerEl.disabled = true; triggerEl.textContent = '…'; }
  if(resultNode){ text(resultNode, 'Loading AI explanation…'); resultNode.style.display = ''; }
  fetch('/ui/ai/explain', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {'Content-Type':'application/json','X-CSRF-Token': csrfToken()},
    body: JSON.stringify({subject_type: subjectType, subject_id: subjectId, provider_preference: 'auto'})
  }).then(function(resp){
    return resp.json().then(function(data){ return {ok: resp.ok, data: data}; }, function(){ return {ok: resp.ok, data: null}; });
  }).then(function(r){
    if(!r.ok){ throw new Error((r.data && r.data.error) || 'AI explain unavailable'); }
    renderResult(resultNode, r.data || {});
  }).catch(function(err){
    if(resultNode){ text(resultNode, 'AI explanation unavailable: ' + err.message); }
  }).finally(function(){
    if(triggerEl){ triggerEl.disabled = false; triggerEl.textContent = '✦'; }
  });
}
// Handle ✦ trigger buttons (data-ai-explain-trigger)
document.addEventListener('click', function(ev){
  var btn = ev.target;
  if(!btn || !btn.matches || !btn.matches('[data-ai-explain-trigger]')){ return; }
  var subjectType = btn.dataset.aiSubjectType || 'event';
  var subjectId   = btn.dataset.aiSubjectId   || '';
  if(!subjectId){ return; }
  // find or create result panel anchored to the parent details
  var details = btn.closest('details') || btn.parentElement;
  var resultNode = details ? details.querySelector('[data-ai-explain-result]') : null;
  if(!resultNode && details){
    resultNode = document.createElement('pre');
    resultNode.dataset.aiExplainResult = '';
    resultNode.style.cssText = 'margin-top:8px;padding:10px 12px;border-radius:8px;border:1px solid rgba(124,108,242,.25);background:rgba(124,108,242,.07);font:500 12px/1.6 "JetBrains Mono",monospace;color:#c5cad8;white-space:pre-wrap;word-break:break-word;display:none';
    details.appendChild(resultNode);
  }
  aiExplainFetch(subjectType, subjectId, resultNode, btn);
});
// Handle legacy data-ai-explain-form submit
document.addEventListener('submit', function(ev){
  var form = ev.target;
  if(!form || !form.matches || !form.matches('[data-ai-explain-form]')){ return; }
  ev.preventDefault();
  var panel = form.closest('[data-ai-explain-block]') || form.parentElement;
  var result = panel ? panel.querySelector('[data-ai-explain-result]') : null;
  var submitBtn = form.querySelector('button[type="submit"]');
  if(submitBtn){ submitBtn.disabled = true; submitBtn.textContent = 'Explaining…'; }
  if(result){ text(result, 'Loading AI explanation…'); }
  var subjectType = (form.querySelector('[name="subject_type"]') || {}).value || '';
  var subjectId   = (form.querySelector('[name="subject_id"]')   || {}).value || '';
  fetch(form.action || '/ui/ai/explain', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {'Content-Type':'application/json','X-CSRF-Token': csrfFrom(form)},
    body: JSON.stringify({subject_type: subjectType, subject_id: subjectId, provider_preference: 'auto'})
  }).then(function(resp){
    return resp.json().then(function(data){ return {ok: resp.ok, data: data}; }, function(){ return {ok: resp.ok, data: null}; });
  }).then(function(r){
    if(!r.ok){ throw new Error((r.data && r.data.error) || 'AI explain unavailable'); }
    renderResult(result, r.data || {});
  }).catch(function(err){
    if(result){ text(result, 'AI explanation unavailable: ' + err.message); }
  }).finally(function(){
    if(submitBtn){ submitBtn.disabled = false; submitBtn.textContent = 'Explain with AI'; }
  });
});
})();`
}
