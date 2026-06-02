package ui

func aiExplainScript() string {
	return `(function(){'use strict';
function text(node, value){ if(node){ node.textContent = value; } }
function nearestResult(form){
  var panel = form.closest('[data-ai-explain-block]') || form.parentElement;
  return panel ? panel.querySelector('[data-ai-explain-result]') : null;
}
function setBusy(form, busy){
  var button = form.querySelector('button[type="submit"]');
  if(button){ button.disabled = !!busy; button.textContent = busy ? 'Explaining...' : 'Explain with AI'; }
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
}
document.addEventListener('submit', function(ev){
  var form = ev.target;
  if(!form || !form.matches || !form.matches('[data-ai-explain-form]')){ return; }
  ev.preventDefault();
  var result = nearestResult(form);
  setBusy(form, true);
  if(result){ text(result, 'Loading AI explanation...'); }
  var body = new URLSearchParams();
  var fields = ['subject_type', 'subject_id', 'provider_preference', 'csrf_token'];
  fields.forEach(function(name){
    var field = form.querySelector('[name="' + name + '"]');
    if(field){ body.set(name, field.value || ''); }
  });
  fetch(form.action || '/ui/ai/explain', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': body.get('csrf_token') || ''
    },
    body: JSON.stringify({
      subject_type: body.get('subject_type') || '',
      subject_id: body.get('subject_id') || '',
      provider_preference: body.get('provider_preference') || 'auto'
    })
  }).then(function(resp){
    return resp.json().then(function(data){ return {ok: resp.ok, data: data}; }, function(){ return {ok: resp.ok, data: null}; });
  }).then(function(resultPayload){
    if(!resultPayload.ok){
      throw new Error((resultPayload.data && resultPayload.data.error) || 'AI explain unavailable');
    }
    renderResult(result, resultPayload.data || {});
  }).catch(function(err){
    if(result){ text(result, 'AI explanation unavailable: ' + err.message); }
  }).finally(function(){ setBusy(form, false); });
});
})();`
}
