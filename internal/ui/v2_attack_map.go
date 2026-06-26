package ui

import (
	"net/http"
)

// handleV2AttackMapScript serves the animated canvas attack-map used by the v2 dashboard.
// Vanilla JS, no framework — lifted from the Dashboard Redesign design doc.
func (s *Server) handleV2AttackMapScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(attackMapJS))
}

// handleV2PaletteScript serves the Ctrl+K command palette logic.
// Extracted to a separate file so CSP script-src 'self' allows it (no unsafe-inline needed).
func (s *Server) handleV2PaletteScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(paletteJS))
}

// handleV2LoaderScript serves the login-page loader/prefetch logic.
// Served WITHOUT authentication so it is accessible on GET /v2/login.
func (s *Server) handleV2LoaderScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(loaderJS))
}

const paletteJS = `
(function(){
  'use strict';
  function palette(){ return document.getElementById('v2-palette'); }
  function paletteInput(){ return document.getElementById('v2-palette-input'); }

  function openPalette(){
    var el=palette(), inp=paletteInput();
    if(!el||!inp) return;
    el.style.display='flex';
    setTimeout(function(){ inp.focus(); inp.select(); }, 0);
  }
  function closePalette(){
    var el=palette();
    if(el) el.style.display='none';
  }

  function submit(){
    var val=(paletteInput()||{}).value||'';
    val=val.trim();
    if(!val) return;
    closePalette();
    window.location='/v2/investigate?q='+encodeURIComponent(val);
  }

  // Keyboard shortcut: Ctrl+K / ⌘K
  document.addEventListener('keydown', function(ev){
    var k=(ev.key||'').toLowerCase();
    if((ev.ctrlKey||ev.metaKey) && k==='k'){ ev.preventDefault(); openPalette(); return; }
    if(k==='escape'){ closePalette(); }
  });

  // Click outside to close
  document.addEventListener('click', function(ev){
    var el=palette();
    if(el && ev.target===el) closePalette();
  });

  // Button triggers
  document.addEventListener('click', function(ev){
    var trigger = ev.target && ev.target.closest ? ev.target.closest('[data-palette-trigger]') : null;
    if(trigger){ ev.preventDefault(); openPalette(); }
  });

  // Form submit inside palette
  document.addEventListener('submit', function(ev){
    if(ev.target && ev.target.id==='v2-palette-form'){
      ev.preventDefault();
      submit();
    }
  });

  // Sign out: POST /logout then redirect, without inline onclick (blocked by CSP)
  document.addEventListener('click', function(ev){
    var el = ev.target && ev.target.closest ? ev.target.closest('[data-v2-signout]') : null;
    if(el){
      ev.preventDefault();
      fetch('/logout',{method:'POST',credentials:'same-origin'}).then(function(){
        window.location.href='/v2/login';
      }).catch(function(){
        window.location.href='/v2/login';
      });
    }
  });
})();
`

// loaderJS drives the login-page loader overlay: intercepts the form submit, shows the
// animated overlay, POSTs credentials via fetch, prefetches dashboard assets on success,
// and injects the server error inline on failure — all without an unsafe-inline script tag.
const loaderJS = `
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
  var form=document.getElementById('v2-login-form');
  var errBox=document.getElementById('v2-err-box');
  if(!loader||!form||!statusEl||!errBox) return;
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
        stopCycle(msgs[msgs.length-1]);
        return Promise.all([
          fetch('/v2/static/attack-map.js',{credentials:'same-origin'}),
          fetch('/v2/static/palette.js',{credentials:'same-origin'})
        ]).catch(function(){}).then(function(){ window.location.href='/v2/'; });
      }
      return r.text().then(function(html){
        var doc=new DOMParser().parseFromString(html,'text/html');
        var el=doc.getElementById('v2-login-error');
        showErr(el?el.textContent.trim():'Invalid password.');
      }).catch(function(){ showErr('Authentication failed.'); });
    }).catch(function(){ showErr('Connection error. Please try again.'); });
  });
})();
`

// attackMapJS is the self-contained canvas animation for the v2 attack map.
// Takes a `data-origins` JSON attribute on the canvas element for real country data.
const attackMapJS = `
(function() {
  'use strict';

  // lat/lon centroids for ISO 3166-1 alpha-2 codes (subset covering typical attack origins)
  const COUNTRY_CENTROIDS = {
    FR:[2.2,46.2], US:[-98,39.5], DE:[10.4,51.2], CN:[104,35.5], RU:[105.3,61.5],
    GB:[-3.4,55.4], NL:[5.3,52.1], JP:[138,36.5], IN:[78,20], BR:[-51,-10],
    PL:[19.1,52.1], UA:[31,48.4], TR:[35,39], KR:[127.8,36.5], HK:[114.1,22.3],
    SG:[103.8,1.35], VN:[108,14], TH:[101,15], ID:[118,-2.5], AU:[135,-25],
    CA:[-96,60], MX:[-102,24], AR:[-64,-34], ZA:[25,-29], NG:[8,10],
    IT:[12.6,41.9], ES:[-3.7,40.4], PT:[-8,39.5], SE:[18.6,60.1], NO:[9,60.5],
    FI:[26,64], DK:[10,56], BE:[4.5,50.5], CH:[8,47], AT:[14,47],
    CZ:[15.5,49.8], RO:[25,45.9], HU:[19,47], BG:[25.5,42.7], GR:[22,39],
    IR:[53,32], IL:[34.9,31.5], SA:[45,24], AE:[54,24], PK:[70,30],
    BD:[90.4,24], MY:[110,4], PH:[121.8,12.9], TW:[121,23.7], RS:[21,44],
    HR:[16,45.1], SK:[19.5,48.7], SI:[14.8,46.1], LT:[24,56], LV:[25,57],
    EE:[25.1,58.6], BY:[28,53.7], MD:[29,47], BA:[17.7,44], AL:[20,41],
    MK:[21.7,41.6], ME:[19.4,42.7], KZ:[66.9,48], UZ:[63.9,41.4],
    GE:[43.4,42.3], AM:[45,40.1], AZ:[47.6,40.1], LB:[35.5,33.9],
  };

  function init(canvas) {
    const dataEl = document.getElementById('v2-attack-origins');
    let origins = [];
    try { origins = JSON.parse(dataEl ? dataEl.textContent : '[]'); } catch(_) {}

    // node = our server (France, fixed)
    const node = {lon:2, lat:46.2};

    const DPR = Math.min(2, window.devicePixelRatio || 1);
    const ctx = canvas.getContext('2d');

    function resize() {
      const r = canvas.getBoundingClientRect();
      canvas.width  = Math.max(1, r.width  * DPR);
      canvas.height = Math.max(1, r.height * DPR);
    }
    resize();

    const W = () => canvas.width;
    const H = () => canvas.height;

    // Equirectangular projection
    const proj = (lon, lat) => [(lon + 180) / 360, (82 - lat) / 140];

    // Approximate landmass as ellipses [lon, lat, rxDeg, ryDeg]
    const regions = [
      [-100,48,30,20],[-92,60,26,12],[-118,40,12,14],[-88,17,11,8],
      [-60,-12,16,24],[-42,72,13,8],[-2,54,5,6],[16,64,9,9],
      [14,50,18,9],[20,20,22,16],[24,-12,16,18],[45,30,15,11],
      [88,60,56,14],[80,42,30,15],[78,22,9,11],[104,12,16,12],
      [118,-3,19,7],[134,-25,16,11],[138,38,5,9]
    ];
    const isLand = (lon, lat) => regions.some(r => {
      const dx=(lon-r[0])/r[2], dy=(lat-r[1])/r[3];
      return dx*dx+dy*dy<=1;
    });

    const dots = [];
    for (let lon=-178; lon<180; lon+=3.0)
      for (let lat=76; lat>-56; lat-=3.4)
        if (isLand(lon, lat)) { const [u,v]=proj(lon,lat); dots.push([u,v]); }

    const [nu,nv] = proj(node.lon, node.lat);

    // Build arc paths from each origin to node
    const arcs = origins.map(o => {
      const c = COUNTRY_CENTROIDS[o.code];
      if (!c) return null;
      const [ou,ov] = proj(c[0], c[1]);
      const mx=(ou+nu)/2, my=(ov+nv)/2-0.13;
      return {ou,ov,mx,my,rgb:o.rgb,count:o.count};
    }).filter(Boolean);

    // Pings along arcs
    const pings = [];
    arcs.forEach((arc, i) => {
      const n = Math.max(1, Math.min(3, Math.round(arc.count/25)));
      for (let k=0; k<n; k++) pings.push({arc, phase:((i*0.31)+(k*0.4))%1});
    });

    let raf, t0 = performance.now();
    function draw(now) {
      const dt = (now - t0) / 1000;
      ctx.clearRect(0, 0, W(), H());

      // Dot grid (landmass)
      for (const [u,v] of dots) {
        ctx.beginPath();
        ctx.arc(u*W(), v*H(), 1.05*DPR, 0, 7);
        ctx.fillStyle = 'rgba(132,146,178,0.15)';
        ctx.fill();
      }

      // Arcs
      for (const a of arcs) {
        ctx.beginPath();
        ctx.moveTo(a.ou*W(), a.ov*H());
        ctx.quadraticCurveTo(a.mx*W(), a.my*H(), nu*W(), nv*H());
        ctx.strokeStyle = 'rgba('+a.rgb+',0.10)';
        ctx.lineWidth = 1*DPR;
        ctx.stroke();
      }

      // Animated pings
      for (const p of pings) {
        const a = p.arc;
        const pr = ((dt*0.16)+p.phase)%1;
        const x = (1-pr)*(1-pr)*a.ou + 2*(1-pr)*pr*a.mx + pr*pr*nu;
        const y = (1-pr)*(1-pr)*a.ov + 2*(1-pr)*pr*a.my + pr*pr*nv;
        ctx.beginPath();
        ctx.arc(x*W(), y*H(), 2.1*DPR, 0, 7);
        ctx.fillStyle = 'rgba('+a.rgb+','+(0.85*(1-pr)+0.15)+')';
        ctx.shadowColor = 'rgba('+a.rgb+',0.9)';
        ctx.shadowBlur = 9*DPR;
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      // Origin markers (pulsing)
      for (const a of arcs) {
        const [ou,ov] = [a.ou, a.ov];
        const base = (2.6 + Math.min(5, Math.log2(a.count+1)))*DPR;
        const pulse = Math.sin(dt*2 + a.ou)*0.5+0.5;
        // Halo
        ctx.beginPath(); ctx.arc(ou*W(), ov*H(), base+pulse*7*DPR, 0, 7);
        ctx.strokeStyle = 'rgba('+a.rgb+','+(0.28*(1-pulse)+0.04)+')';
        ctx.lineWidth = 1.4*DPR; ctx.stroke();
        // Dot
        ctx.beginPath(); ctx.arc(ou*W(), ov*H(), base, 0, 7);
        ctx.fillStyle = 'rgba('+a.rgb+',0.95)'; ctx.fill();
      }

      // Node (our server)
      const npulse = Math.sin(dt*2.2)*0.5+0.5;
      ctx.beginPath(); ctx.arc(nu*W(), nv*H(), (4+npulse*9)*DPR, 0, 7);
      ctx.strokeStyle = 'rgba(124,108,242,'+(0.34*(1-npulse)+0.05)+')';
      ctx.lineWidth = 1.6*DPR; ctx.stroke();
      ctx.beginPath(); ctx.arc(nu*W(), nv*H(), 3.4*DPR, 0, 7);
      ctx.fillStyle = '#9b8cff';
      ctx.shadowColor = '#7c6cf2'; ctx.shadowBlur = 12*DPR;
      ctx.fill(); ctx.shadowBlur = 0;

      raf = requestAnimationFrame(draw);
    }
    raf = requestAnimationFrame(draw);

    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    return () => { cancelAnimationFrame(raf); ro.disconnect(); };
  }

  // Auto-init all canvases with data-attack-map attribute
  document.querySelectorAll('canvas[data-attack-map]').forEach(init);
})();
`
