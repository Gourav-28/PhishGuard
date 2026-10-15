/* shared.js: API client + safe rendering helpers.
   Loaded by popup.html, app.html, blocked.html AND imported by the service worker (importScripts).
   Must not touch `document`/`window` at load time. */
const PG = (() => {
  const DEFAULTS = { apiBase: 'http://localhost:8000', apiKey: '', autoProtect: true, downloadGuard: true, blockThreshold: 70 };
  const getCfg = () => chrome.storage.local.get(DEFAULTS);

  async function api(path, opts = {}) {
    const c = await getCfg();
    const headers = {};
    if (c.apiKey) headers['X-API-Key'] = c.apiKey;
    let body;
    if (opts.form) body = opts.form;
    else if (opts.body !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(opts.body); }
    let res;
    try {
      res = await fetch(c.apiBase.replace(/\/+$/, '') + '/api' + path, { method: opts.method || (body ? 'POST' : 'GET'), headers, body });
    } catch {
      throw new Error(`Cannot reach the backend at ${c.apiBase}. Start it with: python -m uvicorn app.main:app`);
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const d = data.detail;
      throw new Error(typeof d === 'string' ? d : Array.isArray(d) ? d.map(x => x.msg).join('; ') : `Backend error ${res.status}`);
    }
    return data;
  }

  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const LEVELS = [[80, 'Critical Risk', '#ef4444', 'red'], [60, 'High Risk', '#f97316', 'orange'], [35, 'Medium Risk', '#f59e0b', 'amber'], [0, 'Low Risk', '#10b981', 'green']];
  const levelOf = s => LEVELS.find(l => s >= l[0]);
  const ICON = { Clock: '⏰', KeyRound: '🔑', Languages: '🔤', Database: '🗄️', Globe: '🌐', QrCode: '▦', Link2: '🔗', ShieldAlert: '🚨',
    AlertTriangle: '⚠️', FileWarning: '📄', Ban: '⛔', CheckCircle2: '✅', Eye: '👁️', Mail: '✉️', Bot: '🤖' };
  const KIND = { text: 'Text/SMS analyzer', email: 'E-mail analyzer', qr: 'QR decoder', image: 'OCR engine', download: 'Download inspector', url: 'URL analyzer' };
  const BCLS = { red: 'red', orange: 'orange', amber: 'amber', emerald: 'green', green: 'green', sky: 'sky' };

  function meter(score, size = 104) {
    const lv = levelOf(score), r = size / 2 - 9, C = 2 * Math.PI * r, n = Number(score) || 0;
    return `<div class="meter" style="width:${size}px;height:${size}px"><svg width="${size}" height="${size}" style="transform:rotate(-90deg)">
      <circle cx="${size / 2}" cy="${size / 2}" r="${r}" stroke="#1e293b" stroke-width="9" fill="none"/>
      <circle cx="${size / 2}" cy="${size / 2}" r="${r}" stroke="${lv[2]}" stroke-width="9" fill="none" stroke-linecap="round"
        stroke-dasharray="${C}" stroke-dashoffset="${C * (1 - n / 100)}" style="transition:stroke-dashoffset .7s;filter:drop-shadow(0 0 5px ${lv[2]})"/></svg>
      <div class="meter-t"><b style="color:${lv[2]}">${n}%</b><small>${esc(lv[1])}</small></div></div>`;
  }

  /* Every server-provided string goes through esc(): never trust backend/e-mail content. */
  function renderResult(r, o = {}) {
    const lv = levelOf(r.score), bad = r.score >= 60;
    const badges = (r.badges || []).map(b => `<span class="badge b-${BCLS[b[0]] || 'amber'}">${ICON[b[1]] || '•'} ${esc(b[2])}</span>`).join('');
    const det = (r.details || []).map(d => `<li>${esc(d)}</li>`).join('');
    const urls = (r.urls || []).slice(0, 5).map(u => `<div class="mono amber">🔗 ${esc(u)}</div>`).join('');
    const ai = r.ai ? `<div class="ai">🤖 <b>Local AI (${esc(r.ai.model)}):</b> ${esc(r.ai.reasoning)} <span class="muted">· ${esc(r.ai.confidence)}% confidence</span></div>` : '';
    const warn = (r.warnings || []).map(w => `<div class="sky">👁️ ${esc(w)}</div>`).join('');
    const canAct = (r.urls || []).length > 0;
    return `<div class="result ${bad ? 'bad' : ''}">
      <div class="res-top">${meter(r.score, o.compact ? 96 : 112)}<div class="grow">
        <div class="res-h" style="color:${lv[2]}">${bad ? '🚨 Threat detected' : r.score >= 35 ? '⚠️ Suspicious' : '✅ Looks safe'}</div>
        <div class="muted small">${esc(lv[1])} · ${esc(KIND[r.kind] || r.kind)}${r.simulated ? ' · simulated' : ''}</div>
        <div class="badges">${badges}</div></div></div>
      ${ai}${det ? `<ul class="details${bad ? ' bad' : ''}">${det}</ul>` : ''}${warn}
      ${urls ? `<div class="box"><div class="lbl">Extracted URLs</div>${urls}</div>` : ''}
      ${o.actions === false ? '' : `<div class="row gap"><button class="btn btn-red grow" data-act="block" ${canAct ? '' : 'disabled'}>⛔ Block &amp; Exit Site</button>
        <button class="btn btn-amber-o grow" data-act="report" ${canAct ? '' : 'disabled'}>🚩 Report Site</button></div>`}</div>`;
  }

  function toast(msg, ms = 2800) {
    const t = document.createElement('div');
    t.className = 'toast'; t.textContent = msg; document.body.appendChild(t);
    setTimeout(() => t.remove(), ms);
  }

  const blockedUrl = (url, score, details) => chrome.runtime.getURL('blocked.html') + '?' +
    new URLSearchParams({ u: url, s: String(score), d: JSON.stringify((details || []).slice(0, 4)) });

  return { DEFAULTS, getCfg, api, esc, levelOf, meter, renderResult, toast, blockedUrl, ICON };
})();
