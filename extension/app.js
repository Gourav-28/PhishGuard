document.addEventListener('DOMContentLoaded', () => {
  const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = PG.esc, show = (el, msg) => { el.textContent = msg; el.hidden = !msg; };
  const BRANDS = ['paypal.com', 'google.com', 'amazon.com', 'microsoft.com', 'netflix.com', 'github.com', 'apple.com', 'facebook.com', 'instagram.com',
    'whatsapp.com', 'linkedin.com', 'dropbox.com', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com'];
  const SAMPLE = { sender: 'Apple Support <security@account-apple-support.net>',
    text: 'URGENT: Your Apple ID has been locked due to suspicious login attempts from Russia. Verify your credentials immediately within 24 hours at http://apple-id-verify-secure.com or face permanent account termination.' };

  /* ---------------------------------------------------------------- routing */
  const loaders = { dashboard: loadDash, radar: loadRadar, community: loadCommunity, downloads: loadDownloads, settings: loadSettings };
  function route() {
    const raw = location.hash.replace(/^#\/?/, '') || 'dashboard', p = loaders[raw] ? raw : 'dashboard';
    $$('.page').forEach(x => x.classList.toggle('on', x.id === 'page-' + p));
    $$('.nav a[data-p]').forEach(a => a.classList.toggle('on', a.dataset.p === p));
    loaders[p]();
  }
  window.addEventListener('hashchange', route);
  $('#preview-block').onclick = e => { e.preventDefault(); chrome.tabs.create({ url: PG.blockedUrl('http://paypa1-secure-login.xyz', 94,
    ['paypa1-secure-login.xyz imitates paypal.com via homoglyph substitution, combo-squatting', 'Supabase community flagged (482 reports)', 'Urgency language and credential harvesting']) }); };

  async function status() {
    try { const h = await PG.api('/health');
      $('#status').innerHTML = `<span class="dot on"></span>Online · ${esc(h.store)} · AI ${h.llm && h.llm.available ? esc(h.llm.model) : 'off (heuristics only)'}`;
      $('#status').title = `OCR: ${h.ocr ? 'yes' : 'no'} · QR: ${h.qr ? 'yes' : 'no'} · redirect tracing: ${h.trace_mode}`;
    } catch { $('#status').innerHTML = '<span class="dot off"></span>Backend offline'; }
  }

  /* -------------------------------------------------------------- dashboard */
  let mode = 'text'; const hist = [];
  const MODES = [['text', '💬 Text / Email'], ['image', '🖼️ Screenshot'], ['qr', '▦ QR / Quishing'], ['url', '🔗 URL'], ['download', '⬇️ Download']];
  async function loadStats() {
    let s = { scans: 0, blocked: 0, reports: 0, downloads: 0 };
    try { s = await PG.api('/stats'); } catch {}
    const loc = await chrome.storage.local.get({ blockedPages: 0, blockedDownloads: 0 });
    const c = [['Total scans', s.scans, '📡'], ['Phishing blocked', s.blocked, '🛑'], ['Community reports', s.reports, '🗄️'], ['Downloads guarded', s.downloads, '⬇️'],
      ['Pages blocked here', loc.blockedPages, '🚫'], ['Downloads cancelled here', loc.blockedDownloads, '❌']];
    $('#stats').innerHTML = c.map(([l, v, i]) => `<div class="card stat"><span class="muted small">${i} ${l}</span><b>${Number(v).toLocaleString()}</b></div>`).join('');
  }
  function renderModes() {
    $('#modes').innerHTML = MODES.map(([k, l]) => `<button class="tab ${k === mode ? 'on' : ''}" data-m="${k}">${l}</button>`).join('');
    const f = $('#form'); $('#out').innerHTML = ''; show($('#err'), '');
    if (mode === 'text') f.innerHTML = `<label class="f">Sender (optional, enables spoofing checks)</label><input type="text" id="f-sender" class="mono" placeholder="PayPal &lt;security@account-paypa1.net&gt;">
      <label class="f">Message / e-mail body</label><textarea id="f-text" rows="6" placeholder="Paste a suspicious email, SMS or link…"></textarea>
      <label class="sw" style="margin:8px 0"><input type="checkbox" id="f-llm" checked> Add local AI opinion (Ollama, if running)</label>
      <div class="row gap"><button class="btn btn-red grow" id="go">Scan message</button><button class="btn" id="sample">Load sample</button></div>`;
    else if (mode === 'url') f.innerHTML = `<label class="f">URL</label><input type="text" id="f-url" placeholder="http://paypa1-secure-login.xyz"><button class="btn btn-red btn-w" id="go" style="margin-top:10px">Check URL</button>`;
    else if (mode === 'download') f.innerHTML = `<label class="f">Filename</label><input type="text" id="f-file" value="setup_update_patch.exe"><label class="f">Download URL</label><input type="text" id="f-dl" value="http://bit.ly/sketchy-installer-v2">
      <button class="btn btn-red btn-w" id="go" style="margin-top:10px">Inspect download &amp; redirects</button>`;
    else f.innerHTML = `<div class="drop" id="drop" style="margin-top:10px">📤 Drop ${mode === 'qr' ? 'a QR code' : 'a screenshot'} here or click<div class="small">PNG / JPG, up to 5 MB</div></div><input type="file" id="file" accept="image/*" hidden>`;
  }
  async function scan(fn) {
    $('#busy').hidden = false; show($('#err'), ''); $('#out').innerHTML = '';
    try { const r = await fn(); $('#out').innerHTML = PG.renderResult(r); $('#out').dataset.r = JSON.stringify({ urls: r.urls || [], score: r.score, details: r.details || [] });
      hist.unshift(r); hist.splice(6); renderHist(); loadStats(); }
    catch (e) { show($('#err'), e.message); } finally { $('#busy').hidden = true; }
  }
  function renderHist() {
    $('#hist').innerHTML = hist.map(h => `<div class="hist"><b style="color:${PG.levelOf(h.score)[2]};width:44px">${h.score}%</b><span class="muted small" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(h.text)}</span></div>`).join('') || '<p class="muted">No scans yet.</p>';
  }
  const uploadScan = f => { if (!f) return; const form = new FormData(); form.append('file', f); form.append('mode', mode); scan(() => PG.api('/scan/image', { form })); };
  function loadDash() {
    status(); loadStats(); renderModes(); renderInbox();
  }
  $('#modes').addEventListener('click', e => { const b = e.target.closest('[data-m]'); if (b) { mode = b.dataset.m; renderModes(); } });
  $('#form').addEventListener('click', e => {
    const id = e.target.id;
    if (id === 'sample') { $('#f-sender').value = SAMPLE.sender; $('#f-text').value = SAMPLE.text; }
    if (id === 'drop') $('#file').click();
    if (id !== 'go') return;
    if (mode === 'text') { const text = $('#f-text').value.trim(); if (text) scan(() => PG.api('/scan/text', { body: { text, sender: $('#f-sender').value.trim(), use_llm: $('#f-llm').checked } })); }
    if (mode === 'url') { const url = $('#f-url').value.trim(); if (url) scan(() => PG.api('/scan/url', { body: { url } })); }
    if (mode === 'download') scan(() => PG.api('/scan/download', { body: { filename: $('#f-file').value.trim(), url: $('#f-dl').value.trim() } }));
  });
  $('#form').addEventListener('change', e => { if (e.target.id === 'file') { uploadScan(e.target.files[0]); e.target.value = ''; } });
  $('#form').addEventListener('dragover', e => { if (e.target.id === 'drop') { e.preventDefault(); e.target.classList.add('over'); } });
  $('#form').addEventListener('dragleave', e => { if (e.target.id === 'drop') e.target.classList.remove('over'); });
  $('#form').addEventListener('drop', e => { if (e.target.id === 'drop') { e.preventDefault(); e.target.classList.remove('over'); uploadScan(e.dataTransfer.files[0]); } });
  $('#out').addEventListener('click', async e => {
    const b = e.target.closest('[data-act]'); if (!b) return;
    const r = JSON.parse($('#out').dataset.r || '{}'); if (!(r.urls || []).length) return;
    if (b.dataset.act === 'block') chrome.tabs.create({ url: PG.blockedUrl(r.urls[0], r.score, r.details) });
    if (b.dataset.act === 'report') PG.api('/community/report', { body: { url: r.urls[0] } }).then(() => { PG.toast('Reported to the community database'); loadStats(); }).catch(x => PG.toast(x.message, 4000));
  });

  /* ----------------------------------------------------------- Gmail inbox */
  async function renderInbox() {
    const { inbox } = await chrome.storage.local.get({ inbox: [] });
    $('#inbox').innerHTML = inbox.slice(0, 6).map(m => { const lv = PG.levelOf(m.score);
      return `<div class="hist"><b style="color:${lv[2]};width:44px">${m.score}%</b><div class="grow" style="min-width:0"><div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(m.subject || '(no subject)')}</div>
      <div class="muted small" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(m.sender)}</div></div></div>`; }).join('');
  }
  const msg = (t, err) => { const el = $('#gm-msg'); el.textContent = t; el.style.color = err ? '#f87171' : ''; };
  $('#gm-connect').onclick = async () => {
    msg('Connecting…'); const r = await chrome.runtime.sendMessage({ type: 'gmailConnect' });
    if (r && r.ok) { msg('🟢 Inbox connected'); $('#gm-connect').textContent = '🟢 Inbox connected'; } else msg((r && r.error) || 'Connection failed', true);
  };
  $('#gm-scan').onclick = async () => {
    msg('Scanning unread mail…'); const r = await chrome.runtime.sendMessage({ type: 'pollNow' });
    if (r && r.ok) { msg(r.result.busy ? 'A scan is already running' : `Scanned ${r.result.scanned} new mail(s), ${r.result.threats} threat(s) found`); renderInbox(); loadStats(); }
    else msg((r && r.error) || 'Scan failed', true);
  };

  /* ---------------------------------------------------------------- radar */
  const ST = { Safe: 'green', Blocked: 'red', Monitoring: 'amber' };
  async function loadRadar() {
    $('#rd-brand').innerHTML = BRANDS.map(b => `<option>${esc(b)}</option>`).join('');
    try { const rows = await PG.api('/typosquat/radar'); $('#rd-body').innerHTML = rows.map(radarRow).join(''); show($('#rd-err'), ''); }
    catch (e) { show($('#rd-err'), e.message); }
  }
  const radarRow = r => `<tr><td class="mono">${esc(r.brand)}</td><td class="mono amber">${esc(r.suspect)}</td>
    <td>${[0, 1, 2, 3].map(k => `<span style="display:inline-block;width:8px;height:15px;margin-right:2px;border-radius:2px;background:${k < Math.min(r.distance, 4) ? '#ef4444' : '#334155'}"></span>`).join('')}
    <b>${esc(r.distance)}</b>${r.normalized_distance !== r.distance ? `<span class="muted small"> → ${esc(r.normalized_distance)} normalized</span>` : ''}</td>
    <td class="muted small">${esc(r.technique || '—')}</td><td><span class="badge b-${ST[r.status] || 'amber'}">${esc(r.status)}</span></td></tr>`;
  $('#rd-go').onclick = async () => {
    const domain = $('#rd-dom').value.trim(); if (!domain) return;
    try { const r = await PG.api('/typosquat/analyze', { body: { brand: $('#rd-brand').value, domain } }); $('#rd-body').insertAdjacentHTML('afterbegin', radarRow(r)); $('#rd-dom').value = ''; show($('#rd-err'), ''); }
    catch (e) { show($('#rd-err'), e.message); }
  };

  /* ------------------------------------------------------------ community */
  const SC = { Active: 'red', Monitoring: 'amber', 'Takedown filed': 'sky', Pending: 'amber' };
  async function loadCommunity() {
    try { const rows = await PG.api('/community');
      $('#cm-list').innerHTML = rows.map(r => `<div class="led">🔗<div class="grow"><div class="mono">${esc(r.url)}</div><div class="muted small">${esc(r.threat_type)}</div></div>
        <span class="badge b-${SC[r.status] || 'amber'}">${esc(r.status)}</span><button class="btn" data-vote="${esc(r.id)}">👥 ${esc(r.report_count)} reports 👍</button></div>`).join('') || '<p class="muted">No reports yet.</p>';
      show($('#cm-err'), ''); } catch (e) { show($('#cm-err'), e.message); }
  }
  $('#cm-list').addEventListener('click', async e => {
    const b = e.target.closest('[data-vote]'); if (!b) return;
    try { await PG.api(`/community/${b.dataset.vote}/upvote`, { method: 'POST' }); loadCommunity(); } catch (x) { show($('#cm-err'), x.message); }
  });
  $('#cm-new').onclick = () => { $('#modal').hidden = false; show($('#m-err'), ''); };
  $('#m-x').onclick = () => { $('#modal').hidden = true; };
  $('#modal').onclick = e => { if (e.target.id === 'modal') $('#modal').hidden = true; };
  $('#m-go').onclick = async () => {
    const url = $('#m-url').value.trim(); if (!url) return;
    try { await PG.api('/community/report', { body: { url, threat_type: $('#m-type').value } }); $('#m-url').value = ''; $('#modal').hidden = true; loadCommunity(); }
    catch (e) { show($('#m-err'), e.message); }
  };

  /* ------------------------------------------------------------ downloads */
  const dlRow = d => { const lv = PG.levelOf(d.score != null ? d.score : (d.risk === 'Low Risk' ? 0 : 99));
    return `<tr><td class="mono">${esc(d.filename)}</td><td class="mono muted small">${esc(d.source)} (${esc(d.hops)} hops)</td><td class="mono amber">${esc(d.finalDomain)}</td>
    <td><span class="badge b-${lv[3]}">${esc(d.risk)}</span></td><td><b class="small">${esc(d.status)}</b></td></tr>`; };
  async function loadDownloads() {
    try { const rows = await PG.api('/downloads'); $('#dl-body').innerHTML = rows.map(dlRow).join('') || '<tr><td colspan="5" class="muted" style="text-align:center">No inspections yet. Download something or run one above.</td></tr>'; show($('#dl-err'), ''); }
    catch (e) { show($('#dl-err'), e.message); }
  }
  $('#dl-go').onclick = async () => {
    const filename = $('#dl-f').value.trim(), url = $('#dl-u').value.trim(); if (!filename || !url) return;
    try { await PG.api('/scan/download', { body: { filename, url } }); loadDownloads(); show($('#dl-err'), ''); } catch (e) { show($('#dl-err'), e.message); }
  };

  /* ------------------------------------------------------------- settings */
  async function loadSettings() {
    const c = await PG.getCfg();
    $('#s-api').value = c.apiBase; $('#s-key').value = c.apiKey; $('#s-th').value = c.blockThreshold; $('#s-th-v').textContent = c.blockThreshold;
    $('#s-auto').checked = c.autoProtect; $('#s-dl').checked = c.downloadGuard;
    const l = await chrome.storage.local.get({ blockedPages: 0, blockedDownloads: 0 });
    $('#s-sum').textContent = `${l.blockedPages} page(s) and ${l.blockedDownloads} download(s) blocked on this browser.`;
  }
  $('#s-th').oninput = e => { $('#s-th-v').textContent = e.target.value; };
  $('#s-save').onclick = async () => {
    await chrome.storage.local.set({ apiBase: $('#s-api').value.trim() || PG.DEFAULTS.apiBase, apiKey: $('#s-key').value, blockThreshold: Number($('#s-th').value),
      autoProtect: $('#s-auto').checked, downloadGuard: $('#s-dl').checked });
    $('#s-msg').textContent = '✅ Saved'; status();
  };
  $('#s-test').onclick = async () => {
    try { const h = await PG.api('/health'); $('#s-msg').textContent = `🟢 Connected: v${h.version}, store=${h.store}, AI=${h.llm.available ? h.llm.model : 'off'}`; }
    catch (e) { $('#s-msg').textContent = '🔴 ' + e.message; }
  };

  route();
});
