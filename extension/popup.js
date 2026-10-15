document.addEventListener('DOMContentLoaded', async () => {
  const $ = s => document.querySelector(s);
  let last = null;

  /* ---- status + footer ---- */
  async function refresh() {
    try {
      const h = await PG.api('/health');
      $('#status').innerHTML = `<span class="dot on"></span>Online · AI ${h.llm && h.llm.available ? 'on' : 'off'}`;
      const s = await PG.api('/stats');
      $('#foot').textContent = `${Number(s.blocked).toLocaleString()} threats blocked`;
    } catch {
      $('#status').innerHTML = '<span class="dot off"></span>Offline';
      $('#foot').textContent = 'Backend offline';
    }
  }
  refresh();

  /* ---- toggles ---- */
  const cfg = await PG.getCfg();
  $('#t-auto').checked = cfg.autoProtect;
  $('#t-dl').checked = cfg.downloadGuard;
  $('#t-auto').onchange = e => chrome.storage.local.set({ autoProtect: e.target.checked });
  $('#t-dl').onchange = e => chrome.storage.local.set({ downloadGuard: e.target.checked });

  /* ---- tabs ---- */
  $('#tabs').addEventListener('click', e => {
    const t = e.target.closest('.tab'); if (!t) return;
    document.querySelectorAll('.tab').forEach(x => x.classList.toggle('on', x === t));
    document.querySelectorAll('.pane').forEach(p => p.classList.toggle('on', p.dataset.pane === t.dataset.tab));
    $('#out').innerHTML = ''; $('#err').hidden = true;
  });

  /* ---- generic scan runner ---- */
  async function run(fn) {
    $('#busy').hidden = false; $('#err').hidden = true; $('#out').innerHTML = '';
    try { last = await fn(); $('#out').innerHTML = PG.renderResult(last, { compact: true }); refresh(); }
    catch (e) { $('#err').textContent = e.message; $('#err').hidden = false; }
    finally { $('#busy').hidden = true; }
  }

  $('#scan-text').onclick = () => { const text = $('#txt').value.trim(); if (text) run(() => PG.api('/scan/text', { body: { text, use_llm: $('#use-llm').checked } })); };
  $('#demo-text').onclick = () => { $('#txt').value = 'URGENT: Your PayPal account is locked. Verify your password at http://paypa1-secure-login.xyz now'; };
  $('#scan-url').onclick = () => { const url = $('#url').value.trim(); if (url) run(() => PG.api('/scan/url', { body: { url } })); };
  $('#url').addEventListener('keydown', e => { if (e.key === 'Enter') $('#scan-url').click(); });
  $('#cur-tab').onclick = async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) { $('#url').value = tab.url; $('#scan-url').click(); }
  };
  $('#scan-dl').onclick = () => { const filename = $('#dl-file').value.trim(), url = $('#dl-url').value.trim(); if (filename && url) run(() => PG.api('/scan/download', { body: { filename, url } })); };

  /* ---- image / QR upload ---- */
  const pick = f => {
    if (!f) return;
    const form = new FormData(); form.append('file', f); form.append('mode', $('#img-mode').value);
    run(() => PG.api('/scan/image', { form }));
  };
  $('#drop').onclick = () => $('#file').click();
  $('#file').onchange = e => { pick(e.target.files[0]); e.target.value = ''; };
  $('#drop').ondragover = e => { e.preventDefault(); $('#drop').classList.add('over'); };
  $('#drop').ondragleave = () => $('#drop').classList.remove('over');
  $('#drop').ondrop = e => { e.preventDefault(); $('#drop').classList.remove('over'); pick(e.dataTransfer.files[0]); };

  /* ---- reporting ---- */
  const report = (url, type = 'Credential phishing') =>
    PG.api('/community/report', { body: { url, threat_type: type } }).then(() => PG.toast('Reported to the community database')).catch(e => PG.toast(e.message, 4000));
  $('#rep-btn').onclick = () => { const u = $('#rep-url').value.trim(); if (u) report(u, $('#rep-type').value).then(() => ($('#rep-url').value = '')); };

  /* ---- result actions (delegated) ---- */
  $('#out').addEventListener('click', async e => {
    const b = e.target.closest('[data-act]'); if (!b || !last || !(last.urls || []).length) return;
    if (b.dataset.act === 'report') report(last.urls[0]);
    if (b.dataset.act === 'block') {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const target = PG.blockedUrl(last.urls[0], last.score, last.details);
      if (tab) chrome.tabs.update(tab.id, { url: target }); else chrome.tabs.create({ url: target });
      window.close();
    }
  });

  $('#open-dash').onclick = () => { chrome.tabs.create({ url: chrome.runtime.getURL('app.html') }); window.close(); };
});
