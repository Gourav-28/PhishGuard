(() => {
  const $ = s => document.querySelector(s);
  const q = new URLSearchParams(location.search);
  const url = q.get('u') || '', score = Math.max(0, Math.min(99, parseInt(q.get('s'), 10) || 0));
  let reasons = []; try { reasons = JSON.parse(q.get('d') || '[]').filter(x => typeof x === 'string').slice(0, 4); } catch {}
  let host = url; try { host = new URL(url).hostname; } catch {}
  const safeHttp = /^https?:\/\//i.test(url);          // never navigate to javascript:/data: URLs from the query string

  $('#host').textContent = host || 'this site';
  $('#full').textContent = url;
  $('#meter').innerHTML = PG.meter(score, 100);       // numeric only
  if (!reasons.length) reasons = ['Flagged by PhishGuard AI threat analysis.'];
  reasons.forEach(r => { const li = document.createElement('li'); li.textContent = r; $('#reasons').appendChild(li); });

  $('#back').onclick = () => (history.length > 1 ? history.back() : chrome.tabs.update({ url: 'chrome://newtab/' }));
  $('#more').onclick = () => { const d = $('#detail'); d.hidden = !d.hidden; $('#more').textContent = d.hidden ? 'Show details' : 'Hide details'; };
  $('#report').onclick = async () => {
    if (!safeHttp) return;
    try { await PG.api('/community/report', { body: { url, threat_type: 'Credential phishing' } }); PG.toast('Thanks, reported to the community database'); }
    catch (e) { PG.toast(e.message, 4000); }
  };
  $('#proceed').onclick = async () => {
    if (!safeHttp) return;
    await chrome.runtime.sendMessage({ type: 'allow', host });
    location.href = url;
  };
})();
