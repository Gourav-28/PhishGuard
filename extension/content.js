/* PhishGuard AI - Gmail content script. Scans the e-mail you open and shows a banner above it.
   All backend calls go through the service worker (no CORS / mixed-content issues inside Gmail).
   Banner text is built with textContent only: e-mail content is attacker-controlled. */
(() => {
  const scanned = new WeakSet();
  let timer = null;
  const SLD = new Set(['co', 'com', 'org', 'net', 'gov', 'ac']);
  const regDomain = h => { const p = h.toLowerCase().split('.'); if (p.length <= 2) return h.toLowerCase(); return p.slice(SLD.has(p[p.length - 2]) && p[p.length - 1].length === 2 ? -3 : -2).join('.'); };

  // Gmail wraps links as google.com/url?q=<real>; unwrap so we judge the real destination
  function unwrap(href) {
    try { const u = new URL(href); if (/(^|\.)google\.com$/.test(u.hostname) && u.pathname === '/url') return u.searchParams.get('q') || u.searchParams.get('url') || href; } catch {}
    return href;
  }
  const looksLikeDomain = t => /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/\S*)?$/i.test(t.trim());

  function collectLinks(body) {
    const urls = new Set(), mism = [];
    body.querySelectorAll('a[href]').forEach(a => {
      const real = unwrap(a.href);
      if (!/^https?:/i.test(real)) return;
      urls.add(real);
      const txt = (a.textContent || '').trim();
      if (!looksLikeDomain(txt)) return;
      try {
        const shown = new URL(/^https?:/i.test(txt) ? txt : 'http://' + txt).hostname, actual = new URL(real).hostname;
        if (regDomain(shown) !== regDomain(actual)) {
          mism.push(`Link text "${txt.slice(0, 50)}" actually goes to ${actual}`);
          a.style.outline = '2px solid #ef4444'; a.title = `PhishGuard: link text does not match its destination (${actual})`;
        }
      } catch {}
    });
    return { urls: [...urls].slice(0, 40), mism };
  }

  function banner(body, tone, title, lines) {
    body.querySelector(':scope > .phishguard-banner')?.remove();
    const C = { red: ['#7f1d1d', '#ef4444', '#fecaca'], amber: ['#78350f', '#f59e0b', '#fde68a'], green: ['#064e3b', '#10b981', '#a7f3d0'], gray: ['#1e293b', '#64748b', '#cbd5e1'] }[tone];
    const el = document.createElement('div');
    el.className = 'phishguard-banner';
    el.style.cssText = `background:${C[0]};border:2px solid ${C[1]};color:${C[2]};padding:10px 14px;margin-bottom:12px;border-radius:8px;font:13px/1.45 Arial,sans-serif;position:relative;z-index:5`;
    const h = document.createElement('div'); h.style.cssText = 'font-weight:bold;font-size:14px'; h.textContent = title; el.appendChild(h);
    lines.filter(Boolean).slice(0, 5).forEach(t => { const d = document.createElement('div'); d.style.marginTop = '4px'; d.textContent = t; el.appendChild(d); });
    body.prepend(el);
  }

  async function analyze(body) {
    const text = (body.innerText || '').trim();
    if (!text) return;                       // not rendered yet: retry on the next mutation
    scanned.add(body);
    const root = body.closest('.adn') || document;
    const s = root.querySelector('.gD') || document.querySelector('.gD');
    const name = s?.getAttribute('name') || s?.innerText || '', email = s?.getAttribute('email') || '';
    const sender = name && email ? `${name} <${email}>` : email || name || '';
    const subject = document.querySelector('h2.hP')?.innerText || '';
    const { urls, mism } = collectLinks(body);
    let resp;
    try { resp = await chrome.runtime.sendMessage({ type: 'scanEmail', payload: { text: text.slice(0, 8000), sender, subject, urls, use_llm: true } }); }
    catch { return; }                        // extension reloaded: stale content script, ignore
    if (!resp || !resp.ok) { banner(body, 'gray', '🛡️ PhishGuard AI: backend offline, this e-mail was not scanned', [resp?.error]); return; }
    const r = resp.result, why = [...(r.details || []), ...mism];
    if (r.score >= 60) banner(body, 'red', `🚨 PHISHING THREAT DETECTED (${r.score}%)`, ['Do not click links or share credentials.', ...why]);
    else if (r.score >= 35 || mism.length) banner(body, 'amber', `⚠️ Suspicious e-mail (${r.score}%)`, why);
    else banner(body, 'green', `🛡️ PhishGuard AI: no threats detected (${r.score}%)`, []);
  }

  const scan = () => document.querySelectorAll('.a3s.aiL').forEach(b => { if (!scanned.has(b)) analyze(b); });
  new MutationObserver(() => { clearTimeout(timer); timer = setTimeout(scan, 700); }).observe(document.body, { childList: true, subtree: true });
  scan();
})();
