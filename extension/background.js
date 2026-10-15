/* PhishGuard AI service worker (MV3).
   - blocks malicious navigations (webNavigation) - fails OPEN if the backend is down
   - guards downloads (pause -> scan -> cancel / resume)
   - polls Gmail (unread) with de-duplication, scans each new mail with headers + local AI
   - proxies content-script scans (so Gmail's page never talks to localhost directly)
   - right-click "Scan link / selected text" */
importScripts('shared.js');

const TRUSTED = ['google.com', 'youtube.com', 'github.com', 'microsoft.com', 'live.com', 'office.com', 'apple.com', 'amazon.com',
  'paypal.com', 'wikipedia.org', 'facebook.com', 'instagram.com', 'linkedin.com', 'netflix.com', 'dropbox.com', 'zoom.us',
  'slack.com', 'whatsapp.com', 'mozilla.org', 'stackoverflow.com', 'x.com', 'twitter.com', 'claude.ai', 'anthropic.com', 'openai.com'];
const CACHE_MS = 10 * 60 * 1000, ALLOW_MS = 30 * 60 * 1000;

const sget = async (k, d) => (await chrome.storage.session.get({ [k]: d }))[k];
const sset = (k, v) => chrome.storage.session.set({ [k]: v });
const notify = (title, message) => chrome.notifications.create({ type: 'basic', iconUrl: 'icons/icon128.png', title, message, priority: 2 });
async function bump(key) { const o = await chrome.storage.local.get({ [key]: 0 }); await chrome.storage.local.set({ [key]: o[key] + 1 }); }

function isPrivateHost(h) {
  return h === 'localhost' || h.startsWith('[') || !h.includes('.') || /\.(local|internal|lan)$/.test(h) ||
    /^(127\.|10\.|192\.168\.|169\.254\.)/.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h);
}
const isTrusted = h => TRUSTED.some(d => h === d || h.endsWith('.' + d));
const skipUrl = u => !/^https?:$/.test(u.protocol) || isPrivateHost(u.hostname) || isTrusted(u.hostname);

/* ------------------------------------------------------------------ navigation guard */
chrome.webNavigation.onBeforeNavigate.addListener(async d => {
  if (d.frameId !== 0) return;
  try {
    const cfg = await PG.getCfg();
    if (!cfg.autoProtect) return;
    const u = new URL(d.url);
    if (skipUrl(u)) return;
    const allow = await sget('allow', {});
    if ((allow[u.hostname] || 0) > Date.now()) return;
    const cache = await sget('cache', {});
    let hit = cache[u.hostname];
    if (!hit || Date.now() - hit.t > CACHE_MS) {
      const r = await PG.api('/scan/url', { body: { url: d.url, passive: true } });   // passive = not counted in stats
      hit = { score: r.score, details: r.details, t: Date.now() };
      cache[u.hostname] = hit;
      const keep = Object.entries(cache).filter(([, v]) => Date.now() - v.t < CACHE_MS).slice(-300);
      await sset('cache', Object.fromEntries(keep));
    }
    if (hit.score >= cfg.blockThreshold) {
      await bump('blockedPages');
      await chrome.tabs.update(d.tabId, { url: PG.blockedUrl(d.url, hit.score, hit.details) });
    }
  } catch { /* backend offline or tab gone: fail open, never break browsing */ }
});

/* ---------------------------------------------------------------------- download guard */
chrome.downloads.onCreated.addListener(async item => {
  try {
    const cfg = await PG.getCfg();
    if (!cfg.downloadGuard || !/^https?:/i.test(item.url)) return;
    await chrome.downloads.pause(item.id).catch(() => {});
    let verdict = null;
    try {
      const finalUrl = item.finalUrl && item.finalUrl !== item.url ? item.finalUrl : null;
      const name = (item.filename || '').split(/[\\/]/).pop() || decodeURIComponent(new URL(finalUrl || item.url).pathname.split('/').pop() || 'download');
      // trace:false + final_url: the browser already knows the redirect result, so the server never re-fetches the link
      verdict = await PG.api('/scan/download', { body: { filename: name, url: item.url, final_url: finalUrl, trace: false } });
    } catch { /* fail open */ }
    if (verdict && verdict.score >= 60) {
      await chrome.downloads.cancel(item.id);
      await bump('blockedDownloads');
      notify(`🚫 PhishGuard blocked a download (${verdict.score}%)`, `${verdict.filename}\n${(verdict.details || [])[0] || (verdict.badges[0] || [])[2] || 'Suspicious file'}`);
    } else {
      await chrome.downloads.resume(item.id).catch(() => {});
    }
  } catch { try { await chrome.downloads.resume(item.id); } catch {} }
});

/* ------------------------------------------------------------------------ Gmail polling */
const gmailToken = interactive => new Promise((res, rej) =>
  chrome.identity.getAuthToken({ interactive }, t => (chrome.runtime.lastError || !t) ? rej(new Error(chrome.runtime.lastError?.message || 'Not signed in')) : res(t)));

async function gmailGet(url, token) {
  const r = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
  if (r.status === 401) { await new Promise(ok => chrome.identity.removeCachedAuthToken({ token }, ok)); throw new Error('Gmail session expired: reconnect your inbox'); }
  if (!r.ok) throw new Error('Gmail API error ' + r.status);
  return r.json();
}
function b64(s) { const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/')); return new TextDecoder().decode(Uint8Array.from(bin, c => c.charCodeAt(0))); }
function extractBody(payload) {
  let plain = '', html = '';
  (function walk(p) {
    if (p.mimeType === 'text/plain' && p.body?.data) plain += b64(p.body.data);
    else if (p.mimeType === 'text/html' && p.body?.data) html += b64(p.body.data);
    (p.parts || []).forEach(walk);
  })(payload);
  const links = [...html.matchAll(/href\s*=\s*["']([^"']+)["']/gi)].map(m => m[1]).concat(plain.match(/https?:\/\/[^\s<>"']+/g) || []).filter(u => /^https?:/i.test(u));
  const text = plain || html.replace(/<(style|script)[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ');
  return { text: text.trim().slice(0, 6000), links: [...new Set(links)] };
}

let polling = false;
async function pollInbox(interactive = false) {
  if (polling) return { scanned: 0, threats: 0, busy: true };
  polling = true;
  const { seen, inbox } = await chrome.storage.local.get({ seen: [], inbox: [] });
  let scanned = 0, threats = 0;
  try {
    const token = await gmailToken(interactive);
    const list = await gmailGet('https://www.googleapis.com/gmail/v1/users/me/messages?q=is:unread&maxResults=10', token);
    for (const m of (list.messages || []).filter(m => !seen.includes(m.id)).slice(0, 5)) {
      const msg = await gmailGet(`https://www.googleapis.com/gmail/v1/users/me/messages/${m.id}?format=full`, token);
      const h = n => (msg.payload.headers || []).find(x => x.name.toLowerCase() === n)?.value || '';
      const { text, links } = extractBody(msg.payload);
      const r = await PG.api('/scan/gmail', { body: { text: text || msg.snippet || '', sender: h('from'), subject: h('subject'), reply_to: h('reply-to'),
        auth_results: h('authentication-results'), urls: links.slice(0, 30), use_llm: true } });
      seen.push(m.id); scanned++;
      inbox.unshift({ id: m.id, sender: h('from'), subject: h('subject'), score: r.score, level: r.level, reason: (r.details || [])[0] || '', ts: Date.now() });
      if (r.is_phishing) { threats++; notify(`🚨 PhishGuard: phishing email (${r.score}%)`, `From: ${h('from')}\nSubject: ${h('subject')}\n\n${(r.details || [])[0] || 'Suspicious patterns'}`); }
    }
    return { scanned, threats };
  } finally {
    polling = false;
    await chrome.storage.local.set({ seen: seen.slice(-300), inbox: inbox.slice(0, 25) });   // persist even if a later step failed
  }
}

/* ---------------------------------------------------------------- lifecycle + messages */
function setup() {
  chrome.alarms.create('pollInbox', { periodInMinutes: 15 });
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: 'pg-link', title: 'Scan link with PhishGuard AI', contexts: ['link'] });
    chrome.contextMenus.create({ id: 'pg-sel', title: 'Scan selected text with PhishGuard AI', contexts: ['selection'] });
  });
}
chrome.runtime.onInstalled.addListener(setup);
chrome.runtime.onStartup.addListener(() => pollInbox(false).catch(() => {}));
chrome.alarms.onAlarm.addListener(a => { if (a.name === 'pollInbox') pollInbox(false).catch(e => console.log('Inbox poll skipped:', e.message)); });

chrome.contextMenus.onClicked.addListener(async info => {
  try {
    const r = info.menuItemId === 'pg-link'
      ? await PG.api('/scan/url', { body: { url: info.linkUrl } })
      : await PG.api('/scan/text', { body: { text: info.selectionText.slice(0, 5000) } });
    notify(`${r.is_phishing ? '🚨 Threat' : r.score >= 35 ? '⚠️ Suspicious' : '✅ Looks safe'}: ${r.score}% (${r.level})`,
      (r.details || [])[0] || (r.badges[0] || [])[2] || 'No known threat patterns');
  } catch (e) { notify('PhishGuard AI', e.message); }
});

chrome.runtime.onMessage.addListener((msg, sender, send) => {
  const reply = p => p.then(r => send({ ok: true, result: r })).catch(e => send({ ok: false, error: e.message }));
  if (msg.type === 'scanEmail') { reply(PG.api('/scan/gmail', { body: msg.payload })); return true; }
  if (msg.type === 'allow') {
    reply((async () => { const a = await sget('allow', {}); a[msg.host] = Date.now() + ALLOW_MS; await sset('allow', a); return true; })()); return true;
  }
  if (msg.type === 'gmailConnect') { reply(gmailToken(true).then(() => true)); return true; }
  if (msg.type === 'pollNow') { reply(pollInbox(true)); return true; }
  return false;
});
