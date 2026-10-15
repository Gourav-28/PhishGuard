# PhishGuard AI: Chrome extension + FastAPI backend

Real-time phishing, scam, malicious-URL and download protection for Gmail and the web.
Fast rule-based engine (typosquatting, homoglyphs, header spoofing, redirects) **plus an optional local LLM** (Ollama) as a second opinion. Everything runs on your machine.

```
phishguard-ai/
├── backend/      FastAPI service (detection engine, Ollama layer, Supabase/in-memory store)
└── extension/    Manifest V3 extension (popup, dashboard, block page, service worker, Gmail scanner)
```

## 1. Start the backend
```bash
cd backend
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                   # works as-is (in-memory store, no Supabase needed)
python -m uvicorn app.main:app --reload                # http://localhost:8000/docs
```
Optional: `sudo apt install tesseract-ocr libzbar0` (screenshot OCR + QR codes). Without them the API falls back cleanly.

**Optional local AI** (adds the "🤖 AI verdict" signal and reasoning):
```bash
ollama pull llama3.2        # then keep Ollama running; the backend auto-detects it
```
The LLM can only **add** risk. A prompt-injected "this is safe" reply can never lower a score, and its output is strictly parsed and clamped.

**Supabase (optional):** run `backend/schema.sql` in the SQL editor, then set `SUPABASE_URL` + `SUPABASE_SERVICE_KEY` in `.env`.

## 2. Load the extension
1. Chrome → `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select the `extension/` folder.
2. Pin the 🛡️ icon. The popup header shows **Online / Offline** and whether AI is on.
3. Open the dashboard from the popup ("Open dashboard →"). Backend URL and options are under **Settings**.

## 3. What it does
| Feature | How it works |
|---|---|
| **Auto-protect browsing** | Each main-frame navigation is checked (`/scan/url`, passive: not counted in stats). Score ≥ threshold (default 70) → redirected to the warning page. Trusted, private and non-http URLs are skipped. **Fails open** if the backend is down. 10-min cache. |
| **Warning page** | "Back to safety", report site, or proceed for 30 min (allow-list). Navigates only to http(s) URLs. |
| **Download guard** | Every download is paused → scanned (extension, double extension, redirect chain from Chrome's `finalUrl`) → cancelled or resumed. The server never re-fetches the link, so one-time download URLs aren't consumed. |
| **Gmail live scan** | Open an email: banner above it (red / amber / green). Checks sender spoofing, display-name brand spoofing, Reply-To mismatch, SPF/DKIM/DMARC results, link-text vs real-destination mismatch (Gmail's `google.com/url?q=` wrappers are unwrapped), typosquatted domains and local AI. |
| **Inbox Guard** | Every 15 min, new unread mail (max 5 per run, de-duplicated) is scanned with full headers; threats trigger a notification. "Scan inbox now" in the dashboard. |
| **Right-click** | "Scan link" / "Scan selected text" with PhishGuard AI. |
| **Dashboard** | Multi-modal scanner (text/email, screenshot OCR, QR, URL, download), live stats, typosquat radar, community threat DB (report + upvote), downloads monitor, settings. |

## 4. Gmail sign-in (one-time setup)
`chrome.identity` needs an OAuth client of type **Chrome Extension** tied to *your* extension ID:
1. Google Cloud Console → enable the **Gmail API** → OAuth consent screen (add yourself as a test user).
2. Credentials → Create OAuth client ID → **Chrome extension** → paste the extension ID from `chrome://extensions`.
3. Put the client ID in `extension/manifest.json` (`oauth2.client_id`).
4. To keep the extension ID stable across machines/reloads, add a `"key"` to the manifest (public key from the Chrome Web Store developer dashboard or a generated key pair).

Without this, everything except Inbox Guard still works. The live Gmail banner needs no sign-in.

## 5. Tests
```bash
cd backend && pip install pytest && pytest        # 16 detection tests + API tests
```
`tests/test_api.py` needs FastAPI installed. The extension's service worker was exercised against a mocked `chrome` API (navigation blocking, trusted/private skips, fail-open, allow-list, download guard, Gmail MIME parsing, XSS escaping).

## 6. Security design
- **Fail open:** an offline backend never blocks browsing or downloads.
- **No `innerHTML` with untrusted text:** backend and email content is HTML-escaped (dashboard/popup) or inserted with `textContent` (Gmail banner, block page).
- **SSRF-guarded tracing:** private/loopback/link-local targets refused; headers only.
- **Poisoning-resistant community DB:** one vote per hashed reporter, genuine brand domains can't be reported, ≥3 reports to count as "flagged".
- **Privacy:** with a local backend, nothing leaves your machine. If you host the backend remotely, turn off *Auto-protect browsing* (it sends the URLs you visit).
- Optional `API_KEY` on the backend (set the same key in Settings). `ALLOWED_ORIGINS=["*"]` is safe here (no cookies) but protect remote deployments.

## 7. Troubleshooting
| Symptom | Fix |
|---|---|
| Popup says **Offline** | Start the backend; check Settings → *Test connection*. |
| Gmail shows "backend offline" banner | Same, and reload the Gmail tab after reloading the extension. |
| Inbox Guard "Connection failed" | Complete §4 (client ID must match your extension ID). |
| Screenshot scan says OCR unavailable | Install `tesseract-ocr` (or accept the flagged *simulated* demo result). |
| Gmail banner missing | Gmail's CSS classes (`.a3s.aiL`, `.gD`, `h2.hP`) change occasionally; update `content.js`. |
