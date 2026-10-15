"""PhishGuard AI: security & classification engine.

Sections: 1 domain utils | 2 typosquat radar | 3 URL signals | 4 text/SMS signals | 5 scoring
          6 download inspection (redirect tracing) | 7 image OCR / QR | 8 public scan_* entry points

Every signal is a tuple (weight 0-1, badge colour, lucide icon, label). Signals are de-duplicated
by label and combined with a noisy-OR:  score = 1 - prod(1 - w_i), capped at 99%.
The module is storage-agnostic: community intelligence is injected as `lookup(domain) -> row | None`.
"""
import ipaddress
import logging
import re
import socket
from email.utils import parseaddr
from io import BytesIO
from typing import Callable, Dict, List, NamedTuple, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from PIL import Image

from . import config

log = logging.getLogger("phishguard.detection")
Signal = Tuple[float, str, str, str]
Lookup = Callable[[str], Optional[dict]]


class ScanError(Exception):
    """Raised for client-visible scan failures; main.py maps it to an HTTP error."""
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status, self.message = status, message


# ============================================================ 1. domain utilities
BRAND_DOMAINS = ["paypal.com", "google.com", "amazon.com", "microsoft.com", "netflix.com", "github.com",
                 "apple.com", "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com", "dropbox.com",
                 "sbi.co.in", "hdfcbank.com", "icicibank.com"]
PHISH_WORDS = {"secure", "security", "login", "signin", "verify", "verification", "update", "account", "support",
               "help", "service", "services", "refund", "billing", "wallet", "pay", "payment", "confirm", "alert",
               "kyc", "gift", "free", "reward", "official", "online", "recover", "unlock", "id", "portal"}
SUS_TLDS = {"xyz", "top", "ru", "tk", "ml", "ga", "cf", "gq", "click", "link", "icu", "buzz", "zip", "mov", "cfd", "sbs", "rest"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly", "ow.ly", "shorturl.at", "tiny.cc", "rb.gy"}
# Multi-part / private public-suffixes (so user.github.io is its own "registered domain"). Extend as needed.
MULTI_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "gov.in", "ac.in", "in.net",
                  "co.jp", "com.au", "net.au", "org.au", "com.br", "com.mx", "com.cn", "com.tr", "co.nz", "co.za",
                  "com.sg", "com.hk", "github.io", "gitlab.io", "blogspot.com", "pages.dev", "vercel.app",
                  "netlify.app", "web.app", "herokuapp.com", "workers.dev", "000webhostapp.com"}

_L = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "@": "a"}
_HOMO_L, _HOMO_I = str.maketrans(_L), str.maketrans({**_L, "1": "i"})
_CONF = str.maketrans({"\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x",
                       "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u03bf": "o", "\u03b1": "a"})  # Cyrillic/Greek look-alikes

LEVELS = [(80, "Critical", "red"), (60, "High", "orange"), (35, "Medium", "amber"), (0, "Low", "emerald")]


def level(score: int) -> Tuple[int, str, str]:
    return next(l for l in LEVELS if score >= l[0])


def lev(a: str, b: str) -> int:
    """Levenshtein edit distance."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def variants(label: str) -> set:
    """Plausible 'real' spellings of a label after undoing homoglyph tricks (digits, Cyrillic, punycode, rn->m)."""
    s = label.lower()
    if s.startswith("xn--"):
        try:
            s = s.encode("ascii").decode("idna")
        except UnicodeError:
            pass
    s = s.translate(_CONF)
    out = {s.translate(_HOMO_L), s.translate(_HOMO_I)}
    return out | {v.replace("rn", "m").replace("vv", "w") for v in out}


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class Host(NamedTuple):
    subdomain: str
    label: str
    suffix: str


def split_host(host: str) -> Host:
    host = host.lower().strip(".")
    parts = host.split(".")
    if is_ip(host) or len(parts) < 2:
        return Host("", host, "")
    n = 2 if ".".join(parts[-2:]) in MULTI_SUFFIXES else 1
    if len(parts) <= n:
        return Host("", host, "")
    return Host(".".join(parts[:-n - 1]), parts[-n - 1], ".".join(parts[-n:]))


def registered(host: str) -> str:
    h = split_host(host)
    return f"{h.label}.{h.suffix}" if h.suffix else host.lower()


def _tld(h: Host) -> str:
    return h.suffix.split(".")[-1] if h.suffix else ""


BRAND_ITEMS = [(d, split_host(d).label) for d in BRAND_DOMAINS]


def parse_url(raw: str):
    """-> (ParseResult, host, had_explicit_scheme) or None."""
    raw = raw.strip()
    explicit = "://" in raw
    try:
        p = urlparse(raw if explicit else "http://" + raw)
        host = (p.hostname or "").lower().rstrip(".")
        _ = p.port
    except ValueError:
        return None
    return (p, host, explicit) if host else None


def normalize_url(raw: str) -> str:
    parsed = parse_url(raw)
    if not parsed:
        return raw.strip()[:2048]
    p, host, _ = parsed
    port = f":{p.port}" if p.port else ""
    q = f"?{p.query}" if p.query else ""
    return f"{host}{port}{p.path.rstrip('/')}{q}"[:2048]


# ================================================= 2. typosquatting / look-alike radar
_W = {"Brand in subdomain": .7, "Homoglyph substitution": .8, "Combo-squatting": .7, "TLD swap": .5, "Look-alike spelling": .45}


def _combo(v: str, b: str) -> bool:
    toks = [t for t in re.split(r"[^a-z0-9]+", v) if t]
    if b in toks and any(t in PHISH_WORDS for t in toks if t != b):
        return True
    return len(b) >= 5 and any(v in (b + w, w + b) for w in PHISH_WORDS)


def match_brand(host: str) -> Optional[dict]:
    """Best brand-impersonation match for a hostname, or None. Genuine brand domains never match."""
    h, reg = split_host(host), registered(host)
    if not h.suffix or reg in BRAND_DOMAINS:
        return None
    label, sub, vs = h.label, h.subdomain, variants(h.label)
    best = None
    for b_dom, b in BRAND_ITEMS:
        techs: List[str] = []
        if sub and (b_dom in host or b in re.split(r"[.\-]", sub)):
            techs.append("Brand in subdomain")
        for v in vs:
            if v == b:
                if label != b:
                    techs.append("Homoglyph substitution")
                elif len(b) >= 4 and _tld(h) in SUS_TLDS:
                    techs.append("TLD swap")
            elif _combo(v, b):
                techs.append("Combo-squatting")
                if b not in label:
                    techs.append("Homoglyph substitution")
        if not techs and len(b) >= 5 and label != b and 0 < min(lev(v, b) for v in vs) <= (1 if len(b) <= 6 else 2):
            techs.append("Look-alike spelling")
        if not techs:
            continue
        techs = list(dict.fromkeys(techs))
        w = min(.92, max(_W[t] for t in techs) + .05 * (len(techs) - 1))
        nd = min(lev(v, b) for v in vs)
        cand = {"brand": b_dom, "techniques": techs, "weight": w, "distance": lev(label, b), "normalized_distance": nd}
        if not best or (w, -nd) > (best["weight"], -best["normalized_distance"]):
            best = cand
    return best


def radar_row(brand: str, suspect: str) -> dict:
    """One row of the Typosquat Radar table (raw + homoglyph-normalised Levenshtein distance + block status)."""
    b, s = split_host(brand), split_host(suspect)
    base = {"brand": brand, "suspect": suspect, "distance": lev(b.label, s.label)}
    if registered(brand) == registered(suspect):
        return {**base, "normalized_distance": 0, "technique": None, "status": "Safe"}
    m = match_brand(suspect)
    if m and m["brand"] == registered(brand):
        return {**base, "normalized_distance": m["normalized_distance"], "technique": ", ".join(m["techniques"]), "status": "Blocked"}
    return {**base, "normalized_distance": base["distance"], "technique": None, "status": "Monitoring"}


_TOK = re.compile(r"[A-Za-z0-9@$]{5,}")


def text_lookalikes(text: str) -> Dict[str, str]:
    """Brand look-alike *words* inside free text (e.g. 'paypa1', 'g00gle') -> brand domain."""
    out: Dict[str, str] = {}
    for tok in {t.lower() for t in _TOK.findall(text)}:
        if not re.search(r"[a-z]", tok) or not re.search(r"[0-9@$]", tok):
            continue
        for v in variants(tok):
            for dom, b in BRAND_ITEMS:
                if v == b and tok != b:
                    out[tok] = dom
    return out


# ====================================================================== 3. URL signals
_KW = re.compile(r"(login|signin|verify|secure|account|update|wallet|confirm|banking)", re.I)


def url_signals(raw: str):
    """-> (signals, registered_domain | None, details, impersonated_brand | None)"""
    parsed = parse_url(raw)
    if not parsed:
        return [], None, [], None
    p, host, explicit = parsed
    h, reg = split_host(host), registered(host)
    if reg in BRAND_DOMAINS and (p.scheme == "https" or not explicit) and "@" not in p.netloc:
        return [], reg, [], None  # genuine brand domain over HTTPS
    s: List[Signal] = []
    det: List[str] = []
    if is_ip(host):
        s.append((.5, "red", "Globe", "Raw IP address host"))
    if "@" in p.netloc:
        s.append((.4, "red", "Link2", "Credentials-in-URL trick"))
    if "xn--" in host:
        s.append((.45, "red", "Languages", "Punycode / IDN homograph"))
    if _tld(h) in SUS_TLDS:
        s.append((.25, "amber", "Globe", "Suspicious TLD"))
    if reg in SHORTENERS:
        s.append((.2, "amber", "Link2", "URL shortener (destination hidden)"))
    if explicit and p.scheme == "http":
        s.append((.1, "amber", "Globe", "No HTTPS"))
    if len([x for x in h.subdomain.split(".") if x]) >= 3:
        s.append((.2, "amber", "Globe", "Deeply nested subdomains"))
    if p.port not in (None, 80, 443):
        s.append((.15, "amber", "Globe", "Non-standard port"))
    if len(raw) > 100:
        s.append((.1, "amber", "Link2", "Unusually long URL"))
    if _KW.search(host + p.path):
        s.append((.2, "amber", "KeyRound", "Phishing keywords in URL"))
    brand = None
    m = match_brand(host)
    if m:
        brand = m["brand"]
        typo = any(t in m["techniques"] for t in ("Homoglyph substitution", "Look-alike spelling", "TLD swap"))
        s.append((m["weight"], "red", "Languages", "Typosquatting detected" if typo else "Brand impersonation"))
        det.append(f"{host} imitates {m['brand']} via {', '.join(m['techniques']).lower()} (edit distance {m['normalized_distance']})")
    return s, reg, det, brand


# ================================================================ 4. text / SMS signals
_URGENCY = re.compile(r"\b(urgent|immediately|within \d+ (hours?|minutes?)|expires? (today|soon)|act now|final notice|last warning|verify|suspend\w*|locked|deactivat\w+|limited time|asap)\b", re.I)
_CRED = re.compile(r"\b(password|passcode|otp|one[- ]time (code|password)|cvv|card number|pin|ssn|social security|bank|login|sign[- ]in|verify your (account|identity)|kyc|aadhaar|pan card)\b", re.I)
_MONEY = re.compile(r"\b(refund|prize|lottery|winner|you('ve| have) won|gift card|bitcoin|crypto|wire transfer|claim your|reward|cashback)\b", re.I)
_THREAT = re.compile(r"\b(legal action|arrest|account (will be )?(closed|terminated)|penalty|police|court)\b", re.I)
_URL_RE = re.compile(r"https?://[^\s<>\"']+|(?<![@\w.-])(?:[a-z0-9-]+\.)+(?:com|net|org|xyz|top|ru|in|io|co|info|biz|click|link|online|site|live|shop|icu|cc|tk)\b(?:/[^\s<>\"']*)?", re.I)


def extract_urls(text: str) -> List[str]:
    return list(dict.fromkeys(u.rstrip(".,;:)!?\"'") for u in _URL_RE.findall(text)))


def text_signals(text: str, has_urls: bool = False):
    """-> (signals, matched_keywords, details)"""
    s: List[Signal] = []
    det: List[str] = []
    kws: List[str] = []
    urg, cred = _URGENCY.search(text), _CRED.search(text)
    for rx in (_URGENCY, _CRED, _MONEY, _THREAT):
        kws += [m.group(0).lower() for m in rx.finditer(text)]
    if urg:
        s.append((.3, "amber", "Clock", "Urgency language"))
    if cred:
        s.append((.25, "amber", "KeyRound", "Credential harvesting"))
    if _MONEY.search(text):
        s.append((.2, "amber", "AlertTriangle", "Money / prize lure"))
    if _THREAT.search(text):
        s.append((.25, "amber", "AlertTriangle", "Threatening language"))
    if urg and cred and has_urls:
        s.append((.2, "red", "ShieldAlert", "Classic phishing pattern"))
    for tok, brand in text_lookalikes(text).items():
        s.append((.7, "red", "Languages", "Typosquatting detected"))
        det.append(f'"{tok}" is a look-alike spelling of {brand}')
    return s, list(dict.fromkeys(kws)), det


# ============================================================ 4b. e-mail header signals
def email_signals(sender: str, reply_to: str = "", auth_results: str = ""):
    """Sender spoofing checks -> (signals, details, domains, brands)."""
    s: List[Signal] = []
    det: List[str] = []
    doms, brands = set(), set()
    name, addr = parseaddr(sender or "")
    dom = addr.rsplit("@", 1)[-1].lower().strip("<> ") if "@" in addr else ""
    if dom:
        reg = registered(dom)
        doms.add(reg)
        m = match_brand(dom)
        if m:
            s.append((m["weight"], "red", "Mail", "Look-alike sender domain"))
            det.append(f"Sender domain {dom} imitates {m['brand']} ({', '.join(m['techniques']).lower()})")
            brands.add(m["brand"])
        if reg not in BRAND_DOMAINS:
            for b_dom, b in BRAND_ITEMS:
                if split_host(dom).label != b and re.search(rf"\b{re.escape(b)}\b", name.lower()):
                    s.append((.55, "red", "Mail", "Display-name brand spoofing"))
                    det.append(f'Sender name "{name}" claims to be {b_dom} but the mail comes from {reg}')
                    brands.add(b_dom)
                    break
        _, rt = parseaddr(reply_to or "")
        if "@" in rt and registered(rt.rsplit("@", 1)[-1].lower()) != reg:
            s.append((.35, "amber", "Mail", "Reply-To differs from sender"))
            det.append(f"Replies go to {rt}, not to the sender's domain")
    ar = (auth_results or "").lower()
    for proto, w in (("spf", .3), ("dkim", .3), ("dmarc", .4)):
        if re.search(rf"\b{proto}=(fail|softfail|permerror)", ar):
            s.append((w, "red", "Mail", f"{proto.upper()} check failed"))
    return s, det, doms, brands


# ========================================================================= 5. scoring
def build_result(signals: Sequence[Signal], text: str, kind: str, urls: List[str], details: Optional[List[str]] = None,
                 domains: Optional[set] = None, brands: Optional[set] = None, keywords: Optional[List[str]] = None) -> dict:
    best: Dict[str, Signal] = {}
    for sig in signals:  # de-duplicate by label, keep the strongest
        if sig[3] not in best or sig[0] > best[sig[3]][0]:
            best[sig[3]] = sig
    ordered = sorted(best.values(), key=lambda x: -x[0])
    p = 1.0
    for w, *_ in ordered:
        p *= 1 - w
    score = max(4, min(99, round(100 * (1 - p))))  # noisy-OR, capped at 99%
    lv = level(score)
    details = list(details or [])
    if not details and score >= 35:
        details = ["Triggered signals: " + ", ".join(l for _, _, _, l in ordered[:4])]
    return {"score": score, "level": lv[1], "risk": f"{lv[1]} Risk", "is_phishing": score >= 60, "ai": None,
            "badges": [[c, i, l] for _, c, i, l in ordered] or [["emerald", "CheckCircle2", "No known threat patterns"]],
            "urls": urls, "text": text[:1000], "kind": kind, "details": details,
            "indicators": {"urls": urls, "domains": sorted(domains or []), "brands": sorted(brands or []), "keywords": (keywords or [])[:20]}}


def _community(lookup: Lookup, domains: set) -> List[Signal]:
    best: Optional[Signal] = None
    for d in domains:
        row = lookup(d)
        if row and row["report_count"] >= 3:  # >=3 distinct reporters
            w = .85 if row["report_count"] >= 25 else .6
            if not best or w > best[0]:
                best = (w, "red", "Database", f"Supabase community flagged ({row['report_count']} reports)")
    return [best] if best else []


def _url_pass(urls: Sequence[str]):
    sigs: List[Signal] = []
    domains, brands, details = set(), set(), []
    for u in list(urls)[:10]:
        s, reg, det, brand = url_signals(u)
        sigs += s
        details += det
        if reg:
            domains.add(reg)
        if brand:
            brands.add(brand)
    return sigs, domains, brands, details


# ====================================================== 6. download inspection (redirects)
DANGEROUS = {"exe", "scr", "bat", "cmd", "msi", "js", "jse", "vbs", "vbe", "ps1", "jar", "apk", "dmg", "iso",
             "lnk", "hta", "dll", "com", "pif", "reg", "wsf", "cpl", "msix", "appx"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt", "zip"}
EXEC_TYPES = {"application/x-msdownload", "application/x-dosexec", "application/vnd.microsoft.portable-executable",
              "application/x-msi", "application/java-archive", "application/vnd.android.package-archive",
              "application/x-sh", "application/x-bat"}
MAX_HOPS, ALLOWED_PORTS = 5, {None, 80, 443, 8080, 8443}


def filename_signals(name: str) -> List[Signal]:
    s: List[Signal] = []
    parts = name.strip().lower().split(".")
    ext = parts[-1] if len(parts) > 1 else ""
    if ext in DANGEROUS:
        s.append((.55, "red", "FileWarning", f"Executable file type (.{ext})"))
    if len(parts) >= 3 and parts[-2] in DOC_EXT and ext in DANGEROUS:
        s.append((.5, "red", "FileWarning", "Double extension disguise"))
    if "\u202e" in name:
        s.append((.6, "red", "FileWarning", "Right-to-left override spoofing"))
    return s


def host_state(host: str) -> str:
    """'public' | 'private' | 'unresolved'. Blocks SSRF into loopback / RFC1918 / link-local / metadata IPs."""
    try:
        for info in socket.getaddrinfo(host, None):
            if not ipaddress.ip_address(info[4][0].split("%")[0]).is_global:
                return "private"
        return "public"
    except (socket.gaierror, ValueError):
        return "unresolved"


def _real_trace(url: str) -> dict:
    """Follow redirects manually, validating every hop. Reads headers only, never the file body."""
    hops, cur, too_many = [], (url if "://" in url else "http://" + url), True
    with httpx.Client(timeout=httpx.Timeout(5.0), follow_redirects=False,
                      headers={"User-Agent": "PhishGuardBot/1.0 (+security-scan)"}) as c:
        for _ in range(MAX_HOPS + 1):
            p = urlparse(cur)
            hop = {"url": cur, "status": None, "content_type": None, "location": None, "error": None, "simulated": False}
            hops.append(hop)
            try:
                bad = p.scheme not in ("http", "https") or not p.hostname or p.port not in ALLOWED_PORTS
            except ValueError:
                bad = True
            if bad:
                hop["error"], too_many = "unsupported_target", False
                break
            state = host_state(p.hostname)
            if state != "public":
                hop["error"], too_many = ("private_address" if state == "private" else "unresolved"), False
                break
            try:
                with c.stream("GET", cur) as r:
                    hop["status"] = r.status_code
                    hop["content_type"] = r.headers.get("content-type", "").split(";")[0].strip().lower()
                    loc = r.headers.get("location")
            except httpx.HTTPError:
                hop["error"], too_many = "request_failed", False
                break
            if r.status_code in (301, 302, 303, 307, 308) and loc:
                cur = urljoin(cur, loc)
                hop["location"] = cur
                continue
            too_many = False
            break
    return {"hops": hops, "too_many": too_many, "simulated": False}


def _mock_trace(url: str) -> dict:
    """Deterministic offline demo chain: shorteners / suspicious TLDs 'redirect' through a tracker to a payload host."""
    u = url if "://" in url else "http://" + url
    host = urlparse(u).hostname or ""
    mk = lambda x, st, ct=None: {"url": x, "status": st, "content_type": ct, "location": None, "error": None, "simulated": True}
    if registered(host) in SHORTENERS or _tld(split_host(host)) in SUS_TLDS:
        hops = [mk(u, 302), mk("http://redirect-hop-track.top/go?ref=1", 302), mk("http://malicious-cdn.xyz/dl/payload", 200, "application/x-msdownload")]
    else:
        hops = [mk(u, 200, "application/octet-stream")]
    return {"hops": hops, "too_many": False, "simulated": True}


def trace(url: str) -> dict:
    mode = config.TRACE_MODE
    if mode == "mock":
        return _mock_trace(url)
    chain = _real_trace(url)
    if mode == "auto" and chain["hops"][0]["error"] in ("unresolved", "request_failed"):
        return _mock_trace(url)  # offline / unreachable demo host -> clearly-flagged simulation
    return chain


def chain_signals(chain: dict) -> List[Signal]:
    hops = chain["hops"]
    n = max(len(hops) - 1, 0)
    s: List[Signal] = []
    if n >= 2:
        s.append((.2, "amber", "Link2", f"Multi-hop redirect chain ({n} hops)"))
    if chain["too_many"]:
        s.append((.35, "red", "Link2", "Excessive redirects"))
    if n >= 1 and registered(urlparse(hops[0]["url"]).hostname or "") != registered(urlparse(hops[-1]["url"]).hostname or ""):
        s.append((.2, "amber", "Globe", "Cross-domain redirect"))
    err = hops[-1]["error"]
    if err == "private_address":
        s.append((.5, "red", "Ban", "Redirects into a private/internal address"))
    elif err == "unresolved":
        s.append((.1, "amber", "Globe", "Destination did not resolve"))
    if hops[-1]["content_type"] in EXEC_TYPES:
        s.append((.4, "red", "FileWarning", "Executable content-type served"))
    return s


# ============================================================== 7. image OCR / QR codes
Image.MAX_IMAGE_PIXELS = 25_000_000  # decompression-bomb guard
try:
    import pytesseract
except ImportError:  # optional dependency
    pytesseract = None
try:
    from pyzbar.pyzbar import decode as _zbar
except Exception:  # ImportError, or OSError when libzbar0 is missing
    _zbar = None


_OCR_OK: Optional[bool] = None


def _ocr_ready() -> bool:
    """True only if pytesseract is installed AND the native tesseract binary actually runs (cached)."""
    global _OCR_OK
    if _OCR_OK is None:
        try:
            pytesseract.get_tesseract_version()
            _OCR_OK = True
        except Exception:  # package missing (None) or binary not on PATH
            _OCR_OK = False
    return _OCR_OK


def capabilities() -> dict:
    return {"ocr": _ocr_ready(), "qr": _zbar is not None}


def load_image(data: bytes) -> Image.Image:
    Image.open(BytesIO(data)).verify()
    img = Image.open(BytesIO(data))
    img.load()
    return img.convert("RGB")


def decode_qr(img: Image.Image) -> List[str]:
    if _zbar is None:
        return []
    try:
        found = _zbar(img) or _zbar(img.convert("L").resize((img.width * 2, img.height * 2)))
    except Exception as e:
        log.warning("QR decode failed: %s", e)
        return []
    return [x for x in dict.fromkeys(o.data.decode("utf-8", "ignore").strip() for o in found) if x]


def run_ocr(img: Image.Image) -> Optional[str]:
    """Extracted text, or None when the engine / tesseract binary is unavailable."""
    if not _ocr_ready():
        return None
    if img.width > 2000:
        img = img.resize((2000, int(img.height * 2000 / img.width)))
    try:
        return pytesseract.image_to_string(img, timeout=10).strip()[:2000]
    except Exception as e:  # missing tesseract binary, timeout...
        log.warning("OCR failed: %s", e)
        return None


# ================================================================== 8. public entry points
def scan_text(text: str, lookup: Lookup, kind: str = "text", extra_urls: Sequence[str] = (), sender: str = "",
              subject: str = "", reply_to: str = "", auth_results: str = "", llm: Optional[dict] = None) -> dict:
    """Message scan (SMS / e-mail / OCR text). `llm` is an optional local-LLM verdict; it can only ADD risk,
    so a prompt-injected 'this is safe' answer can never lower a heuristic score."""
    full = f"{subject}\n{text}".strip() if subject else text
    urls = list(dict.fromkeys(extract_urls(full) + list(extra_urls)))[:10]
    sigs, kws, det = text_signals(full, bool(urls))
    if kind == "qr":
        sigs.append((.15, "amber", "QrCode", "Quishing vector (QR)"))
    esigs, edet, edomains, ebrands = email_signals(sender, reply_to, auth_results)
    us, domains, brands, udet = _url_pass(urls)
    domains |= edomains
    brands |= ebrands | set(text_lookalikes(full).values())
    sigs += esigs + us + _community(lookup, domains)
    if llm:
        conf = llm["confidence"]
        if llm["is_phishing"]:
            sigs.append((min(.8, conf / 100 * .8), "red", "Bot", f"AI verdict: phishing ({conf}%)"))
            det.insert(0, f"AI analysis: {llm['reasoning']}")
        else:
            udet = udet + [f"AI analysis found no phishing indicators: {llm['reasoning']}"]
    res = build_result(sigs, full, kind, urls, det + edet + udet, domains, brands, kws)
    res["ai"] = llm
    return res


def scan_url(url: str, lookup: Lookup) -> dict:
    url = url.strip()
    sigs, domains, brands, det = _url_pass([url])
    return build_result(sigs + _community(lookup, domains), url, "url", [url], det, domains, brands)


def _static_chain(urls: Sequence[str]) -> dict:
    """Chain built from URLs the browser already resolved (no network access from the server)."""
    hops = [{"url": u, "status": 302 if k < len(urls) - 1 else 200, "content_type": None, "location": None,
             "error": None, "simulated": False} for k, u in enumerate(urls)]
    return {"hops": hops, "too_many": False, "simulated": False}


def scan_download(filename: str, url: str, lookup: Lookup, final_url: Optional[str] = None, do_trace: bool = True) -> dict:
    """final_url: where the browser ended up (Chrome knows it). do_trace=False never fetches anything server-side,
    which matters for single-use / authenticated download links that a server-side GET could 'consume'."""
    if final_url and final_url != url:
        chain = _static_chain([url, final_url])
    elif do_trace:
        chain = trace(url)
    else:
        chain = _static_chain([url])
    urls = [h["url"] for h in chain["hops"]]
    sigs = filename_signals(filename) + chain_signals(chain)
    us, domains, brands, det = _url_pass(urls)
    sigs += us + _community(lookup, domains)
    if chain["simulated"]:
        det = det + ["Redirect chain is SIMULATED (offline demo mode); set TRACE_MODE=real for live tracing"]
    hosts = " -> ".join(urlparse(u).hostname or u for u in urls)
    res = build_result(sigs, f"Download payload: {filename} from {url} (Redirect chain: {hosts})", "download", urls, det, domains, brands)
    sc = res["score"]
    res.update(filename=filename, source=url, hops=max(len(urls) - 1, 0), finalDomain=urlparse(urls[-1]).hostname or "",
               status="Blocked" if sc >= 80 else "Paused & Blocked" if sc >= 60 else "Warn user" if sc >= 35 else "Allowed",
               chain=chain["hops"], simulated=chain["simulated"])
    return res


_SIM_QR = "Decoded QR → https://paypa1-secure-login.xyz/verify?id=88213"
_SIM_OCR = 'OCR: "URGENT: Your bank account is suspended. Verify your password now at http://secure-g00gle-login.top/auth"'


def scan_image(data: bytes, mode: str, filename: str, lookup: Lookup) -> dict:
    """Image/QR scan with graceful degradation:
    QR engine missing -> fall back to OCR; both missing -> simulated demo result (MEDIA_SIMULATION=1) or 503."""
    caps, warnings, simulated = capabilities(), [], False
    try:
        img = load_image(data)
    except Exception:
        raise ScanError(400, "Not a valid image")
    qr = decode_qr(img) if caps["qr"] else []
    ocr = None if (qr and mode == "qr") or not caps["ocr"] else run_ocr(img)
    if mode == "qr" and not caps["qr"]:
        warnings.append("QR decoder unavailable (install libzbar0 + pyzbar); fell back to OCR")
    if not caps["ocr"] and mode == "image":
        warnings.append("OCR unavailable (install tesseract-ocr + pytesseract)")
    if not qr and not ocr:
        if caps["ocr"] or caps["qr"]:
            raise ScanError(422, "No QR code or readable text found in the image")
        if not config.MEDIA_SIMULATION:
            raise ScanError(503, "OCR/QR engines not installed (tesseract-ocr, libzbar0)")
        simulated = True
        is_qr = mode == "qr" or "qr" in filename.lower()
        warnings.append("OCR/QR engines not installed: this result is SIMULATED for demo purposes")
        qr = ["https://paypa1-secure-login.xyz/verify?id=88213"] if is_qr else []
        ocr = None if is_qr else _SIM_OCR[6:-1]
    parts = ([f"Decoded QR → {' '.join(qr)}"] if qr else []) + ([f'OCR: "{ocr}"'] if ocr else [])
    res = scan_text(" ".join(parts), lookup, "qr" if qr else "image", extra_urls=qr)
    return {**res, "qr": qr, "ocr_text": ocr, "warnings": warnings, "simulated": simulated}
