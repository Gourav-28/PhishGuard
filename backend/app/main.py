"""PhishGuard AI API: FastAPI entry point.  Run:  python -m uvicorn app.main:app --reload"""
import hashlib
import hmac
import logging
import time
import uuid
from collections import defaultdict, deque
from typing import List, Literal, Optional

import httpx
from fastapi import APIRouter, Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import config, detection as D, llm
from .store import get_store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("phishguard.api")
store = get_store()

app = FastAPI(title="PhishGuard AI API", version="2.1.0",
              description="Multi-modal phishing detection & community threat intelligence.")
app.add_middleware(CORSMiddleware, allow_origins=config.ALLOWED_ORIGINS, allow_credentials=False,
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type", "X-API-Key"])


@app.exception_handler(D.ScanError)
async def _scan_error(_: Request, exc: D.ScanError):
    return JSONResponse({"detail": exc.message}, status_code=exc.status)


@app.exception_handler(httpx.HTTPError)
async def _storage_error(_: Request, exc: httpx.HTTPError):
    log.error("Storage backend error: %s", exc)
    return JSONResponse({"detail": "Storage backend unavailable"}, status_code=503)


# ------------------------------------------------------------------ security helpers
_hits = defaultdict(deque)


def guard(request: Request, x_api_key: Optional[str] = Header(default=None)) -> None:
    """Optional API key + naive per-IP sliding-window rate limit (use a gateway / Redis in production)."""
    if config.API_KEY and not hmac.compare_digest(x_api_key or "", config.API_KEY):
        raise HTTPException(401, "Invalid or missing X-API-Key")
    ip, now = (request.client.host if request.client else "unknown"), time.monotonic()
    q = _hits[ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= config.RATE_LIMIT_PER_MIN:
        raise HTTPException(429, "Rate limit exceeded, try again in a minute")
    q.append(now)


def reporter_id(request: Request) -> str:
    ip = request.client.host if request.client else "unknown"
    return hashlib.sha256((ip + config.HASH_SALT).encode()).hexdigest()[:32]


# ------------------------------------------------------------------------- schemas
ThreatType = Literal["Credential phishing", "Fake refund scam", "Bank KYC scam", "Malware delivery", "Quishing", "Giveaway scam"]


class ScanIn(BaseModel):
    """Plain text/SMS, or a full e-mail (sender/subject/headers/links are optional extras)."""
    text: str = Field(default="", max_length=20000, examples=["URGENT: your PayPal account is locked. Verify your password at http://paypa1-secure-login.xyz"])
    sender: str = Field(default="", max_length=500, examples=["PayPal <security@account-paypa1.net>"])
    subject: str = Field(default="", max_length=500)
    reply_to: str = Field(default="", max_length=500)
    auth_results: str = Field(default="", max_length=2000, description="Authentication-Results header (SPF/DKIM/DMARC)")
    urls: List[str] = Field(default_factory=list, max_length=50)
    use_llm: bool = True
    passive: bool = Field(default=False, description="Automatic background check: do not log it in the stats")


class UrlIn(BaseModel):
    url: str = Field(min_length=3, max_length=2048, examples=["http://paypa1-secure-login.xyz/verify"])
    passive: bool = False


class DownloadIn(BaseModel):
    filename: str = Field(min_length=1, max_length=255, examples=["invoice_update_2026.pdf.exe"])
    url: str = Field(min_length=3, max_length=2048, examples=["http://bit.ly/suspicious-payload-dl"])
    final_url: Optional[str] = Field(default=None, max_length=2048, description="Where the browser ended up (skips server-side tracing)")
    trace: bool = Field(default=True, description="Follow redirects from the server (SSRF-guarded). False = never fetch the URL")


class ReportIn(BaseModel):
    url: str = Field(min_length=3, max_length=2048, examples=["evil-login-page.xyz"])
    threat_type: ThreatType = "Credential phishing"


class RadarIn(BaseModel):
    brand: str = Field(min_length=3, max_length=253, examples=["paypal.com"])
    domain: str = Field(min_length=3, max_length=253, examples=["paypa1.com"])


# --------------------------------------------------------------------------- routes
router = APIRouter(prefix="/api", dependencies=[Depends(guard)])


def _logged(res: dict) -> dict:
    store.log_scan(res["kind"], res["score"], next(iter(res["indicators"]["domains"]), None))
    return res


def _scan_message(body: ScanIn) -> dict:
    if not (body.text.strip() or body.subject.strip()):
        raise HTTPException(422, "Nothing to scan: text or subject is required")
    verdict = llm.analyze(body.text, body.sender, body.subject) if body.use_llm and llm.available() else None
    kind = "email" if (body.sender or body.subject) else "text"
    res = D.scan_text(body.text, store.find_report, kind, [u[:2048] for u in body.urls], body.sender, body.subject,
                      body.reply_to, body.auth_results, verdict)
    return res if body.passive else _logged(res)


@router.post("/scan/text", tags=["scan"])
def scan_text(body: ScanIn):
    return _scan_message(body)


@router.post("/scan/gmail", tags=["scan"], summary="Scan an e-mail (alias of /scan/text with e-mail fields)")
def scan_gmail(body: ScanIn):
    return _scan_message(body)


@router.post("/scan/url", tags=["scan"])
def scan_url(body: UrlIn):
    res = D.scan_url(body.url, store.find_report)
    return res if body.passive else _logged(res)


@router.post("/scan/image", tags=["scan"])
def scan_image(file: UploadFile = File(...), mode: Literal["image", "qr"] = Form("image")):
    limit = config.MAX_UPLOAD_MB * 1024 * 1024
    data = file.file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"Image larger than {config.MAX_UPLOAD_MB} MB")
    return _logged(D.scan_image(data, mode, file.filename or "", store.find_report))


@router.post("/scan/download", tags=["scan"])
def scan_download(body: DownloadIn):
    res = D.scan_download(body.filename, body.url, store.find_report, body.final_url, body.trace)
    store.log_scan("download", res["score"], next(iter(res["indicators"]["domains"]), None))
    store.log_download(res)
    return res


@router.get("/downloads", tags=["downloads"])
def downloads(limit: int = Query(50, ge=1, le=200)):
    return store.list_downloads(limit)


SEED_RADAR = [("paypal.com", "paypa1.com"), ("google.com", "g00gle.com"), ("amazon.com", "amaz0n-secure.top"),
              ("microsoft.com", "micros0ft.co"), ("netflix.com", "netfl1x.com"), ("github.com", "github.com")]


@router.get("/typosquat/radar", tags=["typosquat"])
def radar():
    """Seed pairs + community-reported domains that imitate a protected brand."""
    pairs = list(SEED_RADAR)
    for r in store.list_reports(200):
        m = D.match_brand(r["domain"])
        if m:
            pairs.append((m["brand"], r["domain"]))
    return [D.radar_row(b, s) for b, s in dict.fromkeys(pairs)]


@router.post("/typosquat/analyze", tags=["typosquat"])
def analyze(body: RadarIn):
    b, s = D.parse_url(body.brand), D.parse_url(body.domain)
    if not b or not s:
        raise HTTPException(422, "Invalid domain")
    return D.radar_row(D.registered(b[1]), s[1])


@router.get("/community", tags=["community"])
def community(limit: int = Query(100, ge=1, le=500)):
    return store.list_reports(limit)


@router.post("/community/report", status_code=201, tags=["community"])
def report(body: ReportIn, request: Request):
    parsed = D.parse_url(body.url)
    if not parsed:
        raise HTTPException(422, "Invalid URL")
    reg = D.registered(parsed[1])
    if reg in D.BRAND_DOMAINS:  # anti-poisoning: genuine brand domains cannot be blacklisted
        raise HTTPException(422, "Protected brand domains cannot be reported")
    return store.add_report(D.normalize_url(body.url), reg, body.threat_type, reporter_id(request))


@router.post("/community/{report_id}/upvote", tags=["community"])
def upvote(report_id: str, request: Request):
    try:
        uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(400, "Invalid report id")
    row = store.vote(report_id, reporter_id(request))
    if not row:
        raise HTTPException(404, "Report not found")
    return row


@router.get("/stats", tags=["system"])
def stats():
    return store.stats()


@router.get("/health", tags=["system"])
def health():
    return {"ok": True, "version": app.version, "store": store.name, "trace_mode": config.TRACE_MODE, "llm": {"mode": config.LLM_MODE, "available": llm.available(), "model": config.OLLAMA_MODEL},
            **D.capabilities()}


app.include_router(router)


@app.get("/", include_in_schema=False)
def root():
    return {"name": "PhishGuard AI API", "docs": "/docs", "health": "/api/health"}
