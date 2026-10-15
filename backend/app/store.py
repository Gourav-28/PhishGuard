"""Storage abstraction: Supabase (PostgREST over httpx) when configured, in-memory otherwise.

Both stores expose the same interface, so the API layer never knows which one it is using:
find_report, list_reports, add_report, vote, log_scan, log_download, list_downloads, stats.
"""
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from . import config

log = logging.getLogger("phishguard.store")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def status_for(count: int, current: str = "Pending") -> str:
    """Mirror of the SQL logic in schema.sql."""
    if current == "Takedown filed":
        return current
    return "Active" if count >= 25 else "Monitoring" if count >= 3 else "Pending"


# --------------------------------------------------------------------------- memory
SEED = [("paypa1-secure-login.xyz", "Credential phishing", 482, "Active"),
        ("amaz0n-refund.top", "Fake refund scam", 311, "Active"),
        ("kyc-update-sbi.in.net", "Bank KYC scam", 207, "Active"),
        ("free-netfl1x-gift.com", "Giveaway scam", 96, "Monitoring"),
        ("g00gle-docs-share.ru", "Malware delivery", 58, "Takedown filed")]


class MemoryStore:
    """Zero-config demo store. Data lives only for the process lifetime."""
    name = "memory"
    # Demo baselines so the dashboard cards look alive on first run (memory mode only).
    BASE = {"scans": 48213, "blocked": 9841, "downloads": 412}

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reports: Dict[str, dict] = {}
        self.upvotes = set()
        self.scans: List[tuple] = []
        self.downloads: List[dict] = []
        for url, typ, cnt, st in SEED:
            rid = str(uuid.uuid4())
            self.reports[rid] = {"id": rid, "url": url, "domain": url, "threat_type": typ, "report_count": cnt,
                                 "status": st, "created_at": _now(), "last_reported": _now()}

    def ping(self) -> None:
        return None

    def find_report(self, domain: str) -> Optional[dict]:
        rows = [r for r in self.reports.values() if r["domain"] == domain]
        return max(rows, key=lambda r: r["report_count"], default=None)

    def list_reports(self, limit: int = 100) -> List[dict]:
        return sorted(self.reports.values(), key=lambda r: -r["report_count"])[:limit]

    def _upvote(self, r: dict, reporter: str) -> None:
        if (r["id"], reporter) not in self.upvotes:
            self.upvotes.add((r["id"], reporter))
            r["report_count"] += 1
            r["last_reported"] = _now()
            r["status"] = status_for(r["report_count"], r["status"])

    def add_report(self, url: str, domain: str, threat_type: str, reporter: str) -> dict:
        with self.lock:
            r = next((x for x in self.reports.values() if x["url"] == url), None)
            if not r:
                rid = str(uuid.uuid4())
                r = self.reports[rid] = {"id": rid, "url": url, "domain": domain, "threat_type": threat_type,
                                         "report_count": 0, "status": "Pending", "created_at": _now(), "last_reported": _now()}
            self._upvote(r, reporter)
            return dict(r)

    def vote(self, report_id: str, reporter: str) -> Optional[dict]:
        with self.lock:
            r = self.reports.get(report_id)
            if r:
                self._upvote(r, reporter)
            return dict(r) if r else None

    def log_scan(self, kind: str, score: int, domain: Optional[str] = None) -> None:
        self.scans.append((kind, score))
        del self.scans[:-5000]

    def log_download(self, row: dict) -> None:
        self.downloads.insert(0, {**row, "created_at": _now()})
        del self.downloads[500:]

    def list_downloads(self, limit: int = 50) -> List[dict]:
        return self.downloads[:limit]

    def stats(self) -> dict:
        return {"scans": self.BASE["scans"] + len(self.scans),
                "blocked": self.BASE["blocked"] + sum(1 for _, s in self.scans if s >= 60),
                "reports": sum(r["report_count"] for r in self.reports.values()),
                "downloads": self.BASE["downloads"] + len(self.downloads)}


# ------------------------------------------------------------------------- supabase
class SupabaseStore:
    """Talks to Supabase's PostgREST API with the service_role key (bypasses RLS; keep it server-side)."""
    name = "supabase"

    def __init__(self) -> None:
        self.base = config.SUPABASE_URL.rstrip("/") + "/rest/v1"
        self.http = httpx.Client(timeout=8.0, headers={
            "apikey": config.SUPABASE_SERVICE_KEY,
            "Authorization": f"Bearer {config.SUPABASE_SERVICE_KEY}",
            "Content-Type": "application/json"})

    def _get(self, table: str, **params: Any) -> Any:
        r = self.http.get(f"{self.base}/{table}", params=params)
        r.raise_for_status()
        return r.json()

    def _rpc(self, fn: str, body: dict) -> Any:
        r = self.http.post(f"{self.base}/rpc/{fn}", json=body)
        r.raise_for_status()
        data = r.json()
        return data[0] if isinstance(data, list) else data

    def _insert(self, table: str, row: dict) -> None:
        r = self.http.post(f"{self.base}/{table}", json=row, headers={"Prefer": "return=minimal"})
        r.raise_for_status()

    def ping(self) -> None:
        self._get("threat_reports", select="id", limit=1)

    def find_report(self, domain: str) -> Optional[dict]:
        rows = self._get("threat_reports", select="*", domain=f"eq.{domain}", order="report_count.desc", limit=1)
        return rows[0] if rows else None

    def list_reports(self, limit: int = 100) -> List[dict]:
        return self._get("threat_reports", select="*", order="report_count.desc", limit=limit)

    def add_report(self, url: str, domain: str, threat_type: str, reporter: str) -> dict:
        return self._rpc("report_site", {"p_url": url, "p_domain": domain, "p_type": threat_type, "p_reporter": reporter})

    def vote(self, report_id: str, reporter: str) -> Optional[dict]:
        return self._rpc("upvote_report", {"p_id": report_id, "p_reporter": reporter})

    def log_scan(self, kind: str, score: int, domain: Optional[str] = None) -> None:
        try:
            self._insert("scan_log", {"kind": kind, "score": score, "domain": domain})
        except httpx.HTTPError:
            log.exception("log_scan failed")  # logging must never break a scan

    def log_download(self, row: dict) -> None:
        try:
            self._insert("downloads_log", {"filename": row["filename"], "source_url": row["source"], "hops": row["hops"],
                                           "final_domain": row["finalDomain"], "risk": row["risk"],
                                           "status": row["status"], "score": row["score"]})
        except httpx.HTTPError:
            log.exception("log_download failed")

    def list_downloads(self, limit: int = 50) -> List[dict]:
        rows = self._get("downloads_log", select="*", order="created_at.desc", limit=limit)
        return [{"filename": r["filename"], "source": r["source_url"], "hops": r["hops"], "finalDomain": r["final_domain"],
                 "risk": r["risk"], "status": r["status"], "score": r.get("score"), "created_at": r["created_at"]} for r in rows]

    def stats(self) -> dict:
        rows = self._get("system_stats", select="*")
        return {k: int(v) for k, v in rows[0].items()} if rows else {"scans": 0, "blocked": 0, "reports": 0, "downloads": 0}


def get_store():
    """Supabase if configured and reachable, otherwise the in-memory store (seamless fallback)."""
    if config.SUPABASE_URL and config.SUPABASE_SERVICE_KEY:
        try:
            s = SupabaseStore()
            s.ping()
            log.info("Using Supabase store")
            return s
        except Exception as e:  # network error, bad key, missing tables...
            log.warning("Supabase unavailable (%s): falling back to in-memory store", e)
    else:
        log.info("SUPABASE_* not set: using in-memory store")
    return MemoryStore()
