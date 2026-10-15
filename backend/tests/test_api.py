from fastapi.testclient import TestClient

from app.main import app

c = TestClient(app)


def test_health_and_cors():
    r = c.get("/api/health", headers={"Origin": "null"})
    assert r.status_code == 200 and r.json()["ok"] and r.headers["access-control-allow-origin"] == "*"


def test_scan_text_shape():
    r = c.post("/api/scan/text", json={"text": "URGENT verify your password http://paypa1-secure-login.xyz"}).json()
    assert {"score", "level", "badges", "urls", "kind", "details", "indicators"} <= r.keys()


def test_report_and_upvote_dedup():
    r = c.post("/api/community/report", json={"url": "https://new-evil.xyz/login", "threat_type": "Quishing"})
    assert r.status_code == 201
    rid = r.json()["id"]
    assert c.post(f"/api/community/{rid}/upvote").json()["report_count"] == r.json()["report_count"]  # same reporter: no inflation


def test_brand_domain_cannot_be_reported():
    assert c.post("/api/community/report", json={"url": "https://paypal.com"}).status_code == 422
