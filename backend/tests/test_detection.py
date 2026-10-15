from app import detection as D

NO_COMMUNITY = lambda d: None
FLAGGED = lambda d: {"report_count": 482} if d == "paypa1-secure-login.xyz" else None


def test_levenshtein():
    assert D.lev("paypal", "paypa1") == 1 and D.lev("", "abc") == 3


def test_homoglyph_and_combo():
    assert "Homoglyph substitution" in D.match_brand("paypa1.com")["techniques"]
    assert "Combo-squatting" in D.match_brand("paypa1-secure-login.xyz")["techniques"]
    assert "Brand in subdomain" in D.match_brand("paypal.com.evil.xyz")["techniques"]


def test_legit_not_flagged():
    for h in ("www.paypal.com", "github.com", "example.com", "amazon.in", "accounts.google.com"):
        assert D.match_brand(h) is None


def test_registered_domain_handling():
    assert D.registered("a.b.sbi.co.in") == "sbi.co.in" and D.registered("user.github.io") == "user.github.io"


def test_text_lookalike_word_without_url():
    r = D.scan_text("Your g00gle account needs attention", NO_COMMUNITY)
    assert any(b[2] == "Typosquatting detected" for b in r["badges"])


def test_phishing_text_scores_critical():
    t = "URGENT: Your PayPal account is locked. Verify your password at http://paypa1-secure-login.xyz now"
    r = D.scan_text(t, FLAGGED)
    assert r["score"] >= 90 and r["level"] == "Critical" and r["score"] <= 99
    assert "paypa1-secure-login.xyz" in r["indicators"]["domains"] and "paypal.com" in r["indicators"]["brands"]


def test_benign_text_low():
    r = D.scan_text("Lunch at 1pm tomorrow?", NO_COMMUNITY)
    assert r["level"] == "Low" and r["score"] < 20


def test_genuine_brand_url_low():
    assert D.scan_url("https://www.paypal.com/signin", NO_COMMUNITY)["level"] == "Low"


def test_radar_rows():
    assert D.radar_row("paypal.com", "paypa1.com")["status"] == "Blocked"
    assert D.radar_row("github.com", "github.com")["status"] == "Safe"


def test_download_double_extension_and_ssrf_guard():
    r = D.scan_download("invoice.pdf.exe", "http://127.0.0.1/payload", NO_COMMUNITY)
    assert r["chain"][0]["error"] == "private_address" and r["status"] in ("Blocked", "Paused & Blocked")
    assert any("Double extension" in b[2] for b in r["badges"])


def test_mock_chain_for_shortener():
    ch = D._mock_trace("http://bit.ly/x")
    assert len(ch["hops"]) == 3 and ch["simulated"]


# ------------------------------------------------ e-mail, LLM and download additions
from app import llm


def test_display_name_spoof_and_reply_to():
    r = D.scan_text("Please confirm your payment details", NO_COMMUNITY, "email", sender="PayPal Support <help@gmail.com>",
                    reply_to="x@evil-mail.ru", auth_results="spf=fail dkim=none dmarc=fail")
    labels = [b[2] for b in r["badges"]]
    assert "Display-name brand spoofing" in labels and "Reply-To differs from sender" in labels and "DMARC check failed" in labels
    assert r["kind"] == "email" and r["is_phishing"] is True and r["details"]


def test_legit_regional_brand_mail_not_spoof():
    r = D.scan_text("Your order has shipped", NO_COMMUNITY, "email", sender="Amazon <ship-confirm@amazon.co.uk>")
    assert not any("spoof" in b[2].lower() for b in r["badges"])


def test_llm_parse_is_strict_and_clamped():
    assert llm.parse_verdict('{"is_phishing": true, "confidence": 250, "reasoning": "x\\u0000y", "tactics": ["urgency"]}')["confidence"] == 100
    assert llm.parse_verdict('{"is_phishing": "yes"}') is None and llm.parse_verdict("not json") is None


def test_llm_can_only_add_risk():
    base = D.scan_text("URGENT verify your password at http://paypa1-secure-login.xyz", NO_COMMUNITY)["score"]
    safe = {"is_phishing": False, "confidence": 99, "reasoning": "looks fine", "tactics": [], "model": "m"}
    bad = {"is_phishing": True, "confidence": 90, "reasoning": "credential lure", "tactics": [], "model": "m"}
    assert D.scan_text("URGENT verify your password at http://paypa1-secure-login.xyz", NO_COMMUNITY, llm=safe)["score"] == base
    assert D.scan_text("Lunch tomorrow?", NO_COMMUNITY, llm=bad)["score"] > D.scan_text("Lunch tomorrow?", NO_COMMUNITY)["score"]


def test_download_with_browser_final_url_never_touches_network():
    r = D.scan_download("setup.exe", "http://bit.ly/x", NO_COMMUNITY, final_url="http://malicious-cdn.xyz/setup.exe")
    assert r["hops"] == 1 and r["simulated"] is False and r["finalDomain"] == "malicious-cdn.xyz"
    assert D.scan_download("a.pdf", "https://example.com/a.pdf", NO_COMMUNITY, do_trace=False)["hops"] == 0
