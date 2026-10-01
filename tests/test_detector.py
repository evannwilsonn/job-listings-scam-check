"""Basic checks that the standalone detector scores postings the way the full system does."""
from scam_detector.scorer import score_posting


def band(title, text, company=""):
    r = score_posting(title, text, company)
    return r["band"] if isinstance(r, dict) else r.band


def test_fake_check_scam_is_blocked():
    assert band("Remote Assistant", "You will be paid $650 weekly for 1-2 hrs a day. Interview on Telegram. "
                "We send a check, deposit it and send the balance by Zelle.") == "block"


def test_fee_to_start_is_flagged():
    assert band("Data Entry", "Start today! You must pay a $90 training fee before your first shift.") in ("review", "block")


def test_negated_fee_is_not_flagged():
    assert band("Barista", "We will never ask you for a training fee. $15/hr, weekends, apply in store.", "Bean Co") == "clear"


def test_ssn_for_payroll_after_hire_is_fine():
    assert band("Cashier", "Your Social Security number is collected for payroll upon hire. $14/hr.", "Corner Market") == "clear"


def test_ordinary_posting_is_clear():
    assert band("Marketing Intern", "Help plan campus events and write social posts. 15 hours a week, $16/hr. "
                "Apply through our careers page.", "Acme") == "clear"


def test_api_refuses_oversized_bodies_and_ignores_spoofed_client_addresses():
    from fastapi.testclient import TestClient
    from scam_detector import api, security
    c = TestClient(api.app)
    assert c.post("/analyze", json={"description": "Pay a $90 training fee to start", "run_network": False}).status_code == 200
    big = b'{"description": "' + b"a" * 70_000 + b'"}'
    assert c.post("/analyze", content=big, headers={"content-type": "application/json"}).status_code == 413
    security.analyze_limiter._hits.clear()
    codes = [c.post("/analyze", json={"description": "hello", "run_network": False},
                    headers={"x-forwarded-for": f"198.51.100.{i}"}).status_code for i in range(61)]
    assert codes[-1] == 429                      # a made-up X-Forwarded-For doesn't buy a fresh allowance


def test_network_lookups_are_capped():
    from scam_detector import scorer
    from scam_detector.intel import findings
    text = " ".join(f"contact{i}@domain{i}.example" for i in range(500))
    assert len(findings._extract(text, [], "")[2]) <= findings.MAX_HOSTS
    assert scorer.MAX_NETWORK_DOMAINS == 8
