"""Server-only rules and the tuning canary, abuse-report drafts, and the API's opt-in cross-origin access."""

import importlib
import json

from scam_detector.tools.abuse_reports import drafts, email_text, registrar_of
from scam_detector.tools.tuning_watch import alert, private_only, rule_table, weekly

RULES = rule_table()
PRIVATE = sorted(r for r, spec in RULES.items() if spec.get("private"))


# ---------------------------------------------------------------- private rules and the canary

def test_private_rules_exist_and_still_run_in_python():
    from scam_detector.rules import run_text_rules
    assert set(PRIVATE) >= {"weekly_pay_few_hours", "remote_weekly_pay"}
    fired = {f.rule_id for f in run_text_rules("Work remotely and get paid weekly, only 1-2 hrs a day.")}
    assert "remote_weekly_pay" in fired


def test_private_only_means_public_rules_alone_would_not_flag():
    assert private_only({"band": "review", "rules": ["remote_weekly_pay", "weekly_pay_few_hours", "student_bait"]}, RULES)
    assert not private_only({"band": "block", "rules": ["remote_weekly_pay", "fake_check_funds"]}, RULES)   # critical public
    assert not private_only({"band": "caution", "rules": ["remote_weekly_pay"]}, RULES)                     # not flagged


def test_canary_alerts_on_a_jump():
    calm = [{"date": "2026-10-05", "band": "block", "rules": ["fake_check_funds"]} for _ in range(10)]
    tuned = [{"date": "2026-10-13", "band": "review", "rules": ["remote_weekly_pay", "weekly_pay_few_hours"]} for _ in range(4)]
    tuned += [{"date": "2026-10-13", "band": "block", "rules": ["fake_check_funds"]} for _ in range(2)]
    rows = weekly(calm + tuned, RULES)
    assert [r["week"] for r in rows] == ["2026-10-05", "2026-10-12"] and rows[-1]["private_only"] == 4
    assert "tuned against the public page" in alert(rows)
    assert alert(weekly(calm, RULES)) == ""


# ---------------------------------------------------------------- abuse drafts

RDAP = json.dumps({"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Cheap Names LLC"]]],
                                 "entities": [{"roles": ["abuse"],
                                               "vcardArray": ["vcard", [["email", {}, "text", "abuse@cheapnames.example"]]]}]}]})


def test_rdap_registrar_and_abuse_contact():
    assert registrar_of("fast-jobs.example", fetch=lambda u: (200, RDAP)) == \
        {"registrar": "Cheap Names LLC", "abuse_email": "abuse@cheapnames.example"}
    assert registrar_of("x.example", fetch=lambda u: (404, "")) == {"registrar": "", "abuse_email": ""}


def test_drafts_group_by_registrar_and_carry_no_student_data():
    reports = [{"received": "2026-10-20T10:00:00+00:00", "outcome": "deposited_check", "reviewer": "E. Wilson",
                "text_masked": "secret student text", "indicators": {"domains": ["fast-jobs.example"]}},
               {"received": "2026-10-22T10:00:00+00:00", "outcome": "", "reviewer": "E. Wilson",
                "indicators": {"domains": ["fast-jobs.example", "pay-now.example"]}}]
    groups = drafts(reports, fetch=lambda u: (200, RDAP))
    g = groups["Cheap Names LLC"]
    assert [d["domain"] for d in g["domains"]] == ["fast-jobs.example", "pay-now.example"]
    assert g["domains"][0]["reports"] == 2 and g["domains"][0]["first_seen"] == "2026-10-20"
    text = email_text("Cheap Names LLC", g)
    assert "abuse@cheapnames.example" in text and "E. Wilson" in text and "secret student text" not in text


# ---------------------------------------------------------------- cross-origin

def test_cors_is_off_by_default_and_opt_in(monkeypatch):
    from fastapi.testclient import TestClient
    from scam_detector import api
    origin = {"Origin": "https://career.example.edu", "Access-Control-Request-Method": "POST",
              "Access-Control-Request-Headers": "content-type"}
    assert "access-control-allow-origin" not in TestClient(api.app).options("/analyze", headers=origin).headers
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://career.example.edu")
    try:
        mod = importlib.reload(api)
        r = TestClient(mod.app).options("/analyze", headers=origin)
        assert r.headers.get("access-control-allow-origin") == "https://career.example.edu"
        assert "access-control-allow-credentials" not in r.headers
    finally:
        monkeypatch.delenv("ALLOWED_ORIGINS")
        importlib.reload(api)
