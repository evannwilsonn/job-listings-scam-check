"""A career center's trusted and blocked domains (scam_detector/guardrails.py): trust quiets only that domain's
infrastructure warnings and protects it from look-alikes; it never overrides scam evidence. Block adds a critical finding."""

import pytest

from scam_detector import guardrails
from scam_detector.tools import school_rules


@pytest.fixture(autouse=True)
def _fresh():
    guardrails.clear_cache()
    yield
    guardrails.clear_cache()


def _client():
    from fastapi.testclient import TestClient
    from scam_detector import api
    return TestClient(api.app)


def _analyze(text, school="fsu", sender=""):
    return _client().post("/analyze", json={"description": text, "school": school, "sender": sender, "run_network": False}).json()


def test_trusting_a_lookalike_named_employer_quiets_that_warning_only(_isolated_store):
    text = "Hi! We're hiring student tellers. Apply at https://fsu-careers.com/jobs this week."
    before = _analyze(text)
    look = [f for f in before["findings"] if f["rule_id"] == "lookalike_domain"]
    assert look and look[0]["weight"] > 0
    assert school_rules.main(["trust", "https://fsu-careers.com/x", "--school", "fsu", "--by", "E. Wilson",
                              "--reason", "verified by phone"]) == 0
    guardrails.clear_cache()
    after = _analyze(text)
    # a trusted domain is never checked as a look-alike at all (intel protected_extra); softening covers the rest
    assert all(f["weight"] == 0 for f in after["findings"] if f["rule_id"] == "lookalike_domain")
    assert after["score"] < before["score"]
    assert _analyze(text, school="")["score"] == before["score"]       # another school's list doesn't apply


def test_trust_never_hides_scam_evidence(_isolated_store):
    school_rules.main(["trust", "acme-jobs.com", "--school", "fsu", "--by", "E"])
    guardrails.clear_cache()
    scam = ("Apply at https://acme-jobs.com today. We will mail you a check to buy office equipment from our vendor; "
            "deposit it and send the rest by Zelle. Reply from your personal email.")
    out = _analyze(scam)
    assert out["band"] in ("review", "block")                                 # the text rules still count in full
    assert all(f["weight"] > 0 for f in out["findings"] if f["rule_id"] not in guardrails.SOFTEN and f["rule_id"] != "model_second_look"
               and f.get("severity") != "note")


def test_a_trusted_domain_is_protected_from_lookalikes(_isolated_store):
    school_rules.main(["trust", "acmecu.org", "--school", "fsu", "--by", "E"])
    guardrails.clear_cache()
    out = _analyze("Your account needs review, sign in at https://acrnecu.org/login today.")
    hit = [f for f in out["findings"] if f["rule_id"] == "lookalike_domain"]
    assert hit and hit[0]["weight"] > 0 and "acmecu.org" in hit[0]["matched"][0]


def test_blocking_adds_a_critical_finding_and_block_beats_trust(_isolated_store):
    assert school_rules.main(["block", "fast-campus-jobs.net", "--school", "fsu", "--by", "E", "--reason", "Oct wave"]) == 0
    school_rules.main(["trust", "fast-campus-jobs.net", "--school", "fsu", "--by", "E"])
    guardrails.clear_cache()
    out = _analyze("Quick job for students, details at fast-campus-jobs.net")
    hit = [f for f in out["findings"] if f["rule_id"] == "school_blocked_domain"]
    assert hit and hit[0]["severity"] == "critical" and out["band"] == "block" and "Florida State" in hit[0]["why"]
    assert any(f["rule_id"] == "school_blocked_domain" for f in _analyze("Hello", sender="hr@fast-campus-jobs.net")["findings"])


def test_softening_only_touches_findings_about_trusted_domains():
    rules = {"trusted": {"acmecu.org"}, "blocked": set()}
    found = [{"rule_id": "new_domain", "severity": "warning", "weight": 16, "why": "new", "matched": ["acmecu.org: 20 days"]},
             {"rule_id": "lookalike_domain", "severity": "critical", "weight": 35, "why": "x",
              "matched": ["acmecu.org (imitates fsu.edu: brand_plus_word)"]},
             {"rule_id": "lookalike_domain", "severity": "critical", "weight": 35, "why": "x",
              "matched": ["acrnecu.org (imitates acmecu.org: homoglyph)"]},
             {"rule_id": "new_domain", "severity": "warning", "weight": 16, "why": "new", "matched": ["other.com: 3 days"]},
             {"rule_id": "confirmed_scam_indicator", "severity": "critical", "weight": 40, "why": "x", "matched": ["acmecu.org"]}]
    out = guardrails.apply(found, rules, school_name="Florida State University")
    assert [f["weight"] for f in out] == [0, 0, 35, 16, 40]
    assert found[0]["weight"] == 16                                          # the input isn't changed


def test_cli_list_remove_and_bad_input(_isolated_store, capsys):
    school_rules.main(["block", "bad.example.com", "--school", "fsu", "--by", "E"])
    school_rules.main(["list", "--school", "fsu"])
    assert "example.com" in capsys.readouterr().out
    assert school_rules.main(["remove", "block", "bad.example.com", "--school", "fsu", "--by", "E"]) == 0
    assert school_rules.main(["remove", "block", "bad.example.com", "--school", "fsu", "--by", "E"]) == 1
    assert school_rules.main(["block", "not a domain", "--school", "fsu", "--by", "E"]) == 2
    assert _isolated_store.school_rules("fsu") == []


def test_entries_cover_subdomains_never_the_parent():
    rules = {"trusted": set(), "blocked": {"jobs.sites-example.com"}}
    hit = lambda text: [f for f in guardrails.apply([], rules, text=text) if f["rule_id"] == "school_blocked_domain"]
    assert hit("apply at https://jobs.sites-example.com/x") and hit("apply at a.jobs.sites-example.com")
    assert not hit("apply at https://sites-example.com/other-page") and not hit("see other.sites-example.com")
    assert guardrails.clean_domain("https://Careers.Acme.com/x") == "careers.acme.com"


def test_schools_json_employer_domains_are_trusted(monkeypatch, tmp_path):
    cfg = tmp_path / "schools.json"
    cfg.write_text('{"fsu": {"name": "Florida State University", "employer_domains": ["fsu-careers.com"]}}')
    monkeypatch.setattr(guardrails, "SCHOOLS", cfg)
    assert "fsu-careers.com" in guardrails.rules_for("fsu")["trusted"]
