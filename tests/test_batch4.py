"""The network ("already confirmed"), lookups, employer attestations, employer screening and the multilingual rules."""

import os
import re

import pytest

from scam_detector.attestations import attestation_findings, company_key
from scam_detector.network import lookup, network_findings, normalize
from scam_detector.reports import make_report
from scam_detector.rules import run_text_rules

SCAM = "Deposit the check we mail you and pay our vendor at https://fast-jobs.example. Text 850-555-0134."


def ids(fs):
    return {f["rule_id"] if isinstance(f, dict) else f.rule_id for f in fs}


def _confirm(store, text=SCAM, school="fsu"):
    rid = store.add_report(make_report(text, school=school, outcome="deposited_check"))
    store.decide_report(rid, "confirmed", "E. Wilson")


# ---------------------------------------------------------------- network

def test_only_confirmed_indicators_warn(_isolated_store):
    _isolated_store.add_report(make_report(SCAM, school="fsu"))              # reported, not confirmed
    assert network_findings("Apply at https://fast-jobs.example") == []
    _confirm(_isolated_store)
    f = network_findings("New posting: apply at https://fast-jobs.example/start")
    assert f and f[0]["severity"] == "critical" and "fast-jobs.example" in f[0]["matched"]


def test_phone_matches_by_hash_and_is_never_shown(_isolated_store):
    _confirm(_isolated_store)
    f = network_findings("Call me at (850) 555-0134 to start")
    assert f and "850" not in " ".join(f[0]["matched"]) and "phone number" in f[0]["why"]


def test_lookup_normalizes_what_students_paste(_isolated_store):
    _confirm(_isolated_store)
    assert lookup("https://www.fast-jobs.example/apply?x=1")["found"]
    assert lookup("+1 (850) 555-0134")["found"]
    assert not lookup("https://realco.example")["found"]
    assert lookup("hello")["kind"] == ""
    assert normalize("someone@gmail.com")[0] == "email" and normalize("gmail.com") == ("", "")


# ---------------------------------------------------------------- attestations

def _attest(store, **kw):
    rec = {"company": "Acme Corp", "company_key": company_key("Acme Corp"), "email_domains": ["acme.com"],
           "careers_url": "https://acme.com/careers", "never_text": True, "never_chat_apps": True,
           "never_checks": True, "never_fees": True, "contact": None, "verified_by": "E. Wilson", **kw}
    store.add_attestation(rec)


def test_company_key_ignores_legal_suffixes():
    assert company_key("Acme Corp.") == company_key("ACME, Inc") == "acme"


def test_no_attestation_means_no_findings(_isolated_store):
    assert attestation_findings("Acme", "hr@other.example", "text me") == (None, [])


def test_attested_rules_are_enforced(_isolated_store):
    _attest(_isolated_store)
    fired = [{"rule_id": f.rule_id} for f in run_text_rules("We'll send a check to buy your equipment.")]
    att, f = attestation_findings("ACME Inc", "recruiting@acme-careers.net", "Add me on WhatsApp to continue.", fired)
    assert att and {"attested_domain_mismatch", "attested_channel_mismatch", "attested_money_mismatch"} <= ids(f)
    _, ok = attestation_findings("Acme", "jordan@acme.com", "Your interview is Tuesday on Zoom.")
    assert ok == []


# ---------------------------------------------------------------- screening and API

def test_screen_employer_holds_confirmed_scams_and_passes_clean(_isolated_store):
    from scam_detector.employer import screen_employer
    _confirm(_isolated_store)
    bad = screen_employer("Fast Jobs", "hr@gmail.com", "https://fast-jobs.example", "Assistant",
                          "Remote assistant, apply at https://fast-jobs.example", run_network=False)
    assert bad["verdict"] == "hold" and "confirmed_scam_indicator" in ids(bad["findings"])
    good = screen_employer("Realco", "talent@realco.example", "https://realco.example", "Data Analyst",
                           "Requirements: SQL and Excel. Benefits: health, dental, 401k. Apply on our careers page.",
                           run_network=False)
    assert good["verdict"] == "ok"


def test_api_lookup_and_analyze_use_the_network(_isolated_store):
    from fastapi.testclient import TestClient
    from scam_detector import api
    _confirm(_isolated_store)
    c = TestClient(api.app)
    assert c.post("/lookup", json={"value": "fast-jobs.example"}).json()["found"]
    out = c.post("/analyze", json={"description": "Great job! Start at https://fast-jobs.example today.",
                                   "run_network": False, "second_look": False}).json()
    assert "confirmed_scam_indicator" in ids(out["findings"]) and out["band"] == "block"
    s = c.post("/screen-employer", json={"company": "Fast Jobs", "website": "https://fast-jobs.example",
                                         "run_network": False}).json()
    assert s["verdict"] == "hold"


# ---------------------------------------------------------------- multilingual rules

@pytest.mark.parametrize("text,rule", [
    ("您好，这里是中国驻纽约领事馆，您涉嫌一起洗钱案件，需要将资金转账到安全账户。", "authority_impersonation_zh"),
    ("Te enviaremos un cheque. Deposítalo y envía el resto a nuestro proveedor de equipo.", "fake_check_es"),
    ("Para empezar tienes que pagar la cuota de inscripción de $50.", "advance_fee_es"),
])
def test_multilingual_scams(text, rule):
    assert rule in ids(run_text_rules(text))


@pytest.mark.parametrize("text", [
    "我们是一家软件公司，欢迎留学生申请暑期实习。",
    "El pago es por cheque cada dos semanas. Puedes depositar tu cheque en cualquier banco.",
    "Ofrecemos pago semanal por depósito directo o cheque. No hay costo de inscripción.",
])
def test_multilingual_legit_stays_quiet(text):
    assert not ids(run_text_rules(text)) & {"authority_impersonation_zh", "fake_check_es", "advance_fee_es"}


# ---------------------------------------------------------------- Postgres

PG = os.environ.get("TEST_DATABASE_URL", "")


@pytest.mark.skipif(not re.search(r"/[\w-]*_test(\?|$)", PG), reason="no *_test database configured")
def test_postgres_network_and_attestations():
    import psycopg
    from scam_detector.store import PostgresStore
    with psycopg.connect(PG) as conn:
        conn.execute("TRUNCATE outcomes, cases, labels, sightings, report_indicators, templates, reports, indicators, "
                     "employer_attestations RESTART IDENTITY CASCADE")
    pg = PostgresStore(PG)
    pg.add_report(make_report(SCAM, school="fsu"))
    assert pg.confirmed_matches({"domains": ["fast-jobs.example"]}) == []
    _confirm(pg)
    m = pg.confirmed_matches({"domains": ["fast-jobs.example"]})
    assert m and m[0]["reports"] == 1 and m[0]["schools"] == 1 and m[0]["schools_7d"] == 1
    assert lookup("850-555-0134", store=pg)["found"]
    _attest(pg)
    _attest(pg, email_domains=["acme.com", "acmejobs.com"])               # upsert, not a duplicate
    assert pg.attestation("acme")["email_domains"] == ["acme.com", "acmejobs.com"]
    _, f = attestation_findings("Acme", "hr@acme-careers.net", store=pg)
    assert "attested_domain_mismatch" in ids(f)
