"""
PostgresStore against a real database with db/migrations applied.

Runs only when TEST_DATABASE_URL points at a database whose name ends in "_test" (CI starts one; locally:
createdb lurecheck_test && psql -d lurecheck_test -f db/migrations/001_initial.sql). The name check is there so this
can never be pointed at production: every test empties the tables first.
"""

import os
import re

import pytest

URL = os.environ.get("TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not re.search(r"/[\w-]*_test(\?|$)", URL), reason="no *_test database configured")

TABLES = "outcomes, cases, labels, sightings, report_indicators, templates, reports, indicators"


@pytest.fixture()
def pg():
    import psycopg
    from scam_detector.store import PostgresStore
    with psycopg.connect(URL) as conn:
        conn.execute(f"TRUNCATE {TABLES} RESTART IDENTITY CASCADE")
    return PostgresStore(URL)


def _report(text="Deposit the check and pay https://fast-jobs.example", school="fsu", outcome="deposited_check"):
    from scam_detector.reports import make_report
    return make_report(text + " Text 850-555-0134 or hr.team@gmail.com.", school=school, outcome=outcome)


def _q(sql, *args):
    import psycopg
    with psycopg.connect(URL) as conn:
        return conn.execute(sql, args).fetchall()


def test_report_creates_indicators_links_and_sightings(pg):
    rid = pg.add_report(_report())
    pending = pg.list_reports()
    assert [r["id"] for r in pending] == [rid]
    ind = pending[0]["indicators"]
    assert ind["domains"] == ["fast-jobs.example"] and len(ind["phone_hashes"]) == 1 and len(ind["email_hashes"]) == 1
    assert _q("SELECT count(*) FROM sightings")[0][0] == 3
    assert _q("SELECT DISTINCT status FROM indicators") == [("reported",)]


def test_confirming_confirms_indicators_and_adds_a_label(pg):
    rid = pg.add_report(_report())
    r = pg.decide_report(rid, "confirmed", "E. Wilson", "same script as wave 12")
    assert r["status"] == "confirmed" and r["reviewer"] == "E. Wilson"
    assert _q("SELECT DISTINCT status, confirmed_by FROM indicators") == [("confirmed", "E. Wilson")]
    assert _q("SELECT label, source, reviewer FROM labels") == [("scam", "report", "E. Wilson")]
    exported = pg.confirmed_reports()
    assert len(exported) == 1 and exported[0]["indicators"]["domains"] == ["fast-jobs.example"]
    with pytest.raises(ValueError):
        pg.decide_report(rid, "dismissed", "E. Wilson")          # already reviewed


def test_dismissing_confirms_nothing_and_a_reviewer_is_required(pg):
    rid = pg.add_report(_report())
    with pytest.raises(ValueError):
        pg.decide_report(rid, "confirmed", "  ")
    pg.decide_report(rid, "dismissed", "E. Wilson", "real staffing agency")
    assert _q("SELECT DISTINCT status FROM indicators") == [("reported",)]
    assert _q("SELECT count(*) FROM labels")[0][0] == 0


def test_same_indicator_from_two_reports_is_one_row(pg):
    pg.add_report(_report())
    pg.add_report(_report(text="Different words, same site https://fast-jobs.example"))
    assert _q("SELECT count(*) FROM indicators WHERE kind = 'domain'")[0][0] == 1
    assert _q("SELECT count(*) FROM sightings s JOIN indicators i ON i.id = s.indicator_id WHERE i.kind = 'domain'")[0][0] == 2


def test_unknown_school_is_stored_without_one(pg):
    rid = pg.add_report(_report(school="nowhere"))
    assert pg.list_reports()[0]["school"] == "" and _q("SELECT count(*) FROM sightings")[0][0] == 0
    assert rid


def test_cases_and_outcomes(pg):
    from scam_detector import followup
    from scam_detector.store import reset_store
    reset_store(pg)
    code = followup.open_case({"band": "review", "score": 52, "findings": [{"rule_id": "fake_check_funds"}]}, "fsu")
    assert followup.record_outcome(code, ["deposited_check"], "job_fake")
    assert not followup.record_outcome("not-a-real-code", ["nothing"])      # unknown case
    assert [c["rules"] for c in pg.cases()] == [["fake_check_funds"]]
    assert pg.outcomes()[0]["verified"] == "job_fake"
    assert code not in str(_q("SELECT * FROM cases"))                     # the code itself isn't stored


def test_api_report_goes_to_postgres(pg):
    from fastapi.testclient import TestClient
    from scam_detector import api
    from scam_detector.store import reset_store
    reset_store(pg)
    out = TestClient(api.app).post("/report", json={"text": "Deposit the check we send, then pay https://fast-jobs.example",
                                                    "school": "fsu", "outcome": "deposited_check"}).json()
    assert out["queued"]
    assert _q("SELECT school_id, outcome, status FROM reports") == [("fsu", "deposited_check", "reported")]
