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

TABLES = ("outcomes, cases, labels, sightings, report_indicators, templates, reports, indicators, model_traffic, release_log, "
          "retrain_runs, models")


@pytest.fixture()
def pg():
    import psycopg
    from scam_detector.store import PostgresStore
    with psycopg.connect(URL) as conn:
        conn.execute("UPDATE model_release SET stage = 'none', lane = 'full', candidate_version = NULL, active_version = NULL, "
                     "previous_version = NULL, run_id = NULL, pct = 0, created_at = NULL, stage_started = NULL, note = ''")
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


# ---------------------------------------------------------------- the learning loop

def test_real_jobs_become_legit_labels_and_labels_read_back(pg):
    rid = pg.add_report(_report())
    pg.decide_report(rid, "dismissed", "E. Wilson", real=True)
    rid2 = pg.add_report(_report("Pay the training fee by Zelle today"))
    pg.decide_report(rid2, "confirmed", "E. Wilson")
    labels = pg.labels()
    assert [(l["label"], l["source"], l["school"]) for l in labels] == [("legit", "report_real", "fsu"), ("scam", "report", "fsu")]
    assert all(isinstance(l["at"], float) for l in labels)


def test_templates_round_trip_unsigned_hashes_and_forget(pg):
    from scam_detector import learning, memory
    text = ("Hello student, our department needs a remote personal assistant. $450 weekly, flexible hours, no experience "
            "needed. You will receive a check to buy office equipment from our vendor and keep the rest.")
    key = learning.remember(text, title="assistant", school="fsu", st=pg)
    rows = pg.templates()
    assert len(rows) == 1 and rows[0]["key"] == key and rows[0]["sketch"] == memory.sketch(text)
    assert any(x >= 2 ** 63 for x in rows[0]["sketch"])            # the signed bigint storage round-trips
    learning._tm["at"] = 0.0
    assert learning.template_finding(text.replace("$450", "$500"), pg)
    learning.forget(text, pg)
    assert pg.templates() == []


def test_models_release_runs_and_traffic(pg):
    import time
    from scam_detector import ml
    import json
    spec = json.loads(ml.MODEL_PATH.read_text())
    spec["version"] = "pgcand"
    pg.save_model(spec)
    pg.save_model(spec)                                             # idempotent
    assert pg.get_model("pgcand")["version"] == "pgcand" and pg.get_model("nope") is None
    rid = pg.start_run("fast", 7)
    pg.finish_run(rid, status="candidate", version="pgcand", train_rows=300, report="ok")
    assert pg.last_run()["status"] == "candidate" and pg.runs(1)[0]["train_rows"] == 300
    now = time.time()
    pg.set_release(stage="shadow", lane="fast", candidate_version="pgcand", run_id=rid, created_at=now, stage_started=now)
    rel = pg.release()
    assert rel["stage"] == "shadow" and rel["lane"] == "fast" and abs(rel["stage_started"] - now) < 1 and rel["run_id"] == rid
    pg.log_release("shadow", "pgcand", "x")
    assert pg.release_log(1)[0]["event"] == "shadow"
    pg.add_traffic({"key": "a" * 64, "served": "x", "p": 0.2, "flag": False, "novelty": 0.5, "other": "pgcand",
                    "other_p": 0.7, "other_flag": True})
    t = pg.traffic(now - 60)
    assert len(t) == 1 and t[0]["other_flag"] is True
    pg.prune_traffic(time.time() + 60)
    assert pg.traffic(0) == []
