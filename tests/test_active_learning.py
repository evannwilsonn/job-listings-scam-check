"""Active learning with consent (api.py ask_review, /report kind=borderline): the page offers a reviewer's eyes on
close calls, stores nothing unless the student agrees, and a reviewer's answer becomes a training label marked as
coming from a close call."""

from scam_detector import api, ml
from scam_detector.tools import review_queue

QUIET = "Campus library assistant, $13/hour, apply through the career center."


def _client():
    from fastapi.testclient import TestClient
    return TestClient(api.app)


def _analyze(text, **kw):
    return _client().post("/analyze", json={"description": text, "school": "fsu", "run_network": False, **kw}).json()


def _pred(p, uncertain=False):
    return {"pred": {"probability": p, "threshold": 0.80, "flag": p >= 0.80, "uncertain": uncertain}, "finding": None}


def test_borderline_is_near_threshold_or_unsettled():
    assert ml.borderline({"probability": 0.70, "threshold": 0.80, "uncertain": False})
    assert not ml.borderline({"probability": 0.20, "threshold": 0.80, "uncertain": False})
    assert ml.borderline({"probability": 0.20, "threshold": 0.80, "uncertain": True})


def test_asks_only_when_rules_are_quiet_and_the_model_is_unsure(monkeypatch):
    monkeypatch.setattr(ml, "assess", lambda *a, **k: _pred(0.72))
    api._ask_day.update({"day": "", "n": 0})
    out = _analyze(QUIET)
    assert out["band"] in ("clear", "caution") and out["ask_review"]["why"].startswith("This one is a close call")
    assert "nothing about you is kept" in out["ask_review"]["why"]
    # the rules already send this one to a person: no offer (the page shows "Report it" instead)
    scam = _analyze("We will mail you a check, deposit it and send the rest by Zelle. Text me on WhatsApp.")
    assert scam["band"] in ("review", "block") and "ask_review" not in scam
    # a confident "legit" is not offered; a model flag with quiet rules is
    monkeypatch.setattr(ml, "assess", lambda *a, **k: _pred(0.05))
    assert "ask_review" not in _analyze(QUIET)
    monkeypatch.setattr(ml, "assess", lambda *a, **k: _pred(0.97))
    assert "ask_review" in _analyze(QUIET)


def test_daily_cap(monkeypatch):
    monkeypatch.setattr(ml, "assess", lambda *a, **k: _pred(0.75))
    monkeypatch.setattr(api, "ASK_REVIEW_PER_DAY", 2)
    api._ask_day.update({"day": "", "n": 0})
    assert "ask_review" in _analyze(QUIET) and "ask_review" in _analyze(QUIET) and "ask_review" not in _analyze(QUIET)
    monkeypatch.setattr(api, "ASK_REVIEW_PER_DAY", 0)
    assert "ask_review" not in _analyze(QUIET)


def test_borderline_report_is_queued_masked_and_labeled_by_kind(_isolated_store, capsys):
    st = _isolated_store
    text = "Remote assistant for a professor, $400 weekly, email me at prof.smith@gmail.com to start."
    r = _client().post("/report", json={"text": text, "school": "fsu", "kind": "borderline"}).json()
    assert r == {"queued": True, "kind": "borderline"}                 # no FTC summary: it's a question, not a report
    rows = st.list_reports()
    assert len(rows) == 1 and rows[0]["kind"] == "borderline" and "prof.smith@gmail.com" not in rows[0]["text_masked"]
    review_queue.main([])
    assert "CLOSE CALL" in capsys.readouterr().out
    assert review_queue.main(["--set", rows[0]["id"], "dismissed", "--real", "--reviewer", "T"]) == 0
    labels = st.labels()
    assert len(labels) == 1 and labels[0]["label"] == "legit" and labels[0]["source"] == "borderline_real"
    # a plain report confirmed as a scam keeps the old source name
    r2 = _client().post("/report", json={"text": "Deposit our check and send the rest by Zelle.", "school": "fsu"}).json()
    assert "ftc_summary" in r2
    rid = [x for x in st.list_reports() if x["status"] == "reported"][0]["id"]
    st.decide_report(rid, "confirmed", "T")
    assert sorted(l["source"] for l in st.labels()) == ["borderline_real", "report"]
    assert _client().post("/report", json={"text": "x", "kind": "whatever"}).status_code == 422
