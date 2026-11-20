"""Check counts (scam_detector/counts.py): a number per school, day and band, nothing else; shown on the review page,
in the empty queue and in the monthly trends report."""

import datetime as dt
import re

import pytest

from scam_detector import counts, review_web, trends
from scam_detector.tools import reviewers as cli


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    counts._pending.clear()
    counts._hits.clear()
    monkeypatch.setenv("REVIEW_COOKIE_SECURE", "0")
    review_web.login_limiter._hits.clear()
    yield
    counts._pending.clear()


def _client():
    from fastapi.testclient import TestClient
    from scam_detector import api
    return TestClient(api.app, follow_redirects=False)


def test_counts_only_known_schools_and_real_bands(_isolated_store):
    st = _isolated_store
    for band in ("clear", "clear", "review", "block", "nonsense"):
        counts.record("fsu", band, st)
    counts.record("not-a-school", "block", st)
    counts.record("", "block", st)
    today = dt.date.today().isoformat()
    assert counts.totals("fsu", today, st) == {"checks": 4, "flagged": 2}          # pending counts included
    counts.flush(st)
    assert counts._pending == {} and counts.totals("fsu", today, st) == {"checks": 4, "flagged": 2}
    assert counts.totals("", today, st)["checks"] == 4 and counts.totals("ucf", today, st)["checks"] == 0
    assert counts.totals("fsu", today, st, until=today)["checks"] == 0
    raw = (st._p("check_counts.json")).read_text()
    assert set(re.findall(r'"([^"]+)"', raw)) == {f"fsu|{today}|clear", f"fsu|{today}|review", f"fsu|{today}|block"}


def test_analyze_counts_and_staff_pages_show_it(_isolated_store, capsys):
    st = _isolated_store
    c = _client()
    for text in ("Campus library assistant, $13/hour.", "We will mail you a check, deposit it and send the rest by Zelle."):
        c.post("/analyze", json={"description": text, "school": "fsu", "run_network": False})
    c.post("/analyze", json={"description": "Campus library assistant.", "school": "", "run_network": False})
    assert counts.totals("fsu", dt.date.today().isoformat(), st) == {"checks": 2, "flagged": 1}
    cli.main(["add", "--email", "jdoe@fsu.edu", "--name", "J. Doe", "--school", "fsu"])
    pw = re.search(r"shown once\): (\S+)", capsys.readouterr().out).group(1)
    c.post("/review/login", data={"email": "jdoe@fsu.edu", "password": pw})
    assert "messages students checked, 1 flagged" in c.get("/review").text
    assert "Students checked 2 messages this week without needing you, and 1 of them were flagged" in c.get("/review/queue").text
    d = trends.monthly("fsu", dt.date.today().strftime("%Y-%m"), st)
    assert d["checks"] == {"checks": 2, "flagged": 1}
