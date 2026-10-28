"""The review page (scam_detector/review_web.py): accounts from the CLI only, school-scoped queues, decisions that become
training labels exactly like tools/review_queue.py, CSRF on every form, and no scripts on any page."""

import re

import pytest

from scam_detector import review_web
from scam_detector.reports import make_report
from scam_detector.tools import reviewers as cli

SCAM = ("Hello student, our department needs a remote assistant. $450 weekly. We will mail you a check to buy office "
        "equipment from our vendor and you send the rest back by Zelle. Text me at 850-555-0142.")
REAL = "Campus library assistant, $13/hour, 10 hours a week, apply through the career center portal."


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("REVIEW_COOKIE_SECURE", "0")
    review_web.login_limiter._hits.clear()


def _client():
    from fastapi.testclient import TestClient
    from scam_detector import api
    return TestClient(api.app, follow_redirects=False)


def _account(capsys, email="jdoe@fsu.edu", name="J. Doe", school="fsu"):
    assert cli.main(["add", "--email", email, "--name", name, "--school", school]) == 0
    return re.search(r"shown once\): (\S+)", capsys.readouterr().out).group(1)


def _login(c, email, pw):
    return c.post("/review/login", data={"email": email, "password": pw})


def _csrf(page: str) -> str:
    return re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)


def test_login_queue_and_a_scam_decision(_isolated_store, capsys):
    st = _isolated_store
    pw = _account(capsys)
    st.add_report(make_report(SCAM, school="fsu", outcome="deposited_check"))
    st.add_report(make_report(REAL, school="fsu", kind="borderline"))
    st.add_report(make_report(SCAM.replace("Zelle", "Venmo"), school="ucf"))     # another school's report
    c = _client()
    assert c.get("/review").headers["location"] == "/review/login"
    assert _login(c, "jdoe@fsu.edu", "wrong password here").status_code == 401
    r = _login(c, "JDoe@FSU.edu ", pw)
    assert r.status_code == 303 and "lc_review" in r.headers["set-cookie"] and "HttpOnly" in r.headers["set-cookie"]
    page = c.get("/review")
    html = page.text
    assert page.status_code == 200 and "script-src" not in page.headers["content-security-policy"]
    assert "<script" not in html and "default-src 'none'" in page.headers["content-security-policy"]
    assert "2 waiting" in html and "Venmo" not in html                       # school-scoped
    assert "Student already deposited a check" in html and "Close call" in html
    assert "850-555-0142" not in html                                       # masked before it was stored
    assert html.index("deposited a check") < html.index("Close call")       # students who acted come first
    assert "Detector today" in html
    # the reviewer's name comes from the account, not the form
    r = c.post("/review/decide", data={"csrf": _csrf(html), "id": "0", "action": "scam", "reviewer": "Mallory", "note": "check scam"})
    assert r.status_code == 303 and "done=scam" in r.headers["location"]
    rec = st.get_report("0")
    assert rec["status"] == "confirmed" and rec["reviewer"] == "J. Doe" and rec["note"] == "check scam"
    assert [(l["label"], l["source"]) for l in st.labels()] == [("scam", "report")]
    assert st.templates()                                                   # template memory, via after_decision
    assert c.post("/review/decide", data={"csrf": _csrf(html), "id": "0", "action": "real"}).status_code == 409
    assert c.post("/review/decide", data={"csrf": _csrf(html), "id": "2", "action": "scam"}).status_code == 404
    assert st.get_report("2")["status"] == "reported"
    decided = c.get("/review?show=decided").text
    assert "check scam" in decided and "Scam · J. Doe" in decided


def test_real_unclear_and_csrf(_isolated_store, capsys):
    st = _isolated_store
    pw = _account(capsys)
    for t in (REAL, REAL + " Ref 2.", SCAM):
        st.add_report(make_report(t, school="fsu", kind="borderline"))
    c = _client()
    _login(c, "jdoe@fsu.edu", pw)
    token = _csrf(c.get("/review").text)
    assert c.post("/review/decide", data={"id": "0", "action": "real"}).status_code == 403      # no CSRF token
    assert c.post("/review/decide", data={"csrf": "0" * 64, "id": "0", "action": "real"}).status_code == 403
    assert st.get_report("0")["status"] == "reported"
    c.post("/review/decide", data={"csrf": token, "id": "0", "action": "real"})
    c.post("/review/decide", data={"csrf": token, "id": "1", "action": "unclear"})
    assert [(l["label"], l["source"]) for l in st.labels()] == [("legit", "borderline_real")]
    assert st.get_report("1")["status"] == "dismissed"


def test_operator_sees_every_school_and_trends(_isolated_store, capsys):
    st = _isolated_store
    pw = _account(capsys, "evan@example.com", "Evan", "")
    st.add_report(make_report(SCAM, school="fsu"))
    st.add_report(make_report(SCAM.replace("Zelle", "Venmo"), school="ucf"))
    c = _client()
    _login(c, "evan@example.com", pw)
    html = c.get("/review").text
    assert "2 waiting" in html and "Venmo" in html and "Florida State University" in html
    t = c.get("/review/trends?school=fsu&month=2026-10")
    assert t.status_code == 200 and "job-scam trends, October 2026" in t.text


def test_password_change_and_disable(_isolated_store, capsys):
    pw = _account(capsys)
    a, b = _client(), _client()
    _login(a, "jdoe@fsu.edu", pw)
    _login(b, "jdoe@fsu.edu", pw)
    token = _csrf(a.get("/review/password").text)
    assert "isn&#x27;t right" in a.post("/review/password", data={"csrf": token, "current": "nope", "new": "x", "again": "x"}).text
    assert "don&#x27;t match" in a.post("/review/password", data={"csrf": token, "current": pw, "new": "a" * 14, "again": "b" * 14}).text
    assert "at least 12" in a.post("/review/password", data={"csrf": token, "current": pw, "new": "short1", "again": "short1"}).text
    new = "harbor violet ladder 42"
    r = a.post("/review/password", data={"csrf": token, "current": pw, "new": new, "again": new})
    assert "Password changed" in r.text
    assert a.get("/review").status_code == 200                              # this browser stays in
    assert b.get("/review").headers["location"] == "/review/login"         # the other one was logged out
    assert _login(_client(), "jdoe@fsu.edu", pw).status_code == 401
    assert cli.main(["disable", "jdoe@fsu.edu"]) == 0
    assert a.get("/review").headers["location"] == "/review/login"
    assert _login(_client(), "jdoe@fsu.edu", new).status_code == 401
    cli.main(["enable", "jdoe@fsu.edu"])
    assert _login(_client(), "jdoe@fsu.edu", new).status_code == 303


def test_cli_and_login_rate_limit(_isolated_store, capsys):
    _account(capsys)
    assert cli.main(["add", "--email", "jdoe@fsu.edu", "--name", "Again", "--school", "fsu"]) == 2      # duplicate
    assert cli.main(["add", "--email", "x@y.edu", "--name", "X", "--school", "nowhere"]) == 2          # unknown school
    assert cli.main(["reset", "nobody@fsu.edu"]) == 1
    capsys.readouterr()
    cli.main(["list"])
    out = capsys.readouterr().out
    assert "jdoe@fsu.edu" in out and "never" in out and "pw_hash" not in out and "scrypt" not in out
    c = _client()
    codes = [_login(c, "jdoe@fsu.edu", "wrong password %d" % i).status_code for i in range(11)]
    assert codes[:10] == [401] * 10 and codes[10] == 429
