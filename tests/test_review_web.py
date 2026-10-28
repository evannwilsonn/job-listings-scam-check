"""The review page (scam_detector/review_web.py): accounts from the CLI only, school-scoped queues ordered by urgency and
risk, decisions that become training labels exactly like tools/review_queue.py, cross-school evidence, the school's own
domain lists, CSRF on every form, and no scripts on any page."""

import re

import pytest

from scam_detector import guardrails, review_web
from scam_detector.reports import make_report
from scam_detector.tools import reviewers as cli

SCAM = ("Hello student, our department needs a remote assistant. $450 weekly. We will mail you a check to buy office "
        "equipment from our vendor and you send the rest back by Zelle. Text me at 850-555-0142.")
REAL = "Campus library assistant, $13/hour, 10 hours a week, apply through the career center portal."
FEE = "Data entry clerk, $35/hr, a training fee of $60 is required before you start. Visit https://fast-campus-jobs.net"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("REVIEW_COOKIE_SECURE", "0")
    review_web.login_limiter._hits.clear()
    guardrails.clear_cache()
    yield
    guardrails.clear_cache()


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


def test_login_queue_order_and_a_scam_decision(_isolated_store, capsys):
    st = _isolated_store
    pw = _account(capsys)
    st.add_report(make_report(REAL, school="fsu", kind="borderline"))                    # 0: low risk, close call
    st.add_report(make_report(FEE, school="fsu"))                                         # 1: medium risk
    st.add_report(make_report(SCAM, school="fsu", outcome="deposited_check"))            # 2: student already acted
    st.add_report(make_report(SCAM.replace("department", "Kestrelwood department"), school="ucf"))              # 3: another school's report
    c = _client()
    assert c.get("/review").headers["location"] == "/review/login"
    assert _login(c, "jdoe@fsu.edu", "wrong password here").status_code == 401
    r = _login(c, "JDoe@FSU.edu ", pw)
    assert r.status_code == 303 and "lc_review" in r.headers["set-cookie"] and "HttpOnly" in r.headers["set-cookie"]
    home = c.get("/review")
    assert home.status_code == 200 and "Hi J." in home.text and "students who sent money or details" in home.text
    page = c.get("/review/queue")
    html = page.text
    csp = page.headers["content-security-policy"]
    assert "<script" not in html and "default-src 'none'" in csp and "script-src" not in csp
    assert "<b>3</b>Waiting" in html and "Kestrelwood" not in html                           # school-scoped
    assert "850-555-0142" not in html                                                  # masked before it was stored
    order = [int(x) for x in re.findall(r"Report #(\d+)", html)]
    assert order == [2, 1, 0]                                                          # acted first, then riskiest
    assert "Student already deposited a check" in html and "Close call" in html
    assert 'class="gauge z3"' in html and "Risk " in html and "They'll send you money" in html.replace("&#x27;", "'")
    assert c.get("/review/queue?tab=acted").text.count("Report #") == 1
    assert c.get("/review/queue?tab=close").text.count("Report #") == 1
    # the reviewer's name comes from the account, not the form
    r = c.post("/review/decide", data={"csrf": _csrf(html), "id": "2", "action": "scam", "reviewer": "Mallory", "note": "check scam"})
    assert r.status_code == 303 and "done=scam" in r.headers["location"]
    rec = st.get_report("2")
    assert rec["status"] == "confirmed" and rec["reviewer"] == "J. Doe" and rec["note"] == "check scam"
    assert [(l["label"], l["source"]) for l in st.labels()] == [("scam", "report")]
    assert st.templates()                                                              # template memory, via after_decision
    assert "Copies of this script are now flagged" in c.get(r.headers["location"]).text
    assert c.post("/review/decide", data={"csrf": _csrf(html), "id": "2", "action": "real"}).status_code == 409
    assert c.post("/review/decide", data={"csrf": _csrf(html), "id": "3", "action": "scam"}).status_code == 404
    assert st.get_report("3")["status"] == "reported"
    decided = c.get("/review/queue?tab=decided").text
    assert "check scam" in decided and "Scam · J. Doe" in decided
    assert "Latest decisions" in c.get("/review").text


def test_cross_school_evidence_shows_on_the_card(_isolated_store, capsys):
    st = _isolated_store
    pw = _account(capsys)
    other = st.add_report(make_report("Start today, details at https://fast-campus-jobs.net and pay the fee.", school="ucf"))
    st.decide_report(other, "confirmed", "UCF reviewer")
    st.add_report(make_report(FEE, school="fsu"))
    c = _client()
    _login(c, "jdoe@fsu.edu", pw)
    html = c.get("/review/queue").text
    assert "Seen before" in html and "fast-campus-jobs.net" in html and "confirmed as a scam in 1 earlier report at 1 school" in html


def test_real_aggregator_unclear_and_csrf(_isolated_store, capsys):
    st = _isolated_store
    pw = _account(capsys)
    for t in (REAL, REAL + " Ref 2.", SCAM, FEE):
        st.add_report(make_report(t, school="fsu", kind="borderline"))
    c = _client()
    _login(c, "jdoe@fsu.edu", pw)
    token = _csrf(c.get("/review/queue").text)
    assert c.post("/review/decide", data={"id": "0", "action": "real"}).status_code == 403      # no CSRF token
    assert c.post("/review/decide", data={"csrf": "0" * 64, "id": "0", "action": "real"}).status_code == 403
    assert st.get_report("0")["status"] == "reported"
    c.post("/review/decide", data={"csrf": token, "id": "0", "action": "real"})
    c.post("/review/decide", data={"csrf": token, "id": "1", "action": "unclear"})
    c.post("/review/decide", data={"csrf": token, "id": "3", "action": "aggregator", "note": "lead-gen funnel"})
    assert [(l["label"], l["source"]) for l in st.labels()] == [("legit", "borderline_real")]   # aggregator: no label
    assert st.get_report("3")["status"] == "dismissed" and st.get_report("3")["note"] == "[aggregator] lead-gen funnel"
    decided = c.get("/review/queue?tab=decided").text
    assert "Aggregator · J. Doe" in decided and "Note: lead-gen funnel" in decided and "[aggregator]" not in decided


def test_operator_sees_every_school_and_trends(_isolated_store, capsys):
    st = _isolated_store
    pw = _account(capsys, "evan@example.com", "Evan", "")
    st.add_report(make_report(SCAM, school="fsu"))
    st.add_report(make_report(SCAM.replace("department", "Kestrelwood department"), school="ucf"))
    c = _client()
    _login(c, "evan@example.com", pw)
    html = c.get("/review/queue").text
    assert "<b>2</b>Waiting" in html and "Kestrelwood" in html and "Florida State University" in html
    assert c.get("/review").status_code == 200
    t = c.get("/review/trends?school=fsu&month=2026-10")
    assert t.status_code == 200 and "job-scam trends, October 2026" in t.text


def test_school_settings(_isolated_store, capsys):
    st = _isolated_store
    pw = _account(capsys)
    c = _client()
    _login(c, "jdoe@fsu.edu", pw)
    token = _csrf(c.get("/review/settings").text)
    r = c.post("/review/settings", data={"csrf": token, "op": "add", "kind": "blocked_domain",
                                         "value": "https://Fast-Campus-Jobs.net/apply", "reason": "Oct wave", "school": "ucf"})
    assert "fast-campus-jobs.net is now blocked" in r.text
    assert [x["value"] for x in st.school_rules("fsu")] == ["fast-campus-jobs.net"] and st.school_rules("ucf") == []
    assert st.school_rules("fsu")[0]["added_by"] == "J. Doe"
    # the API applies it on the next check
    out = c.post("/analyze", json={"description": "Quick job, details at fast-campus-jobs.net", "school": "fsu",
                                   "run_network": False}).json()
    assert any(f["rule_id"] == "school_blocked_domain" for f in out["findings"])
    st.add_report(make_report("Details at https://fast-campus-jobs.net/apply", school="fsu"))
    assert "A domain your career center has blocked" in c.get("/review/queue").text
    assert "isn" in c.post("/review/settings", data={"csrf": token, "op": "add", "kind": "trusted_domain", "value": "not a domain"}).text
    assert c.post("/review/settings", data={"op": "add", "kind": "trusted_domain", "value": "x.com"}).status_code == 403
    r = c.post("/review/settings", data={"csrf": token, "op": "remove", "kind": "blocked_domain", "value": "fast-campus-jobs.net"})
    assert "Removed fast-campus-jobs.net" in r.text and st.school_rules("fsu") == []


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


def test_aggregator_signals_from_the_reports_own_link(_isolated_store, capsys):
    st = _isolated_store
    pw = _account(capsys)
    st.add_report(make_report("Sales Lead Specialist. Create a free profile to see the employer. Apply on our partner site: "
                              "https://example.com/jobmatch/signup?ref=track123&utm_source=feed", school="fsu"))
    st.add_report(make_report(REAL + " https://ymca.org/careers", school="fsu"))
    c = _client()
    _login(c, "jdoe@fsu.edu", pw)
    html = c.get("/review/queue").text
    assert html.count("Looks like an aggregator or lead-gen page") == 1 and "The apply link forces an account signup" in html
