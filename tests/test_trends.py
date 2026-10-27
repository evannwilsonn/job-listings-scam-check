"""The monthly trends report (scam_detector/trends.py): confirmed scams by scheme against last month, the detector's catch
rate on them, contact channels, confirmed domains, student outcomes, and nothing that names a student."""

import datetime as dt
import json

from scam_detector import trends
from scam_detector.reports import make_report
from scam_detector.tools import trends as trends_cli

CHECK = ("Hello student, our department needs a remote assistant. $450 weekly. We will mail you a check to buy office "
         "equipment from our vendor and you send the rest back by Zelle. Text me on WhatsApp. Ref {w}.")
FEE = "Data entry clerk, $35/hr, a training fee of $60 is required before you start. Pay by gift card. Ref {w}."
WORDS = "alder birch cedar dogwood elm fir ginkgo hazel".split()


def _at(month, day=10):
    y, m = (int(x) for x in month.split("-"))
    return dt.datetime(y, m, day, 12, tzinfo=dt.timezone.utc).timestamp()


def _label(st, text, month, school="fsu", label="scam"):
    st.add_label({"label": label, "description": text, "source": "report", "reviewer": "T", "school": school})
    p = st._p("labels.jsonl")
    rows = [json.loads(l) for l in p.read_text().splitlines()]
    rows[-1]["at"] = _at(month)
    st._rewrite(p, rows)


def test_counts_schemes_against_last_month_and_names_nobody(_isolated_store):
    st = _isolated_store
    for w in WORDS[:5]:
        _label(st, CHECK.format(w=w), "2026-10")
    for w in WORDS[:2]:
        _label(st, FEE.format(w=w), "2026-10")
        _label(st, CHECK.format(w=w), "2026-09")
    _label(st, CHECK.format(w="yew"), "2026-10", school="ucf")              # another school's scams don't count
    _label(st, "Campus library assistant, $13/hour. Ref oak.", "2026-10", label="legit")
    d = trends.monthly("fsu", "2026-10", st)
    assert d["confirmed"] == 7 and d["confirmed_prev"] == 2
    fams = {n: (a, b) for n, a, b in d["families"]}
    assert fams["Fake checks and money mule"] == (5, 2) and fams["Pay to start (fees, training, equipment)"] == (2, 0)
    assert d["caught"] == 7 and d["real_jobs_labeled"] == 1
    assert any("messaging app" in what for what, _ in d["channels"])
    text = trends.render(d, "Florida State University")
    assert "Florida State University: job-scam trends, October 2026" in text and "**7 confirmed scams**" in text
    assert "| Fake checks and money mule | 5 | 2 | +150% |" in text and "| Pay to start (fees, training, equipment) | 2 | 0 | new |" in text
    assert "No student is named" in text


def test_domains_and_student_outcomes(_isolated_store):
    st = _isolated_store
    rid = st.add_report(make_report("Apply at https://fast-campus-jobs.net and deposit the check.", school="fsu"))
    st.decide_report(rid, "confirmed", "T")
    month = dt.date.today().strftime("%Y-%m")
    st.add_case({"case": "a" * 64, "date": dt.date.today().isoformat(), "school": "fsu", "band": "block", "score": 80, "rules": []})
    st.add_outcome({"case": "a" * 64, "date": dt.date.today().isoformat(), "happened": ["deposited_check", "replied"], "verified": ""})
    d = trends.monthly("fsu", month, st)
    assert ("fast-campus-jobs.net", 1, 1) in d["domains"] or any(x[0] == "fast-campus-jobs.net" for x in d["domains"])
    assert d["followups"] == 1 and d["harm"] == [("deposited a check", 1)]
    text = trends.render(d)
    assert "fast-campus-jobs.net" in text and "1 deposited a check" in text


def test_empty_month_and_cli(_isolated_store, capsys, tmp_path):
    d = trends.monthly("fsu", "2026-01", _isolated_store)
    assert "No confirmed scams" in trends.render(d)
    assert trends_cli.main(["--school", "fsu", "--month", "2026-01", "-o", str(tmp_path / "r.md")]) == 0
    assert (tmp_path / "r.md").read_text().startswith("# Florida State University: job-scam trends, January 2026")
    assert trends_cli.main(["--school", "fsu", "--month", "2026-13x"]) == 2
    assert trends_cli.last_full_month(dt.date(2026, 1, 5)) == "2025-12"
